import logging
import uuid


from botocore.exceptions import ClientError
from .service_handlers import Worker
from .sts import SessionHelper
from ... import db
from ...db import models

log = logging.getLogger('aws:lakeformation')


class LakeFormation:
    def __init__(self):
        pass

    @staticmethod
    def create_lf_client(accountid, region):
        session = SessionHelper.remote_session(accountid)
        lf_client = session.client('lakeformation', region_name=region)

        return lf_client

    @staticmethod
    def describe_resource(resource_arn, accountid, region):
        """
        Describes a LF data location
        """
        try:
            session = SessionHelper.remote_session(accountid)
            lf_client = session.client('lakeformation', region_name=region)

            response = lf_client.describe_resource(ResourceArn=resource_arn)

            log.info(f'LF data location already registered: {response}')

            return response['ResourceInfo']

        except ClientError as e:
            log.info(
                f'LF data location for resource {resource_arn} not found due to {e}'
            )
            return False

    @staticmethod
    def grant_pivot_role_all_database_permissions(accountid, region, database):
        LakeFormation.grant_permissions_to_database(
            client=SessionHelper.remote_session(accountid=accountid).client(
                'lakeformation', region_name=region
            ),
            principals=[SessionHelper.get_delegation_role_arn(accountid)],
            database_name=database,
            permissions=['ALL'],
        )

    @staticmethod
    def grant_permissions_to_database(
        client,
        principals,
        database_name,
        permissions,
        permissions_with_grant_options=None,
    ):
        for principal in principals:
            log.info(
                f'Granting database permissions {permissions} to {principal} on database {database_name}'
            )
            try:
                client.grant_permissions(
                    Principal={'DataLakePrincipalIdentifier': principal},
                    Resource={
                        'Database': {'Name': database_name},
                    },
                    Permissions=permissions,
                )
                log.info(
                    f'Successfully granted principal {principal} permissions {permissions} '
                    f'to {database_name}'
                )
            except ClientError as e:
                log.error(
                    f'Could not grant permissions '
                    f'principal {principal} '
                    f'{permissions} to database {database_name} due to: {e}'
                )

    @staticmethod
    def grant_permissions_to_table(
        client,
        principal,
        database_name,
        table_name,
        permissions,
        permissions_with_grant_options=None,
    ):
        try:
            grant_dict = dict(
                Principal={'DataLakePrincipalIdentifier': principal},
                Resource={'Table': {'DatabaseName': database_name, 'Name': table_name}},
                Permissions=permissions,
            )
            if permissions_with_grant_options:
                grant_dict[
                    'PermissionsWithGrantOption'
                ] = permissions_with_grant_options

            response = client.grant_permissions(**grant_dict)

            log.info(
                f'Successfully granted principal {principal} permissions {permissions} '
                f'to {database_name}.{table_name}: {response}'
            )
        except ClientError as e:
            log.warning(
                f'Could not grant principal {principal} '
                f'permissions {permissions} to table '
                f'{database_name}.{table_name} due to: {e}'
            )
            # raise e

    @staticmethod
    def revoke_iamallowedgroups_super_permission_from_table(
        client, accountid, database, table
    ):
        """
        When upgrading to LF tables can still have IAMAllowedGroups permissions
        Unless this is revoked the table can not be shared using LakeFormation
        :param client:
        :param accountid:
        :param database:
        :param table:
        :return:
        """
        try:
            log.info(
                f'Revoking IAMAllowedGroups Super '
                f'permission for table {database}|{table}'
            )
            LakeFormation.batch_revoke_permissions(
                client,
                accountid,
                entries=[
                    {
                        'Id': str(uuid.uuid4()),
                        'Principal': {'DataLakePrincipalIdentifier': 'EVERYONE'},
                        'Resource': {
                            'Table': {
                                'DatabaseName': database,
                                'Name': table,
                                'CatalogId': accountid,
                            }
                        },
                        'Permissions': ['ALL'],
                        'PermissionsWithGrantOption': [],
                    }
                ],
            )
        except ClientError as e:
            log.debug(
                f'Could not revoke IAMAllowedGroups Super '
                f'permission on table {database}|{table} due to {e}'
            )

    @staticmethod
    def batch_revoke_permissions(client, accountid, entries):
        """
        Batch revoke permissions to entries
        Retry is set for api throttling
        :param client:
        :param accountid:
        :param entries:
        :return:
        """
        log.info(f'Batch Revoking {entries}')
        entries_chunks: list = [entries[i : i + 20] for i in range(0, len(entries), 20)]
        failures = []
        try:
            for entries_chunk in entries_chunks:
                response = client.batch_revoke_permissions(
                    CatalogId=accountid, Entries=entries_chunk
                )
                log.info(f'Batch Revoke response: {response}')
                failures.extend(response.get('Failures'))

            for failure in failures:
                if not (
                    failure['Error']['ErrorCode'] == 'InvalidInputException'
                    and (
                        'Grantee has no permissions' in failure['Error']['ErrorMessage']
                        or 'No permissions revoked' in failure['Error']['ErrorMessage']
                        or 'not found' in failure['Error']['ErrorMessage']
                    )
                ):
                    raise ClientError(
                        error_response={
                            'Error': {
                                'Code': 'LakeFormation.batch_revoke_permissions',
                                'Message': f'Operation ended with failures: {failures}',
                            }
                        },
                        operation_name='LakeFormation.batch_revoke_permissions',
                    )

        except ClientError as e:
            log.warning(f'Batch Revoke ended with failures: {failures}')
            raise e

    @staticmethod
    def grant_resource_link_permission_on_target(client, source, target):
        for principal in target['principals']:
            try:
                table_grant = dict(
                    Principal={'DataLakePrincipalIdentifier': principal},
                    Resource={
                        'TableWithColumns': {
                            'DatabaseName': source['database'],
                            'Name': source['tablename'],
                            'ColumnWildcard': {},
                            'CatalogId': source['accountid'],
                        }
                    },
                    Permissions=['DESCRIBE', 'SELECT'],
                    PermissionsWithGrantOption=[],
                )
                client.grant_permissions(**table_grant)
                log.info(
                    f'Successfully granted permissions DESCRIBE,SELECT to {principal} on target '
                    f'{source["accountid"]}://{source["database"]}/{source["tablename"]}'
                )
            except ClientError as e:
                logging.error(
                    f'Failed granting principal {principal} '
                    'read access to resource link on target'
                    f' {source["accountid"]}://{source["database"]}/{source["tablename"]} '
                    f'due to: {e}'
                )
                raise e

    @staticmethod
    def grant_resource_link_permission(client, source, target, target_database):
        for principal in target['principals']:
            resourcelink_grant = dict(
                Principal={'DataLakePrincipalIdentifier': principal},
                Resource={
                    'Table': {
                        'DatabaseName': target_database,
                        'Name': source['tablename'],
                        'CatalogId': target['accountid'],
                    }
                },
                # Resource link only supports DESCRIBE and DROP permissions no SELECT
                Permissions=['DESCRIBE'],
            )
            try:
                client.grant_permissions(**resourcelink_grant)
                log.info(
                    f'Granted resource link DESCRIBE access '
                    f'to principal {principal} on {target["accountid"]}://{target_database}/{source["tablename"]}'
                )
            except ClientError as e:
                logging.error(
                    f'Failed granting principal {principal} '
                    f'read access to resource link on {target["accountid"]}://{target_database}/{source["tablename"]} '
                    f'due to: {e}'
                )
                raise e

    @staticmethod
    def revoke_source_table_access(**data):
        """
        Revokes permissions for a principal in a cross account sharing setup
        Parameters
        ----------
        data :

        Returns
        -------

        """
        logging.info(f'Revoking source table access: {data} ...')
        target_accountid = data['target_accountid']
        region = data['region']
        target_principals = data['target_principals']
        source_database = data['source_database']
        source_table = data['source_table']
        source_accountid = data['source_accountid']
        for target_principal in target_principals:
            try:

                aws_session = SessionHelper.remote_session(target_accountid)
                lakeformation = aws_session.client('lakeformation', region_name=region)

                logging.info('Revoking DESCRIBE permission...')
                lakeformation.revoke_permissions(
                    Principal=dict(DataLakePrincipalIdentifier=target_principal),
                    Resource=dict(
                        Table=dict(
                            CatalogId=source_accountid,
                            DatabaseName=source_database,
                            Name=source_table,
                        )
                    ),
                    Permissions=['DESCRIBE'],
                    PermissionsWithGrantOption=[],
                )
                logging.info('Successfully revoked DESCRIBE permissions')

                logging.info('Revoking SELECT permission...')
                lakeformation.revoke_permissions(
                    Principal=dict(DataLakePrincipalIdentifier=target_principal),
                    Resource=dict(
                        TableWithColumns=dict(
                            CatalogId=source_accountid,
                            DatabaseName=source_database,
                            Name=source_table,
                            ColumnWildcard={},
                        )
                    ),
                    Permissions=['SELECT'],
                    PermissionsWithGrantOption=[],
                )
                logging.info('Successfully revoked DESCRIBE permissions')

            except ClientError as e:
                logging.error(
                    f'Failed to revoke permissions for {target_principal} '
                    f'on source table {source_accountid}/{source_database}/{source_table} '
                    f'due to: {e}'
                )
                raise e

    @staticmethod
    def create_lf_tag(accountid, lf_client, tag_name, tag_values):
        try:
            # aws_session = SessionHelper.remote_session(accountid)
            # lakeformation = aws_session.client('lakeformation', region_name=region)

            logging.info(f'Creating LF Tag {tag_name} ...')

            lf_client.create_lf_tag(
                CatalogId=accountid,
                TagKey=tag_name,
                TagValues=tag_values
            )
            logging.info(f'Successfully create LF Tag {tag_name}')

        except ClientError as e:
            logging.error(
                f'Failed to create LF Tag  {tag_name} '
                f'due to: {e}'
            )
            raise e


    @staticmethod
    def create_lf_tag(accountid, lf_client, tag_name, tag_values):
        try:
            logging.info(f'Creating LF Tag {tag_name} ...')

            lf_client.create_lf_tag(
                CatalogId=accountid,
                TagKey=tag_name,
                TagValues=tag_values
            )
            logging.info(f'Successfully create LF Tag {tag_name}')


        except ClientError as e:
            logging.error(
                f'Failed to create LF Tag  {tag_name} '
                f'due to: {e}'
            )
            raise e

    @staticmethod
    @Worker.handler('lakeformation.table.assign.lftags')
    def update_table_lf_tags(engine, task: models.Task):
        with engine.scoped_session() as session:
            dataset_table: models.DatasetTable = db.api.DatasetTable.get_dataset_table_by_uri(
                session, task.targetUri
            )
            dataset: models.Dataset = db.api.Dataset.get_dataset_by_uri(
                session, dataset_table.datasetUri
            )

        if dataset_table.get("lfTagKey") and len(dataset_table.get("lfTagKey")) > 0:
            lftags_to_assign = {dataset_table.lfTagKey[i]: dataset_table.lfTagValue[i] for i in range(len(dataset_table.lfTagKey))}
            
            lf_client = LakeFormation.create_lf_client(dataset.AwsAccountId, dataset.region)

            logging.info(f'Get LF Tags in Already Assigned...')
            table_tags = lf_client.get_resource_lf_tags(
                CatalogId=dataset.AwsAccountId,
                Resource={
                    'Table': {
                        'CatalogId': dataset.AwsAccountId,
                        'DatabaseName': dataset.GlueDatabaseName,
                        'Name': dataset_table.GlueTableName
                    }
                },
                ShowAssignedLFTags=True
            )

            existing_tags = {}
            if table_tags.get('LFTagsOnTable'):
                for tag in table_tags:
                    if tag["TagKey"] in existing_tags.keys():
                        existing_tags[tag["TagKey"]].append(tag["TagValues"])
                    else:
                        existing_tags[tag["TagKey"]] = [tag["TagValues"]]
            

            for tagkey in lftags_to_assign:
                if tagkey in existing_tags.keys() and lftags_to_assign[tagkey] in existing_tags[tagkey]:
                    logging.info("Tag Already Assigned, skipping...")
                    existing_tags[tagkey].remove(lftags_to_assign[tagkey])
                    if len(existing_tags[tagkey]) == 0:
                        existing_tags.pop(tagkey)
                else:
                    logging.info(f"Assigning LF Tag {tagkey} with value {lftags_to_assign[tagkey]} to Table...")
                    try:
                        lf_client.create_lf_tag(
                            CatalogId=dataset.AwsAccountId,
                            TagKey=tagkey,
                            TagValues=[lftags_to_assign[tagkey]]
                        )
                        print(f'Successfully create LF Tag {tagkey}')
                    except ClientError as e:
                        print(f'LF Tag {tagkey} already exists, skippping create attempting update...')
                        try:
                            lf_client.update_lf_tag(
                                CatalogId=dataset.AwsAccountId,
                                TagKey=tagkey,
                                TagValuesToAdd=[lftags_to_assign[tagkey]]
                            )
                        except ClientError as e:
                            print(f'LF Tag {tagkey} already has value {lftags_to_assign[tagkey]}, skippping update...')
                            pass

                    # Add Tag to Resource
                    lf_client.add_lf_tags_to_resource(
                        CatalogId=dataset.AwsAccountId,
                        Resource={
                            'Table': {
                                'CatalogId': dataset.AwsAccountId,
                                'DatabaseName': dataset.GlueDatabaseName,
                                'Name': dataset_table.GlueTableName,
                            }
                        },
                        LFTags=[
                            {
                                'CatalogId': dataset.AwsAccountId,
                                'TagKey': tagkey,
                                'TagValues': [lftags_to_assign[tagkey]]
                            },
                        ]
                    )
            
            if len(existing_tags.keys()) > 0:
                for key, value in existing_tags:
                    lf_client.remove_lf_tags_from_resource(
                        CatalogId=dataset.AwsAccountId,
                        Resource={
                            'Table': {
                                'CatalogId': dataset.AwsAccountId,
                                'DatabaseName': dataset.GlueDatabaseName,
                                'Name': dataset_table.GlueTableName,
                            }
                        },
                        LFTags=[
                            {
                                'CatalogId': dataset.AwsAccountId,
                                'TagKey': tagkey,
                                'TagValues': lftags_to_assign[value]
                            },
                        ]
                    )
    





        
    # @staticmethod
    # def add_lf_tag_permission_to_role(iam_role, lf_client, tag_name, tag_values):
    #     try:
    #         logging.info(f'Adding LF Tag {tag_name} Permissions for {iam_role}...')

    #         response = lf_client.grant_permissions(
    #             CatalogId='string',
    #             Principal={
    #                 'DataLakePrincipalIdentifier': iam_role
    #             },
    #             Resource={
    #                 'LFTag': {
    #                     'CatalogId': 'string',
    #                     'TagKey': 'string',
    #                     'TagValues': [
    #                         'string',
    #                     ]
    #                 }
    #             },
    #             Permissions=[
    #                 'DESCRIBE','ASSOCIATE'
    #             ],
    #             PermissionsWithGrantOption=[
    #                 'DESCRIBE','ASSOCIATE'
    #             ]
    #         )
    #         logging.info(f'Successfully create LF Tag {tag_name}')

    #     except ClientError as e:
    #         logging.error(
    #             f'Failed to create LF Tag  {tag_name} '
    #             f'due to: {e}'
    #         )
    #         raise e
