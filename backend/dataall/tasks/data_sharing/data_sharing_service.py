import logging
import os

from .lf_cross_account.approve_share import (
    CrossAccountShareApproval,
)
from .lf_cross_account.revoke_share import (
    CrossAccountShareRevoke,
)
from .lf_same_account.approve_share import (
    SameAccountShareApproval,
)
from .lf_same_account.revoke_share import (
    SameAccountShareRevoke,
)
from .common.s3_approve_share import (
    S3ShareApproval
)
from .common.s3_revoke_share import (
    S3ShareRevoke
)
from .lf_tag_cross_account.approve_share import (
    LFTagShareApproval
)
from .lf_tag_cross_account.revoke_share import (
    LFTagShareRevoke
)

from ...aws.handlers.lakeformation import LakeFormation
from ...aws.handlers.glue import Glue
from ...aws.handlers.ram import Ram
from ...aws.handlers.sts import SessionHelper
from ...db import api, models, Engine
from ...utils import Parameter
from botocore.exceptions import ClientError
import uuid 
log = logging.getLogger(__name__)


class DataSharingService:
    def __init__(self):
        pass

    @classmethod
    def reject_lftag_share(cls, engine: Engine, lftag_share_uri: str):
        """
        1) Retrieves share related model objects
        2) Build shared database name (unique db per team for a dataset)
        3) Grants pivot role ALL permissions on dataset db and its tables
        4) Calls sharing revoke service

        * Delete Resource Link in Target Consumer Account (as Principal Consumer IAM Role)
        * If Table Share Delete Shared DB as well if no other tables exist
        * Delete External Shares from Producer Accounts to Target Consumer IAM Role

        Parameters
        ----------
        engine : db.engine
        share_uri : share uri

        Returns
        -------
        True if reject succeeds
        """
        with engine.scoped_session() as session:
            (
                source_env_list,
                tagged_datasets,
                tagged_tables,
                tagged_columns,
                lftag_share,
                target_environment
            ) = api.ShareObject.get_lftag_share_data(session, lftag_share_uri, 'Rejected')

        return LFTagShareRevoke(
            session,
            source_env_list,
            tagged_datasets,
            tagged_tables,
            tagged_columns,
            lftag_share,
            target_environment
        ).revoke_share()

        # principalIAMRoleARN = f"arn:aws:iam::{target_environment.AwsAccountId}:role/{lftag_share.principalIAMRoleName}"
        
        # for db in tagged_datasets:
        #     shared_db_name = (db.GlueDatabaseName + '_shared_' + lftag_share_uri)[:254]

        #     # Delete a resource link to the shared DB
        #     Glue.delete_database(
        #         accountid=target_environment.AwsAccountId,
        #         region=target_environment.region,
        #         database=shared_db_name,
        #         role_arn=principalIAMRoleARN
        #     )
        #     log.info("RESOURCE LINK DB DELETED")
        
        # for table in tagged_tables:
        #     shared_db_name = (table.GlueDatabaseName + '_shared_' + lftag_share_uri)[:254]
        #     # Delete a resource link to the shared Table
        #     Glue.batch_delete_tables(
        #         accountid=target_environment.AwsAccountId,
        #         region=target_environment.region,
        #         database=shared_db_name,
        #         tables=[table.GlueTableName],
        #         role_arn=principalIAMRoleARN
        #     )
        #     log.info("RESOURCE LINK TABLE-COLS DELETED")
            
        #     hasTables = Glue.has_tables(
        #         accountid=target_environment.AwsAccountId,
        #         region=target_environment.region,
        #         database=shared_db_name,
        #         role_arn=principalIAMRoleARN
        #     )

        #     if not hasTables:
        #         Glue.delete_database(
        #             accountid=target_environment.AwsAccountId,
        #             region=target_environment.region,
        #             database=shared_db_name,
        #             role_arn=principalIAMRoleARN
        #         )
        
        # for col in tagged_columns:
        #     shared_db_name = (col.GlueDatabaseName + '_shared_' + lftag_share_uri)[:254]
        #     # Delete a resource link to the shared Table
        #     Glue.batch_delete_tables(
        #         accountid=target_environment.AwsAccountId,
        #         region=target_environment.region,
        #         database=shared_db_name,
        #         tables=[col.GlueTableName],
        #         role_arn=principalIAMRoleARN
        #     )
        #     log.info("RESOURCE LINK TABLE-COLS DELETED")
            
        #     hasTables = Glue.has_tables(
        #         accountid=target_environment.AwsAccountId,
        #         region=target_environment.region,
        #         database=shared_db_name,
        #         role_arn=principalIAMRoleARN
        #     )
        #     if not hasTables:
        #         Glue.delete_database(
        #             accountid=target_environment.AwsAccountId,
        #             region=target_environment.region,
        #             database=shared_db_name,
        #             role_arn=principalIAMRoleARN
        #         )

        
        # # Delete External LF Tag Expressions Data Permissions 
        # for source_env in source_env_list:
        #     log.info(
        #         f'Revoking Access for External Principal: {principalIAMRoleARN}'
        #     )
        #     aws_session = SessionHelper.remote_session(accountid=source_env['account'])
        #     client = aws_session.client('lakeformation', region_name=source_env['region'])
        #     revoke_entries = [
        #         {
        #             'Id': str(uuid.uuid4()),
        #             'Principal': {
        #                 'DataLakePrincipalIdentifier': principalIAMRoleARN
        #             },
        #             'Resource': {
        #                 'LFTagPolicy': {
        #                     'CatalogId': source_env['account'],
        #                     'ResourceType': 'DATABASE',
        #                     'Expression': [{'TagKey': lftag_share.lfTagKey, 'TagValues': [lftag_share.lfTagValue]}]
        #                 }
        #             },
        #             'Permissions': ['DESCRIBE']
        #         },
        #         {
        #             'Id': str(uuid.uuid4()),
        #             'Principal': {
        #                 'DataLakePrincipalIdentifier': principalIAMRoleARN
        #             },
        #             'Resource': {
        #                 'LFTagPolicy': {
        #                     'CatalogId': source_env['account'],
        #                     'ResourceType': 'TABLE',
        #                     'Expression': [{'TagKey': lftag_share.lfTagKey, 'TagValues': [lftag_share.lfTagValue]}]
        #                 }
        #             },
        #             'Permissions': ['SELECT', 'DESCRIBE'],
        #         }
        #     ]
        #     LakeFormation.batch_revoke_permissions(
        #         client, source_env['account'], revoke_entries
        #     )

        # return


    @classmethod
    def approve_lftag_share(cls, engine: Engine, lftag_share_uri: str) -> bool:
        """
        1) Create LF Tag in Consumer Account (if not exist already)
        2) Grant Consumer LF Tag Permissions (if not already)
        2) Retrieve All Data Objects with LF Tag Key Value
        3) For Each Data Object (i.e. DB, Table, Column)

            1) Grant LF-tag permissions to the consumer account. --> FROM PRODUCER ACCT
            2) Grant data permissions to the consumer account.  --> FROM PRODUCER ACCT
            3) Optionally, revoke permissions for IAMAllowedPrincipals on the database, tables, and columns.
            4) Create a resource link to the shared table. 
            5) Assign LF-Tag to the target database.

        Parameters
        ----------
        engine : db.engine
        lftag_share_uri : lftag share uri

        Returns
        -------
        True if approve succeeds
        """
        with engine.scoped_session() as session:
            
            """
            Need
            1 - Set of All Source Environments with Tag
            2 - All Datasets (DBs) Tagged with Tag Key, Value
            3 - All Tables Tagged with Tag Key, Value
            4 - All Columns Tagged with Tag Key, Value
            5 - Target Environment
            """
            (
                source_env_list,
                tagged_datasets,
                tagged_tables,
                tagged_columns,
                lftag_share,
                target_environment
            ) = api.ShareObject.get_lftag_share_data(session, lftag_share_uri, 'Approved')

        return LFTagShareApproval(
            session,
            source_env_list,
            tagged_datasets,
            tagged_tables,
            tagged_columns,
            lftag_share,
            target_environment
        ).approve_share()


        # Create LF Tag in Consumer Account (if not exist already)
        # lf_client = LakeFormation.create_lf_client(target_environment.AwsAccountId, target_environment.region)
        # # LakeFormation.create_or_update_lf_tag(
        # #     accountid=target_environment.AwsAccountId,
        # #     lf_client=lf_client,
        # #     tag_name=lftag_share.lfTagKey,
        # #     tag_values=[lftag_share.lfTagValue]
        # # )
        # # log.info("TAG CREATED IN TARGET ENV")

        # # # Grant Consumer LF Tag Permissions (if not already)
        # # LakeFormation.grant_lftag_data_permissions_to_principal(
        # #     source_acct=target_environment.AwsAccountId,
        # #     source_region=target_environment.region,
        # #     principal=lftag_share.principalIAMRoleName,
        # #     tag_name=lftag_share.lfTagKey,
        # #     tag_values=[lftag_share.lfTagValue],
        # #     iamRole=True
        # # )
        # # log.info("PERMISSIONS GRANTED IN TARGET ENV FOR TARGET TAG")

        # For Each Source Env -
        # - Ensure V3 of LF Data Catalog Settings for Source and Target
        # - Revoke Permissions for IAMAllowedPrincipals on the DB, Tables, and Columns
        # - Grant LF Tag Permissions (only DESCRIBE to Consumer IAM ROLE with NO GRANTABLE)
        # - Grant LF Tag DATA Permissions (DESCRIBE DB and SELECT DESCRIBE Table to Consumer IAM ROLE with NO GRANTABLE)
        # principalIAMRoleARN = f"arn:aws:iam::{target_environment.AwsAccountId}:role/{lftag_share.principalIAMRoleName}"
        # for source_env in source_env_list:
        #     # MAY NOT NEED
        #     # LakeFormation.grant_lftag_permissions_to_external_acct(
        #     #     source_acct=source_env['account'],
        #     #     source_region=source_env['region'],
        #     #     principal=principalIAMRoleARN,
        #     #     tag_name=lftag_share.lfTagKey,
        #     #     tag_values=[lftag_share.lfTagValue],
        #     #     permissions=["DESCRIBE"]
        #     # )
        #     # log.info("EXTERNAL IAM Role LF TAG PERMISSIONS GRANTED IN SOURCE ENV FOR SOURCE TAG")

        #     LakeFormation.grant_lftag_data_permissions_to_principal(
        #         source_acct=source_env['account'],
        #         source_region=source_env['region'],
        #         principal=principalIAMRoleARN,
        #         tag_name=lftag_share.lfTagKey,
        #         tag_values=[lftag_share.lfTagValue],
        #         permissionsWithGrant=False
        #     )
        #     log.info("EXTERNAL ACCT DATA PERMISSIONS GRANTED IN SOURCE ENV FOR SOURCE TAG")

        #     # Accept RAM Invites For Each
        #     Ram.accept_lftag_ram_invitation(source_env, target_environment, principalIAMRoleARN)

        # # For Each Dataset (Glue DB)
        # for db in tagged_datasets:
        #     shared_db_name = (db.GlueDatabaseName + '_shared_' + lftag_share_uri)[:254]

        #     # Create a resource link to the shared table
        #     DataSharingService.create_lftag_resource_link_db(db, target_environment, principalIAMRoleARN, shared_db_name)
        #     log.info("RESOURCE LINK CREATED")
            
        # # For Each Data Table
        # for table in tagged_tables:
        #     shared_db_name = (table.GlueDatabaseName + '_shared_' + lftag_share_uri)[:254]
        #     data = DataSharingService.build_lftag_share_data(target_environment, [principalIAMRoleARN], table, shared_db_name)
            
        #     # Create Shared DB if not Exist Already
        #     log.info(
        #         f'Creating shared db ...'
        #         f'{target_environment.AwsAccountId}://{shared_db_name}'
        #     )

        #     database = Glue.create_database(
        #         target_environment.AwsAccountId,
        #         shared_db_name,
        #         target_environment.region,
        #         f's3://{table.S3BucketName}',
        #         principalIAMRoleARN=principalIAMRoleARN
        #     )
        #     log.info("SHARED DB CREATED")

        #     # Create a resource link to the shared table
        #     DataSharingService.create_lftag_resource_link(data, principalIAMRoleARN)
        #     log.info("RESOURCE LINK CREATED")

        # for col in tagged_columns:
        #     shared_db_name = (col.GlueDatabaseName + '_shared_' + lftag_share_uri)[:254]
        #     data = DataSharingService.build_lftag_share_data(target_environment, [principalIAMRoleARN], col, shared_db_name)
            
        #     # Create Shared DB if not Exist Already
        #     log.info(
        #         f'Creating shared db ...'
        #         f'{target_environment.AwsAccountId}://{shared_db_name}'
        #     )
            
        #     with engine.scoped_session() as session:
        #         col_table = api.DatasetTable.get_dataset_table_by_uri(session, col.tableUri)

        #     database = Glue.create_database(
        #         target_environment.AwsAccountId,
        #         shared_db_name,
        #         target_environment.region,
        #         f's3://{col_table.S3BucketName}',
        #         principalIAMRoleARN=principalIAMRoleARN
        #     )
        #     log.info("SHARED DB CREATED")

        #     # Create a resource link to the shared table
        #     DataSharingService.create_lftag_resource_link(data, principalIAMRoleARN)
        #     log.info("RESOURCE LINK CREATED")

        # # For Each Data Table Column
            
        #     # Grant LF-tag permissions to the consumer account
        #     # LakeFormation.grant_lftag_permissions_to_external_acct(
        #     #     source_acct=table.AWSAccountId,
        #     #     source_region=table.region,
        #     #     external_acct=target_environment.AwsAccountId,
        #     #     tag_name=lftag_share.lfTagKey,
        #     #     tag_values=[lftag_share.lfTagValue],
        #     #     permissions=["DESCRIBE"]
        #     # )
        #     # LakeFormation.grant_lftag_permissions_to_external_acct(
        #     #     source_acct=table.AWSAccountId,
        #     #     source_region=table.region,
        #     #     principal=f"arn:aws:iam::{table.AWSAccountId}:role/{lftag_share.principalIAMRoleName}",
        #     #     tag_name=lftag_share.lfTagKey,
        #     #     tag_values=[lftag_share.lfTagValue],
        #     #     permissions=["DESCRIBE"]
        #     # )
        #     # log.info("EXTERNAL ACCT LF TAG PERMISSIONS GRANTED IN SOURCE ENV FOR SOURCE TAG")

        #     # Grant data permissions to the consumer account
        #     # LakeFormation.grant_lftag_data_permissions_to_principal(
        #     #     source_acct=table.AWSAccountId,
        #     #     source_region=table.region,
        #     #     principal=target_environment.AwsAccountId,
        #     #     tag_name=lftag_share.lfTagKey,
        #     #     tag_values=[lftag_share.lfTagValue],
        #     #     iamRole=False,
        #     #     permissionsWithGrant=True
        #     # )
        #     # LakeFormation.grant_lftag_data_permissions_to_principal(
        #     #     source_acct=table.AWSAccountId,
        #     #     source_region=table.region,
        #     #     principal=lftag_share.principalIAMRoleName,
        #     #     tag_name=lftag_share.lfTagKey,
        #     #     tag_values=[lftag_share.lfTagValue],
        #     #     iamRole=True,
        #     #     permissionsWithGrant=True
        #     # )
        #     # log.info("EXTERNAL ACCT DATA PERMISSIONS GRANTED IN SOURCE ENV FOR SOURCE TAG")

        #     # Create Shared DB if not Exist Already
        #     # log.info(
        #     #     f'Creating shared db ...'
        #     #     f'{target_environment.AwsAccountId}://{shared_db_name}'
        #     # )

        #     # database = Glue.create_database(
        #     #     target_environment.AwsAccountId,
        #     #     shared_db_name,
        #     #     target_environment.region,
        #     #     f's3://{table.S3BucketName}',
        #     # )
        #     # log.info("SHARED DB CREATED")

        #     # LakeFormation.grant_pivot_role_all_database_permissions(
        #     #     target_environment.AwsAccountId, target_environment.region, shared_db_name
        #     # )

        #     # # Build Dict of Data For Source and Target 
        #     # principals = [f"arn:aws:iam::{target_environment.AwsAccountId}:role/{lftag_share.principalIAMRoleName}"]
        #     # data = DataSharingService.build_lftag_share_data(target_environment, principals, table, shared_db_name)
            
        #     # # Revoke IAM Allowed Groups
        #     # source_lf_client = LakeFormation.create_lf_client(table.AWSAccountId, table.region)
            
        #     # LakeFormation.revoke_iamallowedgroups_super_permission_from_table(
        #     #     source_lf_client,
        #     #     data['source']['accountid'],
        #     #     data['source']['database'],
        #     #     data['source']['tablename'],
        #     # )

        #     # # Create a resource link to the shared table
        #     # DataSharingService.create_lftag_resource_link(data)
        #     # log.info("RESOURCE LINK CREATED")

        #     # # Assign LF-Tag to the target database
        #     # lf_client.add_lf_tags_to_resource(
        #     #     CatalogId=target_environment.AwsAccountId,
        #     #     Resource={
        #     #         'Table': {
        #     #             'CatalogId': target_environment.AwsAccountId,
        #     #             'DatabaseName': shared_db_name,
        #     #             'Name': table.GlueTableName,
        #     #         }
        #     #     },
        #     #     LFTags=[
        #     #         {
        #     #             'CatalogId': target_environment.AwsAccountId,
        #     #             'TagKey': lftag_share.lfTagKey,
        #     #             'TagValues': [lftag_share.lfTagValue]
        #     #         },
        #     #     ]
        #     # )
        #     # log.info("TAG ASSIGNED TO SHARED TABLE")

        # return True

    # @staticmethod
    # def create_lftag_resource_link(data, principalIAMRoleARN) -> dict:
    #     """
    #     Creates a resource link to the source shared Glue table
    #     Parameters
    #     ----------
    #     data : data of source and target accounts

    #     Returns
    #     -------
    #     boto3 creation response
    #     """
    #     source = data['source']
    #     target = data['target']

    #     target_database = target['database']
    #     resource_link_input = {
    #         'Name': source['tablename'],
    #         'TargetTable': {
    #             'CatalogId': data['source']['accountid'],
    #             'DatabaseName': source['database'],
    #             'Name': source['tablename'],
    #         },
    #     }

    #     try:
    #         resource_link = Glue.create_resource_link(
    #             accountid=target['accountid'],
    #             region=target['region'],
    #             database=target_database,
    #             resource_link_name=source['tablename'],
    #             resource_link_input=resource_link_input,
    #             principalRoleArn=principalIAMRoleARN
    #         )

    #         return resource_link

    #     except ClientError as e:
    #         log.warning(
    #             f'Resource Link {resource_link_input} was not created due to: {e}'
    #         )
    #         raise e

    # @staticmethod
    # def create_lftag_resource_link_db(db, target_env, principalIAMRoleARN, shared_db_name) -> dict:
    #     """
    #     Creates a resource link to the source shared Glue Database
    #     Parameters
    #     ----------
    #     data : data of source and target accounts

    #     Returns
    #     -------
    #     boto3 creation response
    #     """
    #     resource_link_input = {
    #         'Name': shared_db_name,
    #         'TargetDatabase': {
    #             'CatalogId': db.AwsAccountId,
    #             'DatabaseName': db.GlueDatabaseName,
    #         },
    #     }

    #     try:
    #         resource_link = Glue.create_resource_link_db(
    #             accountid=target_env.AwsAccountId,
    #             region=target_env.region,
    #             database=shared_db_name,
    #             resource_link_name=shared_db_name,
    #             resource_link_input=resource_link_input,
    #             principalRoleArn=principalIAMRoleARN
    #         )

    #         return resource_link

    #     except ClientError as e:
    #         log.warning(
    #             f'Resource Link {resource_link_input} was not created due to: {e}'
    #         )
    #         raise e

    # @staticmethod
    # def build_lftag_share_data(target_environment, principals, table, shared_db_name) -> dict:
    #     """
    #     Build aws dict for boto3 operations on Glue and LF from share data
    #     Parameters
    #     ----------
    #     principals : team role
    #     table : dataset table

    #     Returns
    #     -------
    #     dict for boto3 operations
    #     """
    #     data = {
    #         'source': {
    #             'accountid': table.AWSAccountId,
    #             'region': table.region,
    #             'database': table.GlueDatabaseName,
    #             'tablename': table.GlueTableName,
    #         },
    #         'target': {
    #             'accountid': target_environment.AwsAccountId,
    #             'region': target_environment.region,
    #             'principals': principals,
    #             'database': shared_db_name,
    #         },
    #     }
    #     return data

    @classmethod
    def approve_share(cls, engine: Engine, share_uri: str) -> bool:
        """
        Share tables
        1) Retrieves share related model objects
        2) Build shared database name (unique db per team for a dataset)
        3) Grants pivot role ALL permissions on dataset db and its tables
        4) Calls sharing approval service

        Share folders
        1) (one time only) manage_bucket_policy - grants permission in the bucket policy
        2) grant_target_role_access_policy
        3) manage_access_point_and_policy
        4) update_dataset_bucket_key_policy
        5) update_share_item_status
        Parameters
        ----------
        engine : db.engine
        share_uri : share uri

        Returns
        -------
        True if approve succeeds
        """
        with engine.scoped_session() as session:
            (
                source_env_group,
                env_group,
                dataset,
                share,
                shared_tables,
                shared_folders,
                source_environment,
                target_environment,
            ) = api.ShareObject.get_share_data(session, share_uri, ['Approved'])

        log.info(f'Granting permissions to tables : {shared_tables}')
        log.info(f'Granting permissions to folders : {shared_folders}')

        shared_db_name = cls.build_shared_db_name(dataset, share)

        LakeFormation.grant_pivot_role_all_database_permissions(
            source_environment.AwsAccountId,
            source_environment.region,
            dataset.GlueDatabaseName,
        )

        share_folders_succeed = S3ShareApproval.approve_share(
            session,
            dataset,
            share,
            shared_folders,
            source_environment,
            target_environment,
            source_env_group,
            env_group,
        )

        if source_environment.AwsAccountId != target_environment.AwsAccountId:
            return CrossAccountShareApproval(
                session,
                shared_db_name,
                dataset,
                share,
                shared_tables,
                source_environment,
                target_environment,
                env_group,
            ).approve_share() if share_folders_succeed else False

        return SameAccountShareApproval(
            session,
            shared_db_name,
            dataset,
            share,
            shared_tables,
            source_environment,
            target_environment,
            env_group,
        ).approve_share() if share_folders_succeed else False

    @classmethod
    def reject_share(cls, engine: Engine, share_uri: str):
        """
        1) Retrieves share related model objects
        2) Build shared database name (unique db per team for a dataset)
        3) Grants pivot role ALL permissions on dataset db and its tables
        4) Calls sharing revoke service

        Parameters
        ----------
        engine : db.engine
        share_uri : share uri

        Returns
        -------
        True if reject succeeds
        """

        with engine.scoped_session() as session:
            (
                source_env_group,
                env_group,
                dataset,
                share,
                shared_tables,
                shared_folders,
                source_environment,
                target_environment,
            ) = api.ShareObject.get_share_data(session, share_uri, ['Rejected'])

            log.info(f'Revoking permissions for tables : {shared_tables}')
            log.info(f'Revoking permissions for folders : {shared_folders}')

            shared_db_name = cls.build_shared_db_name(dataset, share)

            LakeFormation.grant_pivot_role_all_database_permissions(
                source_environment.AwsAccountId,
                source_environment.region,
                dataset.GlueDatabaseName,
            )

            revoke_folders_succeed = S3ShareRevoke.revoke_share(
                session,
                dataset,
                share,
                shared_folders,
                source_environment,
                target_environment,
                source_env_group,
                env_group,
            )

            if source_environment.AwsAccountId != target_environment.AwsAccountId:
                return CrossAccountShareRevoke(
                    session,
                    shared_db_name,
                    dataset,
                    share,
                    shared_tables,
                    source_environment,
                    target_environment,
                    env_group,
                ).revoke_share() if revoke_folders_succeed else False

            return SameAccountShareRevoke(
                session,
                shared_db_name,
                dataset,
                share,
                shared_tables,
                source_environment,
                target_environment,
                env_group,
            ).revoke_share() if revoke_folders_succeed else False

    @classmethod
    def build_shared_db_name(
        cls, dataset: models.Dataset, share: models.ShareObject
    ) -> str:
        """
        Build Glue shared database name.
        Unique per share Uri.
        Parameters
        ----------
        dataset : models.Dataset
        share : models.ShareObject

        Returns
        -------
        Shared database name
        """
        return (dataset.GlueDatabaseName + '_shared_' + share.shareUri)[:254]

    @classmethod
    def clean_lfv1_ram_resources(cls, environment: models.Environment):
        """
        Deletes LFV1 resource shares for an environment
        Parameters
        ----------
        environment : models.Environment

        Returns
        -------
        None
        """
        return Ram.delete_lakeformation_v1_resource_shares(
            SessionHelper.remote_session(accountid=environment.AwsAccountId).client(
                'ram', region_name=environment.region
            )
        )

    @classmethod
    def refresh_shares(cls, engine: Engine) -> bool:
        """
        Refreshes the shares at scheduled frequency
        Also cleans up LFV1 ram resource shares if enabled on SSM
        Parameters
        ----------
        engine : db.engine

        Returns
        -------
        true if refresh succeeds
        """
        with engine.scoped_session() as session:
            environments = session.query(models.Environment).all()
            shares = (
                session.query(models.ShareObject)
                .filter(models.ShareObject.status.in_(['Approved', 'Rejected']))
                .all()
            )

        # Feature toggle: default value is False
        if (
            Parameter().get_parameter(
                os.getenv('envname', 'local'), 'shares/cleanlfv1ram'
            )
            == 'True'
        ):
            log.info('LFV1 Cleanup toggle is enabled')
            for e in environments:
                log.info(
                    f'Cleaning LFV1 ram resource for environment: {e.AwsAccountId}/{e.region}...'
                )
                cls.clean_lfv1_ram_resources(e)

        if not shares:
            log.info('No Approved nor Rejected shares found. Nothing to do...')
            return True

        for share in shares:
            try:
                log.info(
                    f'Refreshing share {share.shareUri} with {share.status} status...'
                )
                if share.status == 'Approved':
                    cls.approve_share(engine, share.shareUri)
                elif share.status == 'Rejected':
                    cls.reject_share(engine, share.shareUri)
            except Exception as e:
                log.error(
                    f'Failed refreshing share {share.shareUri} with {share.status}. '
                    f'due to: {e}'
                )
        return True
