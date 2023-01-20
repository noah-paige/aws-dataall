import logging
import os
import typing

from aws_cdk import (
    custom_resources as cr,
    aws_s3 as s3,
    aws_kms as kms,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_ssm as ssm,
    aws_glue as glue,
    Stack,
    Duration,
    CfnResource,
    CustomResource,
    Tags,
)
from aws_cdk.aws_glue import CfnCrawler
from sqlalchemy import and_

from .manager import stack
from ... import db
from ...aws.handlers.quicksight import Quicksight
from ...aws.handlers.sts import SessionHelper
from ...db import models
from ...db.api import Environment
from ...utils.cdk_nag_utils import CDKNagUtil
from ...utils.runtime_stacks_tagging import TagsUtil

logger = logging.getLogger(__name__)


@stack(stack='dataset')
class Dataset(Stack):
    module_name = __file__

    def get_engine(self) -> db.Engine:
        envname = os.environ.get('envname', 'local')
        engine = db.get_engine(envname=envname)
        return engine

    def get_env(self, dataset) -> models.Environment:
        engine = self.get_engine()
        with engine.scoped_session() as session:
            env = session.query(models.Environment).get(dataset.environmentUri)
        return env

    def get_env_group(self, dataset) -> models.EnvironmentGroup:
        engine = self.get_engine()
        with engine.scoped_session() as session:
            env = Environment.get_environment_group(
                session, dataset.SamlAdminGroupName, dataset.environmentUri
            )
        return env

    def get_target_with_uri(self, target_uri) -> models.Dataset:
        engine = self.get_engine()
        with engine.scoped_session() as session:
            dataset = session.query(models.Dataset).get(target_uri)
            if not dataset:
                raise Exception('ObjectNotFound')
        return dataset

    def get_target(self) -> models.Dataset:
        engine = self.get_engine()
        with engine.scoped_session() as session:
            dataset = session.query(models.Dataset).get(self.target_uri)
            if not dataset:
                raise Exception('ObjectNotFound')
        return dataset

    def get_shared_tables(self) -> typing.List[models.ShareObjectItem]:
        engine = self.get_engine()
        with engine.scoped_session() as session:
            tables = (
                session.query(
                    models.DatasetTable.GlueDatabaseName.label('GlueDatabaseName'),
                    models.DatasetTable.GlueTableName.label('GlueTableName'),
                    models.DatasetTable.AWSAccountId.label('SourceAwsAccountId'),
                    models.DatasetTable.region.label('SourceRegion'),
                    models.Environment.AwsAccountId.label('TargetAwsAccountId'),
                    models.Environment.region.label('TargetRegion'),
                )
                .join(
                    models.ShareObjectItem,
                    and_(
                        models.ShareObjectItem.itemUri == models.DatasetTable.tableUri
                    ),
                )
                .join(
                    models.ShareObject,
                    models.ShareObject.shareUri == models.ShareObjectItem.shareUri,
                )
                .join(
                    models.Environment,
                    models.Environment.environmentUri
                    == models.ShareObject.environmentUri,
                )
                .filter(
                    and_(
                        models.DatasetTable.datasetUri == self.target_uri,
                        models.DatasetTable.deleted.is_(None),
                        models.ShareObjectItem.status
                        == models.Enums.ShareObjectStatus.Approved.value,
                    )
                )
            )
        return tables

    def get_shared_folders(self) -> typing.List[models.DatasetStorageLocation]:
        engine = self.get_engine()
        with engine.scoped_session() as session:
            locations = (
                session.query(
                    models.DatasetStorageLocation.locationUri.label('locationUri'),
                    models.DatasetStorageLocation.S3BucketName.label('S3BucketName'),
                    models.DatasetStorageLocation.S3Prefix.label('S3Prefix'),
                    models.Environment.AwsAccountId.label('AwsAccountId'),
                    models.Environment.region.label('region'),
                )
                .join(
                    models.ShareObjectItem,
                    and_(
                        models.ShareObjectItem.itemUri
                        == models.DatasetStorageLocation.locationUri
                    ),
                )
                .join(
                    models.ShareObject,
                    models.ShareObject.shareUri == models.ShareObjectItem.shareUri,
                )
                .join(
                    models.Environment,
                    models.Environment.environmentUri
                    == models.ShareObject.environmentUri,
                )
                .filter(
                    and_(
                        models.DatasetStorageLocation.datasetUri == self.target_uri,
                        models.DatasetStorageLocation.deleted.is_(None),
                        models.ShareObjectItem.status
                        == models.Enums.ShareObjectStatus.Approved.value,
                    )
                )
                .all()
            )
            logger.info(f'found {len(locations)} shared locations')

            if locations:
                share_items = (
                    session.query(models.ShareObjectItem)
                    .join(
                        models.ShareObject,
                        models.ShareObject.shareUri == models.ShareObjectItem.shareUri,
                    )
                    .filter(
                        and_(
                            models.ShareObject.datasetUri == self.target_uri,
                            models.ShareObjectItem.itemType == 'DatasetStorageLocation',
                            models.ShareObject.status
                            == models.ShareObjectStatus.Approved.value,
                        )
                    )
                    .all()
                )
                for item in share_items:
                    item.status = models.ShareObjectStatus.Share_Succeeded.value

                session.commit()

        return locations

    def __init__(self, scope, id, target_uri: str = None, **kwargs):
        super().__init__(
            scope,
            id,
            description="Cloud formation stack of DATASET: {}; URI: {}; DESCRIPTION: {}".format(
                self.get_target_with_uri(target_uri=target_uri).label,
                target_uri,
                self.get_target_with_uri(target_uri=target_uri).description,
            )[:1024],
            **kwargs)

        # Required for dynamic stack tagging
        self.target_uri = target_uri

        pivot_role_name = SessionHelper.get_delegation_role_name()

        dataset = self.get_target()

        env = self.get_env(dataset)

        env_group = self.get_env_group(dataset)

        quicksight_default_group_arn = None
        if env.dashboardsEnabled:
            quicksight_default_group = Quicksight.create_quicksight_group(
                dataset.AwsAccountId, 'dataall'
            )
            quicksight_default_group_arn = quicksight_default_group['Group']['Arn']

        if dataset.imported and dataset.importedS3Bucket:
            dataset_bucket = s3.Bucket.from_bucket_name(
                self, f'ImportedBucket{dataset.datasetUri}', dataset.S3BucketName
            )
        else:
            dataset_key = kms.Key(
                self,
                'DatasetKmsKey',
                alias=dataset.KmsAlias,
                enable_key_rotation=True,
                policy=iam.PolicyDocument(
                    assign_sids=True,
                    statements=[
                        iam.PolicyStatement(
                            resources=['*'],
                            effect=iam.Effect.ALLOW,
                            principals=[
                                iam.AccountPrincipal(account_id=dataset.AwsAccountId),
                                iam.ArnPrincipal(
                                    f'arn:aws:iam::{env.AwsAccountId}:role/{pivot_role_name}'
                                ),
                            ],
                            actions=['kms:*'],
                        )
                    ],
                ),
            )

            dataset_bucket = s3.Bucket(
                self,
                'DatasetBucket',
                bucket_name=dataset.S3BucketName,
                encryption=s3.BucketEncryption.KMS,
                encryption_key=dataset_key,
                cors=[
                    s3.CorsRule(
                        allowed_methods=[
                            s3.HttpMethods.HEAD,
                            s3.HttpMethods.POST,
                            s3.HttpMethods.PUT,
                            s3.HttpMethods.DELETE,
                            s3.HttpMethods.GET,
                        ],
                        allowed_origins=['*'],
                        allowed_headers=['*'],
                        exposed_headers=[],
                    )
                ],
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                server_access_logs_bucket=s3.Bucket.from_bucket_name(
                    self,
                    'EnvAccessLogsBucket',
                    f'{env.EnvironmentDefaultBucketName}',
                ),
                server_access_logs_prefix=f'access_logs/{dataset.S3BucketName}/',
                enforce_ssl=True,
                versioned=True,
                bucket_key_enabled=True,
            )

            # dataset_bucket.add_to_resource_policy(
            #     permission=iam.PolicyStatement(
            #         actions=['s3:*'],
            #         resources=[dataset_bucket.bucket_arn],
            #         principals=[iam.AccountPrincipal(account_id=dataset.AwsAccountId)],
            #     )
            # )

            dataset_bucket.add_lifecycle_rule(
                abort_incomplete_multipart_upload_after=Duration.days(7),
                noncurrent_version_transitions=[
                    s3.NoncurrentVersionTransition(
                        storage_class=s3.StorageClass.INFREQUENT_ACCESS,
                        transition_after=Duration.days(30),
                    ),
                    s3.NoncurrentVersionTransition(
                        storage_class=s3.StorageClass.GLACIER,
                        transition_after=Duration.days(60),
                    ),
                ],
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                        transition_after=Duration.days(90),
                    ),
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER,
                        transition_after=Duration.days(360),
                    ),
                ],
                enabled=True,
            )

        # Dataset Admin and ETL User
        dataset_admin_policy = iam.Policy(
            self,
            'DatasetAdminPolicy',
            policy_name=dataset.S3BucketName,
            statements=[
                iam.PolicyStatement(
                    actions=['s3:List*'], resources=['*'], effect=iam.Effect.ALLOW
                ),
                iam.PolicyStatement(
                    actions=['logs:*'], resources=['*'], effect=iam.Effect.ALLOW
                ),
                iam.PolicyStatement(
                    actions=['tag:*'], resources=['*'], effect=iam.Effect.ALLOW
                ),
                iam.PolicyStatement(
                    actions=['s3:List*', 's3:Get*'],
                    resources=[dataset_bucket.bucket_arn],
                    effect=iam.Effect.ALLOW,
                ),
                iam.PolicyStatement(
                    actions=['s3:*'],
                    effect=iam.Effect.ALLOW,
                    resources=[dataset_bucket.bucket_arn + '/*'],
                ),
                iam.PolicyStatement(
                    actions=[
                        's3:GetAccessPoint',
                        's3:GetAccessPointPolicy',
                        's3:ListAccessPoints',
                        's3:CreateAccessPoint',
                        's3:DeleteAccessPoint',
                        's3:GetAccessPointPolicyStatus',
                        's3:DeleteAccessPointPolicy',
                        's3:PutAccessPointPolicy',
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f'arn:aws:s3:{dataset.region}:{dataset.AwsAccountId}:accesspoint/*',
                    ],
                ),
                iam.PolicyStatement(
                    actions=['s3:List*', 's3:Get*'],
                    resources=[f'arn:aws:s3:::{env.EnvironmentDefaultBucketName}'],
                    effect=iam.Effect.ALLOW,
                ),
                iam.PolicyStatement(
                    actions=['s3:*'],
                    effect=iam.Effect.ALLOW,
                    resources=[f'arn:aws:s3:::{env.EnvironmentDefaultBucketName}/*'],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    resources=['arn:aws:s3:::aws-glue-*'],
                    actions=['s3:CreateBucket'],
                ),
                iam.PolicyStatement(
                    actions=['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        'arn:aws:s3:::aws-glue-*/*',
                        'arn:aws:s3:::*/*aws-glue-*/*',
                    ],
                ),
                iam.PolicyStatement(
                    actions=['s3:GetObject'],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        'arn:aws:s3:::crawler-public*',
                        'arn:aws:s3:::aws-glue-*',
                    ],
                ),
                iam.PolicyStatement(
                    actions=[
                        'logs:CreateLogGroup',
                        'logs:CreateLogStream',
                        'logs:PutLogEvents',
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=['arn:aws:logs:*:*:/aws-glue/*'],
                ),
                iam.PolicyStatement(
                    actions=['kms:*'], effect=iam.Effect.ALLOW, resources=['*']
                ),
                iam.PolicyStatement(
                    actions=['glue:*', 'athena:*', 'lakeformation:*'],
                    resources=['*'],
                    effect=iam.Effect.ALLOW,
                ),
                iam.PolicyStatement(
                    actions=['cloudformation:*'],
                    resources=['*'],
                    effect=iam.Effect.ALLOW,
                ),
            ],
        )
        dataset_admin_policy.node.add_dependency(dataset_bucket)

        dataset_admin_role = iam.Role(
            self,
            'DatasetAdminRole',
            role_name=dataset.IAMDatasetAdminRoleArn.split('/')[-1],
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal('glue.amazonaws.com'),
                iam.ServicePrincipal('lakeformation.amazonaws.com'),
                iam.ServicePrincipal('athena.amazonaws.com'),
                iam.ServicePrincipal('sagemaker.amazonaws.com'),
                iam.ServicePrincipal('lambda.amazonaws.com'),
                iam.ServicePrincipal('ec2.amazonaws.com'),
                iam.AccountPrincipal(os.environ.get('CURRENT_AWS_ACCOUNT')),
                iam.AccountPrincipal(dataset.AwsAccountId),
                iam.ArnPrincipal(
                    f'arn:aws:iam::{dataset.AwsAccountId}:role/{pivot_role_name}'
                ),
            ),
        )
        dataset_admin_policy.attach_to_role(dataset_admin_role)

        glue_db_handler_arn = ssm.StringParameter.from_string_parameter_name(
            self,
            'GlueDbCRArnParameter',
            string_parameter_name=f'/dataall/{dataset.environmentUri}/cfn/custom-resources/lambda/arn',
        )

        glue_db_handler = _lambda.Function.from_function_attributes(
            self,
            'CustomGlueDatabaseHandler',
            function_arn=glue_db_handler_arn.string_value,
            same_environment=True,
        )

        GlueDatabase = cr.Provider(
            self,
            f'{env.resourcePrefix}GlueDbCustomResourceProvider',
            on_event_handler=glue_db_handler,
        )

        storage_location = CfnResource(
            self,
            'DatasetStorageLocation',
            type='AWS::LakeFormation::Resource',
            properties={
                'ResourceArn': f'arn:aws:s3:::{dataset.S3BucketName}',
                'RoleArn': f'arn:aws:iam::{env.AwsAccountId}:role/{pivot_role_name}',
                'UseServiceLinkedRole': False,
            },
        )
        dataset_admins = [
            dataset_admin_role.role_arn,
            f'arn:aws:iam::{env.AwsAccountId}:role/{pivot_role_name}',
            env_group.environmentIAMRoleArn,
        ]
        if quicksight_default_group_arn:
            dataset_admins.append(quicksight_default_group_arn)

        if dataset.lfTagValue:
            lf_tags = {dataset.lfTagKey[i]: dataset.lfTagValue[i] for i in range(len(dataset.lfTagKey))}
        else:
            lf_tags = {}

        glue_db = CustomResource(
            self,
            f'{env.resourcePrefix}DatasetDatabase',
            service_token=GlueDatabase.service_token,
            resource_type='Custom::GlueDatabase',
            properties={
                'CatalogId': dataset.AwsAccountId,
                'DatabaseInput': {
                    'Description': 'dataall database {} '.format(
                        dataset.GlueDatabaseName
                    ),
                    'LocationUri': f's3://{dataset.S3BucketName}/',
                    'Name': f'{dataset.GlueDatabaseName}',
                    'CreateTableDefaultPermissions': [],
                },
                'DatabaseAdministrators': dataset_admins,
                'LFTags': lf_tags
            },
        )

        glue.CfnCrawler(
            self,
            dataset.GlueCrawlerName,
            description=f'datall Glue Crawler for bucket {dataset.S3BucketName}',
            name=dataset.GlueCrawlerName,
            database_name=dataset.GlueDatabaseName,
            schedule={'scheduleExpression': f'{dataset.GlueCrawlerSchedule}'}
            if dataset.GlueCrawlerSchedule
            else None,
            role=dataset_admin_role.role_arn,
            targets=CfnCrawler.TargetsProperty(
                s3_targets=[
                    CfnCrawler.S3TargetProperty(path=f's3://{dataset.S3BucketName}')
                ]
            ),
        )

        job_args = {
            '--additional-python-modules': 'pydeequ,great_expectations,requests',
            '--datasetUri': dataset.datasetUri,
            '--database': dataset.GlueDatabaseName,
            '--datasetRegion': dataset.region,
            '--dataallRegion': os.getenv('AWS_REGION', 'eu-west-1'),
            '--environmentUri': env.environmentUri,
            '--environmentBucket': env.EnvironmentDefaultBucketName,
            '--datasetBucket': dataset.S3BucketName,
            '--apiUrl': 'None',
            '--snsTopicArn': 'None',
            '--extra-jars': (
                f's3://{env.EnvironmentDefaultBucketName}'
                f'/profiling/code/jars/deequ-2.0.0-spark-3.1.jar'
            ),
            '--enable-metrics': 'true',
            '--enable-continuous-cloudwatch-log': 'true',
            '--enable-glue-datacatalog': 'true',
        }

        job = glue.CfnJob(
            self,
            'DatasetGlueProfilingJob',
            name=dataset.GlueProfilingJobName,
            role=iam.ArnPrincipal(
                f'arn:aws:iam::{env.AwsAccountId}:role/{pivot_role_name}'
            ).arn,
            allocated_capacity=10,
            execution_property=glue.CfnJob.ExecutionPropertyProperty(
                max_concurrent_runs=100
            ),
            command=glue.CfnJob.JobCommandProperty(
                name='glueetl',
                python_version='3',
                script_location=(
                    f's3://{env.EnvironmentDefaultBucketName}'
                    f'/profiling/code/glue_script.py'
                ),
            ),
            default_arguments=job_args,
            glue_version='3.0',
            tags={'Application': 'dataall'},
        )
        if dataset.GlueProfilingTriggerSchedule:
            trigger = glue.CfnTrigger(
                self,
                'DatasetGlueProfilingTrigger',
                name=dataset.GlueProfilingTriggerName,
                type='SCHEDULED',
                schedule=dataset.GlueProfilingTriggerSchedule,
                start_on_creation=True,
                actions=[
                    glue.CfnTrigger.ActionProperty(
                        job_name=dataset.GlueProfilingJobName, arguments=job_args
                    )
                ],
            )
            trigger.node.add_dependency(job)

        Tags.of(self).add('Classification', dataset.confidentiality)

        TagsUtil.add_tags(self)

        CDKNagUtil.check_rules(self)
