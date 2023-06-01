#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

from aws_cdk import (
    Stack,
    Fn,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_kms as kms,
    aws_ec2 as ec2,
    aws_dynamodb as ddb,
    aws_s3_assets as s3_assets,
    aws_iam as iam,
    aws_ecr_assets as ecr_assets,
    aws_autoscaling as autoscaling,
    aws_lambda as lambda_,
    aws_lambda_python_alpha as lambda_python,
    aws_lambda_event_sources as lambda_event_sources,
    aws_elasticloadbalancingv2 as elbv2,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_sns as sns,
    aws_ssm as ssm,
)

from constructs import Construct

from cdk_nag import NagSuppressions, NagPackSuppression
from typing import List


class NitroWalletStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        params = kwargs.pop("params")
        super().__init__(scope, construct_id, **kwargs)

        application_type = params.get("application_type", "eth2")
        deployment_type = params.get("deployment")
        validator_key_table_arn = params.get("validator_key_table_arn")
        kms_arn = params.get("kms_arn")
        log_level = "WARNING"

        if deployment_type == "dev":
            log_level = "DEBUG"

        print("\n***** Stack Parameters *****")
        print(f"stack name: {self.stack_name}")
        print(f"stack region: {self.region}")
        print(f"stack log level {log_level}")
        print("**************************\n")

        if kms_arn:
            print("KMS key will be imported")
            encryption_key = kms.Key.from_key_arn(self, "ImportedKey", kms_arn)
        else:
            print("KMS key will be created")
            encryption_key = kms.Key(
                self,
                "EncryptionKey",
                enable_key_rotation=True,
                removal_policy=RemovalPolicy.DESTROY,
            )

        if validator_key_table_arn:
            print("Validator keys table will be imported")
            validator_keys_table = ddb.Table.from_table_arn(self, "ImportedValidatorKeyTable", validator_key_table_arn)
        else:
            print("Validator keys table will be created")
            validator_keys_table = ddb.Table(
                self,
                "ValidatorKeyTable",
                partition_key=ddb.Attribute(name="web3signer_uuid", type=ddb.AttributeType.STRING),
                sort_key=ddb.Attribute(name="pubkey", type=ddb.AttributeType.STRING),
                billing_mode=ddb.BillingMode.PROVISIONED,
                removal_policy=RemovalPolicy.DESTROY,
                encryption=ddb.TableEncryption.AWS_MANAGED,
                point_in_time_recovery=True,
            )

        web3signer_init_flag_param = ssm.StringParameter(self, "Web3SignerInitFlagParam", string_value="false")

        tls_keys_table = ddb.Table(
            self,
            "TLSKeyTable",
            partition_key=ddb.Attribute(name="key_id", type=ddb.AttributeType.NUMBER),
            billing_mode=ddb.BillingMode.PROVISIONED,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=ddb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
        )

        signing_server_image = ecr_assets.DockerImageAsset(
            self,
            "EthereumSigningServerImage",
            directory="./application/{}/server".format(application_type),
            build_args={"REGION_ARG": self.region, "LOG_LEVEL_ARG": log_level},
        )

        signing_enclave_image = ecr_assets.DockerImageAsset(
            self,
            "EthereumSigningEnclaveImage",
            directory="./application/{}/enclave".format(application_type),
            build_args={"REGION_ARG": self.region, "LOG_LEVEL_ARG": log_level},
        )

        watchdog = s3_assets.Asset(
            self,
            "AWSNitroEnclaveWatchdog",
            path="./application/{}/watchdog/watchdog.py".format(application_type),
        )

        watchdog_systemd = s3_assets.Asset(
            self,
            "AWSNitroEnclaveWatchdogService",
            path="./application/{}/watchdog/nitro-signing-server.service".format(application_type),
        )

        vpc = ec2.Vpc(
            self,
            "VPC",
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="public", subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(name="private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ],
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        self._create_private_link(vpc, ["KMS", "SECRETS_MANAGER", "SSM", "ECR", "S3", "DYNAMODB"])

        nitro_instance_sg = ec2.SecurityGroup(
            self,
            "Nitro",
            vpc=vpc,
            allow_all_outbound=True,
            description="Private SG for NitroWallet EC2 instance",
        )

        # external members (nlb) can run a health check on the EC2 instance 8443 port
        nitro_instance_sg.add_ingress_rule(ec2.Peer.ipv4(vpc.vpc_cidr_block), ec2.Port.tcp(8443))

        signer_client_sg = ec2.SecurityGroup(
            self,
            "NitroSignerSG",
            vpc=vpc,
            allow_all_outbound=True,
            description="Eth2 signer security group",
        )

        # just allow requests from instances inside the signer_client_sg
        nitro_instance_sg.add_ingress_rule(signer_client_sg, ec2.Port.tcp(8443))

        # AMI
        amzn_linux = ec2.MachineImage.latest_amazon_linux(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2)

        # Instance Role and SSM Managed Policy
        role = iam.Role(
            self,
            "InstanceSSM",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        )
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        role.attach_inline_policy(
            iam.Policy(
                self,
                "readcfstack",
                statements=[
                    iam.PolicyStatement(
                        actions=["cloudformation:Describe*", "cloudformation:Get*"],
                        resources=[f"arn:aws:cloudformation:{self.region}:{self.account}:stack/{self.stack_name}/*"],
                    )
                ],
            )
        )

        # grant EC2 role access to the validators and tls key table
        validator_keys_table.grant_read_data(role)
        tls_keys_table.grant_read_data(role)

        # grant EC2 role access to init flag so that userdata can determine if web3signer should be started or not
        web3signer_init_flag_param.grant_read(role)

        # grant EC2 role access to watchdog assets
        watchdog.grant_read(role)
        watchdog_systemd.grant_read(role)

        block_device = ec2.BlockDevice(
            device_name="/dev/xvda",
            volume=ec2.BlockDeviceVolume(
                ebs_device=ec2.EbsDeviceProps(
                    volume_size=32,
                    volume_type=ec2.EbsDeviceVolumeType.GP3,
                    encrypted=True,
                    delete_on_termination=True if params.get("deployment") == "dev" else False,
                )
            ),
        )

        mappings = {
            "__DEV_MODE__": params["deployment"],
            "__NITRO_ENCLAVE_DEBUG__": "TRUE" if params["deployment"] == "dev" else "FALSE",
            "__SIGNING_SERVER_IMAGE_URI__": signing_server_image.image_uri,
            "__SIGNING_ENCLAVE_IMAGE_URI__": signing_enclave_image.image_uri,
            "__WATCHDOG_S3_URL__": watchdog.s3_object_url,
            "__WATCHDOG_SYSTEMD_S3_URL__": watchdog_systemd.s3_object_url,
            "__REGION__": self.region,
            "__CF_STACK_NAME__": self.stack_name,
            "__TLS_KEYS_TABLE_NAME__": tls_keys_table.table_name,
            "__VALIDATOR_KEYS_TABLE_NAME__": validator_keys_table.table_name,
            "__WEB3SIGNER_INIT_FLAG_PARAM__": web3signer_init_flag_param.parameter_name,
        }

        with open("./user_data/user_data.sh") as f:
            user_data_raw = Fn.sub(f.read(), mappings)

        signing_enclave_image.repository.grant_pull(role)
        signing_server_image.repository.grant_pull(role)

        nitro_launch_template = ec2.LaunchTemplate(
            self,
            "NitroEC2LaunchTemplate",
            instance_type=ec2.InstanceType("c6a.xlarge"),
            user_data=ec2.UserData.custom(user_data_raw),
            nitro_enclave_enabled=True,
            machine_image=amzn_linux,
            block_devices=[block_device],
            role=role,
            security_group=nitro_instance_sg,
        )

        nitro_nlb = elbv2.NetworkLoadBalancer(
            self,
            "NitroEC2NetworkLoadBalancer",
            internet_facing=False,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        )

        zone = route53.PrivateHostedZone(
            self,
            "Web3SignerZone",
            zone_name="{}.private".format(self.stack_name),
            vpc=vpc,
        )

        nitro_nlb_a_record = route53.ARecord(
            self,
            "Web3SignerARecord",
            record_name="signer",
            zone=zone,
            target=route53.RecordTarget.from_alias(route53_targets.LoadBalancerTarget(nitro_nlb)),
        )

        asg = autoscaling.AutoScalingGroup(
            self,
            "NitroEC2AutoScalingGroup",
            max_capacity=2,
            min_capacity=2,
            launch_template=nitro_launch_template,
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            update_policy=autoscaling.UpdatePolicy.rolling_update(),
        )

        target_group = elbv2.NetworkTargetGroup(
            self,
            "Web3SignerTargetGroup",
            targets=[asg],
            protocol=elbv2.Protocol.TCP,
            port=8443,
            vpc=vpc,
            health_check=elbv2.HealthCheck(
                interval=Duration.seconds(10),
                path="/upcheck",
                protocol=elbv2.Protocol.HTTPS,
                healthy_http_codes="200",
                healthy_threshold_count=2,
                unhealthy_threshold_count=2,
                timeout=Duration.seconds(10),
            ),
        )

        nitro_nlb_listener = nitro_nlb.add_listener(
            "HTTPSListener",
            port=443,
            protocol=elbv2.Protocol.TCP,
            default_target_groups=[target_group],
        )

        layer = lambda_python.PythonLayerVersion(
            self,
            "NitroInvokeLambdaLayer",
            entry="application/{}/lambda/layer".format(params["application_type"]),
            compatible_runtimes=[lambda_.Runtime.PYTHON_3_9],
        )

        invoke_lambda = lambda_python.PythonFunction(
            self,
            "NitroInvokeLambda",
            entry="application/{}/lambda/NitroInvoke".format(params["application_type"]),
            handler="lambda_handler",
            index="lambda_function.py",
            runtime=lambda_.Runtime.PYTHON_3_9,
            timeout=Duration.minutes(2),
            memory_size=256,
            environment={
                "LOG_LEVEL": log_level,
                "NITRO_INSTANCE_PRIVATE_DNS": nitro_nlb_a_record.domain_name,
                "TLS_KEYS_TABLE_NAME": tls_keys_table.table_name,
                "KEY_ARN": encryption_key.key_arn,
            },
            layers=[layer],
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[signer_client_sg],
        )

        encryption_key.grant_encrypt(invoke_lambda)
        tls_keys_table.grant_read_write_data(invoke_lambda)

        if deployment_type == "dev":
            encryption_key.grant_decrypt(invoke_lambda)

        CfnOutput(
            self,
            "EC2InstanceRoleARN",
            value=role.role_arn,
            description="EC2 Instance Role ARN",
        )

        CfnOutput(
            self,
            "LambdaFunctionArn",
            value=invoke_lambda.function_arn,
            description="Lambda Function ARN",
        )

        CfnOutput(
            self,
            "LambdaExecutionArn",
            value=invoke_lambda.role.role_arn,
            description="Lambda execution ARN",
        )

        CfnOutput(
            self,
            "ASGGroupName",
            value=asg.auto_scaling_group_name,
            description="ASG Group Name",
        )

        CfnOutput(self, "KMSKeyARN", value=encryption_key.key_arn, description="KMS Key ARN")

        CfnOutput(
            self,
            "ValidatorKeysTableName",
            value=validator_keys_table.table_name,
            description="Validator Keys Table Name",
        )

        CfnOutput(
            self,
            "TLSKeysTableName",
            value=tls_keys_table.table_name,
            description="TLS Keys Table Name",
        )

        CfnOutput(
            self,
            "SignerELBFQDN",
            value=nitro_nlb_a_record.domain_name,
            description="Signer ELB FQDN",
        )

        CfnOutput(
            self,
            "Web3SignerInitFlagParamName",
            value=web3signer_init_flag_param.parameter_name,
            description="Web3SignerInitFlagParam name",
        )

        NagSuppressions.add_resource_suppressions(
            construct=self,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-VPC7",
                    reason="No VPC Flow Log required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-ELB2",
                    reason="No ELB Access Log required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason="Permission to read CF stack is restrictive enough",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason="AmazonSSMManagedInstanceCore is a restrictive role",
                ),
                NagPackSuppression(
                    id="AwsSolutions-AS3",
                    reason="No Auto Scaling Group notifications required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-EC23", reason="Intrinsic functions referenced for cleaner private link creation"
                ),
            ],
            apply_to_children=True,
        )

    def _create_private_link(self, vpc: ec2.Vpc, services: List[str]) -> None:
        for service in services:
            if service in ["DYNAMODB", "S3"]:
                service_gateway = getattr(ec2.GatewayVpcEndpointAwsService, service)
                vpc.add_gateway_endpoint("{}GatewayEndpoint".format(service), service=service_gateway)
            else:
                service_endpoint = getattr(ec2.InterfaceVpcEndpointAwsService, service)
                ec2.InterfaceVpcEndpoint(
                    self,
                    "{}InterfaceEndpoint".format(service),
                    vpc=vpc,
                    subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                    service=service_endpoint,
                    private_dns_enabled=True,
                )
