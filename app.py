#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import os
from aws_cdk import App, Environment, Aspects

from nitro_wallet.nitro_wallet_stack import NitroWalletStack
import cdk_nag

app = App()

NitroWalletStack(
    app,
    "devNitroValidator",
    params={"deployment": "dev", "application_type": "eth2"},
    env=Environment(region=os.environ.get("CDK_DEPLOY_REGION"),
                    account=os.environ.get("CDK_DEPLOY_ACCOUNT")),
)

NitroWalletStack(
    app,
    "prodNitroValidator",
    params={"deployment": "prod", "application_type": "eth2"},
    env=Environment(region=os.environ.get("CDK_DEPLOY_REGION"),
                    account=os.environ.get("CDK_DEPLOY_ACCOUNT")),
)

## If there are existing validator key table and KMS key, comment the code above and uncomment the code below!!

# NitroWalletStack(
#     app,
#     "devNitroValidator",
#     params={
#         "deployment": "dev",
#         "application_type": "eth2",
#         "kms_arn": "<INSERT_KMS_ARN_HERE>",
#         "validator_key_table_arn": "<INSERT_DDB_KEY_TABLE_ARN_HERE>",
#     },
#     env=Environment(region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])),
# )

# NitroWalletStack(
#     app,
#     "prodNitroValidator",
#     params={
#         "deployment": "prod",
#         "application_type": "eth2",
#         "kms_arn": "<INSERT_KMS_ARN_HERE>",
#         "validator_key_table_arn": "<INSERT_DDB_KEY_TABLE_ARN_HERE>",
#     },
#     env=Environment(region=os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])),
# )

Aspects.of(app).add(cdk_nag.AwsSolutionsChecks())

app.synth()
