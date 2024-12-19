#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

set -e
set +x

export CDK_DEPLOY_REGION=us-east-1
export CDK_DEPLOY_ACCOUNT=$(aws sts get-caller-identity | jq -r '.Account')
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

./scripts/build_kmstool_enclave_cli.sh
cdk deploy devNitroValidator -O nitro_validator_output.json --require-approval=never

export CF_STACK_NAME=$(jq -r '. |= keys | .[0]' nitro_validator_output.json)
export KMS_KEY_ARN=$(jq -r ".$CF_STACK_NAME.KMSKeyARN" nitro_validator_output.json)
export DDB_TABLE_NAME=$(jq -r ".${CF_STACK_NAME}.ValidatorKeysTableName" nitro_validator_output.json)
export FUNCTION_ARN=$(jq -r ".${CF_STACK_NAME}.LambdaFunctionArn" nitro_validator_output.json)

cd scripts/load_validator_keys
pip3 install -r requirements.txt
python3 load_validator_keys.py
cd ../..

./scripts/generate_key_policy.sh nitro_validator_output.json >key_policy.json
aws kms put-key-policy \
 --policy-name default \
 --key-id "${KMS_KEY_ARN}" \
 --policy file://key_policy.json \
 --region ${CDK_DEPLOY_REGION} \
 --no-cli-pager

aws lambda invoke --no-cli-pager \
 --function-name "${FUNCTION_ARN}" \
 --region "${CDK_DEPLOY_REGION}" \
 --cli-binary-format raw-in-base64-out \
 --payload '{"operation": "set_tls_key"}' lambda-output
./scripts/start_signing_service.sh nitro_validator_output.json
./tests/e2e/web3signer_status.sh nitro_validator_output.json
