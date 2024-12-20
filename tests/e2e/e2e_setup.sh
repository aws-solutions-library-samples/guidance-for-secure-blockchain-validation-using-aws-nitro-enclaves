#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -e
set +x

source ${SCRIPT_DIR}/e2e.env
printf "building kmstool_enclave_cli\n"
./scripts/build_kmstool_enclave_cli.sh

printf "deploying cdk stack"
cdk deploy devNitroValidator -O nitro_validator_output.json --require-approval=never

export CF_STACK_NAME=$(jq -r '. |= keys | .[0]' nitro_validator_output.json)
export KMS_KEY_ARN=$(jq -r ".$CF_STACK_NAME.KMSKeyARN" nitro_validator_output.json)
export DDB_TABLE_NAME=$(jq -r ".${CF_STACK_NAME}.ValidatorKeysTableName" nitro_validator_output.json)
export FUNCTION_ARN=$(jq -r ".${CF_STACK_NAME}.LambdaFunctionArn" nitro_validator_output.json)

printf "loading validator keys\n"
cd scripts/load_validator_keys
pip3 install -r requirements.txt
python3 load_validator_keys.py
cd ../..

printf "generating key policy\n"
./scripts/generate_key_policy.sh nitro_validator_output.json >key_policy.json

printf "putting key policy\n"
aws kms put-key-policy \
 --policy-name default \
 --key-id "${KMS_KEY_ARN}" \
 --policy file://key_policy.json \
 --region ${CDK_DEPLOY_REGION} \
 --no-cli-pager

printf "setting tls key\n"
aws lambda invoke --no-cli-pager \
 --function-name "${FUNCTION_ARN}" \
 --region "${CDK_DEPLOY_REGION}" \
 --cli-binary-format raw-in-base64-out \
 --payload '{"operation": "set_tls_key"}' lambda-output

sleep 5
printf "starting signing service\n"
./scripts/start_signing_service.sh nitro_validator_output.json

sleep 20
printf "checking web3singer status\n"
./tests/e2e/web3signer_status.sh nitro_validator_output.json
