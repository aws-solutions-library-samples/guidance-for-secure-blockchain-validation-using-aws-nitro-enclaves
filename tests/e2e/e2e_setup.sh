#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -e
set +x

source ${SCRIPT_DIR}/e2e.env

output_file="nitro_validator_output.json"

printf "building kmstool_enclave_cli\n"
./scripts/build_kmstool_enclave_cli.sh

printf "deploying cdk stack"
cdk deploy devNitroValidator -O "${output_file}" --require-approval=never

export CF_STACK_NAME=$(jq -r '. |= keys | .[0]' "${output_file}")
export KMS_KEY_ARN=$(jq -r ".$CF_STACK_NAME.KMSKeyARN" "${output_file}")
export DDB_TABLE_NAME=$(jq -r ".${CF_STACK_NAME}.ValidatorKeysTableName" "${output_file}")
export FUNCTION_ARN=$(jq -r ".${CF_STACK_NAME}.LambdaFunctionArn" "${output_file}")

# get SSM init flag parameter name from cdk output file - if init flag has been set to true already, skip validation key generation and set tls key step
web3signer_init_flag_param_name=$(jq -r ".$CF_STACK_NAME.Web3SignerInitFlagParamName" "${output_file}")

# get aws ssm init parameter
init_flag=$(aws ssm get-parameter \
 --name "${web3signer_init_flag_param_name}" \
 --region "${CDK_DEPLOY_REGION}" \
 --no-cli-pager \
 --query "Parameter.Value" \
 --output text)

# if init_flag is true, service has been started before, no key and tls key generation required
if [[ "${init_flag}" == "true" ]]; then
  printf "init flag is already set to true, skipping validation key generation and setting tls key\n"
else
  printf "loading validator keys\n"
  cd scripts/load_validator_keys
  pip3 install -r requirements.txt
  python3 load_validator_keys.py
  cd ../..

  printf "setting tls key\n"
  aws lambda invoke --no-cli-pager \
   --function-name "${FUNCTION_ARN}" \
   --region "${CDK_DEPLOY_REGION}" \
   --cli-binary-format raw-in-base64-out \
   --payload '{"operation": "set_tls_key"}' lambda-output
fi

printf "generating key policy\n"
./scripts/generate_key_policy.sh "${output_file}" >key_policy.json

printf "putting key policy\n"
aws kms put-key-policy \
 --policy-name default \
 --key-id "${KMS_KEY_ARN}" \
 --policy file://key_policy.json \
 --region "${CDK_DEPLOY_REGION}" \
 --no-cli-pager

sleep 5
printf "starting signing service\n"
./scripts/start_signing_service.sh "${output_file}"

sleep 20
printf "checking web3singer status\n"
./tests/e2e/web3signer_status.sh "${output_file}"
