#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

output=${1}

stack_name=$(jq -r '. |= keys | .[0]' "${output}")
lambda_function_name=$(jq -r ".${stack_name}.LambdaFunctionArn" "${output}")

STATUS_OPERATION="web3signer_status"
PUBLIC_KEYS_OPERATION="web3signer_public_keys"
GENERIC_REQUEST='{
  "operation": ""
}'
function send_request() {
  # create new key
  printf "\n%s\n" "$(date '+%d/%m/%Y %H:%M:%S'): sending request"
  echo "${GENERIC_REQUEST}" | jq '.operation="'${1}'"' >.tmp.payload
  # $( echo ${payload} | jq -R -s '.')
  aws lambda invoke \
   --no-cli-pager \
   --cli-binary-format raw-in-base64-out \
   --region "${CDK_DEPLOY_REGION}" \
   --function-name "${lambda_function_name}" \
   --payload file://.tmp.payload .tmp.out
  echo "result: $(<.tmp.out)"
  rm -rf .tmp.out .tmp.payload
}

while true; do
  send_request "${STATUS_OPERATION}"
  send_request "${PUBLIC_KEYS_OPERATION}"
  sleep 5
done
