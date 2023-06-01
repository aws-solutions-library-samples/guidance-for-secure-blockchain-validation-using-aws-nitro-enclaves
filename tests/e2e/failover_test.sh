#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

output=${1}

stack_name=$(jq -r '. |= keys | .[0]' "${output}")
#lambda_function_name=$(jq -r ".${stack_name}.LambdaFunctionArn" "${output}")
asg_hot_group_name=$(jq -r ".${stack_name}.ASGHotGroupName" "${output}")

instances=$(./scripts/get_asg_instances.sh "${asg_hot_group_name}")

aws ec2 terminate-instances --instance-ids "${instances}"

./tests/e2e/web3signer_status.sh "${output}"
# terminate all instances

