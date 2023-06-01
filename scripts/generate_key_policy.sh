#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set -e
set +x

output=${1}
secure_keygen_stack_name=${2}

# instance id
stack_name=$(jq -r '. |= keys | .[0]' ${output})
asg_name=$(jq -r '."'${stack_name}'".ASGGroupName' ${output})
instance_id=$(./scripts/get_asg_instances.sh ${asg_name} | head -n 1)

# pcr_0
# 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 for debug
pcr_0=$(./scripts/get_pcr0.sh ${instance_id})

# ec2 role
ec2_role_arn=$(jq -r ".${stack_name}.EC2InstanceRoleARN" ${output})
# lambda role
lambda_execution_arn=$(jq -r ".${stack_name}.LambdaExecutionArn" ${output})

if [[ -n "${secure_keygen_stack_name}" ]]; then
  echo "Retrieving ValidatorKeyGenFunction Lambda Role of $secure_keygen_stack_name deployed in https://github.com/aws-samples/eth-keygen-lambda-sam"
  imported_lambda_execution_arn=$(aws cloudformation describe-stacks \
      --stack-name $secure_keygen_stack_name \
      --query "Stacks[0].Outputs[?OutputKey=='ValidatorKeyGenFunctionIamRole'].OutputValue | [0]" \
      --output text)
fi

# account
account_id=$(aws sts get-caller-identity | jq -r '.Account')

if [[ -n "${secure_keygen_stack_name}" ]]; then
  jq '.Statement[0].Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:ImageSha384"="'${pcr_0}'" |
    .Statement[0].Principal.AWS="'${ec2_role_arn}'" |
    .Statement[1].Principal.AWS="'${lambda_execution_arn}'" |
    .Statement[2].Principal.AWS="'${imported_lambda_execution_arn}'" |
    .Statement[3].Principal.AWS="arn:aws:iam::'${account_id}':root"' < ./scripts/kms_key_policy_with_keygen_template.json
else
  jq '.Statement[0].Condition.StringEqualsIgnoreCase."kms:RecipientAttestation:ImageSha384"="'${pcr_0}'" |
    .Statement[0].Principal.AWS="'${ec2_role_arn}'" |
    .Statement[1].Principal.AWS="'${lambda_execution_arn}'" |
    .Statement[2].Principal.AWS="arn:aws:iam::'${account_id}':root"' < ./scripts/kms_key_policy_template.json
fi
