#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

flag_id=$(aws ssm send-command \
 --region "${CDK_DEPLOY_REGION}" \
 --document-name "AWS-RunShellScript" \
 --instance-ids "${1}" \
 --parameters 'commands=["sudo cat /etc/environment | head -n 1 | tr \"=\" \"\n\" | tail -n 1"]' \
 | jq -r '.Command.CommandId')

flags=$(aws ssm list-command-invocations \
 --region "${CDK_DEPLOY_REGION}" \
 --instance-id "${1}" \
 --command-id "${flag_id}" \
 --details \
 | jq -r '.CommandInvocations[0].CommandPlugins[0].Output')

# validate that flags value has been read correctly from ec2 instance - it should be either true or false
if [[ "${flags}" != "TRUE" && "${flags}" != "FALSE" ]]; then
  echo "flags is not true or false"
  exit 1
fi

# if debug flag is true, provide 000 string in key policy, otherwise get PCR value from eif file running on EC2 instance
if [[ "${flags}" == "TRUE" ]]; then
  pcr_0="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
else
  command_id=$(aws ssm send-command \
  --region "${CDK_DEPLOY_REGION}" \
  --document-name "AWS-RunShellScript" \
  --instance-ids "${1}" \
  --parameters 'commands=["sudo nitro-cli describe-eif --eif-path /home/ec2-user/app/server/signing_server.eif | jq -r '.Measurements.PCR0'"]' \
  | jq -r '.Command.CommandId')

  # takes about 5sec to return the pcr0 value from a non running enclave
  sleep 10
  pcr_0=$(aws ssm list-command-invocations \
  --region "${CDK_DEPLOY_REGION}" \
  --instance-id "${1}" \
  --command-id "${command_id}" \
  --details \
  | jq -r '.CommandInvocations[0].CommandPlugins[0].Output')
fi

# ensure that pcr0 is not empty
if [[ "${pcr_0}" == "" ]]; then
  echo "pcr_0 is empty"
  exit 1
fi

echo "${pcr_0}"
