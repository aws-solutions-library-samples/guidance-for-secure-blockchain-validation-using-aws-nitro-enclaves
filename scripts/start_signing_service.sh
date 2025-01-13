#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set -e
set +x

output=${1}

# get EC2 instance ids from autoscaling group
stack_name=$(jq -r '. |= keys | .[0]' "${output}")
asg_name=$(jq -r '."'${stack_name}'".ASGGroupName' "${output}")

# get instance ids from autoscaling group, flatten the array
instance_ids=$(./scripts/get_asg_instances.sh "${asg_name}"| tr "\n" " ")

# get SSM init flag parameter name from cdk output file
web3signer_init_flag_param_name=$(jq -r '."'${stack_name}'"."Web3SignerInitFlagParamName"' "${output}")

# send start command to all EC2 instances at the same time
start_command_id=$(aws ssm send-command \
 --region "${CDK_DEPLOY_REGION}" \
 --document-name "AWS-RunShellScript" \
 --instance-ids ${instance_ids} \
 --parameters 'commands=["sudo systemctl start nitro-signing-server.service"]' | jq -r '.Command.CommandId')

sleep 15
# send get systemd status command to all EC2 instances at the same time
status_command_id_hot=$(aws ssm send-command \
 --region "${CDK_DEPLOY_REGION}" \
 --document-name "AWS-RunShellScript" \
 --instance-ids ${instance_ids} \
 --parameters 'commands=["sudo systemctl status nitro-signing-server.service"]' | jq -r '.Command.CommandId')

# iterate over instances in EC2 autoscaling group and get nitro-signing-server (systemd) status values requested before
instance_ids_nl=$(echo "${instance_ids}" | tr "\n " " ")
for instance_id in ${instance_ids_nl}; do
  status=$(aws ssm list-command-invocations \
  --region "${CDK_DEPLOY_REGION}" \
  --instance-id ${instance_id} \
  --command-id "${status_command_id_hot}" \
  --details | jq -r '.CommandInvocations[0].CommandPlugins[0].Output')
  echo "${instance_id}: ${status}"
done

# init flag validation optional at this point - needs to incorporated into watchdog to do auto systemd start
aws ssm put-parameter \
 --name "${web3signer_init_flag_param_name}" \
 --type "String" \
 --value "true" \
 --overwrite \
 --region "${CDK_DEPLOY_REGION}" \
 --no-cli-pager

printf "\n%s\n" "($(date '+%d/%m/%Y %H:%M:%S')) service has been started and is healthy"