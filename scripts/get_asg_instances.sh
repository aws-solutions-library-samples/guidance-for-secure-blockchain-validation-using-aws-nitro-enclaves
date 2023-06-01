#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

# avoid old terminated instances
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name "${1}" | jq -r '.AutoScalingGroups[0].Instances[] | select ( .LifecycleState | contains("InService")) | .InstanceId '
