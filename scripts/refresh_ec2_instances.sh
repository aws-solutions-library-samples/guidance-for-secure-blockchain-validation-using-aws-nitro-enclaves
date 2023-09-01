#!/usr/bin/env bash
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
set +x
set -e

aws autoscaling start-instance-refresh --region "${CDK_DEPLOY_REGION}" --auto-scaling-group-name "${1}"