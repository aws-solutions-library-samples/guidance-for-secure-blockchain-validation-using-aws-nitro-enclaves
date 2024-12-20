#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

set -e
set +x

source ${SCRIPT_DIR}/e2e.env

cdk destroy devNitroValidator --force