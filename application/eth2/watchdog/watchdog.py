#!/usr/bin/env python3
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
import json
import os
import socket
import subprocess  # nosec B404
import time
import logging
import sys
from http import client

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

ENCLAVE_NAME = "signing_server"
NITRO_ENCLAVE_DEBUG = os.getenv("NITRO_ENCLAVE_DEBUG")

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(pathname)s:%(lineno)s:%(message)s"
formatter = logging.Formatter(LOG_FORMAT)
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)
_logger.addHandler(handler)


def get_imds_token():
    http_ec2_client = client.HTTPConnection("169.254.169.254")
    headers = {
        "X-aws-ec2-metadata-token-ttl-seconds": "21600"  # Token valid for 6 hours
    }
    http_ec2_client.request("PUT", "/latest/api/token", headers=headers)
    token_response = http_ec2_client.getresponse()
    return token_response.read().decode()


def get_aws_session_token():
    try:
        token = get_imds_token()

        http_ec2_client = client.HTTPConnection("169.254.169.254")
        headers = {"X-aws-ec2-metadata-token": token}

        # Get instance profile name
        http_ec2_client.request(
            "GET",
            "/latest/meta-data/iam/security-credentials/",
            headers=headers
        )
        r = http_ec2_client.getresponse()
        instance_profile_name = r.read().decode()

        # Get credentials
        http_ec2_client.request(
            "GET",
            f"/latest/meta-data/iam/security-credentials/{instance_profile_name}",
            headers=headers
        )
        r = http_ec2_client.getresponse()
        response = json.loads(r.read())
        return {
            "access_key_id": response["AccessKeyId"],
            "secret_access_key": response["SecretAccessKey"],
            "token": response["Token"],
        }

    except Exception as e:
        raise Exception(f"Failed to retrieve instance credentials: {str(e)}")
    finally:
        if 'http_ec2_client' in locals():
            http_ec2_client.close()


def get_cloudformation_stack_id(cf_stack_name: str) -> str:
    cf_client = boto3.client(
        service_name="cloudformation", region_name=os.getenv("REGION")
    )

    try:
        response = cf_client.describe_stacks(
            StackName=cf_stack_name,
        )

        if len(response["Stacks"]) < 1:
            raise Exception(f"No CloudFormation stack found with name {cf_stack_name}")

        stack_arn = response["Stacks"][0]["StackId"]
        stack_id = stack_arn.split("/")[2]
        _logger.debug(f"Stack ID {stack_id} will be used as web3signer_uuid")

    except Exception as e:
        raise e

    return stack_id


def nitro_cli_describe_call(name: str = None) -> bool:
    subprocess_args = ["/bin/nitro-cli", "describe-enclaves"]

    _logger.debug(f"enclave args: {subprocess_args}")

    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE)  # nosec B603

    nitro_cli_response = proc.communicate()[0].decode()

    if name:
        response = json.loads(nitro_cli_response)

        if len(response) != 1:
            return False

        if (
                response[0].get("EnclaveName") != name
                and response[0].get("State") != "Running"
        ):
            return False

    return True


def nitro_cli_run_call(debug: bool = False) -> str:
    subprocess_args = [
        "/bin/nitro-cli",
        "run-enclave",
        "--cpu-count",
        "2",
        "--memory",
        "3806",
        "--eif-path",
        "/home/ec2-user/app/server/signing_server.eif",
        "--enclave-cid",
        "16",
    ]

    if debug:
        subprocess_args.append("--debug-mode")

    _logger.debug(f"enclave args: {subprocess_args}")

    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE)  # nosec B603

    # returns b64 encoded plaintext
    nitro_cli_response = proc.communicate()[0].decode()

    return nitro_cli_response


def call_enclave(cid: int, port: int, enclave_payload: dict) -> str:
    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((cid, port))

    s.send(str.encode(json.dumps(enclave_payload)))

    # receive data from the server
    payload_processed = s.recv(1024).decode()

    # close the connection
    s.close()

    return payload_processed


def get_encrypted_validator_keys(validator_keys_table_name: str, uuid: str) -> list:
    dynamodb = boto3.resource(service_name="dynamodb", region_name=os.getenv("REGION"))
    table = dynamodb.Table(validator_keys_table_name)

    _logger.debug("Retrieving encrypted validator keys")

    try:
        response = table.query(KeyConditionExpression=Key("web3signer_uuid").eq(uuid))

        record_count = response["Count"]
        records = response["Items"]
        last_evaluated_key = response.get("LastEvaluatedKey", None)

        if last_evaluated_key:
            _logger.debug(
                "There are more validator keys to be retrieved - but logic to retrieve more keys are not implemented"
            )

        if record_count < 1:
            raise f"No validator keys found for web3signer {uuid}"

        _logger.debug(
            f"Number of validator keys assigned to web3signer {uuid}: {record_count}"
        )

        # Assume there is encrypted_key_password_mnemonic_b64 column
        encrypted_key_password_mnemonic_b64_list = list(
            map(lambda record: record["encrypted_key_password_mnemonic_b64"], records)
        )

        if not len(encrypted_key_password_mnemonic_b64_list) == record_count:
            _logger.debug(
                "There might be missing keys due to missing fields in DynamoDB"
            )

        return encrypted_key_password_mnemonic_b64_list

    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"]["Message"]
        _logger.debug(
            f"Couldn't query for uuid {uuid}. Here's why: {code}: {message}",
        )
        raise

    except Exception as e:
        raise e


def get_encrypted_tls_key(tls_keys_table_name: str, key_id=1) -> str:
    dynamodb = boto3.resource(service_name="dynamodb", region_name=os.getenv("REGION"))
    table = dynamodb.Table(tls_keys_table_name)

    _logger.debug("Retrieving encrypted TLS keys")

    try:
        response = table.query(KeyConditionExpression=Key("key_id").eq(key_id))

        record_count = response["Count"]
        records = response["Items"]

        if record_count < 1:
            raise f"No TLS keys found for key_id {key_id}"

        _logger.debug(f"Number of tls keys for key_id {key_id}: {record_count}")

        encrypted_tls_key_b64 = records[0]["encrypted_tls_key_b64"]
        if not encrypted_tls_key_b64:
            raise f"encrypted_tls_key_b64 column in table {tls_keys_table_name} not found"

        return records[0]["encrypted_tls_key_b64"]

    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"]["Message"]
        _logger.error(
            f"Couldn't query for key_id {key_id}. Here's why: {code}: {message}",
        )
        raise

    except Exception as e:
        raise e


def init_web3signer_call(
        tls_keys_table_name: str, cf_stack_name: str, validator_keys_table_name: str
) -> None:
    uuid = get_cloudformation_stack_id(cf_stack_name)
    encrypted_validator_keys = get_encrypted_validator_keys(
        validator_keys_table_name, uuid
    )
    encrypted_tls_key = get_encrypted_tls_key(tls_keys_table_name=tls_keys_table_name)

    credentials = get_aws_session_token()

    payload = {
        "operation": "init",
        "credential": credentials,
        "encrypted_tls_key": encrypted_tls_key,
        "encrypted_validator_keys": encrypted_validator_keys,
    }

    call_enclave(16, 5000, payload)


def main():
    _logger.info("Starting signing server...")

    tls_keys_table_name = os.getenv("TLS_KEYS_TABLE_NAME")
    if not tls_keys_table_name:
        raise Exception("TLS_KEYS_TABLE_NAME environment variable not set")
    _logger.debug(f"TLS_KEYS_TABLE_NAME = {tls_keys_table_name}")

    validator_keys_table_name = os.getenv("VALIDATOR_KEYS_TABLE_NAME")
    if not validator_keys_table_name:
        raise Exception("VALIDATOR_KEYS_TABLE_NAME environment variable not set")
    _logger.debug(f"VALIDATOR_KEYS_TABLE_NAME = {validator_keys_table_name}")

    cf_stack_name = os.getenv("CF_STACK_NAME")
    if not cf_stack_name:
        raise Exception("CF_STACK_NAME environment variable not set")
    _logger.debug(f"CF_STACK_NAME= {cf_stack_name}")

    if not NITRO_ENCLAVE_DEBUG:
        raise Exception("NITRO_ENCLAVE_DEBUG environment variable not set")
    _logger.debug(f"NITRO_ENCLAVE_DEBUG = {NITRO_ENCLAVE_DEBUG}")

    region = os.getenv("REGION")
    if not region:
        raise Exception("REGION environment variable not set")
    _logger.debug(f"REGION = {region}")

    debug_param = False
    if NITRO_ENCLAVE_DEBUG == "TRUE":
        debug_param = True

    # start enclave
    if not nitro_cli_describe_call(ENCLAVE_NAME):
        try:
            nitro_cli_run_call(debug_param)
        except Exception as e:
            raise Exception(f"exception happened starting Web3Signer enclave: {str(e)}")

    time.sleep(10)

    # init web3signer
    try:
        init_web3signer_call(
            tls_keys_table_name, cf_stack_name, validator_keys_table_name
        )
    except Exception as e:
        raise Exception(f"exception happened initializing Web3Signer enclave: {str(e)}")

    # chekc if siging_server enclave is up and running otherwise restart
    while nitro_cli_describe_call(ENCLAVE_NAME):
        time.sleep(5)


if __name__ == "__main__":
    main()
