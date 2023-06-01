#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import os
import uuid
import requests
from lambda_helper import (
    _logger,
    generate_selfsigned_cert,
    generate_ec_key_from_kms,
    client_kms,
    dynamodb,
    retrieve_and_write_tls_cert,
    TLS_CERT_PATH,
)


def lambda_handler(event, context):
    """
    example request
    {
      "operation": "set_tls_key"
    }
    """
    _logger.debug("incoming event: {}".format(event))

    nitro_instance_private_dns = os.getenv("NITRO_INSTANCE_PRIVATE_DNS")
    tls_keys_table_name = os.getenv("TLS_KEYS_TABLE_NAME")
    kms_key_id = os.getenv("KEY_ARN")

    if not (nitro_instance_private_dns and tls_keys_table_name and kms_key_id):
        _logger.fatal(
            "NITRO_INSTANCE_PRIVATE_DNS, TLS_KEYS_TABLE_NAME and KEY_ARN environment variable need to be set"
        )

    operation = event.get("operation")
    if not operation:
        _logger.fatal("request needs to define operation")

    tls_keys_table = dynamodb.Table(tls_keys_table_name)
    key_id = 1  # Hardcoded value

    if operation == "set_tls_key":

        _logger.info("Generating Public and Private key pair using KMS")
        private_key = generate_ec_key_from_kms(kms_key_id)

        random_string = str(uuid.uuid4()).replace("-", "")[0:15]

        password = random_string.encode("UTF-8")

        cert_pem, key_pem, cert_key_p12 = generate_selfsigned_cert(
            hostname=nitro_instance_private_dns,
            ip_addresses=["127.0.0.1"],
            key=private_key,
            password=password,
        )

        tls_key_store_b64 = base64.b64encode(cert_key_p12).decode()
        tls_password_b64 = base64.b64encode(password).decode()
        cert_pem_b64 = base64.b64encode(cert_pem).decode()

        _logger.info("Encrypting TLS Key with KMS")

        try:
            response = client_kms.encrypt(
                KeyId=kms_key_id,
                Plaintext=json.dumps(
                    {
                        "tls_password_b64": tls_password_b64,
                        "tls_keystore_b64": tls_key_store_b64,
                    }
                ).encode(),
            )

        except Exception as e:
            raise Exception("exception happened sending encryption request to KMS: {}".format(e))

        _logger.debug("KMS Encryption response: {}".format(response["ResponseMetadata"]))
        response_b64 = base64.standard_b64encode(response["CiphertextBlob"]).decode()

        _logger.info(f"Writing encrypted TLS key to Dynamodb with key_id {key_id}")

        try:
            response = tls_keys_table.put_item(
                Item={
                    "key_id": key_id,
                    "encrypted_tls_key_b64": response_b64,
                    "cert_pem": cert_pem_b64,
                }
            )
        except Exception as e:
            raise Exception("Exception happened writing record to DynamoDB: {}".format(e))

        return response

    elif operation == "get_tls_key":

        try:
            response = tls_keys_table.get_item(Key={"key_id": key_id})
            record = response["Item"]

        except Exception as e:
            raise Exception("exception happened reading record from DynamoDB: {}".format(e))

        return record["encrypted_tls_key_b64"]

    elif operation == "decrypt_tls_key":

        try:
            response = tls_keys_table.get_item(Key={"key_id": key_id})
            record = response["Item"]
        except Exception as e:
            raise Exception("exception happened reading record from DynamoDB: {}".format(e))

        secret_string = record["encrypted_tls_key_b64"]

        try:
            response = client_kms.decrypt(KeyId=kms_key_id, CiphertextBlob=secret_string)
        except Exception as e:
            raise Exception("exception happened decrypting secret: {}".format(e))

    elif operation == "web3signer_status":

        try:
            retrieve_and_write_tls_cert(tls_keys_table, key_id=1)
            response = requests.get(f"https://{nitro_instance_private_dns}/upcheck", verify=TLS_CERT_PATH)

        except Exception as e:
            raise Exception("exception happened: {}".format(e))

        return response.text

    elif operation == "web3signer_public_keys":

        try:
            retrieve_and_write_tls_cert(tls_keys_table, key_id=1)
            response = requests.get(
                f"https://{nitro_instance_private_dns}/api/v1/eth2/publicKeys",
                verify=TLS_CERT_PATH,
            )

            response_parsed = json.loads(response.text)

        except Exception as e:
            raise Exception("exception happened: {}".format(e))

        return response_parsed

    else:
        _logger.fatal("operation: {} not supported right now".format(operation))
