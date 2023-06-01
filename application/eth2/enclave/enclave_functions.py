#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import subprocess as sp  # nosec B404
import threading
import os
import sys
import socket
import time
import json
import logging
import base64
import yaml
import psutil
import errno

from typing import List, Optional, Tuple

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(pathname)s:%(lineno)s:%(message)s"
logging.basicConfig(format=LOG_FORMAT)

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def kms_call(credential: dict, ciphertext: str) -> str:
    aws_access_key_id = credential["access_key_id"]
    aws_secret_access_key = credential["secret_access_key"]
    aws_session_token = credential["token"]

    subprocess_args = [
        "/app/kmstool_enclave_cli",
        "decrypt",
        "--region",
        os.getenv("REGION"),
        "--proxy-port",
        "8000",
        "--aws-access-key-id",
        aws_access_key_id,
        "--aws-secret-access-key",
        aws_secret_access_key,
        "--aws-session-token",
        aws_session_token,
        "--ciphertext",
        ciphertext,
    ]

    _logger.debug("subprocess args: {}".format(subprocess_args))

    proc = sp.Popen(subprocess_args, stdout=sp.PIPE)  # nosec B603

    # returns b64 encoded plaintext
    plaintext = proc.communicate()[0].decode()

    return plaintext


def start_web3signer() -> Tuple[Optional[int], Optional[int]]:
    subprocess_args = [
        "/opt/web3signer/bin/web3signer",
        "--key-store-path=/app/key_files/",
        "--tls-keystore-file=/app/certs/keyStore.p12",
        "--tls-keystore-password-file=/app/certs/keyStore.password",
        "--http-listen-host=127.0.0.1",
        "--http-listen-port=9000",
        "--data-path=/app/data",
        "--tls-allow-any-client=true",
        "--http-host-allowlist=*",
        "--logging={}".format(LOG_LEVEL if LOG_LEVEL == "DEBUG" else "WARN"),
        "eth2",
        "--slashing-protection-enabled=false",
    ]

    _logger.debug("subprocess args: {}".format(subprocess_args))

    try:
        web3signer = sp.Popen(subprocess_args, stdout=sys.stdout, stderr=sys.stderr)  # nosec B603
    except OSError as e:
        raise e

    except ValueError as e:
        raise e

    except Exception as e:
        raise e

    # 5 seconds for the web3signer process to start and bin network
    time.sleep(5)

    return web3signer.pid, web3signer.poll()


def start_vsock_proxy(dock_socket: socket.socket) -> None:
    thread = threading.Thread(target=server, args=[dock_socket])
    thread.start()


def server(dock_socket: socket.socket) -> None:
    try:
        while True:
            (server_socket, address) = dock_socket.accept()
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("127.0.0.1", 9000))

            outgoing_thread = threading.Thread(target=forward, args=(client_socket, server_socket))
            incoming_thread = threading.Thread(target=forward, args=(server_socket, client_socket))

            outgoing_thread.start()
            incoming_thread.start()
    finally:
        new_thread = threading.Thread(target=server, args=[dock_socket])
        new_thread.start()


def forward(source: socket.socket, destination: socket.socket) -> None:
    string = " "
    while string:
        string = source.recv(1024)
        if string:
            destination.sendall(string)
        else:
            try:
                source.shutdown(socket.SHUT_RD)
                destination.shutdown(socket.SHUT_WR)
            except socket.error as e:
                # race condition
                if e.errno != errno.ENOTCONN:
                    raise


def handle_response(sock: socket, msg: dict, status: int) -> None:
    response = {"body": msg, "status": status}

    sock.send(str.encode(json.dumps(response)))
    sock.close()


def recvall(s: socket.socket) -> bytes:
    data = bytearray()
    buf_size = 4096
    while True:
        packet = s.recv(buf_size)
        data.extend(packet)
        if len(packet) < buf_size:
            break
    return data


def decrypt_and_parse(credential: dict, ciphertext: str) -> dict:
    try:
        plaintext_b64 = kms_call(credential, ciphertext)
    except Exception as e:
        raise Exception(f"exception happened calling kms binary: {str(e)}")

    try:
        key_b64 = plaintext_b64.split(":")[1].strip()
        key_plaintext = base64.standard_b64decode(key_b64)
    except Exception as e:
        raise Exception(f"exception happened decoding decrypted text from kms call: {str(e)}")

    try:
        parsed = json.loads(key_plaintext)
    except json.JSONDecodeError as e:
        raise Exception("exception happened parsing plaintext key into json structure: {}".format(e))

    return parsed


def decrypt_and_parse_validator_keys(credential: dict, encrypted_validator_keys: List[str]) -> List[dict]:
    _logger.debug(f"decrypting Validator keys and writing into file: {encrypted_validator_keys}")
    num_of_keys = len(encrypted_validator_keys)
    parsed_validator_keys = []
    for idx, encrypted_validator_key in enumerate(encrypted_validator_keys):
        _logger.debug(f"{idx + 1} / {num_of_keys} - decrypting validator key")

        try:
            validator_key_dict = decrypt_and_parse(credential, encrypted_validator_key)
        except Exception as e:
            raise e

        try:
            validator_key_plaintext = base64.standard_b64decode(validator_key_dict["keystore_b64"]).decode()
            validator_key_password_plaintext = base64.standard_b64decode(validator_key_dict["password_b64"]).decode()
        except Exception as e:
            raise Exception(f"exception happened decoding b64 representation of key artifacts: {str(e)}")

        try:
            validator_key_dict = json.loads(validator_key_plaintext)
        except json.JSONDecodeError as e:
            raise Exception("exception happened parsing validator key plaintext into json structure: {}".format(e))

        pubkey = validator_key_dict["pubkey"]

        _logger.debug(f"{idx + 1} / {num_of_keys} - pubkey - {pubkey}")

        pubkey_short = pubkey[0:10]
        parsed_validator_key = {
            "key_suffix": pubkey_short,
            "validator_key_password": validator_key_password_plaintext,
            "validator_key": validator_key_plaintext,
        }

        parsed_validator_keys.append(parsed_validator_key)

    return parsed_validator_keys


def persist_validator_keys(path: str, parsed_validator_keys: List[dict]) -> None:
    num_of_keys = len(parsed_validator_keys)
    for idx, parsed_validator_key in enumerate(parsed_validator_keys):
        key_suffix = parsed_validator_key["key_suffix"]
        password_filepath = f"{path}/{key_suffix}.password"
        keystore_filepath = f"{path}/{key_suffix}_keystore.json"
        key_config_filepath = f"/app/key_files/{key_suffix}_config.yaml"

        _logger.debug(f"{idx + 1} / {num_of_keys} - writing key password to {password_filepath}")
        try:
            with open(password_filepath, "w") as f:
                f.write(parsed_validator_key["validator_key_password"])

            _logger.debug(f"{idx + 1} / {num_of_keys} - writing keystore to {keystore_filepath}")
            with open(keystore_filepath, "w") as f:
                f.write(parsed_validator_key["validator_key"])

            key_config = {
                "type": "file-keystore",
                "keyType": "BLS",
                "keystoreFile": keystore_filepath,
                "keystorePasswordFile": password_filepath,
            }

            _logger.debug(f"{idx + 1} / {num_of_keys} - writing config to {key_config_filepath}")
            with open(key_config_filepath, "w") as f:
                yaml.dump(key_config, f)

            _logger.debug(f"{idx + 1} / {num_of_keys} - completed writing files")

        except OSError as e:
            raise e


def ensure_web3signer_healthiness(pid: int) -> bool:
    try:
        # subprocesses can be evaluated e.g. jstack for java
        p = psutil.Process(pid=pid)
    except Exception as e:
        raise e
    _logger.debug(f"web3signer process (pid: {pid}) healthy with status: {p.status()}")

    # web3signer main thread sleeps after all java modules have been started
    if p.status() not in ["running", "sleeping"]:
        _logger.error(f"web3signer process (pid: {pid}) not healthy with status: {p.status()}")
        return False

    return True
