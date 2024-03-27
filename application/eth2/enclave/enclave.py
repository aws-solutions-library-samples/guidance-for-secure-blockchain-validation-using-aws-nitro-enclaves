#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import socket
import time
from enclave_functions import (
    recvall,
    handle_response,
    start_vsock_proxy,
    start_web3signer,
    _logger,
    decrypt_and_parse,
    decrypt_and_parse_validator_keys,
    persist_validator_keys,
    ensure_web3signer_healthiness,
)


def main():
    _logger.info("Starting server...")

    # init status initially false
    init_state = False

    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Listen for connection from any CID
    cid = socket.VMADDR_CID_ANY

    # The port should match the client running in parent EC2 instance
    port = 5000

    # Bind the socket to CID and port
    s.bind((cid, port))

    # Listen for connection from client
    s.listen(128)

    web3signer_pid = -1

    while True:
        _logger.debug(f"init_state: {init_state}")
        c, _ = s.accept()

        try:
            payload = recvall(c)
        except Exception as e:
            msg = f"error happened receiving datagram from vsock socket: {str(e)}"
            _logger.error(msg)
            handle_response(c, {"error": msg}, 500)
            continue

        if len(payload) == 0:
            _logger.debug("empty request - skipping")
            continue

        try:
            payload_json = json.loads(payload.decode())
        except Exception as e:
            msg = f"error happened loading json request (payload: {str(payload)}): {str(e)}"
            _logger.warning(msg)
            handle_response(c, {"error": msg}, 400)
            continue

        _logger.debug(f"payload json: {str(payload_json)}")

        if payload_json["operation"] == "init_state":
            content = {"init_state": init_state}

            _logger.info(f"init_state: {init_state}")
            handle_response(c, content, 200)
            continue

        if payload_json["operation"] == "init" and not init_state:
            _logger.info("operation: init")
            _logger.debug(f"payload json: {str(payload_json)}")

            if not (
                    payload_json.get("credential")
                    and payload_json.get("encrypted_tls_key")
                    and payload_json.get("encrypted_validator_keys")
            ):
                msg = "init operation requires credential, encrypted_tls_key and encrypted_validator_keys parameters to be set"
                _logger.warning(msg)
                handle_response(c, {"error": msg}, 400)
                continue

            credential = payload_json["credential"]
            encrypted_tls_key = payload_json["encrypted_tls_key"]
            encrypted_validator_keys_passwords_mnemonics = payload_json[
                "encrypted_validator_keys"
            ]

            _logger.debug("decrypting TLS key and writing into file")
            try:
                tls_key_dict = decrypt_and_parse(credential, encrypted_tls_key)

                tls_password = base64.standard_b64decode(
                    tls_key_dict["tls_password_b64"]
                ).decode()
                # no decode since binary data - cat keystore.p12 | base64
                tls_keystore = base64.standard_b64decode(
                    tls_key_dict["tls_keystore_b64"]
                )
            except Exception as e:
                msg = f"exception happened handling tls key artifacts: {str(e)}"
                _logger.error(msg)
                handle_response(c, {"error": msg}, 500)
                continue

            try:
                validator_keys_parsed = decrypt_and_parse_validator_keys(
                    credential, encrypted_validator_keys_passwords_mnemonics
                )
            except Exception as e:
                msg = f"exception happened decrypting and parsing validator keys: {str(e)}"
                _logger.error(msg)
                handle_response(c, {"error": msg}, 500)
                continue

            try:
                with open("/app/certs/keyStore.password", "w") as f:
                    f.write(tls_password)

                # binary mode for keystore
                with open("/app/certs/keyStore.p12", "wb") as f:
                    f.write(tls_keystore)

                persist_validator_keys("/app/key_files", validator_keys_parsed)

            except Exception as e:
                msg = f"error happened writing config artifact to enclave ephemeral storage: {str(e)}"
                _logger.error(msg)
                handle_response(c, {"error": msg}, 500)
                continue

            try:
                web3signer_pid, web3singer_exit_code = start_web3signer()
                if web3signer_pid == -1 or web3singer_exit_code:
                    raise Exception(
                        f"web3signer process was exited with code: {web3singer_exit_code}"
                    )
            except Exception as e:
                msg = f"exception happened starting web3signer: {str(e)}"
                _logger.error(msg)
                handle_response(c, {"error": msg}, 500)
                continue

            init_state = True
            content = {"init_state": init_state}
            _logger.info("enclave has been initiated")
            handle_response(c, content, 200)

            _logger.debug(
                f"web3signer process has been started with pid: {web3signer_pid}"
            )
            _logger.info("starting vsock proxy")
            try:
                start_vsock_proxy(s)
            except Exception as e:
                _logger.fatal(f"exception happened starting vsock proxy: {str(e)}")
            break

    # run process watchdog in main thread
    while True:
        if not ensure_web3signer_healthiness(web3signer_pid):
            _logger.fatal(
                "web3signer process got interrupted - container reboot required"
            )

        time.sleep(60)


if __name__ == "__main__":
    main()
