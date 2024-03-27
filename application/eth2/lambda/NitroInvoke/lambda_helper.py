#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import ipaddress
import typing
import logging
import os
import base64
import boto3
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
logging.basicConfig(format=LOG_FORMAT)
handler = logging.StreamHandler()

_logger = logging.getLogger("nitro_invoke")
_logger.setLevel(LOG_LEVEL)
_logger.addHandler(handler)
_logger.propagate = False

dynamodb = boto3.resource("dynamodb")
client_kms = boto3.client("kms")

TLS_CERT_PATH = "/tmp/tls-cert.pem"  # nosec


def generate_selfsigned_cert(
    hostname: str, ip_addresses: list, key: EllipticCurvePrivateKey, password: bytes
) -> typing.Tuple[bytes, bytes, bytes]:
    """Generates self signed certificate for a hostname, and optional IP addresses."""

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
    alt_names = [x509.DNSName(hostname), x509.DNSName("localhost")]

    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))

    san = x509.SubjectAlternativeName(alt_names)

    # path_len=0 means this cert can only sign itself, not other certs.
    basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_constraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_key_p12 = pkcs12.serialize_key_and_certificates(
        b"signer",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(password),
    )

    return cert_pem, key_pem, cert_key_p12


def generate_ec_key_from_kms(key_id: str) -> ec.EllipticCurvePrivateKey:
    """Get data key pair from KMS and formats the key"""

    response = client_kms.generate_data_key_pair(
        KeyId=key_id,
        KeyPairSpec="ECC_NIST_P256",
    )

    private_key_der = response["PrivateKeyPlaintext"]
    # private_key_plaintext_b64 = base64.b64encode(private_key_der).decode()
    # private_key_ciphertext_b64 = base64.b64encode(response["PrivateKeyCiphertextBlob"]).decode()
    # pubkey = base64.b64encode(response["PublicKey"]).decode()

    loaded_private_key = serialization.load_der_private_key(
        private_key_der, password=None
    )

    if not isinstance(loaded_private_key, ec.EllipticCurvePrivateKey):
        raise Exception("Key provided is not EllipticCurve")

    return loaded_private_key


def retrieve_and_write_tls_cert(tls_keys_table, key_id=1):
    """Get TLS Cert PEM file from DynamoDB and write to temporary storage"""

    try:
        ddb_response = tls_keys_table.get_item(Key={"key_id": key_id})
        record = ddb_response.get("Item", None)
        if not record:
            raise "TLS key information not found"

        cert_pem_b64 = record["cert_pem"]

        cert_pem = base64.b64decode(cert_pem_b64)

        with open(TLS_CERT_PATH, "wb") as f:
            f.write(cert_pem)

        _logger.info(f"Written TLS certificate file to {TLS_CERT_PATH}")

    except Exception as e:
        raise Exception("exception happened: {}".format(e))
