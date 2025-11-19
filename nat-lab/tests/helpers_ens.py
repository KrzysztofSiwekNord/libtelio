import base64
import hashlib
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

from utils.connection import Connection

CERT_PATH = "/etc/ca-certificates/server-cert.pem.test"


async def _read_remote_file(nlx_conn: Connection, path: str) -> str:
    proc = nlx_conn.create_process(["cat", path])
    output = await proc.execute()
    return output.get_stdout()


def _load_pem_chain(pem_data: str) -> List[x509.Certificate]:
    certs: List[x509.Certificate] = []
    block = []
    in_cert = False

    for line in pem_data.splitlines(keepends=True):
        if "BEGIN CERTIFICATE" in line:
            in_cert = True
            block = [line]
        elif "END CERTIFICATE" in line:
            block.append(line)
            pem_block = "".join(block).encode("ascii")
            cert = x509.load_pem_x509_certificate(pem_block)
            certs.append(cert)
            in_cert = False
            block = []
        elif in_cert:
            block.append(line)

    if not certs:
        raise ValueError("No certificates found in PEM data")

    return certs


def _find_root_cert(certs: List[x509.Certificate]) -> x509.Certificate:
    for cert in certs:
        try:
            bc = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            ).value
            is_ca = bc.ca
        except x509.ExtensionNotFound:
            is_ca = False

        if is_ca and cert.issuer == cert.subject:
            return cert

    return certs[-1]


async def get_grpc_tls_fingerprint_from_server(
    nlx_conn: Connection,
    cert_path: str = CERT_PATH,
) -> str:
    pem = await _read_remote_file(nlx_conn, cert_path)
    certs = _load_pem_chain(pem)

    leaf_cert = certs[0]
    leaf_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(leaf_der).hexdigest()
    return fingerprint


async def get_grpc_tls_root_certificate_from_server(
    nlx_conn: Connection,
    cert_path: str = CERT_PATH,
) -> str:
    pem = await _read_remote_file(nlx_conn, cert_path)
    certs = _load_pem_chain(pem)

    root_cert = _find_root_cert(certs)
    root_der = root_cert.public_bytes(serialization.Encoding.DER)

    encoded = base64.b64encode(root_der).decode("ascii")
    return encoded
