"""Basic TLS endpoint assessment for QRAE."""

from __future__ import annotations

import socket
import ssl

from qrae.core import Finding, Primitive, classify_primitive
from qrae.protocols.x509_chain import analyze_certificate_chain, load_der_certificate

_CIPHER_TOKENS: tuple[tuple[str, tuple[str, int]], ...] = (
    ("CHACHA20_POLY1305", ("chacha20-poly1305", 256)),
    ("CHACHA20", ("chacha20", 256)),
    ("AES_256_GCM", ("aes", 256)),
    ("AES_128_GCM", ("aes", 128)),
    ("AES_256_CCM", ("aes", 256)),
    ("AES_128_CCM", ("aes", 128)),
    ("AES256", ("aes", 256)),
    ("AES128", ("aes", 128)),
)


def cipher_to_primitive(cipher_name: str) -> Primitive | None:
    normalized = cipher_name.upper()
    for token, (family, bits) in _CIPHER_TOKENS:
        if token in normalized:
            return classify_primitive(family, bits, "cipher", name=cipher_name)
    return None


def scan_tls_endpoint(
    host: str,
    *,
    port: int = 443,
    sni: str | None = None,
    timeout: float = 5.0,
) -> Finding:
    """Connect to a TLS endpoint and classify visible primitives.

    This basic scanner uses Python's standard ssl API. For deeper inventory, use
    qrae.protocols.tls_deep.scan_tls_deep or the CLI option `qrae tls scan --deep`.
    """
    server_name = sni or host
    finding = Finding(target=f"{host}:{port}", protocol="tls")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=server_name) as tls_socket:
            cipher = tls_socket.cipher()
            finding.metadata["tls_version"] = tls_socket.version()
            finding.metadata["sni"] = server_name
            finding.metadata["cipher"] = {
                "name": cipher[0],
                "protocol": cipher[1],
                "secret_bits": cipher[2],
            } if cipher else None

            if cipher:
                cipher_primitive = cipher_to_primitive(cipher[0])
                if cipher_primitive is not None:
                    finding.add(cipher_primitive)

            cert_der = tls_socket.getpeercert(binary_form=True)
            if cert_der:
                certificate = load_der_certificate(cert_der)
                records, primitives = analyze_certificate_chain([certificate])
                finding.metadata["certificate_chain"] = records
                finding.extend(primitives)

    if finding.metadata.get("tls_version") == "TLSv1.3":
        finding.metadata["limitations"] = [
            "TLS 1.3 key-exchange group is not exposed by Python ssl; use deep/OpenSSL or raw handshake parser for fuller inventory."
        ]

    return finding
