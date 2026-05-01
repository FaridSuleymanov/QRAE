"""TLS endpoint assessment for QRAE."""

from __future__ import annotations

import socket
import ssl
from typing import Any

from qrae.core import Finding, Primitive, classify_primitive

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


def _cipher_to_primitive(cipher_name: str) -> Primitive | None:
    normalized = cipher_name.upper()
    for token, (family, bits) in _CIPHER_TOKENS:
        if token in normalized:
            return classify_primitive(family, bits, "cipher", name=cipher_name)
    return None


def _public_key_to_primitive(public_key: Any) -> Primitive:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

    if isinstance(public_key, rsa.RSAPublicKey):
        return classify_primitive("rsa", public_key.key_size, "signature")
    if isinstance(public_key, dsa.DSAPublicKey):
        return classify_primitive("dsa", public_key.key_size, "signature")
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return classify_primitive(
            "ecdsa",
            public_key.curve.key_size,
            "signature",
            name=f"ECDSA-{public_key.curve.name}",
        )
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return classify_primitive("ed25519", 256, "signature", name="Ed25519")
    if isinstance(public_key, ed448.Ed448PublicKey):
        return classify_primitive("ed448", 448, "signature", name="Ed448")
    return classify_primitive(type(public_key).__name__, None, "signature")


def scan_tls_endpoint(
    host: str,
    *,
    port: int = 443,
    sni: str | None = None,
    timeout: float = 5.0,
) -> Finding:
    """Connect to a TLS endpoint and classify visible cryptographic primitives.

    The standard-library TLS API does not expose every handshake detail. In
    particular, TLS 1.3 key-exchange group extraction requires packet capture or
    a lower-level parser. This function therefore reports only what it can verify:
    negotiated cipher metadata and certificate public-key type.
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
                cipher_primitive = _cipher_to_primitive(cipher[0])
                if cipher_primitive is not None:
                    finding.add(cipher_primitive)

            cert_der = tls_socket.getpeercert(binary_form=True)
            if cert_der:
                from cryptography import x509

                certificate = x509.load_der_x509_certificate(cert_der)
                finding.metadata["certificate"] = {
                    "subject": certificate.subject.rfc4514_string(),
                    "issuer": certificate.issuer.rfc4514_string(),
                    "not_valid_before": certificate.not_valid_before_utc.isoformat(),
                    "not_valid_after": certificate.not_valid_after_utc.isoformat(),
                }
                finding.add(_public_key_to_primitive(certificate.public_key()))

    if finding.metadata.get("tls_version") == "TLSv1.3":
        finding.metadata["limitations"] = [
            "TLS 1.3 key-exchange group is not exposed by Python ssl; use PCAP/raw handshake parser for full inventory."
        ]

    return finding
