"""Active TLS probe.

Connects to a target as a TLS client, negotiates the best handshake the
server offers, and extracts cryptographic primitives from both the
negotiated session and the server certificate.

Limitations (addressed in later iterations):
    * Python's stdlib ssl module does not expose the negotiated NamedGroup
      in TLS 1.3. For the key-exchange primitive, use PCAP mode or a raw
      ClientHello parser.
    * The probe connects as a client; it does not test server-side
      supported cipher lists exhaustively. For that, cycle through
      restricted contexts (see `probe_matrix` — planned).
"""

from __future__ import annotations

import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from ..core.classify import classify
from ..core.findings import Finding, Primitive


# Cipher-name token → (family, bits). Order matters: check longer tokens first.
_CIPHER_FAMILIES: list[tuple[str, tuple[str, int]]] = [
    ("AES_256_GCM", ("aes", 256)),
    ("AES_128_GCM", ("aes", 128)),
    ("AES_256_CCM", ("aes", 256)),
    ("AES_128_CCM", ("aes", 128)),
    ("AES256", ("aes", 256)),
    ("AES128", ("aes", 128)),
    ("CHACHA20_POLY1305", ("chacha20-poly1305", 256)),
    ("CHACHA20", ("chacha20", 256)),
]


def _cipher_to_primitive(cipher_name: str) -> Primitive | None:
    for token, (family, bits) in _CIPHER_FAMILIES:
        if token in cipher_name:
            return classify(family, bits, "cipher", name=cipher_name)
    return None


def _pubkey_to_primitive(pubkey) -> Primitive:
    if isinstance(pubkey, rsa.RSAPublicKey):
        return classify("rsa", pubkey.key_size, "signature")
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return classify(
            "ecdsa",
            pubkey.curve.key_size,
            "signature",
            name=f"ECDSA-{pubkey.curve.name}",
        )
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return classify("ed25519", 256, "signature", name="Ed25519")
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return classify("ed448", 448, "signature", name="Ed448")
    if isinstance(pubkey, dsa.DSAPublicKey):
        return classify("dsa", pubkey.key_size, "signature")
    return classify("unknown", None, "signature", name=type(pubkey).__name__)


def probe(host: str, port: int, timeout: float = 5.0, sni: str | None = None) -> Finding:
    """Active TLS probe. Returns a Finding with the negotiated primitives."""
    ctx = ssl.create_default_context()
    # We're characterizing the endpoint, not validating it.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    finding = Finding(target=f"{host}:{port}", protocol="tls")
    server_hostname = sni or host

    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            cipher = tls.cipher()  # (name, version, bits) or None
            finding.metadata["tls_version"] = tls.version()
            finding.metadata["cipher_name"] = cipher[0] if cipher else None
            finding.metadata["cipher_secret_bits"] = cipher[2] if cipher else None
            finding.metadata["sni"] = server_hostname

            if cipher:
                prim = _cipher_to_primitive(cipher[0])
                if prim:
                    finding.primitives.append(prim)

            der = tls.getpeercert(binary_form=True)
            if der:
                cert = x509.load_der_x509_certificate(der)
                finding.metadata["subject"] = cert.subject.rfc4514_string()
                finding.metadata["issuer"] = cert.issuer.rfc4514_string()
                finding.metadata["not_valid_after"] = cert.not_valid_after_utc.isoformat()
                finding.primitives.append(_pubkey_to_primitive(cert.public_key()))

    if finding.metadata.get("tls_version") == "TLSv1.3":
        finding.metadata["note"] = (
            "TLS 1.3 NamedGroup not exposed by stdlib ssl — "
            "key-exchange primitive missing. Use PCAP mode for full coverage."
        )

    return finding
