"""X.509 certificate-chain analysis for QRAE."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

from qrae.core import Primitive, classify_primitive

_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def load_pem_chain(pem_data: str | bytes) -> list[x509.Certificate]:
    raw = pem_data.encode("utf-8") if isinstance(pem_data, str) else pem_data
    certs: list[x509.Certificate] = []
    for match in _PEM_CERT_RE.finditer(raw):
        certs.append(x509.load_pem_x509_certificate(match.group(0)))
    return certs


def load_der_certificate(der_data: bytes) -> x509.Certificate:
    return x509.load_der_x509_certificate(der_data)


def public_key_to_primitive(public_key: Any, *, role: str = "signature") -> Primitive:
    if isinstance(public_key, rsa.RSAPublicKey):
        return classify_primitive("rsa", public_key.key_size, role)
    if isinstance(public_key, dsa.DSAPublicKey):
        return classify_primitive("dsa", public_key.key_size, role)
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return classify_primitive(
            public_key.curve.name,
            public_key.curve.key_size,
            role,
            name=f"ECDSA-{public_key.curve.name}",
        )
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return classify_primitive("ed25519", 256, role, name="Ed25519")
    if isinstance(public_key, ed448.Ed448PublicKey):
        return classify_primitive("ed448", 448, role, name="Ed448")
    return classify_primitive(type(public_key).__name__, None, role)


def certificate_primitives(cert: x509.Certificate, *, position: int) -> list[Primitive]:
    primitives = [public_key_to_primitive(cert.public_key(), role="certificate_public_key")]

    sig_name = cert.signature_algorithm_oid._name.lower()
    if "rsa" in sig_name:
        primitives.append(classify_primitive("rsa", None, "certificate_signature", name=sig_name))
    elif "ecdsa" in sig_name:
        primitives.append(classify_primitive("ecdsa", None, "certificate_signature", name=sig_name))
    elif "ed25519" in sig_name:
        primitives.append(classify_primitive("ed25519", 256, "certificate_signature", name=sig_name))
    elif "ed448" in sig_name:
        primitives.append(classify_primitive("ed448", 448, "certificate_signature", name=sig_name))
    else:
        primitives.append(classify_primitive(sig_name, None, "certificate_signature"))

    if cert.signature_hash_algorithm is not None:
        primitives.append(
            classify_primitive(
                cert.signature_hash_algorithm.name,
                getattr(cert.signature_hash_algorithm, "digest_size", 0) * 8,
                "certificate_signature_hash",
            )
        )

    for primitive in primitives:
        primitive.metadata["certificate_position"] = position  # type: ignore[index]

    return primitives


def certificate_record(cert: x509.Certificate, *, position: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc

    is_ca = False
    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(basic_constraints.ca)
    except x509.ExtensionNotFound:
        pass

    return {
        "position": position,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number_hex": hex(cert.serial_number),
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": not_after.isoformat(),
        "days_to_expiry": int((not_after - now).total_seconds() // 86400),
        "is_ca": is_ca,
        "self_issued": cert.subject == cert.issuer,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "signature_hash_algorithm": cert.signature_hash_algorithm.name
        if cert.signature_hash_algorithm is not None
        else None,
    }


def analyze_certificate_chain(certs: list[x509.Certificate]) -> tuple[list[dict[str, Any]], list[Primitive]]:
    records: list[dict[str, Any]] = []
    primitives: list[Primitive] = []
    for index, cert in enumerate(certs):
        records.append(certificate_record(cert, position=index))
        primitives.extend(certificate_primitives(cert, position=index))
    return records, primitives
