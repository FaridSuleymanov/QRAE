"""Conservative post-quantum readiness classifier.

This module is intentionally simple. It is a first-pass inventory and triage
classifier, not a cryptographic certification engine.
"""

from __future__ import annotations

from .models import AttackClass, Primitive, Vulnerability

_SHOR_VULNERABLE = {
    "rsa",
    "dsa",
    "dh",
    "ecdh",
    "ecdsa",
    "ed25519",
    "ed448",
    "x25519",
    "x448",
}

_GROVER_AFFECTED = {
    "aes",
    "chacha20",
    "chacha20-poly1305",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3",
    "shake",
    "blake2",
    "blake3",
}

_PQC_RECOGNIZED = {
    "ml-kem",
    "ml-dsa",
    "slh-dsa",
    "kyber",
    "dilithium",
    "sphincs+",
    "falcon",
    "hqc",
    "classic-mceliece",
    "bike",
    "frodo",
    "xmss",
    "lms",
}

_UNPROTECTED = {
    "none",
    "plaintext",
    "cleartext",
    "no-crypto",
    "unauthenticated",
}


def _display_name(family: str, bits: int | None, name: str | None) -> str:
    if name:
        return name
    normalized = family.upper()
    return f"{normalized}-{bits}" if bits else normalized


def classify_primitive(
    family: str,
    bits: int | None,
    role: str,
    *,
    name: str | None = None,
) -> Primitive:
    """Classify a cryptographic primitive for quantum-readiness triage.

    Args:
        family: Primitive family token, for example ``rsa``, ``ecdsa``, ``aes``,
            ``ml-kem`` or ``none``.
        bits: Parameter size, key size, modulus size, or curve size in bits.
        role: Primitive role, for example ``signature``, ``key_exchange``,
            ``cipher``, ``hash`` or ``transport``.
        name: Optional display name used in output.

    Returns:
        A :class:`Primitive` with a conservative vulnerability classification.
    """
    normalized = family.strip().lower()
    display = _display_name(normalized, bits, name)

    if normalized in _UNPROTECTED:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.UNPROTECTED,
            attack_class=AttackClass.NONE,
            notes=(
                "No cryptographic confidentiality, integrity or authentication layer was "
                "identified. Classical protection should be addressed before quantum-specific "
                "migration is meaningful."
            ),
        )

    if normalized in _SHOR_VULNERABLE:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.BROKEN,
            attack_class=AttackClass.SHOR,
            notes=(
                "Asymmetric primitive affected by Shor's algorithm once a cryptographically "
                "relevant quantum computer exists. Include in post-quantum migration planning."
            ),
        )

    if normalized in _GROVER_AFFECTED:
        effective = bits // 2 if bits else None
        effective_note = (
            f" Estimated effective security under Grover's algorithm: ~{effective} bits."
            if effective is not None
            else " Grover's algorithm provides a quadratic search speedup."
        )
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.WEAKENED,
            attack_class=AttackClass.GROVER,
            notes=(
                "Symmetric or hash primitive affected by Grover's algorithm."
                f"{effective_note} Prefer >=256-bit symmetric security for long-term protection."
            ),
        )

    if normalized in _PQC_RECOGNIZED:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.RESISTANT,
            attack_class=AttackClass.NONE,
            notes=(
                "Recognized post-quantum or hash-based primitive in the current classifier table. "
                "Confirm parameter set, implementation maturity and deployment profile manually."
            ),
        )

    return Primitive(
        name=display,
        family=normalized,
        role=role,
        parameter_bits=bits,
        vulnerability=Vulnerability.UNKNOWN,
        attack_class=AttackClass.NONE,
        notes="Primitive family is not recognized by the current classifier table; manual review required.",
    )
