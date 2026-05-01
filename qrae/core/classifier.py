"""Policy-aware post-quantum readiness classifier.

The classifier is deliberately conservative. Unknown does not mean safe, and
legacy PQC names are not treated as equivalent to final standards without review.
"""

from __future__ import annotations

import re

from .models import (
    AttackClass,
    PolicyStatus,
    Primitive,
    StandardizationStatus,
    Vulnerability,
)

_SHOR_VULNERABLE = {
    "rsa",
    "dsa",
    "dh",
    "ffdhe",
    "ecdh",
    "ecdsa",
    "ed25519",
    "ed448",
    "x25519",
    "x448",
    "secp256r1",
    "prime256v1",
    "secp384r1",
    "secp521r1",
    "nistp256",
    "nistp384",
    "nistp521",
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

_STANDARDIZED_PQC = {
    "ml-kem",
    "ml-kem-512",
    "ml-kem-768",
    "ml-kem-1024",
    "ml-dsa",
    "ml-dsa-44",
    "ml-dsa-65",
    "ml-dsa-87",
    "slh-dsa",
    "slh-dsa-sha2-128s",
    "slh-dsa-sha2-128f",
    "slh-dsa-sha2-192s",
    "slh-dsa-sha2-192f",
    "slh-dsa-sha2-256s",
    "slh-dsa-sha2-256f",
}

_BACKUP_PQC = {
    "hqc",
    "hqc-128",
    "hqc-192",
    "hqc-256",
}

_LEGACY_PQC_NAMES = {
    "kyber",
    "kyber512",
    "kyber768",
    "kyber1024",
    "dilithium",
    "dilithium2",
    "dilithium3",
    "dilithium5",
    "sphincs+",
    "sphincsplus",
    "sphincs",
}

_EXPERIMENTAL_OR_NONSTANDARD = {
    "falcon",
    "classic-mceliece",
    "mceliece",
    "bike",
    "frodo",
    "frodo-kem",
    "ntru",
    "sike",
}

_UNPROTECTED = {
    "none",
    "plaintext",
    "cleartext",
    "no-crypto",
    "unauthenticated",
}

_WEAK_HASH = {"sha1", "md5"}
_WEAK_SYMMETRIC_THRESHOLD = 128


def normalize_family(family: str) -> str:
    value = family.strip().lower().replace("_", "-")
    value = re.sub(r"\s+", "-", value)
    aliases = {
        "rsaencryption": "rsa",
        "rsassa-pss": "rsa",
        "rsa-pss": "rsa",
        "ecdsa-with-sha256": "ecdsa",
        "ecdsa-with-sha384": "ecdsa",
        "ecdsa-with-sha512": "ecdsa",
        "ed25519ph": "ed25519",
        "ed448ph": "ed448",
        "x25519kyber768": "x25519-kyber768",
        "x25519mlkem768": "x25519-ml-kem-768",
        "x25519-mlkem768": "x25519-ml-kem-768",
        "p256-mlkem768": "secp256r1-ml-kem-768",
        "p384-mlkem1024": "secp384r1-ml-kem-1024",
    }
    return aliases.get(value, value)


def _display_name(family: str, bits: int | None, name: str | None) -> str:
    if name:
        return name
    display = family.upper()
    return f"{display}-{bits}" if bits else display


def _is_hybrid_pqc(family: str) -> bool:
    has_classical = any(token in family for token in ("x25519", "x448", "secp", "p256", "p384"))
    has_pqc = any(token in family for token in ("ml-kem", "mlkem", "kyber", "hqc"))
    return has_classical and has_pqc


def classify_primitive(
    family: str,
    bits: int | None,
    role: str,
    *,
    name: str | None = None,
) -> Primitive:
    """Classify a cryptographic primitive for PQC readiness and policy triage."""
    normalized = normalize_family(family)
    display = _display_name(normalized, bits, name)

    if _is_hybrid_pqc(normalized):
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.RESISTANT,
            attack_class=AttackClass.NONE,
            standardization_status=StandardizationStatus.STANDARDIZED_PQC
            if "ml-kem" in normalized or "mlkem" in normalized
            else StandardizationStatus.LEGACY_PQC_NAME,
            policy_status=PolicyStatus.HYBRID_PQC,
            hybrid=True,
            migration_hint="Verify exact hybrid group, library version, interoperability profile, and downgrade behavior.",
            notes="Hybrid classical + post-quantum construction observed or declared.",
        )

    if normalized in _UNPROTECTED:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.UNPROTECTED,
            attack_class=AttackClass.NONE,
            standardization_status=StandardizationStatus.NOT_APPLICABLE,
            policy_status=PolicyStatus.UNPROTECTED,
            migration_hint="Add authenticated encryption, key management, and replay protection before PQC migration planning.",
            notes="No cryptographic confidentiality, integrity or authentication layer was identified.",
        )

    if normalized in _SHOR_VULNERABLE:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.BROKEN,
            attack_class=AttackClass.SHOR,
            standardization_status=StandardizationStatus.CLASSICAL_LEGACY,
            policy_status=PolicyStatus.MIGRATE_TO_PQC,
            migration_hint="Replace or hybridize with approved PQC where protocol support exists; prioritize long-lived confidentiality.",
            notes="Classical asymmetric primitive affected by Shor's algorithm once CRQC exists.",
        )

    if normalized in _GROVER_AFFECTED:
        weak = normalized in _WEAK_HASH or (bits is not None and bits <= _WEAK_SYMMETRIC_THRESHOLD)
        effective = bits // 2 if bits else None
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.WEAKENED,
            attack_class=AttackClass.GROVER,
            standardization_status=StandardizationStatus.SYMMETRIC_OR_HASH,
            policy_status=PolicyStatus.WEAK_PARAMETERS if weak else PolicyStatus.ACCEPTABLE_WITH_PARAMETERS,
            migration_hint="Prefer >=256-bit symmetric security for long-term confidentiality; remove SHA-1/MD5.",
            notes=(
                "Symmetric/hash primitive affected by Grover's algorithm."
                + (f" Estimated effective security: ~{effective} bits." if effective is not None else "")
            ),
        )

    if normalized in _STANDARDIZED_PQC:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.RESISTANT,
            attack_class=AttackClass.NONE,
            standardization_status=StandardizationStatus.STANDARDIZED_PQC,
            policy_status=PolicyStatus.APPROVED_PQC,
            migration_hint="Verify approved parameter set, implementation maturity, side-channel posture, and protocol profile.",
            notes="Recognized NIST-standardized post-quantum family in the current QRAE policy table.",
        )

    if normalized in _BACKUP_PQC:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.RESISTANT,
            attack_class=AttackClass.NONE,
            standardization_status=StandardizationStatus.SELECTED_BACKUP_PQC,
            policy_status=PolicyStatus.BACKUP_PQC,
            migration_hint="Treat as backup/contingency PQC; confirm organizational policy before production use.",
            notes="Recognized as backup/selected PQC in the current QRAE policy table.",
        )

    if normalized in _LEGACY_PQC_NAMES:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.RESISTANT,
            attack_class=AttackClass.NONE,
            standardization_status=StandardizationStatus.LEGACY_PQC_NAME,
            policy_status=PolicyStatus.REVIEW_REQUIRED,
            migration_hint="Map legacy/draft name to final standard name and verify parameter compatibility.",
            notes="Legacy or pre-standard PQC name observed; do not assume final-standard compliance without review.",
        )

    if normalized in _EXPERIMENTAL_OR_NONSTANDARD:
        return Primitive(
            name=display,
            family=normalized,
            role=role,
            parameter_bits=bits,
            vulnerability=Vulnerability.UNKNOWN,
            attack_class=AttackClass.NONE,
            standardization_status=StandardizationStatus.LEGACY_FINALIST_OR_EXPERIMENTAL,
            policy_status=PolicyStatus.REVIEW_REQUIRED,
            migration_hint="Requires cryptographic and policy review before production migration reliance.",
            notes="Experimental, finalist, non-standard, or not-currently-approved PQC family in this policy table.",
        )

    return Primitive(
        name=display,
        family=normalized,
        role=role,
        parameter_bits=bits,
        vulnerability=Vulnerability.UNKNOWN,
        attack_class=AttackClass.NONE,
        standardization_status=StandardizationStatus.UNKNOWN,
        policy_status=PolicyStatus.REVIEW_REQUIRED,
        migration_hint="Manual cryptographic review required.",
        notes="Primitive family is not recognized by the current classifier table.",
    )
