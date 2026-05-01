"""Quantum vulnerability classifier.

Maps (family, parameter_bits) pairs to vulnerability class per:

    NIST FIPS 203   — ML-KEM (Module-Lattice KEM)
    NIST FIPS 204   — ML-DSA (Module-Lattice DSA)
    NIST FIPS 205   — SLH-DSA (Stateless Hash-based DSA)
    NIST SP 800-208 — stateful hash-based signatures
    CNSA 2.0        — NSA commercial algorithm suite

The classifier is deliberately conservative: unknown primitives route to
UNKNOWN (not RESISTANT). Manual review is expected for anything outside
the known set.
"""

from __future__ import annotations

from .findings import Primitive, Vulnerability, AttackClass


# Classical asymmetric primitives broken by Shor's algorithm.
_SHOR_VULNERABLE = {
    "rsa", "dsa", "dh", "ecdh", "ecdsa",
    "ed25519", "ed448", "x25519", "x448",
}

# Symmetric and hash primitives weakened (not broken) by Grover's —
# effective security halves. AES-256 → 128-bit effective, still OK.
# AES-128 → 64-bit effective, not OK.
_GROVER_WEAKENED = {
    "aes", "chacha20", "chacha20-poly1305",
    "sha256", "sha384", "sha512", "sha3", "blake2", "blake3",
}

# Post-quantum primitives (FIPS 203/204/205 + NIST round 4 candidates).
_PQC_RESISTANT = {
    "ml-kem", "ml-dsa", "slh-dsa",
    "kyber", "dilithium", "sphincs+", "falcon",
    "hqc", "classic-mceliece", "bike", "frodo",
    "xmss", "lms",  # stateful hash-based (SP 800-208)
}


def classify(family: str, bits: int | None, role: str, name: str = "") -> Primitive:
    """Classify a single cryptographic primitive.

    Args:
        family: lowercase family token e.g. "rsa", "ecdsa", "aes"
        bits: key / modulus / curve size in bits (None if not applicable)
        role: "key_exchange" | "signature" | "cipher" | "kdf" | "transport"
        name: display name — auto-generated if empty

    Returns:
        A fully classified Primitive ready to attach to a Finding.
    """
    f = family.lower()
    display = name or (f"{family.upper()}-{bits}" if bits else family.upper())

    if f in _SHOR_VULNERABLE:
        return Primitive(
            name=display,
            family=f,
            parameter_bits=bits,
            role=role,
            vulnerability=Vulnerability.BROKEN,
            attack_class=AttackClass.SHOR,
            notes=(
                "Broken by Shor's algorithm. Full key recovery once a "
                "cryptographically relevant quantum computer (CRQC) exists."
            ),
        )

    if f in _GROVER_WEAKENED:
        effective = (bits // 2) if bits else None
        tail = f"Effective security under Grover's: ~{effective} bits." if effective else "Effective security under Grover's halves."
        return Primitive(
            name=display,
            family=f,
            parameter_bits=bits,
            role=role,
            vulnerability=Vulnerability.WEAKENED,
            attack_class=AttackClass.GROVER,
            notes=(
                f"Grover's quadratic speedup applies. {tail} "
                "CNSA 2.0 requires ≥256-bit symmetric keys."
            ),
        )

    if f in _PQC_RESISTANT:
        return Primitive(
            name=display,
            family=f,
            parameter_bits=bits,
            role=role,
            vulnerability=Vulnerability.RESISTANT,
            attack_class=AttackClass.NONE,
            notes="Post-quantum primitive; no known quantum attack faster than classical.",
        )

    return Primitive(
        name=display,
        family=f,
        parameter_bits=bits,
        role=role,
        vulnerability=Vulnerability.UNKNOWN,
        attack_class=AttackClass.NONE,
        notes="Primitive not in LAIN's classifier table — manual review required.",
    )
