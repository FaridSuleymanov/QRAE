"""ESPARGOS RF channel assessment.

The ESPARGOS phased-array channel carries IQ samples and beamforming weights
in the clear. There is no cryptographic layer to probe. LAIN's job here is
to state the obvious with a paper trail, classify it as UNPROTECTED (worse
than BROKEN — a classical adversary is sufficient), and emit a migration
recommendation aligned with CNSA 2.0 / FIPS 203.

This module is trivial on purpose. The value is in the audit entry: you
can point to a timestamped, hash-chained record showing you identified
the exposure before it was exploited.
"""

from __future__ import annotations

from ..core.findings import AttackClass, Finding, Primitive, Vulnerability


RECOMMENDATION = (
    "Recommended migration stack:\n"
    "  - Key establishment: ML-KEM-768 (FIPS 203)\n"
    "  - Bulk encryption:   AES-256-GCM\n"
    "  - Beacon / frame auth: ML-DSA-65 (FIPS 204)\n"
    "  - Rekey cadence:     per-session + periodic (≤1h active links)\n"
    "Classical adversary currently sufficient — quantum is irrelevant "
    "until a crypto layer exists."
)


def assess(channel_name: str = "espargos-default") -> Finding:
    f = Finding(target=channel_name, protocol="espargos")
    f.primitives.append(
        Primitive(
            name="none",
            family="none",
            parameter_bits=None,
            role="transport",
            vulnerability=Vulnerability.UNPROTECTED,
            attack_class=AttackClass.NONE,
            notes=(
                "ESPARGOS RF channel transmits IQ samples and beamforming "
                "weights with no confidentiality, integrity, or authentication. "
                + RECOMMENDATION
            ),
        )
    )
    f.metadata["priority"] = "P0"
    f.metadata["classical_risk"] = "high"
    f.metadata["quantum_risk"] = "n/a (no crypto to break)"
    f.metadata["recommendation"] = RECOMMENDATION
    return f
