"""Assessment helpers for channels where no crypto layer is present."""

from __future__ import annotations

from qrae.core import Finding, classify_primitive


def assess_unprotected_channel(
    name: str,
    *,
    channel_type: str = "data-channel",
    recommendation: str | None = None,
) -> Finding:
    """Create a finding for a channel that currently lacks cryptographic protection."""
    finding = Finding(target=name, protocol=channel_type)
    finding.add(
        classify_primitive(
            "none",
            None,
            "transport",
            name="no cryptographic protection identified",
        )
    )
    finding.metadata["classical_risk"] = "high"
    finding.metadata["quantum_risk"] = "not applicable until a cryptographic layer exists"
    finding.metadata["recommendation"] = recommendation or (
        "Add authenticated encryption, key management and replay protection. For long-term "
        "systems, include post-quantum key establishment and signature migration planning."
    )
    return finding
