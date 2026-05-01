"""Generic channel assessment helpers."""

from __future__ import annotations

from qrae.core import Finding, classify_primitive


def assess_unprotected_channel(
    name: str,
    *,
    channel_type: str = "data-channel",
    recommendation: str | None = None,
) -> Finding:
    finding = Finding(target=name, protocol=channel_type)
    finding.add(classify_primitive("none", None, "transport", name="No cryptographic protection"))
    finding.metadata["channel_type"] = channel_type
    finding.metadata["priority_reason"] = (
        "No confidentiality, integrity or authentication layer was identified."
    )
    finding.metadata["recommendation"] = recommendation or (
        "Add authenticated encryption, mutual authentication, key management, replay protection, "
        "and then evaluate post-quantum migration options."
    )
    return finding
