"""Tests for generic unprotected channel assessment."""

from qrae.core import Vulnerability
from qrae.protocols import assess_unprotected_channel


def test_unprotected_channel_assessment():
    finding = assess_unprotected_channel("channel-1", channel_type="rf-link")

    assert finding.target == "channel-1"
    assert finding.protocol == "rf-link"
    assert finding.worst_case == Vulnerability.UNPROTECTED
    assert finding.metadata["classical_risk"] == "high"
