"""Tests for finding model serialization and severity ordering."""

from qrae.core import Finding, Vulnerability, classify_primitive


def test_finding_worst_case_prefers_unprotected():
    finding = Finding(target="channel-1", protocol="test")
    finding.add(classify_primitive("ml-kem", 768, "key_exchange"))
    finding.add(classify_primitive("none", None, "transport"))

    assert finding.worst_case == Vulnerability.UNPROTECTED


def test_finding_to_dict_uses_enum_values():
    finding = Finding(target="example.org:443", protocol="tls")
    finding.add(classify_primitive("rsa", 2048, "signature"))

    payload = finding.to_dict()
    assert payload["worst_case"] == "broken"
    assert payload["primitives"][0]["vulnerability"] == "broken"
    assert payload["primitives"][0]["attack_class"] == "shor"
