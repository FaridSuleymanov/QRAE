"""Tests for conservative primitive classification."""

from qrae.core import AttackClass, Vulnerability, classify_primitive


def test_rsa_is_shor_broken():
    primitive = classify_primitive("rsa", 2048, "signature")
    assert primitive.vulnerability == Vulnerability.BROKEN
    assert primitive.attack_class == AttackClass.SHOR


def test_ecdsa_is_shor_broken():
    primitive = classify_primitive("ECDSA", 256, "signature")
    assert primitive.vulnerability == Vulnerability.BROKEN
    assert primitive.attack_class == AttackClass.SHOR


def test_aes256_is_grover_weakened():
    primitive = classify_primitive("aes", 256, "cipher")
    assert primitive.vulnerability == Vulnerability.WEAKENED
    assert primitive.attack_class == AttackClass.GROVER
    assert "128 bits" in primitive.notes


def test_ml_kem_is_recognized_as_resistant():
    primitive = classify_primitive("ml-kem", 768, "key_exchange")
    assert primitive.vulnerability == Vulnerability.RESISTANT
    assert primitive.attack_class == AttackClass.NONE


def test_none_is_unprotected():
    primitive = classify_primitive("none", None, "transport")
    assert primitive.vulnerability == Vulnerability.UNPROTECTED
    assert primitive.attack_class == AttackClass.NONE


def test_unknown_is_not_treated_as_safe():
    primitive = classify_primitive("custom-scheme", 256, "signature")
    assert primitive.vulnerability == Vulnerability.UNKNOWN
