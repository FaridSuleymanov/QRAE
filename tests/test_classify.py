"""Tests for the vulnerability classifier."""

from lain.core import AttackClass, Vulnerability, classify


def test_rsa_is_broken():
    p = classify("rsa", 2048, "signature")
    assert p.vulnerability == Vulnerability.BROKEN
    assert p.attack_class == AttackClass.SHOR
    assert p.parameter_bits == 2048


def test_ecdsa_is_broken():
    p = classify("ecdsa", 256, "signature")
    assert p.vulnerability == Vulnerability.BROKEN
    assert p.attack_class == AttackClass.SHOR


def test_aes256_is_weakened():
    p = classify("aes", 256, "cipher")
    assert p.vulnerability == Vulnerability.WEAKENED
    assert p.attack_class == AttackClass.GROVER
    assert "128 bits" in p.notes


def test_ml_kem_is_resistant():
    p = classify("ml-kem", 768, "key_exchange")
    assert p.vulnerability == Vulnerability.RESISTANT
    assert p.attack_class == AttackClass.NONE


def test_unknown_family_is_unknown():
    p = classify("snake-oil-sig", 256, "signature")
    assert p.vulnerability == Vulnerability.UNKNOWN


def test_case_insensitive_family():
    p = classify("RSA", 4096, "signature")
    assert p.vulnerability == Vulnerability.BROKEN


def test_ed25519_broken():
    p = classify("ed25519", 256, "signature")
    assert p.vulnerability == Vulnerability.BROKEN
    assert p.attack_class == AttackClass.SHOR
