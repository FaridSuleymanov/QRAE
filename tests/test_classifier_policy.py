from qrae.core import PolicyStatus, StandardizationStatus, Vulnerability, classify_primitive


def test_ml_kem_is_standardized_pqc():
    p = classify_primitive("ml-kem", 768, "key_exchange")
    assert p.vulnerability == Vulnerability.RESISTANT
    assert p.standardization_status == StandardizationStatus.STANDARDIZED_PQC
    assert p.policy_status == PolicyStatus.APPROVED_PQC


def test_hqc_is_backup_pqc():
    p = classify_primitive("hqc", 128, "key_exchange")
    assert p.standardization_status == StandardizationStatus.SELECTED_BACKUP_PQC
    assert p.policy_status == PolicyStatus.BACKUP_PQC


def test_kyber_legacy_name_requires_review():
    p = classify_primitive("kyber768", None, "key_exchange")
    assert p.standardization_status == StandardizationStatus.LEGACY_PQC_NAME
    assert p.policy_status == PolicyStatus.REVIEW_REQUIRED


def test_x25519_mlkem_hybrid():
    p = classify_primitive("x25519mlkem768", None, "key_exchange")
    assert p.hybrid
    assert p.policy_status == PolicyStatus.HYBRID_PQC


def test_rsa_migration_required():
    p = classify_primitive("rsa", 2048, "signature")
    assert p.vulnerability == Vulnerability.BROKEN
    assert p.policy_status == PolicyStatus.MIGRATE_TO_PQC
