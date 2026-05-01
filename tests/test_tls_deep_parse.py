from qrae.core import Finding, PolicyStatus
from qrae.protocols.tls_deep import enrich_from_openssl_output, parse_openssl_summary


def test_parse_openssl_summary_cipher_and_temp_key():
    output = """
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Server Temp Key: X25519, 253 bits
OCSP response: no response sent
"""
    summary = parse_openssl_summary(output)
    assert summary["protocol"] == "TLSv1.3"
    assert summary["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert summary["server_temp_key"] == "X25519, 253 bits"


def test_enrich_adds_temp_key_primitive():
    finding = Finding(target="example.org:443", protocol="tls-deep")
    enrich_from_openssl_output(finding, "Server Temp Key: X25519, 253 bits\n")
    assert any(p.family == "x25519" for p in finding.primitives)
    assert any(p.policy_status == PolicyStatus.MIGRATE_TO_PQC for p in finding.primitives)
