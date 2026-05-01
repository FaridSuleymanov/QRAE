from qrae.protocols.code_scan import scan_code_path


def test_code_scan_finds_rsa_hint(tmp_path):
    sample = tmp_path / "config.txt"
    sample.write_text("-----BEGIN RSA PRIVATE KEY-----\n...\n", encoding="utf-8")
    findings = scan_code_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].primitives[0].family == "rsa"
