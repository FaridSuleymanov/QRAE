from qrae.core import Finding, classify_primitive, score_finding
from qrae.reports import findings_to_markdown, findings_to_sarif


def test_markdown_report_contains_target():
    finding = Finding(target="example.org:443", protocol="tls")
    finding.add(classify_primitive("rsa", 2048, "signature"))
    finding.risk = score_finding(finding)
    report = findings_to_markdown([finding])
    assert "example.org:443" in report
    assert "migrate_to_pqc" in report


def test_sarif_report_shape():
    finding = Finding(target="example.org:443", protocol="tls")
    finding.add(classify_primitive("rsa", 2048, "signature"))
    sarif = findings_to_sarif([finding])
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
