from qrae.core import Finding, RiskInputs, classify_primitive, score_finding


def test_internet_facing_long_lived_rsa_scores_high():
    finding = Finding(target="example.org:443", protocol="tls")
    finding.add(classify_primitive("rsa", 2048, "key_exchange"))
    finding.risk = score_finding(
        finding,
        RiskInputs(
            exposure="internet",
            data_sensitivity="high",
            confidentiality_years=10,
            business_criticality="high",
            migration_complexity="medium",
        ),
    )
    assert finding.risk["score"] >= 70
    assert finding.risk["priority"] in {"P0", "P1"}


def test_compensating_controls_reduce_score():
    finding = Finding(target="internal", protocol="tls")
    finding.add(classify_primitive("aes", 256, "cipher"))
    no_controls = score_finding(finding, RiskInputs(compensating_controls=False))["score"]
    controls = score_finding(finding, RiskInputs(compensating_controls=True))["score"]
    assert controls < no_controls
