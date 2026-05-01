"""Asset-level risk scoring for QRAE findings."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any

from .models import Finding, PolicyStatus, Vulnerability


@dataclass(frozen=True)
class RiskInputs:
    exposure: str = "internal"  # internet | partner | internal | isolated
    data_sensitivity: str = "medium"  # low | medium | high | restricted
    confidentiality_years: int = 1
    business_criticality: str = "medium"  # low | medium | high | mission
    migration_complexity: str = "medium"  # low | medium | high
    compensating_controls: bool = False
    asset_owner: str = ""
    environment: str = ""


_BASE = {
    Vulnerability.UNPROTECTED: 38,
    Vulnerability.BROKEN: 32,
    Vulnerability.WEAKENED: 18,
    Vulnerability.UNKNOWN: 24,
    Vulnerability.RESISTANT: 4,
}

_EXPOSURE = {"internet": 22, "partner": 14, "internal": 8, "isolated": 2}
_SENSITIVITY = {"restricted": 20, "high": 15, "medium": 8, "low": 2}
_CRITICALITY = {"mission": 18, "high": 13, "medium": 7, "low": 2}
_COMPLEXITY = {"high": 10, "medium": 5, "low": 1}


def score_finding(finding: Finding, inputs: RiskInputs | None = None) -> dict[str, Any]:
    """Return an asset-level risk score from 0 to 100.

    The formula is deliberately transparent and easy to adjust. It is a triage
    score, not a formal risk model.
    """
    risk_inputs = inputs or RiskInputs()
    drivers: list[str] = []

    score = _BASE[finding.worst_case]
    drivers.append(f"base:{finding.worst_case.value}={score}")

    exposure_score = _EXPOSURE.get(risk_inputs.exposure, _EXPOSURE["internal"])
    score += exposure_score
    drivers.append(f"exposure:{risk_inputs.exposure}+{exposure_score}")

    sensitivity_score = _SENSITIVITY.get(
        risk_inputs.data_sensitivity, _SENSITIVITY["medium"]
    )
    score += sensitivity_score
    drivers.append(f"data_sensitivity:{risk_inputs.data_sensitivity}+{sensitivity_score}")

    criticality_score = _CRITICALITY.get(
        risk_inputs.business_criticality, _CRITICALITY["medium"]
    )
    score += criticality_score
    drivers.append(f"business_criticality:{risk_inputs.business_criticality}+{criticality_score}")

    complexity_score = _COMPLEXITY.get(
        risk_inputs.migration_complexity, _COMPLEXITY["medium"]
    )
    score += complexity_score
    drivers.append(f"migration_complexity:{risk_inputs.migration_complexity}+{complexity_score}")

    has_hndl = _has_harvest_now_decrypt_later_exposure(finding, risk_inputs)
    if has_hndl:
        score += 12
        drivers.append("long_lived_confidentiality+12")

    cert_expiry_bonus = _certificate_expiry_bonus(finding)
    if cert_expiry_bonus:
        score += cert_expiry_bonus
        drivers.append(f"certificate_expiry+{cert_expiry_bonus}")

    if any(p.policy_status == PolicyStatus.UNPROTECTED for p in finding.primitives):
        score += 10
        drivers.append("unprotected_transport+10")

    if risk_inputs.compensating_controls:
        score -= 10
        drivers.append("compensating_controls-10")

    score = max(0, min(100, score))
    priority = _priority(score)
    return {
        "score": score,
        "priority": priority,
        "drivers": drivers,
        "inputs": asdict(risk_inputs),
        "scored_at": datetime.now(timezone.utc).isoformat(),
    }


def _has_harvest_now_decrypt_later_exposure(finding: Finding, inputs: RiskInputs) -> bool:
    if inputs.confidentiality_years < 5:
        return False
    if inputs.data_sensitivity not in {"high", "restricted"}:
        return False
    return any(
        primitive.vulnerability in {Vulnerability.BROKEN, Vulnerability.WEAKENED}
        and primitive.role in {"key_exchange", "cipher", "transport"}
        for primitive in finding.primitives
    )


def _certificate_expiry_bonus(finding: Finding) -> int:
    chain = finding.metadata.get("certificate_chain")
    if not isinstance(chain, list) or not chain:
        return 0
    days = chain[0].get("days_to_expiry")
    if not isinstance(days, int):
        return 0
    if days < 0:
        return 12
    if days <= 14:
        return 8
    if days <= 45:
        return 4
    return 0


def _priority(score: int) -> str:
    if score >= 85:
        return "P0"
    if score >= 70:
        return "P1"
    if score >= 45:
        return "P2"
    return "P3"
