"""Canonical data models for QRAE assessment output."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Vulnerability(str, Enum):
    """Conservative quantum-readiness classification."""

    UNPROTECTED = "unprotected"
    BROKEN = "broken"
    WEAKENED = "weakened"
    UNKNOWN = "unknown"
    RESISTANT = "resistant"


class AttackClass(str, Enum):
    """Quantum-relevant attack family used for classification."""

    SHOR = "shor"
    GROVER = "grover"
    NONE = "none"


class StandardizationStatus(str, Enum):
    """Policy/standardization state of a primitive family."""

    STANDARDIZED_PQC = "standardized_pqc"
    SELECTED_BACKUP_PQC = "selected_backup_pqc"
    LEGACY_PQC_NAME = "legacy_pqc_name"
    LEGACY_FINALIST_OR_EXPERIMENTAL = "legacy_finalist_or_experimental"
    CLASSICAL_LEGACY = "classical_legacy"
    SYMMETRIC_OR_HASH = "symmetric_or_hash"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class PolicyStatus(str, Enum):
    """Migration policy triage state."""

    APPROVED_PQC = "approved_pqc"
    BACKUP_PQC = "backup_pqc"
    HYBRID_PQC = "hybrid_pqc"
    MIGRATE_TO_PQC = "migrate_to_pqc"
    REVIEW_REQUIRED = "review_required"
    ACCEPTABLE_WITH_PARAMETERS = "acceptable_with_parameters"
    WEAK_PARAMETERS = "weak_parameters"
    UNPROTECTED = "unprotected"


@dataclass(frozen=True)
class Primitive:
    """A single cryptographic primitive or absence of protection."""

    name: str
    family: str
    role: str
    vulnerability: Vulnerability
    attack_class: AttackClass
    parameter_bits: int | None = None
    standardization_status: StandardizationStatus = StandardizationStatus.UNKNOWN
    policy_status: PolicyStatus = PolicyStatus.REVIEW_REQUIRED
    hybrid: bool = False
    migration_hint: str = ""
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family,
            "role": self.role,
            "parameter_bits": self.parameter_bits,
            "vulnerability": self.vulnerability.value,
            "attack_class": self.attack_class.value,
            "standardization_status": self.standardization_status.value,
            "policy_status": self.policy_status.value,
            "hybrid": self.hybrid,
            "migration_hint": self.migration_hint,
            "notes": self.notes,
            "metadata": self.metadata,
        }


@dataclass
class Finding:
    """Assessment result for one target and protocol/channel."""

    target: str
    protocol: str
    primitives: list[Primitive] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    risk: dict[str, Any] | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = "qrae.finding.v2"

    def add(self, primitive: Primitive) -> None:
        self.primitives.append(primitive)

    def extend(self, primitives: list[Primitive]) -> None:
        self.primitives.extend(primitives)

    @property
    def worst_case(self) -> Vulnerability:
        severity_order = [
            Vulnerability.UNPROTECTED,
            Vulnerability.BROKEN,
            Vulnerability.WEAKENED,
            Vulnerability.UNKNOWN,
            Vulnerability.RESISTANT,
        ]
        present = {primitive.vulnerability for primitive in self.primitives}
        for severity in severity_order:
            if severity in present:
                return severity
        return Vulnerability.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "target": self.target,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "worst_case": self.worst_case.value,
            "primitives": [primitive.to_dict() for primitive in self.primitives],
            "metadata": self.metadata,
        }
        if self.risk is not None:
            payload["risk"] = self.risk
        return payload

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


def finding_from_dict(data: dict[str, Any]) -> Finding:
    """Rehydrate a Finding from JSON/dict output.

    This is intentionally tolerant so older qrae.finding.v1 outputs can still be
    consumed by reports.
    """
    finding = Finding(
        target=str(data.get("target", "unknown")),
        protocol=str(data.get("protocol", "unknown")),
        metadata=dict(data.get("metadata", {})),
        risk=data.get("risk"),
        timestamp=str(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
        schema_version=str(data.get("schema_version", "qrae.finding.v1")),
    )
    for item in data.get("primitives", []):
        primitive = Primitive(
            name=str(item.get("name", "unknown")),
            family=str(item.get("family", "unknown")),
            role=str(item.get("role", "unknown")),
            parameter_bits=item.get("parameter_bits"),
            vulnerability=Vulnerability(item.get("vulnerability", "unknown")),
            attack_class=AttackClass(item.get("attack_class", "none")),
            standardization_status=StandardizationStatus(
                item.get("standardization_status", "unknown")
            ),
            policy_status=PolicyStatus(item.get("policy_status", "review_required")),
            hybrid=bool(item.get("hybrid", False)),
            migration_hint=str(item.get("migration_hint", "")),
            notes=str(item.get("notes", "")),
            metadata=dict(item.get("metadata", {})),
        )
        finding.add(primitive)
    return finding
