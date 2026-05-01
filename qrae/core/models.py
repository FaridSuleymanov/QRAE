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


@dataclass(frozen=True)
class Primitive:
    """A single cryptographic primitive or absence of protection."""

    name: str
    family: str
    role: str
    vulnerability: Vulnerability
    attack_class: AttackClass
    parameter_bits: int | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family,
            "role": self.role,
            "parameter_bits": self.parameter_bits,
            "vulnerability": self.vulnerability.value,
            "attack_class": self.attack_class.value,
            "notes": self.notes,
        }


@dataclass
class Finding:
    """Assessment result for one target and protocol/channel."""

    target: str
    protocol: str
    primitives: list[Primitive] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = "qrae.finding.v1"

    def add(self, primitive: Primitive) -> None:
        self.primitives.append(primitive)

    @property
    def worst_case(self) -> Vulnerability:
        """Return the highest-severity classification present in the finding."""
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
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "worst_case": self.worst_case.value,
            "primitives": [primitive.to_dict() for primitive in self.primitives],
            "metadata": self.metadata,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
