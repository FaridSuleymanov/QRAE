"""Authorization scope model for QRAE active assessment."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(RuntimeError):
    """Raised when an assessment is outside declared authorization scope."""


@dataclass(frozen=True)
class Scope:
    """Operator-declared assessment scope.

    This is not a strong security boundary. It is a workflow and accountability
    control: active assessment actions should have an explicit written scope.
    """

    operator: str
    targets: list[str]
    authorized_by: str
    valid_until: str
    reference: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    schema_version: str = "qrae.scope.v1"

    def save(self, path: str | Path = "scope.json") -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path = "scope.json") -> "Scope":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        allowed_fields = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        cleaned = {key: value for key, value in data.items() if key in allowed_fields}
        return cls(**cleaned)

    def expires_at(self) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(self.valid_until)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def is_valid(self, *, now: datetime | None = None) -> bool:
        expires_at = self.expires_at()
        if expires_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return current < expires_at

    def covers(self, target: str) -> bool:
        normalized_target = _normalize_target(target)

        for raw_scope_target in self.targets:
            scope_target = raw_scope_target.strip().lower()
            if scope_target == "*":
                return True
            if scope_target == normalized_target:
                return True
            if _wildcard_hostname_matches(scope_target, normalized_target):
                return True
            if _cidr_matches(scope_target, normalized_target):
                return True
        return False

    def require_valid_for(self, target: str) -> None:
        if not self.is_valid():
            raise ScopeError("assessment scope is expired or has invalid expiry timestamp")
        if not self.covers(target):
            raise ScopeError(f"target is outside authorized scope: {target}")


def _normalize_target(target: str) -> str:
    value = target.strip().lower()
    if not value:
        return value

    parsed = urlparse(value if "://" in value else f"//{value}")
    if parsed.hostname:
        return parsed.hostname.lower()

    # Keep channel names and local identifiers as exact-match scope targets.
    return value


def _wildcard_hostname_matches(scope_target: str, target: str) -> bool:
    if not scope_target.startswith("*."):
        return False
    suffix = scope_target[1:]
    return target.endswith(suffix) and target != suffix.lstrip(".")


def _cidr_matches(scope_target: str, target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        network = ipaddress.ip_network(scope_target, strict=False)
    except ValueError:
        return False
    return ip in network
