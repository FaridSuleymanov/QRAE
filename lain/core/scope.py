"""Scope authorization gate.

Before any active probe runs, the operator declares a scope: who they are,
what targets they claim authority over, who authorized it, and when that
authorization expires.

This isn't DRM — someone could patch it out in 30 seconds. It's a mens rea
marker. If you run LAIN against a target, the scope file is your written
declaration of what you claimed authority to test. Combined with the audit
log, it's the forensic trail that separates authorized red-teaming from
unauthorized access.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Scope:
    operator: str
    targets: list[str]                  # hostnames, IPs, CIDRs, pcap paths, or "*"
    authorized_by: str
    valid_until: str                    # ISO 8601 datetime
    reference: str = ""                 # ticket / PO / contract reference
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # ------------------------------------------------------------------ I/O

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2))

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = json.loads(Path(path).read_text())
        return cls(**data)

    # --------------------------------------------------------------- checks

    def is_valid(self) -> bool:
        try:
            until = datetime.fromisoformat(self.valid_until)
        except ValueError:
            return False
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < until

    def covers(self, target: str) -> bool:
        """Target matching. Exact string, CIDR membership, or '*' wildcard."""
        if "*" in self.targets:
            return True
        if target in self.targets:
            return True
        # CIDR check — only if target parses as an IP
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        for t in self.targets:
            try:
                net = ipaddress.ip_network(t, strict=False)
            except ValueError:
                continue
            if ip in net:
                return True
        return False
