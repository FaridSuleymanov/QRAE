"""Core data structures. Every scan emits a Finding containing one or more
classified Primitives. Findings are the canonical artifact — everything
downstream (reports, audit entries, PSYCHE attack plans) consumes them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Vulnerability(str, Enum):
    """Quantum vulnerability class per NIST SP 800-208 / CNSA 2.0."""

    BROKEN = "broken"              # Shor's applicable — full break
    WEAKENED = "weakened"          # Grover's — effective security halved
    RESISTANT = "resistant"        # PQC primitive (FIPS 203/204/205)
    UNPROTECTED = "unprotected"    # no crypto at all
    UNKNOWN = "unknown"


class AttackClass(str, Enum):
    SHOR = "shor"
    GROVER = "grover"
    NONE = "none"


@dataclass
class Primitive:
    name: str                      # "RSA-2048", "ECDSA-P256", "AES-128-GCM"
    family: str                    # "rsa" | "ecdsa" | "aes" | ...
    parameter_bits: Optional[int]  # modulus / curve / key size
    role: str                      # "key_exchange" | "signature" | "cipher" | "kdf" | "transport"
    vulnerability: Vulnerability
    attack_class: AttackClass
    notes: str = ""


@dataclass
class Finding:
    target: str
    protocol: str                                                # "tls" | "mqtt" | "dds" | "espargos"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    primitives: list[Primitive] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @property
    def worst_case(self) -> Vulnerability:
        """Returns the highest-severity vulnerability across all primitives."""
        order = [
            Vulnerability.UNPROTECTED,
            Vulnerability.BROKEN,
            Vulnerability.WEAKENED,
            Vulnerability.UNKNOWN,
            Vulnerability.RESISTANT,
        ]
        present = {p.vulnerability for p in self.primitives}
        for v in order:
            if v in present:
                return v
        return Vulnerability.UNKNOWN
