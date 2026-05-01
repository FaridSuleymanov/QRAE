"""QRAE — Quantum Readiness Assessment Engine.

QRAE is a small toolkit for authorized post-quantum cryptography readiness
assessment. It focuses on practical inventory, conservative primitive
classification, authorization scope control, and tamper-evident local audit
logging.
"""

from .core import (
    AttackClass,
    AuditLog,
    Finding,
    Primitive,
    Scope,
    Vulnerability,
    classify_primitive,
)

__all__ = [
    "AttackClass",
    "AuditLog",
    "Finding",
    "Primitive",
    "Scope",
    "Vulnerability",
    "classify_primitive",
]

__version__ = "0.1.0"
