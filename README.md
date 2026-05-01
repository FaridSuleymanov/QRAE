# QRAE — Quantum Readiness Assessment Engine

**QRAE** is an early-stage Python toolkit for authorized post-quantum cryptography readiness assessment.

The project was originally developed under the working name **LAIN**, but the public technical framing is now focused on defensive assessment, auditability, and migration planning.

QRAE inspects selected communication endpoints or channels, identifies cryptographic primitives where possible, classifies their exposure to quantum-relevant attack models, and records the assessment process in a tamper-evident audit log.

> Status: alpha / research prototype.  
> Current focus: TLS endpoint inspection, primitive classification, authorization scope control, and audit evidence.

---

## Purpose

Many systems still depend on cryptographic primitives that are expected to be vulnerable or weakened in the presence of cryptographically relevant quantum computers.

QRAE is designed to support practical questions such as:

- Which cryptographic primitives are currently used by a system?
- Which of them are affected by Shor's or Grover's algorithm?
- Which findings require post-quantum migration planning?
- Was the assessment performed inside an explicitly authorized scope?
- Can the assessment trail be reviewed later?

The goal is not to provide a general offensive tool. The goal is to create a repeatable, inspectable workflow for quantum-readiness assessment and post-quantum migration planning.

---

## Current capabilities

| Area | Current implementation |
|---|---|
| Authorization scope | Scope declaration with operator, target list, authorization reference, and expiry |
| Audit trail | Append-only hash-chained JSONL audit log |
| TLS assessment | Active TLS connection, negotiated cipher extraction, certificate public-key classification |
| Primitive classification | Conservative classification of classical, symmetric, hash, and post-quantum primitives |
| Structured output | JSON findings suitable for reporting, dashboards, or later SIEM integration |
| ESPARGOS assessment | Explicit classification of an unprotected RF/data channel as requiring cryptographic protection |
| Tests | Unit tests for audit integrity, scope logic, and primitive classification |

---

## Quantum-risk model

QRAE currently uses a simple conservative model:

| Class | Meaning |
|---|---|
| `broken` | Primitive is expected to be broken by Shor's algorithm once a CRQC exists |
| `weakened` | Primitive is affected by Grover's algorithm; effective security is reduced |
| `resistant` | Primitive is recognized as post-quantum or hash-based in the current classifier table |
| `unprotected` | No confidentiality, integrity, or authentication layer is present |
| `unknown` | Primitive is not recognized and requires manual review |

Examples:

- RSA, DSA, DH, ECDSA, ECDH, Ed25519, X25519 → Shor-relevant
- AES, ChaCha20, SHA-2/SHA-3 families → Grover-relevant
- ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS → treated as post-quantum or quantum-resistant categories
- Unknown primitives are not marked safe by default

The classifier is intentionally conservative. Unknown does not mean secure.

---

## Architecture

```text
qrae / lain
├── cli.py                 # command-line interface
├── core
│   ├── audit.py           # hash-chained audit log
│   ├── scope.py           # authorization scope model
│   ├── classify.py        # quantum vulnerability classifier
│   └── findings.py        # structured finding data model
└── protocol
    ├── tls.py             # TLS endpoint assessment
    └── espargos.py        # unprotected channel assessment
