# QRAE — Quantum Readiness Assessment Engine

**QRAE** is an early-stage Python toolkit for authorized post-quantum cryptography readiness assessment.

It inspects selected systems or communication channels, identifies visible cryptographic primitives where possible, classifies their quantum-readiness risk, and records the assessment process in a tamper-evident local audit log.

This repository was previously developed under the working name **LAIN**. The new public framing is deliberately more conservative: readiness assessment, defensive review, auditability, and migration planning.

> Status: alpha / research prototype.  
> Current focus: TLS endpoint inspection, primitive classification, authorization scope control, structured findings, and local audit integrity.

---

## Why this exists

Post-quantum migration is difficult because many organizations do not have a clear inventory of where classical cryptography is used, which primitives are exposed, and which systems should be prioritized.

QRAE is intended to support practical review questions:

- Which cryptographic primitives are visible on a given endpoint or channel?
- Which primitives are affected by Shor's algorithm or Grover's algorithm?
- Which findings require post-quantum migration planning?
- Was the assessment performed inside an explicit authorization scope?
- Can the assessment trail be reviewed later?

QRAE is not a certification tool and does not claim that a system is compliant or secure. It is a first-pass assessment and training aid.

---

## Current capabilities

| Area | Implementation |
|---|---|
| Authorization scope | Operator, targets, authorization source, expiry, and reference tracking |
| Scope matching | Exact hostname/IP/channel matching, CIDR matching, wildcard hostname matching |
| Audit trail | Append-only JSONL log with SHA-256 hash chaining |
| TLS assessment | Active TLS connection, negotiated cipher metadata, certificate public-key classification |
| Primitive classification | Conservative classification for Shor/Grover/PQC/unprotected/unknown cases |
| Generic channel assessment | Records known unprotected data/RF channels as findings |
| Structured output | JSON findings for reports, dashboards, or later SIEM ingestion |
| Tests | Unit tests for scope, audit, classifier, findings, and channel assessment |

---

## Classification model

QRAE uses a conservative triage model:

| Classification | Meaning |
|---|---|
| `unprotected` | No cryptographic protection was identified |
| `broken` | Primitive is affected by Shor's algorithm once a CRQC exists |
| `weakened` | Primitive is affected by Grover's algorithm; effective security is reduced |
| `unknown` | Primitive is not recognized by the classifier and needs manual review |
| `resistant` | Primitive is recognized as post-quantum or hash-based in the current classifier table |

Examples:

- RSA, DSA, DH, ECDSA, ECDH, Ed25519, X25519 → `broken` / `shor`
- AES, ChaCha20, SHA-2/SHA-3 families → `weakened` / `grover`
- ML-KEM, ML-DSA, SLH-DSA, XMSS, LMS → `resistant` / `none`
- Unknown primitives are never treated as safe by default

---

## Repository layout

```text
qrae/
├── cli.py                  # Command-line interface
├── __main__.py             # Enables python -m qrae
├── core/
│   ├── audit.py            # Tamper-evident local audit log
│   ├── classifier.py       # Quantum-readiness primitive classifier
│   ├── models.py           # Finding and primitive data models
│   └── scope.py            # Authorization scope model
└── protocols/
    ├── channel.py          # Generic unprotected-channel assessment
    └── tls.py              # TLS endpoint assessment

tests/
├── test_audit.py
├── test_channel.py
├── test_classifier.py
├── test_models.py
└── test_scope.py
```

---

## Install

```bash
git clone https://github.com/FaridSuleymanov/LAIN.git
cd LAIN

python -m venv .venv
source .venv/bin/activate

pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

---

## Quickstart

### 1. Create an authorization scope

```bash
qrae scope init \
  --operator analyst@example.org \
  --targets example.org 10.42.0.0/16 lab-rf-link-01 \
  --authorized-by "internal lab authorization" \
  --valid-until 2026-12-31T23:59:59+00:00 \
  --reference "LAB-PQC-REVIEW-001"
```

This writes `scope.json`.

The scope file records:

- operator identity
- authorized targets
- authorization source
- expiry time
- reference ticket, contract, or review identifier

### 2. Assess a TLS endpoint

```bash
qrae tls scan example.org --port 443
```

The CLI checks that the endpoint is inside the declared scope, connects to the TLS service, classifies visible primitives, writes the result to stdout, and appends events to `audit.log`.

Example finding shape:

```json
{
  "schema_version": "qrae.finding.v1",
  "target": "example.org:443",
  "protocol": "tls",
  "worst_case": "broken",
  "primitives": [
    {
      "name": "TLS_AES_256_GCM_SHA384",
      "family": "aes",
      "role": "cipher",
      "parameter_bits": 256,
      "vulnerability": "weakened",
      "attack_class": "grover"
    },
    {
      "name": "ECDSA-secp256r1",
      "family": "ecdsa",
      "role": "signature",
      "parameter_bits": 256,
      "vulnerability": "broken",
      "attack_class": "shor"
    }
  ]
}
```

### 3. Record a known unprotected channel

```bash
qrae channel assess-unprotected \
  --name lab-rf-link-01 \
  --channel-type rf-link
```

This is useful for documenting systems where there is no cryptographic layer to break yet. In that case the priority is classical protection first: authenticated encryption, key management, replay protection, and only then post-quantum migration planning.

### 4. Classify one primitive manually

```bash
qrae classify rsa --bits 2048 --role signature
qrae classify ml-kem --bits 768 --role key_exchange
qrae classify aes --bits 256 --role cipher
```

### 5. Verify audit integrity

```bash
qrae audit verify
```

Expected result:

```text
OK: 3 entries, chain intact
```

### 6. Show audit entries

```bash
qrae audit show
```

---

## Audit model

QRAE writes local assessment actions to an append-only JSONL audit log.

Each entry contains:

- schema version
- timestamp
- event type
- event data
- previous entry hash
- current entry hash

The current hash commits to the previous hash. If an old entry is modified, `qrae audit verify` detects the chain break.

This is not a replacement for signed enterprise logging, centralized SIEM, WORM storage, external timestamping, or access control. It is a lightweight local integrity mechanism that makes the assessment trail easier to inspect and harder to alter silently.

---

## Authorization model

Active assessment should only be performed against systems the operator is authorized to test.

QRAE supports:

- exact hostname matching
- exact IP matching
- exact channel-name matching
- CIDR matching
- wildcard hostname matching, for example `*.example.org`
- expiry checks
- full wildcard `*` for isolated lab environments

The scope gate is not a strong security boundary. It is an accountability and workflow control. It ensures that assessment commands are tied to an explicit operator-declared scope.

---

## Current limitations

- TLS 1.3 key-exchange group extraction is not available through Python's standard `ssl` API.
- The TLS scanner observes one negotiated connection; it does not exhaustively enumerate all server-supported cipher suites.
- PCAP analysis is planned but not implemented in this fresh rewrite.
- MQTT, DDS/RTPS, gRPC, and ROS 2 security inspection are planned but not implemented.
- Qiskit-based toy demonstrations and resource estimation are planned but not implemented.
- The classifier is rule-based and should be treated as triage, not formal cryptographic certification.
- Generic channel assessment records known design exposure; it is not a live RF protocol parser.

---

## Roadmap

Planned work:

- Passive PCAP analysis for TLS, MQTT, DDS/RTPS, and gRPC
- TLS ClientHello / ServerHello parser for key-exchange group inventory
- ROS 2 DDS-Security primitive inventory
- Report generation in Markdown and HTML
- Mapping to NIST post-quantum migration guidance and CNSA 2.0 categories
- Qiskit-based training examples for toy-scale Shor/Grover demonstrations
- Quantum resource-estimation notes that distinguish theoretical vulnerability from practical exploitability
- More protocol-specific tests and fixture-based TLS parsing

---

## Intended use

QRAE is intended for:

- authorized security assessment
- post-quantum readiness review
- cryptographic inventory support
- training and education
- migration planning for cyber-physical and infrastructure systems

It is not intended for unauthorized probing, exploitation, disruption, or access to third-party systems.

---

## License

AGPL-3.0-or-later.

If this project or a modified version is provided as a network-accessible service, the corresponding modified source code must be made available to users under the terms of the AGPL.
