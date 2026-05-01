# QRAE — Quantum Readiness Assessment Engine

**QRAE** is an authorized cryptographic exposure discovery and post-quantum migration prioritization toolkit.

It is intentionally positioned as an operational readiness tool, not a "quantum attack framework". The practical goal is to help an authorized operator map cryptographic assets, classify quantum-relevant exposure, and produce auditable migration evidence.

> Status: alpha / operational prototype.  
> Current focus: TLS deep inventory, X.509 chain analysis, SSH host-key inventory, local code/config crypto scanning, NIST-aware primitive policy classification, risk scoring, structured reports, and tamper-evident audit logging.

---

## Why this exists

Post-quantum migration is not only a cryptography problem. It is an inventory, ownership, exposure, and prioritization problem.

Organizations need to answer practical questions:

- Which systems expose RSA, ECDSA, ECDH, X25519, AES-128, SHA-1, draft PQC names, or hybrid groups?
- Which assets are internet-facing, business-critical, or exposed to harvest-now-decrypt-later risk?
- Which certificates and host keys are classical-only?
- Which local code/config files still contain RSA/ECC/TLS legacy patterns?
- Which findings are standardized PQC, backup PQC, legacy finalist names, experimental, classical legacy, or unknown?
- Can the assessment process be reproduced and audited?

QRAE is designed for authorized assessment, cryptographic inventory, and migration planning.

---

## What changed in this Phase 1 upgrade

This upgrade moves QRAE away from toy-like "quantum demo" framing and toward operational crypto inventory.

Implemented in this code drop:

| Area | Capability |
|---|---|
| NIST-aware classifier | Distinguishes standardized PQC, backup PQC, legacy PQC names, classical legacy, symmetric/hash weakening, unprotected, and unknown |
| TLS deep scan | Uses Python TLS plus optional `openssl s_client` parsing for certificate chain, negotiated cipher, protocol, temp key/group, OCSP hints, and server metadata |
| X.509 chain analyzer | Parses PEM/DER certificate chains and classifies public keys, certificate signature algorithms, hash algorithms, CA/leaf metadata, and expiry |
| SSH inventory | Uses `ssh-keyscan` to inventory host-key algorithms and classify RSA/ECDSA/Ed25519 keys |
| Code/config scan | Local regex-based scan for RSA/ECC/Ed25519/X25519/TLS crypto usage hints |
| Risk scoring | Asset-level score using exposure, data sensitivity, business criticality, confidentiality lifetime, migration complexity, and compensating controls |
| Reports | Markdown and SARIF-like JSON output from QRAE finding JSON |
| Audit metadata | Audit entries include run ID, tool version, runtime metadata, and optional campaign ID |
| File signing | Ed25519 signing/verification helpers for findings, reports, or scope files |

Still not implemented:

- Full custom raw TLS ClientHello/ServerHello parser
- Exhaustive TLS cipher-suite and supported-group enumeration
- IKE/IPsec, WireGuard, Kubernetes, cloud certificate discovery
- Persistent asset inventory database
- External timestamping / WORM audit backend

---

## Classification model

QRAE keeps the simple vulnerability labels but adds policy context.

### Vulnerability

| Value | Meaning |
|---|---|
| `unprotected` | No cryptographic protection was identified |
| `broken` | Classical asymmetric primitive affected by Shor's algorithm once CRQC exists |
| `weakened` | Symmetric/hash primitive affected by Grover's algorithm |
| `unknown` | Primitive not recognized; manual review required |
| `resistant` | Recognized PQC/hash-based/hybrid primitive in the current policy table |

### Standardization status

| Value | Meaning |
|---|---|
| `standardized_pqc` | NIST-standardized PQC family such as ML-KEM, ML-DSA, SLH-DSA |
| `selected_backup_pqc` | Backup/selected PQC candidate such as HQC |
| `legacy_pqc_name` | Pre-standard or legacy name such as Kyber, Dilithium, SPHINCS+ |
| `legacy_finalist_or_experimental` | PQC finalist/experimental family needing policy review |
| `classical_legacy` | Classical asymmetric primitive that needs migration planning |
| `symmetric_or_hash` | Symmetric/hash primitive requiring key-length/context review |
| `not_applicable` | No crypto / transport-level finding |
| `unknown` | Not recognized |

The policy table reflects the project assumptions supplied for this upgrade:
FIPS 203/204/205 are treated as finalized standards for ML-KEM, ML-DSA and SLH-DSA; HQC is treated as selected backup PQC. Verify policy text before formal compliance use.

---

## Install

```bash
git clone https://github.com/FaridSuleymanov/QRAE.git
cd QRAE

python -m venv .venv
source .venv/bin/activate

pip install -e .
```

Development:

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

---

## Quickstart

### 1. Create scope

```bash
qrae scope init \
  --operator analyst@example.org \
  --targets example.org "*.example.org" 10.42.0.0/16 lab-rf-link-01 \
  --authorized-by "internal lab authorization" \
  --valid-until 2026-12-31T23:59:59+00:00 \
  --reference "LAB-PQC-REVIEW-001"
```

### 2. Run a deep TLS inventory

```bash
qrae tls scan example.org \
  --deep \
  --exposure internet \
  --data-sensitivity high \
  --confidentiality-years 10 \
  --business-criticality high \
  --migration-complexity medium \
  --out findings-tls.json
```

The deep TLS scanner uses:
- Python TLS socket inspection
- optional `openssl s_client` output parsing when OpenSSL is available
- X.509 chain extraction from PEM blocks
- negotiated cipher classification
- server temp-key / key-exchange group hints when OpenSSL reports them
- OCSP/stapling hints where visible

### 3. Scan SSH host keys

```bash
qrae ssh scan example.org \
  --exposure internet \
  --data-sensitivity medium \
  --out findings-ssh.json
```

This uses `ssh-keyscan` and classifies host-key algorithms such as RSA, ECDSA and Ed25519.

### 4. Scan local code/config

```bash
qrae code scan ./infra \
  --out findings-code.json
```

This is a local scan for cryptographic implementation and configuration hints. It is not a full static analyzer.

### 5. Generate reports

```bash
qrae report markdown findings-tls.json findings-ssh.json findings-code.json --out qrae-report.md
qrae report sarif findings-tls.json findings-ssh.json findings-code.json --out qrae-report.sarif.json
```

### 6. Sign a report or finding

```bash
qrae sign keygen --private-key qrae_ed25519_private.pem --public-key qrae_ed25519_public.pem
qrae sign file qrae-report.md --private-key qrae_ed25519_private.pem
qrae sign verify qrae-report.md --signature qrae-report.md.sig.json --public-key qrae_ed25519_public.pem
```

---

## Output model

Every scan emits a QRAE finding:

```json
{
  "schema_version": "qrae.finding.v2",
  "target": "example.org:443",
  "protocol": "tls",
  "worst_case": "broken",
  "primitives": [],
  "metadata": {},
  "risk": {
    "score": 84,
    "priority": "P1",
    "drivers": []
  }
}
```

The model is intentionally JSON-first so findings can be fed into dashboards, SIEM pipelines, reports, or a future asset inventory database.

---

## Intended use

QRAE is intended for:

- authorized security assessment
- post-quantum readiness review
- cryptographic inventory
- migration prioritization
- training and education
- cyber-physical and infrastructure system review

It is not intended for unauthorized probing, exploitation, disruption, or access to third-party systems.

---

## Roadmap

Recommended next order:

1. Custom raw TLS ClientHello/ServerHello parser
2. Exhaustive TLS cipher/group probing
3. Persistent asset inventory database
4. IKE/IPsec and WireGuard modules
5. Kubernetes ingress and service TLS inventory
6. Cloud certificate discovery for AWS ACM, Azure Key Vault, and GCP Certificate Manager
7. External timestamping and append-only audit backend
8. Educational Qiskit examples only after the operational inventory is strong

---

## License

AGPL-3.0-or-later.
