# LAIN

**Layered Attack Intelligence for Next-gen cryptography.**

---

## What ships today

| Module | Capability |
|---|---|
| `lain.protocol.tls` | Active TLS probe. Negotiates against target, extracts cipher + cert public key, classifies each against Shor's / Grover's. |
| `lain.protocol.espargos` | ESPARGOS RF channel assessment. Flags zero-crypto channels, emits CNSA 2.0 / FIPS 203 migration recommendation. |
| `lain.core.classify` | Quantum vulnerability classifier (NIST FIPS 203/204/205, CNSA 2.0, SP 800-208). |
| `lain.core.audit` | Hash-chained append-only audit log. Every action is a SHA-256 block committed to the previous. `audit-verify` detects any tampering. |
| `lain.core.scope` | Scope gate. No probe runs without a signed scope declaration covering the target. Exact / CIDR / wildcard matching. Expiry enforced. |

## What's next

- Passive PCAP analysis (MQTT, RTPS/DDS, gRPC) using scapy
- Raw TLS 1.3 ClientHello / ServerHello parsing — extract `NamedGroup` (X25519, P-256, ML-KEM hybrid)
- ROS2 DDS-Security discovery + primitive inventory
- Shor's circuit construction for discovered RSA moduli (Qiskit, toy scale first)
- Grover's oracle for discovered symmetric primitives (Simplified-AES first)
- resource estimation — logical qubits, physical qubits, megaqubit-days, hardware-availability timeline
- PQC migration validation — replay the attack pipeline against the PQC-protected channel, confirm resistance

## Install

```bash
# from source
git clone https://github.com/FaridSuleymanov/lain
cd lain
pip install -e .                 # core
pip install -e ".[pcap]"         # + PCAP analysis (scapy)
pip install -e ".[quantum]"      # + Qiskit backends (PSYCHE)
pip install -e ".[dev]"          # + pytest, ruff
```

## Quickstart — testing your own robots

```bash
# 1. Declare what you're authorized to test
lain scope-init \
    --operator farid@wiewiorkaworks.com \
    --targets mqtt.yorozuya.local 10.42.0.0/52 \
    --authorized-by "self (owner)" \
    --valid-until 2026-12-31T23:59:59+00:00 \
    --reference "internal security review"

# 2. Probe the MQTT-TLS broker
lain scan-tls mqtt.yorozuya.local --port 8883

# 3. Flag the ESPARGOS RF channel
lain scan-espargos --channel espargos-array-01

# 4. Verify the audit log hasn't been tampered with
lain audit-verify

# 5. Walk the chain
lain audit-show
```

Every invocation above appends to `audit.log` (hash-chained). Every probe
checks `scope.json` (target membership + expiry) before touching the
network. Both files are plain-text, inspectable, and designed to be
handed to a CISO, a regulator, or a court.

## Philosophy

Red team tools that pull their punches are not red team tools. LAIN has
two guardrails and no more:

1. **Scope gate** — declare your authority before you probe. Mens rea marker.
2. **Hash-chained audit log** — forensic trail, tamper-evident, regulator-ready.

Beyond those, the tool does its job. It will factor the RSA modulus if
you ask it to. DEUS will then tell you honestly that the circuit needs
~2,500 logical qubits and a machine that won't exist for a decade. **That
honesty is the point** — the tool itself is proof of when the attack
becomes real.

## Output format

Findings are JSON. Every primitive carries `family`, `parameter_bits`,
`role`, `vulnerability` (broken / weakened / resistant / unprotected /
unknown), and `attack_class` (shor / grover / none). Easy to pipe into
dashboards, SIEM, or your own scoring.

## License

AGPL-3.0-or-later. If you run a modified LAIN as a network-accessible
service, you must make the modified source available to your users. No
exceptions.
