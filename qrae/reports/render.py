"""Report rendering for QRAE findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qrae.core import Finding, finding_from_dict


def load_findings(paths: list[str | Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, list):
            findings.extend(finding_from_dict(item) for item in data)
        else:
            findings.append(finding_from_dict(data))
    return findings


def findings_to_markdown(findings: list[Finding]) -> str:
    lines = [
        "# QRAE Cryptographic Exposure Report",
        "",
        "| Target | Protocol | Worst case | Risk | Priority | Primitive count |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for finding in findings:
        risk = finding.risk or {}
        lines.append(
            f"| `{finding.target}` | `{finding.protocol}` | `{finding.worst_case.value}` | "
            f"{risk.get('score', 'n/a')} | {risk.get('priority', 'n/a')} | {len(finding.primitives)} |"
        )

    lines.extend(["", "## Findings", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.target} / {finding.protocol}",
                "",
                f"- Timestamp: `{finding.timestamp}`",
                f"- Worst case: `{finding.worst_case.value}`",
            ]
        )
        if finding.risk:
            lines.append(f"- Risk: `{finding.risk.get('score')}` / `{finding.risk.get('priority')}`")
        lines.extend(["", "| Primitive | Role | Vulnerability | Policy | Standardization | Notes |", "|---|---|---|---|---|---|"])
        for primitive in finding.primitives:
            lines.append(
                f"| `{primitive.name}` | `{primitive.role}` | `{primitive.vulnerability.value}` | "
                f"`{primitive.policy_status.value}` | `{primitive.standardization_status.value}` | "
                f"{_escape_md(primitive.migration_hint or primitive.notes)} |"
            )
        if finding.metadata:
            lines.extend(["", "<details>", "<summary>Metadata</summary>", "", "```json"])
            lines.append(json.dumps(finding.metadata, indent=2, default=str))
            lines.extend(["```", "", "</details>", ""])
    return "\n".join(lines) + "\n"


def findings_to_sarif(findings: list[Finding]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}

    for finding in findings:
        for primitive in finding.primitives:
            rule_id = f"QRAE.{primitive.vulnerability.value}.{primitive.family}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "shortDescription": {"text": f"{primitive.family} {primitive.vulnerability.value}"},
                    "fullDescription": {"text": primitive.notes or primitive.migration_hint},
                    "help": {"text": primitive.migration_hint or primitive.notes},
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": _sarif_level(primitive.vulnerability.value),
                    "message": {
                        "text": f"{primitive.name} on {finding.target}: {primitive.policy_status.value}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.target},
                            }
                        }
                    ],
                    "properties": {
                        "protocol": finding.protocol,
                        "role": primitive.role,
                        "standardization_status": primitive.standardization_status.value,
                        "policy_status": primitive.policy_status.value,
                        "risk": finding.risk,
                    },
                }
            )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "QRAE",
                        "informationUri": "https://github.com/FaridSuleymanov/QRAE",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _sarif_level(vulnerability: str) -> str:
    if vulnerability in {"unprotected", "broken"}:
        return "error"
    if vulnerability in {"weakened", "unknown"}:
        return "warning"
    return "note"


def _escape_md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
