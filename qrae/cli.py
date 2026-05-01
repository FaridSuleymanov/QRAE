"""Command-line interface for QRAE."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from qrae import __version__
from qrae.core import AuditLog, RiskInputs, Scope, ScopeError, classify_primitive, score_finding
from qrae.core.signing import generate_keypair, sign_file, verify_file
from qrae.protocols import (
    assess_unprotected_channel,
    scan_code_path,
    scan_ssh_host_keys,
    scan_tls_deep,
    scan_tls_endpoint,
    scan_tls_raw_groups,
)
from qrae.reports import findings_to_markdown, findings_to_sarif, load_findings


def _write_json(path: str | None, payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    text = json.dumps(payload, indent=2, default=str)
    if path:
        Path(path).write_text(text + "\n", encoding="utf-8")
    print(text)


def _risk_inputs(args: argparse.Namespace) -> RiskInputs:
    return RiskInputs(
        exposure=args.exposure,
        data_sensitivity=args.data_sensitivity,
        confidentiality_years=args.confidentiality_years,
        business_criticality=args.business_criticality,
        migration_complexity=args.migration_complexity,
        compensating_controls=args.compensating_controls,
        asset_owner=args.asset_owner or "",
        environment=args.environment or "",
    )


def _add_risk_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--exposure", choices=["internet", "partner", "internal", "isolated"], default="internal")
    parser.add_argument("--data-sensitivity", choices=["low", "medium", "high", "restricted"], default="medium")
    parser.add_argument("--confidentiality-years", type=int, default=1)
    parser.add_argument("--business-criticality", choices=["low", "medium", "high", "mission"], default="medium")
    parser.add_argument("--migration-complexity", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--compensating-controls", action="store_true")
    parser.add_argument("--asset-owner", default="")
    parser.add_argument("--environment", default="")


def _load_scope(scope_path: str, target: str) -> Scope:
    scope = Scope.load(scope_path)
    scope.require_valid_for(target)
    return scope


def _audit(args: argparse.Namespace) -> AuditLog:
    return AuditLog(args.audit, campaign_id=args.campaign_id)


def _parse_group_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def cmd_scope_init(args: argparse.Namespace) -> int:
    scope = Scope(
        operator=args.operator,
        targets=args.targets,
        authorized_by=args.authorized_by,
        valid_until=args.valid_until,
        reference=args.reference or "",
    )
    scope.save(args.out)
    print(f"Scope written to {args.out}")
    print(f"operator:      {scope.operator}")
    print(f"targets:       {', '.join(scope.targets)}")
    print(f"authorized_by: {scope.authorized_by}")
    print(f"valid_until:   {scope.valid_until}")
    if scope.reference:
        print(f"reference:     {scope.reference}")
    return 0


def cmd_tls_scan(args: argparse.Namespace) -> int:
    try:
        scope = _load_scope(args.scope, args.sni or args.host)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    audit = _audit(args)
    audit.append("tls.scan.begin", {"host": args.host, "port": args.port, "operator": scope.operator})

    try:
        finding = scan_tls_deep(args.host, port=args.port, sni=args.sni, timeout=args.timeout) if args.deep else scan_tls_endpoint(args.host, port=args.port, sni=args.sni, timeout=args.timeout)
    except Exception as exc:  # noqa: BLE001
        audit.append("tls.scan.error", {"host": args.host, "port": args.port, "error": repr(exc)})
        print(f"ERROR: TLS assessment failed: {exc}", file=sys.stderr)
        return 1

    finding.risk = score_finding(finding, _risk_inputs(args))
    payload = finding.to_dict()
    audit.append("tls.scan.finding", payload)
    _write_json(args.out, payload)
    return 0


def cmd_tls_raw_groups(args: argparse.Namespace) -> int:
    try:
        scope = _load_scope(args.scope, args.sni or args.host)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    groups = _parse_group_list(args.groups)
    audit = _audit(args)
    audit.append(
        "tls.raw_groups.begin",
        {
            "host": args.host,
            "port": args.port,
            "sni": args.sni,
            "groups": groups,
            "operator": scope.operator,
        },
    )

    try:
        finding = scan_tls_raw_groups(
            args.host,
            port=args.port,
            sni=args.sni,
            groups=groups,
            timeout=args.timeout,
        )
    except Exception as exc:  # noqa: BLE001
        audit.append(
            "tls.raw_groups.error",
            {"host": args.host, "port": args.port, "groups": groups, "error": repr(exc)},
        )
        print(f"ERROR: raw TLS group probe failed: {exc}", file=sys.stderr)
        return 1

    finding.risk = score_finding(finding, _risk_inputs(args))
    payload = finding.to_dict()
    audit.append("tls.raw_groups.finding", payload)
    _write_json(args.out, payload)
    return 0


def cmd_ssh_scan(args: argparse.Namespace) -> int:
    try:
        scope = _load_scope(args.scope, args.host)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    audit = _audit(args)
    audit.append("ssh.scan.begin", {"host": args.host, "port": args.port, "operator": scope.operator})
    finding = scan_ssh_host_keys(args.host, port=args.port, timeout=args.timeout, key_types=args.key_types)
    finding.risk = score_finding(finding, _risk_inputs(args))
    payload = finding.to_dict()
    audit.append("ssh.scan.finding", payload)
    _write_json(args.out, payload)
    return 0


def cmd_channel_assess(args: argparse.Namespace) -> int:
    try:
        scope = _load_scope(args.scope, args.name)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    audit = _audit(args)
    audit.append("channel.assessment.begin", {"name": args.name, "channel_type": args.channel_type, "operator": scope.operator})
    finding = assess_unprotected_channel(args.name, channel_type=args.channel_type, recommendation=args.recommendation)
    finding.risk = score_finding(finding, _risk_inputs(args))
    payload = finding.to_dict()
    audit.append("channel.assessment.finding", payload)
    _write_json(args.out, payload)
    return 0


def cmd_code_scan(args: argparse.Namespace) -> int:
    findings = scan_code_path(args.path)
    risk_inputs = _risk_inputs(args)
    for finding in findings:
        finding.risk = score_finding(finding, risk_inputs)

    payload = [finding.to_dict() for finding in findings]
    AuditLog(args.audit, campaign_id=args.campaign_id).append(
        "code.scan.findings",
        {"path": args.path, "finding_count": len(payload)},
    )
    _write_json(args.out, payload)
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    primitive = classify_primitive(args.family, args.bits, args.role, name=args.name)
    _write_json(args.out, primitive.to_dict())
    return 0


def cmd_report_markdown(args: argparse.Namespace) -> int:
    findings = load_findings(args.findings)
    text = findings_to_markdown(findings)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0


def cmd_report_sarif(args: argparse.Namespace) -> int:
    findings = load_findings(args.findings)
    payload = findings_to_sarif(findings)
    _write_json(args.out, payload)
    return 0


def cmd_sign_keygen(args: argparse.Namespace) -> int:
    generate_keypair(args.private_key, args.public_key, overwrite=args.overwrite)
    print(f"Private key: {args.private_key}")
    print(f"Public key:  {args.public_key}")
    return 0


def cmd_sign_file(args: argparse.Namespace) -> int:
    payload = sign_file(args.file, args.private_key, args.signature)
    _write_json(None, payload)
    return 0


def cmd_sign_verify(args: argparse.Namespace) -> int:
    ok = verify_file(args.file, args.signature, args.public_key)
    print("OK: signature valid" if ok else "FAIL: signature invalid")
    return 0 if ok else 1


def cmd_audit_verify(args: argparse.Namespace) -> int:
    ok, count, error = AuditLog(args.audit).verify()
    if ok:
        print(f"OK: {count} entries, chain intact")
        return 0
    print(f"FAIL: chain break after {count} verified entries: {error}", file=sys.stderr)
    return 1


def cmd_audit_show(args: argparse.Namespace) -> int:
    for entry in AuditLog(args.audit).entries(unverified=True):
        timestamp = entry.get("timestamp", "unknown-time")
        event = entry.get("event", "unknown-event")
        run_id = str(entry.get("run_id", ""))[:8]
        digest = str(entry.get("this_hash", ""))[:12]
        print(f"[{timestamp}] {event} run={run_id} -> {digest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrae", description="QRAE — Quantum Readiness Assessment Engine")
    parser.add_argument("--version", action="version", version=f"qrae {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scope_parser = subparsers.add_parser("scope", help="manage authorization scope")
    scope_subparsers = scope_parser.add_subparsers(dest="scope_command", required=True)
    scope_init = scope_subparsers.add_parser("init", help="create a scope declaration")
    scope_init.add_argument("--operator", required=True)
    scope_init.add_argument("--targets", nargs="+", required=True)
    scope_init.add_argument("--authorized-by", required=True)
    scope_init.add_argument("--valid-until", required=True)
    scope_init.add_argument("--reference", default="")
    scope_init.add_argument("--out", default="scope.json")
    scope_init.set_defaults(func=cmd_scope_init)

    tls_parser = subparsers.add_parser("tls", help="TLS endpoint assessment")
    tls_subparsers = tls_parser.add_subparsers(dest="tls_command", required=True)

    tls_scan = tls_subparsers.add_parser("scan", help="scan an authorized TLS endpoint")
    tls_scan.add_argument("host")
    tls_scan.add_argument("--deep", action="store_true", help="use OpenSSL-assisted deep inventory when available")
    tls_scan.add_argument("--port", type=int, default=443)
    tls_scan.add_argument("--sni", default=None)
    tls_scan.add_argument("--timeout", type=float, default=6.0)
    tls_scan.add_argument("--scope", default="scope.json")
    tls_scan.add_argument("--audit", default="audit.log")
    tls_scan.add_argument("--campaign-id", default=None)
    tls_scan.add_argument("--out", default=None)
    _add_risk_args(tls_scan)
    tls_scan.set_defaults(func=cmd_tls_scan)

    tls_raw = tls_subparsers.add_parser(
        "raw-groups",
        help="probe TLS 1.3 key-share groups using raw ClientHello messages",
    )
    tls_raw.add_argument("host")
    tls_raw.add_argument("--port", type=int, default=443)
    tls_raw.add_argument("--sni", default=None)
    tls_raw.add_argument(
        "--groups",
        default="x25519,secp256r1,secp384r1,secp521r1",
        help="comma-separated group names or numeric IDs; built-in: x25519,secp256r1,secp384r1,secp521r1",
    )
    tls_raw.add_argument("--timeout", type=float, default=5.0)
    tls_raw.add_argument("--scope", default="scope.json")
    tls_raw.add_argument("--audit", default="audit.log")
    tls_raw.add_argument("--campaign-id", default=None)
    tls_raw.add_argument("--out", default=None)
    _add_risk_args(tls_raw)
    tls_raw.set_defaults(func=cmd_tls_raw_groups)

    ssh_parser = subparsers.add_parser("ssh", help="SSH inventory")
    ssh_subparsers = ssh_parser.add_subparsers(dest="ssh_command", required=True)
    ssh_scan = ssh_subparsers.add_parser("scan", help="scan SSH host keys")
    ssh_scan.add_argument("host")
    ssh_scan.add_argument("--port", type=int, default=22)
    ssh_scan.add_argument("--timeout", type=float, default=5.0)
    ssh_scan.add_argument("--key-types", default="rsa,ecdsa,ed25519")
    ssh_scan.add_argument("--scope", default="scope.json")
    ssh_scan.add_argument("--audit", default="audit.log")
    ssh_scan.add_argument("--campaign-id", default=None)
    ssh_scan.add_argument("--out", default=None)
    _add_risk_args(ssh_scan)
    ssh_scan.set_defaults(func=cmd_ssh_scan)

    channel_parser = subparsers.add_parser("channel", help="generic channel assessment")
    channel_subparsers = channel_parser.add_subparsers(dest="channel_command", required=True)
    channel_assess = channel_subparsers.add_parser("assess-unprotected")
    channel_assess.add_argument("--name", required=True)
    channel_assess.add_argument("--channel-type", default="data-channel")
    channel_assess.add_argument("--recommendation", default=None)
    channel_assess.add_argument("--scope", default="scope.json")
    channel_assess.add_argument("--audit", default="audit.log")
    channel_assess.add_argument("--campaign-id", default=None)
    channel_assess.add_argument("--out", default=None)
    _add_risk_args(channel_assess)
    channel_assess.set_defaults(func=cmd_channel_assess)

    code_parser = subparsers.add_parser("code", help="local code/config crypto scan")
    code_subparsers = code_parser.add_subparsers(dest="code_command", required=True)
    code_scan = code_subparsers.add_parser("scan")
    code_scan.add_argument("path")
    code_scan.add_argument("--audit", default="audit.log")
    code_scan.add_argument("--campaign-id", default=None)
    code_scan.add_argument("--out", default=None)
    _add_risk_args(code_scan)
    code_scan.set_defaults(func=cmd_code_scan)

    classify_parser = subparsers.add_parser("classify", help="classify one primitive")
    classify_parser.add_argument("family")
    classify_parser.add_argument("--bits", type=int, default=None)
    classify_parser.add_argument("--role", default="unknown")
    classify_parser.add_argument("--name", default=None)
    classify_parser.add_argument("--out", default=None)
    classify_parser.set_defaults(func=cmd_classify)

    report_parser = subparsers.add_parser("report", help="render reports from finding JSON")
    report_subparsers = report_parser.add_subparsers(dest="report_command", required=True)
    report_md = report_subparsers.add_parser("markdown")
    report_md.add_argument("findings", nargs="+")
    report_md.add_argument("--out", default=None)
    report_md.set_defaults(func=cmd_report_markdown)
    report_sarif = report_subparsers.add_parser("sarif")
    report_sarif.add_argument("findings", nargs="+")
    report_sarif.add_argument("--out", default=None)
    report_sarif.set_defaults(func=cmd_report_sarif)

    sign_parser = subparsers.add_parser("sign", help="sign or verify QRAE artifacts")
    sign_subparsers = sign_parser.add_subparsers(dest="sign_command", required=True)
    keygen = sign_subparsers.add_parser("keygen")
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-key", required=True)
    keygen.add_argument("--overwrite", action="store_true")
    keygen.set_defaults(func=cmd_sign_keygen)
    sign_cmd = sign_subparsers.add_parser("file")
    sign_cmd.add_argument("file")
    sign_cmd.add_argument("--private-key", required=True)
    sign_cmd.add_argument("--signature", default=None)
    sign_cmd.set_defaults(func=cmd_sign_file)
    verify_cmd = sign_subparsers.add_parser("verify")
    verify_cmd.add_argument("file")
    verify_cmd.add_argument("--signature", required=True)
    verify_cmd.add_argument("--public-key", required=True)
    verify_cmd.set_defaults(func=cmd_sign_verify)

    audit_parser = subparsers.add_parser("audit", help="inspect audit logs")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command", required=True)
    audit_verify = audit_subparsers.add_parser("verify")
    audit_verify.add_argument("--audit", default="audit.log")
    audit_verify.set_defaults(func=cmd_audit_verify)
    audit_show = audit_subparsers.add_parser("show")
    audit_show.add_argument("--audit", default="audit.log")
    audit_show.set_defaults(func=cmd_audit_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
