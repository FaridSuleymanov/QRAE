"""Command-line interface for QRAE."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from qrae import __version__
from qrae.core import AuditLog, Scope, ScopeError, classify_primitive
from qrae.protocols import assess_unprotected_channel, scan_tls_endpoint


def _write_json(path: str | None, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, indent=2)
    if path:
        Path(path).write_text(text + "\n", encoding="utf-8")
    print(text)


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
    scope = Scope.load(args.scope)
    target_for_scope = args.sni or args.host
    try:
        scope.require_valid_for(target_for_scope)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    audit = AuditLog(args.audit)
    audit.append(
        "tls.scan.begin",
        {
            "host": args.host,
            "port": args.port,
            "sni": args.sni,
            "operator": scope.operator,
            "scope_reference": scope.reference,
        },
    )

    try:
        finding = scan_tls_endpoint(args.host, port=args.port, sni=args.sni, timeout=args.timeout)
    except Exception as exc:  # noqa: BLE001 - CLI should surface and audit assessment failures.
        audit.append("tls.scan.error", {"host": args.host, "port": args.port, "error": repr(exc)})
        print(f"ERROR: TLS assessment failed: {exc}", file=sys.stderr)
        return 1

    payload = finding.to_dict()
    audit.append("tls.scan.finding", payload)
    _write_json(args.out, payload)
    return 0


def cmd_channel_assess(args: argparse.Namespace) -> int:
    scope = Scope.load(args.scope)
    try:
        scope.require_valid_for(args.name)
    except ScopeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    audit = AuditLog(args.audit)
    audit.append(
        "channel.assessment.begin",
        {
            "name": args.name,
            "channel_type": args.channel_type,
            "operator": scope.operator,
            "scope_reference": scope.reference,
        },
    )
    finding = assess_unprotected_channel(
        args.name,
        channel_type=args.channel_type,
        recommendation=args.recommendation,
    )
    payload = finding.to_dict()
    audit.append("channel.assessment.finding", payload)
    _write_json(args.out, payload)
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    primitive = classify_primitive(args.family, args.bits, args.role, name=args.name)
    _write_json(args.out, primitive.to_dict())
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    ok, count, error = AuditLog(args.audit).verify()
    if ok:
        print(f"OK: {count} entries, chain intact")
        return 0
    print(f"FAIL: chain break after {count} verified entries: {error}", file=sys.stderr)
    return 1


def cmd_audit_show(args: argparse.Namespace) -> int:
    audit = AuditLog(args.audit)
    entries = audit.entries(unverified=True)
    if entries is None:
        return 0
    for entry in entries:
        timestamp = entry.get("timestamp", "unknown-time")
        event = entry.get("event", "unknown-event")
        digest = str(entry.get("this_hash", ""))[:12]
        print(f"[{timestamp}] {event} -> {digest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qrae",
        description="QRAE — Quantum Readiness Assessment Engine",
    )
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
    tls_scan.add_argument("--port", type=int, default=443)
    tls_scan.add_argument("--sni", default=None)
    tls_scan.add_argument("--timeout", type=float, default=5.0)
    tls_scan.add_argument("--scope", default="scope.json")
    tls_scan.add_argument("--audit", default="audit.log")
    tls_scan.add_argument("--out", default=None, help="optional path to write finding JSON")
    tls_scan.set_defaults(func=cmd_tls_scan)

    channel_parser = subparsers.add_parser("channel", help="generic channel assessment")
    channel_subparsers = channel_parser.add_subparsers(dest="channel_command", required=True)
    channel_assess = channel_subparsers.add_parser(
        "assess-unprotected",
        help="record that a scoped channel has no crypto protection",
    )
    channel_assess.add_argument("--name", required=True)
    channel_assess.add_argument("--channel-type", default="data-channel")
    channel_assess.add_argument("--recommendation", default=None)
    channel_assess.add_argument("--scope", default="scope.json")
    channel_assess.add_argument("--audit", default="audit.log")
    channel_assess.add_argument("--out", default=None, help="optional path to write finding JSON")
    channel_assess.set_defaults(func=cmd_channel_assess)

    classify_parser = subparsers.add_parser("classify", help="classify one primitive")
    classify_parser.add_argument("family")
    classify_parser.add_argument("--bits", type=int, default=None)
    classify_parser.add_argument("--role", default="unknown")
    classify_parser.add_argument("--name", default=None)
    classify_parser.add_argument("--out", default=None)
    classify_parser.set_defaults(func=cmd_classify)

    audit_parser = subparsers.add_parser("audit", help="inspect audit logs")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command", required=True)
    audit_verify = audit_subparsers.add_parser("verify", help="verify audit chain integrity")
    audit_verify.add_argument("--audit", default="audit.log")
    audit_verify.set_defaults(func=cmd_audit_verify)
    audit_show = audit_subparsers.add_parser("show", help="show audit entries")
    audit_show.add_argument("--audit", default="audit.log")
    audit_show.set_defaults(func=cmd_audit_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
