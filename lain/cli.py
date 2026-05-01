"""LAIN command-line interface."""

from __future__ import annotations

import argparse
import sys

from .core.audit import AuditLog
from .core.scope import Scope
from .protocol import espargos as esp_mod
from .protocol import tls as tls_mod


# ---------------------------------------------------------------- commands


def cmd_scope_init(args: argparse.Namespace) -> None:
    scope = Scope(
        operator=args.operator,
        targets=args.targets,
        authorized_by=args.authorized_by,
        valid_until=args.valid_until,
        reference=args.reference or "",
    )
    scope.save(args.out)
    print(f"Scope written to {args.out}")
    print(f"  operator:      {scope.operator}")
    print(f"  targets:       {', '.join(scope.targets)}")
    print(f"  authorized_by: {scope.authorized_by}")
    print(f"  valid_until:   {scope.valid_until}")


def cmd_scan_tls(args: argparse.Namespace) -> None:
    scope = Scope.load(args.scope)
    if not scope.is_valid():
        print("ERROR: scope has expired", file=sys.stderr)
        sys.exit(2)
    if not scope.covers(args.host):
        print(f"ERROR: {args.host} not in authorized scope", file=sys.stderr)
        sys.exit(2)

    audit = AuditLog(args.audit)
    audit.append(
        "scan.tls.begin",
        {"host": args.host, "port": args.port, "operator": scope.operator},
    )
    try:
        finding = tls_mod.probe(args.host, args.port, sni=args.sni)
    except Exception as exc:  # noqa: BLE001 — surface everything, log it
        audit.append("scan.tls.error", {"host": args.host, "error": repr(exc)})
        print(f"ERROR: probe failed: {exc}", file=sys.stderr)
        sys.exit(1)
    audit.append("scan.tls.finding", finding.to_dict())
    print(finding.to_json())
    print(f"\nworst case: {finding.worst_case.value}", file=sys.stderr)


def cmd_scan_espargos(args: argparse.Namespace) -> None:
    audit = AuditLog(args.audit)
    finding = esp_mod.assess(args.channel)
    audit.append("scan.espargos.finding", finding.to_dict())
    print(finding.to_json())


def cmd_audit_verify(args: argparse.Namespace) -> None:
    audit = AuditLog(args.audit)
    ok, n = audit.verify()
    if ok:
        print(f"OK: {n} entries, chain intact")
    else:
        print(f"FAIL: chain break detected at entry {n}", file=sys.stderr)
        sys.exit(1)


def cmd_audit_show(args: argparse.Namespace) -> None:
    audit = AuditLog(args.audit)
    for entry in audit.entries():
        print(f"[{entry['timestamp']}] {entry['event']}  -> {entry['this_hash'][:12]}")


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lain",
        description="LAIN — quantum red team framework",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scope-init", help="declare an authorized scope")
    sp.add_argument("--operator", required=True)
    sp.add_argument("--targets", nargs="+", required=True,
                    help="hostnames, IPs, CIDRs, or '*'")
    sp.add_argument("--authorized-by", required=True)
    sp.add_argument("--valid-until", required=True,
                    help="ISO 8601 datetime, e.g. 2026-12-31T23:59:59+00:00")
    sp.add_argument("--reference", default="")
    sp.add_argument("--out", default="scope.json")
    sp.set_defaults(func=cmd_scope_init)

    sp = sub.add_parser("scan-tls", help="active TLS endpoint probe")
    sp.add_argument("host")
    sp.add_argument("--port", type=int, default=443)
    sp.add_argument("--sni", default=None, help="override SNI hostname")
    sp.add_argument("--scope", default="scope.json")
    sp.add_argument("--audit", default="audit.log")
    sp.set_defaults(func=cmd_scan_tls)

    sp = sub.add_parser("scan-espargos", help="flag ESPARGOS RF channel")
    sp.add_argument("--channel", default="espargos-default")
    sp.add_argument("--audit", default="audit.log")
    sp.set_defaults(func=cmd_scan_espargos)

    sp = sub.add_parser("audit-verify", help="verify audit chain integrity")
    sp.add_argument("--audit", default="audit.log")
    sp.set_defaults(func=cmd_audit_verify)

    sp = sub.add_parser("audit-show", help="print audit entries in file order")
    sp.add_argument("--audit", default="audit.log")
    sp.set_defaults(func=cmd_audit_show)

    return p


def main() -> None:
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
