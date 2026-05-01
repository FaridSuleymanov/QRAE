"""Tests for QRAE audit log integrity."""

from __future__ import annotations

import json

from qrae.core import AuditLog


def test_empty_audit_log_verifies(tmp_path):
    audit = AuditLog(tmp_path / "audit.log")
    ok, count, error = audit.verify()
    assert ok
    assert count == 0
    assert error is None


def test_audit_log_appends_and_verifies(tmp_path):
    audit = AuditLog(tmp_path / "audit.log")
    digest = audit.append("test.event", {"value": 1})

    assert len(digest) == 64
    ok, count, error = audit.verify()
    assert ok
    assert count == 1
    assert error is None


def test_audit_log_detects_tampering(tmp_path):
    path = tmp_path / "audit.log"
    audit = AuditLog(path)
    audit.append("first", {"value": 1})
    audit.append("second", {"value": 2})

    lines = path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["data"]["value"] = 999
    lines[1] = json.dumps(second, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, count, error = AuditLog(path).verify()
    assert not ok
    assert count == 1
    assert error == "entry hash mismatch"


def test_reopened_audit_log_preserves_chain(tmp_path):
    path = tmp_path / "audit.log"
    AuditLog(path).append("first", {})
    AuditLog(path).append("second", {})

    ok, count, error = AuditLog(path).verify()
    assert ok
    assert count == 2
    assert error is None
