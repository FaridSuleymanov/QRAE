"""Tests for the hash-chained audit log."""

import json

import pytest

from lain.core import AuditLog


def test_empty_log_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.log")
    ok, n = log.verify()
    assert ok and n == 0


def test_single_entry_chain(tmp_path):
    log = AuditLog(tmp_path / "a.log")
    h = log.append("test", {"k": "v"})
    assert len(h) == 64
    ok, n = log.verify()
    assert ok and n == 1


def test_many_entries_chain(tmp_path):
    log = AuditLog(tmp_path / "a.log")
    for i in range(10):
        log.append("test", {"i": i})
    ok, n = log.verify()
    assert ok and n == 10


def test_tamper_detection(tmp_path):
    path = tmp_path / "a.log"
    log = AuditLog(path)
    log.append("first", {"k": 1})
    log.append("second", {"k": 2})
    log.append("third", {"k": 3})

    # Tamper with the middle entry
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["data"]["k"] = 999
    lines[1] = json.dumps(entry, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    ok, n = AuditLog(path).verify()
    assert not ok
    assert n == 1  # first entry still valid, break at second


def test_reload_preserves_chain(tmp_path):
    path = tmp_path / "a.log"
    log1 = AuditLog(path)
    log1.append("a", {})
    log1.append("b", {})

    log2 = AuditLog(path)
    log2.append("c", {})

    ok, n = AuditLog(path).verify()
    assert ok and n == 3
