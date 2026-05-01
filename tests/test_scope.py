"""Tests for the scope gate."""

from datetime import datetime, timedelta, timezone

from lain.core import Scope


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def test_exact_match():
    s = Scope("op", ["host.example.com"], "self", _future())
    assert s.covers("host.example.com")
    assert not s.covers("other.example.com")


def test_wildcard():
    s = Scope("op", ["*"], "self", _future())
    assert s.covers("anything.example.com")
    assert s.covers("10.0.0.1")


def test_cidr_match():
    s = Scope("op", ["10.42.0.0/16"], "self", _future())
    assert s.covers("10.42.1.1")
    assert not s.covers("10.43.0.1")


def test_expired_scope():
    s = Scope("op", ["*"], "self", _past())
    assert not s.is_valid()


def test_valid_scope():
    s = Scope("op", ["*"], "self", _future())
    assert s.is_valid()


def test_save_load_roundtrip(tmp_path):
    path = tmp_path / "scope.json"
    original = Scope("op", ["host1", "10.0.0.0/8"], "manager", _future(),
                     reference="TICKET-42")
    original.save(path)
    loaded = Scope.load(path)
    assert loaded.operator == "op"
    assert loaded.targets == ["host1", "10.0.0.0/8"]
    assert loaded.reference == "TICKET-42"
    assert loaded.covers("10.1.2.3")
