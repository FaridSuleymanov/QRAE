"""Tests for QRAE authorization scope."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from qrae.core import Scope, ScopeError


def _future(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def test_scope_exact_hostname_match():
    scope = Scope("operator", ["example.org"], "lab", _future())
    assert scope.covers("example.org")
    assert scope.covers("https://example.org:443")
    assert not scope.covers("other.example.org")


def test_scope_wildcard_hostname_match():
    scope = Scope("operator", ["*.example.org"], "lab", _future())
    assert scope.covers("api.example.org")
    assert scope.covers("deep.api.example.org")
    assert not scope.covers("example.org")


def test_scope_cidr_match():
    scope = Scope("operator", ["10.42.0.0/16"], "lab", _future())
    assert scope.covers("10.42.1.10")
    assert not scope.covers("10.43.1.10")


def test_scope_channel_name_exact_match():
    scope = Scope("operator", ["espargos-array-01"], "lab", _future())
    assert scope.covers("espargos-array-01")
    assert not scope.covers("espargos-array-02")


def test_scope_expiry_blocks_assessment():
    scope = Scope("operator", ["*"], "lab", _past())
    assert not scope.is_valid()
    with pytest.raises(ScopeError):
        scope.require_valid_for("example.org")


def test_scope_save_load_roundtrip(tmp_path):
    path = tmp_path / "scope.json"
    original = Scope(
        "operator",
        ["example.org", "10.0.0.0/8"],
        "lab",
        _future(),
        reference="LAB-001",
    )
    original.save(path)

    loaded = Scope.load(path)
    assert loaded.operator == "operator"
    assert loaded.targets == ["example.org", "10.0.0.0/8"]
    assert loaded.reference == "LAB-001"
    assert loaded.covers("10.1.2.3")
