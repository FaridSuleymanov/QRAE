from datetime import datetime, timedelta, timezone

from qrae.core import Scope


def future():
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def test_wildcard_hostname_scope():
    scope = Scope("op", ["*.example.org"], "lab", future())
    assert scope.covers("api.example.org")
    assert not scope.covers("example.org")


def test_cidr_scope():
    scope = Scope("op", ["10.42.0.0/16"], "lab", future())
    assert scope.covers("10.42.1.2")
    assert not scope.covers("10.43.1.2")
