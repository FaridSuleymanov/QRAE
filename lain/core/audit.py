"""Hash-chained audit log.

Every LAIN action is an append-only block. Each block commits to the
previous via SHA-256 over a canonical JSON encoding. Tampering anywhere
in the file breaks the chain from that point forward, detectable by
`AuditLog.verify()`.

This mirrors the forensic-logging design used across the Yorozuya stack.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64


def _canonical(entry: dict) -> bytes:
    """Canonical JSON encoding for hashing — sorted keys, tight separators."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str).encode()


class AuditLog:
    """Append-only, tamper-evident log."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        with self.path.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                last = json.loads(line)["this_hash"]
        return last

    def append(self, event: str, data: dict) -> str:
        """Append a new entry. Returns the new entry's hash."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data,
            "prev_hash": self._last_hash,
        }
        this_hash = hashlib.sha256(_canonical(entry)).hexdigest()
        entry["this_hash"] = this_hash
        with self.path.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":"), default=str) + "\n")
        self._last_hash = this_hash
        return this_hash

    def verify(self) -> tuple[bool, int]:
        """Walk the chain and verify every link. Returns (ok, entries_checked)."""
        prev = GENESIS_HASH
        count = 0
        if not self.path.exists():
            return True, 0
        with self.path.open("r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("prev_hash") != prev:
                    return False, count
                stored = entry.pop("this_hash")
                recomputed = hashlib.sha256(_canonical(entry)).hexdigest()
                if recomputed != stored:
                    return False, count
                prev = stored
                count += 1
        return True, count

    def entries(self):
        """Iterate verified entries in file order."""
        if not self.path.exists():
            return
        with self.path.open("r") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)
