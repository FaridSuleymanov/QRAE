"""Tamper-evident local audit log for QRAE assessments."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS_HASH = "0" * 64


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def runtime_context() -> dict[str, Any]:
    return {
        "tool": "qrae",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "git_commit": _git_commit(),
    }


def _git_commit() -> str | None:
    env_commit = os.environ.get("QRAE_GIT_COMMIT")
    if env_commit:
        return env_commit
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    commit = proc.stdout.strip()
    return commit or None


class AuditLog:
    """Append-only JSONL audit log with SHA-256 hash chaining."""

    def __init__(
        self,
        path: str | Path = "audit.log",
        *,
        run_id: str | None = None,
        campaign_id: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or os.environ.get("QRAE_RUN_ID") or str(uuid.uuid4())
        self.campaign_id = campaign_id or os.environ.get("QRAE_CAMPAIGN_ID")
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        last_hash = GENESIS_HASH
        if not self.path.exists():
            return last_hash

        for entry in self.entries(unverified=True):
            last_hash = str(entry.get("this_hash", GENESIS_HASH))
        return last_hash

    @staticmethod
    def compute_hash(entry_without_hash: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical_json(entry_without_hash)).hexdigest()

    def append(self, event: str, data: dict[str, Any]) -> str:
        entry = {
            "schema_version": "qrae.audit.v2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "run_id": self.run_id,
            "campaign_id": self.campaign_id,
            "runtime": runtime_context(),
            "data": deepcopy(data),
            "prev_hash": self._last_hash,
        }
        entry["this_hash"] = self.compute_hash(entry)

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":"), default=str) + "\n")

        self._last_hash = entry["this_hash"]
        return entry["this_hash"]

    def entries(self, *, unverified: bool = False) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())

        def _iter() -> Iterator[dict[str, Any]]:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        yield json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        if unverified:
                            raise ValueError(f"Invalid JSON audit entry at line {line_number}") from exc
                        raise

        return _iter()

    def verify(self) -> tuple[bool, int, str | None]:
        previous_hash = GENESIS_HASH
        count = 0

        if not self.path.exists():
            return True, 0, None

        try:
            for entry in self.entries(unverified=True):
                if entry.get("prev_hash") != previous_hash:
                    return False, count, "previous hash mismatch"

                stored_hash = entry.get("this_hash")
                if not isinstance(stored_hash, str):
                    return False, count, "missing this_hash"

                entry_without_hash = dict(entry)
                entry_without_hash.pop("this_hash", None)
                recomputed_hash = self.compute_hash(entry_without_hash)
                if recomputed_hash != stored_hash:
                    return False, count, "entry hash mismatch"

                previous_hash = stored_hash
                count += 1
        except ValueError as exc:
            return False, count, str(exc)

        return True, count, None
