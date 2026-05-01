"""Local code/config cryptographic hint scanner.

This is not a full static analyzer. It identifies patterns that should be
reviewed during post-quantum migration inventory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from qrae.core import Finding, classify_primitive

_SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}

_PATTERNS: tuple[tuple[str, str, int | None, str, re.Pattern[str]], ...] = (
    ("PEM RSA private key", "rsa", None, "code_or_config", re.compile(r"BEGIN RSA PRIVATE KEY")),
    ("PEM EC private key", "ecdsa", None, "code_or_config", re.compile(r"BEGIN EC PRIVATE KEY")),
    ("OpenSSH RSA key", "rsa", None, "code_or_config", re.compile(r"\bssh-rsa\b")),
    ("OpenSSH ECDSA key", "ecdsa", None, "code_or_config", re.compile(r"\becdsa-sha2-")),
    ("OpenSSH Ed25519 key", "ed25519", 256, "code_or_config", re.compile(r"\bssh-ed25519\b")),
    ("X25519 reference", "x25519", 253, "code_or_config", re.compile(r"\bX25519\b", re.IGNORECASE)),
    ("RSA API reference", "rsa", None, "code_or_config", re.compile(r"\bRSA\b|rsa\.GenerateKey|generate_private_key", re.IGNORECASE)),
    ("ECDSA API reference", "ecdsa", None, "code_or_config", re.compile(r"\bECDSA\b|EllipticCurve|secp256r1|prime256v1", re.IGNORECASE)),
    ("TLS 1.0/1.1 reference", "unknown", None, "legacy_tls_config", re.compile(r"TLSv1(?:\.0|\.1)?\b|PROTOCOL_TLSv1", re.IGNORECASE)),
    ("ML-KEM reference", "ml-kem", None, "code_or_config", re.compile(r"ML[-_]?KEM", re.IGNORECASE)),
    ("Kyber legacy name", "kyber", None, "code_or_config", re.compile(r"\bKyber(?:512|768|1024)?\b", re.IGNORECASE)),
)


@dataclass(frozen=True)
class CodeScanOptions:
    max_file_bytes: int = 1_000_000


def scan_code_path(path: str | Path, *, options: CodeScanOptions | None = None) -> list[Finding]:
    root = Path(path)
    opts = options or CodeScanOptions()
    findings: list[Finding] = []

    for file_path in _iter_files(root):
        try:
            if file_path.stat().st_size > opts.max_file_bytes:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        matches = []
        finding = Finding(target=str(file_path), protocol="code-scan")
        for label, family, bits, role, pattern in _PATTERNS:
            hit_count = len(pattern.findall(text))
            if hit_count:
                primitive = classify_primitive(family, bits, role, name=label)
                finding.add(primitive)
                matches.append({"label": label, "hits": hit_count, "family": family, "role": role})

        if matches:
            finding.metadata["matches"] = matches
            findings.append(finding)

    return findings


def _iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path
