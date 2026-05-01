"""SSH host-key inventory for QRAE.

This module uses ssh-keyscan for safe host-key discovery. It does not authenticate
to the server and does not attempt exploitation.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from qrae.core import Finding, classify_primitive


def scan_ssh_host_keys(
    host: str,
    *,
    port: int = 22,
    timeout: float = 5.0,
    key_types: str = "rsa,ecdsa,ed25519",
) -> Finding:
    finding = Finding(target=f"{host}:{port}", protocol="ssh")
    finding.metadata["scanner"] = "ssh-keyscan"
    finding.metadata["requested_key_types"] = key_types

    ssh_keyscan = shutil.which("ssh-keyscan")
    if not ssh_keyscan:
        finding.metadata["error"] = "ssh-keyscan binary not found"
        finding.add(classify_primitive("unknown", None, "ssh_host_key", name="ssh-keyscan unavailable"))
        return finding

    command = [
        ssh_keyscan,
        "-T",
        str(int(timeout)),
        "-p",
        str(port),
        "-t",
        key_types,
        host,
    ]

    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        finding.metadata["error"] = repr(exc)
        finding.add(classify_primitive("unknown", None, "ssh_host_key", name="ssh-keyscan failed"))
        return finding

    finding.metadata["returncode"] = proc.returncode
    finding.metadata["stderr"] = proc.stderr.strip()

    records, primitives = parse_ssh_keyscan_output(proc.stdout)
    finding.metadata["host_keys"] = records
    finding.extend(primitives)

    if not records:
        finding.metadata["warning"] = "No SSH host keys parsed"
        finding.add(classify_primitive("unknown", None, "ssh_host_key", name="No SSH host keys parsed"))

    finding.metadata["limitations"] = [
        "This phase inventories SSH host keys. Full server KEX algorithm negotiation inventory is planned separately."
    ]
    return finding


def parse_ssh_keyscan_output(output: str) -> tuple[list[dict[str, Any]], list]:
    records: list[dict[str, Any]] = []
    primitives = []

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        host_field, key_type, key_blob = parts[:3]
        record = {"host": host_field, "key_type": key_type}
        primitive = _classify_ssh_key(key_type, key_blob)
        record["primitive"] = primitive.to_dict()
        records.append(record)
        primitives.append(primitive)

    return records, primitives


def _classify_ssh_key(key_type: str, key_blob: str):
    line = f"{key_type} {key_blob}".encode("ascii")
    try:
        key = load_ssh_public_key(line)
    except Exception:  # noqa: BLE001
        return classify_primitive(key_type, None, "ssh_host_key", name=key_type)

    if isinstance(key, rsa.RSAPublicKey):
        return classify_primitive("rsa", key.key_size, "ssh_host_key", name=key_type)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return classify_primitive(key.curve.name, key.curve.key_size, "ssh_host_key", name=key_type)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return classify_primitive("ed25519", 256, "ssh_host_key", name=key_type)
    return classify_primitive(key_type, None, "ssh_host_key", name=key_type)
