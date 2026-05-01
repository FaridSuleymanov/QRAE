"""Ed25519 signing helpers for QRAE findings, reports and scope files."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair(
    private_key_path: str | Path,
    public_key_path: str | Path,
    *,
    overwrite: bool = False,
) -> None:
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    if not overwrite and (private_path.exists() or public_path.exists()):
        raise FileExistsError("key file exists; pass overwrite=True to replace")

    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)


def sign_file(
    file_path: str | Path,
    private_key_path: str | Path,
    signature_path: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(file_path)
    private_key = _load_private_key(private_key_path)
    data = path.read_bytes()
    signature = private_key.sign(data)

    payload = {
        "schema_version": "qrae.signature.v1",
        "file": path.name,
        "algorithm": "ed25519",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }
    out = Path(signature_path) if signature_path else path.with_suffix(path.suffix + ".sig.json")
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def verify_file(
    file_path: str | Path,
    signature_path: str | Path,
    public_key_path: str | Path,
) -> bool:
    path = Path(file_path)
    signature_payload = json.loads(Path(signature_path).read_text(encoding="utf-8"))
    signature = base64.b64decode(signature_payload["signature_b64"])
    public_key = _load_public_key(public_key_path)
    try:
        public_key.verify(signature, path.read_bytes())
    except InvalidSignature:
        return False
    return True


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("private key is not Ed25519")
    return key


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("public key is not Ed25519")
    return key
