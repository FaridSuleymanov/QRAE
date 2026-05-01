"""Raw TLS 1.3 ClientHello probing for supported key-exchange groups.

This module intentionally stays narrow: it performs authorized, non-invasive
TLS handshakes and parses the first ServerHello/HelloRetryRequest/Alert. It is
not a full TLS implementation and does not complete the handshake.

Why it exists:
    Python's standard ``ssl`` API does not expose TLS 1.3 key_share /
    supported-group inventory. This prober sends controlled ClientHello messages
    with one candidate key-share group at a time and records how the server
    responds.

Current practical coverage:
    - X25519
    - secp256r1 / P-256
    - secp384r1 / P-384
    - secp521r1 / P-521

Hybrid/PQ group IDs are intentionally not hard-coded here because deployment
codepoints and library support can change. Operators can still add explicit
group IDs later through registry extension work.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from qrae.core import Finding, classify_primitive

TLS_RECORD_HANDSHAKE = 22
TLS_RECORD_ALERT = 21

HANDSHAKE_SERVER_HELLO = 2

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51

TLS13_VERSION = b"\x03\x04"
TLS12_LEGACY_VERSION = b"\x03\x03"

TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303

HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)


@dataclass(frozen=True)
class NamedGroup:
    name: str
    group_id: int
    family: str
    bits: int | None
    role: str = "key_exchange"


@dataclass(frozen=True)
class RawTLSProbeResult:
    group: str
    group_id: int
    supported: bool
    response_type: str
    selected_group: str | None = None
    selected_group_id: int | None = None
    selected_cipher: str | None = None
    selected_version: str | None = None
    alert_level: int | None = None
    alert_description: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "group_id": self.group_id,
            "supported": self.supported,
            "response_type": self.response_type,
            "selected_group": self.selected_group,
            "selected_group_id": self.selected_group_id,
            "selected_cipher": self.selected_cipher,
            "selected_version": self.selected_version,
            "alert_level": self.alert_level,
            "alert_description": self.alert_description,
            "error": self.error,
        }


NAMED_GROUPS: dict[str, NamedGroup] = {
    "x25519": NamedGroup("x25519", 0x001D, "x25519", 253),
    "secp256r1": NamedGroup("secp256r1", 0x0017, "secp256r1", 256),
    "p-256": NamedGroup("secp256r1", 0x0017, "secp256r1", 256),
    "prime256v1": NamedGroup("secp256r1", 0x0017, "secp256r1", 256),
    "secp384r1": NamedGroup("secp384r1", 0x0018, "secp384r1", 384),
    "p-384": NamedGroup("secp384r1", 0x0018, "secp384r1", 384),
    "secp521r1": NamedGroup("secp521r1", 0x0019, "secp521r1", 521),
    "p-521": NamedGroup("secp521r1", 0x0019, "secp521r1", 521),
}

GROUP_BY_ID = {group.group_id: group for group in set(NAMED_GROUPS.values())}

CIPHER_NAMES = {
    TLS_AES_128_GCM_SHA256: "TLS_AES_128_GCM_SHA256",
    TLS_AES_256_GCM_SHA384: "TLS_AES_256_GCM_SHA384",
    TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",
}


def scan_tls_raw_groups(
    host: str,
    *,
    port: int = 443,
    sni: str | None = None,
    groups: list[str] | None = None,
    timeout: float = 5.0,
) -> Finding:
    """Probe a TLS endpoint with raw TLS 1.3 ClientHello messages.

    This does not finish a TLS session. It sends a ClientHello with one
    candidate key-share group, parses the first server response, and closes the
    socket.
    """
    server_name = sni or host
    requested_groups = groups or ["x25519", "secp256r1", "secp384r1", "secp521r1"]

    finding = Finding(target=f"{host}:{port}", protocol="tls-raw-groups")
    finding.metadata["sni"] = server_name
    finding.metadata["probe_type"] = "raw_tls13_clienthello_group_enumeration"
    finding.metadata["requested_groups"] = requested_groups
    finding.metadata["limitations"] = [
        "This probe tests candidate key-share acceptance one group at a time.",
        "It does not enumerate every server-supported group unless the candidate list is comprehensive.",
        "Hybrid/PQ TLS group IDs are not hard-coded; add explicit registry entries when target stack policy is known.",
    ]

    results: list[dict[str, Any]] = []
    seen_primitives: set[str] = set()

    for group_name in requested_groups:
        group = resolve_group(group_name)
        result = probe_tls13_group(
            host,
            port=port,
            sni=server_name,
            group=group,
            timeout=timeout,
        )
        results.append(result.to_dict())

        if result.supported:
            primitive_key = f"{group.family}:{group.bits}:{group.role}"
            if primitive_key not in seen_primitives:
                finding.add(
                    classify_primitive(
                        group.family,
                        group.bits,
                        group.role,
                        name=f"TLS 1.3 key_share {group.name}",
                    )
                )
                seen_primitives.add(primitive_key)

    finding.metadata["raw_group_probe"] = results
    supported = [result["group"] for result in results if result["supported"]]
    finding.metadata["supported_candidate_groups"] = supported
    return finding


def resolve_group(group_name: str) -> NamedGroup:
    normalized = group_name.strip().lower()
    if normalized in NAMED_GROUPS:
        return NAMED_GROUPS[normalized]

    if normalized.startswith("0x"):
        group_id = int(normalized, 16)
        return NamedGroup(normalized, group_id, normalized, None)

    if normalized.isdigit():
        group_id = int(normalized, 10)
        return NamedGroup(f"0x{group_id:04x}", group_id, f"0x{group_id:04x}", None)

    raise ValueError(f"Unsupported raw TLS group name: {group_name}")


def probe_tls13_group(
    host: str,
    *,
    port: int,
    sni: str,
    group: NamedGroup,
    timeout: float,
) -> RawTLSProbeResult:
    try:
        client_hello = build_client_hello(sni, group)
    except Exception as exc:  # noqa: BLE001
        return RawTLSProbeResult(
            group=group.name,
            group_id=group.group_id,
            supported=False,
            response_type="client_build_error",
            error=repr(exc),
        )

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(client_hello)
            records = read_tls_records(sock, max_records=4)
    except Exception as exc:  # noqa: BLE001
        return RawTLSProbeResult(
            group=group.name,
            group_id=group.group_id,
            supported=False,
            response_type="network_error",
            error=type(exc).__name__,
        )

    return parse_probe_records(group, records)


def build_client_hello(server_name: str, group: NamedGroup) -> bytes:
    random = os.urandom(32)
    session_id = os.urandom(32)

    cipher_suites = b"".join(
        _u16(value)
        for value in (
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        )
    )

    extensions = b"".join(
        [
            _extension(EXT_SERVER_NAME, _server_name_extension(server_name)),
            _extension(EXT_SUPPORTED_VERSIONS, b"\x02" + TLS13_VERSION),
            _extension(EXT_SUPPORTED_GROUPS, _vector_u16(_u16(group.group_id))),
            _extension(EXT_SIGNATURE_ALGORITHMS, _signature_algorithms_extension()),
            _extension(EXT_PSK_KEY_EXCHANGE_MODES, b"\x01\x01"),
            _extension(EXT_KEY_SHARE, _key_share_extension(group)),
        ]
    )

    body = b"".join(
        [
            TLS12_LEGACY_VERSION,
            random,
            _opaque_u8(session_id),
            _vector_u16(cipher_suites),
            b"\x01\x00",  # legacy compression_methods: null only
            _vector_u16(extensions),
        ]
    )

    handshake = b"\x01" + _u24(len(body)) + body
    record = bytes([TLS_RECORD_HANDSHAKE]) + b"\x03\x01" + _u16(len(handshake)) + handshake
    return record


def read_tls_records(sock: socket.socket, *, max_records: int = 4) -> list[tuple[int, bytes]]:
    records: list[tuple[int, bytes]] = []
    for _ in range(max_records):
        header = _recv_exact(sock, 5)
        if not header:
            break
        record_type = header[0]
        length = int.from_bytes(header[3:5], "big")
        fragment = _recv_exact(sock, length)
        records.append((record_type, fragment))
        if record_type in {TLS_RECORD_ALERT, TLS_RECORD_HANDSHAKE}:
            break
    return records


def parse_probe_records(group: NamedGroup, records: list[tuple[int, bytes]]) -> RawTLSProbeResult:
    if not records:
        return RawTLSProbeResult(
            group=group.name,
            group_id=group.group_id,
            supported=False,
            response_type="no_response",
        )

    for record_type, fragment in records:
        if record_type == TLS_RECORD_ALERT and len(fragment) >= 2:
            return RawTLSProbeResult(
                group=group.name,
                group_id=group.group_id,
                supported=False,
                response_type="alert",
                alert_level=fragment[0],
                alert_description=fragment[1],
            )

        if record_type == TLS_RECORD_HANDSHAKE:
            parsed = parse_server_hello(fragment)
            if parsed is None:
                continue

            selected_group_id = parsed.get("selected_group_id")
            selected_group = group_name_by_id(selected_group_id)
            response_type = "hello_retry_request" if parsed.get("hello_retry_request") else "server_hello"

            # A ServerHello selecting the candidate group is a positive signal.
            # A HelloRetryRequest is recorded as a server-side group request but
            # is not treated as successful acceptance of the offered key share.
            supported = bool(
                response_type == "server_hello"
                and selected_group_id is not None
                and selected_group_id == group.group_id
            )

            return RawTLSProbeResult(
                group=group.name,
                group_id=group.group_id,
                supported=supported,
                response_type=response_type,
                selected_group=selected_group,
                selected_group_id=selected_group_id,
                selected_cipher=parsed.get("selected_cipher"),
                selected_version=parsed.get("selected_version"),
            )

    return RawTLSProbeResult(
        group=group.name,
        group_id=group.group_id,
        supported=False,
        response_type="unparsed_response",
    )


def parse_server_hello(fragment: bytes) -> dict[str, Any] | None:
    """Parse the first ServerHello-like handshake message in a TLS record."""
    offset = 0
    while offset + 4 <= len(fragment):
        handshake_type = fragment[offset]
        length = int.from_bytes(fragment[offset + 1 : offset + 4], "big")
        body = fragment[offset + 4 : offset + 4 + length]
        offset += 4 + length

        if handshake_type != HANDSHAKE_SERVER_HELLO or len(body) < 38:
            continue

        random = body[2:34]
        cursor = 34

        session_len = body[cursor]
        cursor += 1 + session_len
        if cursor + 3 > len(body):
            return None

        cipher_suite = int.from_bytes(body[cursor : cursor + 2], "big")
        cursor += 2
        cursor += 1  # compression

        if cursor + 2 > len(body):
            return None

        extensions_len = int.from_bytes(body[cursor : cursor + 2], "big")
        cursor += 2
        extensions_end = cursor + extensions_len

        selected_version: str | None = None
        selected_group_id: int | None = None

        while cursor + 4 <= len(body) and cursor < extensions_end:
            ext_type = int.from_bytes(body[cursor : cursor + 2], "big")
            ext_len = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
            ext_data = body[cursor + 4 : cursor + 4 + ext_len]
            cursor += 4 + ext_len

            if ext_type == EXT_SUPPORTED_VERSIONS and len(ext_data) >= 2:
                selected_version = tls_version_name(ext_data[:2])
            elif ext_type == EXT_KEY_SHARE:
                if random == HELLO_RETRY_REQUEST_RANDOM and len(ext_data) >= 2:
                    selected_group_id = int.from_bytes(ext_data[:2], "big")
                elif len(ext_data) >= 4:
                    selected_group_id = int.from_bytes(ext_data[:2], "big")

        return {
            "selected_cipher": CIPHER_NAMES.get(cipher_suite, f"0x{cipher_suite:04x}"),
            "selected_version": selected_version,
            "selected_group_id": selected_group_id,
            "hello_retry_request": random == HELLO_RETRY_REQUEST_RANDOM,
        }

    return None


def group_name_by_id(group_id: int | None) -> str | None:
    if group_id is None:
        return None
    if group_id in GROUP_BY_ID:
        return GROUP_BY_ID[group_id].name
    return f"0x{group_id:04x}"


def tls_version_name(raw: bytes) -> str:
    mapping = {
        b"\x03\x01": "TLSv1.0",
        b"\x03\x02": "TLSv1.1",
        b"\x03\x03": "TLSv1.2",
        b"\x03\x04": "TLSv1.3",
    }
    return mapping.get(raw, "0x" + raw.hex())


def _key_share_extension(group: NamedGroup) -> bytes:
    public = _key_share_public_bytes(group)
    entry = _u16(group.group_id) + _vector_u16(public)
    return _vector_u16(entry)


def _key_share_public_bytes(group: NamedGroup) -> bytes:
    if group.name == "x25519":
        private_key = x25519.X25519PrivateKey.generate()
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    curve: ec.EllipticCurve
    if group.name == "secp256r1":
        curve = ec.SECP256R1()
    elif group.name == "secp384r1":
        curve = ec.SECP384R1()
    elif group.name == "secp521r1":
        curve = ec.SECP521R1()
    else:
        raise ValueError(f"No key_share generator for group: {group.name}")

    private_key = ec.generate_private_key(curve)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def _signature_algorithms_extension() -> bytes:
    # rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512,
    # ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
    # ed25519, ed448, rsa_pkcs1_sha256.
    algorithms = [0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0807, 0x0808, 0x0401]
    return _vector_u16(b"".join(_u16(value) for value in algorithms))


def _server_name_extension(server_name: str) -> bytes:
    encoded = server_name.encode("idna")
    name = b"\x00" + _opaque_u16(encoded)
    return _vector_u16(name)


def _extension(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _opaque_u16(data)


def _vector_u16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _opaque_u8(data: bytes) -> bytes:
    return bytes([len(data)]) + data


def _opaque_u16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
