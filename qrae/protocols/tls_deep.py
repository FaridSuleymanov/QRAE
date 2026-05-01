"""Deeper TLS inventory using Python TLS plus optional OpenSSL output parsing.

This is not a full raw ClientHello/ServerHello parser yet. It is a practical
intermediate step that extracts more operational evidence than Python ssl alone.
"""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
import warnings
from dataclasses import dataclass
from typing import Any

from qrae.core import Finding, classify_primitive
from qrae.protocols.tls import cipher_to_primitive, scan_tls_endpoint
from qrae.protocols.x509_chain import analyze_certificate_chain, load_pem_chain

_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

_TEMP_KEY_RE = re.compile(r"(?:Server Temp Key|Peer signing digest):\s*(.+)", re.IGNORECASE)
_CIPHER_RE = re.compile(r"(?:Ciphersuite|Cipher)\s*[:=]\s*([A-Za-z0-9_\-]+)")
_PROTOCOL_RE = re.compile(r"(?:Protocol version|Protocol)\s*[:=]\s*(TLSv[0-9.]+)")
_NEW_RE = re.compile(r"New,\s*(TLSv[0-9.]+),\s*Cipher is\s*([A-Za-z0-9_\-]+)")


@dataclass(frozen=True)
class OpenSSLResult:
    available: bool
    returncode: int | None
    output: str
    error: str | None = None


def scan_tls_deep(
    host: str,
    *,
    port: int = 443,
    sni: str | None = None,
    timeout: float = 6.0,
    use_openssl: bool = True,
) -> Finding:
    """Run deeper TLS inventory.

    The result combines:
    - Python ssl negotiated endpoint data
    - optional OpenSSL certificate-chain / temp-key / OCSP hints
    - version probing by forcing TLS protocol versions where supported locally
    """
    finding = scan_tls_endpoint(host, port=port, sni=sni, timeout=timeout)
    finding.protocol = "tls-deep"

    finding.metadata["version_probe"] = probe_tls_versions(host, port=port, sni=sni, timeout=timeout)

    if use_openssl:
        openssl = run_openssl_s_client(host, port=port, sni=sni, timeout=timeout)
        finding.metadata["openssl_available"] = openssl.available
        if openssl.error:
            finding.metadata["openssl_error"] = openssl.error
        if openssl.available and openssl.output:
            enrich_from_openssl_output(finding, openssl.output)

    finding.metadata.setdefault("limitations", [])
    finding.metadata["limitations"].append(
        "Full supported-group and server-preference inventory still requires a custom raw TLS handshake prober or packet parser."
    )
    return finding


def run_openssl_s_client(
    host: str,
    *,
    port: int = 443,
    sni: str | None = None,
    timeout: float = 6.0,
) -> OpenSSLResult:
    openssl = shutil.which("openssl")
    if not openssl:
        return OpenSSLResult(False, None, "", "openssl binary not found")

    server_name = sni or host
    command = [
        openssl,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        server_name,
        "-showcerts",
        "-status",
        "-tlsextdebug",
        "-brief",
    ]

    try:
        proc = subprocess.run(
            command,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return OpenSSLResult(True, None, "", repr(exc))

    output = proc.stdout.decode("utf-8", errors="replace") + "\n" + proc.stderr.decode(
        "utf-8", errors="replace"
    )
    return OpenSSLResult(True, proc.returncode, output)


def enrich_from_openssl_output(finding: Finding, output: str) -> None:
    finding.metadata["openssl_summary"] = parse_openssl_summary(output)

    cert_pem_blocks = _CERT_RE.findall(output)
    if cert_pem_blocks:
        certs = load_pem_chain("\n".join(cert_pem_blocks))
        records, primitives = analyze_certificate_chain(certs)
        finding.metadata["certificate_chain"] = records
        finding.extend(primitives)

    summary = finding.metadata["openssl_summary"]

    cipher = summary.get("cipher")
    if isinstance(cipher, str):
        primitive = cipher_to_primitive(cipher)
        if primitive is not None:
            finding.add(primitive)

    temp_key = summary.get("server_temp_key")
    if isinstance(temp_key, str):
        primitive = classify_group_or_temp_key(temp_key)
        if primitive is not None:
            finding.add(primitive)

    if "ocsp_response" in summary:
        finding.metadata["ocsp"] = summary["ocsp_response"]


def parse_openssl_summary(output: str) -> dict[str, Any]:
    summary: dict[str, Any] = {}

    new_match = _NEW_RE.search(output)
    if new_match:
        summary["protocol"] = new_match.group(1)
        summary["cipher"] = new_match.group(2)

    protocol_match = _PROTOCOL_RE.search(output)
    if protocol_match:
        summary["protocol"] = protocol_match.group(1)

    cipher_match = _CIPHER_RE.search(output)
    if cipher_match:
        summary["cipher"] = cipher_match.group(1)

    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("server temp key:"):
            summary["server_temp_key"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("verification:"):
            summary["verification"] = stripped.split(":", 1)[1].strip()
        elif "verify return code:" in stripped.lower():
            summary["verify_return_code"] = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("ocsp response:"):
            summary["ocsp_response"] = stripped.split(":", 1)[1].strip()
        elif "ocsp response status:" in stripped.lower():
            summary["ocsp_response_status"] = stripped.split(":", 1)[1].strip()

    summary["hybrid_or_pq_tls_hint"] = any(
        token in output.lower() for token in ("mlkem", "ml-kem", "kyber", "hqc")
    )
    return summary


def classify_group_or_temp_key(value: str):
    lower = value.lower()
    if "x25519" in lower and ("mlkem" in lower or "ml-kem" in lower or "kyber" in lower):
        return classify_primitive(lower.replace(" ", "-").replace(",", ""), None, "key_exchange", name=value)
    if "x25519" in lower:
        return classify_primitive("x25519", 253, "key_exchange", name=value)
    if "x448" in lower:
        return classify_primitive("x448", 448, "key_exchange", name=value)
    if "prime256v1" in lower or "secp256r1" in lower or "p-256" in lower:
        return classify_primitive("secp256r1", 256, "key_exchange", name=value)
    if "secp384r1" in lower or "p-384" in lower:
        return classify_primitive("secp384r1", 384, "key_exchange", name=value)
    if "secp521r1" in lower or "p-521" in lower:
        return classify_primitive("secp521r1", 521, "key_exchange", name=value)
    if "ffdhe" in lower or "dh" in lower:
        return classify_primitive("dh", None, "key_exchange", name=value)
    if any(token in lower for token in ("mlkem", "ml-kem", "kyber", "hqc")):
        return classify_primitive(lower.replace(" ", "-").replace(",", ""), None, "key_exchange", name=value)
    return None


def probe_tls_versions(
    host: str,
    *,
    port: int = 443,
    sni: str | None = None,
    timeout: float = 4.0,
) -> dict[str, Any]:
    versions = [
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]
    results: dict[str, Any] = {}
    for label, version in versions:
        if version is None:
            results[label] = {"supported": False, "error": "not supported by local Python/OpenSSL"}
            continue
        results[label] = _probe_one_tls_version(host, port, sni or host, version, timeout)
    return results


def _probe_one_tls_version(
    host: str,
    port: int,
    server_name: str,
    version: ssl.TLSVersion,
    timeout: float,
) -> dict[str, Any]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            context.minimum_version = version
            context.maximum_version = version
        except ValueError as exc:
            return {"supported": False, "error": str(exc)}

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=server_name) as tls_socket:
                cipher = tls_socket.cipher()
                return {
                    "supported": True,
                    "negotiated_version": tls_socket.version(),
                    "cipher": cipher[0] if cipher else None,
                }
    except Exception as exc:  # noqa: BLE001 - inventory result should record the failure reason.
        return {"supported": False, "error": type(exc).__name__}
