"""tls_check — inspects a hostname's TLS certificate and negotiated protocol (Phase 7).

Connects on port 443 with certificate verification *disabled* deliberately — the
point is to see whatever certificate is actually being served (expired, self-signed,
wrong hostname) and report it as a finding, not to fail before we can look at it. The
certificate is parsed independently with `cryptography` rather than relying on
`ssl.SSLSocket.getpeercert()`'s dict form, since that form is only populated when
verification succeeded.

Active mode only — opens a real TCP/TLS connection to the target host.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import ssl
import time
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from pydantic import BaseModel

from vigia.tools.base import FindingCandidate, ToolMode, ToolResult, ToolSpec, finalize

SPEC = ToolSpec(
    name="tls_check",
    mode=ToolMode.ACTIVE,
    requires_api_key=False,
    description=(
        "Connects to a hostname on 443 and inspects its TLS certificate for expiry, "
        "self-signed/hostname-mismatch issues, and a weak negotiated protocol version."
    ),
)

CONNECT_TIMEOUT_SECONDS = 10.0
EXPIRING_SOON_DAYS = 30
WEAK_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}


class TlsCheckInput(BaseModel):
    hostname: str
    port: int = 443


def _common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _subject_alt_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return ext.value.get_values_for_type(x509.DNSName)


def _hostname_matches(hostname: str, cert: x509.Certificate) -> bool:
    hostname = hostname.lower()
    candidates = {v.lower() for v in _subject_alt_names(cert)}
    cn = _common_name(cert.subject)
    if cn:
        candidates.add(cn.lower())

    def _match(pattern: str) -> bool:
        if pattern.startswith("*."):
            return hostname.endswith(pattern[1:]) and hostname.count(".") == pattern.count(".")
        return hostname == pattern

    return any(_match(c) for c in candidates)


async def run(input: TlsCheckInput) -> ToolResult:
    start = time.monotonic()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                input.hostname, input.port, ssl=ctx, server_hostname=input.hostname
            ),
            timeout=CONNECT_TIMEOUT_SECONDS,
        )
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return finalize(
            SPEC.name,
            start,
            error=f"tls_check: could not connect to {input.hostname}:{input.port}: {exc}",
        )

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der_cert: bytes = ssl_object.getpeercert(binary_form=True)
        protocol_version: str = ssl_object.version()
    finally:
        writer.close()
        with contextlib.suppress(Exception):  # best-effort close; the check is already done
            await writer.wait_closed()

    if not der_cert:
        return finalize(
            SPEC.name,
            start,
            error=f"tls_check: {input.hostname}:{input.port} presented no certificate",
        )

    cert = x509.load_der_x509_certificate(der_cert)

    findings: list[FindingCandidate] = []
    now = datetime.now(UTC)
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days

    if days_left < 0:
        findings.append(
            FindingCandidate(
                type="tls_cert_expired",
                title=f"TLS certificate for {input.hostname} expired {-days_left} day(s) ago",
                detail=f"Certificate not valid after {not_after.isoformat()}.",
                asset_value=input.hostname,
            )
        )
    elif days_left <= EXPIRING_SOON_DAYS:
        findings.append(
            FindingCandidate(
                type="tls_cert_expiring_soon",
                title=f"TLS certificate for {input.hostname} expires in {days_left} day(s)",
                detail=f"Certificate not valid after {not_after.isoformat()}.",
                asset_value=input.hostname,
            )
        )

    if cert.issuer == cert.subject:
        findings.append(
            FindingCandidate(
                type="tls_self_signed",
                title=f"{input.hostname} serves a self-signed TLS certificate",
                detail=f"Issuer and subject are identical: {cert.subject.rfc4514_string()}.",
                asset_value=input.hostname,
            )
        )

    if not _hostname_matches(input.hostname, cert):
        san_or_cn = ", ".join(_subject_alt_names(cert)) or _common_name(cert.subject) or "none"
        findings.append(
            FindingCandidate(
                type="tls_hostname_mismatch",
                title=f"TLS certificate for {input.hostname} does not cover this hostname",
                detail=f"Certificate SAN/CN entries: {san_or_cn}.",
                asset_value=input.hostname,
            )
        )

    if protocol_version in WEAK_PROTOCOLS:
        findings.append(
            FindingCandidate(
                type="tls_weak_protocol",
                title=f"{input.hostname} negotiated a weak TLS protocol ({protocol_version})",
                detail=f"Negotiated {protocol_version}; TLS 1.2 or higher is expected.",
                asset_value=input.hostname,
            )
        )

    raw_output = json.dumps(
        {
            "hostname": input.hostname,
            "port": input.port,
            "protocol_version": protocol_version,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_after": not_after.isoformat(),
            "subject_alt_names": _subject_alt_names(cert),
        }
    ).encode()
    return finalize(SPEC.name, start, raw_output=raw_output, findings=findings)
