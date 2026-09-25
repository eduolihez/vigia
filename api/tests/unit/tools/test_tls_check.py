"""tls_check tests. `run()` is exercised against a real local TLS server (a
self-signed cert generated in-memory, bound to 127.0.0.1) — a local test target, not
a real domain, same spirit as the PDF exporter's real-Chromium test. The
hostname-matching/self-signed-detection helpers are also tested directly against
`cryptography` certificate objects, no network involved.
"""

from __future__ import annotations

import asyncio
import datetime
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vigia.tools.tls_check import TlsCheckInput, _common_name, _hostname_matches, run


def _make_self_signed_cert(
    common_name: str, san: list[str], *, not_after: datetime.datetime | None = None
) -> tuple[bytes, bytes]:
    """Returns (cert_pem, key_pem) for a self-signed cert usable by an ssl.SSLContext."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    # 90-day default validity (well outside tls_check's 30-day "expiring soon"
    # window); not_valid_before is always derived from not_valid_after so an
    # already-expired `not_after` still produces a well-ordered (before < after)
    # certificate instead of a ValueError from the builder.
    effective_not_after = not_after or (now + datetime.timedelta(days=90))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(effective_not_after - datetime.timedelta(days=91))
        .not_valid_after(effective_not_after)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


async def _start_tls_server(
    cert_pem: bytes, key_pem: bytes, tmp_path: object
) -> tuple[int, asyncio.AbstractServer]:
    import tempfile
    from pathlib import Path

    tmp_dir = Path(tempfile.mkdtemp())
    cert_path = tmp_dir / "cert.pem"
    key_path = tmp_dir / "key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    return port, server


async def test_run_reports_no_findings_for_a_healthy_cert(tmp_path: object) -> None:
    # The client always connects to the literal IP 127.0.0.1 (no DNS lookup needed
    # for a local test server) — the certificate's own SAN content, not the
    # connection target, is what `_hostname_matches` checks.
    cert_pem, key_pem = _make_self_signed_cert("127.0.0.1", ["127.0.0.1"])
    port, server = await _start_tls_server(cert_pem, key_pem, tmp_path)
    async with server:
        result = await run(TlsCheckInput(hostname="127.0.0.1", port=port))
    server.close()

    assert result.error is None
    # A freshly-minted 30-day cert whose SAN covers the connected hostname is
    # self-signed but otherwise fine — self-signed is the one finding we *do* expect.
    types = {f.type for f in result.findings_candidates}
    assert types == {"tls_self_signed"}


async def test_run_flags_hostname_mismatch(tmp_path: object) -> None:
    cert_pem, key_pem = _make_self_signed_cert(
        "not-the-cert-name.example.test", ["not-the-cert-name.example.test"]
    )
    port, server = await _start_tls_server(cert_pem, key_pem, tmp_path)
    async with server:
        result = await run(TlsCheckInput(hostname="127.0.0.1", port=port))
    server.close()

    types = {f.type for f in result.findings_candidates}
    assert "tls_hostname_mismatch" in types


async def test_run_flags_expired_certificate(tmp_path: object) -> None:
    expired = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    cert_pem, key_pem = _make_self_signed_cert("127.0.0.1", ["127.0.0.1"], not_after=expired)
    port, server = await _start_tls_server(cert_pem, key_pem, tmp_path)
    async with server:
        result = await run(TlsCheckInput(hostname="127.0.0.1", port=port))
    server.close()

    types = {f.type for f in result.findings_candidates}
    assert "tls_cert_expired" in types


async def test_run_reports_error_for_unreachable_host() -> None:
    result = await run(TlsCheckInput(hostname="localhost", port=65531))
    assert result.error is not None


def test_hostname_matches_exact_and_wildcard_san() -> None:
    cert_pem, _ = _make_self_signed_cert(
        "cn.example.test", ["exact.example.test", "*.wild.example.test"]
    )
    cert = x509.load_pem_x509_certificate(cert_pem)

    assert _hostname_matches("exact.example.test", cert) is True
    assert _hostname_matches("app.wild.example.test", cert) is True
    assert _hostname_matches("sub.app.wild.example.test", cert) is False
    assert _hostname_matches("unrelated.example.test", cert) is False


def test_common_name_extraction() -> None:
    cert_pem, _ = _make_self_signed_cert("my-cn.example.test", [])
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert _common_name(cert.subject) == "my-cn.example.test"
