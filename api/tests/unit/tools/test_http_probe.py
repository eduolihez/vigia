"""http_probe tests — every response is a local `httpx.MockTransport` handler, never
a real network call (brief rule: active tools are tested against mocks/local
targets, not real domains, even example.com)."""

from __future__ import annotations

import httpx

from vigia.tools.http_probe import HttpProbeInput, run


def _client(handler: httpx.MockTransport) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=handler)


async def test_reports_missing_security_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"server": "nginx"}, text="<html>ok</html>")

    async with _client(httpx.MockTransport(handler)) as client:
        result = await run(HttpProbeInput(hostname="www.example.com"), client)

    assert result.error is None
    types = {f.type for f in result.findings_candidates}
    assert "missing_security_headers" in types


async def test_no_finding_when_security_headers_present() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=63072000",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
            },
            text="<html>ok</html>",
        )

    async with _client(httpx.MockTransport(handler)) as client:
        result = await run(HttpProbeInput(hostname="www.example.com"), client)

    types = {f.type for f in result.findings_candidates}
    assert "missing_security_headers" not in types


async def test_reports_verbose_server_banner() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "server": "Apache/2.4.41 (Ubuntu)",
                "strict-transport-security": "max-age=1",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
            },
            text="<html>ok</html>",
        )

    async with _client(httpx.MockTransport(handler)) as client:
        result = await run(HttpProbeInput(hostname="www.example.com"), client)

    types = {f.type for f in result.findings_candidates}
    assert "verbose_server_banner" in types


async def test_confirms_dangling_dns_takeover_from_body_signature() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404, text="Company site not found. NoSuchBucket does not exist in this region."
        )

    async with _client(httpx.MockTransport(handler)) as client:
        result = await run(HttpProbeInput(hostname="stale.example.com"), client)

    confirmed = [f for f in result.findings_candidates if f.type == "dangling_dns_confirmed"]
    assert len(confirmed) == 1
    assert "stale.example.com" in confirmed[0].title


async def test_falls_back_to_http_when_https_connection_fails() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.scheme)
        if request.url.scheme == "https":
            raise httpx.ConnectError("connection refused", request=request)
        return httpx.Response(200, text="plain http ok")

    async with _client(httpx.MockTransport(handler)) as client:
        result = await run(HttpProbeInput(hostname="http-only.example.com"), client)

    assert calls == ["https", "http"]
    assert result.error is None


async def test_error_when_both_schemes_fail() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    async with _client(httpx.MockTransport(handler)) as client:
        result = await run(HttpProbeInput(hostname="unreachable.example.com"), client)

    assert result.error is not None
    assert "unreachable.example.com" in result.error
