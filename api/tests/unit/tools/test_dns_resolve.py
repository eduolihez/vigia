import dns.asyncresolver
import dns.resolver
import pytest

from vigia.tools.dns_resolve import DnsResolveInput, run


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


async def test_dns_resolve_collects_records(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(self: object, hostname: str, rtype: str) -> list[_FakeRdata]:
        if rtype == "A":
            return [_FakeRdata("93.184.216.34")]
        if rtype == "MX":
            return [_FakeRdata("0 .")]
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await run(DnsResolveInput(hostname="example.com"))

    ips = {a.value for a in result.assets_discovered}
    assert ips == {"93.184.216.34"}
    assert result.error is None


async def test_dns_resolve_handles_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(self: object, hostname: str, rtype: str) -> list[_FakeRdata]:
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await run(DnsResolveInput(hostname="does-not-exist.example.com"))

    assert result.assets_discovered == []
    assert result.error is None
