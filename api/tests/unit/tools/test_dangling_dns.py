import dns.asyncresolver
import dns.resolver
import pytest

from vigia.tools.dangling_dns import DanglingDnsInput, run


class _FakeTarget:
    def __init__(self, name: str) -> None:
        self._name = name

    def __str__(self) -> str:
        return self._name


class _FakeRdata:
    def __init__(self, target: str) -> None:
        self.target = _FakeTarget(target)


async def test_dangling_dns_flags_known_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(self: object, hostname: str, rtype: str) -> list[_FakeRdata]:
        return [_FakeRdata("unclaimed-bucket.s3.amazonaws.com.")]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await run(DanglingDnsInput(hostname="assets.example.com"))

    assert len(result.findings_candidates) == 1
    assert "AWS S3" in result.findings_candidates[0].title
    assert result.error is None


async def test_dangling_dns_no_match_for_unknown_cname(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(self: object, hostname: str, rtype: str) -> list[_FakeRdata]:
        return [_FakeRdata("internal.example.com.")]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await run(DanglingDnsInput(hostname="app.example.com"))

    assert result.findings_candidates == []


async def test_dangling_dns_handles_no_cname(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(self: object, hostname: str, rtype: str) -> list[_FakeRdata]:
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await run(DanglingDnsInput(hostname="app.example.com"))

    assert result.findings_candidates == []
    assert result.error is None
