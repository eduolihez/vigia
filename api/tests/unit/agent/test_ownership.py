import dns.asyncresolver
import dns.resolver
import pytest

from vigia.agent.ownership import generate_token, verify_ownership


class _FakeTxt:
    def __init__(self, *parts: bytes) -> None:
        self.strings = list(parts)


def test_generate_token_has_expected_prefix() -> None:
    token = generate_token()
    assert token.startswith("vigia-verify=")
    assert len(token) > len("vigia-verify=")


async def test_verify_ownership_matches_published_token(monkeypatch: pytest.MonkeyPatch) -> None:
    token = generate_token()

    async def fake_resolve(self: object, domain: str, rtype: str) -> list[_FakeTxt]:
        return [_FakeTxt(b"unrelated=1"), _FakeTxt(token.encode())]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    assert await verify_ownership("example.com", token) is True


async def test_verify_ownership_rejects_mismatched_token(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(self: object, domain: str, rtype: str) -> list[_FakeTxt]:
        return [_FakeTxt(b"vigia-verify=someone-elses-token")]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    assert await verify_ownership("example.com", generate_token()) is False


async def test_verify_ownership_fails_closed_on_nxdomain(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(self: object, domain: str, rtype: str) -> list[_FakeTxt]:
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    assert await verify_ownership("example.com", generate_token()) is False
