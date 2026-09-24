import checkdmarc
import dns.asyncresolver
import dns.resolver
import pytest

from vigia.tools.email_auth import EmailAuthInput, run


def _fake_check_domains(domains: list[str], **kwargs: object) -> dict[str, object]:
    return {
        "domain": domains[0],
        "spf": {"valid": False, "error": "No SPF record found."},
        "dmarc": {"valid": False, "error": "No DMARC record found."},
    }


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


async def test_email_auth_flags_missing_spf_and_dmarc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(checkdmarc, "check_domains", _fake_check_domains)

    async def fake_resolve(self: object, name: str, rtype: str) -> list[_FakeRdata]:
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await run(EmailAuthInput(domain="example.com"))

    types = {f.type for f in result.findings_candidates}
    assert types == {"spf_missing", "dmarc_missing", "dkim_not_found"}
    assert result.error is None


async def test_email_auth_flags_dmarc_policy_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_check(domains: list[str], **kwargs: object) -> dict[str, object]:
        return {
            "domain": domains[0],
            "spf": {"valid": True},
            "dmarc": {"valid": True, "tags": {"p": {"value": "none"}}},
        }

    monkeypatch.setattr(checkdmarc, "check_domains", fake_check)

    async def fake_resolve(self: object, name: str, rtype: str) -> list[_FakeRdata]:
        if name.startswith("google._domainkey"):
            return [_FakeRdata("v=DKIM1; k=rsa; p=abc")]
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", fake_resolve)

    result = await run(EmailAuthInput(domain="example.com"))

    types = {f.type for f in result.findings_candidates}
    assert types == {"dmarc_policy_none"}
