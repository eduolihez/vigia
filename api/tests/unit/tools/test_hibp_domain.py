import httpx
import respx

from vigia.tools.hibp_domain import HibpDomainInput, run


async def test_hibp_domain_without_key_is_graceful() -> None:
    async with httpx.AsyncClient() as client:
        result = await run(HibpDomainInput(domain="example.com"), client, api_key=None)

    assert result.error == "HIBP API key not configured"


@respx.mock
async def test_hibp_domain_aggregates_breach_counts() -> None:
    respx.get("https://haveibeenpwned.com/api/v3/breacheddomain/example.com").respond(
        json={
            "alice": ["Adobe", "LinkedIn"],
            "bob": ["Adobe"],
        }
    )

    async with httpx.AsyncClient() as client:
        result = await run(HibpDomainInput(domain="example.com"), client, api_key="key")

    by_title = {f.title for f in result.findings_candidates}
    assert "2 account(s) on example.com appear in breach 'Adobe'" in by_title
    assert "1 account(s) on example.com appear in breach 'LinkedIn'" in by_title
    # No raw email addresses ever appear in the findings.
    assert not any("alice" in f.title or "bob" in f.title for f in result.findings_candidates)


@respx.mock
async def test_hibp_domain_unverified_domain_is_graceful() -> None:
    respx.get("https://haveibeenpwned.com/api/v3/breacheddomain/example.com").respond(
        status_code=403
    )

    async with httpx.AsyncClient() as client:
        result = await run(HibpDomainInput(domain="example.com"), client, api_key="key")

    assert result.error is not None
