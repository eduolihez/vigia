import httpx
import respx

from vigia.tools.ct_subdomains import CtSubdomainsInput, run


@respx.mock
async def test_ct_subdomains_extracts_and_dedupes() -> None:
    respx.get("https://crt.sh/").respond(
        json=[
            {"name_value": "www.example.com\nexample.com"},
            {"name_value": "*.api.example.com"},
            {"name_value": "unrelated.org"},
        ]
    )

    async with httpx.AsyncClient() as client:
        result = await run(CtSubdomainsInput(domain="example.com"), client)

    values = {a.value for a in result.assets_discovered}
    assert values == {"www.example.com", "api.example.com"}
    assert result.error is None


@respx.mock
async def test_ct_subdomains_handles_upstream_502() -> None:
    respx.get("https://crt.sh/").respond(status_code=502)

    async with httpx.AsyncClient() as client:
        result = await run(CtSubdomainsInput(domain="example.com"), client)

    assert result.error is not None
    assert result.assets_discovered == []
