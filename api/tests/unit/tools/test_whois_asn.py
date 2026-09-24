import httpx
import respx

from vigia.tools.whois_asn import WhoisAsnInput, run


@respx.mock
async def test_whois_asn_finds_asn_holder() -> None:
    respx.get("https://stat.ripe.net/data/whois/data.json").respond(json={"data": {"records": []}})
    respx.get("https://stat.ripe.net/data/network-info/data.json").respond(
        json={"data": {"asns": ["15133"], "prefix": "93.184.216.0/24"}}
    )
    respx.get("https://stat.ripe.net/data/as-overview/data.json").respond(
        json={"data": {"holder": "EDGECAST-NETWORK, US"}}
    )

    async with httpx.AsyncClient() as client:
        result = await run(WhoisAsnInput(resource="93.184.216.34"), client)

    assert result.error is None
    assert any("AS15133" in f.title for f in result.findings_candidates)
    assert result.sha256


@respx.mock
async def test_whois_asn_handles_request_failure() -> None:
    respx.get("https://stat.ripe.net/data/whois/data.json").mock(
        side_effect=httpx.ConnectError("boom")
    )

    async with httpx.AsyncClient() as client:
        result = await run(WhoisAsnInput(resource="example.com"), client)

    assert result.error is not None
