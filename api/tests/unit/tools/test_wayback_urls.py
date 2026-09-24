import httpx
import respx

from vigia.tools.wayback_urls import WaybackUrlsInput, run


@respx.mock
async def test_wayback_urls_parses_cdx_rows() -> None:
    respx.get("http://web.archive.org/cdx/search/cdx").respond(
        json=[["original"], ["http://example.com:80/"], ["http://www.example.com:80/about"]]
    )

    async with httpx.AsyncClient() as client:
        result = await run(WaybackUrlsInput(domain="example.com"), client)

    values = {a.value for a in result.assets_discovered}
    assert values == {"http://example.com:80/", "http://www.example.com:80/about"}
    assert result.error is None


@respx.mock
async def test_wayback_urls_handles_empty_response() -> None:
    respx.get("http://web.archive.org/cdx/search/cdx").respond(json=[])

    async with httpx.AsyncClient() as client:
        result = await run(WaybackUrlsInput(domain="example.com"), client)

    assert result.assets_discovered == []
    assert result.error is None
