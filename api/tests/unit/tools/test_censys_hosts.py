import httpx
import respx

from vigia.tools.censys_hosts import CensysHostsInput, run


async def test_censys_hosts_without_key_is_graceful() -> None:
    async with httpx.AsyncClient() as client:
        result = await run(CensysHostsInput(ip="1.2.3.4"), client, api_id=None, api_secret=None)

    assert result.error == "Censys API credentials not configured"


@respx.mock
async def test_censys_hosts_parses_services() -> None:
    respx.get("https://search.censys.io/api/v2/hosts/1.2.3.4").respond(
        json={
            "result": {
                "ip": "1.2.3.4",
                "services": [{"port": 443, "service_name": "HTTP", "banner": "nginx"}],
            }
        }
    )

    async with httpx.AsyncClient() as client:
        result = await run(CensysHostsInput(ip="1.2.3.4"), client, api_id="id", api_secret="secret")

    assert [a.value for a in result.assets_discovered] == ["1.2.3.4:443"]
    assert result.error is None
