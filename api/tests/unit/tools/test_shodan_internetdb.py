import httpx
import respx

from vigia.tools.shodan_internetdb import ShodanInternetDbInput, run


@respx.mock
async def test_shodan_internetdb_parses_ports_and_vulns() -> None:
    respx.get("https://internetdb.shodan.io/1.2.3.4").respond(
        json={
            "ip": "1.2.3.4",
            "ports": [22, 443],
            "cpes": ["cpe:/a:openbsd:openssh"],
            "hostnames": [],
            "tags": [],
            "vulns": ["CVE-2023-38408"],
        }
    )

    async with httpx.AsyncClient() as client:
        result = await run(ShodanInternetDbInput(ip="1.2.3.4"), client)

    service_values = {a.value for a in result.assets_discovered}
    assert service_values == {"1.2.3.4:22", "1.2.3.4:443"}
    assert result.findings_candidates[0].cve == "CVE-2023-38408"


@respx.mock
async def test_shodan_internetdb_handles_404_as_empty() -> None:
    respx.get("https://internetdb.shodan.io/1.2.3.4").respond(status_code=404)

    async with httpx.AsyncClient() as client:
        result = await run(ShodanInternetDbInput(ip="1.2.3.4"), client)

    assert result.error is None
    assert result.assets_discovered == []
