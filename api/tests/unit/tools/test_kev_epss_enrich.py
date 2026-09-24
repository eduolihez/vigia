from pathlib import Path

import httpx
import respx

from vigia.tools.kev_epss_enrich import KevEpssEnrichInput, run

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@respx.mock
async def test_kev_epss_enrich_marks_kev_and_epss(tmp_path: Path) -> None:
    respx.get(KEV_URL).respond(
        json={
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }
    )
    respx.get("https://api.first.org/data/v1/epss").respond(
        json={"data": [{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"}]}
    )

    async with httpx.AsyncClient() as client:
        result = await run(
            KevEpssEnrichInput(cves=["CVE-2021-44228"]),
            client,
            kev_cache_path=tmp_path / "kev.json",
        )

    import json

    enrichment = json.loads(result.raw_output)["enrichment"][0]
    assert enrichment["in_kev"] is True
    assert enrichment["known_ransomware"] is True
    assert enrichment["epss"] == 0.97


@respx.mock
async def test_kev_epss_enrich_uses_cache_on_second_call(tmp_path: Path) -> None:
    kev_route = respx.get(KEV_URL).respond(json={"vulnerabilities": []})
    respx.get("https://api.first.org/data/v1/epss").respond(json={"data": []})
    cache_path = tmp_path / "kev.json"

    async with httpx.AsyncClient() as client:
        await run(KevEpssEnrichInput(cves=["CVE-2020-0001"]), client, kev_cache_path=cache_path)
        await run(KevEpssEnrichInput(cves=["CVE-2020-0001"]), client, kev_cache_path=cache_path)

    assert kev_route.call_count == 1


async def test_kev_epss_enrich_empty_input_short_circuits() -> None:
    async with httpx.AsyncClient() as client:
        result = await run(KevEpssEnrichInput(cves=[]), client)

    assert result.raw_output == b"{}"
    assert result.error is None
