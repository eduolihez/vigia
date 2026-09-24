"""kev_epss_enrich — CISA KEV membership + FIRST EPSS score for a list of CVEs.

Verified live 2026-09-24:
  - CISA KEV feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - FIRST EPSS API: https://api.first.org/data/v1/epss?cve=CVE-2021-44228
    (returns `{"data": [{"cve": ..., "epss": "0.999990000", "percentile": "1.0...", ...}]}`)

The KEV feed is cached on disk for 24h (per brief section 4) since it's a few MB and
changes infrequently; EPSS is queried fresh per call (small, per-CVE JSON).

This tool doesn't discover assets/findings on its own — it enriches CVEs surfaced by
other tools (e.g. `shodan_internetdb`). The risk multiplier itself (kev_mult, EPSS
weighting) is computed by the Risk Engine in Phase 4; this tool only returns the raw
KEV/EPSS facts.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, TypedDict

import httpx
from pydantic import BaseModel, Field

from vigia.tools.base import ToolMode, ToolResult, ToolSpec, finalize, request_with_retry

SPEC = ToolSpec(
    name="kev_epss_enrich",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="CISA KEV membership and FIRST EPSS score for a list of CVEs.",
)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_CACHE_MAX_AGE_SECONDS = 24 * 60 * 60
DEFAULT_KEV_CACHE_PATH = Path.home() / ".cache" / "vigia" / "kev.json"


class CveEnrichment(TypedDict):
    cve: str
    in_kev: bool
    known_ransomware: bool
    epss: float | None
    epss_percentile: float | None


class KevEpssEnrichInput(BaseModel):
    cves: list[str] = Field(default_factory=list)


def _read_fresh_cache(cache_path: Path) -> dict[str, Any] | None:
    if not cache_path.exists():
        return None
    age = time.time() - cache_path.stat().st_mtime
    if age >= KEV_CACHE_MAX_AGE_SECONDS:
        return None
    payload: dict[str, Any] = json.loads(cache_path.read_text(encoding="utf-8"))
    return payload


def _write_cache(cache_path: Path, text: str) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(text, encoding="utf-8")


async def _load_kev_catalog(
    client: httpx.AsyncClient, cache_path: Path
) -> dict[str, dict[str, object]]:
    cached = await asyncio.to_thread(_read_fresh_cache, cache_path)
    if cached is not None:
        return {v["cveID"]: v for v in cached.get("vulnerabilities", [])}

    response = await request_with_retry(client, "GET", KEV_FEED_URL)
    response.raise_for_status()
    await asyncio.to_thread(_write_cache, cache_path, response.text)
    payload = response.json()
    return {v["cveID"]: v for v in payload.get("vulnerabilities", [])}


async def _fetch_epss(client: httpx.AsyncClient, cves: list[str]) -> dict[str, dict[str, str]]:
    if not cves:
        return {}
    response = await request_with_retry(client, "GET", EPSS_API_URL, params={"cve": ",".join(cves)})
    response.raise_for_status()
    return {row["cve"]: row for row in response.json().get("data", [])}


async def run(
    input: KevEpssEnrichInput,
    client: httpx.AsyncClient,
    *,
    kev_cache_path: Path = DEFAULT_KEV_CACHE_PATH,
) -> ToolResult:
    start = time.monotonic()
    if not input.cves:
        return finalize(SPEC.name, start, raw_output=b"{}")

    try:
        kev_catalog = await _load_kev_catalog(client, kev_cache_path)
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"Failed to fetch CISA KEV feed: {exc}")

    try:
        epss_data = await _fetch_epss(client, input.cves)
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"Failed to fetch FIRST EPSS data: {exc}")

    enrichment: list[CveEnrichment] = []
    for cve in input.cves:
        kev_entry = kev_catalog.get(cve)
        epss_entry = epss_data.get(cve)
        enrichment.append(
            {
                "cve": cve,
                "in_kev": kev_entry is not None,
                "known_ransomware": bool(
                    kev_entry and kev_entry.get("knownRansomwareCampaignUse") == "Known"
                ),
                "epss": float(epss_entry["epss"]) if epss_entry else None,
                "epss_percentile": float(epss_entry["percentile"]) if epss_entry else None,
            }
        )

    raw_output = json.dumps({"enrichment": enrichment}).encode()
    return finalize(SPEC.name, start, raw_output=raw_output)
