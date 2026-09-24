"""shodan_internetdb — open ports, CPEs and known CVEs for an IP, via Shodan InternetDB.

Verified live 2026-09-24 against `https://internetdb.shodan.io/1.1.1.1`: no API key
required; fields are `ip`, `ports`, `cpes`, `hostnames`, `tags`, `vulns`. A 404 means
Shodan has no data for that IP — not an error, just an empty result.
"""

from __future__ import annotations

import time

import httpx
from pydantic import BaseModel

from vigia.tools.base import (
    DiscoveredAsset,
    FindingCandidate,
    ToolMode,
    ToolResult,
    ToolSpec,
    finalize,
    request_with_retry,
)

SPEC = ToolSpec(
    name="shodan_internetdb",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="Open ports, CPEs and known CVEs for an IP, via Shodan InternetDB.",
)

INTERNETDB_URL = "https://internetdb.shodan.io"


class ShodanInternetDbInput(BaseModel):
    ip: str


async def run(input: ShodanInternetDbInput, client: httpx.AsyncClient) -> ToolResult:
    start = time.monotonic()
    try:
        response = await request_with_retry(client, "GET", f"{INTERNETDB_URL}/{input.ip}")
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"Shodan InternetDB request failed: {exc}")

    if response.status_code == 404:
        return finalize(SPEC.name, start, raw_output=response.content)
    if response.status_code != 200:
        return finalize(
            SPEC.name, start, error=f"Shodan InternetDB returned HTTP {response.status_code}"
        )

    try:
        data = response.json()
    except ValueError:
        return finalize(SPEC.name, start, error="Shodan InternetDB returned a non-JSON response")

    assets = [
        DiscoveredAsset(
            type="service",
            value=f"{input.ip}:{port}",
            parent_value=input.ip,
            metadata={"cpes": data.get("cpes", [])},
        )
        for port in data.get("ports", [])
    ]
    findings = [
        FindingCandidate(
            type="known_vulnerability",
            title=f"{cve} reported open on {input.ip} (Shodan InternetDB)",
            detail=f"Shodan InternetDB lists {cve} as a known vulnerability for {input.ip}.",
            asset_value=input.ip,
            cve=cve,
        )
        for cve in data.get("vulns", [])
    ]

    return finalize(SPEC.name, start, raw_output=response.content, assets=assets, findings=findings)
