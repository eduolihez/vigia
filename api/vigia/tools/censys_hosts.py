"""censys_hosts — host details (services, banners, certs) via the Censys Search v2 API.

Verified 2026-09-24 against Censys's own docs: `GET
https://search.censys.io/api/v2/hosts/{ip}`, Basic Auth with `apiId:apiSecret`.
Requires an API key; `run()` returns a graceful error if none is configured rather
than raising, so the pipeline can continue without Censys data.
"""

from __future__ import annotations

import time

import httpx
from pydantic import BaseModel

from vigia.tools.base import (
    DiscoveredAsset,
    ToolMode,
    ToolResult,
    ToolSpec,
    finalize,
    request_with_retry,
)

SPEC = ToolSpec(
    name="censys_hosts",
    mode=ToolMode.PASSIVE,
    requires_api_key=True,
    description="Host details (open services, banners, certificates) via Censys Search v2.",
)

CENSYS_HOSTS_URL = "https://search.censys.io/api/v2/hosts"


class CensysHostsInput(BaseModel):
    ip: str


async def run(
    input: CensysHostsInput,
    client: httpx.AsyncClient,
    *,
    api_id: str | None,
    api_secret: str | None,
) -> ToolResult:
    start = time.monotonic()
    if not api_id or not api_secret:
        return finalize(SPEC.name, start, error="Censys API credentials not configured")

    try:
        response = await request_with_retry(
            client, "GET", f"{CENSYS_HOSTS_URL}/{input.ip}", auth=(api_id, api_secret)
        )
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"Censys request failed: {exc}")

    if response.status_code == 404:
        return finalize(SPEC.name, start, raw_output=response.content)
    if response.status_code != 200:
        return finalize(SPEC.name, start, error=f"Censys returned HTTP {response.status_code}")

    try:
        result = response.json().get("result", {})
    except ValueError:
        return finalize(SPEC.name, start, error="Censys returned a non-JSON response")

    services = result.get("services", [])
    assets = [
        DiscoveredAsset(
            type="service",
            value=f"{input.ip}:{svc.get('port')}",
            parent_value=input.ip,
            metadata={"service_name": svc.get("service_name"), "banner": svc.get("banner")},
        )
        for svc in services
        if svc.get("port") is not None
    ]

    return finalize(SPEC.name, start, raw_output=response.content, assets=assets)
