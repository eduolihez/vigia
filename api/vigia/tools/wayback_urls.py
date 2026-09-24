"""wayback_urls — historical URLs for a domain via the Wayback Machine CDX API.

Verified live 2026-09-24: `http://web.archive.org/cdx/search/cdx?url=example.com&
output=json&fl=original&collapse=urlkey` returns a JSON array of arrays; the first
row is the header (`["original"]`), the rest are one-element rows with the URL.
"""

from __future__ import annotations

import time

import httpx
from pydantic import BaseModel, Field

from vigia.tools.base import (
    DiscoveredAsset,
    ToolMode,
    ToolResult,
    ToolSpec,
    finalize,
    request_with_retry,
)

SPEC = ToolSpec(
    name="wayback_urls",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="Historical URLs for a domain and its subdomains, via the Wayback Machine CDX API.",
)

CDX_URL = "http://web.archive.org/cdx/search/cdx"
MAX_URLS = 500


class WaybackUrlsInput(BaseModel):
    domain: str
    limit: int = Field(default=MAX_URLS, le=5000)


async def run(input: WaybackUrlsInput, client: httpx.AsyncClient) -> ToolResult:
    start = time.monotonic()
    try:
        response = await request_with_retry(
            client,
            "GET",
            CDX_URL,
            params={
                "url": f"*.{input.domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": str(input.limit),
            },
        )
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"Wayback CDX request failed: {exc}")

    if response.status_code != 200:
        return finalize(SPEC.name, start, error=f"Wayback CDX returned HTTP {response.status_code}")

    try:
        rows = response.json()
    except ValueError:
        return finalize(SPEC.name, start, error="Wayback CDX returned a non-JSON response")

    urls = {row[0] for row in rows[1:] if row}
    assets = [
        DiscoveredAsset(type="url", value=url, parent_value=input.domain) for url in sorted(urls)
    ]

    return finalize(SPEC.name, start, raw_output=response.content, assets=assets)
