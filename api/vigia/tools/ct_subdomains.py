"""ct_subdomains — subdomain discovery via crt.sh Certificate Transparency search.

crt.sh's JSON schema (id, issuer_ca_id, issuer_name, common_name, name_value,
entry_timestamp, not_before, not_after, serial_number) is stable and widely
documented; crt.sh itself is known to be flaky (frequent 502s under load), which is
why requests here retry and a failure is reported as a graceful `ToolResult.error`
rather than raised.
"""

from __future__ import annotations

import json
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
    name="ct_subdomains",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="Subdomain discovery via crt.sh Certificate Transparency logs.",
)

CRTSH_URL = "https://crt.sh/"


class CtSubdomainsInput(BaseModel):
    domain: str


def _extract_names(entries: list[dict[str, object]], domain: str) -> set[str]:
    names: set[str] = set()
    suffix = f".{domain}"
    for entry in entries:
        raw_names = str(entry.get("name_value", ""))
        for name in raw_names.splitlines():
            name = name.strip().lower().removeprefix("*.")
            if name == domain or name.endswith(suffix):
                names.add(name)
    return names


async def run(input: CtSubdomainsInput, client: httpx.AsyncClient) -> ToolResult:
    start = time.monotonic()
    try:
        response = await request_with_retry(
            client,
            "GET",
            CRTSH_URL,
            params={"q": input.domain, "output": "json"},
            headers={"User-Agent": "vigia-osint-agent/0.1"},
        )
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"crt.sh request failed: {exc}")

    if response.status_code != 200:
        return finalize(SPEC.name, start, error=f"crt.sh returned HTTP {response.status_code}")

    try:
        entries = response.json()
    except (json.JSONDecodeError, ValueError):
        return finalize(SPEC.name, start, error="crt.sh returned a non-JSON response")

    names = _extract_names(entries, input.domain.lower())
    assets = [
        DiscoveredAsset(type="subdomain", value=name, parent_value=input.domain)
        for name in sorted(names)
        if name != input.domain.lower()
    ]

    return finalize(SPEC.name, start, raw_output=response.content, assets=assets)
