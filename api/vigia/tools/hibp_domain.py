"""hibp_domain — breached-account counts for a verified domain, via HIBP's domain search.

Verified 2026-09-24 against HIBP's own API docs: `GET
https://haveibeenpwned.com/api/v3/breacheddomain/{domain}`, requires a `hibp-api-key`
header and a `User-Agent`, and only works for a domain the API-key owner has verified
control of in their HIBP dashboard — hence `requires_api_key=True` and why a 403 here
is reported as a graceful error, not a crash.

Per the brief's privacy rule (section 6.6), results are aggregated to a per-breach
account *count* — the raw response's per-alias breach list is never surfaced as-is.
"""

from __future__ import annotations

import time
from collections import Counter

import httpx
from pydantic import BaseModel

from vigia.tools.base import (
    FindingCandidate,
    ToolMode,
    ToolResult,
    ToolSpec,
    finalize,
    request_with_retry,
)

SPEC = ToolSpec(
    name="hibp_domain",
    mode=ToolMode.PASSIVE,
    requires_api_key=True,
    description="Aggregated breach-account counts for a domain verified in HIBP.",
)

HIBP_BASE = "https://haveibeenpwned.com/api/v3/breacheddomain"


class HibpDomainInput(BaseModel):
    domain: str


async def run(
    input: HibpDomainInput, client: httpx.AsyncClient, *, api_key: str | None
) -> ToolResult:
    start = time.monotonic()
    if not api_key:
        return finalize(SPEC.name, start, error="HIBP API key not configured")

    headers = {"hibp-api-key": api_key, "User-Agent": "vigia-osint-agent/0.1"}
    try:
        response = await request_with_retry(
            client, "GET", f"{HIBP_BASE}/{input.domain}", headers=headers
        )
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"HIBP domain search failed: {exc}")

    if response.status_code == 404:
        return finalize(SPEC.name, start, raw_output=response.content)
    if response.status_code == 403:
        return finalize(
            SPEC.name, start, error="HIBP: domain not verified for this API key"
        )
    if response.status_code != 200:
        return finalize(SPEC.name, start, error=f"HIBP returned HTTP {response.status_code}")

    try:
        alias_breaches: dict[str, list[str]] = response.json()
    except ValueError:
        return finalize(SPEC.name, start, error="HIBP returned a non-JSON response")

    breach_counts: Counter[str] = Counter()
    for breaches in alias_breaches.values():
        breach_counts.update(breaches)

    findings = [
        FindingCandidate(
            type="breach_exposure",
            title=f"{count} account(s) on {input.domain} appear in breach '{breach}'",
            detail="Aggregated from HIBP domain search; individual accounts are not enumerated.",
            asset_value=input.domain,
        )
        for breach, count in sorted(breach_counts.items())
    ]

    raw_output = str({"breach_counts": dict(breach_counts)}).encode()
    return finalize(SPEC.name, start, raw_output=raw_output, findings=findings)
