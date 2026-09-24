"""whois_asn — WHOIS + ASN/network info via the RIPEstat Data API.

Verified 2026-09-24 against https://stat.ripe.net/docs/02_data_api/ and by a live
passive call against `93.184.216.34` (example.com's IP): `/data/whois/data.json` and
`/data/network-info/data.json` both work unauthenticated, no API key required.
"""

from __future__ import annotations

import json
import time
from ipaddress import ip_address

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
    name="whois_asn",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="WHOIS and ASN/network info for an IP or domain, via RIPEstat.",
)

RIPESTAT_BASE = "https://stat.ripe.net/data"


class WhoisAsnInput(BaseModel):
    resource: str  # an IP address or a domain


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


async def run(input: WhoisAsnInput, client: httpx.AsyncClient) -> ToolResult:
    start = time.monotonic()
    raw: dict[str, object] = {}
    findings: list[FindingCandidate] = []

    try:
        whois_resp = await request_with_retry(
            client, "GET", f"{RIPESTAT_BASE}/whois/data.json", params={"resource": input.resource}
        )
        raw["whois"] = whois_resp.json()
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"RIPEstat whois request failed: {exc}")

    asns: list[str] = []
    if _is_ip(input.resource):
        try:
            net_resp = await request_with_retry(
                client,
                "GET",
                f"{RIPESTAT_BASE}/network-info/data.json",
                params={"resource": input.resource},
            )
            net_data = net_resp.json()
            raw["network_info"] = net_data
            asns = [str(a) for a in net_data.get("data", {}).get("asns", [])]
        except httpx.HTTPError as exc:
            raw["network_info_error"] = str(exc)

    for asn in asns:
        try:
            as_resp = await request_with_retry(
                client, "GET", f"{RIPESTAT_BASE}/as-overview/data.json", params={"resource": asn}
            )
            as_data = as_resp.json().get("data", {})
        except httpx.HTTPError:
            continue
        holder = as_data.get("holder", "unknown")
        findings.append(
            FindingCandidate(
                type="network_info",
                title=f"AS{asn} — {holder}",
                detail=f"{input.resource} is announced by AS{asn} ({holder}).",
                asset_value=input.resource,
            )
        )

    return finalize(
        SPEC.name, start, raw_output=json.dumps(raw).encode(), assets=[], findings=findings
    )
