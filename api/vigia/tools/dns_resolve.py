"""dns_resolve — A/AAAA/CNAME/MX/TXT/NS resolution via dnspython.

The brief allows `dnsx` (Go binary) or `dnspython`; dnspython is used here since it
needs no external binary, keeping local dev and CI simple. `dnsx` in the Docker image
remains available for Phase 3+ if the agent wants faster bulk resolution.
"""

from __future__ import annotations

import json
import time

import dns.asyncresolver
import dns.exception
import dns.resolver
from pydantic import BaseModel

from vigia.tools.base import DiscoveredAsset, ToolMode, ToolResult, ToolSpec, finalize

SPEC = ToolSpec(
    name="dns_resolve",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="Resolves A, AAAA, CNAME, MX, TXT and NS records for a hostname.",
)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]


class DnsResolveInput(BaseModel):
    hostname: str


async def _resolve_one(
    resolver: dns.asyncresolver.Resolver, hostname: str, rtype: str
) -> list[str]:
    try:
        answer = await resolver.resolve(hostname, rtype)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    return [rdata.to_text() for rdata in answer]


async def run(input: DnsResolveInput) -> ToolResult:
    start = time.monotonic()
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        records[rtype] = await _resolve_one(resolver, input.hostname, rtype)

    assets: list[DiscoveredAsset] = []
    for rtype in ("A", "AAAA"):
        for value in records[rtype]:
            assets.append(DiscoveredAsset(type="ip", value=value, parent_value=input.hostname))

    raw_output = json.dumps({"hostname": input.hostname, "records": records}).encode()
    return finalize(SPEC.name, start, raw_output=raw_output, assets=assets)
