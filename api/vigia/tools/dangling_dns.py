"""dangling_dns — flags CNAMEs pointing at services known for subdomain takeover.

Passive only: matches the CNAME target against `fingerprints/dangling_dns.yaml` and
reports a *candidate* finding. It does not attempt to confirm the target is actually
unclaimed (that needs an active HTTP probe / registering-service check — Phase 7).
"""

from __future__ import annotations

import json
import time
from functools import lru_cache
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver
import yaml
from pydantic import BaseModel

from vigia.tools.base import FindingCandidate, ToolMode, ToolResult, ToolSpec, finalize

SPEC = ToolSpec(
    name="dangling_dns",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="Flags CNAMEs pointing at services known for subdomain takeover.",
)

FINGERPRINTS_PATH = Path(__file__).parent / "fingerprints" / "dangling_dns.yaml"


class DanglingDnsInput(BaseModel):
    hostname: str


@lru_cache(maxsize=1)
def _load_fingerprints() -> list[dict[str, str]]:
    data = yaml.safe_load(FINGERPRINTS_PATH.read_text(encoding="utf-8"))
    return list(data["fingerprints"])


async def _resolve_cname_chain(hostname: str) -> tuple[list[str], bool]:
    """Return (cname chain, final_name_resolves). Follows CNAMEs up to 10 hops."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    chain: list[str] = []
    seen = {hostname.lower()}
    current = hostname
    for _ in range(10):
        try:
            answer = await resolver.resolve(current, "CNAME")
        except (dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
            return chain, True
        except dns.resolver.NXDOMAIN:
            return chain, False
        target = str(answer[0].target).rstrip(".")
        if target.lower() in seen:
            break  # CNAME loop
        seen.add(target.lower())
        chain.append(target)
        current = target
    return chain, True


async def run(input: DanglingDnsInput) -> ToolResult:
    start = time.monotonic()
    fingerprints = _load_fingerprints()

    chain, resolves = await _resolve_cname_chain(input.hostname)
    findings: list[FindingCandidate] = []

    resolve_note = "resolves" if resolves else "does NOT resolve (NXDOMAIN) — higher confidence"
    for cname in chain:
        for fp in fingerprints:
            if cname.lower().endswith(fp["cname_suffix"]):
                findings.append(
                    FindingCandidate(
                        type="dangling_dns_candidate",
                        title=f"Possible dangling DNS: {input.hostname} → {fp['service']}",
                        detail=(
                            f"{input.hostname} has a CNAME chain ending in {cname}, matching "
                            f"the {fp['service']} takeover fingerprint ({fp['cname_suffix']}). "
                            f"Final name currently {resolve_note}. "
                            "Not confirmed exploitable; requires an active check."
                        ),
                        asset_value=input.hostname,
                    )
                )
                break
        if findings:
            break

    raw_output = json.dumps(
        {"hostname": input.hostname, "cname_chain": chain, "resolves": resolves}
    ).encode()
    return finalize(SPEC.name, start, raw_output=raw_output, findings=findings)
