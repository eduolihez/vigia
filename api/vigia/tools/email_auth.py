"""email_auth — SPF, DMARC (via checkdmarc) and DKIM (common selectors) for a domain.

Verified 2026-09-24: `checkdmarc==6.0.3` (the version installed) checks SPF, DMARC, MX,
DNSSEC, MTA-STS, BIMI and SMTP TLS reporting via `checkdmarc.check_domains()` — but it
has **no DKIM support** (confirmed: no `dkim` key in its output, no dkim-related
function in the package). The brief asks for "SPF, DKIM (common selectors) and DMARC
with checkdmarc"; since checkdmarc doesn't cover DKIM, this wrapper checks a short list
of common DKIM selectors directly via DNS TXT lookups instead. See ADR in
docs/decisions.md.

checkdmarc's `check_domains()` is synchronous (uses `requests`), so it runs in a
worker thread via `asyncio.to_thread` to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import checkdmarc
import dns.asyncresolver
import dns.exception
import dns.resolver
from pydantic import BaseModel

from vigia.tools.base import FindingCandidate, ToolMode, ToolResult, ToolSpec, finalize

SPEC = ToolSpec(
    name="email_auth",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="SPF, DKIM (common selectors) and DMARC posture for a domain.",
)

COMMON_DKIM_SELECTORS = [
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "default",
    "dkim",
    "smtp",
    "mandrill",
    "mailgun",
    "sendgrid",
    "amazonses",
]


class EmailAuthInput(BaseModel):
    domain: str


async def _check_dkim_selectors(domain: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    found: list[str] = []
    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        try:
            answer = await resolver.resolve(name, "TXT")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
        txt = " ".join(rdata.to_text() for rdata in answer)
        if "v=dkim1" in txt.lower() or "p=" in txt.lower():
            found.append(selector)
    return found


def _run_checkdmarc(domain: str) -> dict[str, Any]:
    result = checkdmarc.check_domains([domain], parked=False)
    return result if isinstance(result, dict) else result[0]


async def run(input: EmailAuthInput) -> ToolResult:
    start = time.monotonic()

    try:
        dmarc_spf = await asyncio.to_thread(_run_checkdmarc, input.domain)
    except Exception as exc:  # checkdmarc can raise a variety of dns/parsing errors
        return finalize(SPEC.name, start, error=f"checkdmarc failed: {exc}")

    dkim_selectors_found = await _check_dkim_selectors(input.domain)

    findings: list[FindingCandidate] = []

    spf = dmarc_spf.get("spf", {})
    if not spf.get("valid"):
        findings.append(
            FindingCandidate(
                type="spf_missing",
                title=f"No valid SPF record for {input.domain}",
                detail=str(spf.get("error", "No valid SPF record found.")),
                asset_value=input.domain,
            )
        )

    dmarc = dmarc_spf.get("dmarc", {})
    if not dmarc.get("valid"):
        findings.append(
            FindingCandidate(
                type="dmarc_missing",
                title=f"No valid DMARC record for {input.domain}",
                detail=str(dmarc.get("error", "No valid DMARC record found.")),
                asset_value=input.domain,
            )
        )
    else:
        policy = dmarc.get("tags", {}).get("p", {}).get("value")
        if policy == "none":
            findings.append(
                FindingCandidate(
                    type="dmarc_policy_none",
                    title=f"DMARC policy is 'none' for {input.domain}",
                    detail=(
                        "DMARC is published but set to monitor-only (p=none); "
                        "spoofed mail is not rejected or quarantined."
                    ),
                    asset_value=input.domain,
                )
            )

    if not dkim_selectors_found:
        findings.append(
            FindingCandidate(
                type="dkim_not_found",
                title=f"No DKIM record found at common selectors for {input.domain}",
                detail=(
                    f"Checked {len(COMMON_DKIM_SELECTORS)} common selectors "
                    f"({', '.join(COMMON_DKIM_SELECTORS)}); none had a DKIM TXT record. "
                    "This is not conclusive — the domain may use an uncommon selector."
                ),
                asset_value=input.domain,
            )
        )

    raw_output = json.dumps(
        {"checkdmarc": dmarc_spf, "dkim_selectors_found": dkim_selectors_found}, default=str
    ).encode()
    return finalize(SPEC.name, start, raw_output=raw_output, findings=findings)
