"""http_probe — active HTTP(S) reconnaissance for one hostname (Phase 7).

Fetches `https://{hostname}{path}` (falling back to plain `http://` if the TLS
connection itself fails), then reports missing security headers, a verbose
`Server`/`X-Powered-By` banner, and — the main reason this exists — checks the
response body against `fingerprints/takeover_signatures.yaml` to confirm a
`dangling_dns` (Phase 2, passive) *candidate* finding is actually exploitable.

Active mode only: this makes a real network request to the target host, unlike every
Phase 2 tool. Only runs once `agent/ownership.py` has verified control of the domain
(brief section 6.1) and only within the scan's own scope (Scope Guard).
"""

from __future__ import annotations

import json
import time
from functools import lru_cache
from pathlib import Path

import httpx
import yaml
from pydantic import BaseModel

from vigia.tools.base import FindingCandidate, ToolMode, ToolResult, ToolSpec, finalize

SPEC = ToolSpec(
    name="http_probe",
    mode=ToolMode.ACTIVE,
    requires_api_key=False,
    description=(
        "Sends a real HTTP(S) request to a hostname: checks security headers, server "
        "banner verbosity, and whether an unclaimed dangling-DNS target is actually "
        "takeover-confirmed."
    ),
)

SIGNATURES_PATH = Path(__file__).parent / "fingerprints" / "takeover_signatures.yaml"
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
)
REQUEST_TIMEOUT_SECONDS = 10.0


class HttpProbeInput(BaseModel):
    hostname: str
    path: str = "/"


@lru_cache(maxsize=1)
def _load_signatures() -> list[dict[str, str]]:
    data = yaml.safe_load(SIGNATURES_PATH.read_text(encoding="utf-8"))
    return list(data["signatures"])


async def _fetch(client: httpx.AsyncClient, url: str) -> httpx.Response:
    return await client.get(
        url,
        timeout=REQUEST_TIMEOUT_SECONDS,
        follow_redirects=True,
        headers={"User-Agent": "Vigia/1"},
    )


async def run(input: HttpProbeInput, client: httpx.AsyncClient) -> ToolResult:
    start = time.monotonic()
    url = f"https://{input.hostname}{input.path}"
    scheme_used = "https"
    try:
        response = await _fetch(client, url)
    except httpx.HTTPError:
        url = f"http://{input.hostname}{input.path}"
        scheme_used = "http"
        try:
            response = await _fetch(client, url)
        except httpx.HTTPError as exc:
            return finalize(
                SPEC.name, start, error=f"http_probe: could not reach {input.hostname}: {exc}"
            )

    findings: list[FindingCandidate] = []

    if scheme_used == "https":
        missing = [h for h in SECURITY_HEADERS if h not in {k.lower() for k in response.headers}]
        if missing:
            findings.append(
                FindingCandidate(
                    type="missing_security_headers",
                    title=f"{input.hostname} is missing security headers",
                    detail=f"Response from {response.url} does not set: {', '.join(missing)}.",
                    asset_value=input.hostname,
                )
            )

    server_banner = response.headers.get("server", "")
    powered_by = response.headers.get("x-powered-by", "")
    if any(char.isdigit() for char in server_banner) or powered_by:
        banner = ", ".join(v for v in (server_banner, powered_by) if v)
        findings.append(
            FindingCandidate(
                type="verbose_server_banner",
                title=f"{input.hostname} exposes a verbose server banner",
                detail=f"Server/X-Powered-By header(s): {banner}.",
                asset_value=input.hostname,
            )
        )

    body_text = response.text[:20000]  # bound how much we scan/store as evidence
    for sig in _load_signatures():
        if sig["body_contains"] in body_text:
            findings.append(
                FindingCandidate(
                    type="dangling_dns_confirmed",
                    title=f"Confirmed subdomain takeover: {input.hostname} ({sig['service']})",
                    detail=(
                        f"HTTP response from {response.url} matches the {sig['service']} "
                        f"'unclaimed' signature ({sig['body_contains']!r}) — this host is "
                        "actively takeoverable, not just a CNAME candidate."
                    ),
                    asset_value=input.hostname,
                )
            )
            break

    raw_output = json.dumps(
        {
            "url": str(response.url),
            "scheme_used": scheme_used,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body_prefix": body_text[:2000],
        }
    ).encode()
    return finalize(SPEC.name, start, raw_output=raw_output, findings=findings)
