"""github_leaks — code search for a domain / internal hostnames on GitHub.

Verified 2026-09-24: `GET https://api.github.com/search/code?q=...` returns HTTP 401
"Requires authentication" without a token — confirms `requires_api_key=True`. Uses a
GitHub personal access token (or fine-grained token) with the `public_repo` scope.

Only records *where* a match was found (repo, path, URL) — not extracted secret
values — keeping this conservative until Phase 4/6 report masking exists.
"""

from __future__ import annotations

import time

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
    name="github_leaks",
    mode=ToolMode.PASSIVE,
    requires_api_key=True,
    description="Searches GitHub code for a domain or internal hostname patterns.",
)

GITHUB_SEARCH_URL = "https://api.github.com/search/code"
MAX_RESULTS = 20


class GithubLeaksInput(BaseModel):
    domain: str


async def run(
    input: GithubLeaksInput, client: httpx.AsyncClient, *, token: str | None
) -> ToolResult:
    start = time.monotonic()
    if not token:
        return finalize(SPEC.name, start, error="GitHub token not configured")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    try:
        response = await request_with_retry(
            client,
            "GET",
            GITHUB_SEARCH_URL,
            params={"q": f'"{input.domain}"', "per_page": str(MAX_RESULTS)},
            headers=headers,
        )
    except httpx.HTTPError as exc:
        return finalize(SPEC.name, start, error=f"GitHub code search failed: {exc}")

    if response.status_code != 200:
        status = response.status_code
        return finalize(SPEC.name, start, error=f"GitHub code search returned HTTP {status}")

    try:
        items = response.json().get("items", [])
    except ValueError:
        return finalize(SPEC.name, start, error="GitHub code search returned a non-JSON response")

    findings = [
        FindingCandidate(
            type="github_leak_candidate",
            title=f"{input.domain} referenced in {item['repository']['full_name']}:{item['path']}",
            detail=f"GitHub code search match. See {item.get('html_url')} for the exact match.",
            asset_value=input.domain,
        )
        for item in items
    ]

    return finalize(SPEC.name, start, raw_output=response.content, findings=findings)
