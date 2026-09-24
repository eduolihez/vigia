"""typosquat — registered look-alike domains for a domain, via the `dnstwist` binary.

Only *registered* permutations are reported as informational findings. Per the Scope
Guard rule (brief section 6.2), these new root domains are never investigated further
by the agent — they're recorded and left alone.

`dnstwist` ships in the Docker image (see api/Dockerfile); if it isn't on PATH (e.g.
local dev on a machine without it installed), this returns a graceful error instead of
crashing the pipeline.
"""

from __future__ import annotations

import json
import time

from pydantic import BaseModel

from vigia.tools.base import (
    FindingCandidate,
    ToolMode,
    ToolResult,
    ToolSpec,
    finalize,
    run_subprocess,
)

SPEC = ToolSpec(
    name="typosquat",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="Registered look-alike (typosquat) domains, via dnstwist.",
)


class TyposquatInput(BaseModel):
    domain: str


async def run(input: TyposquatInput, *, timeout_seconds: float = 180.0) -> ToolResult:
    start = time.monotonic()

    try:
        returncode, stdout, stderr = await run_subprocess(
            "dnstwist",
            "--format",
            "json",
            "--registered",
            input.domain,
            timeout_seconds=timeout_seconds,
        )
    except FileNotFoundError:
        return finalize(SPEC.name, start, error="dnstwist binary not found on PATH")
    except TimeoutError:
        return finalize(SPEC.name, start, error="dnstwist timed out")

    if returncode != 0:
        stderr_text = stderr.decode(errors="replace")
        return finalize(SPEC.name, start, error=f"dnstwist exited {returncode}: {stderr_text}")

    try:
        permutations = json.loads(stdout)
    except json.JSONDecodeError:
        return finalize(SPEC.name, start, error="dnstwist returned invalid JSON")

    findings = [
        FindingCandidate(
            type="typosquat",
            title=f"Registered look-alike domain: {perm.get('domain')}",
            detail=(
                f"Fuzzer: {perm.get('fuzzer', 'unknown')}. "
                f"DNS A: {perm.get('dns_a', [])}. Not investigated further (out of scope)."
            ),
            asset_value=input.domain,
        )
        for perm in permutations
        if perm.get("domain") and perm.get("domain") != input.domain
    ]

    return finalize(SPEC.name, start, raw_output=stdout, findings=findings)
