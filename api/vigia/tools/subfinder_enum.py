"""subfinder_enum — subdomain enumeration via ProjectDiscovery's `subfinder` binary.

subfinder only queries passive third-party sources (it has no active-probing mode of
its own), so it's passive by construction. If the binary isn't on PATH (e.g. local dev
without it installed), this returns a graceful error rather than crashing the pipeline
— it ships in the Docker image (see api/Dockerfile).
"""

from __future__ import annotations

import json
import time

from pydantic import BaseModel

from vigia.tools.base import (
    DiscoveredAsset,
    ToolMode,
    ToolResult,
    ToolSpec,
    finalize,
    run_subprocess,
)

SPEC = ToolSpec(
    name="subfinder_enum",
    mode=ToolMode.PASSIVE,
    requires_api_key=False,
    description="Subdomain enumeration via ProjectDiscovery subfinder (passive sources only).",
)


class SubfinderEnumInput(BaseModel):
    domain: str


async def run(input: SubfinderEnumInput, *, timeout_seconds: float = 90.0) -> ToolResult:
    start = time.monotonic()

    try:
        returncode, stdout, stderr = await run_subprocess(
            "subfinder",
            "-d",
            input.domain,
            "-silent",
            "-json",
            timeout_seconds=timeout_seconds,
        )
    except FileNotFoundError:
        return finalize(SPEC.name, start, error="subfinder binary not found on PATH")
    except TimeoutError:
        return finalize(SPEC.name, start, error="subfinder timed out")

    if returncode != 0 and not stdout:
        stderr_text = stderr.decode(errors="replace")
        return finalize(SPEC.name, start, error=f"subfinder exited {returncode}: {stderr_text}")

    hosts: set[str] = set()
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = record.get("host")
        if host:
            hosts.add(host.lower())

    assets = [
        DiscoveredAsset(type="subdomain", value=host, parent_value=input.domain)
        for host in sorted(hosts)
        if host != input.domain.lower()
    ]

    return finalize(SPEC.name, start, raw_output=stdout, assets=assets)
