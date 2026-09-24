"""Shared contracts and helpers for OSINT tool wrappers.

Every tool in `vigia.tools` returns a `ToolResult`: normalized discovered assets and
finding candidates, plus the raw tool output (hashed, for evidence storage), timing,
and an optional error. Tools never raise on expected failure modes (network error,
missing binary, missing API key, empty result) — they report it via `ToolResult.error`
so the deterministic pipeline (Phase 2) and, later, the agent (Phase 3) can continue.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any

import httpx
from pydantic import BaseModel, Field

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_SECONDS = 0.3


class ToolMode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"


class DiscoveredAsset(BaseModel):
    type: str
    value: str
    parent_value: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingCandidate(BaseModel):
    type: str
    title: str
    detail: str
    asset_value: str | None = None
    cve: str | None = None


class ToolResult(BaseModel):
    tool: str
    assets_discovered: list[DiscoveredAsset] = Field(default_factory=list)
    findings_candidates: list[FindingCandidate] = Field(default_factory=list)
    raw_output: bytes = b""
    sha256: str = ""
    duration_ms: int = 0
    error: str | None = None


class ToolSpec(BaseModel):
    """Static metadata about a tool, independent of any single invocation."""

    name: str
    mode: ToolMode
    requires_api_key: bool = False
    description: str = ""


def finalize(
    tool: str,
    start: float,
    *,
    raw_output: bytes = b"",
    assets: list[DiscoveredAsset] | None = None,
    findings: list[FindingCandidate] | None = None,
    error: str | None = None,
) -> ToolResult:
    """Build a `ToolResult`, computing sha256 and duration from a monotonic `start`."""
    return ToolResult(
        tool=tool,
        assets_discovered=assets or [],
        findings_candidates=findings or [],
        raw_output=raw_output,
        sha256=hashlib.sha256(raw_output).hexdigest(),
        duration_ms=int((time.monotonic() - start) * 1000),
        error=error,
    )


class RateLimiter:
    """A simple per-source minimum-interval limiter, shared across calls to one tool."""

    def __init__(self, min_interval_seconds: float) -> None:
        self._min_interval = min_interval_seconds
        self._lock = asyncio.Lock()
        self._last_call: float = 0.0

    async def wait(self) -> None:
        async with self._lock:
            elapsed = time.monotonic() - self._last_call
            remaining = self._min_interval - elapsed
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_call = time.monotonic()


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    retries: int = DEFAULT_RETRIES,
    backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
    **kwargs: Any,
) -> httpx.Response:
    """GET/POST with a small number of retries on network errors and 5xx responses."""
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            response = await client.request(method, url, **kwargs)
            if response.status_code < 500:
                return response
            last_error = httpx.HTTPStatusError(
                f"{response.status_code} from {url}", request=response.request, response=response
            )
        except httpx.HTTPError as exc:
            last_error = exc
        if attempt < retries:
            await asyncio.sleep(backoff_seconds * (2**attempt))
    assert last_error is not None
    raise last_error


async def run_subprocess(
    *args: str,
    timeout_seconds: float = 60.0,
) -> tuple[int, bytes, bytes]:
    """Run an external binary, returning (returncode, stdout, stderr).

    Raises `FileNotFoundError` if the binary isn't on PATH — callers turn that into a
    graceful `ToolResult.error` rather than crashing the pipeline.
    """
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, stdout, stderr


ToolRunner = Callable[..., Awaitable[ToolResult]]
