"""Tool router: turns (tool_name, args dict) into a `ToolResult`.

Centralizes the per-tool wiring (which ones need the shared httpx client, which need
an API key, which shell out to a binary) so both the Phase 2 deterministic pipeline
and the Phase 3 agent orchestrator invoke tools the same way. Also enforces the
phase/tool allowlist and delegates to the Scope Guard before anything runs.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from vigia.agent.phases import AgentPhase
from vigia.agent.phases import tools_for_phase as _tools_for_phase
from vigia.agent.scope_guard import ScopeGuard
from vigia.config import Settings
from vigia.tools import base as tools_base
from vigia.tools import (
    censys_hosts,
    ct_subdomains,
    dangling_dns,
    dns_resolve,
    email_auth,
    github_leaks,
    hibp_domain,
    http_probe,
    kev_epss_enrich,
    screenshot,
    shodan_internetdb,
    subfinder_enum,
    tls_check,
    typosquat,
    wayback_urls,
    whois_asn,
)


class ToolNotAllowedError(Exception):
    """Raised when a tool isn't permitted in the current phase."""


@dataclass
class ToolContext:
    client: httpx.AsyncClient
    settings: Settings


Invoker = Callable[[dict[str, Any], ToolContext], Awaitable[tools_base.ToolResult]]


async def _whois_asn(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await whois_asn.run(whois_asn.WhoisAsnInput(**args), ctx.client)


async def _ct_subdomains(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await ct_subdomains.run(ct_subdomains.CtSubdomainsInput(**args), ctx.client)


async def _subfinder_enum(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await subfinder_enum.run(subfinder_enum.SubfinderEnumInput(**args))


async def _wayback_urls(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await wayback_urls.run(wayback_urls.WaybackUrlsInput(**args), ctx.client)


async def _dns_resolve(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await dns_resolve.run(dns_resolve.DnsResolveInput(**args))


async def _dangling_dns(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await dangling_dns.run(dangling_dns.DanglingDnsInput(**args))


async def _shodan_internetdb(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await shodan_internetdb.run(shodan_internetdb.ShodanInternetDbInput(**args), ctx.client)


async def _censys_hosts(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await censys_hosts.run(
        censys_hosts.CensysHostsInput(**args),
        ctx.client,
        api_id=ctx.settings.censys_api_id,
        api_secret=ctx.settings.censys_api_secret,
    )


async def _email_auth(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await email_auth.run(email_auth.EmailAuthInput(**args))


async def _typosquat(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await typosquat.run(typosquat.TyposquatInput(**args))


async def _github_leaks(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await github_leaks.run(
        github_leaks.GithubLeaksInput(**args), ctx.client, token=ctx.settings.github_token
    )


async def _hibp_domain(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await hibp_domain.run(
        hibp_domain.HibpDomainInput(**args), ctx.client, api_key=ctx.settings.hibp_api_key
    )


async def _kev_epss_enrich(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await kev_epss_enrich.run(kev_epss_enrich.KevEpssEnrichInput(**args), ctx.client)


async def _http_probe(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await http_probe.run(http_probe.HttpProbeInput(**args), ctx.client)


async def _tls_check(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await tls_check.run(tls_check.TlsCheckInput(**args))


async def _screenshot(args: dict[str, Any], ctx: ToolContext) -> tools_base.ToolResult:
    return await screenshot.run(screenshot.ScreenshotInput(**args))


INVOKERS: dict[str, Invoker] = {
    "whois_asn": _whois_asn,
    "ct_subdomains": _ct_subdomains,
    "subfinder_enum": _subfinder_enum,
    "wayback_urls": _wayback_urls,
    "dns_resolve": _dns_resolve,
    "dangling_dns": _dangling_dns,
    "shodan_internetdb": _shodan_internetdb,
    "censys_hosts": _censys_hosts,
    "email_auth": _email_auth,
    "typosquat": _typosquat,
    "github_leaks": _github_leaks,
    "hibp_domain": _hibp_domain,
    "kev_epss_enrich": _kev_epss_enrich,
    "http_probe": _http_probe,
    "tls_check": _tls_check,
    "screenshot": _screenshot,
}


def tools_for_phase(phase: AgentPhase, *, active_enabled: bool = False) -> list[str]:
    return _tools_for_phase(phase, active_enabled=active_enabled)


async def invoke(
    tool_name: str,
    args: dict[str, Any],
    *,
    phase: AgentPhase,
    scope_guard: ScopeGuard,
    ctx: ToolContext,
    active_enabled: bool = False,
) -> tools_base.ToolResult:
    """Validate (phase/mode allowlist, then Scope Guard) and run one tool call.

    Raises `ToolNotAllowedError` / `ScopeViolation` before any tool code runs — an
    invalid call never reaches the network or a subprocess. `active_enabled` must be
    explicitly True (an active-mode scan that's passed ownership verification —
    `AgentOrchestrator` is the only caller that ever sets it) for http_probe/
    tls_check/screenshot to be reachable at all.
    """
    if tool_name not in _tools_for_phase(phase, active_enabled=active_enabled):
        raise ToolNotAllowedError(f"{tool_name!r} is not allowed in phase {phase.value!r}")
    scope_guard.validate(tool_name, args)
    return await INVOKERS[tool_name](args, ctx)
