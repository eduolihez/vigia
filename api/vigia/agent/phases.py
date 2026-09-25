"""Agent state machine phases and the tools available in each.

Per the brief's state machine: VERIFY -> SEED -> ENUMERATE -> RESOLVE -> EXPOSURE ->
EMAIL_AND_SPOOFING -> LEAKS -> RISK -> REPORT -> DONE. The exact phase-to-tool mapping
isn't specified verbatim in the brief, so this is a reasonable, documented split
(ADR-009 in docs/decisions.md) that mirrors the `phase` values already used by the
Phase 2 deterministic pipeline (`vigia/pipeline.py`) for consistency in the audit log.
"""

from __future__ import annotations

from enum import StrEnum


class AgentPhase(StrEnum):
    VERIFY = "verify"
    SEED = "seed"
    ENUMERATE = "enumerate"
    RESOLVE = "resolve"
    EXPOSURE = "exposure"
    EMAIL_AND_SPOOFING = "email_and_spoofing"
    LEAKS = "leaks"
    RISK = "risk"
    REPORT = "report"
    DONE = "done"


PHASE_ORDER: list[AgentPhase] = [
    AgentPhase.VERIFY,
    AgentPhase.SEED,
    AgentPhase.ENUMERATE,
    AgentPhase.RESOLVE,
    AgentPhase.EXPOSURE,
    AgentPhase.EMAIL_AND_SPOOFING,
    AgentPhase.LEAKS,
    AgentPhase.RISK,
    AgentPhase.REPORT,
    AgentPhase.DONE,
]

# Passive-mode tool names allowed per phase (Phase 2 tool registry) — always
# available, regardless of scan mode.
PHASE_TOOLS: dict[AgentPhase, list[str]] = {
    AgentPhase.VERIFY: [],
    AgentPhase.SEED: ["whois_asn"],
    AgentPhase.ENUMERATE: ["ct_subdomains", "subfinder_enum", "wayback_urls", "typosquat"],
    AgentPhase.RESOLVE: ["dns_resolve"],
    AgentPhase.EXPOSURE: ["dangling_dns", "shodan_internetdb", "censys_hosts"],
    AgentPhase.EMAIL_AND_SPOOFING: ["email_auth"],
    AgentPhase.LEAKS: ["github_leaks", "hibp_domain"],
    AgentPhase.RISK: ["kev_epss_enrich"],
    AgentPhase.REPORT: [],
    AgentPhase.DONE: [],
}

# Additional tool names allowed per phase only for an active-mode scan that has
# passed domain-ownership verification (Phase 7, brief section 6.1) — see
# `AgentOrchestrator`'s VERIFY-phase handling and `tool_router.invoke`'s
# `active_enabled` gate. http_probe/tls_check/screenshot all make real network
# requests to the target host, unlike anything in `PHASE_TOOLS`.
ACTIVE_PHASE_TOOLS: dict[AgentPhase, list[str]] = {
    AgentPhase.EXPOSURE: ["http_probe", "tls_check", "screenshot"],
}


def tools_for_phase(phase: AgentPhase, *, active_enabled: bool = False) -> list[str]:
    """Every tool name allowed in `phase` — the passive set, plus the active set too
    when `active_enabled` (i.e. an active scan that's passed ownership verification)."""
    tools = list(PHASE_TOOLS.get(phase, []))
    if active_enabled:
        tools += ACTIVE_PHASE_TOOLS.get(phase, [])
    return tools


def next_phase(phase: AgentPhase) -> AgentPhase:
    """The phase after `phase`, or DONE if `phase` is already the last one."""
    index = PHASE_ORDER.index(phase)
    if index + 1 >= len(PHASE_ORDER):
        return AgentPhase.DONE
    return PHASE_ORDER[index + 1]
