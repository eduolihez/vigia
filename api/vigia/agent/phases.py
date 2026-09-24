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

# Passive-mode tool names allowed per phase (Phase 2 tool registry). Active tools
# (http_probe, screenshot, tls_check) are added to EXPOSURE only once Phase 7 lands
# domain-ownership verification.
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


def next_phase(phase: AgentPhase) -> AgentPhase:
    """The phase after `phase`, or DONE if `phase` is already the last one."""
    index = PHASE_ORDER.index(phase)
    if index + 1 >= len(PHASE_ORDER):
        return AgentPhase.DONE
    return PHASE_ORDER[index + 1]
