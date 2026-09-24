"""OSINT tool wrapper registry.

Each entry maps a tool name to its module, which exposes `SPEC` (a `ToolSpec`), an
input model, and an async `run(...)` function. `PASSIVE_TOOL_NAMES` is the set used by
the Phase 2 deterministic CLI pipeline; active tools (`http_probe`, `screenshot`,
`tls_check`) land in Phase 7 alongside domain-ownership verification.
"""

from vigia.tools import (
    censys_hosts,
    ct_subdomains,
    dangling_dns,
    dns_resolve,
    email_auth,
    github_leaks,
    hibp_domain,
    kev_epss_enrich,
    shodan_internetdb,
    subfinder_enum,
    typosquat,
    wayback_urls,
    whois_asn,
)
from vigia.tools.base import ToolSpec

TOOL_MODULES = {
    "whois_asn": whois_asn,
    "ct_subdomains": ct_subdomains,
    "subfinder_enum": subfinder_enum,
    "wayback_urls": wayback_urls,
    "dns_resolve": dns_resolve,
    "dangling_dns": dangling_dns,
    "shodan_internetdb": shodan_internetdb,
    "censys_hosts": censys_hosts,
    "email_auth": email_auth,
    "typosquat": typosquat,
    "github_leaks": github_leaks,
    "hibp_domain": hibp_domain,
    "kev_epss_enrich": kev_epss_enrich,
}

TOOL_SPECS: dict[str, ToolSpec] = {name: mod.SPEC for name, mod in TOOL_MODULES.items()}

PASSIVE_TOOL_NAMES = [name for name, spec in TOOL_SPECS.items() if spec.mode == "passive"]

__all__ = ["TOOL_MODULES", "TOOL_SPECS", "PASSIVE_TOOL_NAMES"]
