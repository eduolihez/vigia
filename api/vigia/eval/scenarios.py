"""The lab itself: 5 synthetic scenarios covering SEED, ENUMERATE, RESOLVE, EXPOSURE
(both passive and, once verified, active), EMAIL_AND_SPOOFING, and RISK. Every
scenario's `expected_finding_types` includes "network_info" — the SEED phase's
`whois_asn` lookup runs deterministically every scan and always emits one (see
`tools/whois_asn.py`), so it's not something the agent's own judgment controls, but
its absence would itself signal something broken.
"""

from __future__ import annotations

from typing import Any

from vigia.db.models import ScanMode
from vigia.eval.lab import LabScenario, ToolScript, default_scripts
from vigia.tools.base import DiscoveredAsset, FindingCandidate, ToolResult

_NETWORK_INFO = FindingCandidate(
    type="network_info", title="WHOIS/ASN lookup", detail="Synthetic lab WHOIS record."
)


def _whois_asn_baseline() -> ToolScript:
    def _run(args: dict[str, Any]) -> ToolResult:
        return ToolResult(
            tool="whois_asn",
            raw_output=b"{}",
            sha256="lab",
            duration_ms=1,
            findings_candidates=[_NETWORK_INFO],
        )

    return _run


def _clean_scenario() -> LabScenario:
    domain = "clean-corp.lab"
    scripts = default_scripts()
    scripts["whois_asn"] = _whois_asn_baseline()

    def _dns_resolve(args: dict[str, Any]) -> ToolResult:
        if args.get("hostname") == domain:
            return ToolResult(
                tool="dns_resolve",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                assets_discovered=[
                    DiscoveredAsset(type="ip", value="203.0.113.10", parent_value=domain)
                ],
            )
        return ToolResult(tool="dns_resolve", raw_output=b"{}", sha256="lab", duration_ms=1)

    scripts["dns_resolve"] = _dns_resolve

    return LabScenario(
        name="clean",
        description="A well-configured domain — no subdomains, valid email auth, no exposure.",
        domain=domain,
        mode=ScanMode.PASSIVE,
        tool_scripts=scripts,
        expected_finding_types={"network_info"},
    )


def _email_misconfig_scenario() -> LabScenario:
    domain = "email-misconfig.lab"
    scripts = default_scripts()
    scripts["whois_asn"] = _whois_asn_baseline()

    def _email_auth(args: dict[str, Any]) -> ToolResult:
        if args.get("domain") == domain:
            return ToolResult(
                tool="email_auth",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                findings_candidates=[
                    FindingCandidate(
                        type="dmarc_missing",
                        title=f"No DMARC record for {domain}",
                        detail="Synthetic lab: no DMARC record published.",
                        asset_value=domain,
                    ),
                    FindingCandidate(
                        type="spf_missing",
                        title=f"No SPF record for {domain}",
                        detail="Synthetic lab: no SPF record published.",
                        asset_value=domain,
                    ),
                ],
            )
        return ToolResult(tool="email_auth", raw_output=b"{}", sha256="lab", duration_ms=1)

    scripts["email_auth"] = _email_auth

    return LabScenario(
        name="email-misconfig",
        description="A domain missing SPF and DMARC records.",
        domain=domain,
        mode=ScanMode.PASSIVE,
        tool_scripts=scripts,
        expected_finding_types={"network_info", "dmarc_missing", "spf_missing"},
    )


def _dangling_dns_scenario() -> LabScenario:
    domain = "dangling.lab"
    stale_host = f"old-app.{domain}"
    scripts = default_scripts()
    scripts["whois_asn"] = _whois_asn_baseline()

    def _ct_subdomains(args: dict[str, Any]) -> ToolResult:
        if args.get("domain") == domain:
            return ToolResult(
                tool="ct_subdomains",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                assets_discovered=[
                    DiscoveredAsset(type="subdomain", value=stale_host, parent_value=domain)
                ],
            )
        return ToolResult(tool="ct_subdomains", raw_output=b"{}", sha256="lab", duration_ms=1)

    def _dangling_dns(args: dict[str, Any]) -> ToolResult:
        if args.get("hostname") == stale_host:
            return ToolResult(
                tool="dangling_dns",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                findings_candidates=[
                    FindingCandidate(
                        type="dangling_dns_candidate",
                        title=f"Possible dangling DNS: {stale_host}",
                        detail="Synthetic lab: CNAME points at an unclaimed-looking target.",
                        asset_value=stale_host,
                    )
                ],
            )
        return ToolResult(tool="dangling_dns", raw_output=b"{}", sha256="lab", duration_ms=1)

    scripts["ct_subdomains"] = _ct_subdomains
    scripts["dangling_dns"] = _dangling_dns

    return LabScenario(
        name="dangling-dns",
        description="A stale subdomain with a CNAME matching a takeover fingerprint.",
        domain=domain,
        mode=ScanMode.PASSIVE,
        tool_scripts=scripts,
        expected_finding_types={"network_info", "dangling_dns_candidate"},
    )


def _kev_exposure_scenario() -> LabScenario:
    domain = "kev-exposure.lab"
    ip = "203.0.113.50"
    cve = "CVE-2021-44228"
    scripts = default_scripts()
    scripts["whois_asn"] = _whois_asn_baseline()

    def _dns_resolve(args: dict[str, Any]) -> ToolResult:
        if args.get("hostname") == domain:
            return ToolResult(
                tool="dns_resolve",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                assets_discovered=[DiscoveredAsset(type="ip", value=ip, parent_value=domain)],
            )
        return ToolResult(tool="dns_resolve", raw_output=b"{}", sha256="lab", duration_ms=1)

    def _shodan_internetdb(args: dict[str, Any]) -> ToolResult:
        if args.get("ip") == ip:
            return ToolResult(
                tool="shodan_internetdb",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                findings_candidates=[
                    FindingCandidate(
                        type="known_vulnerability",
                        title=f"{cve} reported open on {ip}",
                        detail="Synthetic lab: Shodan InternetDB lists a known CVE.",
                        asset_value=ip,
                        cve=cve,
                    )
                ],
            )
        return ToolResult(tool="shodan_internetdb", raw_output=b"{}", sha256="lab", duration_ms=1)

    def _kev_epss_enrich(args: dict[str, Any]) -> ToolResult:
        import json

        cves = args.get("cves") or []
        if cve in cves:
            entry = {"cve": cve, "in_kev": True, "known_ransomware": True, "epss": 0.94}
            payload = json.dumps({"enrichment": [entry]}).encode()
            return ToolResult(
                tool="kev_epss_enrich", raw_output=payload, sha256="lab", duration_ms=1
            )
        return ToolResult(tool="kev_epss_enrich", raw_output=b"{}", sha256="lab", duration_ms=1)

    scripts["dns_resolve"] = _dns_resolve
    scripts["shodan_internetdb"] = _shodan_internetdb
    scripts["kev_epss_enrich"] = _kev_epss_enrich

    return LabScenario(
        name="kev-exposure",
        description="A host exposing a service with a known-exploited (KEV) CVE.",
        domain=domain,
        mode=ScanMode.PASSIVE,
        tool_scripts=scripts,
        expected_finding_types={"network_info", "known_vulnerability"},
    )


def _confirmed_takeover_scenario() -> LabScenario:
    domain = "takeover.lab"
    stale_host = f"stale.{domain}"
    scripts = default_scripts()
    scripts["whois_asn"] = _whois_asn_baseline()

    def _ct_subdomains(args: dict[str, Any]) -> ToolResult:
        if args.get("domain") == domain:
            return ToolResult(
                tool="ct_subdomains",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                assets_discovered=[
                    DiscoveredAsset(type="subdomain", value=stale_host, parent_value=domain)
                ],
            )
        return ToolResult(tool="ct_subdomains", raw_output=b"{}", sha256="lab", duration_ms=1)

    def _dangling_dns(args: dict[str, Any]) -> ToolResult:
        if args.get("hostname") == stale_host:
            return ToolResult(
                tool="dangling_dns",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                findings_candidates=[
                    FindingCandidate(
                        type="dangling_dns_candidate",
                        title=f"Possible dangling DNS: {stale_host}",
                        detail="Synthetic lab: CNAME points at an unclaimed-looking target.",
                        asset_value=stale_host,
                    )
                ],
            )
        return ToolResult(tool="dangling_dns", raw_output=b"{}", sha256="lab", duration_ms=1)

    def _http_probe(args: dict[str, Any]) -> ToolResult:
        if args.get("hostname") == stale_host:
            return ToolResult(
                tool="http_probe",
                raw_output=b"{}",
                sha256="lab",
                duration_ms=1,
                findings_candidates=[
                    FindingCandidate(
                        type="dangling_dns_confirmed",
                        title=f"Confirmed subdomain takeover: {stale_host}",
                        detail="Synthetic lab: response body matches an 'unclaimed' signature.",
                        asset_value=stale_host,
                    )
                ],
            )
        return ToolResult(tool="http_probe", raw_output=b"{}", sha256="lab", duration_ms=1)

    scripts["ct_subdomains"] = _ct_subdomains
    scripts["dangling_dns"] = _dangling_dns
    scripts["http_probe"] = _http_probe

    return LabScenario(
        name="confirmed-takeover",
        description=(
            "Active mode: a dangling-DNS candidate actively confirmed as takeoverable "
            "via http_probe, once domain ownership is verified."
        ),
        domain=domain,
        mode=ScanMode.ACTIVE,
        tool_scripts=scripts,
        expected_finding_types={"network_info", "dangling_dns_candidate", "dangling_dns_confirmed"},
    )


def all_scenarios() -> list[LabScenario]:
    return [
        _clean_scenario(),
        _email_misconfig_scenario(),
        _dangling_dns_scenario(),
        _kev_exposure_scenario(),
        _confirmed_takeover_scenario(),
    ]
