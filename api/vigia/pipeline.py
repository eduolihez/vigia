"""Deterministic passive-scan pipeline: `vigia scan --passive <domain>`.

No LLM involved — this is the Phase 2 baseline the Phase 3 agent will eventually
supersede for interactive/adaptive scans. Runs every passive tool in a fixed order,
persists assets/findings/evidence/audit rows, and returns the finished `Scan`.

Kept intentionally simple: a fixed pipeline, not a state machine. Concurrency across
independent per-asset calls (DNS resolution, Shodan lookups) is bounded by small rate
limiters so a single scan doesn't hammer any one source.
"""

from __future__ import annotations

import gzip
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from vigia.config import Settings
from vigia.db.models import (
    Asset,
    AssetType,
    Evidence,
    Finding,
    FindingSeverity,
    Scan,
    ScanMode,
    ScanStatus,
    ToolCall,
    ToolCallStatus,
)
from vigia.tools import base as tools_base
from vigia.tools import (
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
from vigia.tools.censys_hosts import CensysHostsInput
from vigia.tools.censys_hosts import run as censys_hosts_run

MAX_SUBDOMAINS_TO_RESOLVE = 50
MAX_UNIQUE_IPS_TO_ENRICH = 30

# PLACEHOLDER SEVERITY: the Risk Engine (Phase 4) doesn't exist yet. Every finding
# from this pipeline is stored as INFO/score=0 and should be re-scored once
# risk/engine.py lands. See ADR-005 in docs/decisions.md.
PLACEHOLDER_SEVERITY = FindingSeverity.INFO
PLACEHOLDER_SCORE = 0.0
PLACEHOLDER_REMEDIATION = "Pending: severity/remediation are assigned by the Risk Engine (Phase 4)."


@dataclass
class PipelineSummary:
    scan_id: str
    domain: str
    status: ScanStatus
    assets_count: int = 0
    findings_count: int = 0
    tool_statuses: dict[str, str] = field(default_factory=dict)


def _log(message: str) -> None:
    print(message, file=sys.stderr)


async def _record_tool_call(
    session: AsyncSession,
    scan: Scan,
    phase: str,
    result: tools_base.ToolResult,
    args: dict[str, object],
) -> None:
    status = ToolCallStatus.ERROR if result.error else ToolCallStatus.SUCCESS
    session.add(
        ToolCall(
            scan_id=scan.id,
            phase=phase,
            tool=result.tool,
            args=args,
            reason="deterministic passive pipeline",
            status=status,
            duration_ms=result.duration_ms,
            result_sha256=result.sha256 or None,
        )
    )
    if result.raw_output:
        session.add(
            Evidence(
                tool=result.tool,
                raw_output=gzip.compress(result.raw_output),
                sha256=result.sha256,
            )
        )
    await session.flush()


async def _upsert_asset(
    session: AsyncSession, scan: Scan, type_: str, value: str, parent_id: str | None = None
) -> Asset:
    asset_type = AssetType(type_)
    result = await session.execute(
        select(Asset).where(
            col(Asset.scan_id) == scan.id,
            col(Asset.type) == asset_type,
            col(Asset.value) == value,
        )
    )
    asset = result.scalar_one_or_none()
    if asset:
        asset.last_seen = datetime.now(UTC)
        return asset
    asset = Asset(scan_id=scan.id, type=asset_type, value=value, parent_id=parent_id)
    session.add(asset)
    await session.flush()
    return asset


async def _persist_findings(
    session: AsyncSession,
    scan: Scan,
    assets_by_value: dict[str, Asset],
    findings: list[tools_base.FindingCandidate],
    kev_epss_by_cve: dict[str, dict[str, object]],
) -> int:
    count = 0
    for candidate in findings:
        asset = assets_by_value.get(candidate.asset_value or "")
        enrichment = kev_epss_by_cve.get(candidate.cve or "", {})
        session.add(
            Finding(
                scan_id=scan.id,
                asset_id=asset.id if asset else None,
                type=candidate.type,
                severity=PLACEHOLDER_SEVERITY,
                score=PLACEHOLDER_SCORE,
                title=candidate.title,
                explanation=candidate.detail,
                remediation=PLACEHOLDER_REMEDIATION,
                kev=bool(enrichment.get("in_kev", False)),
                epss=enrichment.get("epss"),  # type: ignore[arg-type]
                cve=candidate.cve,
            )
        )
        count += 1
    await session.flush()
    return count


async def run_passive_scan(
    session: AsyncSession, domain: str, settings: Settings
) -> PipelineSummary:
    scan = Scan(
        domain=domain,
        mode=ScanMode.PASSIVE,
        planner_model=settings.planner_model,
        extractor_model=settings.extractor_model,
        status=ScanStatus.RUNNING,
        started_at=datetime.now(UTC),
    )
    session.add(scan)
    await session.flush()

    tool_statuses: dict[str, str] = {}
    assets_by_value: dict[str, Asset] = {}
    all_findings: list[tools_base.FindingCandidate] = []
    all_cves: set[str] = set()

    domain_asset = await _upsert_asset(session, scan, "domain", domain)
    assets_by_value[domain] = domain_asset

    async with httpx.AsyncClient(timeout=tools_base.DEFAULT_TIMEOUT_SECONDS) as client:
        shodan_limiter = tools_base.RateLimiter(min_interval_seconds=1.0)
        dns_limiter = tools_base.RateLimiter(min_interval_seconds=0.2)

        async def record(
            phase: str, result: tools_base.ToolResult, args: dict[str, object]
        ) -> None:
            await _record_tool_call(session, scan, phase, result, args)
            tool_statuses[result.tool] = "error" if result.error else "ok"
            if result.error:
                _log(f"[{result.tool}] error: {result.error}")
            else:
                _log(
                    f"[{result.tool}] ok — {len(result.assets_discovered)} assets, "
                    f"{len(result.findings_candidates)} findings ({result.duration_ms}ms)"
                )
            all_findings.extend(result.findings_candidates)
            for a in result.assets_discovered:
                if a.value not in assets_by_value:
                    parent = assets_by_value.get(a.parent_value or "")
                    assets_by_value[a.value] = await _upsert_asset(
                        session, scan, a.type, a.value, parent.id if parent else None
                    )

        # 1. WHOIS/ASN
        result = await whois_asn.run(whois_asn.WhoisAsnInput(resource=domain), client)
        await record("enumerate", result, {"resource": domain})

        # 2. crt.sh
        result = await ct_subdomains.run(ct_subdomains.CtSubdomainsInput(domain=domain), client)
        await record("enumerate", result, {"domain": domain})

        # 3. subfinder (best-effort — binary may be absent outside Docker)
        result = await subfinder_enum.run(subfinder_enum.SubfinderEnumInput(domain=domain))
        await record("enumerate", result, {"domain": domain})

        # 4. Resolve DNS for the root domain + discovered subdomains (bounded)
        hostnames = [domain] + [
            v for v, a in assets_by_value.items() if a.type == "subdomain"
        ]
        hostnames = hostnames[:MAX_SUBDOMAINS_TO_RESOLVE]
        cname_targets: dict[str, str] = {}
        for hostname in hostnames:
            await dns_limiter.wait()
            result = await dns_resolve.run(dns_resolve.DnsResolveInput(hostname=hostname))
            await record("resolve", result, {"hostname": hostname})
            raw = json.loads(result.raw_output or b"{}")
            cnames = raw.get("records", {}).get("CNAME", [])
            if cnames:
                cname_targets[hostname] = cnames[0]

        # 5. Dangling DNS for hostnames that have a CNAME
        for hostname in cname_targets:
            result = await dangling_dns.run(dangling_dns.DanglingDnsInput(hostname=hostname))
            await record("exposure", result, {"hostname": hostname})

        # 6. Shodan InternetDB + Censys per unique IP (bounded)
        unique_ips = sorted({v for v, a in assets_by_value.items() if a.type == "ip"})[
            :MAX_UNIQUE_IPS_TO_ENRICH
        ]
        for ip in unique_ips:
            await shodan_limiter.wait()
            shodan_input = shodan_internetdb.ShodanInternetDbInput(ip=ip)
            result = await shodan_internetdb.run(shodan_input, client)
            await record("exposure", result, {"ip": ip})
            all_cves.update(f.cve for f in result.findings_candidates if f.cve)

            result = await censys_hosts_run(
                CensysHostsInput(ip=ip),
                client,
                api_id=settings.censys_api_id,
                api_secret=settings.censys_api_secret,
            )
            await record("exposure", result, {"ip": ip})

        # 7. Email auth posture
        result = await email_auth.run(email_auth.EmailAuthInput(domain=domain))
        await record("email_and_spoofing", result, {"domain": domain})

        # 8. Typosquat (informational only — never investigated further)
        result = await typosquat.run(typosquat.TyposquatInput(domain=domain))
        await record("enumerate", result, {"domain": domain})

        # 9. GitHub code search (only if a token is configured)
        result = await github_leaks.run(
            github_leaks.GithubLeaksInput(domain=domain), client, token=settings.github_token
        )
        await record("leaks", result, {"domain": domain})

        # 10. HIBP domain search (only if a key is configured)
        result = await hibp_domain.run(
            hibp_domain.HibpDomainInput(domain=domain), client, api_key=settings.hibp_api_key
        )
        await record("leaks", result, {"domain": domain})

        # 11. Wayback URLs
        result = await wayback_urls.run(wayback_urls.WaybackUrlsInput(domain=domain), client)
        await record("enumerate", result, {"domain": domain})

        # 12. KEV/EPSS enrichment for every CVE surfaced above
        kev_epss_by_cve: dict[str, dict[str, object]] = {}
        if all_cves:
            result = await kev_epss_enrich.run(
                kev_epss_enrich.KevEpssEnrichInput(cves=sorted(all_cves)), client
            )
            await record("risk", result, {"cves": sorted(all_cves)})
            if not result.error:
                payload = json.loads(result.raw_output)
                kev_epss_by_cve = {e["cve"]: e for e in payload.get("enrichment", [])}

    findings_count = await _persist_findings(
        session, scan, assets_by_value, all_findings, kev_epss_by_cve
    )

    scan.status = ScanStatus.COMPLETED
    scan.finished_at = datetime.now(UTC)
    await session.commit()

    return PipelineSummary(
        scan_id=scan.id,
        domain=domain,
        status=scan.status,
        assets_count=len(assets_by_value),
        findings_count=findings_count,
        tool_statuses=tool_statuses,
    )
