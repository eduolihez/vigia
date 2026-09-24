"""Report Validator (brief section 7.2): every entity the Report Writer mentions
must exist in the scan's own evidence — domains, IPs, CVEs, ports. A report that
invents an entity is not trustworthy, regardless of how plausible it reads.

`validate_report` returns violations per section; the caller (`writer.py`) decides
whether to regenerate (feeding the violations back as context) or drop the
offending item after retries are exhausted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from vigia.db.models import Asset, Finding
from vigia.report.models import ReportDraft

# Alphabetic-label dotted tokens that look like domains but aren't ("e.g.", "i.e.",
# version-like "v3.1" is excluded by the digit check in _DOMAIN_RE already).
_DOMAIN_STOPWORDS = {"e.g.", "i.e.", "etc.", "vs."}

_DOMAIN_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,24}){1,}\b"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)

# A claimed count is only checked when it's near one of these keyword phrases —
# anchoring narrowly avoids false positives on unrelated numbers ("3 sentences", a
# severity score, etc). Maps the EvidenceBase.counts key -> its keyword pattern.
_COUNT_KEYWORDS: dict[str, str] = {
    "typosquat": r"(?:look-?alike|typosquat(?:ted)?)\s+domains?",
    "subdomains": r"subdomains?",
    "findings": r"findings?",
    "cves": r"(?:known\s+)?vulnerabilit(?:y|ies)|CVEs?",
}
_COUNT_PATTERNS: dict[str, re.Pattern[str]] = {
    key: re.compile(rf"\b(\d+)\b(?:\s+\w+){{0,3}}?\s+(?:{pattern})", re.IGNORECASE)
    for key, pattern in _COUNT_KEYWORDS.items()
}


@dataclass
class EvidenceBase:
    domain: str
    hostnames: set[str] = field(default_factory=set)  # domain + all subdomains
    ips: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    ports: set[str] = field(default_factory=set)
    counts: dict[str, int] = field(default_factory=dict)


async def build_evidence_base(session: AsyncSession, scan_id: str, domain: str) -> EvidenceBase:
    evidence = EvidenceBase(domain=domain, hostnames={domain})

    assets = (
        (await session.execute(select(Asset).where(col(Asset.scan_id) == scan_id))).scalars().all()
    )
    for asset in assets:
        if asset.type in ("domain", "subdomain"):
            evidence.hostnames.add(asset.value.lower())
        elif asset.type == "ip":
            evidence.ips.add(asset.value)
        elif asset.type == "service" and ":" in asset.value:
            host, _, port = asset.value.rpartition(":")
            evidence.ips.add(host)
            evidence.ports.add(port)

    findings = (
        (await session.execute(select(Finding).where(col(Finding.scan_id) == scan_id)))
        .scalars()
        .all()
    )
    for finding in findings:
        if finding.cve:
            evidence.cves.add(finding.cve.upper())

    subdomain_count = sum(1 for a in assets if a.type == "subdomain")
    typosquat_count = sum(1 for f in findings if f.type == "typosquat")
    evidence.counts = {
        "subdomains": subdomain_count,
        "findings": len(findings),
        "typosquat": typosquat_count,
        "cves": len(evidence.cves),
    }

    return evidence


def _is_valid_domain_mention(token: str, evidence: EvidenceBase) -> bool:
    token = token.lower().rstrip(".")
    if token in _DOMAIN_STOPWORDS:
        return True
    if token == evidence.domain or token in evidence.hostnames:
        return True
    return token.endswith(f".{evidence.domain}") and token in evidence.hostnames


def validate_text(text: str, evidence: EvidenceBase) -> list[str]:
    """Return a list of human-readable violations found in `text` (empty = clean)."""
    violations: list[str] = []

    for match in _DOMAIN_RE.finditer(text):
        token = match.group(0)
        if token in _DOMAIN_STOPWORDS:
            continue
        if _IPV4_RE.fullmatch(token):
            continue  # an IP matches the domain regex shape too; handled separately
        if not _is_valid_domain_mention(token, evidence):
            violations.append(f"mentions domain/host {token!r} not found in this scan's evidence")

    for match in _IPV4_RE.finditer(text):
        ip = match.group(0)
        if ip not in evidence.ips:
            violations.append(f"mentions IP {ip!r} not found in this scan's evidence")

    for match in _CVE_RE.finditer(text):
        cve = match.group(0).upper()
        if cve not in evidence.cves:
            violations.append(f"mentions {cve} which wasn't found in this scan's evidence")

    for match in _PORT_RE.finditer(text):
        port = match.group(1)
        if port not in evidence.ports:
            violations.append(f"mentions port {port} not found in this scan's evidence")

    for key, pattern in _COUNT_PATTERNS.items():
        expected = evidence.counts.get(key)
        if expected is None:
            continue
        for match in pattern.finditer(text):
            claimed = int(match.group(1))
            if claimed != expected:
                violations.append(
                    f"claims {claimed} {key} but this scan's evidence shows {expected}"
                )

    return violations


def validate_report(draft: ReportDraft, evidence: EvidenceBase) -> dict[str, list[str]]:
    """Violations keyed by section path, e.g. 'findings[2]'. Empty dict = clean."""
    violations: dict[str, list[str]] = {}

    v = validate_text(draft.executive_summary, evidence)
    if v:
        violations["executive_summary"] = v

    for i, risk in enumerate(draft.top_risks):
        v = validate_text(f"{risk.title} {risk.reason}", evidence)
        if v:
            violations[f"top_risks[{i}]"] = v

    for i, finding in enumerate(draft.findings):
        text = f"{finding.title} {finding.explanation} {finding.impact} {finding.remediation}"
        v = validate_text(text, evidence)
        if v:
            violations[f"findings[{i}]"] = v

    for i, obs in enumerate(draft.positive_observations):
        v = validate_text(obs, evidence)
        if v:
            violations[f"positive_observations[{i}]"] = v

    return violations


def strip_invalid_items(
    draft: ReportDraft, evidence: EvidenceBase
) -> tuple[ReportDraft, list[str]]:
    """Drop only the specific top_risks/findings/positive_observations items that
    still fail validation; keep everything else. The executive_summary can't be
    partially dropped, so if it's still invalid its violating sentences are removed
    by replacing the whole field with a safe fallback and logging it."""
    dropped: list[str] = []

    summary = draft.executive_summary
    if validate_text(summary, evidence):
        dropped.append(f"executive_summary: {validate_text(summary, evidence)}")
        summary = "Summary withheld: could not be generated without unverifiable claims."

    kept_risks = []
    for risk in draft.top_risks:
        if validate_text(f"{risk.title} {risk.reason}", evidence):
            dropped.append(f"top_risk {risk.title!r}")
        else:
            kept_risks.append(risk)

    kept_findings = []
    for finding in draft.findings:
        text = f"{finding.title} {finding.explanation} {finding.impact} {finding.remediation}"
        if validate_text(text, evidence):
            dropped.append(f"finding {finding.title!r}")
        else:
            kept_findings.append(finding)

    kept_observations = []
    for obs in draft.positive_observations:
        if validate_text(obs, evidence):
            dropped.append(f"positive_observation {obs!r}")
        else:
            kept_observations.append(obs)

    cleaned = ReportDraft(
        executive_summary=summary,
        top_risks=kept_risks,
        findings=kept_findings,
        positive_observations=kept_observations,
    )
    return cleaned, dropped
