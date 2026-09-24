"""Markdown export (brief section 7.4). The PDF exporter renders this same Markdown
(via a minimal HTML wrapper), so this is the one place report layout lives.

Every narrative finding the LLM wrote is followed by an "Evidence" appendix listing
the underlying `Finding` DB rows (severity, score, CVE, audit reference) — brief
section 7.3: "each finding in the report links to its raw evidence".
"""

from __future__ import annotations

from vigia.db.models import Finding, Scan
from vigia.report.writer import ReportResult


def to_markdown(scan: Scan, result: ReportResult, findings: list[Finding]) -> str:
    draft = result.draft
    lines = [
        f"# Vigía Report — {scan.domain}",
        "",
        f"*Scan `{scan.id}` — {scan.mode.value}, {scan.status.value}*",
        "",
        "## Executive Summary",
        "",
        draft.executive_summary,
        "",
        "## Top Risks",
        "",
    ]
    lines += [f"- **{r.title}** — {r.reason}" for r in draft.top_risks] or ["- None identified."]

    lines += ["", "## Findings", ""]
    if not draft.findings:
        lines.append("No findings to report.")
    for f in draft.findings:
        lines += [
            f"### {f.title}",
            "",
            f"**Explanation:** {f.explanation}",
            "",
            f"**Impact:** {f.impact}",
            "",
            f"**Remediation:** {f.remediation}",
            "",
        ]

    lines += ["## Positive Observations", ""]
    lines += [f"- {obs}" for obs in draft.positive_observations] or ["- None recorded."]

    lines += ["", "## Evidence Appendix", "", "Raw findings backing this report:", ""]
    for finding in sorted(findings, key=lambda f: -f.score):
        cve_part = f", {finding.cve}" if finding.cve else ""
        kev_part = ", in CISA KEV" if finding.kev else ""
        lines.append(
            f"- **[{finding.severity.value.upper()} {finding.score}]** {finding.title} "
            f"({finding.type}{cve_part}{kev_part})"
        )
    lines += ["", f"Full tool-call audit trail: `GET /scans/{scan.id}/audit`.", ""]

    if result.dropped_items:
        lines += [
            "## Validation Notes",
            "",
            (
                f"{len(result.dropped_items)} item(s) were removed from this report because "
                "they referenced entities not found in this scan's evidence:"
            ),
            "",
        ]
        lines += [f"- {item}" for item in result.dropped_items]

    return "\n".join(lines)
