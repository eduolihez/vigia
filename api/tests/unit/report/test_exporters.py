from __future__ import annotations

from pathlib import Path

from vigia.db.models import Finding, FindingSeverity, Scan, ScanMode, ScanStatus
from vigia.report.exporters.json_export import to_json_dict
from vigia.report.exporters.markdown import to_markdown
from vigia.report.exporters.pdf import markdown_to_pdf_bytes
from vigia.report.models import ReportDraft, ReportFinding, TopRisk
from vigia.report.writer import ReportResult


def _scan() -> Scan:
    return Scan(
        id="scan-1",
        domain="example.com",
        mode=ScanMode.PASSIVE,
        planner_model="fake",
        extractor_model="fake",
        status=ScanStatus.COMPLETED,
    )


def _result() -> ReportResult:
    draft = ReportDraft(
        executive_summary="example.com is missing DMARC.",
        top_risks=[TopRisk(title="No DMARC", reason="spoofing is possible")],
        findings=[
            ReportFinding(
                title="No DMARC",
                explanation="example.com has no DMARC record.",
                impact="Spoofing.",
                remediation="Publish one.",
            )
        ],
        positive_observations=["SPF is configured correctly."],
    )
    return ReportResult(draft=draft, dropped_items=["a dropped thing"], attempts_used=1)


def _findings() -> list[Finding]:
    return [
        Finding(
            id="f1",
            scan_id="scan-1",
            type="dmarc_missing",
            severity=FindingSeverity.HIGH,
            score=6.5,
            title="No DMARC",
            explanation="...",
            remediation="...",
            cve=None,
            kev=False,
        )
    ]


def test_markdown_export_includes_all_sections() -> None:
    md = to_markdown(_scan(), _result(), _findings())
    assert "# Vigía Report — example.com" in md
    assert "## Executive Summary" in md
    assert "No DMARC" in md
    assert "## Top Risks" in md
    assert "## Findings" in md
    assert "## Positive Observations" in md
    assert "## Evidence Appendix" in md
    assert "/scans/scan-1/audit" in md
    assert "## Validation Notes" in md
    assert "a dropped thing" in md


def test_json_export_shape() -> None:
    data = to_json_dict(_scan(), _result(), _findings())
    assert data["scan"]["domain"] == "example.com"
    assert data["report"]["executive_summary"] == "example.com is missing DMARC."
    assert data["validation"]["dropped_items"] == ["a dropped thing"]
    assert data["evidence"][0]["title"] == "No DMARC"
    assert data["evidence"][0]["severity"] == "high"


async def test_pdf_export_produces_a_real_pdf_file(tmp_path: Path) -> None:
    md = to_markdown(_scan(), _result(), _findings())
    pdf_bytes = await markdown_to_pdf_bytes(md)

    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000

    out_file = tmp_path / "report.pdf"
    out_file.write_bytes(pdf_bytes)
    assert out_file.stat().st_size == len(pdf_bytes)
