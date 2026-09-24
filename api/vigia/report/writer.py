"""Report Writer (brief section 7.1-7.2): drafts a report from a scan's evidence
using the planner LLM with structured output, then validates and repairs it.

The LLM drafts; `report/validator.py` is the deterministic check that nothing was
invented. Up to `max_attempts` regenerations (with the previous violations fed back
as context) are tried; anything still invalid after that is dropped from the final
report and logged in `ReportResult.dropped_items` rather than shipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col

from vigia.agent.llm_client import StructuredGenerator
from vigia.db.models import Asset, Finding, Scan
from vigia.report.models import ReportDraft
from vigia.report.validator import (
    build_evidence_base,
    strip_invalid_items,
    validate_report,
)

DEFAULT_MAX_ATTEMPTS = 2
_PROMPT_PATH = Path(__file__).parent / "prompts" / "report_writer_system.md"


@dataclass
class ReportResult:
    draft: ReportDraft
    dropped_items: list[str]
    attempts_used: int


async def _build_evidence_text(session: AsyncSession, scan: Scan) -> str:
    assets = (
        (await session.execute(select(Asset).where(col(Asset.scan_id) == scan.id))).scalars().all()
    )
    findings = (
        (await session.execute(select(Finding).where(col(Finding.scan_id) == scan.id)))
        .scalars()
        .all()
    )

    lines = [f"Target domain: {scan.domain}", ""]

    by_type: dict[str, list[str]] = {}
    for asset in assets:
        by_type.setdefault(asset.type.value, []).append(asset.value)
    lines.append("Assets discovered:")
    for type_, values in sorted(by_type.items()):
        lines.append(f"- {type_} ({len(values)}): {', '.join(sorted(values))}")

    lines.append("")
    lines.append(f"Findings ({len(findings)}):")
    if not findings:
        lines.append("- none")
    for f in findings:
        cve_part = f" [{f.cve}, KEV={f.kev}, EPSS={f.epss}]" if f.cve else ""
        lines.append(
            f"- [{f.severity.value}/{f.score}] {f.type}: {f.title} — {f.explanation}{cve_part}"
        )

    return "\n".join(lines)


async def generate_report(
    session: AsyncSession,
    scan: Scan,
    generator: StructuredGenerator,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> ReportResult:
    evidence_text = await _build_evidence_text(session, scan)
    evidence_base = await build_evidence_base(session, scan.id, scan.domain)
    system_prompt_template = _PROMPT_PATH.read_text(encoding="utf-8")
    system_prompt = system_prompt_template.format(domain=scan.domain, evidence=evidence_text)
    schema = ReportDraft.model_json_schema()

    feedback = ""
    draft: ReportDraft | None = None
    violations: dict[str, list[str]] = {}
    attempt = 0

    for attempt in range(max_attempts + 1):  # noqa: B007 — read after the loop, below
        user_message = "Write the report now." + (f"\n\n{feedback}" if feedback else "")
        raw = await generator.generate(
            system_prompt=system_prompt, user_message=user_message, json_schema=schema
        )
        draft = ReportDraft.model_validate_json(raw)
        violations = validate_report(draft, evidence_base)
        if not violations:
            break
        feedback = (
            "Your previous attempt mentioned entities not in the evidence:\n"
            + "\n".join(f"- {section}: {'; '.join(msgs)}" for section, msgs in violations.items())
            + "\nRewrite the report using ONLY entities from the evidence above."
        )

    assert draft is not None
    dropped: list[str] = []
    if violations:
        draft, dropped = strip_invalid_items(draft, evidence_base)

    return ReportResult(draft=draft, dropped_items=dropped, attempts_used=attempt + 1)
