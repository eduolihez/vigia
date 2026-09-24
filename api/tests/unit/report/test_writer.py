"""Report Writer tests with synthetic evidence — the brief's Phase 4 acceptance bar:
"report with no invented entities (tested with synthetic evidence)".
"""

from __future__ import annotations

import json
from typing import Any

from vigia.db.models import Asset, AssetType, Finding, FindingSeverity, Scan, ScanMode, ScanStatus
from vigia.db.session import _session_factory
from vigia.report.validator import validate_report
from vigia.report.writer import generate_report


class ScriptedGenerator:
    """Returns pre-scripted JSON strings in order, ignoring the actual prompt."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses = [json.dumps(r) for r in responses]
        self.calls = 0

    async def generate(
        self, *, system_prompt: str, user_message: str, json_schema: dict[str, Any]
    ) -> str:
        response = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return response


async def _make_synthetic_scan() -> Scan:
    async with _session_factory() as session:
        scan = Scan(
            domain="example.com",
            mode=ScanMode.PASSIVE,
            planner_model="fake",
            extractor_model="fake",
            status=ScanStatus.COMPLETED,
        )
        session.add(scan)
        await session.flush()

        session.add(Asset(scan_id=scan.id, type=AssetType.DOMAIN, value="example.com"))
        session.add(Asset(scan_id=scan.id, type=AssetType.SUBDOMAIN, value="www.example.com"))
        session.add(Asset(scan_id=scan.id, type=AssetType.IP, value="93.184.216.34"))
        session.add(
            Finding(
                scan_id=scan.id,
                type="dmarc_missing",
                severity=FindingSeverity.HIGH,
                score=6.5,
                title="No DMARC record for example.com",
                explanation="example.com has no DMARC record.",
                remediation="Publish a DMARC record.",
            )
        )
        await session.commit()
        await session.refresh(scan)
        return scan


_CLEAN_DRAFT = {
    "executive_summary": "example.com is missing a DMARC record.",
    "top_risks": [{"title": "No DMARC", "reason": "www.example.com can be spoofed"}],
    "findings": [
        {
            "title": "No DMARC record for example.com",
            "explanation": "example.com has no DMARC record.",
            "impact": "Email spoofing is possible for www.example.com.",
            "remediation": "Publish a DMARC record for example.com.",
        }
    ],
    "positive_observations": ["93.184.216.34 responded normally."],
}

_INVENTED_DRAFT = {
    "executive_summary": "example.com and evil-invented-host.net share infrastructure.",
    "top_risks": [{"title": "Compromise", "reason": "CVE-1999-0001 affects example.com"}],
    "findings": [
        {
            "title": "No DMARC record for example.com",
            "explanation": "example.com has no DMARC record.",
            "impact": "Attackers could spoof mail from 10.0.0.99.",
            "remediation": "Publish a DMARC record.",
        }
    ],
    "positive_observations": [],
}


async def test_generate_report_accepts_clean_draft_on_first_try() -> None:
    scan = await _make_synthetic_scan()
    generator = ScriptedGenerator([_CLEAN_DRAFT])

    async with _session_factory() as session:
        result = await generate_report(session, scan, generator)

    assert result.attempts_used == 1
    assert result.dropped_items == []
    assert "DMARC" in result.draft.executive_summary


async def test_generate_report_regenerates_after_invented_entity() -> None:
    scan = await _make_synthetic_scan()
    generator = ScriptedGenerator([_INVENTED_DRAFT, _CLEAN_DRAFT])

    async with _session_factory() as session:
        result = await generate_report(session, scan, generator)

    assert generator.calls == 2
    assert result.attempts_used == 2
    assert result.dropped_items == []


async def test_generate_report_drops_invented_items_if_still_invalid_after_retries() -> None:
    scan = await _make_synthetic_scan()
    # Always returns the invented draft — regeneration never succeeds.
    generator = ScriptedGenerator([_INVENTED_DRAFT])

    async with _session_factory() as session:
        result = await generate_report(session, scan, generator, max_attempts=2)
        evidence = await _build_evidence(session, scan)

    assert generator.calls == 3  # 1 initial + 2 retries
    assert len(result.dropped_items) > 0
    # The shipped report, after stripping, has zero invented entities.
    assert validate_report(result.draft, evidence) == {}


async def _build_evidence(session, scan: Scan):  # type: ignore[no-untyped-def]
    from vigia.report.validator import build_evidence_base

    return await build_evidence_base(session, scan.id, scan.domain)
