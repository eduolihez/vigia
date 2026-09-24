"""JSON export (brief section 7.4)."""

from __future__ import annotations

from typing import Any

from vigia.db.models import Finding, Scan
from vigia.report.writer import ReportResult


def to_json_dict(scan: Scan, result: ReportResult, findings: list[Finding]) -> dict[str, Any]:
    return {
        "scan": {
            "id": scan.id,
            "domain": scan.domain,
            "mode": scan.mode.value,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        },
        "report": result.draft.model_dump(),
        "validation": {
            "attempts_used": result.attempts_used,
            "dropped_items": result.dropped_items,
        },
        "evidence": [
            {
                "id": f.id,
                "asset_id": f.asset_id,
                "type": f.type,
                "severity": f.severity.value,
                "score": f.score,
                "title": f.title,
                "cve": f.cve,
                "kev": f.kev,
                "known_ransomware": f.known_ransomware,
                "epss": f.epss,
            }
            for f in findings
        ],
    }
