"""Benchmark runner: drives a real `AgentOrchestrator` (real planner LLM via
Ollama, real orchestrator/risk/report-writer code) through each lab scenario, with
every tool call scripted (`vigia.eval.lab`/`scenarios`) rather than a real network
request — nothing here ever touches a real domain (brief rule 6). Needs a running
Ollama instance; not run in CI (same reason `vigia scan --agent` isn't — see
CLAUDE.md's "manual verification" note).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlmodel import col

from vigia.agent import ownership, tool_router
from vigia.agent.llm_client import (
    OllamaStructuredGenerator,
    Planner,
    PlannerClient,
    StructuredGenerator,
)
from vigia.agent.orchestrator import AgentOrchestrator, resolve_planner
from vigia.config import Settings
from vigia.db.models import Finding, Scan, ScanMode, ScanStatus
from vigia.db.session import session_scope
from vigia.ethics import accept as accept_ethics
from vigia.eval.lab import LabScenario, ScenarioMetrics, ToolScript, score
from vigia.report.writer import generate_report
from vigia.tools import base as tools_base

RESULTS_DIR = Path(__file__).resolve().parents[3] / "eval" / "results"


@dataclass
class ScenarioResult:
    scenario: str
    description: str
    domain: str
    mode: str
    scan_status: str
    step_count: int
    duration_seconds: float
    metrics: ScenarioMetrics
    actual_finding_types: list[str]
    report_dropped_items: int
    report_attempts_used: int


@dataclass
class BenchmarkReport:
    generated_at: str
    planner_model: str
    scenarios: list[ScenarioResult]
    mean_precision: float
    mean_recall: float
    mean_f1: float
    total_report_dropped_items: int


def _wrap(fn: ToolScript) -> tool_router.Invoker:
    async def _invoke(args: dict[str, Any], ctx: tool_router.ToolContext) -> tools_base.ToolResult:
        return fn(args)

    return _invoke


@contextmanager
def _patched_invokers(scripts: dict[str, ToolScript]) -> Iterator[None]:
    original = dict(tool_router.INVOKERS)
    tool_router.INVOKERS.update({name: _wrap(fn) for name, fn in scripts.items()})
    try:
        yield
    finally:
        tool_router.INVOKERS.clear()
        tool_router.INVOKERS.update(original)


@asynccontextmanager
async def _patched_ownership_verification() -> AsyncIterator[None]:
    """Active-mode scenarios need `Scan.verified` to become True — but a real DNS TXT
    lookup would need a real domain (brief rule 6), so this patches the check itself
    to a synthetic always-true stand-in for the duration of one scenario run, the
    same technique `tests/integration/test_orchestrator.py`'s active-mode tests use.
    """
    original = ownership.verify_ownership

    async def _always_verified(domain: str, expected_token: str) -> bool:
        return True

    ownership.verify_ownership = _always_verified
    try:
        yield
    finally:
        ownership.verify_ownership = original


async def run_scenario(
    scenario: LabScenario,
    settings: Settings,
    planner_model: str,
    *,
    planner: Planner | None = None,
    generator: StructuredGenerator | None = None,
) -> ScenarioResult:
    """`planner`/`generator` default to real Ollama-backed clients; tests pass
    scripted fakes so the harness's own mechanics (scripted tools, scoring, report
    pass) are verified offline, the same way `tests/integration/test_orchestrator.py`
    tests the orchestrator itself without a live model."""
    import time

    async with session_scope() as session:
        await accept_ethics(session)

        verification_token = (
            ownership.generate_token() if scenario.mode == ScanMode.ACTIVE else None
        )
        scan = Scan(
            domain=scenario.domain,
            mode=scenario.mode,
            verification_token=verification_token,
            planner_model=planner_model,
            extractor_model=settings.extractor_model,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)

        start = time.monotonic()
        async with httpx.AsyncClient() as client:
            actual_planner = planner or PlannerClient(
                host=settings.ollama_host, model=planner_model
            )
            orch = AgentOrchestrator(session, scan, settings, client, actual_planner)
            with _patched_invokers(scenario.tool_scripts):
                if scenario.mode == ScanMode.ACTIVE:
                    async with _patched_ownership_verification():
                        async for _ in orch.run():
                            pass
                else:
                    async for _ in orch.run():
                        pass
        duration = time.monotonic() - start

        findings = (
            (await session.execute(select(Finding).where(col(Finding.scan_id) == scan.id)))
            .scalars()
            .all()
        )
        actual_types = {f.type for f in findings}
        metrics = score(scenario.expected_finding_types, actual_types)

        # Report Writer pass against the scan's own evidence — doubles as a
        # no-invented-entities check (brief section 7.3) across every scenario.
        actual_generator = generator or OllamaStructuredGenerator(
            host=settings.ollama_host, model=planner_model
        )
        report_result = await generate_report(session, scan, actual_generator)

        return ScenarioResult(
            scenario=scenario.name,
            description=scenario.description,
            domain=scenario.domain,
            mode=scenario.mode.value,
            scan_status=scan.status.value,
            step_count=orch.step_count,
            duration_seconds=duration,
            metrics=metrics,
            actual_finding_types=sorted(actual_types),
            report_dropped_items=len(report_result.dropped_items),
            report_attempts_used=report_result.attempts_used,
        )


async def run_all(
    scenarios: list[LabScenario], settings: Settings, model_override: str | None = None
) -> BenchmarkReport:
    planner_model = await resolve_planner(settings, model_override)

    results = [await run_scenario(scenario, settings, planner_model) for scenario in scenarios]

    n = len(results) or 1
    return BenchmarkReport(
        generated_at=datetime.now(UTC).isoformat(),
        planner_model=planner_model,
        scenarios=results,
        mean_precision=sum(r.metrics.precision for r in results) / n,
        mean_recall=sum(r.metrics.recall for r in results) / n,
        mean_f1=sum(r.metrics.f1 for r in results) / n,
        total_report_dropped_items=sum(r.report_dropped_items for r in results),
    )


def _report_to_dict(report: BenchmarkReport) -> dict[str, Any]:
    return {
        "generated_at": report.generated_at,
        "planner_model": report.planner_model,
        "mean_precision": report.mean_precision,
        "mean_recall": report.mean_recall,
        "mean_f1": report.mean_f1,
        "total_report_dropped_items": report.total_report_dropped_items,
        "scenarios": [
            {
                "scenario": r.scenario,
                "description": r.description,
                "domain": r.domain,
                "mode": r.mode,
                "scan_status": r.scan_status,
                "step_count": r.step_count,
                "duration_seconds": r.duration_seconds,
                "precision": r.metrics.precision,
                "recall": r.metrics.recall,
                "f1": r.metrics.f1,
                "true_positives": r.metrics.true_positives,
                "false_positives": r.metrics.false_positives,
                "false_negatives": r.metrics.false_negatives,
                "actual_finding_types": r.actual_finding_types,
                "report_dropped_items": r.report_dropped_items,
                "report_attempts_used": r.report_attempts_used,
            }
            for r in report.scenarios
        ],
    }


def write_report(report: BenchmarkReport) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = report.generated_at.replace(":", "-") + ".json"
    path = RESULTS_DIR / filename
    path.write_text(json.dumps(_report_to_dict(report), indent=2), encoding="utf-8")
    return path
