"""Eval harness mechanics, tested offline (a scripted planner + scripted report
generator, no live Ollama) — the same split as `tests/integration/test_orchestrator.py`:
this verifies `run_scenario` wires scripted tools, scoring, and the report pass
correctly, not that a real LLM plays along. The actual benchmark numbers need a real
model and are run manually (see `eval/README.md`), never in CI.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from vigia.agent.llm_client import InvalidPlannerResponse, PlannerToolCall
from vigia.config import Settings
from vigia.eval.lab import LabScenario
from vigia.eval.runner import run_scenario
from vigia.eval.scenarios import all_scenarios


def _dangling_dns_scenario() -> LabScenario:
    return next(s for s in all_scenarios() if s.name == "dangling-dns")


class FakePlanner:
    def __init__(self, script: Sequence[PlannerToolCall | None]) -> None:
        self._script = list(script)

    async def decide(
        self, *, system_prompt: str, user_message: str, tools: list[dict[str, Any]]
    ) -> PlannerToolCall:
        if not self._script:
            raise InvalidPlannerResponse("script exhausted")
        decision = self._script.pop(0)
        if decision is None:
            raise InvalidPlannerResponse("scripted invalid turn")
        return decision


class FakeGenerator:
    def __init__(self, draft: dict[str, Any]) -> None:
        self._payload = json.dumps(draft)

    async def generate(
        self, *, system_prompt: str, user_message: str, json_schema: dict[str, Any]
    ) -> str:
        return self._payload


def _settings() -> Settings:
    return Settings(VIGIA_PLANNER_MODEL="fake-model", VIGIA_EXTRACTOR_MODEL="fake-model")


async def test_dangling_dns_scenario_scores_a_perfect_match() -> None:
    scenario = _dangling_dns_scenario()
    stale_host = f"old-app.{scenario.domain}"

    script = [
        PlannerToolCall(
            tool="ct_subdomains", args={"domain": scenario.domain}, reason="enumerate"
        ),
        PlannerToolCall(tool="advance_phase", reason="done enumerating"),
        PlannerToolCall(tool="advance_phase", reason="nothing to resolve"),
        PlannerToolCall(
            tool="dangling_dns", args={"hostname": stale_host}, reason="check exposure"
        ),
        PlannerToolCall(tool="advance_phase", reason="done with exposure"),
        PlannerToolCall(tool="advance_phase", reason="nothing in email"),
        PlannerToolCall(tool="advance_phase", reason="nothing in leaks"),
        PlannerToolCall(tool="advance_phase", reason="nothing to enrich"),
    ]

    clean_draft = {
        "executive_summary": f"{scenario.domain} has a dangling DNS candidate at {stale_host}.",
        "top_risks": [],
        "findings": [],
        "positive_observations": [],
    }

    result = await run_scenario(
        scenario,
        _settings(),
        "fake-model",
        planner=FakePlanner(script),
        generator=FakeGenerator(clean_draft),
    )

    assert result.scenario == "dangling-dns"
    assert result.scan_status == "completed"
    assert set(result.actual_finding_types) == {"network_info", "dangling_dns_candidate"}
    assert result.metrics.precision == 1.0
    assert result.metrics.recall == 1.0
    assert result.metrics.f1 == 1.0
    assert result.report_dropped_items == 0


async def test_scenario_with_unexpected_planner_behavior_penalizes_precision() -> None:
    """If the scripted tools happen to surface something the scenario didn't expect
    (simulating an agent over-reporting), the score reflects that — this is really a
    test that `score()` is actually wired to real persisted findings, not a stub."""
    scenario = _dangling_dns_scenario()
    # Never calls dangling_dns — only the deterministic SEED whois_asn baseline
    # finding shows up, so recall drops.
    script = [
        PlannerToolCall(tool="advance_phase", reason="skip enumerate"),
        PlannerToolCall(tool="advance_phase", reason="skip resolve"),
        PlannerToolCall(tool="advance_phase", reason="skip exposure"),
        PlannerToolCall(tool="advance_phase", reason="skip email"),
        PlannerToolCall(tool="advance_phase", reason="skip leaks"),
        PlannerToolCall(tool="advance_phase", reason="skip risk"),
    ]
    clean_draft = {
        "executive_summary": f"{scenario.domain} looks fine.",
        "top_risks": [],
        "findings": [],
        "positive_observations": [],
    }

    result = await run_scenario(
        scenario,
        _settings(),
        "fake-model",
        planner=FakePlanner(script),
        generator=FakeGenerator(clean_draft),
    )

    assert result.actual_finding_types == ["network_info"]
    assert result.metrics.recall < 1.0
    assert "dangling_dns_candidate" in result.metrics.false_negatives
