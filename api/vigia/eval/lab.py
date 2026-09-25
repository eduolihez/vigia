"""Lab scenario definitions and scoring — the "ground truth" half of the benchmark.

A `LabScenario` scripts every tool the agent might call (so no real network call
ever happens) and declares the `Finding.type` values a correctly-behaving agent
should surface by the end of the scan. `score()` compares what actually got
persisted against that expectation as a set (types, not exact counts/content, since
the agent's exact tool-call sequence isn't prescribed — only what it should end up
finding).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from vigia.db.models import ScanMode
from vigia.tools import TOOL_SPECS
from vigia.tools.base import ToolResult

ToolScript = Callable[[dict[str, Any]], ToolResult]


@dataclass
class LabScenario:
    name: str
    description: str
    domain: str
    mode: ScanMode
    tool_scripts: dict[str, ToolScript]
    expected_finding_types: set[str]


@dataclass
class ScenarioMetrics:
    precision: float
    recall: float
    f1: float
    true_positives: list[str]
    false_positives: list[str]
    false_negatives: list[str]


def score(expected: set[str], actual: set[str]) -> ScenarioMetrics:
    tp = expected & actual
    fp = actual - expected
    fn = expected - actual

    precision = (len(tp) / len(actual)) if actual else (1.0 if not expected else 0.0)
    recall = (len(tp) / len(expected)) if expected else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return ScenarioMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        true_positives=sorted(tp),
        false_positives=sorted(fp),
        false_negatives=sorted(fn),
    )


def empty_result(tool: str) -> ToolScript:
    """The default script for a tool a scenario doesn't care about: succeeds, finds
    nothing — the same as a real passive tool finding nothing to report."""

    def _run(args: dict[str, Any]) -> ToolResult:
        return ToolResult(tool=tool, raw_output=b"{}", sha256="lab", duration_ms=1)

    return _run


def default_scripts() -> dict[str, ToolScript]:
    """Every registered tool, scripted to find nothing — the base a scenario
    overrides only the tools relevant to its narrative on top of."""
    return {name: empty_result(name) for name in TOOL_SPECS}
