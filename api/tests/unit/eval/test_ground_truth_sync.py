"""Guards against `eval/ground_truth/*.json` drifting from `scenarios.py` — those
JSON files are the human-readable "ground truth" artifact the brief asks for
(eval/ directory: "Benchmark lab, ground truth, results"); this keeps them honest
rather than letting them go stale as documentation nobody re-generates.
"""

from __future__ import annotations

import json
from pathlib import Path

from vigia.eval.scenarios import all_scenarios

GROUND_TRUTH_DIR = Path(__file__).resolve().parents[4] / "eval" / "ground_truth"


def test_every_scenario_has_a_ground_truth_file() -> None:
    for scenario in all_scenarios():
        path = GROUND_TRUTH_DIR / f"{scenario.name}.json"
        assert path.exists(), f"missing {path}"

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["name"] == scenario.name
        assert data["domain"] == scenario.domain
        assert data["mode"] == scenario.mode.value
        assert sorted(data["expected_finding_types"]) == sorted(scenario.expected_finding_types)


def test_no_orphaned_ground_truth_files() -> None:
    scenario_names = {s.name for s in all_scenarios()}
    for path in GROUND_TRUTH_DIR.glob("*.json"):
        assert path.stem in scenario_names, f"{path} has no matching scenario"
