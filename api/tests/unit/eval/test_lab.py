from __future__ import annotations

from vigia.eval.lab import score


def test_perfect_match_scores_1_0() -> None:
    m = score({"a", "b"}, {"a", "b"})
    assert (m.precision, m.recall, m.f1) == (1.0, 1.0, 1.0)
    assert m.false_positives == []
    assert m.false_negatives == []


def test_clean_scenario_no_expected_no_actual_scores_1_0() -> None:
    m = score(set(), set())
    assert (m.precision, m.recall, m.f1) == (1.0, 1.0, 1.0)


def test_hallucinated_finding_on_clean_domain_penalizes_precision() -> None:
    m = score(set(), {"phantom_finding"})
    assert m.precision == 0.0
    assert m.recall == 1.0  # vacuously — nothing was expected
    assert m.f1 == 0.0
    assert m.false_positives == ["phantom_finding"]


def test_missed_finding_penalizes_recall() -> None:
    m = score({"dmarc_missing"}, set())
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0
    assert m.false_negatives == ["dmarc_missing"]


def test_partial_overlap() -> None:
    m = score({"a", "b"}, {"a", "c"})
    assert m.true_positives == ["a"]
    assert m.false_positives == ["c"]
    assert m.false_negatives == ["b"]
    assert m.precision == 0.5
    assert m.recall == 0.5
    assert m.f1 == 0.5
