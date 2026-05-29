"""Tests for scripts/report_recall_metrics.py.

Covers:
- confusion matrix construction from analyst_feedback rows
- recall / precision math (incl. zero-denominator None handling)
- latest-row-wins de-dup per (conclusion_id, analyst_id)
- --exclude-auto drops auto:* rows
- distinct_analysts counts auto sources separately from humans
- empty-scope returns no cells (renderer says "no analyst_feedback rows")
"""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

from radar import config
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    new_conclusion_id,
)
from radar.conclusions.feedback import AnalystFeedback, FeedbackLabel, save_feedback
from radar.conclusions.persistence import save_conclusion
from radar.database import db

import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts"),
)
from report_recall_metrics import collect_metrics, render_text  # noqa: E402


_SCENARIO = "recall_metrics_test_scenario"


def _save_conclusion(suffix: str, *, kind: ConclusionType, state: str = "3") -> Conclusion:
    cid = f"recall_metrics_test_{suffix}_{new_conclusion_id()}"
    c = Conclusion(
        id=cid,
        scenario_id=_SCENARIO,
        conclusion_type=kind,
        state=state,
        confidence=0.7,
        observed_at=time.time(),
        formula_ref="test",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
    )
    save_conclusion(db, c)
    return c


def _save_fb(c: Conclusion, label: FeedbackLabel, analyst: str, observed_at: float) -> None:
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=label, analyst_id=analyst,
        observed_at=observed_at,
    ))


@pytest.fixture(autouse=True)
def cleanup():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM analyst_feedback WHERE conclusion_id LIKE 'recall_metrics_test_%'"
            )
            conn.execute(
                "DELETE FROM conclusions WHERE id LIKE 'recall_metrics_test_%'"
            )
    except Exception:
        pass


def test_confusion_matrix_aggregates_per_scenario_type():
    c1 = _save_conclusion("a", kind=ConclusionType.THREAT_LEVEL)
    c2 = _save_conclusion("b", kind=ConclusionType.THREAT_LEVEL)
    c3 = _save_conclusion("c", kind=ConclusionType.ATTACK_MODE, state="SYNC_DDOS")
    _save_fb(c1, FeedbackLabel.TRUE_POSITIVE, "alice", 1.0)
    _save_fb(c2, FeedbackLabel.FALSE_POSITIVE, "alice", 2.0)
    _save_fb(c3, FeedbackLabel.TRUE_POSITIVE, "alice", 3.0)

    cells = collect_metrics(db, scenario_filter=_SCENARIO)
    by_type = {c.conclusion_type: c for c in cells}
    assert by_type["threat_level"].tp == 1
    assert by_type["threat_level"].fp == 1
    assert by_type["attack_mode"].tp == 1


def test_recall_and_precision_math():
    c1 = _save_conclusion("tp1", kind=ConclusionType.THREAT_LEVEL)
    c2 = _save_conclusion("tp2", kind=ConclusionType.THREAT_LEVEL)
    c3 = _save_conclusion("fn1", kind=ConclusionType.THREAT_LEVEL, state="1")
    c4 = _save_conclusion("fp1", kind=ConclusionType.THREAT_LEVEL)
    _save_fb(c1, FeedbackLabel.TRUE_POSITIVE, "alice", 1.0)
    _save_fb(c2, FeedbackLabel.TRUE_POSITIVE, "alice", 2.0)
    _save_fb(c3, FeedbackLabel.FALSE_NEGATIVE, "alice", 3.0)
    _save_fb(c4, FeedbackLabel.FALSE_POSITIVE, "alice", 4.0)

    cells = collect_metrics(db, scenario_filter=_SCENARIO)
    cell = cells[0]
    # recall = TP / (TP + FN) = 2 / 3
    assert cell.recall == pytest.approx(2 / 3)
    # precision = TP / (TP + FP) = 2 / 3
    assert cell.precision == pytest.approx(2 / 3)


def test_zero_denominator_returns_none_not_zero():
    """Distinguish 'no data' from '0% recall'. None propagates correctly to
    the renderer; 0 would falsely advertise complete failure."""
    c = _save_conclusion("only_tn", kind=ConclusionType.THREAT_LEVEL, state="1")
    _save_fb(c, FeedbackLabel.TRUE_NEGATIVE, "alice", 1.0)
    cells = collect_metrics(db, scenario_filter=_SCENARIO)
    assert cells[0].recall is None
    assert cells[0].precision is None


def test_latest_row_wins_per_analyst_conclusion_pair():
    """Analyst flips their label — only the newer row should count."""
    c = _save_conclusion("flip", kind=ConclusionType.THREAT_LEVEL)
    _save_fb(c, FeedbackLabel.TRUE_POSITIVE, "alice", 1.0)   # initial
    _save_fb(c, FeedbackLabel.FALSE_POSITIVE, "alice", 2.0)  # revised
    cells = collect_metrics(db, scenario_filter=_SCENARIO)
    cell = cells[0]
    assert cell.tp == 0
    assert cell.fp == 1


def test_exclude_auto_drops_auto_rows():
    c = _save_conclusion("autovh", kind=ConclusionType.THREAT_LEVEL)
    _save_fb(c, FeedbackLabel.TRUE_POSITIVE, "alice", 1.0)
    _save_fb(c, FeedbackLabel.FALSE_POSITIVE, "auto:acled", 2.0)

    full = collect_metrics(db, scenario_filter=_SCENARIO)
    assert full[0].tp == 1
    assert full[0].fp == 1

    human_only = collect_metrics(db, scenario_filter=_SCENARIO, exclude_auto=True)
    assert human_only[0].tp == 1
    assert human_only[0].fp == 0


def test_distinct_analysts_counts_auto_sources_as_separate_voters():
    """auto:acled and auto:gdelt must each count as one voter, but not be
    inflated into N voters per source. The convention guards Design W."""
    c = _save_conclusion("multi", kind=ConclusionType.THREAT_LEVEL)
    _save_fb(c, FeedbackLabel.TRUE_POSITIVE, "alice", 1.0)
    _save_fb(c, FeedbackLabel.TRUE_POSITIVE, "auto:acled", 2.0)
    _save_fb(c, FeedbackLabel.TRUE_POSITIVE, "auto:gdelt", 3.0)
    cells = collect_metrics(db, scenario_filter=_SCENARIO)
    assert len(cells[0].distinct_analysts) == 3


def test_empty_scope_returns_no_cells():
    cells = collect_metrics(db, scenario_filter="does_not_exist")
    assert cells == []
    assert "no analyst_feedback rows" in render_text(cells)


def test_render_text_includes_total_row():
    c1 = _save_conclusion("t1", kind=ConclusionType.THREAT_LEVEL)
    c2 = _save_conclusion("t2", kind=ConclusionType.ATTACK_MODE, state="SYNC_DDOS")
    _save_fb(c1, FeedbackLabel.TRUE_POSITIVE, "alice", 1.0)
    _save_fb(c2, FeedbackLabel.FALSE_POSITIVE, "alice", 2.0)
    text = render_text(collect_metrics(db, scenario_filter=_SCENARIO))
    assert "TOTAL" in text
    # TOTAL row should sum across both conclusion_types.
    total_line = [line for line in text.splitlines() if line.startswith("TOTAL")][0]
    assert "   1" in total_line  # at least one TP and one FP visible
