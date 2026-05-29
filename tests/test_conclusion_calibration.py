"""Tests for per-Conclusion calibration_status — ground-truth signal.

Rewritten 2026-05-29 (ADR "real-calibration"). The previous version
validated a shadow-sampler (lite-vs-full divergence) signal that became a
dead no-op once the Phase-9 GLOBAL_SIGNALS_DECOUPLED refactor unified the
score paths (delta ≡ 0 ⇒ always "OK"). calibration_status_for now derives
from the ground-truth confusion matrix (analyst_feedback ⋈ conclusions):

- INSUFFICIENT_DATA when fewer than _MIN_RECALL_SAMPLES observed positives
  (TP+FN) — recall is not yet trustworthy.
- DEGRADED when recall < _DEGRADED_RECALL_THRESHOLD — the tool is missing
  real escalations (NP1 sensitivity floor breached).
- OK when enough positives are observed and recall holds.
- Never raises — DB failures fall back to INSUFFICIENT_DATA (NP3).
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar.conclusions import calibration_status_for
from radar.conclusions import calibration as _calib
from radar.conclusions.base import Conclusion, ConclusionType
from radar.conclusions.feedback import AnalystFeedback, FeedbackLabel, save_feedback
from radar.conclusions.persistence import save_conclusion
from radar.database import db

_NOW = time.time()


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    _calib.invalidate_cache()
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM analyst_feedback WHERE conclusion_id LIKE 'calib-test-%'"
            )
            conn.execute("DELETE FROM conclusions WHERE id LIKE 'calib-test-%'")
    except Exception:
        pass
    _calib.invalidate_cache()


def _seed(scenario_id: str, labels: list[str], *, observed_at: float | None = None):
    """Create one THREAT_LEVEL conclusion per label and attach that label
    as an auto-feedback row. Returns nothing; calibration_status_for reads
    them back via the confusion-matrix query."""
    observed_at = observed_at if observed_at is not None else _NOW - 3600
    for i, label in enumerate(labels):
        cid = "calib-test-" + uuid.uuid4().hex[:12]
        save_conclusion(db, Conclusion(
            id=cid,
            scenario_id=scenario_id,
            conclusion_type=ConclusionType.THREAT_LEVEL,
            state="3",
            confidence=0.8,
            observed_at=observed_at,
            formula_ref="test",
            threshold_ref={},
            source_urls=(),
            calibration_status={},
            final_judgment_disclaimer="test",
            metadata={},
        ))
        save_feedback(db, AnalystFeedback(
            conclusion_id=cid,
            label=FeedbackLabel(label),
            analyst_id=f"auto:test{i}",
            observed_at=observed_at,
            observed_outcome_url=None,
            notes="test",
        ))


def _sid() -> str:
    return "test_calib_" + uuid.uuid4().hex[:8]


def test_insufficient_data_when_no_labels():
    status = calibration_status_for(db, _sid())
    assert status["status"] == "INSUFFICIENT_DATA"
    assert status["sample_n"] == 0
    assert status["recall"] is None
    assert status["source"] == "ground_truth"


def test_insufficient_data_when_too_few_positives():
    sid = _sid()
    # 3 positives (< _MIN_RECALL_SAMPLES = 5) → recall not yet trustworthy
    _seed(sid, ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_NEGATIVE"])
    status = calibration_status_for(db, sid)
    assert status["status"] == "INSUFFICIENT_DATA"


def test_ok_when_recall_holds():
    sid = _sid()
    # 9 TP + 1 FN → recall 0.9 ≥ 0.70 floor
    _seed(sid, ["TRUE_POSITIVE"] * 9 + ["FALSE_NEGATIVE"])
    status = calibration_status_for(db, sid)
    assert status["status"] == "OK"
    assert status["recall"] == 0.9
    assert status["fn"] == 1
    assert status["tp"] == 9


def test_degraded_when_recall_below_floor():
    sid = _sid()
    # 3 TP + 7 FN → recall 0.30 < 0.70 floor → DEGRADED (tool is missing
    # real escalations — exactly what the dead shadow sampler could not flag)
    _seed(sid, ["TRUE_POSITIVE"] * 3 + ["FALSE_NEGATIVE"] * 7)
    status = calibration_status_for(db, sid)
    assert status["status"] == "DEGRADED"
    assert status["recall"] == 0.3
    assert status["fn"] == 7


def test_precision_reported_but_does_not_drive_status():
    sid = _sid()
    # 6 TP + 4 FP, zero FN → recall 1.0 (OK), precision 0.6
    _seed(sid, ["TRUE_POSITIVE"] * 6 + ["FALSE_POSITIVE"] * 4)
    status = calibration_status_for(db, sid)
    assert status["status"] == "OK"
    assert status["recall"] == 1.0
    assert status["precision"] == 0.6


def test_true_negatives_alone_stay_insufficient():
    sid = _sid()
    # Only TN/FP → no observed positives → recall undefined → INSUFFICIENT
    _seed(sid, ["TRUE_NEGATIVE"] * 6 + ["FALSE_POSITIVE"] * 2)
    status = calibration_status_for(db, sid)
    assert status["status"] == "INSUFFICIENT_DATA"
    assert status["recall"] is None


def test_never_raises_on_bad_db(monkeypatch):
    class _Boom:
        def _get_conn(self):
            raise RuntimeError("db down")
    status = calibration_status_for(_Boom(), "test_calib_boom")
    assert status["status"] == "INSUFFICIENT_DATA"
    assert status["source"] == "ground_truth"


def test_cache_returns_same_until_invalidated():
    sid = _sid()
    _seed(sid, ["TRUE_POSITIVE"] * 9 + ["FALSE_NEGATIVE"])
    first = calibration_status_for(db, sid)
    assert first["fn"] == 1
    # Add more FN; without invalidation the cached snapshot is returned.
    _seed(sid, ["FALSE_NEGATIVE"] * 5)
    cached = calibration_status_for(db, sid)
    assert cached["fn"] == 1  # stale (cache hit)
    _calib.invalidate_cache(sid)
    fresh = calibration_status_for(db, sid)
    assert fresh["fn"] == 6
