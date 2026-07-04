"""Tests for Phase 2 — tl_calibrator rejection_reason differentiation
(problem 50, 2026-04-30 PM).

Pre-fix: when the Phase H degenerate-data guard fired, the calibrator
returned `rejection_reasons={'no_action_needed': 1}`. This was
indistinguishable from the genuine "recall OK and precision OK → no
action" case. Analysts could not tell whether the calibrator was
healthy-and-quiet or guard-blocked.

Phase 2 fix differentiates the two:
  * 'no_action_needed'    — recall ≥ floor AND precision OK
  * 'degenerate_data_guard' — Phase H guard fired (tn=0, fn=0,
                              precision below floor+0.20)
  * 'insufficient_feedback' — total < min_feedback_per_cell (existing)
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")


def _stub_metrics(monkeypatch, metrics: dict):
    """Replace _read_recall_for_scenario with a function returning the
    given metrics dict, so we exercise the calibrator's branching logic
    without touching the DB."""
    from radar.calibration import tl_threshold_calibrator as tc
    monkeypatch.setattr(tc, "_read_recall_for_scenario",
                        lambda scenario_id: metrics)


def test_no_action_when_recall_and_precision_ok(monkeypatch):
    """recall=1.0, precision=0.95 (with tn>0) → 'no_action_needed'."""
    _stub_metrics(monkeypatch, {
        "tp": 200, "fp": 10, "fn": 0, "tn": 50,
        "total": 260, "recall": 1.0, "precision": 0.952,
    })
    from radar.calibration.tl_threshold_calibrator import calibrate_scenario
    result = calibrate_scenario("test_no_action")
    assert result.proposals_submitted == 0
    assert result.rejection_reasons == {"no_action_needed": 1}


def test_degenerate_data_guard_fires_for_tn0_fn0_low_precision(monkeypatch):
    """tn=0, fn=0, precision=0.25 → 'degenerate_data_guard'.

    This was the production state for taiwan_contingency before
    Phase H. Without the guard, the calibrator would have tightened
    5 thresholds based on a degenerate measurement.
    """
    _stub_metrics(monkeypatch, {
        "tp": 167, "fp": 497, "fn": 0, "tn": 0,
        "total": 664, "recall": 1.0, "precision": 0.2515,
    })
    from radar.calibration.tl_threshold_calibrator import calibrate_scenario
    result = calibrate_scenario("test_degenerate")
    assert result.proposals_submitted == 0
    assert result.rejection_reasons == {"degenerate_data_guard": 1}


def test_insufficient_feedback_path_unchanged(monkeypatch):
    """Sample size below min still returns 'insufficient_feedback'."""
    # _read_recall_for_scenario itself returns None when total<min,
    # so we mimic that path by stubbing.
    _stub_metrics(monkeypatch, None)
    from radar.calibration.tl_threshold_calibrator import calibrate_scenario
    result = calibrate_scenario("test_insufficient")
    assert result.proposals_submitted == 0
    assert result.rejection_reasons == {"insufficient_feedback": 1}


def test_loosening_path_unaffected_by_guard(monkeypatch):
    """recall=0.5 → direction='looser', NOT the no-action paths.

    The Phase H guard only fires on the tighten branch; the loosen
    branch (recall floor breach) must remain functional.
    """
    _stub_metrics(monkeypatch, {
        "tp": 50, "fp": 5, "fn": 50, "tn": 100,
        "total": 205, "recall": 0.5, "precision": 0.91,
    })
    monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
    monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "10")
    monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
    from radar.calibration import auto_tune_governor
    monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red",
                        lambda: False)
    from radar.calibration.tl_threshold_calibrator import calibrate_scenario
    result = calibrate_scenario("test_loosen")
    # We don't care about acceptance ratio (governor may reject) —
    # just that 'no_action_needed' / 'degenerate_data_guard' are NOT
    # the rejection_reasons (because direction was 'looser').
    assert "no_action_needed" not in result.rejection_reasons
    assert "degenerate_data_guard" not in result.rejection_reasons


def test_precision_min_floor_env_override(monkeypatch):
    """Setting TL_CALIB_PRECISION_MIN_FLOOR=0.05 lowers the threshold
    so precision=0.20 (still above floor+0.20=0.25) is NOT degenerate."""
    _stub_metrics(monkeypatch, {
        "tp": 100, "fp": 400, "fn": 0, "tn": 0,
        "total": 500, "recall": 1.0, "precision": 0.20,
    })
    # Default: 0.10, so floor+0.20=0.30. precision=0.20 < 0.30 → degenerate.
    from radar.calibration.tl_threshold_calibrator import calibrate_scenario
    result = calibrate_scenario("test_envA")
    assert result.rejection_reasons == {"degenerate_data_guard": 1}

    # Override: 0.05, so floor+0.20=0.25. precision=0.20 < 0.25 → still degenerate.
    monkeypatch.setenv("TL_CALIB_PRECISION_MIN_FLOOR", "0.05")
    result = calibrate_scenario("test_envB")
    assert result.rejection_reasons == {"degenerate_data_guard": 1}

    # Override: 0.00, so floor+0.20=0.20. precision=0.20 NOT strictly less. → tighten.
    monkeypatch.setenv("TL_CALIB_PRECISION_MIN_FLOOR", "0.00")
    monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
    monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "10")
    monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
    from radar.calibration import auto_tune_governor
    monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red",
                        lambda: False)
    result = calibrate_scenario("test_envC")
    # With precision EQUAL to floor+0.20, is_degenerate = (0.20 < 0.20) = False.
    # So direction='tighter' (recall=1.0, precision<0.30 ceiling).
    assert "degenerate_data_guard" not in result.rejection_reasons


# ── evidence-freshness gate (2026-07-04, runaway-loop fix) ────────────────
#
# Production audit 2026-07-03/04: the calibrator re-applied a -5% loosening
# to all middle_east bands 12 times between 05-30 and 07-02, every pass
# driven by the SAME frozen evidence (fn=54, recall 0.798, last label
# 2026-05-29). Root cause: _read_recall_for_scenario aggregates all-time
# labels with no freshness requirement, so one stale low-recall cell keeps
# justifying step after step. The gate requires at least one label NEWER
# than the calibrator's own last applied change before it may act again.


def test_freshness_gate_blocks_reapplying_stale_evidence(monkeypatch):
    from radar.calibration import tl_threshold_calibrator as tc
    _stub_metrics(monkeypatch, {
        "tp": 213, "fp": 25, "fn": 54, "tn": 0,
        "total": 292, "recall": 0.798, "precision": 0.895,
        "last_label_at": 1_000_000.0,
    })
    # Calibrator already applied a change AFTER the newest label.
    monkeypatch.setattr(tc, "_last_applied_at", lambda _sid: 1_000_500.0)
    result = tc.calibrate_scenario("test_stale_evidence")
    assert result.proposals_submitted == 0
    assert "no_new_evidence" in result.rejection_reasons


def test_freshness_gate_allows_action_on_new_evidence(monkeypatch):
    from radar.calibration import auto_tune_governor
    from radar.calibration import tl_threshold_calibrator as tc
    _stub_metrics(monkeypatch, {
        "tp": 20, "fp": 2, "fn": 30, "tn": 0,
        "total": 52, "recall": 0.40, "precision": 0.90,
        "last_label_at": 2_000_000.0,
    })
    monkeypatch.setattr(tc, "_last_applied_at", lambda _sid: 1_000_000.0)
    monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
    monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "10")
    monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
    monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red",
                        lambda: False)
    result = tc.calibrate_scenario("test_fresh_evidence")
    assert result.proposals_submitted > 0


def test_freshness_gate_permissive_when_no_prior_change(monkeypatch):
    """First-ever calibration for a scenario (no threshold_history rows)
    must not be blocked by the gate."""
    from radar.calibration import auto_tune_governor
    from radar.calibration import tl_threshold_calibrator as tc
    _stub_metrics(monkeypatch, {
        "tp": 20, "fp": 2, "fn": 30, "tn": 0,
        "total": 52, "recall": 0.40, "precision": 0.90,
        "last_label_at": 2_000_000.0,
    })
    monkeypatch.setattr(tc, "_last_applied_at", lambda _sid: None)
    monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
    monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "10")
    monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
    monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red",
                        lambda: False)
    result = tc.calibrate_scenario("test_first_calibration")
    assert result.proposals_submitted > 0
