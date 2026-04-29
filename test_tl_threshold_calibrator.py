"""Tests for radar.calibration.tl_threshold_calibrator (Phase B)."""
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")


@pytest.fixture
def db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    tdb = RadarDB(str(tmp_path / "tlc.db"))
    monkeypatch.setattr("radar.calibration.threshold_history.db", tdb)
    monkeypatch.setattr("radar.calibration.tl_threshold_calibrator.db", tdb)
    yield tdb
    tdb.close()


def _seed_feedback(db, scenario_id, label, n):
    """Insert n analyst_feedback rows of given label for the scenario.

    Each feedback row needs a corresponding conclusion row (FK
    constraint). We create unique conclusion ids per feedback insertion.
    """
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        for i in range(n):
            cid = f"c-{scenario_id}-{label}-{i}-{time.time_ns()}"
            conn.execute(
                "INSERT INTO conclusions "
                "(id, scenario_id, conclusion_type, state, confidence, "
                " observed_at, formula_ref, threshold_ref, source_urls, "
                " llm_prompt_sha256, calibration_status, "
                " conclusion_unavailable_reason, metadata) "
                "VALUES (?, ?, 'threat_level', '3', 0.85, ?, "
                "        'test', '{}', '[]', NULL, '{}', NULL, '{}')",
                (cid, scenario_id, time.time()),
            )
            conn.execute(
                "INSERT INTO analyst_feedback "
                "(conclusion_id, label, observed_outcome_url, analyst_id, "
                " observed_at, notes) "
                "VALUES (?, ?, NULL, 'auto:test', ?, NULL)",
                (cid, label, time.time()),
            )


class TestCalibratorInsufficientData:
    def test_skip_when_feedback_below_min(self, db, monkeypatch):
        monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "30")
        _seed_feedback(db, "taiwan_contingency", "TRUE_POSITIVE", 5)
        from radar.calibration.tl_threshold_calibrator import calibrate_scenario
        result = calibrate_scenario("taiwan_contingency")
        assert result.proposals_submitted == 0
        assert "insufficient_feedback" in result.rejection_reasons


class TestCalibratorRecallOK:
    def test_no_action_when_metrics_healthy(self, db, monkeypatch):
        monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
        _seed_feedback(db, "taiwan_contingency", "TRUE_POSITIVE", 50)
        # No FN, no FP → recall=1.0, precision=1.0 → no action.
        from radar.calibration.tl_threshold_calibrator import calibrate_scenario
        result = calibrate_scenario("taiwan_contingency")
        assert result.proposals_submitted == 0
        assert "no_action_needed" in result.rejection_reasons


class TestCalibratorLowRecall:
    def test_proposes_loosening_when_recall_low(self, db, monkeypatch):
        monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
        monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "10")
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
        from radar.calibration import auto_tune_governor
        monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red", lambda: False)
        # Heavy FN load → recall drops below 0.8
        _seed_feedback(db, "taiwan_contingency", "TRUE_POSITIVE", 10)
        _seed_feedback(db, "taiwan_contingency", "FALSE_NEGATIVE", 30)
        from radar.calibration.tl_threshold_calibrator import calibrate_scenario
        result = calibrate_scenario("taiwan_contingency")
        # Proposals submitted (one per band) — accepted by governor.
        assert result.proposals_submitted == 5
        assert result.proposals_accepted == 5
        # Verify the ledger now has loosened thresholds for taiwan_contingency.
        from radar.calibration import threshold_history
        rec = threshold_history.latest(
            "tl_thresholds.taiwan_contingency.tl1_total",
            scope_scenario_id="taiwan_contingency",
        )
        assert rec is not None
        # Default 9.0 → loosened by 5% → 8.55
        assert rec.value == pytest.approx(9.0 * 0.95)


class TestCalibratorLowPrecision:
    def test_proposes_tightening_when_precision_low(self, db, monkeypatch):
        monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
        monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "10")
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
        monkeypatch.setenv("TL_CALIB_PRECISION_CEILING", "0.30")
        from radar.calibration import auto_tune_governor
        monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red", lambda: False)
        # Recall=1.0 (no FN), but heavy FP → precision << 0.30
        _seed_feedback(db, "middle_east", "TRUE_POSITIVE", 5)
        _seed_feedback(db, "middle_east", "FALSE_POSITIVE", 50)
        from radar.calibration.tl_threshold_calibrator import calibrate_scenario
        result = calibrate_scenario("middle_east")
        assert result.proposals_submitted == 5
        assert result.proposals_accepted == 5
        from radar.calibration import threshold_history
        rec = threshold_history.latest(
            "tl_thresholds.middle_east.tl1_total",
            scope_scenario_id="middle_east",
        )
        assert rec is not None
        # Default 9.0 → tightened by 5% → 9.45
        assert rec.value == pytest.approx(9.0 * 1.05)


class TestCalibratorRecallGateBlocks:
    def test_recall_red_blocks_all_proposals(self, db, monkeypatch):
        monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
        monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "10")
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
        from radar.calibration import auto_tune_governor
        monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red", lambda: True)
        _seed_feedback(db, "taiwan_contingency", "TRUE_POSITIVE", 10)
        _seed_feedback(db, "taiwan_contingency", "FALSE_NEGATIVE", 30)
        from radar.calibration.tl_threshold_calibrator import calibrate_scenario
        result = calibrate_scenario("taiwan_contingency")
        assert result.proposals_submitted == 5
        assert result.proposals_accepted == 0
        assert result.proposals_rejected == 5
        assert "recall_red" in result.rejection_reasons


class TestCalibrateAllScenarios:
    def test_iterates_all_scenarios_independently(self, db, monkeypatch):
        monkeypatch.setenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "10")
        # Seed only one scenario; others should return insufficient_feedback
        # without crashing.
        _seed_feedback(db, "taiwan_contingency", "TRUE_POSITIVE", 50)
        from radar.calibration.tl_threshold_calibrator import calibrate_all_scenarios
        out = calibrate_all_scenarios()
        # 5 scenarios in geo_data.json
        assert len(out) >= 4
        assert "taiwan_contingency" in out
