"""Tests for Phase C / D / F1 calibrators.

Coverage scope is intentionally tighter than Phase A/B/F3 since these
phases reuse the governor / ledger patterns established earlier:
verify the integration points work, not the full rule decision tree
(which is unit-tested via the metrics → propose mapping).
"""
import json
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")


@pytest.fixture
def db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    tdb = RadarDB(str(tmp_path / "phase_cdf1.db"))
    for mod_path in (
        "radar.calibration.threshold_history.db",
        "radar.calibration.llm_confidence_calibrator.db",
        "radar.calibration.sensor_disable_proposer.db",
        "radar.calibration.scenario_improver.db",
    ):
        monkeypatch.setattr(mod_path, tdb)
    yield tdb
    tdb.close()


# ── Phase C: llm_confidence_calibrator ──


class TestLLMConfidenceCalibrator:
    def test_skip_on_insufficient_feedback(self, db, monkeypatch):
        monkeypatch.setenv("LLM_CONF_CALIB_MIN_FEEDBACK", "30")
        from radar.calibration.llm_confidence_calibrator import calibrate_sensor
        result = calibrate_sensor("apt_intel")
        assert result.proposed is False
        assert result.rejection_reason == "insufficient_feedback"

    def test_no_action_on_healthy_sensor(self, db, monkeypatch):
        monkeypatch.setenv("LLM_CONF_CALIB_MIN_FEEDBACK", "5")
        # Seed feedback rows that yield healthy recall + precision
        conn = db._get_conn()
        with conn.writing():
            for i in range(20):
                cid = f"c-apt-{i}"
                conn.execute(
                    "INSERT INTO conclusions "
                    "(id, scenario_id, conclusion_type, state, confidence, "
                    " observed_at, formula_ref, threshold_ref, source_urls, "
                    " llm_prompt_sha256, calibration_status, "
                    " conclusion_unavailable_reason, metadata) "
                    "VALUES (?, 'taiwan_contingency', 'threat_level', '3', "
                    "        0.85, ?, 't', '{}', '[]', NULL, '{}', NULL, '{}')",
                    (cid, time.time()),
                )
                conn.execute(
                    "INSERT INTO analyst_feedback "
                    "(conclusion_id, label, observed_outcome_url, analyst_id, "
                    " observed_at, notes) "
                    "VALUES (?, 'TRUE_POSITIVE', NULL, 'auto', ?, NULL)",
                    (cid, time.time()),
                )
                conn.execute(
                    "INSERT INTO llm_intel "
                    "(id, source_type, source_id, theater, ts, status, "
                    " confidence, raw_text, raw_url, headline, llm_fields, "
                    " score_delta, domain, confirmed_by, confirmed_at, "
                    " override_at, created_at, countries, country_weights) "
                    "VALUES (?, 'apt_intel', 'a', 'taiwan_contingency', ?, "
                    "        'confirmed', 0.85, '', '', '', '{}', 0, "
                    "        'cyber', NULL, NULL, NULL, ?, '[]', '{}')",
                    (f"li-{i}", time.time(), time.time()),
                )
        from radar.calibration.llm_confidence_calibrator import calibrate_sensor
        result = calibrate_sensor("apt_intel")
        assert result.rejection_reason in ("no_action_needed", None)


# ── Phase D: sensor_disable_proposer ──


class TestSensorDisableProposer:
    def _seed_call_log(self, db, sensor, n_pre, n_ok=0, n_err=0):
        conn = db._get_conn()
        with conn.writing():
            for outcome, n in (("pre_filter", n_pre), ("ok", n_ok),
                                ("parse_failed", n_err)):
                for _ in range(n):
                    conn.execute(
                        "INSERT INTO llm_call_log "
                        "(ts, caller, model, outcome) VALUES (?, ?, '', ?)",
                        (time.time(), sensor, outcome),
                    )

    def test_alpha_broken_sensor_emits_pending(self, db, monkeypatch):
        monkeypatch.setenv("SENSOR_DISABLE_MIN_CALLS", "100")
        monkeypatch.setenv("SENSOR_DISABLE_ALPHA_PRE_FILTER", "0.95")
        self._seed_call_log(db, "diplomatic", n_pre=200, n_ok=0)
        from radar.calibration.sensor_disable_proposer import (
            propose_disables, list_pending,
        )
        counts = propose_disables()
        assert counts["alpha"] >= 1
        assert counts["new_proposals"] >= 1
        pending = list_pending()
        names = [p["sensor_name"] for p in pending]
        assert "diplomatic" in names

    def test_healthy_sensor_emits_nothing(self, db, monkeypatch):
        monkeypatch.setenv("SENSOR_DISABLE_MIN_CALLS", "100")
        self._seed_call_log(db, "apt_intel", n_pre=0, n_ok=200)
        from radar.calibration.sensor_disable_proposer import propose_disables
        counts = propose_disables()
        assert counts["alpha"] == 0
        assert counts["new_proposals"] == 0

    def test_acknowledge_dismisses_pending(self, db, monkeypatch):
        monkeypatch.setenv("SENSOR_DISABLE_MIN_CALLS", "100")
        self._seed_call_log(db, "ground_osint", n_pre=200)
        from radar.calibration.sensor_disable_proposer import (
            propose_disables, list_pending, acknowledge,
        )
        propose_disables()
        pending = list_pending()
        assert len(pending) >= 1
        prop_id = pending[0]["id"]
        ok = acknowledge(prop_id, by="analyst:test")
        assert ok is True
        # No longer in pending list
        new_pending = list_pending()
        assert all(p["id"] != prop_id for p in new_pending)


# ── Phase F1: scenario_improver ──


class TestScenarioImprover:
    def test_run_once_produces_per_scenario_counts(self, db):
        from radar.calibration.scenario_improver import run_once
        result = run_once()
        assert isinstance(result, dict)
        # Should iterate the registered scenarios and run all 3 rules.
        for sid, rules in result.items():
            assert "weight_too_low" in rules
            assert "weight_too_high" in rules
            assert "missing_participant" in rules

    def test_dedup_blocks_duplicate_within_window(self, db, monkeypatch):
        from radar.calibration.scenario_improver import (
            ProposalEvent, _emit, _has_recent_pending_for,
        )
        ev = ProposalEvent(
            scenario_id="taiwan_contingency",
            proposal_type="weight_too_low",
            target_country="JP",
            suggested_value={"weight": 0.85, "from": 0.7},
            evidence={},
            formula_ref="test",
            sample_n=30,
            why_string="t",
        )
        rid1 = _emit(ev)
        assert rid1 is not None
        # Second emit for same (scenario, rule, target) → dedup
        rid2 = _emit(ev)
        assert rid2 is None

    def test_active_proposal_cap_enforced(self, db, monkeypatch):
        monkeypatch.setenv("SCENARIO_IMPROVER_MAX_ACTIVE", "2")
        from radar.calibration.scenario_improver import (
            ProposalEvent, _emit,
        )
        for i in range(5):
            _emit(ProposalEvent(
                scenario_id="middle_east",
                proposal_type="missing_participant",
                target_country=f"X{i}",
                suggested_value={"weight": 0.3},
                evidence={},
                formula_ref="test",
                sample_n=30,
                why_string="t",
            ))
        from radar.calibration.scenario_improver import list_pending
        pending = list_pending(scenario_id="middle_east")
        assert len(pending) == 2  # capped

    def test_update_state_applies(self, db):
        from radar.calibration.scenario_improver import (
            ProposalEvent, _emit, update_state, list_pending,
        )
        rid = _emit(ProposalEvent(
            scenario_id="korean_peninsula",
            proposal_type="weight_too_low",
            target_country="KP",
            suggested_value={"weight": 0.5},
            evidence={},
            formula_ref="test",
            sample_n=30,
            why_string="t",
        ))
        assert rid is not None
        ok = update_state(rid, new_state="applied", by="analyst:bob")
        assert ok is True
        # No longer pending
        assert all(p["id"] != rid for p in list_pending())
