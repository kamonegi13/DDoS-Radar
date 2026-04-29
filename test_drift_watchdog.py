"""Tests for radar.calibration.drift_watchdog (Phase F3)."""
import json
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")


@pytest.fixture
def db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    tdb = RadarDB(str(tmp_path / "drift.db"))
    monkeypatch.setattr("radar.calibration.drift_watchdog.db", tdb)
    yield tdb
    tdb.close()


# ── _record_event upsert behavior ──


class TestRecordEvent:
    def test_first_event_creates_row_with_consecutive_runs_1(self, db):
        from radar.calibration.drift_watchdog import DriftEvent, _record_event
        rid = _record_event(DriftEvent(
            scenario_id="taiwan_contingency",
            drift_signal="weight_stale",
            severity="amber",
            target_country="JP",
            formula_ref="test/v1#x",
            sample_n=30,
            why_string="test",
            evidence={"k": "v"},
        ))
        conn = db._get_conn()
        row = conn.execute(
            "SELECT consecutive_runs, ack_state FROM scenario_drift_events WHERE id=?",
            (rid,),
        ).fetchone()
        assert row[0] == 1
        assert row[1] == "unack"

    def test_second_event_within_24h_increments_consecutive_runs(self, db):
        from radar.calibration.drift_watchdog import DriftEvent, _record_event
        ev = DriftEvent(
            scenario_id="middle_east",
            drift_signal="weight_stale",
            severity="amber",
            target_country="IR",
            formula_ref="test/v1",
            sample_n=30,
            why_string="t",
            evidence={},
        )
        _record_event(ev)
        rid2 = _record_event(ev)
        # Should have updated the same row, not created a new one
        conn = db._get_conn()
        row = conn.execute(
            "SELECT consecutive_runs FROM scenario_drift_events WHERE id=?",
            (rid2,),
        ).fetchone()
        assert row[0] == 2
        # Still only one row total
        cnt = conn.execute(
            "SELECT COUNT(*) FROM scenario_drift_events WHERE scenario_id=?",
            ("middle_east",),
        ).fetchone()[0]
        assert cnt == 1


# ── Individual signal detectors ──


class _FakeParticipant:
    def __init__(self, weight, role="primary_target"):
        self.weight = weight
        class _R:
            value = role
        self.role = _R()


class _FakeScenario:
    def __init__(self, sid, participants=None, adversaries=None):
        self.id = sid
        self.participants = participants or {}
        self.adversaries = set(adversaries or [])


class TestWeightStale:
    def test_emits_for_zero_contribution_participant(self, db, monkeypatch):
        monkeypatch.setenv("DRIFT_WEIGHT_STALE_DAYS", "30")
        from radar.calibration.drift_watchdog import _signal_weight_stale
        sc = _FakeScenario(
            "taiwan_contingency",
            participants={"JP": _FakeParticipant(0.7)},
        )
        events = _signal_weight_stale(sc)
        assert len(events) == 1
        assert events[0].target_country == "JP"
        assert events[0].drift_signal == "weight_stale"

    def test_skips_participant_with_observations(self, db, monkeypatch):
        monkeypatch.setenv("DRIFT_WEIGHT_STALE_DAYS", "30")
        from radar.calibration.drift_watchdog import _signal_weight_stale
        # Seed a recent observation for JP
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO sensor_observation_ts (sensor, scope, ts, score) "
                "VALUES ('cf', 'theater:JP', ?, 1.0)",
                (time.time() - 100,),
            )
        sc = _FakeScenario(
            "taiwan_contingency",
            participants={"JP": _FakeParticipant(0.7)},
        )
        events = _signal_weight_stale(sc)
        assert events == []

    def test_skips_zero_weight_participant(self, db):
        from radar.calibration.drift_watchdog import _signal_weight_stale
        sc = _FakeScenario(
            "taiwan_contingency",
            participants={"GU": _FakeParticipant(0.0)},
        )
        events = _signal_weight_stale(sc)
        assert events == []


class TestParticipantOrphan:
    def test_emits_for_country_without_coords(self, db, monkeypatch):
        from radar.calibration import drift_watchdog
        # Stub COUNTRY_COORDS so XX is treated as orphan.
        import radar.config as _cfg
        monkeypatch.setattr(_cfg, "COUNTRY_COORDS", {"JP": {}, "TW": {}, "US": {}})
        sc = _FakeScenario(
            "taiwan_contingency",
            participants={"JP": _FakeParticipant(0.7), "XX": _FakeParticipant(0.5)},
        )
        events = drift_watchdog._signal_participant_orphan(sc)
        assert len(events) == 1
        assert events[0].target_country == "XX"


class TestRunOnce:
    def test_iterates_all_scenarios(self, db, monkeypatch):
        monkeypatch.setenv("DRIFT_WEIGHT_STALE_DAYS", "30")
        from radar.calibration.drift_watchdog import run_once
        result = run_once()
        # Should iterate registered scenarios from scenario_store
        assert isinstance(result, dict)
        # Each scenario gets per-signal counts
        for sid, sigs in result.items():
            assert "weight_stale" in sigs
            assert "adversary_mismatch" in sigs
            assert "recall_underperform" in sigs
            assert "chronic_insufficient" in sigs
            assert "participant_orphan" in sigs


class TestListUnackEvents:
    def test_dwell_time_filters_below_3_runs(self, db):
        from radar.calibration.drift_watchdog import (
            DriftEvent, _record_event, list_unack_events,
        )
        ev = DriftEvent(
            scenario_id="taiwan_contingency",
            drift_signal="weight_stale",
            severity="amber",
            target_country="JP",
            formula_ref="test",
            sample_n=30,
            why_string="t",
            evidence={},
        )
        # First call: consecutive_runs=1
        _record_event(ev)
        out = list_unack_events()
        assert len(out) == 0  # filtered, < 3 runs

        # Second call: consecutive_runs=2
        _record_event(ev)
        out2 = list_unack_events()
        assert len(out2) == 0

        # Third call: consecutive_runs=3 → should now surface
        _record_event(ev)
        out3 = list_unack_events()
        assert len(out3) == 1
        assert out3[0]["consecutive_runs"] >= 3
        assert out3[0]["scenario_id"] == "taiwan_contingency"
