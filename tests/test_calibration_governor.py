"""Tests for radar.calibration — Phase A foundation.

Covers threshold_history ledger and auto_tune_governor safety rules.
"""
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")


@pytest.fixture
def db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    tdb = RadarDB(str(tmp_path / "calib.db"))
    monkeypatch.setattr("radar.calibration.threshold_history.db", tdb)
    # Isolation: the auto-apply tier gate reads its own module-global DB
    # (the real radar.db), not this tmp fixture, so its verdict would
    # otherwise depend on production tier state and reject every commit with
    # reason='tier_gate'. The tier gate has dedicated coverage in
    # test_auto_apply_tier_governor.py; neutralise it here so the cooldown /
    # magnitude / unchanged rules can be exercised in isolation.
    monkeypatch.setattr(
        "radar.calibration.auto_apply_tier_governor.is_apply_allowed",
        lambda *a, **k: True,
    )
    yield tdb
    tdb.close()


def _proposal(**kw):
    from radar.calibration.auto_tune_governor import Proposal
    base = dict(
        key="tl_thresholds.tl4",
        new_value=9.0,
        scope_scenario_id=None,
        derived_from="test_calibrator/v1",
        applied_by="auto:test",
        sample_n=50,
        formula_ref="test_calibrator/v1#test",
        evidence={},
    )
    base.update(kw)
    return Proposal(**base)


# ── threshold_history ──


class TestThresholdHistory:
    def test_record_change_returns_row_id(self, db):
        from radar.calibration import threshold_history
        rid = threshold_history.record_change(
            key="tl_thresholds.tl4",
            value=9.0,
            scope_scenario_id=None,
            derived_from="test/v1",
            applied_by="auto:test",
            sample_n=50,
            formula_ref="test/v1#first",
        )
        assert rid > 0
        rec = threshold_history.latest("tl_thresholds.tl4")
        assert rec is not None
        assert rec.value == 9.0
        assert rec.state == "active"

    def test_value_at_returns_active_at_timestamp(self, db):
        from radar.calibration import threshold_history
        # Two rows: t=1000 (value=8.0), t=2000 (value=9.0)
        threshold_history.record_change(
            key="tl_thresholds.tl4", value=8.0, scope_scenario_id=None,
            derived_from="test", applied_by="auto:test", sample_n=50,
            formula_ref="test", effective_from=1000.0,
        )
        threshold_history.record_change(
            key="tl_thresholds.tl4", value=9.0, scope_scenario_id=None,
            derived_from="test", applied_by="auto:test", sample_n=50,
            formula_ref="test", effective_from=2000.0,
        )
        # Query at t=1500 should see 8.0 (the active row at that time).
        rec = threshold_history.value_at("tl_thresholds.tl4", ts=1500.0)
        assert rec is not None
        assert rec.value == 8.0
        # Query at t=2500 should see 9.0.
        rec2 = threshold_history.value_at("tl_thresholds.tl4", ts=2500.0)
        assert rec2.value == 9.0

    def test_supersedes_prior_active_row(self, db):
        from radar.calibration import threshold_history
        threshold_history.record_change(
            key="x", value=1.0, scope_scenario_id=None,
            derived_from="test", applied_by="auto:test", sample_n=50,
            formula_ref="test", effective_from=1000.0,
        )
        threshold_history.record_change(
            key="x", value=2.0, scope_scenario_id=None,
            derived_from="test", applied_by="auto:test", sample_n=50,
            formula_ref="test", effective_from=2000.0,
        )
        recs = threshold_history.list_recent(hours=999999)
        assert len(recs) == 2
        active = [r for r in recs if r.state == "active"]
        superseded = [r for r in recs if r.state == "superseded"]
        assert len(active) == 1
        assert len(superseded) == 1
        assert active[0].value == 2.0
        assert superseded[0].value == 1.0
        # Prior row's effective_to closes at the new row's effective_from.
        assert superseded[0].effective_to == 2000.0

    def test_scenario_scope_overrides_global(self, db):
        from radar.calibration import threshold_history
        threshold_history.record_change(
            key="tl4", value=9.0, scope_scenario_id=None,
            derived_from="t", applied_by="auto:test", sample_n=50,
            formula_ref="t", effective_from=1000.0,
        )
        threshold_history.record_change(
            key="tl4", value=8.5, scope_scenario_id="taiwan_contingency",
            derived_from="t", applied_by="auto:test", sample_n=50,
            formula_ref="t", effective_from=1500.0,
        )
        rec = threshold_history.value_at(
            "tl4", scope_scenario_id="taiwan_contingency", ts=2000.0,
        )
        assert rec.value == 8.5
        rec_other = threshold_history.value_at(
            "tl4", scope_scenario_id="korean_peninsula", ts=2000.0,
        )
        assert rec_other.value == 9.0

    def test_revert_creates_new_row_with_prior_value(self, db):
        from radar.calibration import threshold_history
        rid1 = threshold_history.record_change(
            key="x", value=1.0, scope_scenario_id=None,
            derived_from="t", applied_by="auto:test", sample_n=50,
            formula_ref="t",
        )
        rid2 = threshold_history.record_change(
            key="x", value=2.0, scope_scenario_id=None,
            derived_from="t", applied_by="auto:test", sample_n=50,
            formula_ref="t", revertible_to_id=rid1,
        )
        rid3 = threshold_history.revert(rid2, reverted_by="analyst:alice")
        assert rid3 is not None
        active = threshold_history.latest("x")
        assert active.value == 1.0
        assert active.applied_by == "analyst:alice"


# ── auto_tune_governor ──


class TestGovernorSampleSize:
    def test_rejects_low_sample(self, db, monkeypatch):
        monkeypatch.setenv("AUTO_TUNE_MIN_SAMPLE_N", "30")
        # Disable recall gate for this test
        from radar.calibration import auto_tune_governor as gov
        monkeypatch.setattr(gov, "_recall_gate_is_red", lambda: False)
        outcome = gov.commit(_proposal(sample_n=10))
        assert not outcome.accepted
        assert outcome.reason == "sample_too_small"


class TestGovernorCooldown:
    def test_blocks_re_tune_within_cooldown(self, db, monkeypatch):
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "72")
        from radar.calibration import auto_tune_governor as gov
        monkeypatch.setattr(gov, "_recall_gate_is_red", lambda: False)

        outcome1 = gov.commit(_proposal(new_value=9.0))
        assert outcome1.accepted

        outcome2 = gov.commit(_proposal(new_value=9.5))
        assert not outcome2.accepted
        assert outcome2.reason == "cooldown"

    def test_allows_after_cooldown_elapsed(self, db, monkeypatch):
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.001")  # ~3.6s
        from radar.calibration import auto_tune_governor as gov
        monkeypatch.setattr(gov, "_recall_gate_is_red", lambda: False)

        gov.commit(_proposal(new_value=9.0))
        time.sleep(4)  # exceed the 0.001h cooldown
        outcome2 = gov.commit(_proposal(new_value=9.5))
        assert outcome2.accepted


class TestGovernorMagnitude:
    def test_clamps_oversized_change(self, db, monkeypatch):
        monkeypatch.setenv("AUTO_TUNE_MAX_MAGNITUDE_PCT", "10.0")
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
        from radar.calibration import auto_tune_governor as gov
        from radar.calibration import threshold_history
        monkeypatch.setattr(gov, "_recall_gate_is_red", lambda: False)

        # Seed prior value 10.0
        threshold_history.record_change(
            key="x", value=10.0, scope_scenario_id=None,
            derived_from="seed", applied_by="auto:test", sample_n=50,
            formula_ref="seed",
        )
        time.sleep(0.01)
        # Propose 15.0 (50% jump → should clamp to 10.0 + 1.0 = 11.0)
        outcome = gov.commit(_proposal(key="x", new_value=15.0))
        assert outcome.accepted
        assert outcome.reason == "magnitude_clamped"
        assert outcome.clamped_value == pytest.approx(11.0)
        # Verify ledger reflects the clamped value, not the requested one.
        rec = threshold_history.latest("x")
        assert rec.value == pytest.approx(11.0)

    def test_allows_change_within_budget(self, db, monkeypatch):
        monkeypatch.setenv("AUTO_TUNE_MAX_MAGNITUDE_PCT", "10.0")
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
        from radar.calibration import auto_tune_governor as gov
        from radar.calibration import threshold_history
        monkeypatch.setattr(gov, "_recall_gate_is_red", lambda: False)
        threshold_history.record_change(
            key="x", value=10.0, scope_scenario_id=None,
            derived_from="seed", applied_by="auto:test", sample_n=50,
            formula_ref="seed",
        )
        time.sleep(0.01)
        outcome = gov.commit(_proposal(key="x", new_value=10.5))  # 5% change
        assert outcome.accepted
        assert outcome.reason == "committed"


class TestGovernorRecallGate:
    def test_blocks_when_recall_red(self, db, monkeypatch):
        from radar.calibration import auto_tune_governor as gov
        monkeypatch.setattr(gov, "_recall_gate_is_red", lambda: True)
        outcome = gov.commit(_proposal(new_value=9.0))
        assert not outcome.accepted
        assert outcome.reason == "recall_red"


class TestGovernorUnchanged:
    def test_short_circuits_unchanged_value(self, db, monkeypatch):
        monkeypatch.setenv("AUTO_TUNE_COOLDOWN_HOURS", "0.0")
        from radar.calibration import auto_tune_governor as gov
        from radar.calibration import threshold_history
        monkeypatch.setattr(gov, "_recall_gate_is_red", lambda: False)
        threshold_history.record_change(
            key="x", value=9.0, scope_scenario_id=None,
            derived_from="seed", applied_by="auto:test", sample_n=50,
            formula_ref="seed",
        )
        outcome = gov.commit(_proposal(key="x", new_value=9.0))
        assert not outcome.accepted
        assert outcome.reason == "unchanged"
