"""Tests for radar.llm_features (LLM Feature Hub, commit G)."""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar import llm_features as lf
from radar.llm_features import FeatureState, FeatureTier


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "features.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.database.db", tdb, raising=False)
    yield tdb
    tdb.close()


# ── Registry shape ───────────────────────────────────────────────────────────


class TestRegistry:
    def test_all_features_unique_keys(self):
        keys = [f.key for f in lf.LLM_FEATURES]
        assert len(keys) == len(set(keys))

    def test_every_feature_has_required_fields(self):
        for f in lf.LLM_FEATURES:
            assert f.key
            assert isinstance(f.tier, FeatureTier)
            assert f.name
            assert f.description
            assert f.env_var
            assert isinstance(f.default_state, FeatureState)
            assert isinstance(f.np7_concern, bool)
            assert isinstance(f.requires_admin, bool)
            assert isinstance(f.supports_shadow, bool)
            # supports_shadow consistent with shadow_env_var presence
            if f.shadow_env_var:
                assert f.supports_shadow is True

    def test_lookup(self):
        assert lf.feature("triage_narrative") is not None
        assert lf.feature("nonexistent") is None

    def test_to_dict_round_trip(self):
        f = lf.feature("triage_narrative")
        d = f.to_dict()
        assert d["key"] == "triage_narrative"
        assert d["tier"] == "narrative"
        assert d["supports_shadow"] is False


# ── Resolution: env-only path ────────────────────────────────────────────────


class TestResolveStateEnvDefault:
    def test_unknown_key_returns_off(self, fresh_db):
        assert lf.resolve_state("nope") == FeatureState.OFF

    def test_default_state_when_no_env_no_db(self, fresh_db, monkeypatch):
        # Clear all relevant envs so we get the registry default
        for f in lf.LLM_FEATURES:
            monkeypatch.delenv(f.env_var, raising=False)
            if f.shadow_env_var:
                monkeypatch.delenv(f.shadow_env_var, raising=False)
        # sensor_intel_extraction default is ON
        assert lf.resolve_state("sensor_intel_extraction") == FeatureState.ON
        # auto_judge_recheck default is OFF
        assert lf.resolve_state("auto_judge_recheck") == FeatureState.OFF

    def test_env_on_returns_on(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_TRIAGE_NARRATIVE_ENABLED", "true")
        assert lf.resolve_state("triage_narrative") == FeatureState.ON

    def test_env_shadow_returns_shadow(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_AUTO_JUDGE_SHADOW", "true")
        monkeypatch.setenv("LLM_AUTO_JUDGE_RECHECK", "false")
        assert lf.resolve_state("auto_judge_recheck") == FeatureState.SHADOW

    def test_env_on_overrides_shadow(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_AUTO_JUDGE_SHADOW", "true")
        monkeypatch.setenv("LLM_AUTO_JUDGE_RECHECK", "true")
        assert lf.resolve_state("auto_judge_recheck") == FeatureState.ON


# ── Resolution: kill switch ──────────────────────────────────────────────────


class TestKillSwitch:
    def test_env_kill_switch_overrides_all(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_FEATURE_KILL_SWITCH", "true")
        monkeypatch.setenv("LLM_ENABLED", "true")  # would normally be ON
        assert lf.resolve_state("sensor_intel_extraction") == FeatureState.OFF

    def test_db_kill_switch_overrides_all(self, fresh_db, monkeypatch):
        monkeypatch.delenv("LLM_FEATURE_KILL_SWITCH", raising=False)
        # Use the public set_state API to enable kill switch via DB
        ok = lf.set_state("__kill_switch__", FeatureState.ON,
                          by="admin:test", reason="emergency stop")
        assert ok is True
        assert lf.resolve_state("auto_judge_recheck") == FeatureState.OFF
        assert lf.resolve_state("sensor_intel_extraction") == FeatureState.OFF

    def test_kill_switch_clears(self, fresh_db, monkeypatch):
        monkeypatch.delenv("LLM_FEATURE_KILL_SWITCH", raising=False)
        lf.set_state("__kill_switch__", FeatureState.ON, by="admin:test")
        assert lf.resolve_state("sensor_intel_extraction") == FeatureState.OFF
        # Restore
        lf.set_state("__kill_switch__", FeatureState.OFF, by="admin:test")
        # sensor_intel_extraction default ON now applies
        assert lf.resolve_state("sensor_intel_extraction") == FeatureState.ON


# ── Resolution: DB override priority ─────────────────────────────────────────


class TestDBOverride:
    def test_db_override_beats_env(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_TRIAGE_NARRATIVE_ENABLED", "true")  # env says ON
        # but DB override says OFF
        ok = lf.set_state("triage_narrative", FeatureState.OFF,
                          by="analyst:test")
        assert ok is True
        assert lf.resolve_state("triage_narrative") == FeatureState.OFF

    def test_clear_override_reverts_to_env(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_TRIAGE_NARRATIVE_ENABLED", "true")
        lf.set_state("triage_narrative", FeatureState.OFF, by="analyst:test")
        assert lf.resolve_state("triage_narrative") == FeatureState.OFF
        ok = lf.clear_override("triage_narrative", by="analyst:test")
        assert ok is True
        assert lf.resolve_state("triage_narrative") == FeatureState.ON

    def test_unknown_feature_reject(self, fresh_db):
        ok = lf.set_state("nonexistent", FeatureState.ON, by="admin:test")
        assert ok is False

    def test_shadow_rejected_when_unsupported(self, fresh_db):
        # triage_narrative.supports_shadow == False
        ok = lf.set_state("triage_narrative", FeatureState.SHADOW,
                          by="admin:test")
        assert ok is False

    def test_shadow_accepted_when_supported(self, fresh_db):
        # auto_judge_recheck.supports_shadow == True
        ok = lf.set_state("auto_judge_recheck", FeatureState.SHADOW,
                          by="admin:test")
        assert ok is True
        assert lf.resolve_state("auto_judge_recheck") == FeatureState.SHADOW


# ── is_enabled / is_shadow / is_active ──────────────────────────────────────


class TestPredicates:
    def test_is_enabled_only_on(self, fresh_db, monkeypatch):
        monkeypatch.delenv("LLM_TRIAGE_NARRATIVE_ENABLED", raising=False)
        # default OFF
        assert lf.is_enabled("triage_narrative") is False
        lf.set_state("triage_narrative", FeatureState.ON, by="admin:test")
        assert lf.is_enabled("triage_narrative") is True

    def test_is_shadow_only_shadow(self, fresh_db):
        lf.set_state("auto_judge_recheck", FeatureState.SHADOW,
                     by="admin:test")
        assert lf.is_shadow("auto_judge_recheck") is True
        assert lf.is_enabled("auto_judge_recheck") is False

    def test_is_active_covers_on_and_shadow(self, fresh_db):
        lf.set_state("auto_judge_recheck", FeatureState.SHADOW,
                     by="admin:test")
        assert lf.is_active("auto_judge_recheck") is True
        lf.set_state("auto_judge_recheck", FeatureState.ON, by="admin:test")
        assert lf.is_active("auto_judge_recheck") is True
        lf.set_state("auto_judge_recheck", FeatureState.OFF, by="admin:test")
        assert lf.is_active("auto_judge_recheck") is False


# ── Audit history ────────────────────────────────────────────────────────────


class TestHistory:
    def test_history_appends_on_set(self, fresh_db):
        lf.set_state("triage_narrative", FeatureState.ON,
                     by="admin:alice", reason="enabling for trial")
        lf.set_state("triage_narrative", FeatureState.OFF,
                     by="analyst:bob", reason="too much latency")
        rows = lf.list_history(hours=24)
        assert len(rows) >= 2
        # Most recent first
        latest = rows[0]
        assert latest["feature_key"] == "triage_narrative"
        assert latest["new_state"] == "off"
        assert latest["old_state"] == "on"
        assert latest["changed_by"] == "analyst:bob"
        assert latest["reason"] == "too much latency"

    def test_history_records_clear_override(self, fresh_db):
        lf.set_state("triage_narrative", FeatureState.ON, by="admin:test")
        lf.clear_override("triage_narrative", by="admin:test",
                          reason="reverting to env default")
        rows = lf.list_history(hours=24)
        latest = rows[0]
        assert latest["new_state"] == "auto"


# ── list_states for UI ───────────────────────────────────────────────────────


class TestListStates:
    def test_returns_full_catalog(self, fresh_db):
        states = lf.list_states()
        assert len(states) == len(lf.LLM_FEATURES)
        keys = {s["key"] for s in states}
        assert "sensor_intel_extraction" in keys
        assert "triage_narrative" in keys

    def test_each_entry_has_resolution_metadata(self, fresh_db):
        for s in lf.list_states():
            assert "current_state" in s
            assert "source" in s
            assert s["source"] in ("ui_override", "env", "default")
            assert "kill_switch_active" in s

    def test_source_reflects_db_override(self, fresh_db, monkeypatch):
        monkeypatch.delenv("LLM_TRIAGE_NARRATIVE_ENABLED", raising=False)
        states = lf.list_states()
        narrative = next(s for s in states if s["key"] == "triage_narrative")
        assert narrative["source"] == "default"
        lf.set_state("triage_narrative", FeatureState.ON, by="admin:test")
        states = lf.list_states()
        narrative = next(s for s in states if s["key"] == "triage_narrative")
        assert narrative["source"] == "ui_override"
        assert narrative["current_state"] == "on"


# ── Migration v31 verification ───────────────────────────────────────────────


class TestMigrationV31:
    def test_tables_exist(self, fresh_db):
        for table in ("llm_feature_state", "llm_feature_state_history"):
            row = fresh_db._get_conn().execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            assert row is not None, f"{table} missing"

    def test_state_check_constraint(self, fresh_db):
        import sqlite3
        with pytest.raises(sqlite3.IntegrityError):
            with fresh_db._get_conn().writing():
                fresh_db._get_conn().execute(
                    "INSERT INTO llm_feature_state "
                    "(feature_key, state, set_at, set_by) "
                    "VALUES ('x', 'invalid_state', 0, 'test')"
                )
