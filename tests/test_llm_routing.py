"""Tests for radar.llm_routing (Phase 8 LLM survey v10 model routing).

Covers:
  - UseCase → ModelChoice resolution honors Feature Hub state (OFF / SHADOW / ON)
  - SHADOW returns legacy choice but records the v10 candidate as
    ``shadow_choice`` so callers can persist it on llm_call_log
  - Migration v41 adds the three new columns + indexes idempotently
  - llm_routing_stats() rolls up per-model and per-use_case correctly
  - choose_model never raises (NP3) when the Feature Hub DB is unavailable

These tests do NOT call Ollama — they patch the model-availability probe
so the routing decisions are deterministic in CI.
"""
from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")
os.environ.setdefault("V2_NP7_DISCLAIMER", "test")

from radar import llm_features as lf
from radar import llm_routing as lr
from radar.llm_features import FeatureState
from radar.llm_routing import ModelChoice, RoutingResult, UseCase, choose_model


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "routing.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.database.db", tdb, raising=False)
    yield tdb
    tdb.close()


@pytest.fixture(autouse=True)
def all_models_available(monkeypatch):
    """Make every probe return True so routing returns the chain primary."""
    monkeypatch.setattr(lr, "_model_available", lambda model: True)
    # Also clear the cache so previous tests can't poison the result.
    lr._avail_cache.clear()
    yield


@pytest.fixture(autouse=True)
def clean_routing_env(monkeypatch):
    """Remove any LLM_ROUTING_* env so tests don't drift on the dev box."""
    for key in (
        "LLM_ROUTING_VERDICT_ENABLED", "LLM_ROUTING_VERDICT_SHADOW",
        "LLM_ROUTING_SENSOR_ENABLED",  "LLM_ROUTING_SENSOR_SHADOW",
        "LLM_ROUTING_ETL_ENABLED",     "LLM_ROUTING_ETL_SHADOW",
        "LLM_ROUTING_CONCLUSION_ENABLED", "LLM_ROUTING_CONCLUSION_SHADOW",
        "LLM_FEATURE_KILL_SWITCH",
    ):
        monkeypatch.delenv(key, raising=False)
    yield


# ── Feature Hub registration ────────────────────────────────────────────────


class TestFeatureHubKeys:
    def test_all_four_routing_features_registered(self):
        keys = {f.key for f in lf.LLM_FEATURES}
        for k in (
            "model_routing_verdict",
            "model_routing_sensor",
            "model_routing_etl",
            "model_routing_conclusion",
        ):
            assert k in keys, f"missing routing feature key: {k}"

    def test_routing_features_support_shadow(self):
        for k in (
            "model_routing_verdict",
            "model_routing_sensor",
            "model_routing_etl",
            "model_routing_conclusion",
        ):
            f = lf.feature(k)
            assert f is not None
            assert f.supports_shadow is True
            assert f.default_state == FeatureState.OFF
            # Each one must declare a shadow_env_var so analysts can
            # opt-in via env without DB writes.
            assert f.shadow_env_var

    def test_use_case_to_feature_key_mapping_complete(self):
        for uc in UseCase:
            key = lr.feature_key_for(uc)
            assert key, f"no feature key for {uc}"
            # Must be one of the registered routing features.
            assert lf.feature(key) is not None


# ── choose_model resolution semantics ───────────────────────────────────────


class TestChooseModelOff:
    def test_use_case_none_returns_legacy_off(self, fresh_db):
        r = choose_model(None)
        assert r.state == "off"
        assert r.shadow_choice is None
        # Legacy uses LLM_MODEL env (default llama3.2:3b in config).
        from radar.config import LLM_MODEL
        assert r.active.model == LLM_MODEL

    def test_default_off_returns_legacy(self, fresh_db):
        # No env, no DB override — default state is OFF.
        r = choose_model(UseCase.VERDICT)
        assert r.state == "off"
        assert r.shadow_choice is None
        from radar.config import LLM_MODEL
        assert r.active.model == LLM_MODEL


class TestChooseModelShadow:
    def test_shadow_runs_legacy_records_v2_candidate(self, fresh_db):
        # Shadow VERDICT routing → legacy actually runs, v10's gemma4:26b
        # would have run.
        ok = lf.set_state(
            "model_routing_verdict", FeatureState.SHADOW,
            by="test", reason="unit",
        )
        assert ok
        r = choose_model(UseCase.VERDICT)
        assert r.state == "shadow"
        # Active is legacy, not v10's gemma4:26b
        from radar.config import LLM_MODEL
        assert r.active.model == LLM_MODEL
        # shadow_choice records what v10 *would* have picked
        assert r.shadow_choice == "gemma4:26b"

    def test_shadow_sensor_records_mistral(self, fresh_db):
        lf.set_state(
            "model_routing_sensor", FeatureState.SHADOW,
            by="test", reason="unit",
        )
        r = choose_model(UseCase.SENSOR_EXTRACT)
        assert r.state == "shadow"
        assert r.shadow_choice == "mistral-small3.2:24b"


class TestChooseModelOn:
    def test_on_verdict_picks_gemma4_26b_with_deterministic_sampling(self, fresh_db):
        lf.set_state(
            "model_routing_verdict", FeatureState.ON,
            by="test", reason="unit",
        )
        r = choose_model(UseCase.VERDICT)
        assert r.state == "on"
        assert r.shadow_choice is None
        c = r.active
        assert c.model == "gemma4:26b"
        # Verdict must be deterministic per the survey: temp=0, top_k=1, seed=42.
        assert c.temperature == 0.0
        assert c.top_k == 1
        assert c.seed == 42
        assert c.thinking_enabled is False  # verdict layer always thinking-OFF

    def test_on_sensor_picks_mistral_small(self, fresh_db):
        lf.set_state(
            "model_routing_sensor", FeatureState.ON,
            by="test", reason="unit",
        )
        r = choose_model(UseCase.SENSOR_EXTRACT)
        assert r.state == "on"
        assert r.active.model == "mistral-small3.2:24b"
        assert r.active.thinking_enabled is False

    def test_on_conclusion_picks_gemma4_31b_thinking_off(self, fresh_db):
        # 2026-05-10: thinking_enabled flipped to False for the default
        # CONCLUSION/DISCOVERY routes. All callers go through
        # llm_analyze_json (JSON output required) and bench data showed
        # thinking-on consumes the entire token budget, breaking parse.
        # Operators wanting thinking can still flip it via
        # LLM_ROUTING_CONCLUSION_PRIMARY_THINK=true (Layer 2 env override).
        lf.set_state(
            "model_routing_conclusion", FeatureState.ON,
            by="test", reason="unit",
        )
        r = choose_model(UseCase.CONCLUSION)
        assert r.state == "on"
        assert r.active.model == "gemma4:31b"
        assert r.active.thinking_enabled is False
        assert r.active.system_prefix == ""

    def test_on_etl_picks_gemma4_31b_thinking_off(self, fresh_db):
        lf.set_state(
            "model_routing_etl", FeatureState.ON,
            by="test", reason="unit",
        )
        r = choose_model(UseCase.DISCOVERY)
        assert r.state == "on"
        assert r.active.model == "gemma4:31b"
        assert r.active.thinking_enabled is False


class TestSystemPromptMerge:
    def test_merge_prepends_prefix_with_blank_line(self):
        c = ModelChoice(
            model="gemma4:31b", temperature=1.0,
            system_prefix="<|think|>", thinking_enabled=True,
        )
        merged = c.merge_system("Be helpful.")
        assert merged.startswith("<|think|>")
        assert "Be helpful." in merged

    def test_merge_no_prefix_returns_input(self):
        c = ModelChoice(
            model="gemma4:26b", temperature=0.0,
            system_prefix="", thinking_enabled=False,
        )
        assert c.merge_system("Hello") == "Hello"
        assert c.merge_system("") == ""


# ── NP3 fault tolerance ─────────────────────────────────────────────────────


class TestNP3:
    def test_choose_model_never_raises_when_feature_hub_broken(
        self, monkeypatch, fresh_db,
    ):
        def boom(_key):
            raise RuntimeError("DB exploded")
        monkeypatch.setattr(lf, "resolve_state", boom)
        # Even when the Feature Hub is broken, choose_model must return a
        # valid RoutingResult — it cannot break sensor/verdict callers.
        r = choose_model(UseCase.VERDICT)
        assert isinstance(r, RoutingResult)
        assert r.state == "off"   # safe default

    def test_kill_switch_overrides_to_off(self, monkeypatch, fresh_db):
        # Even with the routing feature ON, the global LLM kill switch
        # collapses everything back to OFF.
        lf.set_state(
            "model_routing_verdict", FeatureState.ON,
            by="test", reason="unit",
        )
        monkeypatch.setenv("LLM_FEATURE_KILL_SWITCH", "true")
        r = choose_model(UseCase.VERDICT)
        assert r.state == "off"


# ── Migration v41 ───────────────────────────────────────────────────────────


class TestMigrationV41:
    def test_thinking_trace_column_present(self, fresh_db):
        cols = {
            r[1] for r in fresh_db._get_conn()
            .execute("PRAGMA table_info(llm_call_log)").fetchall()
        }
        assert "thinking_trace" in cols
        assert "use_case" in cols
        assert "shadow_model_choice" in cols

    def test_migration_v41_indexes_present(self, fresh_db):
        rows = fresh_db._get_conn().execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND tbl_name='llm_call_log'"
        ).fetchall()
        names = {r[0] for r in rows}
        assert "idx_llm_call_log_usecase_ts" in names
        assert "idx_llm_call_log_model_ts" in names

    def test_migration_v41_idempotent(self, fresh_db):
        # Running it a second time on a DB that already has the columns
        # must be a no-op (no SQLite "duplicate column" error).
        from radar.database import _migration_v41_llm_routing_v10
        conn = fresh_db._get_conn()
        with conn.writing():
            _migration_v41_llm_routing_v10(conn)


# ── llm_call_log_append + llm_routing_stats ────────────────────────────────


class TestRoutingStats:
    def test_append_with_use_case_and_shadow(self, fresh_db):
        fresh_db.llm_call_log_append(
            caller="unit_test", model="gemma4:26b", duration_ms=120,
            outcome="ok", verdict="auto_confirmed", confidence=0.85,
            headline="t", use_case="verdict",
            shadow_model_choice="mistral-small3.2:24b",
            thinking_trace="brief reasoning",
        )
        row = fresh_db._get_conn().execute(
            "SELECT model, use_case, shadow_model_choice, thinking_trace "
            "FROM llm_call_log WHERE caller='unit_test'"
        ).fetchone()
        assert row[0] == "gemma4:26b"
        assert row[1] == "verdict"
        assert row[2] == "mistral-small3.2:24b"
        assert row[3] == "brief reasoning"

    def test_routing_stats_groups_by_model(self, fresh_db):
        # Mix of 3 models, some ok, some parse_failed.
        for model, n_ok, n_bad in [
            ("gemma4:26b", 5, 1),
            ("mistral-small3.2:24b", 3, 2),
            ("gemma4:31b", 2, 0),
        ]:
            for _ in range(n_ok):
                fresh_db.llm_call_log_append(
                    caller="x", model=model, duration_ms=100, outcome="ok",
                    confidence=0.7, use_case="verdict",
                )
            for _ in range(n_bad):
                fresh_db.llm_call_log_append(
                    caller="x", model=model, duration_ms=100,
                    outcome="parse_failed", use_case="verdict",
                )
        stats = fresh_db.llm_routing_stats(hours=1)
        bm = stats["by_model"]
        assert bm["gemma4:26b"]["n"] == 6
        assert bm["gemma4:26b"]["ok_rate"] == round(5 / 6, 3)
        assert bm["mistral-small3.2:24b"]["n"] == 5
        assert bm["mistral-small3.2:24b"]["parse_failed"] == 2
        # Use-case rollup includes the dominant model
        assert stats["by_use_case"]["verdict"]["primary_model"] in bm

    def test_routing_stats_shadow_diff(self, fresh_db):
        # Two SHADOW rows: one same family (gemma vs gemma), one cross.
        fresh_db.llm_call_log_append(
            caller="x", model="gemma4:26b", duration_ms=10, outcome="ok",
            use_case="verdict", shadow_model_choice="gemma4:26b",
        )
        fresh_db.llm_call_log_append(
            caller="x", model="llama3.2:3b", duration_ms=10, outcome="ok",
            use_case="verdict", shadow_model_choice="gemma4:26b",
        )
        stats = fresh_db.llm_routing_stats(hours=1)
        diff = stats["shadow_diff"]
        assert "verdict" in diff
        assert diff["verdict"]["n"] == 2
        # 1 of 2 had v1 and v2 in the same family.
        assert diff["verdict"]["same_family_rate"] == 0.5
        assert diff["verdict"]["v2_model"] == "gemma4:26b"

    def test_routing_stats_empty(self, fresh_db):
        stats = fresh_db.llm_routing_stats(hours=1)
        assert stats["by_model"] == {}
        assert stats["by_use_case"] == {}
        assert stats["shadow_diff"] == {}


# ── llm_client wiring ──────────────────────────────────────────────────────


class TestLlmClientUseCaseLog:
    """Confirm that llm_analyze_json honors use_case + records routing
    metadata in llm_call_log even when the LLM endpoint is unreachable."""

    def test_disabled_path_logs_use_case(self, fresh_db, monkeypatch):
        # Simulate LLM_ENABLED=False so the call short-circuits.
        from radar import llm_client
        monkeypatch.setattr(llm_client, "_global_llm_enabled", lambda: False)
        out = llm_client.llm_analyze_json(
            prompt="p", caller="unit_test_disabled",
            use_case=UseCase.VERDICT,
        )
        assert out["ok"] is False
        # The call should still have logged with use_case='verdict'.
        row = fresh_db._get_conn().execute(
            "SELECT use_case, outcome FROM llm_call_log "
            "WHERE caller='unit_test_disabled'"
        ).fetchone()
        assert row is not None
        assert row[0] == "verdict"
        assert row[1] == "disabled"


# ── Layer 2 (env vars) ─────────────────────────────────────────────────────


class TestEnvOverride:
    """Operators can override model + sampling per use_case via env vars
    without touching the DB or rebuilding the image."""

    def test_env_overrides_primary_model(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_ROUTING_VERDICT_PRIMARY_MODEL", "gemma4:31b")
        from radar.llm_features import set_state, FeatureState
        set_state("model_routing_verdict", FeatureState.ON, by="t")
        r = choose_model(UseCase.VERDICT)
        assert r.state == "on"
        assert r.active.model == "gemma4:31b"
        # Sampling NOT overridden — should still be the v10 verdict defaults
        # (temp=0, top_k=1, seed=42).
        assert r.active.temperature == 0.0
        assert r.active.top_k == 1
        assert r.active.seed == 42

    def test_env_overrides_temperature_only(self, fresh_db, monkeypatch):
        # Override only temperature; model stays at code default.
        monkeypatch.setenv("LLM_ROUTING_SENSOR_PRIMARY_TEMP", "0.05")
        from radar.llm_features import set_state, FeatureState
        set_state("model_routing_sensor", FeatureState.ON, by="t")
        r = choose_model(UseCase.SENSOR_EXTRACT)
        assert r.active.model == "mistral-small3.2:24b"  # code default
        assert r.active.temperature == 0.05               # env override

    def test_env_invalid_float_is_ignored(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_ROUTING_VERDICT_PRIMARY_TEMP", "not-a-float")
        from radar.llm_features import set_state, FeatureState
        set_state("model_routing_verdict", FeatureState.ON, by="t")
        r = choose_model(UseCase.VERDICT)
        # Falls back to v10 default (0.0) instead of raising.
        assert r.active.temperature == 0.0

    def test_env_think_toggle_for_gemma4(self, fresh_db, monkeypatch):
        # Force thinking ON for verdict — even though survey defaults it OFF.
        monkeypatch.setenv("LLM_ROUTING_VERDICT_PRIMARY_THINK", "true")
        from radar.llm_features import set_state, FeatureState
        set_state("model_routing_verdict", FeatureState.ON, by="t")
        r = choose_model(UseCase.VERDICT)
        assert r.active.thinking_enabled is True
        assert "<|think|>" in r.active.system_prefix


# ── Layer 3 (DB override) ─────────────────────────────────────────────────


class TestDbOverride:
    def test_set_override_persists_and_audit(self, fresh_db):
        ok = lr.set_override(
            UseCase.VERDICT, "primary",
            by="admin:test",
            reason="testing",
            model="gemma4:31b",
            temperature=0.0,
            thinking_enabled=False,
        )
        assert ok is True
        rows = lr.list_overrides()
        assert any(
            r["use_case"] == "verdict" and r["slot"] == "primary"
            and r["model"] == "gemma4:31b"
            for r in rows
        )
        # Audit row written with old_json=None (first set) and new_json carrying the patch.
        history = lr.list_override_history(hours=1, limit=10)
        match = [h for h in history if h["use_case"] == "verdict"]
        assert match
        assert match[0]["new"] is not None
        assert "gemma4:31b" in match[0]["new"]

    def test_db_override_beats_env(self, fresh_db, monkeypatch):
        monkeypatch.setenv("LLM_ROUTING_VERDICT_PRIMARY_MODEL", "from-env")
        lr.set_override(
            UseCase.VERDICT, "primary",
            by="admin:test", model="from-db",
        )
        from radar.llm_features import set_state, FeatureState
        set_state("model_routing_verdict", FeatureState.ON, by="t")
        r = choose_model(UseCase.VERDICT)
        assert r.active.model == "from-db"  # DB row wins over env

    def test_clear_override_reverts(self, fresh_db, monkeypatch):
        from radar.llm_features import set_state, FeatureState
        set_state("model_routing_verdict", FeatureState.ON, by="t")
        lr.set_override(
            UseCase.VERDICT, "primary",
            by="admin:test", model="custom-model",
        )
        assert choose_model(UseCase.VERDICT).active.model == "custom-model"
        lr.clear_override(
            UseCase.VERDICT, "primary", by="admin:test", reason="revert",
        )
        assert choose_model(UseCase.VERDICT).active.model == "gemma4:26b"

    def test_invalid_use_case_rejected(self, fresh_db):
        ok = lr.set_override(
            "garbage", "primary", by="t", model="x",
        )
        assert ok is False

    def test_invalid_slot_rejected(self, fresh_db):
        ok = lr.set_override(
            UseCase.VERDICT, "tertiary", by="t", model="x",
        )
        assert ok is False


# ── Effective routing snapshot ────────────────────────────────────────────


class TestEffectiveRouting:
    def test_snapshot_covers_every_use_case(self, fresh_db):
        eff = lr.list_effective_routing()
        seen_use_cases = {e["use_case"] for e in eff}
        assert seen_use_cases == {u.value for u in UseCase}

    def test_snapshot_reflects_db_override(self, fresh_db):
        lr.set_override(
            UseCase.SENSOR_EXTRACT, "primary",
            by="t", model="custom-sensor",
        )
        eff = lr.list_effective_routing()
        primary_sensor = next(
            e for e in eff
            if e["use_case"] == "sensor_extract" and e["slot"] == "primary"
        )
        assert primary_sensor["model"] == "custom-sensor"


# ── Embedding module ──────────────────────────────────────────────────────


class TestEmbedding:
    def test_disabled_feature_returns_none(self, fresh_db):
        from radar.llm_embedding import embed_text
        # embedding_dedupe is OFF by default.
        r = embed_text("hello world")
        assert r.vector is None
        assert r.error == "feature_disabled"

    def test_empty_input(self, fresh_db):
        from radar.llm_embedding import embed_text
        r = embed_text("")
        assert r.vector is None
        assert r.error == "empty_input"

    def test_cosine_basic(self):
        from radar.llm_embedding import cosine
        assert cosine([1, 0, 0], [1, 0, 0]) == pytest.approx(1.0)
        assert cosine([1, 0, 0], [0, 1, 0]) == pytest.approx(0.0)
        # Mismatched length → 0
        assert cosine([1, 0], [1, 0, 0]) == 0.0
        # Zero norm → 0 (no signal)
        assert cosine([0, 0, 0], [1, 0, 0]) == 0.0

    def test_near_duplicates_skips_failed_encodes(self, fresh_db, monkeypatch):
        from radar import llm_embedding as le
        # Pretend the feature is on but every embed call fails.
        monkeypatch.setattr(le, "_feature_active", lambda: True)
        def failing_post(*a, **kw):
            raise RuntimeError("fake")
        monkeypatch.setattr(le.requests, "post", failing_post)
        out = le.near_duplicates(["a", "b", "c"])
        assert out == []  # all failed → no pairs


# ── Migration v42 ─────────────────────────────────────────────────────────


class TestMigrationV42:
    def test_routing_override_tables_exist(self, fresh_db):
        rows = fresh_db._get_conn().execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('llm_routing_override','llm_routing_override_history')"
        ).fetchall()
        names = {r[0] for r in rows}
        assert "llm_routing_override" in names
        assert "llm_routing_override_history" in names

    def test_unique_constraint_use_case_slot(self, fresh_db):
        # Two set_override calls for the same (use_case, slot) must
        # produce one row, not two — UNIQUE(use_case, slot) + ON CONFLICT
        # DO UPDATE is the upsert contract.
        lr.set_override(UseCase.VERDICT, "primary", by="t", model="A")
        lr.set_override(UseCase.VERDICT, "primary", by="t", model="B")
        rows = fresh_db._get_conn().execute(
            "SELECT model FROM llm_routing_override "
            "WHERE use_case='verdict' AND slot='primary'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "B"
