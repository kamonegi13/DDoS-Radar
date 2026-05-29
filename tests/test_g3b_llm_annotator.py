"""Tests for radar.calibration.g3b_llm_annotator (Tier 4, commit 12)."""
from __future__ import annotations

import json
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.calibration import g3b_llm_annotator as g3b


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "g3b.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.calibration.g3b_llm_annotator.db", tdb)
    yield tdb
    tdb.close()


def _seed_cluster(db, *, countries: list[str], centroid: str = "CN") -> int:
    """Seed a discovery_run + discovery_cluster row, return cluster id."""
    conn = db._get_conn()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO cooccurrence_matrix_snapshot "
            "(emitted_at, window_days, bucket_hours, cell_count, "
            " matrix_json, formula_ref) "
            "VALUES (?, 30, 24, 0, '{}', 'cooccurrence/v1#test')",
            (time.time(),),
        )
        snap_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO scenario_discovery_run "
            "(emitted_at, matrix_snapshot_id, algorithm, eps, "
            " min_samples, n_clusters, n_noise, formula_ref) "
            "VALUES (?, ?, 'dbscan', 0.6, 3, 1, 0, 'test')",
            (time.time(), snap_id),
        )
        run_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO discovery_cluster "
            "(run_id, cluster_index, countries_json, centroid_json, "
            " annotation_state, formula_ref) "
            "VALUES (?, 0, ?, ?, 'none', 'test')",
            (run_id, json.dumps(countries),
             json.dumps({"centroid": centroid})),
        )
        return cur.lastrowid


# ── Env-gate behavior ───────────────────────────────────────────────────────


class TestEnvGate:
    def test_default_both_off_skips(self, fresh_db, monkeypatch):
        monkeypatch.delenv("G3B_SHADOW_ENABLED", raising=False)
        monkeypatch.delenv("G3B_LLM_ENABLED", raising=False)
        result = g3b.run_once()
        assert result["skipped"] is True
        assert result["reason"] == "both_flags_off"

    def test_shadow_on_enables_annotation_state(self, fresh_db, monkeypatch):
        monkeypatch.setenv("G3B_SHADOW_ENABLED", "true")
        monkeypatch.delenv("G3B_LLM_ENABLED", raising=False)
        assert g3b._annotation_state() == "shadow"

    def test_production_overrides_shadow(self, fresh_db, monkeypatch):
        monkeypatch.setenv("G3B_SHADOW_ENABLED", "true")
        monkeypatch.setenv("G3B_LLM_ENABLED", "true")
        assert g3b._annotation_state() == "production"


# ── No clusters available ────────────────────────────────────────────────────


class TestNoClusters:
    def test_skips_when_no_unannotated(self, fresh_db, monkeypatch):
        monkeypatch.setenv("G3B_SHADOW_ENABLED", "true")
        result = g3b.run_once()
        assert result["skipped"] is True
        assert result["reason"] == "no_unannotated_clusters"


# ── Annotation flow (mocked LLM) ─────────────────────────────────────────────


class TestAnnotationFlow:
    def test_annotates_cluster_in_shadow_state(
        self, fresh_db, monkeypatch,
    ):
        monkeypatch.setenv("G3B_SHADOW_ENABLED", "true")
        monkeypatch.delenv("G3B_LLM_ENABLED", raising=False)
        cid = _seed_cluster(fresh_db, countries=["CN", "JP", "TW"])

        def fake_llm(*, system, prompt, **kw):
            return {"ok": True, "data": {
                "kind": "scenario",
                "suggested_name": "China-Japan-Taiwan tensions",
                "suggested_description": "Co-occurring intel cluster.",
                "confidence_self_reported": 0.7,
                "rationale": "Frequent co-mention.",
            }}

        monkeypatch.setattr("radar.llm_client.llm_analyze_json", fake_llm)
        result = g3b.run_once()
        assert result["annotated"] == 1
        # Verify state in DB
        row = fresh_db._get_conn().execute(
            "SELECT annotation_state, annotation_json FROM discovery_cluster "
            "WHERE id=?", (cid,),
        ).fetchone()
        assert row[0] == "shadow"
        ann = json.loads(row[1])
        assert ann["kind"] == "scenario"
        assert ann["suggested_name"] == "China-Japan-Taiwan tensions"

    def test_production_state_when_flag_set(
        self, fresh_db, monkeypatch,
    ):
        monkeypatch.setenv("G3B_LLM_ENABLED", "true")
        monkeypatch.setenv("G3B_SHADOW_ENABLED", "true")
        cid = _seed_cluster(fresh_db, countries=["US", "FR", "DE"])

        def fake_llm(*, system, prompt, **kw):
            return {"ok": True, "data": {
                "kind": "random",
                "confidence_self_reported": 0.2,
                "rationale": "Heterogeneous group.",
            }}

        monkeypatch.setattr("radar.llm_client.llm_analyze_json", fake_llm)
        result = g3b.run_once()
        assert result["state"] == "production"
        row = fresh_db._get_conn().execute(
            "SELECT annotation_state FROM discovery_cluster WHERE id=?",
            (cid,),
        ).fetchone()
        assert row[0] == "production"


# ── Circuit breaker ─────────────────────────────────────────────────────────


class TestCircuitBreaker:
    def test_opens_after_consecutive_failures(self, fresh_db, monkeypatch):
        monkeypatch.setenv("G3B_SHADOW_ENABLED", "true")
        monkeypatch.setenv("G3B_CIRCUIT_BREAKER_FAILURES", "3")
        # Seed 5 clusters
        for i in range(5):
            _seed_cluster(fresh_db, countries=[f"X{i}", f"Y{i}"])

        def failing_llm(*, system, prompt, **kw):
            return {"ok": False, "data": {}, "error": "timeout"}

        monkeypatch.setattr("radar.llm_client.llm_analyze_json", failing_llm)
        result = g3b.run_once()
        assert result["circuit_open"] is True
        assert result["errors"] >= 3


# ── Daily cap ───────────────────────────────────────────────────────────────


class TestDailyCap:
    def test_skips_when_cap_reached(self, fresh_db, monkeypatch):
        monkeypatch.setenv("G3B_SHADOW_ENABLED", "true")
        monkeypatch.setenv("G3B_DAILY_CALL_CAP", "0")  # cap=0 → always skip
        _seed_cluster(fresh_db, countries=["CN", "TW"])
        result = g3b.run_once()
        assert result["skipped"] is True
        assert result["reason"] == "daily_cap_reached"


# ── run_now integration ─────────────────────────────────────────────────────


class TestRunNowIntegration:
    def test_g3b_phase_in_dispatcher(self):
        from radar.calibration import run_now
        assert "g3b" in run_now._PHASE_ORDER
        fn = run_now._phase_func("g3b")
        assert callable(fn)
