"""Tests for radar.calibration.scenario_discoverer (Tier 3, commit 10)."""
from __future__ import annotations

import json
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.calibration import scenario_discoverer as sd
from radar.analytics import cooccurrence as cc


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "discoverer.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.analytics.cooccurrence.db", tdb)
    monkeypatch.setattr("radar.calibration.scenario_discoverer.db", tdb)
    yield tdb
    tdb.close()


def _seed_intel(db, country: str, ts: float, source_type: str = "apt_intel"):
    conn = db._get_conn()
    with conn.writing():
        conn.execute(
            "INSERT INTO llm_intel "
            "(id, source_type, source_id, theater, ts, status, "
            " confidence, raw_text, raw_url, headline, llm_fields, "
            " score_delta, domain, confirmed_by, confirmed_at, "
            " override_at, created_at, countries, country_weights) "
            "VALUES (?, ?, ?, ?, ?, 'confirmed', 0.8, '', '', '', "
            "        '{}', 0, 'cyber', NULL, NULL, NULL, ?, '[]', '{}')",
            (f"li-{country}-{ts}", source_type, f"src-{country}-{ts}",
             country, ts, time.time()),
        )


# ── _jaccard ─────────────────────────────────────────────────────────────────


class TestJaccard:
    def test_identical(self):
        assert sd._jaccard({"a", "b"}, {"a", "b"}) == 1.0

    def test_disjoint(self):
        assert sd._jaccard({"a"}, {"b"}) == 0.0

    def test_partial(self):
        assert sd._jaccard({"a", "b", "c"}, {"b", "c", "d"}) == pytest.approx(0.5)

    def test_both_empty(self):
        assert sd._jaccard(set(), set()) == 1.0


# ── _maybe_take_snapshot ─────────────────────────────────────────────────────


class TestMaybeTakeSnapshot:
    def test_returns_none_when_no_snapshot_and_no_data(self, fresh_db):
        # No llm_intel + no existing snapshot → run_once produces empty
        # matrix, get_latest returns the empty snapshot.
        snap = sd._maybe_take_snapshot()
        assert snap is not None
        assert snap["cell_count"] == 0

    def test_reuses_fresh_snapshot(self, fresh_db, monkeypatch):
        # Take one snapshot.
        cc.run_once()
        snap1 = cc.get_latest_snapshot()
        # Override fresh window to 24h so snap1 (just made) is fresh.
        monkeypatch.setenv("DISCOVERY_SNAPSHOT_FRESH_HOURS", "24")
        snap2 = sd._maybe_take_snapshot()
        assert snap2["id"] == snap1["id"]


# ── run_once integration ────────────────────────────────────────────────────


class TestRunOnceIntegration:
    def test_empty_matrix_skips(self, fresh_db):
        result = sd.run_once()
        assert result["skipped"] is True
        assert result["reason"] in ("empty_matrix", "no_snapshot",
                                    "no_countries")

    def test_runs_full_pipeline_with_clusters(self, fresh_db, monkeypatch):
        monkeypatch.setenv("DISCOVERY_DBSCAN_MIN_SAMPLES", "2")
        monkeypatch.setenv("DISCOVERY_DBSCAN_EPS", "0.6")
        # Tight cluster: CN-JP-TW co-occur in 3 buckets
        now = time.time()
        for i in range(3):
            t = now - i * 25 * 3600
            _seed_intel(fresh_db, "CN", t)
            _seed_intel(fresh_db, "JP", t - 100)
            _seed_intel(fresh_db, "TW", t - 200)
        result = sd.run_once()
        assert result["skipped"] is False
        assert result["n_clusters"] >= 1
        assert result["snapshot_id"] is not None
        assert result["discovery_run_id"] is not None

    def test_persists_run_and_clusters(self, fresh_db, monkeypatch):
        monkeypatch.setenv("DISCOVERY_DBSCAN_MIN_SAMPLES", "2")
        now = time.time()
        for i in range(3):
            t = now - i * 25 * 3600
            _seed_intel(fresh_db, "CN", t)
            _seed_intel(fresh_db, "JP", t - 100)
        result = sd.run_once()
        assert result["skipped"] is False
        # Check rows in scenario_discovery_run + discovery_cluster
        conn = fresh_db._get_conn()
        run_count = conn.execute(
            "SELECT COUNT(*) FROM scenario_discovery_run"
        ).fetchone()[0]
        cluster_count = conn.execute(
            "SELECT COUNT(*) FROM discovery_cluster"
        ).fetchone()[0]
        assert run_count >= 1
        assert cluster_count >= 1


# ── _emit_proposals overlap suppression ──────────────────────────────────────


class TestEmitProposalsOverlap:
    def test_skips_clusters_overlapping_existing_scenario(
        self, fresh_db, monkeypatch,
    ):
        # Build a fake scenario_store with a CN+JP+TW scenario; the
        # discoverer should NOT propose a new cluster for those countries.
        from dataclasses import dataclass

        @dataclass
        class _FakeParticipant:
            country: str

        @dataclass
        class _FakeScenario:
            id: str
            participants: dict

        fake_scenario = _FakeScenario(
            id="taiwan_contingency",
            participants={
                "CN": _FakeParticipant("CN"),
                "JP": _FakeParticipant("JP"),
                "TW": _FakeParticipant("TW"),
            },
        )

        class _FakeStore:
            _scenarios = {"taiwan_contingency": fake_scenario}
        import radar.scenarios as _scen
        monkeypatch.setattr(_scen, "scenario_store", _FakeStore())

        # Set up a ClusteringResult containing the existing trio.
        from radar.analytics.dbscan_cluster import (
            ClusteringResult, ClusterMembership,
        )
        result = ClusteringResult(
            memberships=(
                ClusterMembership("CN", 0, True),
                ClusterMembership("JP", 0, True),
                ClusterMembership("TW", 0, True),
            ),
            n_clusters=1, n_noise=0,
            eps=0.6, min_samples=2,
        )
        n = sd._emit_proposals(run_id=1, result=result)
        assert n == 0  # cluster already covered by existing scenario


# ── run_now integration ─────────────────────────────────────────────────────


class TestRunNowIntegration:
    def test_discovery_phase_in_dispatcher(self):
        from radar.calibration import run_now
        assert "discovery" in run_now._PHASE_ORDER
        fn = run_now._phase_func("discovery")
        assert callable(fn)
