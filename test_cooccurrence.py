"""Tests for radar.analytics.cooccurrence (Tier 3, commit 8)."""
from __future__ import annotations

import json
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.analytics import cooccurrence as cc


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "cooccurrence.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.analytics.cooccurrence.db", tdb)
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


# ── compute_matrix ───────────────────────────────────────────────────────────


class TestComputeMatrix:
    def test_empty_db_returns_empty_matrix(self, fresh_db):
        m = cc.compute_matrix(window_days=30)
        assert m.cell_count == 0
        assert m.countries == ()
        assert m.total_events == 0

    def test_single_country_no_pairs(self, fresh_db):
        _seed_intel(fresh_db, "CN", time.time() - 3600)
        m = cc.compute_matrix(window_days=30)
        assert m.cell_count == 0
        assert m.countries == ("CN",)
        assert m.total_events == 1

    def test_two_countries_same_bucket_one_pair(self, fresh_db):
        now = time.time()
        _seed_intel(fresh_db, "CN", now - 100)
        _seed_intel(fresh_db, "TW", now - 200)
        m = cc.compute_matrix(window_days=30, bucket_hours=24)
        assert m.cell_count == 1
        p = m.pairs[0]
        assert (p.a, p.b) == ("CN", "TW")
        assert p.count == 1

    def test_two_countries_different_buckets_no_pair(self, fresh_db):
        now = time.time()
        _seed_intel(fresh_db, "CN", now - 100)
        _seed_intel(fresh_db, "TW", now - 5 * 86400)  # 5 days ago
        m = cc.compute_matrix(window_days=30, bucket_hours=24)
        # Different buckets — no co-occurrence
        assert m.cell_count == 0
        assert "CN" in m.countries
        assert "TW" in m.countries

    def test_multiple_buckets_aggregate(self, fresh_db):
        now = time.time()
        # Bucket 1: CN, JP
        _seed_intel(fresh_db, "CN", now - 100)
        _seed_intel(fresh_db, "JP", now - 200)
        # Bucket 2 (24h+ later): CN, JP again
        _seed_intel(fresh_db, "CN", now - 25 * 3600)
        _seed_intel(fresh_db, "JP", now - 26 * 3600)
        m = cc.compute_matrix(window_days=30, bucket_hours=24)
        # Same pair counted twice (across 2 buckets)
        cn_jp = next((p for p in m.pairs if (p.a, p.b) == ("CN", "JP")), None)
        assert cn_jp is not None
        assert cn_jp.count == 2

    def test_pairs_sorted_by_count_desc(self, fresh_db):
        now = time.time()
        # Strong pair: CN+JP appears in 3 buckets
        for i in range(3):
            _seed_intel(fresh_db, "CN", now - i * 25 * 3600)
            _seed_intel(fresh_db, "JP", now - i * 25 * 3600 - 100)
        # Weak pair: CN+TW appears in 1 bucket
        _seed_intel(fresh_db, "TW", now - 100)
        m = cc.compute_matrix(window_days=30, bucket_hours=24)
        # First pair has the highest count
        assert m.pairs[0].count >= m.pairs[-1].count


# ── snapshot ─────────────────────────────────────────────────────────────────


class TestSnapshot:
    def test_persists_and_reads_back(self, fresh_db):
        now = time.time()
        _seed_intel(fresh_db, "CN", now - 100)
        _seed_intel(fresh_db, "TW", now - 200)
        matrix = cc.compute_matrix(window_days=30)
        rid = cc.snapshot(matrix)
        assert rid is not None
        snap = cc.get_latest_snapshot()
        assert snap is not None
        assert snap["id"] == rid
        assert snap["cell_count"] == 1
        assert snap["window_days"] == 30
        assert "matrix" in snap

    def test_empty_matrix_is_persisted(self, fresh_db):
        m = cc.compute_matrix(window_days=30)
        rid = cc.snapshot(m)
        assert rid is not None
        snap = cc.get_latest_snapshot()
        assert snap["cell_count"] == 0

    def test_oversized_matrix_refused(self, fresh_db, monkeypatch):
        monkeypatch.setenv("COOCCURRENCE_MAX_CELLS", "0")
        now = time.time()
        _seed_intel(fresh_db, "CN", now - 100)
        _seed_intel(fresh_db, "JP", now - 200)
        m = cc.compute_matrix(window_days=30)
        rid = cc.snapshot(m)
        assert rid is None  # refused: cell_count > 0 > max=0

    def test_evidence_includes_metadata(self, fresh_db):
        now = time.time()
        for c in ("CN", "JP", "TW"):
            _seed_intel(fresh_db, c, now - 100)
        m = cc.compute_matrix(window_days=30)
        rid = cc.snapshot(m)
        snap = cc.get_latest_snapshot()
        assert snap["evidence"]["country_count"] == 3
        assert snap["evidence"]["total_events"] == 3
        assert snap["evidence"]["total_buckets"] >= 1


# ── get_latest_snapshot ──────────────────────────────────────────────────────


class TestGetLatestSnapshot:
    def test_returns_none_when_no_snapshots(self, fresh_db):
        snap = cc.get_latest_snapshot()
        assert snap is None

    def test_returns_most_recent(self, fresh_db):
        m1 = cc.compute_matrix(window_days=30)
        rid1 = cc.snapshot(m1)
        time.sleep(0.01)
        m2 = cc.compute_matrix(window_days=14)  # different window
        rid2 = cc.snapshot(m2)
        snap = cc.get_latest_snapshot()
        assert snap["id"] == rid2
        assert snap["window_days"] == 14


# ── run_once ─────────────────────────────────────────────────────────────────


class TestRunOnce:
    def test_returns_summary_dict(self, fresh_db):
        now = time.time()
        _seed_intel(fresh_db, "CN", now - 100)
        _seed_intel(fresh_db, "TW", now - 200)
        result = cc.run_once()
        assert result["snapshot_id"] is not None
        assert result["cell_count"] == 1
        assert result["country_count"] == 2
        assert result["total_events"] == 2

    def test_empty_db_run_succeeds(self, fresh_db):
        result = cc.run_once()
        assert result["snapshot_id"] is not None
        assert result["cell_count"] == 0
