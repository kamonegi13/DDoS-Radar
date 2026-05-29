"""Tests for scripts/check_recall_post_autotune.py (Tier 1, commit 5)."""
from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")


_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "check_recall_post_autotune.py"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "check_recall_post_autotune", _SCRIPT_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def script_mod():
    return _load_script()


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "post_autotune.db"
    db = RadarDB(str(p))
    yield db
    db.close()


def _seed_feedback(db, conclusion_id: str, scenario_id: str,
                   label: str, observed_at: float):
    conn = db._get_conn()
    with conn.writing():
        conn.execute(
            "INSERT OR IGNORE INTO conclusions "
            "(id, scenario_id, conclusion_type, state, confidence, "
            " observed_at, formula_ref, threshold_ref, source_urls, "
            " llm_prompt_sha256, calibration_status, "
            " conclusion_unavailable_reason, metadata) "
            "VALUES (?, ?, 'threat_level', '3', 0.85, ?, 't', '{}', '[]', "
            "        NULL, '{}', NULL, '{}')",
            (conclusion_id, scenario_id, observed_at),
        )
        conn.execute(
            "INSERT INTO analyst_feedback "
            "(conclusion_id, label, observed_outcome_url, analyst_id, "
            " observed_at, notes) "
            "VALUES (?, ?, NULL, 'auto:test', ?, NULL)",
            (conclusion_id, label, observed_at),
        )


def _seed_threshold_row(db, *, key: str, scope: str, effective_from: float):
    conn = db._get_conn()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO threshold_history "
            "(emitted_at, key, value, scope_scenario_id, effective_from, "
            " effective_to, derived_from, applied_by, revertible_to_id, "
            " sample_n, formula_ref, evidence_json, magnitude_pct, state) "
            "VALUES (?, ?, '0.5', ?, ?, NULL, 'test', 'auto:test', NULL, "
            "        50, 'test#row', '{}', 0.0, 'active')",
            (effective_from, key, scope, effective_from),
        )
        return cur.lastrowid


# ── _global_recall ───────────────────────────────────────────────────────────


class TestGlobalRecall:
    def test_returns_none_for_empty_window(self, script_mod, fresh_db):
        result = script_mod._global_recall(
            fresh_db, since=time.time() - 3600, until=time.time(),
        )
        assert result is None

    def test_computes_recall_correctly(self, script_mod, fresh_db):
        now = time.time()
        # 3 TP, 1 FN → recall = 0.75
        for i in range(3):
            _seed_feedback(fresh_db, f"c-tp-{i}", "scen", "TRUE_POSITIVE",
                           now - 1800)
        _seed_feedback(fresh_db, "c-fn-1", "scen", "FALSE_NEGATIVE",
                       now - 1800)
        result = script_mod._global_recall(
            fresh_db, since=now - 3600, until=now,
        )
        assert result == pytest.approx(0.75, abs=0.01)


# ── _recall_for_cell ─────────────────────────────────────────────────────────


class TestRecallForCell:
    def test_returns_none_when_below_min_samples(self, script_mod, fresh_db):
        now = time.time()
        _seed_feedback(fresh_db, "c-1", "scen", "TRUE_POSITIVE", now - 100)
        result = script_mod._recall_for_cell(
            fresh_db, "scen",
            since=now - 3600, until=now, min_samples=10,
        )
        assert result is None

    def test_filters_by_scenario(self, script_mod, fresh_db):
        now = time.time()
        for i in range(15):
            _seed_feedback(fresh_db, f"c-a-{i}", "scen_a",
                           "TRUE_POSITIVE", now - 600)
        for i in range(15):
            _seed_feedback(fresh_db, f"c-b-{i}", "scen_b",
                           "FALSE_NEGATIVE", now - 600)
        recall_a = script_mod._recall_for_cell(
            fresh_db, "scen_a", since=now - 3600, until=now, min_samples=10,
        )
        recall_b = script_mod._recall_for_cell(
            fresh_db, "scen_b", since=now - 3600, until=now, min_samples=10,
        )
        assert recall_a == 1.0
        assert recall_b == 0.0


# ── check_global_trend ───────────────────────────────────────────────────────


class TestCheckGlobalTrend:
    def test_no_data_returns_ok_with_info(self, script_mod, fresh_db):
        ok, msgs = script_mod.check_global_trend(
            fresh_db, hours=168, max_drop=0.10,
        )
        assert ok is True
        assert any("skipped" in m for m in msgs)

    def test_detects_drop(self, script_mod, fresh_db):
        now = time.time()
        # Pre-window: high recall (10 TP, 0 FN = 1.0)
        for i in range(10):
            _seed_feedback(fresh_db, f"c-pre-tp-{i}", "scen",
                           "TRUE_POSITIVE", now - 200 * 3600)
        # Post-window: lower recall (3 TP, 7 FN = 0.3)
        for i in range(3):
            _seed_feedback(fresh_db, f"c-post-tp-{i}", "scen",
                           "TRUE_POSITIVE", now - 50 * 3600)
        for i in range(7):
            _seed_feedback(fresh_db, f"c-post-fn-{i}", "scen",
                           "FALSE_NEGATIVE", now - 50 * 3600)
        ok, msgs = script_mod.check_global_trend(
            fresh_db, hours=168, max_drop=0.10,
        )
        assert ok is False
        assert any("WARN" in m and "global recall dropped" in m for m in msgs)

    def test_passes_when_within_tolerance(self, script_mod, fresh_db):
        now = time.time()
        # Both windows: recall = 0.9
        for i in range(9):
            _seed_feedback(fresh_db, f"c-pre-tp-{i}", "scen",
                           "TRUE_POSITIVE", now - 200 * 3600)
        _seed_feedback(fresh_db, "c-pre-fn-0", "scen",
                       "FALSE_NEGATIVE", now - 200 * 3600)
        for i in range(9):
            _seed_feedback(fresh_db, f"c-post-tp-{i}", "scen",
                           "TRUE_POSITIVE", now - 50 * 3600)
        _seed_feedback(fresh_db, "c-post-fn-0", "scen",
                       "FALSE_NEGATIVE", now - 50 * 3600)
        ok, msgs = script_mod.check_global_trend(
            fresh_db, hours=168, max_drop=0.10,
        )
        assert ok is True


# ── check_per_autotune ───────────────────────────────────────────────────────


class TestCheckPerAutotune:
    def test_no_rows_returns_ok(self, script_mod, fresh_db):
        ok, msgs = script_mod.check_per_autotune(
            fresh_db, hours=168, max_drop=0.10, min_samples=10,
        )
        assert ok is True

    def test_detects_per_row_drop(self, script_mod, fresh_db):
        now = time.time()
        # Autotune happened 10d ago
        eff_from = now - 10 * 86400
        _seed_threshold_row(
            fresh_db, key="tl1.scen", scope="scen", effective_from=eff_from,
        )
        # Pre-window (eff_from - 168h .. eff_from): high recall
        for i in range(10):
            _seed_feedback(fresh_db, f"c-pre-tp-{i}", "scen",
                           "TRUE_POSITIVE", eff_from - 12 * 3600)
        # Post-window (eff_from .. eff_from + 168h): low recall
        for i in range(2):
            _seed_feedback(fresh_db, f"c-post-tp-{i}", "scen",
                           "TRUE_POSITIVE", eff_from + 12 * 3600)
        for i in range(8):
            _seed_feedback(fresh_db, f"c-post-fn-{i}", "scen",
                           "FALSE_NEGATIVE", eff_from + 12 * 3600)
        ok, msgs = script_mod.check_per_autotune(
            fresh_db, hours=168, max_drop=0.10, min_samples=5,
        )
        assert ok is False
        assert any("WARN" in m for m in msgs)


# ── CLI ──────────────────────────────────────────────────────────────────────


class TestCLI:
    def test_warn_only_returns_0_on_drop(self, script_mod, monkeypatch):
        monkeypatch.setattr(script_mod, "check_global_trend",
                            lambda *a, **kw: (False, ["WARN: dropped"]))
        monkeypatch.setattr(script_mod, "check_per_autotune",
                            lambda *a, **kw: (True, []))
        rc = script_mod.main([])
        assert rc == 0  # warn-only

    def test_strict_returns_1_on_drop(self, script_mod, monkeypatch):
        monkeypatch.setattr(script_mod, "check_global_trend",
                            lambda *a, **kw: (False, ["WARN: dropped"]))
        monkeypatch.setattr(script_mod, "check_per_autotune",
                            lambda *a, **kw: (True, []))
        rc = script_mod.main(["--strict"])
        assert rc == 1

    def test_strict_returns_0_on_clean(self, script_mod, monkeypatch):
        monkeypatch.setattr(script_mod, "check_global_trend",
                            lambda *a, **kw: (True, ["OK"]))
        monkeypatch.setattr(script_mod, "check_per_autotune",
                            lambda *a, **kw: (True, []))
        rc = script_mod.main(["--strict"])
        assert rc == 0
