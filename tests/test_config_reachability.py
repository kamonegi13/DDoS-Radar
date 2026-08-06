"""WP-1.2 — runtime half of the config reachability audit (S5-VERIF-014).

The static classifier (tests/test_config_static_audit.py) answers "is there
a code path that reads this key through the 3-layer chain?". This module
covers the second axis S5-VERIF-014 demands: "was it actually read while
the process was running?", the verdict mapping between the two, and the
append-only ledger the daily job writes.

Two rules drive most of the tests here:

  * the runtime axis may not accuse anything before 24h of observation
    (S5-VERIF-014) — below the floor it reports INSUFFICIENT, never WARN;
  * ~95 stable ANOMALYs must not append 95 rows per day — a target's row
    is written only when its verdict changes (plus one summary row per
    run), mirroring the firing_monitor ledger discipline of WP-1.1.

Every DB-touching test binds `config_reachability._db` to a throwaway
RadarDB under tmp_path; the live singleton is never written to.
"""
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

import radar.config  # noqa: F401  — populates the declarative registry
from radar import config_layered
from radar.config_layered import ConfigKey
from radar.database import RadarDB
from radar.verification import config_reachability as cr
from radar.verification import config_static_audit as csa

DAY = 86400.0
REPO_ROOT = Path(__file__).resolve().parent.parent


# ── fixtures ────────────────────────────────────────────────────────────────
class _BrokenDB:
    """Every accessor raises — the NP3 / S5-VERIF-006 degradation path."""

    def __getattr__(self, name):
        raise RuntimeError("db down")


@pytest.fixture
def cr_db(l5_tmp_db):
    return l5_tmp_db(cr, "l5cfg")


def _key(name: str, **kw) -> ConfigKey:
    kw.setdefault("domain", "test")
    kw.setdefault("default", "d")
    kw.setdefault("type_", "str")
    return ConfigKey(key=name, **kw)


_SNIPPETS = {
    "full": 'v_{n} = get_config("{k}")\n',
    "partial": 'v_{n} = get_config("{k}")\nw_{n} = os.getenv("{k}", "d")\n',
    "bypassed": 'w_{n} = os.getenv("{k}", "d")\n',
    "mismatch": 'w_{n} = os.getenv("{k}", "other")\n',
    "dead": "",
}


def synthetic_audit(tmp_path, spec: dict, keys=None):
    """Build a real AuditResult over a throwaway one-file 'repo'."""
    body = "".join(
        _SNIPPETS[kind].format(k=key, n=i)
        for i, (key, kind) in enumerate(sorted(spec.items())))
    src = ("import os\nfrom radar.config_layered import get_config\n"
           "def f():\n    pass\n") + body
    pkg = tmp_path / "synthetic" / "radar"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "mod.py").write_text(src, encoding="utf-8")
    return csa.audit(root=tmp_path / "synthetic",
                     keys=keys or [_key(k) for k in spec])


def verdicts(results):
    return {r["key"]: (r["verdict"], r["reason"]) for r in results}


# ── verdict mapping ─────────────────────────────────────────────────────────
class TestVerdictMapping:
    def test_static_classes_map_to_verdicts(self, cr_db, tmp_path):
        audit = synthetic_audit(tmp_path, {
            "A_FULL": "full", "B_PARTIAL": "partial",
            "C_BYPASSED": "bypassed", "D_DEAD": "dead"})
        now = time.time()
        cr_db.config_read_stats_merge(
            {"A_FULL": {"first_read_at": now - 3 * DAY,
                        "last_read_at": now, "read_count": 7}}, now=now)
        got = verdicts(cr.evaluate(now=now, audit_result=audit))
        assert got["C_BYPASSED"] == ("ANOMALY", "bypassed")
        assert got["B_PARTIAL"] == ("WARN", "partial_resolution")
        assert got["D_DEAD"] == ("WARN", "dead_key")
        assert got["A_FULL"] == ("OK", "resolving")

    def test_default_mismatch_is_an_anomaly_with_its_own_reason(self, cr_db,
                                                               tmp_path):
        audit = synthetic_audit(
            tmp_path, {"M": "mismatch"},
            keys=[_key("M", default="d")])
        results = cr.evaluate(now=time.time(), audit_result=audit)
        row = results[0]
        assert row["verdict"] == "ANOMALY"
        assert row["reason"] == "bypassed_and_default_mismatch"
        assert row["default_mismatches"][0]["direct_default"] == "other"

    def test_mismatch_detail_is_visible_per_key(self, cr_db, tmp_path):
        audit = synthetic_audit(tmp_path, {"M": "mismatch"},
                                keys=[_key("M", default="d")])
        snap = cr.snapshot(now=time.time(), audit_result=audit)
        assert snap["default_mismatches"][0]["key"] == "M"
        assert snap["default_mismatches"][0]["registry_default"] == "d"

    def test_every_registered_key_is_classified(self, cr_db, tmp_path):
        audit = synthetic_audit(tmp_path, {
            "A_FULL": "full", "C_BYPASSED": "bypassed", "D_DEAD": "dead"})
        results = cr.evaluate(now=time.time(), audit_result=audit)
        assert len(results) == 3 == audit.registered_total


# ── S5-VERIF-014: the observation floor, PER KEY ───────────────────────────
#
# review FIX 3: the floor used to be one global window derived from the
# earliest anchor of ANY key, so a key registered today inherited months of
# someone else's observation and was accused of never being read on its
# first day. The window a key is judged by must be its own.
class TestRuntimeObservationFloor:
    def test_a_new_key_is_insufficient_while_an_old_key_warns(self, cr_db,
                                                              tmp_path):
        audit = synthetic_audit(tmp_path, {"OLD": "full", "NEW": "full"})
        now = time.time()
        cr_db.config_read_stats_note_considered(["OLD"], now=now - 5 * DAY)
        cr_db.config_read_stats_note_considered(["NEW"], now=now - 60.0)
        got = verdicts(cr.evaluate(now=now, audit_result=audit))
        assert got["OLD"] == ("WARN", "registered_never_read")
        assert got["NEW"] == ("INSUFFICIENT", "runtime_window_too_short")

    def test_another_keys_long_history_does_not_convict_this_key(self, cr_db,
                                                                 tmp_path):
        audit = synthetic_audit(tmp_path, {"A": "full"})
        now = time.time()
        cr_db.config_read_stats_merge(
            {"UNRELATED": {"first_read_at": now - 90 * DAY,
                           "last_read_at": now, "read_count": 99}}, now=now)
        got = verdicts(cr.evaluate(now=now, audit_result=audit))
        assert got["A"] == ("INSUFFICIENT", "runtime_window_too_short")

    def test_never_considered_key_is_insufficient(self, cr_db, tmp_path):
        audit = synthetic_audit(tmp_path, {"A": "full"})
        got = verdicts(cr.evaluate(now=time.time(), audit_result=audit))
        assert got["A"] == ("INSUFFICIENT", "runtime_window_too_short")

    def test_daily_run_records_first_considered_for_every_key(self, cr_db,
                                                              tmp_path,
                                                              monkeypatch):
        audit = synthetic_audit(tmp_path, {"A": "full", "B": "bypassed"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        rows = cr_db.config_read_stats_all()
        assert set(rows) >= {"A", "B"}
        assert rows["A"]["first_considered_at"] == pytest.approx(now)
        assert rows["A"]["read_count"] == 0

    def test_first_considered_at_is_not_moved_by_later_runs(self, cr_db,
                                                            tmp_path,
                                                            monkeypatch):
        audit = synthetic_audit(tmp_path, {"A": "full"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        cr.run_daily_check_if_due(now=now + 2 * DAY)
        assert cr_db.config_read_stats_all()["A"]["first_considered_at"] == \
            pytest.approx(now)

    def test_a_key_watched_over_24h_and_never_read_warns(self, cr_db, tmp_path,
                                                         monkeypatch):
        audit = synthetic_audit(tmp_path, {"A": "full"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        got = verdicts(cr.evaluate(now=now + DAY + 1, audit_result=audit))
        assert got["A"] == ("WARN", "registered_never_read")

    def test_runtime_view_unavailable_is_its_own_reason(self, cr_db, tmp_path,
                                                        monkeypatch):
        # review FIX 5d: "we could not look" must not read as "we looked and
        # the window was short".
        audit = synthetic_audit(tmp_path, {"A": "full"})
        monkeypatch.setattr(cr, "_db", lambda: _BrokenDB())
        got = verdicts(cr.evaluate(now=time.time(), audit_result=audit))
        assert got["A"] == ("INSUFFICIENT", "runtime_window_unknown")

    def test_floor_never_downgrades_a_static_anomaly(self, cr_db, tmp_path):
        # A short observation window must not hide a bypassing key: the
        # static axis is conclusive on its own (NP1).
        audit = synthetic_audit(tmp_path, {"A": "bypassed"})
        got = verdicts(cr.evaluate(now=time.time(), audit_result=audit))
        assert got["A"][0] == "ANOMALY"

    def test_a_read_key_is_ok_regardless_of_window(self, cr_db, tmp_path):
        audit = synthetic_audit(tmp_path, {"A": "full"})
        now = time.time()
        cr_db.config_read_stats_merge(
            {"A": {"first_read_at": now - 60.0, "last_read_at": now,
                   "read_count": 3}}, now=now)
        got = verdicts(cr.evaluate(now=now, audit_result=audit))
        assert got["A"] == ("OK", "resolving")

    def test_a_considered_but_unread_row_is_not_a_read(self, cr_db, tmp_path):
        audit = synthetic_audit(tmp_path, {"A": "full"})
        now = time.time()
        cr_db.config_read_stats_note_considered(["A"], now=now - 5 * DAY)
        got = verdicts(cr.evaluate(now=now, audit_result=audit))
        assert got["A"][0] == "WARN"


# ── runtime read tracker (radar/config_layered.py) ─────────────────────────
class TestRuntimeReadTracker:
    @pytest.fixture(autouse=True)
    def _clean(self):
        config_layered.reset_read_stats()
        yield
        config_layered.reset_read_stats()

    def test_get_config_records_a_registered_read(self):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        stats = config_layered.runtime_read_stats()
        entry = stats["SIGNAL_LEDGER_RETENTION_DAYS"]
        assert entry["read_count"] >= 1
        assert entry["first_read_at"] <= entry["last_read_at"]
        assert entry["last_source"] in ("db", "env", "default")

    def test_repeated_reads_accumulate(self):
        for _ in range(3):
            config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        assert config_layered.runtime_read_stats()[
            "SIGNAL_LEDGER_RETENTION_DAYS"]["read_count"] == 3

    def test_unregistered_reads_are_tracked_separately(self):
        config_layered.get_config("NO_SUCH_CONFIG_KEY_WP12")
        assert "NO_SUCH_CONFIG_KEY_WP12" not in config_layered.runtime_read_stats()
        assert "NO_SUCH_CONFIG_KEY_WP12" in config_layered.unregistered_read_stats()

    def test_reset_clears_both_tables(self):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        config_layered.get_config("NO_SUCH_CONFIG_KEY_WP12")
        config_layered.reset_read_stats()
        assert config_layered.runtime_read_stats() == {}
        assert config_layered.unregistered_read_stats() == {}

    def test_stats_accessor_returns_a_copy(self):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        snap = config_layered.runtime_read_stats()
        snap.clear()
        assert config_layered.runtime_read_stats() != {}

    # ── review FIX 5a: the drain must be one critical section ──────────────
    def test_drain_takes_and_clears_in_one_step(self):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        config_layered.get_config("NO_SUCH_CONFIG_KEY_WP12")
        registered, unregistered = config_layered.drain_read_stats()
        assert "SIGNAL_LEDGER_RETENTION_DAYS" in registered
        assert "NO_SUCH_CONFIG_KEY_WP12" in unregistered
        assert config_layered.runtime_read_stats() == {}
        assert config_layered.unregistered_read_stats() == {}

    def test_reads_after_a_drain_land_in_the_next_drain(self):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        config_layered.drain_read_stats()
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        registered, _ = config_layered.drain_read_stats()
        assert registered["SIGNAL_LEDGER_RETENTION_DAYS"]["read_count"] == 1

    def test_restore_merges_counters_back(self):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        registered, unregistered = config_layered.drain_read_stats()
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        config_layered.restore_read_stats(registered, unregistered)
        assert config_layered.runtime_read_stats()[
            "SIGNAL_LEDGER_RETENTION_DAYS"]["read_count"] == 2

    # ── review FIX 5b: the unregistered table is bounded ───────────────────
    def test_unregistered_tracking_is_capped(self, monkeypatch):
        monkeypatch.setattr(config_layered, "_UNREGISTERED_READ_CAP", 3)
        for i in range(10):
            config_layered.get_config(f"WP12_GHOST_KEY_{i}")
        assert len(config_layered.unregistered_read_stats()) == 3
        assert config_layered.unregistered_read_dropped() == 7

    def test_capped_table_still_counts_known_keys(self, monkeypatch):
        monkeypatch.setattr(config_layered, "_UNREGISTERED_READ_CAP", 1)
        config_layered.get_config("WP12_GHOST_KEY_A")
        config_layered.get_config("WP12_GHOST_KEY_A")
        config_layered.get_config("WP12_GHOST_KEY_B")
        stats = config_layered.unregistered_read_stats()
        assert stats["WP12_GHOST_KEY_A"]["read_count"] == 2
        assert config_layered.unregistered_read_dropped() == 1


class TestReadStatsPersistence:
    @pytest.fixture(autouse=True)
    def _clean(self):
        config_layered.reset_read_stats()
        yield
        config_layered.reset_read_stats()

    def test_flush_merges_the_tracker_and_resets_it(self, cr_db):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        assert cr.flush_read_stats(now=time.time()) == 1
        rows = cr_db.config_read_stats_all()
        assert rows["SIGNAL_LEDGER_RETENTION_DAYS"]["read_count"] == 1
        assert config_layered.runtime_read_stats() == {}

    def test_counts_accumulate_across_process_restarts(self, cr_db):
        t0 = time.time()
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        cr.flush_read_stats(now=t0)
        # "restart": the in-process tracker is empty again.
        config_layered.reset_read_stats()
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        cr.flush_read_stats(now=t0 + DAY)
        row = cr_db.config_read_stats_all()["SIGNAL_LEDGER_RETENTION_DAYS"]
        assert row["read_count"] == 3
        # first_read_at stays at the first observed read, it is not dragged
        # forward to the second flush.
        assert t0 <= row["first_read_at"] < t0 + DAY
        assert row["last_read_at"] >= t0

    def test_first_read_at_is_never_moved_forward(self, cr_db):
        t0 = 1_700_000_000.0
        cr_db.config_read_stats_merge(
            {"K": {"first_read_at": t0, "last_read_at": t0, "read_count": 1}},
            now=t0)
        cr_db.config_read_stats_merge(
            {"K": {"first_read_at": t0 + DAY, "last_read_at": t0 + DAY,
                   "read_count": 2}}, now=t0 + DAY)
        row = cr_db.config_read_stats_all()["K"]
        assert row["first_read_at"] == t0
        assert row["last_read_at"] == t0 + DAY
        assert row["read_count"] == 3

    def test_unregistered_reads_reach_the_snapshot(self, cr_db, tmp_path):
        config_layered.get_config("NO_SUCH_CONFIG_KEY_WP12")
        audit = synthetic_audit(tmp_path, {"A": "full"})
        snap = cr.snapshot(now=time.time(), audit_result=audit)
        names = {u["key"] for u in snap["unregistered_reads"]}
        assert "NO_SUCH_CONFIG_KEY_WP12" in names

    def test_a_failed_flush_does_not_lose_the_counters(self, cr_db,
                                                       monkeypatch):
        # review FIX 5a: draining before the write must not turn a transient
        # DB error into silently discarded evidence.
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        monkeypatch.setattr(cr, "_db", lambda: _BrokenDB())
        assert cr.flush_read_stats(now=time.time()) == 0
        assert "SIGNAL_LEDGER_RETENTION_DAYS" in config_layered.runtime_read_stats()

    def test_dropped_unregistered_count_reaches_the_snapshot(self, cr_db,
                                                             tmp_path,
                                                             monkeypatch):
        monkeypatch.setattr(config_layered, "_UNREGISTERED_READ_CAP", 1)
        config_layered.get_config("WP12_GHOST_KEY_A")
        config_layered.get_config("WP12_GHOST_KEY_B")
        audit = synthetic_audit(tmp_path, {"A": "full"})
        snap = cr.snapshot(now=time.time(), audit_result=audit)
        assert snap["unregistered_reads_dropped"] == 1

    def test_unregistered_reads_survive_the_daily_flush(self, cr_db, tmp_path):
        # The flush empties the in-process tracker; a silent fallback that
        # disappeared from the surface one day after being seen would be a
        # worse report than none (NP1).
        config_layered.get_config("NO_SUCH_CONFIG_KEY_WP12")
        cr.flush_read_stats(now=time.time())
        assert config_layered.unregistered_read_stats() == {}
        audit = synthetic_audit(tmp_path, {"A": "full"})
        snap = cr.snapshot(now=time.time(), audit_result=audit)
        names = {u["key"] for u in snap["unregistered_reads"]}
        assert "NO_SUCH_CONFIG_KEY_WP12" in names


# ── ledger discipline ───────────────────────────────────────────────────────
def _rows(db, target=None):
    rows = db.l5_check_latest(cr.CHECK_ID, limit=500)
    return [r for r in rows if target is None or r["target"] == target]


class TestLedgerFloodControl:
    def test_first_run_baselines_every_non_ok_target(self, cr_db, tmp_path,
                                                     monkeypatch):
        audit = synthetic_audit(tmp_path, {
            "A": "bypassed", "B": "partial", "C": "full"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr_db.config_read_stats_merge(
            {"C": {"first_read_at": now - DAY, "last_read_at": now,
                   "read_count": 1}}, now=now)
        assert cr.run_daily_check_if_due(now=now) is True
        targets = {r["target"] for r in _rows(cr_db)}
        assert targets == {"config:A", "config:B", cr.SUMMARY_TARGET}

    def test_unchanged_verdicts_append_only_the_summary(self, cr_db, tmp_path,
                                                        monkeypatch):
        audit = synthetic_audit(tmp_path, {"A": "bypassed"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        before = len(_rows(cr_db))
        cr.run_daily_check_if_due(now=now + DAY)
        after = _rows(cr_db)
        assert len(after) == before + 1
        assert after[0]["target"] == cr.SUMMARY_TARGET

    def test_a_class_change_appends_a_row(self, cr_db, tmp_path, monkeypatch):
        bad = synthetic_audit(tmp_path / "a", {"A": "bypassed"})
        monkeypatch.setattr(cr, "_audit", lambda: bad)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        worse = synthetic_audit(tmp_path / "b", {"A": "partial"})
        monkeypatch.setattr(cr, "_audit", lambda: worse)
        cr.run_daily_check_if_due(now=now + DAY)
        verdict_seq = [r["verdict"] for r in _rows(cr_db, "config:A")]
        assert verdict_seq == ["WARN", "ANOMALY"]  # newest first

    def test_recovery_appends_an_ok_row(self, cr_db, tmp_path, monkeypatch):
        bad = synthetic_audit(tmp_path / "a", {"A": "bypassed"})
        monkeypatch.setattr(cr, "_audit", lambda: bad)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        fixed = synthetic_audit(tmp_path / "b", {"A": "full"})
        monkeypatch.setattr(cr, "_audit", lambda: fixed)
        cr_db.config_read_stats_merge(
            {"A": {"first_read_at": now, "last_read_at": now, "read_count": 1}},
            now=now)
        cr.run_daily_check_if_due(now=now + DAY)
        assert [r["verdict"] for r in _rows(cr_db, "config:A")] == \
            ["OK", "ANOMALY"]

    def test_ok_targets_never_append_daily_no_ops(self, cr_db, tmp_path,
                                                  monkeypatch):
        audit = synthetic_audit(tmp_path, {"A": "full"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr_db.config_read_stats_merge(
            {"A": {"first_read_at": now - DAY, "last_read_at": now,
                   "read_count": 1}}, now=now)
        cr.run_daily_check_if_due(now=now)
        cr.run_daily_check_if_due(now=now + DAY)
        assert _rows(cr_db, "config:A") == []

    def test_first_detected_at_carries_across_runs(self, cr_db, tmp_path,
                                                   monkeypatch):
        audit = synthetic_audit(tmp_path, {"A": "bypassed", "B": "partial"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        cr.run_daily_check_if_due(now=now + DAY)
        summary = _rows(cr_db, cr.SUMMARY_TARGET)
        assert summary[0]["first_detected_at"] == pytest.approx(now)

    def test_summary_row_carries_counts_and_a_classification_hash(
            self, cr_db, tmp_path, monkeypatch):
        audit = synthetic_audit(tmp_path, {"A": "bypassed", "B": "dead"})
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        measured = json.loads(_rows(cr_db, cr.SUMMARY_TARGET)[0]["measured_json"])
        assert measured["ANOMALY"] == 1 and measured["WARN"] == 1
        assert len(measured["classification_hash"]) == 16


class TestPersistentSchedule:
    def test_not_due_is_skipped(self, cr_db, tmp_path, monkeypatch):
        monkeypatch.setattr(cr, "_audit",
                            lambda: synthetic_audit(tmp_path, {"A": "full"}))
        now = time.time()
        assert cr.run_daily_check_if_due(now=now) is True
        assert cr.run_daily_check_if_due(now=now + 60) is False

    def test_due_after_the_interval(self, cr_db, tmp_path, monkeypatch):
        monkeypatch.setattr(cr, "_audit",
                            lambda: synthetic_audit(tmp_path, {"A": "full"}))
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        assert cr.run_daily_check_if_due(now=now + cr.JOB_INTERVAL_SEC + 1) is True

    def test_overdue_job_runs_on_the_first_tick_after_a_restart(
            self, cr_db, tmp_path, monkeypatch):
        # Defect F-01: the volatile `_cycle % 24` counter never compensated.
        monkeypatch.setattr(cr, "_audit",
                            lambda: synthetic_audit(tmp_path, {"A": "full"}))
        now = time.time()
        cr_db.l5_job_set(cr.JOB_ID, last_run_at=now - 10 * DAY,
                         next_run_at=now - 9 * DAY)
        assert cr.run_daily_check_if_due(now=now) is True

    def test_schedule_is_persisted(self, cr_db, tmp_path, monkeypatch):
        monkeypatch.setattr(cr, "_audit",
                            lambda: synthetic_audit(tmp_path, {"A": "full"}))
        now = time.time()
        cr.run_daily_check_if_due(now=now)
        job = cr_db.l5_job_get(cr.JOB_ID)
        assert job["next_run_at"] == pytest.approx(now + cr.JOB_INTERVAL_SEC)


# ── NP3 / S5-VERIF-006 ──────────────────────────────────────────────────────
class TestFailureContainment:
    def test_daily_check_returns_false_on_db_failure(self, monkeypatch, caplog):
        monkeypatch.setattr(cr, "_db", lambda: _BrokenDB())
        assert cr.run_daily_check_if_due(now=time.time()) is False

    def test_flush_never_raises(self, monkeypatch):
        config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS")
        monkeypatch.setattr(cr, "_db", lambda: _BrokenDB())
        assert cr.flush_read_stats(now=time.time()) == 0

    def test_snapshot_degrades_to_unknown_not_to_green(self, monkeypatch,
                                                       tmp_path):
        monkeypatch.setattr(cr, "_db", lambda: _BrokenDB())
        audit = synthetic_audit(tmp_path, {"A": "full"})
        snap = cr.snapshot(now=time.time(), audit_result=audit)
        assert snap["runtime_axis"] == "UNKNOWN"
        assert snap["counts"]["BYPASSED"] == 0  # static axis still answered


class TestSnapshotShape:
    def test_snapshot_exposes_the_ap3_fields(self, cr_db, tmp_path):
        audit = synthetic_audit(tmp_path, {
            "A": "bypassed", "B": "partial", "C": "dead", "D": "full"})
        snap = cr.snapshot(now=time.time(), audit_result=audit)
        for field in ("job_id", "job_last_run_at", "job_next_run_at",
                      "registered_total", "counts", "anomalies",
                      "default_mismatches", "dead_keys", "partial_keys",
                      "unregistered_reads", "runtime_axis",
                      "dynamic_getenv_sites"):
            assert field in snap, field
        assert snap["anomalies"] == ["A"]
        assert snap["partial_keys"] == ["B"]
        assert snap["dead_keys"] == ["C"]
        assert snap["registered_total"] == 4

    def test_secret_defaults_never_reach_the_surface_or_the_ledger(
            self, cr_db, tmp_path, monkeypatch):
        # review FIX 1: /api/v2/self_eval is jwt-only and l5_check_result is
        # kept 365 days — neither may carry a secret's value.
        audit = synthetic_audit(
            tmp_path, {"TOKEN": "mismatch"},
            keys=[_key("TOKEN", default="registry-secret", secret=True)])
        monkeypatch.setattr(cr, "_audit", lambda: audit)
        snap = cr.snapshot(now=time.time(), audit_result=audit)
        entry = snap["default_mismatches"][0]
        assert entry["key"] == "TOKEN"
        assert entry["registry_default"] is None
        assert entry["direct_default"] is None
        assert entry["redacted"] is True

        cr.run_daily_check_if_due(now=time.time())
        blob = json.dumps(cr_db.l5_check_latest(cr.CHECK_ID, limit=50))
        assert "registry-secret" not in blob
        assert '"other"' not in blob  # the hardcoded default literal

    def test_snapshot_of_the_real_repo_reports_the_g15_scale(self, cr_db):
        snap = cr.snapshot(now=time.time())
        assert snap["counts"]["BYPASSED"] == 94
        assert len(snap["anomalies"]) >= 94
        assert snap["runtime_axis"] in ("OK", "INSUFFICIENT")


# ── wiring guards ───────────────────────────────────────────────────────────
class TestWiring:
    def test_scheduler_runs_the_daily_check(self):
        src = (REPO_ROOT / "radar" / "scheduler.py").read_text(encoding="utf-8")
        assert "config_reachability" in src
        assert "run_daily_check_if_due" in src

    def test_self_eval_exposes_the_block_and_its_error(self):
        src = (REPO_ROOT / "radar" / "routes" / "conclusions_v2.py").read_text(
            encoding="utf-8")
        assert 'out["config_reachability"]' in src
        assert 'out["config_reachability_error"]' in src

    def test_intel_guide_documents_the_block(self):
        src = (REPO_ROOT / "index.html").read_text(encoding="utf-8")
        assert "config_reachability" in src

    def test_ci_gate_is_wired(self):
        src = (REPO_ROOT / "scripts" / "check_ci.sh").read_text(encoding="utf-8")
        assert "check_config_reachability.py" in src


# ── CI gate script ──────────────────────────────────────────────────────────
def _load_gate():
    path = REPO_ROOT / "scripts" / "check_config_reachability.py"
    spec = importlib.util.spec_from_file_location("check_config_reachability",
                                                  path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCIGate:
    # The test process is gevent-monkeypatched and therefore multi-threaded,
    # so fork() warns. The child execs a fresh interpreter immediately, which
    # is the whole point of the test.
    @pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
    def test_gate_runs_without_booting_the_application(self):
        # review FIX 2: `import radar` runs radar/__init__.py, which migrates
        # and writes the DB and starts ~30 sensor threads with live outbound
        # HTTP. A pre-commit gate must not do that. Run it in a fresh
        # interpreter and prove it neither logged a boot nor touched the DB.
        db_path = REPO_ROOT / "radar" / "persistence" / "radar.db"
        before = db_path.stat().st_mtime_ns if db_path.exists() else None
        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts"
                                 / "check_config_reachability.py")],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120)
        assert proc.returncode == 0, proc.stderr
        combined = proc.stdout + proc.stderr
        for marker in ("[DB] Startup", "bg_scoring", "[Startup]", "[Persist]",
                       "[Scenarios]", "[Sensor/"):
            assert marker not in combined, f"app boot detected: {marker}"
        after = db_path.stat().st_mtime_ns if db_path.exists() else None
        assert after == before, "the gate must not write to the live DB"

    def test_baseline_payload_carries_no_timestamp(self):
        # review FIX 6a: a generated_at field makes every refresh a diff.
        gate = _load_gate()
        baseline = json.loads(gate.BASELINE_PATH.read_text(encoding="utf-8"))
        assert "generated_at" not in baseline
        assert "generated_at" not in gate.build_snapshot()

    def test_checked_in_baseline_matches_the_repo(self):
        gate = _load_gate()
        baseline = json.loads(gate.BASELINE_PATH.read_text(encoding="utf-8"))
        regressions, _ = gate.compare_baseline(baseline, gate.build_snapshot())
        assert regressions == []

    def test_main_exits_zero_against_the_checked_in_baseline(self):
        assert _load_gate().main([]) == 0

    def test_a_new_bypassing_key_is_a_regression(self):
        gate = _load_gate()
        base = {"classes": {"A": "FULL_RESOLUTION"}, "default_mismatches": {}}
        cur = {"classes": {"A": "FULL_RESOLUTION", "B": "BYPASSED"},
               "default_mismatches": {}}
        regressions, _ = gate.compare_baseline(base, cur)
        assert any("B" in r for r in regressions)

    def test_a_downgraded_key_is_a_regression(self):
        gate = _load_gate()
        base = {"classes": {"A": "FULL_RESOLUTION"}, "default_mismatches": {}}
        cur = {"classes": {"A": "BYPASSED"}, "default_mismatches": {}}
        regressions, _ = gate.compare_baseline(base, cur)
        assert any("A" in r for r in regressions)

    def test_a_new_default_mismatch_is_a_regression(self):
        gate = _load_gate()
        base = {"classes": {"A": "BYPASSED"}, "default_mismatches": {}}
        cur = {"classes": {"A": "BYPASSED"},
               "default_mismatches": {"A": "radar/a.py:1"}}
        regressions, _ = gate.compare_baseline(base, cur)
        assert regressions

    def test_an_improvement_is_not_a_regression(self):
        gate = _load_gate()
        base = {"classes": {"A": "BYPASSED"}, "default_mismatches": {"A": "x"}}
        cur = {"classes": {"A": "FULL_RESOLUTION"}, "default_mismatches": {}}
        regressions, improvements = gate.compare_baseline(base, cur)
        assert regressions == []
        assert improvements
