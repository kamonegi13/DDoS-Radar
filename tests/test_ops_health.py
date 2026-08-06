"""WP-0.3 — operational health: backup age + capacity trend (S4-NF-053).

The July failure this exists to prevent: the 04:00 backup cron ran with a
PATH that omitted the docker CLI, so every run failed with "command not
found" — into a log nobody read. Backups stopped for a month
(2026-07-04 -> 08-03) and nothing anywhere said so. The retention setting
claimed 14 generations; three existed.

So the load-bearing rule here is negative: **a backup whose age cannot be
determined must never read as OK**. Silence is exactly what the defect
looked like. `INSUFFICIENT backup_age_unknown` is the honest verdict, and
several tests below exist only to pin that.

Capacity is the second axis: ADR-V3-005 widened signal-ledger retention to
60 days on the estimate that the DB settles at 6-8 GB. That estimate has
never been checked against reality. The check records a daily size sample
and, once there are enough of them, projects the steady state — flagging
divergence for a human rather than concluding anything itself.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.verification import l5_common
from radar.verification import ops_health as oh

REPO_ROOT = Path(__file__).resolve().parent.parent
HOUR = 3600.0
DAY = 86400.0
GB = 1024 ** 3


@pytest.fixture
def oh_db(l5_tmp_db):
    return l5_tmp_db(oh, "l5ops")


@pytest.fixture
def marker(tmp_path, monkeypatch):
    """Point the check at a throwaway backup marker."""
    path = tmp_path / "backup_state.json"
    monkeypatch.setattr(oh, "backup_marker_path", lambda: path)

    def _write(age_hours=None, **extra):
        if age_hours is None:
            return path
        payload = {"last_backup_at": time.time() - age_hours * HOUR,
                   "backup_file": "radar-20260807-040000.db.gz",
                   "size_bytes": 278788029}
        payload.update(extra)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    return _write


def _by_target(results):
    return {r["target"]: r for r in results}


# ── S4-NF-053: backup age ───────────────────────────────────────────────────
class TestBackupAge:
    def test_a_fresh_backup_is_ok(self, marker):
        marker(age_hours=2)
        result = _by_target(oh.evaluate_backup())["backup"]
        assert (result["verdict"], result["reason"]) == ("OK", "backup_fresh")
        assert result["age_hours"] == pytest.approx(2, abs=0.1)

    def test_just_inside_the_daily_cadence_is_ok(self, marker):
        marker(age_hours=25)
        assert _by_target(oh.evaluate_backup())["backup"]["verdict"] == "OK"

    def test_one_missed_run_warns(self, marker):
        marker(age_hours=27)
        result = _by_target(oh.evaluate_backup())["backup"]
        assert (result["verdict"], result["reason"]) == \
            ("WARN", "backup_overdue")

    def test_two_missed_runs_are_an_anomaly(self, marker):
        marker(age_hours=51)
        result = _by_target(oh.evaluate_backup())["backup"]
        assert (result["verdict"], result["reason"]) == \
            ("ANOMALY", "backup_silent")

    def test_a_month_of_silence_is_an_anomaly(self, marker):
        # The actual July outage, in one assertion.
        marker(age_hours=30 * 24)
        result = _by_target(oh.evaluate_backup())["backup"]
        assert result["verdict"] == "ANOMALY"
        assert result["age_hours"] == pytest.approx(720, abs=1)

    def test_a_missing_marker_is_insufficient_never_ok(self, marker):
        marker(age_hours=None)          # no file written
        result = _by_target(oh.evaluate_backup())["backup"]
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == oh.REASON_BACKUP_ABSENT
        assert result["verdict"] != "OK", \
            "unknown backup age is what the July outage looked like"

    def test_a_malformed_marker_is_reported_as_corrupt(self, marker):
        path = marker(age_hours=None)
        path.write_text("{not json", encoding="utf-8")
        result = _by_target(oh.evaluate_backup())["backup"]
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == oh.REASON_BACKUP_CORRUPT

    def test_a_marker_without_a_timestamp_is_corrupt(self, marker):
        path = marker(age_hours=None)
        path.write_text(json.dumps({"backup_file": "x.gz"}), encoding="utf-8")
        result = _by_target(oh.evaluate_backup())["backup"]
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == oh.REASON_BACKUP_CORRUPT

    def test_a_future_timestamp_is_reported_as_clock_skew(self, marker):
        # Clock skew must not manufacture a healthy verdict.
        marker(age_hours=-5)
        result = _by_target(oh.evaluate_backup())["backup"]
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == oh.REASON_BACKUP_SKEW

    def test_every_unknown_reason_is_distinct_and_insufficient(self):
        reasons = {oh.REASON_BACKUP_ABSENT, oh.REASON_BACKUP_CORRUPT,
                   oh.REASON_BACKUP_SKEW}
        assert len(reasons) == 3, "each has a different repair"
        assert oh.REASON_BACKUP_FRESH not in reasons

    # ── threshold boundaries (the numbers are the contract) ──────────────
    @pytest.mark.parametrize("age_hours,expected", [
        (25.999, "OK"),
        (26.0, "WARN"),
        (49.999, "WARN"),
        (50.0, "ANOMALY"),
    ])
    def test_threshold_boundaries(self, marker, age_hours, expected):
        marker(age_hours=age_hours)
        assert _by_target(oh.evaluate_backup())["backup"]["verdict"] == expected

    def test_the_thresholds_carry_their_provenance(self):
        # 24h cron cadence + 2h slack; anomaly at two missed dailies.
        assert oh.BACKUP_WARN_AGE_HOURS == 26.0
        assert oh.BACKUP_ANOMALY_AGE_HOURS == 50.0
        assert oh.BACKUP_CADENCE_HOURS == 24.0

    def test_the_marker_details_survive_into_the_result(self, marker):
        marker(age_hours=1)
        result = _by_target(oh.evaluate_backup())["backup"]
        assert result["backup_file"] == "radar-20260807-040000.db.gz"
        assert result["size_bytes"] == 278788029


# ── capacity ────────────────────────────────────────────────────────────────
class TestCapacityMeasurement:
    def test_measurement_reports_file_sizes(self, oh_db):
        sample = oh.measure_capacity(db_path=oh_db._db_path)
        assert sample["db_bytes"] > 0
        assert sample["wal_bytes"] >= 0
        assert sample["total_bytes"] >= sample["db_bytes"]

    def test_measurement_counts_rows_per_table(self, oh_db):
        # Seed two rows so the table is non-empty: the report keeps the
        # largest tables, which is what a capacity question is about.
        for i in range(2):
            oh_db.l5_check_append(ts=float(i), check_id="probe",
                                  target=f"t{i}", verdict="OK")
        sample = oh.measure_capacity(db_path=oh_db._db_path)
        by_name = {t["table"]: t["rows"] for t in sample["tables"]}
        assert by_name.get("l5_check_result") == 2
        assert all(rows >= 0 for rows in by_name.values())

    def test_measurement_is_bounded_to_the_top_tables(self, oh_db):
        sample = oh.measure_capacity(db_path=oh_db._db_path)
        assert len(sample["tables"]) <= oh.TOP_TABLE_COUNT

    def test_measurement_reports_the_signal_ledger_age(self, oh_db):
        now = time.time()
        conn = oh_db._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO sensor_observation_ts "
                "(sensor, scope, ts, score) VALUES (?,?,?,?)",
                ("probe", "focused", now - 5 * DAY, 1.0))
        sample = oh.measure_capacity(db_path=oh_db._db_path, now=now)
        assert sample["signal_ledger_age_days"] == pytest.approx(5, abs=0.1)
        assert sample["signal_ledger_rows"] >= 1

    def test_measurement_never_raises_on_a_missing_file(self, tmp_path):
        sample = oh.measure_capacity(db_path=str(tmp_path / "absent.db"))
        assert sample["db_bytes"] == 0
        assert sample["tables"] == []

    def test_a_missing_database_is_marked_as_missing(self, tmp_path):
        # 0 bytes from a nonexistent path must stay distinguishable from
        # 0 bytes from an empty database.
        sample = oh.measure_capacity(db_path=str(tmp_path / "absent.db"))
        assert sample["db_exists"] is False

    def test_an_existing_database_is_marked_as_present(self, oh_db):
        assert oh.measure_capacity(db_path=oh_db._db_path)["db_exists"] is True

    def test_only_curated_trend_tables_are_counted(self, oh_db):
        # COUNT(*) is a full scan; counting all 60-100+ tables blocks the
        # gevent loop for seconds a day and grows with the schema.
        sample = oh.measure_capacity(db_path=oh_db._db_path)
        assert {t["table"] for t in sample["tables"]} <= set(oh.TREND_TABLES)

    def test_the_signal_ledger_is_in_the_trend_set(self):
        # ADR-V3-005's subject must never fall out of the curated list.
        assert "sensor_observation_ts" in oh.TREND_TABLES

    def test_truncation_is_surfaced_not_silent(self, oh_db, monkeypatch):
        monkeypatch.setattr(oh, "TABLE_COUNT_BUDGET_SEC", -1.0)
        sample = oh.measure_capacity(db_path=oh_db._db_path)
        assert sample["tables_truncated"] is True

    def test_a_normal_pass_is_not_truncated(self, oh_db):
        assert oh.measure_capacity(
            db_path=oh_db._db_path)["tables_truncated"] is False

    def test_a_path_with_spaces_is_handled(self, tmp_path):
        import sqlite3
        odd = tmp_path / "some dir with spaces"
        odd.mkdir()
        db_file = odd / "radar.db"
        sqlite3.connect(str(db_file)).close()
        sample = oh.measure_capacity(db_path=str(db_file))
        assert sample["db_exists"] is True

    def test_radar_db_dir_overrides_the_default_location(self, tmp_path,
                                                         monkeypatch):
        monkeypatch.setenv("RADAR_DB_DIR", str(tmp_path))
        monkeypatch.delenv("RADAR_DB_PATH", raising=False)
        assert oh.default_db_path() == str(tmp_path / "radar.db")
        assert oh.backup_marker_path() == tmp_path / "backup_state.json"

    def test_radar_db_path_still_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RADAR_DB_DIR", str(tmp_path))
        monkeypatch.setenv("RADAR_DB_PATH", "/explicit/radar.db")
        assert oh.default_db_path() == "/explicit/radar.db"


class TestCapacityEstimate:
    def _samples(self, oh_db, points):
        """Seed the ledger with historical capacity samples."""
        for ts, db_bytes in points:
            l5_common.append_result(
                oh_db, check_id=oh.CHECK_ID, ts=ts,
                target=oh.CAPACITY_TARGET, verdict="OK",
                measured={"db_bytes": db_bytes, "total_bytes": db_bytes,
                          "signal_ledger_age_days": 1.0},
                expected={})

    def test_fewer_than_three_samples_is_insufficient(self, oh_db):
        now = time.time()
        self._samples(oh_db, [(now - 2 * DAY, 2 * GB), (now - DAY, 2.1 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == "capacity_samples_insufficient"

    def test_three_samples_produce_an_estimate(self, oh_db):
        now = time.time()
        self._samples(oh_db, [(now - 3 * DAY, 2.0 * GB),
                              (now - 2 * DAY, 2.1 * GB),
                              (now - DAY, 2.2 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["growth_bytes_per_day"] == pytest.approx(0.1 * GB,
                                                               rel=0.2)
        assert result["estimated_steady_state_bytes"] > 0

    def test_an_in_band_estimate_is_ok(self, oh_db):
        now = time.time()
        # ~0.1 GB/day with ~58 days to go -> well inside [3, 16] GB.
        self._samples(oh_db, [(now - 3 * DAY, 2.0 * GB),
                              (now - 2 * DAY, 2.1 * GB),
                              (now - DAY, 2.2 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["verdict"] == "OK"

    def test_a_runaway_estimate_warns(self, oh_db):
        now = time.time()
        self._samples(oh_db, [(now - 3 * DAY, 2.0 * GB),
                              (now - 2 * DAY, 4.0 * GB),
                              (now - DAY, 6.0 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["verdict"] == "WARN"
        assert result["reason"] == "capacity_estimate_divergent"

    def test_the_s3_band_is_recorded_with_the_verdict(self, oh_db):
        now = time.time()
        self._samples(oh_db, [(now - 3 * DAY, 2.0 * GB),
                              (now - 2 * DAY, 2.1 * GB),
                              (now - DAY, 2.2 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["accepted_band_gb"] == [3.0, 16.0]
        assert result["s3_estimate_gb"] == [6.0, 8.0]

    def test_the_estimate_is_flagged_as_early_below_seven_days(self, oh_db):
        now = time.time()
        self._samples(oh_db, [(now - 3 * DAY, 2.0 * GB),
                              (now - 2 * DAY, 2.1 * GB),
                              (now - DAY, 2.2 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["early_estimate"] is True

    def test_shrinking_data_does_not_produce_a_negative_projection(self, oh_db):
        now = time.time()
        self._samples(oh_db, [(now - 3 * DAY, 4.0 * GB),
                              (now - 2 * DAY, 3.0 * GB),
                              (now - DAY, 2.0 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["estimated_steady_state_bytes"] >= 0

    def test_a_db_failure_is_insufficient_not_ok(self, monkeypatch):
        monkeypatch.setattr(oh, "_db", lambda: _BrokenDB())
        result = _by_target(oh.evaluate_capacity())[oh.CAPACITY_TARGET]
        assert result["verdict"] == "INSUFFICIENT"

    def test_a_missing_database_is_insufficient_never_ok(self, oh_db,
                                                         tmp_path,
                                                         monkeypatch):
        monkeypatch.setenv("RADAR_DB_DIR", str(tmp_path / "nowhere"))
        monkeypatch.delenv("RADAR_DB_PATH", raising=False)
        result = _by_target(oh.evaluate_capacity())[oh.CAPACITY_TARGET]
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == oh.REASON_CAPACITY_UNREADABLE

    def test_a_phantom_zero_never_enters_the_growth_series(self, oh_db):
        now = time.time()
        # A run that could not see the database at all.
        l5_common.append_result(
            oh_db, check_id=oh.CHECK_ID, ts=now - 4 * DAY,
            target=oh.CAPACITY_TARGET, verdict="INSUFFICIENT",
            measured={"db_exists": False, "db_bytes": 0, "total_bytes": 0},
            expected={})
        self._samples(oh_db, [(now - 3 * DAY, 2.0 * GB),
                              (now - 2 * DAY, 2.1 * GB),
                              (now - DAY, 2.2 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["sample_count"] == 3, \
            "a zero-byte phantom must not be read as a collapse in usage"
        assert result["growth_bytes_per_day"] > 0

    def test_early_estimate_clears_after_a_week_of_samples(self, oh_db):
        now = time.time()
        self._samples(oh_db, [(now - 10 * DAY, 2.0 * GB),
                              (now - 5 * DAY, 2.5 * GB),
                              (now - DAY, 2.9 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        assert result["sample_span_days"] >= 7
        assert result["early_estimate"] is False

    def test_irregular_sample_intervals_are_fitted_not_averaged(self, oh_db):
        # Least squares over (ts, bytes): clustered samples must not skew
        # the slope the way a naive first-vs-last difference would.
        now = time.time()
        self._samples(oh_db, [(now - 8 * DAY, 1.0 * GB),
                              (now - 7.9 * DAY, 1.01 * GB),
                              (now - 7.8 * DAY, 1.02 * GB),
                              (now - DAY, 1.7 * GB)])
        result = _by_target(oh.evaluate_capacity(now=now))[oh.CAPACITY_TARGET]
        # True underlying rate is ~0.1 GB/day.
        assert result["growth_bytes_per_day"] == pytest.approx(0.1 * GB,
                                                               rel=0.35)


class _BrokenDB:
    def __getattr__(self, name):
        raise RuntimeError("db down")


# ── daily job / ledger ──────────────────────────────────────────────────────
class TestDailyJob:
    def test_run_records_a_capacity_sample_every_time(self, oh_db, marker):
        marker(age_hours=1)
        now = time.time()
        oh.run_daily_check_if_due(now=now)
        oh.run_daily_check_if_due(now=now + DAY)
        rows = [r for r in oh_db.l5_check_latest(oh.CHECK_ID, limit=200)
                if r["target"] == oh.CAPACITY_TARGET]
        assert len(rows) == 2, \
            "the growth series needs one sample per run, even when OK"

    def test_backup_findings_are_transition_only(self, oh_db, marker):
        marker(age_hours=51)
        now = time.time()
        oh.run_daily_check_if_due(now=now)
        oh.run_daily_check_if_due(now=now + DAY)
        rows = [r for r in oh_db.l5_check_latest(oh.CHECK_ID, limit=200)
                if r["target"] == "backup"]
        assert len(rows) == 1, "a stable backup outage must not repeat daily"

    def test_a_recovered_backup_closes_the_episode(self, oh_db, marker):
        now = time.time()
        marker(age_hours=51)
        oh.run_daily_check_if_due(now=now)
        marker(age_hours=1)
        oh.run_daily_check_if_due(now=now + DAY)
        rows = [r for r in oh_db.l5_check_latest(oh.CHECK_ID, limit=200)
                if r["target"] == "backup"]
        assert [r["verdict"] for r in rows] == ["OK", "ANOMALY"]

    def test_schedule_is_persisted(self, oh_db, marker):
        marker(age_hours=1)
        now = time.time()
        assert oh.run_daily_check_if_due(now=now) is True
        assert oh.run_daily_check_if_due(now=now + 60) is False
        job = oh_db.l5_job_get(oh.JOB_ID)
        assert job["next_run_at"] == pytest.approx(now + oh.JOB_INTERVAL_SEC)

    def test_failure_is_contained(self, monkeypatch):
        monkeypatch.setattr(oh, "_db", lambda: _BrokenDB())
        assert oh.run_daily_check_if_due(now=time.time()) is False


class TestSnapshot:
    def test_snapshot_shape(self, oh_db, marker):
        marker(age_hours=3)
        snap = oh.snapshot()
        for field in ("job_id", "job_last_run_at", "job_next_run_at", "counts",
                      "backup", "capacity"):
            assert field in snap, field

    def test_snapshot_surfaces_the_backup_age(self, oh_db, marker):
        marker(age_hours=3)
        snap = oh.snapshot()
        assert snap["backup"]["age_hours"] == pytest.approx(3, abs=0.1)
        assert snap["backup"]["verdict"] == "OK"

    def test_snapshot_reports_unknown_backup_age_loudly(self, oh_db, marker):
        marker(age_hours=None)
        snap = oh.snapshot()
        assert snap["backup"]["verdict"] == "INSUFFICIENT"

    def test_snapshot_is_json_serializable(self, oh_db, marker):
        marker(age_hours=1)
        json.dumps(oh.snapshot())


# ── the standalone measurement path ─────────────────────────────────────────
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestStandaloneMeasurement:
    """The prod measurement runs via `docker exec`. It must NOT import the
    radar package: that executes radar/__init__.py, which boots a second
    copy of the application inside the running container.

    (fork() warns because the gevent-patched test process is threaded; the
    child execs a fresh interpreter immediately, which is the point.)
    """

    SCRIPT = REPO_ROOT / "radar" / "verification" / "ops_health.py"

    def _run(self, db_dir, stdin=None):
        env = {**os.environ, "RADAR_DB_DIR": str(db_dir)}
        env.pop("RADAR_DB_PATH", None)
        args = [sys.executable, "-"] if stdin else [sys.executable,
                                                    str(self.SCRIPT)]
        return subprocess.run(args, capture_output=True, text=True,
                              cwd=str(REPO_ROOT), env=env, timeout=120,
                              input=stdin)

    @pytest.fixture
    def seeded_db_dir(self, tmp_path):
        """An isolated persistence dir — no dependence on the repo's DB."""
        import sqlite3
        sqlite3.connect(str(tmp_path / "radar.db")).close()
        return tmp_path

    def test_running_the_file_directly_does_not_boot_the_app(self,
                                                             seeded_db_dir):
        proc = self._run(seeded_db_dir)
        assert proc.returncode == 0, proc.stderr
        combined = proc.stdout + proc.stderr
        for marker_text in ("[DB] Startup", "bg_scoring", "[Startup]",
                            "[Persist]", "[Scenarios]", "[Sensor/"):
            assert marker_text not in combined, \
                f"app boot detected: {marker_text}"

    def test_the_report_carries_the_numbers_the_owner_needs(self,
                                                            seeded_db_dir):
        out = self._run(seeded_db_dir).stdout
        for field in ("db_bytes", "wal_bytes", "tables",
                      "signal_ledger_age_days", "db_exists"):
            assert field in out, field

    def test_the_report_is_machine_readable(self, seeded_db_dir):
        payload = json.loads(self._run(seeded_db_dir).stdout)
        assert payload["db_bytes"] >= 0
        assert isinstance(payload["tables"], list)
        assert payload["db_exists"] is True

    def test_a_missing_database_exits_nonzero(self, tmp_path):
        proc = self._run(tmp_path / "nowhere")
        assert proc.returncode == 1
        assert "database not found" in proc.stderr

    def test_piping_the_source_into_stdin_is_refused(self, seeded_db_dir):
        # The live failure mode: `docker exec -i ... python3 -` resolved no
        # persistence path and printed db_bytes=0, which reads exactly like
        # an empty database.
        source = self.SCRIPT.read_text(encoding="utf-8")
        proc = self._run(seeded_db_dir, stdin=source)
        assert proc.returncode == 2
        assert "not via stdin" in proc.stderr

    def test_the_wrapper_script_is_the_documented_entrypoint(self):
        wrapper = (REPO_ROOT / "scripts" / "run_ops_health.sh").read_text(
            encoding="utf-8")
        assert "docker exec" in wrapper
        assert "/app/radar/verification/ops_health.py" in wrapper
        assert "-m radar.verification.ops_health" in wrapper, \
            "the wrapper must document why -m is unsupported"

    def test_the_module_warns_against_the_dash_m_form(self):
        doc = oh.__doc__ or ""
        assert "-m radar.verification.ops_health" in doc
        assert "run_ops_health.sh" in doc


# ── wiring ──────────────────────────────────────────────────────────────────
class TestWiring:
    def test_scheduler_runs_the_daily_check(self):
        src = (REPO_ROOT / "radar" / "scheduler.py").read_text(encoding="utf-8")
        assert "ops_health" in src

    def test_self_eval_exposes_the_block_and_its_error(self):
        src = (REPO_ROOT / "radar" / "routes" / "conclusions_v2.py").read_text(
            encoding="utf-8")
        assert 'out["ops_health"]' in src
        assert 'out["ops_health_error"]' in src

    def test_intel_guide_documents_the_block(self):
        src = (REPO_ROOT / "index.html").read_text(encoding="utf-8")
        assert "ops_health" in src

    def test_the_backup_script_writes_a_visible_marker(self):
        # Backups land on the HOST; the container cannot see them. The
        # script therefore records completion where the app can read it.
        src = (REPO_ROOT / "scripts" / "backup_radar_db.sh").read_text(
            encoding="utf-8")
        assert "backup_state.json" in src
        assert "last_backup_at" in src

    def test_the_job_is_registered_in_the_heartbeat(self):
        assert oh.JOB_ID in {j.job_id for j in l5_common.known_jobs()}
