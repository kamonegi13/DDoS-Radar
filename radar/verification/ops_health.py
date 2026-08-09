"""radar.verification.ops_health — WP-0.3, the fifth L5 check.

Two operational axes that no other check covers:

  backup age (S4-NF-053)
      The 04:00 backup cron ran for a month with a PATH that omitted the
      docker CLI. Every run failed with "command not found", into a log
      nobody read; backups stopped 2026-07-04 and nobody noticed until
      08-03. The retention setting claimed 14 generations and three
      existed. So the rule here is negative and load-bearing: **an
      unknown backup age is never OK**. INSUFFICIENT is the honest
      verdict, because "we cannot tell" is exactly what that month
      looked like from the inside.

      Backups land on the HOST (`<repo>/backups/`), while the container's
      database lives in the `noroshi_radar-data` volume — the application
      cannot see the backup files at all. scripts/backup_radar_db.sh
      therefore writes a small marker into the mounted persistence
      directory after a successful run, and this check reads its age.

  capacity
      ADR-V3-005 widened signal-ledger retention to 60 days on S3's
      estimate that the database settles at 6-8 GB. Nothing has ever
      checked that against reality. Each daily run records a size sample,
      and once there are enough of them the steady state is projected and
      compared against a deliberately wide band. The check flags
      divergence for a human; it does not conclude that the ADR is wrong.

Import contract: module scope is stdlib-only, and `l5_common` is imported
only when this file is used as a module. That is what lets the one-time
production measurement run **by file path**, without executing
radar/__init__.py — which would boot a second copy of the whole
application (DB migrations, ~30 sensor threads) inside the running
container.

    THE SUPPORTED INVOCATION IS:   scripts/run_ops_health.sh

    NEVER run this with `python3 -m radar.verification.ops_health`.
    The -m form imports the parent packages FIRST, so radar/__init__.py
    executes and the second app boots *before* the `__name__` guard below
    is ever evaluated. No guard inside this file can prevent that: by the
    time any line here runs, the damage is done. Only invocation by file
    path (`python3 /app/radar/verification/ops_health.py`) keeps the
    module out of the package import machinery.

    Follow-up, not fixed here: the root cause is that radar/__init__.py
    spawns threads and touches the database at import time. Making imports
    side-effect-free is v3 L0/L6 territory.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("radar")

JOB_ID = "ops_health_daily"
CHECK_ID = "ops_health"
JOB_INTERVAL_SEC = 86400.0
BACKUP_TARGET = "backup"
CAPACITY_TARGET = "capacity_sample"

# ── backup thresholds, with their provenance ───────────────────────────────
# The cron is `0 4 * * *` (scripts/backup_radar_db.sh), so a healthy age is
# under a day. Two hours of slack absorbs a slow run or a clock nudge; two
# consecutive missed dailies is not slack, it is an outage.
BACKUP_CADENCE_HOURS = 24.0
BACKUP_SLACK_HOURS = 2.0
BACKUP_WARN_AGE_HOURS = BACKUP_CADENCE_HOURS + BACKUP_SLACK_HOURS       # 26
BACKUP_ANOMALY_AGE_HOURS = 2 * BACKUP_CADENCE_HOURS + BACKUP_SLACK_HOURS  # 50
BACKUP_MARKER_NAME = "backup_state.json"

# ── capacity constants ─────────────────────────────────────────────────────
CAPACITY_MIN_SAMPLES = 3
CAPACITY_EARLY_ESTIMATE_DAYS = 7.0
SIGNAL_LEDGER_TARGET_DAYS = 60.0        # ADR-V3-005 / WP-0.1
S3_ESTIMATE_GB = (6.0, 8.0)             # S3-data-migration.md:489
# Deliberately wide: the point is to catch an order-of-magnitude surprise,
# not to relitigate S3's arithmetic on a week of data.
CAPACITY_BAND_GB = (3.0, 16.0)
TOP_TABLE_COUNT = 10
GB = 1024 ** 3
HOUR = 3600.0
DAY = 86400.0

# COUNT(*) is a full scan. Counting every table (60-100+, several with
# ~1M rows) blocks the sqlite connection for seconds inside the gevent
# loop, every day, growing with the schema. Only tables whose row count
# actually answers a capacity question are counted; the database file size
# remains the primary metric regardless of what this list contains.
TREND_TABLES: tuple[str, ...] = (
    "sensor_observation_ts",      # the signal ledger — ADR-V3-005's subject
    "conclusions",
    "scenario_contribution_log",
    "scenario_tl_observation",
    "time_series",
    "time_series_ts",
    "l5_check_result",
    "llm_call_log",
    "llm_prompts",
    "hod_baseline",
    "sensor_flag_fire_log",
    "config_read_stats",
)
# Hard wall-clock budget for the counting pass. Exceeding it truncates the
# list and says so — a partial answer must never look like a complete one.
TABLE_COUNT_BUDGET_SEC = 5.0

_DEFAULT_PERSISTENCE_DIR = Path(__file__).resolve().parent.parent / "persistence"

REASON_BACKUP_FRESH = "backup_fresh"
REASON_BACKUP_OVERDUE = "backup_overdue"
REASON_BACKUP_SILENT = "backup_silent"
# Three distinct ways the age can be unknown. All INSUFFICIENT — the
# never-OK guarantee is unchanged — but they have different repairs: no
# backup has run, the marker is damaged, or a clock is wrong.
REASON_BACKUP_ABSENT = "backup_marker_absent"
REASON_BACKUP_CORRUPT = "backup_marker_corrupt"
REASON_BACKUP_SKEW = "backup_marker_clock_skew"
REASON_CAPACITY_OK = "capacity_within_band"
REASON_CAPACITY_DIVERGENT = "capacity_estimate_divergent"
REASON_CAPACITY_INSUFFICIENT = "capacity_samples_insufficient"
REASON_CAPACITY_UNREADABLE = "capacity_unreadable"


def _db():
    """Lazy DB handle. Imported here, never at module scope, so this file
    stays runnable as a standalone script (see the module docstring)."""
    from radar.verification import l5_common
    return l5_common.db()


def _now(value: Optional[float]) -> float:
    return time.time() if value is None else value


def persistence_dir() -> Path:
    """The mounted persistence directory.

    RADAR_DB_DIR lets a caller (tests, or an operator inspecting a copy)
    point the whole check at an isolated directory without depending on
    where this file happens to live.
    """
    override = os.environ.get("RADAR_DB_DIR")
    return Path(override) if override else _DEFAULT_PERSISTENCE_DIR


def backup_marker_path() -> Path:
    """Where scripts/backup_radar_db.sh records a completed backup."""
    return persistence_dir() / BACKUP_MARKER_NAME


def default_db_path() -> str:
    """The same path the application resolves its database from."""
    return os.environ.get("RADAR_DB_PATH") or str(persistence_dir() / "radar.db")


# ── S4-NF-053: backup age ──────────────────────────────────────────────────
def read_backup_marker(path: Optional[Path] = None
                       ) -> tuple[Optional[dict], str, str]:
    """(marker, reason, evidence). Never raises — an unreadable marker is
    itself the finding, and which kind it is decides the repair."""
    target = backup_marker_path() if path is None else Path(path)
    if not target.exists():
        return (None, REASON_BACKUP_ABSENT,
                f"no backup marker at {target}; no backup has completed "
                f"since the marker was introduced")
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return (None, REASON_BACKUP_CORRUPT,
                f"backup marker unreadable: {type(exc).__name__}: {exc}")
    if not isinstance(payload, dict) or payload.get("last_backup_at") is None:
        return (None, REASON_BACKUP_CORRUPT,
                "backup marker carries no last_backup_at timestamp")
    return (payload, "", "")


def _backup_verdict(age_hours: float) -> tuple[str, str]:
    """(verdict, reason) for a known backup age. Pure."""
    if age_hours >= BACKUP_ANOMALY_AGE_HOURS:
        return ("ANOMALY", REASON_BACKUP_SILENT)
    if age_hours >= BACKUP_WARN_AGE_HOURS:
        return ("WARN", REASON_BACKUP_OVERDUE)
    return ("OK", REASON_BACKUP_FRESH)


def evaluate_backup(now: Optional[float] = None) -> list[dict]:
    """One result describing how long ago the last backup completed."""
    ts = _now(now)
    marker, reason, evidence = read_backup_marker()
    base = {"axis": "backup", "target": BACKUP_TARGET,
            "warn_age_hours": BACKUP_WARN_AGE_HOURS,
            "anomaly_age_hours": BACKUP_ANOMALY_AGE_HOURS,
            "marker_path": str(backup_marker_path())}
    if marker is None:
        return [{**base, "verdict": "INSUFFICIENT", "reason": reason,
                 "age_hours": None, "evidence": evidence}]

    age_hours = (ts - float(marker["last_backup_at"])) / HOUR
    if age_hours < 0:
        # A timestamp from the future means a skewed clock somewhere; it
        # must not be allowed to render as a fresh backup.
        return [{**base, "verdict": "INSUFFICIENT",
                 "reason": REASON_BACKUP_SKEW, "age_hours": None,
                 "evidence": f"marker timestamp is {abs(age_hours):.1f}h in "
                             f"the future — clock skew"}]

    verdict, reason = _backup_verdict(age_hours)
    return [{**base, "verdict": verdict, "reason": reason,
             "age_hours": round(age_hours, 3),
             "last_backup_at": marker["last_backup_at"],
             "backup_file": marker.get("backup_file"),
             "size_bytes": marker.get("size_bytes"),
             "evidence": ""}]


# ── capacity measurement (stdlib only — runs standalone) ───────────────────
def _file_bytes(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _table_rows(conn, limit: int) -> tuple[list[dict], bool]:
    """(counted tables, truncated). Curated + time-budgeted.

    Each COUNT(*) is a full scan holding the sqlite connection, which in
    this process means holding the gevent loop. Only the curated trend
    tables are counted, and the pass abandons itself if it exceeds its
    budget — reporting the truncation rather than a quietly short list.
    """
    existing = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    counted: list[dict] = []
    truncated = False
    started = time.monotonic()
    for name in TREND_TABLES:
        if name not in existing:
            continue
        if time.monotonic() - started > TABLE_COUNT_BUDGET_SEC:
            log.warning("ops-health: table-count budget (%.0fs) exhausted "
                        "after %d tables; list truncated",
                        TABLE_COUNT_BUDGET_SEC, len(counted))
            truncated = True
            break
        try:
            rows = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        except sqlite3.Error as exc:      # noqa: PERF203 - per-table tolerance
            log.debug("ops-health: cannot count %s: %s", name, exc)
            continue
        counted.append({"table": name, "rows": int(rows)})
    counted.sort(key=lambda t: t["rows"], reverse=True)
    return (counted[:limit], truncated)


def measure_capacity(db_path: Optional[str] = None,
                     now: Optional[float] = None,
                     top_tables: int = TOP_TABLE_COUNT) -> dict:
    """Read-only size / row-count snapshot. Never raises, never writes."""
    ts = _now(now)
    path = default_db_path() if db_path is None else db_path
    exists = os.path.exists(path)
    sample: dict[str, Any] = {
        "measured_at": ts,
        "db_path": path,
        # Explicit: a missing file and an empty one both report 0 bytes,
        # and conflating them is how a nonexistent path turns into a
        # phantom "the database is empty" data point.
        "db_exists": exists,
        "db_bytes": _file_bytes(path),
        "wal_bytes": _file_bytes(f"{path}-wal"),
        "shm_bytes": _file_bytes(f"{path}-shm"),
        "tables": [],
        "tables_truncated": False,
        "signal_ledger_rows": 0,
        "signal_ledger_age_days": None,
    }
    sample["total_bytes"] = (sample["db_bytes"] + sample["wal_bytes"]
                             + sample["shm_bytes"])
    if not exists:
        return sample

    try:
        uri = f"file:{urllib.parse.quote(path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        log.warning("ops-health: cannot open %s read-only: %s", path, exc)
        return sample
    try:
        sample["tables"], sample["tables_truncated"] = \
            _table_rows(conn, top_tables)
        row = conn.execute(
            "SELECT COUNT(*), MIN(ts) FROM sensor_observation_ts").fetchone()
        if row is not None:
            sample["signal_ledger_rows"] = int(row[0] or 0)
            if row[1] is not None:
                sample["signal_ledger_age_days"] = round(
                    (ts - float(row[1])) / DAY, 3)
    except sqlite3.Error as exc:
        log.warning("ops-health: capacity query failed: %s", exc)
    finally:
        conn.close()
    return sample


# ── capacity trend ─────────────────────────────────────────────────────────
def _historical_samples(handle, limit: int = 120) -> list[tuple[float, float]]:
    """[(ts, total_bytes)] from the ledger, oldest first."""
    points: list[tuple[float, float]] = []
    for row in handle.l5_check_latest(CHECK_ID, limit=limit):
        if row["target"] != CAPACITY_TARGET:
            continue
        try:
            measured = json.loads(row["measured_json"] or "{}")
        except ValueError:
            continue
        if measured.get("db_exists") is False:
            continue    # a run that could not see the database at all
        size = measured.get("total_bytes", measured.get("db_bytes"))
        if size:        # zero is never a real measurement, only a missing file
            points.append((float(row["ts"]), float(size)))
    points.sort()
    return points


def _growth_per_day(points: list[tuple[float, float]]) -> Optional[float]:
    """Least-squares slope in bytes/day. None when it cannot be computed."""
    n = len(points)
    if n < 2:
        return None
    mean_t = sum(p[0] for p in points) / n
    mean_y = sum(p[1] for p in points) / n
    denominator = sum((p[0] - mean_t) ** 2 for p in points)
    if denominator <= 0:
        return None
    slope_per_sec = sum((p[0] - mean_t) * (p[1] - mean_y)
                        for p in points) / denominator
    return slope_per_sec * DAY


def evaluate_capacity(now: Optional[float] = None) -> list[dict]:
    """Current size plus, once there is enough history, a 60-day estimate."""
    ts = _now(now)
    sample = measure_capacity(now=ts)
    base = {"axis": "capacity", "target": CAPACITY_TARGET,
            "db_exists": sample["db_exists"],
            "db_bytes": sample["db_bytes"], "wal_bytes": sample["wal_bytes"],
            "total_bytes": sample["total_bytes"], "tables": sample["tables"],
            "tables_truncated": sample["tables_truncated"],
            "signal_ledger_rows": sample["signal_ledger_rows"],
            "signal_ledger_age_days": sample["signal_ledger_age_days"],
            "accepted_band_gb": list(CAPACITY_BAND_GB),
            "s3_estimate_gb": list(S3_ESTIMATE_GB),
            "retention_target_days": SIGNAL_LEDGER_TARGET_DAYS}

    if not sample["db_exists"]:
        # Never let a nonexistent database contribute a zero-byte point to
        # the growth series: the trend would read as "usage collapsed".
        return [{**base, "verdict": "INSUFFICIENT",
                 "reason": REASON_CAPACITY_UNREADABLE,
                 "evidence": f"database file not found: {sample['db_path']}",
                 "sample_count": None}]

    try:
        points = _historical_samples(_db())
    except Exception as exc:  # noqa: BLE001 - degrade to INSUFFICIENT, not OK
        log.warning("ops-health: capacity history unavailable: %s", exc)
        return [{**base, "verdict": "INSUFFICIENT",
                 "reason": REASON_CAPACITY_UNREADABLE, "evidence": str(exc),
                 "sample_count": None}]

    if len(points) < CAPACITY_MIN_SAMPLES:
        return [{**base, "verdict": "INSUFFICIENT",
                 "reason": REASON_CAPACITY_INSUFFICIENT,
                 "sample_count": len(points),
                 "samples_required": CAPACITY_MIN_SAMPLES}]

    growth = _growth_per_day(points) or 0.0
    span_days = (points[-1][0] - points[0][0]) / DAY
    age_days = sample["signal_ledger_age_days"] or 0.0
    days_remaining = max(0.0, SIGNAL_LEDGER_TARGET_DAYS - age_days)
    estimate = max(0.0, sample["total_bytes"] + growth * days_remaining)
    estimate_gb = estimate / GB
    low, high = CAPACITY_BAND_GB
    divergent = estimate_gb < low or estimate_gb > high

    return [{**base,
             "verdict": "WARN" if divergent else "OK",
             "reason": (REASON_CAPACITY_DIVERGENT if divergent
                        else REASON_CAPACITY_OK),
             "sample_count": len(points),
             "sample_span_days": round(span_days, 3),
             "growth_bytes_per_day": round(growth, 1),
             "days_to_retention_target": round(days_remaining, 2),
             "estimated_steady_state_bytes": round(estimate, 1),
             "estimated_steady_state_gb": round(estimate_gb, 3),
             # Below a week of samples the slope is dominated by whatever
             # the sensors happened to do; the number is directional only.
             "early_estimate": span_days < CAPACITY_EARLY_ESTIMATE_DAYS}]


def evaluate(now: Optional[float] = None) -> list[dict]:
    return evaluate_backup(now=now) + evaluate_capacity(now=now)


# ── the daily job ──────────────────────────────────────────────────────────
_BACKUP_MEASURED = ("reason", "age_hours", "last_backup_at", "backup_file",
                    "size_bytes", "evidence", "marker_path")
_CAPACITY_MEASURED = ("reason", "db_exists", "db_bytes", "wal_bytes",
                      "total_bytes", "tables", "tables_truncated",
                      "evidence", "signal_ledger_rows",
                      "signal_ledger_age_days", "sample_count",
                      "sample_span_days", "growth_bytes_per_day",
                      "days_to_retention_target",
                      "estimated_steady_state_bytes",
                      "estimated_steady_state_gb", "early_estimate")


def _measured(result: dict, fields) -> dict:
    return {k: result[k] for k in fields if k in result}


def _run(handle, ts: float) -> None:
    """One ops-health run. Called by the l5_common job skeleton."""
    from radar.verification import l5_common

    backup = evaluate_backup(now=ts)[0]
    capacity = evaluate_capacity(now=ts)[0]

    # Backup findings are transition-only: a standing outage must not add a
    # row a day, or the ledger stops showing when it started.
    counts = l5_common.record_results(
        handle, check_id=CHECK_ID, ts=ts, transition_only=True,
        rows=[{"target": backup["target"], "verdict": backup["verdict"],
               "measured": _measured(backup, _BACKUP_MEASURED),
               "expected": {"warn_age_hours": BACKUP_WARN_AGE_HOURS,
                            "anomaly_age_hours": BACKUP_ANOMALY_AGE_HOURS,
                            "cadence_hours": BACKUP_CADENCE_HOURS}}])

    # The capacity row is appended unconditionally: it IS the growth series,
    # so an OK verdict still has to leave a data point behind.
    counts[capacity["verdict"]] = counts.get(capacity["verdict"], 0) + 1
    l5_common.append_result(
        handle, check_id=CHECK_ID, ts=ts, target=CAPACITY_TARGET,
        verdict=capacity["verdict"],
        measured=_measured(capacity, _CAPACITY_MEASURED),
        expected={"accepted_band_gb": list(CAPACITY_BAND_GB),
                  "s3_estimate_gb": list(S3_ESTIMATE_GB),
                  "retention_target_days": SIGNAL_LEDGER_TARGET_DAYS})

    if counts.get("ANOMALY"):
        log.warning("[OpsHealth] backup %s (age %sh), capacity %s",
                    backup["reason"], backup["age_hours"], capacity["reason"])


def run_daily_check_if_due(now: Optional[float] = None) -> bool:
    """Run the ops-health check if the persisted schedule says it is due."""
    from radar.verification import l5_common
    return l5_common.run_daily_if_due(
        db_fn=_db, job_id=JOB_ID, run_fn=_run, interval_sec=JOB_INTERVAL_SEC,
        now_ts=now, label="ops-health")


# ── AP3 self-evaluation surface ────────────────────────────────────────────
def snapshot(now: Optional[float] = None) -> dict:
    """Live ops-health summary for /api/v2/self_eval."""
    from radar.verification import l5_common

    ts = _now(now)
    backup = evaluate_backup(now=ts)[0]
    capacity = evaluate_capacity(now=ts)[0]
    try:
        job = _db().l5_job_get(JOB_ID) or {}
        job_lookup_error = None
    except Exception as exc:  # noqa: BLE001 - visible failure, not a blank
        log.warning("ops-health job lookup failed: %s", exc)
        job, job_lookup_error = {}, str(exc)

    results = [backup, capacity]
    counts = {verdict: sum(1 for r in results if r["verdict"] == verdict)
              for verdict in l5_common.VERDICT_ORDER}
    out = {
        "job_id": JOB_ID,
        "job_last_run_at": job.get("last_run_at"),
        "job_next_run_at": job.get("next_run_at"),
        "counts": counts,
        "backup": _measured(backup, ("verdict",) + _BACKUP_MEASURED),
        "capacity": _measured(capacity, ("verdict",) + _CAPACITY_MEASURED),
    }
    if job_lookup_error is not None:
        out["job_lookup_error"] = job_lookup_error
    return out


# Registration is skipped in script mode so the standalone measurement does
# not import the radar package (see the module docstring).
if __name__ != "__main__":
    from radar.verification import l5_common as _l5

    _l5.register_job(JOB_ID, label="Backup age / capacity trend",
                     interval_sec=JOB_INTERVAL_SEC)


if __name__ == "__main__":
    # Supported invocation:  scripts/run_ops_health.sh
    # (which runs: docker exec noroshi python3 /app/radar/verification/ops_health.py)
    #
    # Refuse to run when this file was not executed from disk — piping the
    # source into `python3 -` leaves the __file__-relative persistence path
    # unresolvable, and every size then reads 0, which is indistinguishable
    # from an empty database. Failing loudly beats reporting zeros.
    _source = globals().get("__file__")
    if not _source or not Path(_source).is_file():
        print("ERROR: run this file from disk (scripts/run_ops_health.sh), "
              "not via stdin: the persistence path cannot be resolved and "
              "every measurement would read 0 bytes.", file=sys.stderr)
        sys.exit(2)

    _marker, _reason, _evidence = read_backup_marker()
    _report = measure_capacity()
    _report["backup_marker"] = _marker or {"reason": _reason,
                                           "evidence": _evidence}
    if not _report["db_exists"]:
        print(f"ERROR: database not found at {_report['db_path']} "
              f"(set RADAR_DB_DIR or RADAR_DB_PATH)", file=sys.stderr)
        print(json.dumps(_report, indent=2, sort_keys=True, default=str))
        sys.exit(1)
    print(json.dumps(_report, indent=2, sort_keys=True, default=str))
