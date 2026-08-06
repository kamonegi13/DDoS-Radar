"""radar.verification.l5_common — shared plumbing for the L5 checks.

Extracted at the third copy (WP-1.3), not before: firing_monitor (WP-1.1)
and config_reachability (WP-1.2) had each grown the same four pieces, and
window_unit_health would have been the third.

    db() / now()      the lazy DB handle and the injectable clock
    append_result()   one ledger row with first_detected_at carry-forward
    record_results()  the append policy, including OK recovery rows
    run_daily_if_due() the persistent-schedule job skeleton (the F-01 fix)

Two append policies exist and both are deliberate:

    transition_only=False  every non-OK result is written on every run, so
                           the ledger doubles as a daily census. Right for a
                           bounded catalog (42 sensor flags).
    transition_only=True   only verdict changes are written. Right when the
                           finding set is large and stable — 94 bypassing
                           config keys would otherwise add 94 rows a day.

`db_fn` is passed in rather than resolved here so each check keeps its own
module-level `_db` seam for tests to bind to a throwaway database.

Everything is exception-contained (NP3): a verification failure degrades to
a log line, never to a worker outage.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Callable, Optional

log = logging.getLogger("radar")

DAY = 86400.0
JOB_INTERVAL_SEC = 86400.0
SUMMARY_TARGET = "__summary__"

# l5_check_result retention, aligned with the conclusions-ledger horizon
# (ADR-V3-005): a finding must stay queryable at least as long as the
# conclusions it casts doubt on.
CHECK_RESULT_RETENTION_DAYS = 365

# Worst-first. Callers report the first verdict present.
VERDICT_ORDER = ("ANOMALY", "WARN", "INSUFFICIENT", "OK")


def db():
    """Lazy singleton accessor. Each check aliases this as its own `_db`."""
    from radar.database import db as _db
    return _db


def now(value: Optional[float]) -> float:
    return time.time() if value is None else value


_UNSET = object()   # "caller has not looked" — distinct from "no row exists"


def append_result(handle, *, check_id: str, ts: float, target: str,
                  verdict: str, measured: dict, expected: dict,
                  ttl_sec: Optional[float] = None,
                  previous=_UNSET) -> None:
    """Append one ledger row, carrying first_detected_at across runs.

    Carry-forward only continues an episode: it requires the *latest* row
    for this target to hold the same verdict. Recovery rows are what make
    that correct — without them a fixed-then-broken-again target would
    inherit the first episode's start time and read as one long incident.

    `previous` lets a caller that already fetched the latest row pass it in
    (record_results does), avoiding a second identical SELECT per appended
    target. None means "looked, found nothing"; omitting it means "have not
    looked", and only then is the query issued here.
    """
    if previous is _UNSET:
        previous = handle.l5_check_last_for_target(check_id, target)
    if (previous and previous.get("verdict") == verdict
            and previous.get("first_detected_at") is not None):
        first_detected_at = previous["first_detected_at"]
    else:
        first_detected_at = ts
    handle.l5_check_append(
        ts=ts, check_id=check_id, target=target, verdict=verdict,
        measured_json=json.dumps(measured, sort_keys=True, default=str),
        expected_json=json.dumps(expected, sort_keys=True, default=str),
        first_detected_at=first_detected_at,
        ttl_sec=(CHECK_RESULT_RETENTION_DAYS * DAY if ttl_sec is None
                 else ttl_sec),
    )


def _should_append(handle, check_id: str, target: str, verdict: str,
                   transition_only: bool) -> tuple[bool, object]:
    """(should append, the latest row) for this result.

    The latest row is returned so append_result can reuse it instead of
    re-issuing the same SELECT. Under the census policy the lookup is
    skipped entirely for non-OK results, which is why the second element
    is _UNSET there rather than None — "not looked at" is not "absent".
    """
    if verdict != "OK" and not transition_only:
        return (True, _UNSET)
    previous = handle.l5_check_last_for_target(check_id, target)
    if verdict == "OK":
        # Nothing to close — never append daily no-ops.
        return (bool(previous) and previous.get("verdict") != "OK", previous)
    return (not previous or previous.get("verdict") != verdict, previous)


def record_results(handle, *, check_id: str, ts: float, rows: list,
                   transition_only: bool = False,
                   ttl_sec: Optional[float] = None) -> dict:
    """Append the rows this policy calls for. Returns the verdict counts.

    `rows` are dicts of {target, verdict, measured, expected}.
    """
    counts = {verdict: 0 for verdict in VERDICT_ORDER}
    for row in rows:
        verdict = row["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        should, previous = _should_append(handle, check_id, row["target"],
                                          verdict, transition_only)
        if not should:
            continue
        append_result(handle, check_id=check_id, ts=ts, target=row["target"],
                      verdict=verdict, measured=row["measured"],
                      expected=row["expected"], ttl_sec=ttl_sec,
                      previous=previous)
    return counts


def summary_verdict(counts: dict) -> str:
    """Worst verdict present, for the per-run summary row."""
    if counts.get("ANOMALY"):
        return "ANOMALY"
    return "WARN" if counts.get("WARN") else "OK"


def run_daily_if_due(*, db_fn: Callable, job_id: str, run_fn: Callable,
                     interval_sec: float = JOB_INTERVAL_SEC,
                     now_ts: Optional[float] = None,
                     label: Optional[str] = None) -> bool:
    """Run `run_fn(handle, ts)` if the persisted schedule says it is due.

    Returns True when the check actually ran. Driven by `next_run_at` in
    l5_job_state rather than an in-process counter, so an overdue job runs
    on the first tick after a restart instead of being skipped forever
    (defect F-01).
    """
    ts = now(now_ts)
    try:
        handle = db_fn()
        job = handle.l5_job_get(job_id)
        if job and job.get("next_run_at") is not None and job["next_run_at"] > ts:
            return False
        run_fn(handle, ts)
        handle.l5_job_set(job_id, last_run_at=ts, next_run_at=ts + interval_sec)
        return True
    except Exception as exc:  # noqa: BLE001 - a failed check must not kill the worker
        log.warning("%s daily check failed: %s", label or job_id, exc)
        return False
