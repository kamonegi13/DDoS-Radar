"""radar.verification.config_reachability — runtime half of WP-1.2.

Joins the two axes S5-VERIF-014 asks for and turns them into verdicts:

    static   radar.verification.config_static_audit — does a code path that
             resolves this key through the 3-layer chain exist at all?
    runtime  radar.config_layered's read tracker, persisted into
             `config_read_stats` — was such a path actually executed?

Neither axis alone is sufficient. A static gate cannot see the 71 keys
frozen into module constants at import (P3:156), and the runtime tracker
cannot indict a key the process simply had no reason to read yet — hence
the 24h observation floor below, under which the runtime axis reports
INSUFFICIENT rather than accusing anything (S5-VERIF-014, NP5+8).

Ledger discipline: ~95 keys bypass resolution today and that number moves
slowly. Writing 95 rows a day would bury the transitions that matter, so a
target's row is appended only when its verdict *changes* (first run
baselines everything non-OK, and a fixed key gets one closing OK row).
One summary row per run carries the counts plus a hash of the full
classification, so a change that verdict equality cannot see is still
detectable. Same contract as WP-1.1's firing_monitor.

Everything is exception-contained (NP3) and read failures degrade to
UNKNOWN, never to a green default (S5-VERIF-006).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

from radar import config_layered
from radar.verification import config_static_audit as static_audit

log = logging.getLogger("radar")

JOB_ID = "config_reachability_daily"
CHECK_ID = "config_reachability"
JOB_INTERVAL_SEC = 86400.0
SUMMARY_TARGET = "__summary__"
TARGET_PREFIX = "config:"

_DAY = 86400.0
# S5-VERIF-014: "監査は起動から 24 時間以上稼働した実績に基づく MUST".
MIN_RUNTIME_OBSERVATION_SEC = 86400.0
# Aligned with firing_monitor / ADR-V3-005 — a finding must outlive the
# conclusions it casts doubt on.
CHECK_RESULT_RETENTION_DAYS = 365

_VERDICT_ORDER = ("ANOMALY", "WARN", "INSUFFICIENT", "OK")

# Verdict reasons, kept greppable.
REASON_BYPASSED = "bypassed"
REASON_MISMATCH = "default_mismatch"
REASON_BYPASSED_AND_MISMATCH = "bypassed_and_default_mismatch"
REASON_PARTIAL = "partial_resolution"
REASON_DEAD = "dead_key"
REASON_NEVER_READ = "registered_never_read"
REASON_WINDOW_SHORT = "runtime_window_too_short"
REASON_WINDOW_UNKNOWN = "runtime_window_unknown"
REASON_OK = "resolving"


def _db():
    """Lazy singleton accessor (the seam tests bind to a temp DB)."""
    from radar.database import db
    return db


def _audit() -> static_audit.AuditResult:
    """Seam for tests; production shares one memoised repo scan."""
    return static_audit.audit_cached()


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def target_for(key: str) -> str:
    return f"{TARGET_PREFIX}{key}"


# ── runtime axis ────────────────────────────────────────────────────────────
def flush_read_stats(now: float | None = None) -> int:
    """Merge the in-process read counters into `config_read_stats`.

    Drains the tracker in one critical section (so a read landing during
    the flush is never lost between a copy and a later clear) and folds the
    snapshot back on a failed write, so a transient DB error costs nothing.
    NP3 — never raises.
    """
    ts = _now(now)
    registered, unregistered = config_layered.drain_read_stats(now=ts)
    live = {**registered, **unregistered}
    if not live:
        return 0
    try:
        return _db().config_read_stats_merge(live, now=ts)
    except Exception as exc:  # noqa: BLE001 - a failed flush must not kill the job
        log.warning("config-reachability read-stat flush failed: %s", exc)
        config_layered.restore_read_stats(registered, unregistered)
        return 0


def _merge_entry(persisted: Optional[dict], live: Optional[dict]) -> dict:
    """One key's view across the persisted row and the live counters."""
    if persisted is None:
        return dict(live or {})
    if live is None:
        return dict(persisted)
    firsts = [v for v in (persisted.get("first_read_at"),
                          live.get("first_read_at")) if v is not None]
    lasts = [v for v in (persisted.get("last_read_at"),
                         live.get("last_read_at")) if v is not None]
    return {
        "first_considered_at": persisted.get("first_considered_at"),
        "first_read_at": min(firsts) if firsts else None,
        "last_read_at": max(lasts) if lasts else None,
        "read_count": (persisted.get("read_count") or 0)
        + (live.get("read_count") or 0),
    }


def _runtime_view(now: float) -> tuple[dict, bool]:
    """(reads by key, view available).

    `available` is False when the persisted table could not be read at all:
    "we could not look" must stay distinguishable from "we looked and the
    window is short" (S5-VERIF-006).
    """
    live = {**config_layered.runtime_read_stats(),
            **config_layered.unregistered_read_stats()}
    try:
        persisted = _db().config_read_stats_all()
    except Exception as exc:  # noqa: BLE001 - degrade to UNKNOWN, not to OK
        log.warning("config-reachability read-stat query failed: %s", exc)
        return (live, False)

    return ({key: _merge_entry(persisted.get(key), live.get(key))
             for key in set(persisted) | set(live)}, True)


# ── verdicts ────────────────────────────────────────────────────────────────
def _was_read(entry: Optional[dict]) -> bool:
    return entry is not None and (entry.get("read_count") or 0) > 0


def _key_window(entry: Optional[dict], now: float) -> Optional[float]:
    """How long THIS key has been observed, or None if it never entered
    the audit's field of view."""
    considered = None if entry is None else entry.get("first_considered_at")
    if considered is None:
        return None
    return max(0.0, now - float(considered))


def _verdict_for(verdict_class: str, has_mismatch: bool,
                 entry: Optional[dict], now: float,
                 available: bool) -> tuple[str, str]:
    """(verdict, reason) for one key. Pure."""
    if verdict_class == static_audit.CLASS_BYPASSED:
        return ("ANOMALY", REASON_BYPASSED_AND_MISMATCH if has_mismatch
                else REASON_BYPASSED)
    if has_mismatch:
        # A resolving key whose hardcoded fallback contradicts the registry
        # still lies to the analyst the moment the override is cleared.
        return ("ANOMALY", REASON_MISMATCH)
    if verdict_class == static_audit.CLASS_PARTIAL:
        return ("WARN", REASON_PARTIAL)
    if verdict_class == static_audit.CLASS_DEAD:
        return ("WARN", REASON_DEAD)
    if _was_read(entry):
        return ("OK", REASON_OK)
    # Statically fine, never actually read: a dead knob only runtime sees —
    # but only sayable after watching THIS key long enough (S5-VERIF-014).
    if not available:
        return ("INSUFFICIENT", REASON_WINDOW_UNKNOWN)
    window = _key_window(entry, now)
    if window is None or window < MIN_RUNTIME_OBSERVATION_SEC:
        return ("INSUFFICIENT", REASON_WINDOW_SHORT)
    return ("WARN", REASON_NEVER_READ)


def _mismatch_dicts(result: static_audit.AuditResult) -> dict[str, list[dict]]:
    by_key: dict[str, list[dict]] = {}
    for mismatch in result.default_mismatches:
        # Values are already None for secret keys (config_static_audit
        # redacts at the source); `redacted` travels with them so the
        # surface can say "withheld" rather than "no default".
        by_key.setdefault(mismatch.key, []).append({
            "key": mismatch.key,
            "registry_default": mismatch.registry_default,
            "direct_default": mismatch.direct_default,
            "site": mismatch.site,
            "channel": mismatch.channel,
            "note": mismatch.note,
            "redacted": mismatch.redacted,
        })
    return by_key


def _evaluate_rows(result: static_audit.AuditResult, reads: dict,
                   now: float, available: bool) -> list[dict]:
    """One verdict row per registered key. Total classification, no gaps."""
    mismatches = _mismatch_dicts(result)

    rows: list[dict] = []
    for key in sorted(result.keys):
        cls = result.keys[key]
        read = reads.get(key)
        verdict, reason = _verdict_for(cls.verdict, key in mismatches,
                                       read, now, available)
        rows.append({
            "key": key,
            "verdict": verdict,
            "reason": reason,
            "static_class": cls.verdict,
            "direct_read_sites": [s.site for s in cls.direct_read_sites],
            "frozen_constant_sites": [s.site for s in cls.frozen_constant_sites],
            "resolution_sites": [s.site for s in cls.resolution_sites],
            "read_count": None if read is None else read.get("read_count"),
            "last_read_at": None if read is None else read.get("last_read_at"),
            "observed_sec": _key_window(read, now),
            "default_mismatches": mismatches.get(key, []),
        })
    return rows


def evaluate(now: float | None = None,
             audit_result: static_audit.AuditResult | None = None) -> list[dict]:
    """Verdict rows for every registered key, both axes joined."""
    ts = _now(now)
    result = audit_result if audit_result is not None else _audit()
    reads, available = _runtime_view(ts)
    return _evaluate_rows(result, reads, ts, available)


def _classification_hash(rows: list[dict]) -> str:
    """Stable digest of the whole classification — catches changes that
    verdict-equality alone would miss (e.g. reason churn inside ANOMALY)."""
    payload = "|".join(f"{r['key']}={r['static_class']}:{r['reason']}"
                       for r in rows)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ── ledger ──────────────────────────────────────────────────────────────────
def _append_result(handle, ts: float, target: str, verdict: str,
                   measured: dict, expected: dict) -> None:
    """Append one ledger row, carrying first_detected_at across runs."""
    previous = handle.l5_check_last_for_target(CHECK_ID, target)
    if (previous and previous.get("verdict") == verdict
            and previous.get("first_detected_at") is not None):
        first_detected_at = previous["first_detected_at"]
    else:
        first_detected_at = ts
    handle.l5_check_append(
        ts=ts, check_id=CHECK_ID, target=target, verdict=verdict,
        measured_json=json.dumps(measured, sort_keys=True, default=str),
        expected_json=json.dumps(expected, sort_keys=True, default=str),
        first_detected_at=first_detected_at,
        ttl_sec=CHECK_RESULT_RETENTION_DAYS * _DAY,
    )


def _expected_block() -> dict:
    return {
        "expected_class": static_audit.CLASS_FULL,
        "min_runtime_observation_sec": MIN_RUNTIME_OBSERVATION_SEC,
    }


def _record_results(handle, ts: float, rows: list[dict]) -> dict:
    """Append transitions only. Returns the verdict counts."""
    counts = {v: 0 for v in _VERDICT_ORDER}
    for row in rows:
        verdict = row["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        target = target_for(row["key"])

        previous = handle.l5_check_last_for_target(CHECK_ID, target)
        if previous and previous.get("verdict") == verdict:
            continue                      # unchanged — no daily no-op row
        if verdict == "OK" and not previous:
            continue                      # nothing to close

        _append_result(handle, ts, target, verdict, measured={
            "reason": row["reason"],
            "static_class": row["static_class"],
            "direct_read_sites": row["direct_read_sites"],
            "frozen_constant_sites": row["frozen_constant_sites"],
            "resolution_sites": row["resolution_sites"],
            "read_count": row["read_count"],
            "last_read_at": row["last_read_at"],
            "default_mismatches": row["default_mismatches"],
        }, expected=_expected_block())
    return counts


def run_daily_check_if_due(now: float | None = None) -> bool:
    """Run the reachability check if the persisted schedule says it is due.

    Returns True when the check actually ran. Driven by `next_run_at` in
    l5_job_state, so an overdue run is compensated on the first tick after
    a restart rather than skipped forever (defect F-01).
    """
    ts = _now(now)
    try:
        handle = _db()
        job = handle.l5_job_get(JOB_ID)
        if job and job.get("next_run_at") is not None and job["next_run_at"] > ts:
            return False

        flush_read_stats(now=ts)
        result = _audit()
        # Start (never restart) the per-key observation window before
        # judging, so the 24h floor of S5-VERIF-014 is measured against
        # each key's own exposure rather than the deployment's age.
        handle.config_read_stats_note_considered(sorted(result.keys), now=ts)
        reads, available = _runtime_view(ts)
        rows = _evaluate_rows(result, reads, ts, available)
        counts = _record_results(handle, ts, rows)

        summary_verdict = ("ANOMALY" if counts["ANOMALY"]
                           else "WARN" if counts["WARN"] else "OK")
        measured = dict(counts)
        measured["classification_hash"] = _classification_hash(rows)
        _append_result(handle, ts, SUMMARY_TARGET, summary_verdict,
                       measured=measured,
                       expected={"registered_total": len(rows)})
        handle.l5_job_set(JOB_ID, last_run_at=ts,
                          next_run_at=ts + JOB_INTERVAL_SEC)
        if counts["ANOMALY"]:
            log.warning("[ConfigReachability] %d key(s) ANOMALY, %d WARN",
                        counts["ANOMALY"], counts["WARN"])
        return True
    except Exception as exc:  # noqa: BLE001 - a failed check must not kill the worker
        log.warning("config-reachability daily check failed: %s", exc)
        return False


# ── AP3 self-evaluation surface ─────────────────────────────────────────────
def _runtime_axis(rows: list[dict], available: bool) -> str:
    """Whether the runtime half can speak at all yet.

    OK once any key has cleared the floor — per-key verdicts still use each
    key's own window; this is the "is this axis reportable" indicator.
    """
    if not available:
        return "UNKNOWN"
    observed = [r["observed_sec"] for r in rows if r["observed_sec"] is not None]
    if observed and max(observed) >= MIN_RUNTIME_OBSERVATION_SEC:
        return "OK"
    return "INSUFFICIENT"


def snapshot(now: float | None = None,
             audit_result: static_audit.AuditResult | None = None) -> dict:
    """Live reachability summary for /api/v2/self_eval (AP3).

    Recomputed rather than read back from the ledger, so the surface shows
    the current situation between daily runs; the job timestamps say how
    fresh the *ledger* is.
    """
    ts = _now(now)
    result = audit_result if audit_result is not None else _audit()
    reads, available = _runtime_view(ts)
    rows = _evaluate_rows(result, reads, ts, available)

    try:
        job = _db().l5_job_get(JOB_ID) or {}
    except Exception as exc:  # noqa: BLE001 - visible failure, not a green blank
        log.warning("config-reachability job lookup failed: %s", exc)
        job = {}

    # Read from the merged view, not the live tracker: the daily flush
    # empties the tracker, and a silent fallback that stopped being listed
    # the day after it was first seen would be worse than not listing it.
    registered = set(result.keys)
    unregistered_reads = [
        {"key": key, "read_count": entry.get("read_count"),
         "last_read_at": entry.get("last_read_at")}
        for key, entry in sorted(reads.items())
        if key not in registered and _was_read(entry)
    ]
    return {
        "job_id": JOB_ID,
        "job_last_run_at": job.get("last_run_at"),
        "job_next_run_at": job.get("next_run_at"),
        "registered_total": result.registered_total,
        "counts": dict(result.counts),
        # ~94 entries by design (defect G-15) — names only, the ledger and
        # /api/v2/config/registry carry the per-key detail.
        "anomalies": [r["key"] for r in rows if r["verdict"] == "ANOMALY"],
        "partial_keys": list(result.keys_in_class(static_audit.CLASS_PARTIAL)),
        "dead_keys": list(result.keys_in_class(static_audit.CLASS_DEAD)),
        "never_read": [r["key"] for r in rows
                       if r["reason"] == REASON_NEVER_READ],
        "default_mismatches": [m for group in _mismatch_dicts(result).values()
                               for m in group],
        "unregistered_reads": unregistered_reads,
        "unregistered_reads_dropped": config_layered.unregistered_read_dropped(),
        "unregistered_resolution_reads": sorted(
            result.unregistered_resolution_reads),
        "dynamic_getenv_sites": len(result.dynamic_getenv_sites),
        "runtime_axis": _runtime_axis(rows, available),
        "tracker_started_at": config_layered.read_tracker_started_at(),
        "runtime_observation_sec": max(
            [r["observed_sec"] for r in rows if r["observed_sec"] is not None],
            default=None),
    }
