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
import logging
from typing import Optional

from radar import config_layered
from radar.verification import config_static_audit as static_audit
from radar.verification import l5_common

log = logging.getLogger("radar")

JOB_ID = "config_reachability_daily"
CHECK_ID = "config_reachability"
JOB_INTERVAL_SEC = l5_common.JOB_INTERVAL_SEC
SUMMARY_TARGET = l5_common.SUMMARY_TARGET
TARGET_PREFIX = "config:"

_DAY = l5_common.DAY
# S5-VERIF-014: "監査は起動から 24 時間以上稼働した実績に基づく MUST".
MIN_RUNTIME_OBSERVATION_SEC = 86400.0
CHECK_RESULT_RETENTION_DAYS = l5_common.CHECK_RESULT_RETENTION_DAYS

_VERDICT_ORDER = l5_common.VERDICT_ORDER

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


# Module-level seams: tests bind `_db` to a throwaway database.
_db = l5_common.db
_now = l5_common.now

l5_common.register_job(JOB_ID, label="Config reachability",
                       interval_sec=JOB_INTERVAL_SEC)


def _audit() -> static_audit.AuditResult:
    """Seam for tests; production shares one memoised repo scan."""
    return static_audit.audit_cached()


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
    l5_common.append_result(handle, check_id=CHECK_ID, ts=ts, target=target,
                            verdict=verdict, measured=measured,
                            expected=expected)


def _expected_block() -> dict:
    return {
        "expected_class": static_audit.CLASS_FULL,
        "min_runtime_observation_sec": MIN_RUNTIME_OBSERVATION_SEC,
    }


def _ledger_row(row: dict) -> dict:
    """One verdict row in the shape l5_common.record_results expects."""
    return {
        "target": target_for(row["key"]),
        "verdict": row["verdict"],
        "measured": {
            "reason": row["reason"],
            "static_class": row["static_class"],
            "direct_read_sites": row["direct_read_sites"],
            "frozen_constant_sites": row["frozen_constant_sites"],
            "resolution_sites": row["resolution_sites"],
            "read_count": row["read_count"],
            "last_read_at": row["last_read_at"],
            "default_mismatches": row["default_mismatches"],
        },
        "expected": _expected_block(),
    }


def _record_results(handle, ts: float, rows: list[dict]) -> dict:
    """Append transitions only — ~94 stable ANOMALYs must not recur daily."""
    return l5_common.record_results(
        handle, check_id=CHECK_ID, ts=ts,
        rows=[_ledger_row(row) for row in rows], transition_only=True)


def _run(handle, ts: float) -> None:
    """One reachability run. Called by the l5_common job skeleton."""
    flush_read_stats(now=ts)
    result = _audit()
    # Start (never restart) the per-key observation window before judging,
    # so the 24h floor of S5-VERIF-014 is measured against each key's own
    # exposure rather than the deployment's age.
    handle.config_read_stats_note_considered(sorted(result.keys), now=ts)
    reads, available = _runtime_view(ts)
    rows = _evaluate_rows(result, reads, ts, available)
    counts = _record_results(handle, ts, rows)

    measured = dict(counts)
    measured["classification_hash"] = _classification_hash(rows)
    _append_result(handle, ts, SUMMARY_TARGET,
                   l5_common.summary_verdict(counts), measured=measured,
                   expected={"registered_total": len(rows)})
    if counts["ANOMALY"]:
        log.warning("[ConfigReachability] %d key(s) ANOMALY, %d WARN",
                    counts["ANOMALY"], counts["WARN"])


def run_daily_check_if_due(now: float | None = None) -> bool:
    """Run the reachability check if the persisted schedule says it is due."""
    return l5_common.run_daily_if_due(
        db_fn=_db, job_id=JOB_ID, run_fn=_run, interval_sec=JOB_INTERVAL_SEC,
        now_ts=now, label="config-reachability")


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
