"""Chronic-inconclusive detector — NP5+8 contract enforcement.

CLAUDE.md states the contract directly:

  "過渡的結論不可は許容、データ蓄積後の恒常的結論不可は設計失敗として扱う"
  (transient inconclusive ok, chronic inconclusive after data has
   accumulated = design failure)

Phase 2 / ADR-V2-010 created the ledger (`inconclusive_continuity_log`)
and `radar.conclusions.persistence._record_continuity` writes to it on
every conclusion save. The downstream chronic-detector promised by the
ADR was never built — until now.

Algorithm
---------
Each (scenario_id, conclusion_type) has at most one **open run** of
unavailability at a time. The ledger records *transitions* — opening a
run, extending it, or closing it — never steady-state heartbeats.

To compute current state per pair:

  1. Fetch the latest row per (scenario_id, conclusion_type) via a
     correlated subquery on `MAX(id)`.
  2. If the latest row has `is_available=1`, the run is closed. Skip.
  3. Otherwise the latest row records "still unavailable since
     first_seen_at". Days unavailable = (now - first_seen_at) / 86400.
  4. Chronic iff days >= threshold (default 7).

Threshold is read from `radar.config.CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS`
so an operator can tune it from the SETTINGS Operate>Auto-Calibration
page without a redeploy. Lower bound 3 (any lower would risk
false-positives for routine sensor outages).

NP3: every read swallows DB errors and returns a benign empty payload.
The detector must never crash the scheduler or the snapshot endpoint.

NP5+8: the daily scheduler hook (in `radar.scheduler`) calls
`record_failure("inconclusive_chronic", ...)` for every chronic state
so the silent-failure ledger registers the breach. The HUD surfaces
this through a dedicated CHRONIC chip (Phase C2).
"""
from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from radar.database import RadarDB

log = logging.getLogger("radar.conclusions.inconclusive_continuity")

# Lower bound to keep operators from disabling the detector in disguise.
THRESHOLD_DAYS_MIN = 3.0
THRESHOLD_DAYS_DEFAULT = 7.0

# Duty-cycle criterion (2026-07-04). The consecutive-run rule above is
# blind to flapping: attack_mode spent ~20-30% of ticks UNAVAILABLE for
# two months across all scenarios while chronic_count stayed 0, because
# every run closed within hours. Duty-cycle sums unavailable TIME over a
# rolling window — duration-based, so it stays correct even when
# conclusion writes are change-gated rather than per-tick.
DUTY_WINDOW_DAYS_MIN = 7.0
DUTY_WINDOW_DAYS_DEFAULT = 14.0
DUTY_THRESHOLD_MIN = 0.05  # same anti-disable spirit as THRESHOLD_DAYS_MIN
DUTY_THRESHOLD_DEFAULT = 0.20


@dataclass(frozen=True)
class ContinuityState:
    """Current open-run state for one (scenario_id, conclusion_type)."""
    scenario_id:        str
    conclusion_type:    str
    is_chronic:         bool
    days_unavailable:   float
    first_seen_at:      float
    last_observed_at:   float
    reason:             str


def _resolve_threshold_days() -> float:
    """Read the chronic threshold via the layered config registry so
    operator overrides made through SETTINGS take effect immediately
    (the registry is responsible for env / DB-override layering)."""
    try:
        from radar.config_layered import get_config
        raw = float(get_config("CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS"))
    except Exception:
        raw = THRESHOLD_DAYS_DEFAULT
    return max(THRESHOLD_DAYS_MIN, raw)


def compute_states(
    db: "RadarDB",
    *,
    now: Optional[float] = None,
    threshold_days: Optional[float] = None,
) -> list[ContinuityState]:
    """Return one ContinuityState per (scenario, conclusion_type) that
    currently has an open unavailability run. Closed pairs are not
    returned. Returns an empty list on any DB error (NP3)."""
    n = float(now) if now is not None else time.time()
    thr = (
        max(THRESHOLD_DAYS_MIN, float(threshold_days))
        if threshold_days is not None
        else _resolve_threshold_days()
    )
    try:
        conn = db._get_conn()  # noqa: SLF001
    except Exception as exc:
        log.debug("compute_states: cannot acquire conn: %s", exc)
        return []

    try:
        rows = list(conn.execute(
            "SELECT scenario_id, conclusion_type, observed_at, "
            "       first_seen_at, is_available, reason "
            "FROM inconclusive_continuity_log "
            "WHERE id IN ("
            "    SELECT MAX(id) FROM inconclusive_continuity_log "
            "    GROUP BY scenario_id, conclusion_type"
            ")"
        ))
    except sqlite3.OperationalError:
        # Table not present — schema below the ADR-V2-010 migration.
        return []
    except Exception as exc:
        log.debug("compute_states: query failed: %s", exc)
        return []

    out: list[ContinuityState] = []
    for r in rows:
        if int(r["is_available"]) == 1:
            continue
        first_seen = float(r["first_seen_at"])
        days = max(0.0, (n - first_seen) / 86400.0)
        out.append(ContinuityState(
            scenario_id=str(r["scenario_id"]),
            conclusion_type=str(r["conclusion_type"]),
            is_chronic=days >= thr,
            days_unavailable=round(days, 4),
            first_seen_at=first_seen,
            last_observed_at=float(r["observed_at"]),
            reason=str(r["reason"] or ""),
        ))
    # Stable order: chronic first (worst dwell first), then transient.
    out.sort(key=lambda s: (-int(s.is_chronic), -s.days_unavailable))
    return out


@dataclass(frozen=True)
class DutyCycleState:
    """Rolling-window unavailability share for one (scenario, type)."""
    scenario_id:      str
    conclusion_type:  str
    duty_cycle:       float  # 0..1 share of the window spent unavailable
    unavailable_sec:  float
    window_days:      float
    is_chronic:       bool
    runs_counted:     int


def _resolve_duty_params() -> tuple[float, float]:
    """(window_days, duty_threshold) via the layered config registry,
    with the same graceful fallback as _resolve_threshold_days."""
    try:
        from radar.config_layered import get_config
        window = float(get_config("CHRONIC_DUTY_WINDOW_DAYS"))
    except Exception:
        window = DUTY_WINDOW_DAYS_DEFAULT
    try:
        from radar.config_layered import get_config
        thr = float(get_config("CHRONIC_DUTY_THRESHOLD"))
    except Exception:
        thr = DUTY_THRESHOLD_DEFAULT
    window = max(DUTY_WINDOW_DAYS_MIN, window)
    thr = min(1.0, max(DUTY_THRESHOLD_MIN, thr))
    return window, thr


def compute_duty_cycle_states(
    db: "RadarDB",
    *,
    now: Optional[float] = None,
    window_days: Optional[float] = None,
    duty_threshold: Optional[float] = None,
) -> list[DutyCycleState]:
    """Per (scenario, type): share of the trailing window spent in an
    unavailability run. Sums CLOSED runs (is_available=1 rows carry the
    full [first_seen_at, observed_at] span; extends are not double-counted)
    plus the currently OPEN run if the pair's latest row is unavailable.
    Spans are clamped to the window. Empty list on any DB error (NP3)."""
    n = float(now) if now is not None else time.time()
    if window_days is None or duty_threshold is None:
        cfg_window, cfg_thr = _resolve_duty_params()
        window_days = window_days if window_days is not None else cfg_window
        duty_threshold = (
            duty_threshold if duty_threshold is not None else cfg_thr
        )
    window_days = max(DUTY_WINDOW_DAYS_MIN, float(window_days))
    duty_threshold = min(1.0, max(DUTY_THRESHOLD_MIN, float(duty_threshold)))
    window_sec = window_days * 86400.0
    window_start = n - window_sec

    try:
        conn = db._get_conn()  # noqa: SLF001
        closed = list(conn.execute(
            "SELECT scenario_id, conclusion_type, first_seen_at, observed_at "
            "FROM inconclusive_continuity_log "
            "WHERE is_available = 1 AND observed_at >= ?",
            (window_start,),
        ))
        latest_open = list(conn.execute(
            "SELECT scenario_id, conclusion_type, first_seen_at "
            "FROM inconclusive_continuity_log "
            "WHERE id IN ("
            "    SELECT MAX(id) FROM inconclusive_continuity_log "
            "    GROUP BY scenario_id, conclusion_type"
            ") AND is_available = 0"
        ))
    except sqlite3.OperationalError:
        return []
    except Exception as exc:
        log.debug("compute_duty_cycle_states: query failed: %s", exc)
        return []

    acc: dict[tuple[str, str], list[float]] = {}  # key -> [sec, runs]
    for r in closed:
        overlap = min(float(r["observed_at"]), n) - max(
            float(r["first_seen_at"]), window_start,
        )
        if overlap <= 0:
            continue
        cur = acc.setdefault(
            (str(r["scenario_id"]), str(r["conclusion_type"])), [0.0, 0],
        )
        cur[0] += overlap
        cur[1] += 1
    for r in latest_open:
        overlap = n - max(float(r["first_seen_at"]), window_start)
        if overlap <= 0:
            continue
        cur = acc.setdefault(
            (str(r["scenario_id"]), str(r["conclusion_type"])), [0.0, 0],
        )
        cur[0] += overlap
        cur[1] += 1

    out = [
        DutyCycleState(
            scenario_id=sid,
            conclusion_type=ctype,
            duty_cycle=round(min(1.0, sec / window_sec), 4),
            unavailable_sec=round(sec, 1),
            window_days=window_days,
            is_chronic=(sec / window_sec) >= duty_threshold,
            runs_counted=runs,
        )
        for (sid, ctype), (sec, runs) in acc.items()
    ]
    out.sort(key=lambda s: (-int(s.is_chronic), -s.duty_cycle))
    return out


def current_run_length_sec(
    db: "RadarDB",
    scenario_id: str,
    conclusion_type: str,
    *,
    now: Optional[float] = None,
) -> Optional[float]:
    """Return seconds since the latest open unavailability run started for
    this (scenario_id, conclusion_type). Returns None if the latest entry
    is closed (run already resolved) or no entry exists. NP3-tolerant —
    never raises; returns None on any DB error.

    Used by per-conclusion metadata enrichment so a single NULL row can
    carry "this NULL has lasted N minutes" without waiting for the daily
    chronic-snapshot pass.
    """
    n = float(now) if now is not None else time.time()
    try:
        conn = db._get_conn()  # noqa: SLF001
        row = conn.execute(
            "SELECT first_seen_at, is_available "
            "FROM inconclusive_continuity_log "
            "WHERE scenario_id=? AND conclusion_type=? "
            "ORDER BY observed_at DESC LIMIT 1",
            (scenario_id, conclusion_type),
        ).fetchone()
    except Exception:
        return None
    if row is None or int(row["is_available"]) == 1:
        return None
    return max(0.0, n - float(row["first_seen_at"]))


def chronic_snapshot(
    db: "RadarDB",
    *,
    now: Optional[float] = None,
) -> dict:
    """NP3-tolerant single-shot snapshot used by the API endpoint, the
    HUD chip poller, and the scheduler hook. Shape mirrors
    ``governor_snapshot`` in spirit so downstream consumers stay
    consistent."""
    n = float(now) if now is not None else time.time()
    thr = _resolve_threshold_days()
    duty_window, duty_thr = _resolve_duty_params()
    try:
        states = compute_states(db, now=n, threshold_days=thr)
        chronic = [
            {**asdict(s), "criterion": "consecutive_days"}
            for s in states if s.is_chronic
        ]
        transient = [asdict(s) for s in states if not s.is_chronic]

        # Merge duty-cycle chronic pairs not already flagged by the
        # consecutive-run rule. Synthesized entries mirror the
        # ContinuityState keys so downstream consumers (HUD chip,
        # scheduler record_failure loop) work unchanged.
        duty_states = compute_duty_cycle_states(
            db, now=n, window_days=duty_window, duty_threshold=duty_thr,
        )
        flagged = {(c["scenario_id"], c["conclusion_type"]) for c in chronic}
        for d in duty_states:
            if not d.is_chronic:
                continue
            if (d.scenario_id, d.conclusion_type) in flagged:
                continue
            chronic.append({
                "scenario_id":      d.scenario_id,
                "conclusion_type":  d.conclusion_type,
                "is_chronic":       True,
                "days_unavailable": round(d.unavailable_sec / 86400.0, 4),
                "first_seen_at":    n - d.window_days * 86400.0,
                "last_observed_at": n,
                "reason":           "duty_cycle",
                "criterion":        "duty_cycle",
                "duty_cycle":       d.duty_cycle,
            })

        return {
            "computed_at":   n,
            "threshold_days": thr,
            "summary": {
                "total":          len(states),
                "chronic_count":  len(chronic),
                "transient_count": len(transient),
                "duty_chronic_count": sum(
                    1 for d in duty_states if d.is_chronic
                ),
            },
            "chronic":   chronic,
            "transient": transient,
            "duty": {
                "window_days": duty_window,
                "threshold":   duty_thr,
                "states":      [asdict(d) for d in duty_states],
            },
        }
    except Exception as exc:
        log.warning("chronic_snapshot degraded: %s", exc)
        return {
            "computed_at":   n,
            "threshold_days": thr,
            "summary": {"total": 0, "chronic_count": 0,
                        "transient_count": 0, "duty_chronic_count": 0},
            "chronic":   [],
            "transient": [],
            "duty": {"window_days": duty_window, "threshold": duty_thr,
                     "states": []},
            "error":     str(exc)[:200],
        }
