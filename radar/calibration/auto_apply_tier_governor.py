"""Self-promoting auto-apply tier governor.

Background
----------
The existing `radar.calibration.auto_tune_governor` already enforces
per-proposal safety rules (sample-size minimum, magnitude budget, 72h
cooldown, recall gate). What it does NOT do is reason about whether
the *whole* auto-apply machinery is trustworthy enough yet to let
proposals through. Until 2026-05-05 that decision was implicit: every
calibration proposal that passed the per-proposal rules became live
threshold the next time a downstream consumer called
`threshold_history.latest()`.

This module adds a layer above that: a tier-based confidence model
that the system updates **on its own** by watching its own behaviour.

  Tier 0 — proposal-only. Calibrators can still log proposals into
           the ledger (so we accumulate observability) but they are
           NOT considered "active" by downstream consumers; the
           previous threshold continues to apply.
  Tier 1 — LOW-impact auto-apply (per-scenario tl_thresholds.*).
  Tier 2 — LOW + MED auto-apply (adds per-sensor llm_confidence_min.*).
  Tier 3 — LOW + MED + HIGH (registry-level keys; future calibrators).

Promotion / demotion conditions are computed from existing tables
(`threshold_history`, `analyst_feedback`, `conclusion_diff_log`) and
recorded into `auto_apply_tier_state` — every transition is auditable
under NP6.

Hysteresis: demotion conditions are stricter than promotion conditions
so a transient anomaly does not flap the tier up and down.

Circuit breaker: 3 consecutive failed `evaluate_and_transition` runs
force the tier to 0 regardless of metrics. Failure counts are recorded
on the same table.

Kill switch: `AUTO_CALIBRATION_TIER_CAP` env var (or DB-stored config)
caps the tier ceiling. Setting it to 0 halts auto-apply system-wide.
The governor still records observations; only the apply path is
disabled.

NP integrity:
  NP1 — recall_gate (inherited from auto_tune_governor) holds before
        any tier evaluates promotion
  NP6 — every transition is in auto_apply_tier_state with metrics_json
  NP3 — failures degrade silently to current tier; never crash
        scheduler
  AP3 — tier + last-transition surface-able to HUD as a self-eval chip
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("radar.calibration.auto_apply_tier_governor")


# ── Constants ────────────────────────────────────────────────────────────────

TIER_PROPOSAL_ONLY = 0
TIER_LOW           = 1
TIER_LOW_MED       = 2
TIER_FULL          = 3

TIER_NAMES = {
    TIER_PROPOSAL_ONLY: "proposal_only",
    TIER_LOW:           "low_apply",
    TIER_LOW_MED:       "low_med_apply",
    TIER_FULL:          "full_apply",
}

# Map applied_by → impact level. Calibrators identify themselves via
# `applied_by` when calling auto_tune_governor.commit(); this table
# tells the tier governor how strict to be when deciding whether the
# proposal is allowed at the current tier.
APPLIED_BY_IMPACT: dict[str, str] = {
    "auto:tl_calibrator":   "low",   # per-scenario TL thresholds
    "auto:tl_threshold":    "low",
    "auto:llm_calibrator":  "med",   # per-sensor LLM confidence floor
    "auto:llm_floor":       "med",
    "auto:llm_conf":        "med",
    "auto:domain_weight":   "high",  # reserved — no calibrator yet
    "auto:hysteresis":      "high",  # reserved
    "auto:convergence":     "high",  # reserved
}

# Promotion thresholds (cautious by design).
# 0→1 promotion intentionally does NOT require governor_proposal_count:
# at Tier 0 the tier-gate blocks every proposal from landing, so
# threshold_history stays empty by construction. Requiring "≥10 in
# threshold_history" here would be a chicken-and-egg deadlock. We rely
# instead on auto_feedback_rows as the signal that the upstream data
# pipeline is alive enough to bootstrap the loop.
PROMOTE_TIER0_TO_TIER1 = {
    "min_auto_feedback_rows": 100,
}
PROMOTE_TIER1_TO_TIER2 = {
    "min_days_at_tier": 7.0,
    "max_revert_rate":  0.05,
}
PROMOTE_TIER2_TO_TIER3 = {
    "min_days_at_tier":      14.0,
    "min_diff_log_match_rate": 0.99,
    "max_revert_rate":         0.05,
}

# Demotion thresholds (looser windows, but lower trigger).
DEMOTE_TIER1_TO_TIER0 = {
    "max_revert_rate_24h": 0.20,
}
DEMOTE_TIER2_TO_TIER1 = {
    "max_revert_rate_24h": 0.20,
}
DEMOTE_TIER3_TO_TIER2 = {
    "min_diff_log_match_rate": 0.95,
}

# Circuit breaker.
CONSECUTIVE_FAILURE_LIMIT = 3

# HIGH-impact change cool-down (Tier 3): pause LOW/MED calibrators for
# this many hours after a HIGH change is committed, so chained
# proposals can't pile on a single unproven change.
HIGH_COOLDOWN_HOURS_DEFAULT = 24.0


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TierSnapshot:
    """Result of `current_tier()`. Returns the active tier plus the
    bounded cap (kill-switch / env override) so callers can show both
    values to the analyst."""
    tier: int
    cap:  int          # bounded by AUTO_CALIBRATION_TIER_CAP
    last_transition_at: Optional[float] = None
    last_transition_kind: Optional[str] = None


@dataclass(frozen=True)
class TransitionResult:
    """Audit row for a single evaluate_and_transition() call."""
    prior_tier: int
    new_tier:   int
    transition: str       # 'unchanged' | 'promote' | 'demote' |
                          # 'circuit_breaker' | 'kill_switch_engaged'
    reason: str
    metrics: dict


# ── DB connection helper ─────────────────────────────────────────────────────


def _conn():
    from radar.database import db
    return db._get_conn()  # noqa: SLF001 — established internal pattern


# ── Public API ───────────────────────────────────────────────────────────────


def _raw_stored_tier() -> int:
    """Tier as written to the DB — bypasses the kill-switch cap so the
    governor can detect "tier above the cap" and demote accordingly."""
    try:
        row = _conn().execute(
            "SELECT tier FROM auto_apply_tier_state ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except Exception:
        return 0
    return int(row[0]) if row else 0


def current_tier() -> TierSnapshot:
    """Return the active tier (with kill-switch cap applied).

    NP3: never raises. On any DB error returns TIER_PROPOSAL_ONLY so
    auto-apply pauses safely.
    """
    cap = _tier_cap_from_env()
    try:
        row = _conn().execute(
            "SELECT tier, observed_at, transition FROM auto_apply_tier_state "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        # Table not present yet (migration v52 hasn't run). Treat as
        # tier-0 — the safe default.
        return TierSnapshot(tier=0, cap=cap)
    except Exception as exc:
        log.debug("current_tier() read failed (degrading to 0): %s", exc)
        return TierSnapshot(tier=0, cap=cap)
    if row is None:
        return TierSnapshot(tier=0, cap=cap)
    raw_tier = int(row[0])
    return TierSnapshot(
        tier=min(raw_tier, cap),
        cap=cap,
        last_transition_at=row[1],
        last_transition_kind=row[2],
    )


def is_apply_allowed(applied_by: str) -> bool:
    """Tell `auto_tune_governor.commit()` whether this proposal can be
    written to threshold_history at the current tier.

    NP3: returns False on any error (safe default — proposal stays out
    of the live ledger; calibrator can still log to its own diagnostic
    surface).
    """
    try:
        snap = current_tier()
        impact = APPLIED_BY_IMPACT.get(applied_by, "low")
        # HIGH cooldown: Tier 3 may be active but a recent HIGH change
        # has imposed a downstream pause on LOW/MED.
        if impact in ("low", "med") and _is_in_cooldown(impact):
            return False
        if impact == "low":
            return snap.tier >= TIER_LOW
        if impact == "med":
            return snap.tier >= TIER_LOW_MED
        if impact == "high":
            return snap.tier >= TIER_FULL
        # Unknown applied_by → default to LOW (conservative).
        return snap.tier >= TIER_LOW
    except Exception as exc:
        log.debug("is_apply_allowed degraded: %s", exc)
        return False


def evaluate_and_transition() -> TransitionResult:
    """Inspect metrics and decide whether to promote / demote / hold.

    Designed to be called once per day from the scheduler. Hourly is
    fine too — the cooldown / dwell-time gates dominate.

    Failure handling: any uncaught exception is captured into a
    `circuit_breaker` row; CONSECUTIVE_FAILURE_LIMIT consecutive
    failures force tier=0.
    """
    try:
        return _evaluate_and_transition_inner()
    except Exception as exc:
        log.exception("evaluate_and_transition crashed: %s", exc)
        prior = current_tier().tier
        # Bookkeep a failure marker; if we now have ≥ N consecutive
        # failures, force tier 0.
        consecutive = _count_consecutive_failures() + 1
        if consecutive >= CONSECUTIVE_FAILURE_LIMIT:
            _record_transition(
                new_tier=0, transition="circuit_breaker",
                reason=f"≥{CONSECUTIVE_FAILURE_LIMIT} consecutive failures: {exc}",
                metrics={"consecutive_failures": consecutive},
            )
            return TransitionResult(
                prior_tier=prior, new_tier=0, transition="circuit_breaker",
                reason=str(exc),
                metrics={"consecutive_failures": consecutive},
            )
        # Otherwise just log a failure marker; tier unchanged.
        _record_transition(
            new_tier=prior, transition="evaluation_failed",
            reason=f"transient error (#{consecutive}): {exc}",
            metrics={"consecutive_failures": consecutive},
        )
        return TransitionResult(
            prior_tier=prior, new_tier=prior, transition="evaluation_failed",
            reason=str(exc),
            metrics={"consecutive_failures": consecutive},
        )


def trigger_high_cooldown(triggered_by: str = "") -> None:
    """Called by `auto_tune_governor.commit()` after a successful HIGH
    impact write. Pauses LOW/MED calibrators for HIGH_COOLDOWN_HOURS so
    they don't pile on top of an unproven HIGH change."""
    try:
        hours = float(os.getenv("AUTO_APPLY_HIGH_COOLDOWN_HOURS",
                                 str(HIGH_COOLDOWN_HOURS_DEFAULT)))
        until = time.time() + hours * 3600.0
        with _conn().writing():
            for impact in ("low", "med"):
                _conn().execute(
                    "INSERT INTO auto_apply_cooldown (impact_level, cooldown_until, "
                    "triggered_by, set_at) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(impact_level) DO UPDATE SET "
                    "cooldown_until=excluded.cooldown_until, "
                    "triggered_by=excluded.triggered_by, set_at=excluded.set_at",
                    (impact, until, triggered_by, time.time()),
                )
    except Exception as exc:
        log.debug("trigger_high_cooldown failed (non-fatal): %s", exc)


# ── Tier evaluation internals ────────────────────────────────────────────────


def _evaluate_and_transition_inner() -> TransitionResult:
    snap = current_tier()
    cap  = snap.cap
    # Kill-switch check operates against the raw stored tier, not the
    # already-capped `snap.tier`. If we used the capped value, a
    # genuine kill-switch event (DB says tier=3, cap=1) would never be
    # recorded — current_tier() would silently return 1 and the
    # comparison `cap < prior` would always be false.
    raw_prior = _raw_stored_tier()
    prior = snap.tier  # capped — used for promotion / demotion math

    # Kill-switch check first. If cap < raw_prior we demote immediately.
    if cap < raw_prior:
        _record_transition(
            new_tier=cap, transition="kill_switch_engaged",
            reason=f"AUTO_CALIBRATION_TIER_CAP={cap} < current tier {raw_prior}",
            metrics={"prior_tier": raw_prior, "cap": cap},
        )
        return TransitionResult(
            prior_tier=raw_prior, new_tier=cap,
            transition="kill_switch_engaged",
            reason=f"cap={cap}", metrics={"cap": cap},
        )

    metrics = _collect_metrics(prior)

    # Demotion checks first — bias toward safety.
    demoted = _check_demotion(prior, metrics)
    if demoted is not None:
        new_tier, reason = demoted
        _record_transition(
            new_tier=new_tier, transition="demote", reason=reason,
            metrics=metrics,
        )
        return TransitionResult(
            prior_tier=prior, new_tier=new_tier,
            transition="demote", reason=reason, metrics=metrics,
        )

    # Promotion checks (capped by AUTO_CALIBRATION_TIER_CAP).
    promoted = _check_promotion(prior, cap, metrics)
    if promoted is not None:
        new_tier, reason = promoted
        _record_transition(
            new_tier=new_tier, transition="promote", reason=reason,
            metrics=metrics,
        )
        return TransitionResult(
            prior_tier=prior, new_tier=new_tier,
            transition="promote", reason=reason, metrics=metrics,
        )

    # No change. We still write a heartbeat row only on the *first*
    # eval after process start (init) so the state row exists for
    # is_apply_allowed() readers. Otherwise the table would stay empty
    # at tier 0 forever and current_tier() would return 0 implicitly,
    # which is fine but makes audit stories harder to read.
    if snap.last_transition_at is None:
        _record_transition(
            new_tier=prior, transition="init",
            reason="initial evaluation — no prior state row",
            metrics=metrics,
        )
    return TransitionResult(
        prior_tier=prior, new_tier=prior,
        transition="unchanged", reason="conditions not met",
        metrics=metrics,
    )


def _check_promotion(
    prior: int, cap: int, metrics: dict,
) -> Optional[tuple[int, str]]:
    """Return (new_tier, reason) when the promotion conditions for
    `prior` are met, else None. Honors `cap`."""
    if prior >= cap:
        return None  # already at the kill-switch ceiling
    if prior == TIER_PROPOSAL_ONLY:
        c = PROMOTE_TIER0_TO_TIER1
        if metrics["auto_feedback_rows"] >= c["min_auto_feedback_rows"]:
            return (TIER_LOW,
                    "auto_feedback={fb} rows ≥ bootstrap threshold ({thr})".format(
                        fb=metrics["auto_feedback_rows"],
                        thr=c["min_auto_feedback_rows"]))
    elif prior == TIER_LOW:
        c = PROMOTE_TIER1_TO_TIER2
        if (metrics["days_at_tier"] >= c["min_days_at_tier"]
                and metrics["revert_rate_7d"] <= c["max_revert_rate"]):
            return (TIER_LOW_MED,
                    "tier1 stable {d:.1f}d, revert_rate={rr:.3f}".format(
                        d=metrics["days_at_tier"],
                        rr=metrics["revert_rate_7d"]))
    elif prior == TIER_LOW_MED:
        c = PROMOTE_TIER2_TO_TIER3
        if (metrics["days_at_tier"] >= c["min_days_at_tier"]
                and metrics["diff_log_match_rate"] >= c["min_diff_log_match_rate"]
                and metrics["revert_rate_14d"] <= c["max_revert_rate"]):
            return (TIER_FULL,
                    "tier2 stable {d:.1f}d, match_rate={mr:.4f}, revert_rate={rr:.3f}".format(
                        d=metrics["days_at_tier"],
                        mr=metrics["diff_log_match_rate"],
                        rr=metrics["revert_rate_14d"]))
    return None


def _check_demotion(prior: int, metrics: dict) -> Optional[tuple[int, str]]:
    if prior == TIER_LOW:
        c = DEMOTE_TIER1_TO_TIER0
        if metrics["revert_rate_24h"] >= c["max_revert_rate_24h"]:
            return (TIER_PROPOSAL_ONLY,
                    f"24h revert_rate={metrics['revert_rate_24h']:.3f} "
                    f">= {c['max_revert_rate_24h']}")
    elif prior == TIER_LOW_MED:
        c = DEMOTE_TIER2_TO_TIER1
        if metrics["revert_rate_24h"] >= c["max_revert_rate_24h"]:
            return (TIER_LOW,
                    f"24h revert_rate={metrics['revert_rate_24h']:.3f} "
                    f">= {c['max_revert_rate_24h']}")
    elif prior == TIER_FULL:
        c = DEMOTE_TIER3_TO_TIER2
        if metrics["diff_log_match_rate"] < c["min_diff_log_match_rate"]:
            return (TIER_LOW_MED,
                    f"diff_log match_rate={metrics['diff_log_match_rate']:.4f} "
                    f"< {c['min_diff_log_match_rate']}")
    return None


# ── Metrics collectors ───────────────────────────────────────────────────────


def _collect_metrics(current_tier_int: int) -> dict:
    """Snapshot every signal the promotion / demotion rules read."""
    now = time.time()
    return {
        "evaluated_at":            now,
        "current_tier":            current_tier_int,
        "auto_feedback_rows":      _auto_feedback_rows(),
        "governor_proposal_count": _governor_proposal_count(window_days=7),
        "governor_accept_rate":    _governor_accept_rate(window_days=7),
        "revert_rate_24h":         _revert_rate(window_seconds=86400.0),
        "revert_rate_7d":          _revert_rate(window_seconds=7 * 86400.0),
        "revert_rate_14d":         _revert_rate(window_seconds=14 * 86400.0),
        "diff_log_match_rate":     _diff_log_match_rate(window_days=14),
        "days_at_tier":            _days_at_current_tier(),
    }


def _auto_feedback_rows() -> int:
    try:
        row = _conn().execute(
            "SELECT COUNT(*) FROM analyst_feedback "
            "WHERE analyst_id LIKE 'auto:%'"
        ).fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0


def _governor_proposal_count(window_days: float) -> int:
    """How many threshold_history rows landed in the window. The
    auto_tune_governor only writes accepted proposals, so this is
    "accepted in window"."""
    try:
        cutoff = time.time() - window_days * 86400.0
        row = _conn().execute(
            "SELECT COUNT(*) FROM threshold_history WHERE emitted_at >= ?",
            (cutoff,),
        ).fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0


def _governor_accept_rate(window_days: float) -> float:
    """Accept rate proxy. Without a per-proposal log of *all* attempts
    we approximate: (accepted rows) / max(1, (accepted + estimated
    rejects)). Estimated rejects = (calibrator_runs * keys_per_run -
    accepted). Without calibrator-level instrumentation we just return
    1.0 when at least one accept happened in the window — the goal is
    to gate Tier 0→1 on "the pipeline isn't completely jammed", not on
    a precise rejection ratio.
    """
    return 1.0 if _governor_proposal_count(window_days) > 0 else 0.0


def _revert_rate(window_seconds: float) -> float:
    """Fraction of accepted proposals that were superseded in the
    opposite direction within the window — a reliability indicator
    that the calibrator's proposals don't oscillate.

    For each (key, scope_scenario_id) we walk threshold_history in
    chronological order and count adjacent pairs where the sign of
    `magnitude_pct * (newer.value - older.value)` flips. The pair is
    counted as a "revert" only if the second event is within
    window_seconds of the first.
    """
    try:
        cutoff = time.time() - window_seconds * 2.0
        rows = list(_conn().execute(
            "SELECT key, scope_scenario_id, emitted_at, value "
            "FROM threshold_history "
            "WHERE emitted_at >= ? "
            "ORDER BY key, scope_scenario_id, emitted_at",
            (cutoff,),
        ))
    except Exception:
        return 0.0
    by_key: dict[tuple, list] = {}
    for r in rows:
        by_key.setdefault((r[0], r[1]), []).append(r)
    pairs = 0
    reverts = 0
    for series in by_key.values():
        for i in range(1, len(series)):
            prev = series[i - 1]
            curr = series[i]
            try:
                pv = float(prev[3])
                cv = float(curr[3])
            except (TypeError, ValueError):
                continue
            if curr[2] - prev[2] > window_seconds:
                continue
            pairs += 1
            # A revert is a sign flip in the delta direction relative
            # to the long-run trajectory of this key. With only two
            # samples we approximate: cv == pv → no revert, otherwise
            # we look at the next sample (if any) to confirm the flip.
            if i + 1 < len(series):
                try:
                    nv = float(series[i + 1][3])
                except (TypeError, ValueError):
                    continue
                # The current sample is a revert if it moves opposite
                # to the long-run delta (prev → next).
                long_delta = nv - pv
                short_delta = cv - pv
                if long_delta != 0 and (short_delta * long_delta) < 0:
                    reverts += 1
    return reverts / pairs if pairs > 0 else 0.0


def _diff_log_match_rate(window_days: float) -> float:
    try:
        cutoff = time.time() - window_days * 86400.0
        total = _conn().execute(
            "SELECT COUNT(*) FROM conclusion_diff_log WHERE sampled_at >= ?",
            (cutoff,),
        ).fetchone()[0]
        if total == 0:
            return 1.0  # no signal — don't penalise
        match = _conn().execute(
            "SELECT COUNT(*) FROM conclusion_diff_log "
            "WHERE sampled_at >= ? AND diff_kind='match'",
            (cutoff,),
        ).fetchone()[0]
        return match / total
    except Exception:
        return 1.0


def _days_at_current_tier() -> float:
    """Time since the most recent state-changing transition (i.e. not
    'unchanged' / 'evaluation_failed' / 'init')."""
    try:
        row = _conn().execute(
            "SELECT observed_at FROM auto_apply_tier_state "
            "WHERE transition IN ('promote','demote','circuit_breaker',"
            "                     'kill_switch_engaged','init') "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0.0
        return (time.time() - float(row[0])) / 86400.0
    except Exception:
        return 0.0


def _count_consecutive_failures() -> int:
    """Count adjacent 'evaluation_failed' rows ending at the latest
    row. Resets on any other transition kind."""
    try:
        rows = list(_conn().execute(
            "SELECT transition FROM auto_apply_tier_state "
            "ORDER BY id DESC LIMIT ?", (CONSECUTIVE_FAILURE_LIMIT * 2,),
        ))
    except Exception:
        return 0
    n = 0
    for r in rows:
        if r[0] == "evaluation_failed":
            n += 1
        else:
            break
    return n


# ── Cooldown helpers ─────────────────────────────────────────────────────────


def _is_in_cooldown(impact_level: str) -> bool:
    try:
        row = _conn().execute(
            "SELECT cooldown_until FROM auto_apply_cooldown "
            "WHERE impact_level=?",
            (impact_level,),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    except Exception:
        return False
    if row is None:
        return False
    return float(row[0]) > time.time()


# ── Audit row writer ─────────────────────────────────────────────────────────


def _record_transition(
    *,
    new_tier: int,
    transition: str,
    reason: str,
    metrics: dict,
) -> None:
    try:
        with _conn().writing():
            _conn().execute(
                "INSERT INTO auto_apply_tier_state "
                "(observed_at, tier, transition, reason, metrics_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), int(new_tier), str(transition), str(reason),
                 json.dumps(metrics, default=float)),
            )
        log.info(
            "[TierGovernor] %s tier=%d reason=%s",
            transition, new_tier, reason,
        )
    except Exception as exc:
        log.warning("could not record tier transition: %s", exc)


# ── Env gating ───────────────────────────────────────────────────────────────


def _tier_cap_from_env() -> int:
    """Kill-switch / cap. Set to 0 to halt auto-apply system-wide."""
    try:
        return max(0, min(TIER_FULL,
                          int(os.getenv("AUTO_CALIBRATION_TIER_CAP",
                                        str(TIER_FULL)))))
    except (TypeError, ValueError):
        return TIER_FULL


# ── Scheduler entry point ────────────────────────────────────────────────────


def run_once() -> dict:
    """Daily-tick entry point. Returns a serialisable summary the
    scheduler can log."""
    result = evaluate_and_transition()
    return {
        "prior_tier": result.prior_tier,
        "new_tier":   result.new_tier,
        "transition": result.transition,
        "reason":     result.reason,
        "metrics":    result.metrics,
    }
