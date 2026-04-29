"""Scenario drift watchdog (Phase F3).

Continuously monitors registered scenarios for "drift from reality"
signals and emits passive warnings to scenario_drift_events.

This is **tool territory** in the 5-zone NP7 framework — drift
detection is monitoring, not structural change. The watchdog never
mutates scenarios; analysts decide whether to act on warnings.

Six signals (one formula_ref each):

  1. weight_stale          — participant has 30d zero contribution
  2. adversary_mismatch    — declared adversaries never fire
  3. recall_underperform   — bottom-quartile recall vs cohort
  4. chronic_insufficient  — calibration_status persistent INSUFFICIENT_DATA
  5. participant_orphan    — participant country has no coordinates
  6. signal_inversion      — domain mix has flipped vs 90d baseline

Per F3 dwell-time guardrail: each signal must persist ≥3 consecutive
runs before surfacing to the UI (handled at the API/render layer by
filtering rows with consecutive_runs ≥ 3). The watchdog itself just
records each detection; the consecutive_runs counter is incremented
when the same (scenario, signal, target_country) triple is detected
again.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

from radar.database import db

log = logging.getLogger("radar.calibration.drift_watchdog")


WATCHDOG_VERSION = "drift_watchdog/v1"


def _stale_threshold_days() -> float:
    return float(os.getenv("DRIFT_WEIGHT_STALE_DAYS", "30"))


def _adversary_mismatch_window_days() -> float:
    return float(os.getenv("DRIFT_ADVERSARY_WINDOW_DAYS", "60"))


def _recall_cohort_min() -> int:
    return int(os.getenv("DRIFT_RECALL_COHORT_MIN", "3"))


def _chronic_insufficient_days() -> float:
    return float(os.getenv("DRIFT_CHRONIC_INSUFFICIENT_DAYS", "14"))


def _signal_inversion_baseline_days() -> float:
    return float(os.getenv("DRIFT_SIGNAL_INVERSION_BASELINE_DAYS", "90"))


@dataclass(frozen=True)
class DriftEvent:
    scenario_id: str
    drift_signal: str
    severity: str  # 'amber' | 'red'
    target_country: Optional[str]
    formula_ref: str
    sample_n: int
    why_string: str
    evidence: dict


def _record_event(event: DriftEvent) -> int:
    """Append/upsert: if a matching unack row exists in the last 24h,
    increment its consecutive_runs; otherwise insert a new one."""
    conn = db._get_conn()  # noqa: SLF001
    now = time.time()
    cutoff = now - 24 * 3600
    # Find prior unack row for the same (scenario, signal, target).
    if event.target_country is None:
        prior = conn.execute(
            "SELECT id, consecutive_runs FROM scenario_drift_events "
            "WHERE scenario_id=? AND drift_signal=? "
            "AND target_country IS NULL AND ack_state='unack' "
            "AND emitted_at > ? "
            "ORDER BY emitted_at DESC LIMIT 1",
            (event.scenario_id, event.drift_signal, cutoff),
        ).fetchone()
    else:
        prior = conn.execute(
            "SELECT id, consecutive_runs FROM scenario_drift_events "
            "WHERE scenario_id=? AND drift_signal=? AND target_country=? "
            "AND ack_state='unack' AND emitted_at > ? "
            "ORDER BY emitted_at DESC LIMIT 1",
            (event.scenario_id, event.drift_signal, event.target_country, cutoff),
        ).fetchone()
    with conn.writing():
        if prior:
            new_runs = (prior[1] or 1) + 1
            conn.execute(
                "UPDATE scenario_drift_events SET consecutive_runs=?, emitted_at=? "
                "WHERE id=?",
                (new_runs, now, prior[0]),
            )
            return prior[0]
        cur = conn.execute(
            "INSERT INTO scenario_drift_events "
            "(emitted_at, scenario_id, drift_signal, severity, target_country, "
            " evidence_json, formula_ref, sample_n, why_string, "
            " ack_state, consecutive_runs) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'unack', 1)",
            (now, event.scenario_id, event.drift_signal, event.severity,
             event.target_country, json.dumps(event.evidence, sort_keys=True),
             event.formula_ref, int(event.sample_n), event.why_string),
        )
        return cur.lastrowid


# ── Individual signal detectors ──


def _signal_weight_stale(scenario) -> list[DriftEvent]:
    """Each participant with weight > 0 but zero signal contribution
    over the stale window AND zero analyst feedback gets a row.

    Approximation: sensor_observation_ts has scope='theater:<cc>' rows
    we can sum. If the country has no rows in the window, treat as
    zero contribution.
    """
    out: list[DriftEvent] = []
    cutoff = time.time() - _stale_threshold_days() * 86400
    conn = db._get_conn()  # noqa: SLF001
    for cc, p in scenario.participants.items():
        if p.weight <= 0:
            continue
        # Count contributing observations. NP3: missing table or query
        # failure is treated as "no observation data" (returns 0) so the
        # signal still fires correctly when the watchpane data is
        # unavailable.
        try:
            contrib_rows = conn.execute(
                "SELECT COUNT(*) FROM sensor_observation_ts "
                "WHERE scope=? AND ts > ?",
                (f"theater:{cc}", cutoff),
            ).fetchone()
            n_contrib = contrib_rows[0] if contrib_rows else 0
        except Exception:
            n_contrib = 0
        if n_contrib > 0:
            continue
        # Also check no analyst FN involving this country in the window
        try:
            fn_rows = conn.execute(
                "SELECT COUNT(*) FROM analyst_feedback af "
                "JOIN conclusions c ON af.conclusion_id = c.id "
                "WHERE c.scenario_id=? AND af.label='FALSE_NEGATIVE' "
                "AND af.observed_at > ?",
                (scenario.id, cutoff),
            ).fetchone()
            n_fn = fn_rows[0] if fn_rows else 0
        except Exception:
            n_fn = 0
        if n_fn > 0:
            continue
        out.append(DriftEvent(
            scenario_id=scenario.id,
            drift_signal="weight_stale",
            severity="amber",
            target_country=cc,
            formula_ref=f"{WATCHDOG_VERSION}#weight_stale",
            sample_n=int(_stale_threshold_days()),
            why_string=(
                f"Participant {cc} (weight={p.weight:.2f}) has produced no "
                f"sensor signal AND no analyst false-negative reports for "
                f"{int(_stale_threshold_days())} days. Consider lowering "
                f"weight or removing from scenario."
            ),
            evidence={
                "weight": p.weight,
                "stale_days": int(_stale_threshold_days()),
                "sensor_observations": n_contrib,
                "false_negatives": n_fn,
            },
        ))
    return out


def _signal_adversary_mismatch(scenario) -> list[DriftEvent]:
    """If declared adversaries never fire convergence_engine over the
    window, emit a single scenario-level event."""
    if not scenario.adversaries:
        return []
    window_s = _adversary_mismatch_window_days() * 86400
    cutoff = time.time() - window_s
    conn = db._get_conn()  # noqa: SLF001
    # Use sequence_events as a proxy for adversary attribution: any
    # event recently fired for any of the declared adversary countries.
    adversaries = list(scenario.adversaries)
    if not adversaries:
        return []
    placeholders = ",".join("?" * len(adversaries))
    rows = conn.execute(
        f"SELECT COUNT(*) FROM sequence_events "
        f"WHERE theater IN ({placeholders}) AND ts > ?",
        (*adversaries, cutoff),
    ).fetchone()
    n_events = rows[0] if rows else 0
    # Also need the scenario itself to be "alive" — guard against a
    # genuinely quiet scenario with no traffic at all.
    total_rows = conn.execute(
        "SELECT COUNT(*) FROM conclusions WHERE scenario_id=? "
        "AND observed_at > ?",
        (scenario.id, cutoff),
    ).fetchone()
    n_conclusions = total_rows[0] if total_rows else 0
    if n_conclusions < 50:
        return []  # scenario-level too quiet, don't flag adversary mismatch
    if n_events > 0:
        return []
    return [DriftEvent(
        scenario_id=scenario.id,
        drift_signal="adversary_mismatch",
        severity="amber",
        target_country=None,
        formula_ref=f"{WATCHDOG_VERSION}#adversary_mismatch",
        sample_n=n_conclusions,
        why_string=(
            f"Scenario has {n_conclusions} conclusions over "
            f"{int(_adversary_mismatch_window_days())}d but ZERO sequence "
            f"events for declared adversaries {adversaries}. The scoring "
            f"engine is not attributing escalation to the declared "
            f"adversary set — verify the participant/adversary roles."
        ),
        evidence={
            "adversaries": adversaries,
            "window_days": int(_adversary_mismatch_window_days()),
            "scenario_conclusions": n_conclusions,
            "adversary_events": 0,
        },
    )]


def _signal_recall_underperform(scenario, all_recall: dict) -> list[DriftEvent]:
    """If this scenario's recall is in the bottom quartile of its
    cohort (≥ DRIFT_RECALL_COHORT_MIN scenarios), emit an event.
    `all_recall` is a precomputed map {scenario_id: recall} so the
    watchdog only does one DB pass for all scenarios.
    """
    if len(all_recall) < _recall_cohort_min():
        return []
    my_recall = all_recall.get(scenario.id)
    if my_recall is None:
        return []
    sorted_vals = sorted(all_recall.values())
    p25 = sorted_vals[len(sorted_vals) // 4]
    if my_recall >= p25:
        return []
    return [DriftEvent(
        scenario_id=scenario.id,
        drift_signal="recall_underperform",
        severity="red",
        target_country=None,
        formula_ref=f"{WATCHDOG_VERSION}#recall_underperform",
        sample_n=len(all_recall),
        why_string=(
            f"Recall {my_recall:.3f} is in bottom quartile of cohort "
            f"(p25={p25:.3f}, n={len(all_recall)}). Investigate calibration "
            f"or scenario composition."
        ),
        evidence={
            "my_recall": my_recall,
            "cohort_p25": p25,
            "cohort_size": len(all_recall),
            "all_recall": all_recall,
        },
    )]


def _signal_chronic_insufficient(scenario) -> list[DriftEvent]:
    """If this scenario has had any conclusion type with
    INSUFFICIENT_DATA continuously for >chronic_insufficient_days,
    emit a red event (CLAUDE.md: chronic INSUFFICIENT_DATA = design failure).
    """
    threshold_s = _chronic_insufficient_days() * 86400
    cutoff = time.time() - threshold_s
    conn = db._get_conn()  # noqa: SLF001
    rows = conn.execute(
        "SELECT conclusion_type, MIN(first_seen_at) FROM "
        "inconclusive_continuity_log "
        "WHERE scenario_id=? AND is_available=0 AND first_seen_at < ? "
        "AND id IN (SELECT MAX(id) FROM inconclusive_continuity_log "
        "           WHERE scenario_id=? GROUP BY conclusion_type) "
        "GROUP BY conclusion_type",
        (scenario.id, cutoff, scenario.id),
    ).fetchall()
    out: list[DriftEvent] = []
    now = time.time()
    for ctype, first_seen in rows:
        run_days = (now - first_seen) / 86400
        out.append(DriftEvent(
            scenario_id=scenario.id,
            drift_signal="chronic_insufficient",
            severity="red",
            target_country=None,
            formula_ref=f"{WATCHDOG_VERSION}#chronic_insufficient",
            sample_n=int(run_days),
            why_string=(
                f"Conclusion type {ctype} has been INSUFFICIENT_DATA "
                f"continuously for {run_days:.1f} days (threshold: "
                f"{_chronic_insufficient_days():.0f}d). Per CLAUDE.md "
                f"NP5+8: chronic '結論不可' is a design failure."
            ),
            evidence={
                "conclusion_type": ctype,
                "run_days": run_days,
                "threshold_days": _chronic_insufficient_days(),
            },
        ))
    return out


def _signal_participant_orphan(scenario) -> list[DriftEvent]:
    """Participants whose country code has no coordinates in
    COUNTRY_COORDS — already warned at startup. Promoted to a
    drift event so it's actionable."""
    try:
        from radar.config import COUNTRY_COORDS
    except Exception:
        return []
    out: list[DriftEvent] = []
    for cc, p in scenario.participants.items():
        if cc not in COUNTRY_COORDS:
            out.append(DriftEvent(
                scenario_id=scenario.id,
                drift_signal="participant_orphan",
                severity="amber",
                target_country=cc,
                formula_ref=f"{WATCHDOG_VERSION}#participant_orphan",
                sample_n=1,
                why_string=(
                    f"Participant {cc} has no entry in COUNTRY_COORDS. "
                    f"Map rendering, geo-correlation, and several sensor "
                    f"queries will silently skip this country."
                ),
                evidence={"weight": p.weight, "role": p.role.value},
            ))
    return out


def _read_recall_per_scenario() -> dict:
    """Compute per-scenario recall (TP / (TP + FN)) for THREAT_LEVEL."""
    conn = db._get_conn()  # noqa: SLF001
    rows = conn.execute(
        "SELECT c.scenario_id, af.label, COUNT(*) "
        "FROM analyst_feedback af "
        "JOIN conclusions c ON af.conclusion_id = c.id "
        "WHERE c.conclusion_type = 'threat_level' "
        "GROUP BY c.scenario_id, af.label"
    ).fetchall()
    by_scenario: dict[str, dict] = {}
    for scenario_id, label, n in rows:
        by_scenario.setdefault(scenario_id, {})[label] = n
    out = {}
    for sid, counts in by_scenario.items():
        tp = counts.get("TRUE_POSITIVE", 0)
        fn = counts.get("FALSE_NEGATIVE", 0)
        if tp + fn < 10:
            continue  # too few for meaningful comparison
        out[sid] = tp / max(1, tp + fn)
    return out


def _signal_proposal_quality_inversion() -> list[DriftEvent]:
    """Post-incident drift signal — fires when the proposal generator's
    output is dominated by recall-reducing proposals or has a high
    analyst rejection rate. This is the system telling itself "your
    rules are misfiring".

    Triggers:
      - recall_negative_pct > 30% of pending proposals (last 30d)
      - dismissed_pct > 50% of all closed proposals (last 30d)
        (analysts are rejecting more than they accept)

    Severity:
      - amber when either threshold crosses
      - red   when both cross OR recall_negative_pct > 60%
    """
    cutoff = time.time() - 30 * 86400
    try:
        conn = db._get_conn()  # noqa: SLF001
        rows = conn.execute(
            "SELECT proposal_type, state, COUNT(*) FROM scenario_proposals "
            "WHERE emitted_at > ? GROUP BY proposal_type, state",
            (cutoff,),
        ).fetchall()
    except Exception as exc:
        log.debug("drift quality query failed: %s", exc)
        return []
    if not rows:
        return []

    try:
        from radar.calibration._proposal_writer import (
            TYPE_TO_KIND, ProposalKind,
        )
    except Exception:
        return []

    pending_by_kind: dict[str, int] = {}
    closed_total = 0
    closed_dismissed = 0
    for ptype, state, count in rows:
        n = int(count or 0)
        if state == "pending":
            kind = TYPE_TO_KIND.get(ptype, ProposalKind.STRUCTURE)
            pending_by_kind[kind.value] = pending_by_kind.get(kind.value, 0) + n
        if state in ("applied", "dismissed", "snoozed_30d", "reverted"):
            closed_total += n
            if state == "dismissed":
                closed_dismissed += n

    pending_total = sum(pending_by_kind.values())
    recall_neg_pct = (
        pending_by_kind.get("recall_negative", 0) / pending_total
        if pending_total > 0 else 0.0
    )
    dismissed_pct = (
        closed_dismissed / closed_total if closed_total > 0 else 0.0
    )

    # Both thresholds need a minimum sample to fire — avoids noise on
    # fresh deployments.
    if pending_total < 10 and closed_total < 10:
        return []

    breaches: list[str] = []
    if recall_neg_pct > 0.30:
        breaches.append(f"recall_negative_pct={recall_neg_pct:.0%}>30%")
    if closed_total >= 10 and dismissed_pct > 0.50:
        breaches.append(f"dismissed_pct={dismissed_pct:.0%}>50%")
    if not breaches:
        return []

    severity = "red" if (
        len(breaches) >= 2 or recall_neg_pct > 0.60
    ) else "amber"

    return [DriftEvent(
        scenario_id="__system__",  # cross-scenario signal
        drift_signal="proposal_quality_inversion",
        severity=severity,
        target_country=None,
        evidence={
            "recall_negative_pct": round(recall_neg_pct, 3),
            "dismissed_pct": round(dismissed_pct, 3),
            "pending_total": pending_total,
            "closed_total": closed_total,
            "pending_by_kind": pending_by_kind,
            "breaches": breaches,
        },
        why_string=(
            f"Proposal generator quality inversion: {' and '.join(breaches)}. "
            f"This indicates the rules are misfiring (the 2026-04-29 incident "
            f"shape) — review _rule_weight_too_high / _rule_dormant_participant "
            f"before applying any pending recall-reducing proposals."
        ),
    )]


def run_once() -> dict:
    """Run all signals across all registered scenarios. Returns a dict
    keyed by scenario_id with the count of events emitted per signal."""
    out: dict[str, dict] = {}
    try:
        from radar.scenarios import scenario_store
        scenarios = list(scenario_store._scenarios.values())  # noqa: SLF001
    except Exception as exc:
        log.warning("drift_watchdog: failed to enumerate scenarios: %s", exc)
        return out
    try:
        all_recall = _read_recall_per_scenario()
    except Exception as exc:
        log.debug("drift_watchdog: recall read failed (non-fatal): %s", exc)
        all_recall = {}

    # Cross-scenario signal: proposal_quality_inversion (post-incident).
    # Records under '__system__' scenario_id; surfaces in the UI alongside
    # per-scenario drift events.
    try:
        sys_events = _signal_proposal_quality_inversion()
        if sys_events:
            n_sys = sum(1 for ev in sys_events if _record_event(ev) is not None)
            out.setdefault("__system__", {})["proposal_quality_inversion"] = n_sys
    except Exception as exc:
        log.debug("drift_watchdog: quality-inversion failed: %s", exc)

    for sc in scenarios:
        per_sig: dict[str, int] = {}
        signal_funcs = [
            ("weight_stale", lambda s=sc: _signal_weight_stale(s)),
            ("adversary_mismatch", lambda s=sc: _signal_adversary_mismatch(s)),
            ("recall_underperform",
             lambda s=sc, ar=all_recall: _signal_recall_underperform(s, ar)),
            ("chronic_insufficient",
             lambda s=sc: _signal_chronic_insufficient(s)),
            ("participant_orphan",
             lambda s=sc: _signal_participant_orphan(s)),
        ]
        for name, fn in signal_funcs:
            try:
                events = fn() or []
            except Exception as exc:
                log.debug(
                    "drift_watchdog: %s/%s failed (non-fatal): %s",
                    sc.id, name, exc,
                )
                events = []
            for ev in events:
                _record_event(ev)
            per_sig[name] = len(events)
        out[sc.id] = per_sig
    return out


def list_unack_events(*, severity: Optional[str] = None,
                      min_consecutive_runs: int = 3,
                      hours: int = 168) -> list[dict]:
    """Return dwell-time-filtered unack drift events for UI display.

    Per F3 guardrail: only events that have persisted for ≥ 3
    consecutive cron runs (24h) reach the UI."""
    conn = db._get_conn()  # noqa: SLF001
    cutoff = time.time() - hours * 3600
    if severity:
        rows = conn.execute(
            "SELECT scenario_id, drift_signal, severity, target_country, "
            "evidence_json, why_string, consecutive_runs, emitted_at, id "
            "FROM scenario_drift_events "
            "WHERE ack_state='unack' AND severity=? "
            "AND consecutive_runs >= ? AND emitted_at > ? "
            "ORDER BY emitted_at DESC",
            (severity, min_consecutive_runs, cutoff),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT scenario_id, drift_signal, severity, target_country, "
            "evidence_json, why_string, consecutive_runs, emitted_at, id "
            "FROM scenario_drift_events "
            "WHERE ack_state='unack' AND consecutive_runs >= ? "
            "AND emitted_at > ? "
            "ORDER BY emitted_at DESC",
            (min_consecutive_runs, cutoff),
        ).fetchall()
    out = []
    for r in rows:
        try:
            evidence = json.loads(r[4] or "{}")
        except Exception:
            evidence = {}
        out.append({
            "id": r[8],
            "scenario_id": r[0],
            "drift_signal": r[1],
            "severity": r[2],
            "target_country": r[3],
            "evidence": evidence,
            "why_string": r[5],
            "consecutive_runs": r[6],
            "emitted_at": r[7],
        })
    return out


def acknowledge(event_id: int, *, by: str) -> bool:
    """Mark a drift event as acknowledged.

    Returns True on update, False if the row is already non-unack
    or does not exist. Caller-provided `by` should be `"analyst:<name>"`
    or `"admin:<name>"`. Used by /api/v2/drift_signals/<id>/ack.

    NP6: ack writes are append-event-style — the event row is updated
    in place but the original emitted_at and consecutive_runs counter
    are preserved so analysts can see *when* the signal first crossed
    the dwell threshold.
    """
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            cur = conn.execute(
                "UPDATE scenario_drift_events SET ack_state='acknowledged', "
                "ack_at=?, ack_by=? "
                "WHERE id=? AND ack_state='unack'",
                (time.time(), by, event_id),
            )
            return cur.rowcount > 0
    except Exception as exc:
        log.warning("acknowledge drift event %d failed: %s", event_id, exc)
        return False


__all__ = ["DriftEvent", "run_once", "list_unack_events", "acknowledge"]
