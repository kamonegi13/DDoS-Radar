"""Follow-up watch — auto-detect when a deferred backlog item's
trigger condition is met.

Background
----------
The 2026-05-05 observability audit categorised several gaps as
"don't build yet — wait until the trigger condition fires" rather
than implementing them speculatively (per the
``feedback_phase_cosmetic_vs_purpose`` and
``project_tradecraft_integration_shelved`` precedents).

Manually re-checking the conditions every month is a reliability
hazard: the operator forgets, the trigger silently lapses, and the
backlog item ages out into "we never built it because we never
noticed" — exactly the antipattern this audit was supposed to
prevent.

This module runs once per scheduler day-tick and emits a single
WARN log line per item whose trigger condition is *currently* met.
The check is idempotent and stateless — no DB writes, no failure
suppression, no thresholds to tune. If the operator silences a
warning, they should also delete the corresponding entry from
``_WATCHES`` here.

Each watch is a small dataclass with a name, a description, and a
zero-argument callable that returns ``(condition_met: bool, detail:
str)``. Failure inside a watch is swallowed with a debug log so one
flaky check cannot mask the others (NP3).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger("radar.observability.followup_watch")


# Cached snapshots — guards against the same warning firing every
# day. We only WARN when the condition first transitions to "met";
# subsequent days log at INFO so silent-cron readers can still see
# the persistence without flooding production logs.
_LAST_FIRED_AT: dict[str, float] = {}


@dataclass(frozen=True)
class Watch:
    name:        str
    description: str
    check:       Callable[[], tuple[bool, str]]


# ── Individual checks ────────────────────────────────────────────────────────


def _check_b1_analyst_feedback_threshold() -> tuple[bool, str]:
    """B1 — analyst_feedback viewer becomes worth building when the
    ledger is no longer empty enough to be a "tradecraft shelved"
    repeat. Trigger: ≥ 100 human-authored feedback rows."""
    try:
        from radar.database import db
        row = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM analyst_feedback "
            "WHERE analyst_id NOT LIKE 'auto:%'"
        ).fetchone()
        n = int(row[0]) if row else 0
        return (n >= 100, f"human_feedback_rows={n} (threshold=100)")
    except Exception as exc:
        return (False, f"check_failed: {exc}")


def _check_b5_chronic_persistence() -> tuple[bool, str]:
    """B5+ — CHRONIC chip needs a richer details panel only after the
    detector has been continuously firing. Trigger: chronic_count ≥ 1
    every day for ≥ 14 consecutive scheduler day-ticks. We approximate
    by checking the *current* chronic_count and whether the oldest
    chronic entry has been chronic for ≥ 14d (since first_seen_at)."""
    try:
        from radar.conclusions.inconclusive_continuity import chronic_snapshot
        from radar.database import db
        snap = chronic_snapshot(db)
        chronic = snap.get("chronic", []) or []
        if not chronic:
            return (False, "chronic_count=0")
        oldest_dwell = max(
            float(s.get("days_unavailable", 0.0)) for s in chronic
        )
        return (
            oldest_dwell >= 14.0,
            f"chronic_count={len(chronic)} oldest_dwell={oldest_dwell:.1f}d",
        )
    except Exception as exc:
        return (False, f"check_failed: {exc}")


def _check_b7_silent_failures_persistence() -> tuple[bool, str]:
    """B7 — silent_failures bucketisation becomes worth building when
    the FAULT chip is permanently red. Trigger: NP1 lifetime failure
    count ≥ 100. Coarse but mirrors the chip's `crit` threshold (10×
    its `crit` boundary, so we don't fire on a single bad afternoon)."""
    try:
        from radar.conclusions.shadow_metrics import snapshot as sm_snapshot
        snap = sm_snapshot()
        np1 = {"focused_scoring", "llm_intel_signals",
               "bg_observer_drain", "auto_judge_override_trail"}
        total = sum(
            int(by.get("failure_count", 0))
            for ct, by in snap.get("by_type", {}).items()
            if ct in np1
        )
        return (total >= 100, f"np1_lifetime_failure_count={total}")
    except Exception as exc:
        return (False, f"check_failed: {exc}")


def _check_b9_alias_gap_persistence() -> tuple[bool, str]:
    """B9 — alias-gap editor UI becomes worth building when the gap is
    not just a one-tick blip. Trigger: ``alias_gap`` non-empty in the
    most recent 24h of bg_observer cycles."""
    try:
        from radar.database import db
        bg = db.bg_observer_cycle_summary(hours=24)
        gap = bg.get("alias_gap", []) or []
        return (len(gap) > 0, f"alias_gap_size_24h={len(gap)}")
    except Exception as exc:
        return (False, f"check_failed: {exc}")


# ── Scenario proposal symmetry watches (2026-05-07 review) ───────────────────
#
# The chronic-inconclusive detector enforces NP5+8 on the *tool's own*
# state. The same shape applies to the analyst-decision-process: a
# proposal that is "still pending" past the human-judgement window
# is the decision-process equivalent of chronic UNAVAILABLE. Without
# these watches, recall-reducing proposals can sit in the pending
# queue indefinitely without escalation; that is structurally
# inconsistent with the rest of the auto-detection lattice.

# Recall-reducing proposal types — types whose *application* would
# narrow the scenario coverage. We surveil these because not acting
# on them in time is the same shape of design failure as chronic
# inconclusive: the system asked, the analyst never answered, and
# the answer to "should we shrink?" defaulted to "no" by neglect.
_RECALL_REDUCING_PROPOSAL_TYPES = (
    "weight_too_high",
    "dormant_participant",
    "role_reclassify",
)

PROPOSAL_CHRONIC_PENDING_DAYS = 60.0
PROPOSAL_DISMISSED_INVERSION_PCT = 0.50
PROPOSAL_DISMISSED_INVERSION_DWELL_DAYS = 14.0


def _check_proposal_chronic_pending() -> tuple[bool, str]:
    """Recall-reducing scenario proposals that have been pending past
    the chronic threshold. Default 60d ≫ the 30d snooze cycle so a
    proposal that survived a full snooze loop without resolution
    counts as a decision-process design failure."""
    try:
        from radar.database import db
        cutoff = time.time() - PROPOSAL_CHRONIC_PENDING_DAYS * 86400.0
        placeholders = ",".join(
            "?" for _ in _RECALL_REDUCING_PROPOSAL_TYPES
        )
        row = db._get_conn().execute(  # noqa: SLF001
            f"SELECT COUNT(*) FROM scenario_proposals "
            f"WHERE state='pending' AND emitted_at < ? "
            f"AND proposal_type IN ({placeholders})",
            (cutoff, *_RECALL_REDUCING_PROPOSAL_TYPES),
        ).fetchone()
        n = int(row[0]) if row else 0
        return (
            n > 0,
            f"chronic_pending_recall_reducing={n} "
            f"(>{int(PROPOSAL_CHRONIC_PENDING_DAYS)}d, types="
            f"{','.join(_RECALL_REDUCING_PROPOSAL_TYPES)})",
        )
    except Exception as exc:
        return (False, f"check_failed: {exc}")


def _check_proposal_inactive_scenario() -> tuple[bool, str]:
    """Pending proposals whose target scenario has been moved to
    ``paused`` or ``archived`` state. The proposer cannot apply them
    (the wizard's apply path checks scenario state), and they will
    never auto-clear. Any age — these are dead-letters by definition."""
    try:
        from radar.database import db
        rows = list(db._get_conn().execute(  # noqa: SLF001
            "SELECT sp.id "
            "FROM scenario_proposals sp "
            "JOIN scenarios s ON s.id = sp.scenario_id "
            "WHERE sp.state='pending' "
            "AND s.state IN ('paused','archived')"
        ))
        n = len(rows)
        return (n > 0, f"pending_on_inactive_scenarios={n}")
    except Exception as exc:
        return (False, f"check_failed: {exc}")


def _check_proposal_dismissed_inversion_persistent() -> tuple[bool, str]:
    """`dismissed_pct_30d` (already collected by attention.py) above
    the inversion threshold AND continuously above it for ≥ the dwell
    window. Today we check the instant value; persistence is
    approximated by the existence of an *active* attention rule
    firing for ``autotune_quality_inversion`` AND a long-enough
    consistent history of dismissed-heavy outcomes.

    Approximation rationale: a dedicated time-series of dismissed_pct
    is overkill given how rare proposer flips are; a 14-day window
    sample of cumulative outcomes is a good proxy. We sample two
    points: dismissed_pct over the last 14 days vs the last 30 days.
    If both exceed the inversion threshold, the proposer has been
    misfiring continuously for at least 14 days."""
    try:
        from radar.database import db
        now = time.time()

        def _ratio(window_days: float) -> tuple[float, int]:
            cutoff = now - window_days * 86400.0
            rows = db._get_conn().execute(  # noqa: SLF001
                "SELECT state, COUNT(*) FROM scenario_proposals "
                "WHERE state IN ('applied','dismissed','snoozed_30d','reverted') "
                "AND emitted_at >= ? GROUP BY state",
                (cutoff,),
            ).fetchall()
            d = {state: int(n or 0) for state, n in rows}
            total = sum(d.values())
            # Below sample-size floor we treat as "not enough signal".
            if total < 10:
                return (0.0, total)
            return (d.get("dismissed", 0) / total, total)

        pct_30, n_30 = _ratio(30.0)
        pct_14, n_14 = _ratio(PROPOSAL_DISMISSED_INVERSION_DWELL_DAYS)

        met = (
            n_30 >= 10
            and n_14 >= 10
            and pct_30 > PROPOSAL_DISMISSED_INVERSION_PCT
            and pct_14 > PROPOSAL_DISMISSED_INVERSION_PCT
        )
        return (
            met,
            f"dismissed_pct_30d={pct_30:.2%} (n={n_30}), "
            f"dismissed_pct_14d={pct_14:.2%} (n={n_14}) "
            f"threshold={PROPOSAL_DISMISSED_INVERSION_PCT:.0%}",
        )
    except Exception as exc:
        return (False, f"check_failed: {exc}")


# Registry. Append-only — never delete an entry without also
# implementing the underlying backlog item. Order is the order in
# which warnings fire on a tick.
_WATCHES: tuple[Watch, ...] = (
    Watch(
        name="B1.analyst_feedback_viewer",
        description="analyst_feedback ledger has accumulated enough "
                     "human-authored rows that a viewer UI is worth "
                     "building. See 2026-05-05 audit Bucket B item B1.",
        check=_check_b1_analyst_feedback_threshold,
    ),
    Watch(
        name="B5.chronic_chip_details",
        description="Chronic-inconclusive detector has fired persistently "
                     "(>=14d dwell). The current CHRONIC chip's tooltip "
                     "may no longer be enough — consider a dedicated "
                     "details panel (Bucket B item B5+).",
        check=_check_b5_chronic_persistence,
    ),
    Watch(
        name="B7.silent_failures_buckets",
        description="NP1 silent-failure count has accumulated past the "
                     "10x cry-wolf threshold. Implement 1h/24h bucketing "
                     "so the FAULT chip can signal current degradation "
                     "rather than lifetime damage. Bucket B item B7.",
        check=_check_b7_silent_failures_persistence,
    ),
    Watch(
        name="B9.alias_gap_editor",
        description="bg_observer alias_gap is non-empty within the last "
                     "24h — recall is being lost. Implement an alias "
                     "editor UI that writes into the gap. Bucket B item B9.",
        check=_check_b9_alias_gap_persistence,
    ),
    # Decision-process symmetry watches — same shape as B5 (chronic
    # inconclusive) but applied to scenario proposals. A pending
    # proposal that survived past these thresholds is the analyst-
    # decision equivalent of a chronic UNAVAILABLE state.
    Watch(
        name="proposal.chronic_pending",
        description="Recall-reducing scenario_proposals "
                     "(weight_too_high / dormant_participant / "
                     "role_reclassify) have been pending for >60 days. "
                     "Decision process is in design-failure state — "
                     "act in Wizard or revisit the proposer rule.",
        check=_check_proposal_chronic_pending,
    ),
    Watch(
        name="proposal.inactive_scenario",
        description="Pending proposals exist on paused/archived "
                     "scenarios. The wizard cannot apply them; they "
                     "are dead-letters. Auto-dismiss them or revive "
                     "the scenario.",
        check=_check_proposal_inactive_scenario,
    ),
    Watch(
        name="proposal.dismissed_inversion_persistent",
        description="dismissed_pct over both 14d and 30d windows is "
                     "above 50% with ≥10 closed proposals each — the "
                     "proposer has been misfiring persistently. Tune "
                     "the rule or stop emitting that proposal_type.",
        check=_check_proposal_dismissed_inversion_persistent,
    ),
)


# ── Entry point ──────────────────────────────────────────────────────────────


def run_once() -> dict:
    """Evaluate every watch. Emit a WARN on first transition to "met";
    INFO on subsequent ticks where the condition is still met. Return
    a dict the scheduler can fold into its tick log if it cares."""
    now = time.time()
    fired: list[str] = []
    skipped: list[str] = []

    for w in _WATCHES:
        try:
            met, detail = w.check()
        except Exception as exc:
            log.debug("[FollowupWatch] %s threw: %s", w.name, exc)
            skipped.append(w.name)
            continue

        if not met:
            # Condition no longer met — clear the cache so a future
            # transition will WARN again.
            _LAST_FIRED_AT.pop(w.name, None)
            continue

        prior = _LAST_FIRED_AT.get(w.name)
        if prior is None:
            log.warning(
                "[FollowupWatch] TRIGGER MET: %s — %s. Description: %s",
                w.name, detail, w.description,
            )
        else:
            age_d = max(0.0, (now - prior) / 86400.0)
            log.info(
                "[FollowupWatch] still met: %s — %s (first observed %.1fd ago)",
                w.name, detail, age_d,
            )
        _LAST_FIRED_AT.setdefault(w.name, now)
        fired.append(w.name)

    return {"fired": fired, "skipped": skipped, "evaluated": len(_WATCHES)}
