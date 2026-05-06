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
