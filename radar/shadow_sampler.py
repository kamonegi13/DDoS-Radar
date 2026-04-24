"""radar.shadow_sampler -- Background C-medium evaluation harness (ADR-025).

Problem (Section 9.3.1 structural defect):
  cmedium_recommendation requires focus_switch_log entries to evaluate whether
  C-lite is sufficient. focus_switch_log is only written when an analyst
  rotates focus between scenarios, which in steady-state operation rarely
  happens — leaving the recommendation perpetually INSUFFICIENT_DATA.

Solution (Plan B — Shadow Sampling, ADR-025):
  On each focused scoring cycle, opportunistically pick one non-focused
  scenario (round-robin LRU) and synthesise a (lite, full) score pair from
  the SAME signal set already collected for the focused scenario. Append the
  pair to focus_switch_log with source='shadow_sampler' so the C-medium
  recommendation has data without requiring analyst focus rotation.

Invariants:
  I-1  TL (threat level) is never derived from shadow scores — they only
       feed focus_switch_log delta statistics.
  I-2  Sequence events are not registered from shadow scoring.
  I-3  Intel queue is not touched (no submissions, no overrides).
  I-4  All shadow rows are tagged source='shadow_sampler' so the analyst
       provenance is preserved.
  I-5  Determinism: shadow_lite == background-mode score and shadow_full ==
       focused-mode score for the same signal snapshot.
  I-6  Concurrency: a single instance lock prevents two worker greenlets
       from sampling the same scenario in the same cycle.
  I-7  Stale degradation: if the cycle has no signals (rare), the sample is
       skipped (not written) rather than recording a zero-zero pair.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING

from radar.config import (
    SHADOW_SAMPLING_ENABLED,
    SHADOW_SAMPLING_MIN_GAP_SEC,
    SHADOW_SAMPLING_MAX_PER_DAY,
    SHADOW_SAMPLING_REQUIRE_OVERLAP,
    SHADOW_SAMPLING_WARMUP_SEC,
    C_MEDIUM_DELTA_MISS_SHADOW,
    GLOBAL_SIGNAL_WEIGHT,
    DOMAIN_CAP,
)

if TYPE_CHECKING:
    from radar.scoring import Signal

log = logging.getLogger("radar")

_PROCESS_START = time.time()


class ShadowSampler:
    """Picks a non-focused scenario per cycle and writes a synthetic
    (lite, full) score pair to focus_switch_log."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def record_shadow_sample(self,
                             focused_id: str,
                             signals: list["Signal"],
                             current_time: float) -> dict | None:
        """Synthesise and persist one shadow sample. Returns the recorded
        row dict on success, None when skipped. Never raises — all errors
        are swallowed and logged so a shadow failure cannot break scoring."""
        try:
            return self._record_inner(focused_id, signals, current_time)
        except Exception as err:
            log.warning("[ShadowSampler] sample failed: %s", err)
            return None

    def _record_inner(self,
                      focused_id: str,
                      signals: list["Signal"],
                      current_time: float) -> dict | None:
        if not SHADOW_SAMPLING_ENABLED:
            return None
        # I-7: skip when there is nothing to score
        if not signals:
            return None
        # Warm-up: skip during the first WARMUP_SEC after process start so
        # baselines stabilise before we record divergence statistics.
        if current_time - _PROCESS_START < SHADOW_SAMPLING_WARMUP_SEC:
            return None

        from radar.scenarios import scenario_store
        from radar.database import db as _db

        # I-6: serialise selection so two concurrent greenlets don't pick
        # the same scenario in overlapping cycles.
        with self._lock:
            # Daily budget guard
            if SHADOW_SAMPLING_MAX_PER_DAY > 0:
                daily = _db.shadow_sampler_daily_count()
                if daily >= SHADOW_SAMPLING_MAX_PER_DAY:
                    return None

            target_id = self._pick_target(focused_id, current_time)
            if target_id is None:
                return None

            target_sc = scenario_store.get(target_id)
            if target_sc is None:
                return None

            from radar.scoring import compute_scenario_score

            # Determinism (I-5): same signal set, two scoring modes.
            # is_focused=False mirrors the background scoring path that
            # populates the live scenario's "lite" score.
            lite_state = compute_scenario_score(
                target_sc, signals, is_focused=False,
                global_signal_weight=GLOBAL_SIGNAL_WEIGHT,
                domain_cap=DOMAIN_CAP,
            )
            full_state = compute_scenario_score(
                target_sc, signals, is_focused=True,
                global_signal_weight=GLOBAL_SIGNAL_WEIGHT,
                domain_cap=DOMAIN_CAP,
            )

            lite_score = float(lite_state.score)
            full_score = float(full_state.score)
            delta = round(abs(full_score - lite_score), 4)
            is_miss = delta >= C_MEDIUM_DELTA_MISS_SHADOW

            # Persist the pair and the sampler state in two writes; if the
            # log write succeeds but state upsert fails, the next cycle just
            # re-picks the same scenario, which is harmless.
            _db.focus_switch_append(
                scenario_id=target_id,
                switched_at=current_time,
                lite_score=lite_score,
                full_score=full_score,
                delta=delta,
                is_miss=is_miss,
                source="shadow_sampler",
                shadow_score_kind="piggyback",
            )
            _db.shadow_sampler_state_upsert(
                scenario_id=target_id,
                last_sampled_at=current_time,
                lite_score=lite_score,
                full_score=full_score,
                delta=delta,
            )

            return {
                "scenario_id": target_id,
                "lite_score": lite_score,
                "full_score": full_score,
                "delta": delta,
                "is_miss": is_miss,
            }

    def _pick_target(self, focused_id: str,
                     current_time: float) -> str | None:
        """Pick the eligible non-focused scenario least-recently sampled."""
        from radar.scenarios import scenario_store
        from radar.database import db as _db

        scorable = scenario_store.scorable()
        focused_sc = scenario_store.get(focused_id)
        focused_parts: set[str] = (
            set(focused_sc.participants.keys())
            if (focused_sc and SHADOW_SAMPLING_REQUIRE_OVERLAP)
            else set()
        )

        candidates: list[str] = []
        for sc in scorable:
            if sc.id == focused_id:
                continue
            if SHADOW_SAMPLING_REQUIRE_OVERLAP and focused_parts:
                if not (set(sc.participants.keys()) & focused_parts):
                    continue
            # Per-scenario lockout (anti-thrash)
            if SHADOW_SAMPLING_MIN_GAP_SEC > 0:
                state = _db.shadow_sampler_state_get(sc.id)
                if state and (current_time - state["last_sampled_at"]
                              < SHADOW_SAMPLING_MIN_GAP_SEC):
                    continue
            candidates.append(sc.id)

        if not candidates:
            return None
        return _db.shadow_sampler_least_recent_among(candidates)


shadow_sampler = ShadowSampler()
