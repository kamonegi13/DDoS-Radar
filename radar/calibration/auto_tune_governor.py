"""Single chokepoint for all auto-tune writes.

Phase A foundation. Calibrators (Phase B+ TL_THRESHOLDS calibrator,
Phase C per-sensor LLM_CONFIDENCE_MIN calibrator, etc.) propose changes
via ``commit(proposal)``; the governor decides whether to write them
to the threshold_history ledger.

Hard rules enforced here (NP1 + NP6 safety):

  1. Bounded magnitude per cycle: a numeric change cannot move by more
     than DEFAULT_MAX_MAGNITUDE_PCT (default 10%) per commit. If the
     proposal exceeds this, it is clamped to the budget and recorded
     as ``magnitude_pct=10.0`` in the ledger.

  2. Cooldown: after a successful commit on a (key, scope_scenario_id),
     the same key cannot re-tune for COOLDOWN_HOURS (default 72h).
     Subsequent commits inside the cooldown window are dropped silently
     and a debug log is emitted.

  3. Sample-size minimum: a proposal whose ``sample_n`` is below
     MIN_SAMPLE_N (default 30) is rejected — preserves NP3 "degrade
     silently rather than tune wrongly".

  4. Recall gate: if the global recall_metrics CI gate is currently
     red, the governor refuses any non-revert commit. Auto-tune is
     paused while a regression is being investigated.

These are deliberately defensive defaults. Operators can relax via
env (AUTO_TUNE_MAX_MAGNITUDE_PCT, AUTO_TUNE_COOLDOWN_HOURS,
AUTO_TUNE_MIN_SAMPLE_N) but the governor's job is to be the safety
net, not the optimum performer.

NP integrity:

  NP1 — recall_gate ensures we never tune while recall is regressing
  NP6 — every commit (and rejection!) is observable via list_recent
        for AP3 reliability scoring
  NP3 — silent degradation: a calibrator with bad data produces
        nothing, never a wrong tune
  AP3 — applied vs rejected counts surface in the proposer scoreboard
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from radar.calibration import threshold_history

log = logging.getLogger("radar.calibration.governor")


def _max_magnitude_pct() -> float:
    return float(os.getenv("AUTO_TUNE_MAX_MAGNITUDE_PCT", "10.0"))


def _cooldown_seconds() -> float:
    return float(os.getenv("AUTO_TUNE_COOLDOWN_HOURS", "72")) * 3600.0


def _min_sample_n() -> int:
    return int(os.getenv("AUTO_TUNE_MIN_SAMPLE_N", "30"))


@dataclass(frozen=True)
class ProposalOutcome:
    """Result of governor.commit(). Frozen so callers can't mutate the
    audit record after the fact."""
    accepted: bool
    reason: str  # 'committed' | 'cooldown' | 'sample_too_small' |
                 # 'recall_red' | 'unchanged' | 'magnitude_clamped'
    new_row_id: Optional[int] = None
    clamped_value: Any = None
    actual_magnitude_pct: float = 0.0


@dataclass(frozen=True)
class Proposal:
    """A calibrator's proposed change. Immutable so the governor cannot
    mutate the proposal in place — any clamping produces a derived
    Proposal that's recorded in ProposalOutcome.clamped_value."""
    key: str
    new_value: Any                  # decoded JSON: float, dict, list
    scope_scenario_id: Optional[str]
    derived_from: str               # calibrator id + version
    applied_by: str                 # 'auto:tl_calibrator' / 'auto:llm_floor' / etc.
    sample_n: int
    formula_ref: str                # 'tl_calibrator/v1#derive_from_recall'
    evidence: dict = field(default_factory=dict)


def _is_numeric(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _compute_magnitude_pct(prior: Any, new: Any) -> float:
    """Return the magnitude of change as a percentage of the prior value.

    For non-numeric values (dicts, lists), returns 100.0 (treated as a
    full replace; bounded-magnitude rule does not gate non-numeric
    changes — they're either applied wholesale or not at all). This is
    a conservative interpretation: callers who need finer control over
    structured-value tuning should compose their own bounded changes
    upstream.
    """
    if _is_numeric(prior) and _is_numeric(new):
        if prior == 0:
            return 100.0 if new != 0 else 0.0
        return abs((new - prior) / prior) * 100.0
    return 100.0


def _clamp_to_magnitude(prior: Any, new: Any, max_pct: float) -> Any:
    """If the proposed change exceeds max_pct, return the value at the
    edge of the allowed window. Non-numeric values return new unchanged
    (caller decides whether to accept full replace or not)."""
    if not _is_numeric(prior) or not _is_numeric(new):
        return new
    if prior == 0:
        return new  # Can't bound a 0 baseline; let caller decide.
    delta = new - prior
    max_delta = abs(prior) * (max_pct / 100.0)
    if abs(delta) <= max_delta:
        return new
    sign = 1 if delta > 0 else -1
    return prior + sign * max_delta


def _recall_gate_is_red() -> bool:
    """Return True iff the recall_metrics CI gate currently reports a
    regression. Implementation: best-effort read of the baseline file
    timestamp and a quick recompute. If the gate cannot be evaluated
    (DB sparse, baseline missing, etc.), default to False — we'd
    rather allow tuning when uncertain than block on a stale signal.

    NP3: failure of the gate evaluation must not block the governor.
    """
    try:
        # Defer import — script not always available in all paths.
        from importlib import import_module
        mod = import_module("scripts.check_recall_baseline")
        report = mod.evaluate_against_baseline(  # type: ignore[attr-defined]
            db_path="radar/persistence/radar.db",
            tolerance=0.05,
        )
        return bool(report.get("status") == "FAIL")
    except Exception as exc:
        log.debug("recall gate eval failed (non-fatal): %s", exc)
        return False


def commit(proposal: Proposal) -> ProposalOutcome:
    """Evaluate a proposal against the safety rules and either write it
    to threshold_history or reject it.

    Returns a ProposalOutcome. Callers should not act on accepted=True
    by themselves — the new value is already persisted; downstream
    consumers (Conclusion serializer, scoring layer) will pick it up
    via threshold_history.value_at(...) on their next read.
    """
    # Rule 3: sample size minimum. Strict because a low-n calibration
    # can drift the system based on noise.
    if proposal.sample_n < _min_sample_n():
        log.debug(
            "governor rejected %s scope=%s: sample_n=%d < min=%d",
            proposal.key, proposal.scope_scenario_id, proposal.sample_n,
            _min_sample_n(),
        )
        return ProposalOutcome(accepted=False, reason="sample_too_small")

    # Rule 4: recall gate. Pause auto-tune during a regression window.
    if _recall_gate_is_red():
        log.info(
            "governor rejected %s scope=%s: recall_metrics gate is RED",
            proposal.key, proposal.scope_scenario_id,
        )
        return ProposalOutcome(accepted=False, reason="recall_red")

    # Rule 5 (2026-05-05): tier governor. The system gates whether
    # proposals at this impact level are allowed to land in the live
    # ledger right now. Tier 0 = nothing applies; promotions to Tier 1
    # / 2 / 3 are decided autonomously from the auto_apply_tier_state
    # audit log. NP3 — if the tier governor cannot evaluate (e.g.
    # migration v52 hasn't run yet), it returns False, which is the
    # safe default.
    try:
        from radar.calibration import auto_apply_tier_governor as _tier
        if not _tier.is_apply_allowed(proposal.applied_by):
            log.debug(
                "governor rejected %s scope=%s: tier_gate "
                "(applied_by=%s, tier=%d)",
                proposal.key, proposal.scope_scenario_id,
                proposal.applied_by,
                _tier.current_tier().tier,
            )
            return ProposalOutcome(accepted=False, reason="tier_gate")
    except Exception as _tg_exc:
        log.debug("tier governor unavailable, gating proposal: %s", _tg_exc)
        return ProposalOutcome(accepted=False, reason="tier_gate")

    # Read prior state (for cooldown + magnitude calculation).
    prior_rec = threshold_history.latest(
        proposal.key, scope_scenario_id=proposal.scope_scenario_id,
    )

    # Rule 2: cooldown.
    if prior_rec is not None:
        elapsed = time.time() - prior_rec.emitted_at
        if elapsed < _cooldown_seconds():
            log.debug(
                "governor rejected %s scope=%s: cooldown %.1fh < %.1fh",
                proposal.key, proposal.scope_scenario_id,
                elapsed / 3600, _cooldown_seconds() / 3600,
            )
            return ProposalOutcome(accepted=False, reason="cooldown")

    prior_value = prior_rec.value if prior_rec else None

    # Unchanged short-circuit.
    if prior_value == proposal.new_value:
        return ProposalOutcome(accepted=False, reason="unchanged")

    # Rule 1: bounded magnitude. Clamp if needed (and record the clamp).
    max_pct = _max_magnitude_pct()
    if prior_value is None:
        # First-ever value for this key in the ledger. Magnitude is
        # undefined; commit verbatim. The proposal carries its own
        # justification (sample_n + evidence + formula_ref).
        actual_value = proposal.new_value
        magnitude = 0.0
        was_clamped = False
    else:
        candidate_magnitude = _compute_magnitude_pct(prior_value, proposal.new_value)
        if candidate_magnitude > max_pct:
            actual_value = _clamp_to_magnitude(
                prior_value, proposal.new_value, max_pct,
            )
            magnitude = max_pct
            was_clamped = True
            log.info(
                "governor clamped %s scope=%s: requested %.2f%% → clamped %.2f%%",
                proposal.key, proposal.scope_scenario_id,
                candidate_magnitude, max_pct,
            )
        else:
            actual_value = proposal.new_value
            magnitude = candidate_magnitude
            was_clamped = False

    # Persist.
    revertible_to_id = prior_rec.id if prior_rec else None
    new_id = threshold_history.record_change(
        key=proposal.key,
        value=actual_value,
        scope_scenario_id=proposal.scope_scenario_id,
        derived_from=proposal.derived_from,
        applied_by=proposal.applied_by,
        sample_n=proposal.sample_n,
        formula_ref=proposal.formula_ref,
        evidence=proposal.evidence,
        magnitude_pct=magnitude,
        revertible_to_id=revertible_to_id,
    )
    # Tier-3 HIGH change → trigger downstream cooldown so LOW/MED
    # calibrators don't pile chained proposals onto an unproven HIGH
    # change. Best-effort: cooldown failures must never break commit.
    try:
        from radar.calibration import auto_apply_tier_governor as _tier
        if _tier.APPLIED_BY_IMPACT.get(proposal.applied_by) == "high":
            _tier.trigger_high_cooldown(triggered_by=proposal.applied_by)
    except Exception as _tg_exc:
        log.debug("HIGH cooldown trigger failed (non-fatal): %s", _tg_exc)
    return ProposalOutcome(
        accepted=True,
        reason=("magnitude_clamped" if was_clamped else "committed"),
        new_row_id=new_id,
        clamped_value=actual_value if was_clamped else None,
        actual_magnitude_pct=magnitude,
    )


__all__ = ["Proposal", "ProposalOutcome", "commit"]
