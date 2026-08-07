"""Which observations are allowed to reach a conclusion, and why not.

S1-PIPE-009 calls this the core of the pipeline specification, and
S1-PIPE §6 GAP-01 records that the entire truth table is untested. Both are
true, and together they are the most dangerous combination in the system:
all three calibration incidents (2026-05-29, 2026-07-03, 2026-08-02) were
errors about *what was in the input*, not about the arithmetic applied to
it.

PLACEMENT (ruling, WP-2.4 review): `gate()` is the ORCHESTRATOR's
upstream step, in the same position as `resolve_settings()`. The caller
runs it over raw readings; its verdict becomes `Observation.suppressed`
and `Observation.suppress_reason`, and through `passes_gate()` it decides
which sensors may justify a sequence link. `score_tick()` never calls it.
Do not add a second gate inside the kernel — one gate, one answer to "why
did this drop out", is the entire point of this module.

So the table is a pure function returning an explicit decision record,
rather than a sequence of flag mutations spread through a request handler.
Two properties the legacy shape could not offer:

  * a suppressed observation is still returned, with its score intact.
    "Fired but excluded" and "never fired" are different facts and the
    evidence row has to keep both (NP5+8).
  * exactly one reason survives, by a stated precedence — analyst mute
    beats caller suppression beats a noise rule — so "why did this drop
    out" has a single answer instead of a race.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from v3.kernel.errors import DomainError
from v3.scoring.inputs import STATUS_FIRED, Observation

REASON_ANALYST_MUTE = "analyst_mute"
REASON_NOISE_RULE = "noise_rule"


@dataclass(frozen=True, slots=True)
class NoiseRule:
    """One noise-exclusion rule (S1-PIPE-010).

    `pattern` is matched against the observation's structured `value`, NOT
    against a display string. The legacy system matched formatted output,
    so changing a label silently disabled live exclusion rules — recorded
    as DEFECT-PRESERVE DP4 with "match a structured field" as the v3 norm.
    This is that norm.
    """

    rule_id: str
    sensor: str
    pattern: str
    country: str = ""
    expires_at: Optional[float] = None

    def __post_init__(self) -> None:
        for name in ("rule_id", "sensor", "pattern"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(
                    f"NoiseRule {name} must be a non-empty string, "
                    f"got {value!r}")
            object.__setattr__(self, name, value.strip())
        object.__setattr__(self, "country", (self.country or "").strip().upper())

    def matches(self, observation: Observation, country: str, *,
                now: float) -> bool:
        """Exact sensor, country or wildcard, unexpired, pattern contained."""
        if observation.sensor != self.sensor:
            return False
        if self.country and self.country != country.upper():
            return False
        if self.expires_at is not None and self.expires_at <= now:
            return False
        return self.pattern in observation.value


@dataclass(frozen=True, slots=True)
class GateDecision:
    """The full outcome of gating one observation.

    `admitted` is the answer the scorer uses; everything else is the
    disclosure. S1-PIPE-013 makes `admitted` the precondition for
    registering a sequence event, so this one value governs both what is
    scored and what is remembered.
    """

    observation: Observation
    admitted: bool
    suppressed: bool
    reason: Optional[str] = None
    noise_rule_id: Optional[str] = None
    noise_rule_applied: bool = False
    hidden_signal: bool = False

    def as_dict(self) -> dict:
        return {
            "sensor": self.observation.sensor,
            "admitted": self.admitted,
            "suppressed": self.suppressed,
            "reason": self.reason,
            "noise_rule_id": self.noise_rule_id,
            "noise_rule_applied": self.noise_rule_applied,
            "hidden_signal": self.hidden_signal,
        }


def gate(observation: Observation, *, now: float, country: str = "",
         muted: bool = False, caller_suppressed: bool = False,
         caller_reason: Optional[str] = None,
         noise_rules: Iterable[NoiseRule] = ()) -> GateDecision:
    """S1-PIPE-009's truth table, in the order the clause fixes.

    (1) analyst mute, (2) OR the caller's suppression, (3) settle the
    reason with mute winning outright, (4) consult noise rules ONLY if
    nothing has suppressed this yet, (5) keep the evidence row either way,
    (6) mark a fired-but-suppressed reading as a hidden signal, (7) admit
    only when fired and unsuppressed.

    `now` is required, not defaulted to wall-clock: it decides which noise
    rules have expired, so a defaulted clock would make the same
    observation gate differently on a replay than it did live. Callers
    inside a tick pass `inputs.now`.
    """
    if not isinstance(observation, Observation):
        raise TypeError(
            f"gate takes an Observation, got {type(observation).__name__}")
    fired = observation.status == STATUS_FIRED

    # (1)+(2) mute, then the caller's own suppression verdict.
    suppressed = bool(muted) or bool(caller_suppressed)
    # (3) precedence: an analyst's decision is not overwritten by a
    # machine's, and it is the one an auditor will be asked about.
    if muted:
        reason = REASON_ANALYST_MUTE
    elif caller_suppressed:
        reason = caller_reason
    else:
        reason = None

    # (4) noise rules apply only to something not already suppressed —
    # otherwise the rule's id would replace a reason that outranks it.
    noise_rule_id = None
    noise_applied = False
    if not suppressed:
        for rule in noise_rules:
            if rule.matches(observation, country or "", now=now):
                suppressed = True
                reason = REASON_NOISE_RULE
                noise_rule_id = rule.rule_id
                noise_applied = True
                break

    # (6) a reading that fired and was held back is the one worth
    # recording: it is what the tool would have said and did not.
    hidden = fired and suppressed

    # (7) S1-PIPE-009 row 8: the return value.
    admitted = fired and not suppressed
    return GateDecision(observation=observation, admitted=admitted,
                        suppressed=suppressed, reason=reason,
                        noise_rule_id=noise_rule_id,
                        noise_rule_applied=noise_applied,
                        hidden_signal=hidden)


def apply_gate(decision: GateDecision) -> Observation:
    """The observation as the scorer should see it, score untouched.

    S1-PIPE-009 step 6: suppression sets a flag, it does not zero a score.
    Keeping the number means the hidden-signal ledger can answer "how big
    was the thing we suppressed", which a zeroed row cannot.
    """
    observation = decision.observation
    if observation.suppressed == decision.suppressed and \
            observation.suppress_reason == decision.reason:
        return observation
    return Observation(
        sensor=observation.sensor, domain=observation.domain,
        status=observation.status, score=observation.score,
        signal_source=observation.signal_source,
        countries=observation.countries, confidence=observation.confidence,
        suppressed=decision.suppressed, suppress_reason=decision.reason,
        origin=observation.origin, value=observation.value)


def apply_confidence_penalty(score: float, claim_confidence: float,
                             *, minimum: float, step: float = 1.0) -> float:
    """S1-PIPE-011: a weak claim loses a point, it does not lose its status.

    Deliberately NOT suppression: the observation stays FIRED and carries
    no suppression flag, so it still counts toward domain activity. Only
    its magnitude is discounted. S1-PIPE-011 classifies the shared word
    "suppression" across three unrelated mechanisms as ACCIDENTAL A4; the
    name here says which one this is.
    """
    if claim_confidence >= minimum:
        return score
    return max(0.0, score - step)


__all__ = ["NoiseRule", "GateDecision", "gate", "apply_gate",
           "apply_confidence_penalty", "REASON_ANALYST_MUTE",
           "REASON_NOISE_RULE"]
