"""AP1's attention score, as a pure function of declared inputs.

`attention_score = novelty x confidence_delta x analyst_blindness`, which
is what P7 R6 and AP1 both spell, and what `triage_score.js` computes —
in a browser, from a `localStorage` timestamp, leaving no trace. That is
defect G-03, and P5 O-8 ruled the computation into the backend so the
order an analyst acted on becomes a row AP4 can replay.

Everything here is pure: no clock, no ledger, no request. `now` arrives as
a number and the three factors arrive as `Inputs`, so a snapshot is a
function of (inputs, now) and re-deriving it from the stored components
reproduces the score exactly. That property is what `Provenance` is for —
the stored row carries the inputs, not just the outputs, so "why was this
first" is answerable from the row rather than from a rerun of the tool.

Two deliberate departures from the browser module, both registered in
wp25 §7-2 (#86, #87):

* **Acknowledgement is not folded into the stored score.** The browser
  forced an acknowledged item's score to 0 before computing anything.
  Here the score is what the tool thinks of the finding, and per-user
  state is applied by the projection — because the snapshot is one shared
  record and a score that depended on who was looking could not be one.
* **Blindness is organisational.** The browser measured "how long since
  THIS BROWSER rendered the item". Here it is "how long since any analyst
  acted on it in the command ledger", which is the fact the server can
  actually see and the one AP4 can replay.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from v3.attention import thresholds as T
from v3.kernel.errors import DomainError

#: The formula's published identity. Stored on every row, because a score
#: whose formula is not named cannot be compared with a score computed by
#: a later version of the same tool (NP6).
FORMULA_REF = "AP1/P7-R6: novelty x confidence_delta x analyst_blindness"

#: Why a candidate scored zero, when it did. A zero with no reason is the
#: shape that let production's empty caches answer ROUTINE (G-17).
REASON_UNAVAILABLE = "conclusion_unavailable"
REASON_NO_MOVEMENT = "no_confidence_movement"
REASON_STALE = "beyond_novelty_horizon"
REASON_JUST_SEEN = "analyst_acted_recently"

ITEM_CONCLUSION = "conclusion"


def clamp01(value) -> float:
    """`triage_score.js::_clamp01`, including its treatment of non-numbers.

    A non-finite input becomes 0 rather than raising, transcribed exactly:
    the browser did that so one bad row could not blank the whole lane, and
    the direction is the safe one here too (a candidate the tool cannot
    score does not displace one it can).
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    numeric = float(value)
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        return 0.0
    return max(0.0, min(1.0, numeric))


@dataclass(frozen=True, slots=True)
class Inputs:
    """What the three factors are computed from, for ONE candidate.

    Every field is an observable the ledger can produce, and all of them
    are stored on the row — `Provenance.inputs` is this object, so the
    score is re-derivable from what was persisted rather than only from a
    tool that is still running.
    """

    item_kind: str
    item_id: str
    scenario_id: str
    #: When this finding last changed. `None` = never seen before, which
    #: is maximal novelty.
    last_changed_at: Optional[float] = None
    confidence: float = 0.0
    #: The previous value of the same finding's confidence. `None` = no
    #: predecessor, and then the movement IS the confidence.
    previous_confidence: Optional[float] = None
    #: When an analyst last acted on this item (label, ack, snooze,
    #: dismiss). `None` = nobody ever has.
    last_analyst_action_at: Optional[float] = None
    unavailable_reason: Optional[str] = None
    #: Free-form context the narrative names (conclusion type, state).
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("item_kind", "item_id", "scenario_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(
                    f"attention inputs need a non-empty {name}")
            object.__setattr__(self, name, value.strip())
        object.__setattr__(self, "context", dict(self.context))


@dataclass(frozen=True, slots=True)
class Provenance:
    """The components that produced one score, in the AP1 sense.

    Not a log line. This is the object the ledger row stores, and the
    reason it stores the INPUTS as well as the factors is that AP1 asks
    for the ranking rationale to be visible: a factor of 0.31 explains
    nothing, and "0.31 because the finding last changed 33h ago against a
    48h horizon" explains it without rerunning anything.
    """

    novelty: float
    confidence_delta: float
    analyst_blindness: float
    score: float
    formula_ref: str
    inputs: Mapping[str, Any]
    horizons: Mapping[str, float]
    zero_reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"novelty": self.novelty,
                "confidence_delta": self.confidence_delta,
                "analyst_blindness": self.analyst_blindness,
                "score": self.score, "formula_ref": self.formula_ref,
                "inputs": dict(self.inputs),
                "horizons": dict(self.horizons),
                "zero_reasons": list(self.zero_reasons)}


def novelty_of(*, last_changed_at: Optional[float], now: float) -> float:
    """`1 - age/48h`, clamped. Absent history is maximal novelty (NP1)."""
    if last_changed_at is None:
        return 1.0
    age = max(0.0, float(now) - float(last_changed_at))
    return clamp01(1.0 - age / T.NOVELTY_HORIZON_SEC)


def confidence_delta_of(*, confidence: float,
                        previous_confidence: Optional[float]) -> float:
    """`|c - c_prev|`, or `c` itself when there is no predecessor.

    Absolute, not signed: a collapse in confidence is as much a reason to
    look as a rise. Production's module is explicit about this
    (`Math.abs`), and the direction is the NP1 one — a finding the tool
    has stopped believing is a finding somebody should check.
    """
    current = clamp01(confidence)
    if previous_confidence is None:
        return current
    return clamp01(abs(current - clamp01(previous_confidence)))


def blindness_of(*, last_analyst_action_at: Optional[float],
                 now: float) -> float:
    """`since/6h`, clamped. Never acted on is maximal blindness."""
    if last_analyst_action_at is None:
        return 1.0
    since = max(0.0, float(now) - float(last_analyst_action_at))
    return clamp01(since / T.BLINDNESS_HORIZON_SEC)


def score_for(inputs: Inputs, *, now: float) -> Provenance:
    """The whole formula, with the components that produced it."""
    if not isinstance(inputs, Inputs):
        raise DomainError(
            f"score_for takes Inputs, got {type(inputs).__name__}: the "
            f"declared inputs ARE the provenance, and a dict here would let "
            f"a row be scored from fields nothing recorded")
    horizons = {"novelty_horizon_sec": T.NOVELTY_HORIZON_SEC,
                "blindness_horizon_sec": T.BLINDNESS_HORIZON_SEC,
                "max_score": T.MAX_SCORE}
    stated = {"last_changed_at": inputs.last_changed_at,
              "confidence": inputs.confidence,
              "previous_confidence": inputs.previous_confidence,
              "last_analyst_action_at": inputs.last_analyst_action_at,
              "unavailable_reason": inputs.unavailable_reason,
              "now": float(now), **dict(inputs.context)}
    if inputs.unavailable_reason:
        # Transcribed from `triage_score.js:74-77`: an unconcluded finding
        # does not compete for attention. NP5+8 puts the null zone in R7's
        # reliability breakdown and R3's chronic view, which is where a
        # PERSISTENT absence is meant to be loud.
        return Provenance(novelty=0.0, confidence_delta=0.0,
                          analyst_blindness=0.0, score=0.0,
                          formula_ref=FORMULA_REF, inputs=stated,
                          horizons=horizons,
                          zero_reasons=(REASON_UNAVAILABLE,))
    novelty = novelty_of(last_changed_at=inputs.last_changed_at, now=now)
    delta = confidence_delta_of(
        confidence=inputs.confidence,
        previous_confidence=inputs.previous_confidence)
    blindness = blindness_of(
        last_analyst_action_at=inputs.last_analyst_action_at, now=now)
    score = min(T.MAX_SCORE, clamp01(novelty * delta * blindness))
    reasons = []
    if novelty <= 0.0:
        reasons.append(REASON_STALE)
    if delta <= 0.0:
        reasons.append(REASON_NO_MOVEMENT)
    if blindness <= 0.0:
        reasons.append(REASON_JUST_SEEN)
    return Provenance(novelty=novelty, confidence_delta=delta,
                      analyst_blindness=blindness, score=score,
                      formula_ref=FORMULA_REF, inputs=stated,
                      horizons=horizons,
                      zero_reasons=tuple(reasons) if score <= 0.0 else ())


__all__ = ["FORMULA_REF", "ITEM_CONCLUSION", "Inputs", "Provenance",
           "clamp01", "novelty_of", "confidence_delta_of", "blindness_of",
           "score_for", "REASON_UNAVAILABLE", "REASON_NO_MOVEMENT",
           "REASON_STALE", "REASON_JUST_SEEN"]
