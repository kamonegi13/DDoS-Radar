"""The one time-decay term for LLM intel. WP-2.4 ADDENDUM, landed WP-2.7.

P6 O-17 abolishes "score_delta / bespoke decay / bespoke dedup" as a second
scoring pipeline and folds each into the single mechanism that owns it.
Decay had no such mechanism to fold into: WP-2.4's `Observation` carried no
timestamp, so L2 could not know an observation's age, and the only decay in
the layer was the sequence chain's. That left one honest option and one
dishonest one — put the term here, or let L0 keep pre-decaying scores,
which is the "bespoke decay in the adapter" O-17 names. The design sheet
§9 ruling 1 chose the first.

THE EFFECTIVE PATH (traced with `ast`, not read off the S1 citation):

    radar/intel_queue.py:88-106     _age_weight(age_sec, source_type)
                                    -> exp(-max(0, age) / (tau_h * 3600))
    radar/intel_queue.py:1001-1003  weight = _age_weight(...)
                                    decayed = float(item["score_delta"]) * weight
    radar/intel_queue.py:1026       the DECAYED number is published as "score"
                                    (the undecayed one as "score_raw")

and both consumers take the decayed one:

    radar/routes/core.py:1925       add_rat(..., _llm_entry["score"], ...) —
                                    positional 5, which `add_rat`'s signature
                                    (core.py:930) binds to `score`
    radar/routes/core.py:2078       raw_score=float(_lr["score"])

The second consumer also stamps `observed_at=current_time` (core.py:2074) —
the TICK's clock, not the item's. That is why the age has to travel as its
own field here: production destroys it at exactly the point v3 needs it.

WHAT THIS MODULE DOES NOT DO. Two neighbouring rules from the same
production function are signal-set construction, not arithmetic, and belong
to the caller (S1-PIPE-023, excluded to WP-4.1):

    the 48h TTL cut          intel_queue.py:999  (age_sec > ttl -> drop)
    the 2-per-(source, country) cap   :1005-1017

Both are hard drops. Leaving them out makes v3 keep contributions
production discards, which is the sensitive direction — registered in the
design sheet §7-2 rather than approximated here.
"""
from __future__ import annotations

import math

from v3.kernel.errors import DomainError
from v3.scoring.thresholds import INTEL_AGE_DECAY_TAU_SEC


def intel_age_weight(observed_at: float, now: float, *,
                     tau_sec: float = INTEL_AGE_DECAY_TAU_SEC) -> float:
    """S1-INTEL-020: `exp(-max(0, age_sec) / tau_sec)`.

    age = 0 -> 1.0, age = tau -> 1/e, age = 2*tau -> e^-2. Never zero: the
    TTL is what deletes an item, and production keeps it for exactly that
    reason (intel_queue.py:51-53).

    The negative clamp is the clause's, and it is load-bearing rather than
    defensive. `observed_at` is an upstream publication time; a feed whose
    clock runs fast produces a future timestamp, and without the clamp
    `exp(+x) > 1` scores that item ABOVE its declared delta — a sensor
    error turning into extra threat.
    """
    if not isinstance(tau_sec, (int, float)) or isinstance(tau_sec, bool):
        raise DomainError(f"tau_sec must be a number, got {tau_sec!r}")
    if not math.isfinite(tau_sec) or tau_sec <= 0:
        raise DomainError(
            f"tau_sec must be positive and finite, got {tau_sec!r}. "
            f"Production returns weight 1.0 for a non-positive tau "
            f"(radar/intel_queue.py:103), which is an environment-only "
            f"switch that silently deletes the decay; v3 pins tau, so the "
            f"branch is unreachable and asking for it is an error.")
    age_sec = max(0.0, float(now) - float(observed_at))
    return math.exp(-age_sec / float(tau_sec))


def age_weight_for(observation, *, now: float) -> float:
    """The weight this observation carries into its contribution.

    1.0 for anything that is not LLM intel. Production applies the term in
    `get_active_rationale` alone, and no sensor reading passes through it —
    so a sensor observation has no age term, however old it is. Its
    staleness is L1's `freshness_horizon` question (B-03), not a discount.
    """
    if not observation.is_llm_intel:
        return 1.0
    observed_at = observation.observed_at
    if observed_at is None:
        # Unreachable through the constructor, which refuses it. Kept so a
        # future field-by-field rebuild cannot route around the check.
        raise DomainError(
            f"{observation.sensor!r} is llm_intel but carries no "
            f"observed_at, so its age is unknown; treating unknown as "
            f"fresh inflates every stale item.")
    return intel_age_weight(observed_at, now)


def effective_score(observation, *, now: float) -> float:
    """The observation's score after its age term. One multiplication."""
    return observation.score * age_weight_for(observation, now=now)


__all__ = ["intel_age_weight", "age_weight_for", "effective_score",
           "INTEL_AGE_DECAY_TAU_SEC"]
