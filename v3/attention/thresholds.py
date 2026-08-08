"""AP1's numbers, pinned to the module they came from.

Values were taken from `triage_score.js` by reading the module constants,
not from prose about them — WP-2.6's sweep found 97 transcription
infidelities in constants that looked correctly copied, so the module is
the source and a citation is a lead.

`ATTENTION_MIN_SCORE` is the ONE number here that is not pinned, and the
reason is defect G-02. Production has a per-user threshold table
(`user_attention_thresholds`) whose rows the evaluation path never reads:
`radar/attention.py::evaluate` iterates the frozen `_DEFAULT_RULES` and no
code path consults the table — the tool has an accessor
(`database.py:3531`) whose docstring says it exists "to measure it, not to
feed it", and `gate_lineage.py:202` reports every stored row as an
ANOMALY. A second instance of the same shape sits in
`GET/PUT /api/v2/decisions/threshold`, which is wired end to end and never
called by the UI.

WP-4.1f's ruling on that: **in v3 a per-user threshold is read or it does
not exist.** So there is exactly one per-user key, it is this one, and the
ranking projection consumes it — `tests/test_attention_ledger.py::
TestThePerUserThresholdIsRead` proves that moving it changes what R6
returns, and the C4 threshold command verifies its effect through the same
resolver the projection calls. The per-rule `enter_threshold` overrides
have no v3 counterpart because v3 has no ATTENTION rules engine: P7 §5
absorbed that family into R7's self-evaluation breakdown, so there is no
rule whose entry threshold a user could tune, and inventing keys for one
would recreate G-02 with v3 spelling.
"""
from __future__ import annotations

from typing import Any

from v3.kernel import Threshold
from v3.kernel.errors import DomainError

_PINNED: dict[str, Threshold] = {
    "ATTENTION_NOVELTY_HORIZON_SEC": Threshold.pinned(
        172800.0, unit="s",
        provenance_ref="AP1 / P7 R6; triage_score.js NOVELTY_HORIZON_SEC "
                       "(48 * 3600). A LINEAR ramp, not a decay: novelty is "
                       "1.0 for a finding that has just changed and reaches "
                       "0 at 48h."),
    "ATTENTION_BLINDNESS_HORIZON_SEC": Threshold.pinned(
        21600.0, unit="s",
        provenance_ref="AP1 / P7 R6; triage_score.js BLINDNESS_HORIZON_SEC "
                       "(6 * 3600). Linear the other way: blindness is 0 "
                       "immediately after an analyst acts and saturates at "
                       "1.0 after 6h of nobody acting."),
    "ATTENTION_MAX_SCORE": Threshold.pinned(
        1.0, unit="ratio",
        provenance_ref="AP1; triage_score.js MAX_SCORE. The product of "
                       "three clamped factors cannot exceed it, so this is "
                       "a disclosed ceiling rather than an active clamp."),
    "ATTENTION_DEFAULT_MIN_SCORE": Threshold.pinned(
        0.05, unit="ratio",
        provenance_ref="AP1; triage_score.js MIN_FIRE_THRESHOLD. The default "
                       "for the one per-user key (see module docstring): a "
                       "row below it does not surface."),
    "ATTENTION_MIN_SCORE_CEILING": Threshold.pinned(
        1.0, unit="ratio",
        provenance_ref="WP-4.1f. A per-user floor above the maximum "
                       "attainable score would silence the list entirely, "
                       "which is a mute with no mute button and no record "
                       "that anything was hidden (NP1)."),
}


def _pinned_number(name: str) -> float:
    resolved = _PINNED[name].resolve().value
    return float(getattr(resolved, "value", resolved))


def disclosure() -> dict[str, Any]:
    """Every pinned attention threshold with its provenance (NP6 / R10)."""
    return {name: {"value": _pinned_number(name),
                   "unit": threshold.unit,
                   "provenance_ref": threshold.provenance_ref}
            for name, threshold in sorted(_PINNED.items())}


NOVELTY_HORIZON_SEC = _pinned_number("ATTENTION_NOVELTY_HORIZON_SEC")
BLINDNESS_HORIZON_SEC = _pinned_number("ATTENTION_BLINDNESS_HORIZON_SEC")
MAX_SCORE = _pinned_number("ATTENTION_MAX_SCORE")
DEFAULT_MIN_SCORE = _pinned_number("ATTENTION_DEFAULT_MIN_SCORE")
MIN_SCORE_CEILING = _pinned_number("ATTENTION_MIN_SCORE_CEILING")

#: The per-user keys, and there is one. Declared as a mapping of
#: `key -> default` so that "what may an analyst set" and "what does the
#: projection read" are the same list — a key here that the projection
#: ignores is refused by `tests/test_attention_ledger.py`.
PER_USER_KEYS: dict[str, float] = {"min_score": DEFAULT_MIN_SCORE}


def coerce_per_user(key: str, value) -> float:
    """Validate one per-user threshold. Refuses; never clamps.

    A clamped threshold reads back as the value the analyst typed in some
    places and as the clamp in others, which is how a dial comes to be
    believed. Refusal makes a rejected setting visible at the moment it is
    set.
    """
    if key not in PER_USER_KEYS:
        raise DomainError(
            f"unknown attention threshold {key!r}: the per-user keys are "
            f"{sorted(PER_USER_KEYS)}. A key the ranking does not read is "
            f"defect G-02 — production stores per-user thresholds that its "
            f"evaluation path never consults, and v3 admits a key only if "
            f"the projection reads it.")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(
            f"{key} must be a number, got {value!r}")
    numeric = float(value)
    if not (0.0 <= numeric <= MIN_SCORE_CEILING):
        raise DomainError(
            f"{key} must be within [0, {MIN_SCORE_CEILING}], got {numeric}: "
            f"a floor above the maximum attainable score empties the list "
            f"with no record that anything was hidden")
    return numeric


__all__ = ["disclosure", "NOVELTY_HORIZON_SEC", "BLINDNESS_HORIZON_SEC",
           "MAX_SCORE", "DEFAULT_MIN_SCORE", "MIN_SCORE_CEILING",
           "PER_USER_KEYS", "coerce_per_user"]
