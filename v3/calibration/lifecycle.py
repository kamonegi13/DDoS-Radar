"""The proposal state machine — six values, and a state nobody edits.

S1-CALIB-052 fixes the vocabulary at six and says the DB CHECK is
authoritative. Production keeps that state in a column an UPDATE moves,
which costs it two things this module does not pay:

  * an analyst dismissal and an automatic one are distinguishable **only
    by a marker string** in `state_changed_by` (ACCIDENTAL A9); and
  * a refusal to emit leaves no row at all (S1-CALIB-041), so "why was
    nothing proposed" has no answer after the log rotates.

Here the state is the FOLD of adjudication rows in `command_record` — the
same seam C1/C2/C7/C9 already write through. That gets the actor, the
instant and the required reason for free on every transition, and it makes
the automatic hooks ordinary commands issued by an `auto:` actor rather
than a second mechanism with its own vocabulary.

`REVERTED` is declared because the clause declares it, and it is
**unreachable**: S1-CALIB-052 records that no path writes `reverted` to the
proposal ledger — that value belongs to the THRESHOLD ledger
(`history.revert`). Declaring it without a transition is the honest
transcription; omitting it would make the vocabularies disagree, and
adding an edge would invent a path production does not have.

**The Defer interaction is preserved, and now proved.** S1-CALIB-054 (DP6,
HIGH) says a snoozed proposal returns to `pending` without its `emitted_at`
moving, while the staleness hook judges by `emitted_at` — so with the
default 30-day snooze and 30-day staleness, a deferred proposal is
auto-dismissed on the tick after it revives. Defer is structurally
non-functional. The clause is classified DEFECT-PRESERVE **and** "現行系でも
要修正", so this module reproduces it exactly and `TestDeferIsStructurally
Broken` pins the interaction production never tested. Repairing it is a
ruling, not a port decision — see §7-2 #82 and 裁定要求 11.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from v3.kernel.errors import DomainError

# ── the six states (S1-CALIB-052) ───────────────────────────────────────
PENDING = "pending"
APPLIED = "applied"
DISMISSED = "dismissed"
SNOOZED_30D = "snoozed_30d"
REVERTED = "reverted"
SUPERSEDED = "superseded"
STATES: tuple[str, ...] = (PENDING, APPLIED, DISMISSED, SNOOZED_30D,
                           REVERTED, SUPERSEDED)

#: S1-CALIB-052 MUST NOT: these four look like states and are not.
FORBIDDEN_STATES: frozenset = frozenset({"accepted", "rejected",
                                         "auto_dismissed", "expired"})

# ── the adjudication actions, one per edge ──────────────────────────────
PROPOSAL_APPLY = "proposal.apply"
PROPOSAL_DISMISS = "proposal.dismiss"
PROPOSAL_DEFER = "proposal.defer"
PROPOSAL_REVIVE = "proposal.revive"
PROPOSAL_SUPERSEDE = "proposal.supersede"
ACTIONS: tuple[str, ...] = (PROPOSAL_APPLY, PROPOSAL_DISMISS,
                            PROPOSAL_DEFER, PROPOSAL_REVIVE,
                            PROPOSAL_SUPERSEDE)

TARGET_PROPOSAL = "proposal"

#: What each action moves the proposal TO.
_RESULT_OF: Mapping[str, str] = {
    PROPOSAL_APPLY: APPLIED,
    PROPOSAL_DISMISS: DISMISSED,
    PROPOSAL_DEFER: SNOOZED_30D,
    PROPOSAL_REVIVE: PENDING,
    PROPOSAL_SUPERSEDE: SUPERSEDED,
}

#: Which state each action may be issued FROM. S1-CALIB-052: an analyst
#: transition is legal from `pending` ONLY. Production makes a transition
#: from any other state fail SILENTLY (the UPDATE matches no row); here it
#: raises, because a decision an analyst believes they made and the ledger
#: did not record is G-01's shape.
_ALLOWED_FROM: Mapping[str, frozenset] = {
    PROPOSAL_APPLY: frozenset({PENDING}),
    PROPOSAL_DISMISS: frozenset({PENDING}),
    PROPOSAL_DEFER: frozenset({PENDING}),
    PROPOSAL_REVIVE: frozenset({SNOOZED_30D}),
    # Supersede is issued by the emitter, not by an analyst, and it may
    # retire a snoozed proposal as well as a pending one — a newer
    # proposal for the same subject makes the older one wrong whether or
    # not somebody had parked it.
    PROPOSAL_SUPERSEDE: frozenset({PENDING, SNOOZED_30D}),
}

#: Terminal: nothing moves out of these.
TERMINAL: frozenset = frozenset({APPLIED, DISMISSED, REVERTED, SUPERSEDED})

# ── the automatic hooks (S1-CALIB-053), markers verbatim ────────────────
MARKER_INACTIVE_SCENARIO = "auto:inactive_scenario"
MARKER_DIAGNOSTIC_ACK = "auto:diagnostic_acknowledged"
MARKER_TIMEOUT_NO_ACTION = "auto:timeout_no_action"

DIAGNOSTIC_STALE_SEC = 7 * 86400.0
ACTIONABLE_STALE_SEC = 30 * 86400.0
SNOOZE_SEC = 30 * 86400.0

#: S1-CALIB-033: the nine types, and the three that are diagnostic. The
#: apply primitive covers five; the rest have no automatic path by design
#: (NP7 — the tool proposes, the organisation decides).
TYPE_WEIGHT_TOO_LOW = "weight_too_low"
TYPE_WEIGHT_TOO_HIGH = "weight_too_high"
TYPE_MISSING_PARTICIPANT = "missing_participant"
TYPE_SENSOR_GAP = "sensor_gap_detected"
TYPE_SCENARIO_DORMANT = "scenario_dormant"
TYPE_DORMANT_PARTICIPANT = "dormant_participant"
TYPE_ROLE_RECLASSIFY = "role_reclassify"
TYPE_SCENARIO_DISCOVERY = "scenario_discovery"
TYPE_SENSOR_DISABLE = "sensor_disable"
#: The tenth is v3's own: the TL-threshold calibrator (`proposals.py`) is
#: the only producer that exists here, and it is NOT one of production's
#: nine — production writes its threshold changes straight to the
#: threshold ledger without a queue entry, which is why S1-CALIB-041 has
#: no record of the ones it refused.
TYPE_TL_THRESHOLD = "tl_threshold"

PROPOSAL_TYPES: tuple[str, ...] = (
    TYPE_WEIGHT_TOO_LOW, TYPE_WEIGHT_TOO_HIGH, TYPE_MISSING_PARTICIPANT,
    TYPE_SENSOR_GAP, TYPE_SCENARIO_DORMANT, TYPE_DORMANT_PARTICIPANT,
    TYPE_ROLE_RECLASSIFY, TYPE_SCENARIO_DISCOVERY, TYPE_SENSOR_DISABLE,
    TYPE_TL_THRESHOLD)

DIAGNOSTIC_TYPES: frozenset = frozenset({
    TYPE_SENSOR_GAP, TYPE_SCENARIO_DORMANT, TYPE_SCENARIO_DISCOVERY})

#: S1-CALIB-033 MUST: only these have an apply primitive.
AUTO_APPLICABLE_TYPES: frozenset = frozenset({
    TYPE_WEIGHT_TOO_LOW, TYPE_WEIGHT_TOO_HIGH, TYPE_MISSING_PARTICIPANT,
    TYPE_DORMANT_PARTICIPANT, TYPE_ROLE_RECLASSIFY})


class TransitionRefusedError(DomainError):
    """An adjudication that the state machine does not allow."""


def proposal_id_for(*, proposal_type: str, scenario_id: str,
                    proposal_key: str, target_country: str = "",
                    epoch_id: str) -> str:
    """The identity C5 was blocked on. Derived from WHAT the proposal is.

    WP-4.1c deferred C5 with one remaining blocker: `proposals.Proposal`
    carries no id, so an apply command had nothing to point at. This is
    that id, and it is deterministic rather than random for the reason
    `event_id_for` is: two runs of one calibration pass over one body of
    evidence must converge on one queue entry, not stack up two.

    `epoch_id` is in the key. A proposal generated from `e2026_07_04`
    labels and one generated from `e2026_08_02` labels are different
    proposals even when every other field matches, because the evidence
    behind them is a different population — merging them would let an
    adjudication made under one epoch's evidence apply to another's.
    """
    for name, value in (("proposal_type", proposal_type),
                        ("scenario_id", scenario_id),
                        ("proposal_key", proposal_key),
                        ("epoch_id", epoch_id)):
        if not isinstance(value, str) or not value.strip():
            raise DomainError(
                f"{name} must be a non-empty string, got {value!r}")
    if proposal_type not in PROPOSAL_TYPES:
        raise DomainError(
            f"unknown proposal type {proposal_type!r}; the declared set is "
            f"{list(PROPOSAL_TYPES)}. An undeclared type has no impact "
            f"classification, and an unknown impact is refused rather than "
            f"defaulted (ADR-V3-006, DP15).")
    material = "\x1f".join((proposal_type, scenario_id, proposal_key,
                            target_country or "", epoch_id))
    return "prop_" + hashlib.sha256(material.encode()).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class Adjudication:
    """One transition, as a value. What a command row folds to."""

    proposal_id: str
    action: str
    state: str
    actor_id: str
    at: float
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise DomainError(
                f"unknown adjudication {self.action!r}; the declared edges "
                f"are {list(ACTIONS)}")
        if self.state not in STATES:
            raise DomainError(f"unknown state {self.state!r}")

    @property
    def is_automated(self) -> bool:
        return self.actor_id.startswith("auto:")

    def as_dict(self) -> dict:
        return {"proposal_id": self.proposal_id, "action": self.action,
                "state": self.state, "actor_id": self.actor_id,
                "at": self.at, "reason": self.reason}


def result_of(action: str) -> str:
    if action not in _RESULT_OF:
        raise DomainError(f"unknown adjudication {action!r}")
    return _RESULT_OF[action]


def may_transition(*, action: str, current: str) -> bool:
    """S1-CALIB-052's legality, as a predicate."""
    if action not in _ALLOWED_FROM:
        raise DomainError(f"unknown adjudication {action!r}")
    if current not in STATES:
        raise DomainError(f"unknown state {current!r}")
    return current in _ALLOWED_FROM[action]


def apply_adjudication(before: Optional[Mapping], *, action: str,
                       actor_id: str, at: float,
                       reason: Optional[str] = None) -> dict:
    """The `apply_*` half of the write seam: (before, payload) -> after.

    `before` is the previous fold — `None` (or an empty mapping) means the
    proposal has never been adjudicated, which IS `pending`. There is no
    row anywhere that says "pending"; it is the empty state, which is what
    makes it impossible for a proposal to be emitted in some other one.
    """
    current = state_of(before)
    if not may_transition(action=action, current=current):
        raise TransitionRefusedError(
            f"{action!r} is legal from {sorted(_ALLOWED_FROM[action])}, and "
            f"this proposal is {current!r}. Production lets this UPDATE "
            f"match no row and reports success, so an analyst's decision "
            f"disappears silently (S1-CALIB-052); refusing is the only way "
            f"the analyst learns their decision was not recorded.")
    return {"state": result_of(action), "actor_id": actor_id, "at": float(at),
            "reason": reason, "action": action}


def state_of(after: Optional[Mapping]) -> str:
    """The proposal's state from the fold's `after`. Empty means pending."""
    if not after:
        return PENDING
    state = after.get("state")
    if state not in STATES:
        raise DomainError(
            f"folded state {state!r} is not one of {list(STATES)}")
    return state


def is_terminal(state: str) -> bool:
    if state not in STATES:
        raise DomainError(f"unknown state {state!r}")
    return state in TERMINAL


# ── the automatic hooks, as pure predicates (S1-CALIB-053) ──────────────
def auto_dismiss_marker(*, proposal_type: str, emitted_at: float, now: float,
                        scenario_active: bool) -> Optional[str]:
    """Which auto-dismiss hook fires, or None. Order is the clause's.

    All three judge by `emitted_at` — NOT by when the state last changed.
    That is the clause's MUST and it is also the mechanism of DP6: a
    revival restores `pending` without moving `emitted_at`, so the
    staleness hook still sees a 30-day-old proposal the moment it comes
    back. Encoding the rule in one place is what lets a test state that
    interaction, which production has never had.
    """
    if proposal_type not in PROPOSAL_TYPES:
        raise DomainError(f"unknown proposal type {proposal_type!r}")
    age = float(now) - float(emitted_at)
    if not scenario_active:
        # No time condition at all — the clause is explicit about it.
        return MARKER_INACTIVE_SCENARIO
    if proposal_type in DIAGNOSTIC_TYPES:
        return (MARKER_DIAGNOSTIC_ACK if age > DIAGNOSTIC_STALE_SEC
                else None)
    return MARKER_TIMEOUT_NO_ACTION if age > ACTIONABLE_STALE_SEC else None


def revives_at(*, deferred_at: float) -> float:
    """When a snoozed proposal returns to `pending`."""
    return float(deferred_at) + SNOOZE_SEC


def defer_survives_revival(*, emitted_at: float, deferred_at: float,
                           proposal_type: str, tick_sec: float = 60.0,
                           scenario_active: bool = True) -> bool:
    """Does a deferred proposal survive the FIRST tick after it revives?

    DP6 as a computation rather than a paragraph. With the shipped
    constants the answer is False for every type — the snooze and the
    staleness window are both 30 days and the staleness clock never
    restarted, so Defer is a slower Dismiss. Exposed as a function so the
    suite asserts the CONSEQUENCE rather than the constants, and so a
    ruling that changes either window changes this answer visibly.

    `tick_sec` is a parameter because the boundary is an equality: at
    EXACTLY 30 days the hook's `age > window` is False, so the proposal
    survives the instant it revives and dies on the next evaluation. A
    version of this question that asked about the revival instant alone
    would answer "it survives" and miss the defect entirely.
    """
    if tick_sec <= 0:
        raise DomainError(
            f"tick_sec must be positive, got {tick_sec}: the question is "
            f"what the NEXT evaluation sees, and a zero-length tick asks "
            f"about the revival instant, where the boundary equality hides "
            f"the interaction")
    revived = revives_at(deferred_at=deferred_at) + float(tick_sec)
    return auto_dismiss_marker(proposal_type=proposal_type,
                               emitted_at=emitted_at, now=revived,
                               scenario_active=scenario_active) is None


def revival_boundary_is_equality(*, emitted_at: float,
                                 deferred_at: float,
                                 proposal_type: str) -> bool:
    """True when the proposal is alive at EXACTLY the revival instant.

    The other half of the same fact, kept separate so the two are not
    confused: the proposal is alive for zero ticks, not for none.
    """
    return auto_dismiss_marker(
        proposal_type=proposal_type, emitted_at=emitted_at,
        now=revives_at(deferred_at=deferred_at),
        scenario_active=True) is None


def vocabulary_disclosure() -> dict:
    """What the state machine is, for R13 and the disclosure surface."""
    return {
        "states": list(STATES),
        "forbidden_states": sorted(FORBIDDEN_STATES),
        "terminal_states": sorted(TERMINAL),
        "actions": list(ACTIONS),
        "allowed_from": {action: sorted(states)
                         for action, states in _ALLOWED_FROM.items()},
        "result_of": dict(_RESULT_OF),
        "proposal_types": list(PROPOSAL_TYPES),
        "diagnostic_types": sorted(DIAGNOSTIC_TYPES),
        "auto_applicable_types": sorted(AUTO_APPLICABLE_TYPES),
        "unreachable_states": [REVERTED],
    }


__all__ = [
    "PENDING", "APPLIED", "DISMISSED", "SNOOZED_30D", "REVERTED",
    "SUPERSEDED", "STATES", "FORBIDDEN_STATES", "TERMINAL",
    "PROPOSAL_APPLY", "PROPOSAL_DISMISS", "PROPOSAL_DEFER",
    "PROPOSAL_REVIVE", "PROPOSAL_SUPERSEDE", "ACTIONS", "TARGET_PROPOSAL",
    "MARKER_INACTIVE_SCENARIO", "MARKER_DIAGNOSTIC_ACK",
    "MARKER_TIMEOUT_NO_ACTION", "DIAGNOSTIC_STALE_SEC",
    "ACTIONABLE_STALE_SEC", "SNOOZE_SEC", "PROPOSAL_TYPES",
    "DIAGNOSTIC_TYPES", "AUTO_APPLICABLE_TYPES", "TransitionRefusedError",
    "Adjudication", "proposal_id_for", "result_of", "may_transition",
    "apply_adjudication", "state_of", "is_terminal", "auto_dismiss_marker",
    "revives_at", "defer_survives_revival",
    "revival_boundary_is_equality", "vocabulary_disclosure",
]
