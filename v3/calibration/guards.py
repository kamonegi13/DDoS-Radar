"""One evaluator for generation, application and rejection (E-03).

The defect this module is shaped against is not "a guard was wrong". It
is "the guard that was tested and the guard that ran were different code":

    DP7 / E-03  `_proposal_guards.evaluate_for_country` is never called
                from production; `scenario_improver` calls four helpers
                separately. The integrated guard's three-flag expression
                is a specification the test suite executes and production
                does not.
    DP18 / G-07 `auto_tune_governor._recall_gate_is_red()` calls
                `evaluate_against_baseline`, which did not exist. The bare
                `except` returned False — "not red" — so NP1's last line
                of defence has been permanently open.

Both survive because nothing forces the running path through the tested
one. Here, the running path IS the tested one, because the thing every
write needs — a `Permit` — can only come out of `evaluate()`:

    ruling = evaluate(request)      # the only producer of a Permit
    emit(draft, permit=ruling.permit())

A caller that skips the evaluator has nothing to pass. A caller that
ignores a refusal gets `GuardRefusedError` from `permit()` rather than a
`None` it can quietly proceed past.

Every guard runs even after one has fired — the full verdict list is the
disclosure NP6 wants, and DP9 (refusals leave no trace at all in
production) is closed by `Ruling.as_record()`, which is persistable
whether the answer was yes or no.

A predicate that raises FIRES. ADR-V3-006: v3 fails closed. That is the
single most important line in this file, because the opposite choice is
what G-07 is.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from v3.calibration import matrix as M
from v3.calibration.authority import Actor, Authorisation
from v3.calibration.thresholds import (AUTOTUNE_MIN_SAMPLE_N,
                                       HIGH_COOLDOWN_HOURS)
from v3.kernel.errors import DomainError

# ── phases ──────────────────────────────────────────────────────────────
PHASE_GENERATION = "generation"
PHASE_APPLICATION = "application"
PHASE_REJECTION = "rejection"
PHASES: tuple[str, ...] = (PHASE_GENERATION, PHASE_APPLICATION,
                           PHASE_REJECTION)

#: The authority action each phase requires. Declared here so a phase
#: cannot be added without deciding who may perform it (G-01).
ACTION_FOR_PHASE: dict[str, str] = {
    PHASE_GENERATION: "generate_proposal",
    PHASE_APPLICATION: "apply_proposal",
    PHASE_REJECTION: "reject_proposal",
}

# ── vocabulary ──────────────────────────────────────────────────────────
IMPACT_LOW = "low"
IMPACT_MED = "med"
IMPACT_HIGH = "high"
IMPACTS: tuple[str, ...] = (IMPACT_LOW, IMPACT_MED, IMPACT_HIGH)

#: Minimum tier that may apply each impact (S1-CALIB-056).
_MIN_TIER_FOR_IMPACT: dict[str, int] = {IMPACT_LOW: 1, IMPACT_MED: 2,
                                        IMPACT_HIGH: 3}

#: Roles whose participants ARE the scenario (S1-CALIB-035). Taken from
#: `radar/calibration/_proposal_guards.py:PROTECTED_ROLES` by AST, not
#: from the clause text.
PROTECTED_ROLES: frozenset = frozenset({
    "primary_target", "principal_belligerent", "adversary", "core_country"})

#: Proposal types that reduce recall. NP1: these are the dangerous ones.
RECALL_REDUCING_TYPES: frozenset = frozenset({
    "weight_too_high", "dormant_participant"})

#: Recall statuses that permit a calibration change. Everything else —
#: DEGRADED, INSUFFICIENT_DATA, DEGENERATE — blocks. Fail-closed by
#: allow-list rather than by deny-list, so a status added later blocks
#: until someone decides it should not.
_RECALL_STATUSES_THAT_PERMIT: frozenset = frozenset({M.OK})


def _text(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(f"{name} must be a non-empty string, got {value!r}")
    return value.strip()


# ── request ─────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class ProposalDraft:
    """A proposed change, before any guard has looked at it."""

    proposal_type: str
    scenario_id: str
    target_country: Optional[str]
    direction: str
    impact: str
    prior_value: Optional[float]
    proposed_value: Optional[float]

    def __post_init__(self) -> None:
        object.__setattr__(self, "proposal_type",
                           _text(self.proposal_type, name="proposal_type"))
        object.__setattr__(self, "scenario_id",
                           _text(self.scenario_id, name="scenario_id"))
        if self.direction not in ("looser", "tighter", "structural"):
            raise DomainError(
                f"unknown direction {self.direction!r}; expected looser / "
                f"tighter / structural")
        if self.impact not in IMPACTS:
            # DP15: production classifies an unrecognised writer as `low`,
            # the LOOSEST impact, and calls that conservative.
            raise DomainError(
                f"unknown impact {self.impact!r}; expected one of "
                f"{list(IMPACTS)}. An unrecognised impact is refused, not "
                f"defaulted to the cheapest one (DP15)")

    @property
    def reduces_recall(self) -> bool:
        return self.proposal_type in RECALL_REDUCING_TYPES

    def as_dict(self) -> dict:
        return {"proposal_type": self.proposal_type,
                "scenario_id": self.scenario_id,
                "target_country": self.target_country,
                "direction": self.direction, "impact": self.impact,
                "prior_value": self.prior_value,
                "proposed_value": self.proposed_value}


@dataclass(frozen=True, slots=True)
class SystemState:
    """Everything outside the draft that a guard needs.

    Passed in rather than read: the evaluator makes no queries, so the
    same request always produces the same ruling (AP1's determinism, and
    the precondition for the differential sweep).
    """

    now: float
    tier: int
    last_applied_at: Optional[float]
    motivating_at: Optional[float]
    high_applied_at: Optional[float]
    recall_status: str
    target_role: Optional[str]
    threshold_key: Optional[str]
    scope_scenario_id: Optional[str]

    def __post_init__(self) -> None:
        if isinstance(self.tier, bool) or not isinstance(self.tier, int) \
                or not 0 <= self.tier <= 3:
            raise DomainError(
                f"tier must be an integer 0-3, got {self.tier!r}")
        if isinstance(self.now, bool) or not isinstance(self.now,
                                                        (int, float)):
            raise DomainError(f"now must be a timestamp, got {self.now!r}")


@dataclass(frozen=True, slots=True)
class GuardRequest:
    """One question for the evaluator."""

    phase: str
    authorisation: Authorisation
    draft: ProposalDraft
    evidence: Optional[M.CalibrationEvidence]
    state: SystemState

    def __post_init__(self) -> None:
        if self.phase not in PHASES:
            raise DomainError(
                f"unknown phase {self.phase!r}; expected one of "
                f"{list(PHASES)}")
        if not isinstance(self.authorisation, Authorisation):
            raise DomainError(
                f"a guard request needs an Authorisation, got "
                f"{type(self.authorisation).__name__}: every calibration "
                f"write is gated, and the permit travels with the "
                f"request so the check cannot be skipped (G-01)")
        self.authorisation.require(ACTION_FOR_PHASE[self.phase])
        if not isinstance(self.draft, ProposalDraft):
            raise DomainError(
                f"draft must be a ProposalDraft, got "
                f"{type(self.draft).__name__}")
        if self.evidence is not None \
                and not isinstance(self.evidence, M.CalibrationEvidence):
            raise DomainError(
                f"evidence must be CalibrationEvidence or None, got "
                f"{type(self.evidence).__name__}: a raw cell list would "
                f"bypass the degenerate refusal (S5-VERIF-037)")
        if not isinstance(self.state, SystemState):
            raise DomainError(
                f"state must be a SystemState, got "
                f"{type(self.state).__name__}")

    @property
    def actor(self) -> Actor:
        return self.authorisation.actor


# ── guards ──────────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class Verdict:
    guard_id: str
    clause: str
    fired: bool
    detail: str

    def as_dict(self) -> dict:
        return {"guard_id": self.guard_id, "clause": self.clause,
                "fired": self.fired, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class Guard:
    """A named refusal condition with the clause that justifies it."""

    guard_id: str
    clause: str
    describes: str
    phases: tuple
    predicate: Callable

    def __post_init__(self) -> None:
        _text(self.guard_id, name="guard_id")
        _text(self.clause, name="clause")
        if not self.phases:
            raise DomainError(
                f"guard {self.guard_id!r} applies to no phase, so it can "
                f"never run — that is E-03's shape")

    def run(self, request: GuardRequest) -> Verdict:
        try:
            fired, detail = self.predicate(request)
        except Exception as exc:  # noqa: BLE001 — deliberate, see below
            # ADR-V3-006. Production's recall gate does the opposite: it
            # catches, returns "not red", and has been open ever since
            # (G-07). A guard that cannot answer has not cleared anything.
            return Verdict(guard_id=self.guard_id, clause=self.clause,
                           fired=True,
                           detail=f"guard raised {type(exc).__name__}: "
                                  f"{exc} — treated as a refusal "
                                  f"(fail-closed, ADR-V3-006)")
        return Verdict(guard_id=self.guard_id, clause=self.clause,
                       fired=bool(fired), detail=str(detail))


def _guard_no_evidence(request: GuardRequest) -> tuple:
    if request.evidence is None:
        return True, ("no confusion matrix was supplied; a calibration "
                      "change with no measurement behind it is not a "
                      "calibration")
    return False, "evidence supplied"


def _guard_insufficient_feedback(request: GuardRequest) -> tuple:
    if request.evidence is None:
        return False, "deferred to no_evidence"
    sample = request.evidence.sample_n
    if sample < AUTOTUNE_MIN_SAMPLE_N:
        return True, (f"sample_n {sample} < {AUTOTUNE_MIN_SAMPLE_N} "
                      f"(S1-CALIB-014/062; == is on the passing side)")
    return False, f"sample_n {sample}"


def _guard_no_conclusive_cell(request: GuardRequest) -> tuple:
    if request.evidence is None:
        return False, "deferred to no_evidence"
    if not request.evidence.has_conclusive_cell:
        return True, ("no cell has a measurable recall (every one is "
                      "below the positive-observation floor); the "
                      "evidence cannot support a direction")
    return False, "at least one conclusive cell"


def _guard_recall_degraded(request: GuardRequest) -> tuple:
    status = request.state.recall_status
    if status not in _RECALL_STATUSES_THAT_PERMIT:
        return True, (f"recall status is {status!r}; only "
                      f"{sorted(_RECALL_STATUSES_THAT_PERMIT)} permits a "
                      f"calibration change. This is the gate G-07 left "
                      f"permanently open")
    return False, f"recall status {status!r}"


def _guard_no_motivating_evidence(request: GuardRequest) -> tuple:
    if request.draft.direction == "structural":
        return False, "structural change; freshness is keyed by direction"
    if request.state.motivating_at is None:
        needed = ("FALSE_NEGATIVE" if request.draft.direction == "looser"
                  else "FALSE_POSITIVE")
        return True, (f"no {needed} label exists to motivate a "
                      f"{request.draft.direction} move (S1-CALIB-016)")
    return False, "a motivating label exists"


def _guard_no_new_evidence(request: GuardRequest) -> tuple:
    state = request.state
    if state.motivating_at is None or state.last_applied_at is None:
        return False, "first adjustment, or deferred to the previous guard"
    if state.motivating_at <= state.last_applied_at:
        return True, (f"newest motivating label ({state.motivating_at}) "
                      f"does not postdate the last applied change "
                      f"({state.last_applied_at}); one motivating-"
                      f"evidence state justifies at most one adjustment. "
                      f"The equality boundary refuses (S1-CALIB-016)")
    return False, "strictly newer motivating evidence"


def _guard_tier_gate(request: GuardRequest) -> tuple:
    minimum = _MIN_TIER_FOR_IMPACT[request.draft.impact]
    if request.state.tier < minimum:
        return True, (f"impact {request.draft.impact!r} needs tier "
                      f">= {minimum}, current tier is {request.state.tier}")
    return False, f"tier {request.state.tier} permits {request.draft.impact}"


def _guard_high_cooldown(request: GuardRequest) -> tuple:
    started = request.state.high_applied_at
    if started is None:
        return False, "no HIGH application on record"
    if request.draft.impact == IMPACT_HIGH:
        # S1-CALIB-061: high itself is exempt.
        return False, "HIGH is exempt from its own cooldown"
    elapsed_h = (request.state.now - started) / 3600.0
    if elapsed_h < HIGH_COOLDOWN_HOURS:
        return True, (f"a HIGH change was applied {elapsed_h:.2f}h ago; "
                      f"low and med are held for "
                      f"{HIGH_COOLDOWN_HOURS}h (S1-CALIB-061)")
    return False, f"HIGH cooldown expired {elapsed_h:.2f}h ago"


def _guard_protected_role(request: GuardRequest) -> tuple:
    if not request.draft.reduces_recall:
        return False, "not a recall-reducing proposal"
    role = request.state.target_role
    if role in PROTECTED_ROLES:
        return True, (f"target role {role!r} is protected: removing or "
                      f"weakening it would change the scenario's "
                      f"identity (S1-CALIB-035, the 2026-04-29 accident "
                      f"where 25 weight_too_high proposals fired on every "
                      f"scenario's primary_target)")
    return False, f"role {role!r} is not protected"


#: The registry. Order is the evaluation order, and it matters: the first
#: firing guard owns the outcome, so evidence questions precede tier
#: questions (a tier refusal on evidence-free input would report the
#: wrong reason).
GUARDS: tuple[Guard, ...] = (
    Guard(guard_id="no_evidence", clause="S1-CALIB-019",
          describes="a change proposed with no confusion matrix",
          phases=PHASES, predicate=_guard_no_evidence),
    Guard(guard_id="insufficient_feedback", clause="S1-CALIB-014",
          describes="fewer labels than the calibration floor",
          phases=PHASES, predicate=_guard_insufficient_feedback),
    Guard(guard_id="no_conclusive_cell", clause="S5-VERIF-037",
          describes="no cell has a measurable recall",
          phases=PHASES, predicate=_guard_no_conclusive_cell),
    Guard(guard_id="recall_degraded", clause="S1-CALIB-031",
          describes="the system's own recall does not permit retuning",
          phases=PHASES, predicate=_guard_recall_degraded),
    Guard(guard_id="no_motivating_evidence", clause="S1-CALIB-016",
          describes="no label of the class that motivates this direction",
          phases=(PHASE_GENERATION, PHASE_APPLICATION),
          predicate=_guard_no_motivating_evidence),
    Guard(guard_id="no_new_evidence", clause="S1-CALIB-016",
          describes="the motivating evidence already justified a change",
          phases=(PHASE_GENERATION, PHASE_APPLICATION),
          predicate=_guard_no_new_evidence),
    Guard(guard_id="tier_gate", clause="S1-CALIB-056",
          describes="the auto-apply tier does not permit this impact",
          phases=(PHASE_GENERATION, PHASE_APPLICATION),
          predicate=_guard_tier_gate),
    Guard(guard_id="high_cooldown", clause="S1-CALIB-061",
          describes="a HIGH change is still inside its cooldown",
          phases=(PHASE_GENERATION, PHASE_APPLICATION),
          predicate=_guard_high_cooldown),
    Guard(guard_id="protected_role", clause="S1-CALIB-035",
          describes="a recall-reducing change aimed at a defining role",
          phases=PHASES, predicate=_guard_protected_role),
)


def guard_ids() -> tuple:
    return tuple(sorted(g.guard_id for g in GUARDS))


def registry_disclosure() -> list:
    return [{"guard_id": g.guard_id, "clause": g.clause,
             "condition": g.describes, "phases": list(g.phases)}
            for g in GUARDS]


# ── the permit ──────────────────────────────────────────────────────────

class GuardRefusedError(DomainError):
    """A permit was asked for after the guards said no."""


_PERMIT_TOKEN = object()


@dataclass(frozen=True, slots=True)
class Permit:
    """Proof that the evaluator allowed this phase. Only evaluate() mints one."""

    phase: str
    ruling_id: str
    _token: object = field(default=None, repr=False, compare=False)

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Permit is final: a subclass could mint itself, and then the "
            "evaluator would be advisory again (E-03).")

    def __post_init__(self) -> None:
        if self._token is not _PERMIT_TOKEN:
            raise DomainError(
                "a Permit comes from evaluate() and nowhere else; a "
                "constructible permit is how the tested path and the "
                "running path came apart (E-03 / G-07)")

    def require(self, phase: str) -> "Permit":
        if self.phase != phase:
            raise GuardRefusedError(
                f"this permit is for phase {self.phase!r}, not {phase!r}")
        return self


@dataclass(frozen=True, slots=True)
class Ruling:
    """The evaluator's complete answer, persistable either way (DP9)."""

    ruling_id: str
    phase: str
    verdicts: tuple
    request: GuardRequest

    @property
    def allowed(self) -> bool:
        return not any(v.fired for v in self.verdicts)

    @property
    def blocked_by(self) -> Optional[str]:
        for verdict in self.verdicts:
            if verdict.fired:
                return verdict.guard_id
        return None

    @property
    def blocking_clause(self) -> Optional[str]:
        for verdict in self.verdicts:
            if verdict.fired:
                return verdict.clause
        return None

    def permit(self) -> Permit:
        if not self.allowed:
            blocking = next(v for v in self.verdicts if v.fired)
            raise GuardRefusedError(
                f"{blocking.guard_id} ({blocking.clause}): "
                f"{blocking.detail}")
        return Permit(phase=self.phase, ruling_id=self.ruling_id,
                      _token=_PERMIT_TOKEN)

    def as_record(self) -> dict:
        """The rejection trace production never wrote (DP9 / E-05).

        Recorded for allowed rulings too: "why did this publish" is as
        much an audit question as "why did this not".
        """
        return {"ruling_id": self.ruling_id, "phase": self.phase,
                "allowed": self.allowed, "blocked_by": self.blocked_by,
                "clause": self.blocking_clause or "",
                "actor": self.request.actor.as_dict(),
                "draft": self.request.draft.as_dict(),
                "epoch_id": (self.request.evidence.stamp.epoch_id
                             if self.request.evidence is not None else None),
                "verdicts": [v.as_dict() for v in self.verdicts]}


def evaluate(request: GuardRequest,
             guards: tuple = GUARDS) -> Ruling:
    """Run every guard applicable to the phase. The first firing one wins.

    `guards` is a seam for the suite (and for the mutation harness); the
    production call site passes nothing, so there is exactly one guard
    set in the running system.
    """
    if not isinstance(request, GuardRequest):
        raise DomainError(
            f"evaluate needs a GuardRequest, got {type(request).__name__}")
    applicable = tuple(g for g in guards if request.phase in g.phases)
    verdicts = tuple(g.run(request) for g in applicable)
    return Ruling(ruling_id=uuid.uuid4().hex, phase=request.phase,
                  verdicts=verdicts, request=request)


__all__ = ["PHASES", "PHASE_GENERATION", "PHASE_APPLICATION",
           "PHASE_REJECTION", "ACTION_FOR_PHASE", "IMPACTS", "IMPACT_LOW",
           "IMPACT_MED", "IMPACT_HIGH", "PROTECTED_ROLES",
           "RECALL_REDUCING_TYPES", "ProposalDraft", "SystemState",
           "GuardRequest", "Guard", "Verdict", "GUARDS", "guard_ids",
           "registry_disclosure", "Permit", "Ruling", "GuardRefusedError",
           "evaluate"]
