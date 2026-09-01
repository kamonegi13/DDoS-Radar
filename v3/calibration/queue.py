"""The proposal queue: emission through the guards, and the R13 read.

Two edges, and the discipline is that neither can be gone round.

**Emission takes a Permit.** `guards.evaluate()` is the single evaluator
and the only minter of `Permit`; `emit()` requires one for the GENERATION
phase before it will write a queue row, exactly as
`proposals.apply_to_ledger_row` requires one for APPLICATION. So a
proposal that no guard admitted cannot reach the queue, and a refusal is
not merely logged: `refusal_record()` turns the `Ruling` into a row the
command ledger can hold, which is S1-CALIB-041's repair (production leaves
no persistent trace of a suppression, so "why was nothing proposed" is
unanswerable after the log rotates).

**Reading is one projection, live and replayed.** `entries()` reads the
emitted rows from L1 and folds each one's adjudications out of
`command_record` at an instant. Passing `at=` gives the queue as it stood
then; passing nothing gives it now. There is no second query for history
(P7 derivation principle 4).

What is NOT here, and why: the nine production proposal TYPES
(S1-CALIB-033..039, 047, 050) each have their own generator with its own
evidence rules, and porting them is the rest of WP-3.3's L4 half. The
queue is type-agnostic on purpose — it stores what a generator produced —
so those generators land against a table that already exists rather than
bringing one each.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Optional

from v3.calibration import lifecycle as L
from v3.calibration.guards import PHASE_GENERATION, Permit, Ruling
from v3.calibration.proposals import Proposal
from v3.kernel.errors import DomainError
from v3.ledger.records import ProposalRecord

#: A window wide enough that "the queue" means every live proposal. The
#: auto-dismiss hooks retire an actionable proposal at 30 days, so 90 is
#: three horizons — long enough that a dismissed row is still visible to
#: the analyst who wants to know what happened to it.
DEFAULT_QUEUE_WINDOW_SEC = 90 * 86400.0


def record_for(proposal: Proposal, *, epoch_id: str, emitted_at: float,
               proposal_type: str = L.TYPE_TL_THRESHOLD,
               target_country: str = "") -> ProposalRecord:
    """A `Proposal` (pure, from evidence) as the queue's stored row.

    The identity is derived here rather than carried on `Proposal`,
    because it depends on the epoch — and `Proposal` is a value the pure
    generator produces from evidence that already knows its epoch. Two
    proposals identical in every field but generated from different label
    populations are different proposals (see `proposal_id_for`).
    """
    if not isinstance(proposal, Proposal):
        raise DomainError(
            f"record_for takes a Proposal from proposals.generate(), got "
            f"{type(proposal).__name__}. Generation is the pure half and it "
            f"only accepts CalibrationEvidence, so going round it would "
            f"also go round the degenerate-cell refusal (S5-VERIF-037).")
    return ProposalRecord(
        proposal_id=L.proposal_id_for(
            proposal_type=proposal_type, scenario_id=proposal.scope_scenario_id,
            proposal_key=proposal.key, target_country=target_country,
            epoch_id=epoch_id),
        proposal_type=proposal_type,
        scenario_id=proposal.scope_scenario_id,
        proposal_key=proposal.key,
        impact=proposal.impact,
        emitted_at=emitted_at,
        epoch_id=epoch_id,
        formula_ref=proposal.formula_ref,
        target_country=target_country,
        prior_value=proposal.prior_value,
        proposed_value=proposal.proposed_value,
        direction=proposal.direction,
        sample_n=proposal.sample_n,
        evidence=dict(proposal.provenance.inputs),
        payload={"band": proposal.band,
                 "provenance": proposal.provenance.as_dict()})


def emit(store, proposal: Proposal, *, permit: Permit, epoch_id: str,
         emitted_at: float, proposal_type: str = L.TYPE_TL_THRESHOLD,
         target_country: str = "", now: Optional[float] = None
         ) -> ProposalRecord:
    """Write one proposal to the queue. Requires the generation Permit."""
    if not isinstance(permit, Permit):
        raise DomainError(
            f"emit needs a Permit from guards.evaluate(), got "
            f"{type(permit).__name__}: the single evaluator is the only "
            f"thing that may decide a proposal is admissible (E-03), and a "
            f"second door would make every guard optional")
    permit.require(PHASE_GENERATION)
    record = record_for(proposal, epoch_id=epoch_id, emitted_at=emitted_at,
                        proposal_type=proposal_type,
                        target_country=target_country)
    store.append_proposal(record, now=now)
    return record


def refusal_record(ruling: Ruling, *, proposal_id: str) -> dict:
    """S1-CALIB-041's repair: a refusal that survives the log rotation.

    Production creates no row when a guard blocks emission, so the reason
    exists only in a log line and a process-local object. NP6 asks the
    tool to disclose why it did NOT conclude, and a refusal nobody can
    read afterwards is the same silence as no refusal at all.
    """
    if not isinstance(ruling, Ruling):
        raise DomainError(
            f"refusal_record takes a Ruling from guards.evaluate(), got "
            f"{type(ruling).__name__}")
    if ruling.allowed:
        raise DomainError(
            "this ruling ALLOWED the proposal; recording it as a refusal "
            "would put a suppression in the audit trail for something "
            "nothing suppressed")
    payload = ruling.as_record()
    payload["proposal_id"] = proposal_id
    return payload


def entry_for(row: Mapping, *, state: str,
              history: Iterable = ()) -> dict:
    """One queue entry: the emitted row, its state, and how it got there."""
    entry = dict(row)
    entry["state"] = state
    entry["is_terminal"] = L.is_terminal(state)
    entry["adjudications"] = [item.as_dict() for item in history]
    return entry


def entries(store, ledger, *, now: float,
            window_sec: float = DEFAULT_QUEUE_WINDOW_SEC,
            scenario_id: Optional[str] = None,
            proposal_type: Optional[str] = None,
            epoch_id: Optional[str] = None,
            state: Optional[str] = None,
            at: Optional[float] = None) -> tuple:
    """P7 R13's projection. Newest first, each with its folded state.

    `store` supplies the emitted rows and `ledger` the adjudications; they
    are the same object in production and separated in the signature
    because the second one is read through the API's read-only wrapper.

    `at` bounds the FOLD, not the emission window: "the queue as it stood
    at T" means every proposal emitted by T, each in the state its
    adjudications had reached by T. Bounding only one of the two would
    show today's decisions against yesterday's queue.
    """
    horizon = float(now) if at is None else float(at)
    if state is not None and state not in L.STATES:
        raise DomainError(
            f"unknown state filter {state!r}; the queue's states are "
            f"{list(L.STATES)}")
    rows = store.proposals_between(
        horizon - float(window_sec), horizon, scenario_id=scenario_id,
        proposal_type=proposal_type, epoch_id=epoch_id)
    built = []
    for row in rows:
        from v3.commands import state as command_state
        proposal_id = row["proposal_id"]
        folded = command_state.proposal_state(ledger, proposal_id,
                                              until=horizon)
        current = L.state_of(folded)
        if state is not None and current != state:
            continue
        built.append(entry_for(
            row, state=current,
            history=command_state.proposal_history(ledger, proposal_id,
                                                   until=horizon)))
    return tuple(built)


def pending_count(store, ledger, *, now: float, scenario_id: str,
                  window_sec: float = DEFAULT_QUEUE_WINDOW_SEC) -> int:
    """S1-CALIB-040's cap input, counted rather than estimated.

    Production's cap counts with a query whose failure is treated as zero
    — fail-OPEN, so a database hiccup lifts the cap entirely (ACCIDENTAL
    A6). This raises instead, per ADR-V3-006: a cap that disappears under
    load is a cap that is absent exactly when it matters.
    """
    return len(entries(store, ledger, now=now, scenario_id=scenario_id,
                       state=L.PENDING, window_sec=window_sec))


__all__ = ["DEFAULT_QUEUE_WINDOW_SEC", "record_for", "emit",
           "refusal_record", "entry_for", "entries", "pending_count"]
