"""P7 R13 / C5 — the unified proposal queue and its adjudication.

Production has three proposal families with three shapes; P7 §5 collapses
them into one queue read by `?kind=`. The queue itself landed with WP-3.3
(`v3/calibration/queue.py::entries` — emitted row, folded state,
adjudication history, `?at=` from the same call), so what is here is the
L6 slice the registry named as the only thing remaining: the route
registration and a response vocabulary.

C5 is three of the lifecycle's five edges. `proposal.revive` and
`proposal.supersede` have no route on purpose — they are transitions the
calibration pass makes automatically, and an analyst-facing verb for them
would let a human write a row the state machine believes an automaton
wrote (production can only tell those apart by a marker string inside
`state_changed_by`, ACCIDENTAL A9).
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, command_response, tool_response
from v3.api.write import Change
from v3.calibration import lifecycle as L
from v3.calibration import queue as Q
from v3.commands import spec as SPEC
from v3.commands import state as S
from v3.kernel.errors import DomainError


def _at(at):
    if at is None:
        return None
    try:
        return float(at)
    except (TypeError, ValueError):
        raise E.bad_request(f"at は unix 時刻です: {at!r}", at=at) from None


def read_proposals(context, *, kind=None, scenario_id=None, state=None,
                   at=None) -> ApiResponse:
    """R13 — the queue, live or as it stood at `?at=`.

    `?at=` bounds BOTH the emission window and the adjudication fold, which
    is `entries()`'s own contract: showing today's decisions against
    yesterday's queue would be a replay that never happened.
    """
    horizon = _at(at)
    if scenario_id is not None and context.scenario(str(scenario_id)) is None:
        raise E.not_found(f"シナリオ {scenario_id}", scenario_id=scenario_id)
    try:
        rows = Q.entries(context.ledger, context.ledger, now=context.now,
                         scenario_id=(None if scenario_id is None
                                      else str(scenario_id)),
                         proposal_type=None if kind is None else str(kind),
                         state=None if state is None else str(state),
                         at=horizon)
    except DomainError as exc:
        raise E.bad_request(str(exc), kind=kind, state=state) from exc
    return tool_response(
        observed_at=context.now, at=horizon, proposals=list(rows),
        pending=len([row for row in rows if row["state"] == L.PENDING]),
        states=list(L.STATES), kinds=list(L.PROPOSAL_TYPES),
        vocabulary=L.vocabulary_disclosure(),
        window_sec=Q.DEFAULT_QUEUE_WINDOW_SEC)


def _known_proposal(context, proposal_id: str) -> dict:
    if not isinstance(proposal_id, str) or not proposal_id.strip():
        raise E.bad_request("proposal_id が空です")
    row = context.read.ledger.proposal_by_id(proposal_id)
    if row is None:
        raise E.not_found(f"提案 {proposal_id}", proposal_id=proposal_id)
    return row


def _adjudicate(context, *, proposal_id: str, action: str) -> ApiResponse:
    row = _known_proposal(context, proposal_id)
    body = context.body
    try:
        committed = context.commit(Change(
            action=action,
            target=SPEC.Target(kind=S.TARGET_PROPOSAL, id=proposal_id),
            payload={"reason": body.get("reason")},
            reason=body.get("reason")))
    except L.TransitionRefusedError as exc:
        # An illegal edge is the caller's fault and it must be VISIBLE.
        # Production's UPDATE matches zero rows and reports success, so an
        # analyst who believes they dismissed something is not told the
        # decision was lost — the G-01 shape in a different layer.
        raise E.bad_request(str(exc), proposal_id=proposal_id,
                            action=action) from exc
    return command_response(str(row["scenario_id"]), committed,
                            observed_at=context.now,
                            proposal_id=proposal_id,
                            lifecycle=L.vocabulary_disclosure())


def apply_proposal(context, *, proposal_id: str) -> ApiResponse:
    """C5 — apply. The single guard evaluator has already had its say."""
    return _adjudicate(context, proposal_id=proposal_id,
                       action=S.PROPOSAL_APPLY)


def dismiss_proposal(context, *, proposal_id: str) -> ApiResponse:
    """C5 — dismissed, with the reason it was."""
    return _adjudicate(context, proposal_id=proposal_id,
                       action=S.PROPOSAL_DISMISS)


def defer_proposal(context, *, proposal_id: str) -> ApiResponse:
    """C5 — deferred (snoozed 30 days).

    裁定要求 11, ruled 2026-08-08: production revives a deferred proposal
    into `pending` WITHOUT moving `emitted_at`, while auto-dismiss reads
    `emitted_at` — so at the shipped defaults (snooze 30d, staleness 30d)
    a deferral is a dismissal with a delay. v3 preserves that behaviour
    (§7-2 #82) rather than diverging inside the parity window; the
    production repair is queued for after cutover and owed a D2 entry.
    """
    return _adjudicate(context, proposal_id=proposal_id,
                       action=S.PROPOSAL_DEFER)


__all__ = ["read_proposals", "apply_proposal", "dismiss_proposal",
           "defer_proposal"]
