"""P7 C1 / C2 / C9 — the commands, and how thin a command handler is.

Every handler here does the same three things: validate that the target
exists, declare a `Change`, and answer with what the state actually became.
It cannot do more, and the shape of the module is the evidence:

* no ledger writer is reachable from it (the context forwards one door),
* `before` and `after` are not its to state (`commit` resolves both),
* who is acting is not its to record (`commit` stamps the actor),
* and the value it reports is read back through the read projection, not
  echoed from the request body.

That last one is the G-15 lesson made concrete. There, the UI displayed
the value the analyst had submitted, and the submitted value was never
what the tool used. Here a response cannot contain the submitted value at
all — only what `resolve` returns afterwards.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, command_response, tool_response
from v3.api.write import Change
from v3.commands import spec as SPEC
from v3.commands import state as S


def _known_scenario(context, scenario_id: str):
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise E.bad_request("scenario_id が空です")
    if context.read.scenario(scenario_id) is None:
        raise E.not_found(f"シナリオ {scenario_id}", scenario_id=scenario_id)
    return scenario_id


def read_ground_truth(context, *, scenario_id=None) -> ApiResponse:
    """C9's read half — and the reason the write half is not a lie.

    A command whose effect nothing projects is G-15 regardless of how
    honest its audit row is. This is the projection: the same fold
    `commit()` verifies against, served to anyone who may read the tool's
    reliability inputs.
    """
    wanted = ([ref.scenario_id for ref in context.scenarios]
              if scenario_id is None else [str(scenario_id)])
    if scenario_id is not None and context.scenario(str(scenario_id)) is None:
        raise E.not_found(f"シナリオ {scenario_id}", scenario_id=scenario_id)
    entries = {sid: S.ground_truth_for(context.ledger, sid, until=context.now)
               for sid in wanted}
    return tool_response(observed_at=context.now, ground_truth=entries,
                         entry_count=sum(len(rows) for rows in
                                         entries.values()),
                         required_fields=list(S.GROUND_TRUTH_FIELDS))


def set_focus(context) -> ApiResponse:
    """C1. Focus registration, off the read path (S2-PROP-001).

    In the legacy surface this was a side effect of `GET /api/threat_data`,
    which is why polling could not be stopped and why a focus change and a
    scoring tick could not be told apart in the record. Here it is a POST
    that leaves a row saying who moved the tool's attention and when.
    """
    body = context.body
    scenario_id = _known_scenario(context, str(body.get("scenario_id") or ""))
    committed = context.commit(Change(
        action=S.FOCUS_SET,
        target=SPEC.Target(kind=S.TARGET_SCENARIO, id=scenario_id),
        payload={"scenario_id": scenario_id},
        reason=body.get("reason")))
    return command_response(scenario_id, committed,
                            observed_at=context.now)


def submit_feedback(context, *, conclusion_id: str) -> ApiResponse:
    """C2. The G-01 endpoint, permanently gated by its route declaration.

    G-01 was this endpoint in four variants, three of which called the
    gate. The fix is not a fourth call — it is that the decision is a
    field of the route table and this function has no way to express it.
    """
    if not isinstance(conclusion_id, str) or not conclusion_id.strip():
        raise E.bad_request("conclusion_id が空です")
    row = context.read.ledger.conclusion_by_id(conclusion_id)
    if row is None:
        raise E.not_found(f"結論 {conclusion_id}", conclusion_id=conclusion_id)
    body = context.body
    committed = context.commit(Change(
        action=S.CONCLUSION_LABEL,
        target=SPEC.Target(kind=S.TARGET_CONCLUSION, id=conclusion_id),
        payload={"label": body.get("label"), "reason": body.get("reason"),
                 "observed_outcome_url": body.get("observed_outcome_url")},
        reason=body.get("reason")))
    return command_response(str(row["scenario_id"]), committed,
                            observed_at=context.now,
                            conclusion_id=conclusion_id,
                            label_vocabulary=sorted(S.ANALYST_LABELS))


def assert_ground_truth(context, *, scenario_id: str) -> ApiResponse:
    """C9. A human asserting that something actually happened.

    S9's teacher signal. The assertion carries an observation time and a
    checkable source because incident #1's labels carried neither, and a
    label that cannot be checked is indistinguishable from a fabricated
    one once it is in the confusion matrix.
    """
    _known_scenario(context, scenario_id)
    body = context.body
    committed = context.commit(Change(
        action=S.GROUND_TRUTH_ASSERT,
        target=SPEC.Target(kind=S.TARGET_SCENARIO, id=scenario_id),
        payload={name: body.get(name) for name in S.GROUND_TRUTH_FIELDS},
        reason=body.get("reason")))
    return command_response(scenario_id, committed,
                            observed_at=context.now,
                            required_fields=list(S.GROUND_TRUTH_FIELDS))


__all__ = ["read_ground_truth", "set_focus", "submit_feedback",
           "assert_ground_truth"]
