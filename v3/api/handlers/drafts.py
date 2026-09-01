"""WP-0.4 v2 (0.4e) — the FN draft queue and its two verdicts.

The Tier 3 surface. It is deliberately small, because the ruling it
serves is that Tier 3 must never be load-bearing: an analyst who never
opens this queue changes nothing about whether the pipeline runs, only
how wide the published recall interval is (`R7 self_eval`). Nothing here
has a deadline, an auto-disposition or a nag.

The read serves what is genuinely unresolved — `human.pending_drafts`,
the one definition — and says how long each has been waiting, because a
queue whose age is invisible is a queue whose growth is invisible.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, command_response, tool_response
from v3.api.vocabulary import TOOL_SCOPE
from v3.api.write import Change
from v3.calibration import human as HUMAN
from v3.calibration.epoch import CURRENT_EPOCH
from v3.commands import calibration as C
from v3.commands import spec as SPEC


def read_drafts(context, *, scenario_id=None) -> ApiResponse:
    """The pending FN candidates — what the interval's width is made of."""
    if scenario_id is not None and context.scenario(str(scenario_id)) is None:
        raise E.not_found(f"シナリオ {scenario_id}", scenario_id=scenario_id)
    pending = HUMAN.pending_drafts(context.ledger, now=context.now)
    rows = []
    for draft in pending:
        if scenario_id is not None and \
                str(draft["scenario_id"]) != str(scenario_id):
            continue
        rows.append({
            "draft_id": draft["draft_id"],
            "scenario_id": draft["scenario_id"],
            "conclusion_type": draft["conclusion_type"],
            "conclusion_id": draft["conclusion_id"],
            "label": draft["label"],
            "reason": draft["reason"],
            "evidence_note": draft.get("evidence_note") or "",
            "sources": list(draft.get("sources") or []),
            "proposed_analyst_id": draft["proposed_analyst_id"],
            "rule_id": draft["rule_id"],
            "evidence_url": draft.get("evidence_url"),
            "observed_at": draft["observed_at"],
            "created_at": draft["created_at"],
            "waiting_sec": max(0.0, context.now - float(draft["created_at"])),
        })
    return tool_response(
        observed_at=context.now, drafts=rows, pending_count=len(rows),
        epoch_id=CURRENT_EPOCH.epoch_id,
        note="未裁定の FN 候補です。裁定は任意で、期限も自動処分もありません"
             "（ADR-V3-012: Tier 3 は非同期）。未裁定の間は R7 の "
             "recall_lower_bound が下がり、公表される区間が広がります。")


def _known_draft(context, draft_id: str) -> dict:
    if not isinstance(draft_id, str) or not draft_id.strip():
        raise E.bad_request("draft_id が空です")
    for draft in context.read.ledger.fn_drafts(
            epoch_id=CURRENT_EPOCH.epoch_id):
        if draft["draft_id"] == draft_id:
            return draft
    raise E.not_found(f"FN 草稿 {draft_id}", draft_id=draft_id)


def _adjudicate(context, *, draft_id: str, action: str) -> ApiResponse:
    """The whole handler: validate, declare the Change, report the fold.

    It writes NO label, and that is the design rather than an omission.
    The command surface has exactly one write door (`append_command`,
    proved by `audit_command_writes`), and a confirm's label is
    materialised by the next S9 cycle under the analyst's identity. The
    interval stays honest across that gap because a confirmed draft is
    still counted as pending until its label exists — see
    `commands/calibration.py::rejected_draft_ids`.
    """
    draft = _known_draft(context, draft_id)
    body = context.body
    committed = context.commit(Change(
        action=action,
        target=SPEC.Target(kind=C.TARGET_DRAFT, id=draft_id),
        payload={"reason": body.get("reason")},
        reason=body.get("reason")))
    return command_response(
        str(draft["scenario_id"]), committed, observed_at=context.now,
        draft_id=draft_id,
        note=("確認しました。ラベルは次回の S9 サイクル（日次）で "
              "analyst 名義により台帳へ書き込まれます。それまでこの草稿は "
              "pending のまま数えられます（区間が狭くなるのはラベル着地時 "
              "— 裁定しただけで recall が良く見えることはありません）。"
              if action == C.DRAFT_CONFIRM
              else "却下しました。ラベルは書かれず、この草稿は pending から "
                   "外れます（答えの出た問いが区間を広げ続けないため）。"))


def confirm_draft(context, *, draft_id: str) -> ApiResponse:
    """C14c — this candidate is a real miss."""
    return _adjudicate(context, draft_id=draft_id, action=C.DRAFT_CONFIRM)


def reject_draft(context, *, draft_id: str) -> ApiResponse:
    """C14r — this candidate is not a miss. Writes NO label, and the
    draft leaves the pending set: the question has been answered."""
    return _adjudicate(context, draft_id=draft_id, action=C.DRAFT_REJECT)


__all__ = ["read_drafts", "confirm_draft", "reject_draft"]
