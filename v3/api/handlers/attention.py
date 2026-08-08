"""P7 R6 / C4 — the ranked attention list and the analyst's answer to it.

The pair ships together and neither could ship alone, which is exactly
what the registry said while both were deferred: an ack with no projection
is a write nothing reads (G-15), and a ranked list with no way to say "I
have dealt with this" is a list that only grows.

R6 serves the ledger's rank. It does not compute one. P5 O-8 ruled AP1's
ranking into the backend precisely because G-03 found it living only in
`triage_score.js`, so a handler here that re-derived the order would be
the same defect with a Python spelling.

The C4 commands are thin in the way every command handler here is thin:
they validate the target, declare a `Change`, and answer with what the
state actually became — read back through the same fold R6 projects, not
echoed from the request body.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, command_response, tool_response
from v3.api.vocabulary import TOOL_SCOPE
from v3.api.write import Change
from v3.attention import narrative as narrative_module
from v3.attention import projection as projection_module
from v3.attention import thresholds as T
from v3.commands import attention as A
from v3.commands import spec as SPEC
from v3.kernel.errors import DomainError


def _actor(context):
    """Who the list is for. An identity, never a permission.

    R6 is a per-reader projection — the ack state and the floor are the
    caller's own — so an anonymous caller has no list. The route's access
    declaration already refuses one; this is the restatement, because a
    projection that quietly served somebody else's state would be worse
    than a 401. `context.actor_id` carries the id WITHOUT the role, so
    there is nothing here a permission decision could be made from — G-01's
    shape is unreachable rather than merely avoided.
    """
    actor_id = context.actor_id
    if actor_id is None:
        raise E.ApiFailure(401, E.ApiError(
            code=E.UNAUTHENTICATED,
            message="注目リストは利用者ごとの射影です",
            detail={"reason": "attention rows carry per-user ack/snooze "
                              "state and a per-user score floor"}))
    return actor_id


def _at(at):
    if at is None:
        return None
    try:
        return float(at)
    except (TypeError, ValueError):
        raise E.bad_request(f"at は unix 時刻です: {at!r}", at=at) from None


def read_attention(context, *, at=None, scenario_id=None) -> ApiResponse:
    """R6 — the ranked list, live or as it stood at `?at=`.

    One projection for both, per P7 derivation principle 4: the only
    difference between them is the instant passed to
    `v3/attention/projection.py::project`.
    """
    actor_id = _actor(context)
    if scenario_id is not None and context.scenario(str(scenario_id)) is None:
        raise E.not_found(f"シナリオ {scenario_id}", scenario_id=scenario_id)
    payload = projection_module.project(
        context.ledger, now=context.now, actor_id=actor_id, at=_at(at),
        scenario_id=None if scenario_id is None else str(scenario_id))
    return tool_response(
        observed_at=payload.pop("computed_at") or context.now,
        at=_at(at), **payload,
        threshold_disclosure=T.disclosure(),
        narrative_templates=narrative_module.disclosure())


def _item(context, item_id: str) -> str:
    if not isinstance(item_id, str) or not item_id.strip():
        raise E.bad_request("item_id が空です")
    ranks = context.read.ledger.attention_ranks_for_item(
        item_kind="conclusion", item_id=item_id, limit=1)
    if not ranks:
        raise E.not_found(
            f"注目行 {item_id}", item_id=item_id,
            reason="ack/snooze/dismiss は台帳に順位のある行に対してのみ行えます"
                   "（順位の無い行への操作は読み手のいない書込みです）")
    return item_id


def _item_command(context, *, item_id: str, action: str) -> ApiResponse:
    _item(context, item_id)
    body = context.body
    committed = context.commit(Change(
        action=action,
        target=SPEC.Target(kind=A.TARGET_ATTENTION, id=item_id),
        payload={"minutes": body.get("minutes"),
                 "reason": body.get("reason")},
        reason=body.get("reason")))
    return command_response(TOOL_SCOPE, committed, observed_at=context.now,
                            item_id=item_id)


def ack_attention(context, *, item_id: str) -> ApiResponse:
    """C4 — acknowledged. The next ranking sees an analyst acted."""
    return _item_command(context, item_id=item_id, action=A.ATTENTION_ACK)


def snooze_attention(context, *, item_id: str) -> ApiResponse:
    """C4 — not now, for `minutes` (default 30, max 1440)."""
    return _item_command(context, item_id=item_id, action=A.ATTENTION_SNOOZE)


def dismiss_attention(context, *, item_id: str) -> ApiResponse:
    """C4 — not this, for 24h."""
    return _item_command(context, item_id=item_id, action=A.ATTENTION_DISMISS)


def set_thresholds(context) -> ApiResponse:
    """C4's `PUT .../thresholds` — the G-02 endpoint, with a reader.

    `commit()` resolves through `v3/commands/attention.py::thresholds_for`,
    which is the function `v3/attention/projection.py` calls to decide what
    surfaces. So the effect check is not "we wrote a row": it is "the path
    that decides what you see now answers with this number".
    """
    body = dict(context.body)
    values = body.get("thresholds")
    if not isinstance(values, dict) or not values:
        raise E.bad_request(
            "thresholds オブジェクトを指定してください",
            per_user_keys=sorted(T.PER_USER_KEYS))
    unknown = sorted(set(values) - set(T.PER_USER_KEYS))
    if unknown:
        raise E.bad_request(
            f"未知の閾値キー: {', '.join(unknown)}", unknown=unknown,
            per_user_keys=sorted(T.PER_USER_KEYS),
            reason="読み手のいないキーを受け付けることが G-02 です")
    try:
        cleaned = {key: T.coerce_per_user(key, value)
                   for key, value in values.items()}
    except DomainError as exc:
        raise E.bad_request(str(exc),
                            per_user_keys=sorted(T.PER_USER_KEYS)) from exc
    committed = context.commit(Change(
        action=A.ATTENTION_THRESHOLDS,
        target=SPEC.Target(kind=A.TARGET_ATTENTION_THRESHOLDS,
                           id=context.actor_id),
        payload={"thresholds": cleaned},
        reason=body.get("reason")))
    return command_response(TOOL_SCOPE, committed, observed_at=context.now,
                            per_user_keys=sorted(T.PER_USER_KEYS))


__all__ = ["read_attention", "ack_attention", "snooze_attention",
           "dismiss_attention", "set_thresholds"]
