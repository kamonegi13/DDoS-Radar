"""P7 R9 — ONE decision trail (AP4), projected from the command log.

Production spreads this over five surfaces — `decisions/history`,
`auto_judge/decisions`, `config_audit`, `llm_routing/audit`,
`llm_features/audit` — each with its own row shape, so "what did anyone
change on the 12th" is five queries whose answers cannot be merged. P7
collapses them into this one projection, filtered by `?type=`.

**There is no `decision` table.** The registry's deferral note settled
that when WP-3.3 landed: `command_record` already IS the unified ledger —
every change the surface governs is a row on it, because the effective
state is the fold of those rows — so R9 is a projection across target
kinds rather than a second store to keep in step with the first.

The one face that is not a command is the S8 rank snapshot, and it is
here for the reason P7 R9 names it: the ranking IS an automated judgement,
and AP4's promise is that automated judgements can be replayed. It is
served from `attention_rank` with `?type=attention_rank`, in the same
envelope, so an analyst reading the trail sees "the tool put this first"
next to "and then I dismissed it".
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, tool_response
from v3.commands import spec as SPEC

#: The `?type=` vocabulary. Command target kinds, plus the one derived
#: face. Declared here rather than inferred from the rows, so asking for a
#: type that does not exist is a 400 naming the ones that do — an empty
#: list would read as "nothing happened", which is the answer production
#: gives to a misspelt filter.
TYPE_ATTENTION_RANK = "attention_rank"

DECISION_TYPES: tuple[str, ...] = tuple(sorted(SPEC.TARGET_KINDS)) + (
    TYPE_ATTENTION_RANK,)

#: How many rows one request may return. A trail with no bound is a
#: request that gets slower every day it is not read.
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


def _limit(value) -> int:
    if value is None:
        return DEFAULT_LIMIT
    try:
        limit = int(value)
    except (TypeError, ValueError):
        raise E.bad_request(f"limit は整数です: {value!r}",
                            limit=value) from None
    if not (1 <= limit <= MAX_LIMIT):
        raise E.bad_request(
            f"limit は 1〜{MAX_LIMIT} の範囲です", limit=limit,
            max_limit=MAX_LIMIT)
    return limit


def _at(at):
    if at is None:
        return None
    try:
        return float(at)
    except (TypeError, ValueError):
        raise E.bad_request(f"at は unix 時刻です: {at!r}", at=at) from None


def _command_rows(ledger, *, target_kind, target_id, actor_id, until, limit):
    rows = ledger.command_records(target_kind=target_kind,
                                  target_id=target_id, actor_id=actor_id,
                                  until=until)
    # Newest first: this is a trail somebody reads, not a fold. The store
    # returns oldest-first because that is what a fold needs, and the two
    # orders are reversed HERE rather than by a second query, so there is
    # one definition of the sequence.
    ordered = list(reversed(rows))[:limit]
    return [{"decision_type": row["target_kind"], "id": row["command_id"],
             "action": row["action"], "target_id": row["target_id"],
             "actor_id": row["actor_id"], "actor_role": row["actor_role"],
             "decided_at": row["issued_at"], "reason": row.get("reason"),
             "before": row.get("before"), "after": row.get("after"),
             "automated": False}
            for row in ordered]


def _rank_rows(ledger, *, target_id, until, limit):
    """The S8 snapshot face. Automated, and it says so.

    Production can only distinguish an automatic decision from an
    analyst's by a marker string inside a text column (ACCIDENTAL A9).
    Here `automated` is a field, and it is False for every command row
    because a command always has a human actor by construction.

    Two questions, two reads. Without a target the answer is "what did the
    tool rank at that instant" — one snapshot. With one it is "how long has
    the tool been asking me to look at THIS, and at what rank" — the item's
    history, which is the question an analyst asks after an incident and
    the one production could not answer at all.
    """
    if target_id is None:
        snapshot_id = ledger.latest_attention_snapshot_id(until)
        rows = [] if snapshot_id is None else ledger.attention_snapshot(
            snapshot_id)
    else:
        rows = ledger.attention_ranks_for_item(
            item_kind="conclusion", item_id=str(target_id), until=until,
            limit=limit)
    return [{"decision_type": TYPE_ATTENTION_RANK,
             "id": f"{row['snapshot_id']}:{row['item_id']}",
             "action": "attention.rank", "target_id": row["item_id"],
             "actor_id": None, "actor_role": None,
             "decided_at": row["computed_at"], "reason": row["narrative"],
             "before": None,
             "after": {"rank_position": row["rank_position"],
                       "score": row["score"],
                       "scenario_id": row["scenario_id"]},
             "automated": True,
             "components": row["components"],
             "formula_ref": row["formula_ref"],
             "narrative_template_ref": row["narrative_template_ref"]}
            for row in rows][:limit]


def read_decisions(context, *, type=None, target_id=None, actor_id=None,
                   at=None, limit=None) -> ApiResponse:
    """R9 — the trail, filtered, newest first, live or at `?at=`."""
    horizon = _at(at)
    until = context.now if horizon is None else horizon
    bound = _limit(limit)
    if type is not None and type not in DECISION_TYPES:
        raise E.bad_request(
            f"未知の判断種別: {type}", type=type,
            decision_types=list(DECISION_TYPES),
            reason="空リストを返すと『何も起きていない』と読めます")
    rows: list = []
    if type is None or type != TYPE_ATTENTION_RANK:
        rows.extend(_command_rows(
            context.ledger, target_kind=type,
            target_id=None if target_id is None else str(target_id),
            actor_id=None if actor_id is None else str(actor_id),
            until=until, limit=bound))
    if type is None or type == TYPE_ATTENTION_RANK:
        # An actor filter excludes the automated face by construction: a
        # rank snapshot has no actor, so asking "what did this analyst
        # decide" must not answer with what the tool decided.
        if actor_id is None:
            rows.extend(_rank_rows(
                context.ledger,
                target_id=None if target_id is None else str(target_id),
                until=until, limit=bound))
    rows.sort(key=lambda row: (-float(row["decided_at"]), str(row["id"])))
    return tool_response(observed_at=context.now, at=horizon,
                         decisions=rows[:bound],
                         decision_types=list(DECISION_TYPES),
                         actions=list(SPEC.ACTIONS) + ["attention.rank"],
                         returned=len(rows[:bound]), limit=bound,
                         note="AP4: 指令台帳（command_record）と S8 順位"
                              "スナップショットの 1 射影。判断種別ごとの"
                              "別 endpoint は存在しません")


def read_decision(context, *, command_id: str) -> ApiResponse:
    """R9's by-id face — one decision, with the state it moved."""
    rows = context.ledger.command_records(until=context.now)
    for row in rows:
        if row["command_id"] == command_id:
            return tool_response(observed_at=context.now, decision=row,
                                 decision_types=list(DECISION_TYPES))
    raise E.not_found(f"判断 {command_id}", command_id=command_id)


__all__ = ["DECISION_TYPES", "TYPE_ATTENTION_RANK", "read_decisions",
           "read_decision"]
