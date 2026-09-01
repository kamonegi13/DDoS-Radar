"""P7 R11 — the intel queue, with the NP7 envelope production omitted.

`GET /api/intel/pending/triage` was the one endpoint in the legacy surface
that returned conclusions without the disclaimer (P7 §1.1 R11). Here there
is no way to answer without it: the projection is built by
`tool_response`, which builds the one envelope, and the vocabulary check
runs on every response.

The queue is a JOIN of two things v3 already has and nothing else: the
`llm_intel` observations in L1 (WP-2.7 / O-17) and the adjudication fold
over `command_record`. `?state=` filters on the fold, and `pending` is
the analyst's work list — an item nobody has judged has no row anywhere.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, tool_response
from v3.api.write import Change
from v3.commands import spec as SPEC
from v3.intel import adjudication as A

#: How far back the queue looks. Bounded for the reason R9's limit is:
#: an unbounded queue is a request that gets slower every day nobody
#: reads it.
DEFAULT_WINDOW_SEC = 7 * 86400.0
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


def _limit(value) -> int:
    if value is None:
        return DEFAULT_LIMIT
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise E.bad_request(f"limit は整数です: {value!r}", limit=value) from None
    if not (1 <= parsed <= MAX_LIMIT):
        raise E.bad_request(f"limit は 1〜{MAX_LIMIT} の範囲です", limit=parsed)
    return parsed


def _target(item_id: str):
    if not isinstance(item_id, str) or not item_id.strip():
        raise E.bad_request("item_id が必要です", field="item_id")
    return SPEC.Target(kind=A.TARGET_INTEL, id=item_id.strip())


def read_intel(context, *, state=None, limit=None, window_sec=None) -> ApiResponse:
    """R11 — the queue, each item annotated with its adjudication."""
    if state is not None and state not in A.STATES:
        raise E.bad_request(
            f"未知の裁定状態: {state}", state=state, states=list(A.STATES),
            reason="空リストを返すと『裁定待ちは無い』と読めます")
    try:
        span = DEFAULT_WINDOW_SEC if window_sec is None else float(window_sec)
    except (TypeError, ValueError):
        raise E.bad_request(f"window_sec は秒数です: {window_sec!r}") from None
    bound = _limit(limit)
    rows = context.ledger.signals_between(context.now - span, context.now)
    folded = A.adjudicated(context.ledger, until=context.now)
    items = []
    for row in rows:
        if row.get("signal_source") != A.INTEL_SIGNAL_SOURCE:
            continue
        item_id = str(row["id"])
        current = folded.get(item_id, A.STATE_PENDING)
        if state is not None and current != state:
            continue
        items.append({
            "item_id": item_id, "state": current,
            "sensor": row.get("sensor"), "domain": row.get("domain"),
            "country": row.get("country"),
            "signal_source": row.get("signal_source"),
            "observed_at": row.get("observed_at"),
            "status": row.get("status"), "raw_score": row.get("raw_score"),
            "suppressed": bool(row.get("suppressed")),
            "adjudication": A.intel_state(context.ledger, item_id,
                                          until=context.now),
        })
    items.sort(key=lambda item: (-float(item["observed_at"] or 0.0),
                                 item["item_id"]))
    return tool_response(
        observed_at=context.now, intel=items[:bound],
        returned=len(items[:bound]), pending_count=sum(
            1 for item in items if item["state"] == A.STATE_PENDING),
        states=list(A.STATES), window_sec=span, limit=bound,
        note="LLM インテルは L1 の通常観測です（O-17）。裁定状態は "
             "command_record の fold であり、第 2 のキュー表はありません")


def _adjudicate(context, action: str, item_id: str) -> ApiResponse:
    committed = context.commit(Change(
        action=action, target=_target(item_id), payload=dict(context.body),
        reason=context.body.get("reason")))
    return tool_response(observed_at=context.now,
                         intel_item=committed.effective,
                         command=committed.record.as_dict()["command_id"])


def confirm_intel(context, *, item_id: str) -> ApiResponse:
    """C3 — the item leaves the pending queue."""
    return _adjudicate(context, A.INTEL_CONFIRM, item_id)


def reject_intel(context, *, item_id: str) -> ApiResponse:
    """C3 — the item leaves the queue AND stops scoring."""
    return _adjudicate(context, A.INTEL_REJECT, item_id)


def revert_intel(context, *, item_id: str) -> ApiResponse:
    """C3 — both effects undone. Illegal from `pending`."""
    return _adjudicate(context, A.INTEL_REVERT, item_id)


__all__ = ["read_intel", "confirm_intel", "reject_intel", "revert_intel"]
