"""P7 R6 — the ranked list as served, live and replayed by one projection.

The rank is NOT recomputed here. It is read from the snapshot the ranker
wrote (`v3/runtime/attention.py`), which is the whole of P5 O-8: the
frontend must not re-derive an order the ledger already holds, or the
order an analyst acted on is once again a thing no record contains (G-03).

What this module adds to the stored snapshot is the part that cannot be
stored, because it differs per reader:

* the analyst's own ack / snooze / dismiss on each row, and whether it is
  still in force at the instant being served;
* the analyst's own `min_score`, which decides what surfaces.

Suppression here is ANNOTATION, not removal. An acknowledged row is
returned with `analyst_state: acked` rather than dropped, because the
list is also the record of what the tool asked for, and a row that
vanishes when acknowledged makes "I never saw it" and "I dealt with it"
look identical from outside. The one thing that does remove a row is the
analyst's own floor, and the response says how many rows it removed —
E-17 was a suppression that left no trace, and a silent filter is that
defect with a friendlier name.
"""
from __future__ import annotations

from typing import Optional

from v3.attention import thresholds as T
from v3.commands import attention as A

#: Why the list is empty, when it is. Never a bare `[]`: "nothing needs
#: attention" and "the ranker has not run" are different facts, and
#: production's habit of answering the second as the first is defect G-17.
EMPTY_NO_SNAPSHOT = "ranker_has_not_run"
EMPTY_ALL_FILTERED = "all_rows_below_min_score"
EMPTY_NO_CANDIDATES = "no_ranked_items"


def row_view(row: dict, *, ledger, actor_id: str, at: float) -> dict:
    """One stored rank row plus this analyst's state on it."""
    state = A.item_state(ledger, str(row["item_id"]), actor_id=actor_id,
                         until=at)
    name = A.state_name(state, now=at)
    view = dict(row)
    view["analyst_state"] = name
    view["analyst_state_expires_at"] = (None if not state
                                        else state.get("expires_at"))
    view["analyst_state_at"] = None if not state else state.get("at")
    view["suppressed"] = name != A.STATE_ACTIVE
    return view


def project(ledger, *, now: float, actor_id: str,
            at: Optional[float] = None,
            scenario_id: Optional[str] = None) -> dict:
    """The whole R6 payload body. Live and `?at=` are the same call."""
    horizon = float(now) if at is None else float(at)
    thresholds = A.thresholds_for(ledger, actor_id=actor_id, until=horizon)
    min_score = float(thresholds.get("min_score", T.DEFAULT_MIN_SCORE))
    snapshot_id = ledger.latest_attention_snapshot_id(horizon)
    if snapshot_id is None:
        return {"attention": [], "snapshot_id": None, "computed_at": None,
                "thresholds": thresholds, "considered": 0, "shown": 0,
                "filtered_below_min_score": 0,
                "empty_reason": EMPTY_NO_SNAPSHOT,
                "formula_ref": None}
    stored = ledger.attention_snapshot(snapshot_id)
    if scenario_id is not None:
        stored = [row for row in stored
                  if str(row["scenario_id"]) == str(scenario_id)]
    shown = [row_view(row, ledger=ledger, actor_id=actor_id, at=horizon)
             for row in stored if float(row["score"]) >= min_score]
    filtered = len(stored) - len(shown)
    if not stored:
        empty_reason = EMPTY_NO_CANDIDATES
    elif not shown:
        empty_reason = EMPTY_ALL_FILTERED
    else:
        empty_reason = None
    computed_at = float(stored[0]["computed_at"]) if stored else None
    return {"attention": shown, "snapshot_id": snapshot_id,
            "computed_at": computed_at, "thresholds": thresholds,
            "considered": len(stored), "shown": len(shown),
            "filtered_below_min_score": filtered,
            "empty_reason": empty_reason,
            "formula_ref": (str(stored[0]["formula_ref"]) if stored
                            else None)}


__all__ = ["EMPTY_NO_SNAPSHOT", "EMPTY_ALL_FILTERED", "EMPTY_NO_CANDIDATES",
           "row_view", "project"]
