"""Where the three factors come from in L1. One read path, no second copy.

The registry's deferral note for R6 said the blocker was "not design but
simply unimplemented — novelty, confidence_delta and analyst_blindness are
all derivable from existing L1 tables". This module is the derivation, and
naming it here matters more than it looks: each factor has exactly ONE
source, so a factor that stops moving is a broken read rather than a
disagreement between two readers.

    novelty              the instant the STATE last changed, found by
                         walking the stored history backwards (WP-4.11).
                         The first read here was the latest row's
                         `observed_at`, on the belief that L3 writes only
                         on change — but "change" for L3 includes every
                         confidence jitter, so rows churn each tick and
                         the factor degenerated to 1.0 for every candidate
                         (P9 §1.10 D-25(a)). The state diff is the fact
                         the factor was always meant to read: when did
                         this finding last SAY something different.
    confidence_delta     the same type's PREVIOUS row's `confidence`.
                         Absent (first ever, or older than the lookback)
                         means the movement is the confidence itself,
                         transcribed from `triage_score.js:96-103`.
    analyst_blindness    the newest `command_record` against this item —
                         a label (C2), an ack, a snooze or a dismiss (C4).
                         Production measured "how long since this BROWSER
                         rendered it" out of `localStorage`; the server
                         cannot see that and neither can AP4, so v3 asks
                         the question the ledger can answer: how long since
                         anyone in the organisation acted on it.

Everything takes the store as an argument and returns values; nothing is
cached. A cache here would be a second copy of the ledger's answer, and
the projection would then be able to disagree with the ledger about what
the analyst was shown.
"""
from __future__ import annotations

from typing import Optional, Sequence

from v3.attention import narrative as N
from v3.attention import rank as R
from v3.attention import score as S
from v3.conclusions.vocabulary import CONCLUSION_TYPES
from v3.kernel.errors import DomainError

#: How far back a predecessor is looked for. Bounded rather than
#: unbounded because the query is per (scenario, type) per tick, and a
#: predecessor older than a month tells nothing useful about movement.
#: Beyond it the row is treated as having no predecessor, which raises the
#: delta rather than lowering it — the NP1 direction, and the same branch
#: production takes when its history is empty.
PREDECESSOR_LOOKBACK_SEC = 30 * 86400.0


def _order_hint(conclusion_type: str) -> float:
    """The declared tie-break among equal scores.

    Conclusion types in the order L3 declares them, so the ordering has a
    single source. Production's tie-break was the order the browser
    happened to append candidates in; this is the same KIND of decision
    made once, in the open, where a stored row can be reproduced from it.
    """
    try:
        return float(CONCLUSION_TYPES.index(conclusion_type))
    except ValueError:
        return float(len(CONCLUSION_TYPES))


def _previous_confidence_of(rows, *, latest_id: str) -> Optional[float]:
    """The predecessor's confidence out of an already-fetched window."""
    earlier = [row for row in rows if row["id"] != latest_id]
    if not earlier:
        return None
    value = earlier[-1].get("confidence")
    return None if value is None else float(value)


def previous_confidence(store, *, scenario_id: str, conclusion_type: str,
                        latest_id: str, now: float,
                        lookback_sec: float = PREDECESSOR_LOOKBACK_SEC
                        ) -> Optional[float]:
    """The confidence of the row before the latest one, or None."""
    rows = store.conclusions_between(
        scenario_id=scenario_id, conclusion_type=conclusion_type,
        start=float(now) - float(lookback_sec), end=float(now))
    return _previous_confidence_of(rows, latest_id=latest_id)


def last_state_change_at(rows, *,
                         latest_observed_at: Optional[float]
                         ) -> Optional[float]:
    """When the state actually last changed, by backward diff (WP-4.11).

    `rows` is one (scenario, type)'s window, oldest first — the same
    window the predecessor is read from, fetched once by `candidate_for`.
    The answer is the `observed_at` of the newest row whose `state`
    differs from the row before it. Two boundary rules, both stated:

    * **No change inside the window** means the finding has been saying
      the same thing since at least the window's oldest row, so THAT
      instant is the answer — an age of ≥30 days, which the 48h horizon
      turns into novelty 0. Returning None here would crown a finding
      maximally novel for being maximally stable, which is D-25(a) again
      with the sign flipped.
    * **An empty window** (the latest row is older than the lookback)
      falls back to the latest row's own instant, which is just as old
      and scores the same 0.

    A single-row window IS a change: nothing → a state, dated by the row
    that first said it. Rows without an `observed_at` cannot anchor an
    instant and are skipped rather than guessed at.
    """
    dated = [row for row in rows if row.get("observed_at") is not None]
    if not dated:
        return latest_observed_at
    for index in range(len(dated) - 1, 0, -1):
        if dated[index].get("state") != dated[index - 1].get("state"):
            return float(dated[index]["observed_at"])
    return float(dated[0]["observed_at"])


def last_analyst_action_at(store, *, item_id: str,
                           now: float) -> Optional[float]:
    """When an analyst last acted on this item, from the command ledger.

    Filtered by target id rather than by kind, on purpose: a label targets
    `conclusion:<id>` and an ack targets `attention:<id>` with the same id,
    and both are an analyst having looked. Splitting them would let an
    acknowledged item keep accruing blindness as though nobody had seen it.
    """
    rows = store.command_records(target_id=str(item_id), until=float(now))
    if not rows:
        return None
    return float(rows[-1]["issued_at"])


def candidate_for(store, *, scenario_id: str, conclusion_type: str,
                  now: float) -> Optional[S.Inputs]:
    """One scenario/type's candidate, or None when it has never concluded."""
    row = store.latest_conclusion_at(float(now), scenario_id=scenario_id,
                                     conclusion_type=conclusion_type)
    if row is None:
        return None
    conclusion_id = str(row["id"])
    # One window, two readers: the predecessor's confidence and the last
    # state change come out of the same fetch, so they cannot disagree
    # about what the history was.
    history = store.conclusions_between(
        scenario_id=scenario_id, conclusion_type=conclusion_type,
        start=float(now) - PREDECESSOR_LOOKBACK_SEC, end=float(now))
    return S.Inputs(
        item_kind=S.ITEM_CONCLUSION, item_id=conclusion_id,
        scenario_id=scenario_id,
        last_changed_at=last_state_change_at(
            history,
            latest_observed_at=(None if row.get("observed_at") is None
                                else float(row["observed_at"]))),
        confidence=float(row.get("confidence") or 0.0),
        previous_confidence=_previous_confidence_of(
            history, latest_id=conclusion_id),
        last_analyst_action_at=last_analyst_action_at(
            store, item_id=conclusion_id, now=now),
        unavailable_reason=row.get("conclusion_unavailable_reason") or None,
        context={"conclusion_type": conclusion_type,
                 "state": row.get("state"),
                 # WP-4.13a reads this marker to decide whether the
                 # sentence may speak the change instant: rows scored
                 # before WP-4.11 carry a write instant here, and a
                 # sentence that called one a state change would be false.
                 N.NOVELTY_BASIS_KEY: N.NOVELTY_BASIS_STATE_CHANGE,
                 R.ORDER_HINT: _order_hint(conclusion_type)})


def candidates(store, *, scenario_ids: Sequence[str], now: float) -> tuple:
    """Every scenario's every conclusion type, as scoring inputs.

    ALL scenarios and ALL five types, not the focused scenario's two.
    Production ranked only `attack_mode` and `anomaly`, and only for the
    scenario the analyst already had open — so the list could never tell
    an analyst to look somewhere else, which is most of what a triage list
    is for. Registered as difference #89; the direction is sensitive.
    """
    if isinstance(scenario_ids, str):
        raise DomainError(
            "candidates takes a sequence of scenario ids, not one string")
    found = []
    for scenario_id in scenario_ids:
        for conclusion_type in CONCLUSION_TYPES:
            item = candidate_for(store, scenario_id=scenario_id,
                                 conclusion_type=conclusion_type, now=now)
            if item is not None:
                found.append(item)
    return tuple(found)


__all__ = ["PREDECESSOR_LOOKBACK_SEC", "previous_confidence",
           "last_state_change_at", "last_analyst_action_at",
           "candidate_for", "candidates"]
