"""Ordering, and the rows the ledger stores.

Two things live here and nothing else: the total order over scored
candidates, and the conversion of `(Inputs, Provenance)` into
`AttentionRankRecord`s. Both are pure.

**The order is total and stated.** `triage_score.js` sorts by score alone
and lets ties fall out of `Array.prototype.sort`'s stability, i.e. by the
order the caller happened to build the array in (`radar.js:6698-6715`
inserts attack_mode before anomaly). That is a real order, but it is not a
declared one, and a persisted rank whose tie-break is an accident of the
caller cannot be reproduced from the stored row. So the tie-break here is
explicit — score, then the caller's declared `order_hint`, then scenario,
then item id — and registered as difference #88.

**Every candidate is stored, including the ones that scored zero.** The
browser dropped anything below `MIN_FIRE_THRESHOLD` before ranking. Here
the floor is a per-user projection concern (see
`v3/attention/thresholds.py` on defect G-02), so the snapshot holds what
the tool considered and what it decided, which is what NP6 asks: disclose
why the tool did NOT raise something, not only why it did.
"""
from __future__ import annotations

from typing import Iterable, Sequence

from v3.attention import narrative as N
from v3.attention import score as S
from v3.kernel.errors import DomainError
from v3.ledger.records import AttentionRankRecord

#: The key the caller may put in `Inputs.context` to declare its own
#: preferred order among equal scores. Named rather than positional
#: because the value ends up in the stored provenance, where an unexplained
#: integer would be worse than no tie-break at all.
ORDER_HINT = "order_hint"


def _order_hint(inputs: S.Inputs) -> float:
    value = dict(inputs.context).get(ORDER_HINT)
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(
            f"{ORDER_HINT} must be a number, got {value!r}: it is a sort "
            f"key, and a string here would order lexically in one place and "
            f"raise in another")
    return float(value)


def sort_key(pair) -> tuple:
    """`(-score, order_hint, scenario_id, item_kind, item_id)`.

    Negated score rather than `reverse=True` so that the primary key and
    the tie-breaks sort in the same direction — a reversed sort would
    reverse the tie-breaks too, and the id tie-break would silently become
    "highest id wins".
    """
    inputs, provenance = pair
    return (-provenance.score, _order_hint(inputs), inputs.scenario_id,
            inputs.item_kind, inputs.item_id)


def rank(candidates: Iterable[S.Inputs], *, now: float) -> tuple:
    """Score every candidate and put them in order. Pure.

    Returns `((inputs, provenance, position), ...)` with positions 1..n,
    which is the shape `records_for` turns into ledger rows and the shape
    a test can assert an order on without a database.
    """
    scored = [(item, S.score_for(item, now=now)) for item in candidates]
    ordered = sorted(scored, key=sort_key)
    return tuple((inputs, provenance, position)
                 for position, (inputs, provenance)
                 in enumerate(ordered, start=1))


def records_for(ranked: Sequence, *, snapshot_id: str,
                computed_at: float) -> tuple:
    """The ledger rows for one whole snapshot, in rank order."""
    rows = []
    for inputs, provenance, position in ranked:
        narrative, template_ref = N.render_row(
            inputs=inputs, provenance=provenance, rank=position)
        rows.append(AttentionRankRecord(
            snapshot_id=snapshot_id, computed_at=computed_at,
            scenario_id=inputs.scenario_id, item_kind=inputs.item_kind,
            item_id=inputs.item_id, rank_position=position,
            score=provenance.score, novelty=provenance.novelty,
            confidence_delta=provenance.confidence_delta,
            analyst_blindness=provenance.analyst_blindness,
            formula_ref=provenance.formula_ref,
            narrative_template_ref=template_ref, narrative=narrative,
            components=provenance.as_dict()))
    return tuple(rows)


#: How far a score must move, with the order unchanged, before the
#: snapshot is worth another row. One `min_score` band (the default floor
#: is 0.05), so the threshold is the same size as the smallest decision
#: the projection makes with a score.
SIGNIFICANT_SCORE_DELTA = 0.05


def signature(records: Sequence) -> tuple:
    """The ORDER, which is what "the ranking" means.

    Deliberately not the scores. Two of the three factors move with the
    clock — blindness saturates over 6h, novelty decays over 48h — so a
    signature containing scores changes on every tick by construction, and
    a rounded one changes whenever a row happens to sit near a rounding
    boundary. WP-4.1f measured that: two snapshots one second apart, in
    identical order, differed only because 0.18750 and 0.18749 round to
    different thousandths. A ledger written on that basis would bury the
    tick where the order actually changed under ten thousand where the
    clock advanced.
    """
    return tuple((row.rank_position, row.item_kind, row.item_id)
                 for row in records)


def moved(records: Sequence, previous: Sequence) -> bool:
    """Whether this ranking is worth storing beside the previous one.

    Two reasons to store, and they are different questions:

    1. **the order or the membership changed** — the ranking itself moved;
    2. **a row's score moved by a band** while the order held — the tool's
       opinion of an item changed materially even though nothing overtook
       it, and an analyst asking "when did this become urgent" needs the
       row that says so.

    `previous` is the stored snapshot's rows as dicts. Drift below the
    band with the order intact writes nothing, which is the whole point:
    the clock is not a decision.
    """
    if signature(records) != tuple(
            (int(row["rank_position"]), str(row["item_kind"]),
             str(row["item_id"])) for row in previous):
        return True
    scores = {str(row["item_id"]): float(row["score"]) for row in previous}
    return any(abs(row.score - scores.get(row.item_id, 0.0))
               >= SIGNIFICANT_SCORE_DELTA for row in records)


__all__ = ["ORDER_HINT", "SIGNIFICANT_SCORE_DELTA", "sort_key", "rank",
           "records_for", "signature", "moved"]
