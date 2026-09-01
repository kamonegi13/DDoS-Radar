"""Step S8 — the ranker, run by the tick, writing the attention ledger.

The pure half lives in `v3/attention/`. This module is the impure edge:
it holds the store, it is handed the clock, and it decides whether a
snapshot is worth writing.

**Written only when the ranking changes.** The same rule L3 applies to
conclusions, and here it is load-bearing: two of the three factors move
with the CLOCK, so an unconditional write would produce a snapshot per
cadence forever and bury the tick where the order actually changed.
`rank.moved` is what "changed" means — a different order, or a score that
crossed a band while the order held. A first attempt compared rounded
scores and was measured to fail: two snapshots one second apart, in
identical order, differed because 0.18750 and 0.18749 round apart.

**A snapshot is not written for an empty candidate set.** A ranking of
nothing is not the same fact as no ranking, and the projection reports
the two differently (`EMPTY_NO_SNAPSHOT` vs `EMPTY_NO_CANDIDATES`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from v3.attention import rank as rank_module
from v3.attention import supply as supply_module
from v3.kernel.errors import DomainError

SNAPSHOT_PREFIX = "attn"


def snapshot_id_for(now: float) -> str:
    """Deterministic, like every other identity in v3 (NP6).

    A uuid4 would make a tick un-replayable: replaying the same instant
    must produce the same snapshot id, or the idempotent append writes a
    second copy of a ranking that already exists.
    """
    return f"{SNAPSHOT_PREFIX}-{int(float(now))}"


@dataclass(frozen=True, slots=True)
class RankReport:
    """What the ranker did, as a value the tick can report and publish."""

    snapshot_id: str
    computed_at: float
    considered: int
    written: int
    changed: bool
    rows: tuple = ()

    def as_dict(self) -> dict:
        return {"snapshot_id": self.snapshot_id,
                "computed_at": self.computed_at,
                "considered": self.considered, "written": self.written,
                "changed": self.changed,
                "rows": [row.as_dict() for row in self.rows]}


def previous_rows(store, *, now: float) -> tuple:
    """The stored snapshot in force at `now`, or empty if there is none."""
    previous_id = store.latest_attention_snapshot_id(float(now))
    if previous_id is None:
        return ()
    return tuple(store.attention_snapshot(previous_id))


def rank_cycle(*, now: float, store, scenario_ids: Sequence[str],
               snapshot_id: Optional[str] = None) -> RankReport:
    """Score every candidate, order them, write the snapshot if it moved."""
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
    scenarios = tuple(scenario_ids)
    candidates = supply_module.candidates(store, scenario_ids=scenarios,
                                          now=now)
    identity = snapshot_id or snapshot_id_for(now)
    if not candidates:
        return RankReport(snapshot_id=identity, computed_at=float(now),
                          considered=0, written=0, changed=False, rows=())
    ranked = rank_module.rank(candidates, now=now)
    records = rank_module.records_for(ranked, snapshot_id=identity,
                                      computed_at=float(now))
    if not rank_module.moved(records, previous_rows(store, now=now)):
        return RankReport(snapshot_id=identity, computed_at=float(now),
                          considered=len(records), written=0, changed=False,
                          rows=records)
    written = store.append_attention_snapshot(records, now=now)
    return RankReport(snapshot_id=identity, computed_at=float(now),
                      considered=len(records), written=written, changed=True,
                      rows=records)


__all__ = ["SNAPSHOT_PREFIX", "RankReport", "snapshot_id_for",
           "previous_rows", "rank_cycle"]
