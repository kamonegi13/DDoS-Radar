"""Writing conclusions down. A separate step, on purpose.

Derivation is pure; persistence is where a clock and a database appear.
Keeping them apart is what lets a tick be replayed (L2 does the same with
`resolve_settings`), and it is why the write rule below can be changed
without touching a single formula.

**The write rule, and why it is safe here and was not before.** A
conclusion is appended when it differs from the latest row of its
(scenario, type) — state or unavailable reason. No heartbeat, no run-state
machine, no duty-cycle correction. DP6 requires the ledger's unit to be a
state change (one week of per-tick writes reached 89,884 rows and 83% of
the database), and P6 O-16 forbids rebuilding the compensating mechanisms
that thinning used to require.

Both hold at once now only because the compensation is unnecessary:
chronic detection, null-zone length and trend all read L1's unthinned TL
stream, and anomaly novelty reads the signal stream. Nothing derived from
the conclusion ledger depends on how often it is written. That was the
whole point of O-16, and `test_conclusions_persistence` pins it by
asserting chronic detection is unchanged when every duplicate write is
suppressed.

ANOMALY is compared as a SET, not row by row (S1-CONC-032): one tick emits
several rows and the question "did this tick's picture change" has no
per-row answer. Multiplicity is excluded from the signature — the count of
identical entries moves with every intel item arriving or leaving, and a
signature that moves every tick is a gate that never closes.
"""
from __future__ import annotations

import json
from typing import Iterable

from v3.conclusions import vocabulary as V
from v3.conclusions.conclusion import Conclusion
from v3.ledger.records import ConclusionRecord

# One tick's anomaly rows land microseconds apart, so "the previous batch"
# has to be a time neighbourhood rather than an instant (S1-CONC-032).
BATCH_WINDOW_SEC = 5.0


def to_record(conclusion: Conclusion) -> ConclusionRecord:
    """The ledger row. `metadata` carries the disclosure with no column.

    `threshold_ref` and `calibration_status` are JSON strings because the
    ledger stores them that way; keys are sorted so the same conclusion
    always serialises to the same bytes, which is what makes a stored row
    comparable to a re-derived one.
    """
    return ConclusionRecord(
        conclusion_id=conclusion.conclusion_id,
        scenario_id=conclusion.scenario_id,
        conclusion_type=conclusion.conclusion_type,
        observed_at=conclusion.observed_at,
        confidence=conclusion.confidence,
        state=conclusion.state,
        formula_ref=conclusion.provenance.formula_ref,
        threshold_ref=json.dumps(dict(conclusion.threshold_ref),
                                 sort_keys=True, default=str,
                                 allow_nan=False, ensure_ascii=False),
        source_urls=conclusion.source_urls,
        llm_prompt_sha256=conclusion.llm_prompt_sha256,
        calibration_status=json.dumps(dict(conclusion.calibration_status),
                                      sort_keys=True, default=str,
                                      allow_nan=False, ensure_ascii=False),
        conclusion_unavailable_reason=conclusion.unavailable_reason,
        metadata=_metadata_mapping(conclusion))


def _metadata_mapping(conclusion: Conclusion) -> dict:
    payload = dict(conclusion.metadata)
    payload["input_health"] = conclusion.input_health.as_dict()
    payload["provenance"] = conclusion.provenance.as_dict()
    if conclusion.suppression is not None:
        # E-17: the suppression travels with the row it explains. A
        # suppression recorded only in a log is a suppression that is gone
        # by the time anybody asks.
        payload["suppression"] = conclusion.suppression.as_dict()
    return payload


def _health_marker(conclusion: Conclusion):
    """Which guard, if any, had something to say about this row.

    Part of the write identity, not decoration. Without it, a tick where
    every source died but the level stayed put is "unchanged" and is not
    written — leaving the ledger's most recent threat-level row asserting
    four healthy sources while the pipeline is dead. That is G-17
    reconstituted one layer down, and it hits hardest in the NP1 case the
    override exists for: an ALERTING conclusion republished from broken
    inputs looks, in the ledger, exactly like the healthy tick before it.
    """
    if conclusion.suppression is None:
        return None
    return (conclusion.suppression.guard_id, conclusion.suppression.reason,
            conclusion.suppression.overridden)


def _identity(conclusion: Conclusion) -> tuple:
    return (conclusion.state, conclusion.unavailable_reason,
            _health_marker(conclusion))


def _row_health_marker(row, metadata: dict):
    suppression = metadata.get("suppression")
    if not isinstance(suppression, dict):
        return None
    return (suppression.get("guard_id"), suppression.get("reason"),
            suppression.get("overridden"))


# S1-CONC-032 excludes MULTIPLICITY from the signature because the count
# of identical entries moves every tick. Magnitude is not multiplicity: an
# anomaly going from importance 8 to importance 100 is the whole point of
# the row. It is banded rather than exact so that recency decay (about 2%
# per 900s tick at tau=12h) cannot make the signature move every tick,
# which is the failure mode the multiplicity exclusion was protecting
# against.
IMPORTANCE_BAND = 10.0


def _band(value) -> int:
    try:
        return int(float(value) // IMPORTANCE_BAND)
    except (TypeError, ValueError):
        return -1


def _anomaly_signature(conclusions: Iterable[Conclusion]) -> frozenset:
    """S1-CONC-032's identity set, multiplicity deliberately excluded."""
    return frozenset(
        (item.scenario_id, item.state, item.unavailable_reason,
         item.metadata.get("sensor"),
         item.metadata.get("contributing_country"),
         item.metadata.get("domain"),
         _band(item.metadata.get("importance_score")),
         _health_marker(item))
        for item in conclusions)


def _row_signature(rows) -> frozenset:
    """The same identity set, read back out of stored rows.

    `sensor`, `contributing_country`, `domain`, the importance band and
    the suppression marker have no columns — they live in the metadata
    JSON — so they are parsed here. A row whose metadata will not parse
    contributes its id instead of a null tuple, because collapsing
    unreadable rows onto one signature would make a corrupt batch look
    unchanged.
    """
    signature = set()
    for row in rows:
        try:
            metadata = json.loads(row["metadata"] or "{}")
        except (TypeError, ValueError):
            signature.add(("__unparsable__", row["id"], None, None, None,
                           None, None, None))
            continue
        signature.add((row["scenario_id"], row["state"],
                       row["conclusion_unavailable_reason"],
                       metadata.get("sensor"),
                       metadata.get("contributing_country"),
                       metadata.get("domain"),
                       _band(metadata.get("importance_score")),
                       _row_health_marker(row, metadata)))
    return frozenset(signature)


def _batch_key(conclusion: Conclusion) -> float:
    return float(conclusion.metadata.get("batch_at", conclusion.observed_at))


def _previous_anomaly_batch(store, scenario_id: str, before: float) -> list:
    """Every row of the most recent earlier batch, and only that batch.

    Rows of one tick carry the same `metadata.batch_at`, so the previous
    batch is an exact grouping rather than a time neighbourhood. The
    5-second window survives only as the tolerance for rows written
    without a batch key: with a pure window, two ticks less than
    BATCH_WINDOW_SEC apart (replay, backfill) merge into one "previous
    batch" and a genuine change reads as unchanged.
    """
    anchor = store.latest_conclusion_at(before, scenario_id=scenario_id,
                                        conclusion_type=V.ANOMALY)
    if anchor is None:
        return []
    newest = anchor["observed_at"]
    rows = store.conclusions_between(
        scenario_id=scenario_id, conclusion_type=V.ANOMALY,
        start=newest - BATCH_WINDOW_SEC, end=newest)

    def key(row):
        try:
            return json.loads(row["metadata"] or "{}").get(
                "batch_at", row["observed_at"])
        except (TypeError, ValueError):
            return row["observed_at"]

    anchor_key = key(anchor)
    return [row for row in rows if key(row) == anchor_key]


def _persist_single(store, item: Conclusion, *, write_all: bool,
                    written: list, skipped: list) -> None:
    if not write_all:
        latest = store.latest_conclusion_at(
            item.observed_at, scenario_id=item.scenario_id,
            conclusion_type=item.conclusion_type)
        if latest is not None:
            try:
                metadata = json.loads(latest["metadata"] or "{}")
            except (TypeError, ValueError):
                metadata = {}
            stored = (latest["state"],
                      latest["conclusion_unavailable_reason"],
                      _row_health_marker(latest, metadata))
            if stored == _identity(item):
                skipped.append({"conclusion_type": item.conclusion_type,
                                "scenario_id": item.scenario_id,
                                "reason": "unchanged_since_latest_row"})
                return
    store.append_conclusion(to_record(item))
    written.append(item.conclusion_id)


def _persist_anomaly_batch(store, batch: list, *, write_all: bool,
                           written: list, skipped: list) -> None:
    scenario_id = batch[0].scenario_id
    if not write_all:
        previous = _previous_anomaly_batch(
            store, scenario_id, min(item.observed_at for item in batch))
        if previous and _anomaly_signature(batch) == _row_signature(previous):
            skipped.append({"conclusion_type": V.ANOMALY,
                            "scenario_id": scenario_id,
                            "reason": "identical_batch_signature",
                            "rows": len(batch)})
            return
    for item in batch:
        store.append_conclusion(to_record(item))
        written.append(item.conclusion_id)


def persist(store, conclusions: Iterable[Conclusion], *,
            write_all: bool = False) -> dict:
    """Append what changed. Returns what was written and what was not.

    Anomalies are grouped BY SCENARIO before comparison. A mixed iterable
    is legitimate — a tick scores several scenarios — and comparing the
    union against one scenario's previous batch made a second scenario's
    first-ever anomaly collapse onto the first scenario's set element and
    never reach the ledger, reported as "identical_batch_signature" for a
    scenario with no rows at all. Cross-scenario attribution is the shape
    of calibration incident #3.

    `write_all` disables the comparison entirely — used by replay
    reconstruction and by tests that want a dense series. The report is
    returned rather than logged because "we decided not to write this" is
    itself a decision, and AP4 wants decisions on the record.
    """
    produced = list(conclusions)
    written: list[str] = []
    skipped: list[dict] = []

    batches: dict = {}
    for item in produced:
        if item.conclusion_type == V.ANOMALY:
            batches.setdefault(item.scenario_id, []).append(item)
        else:
            _persist_single(store, item, write_all=write_all,
                            written=written, skipped=skipped)

    for scenario_id in sorted(batches):
        _persist_anomaly_batch(store, batches[scenario_id],
                               write_all=write_all, written=written,
                               skipped=skipped)

    return {"written": written, "skipped": skipped,
            "produced": len(produced)}


__all__ = ["persist", "to_record", "BATCH_WINDOW_SEC"]
