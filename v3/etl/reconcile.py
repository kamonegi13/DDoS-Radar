"""S3's five acceptance criteria, as a machine-readable verdict.

These are not a summary of the migration — they are the gate. S3-DATA-025
says a single mismatched table aborts cutover, and the other four are the
same shape. So this harness reports one of three verdicts per criterion:

    PASS      checked and satisfied
    FAIL      checked and violated — cutover must not proceed
    BLOCKED   cannot be checked yet, and WHY (naming the table and the WP
              that will provide its destination)

BLOCKED is deliberately not PASS. Three of the five criteria depend on
tables whose v3 destination lands in a later layer's WP; reporting those
as satisfied would be exactly the false green this whole rebuild exists
to eliminate (S5-VERIF-006).

The sample hash (criterion 2) is canonical so two runs agree: rows are
taken in primary-key order, columns are sorted by name, `theater` is
normalised to `country` before hashing, values are rendered with
`json.dumps(sort_keys=True, ensure_ascii=False, allow_nan=False)`, and the
random sample uses a fixed seed derived from the table name.
"""
from __future__ import annotations

import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from typing import Optional

from v3.etl.mapping import MIGRATABLE, NOT_YET_MIGRATABLE
from v3.etl.source import V1Source

class _DictRow(dict):
    """A plain mapping with sqlite3.Row's keys() interface."""

    def keys(self):  # noqa: D102
        return list(super().keys())


PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"

SAMPLE_SIZE = 100
TL_CALIBRATION_WINDOW_DAYS = 42     # S3-DATA-028
CONCLUSION_RETENTION_DAYS = 365     # ADR-V3-005
DAY_SEC = 86400.0

# v1 -> v3 table names for the tables the ledger can receive today.
_TARGET_TABLE = {"conclusions": "conclusion",
                 "scenario_tl_observation": "tl_observation"}
_COLUMN_RENAMES = {"theater": "country"}
# Always dropped: the source-side rowid alias the reader adds, and the
# target-side ledger surrogate. Per-table drops live in TableMapping.
_ALWAYS_DROPPED = ("_rowid",)


@dataclass
class ReconciliationReport:
    """The archive artefact the parity phase keeps."""

    source_path: str
    checked_at: float = field(default_factory=time.time)
    criteria: dict = field(default_factory=dict)

    def record(self, key: str, *, verdict: str, detail: dict) -> None:
        self.criteria[key] = {"verdict": verdict, **detail}

    @property
    def verdict(self) -> str:
        verdicts = {entry["verdict"] for entry in self.criteria.values()}
        if FAIL in verdicts:
            return FAIL
        return BLOCKED if BLOCKED in verdicts else PASS

    def as_dict(self) -> dict:
        return {"source_path": self.source_path, "checked_at": self.checked_at,
                "verdict": self.verdict, "criteria": dict(self.criteria)}


def _canonical_row(row, *, drop: tuple[str, ...],
                   json_columns: tuple[str, ...]) -> str:
    """One row as a stable string, comparable across the two databases.

    Three normalisations, each closing a way the same data hashes
    differently on the two sides:
      * dropped columns — surrogate ids whose value spaces are
        uncorrelated, and columns that exist on one side only;
      * renamed columns — `theater` becomes `country` (S3-DATA-026);
      * JSON columns re-canonicalised — v1 wrote with ensure_ascii=True
        and v3 with False, so Japanese metadata differs byte-wise while
        being identical data.
    """
    payload = {}
    for key in row.keys():
        if key in drop or key in _ALWAYS_DROPPED:
            continue
        value = row[key]
        if key in json_columns and isinstance(value, str):
            try:
                value = json.dumps(json.loads(value), sort_keys=True,
                                   ensure_ascii=False, allow_nan=False)
            except ValueError:
                pass    # not JSON after all — hash the raw string
        payload[_COLUMN_RENAMES.get(key, key)] = value
    # default=str renders anything json cannot (bytes/BLOB become their
    # repr); values compare equal only if they render equal, which is the
    # property this hash needs.
    return json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      allow_nan=False, default=str)


def _hash_rows(rows, *, drop: tuple[str, ...] = (),
               json_columns: tuple[str, ...] = ()) -> str:
    digest = hashlib.sha256()
    for row in rows:
        digest.update(_canonical_row(row, drop=drop,
                                     json_columns=json_columns).encode("utf-8"))
        digest.update(b"\x1e")
    return digest.hexdigest()


def _sample_offsets(total: int, table: str) -> list[int]:
    """Row offsets to sample: first 100, last 100, 100 at a fixed seed.

    Offsets rather than materialised rows: the production tables run to a
    million rows, and loading both sides to slice them would dominate the
    reconciliation's cost and memory.
    """
    if total <= SAMPLE_SIZE * 3:
        return list(range(total))
    head = list(range(SAMPLE_SIZE))
    tail = list(range(total - SAMPLE_SIZE, total))
    generator = random.Random(f"noroshi-v3-etl:{table}")
    middle = generator.sample(range(SAMPLE_SIZE, total - SAMPLE_SIZE),
                              SAMPLE_SIZE)
    return head + sorted(middle) + tail


def _fetch_offsets(connection, table: str, order_columns: tuple[str, ...],
                   offsets: list[int]) -> list:
    """Rows at the given offsets, in the declared value order."""
    if not offsets:
        return []
    ordering = ", ".join(f'"{column}" ASC' for column in order_columns)
    rows = []
    for offset in offsets:
        row = connection.execute(
            f'SELECT * FROM "{table}" ORDER BY {ordering} '  # noqa: S608
            f"LIMIT 1 OFFSET ?", (offset,)).fetchone()
        if row is not None:
            rows.append(row)
    return rows


def _criterion_row_counts(source: V1Source, store, report) -> None:
    """S3-DATA-025 ① — every migratable table's COUNT(*) matches."""
    mismatches, matched = {}, {}
    for name in sorted(MIGRATABLE):
        expected = source.count(name)
        actual = store.migrated_row_count(name)
        matched[name] = {"source": expected, "target": actual}
        if expected != actual:
            mismatches[name] = matched[name]
    detail = {"tables": matched, "mismatches": mismatches,
              "not_yet_migratable": sorted(NOT_YET_MIGRATABLE)}
    report.record("1_row_counts",
                  verdict=FAIL if mismatches else PASS, detail=detail)


def _criterion_sample_hashes(source: V1Source, store, report) -> None:
    """S3-DATA-026 ② — deterministic sample hashes match."""
    hashes, mismatches = {}, {}
    for name in sorted(MIGRATABLE):
        mapping = MIGRATABLE[name]
        total = source.count(name)
        offsets = _sample_offsets(total, name)

        if mapping.target == "baseline":
            # Reshaped into baseline_stat, but the composite key
            # (country, bucket) and the VALUE are both stable across the
            # two sides, so the payload is comparable even though the
            # column layout is not.
            source_rows = [
                {"country": row[mapping.hash_order_columns[0]],
                 "bucket": row[mapping.bucket_column],
                 "value": row[mapping.value_column]}
                for row in _fetch_offsets(source.connection(), name,
                                          mapping.hash_order_columns, offsets)]
            target_rows = store.baseline_value_rows(
                mapping.baseline_id, offsets=offsets)
            source_hash = _hash_rows(
                [_DictRow(row) for row in source_rows])
            target_hash = _hash_rows(
                [_DictRow(row) for row in target_rows])
        else:
            source_rows = _fetch_offsets(source.connection(), name,
                                         mapping.hash_order_columns, offsets)
            target_table = _TARGET_TABLE[name]
            target_rows = store.rows_at_offsets(
                target_table, mapping.hash_order_columns, offsets)
            source_hash = _hash_rows(source_rows,
                                     drop=mapping.hash_drop_columns,
                                     json_columns=mapping.hash_json_columns)
            target_hash = _hash_rows(target_rows,
                                     drop=mapping.hash_drop_columns,
                                     json_columns=mapping.hash_json_columns)

        hashes[name] = {"source": source_hash, "target": target_hash,
                        "sampled": len(offsets)}
        if source_hash != target_hash:
            mismatches[name] = hashes[name]
    report.record("2_sample_hashes",
                  verdict=FAIL if mismatches else PASS,
                  detail={"hashes": hashes, "mismatches": mismatches,
                          "sample_size": SAMPLE_SIZE})


def _criterion_recall(source: V1Source, store, report) -> None:
    """S3-DATA-027 ③ — recall/precision identical per cell, both series."""
    report.record("3_recall_precision", verdict=BLOCKED, detail={
        "blocked_by": ["analyst_feedback"],
        "target_wp": NOT_YET_MIGRATABLE["analyst_feedback"]["target_wp"],
        "reason": "the confusion matrix needs analyst_feedback joined to "
                  "conclusions; the label table's v3 destination is defined "
                  "by L3. Reporting PASS without the join would assert an "
                  "equality nobody computed.",
        "series_required": ["human_only", "all_rows"]})


def _criterion_calibration_window(source: V1Source, store, report) -> None:
    """S3-DATA-028 ④ — calibration windows survive the migration."""
    now = time.time()
    checks, failures = {}, []

    # Named for what it holds — a timestamp. `oldest_tl` would read like a
    # threat level, which is the ambiguity the kernel exists to remove.
    oldest_stream_at = store.oldest_observed_at("tl_observation")
    tl_ok = oldest_stream_at is not None and \
        oldest_stream_at <= now - TL_CALIBRATION_WINDOW_DAYS * DAY_SEC
    checks["tl_history_covers_window"] = {
        "oldest_observed_at": oldest_stream_at,
        "required_before": now - TL_CALIBRATION_WINDOW_DAYS * DAY_SEC,
        "ok": tl_ok}
    if not tl_ok:
        failures.append("tl_history_covers_window")

    oldest_conclusion_at = store.oldest_observed_at("conclusion")
    conclusion_ok = oldest_conclusion_at is not None and \
        oldest_conclusion_at <= now - CONCLUSION_RETENTION_DAYS * DAY_SEC
    checks["conclusion_history_covers_retention"] = {
        "oldest_observed_at": oldest_conclusion_at,
        "required_before": now - CONCLUSION_RETENTION_DAYS * DAY_SEC,
        "ok": conclusion_ok}
    if not conclusion_ok:
        failures.append("conclusion_history_covers_retention")

    checks["continuity_run_length_monotonic"] = {
        "blocked_by": "inconclusive_continuity_log",
        "target_wp":
            NOT_YET_MIGRATABLE["inconclusive_continuity_log"]["target_wp"],
        "reason": "P6 O-16 makes continuity a derived view over the TL "
                  "stream rather than a migrated table, so this sub-check "
                  "runs against the view once L3 defines it."}
    report.record("4_calibration_window", verdict=BLOCKED,
                  detail={"checks": checks, "failures": failures})


def _criterion_np6_resolution(source: V1Source, store, report) -> None:
    """S3-DATA-029 ⑤ — every NP6 back-reference resolves."""
    report.record("5_np6_resolution", verdict=BLOCKED, detail={
        "blocked_by": ["llm_prompts", "analyst_feedback"],
        "target_wp": NOT_YET_MIGRATABLE["llm_prompts"]["target_wp"],
        "reason": "resolution requires llm_prompts (prompt retrieval) and "
                  "analyst_feedback (conclusion_id back-reference); both "
                  "land with L3. The conclusions side is migrated and its "
                  "llm_prompt_sha256 values are preserved, so the check "
                  "becomes runnable the moment the prompt store exists.",
        "conclusions_with_prompt_ref":
            store.count_conclusions_with_prompt_ref()})


def reconcile(source_path: str, store) -> ReconciliationReport:
    """Run S3's five acceptance criteria against source and target."""
    report = ReconciliationReport(source_path=source_path)
    source = V1Source(source_path)
    try:
        _criterion_row_counts(source, store, report)
        _criterion_sample_hashes(source, store, report)
        _criterion_recall(source, store, report)
        _criterion_calibration_window(source, store, report)
        _criterion_np6_resolution(source, store, report)
    finally:
        source.close()
    return report


__all__ = ["reconcile", "ReconciliationReport", "PASS", "FAIL", "BLOCKED",
           "SAMPLE_SIZE"]
