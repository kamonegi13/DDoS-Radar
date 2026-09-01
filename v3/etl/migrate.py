"""The migration ETL: v1 SQLite -> the v3 ledger.

Run procedure (NOT executed by this module — the real run is a separate
step in parity setup):

  1. Take a consistent snapshot (S3-DATA-024). The live database is in the
     docker volume `noroshi_radar-data`; the repository copy is stale and
     must never be the input (S3-DATA-023).

        scripts/backup_radar_db.sh /tmp/etl-input

  2. Stop the v1 scoring loop (S3-DATA-031): a live source cannot satisfy
     acceptance criterion 1, because the row counts move while you copy.

  3. Run inside the container, source = the snapshot, target = the v3
     ledger path:

        docker exec noroshi python3 -c "
        from v3.etl import migrate
        from v3.ledger import LedgerStore
        store = LedgerStore('/app/radar/persistence/v3.db')
        print(migrate('/tmp/etl-input/radar-<stamp>.db', store,
                      wipe=True).as_dict())"

  4. Reconcile (v3.etl.reconcile) and archive the report.

Discipline: rows that cannot be migrated are never dropped silently. Each
goes to `report.quarantined` with its primary-key identity and the reason,
so "35 tables migrated" can never quietly mean "35 tables minus the rows
that did not fit" (S5-VERIF-006 applied to migration).
"""
from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from typing import Optional

from v3.etl.mapping import (COUNTRY_SOURCE_COLUMN, FORBIDDEN_JSON_KEY,
                            JSON_PAYLOAD_COLUMNS, MIGRATABLE,
                            NOT_YET_MIGRATABLE, TableMapping)
from v3.etl.source import V1Source
from v3.kernel import ThreatLevel
from v3.ledger.records import ConclusionRecord, TLObservation

DEFAULT_CHUNK_SIZE = 50_000


# The in-memory report keeps this many examples; every rejected row is
# written in full to the JSONL side file. CLAUDE.md's rule for long-running
# scripts: bounded stdout, complete side log.
QUARANTINE_EXAMPLE_LIMIT = 20


@dataclass
class ETLReport:
    """What the run did, in a form the parity phase can archive."""

    source_path: str
    started_at: float
    finished_at: float = 0.0
    migrated: dict = field(default_factory=dict)
    skipped_duplicates: dict = field(default_factory=dict)
    quarantined: list = field(default_factory=list)
    quarantined_count: int = 0
    quarantine_path: Optional[str] = None
    not_yet_migratable: dict = field(default_factory=dict)
    _quarantine_file: object = field(default=None, repr=False)

    def quarantine(self, *, table: str, identity: dict, reason: str) -> None:
        entry = {"table": table, "identity": identity, "reason": reason}
        self.quarantined_count += 1
        if len(self.quarantined) < QUARANTINE_EXAMPLE_LIMIT:
            self.quarantined.append(entry)
        if self._quarantine_file is not None:
            self._quarantine_file.write(
                json.dumps(entry, ensure_ascii=False, allow_nan=False,
                           default=str) + "\n")

    def as_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "migrated": dict(self.migrated),
            "skipped_duplicates": dict(self.skipped_duplicates),
            "quarantined_examples": list(self.quarantined),
            "quarantined_count": self.quarantined_count,
            "quarantine_path": self.quarantine_path,
            "not_yet_migratable": dict(self.not_yet_migratable),
        }


def _identity(row, mapping: TableMapping) -> dict:
    return {column: row[column] for column in mapping.identity_columns
            if column in row.keys()}


def _carries_forbidden_key(node) -> bool:
    """Is the retired key anywhere in this payload, at any depth?

    Depth-0-and-dict-only was the original test, which made the guard inert
    for every list-valued payload column (`source_urls`, `active_countries`
    are JSON arrays, so `isinstance(payload, dict)` was never true for
    them) and blind to `{"detail": {"theater": "TW"}}`. S3-DATA-022 says
    the key must not SURVIVE, not that it must not be at the top.
    """
    if isinstance(node, dict):
        return (FORBIDDEN_JSON_KEY in node
                or any(_carries_forbidden_key(value)
                       for value in node.values()))
    if isinstance(node, list):
        return any(_carries_forbidden_key(item) for item in node)
    return False


def _reject_stale_vocabulary(table: str, row) -> Optional[str]:
    """S3-DATA-022 (追加): the old key must not survive inside JSON."""
    for column in JSON_PAYLOAD_COLUMNS.get(table, ()):
        if column not in row.keys():
            continue
        raw = row[column]
        # The substring test comes first and does the work: production has
        # zero rows containing the literal, so nothing is ever parsed.
        if not isinstance(raw, str) or FORBIDDEN_JSON_KEY not in raw:
            continue
        try:
            payload = json.loads(raw)
        except ValueError:
            continue
        if _carries_forbidden_key(payload):
            return (f"{column} still carries the retired "
                    f"{FORBIDDEN_JSON_KEY!r} key; the v3 vocabulary is "
                    f"'country' (S3-DATA-022)")
    return None


def _require(row, column: str):
    """A NOT NULL source column that is NULL means the upstream constraint
    was relaxed. Coercing it to "" would hide that; quarantine surfaces it."""
    value = row[column]
    if value is None:
        raise ValueError(
            f"{column} is NULL, but S3 declares it NOT NULL — the source "
            f"constraint has been relaxed and the change needs a decision, "
            f"not a default")
    return value


def _migrate_conclusion(store, row, mapping, report, *,
                        connection=None) -> Optional[bool]:
    record = ConclusionRecord(
        conclusion_id=row["id"], scenario_id=row["scenario_id"],
        conclusion_type=row["conclusion_type"], state=row["state"],
        confidence=row["confidence"], observed_at=row["observed_at"],
        formula_ref=_require(row, "formula_ref"),
        threshold_ref=_require(row, "threshold_ref"),
        source_urls=tuple(json.loads(_require(row, "source_urls"))),
        llm_prompt_sha256=row["llm_prompt_sha256"],
        calibration_status=_require(row, "calibration_status"),
        conclusion_unavailable_reason=row["conclusion_unavailable_reason"],
        metadata=json.loads(_require(row, "metadata")))
    return store.append_conclusion(record, connection=connection)


def _migrate_tl(store, row, mapping, report, *,
                connection=None) -> Optional[bool]:
    level = None if row["tl"] is None else ThreatLevel(row["tl"])
    observation = TLObservation(
        tick_id=f"v1:{row['id']}", scenario_id=row["scenario_id"],
        observed_at=row["observed_at"],
        threat_level=level, score=row["score"],
        cyber=row["cyber"], physical=row["physical"], info=row["info"],
        convergence_bonus=row["convergence_bonus"],
        scoring_mode=_require(row, "scoring_mode"),
        active_countries=tuple(json.loads(_require(row, "active_countries"))))
    return store.append_tl(observation, connection=connection)


def _migrate_baseline(store, row, mapping, report, *,
                      connection=None) -> Optional[bool]:
    # theater -> country is a rename; the value moves untouched
    # (S3-DATA-022). sample_count stays 0 because v1 stored only the
    # aggregate — claiming 1 would assert a sample size that never existed.
    #
    # Validated here rather than trusted: this path does not go through a
    # records.py dataclass, so without these checks an empty country would
    # migrate silently while every other table quarantines it.
    country = _require(row, COUNTRY_SOURCE_COLUMN)
    if not isinstance(country, str) or not country.strip():
        raise ValueError(
            f"{COUNTRY_SOURCE_COLUMN} must be a non-empty country code, "
            f"got {country!r}")
    value = _require(row, mapping.value_column)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            f"{mapping.value_column} must be numeric, got {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric):
        raise ValueError(f"{mapping.value_column} must be finite")
    store.upsert_baseline_value(
        baseline_id=mapping.baseline_id, sensor=mapping.source_table,
        country=country.strip(), bucket=int(_require(row,
                                                     mapping.bucket_column)),
        value=numeric, connection=connection)
    return True


_MIGRATORS = {"conclusion": _migrate_conclusion,
              "tl_observation": _migrate_tl,
              "baseline": _migrate_baseline}


def migrate(source_path: str, store, *, chunk_size: int = DEFAULT_CHUNK_SIZE,
            wipe: bool = True, limit: Optional[int] = None,
            quarantine_path: Optional[str] = None) -> ETLReport:
    """Copy every migratable v1 table into the v3 ledger.

    `wipe=True` is the DEFAULT because S3-DATA-030 makes it the norm:
    "部分的な再開ではなく「全消し → 全コピー」を規範とする" — 1.25M rows is
    worth the simplicity, and a full recopy cannot inherit a subtly wrong
    partial state. **S3 rejects partial resume for the production path.**

    `wipe=False` keeps resume available for interrupted development runs
    over a large snapshot; it converges on the same state because every
    write is idempotent on its key and the checkpoint is a composite
    (ordering value, rowid) pair. Do not use it for the cutover run.

    `quarantine_path` receives one JSON object per rejected row. The report
    keeps counts plus the first few examples, so a migration that rejects
    a million rows produces a bounded object and a complete file.
    """
    report = ETLReport(source_path=source_path, started_at=time.time(),
                       quarantine_path=quarantine_path,
                       not_yet_migratable=dict(NOT_YET_MIGRATABLE))
    source = V1Source(source_path)
    quarantine_file = (open(quarantine_path, "w", encoding="utf-8")
                       if quarantine_path else None)
    report._quarantine_file = quarantine_file
    try:
        if wipe:
            store.wipe_migrated_tables()
        # S3-DATA-020: dependency stages in order; within a stage, any order.
        for stage in sorted({m.stage for m in MIGRATABLE.values()}):
            for name, mapping in sorted(MIGRATABLE.items()):
                if mapping.stage != stage:
                    continue
                _migrate_table(source, store, name, mapping, report,
                               chunk_size=chunk_size, limit=limit)
    finally:
        source.close()
        if quarantine_file is not None:
            quarantine_file.close()
        report._quarantine_file = None
    report.finished_at = time.time()
    return report


def _migrate_table(source: V1Source, store, name: str, mapping: TableMapping,
                   report: ETLReport, *, chunk_size: int,
                   limit: Optional[int]) -> None:
    """Copy one table, one transaction per chunk.

    Per-chunk rather than per-row: the documented 1M-row run would
    otherwise cost ~2M synchronous commits (one per row, plus one per
    checkpoint). Batching also makes the checkpoint atomic with exactly
    the rows it covers — a crash cannot leave the cursor ahead of the
    data it claims to have migrated.
    """
    from v3.kernel.errors import KernelError

    migrator = _MIGRATORS[mapping.target]
    report.migrated.setdefault(name, 0)
    report.skipped_duplicates.setdefault(name, 0)
    checkpoint = store.checkpoint(name)

    for chunk in source.iter_chunks(name, order_by=mapping.order_by,
                                    chunk_size=chunk_size, after=checkpoint,
                                    limit=limit):
        pending: list = []
        for row in chunk:
            stale = _reject_stale_vocabulary(name, row)
            if stale is not None:
                report.quarantine(table=name,
                                  identity=_identity(row, mapping),
                                  reason=stale)
                continue
            pending.append(row)

        last = chunk[-1]
        with store.transaction() as connection:
            for row in pending:
                try:
                    inserted = migrator(store, row, mapping, report,
                                        connection=connection)
                except (KernelError, ValueError, TypeError, KeyError) as exc:
                    report.quarantine(
                        table=name, identity=_identity(row, mapping),
                        reason=f"{type(exc).__name__}: {exc}")
                    continue
                if inserted:
                    report.migrated[name] += 1
                else:
                    report.skipped_duplicates[name] += 1
            store.set_checkpoint(name, last[mapping.order_by],
                                 last["_rowid"], connection=connection)


__all__ = ["migrate", "ETLReport", "DEFAULT_CHUNK_SIZE"]
