"""Where parity results go — and the one place a replay is allowed to write.

S5-VERIF-021 says a parity run writes nothing to production and emits only
an isolated comparison ledger. This is a SEPARATE SQLite file, not a table
inside the v3 observation ledger, and the reason is that the v3 ledger is
one of the two systems under comparison. Writing results into a file the
run is simultaneously reading as a source would recreate the shape the
clause names: `scripts/backfill_v2_ledger.py` INSERTed into `conclusions`
while replaying, which is why a later script had to exist purely to tell
replayed rows from live ones. A different file cannot develop that
problem.

S5-VERIF-030 governs the contents: a row records the verdict, and the run
it belongs to resolves to the input window, the input ledger's snapshot
identity, and both systems' code versions. Every mismatch carries enough
to reach the cause — contributions from both sides, the effective
thresholds with their config keys, both formula version tags, and the
primary source URLs. The clause forbids reporting a rate that cannot be
traced to a reason, so `record_comparison` refuses a mismatch with an
empty evidence payload.

Append-only is enforced by triggers, as in L1: a parity result that can be
edited after the fact is not evidence.
"""
from __future__ import annotations

import json
import sqlite3
import urllib.parse
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from v3.kernel import Provenance
from v3.kernel.errors import DomainError
from v3.parity.compare import MATCH, TickComparison

SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 5000

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS parity_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- S5-VERIF-030: parity_run_id resolves to the window, the input snapshot
-- and both code versions. Without these a disagreement cannot be
-- reproduced, and an unreproducible disagreement cannot be ruled on.
CREATE TABLE IF NOT EXISTS parity_run (
    parity_run_id       TEXT PRIMARY KEY,
    started_at          REAL NOT NULL,
    window_start        REAL NOT NULL,
    window_end          REAL NOT NULL,
    tick_interval_sec   REAL NOT NULL,
    input_snapshot_id   TEXT NOT NULL,
    legacy_code_version TEXT NOT NULL,
    v3_code_version     TEXT NOT NULL,
    provenance          TEXT NOT NULL DEFAULT '{}',
    notes               TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS parity_observation (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_at         REAL NOT NULL,
    parity_run_id      TEXT NOT NULL REFERENCES parity_run(parity_run_id),
    scenario_id        TEXT NOT NULL,
    conclusion_type    TEXT NOT NULL,
    tick_ts            REAL NOT NULL,
    legacy_state       TEXT,
    v3_state           TEXT,
    legacy_severity    INTEGER,
    v3_severity        INTEGER,
    is_match           INTEGER NOT NULL,
    verdict            TEXT NOT NULL,
    mismatch_direction TEXT,
    missing_side       TEXT,
    jaccard            REAL,
    evidence_json      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_parity_obs_run
    ON parity_observation (parity_run_id, scenario_id, tick_ts);
CREATE INDEX IF NOT EXISTS idx_parity_obs_mismatch
    ON parity_observation (parity_run_id, is_match, mismatch_direction);

CREATE TRIGGER IF NOT EXISTS parity_observation_no_update
BEFORE UPDATE ON parity_observation
BEGIN
    SELECT RAISE(ABORT, 'parity_observation is append-only (S5-VERIF-030)');
END;

CREATE TRIGGER IF NOT EXISTS parity_observation_no_delete
BEFORE DELETE ON parity_observation
BEGIN
    SELECT RAISE(ABORT, 'parity_observation is append-only');
END;

CREATE TRIGGER IF NOT EXISTS parity_run_no_update
BEFORE UPDATE ON parity_run
BEGIN
    SELECT RAISE(ABORT, 'parity_run is append-only (S5-VERIF-030)');
END;
"""


@dataclass(frozen=True, slots=True)
class RunIdentity:
    """What a `parity_run_id` must resolve to (S5-VERIF-030)."""

    window_start: float
    window_end: float
    tick_interval_sec: float
    input_snapshot_id: str
    legacy_code_version: str
    v3_code_version: str
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("input_snapshot_id", "legacy_code_version",
                     "v3_code_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(
                    f"RunIdentity.{name} is required: without it a "
                    f"disagreement cannot be reproduced, and S5-VERIF-030 "
                    f"requires the run to resolve to it")
        if self.window_end <= self.window_start:
            raise DomainError(
                f"parity window must move forward, got "
                f"{self.window_start} -> {self.window_end}")
        if self.tick_interval_sec <= 0:
            raise DomainError("tick_interval_sec must be positive")


@dataclass(frozen=True, slots=True)
class MismatchEvidence:
    """S5-VERIF-030's per-disagreement disclosure.

    Every field is required for a mismatch. A rate nobody can trace to a
    cause is explicitly not an acceptable output, so the ledger will not
    store one.
    """

    legacy_contributions: tuple = ()
    v3_contributions: tuple = ()
    effective_thresholds: Mapping[str, Any] = field(default_factory=dict)
    config_keys: tuple[str, ...] = ()
    legacy_formula_ref: str = ""
    v3_formula_ref: str = ""
    source_urls: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "legacy_contributions": list(self.legacy_contributions),
            "v3_contributions": list(self.v3_contributions),
            "effective_thresholds": dict(self.effective_thresholds),
            "config_keys": list(self.config_keys),
            "legacy_formula_ref": self.legacy_formula_ref,
            "v3_formula_ref": self.v3_formula_ref,
            "source_urls": list(self.source_urls),
        }

    @property
    def is_traceable(self) -> bool:
        """Enough to reach the cause, not merely to name the systems.

        Both formula tags, AND something to look at: the contributions
        either side used, or the effective thresholds. A record carrying
        only two version strings satisfies the letter of S5-VERIF-030 and
        none of its purpose — the clause forbids an output that reports a
        rate without a route to the cause.

        Empty contributions on BOTH sides is legitimate (two null-zone
        readings can disagree on their reason alone), which is why the
        thresholds satisfy the second half too.
        """
        if not (self.legacy_formula_ref and self.v3_formula_ref):
            return False
        return bool(self.legacy_contributions or self.v3_contributions
                    or self.effective_thresholds)


class ParityLedger:
    """The isolated, append-only comparison store."""

    def __init__(self, path: str):
        if not isinstance(path, str) or not path.strip():
            raise DomainError(
                "ParityLedger needs an explicit path: it must be a "
                "different file from the observation ledger it compares "
                "against (S5-VERIF-021)")
        self._path = str(Path(path).expanduser())
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path, isolation_level=None)
        try:
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            self._conn.executescript(SCHEMA_SQL)
            self._conn.execute(
                "INSERT INTO parity_meta (key, value) VALUES ('version', ?) "
                "ON CONFLICT (key) DO NOTHING", (str(SCHEMA_VERSION),))
            self._read_conn: Optional[sqlite3.Connection] = None
        except BaseException:
            self._conn.close()
            raise

    def _read_connection(self) -> sqlite3.Connection:
        """A mode=ro connection for every query path.

        The URI is quoted: an unquoted path containing '?' or '#' silently
        becomes a different filename, and this is the fourth place in the
        codebase that lesson applies. Read paths that physically cannot
        write are also what lets a query run against a parity ledger while
        a run is appending to it.
        """
        if self._read_conn is None:
            uri = f"file:{urllib.parse.quote(self._path)}?mode=ro"
            self._read_conn = sqlite3.connect(uri, uri=True)
            self._read_conn.row_factory = sqlite3.Row
            self._read_conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        return self._read_conn

    @property
    def path(self) -> str:
        return self._path

    def close(self) -> None:
        if self._read_conn is not None:
            self._read_conn.close()
            self._read_conn = None
        self._conn.close()

    def __enter__(self) -> "ParityLedger":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── runs ────────────────────────────────────────────────────────────
    def open_run(self, identity: RunIdentity, *, started_at: float,
                 provenance: Optional[Provenance] = None) -> str:
        """Register a run and return its id."""
        if not isinstance(identity, RunIdentity):
            raise DomainError(
                f"open_run needs a RunIdentity, got {type(identity).__name__}")
        run_id = uuid.uuid4().hex
        disclosure = json.dumps(
            provenance.as_dict() if provenance else {}, sort_keys=True,
            allow_nan=False, ensure_ascii=False)
        self._conn.execute(
            "INSERT INTO parity_run (parity_run_id, started_at, "
            "window_start, window_end, tick_interval_sec, input_snapshot_id, "
            "legacy_code_version, v3_code_version, provenance, notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (run_id, started_at, identity.window_start, identity.window_end,
             identity.tick_interval_sec, identity.input_snapshot_id,
             identity.legacy_code_version, identity.v3_code_version,
             disclosure, identity.notes))
        return run_id

    def run(self, run_id: str) -> Optional[dict]:
        row = self._read_connection().execute(
            "SELECT * FROM parity_run WHERE parity_run_id = ?",
            (run_id,)).fetchone()
        return dict(row) if row else None

    # ── observations ────────────────────────────────────────────────────
    def _row_for(self, run_id: str, comparison: TickComparison, *,
                 sampled_at: float,
                 evidence: Optional[MismatchEvidence]) -> tuple:
        """Validate one verdict and render it as an INSERT row."""
        is_match = comparison.verdict == MATCH
        if not is_match and comparison.missing_side is None:
            if evidence is None or not evidence.is_traceable:
                raise DomainError(
                    f"a disagreement at {comparison.key} must carry evidence "
                    f"naming both formula version tags and something to "
                    f"inspect. S5-VERIF-030 forbids an output that reports a "
                    f"rate without a route to the cause.")
        payload = {"comparison": comparison.as_dict()}
        if evidence is not None:
            payload["evidence"] = evidence.as_dict()
        return (sampled_at, run_id, comparison.key.scenario_id,
                comparison.key.conclusion_type, comparison.key.tick_ts,
                comparison.legacy_state, comparison.v3_state,
                comparison.legacy_severity, comparison.v3_severity,
                1 if is_match else 0, comparison.verdict, comparison.direction,
                comparison.missing_side, comparison.jaccard,
                json.dumps(payload, sort_keys=True, allow_nan=False,
                           ensure_ascii=False, default=str))

    _INSERT = (
        "INSERT INTO parity_observation (sampled_at, parity_run_id, "
        "scenario_id, conclusion_type, tick_ts, legacy_state, v3_state, "
        "legacy_severity, v3_severity, is_match, verdict, "
        "mismatch_direction, missing_side, jaccard, evidence_json) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")

    def record_comparison(self, run_id: str, comparison: TickComparison, *,
                          sampled_at: float,
                          evidence: Optional[MismatchEvidence] = None) -> None:
        """Append one verdict. A mismatch must arrive with its evidence.

        Convenient for a handful of rows. A whole run goes through
        `record_comparisons`, which does not re-validate the run per row
        and does not autocommit per row.
        """
        if self.run(run_id) is None:
            raise DomainError(
                f"unknown parity_run_id {run_id!r}: a verdict must belong to "
                f"a run that resolves to a window and code versions")
        self._conn.execute(self._INSERT, self._row_for(
            run_id, comparison, sampled_at=sampled_at, evidence=evidence))

    def record_comparisons(self, run_id: str, entries: Iterable, *,
                           sampled_at: float) -> int:
        """Append a whole run's verdicts in ONE transaction.

        `entries` is an iterable of `(comparison, evidence)` pairs. A
        30-day window at a 120 s tick is ~21,600 verdicts per scenario;
        the per-row path would re-read `parity_run` and fsync once each,
        turning a comparison into an I/O benchmark.

        Every row is validated and rendered BEFORE the transaction opens,
        so a bad verdict aborts the batch without leaving a partial run
        behind — an append-only ledger cannot be tidied up afterwards.
        """
        if self.run(run_id) is None:
            raise DomainError(
                f"unknown parity_run_id {run_id!r}: a verdict must belong to "
                f"a run that resolves to a window and code versions")
        rows = [self._row_for(run_id, comparison, sampled_at=sampled_at,
                              evidence=evidence)
                for comparison, evidence in entries]
        if not rows:
            return 0
        # BEGIN IMMEDIATE: take the write lock up front rather than
        # discovering a competing writer partway through the batch.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.executemany(self._INSERT, rows)
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")
        return len(rows)

    def observations(self, run_id: str, *, only_mismatches: bool = False
                     ) -> list[dict]:
        query = ("SELECT * FROM parity_observation WHERE parity_run_id = ?")
        if only_mismatches:
            query += " AND is_match = 0"
        query += " ORDER BY tick_ts ASC, id ASC"
        return [dict(row) for row in
                self._read_connection().execute(query, (run_id,)).fetchall()]

    def count(self, run_id: str) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM parity_observation WHERE parity_run_id = ?",
            (run_id,)).fetchone()[0])

    def evidence_for(self, observation_id: int) -> dict:
        row = self._read_connection().execute(
            "SELECT evidence_json FROM parity_observation WHERE id = ?",
            (observation_id,)).fetchone()
        if row is None:
            raise DomainError(f"no parity observation {observation_id}")
        return json.loads(row["evidence_json"])


__all__ = ["ParityLedger", "RunIdentity", "MismatchEvidence", "SCHEMA_SQL",
           "SCHEMA_VERSION"]
