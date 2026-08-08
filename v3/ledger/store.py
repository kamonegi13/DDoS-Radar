"""LedgerStore — L1's single jurisdiction for v3 persistent state.

One SQLite file holds everything v3 stores. A-09 found the current system
had grown a second store (`convergence_snapshots.db`) with its own backup
and schema-management blind spots; "single jurisdiction" is the rule that
prevents the second one existing at all.

The path is injected by the caller and never defaulted, never read from
the environment. v3 shadow-runs beside v1 until cutover, so which file
this is is a deployment decision, and a hardcoded default is how two
processes end up disagreeing about which database is real.

Three disciplines are enforced here rather than documented:

  append-only   database triggers reject UPDATE and DELETE on the
                observation tables; the retention job is the one writer
                allowed to delete, and it says so explicitly.
  no read side effects  every read goes through a read-only connection,
                so F-05 (a read that updated running statistics, making
                scoring ticks non-idempotent) cannot be reintroduced by
                an accidental write in a query path.
  idempotence   (tick_id, ...) uniqueness with INSERT OR IGNORE, so
                replaying a tick is a no-op rather than a corruption
                (S5-VERIF-019). A same-key row with DIFFERENT content is
                not a replay and raises: it means the producer is not
                deterministic, which parity depends on.

Concurrency: safe for many greenlets or threads in ONE process. Writers
serialise on an in-process lock, because sqlite permits a single writer
and the baseline fold is a read-modify-write that must not interleave.
Two processes writing the same file is out of scope — v3 has one writer
by design, and `busy_timeout` only softens the symptom.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Optional

from v3.kernel import ThreatLevel, Window
from v3.kernel.errors import DomainError
from v3.ledger import schema as schema_module
from v3.ledger.records import (ConclusionRecord, SignalObservation,
                               TLObservation)

log = logging.getLogger("v3.ledger")

_PRUNE_FLAG = "pruning"
# Both connections wait rather than failing instantly when the other holds
# the write lock. WAL keeps readers unblocked; this covers the window when
# a writer is committing.
BUSY_TIMEOUT_MS = 5000


def _require_same_tick(stored, incoming: dict, *, tick_id: str,
                       kind: str) -> None:
    """A same-key re-record must carry the same content.

    S5-VERIF-019 asks that replaying a tick be a no-op. A row with the
    same key and DIFFERENT content is not a replay — it means the caller
    produced two different answers for one tick, which is exactly the
    non-determinism parity depends on not existing. Dropping it silently
    would hide that.
    """
    if stored is None:
        return
    for field, value in incoming.items():
        existing = stored[field]
        if existing is None and value is None:
            continue
        if existing is None or value is None or existing != value:
            raise DomainError(
                f"{kind} tick {tick_id!r} was already recorded with "
                f"{field}={existing!r}, but is being re-recorded with "
                f"{field}={value!r}. A replayed tick must be identical; a "
                f"divergent one means the producer is not deterministic "
                f"(S5-VERIF-019).")


class LedgerStore:
    """The v3 observation ledger, baselines, and conclusion storage."""

    def __init__(self, path: str):
        if not isinstance(path, str) or not path.strip():
            raise ValueError(
                "LedgerStore needs an explicit database path: v3 runs beside "
                "v1 until cutover, so the file is a deployment decision and "
                "a default would let two processes disagree about which "
                "database is real.")
        self._path = str(Path(path).expanduser())
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: transactions are explicit here, because the
        # retention job must set a flag, delete, and clear the flag as ONE
        # unit. Implicit transaction handling cannot express that.
        self._conn = sqlite3.connect(self._path, isolation_level=None)
        try:
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            # WAL + NORMAL: fsync at checkpoints rather than at every
            # commit. Safe against process crash (WAL replays); the
            # exposure is a power loss losing the last transactions, which
            # for an append-only observation ledger costs one tick, not
            # integrity. FULL would make the 1M-row migration fsync-bound.
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._read_conn: Optional[sqlite3.Connection] = None
            # Writes are serialised in-process: sqlite allows one writer,
            # and the fold job is a read-modify-write that must not
            # interleave. Multi-greenlet-safe by this lock; single process.
            self._lock = threading.Lock()
            self._apply_schema()
        except BaseException:
            self._conn.close()
            raise

    # ── lifecycle ───────────────────────────────────────────────────────
    @property
    def path(self) -> str:
        return self._path

    def _apply_schema(self) -> None:
        self._conn.executescript(schema_module.SCHEMA_SQL)
        self._migrate()
        # Defence in depth. The prune gate is opened and closed inside one
        # transaction, so a durable flag here can only mean a process died
        # mid-prune. Leaving it would disable the append-only triggers
        # silently, which is the worst possible failure of this layer.
        stuck = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key = ?",
            (_PRUNE_FLAG,)).fetchone()
        if stuck is not None:
            log.warning(
                "v3 ledger: clearing a stale prune flag at %s — a previous "
                "process died mid-retention and left the append-only "
                "triggers disabled", self._path)
            self._conn.execute("DELETE FROM schema_meta WHERE key = ?",
                               (_PRUNE_FLAG,))

    def _migrate(self) -> None:
        """Apply every migration above the recorded version, in order.

        A fresh store records no version, which reads as 0 and therefore
        takes the full list — so the upgrade path is exercised on every
        new store rather than only on the one deployment that happens to
        be old. That is the whole point of having a list at all.

        Each migration runs inside one transaction with the version bump,
        so a store is never left claiming a version it did not reach.
        """
        current = self.schema_version()
        if current > schema_module.SCHEMA_VERSION:
            raise RuntimeError(
                f"v3 ledger at {self._path} reports schema v{current}, newer "
                f"than this code's v{schema_module.SCHEMA_VERSION}. Refusing "
                f"to open: downgrading a store is not something a forward "
                f"migration list can reason about.")
        for migration in schema_module.MIGRATIONS:
            if migration.version <= current:
                continue
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in migration.statements:
                    self._conn.execute(statement)
                self._conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES "
                    "('version', ?) ON CONFLICT (key) DO UPDATE SET value = ?",
                    (str(migration.version), str(migration.version)))
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
            log.info("v3 ledger: applied schema migration v%d (%s)",
                     migration.version, migration.rationale)
        if not schema_module.MIGRATIONS:
            self._conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('version', ?) "
                "ON CONFLICT (key) DO NOTHING",
                (str(schema_module.SCHEMA_VERSION),))

    def schema_version(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'").fetchone()
        return int(row["value"]) if row else 0

    def close(self) -> None:
        if self._read_conn is not None:
            self._read_conn.close()
            self._read_conn = None
        self._conn.close()

    def _connection(self) -> sqlite3.Connection:
        """The writing connection. Internal — writes go through the API."""
        return self._conn

    def _read_connection(self) -> sqlite3.Connection:
        """A read-only handle: a query path cannot write even by mistake."""
        if self._read_conn is None:
            # quote(): an unquoted '#' or '?' truncates the URI, so the
            # read connection silently opens a DIFFERENT (empty) database
            # while writes keep succeeding — every read returns nothing and
            # nothing reports why. Third occurrence of this lesson here.
            uri = f"file:{urllib.parse.quote(self._path)}?mode=ro"
            self._read_conn = sqlite3.connect(uri, uri=True)
            self._read_conn.row_factory = sqlite3.Row
            self._read_conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        return self._read_conn

    @contextmanager
    def _maybe_transaction(self, connection=None):
        """Join the caller's transaction, or open one.

        The ETL batches a whole chunk into one transaction and passes it
        down; everything else gets its own. The lock is held by whoever
        opened the transaction, and it is not reentrant, so a passed-in
        connection must never re-acquire it.
        """
        if connection is not None:
            yield connection
            return
        with self.transaction() as own:
            yield own

    @contextmanager
    def transaction(self):
        """One serialised write transaction. Rolls back on any exception.

        Held for the whole unit of work, so a partially applied prune or
        fold cannot survive a failure.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    # ── signal ledger (append-only) ─────────────────────────────────────
    def append_signal(self, observation: SignalObservation,
                      now: Optional[float] = None, *, connection=None
                      ) -> bool:
        """Record one signal. Returns False when the tick already exists.

        The evidence is freshness-checked here, at the boundary: a stale
        observation must not become a stored fact that later reads trust
        (B-03). Replay passes its own `now`, so the horizon is evaluated
        at the replayed instant rather than against the wall clock.
        """
        if not isinstance(observation, SignalObservation):
            raise TypeError(
                f"append_signal expects a SignalObservation, got "
                f"{type(observation).__name__}")
        ts = time.time() if now is None else now
        payload = observation.evidence.fresh(now=ts)   # raises when stale

        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO signal_observation "
                "(tick_id, sensor, signal_source, domain, country, "
                " observed_at, recorded_at, raw_score, status, flags, "
                " confidence, suppressed, suppress_reason, evidence_url, "
                " payload, freshness_horizon_sec) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (observation.tick_id, observation.sensor,
                 observation.signal_source, observation.domain,
                 observation.country, observation.observed_at, ts,
                 observation.raw_score, observation.status,
                 observation.flags_json(), observation.confidence,
                 int(observation.suppressed), observation.suppress_reason,
                 observation.evidence_url,
                 json.dumps(payload, sort_keys=True, default=str,
                            allow_nan=False, ensure_ascii=False),
                 observation.evidence.freshness_horizon_sec))
            if cursor.rowcount > 0:
                return True
            stored = conn.execute(
                "SELECT raw_score, status, observed_at FROM "
                "signal_observation WHERE tick_id = ? AND sensor = ? "
                "AND signal_source = ? AND country = ?",
                (observation.tick_id, observation.sensor,
                 observation.signal_source, observation.country)).fetchone()
            _require_same_tick(stored, {
                "raw_score": observation.raw_score,
                "status": observation.status,
                "observed_at": observation.observed_at,
            }, tick_id=observation.tick_id, kind="signal")
        return False

    def latest_signal_at(self, at_ts: float, *, sensor: str, country: str,
                         signal_source: Optional[str] = None
                         ) -> Optional[dict]:
        """S5-VERIF-017's primitive: the row in force at `at_ts`.

        This is what replay reads. Ordering is by `observed_at`, never by
        insert order, so a late-arriving row cannot change what an earlier
        instant looked like.
        """
        query = ("SELECT * FROM signal_observation "
                 "WHERE sensor = ? AND country = ? AND observed_at <= ?")
        params: list = [sensor, country, at_ts]
        if signal_source is not None:
            query += " AND signal_source = ?"
            params.append(signal_source)
        query += " ORDER BY observed_at DESC, id DESC LIMIT 1"
        row = self._read_connection().execute(query, params).fetchone()
        return dict(row) if row else None

    def signals_between(self, start: float, end: float, *,
                        sensor: Optional[str] = None,
                        country: Optional[str] = None) -> list[dict]:
        query = ("SELECT * FROM signal_observation "
                 "WHERE observed_at >= ? AND observed_at <= ?")
        params: list = [start, end]
        if sensor is not None:
            query += " AND sensor = ?"
            params.append(sensor)
        if country is not None:
            query += " AND country = ?"
            params.append(country)
        query += " ORDER BY observed_at ASC, id ASC"
        return [dict(row) for row in
                self._read_connection().execute(query, params).fetchall()]

    def count_signal_source_observations(self, *, signal_source: str,
                                         start: float, end: float,
                                         countries: tuple = (),
                                         status: Optional[str] = None) -> int:
        """How often one signal source was seen in a window (S1-CONC-023).

        A COUNT rather than a materialised list: L3 asks this once per
        emitted anomaly, and loading a day of rows to call len() on them
        is the shape that makes a derived view look expensive enough to
        justify a cached counter — which is the state O-16 removes.

        `countries` scopes the count to a scenario's participants; empty
        means unscoped. `status` scopes it to one reading status, which
        L3's novelty term needs: this table holds one row per POLL, not
        per firing, so an unfiltered count says a healthy quiet sensor
        repeated itself ninety-six times today.
        """
        query = ("SELECT COUNT(*) FROM signal_observation "
                 "WHERE signal_source = ? AND observed_at >= ? "
                 "AND observed_at <= ?")
        params: list = [signal_source, start, end]
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if countries:
            placeholders = ",".join("?" for _ in countries)
            query += f" AND country IN ({placeholders})"  # noqa: S608
            params.extend(countries)
        return int(self._read_connection().execute(query, params).fetchone()[0])

    def count_signals(self) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM signal_observation").fetchone()[0])

    def max_freshness_horizon(self) -> Optional[float]:
        """The longest freshness horizon any stored signal declares.

        Replay needs this to know how far BEFORE a window it must read.
        Deriving the answer from rows inside the window is circular: a
        sensor whose last observation predates the window contributes no
        row to look at, so its horizon never enters the maximum, so the
        lookback is too short to load it, so it stays invisible. A slow
        sensor is exactly the one that suffers, and it suffers identically
        on both sides of a parity comparison — a shared blind spot that
        raises the agreement rate while hiding a detection gap.

        A whole-table MAX() is cheap and cannot be circular.
        """
        row = self._read_connection().execute(
            "SELECT MAX(freshness_horizon_sec) FROM signal_observation"
        ).fetchone()
        return None if row is None or row[0] is None else float(row[0])

    # ── TL stream (P6 O-16: one unthinned stream) ───────────────────────
    def append_tl(self, observation: TLObservation, *,
                  connection=None) -> bool:
        """Append one TL tick. Every tick, including repeats and null zone."""
        if not isinstance(observation, TLObservation):
            raise TypeError(
                f"append_tl expects a TLObservation, got "
                f"{type(observation).__name__}")
        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO tl_observation "
                "(tick_id, scenario_id, observed_at, tl, score, cyber, "
                " physical, info, convergence_bonus, scoring_mode, "
                " active_countries) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (observation.tick_id, observation.scenario_id,
                 observation.observed_at, observation.tl_value,
                 observation.score, observation.cyber, observation.physical,
                 observation.info, observation.convergence_bonus,
                 observation.scoring_mode, observation.countries_json()))
            if cursor.rowcount > 0:
                return True
            stored = conn.execute(
                "SELECT tl, score, observed_at FROM tl_observation "
                "WHERE tick_id = ? AND scenario_id = ?",
                (observation.tick_id, observation.scenario_id)).fetchone()
            _require_same_tick(stored, {
                "tl": observation.tl_value,
                "score": observation.score,
                "observed_at": observation.observed_at,
            }, tick_id=observation.tick_id, kind="TL")
        return False

    @staticmethod
    def _tl_row(row: sqlite3.Row) -> dict:
        record = dict(row)
        record["threat_level"] = (None if record["tl"] is None
                                  else ThreatLevel(record["tl"]))
        return record

    def latest_tl_at(self, at_ts: float, *, scenario_id: str
                     ) -> Optional[dict]:
        row = self._read_connection().execute(
            "SELECT * FROM tl_observation WHERE scenario_id = ? "
            "AND observed_at <= ? ORDER BY observed_at DESC, id DESC LIMIT 1",
            (scenario_id, at_ts)).fetchone()
        return self._tl_row(row) if row else None

    def tl_between(self, scenario_id: str, start: float,
                   end: float) -> list[dict]:
        rows = self._read_connection().execute(
            "SELECT * FROM tl_observation WHERE scenario_id = ? "
            "AND observed_at >= ? AND observed_at <= ? "
            "ORDER BY observed_at ASC, id ASC",
            (scenario_id, start, end)).fetchall()
        return [self._tl_row(row) for row in rows]

    def count_tl(self) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM tl_observation").fetchone()[0])

    # ── conclusions (storage + retention only; L3 owns semantics) ───────
    def append_conclusion(self, record: ConclusionRecord, *,
                          connection=None) -> bool:
        """Append one conclusion. L1 owns storage and retention only.

        Note for WP-3.1: unlike signals and TL ticks, conclusions have no
        tick_id here — `id` is the whole key, so a re-derived conclusion
        with a new id is a new row. Whether replay should be idempotent at
        the conclusion level is L3's decision, not storage's.
        """
        if not isinstance(record, ConclusionRecord):
            raise TypeError(
                f"append_conclusion expects a ConclusionRecord, got "
                f"{type(record).__name__}: a kwargs bag accepts a typo "
                f"silently and stores a row missing the field you set")
        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO conclusion "
                "(id, scenario_id, conclusion_type, state, confidence, "
                " observed_at, formula_ref, threshold_ref, source_urls, "
                " llm_prompt_sha256, calibration_status, "
                " conclusion_unavailable_reason, metadata) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.conclusion_id, record.scenario_id,
                 record.conclusion_type, record.state, record.confidence,
                 record.observed_at, record.formula_ref, record.threshold_ref,
                 record.source_urls_json(), record.llm_prompt_sha256,
                 record.calibration_status,
                 record.conclusion_unavailable_reason,
                 record.metadata_json()))
            return cursor.rowcount > 0

    def latest_conclusion_at(self, at_ts: float, *, scenario_id: str,
                             conclusion_type: str) -> Optional[dict]:
        row = self._read_connection().execute(
            "SELECT * FROM conclusion WHERE scenario_id = ? "
            "AND conclusion_type = ? AND observed_at <= ? "
            "ORDER BY observed_at DESC, id DESC LIMIT 1",
            (scenario_id, conclusion_type, at_ts)).fetchone()
        return dict(row) if row else None

    def conclusions_between(self, *, scenario_id: str, conclusion_type: str,
                            start: float, end: float) -> list:
        """One type's rows across a window, oldest first.

        L3 uses this to compare a whole tick's anomaly batch against the
        previous one (S1-CONC-032): a several-row conclusion type has no
        single latest row to compare against.
        """
        rows = self._read_connection().execute(
            "SELECT * FROM conclusion WHERE scenario_id = ? "
            "AND conclusion_type = ? AND observed_at >= ? "
            "AND observed_at <= ? ORDER BY observed_at ASC, id ASC",
            (scenario_id, conclusion_type, start, end)).fetchall()
        return [dict(row) for row in rows]

    def count_conclusions(self) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM conclusion").fetchone()[0])

    # ── baselines (explicit job only) ───────────────────────────────────
    def update_baselines(self, observations: Iterable[SignalObservation], *,
                         baseline_id: str, window: Optional[Window] = None,
                         now: Optional[float] = None) -> int:
        """Fold observations into a persistent baseline. The ONLY writer.

        Caller-driven by design: the statistics update is a separate,
        explicit stage from reading (S5-VERIF-019). Nothing in a read path
        calls this, and this never reads the ledger to decide what to fold
        in — the caller passes the observations.
        """
        from v3.ledger.baselines import fold_observations
        return fold_observations(self, observations, baseline_id=baseline_id,
                                 window=window, now=now)

    def read_baseline(self, baseline_id: str, *, sensor: str, country: str,
                      bucket: int = 0) -> Optional[dict]:
        """Read a baseline. Never updates it — the connection is read-only.

        The returned `sample_count` / `mean` / `m2` are CUMULATIVE over
        every observation ever folded in; `window_days` and `cadence_sec`
        say what window the baseline was initialised for, not that it is a
        rolling window over that span (see v3.ledger.baselines).

        `bucket` exists for hour-of-day / day-of-week baselines that L2
        will need; nothing writes a non-zero bucket yet.
        """
        row = self._read_connection().execute(
            "SELECT * FROM baseline_stat WHERE baseline_id = ? AND sensor = ? "
            "AND country = ? AND bucket = ?",
            (baseline_id, sensor, country, bucket)).fetchone()
        return dict(row) if row else None

    # ── migration support (WP-2.3) ──────────────────────────────────────
    #
    # Checkpoints live in the TARGET store: the source is opened read-only
    # and must stay byte-identical, so progress state cannot be written
    # there even in principle (S3-DATA-023).
    def checkpoint(self, table: str) -> Optional[tuple]:
        """Last migrated (ordering value, rowid) pair for `table`, or None.

        A pair, not a scalar: the ordering column is not unique, so a
        scalar cursor cannot resume inside a tie group without skipping
        the rest of it.
        """
        row = self._read_connection().execute(
            "SELECT value FROM schema_meta WHERE key = ?",
            (f"etl_checkpoint:{table}",)).fetchone()
        if row is None:
            return None
        payload = json.loads(row["value"])
        return (payload[0], int(payload[1]))

    def set_checkpoint(self, table: str, value, rowid: int, *,
                       connection=None) -> None:
        """Record the composite cursor.

        `connection` lets the ETL write the checkpoint inside the same
        transaction as the chunk it covers, so the two can never disagree.
        """
        payload = json.dumps([value, int(rowid)], allow_nan=False,
                             ensure_ascii=False)
        statement = ("INSERT INTO schema_meta (key, value) VALUES (?, ?) "
                     "ON CONFLICT (key) DO UPDATE SET value = excluded.value")
        params = (f"etl_checkpoint:{table}", payload)
        if connection is not None:
            connection.execute(statement, params)
            return
        with self.transaction() as own:
            own.execute(statement, params)

    def upsert_baseline_value(self, *, baseline_id: str, sensor: str,
                              country: str, bucket: int, value: float,
                              connection=None) -> None:
        """Store a v1 aggregate baseline value.

        `sample_count` stays 0 on purpose: v1 stored only the aggregate and
        never recorded how many samples produced it. Writing 1 would assert
        a sample size that never existed, and a later consumer would have
        no way to tell the difference.
        """
        with self._maybe_transaction(connection) as conn:
            conn.execute(
                "INSERT INTO baseline_stat (baseline_id, sensor, country, "
                " bucket, sample_count, mean, m2, updated_at) "
                "VALUES (?,?,?,?,0,?,0.0,?) "
                "ON CONFLICT (baseline_id, sensor, country, bucket) "
                "DO UPDATE SET mean = excluded.mean, "
                "  updated_at = excluded.updated_at",
                (baseline_id, sensor, country, int(bucket), float(value),
                 time.time()))

    # Reconciliation support (WP-2.3). Read-only by construction.
    _MIGRATED_TABLE = {"conclusions": "conclusion",
                       "scenario_tl_observation": "tl_observation",
                       "hod_baseline": ("baseline_stat", "hod"),
                       "checkhost_hod": ("baseline_stat", "checkhost_hod"),
                       "bgp_hod": ("baseline_stat", "bgp_hod"),
                       "gdelt_dow": ("baseline_stat", "gdelt_dow")}

    def migrated_row_count(self, source_table: str) -> int:
        """Rows in the v3 destination of a v1 table (acceptance criterion 1)."""
        target = self._MIGRATED_TABLE.get(source_table)
        if target is None:
            return 0
        if isinstance(target, tuple):
            table, baseline_id = target
            return int(self._read_connection().execute(
                f'SELECT COUNT(*) FROM "{table}" '  # noqa: S608 - fixed map
                f"WHERE baseline_id = ?", (baseline_id,)).fetchone()[0])
        return int(self._read_connection().execute(
            f'SELECT COUNT(*) FROM "{target}"').fetchone()[0])  # noqa: S608

    def rows_at_offsets(self, table: str, order_columns: tuple,
                        offsets: list) -> list:
        """Rows at given offsets in a declared value order (criterion 2).

        Offsets rather than a full materialisation: the migrated tables
        run to a million rows.
        """
        if table not in ("conclusion", "tl_observation", "signal_observation"):
            raise ValueError(f"unknown ledger table {table!r}")
        ordering = ", ".join(f'"{column}" ASC' for column in order_columns)
        rows = []
        for offset in offsets:
            row = self._read_connection().execute(
                f'SELECT * FROM "{table}" ORDER BY {ordering} '  # noqa: S608
                f"LIMIT 1 OFFSET ?", (offset,)).fetchone()
            if row is not None:
                rows.append(row)
        return rows

    def baseline_value_rows(self, baseline_id: str, *, offsets: list) -> list:
        """(country, bucket, value) triples for a migrated baseline."""
        rows = []
        for offset in offsets:
            row = self._read_connection().execute(
                "SELECT country, bucket, mean AS value FROM baseline_stat "
                "WHERE baseline_id = ? ORDER BY country ASC, bucket ASC "
                "LIMIT 1 OFFSET ?", (baseline_id, offset)).fetchone()
            if row is not None:
                rows.append({"country": row["country"],
                             "bucket": row["bucket"], "value": row["value"]})
        return rows

    def oldest_observed_at(self, table: str) -> Optional[float]:
        if table not in ("conclusion", "tl_observation", "signal_observation"):
            raise ValueError(f"unknown ledger table {table!r}")
        row = self._read_connection().execute(
            f'SELECT MIN(observed_at) FROM "{table}"').fetchone()  # noqa: S608
        return None if row[0] is None else float(row[0])

    def count_conclusions_with_prompt_ref(self) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM conclusion "
            "WHERE llm_prompt_sha256 IS NOT NULL").fetchone()[0])

    def wipe_migrated_tables(self) -> dict:
        """Empty the migration targets (S3-DATA-030's wipe-then-copy norm)."""
        emptied: dict = {}
        with self.transaction() as connection:
            self._set_prune_flag(connection, True)
            for table in ("conclusion", "tl_observation", "baseline_stat"):
                cursor = connection.execute(
                    f'DELETE FROM "{table}"')  # noqa: S608 - fixed literal
                emptied[table] = cursor.rowcount
            connection.execute(
                "DELETE FROM schema_meta WHERE key LIKE 'etl_checkpoint:%'")
            self._set_prune_flag(connection, False)
        return emptied

    # ── deletion (two sanctioned deleters, both explicit) ───────────────
    #   prune_expired         retention, driven by the policy registry
    #   wipe_migrated_tables  S3-DATA-030's wipe-then-copy migration norm
    # Both open the append-only trigger gate inside one transaction and
    # close it in the same one.
    def prune_expired(self, now: Optional[float] = None) -> dict:
        """Apply every retention policy in the registry. Returns row counts."""
        from v3.ledger.retention import prune
        return prune(self, now=now)

    @staticmethod
    def _set_prune_flag(connection, enabled: bool) -> None:
        """Open/close the trigger gate, inside the caller's transaction.

        Takes the connection rather than using self._conn so it cannot be
        called outside a transaction by accident: opening the gate and
        closing it must be the same atomic unit as the deletes between.
        """
        if enabled:
            connection.execute(
                "INSERT INTO schema_meta (key, value) VALUES (?, '1') "
                "ON CONFLICT (key) DO UPDATE SET value = '1'", (_PRUNE_FLAG,))
        else:
            connection.execute("DELETE FROM schema_meta WHERE key = ?",
                               (_PRUNE_FLAG,))


__all__ = ["LedgerStore"]
