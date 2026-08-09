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

BOTH handles are per-thread, and the reason is not symmetry: sqlite3
refuses a connection used off its creating thread, this store is built on
the gunicorn worker's thread, and `v3/runtime/loop.py` runs the tick — the
only writer — on a thread of its own. `v3/ledger/store_connections.py`
carries the handles and the whole argument for why several write handles
are safe when one lock is what serialises them.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable, Optional

from v3.kernel import ThreatLevel, Window
from v3.kernel.errors import DomainError
from v3.ledger import schema as schema_module
from v3.ledger.records import (CommandRecord, ConclusionRecord,
                               SignalObservation, TLObservation)
from v3.ledger.store_attention import AttentionLedgerMixin
from v3.ledger.store_calibration import CalibrationLedgerMixin
from v3.ledger.store_connections import ConnectionMixin
from v3.ledger.store_connections import open_write as _open_write
from v3.ledger.store_entities import EntityStateMixin
from v3.ledger.store_migration import MigrationSupportMixin

log = logging.getLogger("v3.ledger")

_PRUNE_FLAG = "pruning"


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


def _command_row(row) -> dict:
    """One `command_record` row with its JSON columns already decoded.

    Decoded HERE rather than by each caller, because the fold compares a
    stored `after` against a freshly computed one: a caller that forgot to
    decode would compare a string to a value, find them unequal, and
    conclude the write had not taken effect.
    """
    decoded = dict(row)
    for column, key in (("before_json", "before"), ("after_json", "after"),
                        ("payload", "payload")):
        decoded[key] = json.loads(decoded.pop(column))
    return decoded


class LedgerStore(AttentionLedgerMixin, CalibrationLedgerMixin,
                  ConnectionMixin, EntityStateMixin, MigrationSupportMixin):
    """The v3 observation ledger, baselines, and conclusion storage.

    ONE object with one set of handles, assembled from five modules for
    the 800-line house limit. The bases carry methods, never state: the
    connection caches, the write lock and the schema are built HERE, so
    "single jurisdiction" (A-09) stays a property of one object even
    though `store_connections.py` holds the methods that use them.

    The split is audit-visible rather than incidental. `v3/api/readonly.py`
    and `v3/api/writeonly.py` classify these methods by AST — the read seam
    forwards only the ones that hold a read-only handle, the write seam
    proves only `append_command` writes `command_record` — and a method
    hidden in a module they did not parse would make both quietly stop
    checking it. `v3/api/store_source.py` resolves this base chain from the
    source and refuses to run if it finds fewer methods than the recorded
    floor, so a future split that hides methods is a red build rather than
    a coverage number that silently shrinks.
    """

    def __init__(self, path: str):
        if not isinstance(path, str) or not path.strip():
            raise ValueError(
                "LedgerStore needs an explicit database path: v3 runs beside "
                "v1 until cutover, so the file is a deployment decision and "
                "a default would let two processes disagree about which "
                "database is real.")
        self._path = str(Path(path).expanduser())
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        primary = _open_write(self._path)
        try:
            self._read_conns: dict[int, sqlite3.Connection] = {}  # per-thread
            self._read_conns_lock = threading.Lock()
            # Per-thread too, for the reason the module docstring gives.
            # The schema is applied to the FIRST handle only — every later
            # one attaches to a file that already has it, and re-running
            # the migration list per thread would be a second migrator.
            self._write_conns: dict[int, sqlite3.Connection] = {
                threading.get_ident(): primary}
            self._write_conns_lock = threading.Lock()
            # Writes are serialised in-process: sqlite allows one writer,
            # and the fold job is a read-modify-write that must not
            # interleave. THIS is what serialises writes — not the number
            # of connections, which is why several are safe.
            # Multi-greenlet-safe by this lock; single process.
            self._lock = threading.Lock()
            self._apply_schema(primary)
        except BaseException:
            primary.close()
            raise

    # ── lifecycle ───────────────────────────────────────────────────────
    @property
    def path(self) -> str:
        return self._path

    def _apply_schema(self, conn: sqlite3.Connection) -> None:
        """Run once, on the constructing thread's handle, at construction.

        Takes the connection rather than reaching for one, because it runs
        before the store is usable: a lookup that could open a SECOND
        handle here would be a handle racing the schema it depends on.
        """
        conn.executescript(schema_module.SCHEMA_SQL)
        self._migrate(conn)
        # Defence in depth. The prune gate is opened and closed inside one
        # transaction, so a durable flag here can only mean a process died
        # mid-prune. Leaving it would disable the append-only triggers
        # silently, which is the worst possible failure of this layer.
        stuck = conn.execute(
            "SELECT value FROM schema_meta WHERE key = ?",
            (_PRUNE_FLAG,)).fetchone()
        if stuck is not None:
            log.warning(
                "v3 ledger: clearing a stale prune flag at %s — a previous "
                "process died mid-retention and left the append-only "
                "triggers disabled", self._path)
            conn.execute("DELETE FROM schema_meta WHERE key = ?",
                         (_PRUNE_FLAG,))

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Apply every migration above the recorded version, in order.

        A fresh store records no version, which reads as 0 and therefore
        takes the full list — so the upgrade path is exercised on every
        new store rather than only on the one deployment that happens to
        be old. That is the whole point of having a list at all.

        Each migration runs inside one transaction with the version bump,
        so a store is never left claiming a version it did not reach.
        """
        current = self._version_on(conn)
        if current > schema_module.SCHEMA_VERSION:
            raise RuntimeError(
                f"v3 ledger at {self._path} reports schema v{current}, newer "
                f"than this code's v{schema_module.SCHEMA_VERSION}. Refusing "
                f"to open: downgrading a store is not something a forward "
                f"migration list can reason about.")
        for migration in schema_module.MIGRATIONS:
            if migration.version <= current:
                continue
            conn.execute("BEGIN IMMEDIATE")
            try:
                for statement in migration.statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES "
                    "('version', ?) ON CONFLICT (key) DO UPDATE SET value = ?",
                    (str(migration.version), str(migration.version)))
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
            log.info("v3 ledger: applied schema migration v%d (%s)",
                     migration.version, migration.rationale)
        if not schema_module.MIGRATIONS:
            conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('version', ?) "
                "ON CONFLICT (key) DO NOTHING",
                (str(schema_module.SCHEMA_VERSION),))

    @staticmethod
    def _version_on(conn: sqlite3.Connection) -> int:
        row = conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'version'").fetchone()
        return int(row["value"]) if row else 0

    def schema_version(self) -> int:
        return self._version_on(self._connection())

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

    def conclusion_by_id(self, conclusion_id: str) -> Optional[dict]:
        """One conclusion by its id — P7 R4's primitive.

        The derivation surface (formula, effective thresholds, source
        URLs, prompt sha) is addressed by conclusion id, not by
        (scenario, type, instant): an auditor arrives holding an id from
        a report and must land on the same row it was written from.
        """
        row = self._read_connection().execute(
            "SELECT * FROM conclusion WHERE id = ?",
            (conclusion_id,)).fetchone()
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

    # ── commands (append-only; the row IS the change) ───────────────────
    def append_command(self, record: CommandRecord, *,
                       connection=None) -> int:
        """Record one command. Returns its sequence number.

        The only writer of `command_record`, and the only method the L6
        write seam (`v3.api.writeonly.CommandLedger`) forwards. Both
        halves of that sentence are verified by AST in
        `tests/test_api_write_seam.py`, because "the command surface
        writes through one door" is otherwise a claim about intent.

        No `INSERT OR IGNORE`, unlike its siblings: a duplicate command_id
        means two different commands were assigned the same identity, and
        swallowing that would silently drop an analyst's decision. The
        UNIQUE constraint raises instead.
        """
        if not isinstance(record, CommandRecord):
            raise TypeError(
                f"append_command expects a CommandRecord, got "
                f"{type(record).__name__}: a kwargs bag would let a caller "
                f"omit the actor, and an audit row with no actor is the "
                f"shape G-01 produced")
        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT INTO command_record "
                "(command_id, action, target_kind, target_id, actor_id, "
                " actor_role, issued_at, recorded_at, before_json, "
                " after_json, reason, payload) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.command_id, record.action, record.target_kind,
                 record.target_id, record.actor_id, record.actor_role,
                 record.issued_at, time.time(), record.before_json(),
                 record.after_json(), record.reason, record.payload_json()))
            return int(cursor.lastrowid)

    def command_records(self, *, action: Optional[str] = None,
                        target_kind: Optional[str] = None,
                        target_id: Optional[str] = None,
                        actor_id: Optional[str] = None,
                        until: Optional[float] = None,
                        limit: Optional[int] = None) -> list:
        """Command rows, OLDEST FIRST — the order a fold has to see them.

        `until` is what makes a command state replayable: the effective
        focus (or label, or ground-truth set) at an instant is this list
        bounded at that instant and folded, which is the same projection
        the live read performs with `until=now`. P7's derivation principle
        4 applied to the write side — there is no replay-only path.
        """
        query = ["SELECT * FROM command_record WHERE 1 = 1"]
        params: list = []
        for column, value in (("action", action),
                              ("target_kind", target_kind),
                              ("target_id", target_id),
                              ("actor_id", actor_id)):
            if value is not None:
                query.append(f" AND {column} = ?")
                params.append(value)
        if until is not None:
            query.append(" AND issued_at <= ?")
            params.append(float(until))
        query.append(" ORDER BY issued_at ASC, id ASC")
        if limit is not None:
            query.append(" LIMIT ?")
            params.append(int(limit))
        rows = self._read_connection().execute("".join(query),
                                               params).fetchall()
        return [_command_row(row) for row in rows]

    def count_commands(self) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM command_record").fetchone()[0])

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

        `bucket` is the v1 RAW EPOCH hour (or day) for the migrated
        hour-of-day baselines; `baseline_phase_values` is the read that
        asks about a phase of it.
        """
        row = self._read_connection().execute(
            "SELECT * FROM baseline_stat WHERE baseline_id = ? AND sensor = ? "
            "AND country = ? AND bucket = ?",
            (baseline_id, sensor, country, bucket)).fetchone()
        return dict(row) if row else None

    def baseline_phase_values(self, baseline_id: str, *, sensor: str,
                              country: str, phase: int, divisor: int,
                              modulus: int, before_bucket: int) -> list:
        """Values at the same PHASE of the bucket clock, oldest first.

        Transcribes `hod_same_hour` (`radar/database.py:3213-3224`):

            WHERE theater=? AND (hour_bucket/3600)%24=? AND hour_bucket<?

        with `divisor`/`modulus` naming the clock (3600/24 for hour of
        day, 86400/7 for day of week) instead of two near-identical
        methods — DP4 is a catalogue of the same arithmetic written twice
        and then drifting.

        `before_bucket` is exclusive because production records the
        current bucket BEFORE reading; including it would compare a
        reading with itself and pull every Z-score toward zero on exactly
        the tick that mattered.

        There is no lower bound here, and that is not an omission:
        production's window lives on the write side
        (`record_bucket_sample`), so a lower bound in the read would be a
        SECOND window, silently narrower than the declared one.
        """
        if not isinstance(divisor, int) or divisor <= 0:
            raise DomainError(
                f"phase divisor must be a positive integer number of "
                f"seconds, got {divisor!r}")
        if not isinstance(modulus, int) or modulus <= 0:
            raise DomainError(
                f"phase modulus must be a positive integer, got {modulus!r}")
        if not isinstance(phase, int) or not 0 <= phase < modulus:
            raise DomainError(
                f"phase must be in [0, {modulus}), got {phase!r}: an "
                f"out-of-range phase matches no row, and an empty result is "
                f"indistinguishable from a baseline that is merely cold")
        rows = self._read_connection().execute(
            "SELECT mean FROM baseline_stat "
            "WHERE baseline_id = ? AND sensor = ? AND country = ? "
            "AND (bucket / ?) % ? = ? AND bucket < ? "
            "ORDER BY bucket ASC",
            (baseline_id, sensor, country, divisor, modulus, phase,
             int(before_bucket))).fetchall()
        return [float(row["mean"]) for row in rows]

    def baseline_series_values(self, baseline_id: str, *, sensor: str,
                               country: str, before_bucket: int) -> list:
        """EVERY bucket's value, any phase, oldest first — §7-2 #135.

        `baseline_phase_values` without the phase predicate, and that is
        the whole of the difference: same table, same series, same
        exclusive `before_bucket`, same `mean` column. It reads no row the
        phase read could not reach; it declines to throw twenty-three
        twenty-fourths of them away.

        It exists because a same-phase series fills at one sample per DAY
        while the series it is drawn from fills at one per HOUR, so the
        seven samples `HOD_MIN_SAME_HOUR` asks for take a week to arrive
        and seven hours to arrive. §7-2 #135's warm-up verdict is what
        happens in between; production spends that week on a baseline
        held in process memory (A-03) instead.

        NOT a second window. The bound is still the write side's
        (`record_bucket_sample`'s newest-N), for the reason spelled out on
        `baseline_phase_values`: a lower bound here would be a second,
        silently narrower window — F-06's shape.
        """
        rows = self._read_connection().execute(
            "SELECT mean FROM baseline_stat "
            "WHERE baseline_id = ? AND sensor = ? AND country = ? "
            "AND bucket < ? ORDER BY bucket ASC",
            (baseline_id, sensor, country, int(before_bucket))).fetchall()
        return [float(row["mean"]) for row in rows]

    def baseline_bucket_count(self, baseline_id: str, *, sensor: str,
                              country: str) -> int:
        """How many buckets one series is holding — the window, measured."""
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM baseline_stat WHERE baseline_id = ? "
            "AND sensor = ? AND country = ?",
            (baseline_id, sensor, country)).fetchone()[0])

    def latest_baseline_bucket(self, baseline_id: str, *, sensor: str,
                               country: str) -> Optional[int]:
        """`hod_last_bucket` (`radar/database.py:3226-3233`): MAX(bucket)."""
        row = self._read_connection().execute(
            "SELECT MAX(bucket) FROM baseline_stat WHERE baseline_id = ? "
            "AND sensor = ? AND country = ?",
            (baseline_id, sensor, country)).fetchone()
        return None if row[0] is None else int(row[0])

    # ── deletion (four sanctioned deleters, all explicit) ───────────────
    #   prune_expired              retention, from the policy registry
    #   wipe_migrated_tables       S3-DATA-030's wipe-then-copy norm
    #   record_bucket_sample       the hour-of-day window, baseline_stat
    #                              only (ledger/baselines.py)
    #   append_entity_observation  the per-entity count bound, when the
    #                              caller declares one (`max_samples`)
    # The last two exist because production's window for those two shapes
    # is a COUNT enforced on the write (`hod_record`'s newest-N buckets,
    # `deque(maxlen=12)`), not a span enforced by a sweep. Implementing
    # them as retention would have been a second window, silently the
    # narrower of the two, which is F-06's shape.
    # `record_bucket_sample` needs no trigger gate — baseline_stat is
    # updated in place and carries none. `append_entity_observation` opens
    # and closes the gate inside its own transaction, like the prune job.
    def prune_expired(self, now: Optional[float] = None) -> dict:
        """Apply every retention policy in the registry. Returns row counts."""
        from v3.ledger.retention import prune
        return prune(self, now=now)

    @staticmethod
    def _set_prune_flag(connection, enabled: bool) -> None:
        """Open/close the trigger gate, inside the caller's transaction.

        Takes the connection rather than calling `_connection()` so it
        cannot be
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
