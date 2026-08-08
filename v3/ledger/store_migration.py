"""Migration and reconciliation reads — one half of `LedgerStore`, by module.

Split out of `store.py` for the 800-line house limit. See
`v3/ledger/store_entities.py` for why the split had to teach the two AST
audits to follow the class first.

Checkpoints live in the TARGET store: the source is opened read-only and
must stay byte-identical, so progress state cannot be written there even in
principle (S3-DATA-023).
"""
from __future__ import annotations

import json
import time
from typing import Optional


class MigrationSupportMixin:
    """`LedgerStore`'s WP-2.3 migration and reconciliation half."""

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
                              now: Optional[float] = None,
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
                 time.time() if now is None else now))

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


__all__ = ["MigrationSupportMixin"]
