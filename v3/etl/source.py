"""Read-only access to the v1 database.

S3-DATA-023 makes this a MUST, and the reason is concrete: production
lives in a docker volume with WAL enabled, and a writing connection from
outside the container corrupts the visibility invariants. So the ETL is
built so that writing is not merely discouraged but impossible — `mode=ro`
means SQLite itself refuses.

The URI is percent-quoted. An unquoted '#' or '?' in the path truncates
the URI and silently opens a different (empty) database, which here would
present as "the source has no rows" — a migration that succeeds and
copies nothing.
"""
from __future__ import annotations

import sqlite3
import urllib.parse
from pathlib import Path
from typing import Iterator, Optional

# (ordering value, rowid) — the composite keyset cursor. Unique by
# construction, which a bare ordering value is not.
Cursor = tuple[object, int]

BUSY_TIMEOUT_MS = 5000


class V1Source:
    """A read-only handle on a v1 snapshot."""

    def __init__(self, path: str):
        if not isinstance(path, str) or not path.strip():
            raise ValueError("V1Source needs an explicit source path")
        resolved = Path(path).expanduser()
        if not resolved.exists():
            raise FileNotFoundError(
                f"v1 source not found: {resolved}. S3-DATA-024 requires the "
                f"input to be a backup snapshot, and S3-DATA-023 warns that "
                f"the repository copy of radar.db is stale — the live "
                f"database is in the docker volume.")
        self._path = str(resolved)
        uri = f"file:{urllib.parse.quote(self._path)}?mode=ro"
        self._conn = sqlite3.connect(uri, uri=True)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")

    @property
    def path(self) -> str:
        return self._path

    def connection(self) -> sqlite3.Connection:
        return self._conn

    def has_table(self, table: str) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
            (table,)).fetchone() is not None

    def count(self, table: str) -> int:
        if not self.has_table(table):
            return 0
        return int(self._conn.execute(
            f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])  # noqa: S608

    def iter_chunks(self, table: str, *, order_by: str,
                    chunk_size: int = 50_000,
                    after: Optional[Cursor] = None,
                    limit: Optional[int] = None
                    ) -> Iterator[list[sqlite3.Row]]:
        """Rows in deterministic order, one chunk at a time (S3-DATA-021).

        The keyset cursor is the COMPOSITE (order_by, rowid), compared with
        SQL row values. A bare scalar cursor on `observed_at` — which every
        row of a tick shares, as every country shares a bucket — silently
        drops the remainder of any tie group that a chunk boundary or a
        resume falls inside: no exception, no quarantine, just fewer rows.
        The pair is unique, so the sequence is total.
        """
        if not self.has_table(table):
            return
        emitted = 0
        cursor: Optional[Cursor] = after
        while True:
            query = f'SELECT rowid AS _rowid, * FROM "{table}"'  # noqa: S608
            params: list = []
            if cursor is not None:
                query += f' WHERE ("{order_by}", rowid) > (?, ?)'
                params.extend([cursor[0], cursor[1]])
            query += f' ORDER BY "{order_by}" ASC, rowid ASC LIMIT ?'
            params.append(chunk_size)
            rows = self._conn.execute(query, params).fetchall()
            if not rows:
                return
            if limit is not None and emitted + len(rows) > limit:
                rows = rows[:limit - emitted]
            emitted += len(rows)
            yield rows
            if limit is not None and emitted >= limit:
                return
            last = rows[-1]
            cursor = (last[order_by], last["_rowid"])

    def close(self) -> None:
        self._conn.close()


__all__ = ["V1Source", "Cursor"]
