"""Per-entity series and markers — one half of `LedgerStore`, by module.

Split out of `store.py` for the 800-line house limit, and the split is
audit-visible on purpose. `v3/api/readonly.py` and `v3/api/writeonly.py`
both classify `LedgerStore`'s methods by AST, and a method moved into a
module they did not parse would make BOTH of them quietly stop checking it
— the exact failure mode they exist to prevent. So they follow the class
across its declared base chain (`v3/api/store_source.py`) and refuse to run
if they find fewer methods than the recorded floor.

The methods here are unchanged from `store.py`; only their module moved.
They still reach `self._maybe_transaction`, `self._read_connection` and
`self._set_prune_flag`, all defined on the concrete class — a mixin is the
shape that keeps `LedgerStore` ONE object with one connection pair, which
is what "single jurisdiction" (A-09) means at runtime.

Two tables because there are two lifetimes: a SERIES that is observational
(append-only, pruned) and a MARKER that is state (updated in place,
permanent). See `schema.py`'s policies for why neither could be the other.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from v3.kernel.errors import DomainError


class EntityStateMixin:
    """`LedgerStore`'s per-entity half (WP-4.1b ruling 2)."""

    def append_entity_observation(self, *, series: str, sensor: str,
                                  entity: str, observed_at: float,
                                  value: Optional[float] = None,
                                  payload: Optional[dict] = None,
                                  max_samples: Optional[int] = None,
                                  now: Optional[float] = None,
                                  connection=None) -> int:
        """Record one sample of a per-entity series. Returns its rowid.

        `max_samples` transcribes production's own bound — a
        `deque(maxlen=12)` for check_host latency (`checkhost.py:143`), one
        snapshot per MMSI for AIS (`ais_maritime.py:141`). The trim runs in
        the same transaction as the insert, so a failure cannot leave a
        series over its bound with nothing to say so.
        """
        for name, field in (("series", series), ("sensor", sensor),
                            ("entity", entity)):
            if not isinstance(field, str) or not field.strip():
                raise DomainError(
                    f"entity observation {name} must be a non-empty string, "
                    f"got {field!r}: an empty key collapses every entity "
                    f"into one series and the collapse is invisible in the "
                    f"numbers")
        if max_samples is not None and (not isinstance(max_samples, int)
                                        or max_samples <= 0):
            raise DomainError(
                f"max_samples must be a positive count, got {max_samples!r}")
        ts = time.time() if now is None else now
        body = json.dumps(payload or {}, sort_keys=True, default=str,
                          allow_nan=False, ensure_ascii=False)
        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT INTO entity_observation "
                "(series, sensor, entity, observed_at, recorded_at, value, "
                " payload) VALUES (?,?,?,?,?,?,?)",
                (series, sensor, entity, float(observed_at), ts,
                 None if value is None else float(value), body))
            rowid = int(cursor.lastrowid)
            if max_samples is not None:
                self._set_prune_flag(conn, True)
                conn.execute(
                    "DELETE FROM entity_observation WHERE series = ? "
                    "AND sensor = ? AND entity = ? AND id NOT IN ("
                    "  SELECT id FROM entity_observation WHERE series = ? "
                    "  AND sensor = ? AND entity = ? "
                    "  ORDER BY observed_at DESC, id DESC LIMIT ?)",
                    (series, sensor, entity, series, sensor, entity,
                     max_samples))
                self._set_prune_flag(conn, False)
        return rowid

    def entity_series_values(self, series: str, *, sensor: str, entity: str,
                             limit: Optional[int] = None) -> list:
        """The entity's samples, OLDEST FIRST — the order a deque holds.

        `limit` takes the newest N and still returns them oldest-first, so
        a caller that wants "the last 12" gets production's deque exactly.
        """
        rows = self._entity_rows(series, sensor=sensor, entity=entity,
                                 limit=limit)
        return [float(row["value"]) for row in rows
                if row["value"] is not None]

    def entity_series_tail(self, series: str, *, sensor: str,
                           per_entity: int = 1) -> dict:
        """`{entity: [row, ...]}` for EVERY entity, newest `per_entity`.

        One read per cycle for a whole series, which is the shape
        production holds in memory (`self._vessel_history`,
        `_url_latency_history`). The alternative — a read per entity
        inside the fold — would put a database call in a pure function and
        make the fold unreplayable.
        """
        if not isinstance(per_entity, int) or per_entity <= 0:
            raise DomainError(
                f"per_entity must be a positive count, got {per_entity!r}")
        rows = self._read_connection().execute(
            "SELECT entity, observed_at, value, payload FROM ("
            "  SELECT entity, observed_at, value, payload, ROW_NUMBER() OVER ("
            "    PARTITION BY entity ORDER BY observed_at DESC, id DESC"
            "  ) AS rank FROM entity_observation "
            "  WHERE series = ? AND sensor = ?"
            ") WHERE rank <= ? ORDER BY entity ASC, observed_at ASC",
            (series, sensor, per_entity)).fetchall()
        grouped: dict = {}
        for row in rows:
            grouped.setdefault(row["entity"], []).append(
                {"observed_at": float(row["observed_at"]),
                 "value": None if row["value"] is None else float(
                     row["value"]),
                 "payload": json.loads(row["payload"])})
        return grouped

    def _entity_rows(self, series: str, *, sensor: str, entity: str,
                     limit: Optional[int]) -> list:
        query = ("SELECT observed_at, value, payload FROM entity_observation "
                 "WHERE series = ? AND sensor = ? AND entity = ? "
                 "ORDER BY observed_at DESC, id DESC")
        params: list = [series, sensor, entity]
        if limit is not None:
            query += " LIMIT ?"
            params.append(int(limit))
        rows = self._read_connection().execute(query, params).fetchall()
        return list(reversed(rows))

    def touch_entity_marker(self, *, series: str, sensor: str, entity: str,
                            member: str = "", now: Optional[float] = None,
                            connection=None) -> dict:
        """Record that `entity` (optionally `member`) was seen. Returns it.

        `ct_log_record_ca` / `ct_log_set_first_observed`
        (`radar/database.py:5426-5475`): `first_seen` is written once and
        never again, `last_seen` and the count move. A trigger enforces the
        first half, because the consequence of moving `first_seen` forward
        is a warm-up that reopens and a score 3 that stops being emitted.
        """
        for name, field in (("series", series), ("sensor", sensor),
                            ("entity", entity)):
            if not isinstance(field, str) or not field.strip():
                raise DomainError(
                    f"entity marker {name} must be a non-empty string, got "
                    f"{field!r}")
        ts = time.time() if now is None else now
        with self._maybe_transaction(connection) as conn:
            conn.execute(
                "INSERT INTO entity_marker "
                "(series, sensor, entity, member, first_seen, last_seen, "
                " observation_count) VALUES (?,?,?,?,?,?,1) "
                "ON CONFLICT (series, sensor, entity, member) DO UPDATE SET "
                "  last_seen = excluded.last_seen, "
                "  observation_count = observation_count + 1",
                (series, sensor, entity, member, ts, ts))
        return self.entity_marker(series, sensor=sensor, entity=entity,
                                  member=member)

    def entity_marker(self, series: str, *, sensor: str, entity: str,
                      member: str = "") -> Optional[dict]:
        row = self._read_connection().execute(
            "SELECT * FROM entity_marker WHERE series = ? AND sensor = ? "
            "AND entity = ? AND member = ?",
            (series, sensor, entity, member)).fetchone()
        return dict(row) if row else None

    def entity_members(self, series: str, *, sensor: str,
                       entity: str) -> tuple:
        """The membership set for one entity, sorted."""
        rows = self._read_connection().execute(
            "SELECT member FROM entity_marker WHERE series = ? "
            "AND sensor = ? AND entity = ? ORDER BY member ASC",
            (series, sensor, entity)).fetchall()
        return tuple(row["member"] for row in rows)

    def entity_member_sets(self, series: str, *, sensor: str) -> dict:
        """`{entity: (member, ...)}` for a whole series, in one read."""
        rows = self._read_connection().execute(
            "SELECT entity, member FROM entity_marker WHERE series = ? "
            "AND sensor = ? ORDER BY entity ASC, member ASC",
            (series, sensor)).fetchall()
        grouped: dict = {}
        for row in rows:
            grouped.setdefault(row["entity"], []).append(row["member"])
        return {entity: tuple(members) for entity, members in grouped.items()}

    def entity_first_seen(self, series: str, *, sensor: str) -> dict:
        """`{entity: first_seen}` for a whole series, in one read."""
        rows = self._read_connection().execute(
            "SELECT entity, first_seen FROM entity_marker WHERE series = ? "
            "AND sensor = ? AND member = '' ORDER BY entity ASC",
            (series, sensor)).fetchall()
        return {row["entity"]: float(row["first_seen"]) for row in rows}


__all__ = ["EntityStateMixin"]
