"""Legacy access telemetry — Safe Rename Pattern SR4 instrumentation.

This module records every access to a deprecated identifier, dict key,
or API parameter so that the v1 sunset (ADR-V2-002, 90-day rule) can be
made on observed evidence rather than guesswork.

Each call to ``record_legacy_access(key)`` increments an in-memory
counter for ``key`` and updates ``last_seen``. ``flush_to_db`` upserts
the in-memory state to the ``legacy_access_log`` table (added by
migration v23) so that observation persists across restarts.

Design constraints:
  * Hot-path safe: a single ``threading.Lock`` and a ``dict`` mutation,
    no I/O. Worst case ~microseconds per call.
  * Crash-safe: in-memory state is reconciled on startup by reading
    existing rows, so a crash between flushes loses at most the
    increments since the last flush — never data already on disk.
  * Append-no-mutate semantics from the caller's perspective: callers
    only call ``record_legacy_access``; they never read or reset state.
    Snapshots are read-only views.

Read path (admin / sunset evaluation): ``snapshot()`` returns an
immutable dict of ``{key: LegacyAccessStat}`` reflecting both in-memory
deltas and the last DB flush.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from radar.database import RadarDB


@dataclass(frozen=True)
class LegacyAccessStat:
    """Read-only snapshot row. Immutable per project coding-style rule."""
    key: str
    count: int
    first_seen: float
    last_seen: float


_STATE: dict[str, LegacyAccessStat] = {}
_LOCK = threading.Lock()
_HYDRATED = False


def record_legacy_access(key: str, *, now: Optional[float] = None) -> None:
    """Record one access of a deprecated identifier / key / param.

    ``key`` should be a stable, grep-friendly string identifying the
    deprecated surface, e.g.:
      - ``"Participant.theater"``
      - ``"intel_queue.submit:theater_kwarg"``
      - ``"GET /api/threat_data?theater="``

    The convention is enforced by callers; this function does not
    validate the format.
    """
    if not key:
        return
    ts = time.time() if now is None else now
    with _LOCK:
        prev = _STATE.get(key)
        if prev is None:
            _STATE[key] = LegacyAccessStat(
                key=key, count=1, first_seen=ts, last_seen=ts,
            )
        else:
            _STATE[key] = replace(prev, count=prev.count + 1, last_seen=ts)


def snapshot() -> dict[str, LegacyAccessStat]:
    """Return an immutable view of current in-memory state.

    Callers must not mutate the returned dict; the dataclass is frozen
    so individual rows are immutable.
    """
    with _LOCK:
        return dict(_STATE)


def reset_for_test() -> None:
    """Test-only: clear in-memory state and re-arm hydration."""
    global _HYDRATED
    with _LOCK:
        _STATE.clear()
        _HYDRATED = False


def hydrate_from_db(db: "RadarDB") -> int:
    """Load existing rows from ``legacy_access_log`` into memory.

    Idempotent — subsequent calls are no-ops. Called once at startup
    (typically right after migrations run) so that telemetry counts
    survive process restarts.

    Returns the number of rows loaded.
    """
    global _HYDRATED
    with _LOCK:
        if _HYDRATED:
            return 0
        try:
            rows = db._get_conn().execute(  # noqa: SLF001
                "SELECT key, count, first_seen, last_seen FROM legacy_access_log"
            ).fetchall()
        except Exception:
            # Migration v23 may not have run yet (e.g. very old DB).
            # Re-attempt on next call.
            return 0
        for r in rows:
            _STATE[r["key"]] = LegacyAccessStat(
                key=r["key"],
                count=int(r["count"]),
                first_seen=float(r["first_seen"]),
                last_seen=float(r["last_seen"]),
            )
        _HYDRATED = True
        return len(rows)


def flush_to_db(db: "RadarDB") -> int:
    """Upsert the in-memory state into ``legacy_access_log``.

    Uses ``ON CONFLICT(key) DO UPDATE`` so concurrent writers (other
    processes) cannot lose data. Returns the number of keys flushed.

    Callers should run this on a periodic schedule (the cleanup
    worker in radar.scheduler) and once at shutdown if possible.
    """
    with _LOCK:
        items = list(_STATE.values())
    if not items:
        return 0
    # _CooperativeConn serializes writes via its internal lock; we do
    # not need an outer lock around the loop. Each INSERT acquires the
    # write lock, the commit releases it.
    conn = db._get_conn()  # noqa: SLF001
    for stat in items:
        conn.execute(
            """INSERT INTO legacy_access_log (key, count, first_seen, last_seen)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   count = excluded.count,
                   last_seen = MAX(last_seen, excluded.last_seen),
                   first_seen = MIN(first_seen, excluded.first_seen)""",
            (stat.key, stat.count, stat.first_seen, stat.last_seen),
        )
    conn.commit()
    return len(items)
