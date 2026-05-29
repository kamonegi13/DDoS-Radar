"""Repository for the auto-apply tier governor's persisted state.

Encapsulates every SQL touch the governor needs (`auto_apply_tier_state`,
`auto_apply_cooldown`, plus the marker table introduced in migration v53)
behind a small, injectable surface so tests can run against an in-memory
SQLite without touching the live container DB.

The repository accepts a ``conn_factory`` callable (zero-arg) that
returns a connection-shaped object. The shape required is the same one
``radar.database._CooperativeConn`` exposes:

  - ``execute(sql, params) -> cursor``
  - ``writing()`` context manager (commits on exit, rolls back on exc)

Production callers wire ``conn_factory = lambda: radar.database.db._get_conn()``.
Tests inject a wrapper around ``sqlite3.connect(':memory:')`` that
provides the same surface (see ``conftest.py``).

NP3: every method swallows DB errors and returns a benign default. The
governor stays alive even if the table is missing (fresh DB before
migrations run) or write-locked by another greenlet.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

log = logging.getLogger("radar.calibration.auto_apply_tier_repository")


ConnFactory = Callable[[], object]


@dataclass(frozen=True)
class StateRow:
    id: int
    observed_at: float
    tier: int
    transition: str
    reason: str
    metrics_json: str


@dataclass(frozen=True)
class CooldownRow:
    impact_level: str
    cooldown_until: float
    triggered_by: str
    set_at: float


@dataclass(frozen=True)
class MarkerRow:
    tier: int
    entered_at: float
    updated_at: float
    metadata_json: str


_STATE_CHANGING_TRANSITIONS = (
    "promote",
    "demote",
    "circuit_breaker",
    "kill_switch_engaged",
    "init",
)


class TierGovernorRepository:
    """Thin Repository Pattern wrapper. Methods are intentionally small
    so they read like the original SQL they replace.

    All methods return primitives or frozen dataclasses — never live
    cursors — so callers don't need to manage connection state.
    """

    def __init__(self, conn_factory: ConnFactory):
        self._conn_factory = conn_factory

    # -- helpers --------------------------------------------------------

    def _conn(self):
        return self._conn_factory()

    # -- state table ----------------------------------------------------

    def latest_state_row(self) -> Optional[StateRow]:
        """Most recent row regardless of transition kind."""
        try:
            row = self._conn().execute(
                "SELECT id, observed_at, tier, transition, reason, metrics_json "
                "FROM auto_apply_tier_state ORDER BY id DESC LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        except Exception as exc:
            log.debug("latest_state_row failed: %s", exc)
            return None
        if row is None:
            return None
        return StateRow(
            id=int(row[0]),
            observed_at=float(row[1]),
            tier=int(row[2]),
            transition=str(row[3]),
            reason=str(row[4] or ""),
            metrics_json=str(row[5] or "{}"),
        )

    def latest_state_changing_row(self) -> Optional[StateRow]:
        """Most recent row whose transition actually entered a new tier
        (excludes ``unchanged`` / ``evaluation_failed`` heartbeats)."""
        try:
            placeholders = ",".join("?" for _ in _STATE_CHANGING_TRANSITIONS)
            row = self._conn().execute(
                "SELECT id, observed_at, tier, transition, reason, metrics_json "
                "FROM auto_apply_tier_state "
                f"WHERE transition IN ({placeholders}) "
                "ORDER BY id DESC LIMIT 1",
                _STATE_CHANGING_TRANSITIONS,
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        except Exception as exc:
            log.debug("latest_state_changing_row failed: %s", exc)
            return None
        if row is None:
            return None
        return StateRow(
            id=int(row[0]),
            observed_at=float(row[1]),
            tier=int(row[2]),
            transition=str(row[3]),
            reason=str(row[4] or ""),
            metrics_json=str(row[5] or "{}"),
        )

    def recent_transitions(self, n: int) -> list[StateRow]:
        try:
            rows = list(self._conn().execute(
                "SELECT id, observed_at, tier, transition, reason, metrics_json "
                "FROM auto_apply_tier_state ORDER BY id DESC LIMIT ?",
                (int(n),),
            ))
        except Exception as exc:
            log.debug("recent_transitions failed: %s", exc)
            return []
        return [
            StateRow(
                id=int(r[0]),
                observed_at=float(r[1]),
                tier=int(r[2]),
                transition=str(r[3]),
                reason=str(r[4] or ""),
                metrics_json=str(r[5] or "{}"),
            )
            for r in rows
        ]

    def recent_transition_kinds(self, limit: int) -> list[str]:
        """Return the ``transition`` column for the last `limit` rows in
        DESC order. Used by the circuit-breaker counter."""
        try:
            rows = list(self._conn().execute(
                "SELECT transition FROM auto_apply_tier_state "
                "ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ))
        except Exception as exc:
            log.debug("recent_transition_kinds failed: %s", exc)
            return []
        return [str(r[0]) for r in rows]

    def insert_state(
        self,
        *,
        observed_at: float,
        tier: int,
        transition: str,
        reason: str,
        metrics: dict,
    ) -> None:
        """Append a new state row. Caller is responsible for deciding
        when this should fire — the repository never gates writes."""
        c = self._conn()
        try:
            with c.writing():
                c.execute(
                    "INSERT INTO auto_apply_tier_state "
                    "(observed_at, tier, transition, reason, metrics_json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        float(observed_at),
                        int(tier),
                        str(transition),
                        str(reason),
                        json.dumps(metrics, default=float),
                    ),
                )
        except Exception as exc:
            log.warning("insert_state failed (non-fatal): %s", exc)

    # -- cooldown table -------------------------------------------------

    def cooldown_until(self, impact_level: str) -> Optional[float]:
        try:
            row = self._conn().execute(
                "SELECT cooldown_until FROM auto_apply_cooldown "
                "WHERE impact_level=?",
                (impact_level,),
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        except Exception as exc:
            log.debug("cooldown_until failed: %s", exc)
            return None
        if row is None:
            return None
        return float(row[0])

    def all_cooldowns(self) -> list[CooldownRow]:
        try:
            rows = list(self._conn().execute(
                "SELECT impact_level, cooldown_until, triggered_by, set_at "
                "FROM auto_apply_cooldown"
            ))
        except Exception as exc:
            log.debug("all_cooldowns failed: %s", exc)
            return []
        return [
            CooldownRow(
                impact_level=str(r[0]),
                cooldown_until=float(r[1]),
                triggered_by=str(r[2] or ""),
                set_at=float(r[3]),
            )
            for r in rows
        ]

    def upsert_cooldowns(
        self,
        *,
        impact_levels: Iterable[str],
        cooldown_until: float,
        triggered_by: str,
    ) -> None:
        c = self._conn()
        try:
            with c.writing():
                for impact in impact_levels:
                    c.execute(
                        "INSERT INTO auto_apply_cooldown "
                        "(impact_level, cooldown_until, triggered_by, set_at) "
                        "VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(impact_level) DO UPDATE SET "
                        "cooldown_until=excluded.cooldown_until, "
                        "triggered_by=excluded.triggered_by, "
                        "set_at=excluded.set_at",
                        (impact, float(cooldown_until), str(triggered_by),
                         time.time()),
                    )
        except Exception as exc:
            log.debug("upsert_cooldowns failed (non-fatal): %s", exc)

    # -- marker table (Phase 2) -----------------------------------------

    MARKER_KEY = "current_tier_entered_at"

    def marker_get(self) -> Optional[MarkerRow]:
        try:
            row = self._conn().execute(
                "SELECT tier, entered_at, updated_at, metadata_json "
                "FROM auto_apply_tier_marker WHERE marker_key=?",
                (self.MARKER_KEY,),
            ).fetchone()
        except sqlite3.OperationalError:
            return None
        except Exception as exc:
            log.debug("marker_get failed: %s", exc)
            return None
        if row is None:
            return None
        return MarkerRow(
            tier=int(row[0]),
            entered_at=float(row[1]),
            updated_at=float(row[2]),
            metadata_json=str(row[3] or "{}"),
        )

    def marker_set(
        self,
        *,
        tier: int,
        entered_at: float,
        metadata: Optional[dict] = None,
    ) -> None:
        c = self._conn()
        try:
            with c.writing():
                c.execute(
                    "INSERT INTO auto_apply_tier_marker "
                    "(marker_key, tier, entered_at, updated_at, metadata_json) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(marker_key) DO UPDATE SET "
                    "tier=excluded.tier, "
                    "entered_at=excluded.entered_at, "
                    "updated_at=excluded.updated_at, "
                    "metadata_json=excluded.metadata_json",
                    (
                        self.MARKER_KEY,
                        int(tier),
                        float(entered_at),
                        time.time(),
                        json.dumps(metadata or {}, default=float),
                    ),
                )
        except Exception as exc:
            log.debug("marker_set failed (non-fatal): %s", exc)


# -- module-level injection -------------------------------------------------
#
# The governor module imports ``default_repository`` at call-time so tests
# can swap the active repository via ``set_repository(...)`` without
# monkey-patching at the function-call site.

_REPO: Optional[TierGovernorRepository] = None


def default_repository() -> TierGovernorRepository:
    """Repo bound to the production singleton DB connection."""
    global _REPO
    if _REPO is None:
        from radar.database import db
        _REPO = TierGovernorRepository(conn_factory=lambda: db._get_conn())  # noqa: SLF001
    return _REPO


def set_repository(repo: Optional[TierGovernorRepository]) -> None:
    """Inject a test repository, or pass ``None`` to reset to default."""
    global _REPO
    _REPO = repo


def get_repository() -> TierGovernorRepository:
    """Return the active repository (test-injected or default)."""
    return default_repository()
