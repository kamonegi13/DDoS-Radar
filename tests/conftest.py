"""Test-package conftest.

Hosts shared fixtures (``tier_governor_repo``, ``tier_governor_conn``).

The gevent ``monkey.patch_all()`` and the env opt-outs for
flask-limiter / JWT cookies / CSRF live in the **root** conftest.py
because ``patch_all()`` must run before any test module imports
``radar.*``. pytest imports the rootdir conftest first, then this
nested one — that ordering is load-bearing; do not relocate the
gevent patch into this file.

Do NOT add ``tests/__init__.py``: pytest uses rootdir-based imports
for the test files, which is what lets ``from radar.X import Y``
resolve in every test today.
"""
from __future__ import annotations

import contextlib as _contextlib
import sqlite3 as _sqlite3
import threading as _threading

import pytest


# ── Tier governor fixtures ───────────────────────────────────────────────────
#
# The auto-apply tier governor (radar/calibration/auto_apply_tier_governor.py)
# stores its state in `auto_apply_tier_state`, `auto_apply_cooldown`, and
# `auto_apply_tier_marker`. Tests against the live container DB used to
# truncate these tables in setUp/tearDown, which **wiped production tier
# history**. The fixture below replaces the governor's repository with one
# bound to a fresh in-memory SQLite per test, so production state is never
# touched.
#
# The schema duplicated here MUST stay in sync with migrations v52 + v53 in
# radar/database.py. Keep this minimal — only tables the governor reads.

# v52 (auto_apply_tier_state, auto_apply_cooldown) + v53 (auto_apply_tier_marker)
# + the foreign tables the governor's metric helpers query
# (analyst_feedback, threshold_history, conclusion_diff_log).
_TIER_GOVERNOR_TEST_SCHEMA = """
CREATE TABLE IF NOT EXISTS auto_apply_tier_state (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at     REAL    NOT NULL,
    tier            INTEGER NOT NULL,
    transition      TEXT    NOT NULL,
    reason          TEXT    NOT NULL DEFAULT '',
    metrics_json    TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_auto_apply_tier_state_observed
    ON auto_apply_tier_state (observed_at DESC);

CREATE TABLE IF NOT EXISTS auto_apply_cooldown (
    impact_level    TEXT PRIMARY KEY,
    cooldown_until  REAL NOT NULL,
    triggered_by    TEXT NOT NULL DEFAULT '',
    set_at          REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS auto_apply_tier_marker (
    marker_key      TEXT PRIMARY KEY,
    tier            INTEGER NOT NULL,
    entered_at      REAL NOT NULL,
    updated_at      REAL NOT NULL,
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    conclusion_id   INTEGER NOT NULL,
    label           TEXT NOT NULL,
    analyst_id      TEXT NOT NULL,
    observed_at     REAL NOT NULL,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS threshold_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    emitted_at          REAL NOT NULL,
    key                 TEXT NOT NULL,
    value               TEXT NOT NULL,
    scope_scenario_id   TEXT,
    effective_from      REAL NOT NULL,
    effective_to        REAL,
    derived_from        TEXT NOT NULL DEFAULT '',
    applied_by          TEXT NOT NULL DEFAULT '',
    revertible_to_id    INTEGER,
    sample_n            INTEGER NOT NULL DEFAULT 0,
    formula_ref         TEXT NOT NULL DEFAULT '',
    evidence_json       TEXT NOT NULL DEFAULT '{}',
    magnitude_pct       REAL NOT NULL DEFAULT 0,
    state               TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS conclusion_diff_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_at          REAL NOT NULL,
    scenario_id         TEXT NOT NULL,
    conclusion_type     TEXT NOT NULL,
    v1_state            TEXT,
    v2_state            TEXT,
    is_match            INTEGER NOT NULL DEFAULT 0,
    diff_kind           TEXT NOT NULL,
    metadata            TEXT NOT NULL DEFAULT '{}'
);
"""


class _TestConn:
    """Drop-in replacement for ``radar.database._CooperativeConn`` for
    tests. Wraps a plain ``sqlite3.Connection`` and exposes the same
    ``execute(...)`` + ``writing()`` surface the governor's repository
    expects. No greenlet locking — tests run single-threaded."""

    __slots__ = ("_conn", "_lock")

    def __init__(self, conn: _sqlite3.Connection):
        self._conn = conn
        self._lock = _threading.Lock()

    def execute(self, sql, parameters=()):
        return self._conn.execute(sql, parameters)

    def executemany(self, sql, seq):
        return self._conn.executemany(sql, seq)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    @_contextlib.contextmanager
    def writing(self):
        try:
            yield
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise


@pytest.fixture
def tier_governor_repo():
    """Yield a TierGovernorRepository bound to a fresh in-memory SQLite.

    The repo is auto-injected as the governor module's active repository
    for the duration of the test, then reset on teardown. Tests can
    write directly to the repo's conn (via ``repo._conn()``) for
    arrange-stage data, or call governor functions which transparently
    use the same repo.
    """
    from radar.calibration import auto_apply_tier_repository as repo_mod
    from radar.calibration.auto_apply_tier_repository import (
        TierGovernorRepository,
    )

    raw = _sqlite3.connect(":memory:", check_same_thread=False)
    raw.executescript(_TIER_GOVERNOR_TEST_SCHEMA)
    conn = _TestConn(raw)
    repo = TierGovernorRepository(conn_factory=lambda: conn)

    # Inject before the test runs; restore after.
    prior = repo_mod._REPO  # noqa: SLF001
    repo_mod.set_repository(repo)
    try:
        yield repo
    finally:
        repo_mod.set_repository(prior)
        try:
            raw.close()
        except Exception:
            pass


@pytest.fixture
def tier_governor_conn(tier_governor_repo):
    """Convenience: yield the in-memory conn behind the governor repo
    so tests can write fixture data directly via raw SQL."""
    return tier_governor_repo._conn()  # noqa: SLF001
