"""pytest root conftest.

gevent's monkey-patch must run BEFORE any module imports `ssl`,
`socket`, `threading`, etc. When pytest collects multiple test files
in one session, files that import `radar.*` directly (without going
through `radar_api`) cause `ssl` to load unpatched. A subsequent
`from radar_api import ...` then triggers a second-pass patch_all()
which corrupts gevent's thread.get_ident, raising:
  "RuntimeError: cannot release un-acquired lock"
during collection of later files (e.g. test_engine, test_auth,
test_analyst_permissions).

Patching here, before any test module is imported, guarantees a
single consistent patched runtime for the entire test session.
"""
from gevent import monkey as _monkey

_monkey.patch_all()

# Phase 7.5a (audit Security H5): flask-limiter is initialised at import
# time in radar/__init__.py with default limits of 120/min + 2000/hour.
# pytest fires hundreds of requests per minute against the in-process
# Flask test client, which would trip the cap and convert legitimate
# behaviour-under-test into 429 storms. Set the opt-out env var BEFORE
# any test imports `radar` so the limiter constructor sees enabled=False.
import os as _os
_os.environ.setdefault("RADAR_RATE_LIMIT_ENABLED", "false")

# Phase 7.5g (audit Security H3): the cookie-based refresh flow uses
# CSRF double-submit by default. The Flask test client cannot easily
# round-trip the CSRF cookie through every fixture, so opt out at
# import time. Production keeps the protection on (default).
_os.environ.setdefault("RADAR_JWT_CSRF_DISABLED", "true")
# Cookie Secure=true would force the test client (HTTP, no TLS) to
# silently drop the refresh cookie. Disable for the test environment.
_os.environ.setdefault("JWT_COOKIE_SECURE", "false")


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

import contextlib as _contextlib
import sqlite3 as _sqlite3
import threading as _threading

import pytest


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
