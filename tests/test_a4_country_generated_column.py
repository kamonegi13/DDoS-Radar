"""Tests for ADR-V2-006 Safe Rename Pattern A-4 — generated `country` column.

Migration v24 adds a VIRTUAL `country` column to every table that carries
the legacy `theater` column. The column is computed as `theater`, so SELECT
sites can read either name and INSERT sites still write `theater`.

These tests verify:
  * Every expected table gets a `country` column after migration
  * `country` reflects whatever was inserted into `theater` (read coherence)
  * `country` cannot be written directly (generated column write fails)
  * Migration is idempotent (running v24 against a DB that already has the
    column is a no-op, not an error)
  * Indexes on `theater` continue to work (no schema regression)
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time

import pytest

from radar.database import RadarDB, _A4_THEATER_TABLES, _migration_v24_generated_country


@pytest.fixture
def fresh_db():
    """Fresh RadarDB at a tempfile so we don't touch radar/persistence/radar.db."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = RadarDB(path)
    yield db
    try:
        os.unlink(path)
    except OSError:
        pass


def test_every_a4_table_has_country_column(fresh_db):
    """Migration v24 must add `country` to every table in the A-4 list."""
    conn = fresh_db._get_conn()
    missing: list[str] = []
    for table in _A4_THEATER_TABLES:
        rows = conn.execute(f"PRAGMA table_xinfo({table})").fetchall()
        col_names = {r[1] for r in rows}
        if "country" not in col_names:
            missing.append(table)
    assert not missing, f"v24 did not add `country` to: {missing}"


def test_country_mirrors_theater_on_read(fresh_db):
    """Insert into `theater`, read back via `country` — must be equal."""
    conn = fresh_db._get_conn()
    with conn.writing():
        conn.execute(
            "INSERT INTO sequence_events (theater, ts, event_type, meta_json) "
            "VALUES (?, ?, ?, ?)",
            ("TW", time.time(), "TEST_EVENT", "{}"),
        )
    row = conn.execute(
        "SELECT theater, country FROM sequence_events WHERE event_type='TEST_EVENT'"
    ).fetchone()
    assert row is not None
    assert row[0] == "TW"
    assert row[1] == "TW"
    assert row[0] == row[1]


def test_country_is_writeprotected(fresh_db):
    """Writing to a generated column must fail per SQLite semantics."""
    conn = fresh_db._get_conn()
    with pytest.raises(sqlite3.OperationalError):
        with conn.writing():
            conn.execute(
                "INSERT INTO sequence_events (country, ts, event_type, meta_json) "
                "VALUES (?, ?, ?, ?)",
                ("TW", time.time(), "BAD", "{}"),
            )


def test_country_can_be_filtered_in_where(fresh_db):
    """SELECT ... WHERE country=? must return the same rows as WHERE theater=?."""
    conn = fresh_db._get_conn()
    now = time.time()
    with conn.writing():
        conn.execute(
            "INSERT INTO sequence_events (theater, ts, event_type, meta_json) VALUES (?, ?, ?, ?)",
            ("TW", now, "EV1", "{}"),
        )
        conn.execute(
            "INSERT INTO sequence_events (theater, ts, event_type, meta_json) VALUES (?, ?, ?, ?)",
            ("JP", now, "EV2", "{}"),
        )
    by_theater = conn.execute(
        "SELECT id FROM sequence_events WHERE theater='TW' AND event_type LIKE 'EV%'"
    ).fetchall()
    by_country = conn.execute(
        "SELECT id FROM sequence_events WHERE country='TW' AND event_type LIKE 'EV%'"
    ).fetchall()
    assert sorted(r[0] for r in by_theater) == sorted(r[0] for r in by_country)
    assert len(by_country) == 1


def test_v24_migration_is_idempotent(fresh_db):
    """Running the v24 helper on an already-migrated DB must be a no-op."""
    conn = fresh_db._get_conn()
    # First run already happened during RadarDB(...) init. Re-run by hand:
    with conn.writing():
        _migration_v24_generated_country(conn)
    # Still exactly one country column per table.
    for table in _A4_THEATER_TABLES:
        rows = conn.execute(f"PRAGMA table_xinfo({table})").fetchall()
        country_cols = [r for r in rows if r[1] == "country"]
        assert len(country_cols) == 1, (
            f"{table}: expected exactly one country column, got {len(country_cols)}"
        )


def test_existing_theater_index_still_used(fresh_db):
    """A-4 must not break existing `(theater, ...)` indexes."""
    conn = fresh_db._get_conn()
    indexes = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='sequence_events'"
    ).fetchall()
    index_names = [r[0] for r in indexes]
    assert any("theater" in n for n in index_names), (
        f"expected a (theater, ...) index on sequence_events; got {index_names}"
    )


def test_a4_table_list_matches_actual_schema(fresh_db):
    """Guard against drift: every name in _A4_THEATER_TABLES must be a real table."""
    conn = fresh_db._get_conn()
    real_tables = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    missing = [t for t in _A4_THEATER_TABLES if t not in real_tables]
    assert not missing, f"_A4_THEATER_TABLES references non-existent tables: {missing}"
