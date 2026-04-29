"""Tests for radar.legacy_telemetry — Safe Rename Pattern SR4.

Covers:
  * record_legacy_access counts correctly (single + concurrent)
  * snapshot returns immutable view (frozen dataclass + dict copy)
  * flush_to_db round-trips through the on-disk legacy_access_log table
  * hydrate_from_db restores counters across simulated restart
  * Multiple flush + hydrate cycles preserve monotonic count semantics
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time

import pytest

from radar import legacy_telemetry as lt


@pytest.fixture(autouse=True)
def _isolate_state():
    lt.reset_for_test()
    yield
    lt.reset_for_test()


@pytest.fixture
def temp_db():
    """Fresh RadarDB pointing at a tempfile so tests do not touch radar.db."""
    # RadarDB is a module-level singleton, so to test against a clean
    # DB we instantiate a new RadarDB at a temp path. Migrations will
    # run automatically and create legacy_access_log.
    from radar.database import RadarDB

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = RadarDB(path)
    yield db
    try:
        os.unlink(path)
    except OSError:
        pass


def test_record_increments_count():
    lt.record_legacy_access("Participant.theater", now=1000.0)
    lt.record_legacy_access("Participant.theater", now=1010.0)
    snap = lt.snapshot()
    stat = snap["Participant.theater"]
    assert stat.count == 2
    assert stat.first_seen == 1000.0
    assert stat.last_seen == 1010.0


def test_record_distinct_keys():
    lt.record_legacy_access("a", now=1.0)
    lt.record_legacy_access("b", now=2.0)
    snap = lt.snapshot()
    assert set(snap.keys()) == {"a", "b"}
    assert snap["a"].count == 1
    assert snap["b"].count == 1


def test_record_empty_key_is_noop():
    lt.record_legacy_access("", now=1.0)
    assert lt.snapshot() == {}


def test_snapshot_is_immutable_view():
    lt.record_legacy_access("k", now=1.0)
    snap1 = lt.snapshot()
    # Mutating returned dict must not affect internal state
    snap1["k"] = None  # type: ignore[assignment]
    snap1["new"] = None  # type: ignore[assignment]
    snap2 = lt.snapshot()
    assert "new" not in snap2
    assert snap2["k"].count == 1


def test_snapshot_dataclass_is_frozen():
    lt.record_legacy_access("k", now=1.0)
    stat = lt.snapshot()["k"]
    with pytest.raises(Exception):  # FrozenInstanceError
        stat.count = 999  # type: ignore[misc]


def test_concurrent_record_no_lost_updates():
    """100 threads * 100 increments = exactly 10000 counts."""
    THREADS, PER_THREAD = 100, 100

    def worker():
        for _ in range(PER_THREAD):
            lt.record_legacy_access("hot_key")

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert lt.snapshot()["hot_key"].count == THREADS * PER_THREAD


def test_flush_roundtrip(temp_db):
    lt.record_legacy_access("k1", now=100.0)
    lt.record_legacy_access("k1", now=200.0)
    lt.record_legacy_access("k2", now=150.0)

    flushed = lt.flush_to_db(temp_db)
    assert flushed == 2

    # Simulate process restart: reset memory and hydrate from disk.
    lt.reset_for_test()
    loaded = lt.hydrate_from_db(temp_db)
    assert loaded == 2

    snap = lt.snapshot()
    assert snap["k1"].count == 2
    assert snap["k1"].first_seen == 100.0
    assert snap["k1"].last_seen == 200.0
    assert snap["k2"].count == 1


def test_flush_is_upsert_not_insert(temp_db):
    """Flushing the same key twice must not create duplicate rows."""
    lt.record_legacy_access("k", now=1.0)
    lt.flush_to_db(temp_db)
    lt.record_legacy_access("k", now=2.0)
    lt.flush_to_db(temp_db)

    rows = temp_db._get_conn().execute(
        "SELECT key, count, first_seen, last_seen FROM legacy_access_log WHERE key='k'"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["count"] == 2
    assert rows[0]["first_seen"] == 1.0
    assert rows[0]["last_seen"] == 2.0


def test_hydrate_idempotent(temp_db):
    lt.record_legacy_access("k", now=1.0)
    lt.flush_to_db(temp_db)
    lt.reset_for_test()
    n1 = lt.hydrate_from_db(temp_db)
    n2 = lt.hydrate_from_db(temp_db)  # Second call must be a no-op
    assert n1 == 1
    assert n2 == 0
    assert lt.snapshot()["k"].count == 1


def test_hydrate_then_record_extends(temp_db):
    """After hydrate, new record() calls add to the loaded count."""
    lt.record_legacy_access("k", now=1.0)
    lt.flush_to_db(temp_db)
    lt.reset_for_test()
    lt.hydrate_from_db(temp_db)

    lt.record_legacy_access("k", now=2.0)
    snap = lt.snapshot()
    assert snap["k"].count == 2
    assert snap["k"].first_seen == 1.0
    assert snap["k"].last_seen == 2.0


def test_flush_preserves_min_first_seen(temp_db):
    """If a flush carries an earlier first_seen than what's on disk
    (e.g. clock skew or out-of-order processes), the minimum wins."""
    lt.record_legacy_access("k", now=500.0)
    lt.flush_to_db(temp_db)
    lt.reset_for_test()

    # Now record a NEW, earlier first_seen (simulating that this key was
    # actually first seen earlier than the disk thought).
    lt.record_legacy_access("k", now=100.0)
    lt.flush_to_db(temp_db)

    row = temp_db._get_conn().execute(
        "SELECT first_seen, last_seen FROM legacy_access_log WHERE key='k'"
    ).fetchone()
    # first_seen is the MIN of disk + flush; last_seen is the MAX
    assert row["first_seen"] == 100.0
    assert row["last_seen"] == 500.0


# summarize_v1_sunset and its 3 tests were removed 2026-04-29 alongside
# the early ADR-V2-003 sunset. The helper observed v1_sunset_route:* hits;
# the routes themselves no longer exist. Base SR4 telemetry tests above
# remain and continue to cover the per-key counter contract.
