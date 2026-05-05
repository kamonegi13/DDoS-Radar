"""Tests for Phase 1 — snoozed_30d auto-revival sweep.

Pre-fix bug: when an analyst clicks "Defer 30 days" on a Wizard
proposal, the row state is set to 'snoozed_30d'. There was NO sweep
logic to revert it to 'pending' after 30 days, so deferred proposals
were effectively lost forever.

Phase 1 fix adds a sweep in cleanup_old_data() that:
  * scans rows with state='snoozed_30d'
  * if state_changed_at < now - PROPOSAL_SNOOZE_DAYS*86400
  * sets state='pending', state_changed_at=now,
    state_changed_by='auto:snooze_expired'
  * returns count in deleted["proposals_snooze_revived"]

env override: PROPOSAL_SNOOZE_DAYS (default 30)
"""
from __future__ import annotations

import os
import tempfile
import time

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

from radar.database import RadarDB


@pytest.fixture
def fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    instance = RadarDB(path)
    yield instance
    try:
        os.unlink(path)
    except OSError:
        pass


def _seed_snooze(db, scenario_id, target_country, days_ago):
    now = time.time()
    state_changed_at = now - days_ago * 86400
    conn = db._get_conn()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, sample_n, "
            " why_string, state, state_changed_at, state_changed_by) "
            "VALUES (?, ?, 'weight_too_high', ?, ?, ?, ?, ?, ?, "
            "        'snoozed_30d', ?, 'analyst:test')",
            (state_changed_at, scenario_id, target_country,
             "{}", "{}", "test/v1#snooze", 5, "snoozed for test",
             state_changed_at),
        )
        return cur.lastrowid


def test_snooze_expired_row_revives_to_pending(fresh_db):
    """31-day-old snoozed_30d row should auto-revive to pending."""
    rid = _seed_snooze(fresh_db, "test_snz_old", "TW", days_ago=31)

    fresh_db._revive_expired_snoozed_proposals()

    conn = fresh_db._get_conn()
    row = conn.execute(
        "SELECT state, state_changed_by FROM scenario_proposals WHERE id=?",
        (rid,),
    ).fetchone()
    assert row["state"] == "pending"
    assert row["state_changed_by"] == "auto:snooze_expired"


def test_recent_snooze_row_unchanged(fresh_db):
    """10-day-old snoozed_30d row should remain snoozed_30d."""
    rid = _seed_snooze(fresh_db, "test_snz_recent", "TW", days_ago=10)

    fresh_db._revive_expired_snoozed_proposals()

    conn = fresh_db._get_conn()
    row = conn.execute(
        "SELECT state, state_changed_by FROM scenario_proposals WHERE id=?",
        (rid,),
    ).fetchone()
    assert row["state"] == "snoozed_30d"
    assert row["state_changed_by"] == "analyst:test"


def test_cleanup_returns_revived_count(fresh_db):
    """Return dict should report how many rows were revived."""
    _seed_snooze(fresh_db, "test_snz_a", "TW", days_ago=31)
    _seed_snooze(fresh_db, "test_snz_b", "JP", days_ago=45)
    _seed_snooze(fresh_db, "test_snz_c", "KR", days_ago=10)  # not yet expired

    revived = fresh_db._revive_expired_snoozed_proposals()
    assert revived == 2


def test_env_override_for_snooze_days(fresh_db, monkeypatch):
    """Setting PROPOSAL_SNOOZE_DAYS=7 should revive rows older than 7d."""
    monkeypatch.setenv("PROPOSAL_SNOOZE_DAYS", "7")
    rid_old = _seed_snooze(fresh_db, "test_snz_env_old", "TW", days_ago=8)
    rid_new = _seed_snooze(fresh_db, "test_snz_env_new", "JP", days_ago=5)

    fresh_db._revive_expired_snoozed_proposals()

    conn = fresh_db._get_conn()
    state_old = conn.execute(
        "SELECT state FROM scenario_proposals WHERE id=?", (rid_old,)
    ).fetchone()["state"]
    state_new = conn.execute(
        "SELECT state FROM scenario_proposals WHERE id=?", (rid_new,)
    ).fetchone()["state"]
    assert state_old == "pending"
    assert state_new == "snoozed_30d"


def test_only_snoozed_state_affected(fresh_db):
    """A 31-day-old 'dismissed' row must NOT be touched by the snooze sweep."""
    now = time.time()
    state_changed_at = now - 31 * 86400
    conn = fresh_db._get_conn()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, sample_n, "
            " why_string, state, state_changed_at, state_changed_by) "
            "VALUES (?, 'test_dismissed', 'weight_too_high', 'TW', "
            "        '{}', '{}', 'test/v1', 5, 'dismissed', "
            "        'dismissed', ?, 'analyst:x')",
            (state_changed_at, state_changed_at),
        )
        rid = cur.lastrowid

    fresh_db._revive_expired_snoozed_proposals()

    state = conn.execute(
        "SELECT state FROM scenario_proposals WHERE id=?", (rid,)
    ).fetchone()["state"]
    assert state == "dismissed"
