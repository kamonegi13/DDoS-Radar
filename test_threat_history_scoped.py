"""Tests for the per-scenario threat_history pipeline (HUD divergence
fix 2026-04-29 — commits V/W/X/Y).

Migration v33 adds a `scenario_id` column to threat_history so the
HUD sparkline can pull per-scenario TL series instead of the legacy
"any-scenario, whichever-was-focused" mishmash that caused the
HUD/sparkline/FOCUS-card divergence.

These tests verify:
  * threat_history rows carry a scenario_id after migration v33
  * threat_append_scoped() writes (ts, level, scenario_id) correctly
  * threat_list_scoped() returns only the requested scenario, ordered
    ascending by id, capped at the limit, optionally filtered by
    since_ts
  * threat_last_scoped() returns the most recent row per scenario
  * Legacy threat_append() preserves NULL scenario_id for back-compat
  * Per-scenario retention is independent (scenario A overflow does
    not evict scenario B rows)
  * /api/v2/scenarios/<id>/threat_history responds with the scoped
    series, NP7 disclaimer, and rejects out-of-range hours/limit
    gracefully
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import tempfile
import time

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar.database import RadarDB, db


# ───────────────────────────────────────────────────────────────────────
# DB-layer tests (use a fresh tempfile DB so we don't touch
# radar/persistence/radar.db)
# ───────────────────────────────────────────────────────────────────────

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


def test_v33_adds_scenario_id_column(fresh_db):
    """Migration v33 must add a scenario_id column to threat_history."""
    conn = fresh_db._get_conn()
    rows = conn.execute("PRAGMA table_info(threat_history)").fetchall()
    col_names = {r[1] for r in rows}
    assert "scenario_id" in col_names, (
        f"v33 did not add scenario_id (cols={col_names})"
    )


def test_threat_append_scoped_writes_scenario_id(fresh_db):
    """threat_append_scoped writes the scenario_id verbatim."""
    ts = time.time()
    fresh_db.threat_append_scoped(ts, 3, "test_taiwan")

    conn = fresh_db._get_conn()
    row = conn.execute(
        "SELECT ts, threat_level, scenario_id FROM threat_history "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    assert abs(row[0] - ts) < 0.01
    assert row[1] == 3
    assert row[2] == "test_taiwan"


def test_threat_append_legacy_writes_null_scenario(fresh_db):
    """Legacy unscoped threat_append must record scenario_id=NULL.

    Back-compat: paths that don't track scenario context still need
    to write history rows. They are excluded from per-scenario reads.
    """
    fresh_db.threat_append(time.time(), 4)

    conn = fresh_db._get_conn()
    row = conn.execute(
        "SELECT scenario_id FROM threat_history ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row[0] is None


def test_threat_list_scoped_filters_by_scenario(fresh_db):
    """threat_list_scoped returns only the requested scenario_id rows."""
    base = time.time()
    fresh_db.threat_append_scoped(base + 0.1, 2, "scenario_a")
    fresh_db.threat_append_scoped(base + 0.2, 3, "scenario_b")
    fresh_db.threat_append_scoped(base + 0.3, 4, "scenario_a")
    fresh_db.threat_append_scoped(base + 0.4, 5, "scenario_b")

    rows_a = fresh_db.threat_list_scoped("scenario_a")
    rows_b = fresh_db.threat_list_scoped("scenario_b")

    levels_a = [r[1] for r in rows_a]
    levels_b = [r[1] for r in rows_b]

    assert levels_a == [2, 4]
    assert levels_b == [3, 5]


def test_threat_list_scoped_respects_since_ts(fresh_db):
    """since_ts filters out rows older than the threshold."""
    base = time.time()
    fresh_db.threat_append_scoped(base - 100, 1, "scenario_a")
    fresh_db.threat_append_scoped(base - 50, 2, "scenario_a")
    fresh_db.threat_append_scoped(base - 10, 3, "scenario_a")

    rows = fresh_db.threat_list_scoped("scenario_a", since_ts=base - 60)
    levels = [r[1] for r in rows]
    assert 1 not in levels
    assert 2 in levels
    assert 3 in levels


def test_threat_list_scoped_respects_limit(fresh_db):
    """limit caps the number of returned rows."""
    base = time.time()
    for i in range(20):
        fresh_db.threat_append_scoped(base + i * 0.1, (i % 5) + 1,
                                       "scenario_a")

    rows = fresh_db.threat_list_scoped("scenario_a", limit=5)
    assert len(rows) == 5


def test_threat_last_scoped_returns_most_recent(fresh_db):
    """threat_last_scoped returns the highest-id row for the scenario."""
    base = time.time()
    fresh_db.threat_append_scoped(base + 0.1, 2, "scenario_a")
    fresh_db.threat_append_scoped(base + 0.2, 3, "scenario_b")
    fresh_db.threat_append_scoped(base + 0.3, 4, "scenario_a")

    last_a = fresh_db.threat_last_scoped("scenario_a")
    last_b = fresh_db.threat_last_scoped("scenario_b")
    assert last_a is not None and last_a[1] == 4
    assert last_b is not None and last_b[1] == 3


def test_threat_last_scoped_unknown_scenario_returns_none(fresh_db):
    """No history for a scenario → None (not an exception)."""
    assert fresh_db.threat_last_scoped("never_existed") is None


def test_per_scenario_retention_is_independent(fresh_db):
    """Filling scenario_a past max_entries does not evict scenario_b.

    Pre-v33 the retention was a global LIMIT on threat_history, so a
    chatty scenario could starve a quieter one. v33 partitions
    retention by scenario_id.
    """
    base = time.time()
    # Two scenario_b rows we want to survive.
    fresh_db.threat_append_scoped(base, 5, "scenario_b", max_entries=10)
    fresh_db.threat_append_scoped(base + 0.001, 4, "scenario_b",
                                   max_entries=10)
    # Flood scenario_a with 30 rows at max_entries=10 — should keep
    # only the latest 10 of A, but B's two rows must survive.
    for i in range(30):
        fresh_db.threat_append_scoped(base + 1 + i * 0.01, (i % 5) + 1,
                                       "scenario_a", max_entries=10)

    rows_a = fresh_db.threat_list_scoped("scenario_a", limit=100)
    rows_b = fresh_db.threat_list_scoped("scenario_b", limit=100)
    assert len(rows_a) == 10
    assert len(rows_b) == 2
    levels_b = sorted(r[1] for r in rows_b)
    assert levels_b == [4, 5]


def test_legacy_threat_list_returns_all_rows(fresh_db):
    """Legacy threat_list keeps NULL-and-scoped rows mixed (back-compat)."""
    base = time.time()
    fresh_db.threat_append_scoped(base + 0.1, 2, "scenario_a")
    fresh_db.threat_append(base + 0.2, 3)  # NULL
    fresh_db.threat_append_scoped(base + 0.3, 4, "scenario_b")

    rows = fresh_db.threat_list()
    assert len(rows) == 3


# ───────────────────────────────────────────────────────────────────────
# API-layer tests for /api/v2/scenarios/<id>/threat_history
# (use the project DB via the test client; sweep test_* rows after.)
# ───────────────────────────────────────────────────────────────────────

from radar_api import app
from radar import config
from radar.auth import _hash_password


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def enable_v2_api(monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", True)
    yield


@pytest.fixture(autouse=True)
def reset_admin_pw():
    user = db.user_get("admin")
    if user is not None:
        salt = secrets.token_hex(16)
        db.user_update_password(
            user["id"], _hash_password(_TEST_ADMIN_PW, salt), salt,
        )
    yield


@pytest.fixture
def auth_headers(client):
    resp = client.post("/api/auth/login", json={
        "username": "admin", "password": _TEST_ADMIN_PW,
    })
    assert resp.status_code == 200, resp.get_json()
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


@pytest.fixture(autouse=True)
def cleanup_test_threat_rows():
    """Sweep test rows after every test. Test scenarios are namespaced
    `test_*` so this never touches real history.
    """
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM threat_history WHERE scenario_id LIKE 'test_%'"
            )
    except Exception:
        pass


def test_api_threat_history_returns_scoped_series(client, auth_headers):
    """Endpoint returns the scoped TL series for one scenario."""
    base = time.time()
    db.threat_append_scoped(base - 30, 2, "test_taiwan")
    db.threat_append_scoped(base - 20, 3, "test_taiwan")
    db.threat_append_scoped(base - 10, 4, "test_korea")

    resp = client.get(
        "/api/v2/scenarios/test_taiwan/threat_history?hours=1",
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()

    assert body["api_version"] == "2.0"
    assert body["scenario_id"] == "test_taiwan"
    assert body["hours"] == 1
    assert "final_judgment_disclaimer" in body

    levels = [row[1] for row in body["history"]]
    assert 2 in levels and 3 in levels
    assert 4 not in levels  # belongs to test_korea, must be excluded


def test_api_threat_history_clamps_hours(client, auth_headers):
    """hours > 168 should clamp to 168, hours < 1 should clamp to 1."""
    resp_high = client.get(
        "/api/v2/scenarios/test_taiwan/threat_history?hours=9999",
        headers=auth_headers,
    )
    assert resp_high.status_code == 200
    assert resp_high.get_json()["hours"] == 168

    resp_low = client.get(
        "/api/v2/scenarios/test_taiwan/threat_history?hours=0",
        headers=auth_headers,
    )
    assert resp_low.status_code == 200
    assert resp_low.get_json()["hours"] == 1


def test_api_threat_history_handles_garbage_params(client, auth_headers):
    """Non-numeric hours/limit fall back to defaults instead of 500."""
    resp = client.get(
        "/api/v2/scenarios/test_taiwan/threat_history?hours=banana&limit=oops",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["hours"] == 24


def test_api_threat_history_unknown_scenario_returns_empty(client, auth_headers):
    """No rows for a scenario → empty history (not 404)."""
    resp = client.get(
        "/api/v2/scenarios/test_never_existed/threat_history",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["scenario_id"] == "test_never_existed"
    assert body["history"] == []


def test_api_threat_history_disabled_when_v2_off(client, auth_headers,
                                                  monkeypatch):
    """V2_API_ENABLED=False → 503, not 404 (v2 gate)."""
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    resp = client.get(
        "/api/v2/scenarios/test_taiwan/threat_history",
        headers=auth_headers,
    )
    assert resp.status_code == 503


def test_api_threat_history_requires_auth(client):
    """No JWT → 401 (the global before_request gate).

    Confirms the endpoint is not accidentally exposed unauthenticated.
    """
    resp = client.get("/api/v2/scenarios/test_taiwan/threat_history")
    assert resp.status_code in (401, 422)
