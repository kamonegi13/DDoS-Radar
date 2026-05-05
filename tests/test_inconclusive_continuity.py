"""Tests for the chronic-inconclusive detector (ADR-V2-010 / NP5+8).

Covers ``radar.conclusions.inconclusive_continuity.compute_states`` and
``chronic_snapshot``, and the ``GET /api/v2/observability/chronic_inconclusive``
endpoint that exposes the snapshot.

The aggregator runs read-only against ``inconclusive_continuity_log``;
each test arranges rows directly via ``db._get_conn()`` then asserts
the classification.
"""
from __future__ import annotations

import os
import secrets
import time

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD",
                                        "TestAdminPass123!")

import pytest  # noqa: E402

from radar import config  # noqa: E402
from radar.auth import _hash_password  # noqa: E402
from radar.conclusions import inconclusive_continuity as ic  # noqa: E402
from radar.database import db  # noqa: E402
from radar_api import app  # noqa: E402


# ── Setup ────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_continuity_log():
    """Snapshot + restore the continuity log around every test so
    production data is not perturbed. The table is small (transition
    events only) so this is cheap."""
    conn = db._get_conn()  # noqa: SLF001
    rows = list(conn.execute(
        "SELECT id, observed_at, scenario_id, conclusion_type, "
        "is_available, reason, run_length_sec, first_seen_at, metadata "
        "FROM inconclusive_continuity_log"
    ))
    with conn.writing():
        conn.execute("DELETE FROM inconclusive_continuity_log")
    yield
    with conn.writing():
        conn.execute("DELETE FROM inconclusive_continuity_log")
        for r in rows:
            conn.execute(
                "INSERT INTO inconclusive_continuity_log "
                "(id, observed_at, scenario_id, conclusion_type, "
                " is_available, reason, run_length_sec, first_seen_at, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(r),
            )


def _insert(scenario_id, conclusion_type, *,
            observed_at, first_seen_at, is_available=0,
            reason="INSUFFICIENT_DATA"):
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        conn.execute(
            "INSERT INTO inconclusive_continuity_log "
            "(observed_at, scenario_id, conclusion_type, is_available, "
            " reason, run_length_sec, first_seen_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (observed_at, scenario_id, conclusion_type, int(is_available),
             reason, max(0.0, observed_at - first_seen_at),
             first_seen_at, "{}"),
        )


# ── compute_states / chronic_snapshot unit tests ─────────────────────────────


class TestComputeStates:
    def test_empty_table_returns_no_states(self):
        assert ic.compute_states(db) == []

    def test_open_run_under_threshold_is_transient(self):
        now = time.time()
        # 3 days ago opened, no close → open run, 3d.
        _insert("scenario_a", "threat_level",
                observed_at=now - 3 * 86400.0,
                first_seen_at=now - 3 * 86400.0)
        states = ic.compute_states(db, now=now, threshold_days=7.0)
        assert len(states) == 1
        s = states[0]
        assert s.is_chronic is False
        assert 2.5 < s.days_unavailable < 3.5

    def test_open_run_at_threshold_is_chronic(self):
        now = time.time()
        _insert("scenario_b", "threat_level",
                observed_at=now - 7.5 * 86400.0,
                first_seen_at=now - 7.5 * 86400.0)
        states = ic.compute_states(db, now=now, threshold_days=7.0)
        assert len(states) == 1
        assert states[0].is_chronic is True

    def test_intervening_close_resets_clock(self):
        """Run opened 10d ago, closed 5d ago, reopened 2d ago. Latest
        row is the reopen → 2d, transient."""
        now = time.time()
        _insert("scenario_c", "anomaly",
                observed_at=now - 10 * 86400.0,
                first_seen_at=now - 10 * 86400.0)
        _insert("scenario_c", "anomaly",
                observed_at=now - 5 * 86400.0,
                first_seen_at=now - 10 * 86400.0,
                is_available=1, reason="resolved")
        _insert("scenario_c", "anomaly",
                observed_at=now - 2 * 86400.0,
                first_seen_at=now - 2 * 86400.0)
        states = ic.compute_states(db, now=now, threshold_days=7.0)
        assert len(states) == 1
        s = states[0]
        assert s.is_chronic is False
        assert 1.5 < s.days_unavailable < 2.5

    def test_closed_run_not_returned(self):
        """If the latest row is is_available=1 there is no current
        unavailability — the pair is omitted from results entirely."""
        now = time.time()
        _insert("scenario_d", "trend",
                observed_at=now - 5 * 86400.0,
                first_seen_at=now - 5 * 86400.0)
        _insert("scenario_d", "trend",
                observed_at=now - 1 * 86400.0,
                first_seen_at=now - 5 * 86400.0,
                is_available=1, reason="resolved")
        states = ic.compute_states(db, now=now, threshold_days=7.0)
        assert states == []

    def test_multi_pair_isolation_and_ordering(self):
        """Chronic-first ordering: TW chronic (10d), JP transient (2d).
        Each pair is computed independently."""
        now = time.time()
        _insert("scenario_tw", "threat_level",
                observed_at=now - 10 * 86400.0,
                first_seen_at=now - 10 * 86400.0)
        _insert("scenario_jp", "threat_level",
                observed_at=now - 2 * 86400.0,
                first_seen_at=now - 2 * 86400.0)
        states = ic.compute_states(db, now=now, threshold_days=7.0)
        assert len(states) == 2
        # Chronic appears first.
        assert states[0].is_chronic is True
        assert states[0].scenario_id == "scenario_tw"
        assert states[1].is_chronic is False
        assert states[1].scenario_id == "scenario_jp"

    def test_threshold_floor_is_three_days(self):
        """Even if the operator passes `threshold_days=0.1`, the floor
        of 3 days holds — a routine sensor outage cannot trip chronic."""
        now = time.time()
        _insert("scenario_e", "threat_level",
                observed_at=now - 1.0 * 86400.0,
                first_seen_at=now - 1.0 * 86400.0)
        states = ic.compute_states(db, now=now, threshold_days=0.1)
        assert states[0].is_chronic is False  # floor=3d > 1d


class TestChronicSnapshot:
    def test_envelope_shape(self):
        now = time.time()
        _insert("scenario_chronic", "threat_level",
                observed_at=now - 14 * 86400.0,
                first_seen_at=now - 14 * 86400.0)
        _insert("scenario_transient", "anomaly",
                observed_at=now - 1 * 86400.0,
                first_seen_at=now - 1 * 86400.0)
        snap = ic.chronic_snapshot(db, now=now)
        assert snap["computed_at"] == pytest.approx(now)
        assert snap["threshold_days"] >= 3.0
        assert snap["summary"]["total"] == 2
        assert snap["summary"]["chronic_count"] == 1
        assert snap["summary"]["transient_count"] == 1
        assert len(snap["chronic"]) == 1
        assert snap["chronic"][0]["scenario_id"] == "scenario_chronic"
        assert len(snap["transient"]) == 1
        assert snap["transient"][0]["scenario_id"] == "scenario_transient"

    def test_swallows_db_errors(self, monkeypatch):
        def _boom(*_a, **_kw):
            raise RuntimeError("simulated DB outage")
        monkeypatch.setattr(ic, "compute_states", _boom)
        snap = ic.chronic_snapshot(db)
        # NP3 — we get a well-formed envelope with empty lists + error
        # rather than an exception.
        assert snap["summary"]["chronic_count"] == 0
        assert snap["chronic"] == []
        assert snap["transient"] == []
        assert "error" in snap


# ── HTTP endpoint integration tests ──────────────────────────────────────────


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def enable_v2(monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", True)
    yield


@pytest.fixture(autouse=True)
def reset_admin_pw():
    user = db.user_get("admin")
    if user is None:
        pytest.skip("no admin user provisioned")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(_TEST_ADMIN_PW, salt)
    db.user_update_password(user["id"], pw_hash, salt)
    yield


@pytest.fixture
def admin_headers(client):
    r = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": _TEST_ADMIN_PW},
    )
    return {"Authorization": f"Bearer {r.get_json()['access_token']}"}


def test_endpoint_requires_authentication(client):
    r = client.get("/api/v2/observability/chronic_inconclusive")
    assert r.status_code == 401


def test_endpoint_returns_v2_envelope_and_data(client, admin_headers):
    now = time.time()
    _insert("scenario_endpoint", "threat_level",
            observed_at=now - 9 * 86400.0,
            first_seen_at=now - 9 * 86400.0)
    r = client.get(
        "/api/v2/observability/chronic_inconclusive",
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    # Envelope.
    for k in ("api_version", "observed_at", "final_judgment_disclaimer",
              "data"):
        assert k in body
    # Snapshot shape.
    data = body["data"]
    assert data["summary"]["chronic_count"] == 1
    assert data["chronic"][0]["scenario_id"] == "scenario_endpoint"
    assert data["chronic"][0]["is_chronic"] is True
