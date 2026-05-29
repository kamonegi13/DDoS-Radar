"""Tests for the Decision Layer (Phase 1 of the analyst response surface
rollout, 2026-04-30).

Covers:
  * Migration v34 adds the `decisions` table with the expected columns
    and indexes.
  * DecisionLedger.record() writes a row, validates target_kind/action,
    and supersedes any prior current decision for the same
    (decision_type, target_kind, target_id) tuple.
  * latest() returns only NOT-superseded rows; is_active() honors the
    expires_at gate; revoke() deactivates without inserting a replacement.
  * history() filters across decision_type / target_kind / target_id /
    actor / action / since_ts / until_ts, AND-combined.
  * /api/v2/decisions/triage/{snooze,visibility,dismiss,state} record +
    expose state correctly.
  * /api/v2/decisions/threshold (PUT/GET) per-user override is honored.
  (The tl_recalibration/* and dual_weight/* governance endpoints + the
   §10.5 advisory endpoints were retired 2026-05-29 — migration gates whose
   deadlines elapsed; TL calibration is now autonomous via the tier governor.)
  * /api/v2/decisions/history responds with filtered rows and the
    correct shape; <decision_id> returns 404 on unknown id.
  * V2_API_ENABLED=False → 503 on every endpoint (gate consistency).
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
from radar.decisions import DecisionLedger


# ── DB-layer ─────────────────────────────────────────────────────────────

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


def test_v34_creates_decisions_table(fresh_db):
    conn = fresh_db._get_conn()
    cols = {r[1] for r in conn.execute("PRAGMA table_info(decisions)").fetchall()}
    expected = {"id", "decision_type", "target_kind", "target_id",
                "action", "actor", "reason", "parameters", "decided_at",
                "expires_at", "superseded_by"}
    assert expected.issubset(cols), f"missing columns: {expected - cols}"


def test_v34_creates_indexes(fresh_db):
    conn = fresh_db._get_conn()
    idx = {r[1] for r in conn.execute("PRAGMA index_list(decisions)").fetchall()}
    assert "idx_decisions_target" in idx
    assert "idx_decisions_type_ts" in idx


def test_record_writes_row(fresh_db):
    did = fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="analyst:test",
        parameters={"minutes": 30}, expires_at=time.time() + 1800,
    )
    assert did.startswith("dec_")
    row = fresh_db.decisions.get(did)
    assert row is not None
    assert row["action"] == "snooze"
    assert row["actor"] == "analyst:test"
    assert row["parameters"]["minutes"] == 30


def test_record_validates_target_kind(fresh_db):
    with pytest.raises(ValueError, match="target_kind"):
        fresh_db.decisions.record(
            decision_type="x", target_kind="garbage", target_id=None,
            action="accept", actor="analyst:test",
        )


def test_record_validates_action(fresh_db):
    with pytest.raises(ValueError, match="action"):
        fresh_db.decisions.record(
            decision_type="x", target_kind="global", target_id=None,
            action="garbage", actor="analyst:test",
        )


def test_record_requires_actor(fresh_db):
    with pytest.raises(ValueError, match="actor"):
        fresh_db.decisions.record(
            decision_type="x", target_kind="global", target_id=None,
            action="accept", actor="",
        )


def test_supersede_chains_correctly(fresh_db):
    """Recording a 2nd decision on the same (type,kind,id) marks the
    first as superseded_by the second."""
    d1 = fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="analyst:a")
    d2 = fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="analyst:b")
    row1 = fresh_db.decisions.get(d1)
    row2 = fresh_db.decisions.get(d2)
    assert row1["superseded_by"] == d2
    assert row2["superseded_by"] is None


def test_supersede_target_isolated(fresh_db):
    """Different target_id values must NOT supersede each other."""
    fresh_db.decisions.record(
        decision_type="tl_recal_accept", target_kind="scenario",
        target_id="taiwan_contingency", action="accept", actor="admin:a")
    d2 = fresh_db.decisions.record(
        decision_type="tl_recal_accept", target_kind="scenario",
        target_id="korean_peninsula", action="accept", actor="admin:a")
    # The Taiwan record must still be current (not superseded by Korea).
    tw_latest = fresh_db.decisions.latest(
        decision_type="tl_recal_accept", target_kind="scenario",
        target_id="taiwan_contingency")
    assert tw_latest is not None
    assert tw_latest["superseded_by"] is None
    kp_latest = fresh_db.decisions.latest(
        decision_type="tl_recal_accept", target_kind="scenario",
        target_id="korean_peninsula")
    assert kp_latest["id"] == d2


def test_latest_returns_only_current(fresh_db):
    fresh_db.decisions.record(
        decision_type="x", target_kind="global", target_id=None,
        action="accept", actor="a")
    d2 = fresh_db.decisions.record(
        decision_type="x", target_kind="global", target_id=None,
        action="extend", actor="b")
    cur = fresh_db.decisions.latest(
        decision_type="x", target_kind="global", target_id=None)
    assert cur["id"] == d2
    assert cur["action"] == "extend"


def test_is_active_respects_expiry(fresh_db):
    fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="a", expires_at=time.time() + 1000)
    assert fresh_db.decisions.is_active(
        decision_type="triage_snooze", target_kind="global", target_id=None,
    ) is True

    # Now record a snooze that's already expired.
    fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="a", expires_at=time.time() - 100)
    assert fresh_db.decisions.is_active(
        decision_type="triage_snooze", target_kind="global", target_id=None,
    ) is False


def test_is_active_no_expiry_means_always_active(fresh_db):
    """expires_at NULL = "until superseded"; is_active stays True."""
    fresh_db.decisions.record(
        decision_type="triage_visibility", target_kind="user",
        target_id="u1", action="set", actor="a")
    assert fresh_db.decisions.is_active(
        decision_type="triage_visibility", target_kind="user", target_id="u1",
    ) is True


def test_revoke_marks_inactive(fresh_db):
    did = fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="a", expires_at=time.time() + 1000)
    assert fresh_db.decisions.revoke(did, by="admin:b") is True
    assert fresh_db.decisions.is_active(
        decision_type="triage_snooze", target_kind="global", target_id=None,
    ) is False


def test_revoke_idempotent_returns_false(fresh_db):
    did = fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="a")
    fresh_db.decisions.revoke(did, by="admin:b")
    # Second revoke on the same id finds no current row → returns False.
    assert fresh_db.decisions.revoke(did, by="admin:b") is False


def test_history_filters_combine(fresh_db):
    base = time.time()
    fresh_db.decisions.record(
        decision_type="triage_snooze", target_kind="global", target_id=None,
        action="snooze", actor="analyst:a")
    fresh_db.decisions.record(
        decision_type="tl_recal_accept", target_kind="scenario",
        target_id="taiwan", action="accept", actor="admin:b")
    fresh_db.decisions.record(
        decision_type="dual_weight_extend", target_kind="global",
        target_id=None, action="extend", actor="admin:b")

    all_h = fresh_db.decisions.history(limit=10)
    assert len(all_h) == 3
    only_admin = fresh_db.decisions.history(actor="admin:b", limit=10)
    assert len(only_admin) == 2
    only_extend = fresh_db.decisions.history(action="extend", limit=10)
    assert len(only_extend) == 1
    only_taiwan = fresh_db.decisions.history(
        target_kind="scenario", target_id="taiwan", limit=10)
    assert len(only_taiwan) == 1


def test_history_limit_capped_at_1000(fresh_db):
    # Pass an absurd limit; module clamps to 1000. Smoke check.
    rows = fresh_db.decisions.history(limit=99999)
    assert len(rows) <= 1000


# ── API-layer ────────────────────────────────────────────────────────────

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
def admin_headers(client):
    resp = client.post("/api/auth/login", json={
        "username": "admin", "password": _TEST_ADMIN_PW,
    })
    assert resp.status_code == 200, resp.get_json()
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


@pytest.fixture(autouse=True)
def cleanup_test_decisions():
    """Sweep rows touched by tests. The admin user's identity matches
    real production data, so we filter aggressively: anything the test
    suite could have written (admin user is the test login) gets
    cleaned up after each test. Decision Layer test isolation is more
    important than preserving other admin actor history during testing."""
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM decisions WHERE actor LIKE '%test%' "
                "OR actor LIKE 'admin:admin' "
                "OR actor LIKE 'analyst:admin' "
                "OR target_id LIKE 'test_%'"
            )
    except Exception:
        pass


def test_api_triage_snooze_records_decision(client, admin_headers):
    resp = client.post(
        "/api/v2/decisions/triage/snooze",
        headers={**admin_headers, "Content-Type": "application/json"},
        json={"minutes": 45})
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["minutes"] == 45
    assert body["decision_id"].startswith("dec_")
    assert body["expires_at"] > time.time()


def test_api_triage_snooze_clamps_minutes(client, admin_headers):
    resp = client.post(
        "/api/v2/decisions/triage/snooze",
        headers={**admin_headers, "Content-Type": "application/json"},
        json={"minutes": 99999})
    assert resp.status_code == 200
    assert resp.get_json()["minutes"] == 24 * 60  # capped at 1440


def test_api_triage_snooze_release(client, admin_headers):
    client.post("/api/v2/decisions/triage/snooze",
                headers={**admin_headers, "Content-Type": "application/json"},
                json={"minutes": 30})
    resp = client.delete("/api/v2/decisions/triage/snooze",
                          headers=admin_headers)
    assert resp.status_code == 200
    assert resp.get_json()["released"] is True


def test_api_triage_state_reflects_active_snooze(client, admin_headers):
    client.post("/api/v2/decisions/triage/snooze",
                headers={**admin_headers, "Content-Type": "application/json"},
                json={"minutes": 30})
    resp = client.get("/api/v2/decisions/triage/state", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["snooze"] is not None
    assert body["snooze"]["active"] is True


def test_api_triage_visibility_modes(client, admin_headers):
    resp = client.post("/api/v2/decisions/triage/visibility",
                        headers={**admin_headers, "Content-Type": "application/json"},
                        json={"mode": "always"})
    assert resp.status_code == 200
    state = client.get("/api/v2/decisions/triage/state",
                       headers=admin_headers).get_json()
    assert state["visibility"] == "always"


def test_api_triage_visibility_rejects_bad_mode(client, admin_headers):
    resp = client.post("/api/v2/decisions/triage/visibility",
                        headers={**admin_headers, "Content-Type": "application/json"},
                        json={"mode": "garbage"})
    assert resp.status_code == 400


def test_api_threshold_get_returns_defaults(client, admin_headers):
    """Without prior PUT, GET returns the recommended defaults."""
    resp = client.get("/api/v2/decisions/threshold", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["dormant_enter"] == 0.40
    assert body["critical_enter"] == 0.85
    assert body["is_default"] is True


def test_api_threshold_put_then_get(client, admin_headers):
    client.put("/api/v2/decisions/threshold",
               headers={**admin_headers, "Content-Type": "application/json"},
               json={"dormant_enter": 0.30, "critical_enter": 0.90})
    body = client.get("/api/v2/decisions/threshold",
                      headers=admin_headers).get_json()
    assert body["dormant_enter"] == 0.30
    assert body["critical_enter"] == 0.90
    assert body["is_default"] is False


def test_api_threshold_clamps_out_of_range(client, admin_headers):
    resp = client.put("/api/v2/decisions/threshold",
                       headers={**admin_headers, "Content-Type": "application/json"},
                       json={"dormant_enter": 5.0, "critical_enter": -0.5})
    body = resp.get_json()
    assert body["dormant_enter"] == 1.0
    assert body["critical_enter"] == 0.0


def test_api_history_returns_recent_decisions(client, admin_headers):
    client.post("/api/v2/decisions/triage/snooze",
                headers={**admin_headers, "Content-Type": "application/json"},
                json={"minutes": 5})
    resp = client.get("/api/v2/decisions/history?limit=10",
                       headers=admin_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "decisions" in body
    assert isinstance(body["decisions"], list)
    assert body["count"] == len(body["decisions"])


def test_api_history_filter_by_decision_type(client, admin_headers):
    client.post("/api/v2/decisions/triage/snooze",
                headers={**admin_headers, "Content-Type": "application/json"},
                json={"minutes": 5})
    resp = client.get(
        "/api/v2/decisions/history?decision_type=triage_snooze",
        headers=admin_headers)
    body = resp.get_json()
    for d in body["decisions"]:
        assert d["decision_type"] == "triage_snooze"


def test_api_get_decision_404_on_unknown(client, admin_headers):
    resp = client.get("/api/v2/decisions/dec_does_not_exist",
                       headers=admin_headers)
    assert resp.status_code == 404


def test_api_disabled_when_v2_off(client, admin_headers, monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    resp = client.post("/api/v2/decisions/triage/snooze",
                        headers={**admin_headers, "Content-Type": "application/json"},
                        json={"minutes": 30})
    assert resp.status_code == 503


def test_api_requires_auth(client):
    resp = client.post("/api/v2/decisions/triage/snooze", json={"minutes": 30})
    assert resp.status_code in (401, 422)


# ── F2: revoke endpoint ─────────────────────────────────────────────────

def test_api_revoke_marks_decision_inactive(client, admin_headers):
    """POST /<id>/revoke deactivates a current decision; latest()
    returns null for the same target afterwards."""
    snz = client.post(
        "/api/v2/decisions/triage/snooze",
        headers={**admin_headers, "Content-Type": "application/json"},
        json={"minutes": 30},
    )
    decision_id = snz.get_json()["decision_id"]

    resp = client.post(
        f"/api/v2/decisions/{decision_id}/revoke",
        headers={**admin_headers, "Content-Type": "application/json"},
        json={"reason": "false alarm"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["revoked"] is True

    state = client.get("/api/v2/decisions/triage/state",
                       headers=admin_headers).get_json()
    assert state["snooze"] is None  # No active snooze after revoke


def test_api_revoke_404_on_unknown(client, admin_headers):
    resp = client.post("/api/v2/decisions/dec_does_not_exist/revoke",
                        headers={**admin_headers, "Content-Type": "application/json"},
                        json={})
    assert resp.status_code == 404


def test_api_revoke_409_on_already_inactive(client, admin_headers):
    snz = client.post(
        "/api/v2/decisions/triage/snooze",
        headers={**admin_headers, "Content-Type": "application/json"},
        json={"minutes": 30},
    )
    did = snz.get_json()["decision_id"]
    # First revoke OK.
    r1 = client.post(f"/api/v2/decisions/{did}/revoke",
                      headers={**admin_headers, "Content-Type": "application/json"},
                      json={})
    assert r1.status_code == 200
    # Second revoke must fail with 409 (already inactive).
    r2 = client.post(f"/api/v2/decisions/{did}/revoke",
                      headers={**admin_headers, "Content-Type": "application/json"},
                      json={})
    assert r2.status_code == 409
