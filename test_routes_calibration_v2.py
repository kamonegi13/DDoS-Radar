"""Tests for radar.routes.calibration_v2 (Tier 1, commit 3).

Covers:
- v2 disabled → 503
- unauthenticated → 401
- analyst on POST → 403
- threshold_history list / single / revert (with state codes)
- sensor_disable list / ack
- scenario_improver list / apply / dismiss / defer

Tests use the project DB and clean up rows by seeding distinguishable
namespaces (scenario_id LIKE 'test_calv2_%', sensor names with 'test_'
prefix, threshold_history keys 'test_calv2.*').
"""
from __future__ import annotations

import json
import os
import secrets
import time

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar_api import app  # noqa: E402
from radar import config  # noqa: E402
from radar.auth import _hash_password  # noqa: E402
from radar.calibration import scenario_improver, threshold_history  # noqa: E402
from radar.calibration.scenario_improver import ProposalEvent  # noqa: E402
from radar.database import db  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def enable_v2_api(monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", True)
    yield


def _ensure_admin_pw() -> None:
    user = db.user_get("admin")
    if user is None:
        pytest.skip("no admin user")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(_TEST_ADMIN_PW, salt)
    db.user_update_password(user["id"], pw_hash, salt)


@pytest.fixture(autouse=True)
def reset_admin_pw():
    _ensure_admin_pw()
    yield


def _make_user(username: str, role: str, password: str = "TestPass_123456") -> None:
    existing = db.user_get(username)
    if existing:
        salt = secrets.token_hex(16)
        pw_hash = _hash_password(password, salt)
        db.user_update_password(existing["id"], pw_hash, salt)
        conn = db._get_conn()
        with conn.writing():
            conn.execute("UPDATE users SET role=? WHERE id=?", (role, existing["id"]))
        return
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)
    uid = db.user_create(username, pw_hash, salt, role, time.time())
    db.user_settings_create(uid, None, "[]", "en", time.time())


def _login(client, user: str, pw: str) -> str:
    resp = client.post("/api/auth/login", json={"username": user, "password": pw})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["access_token"]


@pytest.fixture
def admin_headers(client):
    token = _login(client, "admin", _TEST_ADMIN_PW)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(client):
    _make_user("calv2_analyst", "analyst")
    token = _login(client, "calv2_analyst", "TestPass_123456")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def cleanup_rows():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM scenario_proposals WHERE scenario_id LIKE 'test_calv2_%' "
                "OR target_country LIKE 'test_sensor_%'"
            )
            conn.execute(
                "DELETE FROM threshold_history WHERE key LIKE 'test_calv2.%'"
            )
    except Exception:
        pass


# ── 1. v2 disabled ────────────────────────────────────────────────────────────


def test_v2_disabled_returns_503(client, admin_headers, monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    r = client.get("/api/v2/threshold_history", headers=admin_headers)
    assert r.status_code == 503
    assert r.get_json()["error"]


# ── 2. unauthenticated ───────────────────────────────────────────────────────


def test_no_auth_returns_401(client):
    r = client.get("/api/v2/threshold_history")
    assert r.status_code == 401


# ── 3. analyst on POST is forbidden ──────────────────────────────────────────


def test_analyst_cannot_apply_proposal(client, analyst_headers):
    r = client.post(
        "/api/v2/proposals/scenario_improver/9999999/apply",
        headers=analyst_headers,
    )
    # Either 403 (role check) or 404 (proposal missing) — both prove the
    # admin gate fired or the auth passed but the proposal is gone.
    # Strict assertion: must be 403, the role check fires before the
    # update_state call.
    assert r.status_code == 403


# ── 4. threshold_history list ────────────────────────────────────────────────


def test_threshold_history_list_returns_envelope(client, admin_headers):
    r = client.get("/api/v2/threshold_history?hours=24&limit=5",
                   headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["api_version"] == "2.0"
    assert "final_judgment_disclaimer" in body
    assert "data" in body
    assert isinstance(body["data"], list)
    assert body["filters"]["hours"] == 24
    assert body["filters"]["limit"] == 5


# ── 5. threshold_history list filters by key ─────────────────────────────────


def test_threshold_history_list_filters_by_key(client, admin_headers):
    threshold_history.record_change(
        key="test_calv2.alpha", value=0.5, scope_scenario_id=None,
        derived_from="test", applied_by="auto:test", sample_n=10,
        formula_ref="test#filter", evidence={}, magnitude_pct=0.0,
    )
    r = client.get("/api/v2/threshold_history?key=test_calv2.alpha",
                   headers=admin_headers)
    assert r.status_code == 200
    items = r.get_json()["data"]
    for item in items:
        assert item["key"] == "test_calv2.alpha"
    assert any(it["key"] == "test_calv2.alpha" for it in items)


# ── 6. threshold_history single 404 ──────────────────────────────────────────


def test_threshold_history_get_missing_returns_404(client, admin_headers):
    r = client.get("/api/v2/threshold_history/99999999",
                   headers=admin_headers)
    assert r.status_code == 404


# ── 7. threshold_history revert without revertible_to → 409 ──────────────────


def test_threshold_history_revert_without_predecessor_returns_409(
    client, admin_headers,
):
    rid = threshold_history.record_change(
        key="test_calv2.beta", value=0.7, scope_scenario_id=None,
        derived_from="test", applied_by="auto:test", sample_n=10,
        formula_ref="test#revert", evidence={}, magnitude_pct=0.0,
    )
    r = client.post(f"/api/v2/threshold_history/{rid}/revert",
                    headers=admin_headers)
    assert r.status_code == 409
    body = r.get_json()
    assert body["row_id"] == rid


# ── 8. sensor_disable list ───────────────────────────────────────────────────


def _seed_sensor_disable_proposal(sensor_name: str = "test_sensor_x") -> int:
    """Seed a pending sensor_disable proposal directly."""
    conn = db._get_conn()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, sample_n, "
            " why_string, state) "
            "VALUES (?, '__system__', 'sensor_disable', ?, "
            "        '{\"action\":\"disable\",\"ack_due_at\":0}', '{}', "
            "        'test#sensor_disable', 200, 'test', 'pending')",
            (time.time(), sensor_name),
        )
        return cur.lastrowid


def test_sensor_disable_list(client, admin_headers):
    pid = _seed_sensor_disable_proposal("test_sensor_a")
    r = client.get("/api/v2/proposals/sensor_disable", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["api_version"] == "2.0"
    ids = [p["id"] for p in body["data"]]
    assert pid in ids


# ── 9. sensor_disable ack happy path ─────────────────────────────────────────


def test_sensor_disable_ack(client, admin_headers):
    pid = _seed_sensor_disable_proposal("test_sensor_b")
    r = client.post(f"/api/v2/proposals/sensor_disable/{pid}/ack",
                    headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["data"]["proposal_id"] == pid
    assert body["data"]["new_state"] == "dismissed"


# ── 10. sensor_disable ack on already-dismissed → 404 ────────────────────────


def test_sensor_disable_ack_on_non_pending(client, admin_headers):
    pid = _seed_sensor_disable_proposal("test_sensor_c")
    # First ack succeeds
    client.post(f"/api/v2/proposals/sensor_disable/{pid}/ack",
                headers=admin_headers)
    # Second ack returns 404 (no longer pending)
    r = client.post(f"/api/v2/proposals/sensor_disable/{pid}/ack",
                    headers=admin_headers)
    assert r.status_code == 404


# ── 11. scenario_improver list (with scenario filter) ────────────────────────


def _seed_scenario_proposal(scenario_id: str = "test_calv2_taiwan") -> int:
    rid = scenario_improver._emit(ProposalEvent(
        scenario_id=scenario_id,
        proposal_type="weight_too_low",
        target_country="TC",
        suggested_value={"weight": 0.85, "from": 0.7},
        evidence={},
        formula_ref="test#scenario_improver",
        sample_n=30,
        why_string="test",
    ))
    assert rid is not None
    return rid


def test_scenario_improver_list_with_filter(client, admin_headers):
    pid = _seed_scenario_proposal("test_calv2_taiwan_a")
    r = client.get(
        "/api/v2/proposals/scenario_improver?scenario_id=test_calv2_taiwan_a",
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    ids = [p["id"] for p in body["data"]]
    assert pid in ids
    for p in body["data"]:
        assert p["scenario_id"] == "test_calv2_taiwan_a"


# ── 12. scenario_improver apply ──────────────────────────────────────────────


def test_scenario_improver_apply(client, admin_headers):
    pid = _seed_scenario_proposal("test_calv2_apply")
    r = client.post(
        f"/api/v2/proposals/scenario_improver/{pid}/apply",
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["data"]["new_state"] == "applied"
    assert body["data"]["proposal_id"] == pid


# ── 13. scenario_improver dismiss ────────────────────────────────────────────


def test_scenario_improver_dismiss(client, admin_headers):
    pid = _seed_scenario_proposal("test_calv2_dismiss")
    r = client.post(
        f"/api/v2/proposals/scenario_improver/{pid}/dismiss",
        headers=admin_headers,
    )
    assert r.status_code == 200
    assert r.get_json()["data"]["new_state"] == "dismissed"


# ── 14. scenario_improver defer ──────────────────────────────────────────────


def test_scenario_improver_defer(client, admin_headers):
    pid = _seed_scenario_proposal("test_calv2_defer")
    r = client.post(
        f"/api/v2/proposals/scenario_improver/{pid}/defer",
        headers=admin_headers,
    )
    assert r.status_code == 200
    assert r.get_json()["data"]["new_state"] == "snoozed_30d"


# ── 15. action on non-existent proposal → 404 ────────────────────────────────


def test_scenario_improver_action_on_missing_returns_404(
    client, admin_headers,
):
    r = client.post(
        "/api/v2/proposals/scenario_improver/99999999/apply",
        headers=admin_headers,
    )
    assert r.status_code == 404


# ── 16. NP7 disclaimer present on every successful response ──────────────────


def test_envelope_includes_np7_disclaimer(client, admin_headers):
    r = client.get("/api/v2/threshold_history", headers=admin_headers)
    body = r.get_json()
    assert body["final_judgment_disclaimer"]
    assert isinstance(body["final_judgment_disclaimer"], str)
    assert len(body["final_judgment_disclaimer"]) > 0


# ─────────────────────────────────────────────────────────────────────────────
#  Commit 4: drift_signals + run_now + health
# ─────────────────────────────────────────────────────────────────────────────


def _seed_drift_event(scenario_id: str, signal: str = "weight_stale",
                      consecutive_runs: int = 5,
                      severity: str = "amber") -> int:
    """Seed an unack drift event with sufficient dwell time."""
    conn = db._get_conn()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_drift_events "
            "(emitted_at, scenario_id, drift_signal, severity, target_country, "
            " evidence_json, why_string, consecutive_runs, formula_ref, "
            " ack_state) "
            "VALUES (?, ?, ?, ?, NULL, '{}', 'test', ?, "
            "        'test#drift', 'unack')",
            (time.time(), scenario_id, signal, severity, consecutive_runs),
        )
        return cur.lastrowid


@pytest.fixture(autouse=True)
def cleanup_drift_rows():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM scenario_drift_events "
                "WHERE scenario_id LIKE 'test_calv2_%'"
            )
    except Exception:
        pass


# 17. drift list returns dwell-filtered events


def test_drift_signals_list_dwell_filter(client, admin_headers):
    pid_short = _seed_drift_event("test_calv2_drift_short", consecutive_runs=1)
    pid_long = _seed_drift_event("test_calv2_drift_long", consecutive_runs=5)
    r = client.get(
        "/api/v2/drift_signals?min_consecutive_runs=3",
        headers=admin_headers,
    )
    assert r.status_code == 200
    ids = [d["id"] for d in r.get_json()["data"]]
    assert pid_long in ids
    assert pid_short not in ids  # filtered by dwell time


# 18. drift ack happy path


def test_drift_signals_ack(client, admin_headers):
    eid = _seed_drift_event("test_calv2_drift_ack", consecutive_runs=4)
    r = client.post(f"/api/v2/drift_signals/{eid}/ack",
                    headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["data"]["event_id"] == eid
    assert body["data"]["new_state"] == "acknowledged"


# 19. drift double-ack returns 404


def test_drift_signals_double_ack(client, admin_headers):
    eid = _seed_drift_event("test_calv2_drift_double", consecutive_runs=4)
    client.post(f"/api/v2/drift_signals/{eid}/ack", headers=admin_headers)
    r = client.post(f"/api/v2/drift_signals/{eid}/ack", headers=admin_headers)
    assert r.status_code == 404


# 20. run_now requires phase param


def test_run_now_missing_phase_returns_400(client, admin_headers):
    r = client.post("/api/v2/calibration/run_now", headers=admin_headers)
    assert r.status_code == 400


# 21. run_now invalid phase returns 400


def test_run_now_invalid_phase_returns_400(client, admin_headers):
    r = client.post("/api/v2/calibration/run_now?phase=banana",
                    headers=admin_headers)
    assert r.status_code == 400


# 22. run_now happy path (drift)


def test_run_now_drift_phase(client, admin_headers):
    r = client.post("/api/v2/calibration/run_now?phase=drift",
                    headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["data"]["phase"] == "drift"
    assert len(body["data"]["results"]) == 1
    assert body["data"]["results"][0]["phase"] == "drift"


# 23. run_now requires admin (analyst is forbidden)


def test_run_now_requires_admin(client, analyst_headers):
    r = client.post("/api/v2/calibration/run_now?phase=drift",
                    headers=analyst_headers)
    assert r.status_code == 403


# 24. health endpoint returns scoreboard envelope


def test_calibration_health(client, admin_headers):
    r = client.get("/api/v2/calibration/health?hours=24",
                   headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["api_version"] == "2.0"
    data = body["data"]
    assert "threshold_history" in data
    assert "scenario_proposals" in data
    assert "scenario_drift_events" in data
    assert "actionable_drift_count" in data
    assert data["window_hours"] == 24
