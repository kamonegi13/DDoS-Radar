"""Tests for radar.routes.llm_features_v2 (commit H)."""
from __future__ import annotations

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
from radar import llm_features as lf  # noqa: E402
from radar.auth import _hash_password  # noqa: E402
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


@pytest.fixture(autouse=True)
def reset_admin_pw():
    user = db.user_get("admin")
    if user is None:
        pytest.skip("no admin user")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(_TEST_ADMIN_PW, salt)
    db.user_update_password(user["id"], pw_hash, salt)
    yield


def _make_user(username: str, role: str, password: str = "TestPass_123456"):
    existing = db.user_get(username)
    if existing:
        salt = secrets.token_hex(16)
        pw_hash = _hash_password(password, salt)
        db.user_update_password(existing["id"], pw_hash, salt)
        conn = db._get_conn()
        with conn.writing():
            conn.execute("UPDATE users SET role=? WHERE id=?",
                         (role, existing["id"]))
        return
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)
    uid = db.user_create(username, pw_hash, salt, role, time.time())
    db.user_settings_create(uid, None, "[]", "en", time.time())


def _login(client, user, pw):
    r = client.post("/api/auth/login",
                    json={"username": user, "password": pw})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["access_token"]


@pytest.fixture
def admin_headers(client):
    token = _login(client, "admin", _TEST_ADMIN_PW)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers(client):
    _make_user("lf_analyst", "analyst")
    token = _login(client, "lf_analyst", "TestPass_123456")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def cleanup_features():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM llm_feature_state "
                "WHERE feature_key NOT IN "
                "  (SELECT feature_key FROM llm_feature_state WHERE 0=1)"
            )
            # Clear our test history rows (any in last 60s by test actors).
            conn.execute(
                "DELETE FROM llm_feature_state_history "
                "WHERE changed_by LIKE 'admin:lf_%' OR "
                "      changed_by LIKE 'analyst:lf_%' OR "
                "      changed_by IN ('admin:test','analyst:test')"
            )
    except Exception:
        pass


# ── List + single ───────────────────────────────────────────────────────────


def test_list_returns_envelope_with_all_features(client, admin_headers):
    r = client.get("/api/v2/llm_features", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["api_version"] == "2.0"
    assert body["count"] == len(lf.LLM_FEATURES)
    keys = {f["key"] for f in body["data"]}
    assert "triage_narrative" in keys
    assert "g3b_cluster_annotator" in keys


def test_list_requires_auth(client):
    r = client.get("/api/v2/llm_features")
    assert r.status_code == 401


def test_get_single_includes_history(client, admin_headers):
    r = client.get("/api/v2/llm_features/triage_narrative",
                   headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["data"]["key"] == "triage_narrative"
    assert "history" in body["data"]
    assert isinstance(body["data"]["history"], list)


def test_get_unknown_returns_404(client, admin_headers):
    r = client.get("/api/v2/llm_features/nonexistent",
                   headers=admin_headers)
    assert r.status_code == 404


# ── /set ────────────────────────────────────────────────────────────────────


def test_admin_can_set_feature_state(client, admin_headers):
    r = client.post(
        "/api/v2/llm_features/auto_judge_recheck/set",
        json={"state": "shadow", "reason": "trial"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["data"]["new_state"] == "shadow"
    assert body["data"]["by"].startswith("admin:")
    # Resolve confirms persistence
    assert lf.resolve_state("auto_judge_recheck") == lf.FeatureState.SHADOW


def test_analyst_can_toggle_narrative_feature(client, analyst_headers):
    """triage_narrative.requires_admin == False → analyst is allowed."""
    r = client.post(
        "/api/v2/llm_features/triage_narrative/set",
        json={"state": "on"},
        headers=analyst_headers,
    )
    assert r.status_code == 200
    assert lf.resolve_state("triage_narrative") == lf.FeatureState.ON


def test_analyst_blocked_from_admin_only_feature(client, analyst_headers):
    r = client.post(
        "/api/v2/llm_features/g3b_cluster_annotator/set",
        json={"state": "shadow"},
        headers=analyst_headers,
    )
    assert r.status_code == 403


def test_set_invalid_state_returns_400(client, admin_headers):
    r = client.post(
        "/api/v2/llm_features/auto_judge_recheck/set",
        json={"state": "maybe"},
        headers=admin_headers,
    )
    assert r.status_code == 400


def test_set_shadow_rejected_when_unsupported(client, admin_headers):
    """triage_narrative.supports_shadow == False"""
    r = client.post(
        "/api/v2/llm_features/triage_narrative/set",
        json={"state": "shadow"},
        headers=admin_headers,
    )
    assert r.status_code == 400


def test_set_unknown_feature_returns_404(client, admin_headers):
    r = client.post(
        "/api/v2/llm_features/nope/set",
        json={"state": "on"},
        headers=admin_headers,
    )
    assert r.status_code == 404


# ── /clear ──────────────────────────────────────────────────────────────────


def test_clear_reverts_override(client, admin_headers, monkeypatch):
    monkeypatch.delenv("LLM_TRIAGE_NARRATIVE_ENABLED", raising=False)
    # First set ON via API
    client.post(
        "/api/v2/llm_features/triage_narrative/set",
        json={"state": "on"},
        headers=admin_headers,
    )
    assert lf.resolve_state("triage_narrative") == lf.FeatureState.ON
    # Then clear
    r = client.post(
        "/api/v2/llm_features/triage_narrative/clear",
        json={"reason": "back to default"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    # Default for triage_narrative is OFF
    assert lf.resolve_state("triage_narrative") == lf.FeatureState.OFF


# ── Kill switch ─────────────────────────────────────────────────────────────


def test_kill_switch_engage_and_release(client, admin_headers, monkeypatch):
    monkeypatch.delenv("LLM_FEATURE_KILL_SWITCH", raising=False)
    # Engage
    r = client.post(
        "/api/v2/llm_features/kill_switch",
        json={"state": "on", "reason": "smoke test"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    # Even sensor_intel_extraction (default ON) drops to OFF
    assert lf.resolve_state("sensor_intel_extraction") == lf.FeatureState.OFF
    # Release
    r = client.post(
        "/api/v2/llm_features/kill_switch",
        json={"state": "off"},
        headers=admin_headers,
    )
    assert r.status_code == 200
    assert lf.resolve_state("sensor_intel_extraction") == lf.FeatureState.ON


def test_kill_switch_admin_only(client, analyst_headers):
    r = client.post(
        "/api/v2/llm_features/kill_switch",
        json={"state": "on"},
        headers=analyst_headers,
    )
    assert r.status_code == 403


def test_kill_switch_invalid_state(client, admin_headers):
    r = client.post(
        "/api/v2/llm_features/kill_switch",
        json={"state": "maybe"},
        headers=admin_headers,
    )
    assert r.status_code == 400


# ── Audit ───────────────────────────────────────────────────────────────────


def test_audit_returns_history(client, admin_headers):
    client.post(
        "/api/v2/llm_features/auto_judge_recheck/set",
        json={"state": "shadow", "reason": "audit-test"},
        headers=admin_headers,
    )
    r = client.get("/api/v2/llm_features/audit?hours=1",
                   headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    rows = body["data"]
    # At least our just-made change
    assert any(
        r["feature_key"] == "auto_judge_recheck"
        and r["new_state"] == "shadow"
        for r in rows
    )


# ── NP7 disclaimer present on every envelope ────────────────────────────────


def test_envelopes_carry_disclaimer(client, admin_headers):
    r = client.get("/api/v2/llm_features", headers=admin_headers)
    assert r.get_json()["final_judgment_disclaimer"]
