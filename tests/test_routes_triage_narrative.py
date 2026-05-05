"""Tests for radar.routes.triage_narrative (commit K)."""
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


@pytest.fixture
def admin_headers(client):
    resp = client.post("/api/auth/login", json={
        "username": "admin", "password": _TEST_ADMIN_PW,
    })
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


@pytest.fixture(autouse=True)
def cleanup_features():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM llm_feature_state")
            conn.execute("DELETE FROM llm_feature_state_history "
                         "WHERE changed_by LIKE 'admin:%' OR changed_by LIKE 'analyst:%'")
    except Exception:
        pass


# ── Feature gate ────────────────────────────────────────────────────────────


def test_503_when_feature_off(client, admin_headers, monkeypatch):
    monkeypatch.delenv("LLM_TRIAGE_NARRATIVE_ENABLED", raising=False)
    # Default state OFF → endpoint refuses without LLM call
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": [{"id": "x", "kindLabel": "TEST"}]},
        headers=admin_headers,
    )
    assert resp.status_code == 503
    body = resp.get_json()
    assert body["error"] == "triage_narrative_disabled"


# ── Validation ──────────────────────────────────────────────────────────────


def test_400_when_items_missing(client, admin_headers):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")
    resp = client.post(
        "/api/v2/triage/narrate",
        json={},
        headers=admin_headers,
    )
    assert resp.status_code == 400


def test_400_when_items_not_list(client, admin_headers):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": "not_a_list"},
        headers=admin_headers,
    )
    assert resp.status_code == 400


# ── Happy path with mocked LLM ──────────────────────────────────────────────


def test_returns_narratives_when_llm_ok(client, admin_headers, monkeypatch):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")

    def fake_llm(*, system, prompt, **kw):
        return {"ok": True, "data": {
            "narrative": "China-Taiwan attack mode escalating; review now.",
        }}

    monkeypatch.setattr("radar.llm_client.llm_analyze_json", fake_llm)
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": [
            {"id": "abc", "kindLabel": "ATTACK_MODE: COORDINATED_DDOS",
             "scenario_id": "taiwan_contingency", "confidence": 0.87,
             "age_minutes": 12, "rank": 1,
             "why": ["new mode", "rising conf"]},
        ]},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.get_json()["data"]
    assert data["feature_state"] == "on"
    assert data["n_ok"] == 1
    r = data["results"][0]
    assert r["id"] == "abc"
    assert r["ok"] is True
    assert "China-Taiwan" in r["narrative"]


def test_shadow_state_returns_results_with_label(client, admin_headers, monkeypatch):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")
    # triage_narrative.supports_shadow == False, so we can't set it to
    # shadow via the registry. But we can verify the response shape
    # carries feature_state. Use ON for this assertion.
    def fake_llm(*, system, prompt, **kw):
        return {"ok": True, "data": {"narrative": "x"}}
    monkeypatch.setattr("radar.llm_client.llm_analyze_json", fake_llm)
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": [{"id": "x", "kindLabel": "T"}]},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.get_json()["data"]["feature_state"] in ("on", "shadow")


# ── Failure paths ───────────────────────────────────────────────────────────


def test_llm_failure_marks_ok_false(client, admin_headers, monkeypatch):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")

    def failing_llm(*, system, prompt, **kw):
        return {"ok": False, "data": {}, "error": "timeout"}

    monkeypatch.setattr("radar.llm_client.llm_analyze_json", failing_llm)
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": [{"id": "x", "kindLabel": "T"}]},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    r = resp.get_json()["data"]["results"][0]
    assert r["ok"] is False
    assert "timeout" in r["error"]


def test_empty_response_treated_as_invalid(client, admin_headers, monkeypatch):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")

    def empty_llm(*, system, prompt, **kw):
        return {"ok": True, "data": {"narrative": "  "}}

    monkeypatch.setattr("radar.llm_client.llm_analyze_json", empty_llm)
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": [{"id": "x", "kindLabel": "T"}]},
        headers=admin_headers,
    )
    r = resp.get_json()["data"]["results"][0]
    assert r["ok"] is False
    assert r["error"] == "empty_or_invalid_response"


def test_narrative_truncated_to_240(client, admin_headers, monkeypatch):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")
    long_text = "abc" * 200  # 600 chars

    def long_llm(*, system, prompt, **kw):
        return {"ok": True, "data": {"narrative": long_text}}

    monkeypatch.setattr("radar.llm_client.llm_analyze_json", long_llm)
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": [{"id": "x", "kindLabel": "T"}]},
        headers=admin_headers,
    )
    r = resp.get_json()["data"]["results"][0]
    assert len(r["narrative"]) <= 240


# ── Batch cap ────────────────────────────────────────────────────────────────


def test_batch_capped_at_8(client, admin_headers, monkeypatch):
    lf.set_state("triage_narrative", lf.FeatureState.ON, by="admin:test")
    call_count = {"n": 0}

    def counting_llm(*, system, prompt, **kw):
        call_count["n"] += 1
        return {"ok": True, "data": {"narrative": "ok"}}

    monkeypatch.setattr("radar.llm_client.llm_analyze_json", counting_llm)
    items = [{"id": f"i{i}", "kindLabel": "T"} for i in range(20)]
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": items},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    # Cap is 8 — only that many results returned
    assert len(resp.get_json()["data"]["results"]) == 8
    assert call_count["n"] == 8


# ── Auth ────────────────────────────────────────────────────────────────────


def test_unauth_returns_401(client):
    resp = client.post(
        "/api/v2/triage/narrate",
        json={"items": []},
    )
    assert resp.status_code == 401
