"""Tests for /api/analyst/* role gating, session-id filtering, and F14 write-through.

Run: python -m pytest test_analyst_permissions.py -v

Covers:
  - role gates (viewer / analyst / admin) on every tradecraft endpoint
  - assumption lock/unlock is admin-only (analyst gets 403)
  - F14 session_id filter round-trips correctly
  - F6/F8/F10/F11/F13 write-through populates decision_ledger with detail.auto=true
  - decision_ledger has no DELETE/PATCH endpoint (append-only by design)
"""
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
from radar.auth import _hash_password  # noqa: E402
from radar.database import db  # noqa: E402


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _ensure_admin_password() -> str:
    user = db.user_get("admin")
    if not user:
        pytest.skip("No admin user exists")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(_TEST_ADMIN_PW, salt)
    db.user_update_password(user["id"], pw_hash, salt)
    return _TEST_ADMIN_PW


@pytest.fixture(autouse=True)
def _reset_admin_pw():
    _ensure_admin_password()
    yield


def _make_user(username: str, role: str, password: str = "TestPass_123456") -> None:
    """Delete any existing test user, then create fresh with the requested role."""
    existing = db.user_get(username)
    if existing:
        # No user_delete API surface; update role + password instead.
        salt = secrets.token_hex(16)
        pw_hash = _hash_password(password, salt)
        db.user_update_password(existing["id"], pw_hash, salt)
        db.user_update_role(existing["id"], role) if hasattr(db, "user_update_role") else None
        # Fall back to raw update if the helper isn't exposed.
        if not hasattr(db, "user_update_role"):
            conn = db._get_conn()
            with conn.writing():
                conn.execute("UPDATE users SET role=? WHERE id=?", (role, existing["id"]))
        return
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)
    uid = db.user_create(username, pw_hash, salt, role, time.time())
    db.user_settings_create(uid, None, "[]", "en", time.time())


def _login(client, username: str, password: str) -> str:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.get_json()}"
    return r.get_json()["access_token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(client):
    token = _login(client, "admin", _TEST_ADMIN_PW)
    return _auth(token)


@pytest.fixture
def analyst_headers(client):
    _make_user("tc_analyst", "analyst")
    token = _login(client, "tc_analyst", "TestPass_123456")
    return _auth(token)


@pytest.fixture
def viewer_headers(client):
    _make_user("tc_viewer", "viewer")
    token = _login(client, "tc_viewer", "TestPass_123456")
    return _auth(token)


@pytest.fixture
def scenario_id() -> str:
    """Return an existing scenario id.

    Presets live in the in-memory ScenarioStore (Layer 1 from geo_data.json),
    not the DB table (which only holds Layer 2 admin edits). Analyst endpoints
    accept any scenario_id string, so we pick the first preset from the store.
    """
    from radar.scenarios import scenario_store
    if not scenario_store.loaded or not scenario_store.all():
        pytest.skip("ScenarioStore not loaded — cannot run permission tests")
    return next(iter(scenario_store.all().keys()))


# ── Role gate: viewer (read-only) ─────────────────────────────────────────

class TestViewerForbidden:
    """Viewer role must not reach any /api/analyst/* endpoint."""

    def test_viewer_cannot_list_disconf(self, client, viewer_headers, scenario_id):
        r = client.get(
            f"/api/analyst/disconf?scenario_id={scenario_id}",
            headers=viewer_headers,
        )
        assert r.status_code == 403

    def test_viewer_cannot_add_disconf(self, client, viewer_headers, scenario_id):
        r = client.post(
            "/api/analyst/disconf",
            headers=viewer_headers,
            json={"scenario_id": scenario_id, "summary": "nope"},
        )
        assert r.status_code == 403

    def test_viewer_cannot_create_ach(self, client, viewer_headers, scenario_id):
        r = client.post(
            "/api/analyst/ach",
            headers=viewer_headers,
            json={"scenario_id": scenario_id, "title": "nope"},
        )
        assert r.status_code == 403

    def test_viewer_cannot_list_decisions(self, client, viewer_headers, scenario_id):
        r = client.get(
            f"/api/analyst/decisions?scenario_id={scenario_id}",
            headers=viewer_headers,
        )
        assert r.status_code == 403


# ── Role gate: analyst (full tradecraft, no admin locks) ──────────────────

class TestAnalystAllowed:
    def test_analyst_can_list_disconf(self, client, analyst_headers, scenario_id):
        r = client.get(
            f"/api/analyst/disconf?scenario_id={scenario_id}",
            headers=analyst_headers,
        )
        assert r.status_code == 200
        assert "items" in r.get_json()

    def test_analyst_can_add_disconf(self, client, analyst_headers, scenario_id):
        r = client.post(
            "/api/analyst/disconf",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "summary": "test disconfirming evidence",
                "source_kind": "manual_note",
                "strength": 3,
                "session_id": "sess-test-analyst",
            },
        )
        assert r.status_code == 200
        assert isinstance(r.get_json().get("id"), int)

    def test_analyst_can_create_ach_matrix(self, client, analyst_headers, scenario_id):
        r = client.post(
            "/api/analyst/ach",
            headers=analyst_headers,
            json={"scenario_id": scenario_id, "title": "Test ACH", "session_id": "sess-test-analyst"},
        )
        assert r.status_code == 200
        assert isinstance(r.get_json().get("id"), int)


class TestAnalystBlockedFromAdmin:
    """assumption lock/unlock is admin-only per ADR-006."""

    def test_analyst_cannot_lock_assumption(self, client, analyst_headers, scenario_id):
        add_r = client.post(
            "/api/analyst/assumptions",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "statement": "sample assumption for lock test",
                "confidence": "medium",
                "session_id": "sess-test-analyst",
            },
        )
        assert add_r.status_code == 200
        aid = add_r.get_json()["id"]

        lock_r = client.post(
            f"/api/analyst/assumptions/{aid}/lock",
            headers=analyst_headers,
            json={"lock": True, "session_id": "sess-test-analyst"},
        )
        assert lock_r.status_code == 403


class TestAdminCanLock:
    def test_admin_can_lock_assumption(self, client, admin_headers, analyst_headers, scenario_id):
        add_r = client.post(
            "/api/analyst/assumptions",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "statement": "admin-lock fixture assumption",
                "confidence": "low",
                "session_id": "sess-test-admin",
            },
        )
        aid = add_r.get_json()["id"]

        lock_r = client.post(
            f"/api/analyst/assumptions/{aid}/lock",
            headers=admin_headers,
            json={"lock": True, "session_id": "sess-test-admin"},
        )
        assert lock_r.status_code == 200
        assert lock_r.get_json().get("ok") is True


# ── F14 session filter ────────────────────────────────────────────────────

class TestDecisionSessionFilter:
    def test_session_id_roundtrip(self, client, analyst_headers, scenario_id):
        unique_sid = f"sess-filter-{secrets.token_hex(4)}"
        client.post(
            "/api/analyst/decisions",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "session_id": unique_sid,
                "decision_type": "other",
                "summary": "session-filter test row",
            },
        )
        r = client.get(
            f"/api/analyst/decisions?session_id={unique_sid}",
            headers=analyst_headers,
        )
        assert r.status_code == 200
        items = r.get_json()["items"]
        assert len(items) >= 1
        assert all(it["session_id"] == unique_sid for it in items)


# ── F6/F8/F10/F11/F13 write-through into F14 ──────────────────────────────

class TestAutoLogWriteThrough:
    """Every tradecraft write must append a decision_ledger row with detail.auto=true."""

    def _latest_for_session(self, sid: str) -> list[dict]:
        return db.decision_list(session_id=sid, limit=20)

    def test_disconf_add_autologs(self, client, analyst_headers, scenario_id):
        sid = f"auto-disconf-{secrets.token_hex(3)}"
        client.post(
            "/api/analyst/disconf",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "summary": "autolog probe",
                "source_kind": "manual_note",
                "strength": 2,
                "session_id": sid,
            },
        )
        rows = self._latest_for_session(sid)
        assert any(
            r["decision_type"] == "disconf_add"
            and (r.get("detail") or {}).get("auto") is True
            for r in rows
        ), f"autolog row missing; got {rows}"

    def test_ach_create_autologs(self, client, analyst_headers, scenario_id):
        sid = f"auto-ach-{secrets.token_hex(3)}"
        client.post(
            "/api/analyst/ach",
            headers=analyst_headers,
            json={"scenario_id": scenario_id, "title": "Autolog ACH", "session_id": sid},
        )
        rows = self._latest_for_session(sid)
        assert any(
            r["decision_type"] == "ach_create"
            and (r.get("detail") or {}).get("auto") is True
            for r in rows
        )

    def test_assumption_add_autologs(self, client, analyst_headers, scenario_id):
        sid = f"auto-assump-{secrets.token_hex(3)}"
        client.post(
            "/api/analyst/assumptions",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "statement": "autolog probe assumption",
                "confidence": "high",
                "session_id": sid,
            },
        )
        rows = self._latest_for_session(sid)
        assert any(
            r["decision_type"] == "assumption_add"
            and (r.get("detail") or {}).get("auto") is True
            for r in rows
        )

    def test_premortem_add_autologs(self, client, analyst_headers, scenario_id):
        sid = f"auto-pm-{secrets.token_hex(3)}"
        client.post(
            "/api/analyst/premortem",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "failure_mode": "false_positive",
                "imagined_outcome": "autolog probe FP",
                "root_cause": "test",
                "session_id": sid,
            },
        )
        rows = self._latest_for_session(sid)
        assert any(
            r["decision_type"] == "premortem_add"
            and (r.get("detail") or {}).get("auto") is True
            for r in rows
        )

    def test_dissent_add_autologs(self, client, analyst_headers, scenario_id):
        sid = f"auto-dissent-{secrets.token_hex(3)}"
        client.post(
            "/api/analyst/dissent",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "title": "autolog probe",
                "body": "test dissenting view",
                "argues_for_tl": 3,
                "session_id": sid,
            },
        )
        rows = self._latest_for_session(sid)
        assert any(
            r["decision_type"] == "dissent_add"
            and (r.get("detail") or {}).get("auto") is True
            for r in rows
        )

    def test_manual_decision_not_marked_auto(self, client, analyst_headers, scenario_id):
        """Manual POST /api/analyst/decisions must NOT be marked auto=true."""
        sid = f"manual-{secrets.token_hex(3)}"
        client.post(
            "/api/analyst/decisions",
            headers=analyst_headers,
            json={
                "scenario_id": scenario_id,
                "session_id": sid,
                "decision_type": "other",
                "summary": "manual decision row",
                "detail": {"rationale": "hand-entered"},
            },
        )
        rows = self._latest_for_session(sid)
        assert rows, "manual decision not persisted"
        assert not any((r.get("detail") or {}).get("auto") is True for r in rows)


# ── Immutability: decision_ledger is append-only ──────────────────────────

class TestDecisionLedgerImmutable:
    def test_no_delete_endpoint(self, client, admin_headers):
        r = client.delete("/api/analyst/decisions/1", headers=admin_headers)
        assert r.status_code in (404, 405)

    def test_no_patch_endpoint(self, client, admin_headers):
        r = client.patch("/api/analyst/decisions/1", headers=admin_headers, json={})
        assert r.status_code in (404, 405)
