"""Tests for authentication endpoints and airspace computation.

Run: python -m pytest test_auth.py -v
"""
import json
import os
import secrets
import time
import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")

# Set a deterministic test password BEFORE app init so _create_default_admin
# uses it (avoids auto-generated password race with gevent).
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar_api import app
from radar.auth import _hash_password
from radar.database import db
from radar.routes.core import _compute_airspace_status


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    """Flask test client with fresh DB state."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _ensure_admin_password():
    """Ensure admin user has the test password (handles post-import state)."""
    user = db.user_get("admin")
    if not user:
        pytest.skip("No admin user exists")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(_TEST_ADMIN_PW, salt)
    db.user_update_password(user["id"], pw_hash, salt)
    return _TEST_ADMIN_PW


@pytest.fixture(autouse=True)
def reset_admin_pw():
    """Reset admin password before each test for determinism."""
    _ensure_admin_password()
    yield


@pytest.fixture
def admin_token(client):
    """Get JWT access token for the default admin user."""
    resp = client.post("/api/auth/login", json={
        "username": "admin",
        "password": _TEST_ADMIN_PW,
    })
    data = resp.get_json()
    assert resp.status_code == 200, f"Admin login failed: {data}"
    return data["access_token"]


@pytest.fixture
def admin_headers(admin_token):
    """Authorization header dict for admin requests."""
    return {"Authorization": f"Bearer {admin_token}"}


# ── Auth: Login ──────────────────────────────────────────────────────────

class TestLogin:
    def test_login_success(self, client):
        resp = client.post("/api/auth/login", json={
            "username": "admin",
            "password": _TEST_ADMIN_PW,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["username"] == "admin"
        assert data["role"] == "admin"
        assert "access_expires_sec" in data

    def test_login_wrong_password(self, client):
        resp = client.post("/api/auth/login", json={
            "username": "admin",
            "password": "wrongpassword12",
        })
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "Invalid credentials"

    def test_login_nonexistent_user(self, client):
        resp = client.post("/api/auth/login", json={
            "username": "nonexistent_user_xyz",
            "password": "somepassword12",
        })
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "Invalid credentials"

    def test_login_missing_fields(self, client):
        resp = client.post("/api/auth/login", json={})
        assert resp.status_code == 400
        assert "required" in resp.get_json()["error"]

    def test_login_empty_username(self, client):
        resp = client.post("/api/auth/login", json={
            "username": "",
            "password": "somepassword12",
        })
        assert resp.status_code == 400


# ── Auth: Token Refresh ──────────────────────────────────────────────────

class TestTokenRefresh:
    def test_refresh_returns_new_access_token(self, client):
        login = client.post("/api/auth/login", json={
            "username": "admin",
            "password": _TEST_ADMIN_PW,
        })
        refresh_token = login.get_json()["refresh_token"]
        resp = client.post("/api/auth/refresh", headers={
            "Authorization": f"Bearer {refresh_token}",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.get_json()

    def test_refresh_rejects_access_token(self, client, admin_token):
        resp = client.post("/api/auth/refresh", headers={
            "Authorization": f"Bearer {admin_token}",
        })
        # Access token is not a refresh token — should fail
        assert resp.status_code in (401, 422)


# ── Auth: Registration (admin only) ─────────────────────────────────────

class TestRegistration:
    def test_register_new_user(self, client, admin_headers):
        resp = client.post("/api/auth/register", json={
            "username": "test_analyst_1",
            "password": "AnalystPass123!",
            "role": "analyst",
        }, headers=admin_headers)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["username"] == "test_analyst_1"
        assert data["role"] == "analyst"
        # Cleanup
        db.user_delete(db.user_get("test_analyst_1")["id"])

    def test_register_rejects_short_password(self, client, admin_headers):
        resp = client.post("/api/auth/register", json={
            "username": "test_short_pw",
            "password": "short",
            "role": "viewer",
        }, headers=admin_headers)
        assert resp.status_code == 400
        assert "12 characters" in resp.get_json()["error"]

    def test_register_rejects_invalid_role(self, client, admin_headers):
        resp = client.post("/api/auth/register", json={
            "username": "test_bad_role",
            "password": "ValidPass123!X",
            "role": "superadmin",
        }, headers=admin_headers)
        assert resp.status_code == 400
        assert "Invalid role" in resp.get_json()["error"]

    def test_register_rejects_duplicate_username(self, client, admin_headers):
        resp = client.post("/api/auth/register", json={
            "username": "admin",
            "password": "AnotherPass123!",
            "role": "viewer",
        }, headers=admin_headers)
        assert resp.status_code == 409

    def test_register_requires_admin_role(self, client, admin_headers):
        # Create a viewer user
        client.post("/api/auth/register", json={
            "username": "test_viewer_2",
            "password": "ViewerPass123!X",
            "role": "viewer",
        }, headers=admin_headers)
        # Login as viewer
        login = client.post("/api/auth/login", json={
            "username": "test_viewer_2",
            "password": "ViewerPass123!X",
        })
        viewer_token = login.get_json()["access_token"]
        # Viewer cannot register
        resp = client.post("/api/auth/register", json={
            "username": "test_another",
            "password": "AnotherPass123!",
            "role": "viewer",
        }, headers={"Authorization": f"Bearer {viewer_token}"})
        assert resp.status_code == 403
        # Cleanup
        db.user_delete(db.user_get("test_viewer_2")["id"])

    def test_register_requires_auth(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "unauthed",
            "password": "SomePass12345!",
            "role": "viewer",
        })
        assert resp.status_code == 401


# ── Auth: Password Change ────────────────────────────────────────────────

class TestPasswordChange:
    def test_change_own_password(self, client, admin_headers):
        old_pw = _TEST_ADMIN_PW
        new_pw = "NewAdminPass123!"
        resp = client.put("/api/auth/password", json={
            "old_password": old_pw,
            "new_password": new_pw,
        }, headers=admin_headers)
        assert resp.status_code == 200
        # Verify new password works
        login = client.post("/api/auth/login", json={
            "username": "admin", "password": new_pw,
        })
        assert login.status_code == 200
        # Restore original password
        new_token = login.get_json()["access_token"]
        client.put("/api/auth/password", json={
            "old_password": new_pw,
            "new_password": old_pw,
        }, headers={"Authorization": f"Bearer {new_token}"})

    def test_change_password_wrong_current(self, client, admin_headers):
        resp = client.put("/api/auth/password", json={
            "old_password": "wrong_current_pw",
            "new_password": "NewPass123456!",
        }, headers=admin_headers)
        assert resp.status_code == 401

    def test_change_password_too_short(self, client, admin_headers):
        resp = client.put("/api/auth/password", json={
            "old_password": _TEST_ADMIN_PW,
            "new_password": "short",
        }, headers=admin_headers)
        assert resp.status_code == 400


# ── Auth: Logout ─────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_revokes_token(self, client):
        login = client.post("/api/auth/login", json={
            "username": "admin",
            "password": _TEST_ADMIN_PW,
        })
        token = login.get_json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        # Logout
        resp = client.post("/api/auth/logout", headers=headers)
        assert resp.status_code == 200
        # Token should be revoked — subsequent requests should fail
        resp2 = client.get("/api/auth/settings", headers=headers)
        assert resp2.status_code == 401


# ── Auth: User Management (admin only) ───────────────────────────────────

class TestUserManagement:
    def test_list_users_admin_only(self, client, admin_headers):
        resp = client.get("/api/auth/users", headers=admin_headers)
        assert resp.status_code == 200
        users = resp.get_json()
        assert isinstance(users, list)
        assert any(u["username"] == "admin" for u in users)

    def test_update_user_role(self, client, admin_headers):
        # Create test user
        client.post("/api/auth/register", json={
            "username": "test_role_change",
            "password": "RoleChange123!X",
            "role": "viewer",
        }, headers=admin_headers)
        # Change role
        resp = client.put("/api/auth/users/test_role_change/role", json={
            "role": "analyst",
        }, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()["role"] == "analyst"
        # Cleanup
        db.user_delete(db.user_get("test_role_change")["id"])

    def test_cannot_change_own_role(self, client, admin_headers):
        resp = client.put("/api/auth/users/admin/role", json={
            "role": "viewer",
        }, headers=admin_headers)
        assert resp.status_code == 400

    def test_delete_user(self, client, admin_headers):
        client.post("/api/auth/register", json={
            "username": "test_delete_me",
            "password": "DeleteMe12345!",
            "role": "viewer",
        }, headers=admin_headers)
        resp = client.delete("/api/auth/users/test_delete_me",
                             headers=admin_headers)
        assert resp.status_code == 200
        assert db.user_get("test_delete_me") is None

    def test_cannot_delete_self(self, client, admin_headers):
        resp = client.delete("/api/auth/users/admin",
                             headers=admin_headers)
        assert resp.status_code == 400

    def test_admin_reset_password(self, client, admin_headers):
        client.post("/api/auth/register", json={
            "username": "test_reset_pw",
            "password": "ResetMe123456!",
            "role": "viewer",
        }, headers=admin_headers)
        resp = client.post("/api/auth/users/test_reset_pw/reset-password",
                           json={"new_password": "NewResetPw123!X"},
                           headers=admin_headers)
        assert resp.status_code == 200
        # Verify new password works
        login = client.post("/api/auth/login", json={
            "username": "test_reset_pw",
            "password": "NewResetPw123!X",
        })
        assert login.status_code == 200
        # Cleanup
        db.user_delete(db.user_get("test_reset_pw")["id"])


# ── Auth: Settings ───────────────────────────────────────────────────────

class TestSettings:
    def test_get_settings(self, client, admin_headers):
        resp = client.get("/api/auth/settings", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "lang" in data
        assert "muted" in data
        assert isinstance(data["muted"], list)

    def test_update_settings(self, client, admin_headers):
        resp = client.put("/api/auth/settings", json={
            "lang": "ja",
        }, headers=admin_headers)
        assert resp.status_code == 200
        # Verify
        get_resp = client.get("/api/auth/settings", headers=admin_headers)
        assert get_resp.get_json()["lang"] == "ja"
        # Restore
        client.put("/api/auth/settings", json={"lang": "en"},
                   headers=admin_headers)

    def test_update_settings_invalid_field(self, client, admin_headers):
        resp = client.put("/api/auth/settings", json={
            "nonexistent_field": "value",
        }, headers=admin_headers)
        assert resp.status_code == 400


# ── Auth: Rate Limiting ──────────────────────────────────────────────────

class TestRateLimiting:
    def test_login_rate_limit(self, client):
        from radar.auth import _login_attempts, _LOGIN_MAX_ATTEMPTS
        # Clear any existing attempts
        _login_attempts.clear()
        # Exhaust rate limit
        for _ in range(_LOGIN_MAX_ATTEMPTS):
            client.post("/api/auth/login", json={
                "username": "admin", "password": "wrong_pw_12345",
            })
        # Next attempt should be rate-limited
        resp = client.post("/api/auth/login", json={
            "username": "admin", "password": "wrong_pw_12345",
        })
        assert resp.status_code == 429
        assert "Too many" in resp.get_json()["error"]
        # Cleanup
        _login_attempts.clear()


# ── Auth: JWT Enforcement ────────────────────────────────────────────────

class TestJWTEnforcement:
    def test_api_requires_auth(self, client):
        resp = client.get("/api/auth/settings")
        assert resp.status_code == 401

    def test_public_endpoints_no_auth(self, client):
        # app_config is public
        resp = client.get("/api/app_config")
        assert resp.status_code == 200

    def test_login_endpoint_no_auth(self, client):
        # login itself should not require auth
        resp = client.post("/api/auth/login", json={
            "username": "nonexistent", "password": "test12345678",
        })
        # Should get 401 (invalid credentials), not 401 (auth required)
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "Invalid credentials"


# ── Airspace Computation ─────────────────────────────────────────────────

class _FakeDB:
    """Minimal DB mock for airspace computation testing."""
    def __init__(self):
        self._store = {}

    def airspace_get(self, code):
        return self._store.get(code)

    def airspace_set(self, code, data):
        self._store[code] = data


class TestComputeAirspaceStatus:
    def test_normal_traffic(self):
        fake_db = _FakeDB()
        # Seed baseline with enough readings
        fake_db._store["TPE"] = {"readings": [100, 100, 100, 100], "avg": 100.0}
        airspace_in = {"TPE": {"count": 95, "airport": "TPE", "lat": 25.0, "lng": 121.5}}
        weather = {}
        enriched, anomalies, filters = _compute_airspace_status(
            airspace_in, weather, time.time(), fake_db, 10, 28, 7)
        assert enriched["TPE"]["status"] == "NORMAL"
        assert len(anomalies) == 0

    def test_closure_detection(self):
        fake_db = _FakeDB()
        fake_db._store["TPE"] = {"readings": [100, 100, 100, 100], "avg": 100.0}
        airspace_in = {"TPE": {"count": 2, "airport": "TPE", "lat": 25.0, "lng": 121.5}}
        weather = {}
        enriched, anomalies, filters = _compute_airspace_status(
            airspace_in, weather, time.time(), fake_db, 10, 28, 7)
        assert enriched["TPE"]["status"] == "CLOSURE"
        assert len(anomalies) == 1
        assert anomalies[0]["severity"] == "CLOSURE"

    def test_weather_suppression(self):
        fake_db = _FakeDB()
        fake_db._store["TPE"] = {"readings": [100, 100, 100, 100], "avg": 100.0}
        airspace_in = {"TPE": {"count": 2, "airport": "TPE", "lat": 25.0, "lng": 121.5}}
        weather = {"TPE": {"is_severe": True}}
        enriched, anomalies, filters = _compute_airspace_status(
            airspace_in, weather, time.time(), fake_db, 10, 28, 7)
        assert enriched["TPE"]["status"] == "WEATHER_NOISE"
        assert len(anomalies) == 0
        assert len(filters) == 1
        assert "weather_noise" in filters[0]

    def test_baseline_building_phase(self):
        fake_db = _FakeDB()
        # Only 1 reading — after appending current count, n=2 which is < 3
        fake_db._store["TPE"] = {"readings": [100], "avg": 100.0}
        airspace_in = {"TPE": {"count": 5, "airport": "TPE", "lat": 25.0, "lng": 121.5}}
        enriched, anomalies, filters = _compute_airspace_status(
            airspace_in, {}, time.time(), fake_db, 10, 28, 7)
        assert enriched["TPE"]["status"] == "BASELINE_BUILDING"

    def test_error_on_negative_count(self):
        fake_db = _FakeDB()
        airspace_in = {"TPE": {"count": -1, "airport": "TPE"}}
        enriched, anomalies, filters = _compute_airspace_status(
            airspace_in, {}, time.time(), fake_db, 10, 28, 7)
        assert enriched["TPE"]["status"] == "ERROR"
        assert len(anomalies) == 0

    def test_hod_zscore_path(self):
        fake_db = _FakeDB()
        now = time.time()
        hour_bucket = int(now // 3600) * 3600
        cur_hour = (hour_bucket // 3600) % 24
        # Build HOD entries at the same hour-of-day for past 8 days
        hod_entries = [
            (hour_bucket - 86400 * d, 100)
            for d in range(1, 9)
        ]
        fake_db._store["TPE"] = {
            "readings": [100] * 10,
            "avg": 100.0,
            "hod": hod_entries,
        }
        # Severe drop: 5 aircraft vs baseline of ~100
        airspace_in = {"TPE": {"count": 5, "airport": "TPE", "lat": 25.0, "lng": 121.5}}
        enriched, anomalies, _ = _compute_airspace_status(
            airspace_in, {}, now, fake_db, 10, 28, 7)
        assert enriched["TPE"]["hod_z"] is not None
        assert enriched["TPE"]["hod_z"] < -3.0
        assert enriched["TPE"]["status"] == "CLOSURE"

    def test_multiple_airports(self):
        fake_db = _FakeDB()
        fake_db._store["TPE"] = {"readings": [100] * 5, "avg": 100.0}
        fake_db._store["NRT"] = {"readings": [80] * 5, "avg": 80.0}
        airspace_in = {
            "TPE": {"count": 95, "airport": "TPE", "lat": 25.0, "lng": 121.5},
            "NRT": {"count": 2, "airport": "NRT", "lat": 35.7, "lng": 139.7},
        }
        enriched, anomalies, _ = _compute_airspace_status(
            airspace_in, {}, time.time(), fake_db, 10, 28, 7)
        assert enriched["TPE"]["status"] == "NORMAL"
        assert enriched["NRT"]["status"] == "CLOSURE"
        assert len(anomalies) == 1
        assert anomalies[0]["code"] == "NRT"


# ── Data Retention / Cleanup ────────────────────────────────────────────

class TestDataRetention:
    """Verify _prune_stale_rows deletes expired rows and keeps recent ones."""

    def test_tl_observation_pruned(self):
        now = time.time()
        old_ts = now - 50 * 86400  # 50 days ago (> 42-day default)
        recent_ts = now - 10 * 86400  # 10 days ago
        sid = "test_ret_tl_obs"
        # Clean up leftovers from prior test runs
        conn = db._get_conn()
        conn.execute("DELETE FROM scenario_tl_observation WHERE scenario_id=?", (sid,))
        conn.commit()
        db.tl_observation_append(sid, old_ts, 3.0, 3, 1.0, 1.0, 1.0, 0.0, "c_lite", ["TW"])
        db.tl_observation_append(sid, recent_ts, 4.0, 4, 2.0, 1.0, 1.0, 0.0, "c_lite", ["TW"])
        deleted = db._prune_stale_rows()
        assert deleted["scenario_tl_observation"] >= 1
        # Recent row should survive (query per-scenario)
        rows = db.scenario_tl_timeseries(sid, hours=24 * 30)
        assert len(rows) >= 1
        assert all(r["observed_at"] >= recent_ts - 1 for r in rows)

    def test_focus_switch_pruned(self):
        now = time.time()
        old_ts = now - 200 * 86400  # 200 days ago (> 180-day default)
        recent_ts = now - 30 * 86400  # 30 days ago
        db.focus_switch_append("test_fs", old_ts, 2.0, 3.0, 1.0, True)
        db.focus_switch_append("test_fs", recent_ts, 2.5, 3.5, 1.0, False)
        deleted = db._prune_stale_rows()
        assert deleted["focus_switch_log"] >= 1

    def test_daily_summary_pruned(self):
        now = time.time()
        old_bucket = int((now - 800 * 86400) // 86400) * 86400  # 800 days ago (> 730-day default)
        recent_bucket = int((now - 30 * 86400) // 86400) * 86400  # 30 days ago
        db.daily_summary_upsert("test_ds", old_bucket, 3.0, 5.0, 3, 5, [], {}, {}, {})
        db.daily_summary_upsert("test_ds", recent_bucket, 4.0, 6.0, 2, 4, [], {}, {}, {})
        deleted = db._prune_stale_rows()
        assert deleted["daily_summary"] >= 1
        # Recent row should survive
        rows = db.daily_summary_get("test_ds", days=90)
        assert any(r["day_bucket"] == recent_bucket for r in rows)

    def test_forecast_log_pruned(self):
        now = time.time()
        old_ts = now - 400 * 86400  # 400 days ago (> 365-day default)
        recent_ts = now - 30 * 86400  # 30 days ago
        db.forecast_log_add("test_fc", old_ts, "trend", "up")
        db.forecast_log_add("test_fc", recent_ts, "trend", "down")
        deleted = db._prune_stale_rows()
        assert deleted["forecast_log"] >= 1

    def test_confirmed_threats_not_pruned(self):
        """confirmed_threats must NOT be auto-deleted (ground truth data)."""
        now = time.time()
        old_ts = now - 1000 * 86400  # ~2.7 years ago
        db.confirmed_threat_add("test_ct", old_ts, "confirmed_threat", [], 4, "test", "admin")
        deleted = db._prune_stale_rows()
        # confirmed_threats should not appear in deleted keys
        assert "confirmed_threats" not in deleted
        # Old row should still exist
        rows = db.confirmed_threat_list("test_ct", limit=10)
        assert any(abs(r["ts"] - old_ts) < 1 for r in rows)

    def test_scenario_change_log_not_pruned(self):
        """scenario_change_log must NOT be auto-deleted (audit trail)."""
        deleted = db._prune_stale_rows()
        assert "scenario_change_log" not in deleted
