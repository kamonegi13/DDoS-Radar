"""Tests for radar.routes.history — country-set endpoints.

Covers the post-rename surface introduced in Phase A of the v2-tail
cleanup:

  GET /api/history/countries     — canonical
  GET /api/history/theaters      — deprecated alias (Deprecation header)

The legacy `?theater=` query param is **not** dual-read anymore (last
seen in the Phase 1 dual-read shim, removed when SR4 telemetry was
dropped in migration v50). These tests therefore only verify path-level
backward compatibility, not query-param compat.
"""
from __future__ import annotations

import os
import secrets

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD",
                                        "TestAdminPass123!")

import pytest  # noqa: E402

from radar_api import app  # noqa: E402
from radar.auth import _hash_password  # noqa: E402
from radar.database import db  # noqa: E402
from radar.routes import history as history_routes  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


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
    assert r.status_code == 200, r.get_data(as_text=True)
    return {"Authorization": f"Bearer {r.get_json()['access_token']}"}


# ── Path canonicalisation ────────────────────────────────────────────────────


def test_history_countries_returns_country_set(client, admin_headers):
    resp = client.get("/api/history/countries", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "countries" in body
    assert isinstance(body["countries"], list)
    # Sorted invariant.
    assert body["countries"] == sorted(body["countries"])


def test_history_theaters_legacy_alias_still_works(client, admin_headers):
    """Path `/api/history/theaters` continues to respond 200 with both keys
    (`theaters` for legacy callers, `countries` for new callers) and the
    Deprecation/Sunset/Link headers RFC-8594 expects."""
    resp = client.get("/api/history/theaters", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert "theaters" in body
    assert "countries" in body
    assert body["theaters"] == body["countries"]
    # RFC 8594 — informational only; we don't auto-disable.
    assert resp.headers.get("Deprecation") == "true"
    assert "Sunset" in resp.headers
    link = resp.headers.get("Link", "")
    assert "/api/history/countries" in link
    assert 'rel="successor-version"' in link


def test_legacy_and_canonical_paths_return_same_payload(client, admin_headers):
    canonical = client.get(
        "/api/history/countries", headers=admin_headers
    ).get_json()
    legacy = client.get(
        "/api/history/theaters", headers=admin_headers
    ).get_json()
    assert canonical["countries"] == legacy["countries"]


# ── Helper rename ────────────────────────────────────────────────────────────


def test_resolve_default_country_helper_exists():
    """The post-rename helper is reachable at the new symbol name."""
    assert callable(history_routes._resolve_default_country)
    # It returns "" or a non-empty uppercase string — never None.
    out = history_routes._resolve_default_country()
    assert isinstance(out, str)
    assert out == "" or out == out.upper()


def test_old_helper_name_is_gone():
    """The old name must not be silently re-exported. If a future commit
    re-introduces the alias the rename gate (scripts/check_rename_coverage.py)
    will be misled — fail loud here instead."""
    assert not hasattr(history_routes, "_resolve_default_theater")
