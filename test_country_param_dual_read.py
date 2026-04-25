"""Tests for ADR-V2-006 Safe Rename Pattern A-3 — `?country=` dual-read.

Validates that selected /api/* endpoints accept both ?country=TW and the
legacy ?theater=TW alias, and that legacy access bumps the SR4 telemetry
counter so the 90-day sunset PR can confirm zero callers depend on it.
"""

from __future__ import annotations

import os
import secrets

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar_api import app
from radar import legacy_telemetry as lt
from radar.auth import _hash_password
from radar.database import db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


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
def isolate_telemetry():
    lt.reset_for_test()
    yield
    lt.reset_for_test()


def _snapshot_count(label: str) -> int:
    snap = lt.snapshot()
    stat = snap.get(label)
    return stat.count if stat is not None else 0


def test_country_param_preferred_over_theater(client, auth_headers):
    """If both ?country= and ?theater= are present, country wins (no SR4 record)."""
    resp = client.get(
        "/api/history/sequence_events?country=TW&theater=JP&hours=1",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["country"] == "TW"
    assert body["theater"] == "TW"  # dual-write mirror
    assert _snapshot_count("/api/history/sequence_events?theater=") == 0


def test_legacy_theater_param_still_accepted_and_recorded(client, auth_headers):
    """Legacy ?theater= path returns the same shape and bumps SR4 counter."""
    resp = client.get(
        "/api/history/sequence_events?theater=TW&hours=1",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["country"] == "TW"
    assert body["theater"] == "TW"
    assert _snapshot_count("/api/history/sequence_events?theater=") == 1


def test_country_param_on_sequence_chain(client, auth_headers):
    """`/api/sequence_chain` — A-3 dual-read covers analytics endpoints too."""
    resp = client.get("/api/sequence_chain?country=TW", headers=auth_headers)
    assert resp.status_code == 200
    assert _snapshot_count("/api/sequence_chain?theater=") == 0

    resp_legacy = client.get(
        "/api/sequence_chain?theater=TW", headers=auth_headers,
    )
    assert resp_legacy.status_code == 200
    assert _snapshot_count("/api/sequence_chain?theater=") == 1


def test_country_param_on_intel_list(client, auth_headers):
    """`/api/intel` — confirms intel listing uses dual-read."""
    resp = client.get("/api/intel?country=TW", headers=auth_headers)
    assert resp.status_code == 200
    assert _snapshot_count("/api/intel?theater=") == 0

    resp_legacy = client.get("/api/intel?theater=TW", headers=auth_headers)
    assert resp_legacy.status_code == 200
    assert _snapshot_count("/api/intel?theater=") == 1


def test_legacy_counter_accumulates_across_calls(client, auth_headers):
    """Every legacy call increments the same SR4 counter (idempotent label)."""
    for _ in range(3):
        client.get(
            "/api/history/sequence_events?theater=TW&hours=1",
            headers=auth_headers,
        )
    assert _snapshot_count("/api/history/sequence_events?theater=") == 3
