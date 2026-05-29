"""Tests for /api/v2/config_audit — cross-domain audit ledger feed.

Pins the contract that the SETTINGS audit.changes page depends on:
  - response shape `{domains: [{domain, count}, ...], rows: [...]}`
  - per-row fields the table renders (ts, domain, config_key,
    old_value, new_value, changed_by, reason)
  - domain filter narrows results
  - hours window filter narrows results

The B6 follow-up audit (2026-05-07) flagged this surface as
"already implemented but lacking test coverage". This file fills
that gap so a future refactor cannot silently break the SETTINGS
table.
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
from radar.database import db  # noqa: E402
from radar_api import app  # noqa: E402


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


@pytest.fixture
def _audit_sandbox():
    """Snapshot config_change_log around each test so the live ledger
    is preserved. The table is small and ts-indexed, so a roundtrip
    snapshot is cheap."""
    conn = db._get_conn()  # noqa: SLF001
    rows = list(conn.execute(
        "SELECT id, ts, domain, config_key, old_value, new_value, "
        "changed_by, reason, request_id FROM config_change_log"
    ))
    with conn.writing():
        conn.execute("DELETE FROM config_change_log")
    yield conn
    with conn.writing():
        conn.execute("DELETE FROM config_change_log")
        for r in rows:
            conn.execute(
                "INSERT INTO config_change_log "
                "(id, ts, domain, config_key, old_value, new_value, "
                " changed_by, reason, request_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(r),
            )


def _insert_audit_row(conn, *, domain: str, config_key: str = "test_key",
                      old_value: str = "0", new_value: str = "1",
                      changed_by: str = "admin", reason: str = "test",
                      ago_seconds: float = 0.0) -> None:
    with conn.writing():
        conn.execute(
            "INSERT INTO config_change_log "
            "(ts, domain, config_key, old_value, new_value, "
            " changed_by, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time() - ago_seconds, domain, config_key,
             old_value, new_value, changed_by, reason),
        )


# ── Endpoint contract ────────────────────────────────────────────────────────


def test_endpoint_requires_authentication(client):
    r = client.get("/api/v2/config_audit")
    assert r.status_code == 401


def test_returns_envelope_shape_when_empty(
    client, admin_headers, _audit_sandbox,
):
    r = client.get("/api/v2/config_audit?hours=24",
                   headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert "domains" in body
    assert "rows" in body
    assert isinstance(body["domains"], list)
    assert isinstance(body["rows"], list)
    assert body["domains"] == []
    assert body["rows"] == []


def test_domains_aggregate_with_counts(
    client, admin_headers, _audit_sandbox,
):
    """The domains array must populate the SETTINGS audit dropdown
    with `{domain, count}` rows ordered by count desc."""
    conn = _audit_sandbox
    for _ in range(3):
        _insert_audit_row(conn, domain="llm.routing")
    _insert_audit_row(conn, domain="sensor.mute")
    r = client.get("/api/v2/config_audit?hours=24",
                   headers=admin_headers)
    body = r.get_json()
    domains = {d["domain"]: d["count"] for d in body["domains"]}
    assert domains == {"llm.routing": 3, "sensor.mute": 1}


def test_rows_have_settings_table_fields(
    client, admin_headers, _audit_sandbox,
):
    """Every field the SETTINGS audit.changes table reads must be
    present in each row. Pinning this protects against backend
    refactors silently dropping a column."""
    conn = _audit_sandbox
    _insert_audit_row(
        conn, domain="llm.routing",
        config_key="LLM_ROUTING_VERDICT_PRIMARY_MODEL",
        old_value="gemma4:26b", new_value="mistral-small3.2:24b",
        changed_by="admin", reason="phase 8 promotion",
    )
    r = client.get("/api/v2/config_audit?hours=24",
                   headers=admin_headers)
    body = r.get_json()
    assert len(body["rows"]) == 1
    row = body["rows"][0]
    for k in ("ts", "domain", "config_key", "old_value", "new_value",
              "changed_by", "reason"):
        assert k in row, f"row missing key {k!r}"
    assert row["domain"] == "llm.routing"
    assert row["new_value"] == "mistral-small3.2:24b"
    assert row["changed_by"] == "admin"
    assert row["reason"] == "phase 8 promotion"


def test_domain_filter_narrows_results(
    client, admin_headers, _audit_sandbox,
):
    conn = _audit_sandbox
    _insert_audit_row(conn, domain="llm.routing")
    _insert_audit_row(conn, domain="llm.routing")
    _insert_audit_row(conn, domain="sensor.mute")
    r_all = client.get("/api/v2/config_audit?hours=24",
                       headers=admin_headers).get_json()
    r_llm = client.get(
        "/api/v2/config_audit?hours=24&domain=llm.routing",
        headers=admin_headers,
    ).get_json()
    assert len(r_all["rows"]) == 3
    assert len(r_llm["rows"]) == 2
    assert all(r["domain"] == "llm.routing" for r in r_llm["rows"])


def test_hours_window_excludes_older_rows(
    client, admin_headers, _audit_sandbox,
):
    conn = _audit_sandbox
    _insert_audit_row(conn, domain="recent", ago_seconds=10 * 3600.0)
    _insert_audit_row(conn, domain="ancient", ago_seconds=72 * 3600.0)
    r = client.get("/api/v2/config_audit?hours=24",
                   headers=admin_headers).get_json()
    assert {row["domain"] for row in r["rows"]} == {"recent"}


def test_limit_clamps_to_max(client, admin_headers, _audit_sandbox):
    """The endpoint clamps `limit` to [1, 2000]; values outside that
    range must not be silently honoured."""
    conn = _audit_sandbox
    for _ in range(5):
        _insert_audit_row(conn, domain="x")
    r = client.get("/api/v2/config_audit?hours=24&limit=2",
                   headers=admin_headers).get_json()
    assert len(r["rows"]) == 2
