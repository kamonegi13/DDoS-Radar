"""Tests for /api/v2/auto_judge/decisions (Bucket B item B3 of the
2026-05-07 audit). Pins the contract that the SETTINGS audit.auto_judge
page consumes.

Sandbox snapshots and restores ``auto_judge_decisions`` around each
test so the live ledger is preserved.
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


# ── Fixtures ─────────────────────────────────────────────────────────────────


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
def _sandbox():
    conn = db._get_conn()  # noqa: SLF001
    cols = [d[0] for d in conn.execute(
        "SELECT * FROM auto_judge_decisions LIMIT 0"
    ).description]
    rows = list(conn.execute(
        f"SELECT {','.join(cols)} FROM auto_judge_decisions"
    ))
    with conn.writing():
        conn.execute("DELETE FROM auto_judge_decisions")
    yield conn
    with conn.writing():
        conn.execute("DELETE FROM auto_judge_decisions")
        if rows:
            placeholders = ",".join("?" for _ in cols)
            conn.executemany(
                f"INSERT INTO auto_judge_decisions ({','.join(cols)}) "
                f"VALUES ({placeholders})",
                [tuple(r) for r in rows],
            )


def _insert(conn, *,
            item_id: str = "item-1",
            action: str = "confirm",
            confidence: float = 0.85,
            applied: bool = True,
            overridden: bool = False,
            override_action: "str | None" = None,
            analyst_id: "str | None" = None,
            ago_seconds: float = 0.0,
            l1_corroborators: int = 2,
            l1_satisfied: bool = True,
            reason: str = "test") -> None:
    now = time.time() - ago_seconds
    with conn.writing():
        conn.execute(
            "INSERT INTO auto_judge_decisions "
            "(ts, item_id, action_proposed, confidence, reason, "
            " layer1_corroborators, layer1_satisfied, applied, applied_at, "
            " analyst_overrode, analyst_override_action, "
            " analyst_override_at, analyst_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now, item_id, action, float(confidence), reason,
             int(l1_corroborators), 1 if l1_satisfied else 0,
             1 if applied else 0,
             now if applied else None,
             1 if overridden else 0,
             override_action,
             now + 60 if overridden else None,
             analyst_id),
        )


# ── HTTP contract ────────────────────────────────────────────────────────────


def test_endpoint_requires_authentication(client):
    r = client.get("/api/v2/auto_judge/decisions")
    assert r.status_code == 401


def test_envelope_shape_when_empty(client, admin_headers, _sandbox):
    r = client.get("/api/v2/auto_judge/decisions?hours=24",
                   headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    for k in ("api_version", "observed_at",
               "final_judgment_disclaimer", "summary", "items"):
        assert k in body
    assert body["summary"]["total"] == 0
    # When no applied rows exist, override_rate is None — never NaN.
    assert body["summary"]["override_rate"] is None


def test_summary_counts_by_action_and_applied(
    client, admin_headers, _sandbox,
):
    conn = _sandbox
    _insert(conn, action="confirm", applied=True)
    _insert(conn, action="confirm", applied=True)
    _insert(conn, action="reject",  applied=False)
    _insert(conn, action="pending", applied=False)
    r = client.get("/api/v2/auto_judge/decisions?hours=24",
                   headers=admin_headers).get_json()
    s = r["summary"]
    assert s["total"] == 4
    assert s["by_action"] == {"confirm": 2, "reject": 1, "pending": 1}
    assert s["applied_total"] == 2
    assert s["overridden_total"] == 0
    assert s["override_rate"] == 0.0


def test_summary_override_rate(client, admin_headers, _sandbox):
    """4 applied, 1 overridden → override_rate = 0.25."""
    conn = _sandbox
    for _ in range(3):
        _insert(conn, action="confirm", applied=True, overridden=False)
    _insert(conn, action="confirm", applied=True,
            overridden=True, override_action="reject",
            analyst_id="alice")
    s = client.get("/api/v2/auto_judge/decisions?hours=24",
                   headers=admin_headers).get_json()["summary"]
    assert s["applied_total"] == 4
    assert s["overridden_total"] == 1
    assert s["override_rate"] == pytest.approx(0.25, abs=1e-3)


def test_action_filter_narrows_items(client, admin_headers, _sandbox):
    conn = _sandbox
    _insert(conn, action="confirm")
    _insert(conn, action="reject")
    _insert(conn, action="pending")
    r = client.get(
        "/api/v2/auto_judge/decisions?hours=24&action=reject",
        headers=admin_headers,
    ).get_json()
    assert {it["action_proposed"] for it in r["items"]} == {"reject"}


def test_applied_filter_narrows_items(client, admin_headers, _sandbox):
    conn = _sandbox
    _insert(conn, action="confirm", applied=True,  item_id="A")
    _insert(conn, action="reject",  applied=False, item_id="B")
    r = client.get(
        "/api/v2/auto_judge/decisions?hours=24&applied=true",
        headers=admin_headers,
    ).get_json()
    assert {it["item_id"] for it in r["items"]} == {"A"}


def test_overridden_filter_narrows_items(
    client, admin_headers, _sandbox,
):
    conn = _sandbox
    _insert(conn, item_id="ov-1", overridden=True,
            override_action="reject", analyst_id="bob")
    _insert(conn, item_id="ov-2", overridden=False)
    r = client.get(
        "/api/v2/auto_judge/decisions?hours=24&overridden=1",
        headers=admin_headers,
    ).get_json()
    assert {it["item_id"] for it in r["items"]} == {"ov-1"}
    overridden_row = r["items"][0]
    assert overridden_row["analyst_overrode"] is True
    assert overridden_row["analyst_id"] == "bob"
    assert overridden_row["analyst_override_action"] == "reject"


def test_hours_window_excludes_older_rows(
    client, admin_headers, _sandbox,
):
    conn = _sandbox
    _insert(conn, item_id="recent", ago_seconds=10 * 3600.0)
    _insert(conn, item_id="ancient", ago_seconds=72 * 3600.0)
    r = client.get("/api/v2/auto_judge/decisions?hours=24",
                   headers=admin_headers).get_json()
    assert {it["item_id"] for it in r["items"]} == {"recent"}


def test_items_carry_settings_table_fields(
    client, admin_headers, _sandbox,
):
    """Every field the SETTINGS audit.auto_judge table reads must be
    present."""
    conn = _sandbox
    _insert(conn, item_id="check-shape", confidence=0.92,
            l1_corroborators=3, l1_satisfied=True,
            reason="auto:rule_corroborated")
    r = client.get("/api/v2/auto_judge/decisions?hours=24",
                   headers=admin_headers).get_json()
    assert len(r["items"]) == 1
    it = r["items"][0]
    expected = {
        "id", "ts", "item_id", "action_proposed", "confidence", "reason",
        "layer1_corroborators", "layer1_satisfied",
        "applied", "applied_at",
        "analyst_overrode", "analyst_override_action",
        "analyst_override_at", "analyst_id",
    }
    missing = expected - set(it.keys())
    assert not missing, f"item missing keys: {missing}"
    assert it["confidence"] == pytest.approx(0.92)
    assert it["layer1_corroborators"] == 3
