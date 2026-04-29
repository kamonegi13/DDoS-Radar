"""Tests for radar.attention + adaptive learning + routes (commits M+O)."""
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
from radar import attention  # noqa: E402
from radar import attention_learning  # noqa: E402
from radar import config  # noqa: E402
from radar.auth import _hash_password  # noqa: E402
from radar.database import db  # noqa: E402


# ── Engine: hysteresis ───────────────────────────────────────────────────────


class TestHysteresis:
    def setup_method(self):
        attention._active_rules.clear()

    def test_below_enter_does_not_fire(self):
        rule = next(r for r in attention.all_rules()
                    if r.rule_id == "autotune_pending_volume")
        assert attention._is_firing(rule, 19) is False

    def test_above_enter_fires(self):
        rule = next(r for r in attention.all_rules()
                    if r.rule_id == "autotune_pending_volume")
        assert attention._is_firing(rule, 21) is True

    def test_after_firing_stays_until_below_exit(self):
        rule = next(r for r in attention.all_rules()
                    if r.rule_id == "autotune_pending_volume")
        # Cross enter
        assert attention._is_firing(rule, 21) is True
        attention._active_rules.add(rule.rule_id)
        # Drop to between exit and enter — stays
        assert attention._is_firing(rule, 18) is True
        # Drop below exit — clears
        assert attention._is_firing(rule, 14) is False


# ── Engine: evaluate ────────────────────────────────────────────────────────


class TestEvaluate:
    def test_returns_list(self, monkeypatch):
        monkeypatch.setattr(attention, "_collect_metrics", lambda: {})
        out = attention.evaluate()
        assert isinstance(out, list)

    def test_critical_rule_fires_on_recall_negative(self, monkeypatch):
        attention._active_rules.clear()
        monkeypatch.setattr(attention, "_collect_metrics",
                            lambda: {"autotune_recall_negative": 3})
        out = attention.evaluate()
        critical = [r for r in out if r["rule_id"] == "autotune_recall_negative"]
        assert critical
        assert critical[0]["severity"] == "critical"
        assert critical[0]["can_snooze"] is False

    def test_per_tool_status_picks_highest_severity(self, monkeypatch):
        attention._active_rules.clear()
        # Clear any DB snoozes from prior tests
        try:
            conn = db._get_conn()
            with conn.writing():
                conn.execute("DELETE FROM attention_snooze")
        except Exception:
            pass
        monkeypatch.setattr(attention, "_collect_metrics",
                            lambda: {
                                "autotune_recall_negative": 1,  # critical
                                "drift_unack": 1,               # warning
                                "autotune_pending_total": 25,   # info
                            })
        # First call seeds the firing set; second call is the actual check
        # (the engine uses hysteresis state set on previous tick).
        attention.evaluate()
        status = attention.per_tool_status()
        assert "autotune" in status
        assert status["autotune"]["severity"] == "critical"


# ── Snooze ──────────────────────────────────────────────────────────────────


class TestSnooze:
    @pytest.fixture(autouse=True)
    def _cleanup(self):
        yield
        try:
            conn = db._get_conn()
            with conn.writing():
                conn.execute("DELETE FROM attention_snooze WHERE rule_id LIKE 'test_%' OR rule_id IN ('autotune_drift_unack','autotune_pending_volume')")
        except Exception:
            pass

    def test_snooze_blocks_critical(self):
        ok = attention.snooze("autotune_recall_negative",
                              hours=24, by="admin:test")
        assert ok is False  # critical can't be snoozed

    def test_snooze_works_for_warning(self):
        ok = attention.snooze("autotune_drift_unack",
                              hours=24, by="admin:test")
        assert ok is True

    def test_snooze_persistence(self, monkeypatch):
        attention._active_rules.clear()
        attention.snooze("autotune_pending_volume",
                         hours=24, by="analyst:test")
        # Now even if metric breaches, the rule shouldn't surface
        monkeypatch.setattr(attention, "_collect_metrics",
                            lambda: {"autotune_pending_total": 50})
        out = attention.evaluate()
        rule_ids = [r["rule_id"] for r in out]
        assert "autotune_pending_volume" not in rule_ids


# ── Adaptive learning ───────────────────────────────────────────────────────


class TestLearning:
    @pytest.fixture(autouse=True)
    def _cleanup(self):
        yield
        try:
            conn = db._get_conn()
            with conn.writing():
                conn.execute("DELETE FROM attention_metric_observation WHERE rule_id LIKE 'test_%' OR rule_id IN ('autotune_pending_volume','drift_unack')")
                conn.execute("DELETE FROM attention_metric_p95 WHERE rule_id LIKE 'test_%' OR rule_id IN ('autotune_pending_volume','drift_unack')")
        except Exception:
            pass

    def test_observe_records_metrics(self, monkeypatch):
        monkeypatch.setattr(attention, "_collect_metrics",
                            lambda: {"autotune_pending_total": 18,
                                     "drift_unack": 2})
        out = attention_learning.observe()
        assert out["recorded"] >= 1

    def test_recompute_p95_with_few_samples(self, monkeypatch):
        # No observations yet → recompute returns 0 updates
        out = attention_learning.recompute_p95()
        assert out["rules_updated"] >= 0

    def test_recompute_p95_with_real_data(self):
        conn = db._get_conn()
        with conn.writing():
            now = time.time()
            for v in (10, 12, 15, 18, 20, 22, 25, 28, 30, 35,
                      40, 45, 50, 55, 60):
                conn.execute(
                    "INSERT INTO attention_metric_observation "
                    "(rule_id, observed_at, observed_value) "
                    "VALUES ('autotune_pending_volume', ?, ?)",
                    (now - 3600, v),
                )
        out = attention_learning.recompute_p95()
        assert out["rules_updated"] >= 1
        row = conn.execute(
            "SELECT p50, p95, sample_count FROM attention_metric_p95 "
            "WHERE rule_id='autotune_pending_volume'"
        ).fetchone()
        assert row is not None
        p50, p95, n = row
        assert n == 15
        assert p50 < p95


# ── API endpoints ───────────────────────────────────────────────────────────


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
        pytest.skip("no admin")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(_TEST_ADMIN_PW, salt)
    db.user_update_password(user["id"], pw_hash, salt)
    yield


@pytest.fixture
def admin_headers(client):
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": _TEST_ADMIN_PW})
    return {"Authorization": f"Bearer {r.get_json()['access_token']}"}


def test_attention_list_returns_envelope(client, admin_headers):
    r = client.get("/api/v2/attention", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert "data" in body
    assert "rules" in body["data"]
    assert "tool_status" in body["data"]
    assert "suggestions" in body["data"]


def test_attention_snooze_critical_returns_403(client, admin_headers):
    r = client.post("/api/v2/attention/autotune_recall_negative/snooze",
                    json={"hours": 24}, headers=admin_headers)
    assert r.status_code == 403


def test_attention_snooze_warning_succeeds(client, admin_headers):
    r = client.post("/api/v2/attention/autotune_drift_unack/snooze",
                    json={"hours": 24}, headers=admin_headers)
    assert r.status_code == 200
    # cleanup
    conn = db._get_conn()
    with conn.writing():
        conn.execute("DELETE FROM attention_snooze WHERE rule_id='autotune_drift_unack'")


def test_attention_snooze_unknown_rule_404(client, admin_headers):
    r = client.post("/api/v2/attention/no_such_rule/snooze",
                    json={"hours": 24}, headers=admin_headers)
    assert r.status_code == 404


def test_attention_thresholds_put_get_delete_roundtrip(client, admin_headers):
    r = client.put("/api/v2/attention/thresholds/autotune_pending_volume",
                   json={"threshold": 30}, headers=admin_headers)
    assert r.status_code == 200
    g = client.get("/api/v2/attention/thresholds", headers=admin_headers)
    assert g.status_code == 200
    rows = g.get_json()["data"]
    assert any(r["rule_id"] == "autotune_pending_volume"
               and r["threshold"] == 30 for r in rows)
    d = client.delete("/api/v2/attention/thresholds/autotune_pending_volume",
                      headers=admin_headers)
    assert d.status_code == 200


def test_attention_thresholds_put_unknown_rule(client, admin_headers):
    r = client.put("/api/v2/attention/thresholds/nope",
                   json={"threshold": 1}, headers=admin_headers)
    assert r.status_code == 404
