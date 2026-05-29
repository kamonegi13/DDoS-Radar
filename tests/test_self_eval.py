"""Tests for /api/v2/self_eval — DRIFT chip data path (Phase B of the
2026-05-05 v2-tail observability hardening).

Today the endpoint composes ~12 chip data sources. Most have their
own dedicated tests; the one we add here is `data.drift` because that
chip used to render `—` forever (the placeholder set the value to
None unconditionally).

Bands the HUD applies:
    good  ≤ 0.05
    warn  ≤ 0.10
    crit  > 0.10
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


def _patch_calibration(monkeypatch, recalls: dict):
    """Stub the ground-truth drift path (2026-05-29 repoint). ``recalls``
    maps scenario_id → recall float, or None for an INSUFFICIENT_DATA
    scenario that must be excluded. Patches both scenario_store.scorable()
    (the scenario list the drift loop walks) and calibration_status_for()
    (the per-scenario recall source)."""
    from radar.scenarios import scenario_store
    import radar.conclusions as _conc

    fake_scenarios = [type("S", (), {"id": sid})() for sid in recalls]
    monkeypatch.setattr(scenario_store, "scorable", lambda: fake_scenarios)

    def _fake_cs(_db, sid):
        recall = recalls.get(sid)
        if recall is None:
            return {"status": "INSUFFICIENT_DATA", "recall": None}
        return {"status": "OK", "recall": recall}
    monkeypatch.setattr(_conc, "calibration_status_for", _fake_cs)


def test_self_eval_drift_null_when_no_calibration_data(
    client, admin_headers, monkeypatch,
):
    _patch_calibration(monkeypatch, recalls={})
    r = client.get("/api/v2/self_eval", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["drift"] is None
    meta = body["drift_meta"]
    assert meta["scenarios_n"] == 0
    assert meta["reason"] == "no_scenarios_with_sufficient_recall_samples"


def test_self_eval_drift_mean_miss_rate(client, admin_headers, monkeypatch):
    """3 scenarios with recall 0.98/0.96/0.94 → miss rates 0.02/0.04/0.06
    → mean = 0.04 (green band). Worst scenario surfaced in meta."""
    _patch_calibration(monkeypatch, recalls={
        "scenario_a": 0.98,
        "scenario_b": 0.96,
        "scenario_c": 0.94,
    })
    r = client.get("/api/v2/self_eval", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["drift"] == pytest.approx(0.04, abs=1e-4)
    meta = body["drift_meta"]
    assert meta["scenarios_n"] == 3
    assert meta["max_miss_rate"] == pytest.approx(0.06, abs=1e-4)
    assert meta["worst_scenario"] == "scenario_c"
    assert meta["source"] == "ground_truth"


def test_self_eval_drift_skips_insufficient_scenarios(
    client, admin_headers, monkeypatch,
):
    """An INSUFFICIENT_DATA scenario is excluded entirely. The remaining
    scenario alone (recall 0.92) gives drift = 0.08."""
    _patch_calibration(monkeypatch, recalls={
        "scenario_thin":  None,
        "scenario_solid": 0.92,
    })
    r = client.get("/api/v2/self_eval", headers=admin_headers)
    body = r.get_json()
    assert body["drift"] == pytest.approx(0.08, abs=1e-4)
    assert body["drift_meta"]["scenarios_n"] == 1
    assert body["drift_meta"]["worst_scenario"] == "scenario_solid"


def test_self_eval_drift_handles_db_error(
    client, admin_headers, monkeypatch,
):
    """NP3 — if the calibration read raises, the chip degrades to None and
    the error is surfaced under drift_meta.error rather than 500-ing."""
    from radar.scenarios import scenario_store

    def _boom():
        raise RuntimeError("scenario store down")
    monkeypatch.setattr(scenario_store, "scorable", _boom)

    r = client.get("/api/v2/self_eval", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["drift"] is None
    assert "error" in body["drift_meta"]


# ── B4: per-model / per-use_case rollups exposed in response ─────────────────
#
# The frontend SETTINGS LLM Self-Eval page renders these rollups
# directly (no separate endpoint). Pin the response shape so a
# future refactor cannot silently drop them and leave the SETTINGS
# table empty.


def test_self_eval_exposes_by_model_rollup(client, admin_headers):
    r = client.get("/api/v2/self_eval", headers=admin_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert "by_model" in body
    # Even on a fresh-start system with no LLM calls yet, the key
    # must be present (an empty dict, not null) so the renderer's
    # `Object.keys()` iteration does not break.
    assert isinstance(body["by_model"], dict)


def test_self_eval_exposes_by_use_case_rollup(client, admin_headers):
    r = client.get("/api/v2/self_eval", headers=admin_headers)
    body = r.get_json()
    assert "by_use_case" in body
    assert isinstance(body["by_use_case"], dict)


def test_self_eval_per_model_entry_shape(client, admin_headers):
    """When at least one model has been called, its entry must
    expose every field the frontend table reads."""
    r = client.get("/api/v2/self_eval", headers=admin_headers)
    body = r.get_json()
    by_model = body.get("by_model", {})
    if not by_model:
        pytest.skip("no LLM call activity yet — shape pinned only "
                    "when data exists")
    sample = next(iter(by_model.values()))
    expected_keys = {
        "n", "ok_rate", "parse_failed", "timeout", "exception",
        "avg_duration_ms", "avg_confidence",
        "auto_confirmed_rate", "use_cases",
    }
    missing = expected_keys - set(sample.keys())
    assert not missing, f"by_model entry missing keys: {missing}"
    assert isinstance(sample.get("use_cases", []), list)


def test_self_eval_per_use_case_entry_shape(client, admin_headers):
    r = client.get("/api/v2/self_eval", headers=admin_headers)
    body = r.get_json()
    by_uc = body.get("by_use_case", {})
    if not by_uc:
        pytest.skip("no LLM call activity yet")
    sample = next(iter(by_uc.values()))
    expected_keys = {
        "n", "ok_rate", "avg_confidence",
        "auto_confirmed_rate", "primary_model",
    }
    missing = expected_keys - set(sample.keys())
    assert not missing, f"by_use_case entry missing keys: {missing}"
