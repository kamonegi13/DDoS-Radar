"""Tests for v2.0 Phase 1 priority 6 conclusion diff sampler.

Validates:
- Disabled-by-default: sample is a no-op when either flag is off
- match: v1 == v2 → diff_kind=match, is_match=1
- divergence: v1 != v2 → diff_kind=divergence, is_match=0
- v2_missing: ledger has no row → diff_kind=v2_missing
- v1_missing: state.tl is None → diff_kind=v1_missing
- Append-only: a second sample adds a row, never updates
- /api/v2/admin/conclusion_diff_stats returns counts + recent divergences
- Stats endpoint requires analyst auth
- Sampler failures never raise (NP3 — observability cannot break scoring)
"""

from __future__ import annotations

import os
import secrets
import time
from unittest.mock import patch

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar_api import app
from radar import config
from radar.auth import _hash_password
from radar.conclusions import (
    Conclusion,
    ConclusionType,
    new_conclusion_id,
    sample_focused_tl_diff,
    save_conclusion,
)
from radar.database import db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def enable_v2_flags(monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", True)
    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", True)
    monkeypatch.setattr(config, "V2_CONCLUSION_DIFF_SAMPLER_ENABLED", True)
    yield


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
def cleanup_test_rows():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM conclusions WHERE scenario_id LIKE 'test_%'")
            conn.execute("DELETE FROM conclusion_diff_log WHERE scenario_id LIKE 'test_%'")
    except Exception:
        pass


def _make_state(scenario_id: str, *, tl: int | None, score: float = 9.0,
                is_focused: bool = True):
    """Minimal stand-in for ScenarioState. The sampler only reads
    .tl / .score / .scoring_mode / .is_focused / .scenario_id, so a
    SimpleNamespace satisfies the contract."""
    from types import SimpleNamespace
    return SimpleNamespace(
        scenario_id=scenario_id, tl=tl, score=score,
        scoring_mode="FULL" if is_focused else "LITE",
        is_focused=is_focused,
    )


def _save_v2_tl(scenario_id: str, *, tl_state: str | None,
                observed_at: float | None = None) -> Conclusion:
    c = Conclusion(
        id=new_conclusion_id(),
        scenario_id=scenario_id,
        conclusion_type=ConclusionType.THREAT_LEVEL,
        state=tl_state,
        confidence=0.7,
        observed_at=observed_at if observed_at is not None else time.time(),
        formula_ref="radar/scoring.py#derive_tl@v2.0.1",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        conclusion_unavailable_reason=None,
    )
    save_conclusion(db, c)
    return c


def _read_diff_rows(scenario_id: str) -> list[dict]:
    conn = db._get_conn()
    return [dict(r) for r in conn.execute(
        "SELECT * FROM conclusion_diff_log WHERE scenario_id = ? "
        "ORDER BY id ASC", (scenario_id,)
    ).fetchall()]


# ── flag gating ─────────────────────────────────────────────────────────

def test_sampler_noop_when_diff_flag_off(monkeypatch):
    monkeypatch.setattr(config, "V2_CONCLUSION_DIFF_SAMPLER_ENABLED", False)
    sid = "test_diff_flag_off"
    _save_v2_tl(sid, tl_state="3")
    result = sample_focused_tl_diff(db, _make_state(sid, tl=3))
    assert result is None
    assert _read_diff_rows(sid) == []


def test_sampler_noop_when_ledger_flag_off(monkeypatch):
    """Without ledger writes, every sample would be v2_missing — that's
    noise, not signal. The sampler should refuse to run."""
    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", False)
    sid = "test_diff_ledger_off"
    result = sample_focused_tl_diff(db, _make_state(sid, tl=3))
    assert result is None
    assert _read_diff_rows(sid) == []


# ── classification ──────────────────────────────────────────────────────

def test_match_when_v1_equals_v2():
    sid = "test_diff_match"
    _save_v2_tl(sid, tl_state="3")
    result = sample_focused_tl_diff(db, _make_state(sid, tl=3))
    assert result["diff_kind"] == "match"
    assert result["is_match"] is True
    rows = _read_diff_rows(sid)
    assert len(rows) == 1
    assert rows[0]["is_match"] == 1
    assert rows[0]["v1_state"] == "3"
    assert rows[0]["v2_state"] == "3"


def test_divergence_when_v1_differs_from_v2():
    sid = "test_diff_diverge"
    _save_v2_tl(sid, tl_state="3")
    result = sample_focused_tl_diff(db, _make_state(sid, tl=4))
    assert result["diff_kind"] == "divergence"
    rows = _read_diff_rows(sid)
    assert rows[0]["v1_state"] == "4"
    assert rows[0]["v2_state"] == "3"
    assert rows[0]["is_match"] == 0


def test_v2_missing_when_ledger_has_no_row():
    sid = "test_diff_v2_missing"
    result = sample_focused_tl_diff(db, _make_state(sid, tl=3))
    assert result["diff_kind"] == "v2_missing"
    rows = _read_diff_rows(sid)
    assert rows[0]["v2_state"] is None
    assert rows[0]["v2_conclusion_id"] is None


def test_v1_missing_when_state_tl_is_none():
    sid = "test_diff_v1_missing"
    _save_v2_tl(sid, tl_state="3")
    result = sample_focused_tl_diff(db, _make_state(sid, tl=None))
    assert result["diff_kind"] == "v1_missing"
    rows = _read_diff_rows(sid)
    assert rows[0]["v1_state"] is None
    assert rows[0]["v2_state"] == "3"


def test_sampler_picks_latest_v2_row_when_multiple_exist():
    """If the ledger has older rows for the same (scenario, type), the diff
    must be against the newest — same semantics as latest_conclusion."""
    sid = "test_diff_latest_wins"
    _save_v2_tl(sid, tl_state="2", observed_at=1000.0)
    _save_v2_tl(sid, tl_state="4", observed_at=2000.0)
    result = sample_focused_tl_diff(db, _make_state(sid, tl=4))
    assert result["diff_kind"] == "match"
    assert result["v2_state"] == "4"


# ── append-only ─────────────────────────────────────────────────────────

def test_repeated_samples_append_rows():
    """Sampler is append-only — two cycles produce two rows even if the
    states match. This is intentional: rate of match over time is the
    rollout signal."""
    sid = "test_diff_append"
    _save_v2_tl(sid, tl_state="3")
    sample_focused_tl_diff(db, _make_state(sid, tl=3))
    sample_focused_tl_diff(db, _make_state(sid, tl=3))
    rows = _read_diff_rows(sid)
    assert len(rows) == 2


# ── failure swallow (NP3) ───────────────────────────────────────────────

def test_sampler_failure_does_not_raise():
    """If the persistence call blows up, the sampler must return None
    rather than propagating — NP3, observability never breaks scoring."""
    sid = "test_diff_failure"
    _save_v2_tl(sid, tl_state="3")
    with patch("radar.conclusions.diff_sampler.latest_conclusion",
               side_effect=RuntimeError("simulated db outage")):
        result = sample_focused_tl_diff(db, _make_state(sid, tl=3))
    assert result is None


# ── v2-only sampling (P2-3, 2026-05-10) ─────────────────────────────────

def test_v2_only_sampler_writes_one_row_per_v2_only_type():
    """sample_v2_only_diffs writes one row per v2-only conclusion type
    (attack_mode, per_domain, trend) so analysts can query the diff log
    for null-zone patterns without scraping conclusions."""
    from radar.conclusions.diff_sampler import sample_v2_only_diffs
    sid = "test_v2only_basic"
    # No v2 rows exist yet → all three types record diff_kind='v2_missing'.
    n = sample_v2_only_diffs(db, _make_state(sid, tl=3))
    assert n == 3
    rows = _read_diff_rows(sid)
    types = {r["conclusion_type"] for r in rows}
    assert types == {"attack_mode", "per_domain", "trend"}
    for r in rows:
        assert r["v1_state"] is None
        assert r["is_match"] == 0


def test_v2_only_sampler_classifies_unavailable_state():
    """When v2 has a row but its state is None (INSUFFICIENT_DATA),
    diff_kind should be 'v2_only_unavailable' so query filters can find
    null-zone history."""
    from radar.conclusions.diff_sampler import sample_v2_only_diffs
    sid = "test_v2only_null"
    from radar.conclusions.base import ConclusionUnavailableReason
    null_attack_mode = Conclusion(
        id=new_conclusion_id(),
        scenario_id=sid,
        conclusion_type=ConclusionType.ATTACK_MODE,
        state=None,  # INSUFFICIENT_DATA
        confidence=0.0,
        observed_at=time.time(),
        formula_ref="radar/conclusions/attack_mode.py#derive@v2.0.0",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
    )
    save_conclusion(db, null_attack_mode)
    sample_v2_only_diffs(db, _make_state(sid, tl=3))
    rows = [r for r in _read_diff_rows(sid)
            if r["conclusion_type"] == "attack_mode"]
    assert len(rows) == 1
    assert rows[0]["diff_kind"] == "v2_only_unavailable"
    assert rows[0]["v2_state"] is None


def test_v2_only_sampler_skips_when_unfocused():
    """v2-only sampling, like the TL sampler, runs only on focused
    scenarios — background scenarios produce no rows."""
    from radar.conclusions.diff_sampler import sample_v2_only_diffs
    sid = "test_v2only_unfocus"
    n = sample_v2_only_diffs(db, _make_state(sid, tl=3, is_focused=False))
    assert n == 0
    assert _read_diff_rows(sid) == []


def test_v2_only_sampler_respects_disabled_flags(monkeypatch):
    from radar.conclusions.diff_sampler import sample_v2_only_diffs
    monkeypatch.setattr(config, "V2_CONCLUSION_DIFF_SAMPLER_ENABLED", False)
    sid = "test_v2only_disabled"
    n = sample_v2_only_diffs(db, _make_state(sid, tl=3))
    assert n == 0


# ── analytics endpoint ──────────────────────────────────────────────────

def test_diff_stats_endpoint_returns_counts(client, auth_headers):
    sid = "test_diff_stats"
    _save_v2_tl(sid, tl_state="3")
    sample_focused_tl_diff(db, _make_state(sid, tl=3))     # match
    sample_focused_tl_diff(db, _make_state(sid, tl=4))     # divergence
    sample_focused_tl_diff(db, _make_state(sid, tl=None))  # v1_missing

    r = client.get("/api/v2/admin/conclusion_diff_stats?window_hours=24",
                   headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["api_version"] == "2.0"
    assert body["total_samples"] >= 3
    counts = body["diff_kind_counts"]
    assert counts.get("match", 0) >= 1
    assert counts.get("divergence", 0) >= 1
    assert counts.get("v1_missing", 0) >= 1
    # match_rate must be a float in [0, 1]
    assert 0.0 <= body["match_rate"] <= 1.0
    # recent_divergences should include our divergence row for this scenario
    assert any(d["scenario_id"] == sid for d in body["recent_divergences"])


def test_diff_stats_endpoint_requires_analyst_auth(client):
    """No JWT → 401, even when V2_API_ENABLED is true."""
    r = client.get("/api/v2/admin/conclusion_diff_stats")
    assert r.status_code == 401


def test_diff_stats_endpoint_503_when_v2_api_disabled(client, auth_headers, monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    r = client.get("/api/v2/admin/conclusion_diff_stats", headers=auth_headers)
    assert r.status_code == 503
