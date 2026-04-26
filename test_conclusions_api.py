"""Tests for v2 conclusions API skeleton (Phase 1 priority 4).

Validates:
- Feature flag off → 503 with explanation
- Bundle endpoint returns latest of each ConclusionType (5 domains)
- Single-type endpoint returns just that type
- Unknown conclusion_type → 400
- Unknown conclusion_id → 404
- Empty ledger for a scenario → unavailable envelope, not 404
- audit_trace resolves llm_prompt full text when sha256 is set
- audit_trace marks llm_prompt missing if the row was purged
- All envelopes carry the NP7 disclaimer
- api_version is "2.0"
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

from radar_api import app
from radar import config
from radar.auth import _hash_password
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    new_conclusion_id,
)
from radar.conclusions.persistence import save_conclusion
from radar.database import db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def enable_v2_api(monkeypatch):
    """Default tests run with the v2 API on. The disable test flips it off."""
    monkeypatch.setattr(config, "V2_API_ENABLED", True)
    yield


@pytest.fixture(autouse=True)
def reset_admin_pw():
    """The /api/v2/* endpoints sit behind the global JWT gate
    (radar/__init__.py before_request). Tests need a known admin password
    to mint a token; reset it before each test the way test_auth.py does.
    """
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


# Tests share the project DB (radar/persistence/radar.db). Sweep our
# test scenario rows so each run starts from a clean slate. Test scenario
# IDs are namespaced with `test_` so this never touches real data.
@pytest.fixture(autouse=True)
def cleanup_test_conclusions():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM conclusions WHERE scenario_id LIKE 'test_%'")
    except Exception:
        pass


def _make_tl(scenario_id: str, *, observed_at: float | None = None,
             llm_prompt_sha256: str | None = None) -> Conclusion:
    return Conclusion(
        id=new_conclusion_id(),
        scenario_id=scenario_id,
        conclusion_type=ConclusionType.THREAT_LEVEL,
        state="3",
        confidence=0.78,
        observed_at=observed_at if observed_at is not None else time.time(),
        formula_ref="radar/scoring.py#derive_tl@v2.0.1",
        threshold_ref={"total": 9.0, "physical": 3.0},
        source_urls=("https://example.test/a", "https://example.test/b"),
        llm_prompt_sha256=llm_prompt_sha256,
        calibration_status={"sampler": "OK"},
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        metadata={"raw_score": 9.4},
    )


def _make_trend(scenario_id: str) -> Conclusion:
    return Conclusion(
        id=new_conclusion_id(),
        scenario_id=scenario_id,
        conclusion_type=ConclusionType.TREND,
        state="rising",
        confidence=0.6,
        observed_at=time.time(),
        formula_ref="radar/trend.py#derive_trend@v2.0.0",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
    )


# ── flag gate ───────────────────────────────────────────────────────────

def test_v2_returns_503_when_flag_off(client, auth_headers, monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    r = client.get("/api/v2/scenarios/taiwan_contingency/conclusions",
                   headers=auth_headers)
    assert r.status_code == 503
    body = r.get_json()
    assert body["api_version"] == "2.0"
    assert "not enabled" in body["error"]


# ── bundle endpoint ─────────────────────────────────────────────────────

def test_bundle_endpoint_returns_latest_of_each_type(client, auth_headers):
    sid = "test_bundle_scenario"
    save_conclusion(db, _make_tl(sid))
    save_conclusion(db, _make_trend(sid))

    r = client.get(f"/api/v2/scenarios/{sid}/conclusions", headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["api_version"] == "2.0"
    assert body["scenario_id"] == sid
    assert body["final_judgment_disclaimer"] == config.V2_NP7_DISCLAIMER
    types_returned = {c["conclusion_type"] for c in body["conclusions"]}
    assert types_returned == {"threat_level", "trend"}


def test_bundle_endpoint_picks_newest_per_type(client, auth_headers):
    """Append-only ledger: the newest row per (scenario, type) wins."""
    sid = "test_bundle_newest"
    older = _make_tl(sid, observed_at=1000.0)
    newer = _make_tl(sid, observed_at=2000.0)
    save_conclusion(db, older)
    save_conclusion(db, newer)

    r = client.get(f"/api/v2/scenarios/{sid}/conclusions", headers=auth_headers)
    body = r.get_json()
    tl = next(c for c in body["conclusions"] if c["conclusion_type"] == "threat_level")
    assert tl["id"] == newer.id


def test_bundle_endpoint_returns_unavailable_for_empty_scenario(client, auth_headers):
    """An unknown / never-scored scenario must NOT 404 — the API returns an
    explicit unavailable envelope so clients can render 'no data yet' UI
    without conflating it with a routing miss."""
    r = client.get("/api/v2/scenarios/zzz_no_such_scenario/conclusions",
                   headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["conclusions"][0]["state"] is None
    assert body["conclusions"][0]["conclusion_unavailable_reason"] == "insufficient_data"


# ── single-type endpoint ────────────────────────────────────────────────

def test_single_type_endpoint_returns_only_that_type(client, auth_headers):
    sid = "test_single_type"
    save_conclusion(db, _make_tl(sid))
    save_conclusion(db, _make_trend(sid))

    r = client.get(f"/api/v2/scenarios/{sid}/conclusions/trend",
                   headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert len(body["conclusions"]) == 1
    assert body["conclusions"][0]["conclusion_type"] == "trend"


def test_single_type_endpoint_rejects_unknown_type(client, auth_headers):
    r = client.get("/api/v2/scenarios/x/conclusions/not_a_real_type",
                   headers=auth_headers)
    assert r.status_code == 400
    assert r.get_json()["error"] == "unknown conclusion_type"


# ── single-id endpoint ──────────────────────────────────────────────────

def test_single_id_endpoint_returns_404_when_unknown(client, auth_headers):
    r = client.get("/api/v2/conclusions/00000000-0000-0000-0000-000000000000",
                   headers=auth_headers)
    assert r.status_code == 404


def test_single_id_endpoint_returns_envelope_when_found(client, auth_headers):
    sid = "test_single_id"
    c = _make_tl(sid)
    save_conclusion(db, c)
    r = client.get(f"/api/v2/conclusions/{c.id}", headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["conclusions"][0]["id"] == c.id
    assert body["scenario_id"] == sid


# ── audit_trace ─────────────────────────────────────────────────────────

def test_audit_trace_returns_404_when_unknown(client, auth_headers):
    r = client.get("/api/v2/conclusions/00000000-0000-0000-0000-000000000000/audit_trace",
                   headers=auth_headers)
    assert r.status_code == 404


def test_audit_trace_returns_full_disclosure_without_llm(client, auth_headers):
    sid = "test_audit_no_llm"
    c = _make_tl(sid)
    save_conclusion(db, c)
    r = client.get(f"/api/v2/conclusions/{c.id}/audit_trace", headers=auth_headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["formula_ref"] == "radar/scoring.py#derive_tl@v2.0.1"
    assert body["threshold_ref"] == {"total": 9.0, "physical": 3.0}
    assert body["source_urls"] == ["https://example.test/a", "https://example.test/b"]
    assert body["llm_prompt"] is None
    assert body["final_judgment_disclaimer"] == config.V2_NP7_DISCLAIMER


def test_audit_trace_resolves_llm_prompt_when_sha_set(client, auth_headers, monkeypatch):
    """If a conclusion is linked to an llm_prompt row, audit_trace must
    inline the full prompt text — that's the entire point of NP6."""
    monkeypatch.setattr(config, "V2_LLM_PROMPT_PERSISTENCE_ENABLED", True)
    from radar.llm_prompts import save_prompt

    sha = save_prompt(db, prompt="please analyze foo", system="be terse",
                      model="llama3.1:8b", temperature=0.1)
    assert sha is not None

    sid = "test_audit_with_llm"
    c = _make_tl(sid, llm_prompt_sha256=sha)
    save_conclusion(db, c)

    r = client.get(f"/api/v2/conclusions/{c.id}/audit_trace", headers=auth_headers)
    body = r.get_json()
    assert body["llm_prompt"]["sha256"] == sha
    assert "please analyze foo" in body["llm_prompt"]["prompt_text"]
    assert body["llm_prompt"]["model"] == "llama3.1:8b"


def test_audit_trace_marks_llm_prompt_missing_when_row_purged(client, auth_headers):
    """If the conclusion references a sha256 but the llm_prompts row is
    absent (purged, or persistence flag was off when the call happened),
    audit_trace must say so explicitly rather than silently omitting it."""
    sid = "test_audit_missing"
    c = _make_tl(sid, llm_prompt_sha256="ff" * 32)
    save_conclusion(db, c)
    r = client.get(f"/api/v2/conclusions/{c.id}/audit_trace", headers=auth_headers)
    body = r.get_json()
    assert body["llm_prompt"]["missing"] is True
    assert body["llm_prompt"]["sha256"] == "ff" * 32


# ── Markdown export (Phase 3) ───────────────────────────────────────────

def test_md_export_returns_markdown_content_type(client, auth_headers):
    sid = "test_md_export_ct"
    save_conclusion(db, _make_tl(sid))

    r = client.get(f"/api/v2/scenarios/{sid}/conclusions.md", headers=auth_headers)
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/markdown")
    cd = r.headers.get("Content-Disposition", "")
    assert "attachment" in cd
    assert f"{sid}-conclusions.md" in cd


def test_md_export_renders_each_saved_conclusion(client, auth_headers):
    sid = "test_md_export_sections"
    save_conclusion(db, _make_tl(sid))
    save_conclusion(db, _make_trend(sid))

    r = client.get(f"/api/v2/scenarios/{sid}/conclusions.md", headers=auth_headers)
    body = r.get_data(as_text=True)
    assert "# DDoS-Radar Scenario Report" in body
    assert "## Threat Level" in body
    assert "## Trend" in body
    # NP7 disclaimer present as blockquote.
    assert f"> {config.V2_NP7_DISCLAIMER}" in body


def test_md_export_returns_placeholder_for_empty_scenario(client, auth_headers):
    r = client.get("/api/v2/scenarios/zzz_no_md_scenario/conclusions.md",
                   headers=auth_headers)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "_No conclusions available for this scenario yet._" in body
    # Disclaimer still required when nothing is reported.
    assert f"> {config.V2_NP7_DISCLAIMER}" in body


def test_md_export_503_when_v2_disabled(client, auth_headers, monkeypatch):
    """Same gate as JSON endpoints — returns the JSON error envelope, not
    a markdown 503 page."""
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    r = client.get("/api/v2/scenarios/x/conclusions.md", headers=auth_headers)
    assert r.status_code == 503
    body = r.get_json()
    assert body["api_version"] == "2.0"


def test_md_export_includes_audit_trace_when_requested(client, auth_headers,
                                                       monkeypatch):
    """?include_audit=1 inlines the LLM prompt full text via <details>."""
    monkeypatch.setattr(config, "V2_LLM_PROMPT_PERSISTENCE_ENABLED", True)
    from radar.llm_prompts import save_prompt

    sha = save_prompt(db, prompt="please analyze md export",
                      system="be terse", model="llama3.1:8b",
                      temperature=0.1)
    sid = "test_md_export_audit"
    c = _make_tl(sid, llm_prompt_sha256=sha)
    save_conclusion(db, c)

    r = client.get(
        f"/api/v2/scenarios/{sid}/conclusions.md?include_audit=1",
        headers=auth_headers,
    )
    body = r.get_data(as_text=True)
    assert "<details><summary>LLM prompt (full text)</summary>" in body
    assert "please analyze md export" in body


def test_md_export_omits_audit_trace_by_default(client, auth_headers,
                                                monkeypatch):
    """Default response is the lighter view — no LLM prompt text leakage
    unless the analyst opts in."""
    monkeypatch.setattr(config, "V2_LLM_PROMPT_PERSISTENCE_ENABLED", True)
    from radar.llm_prompts import save_prompt

    sha = save_prompt(db, prompt="default-omit secret content",
                      system="be terse", model="llama3.1:8b",
                      temperature=0.1)
    sid = "test_md_export_no_audit"
    c = _make_tl(sid, llm_prompt_sha256=sha)
    save_conclusion(db, c)

    r = client.get(f"/api/v2/scenarios/{sid}/conclusions.md",
                   headers=auth_headers)
    body = r.get_data(as_text=True)
    assert "<details>" not in body
    assert "default-omit secret content" not in body


# ── NP7 regression: error envelopes must carry the disclaimer ────────────

@pytest.mark.parametrize("setup,expect_status", [
    # 503: flag off
    (
        {"flag": False, "url": "/api/v2/scenarios/x/conclusions"},
        503,
    ),
    # 400: bad conclusion_type
    (
        {"flag": True, "url": "/api/v2/scenarios/x/conclusions/not_a_real_type"},
        400,
    ),
    # 404: missing single id
    (
        {"flag": True,
         "url": "/api/v2/conclusions/00000000-0000-0000-0000-000000000000"},
        404,
    ),
    # 404: missing audit_trace id
    (
        {"flag": True,
         "url": "/api/v2/conclusions/00000000-0000-0000-0000-000000000000/audit_trace"},
        404,
    ),
])
def test_v2_error_responses_carry_disclaimer(client, auth_headers, monkeypatch,
                                             setup, expect_status):
    """NP7 contract: every v2 response — including error paths — must include
    `final_judgment_disclaimer` and `api_version`. Regression test for the
    pre-Phase-1.5 gap where 503/400/404 paths returned bare error dicts."""
    monkeypatch.setattr(config, "V2_API_ENABLED", setup["flag"])
    r = client.get(setup["url"], headers=auth_headers)
    assert r.status_code == expect_status
    body = r.get_json()
    assert body["api_version"] == "2.0"
    assert body["final_judgment_disclaimer"] == config.V2_NP7_DISCLAIMER
    assert "error" in body
