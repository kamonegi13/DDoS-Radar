"""Tests for analyst_feedback ledger + /api/v2/conclusions/<id>/feedback.

Covers:
- DB layer: save → list → summarize round-trip; multi-analyst aggregate;
  invalid label rejected by CHECK constraint.
- API: POST writes a row with server-derived analyst_id (JWT identity)
  and observed_at, never trusting client-provided values.
- API: GET returns multi-analyst summary + items (newest first).
- API: 404 when conclusion_id is unknown; 400 when label is invalid;
  503 when V2_API_ENABLED=false. NP7 disclaimer present on all paths.

The drill-down feedback flow exists to feed Design W recall calibration
(ADR-V2-011 / v2-migration §11). The bias-mitigation rule "show counts,
not a verdict" is enforced by the response shape — `summary` contains
per-label counts + distinct_analysts, never a single chosen label.
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
from radar.conclusions.feedback import (
    AnalystFeedback,
    FeedbackLabel,
    list_feedback,
    save_feedback,
    summarize_feedback,
)
from radar.conclusions.persistence import save_conclusion
from radar.database import db


# ── shared fixtures ────────────────────────────────────────────────────


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def enable_v2_api(monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", True)
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


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    """Wipe rows we create so each test starts clean. Test conclusion_ids
    follow the `feedback_test_*` prefix to avoid colliding with real data."""
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM analyst_feedback WHERE conclusion_id LIKE 'feedback_test_%'"
            )
            conn.execute(
                "DELETE FROM conclusions WHERE id LIKE 'feedback_test_%'"
            )
    except Exception:
        pass


@pytest.fixture
def auth_headers(client):
    resp = client.post("/api/auth/login", json={
        "username": "admin", "password": _TEST_ADMIN_PW,
    })
    assert resp.status_code == 200, resp.get_json()
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


def _make_saved_conclusion(suffix: str = "tl") -> Conclusion:
    """Build + persist a conclusion the FK can point at. We deliberately
    use a deterministic id so cleanup_test_rows can wipe it."""
    cid = f"feedback_test_{suffix}_{int(time.time() * 1e6)}"
    c = Conclusion(
        id=cid,
        scenario_id=f"feedback_test_scenario_{suffix}",
        conclusion_type=ConclusionType.THREAT_LEVEL,
        state="3",
        confidence=0.7,
        observed_at=time.time(),
        formula_ref="radar/scoring.py#derive_tl@v2.0.1",
        threshold_ref={"total": 9.0},
        source_urls=("https://example.test/a",),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
    )
    save_conclusion(db, c)
    return c


# ── DB layer ────────────────────────────────────────────────────────────


def test_save_then_list_returns_newest_first():
    c = _make_saved_conclusion("list")
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=FeedbackLabel.TRUE_POSITIVE,
        analyst_id="alice", observed_at=1000.0,
    ))
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=FeedbackLabel.FALSE_POSITIVE,
        analyst_id="bob", observed_at=2000.0,
    ))
    rows = list_feedback(db, c.id)
    assert [r.label for r in rows] == [
        FeedbackLabel.FALSE_POSITIVE, FeedbackLabel.TRUE_POSITIVE,
    ]


def test_summarize_returns_zero_counts_for_empty_conclusion():
    """Consumer should never have to guard for missing label keys."""
    c = _make_saved_conclusion("empty")
    s = summarize_feedback(db, c.id)
    assert s["total"] == 0
    assert s["distinct_analysts"] == 0
    assert set(s["label_counts"].keys()) == {
        "TRUE_POSITIVE", "FALSE_POSITIVE", "TRUE_NEGATIVE", "FALSE_NEGATIVE",
    }
    assert all(v == 0 for v in s["label_counts"].values())


def test_summarize_counts_distinct_analysts_separately_from_total():
    """Two analysts, three rows: total=3, distinct_analysts=2. Bias mitigation
    needs to know how many *people* agreed, not just how many entries."""
    c = _make_saved_conclusion("multi")
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=FeedbackLabel.TRUE_POSITIVE,
        analyst_id="alice", observed_at=1.0,
    ))
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=FeedbackLabel.TRUE_POSITIVE,
        analyst_id="alice", observed_at=2.0,  # same analyst, revision
    ))
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=FeedbackLabel.FALSE_POSITIVE,
        analyst_id="bob", observed_at=3.0,
    ))
    s = summarize_feedback(db, c.id)
    assert s["total"] == 3
    assert s["distinct_analysts"] == 2
    assert s["label_counts"]["TRUE_POSITIVE"] == 2
    assert s["label_counts"]["FALSE_POSITIVE"] == 1


def test_db_check_constraint_rejects_unknown_label():
    """Defense-in-depth: even if the API layer regresses, the DB will not
    accept arbitrary strings as labels."""
    import sqlite3
    c = _make_saved_conclusion("bad")
    conn = db._get_conn()
    with pytest.raises(sqlite3.IntegrityError):
        with conn.writing():
            conn.execute(
                "INSERT INTO analyst_feedback (conclusion_id, label, "
                "analyst_id, observed_at) VALUES (?, ?, ?, ?)",
                (c.id, "MAYBE_TRUE", "alice", 1.0),
            )


# ── API: POST ───────────────────────────────────────────────────────────


def test_post_creates_row_with_server_derived_analyst_id(client, auth_headers):
    """Client cannot spoof analyst_id — JWT identity is authoritative."""
    c = _make_saved_conclusion("post1")
    resp = client.post(
        f"/api/v2/conclusions/{c.id}/feedback",
        headers=auth_headers,
        json={
            "label": "TRUE_POSITIVE",
            "analyst_id": "spoofed_evil",  # MUST be ignored
            "observed_at": 1.0,            # MUST be ignored
            "notes": "manual review pass",
        },
    )
    assert resp.status_code == 201, resp.get_json()
    body = resp.get_json()
    assert body["api_version"] == "2.0"
    assert body["final_judgment_disclaimer"] == config.V2_NP7_DISCLAIMER
    assert body["summary"]["label_counts"]["TRUE_POSITIVE"] == 1

    rows = list_feedback(db, c.id)
    assert len(rows) == 1
    assert rows[0].analyst_id == "admin"  # JWT identity, not the spoofed value
    assert rows[0].notes == "manual review pass"
    assert rows[0].observed_at > 1.0      # real server clock, not 1.0


def test_post_returns_404_for_unknown_conclusion(client, auth_headers):
    resp = client.post(
        "/api/v2/conclusions/00000000-0000-0000-0000-000000000000/feedback",
        headers=auth_headers,
        json={"label": "TRUE_POSITIVE"},
    )
    assert resp.status_code == 404
    body = resp.get_json()
    assert body["api_version"] == "2.0"
    assert body["final_judgment_disclaimer"] == config.V2_NP7_DISCLAIMER


def test_post_returns_400_for_unknown_label(client, auth_headers):
    c = _make_saved_conclusion("badlabel")
    resp = client.post(
        f"/api/v2/conclusions/{c.id}/feedback",
        headers=auth_headers,
        json={"label": "MAYBE_TRUE"},
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body["error"] == "invalid feedback label"
    assert body["final_judgment_disclaimer"] == config.V2_NP7_DISCLAIMER


def test_post_returns_400_for_missing_label(client, auth_headers):
    c = _make_saved_conclusion("nolabel")
    resp = client.post(
        f"/api/v2/conclusions/{c.id}/feedback",
        headers=auth_headers,
        json={"notes": "no label"},
    )
    assert resp.status_code == 400


def test_post_truncates_overlong_notes(client, auth_headers):
    """Bound the field so a runaway paste doesn't bloat the DB."""
    c = _make_saved_conclusion("notes")
    resp = client.post(
        f"/api/v2/conclusions/{c.id}/feedback",
        headers=auth_headers,
        json={"label": "TRUE_POSITIVE", "notes": "x" * 5000},
    )
    assert resp.status_code == 201
    rows = list_feedback(db, c.id)
    assert len(rows[0].notes) == 2000


# ── API: GET ────────────────────────────────────────────────────────────


def test_get_returns_summary_and_items(client, auth_headers):
    c = _make_saved_conclusion("get1")
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=FeedbackLabel.TRUE_POSITIVE,
        analyst_id="alice", observed_at=1.0,
    ))
    save_feedback(db, AnalystFeedback(
        conclusion_id=c.id, label=FeedbackLabel.FALSE_POSITIVE,
        analyst_id="bob", observed_at=2.0,
    ))
    resp = client.get(
        f"/api/v2/conclusions/{c.id}/feedback", headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["summary"]["total"] == 2
    assert body["summary"]["distinct_analysts"] == 2
    assert body["summary"]["label_counts"]["TRUE_POSITIVE"] == 1
    assert body["summary"]["label_counts"]["FALSE_POSITIVE"] == 1
    # newest first ordering preserved through the API
    assert body["items"][0]["analyst_id"] == "bob"
    assert body["items"][1]["analyst_id"] == "alice"


def test_get_returns_404_for_unknown_conclusion(client, auth_headers):
    resp = client.get(
        "/api/v2/conclusions/00000000-0000-0000-0000-000000000000/feedback",
        headers=auth_headers,
    )
    assert resp.status_code == 404


def test_get_empty_returns_zero_summary_not_404(client, auth_headers):
    """An existing conclusion with no feedback yet must return an empty
    summary — clients render the labeling form for the first analyst."""
    c = _make_saved_conclusion("empty_get")
    resp = client.get(
        f"/api/v2/conclusions/{c.id}/feedback", headers=auth_headers,
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["summary"]["total"] == 0
    assert body["items"] == []


# ── flag gate ────────────────────────────────────────────────────────────


def test_post_503_when_v2_disabled(client, auth_headers, monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    resp = client.post(
        "/api/v2/conclusions/anything/feedback",
        headers=auth_headers, json={"label": "TRUE_POSITIVE"},
    )
    assert resp.status_code == 503
    assert resp.get_json()["api_version"] == "2.0"


def test_get_503_when_v2_disabled(client, auth_headers, monkeypatch):
    monkeypatch.setattr(config, "V2_API_ENABLED", False)
    resp = client.get(
        "/api/v2/conclusions/anything/feedback", headers=auth_headers,
    )
    assert resp.status_code == 503
