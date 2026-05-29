"""Tests for /api/v2/analyst_feedback + the
list_recent_feedback / aggregate_feedback_matrix helpers (Bucket B
item B1 of the 2026-05-07 audit).

These pin the contract that the SETTINGS audit.feedback page reads.
The fixture snapshots and restores both ``analyst_feedback`` and a
small set of ``conclusions`` rows so the live ledger is preserved.
"""
from __future__ import annotations

import os
import secrets
import time
import uuid

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD",
                                        "TestAdminPass123!")

import pytest  # noqa: E402

from radar import config  # noqa: E402
from radar.auth import _hash_password  # noqa: E402
from radar.conclusions.feedback import (  # noqa: E402
    FeedbackLabel,
    aggregate_feedback_matrix,
    list_recent_feedback,
)
from radar.database import db  # noqa: E402
from radar_api import app  # noqa: E402


# ── App / auth fixtures ──────────────────────────────────────────────────────


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


# ── Sandbox: analyst_feedback + a parent conclusions row ─────────────────────


@pytest.fixture
def _feedback_sandbox():
    """Snapshot/restore analyst_feedback rows and any test conclusions
    we add. We never touch existing conclusion rows."""
    conn = db._get_conn()  # noqa: SLF001
    fb_rows = list(conn.execute(
        "SELECT id, conclusion_id, label, observed_outcome_url, "
        "analyst_id, observed_at, notes FROM analyst_feedback"
    ))
    fb_cols = [d[0] for d in conn.execute(
        "SELECT * FROM analyst_feedback LIMIT 0"
    ).description]
    test_conclusion_ids: list[str] = []
    with conn.writing():
        conn.execute("DELETE FROM analyst_feedback")
    yield (conn, test_conclusion_ids)
    with conn.writing():
        conn.execute("DELETE FROM analyst_feedback")
        if fb_rows:
            placeholders = ",".join("?" for _ in fb_cols)
            conn.executemany(
                f"INSERT INTO analyst_feedback ({','.join(fb_cols)}) "
                f"VALUES ({placeholders})",
                [tuple(r) for r in fb_rows],
            )
        for cid in test_conclusion_ids:
            conn.execute("DELETE FROM conclusions WHERE id=?", (cid,))


def _make_conclusion(conn, *, conclusion_type: str = "threat_level",
                      scenario_id: str = "test_scenario") -> str:
    """Insert a minimal conclusions row so feedback FK constraint
    holds. Returns the new conclusion id. Uses only the columns the
    table actually has — keeps the test resilient to schema growth."""
    cid = "test_" + uuid.uuid4().hex[:12]
    with conn.writing():
        conn.execute(
            "INSERT INTO conclusions "
            "(id, scenario_id, conclusion_type, state, confidence, "
            " observed_at, formula_ref, threshold_ref, source_urls, "
            " calibration_status, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', '{}', '{}')",
            (cid, scenario_id, conclusion_type, "ACTIVE", 0.5,
             time.time(), "test#v1", "test#th"),
        )
    return cid


def _insert_feedback(conn, cid, *, label: str = "TRUE_POSITIVE",
                      analyst_id: str = "alice",
                      ago_seconds: float = 0.0,
                      notes: str = "") -> None:
    with conn.writing():
        conn.execute(
            "INSERT INTO analyst_feedback "
            "(conclusion_id, label, analyst_id, observed_at, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            (cid, label, analyst_id,
             time.time() - ago_seconds, notes),
        )


# ── list_recent_feedback / aggregate helpers ─────────────────────────────────


class TestListRecentFeedback:
    def test_empty_table_returns_empty_list(self, _feedback_sandbox):
        rows = list_recent_feedback(db, hours=24)
        assert rows == []

    def test_returns_rows_with_join_metadata(self, _feedback_sandbox):
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn,
                                conclusion_type="anomaly",
                                scenario_id="taiwan_contingency")
        test_ids.append(cid)
        _insert_feedback(conn, cid, label="TRUE_POSITIVE",
                          analyst_id="alice")
        rows = list_recent_feedback(db, hours=24)
        assert len(rows) == 1
        r = rows[0]
        assert r["conclusion_type"] == "anomaly"
        assert r["scenario_id"] == "taiwan_contingency"
        assert r["analyst_id"] == "alice"
        assert r["label"] == "TRUE_POSITIVE"

    def test_hours_window_excludes_older_rows(self, _feedback_sandbox):
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn)
        test_ids.append(cid)
        _insert_feedback(conn, cid, ago_seconds=10 * 3600.0)
        _insert_feedback(conn, cid, ago_seconds=72 * 3600.0)
        rows = list_recent_feedback(db, hours=24)
        assert len(rows) == 1

    def test_analyst_kind_filter_human(self, _feedback_sandbox):
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn)
        test_ids.append(cid)
        _insert_feedback(conn, cid, analyst_id="alice")
        _insert_feedback(conn, cid, analyst_id="auto:tl_calibrator")
        rows = list_recent_feedback(db, hours=24, analyst_kind="human")
        assert len(rows) == 1
        assert rows[0]["analyst_id"] == "alice"

    def test_analyst_kind_filter_auto(self, _feedback_sandbox):
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn)
        test_ids.append(cid)
        _insert_feedback(conn, cid, analyst_id="alice")
        _insert_feedback(conn, cid, analyst_id="auto:tl_calibrator")
        rows = list_recent_feedback(db, hours=24, analyst_kind="auto")
        assert len(rows) == 1
        assert rows[0]["analyst_id"] == "auto:tl_calibrator"

    def test_label_filter(self, _feedback_sandbox):
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn)
        test_ids.append(cid)
        _insert_feedback(conn, cid, label="TRUE_POSITIVE")
        _insert_feedback(conn, cid, label="FALSE_POSITIVE")
        rows = list_recent_feedback(db, hours=24,
                                     label=FeedbackLabel.FALSE_POSITIVE)
        assert len(rows) == 1
        assert rows[0]["label"] == "FALSE_POSITIVE"


class TestAggregateFeedbackMatrix:
    def test_empty_returns_zero_counts_and_null_recall(
        self, _feedback_sandbox,
    ):
        m = aggregate_feedback_matrix(db, hours=24)
        assert m["total"] == 0
        assert m["human_total"] == 0
        assert m["auto_total"] == 0
        assert m["recall"] is None
        assert m["precision"] is None
        # Even on empty data, the by_label keys must exist (no None).
        assert m["by_label"]["TRUE_POSITIVE"] == 0
        assert m["by_label"]["FALSE_POSITIVE"] == 0

    def test_recall_and_precision_when_signal_exists(
        self, _feedback_sandbox,
    ):
        """3 TP, 1 FP, 1 FN → recall = 3/4 = 0.75, precision = 3/4 = 0.75."""
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn)
        test_ids.append(cid)
        for _ in range(3):
            _insert_feedback(conn, cid, label="TRUE_POSITIVE")
        _insert_feedback(conn, cid, label="FALSE_POSITIVE")
        _insert_feedback(conn, cid, label="FALSE_NEGATIVE")
        m = aggregate_feedback_matrix(db, hours=24)
        assert m["total"] == 5
        assert m["recall"] == pytest.approx(0.75, abs=1e-3)
        assert m["precision"] == pytest.approx(0.75, abs=1e-3)
        assert m["by_label"]["TRUE_POSITIVE"] == 3
        assert m["by_label"]["FALSE_POSITIVE"] == 1
        assert m["by_label"]["FALSE_NEGATIVE"] == 1

    def test_human_vs_auto_breakdown(self, _feedback_sandbox):
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn)
        test_ids.append(cid)
        _insert_feedback(conn, cid, analyst_id="alice")
        _insert_feedback(conn, cid, analyst_id="bob")
        _insert_feedback(conn, cid, analyst_id="auto:tl")
        m = aggregate_feedback_matrix(db, hours=24)
        assert m["human_total"] == 2
        assert m["auto_total"] == 1
        assert m["distinct_analysts"] == 3

    def test_per_conclusion_type_breakdown(self, _feedback_sandbox):
        conn, test_ids = _feedback_sandbox
        cid_a = _make_conclusion(conn, conclusion_type="threat_level")
        cid_b = _make_conclusion(conn, conclusion_type="anomaly")
        test_ids.extend([cid_a, cid_b])
        _insert_feedback(conn, cid_a, label="TRUE_POSITIVE")
        _insert_feedback(conn, cid_a, label="FALSE_POSITIVE")
        _insert_feedback(conn, cid_b, label="TRUE_POSITIVE")
        m = aggregate_feedback_matrix(db, hours=24)
        by_ct = m["by_conclusion_type"]
        assert by_ct["threat_level"]["TRUE_POSITIVE"] == 1
        assert by_ct["threat_level"]["FALSE_POSITIVE"] == 1
        assert by_ct["anomaly"]["TRUE_POSITIVE"] == 1


# ── HTTP endpoint ────────────────────────────────────────────────────────────


class TestEndpoint:
    def test_requires_authentication(self, client):
        r = client.get("/api/v2/analyst_feedback")
        assert r.status_code == 401

    def test_returns_v2_envelope(
        self, client, admin_headers, _feedback_sandbox,
    ):
        r = client.get("/api/v2/analyst_feedback?hours=24",
                       headers=admin_headers)
        assert r.status_code == 200
        body = r.get_json()
        for k in ("api_version", "observed_at",
                   "final_judgment_disclaimer", "summary", "items"):
            assert k in body, f"envelope missing {k!r}"
        assert isinstance(body["summary"], dict)
        assert isinstance(body["items"], list)

    def test_returns_planted_rows_in_summary(
        self, client, admin_headers, _feedback_sandbox,
    ):
        conn, test_ids = _feedback_sandbox
        cid = _make_conclusion(conn,
                                conclusion_type="threat_level",
                                scenario_id="taiwan_contingency")
        test_ids.append(cid)
        _insert_feedback(conn, cid, label="TRUE_POSITIVE",
                          analyst_id="alice")
        _insert_feedback(conn, cid, label="FALSE_NEGATIVE",
                          analyst_id="bob")
        r = client.get("/api/v2/analyst_feedback?hours=24",
                       headers=admin_headers).get_json()
        assert r["summary"]["total"] == 2
        assert r["summary"]["recall"] == pytest.approx(0.5, abs=1e-3)
        # items array carries provenance for the SETTINGS table.
        assert len(r["items"]) == 2
        assert {it["analyst_id"] for it in r["items"]} == {"alice", "bob"}
        for it in r["items"]:
            assert it["scenario_id"] == "taiwan_contingency"
            assert it["conclusion_type"] == "threat_level"
