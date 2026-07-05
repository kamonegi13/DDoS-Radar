"""Human-anchor queue tests (2026-07-04).

The selection policy is the calibration system's independent leg: after
two consecutive silent auto-labeler defects, a weekly trickle of human
labels is what makes auto-label drift detectable at all.
"""
from __future__ import annotations

import os
import secrets
import time
import uuid

os.environ.setdefault("CF_API_TOKEN", "test")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD",
                                        "TestAdminPass123!")

import pytest  # noqa: E402

from radar import config  # noqa: E402
from radar.auth import _hash_password  # noqa: E402
from radar.conclusions import human_anchor as ha  # noqa: E402
from radar.conclusions.base import Conclusion, ConclusionType  # noqa: E402
from radar.conclusions.persistence import save_conclusion  # noqa: E402
from radar.database import db  # noqa: E402
from radar_api import app  # noqa: E402

_NOW = time.time()
_TAG = "anch" + uuid.uuid4().hex[:6]


def _mk_conclusion(*, scenario, state, observed_at,
                   kind=ConclusionType.THREAT_LEVEL):
    cid = f"{_TAG}-" + uuid.uuid4().hex[:10]
    save_conclusion(db, Conclusion(
        id=cid, scenario_id=scenario, conclusion_type=kind,
        state=state, confidence=0.8, observed_at=observed_at,
        formula_ref="test", threshold_ref={}, source_urls=(),
        calibration_status={}, final_judgment_disclaimer="test",
        metadata={},
    ))
    return cid


def _mk_feedback(cid, *, label, analyst_id, observed_at):
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        conn.execute(
            "INSERT INTO analyst_feedback "
            "(conclusion_id, label, analyst_id, observed_at, "
            " observed_outcome_url, notes) VALUES (?, ?, ?, ?, NULL, ?)",
            (cid, label, analyst_id, observed_at, "test evidence"),
        )


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        conn.execute(
            "DELETE FROM analyst_feedback WHERE conclusion_id LIKE ?",
            (f"{_TAG}-%",),
        )
        conn.execute(
            "DELETE FROM conclusions WHERE id LIKE ?", (f"{_TAG}-%",),
        )
        conn.execute(
            "DELETE FROM confirmed_threats WHERE created_by = 'admin' "
            "AND classification LIKE 'human_confirmed%'",
        )


def _mine(cands, scenario):
    return [c for c in cands if c.scenario_id == scenario]


class TestSelection:

    def test_auto_fn_review_candidate_surfaces(self):
        sid = f"{_TAG}_fn"
        cid = _mk_conclusion(scenario=sid, state="4",
                             observed_at=_NOW - 2 * 86400)
        _mk_feedback(cid, label="FALSE_NEGATIVE", analyst_id="auto:rss",
                     observed_at=_NOW - 2 * 86400)
        cands = ha.select_anchor_candidates(db, now=_NOW, limit=20)
        mine = _mine(cands, sid)
        assert any(c.kind == "auto_fn_review" and c.conclusion_id == cid
                   for c in mine)
        fn_cand = next(c for c in mine if c.kind == "auto_fn_review")
        assert "FALSE_NEGATIVE" in fn_cand.suggested_labels
        assert fn_cand.rationale  # AP2 — never empty

    def test_human_answered_conclusion_leaves_queue(self):
        sid = f"{_TAG}_ans"
        cid = _mk_conclusion(scenario=sid, state="4",
                             observed_at=_NOW - 2 * 86400)
        _mk_feedback(cid, label="FALSE_NEGATIVE", analyst_id="auto:rss",
                     observed_at=_NOW - 2 * 86400)
        _mk_feedback(cid, label="TRUE_POSITIVE", analyst_id="admin",
                     observed_at=_NOW - 86400)
        cands = ha.select_anchor_candidates(db, now=_NOW, limit=20)
        assert not any(c.conclusion_id == cid for c in cands)

    def test_peak_severity_picks_most_severe_call(self):
        sid = f"{_TAG}_peak"
        _mk_conclusion(scenario=sid, state="4",
                       observed_at=_NOW - 3 * 86400)
        severe = _mk_conclusion(scenario=sid, state="2",
                                observed_at=_NOW - 2 * 86400)
        cands = ha.select_anchor_candidates(db, now=_NOW, limit=20)
        peak = [c for c in _mine(cands, sid) if c.kind == "peak_severity"]
        assert len(peak) == 1
        assert peak[0].conclusion_id == severe  # TL2 (sev 4) beats TL4

    def test_calm_anchor_requires_elapsed_horizon(self):
        sid = f"{_TAG}_calm"
        horizon = config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS
        aged = _mk_conclusion(
            scenario=sid, state="5",
            observed_at=_NOW - (horizon + 1) * 86400,
        )
        _mk_conclusion(scenario=sid, state="5",
                       observed_at=_NOW - 2 * 86400)  # horizon not elapsed
        cands = ha.select_anchor_candidates(
            db, now=_NOW, window_days=14, limit=20,
        )
        calm = [c for c in _mine(cands, sid) if c.kind == "calm_anchor"]
        assert len(calm) == 1
        assert calm[0].conclusion_id == aged
        assert "TRUE_NEGATIVE" in calm[0].suggested_labels

    def test_answer_model_alert_stance_maps_yes_to_true_positive(self):
        c = ha.AnchorCandidate(
            conclusion_id="x", scenario_id="taiwan_contingency",
            conclusion_type="threat_level", state="2",  # SEVERE = alert
            observed_at=_NOW, kind="peak_severity",
            rationale="", suggested_labels=(),
        )
        am = ha.answer_model_for(c)
        assert am.tool_stance == "alert"
        assert "SEVERE" in am.tool_stance_label
        yes = next(o for o in am.options if o.is_escalation)
        no = next(o for o in am.options if not o.is_escalation)
        assert yes.maps_to == "TRUE_POSITIVE"
        assert no.maps_to == "FALSE_POSITIVE"

    def test_answer_model_calm_stance_maps_yes_to_false_negative(self):
        c = ha.AnchorCandidate(
            conclusion_id="x", scenario_id="korean_peninsula",
            conclusion_type="threat_level", state="5",  # NORMAL = calm
            observed_at=_NOW, kind="calm_anchor",
            rationale="", suggested_labels=(),
        )
        am = ha.answer_model_for(c)
        assert am.tool_stance == "calm"
        yes = next(o for o in am.options if o.is_escalation)
        no = next(o for o in am.options if not o.is_escalation)
        # The analyst affirming an escalation on a calm call is the MISS.
        assert yes.maps_to == "FALSE_NEGATIVE"
        assert no.maps_to == "TRUE_NEGATIVE"

    def test_answer_model_question_names_the_scenario(self):
        c = ha.AnchorCandidate(
            conclusion_id="x", scenario_id="taiwan_contingency",
            conclusion_type="threat_level", state="4",
            observed_at=_NOW, kind="calm_anchor",
            rationale="", suggested_labels=(),
        )
        am = ha.answer_model_for(c)
        assert "China" in am.question and "Taiwan" in am.question
        assert "day" in am.question

    def test_answer_model_attack_mode_fired_is_alert(self):
        c = ha.AnchorCandidate(
            conclusion_id="x", scenario_id="taiwan_contingency",
            conclusion_type="attack_mode", state="SYNC_DDOS",
            observed_at=_NOW, kind="auto_fn_review",
            rationale="", suggested_labels=(),
        )
        am = ha.answer_model_for(c)
        assert am.tool_stance == "alert"
        assert next(o for o in am.options if o.is_escalation).maps_to \
            == "TRUE_POSITIVE"

    def test_limit_respected_and_fn_prioritized(self):
        sid = f"{_TAG}_lim"
        fn_cid = _mk_conclusion(scenario=sid, state="4",
                                observed_at=_NOW - 2 * 86400)
        _mk_feedback(fn_cid, label="FALSE_NEGATIVE", analyst_id="auto:rss",
                     observed_at=_NOW - 2 * 86400)
        for i in range(3):
            _mk_conclusion(scenario=f"{sid}_{i}", state="3",
                           observed_at=_NOW - 86400)
        cands = ha.select_anchor_candidates(db, now=_NOW, limit=1)
        assert len(cands) == 1
        assert cands[0].kind == "auto_fn_review"


# ── route + confirmed_threats revival ────────────────────────────────────


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


class TestQueueEndpoint:

    def test_queue_returns_candidates_and_progress(
        self, client, admin_headers,
    ):
        sid = f"{_TAG}_api"
        _mk_conclusion(scenario=sid, state="2",
                       observed_at=_NOW - 2 * 86400)
        r = client.get("/api/v2/human_anchor/queue", headers=admin_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert "candidates" in body
        assert body["pending"] == len(body["candidates"])
        assert "human_labels_window" in body
        assert body["target_per_week"] >= 1
        for c in body["candidates"]:
            assert c["rationale"]
            assert c["suggested_labels"]

    def test_queue_requires_auth(self, client):
        r = client.get("/api/v2/human_anchor/queue")
        assert r.status_code in (401, 422)


class TestConfirmedThreatsRevival:

    def test_human_tp_with_url_writes_confirmed_threat(
        self, client, admin_headers,
    ):
        sid = "taiwan_contingency"
        cid = _mk_conclusion(scenario=sid, state="2",
                             observed_at=_NOW - 86400)
        before = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM confirmed_threats "
            "WHERE classification LIKE 'human_confirmed:%'",
        ).fetchone()[0]
        r = client.post(
            f"/api/v2/conclusions/{cid}/feedback",
            headers=admin_headers,
            json={"label": "TRUE_POSITIVE",
                  "observed_outcome_url": "https://example.test/event",
                  "notes": "verified against wire reporting"},
        )
        assert r.status_code == 201
        after = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM confirmed_threats "
            "WHERE classification LIKE 'human_confirmed:%'",
        ).fetchone()[0]
        assert after == before + 1

    def test_human_fn_with_url_writes_confirmed_miss(
        self, client, admin_headers,
    ):
        """A human FALSE_NEGATIVE with an outcome URL also revives the
        confirmed_threats ledger: a real escalation the tool missed is
        confirmed ground truth (classification human_confirmed_miss)."""
        cid = _mk_conclusion(scenario="taiwan_contingency", state="5",
                             observed_at=_NOW - 86400)
        before = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM confirmed_threats "
            "WHERE classification LIKE 'human_confirmed_miss:%'",
        ).fetchone()[0]
        r = client.post(
            f"/api/v2/conclusions/{cid}/feedback",
            headers=admin_headers,
            json={"label": "FALSE_NEGATIVE",
                  "observed_outcome_url": "https://example.test/missed"},
        )
        assert r.status_code == 201
        after = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM confirmed_threats "
            "WHERE classification LIKE 'human_confirmed_miss:%'",
        ).fetchone()[0]
        assert after == before + 1

    def test_tp_without_url_does_not_write_confirmed_threat(
        self, client, admin_headers,
    ):
        cid = _mk_conclusion(scenario="taiwan_contingency", state="2",
                             observed_at=_NOW - 86400)
        before = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM confirmed_threats",
        ).fetchone()[0]
        r = client.post(
            f"/api/v2/conclusions/{cid}/feedback",
            headers=admin_headers,
            json={"label": "TRUE_POSITIVE"},
        )
        assert r.status_code == 201
        after = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM confirmed_threats",
        ).fetchone()[0]
        assert after == before
