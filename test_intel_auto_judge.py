"""Tests for radar.intel_auto_judge — deterministic auto-judge recheck.

Issue C (Phase 4 commit 5).

The auto-judge module re-evaluates pending intel items against
corroboration / staleness / duplicate / source-drift rules and either
flips them to confirmed/rejected (with the auto:rule_* analyst marker)
or leaves them pending for human review.

Tests verify each branch of the decision tree, plus NP3 graceful-
degradation behavior.
"""
import os
import time
import uuid
from typing import Any

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")
os.environ["LLM_ENABLED"] = "true"

from radar.database import RadarDB


@pytest.fixture
def testdb(tmp_path):
    tdb = RadarDB(str(tmp_path / "test_auto_judge.db"))
    yield tdb
    tdb.close()


def _base_item(**overrides: Any) -> dict:
    item = {
        "source_type": "military",
        "source_id": "military_usni_news",
        "theater": "TW",
        "countries": ["TW"],
        "country_weights": {"TW": 1.0},
        "ts": time.time(),
        "confidence": 0.72,
        "raw_text": "PLA Navy escalation in Taiwan strait sustained reconnaissance",
        "raw_url": f"https://example.com/{uuid.uuid4()}",
        "headline": "PLA Navy reconnaissance surge near Taiwan",
        "llm_fields": {},
        "score_delta": 2.0,
        "domain": "physical",
    }
    item.update(overrides)
    return item


def _seed_credibility(testdb, source_id, source_type, weight):
    testdb.intel_source_upsert(source_id, source_type, credibility_weight=weight)


def _patch_db(monkeypatch, testdb):
    """Point the auto-judge AND intel_queue at the test db."""
    monkeypatch.setattr("radar.intel_queue.db", testdb)
    monkeypatch.setattr("radar.intel_auto_judge.db", testdb)
    # intel_queue.intel_queue is a singleton — re-instantiate so its
    # internal db reference matches.
    from radar.intel_queue import IntelQueue
    fresh_q = IntelQueue()
    monkeypatch.setattr("radar.intel_auto_judge.intel_queue", fresh_q)
    return fresh_q


# ── Reject paths ────────────────────────────────────────────────────────


class TestAutoJudgeReject:
    def test_low_confidence_no_corroboration_rejects(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import evaluate

        item = _base_item(confidence=0.30)
        # Persist as pending so the corroborator query has DB context.
        testdb.intel_upsert({**item, "id": "i1", "status": "pending",
                           "created_at": time.time()})
        verdict = evaluate(testdb.intel_get("i1"))
        assert verdict.action == "reject"
        assert verdict.reason == "low_confidence_no_corroboration"

    def test_stale_pending_no_corroboration_rejects(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import evaluate

        old = time.time() - 60 * 3600  # 60h old
        item = _base_item(confidence=0.65)  # above reject ceiling
        testdb.intel_upsert({**item, "id": "i_stale", "status": "pending",
                           "created_at": old, "ts": old})
        verdict = evaluate(testdb.intel_get("i_stale"))
        assert verdict.action == "reject"
        assert verdict.reason == "stale_no_corroboration"

    def test_duplicate_of_accepted_rejects(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import evaluate

        # First, an accepted item with a similar headline.
        accepted = _base_item(
            headline="PLA Navy reconnaissance surge near Taiwan strait",
            source_type="diplomatic",
        )
        testdb.intel_upsert({**accepted, "id": "i_acc",
                           "status": "auto_confirmed",
                           "created_at": time.time(), "ts": time.time()})
        # Now a pending duplicate.
        dup = _base_item(headline="PLA Navy reconnaissance surge near Taiwan")
        testdb.intel_upsert({**dup, "id": "i_dup", "status": "pending",
                           "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_dup"))
        assert verdict.action == "reject"
        assert verdict.reason == "duplicate_of_accepted"
        assert "i_acc" in verdict.duplicates_of


# ── Confirm path ────────────────────────────────────────────────────────


class TestAutoJudgeConfirm:
    def test_confidence_plus_corroboration_confirms(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import evaluate

        # First, an independent (different source_type) confirmed peer.
        peer = _base_item(
            source_type="diplomatic",
            source_id="diplomatic_reuters",
            headline="Diplomatic statement on Taiwan strait reconnaissance",
        )
        testdb.intel_upsert({**peer, "id": "i_peer", "status": "confirmed",
                           "created_at": time.time(), "ts": time.time()})
        # Pending item with high confidence + eligible ecosystem.
        target = _base_item(confidence=0.75)  # above confirm floor 0.70
        testdb.intel_upsert({**target, "id": "i_target", "status": "pending",
                           "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_target"))
        assert verdict.action == "confirm"
        assert verdict.corroborator_count >= 1


# ── Pending path ────────────────────────────────────────────────────────


class TestAutoJudgePending:
    def test_middle_band_stays_pending(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import evaluate

        item = _base_item(confidence=0.55)  # above reject ceiling, below confirm floor
        testdb.intel_upsert({**item, "id": "i_mid", "status": "pending",
                           "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_mid"))
        assert verdict.action == "pending"
        assert verdict.reason == "ambiguous_middle_band"

    def test_high_confidence_no_corroborator_stays_pending(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import evaluate

        item = _base_item(confidence=0.80)
        testdb.intel_upsert({**item, "id": "i_hc", "status": "pending",
                           "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_hc"))
        # Without an independent corroborator the auto-judge does not flip.
        assert verdict.action == "pending"

    def test_non_pending_item_returns_pending_action(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import evaluate

        item = _base_item()
        testdb.intel_upsert({**item, "id": "i_done", "status": "auto_confirmed",
                           "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_done"))
        assert verdict.action == "pending"
        assert verdict.reason == "not_pending"


# ── Apply + sweep wiring ────────────────────────────────────────────────


class TestAutoJudgeApply:
    def test_apply_confirm_marks_analyst_marker(self, testdb, monkeypatch):
        q = _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import (
            ANALYST_AUTO_CONFIRM, AutoJudgeVerdict, apply,
        )
        item = _base_item()
        testdb.intel_upsert({**item, "id": "i_apply", "status": "pending",
                           "created_at": time.time(), "ts": time.time()})
        verdict = AutoJudgeVerdict(
            action="confirm", reason="confidence_plus_corroboration",
            confidence_floor_used=0.7, corroborator_count=1,
        )
        ok = apply("i_apply", verdict)
        assert ok is True
        got = testdb.intel_get("i_apply")
        assert got["status"] == "confirmed"
        assert got["confirmed_by"] == ANALYST_AUTO_CONFIRM

    def test_apply_reject_marks_analyst_marker(self, testdb, monkeypatch):
        q = _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import (
            ANALYST_AUTO_REJECT, AutoJudgeVerdict, apply,
        )
        item = _base_item()
        testdb.intel_upsert({**item, "id": "i_rej", "status": "pending",
                           "created_at": time.time(), "ts": time.time()})
        verdict = AutoJudgeVerdict(action="reject", reason="low_confidence_no_corroboration")
        assert apply("i_rej", verdict) is True
        got = testdb.intel_get("i_rej")
        assert got["status"] == "rejected"
        assert got["confirmed_by"] == ANALYST_AUTO_REJECT

    def test_llm_recheck_gated_off_by_default(self, testdb, monkeypatch):
        """LLM_AUTO_JUDGE_RECHECK is unset / false → middle-band items
        stay pending and never invoke the LLM client.
        """
        _patch_db(monkeypatch, testdb)
        monkeypatch.delenv("LLM_AUTO_JUDGE_RECHECK", raising=False)
        from radar.intel_auto_judge import evaluate

        called = {"n": 0}
        def _boom(*a, **k):
            called["n"] += 1
            raise AssertionError("LLM client must NOT be called when flag is off")
        # If the gate is honored, this stub is never invoked.
        monkeypatch.setattr("radar.llm_client.llm_analyze_json", _boom)

        item = _base_item(confidence=0.55)
        testdb.intel_upsert({**item, "id": "i_off", "status": "pending",
                             "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_off"))
        assert verdict.action == "pending"
        assert called["n"] == 0

    def test_llm_recheck_flips_when_enabled_and_confident(self, testdb, monkeypatch):
        """LLM_AUTO_JUDGE_RECHECK=true + LLM returns confident reject →
        verdict flips to reject with the auto:llm_recheck_reject marker.
        """
        _patch_db(monkeypatch, testdb)
        monkeypatch.setenv("LLM_AUTO_JUDGE_RECHECK", "true")

        # Stub llm_available True + llm_analyze_json with a confident reject.
        monkeypatch.setattr("radar.llm_client.llm_available", lambda: True)
        monkeypatch.setattr(
            "radar.llm_client.llm_analyze_json",
            lambda *a, **k: {"ok": True, "data": {
                "action": "reject", "confidence": 0.92,
                "reason": "off-topic social-media noise",
            }},
        )
        from radar.intel_auto_judge import (
            ANALYST_LLM_REJECT, apply, evaluate,
        )
        item = _base_item(confidence=0.55)
        testdb.intel_upsert({**item, "id": "i_llm_rej", "status": "pending",
                             "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_llm_rej"))
        assert verdict.action == "reject"
        assert verdict.reason.startswith("llm_recheck:")
        assert apply("i_llm_rej", verdict) is True
        got = testdb.intel_get("i_llm_rej")
        assert got["status"] == "rejected"
        assert got["confirmed_by"] == ANALYST_LLM_REJECT

    def test_llm_recheck_below_floor_stays_pending(self, testdb, monkeypatch):
        """LLM returns a verdict but below the confidence floor → ignored,
        deterministic pending verdict preserved (NP1 conservatism)."""
        _patch_db(monkeypatch, testdb)
        monkeypatch.setenv("LLM_AUTO_JUDGE_RECHECK", "true")
        monkeypatch.setattr("radar.llm_client.llm_available", lambda: True)
        monkeypatch.setattr(
            "radar.llm_client.llm_analyze_json",
            lambda *a, **k: {"ok": True, "data": {
                "action": "confirm", "confidence": 0.65,  # below default 0.80 floor
                "reason": "looks plausible",
            }},
        )
        from radar.intel_auto_judge import evaluate

        item = _base_item(confidence=0.55)
        testdb.intel_upsert({**item, "id": "i_llm_low", "status": "pending",
                             "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_llm_low"))
        assert verdict.action == "pending"

    def test_llm_recheck_unreachable_falls_back_pending(self, testdb, monkeypatch):
        """LLM is enabled but unavailable → degrades to deterministic pending."""
        _patch_db(monkeypatch, testdb)
        monkeypatch.setenv("LLM_AUTO_JUDGE_RECHECK", "true")
        monkeypatch.setattr("radar.llm_client.llm_available", lambda: False)
        from radar.intel_auto_judge import evaluate

        item = _base_item(confidence=0.55)
        testdb.intel_upsert({**item, "id": "i_unrch", "status": "pending",
                             "created_at": time.time(), "ts": time.time()})
        verdict = evaluate(testdb.intel_get("i_unrch"))
        assert verdict.action == "pending"

    def test_run_sweep_returns_counts(self, testdb, monkeypatch):
        _patch_db(monkeypatch, testdb)
        from radar.intel_auto_judge import run_sweep

        # Seed: one definite reject (low confidence), one definite middle-band pending.
        testdb.intel_upsert({
            **_base_item(confidence=0.20),
            "id": "i_rej_sweep", "status": "pending",
            "created_at": time.time(), "ts": time.time(),
        })
        testdb.intel_upsert({
            **_base_item(confidence=0.55),
            "id": "i_pending_sweep", "status": "pending",
            "created_at": time.time(), "ts": time.time(),
        })
        out = run_sweep(limit=50)
        assert out["evaluated"] >= 2
        assert out["reject"] >= 1
        # The middle-band item should NOT have been confirmed or rejected.
        assert testdb.intel_get("i_pending_sweep")["status"] == "pending"
