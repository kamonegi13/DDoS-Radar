"""Tests for radar.calibration.auto_apply_tier_governor.

The governor's persistence is exercised entirely against an in-memory
SQLite injected via the ``tier_governor_repo`` fixture (defined in the
project root ``conftest.py``). The fixture creates a fresh ``:memory:``
DB per test, applies the v52 + v53 schema inline, and points the
governor module's repository at it for the duration of the test, so
the live container DB is never touched.

This is a deliberate departure from the original test file, which used
``DELETE FROM …`` against the production tables in setUp/tearDown to
"isolate" between cases. That approach destroyed real tier history
every time the suite ran. See Phase 1 of the tier-governor hardening
plan (2026-05-05) for context.
"""
from __future__ import annotations

import os
import time

import pytest

from radar.calibration import auto_apply_tier_governor as tg


# ── CI guardrail ─────────────────────────────────────────────────────────────
#
# This module's tests must NEVER touch the live container DB. Phase 1 of
# the tier-governor hardening introduced this guardrail after we saw the
# pre-refactor suite truncate production tier history every run.
#
# The fixture patches ``radar.database.db._get_conn`` to raise — so any
# code path that bypasses the injected repository immediately fails
# loud instead of silently writing to the production singleton.

@pytest.fixture(autouse=True)
def _block_live_db_access(monkeypatch):
    def _forbid(*_args, **_kwargs):
        raise RuntimeError(
            "test attempted to open the production DB connection — "
            "use the tier_governor_repo / tier_governor_conn fixtures instead"
        )

    # Patch lazily: the real `db._get_conn` may not be importable in
    # every environment; we still want the guardrail to engage for
    # whatever subset is reachable.
    try:
        from radar.database import db as _db
        monkeypatch.setattr(_db, "_get_conn", _forbid, raising=False)
    except Exception:
        pass
    yield


# ── Helpers ──────────────────────────────────────────────────────────────────


def _insert_state(
    conn,
    *,
    tier: int,
    transition: str,
    ago_seconds: float = 0.0,
    reason: str = "test",
    metrics_json: str = "{}",
) -> None:
    with conn.writing():
        conn.execute(
            "INSERT INTO auto_apply_tier_state "
            "(observed_at, tier, transition, reason, metrics_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (time.time() - ago_seconds, tier, transition, reason, metrics_json),
        )


def _insert_threshold_history(
    conn,
    *,
    key: str,
    value: str,
    applied_by: str,
    scope: str | None = None,
    ago_seconds: float = 0.0,
) -> None:
    with conn.writing():
        conn.execute(
            "INSERT INTO threshold_history "
            "(emitted_at, key, value, scope_scenario_id, "
            " effective_from, derived_from, applied_by, sample_n, "
            " formula_ref, evidence_json, magnitude_pct, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                time.time() - ago_seconds,
                key, value, scope,
                time.time() - ago_seconds,
                "test", applied_by, 100, "test#fn",
                "{}", 5.0, "active",
            ),
        )


def _insert_diff_log(conn, *, match: bool, ago_seconds: float = 0.0) -> None:
    with conn.writing():
        conn.execute(
            "INSERT INTO conclusion_diff_log "
            "(sampled_at, scenario_id, conclusion_type, v1_state, v2_state, "
            " is_match, diff_kind, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                time.time() - ago_seconds, "test_scenario", "threat_level",
                "TL3", "TL3", 1 if match else 0,
                "match" if match else "divergence", "{}",
            ),
        )


# ── Tier basics ──────────────────────────────────────────────────────────────


class TestTierGovernorBasics:
    def test_default_tier_is_zero(self, tier_governor_repo):
        snap = tg.current_tier()
        assert snap.tier == 0

    def test_kill_switch_caps_tier(self, tier_governor_conn):
        _insert_state(tier_governor_conn, tier=3, transition="promote")
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "0"
        try:
            snap = tg.current_tier()
            assert snap.tier == 0
            assert snap.cap == 0
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)

    def test_kill_switch_invalid_value_defaults_to_3(self, tier_governor_repo):
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "garbage"
        try:
            snap = tg.current_tier()
            assert snap.cap == 3
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)

    def test_apply_allowed_at_tier_0(self, tier_governor_repo):
        # No state row → tier 0 → nothing applies.
        for ab in ("auto:tl_calibrator", "auto:llm_floor", "auto:domain_weight"):
            assert not tg.is_apply_allowed(ab)

    def test_apply_allowed_at_tier_1(self, tier_governor_conn):
        _insert_state(tier_governor_conn, tier=1, transition="promote")
        assert tg.is_apply_allowed("auto:tl_calibrator")
        assert not tg.is_apply_allowed("auto:llm_floor")
        assert not tg.is_apply_allowed("auto:domain_weight")

    def test_apply_allowed_at_tier_3(self, tier_governor_conn):
        _insert_state(tier_governor_conn, tier=3, transition="promote")
        for ab in ("auto:tl_calibrator", "auto:llm_floor", "auto:domain_weight"):
            assert tg.is_apply_allowed(ab)


# ── Promotion ────────────────────────────────────────────────────────────────


class TestPromotion:
    def test_promote_0_to_1_when_data_sufficient(
        self, tier_governor_repo, monkeypatch,
    ):
        # Tier 0 → 1 needs auto_feedback_rows ≥ 100. Monkey-patch the
        # counter rather than seeding 100 rows + their FK targets — the
        # original test file did the latter against the live DB which
        # is exactly what we're moving away from.
        monkeypatch.setattr(tg, "_auto_feedback_rows", lambda: 200)
        result = tg.evaluate_and_transition()
        assert result.transition == "promote"
        assert result.new_tier == 1

    def test_no_promote_when_feedback_thin(
        self, tier_governor_repo, monkeypatch,
    ):
        monkeypatch.setattr(tg, "_auto_feedback_rows", lambda: 30)
        result = tg.evaluate_and_transition()
        assert result.transition in ("init", "unchanged")
        assert result.new_tier == 0

    def test_promote_blocked_by_cap(self, tier_governor_conn):
        _insert_state(
            tier_governor_conn,
            tier=1, transition="promote", ago_seconds=10 * 86400.0,
        )
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "1"
        try:
            # Even though Tier 1 → 2 conditions might be met, the cap
            # holds us at 1. evaluate_and_transition should not promote.
            result = tg.evaluate_and_transition()
            assert result.new_tier != 2
            assert result.transition != "promote"
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)


# ── Kill-switch demotion ─────────────────────────────────────────────────────


class TestKillSwitchDemotion:
    def test_cap_below_current_tier_forces_demotion(self, tier_governor_conn):
        _insert_state(tier_governor_conn, tier=3, transition="promote")
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "1"
        try:
            result = tg.evaluate_and_transition()
            assert result.transition == "kill_switch_engaged"
            assert result.new_tier == 1
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)


# ── HIGH cooldown ────────────────────────────────────────────────────────────


class TestHighCooldown:
    @pytest.fixture(autouse=True)
    def _seed_tier_3(self, tier_governor_conn):
        _insert_state(tier_governor_conn, tier=3, transition="promote")

    def test_high_change_locks_low_med_for_24h(self, tier_governor_repo):
        # Pre-cooldown: LOW/MED applies allowed at tier 3.
        assert tg.is_apply_allowed("auto:tl_calibrator")
        assert tg.is_apply_allowed("auto:llm_floor")
        # Trigger the cooldown.
        tg.trigger_high_cooldown(triggered_by="auto:domain_weight")
        # LOW/MED now blocked even though tier is 3.
        assert not tg.is_apply_allowed("auto:tl_calibrator")
        assert not tg.is_apply_allowed("auto:llm_floor")
        # HIGH itself still allowed (it's the trigger).
        assert tg.is_apply_allowed("auto:domain_weight")

    def test_cooldown_expires(self, tier_governor_conn):
        tg.trigger_high_cooldown(triggered_by="auto:domain_weight")
        # Manually rewind the cooldown row to the past.
        with tier_governor_conn.writing():
            tier_governor_conn.execute(
                "UPDATE auto_apply_cooldown SET cooldown_until=? "
                "WHERE impact_level IN ('low','med')",
                (time.time() - 10.0,),
            )
        assert tg.is_apply_allowed("auto:tl_calibrator")


# ── Circuit breaker ──────────────────────────────────────────────────────────


class TestCircuitBreaker:
    def test_consecutive_failures_force_tier_zero(
        self, tier_governor_conn, monkeypatch,
    ):
        _insert_state(tier_governor_conn, tier=2, transition="promote")
        # Inject N-1 prior failure rows; the next failed evaluate should
        # trip the breaker.
        for _ in range(tg.CONSECUTIVE_FAILURE_LIMIT - 1):
            with tier_governor_conn.writing():
                tier_governor_conn.execute(
                    "INSERT INTO auto_apply_tier_state "
                    "(observed_at, tier, transition, reason, metrics_json) "
                    "VALUES (?, ?, 'evaluation_failed', 'test', '{}')",
                    (time.time(), 2),
                )

        # Force one more failure by making the inner evaluator raise.
        def _boom():
            raise RuntimeError("synthetic")

        monkeypatch.setattr(tg, "_evaluate_and_transition_inner", _boom)
        result = tg.evaluate_and_transition()
        assert result.transition == "circuit_breaker"
        assert result.new_tier == 0
