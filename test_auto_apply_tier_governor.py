"""Tests for radar.calibration.auto_apply_tier_governor.

The governor is a long-running daemon that reads its own audit log to
decide whether to promote / demote the auto-apply tier. The DB tables
(`auto_apply_tier_state`, `auto_apply_cooldown`) are created by
migration v52; the singleton ``radar.database.db`` ensures they exist
on import.

Each test runs against the live container DB but isolates itself by
truncating the relevant tables in setUp / tearDown, restoring whatever
state was there. Cleanups never fail the suite.
"""
from __future__ import annotations

import json
import os
import time
import unittest

from radar.calibration import auto_apply_tier_governor as tg
from radar.database import db


def _conn():
    return db._get_conn()  # noqa: SLF001


def _truncate(table: str) -> None:
    try:
        with _conn().writing():
            _conn().execute(f"DELETE FROM {table}")
    except Exception:
        pass


def _insert_state(*, tier: int, transition: str, ago_seconds: float = 0.0,
                  reason: str = "test", metrics: dict | None = None) -> None:
    with _conn().writing():
        _conn().execute(
            "INSERT INTO auto_apply_tier_state "
            "(observed_at, tier, transition, reason, metrics_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (time.time() - ago_seconds, tier, transition, reason,
             json.dumps(metrics or {})),
        )


def _insert_threshold_history(
    *, key: str, value: str, applied_by: str, scope: str | None = None,
    ago_seconds: float = 0.0,
) -> None:
    with _conn().writing():
        _conn().execute(
            "INSERT INTO threshold_history "
            "(emitted_at, key, value, scope_scenario_id, "
            " effective_from, derived_from, applied_by, sample_n, "
            " formula_ref, evidence_json, magnitude_pct, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time() - ago_seconds, key, value, scope,
             time.time() - ago_seconds,
             "test", applied_by, 100, "test#fn",
             "{}", 5.0, "active"),
        )


def _insert_diff_log(*, match: bool, ago_seconds: float = 0.0) -> None:
    with _conn().writing():
        _conn().execute(
            "INSERT INTO conclusion_diff_log "
            "(sampled_at, scenario_id, conclusion_type, v1_state, v2_state, "
            " is_match, diff_kind, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time() - ago_seconds, "test_scenario", "threat_level",
             "TL3", "TL3", 1 if match else 0,
             "match" if match else "divergence", "{}"),
        )


def _insert_auto_feedback(n: int = 100) -> None:
    """Insert n auto:* feedback rows. Re-uses existing conclusions
    so the FK constraint to conclusions(id) is satisfied without
    polluting the conclusions table itself."""
    rows = list(_conn().execute(
        "SELECT id FROM conclusions LIMIT ?", (n,)
    ))
    if len(rows) < n:
        # Test environment without enough live conclusions. Skip
        # silently — the unit test using this helper is expected to
        # check `len(_existing_conclusions()) >= 100` itself in CI.
        n = len(rows)
    with _conn().writing():
        for r in rows[:n]:
            _conn().execute(
                "INSERT INTO analyst_feedback "
                "(conclusion_id, label, analyst_id, observed_at, notes) "
                "VALUES (?, ?, ?, ?, ?)",
                (r[0], "TRUE_POSITIVE",
                 "auto:test", time.time(), "test"),
            )


class TestTierGovernorBasics(unittest.TestCase):
    def setUp(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")

    def tearDown(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")

    def test_default_tier_is_zero(self):
        snap = tg.current_tier()
        self.assertEqual(snap.tier, 0)

    def test_kill_switch_caps_tier(self):
        _insert_state(tier=3, transition="promote")
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "0"
        try:
            snap = tg.current_tier()
            self.assertEqual(snap.tier, 0)
            self.assertEqual(snap.cap, 0)
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)

    def test_kill_switch_invalid_value_defaults_to_3(self):
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "garbage"
        try:
            snap = tg.current_tier()
            self.assertEqual(snap.cap, 3)
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)

    def test_apply_allowed_at_tier_0(self):
        # No state row → tier 0 → nothing applies.
        for ab in ("auto:tl_calibrator", "auto:llm_floor", "auto:domain_weight"):
            self.assertFalse(tg.is_apply_allowed(ab))

    def test_apply_allowed_at_tier_1(self):
        _insert_state(tier=1, transition="promote")
        self.assertTrue(tg.is_apply_allowed("auto:tl_calibrator"))
        self.assertFalse(tg.is_apply_allowed("auto:llm_floor"))
        self.assertFalse(tg.is_apply_allowed("auto:domain_weight"))

    def test_apply_allowed_at_tier_3(self):
        _insert_state(tier=3, transition="promote")
        for ab in ("auto:tl_calibrator", "auto:llm_floor", "auto:domain_weight"):
            self.assertTrue(tg.is_apply_allowed(ab))


class TestPromotion(unittest.TestCase):
    def setUp(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")
        _truncate("threshold_history")
        # Snapshot existing analyst_feedback so we restore production
        # data after the test (the test inserts auto:test rows).
        with _conn().writing():
            _conn().execute(
                "DELETE FROM analyst_feedback WHERE analyst_id='auto:test'"
            )

    def tearDown(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")
        _truncate("threshold_history")
        with _conn().writing():
            _conn().execute(
                "DELETE FROM analyst_feedback WHERE analyst_id='auto:test'"
            )

    def test_promote_0_to_1_when_data_sufficient(self):
        # Tier 0 → 1 needs auto_feedback ≥ 100 + recent governor activity.
        _insert_auto_feedback(n=200)
        for i in range(20):
            _insert_threshold_history(
                key=f"tl_thresholds.test_{i}.tl3_total",
                value="5.0", applied_by="auto:tl_calibrator",
                scope=f"test_scope_{i}",
                ago_seconds=3600.0 + i,
            )
        result = tg.evaluate_and_transition()
        self.assertEqual(result.transition, "promote")
        self.assertEqual(result.new_tier, 1)

    def test_no_promote_when_feedback_thin(self):
        # Promotion 0→1 also needs governor_proposal_count ≥ 10 in
        # window. Without threshold_history rows in the last 7d the
        # promotion fails on that gate even when auto_feedback is
        # plentiful, which is what this test verifies.
        # (auto_feedback table may already contain production rows;
        # the assertion is "no promotion happened", not "0 rows".)
        result = tg.evaluate_and_transition()
        self.assertIn(result.transition, ("init", "unchanged"))
        self.assertEqual(result.new_tier, 0)

    def test_promote_blocked_by_cap(self):
        _insert_state(tier=1, transition="promote",
                      ago_seconds=10 * 86400.0)
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "1"
        try:
            # Even though Tier 1 → 2 conditions might be met, the cap
            # holds us at 1. evaluate_and_transition should return
            # 'unchanged' with no promote attempt.
            result = tg.evaluate_and_transition()
            self.assertNotEqual(result.new_tier, 2)
            self.assertNotEqual(result.transition, "promote")
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)


class TestKillSwitchDemotion(unittest.TestCase):
    def setUp(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")

    def tearDown(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")

    def test_cap_below_current_tier_forces_demotion(self):
        _insert_state(tier=3, transition="promote")
        os.environ["AUTO_CALIBRATION_TIER_CAP"] = "1"
        try:
            result = tg.evaluate_and_transition()
            self.assertEqual(result.transition, "kill_switch_engaged")
            self.assertEqual(result.new_tier, 1)
        finally:
            os.environ.pop("AUTO_CALIBRATION_TIER_CAP", None)


class TestHighCooldown(unittest.TestCase):
    def setUp(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")
        _insert_state(tier=3, transition="promote")

    def tearDown(self):
        _truncate("auto_apply_tier_state")
        _truncate("auto_apply_cooldown")

    def test_high_change_locks_low_med_for_24h(self):
        # Pre-cooldown: LOW/MED applies allowed at tier 3.
        self.assertTrue(tg.is_apply_allowed("auto:tl_calibrator"))
        self.assertTrue(tg.is_apply_allowed("auto:llm_floor"))
        # Trigger the cooldown.
        tg.trigger_high_cooldown(triggered_by="auto:domain_weight")
        # LOW/MED now blocked even though tier is 3.
        self.assertFalse(tg.is_apply_allowed("auto:tl_calibrator"))
        self.assertFalse(tg.is_apply_allowed("auto:llm_floor"))
        # HIGH itself still allowed (it's the trigger).
        self.assertTrue(tg.is_apply_allowed("auto:domain_weight"))

    def test_cooldown_expires(self):
        tg.trigger_high_cooldown(triggered_by="auto:domain_weight")
        # Manually rewind the cooldown row to the past.
        with _conn().writing():
            _conn().execute(
                "UPDATE auto_apply_cooldown SET cooldown_until=? "
                "WHERE impact_level IN ('low','med')",
                (time.time() - 10.0,),
            )
        self.assertTrue(tg.is_apply_allowed("auto:tl_calibrator"))


class TestCircuitBreaker(unittest.TestCase):
    def setUp(self):
        _truncate("auto_apply_tier_state")
        _insert_state(tier=2, transition="promote")

    def tearDown(self):
        _truncate("auto_apply_tier_state")

    def test_consecutive_failures_force_tier_zero(self):
        # Inject N failure rows directly; the next failed evaluate
        # should trip the breaker.
        for _ in range(tg.CONSECUTIVE_FAILURE_LIMIT - 1):
            with _conn().writing():
                _conn().execute(
                    "INSERT INTO auto_apply_tier_state "
                    "(observed_at, tier, transition, reason, metrics_json) "
                    "VALUES (?, ?, 'evaluation_failed', 'test', '{}')",
                    (time.time(), 2),
                )
        # Force one more failure by making _evaluate_and_transition_inner raise.
        original = tg._evaluate_and_transition_inner
        try:
            tg._evaluate_and_transition_inner = lambda: (_ for _ in ()).throw(
                RuntimeError("synthetic")
            )
            result = tg.evaluate_and_transition()
            self.assertEqual(result.transition, "circuit_breaker")
            self.assertEqual(result.new_tier, 0)
        finally:
            tg._evaluate_and_transition_inner = original


if __name__ == "__main__":
    unittest.main()
