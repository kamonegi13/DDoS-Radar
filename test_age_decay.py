"""Tests for ADR-023: LLM intel age-decay.

Covers:
  - _age_weight() returns 1.0 when decay disabled or τ<=0
  - Exponential curve: age=0 → 1.0, age=τ → 1/e, age=2τ → 1/e², age=∞ → 0
  - Per-source_type τ override (INTEL_AGE_DECAY_TAU_HOURS_<TYPE>)
  - get_active_rationale() applies decay and ranks cap by decayed score
  - Items past TTL are excluded even when decay would still yield nonzero
"""
from __future__ import annotations

import math
import os
import time
import uuid

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")
os.environ["LLM_ENABLED"] = "true"

from radar import intel_queue as iq
from radar.database import RadarDB


# ── _age_weight() unit tests ─────────────────────────────────────────────────

_DECAY_ENV_KEYS = (
    "INTEL_AGE_DECAY_ENABLED",
    "INTEL_AGE_DECAY_TAU_HOURS",
    "INTEL_AGE_DECAY_TAU_HOURS_DIPLOMATIC",
    "INTEL_AGE_DECAY_TAU_HOURS_HACKTIVIST",
    "INTEL_AGE_DECAY_TAU_HOURS_MILITARY",
)


@pytest.fixture
def clean_decay_env(monkeypatch):
    """Strip any decay-related env vars for deterministic tests.
    Using monkeypatch ensures state cannot leak into other test classes."""
    for k in _DECAY_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


class TestAgeWeight:
    def test_age_zero_returns_one(self, clean_decay_env) -> None:
        assert iq._age_weight(0.0) == pytest.approx(1.0)

    def test_age_equals_tau_returns_one_over_e(self, clean_decay_env) -> None:
        tau_h = 12.0
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS", str(tau_h))
        assert iq._age_weight(tau_h * 3600.0) == pytest.approx(1.0 / math.e, rel=1e-6)

    def test_age_equals_two_tau_returns_e_minus_two(self, clean_decay_env) -> None:
        tau_h = 12.0
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS", str(tau_h))
        assert iq._age_weight(2 * tau_h * 3600.0) == pytest.approx(math.exp(-2), rel=1e-6)

    def test_negative_age_clamped_to_zero(self, clean_decay_env) -> None:
        # Clock skew should never produce a weight > 1.
        assert iq._age_weight(-3600.0) == pytest.approx(1.0)

    def test_decay_disabled_returns_one(self, clean_decay_env) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_ENABLED", "false")
        assert iq._age_weight(48 * 3600.0) == pytest.approx(1.0)

    def test_tau_zero_disables_decay(self, clean_decay_env) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS", "0")
        assert iq._age_weight(12 * 3600.0) == pytest.approx(1.0)

    def test_negative_tau_disables_decay(self, clean_decay_env) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS", "-5")
        assert iq._age_weight(12 * 3600.0) == pytest.approx(1.0)

    def test_per_source_override_takes_precedence(self, clean_decay_env) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS", "24")
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS_DIPLOMATIC", "6")
        # At 6h: global τ=24h would give exp(-0.25)=0.78; override τ=6h gives 1/e≈0.37.
        w_diplomatic = iq._age_weight(6 * 3600.0, source_type="diplomatic")
        w_default    = iq._age_weight(6 * 3600.0, source_type="military")
        assert w_diplomatic == pytest.approx(1.0 / math.e, rel=1e-6)
        assert w_default    == pytest.approx(math.exp(-0.25), rel=1e-6)

    def test_per_source_override_bad_value_falls_back(self, clean_decay_env) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS_DIPLOMATIC", "not-a-number")
        # Bad per-source value must fall back to global τ, not crash.
        assert iq._age_weight(12 * 3600.0, source_type="diplomatic") == pytest.approx(
            1.0 / math.e, rel=1e-6
        )

    def test_case_insensitive_source_type(self, clean_decay_env) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS", "24")
        clean_decay_env.setenv("INTEL_AGE_DECAY_TAU_HOURS_MILITARY", "4")
        w = iq._age_weight(4 * 3600.0, source_type="military")
        assert w == pytest.approx(1.0 / math.e, rel=1e-6)


# ── _decay_enabled() env parsing ─────────────────────────────────────────────

class TestDecayEnabled:
    @pytest.mark.parametrize("val", ["false", "0", "no", "off", "FALSE", "Off"])
    def test_falsy_values_disable(self, clean_decay_env, val: str) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_ENABLED", val)
        assert iq._decay_enabled() is False

    @pytest.mark.parametrize("val", ["true", "1", "yes", "TRUE", "on", "anything-else"])
    def test_truthy_values_enable(self, clean_decay_env, val: str) -> None:
        clean_decay_env.setenv("INTEL_AGE_DECAY_ENABLED", val)
        assert iq._decay_enabled() is True

    def test_unset_defaults_to_enabled(self, clean_decay_env) -> None:
        assert iq._decay_enabled() is True


# ── Integration: get_active_rationale() applies decay ────────────────────────

@pytest.fixture
def iqdb(tmp_path, monkeypatch):
    """Swap intel_queue's module-level `db` for an isolated test DB."""
    db_path = str(tmp_path / "test_decay.db")
    tdb = RadarDB(db_path)
    monkeypatch.setattr(iq, "db", tdb)
    # Reset env to deterministic defaults for each test.
    for k in (
        "INTEL_AGE_DECAY_ENABLED",
        "INTEL_AGE_DECAY_TAU_HOURS",
        "INTEL_ITEM_TTL_HOURS",
        "INTEL_MAX_ITEMS_PER_SOURCE_COUNTRY",
    ):
        monkeypatch.delenv(k, raising=False)
    yield tdb
    tdb.close()


def _confirmed_item(
    *,
    ts: float,
    score_delta: float = 2.0,
    source_type: str = "military",
    theater: str = "TW",
    headline: str = "Test item",
    confidence: float = 0.85,
) -> dict:
    now = ts
    return {
        "id": str(uuid.uuid4()),
        "source_type": source_type,
        "source_id": f"{source_type}_test",
        "theater": theater,
        "countries": [theater],
        "country_weights": {theater: 1.0},
        "ts": ts,
        "status": "confirmed",
        "confidence": confidence,
        "raw_text": "",
        "raw_url": "",
        "headline": headline,
        "llm_fields": {},
        "score_delta": score_delta,
        "domain": "physical",
        "confirmed_by": "test",
        "confirmed_at": now,
        "override_at": None,
        "created_at": ts,
    }


class TestGetActiveRationaleDecay:
    def test_fresh_item_gets_full_score(self, iqdb, monkeypatch) -> None:
        monkeypatch.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        now = time.time()
        iqdb.intel_upsert(_confirmed_item(ts=now - 60, score_delta=3.0))  # 1 min old
        rationale = iq.intel_queue.get_active_rationale()
        assert len(rationale) == 1
        entry = rationale[0]
        assert entry["score_raw"] == pytest.approx(3.0)
        # 1 min out of τ=12h: weight ≈ 0.999
        assert entry["age_weight"] == pytest.approx(math.exp(-60.0 / (12 * 3600.0)), rel=1e-6)
        assert entry["score"] == pytest.approx(3.0 * entry["age_weight"], rel=1e-6)

    def test_aged_item_decays(self, iqdb, monkeypatch) -> None:
        monkeypatch.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        now = time.time()
        # 12h old → weight 1/e ≈ 0.3679
        iqdb.intel_upsert(_confirmed_item(ts=now - 12 * 3600, score_delta=5.0))
        rationale = iq.intel_queue.get_active_rationale()
        assert len(rationale) == 1
        entry = rationale[0]
        assert entry["age_weight"] == pytest.approx(1.0 / math.e, rel=1e-3)
        assert entry["score"] == pytest.approx(5.0 / math.e, rel=1e-3)
        assert "age 12.0h" in entry["detail"]

    def test_item_beyond_ttl_excluded(self, iqdb, monkeypatch) -> None:
        monkeypatch.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        monkeypatch.setenv("INTEL_ITEM_TTL_HOURS", "24")
        now = time.time()
        iqdb.intel_upsert(_confirmed_item(ts=now - 25 * 3600, score_delta=10.0))  # past TTL
        assert iq.intel_queue.get_active_rationale() == []

    def test_decay_disabled_uses_raw_score(self, iqdb, monkeypatch) -> None:
        monkeypatch.setenv("INTEL_AGE_DECAY_ENABLED", "false")
        now = time.time()
        iqdb.intel_upsert(_confirmed_item(ts=now - 10 * 3600, score_delta=4.0))
        rationale = iq.intel_queue.get_active_rationale()
        assert len(rationale) == 1
        entry = rationale[0]
        assert entry["age_weight"] == pytest.approx(1.0)
        assert entry["score"] == pytest.approx(4.0)

    def test_cap_ranks_by_decayed_score(self, iqdb, monkeypatch) -> None:
        """A fresh lower-raw item should outrank a stale higher-raw item once
        decay is applied — the regression target the whole feature exists for.
        """
        monkeypatch.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        monkeypatch.setenv("INTEL_MAX_ITEMS_PER_SOURCE_COUNTRY", "1")
        now = time.time()
        # Stale hi-raw: score_delta=5.0 at age=24h → decayed ≈ 5 * e^-2 ≈ 0.677
        iqdb.intel_upsert(_confirmed_item(
            ts=now - 24 * 3600, score_delta=5.0, headline="STALE high-raw"))
        # Fresh lo-raw: score_delta=2.0 at age=0 → decayed ≈ 2.0
        iqdb.intel_upsert(_confirmed_item(
            ts=now - 60, score_delta=2.0, headline="FRESH low-raw"))
        rationale = iq.intel_queue.get_active_rationale()
        assert len(rationale) == 1  # cap=1
        assert "FRESH" in rationale[0]["detail"]
        assert rationale[0]["score_raw"] == pytest.approx(2.0)

    def test_multiple_groups_independent(self, iqdb, monkeypatch) -> None:
        """Different (source_type, theater) groups each get their own cap."""
        monkeypatch.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        monkeypatch.setenv("INTEL_MAX_ITEMS_PER_SOURCE_COUNTRY", "1")
        now = time.time()
        iqdb.intel_upsert(_confirmed_item(
            ts=now - 60, source_type="military", theater="TW", score_delta=2.0))
        iqdb.intel_upsert(_confirmed_item(
            ts=now - 60, source_type="diplomatic", theater="TW", score_delta=1.0))
        iqdb.intel_upsert(_confirmed_item(
            ts=now - 60, source_type="military", theater="JP", score_delta=1.5))
        rationale = iq.intel_queue.get_active_rationale()
        # 3 distinct (source_type, theater) groups, cap=1 each → 3 items survive.
        assert len(rationale) == 3

    def test_overridden_items_excluded(self, iqdb, monkeypatch) -> None:
        monkeypatch.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        now = time.time()
        item = _confirmed_item(ts=now - 60, score_delta=3.0)
        item["status"] = "auto_confirmed"
        item["override_at"] = now
        iqdb.intel_upsert(item)
        assert iq.intel_queue.get_active_rationale() == []

    def test_detail_string_contains_age_and_weight(self, iqdb, monkeypatch) -> None:
        """Observability: operators need to see age/weight per active entry."""
        monkeypatch.setenv("INTEL_AGE_DECAY_TAU_HOURS", "12")
        now = time.time()
        iqdb.intel_upsert(_confirmed_item(ts=now - 6 * 3600, score_delta=4.0))
        rationale = iq.intel_queue.get_active_rationale()
        detail = rationale[0]["detail"]
        assert "age 6.0h" in detail
        # exp(-0.5) ≈ 0.61 → rendered as "w=0.61"
        assert "w=0.61" in detail
