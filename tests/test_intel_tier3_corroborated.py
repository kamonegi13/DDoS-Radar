"""Tests for Phase 2 / Item 1.1: Tier 3 corroborated auto_confirm.

Background:
  Existing tier1 (strict): confidence >= 0.85 AND credibility >= 0.80
  Existing tier2 (standard): confidence >= 0.80 AND credibility >= 0.75
  These produce 0 auto-confirms in practice because most LLM-rated
  intel falls in the 0.70-0.79 confidence band.

Item 1.1 introduces tier 3 (corroborated):
  confidence >= 0.70 AND credibility >= 0.75 AND corroborating_sources >= 1

Corroboration is only ever added by the dedup pass when an independent
source matches the same event. So tier 3 is "two independent sources
agree" — a meaningful safety net even at lower per-call confidence.

Verdict tag: ``auto_confirmed_corroborated`` (distinct from tier1 / tier2)
to keep analytics breakdowns tier-aware.

Late-corroborator hook: when a fresh item arrives and is itself deduped
into an existing pending record (carrying corroboration to it), the
existing record must be re-evaluated against tier 3 inline — otherwise
the corroborated record stays pending forever.
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
    tdb = RadarDB(str(tmp_path / "test_intel_tier3.db"))
    yield tdb
    tdb.close()


def _seed_credibility(testdb, source_id: str, source_type: str, weight: float) -> None:
    """Force a credibility weight (the bootstrap path picks an archetype
    weight, but tests need deterministic numbers regardless of source_id)."""
    testdb.intel_source_upsert(source_id, source_type, credibility_weight=weight)


def _base_item(**overrides: Any) -> dict:
    item = {
        "source_type": "military",
        # `military_usni_news` → ecosystem=independent → eligible for auto_confirm.
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


# ── Tier 3: corroborated auto_confirm ────────────────────────────────────────


class TestTier3Corroborated:
    def test_tier3_with_corroboration_auto_confirms(self, testdb, monkeypatch):
        """confidence=0.72, credibility=0.78, with 1 corroborating source
        → auto_confirmed under tier 3."""
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "military_usni_news", "military", 0.78)

        q = IntelQueue()
        item = _base_item(
            confidence=0.72,
            llm_fields={"corroborating_sources": ["military_defense_news"]},
        )
        item_id = q.submit(item)
        assert item_id is not None
        got = testdb.intel_get(item_id)
        assert got["status"] == "auto_confirmed", \
            f"expected auto_confirmed under tier3, got {got['status']!r}"

    def test_tier3_below_confidence_floor_pending(self, testdb, monkeypatch):
        """confidence=0.65 (< 0.70) → still pending even with corroboration."""
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "military_usni_news", "military", 0.78)

        q = IntelQueue()
        item = _base_item(
            confidence=0.65,
            llm_fields={"corroborating_sources": ["military_defense_news"]},
        )
        item_id = q.submit(item)
        assert testdb.intel_get(item_id)["status"] == "pending"

    def test_tier3_below_credibility_floor_pending(self, testdb, monkeypatch):
        """credibility=0.70 (< 0.75) → pending even with corroboration."""
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "military_usni_news", "military", 0.70)

        q = IntelQueue()
        item = _base_item(
            confidence=0.75,
            llm_fields={"corroborating_sources": ["military_defense_news"]},
        )
        item_id = q.submit(item)
        assert testdb.intel_get(item_id)["status"] == "pending"

    def test_tier3_no_corroboration_pending(self, testdb, monkeypatch):
        """confidence=0.72, credibility=0.78, 0 corroborators → pending.
        Tier 3 must not relax the threshold without corroboration."""
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "military_usni_news", "military", 0.78)

        q = IntelQueue()
        item = _base_item(
            confidence=0.72,
            llm_fields={"corroborating_sources": []},
        )
        item_id = q.submit(item)
        assert testdb.intel_get(item_id)["status"] == "pending"

    def test_tier3_state_media_never_auto_confirms(self, testdb, monkeypatch):
        """State-media ecosystem stays fail-closed even with corroboration.
        ADR-025 guarantee: ecosystem gate runs BEFORE tier evaluation."""
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "military_tass_military", "military", 0.85)

        q = IntelQueue()
        item = _base_item(
            source_id="military_tass_military",
            confidence=0.90,
            llm_fields={"corroborating_sources": ["military_pla_daily"]},
        )
        item_id = q.submit(item)
        assert testdb.intel_get(item_id)["status"] == "pending"

    def test_tier3_verdict_tag_distinct(self, testdb, monkeypatch):
        """Analytics needs to count tier3 separately from tier1/tier2.
        The internal verdict tag should be auto_confirmed_corroborated
        so /api/intel/llm_call_stats can break it out."""
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "military_usni_news", "military", 0.78)

        q = IntelQueue()
        captured: list[str] = []
        orig = q._record_verdict

        def _capture(source_type, status, confidence, headline):
            captured.append(status)
            return orig(source_type, status, confidence, headline)

        monkeypatch.setattr(q, "_record_verdict", _capture)

        item = _base_item(
            confidence=0.72,
            llm_fields={"corroborating_sources": ["military_defense_news"]},
        )
        item_id = q.submit(item)
        assert item_id is not None
        # The verdict tag passed to _record_verdict must distinguish tier3.
        assert "auto_confirmed_corroborated" in captured, \
            f"expected auto_confirmed_corroborated tag, captured={captured}"

    def test_tier1_strict_unchanged(self, testdb, monkeypatch):
        """High-confidence + high-credibility still routes to tier1
        (auto_confirmed) — tier3 must not steal tier1 traffic."""
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "cert_cisa_advisories", "apt_intel", 0.85)

        q = IntelQueue()
        item = _base_item(
            source_type="apt_intel",
            source_id="cert_cisa_advisories",
            confidence=0.90,
            # corroborating_sources empty so this path is unambiguously tier1
            llm_fields={"corroborating_sources": []},
        )
        item_id = q.submit(item)
        assert testdb.intel_get(item_id)["status"] == "auto_confirmed"


# ── Late corroborator promotion ──────────────────────────────────────────────


class TestLateCorroboratorPromotion:
    """When a pending item gains a corroborator via dedup-replace, it must
    be re-evaluated for auto_confirm inline. Otherwise the corroborated
    record sits pending forever — defeating the whole point of tier 3."""

    def test_pending_promoted_when_dedup_adds_corroborator(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        _seed_credibility(testdb, "military_usni_news", "military", 0.78)
        _seed_credibility(testdb, "military_defense_news", "military", 0.78)

        q = IntelQueue()
        # Submit first item — pending (no corroborators yet).
        first = q.submit(_base_item(
            source_id="military_usni_news",
            confidence=0.72,
            llm_fields={"corroborating_sources": []},
        ))
        assert first is not None
        assert testdb.intel_get(first)["status"] == "pending"

        # Submit a similar headline from a different source — dedup should
        # add it as a corroborator and re-evaluate the existing pending row.
        second = q.submit(_base_item(
            source_id="military_defense_news",
            confidence=0.71,
            headline="PLA Navy reconnaissance surge near Taiwan strait",
            raw_url="https://other.example.com/article",
            llm_fields={"corroborating_sources": []},
        ))
        # Second item is deduped into first (returns None).
        assert second is None

        # Existing record should now be auto_confirmed because it gained a
        # corroborator AND its conf/cred satisfy tier3.
        promoted = testdb.intel_get(first)
        assert promoted["status"] == "auto_confirmed", \
            f"expected late-corroborator promotion, got {promoted['status']!r}"
        assert "military_defense_news" in promoted["llm_fields"]["corroborating_sources"]
