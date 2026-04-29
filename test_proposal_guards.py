"""Tests for radar.calibration._proposal_guards (post-incident redesign).

Covers the 5 design principles (P1-P5) with focused unit tests +
end-to-end evaluate_for_country flow.
"""
from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.calibration import _proposal_guards as guards
from radar.scenarios import Participant, Role, Scenario


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "guards.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.calibration._proposal_guards.db", tdb)
    yield tdb
    tdb.close()


def _make_scenario(scenario_id: str, *, participants: dict) -> Scenario:
    return Scenario(
        id=scenario_id,
        name_en=scenario_id, name_ja=scenario_id,
        description_en="", description_ja="",
        core_country=None, state="active", enabled=True, tier=1,
        participants={
            cc: Participant(country=cc, weight=p["weight"], role=p["role"])
            for cc, p in participants.items()
        },
    )


def _seed_intel(db, country: str, n: int = 1, source_type: str = "apt_intel"):
    """Seed n llm_intel rows for a country (theater = country code)."""
    conn = db._get_conn()
    with conn.writing():
        for i in range(n):
            conn.execute(
                "INSERT INTO llm_intel "
                "(id, source_type, source_id, theater, ts, status, "
                " confidence, raw_text, raw_url, headline, llm_fields, "
                " score_delta, domain, confirmed_by, confirmed_at, "
                " override_at, created_at, countries, country_weights) "
                "VALUES (?, ?, ?, ?, ?, 'confirmed', 0.8, '', '', '', "
                "        '{}', 0, 'cyber', NULL, NULL, NULL, ?, '[]', '{}')",
                (f"li-{country}-{i}-{time.time_ns()}", source_type,
                 f"src-{country}-{i}", country, time.time() - 3600,
                 time.time()),
            )


def _seed_analyst_fn(db, n: int = 1):
    """Seed n FALSE_NEGATIVE analyst_feedback rows."""
    conn = db._get_conn()
    with conn.writing():
        for i in range(n):
            cid = f"c-fn-{i}-{time.time_ns()}"
            conn.execute(
                "INSERT INTO conclusions "
                "(id, scenario_id, conclusion_type, state, confidence, "
                " observed_at, formula_ref, threshold_ref, source_urls, "
                " llm_prompt_sha256, calibration_status, "
                " conclusion_unavailable_reason, metadata) "
                "VALUES (?, 'taiwan_contingency', 'threat_level', '3', "
                "        0.5, ?, 't', '{}', '[]', NULL, '{}', NULL, '{}')",
                (cid, time.time() - 3600),
            )
            conn.execute(
                "INSERT INTO analyst_feedback "
                "(conclusion_id, label, observed_outcome_url, analyst_id, "
                " observed_at, notes) "
                "VALUES (?, 'FALSE_NEGATIVE', NULL, 'auto', ?, NULL)",
                (cid, time.time() - 3600),
            )


# ── P1: Role-Tier Protection ────────────────────────────────────────────────


class TestRoleProtection:
    def test_primary_target_is_protected(self, fresh_db):
        s = _make_scenario("s", participants={
            "TW": {"weight": 1.0, "role": Role.PRIMARY_TARGET},
        })
        assert guards.is_role_protected(s.participants["TW"]) is True

    def test_principal_belligerent_is_protected(self, fresh_db):
        s = _make_scenario("s", participants={
            "RU": {"weight": 0.9, "role": Role.PRINCIPAL_BELLIGERENT},
        })
        assert guards.is_role_protected(s.participants["RU"]) is True

    def test_adversary_is_protected(self, fresh_db):
        s = _make_scenario("s", participants={
            "CN": {"weight": 0.8, "role": Role.ADVERSARY},
        })
        assert guards.is_role_protected(s.participants["CN"]) is True

    def test_strategic_observer_is_NOT_protected(self, fresh_db):
        s = _make_scenario("s", participants={
            "NZ": {"weight": 0.2, "role": Role.STRATEGIC_OBSERVER},
        })
        assert guards.is_role_protected(s.participants["NZ"]) is False

    def test_primary_ally_requires_confirm(self, fresh_db):
        s = _make_scenario("s", participants={
            "JP": {"weight": 0.7, "role": Role.PRIMARY_ALLY},
        })
        assert guards.role_requires_confirm(s.participants["JP"]) is True
        assert guards.is_role_protected(s.participants["JP"]) is False

    def test_none_participant_not_protected(self):
        assert guards.is_role_protected(None) is False


# ── P2: Multi-Source Signals ────────────────────────────────────────────────


class TestCollectMultiSourceSignals:
    def test_empty_returns_zeros(self, fresh_db):
        signals = guards.collect_multi_source_signals("CN", days=30)
        assert signals == {name: 0 for name in guards.SOURCE_NAMES}

    def test_empty_country_returns_zeros(self, fresh_db):
        signals = guards.collect_multi_source_signals("", days=30)
        assert all(v == 0 for v in signals.values())

    def test_llm_intel_counted(self, fresh_db):
        _seed_intel(fresh_db, "CN", n=3)
        signals = guards.collect_multi_source_signals("CN", days=30)
        assert signals["llm_intel"] == 3
        assert signals["sequence_events"] == 0

    def test_other_country_not_counted(self, fresh_db):
        _seed_intel(fresh_db, "JP", n=2)
        signals = guards.collect_multi_source_signals("CN", days=30)
        assert signals["llm_intel"] == 0

    def test_analyst_fn_counted(self, fresh_db):
        _seed_analyst_fn(fresh_db, n=2)
        signals = guards.collect_multi_source_signals("ANY", days=30)
        assert signals["analyst_feedback_fn"] == 2


class TestZeroSourceCount:
    def test_all_zero(self):
        sigs = {n: 0 for n in guards.SOURCE_NAMES}
        assert guards.zero_source_count(sigs) == len(guards.SOURCE_NAMES)

    def test_partial_zero(self):
        sigs = {"llm_intel": 5, "sequence_events": 0,
                "sensor_observation_ts": 0, "analyst_feedback_fn": 0,
                "conclusions_contribution": 2}
        assert guards.zero_source_count(sigs) == 3


class TestIsTrulyDormant:
    def test_all_zero_with_default_5_dormant(self):
        sigs = {n: 0 for n in guards.SOURCE_NAMES}
        assert guards.is_truly_dormant(sigs) is True

    def test_one_active_blocks_dormancy_at_default_threshold(self):
        # 4 zeros + 1 active → not 'strong' dormancy under tightened design
        sigs = {"llm_intel": 5, "sequence_events": 0,
                "sensor_observation_ts": 0, "analyst_feedback_fn": 0,
                "conclusions_contribution": 0}
        assert guards.is_truly_dormant(sigs) is False  # default min=5

    def test_relaxed_threshold_4_admits_one_active(self):
        # When caller explicitly relaxes to 4, single-active is OK
        sigs = {"llm_intel": 5, "sequence_events": 0,
                "sensor_observation_ts": 0, "analyst_feedback_fn": 0,
                "conclusions_contribution": 0}
        assert guards.is_truly_dormant(sigs, min_zero_sources=4) is True

    def test_with_fn_blocks_dormancy(self):
        sigs = {"llm_intel": 0, "sequence_events": 0,
                "sensor_observation_ts": 0, "analyst_feedback_fn": 1,
                "conclusions_contribution": 0}
        # FN > 0 → analyst flagged something missed
        assert guards.is_truly_dormant(sigs) is False

    def test_few_zeros_not_dormant(self):
        sigs = {"llm_intel": 5, "sequence_events": 5,
                "sensor_observation_ts": 5, "analyst_feedback_fn": 0,
                "conclusions_contribution": 0}
        assert guards.is_truly_dormant(sigs) is False


# ── P3: Scenario Vitality ───────────────────────────────────────────────────


class TestScenarioVitality:
    def test_empty_scenario_returns_dormant(self, fresh_db):
        s = _make_scenario("empty", participants={})
        v = guards.scenario_vitality(s)
        assert v.state == "dormant"
        assert v.total_signals == 0

    def test_no_data_returns_data_gap(self, fresh_db):
        # 5 participants but llm_intel is empty → data_gap
        s = _make_scenario("test", participants={
            cc: {"weight": 0.5, "role": Role.SECONDARY_ALLY}
            for cc in ("CN", "JP", "TW", "US", "PH")
        })
        v = guards.scenario_vitality(s)
        assert v.state == "data_gap"
        assert v.sensor_coverage_ratio == 0.0

    def test_high_activity_returns_active(self, fresh_db):
        s = _make_scenario("test", participants={
            cc: {"weight": 0.5, "role": Role.SECONDARY_ALLY}
            for cc in ("CN", "JP", "TW")
        })
        for c in ("CN", "JP", "TW"):
            _seed_intel(fresh_db, c, n=10)
        v = guards.scenario_vitality(s)
        assert v.state == "active"
        assert v.active_participant_count == 3
        assert v.sensor_coverage_ratio == pytest.approx(1.0)

    def test_partial_coverage_data_gap(self, fresh_db):
        # 5 participants, only 1 with signals → coverage 20%, < 30% default
        s = _make_scenario("test", participants={
            cc: {"weight": 0.5, "role": Role.SECONDARY_ALLY}
            for cc in ("CN", "JP", "TW", "US", "PH")
        })
        _seed_intel(fresh_db, "CN", n=20)  # only one country active
        v = guards.scenario_vitality(s)
        assert v.state == "data_gap"
        assert v.active_participant_count == 1


# ── P5: Evidence Strength ───────────────────────────────────────────────────


class TestEvidenceStrength:
    def test_protected_role_always_insufficient(self):
        sigs = {n: 0 for n in guards.SOURCE_NAMES}
        s = guards.evidence_strength(sigs, role_protected=True)
        assert s == "insufficient"

    def test_with_fn_insufficient(self):
        sigs = {"llm_intel": 0, "sequence_events": 0,
                "sensor_observation_ts": 0, "analyst_feedback_fn": 1,
                "conclusions_contribution": 0}
        assert guards.evidence_strength(sigs, role_protected=False) == "insufficient"

    def test_5_zeros_strong(self):
        sigs = {n: 0 for n in guards.SOURCE_NAMES}
        assert guards.evidence_strength(sigs, role_protected=False) == "strong"

    def test_4_zeros_no_longer_strong(self):
        # Tightened post-incident: 4 zeros = moderate, not strong
        sigs = {"llm_intel": 5, "sequence_events": 0,
                "sensor_observation_ts": 0, "analyst_feedback_fn": 0,
                "conclusions_contribution": 0}
        # 4 zeros → moderate (NOT strong; need 5 zeros for strong)
        assert guards.evidence_strength(sigs, role_protected=False) == "moderate"

    def test_3_zeros_moderate(self):
        sigs = {"llm_intel": 5, "sequence_events": 5,
                "sensor_observation_ts": 0, "analyst_feedback_fn": 0,
                "conclusions_contribution": 0}
        assert guards.evidence_strength(sigs, role_protected=False) == "moderate"

    def test_1_zero_weak(self):
        sigs = {"llm_intel": 5, "sequence_events": 5,
                "sensor_observation_ts": 5, "analyst_feedback_fn": 0,
                "conclusions_contribution": 5}
        assert guards.evidence_strength(sigs, role_protected=False) == "weak"

    def test_all_active_insufficient(self):
        sigs = {"llm_intel": 5, "sequence_events": 5,
                "sensor_observation_ts": 5, "analyst_feedback_fn": 0,
                "conclusions_contribution": 5}
        # all 5 sources non-zero except FN — 1 zero (FN), other 4 active
        # zero_count = 1 → weak (still emits hint-level)
        # but if all 5 are non-zero, no zeros → insufficient
        sigs2 = {"llm_intel": 5, "sequence_events": 5,
                 "sensor_observation_ts": 5, "analyst_feedback_fn": 1,
                 "conclusions_contribution": 5}
        assert guards.evidence_strength(sigs2, role_protected=False) == "insufficient"


# ── End-to-End: evaluate_for_country ────────────────────────────────────────


class TestEvaluateForCountry:
    def test_protected_role_blocks_recall_negative(self, fresh_db):
        # Active scenario, but TW is primary_target → block
        s = _make_scenario("taiwan_contingency", participants={
            "TW": {"weight": 1.0, "role": Role.PRIMARY_TARGET},
            "JP": {"weight": 0.5, "role": Role.PRIMARY_ALLY},
            "US": {"weight": 0.7, "role": Role.PRIMARY_ALLY},
            "CN": {"weight": 1.0, "role": Role.ADVERSARY},
        })
        for c in ("CN", "JP", "US"):
            _seed_intel(fresh_db, c, n=20)
        # TW has zero signals
        decision = guards.evaluate_for_country(s, "TW")
        assert decision.can_emit_recall_negative is False
        # role_protected reason recorded
        assert any("role_protected" in r for r in decision.blocking_reasons)

    def test_data_gap_blocks_all_structural(self, fresh_db):
        # Scenario in data_gap state → no per-participant proposals
        s = _make_scenario("test", participants={
            cc: {"weight": 0.5, "role": Role.SECONDARY_ALLY}
            for cc in ("CN", "JP", "TW", "US", "PH")
        })
        decision = guards.evaluate_for_country(s, "CN")
        assert decision.vitality.state == "data_gap"
        assert decision.can_emit_recall_negative is False
        assert decision.can_emit_structure_change is False
        # diagnostic IS allowed even in data_gap (informational)
        assert decision.can_emit_diagnostic is True

    def test_active_scenario_dormant_country_allows_recall_negative(
        self, fresh_db,
    ):
        s2 = _make_scenario("test2", participants={
            "CN": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
            "JP": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
            "TW": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
            "US": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
            "ZZ": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
        })
        for c in ("CN", "JP", "TW", "US"):
            _seed_intel(fresh_db, c, n=20)
        # ZZ has no signals at all → all 5 sources zero → strong
        decision = guards.evaluate_for_country(s2, "ZZ")
        assert decision.vitality.state == "active"
        assert decision.strength == "strong"
        assert decision.can_emit_recall_negative is True
        assert decision.blocking_reasons == ()


# ── Regression: the original incident shape ────────────────────────────────


class TestOriginalIncident:
    """The 2026-04-29 incident: 25 weight_too_high proposals against
    primary_target / primary_ally / adversary participants in scenarios
    where llm_intel was sparse. Prove the new guards reject these."""

    def test_taiwan_TW_is_protected_under_data_gap(self, fresh_db):
        # Re-create the production state: empty llm_intel, all
        # participants at zero, TW is primary_target.
        s = _make_scenario("taiwan_contingency", participants={
            "TW": {"weight": 1.0, "role": Role.PRIMARY_TARGET},
            "US": {"weight": 0.7, "role": Role.PRIMARY_ALLY},
            "JP": {"weight": 0.5, "role": Role.PRIMARY_ALLY},
            "GU": {"weight": 0.4, "role": Role.FORWARD_BASE},
            "PH": {"weight": 0.3, "role": Role.SECONDARY_ALLY},
            "CN": {"weight": 1.0, "role": Role.ADVERSARY},
        })
        # No data seeded → data_gap state
        decision = guards.evaluate_for_country(s, "TW")
        # TW is BOTH protected AND in data_gap scenario
        assert decision.can_emit_recall_negative is False
        # CN (adversary, also protected) likewise
        d2 = guards.evaluate_for_country(s, "CN")
        assert d2.can_emit_recall_negative is False
        # US (primary_ally, requires confirm but not protected)
        d3 = guards.evaluate_for_country(s, "US")
        assert d3.can_emit_recall_negative is False  # blocked by data_gap

    def test_eastern_europe_UA_protected_when_data_sparse(self, fresh_db):
        s = _make_scenario("eastern_europe", participants={
            "UA": {"weight": 1.0, "role": Role.PRIMARY_TARGET},
            "PL": {"weight": 0.6, "role": Role.PRIMARY_ALLY},
            "RU": {"weight": 1.0, "role": Role.PRINCIPAL_BELLIGERENT},
        })
        decision = guards.evaluate_for_country(s, "UA")
        assert decision.can_emit_recall_negative is False
        d2 = guards.evaluate_for_country(s, "RU")
        assert d2.can_emit_recall_negative is False
