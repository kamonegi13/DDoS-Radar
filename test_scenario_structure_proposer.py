"""Tests for radar.calibration.scenario_structure_proposer (Tier 2, commit 6)."""
from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.calibration import scenario_structure_proposer as ssp
from radar.scenarios import Participant, Role, Scenario


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "structure.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.calibration.scenario_improver.db", tdb)
    monkeypatch.setattr("radar.calibration.scenario_structure_proposer.db",
                        tdb)
    yield tdb
    tdb.close()


def _make_scenario(scenario_id: str, *, participants: dict) -> Scenario:
    """Build a minimal Scenario object that matches the dataclass shape."""
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


def _seed_intel(db, theater: str, country: str, source_type: str, n: int):
    """Seed n llm_intel rows. NOTE: country is a GENERATED column
    (mirrors theater per migration v24); to test per-country signal mix
    we set theater=country to drive the generated value."""
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
                "        '{}', 0, 'cyber', NULL, NULL, NULL, ?, '[]', "
                "        '{}')",
                (f"li-{theater}-{country}-{source_type}-{i}", source_type,
                 f"src-{i}", country, time.time() - 3600,
                 time.time()),
            )


# ── _read_signal_mix ─────────────────────────────────────────────────────────


class TestReadSignalMix:
    def test_returns_empty_for_empty_table(self, fresh_db):
        scenario = _make_scenario("taiwan_contingency", participants={
            "CN": {"weight": 0.7, "role": Role.ADVERSARY},
        })
        assert ssp._read_signal_mix(scenario) == {}

    def test_returns_empty_when_no_participants(self, fresh_db):
        scenario = _make_scenario("empty_scen", participants={})
        assert ssp._read_signal_mix(scenario) == {}

    def test_aggregates_by_participant_and_source_type(self, fresh_db):
        # llm_intel.theater holds country code (post A-3 rename).
        # Seed CN and JP rows; scenario participants are CN + JP.
        _seed_intel(fresh_db, "taiwan_contingency", "CN", "apt_intel", 10)
        _seed_intel(fresh_db, "taiwan_contingency", "CN", "diplomatic", 3)
        _seed_intel(fresh_db, "taiwan_contingency", "JP", "diplomatic", 5)
        scenario = _make_scenario("taiwan_contingency", participants={
            "CN": {"weight": 0.7, "role": Role.ADVERSARY},
            "JP": {"weight": 0.5, "role": Role.PRIMARY_ALLY},
        })
        result = ssp._read_signal_mix(scenario)
        assert result["CN"]["apt_intel"] == 10
        assert result["CN"]["diplomatic"] == 3
        assert result["JP"]["diplomatic"] == 5

    def test_filters_to_scenario_participants(self, fresh_db):
        # Seed a country (KP) that is NOT a participant; should be excluded.
        _seed_intel(fresh_db, "test_scen", "CN", "apt_intel", 5)
        _seed_intel(fresh_db, "test_scen", "KP", "apt_intel", 5)
        scenario = _make_scenario("test_scen", participants={
            "CN": {"weight": 0.7, "role": Role.ADVERSARY},
        })
        result = ssp._read_signal_mix(scenario)
        assert "CN" in result
        assert "KP" not in result


# ── _dominant_signal ─────────────────────────────────────────────────────────


class TestDominantSignal:
    def test_returns_none_for_empty(self):
        assert ssp._dominant_signal({}) is None

    def test_returns_none_below_min_count(self, monkeypatch):
        monkeypatch.setenv("STRUCTURE_PROPOSER_MIN_DOMINANT", "10")
        assert ssp._dominant_signal({"apt_intel": 3}) is None

    def test_returns_none_below_share_threshold(self, monkeypatch):
        monkeypatch.setenv("STRUCTURE_PROPOSER_MIN_SHARE", "0.80")
        result = ssp._dominant_signal({"apt_intel": 5, "diplomatic": 5})
        assert result is None  # 0.50 share < 0.80

    def test_returns_dominant_when_meets_floors(self):
        result = ssp._dominant_signal({"apt_intel": 8, "diplomatic": 2})
        assert result is not None
        top, count, share = result
        assert top == "apt_intel"
        assert count == 8
        assert share == pytest.approx(0.8)


# ── _rule_role_reclassify ────────────────────────────────────────────────────


class TestRoleReclassify:
    def test_no_intel_no_proposals(self, fresh_db):
        scenario = _make_scenario("test_scen", participants={
            "CN": {"weight": 0.7, "role": Role.ADVERSARY},
        })
        events = ssp._rule_role_reclassify(scenario)
        assert events == []

    def test_proposes_when_dominant_implies_different_role(self, fresh_db):
        # CN configured as PRIMARY_ALLY but signal is dominantly apt_intel
        # → infer ADVERSARY → propose reclassify
        _seed_intel(fresh_db, "test_scen", "CN", "apt_intel", 8)
        _seed_intel(fresh_db, "test_scen", "CN", "diplomatic", 1)
        scenario = _make_scenario("test_scen", participants={
            "CN": {"weight": 0.7, "role": Role.PRIMARY_ALLY},
        })
        events = ssp._rule_role_reclassify(scenario)
        assert len(events) == 1
        ev = events[0]
        assert ev.proposal_type == "role_reclassify"
        assert ev.target_country == "CN"
        assert ev.suggested_value["role_from"] == "primary_ally"
        assert ev.suggested_value["role_to"] == "adversary"
        assert ev.evidence["dominant_source_type"] == "apt_intel"

    def test_no_proposal_when_role_already_matches(self, fresh_db):
        _seed_intel(fresh_db, "test_scen", "CN", "apt_intel", 8)
        scenario = _make_scenario("test_scen", participants={
            "CN": {"weight": 0.7, "role": Role.ADVERSARY},
        })
        events = ssp._rule_role_reclassify(scenario)
        assert events == []

    def test_skips_unknown_source_type(self, fresh_db):
        _seed_intel(fresh_db, "test_scen", "CN", "unknown_type", 10)
        scenario = _make_scenario("test_scen", participants={
            "CN": {"weight": 0.7, "role": Role.ADVERSARY},
        })
        events = ssp._rule_role_reclassify(scenario)
        assert events == []


# ── _rule_dormant_participant ────────────────────────────────────────────────


class TestDormantParticipant:
    def test_proposes_for_high_weight_no_signals(self, fresh_db):
        scenario = _make_scenario("test_dormant", participants={
            "JP": {"weight": 0.7, "role": Role.PRIMARY_ALLY},
        })
        events = ssp._rule_dormant_participant(scenario)
        assert len(events) == 1
        ev = events[0]
        assert ev.proposal_type == "dormant_participant"
        assert ev.target_country == "JP"
        assert ev.suggested_value["weight_from"] == 0.7
        assert ev.suggested_value["weight_to"] < 0.7

    def test_skips_low_weight_participants(self, fresh_db, monkeypatch):
        monkeypatch.setenv("STRUCTURE_PROPOSER_DORMANT_WEIGHT", "0.50")
        scenario = _make_scenario("test_dormant", participants={
            "PH": {"weight": 0.20, "role": Role.STRATEGIC_OBSERVER},
        })
        events = ssp._rule_dormant_participant(scenario)
        assert events == []

    def test_skips_when_signals_present(self, fresh_db):
        _seed_intel(fresh_db, "test_dormant", "JP", "diplomatic", 2)
        scenario = _make_scenario("test_dormant", participants={
            "JP": {"weight": 0.7, "role": Role.PRIMARY_ALLY},
        })
        events = ssp._rule_dormant_participant(scenario)
        assert events == []


# ── run_once integration ─────────────────────────────────────────────────────


class TestRunOnce:
    def test_runs_against_real_scenarios(self, fresh_db):
        # Production scenarios are loaded into scenario_store at module
        # import. With empty llm_intel, both rules should be no-ops or
        # produce only dormant_participant proposals (some real
        # participants will have weight ≥ 0.30 and zero signals).
        result = ssp.run_once()
        assert isinstance(result, dict)
        for sid, per_rule in result.items():
            assert "role_reclassify" in per_rule
            assert "dormant_participant" in per_rule

    def test_handles_scenario_store_failure(self, monkeypatch):
        # If scenario_store enumeration fails, run_once should return {}
        # rather than raise (NP3).
        import radar.scenarios as _scen
        broken = type("X", (), {})()
        broken._scenarios = {}  # empty dict; safe iteration
        monkeypatch.setattr(_scen, "scenario_store", broken)
        result = ssp.run_once()
        assert result == {}


# ── run_now integration ─────────────────────────────────────────────────────


class TestRunNowIntegration:
    def test_structure_phase_in_dispatcher(self):
        from radar.calibration import run_now
        assert "structure" in run_now._PHASE_ORDER
        fn = run_now._phase_func("structure")
        assert callable(fn)
