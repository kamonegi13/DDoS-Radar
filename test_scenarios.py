"""Tests for radar.scenarios (Phase 1) and radar.scoring.Signal."""
import pytest
import time

from radar.scenarios import (
    Role, SensorTier, Participant, Scenario,
    ScenarioValidationError,
    validate_scenario_id, validate_participant, validate_state,
    _parse_scenario_json, load_layer1,
    RESERVED_IDS, _SCENARIO_ID_RE,
)
from radar.scoring import Signal


# ── Role enum ───────────────────────────────────────────────────────────────

class TestRole:
    def test_all_13_roles(self):
        assert len(Role) == 13

    def test_role_values_are_lowercase_snake(self):
        for r in Role:
            assert r.value == r.value.lower()
            assert " " not in r.value

    def test_role_round_trip(self):
        for r in Role:
            assert Role(r.value) is r

    def test_invalid_role_raises(self):
        with pytest.raises(ValueError):
            Role("nonexistent_role")


# ── SensorTier enum ─────────────────────────────────────────────────────────

class TestSensorTier:
    def test_three_values(self):
        assert len(SensorTier) == 3
        assert SensorTier.GLOBAL.value == "global"
        assert SensorTier.FOCUSED_ONLY.value == "focused_only"
        assert SensorTier.BACKGROUND_ELIGIBLE.value == "background_eligible"


# ── scenario_id validation ──────────────────────────────────────────────────

class TestScenarioIdValidation:
    def test_valid_ids(self):
        for sid in ["taiwan_contingency", "abc", "a_1", "x" * 30]:
            validate_scenario_id(sid)

    def test_too_short(self):
        with pytest.raises(ScenarioValidationError):
            validate_scenario_id("ab")

    def test_too_long(self):
        with pytest.raises(ScenarioValidationError):
            validate_scenario_id("a" * 31)

    def test_starts_with_number(self):
        with pytest.raises(ScenarioValidationError):
            validate_scenario_id("1abc")

    def test_uppercase_rejected(self):
        with pytest.raises(ScenarioValidationError):
            validate_scenario_id("Taiwan")

    def test_hyphen_rejected(self):
        with pytest.raises(ScenarioValidationError):
            validate_scenario_id("east-europe")

    def test_reserved_words(self):
        for word in RESERVED_IDS:
            if len(word) >= 3:
                with pytest.raises(ScenarioValidationError, match="reserved"):
                    validate_scenario_id(word)

    def test_test_prefix_warns(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="radar"):
            validate_scenario_id("test_scenario")
        assert "test_ prefix" in caplog.text


# ── Participant validation ──────────────────────────────────────────────────

class TestParticipantValidation:
    def test_valid(self):
        p = validate_participant("TW", {"weight": 1.0, "role": "primary_target"}, "test_scen")
        assert p.country == "TW"
        assert p.weight == 1.0
        assert p.role == Role.PRIMARY_TARGET

    def test_invalid_role(self):
        with pytest.raises(ScenarioValidationError, match="unknown role"):
            validate_participant("TW", {"weight": 1.0, "role": "boss"}, "test_scen")

    def test_weight_below_zero(self):
        with pytest.raises(ScenarioValidationError, match="weight"):
            validate_participant("TW", {"weight": -0.1, "role": "adversary"}, "test_scen")

    def test_weight_above_one(self):
        with pytest.raises(ScenarioValidationError, match="weight"):
            validate_participant("TW", {"weight": 1.1, "role": "adversary"}, "test_scen")

    def test_weight_zero_valid(self):
        p = validate_participant("TW", {"weight": 0.0, "role": "adversary"}, "test_scen")
        assert p.weight == 0.0

    def test_weight_one_valid(self):
        p = validate_participant("TW", {"weight": 1.0, "role": "adversary"}, "test_scen")
        assert p.weight == 1.0


# ── State validation ────────────────────────────────────────────────────────

class TestStateValidation:
    def test_valid_states(self):
        for s in ("active", "paused", "archived"):
            assert validate_state(s, "sid") == s

    def test_invalid_state(self):
        with pytest.raises(ScenarioValidationError, match="invalid state"):
            validate_state("deleted", "sid")


# ── Scenario parsing ───────────────────────────────────────────────────────

class TestScenarioParsing:
    def _taiwan_raw(self):
        return {
            "name_en": "Taiwan Contingency",
            "name_ja": "台湾有事",
            "description_en": "PRC contingency",
            "description_ja": "台湾有事対応",
            "core_country": "TW",
            "state": "active",
            "enabled": True,
            "tier": 1,
            "participants": {
                "TW": {"weight": 1.0, "role": "primary_target"},
                "US": {"weight": 0.8, "role": "primary_ally"},
                "CN": {"weight": 0.7, "role": "adversary"},
            },
        }

    def test_parse_valid(self):
        s = _parse_scenario_json("taiwan_contingency", self._taiwan_raw())
        assert s.id == "taiwan_contingency"
        assert s.name_en == "Taiwan Contingency"
        assert s.core_country == "TW"
        assert len(s.participants) == 3
        assert s.participants["TW"].role == Role.PRIMARY_TARGET
        assert s.is_scorable is True

    def test_core_country_null(self):
        raw = {
            "name_en": "Middle East",
            "name_ja": "中東紛争",
            "core_country": None,
            "participants": {
                "IL": {"weight": 1.0, "role": "principal_belligerent"},
                "IR": {"weight": 1.0, "role": "principal_belligerent"},
            },
        }
        s = _parse_scenario_json("middle_east", raw)
        assert s.core_country is None
        assert len(s.participants) == 2

    def test_no_participants_raises(self):
        raw = {"name_en": "Empty", "name_ja": "空", "participants": {}}
        with pytest.raises(ScenarioValidationError, match="no participants"):
            _parse_scenario_json("empty_scen", raw)

    def test_disabled_not_scorable(self):
        raw = self._taiwan_raw()
        raw["enabled"] = False
        s = _parse_scenario_json("taiwan_contingency", raw)
        assert s.is_scorable is False

    def test_paused_not_scorable(self):
        raw = self._taiwan_raw()
        raw["state"] = "paused"
        s = _parse_scenario_json("taiwan_contingency", raw)
        assert s.is_scorable is False

    def test_to_dict_round_trip(self):
        s = _parse_scenario_json("taiwan_contingency", self._taiwan_raw())
        d = s.to_dict()
        assert d["id"] == "taiwan_contingency"
        assert d["participants"]["TW"]["role"] == "primary_target"
        assert d["participants"]["CN"]["weight"] == 0.7

    def test_default_state(self):
        raw = self._taiwan_raw()
        del raw["state"]
        s = _parse_scenario_json("taiwan_contingency", raw)
        assert s.state == "active"


# ── Layer 1 loader ──────────────────────────────────────────────────────────

class TestLayer1Loader:
    def test_load_from_geo_data(self):
        geo = {
            "SCENARIOS": {
                "taiwan_contingency": {
                    "name_en": "Taiwan Contingency",
                    "name_ja": "台湾有事",
                    "core_country": "TW",
                    "participants": {
                        "TW": {"weight": 1.0, "role": "primary_target"},
                        "CN": {"weight": 0.7, "role": "adversary"},
                    },
                },
                "middle_east": {
                    "name_en": "Middle East",
                    "name_ja": "中東紛争",
                    "core_country": None,
                    "participants": {
                        "IL": {"weight": 1.0, "role": "principal_belligerent"},
                        "IR": {"weight": 1.0, "role": "principal_belligerent"},
                    },
                },
            }
        }
        result = load_layer1(geo)
        assert len(result) == 2
        assert "taiwan_contingency" in result
        assert "middle_east" in result

    def test_empty_scenarios_returns_empty(self):
        result = load_layer1({})
        assert result == {}

    def test_invalid_scenario_raises_runtime(self):
        geo = {
            "SCENARIOS": {
                "1bad_id": {
                    "name_en": "Bad",
                    "name_ja": "悪い",
                    "participants": {"TW": {"weight": 1.0, "role": "primary_target"}},
                },
            }
        }
        with pytest.raises(RuntimeError, match="Failed to load preset"):
            load_layer1(geo)

    def test_load_real_geo_data(self):
        import json
        with open("geo_data.json", "r", encoding="utf-8") as f:
            geo = json.load(f)
        result = load_layer1(geo)
        assert len(result) == 5
        assert result["taiwan_contingency"].core_country == "TW"
        assert result["middle_east"].core_country is None
        assert result["south_china_sea"].enabled is False
        assert result["korean_peninsula"].tier == 2

        scorable = [s for s in result.values() if s.is_scorable]
        assert len(scorable) == 4


# ── Scenario.is_scorable ───────────────────────────────────────────────────

class TestIsScorable:
    def _make(self, state="active", enabled=True):
        return Scenario(
            id="test_sid", name_en="T", name_ja="T",
            description_en="", description_ja="",
            core_country=None, state=state, enabled=enabled,
            tier=1, participants={},
        )

    def test_active_enabled(self):
        assert self._make("active", True).is_scorable is True

    def test_active_disabled(self):
        assert self._make("active", False).is_scorable is False

    def test_paused_enabled(self):
        assert self._make("paused", True).is_scorable is False

    def test_archived_enabled(self):
        assert self._make("archived", True).is_scorable is False


# ── Signal dataclass ────────────────────────────────────────────────────────

class TestSignal:
    def test_per_country_signal(self):
        s = Signal(
            signal_source="bgp",
            sensor="ripe_bgp",
            observed_at=time.time(),
            domain="cyber",
            countries=["TW"],
            raw_score=3.0,
            value_display="BGP instability: 45%",
        )
        assert s.countries == ["TW"]
        assert s.country_weights == {}
        d = s.to_dict()
        assert d["signal_source"] == "bgp"
        assert "country_weights" not in d

    def test_global_signal_empty_countries(self):
        s = Signal(
            signal_source="greynoise",
            sensor="greynoise",
            observed_at=time.time(),
            domain="cyber",
            countries=[],
            raw_score=1.0,
            value_display="Global scan spike",
        )
        assert s.countries == []

    def test_llm_signal_with_weights(self):
        s = Signal(
            signal_source="apt_intel",
            sensor="apt_intel",
            observed_at=time.time(),
            domain="cyber",
            countries=["US", "TW"],
            country_weights={"US": 1.0, "TW": 0.6},
            raw_score=3.0,
            value_display="APT group targeting US infrastructure",
            evidence_url="https://example.com/report",
            llm_reasoning="APT group linked to PRC targeting US PLCs",
        )
        assert s.country_weights["TW"] == 0.6
        d = s.to_dict()
        assert d["country_weights"] == {"US": 1.0, "TW": 0.6}
        assert d["evidence_url"] == "https://example.com/report"
        assert d["llm_reasoning"] is not None

    def test_signal_defaults(self):
        s = Signal(
            signal_source="test",
            sensor="test_sensor",
            observed_at=0.0,
            domain="info",
            countries=[],
        )
        assert s.raw_score == 0.0
        assert s.value_display == ""
        assert s.evidence_url is None
        assert s.llm_reasoning is None
