"""Tests for Phase 3.2 — ScenarioStore preset_originals + override
detection (problem 49, 2026-04-30 PM).

Pre-fix: when admin enabled south_china_sea (preset says enabled=False),
the API exposed no signal to UI distinguishing 'preset-aligned' from
'admin-override'. Analysts saw the scenario active without warning.

Phase 3.2 fix:
  * ScenarioStore retains _preset_originals (Layer-1 raw) at load time
  * is_enabled_overridden(sid) compares preset.enabled vs current.enabled
  * preset_enabled(sid) exposes the Layer-1 value
  * preset_metadata(sid) exposes the _preset_metadata dict
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

from radar.scenarios import ScenarioStore, Scenario, Participant, Role


def _scenario(sid, enabled, preset_metadata=None):
    return Scenario(
        id=sid,
        name_en=sid, name_ja=sid,
        description_en="", description_ja="",
        core_country="XX",
        state="active",
        enabled=enabled,
        tier=1,
        participants={"XX": Participant(country="XX", weight=1.0, role=Role.PRIMARY_TARGET)},
        preset_metadata=preset_metadata,
    )


def test_no_override_when_preset_and_db_agree():
    """preset.enabled=True AND merged.enabled=True → no override."""
    store = ScenarioStore()
    store._preset_originals = {"sc1": _scenario("sc1", enabled=True)}
    store._scenarios = {"sc1": _scenario("sc1", enabled=True)}
    assert store.is_enabled_overridden("sc1") is False


def test_override_when_admin_enables_preset_disabled():
    """preset.enabled=False BUT merged.enabled=True → override detected."""
    store = ScenarioStore()
    store._preset_originals = {"sc2": _scenario("sc2", enabled=False)}
    store._scenarios = {"sc2": _scenario("sc2", enabled=True)}
    assert store.is_enabled_overridden("sc2") is True


def test_override_when_admin_disables_preset_enabled():
    """preset.enabled=True BUT merged.enabled=False → override detected
    (the inverse direction — analyst silenced a default scenario)."""
    store = ScenarioStore()
    store._preset_originals = {"sc3": _scenario("sc3", enabled=True)}
    store._scenarios = {"sc3": _scenario("sc3", enabled=False)}
    assert store.is_enabled_overridden("sc3") is True


def test_no_override_for_db_only_scenario():
    """A scenario that exists only in DB (no preset) reports no override
    — there is no preset to override."""
    store = ScenarioStore()
    store._preset_originals = {}
    store._scenarios = {"sc4": _scenario("sc4", enabled=True)}
    assert store.is_enabled_overridden("sc4") is False


def test_no_override_for_unknown_scenario():
    """A scenario_id absent from both stores returns False."""
    store = ScenarioStore()
    store._preset_originals = {}
    store._scenarios = {}
    assert store.is_enabled_overridden("ghost") is False


def test_preset_enabled_returns_layer1_value():
    store = ScenarioStore()
    store._preset_originals = {"sc5": _scenario("sc5", enabled=False)}
    store._scenarios = {"sc5": _scenario("sc5", enabled=True)}
    assert store.preset_enabled("sc5") is False


def test_preset_metadata_returns_block():
    """preset_metadata accessor returns the dict from Layer 1 raw."""
    meta = {
        "disabled_reason": "test reason",
        "added_at": "2026-04-30",
        "policy_owner": "ops",
    }
    store = ScenarioStore()
    store._preset_originals = {
        "sc6": _scenario("sc6", enabled=False, preset_metadata=meta),
    }
    store._scenarios = {"sc6": _scenario("sc6", enabled=True)}
    result = store.preset_metadata("sc6")
    assert result == meta


def test_preset_metadata_returns_none_for_unknown():
    store = ScenarioStore()
    assert store.preset_metadata("ghost") is None


def test_load_populates_preset_originals():
    """ScenarioStore.load() snapshots Layer-1 BEFORE Layer-2 merge,
    so preset_originals reflects geo_data.json baseline regardless of
    later DB overrides."""
    store = ScenarioStore()
    geo_data = {
        "SCENARIOS": {
            "test_load": {
                "name_en": "Test Load",
                "name_ja": "テスト",
                "core_country": "XX",
                "state": "active",
                "enabled": False,
                "tier": 1,
                "participants": {"XX": {"weight": 1.0, "role": "primary_target"}},
                "_preset_metadata": {"disabled_reason": "test"},
            },
        },
    }
    store.load(geo_data)
    # Preset originals should retain enabled=False even if Layer-2
    # override would change it (no Layer-2 row exists in this test).
    assert store.preset_enabled("test_load") is False
    assert store.preset_metadata("test_load") == {"disabled_reason": "test"}
