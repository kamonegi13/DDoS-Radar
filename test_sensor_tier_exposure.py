"""Tests for Phase 3 / Item 3.2: Sensor tier exposure in admin endpoint.

The Sensor Quota Dashboard needs `tier` (FOCUSED_ONLY / GLOBAL /
BACKGROUND_ELIGIBLE) on every sensor row to support the upcoming
filter buttons and to inform BACKGROUND_ELIGIBLE promotion decisions
for the C-medium migration. SensorTier already lives on every
BaseSensor subclass — surface it through to_config_dict() so the
admin sensor_health endpoint emits it without an extra registry
walk.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.scenarios import SensorTier
from radar.sensors.base import BaseSensor


class _StubSensor(BaseSensor):
    tier = SensorTier.FOCUSED_ONLY

    def fetch(self, context: dict) -> dict:
        return {}


class _GlobalStub(BaseSensor):
    tier = SensorTier.GLOBAL

    def fetch(self, context: dict) -> dict:
        return {}


def test_to_config_dict_emits_tier():
    sensor = _StubSensor("stub_sensor", "cyber", 60)
    cfg = sensor.to_config_dict()
    assert cfg.get("tier") == "focused_only", \
        f"expected tier=focused_only, got {cfg.get('tier')!r}"


def test_to_config_dict_emits_global_tier():
    sensor = _GlobalStub("stub_global", "physical", 60)
    cfg = sensor.to_config_dict()
    assert cfg.get("tier") == "global", \
        f"expected tier=global, got {cfg.get('tier')!r}"


def test_tier_values_match_enum():
    """The string values in to_config_dict must match the SensorTier
    enum values exactly so the frontend can switch on them without
    a translation layer."""
    assert SensorTier.GLOBAL.value == "global"
    assert SensorTier.FOCUSED_ONLY.value == "focused_only"
    assert SensorTier.BACKGROUND_ELIGIBLE.value == "background_eligible"
