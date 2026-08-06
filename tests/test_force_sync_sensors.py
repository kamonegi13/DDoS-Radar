"""WP-0.2 F-02 regression — the force-sync allow-list names real sensors.

`_FORCE_SYNC_SENSORS` listed `"cf"` and `"ioda"`, but the registry knows
those sensors as `"cloudflare_radar"` and `"ioda_bgp"`. The force path
filters the registry by name, so two of the six never refreshed — and the
mismatch was silent: an unknown name simply matches nothing, which looks
exactly like a sensor that had nothing to do.

That is the S5-VERIF-015 failure mode (identifier sets matched without
existence checking). The subset assertion below is the general guard: any
future edit to the list that invents a name fails here rather than in
production silence.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

import radar.config  # noqa: F401  — registry population
from radar import registry
from radar.routes.core import _FORCE_SYNC_SENSORS


@pytest.fixture(scope="module")
def registered_names():
    return {sensor.name for sensor in registry.all()}


class TestForceSyncAllowList:
    def test_every_listed_sensor_exists(self, registered_names):
        unknown = _FORCE_SYNC_SENSORS - registered_names
        assert unknown == set(), \
            f"force-sync names no registered sensor: {sorted(unknown)}"

    def test_the_two_renamed_sensors_are_reachable(self, registered_names):
        # The exact pair F-02 lost. Named explicitly so a regression says
        # which sensors went dark, not just "the subset check failed".
        assert "cloudflare_radar" in _FORCE_SYNC_SENSORS
        assert "ioda_bgp" in _FORCE_SYNC_SENSORS
        assert {"cloudflare_radar", "ioda_bgp"} <= registered_names

    def test_the_stale_short_names_are_gone(self):
        assert "cf" not in _FORCE_SYNC_SENSORS
        assert "ioda" not in _FORCE_SYNC_SENSORS

    def test_the_list_still_covers_six_sensors(self):
        # The set was sized deliberately (fast global sensors only, so the
        # request greenlet does not fan out to slow ones). A rename must
        # not silently drop a member.
        assert len(_FORCE_SYNC_SENSORS) == 6

    def test_listed_sensors_resolve_through_the_registry(self):
        # registry.get() is what the force path actually calls.
        for name in _FORCE_SYNC_SENSORS:
            assert registry.get(name) is not None, name
