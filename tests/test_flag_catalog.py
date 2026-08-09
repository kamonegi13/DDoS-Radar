"""WP-1.1 — declarative detection-flag catalog (S5-VERIF-001).

The catalog is the machine-readable enumeration the current system does
not have: today every detection flag is an ad-hoc key in a fetch() return
dict, which is exactly how F-08 (gps_jamming) stayed permanently
non-firing without anyone noticing.

Two properties matter more than any individual entry:

  * **totality** — every registered sensor is either catalogued or
    explicitly declared flagless. A sensor that is silently absent from
    both sets is unmonitored, which is the failure mode we are building
    this to prevent.
  * **purity** — evaluation must never raise on a malformed payload.
    It runs inside BaseSensor.set_cache(); an exception there would turn
    a monitoring feature into a sensor outage (NP3).
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.verification import flag_catalog
from radar.verification.flag_catalog import (
    CATALOG, NO_DETECTION_FLAGS, evaluate_flags,
)

# Flags whose values are read by the scoring layer (radar/routes/core.py).
# S5-VERIF-001: a detection flag MUST NOT reach scoring without a catalog
# entry, so this is the hard floor for coverage.
SCORING_CONSUMED = {
    ("gps_jamming", "is_jammed"),
    ("gps_jamming", "is_critical"),
    ("telegram_mirror", "is_burst"),
    ("telegram_mirror", "has_attack_intent"),
    ("telegram_mirror", "status"),
    ("rss_narrative", "is_burst"),
    ("rss_narrative", "status"),
    ("isr_hotspot", "is_surge"),
    ("ripe_bgp", "is_anomaly"),
    ("ais_maritime", "has_anomaly"),
    ("mil_support_air", "is_transport_surge"),
    ("mil_support_air", "is_awacs_active"),
}

# radar/__init__.py:95-107. Hardcoded so a sensor silently dropped from
# the registry shows up as a test failure rather than as a coverage gain.
REGISTERED_SENSORS = {
    "cloudflare_radar", "ioda_bgp", "opensky", "openweather", "gdelt",
    "peeringdb_ixp", "ripe_bgp", "nasa_firms", "threatfox", "rss_narrative",
    "isr_hotspot", "ais_maritime", "telegram_mirror", "check_host",
    "greynoise", "space_weather", "ihr_health", "ripe_atlas", "tor_metrics",
    "notam", "travel_advisory", "ooni_censorship", "usgs_seismic",
    "mil_support_air", "gps_jamming", "ct_log", "hacktivist_intel",
    "ground_osint", "diplomatic", "military_exercise", "apt_intel",
    "convergence_tracker", "hacktivist_news", "bg_observer_rss",
}


class TestCoverage:
    def test_every_scoring_consumed_flag_is_catalogued(self):
        catalogued = {(s.sensor, s.flag_id) for s in CATALOG}
        missing = SCORING_CONSUMED - catalogued
        assert not missing, f"flags consumed by scoring but not catalogued: {missing}"

    def test_registry_matches_the_hardcoded_expectation(self):
        from radar import registry
        assert {s.name for s in registry.all()} == REGISTERED_SENSORS

    def test_every_registered_sensor_is_classified(self):
        """Totality: catalogued OR explicitly flagless. No third state."""
        catalogued = {s.sensor for s in CATALOG}
        unclassified = REGISTERED_SENSORS - catalogued - set(NO_DETECTION_FLAGS)
        assert not unclassified, f"sensors with no classification: {unclassified}"

    def test_classification_is_exclusive(self):
        catalogued = {s.sensor for s in CATALOG}
        assert not (catalogued & set(NO_DETECTION_FLAGS)), \
            "a sensor cannot be both catalogued and declared flagless"

    def test_no_catalog_entry_for_an_unregistered_sensor(self):
        stray = {s.sensor for s in CATALOG} - REGISTERED_SENSORS
        assert not stray, f"catalog references unregistered sensors: {stray}"

    def test_flagless_declarations_are_registered(self):
        stray = set(NO_DETECTION_FLAGS) - REGISTERED_SENSORS
        assert not stray, f"flagless set references unregistered sensors: {stray}"


class TestSpecIntegrity:
    def test_flag_ids_are_unique_per_sensor(self):
        keys = [(s.sensor, s.flag_id) for s in CATALOG]
        assert len(keys) == len(set(keys))

    @pytest.mark.parametrize("spec", CATALOG, ids=lambda s: f"{s.sensor}.{s.flag_id}")
    def test_every_spec_is_well_formed(self, spec):
        assert spec.expected_fire_interval_days > 0
        assert spec.note.strip(), "each interval needs a stated rationale"
        assert spec.kind in ("bool", "enum")
        assert spec.path, "a spec needs a resolution path"
        assert spec.scope in ("global", "per_country", "per_event")
        # S5-VERIF-007: unit is mandatory and drawn from a closed vocabulary.
        assert spec.unit in flag_catalog.UNIT_VOCABULARY

    def test_intervals_are_not_uniform(self):
        """WP-1.1 condition 2: thresholds depend on sensor nature."""
        intervals = {s.expected_fire_interval_days for s in CATALOG}
        assert len(intervals) >= 4, f"intervals look uniform: {intervals}"

    @pytest.mark.parametrize("spec", CATALOG, ids=lambda s: f"{s.sensor}.{s.flag_id}")
    def test_scope_agrees_with_the_path(self, spec):
        """`scope` is declared for auditability; the resolver keys off the
        wildcard. They must not drift apart."""
        has_wildcard = flag_catalog.ANY in spec.path
        assert has_wildcard == (spec.scope != "global"), \
            f"{spec.sensor}.{spec.flag_id}: scope={spec.scope} path={spec.path}"

    @pytest.mark.parametrize(
        "spec", [s for s in CATALOG if s.kind == "enum"],
        ids=lambda s: f"{s.sensor}.{s.flag_id}")
    def test_enum_specs_declare_their_non_firing_values(self, spec):
        assert spec.non_firing_values, "an enum needs its clear/normal values"
        assert all(v is None or isinstance(v, str) for v in spec.non_firing_values)


class TestEvaluate:
    def test_bool_flag_fires_when_true(self):
        payload = {"has_anomaly": True}
        assert evaluate_flags("ais_maritime", payload)["has_anomaly"] is True

    def test_bool_flag_does_not_fire_when_false(self):
        payload = {"has_anomaly": False}
        assert evaluate_flags("ais_maritime", payload)["has_anomaly"] is False

    def test_enum_fires_on_a_non_default_value(self):
        payload = {"country_status": {"TW": "JAMMING_DETECTED"}}
        assert evaluate_flags("gps_jamming", payload)["country_status"] is True

    def test_enum_does_not_fire_on_the_clear_value(self):
        payload = {"country_status": {"TW": "NORMAL", "JP": "NORMAL"}}
        assert evaluate_flags("gps_jamming", payload)["country_status"] is False

    def test_no_data_is_not_a_detection(self):
        payload = {"country_status": {"TW": "NO_DATA"}}
        assert evaluate_flags("gps_jamming", payload)["country_status"] is False

    def test_warmup_is_not_a_detection(self):
        """ct_log emits WARMUP while its baseline is immature — that is an
        absence of measurement, not a detection (NP5+8)."""
        payload = {"country_status": {"TW": "WARMUP"}}
        assert evaluate_flags("ct_log", payload)["country_status"] is False

    def test_per_country_fires_when_any_country_fires(self):
        payload = {"jamming_data": {
            "JP": {"is_jammed": False},
            "TW": {"is_jammed": True},
        }}
        assert evaluate_flags("gps_jamming", payload)["is_jammed"] is True

    def test_per_country_does_not_fire_when_all_clear(self):
        payload = {"jamming_data": {
            "JP": {"is_jammed": False}, "TW": {"is_jammed": False}}}
        assert evaluate_flags("gps_jamming", payload)["is_jammed"] is False

    def test_per_event_list_fires_from_any_element(self):
        payload = {"bgp_hijacks": [
            {"is_ongoing": False}, {"is_ongoing": True}]}
        assert evaluate_flags("cloudflare_radar", payload)["is_ongoing"] is True

    def test_nested_wildcards_resolve(self):
        """notam's per-NOTAM flags sit in a list inside a per-country dict."""
        payload = {"notam_data": {"TW": {"recent": [{"is_military": True}]}}}
        assert evaluate_flags("notam", payload)["is_military"] is True

    def test_nested_global_path_resolves(self):
        payload = {"seismic": {"has_cable_threat": True}}
        assert evaluate_flags("usgs_seismic", payload)["has_cable_threat"] is True


class TestDefensiveEvaluation:
    @pytest.mark.parametrize("payload", [
        {}, None, [], "not a dict", 42,
        {"jamming_data": None},
        {"jamming_data": "wrong type"},
        {"jamming_data": {"TW": None}},
        {"jamming_data": {"TW": ["unexpected"]}},
        {"country_status": {"TW": {"nested": "wrong"}}},
        {"bgp_hijacks": {"not": "a list"}},
        {"notam_data": {"TW": {"recent": "not a list"}}},
    ])
    def test_malformed_payloads_never_raise_and_never_fire(self, payload):
        for sensor in ("gps_jamming", "cloudflare_radar", "notam"):
            result = evaluate_flags(sensor, payload)
            assert all(v is False for v in result.values()), \
                f"{sensor} fired on malformed payload {payload!r}: {result}"

    def test_unknown_sensor_returns_empty(self):
        assert evaluate_flags("no_such_sensor", {"anything": True}) == {}

    def test_flagless_sensor_returns_empty(self):
        assert evaluate_flags("opensky", {"airports": {}}) == {}

    def test_every_catalogued_sensor_survives_an_empty_payload(self):
        for sensor in {s.sensor for s in CATALOG}:
            res = evaluate_flags(sensor, {})
            assert res and all(v is False for v in res.values())


class TestThresholds:
    def test_silence_ratios_match_the_spec(self):
        # S5-VERIF-003. Deliberately module constants, not registry keys
        # (P6 O-18): a verification gate that can be relaxed at runtime is
        # not a gate.
        assert flag_catalog.SILENCE_WARN_RATIO == 1.0
        assert flag_catalog.SILENCE_ANOMALY_RATIO == 3.0
        assert flag_catalog.NEVER_FIRED_GRACE_DAYS == 30

    def test_thresholds_are_not_registry_keys(self):
        from radar import config_layered
        for key in ("SILENCE_WARN_RATIO", "SILENCE_ANOMALY_RATIO",
                    "NEVER_FIRED_GRACE_DAYS"):
            assert config_layered.get_meta(key) is None, \
                f"{key} must not be runtime-overridable (P6 O-18)"


class TestF08UnitMismatchIsRecorded:
    """The catalog is also the place where the F-08 unit defect becomes
    machine-readable — WP-1.2 / S5-VERIF-008 will consume this."""

    def _spec(self, flag_id):
        return next(s for s in CATALOG
                    if s.sensor == "gps_jamming" and s.flag_id == flag_id)

    def test_is_jammed_declares_a_ratio_unit_and_its_threshold_key(self):
        spec = self._spec("is_jammed")
        assert spec.unit == "ratio"
        assert spec.threshold_key == "GPS_JAM_THRESHOLD"

    def test_is_critical_declares_a_ratio_unit_and_its_threshold_key(self):
        spec = self._spec("is_critical")
        assert spec.unit == "ratio"
        assert spec.threshold_key == "GPS_JAM_CRITICAL_THRESHOLD"
