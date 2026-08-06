"""WP-1.3 — the window / threshold catalogs (S5-VERIF-007..011).

The catalogs are the declarative half of the check: every rolling baseline
in the sensor layer and every threshold-vs-value comparison is described
once, so the check can be a pure function of {catalog, live cadence,
registry}. Like flag_catalog's NO_DETECTION_FLAGS, coverage is total —
a sensor is either catalogued or explicitly declared baseline-free. There
is no third state in which a baseline simply goes unwatched.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

import radar.config  # noqa: F401  — populates the config registry
from radar import registry
from radar.verification import window_catalog as wc

HOUR = 3600.0


def _spec(baseline_id):
    return next(s for s in wc.CATALOG if s.baseline_id == baseline_id)


# ── totality (no third state) ───────────────────────────────────────────────
class TestCoverage:
    def test_every_registered_sensor_is_classified(self):
        catalogued = {s.sensor for s in wc.CATALOG if s.sensor}
        known = catalogued | set(wc.NO_BASELINE_SENSORS)
        live = {s.name for s in registry.all()}
        assert live - known == set(), \
            "a sensor with neither a WindowSpec nor a NO_BASELINE declaration"

    def test_no_baseline_declarations_are_real_sensors(self):
        live = {s.name for s in registry.all()}
        assert set(wc.NO_BASELINE_SENSORS) - live == set()

    def test_declared_baseline_free_sensors_have_no_spec(self):
        catalogued = {s.sensor for s in wc.CATALOG if s.sensor}
        assert catalogued & set(wc.NO_BASELINE_SENSORS) == set()

    def test_catalogued_sensors_still_exist(self):
        # Reverse totality: a spec naming a sensor that no longer exists
        # must fail here rather than decay into a permanent INSUFFICIENT
        # verdict nobody reads.
        live = {s.name for s in registry.all()}
        stale = {s.sensor for s in wc.CATALOG if s.sensor} - live
        assert stale == set(), f"WindowSpec(s) naming unregistered sensors: {stale}"

    def test_threshold_catalog_sensors_still_exist(self):
        live = {s.name for s in registry.all()}
        stale = {c.sensor for c in wc.THRESHOLD_CATALOG if c.sensor} - live
        assert stale == set()

    def test_target_namespace_has_no_collisions(self):
        # Both axes write into the same l5_check_result target column; a
        # shared id would merge two findings into one episode.
        baseline_ids = {s.baseline_id for s in wc.CATALOG}
        comparison_ids = {c.comparison_id for c in wc.THRESHOLD_CATALOG}
        assert baseline_ids & comparison_ids == set()

    def test_non_sensor_baselines_are_allowed_and_named(self):
        # sensor_zscore_stats and the engine baseline live outside the
        # sensor registry but are still rolling state that can rot.
        outside = [s for s in wc.CATALOG if not s.sensor]
        assert outside, "the non-sensor baselines must still be catalogued"
        assert all(s.baseline_id for s in outside)


class TestSpecWellFormedness:
    def test_kinds_are_from_the_closed_vocabulary(self):
        assert all(s.kind in wc.ALL_KINDS for s in wc.CATALOG)

    def test_cap_modes_are_from_the_closed_vocabulary(self):
        assert all(s.cap_mode in wc.ALL_CAP_MODES for s in wc.CATALOG)

    def test_baseline_ids_are_unique(self):
        ids = [s.baseline_id for s in wc.CATALOG]
        assert len(ids) == len(set(ids))

    def test_every_spec_explains_itself(self):
        assert all(s.note for s in wc.CATALOG), "NP6: no unexplained entry"

    def test_fixed_caps_declare_a_value(self):
        for spec in wc.CATALOG:
            if spec.cap_mode == wc.CAP_FIXED:
                assert spec.cap_value and spec.cap_value > 0, spec.baseline_id

    def test_derived_caps_declare_the_window_they_derive_from(self):
        for spec in wc.CATALOG:
            if spec.cap_mode == wc.CAP_DAYS_X_CYCLES:
                assert spec.declared_days, spec.baseline_id


# ── effective-window arithmetic (S5-VERIF-010/011) ─────────────────────────
class TestEffectiveWindow:
    def test_fixed_cap_is_samples_times_cadence(self):
        # F-06 in one line: 30 samples at 900 s is 7.5 h, not 30 days.
        spec = _spec("telegram_mirror._baseline_tg")
        assert wc.cap_samples(spec, 900) == 30
        assert wc.effective_window_hours(spec, 900) == pytest.approx(7.5)

    def test_declared_window_is_days_in_hours(self):
        spec = _spec("telegram_mirror._baseline_tg")
        assert wc.declared_window_hours(spec) == pytest.approx(720.0)

    def test_derived_cap_tracks_the_declared_window(self):
        spec = _spec("rss_narrative._baseline")
        assert wc.cap_samples(spec, 1800) == 30 * 48
        assert wc.effective_window_hours(spec, 1800) == pytest.approx(720.0)

    def test_derived_cap_recomputes_when_cadence_changes(self):
        # S5-VERIF-011: a sensor that changes cadence at runtime must not
        # keep a cap computed once at import.
        spec = _spec("rss_narrative._baseline")
        assert wc.cap_samples(spec, 900) == 30 * 96
        assert wc.effective_window_hours(spec, 900) == pytest.approx(720.0)

    def test_fixed_cap_window_moves_with_cadence(self):
        spec = _spec("telegram_mirror._baseline_tg")
        assert wc.effective_window_hours(spec, 1800) == pytest.approx(15.0)

    def test_deviation_is_relative_to_the_declaration(self):
        assert wc.window_deviation(7.5, 720.0) == pytest.approx(0.98958, abs=1e-5)
        assert wc.window_deviation(720.0, 720.0) == 0.0
        assert wc.window_deviation(720.0, None) is None

    def test_unbounded_and_by_construction_have_no_effective_window(self):
        for baseline_id in ("sensor_zscore_stats", "checkhost_hod"):
            spec = _spec(baseline_id)
            assert wc.effective_window_hours(spec, 600) is None


class TestSampleInterval:
    def test_interval_reads_the_live_poll_value(self):
        spec = _spec("telegram_mirror._baseline_tg")
        assert wc.sample_interval_sec(spec) == 900

    def test_cooldown_floors_the_interval(self):
        # check_host polls every 600 s but also refuses to re-check a URL
        # inside 300 s; the effective sample spacing is the larger.
        spec = _spec("check_host._url_latency_history")
        assert spec.cooldown_sec == 300
        assert wc.sample_interval_sec(spec) == 600

    def test_cooldown_wins_when_it_exceeds_the_poll(self, monkeypatch):
        spec = _spec("check_host._url_latency_history")
        sensor = registry.get("check_host")
        monkeypatch.setattr(sensor, "poll_interval", 60)
        assert wc.sample_interval_sec(spec) == 300

    def test_runtime_cadence_change_is_observed(self, monkeypatch):
        # ct_log / ooni mutate poll_interval while running; the catalog must
        # read the live attribute rather than a cached one.
        spec = _spec("telegram_mirror._baseline_tg")
        sensor = registry.get("telegram_mirror")
        monkeypatch.setattr(sensor, "poll_interval", 3600)
        assert wc.sample_interval_sec(spec) == 3600
        assert wc.effective_window_hours(spec, 3600) == pytest.approx(30.0)

    def test_unknown_sensor_yields_no_interval(self):
        spec = _spec("sensor_zscore_stats")
        assert wc.sample_interval_sec(spec) is None


# ── threshold catalog (S5-VERIF-007/008/009) ───────────────────────────────
def _cmp(comparison_id):
    return next(c for c in wc.THRESHOLD_CATALOG
                if c.comparison_id == comparison_id)


class TestThresholdCatalog:
    def test_comparison_ids_are_unique(self):
        ids = [c.comparison_id for c in wc.THRESHOLD_CATALOG]
        assert len(ids) == len(set(ids))

    def test_domains_are_from_the_closed_vocabulary(self):
        assert all(c.domain_kind in wc.ALL_UNITS for c in wc.THRESHOLD_CATALOG)

    def test_every_comparison_is_either_keyed_or_literal(self):
        for c in wc.THRESHOLD_CATALOG:
            # keyed  <=>  no literal. Exactly one source of the threshold.
            assert bool(c.threshold_key) == (c.literal_value is None), \
                f"{c.comparison_id}: exactly one of key / literal"

    def test_every_comparison_explains_itself(self):
        assert all(c.note for c in wc.THRESHOLD_CATALOG)

    def test_domain_bounds_are_ordered(self):
        for c in wc.THRESHOLD_CATALOG:
            if c.domain_lo is not None and c.domain_hi is not None:
                assert c.domain_lo < c.domain_hi, c.comparison_id

    def test_gps_jamming_comparisons_are_catalogued_as_ratios(self):
        for cid in ("gps_jamming.is_jammed", "gps_jamming.is_critical"):
            comparison = _cmp(cid)
            assert (comparison.domain_kind, comparison.domain_lo,
                    comparison.domain_hi) == ("ratio", 0.0, 1.0)

    def test_flag_catalog_thresholds_are_all_represented(self):
        # Whatever flag_catalog annotates with a threshold_key must be
        # covered here, or the unit check would silently skip it.
        from radar.verification import flag_catalog
        annotated = {spec.threshold_key for spec in flag_catalog.CATALOG
                     if spec.threshold_key}
        covered = {c.threshold_key for c in wc.THRESHOLD_CATALOG
                   if c.threshold_key}
        assert annotated - covered == set()


class TestDomainMath:
    def test_value_inside_the_domain(self):
        assert wc.in_domain(0.5, 0.0, 1.0) is True
        assert wc.in_domain(3.0, 0.0, 1.0) is False

    def test_open_ended_domains(self):
        assert wc.in_domain(1e9, 0.0, None) is True
        assert wc.in_domain(-1.0, 0.0, None) is False

    def test_overlap_fraction_of_a_tunable_range(self):
        # GPS_JAM_THRESHOLD: min 0.5 max 20.0 against a [0,1] domain — only
        # [0.5, 1.0] of a 19.5-wide range can ever fire.
        assert wc.range_overlap_fraction(0.5, 20.0, 0.0, 1.0) == \
            pytest.approx(0.5 / 19.5)

    def test_overlap_fraction_is_zero_when_the_range_only_touches(self):
        # GPS_JAM_CRITICAL_THRESHOLD: min 1.0 touches the domain's top edge
        # but encloses no reachable interval.
        assert wc.range_overlap_fraction(1.0, 30.0, 0.0, 1.0) == 0.0

    def test_overlap_fraction_is_one_when_fully_inside(self):
        assert wc.range_overlap_fraction(0.1, 0.9, 0.0, 1.0) == 1.0

    def test_overlap_fraction_is_none_without_a_declared_range(self):
        assert wc.range_overlap_fraction(None, None, 0.0, 1.0) is None
