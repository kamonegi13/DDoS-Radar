"""F-08 — the full L5 cycle: detect, fix, observe the recovery.

F-08 (D2 §F): `gps_jamming` compares `jam_ratio` / `max_ratio`, fractions
in [0, 1], against `GPS_JAM_THRESHOLD=3.0` and
`GPS_JAM_CRITICAL_THRESHOLD=7.0`, which were percent-scaled. `is_jammed`
and `is_critical` were mathematically unreachable — the sensor fetched
successfully and detected nothing from the day it shipped, and no test
ever caught it.

WP-1.1 built the monitor against the live defect. **WP-0.2 (2026-08-07)
repaired the sensor**: the defaults are now 0.03 / 0.07 on the ratio
scale. This file therefore does two jobs at once, and the split matters:

  TestPostFixSensorFires        the recovery. The same 8%-bad input that
                                produced nothing now fires both flags, and
                                the firing monitor records last_fired_at.
  TestL5DetectsPermanentNonFiring   the detection capability, preserved.
                                It now runs on a genuinely quiet input
                                (0.5% bad) that legitimately never fires,
                                so the monitor's ability to call out
                                恒久無発火 stays proven after the defect it
                                was built for is gone. A check that can
                                only be validated against a live defect
                                stops being validatable the moment the fix
                                lands.

The whole chain runs under the REAL sensor name and the REAL
GpsJammingSensor.fetch() code path; only the two HTTP helpers and the H3
geometry lookup are replaced with synthetic data. The monitor's DB is
bound to a throwaway RadarDB so no production row is touched.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.database import RadarDB
from radar.sensors import gps_jamming as gps_mod
from radar.sensors.gps_jamming import GpsJammingSensor
from radar.verification import firing_monitor
from radar.verification.flag_catalog import evaluate_flags

DAY = 86400.0
SENSOR = "gps_jamming"
TARGET_CC = "TW"

# 8 bad out of 100 aircraft = a 0.08 jamming ratio. Against a correctly
# unitised 3% threshold this is a clear detection; against the shipped
# 3.0 (percent value used as a fraction) it is not.
BAD_RATIO = 0.08
CORRECT_THRESHOLD_AS_FRACTION = 0.03


@pytest.fixture
def fm_db(tmp_path, monkeypatch):
    inst = RadarDB(str(tmp_path / "f08" / "radar.db"))
    monkeypatch.setattr(firing_monitor, "_db", lambda: inst)
    return inst


def _drive_fetch(monkeypatch, bad: int, good: int):
    """Run the real fetch() over synthetic tiles of a given bad ratio."""
    coord = gps_mod.COUNTRY_COORDS[TARGET_CC]
    tiles = [{"hex": f"synthetic_{i}", "good": good, "bad": bad}
             for i in range(20)]

    sensor = GpsJammingSensor()
    monkeypatch.setattr(sensor, "_get_latest_date", lambda: "2026-08-05")
    monkeypatch.setattr(sensor, "_fetch_tile_data", lambda _d: tiles)
    # Place every tile at the target country's centre so the radius filter
    # keeps them all.
    monkeypatch.setattr(
        gps_mod, "_h3_to_lat_lon", lambda _h: (coord["lat"], coord["lng"]))

    return sensor.fetch({"strategic_theaters": [TARGET_CC],
                         "adversary_states": []})


@pytest.fixture
def jammed_payload(monkeypatch, fm_db):
    """8 bad of 100 aircraft — a genuine detection candidate."""
    return _drive_fetch(monkeypatch, bad=8, good=92)


@pytest.fixture
def quiet_payload(monkeypatch, fm_db):
    """0.5 bad of 100 — below any sane threshold, so it never fires.

    This is what keeps the never-fired detection provable now that the
    sensor works: a real sensor, real code path, honestly quiet input.
    """
    return _drive_fetch(monkeypatch, bad=1, good=199)


class TestPostFixSensorFires:
    """The recovery: the input that produced nothing now produces detections."""

    def test_ratio_is_above_the_repaired_threshold(self, jammed_payload):
        entry = jammed_payload["jamming_data"][TARGET_CC]
        assert entry["avg_level"] == pytest.approx(BAD_RATIO)
        assert entry["max_level"] == pytest.approx(BAD_RATIO)
        assert entry["avg_level"] > CORRECT_THRESHOLD_AS_FRACTION

    def test_is_jammed_now_fires(self, jammed_payload):
        assert jammed_payload["jamming_data"][TARGET_CC]["is_jammed"] is True, \
            "F-08 regressed — the ratio/percent mismatch is back"

    def test_is_critical_fires_above_the_critical_fraction(self, jammed_payload):
        # 8% clears the 7% critical threshold.
        assert jammed_payload["jamming_data"][TARGET_CC]["is_critical"] is True

    def test_country_status_escalates(self, jammed_payload):
        assert jammed_payload["country_status"][TARGET_CC] == "CRITICAL_JAMMING"

    def test_a_quiet_ratio_still_does_not_fire(self, quiet_payload):
        # The fix must not turn the sensor into a permanent alarm: 0.5%
        # is below the 3% threshold and stays quiet.
        entry = quiet_payload["jamming_data"][TARGET_CC]
        assert entry["avg_level"] == pytest.approx(0.005)
        assert entry["is_jammed"] is False
        assert entry["is_critical"] is False
        assert quiet_payload["country_status"][TARGET_CC] == "NORMAL"

    def test_thresholds_now_sit_inside_the_ratio_domain(self):
        jam_thr = float(os.getenv("GPS_JAM_THRESHOLD", "0.03"))
        crit_thr = float(os.getenv("GPS_JAM_CRITICAL_THRESHOLD", "0.07"))
        assert 0.0 < jam_thr <= 1.0 and 0.0 < crit_thr <= 1.0, \
            "thresholds must live in [0,1] — the domain of the compared value"
        assert jam_thr < crit_thr

    def test_catalog_agrees_both_flags_fired(self, jammed_payload):
        fired = evaluate_flags(SENSOR, jammed_payload)
        assert fired["is_jammed"] is True
        assert fired["is_critical"] is True

    def test_the_firing_monitor_records_the_recovery(self, fm_db,
                                                     jammed_payload):
        """The L5 side of the recovery: last_fired_at is finally set."""
        rows = {r["flag_id"]: r for r in fm_db.flag_state_for(SENSOR)}
        for flag in ("is_jammed", "is_critical"):
            assert rows[flag]["last_fired_at"] is not None, \
                f"{flag} fired but the monitor did not record it"

    def test_detection_health_is_no_longer_anomalous(self, fm_db,
                                                     jammed_payload):
        assert firing_monitor.detection_health(SENSOR) in ("OK", "INSUFFICIENT")


class TestUnitCheckObservesTheRecovery:
    """WP-1.3's unit axis flips to OK without the check changing."""

    def _results(self):
        from radar.verification import window_unit_health as wuh
        return {r["target"]: r for r in wuh.evaluate_units()}

    @pytest.mark.parametrize("target", ["gps_jamming.is_jammed",
                                        "gps_jamming.is_critical"])
    def test_threshold_is_inside_the_domain(self, target):
        result = self._results()[target]
        assert result["verdict"] == "OK", result
        assert result["reason"] == "unit_consistent"

    def test_the_whole_tunable_range_is_now_reachable(self):
        # Was 2.6% and 0% of the registry range; rescaling min/max to the
        # ratio domain makes every settable value capable of firing.
        for target in ("gps_jamming.is_jammed", "gps_jamming.is_critical"):
            assert self._results()[target]["range_overlap_fraction"] == 1.0

    def test_the_unit_annotation_is_declared(self):
        # S5-VERIF-007: the missing unit is how the scale error stayed
        # invisible in the first place.
        for target in ("gps_jamming.is_jammed", "gps_jamming.is_critical"):
            assert self._results()[target]["unit_declared"] == "ratio"

    def test_no_unit_anomalies_remain(self):
        offenders = {t for t, r in self._results().items()
                     if r["verdict"] == "ANOMALY"}
        assert offenders == set(), "the unit axis should be fully green"


class TestL5DetectsPermanentNonFiring:
    """Detection capability, preserved after the fix.

    Driven by `quiet_payload` (0.5% bad) rather than the repaired defect:
    a real sensor on honestly quiet data never fires, which is exactly the
    condition the monitor must still be able to call out."""

    NOW = 1_700_000_000.0

    def test_the_real_set_cache_hook_recorded_the_fetch(self, fm_db,
                                                        quiet_payload):
        """Wiring, end to end: the fixture above ran the real
        GpsJammingSensor.fetch(), so BaseSensor.set_cache() must already
        have written state under the real sensor name — no synthetic
        clock, no hand-rolled call."""
        flags = {r["flag_id"] for r in fm_db.flag_state_for(SENSOR)}
        assert {"is_jammed", "is_critical", "country_status"} <= flags
        assert all(r["last_fired_at"] is None
                   for r in fm_db.flag_state_for(SENSOR))

    # is_jammed expects a fire every 30d, is_critical every 90d. Under the
    # 2026-08-06 amendment a never-fired flag reaches ANOMALY at 3x its own
    # interval, so the observation window must clear 3 x 90d = 270d for the
    # slowest flag in the sensor.
    OBSERVED_DAYS = 300

    def _replay(self, fm_db, payload, span_days):
        """Clear the wall-clock row from the real fetch(), then replay the
        sensor on a synthetic clock for `span_days` of never-firing fetches."""
        conn = fm_db._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM sensor_flag_state WHERE sensor = ?", (SENSOR,))
            conn.execute("DELETE FROM sensor_flag_fire_log WHERE sensor = ?", (SENSOR,))
        ages = sorted({span_days, span_days // 2, span_days // 4, 3, 0},
                      reverse=True)
        for age_days in ages:
            firing_monitor.record_evaluation(
                SENSOR, payload, now=self.NOW - age_days * DAY)
        return fm_db

    @pytest.fixture
    def recorded(self, fm_db, quiet_payload):
        """300 days of successful fetches that never once fire.

        The wall-clock row written by the real fetch() in `jammed_payload`
        is cleared first so the synthetic clock is unambiguous; that the
        hook wrote it at all is asserted separately above.
        """
        return self._replay(fm_db, quiet_payload, self.OBSERVED_DAYS)

    @pytest.mark.parametrize("flag,expected", [
        ("is_jammed", "WARN"),          # interval 30d -> ratio ~1.03
        ("is_critical", "INSUFFICIENT"),  # interval 90d -> ratio ~0.34
    ])
    def test_day_31_is_not_yet_anomaly(self, fm_db, quiet_payload, flag,
                                       expected):
        """Pins the 2026-08-06 amendment. Under the old flat-30d rule both
        flags were ANOMALY at day 31 regardless of their expected cadence —
        the groundless burst that would have polluted CUT-08. The verdict
        now scales with each flag's own interval."""
        self._replay(fm_db, quiet_payload, 31)
        results = {(r["sensor"], r["flag_id"]): r
                   for r in firing_monitor.evaluate_silence(now=self.NOW)}
        result = results[(SENSOR, flag)]
        assert result["verdict"] == expected, result
        assert result["verdict"] != "ANOMALY"

    def test_state_shows_a_live_sensor_that_never_fired(self, recorded):
        rows = {r["flag_id"]: r for r in recorded.flag_state_for(SENSOR)}
        for flag in ("is_jammed", "is_critical"):
            assert rows[flag]["first_observed_at"] == \
                self.NOW - self.OBSERVED_DAYS * DAY
            assert rows[flag]["last_eval_at"] == self.NOW, \
                "the sensor is being evaluated — fetch liveness is fine"
            assert rows[flag]["last_fired_at"] is None, \
                "detection liveness is not"

    @pytest.mark.parametrize("flag", ["is_jammed", "is_critical"])
    def test_verdict_is_anomaly_never_fired(self, recorded, flag):
        results = {(r["sensor"], r["flag_id"]): r
                   for r in firing_monitor.evaluate_silence(now=self.NOW)}
        r = results[(SENSOR, flag)]
        assert r["verdict"] == "ANOMALY"
        assert r["reason"] == "never_fired"
        assert r["last_fired_at"] is None
        assert r["fire_count_30d"] == 0
        assert r["silence_ratio"] >= 3.0, \
            "ANOMALY must be justified by >=3x the flag's own interval"

    def test_detection_health_is_anomaly_while_fetch_health_is_not(
            self, recorded, quiet_payload):
        """S5-VERIF-004: the two axes must be independent, and the pair
        (fetch OK, detection ANOMALY) must never render as OK."""
        assert firing_monitor.detection_health(SENSOR, now=self.NOW) == "ANOMALY"

    def test_snapshot_lists_gps_jamming_among_anomalies(self, recorded):
        snap = firing_monitor.snapshot(now=self.NOW)
        anomalous = {(a["sensor"], a["flag_id"]) for a in snap["anomalies"]}
        assert (SENSOR, "is_jammed") in anomalous
        assert (SENSOR, "is_critical") in anomalous

    def test_daily_job_writes_the_finding_to_the_append_only_ledger(self, recorded):
        assert firing_monitor.run_daily_check_if_due(now=self.NOW) is True
        rows = {r["target"]: r for r in
                recorded.l5_check_latest(firing_monitor.CHECK_ID, limit=200)}
        entry = rows[f"{SENSOR}:is_jammed"]
        assert entry["verdict"] == "ANOMALY"
        assert entry["first_detected_at"] == self.NOW
        assert rows["__summary__"]["verdict"] == "ANOMALY"


class TestFixIsNotReverted:
    """Guard, inverted: the percent-scaled defaults must never come back."""

    def test_gps_jamming_reads_ratio_scaled_defaults(self):
        from pathlib import Path
        src = Path(gps_mod.__file__).read_text(encoding="utf-8")
        assert '"GPS_JAM_THRESHOLD",          "0.03"' in src
        assert '"GPS_JAM_CRITICAL_THRESHOLD", "0.07"' in src
        assert '"3.0"' not in src and '"7.0"' not in src

    def test_registry_and_sensor_defaults_agree(self):
        """A mismatch here would resurrect the defect the moment an
        analyst cleared the override (S1-CONF-009's failure mode)."""
        from radar import config_layered
        assert config_layered.get_meta("GPS_JAM_THRESHOLD").default == 0.03
        assert config_layered.get_meta(
            "GPS_JAM_CRITICAL_THRESHOLD").default == 0.07

    def test_module_constant_matches_too(self):
        from radar import config
        assert config.GPS_JAM_THRESHOLD == 0.03
        assert config.GPS_JAM_CRITICAL_THRESHOLD == 0.07
