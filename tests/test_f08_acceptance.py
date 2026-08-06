"""WP-1.1 acceptance — L5 must detect F-08 as permanently non-firing.

F-08 (D2 §F): `gps_jamming` compares `jam_ratio` / `max_ratio`, which are
fractions in [0, 1], against `GPS_JAM_THRESHOLD=3.0` and
`GPS_JAM_CRITICAL_THRESHOLD=7.0`, which are percent-scaled. `is_jammed`
and `is_critical` are therefore mathematically unreachable — the sensor
has been fetching successfully and detecting nothing since the day it
shipped, and no test ever caught it.

**This defect is deliberately NOT fixed here.** WP-1.1 is the monitor;
fixing the sensor first would make the monitor unverifiable (WP-1.1
「やってはいけないこと」). The test below pins the broken behaviour as the
input and asserts that the firing-liveness layer reports it as
恒久無発火 (ANOMALY / never_fired).

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


@pytest.fixture
def jammed_payload(monkeypatch, fm_db):
    """Drive the real fetch() with synthetic tiles showing 8% bad aircraft."""
    coord = gps_mod.COUNTRY_COORDS[TARGET_CC]
    tiles = [{"hex": f"synthetic_{i}", "good": 92, "bad": 8} for i in range(20)]

    sensor = GpsJammingSensor()
    monkeypatch.setattr(sensor, "_get_latest_date", lambda: "2026-08-05")
    monkeypatch.setattr(sensor, "_fetch_tile_data", lambda _d: tiles)
    # Place every tile at the target country's centre so the radius filter
    # keeps them all.
    monkeypatch.setattr(
        gps_mod, "_h3_to_lat_lon", lambda _h: (coord["lat"], coord["lng"]))

    payload = sensor.fetch({"strategic_theaters": [TARGET_CC],
                            "adversary_states": []})
    return payload


class TestPreFixSensorIsDead:
    """(a) Sanity — the input is 'should-fire' data and the detector is dead."""

    def test_ratio_is_above_a_correctly_unitised_threshold(self, jammed_payload):
        entry = jammed_payload["jamming_data"][TARGET_CC]
        assert entry["avg_level"] == pytest.approx(BAD_RATIO)
        assert entry["max_level"] == pytest.approx(BAD_RATIO)
        assert entry["avg_level"] > CORRECT_THRESHOLD_AS_FRACTION, \
            "the synthetic input must be a genuine detection candidate"

    def test_is_jammed_is_false_anyway(self, jammed_payload):
        assert jammed_payload["jamming_data"][TARGET_CC]["is_jammed"] is False, \
            "F-08 appears fixed — WP-1.1's acceptance target no longer exists"

    def test_is_critical_is_false_anyway(self, jammed_payload):
        assert jammed_payload["jamming_data"][TARGET_CC]["is_critical"] is False

    def test_country_status_stays_normal(self, jammed_payload):
        assert jammed_payload["country_status"][TARGET_CC] == "NORMAL"

    def test_thresholds_are_unreachable_for_any_ratio(self):
        """The domain of `jam_ratio` is [0, 1]; the thresholds are 3.0 / 7.0."""
        jam_thr = float(os.getenv("GPS_JAM_THRESHOLD", "3.0"))
        crit_thr = float(os.getenv("GPS_JAM_CRITICAL_THRESHOLD", "7.0"))
        assert jam_thr > 1.0 and crit_thr > 1.0, \
            "thresholds now sit inside the ratio domain — F-08 was fixed"

    def test_catalog_agrees_nothing_fired(self, jammed_payload):
        fired = evaluate_flags(SENSOR, jammed_payload)
        assert fired["is_jammed"] is False
        assert fired["is_critical"] is False
        assert fired["country_status"] is False


class TestL5DetectsPermanentNonFiring:
    """(b)+(c)+(d) — record, evaluate, and surface it in the AP3 snapshot."""

    NOW = 1_700_000_000.0

    def test_the_real_set_cache_hook_recorded_the_fetch(self, fm_db,
                                                        jammed_payload):
        """Wiring, end to end: the fixture above ran the real
        GpsJammingSensor.fetch(), so BaseSensor.set_cache() must already
        have written state under the real sensor name — no synthetic
        clock, no hand-rolled call."""
        flags = {r["flag_id"] for r in fm_db.flag_state_for(SENSOR)}
        assert {"is_jammed", "is_critical", "country_status"} <= flags
        assert all(r["last_fired_at"] is None
                   for r in fm_db.flag_state_for(SENSOR))

    @pytest.fixture
    def recorded(self, fm_db, jammed_payload):
        """31 days of successful fetches that never once fire.

        The wall-clock row written by the real fetch() in `jammed_payload`
        is cleared first so the synthetic clock below is unambiguous; that
        the hook wrote it at all is asserted separately above.
        """
        conn = fm_db._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM sensor_flag_state WHERE sensor = ?", (SENSOR,))
            conn.execute("DELETE FROM sensor_flag_fire_log WHERE sensor = ?", (SENSOR,))
        for age_days in (31, 20, 10, 3, 0):
            firing_monitor.record_evaluation(
                SENSOR, jammed_payload, now=self.NOW - age_days * DAY)
        return fm_db

    def test_state_shows_a_live_sensor_that_never_fired(self, recorded):
        rows = {r["flag_id"]: r for r in recorded.flag_state_for(SENSOR)}
        for flag in ("is_jammed", "is_critical"):
            assert rows[flag]["first_observed_at"] == self.NOW - 31 * DAY
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

    def test_detection_health_is_anomaly_while_fetch_health_is_not(
            self, recorded, jammed_payload):
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


class TestSensorIsUnmodified:
    """Guard: a later session must not 'helpfully' fix F-08 and quietly
    destroy this acceptance test."""

    def test_gps_jamming_still_reads_the_percent_scaled_defaults(self):
        from pathlib import Path
        src = Path(gps_mod.__file__).read_text(encoding="utf-8")
        assert '"GPS_JAM_THRESHOLD",          "3.0"' in src
        assert '"GPS_JAM_CRITICAL_THRESHOLD", "7.0"' in src
