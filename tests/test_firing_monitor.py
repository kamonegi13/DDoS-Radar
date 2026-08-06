"""WP-1.1 — firing liveness monitor (L5 self-verification layer).

Covers S5-VERIF-002 (persist last_fired_at / first_observed_at /
fire_count_30d), S5-VERIF-003 (numeric silence rules), S5-VERIF-004
(detection_health as a second, independent health axis) and
S5-VERIF-016 (one daily job driven by a *persistent* schedule, never a
volatile process counter — that was defect F-01).

Every DB-touching test binds `firing_monitor._db` to a throwaway
`RadarDB` under tmp_path. tests/conftest.py documents why truncating
tables on the live singleton is forbidden; a temp instance exercises
the real accessors without going anywhere near production rows.
"""
import contextlib
import os
import time
import uuid
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.database import RadarDB
from radar.scenarios import SensorTier
from radar.sensors.base import BaseSensor
from radar.verification import flag_catalog, firing_monitor
from radar.verification.flag_catalog import FlagSpec

DAY = 86400.0


class _StubSensor(BaseSensor):
    tier = SensorTier.GLOBAL

    def fetch(self, context: dict) -> dict:
        return {}


def _spec(sensor: str, flag_id: str = "is_probe", interval: int = 10) -> FlagSpec:
    return FlagSpec(
        sensor=sensor, flag_id=flag_id, kind="bool",
        non_firing_values=(False, None), path=(flag_id,), scope="global",
        threshold_key="", unit="bool", expected_fire_interval_days=interval,
        note="synthetic probe spec for tests",
    )


@pytest.fixture
def fm_db(l5_tmp_db):
    """Bind the monitor to a throwaway RadarDB (real schema, real accessors)."""
    return l5_tmp_db(firing_monitor, "l5")


@pytest.fixture
def probe_catalog(monkeypatch):
    """Replace the catalog with a single synthetic spec (10d interval)."""
    sensor = f"probe_{uuid.uuid4().hex[:8]}"
    spec = _spec(sensor)
    monkeypatch.setattr(flag_catalog, "CATALOG", (spec,))
    return sensor, spec


# ── S5-VERIF-002: persistence semantics ─────────────────────────────────────
class TestStateUpsert:
    def test_first_observed_at_is_set_once(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        t0 = 1_700_000_000.0
        firing_monitor.record_evaluation(sensor, {"is_probe": False}, now=t0)
        firing_monitor.record_evaluation(sensor, {"is_probe": False}, now=t0 + DAY)
        rows = fm_db.flag_state_for(sensor)
        assert len(rows) == 1
        assert rows[0]["first_observed_at"] == t0, \
            "first_observed_at must not be rewritten on later evaluations"

    def test_last_eval_at_advances_every_evaluation(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        t0 = 1_700_000_000.0
        firing_monitor.record_evaluation(sensor, {"is_probe": False}, now=t0)
        firing_monitor.record_evaluation(sensor, {"is_probe": False}, now=t0 + DAY)
        assert fm_db.flag_state_for(sensor)[0]["last_eval_at"] == t0 + DAY

    def test_last_fired_at_only_moves_on_a_fire(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        t0 = 1_700_000_000.0
        firing_monitor.record_evaluation(sensor, {"is_probe": False}, now=t0)
        assert fm_db.flag_state_for(sensor)[0]["last_fired_at"] is None
        firing_monitor.record_evaluation(sensor, {"is_probe": True}, now=t0 + DAY)
        assert fm_db.flag_state_for(sensor)[0]["last_fired_at"] == t0 + DAY
        firing_monitor.record_evaluation(sensor, {"is_probe": False}, now=t0 + 2 * DAY)
        assert fm_db.flag_state_for(sensor)[0]["last_fired_at"] == t0 + DAY, \
            "a non-firing evaluation must not clear last_fired_at"

    def test_out_of_order_evaluations_do_not_corrupt_the_window(
            self, fm_db, probe_catalog):
        """Backfill / replay must not rewrite the measurement window."""
        sensor, _ = probe_catalog
        t0 = 1_700_000_000.0
        firing_monitor.record_evaluation(sensor, {"is_probe": True}, now=t0)
        firing_monitor.record_evaluation(sensor, {"is_probe": True}, now=t0 - 10 * DAY)
        row = fm_db.flag_state_for(sensor)[0]
        assert row["first_observed_at"] == t0 - 10 * DAY, "earliest wins"
        assert row["last_eval_at"] == t0, "latest wins"
        assert row["last_fired_at"] == t0, "an older fire must not rewind the clock"

    def test_uncatalogued_sensor_writes_nothing(self, fm_db, probe_catalog):
        firing_monitor.record_evaluation("not_in_catalog", {"is_probe": True})
        assert fm_db.flag_state_all() == []


class TestFireLog:
    def test_fire_log_appends_and_counts_30d(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        for age in (1, 5, 20):
            firing_monitor.record_evaluation(
                sensor, {"is_probe": True}, now=now - age * DAY)
        counts = fm_db.flag_fire_counts_since(now - 30 * DAY)
        assert counts[(sensor, "is_probe")] == 3

    def test_fire_log_prunes_beyond_retention(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        ttl = flag_catalog.FIRE_LOG_RETENTION_DAYS * DAY
        fm_db.flag_fire_append(sensor, "is_probe", now - ttl - DAY, ttl)
        fm_db.flag_fire_append(sensor, "is_probe", now - ttl + DAY, ttl)
        # The second append's opportunistic prune uses its own ts as the
        # anchor, so re-append at `now` to sweep against the current clock.
        fm_db.flag_fire_append(sensor, "is_probe", now, ttl)
        assert fm_db.flag_fire_counts_since(0.0)[(sensor, "is_probe")] == 2, \
            "rows older than the retention window must be pruned on insert"


# ── S5-VERIF-003: numeric silence rules ─────────────────────────────────────
class TestSilenceVerdicts:
    def _fire_then(self, fm_db, sensor, fired_at, first_seen):
        fm_db.flag_state_upsert(sensor, "is_probe", first_seen, fired=False)
        fm_db.flag_state_upsert(sensor, "is_probe", fired_at, fired=True)

    def _verdict(self, sensor, now):
        res = [r for r in firing_monitor.evaluate_silence(now=now)
               if r["sensor"] == sensor]
        assert len(res) == 1
        return res[0]

    @pytest.mark.parametrize("ratio,expected", [
        (0.99, "OK"), (1.0, "WARN"), (2.99, "WARN"), (3.0, "ANOMALY"),
    ])
    def test_silence_ratio_boundaries(self, fm_db, probe_catalog, ratio, expected):
        sensor, spec = probe_catalog
        now = 1_700_000_000.0
        window = spec.expected_fire_interval_days * DAY
        self._fire_then(fm_db, sensor, now - ratio * window, now - 400 * DAY)
        r = self._verdict(sensor, now)
        assert r["verdict"] == expected, f"ratio={ratio} → {r}"
        assert r["silence_ratio"] == pytest.approx(ratio, abs=1e-6)

    def test_never_fired_within_grace_is_insufficient(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", now - 29 * DAY, fired=False)
        r = self._verdict(sensor, now)
        assert r["verdict"] == "INSUFFICIENT"
        assert r["last_fired_at"] is None

    def test_never_fired_past_grace_is_anomaly(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", now - 31 * DAY, fired=False)
        r = self._verdict(sensor, now)
        assert r["verdict"] == "ANOMALY"
        assert r["reason"] == "never_fired"

    def test_grace_boundary_is_inclusive(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        grace = flag_catalog.NEVER_FIRED_GRACE_DAYS
        fm_db.flag_state_upsert(sensor, "is_probe", now - grace * DAY, fired=False)
        assert self._verdict(sensor, now)["verdict"] == "ANOMALY"

    def test_epoch_zero_first_observed_is_not_read_as_now(self, fm_db,
                                                          probe_catalog):
        """A 0.0 timestamp is a real (if absurd) value, not a missing one —
        `or now` would silently reclassify a decade of silence as fresh."""
        sensor, _ = probe_catalog
        conn = fm_db._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO sensor_flag_state (sensor, flag_id, "
                "first_observed_at, last_eval_at, last_fired_at) "
                "VALUES (?, ?, ?, ?, ?)", (sensor, "is_probe", 0.0, 0.0, None))
        assert self._verdict(sensor, 1_700_000_000.0)["verdict"] == "ANOMALY"

    def test_no_state_row_is_never_evaluated(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        r = self._verdict(sensor, 1_700_000_000.0)
        assert r["verdict"] == "INSUFFICIENT"
        assert r["reason"] == "never_evaluated"

    def test_result_carries_the_measured_inputs(self, fm_db, probe_catalog):
        sensor, spec = probe_catalog
        now = 1_700_000_000.0
        self._fire_then(fm_db, sensor, now - DAY, now - 100 * DAY)
        r = self._verdict(sensor, now)
        assert r["expected_fire_interval_days"] == spec.expected_fire_interval_days
        assert r["first_observed_at"] == now - 100 * DAY
        assert r["fire_count_30d"] == 0  # state was seeded directly, no fire log


class TestNeverFiredRatioSemantics:
    """S5-VERIF-003 as amended 2026-08-06 (owner-approved).

    A flat 30-day never-fired grace was asymmetrically harsher than the
    rule for fired flags — a flag with a 30d interval that fired 30d ago is
    merely WARN, while an identical flag that never fired was ANOMALY. It
    also produced a groundless ANOMALY burst for genuinely rare flags
    (180d intervals) 31 days after deployment, which would have polluted
    CUT-08. Never-fired now uses the same ratio semantics, anchored at
    first_observed_at, with 30 days kept only as an observation floor.
    """

    NOW = 1_700_000_000.0

    def _verdict(self, fm_db, monkeypatch, interval_days, age_days):
        sensor = f"probe_{uuid.uuid4().hex[:8]}"
        monkeypatch.setattr(flag_catalog, "CATALOG",
                            (_spec(sensor, interval=interval_days),))
        fm_db.flag_state_upsert(
            sensor, "is_probe", self.NOW - age_days * DAY, fired=False)
        results = [r for r in firing_monitor.evaluate_silence(now=self.NOW)
                   if r["sensor"] == sensor]
        assert len(results) == 1
        return results[0]

    @pytest.mark.parametrize("interval,age,expected", [
        (7, 31, "ANOMALY"),          # ratio ~4.4 — clearly dead
        (30, 31, "WARN"),            # ratio ~1.03 — overdue, not yet damning
        (30, 90, "ANOMALY"),         # ratio 3.0 — boundary
        (30, 89, "WARN"),            # ratio ~2.97 — just below
        (180, 31, "INSUFFICIENT"),   # ratio ~0.17 — the false burst removed
        (10, 29, "INSUFFICIENT"),    # under the observation floor
        (1, 29, "INSUFFICIENT"),     # floor wins even at ratio 29
    ])
    def test_never_fired_verdict_boundaries(self, fm_db, monkeypatch,
                                            interval, age, expected):
        result = self._verdict(fm_db, monkeypatch, interval, age)
        assert result["verdict"] == expected, result

    def test_observation_floor_is_thirty_days(self, fm_db, monkeypatch):
        assert flag_catalog.NEVER_FIRED_GRACE_DAYS == 30
        assert self._verdict(fm_db, monkeypatch, 1, 29)["verdict"] == "INSUFFICIENT"
        assert self._verdict(fm_db, monkeypatch, 1, 30)["verdict"] == "ANOMALY"

    def test_reasons_distinguish_the_three_never_fired_states(self, fm_db,
                                                              monkeypatch):
        assert self._verdict(fm_db, monkeypatch, 10, 29)["reason"] == \
            "never_fired_within_grace"
        assert self._verdict(fm_db, monkeypatch, 180, 31)["reason"] == \
            "never_fired_within_interval"
        assert self._verdict(fm_db, monkeypatch, 7, 31)["reason"] == "never_fired"

    def test_silence_ratio_is_reported_for_never_fired_flags(self, fm_db,
                                                             monkeypatch):
        """NP6: the number the verdict was derived from must be visible."""
        result = self._verdict(fm_db, monkeypatch, 30, 90)
        assert result["silence_ratio"] == pytest.approx(3.0, abs=1e-6)
        assert result["last_fired_at"] is None

    @pytest.mark.parametrize("age,expected", [(31, "WARN"), (90, "ANOMALY")])
    def test_never_fired_matches_fired_at_the_same_ratio(self, fm_db, monkeypatch,
                                                         age, expected):
        """The asymmetry the amendment removes: identical silence, identical
        interval, identical verdict — whether or not it ever fired."""
        never = self._verdict(fm_db, monkeypatch, 30, age)

        fired_sensor = f"probe_{uuid.uuid4().hex[:8]}"
        monkeypatch.setattr(flag_catalog, "CATALOG",
                            (_spec(fired_sensor, interval=30),))
        fm_db.flag_state_upsert(
            fired_sensor, "is_probe", self.NOW - 400 * DAY, fired=False)
        fm_db.flag_state_upsert(
            fired_sensor, "is_probe", self.NOW - age * DAY, fired=True)
        fired = [r for r in firing_monitor.evaluate_silence(now=self.NOW)
                 if r["sensor"] == fired_sensor][0]

        assert never["verdict"] == fired["verdict"] == expected
        assert never["silence_ratio"] == pytest.approx(fired["silence_ratio"])


class TestDisabledSensorsSkipped:
    def test_disabled_sensor_is_not_evaluated(self, fm_db, monkeypatch):
        from radar import registry
        name = f"probe_disabled_{uuid.uuid4().hex[:8]}"
        stub = _StubSensor(name, "cyber", 60)
        stub.enabled = False
        registry.register(stub)
        try:
            monkeypatch.setattr(flag_catalog, "CATALOG", (_spec(name),))
            now = 1_700_000_000.0
            fm_db.flag_state_upsert(name, "is_probe", now - 400 * DAY, fired=False)
            assert firing_monitor.evaluate_silence(now=now) == []
            assert name in firing_monitor.snapshot(now=now)["disabled_skipped"]
        finally:
            registry._sensors.pop(name, None)


# ── S5-VERIF-004: detection_health as a separate axis ───────────────────────
class TestDetectionHealth:
    def test_unknown_without_state_rows(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        assert firing_monitor.detection_health(sensor) == "UNKNOWN"

    def test_no_flags_for_catalogued_flagless_sensor(self, fm_db):
        name = next(iter(flag_catalog.NO_DETECTION_FLAGS))
        assert firing_monitor.detection_health(name) == "NO_FLAGS"

    def test_worst_verdict_wins(self, fm_db, monkeypatch):
        sensor = f"probe_{uuid.uuid4().hex[:8]}"
        monkeypatch.setattr(flag_catalog, "CATALOG", (
            _spec(sensor, "flag_ok"), _spec(sensor, "flag_dead"),
        ))
        now = time.time()
        fm_db.flag_state_upsert(sensor, "flag_ok", now - 400 * DAY, fired=False)
        fm_db.flag_state_upsert(sensor, "flag_ok", now, fired=True)
        fm_db.flag_state_upsert(sensor, "flag_dead", now - 400 * DAY, fired=False)
        assert firing_monitor.detection_health(sensor) == "ANOMALY"

    def test_all_healthy_is_ok(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = time.time()
        fm_db.flag_state_upsert(sensor, "is_probe", now - 400 * DAY, fired=False)
        fm_db.flag_state_upsert(sensor, "is_probe", now, fired=True)
        assert firing_monitor.detection_health(sensor) == "OK"

    def test_db_failure_degrades_to_unknown_not_ok(self, fm_db, probe_catalog,
                                                  monkeypatch):
        """S5-VERIF-006: a query failure must never render as green."""
        sensor, _ = probe_catalog

        def _boom(*_a, **_kw):
            raise RuntimeError("simulated DB failure")

        monkeypatch.setattr(fm_db, "flag_state_for", _boom)
        assert firing_monitor.detection_health(sensor) == "UNKNOWN"


# ── S5-VERIF-016: persistent daily schedule ─────────────────────────────────
class TestPersistentSchedule:
    def test_runs_when_never_run_before(self, fm_db, probe_catalog):
        now = 1_700_000_000.0
        assert firing_monitor.run_daily_check_if_due(now=now) is True
        job = fm_db.l5_job_get(firing_monitor.JOB_ID)
        assert job["last_run_at"] == now
        assert job["next_run_at"] == now + DAY

    def test_skips_when_next_run_is_in_the_future(self, fm_db, probe_catalog):
        now = 1_700_000_000.0
        firing_monitor.run_daily_check_if_due(now=now)
        assert firing_monitor.run_daily_check_if_due(now=now + 3600) is False

    def test_runs_when_overdue_after_restart(self, fm_db, probe_catalog):
        """F-01 regression: a volatile `_cycle % 24` counter would skip this."""
        now = 1_700_000_000.0
        firing_monitor.run_daily_check_if_due(now=now)
        assert firing_monitor.run_daily_check_if_due(now=now + 5 * DAY) is True
        assert fm_db.l5_job_get(firing_monitor.JOB_ID)["next_run_at"] == \
            now + 5 * DAY + DAY

    def test_non_ok_results_are_appended_with_summary(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", now - 400 * DAY, fired=False)
        firing_monitor.run_daily_check_if_due(now=now)
        rows = fm_db.l5_check_latest(firing_monitor.CHECK_ID, limit=50)
        targets = {r["target"]: r for r in rows}
        assert targets[f"{sensor}:is_probe"]["verdict"] == "ANOMALY"
        assert targets["__summary__"]["verdict"] == "ANOMALY"

    def test_ok_results_are_not_appended(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", now - 400 * DAY, fired=False)
        fm_db.flag_state_upsert(sensor, "is_probe", now, fired=True)
        firing_monitor.run_daily_check_if_due(now=now)
        rows = fm_db.l5_check_latest(firing_monitor.CHECK_ID, limit=50)
        assert [r["target"] for r in rows] == ["__summary__"]

    def test_first_detected_at_carries_forward(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        t0 = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 400 * DAY, fired=False)
        firing_monitor.run_daily_check_if_due(now=t0)
        firing_monitor.run_daily_check_if_due(now=t0 + DAY)
        rows = [r for r in fm_db.l5_check_latest(firing_monitor.CHECK_ID, limit=50)
                if r["target"] == f"{sensor}:is_probe"]
        assert len(rows) == 2, "the ledger is append-only"
        assert {r["first_detected_at"] for r in rows} == {t0}, \
            "first_detected_at must survive across consecutive runs"

    def test_first_detected_at_resets_on_verdict_change(self, fm_db, probe_catalog):
        sensor, spec = probe_catalog
        t0 = 1_700_000_000.0
        window = spec.expected_fire_interval_days * DAY
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 400 * DAY, fired=False)
        firing_monitor.run_daily_check_if_due(now=t0)  # ANOMALY (never_fired)
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 1.5 * window, fired=True)
        t1 = t0 + DAY
        firing_monitor.run_daily_check_if_due(now=t1)  # now WARN
        rows = [r for r in fm_db.l5_check_latest(firing_monitor.CHECK_ID, limit=50)
                if r["target"] == f"{sensor}:is_probe"]
        latest = max(rows, key=lambda r: r["ts"])
        assert latest["verdict"] == "WARN"
        assert latest["first_detected_at"] == t1


class TestEpisodeBoundaries:
    """first_detected_at answers "since when has this been broken?". Without
    a recovery marker the ledger would bridge a fixed-then-broken-again gap
    into one continuous incident and overstate the age of the finding."""

    def _run_at(self, ts):
        return firing_monitor.run_daily_check_if_due(now=ts)

    def _rows(self, fm_db, sensor):
        return sorted(
            (r for r in fm_db.l5_check_latest(firing_monitor.CHECK_ID, limit=200)
             if r["target"] == f"{sensor}:is_probe"),
            key=lambda r: r["ts"])

    def test_recovery_starts_a_new_episode(self, fm_db, probe_catalog):
        sensor, spec = probe_catalog
        window = spec.expected_fire_interval_days * DAY
        t0 = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 400 * DAY, fired=False)

        # Episode 1 — silent for 1.5 windows.
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 1.5 * window, fired=True)
        self._run_at(t0)

        # Recovery — the flag fires again the next day.
        t_fire = t0 + DAY
        fm_db.flag_state_upsert(sensor, "is_probe", t_fire, fired=True)
        self._run_at(t_fire)

        # Episode 2 — silent again for another 1.5 windows.
        t2 = t_fire + 1.5 * window
        self._run_at(t2)

        rows = self._rows(fm_db, sensor)
        assert [r["verdict"] for r in rows] == ["WARN", "OK", "WARN"]
        assert rows[0]["first_detected_at"] == t0
        assert rows[1]["verdict"] == "OK", "the recovery must be recorded"
        assert rows[2]["first_detected_at"] == t2, \
            "a new episode must not inherit the first episode's start time"

    def test_recovery_rows_are_only_written_on_transition(self, fm_db,
                                                          probe_catalog):
        """Bounded: an already-OK target must not append a row every day."""
        sensor, _ = probe_catalog
        t0 = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 400 * DAY, fired=False)
        fm_db.flag_state_upsert(sensor, "is_probe", t0, fired=True)
        self._run_at(t0)
        self._run_at(t0 + DAY)
        self._run_at(t0 + 2 * DAY)
        assert self._rows(fm_db, sensor) == [], \
            "a target that was never non-OK must never be logged"

    def test_continuous_incident_still_carries_forward(self, fm_db, probe_catalog):
        sensor, spec = probe_catalog
        window = spec.expected_fire_interval_days * DAY
        t0 = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 400 * DAY, fired=False)
        fm_db.flag_state_upsert(sensor, "is_probe", t0 - 1.5 * window, fired=True)
        self._run_at(t0)
        self._run_at(t0 + DAY)
        rows = self._rows(fm_db, sensor)
        assert {r["first_detected_at"] for r in rows} == {t0}


class TestWriteBatching:
    """record_evaluation runs on the set_cache hot path. One fetch must cost
    one transaction, not 2N — both for gevent latency and so a crash cannot
    land last_fired_at without its matching fire-log row."""

    def test_one_evaluation_is_one_transaction(self, fm_db, monkeypatch):
        sensor = f"probe_{uuid.uuid4().hex[:8]}"
        monkeypatch.setattr(flag_catalog, "CATALOG", tuple(
            _spec(sensor, f"flag_{i}") for i in range(3)))
        conn = fm_db._get_conn()
        original = type(conn).writing
        entries = []

        @contextlib.contextmanager
        def _counting(self):
            entries.append(1)
            with original(self):
                yield

        monkeypatch.setattr(type(conn), "writing", _counting)
        firing_monitor.record_evaluation(
            sensor, {"flag_0": True, "flag_1": True, "flag_2": False},
            now=1_700_000_000.0)
        assert len(entries) == 1, \
            f"expected a single write transaction, got {len(entries)}"

    def test_batched_write_produces_the_same_state(self, fm_db, monkeypatch):
        sensor = f"probe_{uuid.uuid4().hex[:8]}"
        monkeypatch.setattr(flag_catalog, "CATALOG", tuple(
            _spec(sensor, f"flag_{i}") for i in range(3)))
        now = 1_700_000_000.0
        firing_monitor.record_evaluation(
            sensor, {"flag_0": True, "flag_1": True, "flag_2": False}, now=now)
        states = {r["flag_id"]: r for r in fm_db.flag_state_for(sensor)}
        assert set(states) == {"flag_0", "flag_1", "flag_2"}
        assert states["flag_0"]["last_fired_at"] == now
        assert states["flag_2"]["last_fired_at"] is None
        counts = fm_db.flag_fire_counts_since(0.0)
        assert counts.get((sensor, "flag_0")) == 1
        assert (sensor, "flag_2") not in counts

    def test_fire_log_is_pruned_inside_the_batch(self, fm_db, monkeypatch):
        sensor = f"probe_{uuid.uuid4().hex[:8]}"
        monkeypatch.setattr(flag_catalog, "CATALOG", (_spec(sensor),))
        now = 1_700_000_000.0
        ttl = flag_catalog.FIRE_LOG_RETENTION_DAYS * DAY
        fm_db.flag_fire_append(sensor, "is_probe", now - ttl - DAY, ttl)
        firing_monitor.record_evaluation(sensor, {"is_probe": True}, now=now)
        assert fm_db.flag_fire_counts_since(0.0)[(sensor, "is_probe")] == 1


class TestBulkDetectionHealth:
    """to_config_dict() is called once per sensor by config_list(); a
    per-sensor SELECT there is ~26 queries per /api/sensor_config request."""

    @pytest.fixture
    def two_sensors(self, fm_db, monkeypatch):
        alive = f"probe_ok_{uuid.uuid4().hex[:8]}"
        dead = f"probe_dead_{uuid.uuid4().hex[:8]}"
        monkeypatch.setattr(flag_catalog, "CATALOG",
                            (_spec(alive), _spec(dead)))
        now = time.time()
        fm_db.flag_state_upsert(alive, "is_probe", now - 400 * DAY, fired=False)
        fm_db.flag_state_upsert(alive, "is_probe", now, fired=True)
        fm_db.flag_state_upsert(dead, "is_probe", now - 400 * DAY, fired=False)
        return alive, dead

    def test_bulk_matches_per_sensor_results(self, two_sensors):
        alive, dead = two_sensors
        now = time.time()
        bulk = firing_monitor.detection_health_bulk(now=now)
        assert bulk[alive] == firing_monitor.detection_health(alive, now=now)
        assert bulk[dead] == firing_monitor.detection_health(dead, now=now)
        assert bulk[alive] == "OK" and bulk[dead] == "ANOMALY"

    def test_bulk_issues_one_state_query(self, fm_db, two_sensors, monkeypatch):
        per_sensor = []
        original = fm_db.flag_state_for
        monkeypatch.setattr(
            fm_db, "flag_state_for",
            lambda name: (per_sensor.append(name), original(name))[1])
        firing_monitor.detection_health_bulk()
        assert per_sensor == [], "bulk must not fall back to per-sensor SELECTs"

    def test_bulk_covers_flagless_and_unknown_sensors(self, two_sensors):
        bulk = firing_monitor.detection_health_bulk()
        flagless = next(iter(flag_catalog.NO_DETECTION_FLAGS))
        assert bulk[flagless] == "NO_FLAGS"

    def test_bulk_restricts_to_requested_names(self, two_sensors):
        alive, dead = two_sensors
        bulk = firing_monitor.detection_health_bulk(sensor_names=[alive])
        assert set(bulk) == {alive}

    def test_bulk_degrades_to_unknown_on_db_failure(self, fm_db, two_sensors,
                                                    monkeypatch):
        alive, dead = two_sensors

        def _boom():
            raise RuntimeError("simulated DB failure")

        monkeypatch.setattr(fm_db, "flag_state_all", _boom)
        bulk = firing_monitor.detection_health_bulk(sensor_names=[alive, dead])
        assert bulk == {alive: "UNKNOWN", dead: "UNKNOWN"}

    def test_to_config_dict_accepts_a_precomputed_value(self):
        sensor = _StubSensor(f"probe_{uuid.uuid4().hex[:8]}", "cyber", 60)
        cfg = sensor.to_config_dict(detection_health="ANOMALY")
        assert cfg["detection_health"] == "ANOMALY"

    def test_to_config_dict_still_self_queries_when_not_supplied(self):
        sensor = _StubSensor(f"probe_{uuid.uuid4().hex[:8]}", "cyber", 60)
        assert sensor.to_config_dict()["detection_health"] == "UNKNOWN"


class TestLedgerRetention:
    def test_check_results_are_pruned_beyond_retention(self, fm_db):
        now = 1_700_000_000.0
        ttl = firing_monitor.CHECK_RESULT_RETENTION_DAYS * DAY
        fm_db.l5_check_append(
            ts=now - ttl - DAY, check_id=firing_monitor.CHECK_ID,
            target="old:flag", verdict="WARN", ttl_sec=ttl)
        fm_db.l5_check_append(
            ts=now, check_id=firing_monitor.CHECK_ID,
            target="new:flag", verdict="WARN", ttl_sec=ttl)
        targets = {r["target"] for r in
                   fm_db.l5_check_latest(firing_monitor.CHECK_ID, limit=50)}
        assert targets == {"new:flag"}

    def test_retention_is_a_year(self):
        assert firing_monitor.CHECK_RESULT_RETENTION_DAYS == 365


class TestSnapshot:
    def test_snapshot_reports_job_state_and_buckets(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        now = 1_700_000_000.0
        fm_db.flag_state_upsert(sensor, "is_probe", now - 400 * DAY, fired=False)
        firing_monitor.run_daily_check_if_due(now=now)
        snap = firing_monitor.snapshot(now=now)
        assert snap["job_last_run_at"] == now
        assert snap["job_next_run_at"] == now + DAY
        assert snap["flags_total"] == 1
        assert [a["sensor"] for a in snap["anomalies"]] == [sensor]
        assert snap["warns"] == []
        assert snap["never_evaluated"] == []

    def test_never_evaluated_lists_sensors_without_state(self, fm_db, probe_catalog):
        sensor, _ = probe_catalog
        snap = firing_monitor.snapshot(now=1_700_000_000.0)
        assert snap["never_evaluated"] == [sensor]
        assert snap["insufficient_count"] == 1


class TestFailureContainment:
    def test_record_evaluation_never_raises(self, fm_db, probe_catalog, monkeypatch,
                                            caplog):
        """NP3: a monitor failure must never break a sensor fetch."""
        sensor, _ = probe_catalog

        def _boom(*_a, **_kw):
            raise RuntimeError("simulated DB failure")

        monkeypatch.setattr(fm_db, "flag_record_evaluation", _boom)
        firing_monitor.record_evaluation(sensor, {"is_probe": True})
        assert any("firing-monitor" in r.message or "firing-monitor" in r.getMessage()
                   for r in caplog.records), "the failure must be logged, not silent"

    def test_run_daily_check_never_raises(self, fm_db, probe_catalog, monkeypatch):
        monkeypatch.setattr(
            firing_monitor, "evaluate_silence",
            lambda **_kw: (_ for _ in ()).throw(RuntimeError("boom")))
        assert firing_monitor.run_daily_check_if_due(now=1_700_000_000.0) is False


# ── wiring guards (G-15: "written" is not "called") ─────────────────────────
class TestCallSiteWiring:
    def _src(self, *parts: str) -> str:
        return Path(__file__).resolve().parent.parent.joinpath(
            *parts).read_text(encoding="utf-8")

    def test_set_cache_records_the_evaluation(self):
        src = self._src("radar", "sensors", "base.py")
        body = src[src.index("def set_cache"):src.index("def set_error")]
        assert "record_evaluation" in body, \
            "BaseSensor.set_cache must feed the firing monitor"

    def test_to_config_dict_exposes_detection_health(self):
        src = self._src("radar", "sensors", "base.py")
        body = src[src.index("def to_config_dict"):]
        assert '"detection_health"' in body, \
            "S5-VERIF-004: detection_health must be a separate exposed axis"

    def test_fetch_health_semantics_untouched(self):
        """The `health` property still reports fetch liveness only; scoring
        confidence (compute_confidence) depends on that baseline."""
        src = self._src("radar", "sensors", "base.py")
        body = src[src.index("def health"):src.index("def compute_confidence")]
        assert "detection_health" not in body

    def test_scheduler_drives_the_persistent_job(self):
        src = self._src("radar", "scheduler.py")
        assert "run_daily_check_if_due" in src, \
            "the daily job must be driven from the maintenance worker"
        call = src[src.index("run_daily_check_if_due"):]
        assert "_cycle %" not in call[:400], \
            "F-01: the job must not be gated behind a volatile cycle counter"

    def test_config_list_uses_the_bulk_lookup(self):
        """N+1 guard: one bulk query per config_list(), not one per sensor."""
        src = self._src("radar", "engine.py")
        body = src[src.index("def config_list"):src.index("class WeightedConvergenceEngine")]
        assert "detection_health_bulk" in body
        assert "detection_health=" in body, \
            "the bulk value must be passed into to_config_dict"

    def test_base_sensor_has_no_per_method_logging_import(self):
        src = self._src("radar", "sensors", "base.py")
        body = src[src.index("class BaseSensor"):]
        assert "        import logging" not in body, \
            "hoist stdlib logging to module scope"

    def test_self_eval_exposes_firing_liveness(self):
        src = self._src("radar", "routes", "conclusions_v2.py")
        assert 'out["firing_liveness"]' in src
        assert 'out["firing_liveness_error"]' in src, \
            "S5-VERIF-006: a query failure must be visible, not an empty green block"
