"""Operational safety for `scripts/backfill_bgp_hod.py` — the ordering
guard and the monitored-country scope. Distinct from the quantity the
backfill writes, which `tests/test_bgp_prefix_quantity.py` covers.

Two review fixes pinned here:

  guard    A code review found the ordering rule — "deploy the repaired
           sensor and RESTART it before running the backfill" — lived
           only in `docs/design/v3/S3-data-migration.md`, a document an
           operator can run this script without ever opening.
           `_assert_no_live_sensor_writes` is the runtime half of that
           rule: it refuses when a monitored country's NEWEST `bgp_hod`
           bucket is a zero written within roughly one sensor cycle —
           the signature of the OLD, unrepaired sensor still writing a
           fresh 0.0 every poll. Historical zeros (the dead epoch this
           script is about to delete) and countries with no row at all
           (a fresh table, or a country never backfilled) must NOT trip
           it — only a RECENT zero is evidence of a live writer.
  default  `monitored_countries()` computed `enabled` as
           `bool(preset.get("enabled"))`, silently treating an omitted
           key as DISABLED. Production's Layer-1 default
           (`_parse_scenario_json`, `radar/scenarios.py:302`:
           `bool(raw.get("enabled", True))`) is the opposite: an omitted
           key is ENABLED. Every preset in the live `geo_data.json` sets
           the key today, so there is no current effect — but a future
           preset relying on the implicit default would be silently
           dropped from the backfill's scope while production keeps
           scoring it.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sqlite3

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
HOUR = 3600


def _backfill():
    """The script, loaded by path — `scripts/` is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        "backfill_bgp_hod", REPO / "scripts" / "backfill_bgp_hod.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backfill = _backfill()

NOW = 1_786_000_000.0
#: Read from the real sensor source, exactly as the guard itself does —
#: a hardcoded 1800 here would stop pinning anything the moment someone
#: changed the sensor's cadence and forgot this file.
CYCLE = backfill._sensor_poll_interval_sec()
WINDOW = CYCLE * backfill.GUARD_ZERO_WINDOW_CYCLES


def _ledger(tmp_path, rows=()) -> sqlite3.Connection:
    connection = sqlite3.connect(str(tmp_path / "radar.db"))
    connection.execute(
        "CREATE TABLE bgp_hod (theater TEXT NOT NULL, "
        "hour_bucket INTEGER NOT NULL, prefix_count REAL NOT NULL, "
        "PRIMARY KEY (theater, hour_bucket))")
    connection.executemany("INSERT INTO bgp_hod VALUES (?,?,?)", rows)
    connection.commit()
    return connection


# ── the live-sensor guard ───────────────────────────────────────────────

class TestTheLiveSensorGuardsExactDiscriminator:
    def test_a_zero_written_inside_the_window_trips_the_guard(self, tmp_path):
        """The signature of the old, unrepaired sensor still writing."""
        bucket = int(NOW - (WINDOW - 1))
        connection = _ledger(tmp_path, [("TW", bucket, 0.0)])
        try:
            with pytest.raises(backfill.LiveSensorGuardTripped, match="TW"):
                backfill._assert_no_live_sensor_writes(
                    connection, ["TW"], now=NOW, override=False)
        finally:
            connection.close()

    def test_a_zero_at_exactly_the_window_boundary_does_not_trip_it(
            self, tmp_path):
        """The comparison is strict (`age < window`), not `<=`."""
        bucket = int(NOW - WINDOW)
        connection = _ledger(tmp_path, [("TW", bucket, 0.0)])
        try:
            backfill._assert_no_live_sensor_writes(
                connection, ["TW"], now=NOW, override=False)  # no raise
        finally:
            connection.close()

    def test_an_old_historical_zero_does_not_trip_it(self, tmp_path):
        """Historical zeros are exactly what this run is about to delete
        — they must not be mistaken for evidence of a live writer."""
        bucket = int(NOW - (WINDOW + HOUR))
        connection = _ledger(tmp_path, [("TW", bucket, 0.0)])
        try:
            backfill._assert_no_live_sensor_writes(
                connection, ["TW"], now=NOW, override=False)  # no raise
        finally:
            connection.close()

    def test_a_country_with_no_row_at_all_does_not_trip_it(self, tmp_path):
        """Absence is not evidence the old sensor is running."""
        connection = _ledger(tmp_path)  # `bgp_hod` exists, empty
        try:
            backfill._assert_no_live_sensor_writes(
                connection, ["TW"], now=NOW, override=False)  # no raise
        finally:
            connection.close()

    def test_a_completely_fresh_database_does_not_trip_it(self, tmp_path):
        """No `bgp_hod` table at all — a brand-new install."""
        connection = sqlite3.connect(str(tmp_path / "radar.db"))
        try:
            backfill._assert_no_live_sensor_writes(
                connection, ["TW"], now=NOW, override=False)  # no raise
        finally:
            connection.close()

    def test_a_recent_nonzero_bucket_does_not_trip_it(self, tmp_path):
        """A live, REPAIRED sensor writing real values must not be
        refused just for being recent."""
        bucket = int(NOW - (WINDOW - 1))
        connection = _ledger(tmp_path, [("TW", bucket, 10800.0)])
        try:
            backfill._assert_no_live_sensor_writes(
                connection, ["TW"], now=NOW, override=False)  # no raise
        finally:
            connection.close()

    def test_only_the_newest_bucket_is_the_discriminator(self, tmp_path):
        """An old zero behind a recent real value must not trip it —
        the newest row is what matters, not any zero in the country's
        history."""
        old_zero = int(NOW - (WINDOW + HOUR))
        recent_real = int(NOW - (WINDOW - 1))
        connection = _ledger(tmp_path, [("TW", old_zero, 0.0),
                                        ("TW", recent_real, 9600.0)])
        try:
            backfill._assert_no_live_sensor_writes(
                connection, ["TW"], now=NOW, override=False)  # no raise
        finally:
            connection.close()

    def test_the_override_flag_bypasses_the_guard(self, tmp_path):
        bucket = int(NOW - (WINDOW - 1))
        connection = _ledger(tmp_path, [("TW", bucket, 0.0)])
        try:
            backfill._assert_no_live_sensor_writes(
                connection, ["TW"], now=NOW, override=True)  # no raise
        finally:
            connection.close()

    def test_the_message_names_what_is_running_and_what_to_do(
            self, tmp_path):
        bucket = int(NOW - (WINDOW - 1))
        connection = _ledger(tmp_path, [("TW", bucket, 0.0)])
        try:
            with pytest.raises(backfill.LiveSensorGuardTripped) as excinfo:
                backfill._assert_no_live_sensor_writes(
                    connection, ["TW"], now=NOW, override=False)
        finally:
            connection.close()
        message = str(excinfo.value)
        assert "restart" in message.lower()
        assert "--override-live-sensor-guard" in message


class TestTheSensorCadenceIsReadNotHardcoded:
    def test_the_poll_interval_matches_the_sensors_own_constructor_call(
            self):
        """`BgpRoutingSensor.__init__` calls `super().__init__("ripe_bgp",
        "cyber", 1800)` — the guard must read that 1800 out of the
        sensor's own source, not carry a second copy of the number."""
        assert backfill._sensor_poll_interval_sec() == 1800

    def test_the_window_is_derived_from_the_cadence(self):
        assert WINDOW == CYCLE * backfill.GUARD_ZERO_WINDOW_CYCLES
        assert WINDOW > 0


# ── the monitored-country default ───────────────────────────────────────

def _geo_data(tmp_path, scenarios: dict) -> None:
    (tmp_path / "geo_data.json").write_text(json.dumps(
        {"SCENARIOS": scenarios}))


class TestAnOmittedEnabledKeyDefaultsToEnabled:
    def test_an_omitted_key_is_treated_as_enabled(self, tmp_path,
                                                   monkeypatch):
        monkeypatch.setattr(backfill, "REPO", tmp_path)
        _geo_data(tmp_path, {"implicit": {"participants": {"TW": {}}}})
        connection = sqlite3.connect(":memory:")
        try:
            assert backfill.monitored_countries(connection) == ["TW"]
        finally:
            connection.close()

    def test_an_explicit_false_is_still_disabled(self, tmp_path,
                                                  monkeypatch):
        monkeypatch.setattr(backfill, "REPO", tmp_path)
        _geo_data(tmp_path, {
            "off": {"enabled": False, "participants": {"TW": {}}}})
        connection = sqlite3.connect(":memory:")
        try:
            assert backfill.monitored_countries(connection) == []
        finally:
            connection.close()

    def test_an_explicit_true_is_still_enabled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(backfill, "REPO", tmp_path)
        _geo_data(tmp_path, {
            "on": {"enabled": True, "participants": {"TW": {}}}})
        connection = sqlite3.connect(":memory:")
        try:
            assert backfill.monitored_countries(connection) == ["TW"]
        finally:
            connection.close()

    def test_a_db_override_wins_over_the_implicit_default(self, tmp_path,
                                                           monkeypatch):
        """The `scenarios` table override, when a row exists, is
        authoritative regardless of what the preset omits — matching
        Layer 2 in `radar/scenarios.py`."""
        monkeypatch.setattr(backfill, "REPO", tmp_path)
        _geo_data(tmp_path, {"implicit": {"participants": {"TW": {}}}})
        connection = sqlite3.connect(":memory:")
        connection.execute(
            "CREATE TABLE scenarios (id TEXT, enabled INTEGER)")
        connection.execute("INSERT INTO scenarios VALUES ('implicit', 0)")
        connection.commit()
        try:
            assert backfill.monitored_countries(connection) == []
        finally:
            connection.close()
