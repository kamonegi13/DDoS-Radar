"""WP-2.6 remediation pins for the three geography-driven physical adapters.

`gps_jamming`, `ais_maritime` and `openweather` all turn a global or
box-shaped upstream answer into a per-country fact by arithmetic, and every
defect fixed here was in that arithmetic or in the way its result was
labelled. The two that matter most are failure DIRECTIONS rather than
values:

* `gps_jamming` wrote the string `"pending_l1_prev_ratio"` into `surge`, a
  key the flag catalog reads as a bool. A non-empty string is truthy, so
  the sensor read as permanently firing and the L5 silence detector could
  never register it as quiet.
* `ais_maritime` coerced malformed vessel records instead of discarding
  them, and substituted `distance_km = 0.0` when the chokepoint centre was
  unknown. Both fabricate alarms: a parse failure became a stationary
  warship, and "unknown distance" became "on top of the chokepoint".

Every assertion here either compares against the live production module
(read with `ast`/text, never imported) or drives `normalize` over a
recorded payload.
"""
import ast

import pytest

from tests.test_adapters_cyber import legacy_source
from tests.test_adapters_physical import FIXTURES, T0, context, payload

from v3.adapters.physical import ais_maritime, gps_jamming, openweather
from v3.adapters.types import (AdapterId, AUTH_IN_QUERY, FetchedPayload,
                               NormalizeContext, STATUS_FIRED,
                               STATUS_NO_DATA, STATUS_OK)

TILES_URL = "https://gpsjam.org/data/2026-08-06-h3_4.csv"
BASHI = ("Bashi Channel", 21.9, 121.0, "TW")
BASHI_LABEL = "cp=Bashi Channel;lat=21.9;lon=121.0"


def flag_values(relative_path: str, key: str) -> set:
    """Every literal a module writes under one dict key.

    Read with `ast` because the branch a fixture never reaches still
    reaches the ledger in production, and the type of a flag value is what
    the flag catalog dispatches on.
    """
    tree = ast.parse((FIXTURES.parent.parent.parent
                      / relative_path).read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for name_node, value_node in zip(node.keys, node.values):
            if isinstance(name_node, ast.Constant) \
                    and name_node.value == key \
                    and isinstance(value_node, ast.Constant):
                found.add(value_node.value)
    return found


def getenv_default(relative_path: str, name: str):
    """The default in `os.getenv("NAME", "default")` in a live module."""
    for node in ast.walk(ast.parse(legacy_source(relative_path))):
        if not isinstance(node, ast.Call) or len(node.args) != 2:
            continue
        function = node.func
        if not (isinstance(function, ast.Attribute)
                and function.attr == "getenv"):
            continue
        if isinstance(node.args[0], ast.Constant) \
                and node.args[0].value == name:
            return ast.literal_eval(node.args[1])
    raise AssertionError(f"{name} getenv default not found in {relative_path}")


# ── gps_jamming ─────────────────────────────────────────────────────────

class TestGpsJammingSurgeIsWithheldNotAsserted:
    """The defect that defeats L5, and the convention that replaces it."""

    def _draft(self):
        return gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", url=TILES_URL,
                    label="tiles"), context("gps_jamming"))[0]

    def test_surge_is_absent_rather_than_a_truthy_string(self):
        """`"pending_l1_prev_ratio"` in `surge` is a non-empty string in a
        key the catalog reads as a bool, so the sensor read as firing on
        every tick, forever — which is exactly what a silence detector
        cannot see through."""
        flags = self._draft().flags
        assert "surge" not in flags
        assert flags["surge_verdict"] == "pending_l1_prev_ratio"

    def test_no_flag_value_would_read_as_firing_in_the_bool_catalog(self):
        """`radar/verification/flag_catalog.py:125` registers
        `gps_jamming.surge` as a bool with `non_firing_values = (False,
        None)` (`:84`). Every key the catalog declares for this sensor must
        carry a value that set can classify."""
        catalog = legacy_source("radar/verification/flag_catalog.py")
        assert '_b("gps_jamming", "surge"' in catalog
        assert "_BOOL_OFF = (False, None)" in catalog
        flags = self._draft().flags
        for key in ("is_jammed", "is_critical"):
            assert isinstance(flags[key], bool)
        assert flags.get("surge", False) in (False, None)

    def test_no_pending_marker_is_written_into_a_verdict_field(self):
        """§7-2 #8's convention, pinned in the source rather than in one
        branch: the marker names itself in a sibling key."""
        assert flag_values("v3/adapters/physical/gps_jamming.py",
                           "surge") == set()
        assert flag_values("v3/adapters/physical/gps_jamming.py",
                           "surge_verdict") == {"pending_l1_prev_ratio"}

    def test_surge_is_never_asserted_false_either(self):
        """`False` would be a verdict — "no surge" — reached from a
        baseline this layer does not hold. Absent means "not stated"."""
        source = (FIXTURES.parent.parent.parent
                  / "v3/adapters/physical/gps_jamming.py").read_text()
        assert '"surge": False' not in source


class TestGpsJammingNoDataAndNormalAreNotSwapped:

    def test_a_country_with_coordinates_and_no_tiles_is_normal(self):
        """`radar/sensors/gps_jamming.py:170-224`: zero nearby tiles falls
        through the ordinary arithmetic to `country_status = "NORMAL"`.
        The port reported NO_DATA for it."""
        drafts = gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", url=TILES_URL,
                    label="tiles"),
            context("gps_jamming", countries=("JP",),
                    country_coordinates={"JP": (35.68, 139.7)}))
        assert drafts[0].status == STATUS_OK
        assert drafts[0].flags["status"] == "NORMAL"
        assert drafts[0].flags["total_tiles"] == 0
        assert drafts[0].value == "max=0.0 avg=0.0 [NORMAL]"

    def test_a_country_without_coordinates_is_no_data_and_still_emitted(self):
        """`:152-156` is the ONLY place production sets NO_DATA, and it
        still records the entry. The port emitted nothing at all, so a
        country the sensor is blind to disappeared from the output."""
        drafts = gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", url=TILES_URL,
                    label="tiles"),
            context("gps_jamming", countries=("TW", "KP"),
                    country_coordinates={"TW": (25.03, 121.5)}))
        by_country = {draft.country: draft for draft in drafts}
        assert set(by_country) == {"TW", "KP"}
        assert by_country["KP"].status == STATUS_NO_DATA
        assert by_country["KP"].flags["status"] == "NO_DATA"
        assert by_country["KP"].raw_score == 0.0

    def test_production_sets_no_data_only_where_coordinates_are_missing(self):
        """Two sites, and neither is "measured, nothing nearby": the
        no-coordinates branch and the whole-fetch exception handler. The
        second has no `normalize` counterpart — a failed fetch never
        reaches L0 at all."""
        source = legacy_source("radar/sensors/gps_jamming.py")
        assert source.count('country_status[code] = "NO_DATA"') == 2
        assert 'if not coord:' in source
        assert 'country_status[code] = "NORMAL"' in source


class TestGpsJammingFiredReasonAndDate:

    def _draft(self):
        return gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", url=TILES_URL,
                    label="tiles"), context("gps_jamming"))[0]

    def test_the_fired_reason_matches_the_scoring_call(self):
        """`radar/routes/core.py:1811-1814`. The port left `reason` empty,
        so the sentence the analyst reads next to the verdict was gone."""
        draft = self._draft()
        assert draft.status == STATUS_FIRED
        assert draft.reason.startswith("GPS jamming: CRITICAL_JAMMING (max=")
        assert "avg=" in draft.reason
        assert "GPS jamming: " in legacy_source("radar/routes/core.py")

    def test_a_quiet_country_carries_no_reason(self):
        drafts = gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", url=TILES_URL,
                    label="tiles"),
            context("gps_jamming", countries=("JP",),
                    country_coordinates={"JP": (35.68, 139.7)}))
        assert drafts[0].reason == ""

    def test_the_product_day_is_recovered_from_the_url(self):
        """The legacy entry carries `"date"` (`:216`). `normalize` has no
        manifest and no clock, but the day is in the URL it was given."""
        assert self._draft().flags["date"] == "2026-08-06"
        assert gps_jamming.tiles_date("https://x/2026-01-02-h3_4.csv") \
            == "2026-01-02"
        assert gps_jamming.tiles_date("https://x/manifest.csv") == ""


class TestGpsJammingMalformedRowsAreDropped:

    def _draft(self, name: str):
        return gps_jamming.normalize(
            payload("gps_jamming", name, url=TILES_URL, label="tiles"),
            context("gps_jamming"))[0]

    def test_a_row_with_an_unreadable_count_is_discarded(self):
        """`radar/sensors/gps_jamming.py:98-105` wraps the row in
        `try ... except (KeyError, ValueError): continue`. Coercing the
        count to 0 instead keeps a tile with `bad=0`, which dilutes
        `jam_ratio` and lowers the reading."""
        flags = self._draft("tiles-malformed.csv").flags
        assert flags["total_tiles"] == 2
        assert flags["total_aircraft"] == 142     # 123 + 19, not 182

    def test_production_skips_the_row_rather_than_defaulting_it(self):
        source = legacy_source("radar/sensors/gps_jamming.py")
        assert "except (KeyError, ValueError):" in source


class TestGpsJammingThresholdsStillMatchTheRepairedProduction:

    def test_the_ratio_scale_defaults_are_productions(self):
        """DP7's repair is registered as RESOLVED; this keeps the two
        numbers tied together so the registration stays true."""
        assert gps_jamming.JAM_THRESHOLD.value == float(getenv_default(
            "radar/sensors/gps_jamming.py", "GPS_JAM_THRESHOLD"))
        assert gps_jamming.JAM_CRITICAL_THRESHOLD.value == float(
            getenv_default("radar/sensors/gps_jamming.py",
                           "GPS_JAM_CRITICAL_THRESHOLD"))

    def test_the_signal_source_is_the_sensor_name(self):
        draft = gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", url=TILES_URL,
                    label="tiles"), context("gps_jamming"))[0]
        assert draft.signal_source == "gps_jamming"


# ── ais_maritime ────────────────────────────────────────────────────────

def ais_context(**overrides) -> NormalizeContext:
    base = {"adapter_id": AdapterId("ais_maritime"), "now": T0,
            "countries": ("TW",), "chokepoints": (BASHI,)}
    base.update(overrides)
    return NormalizeContext(**base)


class TestAisMalformedVesselsAreDiscarded:
    """The worst direction this adapter has: a parse failure that scores."""

    def test_a_broken_record_does_not_become_a_stationary_warship(self):
        """Coerced, `SHIPTYPE "N/A"` becomes 0 — outside the commercial
        band, therefore suspicious — and `SOG ""` becomes 0.0, therefore
        stationary. `radar/sensors/ais_maritime.py:100-107` discards the
        record instead."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat_malformed.json",
                    label=BASHI_LABEL), ais_context())[0]
        assert draft.status == STATUS_OK
        assert draft.raw_score == 0.0
        assert draft.flags["stationary_anomalies"] == []
        assert draft.flags["vessels_examined"] == 1   # only the cargo hull

    def test_the_helper_returns_none_for_each_unreadable_field(self):
        assert ais_maritime.vessel_fields({"SHIPTYPE": "N/A"}, T0) is None
        assert ais_maritime.vessel_fields({"SOG": "fast"}, T0) is None
        assert ais_maritime.vessel_fields({"LATITUDE": [1.0]}, T0) is None
        assert ais_maritime.vessel_fields({"TIME": "yesterday"}, T0) is None

    def test_a_falsy_field_still_takes_the_legacy_default(self):
        """`vessel.get("SOG", 0) or 0` — production coerces `None`, `""`
        and `[]` to 0 BEFORE converting, so those are not the malformed
        case and must not start being discarded."""
        assert ais_maritime.vessel_fields(
            {"SHIPTYPE": None, "SOG": "", "LATITUDE": [],
             "LONGITUDE": 0}, T0) == (0, 0.0, 0.0, 0.0, T0)

    def test_production_discards_rather_than_defaults(self):
        source = legacy_source("radar/sensors/ais_maritime.py")
        assert "except (ValueError, TypeError):" in source
        assert "# Malformed vessel record — skip" in source


class TestAisVesselTimeIsCarried:

    def test_the_report_timestamp_reaches_the_output(self):
        """`last_ts` (`radar/sensors/ais_maritime.py:105`) is the only
        input to dark-gap detection (`:113-116`). Dropped, the L1 vessel
        history has nothing to store and dark gaps stay uncomputable."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat_malformed.json",
                    label=BASHI_LABEL), ais_context())[0]
        # `dist_km` joined it in WP-4.1b: the dark-gap rule is
        # `gap > 1h AND dist < 50km` and the fold that applies it has no
        # chokepoint centre to recompute the distance from.
        assert draft.flags["vessel_reports"] == [
            {"mmsi": "477000111", "last_ts": 1699996400.0,
             "lat": 22.1, "lng": 121.2, "dist_km": 30.3}]

    def test_a_missing_time_falls_back_to_the_fetch_instant(self):
        """`float(vessel.get("TIME", now) or now)` — `context.now` IS the
        fetch instant, so this stays a pure function of its arguments."""
        assert ais_maritime.vessel_fields({"SHIPTYPE": 70}, T0)[4] == T0

    def test_production_reads_time_and_stores_it_as_history(self):
        source = legacy_source("radar/sensors/ais_maritime.py")
        assert 'float(vessel.get("TIME", now) or now)' in source
        assert '"last_ts": last_ts' in source


class TestAisChokepointCountry:

    def test_the_country_comes_from_the_chokepoint_not_the_scope(self):
        """`geo_data.json` gives every CHOKEPOINTS entry a `country`, and
        `core.py:1250-1253` joins a dark gap to a country through
        `cp["name"]`. The port used `context.countries[0] if len == 1`, so
        the moment two countries were in scope every chokepoint
        observation landed on GLOBAL."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat.json", label=BASHI_LABEL),
            ais_context(countries=("TW", "CN")))[0]
        assert draft.country == "TW"

    def test_an_unknown_chokepoint_does_not_borrow_a_country(self):
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat.json",
                    label="cp=Unlisted Strait;lat=21.9;lon=121.0"),
            ais_context())[0]
        assert draft.country == ""

    def test_production_joins_by_chokepoint_name(self):
        assert 'cp["name"] == g.get("chokepoint")' in \
            legacy_source("radar/routes/core.py")


class TestAisUnknownCentreIsNotAnAnomaly:

    def test_a_missing_centre_reports_no_data_rather_than_firing(self):
        """`distance_km = 0.0` is "directly on top of the chokepoint", and
        `0.0 < ANCHOR_RADIUS_KM` is true for every vessel — so a label
        without coordinates turned every hull in the box into a stationary
        anomaly. Production cannot reach the case: `cp["lat"] / cp["lng"]`
        are read straight off the CHOKEPOINTS row (`:50`)."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat.json",
                    label="cp=Unlisted Strait"), ais_context())[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.raw_score == 0.0
        assert draft.flags["stationary_anomalies"] == []
        assert draft.value == "chokepoint centre unknown"

    def test_the_centre_falls_back_to_the_chokepoint_row(self):
        """A label that lost its coordinates is still measurable when the
        context carries the row — NO_DATA is the last resort, not the
        first."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat.json",
                    label="cp=Bashi Channel"), ais_context())[0]
        assert draft.status == STATUS_FIRED
        assert draft.flags["stationary_anomalies"][0]["ship_type"] == 35

    def test_distance_is_never_defaulted_to_zero(self):
        """Pinned in the shape rather than the behaviour: the fail-open was
        a conditional expression with a `0.0` fallback, so no assignment to
        `distance_km` may be one."""
        tree = ast.parse((FIXTURES.parent.parent.parent
                          / "v3/adapters/physical/ais_maritime.py"
                          ).read_text(encoding="utf-8"))
        assignments = [node for node in ast.walk(tree)
                       if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name)
                               and target.id == "distance_km"
                               for target in node.targets)]
        assert assignments
        assert not any(isinstance(node.value, ast.IfExp)
                       for node in assignments)


class TestAisFiredReasonAndPreservedDefect:

    def test_the_fired_reason_matches_the_scoring_call(self):
        """`radar/routes/core.py:1257`."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat.json", label=BASHI_LABEL),
            ais_context())[0]
        assert draft.reason == \
            "AIS Dark Gap / Stationary Anomaly at chokepoint"
        assert draft.reason in legacy_source("radar/routes/core.py")

    def test_a_quiet_chokepoint_carries_no_reason(self):
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat_malformed.json",
                    label=BASHI_LABEL), ais_context())[0]
        assert draft.reason == ""

    def test_the_aishub_envelope_defect_is_still_preserved(self):
        """§3-5 H-2, ruling open. Nothing fixed here may accidentally make
        this sensor capable of firing on the real AISHub shape — that is a
        sensitivity change with no production basis, and it belongs in the
        LIVE system first."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels.json", label=BASHI_LABEL),
            ais_context())[0]
        assert draft.flags["vessels_examined"] == 0
        assert draft.status == STATUS_OK

    def test_the_dark_gap_verdict_is_still_withheld(self):
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat.json", label=BASHI_LABEL),
            ais_context())[0]
        assert draft.flags["dark_gap_detection"] == \
            "pending_l1_vessel_history"
        assert draft.value.startswith("dark_gaps=0 ")


# ── openweather ─────────────────────────────────────────────────────────

class TestOpenweatherSignalSourceAndGeometry:

    def _draft(self, name="weather_tw.json", label="weather:TW", **kwargs):
        return openweather.normalize(
            payload("openweather", name, label=label),
            context("openweather", **kwargs))[0]

    def test_the_signal_source_is_the_sensor_name(self):
        """Production's effective value is `rat.signal_source or
        rat.sensor` (`radar/scoring.py:81`) and `core.py:1125` passes no
        explicit kwarg. `"weather"` was invented by the port and breaks
        both the L1 uniqueness key and WP-2.8's parity join."""
        assert self._draft().signal_source == "openweather"
        assert 'add_rat("openweather"' in legacy_source("radar/routes/core.py")

    def test_the_queried_point_reaches_the_output(self):
        """`radar/sensors/openweather.py:38` stores `lat`/`lng` in the
        entry; the map overlay reads them. Dropped, the weather layer
        renders empty and an airspace drop loses its visible
        explanation."""
        flags = self._draft().flags
        assert (flags["lat"], flags["lng"]) == (25.03, 121.5)
        assert '"lat": coord["lat"]' in \
            legacy_source("radar/sensors/openweather.py")

    def test_the_body_coordinates_are_the_fallback(self):
        flags = self._draft("weather_calm.json", label="weather:JP",
                            countries=("JP",)).flags
        assert (flags["lat"], flags["lng"]) == (35.68, 139.7)

    def test_the_reading_is_filed_under_the_country_that_was_queried(self):
        """Production keys `conditions` by the `strategic_theaters` code
        whose `COUNTRY_COORDS` row built the query; it never reads
        `sys.country`. On a border coordinate the body answers with the
        neighbour."""
        draft = openweather.normalize(
            payload("openweather", "weather_border.json",
                    label="weather:TW"), context("openweather"))[0]
        assert draft.country == "TW"
        assert draft.value == "TW: SEVERE"


class TestOpenweatherModerateIsIndependentOfSevere:

    def test_a_severe_rain_band_is_also_moderate(self):
        """`radar/sensors/openweather.py:36-37` computes the two
        predicates separately, and 502 satisfies both. Deriving
        `is_moderate` from the ladder turned "at least moderate" into
        "exactly moderate"."""
        flags = openweather.normalize(
            payload("openweather", "weather_tw.json", label="weather:TW"),
            context("openweather"))[0].flags
        assert flags["severity"] == "SEVERE"
        assert flags["is_severe"] is True
        assert flags["is_moderate"] is True

    def test_production_computes_them_independently(self):
        source = legacy_source("radar/sensors/openweather.py")
        assert "is_severe = wid in SEVERE_WEATHER_IDS or wind > 25" in source
        assert ("is_moderate = (500 <= wid < 600) or (300 <= wid < 400) "
                "or wind > 15") in source

    @pytest.mark.parametrize("weather_id,wind,severe,moderate", [
        (502, 5.0, True, True), (800, 30.0, True, True),
        (520, 5.0, False, True), (301, 2.0, False, True),
        (800, 20.0, False, True), (800, 3.0, False, False)])
    def test_the_two_predicates(self, weather_id, wind, severe, moderate):
        assert openweather.is_severe_weather(weather_id, wind) is severe
        assert openweather.is_moderate_weather(weather_id, wind) is moderate


class TestOpenweatherSuppressionSemanticsAreUntouched:

    def test_the_key_is_still_a_query_parameter(self):
        """Already repaired and pinned in
        `tests/test_adapters_request_fidelity.py`; re-asserted here so a
        change to this module cannot quietly undo it."""
        auth = openweather.OPENWEATHER_ADAPTER.auth
        assert auth.placement == AUTH_IN_QUERY and auth.name == "appid"
        assert all(name != "appid" for name, _ in
                   openweather.OPENWEATHER_ADAPTER.requests[0].params)

    def test_it_annotates_without_suppressing_itself(self):
        draft = openweather.normalize(
            payload("openweather", "weather_tw.json", label="weather:TW"),
            context("openweather"))[0]
        assert draft.status == STATUS_OK and draft.raw_score == 0.0
        assert draft.suppressed is False
        assert draft.suppress_reason == "Active noise filter"
        assert draft.reason == ""

    def test_a_body_that_is_not_a_mapping_produces_nothing(self):
        empty = FetchedPayload(
            url="https://api.openweathermap.org/data/2.5/weather",
            status=200, body=b"[]", fetched_at=T0, label="weather:TW")
        assert openweather.normalize(
            empty, context("openweather")) == ()
