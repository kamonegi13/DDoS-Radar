"""WP-2.6 — the fifteen physical adapters, against recorded payloads.

Every test here runs `normalize` on a fixture and asserts values. No test
touches the network: the fixtures ARE the upstream, and the barrier guard
in test_adapters_catalog.py proves that stays true at execution time.

Fixture provenance: shapes are taken from what the current sensors
actually parse (field names, array positions, nesting) and from the S1
clauses that describe them, with values chosen to sit on the interesting
side of each threshold.
"""
import ast
import json
from pathlib import Path

import pytest

from tests.test_adapters_cyber import (dict_containing, legacy_source,
                                       literal_in)

from v3.adapters.physical import (ais_maritime, check_host, gps_jamming,
                                  ihr_health, ioda_bgp, nasa_eonet, notam,
                                  opensky, openweather, peeringdb_ixp,
                                  ripe_atlas, space_weather, usgs_seismic)
from v3.adapters.types import (AdapterId, FetchedPayload, NormalizeContext,
                               STATUS_FIRED, STATUS_NO_DATA, STATUS_OBSERVED,
                               STATUS_OK, STATUS_SUPPRESSED)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adapters"
T0 = 1_700_000_000.0

TAIWAN = {"TW": (25.03, 121.5)}
CHOKEPOINTS = (("Bashi Channel", 21.9, 121.0, "TW"),)

#: One expanded ISR zone label, as the composition root will produce it.
#: The name and coordinates are `geo_data.json`'s first TW hotspot; they
#: are in the LABEL because four bounding-box numbers do not say which
#: named zone they are, and `core.py:2931` joins the map overlay on
#: exactly that name.
ISR_ZONE_LABEL = ("isr;zone=Taiwan Strait Median Line;lat=24.5;lng=119.5"
                  ";cc=TW")
MIL_ZONE_LABEL = ("mil_air;zone=Taiwan Strait Median Line;lat=24.5;lng=119.5"
                  ";cc=TW")


def payload(adapter: str, name: str, *, url="https://upstream.test/x",
            label="", status=200) -> FetchedPayload:
    body = (FIXTURES / adapter / name).read_bytes()
    return FetchedPayload(url=url, status=status, body=body, fetched_at=T0,
                          content_type="application/json", label=label)


def context(adapter_id: str, **overrides) -> NormalizeContext:
    base = {"adapter_id": AdapterId(adapter_id), "now": T0,
            "countries": ("TW",), "country_coordinates": TAIWAN}
    base.update(overrides)
    return NormalizeContext(**base)


def draft_signal_sources(relative_path: str) -> set:
    """Every `signal_source=` literal an adapter module can emit.

    Read with `ast` rather than by calling `normalize`, because a branch
    the fixtures never reach still writes a row into the ledger in
    production — and the ledger key is what this pins.
    """
    tree = ast.parse((REPO_ROOT / relative_path).read_text(encoding="utf-8"))
    sources = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = (node.func.id if isinstance(node.func, ast.Name)
                  else getattr(node.func, "attr", ""))
        if called != "ObservationDraft":
            continue
        for keyword in node.keywords:
            if keyword.arg != "signal_source":
                continue
            assert isinstance(keyword.value, ast.Constant), (
                f"{relative_path} computes a signal_source; the ledger key "
                f"must be readable without running the adapter")
            sources.add(keyword.value.value)
    return sources


def _add_rat_calls() -> list:
    """Every `add_rat(...)` in the scoring block.

    Returns `(sensor, explicit_signal_source)` pairs, where the second is
    the literal passed as `signal_source=` or None when the call omits it.
    Legacy's effective source is `rat.signal_source or rat.sensor`
    (`radar/scoring.py:81`), so both halves are needed to know what a row
    actually dedups under.

    `sensor` is None when the first argument is not a literal: the LLM
    intel path passes `_llm_entry["sensor"]` (`core.py:1925-1933`), and a
    helper that skipped those calls would also skip the explicit
    `signal_source="llm_intel"` they carry — which is half the premise
    that the OTHER calls dedup under their sensor name.
    """
    tree = ast.parse(legacy_source("radar/routes/core.py"))
    calls = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "id", "") == "add_rat" and node.args):
            continue
        sensor = node.args[0]
        override = None
        for keyword in node.keywords:
            if keyword.arg == "signal_source" and \
                    isinstance(keyword.value, ast.Constant):
                override = keyword.value.value
        calls.append((sensor.value if isinstance(sensor, ast.Constant)
                      else None, override))
    return calls


def getenv_default(relative_path: str, key: str) -> str:
    """The default string an `os.getenv(key, default)` call ships with.

    `radar/config.py` builds several ledgers by splitting a getenv
    default, so the value is a literal inside a call rather than a named
    constant — `literal_in` cannot see it, and copying it into the test
    would defeat the point of comparing against the live source.
    """
    for node in ast.walk(ast.parse(legacy_source(relative_path))):
        if not (isinstance(node, ast.Call)
                and getattr(node.func, "attr", "") == "getenv"
                and len(node.args) == 2):
            continue
        name, default = node.args
        if isinstance(name, ast.Constant) and name.value == key \
                and isinstance(default, ast.Constant):
            return default.value
    raise AssertionError(
        f"no os.getenv({key!r}, <literal>) in {relative_path}")


# ── opensky family (K01) ────────────────────────────────────────────────

class TestOpensky:
    def test_the_aircraft_count_is_reported_not_judged(self):
        """S1-SENS-023: the sensor carries no status flag; CLOSURE is
        decided against an hour-of-day baseline that is L1's."""
        drafts = opensky.normalize_opensky(
            payload("opensky", "states_all.json", label="airports:TW"),
            context("opensky"))
        assert len(drafts) == 1
        assert drafts[0].status == STATUS_OBSERVED
        assert drafts[0].flags["aircraft_count"] == 3
        assert drafts[0].raw_score == 0.0

    def test_the_dependency_on_the_airspace_baseline_is_declared(self):
        """Declared twice on purpose: in `baseline_refs`, where the
        registry can see it, and as the `pending_l1_*` marker every other
        OBSERVED adapter carries, where the analyst reading the row can.
        The withheld verdict is score 2 (ANOMALY) or 3 (CLOSURE),
        `core.py:1112-1113`."""
        assert opensky.OPENSKY_ADAPTER.baseline_refs == ("airspace_hod",)
        draft = opensky.normalize_opensky(
            payload("opensky", "states_all.json", label="airports:TW"),
            context("opensky"))[0]
        assert draft.flags["airspace_verdict"] == "pending_l1_airspace_hod"
        assert draft.raw_score == 0.0

    def test_a_payload_with_no_country_yields_nothing(self):
        drafts = opensky.normalize_opensky(
            payload("opensky", "states_all.json"),
            context("opensky", countries=("TW", "JP")))
        assert drafts == ()

    def test_a_null_states_array_counts_as_zero_aircraft(self):
        """`res.json().get("states") or []` (`opensky.py:26`): a JSON object
        with no states IS a measurement, and its answer is zero."""
        drafts = opensky.normalize_opensky(
            payload("opensky", "states_empty.json", label="airports:TW"),
            context("opensky"))
        assert drafts[0].status == STATUS_OBSERVED
        assert drafts[0].flags["aircraft_count"] == 0

    def test_an_unreadable_body_is_not_an_airspace_closure(self):
        """S1-SENS-023, the worst failure direction this adapter has.

        A 502 error page parses to no states. Counting that as ZERO
        aircraft over the principal airport is, against any established
        hour-of-day baseline, a 100% drop — CLOSURE, score 3, the highest
        this family emits. Legacy refuses: the count becomes -1
        (`opensky.py:35`), `_compute_airspace_status` sets ERROR and
        `continue`s before touching the baseline (`core.py:317-319`), and
        the scoring block sees neither CLOSURE nor ANOMALY (`core.py:1113`).
        """
        draft = opensky.normalize_opensky(
            payload("opensky", "gateway_error.html", label="airports:TW"),
            context("opensky"))[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.status != STATUS_FIRED
        assert draft.raw_score == 0.0
        assert draft.flags["aircraft_count"] == \
            opensky.UNMEASURED_AIRCRAFT_COUNT == -1

    def test_a_json_array_body_is_also_unmeasured(self):
        """`res.json().get(...)` on a list raises AttributeError, which
        legacy catches into the same `count: -1` (`opensky.py:34-35`)."""
        draft = opensky.normalize_opensky(
            FetchedPayload(url="https://x.test", status=200, body=b"[1,2,3]",
                           fetched_at=T0, label="airports:TW"),
            context("opensky"))[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.flags["aircraft_count"] == -1

    def test_the_minus_one_sentinel_and_its_reader_are_both_live(self):
        """Pinned at BOTH ends, because the sentinel only works if the
        reader still tests for it: a later edit that made
        `_compute_airspace_status` treat a negative count as a real
        reading would restore the fabricated alarm without touching this
        adapter."""
        sensor = legacy_source("radar/sensors/opensky.py")
        assert '"count": -1' in sensor
        scoring = legacy_source("radar/routes/core.py")
        assert "count = ainfo.get(\"count\", -1)" in scoring
        assert "if count < 0:" in scoring
        assert 'ainfo["status"] = "ERROR"' in scoring


class TestIsrHotspot:
    def _drafts(self):
        return opensky.normalize_isr_hotspot(
            payload("isr_hotspot", "states_isr.json", label=ISR_ZONE_LABEL),
            context("isr_hotspot"))

    def test_high_and_slow_squawk_and_callsign_all_count(self):
        """S1-SENS-024's three ORed conditions, one aircraft each in the
        fixture, plus one airliner and one on the ground."""
        flags = self._drafts()[0].flags
        assert flags["count"] == 3
        assert {track["callsign"] for track in flags["tracks"]} == {
            "FORTE10", "UNKNOWN1", "HIGHSLOW"}

    def test_a_surge_of_three_fires_and_scores_two(self):
        draft = self._drafts()[0]
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 2.0

    def test_ground_traffic_is_excluded_before_anything_else(self):
        flags = self._drafts()[0].flags
        assert "PARKED" not in {t["callsign"] for t in flags["tracks"]}

    def test_a_missing_velocity_defaults_to_999_so_it_cannot_look_slow(self):
        """The asymmetric defaults fail towards NOT claiming a track."""
        state = ["abc", "TEST123", "", 0, 0, 121.0, 25.0, 12000.0, False,
                 None, 0, 0, None, 0, None, False, 0]
        assert opensky._is_isr(state) is False

    def test_the_track_record_keys_are_the_legacy_ones_in_order(self):
        """`isr_hotspot.py:75-84`. The port kept `icao24`/`callsign`/
        `lat`/`lon` and dropped `alt_m`, `vel_ms`, `heading` and `squawk`
        — the four an analyst reads to tell an ISR orbit from an airliner
        in the per-aircraft readout the map draws from
        `hotspots[].tracks` (`core.py:2929-2933`)."""
        live = dict_containing("radar/sensors/isr_hotspot.py", "icao24")
        assert list(live) == ["icao24", "callsign", "lat", "lon", "alt_m",
                              "vel_ms", "heading", "squawk"]
        track = next(t for t in self._drafts()[0].flags["tracks"]
                     if t["callsign"] == "UNKNOWN1")
        assert list(track) == list(live)
        assert track["squawk"] == "7777"
        assert track["alt_m"] == 10000.0
        assert track["vel_ms"] == 120.0
        assert track["heading"] == 90.0

    def test_the_surge_carries_the_legacy_sentence(self):
        """`core.py:1226`. The port emitted the verdict with no reason."""
        assert "ISR surge: {isr_count} aircraft" in \
            legacy_source("radar/routes/core.py")
        assert self._drafts()[0].reason == "ISR surge: 3 aircraft"

    def test_the_zone_record_is_the_legacy_one_and_names_the_zone(self):
        """`isr_hotspot.py:87-93`, key for key.

        The port emitted no `hotspots` array at all. `core.py:2931` joins
        the map overlay's per-aircraft `tracks` on `h["name"] ==
        hs["name"]`, so an absent record — or one with an empty name —
        matches no zone and every ISR overlay renders with no aircraft
        and no error. `core.py:1231`'s ISR_SURGE sequence-event payload
        carries the same array whole.
        """
        live = dict_containing("radar/sensors/isr_hotspot.py", "isr_count")
        assert list(live) == ["name", "lat", "lng", "isr_count", "tracks"]
        assert 'h["name"] == hs["name"]' in \
            legacy_source("radar/routes/core.py")

        hotspots = self._drafts()[0].flags["hotspots"]
        assert len(hotspots) == 1              # one payload, one zone
        assert list(hotspots[0]) == list(live)
        assert hotspots[0]["name"] == "Taiwan Strait Median Line"
        assert (hotspots[0]["lat"], hotspots[0]["lng"]) == (24.5, 119.5)
        assert hotspots[0]["isr_count"] == 3
        assert hotspots[0]["tracks"] == self._drafts()[0].flags["tracks"]

    def test_the_zone_travels_in_the_label_because_the_box_cannot_say_it(
            self):
        """`FetchedPayload.url` is the base URL with no query string
        (`v3/fetch/client.py:332`) and `NormalizeContext` has a
        `chokepoints` field but no ISR equivalent, so the label is the
        only carrier the zone identity has."""
        spec = opensky.ISR_HOTSPOT_ADAPTER.requests[0]
        assert spec.label == ("isr;zone={zone};lat={lat};lng={lng}"
                              ";cc={country}")
        assert opensky.MIL_SUPPORT_AIR_ADAPTER.requests[0].label == (
            "mil_air;zone={zone};lat={lat};lng={lng};cc={country}")
        # The airport request keeps its shape: AIRPORT_BOXES is one box
        # per country, so there is no zone to name.
        assert opensky.OPENSKY_ADAPTER.requests[0].label == \
            "airports:{country}"

    def test_a_failed_zone_contributes_no_record_rather_than_a_zero(self):
        """`isr_hotspot.py:96-100` never appends a failed box. A record
        claiming `isr_count: 0` would sum into the country total as a
        real zero, which is a surge that does not reach the threshold."""
        draft = opensky.normalize_isr_hotspot(
            payload("opensky", "gateway_error.html", label=ISR_ZONE_LABEL),
            context("isr_hotspot"))[0]
        assert draft.flags["hotspots"] == []

    def test_an_unreadable_body_measures_nothing_rather_than_nothing_seen(
            self):
        """OK/0 here would assert "no ISR aircraft over this zone" from a
        body nobody could parse. Legacy's equivalent is structural — a
        failed box never reaches `results[theater]`
        (`isr_hotspot.py:96-100`) — and there is no cache at L0 to fall
        back on, so the honest answer is NO_DATA."""
        draft = opensky.normalize_isr_hotspot(
            payload("opensky", "gateway_error.html", label=ISR_ZONE_LABEL),
            context("isr_hotspot"))[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.raw_score == 0.0
        assert draft.flags["is_surge"] is False
        assert draft.flags["count"] == opensky.UNMEASURED_AIRCRAFT_COUNT


class TestMilSupportAir:
    def _draft(self):
        return opensky.normalize_mil_support_air(
            payload("mil_support_air", "states_mil.json",
                    label=MIL_ZONE_LABEL),
            context("mil_support_air"))[0]

    def _flags(self):
        return self._draft().flags

    def test_the_three_categories_are_counted_separately(self):
        flags = self._flags()
        assert (flags["tanker"], flags["transport"], flags["awacs"]) == (2, 1, 1)

    def test_awacs_plus_a_tanker_surge_scores_two(self):
        draft = self._draft()
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 2.0

    def test_classification_order_is_tanker_then_transport_then_awacs(self):
        """Shared prefixes make the order load-bearing: RFF78 is a tanker
        and RFF76 a transport, and both start with RFF."""
        assert opensky.classify_support("RFF78ABC") == "TANKER"
        assert opensky.classify_support("RFF76ABC") == "TRANSPORT"
        assert opensky.classify_support("RFF50ABC") == "AWACS"
        assert opensky.classify_support("CAL123") == ""

    def test_the_generic_callsign_prefixes_are_preserved_not_cleaned(self):
        """A12: NAF / RAF / SAM / CARGO are ordinary words. Removing them
        would be an unregistered reduction in sensitivity."""
        for generic in ("NAF", "RAF", "GAF"):
            assert generic in opensky.TANKER_PREFIXES
        for generic in ("SAM", "CARGO"):
            assert generic in opensky.TRANSPORT_PREFIXES

    def test_the_track_record_keys_are_the_legacy_ones_in_order(self):
        """`mil_support_air.py:118-126`. Note the key set is NOT the ISR
        sensor's: `category` sits third and there is no heading or
        squawk."""
        live = dict_containing("radar/sensors/mil_support_air.py", "category")
        assert list(live) == ["icao24", "callsign", "category", "lat", "lon",
                              "alt_m", "vel_ms"]
        track = self._flags()["tracks"][0]
        assert list(track) == list(live)
        assert (track["callsign"], track["category"]) == ("TEXAC51", "TANKER")
        assert (track["alt_m"], track["vel_ms"]) == (9000.0, 220.0)

    def test_a_missing_velocity_reads_zero_here_and_999_in_the_isr_sensor(
            self):
        """`mil_support_air.py:105` vs `isr_hotspot.py:53`. The defaults
        differ on purpose: only the ISR rule asks whether an aircraft is
        SLOW, so only it needs an absent velocity to fail that test."""
        state = ["abc", "TEXAC99", "", 0, 0, 121.0, 25.0, 9000.0, False,
                 None, 90.0, 0, None, 0, None, False, 0]
        zone = {"name": "Z", "lat": 24.5, "lng": 119.5}
        assert opensky._mil_track(state, "TANKER", zone)["vel_ms"] == 0.0
        assert opensky._isr_track(state, zone)["vel_ms"] == 999.0

    def test_an_unlocated_aircraft_falls_back_to_the_zone_centre(self):
        """`mil_support_air.py:122-123` / `isr_hotspot.py:78-79`: an
        absent position reads as the box centre — the aircraft IS in the
        box that was queried. The port defaulted to 0.0, which puts it in
        the Gulf of Guinea."""
        state = ["abc", "TEXAC99", "", 0, 0, None, None, 9000.0, False,
                 200.0, 90.0, 0, None, 0, None, False, 0]
        zone = {"name": "Z", "lat": 24.5, "lng": 119.5}
        assert (opensky._mil_track(state, "TANKER", zone)["lat"],
                opensky._mil_track(state, "TANKER", zone)["lon"]) == \
            (24.5, 119.5)
        assert opensky._isr_track(state, zone)["lat"] == 24.5

    def test_the_reason_lists_the_firing_clauses_in_the_legacy_order(self):
        """`core.py:1768-1776`. Which clauses appear IS the finding —
        "tanker surge (2), AWACS active (1)" is the sortie shape that
        scores 2 — and the port emitted no reason at all."""
        source = legacy_source("radar/routes/core.py")
        for clause in ('f"tanker surge ({_mil_tanker})"',
                       'f"transport surge ({_mil_transport})"',
                       'f"AWACS active ({_mil_awacs})"'):
            assert clause in source
        draft = self._draft()
        assert draft.reason == \
            "Military support aircraft: tanker surge (2), AWACS active (1)"

    def test_no_surge_carries_no_reason(self):
        assert opensky.support_reason(0, 0, 0, False, False, False) == ""

    def test_the_zone_record_is_the_legacy_one_and_is_not_the_isr_one(self):
        """`mil_support_air.py:136-140`. Same first three keys, then the
        per-category counts instead of `isr_count` — two different
        records, and a shared builder would have quietly merged them."""
        # Located by `tracks`, not by `awacs`: the per-theater accumulator
        # default at `:128-131` also carries `awacs`, and matching that
        # would have compared against the wrong dict.
        live = dict_containing("radar/sensors/mil_support_air.py", "tracks")
        assert list(live) == ["name", "lat", "lng", "tanker", "transport",
                              "awacs", "tracks"]
        hotspots = self._flags()["hotspots"]
        assert len(hotspots) == 1
        assert list(hotspots[0]) == list(live)
        assert hotspots[0]["name"] == "Taiwan Strait Median Line"
        assert (hotspots[0]["lat"], hotspots[0]["lng"]) == (24.5, 119.5)
        assert (hotspots[0]["tanker"], hotspots[0]["transport"],
                hotspots[0]["awacs"]) == (2, 1, 1)

    def test_the_sequence_event_payload_carries_no_zone_array(self):
        """`core.py:1782` — MIL_AIR_SURGE is `{tanker, transport, awacs}`
        only, unlike ISR_SURGE at `:1231`. The zone array still has to
        exist for the map overlay; it just does not travel in this
        event."""
        source = legacy_source("radar/routes/core.py")
        assert ('{"tanker": _mil_tanker, "transport": _mil_transport, '
                '"awacs": _mil_awacs}') in source

    def test_an_unreadable_body_measures_nothing(self):
        draft = opensky.normalize_mil_support_air(
            payload("opensky", "gateway_error.html", label=MIL_ZONE_LABEL),
            context("mil_support_air"))[0]
        assert draft.status == STATUS_NO_DATA
        assert draft.raw_score == 0.0
        assert draft.flags["is_surge"] is False
        assert draft.flags["total"] == opensky.UNMEASURED_AIRCRAFT_COUNT


# ── ais_maritime (K02) ──────────────────────────────────────────────────

class TestAisMaritime:
    LABEL = "cp=Bashi Channel;lat=21.9;lon=121.0"

    def test_the_nested_aishub_envelope_yields_no_vessels(self):
        """DEFECT PRESERVED, and reported.

        AISHub answers `[header, [vessel, ...]]`. The legacy slice takes
        everything after the header and then skips non-dicts, so the
        single element — the vessel ARRAY — is skipped and no vessel is
        ever examined. Same family as DP7: a sensor that cannot fire,
        whose silence reads as calm. Changing it here would be an
        unregistered sensitivity change (P2 §5-C), so it is pinned
        instead and raised for a ruling: **design sheet §3-5 H-2**, owner
        ruling open. If this test ever starts failing, the ruling has been
        made somewhere other than the design sheet.
        """
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels.json", label=self.LABEL),
            context("ais_maritime"))[0]
        assert draft.flags["vessels_examined"] == 0
        assert draft.status == STATUS_OK

    def test_a_flat_envelope_does_detect_a_stationary_warship(self):
        """The rule itself is correct — it is the envelope handling that
        never reaches it."""
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels_flat.json", label=self.LABEL),
            context("ais_maritime"))[0]
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 1.0
        assert draft.flags["stationary_anomalies"][0]["ship_type"] == 35

    def test_a_commercial_hull_under_way_is_not_an_anomaly(self):
        assert ais_maritime._is_stationary_anomaly(70, 12.4, 5.0) is False

    def test_a_military_hull_at_anchor_inside_the_radius_is(self):
        assert ais_maritime._is_stationary_anomaly(35, 0.2, 5.0) is True

    def test_distance_beyond_the_anchor_radius_is_not(self):
        assert ais_maritime._is_stationary_anomaly(35, 0.2, 500.0) is False

    def test_dark_gap_detection_declares_its_missing_history(self):
        draft = ais_maritime.normalize(
            payload("ais_maritime", "vessels.json", label=self.LABEL),
            context("ais_maritime"))[0]
        assert draft.flags["dark_gap_detection"] == "pending_l1_vessel_history"
        assert "ais_vessel_history" in \
            ais_maritime.AIS_MARITIME_ADAPTER.baseline_refs


# ── gps_jamming (K12, DP7) ──────────────────────────────────────────────

class TestGpsJamming:
    def _draft(self):
        drafts = gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", label="tiles"),
            context("gps_jamming"))
        return drafts[0]

    def test_the_thresholds_are_ratios_and_refuse_percent_values(self):
        """DP7's repair, in the type. `Ratio(3.0)` cannot be built, so the
        defect cannot be re-introduced by editing a number."""
        from v3.kernel import Ratio
        from v3.kernel.errors import DomainError
        assert gps_jamming.JAM_THRESHOLD.value == 0.03
        assert gps_jamming.JAM_CRITICAL_THRESHOLD.value == 0.07
        with pytest.raises(DomainError):
            Ratio(3.0)

    def test_the_sensor_can_actually_fire_at_its_default_thresholds(self):
        """GAP-S4 demanded exactly this test: the boundary case proving a
        sensor is capable of firing as configured."""
        draft = self._draft()
        assert draft.status == STATUS_FIRED
        assert draft.flags["is_critical"] is True
        assert draft.raw_score == 2.0

    def test_tiles_outside_the_search_box_are_not_counted(self):
        assert self._draft().flags["total_tiles"] == 3

    def test_the_manifest_payload_produces_no_observations(self):
        drafts = gps_jamming.normalize(
            payload("gps_jamming", "manifest.csv", label="manifest"),
            context("gps_jamming"))
        assert drafts == ()

    def test_a_country_without_coordinates_reports_no_data_not_calm(self):
        """Production sets NO_DATA in exactly one MEASURED case:
        `COUNTRY_COORDS.get(code)` is empty, so the tile grid could not be
        searched at all (`radar/sensors/gps_jamming.py:152-156`). A country
        WITH coordinates and zero nearby tiles falls through the ordinary
        arithmetic and is labelled NORMAL (`:170-224`). The port had the
        two the wrong way round, which reports a blind spot as an
        all-clear and an all-clear as a blind spot."""
        drafts = gps_jamming.normalize(
            payload("gps_jamming", "tiles-h3_4.csv", label="tiles"),
            context("gps_jamming", countries=("TW", "KP")))
        by_country = {draft.country: draft for draft in drafts}
        assert by_country["KP"].status == STATUS_NO_DATA
        assert by_country["TW"].status == STATUS_FIRED


# ── nasa_eonet (DP6 rename) ─────────────────────────────────────────────

class TestNasaEonet:
    def test_a_fire_inside_the_country_box_fires_and_scores_three(self):
        drafts = nasa_eonet.normalize(
            payload("nasa_eonet", "events.json", label="events"),
            context("nasa_eonet"))
        assert drafts[0].status == STATUS_FIRED
        assert drafts[0].raw_score == 3.0

    def test_coordinates_are_read_as_lon_lat(self):
        """EONET's order. Reading it the other way puts every event in the
        wrong hemisphere."""
        drafts = nasa_eonet.normalize(
            payload("nasa_eonet", "events.json", label="events"),
            context("nasa_eonet"))
        anomaly = drafts[0].flags["anomalies"][0]
        assert (round(anomaly["lat"], 1), round(anomaly["lng"], 1)) == \
            (24.0, 121.6)

    def test_a_distant_fire_does_not_count(self):
        drafts = nasa_eonet.normalize(
            payload("nasa_eonet", "events.json", label="events"),
            context("nasa_eonet"))
        assert drafts[0].flags["count"] == 1

    def test_small_countries_get_a_tighter_search_radius(self):
        assert nasa_eonet.RADIUS_DEG_BY_COUNTRY["TW"] == 2.0
        assert nasa_eonet.RADIUS_DEG_DEFAULT == 3.0

    def test_the_identifier_names_the_real_source(self):
        """DP6/NP6: the old name pointed an analyst at a source that
        produced none of the conclusion."""
        assert nasa_eonet.NASA_EONET.value == "nasa_eonet"
        assert nasa_eonet.LEGACY_ADAPTER_ID == "nasa_firms"
        assert "eonet.gsfc.nasa.gov" in \
            nasa_eonet.NASA_EONET_ADAPTER.requests[0].url

    def _global_only(self, countries, coordinates):
        return {draft.country: draft.value for draft in nasa_eonet.normalize(
            payload("nasa_eonet", "events.json", label="events"),
            context("nasa_eonet", countries=countries,
                    country_coordinates=coordinates))}

    def test_a_quiet_country_says_where_the_feed_did_see_fires(self):
        """`core.py:1186-1191` has THREE values, not two. "No Anomalies"
        and "Global only [AU]" are different statements about the same
        local zero: the second says the feed was alive and looking
        elsewhere, which is what tells an analyst a quiet reading is a
        reading. The port collapsed both into "No Anomalies"."""
        values = self._global_only(
            ("TW", "JP"), {**TAIWAN, "JP": (35.6, 139.7)})
        assert values["TW"] == "Thermal Anomaly [TW]"
        assert values["JP"] == "Global only [TW]"

    def test_with_no_fire_anywhere_the_value_is_no_anomalies(self):
        values = self._global_only(("JP",), {"JP": (35.6, 139.7)})
        assert values["JP"] == "No Anomalies"

    def test_the_global_code_list_is_sorted_and_stops_at_four(self):
        """`sorted({...})[:4]`, `core.py:1183,1189`. Five burning
        countries name four; the fifth is the one that would have made the
        string unbounded."""
        events = {"events": [
            {"id": f"E{n}", "title": "Wildfire",
             "geometry": [{"coordinates": [lon, lat]}]}
            for n, (lat, lon) in enumerate(
                [(25.0, 121.5), (35.6, 139.7), (37.5, 126.9),
                 (14.5, 121.0), (-33.8, 151.2)])]}
        coordinates = {"TW": (25.03, 121.5), "JP": (35.6, 139.7),
                       "KR": (37.5, 126.9), "PH": (14.5, 121.0),
                       "AU": (-33.8, 151.2), "SG": (1.35, 103.8)}
        drafts = nasa_eonet.normalize(
            FetchedPayload(url="https://eonet.test", status=200,
                           body=json.dumps(events).encode(), fetched_at=T0,
                           label="events"),
            context("nasa_eonet", countries=tuple(coordinates),
                    country_coordinates=coordinates))
        quiet = next(d for d in drafts if d.country == "SG")
        assert quiet.value == "Global only [AU,JP,KR,PH]"
        assert nasa_eonet.GLOBAL_CODES_SHOWN == 4

    def test_the_anomaly_list_is_not_truncated(self):
        """`nasa_firms.py:85` appends without a limit and `core.py:1183`
        reads the whole list. The port held a `[:10]` with no counterpart
        in production — a silent truncation of detections."""
        events = {"events": [
            {"id": f"E{n}", "title": f"Wildfire {n}",
             "geometry": [{"coordinates": [121.5 + n * 0.01, 25.0]}]}
            for n in range(14)]}
        draft = nasa_eonet.normalize(
            FetchedPayload(url="https://eonet.test", status=200,
                           body=json.dumps(events).encode(), fetched_at=T0,
                           label="events"),
            context("nasa_eonet"))[0]
        assert draft.flags["count"] == 14
        assert len(draft.flags["anomalies"]) == 14
        # The list leaves the sensor whole and the scoring block reads it
        # whole. `nasa_firms.py` does hold one `[:10]`, on the event
        # SIGNATURE (`:59`) — a different list, for a cache-skip hash.
        assert '{"anomalies": anomalies}' in \
            legacy_source("radar/sensors/nasa_firms.py")
        assert 'for f in nasa_firms_data' in legacy_source(
            "radar/routes/core.py")

    def test_the_fired_reason_is_the_legacy_sentence(self):
        """`core.py:1185` passes it positionally on BOTH branches, and
        `add_rat` stores `fired_reason` regardless of status
        (`core.py:973-975`), so the OK row carries it too."""
        assert '"Kinetic Strike Precursor"' in \
            legacy_source("radar/routes/core.py")
        drafts = nasa_eonet.normalize(
            payload("nasa_eonet", "events.json", label="events"),
            context("nasa_eonet"))
        assert drafts[0].reason == nasa_eonet.FIRED_REASON == \
            "Kinetic Strike Precursor"

    def test_the_legacy_id_is_the_catalogs_rename_key_not_a_second_copy(self):
        """The constant had no consumer, and its docstring described a
        ledger alias that no code performs. Its one real consumer is the
        catalog's design-sheet rename map, which is wired to it rather
        than repeating the string — one place for the fact, and a rename
        that goes unresolved now fails a test."""
        from v3.adapters import catalog
        assert catalog.DESIGN_SHEET_RENAMES[nasa_eonet.LEGACY_ADAPTER_ID] == \
            nasa_eonet.NASA_EONET.value
        assert nasa_eonet.LEGACY_ADAPTER_ID in \
            dict(catalog.WP26_DESIGN_SHEET_ROWS).values()


# ── openweather (suppressor) ────────────────────────────────────────────

class TestOpenweather:
    def test_heavy_rain_is_severe_and_annotates_without_suppressing(self):
        draft = openweather.normalize(
            payload("openweather", "weather_tw.json", label="weather:TW"),
            context("openweather"))[0]
        assert draft.status == STATUS_OK
        assert draft.raw_score == 0.0
        assert draft.suppressed is False        # reason without the flag
        assert draft.suppress_reason == "Active noise filter"

    def test_a_clear_sky_carries_no_reason(self):
        draft = openweather.normalize(
            payload("openweather", "weather_calm.json",
                    label="weather:JP"),
            context("openweather", countries=("JP",)))[0]
        assert draft.suppress_reason is None
        assert draft.flags["severity"] == "NORMAL"

    @pytest.mark.parametrize("weather_id,wind,expected", [
        (502, 5.0, "SEVERE"), (800, 30.0, "SEVERE"), (520, 5.0, "MODERATE"),
        (301, 2.0, "MODERATE"), (800, 20.0, "MODERATE"), (800, 3.0, "NORMAL")])
    def test_the_severity_ladder(self, weather_id, wind, expected):
        assert openweather.severity_of(weather_id, wind) == expected


# ── usgs_seismic (K16) ──────────────────────────────────────────────────

class TestUsgsSeismic:
    def _draft(self, adversaries=("KP",), coordinates=None):
        return usgs_seismic.normalize(
            payload("usgs_seismic", "quakes.json", label="quakes"),
            context("usgs_seismic", adversaries=adversaries,
                    chokepoints=CHOKEPOINTS,
                    country_coordinates=coordinates or {
                        **TAIWAN, "KP": (40.3, 127.5)}))[0]

    def test_a_shallow_magnitude_five_in_hostile_territory_fires(self):
        draft = self._draft()
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 3.0
        assert draft.flags["candidate_countries"] == ["KP"]

    def test_detection_beats_cable_suppression(self):
        """A nuclear candidate anywhere cancels the cable explanation —
        an explanation must not hide the event it explains away."""
        draft = self._draft()
        assert draft.flags["has_cable_threat"] is True
        assert draft.suppressed is False

    def test_without_a_candidate_the_cable_event_suppresses(self):
        draft = self._draft(adversaries=())
        assert draft.status == STATUS_SUPPRESSED
        assert draft.suppressed is True
        assert "Bashi Channel" in draft.suppress_reason
        assert draft.raw_score == 0.0

    def test_a_deep_quake_is_not_a_test_candidate(self):
        draft = self._draft(adversaries=("PH",),
                            coordinates={**TAIWAN, "PH": (21.0, 121.0)})
        assert draft.flags["has_nuclear_candidate"] is False

    def test_the_observation_is_global_rather_than_per_country(self):
        assert self._draft().country == ""

    def test_the_quake_record_keys_are_the_legacy_ones_in_order(self):
        """`usgs_seismic.py:101-110`. The port dropped `type` and
        `tsunami` and added an `id` legacy never stores. `type` is the
        field that separates an `explosion` from an `earthquake`, which
        is the distinction K16 exists to make."""
        live = dict_containing("radar/sensors/usgs_seismic.py", "tsunami")
        assert list(live) == ["mag", "place", "time", "lat", "lon",
                              "depth_km", "type", "tsunami"]
        record = self._draft().flags["earthquakes"][0]
        assert list(record) == list(live)
        assert record["type"] == "earthquake" and record["tsunami"] == 0

    def test_the_near_cable_entry_is_nested_and_keeps_the_distance(self):
        """`usgs_seismic.py:117-121`. The port flattened the record and
        dropped `distance_km` — the only field that says HOW near "near a
        cable" was, which is what an analyst needs to judge whether the
        explanation is credible."""
        live = dict_containing("radar/sensors/usgs_seismic.py", "distance_km")
        assert list(live) == ["earthquake", "chokepoint", "distance_km"]
        entry = self._draft().flags["near_cable"][0]
        assert list(entry) == list(live)
        assert entry["chokepoint"] == "Bashi Channel"
        assert entry["earthquake"]["place"] == "Luzon Strait"
        assert 0 < entry["distance_km"] <= usgs_seismic.CABLE_RADIUS_KM
        assert round(entry["distance_km"], 1) == entry["distance_km"]

    def test_the_nuclear_verdict_carries_the_legacy_sentence(self):
        """`core.py:1738-1740`. The candidate COUNT is the finding; the
        port emitted the score with no sentence attached to it."""
        source = legacy_source("radar/routes/core.py")
        assert "USGS: Possible underground nuclear test signature" in source
        assert self._draft().reason == (
            "USGS: Possible underground nuclear test signature "
            "(1 candidates)")

    def test_a_suppression_carries_no_nuclear_sentence(self):
        assert self._draft(adversaries=()).reason == ""

    def test_the_three_list_caps_are_the_legacy_three(self):
        """`usgs_seismic.py:146-148`: events 20, near-cable 10, candidates
        uncapped. Three different numbers, none of them interchangeable."""
        source = legacy_source("radar/sensors/usgs_seismic.py")
        assert f'earthquakes[:{usgs_seismic.EVENT_LIST_CAP}]' in source
        assert f'near_cable[:{usgs_seismic.NEAR_CABLE_LIST_CAP}]' in source
        assert '"nuclear_candidates": nuclear_candidates,' in source
        assert (usgs_seismic.EVENT_LIST_CAP,
                usgs_seismic.NEAR_CABLE_LIST_CAP) == (20, 10)

    def test_the_query_parameters_are_the_legacy_ones_in_order(self):
        """`usgs_seismic.py:63-69`. Name, value AND order."""
        live = dict_containing("radar/sensors/usgs_seismic.py", "minmagnitude")
        spec = usgs_seismic.USGS_SEISMIC_ADAPTER.requests[0]
        assert [name for name, _ in spec.params] == list(live)
        assert dict(spec.params)["format"] == live["format"] == "geojson"
        assert dict(spec.params)["orderby"] == live["orderby"] == "time"
        assert dict(spec.params)["limit"] == str(live["limit"]) == "100"
        assert dict(spec.params)["minmagnitude"] == "4.0"
        assert usgs_seismic.MIN_MAGNITUDE == float(getenv_default(
            "radar/config.py", "USGS_MIN_MAGNITUDE"))
        assert usgs_seismic.CABLE_RADIUS_KM == float(getenv_default(
            "radar/config.py", "USGS_CABLE_RADIUS_KM"))


# ── space_weather (K17, fail-closed) ────────────────────────────────────

class TestSpaceWeather:
    def test_an_observed_kp_of_six_suppresses(self):
        draft = space_weather.normalize(
            payload("space_weather", "kp.json", label="kp"),
            context("space_weather"))[0]
        assert draft.status == STATUS_SUPPRESSED
        assert draft.flags["kp_index"] == pytest.approx(6.33)

    def test_the_forecast_does_not_trigger_suppression_on_its_own(self):
        """Only the observed index suppresses: discarding real signal on
        the strength of a prediction is not a trade this tool makes."""
        draft = space_weather.normalize(
            payload("space_weather", "kp.json", label="kp"),
            context("space_weather"))[0]
        assert draft.flags["kp_forecast_24h"] == pytest.approx(7.0)
        assert draft.flags["storm_level"] == "STRONG"

    def test_an_m_class_flare_suppresses(self):
        draft = space_weather.normalize(
            payload("space_weather", "xray.json", label="xray"),
            context("space_weather"))[0]
        assert draft.flags["xray_class"] == "M"
        assert draft.suppressed is True

    def test_a_missing_endpoint_produces_no_observation_at_all(self):
        """A15's repair (§7-2 expected difference #2): fail-CLOSED.

        The legacy sensor recorded Kp=0.0 and class A when both endpoints
        failed — the readings of a quiet sun — and stayed healthy. Here
        an endpoint that produced nothing contributes nothing; there is
        no code path that invents a reading.
        """
        empty = FetchedPayload(url="https://x.test", status=200, body=b"",
                               fetched_at=T0, label="kp")
        assert space_weather.normalize(empty, context("space_weather")) == ()

    @pytest.mark.parametrize("flux,expected", [
        (2e-4, "X"), (2.4e-5, "M"), (3e-6, "C"), (5e-7, "B"), (1e-9, "A")])
    def test_the_xray_class_ladder(self, flux, expected):
        assert space_weather.xray_class(flux) == expected

    def test_the_storm_ladder_is_the_legacy_one(self):
        """`space_weather.py:31-43`, and it reads the HIGHER of observed
        and forecast — unlike the suppression, which reads observed
        alone."""
        for kp, level in ((9, "EXTREME"), (8, "SEVERE"), (7, "STRONG"),
                          (6, "MODERATE"), (5, "MINOR"), (4.9, "NONE")):
            assert space_weather.storm_level(kp) == level
        assert space_weather.KP_SUPPRESS_THRESHOLD == float(getenv_default(
            "radar/config.py", "SPACE_WEATHER_KP_SUPPRESS_THRESHOLD"))
        assert space_weather.XRAY_SUPPRESS_CLASS == getenv_default(
            "radar/config.py", "SPACE_WEATHER_XRAY_SUPPRESS_CLASS") == "M"

    def test_both_endpoints_emit_the_one_production_signal_source(self):
        """RULING R1: `core.py:1404` is a single `add_rat("space_weather",
        ...)` with no explicit kwarg, so both halves of the split dedup
        under that one name.

        REPORTED, NOT RESOLVED: the fail-closed split (§7-2 #2) means one
        adapter now emits TWO drafts per tick sharing
        `(signal_source, country)` — and the ledger key is
        `UNIQUE (tick_id, sensor, signal_source, country)`. Their
        `observed_at` differ (two fetch instants) so `_require_same_tick`
        raises DomainError rather than dropping one. Renaming them apart
        would break the R1 join key, so the choice belongs to the lead.
        """
        kp = space_weather.normalize(
            payload("space_weather", "kp.json", label="kp"),
            context("space_weather"))[0]
        xray = space_weather.normalize(
            payload("space_weather", "xray.json", label="xray"),
            context("space_weather"))[0]
        assert kp.signal_source == xray.signal_source == "space_weather"
        assert kp.country == xray.country == ""
        assert kp.flags["endpoint"] != xray.flags["endpoint"]


# ── peeringdb_ixp (finalised scoring rule) ──────────────────────────────

class TestPeeringdbIxp:
    def test_it_is_an_inventory_and_never_fires(self):
        """S1-SENS-035's consumer emits OK/0 unconditionally
        (core.py:1193). The WP-2.5 exemplar guessed FIRED-on-zero, which
        would have fired forever for every country PeeringDB lacks."""
        drafts = peeringdb_ixp.normalize(
            payload("peeringdb_ixp", "ix.json", label="ix"),
            context("peeringdb_ixp", countries=()))
        assert {draft.status for draft in drafts} == {STATUS_OK}
        assert {draft.raw_score for draft in drafts} == {0.0}

    def test_one_observation_per_country_with_its_count(self):
        drafts = peeringdb_ixp.normalize(
            payload("peeringdb_ixp", "ix.json", label="ix"),
            context("peeringdb_ixp", countries=()))
        counts = {draft.country: draft.flags["count"] for draft in drafts}
        assert counts == {"HK": 1, "JP": 2, "TW": 1}

    def test_the_courtesy_delay_is_declared_not_slept(self):
        adapter = peeringdb_ixp.PEERINGDB_IXP_ADAPTER
        assert adapter.min_interval_sec == 10.0
        assert adapter.rate_limit_group == "peeringdb"


# ── ihr_health and notam: ported disabled ───────────────────────────────

class TestDisabledAdapters:
    def test_ihr_is_disabled_with_both_reasons_recorded(self):
        adapter = ihr_health.IHR_HEALTH_ADAPTER
        assert adapter.enabled is False
        assert "400" in adapter.disabled_reason
        assert "dedup" in adapter.disabled_reason or \
            "S1-SCORE-008" in adapter.disabled_reason

    def test_the_ihr_mirror_host_is_kept(self):
        """K06: `ihr.iijlab.net` 301s, and behind a proxy that second hop
        times out."""
        assert ihr_health.IHR_API_BASE.startswith("https://www.ihr.live")
        assert all("iijlab" not in spec.url
                   for spec in ihr_health.IHR_HEALTH_ADAPTER.requests)

    def test_ihr_still_normalizes_its_recorded_payload(self):
        draft = ihr_health.normalize(
            payload("ihr_health", "disco_events.json", label="disco"),
            context("ihr_health"))[0]
        assert draft.country == "TW"
        assert draft.signal_source == "bgp"      # dedups with ripe/ioda
        assert draft.raw_score == 2.0            # avglevel 12.5 > 5

    def test_notam_is_disabled_and_says_why_in_terms_of_the_world(self):
        adapter = notam.NOTAM_ADAPTER
        assert adapter.enabled is False
        assert "no free international NOTAM API" in adapter.disabled_reason

    def test_the_faa_payload_shape_is_preserved_as_an_asset(self):
        assert notam.FAA_PAYLOAD_SHAPE["radius"] == 100
        assert notam.FAA_PAYLOAD_SHAPE["notamType"] == "N"
        assert notam.FAA_PAYLOAD_SHAPE["pageSize"] == 50

    def test_a_disabled_adapter_emits_nothing(self):
        empty = FetchedPayload(url="https://x.test", status=200, body=b"{}",
                               fetched_at=T0)
        assert notam.normalize(empty, context("notam")) == ()

    def test_the_military_keyword_ledger_is_the_live_fourteen(self):
        """`radar/config.py:498-503`, compared as a SEQUENCE against the
        live default.

        This is the classifier, not a shape: the phrases are the ones that
        actually appear in NOTAM free text ("AIR REFUELING", not
        "REFUELLING"), each is a decision somebody made against real
        notices, and `military >= 3` is one of the three surge conditions
        and the one that separates score 2 from score 1 (`core.py:1636`).
        The port dropped the table entirely, which leaves a disabled
        adapter that cannot be re-enabled without re-deriving it.
        """
        live = tuple(
            keyword.strip().upper()
            for keyword in getenv_default(
                "radar/config.py", "NOTAM_MILITARY_KEYWORDS").split(",")
            if keyword.strip())
        assert notam.NOTAM_MILITARY_KEYWORDS == live
        assert len(live) == 14

    def test_the_tfr_pair_is_a_second_ledger_not_a_subset(self):
        """`notam.py:142` tests two phrases of its own, and "TFR" is in
        BOTH ledgers — it counts towards `military` AND towards `tfr`.
        The port kept neither list."""
        assert '"TFR" in text_upper or "FLIGHT RESTRICTION" in text_upper' \
            in legacy_source("radar/sensors/notam.py")
        assert notam.NOTAM_TFR_KEYWORDS == ("TFR", "FLIGHT RESTRICTION")
        assert "TFR" in notam.NOTAM_MILITARY_KEYWORDS

    def test_the_surge_rule_constants_are_the_live_ones(self):
        """`notam.py:158-160` and `core.py:1636`."""
        assert notam.SURGE_THRESHOLD == int(getenv_default(
            "radar/config.py", "NOTAM_SURGE_THRESHOLD")) == 20
        source = legacy_source("radar/sensors/notam.py")
        assert (f"mil_count >= {notam.MILITARY_COUNT_THRESHOLD}") in source
        assert (f"surge_pct > {notam.SURGE_PCT_THRESHOLD} and "
                f"total_count > {notam.SURGE_PCT_MIN_TOTAL}") in source
        assert f"text[:{notam.NOTAM_TEXT_EXCERPT_CHARS}]" in source
        assert f"notams[:{notam.RECENT_NOTAM_CAP}]" in source


# ── ioda_bgp (K19) ──────────────────────────────────────────────────────

class TestIodaBgp:
    def _drafts(self, name="alerts.json", label="ioda"):
        return ioda_bgp.normalize(
            payload("ioda_bgp", name, label=label),
            context("ioda_bgp", countries=("TW", "PH")))

    def test_recovery_is_reflected_because_only_the_newest_alert_counts(self):
        """GAP-S7's test. IODA publishes `level="normal"` when an outage
        ends; keeping every alert keeps the stale `critical` forever."""
        by_country = {draft.country: draft for draft in self._drafts()}
        assert by_country["TW"].status == STATUS_OK
        assert by_country["TW"].flags["level"] == "normal"

    def test_a_warning_level_fires_and_scores_one(self):
        by_country = {draft.country: draft for draft in self._drafts()}
        assert by_country["PH"].status == STATUS_FIRED
        assert by_country["PH"].raw_score == 1.0

    def test_the_signal_source_is_shared_with_the_other_bgp_sensors(self):
        """S1-SCORE-008 dedups by MAX within a source, so one event seen
        by IODA, RIPE and IHR counts once."""
        assert {draft.signal_source for draft in self._drafts()} == {"bgp"}

    def test_the_cloudflare_fallback_omits_the_datasource_fields(self):
        """The fallback genuinely lacks them; an empty dict would let a
        reader take "0 corroborating sources" for a measurement."""
        drafts = self._drafts("cf_traffic_anomalies.json", "cf_fallback")
        assert drafts[0].country == "PH"
        assert drafts[0].flags == {"source": "cf_fallback"}


# ── check_host (K03) ────────────────────────────────────────────────────

class TestCheckHost:
    def _summary(self, name="check_result.json"):
        return check_host.summarise_nodes(
            json.loads((FIXTURES / "check_host" / name).read_text()))

    def test_pending_nodes_are_excluded_from_the_denominator(self):
        """K03/GAP-S2. Two nodes are pending (one null list, one null
        element); counting them as failures manufactures blackouts."""
        summary = self._summary()
        # `ok_nodes` / `total_nodes` are production's names for the two
        # counts (`radar/sensors/checkhost.py:159-160`), and `radar.js:1167`
        # renders `${r.ok_nodes}/${r.total_nodes}` behind an `!== undefined`
        # guard — a renamed field shows an empty string, not an error.
        assert summary["total_nodes"] == 3
        assert summary["pending"] == 2
        assert summary["success_rate"] == pytest.approx(2 / 3, abs=1e-3)

    def test_success_needs_ok_flag_and_a_sub_400_status(self):
        assert check_host.summarise_nodes(
            {"a.node": [[1, 0.5, "Found", "302", "1.2.3.4"]],
             "b.node": [[1, 0.5, "Bad Gateway", "502", "1.2.3.4"]]}
        )["ok_nodes"] == 1

    def test_a_single_responding_check_is_not_evidence(self):
        assert check_host.summarise_nodes(
            {"a.node": [[1, 0.5, "Found", "302", ""]]})["success_rate"] is None

    def test_everything_pending_yields_no_data_rather_than_a_blackout(self):
        draft = check_host.normalize(
            payload("check_host", "check_result_pending.json",
                    label="result"),
            context("check_host"))[0]
        assert draft.status == STATUS_NO_DATA

    def test_latency_never_lowers_the_success_rate(self):
        """K03: intercontinental checks exceed 3000 ms when healthy."""
        slow = check_host.summarise_nodes(
            {"a.node": [[1, 9.0, "Found", "302", ""]],
             "b.node": [[1, 8.0, "Found", "302", ""]]})
        assert slow["success_rate"] == 1.0
        assert set(slow["node_ok"].values()) == {"TIMEOUT"}

    def test_asphyxiation_needs_a_baseline_and_says_so_without_one(self):
        assert check_host.is_asphyxiation(1.0, 9000.0, None) is False
        assert check_host.is_asphyxiation(1.0, 9000.0, 1000.0) is True
        assert check_host.is_asphyxiation(0.5, 9000.0, 1000.0) is False

    def test_the_country_verdict_declares_its_baseline(self):
        draft = check_host.normalize(
            payload("check_host", "check_result.json", label="result"),
            context("check_host"))[0]
        assert draft.status == STATUS_OBSERVED
        assert "checkhost_hod" in check_host.CHECK_HOST_ADAPTER.baseline_refs

    def test_the_request_stage_produces_no_observation(self):
        assert check_host.normalize(
            payload("check_host", "check_http_request.json", label="request"),
            context("check_host")) == ()


# ── ripe_atlas ──────────────────────────────────────────────────────────

class TestRipeAtlas:
    def test_the_probe_count_is_reported_with_its_missing_baseline(self):
        draft = ripe_atlas.normalize(
            payload("ripe_atlas", "probes_count.json", label="probes",
                    url="https://atlas.ripe.net/api/v2/probes/?country_code=TW"),
            context("ripe_atlas"))[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.flags["active"] == 412
        # The marker lives in its OWN key: production carries `drop_pct` as
        # `round(drop_pct, 3)`, a float (`radar/sensors/ripe_atlas.py:62`),
        # and a non-empty string there reads as a truthy number to every
        # consumer. §7-2 #8's `untrusted_ca_verdict` set the convention.
        assert "drop_pct" not in draft.flags
        assert draft.flags["probe_drop_verdict"] == \
            "pending_l1_prev_probe_count"

    def test_rtts_pool_probe_averages_and_individual_results(self):
        draft = ripe_atlas.normalize(
            payload("ripe_atlas", "measurement_latest.json", label="latency",
                    url="https://atlas.ripe.net/api/v2/measurements/1001/"
                        "latest/?probe_cc=TW"),
            context("ripe_atlas"))[0]
        # 32.5, 30.1, 34.9, 120.4, 118.0 — the -1 is a lost packet.
        assert draft.flags["probes_responding"] == 5

    def test_the_sample_count_is_named_so_it_is_not_read_as_probes(self):
        assert ripe_atlas.collect_rtts(
            [{"avg": 10.0, "result": [{"rt": 11.0}, {"rt": 12.0}]}]) == \
            [10.0, 11.0, 12.0]

    def test_the_p95_index_is_clipped_to_the_last_sample(self):
        assert ripe_atlas.percentile_95([1.0, 2.0]) == 2.0
        assert ripe_atlas.percentile_95([]) == 0.0

    def test_the_first_observation_of_a_country_reports_no_drop(self):
        assert ripe_atlas.drop_pct(None, 412) == 0.0
        assert ripe_atlas.drop_pct(0, 412) == 0.0

    @pytest.mark.parametrize("previous,active,expected", [
        (400, 100, "PROBE_BLACKOUT"), (400, 250, "PROBE_DROP"),
        (400, 390, "NORMAL")])
    def test_the_drop_ladder(self, previous, active, expected):
        assert ripe_atlas.status_for(
            ripe_atlas.drop_pct(previous, active)) == expected


# ── signal_source is the ledger key, not a label (RULING R1) ────────────

#: v3 `signal_source` -> the `add_rat(...)` sensor it must dedup with.
#:
#: Legacy's effective source is `rat.signal_source or rat.sensor`
#: (`radar/scoring.py:81`), and only `"bgp"` and `"llm_intel"` are ever
#: passed as an explicit kwarg — so for every adapter below the effective
#: value is the `add_rat` FIRST ARGUMENT. `nasa_eonet` is the one
#: exception and it is a registered rename (§7-2 #5), not a free choice.
#:
#: The names invented during the port ("airspace", "thermal_anomaly",
#: "seismic") were not cosmetic: `UNIQUE (tick_id, sensor, signal_source,
#: country)` (`v3/ledger/schema.py:157`) makes this column half of the
#: ledger's dedup identity, and it is WP-2.8's parity join key.
SIGNAL_SOURCE_TO_ADD_RAT = {
    "v3/adapters/physical/opensky.py": {
        "opensky": "opensky",                       # core.py:1119
        "isr_hotspot": "isr_hotspot",               # core.py:1223
        "mil_support_air": "mil_support_air"},      # core.py:1776
    "v3/adapters/physical/nasa_eonet.py": {
        "nasa_eonet": "nasa_firms"},                # core.py:1185, §7-2 #5
    "v3/adapters/physical/usgs_seismic.py": {
        "usgs_seismic": "usgs_seismic"},            # core.py:1743
    "v3/adapters/physical/space_weather.py": {
        "space_weather": "space_weather"},          # core.py:1404
}


class TestSignalSourceIsTheProductionSensorName:
    @pytest.mark.parametrize("module", sorted(SIGNAL_SOURCE_TO_ADD_RAT))
    def test_every_draft_the_module_can_emit_is_accounted_for(self, module):
        assert draft_signal_sources(module) == \
            set(SIGNAL_SOURCE_TO_ADD_RAT[module])

    @pytest.mark.parametrize("module,source,sensor", [
        (module, source, sensor)
        for module, mapping in sorted(SIGNAL_SOURCE_TO_ADD_RAT.items())
        for source, sensor in sorted(mapping.items())])
    def test_it_names_a_live_add_rat_sensor(self, module, source, sensor):
        calls = _add_rat_calls()
        assert sensor in {name for name, _ in calls}, (
            f"{module} emits signal_source={source!r}, which must dedup "
            f"with add_rat({sensor!r}, ...) — no such call in "
            f"radar/routes/core.py")
        assert all(override is None
                   for name, override in calls if name == sensor), (
            f"add_rat({sensor!r}, ...) now passes an explicit "
            f"signal_source; the effective value is no longer the sensor "
            f"name and this mapping is stale (radar/scoring.py:81)")

    def test_only_bgp_and_llm_intel_are_ever_passed_explicitly(self):
        """The premise the whole mapping rests on. If a third call ever
        passes `signal_source=`, every row above has to be re-derived."""
        assert {override for _, override in _add_rat_calls()
                if override is not None} == {"bgp", "llm_intel"}

    def test_the_eonet_rename_is_registered_rather_than_improvised(self):
        from v3.adapters import catalog
        assert catalog.DESIGN_SHEET_RENAMES["nasa_firms"] == "nasa_eonet"

    def test_one_adapter_never_emits_two_drafts_under_one_source(self):
        """`UNIQUE (tick_id, sensor, signal_source, country)`. Two drafts
        from one adapter, one tick and one country collide: identical
        content is dropped silently, divergent content raises DomainError
        (`v3/ledger/store.py:290`, S5-VERIF-019). The per-payload guard is
        here; the per-TICK guard needs the composition root and is
        reported, not asserted."""
        for normalize, fixture, label, adapter in (
                (opensky.normalize_opensky, "opensky/states_all.json",
                 "airports:TW", "opensky"),
                (opensky.normalize_isr_hotspot, "isr_hotspot/states_isr.json",
                 ISR_ZONE_LABEL, "isr_hotspot"),
                (opensky.normalize_mil_support_air,
                 "mil_support_air/states_mil.json", MIL_ZONE_LABEL,
                 "mil_support_air"),
                (nasa_eonet.normalize, "nasa_eonet/events.json", "events",
                 "nasa_eonet"),
                (usgs_seismic.normalize, "usgs_seismic/quakes.json", "quakes",
                 "usgs_seismic")):
            directory, name = fixture.split("/")
            drafts = normalize(payload(directory, name, label=label),
                               context(adapter, adversaries=("KP",),
                                       chokepoints=CHOKEPOINTS,
                                       country_coordinates={
                                           **TAIWAN, "KP": (40.3, 127.5)}))
            keys = [(draft.signal_source, draft.country) for draft in drafts]
            assert len(keys) == len(set(keys)), adapter


# ── transcription pins, checked against the live source (WP-2.6 sweep) ──
#
# Same rule the apt_intel sweep established: compare against the legacy
# source PARSED AT TEST TIME, never against a value copied into the test.
# A pin that holds the port's own output proves only that nothing changed;
# it cannot notice that the value was wrong when it was written.

class TestPhysicalTranscriptionPins:
    def test_the_aishub_account_is_the_live_one(self):
        """`radar/sensors/ais_maritime.py:57` sends the literal `"guest"`.
        The port declared `"{aishub_username}"` — a placeholder with no
        expander, no `AuthRequirement` naming it, and no counterpart in the
        legacy sensor. K02: AISHub answers a rejected request with HTTP 200
        and an empty body, so it would have read as "no vessels"."""
        live = dict_containing("radar/sensors/ais_maritime.py", "username")
        assert ais_maritime.AISHUB_USERNAME == live["username"] == "guest"
        spec = ais_maritime.AIS_MARITIME_ADAPTER.requests[0]
        assert spec.param_values("username") == ("guest",)
        assert spec.param_values("format")[0] == live["format"] == "1"

    def test_the_chokepoint_box_half_width_is_declared(self):
        """`cp_lat ± 0.5` / `cp_lng ± 0.5` (`ais_maritime.py:59-62`) is the
        search aperture. The port erased it, leaving nothing for the
        composition root to read — and a guess of 3.0, by analogy with the
        two sibling ports that do declare theirs, is ~36x the area."""
        live = dict_containing("radar/sensors/ais_maritime.py", "latmin")
        half = ais_maritime.CHOKEPOINT_BOX_HALF_DEG
        assert half == 0.5
        for name, sign in (("latmin", "-"), ("latmax", "+"),
                           ("lonmin", "-"), ("lonmax", "+")):
            assert live[name].endswith(f"{sign} {half}")

    def test_the_nasa_radius_table_is_the_legacy_sequence(self):
        """Compared as a SEQUENCE: `.get` does not care about order, but a
        ledger silently reordered is a ledger whose next edit lands in the
        wrong row. This is the shape that failed in apt_intel."""
        live = literal_in("radar/sensors/nasa_firms.py", "_THEATER_RADIUS")
        assert list(nasa_eonet.RADIUS_DEG_BY_COUNTRY.items()) == \
            list(live.items())
        assert nasa_eonet.RADIUS_DEG_DEFAULT == literal_in(
            "radar/sensors/nasa_firms.py", "GEO_RADIUS_DEG_DEFAULT")

    def test_the_space_weather_suppress_reasons_use_the_legacy_glyph(self):
        """`space_weather.py:125,127` write U+2265 `≥`. The port wrote
        ASCII `>=`. The string is re-emitted verbatim into
        `noise_filters_applied` (`core.py:1412`) and into
        `deep_analysis.space_weather.suppress_reason` (`core.py:2708`), so
        a one-character difference fails every literal comparison."""
        source = legacy_source("radar/sensors/space_weather.py")
        assert "(≥{SPACE_WEATHER_KP_SUPPRESS_THRESHOLD})" in source
        assert "(≥{SPACE_WEATHER_XRAY_SUPPRESS_CLASS})" in source

        kp = space_weather.normalize(
            payload("space_weather", "kp.json", label="kp"),
            context("space_weather"))[0]
        assert kp.suppressed is True
        assert "(≥6)" in kp.suppress_reason
        assert ">=" not in kp.suppress_reason

        xray = space_weather.normalize(
            payload("space_weather", "xray.json", label="xray"),
            context("space_weather"))[0]
        assert "(≥M)" in xray.suppress_reason
        assert ">=" not in xray.suppress_reason

    def test_the_peeringdb_request_carries_the_legacy_header(self):
        """`peeringdb.py:54`, and again on the 429 retry at `:66`. Nothing
        in the fetch kernel adds a default Accept, so a dropped header is a
        dropped header — the apt_intel one-of-three-headers shape."""
        live = dict_containing("radar/sensors/peeringdb.py", "Accept")
        spec = peeringdb_ixp.PEERINGDB_IXP_ADAPTER.requests[0]
        assert dict(spec.headers) == live == {"Accept": "application/json"}

    def test_the_ixp_inventory_is_not_truncated(self):
        """`peeringdb.py:77` stores the full list and `core.py:2902`
        iterates all of it to build `critical_nodes`. The port held a
        `[:20]` with no counterpart anywhere in production."""
        rows = [{"id": n, "name": f"IX{n}", "city": "Taipei",
                 "country": "TW", "name_long": f"Exchange {n}"}
                for n in range(26)]
        body = json.dumps({"data": rows}).encode()
        draft = peeringdb_ixp.normalize(
            FetchedPayload(url="https://www.peeringdb.com/api/ix?country=TW",
                           status=200, body=body, fetched_at=T0, label="ix"),
            context("peeringdb_ixp"))[0]
        assert draft.flags["count"] == 26
        assert len(draft.flags["ixps"]) == 26

    def test_only_the_ihr_disco_endpoint_asks_for_country_streams(self):
        """`ihr.py:46` sends `streamtype=country` on disco alone; hegemony
        (`:74`) and delay (`:101`) send three parameters. `normalize` reads
        `streamname` through `iso2()`, so without the constraint IHR also
        returns ASN and IXP streams whose `streamname` is numeric — and
        every event is dropped, silently, against a live payload."""
        live = dict_containing("radar/sensors/ihr.py", "streamtype")
        assert live["streamtype"] == "country"
        by_label = {spec.label: spec
                    for spec in ihr_health.IHR_HEALTH_ADAPTER.requests}
        assert by_label["disco"].param_values("streamtype") == ("country",)
        for label in ("hegemony", "network_delay"):
            names = {name for name, _ in by_label[label].params}
            assert "streamtype" not in names
            assert names == {"starttime", "endtime", "format"}

    def test_the_ihr_event_keys_are_the_legacy_stored_ones(self):
        """The source field is `starttime` and the STORED key is `ts`
        (`ihr.py:58-64`) — a key name that reads correct because the
        upstream field is spelled that way. `level` and `avglevel` are a
        pair; the port kept one and dropped the other, which is the
        dropped-`authority` shape."""
        source = legacy_source("radar/sensors/ihr.py")
        stored = ["ts", "endtime", "level", "avglevel", "nbprobes"]
        assert all(f'"{key}":' in source for key in stored)

        rows = [{"streamname": "TW", "starttime": "2026-08-07T00:00",
                 "endtime": "2026-08-07T01:00", "level": 4, "avglevel": 9,
                 "nbprobes": 12} for _ in range(13)]
        body = json.dumps({"results": rows}).encode()
        draft = ihr_health.normalize(
            FetchedPayload(url="https://www.ihr.live/ihr/api/disco/events/",
                           status=200, body=body, fetched_at=T0,
                           label="disco"), context("ihr_health"))[0]
        assert list(draft.flags["events"][0]) == stored
        assert draft.flags["events"][0]["ts"] == "2026-08-07T00:00"
        assert draft.flags["events"][0]["level"] == 4
        # uncapped: `ihr.py:58` appends without a limit
        assert len(draft.flags["events"]) == 13
