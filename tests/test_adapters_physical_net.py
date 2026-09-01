"""WP-2.6 remediation — the four network-observation physical adapters.

`ripe_atlas`, `ihr_health`, `ioda_bgp`, `peeringdb_ixp`. Every pin here
compares against the LIVE production source parsed at test time
(`radar/sensors/*.py`, `radar/routes/core.py`), never against a value
copied into the test: a pin that holds the port's own output proves only
that nothing changed since, and cannot notice that the value was wrong
when it was written.
"""
import ast
import json
from pathlib import Path

import pytest

from tests.test_adapters_cyber import (dict_containing, legacy_source,
                                       literal_in)

from v3.adapters.physical import (ihr_health, ioda_bgp, peeringdb_ixp,
                                  ripe_atlas)
from v3.adapters.types import (AdapterId, FetchedPayload, NormalizeContext,
                               RequestChain, STATUS_FIRED, STATUS_OBSERVED,
                               STATUS_OK)
from v3.fetch.expand import ExpansionInput, ExpansionScope, expand_requests

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adapters"
CORE = "radar/routes/core.py"
PROBES_URL = ("https://atlas.ripe.net/api/v2/probes/?country_code=TW")
T0 = 1_700_000_000.0

TAIWAN = {"TW": (25.03, 121.5)}

MY_MODULES = ("v3/adapters/physical/ripe_atlas.py",
              "v3/adapters/physical/ihr_health.py",
              "v3/adapters/physical/ioda_bgp.py",
              "v3/adapters/physical/peeringdb_ixp.py")


# ── helpers ─────────────────────────────────────────────────────────────

def payload(adapter: str, name: str, *, url="https://upstream.test/x",
            label="", status=200) -> FetchedPayload:
    body = (FIXTURES / adapter / name).read_bytes()
    return FetchedPayload(url=url, status=status, body=body, fetched_at=T0,
                          content_type="application/json", label=label)


def body_payload(document, *, url="https://upstream.test/x",
                 label="") -> FetchedPayload:
    return FetchedPayload(url=url, status=200,
                          body=json.dumps(document).encode(), fetched_at=T0,
                          content_type="application/json", label=label)


def context(adapter_id: str, **overrides) -> NormalizeContext:
    base = {"adapter_id": AdapterId(adapter_id), "now": T0,
            "countries": ("TW",), "country_coordinates": TAIWAN}
    base.update(overrides)
    return NormalizeContext(**base)


def add_rat_calls() -> list:
    """`(sensor, explicit_signal_source)` for every `add_rat` in the block.

    `radar/scoring.py:81` makes the effective source `rat.signal_source or
    rat.sensor`, so the second element decides which of the two names a
    v3 adapter has to carry.
    """
    calls: list = []
    for node in ast.walk(ast.parse(legacy_source(CORE))):
        if not isinstance(node, ast.Call) or \
                getattr(node.func, "id", "") != "add_rat" or not node.args:
            continue
        sensor = node.args[0]
        override = None
        for keyword in node.keywords:
            if keyword.arg == "signal_source" and \
                    isinstance(keyword.value, ast.Constant):
                override = keyword.value.value
        # The LLM entry names its sensor from a dict at run time
        # (core.py:1926); it still declares an override, and the "only two
        # are ever explicit" premise has to see it.
        calls.append((sensor.value if isinstance(sensor, ast.Constant)
                      else None, override))
    return calls


def effective_signal_source(sensor: str) -> str:
    """What production's ledger would record for that `add_rat` sensor.

    Every sensor here has TWO calls — a `DISABLED` one taking the default
    and a live one — so the override is collected across all of them
    rather than from whichever appears first.
    """
    overrides = {override for name, override in add_rat_calls()
                 if name == sensor}
    assert overrides, f"no add_rat({sensor!r}, ...) in {CORE}"
    explicit = {override for override in overrides if override is not None}
    assert len(explicit) <= 1, (
        f"add_rat({sensor!r}, ...) passes conflicting signal_source values "
        f"{sorted(explicit)}; the effective value is no longer derivable")
    return explicit.pop() if explicit else sensor


def draft_signal_sources(relative_path: str) -> set:
    """Every `signal_source=` literal a module can emit, read with `ast`.

    A branch the fixtures never reach still writes a ledger row in
    production, and the ledger key is what this pins.
    """
    sources: set = set()
    tree = ast.parse((REPO_ROOT / relative_path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (
                getattr(node.func, "id", "")
                or getattr(node.func, "attr", "")) == "ObservationDraft":
            for keyword in node.keywords:
                if keyword.arg == "signal_source" and \
                        isinstance(keyword.value, ast.Constant):
                    sources.add(keyword.value.value)
        # `ihr_health` reaches its source through a declared table rather
        # than a literal at the call site; the table is still a literal.
        if isinstance(node, ast.Assign) and any(
                getattr(target, "id", "") == "LABEL_SIGNAL_SOURCE"
                for target in node.targets):
            sources |= set(ast.literal_eval(node.value).values())
    return sources


def ledger_keys(drafts) -> list:
    """`(signal_source, country)` — the UNIQUE-key half an adapter owns."""
    return [(draft.signal_source, draft.country) for draft in drafts]


# ── §1 / RULING R1: signal_source is the ledger key ─────────────────────

class TestSignalSourceMatchesProduction:
    def test_peeringdb_carries_the_add_rat_sensor_name(self):
        """`add_rat("peeringdb_ixp", ...)` (core.py:1193) passes no
        explicit source, so the effective value is the sensor name. The
        port's "ixp" broke both the ledger dedup identity and WP-2.8's
        parity join key."""
        assert draft_signal_sources(
            "v3/adapters/physical/peeringdb_ixp.py") == {"peeringdb_ixp"}
        assert effective_signal_source("peeringdb_ixp") == "peeringdb_ixp"

    def test_ioda_carries_the_explicit_bgp_override(self):
        """The one place a kwarg wins: core.py:1103 passes
        `signal_source="bgp"`, so IODA dedups with RIPE and IHR."""
        assert draft_signal_sources(
            "v3/adapters/physical/ioda_bgp.py") == {"bgp"}
        assert effective_signal_source("ioda_bgp") == "bgp"

    def test_the_ripe_atlas_probe_half_owns_the_production_name(self):
        """Production emits ONE entry, `add_rat("ripe_atlas", ...)`
        (core.py:1547), whose FIRED verdict comes from the probe-drop
        status alone — so the probe half is the parity row."""
        assert effective_signal_source("ripe_atlas") == "ripe_atlas"
        draft = ripe_atlas.normalize(
            payload("ripe_atlas", "probes_count.json", label="probes",
                    url=PROBES_URL),
            context("ripe_atlas"))[0]
        assert draft.signal_source == "ripe_atlas"

    def test_the_ihr_disco_and_delay_halves_take_their_own_add_rat_names(self):
        """`ihr_disco` passes `signal_source="bgp"` (core.py:1515);
        `ihr_delay` passes nothing (core.py:1518), so its effective source
        is its sensor name and nothing dedups it."""
        assert effective_signal_source("ihr_disco") == "bgp"
        assert effective_signal_source("ihr_delay") == "ihr_delay"
        assert ihr_health.LABEL_SIGNAL_SOURCE["disco"] == "bgp"
        assert ihr_health.LABEL_SIGNAL_SOURCE["network_delay"] == "ihr_delay"

    def test_hegemony_has_no_add_rat_so_its_name_is_a_registered_v3_one(self):
        """Production reads hegemony into `country_status` and
        `deep_analysis.ihr.core_hegemony` (core.py:2783) and scores it
        nowhere. The v3 name is the one production gives that cache slice
        (core.py:490); it exists so the three endpoints cannot collide."""
        assert "ihr_hegemony" not in {name for name, _ in add_rat_calls()}
        assert '"ihr_hegemony": _ihr_cache.get("hegemony_alarms"' in \
            legacy_source(CORE)

    def test_only_bgp_and_llm_intel_are_ever_passed_explicitly(self):
        """The premise every row above rests on."""
        assert {override for _, override in add_rat_calls()
                if override is not None} == {"bgp", "llm_intel"}


class TestOneAdapterNeverEmitsTwoDraftsUnderOneKey:
    """`UNIQUE (tick_id, sensor, signal_source, country)` — two
    `OBSERVED`/`0.0` drafts under one key are dropped SILENTLY
    (`v3/ledger/store.py:290`, S5-VERIF-019), so a collision is not a
    crash, it is a lost observation."""

    def test_the_ripe_atlas_probe_and_latency_halves_do_not_collide(self):
        drafts = []
        drafts += ripe_atlas.normalize(
            payload("ripe_atlas", "probes_count.json", label="probes",
                    url=PROBES_URL),
            context("ripe_atlas"))
        for measurement_id in ripe_atlas.MEASUREMENT_IDS:
            drafts += ripe_atlas.normalize(
                payload("ripe_atlas", "measurement_latest.json",
                        label=f"latency_{measurement_id}",
                        url=f"https://atlas.ripe.net/api/v2/measurements/"
                            f"{measurement_id}/latest/?probe_cc=TW"),
                context("ripe_atlas"))
        keys = ledger_keys(drafts)
        assert len(keys) == len(set(keys))
        assert keys == [("ripe_atlas", "TW"), ("atlas_latency_1001", "TW"),
                        ("atlas_latency_1004", "TW"),
                        ("atlas_latency_10509", "TW")]

    def test_the_three_ihr_endpoints_do_not_collide(self):
        drafts = []
        for name, label in (("disco_events.json", "disco"),
                            ("hegemony_alarms.json", "hegemony"),
                            ("delay_alarms.json", "network_delay")):
            drafts += ihr_health.normalize(
                payload("ihr_health", name, label=label),
                context("ihr_health"))
        keys = ledger_keys(drafts)
        assert len(keys) == len(set(keys))
        assert {source for source, _ in keys} == {"bgp", "ihr_hegemony",
                                                  "ihr_delay"}


# ── §2: ripe_atlas ──────────────────────────────────────────────────────

class TestRipeAtlasMeasurementTableIsWired:
    def _steps(self):
        return expand_requests(
            ripe_atlas.RIPE_ATLAS_ADAPTER.requests,
            ExpansionInput(scopes=(ExpansionScope(values={"country": "TW"},
                                                  scope_key="TW"),)))

    def test_the_declaration_expands_to_four_concrete_requests(self):
        """`MEASUREMENT_IDS` was transcribed and never wired: the declared
        URL held `{measurement_id}` and nothing supplied it, so
        `expand_requests` raised and `run_due` skipped the WHOLE adapter as
        `unresolved_placeholder` every cycle — the silent death that took
        `check_host` out of the roster."""
        urls = [step.primary.url for step in self._steps()]
        assert urls == [
            "https://atlas.ripe.net/api/v2/probes/",
            "https://atlas.ripe.net/api/v2/measurements/1001/latest/",
            "https://atlas.ripe.net/api/v2/measurements/1004/latest/",
            "https://atlas.ripe.net/api/v2/measurements/10509/latest/"]
        assert all("{" not in url for url in urls)

    def test_every_expanded_request_names_its_country_and_its_label(self):
        steps = self._steps()
        assert [step.primary.label for step in steps] == [
            "probes", "latency_1001", "latency_1004", "latency_10509"]
        assert steps[0].primary.params == (
            ("country_code", "TW"), ("status", "1"), ("page_size", "1"))
        for step in steps[1:]:
            assert step.primary.params == (("probe_cc", "TW"),)

    def test_the_measurement_ids_are_the_live_table_in_order(self):
        """`DEFAULT_MEASUREMENT_IDS` (`ripe_atlas.py:27`) compared as a
        SEQUENCE: `.get` does not care about order, but the ids are part
        of three distinct request addresses."""
        assert list(ripe_atlas.MEASUREMENT_IDS) == literal_in(
            "radar/sensors/ripe_atlas.py", "DEFAULT_MEASUREMENT_IDS")

    def test_the_measurement_parameter_is_the_live_one(self):
        """`ripe_atlas.py:73` sends `probe_cc`, not `country_code` — the
        probe endpoint's parameter. Sending the wrong one returns every
        probe on earth, which reads as a very healthy country."""
        live = dict_containing("radar/sensors/ripe_atlas.py", "probe_cc")
        assert set(live) == {"probe_cc"}
        assert '{ATLAS_API_BASE}/measurements/{mid}/latest/' in \
            legacy_source("radar/sensors/ripe_atlas.py")

    def test_the_drop_thresholds_are_the_live_constants(self):
        assert ripe_atlas.PROBE_DROP_PCT == literal_in(
            "radar/sensors/ripe_atlas.py", "PROBE_DROP_PCT")
        assert ripe_atlas.PROBE_BLACKOUT_PCT == literal_in(
            "radar/sensors/ripe_atlas.py", "PROBE_BLACKOUT_PCT")

    def test_the_measurement_id_is_recovered_from_the_address(self):
        assert ripe_atlas.measurement_id_of(body_payload(
            [], url="https://atlas.ripe.net/api/v2/measurements/1004/latest/"
                    "?probe_cc=TW")) == 1004
        assert ripe_atlas.measurement_id_of(
            body_payload([], label="latency_10509")) == 10509
        assert ripe_atlas.measurement_id_of(
            body_payload([], label="probes")) is None

    def test_each_measurement_owns_its_ledger_name(self):
        """Three latency drafts per country per tick. One name for all
        three is a `DomainError` at best (the flags differ) and a silent
        drop at worst; production has no name to copy because it pools
        the three BEFORE anything is recorded."""
        assert ripe_atlas.LATENCY_SIGNAL_SOURCES == {
            1001: "atlas_latency_1001", 1004: "atlas_latency_1004",
            10509: "atlas_latency_10509"}
        assert set(ripe_atlas.LATENCY_SIGNAL_SOURCES) == set(
            ripe_atlas.MEASUREMENT_IDS)


class TestRipeAtlasWithholdsTheVerdictWithoutFabricatingIt:
    def _probes(self):
        return ripe_atlas.normalize(
            payload("ripe_atlas", "probes_count.json", label="probes",
                    url=PROBES_URL),
            context("ripe_atlas"))[0]

    def test_the_marker_does_not_occupy_the_float_key(self):
        """`radar/sensors/ripe_atlas.py:62` carries `drop_pct` as
        `round(drop_pct, 3)` — a float. A marker string there reads as a
        truthy float to every consumer, which is a fabricated alarm
        dressed as "undecided" and also defeats a silence detector reading
        the same key. Absent means "not stated"; 0.0 would be a false
        negative (§7-2 #8, the `ct_log` convention)."""
        assert '"drop_pct": round(drop_pct, 3)' in \
            legacy_source("radar/sensors/ripe_atlas.py")
        flags = self._probes().flags
        assert "drop_pct" not in flags
        assert "prev" not in flags
        assert flags["probe_drop_verdict"] == "pending_l1_prev_probe_count"

    def test_the_reading_itself_is_reported_as_observed(self):
        draft = self._probes()
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["active"] == 412
        assert draft.value == "412 probes"

    def test_the_baseline_the_verdict_needs_is_declared(self):
        assert "atlas_prev_probe_count" in \
            ripe_atlas.RIPE_ATLAS_ADAPTER.baseline_refs

    @pytest.mark.parametrize("previous,active,expected", [
        (400, 100, "PROBE_BLACKOUT"), (400, 250, "PROBE_DROP"),
        (400, 390, "NORMAL")])
    def test_the_exported_ladder_is_what_the_wiring_will_use(
            self, previous, active, expected):
        assert ripe_atlas.status_for(
            ripe_atlas.drop_pct(previous, active)) == expected


class TestRipeAtlasRttPoolingIsAReductionNotAFake:
    def _latency(self, measurement_id=1001):
        return ripe_atlas.normalize(
            payload("ripe_atlas", "measurement_latest.json",
                    label=f"latency_{measurement_id}",
                    url=f"https://atlas.ripe.net/api/v2/measurements/"
                        f"{measurement_id}/latest/?probe_cc=TW"),
            context("ripe_atlas"))[0]

    def test_production_pools_across_all_three_before_computing(self):
        """`ripe_atlas.py:133` accumulates into `latency_rtts[code]` and
        `:137-147` computes `avg_ms` / `p95_ms` / `probes_responding` only
        after the loop. `normalize` sees one payload at a time, so the
        fold is a WP-4.1 reduction (§3-5 H-1(b) shape), not something L0
        may pretend to have done."""
        source = legacy_source("radar/sensors/ripe_atlas.py")
        assert "latency_rtts.setdefault(code, []).extend(rtts)" in source
        assert "for code, rtt_values in latency_rtts.items():" in source

    def test_each_draft_states_that_it_covers_one_measurement(self):
        draft = self._latency(1004)
        assert draft.flags["pool_scope"] == "single_measurement"
        assert draft.flags["measurement_id"] == 1004
        assert draft.status == STATUS_OBSERVED

    def test_the_samples_the_reduction_needs_travel_with_the_draft(self):
        """A pooled p95 cannot be recovered from three per-measurement
        p95s, so the raw samples are what makes the reduction possible."""
        draft = self._latency()
        # 32.5, 30.1, 34.9, 120.4, 118.0 — the -1 is a lost packet.
        assert list(draft.flags["rtt_samples"]) == [32.5, 30.1, 34.9,
                                                   120.4, 118.0]
        assert draft.flags["probes_responding"] == 5

    def test_rejoining_the_samples_reproduces_the_production_arithmetic(self):
        pooled: list = []
        for measurement_id in ripe_atlas.MEASUREMENT_IDS:
            pooled += list(self._latency(measurement_id).flags["rtt_samples"])
        ordered = sorted(pooled)
        expected_p95 = round(
            ordered[min(int(len(ordered) * 0.95), len(ordered) - 1)], 2)
        assert ripe_atlas.percentile_95(pooled) == expected_p95
        assert len(pooled) == 15


# ── §3: ihr_health — the signal that was missing ────────────────────────

class TestIhrDelayIsNoLongerMissing:
    def _delay(self, **overrides):
        return ihr_health.normalize(
            payload("ihr_health", "delay_alarms.json", label="network_delay"),
            context("ihr_health", **overrides))

    def test_production_emits_a_second_rationale_entry(self):
        """`add_rat("ihr_delay", ...)` at core.py:1518. The port emitted
        only the disco half, so v3 scored LOWER than production on a
        delay-only payload — the insensitive direction, a C-02/C-03
        cutover blocker."""
        source = legacy_source(CORE)
        assert 'add_rat("ihr_delay", "physical",' in source
        assert 'f"{len(_ihr_core_delay)} alarms" if _ihr_delay_fired ' \
               'else "—"' in source
        assert 'f"IHR: Network delay anomaly ({len(_ihr_core_delay)} ' \
               'alarms)"' in source

    def test_a_delay_alarm_fires_and_scores_one(self):
        by_country = {draft.country: draft for draft in self._delay(
            countries=("TW", "PH"))}
        assert by_country["TW"].status == STATUS_FIRED
        assert by_country["TW"].raw_score == 1.0
        assert by_country["TW"].value == "2 alarms"
        assert by_country["TW"].reason == \
            "IHR: Network delay anomaly (2 alarms)"
        assert by_country["TW"].signal_source == "ihr_delay"

    def test_the_delay_country_is_the_first_two_letters_of_the_endpoint(self):
        """`ihr.py:112-113`: network-delay alarms are about a LINK, so the
        country comes from the human-readable endpoint name, `[:2]` of the
        uppercased string. The second alarm has an empty `startpoint_name`
        and falls through to `endpoint_name`."""
        assert '.upper()[:2]' in legacy_source("radar/sensors/ihr.py")
        assert {draft.country for draft in self._delay(
            countries=("TW", "PH"))} == {"TW", "PH"}

    def test_the_stored_alarm_keys_are_the_legacy_ones(self):
        """`ihr.py:115-119` stores `link` / `deviation` / `ts` — and `ts`
        is the STORED name for the upstream's `timebin`."""
        by_country = {draft.country: draft
                      for draft in self._delay(countries=("TW",))}
        entry = by_country["TW"].flags["alarms"][0]
        assert list(entry) == ["link", "deviation", "ts"]
        assert entry["ts"] == "2026-08-07T08:00:00Z"
        assert entry["link"] == "AS3462-AS2914"


class TestIhrCountryStatusLadder:
    def test_the_ladder_is_the_live_four_rung_one(self):
        """`ihr.py:167-177` resolves disco -> hegemony -> delay, first
        match wins, else NORMAL. The port kept `DISCO_EVENT` alone."""
        source = legacy_source("radar/sensors/ihr.py")
        for rung in ("DISCO_EVENT", "HEGEMONY_ALARM", "DELAY_ANOMALY",
                     "NORMAL"):
            assert f'"{rung}"' in source
            assert rung in ihr_health.LADDER_RANK
        assert ihr_health.LADDER_RANK == {"DISCO_EVENT": 1,
                                          "HEGEMONY_ALARM": 2,
                                          "DELAY_ANOMALY": 3, "NORMAL": 4}

    @pytest.mark.parametrize("name,label,rung", [
        ("disco_events.json", "disco", "DISCO_EVENT"),
        ("hegemony_alarms.json", "hegemony", "HEGEMONY_ALARM"),
        ("delay_alarms.json", "network_delay", "DELAY_ANOMALY")])
    def test_each_endpoint_reports_the_rung_it_supports(self, name, label,
                                                        rung):
        draft = ihr_health.normalize(
            payload("ihr_health", name, label=label),
            context("ihr_health"))[0]
        assert draft.flags["status"] == rung
        assert draft.flags["ladder_rank"] == ihr_health.LADDER_RANK[rung]

    def test_a_country_in_scope_the_endpoint_missed_reads_ok_not_absent(self):
        """`add_rat(..., "OK", "—", 0, None)` (core.py:1511, :1520) is what
        production records for a quiet country. Emitting nothing would make
        "asked and saw nothing" indistinguishable from "never asked"."""
        by_country = {draft.country: draft for draft in ihr_health.normalize(
            payload("ihr_health", "hegemony_alarms.json", label="hegemony"),
            context("ihr_health", countries=("TW", "PH", "JP")))}
        assert by_country["JP"].status == STATUS_OK
        assert by_country["JP"].value == "—"
        assert by_country["JP"].flags["status"] == "NORMAL"
        assert by_country["JP"].flags["ladder_rank"] == 4

    def test_hegemony_is_carried_but_scores_nothing(self):
        drafts = ihr_health.normalize(
            payload("ihr_health", "hegemony_alarms.json", label="hegemony"),
            context("ihr_health", countries=("TW", "PH")))
        assert {draft.status for draft in drafts} == {STATUS_OK}
        assert {draft.raw_score for draft in drafts} == {0.0}
        by_country = {draft.country: draft for draft in drafts}
        assert list(by_country["TW"].flags["alarms"][0]) == \
            ["asn", "deviation", "ts"]
        assert by_country["TW"].flags["alarms"][0]["asn"] == 3462
        # `originasn` is the fallback spelling (`ihr.py:88`)
        assert by_country["PH"].flags["alarms"][0]["asn"] == 9299


class TestIhrDiscoIsUnchangedWhereProductionIs:
    def test_the_disco_score_ladder_and_reason_match_core(self):
        source = legacy_source(CORE)
        assert 'e.get("avglevel", 0) > 5' in source
        assert 'f"IHR: Disconnection event in {core_theater} "' in source
        draft = ihr_health.normalize(
            payload("ihr_health", "disco_events.json", label="disco"),
            context("ihr_health"))[0]
        assert draft.country == "TW"
        assert draft.signal_source == "bgp"
        assert draft.raw_score == 2.0            # avglevel 12.5 > 5
        assert draft.value == "1 events"
        assert draft.reason == \
            "IHR: Disconnection event in TW (1 events, probes=0)"

    def test_the_disposition_is_still_disabled_with_both_reasons(self):
        adapter = ihr_health.IHR_HEALTH_ADAPTER
        assert adapter.enabled is False
        assert "400" in adapter.disabled_reason
        assert "S1-SCORE-008" in adapter.disabled_reason
        assert ihr_health.IHR_API_BASE.startswith("https://www.ihr.live")


# ── §4: ioda_bgp ────────────────────────────────────────────────────────

class TestIodaValueStringIsConditional:
    def _drafts(self, name="alerts.json", label="ioda"):
        return ioda_bgp.normalize(
            payload("ioda_bgp", name, label=label),
            context("ioda_bgp", countries=("TW", "PH")))

    def test_production_guards_the_datasource_segment(self):
        """`core.py:1088` is guarded by `if _ioda_src_count > 0`, and
        `_ioda_src_count` reads `ioda_details[country]`, which
        `ioda.py:130-137` populates ONLY for warning/critical countries.
        A calm country's text therefore has no `ioda=` segment at all."""
        source = legacy_source(CORE)
        assert "if _ioda_src_count > 0:" in source
        assert 'bgp_value += f" ioda={_ioda_level}({_ioda_src_count}src)"' \
            in source
        assert 'bgp_value += f" [{ioda_source}]"' in source
        assert 'if ca and ca["max_level"] in IODA_ALERT_LEVELS:' in \
            legacy_source("radar/sensors/ioda.py")

    def test_a_calm_country_carries_no_datasource_segment(self):
        by_country = {draft.country: draft for draft in self._drafts()}
        assert by_country["TW"].status == STATUS_OK
        assert by_country["TW"].value == "bgp=NORMAL [ioda_proper]"

    def test_a_degraded_country_keeps_the_segment(self):
        by_country = {draft.country: draft for draft in self._drafts()}
        assert by_country["PH"].status == STATUS_FIRED
        assert by_country["PH"].value == \
            "bgp=OUTAGE ioda=warning(1src) [ioda_proper]"

    def test_the_fallback_text_names_the_fallback(self):
        drafts = self._drafts("cf_traffic_anomalies.json", "cf_fallback")
        assert drafts[0].value == "bgp=OUTAGE [cf_fallback]"


class TestIodaFiredReasonSurvivesThePort:
    def _draft(self, alerts):
        return ioda_bgp.normalize(
            body_payload({"data": alerts}, label="ioda"),
            context("ioda_bgp", countries=("TW",)))[0]

    def _alert(self, datasource, level="critical", moment=1.0):
        return {"entity": {"code": "TW"}, "datasource": datasource,
                "level": level, "time": moment}

    def test_production_writes_two_sentences_not_none(self):
        source = legacy_source(CORE)
        assert '_ioda_fired_reason = "BGP anomaly confirmed"' in source
        assert "if core_degraded and _ioda_src_count >= 2:" in source
        assert 'f"BGP anomaly confirmed by {_ioda_src_count} independent ' \
               'IODA datasources "' in source

    def test_a_single_datasource_gets_the_bare_sentence(self):
        assert self._draft([self._alert("bgp")]).reason == \
            "BGP anomaly confirmed"

    def test_two_datasources_name_themselves_in_declaration_order(self):
        """`ca["alert_sources"]` is a dict, so the join follows first-seen
        order — the order the alerts arrived in."""
        draft = self._draft([self._alert("bgp"),
                             self._alert("merit-nt", "warning")])
        assert draft.reason == ("BGP anomaly confirmed by 2 independent IODA "
                                "datasources (bgp, merit-nt)")

    def test_a_calm_country_carries_no_reason(self):
        assert self._draft([self._alert("bgp", "normal")]).reason == ""

    def test_the_fallback_carries_the_bare_sentence(self):
        """On the fallback path `ioda_details` does not exist
        (`ioda.py:185`), so the corroborated variant is unreachable."""
        draft = ioda_bgp.normalize(
            payload("ioda_bgp", "cf_traffic_anomalies.json",
                    label="cf_fallback"),
            context("ioda_bgp", countries=("PH",)))[0]
        assert draft.reason == "BGP anomaly confirmed"
        assert draft.flags == {"source": "cf_fallback"}


class TestIodaKeepsAnAlertWithNoDatasource:
    def test_production_indexes_the_empty_string_rather_than_skipping(self):
        """`ioda.py:96` reads `alert.get("datasource", "")` and indexes
        `alert_sources` with whatever came back. Dropping such an alert
        discards a `critical` and reports the country as calm — the
        insensitive direction NP1 exists to forbid."""
        source = legacy_source("radar/sensors/ioda.py")
        assert 'datasource = alert.get("datasource", "")' in source
        assert 'ca["alert_sources"][datasource] = {' in source

    def test_the_alert_still_sets_the_country_level(self):
        draft = ioda_bgp.normalize(
            payload("ioda_bgp", "alerts_no_datasource.json", label="ioda"),
            context("ioda_bgp", countries=("TW",)))[0]
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 1.0
        assert draft.flags["level"] == "critical"
        assert draft.flags["source_count"] == 1
        assert list(draft.flags["sources"]) == [""]


class TestIodaChainIsUnbroken:
    def test_the_declared_chain_still_falls_back_conditionally(self):
        """K19: production reaches Cloudflare only when
        `_fetch_ioda_proper` returns None (`ioda.py:49-55`)."""
        chain = ioda_bgp.IODA_BGP_ADAPTER.requests[0]
        assert isinstance(chain, RequestChain)
        assert [spec.label for spec in chain.alternatives] == [
            "ioda", "cf_fallback"]
        assert chain.alternatives[0].auth is None
        assert chain.alternatives[1].auth.key_id == "CF_API_TOKEN"

    def test_the_lookback_and_limit_are_the_live_ones(self):
        source = legacy_source("radar/sensors/ioda.py")
        assert f"since = now - {ioda_bgp.LOOKBACK_SEC}" in source
        assert f'"limit": {ioda_bgp.ALERT_LIMIT},' in source
        assert ioda_bgp.ALERT_LEVELS == literal_in(
            "radar/sensors/ioda.py", "IODA_ALERT_LEVELS")


# ── §7: peeringdb_ixp — the dropped map coordinates ─────────────────────

class TestPeeringdbCarriesTheMapOverlayCoordinates:
    def _draft(self, **overrides):
        return peeringdb_ixp.normalize(
            FetchedPayload(url="https://www.peeringdb.com/api/ix?country=TW",
                           status=200, fetched_at=T0, label="ix",
                           body=json.dumps({"data": [
                               {"id": 1, "name": "TWIX", "city": "Taipei",
                                "country": "TW", "name_long": "Taiwan IX"}]}
                           ).encode()),
            context("peeringdb_ixp", **overrides))[0]

    def test_the_stored_record_keys_are_the_live_ones_in_order(self):
        """`peeringdb.py:74-76`. The port dropped `lat` and `lng`, which
        are the only coordinates the map overlay has — `core.py:2902`
        builds `critical_nodes` from this list, so the overlay goes
        silently empty while the count still says it is full."""
        live = dict_containing("radar/sensors/peeringdb.py", "lat")
        assert list(live) == ["id", "name", "city", "country", "lat", "lng",
                              "status", "aka"]
        assert list(self._draft().flags["ixps"][0]) == list(live)

    def test_the_coordinates_come_from_the_supplied_geo_table(self):
        record = self._draft().flags["ixps"][0]
        assert (record["lat"], record["lng"]) == TAIWAN["TW"]

    def test_an_unknown_country_defaults_to_zero_as_production_does(self):
        """`COUNTRY_COORDS.get(code, {})` then `.get("lat", 0)` — the
        legacy default is 0, not None, and a None here would crash the
        overlay rather than place the marker at the origin."""
        live = dict_containing("radar/sensors/peeringdb.py", "lat")
        assert live["lat"] == "coord.get('lat', 0)"
        assert live["lng"] == "coord.get('lng', 0)"
        record = self._draft(country_coordinates={}).flags["ixps"][0]
        assert (record["lat"], record["lng"]) == (0, 0)

    def test_it_is_still_an_inventory_and_never_fires(self):
        draft = self._draft()
        assert draft.status == STATUS_OK
        assert draft.raw_score == 0.0
        assert draft.value == "IXP(s) registered"
        assert 'f"IXP(s) registered"' in legacy_source(CORE)


# ── §5: markers never occupy a typed key (cross-cutting) ────────────────

def _marker_keys(relative_path: str) -> list:
    """`(key, value)` for every `pending_l1_*` string in a dict literal."""
    found: list = []
    tree = ast.parse((REPO_ROOT / relative_path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key_node, value_node in zip(node.keys, node.values):
            if isinstance(value_node, ast.Constant) and \
                    isinstance(value_node.value, str) and \
                    value_node.value.startswith("pending_l1_") and \
                    isinstance(key_node, ast.Constant):
                found.append((key_node.value, value_node.value))
    return found


class TestPendingMarkersLiveInSiblingKeys:
    @pytest.mark.parametrize("module", MY_MODULES)
    def test_no_marker_sits_in_a_key_production_types(self, module):
        """A marker is a NON-EMPTY string, so a consumer reading its key
        as a bool sees `True` forever and one reading it as a float sees a
        truthy number. `ct_log` sets the convention (§7-2 #8): the
        unreachable verdict is ABSENT from the field that carries verdicts
        and NAMED in a sibling."""
        for key, value in _marker_keys(module):
            assert key.endswith("_verdict"), (
                f"{module} writes {value!r} into {key!r}; the convention is "
                f"a sibling `<thing>_verdict` key, with the typed field "
                f"left absent")

    def test_the_convention_is_the_one_ct_log_established(self):
        assert ("untrusted_ca_verdict", "pending_l1_known_ca_ledger") in \
            _marker_keys("v3/adapters/cyber/ct_log.py")
        assert _marker_keys("v3/adapters/physical/ripe_atlas.py") == [
            ("probe_drop_verdict", "pending_l1_prev_probe_count")]
