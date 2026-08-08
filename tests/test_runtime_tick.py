"""WP-4.1 — the tick, the suppression join, and the one thread.

Three things are proved end to end, with a fake transport and a fake
clock, in a temporary ledger:

  * the pipeline runs and is IDEMPOTENT. Re-running the same instant is a
    no-op because the ledger is keyed on `(tick_id, sensor, signal_source,
    country)` and `tick_id` is derived from the instant (S5-VERIF-019);
  * suppression producers run FIRST. `space_weather` cannot mute RIPE
    Atlas in a cycle where it has not been fetched, so the plan is
    reordered — a reordering, never a filter;
  * the loop starts one thread on an explicit call, stops between ticks,
    and survives a tick that raises (NP3: a monitoring tool that stops
    monitoring when something breaks is the failure mode, not the
    symptom).
"""
import dataclasses
import threading

import pytest

from v3.adapters.types import (CYBER, INFO, PHYSICAL, STATUS_FIRED,
                               STATUS_OK, AdapterId, ObservationDraft,
                               RequestSpec, SourceAdapter)
from v3.fetch.registry import AdapterRegistry
from v3.fetch.runner import FetchPlan, PlannedFetch, run_due
from v3.fetch.breaker import BreakerState
from v3.kernel.errors import DomainError
from v3.kernel.window import Window
from v3.ledger.store import LedgerStore
from v3.runtime import geo as geo_module
from v3.runtime import suppression, tick
from v3.runtime.loop import Runtime
from v3.runtime.secrets import (ANONYMOUS, CredentialPlan, CredentialPosture,
                                UNSATISFIED)

NOW = 1_800_000_000.0

GEO_DOC = {
    "ISR_HOTSPOTS": [
        {"name": "Taiwan Strait Median Line", "lat": 24.5, "lng": 120.5,
         "theater": "TW", "radius_km": 200},
        {"name": "East China Sea ADIZ Overlap", "lat": 26.0, "lng": 123.0,
         "theater": "TW", "radius_km": 200},
    ],
    "CHOKEPOINTS": [{"name": "Bashi Channel", "lat": 21.5, "lng": 121.0,
                     "country": "TW"}],
    "COUNTRY_COORDS": {"TW": {"lat": 23.7, "lng": 121.0, "name": "Taiwan"}},
    "SCENARIOS": {"taiwan_contingency": {
        "participants": {"TW": {"weight": 1.0, "role": "primary_target"},
                         "CN": {"weight": 0.7, "role": "adversary"}}}},
}


@pytest.fixture
def geography():
    return geo_module.from_document(GEO_DOC)


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "tick.db"))
    yield instance
    instance.close()


class _Payload:
    def __init__(self, url="https://example.test/x", label=""):
        self.url, self.label, self.body = url, label, b"{}"
        self.status, self.content_type = 200, "application/json"

    def json(self):
        return {}


class _Outcome:
    def __init__(self, url):
        self.outcome, self.url, self.status = "ok", url, 200
        self.latency_ms, self.attempts, self.detail = 1.0, 1, ""
        self.body_sha256 = "0" * 64
        self.url_sha256 = "1" * 64
        self.payload = _Payload(url)
        self.succeeded = True


class _Client:
    """Answers every request identically. Never touches a socket."""

    def __init__(self):
        self.sent = []

    def fetch(self, spec, *, now, auth=None, **kwargs):
        self.sent.append(spec)
        return _Outcome(spec.url)

    def pause(self, seconds):
        pass


def _adapter(name, category, drafts, *, group=""):
    return SourceAdapter(
        adapter_id=AdapterId(name), category=category,
        cadence=Window.from_days(1.0, cadence_sec=1.0),
        requests=(RequestSpec(url=f"https://{name}.test/x"),),
        normalize=lambda payload, context, _d=drafts: tuple(_d),
        freshness_horizon_sec=86400.0, rate_limit_group=group or name)


def _storm(active=True):
    return ObservationDraft(
        signal_source="space_weather", domain=PHYSICAL, country="",
        status=STATUS_OK, value="Kp=6.3 xray=M [SEVERE]",
        suppressed=active,
        suppress_reason="Geomagnetic storm: Kp=6.3 — physical sensor noise"
        if active else None,
        flags={"kp_index": 6.3, "kp_forecast_24h": 6.3, "xray_class": "M",
               "suppress_physical": active, "endpoint": "kp"})


def _atlas():
    return ObservationDraft(
        signal_source="ripe_atlas", domain=PHYSICAL, country="TW",
        status=STATUS_FIRED, raw_score=2.0, value="20 probes",
        flags={"active": 20})


class TestSuppressionNeedsItsProducerFirst:
    def test_the_plan_is_reordered_not_filtered(self):
        def item(name):
            return PlannedFetch(adapter_id=AdapterId(name), steps=(),
                                breaker=BreakerState())
        plan = FetchPlan(now=NOW, planned=(item("ripe_atlas"),
                                           item("space_weather"),
                                           item("gdelt"),
                                           item("openweather")))
        ordered = tick.order_producers_first(plan)
        assert ordered.planned_ids[:2] == ("space_weather", "openweather")
        assert set(ordered.planned_ids) == set(plan.planned_ids)

    def test_a_storm_marks_atlas_suppressed(self):
        producers = {"space_weather": (_storm(),)}
        state = suppression.read_suppressors(producers)
        marked = suppression.apply("ripe_atlas", (_atlas(),),
                                   suppressors=state)
        assert marked[0].suppressed is True
        assert "Geomagnetic storm" in marked[0].suppress_reason

    def test_a_quiet_sun_leaves_atlas_alone(self):
        state = suppression.read_suppressors(
            {"space_weather": (_storm(active=False),)})
        marked = suppression.apply("ripe_atlas", (_atlas(),),
                                   suppressors=state)
        assert marked[0].suppressed is False

    def test_a_suppressed_physical_row_keeps_its_score(self):
        """`add_rat` stores the caller's number unchanged; exclusion is at
        aggregation. Zeroing here would be a second mechanism."""
        state = suppression.read_suppressors({"space_weather": (_storm(),)})
        marked = suppression.apply("ripe_atlas", (_atlas(),),
                                   suppressors=state)
        assert marked[0].raw_score == 2.0

    def test_severe_weather_zeroes_gdelt_because_production_does(self):
        weather = ObservationDraft(
            signal_source="openweather", domain=PHYSICAL, country="TW",
            status=STATUS_OK, value="storm", flags={"is_severe": True})
        gdelt = ObservationDraft(
            signal_source="gdelt", domain=INFO, country="TW",
            status=STATUS_FIRED, raw_score=1.0, value="ALERT",
            reason="Media tone collapse", flags={"tone": -6.0})
        state = suppression.read_suppressors({"openweather": (weather,)})
        marked = suppression.apply("gdelt", (gdelt,), suppressors=state)
        assert marked[0].raw_score == 0.0
        assert marked[0].status == "SUPPRESSED"
        assert marked[0].suppress_reason == suppression.SEVERE_WEATHER_REASON

    def test_calm_weather_leaves_gdelt_firing(self):
        weather = ObservationDraft(
            signal_source="openweather", domain=PHYSICAL, country="TW",
            status=STATUS_OK, value="clear", flags={"is_severe": False})
        gdelt = ObservationDraft(
            signal_source="gdelt", domain=INFO, country="TW",
            status=STATUS_FIRED, raw_score=1.0, value="ALERT")
        state = suppression.read_suppressors({"openweather": (weather,)})
        assert suppression.apply("gdelt", (gdelt,),
                                 suppressors=state)[0].raw_score == 1.0

    def test_weather_suppresses_only_the_country_it_is_over(self):
        weather = ObservationDraft(
            signal_source="openweather", domain=PHYSICAL, country="TW",
            status=STATUS_OK, value="storm", flags={"is_severe": True})
        other = ObservationDraft(
            signal_source="gdelt", domain=INFO, country="JP",
            status=STATUS_FIRED, raw_score=1.0, value="ALERT")
        state = suppression.read_suppressors({"openweather": (weather,)})
        assert suppression.apply("gdelt", (other,),
                                 suppressors=state)[0].suppressed is False

    def test_a_quiet_row_is_not_marked_suppressed(self):
        """`core.py:1372` computes `_ch_sw_suppress = sw_suppress and
        ch_fired`. An OK row during a storm is not "suppressed", it is
        quiet — and marking it so would put a suppression in the audit
        trail for an observation nothing was hiding.

        (Added after a mutation sweep: removing the `only_when_fired`
        check survived every other test in this file.)
        """
        quiet = ObservationDraft(
            signal_source="check_host", domain=PHYSICAL, country="TW",
            status=STATUS_OK, raw_score=0.0, value="success=100%")
        state = suppression.read_suppressors({"space_weather": (_storm(),)})
        assert suppression.apply("check_host", (quiet,),
                                 suppressors=state)[0].suppressed is False

    def test_a_firing_row_of_the_same_sensor_is_marked(self):
        firing = ObservationDraft(
            signal_source="check_host", domain=PHYSICAL, country="TW",
            status=STATUS_FIRED, raw_score=3.0, value="BLACKOUT")
        state = suppression.read_suppressors({"space_weather": (_storm(),)})
        assert suppression.apply("check_host", (firing,),
                                 suppressors=state)[0].suppressed is True

    def test_an_unsuppressed_sensor_is_returned_unchanged(self):
        row = ObservationDraft(signal_source="x", domain=CYBER, country="TW",
                               status=STATUS_OK, value="v")
        state = suppression.read_suppressors({"space_weather": (_storm(),)})
        assert suppression.apply("threatfox", (row,),
                                 suppressors=state) == (row,)

    def test_every_rule_cites_production_and_the_register(self):
        for entry in suppression.registry_disclosure():
            assert "radar/" in entry["production_ref"]
            assert entry["register_ref"].startswith("§7-2")


class TestTheTickRunsEndToEnd:
    def _registry(self):
        return AdapterRegistry([
            _adapter("space_weather", "physical", (_storm(),)),
            _adapter("ripe_atlas", "physical", (_atlas(),)),
        ])

    def test_it_writes_observations_and_conclusions(self, store, geography):
        report = tick.run_tick(
            now=NOW, registry=self._registry(), store=store,
            client=_Client(), geography=geography,
            scenario_ids=("taiwan_contingency",))
        assert report.observations_written == 2
        assert report.tick_id == f"t{int(NOW)}"
        assert store.count_conclusions() > 0

    def test_the_context_an_adapter_receives_names_the_adversaries(
            self, store, geography):
        """The seam that was broken. `usgs_seismic`'s own unit tests always
        passed an adversary set, so the adapter's nuclear-candidate logic
        was covered — what nothing covered was the SUPPLIER, which handed
        every adapter an empty tuple. The detection was dead in the running
        system while its tests were green, so the test has to live where
        the real context is built."""
        seen: list = []

        def _record(payload, context):
            seen.append(context)
            return ()

        recorder = _adapter("usgs_seismic", "physical", ())
        recorder = dataclasses.replace(recorder, normalize=_record)
        tick.run_tick(now=NOW, registry=AdapterRegistry([recorder]),
                      store=store, client=_Client(), geography=geography,
                      scenario_ids=("taiwan_contingency",))
        assert seen, "the adapter was never normalized"
        assert seen[0].adversaries == ("CN",)

    def test_the_storm_reaches_the_ledger_as_a_suppression(self, store,
                                                           geography):
        tick.run_tick(now=NOW, registry=self._registry(), store=store,
                      client=_Client(), geography=geography,
                      scenario_ids=("taiwan_contingency",))
        row = store.latest_signal_at(NOW, sensor="ripe_atlas", country="TW")
        assert row["suppressed"] == 1

    def test_rerunning_the_same_instant_is_a_no_op(self, store, geography):
        """S5-VERIF-019: same key, same content, already stored."""
        first = tick.run_tick(now=NOW, registry=self._registry(),
                              store=store, client=_Client(),
                              geography=geography,
                              scenario_ids=("taiwan_contingency",))
        before = store.count_signals()
        second = tick.run_tick(now=NOW, registry=self._registry(),
                               store=store, client=_Client(),
                               geography=geography,
                               scenario_ids=("taiwan_contingency",))
        assert first.tick_id == second.tick_id
        assert store.count_signals() == before

    def test_health_reaches_the_conclusions(self, store, geography):
        report = tick.run_tick(now=NOW, registry=self._registry(),
                               store=store, client=_Client(),
                               geography=geography,
                               scenario_ids=("taiwan_contingency",))
        health = report.health["taiwan_contingency"]
        assert set(health["sources_ok"]) == {"space_weather", "ripe_atlas"}
        assert health["failure_ratio"] == 0.0

    def test_the_coverage_report_counts_zones_not_only_countries(
            self, store, geography):
        report = tick.run_tick(now=NOW, registry=self._registry(),
                               store=store, client=_Client(),
                               geography=geography,
                               scenario_ids=("taiwan_contingency",))
        assert report.coverage["zone_requests"] == 2
        assert report.coverage["zones_per_country"]["TW"] == 2
        assert report.coverage["countries_without_a_zone"] == ["CN"]

    def test_the_credential_posture_travels_in_the_report(self, store,
                                                          geography):
        plan = CredentialPlan(material={}, postures=(
            CredentialPosture(adapter_id="opensky", key_id="K",
                              mode=ANONYMOUS),
            CredentialPosture(adapter_id="threatfox", key_id="T",
                              mode=UNSATISFIED)))
        report = tick.run_tick(now=NOW, registry=self._registry(),
                               store=store, client=_Client(),
                               geography=geography, credentials=plan,
                               scenario_ids=("taiwan_contingency",))
        assert report.credentials["anonymous"] == ["opensky"]
        assert report.credentials["unsatisfied"] == ["threatfox"]

    def test_a_dark_adapter_degrades_the_health_it_never_reached(
            self, store, geography):
        plan = CredentialPlan(material={}, postures=(
            CredentialPosture(adapter_id="threatfox", key_id="T",
                              mode=UNSATISFIED),))
        report = tick.run_tick(now=NOW, registry=self._registry(),
                               store=store, client=_Client(),
                               geography=geography, credentials=plan,
                               scenario_ids=("taiwan_contingency",))
        assert "threatfox" in report.health[
            "taiwan_contingency"]["sources_failed"]

    def test_no_scenarios_is_refused(self, store, geography):
        with pytest.raises(DomainError, match="no scenarios"):
            tick.run_tick(now=NOW, registry=self._registry(), store=store,
                          client=_Client(), geography=geography,
                          scenario_ids=())

    def test_the_anonymous_note_lands_in_the_fetch_log(self, store,
                                                       geography):
        from v3.fetch import recorder
        plan = CredentialPlan(material={}, postures=(
            CredentialPosture(adapter_id="ripe_atlas", key_id="K",
                              mode=ANONYMOUS),))
        tick.run_tick(now=NOW, registry=self._registry(), store=store,
                      client=_Client(), geography=geography,
                      credentials=plan,
                      scenario_ids=("taiwan_contingency",))
        rows = recorder.fetch_log_for(store, "ripe_atlas")
        assert any("anonymous: no K" in row["detail"] for row in rows)


class TestTheOneThread:
    def test_creating_a_runtime_starts_nothing(self):
        before = threading.active_count()
        Runtime(lambda now: None)
        assert threading.active_count() == before

    def test_start_runs_ticks_and_stop_ends_them(self):
        seen = []
        runtime = Runtime(lambda now: seen.append(now), interval_sec=0.01,
                          clock=lambda: NOW)
        with runtime:
            for _ in range(1000):
                if seen:
                    break
        runtime.stop(timeout_sec=5)
        assert seen
        assert not runtime.is_running

    def test_run_once_runs_in_the_calling_thread(self):
        seen = []
        runtime = Runtime(lambda now: seen.append(threading.current_thread()),
                          clock=lambda: NOW)
        runtime.run_once()
        assert seen == [threading.current_thread()]
        assert runtime.status().ticks == 1

    def test_a_second_start_is_refused(self):
        runtime = Runtime(lambda now: None, interval_sec=0.01,
                          clock=lambda: NOW)
        with runtime:
            with pytest.raises(DomainError, match="already running"):
                runtime.start()
        runtime.stop(timeout_sec=5)

    def test_a_failing_tick_is_counted_and_the_loop_survives(self):
        failures = []

        def explode(now):
            raise RuntimeError("upstream on fire")

        runtime = Runtime(explode, interval_sec=0.01, clock=lambda: NOW,
                          on_error=failures.append)
        with runtime:
            for _ in range(1000):
                if failures:
                    break
        runtime.stop(timeout_sec=5)
        assert failures
        status = runtime.status()
        assert status.errors >= 1
        assert "upstream on fire" in status.last_error

    def test_run_once_re_raises_so_a_caller_sees_the_failure(self):
        runtime = Runtime(lambda now: 1 / 0, clock=lambda: NOW)
        with pytest.raises(ZeroDivisionError):
            runtime.run_once()
        assert runtime.status().errors == 1

    def test_a_non_positive_interval_is_refused(self):
        with pytest.raises(DomainError, match="interval_sec must be"):
            Runtime(lambda now: None, interval_sec=0.0)

    def test_the_tick_must_be_callable(self):
        with pytest.raises(DomainError, match="callable tick"):
            Runtime("not a function")
