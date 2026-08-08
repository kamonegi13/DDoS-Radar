"""WP-4.1 — InputHealth, built from what the tick actually got.

G-17's remaining half. `InputHealth` exists so a dead pipeline and a quiet
world stop being the same absence; until now nothing built one, so L3's
guards received whatever a caller invented.

The tests below fix the boundaries, because the boundaries are where the
defect lives:
  * a source that is NOT DUE is not a broken source (counting it would
    make every tick degraded, and a permanently unavailable conclusion is
    NP5+8's design failure);
  * a source held shut by its own breaker IS one (it answered nothing);
  * a source whose newest data is past its horizon is STALE, not ok
    (B-03: a live endpoint serving a stale cache read as healthy);
  * a source whose required credential was never supplied is FAILED even
    though it appears in neither the results nor the skips.
"""
import pytest

from v3.kernel import Evidence
from v3.kernel.threat_level import ThreatLevel
from v3.ledger.records import SignalObservation, TLObservation
from v3.ledger.store import LedgerStore
from v3.conclusions.availability import InputHealth
from v3.fetch import runner as runner_module
from v3.fetch.client import OK, TIMEOUT
from v3.fetch.runner import (AdapterResult, CycleResult, FetchPlan,
                             SkippedFetch)
from v3.adapters.types import AdapterId
from v3.kernel.errors import DomainError
from v3.runtime import health as H
from v3.runtime import secrets


@pytest.fixture
def ledger_store(tmp_path):
    store = LedgerStore(str(tmp_path / "runtime.db"))
    yield store
    store.close()


def write_signal(store, *, sensor, country, observed_at, horizon,
                 tick_id="t1"):
    store.append_signal(SignalObservation(
        tick_id=tick_id, sensor=sensor, signal_source=sensor,
        domain="physical", country=country,
        evidence=Evidence.observe({"n": 1}, observed_at=observed_at,
                                  freshness_horizon_sec=horizon,
                                  source=sensor),
        status="OK", raw_score=0.0), now=observed_at)


def write_tl(store, *, scenario_id, observed_at, tl=3, tick=None):
    store.append_tl(TLObservation(
        tick_id=tick or f"tick-{observed_at:.0f}", scenario_id=scenario_id,
        observed_at=observed_at, threat_level=ThreatLevel(tl), score=1.0))


def _cycle(results=(), skipped=()):
    return CycleResult(
        plan=FetchPlan(now=1_000.0, planned=(), skipped=tuple(skipped)),
        results=tuple(results))


def _result(name, outcome=OK, detail=""):
    return AdapterResult(adapter_id=AdapterId(name), outcome=outcome,
                         detail=detail)


def _skip(name, reason, detail="d"):
    return SkippedFetch(adapter_id=AdapterId(name), reason=reason,
                        detail=detail)


class TestOutcomesReadBothHalvesOfTheCycle:
    def test_a_successful_fetch_is_healthy(self):
        outcomes = H.outcomes_for_cycle(_cycle(results=[_result("ripe_bgp")]))
        assert [(o.adapter_id, o.bucket) for o in outcomes] == [
            ("ripe_bgp", H.SourceOutcome.OK)]

    def test_a_failed_fetch_carries_its_reason(self):
        outcomes = H.outcomes_for_cycle(_cycle(
            results=[_result("gdelt", TIMEOUT, "timeout after 10s")]))
        assert outcomes[0].bucket == H.SourceOutcome.FAILED
        assert "timeout after 10s" in outcomes[0].detail

    def test_a_breaker_held_source_counts_against_health(self):
        """B-01 is what "the breaker holds it, so it did not fetch, so it
        does not count" looks like from the other side."""
        outcomes = H.outcomes_for_cycle(_cycle(
            skipped=[_skip("ioda_bgp", runner_module.BREAKER_OPEN)]))
        assert outcomes[0].bucket == H.SourceOutcome.FAILED

    def test_a_rate_limited_source_counts_against_health(self):
        outcomes = H.outcomes_for_cycle(_cycle(
            skipped=[_skip("opensky", runner_module.RATE_LIMITED)]))
        assert outcomes[0].bucket == H.SourceOutcome.FAILED

    def test_an_unresolved_placeholder_counts_against_health(self):
        outcomes = H.outcomes_for_cycle(_cycle(
            skipped=[_skip("isr_hotspot", runner_module.UNRESOLVED)]))
        assert outcomes[0].bucket == H.SourceOutcome.FAILED

    @pytest.mark.parametrize("reason", [runner_module.NOT_DUE,
                                        runner_module.DISABLED])
    def test_out_of_scope_sources_are_not_consulted_not_failed(self, reason):
        """A four-hour source at minute thirty is not an outage."""
        outcomes = H.outcomes_for_cycle(_cycle(skipped=[_skip("x", reason)]))
        assert outcomes[0].bucket == H.SourceOutcome.NOT_CONSULTED

    def test_the_two_skip_sets_partition_the_runners_vocabulary(self):
        assert H.COUNTED_SKIPS & H.UNCOUNTED_SKIPS == frozenset()
        assert H.COUNTED_SKIPS | H.UNCOUNTED_SKIPS == {
            runner_module.NOT_DUE, runner_module.DISABLED,
            runner_module.BREAKER_OPEN, runner_module.RATE_LIMITED,
            runner_module.UNRESOLVED}


class TestAMissingRequiredCredentialIsAnOutage:
    def test_a_dark_adapter_appears_in_neither_list_without_this(self):
        cycle = _cycle()
        assert H.outcomes_for_cycle(cycle) == ()

    def test_it_is_counted_as_failed_with_its_key_named(self):
        plan = secrets.CredentialPlan(
            material={}, postures=(secrets.CredentialPosture(
                adapter_id="threatfox", key_id="THREATFOX_API_KEY",
                mode=secrets.UNSATISFIED),))
        outcomes = H.outcomes_for_cycle(_cycle(), credentials=plan)
        assert outcomes[0].bucket == H.SourceOutcome.FAILED
        assert "THREATFOX_API_KEY" in outcomes[0].detail

    def test_an_anonymous_adapter_is_not_an_outage(self):
        """Production ships OpenSky anonymous; calling that a failure
        would report a permanent outage on a working source."""
        plan = secrets.CredentialPlan(
            material={}, postures=(secrets.CredentialPosture(
                adapter_id="opensky", key_id="OPENSKY_CLIENT_CREDENTIALS",
                mode=secrets.ANONYMOUS),))
        outcomes = H.outcomes_for_cycle(
            _cycle(results=[_result("opensky")]), credentials=plan)
        assert [o.bucket for o in outcomes] == [H.SourceOutcome.OK]

    def test_it_does_not_double_count_an_adapter_that_did_run(self):
        plan = secrets.CredentialPlan(
            material={}, postures=(secrets.CredentialPosture(
                adapter_id="threatfox", key_id="K",
                mode=secrets.UNSATISFIED),))
        outcomes = H.outcomes_for_cycle(
            _cycle(results=[_result("threatfox", TIMEOUT)]), credentials=plan)
        assert len(outcomes) == 1


class TestBuildingTheRecord:
    def test_the_three_buckets_reach_input_health(self):
        health = H.build(
            (H.SourceOutcome("a", H.SourceOutcome.OK),
             H.SourceOutcome("b", H.SourceOutcome.FAILED, "boom")),
            stale=("c",), history_span=3600.0)
        assert isinstance(health, InputHealth)
        assert health.sources_ok == ("a",)
        assert health.sources_failed == ("b",)
        assert health.sources_stale == ("c",)
        assert health.history_span_sec == 3600.0

    def test_not_consulted_sources_are_absent_from_the_denominator(self):
        health = H.build((H.SourceOutcome("a", H.SourceOutcome.OK),
                          H.SourceOutcome("z",
                                          H.SourceOutcome.NOT_CONSULTED)))
        assert health.consulted == 1

    def test_stale_wins_over_ok(self):
        """A source that answered with data past its horizon answered,
        and what it said cannot be used (B-03)."""
        health = H.build((H.SourceOutcome("a", H.SourceOutcome.OK),),
                         stale=("a",))
        assert health.sources_ok == ()
        assert health.sources_stale == ("a",)

    def test_failure_wins_over_health_for_the_same_source(self):
        health = H.build((H.SourceOutcome("a", H.SourceOutcome.OK),
                          H.SourceOutcome("a", H.SourceOutcome.FAILED, "x")))
        assert health.sources_ok == () and health.sources_failed == ("a",)

    def test_a_total_outage_is_representable_and_is_not_calm(self):
        """WP-3.1: a tick where every source died but TL held must still
        write, and the guard identity is part of the write identity."""
        health = H.build(tuple(
            H.SourceOutcome(name, H.SourceOutcome.FAILED, "down")
            for name in ("a", "b", "c")))
        assert health.failure_ratio == 1.0
        assert health.has_no_basis is False
        assert health.consulted == 3

    def test_an_empty_cycle_is_the_no_basis_shape(self):
        health = H.build(())
        assert health.has_no_basis is True

    def test_an_unknown_bucket_is_refused(self):
        with pytest.raises(DomainError, match="unknown health bucket"):
            H.SourceOutcome("a", "probably_fine")


class TestStalenessIsAskedOfTheLedger:
    def test_a_source_past_its_horizon_is_stale(self, ledger_store):
        adapter = _adapter("slow", horizon=60.0)
        write_signal(ledger_store, sensor="slow", country="TW",
                     observed_at=1_000.0, horizon=60.0)
        assert H.stale_sources(ledger_store, now=2_000.0,
                               adapters=[adapter],
                               countries=("TW",)) == ("slow",)

    def test_a_source_inside_its_horizon_is_not(self, ledger_store):
        adapter = _adapter("fresh", horizon=3600.0)
        write_signal(ledger_store, sensor="fresh", country="TW",
                     observed_at=1_000.0, horizon=3600.0)
        assert H.stale_sources(ledger_store, now=1_500.0,
                               adapters=[adapter],
                               countries=("TW",)) == ()

    def test_a_source_that_never_wrote_is_not_stale(self, ledger_store):
        """Never-observed and observed-too-long-ago are different facts:
        the first is a failure the cycle already reported, and reporting
        it twice would count one outage as two."""
        assert H.stale_sources(ledger_store, now=1_000.0,
                               adapters=[_adapter("never")],
                               countries=("TW",)) == ()

    def test_the_newest_country_governs(self, ledger_store):
        adapter = _adapter("mixed", horizon=100.0)
        write_signal(ledger_store, sensor="mixed", country="TW",
                     observed_at=1_000.0, horizon=100.0)
        write_signal(ledger_store, sensor="mixed", country="JP",
                     observed_at=1_950.0, horizon=100.0)
        assert H.stale_sources(ledger_store, now=2_000.0, adapters=[adapter],
                               countries=("TW", "JP")) == ()


class TestHistorySpanIsDerived:
    def test_no_history_is_zero(self, ledger_store):
        assert H.history_span_sec(ledger_store, "taiwan_contingency",
                                  now=1_000.0) == 0.0

    def test_it_measures_from_the_first_observation(self, ledger_store):
        write_tl(ledger_store, scenario_id="s", observed_at=1_000.0)
        write_tl(ledger_store, scenario_id="s", observed_at=2_000.0)
        assert H.history_span_sec(ledger_store, "s", now=5_000.0) == 4_000.0


class TestTheDisclosureNamesEverySource:
    def test_every_outcome_carries_its_cause(self):
        outcomes = H.outcomes_for_cycle(_cycle(
            results=[_result("a"), _result("b", TIMEOUT, "boom")],
            skipped=[_skip("c", runner_module.BREAKER_OPEN, "open")]))
        rows = H.disclosure(outcomes)
        assert {r["adapter_id"] for r in rows} == {"a", "b", "c"}
        assert all("bucket" in r and "detail" in r for r in rows)


def _adapter(name: str, horizon: float = 3600.0):
    from v3.adapters.types import AdapterId, RequestSpec, SourceAdapter
    from v3.kernel.window import Window
    return SourceAdapter(
        adapter_id=AdapterId(name), category="cyber",
        cadence=Window.from_days(1.0, cadence_sec=300.0),
        requests=(RequestSpec(url="https://example.test/x"),),
        normalize=lambda payload, context: (),
        freshness_horizon_sec=horizon)
