"""WP-4.1e Piece 1 — the scoring tick reads v3's OWN configuration chain.

WP-4.1d landed `ConfigResolver` and proved `resolve_settings` sees a C7
override. What it did not land is the edge that makes the override matter:
nothing under `v3/runtime/` called `resolve_settings`, so a scored tick
still fell through to legacy `radar.config_layered`. An override that
reaches storage, the audit row and the settings screen but not the formula
is G-15 one layer up — the registry was decorative for months in exactly
that shape.

So the proof here is not "the resolver answers". It is **a C7 override
changes a scored outcome that the tick wrote down**: two ticks, identical
observations, one override between them, and a different `score` and
`domain_scores` in `tl_observation`.

The mutation guard is the second class: it points the tick at a chain
that cannot see the override row and requires the scored number to go
back to the default. If that test ever passes while the end-to-end one
also passes, the tick has grown a second configuration path.
"""
from __future__ import annotations

import pytest

from v3.adapters.types import (CYBER, INFO, PHYSICAL, STATUS_FIRED,
                               AdapterId, ObservationDraft, RequestSpec,
                               SourceAdapter)
from v3.api.dispatch import handle
from v3.api.readonly import ReadOnlyLedger
from v3.api.request import ApiRequest, Principal, ReadContext, ScenarioRef
from v3.api.vocabulary import API_PREFIX, POST
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.config.resolution import ConfigResolver
from v3.fetch.registry import AdapterRegistry
from v3.kernel.errors import DomainError
from v3.kernel.window import Window
from v3.ledger.store import LedgerStore
from v3.runtime import geo as geo_module
from v3.runtime import scoring as scoring_module
from v3.runtime import tick as tick_module

NOW = 1_800_000_000.0
LATER = NOW + 3600.0
SCENARIO = "taiwan_contingency"
KEY = "DOMAIN_CAP"

GEO_DOC = {
    "ISR_HOTSPOTS": [
        {"name": "Taiwan Strait Median Line", "lat": 24.5, "lng": 120.5,
         "theater": "TW", "radius_km": 200},
    ],
    "COUNTRY_COORDS": {"TW": {"lat": 23.7, "lng": 121.0, "name": "Taiwan"}},
    "SCENARIOS": {SCENARIO: {
        "participants": {"TW": {"weight": 1.0, "role": "primary_target"},
                         "CN": {"weight": 0.7, "role": "adversary"}}}},
}


@pytest.fixture()
def geography():
    return geo_module.from_document(GEO_DOC)


@pytest.fixture()
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "wiring.db"))
    yield instance
    instance.close()


class _Payload:
    def __init__(self, url="https://example.test/x"):
        self.url, self.label, self.body = url, "", b"{}"
        self.status, self.content_type = 200, "application/json"

    def json(self):
        return {}


class _Outcome:
    def __init__(self, url):
        self.outcome, self.url, self.status = "ok", url, 200
        self.latency_ms, self.attempts, self.detail = 1.0, 1, ""
        self.body_sha256, self.url_sha256 = "0" * 64, "1" * 64
        self.payload = _Payload(url)
        self.succeeded = True


class _Client:
    def fetch(self, spec, *, now, auth=None, **kwargs):
        return _Outcome(spec.url)

    def pause(self, seconds):
        pass


def _fire(source, domain, score, country="TW"):
    return ObservationDraft(
        signal_source=source, domain=domain, country=country,
        status=STATUS_FIRED, raw_score=score, value=f"{source} fired",
        reason=f"{source} test firing")


def _adapter(name, category, drafts):
    return SourceAdapter(
        adapter_id=AdapterId(name), category=category,
        cadence=Window.from_days(1.0, cadence_sec=1.0),
        requests=(RequestSpec(url=f"https://{name}.test/x"),),
        normalize=lambda payload, context, _d=drafts: tuple(_d),
        freshness_horizon_sec=86400.0, rate_limit_group=name)


def _registry():
    """Three domains, each well above the caps this test moves."""
    return AdapterRegistry([
        _adapter("threatfox", "cyber", (_fire("threatfox", CYBER, 4.0),)),
        _adapter("ripe_atlas", "physical",
                 (_fire("ripe_atlas", PHYSICAL, 4.0),)),
        _adapter("gdelt", "info", (_fire("gdelt", INFO, 4.0),)),
    ])


def _post_override(store, *, value, now, key=KEY):
    read = ReadContext(ledger=ReadOnlyLedger(store), now=now,
                       scenarios=(ScenarioRef(scenario_id=SCENARIO),),
                       config=ConfigResolver({}))
    context = WriteContext(
        read=read, ledger=CommandLedger(store),
        principal=Principal(user_id="u-1", role="analyst"),
        body={"value": value, "reason": "配線検証のための暫定変更"})
    response = handle(
        ApiRequest(method=POST, path=f"{API_PREFIX}/config/{key}",
                   body=context.body, principal=context.principal), context)
    assert response.status in (200, 201), response.as_dict()
    return response


def _run(store, geography, *, now, chain=None):
    return tick_module.run_tick(
        now=now, registry=_registry(), store=store, client=_Client(),
        geography=geography, scenario_ids=(SCENARIO,),
        config=ConfigResolver({}) if chain is None else chain)


class TestTheTickResolvesThroughTheV3Chain:
    def test_the_settings_the_tick_uses_carry_the_override(self, store):
        baseline = scoring_module.settings_for(
            store, config=ConfigResolver({}), at=NOW)
        _post_override(store, value=1.0, now=NOW)
        after = scoring_module.settings_for(
            store, config=ConfigResolver({}), at=LATER)
        assert baseline.domain_cap != 1.0
        assert after.domain_cap == 1.0

    def test_the_environment_layer_reaches_the_tick_too(self, store):
        settings = scoring_module.settings_for(
            store, config=ConfigResolver({KEY: "2.5"}), at=NOW)
        assert settings.domain_cap == 2.5

    def test_an_override_written_later_does_not_reach_an_earlier_tick(
            self, store, geography):
        """The fold is bounded at the tick instant (P7 principle 4).

        Live and replay are one projection: replaying 09:00 must compute
        with the override in force AT 09:00, not with the one an analyst
        wrote at 10:00. An unbounded fold would silently rewrite history
        every time somebody changed a dial.
        """
        _post_override(store, value=1.0, now=LATER)
        settings = scoring_module.settings_for(store,
                                               config=ConfigResolver({}),
                                               at=NOW)
        assert settings.domain_cap != 1.0
        report = _run(store, geography, now=NOW)
        assert report.scoring[SCENARIO]["domains"]["cyber"] == 4.0

    def test_the_resolved_settings_travel_into_the_provenance(self, store,
                                                              geography):
        _post_override(store, value=1.0, now=NOW)
        report = _run(store, geography, now=LATER)
        disclosed = report.scoring[SCENARIO]["provenance"]["inputs"]
        assert disclosed["domain_cap"] == 1.0


class TestAnOverrideChangesAScoredOutcome:
    """The effect verification, end to end and on the ledger."""

    def test_two_ticks_one_override_two_different_scores(self, store,
                                                         geography):
        before = _run(store, geography, now=NOW)
        _post_override(store, value=1.0, now=NOW + 1.0)
        after = _run(store, geography, now=LATER)

        assert before.scoring[SCENARIO]["score"] > \
            after.scoring[SCENARIO]["score"]
        assert after.scoring[SCENARIO]["domains"]["cyber"] == 1.0

    def test_the_change_is_visible_in_the_tl_ledger(self, store, geography):
        _run(store, geography, now=NOW)
        _post_override(store, value=1.0, now=NOW + 1.0)
        _run(store, geography, now=LATER)

        rows = store.tl_between(SCENARIO, NOW - 1, LATER + 1)
        assert len(rows) == 2
        assert rows[0]["score"] > rows[1]["score"]
        assert rows[1]["cyber"] == 1.0

    def test_a_chain_blind_to_the_override_scores_the_default(self, store,
                                                             geography):
        """The mutation: a resolver whose ledger cannot see the C7 row.

        This is WP-4.1c's blocker reproduced deliberately. If the tick had
        a second configuration path, this would still show 1.0.
        """
        _post_override(store, value=1.0, now=NOW)

        class _Blind:
            def command_records(self, **kwargs):
                return []

        blind = ConfigResolver({})
        settings = scoring_module.settings_for(_Blind(), config=blind,
                                               at=LATER)
        overridden = scoring_module.settings_for(store, config=blind,
                                                 at=LATER)
        assert settings.domain_cap != 1.0
        assert overridden.domain_cap == 1.0


class TestTheAssemblySeamIsCallableOutsideTheTick:
    """C6's blocker: a dry-run needs `ScoringInputs` without a scored tick."""

    def test_assemble_builds_a_scorable_input_from_the_ledger(self, store,
                                                              geography):
        _run(store, geography, now=NOW)
        settings = scoring_module.settings_for(store,
                                               config=ConfigResolver({}),
                                               at=NOW)
        inputs = scoring_module.assemble(
            now=NOW, store=store, geography=geography,
            scenario_ids=(SCENARIO,), settings=settings)
        assert [s.scenario_id for s in inputs.scenarios] == [SCENARIO]
        assert {o.sensor for o in inputs.observations} == {
            "threatfox", "ripe_atlas", "gdelt"}
        assert inputs.settings is settings

    def test_assembly_takes_counterfactual_settings_without_a_ledger_write(
            self, store, geography):
        _run(store, geography, now=NOW)
        counterfactual = scoring_module.settings_for(
            store, config=ConfigResolver({KEY: "0.5"}), at=NOW)
        result = scoring_module.score(scoring_module.assemble(
            now=NOW, store=store, geography=geography,
            scenario_ids=(SCENARIO,), settings=counterfactual))
        assert result.results[SCENARIO].domain_scores["cyber"] == 0.5
        assert store.tl_between(SCENARIO, NOW - 1, NOW + 1)[0]["cyber"] == 4.0


class TestTheTickRefusesTwoScoringPaths:
    def test_a_resolver_and_an_injected_scorer_together_are_refused(
            self, store, geography):
        with pytest.raises(DomainError, match="one scoring path"):
            tick_module.run_tick(
                now=NOW, registry=_registry(), store=store, client=_Client(),
                geography=geography, scenario_ids=(SCENARIO,),
                config=ConfigResolver({}), score=lambda now, cycle: {})

    def test_without_a_resolver_the_tick_is_acquisition_only(self, store,
                                                             geography):
        report = tick_module.run_tick(
            now=NOW, registry=_registry(), store=store, client=_Client(),
            geography=geography, scenario_ids=(SCENARIO,))
        assert report.observations_written == 3
        assert report.scoring == {}
        assert store.tl_between(SCENARIO, NOW - 1, NOW + 1) == []


class TestHysteresisSurvivesTheProcess:
    def test_the_prior_level_is_read_from_the_tl_ledger(self, store,
                                                        geography):
        _run(store, geography, now=NOW)
        prior = scoring_module.prior_state(store, now=LATER,
                                           scenario_ids=(SCENARIO,))
        stored = store.tl_between(SCENARIO, NOW - 1, NOW + 1)[0]
        assert prior.tl_for(SCENARIO) == stored["threat_level"]

    def test_this_ticks_own_row_is_not_its_own_prior(self, store, geography):
        """A re-run of the same instant must resolve the same prior, or
        idempotence dies on the second write."""
        _run(store, geography, now=NOW)
        prior = scoring_module.prior_state(store, now=NOW,
                                           scenario_ids=(SCENARIO,))
        assert prior.tl_for(SCENARIO) is None

    def test_rerunning_the_same_instant_is_still_a_no_op(self, store,
                                                         geography):
        first = _run(store, geography, now=NOW)
        second = _run(store, geography, now=NOW)
        assert first.tick_id == second.tick_id
        assert len(store.tl_between(SCENARIO, NOW - 1, NOW + 1)) == 1
