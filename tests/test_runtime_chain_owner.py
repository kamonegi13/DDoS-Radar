"""§7-2 #115 — the escalation chain's owner is MEASURED, not configured.

WP-4.4 wired the tick and found the trap: `ScoringInputs.chain_country_for`
raises for a scenario with no supplied owner and no declared core country,
`v3/runtime/scoring.py::scenarios_for` supplied neither, and nothing is
focused at start-up — so the first C1 focus command made every later tick
raise, NP3 kept the loop alive around it, and the conclusion stream quietly
stopped. The registered mitigation was an environment constant
(`NOROSHI_V3_CHAIN_COUNTRIES`) an operator had to set.

**The owner rejected the constant**, and the reason is the reason the
original ruling rejected static derivation: production picks the owner as
`max(effective_cores, key=avg_spike)` — the belligerent that is escalating
THIS TICK. A configured constant picks the same country forever, which is
exactly the failure the ruling was written to prevent. An operator-set
constant is that same defect with a human's name on it.

So the composition root performs production's own selection, at the layer
that holds the tick's observations (`v3/runtime/chain.py`), and hands the
answer to the kernel through `ScoringInputs.chain_countries`. The kernel
stays pure: the SELECTION is the orchestrator's step, and now the
orchestrator actually performs it.

Four things are proved here:

  1. **the transcription is production's**, verified by AST against the
     two functions it came from rather than by reading them once.
  2. **the acceptance case the original ruling asked for**: middle_east
     with IL and IR at equal weight selects IR when the observations
     favour IR, and IL when they favour IL.
  3. **focusing a scenario no longer stops the conclusion stream** — and
     the silent-stop shape itself has a regression test, because NP3
     containment is what made the symptom "conclusions stop growing"
     rather than "the process dies".
  4. **the ordering rule's difference from production is registered**,
     with its evidence: v3 does not fetch the input `avg_spike` is
     computed from, so the quantity cannot be reconstructed.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from v3.adapters.types import (CYBER, INFO, PHYSICAL, STATUS_FIRED,
                               AdapterId, ObservationDraft, RequestSpec,
                               SourceAdapter)
from v3.config.resolution import ConfigResolver
from v3.fetch.registry import AdapterRegistry
from v3.kernel.errors import DomainError
from v3.kernel.window import Window
from v3.ledger.store import LedgerStore
from v3.runtime import chain as chain_module
from v3.runtime import geo as geo_module
from v3.runtime import scoring as scoring_module
from v3.runtime import tick as tick_module
from v3.runtime.loop import Runtime
from v3.scoring import CountryWeight, Observation, Participant, Scenario
from v3.kernel import Ratio

REPO_ROOT = Path(__file__).resolve().parent.parent
NOW = 1_800_000_000.0
LATER = NOW + 3600.0
DUAL = "middle_east"
SINGLE = "taiwan_contingency"
#: A dual-core scenario carrying a NON-belligerent at the weight floor.
#: Without it the role half of the transcription is untested: middle_east's
#: only heavy participants are its two belligerents, so a port that
#: ignored `role` would agree with a port that read it.
DUAL_HEAVY_ALLY = "heavy_ally"

GEO_DOC = {
    "COUNTRY_COORDS": {
        "IL": {"lat": 31.5, "lng": 34.8, "name": "Israel"},
        "IR": {"lat": 32.4, "lng": 53.7, "name": "Iran"},
        "TW": {"lat": 23.7, "lng": 121.0, "name": "Taiwan"},
        "CN": {"lat": 35.0, "lng": 105.0, "name": "China"},
    },
    "SCENARIOS": {
        DUAL: {
            "core_country": None,
            "participants": {
                "IL": {"weight": 1.0, "role": "principal_belligerent"},
                "IR": {"weight": 1.0, "role": "principal_belligerent"},
                "LB": {"weight": 0.7, "role": "proxy_front"},
            },
        },
        SINGLE: {
            "core_country": "TW",
            "participants": {"TW": {"weight": 1.0, "role": "primary_target"},
                             "CN": {"weight": 0.7, "role": "adversary"}},
        },
        DUAL_HEAVY_ALLY: {
            "core_country": None,
            "participants": {
                "IL": {"weight": 1.0, "role": "principal_belligerent"},
                "IR": {"weight": 1.0, "role": "principal_belligerent"},
                "US": {"weight": 1.0, "role": "force_projection"},
            },
        },
    },
}


# ── helpers ───────────────────────────────────────────────────────────────
def _scenario(scenario_id=DUAL):
    return scoring_module.scenarios_for(
        geo_module.from_document(GEO_DOC), [scenario_id])[0]


def _obs(country, score, *, domain=CYBER, sensor="threatfox",
         status=STATUS_FIRED, suppressed=False):
    return Observation(
        sensor=sensor, domain=domain, status=status, score=score,
        signal_source=sensor, suppressed=suppressed,
        countries=(CountryWeight(country, Ratio(1.0)),))


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

    def close(self):
        pass


def _draft(source, domain, country, score):
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


def _registry(*, hot: str, cold: str):
    """Three domains firing for `hot`, one weak reading for `cold`."""
    return AdapterRegistry([
        _adapter("threatfox", "cyber", (_draft("threatfox", CYBER, hot, 4.0),
                                        _draft("threatfox", CYBER, cold, 1.0))),
        _adapter("ripe_atlas", "physical",
                 (_draft("ripe_atlas", PHYSICAL, hot, 3.0),)),
        _adapter("gdelt", "info", (_draft("gdelt", INFO, hot, 2.0),)),
    ])


@pytest.fixture()
def geography():
    return geo_module.from_document(GEO_DOC)


@pytest.fixture()
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "chain.db"))
    yield instance
    instance.close()


# ── 1. the transcription is production's ──────────────────────────────────
class TestTheSelectionRuleIsProductions:
    """AST-verified against the two functions it was transcribed from.

    Read once and copied is how WP-2.6 found 97 transcription
    infidelities in values that looked correctly copied. These parse the
    production source (they do NOT import it) and assert the shape the
    port claims to reproduce.
    """

    def _assignment(self, path, lineno):
        tree = ast.parse(Path(path).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and node.lineno <= lineno \
                    <= (node.end_lineno or node.lineno):
                return ast.unparse(node)
        raise AssertionError(f"no assignment covering {path}:{lineno}")

    def test_the_cited_lines_are_the_primary_ec_selection(self):
        """§7-2 #115 cites radar/routes/core.py:878-881. Verify it."""
        source = self._assignment(REPO_ROOT / "radar/routes/core.py", 879)
        assert source.startswith("primary_ec = max(effective_cores")
        assert "key=lambda ec: target_details.get(ec, {}).get('avg_spike', 0)" \
            in source
        # The tie-break is `max`'s: the FIRST maximal element of a list
        # production sorted alphabetically. Reproduced by `chain_owner`.
        assert "if effective_cores else ''" in source

    def test_the_core_list_is_role_and_weight_from_derive_country_context(self):
        tree = ast.parse((REPO_ROOT / "radar/scenarios.py").read_text())
        fn = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef)
                  and node.name == "derive_country_context")
        body = ast.unparse(fn)
        assert "Role.PRINCIPAL_BELLIGERENT" in body
        assert "p.weight >= 0.9" in body
        assert "effective_cores = sorted(" in body
        assert "effective_cores = [core]" in body

    def test_the_ports_constants_match_that_source(self):
        assert chain_module.PRINCIPAL_BELLIGERENT == "principal_belligerent"
        assert chain_module.CORE_WEIGHT_FLOOR == 0.9

    def test_a_declared_core_country_is_the_whole_core_list(self, geography):
        assert chain_module.effective_cores(_scenario(SINGLE)) == ("TW",)

    def test_a_dual_core_scenario_derives_its_cores_sorted(self):
        assert chain_module.effective_cores(_scenario(DUAL)) == ("IL", "IR")

    def test_a_proxy_front_is_not_a_core_however_heavy(self):
        scenario = Scenario(
            scenario_id="x",
            participants=(Participant("LB", Ratio(1.0), "proxy_front"),))
        assert chain_module.effective_cores(scenario) == ()

    def test_a_heavy_non_belligerent_is_not_a_core(self):
        assert chain_module.effective_cores(
            _scenario(DUAL_HEAVY_ALLY)) == ("IL", "IR")

    def test_a_belligerent_below_the_weight_floor_is_not_a_core(self):
        scenario = Scenario(
            scenario_id="x",
            participants=(Participant("IL", Ratio(0.89),
                                      "principal_belligerent"),
                          Participant("IR", Ratio(0.9),
                                      "principal_belligerent")))
        assert chain_module.effective_cores(scenario) == ("IR",)


# ── 2. the obstacle, and what stands in for it ────────────────────────────
class TestTheAvgSpikeObstacleIsRealAndRegistered:
    """Why the ordering quantity is not production's, with the evidence.

    `avg_spike` (core.py:817) is `target_weighted_spike / max(
    total_local_pct, 5.0)` over the per-target ATTACK ORIGIN distribution
    (core.py:747-748) against a 90-day origin baseline (core.py:741-742).
    §7-2 #9 already records that v3 computes it nowhere; the harder fact
    is below — v3 never fetches the endpoint it is computed FROM, so this
    is not a derivation gap that L1 wiring could close.
    """

    def test_v3_never_fetches_the_origin_endpoint_avg_spike_needs(self):
        from v3.adapters.cyber.cloudflare_radar import \
            CLOUDFLARE_RADAR_ADAPTER
        urls = [spec.url for spec in CLOUDFLARE_RADAR_ADAPTER.requests]
        assert urls, "the adapter declares requests"
        assert not any("locations/origin" in url for url in urls), (
            "if v3 ever fetches the per-target origin distribution, "
            "avg_spike becomes reconstructible and §7-2's registered "
            "difference for the ordering rule must be revisited")

    def test_production_computes_avg_spike_from_that_endpoint(self):
        source = (REPO_ROOT / "radar/routes/core.py").read_text()
        assert "layer3/top/locations/origin" in source
        assert "avg_spike_record = round(target_weighted_spike" in source

    def test_the_stand_in_is_this_ticks_admitted_evidence(self):
        """The smallest honest alternative: a live measurement, not a
        constant. Same default as production's — a country with no
        reading scores 0 (`target_details.get(ec, {}).get('avg_spike',
        0)`)."""
        observations = (_obs("IR", 3.0), _obs("IR", 1.5, domain=INFO,
                                              sensor="gdelt"))
        assert chain_module.escalation_intensity(observations, "IR") == 4.5
        assert chain_module.escalation_intensity(observations, "IL") == 0.0

    def test_a_reading_that_does_not_contribute_score_does_not_rank(self):
        """`admits()` is the kernel's own predicate, not a new one."""
        suppressed = _obs("IL", 9.0, suppressed=True)
        unfired = _obs("IL", 9.0, status="DISABLED")
        zero = _obs("IL", 0.0)
        assert chain_module.escalation_intensity(
            (suppressed, unfired, zero), "IL") == 0.0


# ── 3. THE acceptance test the original ruling asked for ──────────────────
class TestADualCoreScenarioSelectsWhoeverIsEscalating:
    """middle_east: IL and IR at weight 1.0. The static answer is wrong
    forever for exactly this scenario, which is why it is the case the
    ruling named."""

    def test_observations_favouring_ir_select_ir(self):
        scenario = _scenario(DUAL)
        observations = (_obs("IL", 1.0), _obs("IR", 4.0))
        assert chain_module.chain_owner(scenario, observations) == "IR"

    def test_the_same_scenario_with_the_spike_on_il_selects_il(self):
        scenario = _scenario(DUAL)
        observations = (_obs("IL", 4.0), _obs("IR", 1.0))
        assert chain_module.chain_owner(scenario, observations) == "IL"

    def test_the_selection_follows_evidence_across_domains(self):
        scenario = _scenario(DUAL)
        observations = (_obs("IL", 3.0),
                        _obs("IR", 2.0, domain=PHYSICAL, sensor="ripe_atlas"),
                        _obs("IR", 2.0, domain=INFO, sensor="gdelt"))
        assert chain_module.chain_owner(scenario, observations) == "IR"

    def test_a_tie_breaks_the_way_productions_max_breaks_it(self):
        """`max` over a sorted list returns the FIRST maximal element."""
        scenario = _scenario(DUAL)
        assert chain_module.chain_owner(
            scenario, (_obs("IL", 2.0), _obs("IR", 2.0))) == "IL"

    def test_a_quiet_tick_lands_on_the_same_country_both_systems_do(self):
        """Nothing escalating is the one case where a constant is right —
        and production reaches it by the same arithmetic (every core at
        0, `max` returns the first). Stated because a reader will ask why
        a quiet tick looks static."""
        assert chain_module.chain_owner(_scenario(DUAL), ()) == "IL"

    def test_a_single_core_scenario_needs_no_measurement(self):
        assert chain_module.chain_owner(_scenario(SINGLE), ()) == "TW"

    def test_a_scenario_with_no_cores_at_all_has_no_owner(self):
        scenario = Scenario(
            scenario_id="x",
            participants=(Participant("LB", Ratio(0.7), "proxy_front"),))
        assert chain_module.chain_owner(scenario, ()) == ""
        assert chain_module.scenarios_without_cores((scenario,)) == ("x",)
        assert chain_module.chain_owners((scenario,), ()) == {}


# ── 4. the mutation sweep on the selection rule ───────────────────────────
class TestTheSelectionRuleSurvivesNoMutation:
    """Every plausible way to write this wrong, and the test that catches
    it. A selection rule with no mutation coverage is a rule whose tests
    might only be asserting that it returns a string."""

    def _mutants(self):
        floor = chain_module.CORE_WEIGHT_FLOOR

        def picks_the_minimum(scenario, observations):
            cores = chain_module.effective_cores(scenario)
            return min(cores, key=lambda c: chain_module.escalation_intensity(
                observations, c)) if cores else ""

        def picks_the_first_declared(scenario, observations):
            cores = chain_module.effective_cores(scenario)
            return cores[0] if cores else ""

        def picks_by_coupling_weight(scenario, observations):
            cores = chain_module.effective_cores(scenario)
            weights = {p.country: p.weight.value
                       for p in scenario.participants}
            return max(cores, key=lambda c: weights.get(c, 0.0)) \
                if cores else ""

        def ignores_the_role(scenario, observations):
            cores = tuple(sorted(p.country for p in scenario.participants
                                 if p.weight.value >= floor))
            return max(cores, key=lambda c: chain_module.escalation_intensity(
                observations, c)) if cores else ""

        def counts_suppressed_readings(scenario, observations):
            cores = chain_module.effective_cores(scenario)

            def loose(country):
                return sum(o.score for o in observations
                           if any(cw.country == country
                                  for cw in o.countries))
            return max(cores, key=loose) if cores else ""

        return {"minimum": picks_the_minimum,
                "first_declared": picks_the_first_declared,
                "coupling_weight": picks_by_coupling_weight,
                "role_ignored": ignores_the_role,
                "suppression_ignored": counts_suppressed_readings}

    #: (scenario_id, observations, expected) — the assertions above, as data.
    def _cases(self):
        return (
            (DUAL, (_obs("IL", 1.0), _obs("IR", 4.0)), "IR"),
            (DUAL, (_obs("IL", 4.0), _obs("IR", 1.0)), "IL"),
            (DUAL, (_obs("IL", 2.0), _obs("IR", 2.0)), "IL"),
            (DUAL, (_obs("IL", 1.0),
                    _obs("IR", 9.0, suppressed=True)), "IL"),
            (SINGLE, (_obs("CN", 9.0),), "TW"),
            # A force-projection ally at the weight floor is not a core,
            # however loudly it is being hit.
            (DUAL_HEAVY_ALLY, (_obs("US", 9.0), _obs("IR", 2.0)), "IR"),
        )

    def test_the_rule_itself_passes_every_case(self):
        for scenario_id, observations, expected in self._cases():
            assert chain_module.chain_owner(
                _scenario(scenario_id), observations) == expected

    @pytest.mark.parametrize("name", sorted({
        "minimum", "first_declared", "coupling_weight", "role_ignored",
        "suppression_ignored"}))
    def test_every_mutant_is_caught_by_at_least_one_case(self, name):
        mutant = self._mutants()[name]
        caught = [expected for scenario_id, observations, expected
                  in self._cases()
                  if mutant(_scenario(scenario_id), observations) != expected]
        assert caught, f"mutant {name!r} survives the whole case set"


# ── 5. the wiring: the tick performs the selection ────────────────────────
class TestTheTickSelectsTheOwnerFromItsOwnObservations:
    def test_assemble_fills_chain_countries_from_the_ledger(self, store,
                                                            geography):
        tick_module.run_tick(
            now=NOW, registry=_registry(hot="IR", cold="IL"), store=store,
            client=_Client(), geography=geography, scenario_ids=(DUAL,),
            config=ConfigResolver({}))
        inputs = scoring_module.assemble(
            now=NOW, store=store, geography=geography, scenario_ids=(DUAL,),
            settings=scoring_module.settings_for(store,
                                                 config=ConfigResolver({}),
                                                 at=NOW))
        assert inputs.chain_countries[DUAL] == "IR"
        assert inputs.chain_country_for(inputs.scenarios[0]) == "IR"

    def test_the_other_belligerent_wins_when_the_evidence_moves(self, store,
                                                                geography):
        tick_module.run_tick(
            now=NOW, registry=_registry(hot="IL", cold="IR"), store=store,
            client=_Client(), geography=geography, scenario_ids=(DUAL,),
            config=ConfigResolver({}))
        inputs = scoring_module.assemble(
            now=NOW, store=store, geography=geography, scenario_ids=(DUAL,),
            settings=scoring_module.settings_for(store,
                                                 config=ConfigResolver({}),
                                                 at=NOW))
        assert inputs.chain_countries[DUAL] == "IL"

    def test_the_tick_discloses_who_it_selected(self, store, geography):
        """NP6: a bonus computed for a country nobody can name afterwards
        is a bonus nobody can check."""
        report = tick_module.run_tick(
            now=NOW, registry=_registry(hot="IR", cold="IL"), store=store,
            client=_Client(), geography=geography, scenario_ids=(DUAL,),
            config=ConfigResolver({}))
        assert report.chain_owners[DUAL] == "IR"
        assert report.as_dict()["chain_owners"][DUAL] == "IR"

    def test_scenarios_for_carries_the_declared_core_country(self,
                                                            geography):
        single = scoring_module.scenarios_for(geography, [SINGLE])[0]
        dual = scoring_module.scenarios_for(geography, [DUAL])[0]
        assert single.core_country == "TW"
        assert dual.core_country is None


# ── 6. the silent stop, which is what #115 was actually about ─────────────
class TestFocusNoLongerStopsTheConclusionStream:
    def _focus(self, store, scenario_id, *, at):
        from v3.api.dispatch import handle
        from v3.api.readonly import ReadOnlyLedger
        from v3.api.request import (ApiRequest, Principal, ReadContext,
                                    ScenarioRef)
        from v3.api.vocabulary import API_PREFIX, POST
        from v3.api.write import WriteContext
        from v3.api.writeonly import CommandLedger

        read = ReadContext(
            ledger=ReadOnlyLedger(store), now=at,
            scenarios=(ScenarioRef(scenario_id=scenario_id),),
            config=ConfigResolver({}))
        context = WriteContext(
            read=read, ledger=CommandLedger(store),
            principal=Principal(user_id="u-1", role="analyst"),
            body={"scenario_id": scenario_id,
                  "reason": "系列連鎖の所有国を実測で選ぶ検証"})
        response = handle(
            ApiRequest(method=POST, path=f"{API_PREFIX}/focus",
                       body=context.body, principal=context.principal),
            context)
        assert response.status in (200, 201), response.as_dict()

    def test_a_focused_dual_core_scenario_still_scores(self, store,
                                                       geography):
        registry = _registry(hot="IR", cold="IL")
        tick_module.run_tick(
            now=NOW, registry=registry, store=store, client=_Client(),
            geography=geography, scenario_ids=(DUAL,),
            config=ConfigResolver({}))
        report = tick_module.run_tick(
            now=LATER, registry=registry, store=store, client=_Client(),
            geography=geography, scenario_ids=(DUAL,),
            config=ConfigResolver({}), focused_scenario_id=DUAL)
        assert report.scoring[DUAL]["scoring_mode"] == "full"
        assert report.conclusions[DUAL]

    def test_the_conclusion_stream_keeps_growing_after_a_focus(self, store,
                                                               geography):
        """The regression proper. Before the fix this second tick raised,
        NP3 swallowed it into a counter, and `count_conclusions()` stopped
        moving while the process looked healthy."""
        registry = _registry(hot="IR", cold="IL")
        tick_module.run_tick(
            now=NOW, registry=registry, store=store, client=_Client(),
            geography=geography, scenario_ids=(DUAL,),
            config=ConfigResolver({}))
        self._focus(store, DUAL, at=NOW + 1.0)
        before = store.count_conclusions()
        tick_module.run_tick(
            now=LATER, registry=registry, store=store, client=_Client(),
            geography=geography, scenario_ids=(DUAL,),
            config=ConfigResolver({}), focused_scenario_id=DUAL)
        assert store.count_conclusions() > before


class TestASilentStopCannotHappenUnnoticed:
    """NP3 keeps the loop alive through a bad tick — that is the design,
    and it is also what turned #115 from a crash into a silence. The
    containment must therefore be OBSERVABLE: a loop that survives must
    say so in `status()`, or the next defect of this shape is invisible
    in the same way."""

    def test_the_loop_survives_a_raising_tick(self):
        calls = []

        def failing(now):
            calls.append(now)
            raise DomainError("chain owner missing")

        runtime = Runtime(failing, interval_sec=0.01,
                          clock=lambda: NOW, on_error=lambda exc: None)
        with runtime:
            for _ in range(200):
                if len(calls) >= 2:
                    break
            runtime.stop(timeout_sec=5)
        assert len(calls) >= 1

    def test_the_failure_is_counted_and_named_not_swallowed(self):
        def failing(now):
            raise DomainError("'middle_east' declares no core_country")

        runtime = Runtime(failing, clock=lambda: NOW)
        with pytest.raises(DomainError):
            runtime.run_once()
        status = runtime.status()
        assert status.errors == 1
        assert status.ticks == 0
        assert "middle_east" in status.last_error
        assert "DomainError" in status.last_error

    def test_a_surviving_loop_that_writes_nothing_is_visible_in_status(self):
        """The exact silent-stop shape, as a value a reader can test:
        ticks stop advancing while the loop keeps running."""
        def failing(now):
            raise DomainError("boom")

        runtime = Runtime(failing, clock=lambda: NOW)
        for _ in range(3):
            with pytest.raises(DomainError):
                runtime.run_once()
        status = runtime.status()
        assert (status.ticks, status.errors) == (0, 3)
        assert status.last_tick_at is None


# ── 7. the constant is gone ───────────────────────────────────────────────
class TestNoOperatorConstantRemains:
    def test_the_environment_key_is_not_honoured_anywhere(self):
        from v3.server import settings as settings_module
        assert not hasattr(settings_module, "CHAIN_COUNTRIES_KEY")
        assert not any("CHAIN_COUNTRIES" in key
                       for key in settings_module.KEY_IDS)
        assert not any("CHAIN_COUNTRIES" in row["key"]
                       for row in settings_module.describe())

    def test_setting_the_retired_key_changes_nothing(self, tmp_path):
        """Inert even when present. `SECRETS.from_environment` reads only
        the derived name set, so a leftover value in a compose file or a
        shell profile cannot quietly pin an owner again."""
        from v3.server import settings as settings_module
        built = settings_module.from_environment({
            settings_module.LEDGER_PATH_KEY: str(tmp_path / "v3.db"),
            "NOROSHI_V3_CHAIN_COUNTRIES": "middle_east:IL"})
        assert not hasattr(built, "chain_countries")
        assert "chain_countries" not in built.as_dict()

    def test_assemble_takes_no_supplied_owner(self):
        import inspect
        signature = inspect.signature(scoring_module.assemble)
        assert "chain_countries" not in signature.parameters, (
            "a supplied-owner seam is the constant coming back in by "
            "another door; the owner is measured per tick")
