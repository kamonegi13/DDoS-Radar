"""§7-2 #123 — the escalation chain's input.

`v3/scoring/sequence.py` was a finished state machine with no supply:
`ScoringInputs.arriving_events` defaulted to `()` and neither the live
tick nor the parity driver ever set it. Every kernel test passed, because
kernel tests hand the events in directly; the detection was dead anyway.

What is asserted here, in order:

  table        every production registration site is accounted for —
               either transcribed into `REGISTRATIONS` or named in
               `ABSENCES` with a reason (AST over `radar/routes/core.py`)
  gate         `passes_gate()`, never `admits()` (CLAUDE.md §5)
  ownership    the scenario's effective cores, and only from that
               country's OWN reading
  supply       the live tick and the parity driver derive the SAME events
               from the same rows (the #38 lesson)
  shape        `ScoringInputs` cannot be built without deciding
  coverage     two of four chain links, stated rather than implied
"""
import ast
import pathlib

import pytest

from v3.adapters.types import (CYBER, PHYSICAL, ObservationDraft,
                               STATUS_FIRED, STATUS_OBSERVED, STATUS_OK)
from v3.kernel.errors import DomainError
from v3.runtime import attribution as A
from v3.runtime import events as E
from v3.scoring import (CountryWeight, Observation, Participant, Scenario,
                        ScoringInputs, ScoringSettings)

NOW = 1_786_000_000.0
REPO = pathlib.Path(__file__).resolve().parents[1]
CORE = REPO / "radar" / "routes" / "core.py"


def _scenario(scenario_id="middle_east", cores=("IL", "IR"), enabled=True):
    return Scenario(
        scenario_id=scenario_id,
        participants=tuple(
            Participant(country=c, weight=1.0, role="principal_belligerent")
            for c in cores) + (Participant(country="US", weight=0.5,
                                           role="primary_ally"),),
        enabled=enabled)


def _ooni_draft(country, *, score, status=STATUS_FIRED, suppressed=False):
    return ObservationDraft(
        signal_source="ooni_censorship", domain=CYBER, country=country,
        status=status, raw_score=score, suppressed=suppressed,
        suppress_reason="analyst_mute" if suppressed else None,
        value="anomaly=0.4 confirmed=0.2")


def _ooni_rungs(*drafts):
    """The rung rows §7-2 #127's fold emits, isolated from the rest."""
    return tuple(d for d in A.collapse("ooni_censorship", drafts,
                                       cores=("IL", "IR"))
                 if d.signal_source == A.OONI_HEAVY)


def _obs(signal_source, country, *, status=STATUS_FIRED, score=2.0,
         at=NOW - 30.0, sensor=None, suppressed=False):
    return Observation(
        sensor=sensor or signal_source, domain=PHYSICAL, status=status,
        score=score, signal_source=signal_source,
        countries=((CountryWeight(country, 1.0),) if country else ()),
        suppressed=suppressed,
        suppress_reason="analyst_mute" if suppressed else None,
        observed_at=at, value="x")


# ══ 1. the table is production's, and nothing is missing from it ═════════

class TestEveryProductionSiteIsAccountedFor:
    """The audit that makes an omission loud.

    A registration site production has and this module names in neither
    `REGISTRATIONS` nor `ABSENCES` is a chain link that vanishes without
    anyone deciding it should — which is what #123 was.
    """

    @staticmethod
    def _production_event_types():
        tree = ast.parse(CORE.read_text())
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or \
                getattr(node.func, "attr", None)
            if name not in ("_seq_fire", "register_sequence_event"):
                continue
            # the event type is the SECOND positional in both signatures
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                found.add(node.args[1].value)
        return found

    def test_production_registers_the_types_we_transcribed(self):
        production = self._production_event_types()
        # the AST pass must actually find the sites, or it proves nothing
        assert len(production) >= 6, production
        accounted = ({entry.event_type for entry in E.REGISTRATIONS}
                     | {entry.event_type for entry in E.ABSENCES})
        assert production - accounted == set(), production - accounted

    def test_nothing_is_claimed_that_production_does_not_register(self):
        production = self._production_event_types()
        claimed = {entry.event_type for entry in E.REGISTRATIONS}
        assert claimed - production == set()

    def test_every_absence_states_a_direction_and_a_reason(self):
        for entry in E.ABSENCES:
            assert entry.reason and entry.register_ref
            assert entry.direction in ("insensitive", "sensitive", "neutral")

    def test_the_chain_vocabulary_is_the_kernels(self):
        from v3.scoring.thresholds import SEQUENCE_CHAIN_TYPES
        assert set(SEQUENCE_CHAIN_TYPES) == {
            E.NARRATIVE_BURST, E.ISR_SURGE, E.SYNC_DDOS, E.FIRMS_ANOMALY}

    def test_the_production_refs_point_at_a_registration(self):
        """A citation that does not name the line it claims is a citation
        nobody can check."""
        lines = CORE.read_text().split("\n")
        for entry in E.REGISTRATIONS:
            first = int(entry.production_ref.split(":")[1].split("-")[0])
            last = int(entry.production_ref.split(":")[1].split("-")[1])
            window = "\n".join(lines[first - 1:last])
            assert "_seq_fire" in window, entry
            assert entry.event_type in window, entry


# ══ 2. the gate is production's, and it is passes_gate ═══════════════════

class TestTheGateIsAddRatsReturn:
    def test_a_fired_reading_registers(self):
        events = E.arriving_from((_obs("isr_hotspot", "IL"),), (_scenario(),))
        assert [(e.country, e.event_type) for e in events] == [
            ("IL", "ISR_SURGE")]

    def test_a_quiet_reading_registers_nothing(self):
        assert E.arriving_from((_obs("isr_hotspot", "IL", status=STATUS_OK,
                                     score=0.0),), (_scenario(),)) == ()

    def test_a_suppressed_reading_registers_nothing(self):
        """CLAUDE.md §5: the scoring layer registers only when `add_rat()`
        returned True, and suppression is exactly what makes it False."""
        assert E.arriving_from((_obs("isr_hotspot", "IL", suppressed=True),),
                               (_scenario(),)) == ()

    def test_an_observed_reading_registers_nothing(self):
        assert E.arriving_from((_obs("isr_hotspot", "IL",
                                     status=STATUS_OBSERVED, score=0.0),),
                               (_scenario(),)) == ()

    def test_the_gate_has_no_score_condition(self):
        """`add_rat` returns `status == "FIRED" and not _is_muted`
        (`core.py:997`) — no score test. A FIRED row scoring 0 still gates
        its link, which is the property `admits()` would have deleted."""
        events = E.arriving_from((_obs("isr_hotspot", "IL", score=0.0),),
                                 (_scenario(),))
        assert len(events) == 1

    def test_suppression_and_score_zero_are_different_facts(self):
        zero = _obs("isr_hotspot", "IL", score=0.0)
        muted = _obs("isr_hotspot", "IL", score=2.0, suppressed=True)
        assert zero.passes_gate() is True and zero.admits() is False
        assert muted.passes_gate() is False


class TestTheOoniRungIsTheHeavyBranch:
    """Production registers CENSORSHIP_DETECTED on `_ooni_heavy`
    (`core.py:1710`), not on `_ooni_censoring` which is what makes the row
    FIRE (`core.py:1707`). Heavy is the rung that scores 2.

    Since §7-2 #127 the per-country `ooni_censorship` row no longer carries
    that score — it moved to the countryless row — so the rung is a row of
    its own (`attribution.OONI_HEAVY`), emitted by the same fold that moved
    the score and gated on the same two facts production reads.
    """

    def test_the_scoring_row_can_no_longer_anchor_anything(self):
        """The countryless row is where the score went, and a row with no
        country anchors nothing — which is why the rung needed a face."""
        assert E.arriving_from(
            (_obs("ooni_censorship", "", score=2.0),), (_scenario(),)) == ()
        assert E.arriving_from(
            (_obs("ooni_censorship", "IL", score=2.0),), (_scenario(),)) == ()

    def test_censoring_but_not_heavy_emits_no_rung(self):
        assert _ooni_rungs(_ooni_draft("IL", score=1.0)) == ()

    def test_heavy_registers_through_the_rung(self):
        rungs = _ooni_rungs(_ooni_draft("IL", score=2.0))
        assert [d.signal_source for d in rungs] == [A.OONI_HEAVY]
        assert rungs[0].raw_score == 0.0        # gates, never scores
        events = E.arriving_from(
            (_obs(A.OONI_HEAVY, "IL", score=0.0),), (_scenario(),))
        assert [e.event_type for e in events] == ["CENSORSHIP_DETECTED"]

    def test_a_muted_heavy_reading_emits_no_rung(self):
        """`_ooni_active` is the other half of production's condition."""
        assert _ooni_rungs(
            _ooni_draft("IL", score=2.0, status=STATUS_OK)) == ()
        assert _ooni_rungs(
            _ooni_draft("IL", score=2.0, suppressed=True)) == ()

    def test_the_rung_and_the_flag_agree_over_the_whole_input_space(self):
        """A differential sweep, because reading the gate off the ladder is
        only sound while the ladder and the flag stay in step."""
        import random

        from v3.adapters.cyber import ooni_censorship as OONI
        rng = random.Random(4242)
        seen_heavy = seen_light = 0
        for _ in range(4000):
            anomaly = round(rng.uniform(0.0, 1.0), 4)
            confirmed = round(rng.uniform(0.0, anomaly), 4)
            is_censoring, is_heavy, _ = OONI.verdict(anomaly, confirmed)
            score = 2.0 if is_heavy else (1.0 if is_censoring else 0.0)
            emitted = _ooni_rungs(_ooni_draft(
                "IL", score=score,
                status=STATUS_FIRED if is_censoring else STATUS_OK))
            assert bool(emitted) is bool(is_heavy)
            seen_heavy += bool(is_heavy)
            seen_light += bool(is_censoring and not is_heavy)
        assert seen_heavy and seen_light   # the sweep reached both branches


# ══ 3. who the event belongs to ══════════════════════════════════════════

class TestTheEventBelongsToAnEffectiveCore:
    def test_a_non_core_participant_anchors_nothing(self):
        """`register_sequence_event` refuses an empty theatre and
        production's targets are the effective cores in every branch of
        `resolve_seq_fire_targets`."""
        assert E.arriving_from((_obs("isr_hotspot", "US"),),
                               (_scenario(),)) == ()

    def test_a_disabled_scenario_contributes_no_cores(self):
        assert E.arriving_from((_obs("isr_hotspot", "IL"),),
                               (_scenario(enabled=False),)) == ()

    def test_a_declared_core_country_is_the_whole_list(self):
        taiwan = Scenario(
            scenario_id="taiwan_contingency", core_country="TW",
            participants=(Participant(country="TW", weight=1.0,
                                      role="primary_target"),
                          Participant(country="CN", weight=1.0,
                                      role="principal_belligerent")))
        assert E.eligible_countries((taiwan,)) == frozenset({"TW"})

    def test_each_core_answers_for_itself(self):
        """v3 registers from the country's OWN reading. Production's
        dual-core spill — the primary's reading also firing on the
        secondary because `resolve_seq_fire_targets`' guard is bypassed
        when `core_theater` is empty — is a registered difference, not
        copied: it attaches an event to a chain whose sensor data was
        never inspected."""
        events = E.arriving_from((_obs("isr_hotspot", "IL"),), (_scenario(),))
        assert {e.country for e in events} == {"IL"}

    def test_two_scenarios_union_their_cores(self):
        other = _scenario("taiwan_contingency", cores=("TW",))
        assert E.eligible_countries((_scenario(), other)) == frozenset(
            {"IL", "IR", "TW"})


class TestTheTimestampIsTheObservations:
    def test_occurred_at_is_the_reading_not_the_tick(self):
        events = E.arriving_from((_obs("isr_hotspot", "IL", at=NOW - 5000),),
                                 (_scenario(),), now=NOW)
        assert events[0].occurred_at == NOW - 5000

    def test_a_still_in_force_reading_mints_the_same_event_each_tick(self):
        """Which is what lets `advance()`'s 300 s dedup collapse it. With
        `now` as the stamp, a row in force for four ticks would look like
        four fresh links and the chain's decay term would never age."""
        reading = _obs("isr_hotspot", "IL", at=NOW - 5000)
        first = E.arriving_from((reading,), (_scenario(),), now=NOW)
        later = E.arriving_from((reading,), (_scenario(),), now=NOW + 900)
        assert first == later

    def test_a_reading_with_no_timestamp_falls_back_to_now(self):
        stampless = Observation(
            sensor="isr_hotspot", domain=PHYSICAL, status=STATUS_FIRED,
            score=2.0, signal_source="isr_hotspot",
            countries=(CountryWeight("IL", 1.0),))
        assert E.arriving_from((stampless,), (_scenario(),),
                               now=NOW)[0].occurred_at == NOW
        assert E.arriving_from((stampless,), (_scenario(),)) == ()

    def test_the_order_is_stable(self):
        readings = (_obs("gps_jamming", "IR", at=NOW - 10),
                    _obs("isr_hotspot", "IL", at=NOW - 20),
                    _obs("ais_maritime", "IL", at=NOW - 20))
        stamps = [(e.occurred_at, e.country, e.event_type)
                  for e in E.arriving_from(readings, (_scenario(),))]
        assert stamps == sorted(stamps)


# ══ 4. the supply reaches BOTH callers, identically ══════════════════════

@pytest.fixture
def store(tmp_path):
    from v3.ledger import LedgerStore
    instance = LedgerStore(str(tmp_path / "events.db"))
    yield instance
    instance.close()


def _write(store, signal_source, country, *, at, status=STATUS_FIRED,
           score=2.0, sensor=None):
    from v3.kernel import Evidence
    from v3.ledger.records import SignalObservation
    store.append_signal(SignalObservation(
        tick_id=f"t{int(at)}", sensor=sensor or signal_source,
        signal_source=signal_source, domain="physical", country=country,
        evidence=Evidence.observe({}, observed_at=at,
                                  freshness_horizon_sec=86400.0,
                                  source=signal_source),
        status=status, raw_score=score, flags={}), now=at)


class TestBothCallersSupplyTheSameEvents:
    def test_assemble_derives_rather_than_defaults(self, store):
        from v3.runtime.scoring import assemble
        _write(store, "isr_hotspot", "IL", at=NOW - 30)
        inputs = assemble(now=NOW, store=store, settings=ScoringSettings(),
                          scenarios=(_scenario(),))
        assert [e.event_type for e in inputs.arriving_events] == ["ISR_SURGE"]

    def test_the_parity_driver_derives_the_same_set(self, store):
        """The #38 lesson: a harness that manufactures its own version of
        an input measures agreement about a system nobody runs."""
        from v3.parity.driver_v3 import replay
        from v3.runtime.scoring import assemble
        _write(store, "isr_hotspot", "IL", at=NOW - 30)
        _write(store, "nasa_eonet", "IR", at=NOW - 30)
        live = assemble(now=NOW, store=store, settings=ScoringSettings(),
                        scenarios=(_scenario(),))

        seen = {}
        import v3.parity.driver_v3 as driver
        real = driver.score_tick

        def capture(inputs):
            seen["arriving"] = inputs.arriving_events
            return real(inputs)

        driver.score_tick = capture
        try:
            replay(store, (_scenario(),), start=NOW, end=NOW,
                   tick_interval_sec=900.0)
        finally:
            driver.score_tick = real
        assert seen["arriving"] == live.arriving_events
        assert seen["arriving"]

    def test_the_history_gives_the_chain_more_than_one_tick_of_memory(
            self, store):
        """Supplying `arriving_events` alone would have fixed #123 in form
        only: `run_tick` carries no state, so `prior.sequence_events` left
        at `()` gives the chain a one-tick memory and a 24 h chain can
        never assemble."""
        from v3.runtime.scoring import assemble
        _write(store, "isr_hotspot", "IL", at=NOW - 40000)
        _write(store, "nasa_eonet", "IL", at=NOW - 30)
        inputs = assemble(now=NOW, store=store, settings=ScoringSettings(),
                          scenarios=(_scenario(),))
        assert {e.event_type for e in inputs.prior.sequence_events} == {
            "ISR_SURGE", "FIRMS_ANOMALY"}

    def test_the_history_stops_at_the_retention_window(self, store):
        from v3.runtime.scoring import assemble
        settings = ScoringSettings()
        _write(store, "isr_hotspot", "IL",
               at=NOW - settings.sequence_window_sec - 60)
        inputs = assemble(now=NOW, store=store, settings=settings,
                          scenarios=(_scenario(),))
        assert inputs.prior.sequence_events == ()

    def test_the_chain_actually_advances_through_the_kernel(self, store):
        from v3.runtime.scoring import assemble, score
        _write(store, "isr_hotspot", "IL", at=NOW - 30)
        _write(store, "nasa_eonet", "IL", at=NOW - 60)
        result = score(assemble(now=NOW, store=store,
                                settings=ScoringSettings(),
                                scenarios=(_scenario(),),
                                focused_scenario_id="middle_east"))
        assert {e.event_type for e in result.next_sequence_events} == {
            "ISR_SURGE", "FIRMS_ANOMALY"}

    def test_temporal_coherence_becomes_reachable(self, store):
        """Two theatres inside 10 s is the bonus the empty input made
        unreachable — and the one the two supplied links CAN reach."""
        from v3.runtime.scoring import assemble, score
        _write(store, "isr_hotspot", "IL", at=NOW - 30)
        _write(store, "isr_hotspot", "IR", at=NOW - 28)
        result = score(assemble(now=NOW, store=store,
                                settings=ScoringSettings(),
                                scenarios=(_scenario(),),
                                focused_scenario_id="middle_east"))
        assert result.results["middle_east"].bonuses.temporal_coherence > 0


# ══ 5. the shape: the omission cannot recur silently ═════════════════════

class TestTheInputCannotBeBuiltWithoutDeciding:
    def test_omitting_arriving_events_is_a_construction_error(self):
        with pytest.raises(TypeError):
            ScoringInputs(now=NOW, observations=(),
                          scenarios=(_scenario(),),
                          settings=ScoringSettings())

    def test_an_explicit_empty_set_is_allowed(self):
        inputs = ScoringInputs(now=NOW, observations=(),
                               scenarios=(_scenario(),),
                               settings=ScoringSettings(),
                               arriving_events=())
        assert inputs.arriving_events == ()

    def test_the_field_still_validates_its_members(self):
        with pytest.raises(DomainError):
            ScoringInputs(now=NOW, observations=(),
                          scenarios=(_scenario(),),
                          settings=ScoringSettings(),
                          arriving_events=("ISR_SURGE",))

    def test_a_round_trip_survives_the_new_field_order(self):
        import pickle
        inputs = ScoringInputs(
            now=NOW, observations=(), scenarios=(_scenario(),),
            settings=ScoringSettings(),
            arriving_events=E.arriving_from((_obs("isr_hotspot", "IL"),),
                                            (_scenario(),)),
            focused_scenario_id="middle_east")
        assert pickle.loads(pickle.dumps(inputs)) == inputs


# ══ 6. what is still missing, said out loud ══════════════════════════════

class TestTheRemainderIsDisclosed:
    def test_two_of_four_chain_links_are_supplied(self):
        coverage = E.chain_coverage()
        assert coverage["supplied"] == ["ISR_SURGE", "FIRMS_ANOMALY"]
        assert coverage["missing"] == ["NARRATIVE_BURST", "SYNC_DDOS"]

    def test_the_chain_bonus_is_still_unreachable_and_says_so(self):
        """Honesty over optimism: three link types are the minimum tier,
        so two supplied links cannot produce a chain bonus at all. A fix
        that left this unsaid would read as 'the chain works now'."""
        coverage = E.chain_coverage()
        assert coverage["chain_bonus_reachable"] is False
        assert coverage["minimum_for_a_bonus"] == 3

    def test_the_missing_links_name_their_register_rows(self):
        rows = {item["event_type"]: item
                for item in E.chain_coverage()["absences"]}
        assert "#122" in rows["SYNC_DDOS"]["register_ref"]
        assert rows["SYNC_DDOS"]["direction"] == "insensitive"
        assert rows["NARRATIVE_BURST"]["direction"] == "insensitive"

    def test_the_narrative_fold_really_does_withhold(self, store):
        """The stated reason, measured rather than asserted: if
        `rss_narrative` ever starts firing, this test fails and the
        absence row is out of date."""
        from v3.runtime import reduce as R
        from v3.adapters.types import ObservationDraft, INFO
        drafts = (ObservationDraft(
            signal_source="narrative_tass", domain=INFO, country="IL",
            status=STATUS_OBSERVED, raw_score=0.0,
            flags={"feed": "tass", "keyword_hits": 99,
                   "article_count": 100, "normalized_freq": 0.99}),)
        reduced = R.reduce_drafts("rss_narrative", drafts, baselines={},
                                  now=NOW)
        assert all(d.status != STATUS_FIRED for d in reduced)

    def test_the_disabled_sources_are_disabled_on_both_sides(self):
        from v3.adapters.physical.ihr_health import IHR_HEALTH_ADAPTER
        from v3.adapters.physical.notam import NOTAM_ADAPTER
        assert IHR_HEALTH_ADAPTER.enabled is False
        assert NOTAM_ADAPTER.enabled is False


# ══ 7. mutation: the table's own values are load-bearing ═════════════════

class TestTheMutantsAreCaught:
    @pytest.mark.parametrize("mutant", [
        {"signal_source": "isr_hotspot", "min_score": 1.0},
        {"signal_source": A.OONI_HEAVY, "min_score": 1.0},
        {"signal_source": A.OONI_HEAVY, "event_type": "ISR_SURGE"},
        {"signal_source": "isr_hotspot", "event_type": "SYNC_DDOS"},
        {"signal_source": "nasa_eonet", "event_type": "ISR_SURGE"},
    ])
    def test_a_mutated_row_changes_an_answer(self, mutant):
        """Each mutation must move at least one of: which event type a
        reading becomes, or whether it becomes one at all."""
        from dataclasses import replace
        source = mutant.pop("signal_source")
        original = next(r for r in E.REGISTRATIONS
                        if r.signal_source == source)
        changed = replace(original, **mutant)
        probes = [
            _obs(source, "IL", score=0.0),
            _obs(source, "IL", score=1.0),
            _obs(source, "IL", score=2.0),
        ]
        before = [(original.admits(p), original.event_type) for p in probes]
        after = [(changed.admits(p), changed.event_type) for p in probes]
        assert before != after


# ══ 8. the tick discloses the chain it built (NP6) ══════════════════════

class TestTheTickDisclosesTheChain:
    """A sequence bonus of 0 has two readings — "no escalation" and "the
    link that would have shown it is not implemented" — and only one of
    them is a conclusion about the world."""

    def test_the_report_carries_the_live_links_and_the_coverage(self, store):
        from v3.runtime.tick import _chain_event_disclosure
        from v3.runtime.scoring import assemble, score
        _write(store, "isr_hotspot", "IL", at=NOW - 30)
        _write(store, "nasa_eonet", "IR", at=NOW - 30)
        result = score(assemble(now=NOW, store=store,
                                settings=ScoringSettings(),
                                scenarios=(_scenario(),)))
        disclosure = _chain_event_disclosure(result.next_sequence_events)
        assert disclosure["live"] == {"IL": ["ISR_SURGE"],
                                      "IR": ["FIRMS_ANOMALY"]}
        assert disclosure["count"] == 2
        assert disclosure["coverage"]["chain_bonus_reachable"] is False

    def test_an_empty_chain_still_says_what_is_unsupplied(self):
        from v3.runtime.tick import _chain_event_disclosure
        disclosure = _chain_event_disclosure(())
        assert disclosure["live"] == {} and disclosure["count"] == 0
        assert disclosure["coverage"]["missing"] == ["NARRATIVE_BURST",
                                                     "SYNC_DDOS"]

    def test_the_report_serialises_it(self):
        from v3.runtime.tick import TickReport
        report = TickReport(
            tick_id="t", now=NOW, scenario_ids=(), planned=(), skipped=(),
            withheld={}, observations_written=0, health={}, conclusions={},
            credentials={}, suppressors={}, coverage={},
            chain_events={"live": {}, "count": 0})
        assert report.as_dict()["chain_events"] == {"live": {}, "count": 0}

    def test_the_history_applies_the_adjudication_predicate(self, store):
        """The third ledger->kernel path must gate intel like the other two.

        No registration names an intel source today, so this is a guard
        against the future rather than a live bug — which is exactly the
        shape that would land unnoticed, since a chain that grew a link
        looks like a chain that should have.
        """
        from v3.runtime import scoring as SCORING
        seen = {}
        import v3.intel.adjudication as adjudication
        real = adjudication.scoreable_rows

        def capture(ledger, rows, *, until=None):
            seen["called"] = True
            return real(ledger, rows, until=until)

        adjudication.scoreable_rows = capture
        try:
            SCORING.sequence_history(store, now=NOW, scenarios=(_scenario(),),
                                     retention_sec=86400.0)
        finally:
            adjudication.scoreable_rows = real
        assert seen.get("called") is True
