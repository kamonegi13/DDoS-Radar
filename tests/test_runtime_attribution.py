"""§7-2 #127 — where the score sits when production files under a SIGNAL name.

Production gives a rationale entry a country only when `add_rat`'s first
positional is in `FOCUSED_ONLY_SENSOR_NAMES` (`radar/routes/core.py:2039-2041`).
Nine families v3 scored per country fail that test in production, so
production contributes ZERO from them to every scenario score
(`radar/scoring.py:1452-1453` under `GLOBAL_SIGNALS_DECOUPLED`) and reaches
only the global envelope. `v3/runtime/attribution.py` moves the score onto
one countryless row and leaves everything else on the per-country rows.

What is asserted here:

  landing      one countryless row per family per cycle, carrying the
               PRIMARY CORE's reading; the per-country rows keep country,
               status, suppression and flags and lose only the number
  predicates   measured with the kernel's own `admits()` / `passes_gate()`
               and its own `global_threat` / `build_contributions`, not
               with a re-statement of them
  readers      every per-country reader the enumeration found is still
               fed — the failure mode #118 taught, which is invisible
  ordering     the collapse runs AFTER suppression, because GDELT's
               weather join is keyed on the row's own country
  ledger       N countryless rows of one family cannot be written at all,
               so collapsing is forced rather than preferred
  sweep        the primary-core rule against an independent re-derivation
  mutation     every constant and every rule in the module, killed
"""
import pathlib
import random

import pytest

from v3.adapters.types import (AdapterId, CYBER, INFO, PHYSICAL, RequestSpec,
                               SourceAdapter, STATUS_FIRED, STATUS_OBSERVED,
                               STATUS_OK, STATUS_SUPPRESSED, ObservationDraft)
from v3.config.resolution import ConfigResolver
from v3.conclusions import vocabulary as V
from v3.fetch.registry import AdapterRegistry
from v3.kernel.errors import DomainError
from v3.kernel.window import Window
from v3.ledger.store import LedgerStore
from v3.runtime import attribution as A
from v3.runtime import events as E
from v3.runtime import geo as geo_module
from v3.runtime import reduce as R
from v3.runtime import suppression
from v3.runtime import tick as tick_module
from v3.parity.adapter import to_v3_observations

NOW = 1_800_000_000.0
CORES = ("IL", "IR")


def _draft(source, country, *, score=2.0, status=STATUS_FIRED, domain=CYBER,
           suppressed=False, flags=None):
    return ObservationDraft(
        signal_source=source, domain=domain, country=country, status=status,
        raw_score=score, suppressed=suppressed,
        suppress_reason="analyst_mute" if suppressed else None,
        value=f"{source}@{country}", reason=f"{source} fired",
        flags=dict(flags or {"probe": country}))


def _rows(drafts, source):
    return [d for d in drafts if d.signal_source == source]


def _observation(draft, sensor):
    """The draft as the kernel receives it, through the REAL projection.

    `country=draft.country or "GLOBAL"` is the runner's own write
    (`v3/fetch/runner.py:560`), so a test that passed `""` straight into
    the projection would be testing a row the ledger never holds.
    """
    return to_v3_observations([{
        "sensor": sensor, "signal_source": draft.signal_source,
        "domain": draft.domain, "status": draft.status,
        "raw_score": draft.raw_score, "country": draft.country or "GLOBAL",
        "confidence": draft.confidence, "observed_at": NOW,
        "suppressed": draft.suppressed, "payload": draft.value}])[0]


# ══ 1. the landing ═══════════════════════════════════════════════════════

class TestTheScoreMovesAndNothingElseDoes:
    def test_one_countryless_row_carries_the_primary_core(self):
        out = A.collapse("ooni_censorship",
                         (_draft("ooni_censorship", "IL", score=1.0),
                          _draft("ooni_censorship", "IR", score=2.0)),
                         cores=CORES)
        globals_ = [d for d in _rows(out, "ooni_censorship") if not d.country]
        assert len(globals_) == 1
        assert globals_[0].raw_score == 2.0
        assert globals_[0].flags[A.PRIMARY_CORE] == "IR"
        assert globals_[0].flags[A.COUNTRIES_MEASURED] == ["IL", "IR"]

    def test_the_per_country_rows_keep_everything_but_the_number(self):
        source = _draft("gdelt", "IL", score=1.0, domain=INFO,
                        flags={"tone": -6.0, "dow_z": 2.4})
        face = next(d for d in A.collapse("gdelt", (source,), cores=CORES)
                    if d.country)
        assert (face.country, face.status, face.suppressed) == \
            (source.country, source.status, source.suppressed)
        assert face.value == source.value and face.reason == source.reason
        assert face.flags["tone"] == -6.0 and face.flags["dow_z"] == 2.4
        assert face.raw_score == 0.0
        assert face.flags[A.COUNTRY_SCORE] == 1.0
        assert face.flags[A.SCORE_MOVED_TO] == A.GLOBAL

    def test_a_suppressed_reading_travels_with_its_suppression(self):
        """The collapse runs after `suppression.apply`, so the primary
        core's row may already be marked; copying it is how production's
        `core_theater` weather join reaches the countryless entry."""
        out = A.collapse("gdelt", (_draft("gdelt", "IL", score=0.0,
                                          domain=INFO,
                                          status=STATUS_SUPPRESSED,
                                          suppressed=True),), cores=("IL",))
        row = next(d for d in out if not d.country)
        assert row.suppressed is True and row.status == STATUS_SUPPRESSED

    def test_an_unlisted_adapter_is_returned_untouched(self):
        drafts = (_draft("isr_hotspot", "IL", domain=PHYSICAL),)
        assert A.collapse("opensky", drafts, cores=CORES) == drafts

    def test_a_family_with_no_measured_core_withholds_its_verdict(self):
        """A row synthesised for a core nobody measured is a claim of calm,
        which `_fold_cf_spike` declines for the same reason."""
        out = A.collapse("threatfox", (_draft("threatfox", "JP"),),
                         cores=CORES)
        assert [d.country for d in out] == ["JP"]
        assert all(A.PRIMARY_CORE not in d.flags for d in out)

    def test_no_cores_at_all_withholds_too(self):
        out = A.collapse("threatfox", (_draft("threatfox", "IL"),), cores=())
        assert [d.country for d in out] == ["IL"]

    def test_two_families_of_one_adapter_collapse_independently(self):
        out = A.collapse("ihr_health",
                         (_draft("ihr_delay", "IL", domain=PHYSICAL),
                          _draft("ihr_hegemony", "IR", score=1.0,
                                 domain=PHYSICAL),
                          _draft("bgp", "IL", domain=PHYSICAL)), cores=CORES)
        assert [d.flags[A.PRIMARY_CORE]
                for d in out if not d.country] == ["IL", "IR"]
        # `bgp` is country-bearing in production (`ripe_bgp`/`ioda_bgp` are
        # FOCUSED_ONLY sensors), so it is not this module's business.
        assert [d.country for d in _rows(out, "bgp")] == ["IL"]

    def test_the_disclosure_names_every_family_and_its_production_site(self):
        rows = A.registry_disclosure()
        assert len(rows) == len(A.FAMILIES)
        assert all(row["production_ref"].startswith("radar/routes/core.py:")
                   for row in rows)
        assert all(row["register_ref"] == "§7-2 #127" for row in rows)


# ══ 2. the kernel's own predicates ══════════════════════════════════════

class TestTheKernelSeesWhatProductionSees:
    def test_the_face_gates_but_no_longer_admits(self):
        face = next(d for d in A.collapse(
            "gps_jamming", (_draft("gps_jamming", "IL", domain=PHYSICAL),),
            cores=CORES) if d.country)
        observation = _observation(face, "gps_jamming")
        assert observation.passes_gate() is True     # the chain link lives
        assert observation.admits() is False         # the score does not

    def test_the_verdict_row_is_global_to_the_kernel(self):
        row = next(d for d in A.collapse(
            "gps_jamming", (_draft("gps_jamming", "IL", domain=PHYSICAL),),
            cores=CORES) if not d.country)
        assert _observation(row, "gps_jamming").is_global is True

    def test_the_scenario_scores_zero_and_the_envelope_carries_it(self):
        """Both halves through the kernel's own functions: this is the
        quantity §7-2 #127 was about."""
        from v3.kernel import Ratio
        from v3.scoring import Participant, Scenario
        from v3.scoring.contributions import build_contributions, global_threat
        from v3.scoring.settings import ScoringSettings

        scenario = Scenario(
            scenario_id="middle_east", core_country="IL",
            participants=(Participant(country="IL", weight=1.0,
                                      role="principal_belligerent"),))
        settings = ScoringSettings()
        drafts = A.collapse("threatfox", (_draft("threatfox", "IL"),),
                            cores=("IL",))
        observations = tuple(_observation(d, "threatfox") for d in drafts)

        assert build_contributions(observations, scenario,
                                   settings=settings, now=NOW) == ()
        envelope = global_threat(observations,
                                 global_signal_weight=Ratio(0.5), now=NOW)
        assert envelope["score"] == pytest.approx(1.0)   # 2.0 x 0.5, ONCE
        assert envelope["sources"] == ("threatfox",)

    def test_the_envelope_is_not_multiplied_by_the_countries_measured(self):
        """The reason collapsing is not optional: three countries would
        otherwise be three global contributions where production has one."""
        from v3.kernel import Ratio
        from v3.scoring.contributions import global_threat
        drafts = A.collapse(
            "threatfox", tuple(_draft("threatfox", c)
                               for c in ("IL", "IR", "JP")), cores=CORES)
        observations = tuple(_observation(d, "threatfox") for d in drafts)
        envelope = global_threat(observations,
                                 global_signal_weight=Ratio(0.5), now=NOW)
        assert envelope["score"] == pytest.approx(1.0)


# ══ 3. the ledger forces it ═════════════════════════════════════════════

class TestTheLedgerCannotHoldTwoGlobalRows:
    def test_two_countryless_rows_of_one_family_are_refused(self):
        """`reduce._require_writable` keys a countryless row as
        `(signal_source, "GLOBAL")`. Aligning attribution and collapsing to
        one row are the same act, not two decisions."""
        with pytest.raises(DomainError, match="after reduction"):
            R.reduce_drafts("threatfox",
                            (_draft("threatfox", ""), _draft("threatfox", "")),
                            baselines={}, now=NOW)

    def test_a_family_that_already_went_global_is_a_named_failure(self):
        """The day a fold reaches one of these verdicts itself, the second
        countryless row would be dropped in silence rather than refused."""
        with pytest.raises(DomainError, match="already emitted a countryless"):
            A.collapse("threatfox", (_draft("threatfox", "IL"),
                                     _draft("threatfox", "")), cores=CORES)

    def test_the_collapse_output_is_writable(self):
        out = A.collapse("threatfox",
                         tuple(_draft("threatfox", c) for c in ("IL", "IR")),
                         cores=CORES)
        seen = {(d.signal_source, d.country or "GLOBAL") for d in out}
        assert len(seen) == len(out)


# ══ 4. every per-country reader is still fed ════════════════════════════

class TestTheReadersAreStillFed:
    """The enumeration behind #118's landing, re-run for the nine. A reader
    that stops being fed is the failure mode here, and it is invisible."""

    @pytest.mark.parametrize("source,sensor,domain", [
        ("gdelt", "gdelt", INFO),
        ("tor_metrics", "tor_metrics", INFO),
        ("gps_jamming", "gps_jamming", PHYSICAL),
        ("ooni_censorship", "ooni_censorship", CYBER),
        ("ct_log", "ct_log", CYBER),
    ])
    def test_the_country_and_the_flags_survive(self, source, sensor, domain):
        """`baselines.previous_cycle`, `record.record_phase_samples` and
        `record._record_ct_log` all read `latest_signal_at(..., country=c)`
        and pull a FLAG off it. Both halves are here."""
        face = next(d for d in A.collapse(
            source, (_draft(source, "IL", domain=domain,
                            flags={"tone": -6.0, "running": 4200}),),
            cores=CORES) if d.country)
        assert face.country == "IL"
        assert face.flags["tone"] == -6.0 and face.flags["running"] == 4200

    def test_novelty_counting_still_sees_a_fired_row_per_country(self):
        """`conclusions/anomaly.novelty_counts` counts rows by
        `(signal_source, country, status="FIRED")`. Zeroing a score does
        not change a status, and that is why it must not."""
        faces = [d for d in A.collapse(
            "gdelt", tuple(_draft("gdelt", c, domain=INFO)
                           for c in ("IL", "IR")), cores=CORES) if d.country]
        assert {(d.country, d.status) for d in faces} == \
            {("IL", STATUS_FIRED), ("IR", STATUS_FIRED)}

    def test_the_gps_chain_link_survives_the_move(self):
        from v3.scoring import Participant, Scenario
        scenario = Scenario(
            scenario_id="middle_east",
            participants=tuple(Participant(country=c, weight=1.0,
                                           role="principal_belligerent")
                               for c in CORES))
        drafts = A.collapse("gps_jamming",
                            (_draft("gps_jamming", "IL", domain=PHYSICAL),),
                            cores=CORES)
        events = E.arriving_from(
            tuple(_observation(d, "gps_jamming") for d in drafts),
            (scenario,), now=NOW)
        assert [(e.country, e.event_type) for e in events] == \
            [("IL", "GPS_JAMMING")]

    def test_the_ooni_chain_link_survives_through_its_rung(self):
        from v3.scoring import Participant, Scenario
        scenario = Scenario(
            scenario_id="middle_east",
            participants=tuple(Participant(country=c, weight=1.0,
                                           role="principal_belligerent")
                               for c in CORES))
        drafts = A.collapse("ooni_censorship",
                            (_draft("ooni_censorship", "IL", score=2.0),
                             _draft("ooni_censorship", "IR", score=1.0)),
                            cores=CORES)
        events = E.arriving_from(
            tuple(_observation(d, "ooni_censorship") for d in drafts),
            (scenario,), now=NOW)
        # IL was heavy, IR was only censoring — production's own condition.
        assert [(e.country, e.event_type) for e in events] == \
            [("IL", "CENSORSHIP_DETECTED")]

    def test_the_rung_row_scores_nothing_of_its_own(self):
        rung = next(d for d in A.collapse(
            "ooni_censorship", (_draft("ooni_censorship", "IL", score=2.0),),
            cores=CORES) if d.signal_source == A.OONI_HEAVY)
        observation = _observation(rung, "ooni_censorship")
        assert observation.passes_gate() is True
        assert observation.admits() is False
        assert rung.flags["anchors_for"] == "ooni_censorship"


# ══ 5. ordering: after suppression, never before ════════════════════════

class TestTheOrderIsLoadBearing:
    def test_weather_reaches_the_countryless_gdelt_row(self):
        """Production suppresses GDELT on `core_theater`'s weather
        (`radar/sensors/gdelt.py:58,73,83` -> `core.py:1132`). Collapsing
        first would leave the row asking `severe_weather[""]`."""
        weather = ObservationDraft(
            signal_source="openweather", domain=PHYSICAL, country="IL",
            status=STATUS_OK, value="storm", flags={"is_severe": True})
        state = suppression.read_suppressors({"openweather": (weather,)})
        gdelt = _draft("gdelt", "IL", score=1.0, domain=INFO)

        after = A.collapse("gdelt", suppression.apply(
            "gdelt", (gdelt,), suppressors=state), cores=("IL",))
        row = next(d for d in after if not d.country)
        assert row.suppressed is True
        assert row.suppress_reason == suppression.SEVERE_WEATHER_REASON

        before = suppression.apply(
            "gdelt", A.collapse("gdelt", (gdelt,), cores=("IL",)),
            suppressors=state)
        stranded = next(d for d in before if not d.country)
        assert stranded.suppressed is False      # the failure being avoided

    def test_the_tick_wires_it_in_that_order(self):
        source = (pathlib.Path(__file__).resolve().parents[1]
                  / "v3" / "runtime" / "tick.py").read_text()
        collapse_at = source.index("attribution_module.collapse")
        apply_at = source.index("suppression_module.apply")
        assert collapse_at < apply_at        # collapse WRAPS apply's result
        assert "cores=baselines.get(baselines_module.EFFECTIVE_CORES)" \
            in source


# ══ 6. the primary-core rule, swept against a re-derivation ═════════════

class TestThePrimaryCoreRule:
    def test_ties_resolve_alphabetically_as_max_over_a_sorted_list_does(self):
        assert A.primary_core(("IR", "IL"), {"IL": 3.0, "IR": 3.0}) == "IL"

    def test_an_unmeasured_core_defaults_to_zero(self):
        assert A.primary_core(("IL", "IR"), {"IR": 0.5}) == "IR"
        assert A.primary_core(("IL", "IR"), {}) == "IL"

    def test_case_and_blanks_are_normalised(self):
        assert A.primary_core(("il", "", "IR"), {"IL": 9.0}) == "IL"

    def test_the_sweep_agrees_with_an_independent_derivation(self):
        """Production's rule at `core.py:878-881` re-keyed: the argmax of
        the cores by their own reading, first-maximal on a sorted list, 0
        for a core with no entry."""
        rng = random.Random(20260809)
        seen_tie = seen_unmeasured = 0
        for _ in range(4000):
            cores = rng.sample(["IL", "IR", "TW", "CN", "UA", "RU"],
                               rng.randint(1, 4))
            scores = {c: float(rng.choice([0.0, 1.0, 2.0, 3.0]))
                      for c in cores if rng.random() < 0.8}
            expected = ""
            best = None
            for core in sorted(cores):
                value = scores.get(core, 0.0)
                if best is None or value > best:
                    best, expected = value, core
            assert A.primary_core(cores, scores) == expected
            seen_tie += len({scores.get(c, 0.0) for c in cores}) < len(cores)
            seen_unmeasured += any(c not in scores for c in cores)
        assert seen_tie and seen_unmeasured

    def test_the_fold_reads_the_rule_it_declares(self):
        """A sweep over whole collapses, not over the helper alone: the
        verdict row must be the row of `primary_core`'s answer."""
        rng = random.Random(4242)
        for _ in range(2000):
            countries = rng.sample(["IL", "IR", "TW", "CN"],
                                   rng.randint(1, 4))
            scores = {c: float(rng.randint(0, 3)) for c in countries}
            cores = tuple(rng.sample(countries, rng.randint(1, len(countries))))
            out = A.collapse("threatfox",
                             tuple(_draft("threatfox", c, score=scores[c])
                                   for c in countries), cores=cores)
            verdict = [d for d in out
                       if d.signal_source == "threatfox" and not d.country]
            expected = A.primary_core(cores, scores)
            assert [d.raw_score for d in verdict] == [scores[expected]]


# ══ 7. mutation: every rule in the module, killed ═══════════════════════

def _reference(drafts, cores):
    """An independent re-keying of the whole collapse, from production.

    Written from `core.py` rather than from `attribution.py`: production
    reads one core theatre, files ONE entry under a signal name, and keeps
    the per-target numbers in a working structure the entry never sees
    (`target_details`, `core.py:831`). Returned as the two quantities that
    can move — the countryless verdict per family, and the score left on
    each per-country row.
    """
    verdicts, faces = {}, {}
    families = {d.signal_source for d in drafts
                if d.signal_source in A.COUNTRYLESS_SOURCES and d.country}
    ranked = sorted({c.strip().upper() for c in cores if c})
    for family in families:
        members = [d for d in drafts if d.signal_source == family
                   and d.country]
        for member in members:
            faces[(family, member.country)] = 0.0
        best_core, best_score = "", None
        for core in ranked:
            score = next((m.raw_score for m in members if m.country == core),
                         0.0)
            if best_score is None or score > best_score:
                best_core, best_score = core, score
        if best_core and any(m.country == best_core for m in members):
            verdicts[family] = best_score
    return verdicts, faces


def _measured(out):
    verdicts = {d.signal_source: d.raw_score for d in out
                if not d.country and d.signal_source in A.COUNTRYLESS_SOURCES}
    faces = {(d.signal_source, d.country): d.raw_score for d in out
             if d.country and d.signal_source in A.COUNTRYLESS_SOURCES}
    return verdicts, faces


def _probe(rng):
    countries = rng.sample(["IL", "IR", "TW", "CN", "JP"], rng.randint(1, 5))
    drafts = tuple(_draft("threatfox", c, score=float(rng.randint(0, 3)),
                          status=(STATUS_FIRED if rng.random() < 0.7
                                  else STATUS_OK))
                   for c in countries)
    cores = tuple(rng.sample(countries + ["UA"],
                             rng.randint(0, min(3, len(countries)))))
    return drafts, cores


class TestTheCollapseAgreesWithAnIndependentDerivation:
    def test_four_thousand_probes(self):
        rng = random.Random(90909)
        seen_withheld = seen_verdict = 0
        for _ in range(4000):
            drafts, cores = _probe(rng)
            out = A.collapse("threatfox", drafts, cores=cores)
            # The ledger's own key, on every probe: `_require_writable` runs
            # BEFORE this step, so a second countryless row would reach L1
            # unchecked and be dropped in silence (`store.py:290`).
            keys = [(d.signal_source, d.country or "GLOBAL") for d in out]
            assert len(keys) == len(set(keys))
            observed = _measured(out)
            assert observed == _reference(drafts, cores)
            seen_withheld += not observed[0]
            seen_verdict += bool(observed[0])
        assert seen_withheld and seen_verdict     # both branches reached


#: Each mutant is an alternative implementation of ONE rule. A mutant that
#: never disagrees with the real fold over the sweep is a rule nothing
#: depends on, and the assertion below reports it as such.
def _mutant_quietest_core(drafts, cores):
    ranked = sorted({c.strip().upper() for c in cores if c})
    verdicts, faces = _reference(drafts, cores)
    for family in list(verdicts):
        members = [d for d in drafts if d.signal_source == family
                   and d.country]
        core = min(ranked, key=lambda c: next(
            (m.raw_score for m in members if m.country == c), 0.0))
        hit = next((m for m in members if m.country == core), None)
        if hit is None:
            del verdicts[family]
        else:
            verdicts[family] = hit.raw_score
    return verdicts, faces


def _mutant_first_core(drafts, cores):
    ranked = sorted({c.strip().upper() for c in cores if c})
    verdicts, faces = _reference(drafts, cores)
    for family in list(verdicts):
        members = [d for d in drafts if d.signal_source == family
                   and d.country]
        hit = next((m for m in members if m.country == ranked[0]), None)
        if hit is None:
            del verdicts[family]
        else:
            verdicts[family] = hit.raw_score
    return verdicts, faces


def _mutant_all_countries(drafts, cores):
    """The core set ignored — v3's wider measured set used instead."""
    return _reference(drafts, tuple(d.country for d in drafts if d.country))


def _mutant_face_keeps_its_score(drafts, cores):
    verdicts, faces = _reference(drafts, cores)
    return verdicts, {(d.signal_source, d.country): d.raw_score
                      for d in drafts if d.country
                      and d.signal_source in A.COUNTRYLESS_SOURCES}


def _mutant_synthesises_a_missing_core(drafts, cores):
    """The withholding removed: an unmeasured core reported as calm."""
    verdicts, faces = _reference(drafts, cores)
    families = {d.signal_source for d in drafts
                if d.signal_source in A.COUNTRYLESS_SOURCES and d.country}
    for family in families:
        verdicts.setdefault(family, 0.0)
    return verdicts, faces


class TestTheMutantsAreCaught:
    @pytest.mark.parametrize("mutant", [
        _mutant_quietest_core, _mutant_first_core, _mutant_all_countries,
        _mutant_face_keeps_its_score, _mutant_synthesises_a_missing_core,
    ], ids=["quietest_core", "first_core", "all_countries",
            "face_keeps_score", "synthesised_core"])
    def test_a_mutated_rule_changes_an_answer(self, mutant):
        rng = random.Random(31337)
        for _ in range(4000):
            drafts, cores = _probe(rng)
            if _measured(A.collapse("threatfox", drafts, cores=cores)) != \
                    mutant(drafts, cores):
                return
        pytest.fail(f"{mutant.__name__} survived 4,000 probes — the rule it "
                    f"changes is load-bearing on nothing")

    @pytest.mark.parametrize("rung", [0.0, 1.0, 3.0])
    def test_the_anchor_rung_is_load_bearing(self, rung):
        """`anchor_min_score` is OONI's heavy branch (`core.py:1710`)."""
        family = next(f for f in A.FAMILIES
                      if f.signal_source == "ooni_censorship")
        assert family.anchor_min_score == 2.0
        drafts = (_draft("ooni_censorship", "IL", score=2.0),
                  _draft("ooni_censorship", "IR", score=1.0))
        emitted = {d.country for d in A.collapse("ooni_censorship", drafts,
                                                 cores=CORES)
                   if d.signal_source == A.OONI_HEAVY}
        assert emitted == {"IL"}
        mutated = {d.country for d in drafts if d.raw_score >= rung}
        assert mutated != emitted

    def test_the_anchor_reads_the_gate_as_well_as_the_rung(self):
        """`_ooni_active` is the other half. A muted heavy reading must not
        anchor, or the analyst's mute stops meaning anything."""
        for kwargs in ({"status": STATUS_OK}, {"suppressed": True}):
            drafts = (_draft("ooni_censorship", "IL", score=2.0, **kwargs),)
            assert not [d for d in A.collapse("ooni_censorship", drafts,
                                              cores=CORES)
                        if d.signal_source == A.OONI_HEAVY]

    def test_dropping_a_family_from_the_table_restores_the_divergence(self):
        """The table is the mechanism, not documentation."""
        assert "threatfox" in A.COUNTRYLESS_SOURCES
        out = A.collapse("greynoise", (_draft("greynoise", "IL"),),
                         cores=CORES)
        assert [d.country for d in out] == ["IL"]     # not in the table
        assert _observation(out[0], "greynoise").admits() is True

    def test_an_observed_row_of_a_listed_family_still_loses_its_score(self):
        """The collapse does not read `status`: an OBSERVED row scores 0
        anyway, and a status test here would be a second gate to keep in
        step with `admits()`."""
        out = A.collapse("ct_log", (_draft("ct_log", "IL", score=3.0,
                                           status=STATUS_OBSERVED),),
                         cores=("IL",))
        assert next(d for d in out if d.country).raw_score == 0.0
        assert next(d for d in out if not d.country).raw_score == 3.0


# ══ 8. the conclusions layer, exercised end to end (§7-2 #132) ══════════

#: A real tick's transport, copied from `test_runtime_tick.py` /
#: `test_runtime_scoring_wiring.py` rather than re-imported: this module's
#: `_draft` builds `ObservationDraft`s, those modules' `_Client` answers
#: HTTP, and the two must not be confused by sharing a name.
class _TickPayload:
    def __init__(self, url):
        self.url, self.label, self.body = url, "", b"{}"
        self.status, self.content_type = 200, "application/json"

    def json(self):
        return {}


class _TickOutcome:
    def __init__(self, url):
        self.outcome, self.url, self.status = "ok", url, 200
        self.latency_ms, self.attempts, self.detail = 1.0, 1, ""
        self.body_sha256, self.url_sha256 = "0" * 64, "1" * 64
        self.payload = _TickPayload(url)
        self.succeeded = True


class _TickClient:
    def fetch(self, spec, *, now, auth=None, **kwargs):
        return _TickOutcome(spec.url)

    def pause(self, seconds):
        pass


def _tick_adapter(name, category, drafts):
    return SourceAdapter(
        adapter_id=AdapterId(name), category=category,
        cadence=Window.from_days(1.0, cadence_sec=1.0),
        requests=(RequestSpec(url=f"https://{name}.test/x"),),
        normalize=lambda payload, context, _d=drafts: tuple(_d),
        freshness_horizon_sec=86400.0, rate_limit_group=name)


#: `TW` is `principal_belligerent` (not `primary_target`, as the other
#: fixtures in this repo use it) so `chain.effective_cores` names it and
#: `attribution.collapse` emits the countryless verdict row too — the full
#: shape a live scenario produces, not only the per-country face.
_TICK_GEO_DOC = {
    "COUNTRY_COORDS": {"TW": {"lat": 23.7, "lng": 121.0, "name": "Taiwan"},
                       "CN": {"lat": 35.0, "lng": 103.0, "name": "China"}},
    "SCENARIOS": {"taiwan_contingency": {"participants": {
        "TW": {"weight": 1.0, "role": "principal_belligerent"},
        "CN": {"weight": 0.7, "role": "adversary"}}}},
}


@pytest.fixture
def tick_geography():
    return geo_module.from_document(_TICK_GEO_DOC)


@pytest.fixture
def tick_store(tmp_path):
    instance = LedgerStore(str(tmp_path / "attribution_anomaly.db"))
    yield instance
    instance.close()


class TestNoIndividualAnomalyForTheNineFamilies:
    """The consequence a code review flagged CRITICAL and the owner
    confirmed is a REGISTRATION, not a divergence: production has the same
    limitation, for the same reason, so this is pinned rather than fixed.

    `_face()` zeros `raw_score` on the per-country rows of the nine
    collapsed families. `Observation.admits()` (`v3/scoring/inputs.py:249`)
    is `passes_gate() and score > 0`, so a zeroed row stops admitting.
    `build_contributions` (`v3/scoring/contributions.py:149`) skips a
    non-admitting observation before a `Contribution` even exists, so
    `ScoringResult.contributions` — and `ScenarioContext.contributions`
    through it (`v3/conclusions/context.py:91-92`) — never carries the row.
    `v3/conclusions/anomaly.py::derive` (`:145-149`) loops over
    `context.contributions` and additionally skips `raw <= 0`, so even a
    row reaching it by some other path would still not become an ANOMALY
    conclusion.

    Production has the identical shape: `derive_anomaly`
    (`radar/conclusions/anomaly.py:187`) reads `state.contributions`, the
    `deduped` list `compute_scenario_score` builds
    (`radar/scoring.py:1555`) after dropping every countryless signal at
    `radar/scoring.py:1447-1453` under `GLOBAL_SIGNALS_DECOUPLED` (shipped
    `true`, `radar/config.py:421`, unset in `config.env`). v3 now matches
    production; it does not newly diverge from it. §7-2 #132 registers the
    direction as NEUTRAL and files the open question — whether a
    countryless signal should ever be able to produce an individual
    anomaly at all — as a post-cutover question about the LIVE system
    (D2 H-03), not a v3 defect.

    This is also why `derive()` must NOT fall back to
    `flags["country_score"]`, the fix a reviewer proposed:
    `Contribution` (`v3/scoring/contributions.py:35-57`) carries no
    `flags` field, so a fallback written inside `derive()` alone has
    nothing to read — reaching the value would require ALSO admitting the
    zeroed observation earlier, in `build_contributions` or `admits()`,
    which would make v3 emit an anomaly production structurally cannot, in
    exactly the blind spot §7-2 #127 closed. The test below asserts the
    OUTCOME rather than one function's internals, so it fails no matter
    which layer such a change is made in.
    """

    def test_the_family_never_becomes_a_per_country_anomaly(
            self, tick_store, tick_geography):
        registry = AdapterRegistry([
            _tick_adapter("threatfox", "cyber",
                          (_draft("threatfox", "TW", score=4.0),)),
            _tick_adapter("ripe_atlas", "physical",
                          (_draft("ripe_atlas", "TW", score=4.0,
                                  domain=PHYSICAL),)),
        ])
        report = tick_module.run_tick(
            now=NOW, registry=registry, store=tick_store,
            client=_TickClient(), geography=tick_geography,
            scenario_ids=("taiwan_contingency",),
            config=ConfigResolver({}))
        assert report.observations_written > 0

        rows = tick_store.conclusions_between(
            scenario_id="taiwan_contingency", conclusion_type=V.ANOMALY,
            start=NOW - 1, end=NOW + 1)
        states = {row["state"] for row in rows}

        # The claim under test: a §7-2 #127 family — collapsed by this
        # module — cannot surface as an individual anomaly, per-country or
        # otherwise (with GLOBAL_SIGNALS_DECOUPLED on, its countryless
        # verdict row does not score either).
        assert "threatfox" not in states
        # The positive control: `ripe_atlas` is an ordinarily-attributed
        # family (untouched by `attribution.collapse`), so its absence
        # would mean the tick itself is broken rather than that
        # attribution is working. Its presence proves the gap above is
        # about attribution specifically.
        assert "ripe_atlas" in states

    def test_the_family_still_admits_without_the_collapse(self):
        """The counterfactual: without `attribution.collapse` in the loop,
        the identical payload WOULD have produced a per-country
        contribution. This is what proves the earlier absence is
        `attribution.collapse`'s doing, not an unrelated reason `threatfox`
        never fires (a fixture typo, a scenario with no matching
        participant, and so on)."""
        from v3.scoring import Participant, Scenario
        from v3.scoring.contributions import build_contributions
        from v3.scoring.settings import ScoringSettings

        scenario = Scenario(
            scenario_id="taiwan_contingency", core_country="TW",
            participants=(Participant(country="TW", weight=1.0,
                                      role="principal_belligerent"),))
        settings = ScoringSettings()
        draft = _draft("threatfox", "TW", score=4.0)

        uncollapsed = _observation(draft, "threatfox")
        contributions = build_contributions(
            (uncollapsed,), scenario, settings=settings, now=NOW)
        assert len(contributions) == 1
        assert contributions[0].raw_score == 4.0

        face = next(d for d in
                    A.collapse("threatfox", (draft,), cores=("TW",))
                    if d.country)
        collapsed_observation = _observation(face, "threatfox")
        assert build_contributions((collapsed_observation,), scenario,
                                   settings=settings, now=NOW) == ()
