"""§7-2 #122 — `cf_botnet_overlap` and the IDF correlation family.

**The register's premise was wrong, and that is the first thing this
module measures.** #122 said the family "requires a NEW fetch —
`attacks/layer7/top/ases/origin`, one per target — and a scenario-level
computation", and priced the work accordingly. It requires neither. The
distributions that reach `compute_idf_weights` (`core.py:853-855`) are
`origin_distributions*`, built at `core.py:785`/`:810` from
`parse_origins`, whose keys are two-letter ORIGIN COUNTRY codes
(`radar/scoring.py:659-668`) — the same numbers `OriginSpike.origins`
has carried since WP-4.1d. The ASN histogram production DOES fetch is
consumed at `core.py:751-754` for `state_asn_hits` and reaches no
overlap. `compute_idf_weights`' own docstring says "ASN keys", which is
where the misreading came from, so the tests below assert the data path
rather than quoting either docstring.

Six obligations:

  premise      the input exists — traced from the fetch to the overlap on
               production's own source, so a future reader does not have
               to re-derive it.
  arithmetic   `radar/scoring.py:679-736` and `core.py:838-861`,
               transcribed and swept against an independent re-typing,
               with every rung of the ladder shown to be reached.
  the ladder   `core.py:1042-1062` — including the property the comment
               above it exists to record: the lowest rung FIRES and
               scores ZERO, because a flat score of 1 fired 395 times in
               24 h at a 47% false-positive rate.
  attribution  the row is countryless, like its four siblings, and the
               derived roster in `tests/test_v3_country_attribution.py`
               stays empty because of what the row IS, not because it was
               listed.
  readers      no per-country reader is created or starved: the input
               rides on `cf_spike_target`, which already exists.
  the chain    SYNC_DDOS becomes reachable. Measured through the
               composition route, not through a hand-built event.
"""
import math
import pathlib
import random
import re

import pytest

from v3.adapters.types import CYBER, STATUS_FIRED, STATUS_OK, ObservationDraft
from v3.runtime import correlation as C
from v3.runtime import events as E
from v3.runtime import reduce_cyber as RC
from v3.scoring import (CountryWeight, Observation, Participant, Scenario,
                        ScoringSettings)

NOW = 1_786_000_000.0
REPO = pathlib.Path(__file__).resolve().parents[1]
CORE = REPO / "radar" / "routes" / "core.py"
SCORING = REPO / "radar" / "scoring.py"


# ── an independent re-typing of production, for the sweep ───────────────

def _production_idf_weights(distributions):
    """`radar/scoring.py:679-711`, re-typed from the source."""
    if not distributions:
        return {}
    n_docs = sum(1 for d in distributions.values() if d)
    if n_docs <= 0:
        return {}
    df = {}
    for d in distributions.values():
        if not d:
            continue
        for k in d.keys():
            df[k] = df.get(k, 0) + 1
    if not df:
        return {}
    raw = {k: math.log((n_docs + 1) / (cnt + 1)) for k, cnt in df.items()}
    max_w = max(raw.values()) or 1.0
    if max_w <= 0:
        return {k: 0.0 for k in raw}
    return {k: max(0.0, w / max_w) for k, w in raw.items()}


def _production_overlap_idf(dist1, dist2, idf_weights):
    """`radar/scoring.py:713-736`, re-typed. Iterates a plain SET."""
    if not dist1 or not dist2 or not idf_weights:
        return 0.0
    s1 = sum(dist1.values()) or 1.0
    s2 = sum(dist2.values()) or 1.0
    all_keys = set(dist1) | set(dist2)
    num = sum(min(dist1.get(k, 0.0) / s1, dist2.get(k, 0.0) / s2)
              * idf_weights.get(k, 0.0)
              for k in all_keys)
    return round(num * 100, 2)


def _production_ladder(correlations_idf_l3):
    """`core.py:917-918` and `:1042-1062`, re-typed."""
    _HIGH_CORR_IDF_MIN = 1.5
    high_correlation = any(v >= _HIGH_CORR_IDF_MIN
                           for v in correlations_idf_l3.values())
    max_overlap_idf = max(correlations_idf_l3.values(), default=0.0)
    if max_overlap_idf >= 3.5:
        score = 2
        reason = (f"Strong shared botnet IDF={max_overlap_idf:.2f} "
                  f"(≥3.5 — rare ASN overlap)")
    elif max_overlap_idf >= 2.0:
        score = 1
        reason = f"Shared botnet IDF={max_overlap_idf:.2f} (≥2.0)"
    elif high_correlation:
        score = 0
        reason = (f"Marginal shared botnet IDF={max_overlap_idf:.2f} "
                  f"(≥1.5; below scoring floor)")
    else:
        score = 0
        reason = None
    return {"fired": high_correlation, "score": float(score),
            "value": f"{max_overlap_idf:.2f} IDF overlap",
            "reason": reason or "", "max": max_overlap_idf}


#: The corpus has to reach every rung, and the rungs are not where a
#: uniform draw over a fixed alphabet puts its mass. A high IDF overlap
#: needs two countries whose mass CONCENTRATES on origins few others
#: report, so the generator draws the sharing structure — how many
#: countries, how large the origin alphabet, how many origins each country
#: reports — rather than only the percentages.
_ALPHABETS = (3, 6, 12)
_BREADTHS = ((1, 2), (1, 5), (3, 9))
_PCT_SCALES = ((0.05, 4.0), (0.5, 12.0), (2.0, 45.0))


def _random_distributions(rng):
    """`{country: {origin: pct}}` for one layer, one tick."""
    alphabet = ["O%02d" % i for i in range(rng.choice(_ALPHABETS))]
    countries = ["TW", "JP", "PH", "KR"][:rng.randint(1, 4)]
    low, high = rng.choice(_PCT_SCALES)
    breadth = rng.choice(_BREADTHS)
    built = {}
    for country in countries:
        size = min(rng.randint(*breadth), len(alphabet))
        codes = rng.sample(alphabet, size) if alphabet else []
        # Zero-valued keys are real: `core.py:785` writes every code in
        # `set(o_l3) | set(o_l7)` into the L3 distribution, so an origin
        # seen only at L7 is present with 0.0 and still raises `df`.
        built[country] = {code: (0.0 if rng.random() < 0.15
                                 else round(rng.uniform(low, high), 2))
                          for code in codes}
    return built


# ══ 1. the premise: the input exists, and #122 said it did not ══════════

class TestTheInputWasAlreadyThere:
    """#122 priced this family as a new fetch. It is not one.

    Every assertion here reads production's own source: the register was
    written from a docstring, and a docstring is what got it wrong.
    """

    def test_the_overlap_is_fed_the_origin_country_distributions(self):
        """`core.py:853-855` — the three `compute_idf_weights` calls take
        `origin_distributions*`, nothing else."""
        source = CORE.read_text()
        assert "_idf_w_l3 = compute_idf_weights(_scoped_dists_l3)" in source
        assert ("_scoped_dists_l3 = {t: origin_distributions_l3.get(t, {}) "
                "for t in _corr_theaters}") in source

    def test_those_distributions_are_built_from_parse_origins(self):
        """`core.py:748-749` fetch `top/locations/origin`, `:785` writes
        the per-code percentages, `:810` files them per target."""
        lines = CORE.read_text().splitlines()
        assert "parse_origins" in lines[747] and "locations/origin" in lines[747]
        assert "normalized_dist_l3[code]" in lines[784]
        assert "origin_distributions_l3[t]" in lines[809]

    def test_parse_origins_keys_are_two_letter_country_codes(self):
        """`radar/scoring.py:659-668` — `origin1` / `location` /
        `clientCountryAlpha2`, with a `len(v) == 2 and v.isupper()`
        fallback. Not an ASN."""
        from radar.scoring import parse_origins
        parsed = parse_origins([{"origin1": "CN", "value": 40.0},
                                {"clientCountryAlpha2": "RU", "value": 5.0}])
        assert parsed == {"CN": 40.0, "RU": 5.0}
        assert all(len(k) == 2 and k.isupper() for k in parsed)

    def test_the_asn_fetch_only_feeds_the_state_asn_decoration(self):
        """`core.py:751-754` is the ONLY reader of `fetch_asn_origins`,
        and what it produces is `state_asn_hits` — the `is_state_asn=`
        kwarg §7-2 #125(b) already registered, which decorates the CAC
        direction and touches no score."""
        source = CORE.read_text()
        assert source.count("fetch_asn_origins(") == 1
        window = source.split("for asn_key in fetch_asn_origins(t):")[1][:200]
        assert "state_asn_hits.setdefault" in window
        assert "correlations" not in window

    def test_v3_therefore_declares_no_new_request(self):
        """The adapter's declaration is unchanged: four global endpoints
        and the four per-target origin requests WP-4.1d added."""
        from v3.adapters.cyber.cloudflare_radar import CLOUDFLARE_RADAR_ADAPTER
        urls = {spec.url for spec in CLOUDFLARE_RADAR_ADAPTER.requests}
        assert not any("ases/origin" in url for url in urls)
        assert any("layer3/top/locations/origin" in url for url in urls)

    def test_the_numbers_the_fold_correlates_are_already_on_the_row(self):
        """`OriginSpike.origins[code]["l3_pct"]` IS
        `normalized_dist_l3[code]`, including the zeros."""
        from v3.runtime.spike import origin_spike
        spike = origin_spike(current_l3={"CN": 40.0}, current_l7={"RU": 9.0},
                             baseline_l3={}, baseline_l7={})
        assert {code: working["l3_pct"]
                for code, working in spike.origins.items()} == {"CN": 40.0,
                                                                "RU": 0.0}


# ══ 2. the arithmetic ════════════════════════════════════════════════════

class TestTheIdfWeightsAreProductions:
    def test_a_worked_case(self):
        """Three countries; one origin is everywhere, one is in two, one
        is in one. The rarest normalises to 1 and the ubiquitous one to
        0."""
        weights = C.idf_weights({"TW": {"A": 1.0, "B": 1.0, "C": 1.0},
                                 "JP": {"A": 1.0, "B": 1.0},
                                 "PH": {"A": 1.0}})
        assert weights["C"] == pytest.approx(1.0)
        assert weights["A"] == pytest.approx(0.0)
        assert 0.0 < weights["B"] < 1.0

    def test_an_empty_distribution_is_not_a_document(self):
        with_empty = C.idf_weights({"TW": {"A": 1.0}, "JP": {}})
        alone = C.idf_weights({"TW": {"A": 1.0}})
        assert with_empty == alone

    def test_an_all_ubiquitous_scope_weighs_nothing(self):
        """`radar/scoring.py:708`'s `or 1.0`: every raw weight is 0, so
        two IDENTICAL histograms still overlap by 0."""
        scope = {"TW": {"A": 1.0}, "JP": {"A": 1.0}}
        weights = C.idf_weights(scope)
        assert set(weights.values()) == {0.0}
        assert C.overlap_idf(scope["TW"], scope["JP"], weights) == 0.0

    def test_the_negative_maximum_branch_is_unreachable(self):
        """`radar/scoring.py:709-710` guards `max_w <= 0`, which cannot
        happen: `df[k] <= n_docs` by construction, so every raw weight is
        `log(x >= 1) >= 0`. Asserted over the sweep corpus rather than
        argued, because the transcription drops the branch."""
        rng = random.Random(77)
        for _ in range(2000):
            scope = _random_distributions(rng)
            n_docs = sum(1 for d in scope.values() if d)
            for values in scope.values():
                for key in values:
                    df = sum(1 for d in scope.values() if d and key in d)
                    assert df <= n_docs
            assert all(w >= 0.0 for w in C.idf_weights(scope).values())


class TestTheOverlapIsProductions:
    def test_it_is_symmetric(self):
        first, second = {"A": 3.0, "B": 1.0}, {"A": 1.0, "C": 2.0}
        weights = C.idf_weights({"x": first, "y": second})
        assert C.overlap_idf(first, second, weights) == \
            C.overlap_idf(second, first, weights)

    def test_shape_not_volume(self):
        """Both distributions are normalised to their own sum first."""
        weights = C.idf_weights({"x": {"A": 1.0, "B": 1.0},
                                 "y": {"A": 1.0}, "z": {"B": 1.0}})
        small = C.overlap_idf({"A": 1.0, "B": 1.0}, {"A": 5.0, "B": 5.0},
                              weights)
        large = C.overlap_idf({"A": 100.0, "B": 100.0},
                              {"A": 500.0, "B": 500.0}, weights)
        assert small == large

    def test_an_empty_side_overlaps_nothing(self):
        assert C.overlap_idf({}, {"A": 1.0}, {"A": 1.0}) == 0.0
        assert C.overlap_idf({"A": 1.0}, {"A": 1.0}, {}) == 0.0

    def test_one_country_makes_no_pair(self):
        correlations = C.pairwise_idf({"TW": {"CN": 40.0}})
        assert correlations.overlaps == {}
        assert correlations.max_overlap == 0.0
        assert C.high_correlation(correlations.overlaps) is False


class TestTheSweepAgreesWithProduction:
    """3 seeds x 4,000 distribution sets against the re-typed original."""

    @pytest.mark.parametrize("seed", [31, 32, 33])
    def test_a_random_sweep_agrees_on_every_input(self, seed):
        rng = random.Random(seed)
        rungs = set()
        for _ in range(4000):
            scope = _random_distributions(rng)
            theirs_weights = _production_idf_weights(scope)
            ordered = sorted(scope)
            theirs_pairs = {
                f"{a}-{b}": _production_overlap_idf(scope[a], scope[b],
                                                    theirs_weights)
                for i, a in enumerate(ordered) for b in ordered[i + 1:]}
            theirs = _production_ladder(theirs_pairs)

            mine = C.pairwise_idf(scope)
            verdict = C.botnet_overlap_verdict(
                mine.max_overlap, C.high_correlation(mine.overlaps))

            # The INDEX with a tolerance of one rounding unit: production
            # sums over a plain `set` whose `str` hash is per-process, so
            # its own raw index is not bit-reproducible across restarts.
            assert mine.max_overlap == pytest.approx(theirs["max"], abs=0.01)
            assert sorted(mine.overlaps.values()) == \
                pytest.approx(sorted(theirs_pairs.values()), abs=0.01)
            # The VERDICT exactly.
            assert (verdict.fired, verdict.score) == (theirs["fired"],
                                                      theirs["score"])
            assert verdict.value == theirs["value"]
            assert verdict.reason == theirs["reason"]
            rungs.add(verdict.score if verdict.fired else -1.0)
        # Every rung reached, or the agreement is about one branch.
        assert rungs == {-1.0, 0.0, 1.0, 2.0}, rungs


# ══ 3. the ladder, and the repair it encodes ════════════════════════════

class TestTheBotnetOverlapLadder:
    @pytest.mark.parametrize("value,fired,score", [
        (0.0, False, 0.0),
        (1.49, False, 0.0),
        (1.5, True, 0.0),      # FIRED and scoring nothing — the repair
        (1.99, True, 0.0),
        (2.0, True, 1.0),
        (3.49, True, 1.0),
        (3.5, True, 2.0),
        (9.0, True, 2.0),
    ])
    def test_the_rungs(self, value, fired, score):
        verdict = C.botnet_overlap_verdict(value, value >= 1.5)
        assert (verdict.fired, verdict.score) == (fired, score)

    def test_the_printed_value_and_reasons_are_productions(self):
        assert C.botnet_overlap_verdict(4.0, True).reason == \
            "Strong shared botnet IDF=4.00 (≥3.5 — rare ASN overlap)"
        assert C.botnet_overlap_verdict(2.5, True).reason == \
            "Shared botnet IDF=2.50 (≥2.0)"
        assert C.botnet_overlap_verdict(1.7, True).reason == \
            "Marginal shared botnet IDF=1.70 (≥1.5; below scoring floor)"
        assert C.botnet_overlap_verdict(0.4, False).reason == ""
        assert C.botnet_overlap_verdict(1.7, True).value == "1.70 IDF overlap"


class TestTheMarginalRungIsTheRepair:
    """`core.py:1031-1041` records why this row's lowest rung fires at
    zero: a flat `score=1` at IDF>=1.5 fired 395 times in 24 h, put a
    constant cyber=1 under every scenario and pushed threat_level L5->L4
    at a 47% observed false-positive rate. Two properties came out of
    that, and both are load-bearing in opposite directions."""

    def test_production_still_records_the_history(self):
        """If the comment goes, the reason this rung is graded goes with
        it — and the next author simplifies it back."""
        source = CORE.read_text()
        assert "fired 395 times / 24h" in source
        assert "47% FP rate observed" in source
        assert "Status remains" in source and "for analyst visibility" in source

    def test_the_marginal_band_scores_nothing(self):
        """The precision half: commodity co-occurrence must not put a
        floor under a scenario score."""
        assert C.botnet_overlap_verdict(1.8, True).score == 0.0

    def test_the_marginal_band_still_fires(self):
        """The recall half (NP1): the analyst keeps the visibility, and
        the row keeps its sequence-event gate."""
        verdict = C.botnet_overlap_verdict(1.8, True)
        assert verdict.fired is True
        observation = _observation_of(verdict)
        assert observation.passes_gate() is True
        assert observation.admits() is False

    def test_a_flat_score_would_change_the_answer(self, monkeypatch):
        """The counterfactual the comment describes, RUN: restore the
        pre-2026-05-10 shape — one point from IDF>=1.5 — and the marginal
        band starts admitting to scenario scores again."""
        assert _observation_of(
            C.botnet_overlap_verdict(1.8, True)).admits() is False
        monkeypatch.setattr(C, "MARGINAL_OVERLAP_SCORE", 1.0)
        monkeypatch.setattr(C, "OVERLAP_IDF_MIN", C.HIGH_CORR_IDF_MIN)
        assert _observation_of(
            C.botnet_overlap_verdict(1.8, True)).admits() is True


def _observation_of(verdict, score=None):
    return Observation(
        sensor="cloudflare_radar", domain=CYBER,
        status=STATUS_FIRED if verdict.fired else STATUS_OK,
        score=verdict.score if score is None else score,
        signal_source=RC.BOTNET_OVERLAP_SIGNAL, countries=(),
        observed_at=NOW, value=verdict.value)


class TestHighCorrelationIsTheSameFactAsTheMaximum:
    """`core.py:918` and `:1042` read the same dict two ways. Production
    keeps both names and three readers depend on them, so the equivalence
    is pinned rather than assumed — a future divergence between them would
    otherwise be invisible."""

    def test_the_two_agree_over_the_sweep(self):
        rng = random.Random(55)
        seen = set()
        for _ in range(3000):
            overlaps = C.pairwise_idf(_random_distributions(rng)).overlaps
            answer = C.high_correlation(overlaps)
            assert answer == (max(overlaps.values(), default=0.0)
                              >= C.HIGH_CORR_IDF_MIN)
            seen.add(answer)
        assert seen == {True, False}

    def test_production_reads_it_in_three_places(self):
        source = CORE.read_text()
        assert source.count("high_correlation") >= 4      # 1 def + 3 reads
        assert "if is_coordinated and high_correlation and _coord_active" in \
            source


# ══ 4. the citations point at the lines they claim ══════════════════════

class TestEveryCitationPointsAtTheLineItClaims:
    """The transcription rule, extended to a second production file.

    `tests/test_runtime_cf_spike.py` does this for `v3/runtime/spike.py`,
    whose citations are all `core.py:N`. This family's arithmetic lives in
    `radar/scoring.py`, so the audit has to resolve BOTH — and a citation
    naming a file that is never checked is worth nothing.
    """

    NUMBER = re.compile(r"\d+(?:\.\d+)?")
    CITATION = re.compile(r"(?:radar/)?(core|scoring)\.py:([\d,\-]+)")
    FILES = {"core": CORE, "scoring": SCORING}

    @classmethod
    def _cited_constants(cls):
        source = (REPO / "v3" / "runtime"
                  / "correlation.py").read_text().splitlines()
        found, comment = [], []
        for raw in source:
            line = raw.strip()
            if line.startswith("#"):
                comment.append(line)
                continue
            match = re.match(r"^([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*(.+)$", line)
            if match and comment:
                cited = cls.CITATION.search(" ".join(comment))
                if cited:
                    values = [float(n) for n
                              in cls.NUMBER.findall(match.group(2))]
                    if values:
                        found.append((match.group(1), values,
                                      cited.group(1),
                                      cls._lines(cited.group(2))))
            comment = []
        return found

    @staticmethod
    def _lines(spec):
        wanted = []
        for part in spec.split(","):
            if "-" in part:
                start, end = part.split("-")
                wanted.extend(range(int(start), int(end) + 1))
            elif part:
                wanted.append(int(part))
        return wanted

    def test_the_audit_actually_found_the_constants(self):
        names = {name for name, _, _, _ in self._cited_constants()}
        assert {"HIGH_CORR_IDF_MIN", "STRONG_OVERLAP_IDF_MIN",
                "OVERLAP_IDF_MIN", "MARGINAL_OVERLAP_SCORE",
                "OVERLAP_SCALE", "IDF_SMOOTHING"} <= names
        assert len(names) >= 9

    def test_both_production_files_are_actually_cited(self):
        """A single-file audit would silently skip every `scoring.py`
        citation, which is where this family's arithmetic lives."""
        cited = {source for _, _, source, _ in self._cited_constants()}
        assert cited == {"core", "scoring"}

    def test_every_cited_line_contains_the_value(self):
        for name, values, source, lines in self._cited_constants():
            production = self.FILES[source].read_text().splitlines()
            present = set()
            for number in lines:
                present.update(float(n) for n
                               in self.NUMBER.findall(production[number - 1]))
            missing = [v for v in values if v not in present]
            assert not missing, (
                f"{name}={values} cites {source}.py:{lines} but those lines "
                f"contain {sorted(present)} — the citation has drifted or "
                f"the constant was not transcribed from there")


# ══ 5. attribution: countryless, proven rather than asserted ════════════

class TestTheRowIsCountrylessLikeItsSiblings:
    def test_production_files_it_under_a_signal_name(self):
        assert f'add_rat(\n                "{RC.BOTNET_OVERLAP_SIGNAL}"' in \
            CORE.read_text()

    def test_it_is_not_a_focused_only_sensor(self):
        """THE line that settles per-scenario vs per-country
        (`core.py:2039-2041`): a rationale entry acquires a country only
        when `rat.sensor in FOCUSED_ONLY_SENSOR_NAMES`, and that frozenset
        holds SENSOR names."""
        from radar.scenarios import FOCUSED_ONLY_SENSOR_NAMES
        assert RC.BOTNET_OVERLAP_SIGNAL not in FOCUSED_ONLY_SENSOR_NAMES
        assert "cloudflare_radar" in FOCUSED_ONLY_SENSOR_NAMES

    def test_it_joined_the_family_set_rather_than_being_listed(self):
        assert RC.BOTNET_OVERLAP_SIGNAL in RC.COUNTRYLESS_SIGNALS
        assert len(RC.COUNTRYLESS_SIGNALS) == 5

    def test_the_fold_emits_it_without_a_country(self):
        rows = _derived(_fold(_origin_drafts("TW", {"CN": 40.0}, {}),
                              _origin_drafts("JP", {"CN": 30.0}, {})))
        assert rows[RC.BOTNET_OVERLAP_SIGNAL].country == ""
        assert rows[RC.BOTNET_OVERLAP_SIGNAL].domain == CYBER

    def test_it_does_not_belong_in_the_attribution_roster(self):
        """The roster (`v3/runtime/attribution.FAMILIES`) is for families
        v3 folds PER COUNTRY where production scores none — the score then
        moves to a synthesised countryless row. This row is not one: the
        fold never builds a per-country version of it, so there is no
        score to move and `collapse` has nothing to do. Proven by running
        the roster's own derivation, not by reading the table."""
        from v3.runtime import attribution as A
        assert RC.BOTNET_OVERLAP_SIGNAL not in A.COUNTRYLESS_SOURCES
        # `collapse` is RUN, not looked up: a name absent from the table
        # must also be a name the fold leaves alone.
        draft = ObservationDraft(
            signal_source=RC.BOTNET_OVERLAP_SIGNAL, domain=CYBER, country="",
            status=STATUS_FIRED, raw_score=2.0, value="x")
        assert A.collapse("cloudflare_radar", (draft,),
                          cores=("TW",)) == (draft,)

    def test_the_derived_roster_is_still_empty(self):
        """Imported rather than duplicated: `KNOWN_PER_COUNTRY_IN_V3_ONLY`
        is frozen empty and a fifth countryless row must not change it."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_roster", REPO / "tests" / "test_v3_country_attribution.py")
        roster = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(roster)
        assert roster._divergent() == roster.KNOWN_PER_COUNTRY_IN_V3_ONLY
        assert RC.BOTNET_OVERLAP_SIGNAL not in \
            roster._v3_admitting_rows_with_a_country()
        assert RC.BOTNET_OVERLAP_SIGNAL in roster._production_countryless()

    def test_it_adds_nothing_to_any_scenario_score(self):
        """The other half of the countryless claim, measured: S1-SCORE-012
        skips a global observation in `build_contributions`."""
        from v3.scoring.contributions import build_contributions
        settings = ScoringSettings()
        scenario = Scenario(scenario_id="s", participants=(
            Participant(country="TW", weight=1.0, role="primary_target"),))
        anchored = Observation(sensor="ripe_atlas", domain=CYBER,
                               status=STATUS_FIRED, score=3.0,
                               signal_source="atlas_latency",
                               countries=(CountryWeight("TW", 1.0),),
                               observed_at=NOW, value="x")
        overlap = _observation_of(C.botnet_overlap_verdict(9.0, True))
        alone = build_contributions((anchored,), scenario, settings=settings,
                                    now=NOW)
        beside = build_contributions((anchored, overlap), scenario,
                                     settings=settings, now=NOW)
        assert len(alone) == len(beside)


# ══ 6. the readers, enumerated before anything changed ═════════════════

class TestNoPerCountryReaderWasCreatedOrStarved:
    """The programme's signature defect is a reader that silently stops
    being fed. This family creates no per-country working value: its input
    is `cf_spike_target.flags["origins"]`, which already exists and which
    §7-2 #118 put there for three OTHER readers. The tests below fix that
    as a property rather than as a claim in a report."""

    def test_the_input_is_the_existing_measurement_face(self):
        from v3.adapters.cyber.cloudflare_radar import SPIKE_TARGET_SIGNAL
        rows = _fold(_origin_drafts("TW", {"CN": 40.0}, {"RU": 9.0}),
                     _origin_drafts("JP", {"CN": 30.0}, {}))
        faces = [d for d in rows if d.signal_source == SPIKE_TARGET_SIGNAL]
        assert {d.country for d in faces} == {"TW", "JP"}
        assert all("origins" in d.flags for d in faces)

    def test_the_measurement_face_still_never_scores(self):
        from v3.adapters.cyber.cloudflare_radar import SPIKE_TARGET_SIGNAL
        rows = _fold(_origin_drafts("TW", {"CN": 40.0}, {}))
        faces = [d for d in rows if d.signal_source == SPIKE_TARGET_SIGNAL]
        assert all(d.raw_score == 0.0 and d.status == "OBSERVED"
                   for d in faces)

    def test_the_l7_only_origin_is_carried_with_a_zero(self):
        """The one way this could have starved a reader quietly: dropping
        the zero-valued keys would lower every document frequency and
        inflate every weight, with no row missing and no test failing."""
        rows = _derived(_fold(_origin_drafts("TW", {"CN": 40.0}, {"RU": 9.0}),
                              _origin_drafts("JP", {"CN": 40.0}, {})))
        weights = rows[RC.BOTNET_OVERLAP_SIGNAL].flags["idf_weights_l3"]
        assert set(weights) == {"CN", "RU"}
        assert weights["CN"] == pytest.approx(0.0)   # in both documents
        assert weights["RU"] == pytest.approx(1.0)   # in one

    def test_the_row_discloses_its_whole_derivation(self):
        rows = _derived(_fold(_origin_drafts("TW", {"CN": 40.0}, {}),
                              _origin_drafts("JP", {"CN": 30.0}, {})))
        flags = rows[RC.BOTNET_OVERLAP_SIGNAL].flags
        assert set(flags["overlaps_idf_l3"]) == {"JP-TW"}
        assert flags["correlation_targets"] == ["JP", "TW"]
        assert flags["layer"] == "l3"
        assert flags["high_correlation"] is (flags["max_overlap_idf"] >= 1.5)
        assert flags["production_ref"] == "radar/routes/core.py:1042-1062"

    def test_the_l7_and_combined_maps_are_deliberately_absent(self):
        """Production computes three and reads one for anything that
        moves a number (`core.py:918`, `:1042`); the other two reach the
        API payload only (`core.py:2874`), for a frontend v3 does not
        have. Stated so the omission is a decision, not a gap."""
        source = CORE.read_text()
        assert "high_correlation = any(v >= _HIGH_CORR_IDF_MIN " \
               "for v in correlations_idf_l3.values())" in source
        assert '"correlations_idf_l7": correlations_idf_l7' in source
        rows = _derived(_fold(_origin_drafts("TW", {"CN": 40.0}, {}),
                              _origin_drafts("JP", {"CN": 30.0}, {})))
        assert "overlaps_idf_l7" not in rows[RC.BOTNET_OVERLAP_SIGNAL].flags


# ══ 7. the chain link that became reachable ════════════════════════════

class TestSyncDdosBecameReachable:
    """§7-2 #123's residual, half-closed. `chain_coverage()` went from two
    supplied link types to three, and three IS `SEQUENCE_MIN_CHAIN`, so
    `chain_bonus` stops being structurally zero for the first time."""

    def test_the_gate_reduces_to_the_two_rows(self):
        """`core.py:1309` has four conjuncts. `_overlap_active` is the
        return of the `add_rat` whose status IS `high_correlation`
        (`core.py:1055-1057`) and `_coord_active` likewise carries
        `is_coordinated` (`core.py:1076`), so the two-row form is the
        four-conjunct form."""
        lines = CORE.read_text().splitlines()
        assert lines[1308].strip() == (
            "if is_coordinated and high_correlation and _coord_active "
            "and _overlap_active:")
        assert '"FIRED" if high_correlation else "OK",' in "\n".join(
            lines[1054:1058])
        assert 'if is_coordinated else "OK"' in lines[1075]

    def test_the_conjunction_names_both_rows(self):
        entry = next(c for c in E.CONJUNCTIONS if c.event_type == E.SYNC_DDOS)
        assert entry.signal_sources == (RC.COORDINATED_SIGNAL,
                                        RC.BOTNET_OVERLAP_SIGNAL)

    def test_both_rows_firing_registers_the_event(self):
        events = E.arriving_from(
            (_global(RC.COORDINATED_SIGNAL), _global(RC.BOTNET_OVERLAP_SIGNAL)),
            (_scenario(),))
        assert {(e.country, e.event_type) for e in events} == {
            ("IL", "SYNC_DDOS"), ("IR", "SYNC_DDOS")}

    def test_one_row_alone_registers_nothing(self):
        for source in (RC.COORDINATED_SIGNAL, RC.BOTNET_OVERLAP_SIGNAL):
            assert E.arriving_from((_global(source),), (_scenario(),)) == ()

    def test_a_muted_half_closes_the_gate(self):
        """CLAUDE.md §5: the registration is `add_rat`'s return, and
        suppression is exactly what makes it False."""
        assert E.arriving_from(
            (_global(RC.COORDINATED_SIGNAL),
             _global(RC.BOTNET_OVERLAP_SIGNAL, suppressed=True)),
            (_scenario(),)) == ()

    def test_the_marginal_band_still_opens_the_link(self):
        """The property `admits()` would have deleted: `cf_botnet_overlap`
        scores 0 across the whole 1.5-2.0 band and still gates."""
        overlap = _global(RC.BOTNET_OVERLAP_SIGNAL, score=0.0)
        assert overlap.admits() is False
        events = E.arriving_from((_global(RC.COORDINATED_SIGNAL), overlap),
                                 (_scenario(),))
        assert [e.event_type for e in events] == ["SYNC_DDOS", "SYNC_DDOS"]

    def test_two_different_ticks_do_not_conjoin(self):
        """`sequence_history` hands a whole retention window to
        `arriving_from` in one call. Without the per-tick grouping a
        Monday `cf_coordinated` and a Tuesday `cf_botnet_overlap` would
        mint a SYNC_DDOS production never fired — the SENSITIVE direction,
        and an invented link is indistinguishable from an observed one
        once it is in the chain."""
        assert E.arriving_from(
            (_global(RC.COORDINATED_SIGNAL, at=NOW - 86000),
             _global(RC.BOTNET_OVERLAP_SIGNAL, at=NOW - 30)),
            (_scenario(),)) == ()

    def test_the_event_carries_the_adapter_that_justified_it(self):
        events = E.arriving_from(
            (_global(RC.COORDINATED_SIGNAL), _global(RC.BOTNET_OVERLAP_SIGNAL)),
            (_scenario(),))
        assert all(e.justified_by == ("cloudflare_radar",) for e in events)

    def test_the_history_query_still_retrieves_both_rows(self):
        """`sequence_history` filters L1 to `SUPPLIED_SOURCES` BEFORE
        projecting. A conjunction source missing from that set would work
        live and vanish on the next tick — the hardest shape of this
        defect to notice."""
        assert {RC.COORDINATED_SIGNAL, RC.BOTNET_OVERLAP_SIGNAL} <= \
            E.SUPPLIED_SOURCES

    def test_the_chain_bonus_is_now_reachable(self):
        coverage = E.chain_coverage()
        assert coverage["supplied"] == ["ISR_SURGE", "SYNC_DDOS",
                                        "FIRMS_ANOMALY"]
        assert coverage["chain_bonus_reachable"] is True
        assert coverage["missing"] == ["NARRATIVE_BURST"]


class TestTheSupplyRunsThroughTheCompositionRoute:
    """WP-4.1d's rule, restated by #123: a state machine whose only
    supply is a test fixture is 'tested and permanently silent'. So the
    link is exercised through `assemble`, off rows in the ledger."""

    @pytest.fixture
    def store(self, tmp_path):
        from v3.ledger import LedgerStore
        instance = LedgerStore(str(tmp_path / "corr.db"))
        yield instance
        instance.close()

    #: `v3/fetch/runner.py:560` — a countryless draft is STORED as the
    #: literal "GLOBAL", and `to_v3_observations` projects that back to
    #: `is_global`. Writing "" here would not even be accepted by L1.
    STORED_COUNTRY = "GLOBAL"

    @classmethod
    def _write(cls, store, signal_source, *, at, score, status=STATUS_FIRED):
        from v3.kernel import Evidence
        from v3.ledger.records import SignalObservation
        store.append_signal(SignalObservation(
            tick_id=f"t{int(at)}", sensor="cloudflare_radar",
            signal_source=signal_source, domain="cyber",
            country=cls.STORED_COUNTRY,
            evidence=Evidence.observe({}, observed_at=at,
                                      freshness_horizon_sec=86400.0,
                                      source="cloudflare_radar"),
            status=status, raw_score=score, flags={}), now=at)

    def test_assemble_derives_the_link_from_the_ledger(self, store):
        from v3.runtime.scoring import assemble
        self._write(store, RC.COORDINATED_SIGNAL, at=NOW - 30, score=1.0)
        self._write(store, RC.BOTNET_OVERLAP_SIGNAL, at=NOW - 30, score=0.0)
        inputs = assemble(now=NOW, store=store, settings=ScoringSettings(),
                          scenarios=(_scenario(),))
        assert {e.event_type for e in inputs.arriving_events} == {"SYNC_DDOS"}
        assert {e.country for e in inputs.arriving_events} == {"IL", "IR"}

    def test_the_retention_window_does_not_conjoin_across_ticks(self, store):
        from v3.runtime.scoring import assemble
        self._write(store, RC.COORDINATED_SIGNAL, at=NOW - 40000, score=1.0)
        self._write(store, RC.BOTNET_OVERLAP_SIGNAL, at=NOW - 30, score=0.0)
        inputs = assemble(now=NOW, store=store, settings=ScoringSettings(),
                          scenarios=(_scenario(),))
        assert inputs.arriving_events == ()

    def test_the_link_survives_into_the_prior_state(self, store):
        """The other half of #123: `run_tick` carries no state, so the
        chain's memory is re-derived from L1. A link that only exists in
        `arriving_events` has a one-tick life."""
        from v3.runtime.scoring import prior_state, sequence_history
        self._write(store, RC.COORDINATED_SIGNAL, at=NOW - 4000, score=1.0)
        self._write(store, RC.BOTNET_OVERLAP_SIGNAL, at=NOW - 4000, score=0.0)
        history = sequence_history(store, now=NOW, scenarios=(_scenario(),),
                                   retention_sec=86400.0)
        assert {e.event_type for e in history} == {"SYNC_DDOS"}
        state = prior_state(store, now=NOW, scenario_ids=("middle_east",),
                            sequence_events=history)
        assert state.sequence_events == history


# ── helpers ─────────────────────────────────────────────────────────────

def _scenario(scenario_id="middle_east", cores=("IL", "IR")):
    return Scenario(
        scenario_id=scenario_id,
        participants=tuple(
            Participant(country=c, weight=1.0, role="principal_belligerent")
            for c in cores))


def _global(signal_source, *, score=1.0, at=NOW - 30.0, suppressed=False):
    return Observation(
        sensor="cloudflare_radar", domain=CYBER,
        status=STATUS_FIRED, score=score, signal_source=signal_source,
        countries=(), suppressed=suppressed,
        suppress_reason="analyst_mute" if suppressed else None,
        observed_at=at, value="x")


def _origin_drafts(country, l3, l7):
    """The two CURRENT origin rows `normalize` produces, built directly."""
    from v3.adapters.cyber.cloudflare_radar import (ORIGIN_L3, ORIGIN_L7,
                                                    ORIGIN_SIGNALS)
    return tuple(
        ObservationDraft(signal_source=ORIGIN_SIGNALS[label], domain=CYBER,
                         country=country, status="OBSERVED", raw_score=0.0,
                         flags={"origins": dict(distribution)})
        for label, distribution in ((ORIGIN_L3, l3), (ORIGIN_L7, l7)))


def _fold(*draft_groups):
    drafts = tuple(d for group in draft_groups for d in group)
    from v3.runtime.baselines import ADVERSARY_ORIGINS, EFFECTIVE_CORES
    return RC._fold_cloudflare(drafts, {ADVERSARY_ORIGINS: ("CN",),
                                        EFFECTIVE_CORES: ("TW",)}, NOW)


def _derived(reduced):
    return {d.signal_source: d for d in reduced if not d.country}
