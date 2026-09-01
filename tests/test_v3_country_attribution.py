"""§7-2 #127 — which rows carry a country, measured on both sides.

The ruling that retired #118 named the reason the difference had survived:
**the parity gate cannot see it.** `v3/parity/adapter.py:175-177` takes
`country` from the STORED historical row, so production's countryless
history stays countryless through the harness and v3's live fold is never
exercised by it. A difference the gate structurally cannot measure cannot
be validated by the gate.

This module is the measurement the gate cannot make. It compares, per
signal name:

  production   does `rationale_to_signal` give this row a country? That is
               `rat.sensor in FOCUSED_ONLY_SENSOR_NAMES` and nothing else
               (`radar/routes/core.py:2039-2041`), where `rat.sensor` is
               `add_rat`'s FIRST POSITIONAL — a sensor name for twelve
               rows and a SIGNAL name for the rest.
  v3           can a row of this name reach a SCENARIO SCORE carrying a
               country? Three conditions, all measured: it is built with a
               country, it can be FIRED with a score above zero (that is
               `Observation.admits()`, `v3/scoring/inputs.py:249`), and
               `v3/runtime/attribution.collapse` does not move that score
               off it.

**"Carries a country" was the wrong question and it over-reported.** The
predicate that decides whether a scenario score moves is `admits()`, not
`country != ""`. Six of the fifteen families the first version of this
roster named — `greynoise`, `space_weather`, `peeringdb_ixp`,
`rss_narrative`, `telegram_mirror`, `travel_advisory` — cannot be FIRED
with a positive score at any construction site, so their country never
reached a scenario score at all and taking it away would have broken the
suppression join and four baseline reads to change no number. That is the
argument that already excluded `cf_spike_target` from the roster, applied
to the same predicate rather than to the two statuses somebody remembered.

The remaining nine were real, and `v3/runtime/attribution.py` moves their
score onto one countryless row. What is asserted below is that the roster
is now EMPTY — derived on both sides, so a tenth family, or a regression
in the fold, fails here instead of shipping.
"""
import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
CORE = REPO / "radar" / "routes" / "core.py"

#: Statuses a draft can be built with that can never pass the sequence
#: gate, so a row whose status expression mentions none of the others can
#: never be FIRED and can never admit. `STATUS_FIRED` is absent by
#: construction: its presence is what the test looks for.
_NEVER_FIRES = {"STATUS_OBSERVED", "STATUS_NO_DATA", "STATUS_OK",
                "STATUS_SUPPRESSED"}


def _production_add_rat_names():
    """Every `add_rat` first positional in the scoring pass."""
    names = set()
    for node in ast.walk(ast.parse(CORE.read_text())):
        if not isinstance(node, ast.Call):
            continue
        func = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if func == "add_rat" and node.args and \
                isinstance(node.args[0], ast.Constant):
            names.add(node.args[0].value)
    return names


def _production_countryless():
    from radar.scenarios import FOCUSED_ONLY_SENSOR_NAMES
    return {name for name in _production_add_rat_names()
            if name not in FOCUSED_ONLY_SENSOR_NAMES}


#: v3 row -> production `add_rat` name, where the two spell it differently.
#: Only renames appear; everything else maps to itself.
V3_TO_PRODUCTION = {
    "nasa_eonet": "nasa_firms",      # production's sensor never fetched FIRMS
    "atlas_latency": "ripe_atlas",
    "tor_clients": "tor_metrics",
    "ihr_hegemony": "ihr_disco",     # production has no add_rat for hegemony
    "cf_spike_target": "cf_spike_core",
}

#: The rows v3 writes with a country, able to score, whose production
#: counterpart is COUNTRYLESS. Empty, and empty is the assertion: every
#: family that used to be here is either countryless on its scoring face
#: (`v3/runtime/attribution.FAMILIES`) or provably unable to admit.
#:
#: A new per-country row for a countryless production entry fails the test
#: below rather than shipping unnoticed — which is what happened to
#: `cf_spike_core` (#118), whose three siblings were countryless while it
#: was not.
KNOWN_PER_COUNTRY_IN_V3_ONLY: frozenset = frozenset()


def _module_constants(tree):
    """Module-level `NAME = "literal"` bindings, for `signal_source=NAME`."""
    table = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and \
                isinstance(node.targets[0], ast.Name) and \
                isinstance(node.value, ast.Constant) and \
                isinstance(node.value.value, str):
            table[node.targets[0].id] = node.value.value
    return table


def _fold_factory_names():
    """`_fold_named_sources("x", ...)` — its first positional IS the row it
    emits, and the emitting draft names only the parameter."""
    names = set()
    for path in (REPO / "v3").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and \
                    getattr(node.func, "id", None) == "_fold_named_sources" \
                    and node.args and isinstance(node.args[0], ast.Constant):
                names.add(node.args[0].value)
    return frozenset(names)


def _factory_scopes(tree):
    """Line ranges of `_fold_named_sources` and anything nested in it.

    Scoped rather than global: `_derived_draft` also builds a draft from a
    parameter called `signal_source`, and resolving that name everywhere
    would file the cloudflare family's four countryless rows under three
    info names.
    """
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and \
                node.name == "_fold_named_sources":
            spans.append((node.lineno, node.end_lineno))
    return spans


def _resolve(node, constants, factory_names, in_factory, modules):
    """A draft's `signal_source`, as the set of names it can take."""
    if isinstance(node, ast.Constant):
        return {node.value}
    if isinstance(node, ast.Name):
        if node.id in constants:
            return {constants[node.id]}
        if in_factory and node.id == "signal_source":
            return set(factory_names)
    text = ast.unparse(node)
    CF, TOR, IHR, ATLAS = modules
    table = {
        "BGP_HIJACK_SIGNAL": {CF.BGP_HIJACK_SIGNAL},
        "BGP_LEAK_SIGNAL": {CF.BGP_LEAK_SIGNAL},
        "SPIKE_SIGNAL": {CF.SPIKE_SIGNAL},
        "SPIKE_TARGET_SIGNAL": {CF.SPIKE_TARGET_SIGNAL},
        "TOR_SIGNAL": {TOR.SIGNAL_SOURCE},
        "CLIENT_SIGNAL_SOURCE": {TOR.CLIENT_SIGNAL_SOURCE},
        "LABEL_SIGNAL_SOURCE[label]": set(IHR.LABEL_SIGNAL_SOURCE.values()),
        "LATENCY_SIGNAL_SOURCES.get(measurement_id, LATENCY_SIGNAL_SOURCE)":
            {ATLAS.LATENCY_SIGNAL_SOURCE},
    }
    return table.get(text, set())


def _v3_admitting_rows_with_a_country():
    """Signal sources v3 can write to L1 carrying a country AND admitting.

    Read from the DRAFT constructions, statically: the alternative is to
    run every adapter, and a row that only some payload shape produces
    would then depend on the fixture rather than on the code.

    Three conditions, because `admits()` has three
    (`v3/scoring/inputs.py:233,249` — FIRED, unsuppressed, score above
    zero) and a row failing any of them puts nothing into a scenario score
    no matter what country it names. `status` is read as "can this
    expression yield FIRED": an expression naming none of the never-firing
    constants is UNKNOWN and counted as firing, so an unreadable status is
    a false positive here rather than a silent omission.
    """
    from v3.adapters.cyber import cloudflare_radar as CF
    from v3.adapters.info import tor_metrics as TOR
    from v3.adapters.physical import ihr_health as IHR
    from v3.adapters.physical import ripe_atlas as ATLAS

    modules = (CF, TOR, IHR, ATLAS)
    factory_names = _fold_factory_names()
    admitting: dict = {}
    for path in sorted((REPO / "v3").rglob("*.py")):
        if "adapters" not in str(path) and "reduce" not in str(path):
            continue
        tree = ast.parse(path.read_text())
        constants = _module_constants(tree)
        spans = _factory_scopes(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = getattr(node.func, "id", None) or \
                getattr(node.func, "attr", None)
            if func != "ObservationDraft":
                continue
            keywords = {k.arg: k.value for k in node.keywords}
            source, country = keywords.get("signal_source"), \
                keywords.get("country")
            if source is None or country is None:
                continue
            has_country = not (isinstance(country, ast.Constant)
                               and country.value == "")
            status = keywords.get("status")
            status_text = ast.unparse(status) if status is not None else ""
            can_fire = ("STATUS_FIRED" in status_text
                        or not any(name in status_text
                                   for name in _NEVER_FIRES))
            score = keywords.get("raw_score")
            can_score = not (isinstance(score, ast.Constant)
                             and float(score.value) == 0.0)
            in_factory = any(start <= node.lineno <= end
                             for start, end in spans)
            reaches = has_country and can_fire and can_score
            for name in _resolve(source, constants, factory_names,
                                 in_factory, modules):
                admitting[name] = admitting.get(name, False) or reaches
    return {name for name, reaches in admitting.items() if reaches}


def _survives_the_fold(name):
    """Does a country-bearing, admitting row of this name still score?

    The fold is RUN rather than looked up in its own table: a family
    listed in `attribution.FAMILIES` that `collapse` never reaches would
    otherwise pass by being named.
    """
    from v3.adapters.types import CYBER, STATUS_FIRED, ObservationDraft
    from v3.runtime import attribution

    family = next((f for f in attribution.FAMILIES
                   if f.signal_source == name), None)
    adapter = family.adapter_id if family else name
    draft = ObservationDraft(signal_source=name, domain=CYBER, country="TW",
                             status=STATUS_FIRED, raw_score=2.0, value="x")
    return any(row.signal_source == name and row.country and row.raw_score > 0
               for row in attribution.collapse(adapter, (draft,),
                                               cores=("TW",)))


def _divergent():
    return {name for name in _v3_admitting_rows_with_a_country()
            if V3_TO_PRODUCTION.get(name, name) in _production_countryless()
            and _survives_the_fold(name)}


class TestTheAttributionRosterIsFrozen:
    def test_production_files_most_rows_under_signal_names(self):
        """The mechanism, measured rather than quoted: two thirds of
        production's rationale rows never acquire a country at all."""
        countryless = _production_countryless()
        assert len(countryless) >= 25
        assert "cf_spike_core" in countryless
        assert "cloudflare_radar" not in countryless

    def test_the_twelve_country_bearing_names_are_the_focused_tier(self):
        from radar.scenarios import FOCUSED_ONLY_SENSOR_NAMES
        bearing = _production_add_rat_names() & FOCUSED_ONLY_SENSOR_NAMES
        assert bearing <= FOCUSED_ONLY_SENSOR_NAMES
        assert len(bearing) == 12

    def test_the_divergent_set_is_exactly_the_registered_one(self):
        """§7-2 #127, after the disposition: nothing left."""
        divergent = _divergent()
        assert divergent == KNOWN_PER_COUNTRY_IN_V3_ONLY, {
            "unregistered": sorted(divergent - KNOWN_PER_COUNTRY_IN_V3_ONLY),
            "resolved": sorted(KNOWN_PER_COUNTRY_IN_V3_ONLY - divergent)}

    def test_the_nine_families_would_be_divergent_without_the_fold(self):
        """The counterfactual, so an empty roster cannot pass by the
        measurement having stopped working. Each of the nine still builds
        a country-bearing admitting draft; it is the fold, and only the
        fold, that keeps it out of a scenario score."""
        from v3.runtime import attribution
        named = {f.signal_source for f in attribution.FAMILIES}
        assert len(named) == 9
        admitting = _v3_admitting_rows_with_a_country()
        assert named <= admitting
        assert {V3_TO_PRODUCTION.get(n, n) for n in named} <= \
            _production_countryless()
        assert not any(_survives_the_fold(name) for name in named)

    def test_the_six_measurement_only_families_are_left_alone(self):
        """They never reached a scenario score, so their country is not an
        attribution difference — and `greynoise` / `space_weather` are read
        per country by the suppression join, which taking it away would
        have broken to change no number."""
        from v3.runtime import attribution, suppression
        measurement_only = {"greynoise", "space_weather", "peeringdb_ixp",
                            "rss_narrative", "telegram_mirror",
                            "travel_advisory"}
        assert measurement_only <= _production_countryless()
        assert not (measurement_only & _v3_admitting_rows_with_a_country())
        assert not (measurement_only & attribution.COUNTRYLESS_SOURCES)
        assert suppression.SPACE_WEATHER in measurement_only

    def test_the_cloudflare_family_is_no_longer_in_it(self):
        """#118's retirement, asserted where it would regress."""
        from v3.runtime import reduce_cyber as RC
        assert not (RC.COUNTRYLESS_SIGNALS & _divergent())
        assert "cf_spike_core" not in _v3_admitting_rows_with_a_country()

    def test_the_measurement_face_is_not_a_scoring_row(self):
        """`cf_spike_target` carries a country and is absent from the
        roster for one reason only: it is OBSERVED, so it never reaches a
        scenario score. If it ever fires, this test fails and the roster
        is wrong — which is the whole point of measuring rather than
        asserting the intent."""
        from v3.adapters.cyber import cloudflare_radar as CF
        from v3.runtime import reduce_cyber as RC
        assert CF.SPIKE_TARGET_SIGNAL not in \
            _v3_admitting_rows_with_a_country()
        source = (REPO / "v3" / "runtime" / "reduce_cyber.py").read_text()
        assert "status=STATUS_OBSERVED, raw_score=0.0" in source
        assert CF.SPIKE_TARGET_SIGNAL not in RC.COUNTRYLESS_SIGNALS


class TestTheGateCannotSeeAnyOfThis:
    """Claim (a) of the ruling, verified rather than assumed."""

    def test_the_parity_projection_reads_the_stored_country(self):
        source = (REPO / "v3" / "parity" / "adapter.py").read_text()
        assert 'country = (row.get("country") or "").strip()' in source

    def test_a_countryless_stored_row_stays_countryless_on_the_v3_side(self):
        from v3.parity.adapter import to_v3_observations
        rows = [{"sensor": "cloudflare_radar", "signal_source":
                 "cf_spike_core", "domain": "cyber", "status": "FIRED",
                 "raw_score": 3.0, "country": "", "confidence": 1.0,
                 "observed_at": 1_786_000_000.0, "payload": "3x"}]
        assert to_v3_observations(rows)[0].is_global is True

    def test_the_written_global_row_projects_back_as_countryless(self):
        """The collapse writes `country=""`, which the runner stores as the
        literal `"GLOBAL"` (`v3/fetch/runner.py:560`). If the projection
        read that as a country the whole disposition would invert: nine
        families would score against a participant nobody declared."""
        from v3.parity.adapter import to_v3_observations
        rows = [{"sensor": "gdelt", "signal_source": "gdelt",
                 "domain": "info", "status": "FIRED", "raw_score": 1.0,
                 "country": "GLOBAL", "confidence": 1.0,
                 "observed_at": 1_786_000_000.0, "payload": "ALERT"}]
        assert to_v3_observations(rows)[0].is_global is True

    def test_the_harness_therefore_never_runs_the_live_fold(self):
        """The fold is not on the replay path at all: the driver projects
        stored rows straight into the kernel."""
        source = (REPO / "v3" / "parity" / "driver_v3.py").read_text()
        assert "reduce" not in source
        assert "to_v3_observations" in source


class TestPhase9RemovedThisFloorOnPurpose:
    """Claim (b) of the ruling, verified against the line it cites."""

    def test_the_decoupling_names_the_constant_floor(self):
        source = (REPO / "radar" / "scoring.py").read_text()
        assert "constant floor that previously contaminated every scenario" \
            in source

    def test_the_decoupling_is_shipped_on(self):
        from radar import config
        assert config.GLOBAL_SIGNALS_DECOUPLED is True

    def test_a_countryless_signal_contributes_nothing_to_a_scenario(self):
        """Measured through production's own function, not read off the
        comment: the `continue` is what makes the difference 'N x weight
        vs ZERO' rather than 'N rows vs 1'."""
        import time

        from radar.scenarios import Participant, Role, Scenario
        from radar.scoring import Signal, compute_scenario_score
        now = time.time()
        scenario = Scenario(
            id="s", name_en="s", name_ja="s", description_en="",
            description_ja="", core_country="TW", state="active",
            enabled=True, tier=1,
            participants={"TW": Participant(country="TW", weight=1.0,
                                            role=Role.PRIMARY_TARGET)})
        countryless = Signal(signal_source="cf_spike_core",
                             sensor="cf_spike_core", observed_at=now,
                             domain="cyber", countries=[], raw_score=3.0,
                             value_display="3x")
        attributed = Signal(signal_source="cf_spike_core",
                            sensor="cf_spike_core", observed_at=now,
                            domain="cyber", countries=["TW"],
                            country_weights={"TW": 1.0}, raw_score=3.0,
                            value_display="3x")
        assert compute_scenario_score(scenario, [countryless],
                                      is_focused=True).score == 0.0
        assert compute_scenario_score(scenario, [attributed],
                                      is_focused=True).score > 0.0
