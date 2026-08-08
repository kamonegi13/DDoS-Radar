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
  v3           does the fold put a country on the row that reaches L1?

The roster below is the answer, frozen. It is not an aspiration: fifteen
families disagree today, in the sensitive direction, and the two arguments
that reversed #118 apply to every one of them. Freezing it means the set
cannot grow, shrink or drift without a decision.
"""
import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
CORE = REPO / "radar" / "routes" / "core.py"


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

#: The rows v3 writes with a country whose production counterpart is
#: COUNTRYLESS. Direction: **sensitive** — production contributes 0 to
#: every scenario score for these (`radar/scoring.py:1452-1453` under
#: `GLOBAL_SIGNALS_DECOUPLED`, shipped true) and reaches only the global
#: envelope at x0.5, while v3 contributes participant weight x score to
#: the scenario itself.
#:
#: Frozen, not accepted. Registered as §7-2 #127 with the note that the
#: two arguments that reversed #118 — the gate cannot see it, and Phase 9
#: (2026-05-13) removed exactly this constant floor on purpose
#: (`radar/scoring.py:1448-1451`) — apply unchanged to all fifteen. The
#: disposition is an owner's, because making them countryless removes
#: most of v3's per-scenario detection and that is not a fold-level call.
KNOWN_PER_COUNTRY_IN_V3_ONLY = frozenset({
    "cf_bgp_hijack", "ct_log", "gdelt", "gps_jamming", "greynoise",
    "ihr_delay", "ihr_hegemony", "ooni_censorship", "peeringdb_ixp",
    "rss_narrative", "space_weather", "telegram_mirror", "threatfox",
    "tor_metrics", "travel_advisory",
})


#: Statuses that mean "measured, no verdict". A draft that can only ever
#: carry one of these never reaches a scenario score, so its country is
#: not an attribution difference — `cf_spike_target` is exactly that row.
_NON_SCORING_STATUSES = {"STATUS_OBSERVED", "STATUS_NO_DATA"}


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


def _fold_factory_names(tree):
    """`_fold_named_sources("x", ...)` — its first positional IS the row it
    emits, and the emitting draft names only the parameter."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and \
                getattr(node.func, "id", None) == "_fold_named_sources" and \
                node.args and isinstance(node.args[0], ast.Constant):
            names.add(node.args[0].value)
    return names


def _v3_rows_with_a_country():
    """Signal sources v3 writes to L1 carrying a country AND able to score.

    Read from the DRAFT constructions, statically: the alternative is to
    run every adapter, and a row that only some payload shape produces
    would then depend on the fixture rather than on the code.
    """
    from v3.adapters.cyber import cloudflare_radar as CF
    from v3.adapters.info import tor_metrics as TOR
    from v3.adapters.physical import ihr_health as IHR
    from v3.adapters.physical import ripe_atlas as ATLAS

    scoring: dict = {}
    factory_rows = set()
    for path in sorted((REPO / "v3").rglob("*.py")):
        if "adapters" not in str(path) and "reduce" not in str(path):
            continue
        tree = ast.parse(path.read_text())
        constants = _module_constants(tree)
        factory_rows |= _fold_factory_names(tree)
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
            can_score = not (status is not None
                             and getattr(status, "id", None)
                             in _NON_SCORING_STATUSES)
            for name in _resolve(source, constants, CF, TOR, IHR, ATLAS):
                scoring[name] = scoring.get(name, False) or (has_country
                                                             and can_score)
    # `_fold_named_sources` emits `country=country` for every one of them.
    for name in factory_rows:
        scoring[name] = True
    return {name for name, carried in scoring.items() if carried}


def _resolve(node, constants, CF, TOR, IHR, ATLAS):
    """A draft's `signal_source`, as the set of names it can take."""
    if isinstance(node, ast.Constant):
        return {node.value}
    if isinstance(node, ast.Name) and node.id in constants:
        return {constants[node.id]}
    text = ast.unparse(node)
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
        """§7-2 #127. A new per-country row for a countryless production
        entry fails here rather than shipping unnoticed — which is what
        happened to `cf_spike_core` (#118), whose three siblings were
        countryless while it was not."""
        countryless = _production_countryless()
        divergent = set()
        for row in _v3_rows_with_a_country():
            production = V3_TO_PRODUCTION.get(row, row)
            if production in countryless:
                divergent.add(row)
        assert divergent == KNOWN_PER_COUNTRY_IN_V3_ONLY, {
            "unregistered": sorted(divergent - KNOWN_PER_COUNTRY_IN_V3_ONLY),
            "resolved": sorted(KNOWN_PER_COUNTRY_IN_V3_ONLY - divergent)}

    def test_the_cloudflare_family_is_no_longer_in_it(self):
        """#118's retirement, asserted where it would regress."""
        from v3.runtime import reduce_cyber as RC
        assert not (RC.COUNTRYLESS_SIGNALS & KNOWN_PER_COUNTRY_IN_V3_ONLY)
        assert "cf_spike_core" not in _v3_rows_with_a_country()

    def test_the_measurement_face_is_not_a_scoring_row(self):
        """`cf_spike_target` carries a country and is absent from the
        roster for one reason only: it is OBSERVED, so it never reaches a
        scenario score. If it ever fires, this test fails and the roster
        is wrong — which is the whole point of measuring rather than
        asserting the intent."""
        from v3.adapters.cyber import cloudflare_radar as CF
        from v3.runtime import reduce_cyber as RC
        assert CF.SPIKE_TARGET_SIGNAL not in _v3_rows_with_a_country()
        assert CF.SPIKE_TARGET_SIGNAL not in KNOWN_PER_COUNTRY_IN_V3_ONLY
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
