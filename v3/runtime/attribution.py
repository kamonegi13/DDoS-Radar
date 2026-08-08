"""Where the SCORE sits when production files a row under a SIGNAL name.

`add_rat`'s first positional becomes `RationaleEntry.sensor`, and
`radar/routes/core.py:2039-2041` gives a rationale entry a country ONLY
when that value is in `FOCUSED_ONLY_SENSOR_NAMES` (`radar/scenarios.py:75-79`,
twelve SENSOR names). Twenty-seven of production's thirty-nine `add_rat`
names are SIGNAL names, so `rationale_to_signal` builds them with
`countries=[]` (`radar/scoring.py:79`), and with `GLOBAL_SIGNALS_DECOUPLED`
shipped true (`radar/config.py:421`) `compute_scenario_score` skips them
outright (`radar/scoring.py:1452-1453`). Production's contribution from
such a row to EVERY scenario score is zero; it reaches only the global
envelope, at `global_signal_weight` (`radar/scoring.py:1177-1215`).

v3 folded nine of those families per country, so v3's per-scenario scores
carried `participant_weight x score` where production's carried nothing —
§7-2 #127, and the direction is sensitive. The parity harness cannot see
it: `v3/parity/adapter.py:175-177` takes `country` from the STORED row, so
production's countryless history stays countryless through the harness and
the live fold is not on the replay path at all.

**What moves is the SCORE, not the row.** The per-country rows stay,
keeping their country, status, suppression and flags, with `raw_score`
zeroed and the reading preserved in `flags["country_score"]`. They are the
`cf_spike_target` pattern (§7-2 #118) applied without renaming anything:
every reader keyed on `(signal_source, country)` is fed exactly as before,
`passes_gate()` still answers True for a FIRED row so its sequence-event
link survives, and `admits()` — `passes_gate()` AND `score > 0`
(`v3/scoring/inputs.py:249`) — now answers False, which is the whole
change. Renaming the face instead would have moved the break from "a
number is zero" to "a name is gone", and a reader that stops being fed is
invisible either way.

The verdict then leaves as ONE countryless row carrying the PRIMARY CORE's
reading, because production writes exactly one rationale entry per family
per cycle and computes it from `core_theater` (`core.py:1128` gdelt,
`:1190` threatfox, `:1391` greynoise, ... — every one of them reads
`<data>.get(core_theater)`).

**One row is not a preference, it is the ledger's rule.** L1 is UNIQUE on
`(tick_id, sensor, signal_source, country)` and `reduce._require_writable`
keys countryless rows as `(signal_source, "GLOBAL")`, so N countryless
rows of one family cannot be written at all. Aligning attribution and
collapsing to one row are the same act.

**This runs AFTER suppression.** `suppression.apply` decides per country
(`_fires` reads `severe_weather.get(draft.country)`), and GDELT's
weather-noise join is exactly that shape (`RULES`, §7-2 #42): a countryless
row would look up `""`, find nothing, and silently stop being suppressed —
production suppresses GDELT on `core_theater`'s weather
(`radar/sensors/gdelt.py:58,73,83`). Collapsing after `apply` copies the
primary core's already-decided suppression instead of re-deriving it.

Pure. `cores` arrives as an argument for the reason every fold's baselines
do: a step that read the scenario store mid-cycle could not be replayed,
and replay is what parity rests on.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Mapping, Sequence

from v3.adapters.types import STATUS_FIRED, ObservationDraft
from v3.kernel.errors import DomainError

#: Flag key holding the reading the row itself no longer scores. Named
#: rather than dropped: `is_heavy`-style booleans survive in `flags`
#: already, but the graded rungs (OONI 1 vs 2, IHR 1 vs 2, CT 1/2/3) live
#: only in the number, and an analyst asking "how hard did TW read" needs
#: an answer the countryless row cannot give.
COUNTRY_SCORE = "country_score"

#: Flag key on the face saying where its score went. Two rows of one
#: family with different scores is the kind of thing a reader has to be
#: told about rather than infer.
SCORE_MOVED_TO = "score_moved_to"
GLOBAL = "GLOBAL"

#: Flag keys on the countryless row: which core decided it, and out of
#: what set. NP6 — the choice of core is a derivation step and has to be
#: readable off the row, exactly as `cf_spike_core` carries `primary_core`.
PRIMARY_CORE = "primary_core"
COUNTRIES_MEASURED = "countries_measured"
EFFECTIVE_CORES_FLAG = "effective_cores"

#: The one anchor face this module emits. A name production does not
#: have, for the reason `cf_spike_target` is one: the working value it
#: carries (OONI's heavy rung) has a reader that the countryless row
#: cannot answer, and inventing the name is what makes the reader's input
#: visible in L1 instead of implicit in a score nobody can see.
OONI_HEAVY = "ooni_heavy"


@dataclass(frozen=True, slots=True)
class Countryless:
    """One family whose SCORING face carries no country, with the proof.

    `production_ref` is the `add_rat` site — the first positional there is
    the name that fails the `FOCUSED_ONLY_SENSOR_NAMES` test, so the
    reference IS the argument. `reads_core` is the line where production
    picks the country it judges, kept because "production judged the core
    theatre" is the claim the primary-core selection reproduces.
    """

    signal_source: str
    adapter_id: str
    domain: str
    production_ref: str
    reads_core: str
    register_ref: str = "§7-2 #127"
    #: A per-country row that exists ONLY to keep a sequence-event link
    #: alive, for a registration whose condition is a graded RUNG rather
    #: than "did it fire". `v3/scoring/inputs.py::Observation` carries no
    #: `flags`, so a rung the row states as a number is unreadable once
    #: the number moves to the countryless row, and the link would die
    #: silently — the shape §7-2 #118 was retired for. OONI is the only
    #: case: production registers CENSORSHIP_DETECTED on `_ooni_heavy`
    #: (`core.py:1710`), a bool that is exactly the rung scoring 2.
    anchor_source: str = ""
    #: The rung, read off the ORIGINAL per-country score before it moves.
    anchor_min_score: float = 0.0


#: The families v3 scored per country where production scores none. Each
#: is a production `add_rat` name that is NOT in `FOCUSED_ONLY_SENSOR_NAMES`
#: AND that v3 can emit FIRED with a positive score and a country —
#: `tests/test_v3_country_attribution.py` derives both halves and fails if
#: this table drifts from either.
#:
#: The six other §7-2 #127 families are absent on purpose. `greynoise`,
#: `space_weather` and `peeringdb_ixp` are scoreless by construction
#: (suppressors and an inventory row, `raw_score=0.0` at every
#: construction site), and `rss_narrative`, `telegram_mirror` and
#: `travel_advisory` land OBSERVED because their burst baselines are not
#: in L1 yet (`_fold_named_sources`). None of the six can reach `admits()`,
#: so none of them puts a number into a scenario score, so none of them is
#: an attribution difference — the argument that excludes `cf_spike_target`
#: from the roster, applied to the same predicate. Taking their countries
#: away would have broken the suppression join (`suppression.read_suppressors`
#: reads `greynoise` and `space_weather` per country) to change nothing.
FAMILIES: tuple[Countryless, ...] = (
    Countryless("cf_bgp_hijack", "cloudflare_radar", "cyber",
                "radar/routes/core.py:1165", "radar/routes/core.py:1152-1157"),
    Countryless("ct_log", "ct_log", "cyber",
                "radar/routes/core.py:1869", "radar/routes/core.py:1836-1848"),
    Countryless("gdelt", "gdelt", "info",
                "radar/routes/core.py:1132", "radar/routes/core.py:1128"),
    Countryless("gps_jamming", "gps_jamming", "physical",
                "radar/routes/core.py:1815", "radar/routes/core.py:1804-1808"),
    Countryless("ihr_delay", "ihr_health", "physical",
                "radar/routes/core.py:1518", "radar/routes/core.py:1498"),
    Countryless("ihr_hegemony", "ihr_health", "physical",
                "radar/routes/core.py:1501 (ihr_disco — production has no "
                "hegemony entry; §7-2 #31)",
                "radar/routes/core.py:1497"),
    Countryless("ooni_censorship", "ooni_censorship", "cyber",
                "radar/routes/core.py:1706", "radar/routes/core.py:1693",
                anchor_source=OONI_HEAVY, anchor_min_score=2.0),
    Countryless("threatfox", "threatfox", "cyber",
                "radar/routes/core.py:1190", "radar/routes/core.py:1189"),
    Countryless("tor_metrics", "tor_metrics", "info",
                "radar/routes/core.py:1576", "radar/routes/core.py:1553-1555"),
)

BY_ADAPTER: Mapping[str, tuple[Countryless, ...]] = {
    adapter: tuple(family for family in FAMILIES
                   if family.adapter_id == adapter)
    for adapter in {family.adapter_id for family in FAMILIES}
}

#: Every name this module moves the score off. Exported so a reader can
#: ask the question as a set membership instead of by scanning the table.
COUNTRYLESS_SOURCES: frozenset = frozenset(
    family.signal_source for family in FAMILIES)


def primary_core(cores: Sequence[str],
                 scores: Mapping[str, float]) -> str:
    """The core whose reading the countryless row carries.

    Production reads `core_theater`, which for a dual-core scenario is
    `primary_ec` — the argmax of the cores by their own measurement
    (`core.py:878-881`) — and for a single-core scenario is the scenario's
    only core. v3 acquires once for every scored scenario, so the set here
    is the UNION of their effective cores (§7-2 #124) and there is no
    focused scenario to name one of them. The argmax is production's own
    rule in the branch where it has to choose, it degenerates to
    production's answer whenever the union holds one measured core, and it
    picks the loudest reading, which is the NP1 direction.

    `max` returns the FIRST maximal element and the input is sorted, so a
    tie resolves alphabetically — production's behaviour for the same
    reason (`core.py:878`). A core with no reading defaults to 0.0, as
    production's `target_details.get(ec, {}).get("avg_spike", 0)` does.
    """
    ranked = sorted({str(core).strip().upper() for core in cores if core})
    if not ranked:
        return ""
    return max(ranked, key=lambda core: float(scores.get(core, 0.0)))


def collapse(adapter_id: str, drafts: Sequence[ObservationDraft], *,
             cores: Sequence[str]) -> tuple[ObservationDraft, ...]:
    """Move each family's score off its per-country rows onto one global row.

    Returns new drafts; nothing is mutated. An adapter no family names
    comes back untouched, which is most of them.

    A family whose measured countries include no effective core produces
    NO countryless row. Production would print an OK/0 entry there, and
    the two agree numerically — but an OK row v3 synthesised from a core
    it never measured is a claim of calm rather than an absence of
    measurement, and `_fold_cf_spike` declines the same synthesis for the
    same reason. The per-country readings still land; only the verdict is
    withheld, and `flags[PRIMARY_CORE]` is absent rather than empty so the
    withholding is readable.
    """
    families = BY_ADAPTER.get(adapter_id)
    if not families:
        return tuple(drafts)

    by_source: dict[str, list[ObservationDraft]] = {}
    for draft in drafts:
        if draft.signal_source not in COUNTRYLESS_SOURCES:
            continue
        if draft.country:
            by_source.setdefault(draft.signal_source, []).append(draft)
            continue
        raise DomainError(
            f"{adapter_id} already emitted a countryless "
            f"{draft.signal_source!r} row before this step. This layer emits "
            f"exactly one, and L1 is UNIQUE on (tick_id, sensor, "
            f"signal_source, country): a second row with identical content "
            f"is dropped SILENTLY (`v3/ledger/store.py:290`) and a differing "
            f"one raises inside the write. Either the fold now reaches the "
            f"verdict itself — in which case drop the family from FAMILIES "
            f"(§7-2 #127) — or the row is a mistake.")

    if not by_source:
        return tuple(drafts)

    ranked = sorted({str(core).strip().upper() for core in cores if core})
    out: list[ObservationDraft] = []
    emitted: list[ObservationDraft] = []
    for draft in drafts:
        members = by_source.get(draft.signal_source)
        if members is None or not draft.country:
            out.append(draft)
            continue
        family = _BY_SOURCE[draft.signal_source]
        anchor = _anchor_row(draft, family)
        if anchor is not None:
            emitted.append(anchor)
        out.append(_face(draft))
        if draft is members[0]:
            verdict = _verdict_row(members, ranked)
            if verdict is not None:
                emitted.append(verdict)
    return tuple(out + emitted)


def _anchor_row(draft: ObservationDraft,
                family: Countryless) -> ObservationDraft | None:
    """The rung, restated as a row so a sequence-event link can read it.

    FIRED with score 0.0 — `passes_gate()` True (the sequence gate has no
    score condition: `radar/routes/core.py:997`, CLAUDE.md §5) and
    `admits()` False, so the link survives and nothing is scored twice.
    The gate is read off the SOURCE row rather than re-derived: production
    registers on `_ooni_heavy and _ooni_active` (`core.py:1710`), which is
    the rung AND the row having fired unmuted, and both are facts the row
    in hand already states.
    """
    if not family.anchor_source:
        return None
    fired = draft.status == STATUS_FIRED and not draft.suppressed
    if not fired or float(draft.raw_score) < family.anchor_min_score:
        return None
    return replace(
        draft, signal_source=family.anchor_source, raw_score=0.0,
        flags={**dict(draft.flags),
               COUNTRY_SCORE: float(draft.raw_score),
               SCORE_MOVED_TO: GLOBAL,
               "anchors_for": family.signal_source,
               "anchor_min_score": family.anchor_min_score,
               "production_ref": family.production_ref})


def _face(draft: ObservationDraft) -> ObservationDraft:
    """The per-country row, unchanged except that it no longer scores.

    Status, suppression, confidence, value, reason and every flag survive
    — the row is still the country's reading and every reader keyed on it
    still reads it. `passes_gate()` is untouched by design: production
    gates sequence-event registration on FIRED-and-unmuted with NO score
    condition (`radar/routes/core.py:997`, CLAUDE.md §5), so zeroing the
    score here must not, and does not, delete a chain link.
    """
    return replace(draft, raw_score=0.0, flags={
        **dict(draft.flags),
        COUNTRY_SCORE: float(draft.raw_score),
        SCORE_MOVED_TO: GLOBAL})


def _verdict_row(members: Sequence[ObservationDraft],
                 ranked: Sequence[str]) -> ObservationDraft | None:
    """Production's single entry: the primary core's reading, countryless."""
    scores = {draft.country: float(draft.raw_score) for draft in members}
    core = primary_core(ranked, scores)
    chosen = next((draft for draft in members if draft.country == core), None)
    if chosen is None:
        return None
    return replace(
        chosen, country="", flags={
            **dict(chosen.flags),
            PRIMARY_CORE: core,
            COUNTRIES_MEASURED: sorted(scores),
            EFFECTIVE_CORES_FLAG: list(ranked),
            "production_ref": _BY_SOURCE[chosen.signal_source].production_ref})


_BY_SOURCE: Mapping[str, Countryless] = {
    family.signal_source: family for family in FAMILIES}


def registry_disclosure() -> list[dict]:
    """Every family whose score this layer moves, with its provenance (NP6)."""
    return [{"signal_source": family.signal_source,
             "adapter_id": family.adapter_id,
             "domain": family.domain,
             "production_ref": family.production_ref,
             "reads_core": family.reads_core,
             "register_ref": family.register_ref}
            for family in FAMILIES]


__all__ = ["Countryless", "FAMILIES", "BY_ADAPTER", "COUNTRYLESS_SOURCES",
           "collapse", "primary_core", "registry_disclosure",
           "COUNTRY_SCORE", "SCORE_MOVED_TO", "PRIMARY_CORE",
           "COUNTRIES_MEASURED", "EFFECTIVE_CORES_FLAG", "GLOBAL",
           "OONI_HEAVY"]
