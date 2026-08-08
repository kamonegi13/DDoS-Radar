"""`cloudflare_radar`'s fold — both halves, in one place.

One source, four endpoint families, and two joins that `normalize` cannot
perform because it sees one payload by construction (§2-2):

  BGP     hijacks OR route leaks -> production's single `cf_bgp_hijack`
          entry (§7-2 #12/#13, `core.py:1150-1170`).
  spike   this cycle's L3/L7 attack-ORIGIN distributions against the same
          target's baseline-window distributions -> `avg_spike`, and
          `avg_spike` against the target's hour-of-day history ->
          `cf_spike_core` (§7-2 #9's last withheld member, §7-2 #116's
          ranking quantity; `core.py:763-817` and `:1006-1025`) — plus the
          FOUR further entries production derives from the same numbers:
          `cf_vector_shift`, `cf_adversary_strike`, `cf_coordinated`
          (§7-2 #121, `core.py:1063-1076`) and `cf_botnet_overlap`
          (§7-2 #122, `core.py:1042-1062`, whose IDF correlation is
          `v3/runtime/correlation.py`). ALL FIVE are decided once per
          cycle rather than per country and carry NO country, which is
          production's own attribution — `_derived_rows` names the line
          that settles it. The per-target numbers those five are made of
          stay on `cf_spike_target`, the OBSERVED measurement face that
          mirrors production's `target_details` (`core.py:831`).

Moved out of `reduce_physical.py` when the second half landed: that
module is the physical-domain folds, and one adapter's two halves living
in different files is how the next reader concludes there is only one.

Everything here is a pure function of its arguments. The baseline values
and the adversary list arrive in the mapping the composition root read
before the cycle wrote anything; nothing opens a database, so a fold can
be replayed from recorded payloads exactly as it ran.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from v3.adapters.cyber.cloudflare_radar import (BGP_HIJACK_SIGNAL,
                                                BGP_LEAK_SIGNAL,
                                                LEAK_FIRE_THRESHOLD,
                                                ORIGIN_L3, ORIGIN_L3_BASELINE,
                                                ORIGIN_L7, ORIGIN_L7_BASELINE,
                                                ORIGIN_SIGNALS, SPIKE_SIGNAL,
                                                SPIKE_TARGET_SIGNAL)
from v3.adapters.types import (CYBER, STATUS_FIRED, STATUS_OBSERVED,
                               STATUS_OK, ObservationDraft)
from v3.runtime.baselines import ADVERSARY_ORIGINS, EFFECTIVE_CORES
from v3.runtime.correlation import (botnet_overlap_verdict, high_correlation,
                                    pairwise_idf)
from v3.runtime.reduce_common import _by_country, _first_url, _min_confidence
from v3.runtime.spike import (OriginSpike, adversary_strike_verdict,
                              coordinated_verdict, elevated_targets,
                              origin_spike, spike_verdict,
                              vector_shift_verdict)

#: The adapter's own `baseline_refs`, named here because this is what
#: reads them out of the cycle mapping.
ORIGIN_BASELINE_REF = "cf_origin_baseline"
SHARE_BASELINE_REF = "cf_attack_share_baseline"

#: The three entries production derives from the same origin distribution
#: (§7-2 #121), under PRODUCTION's own names — `add_rat`'s first positional
#: at `core.py:1070` / `:1075` / `:1076`, which becomes the Signal's
#: `signal_source` through `rationale_to_signal`'s `rat.signal_source or
#: rat.sensor` fallback (`radar/scoring.py:81`; these four calls pass no
#: `signal_source=`).
VECTOR_SHIFT_SIGNAL = "cf_vector_shift"
ADVERSARY_STRIKE_SIGNAL = "cf_adversary_strike"
COORDINATED_SIGNAL = "cf_coordinated"
#: `core.py:1056` — production's FIFTH entry off the same distribution,
#: and §7-2 #122's whole subject. It reads the IDF-weighted overlap
#: between participants' ORIGIN-COUNTRY histograms, which are the same
#: `l3_pct` numbers `cf_spike_target` already carries; the register's
#: belief that it needed `attacks/layer7/top/ases/origin` was a misread of
#: `compute_idf_weights`' docstring — see `v3/runtime/correlation.py`.
BOTNET_OVERLAP_SIGNAL = "cf_botnet_overlap"

#: Every entry the cloudflare fold files under a SIGNAL name, which is
#: the whole reason each is countryless (`core.py:2039-2041`). Named as a
#: set so a test can assert the property over the family instead of over
#: whichever member the author remembered — §7-2 #118 was a member added
#: with a country while its three siblings had none.
COUNTRYLESS_SIGNALS: frozenset = frozenset({
    SPIKE_SIGNAL, VECTOR_SHIFT_SIGNAL, ADVERSARY_STRIKE_SIGNAL,
    COORDINATED_SIGNAL, BOTNET_OVERLAP_SIGNAL})

#: The global TARGET shares, whose `share_pct` decides which origins are
#: eligible to be `shift_actors` (`core.py:744-745`, `:806`).
_SHARE_L3_SIGNAL = "cf_l3"
_SHARE_L7_SIGNAL = "cf_l7"

_ORIGIN_SIGNAL_SET = frozenset(ORIGIN_SIGNALS.values())
_CURRENT_L3 = ORIGIN_SIGNALS[ORIGIN_L3]
_CURRENT_L7 = ORIGIN_SIGNALS[ORIGIN_L7]
_BASELINE_L3 = ORIGIN_SIGNALS[ORIGIN_L3_BASELINE]
_BASELINE_L7 = ORIGIN_SIGNALS[ORIGIN_L7_BASELINE]

#: Which baseline the spike was computed against, on the row (NP6). The
#: three are genuinely different facts and one value for all three would
#: hide the middle one, which is the only one that means "a fetch failed
#: and the last good answer carried this tick".
BASELINE_FETCHED = "fetched"
BASELINE_STORED = "stored"
BASELINE_ABSENT = "absent"


def _fold_cf_bgp(drafts: Sequence[ObservationDraft],
                 baselines: Mapping[str, Any],
                 now: float) -> list[ObservationDraft]:
    """hijack OR leak -> the single `cf_bgp_hijack` entry (`core.py:1150-1170`).

    The port's docstring assumed S1-SCORE-008's MAX fold would reassemble
    the disjunction downstream. It would not have: the two halves shared a
    `signal_source`, so L1 rejected the second row before any scoring saw
    it (§7-2 #12). They were split into two names to survive the ledger,
    and rejoined here, where the country's whole picture exists.

    Untouched rows pass through: `cf_l3` / `cf_l7` are the global TARGET
    shares, a different quantity from the per-target origin distribution
    `_fold_cf_spike` judges.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        hijack = next((d for d in group
                       if d.signal_source == BGP_HIJACK_SIGNAL), None)
        leak = next((d for d in group
                     if d.signal_source == BGP_LEAK_SIGNAL), None)
        reduced.extend(d for d in group
                       if d.signal_source not in (BGP_HIJACK_SIGNAL,
                                                  BGP_LEAK_SIGNAL))
        if hijack is None and leak is None:
            continue
        hijacks = int((hijack.flags.get("count", 0) if hijack else 0) or 0)
        ongoing = int((hijack.flags.get("ongoing", 0) if hijack else 0) or 0)
        leaks = int((leak.flags.get("count", 0) if leak else 0) or 0)
        fired = ongoing > 0 or leaks >= LEAK_FIRE_THRESHOLD
        present = [d for d in (hijack, leak) if d is not None]
        reduced.append(ObservationDraft(
            signal_source=BGP_HIJACK_SIGNAL, domain=present[0].domain,
            country=country,
            status=STATUS_FIRED if fired else STATUS_OK,
            raw_score=1.0 if fired else 0.0,
            confidence=_min_confidence(present),
            value=f"hijack={hijacks}(ongoing={ongoing}) leak={leaks}",
            reason=(f"BGP manipulation detected: {ongoing} ongoing "
                    f"hijack(s), {leaks} route leak(s)") if fired else "",
            flags={"hijacks": hijacks, "ongoing": ongoing, "leaks": leaks,
                   "leak_fire_threshold": LEAK_FIRE_THRESHOLD,
                   "events": [event for d in present
                              for event in list(d.flags.get("events", ()))],
                   "folded_sources": [d.signal_source for d in present]},
            evidence_url=_first_url(present)))
    return reduced


def _origins_of(draft: Optional[ObservationDraft]) -> dict:
    return dict((draft.flags.get("origins") or {})) if draft else {}


def _share_pct(group: Sequence[ObservationDraft], signal_source: str) -> float:
    """This target's global attack share, or production's own default.

    `core.py:744` reads `g_l3.get(t, 0.0)`: a target Cloudflare does not
    rank at all is 0.0, not absent, and the floor at `:745` then lifts it.
    A country with no `cf_l3` row is exactly that case — `_attack_shares`
    emits a row only for countries the payload named.
    """
    for draft in group:
        if draft.signal_source == signal_source:
            value = draft.flags.get("share_pct")
            if not isinstance(value, bool) and isinstance(value, (int, float)):
                return float(value)
    return 0.0


def stored_baseline(snapshot: Optional[Mapping[str, Sequence]],
                    country: str) -> tuple[dict, dict]:
    """The last stored origin snapshot for a target, or two empty dicts.

    Production keeps this in its own table and refreshes it only when it
    is over a day old (`core.py:738-742`); its fetch helper additionally
    preserves a stale entry when a call comes back empty
    (`scoring.py:648-654`). Both exist for the same reason: an empty
    baseline is not a measurement of a calm world, it is the input the
    anti-inflation guard refuses to compute with.
    """
    rows = (snapshot or {}).get(country) or ()
    for row in reversed(list(rows)):
        payload = (row.get("payload") if isinstance(row, Mapping) else None) \
            or {}
        l3 = dict(payload.get("l3") or {})
        l7 = dict(payload.get("l7") or {})
        if l3 or l7:
            return l3, l7
    return {}, {}


def _fold_cf_spike(drafts: Sequence[ObservationDraft],
                   baselines: Mapping[str, Any],
                   now: float) -> list[ObservationDraft]:
    """Four origin payloads -> the measurement face, then the five entries.

    **The four inputs never reach L1.** Production writes ONE rationale
    record per cycle (`core.py:1025`); the per-window, per-layer rows
    exist only so that four payloads can survive the ledger's uniqueness
    key long enough to be joined, and keeping them would be four
    observations production never made.

    **What IS per-country is the measurement, not the verdict.**
    `cf_spike_target` carries one target's `avg_spike` and the numbers
    behind it, OBSERVED and unscored, because that is what production
    keeps per target: `target_details` (`core.py:831`) is a working
    structure the rationale entry never sees. Three readers need it —
    the chain owner (`core.py:878-881`), the hour-of-day sample
    (`core.py:824-825`) and the stored origin baseline
    (`core.py:739-742`) — and in v3 a fold reaches its readers only
    through L1, so the working values are written rather than passed.

    **A country with no CURRENT origin payload gets no row at all.** A
    fetch that did not happen is not a measurement of calm, and an
    OBSERVED/0.0 row would be indistinguishable from a quiet target in
    every downstream view.

    The warm-up branch is production's, not a withholding: below seven
    same-hour samples it scores on raw ratios (`core.py:1015-1018`), so a
    newly watched target is judged from its first cycle.
    """
    adversaries = tuple(baselines.get(ADVERSARY_ORIGINS) or ())
    cores = tuple(baselines.get(EFFECTIVE_CORES) or ())
    snapshot = baselines.get(ORIGIN_BASELINE_REF)
    history = baselines.get(SHARE_BASELINE_REF) or {}
    reduced = []
    measured: dict[str, OriginSpike] = {}
    contributing: list[ObservationDraft] = []
    for country, group in _by_country(drafts).items():
        rows = {d.signal_source: d for d in group
                if d.signal_source in _ORIGIN_SIGNAL_SET}
        reduced.extend(d for d in group
                       if d.signal_source not in _ORIGIN_SIGNAL_SET)
        if _CURRENT_L3 not in rows and _CURRENT_L7 not in rows:
            continue

        fetched_l3 = _origins_of(rows.get(_BASELINE_L3))
        fetched_l7 = _origins_of(rows.get(_BASELINE_L7))
        if fetched_l3 or fetched_l7:
            base_l3, base_l7 = fetched_l3, fetched_l7
            source = BASELINE_FETCHED
        else:
            base_l3, base_l7 = stored_baseline(snapshot, country)
            source = BASELINE_STORED if (base_l3 or base_l7) \
                else BASELINE_ABSENT

        spike = origin_spike(current_l3=_origins_of(rows.get(_CURRENT_L3)),
                             current_l7=_origins_of(rows.get(_CURRENT_L7)),
                             baseline_l3=base_l3, baseline_l7=base_l7,
                             adversaries=adversaries,
                             global_l3_pct=_share_pct(group, _SHARE_L3_SIGNAL),
                             global_l7_pct=_share_pct(group, _SHARE_L7_SIGNAL))
        present = list(rows.values())
        measured[country] = spike
        contributing.extend(present)
        reduced.append(ObservationDraft(
            signal_source=SPIKE_TARGET_SIGNAL, domain=CYBER, country=country,
            # OBSERVED and 0.0: production reaches no per-target verdict
            # (`compute_hod_zscore` is called once, on `primary_ec` —
            # `core.py:1006`), so a per-target FIRED here would be a
            # conclusion production never draws. OBSERVED also keeps the
            # row out of `passes_gate()` and `admits()`, so the
            # measurement face cannot score or justify a chain link.
            status=STATUS_OBSERVED, raw_score=0.0,
            confidence=_min_confidence(present),
            value=f"{spike.avg_spike:.2f}x [baseline {source}]", reason="",
            flags={"avg_spike": spike.avg_spike,
                   "avg_l3_spike": round(spike.avg_l3_spike, 2),
                   "avg_l7_spike": round(spike.avg_l7_spike, 2),
                   "total_local_pct": round(spike.total_local_pct, 2),
                   "has_baseline": spike.has_baseline,
                   "is_vector_shift": spike.is_vector_shift,
                   "shift_actors": list(spike.shift_actors),
                   "origins": dict(spike.origins),
                   # Carried on the row because the NEXT cycle's fallback
                   # is written from it (`v3/runtime/record.py`) — the
                   # snapshot is stored from what the ledger holds, never
                   # from a draft in flight.
                   "origin_baseline": {"l3": base_l3, "l7": base_l7},
                   "baseline_source": source,
                   "adversary_origins": sorted(adversaries),
                   "production_ref": "radar/routes/core.py:831 "
                                     "(target_details)",
                   "folded_sources": [d.signal_source for d in present]},
            evidence_url=_first_url(present)))
    # A cycle in which no target produced a current distribution makes no
    # derived claim either. Production would emit four OK/0 rows here;
    # v3 does not, for the reason the per-country loop skips a country
    # with no payload — a fetch that did not happen is not a measurement
    # of calm. Score is 0 on both sides, so nothing numeric moves.
    if measured:
        reduced.extend(_derived_rows(measured, cores=cores,
                                     contributing=contributing,
                                     history=history))
    return reduced


def _derived_rows(measured: Mapping[str, OriginSpike], *,
                  cores: Sequence[str],
                  contributing: Sequence[ObservationDraft],
                  history: Mapping[str, Sequence[float]]
                  ) -> list[ObservationDraft]:
    """The FIVE entries production makes of one cycle's origin data.

    **None of the five is per-scenario, and none carries a country.** The
    line that settles it is `radar/routes/core.py:2039-2041`, where a
    rationale entry acquires a country ONLY if `rat.sensor in
    FOCUSED_ONLY_SENSOR_NAMES`. That frozenset (`radar/scenarios.py:75-79`)
    holds sensor names — `cloudflare_radar`, `ioda_bgp`, ... — and all five
    entries are filed under SIGNAL names, so none matches and all five
    become countryless Signals (`radar/scoring.py:79`). Countryless is
    not a gap here: it is production's own attribution, it is what
    `compute_global_threat` aggregates (`radar/scoring.py:1177-1215`), and
    with `GLOBAL_SIGNALS_DECOUPLED` shipped true (`radar/config.py:421`)
    it is what keeps them out of every scenario score
    (`radar/scoring.py:1452-1453`). v3 reaches the same place through
    `Observation.is_global` and S1-SCORE-012.

    `cf_spike_core` was one of them for one release and was emitted per
    participant instead (§7-2 #118). The register called that a
    sensitive-direction widening of "one row into N"; it was in fact
    "zero into N x coupling weight", because the countryless row scores
    nothing per scenario. Phase 9 (2026-05-13) decoupled global signals
    precisely to delete "the ~1.5 constant floor that previously
    contaminated every scenario" (`radar/scoring.py:1448-1451`), and a
    floor that rises equally on a quiet day is bias rather than
    detection, so NP1 does not shelter it. Worse, the parity harness
    could not see the difference at all: `v3/parity/adapter.py:175-177`
    takes `country` from the STORED row, so production's countryless
    history stays countryless on both sides and the divergence lived
    only in v3's live fold, where nothing measured it.

    `source_country=_adv_top_actor` at `core.py:1075` does NOT contradict
    this: that argument is consumed by `classify_direction` and the two
    context helpers inside `add_rat` (`core.py:956-971`) and never reaches
    `RationaleEntry`, so it decorates the CAC direction and nothing else.
    Carried in the flags for the same reason production computes it.

    The set the five range over is the CYCLE's countries, where
    production's is the focused scenario's `strategic_theaters`. v3 scores
    every scenario from one acquisition, so the union is what exists. That
    widening is §7-2 #124's, and it is the direction NP1 accepts — the
    rows carry `targets_measured` / `effective_cores` / `primary_core` so
    which set decided them is readable off the row.

    **The fifth entry is `cf_botnet_overlap` (§7-2 #122)**, and it needed
    no fetch: the histograms it correlates are the ORIGIN-COUNTRY
    distributions already on every `OriginSpike`, not the ASN histogram
    the register named. For this row the widened set is NOT simply the
    sensitive direction — `idf_weights` is scoped to the compared
    countries (`core.py:846-855`), so a wider scope both adds pairs (which
    can only raise `max`) and re-weights every key (which can move it
    either way). Registered under §7-2 #124 with that asymmetry stated;
    the row carries `correlation_targets` and `idf_weights_l3` so the
    scope that decided it is readable.
    """
    shifted = sorted(country for country, spike in measured.items()
                     if spike.is_vector_shift)
    elevated = list(elevated_targets({country: spike.avg_spike
                                      for country, spike in measured.items()}))
    strikes = [dict(strike, target=country)
               for country in sorted(measured)
               for strike in measured[country].strikes]

    # `core.py:877` / `:886` — the STATUS is "did any effective core
    # shift", never "did anything shift".
    ranked = sorted(str(core).upper() for core in cores)
    core_shifted = any(core in shifted for core in ranked)
    # `core.py:878-881` — `max` over the sorted cores by `avg_spike`, with
    # production's own 0 default for a core that has no reading
    # (`target_details.get(ec, {}).get("avg_spike", 0)`). `max` returns the
    # FIRST maximal element, so a tie resolves alphabetically.
    primary = max(ranked,
                  key=lambda core: (measured[core].avg_spike
                                    if core in measured else 0.0),
                  default="")
    # `core.py:1064-1065` — the ROUNDED means off `target_details`
    # (`core.py:831`), and 0 when the primary core has no entry.
    core_l7 = round(measured[primary].avg_l7_spike, 2) \
        if primary in measured else 0
    core_l3 = round(measured[primary].avg_l3_spike, 2) \
        if primary in measured else 0

    # `core.py:872-884` — `core_spike` is the primary core's own
    # `avg_spike`, by BOTH branches: the dual-core branch takes
    # `max(avg_spike)` while `primary_ec` takes the argmax of the same
    # lookup, and the single-core branch reads `core_theater`, which is
    # its only effective core. Production's default for a core with no
    # entry is 0 (`target_details.get(ec, {}).get("avg_spike", 0)`).
    core_spike = measured[primary].avg_spike if primary in measured else 0.0
    # `core.py:1006` — ONE hour-of-day verdict per cycle, on the primary
    # core's series. Not one per participant: that is §7-2 #118.
    spike = spike_verdict(history.get(primary, ()), core_spike)

    shift = vector_shift_verdict(shifted_targets=shifted,
                                 core_shifted=core_shifted,
                                 core_l7_spike=core_l7, core_l3_spike=core_l3)
    strike = adversary_strike_verdict(strikes)
    coordinated = coordinated_verdict(elevated)

    # `core.py:785,810` — `normalized_dist_l3` keyed by ORIGIN COUNTRY, one
    # entry per code in `set(o_l3) | set(o_l7)`. A code seen only in the L7
    # payload is present here with 0.0, and it must be: `compute_idf_weights`
    # counts KEYS, so dropping the zeros would lower every document
    # frequency and inflate the weights.
    distributions_l3 = {
        country: {code: float(working.get("l3_pct", 0.0))
                  for code, working in target_spike.origins.items()}
        for country, target_spike in measured.items()}
    correlations = pairwise_idf(distributions_l3)
    # `core.py:1042` — `max(..., default=0.0)`; `core.py:918` — `any(...)`.
    max_overlap = correlations.max_overlap
    correlated = high_correlation(correlations.overlaps)
    overlap = botnet_overlap_verdict(max_overlap, correlated)

    shared = {"targets_measured": sorted(measured),
              "effective_cores": list(ranked),
              "primary_core": primary}
    return [
        _derived_draft(SPIKE_SIGNAL, spike, contributing,
                       # `core_avg_spike`, never `avg_spike`: the
                       # per-country name belongs to the measurement face
                       # and a countryless row answering to it would be
                       # read as a target's reading by anything that
                       # scans for the key.
                       {**shared, "core_avg_spike": core_spike,
                        "hod_z": (None if spike.z is None
                                  else round(spike.z, 2)),
                        "hod_n": spike.n, "hod_valid": spike.valid,
                        "production_ref": "radar/routes/core.py:1006-1025"}),
        _derived_draft(VECTOR_SHIFT_SIGNAL, shift, contributing,
                       {**shared, "shifted_targets": shifted,
                        "core_shifted": core_shifted,
                        "core_avg_l7_spike": core_l7,
                        "core_avg_l3_spike": core_l3,
                        "shift_actors": {country: list(spike.shift_actors)
                                         for country, spike in
                                         sorted(measured.items())
                                         if spike.shift_actors},
                        "production_ref": "radar/routes/core.py:1063-1070"}),
        _derived_draft(ADVERSARY_STRIKE_SIGNAL, strike, contributing,
                       {**shared, "strikes": strikes,
                        "strike_count": len(strikes),
                        # `core.py:1074`. Production reads `[0]` off a list
                        # built by iterating two SETS, so which actor it
                        # names is not determined; v3 sorts. Neutral — the
                        # value never leaves the CAC decoration.
                        "top_actor": strikes[0]["actor"] if strikes else "",
                        "production_ref": "radar/routes/core.py:1071-1075"}),
        _derived_draft(COORDINATED_SIGNAL, coordinated, contributing,
                       {**shared, "elevated_targets": elevated,
                        "production_ref": "radar/routes/core.py:863-864,1076"}),
        _derived_draft(BOTNET_OVERLAP_SIGNAL, overlap, contributing,
                       # The whole derivation, because a bare "1.83 IDF
                       # overlap" is not a checkable claim: the pair map
                       # says which two countries produced it and the
                       # weight map says which origins were treated as
                       # rare. Both are bounded by the cycle's countries
                       # and their origin codes (NP6).
                       {**shared, "max_overlap_idf": max_overlap,
                        "high_correlation": correlated,
                        "overlaps_idf_l3": dict(correlations.overlaps),
                        "idf_weights_l3": dict(correlations.weights),
                        "correlation_targets": sorted(distributions_l3),
                        "layer": "l3",
                        "production_ref": "radar/routes/core.py:1042-1062"}),
    ]


def _derived_draft(signal_source: str, verdict, contributing, flags
                   ) -> ObservationDraft:
    """One derived row. `country=""` IS the claim — see `_derived_rows`."""
    return ObservationDraft(
        signal_source=signal_source, domain=CYBER, country="",
        status=STATUS_FIRED if verdict.fired else STATUS_OK,
        raw_score=verdict.score,
        # The weakest input governs, as it does for `cf_spike_core`.
        # Production uses the sensor's confidence curve on the primary
        # core's HOD sample count instead (`core.py:1024`); that curve is
        # a sensor object v3's folds do not hold, and the difference is
        # registered rather than approximated.
        confidence=_min_confidence(contributing),
        value=verdict.value, reason=verdict.reason,
        flags=flags, evidence_url=_first_url(contributing))


def _fold_cloudflare(drafts: Sequence[ObservationDraft],
                     baselines: Mapping[str, Any],
                     now: float) -> list[ObservationDraft]:
    """The adapter's whole fold: BGP first, then the spike.

    Sequenced rather than merged because the two joins share nothing but
    the country grouping, and a single loop over both would make the
    reader hold the disjunction and the ratio at the same time.
    """
    return _fold_cf_spike(_fold_cf_bgp(drafts, baselines, now),
                          baselines, now)


__all__ = ["_fold_cloudflare", "_fold_cf_bgp", "_fold_cf_spike",
           "_derived_rows", "stored_baseline", "ORIGIN_BASELINE_REF",
           "SHARE_BASELINE_REF", "BASELINE_FETCHED", "BASELINE_STORED",
           "BASELINE_ABSENT", "VECTOR_SHIFT_SIGNAL",
           "ADVERSARY_STRIKE_SIGNAL", "COORDINATED_SIGNAL",
           "COUNTRYLESS_SIGNALS"]
