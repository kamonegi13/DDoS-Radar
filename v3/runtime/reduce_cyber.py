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
          THREE further entries production derives from the same numbers,
          which §7-2 #121 registered as missing: `cf_vector_shift`,
          `cf_adversary_strike`, `cf_coordinated` (`core.py:1063-1076`).
          Those three are decided once per cycle rather than per country
          and carry NO country, which is production's own attribution —
          `_derived_rows` names the line that settles it.

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
                                                ORIGIN_SIGNALS, SPIKE_SIGNAL)
from v3.adapters.types import (CYBER, STATUS_FIRED, STATUS_OK,
                               ObservationDraft)
from v3.runtime.baselines import ADVERSARY_ORIGINS, EFFECTIVE_CORES
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
    """Four origin payloads -> production's four cloudflare spike entries.

    **The four inputs never reach L1.** Production writes ONE rationale
    record per country per cycle (`core.py:1025`); the per-window,
    per-layer rows exist only so that four payloads can survive the
    ledger's uniqueness key long enough to be joined, and keeping them
    would be four observations production never made.

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
        verdict = spike_verdict(history.get(country, ()), spike.avg_spike)
        present = list(rows.values())
        measured[country] = spike
        contributing.extend(present)
        reduced.append(ObservationDraft(
            signal_source=SPIKE_SIGNAL, domain=CYBER, country=country,
            status=STATUS_FIRED if verdict.fired else STATUS_OK,
            raw_score=verdict.score,
            confidence=_min_confidence(present),
            value=verdict.value, reason=verdict.reason,
            flags={"avg_spike": spike.avg_spike,
                   "avg_l3_spike": round(spike.avg_l3_spike, 2),
                   "avg_l7_spike": round(spike.avg_l7_spike, 2),
                   "total_local_pct": round(spike.total_local_pct, 2),
                   "has_baseline": spike.has_baseline,
                   "origins": dict(spike.origins),
                   # Carried on the row because the NEXT cycle's fallback
                   # is written from it (`v3/runtime/record.py`) — the
                   # snapshot is stored from what the ledger holds, never
                   # from a draft in flight.
                   "origin_baseline": {"l3": base_l3, "l7": base_l7},
                   "baseline_source": source,
                   "adversary_origins": sorted(adversaries),
                   "hod_z": (None if verdict.z is None
                             else round(verdict.z, 2)),
                   "hod_n": verdict.n, "hod_valid": verdict.valid,
                   "folded_sources": [d.signal_source for d in present]},
            evidence_url=_first_url(present)))
    # A cycle in which no target produced a current distribution makes no
    # derived claim either. Production would emit three OK/0 rows here;
    # v3 does not, for the reason the per-country loop skips a country
    # with no payload — a fetch that did not happen is not a measurement
    # of calm. Score is 0 on both sides, so nothing numeric moves.
    if measured:
        reduced.extend(_derived_rows(measured, cores=cores,
                                     contributing=contributing))
    return reduced


def _derived_rows(measured: Mapping[str, OriginSpike], *,
                  cores: Sequence[str],
                  contributing: Sequence[ObservationDraft]
                  ) -> list[ObservationDraft]:
    """The three entries §7-2 #121 registered as missing. One set per cycle.

    **None of the three is per-scenario, and none is per-country in the way
    `cf_spike_core` is.** The line that settles it is
    `radar/routes/core.py:2039-2041`, where a rationale entry acquires a
    country ONLY if `rat.sensor in FOCUSED_ONLY_SENSOR_NAMES`. That
    frozenset (`radar/scenarios.py:75-79`) holds sensor names —
    `cloudflare_radar`, `ioda_bgp`, ... — and these three entries are
    filed under SIGNAL names, so none of them matches and all three
    become countryless Signals (`radar/scoring.py:79`). Countryless is
    not a gap here: it is production's own attribution, it is what
    `compute_global_threat` aggregates (`radar/scoring.py:1177-1215`), and
    with `GLOBAL_SIGNALS_DECOUPLED` shipped true (`radar/config.py:421`)
    it is what keeps them out of every scenario score
    (`radar/scoring.py:1452-1453`). v3 reaches the same place through
    `Observation.is_global` and S1-SCORE-012.

    `source_country=_adv_top_actor` at `core.py:1075` does NOT contradict
    this: that argument is consumed by `classify_direction` and the two
    context helpers inside `add_rat` (`core.py:956-971`) and never reaches
    `RationaleEntry`, so it decorates the CAC direction and nothing else.
    Carried in the flags for the same reason production computes it.

    The set the three range over is the CYCLE's countries, where
    production's is the focused scenario's `strategic_theaters`. v3 scores
    every scenario from one acquisition, so the union is what exists; the
    widening is §7-2 #118's, and it is the direction NP1 accepts.
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

    shift = vector_shift_verdict(shifted_targets=shifted,
                                 core_shifted=core_shifted,
                                 core_l7_spike=core_l7, core_l3_spike=core_l3)
    strike = adversary_strike_verdict(strikes)
    coordinated = coordinated_verdict(elevated)

    shared = {"targets_measured": sorted(measured),
              "effective_cores": list(ranked),
              "primary_core": primary}
    return [
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
           "ADVERSARY_STRIKE_SIGNAL", "COORDINATED_SIGNAL"]
