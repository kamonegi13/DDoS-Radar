"""`cloudflare_radar`'s fold — both halves, in one place.

One source, four endpoint families, and two joins that `normalize` cannot
perform because it sees one payload by construction (§2-2):

  BGP     hijacks OR route leaks -> production's single `cf_bgp_hijack`
          entry (§7-2 #12/#13, `core.py:1150-1170`).
  spike   this cycle's L3/L7 attack-ORIGIN distributions against the same
          target's baseline-window distributions -> `avg_spike`, and
          `avg_spike` against the target's hour-of-day history ->
          `cf_spike_core` (§7-2 #9's last withheld member, §7-2 #116's
          ranking quantity; `core.py:762-817` and `:1006-1025`).

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
from v3.runtime.baselines import ADVERSARY_ORIGINS
from v3.runtime.reduce_common import _by_country, _first_url, _min_confidence
from v3.runtime.spike import origin_spike, spike_verdict

#: The adapter's own `baseline_refs`, named here because this is what
#: reads them out of the cycle mapping.
ORIGIN_BASELINE_REF = "cf_origin_baseline"
SHARE_BASELINE_REF = "cf_attack_share_baseline"

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
    """Four origin payloads -> production's one `cf_spike_core` entry.

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
    snapshot = baselines.get(ORIGIN_BASELINE_REF)
    history = baselines.get(SHARE_BASELINE_REF) or {}
    reduced = []
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
                             adversaries=adversaries)
        verdict = spike_verdict(history.get(country, ()), spike.avg_spike)
        present = list(rows.values())
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
    return reduced


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
           "stored_baseline", "ORIGIN_BASELINE_REF", "SHARE_BASELINE_REF",
           "BASELINE_FETCHED", "BASELINE_STORED", "BASELINE_ABSENT"]
