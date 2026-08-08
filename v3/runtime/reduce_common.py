"""Shared vocabulary for the reductions: the `Reduction` record, the
constants the folds compare against, and the helpers they all use.

Split out of `reduce.py` for the 800-line house limit, with the folds in
`reduce_physical.py` / `reduce_info.py` and the REGISTRY still in
`reduce.py`. Nothing about a fold changed; only where it is written, and
`reduce.py` re-exports every public name so a caller still sees one module.

The registry deliberately did NOT move. A reader asking "which adapters
have a fold, and why" has to be able to hold that answer in one place, and
`tests/test_runtime_reduce.py` reasons about it through `reduce.py` — a
split that scattered the registry would have been the split that cost
something.

Everything here is a pure function of its arguments, for the reason
`reduce.py` gives: a reduction that reads a database mid-fold cannot be
replayed, and replay is what parity rests on.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence

from v3.adapters.info.rss_narrative import feed_source as _feed_source
from v3.adapters.physical.check_host import URL_OK_RATE as \
    CHECK_HOST_URL_OK_RATE
from v3.adapters.types import STATUS_NO_DATA, ObservationDraft

#: Production's per-URL "this URL is up" line (`checkhost.py:225-233`),
#: taken from the adapter that already declares it rather than restated.
CHECKHOST_URL_OK_RATE = CHECK_HOST_URL_OK_RATE
#: `space_weather.py:117` — the two suppressors are OR-ed, and the joined
#: sentence is rebuilt rather than concatenated from the halves.
SPACE_WEATHER_KP_THRESHOLD = 6.0
SPACE_WEATHER_XRAY_CLASS = "M"

#: `ripe_atlas` score ladder (`core.py:1536`).
ATLAS_BLACKOUT = "PROBE_BLACKOUT"
ATLAS_DROP = "PROBE_DROP"

#: The per-feed prefix `rss_narrative` invents (`feed_source("x")` ->
#: `"narrative_x"`). Derived by calling the adapter's own function rather
#: than written out: a second copy of a naming rule is a second thing to
#: keep in step, and this one exists only until the fold retires it.
NARRATIVE_SOURCE_PREFIX = _feed_source("")

#: Where a baseline the reduction needs but did not receive is named, so
#: an unfinished verdict says which value it is waiting for instead of
#: reporting a verdict it could not reach. Same discipline as §7-2 #9's:
#: the marker never occupies a key whose type a consumer relies on.
PENDING_PREFIX = "pending_l1_"


@dataclass(frozen=True, slots=True)
class Reduction:
    """One adapter's fold, with its provenance attached.

    `register_ref` and `production_ref` are carried so the disclosure can
    say WHY a row looks the way it does without a second table to keep in
    step — NP6 applied to the composition root's own arithmetic.
    """

    adapter_id: str
    fold: Callable[[Sequence[ObservationDraft], Mapping[str, Any], float],
                   Sequence[ObservationDraft]]
    register_ref: str
    production_ref: str
    note: str = ""


def _by_country(drafts: Sequence[ObservationDraft]) -> dict:
    grouped: dict = {}
    for draft in drafts:
        grouped.setdefault(draft.country, []).append(draft)
    return grouped


def _first_url(drafts: Sequence[ObservationDraft]) -> Optional[str]:
    for draft in drafts:
        if draft.evidence_url:
            return draft.evidence_url
    return None


def _mmsi_last_seen(snapshot) -> Optional[dict]:
    """`{mmsi: last_ts}` from the entity series' newest row per vessel.

    None when the series was not supplied at all — which is not the same
    as an empty one. An empty history means every hull is a first
    sighting and no gap can be claimed; an absent history means the
    verdict was never attempted, and those must not print the same.
    """
    if snapshot is None:
        return None
    latest = {}
    for mmsi, rows in snapshot.items():
        for row in rows:
            stamp = (row.get("payload") or {}).get("last_ts")
            if stamp is None:
                stamp = row.get("value")
            if stamp is not None:
                latest[str(mmsi)] = float(stamp)
    return latest


def _min_confidence(drafts: Sequence[ObservationDraft]) -> float:
    """The weakest input governs the fold.

    Taking the mean would let one healthy zone raise the confidence of a
    country whose other zone could not be read — the direction that hides
    a partial outage.
    """
    return min((draft.confidence for draft in drafts), default=1.0)


def _measured(drafts: Sequence[ObservationDraft],
              key: str) -> list[ObservationDraft]:
    """Zones whose payload was readable.

    An unmeasured zone contributes NOTHING, not zero. Production's
    equivalent is structural — a failed box never reaches
    `results[theater]` (`isr_hotspot.py:96-100`) — and a zero would sum in
    as a real observation of no aircraft.
    """
    return [d for d in drafts
            if d.status != STATUS_NO_DATA and int(d.flags.get(key, 0) or 0) >= 0]


def _coverage(measured: Sequence, total: Sequence) -> dict:
    """What the fold actually saw, always recorded (NP6).

    Partial coverage that is not disclosed is the same output as full
    coverage, and the difference is exactly a missed detection.
    """
    return {"zones_folded": len(measured),
            "zones_requested": len(total),
            "zones_unmeasured": len(total) - len(measured)}
