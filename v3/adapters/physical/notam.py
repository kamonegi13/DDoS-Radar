"""`notam` — S1-SENS-028, D1 §4 K14. Disabled, and the reason is external.

K14: **there is no free international NOTAM API.** The FAA's search
covers United States airspace only, and ICAO's data service allows 100
calls on its free tier, which is not a monitoring capability. This is not
a defect to fix later; it is the state of the world, and the design sheet
§7-1 puts NOTAM revival explicitly out of scope.

What is kept is the FAA request shape, because it is the expensive part
to rediscover: degrees split into degrees/minutes/seconds across separate
fields, a 100-mile radius, `notamType="N"`, `pageSize=50`. The firing
rule is kept in the same spirit — as declared constants that document
what the sensor did, not as code pretending it still runs.

`NOTAM_MILITARY_KEYWORDS` is kept for a stronger reason than shape. It is
the classifier itself: fourteen phrases derived from real NOTAM free
text, and without them a revived adapter counts notices but cannot tell a
military one from a runway closure — which is the whole signal, since
`military >= 3` is one of the three surge conditions and is what
separates score 2 from score 1 (`core.py:1636`).
"""
from __future__ import annotations

from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter)
from v3.kernel import Window

NOTAM = AdapterId("notam")

_FAA_SEARCH_URL = "https://notams.aim.faa.gov/notamSearch/search"

#: The firing rule as it stood (S1-SENS-028), preserved for whoever
#: revives this if a usable source ever appears. `notam.py:158-160`:
#: `total >= 20 or military >= 3 or (surge_pct > 0.5 and total > 5)` —
#: the last two comparisons are STRICT, and the scoring block then reads
#: 2 when a surge also carries `military >= 3`, else 1 (`core.py:1636`).
SURGE_THRESHOLD = 20
MILITARY_COUNT_THRESHOLD = 3
SURGE_PCT_THRESHOLD = 0.5
SURGE_PCT_MIN_TOTAL = 5

#: The classifier ledger, `radar/config.py:498-503`, all fourteen entries
#: in declaration order. This is the expensive part of the sensor and the
#: part the port lost.
#:
#: It is a derived asset, not a lookup that can be rebuilt from a
#: specification: the phrases are the ones that actually appear in NOTAM
#: free text ("DANGER AREA", "LIVE FIRING", "AIR REFUELING" — not
#: "REFUELLING"), and each one is a decision somebody made against real
#: notices. A disabled adapter that has lost its table cannot be
#: re-enabled without re-deriving it, which means re-doing that work.
#: Legacy upper-cases the whole list and matches against `text.upper()`
#: (`notam.py:139-141`), so the entries are stored upper-case here too.
NOTAM_MILITARY_KEYWORDS: tuple[str, ...] = (
    "MILITARY", "MIL AIRSPACE", "PROHIBITED AREA", "RESTRICTED AREA",
    "DANGER AREA", "LIVE FIRING", "MISSILE", "EXERCISE", "TFR", "NO FLY",
    "HAZARD AREA", "COMBAT", "AIR DEFENSE", "AIR REFUELING",
)
#: The TFR test is separate from the military keyword scan and is its own
#: pair of phrases (`notam.py:142`). "TFR" is in BOTH ledgers — the
#: keyword list counts it towards `military`, this pair counts it towards
#: `tfr` — and the port kept neither.
NOTAM_TFR_KEYWORDS: tuple[str, ...] = ("TFR", "FLIGHT RESTRICTION")
#: `notam.py:148`. NOTAM free text is long; the stored excerpt is not.
NOTAM_TEXT_EXCERPT_CHARS = 200
#: `notam.py:169`. Five notices travel with the count.
RECENT_NOTAM_CAP = 5
#: The FAA payload's fixed fields (the part worth keeping).
FAA_PAYLOAD_SHAPE: dict = {
    "searchType": 0, "designatorsForLocation": "", "radius": 100,
    "fcmSequenceNumber": 0, "notamType": "N", "offset": 0, "pageSize": 50,
    "sortColumn": "notamNumber", "sortDirection": "DESC",
}
#: Countries without a published bounding box used a ±3° box instead.
FALLBACK_BOX_HALF_DEG = 3.0

DISABLED_REASON = (
    "no free international NOTAM API exists: the FAA search is US-only and "
    "ICAO's free tier is 100 calls (D1 §4 K14). gps_jamming, isr_hotspot "
    "and mil_support_air cover the physical domain instead (S1-SENS-028)")

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 3600.0


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """No observations: this source has no reachable data.

    Present so the adapter satisfies the same contract as the other 21 —
    a disabled source that cannot even be called is harder to re-enable
    than one that is simply never scheduled.
    """
    return ()


NOTAM_ADAPTER = SourceAdapter(
    adapter_id=NOTAM, category=PHYSICAL,
    requests=(RequestSpec(url=_FAA_SEARCH_URL, method="POST",
                          expect_content="json",
                          headers={"Content-Type": "application/json",
                                   "Accept": "application/json"},
                          label="faa_notam_search"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="faa", knowledge_refs=("K14",),
    enabled=False, disabled_reason=DISABLED_REASON)

__all__ = ["NOTAM", "NOTAM_ADAPTER", "normalize", "DISABLED_REASON",
           "SURGE_THRESHOLD", "MILITARY_COUNT_THRESHOLD",
           "SURGE_PCT_THRESHOLD", "SURGE_PCT_MIN_TOTAL", "FAA_PAYLOAD_SHAPE",
           "FALLBACK_BOX_HALF_DEG", "NOTAM_MILITARY_KEYWORDS",
           "NOTAM_TFR_KEYWORDS", "NOTAM_TEXT_EXCERPT_CHARS",
           "RECENT_NOTAM_CAP"]
