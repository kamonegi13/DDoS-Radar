"""`peeringdb_ixp` — the WP-2.6 pattern exemplar. Executable documentation.

**Status: this is a PATTERN EXEMPLAR, not the finished port.** It exists so
the declaration model in §2 is demonstrated by something that runs rather
than only described. WP-2.6 finalises the scoring rule against
S1-SENS-035; what is settled here is the SHAPE every adapter takes.

Chosen because it is the simplest S-class adapter in the §3 inventory and
still exercises the parts that matter:

  * no authentication, so the auth seam is visible by its absence
  * a courtesy delay (PeeringDB 10s, D1 §4 K15) expressed as the shared
    rate-limit mechanism rather than a `sleep` in a fetch function
  * plain field extraction, so `normalize` is legible as what it is: a
    pure function from bytes to values

Read what this module CANNOT do. There is no HTTP import, no client
handle, no ledger handle, no clock, and no way to reach any of them: the
kernel discipline gate fails the build on an HTTP or socket import
anywhere under `v3/adapters/`, and `normalize` receives bytes that were
fetched before it was called. That is §2-2's four barriers in practice —
and it is the answer to A-10, where the shared helpers existed, were
optional, and had zero callers.
"""
from __future__ import annotations

import json

from v3.adapters.types import (AdapterId, AuthRequirement, NormalizeContext,
                               ObservationDraft, PHYSICAL, RequestSpec,
                               SourceAdapter)
from v3.kernel import Window

PEERINGDB_IXP = AdapterId("peeringdb_ixp")

#: D1 §4 K15. Ten seconds is PeeringDB's courtesy interval, and the legacy
#: client also retries once after 20s on a 429. Declared, not slept.
PEERINGDB_MIN_INTERVAL_SEC = 10.0

#: PeeringDB publishes slowly; an hourly poll is generous for it.
_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)

#: An IX record stays meaningful well past one poll, so the horizon is
#: deliberately wider than the cadence — but finite, because B-03 is what
#: happens when a stale reading is treated as current.
_FRESHNESS_HORIZON_SEC = 6 * 3600.0


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """PeeringDB IX records -> one observation per country.

    A pure function of `(bytes, context)`. It cannot fetch anything, and
    it takes its instant from `context.now` rather than the clock, which
    is what lets a recorded fixture reproduce byte-for-byte in a test and
    in a parity replay.

    Malformed input yields no observations rather than raising: one
    upstream serving nonsense must not abort the cycle for the other 33
    adapters. The fetch itself is already recorded in `fetch_log`, so the
    event is visible without being fatal.
    """
    try:
        document = json.loads(payload.body.decode("utf-8", "replace"))
    except (json.JSONDecodeError, AttributeError):
        return ()
    records = document.get("data") if isinstance(document, dict) else None
    if not isinstance(records, list):
        return ()

    per_country: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        country = str(record.get("country") or "").strip().upper()
        if not country:
            continue
        if context.countries and country not in context.countries:
            continue
        per_country[country] = per_country.get(country, 0) + 1

    return tuple(
        ObservationDraft(
            signal_source="ixp",
            domain=PHYSICAL,
            country=country,
            status="FIRED" if count == 0 else "CLEAR",
            # WP-2.6 sets the real rule against S1-SENS-035. Zero
            # exchanges for a country we asked about is the only signal
            # this exemplar claims to carry.
            raw_score=0.0,
            value=f"ix_count={count}",
            flags={"ix_count": count},
            evidence_url=payload.url)
        for country, count in sorted(per_country.items()))


PEERINGDB_IXP_ADAPTER = SourceAdapter(
    adapter_id=PEERINGDB_IXP,
    category=PHYSICAL,
    requests=(RequestSpec(url="https://www.peeringdb.com/api/ix",
                          expect_content="json", label="ix"),),
    cadence=_CADENCE,
    normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    auth=AuthRequirement(),          # none — PeeringDB's read API is open
    rate_limit_group="peeringdb",
    min_interval_sec=PEERINGDB_MIN_INTERVAL_SEC,
    knowledge_refs=("K15",),
)


__all__ = ["PEERINGDB_IXP", "PEERINGDB_IXP_ADAPTER", "normalize",
           "PEERINGDB_MIN_INTERVAL_SEC"]
