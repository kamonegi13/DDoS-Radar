"""`peeringdb_ixp` — S1-SENS-035, D1 §4 K15. Inventory, not alarm.

WP-2.5 shipped this as the pattern exemplar with its scoring rule left
open. Settled here against the clause and its consumer: the legacy entry
is `add_rat("peeringdb_ixp", "physical", "OK", "IXP(s) registered", 0,
None)` (core.py:1193) — status OK and score 0, unconditionally. It is a
register of where exchanges exist, and a country having few exchanges is
a fact about its topology, not an escalation signal.

The exemplar guessed FIRED-on-zero. That guess would have fired
permanently for every country PeeringDB has no record of, which is a
steady stream of false corroboration into the convergence count (NP2:
false corroboration is worse than none). Recording the correction here,
because the difference between an inventory and an alarm is exactly the
kind of thing a port gets wrong quietly.

K15: ten seconds between requests, declared as the shared limiter's
interval rather than slept inside a fetch function.
"""
from __future__ import annotations

from v3.adapters.common import (country_of, list_or_empty, load_json,
                                mapping_or_empty)
from v3.adapters.types import (AdapterId, AuthRequirement, NormalizeContext,
                               ObservationDraft, PHYSICAL, RequestSpec,
                               SourceAdapter, STATUS_OK)
from v3.kernel import Window

PEERINGDB_IXP = AdapterId("peeringdb_ixp")

_IX_URL = "https://www.peeringdb.com/api/ix"

#: D1 §4 K15. PeeringDB's courtesy interval; the legacy client also waits
#: 20s and retries once on a 429.
PEERINGDB_MIN_INTERVAL_SEC = 10.0
PEERINGDB_RETRY_AFTER_SEC = 20.0
#: Per-country result reuse window (S1-SENS-035). Exchanges are not built
#: hourly, so re-asking daily is generous.
COUNTRY_CACHE_TTL_SEC = 86400.0

_CADENCE = Window.from_days(1.0, cadence_sec=14400.0)
#: An IX record stays meaningful well past one poll, so the horizon is
#: wider than the cadence — but finite, because B-03 is what happens when
#: a stale reading is treated as current.
_FRESHNESS_HORIZON_SEC = 24 * 3600.0


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """PeeringDB IX records -> one OK observation per country.

    Malformed input yields no observations rather than raising: one
    upstream serving nonsense must not abort the cycle for the other 33
    adapters, and the fetch is already recorded in `fetch_log`.
    """
    document = load_json(payload)
    records = list_or_empty(mapping_or_empty(document).get("data"))
    if not isinstance(document, dict):
        return ()

    per_country: dict[str, list] = {}
    requested = country_of(payload, context)
    for record in records:
        if not isinstance(record, dict):
            continue
        country = str(record.get("country") or requested or "").strip().upper()
        if not country:
            continue
        if context.countries and country not in context.countries:
            continue
        # `lat` / `lng` come from the geo table, not from PeeringDB —
        # `radar/sensors/peeringdb.py:73-76` reads `COUNTRY_COORDS.get(code,
        # {})` and defaults BOTH to 0. They are the map overlay's only
        # coordinates (`core.py:2902` builds `critical_nodes` from this
        # list), so dropping them empties the overlay without emptying the
        # count that says it should be full.
        point = context.country_coordinates.get(country) or (0, 0)
        per_country.setdefault(country, []).append({
            "id": record.get("id"), "name": record.get("name", ""),
            "city": record.get("city", ""), "country": country,
            "lat": point[0], "lng": point[1],
            "status": record.get("status", "ok"),
            "aka": record.get("name_long", "")})

    if requested and requested not in per_country:
        per_country[requested] = []

    return tuple(
        ObservationDraft(
            # `add_rat("peeringdb_ixp", ...)` (core.py:1193) passes no
            # explicit `signal_source`, so production's effective value is
            # the sensor name (`radar/scoring.py:81`). The port's "ixp" was
            # a semantic label; the column is half of the ledger's dedup
            # identity and WP-2.8's parity join key (RULING R1).
            signal_source="peeringdb_ixp", domain=PHYSICAL, country=country,
            status=STATUS_OK, raw_score=0.0,
            value="IXP(s) registered",
            # Uncapped, as `radar/sensors/peeringdb.py:77` is. `core.py:2902`
            # iterates the whole list to build `critical_nodes`; a cap here
            # would delete the tail of every large country's map overlay.
            flags={"count": len(exchanges), "ixps": exchanges},
            evidence_url=payload.url)
        for country, exchanges in sorted(per_country.items()))


PEERINGDB_IXP_ADAPTER = SourceAdapter(
    adapter_id=PEERINGDB_IXP, category=PHYSICAL,
    requests=(RequestSpec(url=_IX_URL, expect_content="json",
                          params=(("country", "{country}"),),
                          # `radar/sensors/peeringdb.py:54` and again on the
                          # 429 retry at :66. PeeringDB's /api/ix content-
                          # negotiates, and nothing in the fetch kernel adds
                          # a default Accept.
                          headers={"Accept": "application/json"},
                          label="ix"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    auth=AuthRequirement(),          # PeeringDB's read API is open
    rate_limit_group="peeringdb",
    min_interval_sec=PEERINGDB_MIN_INTERVAL_SEC,
    knowledge_refs=("K15",))

__all__ = ["PEERINGDB_IXP", "PEERINGDB_IXP_ADAPTER", "normalize",
           "PEERINGDB_MIN_INTERVAL_SEC", "PEERINGDB_RETRY_AFTER_SEC",
           "COUNTRY_CACHE_TTL_SEC"]
