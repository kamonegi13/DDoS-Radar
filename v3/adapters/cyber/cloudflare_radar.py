"""`cloudflare_radar` — S1-SENS-001..003. Four endpoints, one output face.

DP8 is what this port removes. The legacy sensor wrote its L3/L7 payloads
into a **module-level dict shared with the scoring layer**, keyed by
`(url, params)`, alongside its ordinary cache — a second path from sensor
to scoring that no contract described and that the scoring layer swept
for TTL and capped at 1000 entries. Here the output face is
`ObservationDraft` and nothing else; §2-2 gives an adapter nowhere else
to write.

The asymmetry in BGP events is real and preserved (A9): **hijacks are
filtered at confidence >= 50, leaks are not filtered at all.** A leak is
a routing fact reported by the same infrastructure that detects it; a
hijack is an accusation of intent, and a low-confidence accusation is
worth less than none.

The firing rule is asymmetric for the same reason and preserved with the
same care: one ongoing hijack fires, but leaks need three
(`LEAK_FIRE_THRESHOLD`). Legacy reaches that verdict once per country per
cycle across both endpoints; here the endpoints arrive separately, so the
two halves travel under DIFFERENT `signal_source` keys and the
disjunction is reassembled by a WP-4.1 reduction step — see `_bgp_events`
for why L1 cannot be asked to do it.

Attack-share spikes are NOT decided here. That verdict compares against a
DDoS time series baseline in the scoring layer (S1-SCORE-025/029/030 are
excluded from L2 as derived-observation producers), so the L3/L7 rankings
are reported as OBSERVED with the share in the flags.
"""
from __future__ import annotations

from v3.adapters.common import (as_float, iso2, list_or_empty, load_json,
                                mapping_or_empty)
from v3.adapters.types import (AdapterId, AUTH_API_KEY, AuthRequirement,
                               CYBER, NormalizeContext, ObservationDraft,
                               RequestSpec, SourceAdapter, STATUS_FIRED,
                               STATUS_OBSERVED, STATUS_OK)
from v3.kernel import Window

CLOUDFLARE_RADAR = AdapterId("cloudflare_radar")

_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"
_L3_URL = f"{_RADAR_BASE}/attacks/layer3/top/locations/target"
_L7_URL = f"{_RADAR_BASE}/attacks/layer7/top/locations/target"
_HIJACKS_URL = f"{_RADAR_BASE}/bgp/hijacks/events"
_LEAKS_URL = f"{_RADAR_BASE}/bgp/leaks/events"

#: A9: hijack accusations below this are dropped; leaks are not filtered.
BGP_EVENT_MIN_CONFIDENCE = 50
#: core.py:1156 — `len(_hijack_ongoing) > 0 or len(_core_leaks) >= 3`.
#: A leak reaching the count threshold is the leak half of that
#: disjunction. One or two route leaks a day is ordinary internet; the
#: threshold is what separates the ordinary from the event.
LEAK_FIRE_THRESHOLD = 3
#: BGP windows are fixed at one day even when attack data uses a longer
#: range — a hijack is an event, not a trend.
BGP_DATE_RANGE = "1d"
#: `CURRENT_DATE_RANGE`'s shipped default (`radar/config.py:147`).
DEFAULT_DATE_RANGE = "1d"

#: The ledger key each BGP payload lands under. `cf_bgp_hijack` is
#: production's rationale entry (`radar/routes/core.py:1165`); the leak
#: half needs a key of its own or the two collide on
#: `(tick_id, sensor, signal_source, country)` — see `_bgp_events`.
BGP_HIJACK_SIGNAL = "cf_bgp_hijack"
BGP_LEAK_SIGNAL = "cf_bgp_leak"
#: `radar/scoring.py:604` — "CF free tier allows ~1200 req/5min (~4/s); we
#: conservatively limit to ~3/s". Four endpoints fire per cycle, so the
#: pacing is the whole reason the rate-limit group exists; a group with no
#: interval paces nothing (`v3/fetch/runner.py:133-144` only spaces when
#: `min_interval_sec > 0`).
CF_MIN_INTERVAL_SEC = 0.35

_CADENCE = Window.from_days(1.0, cadence_sec=900.0)
_FRESHNESS_HORIZON_SEC = 2 * 3600.0


def _top_locations(payload) -> list[dict]:
    document = load_json(payload)
    result = mapping_or_empty(mapping_or_empty(document).get("result"))
    return [mapping_or_empty(entry)
            for entry in list_or_empty(result.get("top_0"))]


#: Where production looks for the country in a `top_0` row, in order
#: (`parse_origins`, `radar/scoring.py:660-661`). The port read
#: `targetCountryAlpha2` and nothing else — a key that appears NOWHERE in
#: `radar/`, so if Cloudflare answers with `location` (which the first
#: three entries exist for) every row resolves to no country and the
#: adapter is silent while reporting success. That is the failure NP1
#: forbids, so the whole ladder is transcribed, fallback included.
LOCATION_KEYS: tuple[str, ...] = ("origin1", "location", "clientCountryAlpha2")


def location_of(entry) -> str:
    """The country a `top_0` row is about. `parse_origins`'s rule, exactly.

    The trailing scan is production's: any string value that is exactly
    two upper-case characters. It is what makes `targetCountryAlpha2`
    resolve at all today, and dropping it in favour of one hard-coded key
    is how a schema rename turns into silence rather than an error.
    """
    record = mapping_or_empty(entry)
    for key in LOCATION_KEYS:
        code = record.get(key)
        if code:
            return iso2(code)
    for value in record.values():
        if isinstance(value, str) and len(value) == 2 and value.isupper():
            return iso2(value)
    return ""


def share_of(entry) -> float:
    """`float(o.get("value") or o.get("count") or 1.0)` (`scoring.py:663`).

    The `or` chain is load-bearing and preserved: a row whose `value` is
    zero falls through to `count`, and a row with neither weighs 1.0. The
    port read `value` alone with a 0.0 default, which turns "Cloudflare
    reported this location with no share figure" into "this location was
    attacked 0%" — an all-clear production never asserted.
    """
    record = mapping_or_empty(entry)
    for key in ("value", "count"):
        number = as_float(record.get(key), None)
        if number:                       # production's falsy fall-through
            return number
    return 1.0


def _events(payload, key: str) -> list[dict]:
    document = load_json(payload)
    result = mapping_or_empty(mapping_or_empty(document).get("result"))
    return [mapping_or_empty(entry) for entry in list_or_empty(result.get(key))]


def normalize_hijacks(payload) -> list[dict]:
    """`asn_hijacks` -> normalized records, confidence-filtered (A9)."""
    records = []
    for event in _events(payload, "asn_hijacks"):
        confidence = as_float(event.get("confidence"), 0.0) or 0.0
        if confidence < BGP_EVENT_MIN_CONFIDENCE:
            continue
        records.append({
            "type": "hijack", "confidence": confidence,
            # Defaults transcribed from `radar/sensors/cloudflare.py:92-98`.
            # `prefix` is `""` and `is_ongoing` is `False` there; a `None`
            # in their place travels into the flags and out to the analyst
            # as a missing field rather than an empty one.
            "prefix": event.get("prefix", ""),
            "victim_asn": event.get("victim_asn"),
            "hijacker_asn": event.get("hijacker_asn"),
            "victim_country": iso2(event.get("victim_country")),
            "hijacker_country": iso2(event.get("hijacker_country")),
            "is_ongoing": bool(event.get("is_ongoing", False)),
            "duration": event.get("duration")})
    return records


def normalize_leaks(payload) -> list[dict]:
    """`asn_leaks` -> normalized records. No confidence filter (A9).

    Counts default to 0, not None (`radar/sensors/cloudflare.py:118,120`).
    """
    return [{"type": "leak", "leak_asn": event.get("leak_asn"),
             "leak_country": iso2(event.get("leak_country")),
             "leaked_prefix_count": event.get("leaked_prefix_count", 0),
             "origin_asn": event.get("origin_asn"),
             "peer_count": event.get("peer_count", 0)}
            for event in _events(payload, "asn_leaks")]


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """Dispatch on the request label; one observation per country in scope."""
    if payload.label in ("l3", "l7"):
        return _attack_shares(payload, context)
    if payload.label == "hijacks":
        return _bgp_events(payload, context, normalize_hijacks(payload),
                           "victim_country", BGP_HIJACK_SIGNAL)
    if payload.label == "leaks":
        return _bgp_events(payload, context, normalize_leaks(payload),
                           "leak_country", BGP_LEAK_SIGNAL)
    return ()


def _attack_shares(payload, context) -> tuple[ObservationDraft, ...]:
    shares = {}
    for entry in _top_locations(payload):
        country = location_of(entry)
        if country:
            shares[country] = share_of(entry)
    drafts = []
    for country in context.countries:
        if country not in shares:
            continue
        drafts.append(ObservationDraft(
            signal_source=f"cf_{payload.label}", domain=CYBER,
            country=country,
            # The spike verdict needs the attack time series baseline the
            # scoring layer holds; this is the measurement, not the claim.
            status=STATUS_OBSERVED, raw_score=0.0,
            value=f"{payload.label}_share={shares[country]:.1f}%",
            flags={"share_pct": shares[country], "layer": payload.label},
            evidence_url=payload.url))
    return tuple(drafts)


def _bgp_events(payload, context, records, country_key, signal_source
                ) -> tuple[ObservationDraft, ...]:
    """One observation per country in scope. Score 1 (core.py:1165-1176).

    Each half of legacy's disjunction keeps its own condition: an ongoing
    hijack fires with no count threshold, leaks fire at
    `LEAK_FIRE_THRESHOLD`. Firing a leak payload on `bool(matching)` would
    have dropped the threshold from three events to one — a real, and
    unregistered, loosening.

    **The two payloads MUST NOT share a `signal_source`.** The port gave
    both `cf_bgp_hijack`, production's entry name, on the theory that
    S1-SCORE-008's MAX fold would reassemble `ongoing > 0 or leaks >= 3`.
    It does not reach that fold: the L1 ledger's key is
    `(tick_id, sensor, signal_source, country)` (`v3/ledger/schema.py:157`)
    and `append_signal` calls `_require_same_tick` on a collision, which
    **raises `DomainError` when the two rows differ** and **silently drops
    the second when they match** (S5-VERIF-019). One tick, one country,
    one adapter, two payloads — so the leaks row was either lost or fatal,
    every cycle, depending on whether the hijack row happened to agree
    with it. Hence `cf_bgp_hijack` for hijacks (production's name,
    `core.py:1165`) and `cf_bgp_leak` for leaks.

    **Deferred to WP-4.1** (the composition root, `v3/runtime/`, §1-2):
    production emits ONE rationale record per country per cycle, whose
    verdict is the disjunction, whose value reads
    `hijack=N(ongoing=M) leak=K` and whose `fired_reason` reads
    `BGP manipulation detected: M ongoing hijack(s), K route leak(s)`
    (`core.py:1170-1176`). All three need BOTH endpoints' payloads
    joined, and `normalize` sees one payload at a time by construction
    (§2-2). The reduction is a WP-4.1 step over the two `signal_source`
    keys, not something L1 performs.
    """
    drafts = []
    for country in context.countries:
        matching = [record for record in records
                    if record.get(country_key) == country]
        ongoing = [record for record in matching if record.get("is_ongoing")]
        fired = (bool(ongoing) if payload.label == "hijacks"
                 else len(matching) >= LEAK_FIRE_THRESHOLD)
        drafts.append(ObservationDraft(
            signal_source=signal_source, domain=CYBER, country=country,
            status=STATUS_FIRED if fired else STATUS_OK,
            raw_score=1.0 if fired else 0.0,
            value=f"{payload.label}={len(matching)}",
            # Uncapped. `core.py:467-468` and `:2712-2716` carry
            # `cf_bgp_hijacks` / `cf_bgp_leaks` whole; the `[:10]` this
            # previously held had no counterpart in production.
            flags={"events": matching, "count": len(matching),
                   "ongoing": len(ongoing),
                   "fire_threshold": (1 if payload.label == "hijacks"
                                      else LEAK_FIRE_THRESHOLD)},
            evidence_url=payload.url))
    return tuple(drafts)


#: `radar/config.py:322` — `CF_HEADERS = {"Authorization": f"Bearer {token}"}`.
#: The WP-2.6 sweep found the fetch kernel sending `Auth-Key` instead, which
#: Cloudflare answers with 403; a 403 this layer reads as "no data" is a
#: quiet day that never happened.
CF_AUTH = AuthRequirement(kind=AUTH_API_KEY, key_id="CF_API_TOKEN",
                          name="Authorization",
                          value_template="Bearer {secret}",
                          note="Radar requires a token even for public "
                               "aggregates")
_CF_AUTH = CF_AUTH

CLOUDFLARE_RADAR_ADAPTER = SourceAdapter(
    adapter_id=CLOUDFLARE_RADAR, category=CYBER,
    requests=(RequestSpec(url=_L3_URL, expect_content="json",
                          params=(("dateRange", DEFAULT_DATE_RANGE),
                                  ("format", "json")), label="l3"),
              RequestSpec(url=_L7_URL, expect_content="json",
                          params=(("dateRange", DEFAULT_DATE_RANGE),
                                  ("format", "json")), label="l7"),
              RequestSpec(url=_HIJACKS_URL, expect_content="json",
                          params=(("dateRange", BGP_DATE_RANGE),
                                  ("format", "json")), label="hijacks"),
              RequestSpec(url=_LEAKS_URL, expect_content="json",
                          params=(("dateRange", BGP_DATE_RANGE),
                                  ("format", "json")), label="leaks")),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC, auth=_CF_AUTH,
    rate_limit_group="cloudflare", min_interval_sec=CF_MIN_INTERVAL_SEC,
    baseline_refs=("cf_attack_share_baseline",))

__all__ = ["CLOUDFLARE_RADAR", "CLOUDFLARE_RADAR_ADAPTER", "normalize",
           "normalize_hijacks", "normalize_leaks", "location_of", "share_of",
           "BGP_EVENT_MIN_CONFIDENCE", "LEAK_FIRE_THRESHOLD",
           "BGP_DATE_RANGE", "DEFAULT_DATE_RANGE", "CF_MIN_INTERVAL_SEC",
           "CF_AUTH", "LOCATION_KEYS", "BGP_HIJACK_SIGNAL", "BGP_LEAK_SIGNAL"]
