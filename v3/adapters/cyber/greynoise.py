"""`greynoise` — S1-SENS-008..011, D1 §4 K11/K15. A suppressor, score 0.

The observation never adds anything: `add_rat("greynoise", "cyber", ...,
0, None)` (core.py:1391). What it can do is mark its own entry
SUPPRESSED when the traffic against a country is dominated by internet
background noise. A10 notes that this suppresses only greynoise's own
entry and no other cyber signal — preserved, because the design sheet
moves suppression APPLICATION to L2 gating rather than changing what the
adapter asserts.

K11, the fact that keeps this sensor healthy: GNQL answers 410 now that
v2 is retired, 401 for a community key, 403/429 for tier and rate limits.
The legacy sensor treats any of those as a **permanent** switch to the
no-GNQL mode and **still records a successful fetch** — because a source
that is structurally unavailable is not a failing source, and treating it
as one manufactures a permanently DEGRADED sensor that nobody looks at
any more. That is the good version of NP3.

An earlier revision of this docstring said that mode was "preserved
exactly". It was not — the claim was another gate verifying the surface
next to the one it names. The kernel classifies a 410 as `http_error`,
`normalize` never runs, no observation is ever written, and the sweep
monitor holds ANOMALY-over-distrust for a source that structurally
cannot answer (measured on the shadow, 2026-08-13: 81 requests in six
hours, all 410, the catalogue's only adapter with zero OK fetches ever).
In v3's model the no-GNQL mode IS `enabled=False` with the reason
carried: `run_due` skips a disabled adapter as "never in scope"
(UNCOUNTED_SKIPS), which is exactly "unavailable, not failing".
Re-enable by porting the request to a reachable GreyNoise endpoint and
deleting `enabled=False` — everything below it still works.

Two more rules that look like details and are not:
  * the query must NOT filter `classification:malicious` — that excludes
    benign, and the ratio it computes is benign/total, so filtering makes
    it permanently 0
  * an unobtainable ratio yields UNKNOWN with suppression OFF. "We could
    not measure" must never become "this is noise" (NP1). Unobtainable
    means the body did not parse into the shape the ratio is read from —
    NOT "the shape was there and held nothing". Production computes
    `data.get("stats", {}).get("classifications", [])` and divides, so an
    empty distribution is `0.0` -> TARGETED, a measured all-clear
    (`radar/sensors/greynoise.py:192-197`). The port answered UNKNOWN
    there, which reports "we could not look" about a request that
    answered.
"""
from __future__ import annotations

from typing import Mapping

from v3.adapters.common import (as_int, country_of, list_or_empty, load_json,
                                mapping_or_empty)
from v3.adapters.types import (AdapterId, AUTH_API_KEY, AuthRequirement,
                               CYBER, NormalizeContext, ObservationDraft,
                               RequestSpec, SourceAdapter, STATUS_OK,
                               STATUS_SUPPRESSED)
from v3.kernel import Window

GREYNOISE = AdapterId("greynoise")

_GNQL_STATS_URL = "https://api.greynoise.io/v2/experimental/gnql/stats"

NOISE_DOMINANT_RATIO = 0.70
MIXED_RATIO = 0.40
GNQL_COUNT = 500
#: K15's family: half a second between countries.
GREYNOISE_MIN_INTERVAL_SEC = 0.5
#: The on-demand Community lookup path (S1-SENS-011), kept as declared
#: constants — it is not part of the polling cycle.
COMMUNITY_DAILY_LIMIT = 50
COMMUNITY_CACHE_TTL_SEC = 86400.0

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 2 * 3600.0

DISABLED_REASON = (
    "GNQL v2 answers HTTP 410 Gone — the endpoint is retired, with or "
    "without a key (K11; shadow 2026-08-13: 81/81 requests 410, zero OK "
    "fetches ever). K11's no-GNQL mode is enabled=False here: the kernel "
    "has no way to record a structurally dead endpoint as anything but a "
    "failing fetch. Re-enable when the request is ported to a reachable "
    "GreyNoise endpoint")


def classify(noise_ratio) -> str:
    if noise_ratio is None:
        return "UNKNOWN"
    if noise_ratio > NOISE_DOMINANT_RATIO:
        return "NOISE_DOMINANT"
    return "MIXED" if noise_ratio > MIXED_RATIO else "TARGETED"


def counts_of(classifications) -> tuple[int, int]:
    """`(total, benign)` — the two sums production keeps separately.

    `radar/sensors/greynoise.py:193-196` computes `malicious = total -
    noise` from the SUMMED benign count. The port reconstructed benign as
    `round(ratio * total)` from the ratio it had already rounded to three
    decimals, so `malicious_ips` drifted from the true figure by up to
    0.05% of the total — on a million-IP country, hundreds of addresses
    that were counted as malicious because of a rounding step production
    does not perform.
    """
    total = 0
    benign = 0
    for entry in list_or_empty(classifications):
        record = mapping_or_empty(entry)
        count = as_int(record.get("count"), 0) or 0
        total += count
        if str(record.get("classification") or "").lower() == "benign":
            benign += count
    return total, benign


def noise_ratio_of(classifications) -> float:
    """benign / all classified. Zero total yields 0.0, not None."""
    total, benign = counts_of(classifications)
    return round(benign / total, 3) if total > 0 else 0.0


def classification_rows(document):
    """The classification distribution, or None when it is unreadable.

    Production reaches this list through two `.get` calls with defaults
    and divides inside a `try` (`radar/sensors/greynoise.py:190-205`).
    Absent keys therefore mean "an empty distribution" — a measured zero;
    anything that would have raised (a body that is not an object, a
    `stats` that is not an object, a `classifications` that is not a
    list) lands in the `except` and returns `{}`, which becomes
    `noise_ratio=None` and UNKNOWN (`:229-240`). Both halves are kept
    because they are different facts.
    """
    if not isinstance(document, Mapping):
        return None
    stats = document.get("stats", {})
    if not isinstance(stats, Mapping):
        return None
    rows = stats.get("classifications", [])
    return rows if isinstance(rows, list) else None


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    country = country_of(payload, context)
    if not country:
        return ()
    classifications = classification_rows(load_json(payload))
    if classifications is None:
        # Unmeasurable, so UNKNOWN with suppression off. The alternative
        # (assume noise) discards real signal on the strength of a failed
        # request. `total_ips` / `malicious_ips` are None rather than
        # absent, matching `stats.get(...)` on an empty stats dict
        # (`radar/sensors/greynoise.py:246-247`).
        return (ObservationDraft(
            signal_source="greynoise", domain=CYBER, country=country,
            status=STATUS_OK, raw_score=0.0, value="UNKNOWN",
            flags={"noise_class": "UNKNOWN", "noise_ratio": None,
                   "suppress_confidence": False, "total_ips": None,
                   "malicious_ips": None},
            evidence_url=payload.url),)

    total, benign = counts_of(classifications)
    ratio = round(benign / total, 3) if total > 0 else 0.0
    noise_class = classify(ratio)
    suppress = noise_class == "NOISE_DOMINANT"
    return (ObservationDraft(
        signal_source="greynoise", domain=CYBER, country=country,
        status=STATUS_SUPPRESSED if suppress else STATUS_OK,
        raw_score=0.0,                      # suppression only, never a bonus
        suppressed=suppress,
        suppress_reason=(
            f"GreyNoise: {noise_class} — traffic classified as internet "
            f"background noise" if suppress else None),
        value=f"{noise_class} noise={ratio:.0%}",
        flags={"noise_class": noise_class, "noise_ratio": ratio,
               "suppress_confidence": suppress, "total_ips": total,
               "malicious_ips": max(total - benign, 0)},
        evidence_url=payload.url),)


GREYNOISE_ADAPTER = SourceAdapter(
    adapter_id=GREYNOISE, category=CYBER,
    requests=(RequestSpec(
        url=_GNQL_STATS_URL, expect_content="json",
        # No `classification:` filter — see the module docstring.
        params=(("query", "metadata.destination_country:{country}"),
                ("count", str(GNQL_COUNT))),
        headers={"Accept": "application/json",
                 "User-Agent": "OSINT-Radar/9.0"},
        label="gnql:{country}"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    # `radar/sensors/greynoise.py:49` — the header is literally `key`, not
    # `Auth-Key` and not `Authorization`. The WP-2.6 sweep found the kernel
    # sending `Auth-Key`, which GreyNoise treats as unauthenticated.
    auth=AuthRequirement(kind=AUTH_API_KEY, key_id="GREYNOISE_API_KEY",
                         name="key", value_template="{secret}",
                         note="GNQL needs an enterprise key; without one "
                              "the adapter is inert, not failing (K11)"),
    rate_limit_group="greynoise",
    min_interval_sec=GREYNOISE_MIN_INTERVAL_SEC,
    knowledge_refs=("K11", "K15"),
    enabled=False, disabled_reason=DISABLED_REASON)

__all__ = ["GREYNOISE", "GREYNOISE_ADAPTER", "normalize", "classify",
           "DISABLED_REASON",
           "noise_ratio_of", "counts_of", "classification_rows",
           "NOISE_DOMINANT_RATIO", "MIXED_RATIO",
           "GREYNOISE_MIN_INTERVAL_SEC", "COMMUNITY_DAILY_LIMIT",
           "COMMUNITY_CACHE_TTL_SEC", "GNQL_COUNT"]
