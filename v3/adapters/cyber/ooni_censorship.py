"""`ooni_censorship` — S1-SENS-012/013, D1 §4 K04/K15. Censorship measured.

The verdict is three ORed conditions, and the third is the interesting
one: a surge relative to the country's own previous anomaly count. It
only applies above ten prior anomalies, because 1 -> 2 is not a surge, it
is a Tuesday.

K04 is the degraded mode and the design sheet keeps it as the good
example of NP3: three consecutive all-fail cycles slow the cadence to two
hours, narrow the target list to a single probe country, and demote the
per-country logs to DEBUG; one success restores everything immediately.
In v3 that behaviour belongs to the kernel's adaptive cadence rather than
to this adapter — an adapter cannot rewrite its own poll interval — so
what is preserved here is the fact and its thresholds.

`prev` (the previous anomaly count) lived in process memory, so a restart
disabled surge detection silently (DP3). It is declared as a baseline
dependency; the two rate-based conditions need no history and are
computed here.
"""
from __future__ import annotations

from typing import Mapping

from v3.adapters.common import (as_int, country_of, list_or_empty, load_json,
                                mapping_or_empty)
from v3.adapters.types import (AdapterId, CYBER, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_OK)
from v3.kernel import Window

OONI_CENSORSHIP = AdapterId("ooni_censorship")

_AGGREGATION_URL = "https://api.ooni.io/api/v1/aggregation"

CONFIRMED_RATE_CENSORING = 0.05
ANOMALY_RATE_CENSORING = 0.20
CONFIRMED_RATE_HEAVY = 0.15
ANOMALY_RATE_HEAVY = 0.40
SURGE_FACTOR = 1.5
SURGE_MIN_PREVIOUS = 10
#: K04 — three consecutive all-fail cycles, then 7200s and one probe.
DEGRADED_AFTER_FAILURES = 3
DEGRADED_CADENCE_SEC = 7200.0
NORMAL_CADENCE_SEC = 1800.0
LOOKBACK_DAYS = 7
#: K15's family.
OONI_MIN_INTERVAL_SEC = 0.5
#: The `add_rat` sensor name (`radar/routes/core.py:1706`), which is the
#: effective `signal_source` because no explicit kwarg is passed
#: (`rat.signal_source or rat.sensor`, `radar/scoring.py:81`). The port
#: shortened it to `"ooni"`, which is not a name production ever wrote —
#: it breaks the ledger's dedup identity and WP-2.8's parity join key.
SIGNAL_SOURCE = "ooni_censorship"
#: `core.py:1703-1705`, on the FIRED branch only.
FIRED_REASON_TEMPLATE = ("OONI: Internet censorship detected "
                         "(anomaly={anomaly:.1%}, confirmed={confirmed:.1%})")

_CADENCE = Window.from_days(1.0, cadence_sec=NORMAL_CADENCE_SEC)
_FRESHNESS_HORIZON_SEC = 4 * 3600.0


def verdict(anomaly_rate: float, confirmed_rate: float,
            surging: bool = False) -> tuple[bool, bool, str]:
    """`(is_censoring, is_heavy, status)` — S1-SENS-012's three conditions."""
    is_censoring = (confirmed_rate > CONFIRMED_RATE_CENSORING
                    or anomaly_rate > ANOMALY_RATE_CENSORING or surging)
    is_heavy = (confirmed_rate > CONFIRMED_RATE_HEAVY
                or anomaly_rate > ANOMALY_RATE_HEAVY)
    status = ("HEAVY_CENSORSHIP" if is_heavy
              else "CENSORSHIP_DETECTED" if is_censoring else "NORMAL")
    return is_censoring, is_heavy, status


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """Seven days of web_connectivity aggregation for one country.

    Score 2 for heavy censorship, 1 for censorship, matching
    core.py:1706-1710.

    **An empty `result` array is an answer, not a miss.** Production reads
    `data.get("result", [])` and then writes `censorship_data[code]`
    unconditionally (`radar/sensors/ooni.py:128,164-175`), so a country
    with no OONI measurements in seven days lands as
    `anomaly=0.0% confirmed=0.0% [NORMAL]` — measured, quiet. The port
    returned nothing there, which is the one shape NP1 refuses: "nothing
    to report" and "never asked" became the same absence in the ledger.
    A body that is not a JSON object at all still yields nothing, because
    that is the case production's `except` path drops (`ooni.py:121-126`).
    """
    country = country_of(payload, context)
    if not country:
        return ()
    document = load_json(payload)
    if not isinstance(document, Mapping):
        return ()
    rows = list_or_empty(document.get("result"))

    measurements = anomalies = confirmed = failures = 0
    daily: list[float] = []
    for row in rows:
        record = mapping_or_empty(row)
        count = as_int(record.get("measurement_count"), 0) or 0
        anomaly = as_int(record.get("anomaly_count"), 0) or 0
        measurements += count
        anomalies += anomaly
        confirmed += as_int(record.get("confirmed_count"), 0) or 0
        failures += as_int(record.get("failure_count"), 0) or 0
        if count > 0:
            daily.append(round(anomaly / count, 3))

    anomaly_rate = anomalies / max(measurements, 1) if measurements else 0.0
    confirmed_rate = confirmed / max(measurements, 1) if measurements else 0.0
    # The surge condition needs the previous cycle's anomaly count, which
    # is L1's to hold (DP3). Omitted rather than assumed False silently:
    # the flag below says which of the three conditions was evaluated.
    is_censoring, is_heavy, status = verdict(anomaly_rate, confirmed_rate)

    return (ObservationDraft(
        signal_source=SIGNAL_SOURCE, domain=CYBER, country=country,
        status=STATUS_FIRED if is_censoring else STATUS_OK,
        raw_score=2.0 if is_heavy else (1.0 if is_censoring else 0.0),
        value=(f"anomaly={anomaly_rate:.1%} confirmed={confirmed_rate:.1%} "
               f"[{status}]"),
        # `fired_reason` (`core.py:1703-1705`). It is the sentence the
        # cross-sensor enrichment at `core.py:1876-1880` appends the Tor
        # corroboration to, so an empty one loses that text as well.
        reason=(FIRED_REASON_TEMPLATE.format(anomaly=anomaly_rate,
                                             confirmed=confirmed_rate)
                if is_censoring else ""),
        flags={"total_measurements": measurements,
               "anomaly_count": anomalies, "confirmed_count": confirmed,
               "failure_count": failures,
               "anomaly_rate": round(anomaly_rate, 4),
               "confirmed_rate": round(confirmed_rate, 4),
               "is_censoring": is_censoring, "is_heavy": is_heavy,
               "daily_anomaly_rates": daily[-7:],
               # `anomaly_surge` is a BOOL in production
               # (`radar/sensors/ooni.py:156-157,171`), so the pending
               # marker cannot live under that key: a string is truthy,
               # and a consumer reading it as the bool it is declared to
               # be would see a surge asserted on every country forever.
               # The key is ABSENT — "not stated" — and the reason it is
               # absent is named beside it.
               "anomaly_surge_verdict": "pending_l1_prev_anomaly_count"},
        evidence_url=payload.url),)


OONI_CENSORSHIP_ADAPTER = SourceAdapter(
    adapter_id=OONI_CENSORSHIP, category=CYBER,
    requests=(RequestSpec(url=_AGGREGATION_URL, expect_content="json",
                          params=(("probe_cc", "{country}"),
                                  ("since", "{since_date}"),
                                  ("until", "{until_date}"),
                                  ("axis_x", "measurement_start_day"),
                                  ("test_name", "web_connectivity")),
                          headers={"Accept": "application/json"},
                          label="aggregation"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="ooni", min_interval_sec=OONI_MIN_INTERVAL_SEC,
    knowledge_refs=("K04", "K15"),
    baseline_refs=("ooni_prev_anomaly_count",))

__all__ = ["OONI_CENSORSHIP", "OONI_CENSORSHIP_ADAPTER", "normalize",
           "verdict", "CONFIRMED_RATE_CENSORING", "ANOMALY_RATE_CENSORING",
           "CONFIRMED_RATE_HEAVY", "ANOMALY_RATE_HEAVY", "SURGE_FACTOR",
           "SURGE_MIN_PREVIOUS", "DEGRADED_AFTER_FAILURES",
           "DEGRADED_CADENCE_SEC", "NORMAL_CADENCE_SEC",
           "OONI_MIN_INTERVAL_SEC", "SIGNAL_SOURCE",
           "FIRED_REASON_TEMPLATE", "LOOKBACK_DAYS"]
