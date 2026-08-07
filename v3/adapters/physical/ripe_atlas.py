"""`ripe_atlas` — S1-SENS-041, D1 §4 K15. Probes that stop answering.

Two measurements, one question. The probe count says how much of the
country's measurement infrastructure is still reachable; the latency of
three always-on public measurements (k-root 1001, f-root 1004, Google DNS
10509) says how the paths to it are behaving.

`drop_pct` compares the count against the previous cycle's — state the
legacy sensor kept in `self._prev_probe_counts`, so a restart made every
country look stable exactly when a restart was most likely (DP3/A-03).
§3-2 rules it to L1; the dependency is declared, and the count is
reported as measured rather than compared against a baseline this layer
does not hold.

Two facts about the RTT numbers, both counter-intuitive and both easy to
misread:

1. `probes_responding` counts RTT SAMPLES, pooling each probe's `avg`
   with every individual `rt`. It is not a probe count, and reading it as
   one overstates coverage.
2. `normalize` sees ONE measurement's payload at a time, so `avg_ms` /
   `p95_ms` / `probes_responding` here describe **one measurement id**.
   Production pools all three into `latency_rtts[code]` FIRST and only
   then computes them (`radar/sensors/ripe_atlas.py:133, 137-147`). That
   fold is a WP-4.1 reduction, the same shape as design sheet §3-5
   H-1(b); `pool_scope` says so on every emitted draft, and
   `rtt_samples` carries what the reduction needs, because a pooled p95
   cannot be recovered from three per-measurement p95s.
"""
from __future__ import annotations

from typing import Optional

from v3.adapters.common import (as_float, as_int, country_of, list_or_empty,
                                load_json, mapping_or_empty)
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter,
                               STATUS_OBSERVED)
from v3.kernel import Window

RIPE_ATLAS = AdapterId("ripe_atlas")

_ATLAS_BASE = "https://atlas.ripe.net/api/v2"
_PROBES_URL = f"{_ATLAS_BASE}/probes/"

#: k-root, f-root, Google DNS — always-on public measurements.
#: `radar/sensors/ripe_atlas.py:27` (`DEFAULT_MEASUREMENT_IDS`), queried
#: once per (country, id) at `:124`.
MEASUREMENT_IDS: tuple[int, ...] = (1001, 1004, 10509)
PROBE_DROP_PCT = 0.30
PROBE_BLACKOUT_PCT = 0.70
#: K15's family: RIPE asks for 0.3s between calls.
RIPE_MIN_INTERVAL_SEC = 0.3

#: The label every latency request carries, with its measurement id
#: appended. The ids are part of the ADDRESS, so each is its own concrete
#: request: a `{measurement_id}` nobody supplies makes `expand_requests`
#: refuse, and `run_due` turns that refusal into a whole-adapter skip
#: recorded as `unresolved_placeholder` — the silent death that took
#: `check_host` out of the roster.
LATENCY_LABEL_PREFIX = "latency_"
PROBES_LABEL = "probes"

#: The three latency drafts a country produces in one tick MUST NOT share
#: a `signal_source`: the ledger key is
#: `UNIQUE (tick_id, sensor, signal_source, country)`
#: (`v3/ledger/schema.py:157`), so three rows under one name are a
#: `DomainError` at best and a silent drop at worst
#: (`v3/ledger/store.py:290`). Production has no name to copy — it pools
#: the three into a single per-country figure BEFORE anything is recorded
#: — so the id is carried in the name and the fold is WP-4.1's. Declared
#: as a table so the ledger keys stay readable without running `normalize`.
LATENCY_SIGNAL_SOURCE = "atlas_latency"
LATENCY_SIGNAL_SOURCES: dict = {
    measurement_id: f"{LATENCY_SIGNAL_SOURCE}_{measurement_id}"
    for measurement_id in MEASUREMENT_IDS}

_CADENCE = Window.from_days(1.0, cadence_sec=600.0)
_FRESHNESS_HORIZON_SEC = 1800.0


def collect_rtts(results) -> list[float]:
    """Every positive `avg` and every positive nested `rt`, pooled.

    Non-positive values are dropped: RIPE encodes a lost packet as -1,
    and averaging that in would report an impossibly fast path.
    """
    values: list[float] = []
    for probe in list_or_empty(results):
        record = mapping_or_empty(probe)
        average = as_float(record.get("avg"), None)
        if average is not None and average > 0:
            values.append(average)
        for result in list_or_empty(record.get("result")):
            rtt = as_float(mapping_or_empty(result).get("rt"), None)
            if rtt is not None and rtt > 0:
                values.append(rtt)
    return values


def percentile_95(values) -> float:
    """Index `int(n * 0.95)`, clipped to the last element."""
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(int(len(ordered) * 0.95), len(ordered) - 1)
    return round(ordered[index], 2)


def drop_pct(previous, active) -> float:
    """`(prev - active) / max(prev, 1)`, 0.0 when there is no previous.

    The first observation of a country compares it against itself, which
    is why a fresh process reports no drop rather than a total one.
    """
    if not previous or previous <= 0:
        return 0.0
    return round((previous - active) / max(previous, 1), 3)


def status_for(drop) -> str:
    if drop >= PROBE_BLACKOUT_PCT:
        return "PROBE_BLACKOUT"
    return "PROBE_DROP" if drop >= PROBE_DROP_PCT else "NORMAL"


def measurement_id_of(payload) -> Optional[int]:
    """Which of the three measurements this latency payload answers for.

    Read out of the URL that was actually fetched, with the label as a
    second try. The same argument `country_of` makes in
    `v3/adapters/common.py`: the address is the self-describing part of a
    recorded payload, and the id is IN the address
    (`/measurements/{mid}/latest/`, `radar/sensors/ripe_atlas.py:72`).
    """
    url = str(getattr(payload, "url", "") or "")
    marker = "/measurements/"
    if marker in url:
        found = as_int(url.split(marker, 1)[1].split("/", 1)[0], None)
        if found is not None:
            return found
    label = str(getattr(payload, "label", "") or "")
    if label.startswith(LATENCY_LABEL_PREFIX):
        return as_int(label[len(LATENCY_LABEL_PREFIX):], None)
    return None


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """Probe counts and RTTs -> one OBSERVED reading per country.

    The verdict (`PROBE_DROP` / `PROBE_BLACKOUT`, scoring 1 and 2) needs
    the previous count, which L1 will hold. `status_for` and `drop_pct`
    are exported so that wiring computes the same verdict rather than a
    second implementation of it — DP4 is what happens otherwise.

    The two halves carry DIFFERENT `signal_source` values on purpose.
    Production emits one rationale entry, `add_rat("ripe_atlas", ...)`
    (`radar/routes/core.py:1547`), whose FIRED verdict comes only from
    the probe-drop status — so the probe half owns that name and is the
    row WP-2.8 joins on. The latency half cannot share it: the ledger key
    is `UNIQUE (tick_id, sensor, signal_source, country)`
    (`v3/ledger/schema.py:157`) and two `OBSERVED`/`0.0` rows under one
    key are dropped SILENTLY (`v3/ledger/store.py:290`, S5-VERIF-019).
    """
    country = country_of(payload, context)
    if not country:
        return ()

    if payload.label == PROBES_LABEL:
        document = mapping_or_empty(load_json(payload))
        active = as_int(document.get("count"), None)
        if active is None:
            return ()
        return (ObservationDraft(
            signal_source="ripe_atlas", domain=PHYSICAL, country=country,
            status=STATUS_OBSERVED, raw_score=0.0,
            # `f"{active} probes, {avg_ms:.0f}ms"` is production's OK text
            # (core.py:1544). The latency half arrives in a different
            # payload, so the join is WP-4.1's; this states what THIS
            # payload measured.
            value=f"{active} probes",
            # `prev` and `drop_pct` are ABSENT rather than 0 / "pending".
            # Production carries `drop_pct` as a float
            # (`radar/sensors/ripe_atlas.py:62`, `round(drop_pct, 3)`), and
            # a marker string in that key reads as a truthy float to every
            # consumer — a fabricated reading dressed as "undecided", which
            # also defeats any silence detector watching the same key. The
            # verdict is NAMED in a sibling instead (§7-2 #8, `ct_log`).
            flags={"active": active,
                   "probe_drop_verdict": "pending_l1_prev_probe_count"},
            evidence_url=payload.url),)

    measurement_id = measurement_id_of(payload)
    rtts = collect_rtts(load_json(payload))
    if not rtts:
        return ()
    average = round(sum(rtts) / len(rtts), 2)
    return (ObservationDraft(
        signal_source=LATENCY_SIGNAL_SOURCES.get(measurement_id,
                                                 LATENCY_SIGNAL_SOURCE),
        domain=PHYSICAL, country=country,
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"{average:.0f}ms",
        flags={"avg_ms": average, "p95_ms": percentile_95(rtts),
               # Samples, not probes. Named so it cannot be misread.
               "probes_responding": len(rtts),
               "measurement_id": measurement_id,
               # ONE measurement id, not the country's pooled figure.
               "pool_scope": "single_measurement",
               # What the WP-4.1 fold needs: a pooled p95 cannot be
               # recovered from three per-measurement p95s.
               "rtt_samples": tuple(rtts)},
        evidence_url=payload.url),)


def _probes_spec() -> RequestSpec:
    """`radar/sensors/ripe_atlas.py:50-51`, parameters in that order."""
    return RequestSpec(url=_PROBES_URL, expect_content="json",
                       params=(("country_code", "{country}"), ("status", "1"),
                               ("page_size", "1")),
                       label=PROBES_LABEL)


def _latency_spec(measurement_id: int) -> RequestSpec:
    """`radar/sensors/ripe_atlas.py:72-73` for one measurement id."""
    return RequestSpec(
        url=f"{_ATLAS_BASE}/measurements/{measurement_id}/latest/",
        expect_content="json", params=(("probe_cc", "{country}"),),
        label=f"{LATENCY_LABEL_PREFIX}{measurement_id}")


RIPE_ATLAS_ADAPTER = SourceAdapter(
    adapter_id=RIPE_ATLAS, category=PHYSICAL,
    requests=(_probes_spec(),) + tuple(_latency_spec(measurement_id)
                                       for measurement_id in MEASUREMENT_IDS),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="ripe", min_interval_sec=RIPE_MIN_INTERVAL_SEC,
    knowledge_refs=("K15",), baseline_refs=("atlas_prev_probe_count",))

__all__ = ["RIPE_ATLAS", "RIPE_ATLAS_ADAPTER", "normalize", "collect_rtts",
           "percentile_95", "drop_pct", "status_for", "measurement_id_of",
           "MEASUREMENT_IDS", "PROBE_DROP_PCT", "PROBE_BLACKOUT_PCT",
           "RIPE_MIN_INTERVAL_SEC", "LATENCY_LABEL_PREFIX", "PROBES_LABEL",
           "LATENCY_SIGNAL_SOURCE", "LATENCY_SIGNAL_SOURCES"]
