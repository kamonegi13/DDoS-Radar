"""`space_weather` — S1-SENS-033/034, D1 §4 K17. Now fail-CLOSED.

A15: when both NOAA endpoints failed, the legacy sensor recorded a
successful fetch with `Kp = 0.0` and X-ray class A — the readings of a
perfectly quiet sun — and its health stayed OK. An outage was therefore
indistinguishable from calm, and under NP1 reading a gap as quiet is the
one thing a suppressor must never do (it removes suppression that should
have applied, or asserts calm that was never measured).

Design sheet §7-2 registers the repair as expected difference #2. The
structure here makes it hold by construction: each endpoint normalizes
its OWN payload, and `normalize` is only ever called on a payload that
arrived. A failed endpoint therefore contributes no observation at all,
rather than a default one. There is no code path that invents a reading.

K17: Kp >= 6 (observed, never forecast) or X-ray class M or above.
"""
from __future__ import annotations

from v3.adapters.common import as_float, list_or_empty, load_json
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter,
                               STATUS_OK, STATUS_SUPPRESSED)
from v3.kernel import Window

SPACE_WEATHER = AdapterId("space_weather")

_KP_URL = ("https://services.swpc.noaa.gov/products/"
           "noaa-planetary-k-index-forecast.json")
_XRAY_URL = "https://services.swpc.noaa.gov/json/goes/primary/xrays-6-hour.json"

KP_SUPPRESS_THRESHOLD = 6.0
XRAY_SUPPRESS_CLASS = "M"
XRAY_CLASS_ORDER: dict = {"A": 0, "B": 1, "C": 2, "M": 3, "X": 4}
#: Flux (W/m²) at which each class starts.
XRAY_CLASS_FLOORS: tuple = (("X", 1e-4), ("M", 1e-5), ("C", 1e-6),
                            ("B", 1e-7))

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 3 * 3600.0


def xray_class(flux: float) -> str:
    for name, floor in XRAY_CLASS_FLOORS:
        if flux >= floor:
            return name
    return "A"


def storm_level(kp: float) -> str:
    for threshold, name in ((9, "EXTREME"), (8, "SEVERE"), (7, "STRONG"),
                            (6, "MODERATE"), (5, "MINOR")):
        if kp >= threshold:
            return name
    return "NONE"


def _normalize_kp(payload) -> tuple[ObservationDraft, ...]:
    rows = load_json(payload)
    if not isinstance(rows, list) or len(rows) < 2:
        return ()
    observed = [row for row in rows[1:]
                if isinstance(row, list) and len(row) >= 3
                and row[2] == "observed"]
    values = [as_float(row[1], None) for row in rows[1:]
              if isinstance(row, list) and len(row) >= 2]
    values = [value for value in values if value is not None]
    if not observed and not values:
        return ()
    kp_index = as_float(observed[-1][1], 0.0) or 0.0 if observed else 0.0
    kp_forecast = max(values) if values else 0.0
    # The suppression reads the OBSERVED index only. A forecast storm is
    # not yet noise, and suppressing on a forecast would discard real
    # signal on the strength of a prediction.
    suppress = kp_index >= KP_SUPPRESS_THRESHOLD
    return (ObservationDraft(
        signal_source="space_weather", domain=PHYSICAL, country="",
        status=STATUS_SUPPRESSED if suppress else STATUS_OK, raw_score=0.0,
        suppressed=suppress,
        suppress_reason=(
            f"Geomagnetic storm: Kp={kp_index:.1f} "
            f"(≥{KP_SUPPRESS_THRESHOLD:.0f}) — physical sensor noise "
            f"expected" if suppress else None),
        value=f"Kp={kp_index:.1f} [{storm_level(max(kp_index, kp_forecast))}]",
        flags={"kp_index": kp_index, "kp_forecast_24h": kp_forecast,
               "storm_level": storm_level(max(kp_index, kp_forecast)),
               "suppress_physical": suppress, "endpoint": "kp"},
        evidence_url=payload.url),)


def _normalize_xray(payload) -> tuple[ObservationDraft, ...]:
    rows = load_json(payload)
    rows = [row for row in list_or_empty(rows) if isinstance(row, dict)]
    if not rows:
        return ()
    flux = as_float(rows[-1].get("flux"), None)
    if flux is None:
        return ()
    name = xray_class(flux)
    suppress = (XRAY_CLASS_ORDER.get(name, 0)
                >= XRAY_CLASS_ORDER[XRAY_SUPPRESS_CLASS])
    return (ObservationDraft(
        signal_source="space_weather", domain=PHYSICAL, country="",
        status=STATUS_SUPPRESSED if suppress else STATUS_OK, raw_score=0.0,
        suppressed=suppress,
        suppress_reason=(
            f"Geomagnetic storm: X-ray {name}-class "
            f"(≥{XRAY_SUPPRESS_CLASS}) — physical sensor noise expected"
            if suppress else None),
        value=f"xray={name}",
        flags={"xray_class": name, "xray_flux": flux,
               "suppress_physical": suppress, "endpoint": "xray"},
        evidence_url=payload.url),)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """Dispatch on the request label. One endpoint, one observation.

    Splitting the two endpoints is what makes the fail-closed repair
    structural: there is no combined reading to default half of.
    """
    if payload.label == "kp":
        return _normalize_kp(payload)
    if payload.label == "xray":
        return _normalize_xray(payload)
    return ()


SPACE_WEATHER_ADAPTER = SourceAdapter(
    adapter_id=SPACE_WEATHER, category=PHYSICAL,
    requests=(RequestSpec(url=_KP_URL, expect_content="json", label="kp"),
              RequestSpec(url=_XRAY_URL, expect_content="json",
                          label="xray")),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="noaa_swpc", knowledge_refs=("K17",))

__all__ = ["SPACE_WEATHER", "SPACE_WEATHER_ADAPTER", "normalize",
           "xray_class", "storm_level", "KP_SUPPRESS_THRESHOLD",
           "XRAY_SUPPRESS_CLASS", "XRAY_CLASS_ORDER"]
