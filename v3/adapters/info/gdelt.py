"""`gdelt` — S1-SENSI-001..004, D1 §4 K15/K18. Media tone, per country.

GDELT's TimelineTone endpoint returns a sentiment series; the sensor takes
its mean and asks whether today's tone is anomalously hostile. Two windows
are fetched for every country — `1d` (now) and `{history_window}d`, 28 by
default (the comparison baseline).

**K18 is why the verdict is not simply "tone below a line".** Media tone
carries a day-of-week bias — weekend news is a different mix of stories,
not a different world — so production keeps a per-weekday history in L1
(`db.gdelt_dow_record` / `gdelt_dow_same_weekday`) and alerts on a
z-score against SAME-WEEKDAY samples. Comparing Sunday against a Tuesday
mean produces an anomaly every Sunday.

The alert is an OR (`radar/sensors/gdelt.py:73`): the day-of-week z-score
**or** a fixed floor on the raw tone. The second arm needs no history, so
this adapter can and does decide it — a tone under the floor FIRES here.
The first arm needs L1, so when the fixed arm does not fire the row says
OBSERVED and names the baseline it is waiting for, rather than reporting
OK. §7-2 #9's family: "measured, nothing wrong" and "could not finish
judging" must not be the same sentence.

**A7 — the standard-deviation floor.** `max(std, 0.5)` (`gdelt.py:70`) is
hard-coded with no stated origin, and it is load-bearing: it is what stops
a quiet country's near-zero variance from turning a one-point tone move
into an eight-sigma alarm. §3-3 rules that v3 must disclose where the
number came from, so it is a pinned `Threshold` — same value, no longer
anonymous.

**Weather suppression is not reachable from here.** `WEATHER_NOISE`
depends on `weather_conditions`, which is ANOTHER adapter's output
(§2-2 barrier 4). The row states that the check was not performed instead
of leaving `suppressed=False` to be read as fair weather. §7-2 #35.
"""
from __future__ import annotations

from typing import Mapping

from v3.adapters.common import (as_float, country_of, list_or_empty,
                                load_json, mapping_or_empty)
from v3.adapters.types import (AdapterId, INFO, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_NO_DATA, STATUS_OBSERVED)
from v3.kernel import Threshold, Window

GDELT = AdapterId("gdelt")

DOC_API_URL = "https://api.gdeltproject.org/api/v2/doc/doc"

#: `GDELTSensor.QUERY_TEMPLATES` (`radar/sensors/gdelt.py:15-20`),
#: transcribed and pinned against the live class body by a test.
#:
#: These eight strings ARE the sensor: each one decides which corpus the
#: tone series is computed over. A paraphrase — dropping a quoted phrase,
#: reordering an OR, widening a term — changes the measurement while
#: leaving the identifier, the threshold and the output shape intact, so
#: the resulting tone shift is attributed to the world rather than to the
#: port.
QUERY_TEMPLATES: dict = {
    "TW": '"Taiwan" (military OR invasion OR strait OR conflict)',
    "PH": '"Philippines" (military OR "South China Sea" OR conflict)',
    "JP": '"Japan" (military OR defense OR strait OR China)',
    "KR": '"Korea" (military OR nuclear OR "North Korea")',
    "UA": '"Ukraine" (war OR military OR Russia OR offensive)',
    "IL": '"Israel" (military OR attack OR Gaza OR Iran)',
    "US": '"United States" (military OR China OR Taiwan OR Russia)',
    "AU": '"Australia" (military OR China OR defense OR Pacific)',
}

#: K18's constants (`gdelt.py:21-22`).
DOW_MIN_SAMPLES = 3
DOW_MAX_PER_DAY = 20
#: `max_entries=self.DOW_MAX_PER_DAY * 7` (`gdelt.py:64`) — seven weekday
#: buckets, so the retention is per-weekday x 7, not per-day. Derived here
#: rather than written as 140, because F-06 was a "30 day" window that
#: held 30 samples: a product computed at two call sites is a product
#: computed differently at one of them.
DOW_MAX_ENTRIES = DOW_MAX_PER_DAY * 7
#: `_dow_z < -2.0` (`gdelt.py:73`). Negative tone is hostile sentiment, so
#: the alarm is on the LOW side and the sign is part of the threshold.
DOW_Z_ALERT = -2.0

#: A7. The floor under the same-weekday standard deviation
#: (`gdelt.py:70`), disclosed rather than inlined.
DOW_STDDEV_FLOOR = Threshold.pinned(
    0.5, unit="score",
    provenance_ref="radar/sensors/gdelt.py:70 — `max(..., 0.5)`; A7 records "
                   "that the value's origin is unstated in production. It "
                   "guards the divisor: a country whose weekday tone barely "
                   "moves has a near-zero sigma, and without a floor an "
                   "ordinary one-point drift becomes a large z-score.")
#: `GDELT_TONE_ALERT_THRESHOLD`, whose deployed value is the default
#: (`radar/routes/core.py:642`, `os.getenv(..., "-15.0")`). Pinned rather
#: than read: nothing under `v3/` reads the environment, and O-18 rules
#: that "register everything" is the wrong repair — this one is not
#: operationally varied in the deployment.
TONE_ALERT_THRESHOLD = Threshold.pinned(
    -15.0, unit="score",
    provenance_ref="radar/routes/core.py:642 — GDELT_TONE_ALERT_THRESHOLD "
                   "default, which is the deployed value")

#: `add_rat("gdelt", "info", ...)` (`radar/routes/core.py:1132`).
SIGNAL_SOURCE = "gdelt"
#: The 28-day window's row. Production folds both windows into one entry
#: before scoring; L1 cannot hold two rows under one name for one country
#: in one tick, so the baseline half needs a name of its own (§7-2 #11).
BASELINE_SIGNAL_SOURCE = "gdelt_baseline"
#: `core.py:1132`, the FIRED branch's `fired_reason`.
FIRED_REASON = "Media tone collapse"

#: K15's family: `time.sleep(0.5)` between per-country requests
#: (`gdelt.py:43`).
GDELT_MIN_INTERVAL_SEC = 0.5
#: `super().__init__("gdelt", "info", 1800)` (`gdelt.py:23`).
_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 2 * 3600.0

#: `if res.status_code in (429, 503): return None` (`gdelt.py:27`).
NO_DATA_STATUSES: frozenset = frozenset({429, 503})

_CURRENT_LABEL = "tone_1d"
_BASELINE_LABEL = "tone_28d"


def fallback_query(country_name: str) -> str:
    """`gdelt.py:47` — the query for a country with no hand-written one."""
    return (f'"{country_name}" '
            f'(military OR conflict OR attack OR defense OR war)')


def query_for(country: str, country_names: Mapping[str, str]) -> str:
    """The template if one exists, else the name-based fallback.

    `COUNTRY_COORDS.get(code, {}).get("name", code)` (`gdelt.py:46`) falls
    back to the CODE, not to an empty string — a country with no entry in
    the geographic ledger still gets a query that asks about something.
    The ledger arrives through `NormalizeContext` because nothing under
    `v3/` reads configuration.
    """
    template = QUERY_TEMPLATES.get(country)
    if template:
        return template
    name = str(country_names.get(country) or "").strip() or country
    return fallback_query(name)


def mean_tone(document: Mapping):
    """The series mean, rounded to three places — `gdelt.py:28-31`.

    None means "the source did not answer", which stays distinct from a
    tone of 0.0 all the way to the ledger. An empty timeline is the shape
    GDELT returns under load, and reading it as neutral sentiment would
    publish calm the source never reported.
    """
    timeline = list_or_empty(document.get("timeline"))
    if not timeline:
        return None
    points = list_or_empty(mapping_or_empty(timeline[0]).get("data"))
    values = [as_float(mapping_or_empty(point).get("value"))
              for point in points
              if "value" in mapping_or_empty(point)]
    values = [value for value in values if value is not None]
    if not values:
        return None
    return round(sum(values) / len(values), 3)


def dow_zscore(tone: float, samples) -> float:
    """K18's same-weekday z-score (`gdelt.py:69-71`), floor and all.

    Exported because the caller that HAS the samples is WP-4.1's baseline
    wiring, and it must call this rather than write the arithmetic a
    second time — DP4 is the record of what three copies of one z-score
    cost.
    """
    count = len(samples)
    if count < DOW_MIN_SAMPLES:
        raise ValueError(
            f"a day-of-week z-score needs at least {DOW_MIN_SAMPLES} "
            f"same-weekday samples, got {count}; production falls back to "
            f"the fixed threshold alone rather than computing one")
    mean = sum(samples) / count
    variance = sum((value - mean) ** 2 for value in samples) / count
    floor = DOW_STDDEV_FLOOR.resolve().value
    return (tone - mean) / max(variance ** 0.5, floor)


def _no_data(country: str, url: str, detail: str) -> ObservationDraft:
    return ObservationDraft(
        signal_source=SIGNAL_SOURCE, domain=INFO, country=country,
        status=STATUS_NO_DATA, raw_score=0.0, value="NO_DATA",
        flags={"reason": detail}, evidence_url=url)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One tone window for one country.

    Which window this is comes from the request label; both requests go to
    the same URL and differ only in the `timespan` parameter, so the body
    cannot say which one answered.
    """
    country = country_of(payload, context)
    if not country:
        return ()
    is_baseline = str(payload.label or "").startswith(_BASELINE_LABEL)

    if payload.status in NO_DATA_STATUSES:
        # `gdelt.py:27` returns None here, and a None current tone makes
        # the country NO_DATA (`:55`). The baseline window's absence is
        # not NO_DATA in production — it only makes `delta` None — so it
        # is reported as an OBSERVED row with no tone.
        if is_baseline:
            return (ObservationDraft(
                signal_source=BASELINE_SIGNAL_SOURCE, domain=INFO,
                country=country, status=STATUS_OBSERVED, raw_score=0.0,
                value="baseline unavailable",
                flags={"reason": f"http_{payload.status}"},
                evidence_url=payload.url),)
        return (_no_data(country, payload.url, f"http_{payload.status}"),)

    document = load_json(payload)
    if not isinstance(document, Mapping):
        return () if is_baseline else (
            _no_data(country, payload.url, "unparseable"),)

    tone = mean_tone(document)
    if is_baseline:
        return (ObservationDraft(
            signal_source=BASELINE_SIGNAL_SOURCE, domain=INFO,
            country=country, status=STATUS_OBSERVED, raw_score=0.0,
            value=("baseline unavailable" if tone is None
                   else f"tone={tone:.3f}"),
            flags={"tone": tone, "window": _BASELINE_LABEL},
            evidence_url=payload.url),)

    if tone is None:
        return (_no_data(country, payload.url, "empty_timeline"),)

    # `tone_current < alert_threshold` (`gdelt.py:73`), written as the
    # negation of the kernel's `>=` so the comparison goes through the
    # threshold type rather than around it. Reading `.value` out and
    # comparing the bare number is what the discipline gate refuses: it is
    # how F-08 measured a ratio against a percentage.
    below_floor = not TONE_ALERT_THRESHOLD.exceeded_by(tone, unit="score")
    flags: dict = {
        "tone": tone,
        "window": _CURRENT_LABEL,
        "below_alert_threshold": below_floor,
        # §7-2 #35: `weather_conditions` is another adapter's output, so
        # the SUPPRESSED branch cannot be evaluated in this layer. Stated
        # rather than left implied by `suppressed=False`.
        "weather_verdict": "pending_wp41_weather_join",
    }
    if below_floor:
        # The fixed arm of `gdelt.py:73`'s OR decides ALERT on its own, so
        # withholding here would lose a firing production makes — the
        # insensitive direction, which C-02/C-03 treat as blocking.
        return (ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=INFO, country=country,
            status=STATUS_FIRED, raw_score=1.0, value="ALERT",
            reason=FIRED_REASON, flags=flags, evidence_url=payload.url),)

    # The other arm needs the same-weekday history. `is_alert` and `status`
    # are the keys production's consumers read (`core.py:1131`), so neither
    # may carry the marker — the verdict keys are absent and a sibling
    # names why (§7-2 #9's rule).
    flags["dow_verdict"] = "pending_l1_dow_baseline"
    return (ObservationDraft(
        signal_source=SIGNAL_SOURCE, domain=INFO, country=country,
        status=STATUS_OBSERVED, raw_score=0.0, value=f"tone={tone:.3f}",
        flags=flags, evidence_url=payload.url),)


def _tone_request(label: str, timespan: str) -> RequestSpec:
    """One TimelineTone call. Parameter ORDER is production's (`:26`)."""
    return RequestSpec(
        url=DOC_API_URL, expect_content="json",
        params=(("query", "{gdelt_query}"),
                ("mode", "TimelineTone"),
                ("timespan", timespan),
                ("format", "json")),
        label=f"{label}:{{country}}")


GDELT_ADAPTER = SourceAdapter(
    adapter_id=GDELT, category=INFO,
    # Two independent windows, both fetched every cycle. Production runs
    # them on a two-worker pool (`gdelt.py:49-53`); concurrency is the
    # composition root's to decide here (§1-2), so the declaration says
    # only that both are wanted.
    requests=(_tone_request(_CURRENT_LABEL, "1d"),
              _tone_request(_BASELINE_LABEL, "{history_window}d")),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="gdelt", min_interval_sec=GDELT_MIN_INTERVAL_SEC,
    knowledge_refs=("K15", "K18"),
    baseline_refs=("gdelt_dow_tone",))

__all__ = ["GDELT", "GDELT_ADAPTER", "normalize", "query_for",
           "fallback_query", "mean_tone", "dow_zscore", "QUERY_TEMPLATES",
           "DOC_API_URL", "DOW_MIN_SAMPLES", "DOW_MAX_PER_DAY",
           "DOW_MAX_ENTRIES", "DOW_Z_ALERT", "DOW_STDDEV_FLOOR",
           "TONE_ALERT_THRESHOLD", "SIGNAL_SOURCE", "BASELINE_SIGNAL_SOURCE",
           "FIRED_REASON", "GDELT_MIN_INTERVAL_SEC", "NO_DATA_STATUSES"]
