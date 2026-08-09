"""radar.verification.window_catalog — the declarative half of WP-1.3.

Two catalogs, both total by construction:

    CATALOG            every rolling baseline in the system, with how its
                       retention cap is derived and what window it claims.
    THRESHOLD_CATALOG  every threshold-vs-value comparison, with the domain
                       the compared value actually lives in.

Both exist because two defects of the same family shipped unnoticed:

  F-06 (S5-VERIF-010) telegram_mirror caps its baseline at
       NARRATIVE_BASELINE_DAYS *samples*. At a 900 s cadence the declared
       30-day window is 7.5 hours, so the z-score normalises against the
       last few hours of itself. rss_narrative had the identical bug and
       was fixed on 2026-04-29 by multiplying by cycles-per-day — the fix
       was never carried across.
  F-08 (S5-VERIF-008/009) gps_jamming compares a ratio in [0,1] against a
       threshold defaulting to 3.0. Unit-blind comparison, permanently
       false, and fetch health stays green throughout.

Neither is repaired here; WP-0.2 owns the repairs and these catalogs are
the acceptance targets. Coverage is total in the flag_catalog sense: a
sensor is either catalogued or listed in NO_BASELINE_SENSORS. There is no
third state where a baseline is simply not looked at (NP1).

Pure module: dataclasses, arithmetic, and one live read of each sensor's
`poll_interval` — which must stay live, because ct_log and ooni change
their cadence at runtime and a cap computed once at import would lie
(S5-VERIF-011).
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("radar")

# ── baseline kinds ──────────────────────────────────────────────────────────
KIND_ROLLING_LIST = "rolling_list"    # list truncated by slicing
KIND_DEQUE = "deque"                  # collections.deque(maxlen=...)
KIND_WELFORD = "welford"              # running moments, no retention at all
KIND_SNAPSHOT = "snapshot"            # replaced wholesale each cycle
KIND_BUCKETED = "bucketed"            # one row per wall-clock bucket
KIND_STATE_CACHE = "state_cache"      # working state, not a statistic
KIND_TIME_CUTOFF = "time_cutoff"      # pruned by timestamp, not by count
ALL_KINDS = (KIND_ROLLING_LIST, KIND_DEQUE, KIND_WELFORD, KIND_SNAPSHOT,
             KIND_BUCKETED, KIND_STATE_CACHE, KIND_TIME_CUTOFF)

# ── how the retention cap is derived ────────────────────────────────────────
CAP_FIXED = "fixed"                   # N samples regardless of cadence (F-06)
CAP_DAYS_X_CYCLES = "days_x_cycles"   # days x floor(86400/interval) — correct
CAP_NONE = "none"                     # unbounded
CAP_NOT_APPLICABLE = "not_applicable"  # time-anchored, count is not the bound
ALL_CAP_MODES = (CAP_FIXED, CAP_DAYS_X_CYCLES, CAP_NONE, CAP_NOT_APPLICABLE)

# ── how far apart two samples actually land ─────────────────────────────────
INTERVAL_POLL = "poll"                 # the sensor's live poll_interval
INTERVAL_POLL_OR_COOLDOWN = "poll_or_cooldown"  # whichever is slower
INTERVAL_NONE = "none"                 # not driven by a sensor cadence

# Closed unit vocabulary (S5-VERIF-007).
ALL_UNITS = ("ratio", "percent", "count", "s", "min", "h", "d", "km", "z",
             "score", "bool", "multiplier", "index")

HOUR = 3600.0
DAY_SEC = 86400.0


@dataclass(frozen=True)
class WindowSpec:
    """One rolling baseline and the window it claims to hold."""
    baseline_id: str
    sensor: str                        # "" when it lives outside the registry
    kind: str
    cap_mode: str
    note: str
    declared_days: Optional[float] = None
    declared_key: str = ""
    cap_value: Optional[int] = None
    interval_mode: str = INTERVAL_POLL
    cooldown_sec: Optional[float] = None
    source: str = ""                   # file:line of the retention rule


@dataclass(frozen=True)
class ThresholdComparisonSpec:
    """One threshold-vs-value comparison and the domain it compares in."""
    comparison_id: str
    sensor: str
    domain_kind: str
    domain_lo: Optional[float]
    domain_hi: Optional[float]
    note: str
    threshold_key: str = ""            # registered config key, if any
    literal_value: Optional[float] = None   # hardcoded threshold, if any
    source: str = ""


# ── baseline inventory ──────────────────────────────────────────────────────
CATALOG: tuple[WindowSpec, ...] = (
    WindowSpec(
        baseline_id="telegram_mirror._baseline_tg", sensor="telegram_mirror",
        kind=KIND_ROLLING_LIST, cap_mode=CAP_DAYS_X_CYCLES,
        declared_days=30, declared_key="NARRATIVE_BASELINE_DAYS",
        source="radar/sensors/telegram.py:289-322",
        note="Was F-06: the cap truncated to 30 raw samples (7.5 h at the "
             "900 s cadence) against a declared 30 d. Repaired 2026-08-07 "
             "(WP-0.2) to days x cycles_per_day, matching rss_narrative. "
             "The sensor derives that cap from its LIVE poll_interval, the "
             "same value sample_interval_sec() reads here, so the two "
             "cannot drift apart if the cadence ever becomes adaptive. "
             "Class-level state shared by every instance."),
    # ── the same bug, fixed earlier — the control case ─────────────────────
    WindowSpec(
        baseline_id="rss_narrative._baseline", sensor="rss_narrative",
        kind=KIND_ROLLING_LIST, cap_mode=CAP_DAYS_X_CYCLES,
        declared_days=30, declared_key="NARRATIVE_BASELINE_DAYS",
        source="radar/sensors/rss_narrative.py:626-633",
        note="The 2026-04-29 fix: cap = days x cycles_per_day derived from "
             "the sensor's own cadence, so it auto-adjusts. This is the "
             "shape S5-VERIF-010 mandates and telegram never received."),
    # ── bounded, but against nothing declared ──────────────────────────────
    WindowSpec(
        baseline_id="check_host._url_latency_history", sensor="check_host",
        kind=KIND_DEQUE, cap_mode=CAP_FIXED, cap_value=12,
        interval_mode=INTERVAL_POLL_OR_COOLDOWN, cooldown_sec=300,
        source="radar/sensors/checkhost.py:34-35,143",
        note="deque(maxlen=12) backing the asphyxiation comparison. No "
             "declared window to check against; the source comment claims "
             "'≈1 h at 5-min poll' while the poll default is 600 s and a "
             "300 s per-URL cooldown floors the spacing — really ~2 h."),
    # ── unbounded ──────────────────────────────────────────────────────────
    WindowSpec(
        baseline_id="sensor_zscore_stats", sensor="",
        kind=KIND_WELFORD, cap_mode=CAP_NONE,
        source="radar/database.py:885 (DDL), :4652 (zscore_stats_update)",
        note="Welford running moments per (sensor, country). sample_count "
             "only ever grows: no cap, no TTL, no decay. A regime change "
             "from a year ago still weighs as much as yesterday."),
    # ── correct by construction ────────────────────────────────────────────
    WindowSpec(
        baseline_id="bgp_routing.snapshot", sensor="ripe_bgp",
        kind=KIND_SNAPSHOT, cap_mode=CAP_NOT_APPLICABLE,
        source="radar/sensors/bgp_routing.py:56-57",
        note="Single hourly snapshot, reset each cycle — there is no "
             "accumulation to mis-size."),
    WindowSpec(
        baseline_id="checkhost_hod", sensor="check_host",
        kind=KIND_BUCKETED, cap_mode=CAP_NOT_APPLICABLE,
        declared_days=28, declared_key="HOD_BASELINE_DAYS",
        source="radar/sensors/checkhost.py:248-251",
        note="One row per wall-clock hour behind a bucket guard, capped at "
             "HOD_MAX_ENTRIES = 28 d x 24. Bound is time, not sample count, "
             "so cadence changes cannot shrink the window."),
    WindowSpec(
        baseline_id="bgp_hod", sensor="ripe_bgp",
        kind=KIND_BUCKETED, cap_mode=CAP_NOT_APPLICABLE,
        declared_days=28, declared_key="HOD_BASELINE_DAYS",
        source="radar/sensors/bgp_routing.py:63-66",
        note="Same hour-bucket guard as checkhost_hod."),
    WindowSpec(
        baseline_id="gdelt_dow", sensor="gdelt",
        kind=KIND_BUCKETED, cap_mode=CAP_NOT_APPLICABLE,
        source="radar/sensors/gdelt.py:61-63",
        note="One entry per day-of-week bucket, max 140 — 20 weeks of "
             "same-weekday history. Time-anchored."),
    WindowSpec(
        baseline_id="ais_maritime._vessel_history", sensor="ais_maritime",
        kind=KIND_STATE_CACHE, cap_mode=CAP_NOT_APPLICABLE,
        source="radar/sensors/ais_maritime.py:143-152",
        note="Working state for dark-gap detection (24 h + 5000 entries), "
             "not a statistical baseline — nothing normalises against it."),
    WindowSpec(
        baseline_id="convergence_tracker.window", sensor="convergence_tracker",
        kind=KIND_TIME_CUTOFF, cap_mode=CAP_NOT_APPLICABLE,
        declared_days=3,
        source="radar/sensors/convergence_tracker.py:44,47",
        note="72 h retention enforced by timestamp cutoff."),
    WindowSpec(
        baseline_id="engine.theater_baseline", sensor="",
        kind=KIND_TIME_CUTOFF, cap_mode=CAP_NOT_APPLICABLE,
        declared_key="THEATER_BASELINE_WINDOW",
        source="radar/engine.py:846",
        note="Scoring-side baseline pruned by a time cutoff, so the "
             "declared window is enforced directly."),
)

# Sensors with no rolling baseline of their own. Declared explicitly so the
# catalog is total: coverage gaps must be impossible, not merely unlikely.
NO_BASELINE_SENSORS: frozenset = frozenset({
    "apt_intel", "bg_observer_rss", "cloudflare_radar", "ct_log",
    "diplomatic", "greynoise", "ground_osint", "hacktivist_intel",
    "hacktivist_news", "ihr_health", "ioda_bgp", "isr_hotspot",
    "mil_support_air", "military_exercise", "nasa_firms", "notam",
    "ooni_censorship", "opensky", "openweather", "peeringdb_ixp",
    "ripe_atlas", "space_weather", "threatfox", "tor_metrics",
    "travel_advisory", "usgs_seismic", "gps_jamming",
})


# ── threshold inventory ─────────────────────────────────────────────────────
THRESHOLD_CATALOG: tuple[ThresholdComparisonSpec, ...] = (
    ThresholdComparisonSpec(
        comparison_id="gps_jamming.is_jammed", sensor="gps_jamming",
        domain_kind="ratio", domain_lo=0.0, domain_hi=1.0,
        threshold_key="GPS_JAM_THRESHOLD",
        source="radar/sensors/gps_jamming.py:188,203",
        note="Was F-08: `bad / (good + bad)` is a fraction but the "
             "threshold defaulted to 3.0 on a percent scale, so the "
             "comparison was never true. Repaired 2026-08-07 (WP-0.2) to "
             "0.03 with unit='ratio' and a rescaled tunable range."),
    ThresholdComparisonSpec(
        comparison_id="gps_jamming.is_critical", sensor="gps_jamming",
        domain_kind="ratio", domain_lo=0.0, domain_hi=1.0,
        threshold_key="GPS_JAM_CRITICAL_THRESHOLD",
        source="radar/sensors/gps_jamming.py:189,215",
        note="Was F-08, CRITICAL tier. Same ratio against a 7.0 percent "
             "threshold; repaired 2026-08-07 (WP-0.2) to 0.07."),
    ThresholdComparisonSpec(
        comparison_id="isr_hotspot.surge", sensor="isr_hotspot",
        domain_kind="count", domain_lo=0.0, domain_hi=None,
        threshold_key="ISR_SURGE_THRESHOLD",
        source="radar/sensors/isr_hotspot.py:107",
        note="Aircraft count against a count threshold — consistent."),
    ThresholdComparisonSpec(
        comparison_id="gdelt.tone_alert", sensor="gdelt",
        domain_kind="score", domain_lo=-100.0, domain_hi=100.0,
        threshold_key="GDELT_TONE_ALERT_THRESHOLD",
        source="radar/sensors/gdelt.py:73,76",
        note="GDELT tone is a signed score; -15 sits inside the domain and "
             "the registry range [-100, 0] is entirely reachable."),
    ThresholdComparisonSpec(
        comparison_id="telegram_mirror.zscore_alert", sensor="telegram_mirror",
        domain_kind="z", domain_lo=None, domain_hi=None,
        threshold_key="NARRATIVE_ZSCORE_ALERT",
        source="radar/sensors/telegram.py:396-399",
        note="z-score against a z threshold. Unit-consistent, and since "
             "the F-06 repair (2026-08-07) the baseline it standardises "
             "against is the declared 30 d rather than 7.5 h."),
    ThresholdComparisonSpec(
        comparison_id="rss_narrative.zscore_critical", sensor="rss_narrative",
        domain_kind="z", domain_lo=None, domain_hi=None,
        threshold_key="NARRATIVE_ZSCORE_CRITICAL",
        source="radar/sensors/rss_narrative.py:707-709",
        note="z-score against a z threshold, over a correctly sized window."),
    ThresholdComparisonSpec(
        comparison_id="telegram_mirror.claim_confidence",
        sensor="telegram_mirror",
        domain_kind="ratio", domain_lo=0.0, domain_hi=1.0,
        threshold_key="TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD",
        source="radar/sensors/telegram.py:22",
        note="Confidence in [0,1] against a [0,1]-bounded threshold."),
    ThresholdComparisonSpec(
        comparison_id="usgs_seismic.magnitude", sensor="usgs_seismic",
        domain_kind="index", domain_lo=0.0, domain_hi=10.0,
        threshold_key="USGS_MIN_MAGNITUDE",
        source="radar/sensors/usgs_seismic.py:66",
        note="Moment magnitude against a magnitude floor, both on the "
             "Richter-like scale."),
    ThresholdComparisonSpec(
        comparison_id="notam.surge", sensor="notam",
        domain_kind="count", domain_lo=0.0, domain_hi=None,
        literal_value=20.0, source="radar/sensors/notam.py:158",
        note="Hardcoded count threshold against a count."),
    ThresholdComparisonSpec(
        comparison_id="ooni.anomaly_ratio", sensor="ooni_censorship",
        domain_kind="ratio", domain_lo=0.0, domain_hi=1.0,
        literal_value=0.05, source="radar/sensors/ooni.py:150-162",
        note="Hardcoded fractions 0.05/0.15/0.20/0.40 against a measured "
             "fraction. The lowest is catalogued as the representative."),
    ThresholdComparisonSpec(
        comparison_id="check_host.asphyxiation", sensor="check_host",
        domain_kind="multiplier", domain_lo=0.0, domain_hi=None,
        literal_value=3.0, source="radar/sensors/checkhost.py:147-151",
        note="latency_ms > rolling_avg_ms x 3.0 — a ratio of like units, so "
             "the multiplier is dimensionless and consistent."),
    ThresholdComparisonSpec(
        comparison_id="ripe_bgp.prefix_drop", sensor="ripe_bgp",
        domain_kind="ratio", domain_lo=0.0, domain_hi=1.0,
        literal_value=0.15, source="radar/sensors/bgp_routing.py:22,77",
        note="Class-constant fraction against a measured fraction."),
    ThresholdComparisonSpec(
        comparison_id="mil_support_air.tanker_count", sensor="mil_support_air",
        domain_kind="count", domain_lo=0.0, domain_hi=None,
        literal_value=3.0, source="radar/sensors/mil_support_air.py:154-155",
        note="Hardcoded aircraft counts against counts."),
    ThresholdComparisonSpec(
        comparison_id="space_weather.kp_suppress", sensor="space_weather",
        domain_kind="index", domain_lo=0.0, domain_hi=9.0,
        literal_value=6.0, source="radar/sensors/space_weather.py:117",
        note="Kp index in [0,9] against 6. Env-tunable but NOT registered, "
             "so the SETTINGS UI cannot see it (a G-15 sibling)."),
)


# ── arithmetic (pure) ───────────────────────────────────────────────────────
def _sensor(name: str):
    try:
        from radar import registry
        return registry.get(name)
    except Exception as exc:  # noqa: BLE001 - a lookup failure is not a verdict
        log.warning("window catalog: registry lookup failed for %s: %s",
                    name, exc)
        return None


def sample_interval_sec(spec: WindowSpec) -> Optional[float]:
    """How far apart two samples of this baseline actually land.

    Read live on every call: ct_log and ooni rewrite `poll_interval` while
    running, and S5-VERIF-011 forbids trusting an import-time value.
    """
    if spec.interval_mode == INTERVAL_NONE or not spec.sensor:
        return None
    sensor = _sensor(spec.sensor)
    if sensor is None or not getattr(sensor, "poll_interval", None):
        return None
    interval = float(sensor.poll_interval)
    if spec.interval_mode == INTERVAL_POLL_OR_COOLDOWN and spec.cooldown_sec:
        return max(interval, float(spec.cooldown_sec))
    return interval


def cap_samples(spec: WindowSpec, interval_sec: Optional[float]) -> Optional[int]:
    """The retention cap in samples, given the live cadence."""
    if spec.cap_mode == CAP_FIXED:
        return spec.cap_value
    if spec.cap_mode == CAP_DAYS_X_CYCLES:
        if not interval_sec or not spec.declared_days:
            return None
        cycles_per_day = max(1, int(DAY_SEC / max(1.0, interval_sec)))
        return int(spec.declared_days * cycles_per_day)
    return None


def effective_window_hours(spec: WindowSpec,
                           interval_sec: Optional[float]) -> Optional[float]:
    """How much wall-clock time the cap actually holds."""
    cap = cap_samples(spec, interval_sec)
    if cap is None or not interval_sec:
        return None
    return cap * float(interval_sec) / HOUR


def declared_window_hours(spec: WindowSpec) -> Optional[float]:
    if spec.declared_days is None:
        return None
    return float(spec.declared_days) * 24.0


def window_deviation(effective_h: Optional[float],
                     declared_h: Optional[float]) -> Optional[float]:
    """|effective/declared - 1|, the S5-VERIF-011 measure."""
    if effective_h is None or not declared_h:
        return None
    return abs(effective_h / declared_h - 1.0)


def in_domain(value: Optional[float], lo: Optional[float],
              hi: Optional[float]) -> Optional[bool]:
    """Whether a threshold can ever be met by a value from this domain."""
    if value is None:
        return None
    if lo is not None and value < lo:
        return False
    if hi is not None and value > hi:
        return False
    return True


def range_overlap_fraction(min_value: Optional[float],
                           max_value: Optional[float],
                           lo: Optional[float],
                           hi: Optional[float]) -> Optional[float]:
    """What share of a key's tunable range lands inside the domain.

    S5-VERIF-009a nuance: GPS_JAM_THRESHOLD's min of 0.5 does intersect
    [0,1], so "0% reachable" would overstate the defect — 2.6% of the
    tunable range works and the rest cannot.
    """
    if min_value is None or max_value is None:
        return None
    span = float(max_value) - float(min_value)
    low = max(float(min_value), -math.inf if lo is None else float(lo))
    high = min(float(max_value), math.inf if hi is None else float(hi))
    overlap = max(0.0, high - low)
    if span <= 0:
        return 1.0 if overlap >= 0 and in_domain(min_value, lo, hi) else 0.0
    return min(1.0, overlap / span)
