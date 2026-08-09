"""The verdicts that were withheld for want of history — transcribed.

Pure. Every function here takes the history as an argument and returns a
value; nothing opens a database, so a fold that uses one can be replayed
from recorded payloads exactly as it ran.

Each ladder names the production line it came from. They are gathered in
one module rather than inlined in `reduce.py` because they are the part a
differential sweep runs against production, and a sweep needs a function
to call.

**The warm-up branch is not optional.** Production never withholds a score
while an hour-of-day baseline is cold — it falls back to fixed thresholds
(`core.py:1015-1019`, `checkhost.py:266-269`, `gdelt.py:75-77`). Porting
only the Z-score branch would have swapped one silence for another: an
adapter that says nothing for the first seven days of every new country.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from v3.adapters.cyber import ct_log as _ct_log
from v3.adapters.physical import ais_maritime as _ais
from v3.adapters.physical import check_host as _check_host

# ── the shared statistic ────────────────────────────────────────────────
#
# `compute_hod_zscore` (`radar/scoring.py:473-497`), checkhost
# (`:255-259`), bgp (`:69-73`) and gdelt (`:68-71`) are the SAME four
# lines four times, differing only in the floor and the minimum. DP4 is a
# catalogue of what happens when that is left as four copies, so it is one
# function with the differences as arguments.
#
# Two details that look like rounding and are not:
#   * the variance divides by n, not n-1. A sample variance would make
#     every Z smaller and every threshold harder to reach — insensitive.
#   * the floor is applied to the STANDARD DEVIATION, after the square
#     root, not to the variance.


@dataclass(frozen=True, slots=True)
class PhaseStat:
    """The result of comparing a reading with its same-phase history."""

    z: Optional[float]
    valid: bool
    n: int
    mean: Optional[float] = None


def phase_zscore(values: Sequence[float], current: float, *,
                 min_samples: int, std_floor: float) -> PhaseStat:
    """`(current - mean) / max(std, floor)` over the same-phase history.

    `valid` is False below `min_samples`, and `z` is then None rather than
    0.0. Production returns 0.0 there and relies on every caller checking
    the flag; a 0.0 that escapes a missed check reads as "exactly average",
    which is the most reassuring possible value for an unknown.
    """
    n = len(values)
    if n < min_samples:
        return PhaseStat(z=None, valid=False, n=n)
    mean = sum(values) / n
    variance = sum((value - mean) ** 2 for value in values) / n
    std = max(variance ** 0.5, std_floor)
    return PhaseStat(z=(current - mean) / std, valid=True, n=n, mean=mean)


# ── ripe_bgp (`radar/sensors/bgp_routing.py:67-77`, core.py:1148) ───────

BGP_HOD_MIN_SAMPLES = 7          # `HOD_MIN_SAME_HOUR`
BGP_HOD_STD_FLOOR = 1.0
BGP_HOD_ANOMALY_Z = -2.0
BGP_ANOMALY_SCORE = 1.0


def bgp_hod_verdict(values: Sequence[float], prefixes: float) -> PhaseStat:
    return phase_zscore(values, prefixes, min_samples=BGP_HOD_MIN_SAMPLES,
                        std_floor=BGP_HOD_STD_FLOOR)


def bgp_is_anomaly(stat: PhaseStat) -> bool:
    return bool(stat.valid and stat.z is not None
                and stat.z < BGP_HOD_ANOMALY_Z)


# ── ripe_bgp warm-up — v3 only, §7-2 #135 ───────────────────────────────
#
# The one verdict in this module production does NOT reach the same way.
# Everything above is transcription; this is a design, and it is here
# rather than in the fold for the reason the module docstring gives —
# a differential sweep needs a function to call, and this one is swept
# against `bgp_is_anomaly` to prove it is the stricter of the two.
#
# Production's warm-up branch (`bgp_routing.py:74`) is
# `drop_ratio > 0.15`, where `drop_ratio` measures against
# `self._baseline[code]`: a dict in process memory, re-seeded on the first
# reading after every restart and refreshed hourly (`:53,:57`). D2 A-03.
# It is not in `baseline_refs`, it is not in L1, and it cannot be
# replayed — so v3 cannot transcribe it, and R1 says it must not try.
#
# What v3 has instead is the SAME series the warm path reads, unfiltered.
# `bgp_hod` holds one bucket per HOUR; the warm path keeps only the
# buckets sharing the current hour of day, so it needs seven DAYS to see
# seven samples where the series itself needed seven HOURS. The pooled
# read is those same rows with the phase filter lifted.
#
# Pooling costs something real and the constants are what pays for it.
# Writing the pooled variance as sigma_a^2 = sigma_w^2 + sigma_b^2
# (within-hour plus between-hour) and the current hour's diurnal offset
# as d_h, the two Z scores relate as
#
#     z_pooled = (z_hod * sigma_w + d_h) / sigma_a
#
# so at an hour that is normally QUIET (d_h < 0) the pooled Z is depressed
# by an amount that has nothing to do with the reading. With
# sigma_w = sigma_b, an exactly average country (z_hod = 0) already scores
# z_pooled = -0.71, and a -2.0 threshold on the pooled Z would fire at
# z_hod = -1.83: EARLIER than the warm path, on strictly less evidence.
# Hence two changes rather than none:
#
#   * the threshold widens to -3.0, and
#   * firing additionally requires production's own relative drop.
#
# The conjunction is not invented either. `checkhost_status` above is the
# same shape and says why: a Z branch that also requires the absolute
# reading to be bad is what keeps a routine maintenance window out of the
# ledger. Here it also bounds the smallest movement that can fire at 15%
# of the pooled mean, which is what makes the pooled sigma's quality
# non-critical — a badly estimated sigma cannot turn a 2% wobble into a
# verdict.

#: `HOD_MIN_SAME_HOUR` (`radar/config.py`, `bgp_routing.py:23`) — the same
#: minimum production asks of the warm path, asked of the pooled series.
#: Not raised to 24 (a full diurnal cycle) on purpose: at one bucket an
#: hour, 24 would surrender the first day of every new scenario, and the
#: drop conjunction is what guards a short pool, not the sample count.
BGP_WARMUP_MIN_SAMPLES = BGP_HOD_MIN_SAMPLES

#: `bgp_routing.py:70` — `max(std, 1.0)`, applied after the square root.
BGP_WARMUP_STD_FLOOR = BGP_HOD_STD_FLOOR

#: Widened from `BGP_HOD_ANOMALY_Z` (-2.0) by the pooling argument above.
#: -3.0 is not a new number in this system: it is what production calls a
#: BLACKOUT on the same statistic (`CHECKHOST_BLACKOUT_Z`,
#: `checkhost.py:265`) — the stricter tier of the same ladder.
BGP_WARMUP_ANOMALY_Z = -3.0

#: `BgpRoutingSensor.BGP_DROP_THRESHOLD` (`bgp_routing.py:23`), used by
#: production in EXACTLY this branch (`:74`). v3 changes what the drop is
#: measured against — the ledger's pooled mean instead of a dict in
#: memory — and keeps the threshold and the shape.
BGP_WARMUP_DROP_THRESHOLD = 0.15


@dataclass(frozen=True, slots=True)
class WarmupStat:
    """A warm-up reading, with both guards readable (NP6, AP2).

    `valid` False means WITHHELD, not "no anomaly", and `n` says which of
    the two silences it is: 0 samples is a ledger with no history for this
    country at all, and anything below `BGP_WARMUP_MIN_SAMPLES` is a
    ledger with some. G-17 is what happens when those read alike.
    """

    anomaly: bool
    valid: bool
    n: int
    z: Optional[float] = None
    drop_ratio: Optional[float] = None
    mean: Optional[float] = None


def bgp_warmup_verdict(pooled: Sequence[float], prefixes: float
                       ) -> WarmupStat:
    """The pooled-series verdict, for use ONLY while the warm path is cold.

    Both guards must agree. `drop_ratio` is `(mean - now) / mean`, which
    is production's `(pfx_base - pfx_now) / pfx_base` with `pfx_base`
    supplied by L1; a non-positive mean yields no ratio at all rather than
    a zero, because a zero there is a claim that nothing dropped.
    """
    stat = phase_zscore(pooled, prefixes,
                        min_samples=BGP_WARMUP_MIN_SAMPLES,
                        std_floor=BGP_WARMUP_STD_FLOOR)
    if not stat.valid or stat.z is None or stat.mean is None:
        return WarmupStat(anomaly=False, valid=False, n=stat.n)
    if stat.mean > 0:
        drop_ratio = max(0.0, (stat.mean - prefixes) / stat.mean)
    else:
        drop_ratio = None
    anomaly = bool(stat.z < BGP_WARMUP_ANOMALY_Z
                   and drop_ratio is not None
                   and drop_ratio > BGP_WARMUP_DROP_THRESHOLD)
    return WarmupStat(anomaly=anomaly, valid=True, n=stat.n, z=stat.z,
                      drop_ratio=drop_ratio, mean=stat.mean)


# ── check_host (`radar/sensors/checkhost.py:247-269`, core.py:1373) ─────

CHECKHOST_HOD_MIN_SAMPLES = 7
CHECKHOST_HOD_STD_FLOOR = 0.05
CHECKHOST_BLACKOUT_Z = -3.0
CHECKHOST_BLACKOUT_RATE = 0.3
CHECKHOST_PARTIAL_Z = -2.0
CHECKHOST_PARTIAL_RATE = 0.8
CHECKHOST_BLACKOUT = "BLACKOUT"
CHECKHOST_PARTIAL = "PARTIAL"
CHECKHOST_OK = "OK"
#: `core.py:1372` — PARTIAL is capped at +1 for maskirovka consistency.
CHECKHOST_SCORES = {CHECKHOST_BLACKOUT: 3.0, CHECKHOST_PARTIAL: 1.0,
                    CHECKHOST_OK: 0.0}


def checkhost_status(success_rate: float, stat: PhaseStat) -> str:
    """The four-line ladder, Z-normalised branch and warm-up branch both.

    The warm-up thresholds are NOT the Z branch with a different constant:
    they are absolute rates (`>=0.8` OK, `>=0.3` PARTIAL, else BLACKOUT),
    and the Z branch additionally requires the absolute rate to be low.
    A country whose success rate drops from 100% to 95% at an hour when it
    is normally 100% is anomalous and still OK — that conjunction is what
    keeps a routine maintenance window out of the ledger.
    """
    if not stat.valid or stat.z is None:
        if success_rate >= CHECKHOST_PARTIAL_RATE:
            return CHECKHOST_OK
        if success_rate >= CHECKHOST_BLACKOUT_RATE:
            return CHECKHOST_PARTIAL
        return CHECKHOST_BLACKOUT
    if stat.z < CHECKHOST_BLACKOUT_Z and success_rate < CHECKHOST_BLACKOUT_RATE:
        return CHECKHOST_BLACKOUT
    if stat.z < CHECKHOST_PARTIAL_Z and success_rate < CHECKHOST_PARTIAL_RATE:
        return CHECKHOST_PARTIAL
    return CHECKHOST_OK


# ── check_host asphyxiation (`checkhost.py:138-155`) ────────────────────

#: `LATENCY_MIN_SAMPLES` on the adapter, which already owns the
#: predicate — this module supplies the history it was written to take.
ASPHYXIATION_MIN_SAMPLES = _check_host.LATENCY_MIN_SAMPLES


def rolling_latency(history: Sequence[float]) -> Optional[float]:
    """The average of the samples BEFORE this reading (`checkhost.py:152`).

    None below three samples, which is the value `is_asphyxiation` reads as
    "no baseline yet" — a spike that included itself would lift its own
    baseline and shrink the ratio meant to detect it.
    """
    if len(history) < ASPHYXIATION_MIN_SAMPLES:
        return None
    return sum(history) / len(history)


def is_asphyxiation(success_rate: Optional[float],
                    latency_ms: Optional[float],
                    history: Sequence[float]) -> bool:
    """Every node answers, and answers far slower than this URL's normal."""
    return _check_host.is_asphyxiation(success_rate, latency_ms,
                                       rolling_latency(history))


# ── gdelt day-of-week (`radar/sensors/gdelt.py:66-77`, core.py:1131) ────

GDELT_DOW_MIN_SAMPLES = 3
GDELT_DOW_STD_FLOOR = 0.5
GDELT_DOW_ALERT_Z = -2.0


def gdelt_dow_alert(stat: PhaseStat) -> bool:
    """The Z arm of `is_alert`'s OR. The fixed arm fires in the adapter."""
    return bool(stat.valid and stat.z is not None
                and stat.z < GDELT_DOW_ALERT_Z)


# ── ct_log (`radar/sensors/ct_log.py:273-341`, core.py:1836-1848) ───────

CT_LOG_WARMUP_DAYS = _ct_log.WARMUP_DAYS
CT_LOG_UNTRUSTED_SCORE = 3.0
CT_LOG_WILDCARD_SCORE = 2.0


def ct_log_in_warmup(first_observed: Optional[float], now: float, *,
                     warmup_days: float = CT_LOG_WARMUP_DAYS) -> bool:
    """A domain first seen less than `warmup_days` ago is still learning.

    An unknown domain (`first_observed is None`) is IN warm-up: the first
    cycle that ever looks at a domain would otherwise report every CA it
    has as untrusted, which is the false-positive avalanche the warm-up
    exists to prevent (`ct_log.py:273-275`).
    """
    if first_observed is None:
        return True
    return (now - first_observed) < warmup_days * 86400.0


def ct_log_untrusted(candidates: Sequence[dict], known_cas: Sequence[str], *,
                     in_warmup: bool) -> tuple:
    """Candidates that are neither globally trusted nor known here.

    The adapter has already applied the global-trust test — what arrives
    is its `untrusted_ca_candidates`. What is added is the second half
    production applies (`ct_log.py:315-341`): a CA this DOMAIN has used
    before is not an anomaly even if no global list names it, and nothing
    fires at all while the domain is in warm-up.
    """
    if in_warmup:
        return ()
    known = {str(name).strip().lower() for name in known_cas}
    return tuple(candidate for candidate in candidates
                 if str(candidate.get("ca_normalized", "")).strip().lower()
                 not in known)


# ── ais dark gaps (`radar/sensors/ais_maritime.py:112-125`) ─────────────

AIS_DARK_GAP_THRESHOLD_SEC = _ais.DARK_GAP_THRESHOLD_SEC
AIS_ANCHOR_RADIUS_KM = _ais.ANCHOR_RADIUS_KM


def ais_dark_gaps(reports: Sequence[dict], previous, now: float, *,
                  gap_threshold_sec: float = AIS_DARK_GAP_THRESHOLD_SEC,
                  anchor_radius_km: float = AIS_ANCHOR_RADIUS_KM) -> tuple:
    """Hulls that went quiet for an hour and are near the chokepoint.

    `previous` is `{mmsi: last_ts}` from the prior cycle. A vessel with no
    prior snapshot produces NOTHING: production reads
    `self._vessel_history.get(mmsi)` and skips on a miss (`:113-115`), so a
    first sighting is not a gap. Treating an unknown vessel as a gap would
    make the first cycle after any restart a fleet-wide dark-gap alert.
    """
    gaps = []
    for report in reports:
        mmsi = str(report.get("mmsi", ""))
        if not mmsi or mmsi not in previous:
            continue
        distance = report.get("dist_km")
        if distance is None:
            continue
        gap_sec = now - float(previous[mmsi])
        if gap_sec > gap_threshold_sec and float(distance) < anchor_radius_km:
            gaps.append({"mmsi": mmsi, "gap_sec": round(gap_sec, 1),
                         "lat": report.get("lat"), "lng": report.get("lng"),
                         "dist_km": report.get("dist_km")})
    return tuple(gaps)


__all__ = ["PhaseStat", "phase_zscore", "bgp_hod_verdict", "bgp_is_anomaly",
           "WarmupStat", "bgp_warmup_verdict", "BGP_WARMUP_MIN_SAMPLES",
           "BGP_WARMUP_STD_FLOOR", "BGP_WARMUP_ANOMALY_Z",
           "BGP_WARMUP_DROP_THRESHOLD",
           "checkhost_status", "is_asphyxiation", "gdelt_dow_alert",
           "ct_log_in_warmup", "ct_log_untrusted", "ais_dark_gaps",
           "BGP_HOD_MIN_SAMPLES", "BGP_HOD_STD_FLOOR", "BGP_HOD_ANOMALY_Z",
           "BGP_ANOMALY_SCORE", "CHECKHOST_HOD_MIN_SAMPLES",
           "CHECKHOST_HOD_STD_FLOOR", "CHECKHOST_SCORES", "CHECKHOST_OK",
           "CHECKHOST_PARTIAL", "CHECKHOST_BLACKOUT",
           "GDELT_DOW_MIN_SAMPLES", "GDELT_DOW_STD_FLOOR",
           "GDELT_DOW_ALERT_Z", "CT_LOG_WARMUP_DAYS", "CT_LOG_UNTRUSTED_SCORE",
           "CT_LOG_WILDCARD_SCORE", "ASPHYXIATION_MIN_SAMPLES",
           "rolling_latency",
           "AIS_DARK_GAP_THRESHOLD_SEC", "AIS_ANCHOR_RADIUS_KM"]
