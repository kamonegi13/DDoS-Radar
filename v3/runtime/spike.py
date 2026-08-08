"""`avg_spike` — the DDoS attack-origin spike, and the verdict it feeds.

§7-2 #9's last withheld member and §7-2 #116 were waiting on the same
absence, and it was not a wiring gap: `CLOUDFLARE_RADAR_ADAPTER` declared
four requests and none of them was the per-target attack-ORIGIN
distribution, so the quantity production ranks and judges by had no input
in v3 at all. The adapter now declares it; this module is what the numbers
become.

Two computations, both pure, both taking their history as an argument:

  `origin_spike`   `radar/routes/core.py:762-817`. One target's current
                   L3/L7 origin distributions against that target's
                   baseline distributions, weighted by how much traffic
                   each origin accounts for.
  `spike_verdict`  `radar/routes/core.py:1006-1018`. The hour-of-day
                   Z-score ladder, warm-up branch included, that
                   `cf_spike_core` had been reporting OBSERVED/0.0 in
                   place of.

**The baseline is a QUERY WINDOW, not an accumulation.** The register
called it a 90-day origin baseline; `radar/config.py:148` ships
`BASELINE_DATE_RANGE` as `28d`, and production obtains it by asking
Cloudflare the same question over the longer range
(`core.py:740-741`), storing the answer per target and refreshing it when
it is over a day old. So nothing here accumulates a series — the window
travels on the wire, and the ledger holds one snapshot.

**Four constants decide whether a small attack is visible at all**, and
each is a module-level name rather than a literal because that is what
makes a mutation of one of them a test failure rather than a quiet
recalibration:

  * `SPIKE_CAP` — 25x. Above it, statistical noise on a tiny baseline
    would dominate the weighted average.
  * `INCLUSION_PCT` — an origin below 1% of the target's traffic does not
    aggregate at all, however large its ratio.
  * `DENOMINATOR_FLOOR` — 5%. Without it a single 1% origin at 2x reports
    2x for the whole country.
  * the floors — `ADVERSARY_FLOOR` (0.5) against
    `NEW_ACTOR_FLOOR`/`EXISTING_ACTOR_FLOOR` (3.0/2.0). This is the
    asymmetry that lets KP going from 0.1% to 2% read as a 4x spike while
    the same movement from an ordinary origin reads as nothing. Raising
    the adversary floor is the single most insensitive edit available in
    this file, so `tests/test_runtime_cf_spike.py` mutates it explicitly.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Container, Mapping, Optional, Sequence

from v3.runtime.verdicts import PhaseStat, phase_zscore

#: `core.py:786` — `min(max(l3_spike, l7_spike), 25.0)`.
SPIKE_CAP = 25.0
#: `core.py:790` — `current_local_pct >= 1.0`.
INCLUSION_PCT = 1.0
#: `core.py:811,817` — `max(total_local_pct, 5.0)`.
DENOMINATOR_FLOOR = 5.0
#: `core.py:775-777` — adversary states use a lower floor so that even a
#: small absolute movement registers; everyone else is held to a higher
#: one so that ordinary commodity-cloud noise does not.
ADVERSARY_FLOOR = 0.5
NEW_ACTOR_FLOOR = 3.0
EXISTING_ACTOR_FLOOR = 2.0
#: `core.py:817` — the recorded value is rounded, and it is the ROUNDED
#: value that is compared against the hour-of-day baseline and that ranks
#: the chain owner, so the rounding is part of the arithmetic.
ROUND_DIGITS = 2

#: `radar/config.py:337` — `HOD_MIN_SAME_HOUR`.
HOD_MIN_SAMPLES = 7
#: `radar/scoring.py:496` — the std floor, applied AFTER the square root.
HOD_STD_FLOOR = 0.15
#: `core.py:1009-1010` — 1.5 / 2.5 / 3.5 sigma, one point each.
Z_THRESHOLDS: tuple[float, ...] = (1.5, 2.5, 3.5)
#: `core.py:1015-1016` — the warm-up branch is raw ratios, not a Z with a
#: different constant. Production never withholds while a baseline is
#: cold, and neither does this.
WARMUP_THRESHOLDS: tuple[float, ...] = (2.0, 4.0, 6.0)


@dataclass(frozen=True, slots=True)
class OriginSpike:
    """One target's spike, with everything that produced it (NP6).

    `origins` is the per-origin working — the ratio each origin reached,
    the floor it was held to, and whether it appeared in the baseline at
    all. Published because "TW is at 8.4x" is not a checkable claim and
    "TW is at 8.4x because CN went from 4% to 40%" is.
    """

    avg_spike: float
    avg_l3_spike: float
    avg_l7_spike: float
    total_local_pct: float
    has_baseline: bool
    origins: Mapping[str, dict]


def _floors(code: str, adversaries: Container[str]) -> tuple[float, float]:
    """`(new-actor floor, existing-actor floor)` for one origin."""
    if code in adversaries:
        return ADVERSARY_FLOOR, ADVERSARY_FLOOR
    return NEW_ACTOR_FLOOR, EXISTING_ACTOR_FLOOR


def _baseline_for(code: str, baseline: Mapping[str, float],
                  floor_new: float, floor_exist: float) -> float:
    """`max(b.get(code, floor_new), floor_new if absent else floor_exist)`.

    Production writes it as one expression whose two arms collapse
    differently: an origin ABSENT from the baseline reduces to
    `max(floor_new, floor_new)` — the floor itself — while one PRESENT at
    0.4% is held up to the (lower) existing-actor floor. Written as two
    branches here because `max(x, x)` reads as a mistake; the arithmetic
    is identical and the sweep in `tests/test_runtime_cf_spike.py` runs
    both against a re-typing of production's single expression.
    """
    if code not in baseline:
        return floor_new
    return max(float(baseline[code]), floor_exist)


def origin_spike(*, current_l3: Mapping[str, float],
                 current_l7: Mapping[str, float],
                 baseline_l3: Mapping[str, float],
                 baseline_l7: Mapping[str, float],
                 adversaries: Sequence[str] = ()) -> OriginSpike:
    """`core.py:762-817`, transcribed. The traffic-weighted mean spike.

    **The empty-baseline guard is load-bearing** (`core.py:762-765`): with
    no baseline every origin falls to the minimum floor, so a routine
    distribution reads as a 90x event. Production skips the aggregation
    entirely and reports 0.0, and so does this — reported as 0.0 with
    `has_baseline=False` beside it, never as a withheld verdict, because
    production emits the row either way and a v3 that withheld here would
    be the insensitive difference §7-2 #9 is about.

    Iteration is over a SORTED set where production iterates a plain set:
    float addition is not associative, and a replay has to reproduce the
    number it is replaying.
    """
    adversary_set = {str(code).upper() for code in adversaries}
    current_l3 = dict(current_l3 or {})
    current_l7 = dict(current_l7 or {})
    baseline_l3 = dict(baseline_l3 or {})
    baseline_l7 = dict(baseline_l7 or {})
    has_baseline = bool(baseline_l3 or baseline_l7)

    weighted = 0.0
    l3_sum = 0.0
    l7_sum = 0.0
    total_local_pct = 0.0
    working: dict = {}
    for code in sorted(set(current_l3) | set(current_l7)):
        local_l3 = float(current_l3.get(code, 0.0))
        local_l7 = float(current_l7.get(code, 0.0))
        current_local_pct = max(local_l3, local_l7)
        floor_new, floor_exist = _floors(code, adversary_set)
        base_l3 = _baseline_for(code, baseline_l3, floor_new, floor_exist)
        base_l7 = _baseline_for(code, baseline_l7, floor_new, floor_exist)
        l3_spike = (local_l3 / base_l3) if local_l3 > 0 else 0.0
        l7_spike = (local_l7 / base_l7) if local_l7 > 0 else 0.0
        spike_factor = min(max(l3_spike, l7_spike), SPIKE_CAP)
        counted = has_baseline and current_local_pct >= INCLUSION_PCT
        if counted:
            weighted += spike_factor * current_local_pct
            l3_sum += l3_spike * current_local_pct
            l7_sum += l7_spike * current_local_pct
            total_local_pct += current_local_pct
        working[code] = {
            "l3_pct": local_l3, "l7_pct": local_l7,
            "l3_spike": round(l3_spike, 2), "l7_spike": round(l7_spike, 2),
            "spike_factor": round(spike_factor, 2),
            "is_new_actor": code not in baseline_l3 and code not in baseline_l7,
            "is_adversary": code in adversary_set,
            "counted": counted}

    denominator = max(total_local_pct, DENOMINATOR_FLOOR)
    return OriginSpike(
        avg_spike=round(weighted / denominator, ROUND_DIGITS),
        avg_l3_spike=l3_sum / denominator,
        avg_l7_spike=l7_sum / denominator,
        total_local_pct=total_local_pct,
        has_baseline=has_baseline,
        origins=working)


@dataclass(frozen=True, slots=True)
class SpikeVerdict:
    """What `add_rat("cf_spike_core", ...)` is given (`core.py:1025`)."""

    score: float
    fired: bool
    value: str
    reason: str
    z: Optional[float]
    valid: bool
    n: int


def spike_verdict(history: Sequence[float], avg_spike: float) -> SpikeVerdict:
    """The hour-of-day ladder (`core.py:1007-1018`), both branches.

    `history` is this target's same-hour readings, oldest first, from L1
    (`baseline_id="hod"`, `sensor="hod_baseline"` — the migrated series
    whose name differs from the adapter's `baseline_refs` entry).

    Below `HOD_MIN_SAMPLES` production does NOT withhold: it falls back to
    raw ratio thresholds. Porting only the Z branch would have replaced
    one silence with another — a target that says nothing for the first
    seven days it is watched.
    """
    stat: PhaseStat = phase_zscore(history, float(avg_spike),
                                   min_samples=HOD_MIN_SAMPLES,
                                   std_floor=HOD_STD_FLOOR)
    if stat.valid and stat.z is not None:
        score = sum(1 for threshold in Z_THRESHOLDS if stat.z > threshold)
        fired = stat.z > Z_THRESHOLDS[0]
        return SpikeVerdict(
            score=float(score), fired=fired,
            value=f"HOD Z={stat.z:.2f} ({avg_spike:.2f}x, n={stat.n})",
            reason=(f"HOD Z-score={stat.z:.2f} — spike anomalous vs "
                    f"same-hour 28d baseline") if fired else "",
            z=stat.z, valid=True, n=stat.n)
    score = sum(1 for threshold in WARMUP_THRESHOLDS if avg_spike > threshold)
    fired = avg_spike > WARMUP_THRESHOLDS[0]
    return SpikeVerdict(
        score=float(score), fired=fired,
        value=f"{avg_spike:.2f}x (HOD warmup {stat.n}/{HOD_MIN_SAMPLES})",
        reason=("Core theater spike exceeds 2x baseline (HOD warmup)"
                if fired else ""),
        z=None, valid=False, n=stat.n)


__all__ = ["OriginSpike", "SpikeVerdict", "origin_spike", "spike_verdict",
           "SPIKE_CAP", "INCLUSION_PCT", "DENOMINATOR_FLOOR",
           "ADVERSARY_FLOOR", "NEW_ACTOR_FLOOR", "EXISTING_ACTOR_FLOOR",
           "ROUND_DIGITS", "HOD_MIN_SAMPLES", "HOD_STD_FLOOR",
           "Z_THRESHOLDS", "WARMUP_THRESHOLDS"]
