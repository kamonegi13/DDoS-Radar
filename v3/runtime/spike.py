"""`avg_spike` — the DDoS attack-origin spike, and the verdict it feeds.

§7-2 #9's last withheld member and §7-2 #116 were waiting on the same
absence, and it was not a wiring gap: `CLOUDFLARE_RADAR_ADAPTER` declared
four requests and none of them was the per-target attack-ORIGIN
distribution, so the quantity production ranks and judges by had no input
in v3 at all. The adapter now declares it; this module is what the numbers
become.

Five computations, all pure, all taking their history as an argument:

  `origin_spike`   `radar/routes/core.py:763-817`. One target's current
                   L3/L7 origin distributions against that target's
                   baseline distributions, weighted by how much traffic
                   each origin accounts for.
  `spike_verdict`  `radar/routes/core.py:1006-1018`. The hour-of-day
                   Z-score ladder, warm-up branch included, that
                   `cf_spike_core` had been reporting OBSERVED/0.0 in
                   place of.
  the three derived rows — `vector_shift_verdict` (`:1063-1070`),
                   `adversary_strike_verdict` (`:1071-1075`) and
                   `coordinated_verdict` (`:863-864`, `:1076`). §7-2 #121:
                   production makes FOUR entries out of one origin
                   distribution and v3 shipped one. No extra fetch was
                   needed for the other three — every quantity they read
                   was already on `OriginSpike`, or is here now because it
                   needs the unrounded ratio (`shift_actors`, `strikes`).

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

#: `core.py:783` — `min(max(l3_spike, l7_spike), 25.0)`.
SPIKE_CAP = 25.0
#: `core.py:788` — `current_local_pct >= 1.0`.
INCLUSION_PCT = 1.0
#: `core.py:812,817` — `max(total_local_pct, 5.0)`.
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

#: `core.py:802` — the PER-ORIGIN L7 shift. Computed from the UNROUNDED
#: ratios, which is why it is decided in `origin_spike` beside them rather
#: than downstream from the rounded copies on the row.
PER_ORIGIN_L7_MIN = 2.5
PER_ORIGIN_L7_RATIO = 1.5
PER_ORIGIN_L7_PCT_MIN = 1.5
#: `core.py:798` — an adversary origin's DIRECT strike: adversary origin,
#: strategic target, and BOTH a ratio and an absolute floor. The absolute
#: floor is what stops a 0.5%-floored adversary reading as a strike on
#: traffic nobody would notice.
STRIKE_SPIKE_MIN = 4.0
STRIKE_PCT_MIN = 3.0
#: `core.py:745` — the global target share is floored before it multiplies,
#: so a target absent from Cloudflare's global list still has a weight.
GLOBAL_SHARE_FLOOR = 0.1
#: `core.py:806` — an origin enters `combined_sources` (and only then can
#: it be counted as a `shift_actor`, `core.py:813`) on either its global
#: weight or on being a direct strike.
COMBINED_WEIGHT_MIN = 0.01
#: `core.py:814` — the TARGET-level vector shift, on the unrounded means.
VECTOR_L7_MIN = 2.5
VECTOR_L7_RATIO = 1.5

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

    `is_vector_shift`, `shift_actors` and `strikes` are the three
    per-target facts the derived rows are built from (`core.py:813-815`,
    `:798-799`). They are decided HERE because each reads the UNROUNDED
    ratio, and the row carries the rounded copy: recomputing them from the
    row would compare `2.4999` against `2.5` as `2.50`.
    """

    avg_spike: float
    avg_l3_spike: float
    avg_l7_spike: float
    total_local_pct: float
    has_baseline: bool
    origins: Mapping[str, dict]
    #: `core.py:814`.
    is_vector_shift: bool = False
    #: `core.py:813` — origins flagged `is_l7_shift` that also made it into
    #: `combined_sources`. Sorted where production's set iteration is not.
    shift_actors: tuple[str, ...] = ()
    #: `core.py:799` minus the `target` key, which only the caller knows.
    strikes: tuple[Mapping[str, object], ...] = ()


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
                 adversaries: Sequence[str] = (),
                 global_l3_pct: float = 0.0,
                 global_l7_pct: float = 0.0) -> OriginSpike:
    """`core.py:763-817`, transcribed. The traffic-weighted mean spike.

    `global_l3_pct` / `global_l7_pct` are this TARGET's share of world
    attack traffic (`core.py:744`, from the `top/locations/target`
    endpoints v3 already fetches as `cf_l3` / `cf_l7`). They are only
    read to decide which origins enter `combined_sources`
    (`core.py:806`), which is what makes an origin eligible to be a
    `shift_actor`. Defaulting to 0.0 is production's own default —
    `g_l3.get(t, 0.0)` at `core.py:744` — and not a guess: the floor at
    `core.py:745` then lifts it to `GLOBAL_SHARE_FLOOR`.

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
    # `core.py:745` — display value floored before it multiplies.
    share_l3 = max(float(global_l3_pct), GLOBAL_SHARE_FLOOR)
    share_l7 = max(float(global_l7_pct), GLOBAL_SHARE_FLOOR)

    weighted = 0.0
    l3_sum = 0.0
    l7_sum = 0.0
    total_local_pct = 0.0
    working: dict = {}
    shift_actors: list[str] = []
    strikes: list[dict] = []
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
        # `core.py:794-795`. The percentages are shares, hence /100.
        global_weight = (share_l3 * (local_l3 / 100.0)
                         + share_l7 * (local_l7 / 100.0))
        # `core.py:798`. The `t in strategic_theaters_set` conjunct is not
        # transcribed: every country this fold sees is a participant of a
        # scored scenario, and production's `strategic_theaters` IS the
        # focused scenario's participant list (`radar/scenarios.py:604`),
        # so the test is satisfied by construction. §7-2 #118 is where the
        # widened SET is registered.
        is_direct_strike = (code in adversary_set
                            and spike_factor >= STRIKE_SPIKE_MIN
                            and current_local_pct > STRIKE_PCT_MIN)
        # `core.py:802`, on the unrounded ratios.
        is_l7_shift = (l7_spike >= PER_ORIGIN_L7_MIN
                       and l7_spike > l3_spike * PER_ORIGIN_L7_RATIO
                       and local_l7 > PER_ORIGIN_L7_PCT_MIN)
        # `core.py:806` — membership in `combined_sources`, which
        # `core.py:813` then filters for `is_l7_shift`.
        in_combined = global_weight > COMBINED_WEIGHT_MIN or is_direct_strike
        if in_combined and is_l7_shift:
            shift_actors.append(code)
        if is_direct_strike:
            # `core.py:799`'s record, minus `target`: this function is
            # given one target's distributions and never told which.
            strikes.append({"actor": code,
                            "spike": round(spike_factor, 1),
                            "pct": round(current_local_pct, 1)})
        working[code] = {
            "l3_pct": local_l3, "l7_pct": local_l7,
            "local_pct": current_local_pct,
            "l3_spike": round(l3_spike, 2), "l7_spike": round(l7_spike, 2),
            "spike_factor": round(spike_factor, 2),
            "is_new_actor": code not in baseline_l3 and code not in baseline_l7,
            "is_adversary": code in adversary_set,
            "is_l7_shift": is_l7_shift,
            "is_direct_strike": is_direct_strike,
            "in_combined_sources": in_combined,
            "counted": counted}

    denominator = max(total_local_pct, DENOMINATOR_FLOOR)
    avg_l3_spike = l3_sum / denominator
    avg_l7_spike = l7_sum / denominator
    # `core.py:814` — the disjunction, on the UNROUNDED means.
    is_vector_shift = ((avg_l7_spike >= VECTOR_L7_MIN
                        and avg_l7_spike > avg_l3_spike * VECTOR_L7_RATIO)
                       or len(shift_actors) > 0)
    return OriginSpike(
        avg_spike=round(weighted / denominator, ROUND_DIGITS),
        avg_l3_spike=avg_l3_spike,
        avg_l7_spike=avg_l7_spike,
        total_local_pct=total_local_pct,
        has_baseline=has_baseline,
        origins=working,
        is_vector_shift=is_vector_shift,
        shift_actors=tuple(shift_actors),
        strikes=tuple(strikes))


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


# ── the three derived rows (§7-2 #121) ──────────────────────────────────
#
# `cf_spike_core` was never the only thing production makes of the origin
# distribution. Three more entries come off the SAME numbers, and until
# now v3 emitted none of them.
#
# All three are decided ONCE per cycle, not per country, and none of them
# is attributed to a country — nor is `cf_spike_core` itself, since §7-2
# #118's retirement. See `v3/runtime/reduce_cyber.py::_derived_rows` for
# the production line that settles all four.

#: `core.py:1066` — the severe branch. BOTH conditions, on the primary
#: core's ROUNDED means (`core.py:1064-1065` reads `target_details`, which
#: holds `round(avg_l7_spike, 2)` — `core.py:831`).
SEVERE_L7_MIN = 5.0
SEVERE_L7_RATIO = 2.0
#: `core.py:1067` — `2 if severe else (1 if core_shifted else 0)`.
SEVERE_SHIFT_SCORE = 2.0
SHIFT_SCORE = 1.0
#: `core.py:1073` — `3 if count >= 3 else (2 if count >= 1 else 0)`. The
#: count is of STRIKES, not of distinct actors, however the reason string
#: at `core.py:1075` words it.
STRIKE_MANY = 3
STRIKE_MANY_SCORE = 3.0
STRIKE_ANY_SCORE = 2.0
#: `core.py:863` — a target counts as elevated STRICTLY above this.
ELEVATED_SPIKE_MIN = 3.0
#: `core.py:864` — two elevated targets is what "coordinated" means.
COORDINATED_MIN = 2
#: `core.py:1076` — one point, flat.
COORDINATED_SCORE = 1.0


@dataclass(frozen=True, slots=True)
class DerivedVerdict:
    """What one derived `add_rat` call is given. Same four fields each."""

    fired: bool
    score: float
    value: str
    reason: str


def vector_shift_verdict(*, shifted_targets: Sequence[str],
                         core_shifted: bool,
                         core_l7_spike: float,
                         core_l3_spike: float) -> DerivedVerdict:
    """`cf_vector_shift` — `core.py:1063-1070`, transcribed.

    Two different countries can decide this row. The STATUS comes from
    whether any effective core shifted (`core.py:877`/`:886`); the SEVERITY
    comes from the primary core's own means (`core.py:1064-1065`), and in
    a dual-core scenario production can therefore report severity for a
    core that did not shift. Reproduced rather than repaired: the
    difference would be a v3 verdict production never gives.
    """
    severe = (core_shifted
              and core_l7_spike >= SEVERE_L7_MIN
              and core_l7_spike > core_l3_spike * SEVERE_L7_RATIO)
    score = SEVERE_SHIFT_SCORE if severe else (
        SHIFT_SCORE if core_shifted else 0.0)
    if severe:
        reason = (f"Severe L7 escalation (L7={core_l7_spike:.1f}x vs "
                  f"L3={core_l3_spike:.1f}x)")
    elif core_shifted:
        reason = "L7 application-layer escalation detected"
    else:
        reason = ""
    return DerivedVerdict(
        fired=core_shifted, score=score,
        value=(f"theaters={list(shifted_targets)} "
               f"L7={core_l7_spike:.1f}x L3={core_l3_spike:.1f}x"),
        reason=reason)


def adversary_strike_verdict(strikes: Sequence[Mapping]) -> DerivedVerdict:
    """`cf_adversary_strike` — `core.py:1071-1075`, transcribed.

    `major_adversary` (`core.py:919`) is `len(adversary_strikes) > 0`, the
    same test the score's lowest rung uses, so status and score cannot
    disagree.
    """
    count = len(strikes)
    score = STRIKE_MANY_SCORE if count >= STRIKE_MANY else (
        STRIKE_ANY_SCORE if count >= 1 else 0.0)
    return DerivedVerdict(
        fired=count > 0, score=score, value=f"{count} strike(s)",
        reason=(f"Adversary state direct strike ({count} actors)"
                if count > 0 else ""))


def elevated_targets(avg_spikes: Mapping[str, float]) -> tuple[str, ...]:
    """`core.py:863` — the strategic targets above the elevation floor.

    Sorted where production iterates a set. A function rather than a
    comprehension at the call site so that `ELEVATED_SPIKE_MIN` is read at
    call time and a mutation of it is a test failure, not a silent
    recalibration.
    """
    return tuple(sorted(country for country, avg_spike in avg_spikes.items()
                        if avg_spike > ELEVATED_SPIKE_MIN))


def coordinated_verdict(elevated: Sequence[str]) -> DerivedVerdict:
    """`cf_coordinated` — `core.py:863-864` and `:1076`, transcribed."""
    fired = len(elevated) >= COORDINATED_MIN
    return DerivedVerdict(
        fired=fired, score=COORDINATED_SCORE if fired else 0.0,
        value=f"theaters={list(elevated)}",
        reason="Simultaneous surge" if fired else "")


__all__ = ["OriginSpike", "SpikeVerdict", "DerivedVerdict", "origin_spike",
           "spike_verdict", "vector_shift_verdict",
           "adversary_strike_verdict", "coordinated_verdict",
           "elevated_targets",
           "SPIKE_CAP", "INCLUSION_PCT", "DENOMINATOR_FLOOR",
           "ADVERSARY_FLOOR", "NEW_ACTOR_FLOOR", "EXISTING_ACTOR_FLOOR",
           "ROUND_DIGITS", "HOD_MIN_SAMPLES", "HOD_STD_FLOOR",
           "Z_THRESHOLDS", "WARMUP_THRESHOLDS",
           "PER_ORIGIN_L7_MIN", "PER_ORIGIN_L7_RATIO", "PER_ORIGIN_L7_PCT_MIN",
           "STRIKE_SPIKE_MIN", "STRIKE_PCT_MIN", "GLOBAL_SHARE_FLOOR",
           "COMBINED_WEIGHT_MIN", "VECTOR_L7_MIN", "VECTOR_L7_RATIO",
           "SEVERE_L7_MIN", "SEVERE_L7_RATIO", "SEVERE_SHIFT_SCORE",
           "SHIFT_SCORE", "STRIKE_MANY", "STRIKE_MANY_SCORE",
           "STRIKE_ANY_SCORE", "ELEVATED_SPIKE_MIN", "COORDINATED_MIN",
           "COORDINATED_SCORE"]
