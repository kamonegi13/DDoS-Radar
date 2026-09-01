"""Rate-of-change over a score series. One implementation, not two.

D2 A-02: `_linear_regression_slope`, `compute_velocity` and
`compute_acceleration` exist twice — once in `radar/engine.py:241-271` and
once in `radar/scoring.py:1060-1104` — with a comment in the second
politely noting it is "shared with engine.py", which it is not. Only the
scoring copy reaches the served threat level, so that is the one ported,
and it is ported once. P1 §6 discipline 3 says the duplication must be
impossible to construct rather than merely absent.

This module is NOT the O-2 trend conclusion. P6 O-15 gives that to L3's
TREND conclusion (severity-mean deltas over 24h/7d/30d), and
S1-SCORE-036's TL-history state machine is not ported at all. What lives
here is only the score-series derivative that feeds S1-PIPE-026's focused
bonus fold.
"""
from __future__ import annotations

from typing import Sequence

from v3.kernel.errors import DomainError
from v3.scoring.thresholds import (ACCELERATION_BONUS_MAX,
                                   ACCELERATION_BONUS_SCALE,
                                   ACCELERATION_MIN_OBSERVATIONS,
                                   ACCELERATION_MIN_PTS_PER_H2,
                                   VELOCITY_BONUS_CAP, VELOCITY_BONUS_SCALE,
                                   VELOCITY_EPSILON,
                                   VELOCITY_MIN_OBSERVATIONS)

FORMULA_REF = "v3.scoring.trend@S1-SCORE-024"

_SECONDS_PER_HOUR = 3600.0


def linear_regression_slope(xs: Sequence[float],
                            ys: Sequence[float]) -> float:
    """Least-squares slope. Zero for fewer than two points.

    S1-SCORE-024 pins n=0 and n=1 at 0.0 — a slope through one point is
    undefined, and returning anything else would let a single observation
    look like a trend. A zero denominator (every x identical) returns 0.0
    for the same reason.
    """
    if len(xs) != len(ys):
        raise DomainError(
            f"slope needs matching series, got {len(xs)} x-values and "
            f"{len(ys)} y-values")
    n = len(xs)
    if n < 2:
        return 0.0
    sum_x = sum(xs)
    sum_y = sum(ys)
    sum_xy = sum(x * y for x, y in zip(xs, ys))
    sum_xx = sum(x * x for x in xs)
    denominator = n * sum_xx - sum_x * sum_x
    if denominator == 0:
        return 0.0
    return (n * sum_xy - sum_x * sum_y) / denominator


def _split(series: Sequence[tuple[float, float]]) -> tuple[list, list]:
    origin = series[0][0]
    return ([point[0] - origin for point in series],
            [point[1] for point in series])


def velocity(series: Sequence[tuple[float, float]]) -> float:
    """Score change per second, as a regression slope over the window.

    `series` is [(observed_at, score), ...], oldest first. Below four
    observations the answer is 0.0: a slope fitted to three points is
    mostly noise, and this number feeds a scoring bonus.
    """
    if len(series) < VELOCITY_MIN_OBSERVATIONS:
        return 0.0
    xs, ys = _split(series)
    return round(linear_regression_slope(xs, ys), 6)


def acceleration(series: Sequence[tuple[float, float]]) -> float:
    """Change in velocity per second, from consecutive-pair velocities."""
    if len(series) < ACCELERATION_MIN_OBSERVATIONS:
        return 0.0
    velocities: list[tuple[float, float]] = []
    for index in range(1, len(series)):
        span = series[index][0] - series[index - 1][0]
        if span > 0:
            rate = (series[index][1] - series[index - 1][1]) / span
            velocities.append((series[index][0], rate))
    if len(velocities) < 2:
        return 0.0
    xs, ys = _split(velocities)
    return round(linear_regression_slope(xs, ys), 8)


def velocity_bonus(rate: float, accel: float) -> tuple[float, float]:
    """The (velocity, acceleration) bonus pair for S1-PIPE-026's fold.

    Velocity is converted to points-per-hour, halved and clamped to
    +/-1.5 — bounded on purpose, because the bonus feeds a score that
    feeds the next tick's velocity, and an unbounded term there is a
    feedback loop rather than a measurement.

    Acceleration only ever adds: a decelerating scenario is not evidence
    of safety, which is NP1 applied to a derivative.

    None of these constants has an S1 clause (S1-scoring-pipeline §7
    item 5); they are transcribed from radar/scoring.py:1107-1135.
    """
    rate_bonus = 0.0
    if abs(rate) > VELOCITY_EPSILON:
        per_hour = rate * _SECONDS_PER_HOUR
        rate_bonus = round(
            max(-VELOCITY_BONUS_CAP,
                min(per_hour * VELOCITY_BONUS_SCALE, VELOCITY_BONUS_CAP)), 2)

    accel_bonus = 0.0
    if accel > 0:
        per_hour_squared = accel * _SECONDS_PER_HOUR * _SECONDS_PER_HOUR
        if per_hour_squared > ACCELERATION_MIN_PTS_PER_H2:
            accel_bonus = min(
                round(per_hour_squared * ACCELERATION_BONUS_SCALE, 2),
                ACCELERATION_BONUS_MAX)

    return rate_bonus, accel_bonus


__all__ = ["linear_regression_slope", "velocity", "acceleration",
           "velocity_bonus", "FORMULA_REF"]
