"""Persistent baselines, updated only by an explicit job.

A-03: the current system keeps several baselines in process memory
(`_baseline_tg`, `_baseline`, `_baseline_tg` class dicts), so every
restart is a silent reset that nothing reports. Here the only storage is
the `baseline_stat` table.

F-05 / S5-VERIF-019 is the other half: statistics must move in a stage
that is separate from reading. `fold_observations` is called by a job with
the observations it wants folded in; it never reads the ledger to decide
for itself, and no read path calls it. There is deliberately no
module-level cache here — a test asserts that too, because a cache is how
"persistent" quietly becomes "persistent plus a stale copy".
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Iterable, Optional

from v3.kernel import Window
from v3.kernel.errors import DomainError
from v3.ledger.records import SignalObservation

if TYPE_CHECKING:
    from v3.ledger.store import LedgerStore


def _welford(count: int, mean: float, m2: float,
             value: float) -> tuple[int, float, float]:
    """One online-variance step. Pure — the caller owns the persistence.

    Forward note: folding two independently accumulated baselines (a
    parallel or sharded job) needs Chan's parallel merge, not repeated
    application of this step. Adding that is a change of job shape, not of
    this function.
    """
    count += 1
    delta = value - mean
    mean += delta / count
    m2 += delta * (value - mean)
    return (count, mean, m2)


def fold_observations(store: "LedgerStore",
                      observations: Iterable[SignalObservation], *,
                      baseline_id: str, window: Optional[Window] = None,
                      now: Optional[float] = None, bucket: int = 0) -> int:
    """Fold observations into `baseline_id`. Returns rows touched.

    **The statistic is CUMULATIVE.** Welford accumulates over every
    observation ever folded in; nothing here expires old samples. So:

      * `window_days` / `cadence_sec` record the window this baseline was
        *initialised for*. They are metadata for the reader, NOT a promise
        that the statistic is a rolling window over that span. Reading
        them as a guarantee would be F-06 in a new place — a declared
        window that the mechanism does not actually hold.
      * Whether a baseline should be windowed, decayed, or reset is L2's
        decision (it depends on what the score is for), so this layer
        stores what it is told and says plainly what that means.

    The whole fold runs in one transaction: the read-modify-write of each
    row would otherwise be open to a lost update, and a failure halfway
    would leave some counters advanced and others not.
    """
    if not isinstance(baseline_id, str) or not baseline_id.strip():
        raise DomainError("baseline_id must be a non-empty string")
    if window is not None and not isinstance(window, Window):
        raise TypeError(
            f"window must be a kernel Window, got {type(window).__name__}: a "
            f"bare number cannot say what cadence it assumes (F-06)")

    ts = time.time() if now is None else now
    touched = 0
    with store.transaction() as connection:
        touched = _fold_all(connection, observations, baseline_id=baseline_id,
                            window=window, ts=ts, bucket=bucket)
    return touched


def _fold_all(connection, observations, *, baseline_id, window, ts,
              bucket) -> int:
    touched = 0
    for observation in observations:
        if not isinstance(observation, SignalObservation):
            raise TypeError(
                f"baseline updates take SignalObservation values, got "
                f"{type(observation).__name__}")
        if observation.raw_score is None:
            continue
        row = connection.execute(
            "SELECT sample_count, mean, m2 FROM baseline_stat "
            "WHERE baseline_id = ? AND sensor = ? AND country = ? "
            "AND bucket = ?",
            (baseline_id, observation.sensor, observation.country,
             bucket)).fetchone()
        count, mean, m2 = (0, 0.0, 0.0) if row is None else (
            int(row["sample_count"]), float(row["mean"]), float(row["m2"]))
        count, mean, m2 = _welford(count, mean, m2, observation.raw_score)

        connection.execute(
            "INSERT INTO baseline_stat (baseline_id, sensor, country, bucket, "
            " sample_count, mean, m2, window_days, cadence_sec, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT (baseline_id, sensor, country, bucket) DO UPDATE SET "
            "  sample_count = excluded.sample_count, mean = excluded.mean, "
            "  m2 = excluded.m2, window_days = excluded.window_days, "
            "  cadence_sec = excluded.cadence_sec, "
            "  updated_at = excluded.updated_at",
            (baseline_id, observation.sensor, observation.country, bucket,
             count, mean, m2,
             None if window is None else window.declared_days,
             None if window is None else window.cadence_sec, ts))
        touched += 1
    return touched


__all__ = ["fold_observations"]
