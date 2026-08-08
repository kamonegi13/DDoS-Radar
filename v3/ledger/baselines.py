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


def record_bucket_sample(store: "LedgerStore", *, baseline_id: str,
                         sensor: str, country: str, bucket: int, value: float,
                         max_entries: int,
                         now: Optional[float] = None) -> bool:
    """One sample at one bucket, with production's window. Returns written.

    The second half of ruling 1. `baseline_phase_values` transcribes
    production's READ; this transcribes its WRITE, and the write is where
    production's window actually is (`hod_record`,
    `radar/database.py:3173-3191`):

        INSERT OR REPLACE ...
        DELETE ... WHERE theater=? AND hour_bucket NOT IN
            (SELECT hour_bucket ... ORDER BY hour_bucket DESC LIMIT ?)

    Two consequences worth stating rather than discovering later:

      * the cap is a count of BUCKETS per country, not a span of days.
        28 days is what 672 hourly buckets means at one sample an hour;
        a gap in acquisition stretches the span, it does not shorten it.
      * a bucket that already exists at or above the newest one is NOT
        rewritten (`if _last_bucket != _hour_bucket`,
        `bgp_routing.py:64-66`). The hour's sample is its FIRST reading,
        not its last, and a second cycle inside the hour is a no-op.

    Unlike `fold_observations` this stores the value as given: v1 kept a
    raw per-bucket value and computed mean and variance at read time, and
    the migrated rows are that shape. Folding them into Welford instead
    would change the statistic from production's rolling window to an
    unwindowed cumulative one — F-06 at the storage layer.

    Never called from a read path (F-05 / S5-VERIF-019): the caller owns
    the value, and nothing here consults the ledger to invent one.
    """
    if not isinstance(baseline_id, str) or not baseline_id.strip():
        raise DomainError("baseline_id must be a non-empty string")
    if not isinstance(max_entries, int) or max_entries <= 0:
        raise DomainError(
            f"max_entries must be a positive bucket count, got "
            f"{max_entries!r}: a non-positive cap deletes the history it "
            f"is meant to bound")
    bucket = int(bucket)
    newest = store.latest_baseline_bucket(baseline_id, sensor=sensor,
                                          country=country)
    if newest == bucket:
        return False
    ts = time.time() if now is None else now
    with store.transaction() as connection:
        store.upsert_baseline_value(baseline_id=baseline_id, sensor=sensor,
                                    country=country, bucket=bucket,
                                    value=float(value), now=ts,
                                    connection=connection)
        connection.execute(
            "DELETE FROM baseline_stat WHERE baseline_id = ? AND sensor = ? "
            "AND country = ? AND bucket NOT IN ("
            "  SELECT bucket FROM baseline_stat WHERE baseline_id = ? "
            "  AND sensor = ? AND country = ? ORDER BY bucket DESC LIMIT ?)",
            (baseline_id, sensor, country, baseline_id, sensor, country,
             max_entries))
    return True


__all__ = ["fold_observations", "record_bucket_sample"]
