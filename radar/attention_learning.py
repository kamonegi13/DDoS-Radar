"""Adaptive learning observer + p95 recomputation (commit O).

Periodic tick (5-minute polling cadence in scheduler) records each
attention rule's metric value to attention_metric_observation. A
nightly cron computes p50/p95/p99 over the last 30 days and stores
into attention_metric_p95 for the suggestion API to read.

NP integrity:
  NP3 — observation failure for one rule does not abort the others;
        recompute is also fault-tolerant.
  NP6 — sample_count + computed_at on every p95 row provides
        provenance for any threshold suggestion derived from it.
  NP7 — suggestions are surface-only. Applying them still requires
        an explicit PUT /api/v2/attention/thresholds/<id>.

Bootstrap mode (sample_count < ATTENTION_MIN_LEARN_SAMPLES) returns
no suggestion; the operator continues with hardcoded defaults until
enough samples accumulate.
"""
from __future__ import annotations

import logging
import os
import statistics
import time

log = logging.getLogger("radar.attention_learning")


_RETENTION_DAYS = int(os.getenv("ATTENTION_OBS_RETENTION_DAYS", "30"))


def observe() -> dict:
    """Record one observation per ATTENTION rule into the DB.

    Called from the 5-minute polling tick (scheduler). Failure of one
    rule does not poison the others; the rest are recorded normally.
    """
    from radar.attention import all_rules, _collect_metrics
    metrics = _collect_metrics()
    out = {"recorded": 0, "skipped": 0}
    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        with conn.writing():
            now = time.time()
            for rule in all_rules():
                if rule.threshold_mode == "boolean":
                    out["skipped"] += 1
                    continue
                try:
                    val = rule.eval_fn(metrics)
                except Exception:
                    val = None
                if val is None:
                    out["skipped"] += 1
                    continue
                conn.execute(
                    "INSERT INTO attention_metric_observation "
                    "(rule_id, observed_at, observed_value) "
                    "VALUES (?, ?, ?)",
                    (rule.rule_id, now, float(val)),
                )
                out["recorded"] += 1
    except Exception as exc:
        log.debug("observe failed: %s", exc)
    return out


def recompute_p95(*, window_days: int | None = None) -> dict:
    """Compute p50/p95/p99 + sample_count over the lookback window for
    every rule with observations, write into attention_metric_p95
    (UPSERT). Returns counters dict for log messages."""
    days = int(window_days or _RETENTION_DAYS)
    cutoff = time.time() - days * 86400
    out = {"rules_updated": 0, "rules_with_few_samples": 0}
    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        rule_ids_rows = conn.execute(
            "SELECT DISTINCT rule_id FROM attention_metric_observation "
            "WHERE observed_at >= ?",
            (cutoff,),
        ).fetchall()
        with conn.writing():
            for (rid,) in rule_ids_rows:
                values_rows = conn.execute(
                    "SELECT observed_value FROM attention_metric_observation "
                    "WHERE rule_id=? AND observed_at >= ?",
                    (rid, cutoff),
                ).fetchall()
                values = [r[0] for r in values_rows if r[0] is not None]
                n = len(values)
                if n == 0:
                    out["rules_with_few_samples"] += 1
                    continue
                values.sort()
                p50 = statistics.median(values)
                # statistics.quantiles is more accurate but requires
                # n >= 2; fall back to the highest single value
                if n >= 2:
                    qs = statistics.quantiles(values, n=20, method="inclusive")
                    p95 = qs[18]  # 95th percentile bucket
                    if n >= 5:
                        qs99 = statistics.quantiles(values, n=100, method="inclusive")
                        p99 = qs99[98]
                    else:
                        p99 = max(values)
                else:
                    p95 = values[0]
                    p99 = values[0]
                conn.execute(
                    "INSERT INTO attention_metric_p95 "
                    "(rule_id, p50, p95, p99, sample_count, "
                    " computed_at, window_days) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(rule_id) DO UPDATE SET "
                    "  p50=excluded.p50, p95=excluded.p95, "
                    "  p99=excluded.p99, sample_count=excluded.sample_count, "
                    "  computed_at=excluded.computed_at, "
                    "  window_days=excluded.window_days",
                    (rid, p50, p95, p99, n, time.time(), days),
                )
                out["rules_updated"] += 1
    except Exception as exc:
        log.warning("recompute_p95 failed: %s", exc)
    return out


def cleanup_old_observations() -> int:
    """Delete observations older than RETENTION_DAYS. Returns row count."""
    cutoff = time.time() - _RETENTION_DAYS * 86400
    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        with conn.writing():
            cur = conn.execute(
                "DELETE FROM attention_metric_observation WHERE observed_at < ?",
                (cutoff,),
            )
            return int(cur.rowcount or 0)
    except Exception as exc:
        log.debug("cleanup_old_observations failed: %s", exc)
        return 0


__all__ = ["observe", "recompute_p95", "cleanup_old_observations"]
