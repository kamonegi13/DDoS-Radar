"""Per-Conclusion calibration status — closes NP5+8 in v2.0.

NP5+8 ("結論品質規律") requires every conclusion to declare the calibration
state of the system that produced it. v1 surfaced calibration globally
through /api/analytics/cmedium_recommendation; v2 inlines a per-scenario
snapshot into Conclusion.calibration_status so analysts can see drift on
the same row as the conclusion itself.

History (2026-05-29 rewrite — ADR "real-calibration")
-----------------------------------------------------
Until 2026-05-29 this module derived calibration_status from the
**shadow sampler** (lite-vs-full score divergence). The Phase-9
``GLOBAL_SIGNALS_DECOUPLED`` refactor unified the lite/full score paths,
so ``full_score - lite_score`` became 0 by construction — the sampler
reported ``recent_miss_rate=0.0`` / ``drift=stable`` / ``sampler=OK`` for
every one of 360k conclusions regardless of reality. That is a dead
instrument: it could never have surfaced real drift, violating NP5+8
(degenerate calibration after data accumulation = design failure).

This module now derives calibration_status from the **ground-truth
confusion matrix** (analyst_feedback ⋈ conclusions) — the same labels the
recall metric uses. The headline number is recall (NP1: sensitivity), and
status flips to DEGRADED the moment recall drops below the floor, i.e. the
moment the tool starts missing real escalations. That is exactly what the
shadow sampler could not do.

Schema of the dict written into Conclusion.calibration_status:

  {
    "source": "ground_truth",
    "status": "OK" | "INSUFFICIENT_DATA" | "DEGRADED",
    "recall": float | None,        # TP / (TP + FN)  — NP1 sensitivity
    "precision": float | None,     # TP / (TP + FP)
    "tp": int, "fp": int, "tn": int, "fn": int,
    "sample_n": int,               # tp + fp + tn + fn
    "window_days": int,
    "last_label_at": float | None,
  }

Design choices:
- Read-only — never writes — so it is safe to call from any scoring path.
- One indexed DB round-trip, memoised behind a short TTL cache so the
  per-conclusion call site (threat_level.py) does not re-query on every
  scoring tick.
- All failures return the INSUFFICIENT_DATA envelope rather than raise:
  observability cannot break scoring (NP3).
- Status is keyed on the *recall denominator* (TP+FN), not total labels:
  recall is undefined without observed positives, and recall is the metric
  NP1 cares about. A scenario with only TRUE_NEGATIVE/FALSE_POSITIVE labels
  stays INSUFFICIENT_DATA for recall purposes until positives accumulate.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Optional

from radar import config

if TYPE_CHECKING:
    from radar.database import RadarDB


log = logging.getLogger("radar")

# Minimum observed positives (TP+FN) before we trust a recall number.
_MIN_RECALL_SAMPLES = 5
# Recall below this floor means the tool is missing real escalations →
# DEGRADED. NP1 prioritises recall, so the floor is deliberately high.
_DEGRADED_RECALL_THRESHOLD = 0.70
# Rolling window for the confusion matrix.
_WINDOW_DAYS = int(getattr(config, "CALIBRATION_WINDOW_DAYS", 30))
# Memoisation TTL — calibration_status_for is called per conclusion write.
_CACHE_TTL_SEC = 300.0


_INSUFFICIENT: dict = {
    "source": "ground_truth",
    "status": "INSUFFICIENT_DATA",
    "recall": None,
    "precision": None,
    "tp": 0,
    "fp": 0,
    "tn": 0,
    "fn": 0,
    "sample_n": 0,
    "window_days": _WINDOW_DAYS,
    "last_label_at": None,
}


_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, dict]] = {}


def calibration_status_for(db: "RadarDB", scenario_id: str) -> dict:
    """Build the per-Conclusion calibration_status dict for `scenario_id`.

    Derived from the ground-truth confusion matrix over the last
    ``_WINDOW_DAYS`` days (THREAT_LEVEL conclusions only — that is the
    surface recall is defined on). Memoised for ``_CACHE_TTL_SEC``.

    Returns the INSUFFICIENT_DATA envelope when no labels exist or the read
    fails — never raises (NP3).
    """
    now = time.time()
    with _cache_lock:
        hit = _cache.get(scenario_id)
        if hit is not None and (now - hit[0]) < _CACHE_TTL_SEC:
            return dict(hit[1])

    try:
        snapshot = _compute_snapshot(db, scenario_id, now=now)
    except Exception:
        log.exception("[calibration] non-fatal read failure for %s", scenario_id)
        return dict(_INSUFFICIENT)

    with _cache_lock:
        _cache[scenario_id] = (now, snapshot)
    return dict(snapshot)


def invalidate_cache(scenario_id: Optional[str] = None) -> None:
    """Drop memoised snapshots. Call after an ETL pass writes fresh labels
    so the next conclusion picks up the new calibration state immediately."""
    with _cache_lock:
        if scenario_id is None:
            _cache.clear()
        else:
            _cache.pop(scenario_id, None)


def _compute_snapshot(db: "RadarDB", scenario_id: str, *, now: float) -> dict:
    """Query the deduped confusion matrix for one scenario and classify."""
    since = now - _WINDOW_DAYS * 86400.0
    conn = db._get_conn()  # noqa: SLF001
    rows = conn.execute(
        "SELECT f.conclusion_id, f.analyst_id, f.label, f.observed_at "
        "FROM analyst_feedback f "
        "JOIN conclusions c ON c.id = f.conclusion_id "
        "WHERE c.scenario_id = ? "
        "  AND c.conclusion_type = 'threat_level' "
        "  AND f.observed_at >= ? "
        "ORDER BY f.observed_at DESC",
        (scenario_id, since),
    ).fetchall()

    # Latest label per (conclusion, analyst) — first row wins (DESC order).
    seen: set[tuple] = set()
    tp = fp = tn = fn = 0
    last_label_at: Optional[float] = None
    for r in rows:
        pair = (r["conclusion_id"], r["analyst_id"])
        if pair in seen:
            continue
        seen.add(pair)
        label = r["label"]
        if last_label_at is None:
            last_label_at = float(r["observed_at"])
        if label == "TRUE_POSITIVE":
            tp += 1
        elif label == "FALSE_POSITIVE":
            fp += 1
        elif label == "TRUE_NEGATIVE":
            tn += 1
        elif label == "FALSE_NEGATIVE":
            fn += 1

    sample_n = tp + fp + tn + fn
    if sample_n == 0:
        return dict(_INSUFFICIENT)

    recall = tp / (tp + fn) if (tp + fn) else None
    precision = tp / (tp + fp) if (tp + fp) else None
    status = _classify_status(recall_denom=tp + fn, recall=recall)

    return {
        "source": "ground_truth",
        "status": status,
        "recall": round(recall, 4) if recall is not None else None,
        "precision": round(precision, 4) if precision is not None else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "sample_n": sample_n,
        "window_days": _WINDOW_DAYS,
        "last_label_at": last_label_at,
    }


def _classify_status(*, recall_denom: int, recall: Optional[float]) -> str:
    """OK / DEGRADED / INSUFFICIENT_DATA from the recall denominator.

    INSUFFICIENT_DATA  — fewer than _MIN_RECALL_SAMPLES observed positives
                         (TP+FN); recall is not yet trustworthy.
    DEGRADED           — recall below the NP1 sensitivity floor: the tool is
                         demonstrably missing real escalations.
    OK                 — enough positives observed and recall holds.
    """
    if recall_denom < _MIN_RECALL_SAMPLES or recall is None:
        return "INSUFFICIENT_DATA"
    if recall < _DEGRADED_RECALL_THRESHOLD:
        return "DEGRADED"
    return "OK"
