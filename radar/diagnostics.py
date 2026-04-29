"""radar.diagnostics — Weekly observability runner.

Phase 4 N3 — wraps the two CLI diagnostic scripts (intel sensor audit and
Layer 1 backtest) so the scheduler can run them on a weekly cadence
without shelling out to a subprocess. Output is logged at INFO level so
operators can grep historical reports out of container logs.

Why weekly: the two diagnostics measure trends that move on the scale of
days (sensor pre_filter ratios, source-type diversity, confirmed-item
accumulation toward Layer 1's n≥30 threshold). Running them more often
just adds noise to logs; less often risks missing a regression.

State: a single in-memory timestamp `_last_run_at` gates the cadence.
A container restart resets it, which means the diagnostic runs on the
first cleanup tick after restart and then once a week thereafter — at
worst a small over-report. Persisting via DB would help but the marginal
benefit is small (the diagnostics are read-only, ~2s cost, no side
effects on production state) so the simpler approach wins for now.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from typing import Any

log = logging.getLogger("radar.diagnostics")

# Module-level state. Reset on container restart — see docstring.
_last_run_at: float = 0.0
_state_lock = threading.Lock()

# Cadence: 7 days. Override via env for ops/test (kept clamped to ≥1h so
# a typo doesn't accidentally hammer the DB hourly).
def _interval_seconds() -> float:
    raw = float(os.getenv("WEEKLY_DIAGNOSTICS_INTERVAL_HOURS", "168"))  # 168h = 7d
    return max(3600.0, raw * 3600.0)


def _import_scripts() -> tuple[Any, Any]:
    """Import the two CLI diagnostic scripts as modules. They live in
    `scripts/` (outside the radar package), so the path needs adjustment.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    scripts_dir = os.path.join(repo_root, "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    import audit_intel_sensors as audit_mod
    import backtest_auto_judge_layer1 as backtest_mod
    return audit_mod, backtest_mod


def _diversity_signal(audit_result: dict, backtest_result: dict) -> str:
    """Return a one-line signal summarising whether the radar's
    cross-source diversity has reached Layer-1-ready territory.
    """
    a_div = audit_result.get("diversity_7d", {})
    b_div = backtest_result.get("diversity", {})
    avg = a_div.get("avg_distinct", b_div.get("avg_distinct", 0.0))
    max_ = a_div.get("max_distinct", b_div.get("max_distinct", 0))
    if max_ >= 2 and avg >= 2.0:
        return f"diversity OK (avg={avg:.2f} max={max_}) — Layer 1 unlock conditions met"
    if max_ >= 2:
        return f"diversity emerging (avg={avg:.2f} max={max_}) — at least one theater multi-source"
    return f"diversity = 1.0 (single-source-per-theater) — Layer 1 still blocked"


def run_once(db_path: str | None = None) -> dict:
    """Run both diagnostics once unconditionally and log the reports.

    Returns a result dict for callers (scheduler, tests). Catches and logs
    any per-diagnostic exception so a transient DB issue doesn't take the
    cleanup worker out (NP3).
    """
    audit_mod, backtest_mod = _import_scripts()
    db = db_path or "radar/persistence/radar.db"

    audit_result: dict = {}
    audit_text: str = ""
    try:
        audit_result = audit_mod.analyze(db)
        audit_text = audit_mod.format_text(audit_result)
    except Exception as exc:
        log.warning("[WeeklyDiag] audit_intel_sensors failed: %s", exc)

    backtest_result: dict = {}
    backtest_text: str = ""
    try:
        backtest_result = backtest_mod.analyze(db)
        backtest_text = backtest_mod.format_text(backtest_result)
    except Exception as exc:
        log.warning("[WeeklyDiag] backtest_auto_judge_layer1 failed: %s", exc)

    if audit_text:
        log.info("[WeeklyDiag] === Intel Sensor Audit ===\n%s", audit_text)
    if backtest_text:
        log.info("[WeeklyDiag] === Layer 1 Backtest ===\n%s", backtest_text)

    if audit_result or backtest_result:
        signal = _diversity_signal(audit_result, backtest_result)
        log.info("[WeeklyDiag] %s", signal)

    return {
        "audit": audit_result,
        "backtest": backtest_result,
        "ran_at": time.time(),
    }


def maybe_run() -> dict | None:
    """Cadence-gated entry point — invoked by the cleanup_worker on every
    hourly tick. Runs only if at least WEEKLY_DIAGNOSTICS_INTERVAL_HOURS
    have elapsed since the last run in this process.
    """
    now = time.time()
    interval = _interval_seconds()
    with _state_lock:
        global _last_run_at
        if (now - _last_run_at) < interval:
            return None
        # Mark optimistically so a long-running invocation doesn't
        # double-fire if cleanup_worker overlaps; a failure inside
        # run_once() is logged but doesn't roll the timestamp back —
        # we'd rather skip a week than spin on a broken DB.
        _last_run_at = now
    log.info("[WeeklyDiag] cadence elapsed (%.1fh) — running diagnostics", interval / 3600)
    try:
        return run_once()
    except Exception as exc:
        log.warning("[WeeklyDiag] run_once raised: %s", exc)
        return None


def _force_reset_for_tests() -> None:
    """Test-only helper: reset the cadence gate so a test can re-trigger
    maybe_run() without waiting a week. Not exported in __all__."""
    global _last_run_at
    with _state_lock:
        _last_run_at = 0.0


__all__ = ["run_once", "maybe_run"]
