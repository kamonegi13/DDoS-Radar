"""Manual calibration trigger dispatcher (Tier 1, commit 2).

Provides a single chokepoint for invoking each Phase A-F1+F3 calibrator
or proposer on demand. The scheduler runs these on a daily cadence; this
module lets analysts (and the API in commit 4) trigger them ad-hoc when
investigating an issue or after applying an analyst-confirmed change.

Available phases:
  tl              — tl_threshold_calibrator.calibrate_all_scenarios
  llm_conf        — llm_confidence_calibrator.calibrate_all_sensors
  sensor_disable  — sensor_disable_proposer.propose_disables
  scenario        — scenario_improver.run_once
  drift           — drift_watchdog.run_once
  all             — every phase, in deterministic order (above)

NP3 — any phase failure is captured per-phase and returned in the result;
      it never propagates and never blocks subsequent phases when running
      'all'.
NP6 — every dispatch returns a structured RunResult tuple with start
      timestamp, duration, and the summary dict the underlying phase
      returned, so callers can audit what ran when and what changed.
NP7 — read-mostly: most phases only emit pending proposals (no side
      effects on production scoring). Sensor auto-disable escalation
      remains gated by V2_AUTO_DISABLE_ENABLED inside the proposer.

Usage:
  python -m radar.calibration.run_now tl
  python -m radar.calibration.run_now all --json
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

log = logging.getLogger("radar.calibration.run_now")


# Phase identifiers in the order used by 'all'.
_PHASE_ORDER: tuple[str, ...] = (
    "tl",
    "llm_conf",
    "sensor_disable",
    "scenario",
    "drift",
)

_VALID_PHASES = frozenset(_PHASE_ORDER) | {"all"}


@dataclass(frozen=True)
class RunResult:
    phase: str
    started_at: float
    duration_ms: float
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


def _phase_func(phase: str) -> Callable[[], dict]:
    """Late-bind the phase entry-point. Imported lazily so a failure in
    one calibrator's import does not prevent dispatching the others."""
    if phase == "tl":
        from radar.calibration.tl_threshold_calibrator import calibrate_all_scenarios
        return calibrate_all_scenarios
    if phase == "llm_conf":
        from radar.calibration.llm_confidence_calibrator import calibrate_all_sensors
        return calibrate_all_sensors
    if phase == "sensor_disable":
        from radar.calibration.sensor_disable_proposer import propose_disables
        return propose_disables
    if phase == "scenario":
        from radar.calibration.scenario_improver import run_once
        return run_once
    if phase == "drift":
        from radar.calibration.drift_watchdog import run_once
        return run_once
    raise ValueError(f"Unknown phase: {phase!r}")


def _dispatch_one(phase: str) -> RunResult:
    """Execute a single phase. NP3: any exception is captured into the
    RunResult; the function itself never raises."""
    started_at = time.time()
    t0 = time.perf_counter()
    try:
        fn = _phase_func(phase)
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        log.warning("[run_now] phase %s import failed: %s", phase, exc)
        return RunResult(
            phase=phase, started_at=started_at, duration_ms=elapsed,
            summary={}, error=f"import_failed: {exc}"[:200],
        )
    try:
        summary = fn() or {}
        elapsed = (time.perf_counter() - t0) * 1000.0
        log.info("[run_now] phase %s ok in %.1fms summary=%s",
                 phase, elapsed, summary)
        return RunResult(
            phase=phase, started_at=started_at, duration_ms=elapsed,
            summary=dict(summary), error=None,
        )
    except Exception as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        log.exception("[run_now] phase %s failed", phase)
        return RunResult(
            phase=phase, started_at=started_at, duration_ms=elapsed,
            summary={}, error=str(exc)[:200],
        )


def dispatch(phase: str) -> list[RunResult]:
    """Dispatch one phase or 'all'. Returns a list of RunResult, one per
    phase executed, in execution order. Never raises for valid phase
    inputs (NP3); raises ValueError only for unknown phase names."""
    if phase not in _VALID_PHASES:
        raise ValueError(
            f"Unknown phase: {phase!r}. Valid: {sorted(_VALID_PHASES)}"
        )
    if phase == "all":
        return [_dispatch_one(p) for p in _PHASE_ORDER]
    return [_dispatch_one(phase)]


def format_results(results: list[RunResult]) -> str:
    """Render RunResult list as a short text report."""
    lines: list[str] = []
    lines.append("Calibration run_now report")
    lines.append("=" * 60)
    if not results:
        lines.append("(no results)")
        return "\n".join(lines)
    total_ms = sum(r.duration_ms for r in results)
    n_ok = sum(1 for r in results if r.succeeded)
    n_err = len(results) - n_ok
    for r in results:
        status = "OK " if r.succeeded else "ERR"
        lines.append(f"  [{status}] {r.phase:<16} {r.duration_ms:>8.1f}ms "
                     f"summary={r.summary}")
        if r.error:
            lines.append(f"        error: {r.error}")
    lines.append("-" * 60)
    lines.append(f"Summary: {n_ok} ok, {n_err} err, {total_ms:.1f}ms total")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Manually trigger Phase A-F1+F3 calibrators."
    )
    parser.add_argument(
        "phase", choices=sorted(_VALID_PHASES),
        help="Phase to run (or 'all' for every phase in order).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args(argv)

    try:
        results = dispatch(args.phase)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        out = {
            "phase": args.phase,
            "results": [asdict(r) for r in results],
            "n_ok": sum(1 for r in results if r.succeeded),
            "n_err": sum(1 for r in results if not r.succeeded),
        }
        print(json.dumps(out, indent=2))
    else:
        print(format_results(results))

    return 1 if any(not r.succeeded for r in results) else 0


__all__ = [
    "RunResult",
    "dispatch",
    "format_results",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
