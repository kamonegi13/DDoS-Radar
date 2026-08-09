"""radar.verification.window_unit_health — WP-1.3, the third L5 check.

Asks two questions the existing checks cannot:

    "the baseline is being updated, but does it hold the window it claims?"
    "the threshold is configured, but can the compared value ever reach it?"

firing_monitor (WP-1.1) reports a detector that never fires; this reports
*why* one class of them never can. F-08's is_jammed shows up in both: there
as a flag silent past its expected interval, here as a ratio in [0,1]
compared against 3.0. F-06 shows up only here — telegram's z-score does
fire, it is just normalised against 7.5 hours of history while claiming 30
days, so nothing looks broken from the outside.

Verdicts (S5-VERIF-010/011 for windows, 007/008/009a for units):

    window  deviation > 20%          -> ANOMALY window_mismatch
            no declared window       -> WARN undeclared_window
            unbounded accumulation   -> WARN unbounded_baseline
            cadence unknown          -> INSUFFICIENT cadence_unknown
            time-anchored / in range -> OK
    unit    threshold outside domain -> ANOMALY unit_mismatch
            registered key, no unit  -> WARN missing_unit
            threshold value unknown  -> INSUFFICIENT threshold_value_unknown
            otherwise                -> OK

The unit axis has its own INSUFFICIENT case: a catalogued comparison whose
threshold resolves to nothing (a registered key with a None default, or a
key that vanished from the registry) cannot be checked for reachability.
That is a distinct condition from a window whose cadence is unknown, and
is reported as such rather than borrowed from the window vocabulary — an
unanswerable check must not read as a healthy one (S5-VERIF-006).

Both axes classify every catalogued entry, healthy ones included: a check
that only reports problems cannot distinguish "clean" from "not run".
Built on l5_common, so the ledger, the carry-forward and the persistent
schedule behave exactly like the other two checks.
"""
from __future__ import annotations

import logging
from typing import Optional

from radar import config_layered
from radar.verification import l5_common
from radar.verification import window_catalog as catalog

log = logging.getLogger("radar")

JOB_ID = "window_unit_health_daily"
CHECK_ID = "window_unit_health"
JOB_INTERVAL_SEC = l5_common.JOB_INTERVAL_SEC
SUMMARY_TARGET = l5_common.SUMMARY_TARGET

# S5-VERIF-011: allowed relative deviation between effective and declared.
WINDOW_DEVIATION_LIMIT = 0.20

REASON_WINDOW_MISMATCH = "window_mismatch"
REASON_UNDECLARED = "undeclared_window"
REASON_UNBOUNDED = "unbounded_baseline"
REASON_CADENCE_UNKNOWN = "cadence_unknown"
REASON_BY_CONSTRUCTION = "bounded_by_construction"
REASON_WINDOW_OK = "window_matches_declaration"
REASON_UNIT_MISMATCH = "unit_mismatch"
REASON_MISSING_UNIT = "missing_unit"
REASON_VALUE_UNKNOWN = "threshold_value_unknown"
REASON_UNIT_OK = "unit_consistent"

# Module-level seams: tests bind `_db` to a throwaway database.
_db = l5_common.db
_now = l5_common.now

l5_common.register_job(JOB_ID, label="Baseline window / unit consistency",
                       interval_sec=JOB_INTERVAL_SEC)


# ── S5-VERIF-010/011: window health ────────────────────────────────────────
def window_verdict(effective_h: Optional[float],
                   declared_h: Optional[float]) -> tuple[str, str]:
    """(verdict, reason) for a bounded, cadence-driven baseline. Pure."""
    deviation = catalog.window_deviation(effective_h, declared_h)
    if deviation is None:
        return ("INSUFFICIENT", REASON_CADENCE_UNKNOWN)
    if deviation > WINDOW_DEVIATION_LIMIT:
        return ("ANOMALY", REASON_WINDOW_MISMATCH)
    return ("OK", REASON_WINDOW_OK)


def _evaluate_window(spec: catalog.WindowSpec) -> dict:
    interval = catalog.sample_interval_sec(spec)
    effective_h = catalog.effective_window_hours(spec, interval)
    declared_h = catalog.declared_window_hours(spec)

    if spec.cap_mode == catalog.CAP_NONE:
        verdict, reason = "WARN", REASON_UNBOUNDED
    elif spec.cap_mode == catalog.CAP_NOT_APPLICABLE:
        # Time-anchored retention: the count is not the bound, so there is
        # no sample-vs-cadence arithmetic that could drift.
        verdict, reason = "OK", REASON_BY_CONSTRUCTION
    elif interval is None:
        verdict, reason = "INSUFFICIENT", REASON_CADENCE_UNKNOWN
    elif declared_h is None:
        verdict, reason = "WARN", REASON_UNDECLARED
    else:
        verdict, reason = window_verdict(effective_h, declared_h)

    return {
        "axis": "window",
        "target": spec.baseline_id,
        "sensor": spec.sensor,
        "verdict": verdict,
        "reason": reason,
        "kind": spec.kind,
        "cap_mode": spec.cap_mode,
        "cap_samples": catalog.cap_samples(spec, interval),
        "sample_interval_sec": interval,
        "effective_window_h": (None if effective_h is None
                               else round(effective_h, 4)),
        "declared_window_h": declared_h,
        "declared_key": spec.declared_key,
        "deviation": catalog.window_deviation(effective_h, declared_h),
        "source": spec.source,
    }


def evaluate_windows() -> list[dict]:
    """A verdict for every catalogued baseline. Total, healthy ones included."""
    return [_evaluate_window(spec) for spec in catalog.CATALOG]


# ── S5-VERIF-007/008/009: unit consistency ─────────────────────────────────
def _threshold_metadata(spec: catalog.ThresholdComparisonSpec) -> dict:
    """Resolve the threshold's declared value, range and unit."""
    if not spec.threshold_key:
        return {"value": spec.literal_value, "unit": None,
                "min": None, "max": None, "registered": False}
    meta = config_layered.get_meta(spec.threshold_key)
    if meta is None:
        # Env-tunable but unregistered — invisible to SETTINGS (a G-15
        # sibling). Nothing to check the unit annotation against.
        return {"value": spec.literal_value, "unit": None,
                "min": None, "max": None, "registered": False}
    value = meta.default
    return {
        "value": None if value is None else float(value),
        "unit": meta.unit,
        "min": meta.min_value,
        "max": meta.max_value,
        "registered": True,
    }


def _evaluate_unit(spec: catalog.ThresholdComparisonSpec) -> dict:
    meta = _threshold_metadata(spec)
    reachable = catalog.in_domain(meta["value"], spec.domain_lo, spec.domain_hi)
    overlap = catalog.range_overlap_fraction(
        meta["min"], meta["max"], spec.domain_lo, spec.domain_hi)

    if reachable is False:
        verdict, reason = "ANOMALY", REASON_UNIT_MISMATCH
    elif reachable is None:
        # No threshold value to compare — the check cannot be performed.
        verdict, reason = "INSUFFICIENT", REASON_VALUE_UNKNOWN
    elif meta["registered"] and not meta["unit"]:
        # S5-VERIF-007: an unannotated threshold is how F-08 stayed
        # invisible — nothing declared that 3.0 was a percent.
        verdict, reason = "WARN", REASON_MISSING_UNIT
    else:
        verdict, reason = "OK", REASON_UNIT_OK

    return {
        "axis": "unit",
        "target": spec.comparison_id,
        "sensor": spec.sensor,
        "verdict": verdict,
        "reason": reason,
        "threshold_key": spec.threshold_key,
        "threshold_value": meta["value"],
        "threshold_registered": meta["registered"],
        "unit_declared": "" if meta["unit"] is None else meta["unit"],
        "domain": [spec.domain_kind, spec.domain_lo, spec.domain_hi],
        "registry_min": meta["min"],
        "registry_max": meta["max"],
        "range_overlap_fraction": overlap,
        "source": spec.source,
    }


def evaluate_units() -> list[dict]:
    """A verdict for every catalogued comparison."""
    return [_evaluate_unit(spec) for spec in catalog.THRESHOLD_CATALOG]


def evaluate() -> list[dict]:
    return evaluate_windows() + evaluate_units()


# ── the daily job ───────────────────────────────────────────────────────────
_WINDOW_MEASURED = ("reason", "kind", "cap_mode", "cap_samples",
                    "sample_interval_sec", "effective_window_h", "deviation",
                    "source")
_UNIT_MEASURED = ("reason", "threshold_key", "threshold_value",
                  "unit_declared", "range_overlap_fraction",
                  "registry_min", "registry_max", "source")


def _ledger_row(result: dict) -> dict:
    """One result in the shape l5_common.record_results expects."""
    if result["axis"] == "window":
        measured = {k: result[k] for k in _WINDOW_MEASURED}
        expected = {"declared_window_h": result["declared_window_h"],
                    "declared_key": result["declared_key"],
                    "deviation_limit": WINDOW_DEVIATION_LIMIT}
    else:
        measured = {k: result[k] for k in _UNIT_MEASURED}
        # Only a registered key can carry a unit annotation; a hardcoded
        # literal has nowhere to declare one, so demanding it would record
        # an expectation the code could never satisfy.
        expected = {"domain": result["domain"],
                    "unit_required": bool(result["threshold_key"])}
    return {"target": result["target"], "verdict": result["verdict"],
            "measured": measured, "expected": expected}


def _run(handle, ts: float) -> None:
    """One window/unit run. Called by the l5_common job skeleton.

    The catalogs are small and stable (a few dozen entries), so this uses
    the census policy: every non-OK row is written on every run, exactly
    like firing_monitor. The transition-only policy is for the ~94-row
    config check.
    """
    windows = evaluate_windows()
    units = evaluate_units()
    results = windows + units
    counts = l5_common.record_results(
        handle, check_id=CHECK_ID, ts=ts,
        rows=[_ledger_row(r) for r in results], transition_only=False)

    measured = dict(counts)
    measured["windows_total"] = len(windows)
    measured["comparisons_total"] = len(units)
    l5_common.append_result(
        handle, check_id=CHECK_ID, ts=ts, target=SUMMARY_TARGET,
        verdict=l5_common.summary_verdict(counts), measured=measured,
        expected={"deviation_limit": WINDOW_DEVIATION_LIMIT})
    if counts["ANOMALY"]:
        log.warning("[WindowUnitHealth] %d ANOMALY, %d WARN across %d "
                    "baselines and %d comparisons", counts["ANOMALY"],
                    counts["WARN"], len(windows), len(units))


def run_daily_check_if_due(now: float | None = None) -> bool:
    """Run the window/unit check if the persisted schedule says it is due."""
    return l5_common.run_daily_if_due(
        db_fn=_db, job_id=JOB_ID, run_fn=_run, interval_sec=JOB_INTERVAL_SEC,
        now_ts=now, label="window-unit-health")


# ── AP3 self-evaluation surface ─────────────────────────────────────────────
def _brief(result: dict) -> dict:
    keys = (("target", "sensor", "reason", "effective_window_h",
             "declared_window_h", "deviation")
            if result["axis"] == "window"
            else ("target", "sensor", "reason", "threshold_key",
                  "threshold_value", "domain", "range_overlap_fraction"))
    return {k: result[k] for k in keys}


def snapshot() -> dict:
    """Live window/unit summary for /api/v2/self_eval.

    Takes no `now`, unlike its two siblings: every input here is current
    state — the catalogs, the registry metadata and the sensors' live
    cadence. There is no accumulated history to evaluate "as of" a past
    instant, so a clock parameter could only be decorative.
    """
    windows = evaluate_windows()
    units = evaluate_units()
    results = windows + units
    try:
        job = _db().l5_job_get(JOB_ID) or {}
    except Exception as exc:  # noqa: BLE001 - visible failure, not a green blank
        log.warning("window-unit-health job lookup failed: %s", exc)
        job = {}

    counts = {verdict: sum(1 for r in results if r["verdict"] == verdict)
              for verdict in l5_common.VERDICT_ORDER}
    return {
        "job_id": JOB_ID,
        "job_last_run_at": job.get("last_run_at"),
        "job_next_run_at": job.get("next_run_at"),
        "windows_total": len(windows),
        "comparisons_total": len(units),
        "counts": counts,
        "window_anomalies": [_brief(r) for r in windows
                             if r["verdict"] == "ANOMALY"],
        "unit_anomalies": [_brief(r) for r in units
                           if r["verdict"] == "ANOMALY"],
        "warns": [_brief(r) for r in results if r["verdict"] == "WARN"],
        "insufficient_count": sum(1 for r in results
                                  if r["verdict"] == "INSUFFICIENT"),
        "deviation_limit": WINDOW_DEVIATION_LIMIT,
    }
