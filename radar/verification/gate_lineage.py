"""radar.verification.gate_lineage — WP-1.4, the fourth L5 check.

The first three checks ask whether the *system* is measuring. This one
asks whether the things that are supposed to constrain it are still
participating at all. Three sub-audits, one shape of defect: a guard that
stopped guarding, and nothing said so.

  gate liveness (G-07)
      auto_tune_governor._recall_gate_is_red() calls
      `scripts.check_recall_baseline.evaluate_against_baseline(...)`, which
      does not exist — the real API is `compare()`. Its `except Exception`
      logs at DEBUG and returns False, i.e. "not red", so the governor's
      only recall guard has taken its fail-open branch on every invocation
      since it shipped. The probe therefore cannot be "call it and watch
      for an exception": the function swallows its own death by design. It
      introspects instead — can the module be imported, does it expose the
      attribute the gate calls — and never invokes the governor, because a
      liveness probe that ran commit() would write threshold_history and
      change what it measures.

      The probe imports the module rather than merely locating it, because
      that is what the governor itself does and the attribute can only be
      checked on a real module object. That import is not free of ambient
      effects, and they are named here rather than hidden behind a
      "side-effect free" claim:
        * `sys.path` gains the repository root (module-level insert) —
          already present in both real entry points (radar_api.py, wsgi.py);
        * `os.environ` gains V2_NP7_DISCLAIMER via setdefault — radar.config
          resolves that key earlier in startup, so the default never wins;
        * the root logger gets basicConfig() — a no-op after radar/__init__
          has already configured handlers.
      All three are inert in this application today. None writes to the
      database, the ledger or any sensor. If a future gate names a module
      whose import is genuinely consequential, that belongs in its
      GateProbe entry as a reason not to probe it this way.

  override liveness (G-02)
      user_attention_thresholds has a full CRUD API and a table. The
      evaluation path (attention._DEFAULT_RULES) reads none of it. An
      analyst tunes a threshold, gets a 200 and a persisted row, and
      changes nothing — the G-15 pattern on the attention axis.

  label lineage (G-08 / F-16)
      Recall cells with fn=0 and tn=0 have recall pinned to 1.0 by
      construction; a gate defending them defends a number that cannot
      move. And the baseline's `since` is null, so comparisons span the
      2026-07-04 and 08-02 label-series breaks as one continuous history.
      Degeneracy is detected by predicate, never by an expected count —
      the count was already wrong once (S5-VERIF-037, corrected 4 -> 5).

Nothing here is repaired; WP-0.2 owns the fixes. The gate probe is
declarative so that whatever shape the repair takes, it flips to OK
without the probe changing.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Optional

from radar.verification import l5_common

log = logging.getLogger("radar")

JOB_ID = "gate_lineage_daily"
CHECK_ID = "gate_lineage"
JOB_INTERVAL_SEC = l5_common.JOB_INTERVAL_SEC
SUMMARY_TARGET = l5_common.SUMMARY_TARGET

REASON_GATE_DEAD = "gate_dead"
REASON_GATE_ALIVE = "gate_alive"
REASON_OVERRIDE_INEFFECTIVE = "override_ineffective"
REASON_STALE_OVERRIDE = "stale_override"
REASON_NO_OVERRIDES = "no_overrides_stored"
REASON_OVERRIDES_UNREADABLE = "overrides_unreadable"
REASON_DEGENERATE = "degenerate_cell"
REASON_UNBOUNDED = "unbounded_series"
REASON_BOUNDED = "series_window_declared"
REASON_NO_EPOCH = "no_epoch_field"
REASON_EPOCH_PRESENT = "epoch_declared"
REASON_BOOTSTRAP = "baseline_missing"

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RECALL_BASELINE_PATH = _REPO_ROOT / "docs" / "baselines" / "recall_metrics.json"

# Module-level seam: tests bind `_db` to a throwaway database.
_db = l5_common.db

l5_common.register_job(JOB_ID, label="Gate liveness / label lineage",
                       interval_sec=JOB_INTERVAL_SEC)


# ── gate liveness (G-07) ────────────────────────────────────────────────────
@dataclass(frozen=True)
class GateProbe:
    """A safety gate and the import it needs in order to function.

    Declarative on purpose: a gate is described by what its implementation
    reaches for, so repairing the gate flips the verdict without touching
    this module, and adding a gate is one tuple entry.
    """
    gate_id: str
    description: str
    required_module: str
    required_attr: str
    consequence: str          # what silently proceeds when the gate is dead
    source: str = ""


GATE_PROBES: tuple[GateProbe, ...] = (
    GateProbe(
        gate_id="auto_tune_recall",
        description="Recall-regression gate guarding every auto-tune write "
                    "(the single chokepoint gov.commit() consults).",
        required_module="scripts.check_recall_baseline",
        required_attr="evaluate_against_baseline",
        consequence="Threshold auto-tuning proceeds unguarded: the gate's "
                    "except-branch returns False (not red), so the "
                    "fail-open path is taken on every invocation.",
        source="radar/calibration/auto_tune_governor.py:131-151",
    ),
)


def _ambient_context() -> str:
    """Environment facts that decide whether an import CAN succeed.

    An import-stage failure means something different depending on these:
    with the repository root off sys.path it is environmental (the process
    was started from elsewhere), with it on sys.path it is a genuine
    packaging problem. Recording it makes the two distinguishable after
    the fact instead of requiring a repro.
    """
    root_on_path = str(_REPO_ROOT) in sys.path or "" in sys.path
    return (f"repo_root_on_sys_path={root_on_path}, cwd={os.getcwd()!r}")


def probe_module_attr(module_path: str, attr: str) -> tuple[bool, str]:
    """(alive, evidence) for "module X exposes callable Y".

    Evidence names the stage that failed, because the two stages have
    different repairs: an import failure is a packaging (or environment)
    problem, a missing attribute is a call site that drifted from its
    callee. Both are live for G-07 — `scripts` resolves as a namespace
    package only when the repository root is on sys.path, so the same
    defect surfaces at either stage depending on how the process started.
    """
    try:
        module = import_module(module_path)
    except Exception as exc:  # noqa: BLE001 - the probe reports, never raises
        return (False, f"import stage failed: {module_path!r} is not "
                       f"importable ({type(exc).__name__}: {exc}); "
                       f"{_ambient_context()}")
    if not hasattr(module, attr):
        available = sorted(a for a in dir(module) if not a.startswith("_"))
        return (False, f"attribute stage failed: {module_path}.{attr}() does "
                       f"not exist; module exposes {available}")
    return (True, "")


def _evaluate_gate(probe: GateProbe) -> dict:
    alive, evidence = probe_module_attr(probe.required_module,
                                        probe.required_attr)
    failed_stage = ""
    if not alive:
        failed_stage = "import" if evidence.startswith("import") else "attribute"
    return {
        "axis": "gate",
        "target": f"gate:{probe.gate_id}",
        "gate_id": probe.gate_id,
        "verdict": "OK" if alive else "ANOMALY",
        "reason": REASON_GATE_ALIVE if alive else REASON_GATE_DEAD,
        "evidence": evidence,
        "failed_stage": failed_stage,
        "requires": f"{probe.required_module}.{probe.required_attr}",
        "consequence": "" if alive else probe.consequence,
        "description": probe.description,
        "source": probe.source,
    }


def evaluate_gates() -> list[dict]:
    """Liveness of every declared safety gate. Side-effect free."""
    return [_evaluate_gate(probe) for probe in GATE_PROBES]


# ── override liveness (G-02) ────────────────────────────────────────────────
def _known_rule_ids() -> Optional[frozenset]:
    try:
        from radar import attention
        return frozenset(rule.rule_id for rule in attention.all_rules())
    except Exception as exc:  # noqa: BLE001 - unknown != absent
        log.warning("gate-lineage attention rule lookup failed: %s", exc)
        return None


def _override_result(row: dict, known: Optional[frozenset]) -> dict:
    rule_id = row.get("rule_id")
    stale = known is not None and rule_id not in known
    return {
        "axis": "override",
        "target": f"attention_override:{row.get('user_id')}:{rule_id}",
        "verdict": "ANOMALY",
        # Both are dead knobs; a stale rule_id is additionally pointing at
        # a rule that no longer exists, which is the more actionable fact.
        "reason": REASON_STALE_OVERRIDE if stale else REASON_OVERRIDE_INEFFECTIVE,
        "user_id": row.get("user_id"),
        "rule_id": rule_id,
        "threshold": row.get("threshold"),
        "set_at": row.get("set_at"),
        "consequence": "The analyst's stored threshold is never read: "
                       "attention.evaluate() iterates the frozen "
                       "_DEFAULT_RULES and no code path consults this table.",
        "source": "radar/routes/attention_v2.py:161-201 (write) vs "
                  "radar/attention.py:454-485 (evaluation)",
    }


def evaluate_attention_overrides() -> list[dict]:
    """One result per stored override; a single OK row when there are none."""
    try:
        rows = _db().user_attention_thresholds_all()
    except Exception as exc:  # noqa: BLE001 - degrade to INSUFFICIENT, not OK
        log.warning("gate-lineage override query failed: %s", exc)
        return [{"axis": "override", "target": "attention_overrides",
                 "verdict": "INSUFFICIENT", "reason": REASON_OVERRIDES_UNREADABLE,
                 "error": str(exc), "override_count": None}]

    if not rows:
        # The structural defect stands, but no analyst input is currently
        # being ignored — reporting ANOMALY here would cry wolf.
        return [{"axis": "override", "target": "attention_overrides",
                 "verdict": "OK", "reason": REASON_NO_OVERRIDES,
                 "override_count": 0,
                 "note": "No stored overrides. The read path is still "
                         "absent, so any future write would be inert."}]

    known = _known_rule_ids()
    return [_override_result(row, known) for row in rows]


# ── label lineage (G-08 / F-16) ─────────────────────────────────────────────
def _is_degenerate(cell: dict) -> bool:
    """fn == 0 and tn == 0 pins recall to 1.0 by construction.

    A predicate, never a count: the "4 degenerate cells" figure in the
    specs was already stale when it was written (the real answer is 5),
    and it will change again the moment the baseline is regenerated.
    """
    return (cell.get("fn") == 0) and (cell.get("tn") == 0)


def _load_baseline(path: Path) -> tuple[Optional[dict], str]:
    if not path.exists():
        return (None, f"baseline file absent: {path.name}")
    try:
        return (json.loads(path.read_text(encoding="utf-8")), "")
    except (OSError, ValueError) as exc:
        return (None, f"baseline unreadable: {type(exc).__name__}: {exc}")


def evaluate_recall_lineage(path: Optional[Path] = None) -> list[dict]:
    """Degenerate cells, series boundedness and epoch identity."""
    baseline_path = RECALL_BASELINE_PATH if path is None else Path(path)
    baseline, problem = _load_baseline(baseline_path)
    if baseline is None:
        # No data is not a finding. Fabricating one here would be the
        # blanket-TP mistake in a new costume.
        return [{"axis": "lineage", "target": "recall_baseline",
                 "verdict": "INSUFFICIENT", "reason": REASON_BOOTSTRAP,
                 "evidence": problem, "path": str(baseline_path)}]

    cells = baseline.get("cells", [])
    if not isinstance(cells, list):
        # `"cells": null` and friends: the file parsed but says nothing we
        # can audit. Degrade like a missing file rather than crashing the
        # whole daily job on a TypeError.
        return [{"axis": "lineage", "target": "recall_baseline",
                 "verdict": "INSUFFICIENT", "reason": REASON_BOOTSTRAP,
                 "evidence": f"baseline 'cells' is {type(cells).__name__}, "
                             f"expected a list",
                 "path": str(baseline_path)}]

    results = []
    for cell in cells:
        if not isinstance(cell, dict):
            log.warning("gate-lineage: skipping non-dict recall cell (%s)",
                        type(cell).__name__)
            continue
        if not _is_degenerate(cell):
            continue
        results.append({
            "axis": "lineage",
            "target": f"recall_cell:{cell.get('scenario_id')}:"
                      f"{cell.get('conclusion_type')}",
            "verdict": "ANOMALY",
            "reason": REASON_DEGENERATE,
            "scenario_id": cell.get("scenario_id"),
            "conclusion_type": cell.get("conclusion_type"),
            "fn": cell.get("fn"), "tn": cell.get("tn"),
            "tp": cell.get("tp"), "recall": cell.get("recall"),
            "consequence": "recall is 1.0 by construction, so the gate "
                           "defending this cell cannot ever fail.",
        })

    since = baseline.get("since")
    results.append({
        "axis": "lineage", "target": "recall_series_window",
        "verdict": "OK" if since is not None else "ANOMALY",
        "reason": REASON_BOUNDED if since is not None else REASON_UNBOUNDED,
        "since": since,
        "consequence": "" if since is not None else
                       "Comparisons run over the full label history, "
                       "spanning the known series breaks as if they were "
                       "one continuous epoch (F-16).",
    })

    has_epoch = any(key in baseline for key in ("epoch_id", "epoch"))
    results.append({
        "axis": "lineage", "target": "recall_epoch_field",
        "verdict": "OK" if has_epoch else "WARN",
        "reason": REASON_EPOCH_PRESENT if has_epoch else REASON_NO_EPOCH,
        "schema_version": baseline.get("schema_version"),
        "consequence": "" if has_epoch else
                       "No epoch identity anywhere in the baseline schema, "
                       "so a re-labelled series cannot be told from a "
                       "continuation of the old one (S5-VERIF-032/033).",
    })
    return results


def evaluate() -> list[dict]:
    """Every sub-audit, in one list."""
    return (evaluate_gates() + evaluate_attention_overrides()
            + evaluate_recall_lineage())


# ── the daily job ───────────────────────────────────────────────────────────
_MEASURED_FIELDS = ("reason", "evidence", "failed_stage", "consequence",
                    "user_id", "rule_id", "threshold", "fn", "tn", "tp",
                    "recall", "since", "override_count", "error", "note",
                    "schema_version", "source")


def _ledger_row(result: dict) -> dict:
    measured = {k: result[k] for k in _MEASURED_FIELDS if k in result}
    expected = {"axis": result["axis"]}
    if result["axis"] == "gate":
        expected["requires"] = result.get("requires")
    elif result["axis"] == "lineage":
        expected["degenerate_predicate"] = "fn == 0 and tn == 0"
    return {"target": result["target"], "verdict": result["verdict"],
            "measured": measured, "expected": expected}


def _run(handle, ts: float) -> None:
    """One gate/lineage run. Called by the l5_common job skeleton."""
    results = evaluate()
    # Transition-only: gate and lineage states are stable for weeks at a
    # time, exactly like the config classification. A daily census would
    # bury the moment a gate dies under identical rows.
    counts = l5_common.record_results(
        handle, check_id=CHECK_ID, ts=ts,
        rows=[_ledger_row(r) for r in results], transition_only=True)

    measured = dict(counts)
    measured["gates_probed"] = len(GATE_PROBES)
    l5_common.append_result(
        handle, check_id=CHECK_ID, ts=ts, target=SUMMARY_TARGET,
        verdict=l5_common.summary_verdict(counts), measured=measured,
        expected={"findings_total": len(results)})
    if counts["ANOMALY"]:
        log.warning("[GateLineage] %d ANOMALY, %d WARN across gates, "
                    "overrides and recall lineage",
                    counts["ANOMALY"], counts["WARN"])


def run_daily_check_if_due(now: float | None = None) -> bool:
    """Run the gate/lineage check if the persisted schedule says it is due."""
    return l5_common.run_daily_if_due(
        db_fn=_db, job_id=JOB_ID, run_fn=_run, interval_sec=JOB_INTERVAL_SEC,
        now_ts=now, label="gate-lineage")


# ── AP3 self-evaluation surface ─────────────────────────────────────────────
def snapshot() -> dict:
    """Live gate/lineage summary for /api/v2/self_eval.

    Takes no clock: every input is current state (module imports, the
    override table, the baseline file on disk), so there is nothing to
    evaluate "as of" a past instant.
    """
    gates = evaluate_gates()
    overrides = evaluate_attention_overrides()
    lineage = evaluate_recall_lineage()
    results = gates + overrides + lineage
    job_lookup_error = None
    try:
        job = _db().l5_job_get(JOB_ID) or {}
    except Exception as exc:  # noqa: BLE001 - visible failure, not a blank
        log.warning("gate-lineage job lookup failed: %s", exc)
        job = {}
        # Without this, a failed lookup is indistinguishable from "the job
        # has never run" — both would render as two nulls (S5-VERIF-006).
        job_lookup_error = str(exc)

    counts = {verdict: sum(1 for r in results if r["verdict"] == verdict)
              for verdict in l5_common.VERDICT_ORDER}
    out = {
        "job_id": JOB_ID,
        "job_last_run_at": job.get("last_run_at"),
        "job_next_run_at": job.get("next_run_at"),
        "counts": counts,
        "dead_gates": [{"gate_id": g["gate_id"], "requires": g["requires"],
                        "failed_stage": g["failed_stage"],
                        "evidence": g["evidence"],
                        "consequence": g["consequence"]}
                       for g in gates if g["verdict"] == "ANOMALY"],
        "ineffective_overrides": [
            {"target": o["target"], "reason": o["reason"],
             "rule_id": o.get("rule_id"), "threshold": o.get("threshold")}
            for o in overrides if o["verdict"] == "ANOMALY"],
        "degenerate_cells": [
            {"target": c["target"], "scenario_id": c.get("scenario_id"),
             "conclusion_type": c.get("conclusion_type"),
             "fn": c.get("fn"), "tn": c.get("tn"), "recall": c.get("recall")}
            for c in lineage if c["reason"] == REASON_DEGENERATE],
        "lineage_findings": [
            {"target": r["target"], "reason": r["reason"],
             "verdict": r["verdict"]}
            for r in lineage if r["verdict"] != "OK"
            and r["reason"] != REASON_DEGENERATE],
    }
    if job_lookup_error is not None:
        out["job_lookup_error"] = job_lookup_error
    return out
