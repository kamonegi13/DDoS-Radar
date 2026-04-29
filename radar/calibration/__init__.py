"""radar.calibration — auto-tuning foundation (Phase A).

This package implements the load-bearing infrastructure for automated
threshold tuning while preserving NP6 (full disclosure) and NP7
(organizational node) under automation.

Modules:

  threshold_history
    Append-only ledger of every threshold value that has ever been in
    force, with effective_from/effective_to timestamps. Conclusions
    persist their `threshold_ref` as a snapshot of the threshold at
    decision time, and the dereferencer reads from this ledger so
    "why was TL=4 fired?" can always be answered against the value
    actually used, not the current live value.

  auto_tune_governor
    Single chokepoint that all auto-tune writes go through. Enforces
    bounded-magnitude-per-cycle (default 10%), cooldown (default 72h
    per key), and revertible_to chaining. If a candidate change
    violates governor rules, the proposal is recorded as 'rejected'
    but never applied — preserving safety even if a calibrator
    misbehaves.

  drift_watchdog
    Phase F3: passive monitoring of registered scenarios for "drift
    from reality" signals. Emits SCENARIO_DRIFT_DETECTED ledger rows
    with templated AP2 narratives. Never auto-applies anything; only
    surfaces warnings.

NP integrity contract for everything in this package:

  - NP1: changes that could reduce recall require analyst confirmation
  - NP6: every decision is a ledger row with formula_ref + sample_n +
         evidence + revertible_to
  - NP7: structural changes to scenarios are propose-only; thresholds
         internal to scoring are auto-tunable
  - NP3: a misconfigured calibrator must degrade silently (no proposal,
         not a wrong proposal)
  - AP3: per-emitter reliability is observable in HUD
  - AP4: every decision is replayable via /api/v2/replay
"""
from __future__ import annotations
