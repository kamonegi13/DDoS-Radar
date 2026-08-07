"""How to actually run the 30-day parity measurement, when the window opens.

Documented rather than executed. WP-0.1 extended the signal ledger's
retention to 60 days on 2026-08-06; a 30-day window therefore cannot be
measured before **2026-09-05**, and running earlier would compare a window
the ledger only partly covers — which S5-VERIF-023 would then void for
one-side-missing anyway, after burning the run.

The text lives here rather than in a document because the harness should
carry its own operating instructions: the previous replay machinery was
deleted (G-06) and its procedure went with it.
"""
from __future__ import annotations

PROCEDURE = """\
PARITY RUN PROCEDURE (WP-2.8)
=============================

PRECONDITIONS
  1. The v3 signal ledger holds >= 30 days of continuous observations.
     Check:  LedgerStore(path).oldest_observed_at("signal_observation")
     Earliest possible date: 2026-09-05 (WP-0.1 retention change + 30d).
  2. The ETL has been run and reconciled, so C-10/C-11 can be answered:
     v3.etl.reconcile(...) -> pass its dict as `migration_report`.
  3. The scenario set is fixed for the window. A scenario whose
     participants changed mid-window makes both sides disagree with
     themselves, not with each other.

RUNNING
  from v3.ledger import LedgerStore
  from v3.parity import ParityLedger, run_parity

  store  = LedgerStore("/path/to/v3.db")            # read-only usage
  parity = ParityLedger("/path/to/parity.db")       # SEPARATE file
  run = run_parity(
      store=store, parity_ledger=parity, scenarios=scenarios,
      start=window_start, end=window_end,
      tick_interval_sec=120.0,                      # BG_SCORING_INTERVAL_SEC
      legacy_code_version=<git rev of the legacy tree>,
      v3_code_version=<git rev of v3>,
      migration_report=<v3.etl.reconcile output>)
  print(run.report.to_json())

  Runtime is dominated by the legacy subprocess. It is spawned ONCE for
  the whole window, not per tick; a 30-day window at a 120 s tick is
  21,600 ticks in a single call. Raise `timeout_sec` accordingly.

READING THE RESULT
  * report.blocked lists conditions whose layer does not exist yet. Nine
    are expected until WP-2.5/2.6/2.7, WP-3.1 and WP-3.2 land.
  * report.failed is what must be fixed. Note that C-03 fails on ANY
    insensitive disagreement regardless of the agreement rate: NP1 treats
    a v3 that saw less as blocking, and the rate cannot buy it off.
  * summary.is_void means the one-side-missing rate exceeded 5%
    (S5-VERIF-023) — the run is not a measurement of anything and must be
    re-run over a window both systems cover.
  * Every disagreement is in the parity ledger with both formula version
    tags and the effective thresholds:
        parity.observations(run_id, only_mismatches=True)
        parity.evidence_for(observation_id)

SAFETY
  * The legacy driver never boots the application. `driver_v2.replay`
    verifies the subprocess's own module list and raises if
    radar.routes / radar.sensors / radar.scheduler / radar.ws loaded.
  * No writes reach either source system. Verify after a run:
        the v1/v3 database file mtimes are unchanged.
  * No LLM is called. Both sides consume recorded observations.

WHAT THIS RUN DOES NOT MEASURE
  See v3.parity.SCOPE_NOTES — the focused bonus fold and all
  conclusion-level types beyond threat_level.
"""

__all__ = ["PROCEDURE"]
