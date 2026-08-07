"""The parity harness — the cutover prerequisite (WP-2.8).

Drives the legacy system and v3 from the SAME window of the same
observation ledger, compares their conclusions in severity space, and
answers P2 §5's fourteen cutover conditions mechanically.

    run_parity(...)     one window, both systems, a ParityReport
    ParityLedger        the isolated append-only result store
    compare_tick / summarise    the comparison engine

Three properties are structural rather than promised:

  * **Nothing in this package imports `radar`.** The legacy scoring
    functions are the real ones, called inside a subprocess that stubs
    `radar/__init__.py` and `radar.database` out of `sys.modules`. See
    `_v2_subprocess` for what that does and what residue remains.
  * **A replay writes to neither source system.** The v1 side's database
    access raises rather than being redirected; the v3 ledger is read
    through its read-only connection; results go only to the parity
    ledger, which is a separate file (S5-VERIF-021).
  * **Comparison happens in severity space only.** `Reading` holds a
    kernel `ThreatLevel`, whose ordering operators raise, so comparing
    raw TL integers is not reachable through this API (S5-VERIF-024).

Conditions whose layer does not exist yet report BLOCKED naming the work
package that will supply them — never PASS by default. Nine of the
fourteen are in that state today, which is the honest position for a
harness built ahead of L0, L3 and L4.

The 30-day run procedure is documented in `PROCEDURE`; the parity window
opens once the signal ledger holds 30 days (WP-0.1 + 30 days).
"""
from v3.parity.adapter import (LedgerInputAdapter, TickInput,
                               to_v3_observations, to_wire)
from v3.parity.compare import (ANOMALY, ATTACK_MODE, INSENSITIVE, MATCH,
                               MISMATCH, ONE_SIDE_MISSING, PER_DOMAIN,
                               SENSITIVE, THREAT_LEVEL, TREND, Contributor,
                               Reading, TickComparison, TickKey, compare_tick,
                               compare_transitions, extract_transitions)
from v3.parity.conditions import (BLOCKED, CONDITIONS, FAIL, PASS, Condition,
                                  ConditionVerdict, evaluate)
from v3.parity.ledger import (MismatchEvidence, ParityLedger, RunIdentity)
from v3.parity.procedure import PROCEDURE
from v3.parity.report import ParityContext, ParityReport, build_report
from v3.parity.run import SCOPE_NOTES, ParityRun, run_parity
from v3.parity.summary import SeriesSummary, summarise

__all__ = [
    # orchestration
    "run_parity",
    "ParityRun",
    "SCOPE_NOTES",
    "PROCEDURE",
    # input adapter (S5-VERIF-031)
    "LedgerInputAdapter",
    "TickInput",
    "to_v3_observations",
    "to_wire",
    # comparison engine
    "Reading",
    "Contributor",
    "TickKey",
    "TickComparison",
    "compare_tick",
    "extract_transitions",
    "compare_transitions",
    "summarise",
    "SeriesSummary",
    "MATCH",
    "MISMATCH",
    "ONE_SIDE_MISSING",
    "INSENSITIVE",
    "SENSITIVE",
    "THREAT_LEVEL",
    "PER_DOMAIN",
    "ATTACK_MODE",
    "TREND",
    "ANOMALY",
    # conditions and reporting
    "CONDITIONS",
    "Condition",
    "ConditionVerdict",
    "evaluate",
    "PASS",
    "FAIL",
    "BLOCKED",
    "ParityContext",
    "ParityReport",
    "build_report",
    # results ledger
    "ParityLedger",
    "RunIdentity",
    "MismatchEvidence",
]
