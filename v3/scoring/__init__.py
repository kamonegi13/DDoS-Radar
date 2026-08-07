"""L2 — the scoring kernel. One of them (P6 O-14).

Observations in, threat levels out, and nothing else touched. The kernel
reads no database, no clock and no environment: every value it uses,
including the tick instant and the state carried from the previous tick,
arrives through `ScoringInputs`. That is what makes a tick replayable, and
replay is what parity measurement rests on (F-05, S5-VERIF-020).

    score_tick(inputs) -> TickResult     the single entry point
    resolve_settings()                   the caller's impure step, run
                                         BEFORE score_tick, never inside it

The legacy system carries two formula families and four copies of the
threat-level ladder. This package implements the one family that actually
reaches a served threat level — the scenario path — and `registry` records
every clause of both S1 books as either implemented-with-a-test or
excluded-with-a-reason, so the accounting cannot quietly drift.

Nothing here has import-time side effects, and nothing imports the legacy
`radar` package except through `Threshold`, lazily, at resolution time.
"""
from v3.scoring.contributions import Contribution
from v3.scoring.convergence import (DUAL_DOMAIN, FULL_CONVERGENCE, NONE,
                                    SINGLE_DOMAIN, convergence_bonus,
                                    convergence_level)
from v3.scoring.gating import GateDecision, NoiseRule, gate
from v3.scoring.inputs import (CountryWeight, Observation, Participant,
                               PatternFlags, PriorState, Scenario,
                               ScoringInputs, SequenceEvent)
from v3.scoring.kernel import score_scenario, score_tick
from v3.scoring.registry import EXCLUDED, IMPLEMENTED, S1_SCORING_CLAUSES
from v3.scoring.result import BonusBreakdown, ScoringResult, TickResult
from v3.scoring.settings import ScoringSettings, resolve_settings
from v3.scoring.threat_level import apply_hysteresis, derive_tl

__all__ = [
    # entry point
    "score_tick",
    "score_scenario",
    # inputs
    "ScoringInputs",
    "Observation",
    "CountryWeight",
    "Scenario",
    "Participant",
    "SequenceEvent",
    "PriorState",
    "PatternFlags",
    "ScoringSettings",
    "resolve_settings",
    # gating
    "gate",
    "GateDecision",
    "NoiseRule",
    # formulas
    "derive_tl",
    "apply_hysteresis",
    "convergence_level",
    "convergence_bonus",
    "NONE",
    "SINGLE_DOMAIN",
    "DUAL_DOMAIN",
    "FULL_CONVERGENCE",
    # results
    "TickResult",
    "ScoringResult",
    "BonusBreakdown",
    "Contribution",
    # clause accounting
    "IMPLEMENTED",
    "EXCLUDED",
    "S1_SCORING_CLAUSES",
]
