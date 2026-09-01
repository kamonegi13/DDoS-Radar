"""L3 — the conclusion layer. What the tool actually says, and why not.

Five outputs (CLAUDE.md's tool definition), one envelope, four reasons for
saying nothing, and a rule that the fourth kind of answer is still an
answer that gets written down.

    Conclusion        unconstructible without Provenance, InputHealth and
                      the NP7 disclaimer
    InputHealth       what the tick had to work with, so that "quiet
                      world" and "empty cache" are different rows (G-17)
    GUARDS            reason -> the condition that emits it. Every one of
                      the four has a live path and a test (F-12, C-08)
    Suppression       what stopped a conclusion, kept on the row it
                      explains rather than in a log line (E-17)
    derive_all        five types per tick, always; a type never goes
                      missing, because a missing row reads as a healthy one
    persist           the separated impure step

Trend, chronic detection and null-zone are queries over L1's unthinned TL
stream (P6 O-15 / O-16). There is no state machine here, and no
compensating mechanism: the chain of three that the legacy system grew —
thinning broke chronic detection, a continuity ledger fixed that, a duty
cycle fixed the continuity ledger — starts with the first lane, and there
is only one lane.

Nothing here has import-time side effects, reads the environment, or
imports the legacy `radar` package.
"""
from v3.conclusions.availability import (GUARDS, Availability, Candidate,
                                         Guard, GuardVerdict, InputHealth,
                                         Suppression, evaluate,
                                         reasons_with_a_generation_path,
                                         registry_disclosure)
from v3.conclusions.conclusion import Conclusion, build, new_conclusion_id
from v3.conclusions.context import ScenarioContext
from v3.conclusions.derive import derive_all, latest_of_each_type
from v3.conclusions.envelope import (API_VERSION, ConclusionEnvelope, bundle)
from v3.conclusions.persistence import persist, to_record
from v3.conclusions.registry import (DEFERRED, EXCLUDED, IMPLEMENTED,
                                     S1_CONCLUSION_CLAUSES, unaccounted)
from v3.conclusions.vocabulary import (ANOMALY, ATTACK_MODE,
                                       CALIBRATION_PENDING, CONCLUSION_TYPES,
                                       INSUFFICIENT_DATA, NP7_DISCLAIMER,
                                       PER_DOMAIN, SENSOR_DEGRADED,
                                       THREAT_LEVEL, TREND,
                                       UNAVAILABLE_REASONS, UPSTREAM_FAILURE)

__all__ = [
    # types
    "Conclusion",
    "ConclusionEnvelope",
    "ScenarioContext",
    "InputHealth",
    "Candidate",
    "Suppression",
    "Guard",
    "GuardVerdict",
    "Availability",
    # entry points
    "derive_all",
    "persist",
    "bundle",
    "build",
    "evaluate",
    "to_record",
    "latest_of_each_type",
    "new_conclusion_id",
    # the F-12 registry
    "GUARDS",
    "reasons_with_a_generation_path",
    "registry_disclosure",
    # vocabulary
    "CONCLUSION_TYPES",
    "THREAT_LEVEL",
    "TREND",
    "PER_DOMAIN",
    "ANOMALY",
    "ATTACK_MODE",
    "UNAVAILABLE_REASONS",
    "INSUFFICIENT_DATA",
    "CALIBRATION_PENDING",
    "SENSOR_DEGRADED",
    "UPSTREAM_FAILURE",
    "NP7_DISCLAIMER",
    "API_VERSION",
    # clause accounting
    "S1_CONCLUSION_CLAUSES",
    "IMPLEMENTED",
    "DEFERRED",
    "EXCLUDED",
    "unaccounted",
]
