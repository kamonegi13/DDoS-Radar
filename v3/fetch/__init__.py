"""L0 — the shared fetch kernel. No egress exists outside it.

    run_due(now, adapters, states)   PURE: what to fetch, as values
    execute_plan(plan, ...)          the impure half, kept separate
    HttpClient                       the ONLY requests import in v3
    parse_feed                       the ONE tolerant parser
    breaker / limiter / schedule     pure state machines, state as values

The completion condition for WP-2.5 is that no outside access bypasses
this kernel, and it is proved structurally rather than asserted:
`scripts/check_kernel_discipline.py` fails on any HTTP or socket import
under `v3/` outside `client.py`, and the boundary tests show that
importing any module here starts no thread and pulls in no legacy module.

Importing this package does nothing. Threads belong to the composition
root — `radar/__init__.py` spawning ~40 at import is what made the legacy
test suite talk to the production database and let `bg_observer` walk
past the circuit breaker (B-01).
"""
from v3.fetch.breaker import (BreakerState, effective_state, should_skip,
                              step)
from v3.fetch.client import FetchOutcome, HttpClient
from v3.fetch.expand import (ExpansionInput, ExpansionScope,
                             ResolvedContinuation, ResolvedStep,
                             carried_values, continue_with, expand_requests,
                             expand_spec, placeholders_in)
from v3.fetch.limiter import LimiterState, is_allowed, wait_seconds
from v3.fetch.parse import DEATH_CAUSES, FeedItem, ParseResult, parse_feed
from v3.fetch.registry import AdapterRegistry
from v3.fetch.runner import (CycleResult, FetchPlan, PlannedFetch,
                             SkippedFetch, execute_plan, run_due)
from v3.fetch.schedule import is_due, next_run_at, overdue_by
from v3.fetch.state import AdapterState

__all__ = [
    "run_due", "execute_plan", "FetchPlan", "PlannedFetch", "SkippedFetch",
    "CycleResult",
    "HttpClient", "FetchOutcome",
    "AdapterRegistry", "AdapterState",
    "BreakerState", "effective_state", "should_skip", "step",
    "LimiterState", "is_allowed", "wait_seconds",
    "parse_feed", "ParseResult", "FeedItem", "DEATH_CAUSES",
    "is_due", "next_run_at", "overdue_by",
    "ExpansionInput", "ExpansionScope", "ResolvedStep",
    "ResolvedContinuation", "carried_values", "continue_with",
    "expand_requests", "expand_spec", "placeholders_in",
]
