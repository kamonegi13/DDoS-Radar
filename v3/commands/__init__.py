"""The command domain — what an analyst's decision IS, before any HTTP.

Framework-free and API-free on purpose: `state.py` holds the folds and
`spec.py` the registry, and neither imports `v3.api`. The API layer
depends on this; this depends on the ledger's read shape only (duck-typed,
so a `ReadOnlyLedger` satisfies it and a writer is never needed here).

    state   the folds — effective focus, labels, ground truth
    spec    the closed action registry and its resolve/apply pairs

Nothing here has import-time side effects.
"""
from v3.commands.spec import (ACTIONS, SPECS, CommandSpec, Target, find,
                              spec_for)
from v3.commands.state import (ANALYST_LABELS, CONCLUSION_LABEL, FOCUS_SET,
                               GROUND_TRUTH_ASSERT, TARGET_CONCLUSION,
                               TARGET_SCENARIO, focus_state,
                               ground_truth_for, labels_for, latest_after)

__all__ = ["Target", "CommandSpec", "SPECS", "ACTIONS", "spec_for", "find",
           "FOCUS_SET", "CONCLUSION_LABEL", "GROUND_TRUTH_ASSERT",
           "TARGET_SCENARIO", "TARGET_CONCLUSION", "ANALYST_LABELS",
           "focus_state", "labels_for", "ground_truth_for", "latest_after"]
