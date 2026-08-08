"""S8 — the attention ledger (AP1), server-side and persisted.

Five modules, each with one job:

    thresholds   the pinned numbers, and the ONE per-user key (G-02).
    score        the pure formula and the provenance it produces.
    narrative    AP2's template engine — text from slots, never a model.
    rank         the total order, and the ledger rows.
    supply       where the three factors come from in L1.
    projection   P7 R6, live and replayed by one call.

Import is inert: nothing here opens a database, reads the environment or
starts a thread. The writer lives in `v3/runtime/attention.py`, because
the composition root owns clocks and stores.
"""
from __future__ import annotations

from v3.attention.score import (FORMULA_REF, ITEM_CONCLUSION, Inputs,
                                Provenance, score_for)

__all__ = ["FORMULA_REF", "ITEM_CONCLUSION", "Inputs", "Provenance",
           "score_for"]
