"""The retention job — the only writer permitted to delete.

S3-DATA-040: policy lives in a declarative registry and this walks it.
The current system has twenty hand-written DELETE statements in one
method, which is how a hardcoded 7-day prune sat beside a live config key
for months while the key did nothing.

The append-only triggers block deletes outright; this job opens the gate
for the duration of the prune and closes it in a `finally`, so the one
sanctioned exception is explicit, narrow, and cannot be left open by an
exception on the way through.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

from v3.ledger.schema import RETENTION_POLICIES

if TYPE_CHECKING:
    from v3.ledger.store import LedgerStore

DAY_SEC = 86400.0


def prune(store: "LedgerStore", now: Optional[float] = None) -> dict:
    """Apply every policy in ONE transaction. Returns {table: rows deleted}.

    Opening the append-only gate, deleting, and closing the gate are a
    single atomic unit. Split across transactions, a crash in between
    leaves a durable `pruning` flag behind, the triggers stop firing, and
    the ledger stops being append-only with nothing to say so. A mid-loop
    failure likewise rolls back every delete rather than leaving the
    ledger half-pruned.

    Table and column names are interpolated because SQLite cannot
    parameterise identifiers; RetentionPolicy validates both as plain
    identifiers at construction, which is what makes that safe.
    """
    ts = time.time() if now is None else now
    deleted: dict = {}
    with store.transaction() as connection:
        store._set_prune_flag(connection, True)   # noqa: SLF001
        for policy in RETENTION_POLICIES:
            if policy.is_permanent or policy.time_column is None:
                deleted[policy.table] = 0
                continue
            cutoff = ts - policy.retention_days * DAY_SEC
            cursor = connection.execute(
                f'DELETE FROM "{policy.table}" '  # noqa: S608 - validated id
                f'WHERE "{policy.time_column}" < ?', (cutoff,))
            deleted[policy.table] = cursor.rowcount
        store._set_prune_flag(connection, False)  # noqa: SLF001
    return deleted


__all__ = ["prune", "DAY_SEC"]
