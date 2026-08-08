"""The read seam. A read handler is handed this and nothing else.

WP-4.1 completion condition 1 is "reads have no side effects, A-01
structurally dead". A-01 was `GET /api/threat_data` running the scoring
tick — a GET that appended to the ledger, emitted over the websocket and
cleared a failure flag. The v2 remedy was a rule in a review checklist.

This is the structural remedy. `ReadOnlyLedger` forwards a named set of
`LedgerStore` methods; every other attribute is an `AttributeError`. The
named set is not maintained by hand: `audit_store_methods()` re-derives
it from `v3/ledger/store.py` by AST and the suite fails if the two
disagree, which is the same discipline WP-2.6 used after finding 97
transcription infidelities in constants that looked correctly copied.

Why the AST pass is the real proof: the forwarded methods are exactly the
ones whose bodies use `_read_connection()`, and that connection is opened
`file:...?mode=ro`. SQLite refuses a write on it. So the barrier is not
"we listed the safe methods" but "the listed methods hold a handle the
database will not let them write through".

LIMITATION, stated rather than implied (the discipline gate states its
own the same way): this object holds the store in an attribute, and
Python offers no attribute that introspection cannot reach. The SQLite
barrier is what makes reachability harmless; the whitelist is what makes
the ordinary path — `ledger.append_signal(...)` — impossible to write by
accident.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Optional

from v3.kernel.errors import DomainError

_STORE_SOURCE = (Path(__file__).resolve().parent.parent
                 / "ledger" / "store.py")
_STORE_CLASS = "LedgerStore"

#: Attributes whose presence in a body means the method can write.
_WRITE_HANDLES = frozenset({"_connection", "_maybe_transaction",
                            "transaction", "_lock", "_set_prune_flag",
                            "_apply_schema", "_migrate"})
#: SQL that changes something. Matched case-insensitively against the
#: leading token of every string literal a method passes to `execute`.
_WRITE_SQL = ("insert", "update", "delete", "replace", "create", "drop",
              "alter", "vacuum")
#: `_read_connection()` is the read-only (`mode=ro`) handle.
_READ_HANDLE = "_read_connection"

#: The forwarded set. Verified against the source by
#: `audit_store_methods()`; do not edit by hand without re-running it.
READ_METHODS: frozenset = frozenset({
    "baseline_bucket_count",
    "baseline_phase_values",
    "baseline_value_rows",
    "checkpoint",
    "command_records",
    "conclusion_by_id",
    "conclusions_between",
    "count_commands",
    "count_conclusions",
    "count_conclusions_with_prompt_ref",
    "count_signal_source_observations",
    "count_signals",
    "count_tl",
    "entity_first_seen",
    "entity_marker",
    "entity_member_sets",
    "entity_members",
    "entity_series_tail",
    "entity_series_values",
    "latest_baseline_bucket",
    "latest_conclusion_at",
    "latest_signal_at",
    "latest_tl_at",
    "max_freshness_horizon",
    "migrated_row_count",
    "oldest_observed_at",
    "read_baseline",
    "rows_at_offsets",
    "signals_between",
    "tl_between",
})

#: Everything else public on `LedgerStore`. Named rather than implied,
#: so that a method added to the store lands in neither set and fails
#: `test_the_two_sets_are_disjoint_and_total` — a default is how G-01
#: happened, so there is no default.
WRITE_METHODS: frozenset = frozenset({
    "append_command",
    "append_conclusion",
    "append_entity_observation",
    "append_signal",
    "append_tl",
    "close",
    "prune_expired",
    # Reads, but through the WRITING connection (`self._conn`), so it is
    # not forwarded. Classifying it as a reader would put the writable
    # handle one attribute away from a read handler for the sake of an
    # integer nothing projects.
    "schema_version",
    "set_checkpoint",
    "touch_entity_marker",
    "transaction",
    "update_baselines",
    "upsert_baseline_value",
    "wipe_migrated_tables",
})


class ReadOnlyLedger:
    """A `LedgerStore` with the write half unreachable by name."""

    __slots__ = ("_store",)

    def __init__(self, store):
        if isinstance(store, ReadOnlyLedger):
            raise DomainError(
                "a ReadOnlyLedger is already read-only; wrapping it twice "
                "hides which object the handler actually holds")
        missing = [name for name in ("latest_tl_at", "latest_conclusion_at")
                   if not callable(getattr(store, name, None))]
        if missing:
            raise DomainError(
                f"ReadOnlyLedger wraps a LedgerStore; the object given is "
                f"missing {missing}")
        object.__setattr__(self, "_store", store)

    def __getattr__(self, name: str):
        if name in READ_METHODS:
            return getattr(self._store, name)
        raise AttributeError(
            f"{name!r} is not readable through a ReadOnlyLedger. A read "
            f"handler holds this object precisely so that the write half "
            f"of the ledger is not reachable from it (A-01).")

    def __setattr__(self, name: str, value) -> None:
        raise DomainError(
            f"a ReadOnlyLedger is immutable; setting {name!r} would let a "
            f"handler graft a writer onto the read seam")

    def __dir__(self):
        return sorted(READ_METHODS)

    def __repr__(self) -> str:
        return f"ReadOnlyLedger<{len(READ_METHODS)} projections>"


def _touches(node) -> tuple[bool, bool, frozenset]:
    """(reads, writes, private helpers called) for one method body."""
    reads = writes = False
    callees: set = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            if child.attr == _READ_HANDLE:
                reads = True
            elif child.attr in _WRITE_HANDLES:
                writes = True
            elif child.attr.startswith("_"):
                callees.add(child.attr)
        elif isinstance(child, ast.Name) and child.id in _WRITE_HANDLES:
            writes = True
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            head = child.value.strip().split(None, 1)
            if head and head[0].lower() in _WRITE_SQL:
                writes = True
    return reads, writes, frozenset(callees)


def _classify_all(methods: dict) -> dict:
    """Fixpoint over the private call graph.

    A public method that delegates to a private helper inherits what the
    helper touches — `entity_series_values` reads through `_entity_rows`
    and would otherwise be classified as a writer by omission, i.e. the
    check would be conservative in the direction that quietly shrinks the
    read surface until a handler starts reaching around it.
    """
    facts = {name: list(_touches(node)) for name, node in methods.items()}
    changed = True
    while changed:
        changed = False
        for name, (reads, writes, callees) in facts.items():
            for callee in callees:
                if callee not in facts:
                    continue
                sub_reads, sub_writes, _ = facts[callee]
                if sub_reads and not reads:
                    facts[name][0] = reads = True
                    changed = True
                if sub_writes and not writes:
                    facts[name][1] = writes = True
                    changed = True
    return {name: ("reader" if reads and not writes else "writer")
            for name, (reads, writes, _) in facts.items()}


def audit_store_methods(read_methods: Optional[Iterable[str]] = None,
                        source: Optional[Path] = None) -> dict:
    """Re-derive the classification from `store.py` and compare.

    Returns `{classified: {name: kind}, misclassified: [...]}`. The suite
    treats a non-empty `misclassified` as a failure, so a `LedgerStore`
    method that starts writing stops being forwarded on the same commit
    the write is added — not on the commit somebody notices.
    """
    whitelist = frozenset(READ_METHODS if read_methods is None
                          else read_methods)
    tree = ast.parse((source or _STORE_SOURCE).read_text(encoding="utf-8"))
    bodies: dict = {}
    public: set = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != _STORE_CLASS:
            continue
        for item in node.body:
            if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            bodies[item.name] = item
            is_property = any(isinstance(dec, ast.Name)
                              and dec.id == "property"
                              for dec in item.decorator_list)
            if not item.name.startswith("_") and not is_property:
                public.add(item.name)
    every = _classify_all(bodies)
    classified = {name: kind for name, kind in every.items()
                  if name in public}
    if not classified:
        raise DomainError(
            f"the audit found no methods on {_STORE_CLASS}; the store "
            f"moved and this check silently stopped checking")
    misclassified = sorted(name for name in whitelist
                           if classified.get(name) != "reader")
    return {"classified": classified, "misclassified": misclassified}


__all__ = ["ReadOnlyLedger", "READ_METHODS", "WRITE_METHODS",
           "audit_store_methods"]
