"""The write seam. A command handler never holds this; the context does.

`ReadOnlyLedger` exists because A-01 was a GET that scored. This is its
mirror, and it has its own defect history:

* **G-01** — one of four feedback endpoints forgot `_require_analyst()`,
  on the path that feeds the calibration chain whose three disasters were
  all label contamination.
* **E-17** — a guard suppressed a conclusion and left no trace, because
  the suppression had nowhere to be written.
* **G-15** — an analyst changed a value, an override row and an audit row
  were both written honestly, the UI showed the new value, and nothing
  read it.

A raw `LedgerStore` handle in a command handler reproduces all three
conditions: a handler can append whatever it likes, record nothing, and
return 200. `CommandLedger` forwards exactly one method — `append_command`
— and the audit of that method is not "we listed the safe one" but two
AST facts about the store's source:

1. `append_command` writes `command_record` and NOTHING else, so the one
   forwarded door cannot quietly gain a second room.
2. NO OTHER store method writes `command_record`, so a row in the decision
   trail can only have arrived through this door.

Fact 2 is only as good as the set of methods the audit can see, and since
WP-4.1d `LedgerStore` spans three modules (the 800-line house limit). So
the parse goes through `v3/api/store_source.py`, which follows the class's
declared base chain and refuses to return a chain it cannot follow or one
smaller than the recorded floor. A second writer hidden in an unparsed
module would otherwise satisfy this audit exactly.

Together those make "every change to what the command surface governs is
an audit row" a property of the code rather than of a review checklist —
because the effective state IS the fold of those rows (see
`v3/commands/state.py`), so a change without a row is not a change.

LIMITATION, stated the same way the read seam states its own: this object
holds the store in an attribute and Python has no attribute introspection
cannot reach. The point is that the ordinary path — the one a handler
writes without thinking — leads to `commit()` and nowhere else.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional, Sequence

from v3.api.store_source import STORE_CLASS as _STORE_CLASS
from v3.api.store_source import class_methods
from v3.kernel.errors import DomainError

#: The one table the command surface may write.
COMMAND_TABLE = "command_record"

#: The one method that writes it. A frozenset of one, spelled as a set so
#: that a second entry is a visible edit rather than a changed string.
COMMAND_METHODS: frozenset = frozenset({"append_command"})

#: `INSERT INTO x`, `UPDATE x`, `DELETE FROM x`, `REPLACE INTO x`.
_WRITE_STATEMENT = re.compile(
    r"\b(?:insert\s+(?:or\s+\w+\s+)?into|replace\s+into|update|delete\s+from)"
    r"\s+[\"'`]?(\w+)", re.IGNORECASE)


class CommandLedger:
    """A `LedgerStore` reduced to the single door a command goes through."""

    __slots__ = ("_store",)

    def __init__(self, store):
        if isinstance(store, CommandLedger):
            raise DomainError(
                "a CommandLedger is already narrowed; wrapping it twice "
                "hides which object the seam actually holds")
        missing = [name for name in sorted(COMMAND_METHODS)
                   if not callable(getattr(store, name, None))]
        if missing:
            raise DomainError(
                f"CommandLedger wraps a LedgerStore; the object given is "
                f"missing {missing}")
        object.__setattr__(self, "_store", store)

    def __getattr__(self, name: str):
        if name in COMMAND_METHODS:
            return getattr(self._store, name)
        raise AttributeError(
            f"{name!r} is not reachable through a CommandLedger. The "
            f"command surface writes one table, through one method, and "
            f"the row it writes IS the change (S2-PROP-019). Reaching any "
            f"other writer would be a change with no audit row, which is "
            f"the G-15 shape.")

    def __setattr__(self, name: str, value) -> None:
        raise DomainError(
            f"a CommandLedger is immutable; setting {name!r} would let a "
            f"handler graft a second writer onto the command seam")

    def __dir__(self):
        return sorted(COMMAND_METHODS)

    def __repr__(self) -> str:
        return f"CommandLedger<{COMMAND_TABLE}>"


def _method_bodies(source: Optional[Path] = None,
                   extra_sources: Optional[Sequence[Path]] = None) -> dict:
    """Every method on the class, across every module the chain reaches.

    Delegated to `v3/api/store_source.py` since the store was split for
    the 800-line limit. The delegation is the point: a writer of
    `command_record` hidden in a module this file did not parse would
    satisfy `writers == ["append_command"]` while a second door stood
    open, and nothing would have failed.
    """
    bodies = class_methods(root=source, extra_sources=extra_sources)
    if not bodies:
        raise DomainError(
            f"the audit found no methods on {_STORE_CLASS}; the store moved "
            f"and this check silently stopped checking")
    return bodies


def _tables_written(node) -> frozenset:
    """Every table a method's SQL literals mutate."""
    tables: set = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            for match in _WRITE_STATEMENT.finditer(child.value):
                tables.add(match.group(1).lower())
    return frozenset(tables)


def audit_command_writes(source: Optional[Path] = None,
                         extra_sources: Optional[Sequence[Path]] = None
                         ) -> dict:
    """The two AST facts the seam's promise rests on.

    Returns `{writers: [...], extra_tables: [...]}`. `writers` is every
    store method whose SQL mutates `command_record`; `extra_tables` is
    every OTHER table the forwarded method touches. The suite requires
    `writers == sorted(COMMAND_METHODS)` and `extra_tables == []`, so
    either half drifting is a red build on the commit that drifts it.
    """
    bodies = _method_bodies(source, extra_sources)
    writers = sorted(name for name, node in bodies.items()
                     if COMMAND_TABLE in _tables_written(node))
    extra: set = set()
    for name in COMMAND_METHODS:
        if name not in bodies:
            raise DomainError(
                f"{name!r} is forwarded by CommandLedger but does not exist "
                f"on {_STORE_CLASS}: the seam forwards a method that is not "
                f"there, so nothing would be audited at all")
        extra |= (_tables_written(bodies[name]) - {COMMAND_TABLE})
    return {"writers": writers, "extra_tables": sorted(extra)}


__all__ = ["CommandLedger", "COMMAND_METHODS", "COMMAND_TABLE",
           "audit_command_writes"]
