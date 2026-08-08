"""`WriteContext` — what a command handler is handed, and nothing else.

The read side has three barriers because A-01 was real. The write side has
its own history and it is worse: **G-01** (one endpoint of four forgetting
the authorization call, on the path feeding the calibration chain whose
three disasters were all label contamination), **E-17** (a guard
suppressed a conclusion and left no trace), **G-15** (an analyst changed a
value, an override row and an audit row were written, the UI showed the
new value, and nothing read it).

Four properties answer those, and each is a type or a check rather than a
rule someone follows:

1. **The principal arrives resolved.** The route declares access
   (`v3/api/routes.py`), the dispatcher evaluates it, and this context
   carries the result. There is no decision inside a handler to forget —
   G-01's shape needs a decision to be forgettable.
2. **The audit row is the commit.** `commit()` takes a `Change` and
   builds the `CommandRecord` itself; a handler holds no other writer,
   because `CommandLedger` forwards `append_command` and nothing else. So
   "one change, one audit row" (S2-PROP-019) is not a discipline — there
   is no way to express a change that is not one.
3. **The handler never states the state.** `Change` carries intent
   (action, target, payload), not `before`/`after`. Both are computed
   HERE, by the registry's resolver, through the read seam the read side
   uses. A command therefore cannot project one state and write against
   another; there is only one projection.
4. **The claimed effect is verified.** After appending, `commit()` re-runs
   the resolver and refuses if the state did not become what the command
   said. That is the direct answer to G-15: a write nothing reads fails
   here, loudly, instead of returning 200 while the UI repeats the lie.

`Change` deliberately has no actor field. A handler cannot record an actor
other than the one the route resolved, because it has nothing to record it
with.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from v3.api import errors as E
from v3.api.request import Principal, ReadContext
from v3.api.writeonly import CommandLedger
from v3.commands import spec as SPEC
from v3.ledger.records import CommandRecord
from v3.kernel.errors import DomainError


@dataclass(frozen=True, slots=True)
class Change:
    """A handler's declared intent. Note what is absent: who, when, and
    what the state was — none of which a handler is trusted to state."""

    action: str
    target: SPEC.Target
    payload: Mapping[str, Any] = field(default_factory=dict)
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.target, SPEC.Target):
            raise DomainError(
                f"a change targets a commands.Target, got "
                f"{type(self.target).__name__}: an untyped target is a row "
                f"no fold picks up")
        if not isinstance(self.payload, Mapping):
            raise DomainError("a change payload must be a mapping")
        object.__setattr__(self, "payload", dict(self.payload))


@dataclass(frozen=True, slots=True)
class Committed:
    """The outcome of one command, including what the state actually is.

    `effective` is read back through the resolver AFTER the append — not
    echoed from the request. A response built from `after` alone would be
    a claim; built from `effective` it is an observation.
    """

    record: CommandRecord
    sequence: int
    effective: Any
    effect_key: str

    @property
    def changed(self) -> bool:
        return self.record.changed

    def as_dict(self) -> dict:
        return {"command": self.record.as_dict(), "sequence": self.sequence,
                "changed": self.changed,
                "effect": {self.effect_key: self.effective}}


class CommandJournal:
    """What this request committed. The dispatcher counts it.

    Mutable by design and deliberately tiny: the count is how
    "a command route commits exactly one audit row" is checked from
    outside the handler, which is the only place it can be checked without
    trusting the handler.
    """

    __slots__ = ("records",)

    def __init__(self) -> None:
        self.records: list = []

    def __len__(self) -> int:
        return len(self.records)


@dataclass(frozen=True, slots=True)
class WriteContext:
    """Everything a command handler may touch.

    Deliberately not on here: a clock, an HTTP client, the scoring engine,
    or any ledger writer other than the command door. `now` is a number
    the composition root passed in, so a command's record is a pure
    function of (request, ledger contents, now) — replayable, which is
    what AP4 needs from a decision trail.
    """

    read: ReadContext
    ledger: CommandLedger
    principal: Principal
    #: The request body, put here by the dispatcher rather than passed as
    #: a handler argument: a command's input is a document, and threading
    #: it through `**kwargs` alongside path params is how an unknown key
    #: comes to be accepted in silence (`PUT /api/auth/settings`).
    body: Mapping[str, Any] = field(default_factory=dict)
    journal: CommandJournal = field(default_factory=CommandJournal)

    def __post_init__(self) -> None:
        if not isinstance(self.read, ReadContext):
            raise DomainError(
                f"a command's reads go through a ReadContext, got "
                f"{type(self.read).__name__}. Commands read the SAME "
                f"projection the read surface serves; a second read path is "
                f"how a command comes to write against a state nobody else "
                f"can see.")
        if not isinstance(self.ledger, CommandLedger):
            raise DomainError(
                f"a command handler writes through a CommandLedger, not a "
                f"{type(self.ledger).__name__}. The seam forwards one "
                f"method, and the row it writes IS the change (S2-PROP-019); "
                f"a raw store here is a change with no audit row, which is "
                f"the G-15 shape.")
        if not isinstance(self.principal, Principal):
            raise DomainError(
                "a command always has an actor. ANONYMOUS is refused here "
                "rather than defaulted, because an audit row whose actor is "
                "'unknown' answers none of the questions AP4 asks of it.")
        if not isinstance(self.body, Mapping):
            raise DomainError("a command body must be a mapping")
        object.__setattr__(self, "body", dict(self.body))

    @property
    def now(self) -> float:
        return self.read.now

    def commit(self, change: Change) -> Committed:
        """Resolve, apply, append, verify. The only write in the surface."""
        if not isinstance(change, Change):
            raise DomainError(
                f"commit takes a Change, got {type(change).__name__}")
        spec = SPEC.spec_for(change.action)
        if spec.target_kind != change.target.kind:
            raise DomainError(
                f"{change.action} acts on a {spec.target_kind}, but the "
                f"target is a {change.target.kind}")
        reason = _reason_for(spec, change)
        actor = self.principal
        before = self._resolve(spec, change.target)
        try:
            after = spec.apply(before, target_id=change.target.id,
                               payload=dict(change.payload),
                               actor_id=actor.user_id, at=self.now,
                               config=self.read.config)
        except DomainError as exc:
            # An `apply` refusal is the caller's fault, not the server's:
            # it is a payload the vocabulary does not admit. Surfacing it
            # as a 500 would tell the analyst the tool broke.
            raise E.bad_request(str(exc), action=change.action) from exc
        record = CommandRecord(
            command_id=self._command_id(change, after),
            action=change.action, target_kind=change.target.kind,
            target_id=change.target.id, actor_id=actor.user_id,
            actor_role=actor.role, issued_at=self.now, before=before,
            after=after, reason=reason, payload=dict(change.payload))
        sequence = self.ledger.append_command(record)
        effective = self._resolve(spec, change.target)
        if effective != after:
            # THE G-15 check. The command claimed a state and the serving
            # path does not agree, which means the write did not take
            # effect where anything reads it. Failing here is the whole
            # point: G-15's damage was that this case returned 200.
            raise DomainError(
                f"{change.action} on {change.target.kind}:{change.target.id} "
                f"reported an effect the read path does not show. Committed "
                f"{after!r}; reading back through the same projection the "
                f"API serves gives {effective!r}. A change nothing reads is "
                f"defect G-15, and it is refused rather than reported.")
        committed = Committed(record=record, sequence=sequence,
                              effective=effective,
                              effect_key=spec.effect_key)
        self.journal.records.append(committed)
        return committed

    def _resolve(self, spec, target):
        """The one projection, plus the one resolution chain.

        `config` is threaded from the read context rather than reached for,
        so a command that resolves a configured value resolves it through
        the chain the read surface serves — the same "there is only one
        projection to be right or wrong about" property, extended to the
        layer G-15 actually broke.
        """
        return spec.resolve(self.read.ledger, target_id=target.id,
                            actor_id=self.principal.user_id,
                            until=self.now, config=self.read.config)

    def _command_id(self, change: Change, after) -> str:
        """Deterministic identity, derived rather than random.

        A uuid4 would make the log un-replayable: NP6 asks that a derived
        value be reproducible from its inputs, and an id is a derived
        value. The material includes how many commands of this action
        already exist for this target, so two genuine commands at one
        instant (a fixed clock in a test, a double-submit in production)
        get different ids rather than colliding on the UNIQUE constraint.
        """
        prior = len(self.read.ledger.command_records(
            action=change.action, target_id=change.target.id, until=self.now))
        material = "\x1f".join([
            change.action, change.target.kind, change.target.id,
            self.principal.user_id, f"{self.now:.6f}", str(prior),
            json.dumps(after, sort_keys=True, default=str,
                       ensure_ascii=False),
        ])
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _reason_for(spec, change: Change) -> Optional[str]:
    stated = change.reason
    if stated is not None and not str(stated).strip():
        stated = None
    if spec.requires_reason and stated is None:
        raise E.bad_request(
            f"{change.action} は理由の記載を必須とします"
            f"（較正災害 3 件はすべてラベル汚染でした）",
            action=change.action, field="reason")
    return None if stated is None else str(stated).strip()


__all__ = ["Change", "Committed", "CommandJournal", "WriteContext"]
