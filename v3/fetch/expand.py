"""Placeholder expansion — declared template to concrete request.

Design sheet §2-1, ruling 4 (WP-2.5 retroactive). Six ported adapters
declare `{country}`, `{lat}`, `{since_iso}` and friends, and until this
module existed **nothing substituted them**: the braces went on the wire
literally. K02 records that AISHub answers a rejected request with HTTP
200 and an empty body, so that failure would have been recorded as a
successful fetch that found nothing — the shape NP1 exists to forbid.

**Why here and not in the composition root.** The same argument as the
HTTP client (§1-4). A substitution each caller performs is a substitution
each caller can get wrong, and getting it wrong produces a request that
succeeds and answers about nothing. One expander, one refusal path, one
place to read.

**What the caller supplies.** An `ExpansionInput`: run-wide values
(`common`) plus zero or more `ExpansionScope`s. One scope becomes one
concrete request — which is how §3-5 H-1 (N named ISR zones per country,
each its own bounding box) becomes expressible from a single declared
spec. A spec whose text does not vary across the scopes is recognised as
a single global request and fetched **once**, not N identical times.

**Unresolved placeholders raise.** `run_due` converts the refusal into a
recorded skip so one misconfigured adapter cannot take a cycle down, but
the refusal itself is loud, because a `{country}` that reaches the wire
is invisible afterwards.

This module performs no I/O, holds no credentials, and imports nothing
outside the kernel — auth material is applied by `client.py` at request
time and never appears in a plan.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence

from v3.adapters.types import (FALLBACK_ON_FAILURE, RequestChain,
                               RequestContinuation, RequestSpec, ResponseValue)
from v3.kernel.errors import DomainError

#: `{name}` where name is a lower_snake_case identifier. Doubled braces
#: (`{{`/`}}`) escape to a literal brace, so a body value that genuinely
#: contains one is expressible.
_PLACEHOLDER = re.compile(r"(?<!\{)\{([a-z_][a-z0-9_]*)\}(?!\})")
_ESCAPED_OPEN = "{{"
_ESCAPED_CLOSE = "}}"


@dataclass(frozen=True, slots=True)
class ExpansionScope:
    """One substitution set. One scope becomes one concrete request.

    `scope_key` names what this scope IS — `"TW"`, `"TW/strait_midline"`,
    `"malacca"`. It travels into the plan and the fetch record so that a
    later reader can tell which of N requests a row describes. It is
    `scope_key` rather than `key` because this module sits next to one
    that means API credential by "key", and `ResolvedStep` already spells
    the same value this way.
    """

    values: Mapping[str, str] = field(default_factory=dict)
    scope_key: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.values, Mapping):
            raise DomainError(
                f"ExpansionScope values must be a mapping of placeholder "
                f"name to string, got {type(self.values).__name__}")
        for name, value in self.values.items():
            if callable(value):
                raise DomainError(
                    f"ExpansionScope value {name!r} is callable; an "
                    f"expansion input is data, not a computation")
        object.__setattr__(self, "values",
                           MappingProxyType(dict(self.values)))

    __hash__ = None


@dataclass(frozen=True, slots=True)
class ExpansionInput:
    """Everything one adapter needs substituted for one run.

    `common` holds run-wide values (`{since_iso}`, `{until_iso}`) so they
    are not repeated into every scope, where they could disagree.
    """

    scopes: tuple = ()
    common: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        scopes = tuple(self.scopes)
        for scope in scopes:
            if not isinstance(scope, ExpansionScope):
                raise DomainError(
                    f"ExpansionInput scopes hold ExpansionScope values, got "
                    f"{type(scope).__name__}")
        object.__setattr__(self, "scopes", scopes)
        if not isinstance(self.common, Mapping):
            raise DomainError("ExpansionInput common must be a mapping")
        object.__setattr__(self, "common",
                           MappingProxyType(dict(self.common)))

    def resolved_scopes(self) -> tuple:
        """The scopes to expand over, with `common` merged underneath.

        A scope value beats a common value: the specific statement wins
        over the run-wide default.
        """
        if not self.scopes:
            return (ExpansionScope(values=dict(self.common)),)
        return tuple(
            ExpansionScope(values={**dict(self.common), **dict(scope.values)},
                           scope_key=scope.scope_key)
            for scope in self.scopes)

    __hash__ = None


@dataclass(frozen=True, slots=True)
class ResolvedContinuation:
    """The second half of "A then B(A)", still holding its carried slots.

    `spec` is expanded for everything the scope knew — `{country}`, dates,
    coordinates — and deliberately NOT for the placeholders in `carries`,
    because those values do not exist until the first response arrives.
    `carried_slots` names exactly which ones were left, so nothing has to
    re-derive that from the text.
    """

    spec: RequestSpec
    carries: tuple = ()
    delay_sec: float = 0.0
    reason: str = ""

    @property
    def carried_slots(self) -> frozenset:
        return frozenset(value.placeholder for value in self.carries)

    __hash__ = None


@dataclass(frozen=True, slots=True)
class ResolvedStep:
    """One concrete unit of work: try `alternatives` in order.

    A plain `RequestSpec` becomes a step of one alternative; a
    `RequestChain` becomes a step of N, and `advance_on` says when the
    kernel moves from one to the next. The runner never sees a template.

    A `RequestContinuation` becomes a step of ONE alternative plus a
    `continuation`: the first request is fetched like any other, and only
    then does the second one acquire an address. Keeping it out of
    `alternatives` is what stops the runner treating it as a fallback —
    "A or B" and "A then B(A)" would otherwise be the same shape, and the
    difference is whether the second request is fetched when the first one
    SUCCEEDS or when it FAILS.
    """

    alternatives: tuple
    advance_on: str = FALLBACK_ON_FAILURE
    reason: str = ""
    scope_key: str = ""
    continuation: Optional[ResolvedContinuation] = None

    @property
    def is_chain(self) -> bool:
        return len(self.alternatives) > 1

    @property
    def is_continued(self) -> bool:
        return self.continuation is not None

    @property
    def primary(self) -> RequestSpec:
        return self.alternatives[0]

    __hash__ = None


# ── reading a template ──────────────────────────────────────────────────

def _names_in(text: Any) -> set:
    if not isinstance(text, str):
        return set()
    return set(_PLACEHOLDER.findall(text))


def placeholders_in(spec: RequestSpec) -> frozenset:
    """Every placeholder name the spec uses, anywhere."""
    names: set = set()
    names |= _names_in(spec.url)
    names |= _names_in(spec.label)
    for key, value in spec.params:
        names |= _names_in(key) | _names_in(value)
    for key, value in spec.headers.items():
        names |= _names_in(key) | _names_in(value)
    if spec.body is not None:
        for key, value in spec.body.items():
            names |= _names_in(key) | _names_in(value)
    return frozenset(names)


def _substitute(text: Any, scope: ExpansionScope, *, spec: RequestSpec,
                where: str, deferred: frozenset = frozenset()) -> Any:
    """Resolve one string. Anything unresolved is an error, never a guess.

    `deferred` names placeholders the caller has PROMISED to fill later —
    the values a `RequestContinuation` lifts out of its first response.
    They are left as written rather than resolved or refused, because at
    plan time "not yet known" and "nobody supplied it" are different
    facts and only the second one is a defect.
    """
    if not isinstance(text, str):
        return text
    missing = _names_in(text) - set(scope.values) - deferred
    if missing:
        raise DomainError(
            f"unresolved placeholder(s) {sorted(missing)} in {where} of "
            f"request {spec.label or spec.url!r}"
            + (f" (scope {scope.scope_key!r})" if scope.scope_key else "")
            + f"; the scope supplied {sorted(scope.values)}. An unexpanded "
              f"placeholder goes on the wire literally, and K02 records "
              f"that a rejected request can answer HTTP 200 with an empty "
              f"body — a failure that reads as 'nothing there'.")

    def _replace(match: re.Match) -> str:
        name = match.group(1)
        if name in deferred and name not in scope.values:
            return match.group(0)          # left for the continuation
        value = scope.values[name]
        if not isinstance(value, str):
            raise DomainError(
                f"expansion value {match.group(1)!r} must be a string, got "
                f"{type(value).__name__}: the wire carries text, and "
                f"coercing here would hide a float's formatting from the "
                f"declaration that has to match production")
        return value

    resolved = _PLACEHOLDER.sub(_replace, text)
    return resolved.replace(_ESCAPED_OPEN, "{").replace(_ESCAPED_CLOSE, "}")


def expand_spec(spec: RequestSpec, scope: ExpansionScope, *,
                deferred: frozenset = frozenset()) -> RequestSpec:
    """One declared spec plus one scope becomes one concrete request."""
    if not isinstance(spec, RequestSpec):
        raise DomainError(
            f"expand_spec takes a RequestSpec, got {type(spec).__name__}")
    if not isinstance(scope, ExpansionScope):
        raise DomainError(
            f"expand_spec takes an ExpansionScope, got "
            f"{type(scope).__name__}")

    def resolve(text, where: str):
        return _substitute(text, scope, spec=spec, where=where,
                           deferred=deferred)

    return spec.substituted(
        url=resolve(spec.url, "url"),
        params=tuple((resolve(key, "a parameter name"),
                      resolve(value, f"parameter {key!r}"))
                     for key, value in spec.params),
        headers={resolve(key, "a header name"):
                 resolve(value, f"header {key!r}")
                 for key, value in spec.headers.items()},
        body=None if spec.body is None else {
            resolve(key, "a body key"): resolve(value, f"body {key!r}")
            for key, value in spec.body.items()},
        label=resolve(spec.label, "the label"))


# ── fan-out ─────────────────────────────────────────────────────────────

def _alternatives_of(declared) -> tuple:
    if isinstance(declared, RequestContinuation):
        return (declared.first,)
    if isinstance(declared, RequestChain):
        return declared.alternatives
    return (declared,)


def _identity(specs: Sequence[RequestSpec]) -> tuple:
    """A comparable summary of what would actually go on the wire."""
    return tuple((spec.url, spec.params, tuple(sorted(spec.headers.items())),
                  spec.body_bytes(), spec.label) for spec in specs)


# ── continuations ───────────────────────────────────────────────────────

def _lookup(document: Any, path: Sequence) -> Any:
    """Walk a declared path into a decoded document, or return None."""
    current = document
    for key in path:
        if isinstance(key, int) and not isinstance(key, bool):
            if not isinstance(current, (list, tuple)) or \
                    not -len(current) <= key < len(current):
                return None
            current = current[key]
            continue
        if not isinstance(current, Mapping):
            return None
        if key not in current:
            return None
        current = current[key]
    return current


def carried_values(continuation: ResolvedContinuation, document: Any
                   ) -> tuple:
    """`(values, missing)` — what the first response yielded, and what it did not.

    PURE, and separated from the fetch on purpose: "the handshake did not
    return a handle" is a fact a test can produce without a socket, and
    `radar/sensors/checkhost.py:62-63` shows it is a real branch
    (`if not request_id: ... "no request_id"`), not a theoretical one.

    A value is stringified here because that is what a URL carries. The
    coercion is deliberate and narrow — numbers and strings only. A list
    or an object where a handle was promised means the upstream changed
    shape, and formatting it into a URL would send a plausible-looking
    request about nothing.
    """
    values: dict = {}
    missing: list = []
    for carried in continuation.carries:
        found = _lookup(document, carried.path)
        if found is None or isinstance(found, (Mapping, list, tuple)) \
                or isinstance(found, bool):
            if carried.required:
                missing.append(carried.placeholder)
            continue
        text = str(found)
        if not text:
            if carried.required:
                missing.append(carried.placeholder)
            continue
        values[carried.placeholder] = text
    return (values, tuple(missing))


def continue_with(continuation: ResolvedContinuation,
                  values: Mapping[str, str]) -> RequestSpec:
    """The second request, now that the first one has answered."""
    return expand_spec(continuation.spec,
                       ExpansionScope(values=dict(values)))


def expand_requests(declared: Sequence, expansion: Optional[ExpansionInput] = None
           ) -> tuple:
    """Declared requests plus one run's inputs become concrete steps.

    A declaration whose text does not vary across the supplied scopes is a
    GLOBAL request and yields ONE step: `usgs_seismic` asks the world a
    single question, and five countries in scope must not become five
    identical queries against a rate-limited source.
    """
    inputs = expansion or ExpansionInput()
    if not isinstance(inputs, ExpansionInput):
        raise DomainError(
            f"expand takes an ExpansionInput, got {type(inputs).__name__}")
    scopes = inputs.resolved_scopes()

    steps: list = []
    for item in declared:
        alternatives = _alternatives_of(item)
        advance_on = getattr(item, "advance_on", FALLBACK_ON_FAILURE)
        reason = getattr(item, "reason", "")

        followed = item if isinstance(item, RequestContinuation) else None
        deferred = (frozenset(value.placeholder for value in followed.carries)
                    if followed is not None else frozenset())

        # first occurrence wins, so declaration order survives
        seen: dict = {}
        for scope in scopes:
            concrete = tuple(expand_spec(spec, scope) for spec in alternatives)
            tail = (None if followed is None else ResolvedContinuation(
                spec=expand_spec(followed.then, scope, deferred=deferred),
                carries=followed.carries, delay_sec=followed.delay_sec,
                reason=followed.reason))
            # The follow-up's address is part of what makes two expansions
            # different: two scopes can produce the same first request and
            # different second ones, and folding those together would drop
            # a fetch that was supposed to happen.
            key = (_identity(concrete),
                   None if tail is None else _identity((tail.spec,)))
            if key in seen:
                seen[key][2].append(scope)
                continue
            seen[key] = (concrete, tail, [scope])

        for concrete, tail, owning_scopes in seen.values():
            # Attributed to a scope only when it belongs to exactly one.
            # A request several scopes produce identically is not "the TW
            # request"; claiming otherwise would put a country on a row
            # that answers about all of them.
            scope_key = (owning_scopes[0].scope_key
                         if len(owning_scopes) == 1 else "")
            steps.append(ResolvedStep(alternatives=concrete,
                                      advance_on=advance_on, reason=reason,
                                      scope_key=scope_key, continuation=tail))
    return tuple(steps)


__all__ = ["ExpansionScope", "ExpansionInput", "ResolvedStep",
           "ResolvedContinuation", "placeholders_in", "expand_spec",
           "expand_requests", "carried_values", "continue_with"]
