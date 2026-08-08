"""The typed request, the principal, and the read context.

A handler is a function `(ReadContext, **path_params) -> ApiResponse`. It
never sees a framework object, so the whole handler layer is testable
without a server — which is the point: the legacy surface's endpoint
behaviour could only be exercised by booting Flask, which meant booting
`radar/__init__.py`, which meant ~40 threads and the production database
(B-01).

`ReadContext` is where completion condition 1 becomes a type. It accepts
a `ReadOnlyLedger` and refuses a `LedgerStore` by name, with the reason
in the message, because the next person to try it should be told what
A-01 was rather than be told "wrong type".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from v3.api.readonly import ReadOnlyLedger
from v3.api.vocabulary import METHODS, ROLES
from v3.config.resolution import ConfigResolver
from v3.kernel.errors import DomainError


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is asking. `role` is resolved per request, never from a token.

    S2-API-002 keeps the legacy behaviour deliberately: the role is read
    at request time so revoking a role takes effect without waiting for a
    token to expire. That is an operational property worth the read.
    """

    user_id: str
    role: str

    def __post_init__(self) -> None:
        if not isinstance(self.user_id, str) or not self.user_id.strip():
            raise DomainError("a principal must have a non-empty user id")
        if self.role not in ROLES:
            raise DomainError(
                f"unknown role {self.role!r}: roles are the closed set "
                f"{sorted(ROLES)} declared in v3/api/vocabulary.py, and a "
                f"role invented at a call site is a gate nobody audits")

    @property
    def is_anonymous(self) -> bool:
        return False


class _Anonymous:
    """No principal. A distinct object, so `None` is never a role."""

    __slots__ = ()
    user_id = None
    role = None
    is_anonymous = True

    def __repr__(self) -> str:
        return "ANONYMOUS"


ANONYMOUS = _Anonymous()


@dataclass(frozen=True, slots=True)
class ScenarioRef:
    """What the composition root tells the API about a scenario.

    The API does not read `geo_data.json` — that is the composition
    root's job (`v3/runtime/geo.py`), and a second reader of deployment
    data is a second ledger that drifts.
    """

    scenario_id: str
    participants: Mapping[str, float] = field(default_factory=dict)
    adversaries: tuple[str, ...] = ()
    focused: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, str) or \
                not self.scenario_id.strip():
            raise DomainError("a scenario ref needs a non-empty scenario_id")
        object.__setattr__(self, "participants", dict(self.participants))
        object.__setattr__(self, "adversaries", tuple(self.adversaries))

    def as_dict(self) -> dict:
        return {"scenario_id": self.scenario_id,
                "participants": dict(self.participants),
                "adversaries": list(self.adversaries),
                "focused": self.focused}


@dataclass(frozen=True, slots=True)
class ReadContext:
    """Everything a read handler is allowed to touch.

    Deliberately not on here: a clock function, an HTTP client, a writer,
    or the scoring engine. `now` is a number the composition root passed
    in, so a projection is a pure function of (ledger contents, now) and
    a replay of the same inputs produces the same bytes (NP6).
    """

    ledger: ReadOnlyLedger
    now: float
    scenarios: tuple[ScenarioRef, ...] = ()
    adapters: tuple[str, ...] = ()
    app_config: Mapping[str, Any] = field(default_factory=dict)
    #: v3's 3-layer resolution chain, built by the composition root
    #: (`v3/runtime/config.py`). Optional because a deployment may be
    #: composed without one — and NOT defaulted to an empty resolver,
    #: because an empty chain answers "default" for every key including
    #: the ones the environment sets, which is a confident wrong answer.
    #: R14 and the C7 commands raise rather than guess (`None` reaches
    #: them as `None`).
    config: Optional[Any] = None

    def __post_init__(self) -> None:
        if self.config is not None and not isinstance(self.config,
                                                      ConfigResolver):
            raise DomainError(
                f"a read context's config chain is a ConfigResolver, got "
                f"{type(self.config).__name__}. A hand-rolled resolver is a "
                f"second configuration path, which is what G-15 was.")
        if not isinstance(self.ledger, ReadOnlyLedger):
            raise DomainError(
                f"a read handler takes a ReadOnlyLedger, not a "
                f"{type(self.ledger).__name__}. A-01 was a GET that ran the "
                f"scoring tick and appended to the ledger; the remedy is "
                f"that the write half is not reachable from here, not that "
                f"handlers are asked to remember.")
        if isinstance(self.now, bool) or not isinstance(self.now,
                                                        (int, float)):
            raise DomainError(f"now must be a timestamp, got {self.now!r}")
        object.__setattr__(self, "now", float(self.now))
        object.__setattr__(self, "scenarios", tuple(self.scenarios))
        object.__setattr__(self, "adapters", tuple(self.adapters))
        object.__setattr__(self, "app_config", dict(self.app_config))

    def scenario(self, scenario_id: str) -> Optional[ScenarioRef]:
        for ref in self.scenarios:
            if ref.scenario_id == scenario_id:
                return ref
        return None


@dataclass(frozen=True, slots=True)
class ApiRequest:
    """One inbound call, framework-free."""

    method: str
    path: str
    params: Mapping[str, str] = field(default_factory=dict)
    body: Mapping[str, Any] = field(default_factory=dict)
    principal: Any = ANONYMOUS

    def __post_init__(self) -> None:
        if self.method not in METHODS:
            raise DomainError(
                f"unsupported method {self.method!r}; the surface uses "
                f"{sorted(METHODS)}")
        if not isinstance(self.path, str) or not self.path.startswith("/"):
            raise DomainError(f"path must be absolute, got {self.path!r}")
        object.__setattr__(self, "params", dict(self.params))
        object.__setattr__(self, "body", dict(self.body))
        if not (self.principal is ANONYMOUS
                or isinstance(self.principal, Principal)):
            raise DomainError(
                "principal must be a Principal or ANONYMOUS; a bare dict "
                "here is how a role becomes whatever the client sent")


__all__ = ["ApiRequest", "Principal", "ANONYMOUS", "ReadContext",
           "ScenarioRef"]
