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
    #: `{country: role}`. Carried because C6 rebuilds the kernel's
    #: scenarios from these refs rather than from `geo_data.json`, and a
    #: contribution whose role came back empty would differ from the tick's
    #: for a reason that has nothing to do with the counterfactual.
    roles: Mapping[str, str] = field(default_factory=dict)
    #: Which belligerent owns the sequence chain. NOT derived, for the
    #: reason `v3/runtime/scoring.py::scenarios_for` gives: production
    #: picks it by live spike, and any static rule picks the same country
    #: forever — wrong for exactly the scenario that motivates the field
    #: (middle_east has IL and IR both at weight 1.0). The composition root
    #: supplies it to the tick and supplies it here, so a counterfactual
    #: and the tick score the same scenario the same way.
    chain_country: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, str) or \
                not self.scenario_id.strip():
            raise DomainError("a scenario ref needs a non-empty scenario_id")
        object.__setattr__(self, "participants", dict(self.participants))
        object.__setattr__(self, "adversaries", tuple(self.adversaries))
        object.__setattr__(self, "roles", dict(self.roles))

    def as_dict(self) -> dict:
        return {"scenario_id": self.scenario_id,
                "participants": dict(self.participants),
                "adversaries": list(self.adversaries),
                "focused": self.focused,
                "roles": dict(self.roles),
                "chain_country": self.chain_country}


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
    #: WHO is reading, stamped by the dispatcher after authorization.
    #: Needed because R6 is a per-reader projection — the ack state on a
    #: row and the score floor that decides whether it surfaces are the
    #: caller's own — and a projection that guessed the reader would serve
    #: one analyst another's decisions. Defaults to ANONYMOUS rather than
    #: to a user id, so a context nobody stamped cannot impersonate.
    principal: Any = None
    #: The request body, and ONLY for a declared dry run (P7 C6) or a
    #: session route (P7 C13). A GET has no body and a command's body
    #: lives on the `WriteContext`, so this stays empty for every other
    #: route — a body reachable from an ordinary read context would be an
    #: input nobody declared.
    body: Mapping[str, Any] = field(default_factory=dict)
    #: The composition root's auth provider (`v3.auth.session.AuthProvider`)
    #: or None. Optional and NOT defaulted to a permissive stand-in, for
    #: the same reason `config` is not defaulted to an empty resolver: a
    #: deployment composed without signing material must answer 503 on the
    #: session routes rather than authenticate against nothing. v3 never
    #: generates a key — production generates and PERSISTS one, and a
    #: second generator racing that file would log every live analyst out.
    auth: Optional[Any] = None
    #: The composition root's ops probe result (`v3.runtime.ops_health`),
    #: or None. A deployment fact rather than a ledger projection: a file
    #: size and a marker's mtime are things only the layer that chose the
    #: paths can see, and a read handler that stat()ed a path would be a
    #: projection no `ReadOnlyLedger` could reproduce. `None` is served as
    #: four monitors that each say why they are absent, never as silence.
    ops_health: Optional[Any] = None
    #: WHERE the call came from, stamped by the dispatcher from the
    #: transport. Never from the body: the login guard counts failures per
    #: source, and a client-supplied address would let one caller occupy a
    #: fresh bucket per attempt.
    client_ip: Optional[str] = None

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
        if not isinstance(self.body, Mapping):
            raise DomainError("a read context's body must be a mapping")
        object.__setattr__(self, "body", dict(self.body))
        if self.auth is not None and not hasattr(self.auth, "authority"):
            raise DomainError(
                f"a read context's auth seam is an AuthProvider, got "
                f"{type(self.auth).__name__}. Duck-typed rather than "
                f"imported because `v3.auth` imports this module; the "
                f"attribute checked is the one that holds the signing key.")
        if self.principal is None:
            object.__setattr__(self, "principal", ANONYMOUS)
        elif not (self.principal is ANONYMOUS
                  or isinstance(self.principal, Principal)):
            raise DomainError(
                f"a read context's principal is a Principal or ANONYMOUS, "
                f"got {type(self.principal).__name__}: a bare string here is "
                f"how a per-reader projection comes to serve whoever the "
                f"caller claimed to be")

    @property
    def actor_id(self) -> Optional[str]:
        """WHO is reading, and deliberately not what they may do.

        A per-reader projection needs an identity; it must never need a
        role. G-01 was a permission decision living in a handler body, so
        the suite refuses the whole role vocabulary — `principal` included
        — anywhere under `v3/api/handlers/`. This property is the identity
        WITHOUT the decision: a handler can say "whose acknowledgements are
        these" and has no way to say "and may they".
        """
        principal = self.principal
        if principal is None or getattr(principal, "is_anonymous", True):
            return None
        return principal.user_id

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
    #: The transport's view of the caller's address. The binding fills it;
    #: nothing else may, and no handler may read it from the body.
    client_ip: Optional[str] = None

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
