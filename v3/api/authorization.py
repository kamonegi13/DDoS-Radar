"""Authorization as a declaration on the route. Never a call in a body.

G-01, in full: `/api/v2/conclusions/<id>/feedback` came in four variants;
three called `_require_analyst()` and the fourth did not. Nothing failed
and nothing logged, because an absent call and an unnecessary call look
identical in a diff. The defect was not the missing line — it was that
the enforcement could live in a body at all.

So it cannot, here. `Access` is a required field of `Route` (no default),
the two ways to build one are explicit constructors that each demand a
reason, and `tests/test_api_authorization.py` AST-scans every handler
module for role vocabulary. A handler that tried to make the decision
would fail the suite before it could forget to.

Order matters as much as presence. S2-PROP-016 fixes it at
503 -> 401 -> 403 -> 400/404 -> 200: an unauthenticated caller is told
401 whether or not their role would have sufficed, and a caller who is
merely not permitted never learns whether the resource exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from v3.api.errors import (ApiError, ApiFailure, FORBIDDEN, UNAUTHENTICATED)
from v3.api.vocabulary import (ROLE_ADMIN, ROLE_ANALYST, ROLE_ORDER,
                               ROLE_VIEWER, ROLES)
from v3.kernel.errors import DomainError


def role_is_at_least(role: str, minimum: str) -> bool:
    """Containment expressed through THE order (S2-PROP-021).

    Not `role in ("admin", "analyst")`, which is the spelling the legacy
    system repeated thirteen times, and not an integer rank, which is the
    spelling that lets a caller do its own arithmetic.
    """
    for name in (role, minimum):
        if name not in ROLES:
            raise DomainError(
                f"unknown role {name!r}: ranking an unknown role is how a "
                f"typo becomes a privilege")
    return ROLE_ORDER.index(role) >= ROLE_ORDER.index(minimum)


@dataclass(frozen=True, slots=True)
class Access:
    """The authorization decision for exactly one route.

    There is no default and no "unset". `public` is a decision with a
    stated reason, which is the difference between "we thought about it"
    and "nobody wrote a decorator".
    """

    public: bool
    minimum_role: Optional[str]
    reason: str

    def __post_init__(self) -> None:
        if self.public and self.minimum_role is not None:
            raise DomainError(
                "a route is public or role-gated, never both: two answers "
                "to one question is how the evaluation order got decided "
                "per-endpoint (S2 §12-DP3)")
        if not self.public and self.minimum_role is None:
            raise DomainError(
                "a route must state an authorization decision. 'Public' is "
                "available and is a decision; the absent decision is not, "
                "because that is exactly the G-01 shape.")
        if self.minimum_role is not None and self.minimum_role not in ROLES:
            raise DomainError(f"unknown role {self.minimum_role!r}")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise DomainError(
                "an access decision carries the reason it was made; a bare "
                "level cannot be reviewed against S2-PROP-021's matrix")

    # Named `public_route` rather than `public`: the field is already
    # called `public`, and on a slots dataclass a same-named classmethod
    # would overwrite the slot descriptor and break `access.public` on
    # every instance. A shorter name is not worth a silent one.
    @classmethod
    def public_route(cls, *, reason: str) -> "Access":
        return cls(public=True, minimum_role=None, reason=reason)

    @classmethod
    def at_least(cls, minimum_role: str, *, reason: str) -> "Access":
        return cls(public=False, minimum_role=minimum_role, reason=reason)

    def as_dict(self) -> dict:
        return {"public": self.public, "minimum_role": self.minimum_role,
                "reason": self.reason}


def authorize(access: Access, principal) -> Optional[ApiFailure]:
    """`None` to admit; an `ApiFailure` carrying the status to refuse."""
    if not isinstance(access, Access):
        raise DomainError(
            f"authorize needs an Access declaration, got "
            f"{type(access).__name__}")
    if access.public:
        return None
    if getattr(principal, "is_anonymous", True):
        return ApiFailure(401, ApiError(
            code=UNAUTHENTICATED,
            message="認証が必要です",
            detail={"minimum_role": access.minimum_role}))
    if not role_is_at_least(principal.role, access.minimum_role):
        return ApiFailure(403, ApiError(
            code=FORBIDDEN,
            message="この操作を行う権限がありません",
            detail={"minimum_role": access.minimum_role,
                    "role": principal.role}))
    return None


__all__ = ["Access", "authorize", "role_is_at_least", "ROLE_ORDER",
           "ROLE_VIEWER", "ROLE_ANALYST", "ROLE_ADMIN"]
