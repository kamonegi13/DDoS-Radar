"""One error shape, machine-readable, and a fixed evaluation order.

S2-PROP-017 counts the damage in the legacy surface: 123 endpoints
returning English prose in an `error` string, five of them returning it
inside an HTTP 200, and four distinct error bodies. Prose cannot be
translated by the Japanese-only UI and cannot be branched on by a client,
so the code here is a stable identifier and the message is the human half.

The evaluation order is also a constant rather than a convention. S2's
§12-DP3/DP8 found endpoints that answered 403 to an unauthenticated
caller and 404 to a caller who was merely not allowed to know — both
leak, and both came from checks written in whatever order the body
happened to run them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from v3.kernel.errors import DomainError

#: S2-PROP-016. The dispatcher walks these in order and stops at the
#: first failure, so a route cannot answer 404 to a caller who should
#: have been told 401.
EVALUATION_ORDER: tuple[int, ...] = (503, 401, 403, 400, 404, 200)

# Stable codes. The UI maps these to i18n keys; the message is the
# fallback for a caller that has no dictionary.
UNAVAILABLE = "api.unavailable"
UNAUTHENTICATED = "api.unauthenticated"
FORBIDDEN = "api.forbidden"
BAD_REQUEST = "api.bad_request"
NOT_FOUND = "api.not_found"
METHOD_NOT_ALLOWED = "api.method_not_allowed"
INTERNAL = "api.internal_error"

ERROR_CODES: frozenset = frozenset({
    UNAVAILABLE, UNAUTHENTICATED, FORBIDDEN, BAD_REQUEST, NOT_FOUND,
    METHOD_NOT_ALLOWED, INTERNAL})


@dataclass(frozen=True, slots=True)
class ApiError:
    """`{code, message, detail}` — the only error body (S2-PROP-017)."""

    code: str
    message: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.code not in ERROR_CODES:
            raise DomainError(
                f"unknown error code {self.code!r}: the code is a contract "
                f"the UI branches on, so a new one is a deliberate addition "
                f"to ERROR_CODES rather than a string typed at a call site")
        if not isinstance(self.message, str) or not self.message.strip():
            raise DomainError("an error must carry a human-readable message")
        if not isinstance(self.detail, Mapping):
            raise DomainError("error detail must be a mapping")
        object.__setattr__(self, "detail", dict(self.detail))

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message,
                "detail": dict(self.detail)}


class ApiFailure(Exception):
    """A refusal with its status. Carries the ONE error shape."""

    def __init__(self, status: int, error: ApiError):
        if status not in EVALUATION_ORDER or status == 200:
            raise DomainError(
                f"status {status} is not one of the declared refusal "
                f"statuses {EVALUATION_ORDER[:-1]}")
        self.status = status
        self.error = error
        super().__init__(f"{status} {error.code}: {error.message}")


def not_found(what: str, **detail: Any) -> ApiFailure:
    return ApiFailure(404, ApiError(code=NOT_FOUND,
                                    message=f"{what} は存在しません",
                                    detail=detail))


def bad_request(message: str, **detail: Any) -> ApiFailure:
    return ApiFailure(400, ApiError(code=BAD_REQUEST, message=message,
                                    detail=detail))


__all__ = ["ApiError", "ApiFailure", "EVALUATION_ORDER", "ERROR_CODES",
           "UNAVAILABLE", "UNAUTHENTICATED", "FORBIDDEN", "BAD_REQUEST",
           "NOT_FOUND", "METHOD_NOT_ALLOWED", "INTERNAL", "not_found",
           "bad_request"]
