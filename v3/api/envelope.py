"""Response construction. There is one envelope, and it is L3's.

WP-3.1 condition 5 and P7 derivation principle 2 are the same rule seen
from two layers: ONE payload shape, the NP7 sentence required by the
type, no exceptions. `v3.conclusions.ConclusionEnvelope` already is that
type — it refuses a wrong disclaimer, refuses a subclass, and refuses an
`extra` key that would overwrite the sentence after validation. So this
module builds that type; it does not define a second one.

Two shapes of projection need serving:

* **scenario-scoped** (R2..R5, R12): the envelope as L3 built it.
* **tool-scoped** (R7, R8, R10, R15): about the tool rather than a
  scenario, served with `scenario_id = TOOL_SCOPE` and an empty
  conclusion list. The alternative — a second, scenario-less envelope —
  is defect G-13 by construction, and G-13 is how the NP7 sentence went
  missing from `/api/intel/pending/triage` in the first place.

`ApiResponse` pairs a status with an envelope. It is not an envelope: it
declares no disclaimer, carries no payload keys of its own, and
`tests/test_api_surface.py` asserts nothing under `v3/api/` declares a
`disclaimer` field.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from v3.api.errors import ApiError, ApiFailure
from v3.api.vocabulary import FORBIDDEN_RESPONSE_KEYS, TOOL_SCOPE
from v3.conclusions import Conclusion, ConclusionEnvelope
from v3.kernel.errors import DomainError

OK = 200


def _check_vocabulary(payload: Any, *, path: str = "$") -> None:
    """C-01: the retired vocabulary cannot leave through a response.

    Checked at construction rather than in a test alone, because a test
    can only see the responses it thought to build, and `theater` reached
    four release surfaces the last time it was 'removed'.
    """
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(key, str) and key in FORBIDDEN_RESPONSE_KEYS:
                raise DomainError(
                    f"response key {path}.{key!r} uses retired vocabulary. "
                    f"The tool's units are country and scenario (C-01); "
                    f"`theater` conflated the two and the conflation is "
                    f"what the rename exists to end.")
            _check_vocabulary(value, path=f"{path}.{key}")
    elif isinstance(payload, (list, tuple)):
        for index, value in enumerate(payload):
            _check_vocabulary(value, path=f"{path}[{index}]")


@dataclass(frozen=True, slots=True)
class ApiResponse:
    """A status and THE envelope. Deliberately not a second envelope."""

    status: int
    envelope: ConclusionEnvelope

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ConclusionEnvelope):
            raise DomainError(
                f"a response carries a ConclusionEnvelope, got "
                f"{type(self.envelope).__name__}: a hand-built dict is the "
                f"path by which the NP7 sentence went missing (G-13)")
        _check_vocabulary(self.envelope.as_dict())

    def as_dict(self) -> dict:
        return self.envelope.as_dict()


def scenario_response(scenario_id: str,
                      conclusions: Iterable[Conclusion] = (), *,
                      at: Optional[float] = None,
                      observed_at: Optional[float] = None,
                      status: int = OK, **extra: Any) -> ApiResponse:
    """A scenario-scoped projection."""
    envelope = ConclusionEnvelope(scenario_id=scenario_id,
                                  conclusions=tuple(conclusions),
                                  observed_at=observed_at, at=at,
                                  extra=dict(extra))
    return ApiResponse(status=status, envelope=envelope)


def tool_response(*, observed_at: float, at: Optional[float] = None,
                  status: int = OK, **extra: Any) -> ApiResponse:
    """A tool-scoped projection (R7/R8/R10/R15), same envelope."""
    envelope = ConclusionEnvelope(scenario_id=TOOL_SCOPE,
                                  observed_at=observed_at, at=at,
                                  extra=dict(extra))
    return ApiResponse(status=status, envelope=envelope)


def failure_response(failure: ApiFailure, *, observed_at: float,
                     scenario_id: str = TOOL_SCOPE) -> ApiResponse:
    """A 4xx/5xx body: the SAME envelope, with `error` set.

    Not a body assembled in an exception handler — that is exactly where
    the disclaimer stopped being attached.
    """
    if not isinstance(failure, ApiFailure):
        raise DomainError("failure_response takes an ApiFailure")
    envelope = ConclusionEnvelope(
        scenario_id=scenario_id, observed_at=observed_at,
        error=failure.error.code, extra={"error_detail": _error_body(
            failure.error)})
    return ApiResponse(status=failure.status, envelope=envelope)


def _error_body(error: ApiError) -> dict:
    return error.as_dict()


#: P7 §3 makes this mandatory on EVERY projection, and the reason is
#: specific to what v3 does: the API projects the ledger rather than
#: re-scoring on demand (A-01's repair), and conclusions are written only
#: when they change (§7-2 #58). Both are correct, and together they mean
#: a served conclusion can legitimately be older than this request. The
#: analyst has to be able to see that without doing subtraction.
FRESHNESS_KEY = "data_freshness_sec"


def with_freshness(response: ApiResponse, now: float) -> ApiResponse:
    """Stamp "how old is what you are looking at" onto a response.

    Applied by the dispatcher to every route rather than by each handler,
    because a field each handler must remember is a field one handler
    will not — which is the shape of every defect this layer was rebuilt
    to make impossible.
    """
    envelope = response.envelope
    if FRESHNESS_KEY in envelope.extra:
        raise DomainError(
            f"{FRESHNESS_KEY} is stamped once, by the dispatcher. A handler "
            f"setting it is a second writer of the same field, and the two "
            f"will disagree the first time one of them is edited.")
    observed_at = envelope.observed_at
    age = None if observed_at is None else max(0.0, float(now) - observed_at)
    stamped = ConclusionEnvelope(
        scenario_id=envelope.scenario_id, conclusions=envelope.conclusions,
        observed_at=observed_at, at=envelope.at, error=envelope.error,
        extra={**envelope.extra, FRESHNESS_KEY: age, "served_at": float(now)})
    return ApiResponse(status=response.status, envelope=stamped)


__all__ = ["ApiResponse", "scenario_response", "tool_response",
           "failure_response", "OK"]
