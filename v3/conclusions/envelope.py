"""ONE envelope. Success and failure use the same one (G-13, condition 5).

The v2 surface reached four envelope shapes plus three success bodies plus
four error bodies, and one of those shapes had dropped the NP7 sentence
entirely. The contract was not written down anywhere that could refuse a
fifth shape, so a fifth shape is what kept appearing.

Here the envelope is a type with a required `disclaimer`, and an error is
the same type with `error` set — not a different body assembled in an
exception handler, which is where the sentence went missing. P7's
derivation principle 2 ("envelope is one shape, NP7 required, no
exceptions") is this class.

P7 R2 also requires live and replay to be the same projection, so `at` is
an ordinary field rather than a separate `replay_at` key on a separate
shape (S1-CONC-037's DP9 removed structurally).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from v3.conclusions import vocabulary as V
from v3.conclusions.conclusion import Conclusion
from v3.kernel.errors import DomainError

API_VERSION = "3.0"

# The keys `as_dict()` owns. `extra` is merged last, so anything here that
# a caller could also set is a second way to write the field — and one of
# these fields is the NP7 sentence.
_RESERVED_KEYS = frozenset({"api_version", "scenario_id", "observed_at",
                            "final_judgment_disclaimer", "conclusions",
                            "at", "error"})


@dataclass(frozen=True, slots=True)
class ConclusionEnvelope:
    """The one payload shape L6 serves, for every status code."""

    scenario_id: str
    conclusions: tuple[Conclusion, ...] = ()
    observed_at: Optional[float] = None
    at: Optional[float] = None
    error: Optional[str] = None
    api_version: str = API_VERSION
    disclaimer: str = V.NP7_DISCLAIMER
    extra: dict = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "ConclusionEnvelope is final: a subclass is a second envelope "
            "shape, which is defect G-13.")

    def __post_init__(self) -> None:
        if self.disclaimer != V.NP7_DISCLAIMER:
            raise DomainError(
                f"every envelope carries THE NP7 disclaimer, including error "
                f"responses, and it is a tool-level constant rather than a "
                f"per-response string: got {self.disclaimer!r}. Requiring "
                f"only 'some non-empty text' would let the sentence be "
                f"replaced as easily as it was once dropped (G-13).")
        reserved = _RESERVED_KEYS & set(self.extra or {})
        if reserved:
            raise DomainError(
                f"envelope extra may not carry the reserved key(s) "
                f"{sorted(reserved)}: extras are merged last, so this is a "
                f"path that overwrites the NP7 disclaimer AFTER the "
                f"constructor validated it — G-13 by a side door.")
        object.__setattr__(self, "extra", dict(self.extra or {}))
        if not isinstance(self.scenario_id, str) or not self.scenario_id.strip():
            raise DomainError("envelope scenario_id must be a non-empty string")
        conclusions = tuple(self.conclusions)
        for item in conclusions:
            if not isinstance(item, Conclusion):
                raise DomainError(
                    f"an envelope carries Conclusion objects, got "
                    f"{type(item).__name__}. S1-CONC-006's hand-built dict "
                    f"bypassed every schema invariant, which is ACCIDENTAL "
                    f"A2 — there is no second path here.")
        object.__setattr__(self, "conclusions", conclusions)
        if self.observed_at is None and conclusions:
            # S1-CONC-005: the latest observation in the bundle.
            object.__setattr__(
                self, "observed_at",
                max(item.observed_at for item in conclusions))
        if self.error is not None and (not isinstance(self.error, str)
                                       or not self.error.strip()):
            raise DomainError("an envelope error must be a non-empty code")

    @classmethod
    def failure(cls, *, scenario_id: str, error: str, observed_at: float,
                **extra: Any) -> "ConclusionEnvelope":
        """A 4xx/5xx body. Same shape, same disclaimer, no conclusions."""
        return cls(scenario_id=scenario_id, error=error,
                   observed_at=observed_at, extra=dict(extra))

    def as_dict(self) -> dict:
        payload = {
            "api_version": self.api_version,
            "scenario_id": self.scenario_id,
            "observed_at": self.observed_at,
            "final_judgment_disclaimer": self.disclaimer,
            "conclusions": [item.as_dict() for item in self.conclusions],
        }
        if self.at is not None:
            payload["at"] = self.at
        if self.error is not None:
            payload["error"] = self.error
        payload.update(self.extra)
        return payload

    def of_type(self, conclusion_type: str) -> tuple[Conclusion, ...]:
        V.require_conclusion_type(conclusion_type)
        return tuple(item for item in self.conclusions
                     if item.conclusion_type == conclusion_type)


def bundle(scenario_id: str, conclusions: Iterable[Conclusion], *,
           at: Optional[float] = None) -> ConclusionEnvelope:
    """The R2 projection: whatever was derived, in one envelope."""
    return ConclusionEnvelope(scenario_id=scenario_id,
                              conclusions=tuple(conclusions), at=at)


__all__ = ["ConclusionEnvelope", "bundle", "API_VERSION"]
