"""One conclusion. It cannot be built without its justification.

The type carries five refusals, each answering a diagnosed defect:

  * no `Provenance`, no conclusion (WP-3.1 condition 1). NP6 asks for the
    formula, the effective thresholds and the primary sources; disclosure
    added afterwards is disclosure that goes missing (E-08 is prompts
    nobody recorded).
  * no NP7 disclaimer, no conclusion (condition 5 / G-13). The v2 surface
    grew four envelope shapes and one of them had lost the sentence.
  * no `InputHealth`, no conclusion (condition 4 / G-17). A verdict that
    cannot say what it was built from cannot be told apart from a verdict
    built from nothing.
  * unavailable without a `Suppression`, refused (condition 3 / E-17).
  * a calm state with no basis at all, refused. That is G-17 stated as an
    invariant rather than as a review note.

Everything else is S1-CONC-001 and S1-CONC-002: the five types, a unique
id, state/reason exclusivity, confidence in [0,1], immutability, and a
stable serialisation.
"""
from __future__ import annotations

import json
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional

from v3.conclusions import vocabulary as V
from v3.conclusions.availability import Availability, InputHealth, Suppression
from v3.kernel import Provenance
from v3.kernel.errors import DomainError, ProvenanceRequiredError


def new_conclusion_id() -> str:
    return str(uuid.uuid4())


@dataclass(frozen=True, slots=True, kw_only=True)
class Conclusion:
    """One published judgement, or one published inability to judge.

    Keyword-only: fourteen fields in a positional signature is how a
    `state` ends up in a `formula_ref`, and the constructor is the only
    place these invariants can still be checked.
    """

    scenario_id: str
    conclusion_type: str
    observed_at: float
    confidence: float
    provenance: Provenance
    input_health: InputHealth
    state: Optional[str] = None
    unavailable_reason: Optional[str] = None
    suppression: Optional[Suppression] = None
    conclusion_id: str = field(default_factory=new_conclusion_id)
    disclaimer: str = V.NP7_DISCLAIMER
    threshold_ref: Mapping[str, Any] = field(default_factory=dict)
    source_urls: tuple[str, ...] = ()
    calibration_status: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    llm_prompt_sha256: Optional[str] = None

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Conclusion is final: a subclass could relax the invariants "
            "that make a published judgement auditable (NP6 / NP7).")

    def __post_init__(self) -> None:
        V.require_conclusion_type(self.conclusion_type)

        if not isinstance(self.scenario_id, str) or not self.scenario_id.strip():
            raise DomainError(
                f"scenario_id must be a non-empty string, "
                f"got {self.scenario_id!r}")
        object.__setattr__(self, "scenario_id", self.scenario_id.strip())
        if not isinstance(self.conclusion_id, str) or \
                not self.conclusion_id.strip():
            raise DomainError("conclusion_id must be a non-empty string")

        # ── condition 1: no provenance, no conclusion ──────────────────
        if not isinstance(self.provenance, Provenance):
            raise ProvenanceRequiredError(
                f"a conclusion must carry a kernel Provenance, got "
                f"{type(self.provenance).__name__}. A published judgement "
                f"whose derivation cannot be reconstructed is not a "
                f"disclosed conclusion (NP6) — and disclosure bolted on "
                f"later is the disclosure that goes missing (E-08).")

        # ── condition 4: no health record, no conclusion ───────────────
        if not isinstance(self.input_health, InputHealth):
            raise DomainError(
                f"a conclusion must carry the InputHealth it was built "
                f"from, got {type(self.input_health).__name__}. Without it, "
                f"'quiet world' and 'empty cache' are the same row — "
                f"defect G-17.")

        # ── condition 5: NP7 is a field of the type ────────────────────
        if self.disclaimer != V.NP7_DISCLAIMER:
            raise DomainError(
                f"the NP7 disclaimer is THE sentence, not any sentence: got "
                f"{self.disclaimer!r}. The tool is one node in an "
                f"organisational process and every conclusion has to say so "
                f"in the agreed words (S1-CONC-005). Requiring only "
                f"non-empty text would let it be replaced as easily as it "
                f"was once dropped.")

        stamp = self.observed_at
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) \
                or stamp <= 0:
            raise DomainError(
                f"observed_at must be a positive timestamp, got {stamp!r}")
        object.__setattr__(self, "observed_at", float(stamp))

        confidence = self.confidence
        if isinstance(confidence, bool) or \
                not isinstance(confidence, (int, float)):
            raise DomainError(
                f"confidence must be a number, got {confidence!r}")
        if not 0.0 <= confidence <= 1.0:
            # S1-CONC-001: refuse, never clamp. A silently clamped 1.4
            # reads as certainty and hides the arithmetic that produced it.
            raise DomainError(
                f"confidence must be within [0.0, 1.0], got {confidence}. "
                f"The construction is refused rather than clamped: a "
                f"quietly corrected value hides the formula that overflowed.")
        object.__setattr__(self, "confidence", float(confidence))

        # ── state / reason exclusivity (S1-CONC-001) ───────────────────
        if self.unavailable_reason is None:
            if self.state is None:
                raise DomainError(
                    "a conclusion with no state must give a reason: silence "
                    "without an explanation is exactly the shape NP5+8 "
                    "forbids")
        else:
            V.require_unavailable_reason(self.unavailable_reason)
            if self.state is not None:
                raise DomainError(
                    f"an unavailable conclusion must have state None, got "
                    f"{self.state!r}: a reason beside a verdict lets a "
                    f"consumer read whichever one it prefers")

        # ── condition 3: suppression is recorded, both directions ──────
        if self.unavailable_reason is not None:
            if self.suppression is None:
                raise DomainError(
                    "an unavailable conclusion must carry the Suppression "
                    "that produced it (defect E-17: guards stopped emits "
                    "and left only a log line)")
            if self.suppression.overridden:
                raise DomainError(
                    "an overridden suppression means the conclusion was "
                    "published anyway; it cannot also be unavailable")
            if self.suppression.reason != self.unavailable_reason:
                raise DomainError(
                    f"the recorded suppression says "
                    f"{self.suppression.reason!r} but the conclusion says "
                    f"{self.unavailable_reason!r}: two answers to 'why' is "
                    f"no answer")
        elif self.suppression is not None and not self.suppression.overridden:
            raise DomainError(
                "a non-overridden suppression must make the conclusion "
                "unavailable; recording one beside a published verdict "
                "loses which of the two actually happened")

        # ── condition 4, stated as an invariant ────────────────────────
        if self.state is not None and self.input_health.has_no_basis:
            raise DomainError(
                f"conclusion {self.conclusion_type} claims the state "
                f"{self.state!r} while no source was consulted at all. That "
                f"is defect G-17 — an empty cache rendered as ROUTINE / "
                f"CLEAR / NORMAL. Absent data yields an unavailable "
                f"conclusion with a reason, never a verdict.")

        for name in ("threshold_ref", "calibration_status", "metadata"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise DomainError(
                    f"{name} must be a mapping, got {type(value).__name__}")
            # DEEP copy, not shallow. A read-only proxy over a shallow copy
            # leaves `rationale_matrix`, `ranked_modes` and `windows` —
            # the structures that carry the actual disclosure — shared with
            # the caller, so a published conclusion could be rewritten
            # through the dict that built it. Immutability one level deep
            # is the kind of guarantee that reads as complete and is not.
            object.__setattr__(self, name,
                               MappingProxyType(deepcopy(dict(value))))
        if isinstance(self.source_urls, (str, bytes)):
            raise DomainError(
                "source_urls must be a sequence of URLs, not a single string")
        object.__setattr__(self, "source_urls", tuple(self.source_urls))

    # ── reading ────────────────────────────────────────────────────────
    @property
    def is_available(self) -> bool:
        return self.unavailable_reason is None

    def __reduce__(self):
        # mappingproxy is unpicklable and deepcopy takes the same path;
        # rebuilding through the constructor re-validates, so a restored
        # conclusion is one the constructor would have accepted.
        return (_rebuild, (dict(
            scenario_id=self.scenario_id,
            conclusion_type=self.conclusion_type,
            observed_at=self.observed_at, confidence=self.confidence,
            provenance=self.provenance, input_health=self.input_health,
            state=self.state, unavailable_reason=self.unavailable_reason,
            suppression=self.suppression, conclusion_id=self.conclusion_id,
            disclaimer=self.disclaimer,
            threshold_ref=dict(self.threshold_ref),
            source_urls=self.source_urls,
            calibration_status=dict(self.calibration_status),
            metadata=dict(self.metadata),
            llm_prompt_sha256=self.llm_prompt_sha256),))

    def as_dict(self) -> dict:
        """The API representation (S1-CONC-002): JSON-ready, stable order."""
        return {
            "id": self.conclusion_id,
            "scenario_id": self.scenario_id,
            "conclusion_type": self.conclusion_type,
            "state": self.state,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "conclusion_unavailable_reason": self.unavailable_reason,
            "final_judgment_disclaimer": self.disclaimer,
            "formula_ref": self.provenance.formula_ref,
            "provenance": self.provenance.as_dict(),
            "threshold_ref": deepcopy(dict(self.threshold_ref)),
            "source_urls": list(self.source_urls),
            "calibration_status": deepcopy(dict(self.calibration_status)),
            "llm_prompt_sha256": self.llm_prompt_sha256,
            "input_health": self.input_health.as_dict(),
            "suppression": (None if self.suppression is None
                            else self.suppression.as_dict()),
            "metadata": deepcopy(dict(self.metadata)),
        }

    def json_metadata(self) -> str:
        """Ledger form: the disclosure fields that have no column.

        `suppression` and `input_health` ride here rather than in new
        columns because they are per-conclusion disclosure, and because a
        column added for one of them would tempt a later reader to treat
        the other as optional.
        """
        payload = deepcopy(dict(self.metadata))
        payload["input_health"] = self.input_health.as_dict()
        payload["provenance"] = self.provenance.as_dict()
        if self.suppression is not None:
            payload["suppression"] = self.suppression.as_dict()
        return json.dumps(payload, sort_keys=True, default=str,
                          allow_nan=False, ensure_ascii=False)


def _rebuild(kwargs: dict) -> Conclusion:
    return Conclusion(**kwargs)


def build(*, scenario_id: str, conclusion_type: str, observed_at: float,
          confidence: float, provenance: Provenance,
          input_health: InputHealth, availability: Availability,
          state: Optional[str] = None,
          threshold_ref: Optional[Mapping[str, Any]] = None,
          source_urls: tuple[str, ...] = (),
          calibration_status: Optional[Mapping[str, Any]] = None,
          metadata: Optional[Mapping[str, Any]] = None,
          llm_prompt_sha256: Optional[str] = None) -> Conclusion:
    """THE constructor every derivation uses.

    It takes the guard chain's `Availability` rather than a reason string,
    so the only way to publish an unavailable conclusion is to have run
    the guards — a reason cannot be invented at a call site, which is how
    F-12's three unused values would come back under new names.

    An unavailable conclusion keeps its threshold_ref, source_urls,
    calibration_status and metadata (S1-CONC-013 / S1-CONC-026: the row
    that says "I cannot tell you" still shows its work), and its
    confidence is 0.0 by definition.
    """
    if not isinstance(availability, Availability):
        raise TypeError(
            f"build() needs the guard chain's Availability, got "
            f"{type(availability).__name__}. Passing a bare reason string "
            f"would let a caller mint an unavailable reason with no "
            f"condition behind it — defect F-12.")
    meta = dict(metadata or {})
    if availability.available:
        return Conclusion(
            scenario_id=scenario_id, conclusion_type=conclusion_type,
            observed_at=observed_at, confidence=confidence,
            provenance=provenance, input_health=input_health, state=state,
            suppression=availability.suppression,
            threshold_ref=threshold_ref or {}, source_urls=source_urls,
            calibration_status=calibration_status or {}, metadata=meta,
            llm_prompt_sha256=llm_prompt_sha256)

    suppression = availability.suppression
    meta.setdefault("reason_detail", suppression.detail)
    # S1-CONC-004: an unavailable conclusion asserts nothing about the
    # world. `is_transient` says whether waiting is expected to fix it —
    # a degraded sensor or a young scenario resolves itself; nothing else
    # about the row should be read as "no threat".
    meta.setdefault("is_transient", suppression.reason in (
        V.SENSOR_DEGRADED, V.UPSTREAM_FAILURE, V.CALIBRATION_PENDING))
    meta.setdefault("asserts_absence", False)
    return Conclusion(
        scenario_id=scenario_id, conclusion_type=conclusion_type,
        observed_at=observed_at, confidence=0.0, provenance=provenance,
        input_health=input_health, state=None,
        unavailable_reason=availability.reason, suppression=suppression,
        threshold_ref=threshold_ref or {}, source_urls=source_urls,
        calibration_status=calibration_status or {}, metadata=meta,
        llm_prompt_sha256=llm_prompt_sha256)


__all__ = ["Conclusion", "build", "new_conclusion_id"]
