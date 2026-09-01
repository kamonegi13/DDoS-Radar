"""Provenance — the disclosure record NP6 requires, made unbypassable.

NP6 says a conclusion must be traceable to its formula, effective
thresholds, primary sources and LLM prompt. The diagnosis found that
disclosure added afterwards is disclosure that goes missing: E-08 is
prompts nobody recorded, and the conclusion envelope had no slot that
would have forced the question.

The record is immutable so that a justification cannot be edited after the
conclusion it justifies has shipped. Deriving a new record is easy;
rewriting history is not possible. L3 (WP-3.1) will make conclusions
unconstructible without one — the type exists now so that requirement has
something to demand.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from v3.kernel.errors import DomainError


def _require_ref(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(
            f"Provenance {name} must be a non-empty string, got {value!r}")
    return value.strip()


# JSON primitives only. Storing a caller's dict or list would keep it by
# reference: the caller (or anyone holding record.inputs["k"]) could edit a
# shipped disclosure afterwards, while equality and hash — fixed at
# construction — kept answering for the old contents. Restricting to
# primitives closes that at the source and matches what as_dict() and
# json.dumps() already promise about this field.
_PRIMITIVE_TYPES = (str, int, float, bool, type(None))


def _freeze_inputs(inputs: Mapping[str, Any]) -> tuple:
    if inputs is None:
        return ()
    if not isinstance(inputs, Mapping):
        raise DomainError(
            f"Provenance inputs must be a mapping, got "
            f"{type(inputs).__name__}")
    frozen = []
    for key, value in inputs.items():
        if not isinstance(key, str) or not key:
            raise DomainError(
                f"Provenance input names must be non-empty strings, "
                f"got {key!r}")
        if not isinstance(value, _PRIMITIVE_TYPES):
            raise DomainError(
                f"Provenance input {key!r} must be a JSON primitive "
                f"(str/int/float/bool/None), got "
                f"{type(value).__name__}. A structured value would be "
                f"stored by reference and could be edited after the "
                f"conclusion shipped — serialize it explicitly "
                f"(json.dumps) so the disclosure is a fixed string.")
        frozen.append((key, value))
    return tuple(sorted(frozen, key=lambda pair: pair[0]))


def _freeze_sources(source_refs: Iterable[str]) -> tuple[str, ...]:
    if source_refs is None:
        return ()
    if isinstance(source_refs, (str, bytes)):
        raise DomainError(
            "Provenance source_refs must be a sequence of strings, not a "
            "single string")
    return tuple(_require_ref(ref, name="source_refs entry")
                 for ref in source_refs)


@dataclass(frozen=True, slots=True)
class Provenance:
    """How a value was derived: formula, inputs, sources, and when.

    `inputs` is exposed as a read-only mapping — assigning into it raises
    rather than quietly editing a copy, because a disclosure record that
    can be adjusted after the fact is not a disclosure. Equality and
    hashing use `_inputs_key`, a stable rendering of the same data, so a
    record stays hashable even when an input value is not.
    """

    formula_ref: str
    computed_at: float
    inputs: Mapping[str, Any] = field(default_factory=dict, compare=False)
    source_refs: tuple[str, ...] = ()
    _inputs_key: tuple = field(default=(), repr=False, compare=True)

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Provenance is final: a subclass could relax the immutability "
            "that makes a disclosure record trustworthy (NP6).")

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "formula_ref",
            _require_ref(self.formula_ref, name="formula_ref"))

        stamp = self.computed_at
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
            raise DomainError(
                f"Provenance computed_at must be a unix timestamp, got "
                f"{type(stamp).__name__} {stamp!r}")
        if math.isnan(stamp) or math.isinf(stamp) or stamp <= 0:
            raise DomainError(
                f"Provenance computed_at must be a positive timestamp, "
                f"got {stamp!r}")
        object.__setattr__(self, "computed_at", float(stamp))

        frozen = _freeze_inputs(self.inputs)
        # A copy behind a read-only view: not aliased to the caller's dict,
        # and not writable through the accessor either.
        object.__setattr__(self, "inputs", MappingProxyType(dict(frozen)))
        # Values are primitives, so they are hashable and stable — no
        # repr() indirection, and no address-dependent identity.
        object.__setattr__(self, "_inputs_key", frozen)
        object.__setattr__(self, "source_refs",
                           _freeze_sources(self.source_refs))

    @property
    def has_sources(self) -> bool:
        return bool(self.source_refs)

    # ── derivation (never mutation) ────────────────────────────────────
    def with_input(self, name: str, value: Any) -> "Provenance":
        merged = dict(self.inputs)
        merged[_require_ref(name, name="input name")] = value
        return Provenance(formula_ref=self.formula_ref,
                          computed_at=self.computed_at, inputs=merged,
                          source_refs=self.source_refs)

    def with_source(self, source_ref: str) -> "Provenance":
        added = _require_ref(source_ref, name="source_ref")
        return Provenance(formula_ref=self.formula_ref,
                          computed_at=self.computed_at,
                          inputs=dict(self.inputs),
                          source_refs=self.source_refs + (added,))

    def __reduce__(self):
        # mappingproxy cannot be pickled, and deepcopy follows the same
        # path. Rebuilding through the constructor also re-runs validation,
        # so a round-tripped record is a validated record.
        return (type(self), (self.formula_ref, self.computed_at,
                             dict(self.inputs), self.source_refs))

    def as_dict(self) -> dict:
        """JSON-ready copy for the conclusion envelope and the ledger."""
        return {
            "formula_ref": self.formula_ref,
            "computed_at": self.computed_at,
            "inputs": dict(self.inputs),
            "source_refs": list(self.source_refs),
        }

    def __str__(self) -> str:
        return (f"Provenance<{self.formula_ref}, "
                f"{len(self.inputs)} inputs, "
                f"{len(self.source_refs)} sources>")


__all__ = ["Provenance"]
