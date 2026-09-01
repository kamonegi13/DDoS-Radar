"""Threshold — a value you cannot read without learning how it resolved.

G-15 measured the damage: 95 of 98 registered keys were read through
`os.getenv` or an import-time constant, so the settings UI wrote override
rows nobody consulted. G-04 is the same defect on GPS_JAM_THRESHOLD, where
a registry entry existed and the sensor bypassed it.

P6 O-18 rules that "register everything" is the wrong repair — the
evidence is that almost nothing needs runtime variability. So thresholds
come in exactly two shapes:

    registry_backed(key)   operationally variable; resolved through the
                           3-layer chain at READ time, recording which
                           layer answered.
    pinned(value, ref)     a constant, which must still disclose where its
                           value came from. Changing it is a code change,
                           which forces review and re-calibration.

There is no third shape, no `.value` attribute, and no float conversion:
the only way to a number is `resolve()`, which hands back the value and
its provenance together.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from v3.kernel.errors import (DomainError, ProvenanceRequiredError,
                              ThresholdResolutionError, UnitMismatchError)
from v3.kernel.units import Percentage, Ratio

# Closed vocabulary, matching S5-VERIF-007's requirement that every
# threshold declare a unit from a fixed set.
UNIT_RATIO = "ratio"
UNIT_PERCENT = "percent"
KNOWN_UNITS = frozenset({UNIT_RATIO, UNIT_PERCENT, "count", "s", "min", "h",
                         "d", "km", "z", "score", "bool", "index",
                         "multiplier"})
# Units with a kernel type: an observation MUST arrive as that type.
_TYPED_UNITS: dict[str, type] = {UNIT_RATIO: Ratio, UNIT_PERCENT: Percentage}

SOURCE_PINNED = "pinned"


def _reject_non_finite(value, *, role: str, unit: str):
    """NaN/Inf must never reach a comparison.

    A NaN threshold — or a NaN observation, which a zero-variance
    baseline produces as 0/0 — compares False against everything, so the
    check reads "not exceeded" forever. That is F-08's failure mode
    arriving by a different road, and it is invisible in the same way.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    if math.isnan(value) or math.isinf(value):
        raise DomainError(
            f"{role} for a {unit!r} threshold must be finite, got "
            f"{value!r}: a NaN or infinite value compares False against "
            f"everything, which reads as 'never exceeded' rather than as "
            f"an error.")
    return value


def _wrap(value, unit: str):
    """Put a resolved number into its unit type, validating the domain."""
    _reject_non_finite(value, role="threshold value", unit=unit)
    typed = _TYPED_UNITS.get(unit)
    return typed(value) if typed is not None else value


def _raw(value):
    return value.value if isinstance(value, (Ratio, Percentage)) else value


@dataclass(frozen=True, slots=True)
class ResolvedThreshold:
    """A threshold value together with the path that produced it."""

    value: Any
    unit: str
    source: str                      # 'db' | 'env' | 'default' | 'pinned'
    key: Optional[str]
    provenance_ref: Optional[str]
    resolved_at: float

    def __str__(self) -> str:
        origin = self.key or self.provenance_ref
        return f"{self.value} [{self.source}: {origin}]"


#: There is deliberately NO fallback resolver. Until WP-4.4 this module
#: held `_default_resolver`, which did `from radar import config_layered`
#: whenever a registry-backed threshold resolved with no injected chain —
#: and that import boots the legacy Flask app, its migrations and ~40
#: sensor threads against the production database. Wiring v3 found it as
#: the one live path from a v3 process into v1, and the composition root
#: answered with a `sys.meta_path` barrier that turns the import into a
#: stack trace.
#:
#: A barrier is the right guard for code v3 does not own (an adapter, a
#: dependency). It is the wrong repair for a fallback v3 never wants: v3's
#: composition root injects its own chain everywhere
#: (`v3/config/resolution.py`, the single licensed `resolver=` call site),
#: so the fallback's only reachable outcomes were "boots v1" outside the
#: barrier and "obscure ImportError" inside it. Neither is a resolution.
#: Absent, the failure says what actually went wrong and names the seam.
_NO_RESOLVER = (
    "no resolver was supplied and this kernel has no fallback: v3's "
    "3-layer chain lives in v3/config/resolution.py and is injected by the "
    "composition root (v3/runtime/config.py::build_resolver). The removed "
    "fallback read the LEGACY registry, which boots radar/__init__.py — "
    "the Flask app, the migrations and ~40 sensor threads — against the "
    "production database.")


@dataclass(frozen=True, slots=True)
class Threshold:
    """A comparison threshold with a declared unit and resolution path."""

    unit: str
    key: Optional[str] = None
    provenance_ref: Optional[str] = None
    _pinned_value: Any = field(default=None, repr=False)

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Threshold is final: a subclass could expose a value without "
            "its resolution path (defects G-15 / G-04).")

    def __post_init__(self) -> None:
        if self.unit not in KNOWN_UNITS:
            raise DomainError(
                f"unknown threshold unit {self.unit!r}; expected one of "
                f"{sorted(KNOWN_UNITS)}")

    # ── the two shapes (P6 O-18) ───────────────────────────────────────
    @classmethod
    def pinned(cls, value, *, unit: str, provenance_ref: str) -> "Threshold":
        """A constant. `provenance_ref` names the clause, ADR or derivation."""
        if not isinstance(provenance_ref, str) or not provenance_ref.strip():
            raise ProvenanceRequiredError(
                "a pinned threshold needs a provenance reference (spec "
                "clause, ADR id, or derivation note): the value is not "
                "runtime-variable, so disclosure is the only thing making "
                "it auditable (P6 O-18)")
        instance = cls(unit=unit, provenance_ref=provenance_ref.strip())
        # Validate the value against the unit domain at construction, so a
        # percent-scaled constant cannot sit in a ratio threshold.
        _wrap(value, unit)
        object.__setattr__(instance, "_pinned_value", value)
        return instance

    @classmethod
    def registry_backed(cls, key: str, *, unit: str) -> "Threshold":
        """An operationally variable key, resolved through the 3-layer chain."""
        if not isinstance(key, str) or not key.strip():
            raise DomainError("registry_backed requires a config key name")
        return cls(unit=unit, key=key.strip())

    @property
    def is_registry_backed(self) -> bool:
        return self.key is not None

    # ── resolution ─────────────────────────────────────────────────────
    def resolve(self, resolver: Optional[Callable[[str], tuple]] = None
                ) -> ResolvedThreshold:
        """The only path to a value. Returns it with its provenance.

        `resolver` is `(key) -> (value, source)` and it is THE seam through
        which v3's own resolution chain arrives. WP-4.1d's ruling: the
        kernel stays pure and the composition root supplies the chain, so
        this parameter is how `v3/config/resolution.py` — built by
        `v3/runtime/config.py` with an environment snapshot and handed a
        ledger — answers for a registry-backed key without the kernel ever
        importing L1.

        It is not a free-for-all. The discipline gate licenses `resolver=`
        in exactly one non-test file (`_RESOLVER_OWNER`), because a private
        resolver constructed at an arbitrary call site is the G-15 shape:
        a configuration path nobody else can see. Left unset on a
        registry-backed threshold, this RAISES — see `_NO_RESOLVER` for
        why an unusable fallback was worse than a loud failure. A pinned
        threshold never consults a resolver, so it is unaffected.
        """
        if not self.is_registry_backed:
            return ResolvedThreshold(
                value=_wrap(self._pinned_value, self.unit), unit=self.unit,
                source=SOURCE_PINNED, key=None,
                provenance_ref=self.provenance_ref, resolved_at=time.time())

        if resolver is None:
            raise ThresholdResolutionError(
                f"cannot resolve threshold {self.key!r}: {_NO_RESOLVER}")
        try:
            value, source = resolver(self.key)
        except Exception as exc:  # noqa: BLE001 - surfaced, never defaulted
            raise ThresholdResolutionError(
                f"could not resolve threshold {self.key!r}: "
                f"{type(exc).__name__}: {exc}") from exc
        if value is None:
            # Falling back silently is exactly how a dead knob looks healthy.
            raise ThresholdResolutionError(
                f"threshold {self.key!r} resolved to None; refusing to "
                f"substitute a default, because a silent fallback is how "
                f"G-15 stayed invisible")
        return ResolvedThreshold(
            value=_wrap(value, self.unit), unit=self.unit, source=str(source),
            key=self.key, provenance_ref=self.provenance_ref,
            resolved_at=time.time())

    # ── comparison ─────────────────────────────────────────────────────
    def _check_unit(self, observed, declared_unit: Optional[str]) -> None:
        expected_type = _TYPED_UNITS.get(self.unit)
        if expected_type is not None:
            if not isinstance(observed, expected_type):
                raise UnitMismatchError(
                    f"threshold declares unit {self.unit!r}, so the observed "
                    f"value must be a {expected_type.__name__}, got "
                    f"{type(observed).__name__}. A bare number carries no "
                    f"unit — that is how F-08 compared a ratio against a "
                    f"percentage.")
            return
        if declared_unit is None:
            raise UnitMismatchError(
                f"threshold declares unit {self.unit!r}; pass the observed "
                f"value's unit explicitly (exceeded_by(value, "
                f"unit={self.unit!r})) so an unlabelled number cannot be "
                f"compared by accident")
        if declared_unit != self.unit:
            raise UnitMismatchError(
                f"unit mismatch: threshold is {self.unit!r}, observation is "
                f"{declared_unit!r}")

    def exceeded_by(self, observed, *, unit: Optional[str] = None,
                    resolver: Optional[Callable[[str], tuple]] = None) -> bool:
        """True when `observed >= threshold`, in matching units.

        `resolver` is the same injected chain as on resolve(), under the
        same one-file licence.
        """
        self._check_unit(observed, unit)
        _reject_non_finite(_raw(observed), role="observed value",
                           unit=self.unit)
        resolved = self.resolve(resolver=resolver)
        return _raw(observed) >= _raw(resolved.value)

    def __float__(self):  # noqa: D105
        raise TypeError(
            "float(Threshold) is refused: a threshold value must travel with "
            "the path that produced it. Use resolve(), which returns the "
            "value together with its source.")

    def __str__(self) -> str:
        origin = f"registry:{self.key}" if self.is_registry_backed \
            else f"pinned:{self.provenance_ref}"
        return f"Threshold<{self.unit}, {origin}>"


__all__ = ["Threshold", "ResolvedThreshold", "KNOWN_UNITS",
           "UNIT_RATIO", "UNIT_PERCENT", "SOURCE_PINNED"]
