"""The resolved operationally-variable values, and the one impure step.

This module is the seam between "a threshold key" and "a number".
Resolution happens HERE, in `resolve_settings()`, which the L2 *caller*
runs once per tick — never the kernel. `score_tick()` receives a finished
`ScoringSettings` and therefore reads no registry, no environment and no
clock, which is what makes the same input reproduce the same output
(WP-2.4 completion condition 1, F-05).

The split is deliberately testable: `ScoringSettings` is an ordinary
frozen value object, so the suite constructs one directly, and the purity
test can break the registry outright and watch scoring carry on.

Every field here corresponds to a key the EFFECTIVE path reads. Values
the engine formula family reads (domain weights, CONVERGENCE_FULL_BONUS)
are deliberately absent — see `thresholds` for why carrying them would
install a dial that does nothing.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from v3.kernel import Ratio, Threshold, Window
from v3.kernel.errors import DomainError
from v3.scoring.thresholds import VARIABLE


def _number(value, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(f"{name} must be a number, got "
                          f"{type(value).__name__} {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric):
        raise DomainError(
            f"{name} must be finite, got {value!r}: a NaN threshold "
            f"compares False against everything, which reads as 'never "
            f"exceeded' rather than as an error")
    return numeric


def _positive(value, *, name: str) -> float:
    numeric = _number(value, name=name)
    if numeric <= 0:
        raise DomainError(f"{name} must be positive, got {numeric!r}")
    return numeric


def _flag(value, *, name: str) -> bool:
    if not isinstance(value, bool):
        raise DomainError(
            f"{name} must be a real bool, got {type(value).__name__} "
            f"{value!r}. Coercing would make the string 'false' mean True, "
            f"and a registry row is a string.")
    return value


def _as_ratio(value, *, name: str) -> Ratio:
    if isinstance(value, Ratio):
        return value
    try:
        return Ratio(value)
    except DomainError as exc:
        raise DomainError(f"{name}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class ScoringSettings:
    """Every operationally-variable value on the effective path, resolved.

    Defaults match `thresholds.VARIABLE`, so a test that cares about one
    dial sets that dial alone.
    """

    domain_cap: float = 6.0
    global_signals_decoupled: bool = True
    global_signal_weight: Ratio = field(default_factory=lambda: Ratio(0.5))
    llm_primary_country_only: bool = True
    llm_primary_threshold: Ratio = field(default_factory=lambda: Ratio(0.8))
    convergence_scenario_specific: bool = False
    sequence_window_sec: float = 86400.0
    sequence_full_bonus: float = 3.0
    sequence_partial_bonus: float = 2.0

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "ScoringSettings is final: a subclass could add a value the "
            "kernel reads but the disclosure record does not list, which "
            "is an undisclosed input to a published conclusion (NP6).")

    def __post_init__(self) -> None:
        object.__setattr__(self, "domain_cap",
                           _positive(self.domain_cap, name="domain_cap"))
        object.__setattr__(
            self, "global_signals_decoupled",
            _flag(self.global_signals_decoupled,
                  name="global_signals_decoupled"))
        object.__setattr__(
            self, "global_signal_weight",
            _as_ratio(self.global_signal_weight, name="global_signal_weight"))
        object.__setattr__(
            self, "llm_primary_country_only",
            _flag(self.llm_primary_country_only,
                  name="llm_primary_country_only"))
        object.__setattr__(
            self, "llm_primary_threshold",
            _as_ratio(self.llm_primary_threshold, name="llm_primary_threshold"))
        object.__setattr__(
            self, "convergence_scenario_specific",
            _flag(self.convergence_scenario_specific,
                  name="convergence_scenario_specific"))
        object.__setattr__(
            self, "sequence_window_sec",
            _positive(self.sequence_window_sec, name="sequence_window_sec"))
        # Positive, not merely finite. A zero bonus reads as "chain
        # detection off", but SEQUENCE_MIN_BONUS floors a qualifying chain
        # at 1.0 regardless — so 0 would quietly mean 1, and a negative
        # value would subtract score for detecting an escalation chain.
        object.__setattr__(
            self, "sequence_full_bonus",
            _positive(self.sequence_full_bonus, name="sequence_full_bonus"))
        object.__setattr__(
            self, "sequence_partial_bonus",
            _positive(self.sequence_partial_bonus,
                      name="sequence_partial_bonus"))

    def sequence_window(self, *, cadence_sec: float) -> Window:
        """The chain retention window as a kernel `Window`.

        The cadence is required rather than assumed: F-06 was a 30-"day"
        baseline holding 30 samples, and the two numbers only stay
        distinguishable when the cadence is stated at the call site.
        """
        return Window.from_days(self.sequence_window_sec / 86400.0,
                                cadence_sec=cadence_sec)

    def disclosed(self) -> dict:
        """JSON-primitive rendering for the provenance record (NP6)."""
        return {
            "domain_cap": self.domain_cap,
            "global_signals_decoupled": self.global_signals_decoupled,
            "global_signal_weight": self.global_signal_weight.value,
            "llm_primary_country_only": self.llm_primary_country_only,
            "llm_primary_threshold": self.llm_primary_threshold.value,
            "convergence_scenario_specific": self.convergence_scenario_specific,
            "sequence_window_sec": self.sequence_window_sec,
            "sequence_full_bonus": self.sequence_full_bonus,
            "sequence_partial_bonus": self.sequence_partial_bonus,
        }


def resolve_settings(resolve_threshold=None) -> ScoringSettings:
    """Resolve every variable key through the 3-layer chain. NOT PURE.

    The only function in `v3.scoring` that talks to configuration, and it
    is unreachable from `score_tick`. Call it once per tick, in the caller,
    and hand the result to the kernel.

    `resolve_threshold` is the INJECTION POINT, not a test seam. It takes a
    `Threshold` and returns a `ResolvedThreshold`, and the composition root
    supplies v3's own chain through it
    (`ConfigResolver.settings_resolver(ledger=..., at=...)`) — which is what
    makes an analyst's C7 override reach the scoring path rather than stop
    at the settings screen. Left unset it falls to `Threshold.resolve`,
    which for a registry-backed key now RAISES: the legacy fallback that
    used to answer there was removed in the §7-2 #115 sweep, because it
    booted the v1 application and v3 never wanted it. So an uninjected
    call fails loudly instead of resolving through a system nobody is
    running.

    The parameter is deliberately NOT named `resolver`: that name is the
    kernel's own seam, whose use outside `v3/config/resolution.py` the
    discipline gate refuses, and two differently-scoped things sharing a
    name is how a licence gets inherited by accident.

    Failures are not defaulted: `Threshold.resolve()` raises rather than
    substituting, because a silent fallback is exactly how 95 dead keys
    went unnoticed for months (G-15).
    """
    resolve_one = (Threshold.resolve if resolve_threshold is None
                   else resolve_threshold)
    values: dict[str, Any] = {}
    for name, entry in VARIABLE.items():
        raw = resolve_one(entry.threshold).value
        values[name] = getattr(raw, "value", raw)
    return ScoringSettings(
        domain_cap=values["DOMAIN_CAP"],
        global_signals_decoupled=bool(values["GLOBAL_SIGNALS_DECOUPLED"]),
        global_signal_weight=values["GLOBAL_SIGNAL_WEIGHT"],
        llm_primary_country_only=bool(values["LLM_INTEL_PRIMARY_COUNTRY_ONLY"]),
        llm_primary_threshold=values["LLM_INTEL_PRIMARY_THRESHOLD"],
        convergence_scenario_specific=bool(
            values["CONVERGENCE_SCENARIO_SPECIFIC"]),
        sequence_window_sec=values["SEQUENCE_WINDOW"],
        sequence_full_bonus=values["SEQUENCE_FULL_BONUS"],
        sequence_partial_bonus=values["SEQUENCE_PARTIAL_BONUS"],
    )


__all__ = ["ScoringSettings", "resolve_settings"]
