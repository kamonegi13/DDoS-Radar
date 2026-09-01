"""Kernel exception hierarchy.

Every kernel refusal raises one of these, and every message is expected to
name the correct alternative. A type that only says "no" teaches nothing;
the diagnosis behind this rebuild found engineers reaching for the wrong
construct because the right one was not obvious at the call site.
"""
from __future__ import annotations


class KernelError(Exception):
    """Base for every kernel contract violation."""


class DomainError(KernelError, ValueError):
    """A value outside the domain its type declares.

    ValueError as well, so `except ValueError` in calling code still sees
    a malformed-input error rather than being surprised.
    """


class UnitMismatchError(KernelError, TypeError):
    """An operation between incompatible units, or against a bare number.

    TypeError as well: this is the same category of mistake as adding a
    string to an integer, and should read that way in a traceback.
    """


class OrderingForbiddenError(KernelError, TypeError):
    """An ordering comparison the type deliberately refuses.

    Used by ThreatLevel, where the scale is inverted (TL1 = CRITICAL) and
    direct comparison silently means the opposite of what it reads.
    """


class StaleEvidenceError(KernelError):
    """Consuming an observation past its freshness horizon."""


class ProvenanceRequiredError(KernelError):
    """Building something that must carry provenance, without it."""


class ThresholdResolutionError(KernelError):
    """A threshold that could not be resolved through its declared path."""


__all__ = [
    "KernelError",
    "DomainError",
    "UnitMismatchError",
    "OrderingForbiddenError",
    "StaleEvidenceError",
    "ProvenanceRequiredError",
    "ThresholdResolutionError",
]
