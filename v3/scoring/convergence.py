"""Convergence: how many independent domains agree, and what that is worth.

NP2 says a conclusion's strength comes from independent sensors agreeing.
P6 O-17 rules that the arithmetic for that lives in exactly one place —
here — and that the other five or six mechanisms which asked "are these
sources seeing the same event?" become *inputs* (independence metadata)
rather than parallel scorers.

The tiers implemented are the effective path's (`radar/scoring.py:1163-1174`):
domain count decides the bonus, and when `CONVERGENCE_SCENARIO_SPECIFIC`
is on, a three-domain convergence carried by a single participant is
downgraded to the two-domain bonus. Three domains lit by one country
flooding three pipes is not what NP2 means.
"""
from __future__ import annotations

from v3.kernel.errors import DomainError
from v3.scoring.thresholds import (CONVERGENCE_DUAL_BONUS,
                                   CONVERGENCE_DUAL_MIN_DOMAINS,
                                   CONVERGENCE_FULL_BONUS,
                                   CONVERGENCE_FULL_MIN_DOMAINS,
                                   CONVERGENCE_MIN_PARTICIPANTS)

NONE = "NONE"
SINGLE_DOMAIN = "SINGLE_DOMAIN"
DUAL_DOMAIN = "DUAL_DOMAIN"
FULL_CONVERGENCE = "FULL_CONVERGENCE"

FORMULA_REF = "v3.scoring.convergence@S1-SCORE-003+007"


def convergence_level(domain_count: int) -> str:
    """S1-SCORE-003: name the number of domains carrying score."""
    if isinstance(domain_count, bool) or not isinstance(domain_count, int):
        raise DomainError(
            f"domain_count must be an int, got "
            f"{type(domain_count).__name__} {domain_count!r}")
    if domain_count < 0:
        raise DomainError(f"domain_count cannot be negative, got {domain_count}")
    if domain_count == 0:
        return NONE
    if domain_count == 1:
        return SINGLE_DOMAIN
    if domain_count == 2:
        return DUAL_DOMAIN
    return FULL_CONVERGENCE


def convergence_bonus(domain_count: int, distinct_participants: int, *,
                      scenario_specific: bool) -> float:
    """S1-SCORE-007: the bonus, with the single-participant downgrade.

    Tiers, evaluated top down:
      >= 3 domains, and (if the gate is on) >= 2 participants  -> 2.0
      >= 3 domains but only 1 participant, gate on             -> 1.0
      == 2 domains                                             -> 1.0
      otherwise                                                -> 0.0

    The downgrade is a *demotion to the dual tier*, not a removal: two
    domains' worth of credit for evidence that did converge across
    domains, just not across countries.
    """
    if isinstance(distinct_participants, bool) or \
            not isinstance(distinct_participants, int):
        raise DomainError(
            f"distinct_participants must be an int, got "
            f"{type(distinct_participants).__name__} "
            f"{distinct_participants!r}")
    if distinct_participants < 0:
        raise DomainError(
            f"distinct_participants cannot be negative, got "
            f"{distinct_participants}")
    if isinstance(domain_count, bool) or not isinstance(domain_count, int):
        raise DomainError(
            f"domain_count must be an int, got "
            f"{type(domain_count).__name__} {domain_count!r}")

    if domain_count >= CONVERGENCE_FULL_MIN_DOMAINS:
        if scenario_specific and \
                distinct_participants < CONVERGENCE_MIN_PARTICIPANTS:
            return CONVERGENCE_DUAL_BONUS
        return CONVERGENCE_FULL_BONUS
    if domain_count == CONVERGENCE_DUAL_MIN_DOMAINS:
        return CONVERGENCE_DUAL_BONUS
    return 0.0


__all__ = ["convergence_level", "convergence_bonus", "FORMULA_REF",
           "NONE", "SINGLE_DOMAIN", "DUAL_DOMAIN", "FULL_CONVERGENCE"]
