"""Similarity and the same-event verdict. Neither returns a score.

O-17 rules that the convergence arithmetic lives in exactly one place —
S5's scoring kernel. Matching answers a different question ("are these two
reports about the same event?") and hands the answer to S5, which decides
what it is worth. So `MatchVerdict` deliberately carries no score field,
and the tests assert its absence: a similarity that quietly became a
score is how a second scorer grows.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from v3.kernel.errors import DomainError
from v3.matching.segment import tokens

#: Default agreement bar. Deliberately a parameter at every call site
#: rather than a constant somebody has to go looking for.
DEFAULT_THRESHOLD = 0.5

#: Ruling 2: Tier 2 (cross-language embeddings) is off in v3.0. Enabling
#: it would make matching depend on a model response, which S5-VERIF-022
#: would then require be recorded for every parity run — breaking
#: determinism to fix a defect Tier 1 already closes.
TIER2_DISABLED_REASON = (
    "tier 2 (cross-language embedding) is disabled by default: enabling it "
    "makes matching depend on a model response, which S5-VERIF-022 requires "
    "be recorded for replay (ruling 2)")


@dataclass(frozen=True, slots=True)
class MatchVerdict:
    """Whether two texts describe one event, and how sure on what basis.

    `tier2_skipped_reason` is populated whenever Tier 2 did not run, so a
    reader can tell "these did not match" from "cross-language matching
    was never attempted" — the same discipline S5-VERIF-022 applies to
    conclusion types excluded from parity.
    """

    same_event: bool
    similarity: float
    threshold: float
    tier: int = 1
    tier2_skipped_reason: Optional[str] = TIER2_DISABLED_REASON

    def __post_init__(self) -> None:
        if not 0.0 <= self.similarity <= 1.0:
            raise DomainError(
                f"similarity must be within [0,1], got {self.similarity}")


def jaccard(left: str, right: str) -> float:
    """Set overlap of the two token sets.

    Two texts that both tokenize to nothing score 0.0, not 1.0. The
    parity comparator treats two empty contributor sets as agreement
    because both systems genuinely observed nothing; here the question is
    whether two reports describe the same event, and two headlines with no
    content are not evidence that they do.
    """
    left_tokens = tokens(left)
    right_tokens = tokens(right)
    union = left_tokens | right_tokens
    if not union:
        return 0.0
    return len(left_tokens & right_tokens) / len(union)


def same_event(left: str, right: str, *,
               threshold: float = DEFAULT_THRESHOLD) -> MatchVerdict:
    """The Tier 1 verdict. Pure, deterministic, no I/O."""
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise DomainError(
            f"threshold must be a number, got {type(threshold).__name__}")
    if not 0.0 <= threshold <= 1.0:
        raise DomainError(
            f"threshold must be within [0,1], got {threshold}")
    similarity = jaccard(left, right)
    return MatchVerdict(
        same_event=similarity > 0.0 and similarity >= threshold,
        similarity=similarity, threshold=float(threshold), tier=1)


__all__ = ["MatchVerdict", "jaccard", "same_event", "DEFAULT_THRESHOLD",
           "TIER2_DISABLED_REASON"]
