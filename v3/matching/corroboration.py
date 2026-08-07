"""Corroboration: the one thing that survives the convergence machinery.

Design sheet §4-3 disposes of two production mechanisms at once.

`convergence_tracker` is NOT ported. It was a second scoring pipeline —
it read a private SQLite of its own (A-09), reached across into data the
scoring layer owns (DP10), and emitted `domain="mixed"`, a fourth value
outside the three-domain vocabulary (A5). None of the three has anywhere
to land in v3, and its actual question — "are several sources looking at
the same event?" — is answered here and returned as METADATA. It produces
no score. P6 O-17: the convergence arithmetic exists exactly once, in the
S5 formula already implemented in `v3/scoring/convergence.py`, whose
inputs are the domain count and the participant count. Matching makes
those inputs; it does not add to them.

The corroboration engine keeps only its MATCHING function, and production
carried THREE definitions of "corroborator". One survives:

    a corroborator is a DIFFERENT `signal_source` that independently
    observed the same event.

`signal_source` is the right identity because it is what S1-SCORE-008
already dedups on: two readings under one source are one fact folded by
MAX, so counting them as mutual corroboration would count that one fact
twice and inflate the very convergence NP2 rests on.

Pure. No I/O, no clock, no score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Sequence

from v3.kernel.errors import DomainError
from v3.matching.similarity import DEFAULT_THRESHOLD, MatchVerdict, jaccard


@dataclass(frozen=True, slots=True)
class Observed:
    """One source's account of an event, as matching needs it."""

    signal_source: str
    headline: str

    def __post_init__(self) -> None:
        for name in ("signal_source", "headline"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise DomainError(f"Observed.{name} must be a string")
        object.__setattr__(self, "signal_source", self.signal_source.strip())
        if not self.signal_source:
            raise DomainError(
                "Observed.signal_source must be non-empty: an unlabelled "
                "account cannot be shown to be independent of any other, "
                "and counting it would be counting an unknown twice")


@dataclass(frozen=True, slots=True)
class Corroboration:
    """The verdict. Deliberately not a number.

    `independent_sources` is the count NP2's convergence reads THROUGH
    the scoring kernel's own inputs — it is reported here so an analyst
    can see the basis, not so anything here can turn it into points.
    """

    subject: Observed
    supporters: tuple[Observed, ...] = ()
    similarities: Mapping[str, float] = field(default_factory=dict)
    threshold: float = DEFAULT_THRESHOLD

    def __post_init__(self) -> None:
        object.__setattr__(self, "similarities",
                           MappingProxyType(dict(self.similarities or {})))

    @property
    def is_corroborated(self) -> bool:
        return bool(self.supporters)

    @property
    def independent_sources(self) -> int:
        """The subject plus every distinct supporting source."""
        return len({self.subject.signal_source}
                   | {s.signal_source for s in self.supporters})

    @property
    def group_key(self) -> str:
        """A stable identity for the matched set (NP6 / AP4).

        Sorted, so the same set of accounts produces the same key
        whatever order they arrived in — a group id that depends on
        iteration order cannot be re-derived from the ledger later.
        """
        return "|".join(sorted(
            {self.subject.signal_source}
            | {s.signal_source for s in self.supporters}))

    def as_dict(self) -> dict:
        return {
            "signal_source": self.subject.signal_source,
            "corroborated": self.is_corroborated,
            "corroboration_group": self.group_key,
            "independent_sources": self.independent_sources,
            "supporting_sources": tuple(
                sorted({s.signal_source for s in self.supporters})),
            "similarities": dict(self.similarities),
            "threshold": self.threshold,
        }


def corroborate(subject: Observed, candidates: Sequence[Observed], *,
                threshold: float = DEFAULT_THRESHOLD) -> Corroboration:
    """Who else saw this, under a different source label.

    Same-source candidates are skipped before matching, not after: they
    are the same instrument reporting twice, and letting them into the
    similarity map would publish a "corroboration" an analyst would then
    have to un-count by hand.

    Matching is `v3.matching`'s tier 1 — script-aware segmentation, so a
    Japanese headline and a Russian one each produce non-empty tokens
    instead of the empty set `re.findall(r"[a-z]{3,}")` produced for both
    (F-09). Cross-LANGUAGE matching is tier 2 and stays off by default;
    `MatchVerdict` states the skip rather than hiding it.
    """
    supporters: list[Observed] = []
    similarities: dict[str, float] = {}
    for candidate in candidates:
        if candidate.signal_source == subject.signal_source:
            continue
        score = jaccard(subject.headline, candidate.headline)
        similarities[candidate.signal_source] = max(
            score, similarities.get(candidate.signal_source, 0.0))
        if score >= threshold:
            supporters.append(candidate)
    return Corroboration(subject=subject, supporters=tuple(supporters),
                         similarities=similarities, threshold=threshold)


def verdict_for(subject: Observed, candidates: Sequence[Observed], *,
                threshold: float = DEFAULT_THRESHOLD) -> MatchVerdict:
    """The tier-1 verdict for the best-matching candidate, for auditing."""
    best = 0.0
    for candidate in candidates:
        if candidate.signal_source == subject.signal_source:
            continue
        best = max(best, jaccard(subject.headline, candidate.headline))
    return MatchVerdict(same_event=best >= threshold, similarity=best,
                        threshold=threshold)


__all__ = ["Observed", "Corroboration", "corroborate", "verdict_for"]
