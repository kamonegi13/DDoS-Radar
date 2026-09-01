"""Language-independent matching — F-09's repair (design sheet §5).

    normalize(text)          NFKC + casefold + category-based stripping
    tokens(text)             a non-empty token set for EVERY script
    jaccard(a, b)            set overlap
    same_event(a, b)         the Tier 1 verdict
    corroborate(subject, …)  who else, under a DIFFERENT signal_source,
                             saw the same event (design sheet §4-3 — the
                             one function that survives the corroboration
                             engine; `convergence_tracker` itself is not
                             ported and its verdict becomes metadata)

The defect: `re.findall(r"[a-z]{3,}", ...)` gives Japanese, Chinese,
Russian and Arabic headlines zero tokens, so those sources can never
corroborate one another — the convergence input is structurally
English-only, which D2 rates CRITICAL and NP2-direct.

Tier 1 (here) is deterministic and has no I/O, which is what lets a parity
run replay it. Tier 2 (cross-language embeddings) is out of scope by
ruling 2 and its absence is reported in every verdict rather than left for
the reader to assume.

Nothing in this package returns a score: O-17 keeps the convergence
arithmetic in S5 alone.
"""
from v3.matching.corroboration import (Corroboration, Observed, corroborate,
                                       verdict_for)
from v3.matching.segment import (MIN_WORD_LENGTH, NGRAM_SIZE, is_unspaced,
                                 normalize, tokens)
from v3.matching.similarity import (DEFAULT_THRESHOLD, TIER2_DISABLED_REASON,
                                    MatchVerdict, jaccard, same_event)

__all__ = [
    "normalize", "tokens", "is_unspaced",
    "jaccard", "same_event", "MatchVerdict",
    "corroborate", "verdict_for", "Corroboration", "Observed",
    "MIN_WORD_LENGTH", "NGRAM_SIZE", "DEFAULT_THRESHOLD",
    "TIER2_DISABLED_REASON",
]
