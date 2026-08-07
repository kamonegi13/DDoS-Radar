"""L0 source adapters — declarations only (design sheet §2).

An adapter says WHAT to fetch and HOW to normalize. It cannot say how to
fetch: no timeout, no retry, no parser choice, no circuit breaker, no
output destination. A-10 measured the alternative — the shared helpers
existed, were optional, and had zero callers across 28 implementations.

    types       the declaration vocabulary
    reference   `peeringdb_ixp`, the WP-2.6 pattern exemplar

The 34 real adapters land in WP-2.6 (cyber 7 + physical 15) and WP-2.7
(info 6 + LLM/meta 6, minus `convergence_tracker`, which O-17 abolishes
rather than ports).

Nothing here imports an HTTP library, opens a socket, reads the clock or
writes to L1 — enforced by the discipline gate and the boundary tests
rather than by convention.
"""
from v3.adapters.types import (AUTH_API_KEY, AUTH_NONE, AUTH_OAUTH2,
                               CATEGORIES, CYBER, INFO, LLM, META, PHYSICAL,
                               SCORING_DOMAINS, AdapterId, AuthRequirement,
                               FetchedPayload, NormalizeContext, NormalizeFn,
                               ObservationDraft, RequestSpec, SourceAdapter)

__all__ = [
    "AdapterId", "AuthRequirement", "RequestSpec", "FetchedPayload",
    "NormalizeContext", "ObservationDraft", "NormalizeFn", "SourceAdapter",
    "CATEGORIES", "SCORING_DOMAINS",
    "CYBER", "PHYSICAL", "INFO", "LLM", "META",
    "AUTH_NONE", "AUTH_API_KEY", "AUTH_OAUTH2",
]
