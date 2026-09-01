"""`peeringdb_ixp` as the pattern exemplar — now pointing at the real port.

**Status: WP-2.6 finalised this adapter.** It lives at
`v3/adapters/physical/peeringdb_ixp.py` with the rest of the physical
batch, and this module re-exports it so the WP-2.5 narrative — "here is
the shape every adapter takes" — keeps a home and one declaration
remains the only declaration. Two modules each building a `SourceAdapter`
for the same identifier would be two adapters, and the registry would
reject the duplicate (correctly, and confusingly).

What made it the exemplar, and still does:

  * no authentication, so the auth seam is visible by its absence
  * a courtesy delay (PeeringDB 10s, D1 §4 K15) expressed through the
    shared rate-limit mechanism rather than a `sleep` in a fetch function
  * plain field extraction, so `normalize` is legible as what it is: a
    pure function from bytes to values

Read what this module CANNOT do. There is no HTTP import, no client
handle, no ledger handle, no clock, and no way to reach any of them: the
discipline gate fails the build on an HTTP or socket import anywhere
under `v3/adapters/`, and `normalize` receives bytes that were fetched
before it was called. That is §2-2's four barriers in practice — and it
is the answer to A-10, where the shared helpers existed, were optional,
and had zero callers.

The one thing WP-2.6 changed is the scoring rule the exemplar left open.
It guessed FIRED when a country had no exchanges; the clause's consumer
(core.py:1193) emits OK with score 0, always. See the module docstring
there for why the guess would have been worse than a no-op.
"""
from v3.adapters.physical.peeringdb_ixp import (COUNTRY_CACHE_TTL_SEC,
                                                PEERINGDB_IXP,
                                                PEERINGDB_IXP_ADAPTER,
                                                PEERINGDB_MIN_INTERVAL_SEC,
                                                PEERINGDB_RETRY_AFTER_SEC,
                                                normalize)

__all__ = ["PEERINGDB_IXP", "PEERINGDB_IXP_ADAPTER", "normalize",
           "PEERINGDB_MIN_INTERVAL_SEC", "PEERINGDB_RETRY_AFTER_SEC",
           "COUNTRY_CACHE_TTL_SEC"]
