"""radar.sensors.ct_log_sources.issuer_parse -- shared issuer normalizer.

Both CrtshSource and CertspotterSource (and any future CT source) need to
collapse the CA's distinguished name to a stable canonical form so that
the same CA arriving via different sources collapses to the same key in
the buffer's idempotency map and in the per-domain known-CA DB table.

Kept in its own tiny module — not on BaseCtLogPullSource — so that:

  * Push sources (which don't subclass the pull base) get the same parser
    without inheriting the pull contract.
  * Test code can import it without standing up a full source instance.
"""
from __future__ import annotations


def parse_issuer(issuer_name: str) -> tuple[str, str]:
    """Return (normalized_for_dedup, raw_for_display).

    Normalization rules (intentionally simple — the goal is consistent
    keying across sources, not RFC-perfect DN parsing):

      1. Pick the O= component if present (organization).
      2. Else fall back to the CN= component (common name).
      3. Else use the whole string verbatim.
      4. Lowercase + strip + remove surrounding quotes for the final key.

    Returns ("unknown", "unknown") on empty input. Sources should drop
    observations that normalize to "unknown" — without an issuer key the
    DB-backed dedup falls apart.
    """
    if not issuer_name:
        return ("unknown", "unknown")
    raw = issuer_name.strip()
    parsed_o = None
    for part in raw.split(","):
        s = part.strip()
        if s.upper().startswith("O="):
            parsed_o = s[2:].strip().strip('"').strip("'")
            break
    if not parsed_o:
        for part in raw.split(","):
            s = part.strip()
            if s.upper().startswith("CN="):
                parsed_o = s[3:].strip().strip('"').strip("'")
                break
    canonical = (parsed_o or raw).lower().strip()
    return (canonical, raw)
