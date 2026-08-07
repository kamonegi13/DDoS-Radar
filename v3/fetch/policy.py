"""The fetch policy constants — declared here, never by an adapter.

Design sheet §2-1: an adapter declares WHAT to fetch and HOW to normalize.
Timeout, retry, backoff, rate limiting and circuit breaking are not
declarable, because A-10 measured what happens when they are optional:
`_safe_get` / `_safe_post` / `handle_rate_limit` had **zero** callers, all
28 fetch implementations used raw requests, and only 8 of 36 sensors
handled 429 at all.

Every value below is a pinned kernel `Threshold`, so it is disclosed with
its source rather than sitting as a bare literal (P6 O-18). None of them
is registry-backed: an operator turning down the circuit breaker's failure
threshold during an incident is not a scenario anybody asked for, and the
values are load-bearing for NP3.
"""
from __future__ import annotations

from v3.kernel import Threshold

_PINNED: dict[str, Threshold] = {
    # S1-SCORE-038 pins the current values; the legacy constants live at
    # radar/sensors/base.py:17-19.
    "CB_FAILURE_THRESHOLD": Threshold.pinned(
        5, unit="count",
        provenance_ref="S1-SCORE-038 / radar/sensors/base.py:17 — "
                       "consecutive failures before the breaker opens"),
    "CB_INITIAL_DELAY_SEC": Threshold.pinned(
        300.0, unit="s",
        provenance_ref="S1-SCORE-038 / radar/sensors/base.py:18 — "
                       "first recovery delay, doubled on each failed probe"),
    "CB_MAX_DELAY_SEC": Threshold.pinned(
        3600.0, unit="s",
        provenance_ref="S1-SCORE-038 / radar/sensors/base.py:19 — "
                       "ceiling for the doubled recovery delay"),
    # S4-NF-002: a fetch without a timeout blocks the gevent loop. The
    # legacy default was per-call and frequently omitted.
    "HTTP_TIMEOUT_SEC": Threshold.pinned(
        20.0, unit="s",
        provenance_ref="S4-NF-002 (timeout mandatory on every fetch); "
                       "a missing timeout blocks the event loop"),
    # requests takes (connect, read) separately, and a single value applies
    # the same budget to both. Connecting should be fast or fail; reading a
    # large feed legitimately is not.
    "HTTP_CONNECT_TIMEOUT_SEC": Threshold.pinned(
        5.0, unit="s",
        provenance_ref="S4-NF-002: connect budget. A TCP handshake that "
                       "has not completed in 5s is not going to."),
    "HTTP_MAX_ATTEMPTS": Threshold.pinned(
        3, unit="count",
        provenance_ref="S1-PIPE-042's startup ladder is 3 attempts; the "
                       "same budget applies to an ordinary fetch"),
    "HTTP_BACKOFF_BASE_SEC": Threshold.pinned(
        1.0, unit="s",
        provenance_ref="Exponential base for retry backoff (attempt N waits "
                       "base * 2^(N-1))"),
    # D1 §4: OpenSky returns X-Rate-Limit-Retry-After-Seconds, and the
    # legacy client retries only when it is <= 120s — above that the
    # anonymous quota is exhausted and waiting is pointless.
    "RETRY_AFTER_MAX_SEC": Threshold.pinned(
        120.0, unit="s",
        provenance_ref="D1-sensors §4 (K01): honour Retry-After only up to "
                       "120s; a longer value means the daily quota is gone "
                       "and waiting cannot recover it"),
    "MAX_BODY_BYTES": Threshold.pinned(
        8_000_000, unit="count",
        provenance_ref="Guard against an upstream streaming an unbounded "
                       "body into memory; no legacy equivalent exists"),
}


def _value(name: str) -> float:
    resolved = _PINNED[name].resolve().value
    return float(getattr(resolved, "value", resolved))


CB_FAILURE_THRESHOLD = int(_value("CB_FAILURE_THRESHOLD"))
CB_INITIAL_DELAY_SEC = _value("CB_INITIAL_DELAY_SEC")
CB_MAX_DELAY_SEC = _value("CB_MAX_DELAY_SEC")
HTTP_TIMEOUT_SEC = _value("HTTP_TIMEOUT_SEC")
HTTP_CONNECT_TIMEOUT_SEC = _value("HTTP_CONNECT_TIMEOUT_SEC")
HTTP_MAX_ATTEMPTS = int(_value("HTTP_MAX_ATTEMPTS"))
HTTP_BACKOFF_BASE_SEC = _value("HTTP_BACKOFF_BASE_SEC")
RETRY_AFTER_MAX_SEC = _value("RETRY_AFTER_MAX_SEC")
MAX_BODY_BYTES = int(_value("MAX_BODY_BYTES"))


def pinned(name: str) -> Threshold:
    """The declaration behind a constant, for disclosure (NP6)."""
    return _PINNED[name]


def pinned_names() -> tuple[str, ...]:
    return tuple(sorted(_PINNED))


def backoff_delay(attempt: int) -> float:
    """Seconds to wait before `attempt` (1-based). Pure."""
    if attempt < 1:
        raise ValueError(f"attempt is 1-based, got {attempt}")
    return HTTP_BACKOFF_BASE_SEC * (2 ** (attempt - 1))


__all__ = ["CB_FAILURE_THRESHOLD", "CB_INITIAL_DELAY_SEC", "CB_MAX_DELAY_SEC",
           "HTTP_TIMEOUT_SEC", "HTTP_CONNECT_TIMEOUT_SEC", "HTTP_MAX_ATTEMPTS", "HTTP_BACKOFF_BASE_SEC",
           "RETRY_AFTER_MAX_SEC", "MAX_BODY_BYTES",
           "pinned", "pinned_names", "backoff_delay"]
