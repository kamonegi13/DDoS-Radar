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
    #
    # 15, not 5, and the difference is a measured fact: urllib3 applies
    # this budget to the TLS handshake as well as the TCP connect, and
    # api.gdeltproject.org completes TCP in 0.2s but TLS in 9.0-10.3s
    # (three runs, 2026-08-13, from the shadow container). At 5s every
    # gdelt fetch died in the handshake — 108 of 108 in six hours — while
    # urllib3 labelled the failure "Read timed out (read timeout=5.0)",
    # which pointed a day's diagnosis at the wrong half of the tuple. The
    # cost of the raise is bounded and priced into FETCH_BUDGET_REQUESTS
    # below: one dead host now burns 108s across the retry ladder, not 78s.
    "HTTP_CONNECT_TIMEOUT_SEC": Threshold.pinned(
        15.0, unit="s",
        provenance_ref="S4-NF-002: connect budget, which urllib3 also "
                       "applies to the TLS handshake; sized above the "
                       "measured 9.0-10.3s TLS handshake of "
                       "api.gdeltproject.org (2026-08-13), which 5s "
                       "classified as permanently dead"),
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
    # G-19: a cold ledger has an empty `fetch_schedule`, so EVERY adapter
    # is due in the same tick. Measured against the deployed geography (4
    # scenarios, 27 participants) that first plan is 772 expanded steps and
    # up to 935 requests, and two shadow runs were still inside `ppoll` at
    # twenty-five minutes having reached neither the scoring stage nor a
    # single `tl_observation`. A first sweep that cannot finish is a
    # deployment that cannot reach a first conclusion, which NP5+8 makes a
    # design failure rather than a slow start.
    #
    # 120 is derived, not chosen. `ops_health.LOOP_MIN_OVERDUE_SEC` is the
    # 300s at which this programme's own health surface calls a deployment
    # late, and the shadow ledger's measured cost is ~2.5s per request
    # across the whole sweep (311 requests in >25 min; the healthy-only p95
    # is 0.6s, so the average is carried by the timeout and retry paths —
    # 3 attempts x (15s connect + 20s read) + backoff is 108s for one dead
    # host, up from 78s when the connect budget was 5s). 120 x 2.5s = 300s,
    # so one tick's fetch stage is sized to the same budget the monitor
    # judges it by, and the 772-step cold sweep completes in seven ticks —
    # well inside `first_tick_grace` (1800s).
    "FETCH_BUDGET_REQUESTS": Threshold.pinned(
        120, unit="count",
        provenance_ref="G-19 / ops_health.LOOP_MIN_OVERDUE_SEC (300s) at "
                       "the shadow ledger's measured ~2.5s per request "
                       "across a full sweep; bounds ONE tick's fetch stage "
                       "so a cold start reaches a conclusion by staging "
                       "the sweep instead of never finishing it"),
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
FETCH_BUDGET_REQUESTS = int(_value("FETCH_BUDGET_REQUESTS"))
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
           "RETRY_AFTER_MAX_SEC", "FETCH_BUDGET_REQUESTS", "MAX_BODY_BYTES",
           "pinned", "pinned_names", "backoff_delay"]
