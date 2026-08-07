"""The ONLY module under `v3/` that imports an HTTP library.

Design sheet §1-4. `requests` is the choice, and the reasoning is parity
risk rather than ergonomics: v3 runs beside the legacy system until
cutover, the legacy system is `requests` + gevent monkey-patching with
years of operational history, and introducing a second HTTP stack would
double the monkey-patch surface, the connection pooling and the TLS
configuration — adding candidate causes to every parity difference we then
have to explain.

The dependency is confined to one file precisely so that swapping it later
costs one file. `scripts/check_kernel_discipline.py` fails the build on
any HTTP or socket import elsewhere under `v3/`, which is S4-NF-061's
"forbid direct calls in CI" branch. The other branch — making it
type-unreachable — was rejected because a determined caller can always
`import` something; a gate that reads every file cannot be talked around.

**Credentials are injected.** Nothing here reads the environment (the same
gate fails on `os.getenv`), so a key reaches a request only because the
composition root passed it in.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Optional

import requests

from v3.adapters.types import (AUTH_API_KEY, AUTH_OAUTH2, AuthRequirement,
                               FetchedPayload, RequestSpec)
from v3.fetch import policy
from v3.kernel.errors import DomainError

# ── outcomes recorded in fetch_log ──────────────────────────────────────
OK = "ok"
HTTP_ERROR = "http_error"
TIMEOUT = "timeout"
CONNECTION_ERROR = "connection_error"
RATE_LIMITED = "rate_limited"
TOO_LARGE = "too_large"
AUTH_MISSING = "auth_missing"

RETRYABLE_STATUSES: frozenset = frozenset({429, 500, 502, 503, 504})

#: D1 §4 K01 — OpenSky sends this header, and the legacy client honours it
#: only when it is <= 120s, because a larger value means the daily quota is
#: exhausted and no amount of waiting inside this cycle recovers it.
RETRY_AFTER_HEADERS = ("Retry-After", "X-Rate-Limit-Retry-After-Seconds")


@dataclass(frozen=True, slots=True)
class FetchOutcome:
    """One request's result, in the shape `fetch_log` stores."""

    outcome: str
    url: str
    requested_at: float
    latency_ms: float
    attempts: int = 1
    status: Optional[int] = None
    payload: Optional[FetchedPayload] = None
    body_sha256: Optional[str] = None
    detail: str = ""

    @property
    def succeeded(self) -> bool:
        return self.outcome == OK

    @property
    def url_sha256(self) -> str:
        return hashlib.sha256(self.url.encode("utf-8")).hexdigest()

    def as_log_row(self) -> dict:
        return {"requested_at": self.requested_at, "url_sha256":
                self.url_sha256, "http_status": self.status,
                "latency_ms": self.latency_ms, "outcome": self.outcome,
                "body_sha256": self.body_sha256, "detail": self.detail}


def _retry_after(headers) -> Optional[float]:
    """Read Retry-After off the response's own header mapping.

    Passed the live `CaseInsensitiveDict` rather than a `dict()` copy: the
    copy loses case-insensitivity, so a server answering `retry-after`
    instead of `Retry-After` would go unnoticed and the request would be
    retried into an exhausted quota.
    """
    for name in RETRY_AFTER_HEADERS:
        raw = headers.get(name)
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def _read_capped(response, max_body_bytes: int) -> tuple:
    """Read a streamed body, stopping the moment it exceeds the cap.

    `iter_content` rather than `.content`: the point of a size guard is to
    avoid holding an unbounded body in memory, and a check performed after
    buffering it has already failed at the only job it had.
    """
    chunks: list[bytes] = []
    seen = 0
    try:
        iterator = response.iter_content(chunk_size=65536)
    except AttributeError:      # a response object without streaming
        body = bytes(getattr(response, "content", b"") or b"")
        return (body, len(body) > max_body_bytes, len(body))
    try:
        for chunk in iterator:
            if not chunk:
                continue
            seen += len(chunk)
            if seen > max_body_bytes:
                return (b"", True, seen)
            chunks.append(chunk)
    finally:
        closer = getattr(response, "close", None)
        if callable(closer):
            closer()
    return (b"".join(chunks), False, seen)


class HttpClient:
    """The shared egress. One timeout policy, one retry ladder, one log.

    `session` and `sleeper` are injection seams for tests: the suite never
    touches the network (§6-1), and a real sleep would make the retry
    tests take a minute.
    """

    def __init__(self, *, credentials: Optional[Mapping[str, str]] = None,
                 session=None, timeout_sec: float = policy.HTTP_TIMEOUT_SEC,
                 connect_timeout_sec: float = policy.HTTP_CONNECT_TIMEOUT_SEC,
                 max_attempts: int = policy.HTTP_MAX_ATTEMPTS,
                 sleeper=time.sleep):
        if timeout_sec <= 0 or connect_timeout_sec <= 0:
            raise DomainError(
                f"timeouts must be positive, got connect="
                f"{connect_timeout_sec} read={timeout_sec}: a fetch without "
                f"one blocks the event loop (S4-NF-002)")
        if max_attempts < 1:
            raise DomainError(f"max_attempts must be >= 1, got {max_attempts}")
        self._credentials = MappingProxyType(dict(credentials or {}))
        self._session = session if session is not None else requests.Session()
        self._timeout_sec = float(timeout_sec)
        self._connect_timeout_sec = float(connect_timeout_sec)
        self._max_attempts = int(max_attempts)
        self._sleep = sleeper

    @property
    def timeout(self) -> tuple:
        """`(connect, read)` — the shape requests expects."""
        return (self._connect_timeout_sec, self._timeout_sec)

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def credentials(self) -> Mapping[str, str]:
        return self._credentials

    def close(self) -> None:
        close = getattr(self._session, "close", None)
        if callable(close):
            close()

    # ── auth ────────────────────────────────────────────────────────────
    def _auth_headers(self, auth: AuthRequirement) -> dict:
        if not auth.is_required:
            return {}
        secret = self._credentials.get(auth.key_id)
        if not secret:
            raise KeyError(auth.key_id)
        if auth.kind == AUTH_API_KEY:
            # abuse.ch ThreatFox requires Auth-Key on get_iocs too, since
            # 2024 (D1 §4 K10). The header name is the adapter's business;
            # supplying the value is the composition root's.
            return {"Auth-Key": secret}
        if auth.kind == AUTH_OAUTH2:
            return {"Authorization": f"Bearer {secret}"}
        return {}

    # ── the one fetch path ──────────────────────────────────────────────
    def fetch(self, spec: RequestSpec, *, now: float,
              auth: Optional[AuthRequirement] = None,
              max_body_bytes: int = policy.MAX_BODY_BYTES) -> FetchOutcome:
        """Perform one declared request, with the shared policy applied."""
        if not isinstance(spec, RequestSpec):
            raise DomainError(
                f"fetch takes a RequestSpec, got {type(spec).__name__}")
        requirement = auth or AuthRequirement()
        started = time.perf_counter()
        try:
            headers = {**dict(spec.headers), **self._auth_headers(requirement)}
        except KeyError as missing:
            return FetchOutcome(
                outcome=AUTH_MISSING, url=spec.url, requested_at=now,
                latency_ms=0.0,
                detail=f"credential {missing.args[0]!r} was not supplied by "
                       f"the composition root; nothing under v3/ reads the "
                       f"environment")

        last_detail = ""
        status: Optional[int] = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                response = self._session.request(
                    spec.method, spec.url, params=dict(spec.params),
                    headers=headers, timeout=self.timeout, stream=True)
            except requests.Timeout as exc:
                last_detail = f"timeout after {self._timeout_sec}s: {exc}"
                if attempt < self._max_attempts:
                    self._sleep(policy.backoff_delay(attempt))
                    continue
                return FetchOutcome(
                    outcome=TIMEOUT, url=spec.url, requested_at=now,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    attempts=attempt, detail=last_detail)
            except requests.RequestException as exc:
                last_detail = f"{type(exc).__name__}: {exc}"
                if attempt < self._max_attempts:
                    self._sleep(policy.backoff_delay(attempt))
                    continue
                return FetchOutcome(
                    outcome=CONNECTION_ERROR, url=spec.url, requested_at=now,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    attempts=attempt, detail=last_detail)

            status = int(getattr(response, "status_code", 0))
            response_headers = getattr(response, "headers", {}) or {}
            body, oversized, seen = _read_capped(response, max_body_bytes)

            if oversized:
                # The read is ABANDONED at the cap, not measured after the
                # fact: buffering the whole body and then complaining about
                # its size is a guard that has already lost.
                return FetchOutcome(
                    outcome=TOO_LARGE, url=spec.url, requested_at=now,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    attempts=attempt, status=status,
                    detail=f"stopped after {seen} bytes; exceeds the "
                           f"{max_body_bytes}-byte cap")

            if status in RETRYABLE_STATUSES and attempt < self._max_attempts:
                delay = _retry_after(response_headers)
                if delay is not None and delay > policy.RETRY_AFTER_MAX_SEC:
                    # K01: the quota is gone. Waiting cannot recover it,
                    # so record the refusal instead of sleeping through it.
                    return FetchOutcome(
                        outcome=RATE_LIMITED, url=spec.url, requested_at=now,
                        latency_ms=(time.perf_counter() - started) * 1000.0,
                        attempts=attempt, status=status,
                        detail=f"Retry-After {delay}s exceeds the "
                               f"{policy.RETRY_AFTER_MAX_SEC}s ceiling; the "
                               f"quota is exhausted, not merely throttled")
                self._sleep(delay if delay is not None
                            else policy.backoff_delay(attempt))
                last_detail = f"HTTP {status}, retrying"
                continue

            latency_ms = (time.perf_counter() - started) * 1000.0
            digest = hashlib.sha256(body).hexdigest()
            if status == 429:
                return FetchOutcome(
                    outcome=RATE_LIMITED, url=spec.url, requested_at=now,
                    latency_ms=latency_ms, attempts=attempt, status=status,
                    body_sha256=digest, detail="HTTP 429")
            if status >= 400:
                return FetchOutcome(
                    outcome=HTTP_ERROR, url=spec.url, requested_at=now,
                    latency_ms=latency_ms, attempts=attempt, status=status,
                    body_sha256=digest, detail=f"HTTP {status}")
            return FetchOutcome(
                outcome=OK, url=spec.url, requested_at=now,
                latency_ms=latency_ms, attempts=attempt, status=status,
                body_sha256=digest,
                payload=FetchedPayload(
                    url=spec.url, status=status, body=body, fetched_at=now,
                    content_type=str(response_headers.get("Content-Type", "")),
                    label=spec.label))

        raise AssertionError(   # pragma: no cover - structurally unreachable
            "fetch fell out of its retry loop: every path inside returns or "
            "continues, and the final attempt cannot continue. Reaching here "
            "means the loop's exit conditions were changed without updating "
            "this contract.")


__all__ = ["HttpClient", "FetchOutcome", "OK", "HTTP_ERROR", "TIMEOUT",
           "CONNECTION_ERROR", "RATE_LIMITED", "TOO_LARGE", "AUTH_MISSING",
           "RETRYABLE_STATUSES", "RETRY_AFTER_HEADERS"]
