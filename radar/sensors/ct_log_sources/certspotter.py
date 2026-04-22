"""radar.sensors.ct_log_sources.certspotter -- SSLMate Certspotter source.

Pull source. Replaces crt.sh as the primary CT data path after the
Phase 2 root-cause investigation found crt.sh in chronic production
silence (10s timeout floor against typical 7-30s response times,
per-request instability, and 404 on apex-only Identity= queries for
domains that only issue subdomain certs).

Why certspotter over the alternatives:

  * `include_subdomains=true` — one query per watched apex returns the
    subdomain certs we actually need, eliminating the multi-subdomain
    enumeration that the round-robin per-domain budget couldn't cover.
  * Empirically 0.9-2.3s response times vs. crt.sh's 7-30s. Sustainable
    inside the orchestrator's per-cycle timing budget.
  * Stable JSON contract documented at
    https://github.com/SSLMate/certspotter/blob/master/cmd/certspotter/api.md
    (so we won't get the schema-drift surprises crt.sh sometimes ships).

Trade-off: free tier is rate-limited to ~30 requests/hour per IP. With
N watched domains and a normal 1h fetch cycle that's well under budget,
but we still install a token-bucket limiter so a degraded-mode probe
storm or a misconfigured watched-list expansion can't hammer the API
into 429-permanent. The orchestrator's existing CrtshSource stays in
the source list as a fallback for the cases certspotter rejects (some
ccTLD gov domains are 403 from certspotter — see Phase 2D audit).
"""
from __future__ import annotations

import logging
import threading
import time
import requests

from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY,
    CT_LOG_QUERY_TIMEOUT_SEC,
)
from radar.sensors.ct_log_sources.base import (
    BaseCtLogPullSource,
    CertObservation,
)
from radar.sensors.ct_log_sources.buffer import make_observation
from radar.sensors.ct_log_sources.issuer_parse import parse_issuer

log = logging.getLogger("radar")

_CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
_USER_AGENT = "OSINT-Radar/8.0 (CT-anomaly-detector)"
# Free-tier ceiling is 30 req/hr. Default to 25 to leave headroom for
# the rate limiter's window edges and to avoid clipping right against
# the upstream's own counter.
_DEFAULT_RATE_LIMIT_CALLS = 25
_DEFAULT_RATE_LIMIT_WINDOW_SEC = 3600
_FAILURE_MODES_INIT = {
    "timeout": 0,
    "conn_error": 0,
    "http_5xx": 0,
    "http_4xx": 0,
    "http_403": 0,
    "json_error": 0,
    "empty_result": 0,
    "rate_limited_local": 0,
}


class _TokenBucket:
    """Sliding-window rate limiter.

    Not a true token bucket — a fixed-window counter would be cheaper
    but would let the source burst all 25 calls in the last second of
    one window and the first second of the next. Sliding window is
    fairer to the upstream and the implementation cost is trivial at
    these sizes.
    """

    def __init__(self, max_calls: int, window_sec: int):
        self._max = max(1, int(max_calls))
        self._window = max(60, int(window_sec))
        self._calls: list[float] = []
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            self._calls = [t for t in self._calls if t > cutoff]
            if len(self._calls) >= self._max:
                return False
            self._calls.append(now)
            return True

    def remaining(self) -> int:
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            self._calls = [t for t in self._calls if t > cutoff]
            return max(0, self._max - len(self._calls))

    def next_slot_in_sec(self) -> float:
        """Seconds until the oldest in-window call ages out (i.e. when
        the next acquire could succeed). Returns 0.0 if room is available."""
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            self._calls = [t for t in self._calls if t > cutoff]
            if len(self._calls) < self._max:
                return 0.0
            oldest = self._calls[0]
            return max(0.0, oldest + self._window - now)


class CertspotterSource(BaseCtLogPullSource):
    """SSLMate Certspotter REST source. Per-domain query, returns issuances
    including subdomains and wildcards.

    Free-tier: no API key required, 30 req/hr/IP. The optional
    Authorization header (`Authorization: Bearer <token>`) raises the
    limit substantially — pass via the constructor when the operator
    has provisioned a token in config.env (CERTSPOTTER_API_TOKEN).
    """

    name = "certspotter"

    def __init__(
        self,
        api_token: str | None = None,
        rate_limit_calls: int = _DEFAULT_RATE_LIMIT_CALLS,
        rate_limit_window_sec: int = _DEFAULT_RATE_LIMIT_WINDOW_SEC,
    ):
        self._api_token = (api_token or "").strip() or None
        self._failure_modes: dict[str, int] = dict(_FAILURE_MODES_INIT)
        self._success_count: int = 0
        self._consecutive_failures: int = 0
        self._last_success_ts: float = 0.0
        self._status: str = "unknown"
        self._rate_limited_until_ts: float = 0.0
        self._last_retry_after_sec: int = 0
        self._cb_open_until_ts: float = 0.0
        # Authenticated callers get a much higher upstream allowance, so
        # widen the local bucket too. Still cap to a sane multiple to
        # avoid bursts that would inflate latency for other tenants.
        if self._api_token:
            rate_limit_calls = max(rate_limit_calls, 250)
        self._bucket = _TokenBucket(rate_limit_calls, rate_limit_window_sec)
        self._rate_limit_calls = rate_limit_calls
        self._rate_limit_window_sec = rate_limit_window_sec

    # ── Public API: pull contract ─────────────────────────────────────
    def fetch_domain(self, domain: str) -> list[CertObservation] | None:
        """Query certspotter for one watched apex domain, including
        subdomains and wildcard matches.

        Returns:
            list[CertObservation] (possibly empty) on transport success,
            None on hard failure / suppression. The orchestrator treats
            None as "do not advance the warm-up marker" — same contract
            CrtshSource follows.
        """
        now = time.time()
        if self._cb_open_until_ts > now:
            return None
        if self._rate_limited_until_ts > now:
            return None
        if not self._bucket.try_acquire():
            self._failure_modes["rate_limited_local"] += 1
            log.debug(
                f"[CTLog/certspotter] Local rate-limit hit for {domain}; "
                f"next slot in {self._bucket.next_slot_in_sec():.0f}s"
            )
            return None

        certs = self._fetch_issuances(domain)
        if certs is None:
            self._consecutive_failures += 1
            return None

        self._success_count += 1
        self._consecutive_failures = 0
        self._last_success_ts = time.time()
        self._status = "healthy"

        if not certs:
            self._failure_modes["empty_result"] += 1
            return []

        out: list[CertObservation] = []
        for cert in certs[:200]:
            issuer_obj = cert.get("issuer") or {}
            # Certspotter wraps the DN in {"name": "C=..., O=..., CN=..."}.
            # Treat anything else as malformed and skip — we can't dedup
            # without a stable issuer key.
            issuer_name = ""
            if isinstance(issuer_obj, dict):
                issuer_name = (issuer_obj.get("name") or "").strip()
            elif isinstance(issuer_obj, str):
                issuer_name = issuer_obj.strip()
            ca_norm, ca_raw = parse_issuer(issuer_name)
            if ca_norm == "unknown":
                continue

            dns_names = cert.get("dns_names") or []
            if not isinstance(dns_names, list):
                dns_names = []
            cn = ""
            for n in dns_names:
                if n and isinstance(n, str) and not n.startswith("*."):
                    cn = n
                    break
            if not cn and dns_names:
                # Fall back to the wildcard form so the wildcard-TLD
                # detector still sees it via the SAN list.
                cn = dns_names[0] if isinstance(dns_names[0], str) else ""

            obs = make_observation(
                domain=domain,
                issuer_raw=ca_raw,
                issuer_norm=ca_norm,
                common_name=cn,
                subject_alt_names=[s for s in dns_names if isinstance(s, str)],
                not_before_iso=cert.get("not_before") or "",
                serial=str(cert.get("id") or ""),
                source_name=self.name,
            )
            if obs is not None:
                out.append(obs)
        return out

    def health(self) -> dict:
        now = time.time()
        rate_limited = self._rate_limited_until_ts > now
        cb_open = self._cb_open_until_ts > now
        return {
            "status": self._status,
            "last_success_ts": self._last_success_ts,
            "consecutive_failures": self._consecutive_failures,
            "mode_counters": dict(self._failure_modes),
            "source_specific": {
                "success_count": self._success_count,
                "authenticated": bool(self._api_token),
                "rate_limit_calls": self._rate_limit_calls,
                "rate_limit_window_sec": self._rate_limit_window_sec,
                "local_bucket_remaining": self._bucket.remaining(),
                "rate_limited": rate_limited,
                "rate_limited_remaining_sec": (
                    round(self._rate_limited_until_ts - now, 1)
                    if rate_limited else 0
                ),
                "last_retry_after_sec": self._last_retry_after_sec,
                "cb_open": cb_open,
                "cb_open_remaining_sec": (
                    round(self._cb_open_until_ts - now, 1) if cb_open else 0
                ),
            },
        }

    def mark_dead(self, cooldown_sec: float) -> None:
        """Orchestrator hook — open this source's CB for `cooldown_sec`."""
        self._cb_open_until_ts = time.time() + max(0.0, cooldown_sec)
        self._status = "dead"

    # ── Internal: HTTP transport ──────────────────────────────────────
    def _fetch_issuances(self, domain: str) -> list[dict] | None:
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "match_wildcards": "true",
            "expand": ["dns_names", "issuer"],
        }
        headers = {
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
        }
        if self._api_token:
            headers["Authorization"] = f"Bearer {self._api_token}"

        try:
            res = requests.get(
                _CERTSPOTTER_URL,
                params=params,
                timeout=CT_LOG_QUERY_TIMEOUT_SEC,
                proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                headers=headers,
            )
        except requests.exceptions.Timeout:
            self._failure_modes["timeout"] += 1
            log.debug(f"[CTLog/certspotter] Timeout for {domain}")
            return None
        except requests.exceptions.ConnectionError as e:
            self._failure_modes["conn_error"] += 1
            log.debug(f"[CTLog/certspotter] Connection error for {domain}: {e}")
            return None

        if res.status_code == 200:
            try:
                parsed = res.json()
            except Exception as e:
                self._failure_modes["json_error"] += 1
                snippet = (res.text or "")[:80].replace("\n", " ")
                log.warning(
                    f"[CTLog/certspotter] JSON parse error for {domain}: "
                    f"{e} body[:80]={snippet!r}"
                )
                return None
            return parsed if isinstance(parsed, list) else []

        if res.status_code == 429:
            self._failure_modes["http_4xx"] += 1
            retry_after = res.headers.get("Retry-After", "")
            try:
                retry_sec = min(3600, int(float(retry_after))) if retry_after else 600
            except ValueError:
                retry_sec = 600
            self._rate_limited_until_ts = time.time() + retry_sec
            self._last_retry_after_sec = retry_sec
            log.warning(
                f"[CTLog/certspotter] Upstream 429 for {domain}; "
                f"backing off for {retry_sec}s"
            )
            return None

        if res.status_code == 403:
            # Certspotter returns 403 for some regional / restricted
            # domains (observed: gov.ua). Track as its own bucket so the
            # operator can tell "broken" from "blocked" in the panel.
            self._failure_modes["http_403"] += 1
            log.debug(f"[CTLog/certspotter] HTTP 403 for {domain} (region/policy block)")
            return None

        if 400 <= res.status_code < 500:
            self._failure_modes["http_4xx"] += 1
            log.debug(f"[CTLog/certspotter] HTTP {res.status_code} for {domain}")
            return None

        if 500 <= res.status_code < 600:
            self._failure_modes["http_5xx"] += 1
            log.debug(
                f"[CTLog/certspotter] HTTP {res.status_code} for {domain}"
            )
            return None

        return None
