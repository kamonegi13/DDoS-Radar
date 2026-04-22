"""radar.sensors.ct_log_sources.crtsh -- crt.sh REST source.

Pull source. Wraps the identity-match query that uses the fast btree
index path (vs. the slow trigram code path that the legacy ILIKE form
hit). Same transport/retry/rate-limit logic that lived in CtLogSensor
prior to the multi-source refactor; verbatim relocation, with one
addition: per-source CB state isolated from the BaseSensor CB so a
dead crt.sh doesn't OPEN the whole sensor's CB if certstream is
delivering observations.
"""
from __future__ import annotations

import logging
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

# Backward-compat alias — tests imported this name when the parser still
# lived in this module. Keeping the symbol stable means the parser move
# is invisible to callers.
_parse_issuer = parse_issuer

log = logging.getLogger("radar")

_CRTSH_URL = "https://crt.sh/"
_RETRY_STATUSES = (502, 503, 504)
_RETRY_DELAY_SEC = 1.5
_FAILURE_MODES_INIT = {
    "timeout": 0,
    "conn_error": 0,
    "http_5xx": 0,
    "http_4xx": 0,
    "json_error": 0,
    "empty_result": 0,
}


class CrtshSource(BaseCtLogPullSource):
    """crt.sh REST per-domain identity-match source."""

    name = "crtsh"

    def __init__(self):
        self._failure_modes: dict[str, int] = dict(_FAILURE_MODES_INIT)
        self._success_count: int = 0
        self._consecutive_failures: int = 0
        self._last_success_ts: float = 0.0
        self._status: str = "unknown"  # unknown | healthy | degraded | dead
        self._rate_limited_until_ts: float = 0.0
        self._last_retry_after_sec: int = 0
        # Per-source CB. Independent from BaseSensor CB so that a dead
        # crt.sh doesn't OPEN the orchestrator-level CB if certstream is
        # delivering. Used by the orchestrator's backfill scheduler to
        # decide whether to skip this source for one cycle.
        self._cb_open_until_ts: float = 0.0

    # ── Public API: pull contract ─────────────────────────────────────
    def fetch_domain(self, domain: str) -> list[CertObservation] | None:
        """Query crt.sh for one watched domain. Returns observations
        (possibly empty) on transport success; None on hard failure.

        The empty list is meaningful: it means "the upstream is alive and
        explicitly told us this domain has no recent unexpired certs."
        That's how the orchestrator advances the warm-up marker for
        domains genuinely untouched in the observation window.
        """
        if self._cb_open_until_ts > time.time():
            return None
        if self._rate_limited_until_ts > time.time():
            # Don't touch crt.sh while we're inside the Retry-After window.
            return None

        certs = self._fetch_identity(domain)
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
            issuer = (cert.get("issuer_name") or "").strip()
            ca_norm, ca_raw = parse_issuer(issuer)
            if ca_norm == "unknown":
                continue
            cn = (cert.get("common_name") or cert.get("name_value") or "").strip()
            sans_str = cert.get("name_value") or ""
            sans = [s for s in sans_str.split("\n") if s] if sans_str else []
            obs = make_observation(
                domain=domain,
                issuer_raw=ca_raw,
                issuer_norm=ca_norm,
                common_name=cn,
                subject_alt_names=sans,
                not_before_iso=cert.get("not_before") or "",
                serial=str(cert.get("serial_number") or ""),
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
        """Orchestrator hook: open this source's CB for `cooldown_sec`.

        Used when the orchestrator decides crt.sh has been failing in a
        pattern that warrants longer suppression than the natural
        request-rate would give us.
        """
        self._cb_open_until_ts = time.time() + max(0.0, cooldown_sec)
        self._status = "dead"

    # ── Internal: HTTP transport ──────────────────────────────────────
    def _fetch_identity(self, domain: str) -> list[dict] | None:
        for attempt in (1, 2):
            try:
                res = requests.get(
                    _CRTSH_URL,
                    params={
                        "Identity": domain,
                        "output": "json",
                        "exclude": "expired",
                    },
                    timeout=CT_LOG_QUERY_TIMEOUT_SEC,
                    proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                    headers={"Accept": "application/json"},
                )
            except requests.exceptions.Timeout:
                self._failure_modes["timeout"] += 1
                log.debug(f"[CTLog/crtsh] Timeout for {domain} attempt={attempt}")
                return None
            except requests.exceptions.ConnectionError as e:
                self._failure_modes["conn_error"] += 1
                log.debug(f"[CTLog/crtsh] Connection error for {domain}: {e}")
                return None

            if res.status_code == 200:
                try:
                    parsed = res.json()
                except Exception as e:
                    self._failure_modes["json_error"] += 1
                    snippet = (res.text or "")[:80].replace("\n", " ")
                    log.warning(
                        f"[CTLog/crtsh] JSON parse error for {domain}: {e} body[:80]={snippet!r}"
                    )
                    return None
                return parsed if isinstance(parsed, list) else []

            if res.status_code in _RETRY_STATUSES and attempt == 1:
                log.debug(
                    f"[CTLog/crtsh] Transient {res.status_code} for {domain}; "
                    f"retrying in {_RETRY_DELAY_SEC}s"
                )
                time.sleep(_RETRY_DELAY_SEC)
                continue

            if res.status_code == 429:
                self._failure_modes["http_4xx"] += 1
                retry_after = res.headers.get("Retry-After", "")
                try:
                    retry_sec = min(60, int(float(retry_after))) if retry_after else 30
                except ValueError:
                    retry_sec = 30
                self._rate_limited_until_ts = time.time() + retry_sec
                self._last_retry_after_sec = retry_sec
                log.warning(
                    f"[CTLog/crtsh] Rate limited (429) for {domain}; "
                    f"backing off for {retry_sec}s"
                )
                return None
            if 400 <= res.status_code < 500:
                self._failure_modes["http_4xx"] += 1
                log.debug(f"[CTLog/crtsh] HTTP {res.status_code} for {domain}")
                return None
            if 500 <= res.status_code < 600:
                self._failure_modes["http_5xx"] += 1
                log.debug(
                    f"[CTLog/crtsh] HTTP {res.status_code} for {domain} "
                    f"after {attempt} attempt(s)"
                )
                return None

        self._failure_modes["http_5xx"] += 1
        return None
