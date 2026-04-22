"""radar.sensors.ct_log -- Certificate Transparency Log sensor.

Monitors Certificate Transparency (CT) logs via crt.sh for anomalous
certificate issuance patterns in strategic theaters. A surge in
wildcard certificates, government domain certificates, or certificates
from unusual CAs for a country's TLD may indicate:

  - Infrastructure preparation for man-in-the-middle attacks
  - DNS hijacking with fraudulent certificate issuance
  - Preemptive legitimate certificate renewal before anticipated disruption

API: https://crt.sh/ (public PostgreSQL interface via REST)
No API key required.

ADR-024: Multi-source fallback investigation (concluded REST-only).
  - crt.sh PostgreSQL (crt.sh:5432, user=guest): reachable but the canonical
    domain-pattern queries (`name_value ILIKE '%.gov.xx'` over 24h window)
    consistently exceed 30s server-side statement_timeout because the FTS
    GIN index on identities() is too coarse for our query shape. Not viable.
  - SSLMate certspotter: blocks free-plan lookups on regulated TLDs we
    actually need (gov.tw, gov.ph, mil.kr, go.jp, US `gov`/`mil`); only
    eTLD+1 subdomains are queryable. Not viable as a TLD-pattern fallback.
  - Direct CT log clients (Cloudflare/Google/Let's Encrypt RFC 6962): not
    domain-searchable; require entry-index iteration. Out of scope.
  Decision: harden the REST path (longer timeout, log non-200 statuses,
  one transient retry) and accept that crt.sh outages cause the sensor
  to legitimately degrade — the "no data" state is an honest signal that
  upstream is down, not a silent bug.
"""
from __future__ import annotations
import logging
import time
from datetime import datetime, timezone, timedelta
import requests
from radar.sensors.base import BaseSensor
import os as _os
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
    CT_LOG_GOV_TLDS,
)

log = logging.getLogger("radar")

_CRTSH_URL = "https://crt.sh/"

# Country code to TLD mapping (most countries use .cc TLD)
# KP (.kp) is excluded: North Korea has virtually no certificates on crt.sh,
# causing a full timeout (30s) on every fetch cycle with no useful signal.
_CC_TLDS = {
    "TW": ".tw", "JP": ".jp", "KR": ".kr", "CN": ".cn",
    "RU": ".ru", "UA": ".ua", "IR": ".ir",
    "IL": ".il", "US": ".us", "GB": ".uk", "DE": ".de",
    "FR": ".fr", "PH": ".ph", "VN": ".vn", "IN": ".in",
    "PK": ".pk", "BY": ".by", "GE": ".ge", "PL": ".pl",
    "EE": ".ee", "LV": ".lv", "LT": ".lt", "FI": ".fi",
    "SE": ".se", "NO": ".no", "RO": ".ro",
}


class CtLogSensor(BaseSensor):
    """Certificate Transparency log anomaly sensor (cyber domain).

    Redesigned thresholds: uses Z-score relative to per-country rolling
    baseline instead of a fixed absolute threshold (CT_LOG_SURGE_THRESHOLD).
    This reduces false positives from Let's Encrypt automated renewals
    and adapts to each country's normal certificate volume.
    """

    # Minimum history entries before Z-score is valid
    _MIN_HISTORY = 4

    # Upstream self-healing: crt.sh suffers chronic 502/timeout storms.
    # After this many consecutive cycles with zero successful queries we
    # switch to degraded mode (long interval, probe-only requests,
    # DEBUG-level logging).  A single successful fetch clears the flag.
    _UPSTREAM_FAIL_THRESHOLD = 3
    _NORMAL_INTERVAL = 3600          # 1h
    _DEGRADED_INTERVAL = 14400       # 4h (probe cadence while crt.sh is down)
    # crt.sh typically answers in 2-5s when healthy, but during recovery
    # responses arrive 6-10s in. The previous 3s cap was too aggressive
    # and silently killed valid responses on warm-up.
    _REQUEST_TIMEOUT_NORMAL = 8
    _REQUEST_TIMEOUT_DEGRADED = 5    # tighter while degraded — probe only
    # Single in-cycle retry on transient nginx failures (502/503/504).
    # crt.sh's edge often recovers within 1-2s of a bad-gateway response.
    _RETRY_STATUSES = (502, 503, 504)
    _RETRY_DELAY_SEC = 1.5

    def __init__(self):
        super().__init__("ct_log", "cyber", self._NORMAL_INTERVAL)
        self._prev_counts: dict[str, int] = {}
        # Rolling history for Z-score computation: country -> [count, ...]
        self._count_history: dict[str, list[int]] = {}
        # Upstream health tracking (crt.sh).  Exposed for Health API.
        self._consecutive_failures: int = 0
        self._upstream_status: str = "unknown"  # healthy | degraded | unknown
        self._last_success_ts: float = 0.0
        # Per-failure-mode observability so operators can distinguish
        # "crt.sh is timing out" from "crt.sh returned a 502" from
        # "crt.sh returned an empty list" — all three look identical
        # without per-mode counters.
        self._failure_modes: dict[str, int] = {
            "timeout": 0,
            "conn_error": 0,
            "http_5xx": 0,
            "http_4xx": 0,
            "json_error": 0,
            "empty_result": 0,
        }
        self._success_count: int = 0

    def _fetch_one_pattern(
        self, code: str, domain_pattern: str, req_timeout: int, log_level: int,
    ) -> list[dict] | None:
        """Fetch one (country, gov-TLD) pattern from crt.sh with one retry on
        transient nginx 5xx.

        Returns:
          list[dict] — parsed cert array on success (may be empty)
          None      — hard failure (timeout, conn error, 4xx, JSON parse,
                      or 5xx after retry); the caller should not treat the
                      pattern as having delivered data.

        Side effects: increments per-mode failure counters so operators
        can distinguish "crt.sh is timing out" from "crt.sh returned a 502"
        from "crt.sh returned an empty list" — all three look identical
        without per-mode counters and used to be silently lumped together.
        """
        last_status = None
        for attempt in (1, 2):
            try:
                res = requests.get(
                    _CRTSH_URL,
                    params={
                        "q": domain_pattern,
                        "output": "json",
                        "exclude": "expired",
                    },
                    timeout=req_timeout,
                    proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                    headers={"Accept": "application/json"},
                )
            except requests.exceptions.Timeout:
                self._failure_modes["timeout"] += 1
                log.log(log_level, f"[CTLog] Timeout for {code} ({domain_pattern}) attempt={attempt}")
                return None
            except requests.exceptions.ConnectionError as e:
                self._failure_modes["conn_error"] += 1
                log.log(log_level, f"[CTLog] Connection error for {code} ({domain_pattern}): {e}")
                return None

            last_status = res.status_code
            if res.status_code == 200:
                try:
                    parsed = res.json()
                except Exception as e:
                    self._failure_modes["json_error"] += 1
                    # crt.sh sometimes returns an HTML error page with 200 —
                    # log the first 80 bytes so the cause is visible.
                    snippet = (res.text or "")[:80].replace("\n", " ")
                    log.warning(
                        f"[CTLog] JSON parse error for {code} ({domain_pattern}): "
                        f"{e} body[:80]={snippet!r}"
                    )
                    return None
                return parsed if isinstance(parsed, list) else []

            if res.status_code in self._RETRY_STATUSES and attempt == 1:
                # crt.sh's edge often recovers within ~1-2s of a bad-gateway.
                log.log(log_level,
                        f"[CTLog] Transient {res.status_code} for {code} "
                        f"({domain_pattern}); retrying in {self._RETRY_DELAY_SEC}s")
                time.sleep(self._RETRY_DELAY_SEC)
                continue

            if res.status_code == 429:
                self._failure_modes["http_4xx"] += 1
                log.warning(f"[CTLog] Rate limited (429) for {code}, skipping pattern")
                return None
            if 400 <= res.status_code < 500:
                self._failure_modes["http_4xx"] += 1
                log.log(log_level, f"[CTLog] HTTP {res.status_code} for {code} ({domain_pattern})")
                return None
            if 500 <= res.status_code < 600:
                # Either second attempt or an unretried 5xx — give up on this pattern.
                self._failure_modes["http_5xx"] += 1
                log.log(log_level,
                        f"[CTLog] HTTP {res.status_code} for {code} ({domain_pattern}) "
                        f"after {attempt} attempt(s)")
                return None

        # Defensive: shouldn't reach here, but if we do, count it as a 5xx.
        self._failure_modes["http_5xx"] += 1
        log.warning(f"[CTLog] Exhausted retries for {code} ({domain_pattern}) last_status={last_status}")
        return None

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_theaters", [])
        adversaries = context.get("adversary_states", [])
        all_targets = list(set(theaters + adversaries))
        if not all_targets:
            all_targets = list(COUNTRY_COORDS.keys())[:10]

        ct_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        error_countries: list[str] = []

        for code in all_targets:
            tld = _CC_TLDS.get(code)
            if not tld:
                continue

            try:
                # Query crt.sh for government-domain certificates only.
                # Full-TLD wildcard queries (e.g. "%.cn") are too heavy for
                # crt.sh and cause frequent timeouts. Gov-domain queries are
                # targeted and return fast — and are the actual signal we need.
                gov_tlds = CT_LOG_GOV_TLDS.get(code, [f"gov{tld}"])
                total_recent = 0
                gov_count = 0
                wildcard_count = 0
                recent_certs = []

                # During degraded mode we still probe — but only one pattern
                # per country, to detect upstream recovery without hammering.
                patterns = [f"%.{g}" for g in gov_tlds]
                if self._upstream_status == "degraded":
                    patterns = patterns[:1]

                _req_timeout = (self._REQUEST_TIMEOUT_DEGRADED
                                if self._upstream_status == "degraded"
                                else self._REQUEST_TIMEOUT_NORMAL)
                _log_level = (logging.DEBUG
                              if self._upstream_status == "degraded"
                              else logging.WARNING)

                for domain_pattern in patterns:
                    certs = self._fetch_one_pattern(
                        code, domain_pattern, _req_timeout, _log_level
                    )
                    if certs is None:
                        continue
                    if not certs:
                        # 200 but empty list — distinct failure mode from
                        # transport errors; could be "no recent certs" OR
                        # "crt.sh returned [] under load" — count it.
                        self._failure_modes["empty_result"] += 1
                        any_success = True  # endpoint did respond
                        continue

                    any_success = True
                    self._success_count += 1
                    age_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
                    for cert in certs[:100]:
                        name = cert.get("common_name", "") or cert.get("name_value", "")
                        issuer = cert.get("issuer_name", "")
                        not_before = cert.get("not_before", "")
                        is_recent = False
                        if not_before:
                            try:
                                nb = datetime.fromisoformat(
                                    not_before.replace("T", " ").split(".")[0]
                                ).replace(tzinfo=timezone.utc)
                                is_recent = nb >= age_cutoff
                            except (ValueError, TypeError):
                                pass
                        if not is_recent:
                            continue
                        total_recent += 1
                        if name.startswith("*."):
                            wildcard_count += 1
                        for g in gov_tlds:
                            if g in name.lower():
                                gov_count += 1
                                break
                        if len(recent_certs) < 5:
                            recent_certs.append({
                                "name": name[:100],
                                "issuer": issuer[:100],
                                "not_before": not_before,
                            })

                    time.sleep(0.3)  # Mild pacing between patterns within a country

                prev = self._prev_counts.get(code, total_recent)
                surge_pct = ((total_recent - prev) / max(prev, 1)
                             if prev > 0 else 0)

                # Z-score based surge detection (replaces fixed threshold)
                hist = self._count_history.setdefault(code, [])
                z_score = 0.0
                z_valid = len(hist) >= self._MIN_HISTORY
                if z_valid:
                    import math
                    h_mean = sum(hist) / len(hist)
                    h_var = sum((x - h_mean) ** 2 for x in hist) / len(hist)
                    h_std = max(math.sqrt(h_var) if h_var > 0 else 1.0, 1.0)
                    z_score = (total_recent - h_mean) / h_std

                # Update history (keep last 30 observations)
                hist.append(total_recent)
                if len(hist) > 30:
                    self._count_history[code] = hist[-30:]

                # Gov domain cert surge: Z-score ≥ 2.5 on gov certs OR ≥5 gov certs
                # General surge: Z-score ≥ 2.5 on total certs (replaces flat 100 threshold)
                is_gov_surge = gov_count >= 5
                is_z_surge = z_valid and z_score >= 2.5 and total_recent > 10
                is_surge = is_gov_surge or is_z_surge or (
                    not z_valid and (total_recent >= int(_os.getenv("CT_LOG_SURGE_THRESHOLD", "100")) or
                                    (surge_pct > 1.0 and total_recent > 20)))

                ct_data[code] = {
                    "total_recent": total_recent,
                    "gov_count": gov_count,
                    "wildcard_count": wildcard_count,
                    "prev_count": prev,
                    "surge_pct": round(surge_pct, 3),
                    "z_score": round(z_score, 2),
                    "z_valid": z_valid,
                    "is_surge": is_surge,
                    "recent_certs": recent_certs,
                }

                if is_surge and is_gov_surge:
                    country_status[code] = "GOV_CERT_SURGE"
                elif is_surge:
                    country_status[code] = "CERT_SURGE"
                else:
                    country_status[code] = "NORMAL"

                if total_recent > 0:
                    self._prev_counts[code] = total_recent

            except Exception as e:
                error_countries.append(code)
                log.warning(f"[CTLog] Error for {code}: {e}")

        duration = round((time.time() - t0) * 1000)
        combined_error = f"timeout({','.join(error_countries)})" if error_countries else ""
        self.log_fetch(any_success, duration, 0,
                       sum(d["total_recent"] for d in ct_data.values()), combined_error)

        # Self-healing: track upstream crt.sh health.  Adjust fetch cadence
        # to reduce noise while degraded, and restore normal cadence the
        # moment a single query succeeds.
        if any_success:
            if self._consecutive_failures or self._upstream_status != "healthy":
                log.info(f"[CTLog] Upstream crt.sh recovered after {self._consecutive_failures} failed cycles")
            self._consecutive_failures = 0
            self._upstream_status = "healthy"
            self._last_success_ts = time.time()
            self.poll_interval = self._NORMAL_INTERVAL
        else:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._UPSTREAM_FAIL_THRESHOLD \
                    and self._upstream_status != "degraded":
                self._upstream_status = "degraded"
                self.poll_interval = self._DEGRADED_INTERVAL
                log.warning(
                    f"[CTLog] Upstream crt.sh appears down "
                    f"({self._consecutive_failures} consecutive fail cycles) — "
                    f"entering degraded mode, probing every {self._DEGRADED_INTERVAL // 60}min"
                )

        result = {"ct_data": ct_data, "country_status": country_status}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "ct_data": {},
            "country_status": {c: "NORMAL" for c in all_targets},
        }

    def upstream_health(self) -> dict:
        """Return crt.sh upstream health state for Health/Diagnostics APIs.

        ADR-024 telemetry: failure-mode counters distinguish the four ways
        crt.sh "doesn't return data" — timeout, connection error, HTTP 5xx,
        HTTP 4xx, JSON parse error, and empty result. Without these, an
        operator looking at the Health panel sees only "0 successes" and
        cannot tell if crt.sh is down, throttling us, returning HTML
        instead of JSON, or simply has no recent gov certs to report.
        """
        return {
            "status": self._upstream_status,
            "consecutive_failures": self._consecutive_failures,
            "last_success_ts": self._last_success_ts,
            "current_interval_sec": self.poll_interval,
            "success_count": self._success_count,
            "failure_modes": dict(self._failure_modes),
        }
