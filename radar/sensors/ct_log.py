"""radar.sensors.ct_log -- Certificate Transparency Log sensor.

ADR-024 redesign (signal-model rewrite):

The legacy implementation queried crt.sh with `name_value ILIKE '%.gov.xx'`
patterns and scored a "surge in gov certs" as the threat signal. Two problems
collapsed it into a permanent zero-data sensor:

  1. Transport: leading-wildcard ILIKE queries hit a slow PostgreSQL trigram
     code path on crt.sh's backend, exceeding statement_timeout (30s) and
     returning nginx 502 Bad Gateway in ~1.5s on virtually every request.
     Empirically verified: `q=%.gov.tw` returns 502 in 1.5s, while
     `Identity=mofa.gov.tw` returns 200 in ~10s using the btree index path.
  2. Signal model: a "count surge" of gov certs is a poor proxy for the
     actual threat. Let's Encrypt issues thousands of certs daily for any
     active gov TLD — the threat is *who* issued the cert, not *how many*.

This rewrite addresses both:

  * Per-domain identity-match queries against a curated watched-domain set
    (`CT_LOG_WATCHED_DOMAINS` in geo_data.json — head of state, MoFA, MoD,
    parliament, central bank, security agencies). These queries take the
    fast crt.sh code path.
  * Anomaly-based scoring: a cert is anomalous if its issuer is neither in
    the global trusted-CA allowlist nor in the per-domain known-CA history
    table populated over a 14-day warm-up window. This catches the actual
    threat — a state-aligned CA suddenly issuing for a foreign gov domain
    when the historical issuer was always Let's Encrypt or DigiCert.
  * Opportunistic wildcard-TLD detection: while inspecting watched-domain
    certs, flag any cert whose subject contains a wildcard for a country
    TLD (e.g. `*.gov.tw`) — rare and high-signal regardless of issuer.

Backward compatibility: ct_data still carries the legacy fields
(`total_recent`, `gov_count`, `wildcard_count`, `is_surge`, `recent_certs`)
so existing consumers in core.py and climate.py do not crash. The legacy
`gov_count` field is hard-set to 0 (the concept is gone). New fields:
`untrusted_ca_events`, `wildcard_tld_detected`, `warmup_active`,
`watched_domains`, `observed_domains`. Status values added:
`UNTRUSTED_CA_DETECTED` (highest), `WILDCARD_TLD_DETECTED`, `WARMUP`.
"""
from __future__ import annotations
import logging
import time
from datetime import datetime, timezone, timedelta
import requests
from radar.sensors.base import BaseSensor
from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY,
    CT_LOG_WATCHED_DOMAINS,
    CT_LOG_TRUSTED_CAS_GLOBAL,
    CT_LOG_WARMUP_DAYS,
    CT_LOG_OBSERVATION_WINDOW_HOURS,
    CT_LOG_MAX_QUERIES_PER_THEATER,
    CT_LOG_QUERY_TIMEOUT_SEC,
    CT_LOG_INTER_QUERY_SLEEP_SEC,
)
from radar import database as _db_mod

log = logging.getLogger("radar")

_CRTSH_URL = "https://crt.sh/"

# Wildcards exactly at this level cover an entire ministry namespace and
# are a classic MITM-prep indicator. Compared against the form left after
# stripping leading "*." from a cert subject. *.gov.tw → "gov.tw".
_GOV_TLD_WILDCARD_TARGETS: frozenset[str] = frozenset({
    "gov", "mil",
    "gov.tw", "gov.uk", "go.jp", "gov.ru", "gov.cn", "gov.kr", "gov.il",
    "gov.ua", "gov.in", "gov.au", "gov.ph", "gov.pk", "gov.by", "gov.ge",
    "gov.vn", "gov.ir", "gov.lv", "gov.pl", "gov.ro", "gov.se",
})


def _parse_issuer(issuer_name: str) -> tuple[str, str]:
    """Return (normalized_for_dedup, raw_for_display).

    crt.sh issuer_name looks like `C=US, O=Let's Encrypt, CN=R3`. We pull the
    O= (organization) component as the canonical identifier — it's stable
    across cert chains and intermediate rotations within a single CA. Falls
    back to CN= and finally the full string if no O= is present (some
    self-issued or test CAs omit O=).
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


def _is_globally_trusted(issuer_full: str) -> bool:
    """Substring match against CT_LOG_TRUSTED_CAS_GLOBAL (case-insensitive)."""
    if not issuer_full:
        return False
    haystack = issuer_full.lower()
    return any(needle in haystack for needle in CT_LOG_TRUSTED_CAS_GLOBAL)


def _parse_not_before(s: str) -> datetime | None:
    """Parse crt.sh `not_before` field. Returns UTC-aware datetime or None."""
    if not s:
        return None
    try:
        # crt.sh returns "2026-04-22T08:15:33" or with fractional seconds
        clean = s.replace("T", " ").split(".")[0]
        return datetime.fromisoformat(clean).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


class CtLogSensor(BaseSensor):
    """Certificate Transparency anomaly sensor (cyber domain).

    Detects anomalous CA issuance for a curated set of authoritative state
    domains. See module docstring and ADR-024 for the full design rationale.
    """

    # Upstream self-healing knobs — preserved from prior implementation
    # because the underlying problem (crt.sh chronic instability) hasn't
    # gone away; the redesign only changes the *query shape*, not the
    # service's reliability profile.
    _UPSTREAM_FAIL_THRESHOLD = 3
    _NORMAL_INTERVAL = 3600          # 1h
    _DEGRADED_INTERVAL = 14400       # 4h (probe cadence while crt.sh is down)

    _RETRY_STATUSES = (502, 503, 504)
    _RETRY_DELAY_SEC = 1.5

    def __init__(self):
        super().__init__("ct_log", "cyber", self._NORMAL_INTERVAL)
        # Round-robin cursor per theater so we cover all watched domains
        # over multiple cycles when a theater has more domains than the
        # per-cycle budget allows.
        self._query_cursor: dict[str, int] = {}
        # Upstream health tracking — exposed via upstream_health() to the
        # /api/admin/sensor_health endpoint (T1.B).
        self._consecutive_failures: int = 0
        self._upstream_status: str = "unknown"
        self._last_success_ts: float = 0.0
        # Per-failure-mode observability. Without these, "0 successes"
        # could mean four very different upstream pathologies.
        self._failure_modes: dict[str, int] = {
            "timeout": 0,
            "conn_error": 0,
            "http_5xx": 0,
            "http_4xx": 0,
            "json_error": 0,
            "empty_result": 0,
        }
        self._success_count: int = 0
        # Anomaly counters for diagnostics.
        self._anomaly_counts: dict[str, int] = {
            "untrusted_ca": 0,
            "wildcard_tld": 0,
            "warmup_recorded": 0,
        }
        # Per-cycle rate-limit guard. Set when crt.sh returns 429; the active
        # fetch() loop checks this between domains and aborts early to avoid
        # hammering the upstream further. Reset at the top of each fetch().
        self._rate_limited_this_cycle: bool = False
        self._last_retry_after_sec: int = 0

    # ── Identity-match query (fast crt.sh path) ───────────────────────────
    def _fetch_identity(self, domain: str, log_level: int) -> list[dict] | None:
        """Query crt.sh with ?Identity=<domain>&output=json — exact-match path
        that uses the btree index instead of the slow trigram code path.

        Returns:
          list[dict] — parsed cert array on success (may be empty)
          None      — hard failure; caller must not treat domain as having
                      delivered data.
        """
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
                log.log(log_level, f"[CTLog] Timeout for {domain} attempt={attempt}")
                return None
            except requests.exceptions.ConnectionError as e:
                self._failure_modes["conn_error"] += 1
                log.log(log_level, f"[CTLog] Connection error for {domain}: {e}")
                return None

            if res.status_code == 200:
                try:
                    parsed = res.json()
                except Exception as e:
                    self._failure_modes["json_error"] += 1
                    snippet = (res.text or "")[:80].replace("\n", " ")
                    log.warning(
                        f"[CTLog] JSON parse error for {domain}: {e} body[:80]={snippet!r}"
                    )
                    return None
                return parsed if isinstance(parsed, list) else []

            if res.status_code in self._RETRY_STATUSES and attempt == 1:
                log.log(log_level,
                        f"[CTLog] Transient {res.status_code} for {domain}; "
                        f"retrying in {self._RETRY_DELAY_SEC}s")
                time.sleep(self._RETRY_DELAY_SEC)
                continue

            if res.status_code == 429:
                self._failure_modes["http_4xx"] += 1
                # Honor Retry-After if present; otherwise cap at 60s.
                retry_after = res.headers.get("Retry-After", "")
                try:
                    retry_sec = min(60, int(float(retry_after))) if retry_after else 0
                except ValueError:
                    retry_sec = 0
                self._rate_limited_this_cycle = True
                self._last_retry_after_sec = retry_sec
                log.warning(
                    f"[CTLog] Rate limited (429) for {domain}; "
                    f"retry_after={retry_sec}s — aborting remainder of cycle"
                )
                return None
            if 400 <= res.status_code < 500:
                self._failure_modes["http_4xx"] += 1
                log.log(log_level, f"[CTLog] HTTP {res.status_code} for {domain}")
                return None
            if 500 <= res.status_code < 600:
                self._failure_modes["http_5xx"] += 1
                log.log(log_level,
                        f"[CTLog] HTTP {res.status_code} for {domain} after {attempt} attempt(s)")
                return None

        self._failure_modes["http_5xx"] += 1
        return None

    # ── Per-domain inspection ─────────────────────────────────────────────
    def _inspect_domain(
        self,
        domain: str,
        country_code: str,
        certs: list[dict],
        now: float,
        db,
    ) -> dict:
        """Inspect certs for one watched domain. Returns per-domain summary
        and possibly emits untrusted-CA / wildcard-TLD events.

        The trust decision tree, in order:
          1. Skip cert if not_before is older than the observation window
             (we already evaluated old certs in prior cycles).
          2. Always-record-and-pass: cert from globally-trusted CA
             (Let's Encrypt, DigiCert, etc.). Updates known-CA history but
             never fires.
          3. Always-record-and-pass: cert from a CA already in this domain's
             known-CA history. Updates last_seen counter. No fire.
          4. Warm-up window: if the domain's first_observed marker is less
             than CT_LOG_WARMUP_DAYS ago, every CA seen is *recorded* into
             history and the event is suppressed (we have no baseline yet).
          5. Anomaly: cert from a CA neither globally-trusted nor in
             per-domain history nor in warm-up. Fire UNTRUSTED_CA_DETECTED.

        Wildcard-TLD detection is orthogonal: any cert whose subject (CN or
        SAN) contains a wildcard at the country TLD level (e.g. `*.gov.tw`)
        is flagged regardless of trust class. These are rare in legitimate
        ops and uniformly suspicious.
        """
        first_obs = db.ct_log_first_observed(domain)
        if first_obs is None:
            db.ct_log_set_first_observed(domain, now)
            first_obs = now
        in_warmup = (now - first_obs) < (CT_LOG_WARMUP_DAYS * 86400)
        warmup_remaining_days = max(0.0,
            CT_LOG_WARMUP_DAYS - ((now - first_obs) / 86400.0))

        known_cas = db.ct_log_known_cas(domain)
        observation_cutoff = datetime.now(timezone.utc) - timedelta(
            hours=CT_LOG_OBSERVATION_WINDOW_HOURS
        )

        total_recent = 0
        wildcard_count = 0
        untrusted_events: list[dict] = []
        wildcard_tld_events: list[dict] = []
        recent_certs: list[dict] = []
        observed_cas_this_cycle: set[str] = set()

        for cert in certs[:200]:
            name = (cert.get("common_name") or cert.get("name_value") or "").strip()
            issuer = (cert.get("issuer_name") or "").strip()
            not_before = cert.get("not_before") or ""
            nb_dt = _parse_not_before(not_before)
            if nb_dt is None or nb_dt < observation_cutoff:
                continue

            total_recent += 1
            ca_norm, ca_raw = _parse_issuer(issuer)
            observed_cas_this_cycle.add(ca_norm)

            # Wildcard-TLD detection — fire only when the wildcard is
            # exactly at a recognised gov-TLD level (e.g. "*.gov.tw").
            # Wildcards at sub-namespaces (*.api.mofa.gov.tw) are normal
            # enterprise practice and are intentionally not flagged.
            all_names = name.lower().split("\n") if name else []
            for n in all_names:
                n = n.strip()
                if not n.startswith("*."):
                    continue
                stripped = n[2:]
                if stripped in _GOV_TLD_WILDCARD_TARGETS:
                    wildcard_count += 1
                    wildcard_tld_events.append({
                        "domain": domain,
                        "wildcard_subject": n,
                        "issuer": ca_raw[:120],
                        "not_before": not_before,
                    })

            # Trust-class evaluation
            is_trusted = _is_globally_trusted(issuer)
            is_known_per_domain = ca_norm in known_cas

            if is_trusted or is_known_per_domain:
                # Pass — refresh history (idempotent)
                db.ct_log_record_ca(domain, ca_norm, ca_raw, now)
                continue

            if in_warmup:
                # Record the CA but do not fire — no baseline yet.
                db.ct_log_record_ca(domain, ca_norm, ca_raw, now)
                self._anomaly_counts["warmup_recorded"] += 1
                continue

            # Anomaly: untrusted CA on an out-of-warmup watched domain.
            untrusted_events.append({
                "domain": domain,
                "country": country_code,
                "ca_normalized": ca_norm,
                "ca_raw": ca_raw[:120],
                "common_name": name[:120],
                "not_before": not_before,
                "first_observed_age_days": round((now - first_obs) / 86400.0, 1),
            })
            self._anomaly_counts["untrusted_ca"] += 1
            # Record the CA so we don't re-fire on the same issuance every
            # cycle until the cert expires. The first detection is the
            # signal; subsequent identical certs from the same CA are noise.
            db.ct_log_record_ca(domain, ca_norm, ca_raw, now)
            # Mutate the snapshot so the same CA appearing again later in
            # *this* cert batch (multiple certs issued in one window) is
            # treated as known-per-domain on the second hit instead of
            # firing a duplicate event.
            known_cas.add(ca_norm)

            if len(recent_certs) < 5:
                recent_certs.append({
                    "name": name[:100],
                    "issuer": ca_raw[:100],
                    "not_before": not_before,
                })

        if wildcard_tld_events:
            self._anomaly_counts["wildcard_tld"] += len(wildcard_tld_events)

        return {
            "domain": domain,
            "total_recent": total_recent,
            "untrusted_events": untrusted_events,
            "wildcard_events": wildcard_tld_events,
            "wildcard_count": wildcard_count,
            "warmup_active": in_warmup,
            "warmup_remaining_days": round(warmup_remaining_days, 1),
            "known_ca_count": len(known_cas | observed_cas_this_cycle),
            "recent_certs": recent_certs,
        }

    # ── Round-robin domain selection ──────────────────────────────────────
    def _select_domains_for_theater(self, code: str) -> list[str]:
        """Return up to CT_LOG_MAX_QUERIES_PER_THEATER domains for this poll,
        rotating through the full watched-domain list across cycles.
        """
        all_domains = CT_LOG_WATCHED_DOMAINS.get(code, [])
        if not all_domains:
            return []
        budget = max(1, CT_LOG_MAX_QUERIES_PER_THEATER)
        if len(all_domains) <= budget:
            return list(all_domains)
        cursor = self._query_cursor.get(code, 0) % len(all_domains)
        # Wrap-around slice
        if cursor + budget <= len(all_domains):
            chunk = all_domains[cursor:cursor + budget]
        else:
            chunk = all_domains[cursor:] + all_domains[:budget - (len(all_domains) - cursor)]
        self._query_cursor[code] = (cursor + budget) % len(all_domains)
        return chunk

    # ── Main fetch loop ───────────────────────────────────────────────────
    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        # Reset per-cycle rate-limit guard. If crt.sh starts 429ing mid-cycle
        # we abort the remainder rather than burn the rest of our budget on
        # rejected requests.
        self._rate_limited_this_cycle = False
        self._last_retry_after_sec = 0
        theaters = context.get("strategic_theaters", []) or []
        adversaries = context.get("adversary_states", []) or []
        all_targets = sorted(set(theaters + adversaries))
        # Restrict to theaters that actually have a curated watched-domain set;
        # without it we have nothing meaningful to query.
        all_targets = [c for c in all_targets if CT_LOG_WATCHED_DOMAINS.get(c)]
        if not all_targets:
            log.debug("[CTLog] No theaters with watched domains in this cycle")
            self.log_fetch(True, int((time.time() - t0) * 1000), 0, 0, "")
            return self.get_cache() or {"ct_data": {}, "country_status": {}}

        ct_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        any_real_response = False
        error_countries: list[str] = []
        db = _db_mod.db
        now = time.time()

        log_level = (logging.DEBUG
                     if self._upstream_status == "degraded"
                     else logging.WARNING)

        for code in all_targets:
            try:
                domains = self._select_domains_for_theater(code)
                # In degraded mode probe just a single domain per theater to
                # detect upstream recovery without hammering crt.sh.
                if self._upstream_status == "degraded":
                    domains = domains[:1]

                aggregate_total = 0
                aggregate_wildcard = 0
                aggregate_untrusted: list[dict] = []
                aggregate_wildcard_events: list[dict] = []
                aggregate_recent_certs: list[dict] = []
                observed_domains: list[dict] = []
                warmup_any = False

                for domain in domains:
                    if self._rate_limited_this_cycle:
                        # Stop hammering crt.sh as soon as it 429s. The
                        # remaining domains will be picked up by the round-
                        # robin selector on the next cycle.
                        break
                    certs = self._fetch_identity(domain, log_level)
                    if certs is None:
                        # Transport failure — already counted in failure_modes
                        continue
                    any_real_response = True
                    if not certs:
                        # 200 OK with empty list. crt.sh distinguishes "no
                        # data found" from errors at the HTTP level, so this
                        # is genuinely "no recent issuance for this domain".
                        # Still register the warm-up marker the first time.
                        if db.ct_log_first_observed(domain) is None:
                            db.ct_log_set_first_observed(domain, now)
                        self._failure_modes["empty_result"] += 1
                        observed_domains.append({"domain": domain, "total_recent": 0,
                                                 "warmup_active": True, "known_ca_count": 0})
                        continue

                    self._success_count += 1
                    summary = self._inspect_domain(domain, code, certs, now, db)
                    aggregate_total += summary["total_recent"]
                    aggregate_wildcard += summary["wildcard_count"]
                    aggregate_untrusted.extend(summary["untrusted_events"])
                    aggregate_wildcard_events.extend(summary["wildcard_events"])
                    aggregate_recent_certs.extend(summary["recent_certs"])
                    if summary["warmup_active"]:
                        warmup_any = True
                    observed_domains.append({
                        "domain": domain,
                        "total_recent": summary["total_recent"],
                        "warmup_active": summary["warmup_active"],
                        "warmup_remaining_days": summary["warmup_remaining_days"],
                        "known_ca_count": summary["known_ca_count"],
                    })

                    # Mild pacing — crt.sh is happier with serial requests
                    # than with parallel ones from the same client IP.
                    time.sleep(CT_LOG_INTER_QUERY_SLEEP_SEC)

                any_success = any_success or any_real_response

                if self._rate_limited_this_cycle:
                    # Skip remaining theaters too — the rate-limit window
                    # applies to our client IP, not per-domain.
                    break

                # Trim to top events for transport
                untrusted_top = aggregate_untrusted[:10]
                wildcard_top = aggregate_wildcard_events[:5]
                recent_top = aggregate_recent_certs[:5]

                # Backward-compat: legacy consumers read total_recent and
                # is_surge. Keep them populated; redirect is_surge so it now
                # *means* "an anomaly fired", not "count exceeded threshold".
                untrusted_count = len(untrusted_top)
                is_surge = (untrusted_count > 0) or (aggregate_wildcard > 0)

                if untrusted_count > 0:
                    status = "UNTRUSTED_CA_DETECTED"
                elif aggregate_wildcard > 0:
                    status = "WILDCARD_TLD_DETECTED"
                elif warmup_any and aggregate_total == 0 and not observed_domains:
                    status = "WARMUP"
                else:
                    status = "NORMAL"

                ct_data[code] = {
                    # legacy fields preserved for backward-compat
                    "total_recent": aggregate_total,
                    "gov_count": 0,  # legacy concept — gone in redesign
                    "wildcard_count": aggregate_wildcard,
                    "is_surge": is_surge,
                    "recent_certs": recent_top,
                    # new fields
                    "untrusted_ca_count": untrusted_count,
                    "untrusted_ca_events": untrusted_top,
                    "wildcard_tld_detected": aggregate_wildcard > 0,
                    "wildcard_tld_events": wildcard_top,
                    "watched_domains": list(domains),
                    "observed_domains": observed_domains,
                    "warmup_active": warmup_any,
                    "scoring_model": "adr_024_signal_redesign",
                }
                country_status[code] = status

            except Exception as e:
                error_countries.append(code)
                log.warning(f"[CTLog] Error for {code}: {e}")

        duration = round((time.time() - t0) * 1000)
        combined_error = f"errors({','.join(error_countries)})" if error_countries else ""
        self.log_fetch(any_real_response, duration, 0,
                       sum(d.get("total_recent", 0) for d in ct_data.values()),
                       combined_error)

        # Self-healing — degraded mode triggers on N consecutive zero-response
        # cycles, recovers immediately on first response.
        if any_real_response:
            if self._consecutive_failures or self._upstream_status != "healthy":
                log.info(
                    f"[CTLog] Upstream crt.sh recovered after "
                    f"{self._consecutive_failures} failed cycles"
                )
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
                    f"degraded mode, probing every {self._DEGRADED_INTERVAL // 60}min"
                )

        result = {"ct_data": ct_data, "country_status": country_status}
        if any_real_response:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "ct_data": {},
            "country_status": {c: "NORMAL" for c in all_targets},
        }

    def upstream_health(self) -> dict:
        """Return crt.sh upstream health for the /api/admin/sensor_health endpoint.

        Failure-mode counters distinguish the ways crt.sh "doesn't return
        data": timeout, connection error, HTTP 5xx, HTTP 4xx, JSON parse
        error, empty result. Anomaly counts surface what the redesigned
        signal model has actually fired since process start.
        """
        return {
            "status": self._upstream_status,
            "consecutive_failures": self._consecutive_failures,
            "last_success_ts": self._last_success_ts,
            "current_interval_sec": self.poll_interval,
            "success_count": self._success_count,
            "failure_modes": dict(self._failure_modes),
            "anomaly_counts": dict(self._anomaly_counts),
            "scoring_model": "adr_024_signal_redesign",
            "warmup_days": CT_LOG_WARMUP_DAYS,
            "observation_window_hours": CT_LOG_OBSERVATION_WINDOW_HOURS,
            "queries_per_theater_per_cycle": CT_LOG_MAX_QUERIES_PER_THEATER,
            "inter_query_sleep_sec": CT_LOG_INTER_QUERY_SLEEP_SEC,
            "rate_limited_last_cycle": self._rate_limited_this_cycle,
            "last_retry_after_sec": self._last_retry_after_sec,
        }
