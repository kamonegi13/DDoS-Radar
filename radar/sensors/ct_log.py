"""radar.sensors.ct_log -- Certificate Transparency Log sensor (orchestrator).

ADR-024 redesign + multi-source pipeline (Phase 1 of the resilient-CT plan).

The legacy implementation queried crt.sh directly inside fetch() and folded
transport, buffer, and scoring into a single body. After crt.sh's chronic
upstream instability made it the de-facto single point of failure for this
whole sensor, the design was split:

  * Sources (radar.sensors.ct_log_sources.*) own transport. Pull sources
    answer fetch_domain() synchronously; push sources own background
    workers (Phase 2 will introduce CertstreamSource via WebSocket). All
    sources write into a shared ObservationBuffer keyed on
    (domain, serial, issuer_norm, day) for cross-source idempotency.
  * This orchestrator drives backfill via pull sources, drains the buffer,
    and runs the unchanged ADR-024 anomaly logic — untrusted CA per
    watched gov domain + wildcard-TLD detection — against the drained
    observations. The DB-backed dedup table (ct_log_known_ca_per_domain)
    continues to prevent re-firing across cycles.

Phase 1 ships only CrtshSource; the orchestrator pattern is in place so
Phase 2 can drop in CertstreamSource without touching the scoring layer.
The buffer-and-drain split is also what lets a push source feed
observations between fetch() cycles.

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
from datetime import datetime, timezone

from radar.sensors.base import BaseSensor
from radar.config import (
    CT_LOG_WATCHED_DOMAINS,
    CT_LOG_TRUSTED_CAS_GLOBAL,
    CT_LOG_WARMUP_DAYS,
    CT_LOG_OBSERVATION_WINDOW_HOURS,
    CT_LOG_MAX_QUERIES_PER_COUNTRY,
    CT_LOG_INTER_QUERY_SLEEP_SEC,
    CT_LOG_BUFFER_MAX_OBS,
    CT_LOG_DEGRADED_INTERVAL_SEC,
    CERTSPOTTER_API_TOKEN,
    CT_LOG_CERTSPOTTER_RATE_LIMIT_CALLS,
    CT_LOG_CERTSPOTTER_RATE_LIMIT_WINDOW_SEC,
    CT_LOG_CERTSTREAM_ENABLED,
    CT_LOG_CERTSTREAM_URL,
    CT_LOG_CERTSTREAM_LIVENESS_SEC,
    CT_LOG_CERTSTREAM_PING_INTERVAL,
    CT_LOG_CERTSTREAM_PING_TIMEOUT,
    CT_LOG_CERTSTREAM_HEARTBEAT_BUDGET_SEC,
    CT_LOG_CERTSTREAM_RECONNECT_MAX_SEC,
)
from radar.sensors.ct_log_sources import (
    CertObservation,
    BaseCtLogPullSource,
    BaseCtLogPushSource,
    ObservationBuffer,
)
from radar.sensors.ct_log_sources.certspotter import CertspotterSource
from radar.sensors.ct_log_sources.crtsh import CrtshSource
# CertstreamSource is imported lazily below — see _maybe_start_certstream() — so
# test suites that don't touch certstream don't pull in websocket-client.
from radar import database as _db_mod

log = logging.getLogger("radar")


# Wildcards exactly at this level cover an entire ministry namespace and
# are a classic MITM-prep indicator. Compared against the form left after
# stripping leading "*." from a cert subject. *.gov.tw → "gov.tw".
_GOV_TLD_WILDCARD_TARGETS: frozenset[str] = frozenset({
    "gov", "mil",
    "gov.tw", "gov.uk", "go.jp", "gov.ru", "gov.cn", "gov.kr", "gov.il",
    "gov.ua", "gov.in", "gov.au", "gov.ph", "gov.pk", "gov.by", "gov.ge",
    "gov.vn", "gov.ir", "gov.lv", "gov.pl", "gov.ro", "gov.se",
})


def _is_globally_trusted(issuer_full: str) -> bool:
    """Substring match against CT_LOG_TRUSTED_CAS_GLOBAL (case-insensitive)."""
    if not issuer_full:
        return False
    haystack = issuer_full.lower()
    return any(needle in haystack for needle in CT_LOG_TRUSTED_CAS_GLOBAL)


def _ts_to_iso(ts: float) -> str:
    """Convert UNIX ts → ISO 8601 string for backward-compat dict shape.

    Legacy event dicts carried the raw crt.sh `not_before` string verbatim;
    consumers (UI, Slack alerts) treat it as opaque display text. Sources
    parse to a unix ts at the boundary, so we re-render here for output.
    """
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (ValueError, OSError):
        return ""


class CtLogSensor(BaseSensor):
    """Certificate Transparency anomaly sensor (cyber domain).

    Acts as an orchestrator over a list of CtLogSource instances and a
    shared ObservationBuffer. fetch() drives pull-source backfill, drains
    the buffer, and runs the ADR-024 trust-class evaluation against the
    drained observations.
    """

    # Self-healing knobs — preserved from the prior implementation. The
    # underlying problem (crt.sh chronic instability) hasn't gone away in
    # Phase 1; once Phase 2's certstream push source lands the orchestrator
    # will rarely flip into degraded mode because a single live source is
    # enough to keep aggregate health green.
    _UPSTREAM_FAIL_THRESHOLD = 3
    _NORMAL_INTERVAL = 3600
    # Per-source park policy: a pull source that returns None on
    # PARK_AFTER_FAILURES consecutive cycles AND has at least one healthy
    # peer is parked via mark_dead(PARK_COOLDOWN_SEC). The cooldown floor
    # is 30 minutes — long enough to let upstream recovery happen, short
    # enough that a transient outage doesn't sideline the source for the
    # rest of the day. The "healthy peer" gate is critical: if all sources
    # are failing the orchestrator's own degraded mode handles it; parking
    # the last live source would silence the sensor entirely.
    _PARK_AFTER_FAILURES = 5
    _PARK_COOLDOWN_SEC = 1800

    def __init__(self):
        super().__init__("ct_log", "cyber", self._NORMAL_INTERVAL)
        # Round-robin cursor per theater so we cover all watched domains
        # over multiple cycles when a theater has more domains than the
        # per-cycle budget allows.
        self._query_cursor: dict[str, int] = {}

        # Multi-source pipeline. Phase 2 promotes CertspotterSource to
        # primary after the root-cause investigation showed crt.sh's
        # chronic instability — 7-30s response times against the prior
        # 10s timeout, plus 404s on apex-only ?Identity= queries — was
        # the underlying driver of the chronic-silence symptom that
        # started this rework. Certspotter's `include_subdomains=true`
        # query collapses what previously needed N round-robin
        # subdomain queries per theater into one fast call. CrtshSource
        # stays as fallback for the cases certspotter rejects (some
        # ccTLD gov domains 403 from certspotter — see Phase 2D audit).
        self._buffer = ObservationBuffer(
            max_obs=CT_LOG_BUFFER_MAX_OBS,
            window_hours=CT_LOG_OBSERVATION_WINDOW_HOURS,
        )
        self._pull_sources: list[BaseCtLogPullSource] = [
            CertspotterSource(
                api_token=CERTSPOTTER_API_TOKEN,
                rate_limit_calls=CT_LOG_CERTSPOTTER_RATE_LIMIT_CALLS,
                rate_limit_window_sec=CT_LOG_CERTSPOTTER_RATE_LIMIT_WINDOW_SEC,
            ),
            CrtshSource(),
        ]
        self._push_sources: list[BaseCtLogPushSource] = []
        self._maybe_start_certstream()

        # Aggregate self-healing — driven by "any source delivered any
        # response (data or 200-empty) this cycle", not per-source health.
        # A single live source keeps the sensor in healthy mode.
        self._consecutive_failures: int = 0
        self._upstream_status: str = "unknown"
        self._last_success_ts: float = 0.0

        # Cycle anomaly counters (DB still keeps long-term truth; these
        # are diagnostics for the operator panel since process start).
        self._anomaly_counts: dict[str, int] = {
            "untrusted_ca": 0,
            "wildcard_tld": 0,
            "warmup_recorded": 0,
        }

    # ── Push-source bootstrap & shutdown ──────────────────────────────────
    def _maybe_start_certstream(self) -> None:
        """Conditionally instantiate and start CertstreamSource.

        Skipped silently when:
          * CT_LOG_CERTSTREAM_ENABLED is false (operator opt-out)
          * the watched-domain map is empty (nothing to filter for)
          * websocket-client is not installed (logged once by the source)

        Lazy import keeps test runs that don't touch certstream from
        having to install websocket-client.
        """
        if not CT_LOG_CERTSTREAM_ENABLED:
            log.info(
                "[CTLog] certstream push source disabled by config "
                "(Calidog upstream broken since 2026-04-23: 60s server-close, "
                "no messages). Pull sources (certspotter + crt.sh) carry CT "
                "coverage. Set CT_LOG_CERTSTREAM_ENABLED=true to retry."
            )
            return
        all_watched = sorted({
            d for ds in CT_LOG_WATCHED_DOMAINS.values() for d in ds
        })
        if not all_watched:
            log.info("[CTLog] No watched domains; certstream push source not started")
            return
        try:
            from radar.sensors.ct_log_sources import CertstreamSource
        except Exception as e:
            log.warning(f"[CTLog] CertstreamSource import failed: {e}")
            return
        try:
            cs = CertstreamSource(
                buffer=self._buffer,
                watched_domains=all_watched,
                ws_url=CT_LOG_CERTSTREAM_URL,
                ping_interval=CT_LOG_CERTSTREAM_PING_INTERVAL,
                ping_timeout=CT_LOG_CERTSTREAM_PING_TIMEOUT,
                reconnect_max_sec=CT_LOG_CERTSTREAM_RECONNECT_MAX_SEC,
                liveness_sec=CT_LOG_CERTSTREAM_LIVENESS_SEC,
                heartbeat_budget_sec=CT_LOG_CERTSTREAM_HEARTBEAT_BUDGET_SEC,
            )
            cs.start()
            self._push_sources.append(cs)
        except Exception as e:
            log.warning(f"[CTLog] CertstreamSource start failed: {e}")

    def shutdown(self) -> None:
        """Stop all push sources cleanly. Called via atexit/SIGTERM hook in
        radar/__init__.py. Idempotent — re-entry on already-stopped sources
        is a no-op inside each source's stop().
        """
        for src in self._push_sources:
            try:
                src.stop()
            except Exception as e:
                log.warning(f"[CTLog] push source {src.name} stop failed: {e}")

    # ── Per-domain inspection ─────────────────────────────────────────────
    def _inspect_domain(
        self,
        domain: str,
        country_code: str,
        observations: list[CertObservation],
        now: float,
        db,
    ) -> dict:
        """Inspect observations for one watched domain. Returns per-domain
        summary and possibly emits untrusted-CA / wildcard-TLD events.

        Trust decision tree (unchanged from ADR-024):
          1. Skip observation if not_before is older than the window
             (defence-in-depth; the buffer already filters by window).
          2. Always-record-and-pass: cert from a globally-trusted CA.
          3. Always-record-and-pass: cert from a CA already in this
             domain's known-CA history.
          4. Warm-up window: if domain's first_observed marker is less
             than CT_LOG_WARMUP_DAYS ago, record the CA into history but
             suppress the event (no baseline yet).
          5. Anomaly: cert from a CA neither globally-trusted nor in
             per-domain history nor in warm-up. Fire UNTRUSTED_CA_DETECTED.

        Wildcard-TLD detection is orthogonal: any cert whose CN/SAN
        contains a wildcard at the country TLD level (e.g. `*.gov.tw`)
        is flagged regardless of trust class.
        """
        first_obs = db.ct_log_first_observed(domain)
        if first_obs is None:
            db.ct_log_set_first_observed(domain, now)
            first_obs = now
        in_warmup = (now - first_obs) < (CT_LOG_WARMUP_DAYS * 86400)
        warmup_remaining_days = max(0.0,
            CT_LOG_WARMUP_DAYS - ((now - first_obs) / 86400.0))

        known_cas = db.ct_log_known_cas(domain)
        observation_cutoff_ts = now - (CT_LOG_OBSERVATION_WINDOW_HOURS * 3600)

        total_recent = 0
        wildcard_count = 0
        untrusted_events: list[dict] = []
        wildcard_tld_events: list[dict] = []
        recent_certs: list[dict] = []
        observed_cas_this_cycle: set[str] = set()

        for obs in observations[:200]:
            if obs.not_before_ts < observation_cutoff_ts:
                continue

            total_recent += 1
            ca_norm = obs.issuer_norm
            ca_raw = obs.issuer_raw
            observed_cas_this_cycle.add(ca_norm)

            # Wildcard-TLD detection — fire only when the wildcard is
            # exactly at a recognised gov-TLD level (e.g. "*.gov.tw").
            # Wildcards at sub-namespaces (*.api.mofa.gov.tw) are normal
            # enterprise practice and intentionally not flagged.
            candidate_names = [obs.common_name] + list(obs.subject_alt_names)
            for raw_name in candidate_names:
                n = (raw_name or "").strip().lower()
                if not n.startswith("*."):
                    continue
                stripped = n[2:]
                if stripped in _GOV_TLD_WILDCARD_TARGETS:
                    wildcard_count += 1
                    wildcard_tld_events.append({
                        "domain": domain,
                        "wildcard_subject": n,
                        "issuer": ca_raw[:120],
                        "not_before": _ts_to_iso(obs.not_before_ts),
                    })

            is_trusted = _is_globally_trusted(ca_raw)
            is_known_per_domain = ca_norm in known_cas

            if is_trusted or is_known_per_domain:
                db.ct_log_record_ca(domain, ca_norm, ca_raw, now)
                continue

            if in_warmup:
                db.ct_log_record_ca(domain, ca_norm, ca_raw, now)
                self._anomaly_counts["warmup_recorded"] += 1
                continue

            # Anomaly: untrusted CA on an out-of-warmup watched domain.
            untrusted_events.append({
                "domain": domain,
                "country": country_code,
                "ca_normalized": ca_norm,
                "ca_raw": ca_raw[:120],
                "common_name": obs.common_name[:120],
                "not_before": _ts_to_iso(obs.not_before_ts),
                "first_observed_age_days": round((now - first_obs) / 86400.0, 1),
            })
            self._anomaly_counts["untrusted_ca"] += 1
            # Record so subsequent drains within the window don't re-fire
            # on the same observation. The first detection is the signal.
            db.ct_log_record_ca(domain, ca_norm, ca_raw, now)
            known_cas.add(ca_norm)

            if len(recent_certs) < 5:
                recent_certs.append({
                    "name": obs.common_name[:100],
                    "issuer": ca_raw[:100],
                    "not_before": _ts_to_iso(obs.not_before_ts),
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
    def _select_domains_for_country(self, code: str) -> list[str]:
        """Return up to CT_LOG_MAX_QUERIES_PER_THEATER domains for this poll,
        rotating through the full watched-domain list across cycles.
        """
        all_domains = CT_LOG_WATCHED_DOMAINS.get(code, [])
        if not all_domains:
            return []
        budget = max(1, CT_LOG_MAX_QUERIES_PER_COUNTRY)
        if len(all_domains) <= budget:
            return list(all_domains)
        cursor = self._query_cursor.get(code, 0) % len(all_domains)
        if cursor + budget <= len(all_domains):
            chunk = all_domains[cursor:cursor + budget]
        else:
            chunk = all_domains[cursor:] + all_domains[:budget - (len(all_domains) - cursor)]
        self._query_cursor[code] = (cursor + budget) % len(all_domains)
        return chunk

    # ── Main fetch loop ───────────────────────────────────────────────────
    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_countries", []) or []
        adversaries = context.get("adversary_states", []) or []
        all_targets = sorted(set(theaters + adversaries))
        # Restrict to theaters that actually have a curated watched-domain
        # set; without it we have nothing meaningful to query.
        all_targets = [c for c in all_targets if CT_LOG_WATCHED_DOMAINS.get(c)]
        if not all_targets:
            log.debug("[CTLog] No theaters with watched domains in this cycle")
            self.log_fetch(True, int((time.time() - t0) * 1000), 0, 0, "")
            return self.get_cache() or {"ct_data": {}, "country_status": {}}

        db = _db_mod.db
        now = time.time()

        # ── Phase A: backfill via pull sources ────────────────────────────
        # For each theater, select domains (round-robin), then ask each
        # pull source for that domain's observations. Sources own their
        # own circuit breaker / rate-limit state and return None when
        # they're suppressing themselves. Push sources (Phase 2) feed the
        # buffer asynchronously between cycles.
        polled_domains_by_country: dict[str, list[str]] = {}
        any_real_response = False
        any_pull_attempt = False

        for code in all_targets:
            domains = self._select_domains_for_country(code)
            # In degraded mode probe just a single domain per theater to
            # detect upstream recovery without hammering crt.sh.
            if self._upstream_status == "degraded":
                domains = domains[:1]
            polled_domains_by_country[code] = list(domains)

            for domain in domains:
                alive = False
                got_data = False
                # Fallback semantics: pull sources are tried in priority
                # order; subsequent sources fire only when the prior one
                # returns None (hard failure / CB-open / rate-limited).
                # A 200-empty from the primary is a successful response
                # and stops the fallback chain — the buffer's idempotency
                # key already collapses cross-source duplicates, but
                # avoiding the redundant call saves budget on the
                # rate-limited free-tier sources (certspotter at 25 req/hr
                # local, 30 req/hr upstream).
                for source in self._pull_sources:
                    any_pull_attempt = True
                    obs_list = source.fetch_domain(domain)
                    if obs_list is None:
                        # Source skipped (CB open / rate-limited) or hard
                        # failure. Already counted in source's failure_modes.
                        # Keep walking the chain.
                        continue
                    alive = True
                    if obs_list:
                        got_data = True
                        for obs in obs_list:
                            self._buffer.record(obs)
                    # Stop on first source that responded — even an empty
                    # 200 is authoritative ("upstream confirms no recent
                    # certs for this domain"). Fallback is for transport
                    # failures only.
                    break

                if alive:
                    any_real_response = True
                    if db.ct_log_first_observed(domain) is None:
                        # Any 200 response (data or empty) confirms upstream
                        # knows about this watched domain — arm the warm-up
                        # marker on first contact. We previously gated this
                        # on `not got_data` so the in-window observation
                        # path could record the marker via _inspect_domain,
                        # but Phase 2 surfaced a corner case: certspotter's
                        # first call to a domain returns at most one
                        # historical issuance, which is then filtered out
                        # by the 24h observation window at drain time. The
                        # marker never armed, the domain never warmed up,
                        # and the watched-list never converged. Arming on
                        # any alive response handles both 200-empty and
                        # 200+old-cert uniformly. _inspect_domain still
                        # arms it for the 200+in-window-cert path on first
                        # contact, which is idempotent.
                        db.ct_log_set_first_observed(domain, now)
                # Mild pacing between domains — keeps the orchestrator
                # polite to whichever source ended up answering. Applied
                # outside the source loop so unused fallback budget isn't
                # eaten by sleep cycles.
                time.sleep(CT_LOG_INTER_QUERY_SLEEP_SEC)

        # Push sources may have written into the buffer asynchronously;
        # they contribute to "real response" via buffer source-freshness.
        push_freshness = self._buffer.source_freshness()
        for src in self._push_sources:
            ts = push_freshness.get(src.name, 0.0)
            # Honour the push source's own data-level liveness budget so
            # "ws connected but silent" eventually flips the orchestrator
            # off "any_real_response". A push source matched a watched
            # domain inside the last liveness window → counts as alive.
            if ts and (now - ts) < CT_LOG_CERTSTREAM_LIVENESS_SEC:
                any_real_response = True

        # ── Phase B: drain the shared buffer ──────────────────────────────
        drained = self._buffer.drain_for_scoring(now=now)

        # ── Phase C: score per theater ────────────────────────────────────
        ct_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        error_countries: list[str] = []

        for code in all_targets:
            try:
                domains = polled_domains_by_country[code]
                aggregate_total = 0
                aggregate_wildcard = 0
                aggregate_untrusted: list[dict] = []
                aggregate_wildcard_events: list[dict] = []
                aggregate_recent_certs: list[dict] = []
                observed_domains: list[dict] = []
                warmup_any = False

                for domain in domains:
                    obs_list = drained.get(domain.lower(), [])
                    if not obs_list:
                        # No observations in window — record a placeholder
                        # so the operator panel can see we polled it.
                        observed_domains.append({
                            "domain": domain,
                            "total_recent": 0,
                            "warmup_active": True,
                            "known_ca_count": 0,
                        })
                        continue
                    summary = self._inspect_domain(domain, code, obs_list, now, db)
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

                untrusted_top = aggregate_untrusted[:10]
                wildcard_top = aggregate_wildcard_events[:5]
                recent_top = aggregate_recent_certs[:5]
                untrusted_count = len(untrusted_top)
                is_surge = (untrusted_count > 0) or (aggregate_wildcard > 0)

                if untrusted_count > 0:
                    status = "UNTRUSTED_CA_DETECTED"
                elif aggregate_wildcard > 0:
                    status = "WILDCARD_TLD_DETECTED"
                elif warmup_any and aggregate_total == 0:
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
        # Compose the fetch_log error field so /api/admin/sensor_fetch_log
        # tells an operator at a glance whether silence is from per-country
        # scoring exceptions, source-level degradation (CB-open / rate-
        # limited / persistent failure mode), or both. Without the source
        # tag, a quiet cycle looked indistinguishable from a healthy cycle
        # whose theaters happened to have no fresh certs.
        src_summary = self._summarize_source_state()
        err_parts: list[str] = []
        if error_countries:
            err_parts.append(f"errors({','.join(error_countries)})")
        if src_summary:
            err_parts.append(f"src({src_summary})")
        combined_error = "; ".join(err_parts)
        self.log_fetch(any_real_response, duration, 0,
                       sum(d.get("total_recent", 0) for d in ct_data.values()),
                       combined_error)

        # Self-healing — degraded mode triggers on N consecutive zero-
        # response cycles, recovers immediately on first response.
        if any_real_response:
            if self._consecutive_failures or self._upstream_status != "healthy":
                log.info(
                    f"[CTLog] Upstream recovered after "
                    f"{self._consecutive_failures} failed cycles"
                )
            self._consecutive_failures = 0
            self._upstream_status = "healthy"
            self._last_success_ts = time.time()
            self.poll_interval = self._NORMAL_INTERVAL
        elif any_pull_attempt:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._UPSTREAM_FAIL_THRESHOLD \
                    and self._upstream_status != "degraded":
                self._upstream_status = "degraded"
                self.poll_interval = CT_LOG_DEGRADED_INTERVAL_SEC
                log.warning(
                    f"[CTLog] All sources appear down "
                    f"({self._consecutive_failures} consecutive fail cycles) — "
                    f"degraded mode, probing every {CT_LOG_DEGRADED_INTERVAL_SEC // 60}min"
                )

        # Per-source park policy. Run AFTER the aggregate self-heal so the
        # decision sees the latest health snapshots; only act on pull sources
        # since push sources don't need orchestrator-driven CB parking
        # (their reconnect loop handles transient ws drops on its own).
        self._park_chronically_failing_sources()

        result = {"ct_data": ct_data, "country_status": country_status}
        if any_real_response:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "ct_data": {},
            "country_status": {c: "NORMAL" for c in all_targets},
        }

    def _park_chronically_failing_sources(self) -> None:
        """Park pull sources that have failed _PARK_AFTER_FAILURES cycles
        in a row, but only when at least one peer pull source is healthy.

        Without this, a chronically-broken source (e.g. crt.sh during one
        of its multi-hour outages) gets re-tried every cycle, wastes the
        per-cycle budget, and pollutes the operator panel with the same
        timeout flood. With this, the orchestrator parks it for 30 min
        and the healthy peer absorbs the load. After cooldown the parked
        source is re-tried — if upstream is still broken its CB re-opens
        within seconds; if recovered, it slots back in.
        """
        snapshots = []
        for src in self._pull_sources:
            try:
                snapshots.append((src, src.health()))
            except Exception:
                continue
        any_healthy = any(
            h.get("status") == "healthy" for _, h in snapshots
        )
        if not any_healthy:
            return  # don't park the last live source — let degraded mode handle it
        for src, h in snapshots:
            if h.get("status") == "dead":
                continue  # already parked
            cf = h.get("consecutive_failures", 0)
            if cf < self._PARK_AFTER_FAILURES:
                continue
            if not hasattr(src, "mark_dead"):
                continue
            try:
                src.mark_dead(self._PARK_COOLDOWN_SEC)
                log.warning(
                    f"[CTLog] Parking {src.name} for "
                    f"{self._PARK_COOLDOWN_SEC // 60}min after "
                    f"{cf} consecutive failures (healthy peer present)"
                )
            except Exception as e:
                log.warning(f"[CTLog] mark_dead({src.name}) raised: {e}")

    def _summarize_source_state(self) -> str:
        """Compact one-line summary of per-source degradation, for the
        sensor_fetch_log.error field.

        Only sources actively blocking work are mentioned: CB-open, rate-
        limited, or status=="dead". A healthy/unknown source with zero
        failure-mode counts is silent so the field stays empty on normal
        cycles. The companion structured view lives in upstream_health()
        / /api/admin/sensor_health for the full per-source dict.
        """
        parts: list[str] = []
        for src in self._pull_sources:
            try:
                h = src.health()
            except Exception as e:
                parts.append(f"{src.name}=health_err:{type(e).__name__}")
                continue
            ss = h.get("source_specific", {})
            flags: list[str] = []
            if ss.get("cb_open"):
                r = ss.get("cb_open_remaining_sec", 0)
                flags.append(f"cb_open({int(r)}s)")
            if ss.get("rate_limited"):
                r = ss.get("rate_limited_remaining_sec", 0)
                flags.append(f"rate_limited({int(r)}s)")
            status = h.get("status", "unknown")
            if status == "dead":
                cf = h.get("consecutive_failures", 0)
                top_modes = sorted(
                    ((k, v) for k, v in h.get("mode_counters", {}).items()
                     if v),
                    key=lambda kv: -kv[1],
                )[:2]
                tag = f"dead:cf={cf}"
                if top_modes:
                    tag += "(" + ",".join(
                        f"{k}={v}" for k, v in top_modes) + ")"
                flags.append(tag)
            if flags:
                parts.append(f"{src.name}=" + "+".join(flags))
        return ";".join(parts)

    def upstream_health(self) -> dict:
        """Return upstream health for the /api/admin/sensor_health endpoint.

        Aggregates per-source health under `sources`, plus orchestrator-
        level state (current interval, consecutive failures), buffer
        statistics, and the watched-domain coverage report — observed_24h /
        72h plus the 10 stalest watched apexes — so the operator can
        answer "are we actually getting cert observations for the things
        we care about?" at a glance.
        """
        per_source = {}
        for src in self._pull_sources + self._push_sources:
            try:
                per_source[src.name] = src.health()
            except Exception as e:
                per_source[src.name] = {"status": "error", "error": str(e)}
        all_watched = sorted({
            d for ds in CT_LOG_WATCHED_DOMAINS.values() for d in ds
        })
        return {
            "status": self._upstream_status,
            "consecutive_failures": self._consecutive_failures,
            "last_success_ts": self._last_success_ts,
            "current_interval_sec": self.poll_interval,
            "scoring_model": "adr_024_signal_redesign",
            "warmup_days": CT_LOG_WARMUP_DAYS,
            "observation_window_hours": CT_LOG_OBSERVATION_WINDOW_HOURS,
            "queries_per_country_per_cycle": CT_LOG_MAX_QUERIES_PER_COUNTRY,
            "inter_query_sleep_sec": CT_LOG_INTER_QUERY_SLEEP_SEC,
            "buffer": self._buffer.stats(),
            "source_freshness": self._buffer.source_freshness(),
            "sources": per_source,
            "anomaly_counts": dict(self._anomaly_counts),
            "coverage": self._buffer.coverage_report(all_watched),
        }
