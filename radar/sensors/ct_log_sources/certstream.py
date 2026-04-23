"""radar.sensors.ct_log_sources.certstream -- Calidog certstream push source.

Push source. Subscribes to Calidog's free public ws (certstream.calidog.io)
and writes a CertObservation to the shared buffer for every cert whose
SAN/CN matches a watched apex domain (or a subdomain thereof).

Why now (Phase 2 second-half): the Phase 2 root-cause work promoted
certspotter from "untried" to "primary", but free-tier certspotter is
unauthenticated 30 req/hr/IP. Across the full 246-domain watched list the
sustainable per-domain visit cadence is hours. For the project's
sensitivity-first mandate (catch open-conflict precursors early), an
attacker-issued cert that exists for hours before our next pull-cycle
visit could be missed if it expires or rotates inside that window. A
push source closes the gap by surfacing matches within seconds, while
the pull sources continue to backfill stragglers and absorb the SPOF
risk of relying on a single community-run ws.

Free-OSINT alignment: Calidog's full-stream is free, unauthenticated,
and has no rate limit on the consumer side. The project definition
mandates free OSINT; this source is the only push CT feed that fits.

Failure modes addressed:
  * ws disconnect          → capped exponential reconnect (1s → 60s ceiling).
  * ws hang                → an in-thread watchdog fires ws.close() when
                              (now - last_message_ts) exceeds the heartbeat
                              budget, and the outer loop reconnects.
  * malformed message      → caught and counted (mode_counters['parse_error']),
                              never propagated.
  * Calidog operator drops feed    → reconnect attempts age out into status="dead",
                              pull sources absorb. The whole point of having
                              three layers.
  * Buffer overflow under burst    → ObservationBuffer's _evict_oldest_locked
                              policy already protects memory.

Liveness model (gevent caveat):
  RFC 6455 ping/pong via websocket-client's `ping_interval` argument
  proved unreliable under gevent monkey-patching — the ping thread races
  the recv loop reading the pong frame and falsely trips ping_timeout
  every ~60s, churning the connection. We disable the client-side ping
  (ping_interval=0) and rely on Calidog's application-layer heartbeat
  frames (≈30s cadence) as the liveness signal. A watchdog thread in
  this module forces a reconnect when no message has arrived for
  `heartbeat_budget_sec` (default 120s, 4× the heartbeat period).

Subdomain match: certspotter pulls use `include_subdomains=true`, so the
push side mirrors that semantics. A cert for `attacker.kantei.go.jp`
must trigger when `kantei.go.jp` is the watched apex. We use suffix-
based matching (no PSL dependency): match iff name == watched OR name
endswith `.` + watched. This is the exact threat model in ADR-024 —
a hostile cert prepared on a watched namespace.

Coarse pre-filter: building a set of country-gov-TLD endings (e.g.
`.go.jp`, `.gov.tw`) lets us reject ~99% of incoming messages without
walking the watched-domain list. Only candidates whose any-SAN ends
with one of these endings pay the per-watched-domain check cost.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from typing import Iterable

from radar.sensors.ct_log_sources.base import (
    BaseCtLogPushSource,
    CertObservation,
)
from radar.sensors.ct_log_sources.buffer import ObservationBuffer, make_observation
from radar.sensors.ct_log_sources.issuer_parse import parse_issuer

log = logging.getLogger("radar")

_USER_AGENT = "OSINT-Radar/8.0 (CT-anomaly-detector)"
_FAILURE_MODES_INIT = {
    "ws_disconnect": 0,
    "ws_error": 0,
    "ws_open_failed": 0,
    "parse_error": 0,
    "make_obs_failed": 0,
    "non_dict_message": 0,
    "heartbeat_only": 0,
    "buffer_record_error": 0,
}


def _build_suffix_set(watched: Iterable[str]) -> set[str]:
    """Pre-compute the coarse-filter set of TLD/SLD endings.

    For each watched apex `a.b.c`, the SLD `b.c` is added (e.g. `gov.tw`,
    `go.jp`). Single-label apexes (rare) add themselves. The set is used
    as a fast first-pass — if no SAN of an incoming cert ends with any of
    these, we skip the per-watched-domain comparison entirely.
    """
    suffixes: set[str] = set()
    for w in watched:
        w_norm = (w or "").strip().lower().lstrip(".")
        if not w_norm:
            continue
        labels = w_norm.split(".")
        if len(labels) >= 2:
            suffixes.add(".".join(labels[-2:]))
        else:
            suffixes.add(w_norm)
    return suffixes


def _match_watched(name: str, watched_set: set[str]) -> str | None:
    """Return the matching watched apex if `name` is the apex or a subdomain.

    Pure suffix-check, no PSL. ADR-024 threat model is "cert prepared on a
    watched namespace" — `*.kantei.go.jp` and `attacker.kantei.go.jp`
    must both match watched `kantei.go.jp`. Wildcards: strip leading `*.`
    before the suffix-check so `*.kantei.go.jp` resolves to apex match.
    """
    n = (name or "").strip().lower()
    if not n:
        return None
    if n.startswith("*."):
        n = n[2:]
    if n in watched_set:
        return n
    for w in watched_set:
        # n endswith ("." + w) means n is a subdomain of w. Avoid the
        # `n.endswith(w)` trap that would also match `notkantei.go.jp`.
        if n.endswith("." + w):
            return w
    return None


class CertstreamSource(BaseCtLogPushSource):
    """Calidog certstream subscriber. Filters to watched-domain matches and
    writes CertObservations into the shared ObservationBuffer.
    """

    name = "certstream"

    def __init__(
        self,
        buffer: ObservationBuffer,
        watched_domains: Iterable[str],
        ws_url: str,
        ping_interval: int = 0,
        ping_timeout: int = 0,
        reconnect_max_sec: int = 60,
        liveness_sec: int = 900,
        heartbeat_budget_sec: int = 120,
    ):
        self._buffer = buffer
        self._watched: set[str] = {
            (d or "").strip().lower() for d in watched_domains if d
        }
        self._suffix_set: set[str] = _build_suffix_set(self._watched)
        self._ws_url = ws_url
        # ping_interval=0 disables websocket-client's RFC 6455 ping/pong loop.
        # See module docstring "Liveness model (gevent caveat)" for why.
        self._ping_interval = max(0, int(ping_interval))
        self._ping_timeout = max(0, int(ping_timeout))
        self._reconnect_max_sec = max(1, int(reconnect_max_sec))
        self._liveness_sec = max(60, int(liveness_sec))
        # Watchdog: if no ws message (Calidog sends heartbeats every ~30s)
        # for this many seconds, force-close the socket and let the outer
        # loop reconnect. 4× the heartbeat period gives room for network
        # jitter without waiting on OS-level TCP keepalive (~2h default).
        self._heartbeat_budget_sec = max(30, int(heartbeat_budget_sec))

        self._failure_modes: dict[str, int] = dict(_FAILURE_MODES_INIT)
        self._matches_total: int = 0
        self._messages_total: int = 0
        self._connect_count: int = 0
        self._last_message_ts: float = 0.0
        self._last_match_ts: float = 0.0
        self._last_open_ts: float = 0.0
        self._last_disconnect_ts: float = 0.0
        self._consecutive_failures: int = 0
        self._status: str = "unknown"
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._ws = None  # WebSocketApp instance, set by worker
        self._watchdog_stop: threading.Event | None = None
        self._lock = threading.Lock()

    # ── Lifecycle ─────────────────────────────────────────────────────
    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        if not self._suffix_set:
            log.info(
                "[CTLog/certstream] No watched domains; not starting worker."
            )
            return
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._run_forever_with_reconnect,
            name="certstream-worker",
            daemon=True,
        )
        self._worker.start()
        log.info(
            "[CTLog/certstream] Worker started (watched=%d suffixes=%d url=%s)",
            len(self._watched), len(self._suffix_set), self._ws_url,
        )

    def stop(self) -> None:
        self._stop_event.set()
        try:
            if self._ws is not None:
                self._ws.close()
        except Exception:
            pass
        if self._worker is not None:
            self._worker.join(timeout=5)

    # ── Health ────────────────────────────────────────────────────────
    def health(self) -> dict:
        now = time.time()
        last_msg_age = (now - self._last_message_ts) if self._last_message_ts else None
        liveness_breached = (
            self._last_message_ts > 0
            and (now - self._last_message_ts) > self._liveness_sec
        )
        # Status precedence: dead > degraded > healthy > unknown.
        # Worker not yet seen a message → unknown until first connect.
        if self._consecutive_failures >= 6:
            status = "dead"
        elif liveness_breached or self._consecutive_failures > 0:
            status = "degraded"
        elif self._last_message_ts > 0:
            status = "healthy"
        else:
            status = "unknown"
        with self._lock:
            self._status = status
        return {
            "status": status,
            "last_success_ts": self._last_message_ts,
            "consecutive_failures": self._consecutive_failures,
            "mode_counters": dict(self._failure_modes),
            "source_specific": {
                "kind": "push",
                "url": self._ws_url,
                "watched_domains": len(self._watched),
                "coarse_suffixes": len(self._suffix_set),
                "messages_total": self._messages_total,
                "matches_total": self._matches_total,
                "connect_count": self._connect_count,
                "last_match_ts": self._last_match_ts,
                "last_open_ts": self._last_open_ts,
                "last_disconnect_ts": self._last_disconnect_ts,
                "last_message_age_sec": (
                    round(last_msg_age, 1) if last_msg_age is not None else None
                ),
                "liveness_budget_sec": self._liveness_sec,
                "liveness_breached": liveness_breached,
                "ping_interval_sec": self._ping_interval,
                "ping_timeout_sec": self._ping_timeout,
                "heartbeat_budget_sec": self._heartbeat_budget_sec,
                "running": bool(self._worker and self._worker.is_alive()),
            },
        }

    # ── Hot-reload of watched set (for future watched-list edits) ─────
    def update_watched(self, watched_domains: Iterable[str]) -> None:
        new_set = {(d or "").strip().lower() for d in watched_domains if d}
        with self._lock:
            self._watched = new_set
            self._suffix_set = _build_suffix_set(new_set)

    # ── Message processing (extracted for unit testing) ───────────────
    def process_message(self, raw: str | bytes) -> int:
        """Parse one ws message and record any watched-domain matches.

        Returns the number of observations recorded into the buffer (so
        tests can assert on filter behavior without standing up a real ws).
        """
        self._messages_total += 1
        self._last_message_ts = time.time()
        try:
            msg = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        except Exception:
            self._failure_modes["parse_error"] += 1
            return 0
        if not isinstance(msg, dict):
            self._failure_modes["non_dict_message"] += 1
            return 0
        mtype = msg.get("message_type")
        # Calidog emits "heartbeat" frames with no `data` payload — count
        # them so operators can distinguish "ws idle" from "ws disconnected".
        if mtype == "heartbeat":
            self._failure_modes["heartbeat_only"] += 1
            return 0
        data = msg.get("data") or {}
        if not isinstance(data, dict):
            return 0
        leaf = data.get("leaf_cert") or {}
        if not isinstance(leaf, dict):
            return 0

        all_domains_raw = leaf.get("all_domains") or []
        if not isinstance(all_domains_raw, list):
            return 0
        # Coarse pre-filter: walk the SANs once, normalize, and reject the
        # whole cert if no SAN ends with a known gov-TLD suffix.
        sans: list[str] = []
        any_suffix_hit = False
        for s in all_domains_raw:
            if not isinstance(s, str):
                continue
            n = s.strip().lower()
            if not n:
                continue
            sans.append(n)
            check = n[2:] if n.startswith("*.") else n
            for suffix in self._suffix_set:
                if check == suffix or check.endswith("." + suffix):
                    any_suffix_hit = True
                    break
        if not any_suffix_hit:
            return 0

        # Per-SAN exact watched-apex check (only after coarse filter passed).
        # Group matches by watched apex so one cert spanning multiple watched
        # apexes generates one observation per apex.
        with self._lock:
            watched_set = set(self._watched)
        matched_apexes: set[str] = set()
        for n in sans:
            apex = _match_watched(n, watched_set)
            if apex:
                matched_apexes.add(apex)
        if not matched_apexes:
            return 0

        # Issuer normalization. Calidog's issuer is a dict of components —
        # build the comma-DN form parse_issuer() expects.
        issuer = leaf.get("issuer") or {}
        if isinstance(issuer, dict):
            parts = []
            for k, v in issuer.items():
                if isinstance(v, str) and v.strip():
                    parts.append(f"{k.upper()}={v.strip()}")
            issuer_dn = ", ".join(parts)
        elif isinstance(issuer, str):
            issuer_dn = issuer
        else:
            issuer_dn = ""
        ca_norm, ca_raw = parse_issuer(issuer_dn)
        if ca_norm == "unknown":
            return 0

        # Common name / SAN list / not_before. Calidog gives subject.CN
        # as a string and not_before as float epoch.
        subj = leaf.get("subject") or {}
        cn = ""
        if isinstance(subj, dict):
            cn = (subj.get("CN") or subj.get("cn") or "").strip()
        if not cn:
            for n in sans:
                if not n.startswith("*."):
                    cn = n
                    break
            if not cn and sans:
                cn = sans[0]

        not_before_iso = ""
        nb_raw = leaf.get("not_before")
        if isinstance(nb_raw, (int, float)) and nb_raw > 0:
            try:
                from datetime import datetime, timezone
                not_before_iso = datetime.fromtimestamp(
                    nb_raw, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%S")
            except (ValueError, OSError):
                not_before_iso = ""
        elif isinstance(nb_raw, str):
            not_before_iso = nb_raw

        serial = ""
        s_raw = leaf.get("serial_number")
        if isinstance(s_raw, str):
            serial = s_raw

        recorded = 0
        now_ts = time.time()
        for apex in matched_apexes:
            obs = make_observation(
                domain=apex,
                issuer_raw=ca_raw,
                issuer_norm=ca_norm,
                common_name=cn,
                subject_alt_names=sans,
                not_before_iso=not_before_iso,
                serial=serial,
                source_name=self.name,
                observed_at_ts=now_ts,
            )
            if obs is None:
                self._failure_modes["make_obs_failed"] += 1
                continue
            try:
                if self._buffer.record(obs):
                    recorded += 1
            except Exception as e:
                self._failure_modes["buffer_record_error"] += 1
                log.debug(f"[CTLog/certstream] buffer.record raised: {e}")
        if recorded:
            self._matches_total += recorded
            self._last_match_ts = now_ts
        return recorded

    # ── ws lifecycle (private, runs in worker thread) ─────────────────
    def _run_forever_with_reconnect(self) -> None:
        """Capped exponential reconnect loop. Runs in worker thread under
        gevent monkey-patch (the spike confirmed interop). Outer loop owns
        backoff and shutdown signal; inner WebSocketApp.run_forever() owns
        the socket; a sibling watchdog thread owns liveness detection.
        """
        try:
            from websocket import WebSocketApp  # type: ignore[import-not-found]
        except ImportError:
            log.error(
                "[CTLog/certstream] websocket-client not installed; "
                "push source will not run. pip install websocket-client>=1.7"
            )
            return

        backoff = 1.0
        while not self._stop_event.is_set():
            watchdog = threading.Thread(
                target=self._watchdog_loop,
                name="certstream-watchdog",
                daemon=True,
            )
            watchdog_stop = threading.Event()
            try:
                ws = WebSocketApp(
                    self._ws_url,
                    on_message=lambda _ws, raw: self._on_message_safe(raw),
                    on_open=lambda _ws: self._on_open(),
                    on_close=lambda _ws, code, reason: self._on_close(code, reason),
                    on_error=lambda _ws, err: self._on_error(err),
                    header={"User-Agent": _USER_AGENT},
                )
                with self._lock:
                    self._ws = ws
                    self._watchdog_stop = watchdog_stop
                watchdog.start()
                # ping_interval=0 disables websocket-client's RFC 6455 ping
                # thread. Under gevent that thread races the recv loop's
                # pong handler and falsely trips ping_timeout every ~60s.
                # The watchdog thread below is the liveness backstop: it
                # calls ws.close() if no Calidog heartbeat (or cert msg)
                # arrives within heartbeat_budget_sec.
                ws.run_forever(
                    ping_interval=self._ping_interval,
                    ping_timeout=self._ping_timeout or None,
                )
            except Exception as e:
                self._failure_modes["ws_open_failed"] += 1
                log.warning(f"[CTLog/certstream] ws loop exception: {e}")
            finally:
                watchdog_stop.set()
                with self._lock:
                    self._ws = None
                    self._watchdog_stop = None
                try:
                    watchdog.join(timeout=2)
                except Exception:
                    pass

            if self._stop_event.is_set():
                break
            # Capped exponential backoff with jitter avoidance: doubling.
            sleep_for = min(self._reconnect_max_sec, backoff)
            self._stop_event.wait(timeout=sleep_for)
            backoff = min(self._reconnect_max_sec, backoff * 2.0)
            self._consecutive_failures += 1
        log.info("[CTLog/certstream] Worker exiting.")

    def _watchdog_loop(self) -> None:
        """Force-close the ws if no message has arrived within the budget.

        Calidog sends an application-layer heartbeat every ~30s. Going
        longer than `heartbeat_budget_sec` (default 120s, 4× period) means
        the ws is effectively dead — reconnect via the outer loop.
        """
        with self._lock:
            stop = self._watchdog_stop
        if stop is None:
            return
        # Prime last_message_ts to now so the budget starts counting from
        # the moment the watchdog started, not from the previous session.
        grace_start = time.time()
        while not stop.is_set() and not self._stop_event.is_set():
            if stop.wait(timeout=5):
                return
            now = time.time()
            last = self._last_message_ts or grace_start
            if (now - last) > self._heartbeat_budget_sec:
                log.info(
                    "[CTLog/certstream] watchdog: no message for %.0fs "
                    "(budget=%ds), forcing reconnect",
                    now - last, self._heartbeat_budget_sec,
                )
                try:
                    with self._lock:
                        ws = self._ws
                    if ws is not None:
                        ws.close()
                except Exception as e:
                    log.debug(f"[CTLog/certstream] watchdog close raised: {e}")
                return

    def _on_message_safe(self, raw) -> None:
        try:
            self.process_message(raw)
        except Exception as e:
            self._failure_modes["parse_error"] += 1
            log.debug(f"[CTLog/certstream] on_message exception: {e}")

    def _on_open(self) -> None:
        self._connect_count += 1
        self._last_open_ts = time.time()
        self._consecutive_failures = 0
        log.info(f"[CTLog/certstream] ws connected (connect_count={self._connect_count})")

    def _on_close(self, code, reason) -> None:
        self._failure_modes["ws_disconnect"] += 1
        self._last_disconnect_ts = time.time()
        log.info(f"[CTLog/certstream] ws closed code={code} reason={reason}")

    def _on_error(self, err) -> None:
        self._failure_modes["ws_error"] += 1
        log.debug(f"[CTLog/certstream] ws error: {type(err).__name__}: {err}")
