"""radar.sensors.checkhost -- CheckHostSensor."""
from __future__ import annotations
import requests
import time
from collections import deque
from radar.config import (
    INFRASTRUCTURE_URLS, GLOBAL_PROXIES, SSL_VERIFY, HOD_MIN_SAME_HOUR, HOD_MAX_ENTRIES,
)
from radar.sensors.base import BaseSensor
from radar.database import db as _db
import os

CHECKHOST_NODES_STR = os.getenv("CHECKHOST_NODES",
    "jp1.node.check-host.net,us1.node.check-host.net,"
    "de1.node.check-host.net,nl1.node.check-host.net,fr1.node.check-host.net")
CHECKHOST_NODES = [n.strip() for n in CHECKHOST_NODES_STR.split(",") if n.strip()]
CHECKHOST_POLL_INTERVAL = int(os.getenv("CHECKHOST_POLL_INTERVAL", "600"))
CHECKHOST_TIMEOUT_MS = int(os.getenv("CHECKHOST_TIMEOUT_MS", "3000"))

class CheckHostSensor(BaseSensor):
    """
    Infra Domain sensor: uses check-host.net API to run reachability checks
    against INFRASTRUCTURE_URLS from multiple global nodes and compute Success Rate.
    Also invoked on DDoS acceleration spike detection (from WeightedConvergenceEngine).
    """
    CHECK_HOST_API = "https://check-host.net/check-http"
    RESULT_API     = "https://check-host.net/check-result/{request_id}"
    # Per-URL cooldown: only re-check a URL if ≥ 5 min has elapsed since last poll
    _URL_COOLDOWN_SEC = 300
    _url_last_poll: dict = {}   # url → unix timestamp of last successful check
    # Rolling latency history: last 12 readings per URL (≈1 h at 5-min poll interval)
    _url_latency_history: dict = {}  # url → deque of latency_ms floats

    def __init__(self):
        super().__init__("check_host", "physical", CHECKHOST_POLL_INTERVAL)

    def check_url(self, url: str, nodes: list) -> dict:
        """Check a single URL from multiple nodes and return {success_rate, node_ok, results}.
        Detects CDN-masked asphyxiation: success_rate==1.0 but latency > 3× 1-hour rolling avg."""
        try:
            # Pass list of tuples to requests to allow repeated same key
            params = [("host", url), ("max_nodes", min(len(nodes), 5))]
            params += [("node[]", n) for n in nodes[:5]]
            res = requests.get(
                self.CHECK_HOST_API,
                params=params,
                headers={"Accept": "application/json",
                         "User-Agent": "OSINT-Radar/9.0"},
                timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if res.status_code == 429:
                return {"success_rate": None, "error": "rate_limited(429)"}
            if res.status_code != 200:
                return {"success_rate": None, "error": f"HTTP {res.status_code}"}

            data = res.json()
            request_id = data.get("request_id", "")
            if not request_id:
                return {"success_rate": None, "error": "no request_id"}

            # Wait up to 10 seconds for results
            time.sleep(5)
            r2 = requests.get(
                self.RESULT_API.format(request_id=request_id),
                headers={"Accept": "application/json",
                         "User-Agent": "OSINT-Radar/9.0"},
                timeout=12, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if r2.status_code != 200:
                return {"success_rate": None, "error": f"result HTTP {r2.status_code}"}

            node_results = r2.json()
            ok_count  = 0
            all_count = 0
            latencies: list = []
            # Per-node result map: short label (e.g. "JP", "US") → "OK"/"FAIL"/"TIMEOUT"
            node_ok: dict = {}
            for node_id, checks in node_results.items():
                # Derive short display label from hostname prefix (e.g. "jp1" → "JP1")
                node_label = node_id.split(".")[0][:3].upper()
                if not isinstance(checks, list):
                    # Node returned null: still pending (5s wait insufficient) or unreachable.
                    # Do NOT count in all_count — pending nodes must not dilute success_rate.
                    node_ok[node_label] = "PENDING"
                    continue
                for chk in checks:
                    # check-host.net HTTP result format:
                    # [ok_flag, time_seconds, status_msg, http_code_str, ip]
                    # ok_flag: 1=success, 0=failure
                    # e.g. [1, 0.634, "Found", "302", "1.2.3.4"]
                    # error:  [0, 0.0, "Connection refused", "", ""]
                    # individual null entry: single check still pending
                    if chk is None:
                        # Individual check still pending — do NOT count in all_count.
                        # Treating as failure would dilute success_rate identically to
                        # the top-level null case fixed above.
                        node_ok[node_label] = "PENDING"
                        continue
                    if not isinstance(chk, list) or len(chk) < 2:
                        continue
                    all_count += 1
                    ok_flag  = chk[0]                                 # int: 1 or 0
                    time_s   = chk[1] if isinstance(chk[1], (int, float)) else None
                    http_str = chk[3] if len(chk) > 3 else None      # e.g. "200", "302"
                    # Determine success: ok_flag==1 AND HTTP code < 400 (if available)
                    try:
                        http_int = int(http_str) if http_str else None
                    except (ValueError, TypeError):
                        http_int = None
                    is_ok = (ok_flag == 1) and (http_int is None or http_int < 400)
                    if is_ok:
                        ok_count += 1
                    if time_s is not None and time_s > 0:
                        lat_ms = time_s * 1000  # seconds → ms
                        latencies.append(lat_ms)
                        if lat_ms > CHECKHOST_TIMEOUT_MS:
                            node_ok[node_label] = "TIMEOUT"
                        else:
                            node_ok[node_label] = "OK" if is_ok else "FAIL"
                    else:
                        node_ok[node_label] = "OK" if is_ok else "FAIL"

            # Require at least 2 nodes to respond before trusting success_rate.
            # A single responding node (others still pending) is not sufficient evidence.
            success_rate = round(ok_count / all_count, 3) if all_count >= 2 else None
            avg_latency  = round(sum(latencies) / len(latencies)) if latencies else None

            # NOTE: Latency-based success_rate penalty removed.
            # Cross-continental checks (e.g. EU nodes → TW/UA gov sites) legitimately
            # exceed 3000ms without indicating failure. HTTP ok_flag already captures
            # true failures. High latency is surfaced via node_ok TIMEOUT labels and
            # the asphyxiation detector below — it must not corrupt success_rate.

            # ── Asphyxiation detection (CDN masking) ─────────────────────────────
            # Compute rolling baseline BEFORE appending current sample so the spike
            # does not contaminate the baseline it is being compared against.
            if url not in CheckHostSensor._url_latency_history:
                CheckHostSensor._url_latency_history[url] = deque(maxlen=12)
            lat_history = list(CheckHostSensor._url_latency_history[url])
            rolling_avg = sum(lat_history) / len(lat_history) if len(lat_history) >= 3 else None
            # Asphyxiation: success looks 100% but latency has tripled vs rolling baseline
            asphyxiation = (
                success_rate is not None and success_rate >= 0.99
                and avg_latency is not None and rolling_avg is not None
                and avg_latency > rolling_avg * 3.0
            )
            # Append current sample after comparison (update history for next cycle)
            if avg_latency is not None:
                CheckHostSensor._url_latency_history[url].append(avg_latency)

            return {
                "success_rate":   success_rate,
                "ok_nodes":       ok_count,
                "total_nodes":    all_count,
                "avg_latency_ms": avg_latency,
                "node_ok":        node_ok,
                "asphyxiation":   asphyxiation,
                "rolling_avg_latency_ms": round(rolling_avg) if rolling_avg else None,
                "status": ("OK"      if success_rate and success_rate >= 0.8 else
                           "PARTIAL" if success_rate and success_rate >= 0.3 else
                           "BLACKOUT"),
            }
        except Exception as e:
            return {"success_rate": None, "error": str(e)}

    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        results: dict = {}
        t0 = time.time()
        total_checked = 0
        any_success   = False
        now = time.time()

        # Evict stale URL entries (>24h old) to prevent unbounded growth
        _stale_cutoff = now - 86400
        for url in [u for u, ts in CheckHostSensor._url_last_poll.items() if ts < _stale_cutoff]:
            CheckHostSensor._url_last_poll.pop(url, None)
            CheckHostSensor._url_latency_history.pop(url, None)

        for theater in theaters:
            urls = INFRASTRUCTURE_URLS.get(theater, [])
            if not urls:
                continue

            url_results: dict = {}
            ok_count   = 0
            asphyx_any = False
            url_count  = 0

            for url in urls[:3]:  # Rate limit mitigation: max 3 URLs per theater
                # Per-URL cooldown: skip if polled within the last 5 minutes
                last_poll = CheckHostSensor._url_last_poll.get(url, 0)
                if now - last_poll < CheckHostSensor._URL_COOLDOWN_SEC:
                    # Reuse cached result from previous fetch if available
                    cached_ch = self.get_cache().get("check_host", {})
                    prev = cached_ch.get(theater, {}).get("urls", {}).get(url)
                    if prev:
                        url_results[url] = prev
                        url_count += 1
                        if prev.get("success_rate", 0) >= 0.8:
                            ok_count += 1
                        if prev.get("asphyxiation"):
                            asphyx_any = True
                    continue

                chk = self.check_url(url, CHECKHOST_NODES)
                url_results[url] = chk
                if chk.get("success_rate") is not None:
                    # Only count URLs that returned a valid result (not API errors/timeouts)
                    url_count += 1
                    any_success = True
                    total_checked += 1
                    CheckHostSensor._url_last_poll[url] = now
                    if chk["success_rate"] >= 0.8:
                        ok_count += 1
                if chk.get("asphyxiation"):
                    asphyx_any = True

            # Overall success rate for the theater
            # theater_success_rate is None when all API calls failed (API unreachable, not target down)
            theater_success_rate = ok_count / url_count if url_count else None

            # HOD-normalized status: compare against same-hour historical distribution.
            # Eliminates false PARTIAL from routine maintenance windows (e.g., deep-night UTC).
            # Falls back to fixed thresholds during warmup (< HOD_MIN_SAME_HOUR same-hour samples).
            if theater_success_rate is None:
                overall_status = "UNKNOWN"
            else:
                _hour_bucket = int(now // 3600) * 3600
                _last_bucket = _db.hod_last_bucket("checkhost_hod", theater)
                if _last_bucket != _hour_bucket:
                    _db.hod_record("checkhost_hod", theater, _hour_bucket,
                                   theater_success_rate, max_entries=HOD_MAX_ENTRIES)
                _cur_hod   = (_hour_bucket // 3600) % 24
                _same_hour = _db.hod_same_hour("checkhost_hod", theater,
                                               _cur_hod, _hour_bucket)
                if len(_same_hour) >= HOD_MIN_SAME_HOUR:
                    _hm = sum(_same_hour) / len(_same_hour)
                    _hs = max((sum((x - _hm)**2 for x in _same_hour) / len(_same_hour))**0.5, 0.05)
                    _hz = (theater_success_rate - _hm) / _hs
                    if _hz < -3.0 and theater_success_rate < 0.3:
                        overall_status = "BLACKOUT"
                    elif _hz < -2.0 and theater_success_rate < 0.8:
                        overall_status = "PARTIAL"
                    else:
                        overall_status = "OK"
                else:
                    # Warmup: fixed thresholds
                    overall_status = ("OK"       if theater_success_rate >= 0.8 else
                                      "PARTIAL"  if theater_success_rate >= 0.3 else
                                      "BLACKOUT")

            results[theater] = {
                "urls":                 url_results,
                "theater_success_rate": theater_success_rate,
                "status":               overall_status,
                "asphyxiation":         asphyx_any,
            }

        self.log_fetch(any_success, round((time.time() - t0) * 1000), 200, total_checked)
        result = {"check_host": results}
        self.set_cache(result)
        return result

