"""radar.sensors.ooni -- OONI Censorship Measurement sensor.

Queries the OONI (Open Observatory of Network Interference) API for
internet censorship measurements. Detects website blocking, DNS
tampering, and protocol filtering in strategic theaters.

A surge in censorship measurements is a strong indicator of
state-level internet control tightening (pre-conflict preparation).

API: https://api.ooni.io/
No API key required (public).

Self-healing degraded mode (added 2026-04-22): api.ooni.io has
extended outages where every theater 500s or times out for hours at a
time. In that situation the sensor must not flood logs at the normal
30-min cadence, must not chew through 9 × 20s = 3 minutes of fetch
budget per cycle, and must still detect when the upstream recovers.

After 3 consecutive cycles where every probed theater fails, the
sensor enters degraded mode: probes a single theater every 2h until
one succeeds, then snaps back to normal cadence.
"""
from __future__ import annotations
import logging
import time
import requests
from radar.sensors.base import BaseSensor
from radar.config import COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY

log = logging.getLogger("radar")

OONI_API_BASE = "https://api.ooni.io/api/v1"


class OoniSensor(BaseSensor):
    """OONI internet censorship measurement sensor (cyber domain)."""

    _NORMAL_INTERVAL = 1800           # 30 min
    _DEGRADED_INTERVAL = 7200         # 2h (probe cadence while api.ooni.io is down)
    _DEGRADED_AFTER_FAILS = 3         # consecutive empty-cycle threshold

    def __init__(self):
        super().__init__("ooni_censorship", "cyber", self._NORMAL_INTERVAL)
        self._prev_anomaly_counts: dict[str, int] = {}
        # Self-healing state. Same structure as CtLogSensor for consistency
        # so the operator diagnostics panel can render both with one
        # template once T1.B ships.
        self._upstream_status: str = "unknown"  # unknown | healthy | degraded
        self._consecutive_failures: int = 0
        self._last_success_ts: float = 0.0
        self._success_count: int = 0
        self._failure_modes: dict[str, int] = {
            "timeout": 0,
            "conn_error": 0,
            "http_5xx": 0,
            "http_4xx": 0,
            "json_error": 0,
        }

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_countries", [])
        adversaries = context.get("adversary_states", [])
        all_targets = list(set(theaters + adversaries))
        if not all_targets:
            all_targets = list(COUNTRY_COORDS.keys())[:10]

        # In degraded mode probe just one theater to detect recovery.
        probe_targets = (all_targets[:1]
                         if self._upstream_status == "degraded"
                         else all_targets)
        # In degraded mode, demote per-theater error logs to DEBUG so a
        # multi-hour upstream outage doesn't fill the operator's window.
        log_level = (logging.DEBUG
                     if self._upstream_status == "degraded"
                     else logging.WARNING)

        censorship_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        last_status = 0
        last_error = ""

        for code in probe_targets:
            try:
                url = f"{OONI_API_BASE}/aggregation"
                params = {
                    "probe_cc": code,
                    "since": _days_ago(7),
                    "until": _today(),
                    "axis_x": "measurement_start_day",
                    "test_name": "web_connectivity",
                }
                res = requests.get(
                    url, params=params, timeout=20,
                    proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                    headers={"Accept": "application/json"},
                )
                last_status = res.status_code

                if res.status_code == 429:
                    self._failure_modes["http_4xx"] += 1
                    self.handle_rate_limit(res, round((time.time() - t0) * 1000))
                    break

                if 500 <= res.status_code < 600:
                    self._failure_modes["http_5xx"] += 1
                    log.log(log_level,
                            f"[OONI] HTTP {res.status_code} for {code}")
                    time.sleep(0.5)
                    continue

                if 400 <= res.status_code < 500:
                    self._failure_modes["http_4xx"] += 1
                    log.log(log_level,
                            f"[OONI] HTTP {res.status_code} for {code}")
                    time.sleep(0.5)
                    continue

                if res.status_code == 200:
                    try:
                        data = res.json()
                    except Exception as e:
                        self._failure_modes["json_error"] += 1
                        log.log(log_level, f"[OONI] JSON parse error for {code}: {e}")
                        continue

                    result_rows = data.get("result", [])
                    any_success = True
                    self._success_count += 1

                    total_measurements = 0
                    anomaly_count = 0
                    confirmed_count = 0
                    failure_count = 0
                    daily_anomalies = []

                    for row in result_rows:
                        m_count = row.get("measurement_count", 0)
                        a_count = row.get("anomaly_count", 0)
                        c_count = row.get("confirmed_count", 0)
                        f_count = row.get("failure_count", 0)
                        total_measurements += m_count
                        anomaly_count += a_count
                        confirmed_count += c_count
                        failure_count += f_count
                        if m_count > 0:
                            daily_anomalies.append(round(a_count / m_count, 3))

                    anomaly_rate = (anomaly_count / max(total_measurements, 1)
                                    if total_measurements > 0 else 0)
                    confirmed_rate = (confirmed_count / max(total_measurements, 1)
                                      if total_measurements > 0 else 0)

                    prev_anomalies = self._prev_anomaly_counts.get(code, anomaly_count)
                    anomaly_surge = (anomaly_count > prev_anomalies * 1.5
                                     if prev_anomalies > 10 else False)

                    is_censoring = (confirmed_rate > 0.05 or
                                    anomaly_rate > 0.20 or
                                    anomaly_surge)
                    is_heavy = (confirmed_rate > 0.15 or anomaly_rate > 0.40)

                    censorship_data[code] = {
                        "total_measurements": total_measurements,
                        "anomaly_count": anomaly_count,
                        "confirmed_count": confirmed_count,
                        "failure_count": failure_count,
                        "anomaly_rate": round(anomaly_rate, 4),
                        "confirmed_rate": round(confirmed_rate, 4),
                        "anomaly_surge": anomaly_surge,
                        "is_censoring": is_censoring,
                        "is_heavy": is_heavy,
                        "daily_anomaly_rates": daily_anomalies[-7:],
                    }

                    if is_heavy:
                        country_status[code] = "HEAVY_CENSORSHIP"
                    elif is_censoring:
                        country_status[code] = "CENSORSHIP_DETECTED"
                    else:
                        country_status[code] = "NORMAL"

                    if anomaly_count > 0:
                        self._prev_anomaly_counts[code] = anomaly_count

                time.sleep(0.5)

            except requests.exceptions.Timeout:
                self._failure_modes["timeout"] += 1
                last_error = f"ooni({code}): timeout"
                log.log(log_level, f"[OONI] Timeout for {code}")
            except requests.exceptions.ConnectionError as e:
                self._failure_modes["conn_error"] += 1
                last_error = f"ooni({code}): {e}"
                log.log(log_level, f"[OONI] Connection error for {code}: {e}")
            except Exception as e:
                last_error = f"ooni({code}): {e}"
                log.log(log_level, f"[OONI] Error for {code}: {e}")

        # ── Self-healing cadence management ───────────────────────────────
        if any_success:
            if self._upstream_status != "healthy":
                if self._upstream_status == "degraded":
                    log.info(
                        f"[OONI] Upstream api.ooni.io recovered after "
                        f"{self._consecutive_failures} fail cycles — "
                        f"resuming normal {self._NORMAL_INTERVAL // 60}min cadence"
                    )
                self._upstream_status = "healthy"
            self._consecutive_failures = 0
            self._last_success_ts = time.time()
            self.poll_interval = self._NORMAL_INTERVAL
        else:
            self._consecutive_failures += 1
            if (self._consecutive_failures >= self._DEGRADED_AFTER_FAILS
                    and self._upstream_status != "degraded"):
                self._upstream_status = "degraded"
                self.poll_interval = self._DEGRADED_INTERVAL
                log.warning(
                    f"[OONI] Upstream api.ooni.io appears down "
                    f"({self._consecutive_failures} consecutive fail cycles) — "
                    f"degraded mode, probing every {self._DEGRADED_INTERVAL // 60}min"
                )

        duration = round((time.time() - t0) * 1000)
        total_records = sum(d["total_measurements"] for d in censorship_data.values())
        self.log_fetch(any_success, duration, last_status, total_records, last_error)

        result = {"censorship_data": censorship_data, "country_status": country_status}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "censorship_data": {},
            "country_status": {c: "NORMAL" for c in all_targets},
        }

    def upstream_health(self) -> dict:
        """Return api.ooni.io upstream health for the diagnostics panel.

        Mirror of CtLogSensor.upstream_health() shape so T1.B can render
        both sensors with the same template.
        """
        return {
            "status": self._upstream_status,
            "consecutive_failures": self._consecutive_failures,
            "last_success_ts": self._last_success_ts,
            "current_interval_sec": self.poll_interval,
            "success_count": self._success_count,
            "failure_modes": dict(self._failure_modes),
        }


def _today() -> str:
    """Return today's date in YYYY-MM-DD format."""
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _days_ago(n: int) -> str:
    """Return a date N days ago in YYYY-MM-DD format."""
    import datetime
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=n)
    return dt.strftime("%Y-%m-%d")
