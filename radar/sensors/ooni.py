"""radar.sensors.ooni -- OONI Censorship Measurement sensor.

Queries the OONI (Open Observatory of Network Interference) API for
internet censorship measurements. Detects website blocking, DNS
tampering, and protocol filtering in strategic theaters.

A surge in censorship measurements is a strong indicator of
state-level internet control tightening (pre-conflict preparation).

API: https://api.ooni.io/
No API key required (public).
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

    def __init__(self):
        super().__init__("ooni_censorship", "cyber", 1800)
        self._prev_anomaly_counts: dict[str, int] = {}

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_theaters", [])
        adversaries = context.get("adversary_states", [])
        all_targets = list(set(theaters + adversaries))
        if not all_targets:
            all_targets = list(COUNTRY_COORDS.keys())[:10]

        censorship_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        last_status = 0
        last_error = ""

        for code in all_targets:
            try:
                # Query OONI aggregation API for recent measurements
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
                    self.handle_rate_limit(res, round((time.time() - t0) * 1000))
                    break
                elif res.status_code == 200:
                    data = res.json()
                    result_rows = data.get("result", [])
                    any_success = True

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

                    # Detect surge: anomaly rate > 20% or confirmed blocks > 5%
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

            except Exception as e:
                last_error = f"ooni({code}): {e}"
                log.warning(f"[OONI] Error for {code}: {e}")

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


def _today() -> str:
    """Return today's date in YYYY-MM-DD format."""
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _days_ago(n: int) -> str:
    """Return a date N days ago in YYYY-MM-DD format."""
    import datetime
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=n)
    return dt.strftime("%Y-%m-%d")
