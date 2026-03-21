"""radar.sensors.ripe_atlas -- RIPE Atlas global reachability sensor.

Queries the RIPE Atlas API for two independent signals:
  - Active probe counts per country (drop = regional disruption)
  - Public measurement RTT from global probes (latency anomaly detection)

Reading public measurement data requires no API key and no credits.
Over 12,000 probes worldwide provide ground-truth reachability data.

API base: https://atlas.ripe.net/api/v2/
"""
from __future__ import annotations
import requests
import time
import logging
from radar.config import COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY
from radar.sensors.base import BaseSensor

log = logging.getLogger("radar")

ATLAS_API_BASE = "https://atlas.ripe.net/api/v2"

# Public always-running measurements (root DNS server pings, no credits needed)
# 1001 = k-root (RIPE), 1004 = f-root, 10509 = Google DNS
DEFAULT_MEASUREMENT_IDS = [1001, 1004, 10509]

# Thresholds for probe drop detection
PROBE_DROP_PCT = 0.30      # 30% drop = PROBE_DROP
PROBE_BLACKOUT_PCT = 0.70  # 70% drop = PROBE_BLACKOUT


class RipeAtlasSensor(BaseSensor):
    """RIPE Atlas sensor: probe availability and public measurement RTT."""

    def __init__(self):
        super().__init__("ripe_atlas", "physical", 600)
        self._prev_probe_counts: dict[str, int] = {}

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_theaters", [])
        if not theaters:
            theaters = list(COUNTRY_COORDS.keys())[:20]

        probe_counts: dict[str, dict] = {}
        latency_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        last_status = 0
        last_error = ""

        # 1. Probe availability per country
        for code in theaters:
            try:
                url = f"{ATLAS_API_BASE}/probes/"
                params = {"country_code": code, "status": 1, "page_size": 1}
                res = requests.get(url, params=params, timeout=10,
                                   proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                last_status = res.status_code
                if res.status_code == 200:
                    data = res.json()
                    active = data.get("count", 0)
                    prev = self._prev_probe_counts.get(code, active)
                    drop_pct = (prev - active) / max(prev, 1) if prev > 0 else 0
                    probe_counts[code] = {
                        "active": active,
                        "prev": prev,
                        "drop_pct": round(drop_pct, 3),
                    }
                    any_success = True
                time.sleep(0.5)  # Rate limit courtesy
            except Exception as e:
                last_error = f"probes({code}): {e}"

        # 2. Public measurement latency per country
        for code in theaters:
            rtt_values = []
            for mid in DEFAULT_MEASUREMENT_IDS:
                try:
                    url = f"{ATLAS_API_BASE}/measurements/{mid}/latest/"
                    params = {"probe_cc": code}
                    res = requests.get(url, params=params, timeout=10,
                                       proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                    if res.status_code == 200:
                        probes = res.json()
                        if isinstance(probes, list):
                            for probe in probes:
                                # Extract avg RTT from ping measurement
                                avg = probe.get("avg")
                                if avg is not None and avg > 0:
                                    rtt_values.append(avg)
                                # Also check result array for DNS measurements
                                for result in probe.get("result", []):
                                    if not isinstance(result, dict):
                                        continue
                                    rt = result.get("rt")
                                    if rt is not None and rt > 0:
                                        rtt_values.append(rt)
                        any_success = True
                    time.sleep(0.3)
                except Exception as e:
                    last_error = f"meas({mid},{code}): {e}"

            if rtt_values:
                rtt_values.sort()
                avg_ms = sum(rtt_values) / len(rtt_values)
                p95_idx = int(len(rtt_values) * 0.95)
                p95_ms = rtt_values[min(p95_idx, len(rtt_values) - 1)]
                latency_data[code] = {
                    "avg_ms": round(avg_ms, 2),
                    "p95_ms": round(p95_ms, 2),
                    "probes_responding": len(rtt_values),
                }

        # Determine country status
        for code in theaters:
            pc = probe_counts.get(code, {})
            drop = pc.get("drop_pct", 0)
            lat = latency_data.get(code, {})

            if drop >= PROBE_BLACKOUT_PCT:
                country_status[code] = "PROBE_BLACKOUT"
            elif drop >= PROBE_DROP_PCT:
                country_status[code] = "PROBE_DROP"
            else:
                country_status[code] = "NORMAL"

        # Update previous probe counts for next cycle
        for code, pc in probe_counts.items():
            if pc.get("active", 0) > 0:
                self._prev_probe_counts[code] = pc["active"]

        duration = round((time.time() - t0) * 1000)
        total_records = len(probe_counts) + len(latency_data)
        self.log_fetch(any_success, duration, last_status, total_records, last_error)

        result = {
            "probe_counts": probe_counts,
            "latency": latency_data,
            "country_status": country_status,
        }
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "probe_counts": {}, "latency": {},
            "country_status": {c: "NORMAL" for c in theaters},
        }
