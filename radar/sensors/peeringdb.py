"""radar.sensors.peeringdb -- PeeringDbSensor."""
from __future__ import annotations
import requests
import time
import logging
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
)
from radar.sensors.base import BaseSensor

log = logging.getLogger("radar")

class PeeringDbSensor(BaseSensor):
    def __init__(self): super().__init__("peeringdb_ixp", "physical", 14400)
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        ixp_data: dict = {}
        t0 = time.time()
        total_ixps = 0; any_success = False; last_status = 0; last_error = ""
        rate_limited = 0

        for idx, code in enumerate(theaters):
            if idx > 0:
                time.sleep(10)  # PeeringDB rate limit mitigation (10s/request)
            try:
                res = requests.get(
                    "https://www.peeringdb.com/api/ix",
                    params={"country": code},
                    headers={"Accept": "application/json"},
                    timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
                )
                last_status = res.status_code
                if res.status_code == 429:
                    # 429 → wait 20s (reduced from 60s) and retry once
                    time.sleep(20)
                    try:
                        res = requests.get(
                            "https://www.peeringdb.com/api/ix",
                            params={"country": code},
                            headers={"Accept": "application/json"},
                            timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
                        )
                        last_status = res.status_code
                    except Exception:
                        pass
                if res.status_code == 200:
                    items = res.json().get("data", [])
                    coord = COUNTRY_COORDS.get(code, {})
                    ixps = [{"id": ix.get("id"), "name": ix.get("name", ""), "city": ix.get("city", ""),
                             "country": code, "lat": coord.get("lat", 0), "lng": coord.get("lng", 0),
                             "status": ix.get("status", "ok"), "aka": ix.get("name_long", "")} for ix in items]
                    ixp_data[code] = {"ixps": ixps, "count": len(ixps)}
                    total_ixps += len(items); any_success = True
                elif res.status_code == 429:
                    # On persistent 429, preserve previously cached data for this country
                    prev = self.get_cache().get("ixp_data", {}).get(code)
                    if prev and prev.get("count", 0) > 0:
                        ixp_data[code] = prev
                        log.debug(f"[PeeringDB] 429 for {code}, using cached data ({prev['count']} IXPs)")
                    else:
                        ixp_data[code] = {"ixps": [], "count": 0, "error": "rate_limited"}
                    rate_limited += 1
                else:
                    ixp_data[code] = {"ixps": [], "count": 0, "error": f"HTTP {res.status_code}"}
                    last_error = f"HTTP {res.status_code}"
            except Exception as e:
                # On error, preserve previously cached data for this country
                prev = self.get_cache().get("ixp_data", {}).get(code)
                if prev and prev.get("count", 0) > 0:
                    ixp_data[code] = prev
                else:
                    ixp_data[code] = {"ixps": [], "count": 0, "error": str(e)}
                last_error = str(e)

        if rate_limited and not last_error:
            last_error = f"rate_limited ({rate_limited} countries)"
        self.log_fetch(any_success or bool(ixp_data), round((time.time() - t0) * 1000),
                       last_status, total_ixps,
                       last_error if not any_success else "")
        result = {"ixp_data": ixp_data}
        self.set_cache(result)
        return result
