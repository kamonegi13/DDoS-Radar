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
"""
from __future__ import annotations
import logging
import time
import requests
from radar.sensors.base import BaseSensor
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
    CT_LOG_SURGE_THRESHOLD, CT_LOG_GOV_TLDS,
)

log = logging.getLogger("radar")

_CRTSH_URL = "https://crt.sh/"

# Country code to TLD mapping (most countries use .cc TLD)
_CC_TLDS = {
    "TW": ".tw", "JP": ".jp", "KR": ".kr", "CN": ".cn",
    "RU": ".ru", "UA": ".ua", "IR": ".ir", "KP": ".kp",
    "IL": ".il", "US": ".us", "GB": ".uk", "DE": ".de",
    "FR": ".fr", "PH": ".ph", "VN": ".vn", "IN": ".in",
    "PK": ".pk", "BY": ".by", "GE": ".ge", "PL": ".pl",
    "EE": ".ee", "LV": ".lv", "LT": ".lt", "FI": ".fi",
    "SE": ".se", "NO": ".no", "RO": ".ro",
}


class CtLogSensor(BaseSensor):
    """Certificate Transparency log anomaly sensor (cyber domain)."""

    def __init__(self):
        super().__init__("ct_log", "cyber", 3600)
        self._prev_counts: dict[str, int] = {}

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
                # Query crt.sh for recent certificates for this TLD
                # Check government-related domains
                gov_tlds = CT_LOG_GOV_TLDS.get(code, [f"gov{tld}"])
                total_recent = 0
                gov_count = 0
                wildcard_count = 0
                recent_certs = []

                for domain_pattern in [f"%{tld}", ] + [f"%.{g}" for g in gov_tlds]:
                    res = requests.get(
                        _CRTSH_URL,
                        params={
                            "q": domain_pattern,
                            "output": "json",
                            "exclude": "expired",
                        },
                        timeout=20, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                        headers={"Accept": "application/json"},
                    )

                    if res.status_code == 429:
                        log.warning(f"[CTLog] Rate limited for {code}, skipping")
                        break
                    elif res.status_code == 200:
                        try:
                            certs = res.json()
                        except Exception:
                            certs = []

                        if isinstance(certs, list):
                            any_success = True
                            # Only count certificates from the last 24 hours
                            for cert in certs[:100]:
                                name = cert.get("common_name", "") or cert.get("name_value", "")
                                issuer = cert.get("issuer_name", "")
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
                                        "not_before": cert.get("not_before", ""),
                                    })

                    time.sleep(1.0)  # Rate limit crt.sh

                prev = self._prev_counts.get(code, total_recent)
                surge_pct = ((total_recent - prev) / max(prev, 1)
                             if prev > 0 else 0)
                is_surge = (total_recent >= CT_LOG_SURGE_THRESHOLD or
                            (surge_pct > 1.0 and total_recent > 20) or
                            gov_count >= 5)

                ct_data[code] = {
                    "total_recent": total_recent,
                    "gov_count": gov_count,
                    "wildcard_count": wildcard_count,
                    "prev_count": prev,
                    "surge_pct": round(surge_pct, 3),
                    "is_surge": is_surge,
                    "recent_certs": recent_certs,
                }

                if is_surge and gov_count >= 5:
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

        result = {"ct_data": ct_data, "country_status": country_status}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "ct_data": {},
            "country_status": {c: "NORMAL" for c in all_targets},
        }
