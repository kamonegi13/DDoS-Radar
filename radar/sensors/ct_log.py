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
    """Certificate Transparency log anomaly sensor (cyber domain).

    Redesigned thresholds: uses Z-score relative to per-country rolling
    baseline instead of a fixed absolute threshold (CT_LOG_SURGE_THRESHOLD).
    This reduces false positives from Let's Encrypt automated renewals
    and adapts to each country's normal certificate volume.
    """

    # Minimum history entries before Z-score is valid
    _MIN_HISTORY = 4

    def __init__(self):
        super().__init__("ct_log", "cyber", 3600)
        self._prev_counts: dict[str, int] = {}
        # Rolling history for Z-score computation: country -> [count, ...]
        self._count_history: dict[str, list[int]] = {}

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

                for domain_pattern in [f"%.{g}" for g in gov_tlds]:
                    try:
                        res = requests.get(
                            _CRTSH_URL,
                            params={
                                "q": domain_pattern,
                                "output": "json",
                                "exclude": "expired",
                            },
                            timeout=30, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                            headers={"Accept": "application/json"},
                        )
                    except requests.exceptions.Timeout:
                        log.warning(f"[CTLog] Timeout for {code} ({domain_pattern})")
                        continue
                    except requests.exceptions.ConnectionError:
                        log.warning(f"[CTLog] Connection error for {code}")
                        continue

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

                    time.sleep(1.5)  # Rate limit crt.sh (slightly longer gap)

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
                    not z_valid and (total_recent >= CT_LOG_SURGE_THRESHOLD or
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

        result = {"ct_data": ct_data, "country_status": country_status}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "ct_data": {},
            "country_status": {c: "NORMAL" for c in all_targets},
        }
