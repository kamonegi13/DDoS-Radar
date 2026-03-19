"""radar.sensors.opensky_auth -- OpenSky OAuth2 token cache and shared rate limiter."""
from __future__ import annotations
import time
import threading
import logging
import requests
from radar.config import (
    OPENSKY_CLIENT_ID, OPENSKY_CLIENT_SECRET, OPENSKY_TOKEN_URL,
    GLOBAL_PROXIES, SSL_VERIFY, OPENSKY_MIN_INTERVAL,
)

log = logging.getLogger("radar")

_opensky_oauth_token: dict = {"access_token": "", "expires_at": 0.0}
_opensky_oauth_lock         = threading.Lock()
if not OPENSKY_CLIENT_ID:
    log.warning("[OpenSky] OPENSKY_CLIENT_ID not set — running in anonymous mode (400 req/day limit)")

def _get_opensky_bearer() -> str:
    """Fetch and cache Bearer token via OAuth2 Client Credentials flow.
    Auto-refreshes 5 minutes before expiry. Returns empty string if credentials not set (anonymous access)."""
    global _opensky_oauth_token
    if not OPENSKY_CLIENT_ID:
        return ""
    with _opensky_oauth_lock:
        if time.time() < _opensky_oauth_token["expires_at"] - 300:
            return _opensky_oauth_token["access_token"]
        try:
            res = requests.post(
                OPENSKY_TOKEN_URL,
                data={"grant_type": "client_credentials",
                      "client_id": OPENSKY_CLIENT_ID,
                      "client_secret": OPENSKY_CLIENT_SECRET},
                timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if res.status_code == 200:
                td = res.json()
                _opensky_oauth_token["access_token"] = td.get("access_token", "")
                _opensky_oauth_token["expires_at"]   = time.time() + td.get("expires_in", 1800)
                log.info(f"[OpenSky OAuth2] Token acquired, expires_in={td.get('expires_in')}s")
                return _opensky_oauth_token["access_token"]
            log.warning(f"[OpenSky OAuth2] Token fetch failed: HTTP {res.status_code} — {res.text[:200]}")
        except Exception as e:
            log.error(f"[OpenSky OAuth2] Token fetch error: {e}")
        return ""

# ─────────────────────────────────────────────────────────────────────────────
# Shared OpenSky API rate limiter
# Module-level sharing since OpenSkySensor and IsrHotspotSensor both hit the same API.
# ─────────────────────────────────────────────────────────────────────────────
_opensky_lock          = threading.Lock()
_opensky_last_req_time = 0.0

def _opensky_get(params: dict, timeout: int = 12) -> requests.Response:
    """Shared OpenSky API request function for both sensors (rate limiter + OAuth2 built-in).
    On 429, respects Retry-After header and retries once."""
    global _opensky_last_req_time

    def _do_request() -> requests.Response:
        headers = {}
        token = _get_opensky_bearer()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return requests.get(
            "https://opensky-network.org/api/states/all",
            params=params, timeout=timeout,
            headers=headers, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
        )

    with _opensky_lock:
        elapsed = time.time() - _opensky_last_req_time
        if elapsed < OPENSKY_MIN_INTERVAL:
            time.sleep(OPENSKY_MIN_INTERVAL - elapsed)
        _opensky_last_req_time = time.time()
        res = _do_request()

    # Handle 429 outside the lock to avoid holding it during long sleeps
    if res.status_code == 429:
        retry_after = int(res.headers.get("X-Rate-Limit-Retry-After-Seconds", 60))
        auth_status = 'yes' if _opensky_oauth_token.get('access_token') else 'no'
        log.warning(f"[OpenSky] 429 rate-limited, Retry-After={retry_after}s (auth={auth_status})")
        if retry_after <= 120:
            # Only retry short waits. Return 429 as-is for long waits (anonymous quota exceeded)
            time.sleep(retry_after)
            with _opensky_lock:
                _opensky_last_req_time = time.time()
                res = _do_request()

    return res
