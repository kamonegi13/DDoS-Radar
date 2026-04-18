"""radar.sensors.base -- Abstract base sensor class."""
from __future__ import annotations
import datetime
import time
import threading
from abc import ABC, abstractmethod
from radar.scenarios import SensorTier


def _get_db():
    """Lazy import to avoid circular import at module load time."""
    from radar.database import db
    return db

class BaseSensor(ABC):
    # Circuit breaker defaults (can be overridden per-sensor via config)
    CB_FAILURE_THRESHOLD = 5    # Consecutive failures before opening
    CB_INITIAL_DELAY = 300      # 5 min initial recovery delay
    CB_MAX_DELAY = 3600         # 1 hour max recovery delay
    CB_STATES = ("CLOSED", "OPEN", "HALF_OPEN")

    tier: SensorTier = SensorTier.GLOBAL

    def __init__(self, name: str, domain: str, poll_interval: int):
        self.name = name
        self.domain = domain
        self.poll_interval = poll_interval
        self.enabled = True
        self._cache: dict = {}
        self._cache_time: float = 0.0
        self._last_error: str = ""
        self._lock = threading.Lock()
        self._fetch_log: list = []
        # Circuit breaker state
        self._cb_state: str = "CLOSED"
        self._cb_fail_count: int = 0
        self._cb_opened_at: float = 0.0
        self._cb_recovery_delay: float = self.CB_INITIAL_DELAY
    @abstractmethod
    def fetch(self, context: dict) -> dict: pass
    def get_cache(self) -> dict:
        with self._lock: return dict(self._cache)
    def set_cache(self, data: dict):
        with self._lock:
            self._cache = data; self._cache_time = time.time()
            last = self._fetch_log[-1] if self._fetch_log else {}
            if not last.get("_from_log_fetch"):
                rec_count = sum(len(v) for v in data.values() if isinstance(v, (list, dict)))
                self._fetch_log.append({"ts": datetime.datetime.now().isoformat(), "success": True, "duration_ms": None, "http_status": None, "records": rec_count, "error": ""})
                self._fetch_log = self._fetch_log[-10:]
    def set_error(self, error: str):
        with self._lock:
            self._last_error = error
            last = self._fetch_log[-1] if self._fetch_log else {}
            if not last.get("_from_log_fetch"):
                self._fetch_log.append({"ts": datetime.datetime.now().isoformat(), "success": False, "duration_ms": None, "http_status": None, "records": 0, "error": error[:300]})
                self._fetch_log = self._fetch_log[-10:]
    def log_fetch(self, success: bool, duration_ms: int = 0, http_status: int = 0, records: int = 0, error: str = ""):
        with self._lock:
            self._fetch_log.append({"ts": datetime.datetime.now().isoformat(), "success": success, "duration_ms": duration_ms, "http_status": http_status, "records": records, "error": error[:300] if error else "", "_from_log_fetch": True})
            self._fetch_log = self._fetch_log[-10:]
            # Sync health status: set _last_error on failure, clear on success
            # Partial success (success=True but error present) → keep error for display but mark as DEGRADED
            if not success:
                self._last_error = error[:300] if error else "fetch_failed"
            elif success and error:
                self._last_error = f"PARTIAL: {error[:280]}"
            else:
                self._last_error = ""
        # Persist to SQLite (non-critical; never break sensor on DB error)
        try:
            _get_db().fetch_log_append(self.name, time.time(), success, duration_ms, http_status, records, error[:300] if error else "")
        except Exception:
            pass
    def get_fetch_log(self) -> list:
        with self._lock: return [{k: v for k, v in e.items() if k != "_from_log_fetch"} for e in self._fetch_log]
    # ── Circuit Breaker ──────────────────────────────────────────────────────
    def cb_record_success(self):
        """Record a successful fetch — reset circuit breaker to CLOSED."""
        with self._lock:
            if self._cb_state != "CLOSED":
                import logging
                logging.getLogger("radar").info(
                    f"[CB/{self.name}] {self._cb_state} → CLOSED (recovered)")
            self._cb_state = "CLOSED"
            self._cb_fail_count = 0
            self._cb_recovery_delay = self.CB_INITIAL_DELAY

    def cb_record_failure(self):
        """Record a failed fetch — may open the circuit breaker."""
        with self._lock:
            self._cb_fail_count += 1
            if self._cb_state == "HALF_OPEN":
                # Probe failed — reopen with doubled delay
                self._cb_state = "OPEN"
                self._cb_opened_at = time.time()
                self._cb_recovery_delay = min(
                    self._cb_recovery_delay * 2, self.CB_MAX_DELAY)
                import logging
                logging.getLogger("radar").warning(
                    f"[CB/{self.name}] HALF_OPEN → OPEN (probe failed, "
                    f"next retry in {self._cb_recovery_delay:.0f}s)")
            elif (self._cb_state == "CLOSED"
                  and self._cb_fail_count >= self.CB_FAILURE_THRESHOLD):
                self._cb_state = "OPEN"
                self._cb_opened_at = time.time()
                import logging
                logging.getLogger("radar").warning(
                    f"[CB/{self.name}] CLOSED → OPEN after "
                    f"{self._cb_fail_count} consecutive failures, "
                    f"pausing for {self._cb_recovery_delay:.0f}s")

    def cb_should_skip(self) -> bool:
        """Return True if the scheduler should skip this fetch cycle.
        Side effect: transitions OPEN → HALF_OPEN when recovery delay has elapsed.
        Must be called exactly once per scheduler cycle.
        """
        with self._lock:
            if self._cb_state == "CLOSED":
                return False
            if self._cb_state == "OPEN":
                elapsed = time.time() - self._cb_opened_at
                if elapsed >= self._cb_recovery_delay:
                    # Transition to HALF_OPEN — allow one probe
                    self._cb_state = "HALF_OPEN"
                    import logging
                    logging.getLogger("radar").info(
                        f"[CB/{self.name}] OPEN → HALF_OPEN (probing)")
                    return False
                return True  # Still cooling down
            # HALF_OPEN: allow the single probe fetch
            return False

    @property
    def health(self) -> str:
        if not self.enabled: return "DISABLED"
        with self._lock:
            cb_state = self._cb_state
            last_error = self._last_error
            cache_time = self._cache_time
            has_cache = bool(self._cache)
        if cb_state == "OPEN": return "CIRCUIT_OPEN"
        if last_error:
            if last_error.startswith("PARTIAL:"): return "DEGRADED"
            return "ERROR"
        elapsed = time.time() - cache_time
        if elapsed > self.poll_interval * 3: return "STALE" if has_cache else "INITIALIZING"
        return "OK"
    def compute_confidence(self, sample_count: int = 0, baseline_samples: int = 0) -> float:
        """
        Compute sensor confidence factor (0.0–1.0).
        Combines health state, sample adequacy, and baseline coverage.
        When confidence is 1.0 (default), scoring is unchanged from legacy behavior.
        """
        from radar.config import CONFIDENCE_MIN_SAMPLES
        # Health factor: maps sensor health state to confidence
        health_factors = {"OK": 1.0, "DEGRADED": 0.8, "STALE": 0.5, "ERROR": 0.0, "CIRCUIT_OPEN": 0.0, "INITIALIZING": 0.1, "DISABLED": 0.0}
        health_f = health_factors.get(self.health, 0.0)
        if health_f == 0.0:
            return 0.0
        # Sample factor: ramp from 0.3 to 1.0 as samples reach CONFIDENCE_MIN_SAMPLES
        if CONFIDENCE_MIN_SAMPLES > 0 and sample_count < CONFIDENCE_MIN_SAMPLES:
            sample_f = 0.3 + 0.7 * (sample_count / CONFIDENCE_MIN_SAMPLES)
        else:
            sample_f = 1.0
        # Baseline factor: penalize when baseline data is insufficient
        if baseline_samples > 0 and baseline_samples < CONFIDENCE_MIN_SAMPLES:
            baseline_f = 0.5 + 0.5 * (baseline_samples / CONFIDENCE_MIN_SAMPLES)
        else:
            baseline_f = 1.0
        return round(min(health_f * sample_f * baseline_f, 1.0), 3)

    def handle_rate_limit(self, response, duration_ms: int = 0) -> bool:
        """Check if response is 429 and log appropriately. Returns True if rate-limited.

        Usage in sensor fetch():
            res = requests.get(...)
            if self.handle_rate_limit(res, duration_ms):
                return self.get_cache() or default_result
        """
        if response.status_code != 429:
            return False
        retry_after = response.headers.get("Retry-After", "60")
        import logging
        logging.getLogger("radar").warning(
            f"[{self.name}] Rate limited (429). Retry-After: {retry_after}s"
        )
        cached = self.get_cache()
        if cached:
            self.log_fetch(True, duration_ms, 429, 0,
                           f"rate_limited(429), using cache. Retry-After={retry_after}s")
        else:
            self.log_fetch(False, duration_ms, 429, 0,
                           f"rate_limited(429), no cache. Retry-After={retry_after}s")
        return True

    # Default timeout for external API calls (connect, read) in seconds.
    # Prevents a single hung connection from blocking the gevent event loop.
    _DEFAULT_TIMEOUT = (10, 20)  # (connect_timeout, read_timeout)

    def _safe_get(self, url: str, **kwargs):
        """requests.get wrapper with automatic 429 handling.

        Returns response object, or None if rate-limited (cache/log handled internally).
        Callers should check: if res is None: return self.get_cache() or default
        """
        import requests as _requests
        kwargs.setdefault("timeout", self._DEFAULT_TIMEOUT)
        duration = kwargs.pop("_duration_ms", 0)
        res = _requests.get(url, **kwargs)
        if res.status_code == 429:
            self.handle_rate_limit(res, duration)
            return None
        return res

    def _safe_post(self, url: str, **kwargs):
        """requests.post wrapper with automatic 429 handling."""
        import requests as _requests
        kwargs.setdefault("timeout", self._DEFAULT_TIMEOUT)
        duration = kwargs.pop("_duration_ms", 0)
        res = _requests.post(url, **kwargs)
        if res.status_code == 429:
            self.handle_rate_limit(res, duration)
            return None
        return res

    def to_config_dict(self) -> dict:
        h = self.health
        with self._lock:
            last_error = self._last_error
            cache_time = self._cache_time
            cb_state = self._cb_state
            cb_fail_count = self._cb_fail_count
        return {
            "name": self.name, "domain": self.domain, "enabled": self.enabled,
            "health": h, "poll_interval_sec": self.poll_interval,
            "last_error": last_error,
            "cache_age_sec": round(time.time() - cache_time) if cache_time else None,
            "last_fetch_ts": cache_time or None,
            "cb_state": cb_state,
            "cb_fail_count": cb_fail_count,
        }
