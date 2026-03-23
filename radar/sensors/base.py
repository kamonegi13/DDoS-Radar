"""radar.sensors.base -- Abstract base sensor class."""
from __future__ import annotations
import datetime
import time
import threading
from abc import ABC, abstractmethod


def _get_db():
    """Lazy import to avoid circular import at module load time."""
    from radar.database import db
    return db

class BaseSensor(ABC):
    def __init__(self, name: str, domain: str, poll_interval: int):
        self.name = name; self.domain = domain; self.poll_interval = poll_interval; self.enabled = True
        self._cache: dict = {}; self._cache_time: float = 0.0; self._last_error: str = ""
        self._lock = threading.Lock(); self._fetch_log: list = []
    @abstractmethod
    def fetch(self, context: dict) -> dict: pass
    def get_cache(self) -> dict:
        with self._lock: return dict(self._cache)
    def set_cache(self, data: dict):
        with self._lock:
            self._cache = data; self._cache_time = time.time(); self._last_error = ""
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
            if not success and error:
                self._last_error = error[:300]
            elif success:
                self._last_error = ""
        # Persist to SQLite (non-critical; never break sensor on DB error)
        try:
            _get_db().fetch_log_append(self.name, time.time(), success, duration_ms, http_status, records, error[:300] if error else "")
        except Exception:
            pass
    def get_fetch_log(self) -> list:
        with self._lock: return [{k: v for k, v in e.items() if k != "_from_log_fetch"} for e in self._fetch_log]
    @property
    def health(self) -> str:
        if not self.enabled: return "DISABLED"
        if self._last_error: return "ERROR"
        elapsed = time.time() - self._cache_time
        if elapsed > self.poll_interval * 3: return "STALE" if self._cache else "INITIALIZING"
        return "OK"
    def compute_confidence(self, sample_count: int = 0, baseline_samples: int = 0) -> float:
        """
        Compute sensor confidence factor (0.0–1.0).
        Combines health state, sample adequacy, and baseline coverage.
        When confidence is 1.0 (default), scoring is unchanged from legacy behavior.
        """
        from radar.config import CONFIDENCE_MIN_SAMPLES
        # Health factor: maps sensor health state to confidence
        health_factors = {"OK": 1.0, "STALE": 0.5, "ERROR": 0.0, "INITIALIZING": 0.1, "DISABLED": 0.0}
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

    def to_config_dict(self) -> dict:
        return {"name": self.name, "domain": self.domain, "enabled": self.enabled, "health": self.health, "poll_interval_sec": self.poll_interval, "last_error": self._last_error, "cache_age_sec": round(time.time() - self._cache_time) if self._cache_time else None}
