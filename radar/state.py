"""radar.state -- In-memory transient runtime state.

Only fast-changing transient caches remain here.
All persistent state has been migrated to SQLite (radar.database).
"""
from __future__ import annotations
import threading

# ── Transient API response cache (replaced every scoring cycle) ──
global_cache      = {"time": 0, "data": {}, "strategic": {}}
_global_cache_lock = threading.Lock()

# ── Constants ──
ALERT_TIMELINE_MAX = 288
SEQUENCE_EVENT_TYPES = ["NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY", "AIS_DARK_GAP",
                        "TELEGRAM_INTENT", "MASKIROVKA", "C2_SYNC", "INFRA_BLACKOUT"]  # v9

# ── Short-lived scoring cache (NOT persisted) ──
# Key: (url, frozenset(params.items())) → {"time": float, "data": list}
_cf_scoring_cache: dict = {}
_cf_cache_lock = threading.Lock()  # Protects _cf_scoring_cache across threads

# ── Active analyst focus registry (scenario-refactor §8.1, P0-3) ──
# Maps scenario_id → last-touched epoch seconds. Each /api/threat_data call
# registers the requested focus. The scheduler reads this registry so per-
# country FOCUSED_ONLY sensors fetch the union of recently-active focuses,
# not just DEFAULT_FOCUSED_SCENARIO. TTL-bounded to avoid unbounded growth.
_active_focus: dict[str, float] = {}
_active_focus_lock = threading.Lock()
# How long after the last /api/threat_data touch we keep fetching for a focus
ACTIVE_FOCUS_TTL_SEC = 1800  # 30 minutes
# Safety cap on concurrent active focuses so a stream of stale switches
# cannot blow up the scheduler fetch budget.
ACTIVE_FOCUS_MAX = 4


def touch_active_focus(scenario_id: str) -> None:
    """Register an analyst focus; called by /api/threat_data per request."""
    if not scenario_id:
        return
    import time as _t
    with _active_focus_lock:
        _active_focus[scenario_id] = _t.time()
        # Bound the set: drop the oldest if we exceed the cap
        if len(_active_focus) > ACTIVE_FOCUS_MAX:
            oldest = sorted(_active_focus.items(), key=lambda kv: kv[1])
            for sid, _ in oldest[: len(_active_focus) - ACTIVE_FOCUS_MAX]:
                _active_focus.pop(sid, None)


def get_active_focus_ids() -> list[str]:
    """Return scenario IDs touched within ACTIVE_FOCUS_TTL_SEC, freshest first."""
    import time as _t
    cutoff = _t.time() - ACTIVE_FOCUS_TTL_SEC
    with _active_focus_lock:
        fresh = [(sid, ts) for sid, ts in _active_focus.items() if ts >= cutoff]
        # Prune stale entries opportunistically
        for sid, ts in list(_active_focus.items()):
            if ts < cutoff:
                _active_focus.pop(sid, None)
    fresh.sort(key=lambda kv: kv[1], reverse=True)
    return [sid for sid, _ in fresh]
