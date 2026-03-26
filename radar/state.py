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
