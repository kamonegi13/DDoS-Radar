"""radar.state -- Mutable global runtime state.

All shared mutable state lives here so that any module can import it
without circular dependencies.
"""
from __future__ import annotations
import threading
from collections import deque

global_cache      = {"time": 0, "data": {}, "strategic": {}}
_global_cache_lock = threading.Lock()   # Thread safety for full global_cache replacement
baseline_cache:    dict = {}
time_series_db:    dict = {}   # {theater: [float,...]}  ← backward compat: values only
time_series_ts_db: dict = {}   # {theater: [(ts, val),...]} ← with timestamps
time_series_l3_db: dict = {}
time_series_l7_db: dict = {}
airspace_baseline: dict = {}
# HOD (Hour-of-Day) baseline: {theater: [(hour_bucket_ts, avg_spike), ...]}
# Stores one entry per UTC hour per theater for up to 28 days (672 entries).
# Used to normalize CF spike scores against same-hour historical distribution,
# eliminating the diurnal bias where daytime attack patterns inflate spike ratios
# when compared against a flat day+night average baseline.
hod_baseline_db:   dict = {}
# Check-Host HOD: {theater: [(hour_bucket_ts, success_rate), ...]}
checkhost_hod_db:  dict = {}
# RIPE BGP HOD: {theater: {hod_h: [prefix_count, ...]}}, max HOD_MIN_SAME_HOUR*4 per slot
bgp_hod_db:        dict = {}
# GDELT DoW: {theater: {weekday(0-6): {"tone": float, "ts": float}}}
gdelt_dow_db:      dict = {}
threat_history:    deque = deque(maxlen=20)
alert_timeline:    deque = deque(maxlen=288)
ALERT_TIMELINE_MAX = 288  # Must match deque maxlen

# Event log for sequence scorer
# {theater: [{"ts": float, "type": str, "meta": dict}, ...]}
sequence_event_log: dict = {}
SEQUENCE_EVENT_TYPES = ["NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY", "AIS_DARK_GAP",
                        "TELEGRAM_INTENT", "MASKIROVKA", "C2_SYNC", "INFRA_BLACKOUT"]  # v9

# CF scoring-loop result cache (short-term cache for scoring, independent of sensor fetch)
# Key: (url, frozenset(params.items())) → {"time": float, "data": list}
_cf_scoring_cache: dict = {}
