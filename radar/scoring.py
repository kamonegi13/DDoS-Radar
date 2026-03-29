"""radar.scoring -- Sequence scorer, HOD Z-score, CF helpers, misc scoring functions,
   and Context-Aware Convergence (CAC) direction classification."""
from __future__ import annotations
import hashlib
import logging
import requests
import threading
import time
import os as _os
from radar.config import (
    CF_HEADERS, GLOBAL_PROXIES, SSL_VERIFY, CURRENT_DATE_RANGE,
    BASELINE_DATE_RANGE, CACHE_EXPIRY,
    HOD_BASELINE_DAYS, HOD_MIN_SAME_HOUR, HOD_MAX_ENTRIES,
    DEFAULT_CORE, DEFAULT_CORRELATES, DEFAULT_ADVERSARIES, DEFAULT_PINS,
    ADAPTIVE_ZSCORE_ENABLED, ADAPTIVE_ZSCORE_MIN_SAMPLES, ADAPTIVE_ZSCORE_SENSITIVITY,
    STATE_ASNS, COUNTRY_COORDS, CHOKEPOINTS,
)
from radar.models import (
    DIRECTION_ADVERSARY_OFFENSIVE, DIRECTION_FRIENDLY_DEFENSIVE,
    DIRECTION_TARGET_IMPACT, DIRECTION_UNKNOWN,
)
from radar.state import _cf_scoring_cache, _cf_cache_lock
from radar.database import db as _db

log = logging.getLogger("radar")

def register_sequence_event(theater: str, event_type: str, meta: dict = None,
                            dedup_window: int = 300):
    """Register an event in the escalation chain log.

    dedup_window: seconds within which duplicate event_type entries are suppressed
        (default 300 s = 5 min).  Prevents double-counting when multiple sensors
        (e.g. RSS + Telegram) fire the same event type in the same scoring cycle.
    """
    now = time.time()
    # Dedup: skip if the same event type was registered within the dedup window
    dedup_cutoff = now - dedup_window
    if _db.seq_exists_since(theater, event_type, dedup_cutoff):
        return
    _db.seq_append(theater, now, event_type, meta or {})
    # Remove entries older than 24h
    cutoff = now - int(_os.getenv("SEQUENCE_WINDOW", "86400"))
    _db.seq_cleanup(cutoff)

def compute_sequence_bonus(theater: str) -> tuple:
    """
    Validate the escalation chain within a 24h window and return bonus score and status string.
    Chain order (loose co-existence mode): all event types must exist within SEQUENCE_WINDOW.
    Strict ordering is not required, but temporal direction is verified (first event precedes last).
    Temporal decay: events are weighted by recency — weight = max(0.3, 1.0 - age_hours/24).
    The raw bonus is multiplied by the average weight of chain events.
    Returns: (bonus: int, chain_status: str, events_found: list)
    """
    now = time.time()
    cutoff = now - int(_os.getenv("SEQUENCE_WINDOW", "86400"))
    events = _db.seq_events_since(theater, cutoff)
    if not events:
        return 0, "NO_EVENTS", []

    # Chain definition order (loose co-existence: existence check only)
    chain_def = ["NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY"]
    found_types = {e["type"] for e in events}
    found_in_chain = [t for t in chain_def if t in found_types]
    found_count = len(found_in_chain)

    # Temporal direction check: first event must precede last (sanity check)
    if len(events) >= 2:
        earliest = min(e["ts"] for e in events)
        latest_ts = max(e["ts"] for e in events)
        timespan_h = round((latest_ts - earliest) / 3600, 1)
    else:
        timespan_h = 0.0

    # Temporal decay: weight each chain event by recency
    # Use the most recent event of each type for decay calculation
    chain_weights = []
    for ctype in found_in_chain:
        type_events = [e for e in events if e["type"] == ctype]
        most_recent = max(e["ts"] for e in type_events)
        age_hours = (now - most_recent) / 3600.0
        weight = max(0.3, 1.0 - age_hours / 24.0)
        chain_weights.append(weight)
    avg_weight = sum(chain_weights) / len(chain_weights) if chain_weights else 1.0

    if found_count == 4:
        raw_bonus = int(_os.getenv("SEQUENCE_FULL_BONUS", "3"))
        decayed_bonus = round(raw_bonus * avg_weight)
        return max(1, decayed_bonus), f"FULL_CHAIN_CONFIRMED [{timespan_h}h span, decay={avg_weight:.2f}]", found_in_chain
    elif found_count >= 3:
        raw_bonus = int(_os.getenv("SEQUENCE_PARTIAL_BONUS", "1"))
        decayed_bonus = round(raw_bonus * avg_weight)
        return max(1, decayed_bonus), f"PARTIAL_CHAIN ({found_count}/4, decay={avg_weight:.2f}): {found_in_chain}", found_in_chain
    else:
        return 0, f"INSUFFICIENT_CHAIN ({found_count}/4)", found_in_chain

_HOD_PREFILL_L3_URL  = "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin"
_HOD_PREFILL_L7_URL  = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin"
_HOD_PREFILL_TS_URL  = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/timeseries"
_HOD_PREFILL_L3_TS_URL = "https://api.cloudflare.com/client/v4/radar/attacks/layer3/timeseries"


def _fetch_cf_timeseries_hourly(theater: str, days: int) -> dict:
    """Fetch hourly L3+L7 combined attack timeseries for a theater.

    Fetches both L3 and L7 timeseries and merges them (max of each hour bucket).
    Falls back to L7-only, then global timeseries.
    Returns {unix_hour_bucket: normalized_value}, empty dict on total failure."""
    from datetime import datetime

    def _parse_ts_response(res) -> dict:
        if res.status_code != 200:
            return {}
        result = res.json().get("result", {})
        # CF Radar timeseries may store data directly in result OR nested under
        # "serie_0", "serie_1" etc. Try both layouts.
        if "timestamps" in result:
            timestamps = result["timestamps"]
            values     = result.get("values", [])
        else:
            serie = next((v for k, v in result.items()
                          if k.startswith("serie_") and isinstance(v, dict)), {})
            timestamps = serie.get("timestamps", [])
            values     = serie.get("values", [])
        if not timestamps or not values:
            return {}
        out: dict = {}
        for ts_str, v_str in zip(timestamps, values):
            try:
                dt  = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                bkt = int(dt.timestamp() // 3600) * 3600
                out[bkt] = float(v_str)
            except (ValueError, TypeError):
                pass
        return out

    base_params = {"dateRange": f"{days}d", "aggInterval": "1h", "format": "json"}
    try:
        # Fetch L7 timeseries (theater-specific, then global fallback)
        l7_out = _fetch_single_ts(_HOD_PREFILL_TS_URL, base_params, theater)

        # Fetch L3 timeseries (non-critical; merge with L7 if available)
        l3_out = _fetch_single_ts(_HOD_PREFILL_L3_TS_URL, base_params, theater)

        # Merge: take max(L3, L7) per hour bucket for combined attack intensity
        if l7_out and l3_out:
            all_keys = set(l7_out) | set(l3_out)
            return {k: max(l7_out.get(k, 0), l3_out.get(k, 0)) for k in all_keys}
        return l7_out or l3_out or {}
    except Exception as e:
        log.warning(f"[HOD TS] {theater}: fetch error — {e}")
        return {}


def _fetch_single_ts(url: str, base_params: dict, theater: str) -> dict:
    """Fetch a single CF Radar timeseries (L3 or L7) for a theater."""
    from datetime import datetime

    def _parse_ts_response(res) -> dict:
        if res.status_code != 200:
            return {}
        result = res.json().get("result", {})
        if "timestamps" in result:
            timestamps = result["timestamps"]
            values     = result.get("values", [])
        else:
            serie = next((v for k, v in result.items()
                          if k.startswith("serie_") and isinstance(v, dict)), {})
            timestamps = serie.get("timestamps", [])
            values     = serie.get("values", [])
        if not timestamps or not values:
            return {}
        out: dict = {}
        for ts_str, v_str in zip(timestamps, values):
            try:
                dt  = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                bkt = int(dt.timestamp() // 3600) * 3600
                out[bkt] = float(v_str)
            except (ValueError, TypeError):
                pass
        return out

    try:
        # Attempt 1: theater-specific
        res = requests.get(url, headers=CF_HEADERS,
                           params={**base_params, "location": theater},
                           timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
        out = _parse_ts_response(res)
        if out:
            return out
        # Attempt 2: global fallback
        res = requests.get(url, headers=CF_HEADERS,
                           params=base_params,
                           timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
        return _parse_ts_response(res)
    except Exception as e:
        log.warning(f"[HOD TS] {theater}: {url.split('/')[-1]} fetch error — {e}")
        return {}


def compute_avg_spike_raw(o_l3: dict, o_l7: dict, b_data: dict, adversary_codes: list) -> float:
    """Compute avg_spike from pre-fetched origin distribution dicts.
    Mirrors the spike computation in the main scoring loop, without map/display side-effects."""
    _bl3 = b_data.get("l3", {})
    _bl7 = b_data.get("l7", {})
    if not (_bl3 or _bl7):
        return 0.0
    target_weighted_spike = 0.0
    total_local_pct = 0.0
    for code in set(o_l3) | set(o_l7):
        local_l3_pct   = o_l3.get(code, 0.0)
        local_l7_pct   = o_l7.get(code, 0.0)
        current_local_pct = max(local_l3_pct, local_l7_pct)
        if current_local_pct < 1.0:
            continue
        is_adv       = code in adversary_codes
        _floor_new   = 0.5 if is_adv else 3.0
        _floor_exist = 0.5 if is_adv else 2.0
        base_l3 = max(_bl3.get(code, _floor_new), _floor_new if code not in _bl3 else _floor_exist)
        base_l7 = max(_bl7.get(code, _floor_new), _floor_new if code not in _bl7 else _floor_exist)
        l3_spike     = (local_l3_pct / base_l3) if local_l3_pct > 0 else 0.0
        l7_spike     = (local_l7_pct / base_l7) if local_l7_pct > 0 else 0.0
        spike_factor = min(max(l3_spike, l7_spike), 25.0)
        target_weighted_spike += spike_factor * current_local_pct
        total_local_pct       += current_local_pct
    return round(target_weighted_spike / max(total_local_pct, 5.0), 2)


def prefill_hod_baseline_bg(theaters: list, adversary_codes: list) -> None:
    """Background thread: populate HOD baseline for ALL 24 UTC hour slots using
    past HOD_BASELINE_DAYS daily (24h) windows from the CF Radar API.

    Strategy: fetch ONE 24h API call per past day per theater, then record the
    resulting avg_spike for ALL 24 HOD slots of that day. This means:
      - API calls: 28 days × 2 (L3+L7) per theater  (~7 s per theater)
      - Coverage: all 24 HOD slots filled immediately at startup
      - No warmup regardless of which UTC hour the server starts or restarts in

    Trade-off: all hours of the same day share the same daily avg_spike value
    (no intra-day resolution), but inter-day trend changes are fully captured.
    True per-hour resolution accumulates naturally as the server runs (one real
    sample per UTC hour per scoring cycle).

    Slots that already have ≥ HOD_MIN_SAME_HOUR samples are skipped.
    Rate-limited to ~4 req-pairs/s (0.25 s sleep) to stay within CF Radar free tier."""
    from datetime import datetime, timezone

    # Ensure baseline_cache is populated for each theater.
    _BL_L3_URL = "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin"
    _BL_L7_URL = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin"
    for t in theaters:
        _bc = _db.baseline_get(t)
        if _bc.get("l3") or _bc.get("l7"):
            continue
        log.info(f"[HOD Prefill] Fetching 28d baseline for {t} ...")
        _bl3 = parse_origins(fetch_cf_data(_BL_L3_URL, {"location": t, "dateRange": BASELINE_DATE_RANGE, "format": "json"}))
        _bl7 = parse_origins(fetch_cf_data(_BL_L7_URL, {"location": t, "dateRange": BASELINE_DATE_RANGE, "format": "json"}))
        if _bl3 or _bl7:
            _db.baseline_set(t, {"l3": _bl3, "l7": _bl7}, time.time())
        else:
            log.warning(f"[HOD Prefill] {t}: baseline fetch failed, skipping theater.")

    log.info(f"[HOD Prefill] Starting — theaters={theaters}, days={HOD_BASELINE_DAYS}, all 24h slots")

    total_filled = total_skipped = total_errors = 0

    for theater in theaters:
        b_data = _db.baseline_get(theater)
        if not (b_data.get("l3") or b_data.get("l7")):
            log.warning(f"[HOD Prefill] {theater}: no baseline available, skipping.")
            continue

        filled = day_errors = 0
        now_day = int(time.time() // 86400)

        # ── Step 1: fetch hourly timeseries for the full 28d window (1 API call) ──
        # Provides per-hour attack intensity — used to scale the daily avg_spike
        # so each of the 24 HOD slots gets a realistic hourly estimate rather than
        # the flat daily average.
        ts_by_bucket = _fetch_cf_timeseries_hourly(theater, HOD_BASELINE_DAYS)
        has_ts = bool(ts_by_bucket)
        if has_ts:
            log.info(f"[HOD Prefill] {theater}: timeseries OK ({len(ts_by_bucket)} hourly pts)")
        else:
            log.info(f"[HOD Prefill] {theater}: timeseries unavailable — using flat daily avg")

        # ── Step 2: for each past day, fetch the daily origin distribution ──
        for day_offset in range(1, HOD_BASELINE_DAYS + 1):
            target_day_start = (now_day - day_offset) * 86400

            existing_buckets = _db.hod_existing_buckets("hod_baseline", theater)
            slots_needed = [h for h in range(24)
                            if (target_day_start + h * 3600) not in existing_buckets]
            if not slots_needed:
                total_skipped += 24
                continue

            # Fetch ONE 24h window for this day to get the origin distribution
            date_start = datetime.fromtimestamp(target_day_start,         tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            date_end   = datetime.fromtimestamp(target_day_start + 86400, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            params     = {"location": theater, "dateStart": date_start, "dateEnd": date_end, "format": "json"}

            o_l3 = parse_origins(fetch_cf_data(_HOD_PREFILL_L3_URL, params))
            o_l7 = parse_origins(fetch_cf_data(_HOD_PREFILL_L7_URL, params))

            if not o_l3 and not o_l7:
                day_errors += 1
                time.sleep(0.25)
                continue

            daily_avg_spike = compute_avg_spike_raw(o_l3, o_l7, b_data, adversary_codes)

            # Compute this day's average timeseries value (for scaling)
            if has_ts:
                day_ts_vals = [ts_by_bucket[target_day_start + h * 3600]
                               for h in range(24)
                               if (target_day_start + h * 3600) in ts_by_bucket]
                day_ts_avg = sum(day_ts_vals) / len(day_ts_vals) if day_ts_vals else None
            else:
                day_ts_avg = None

            # Record per-hour estimates for each needed slot
            for hour in slots_needed:
                hour_bkt = target_day_start + hour * 3600
                if has_ts and day_ts_avg and day_ts_avg > 0:
                    hour_val = ts_by_bucket.get(hour_bkt)
                    if hour_val is not None:
                        # Scale: daily_avg_spike × (this_hour / day_avg)
                        hour_spike = daily_avg_spike * (hour_val / day_ts_avg)
                    else:
                        hour_spike = daily_avg_spike  # no TS data for this slot
                else:
                    hour_spike = daily_avg_spike      # fallback: flat daily avg

                record_hod_sample(theater, hour_bkt + 1800, max(0.0, hour_spike))
                filled += 1

            time.sleep(0.25)   # ~4 req-pairs/s

        slots_covered = _db.hod_distinct_hours("hod_baseline", theater)
        log.info(f"[HOD Prefill] {theater}: filled={filled}, day_errors={day_errors}, "
              f"hod_slots_covered={slots_covered}/24")
        total_filled  += filled
        total_errors  += day_errors

    total_pts = _db.hod_total_points("hod_baseline")
    log.info(f"[HOD Prefill] Complete — filled={total_filled}, skipped={total_skipped}, "
          f"errors={total_errors}, total_hod_pts={total_pts}")


def record_hod_sample(theater: str, ts: float, avg_spike: float) -> None:
    """Record one HOD (Hour-of-Day) sample per UTC hour per theater.
    Deduplicates by hour bucket so multiple scoring cycles within the same
    UTC hour do not create redundant entries."""
    hour_bucket = int(ts // 3600) * 3600   # floor to UTC hour boundary
    _last = _db.hod_last_bucket("hod_baseline", theater)
    if _last != hour_bucket:
        _db.hod_record("hod_baseline", theater, hour_bucket, avg_spike,
                        max_entries=HOD_MAX_ENTRIES)


def compute_hod_zscore(theater: str, current_spike: float, current_ts: float) -> tuple:
    """Compute Z-score of current_spike against same-UTC-hour historical distribution.

    Returns:
        (z_score: float, is_valid: bool, same_hour_n: int)
    is_valid=False when fewer than HOD_MIN_SAME_HOUR same-hour samples exist;
    caller should fall back to raw-ratio spike scoring during warmup.
    """
    current_hour_bucket = int(current_ts // 3600) * 3600
    current_hod         = (current_hour_bucket // 3600) % 24   # 0–23 UTC

    same_hour_spikes = _db.hod_same_hour("hod_baseline", theater,
                                         current_hod, current_hour_bucket)
    n = len(same_hour_spikes)
    if n < HOD_MIN_SAME_HOUR:
        return 0.0, False, n

    mean = sum(same_hour_spikes) / n
    variance = sum((x - mean) ** 2 for x in same_hour_spikes) / n
    std = variance ** 0.5

    # Guard against near-zero std (extremely stable baseline at this hour).
    # Use a minimum std floor of 0.15 to keep the Z-score meaningful.
    std = max(std, 0.15)
    return (current_spike - mean) / std, True, n



def compute_adaptive_zscore(sensor_name: str, theater: str,
                            current_value: float,
                            fallback_threshold: float = 2.0) -> tuple:
    """Compute Z-score using per-sensor/per-theater running statistics (Welford).

    Returns: (z_score, is_adaptive, threshold, sample_count)
    - is_adaptive=True: enough samples for adaptive threshold
    - is_adaptive=False: using fallback_threshold (warmup period)
    """
    if not ADAPTIVE_ZSCORE_ENABLED:
        return 0.0, False, fallback_threshold, 0

    stats = _db.zscore_stats_get(sensor_name, theater)
    # Always update running stats with the new value
    _db.zscore_stats_update(sensor_name, theater, current_value)

    if not stats or stats["sample_count"] < ADAPTIVE_ZSCORE_MIN_SAMPLES:
        n = stats["sample_count"] if stats else 0
        return 0.0, False, fallback_threshold, n

    mean = stats["mean"]
    std = max(stats["std"], 0.15)  # floor to prevent division by near-zero
    z_score = (current_value - mean) / std
    adaptive_threshold = ADAPTIVE_ZSCORE_SENSITIVITY * std + mean
    return round(z_score, 3), True, round(adaptive_threshold, 3), stats["sample_count"]


def compute_origin_entropy(distribution: dict) -> float:
    """Compute Shannon entropy of an attack origin distribution.

    distribution: {country_code: percentage_share, ...}
    Returns entropy in bits. Higher = more distributed attack sources.
    Single-source attacks → 0 bits. Perfectly uniform across N sources → log2(N).
    """
    import math
    total = sum(v for v in distribution.values() if v > 0)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for v in distribution.values():
        if v > 0:
            p = v / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)


# In-memory entropy history per theater (rolling window for moving average)
_entropy_history: dict[str, list[float]] = {}
_entropy_lock = threading.Lock()
ENTROPY_HISTORY_SIZE = 20  # Keep last 20 readings for moving average


def track_entropy_change(theater: str, current_entropy: float) -> dict:
    """Track entropy changes with a moving average for anomaly detection.

    Returns dict with:
      - current: current entropy value
      - moving_avg: moving average of recent entropy values
      - delta_pct: percent change from moving average
      - shift_label: CONCENTRATING / DISPERSING / STABLE
    """
    with _entropy_lock:
        history = _entropy_history.setdefault(theater, [])
        history.append(current_entropy)
        if len(history) > ENTROPY_HISTORY_SIZE:
            _entropy_history[theater] = history[-ENTROPY_HISTORY_SIZE:]
        history = list(_entropy_history[theater])  # snapshot for read

    if len(history) < 3:
        return {
            "current": current_entropy, "moving_avg": current_entropy,
            "delta_pct": 0.0, "shift_label": "INSUFFICIENT_DATA",
        }

    # Moving average excluding the latest point (to compare against)
    prior = history[:-1]
    moving_avg = sum(prior) / len(prior) if prior else current_entropy

    if moving_avg > 0:
        delta_pct = round(((current_entropy - moving_avg) / moving_avg) * 100, 2)
    else:
        delta_pct = 0.0

    # Significant change thresholds
    if delta_pct < -20.0:
        label = "CONCENTRATING"  # Attack sources becoming more focused
    elif delta_pct > 20.0:
        label = "DISPERSING"     # Attack spreading to more sources
    else:
        label = "STABLE"

    return {
        "current": current_entropy,
        "moving_avg": round(moving_avg, 3),
        "delta_pct": delta_pct,
        "shift_label": label,
    }


def get_fallback_coord(code: str) -> dict:
    h = int(hashlib.md5((code or "Unknown").encode()).hexdigest(), 16)
    return {"lat": (h % 100) - 50, "lng": ((h // 100) % 360) - 180, "name": f"Origin: {code}"}

# Minimum interval between live CF API calls to avoid burst rate-limiting.
# CF free tier allows ~1200 req/5min (~4/s); we conservatively limit to ~3/s.
_CF_MIN_INTERVAL = 0.35  # seconds
_cf_req_last_ts: float = 0.0
_cf_req_lock = threading.Lock()


def fetch_cf_data(url: str, params: dict) -> list:
    global _cf_req_last_ts
    with _cf_req_lock:
        gap = time.time() - _cf_req_last_ts
        if gap < _CF_MIN_INTERVAL:
            time.sleep(_CF_MIN_INTERVAL - gap)
        _cf_req_last_ts = time.time()
    try:
        res = requests.get(url, headers=CF_HEADERS, params=params, timeout=5, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
        if res.status_code == 200:
            return res.json().get("result", {}).get("top_0", [])
        else:
            log.warning("[CF fetch] HTTP %d for %s params=%s", res.status_code, url, params)
    except Exception as e:
        log.warning("[CF fetch] Exception for %s: %s", url, e)
    return []

def fetch_cf_data_cached(url: str, params: dict, ttl: float = None) -> list:
    """Cache CF API calls within the scoring loop.
    Uses CACHE_EXPIRY when TTL is omitted. Prevents repeated fetches on reload.
    Cleans up expired entries on each call to prevent memory leaks.
    On fetch failure (empty result), preserves stale cache instead of overwriting."""
    if ttl is None:
        ttl = CACHE_EXPIRY
    now = time.time()
    cache_key = (url, frozenset(params.items()))
    # Cleanup: only remove entries older than max TTL (86400*2) to avoid
    # short-TTL calls evicting long-TTL baseline entries (BUG-6 fix)
    _MAX_TTL = 86400 * 2
    with _cf_cache_lock:
        expired = [k for k, v in _cf_scoring_cache.items() if now - v["time"] > _MAX_TTL]
        for k in expired:
            _cf_scoring_cache.pop(k, None)
        entry = _cf_scoring_cache.get(cache_key)
        if entry and (now - entry["time"]) < ttl:
            return entry["data"]
    data = fetch_cf_data(url, params)
    # On failure (empty list), preserve stale cache data instead of overwriting
    if not data:
        with _cf_cache_lock:
            stale = _cf_scoring_cache.get(cache_key)
        if stale:
            log.debug("[CF cache] Fetch returned empty, using stale cache for %s", url)
            return stale["data"]
    with _cf_cache_lock:
        _cf_scoring_cache[cache_key] = {"time": now, "data": data}
    return data

def parse_origins(origins_list: list) -> dict:
    parsed = {}
    for o in origins_list:
        code = o.get("origin1") or o.get("location") or o.get("clientCountryAlpha2")
        if not code:
            for k, v in o.items():
                if isinstance(v, str) and len(v) == 2 and v.isupper(): code = v; break
        weight = float(o.get("value") or o.get("count") or 1.0)
        if code: parsed[code] = weight
    return parsed

def calculate_overlap(dist1: dict, dist2: dict) -> float:
    if not dist1 or not dist2: return 0.0
    # Normalize both distributions so each sums to 100%
    s1 = sum(dist1.values()) or 1.0
    s2 = sum(dist2.values()) or 1.0
    all_keys = set(dist1) | set(dist2)
    return round(sum(min(dist1.get(k, 0.0) / s1, dist2.get(k, 0.0) / s2) for k in all_keys) * 100, 2)

_asn_cache: dict = {}  # {target_code: {"time": float, "data": dict}}

def fetch_asn_origins(target_code: str) -> dict:
    global _asn_cache
    now = time.time()
    # Remove expired entries (memory leak prevention)
    expired = [k for k, v in _asn_cache.items() if now - v["time"] > CACHE_EXPIRY * 2]
    for k in expired:
        del _asn_cache[k]
    entry = _asn_cache.get(target_code)
    if entry and (now - entry["time"]) < CACHE_EXPIRY:
        return entry["data"]
    try:
        res = requests.get("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/ases/origin", headers=CF_HEADERS, params={"location": target_code, "dateRange": CURRENT_DATE_RANGE, "format": "json"}, timeout=5, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
        if res.status_code == 200:
            data = {f"AS{item.get('originAsn') or item.get('clientASN') or item.get('originAsnId')}": float(item.get("value", 0)) for item in res.json().get("result", {}).get("top_0", []) if item.get("originAsn") or item.get("clientASN") or item.get("originAsnId")}
            _asn_cache[target_code] = {"time": now, "data": data}
            return data
    except Exception: pass
    return {}

def compute_confidence(spike_factor: float, code: str, is_new_actor: bool, is_state_asn: bool) -> str:
    if is_state_asn and spike_factor > 2.0: return "HIGH"
    if is_new_actor: return "LOW"
    if spike_factor > 3.0: return "MEDIUM"
    if spike_factor > 2.0: return "MEDIUM"
    return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
# Context-Aware Convergence (CAC) — Direction & Context Classification
# ══════════════════════════════════════════════════════════════════════════════

def classify_direction(sensor_name: str, domain: str,
                       source_country: str = "",
                       target_country: str = "",
                       adversary_states: list = None,
                       strategic_theaters: list = None,
                       **kwargs) -> tuple[str, float]:
    """Classify a signal's direction as ADVERSARY_OFFENSIVE, FRIENDLY_DEFENSIVE,
    TARGET_IMPACT, or UNKNOWN.

    Returns: (direction: str, confidence: float 0.0-1.0)

    Rules:
    - Attack traffic FROM adversary state TO target → ADVERSARY_OFFENSIVE (high conf)
    - ISR/military recon FROM friendly state near target → FRIENDLY_DEFENSIVE
    - Infrastructure degradation AT target → TARGET_IMPACT
    - Narrative/media signals: depends on source attribution
    - State ASN involvement raises confidence
    """
    adversary_states = adversary_states or []
    strategic_theaters = strategic_theaters or []
    src = source_country.upper() if source_country else ""
    tgt = target_country.upper() if target_country else ""
    is_src_adversary = src in adversary_states
    is_src_friendly = src in strategic_theaters and src not in adversary_states
    is_tgt_strategic = tgt in strategic_theaters

    # Cyber domain: DDoS origin, BGP manipulation, APT infrastructure
    if domain == "cyber":
        if is_src_adversary and is_tgt_strategic:
            # State ASN involvement increases confidence
            has_state_asn = kwargs.get("is_state_asn", False)
            conf = 0.9 if has_state_asn else 0.7
            return DIRECTION_ADVERSARY_OFFENSIVE, conf
        if is_src_adversary:
            return DIRECTION_ADVERSARY_OFFENSIVE, 0.5
        if is_tgt_strategic and not src:
            # Impact on target without clear source attribution
            return DIRECTION_TARGET_IMPACT, 0.4
        return DIRECTION_UNKNOWN, 0.2

    # Physical domain: airspace, maritime, infrastructure, seismic
    if domain == "physical":
        # ISR/reconnaissance: friendly aircraft near target = defensive posture
        if sensor_name in ("isr_hotspot", "opensky"):
            if is_src_friendly or kwargs.get("is_friendly_asset", False):
                return DIRECTION_FRIENDLY_DEFENSIVE, 0.7
            if is_src_adversary:
                return DIRECTION_ADVERSARY_OFFENSIVE, 0.6
        # Infrastructure degradation (Check-Host, IODA, BGP routing)
        if sensor_name in ("check_host", "ioda_bgp", "ripe_bgp"):
            if is_tgt_strategic:
                return DIRECTION_TARGET_IMPACT, 0.8
        # Maritime: AIS dark gap near chokepoint
        if sensor_name == "ais_maritime":
            return DIRECTION_ADVERSARY_OFFENSIVE, 0.4
        # FIRMS thermal anomaly at target
        if sensor_name == "nasa_firms":
            if is_tgt_strategic:
                return DIRECTION_TARGET_IMPACT, 0.6
        # Space weather: natural phenomenon, no direction
        if sensor_name == "space_weather":
            return DIRECTION_UNKNOWN, 0.0
        return DIRECTION_UNKNOWN, 0.3

    # Info domain: narrative, media tone, Telegram
    if domain == "info":
        if sensor_name in ("rss_narrative", "telegram_mirror"):
            # Narrative from adversary-attributed sources
            if kwargs.get("is_adversary_narrative", False):
                return DIRECTION_ADVERSARY_OFFENSIVE, 0.6
            # General media tone shift about target
            if is_tgt_strategic:
                return DIRECTION_TARGET_IMPACT, 0.4
        if sensor_name == "gdelt":
            if is_tgt_strategic:
                return DIRECTION_TARGET_IMPACT, 0.5
        return DIRECTION_UNKNOWN, 0.3

    return DIRECTION_UNKNOWN, 0.1


def compute_temporal_context(sensor_name: str, current_ts: float,
                             theater: str) -> dict:
    """Compute temporal context features for a sensor signal.

    Returns dict with:
    - hour_of_day: 0-23 UTC
    - is_business_hours: whether target timezone is in business hours (approx)
    - day_of_week: 0=Mon, 6=Sun
    - is_weekend: boolean
    - recency_weight: decay factor based on data freshness
    """
    import datetime
    dt = datetime.datetime.fromtimestamp(current_ts, tz=datetime.timezone.utc)
    hod = dt.hour
    dow = dt.weekday()

    # Approximate business hours for theater (UTC offset estimation)
    tz_offsets = {
        "TW": 8, "JP": 9, "KR": 9, "CN": 8, "US": -5, "RU": 3,
        "UA": 2, "IL": 2, "IR": 3.5, "IN": 5.5, "AU": 10,
    }
    offset = tz_offsets.get(theater, 0)
    local_hour = (hod + offset) % 24
    is_business = 8 <= local_hour < 18

    return {
        "hour_of_day": hod,
        "local_hour": round(local_hour),
        "is_business_hours": is_business,
        "day_of_week": dow,
        "is_weekend": dow >= 5,
    }


def compute_spatial_context(sensor_name: str, theater: str,
                            source_country: str = "",
                            adversary_states: list = None) -> dict:
    """Compute spatial context: geographic relationship between signal source and target.

    Returns dict with:
    - distance_class: PROXIMATE / REGIONAL / DISTANT
    - near_chokepoint: boolean
    - chokepoint_name: nearest chokepoint name if relevant
    """
    adversary_states = adversary_states or []

    # Check chokepoint proximity
    near_cp = False
    cp_name = ""
    for cp in CHOKEPOINTS:
        cp_countries = cp.get("countries", [])
        if isinstance(cp_countries, list):
            if theater in cp_countries or source_country in cp_countries:
                near_cp = True
                cp_name = cp.get("name", "")
                break

    # Distance classification based on regional proximity
    src_coord = COUNTRY_COORDS.get(source_country, {})
    tgt_coord = COUNTRY_COORDS.get(theater, {})
    if src_coord and tgt_coord:
        import math
        dlat = abs(src_coord.get("lat", 0) - tgt_coord.get("lat", 0))
        dlng = abs(src_coord.get("lng", 0) - tgt_coord.get("lng", 0))
        approx_dist = math.sqrt(dlat**2 + dlng**2)
        if approx_dist < 15:
            dist_class = "PROXIMATE"
        elif approx_dist < 40:
            dist_class = "REGIONAL"
        else:
            dist_class = "DISTANT"
    else:
        dist_class = "UNKNOWN"

    return {
        "distance_class": dist_class,
        "near_chokepoint": near_cp,
        "chokepoint_name": cp_name,
    }


def compute_target_context(sensor_name: str, theater: str,
                           source_country: str = "",
                           adversary_states: list = None,
                           strategic_theaters: list = None) -> dict:
    """Compute target context: relationship between signal and monitored target.

    Returns dict with:
    - target_relevance: DIRECT / INDIRECT / AMBIENT
    - is_core_theater: boolean
    - adversary_involvement: boolean
    - multi_target: boolean (signal affects multiple strategic theaters)
    """
    adversary_states = adversary_states or []
    strategic_theaters = strategic_theaters or []
    is_core = theater == (strategic_theaters[0] if strategic_theaters else "")
    is_adversary = source_country in adversary_states if source_country else False

    # Direct: signal specifically targets this theater
    # Indirect: signal affects regional infrastructure that includes this theater
    # Ambient: background signal with no specific target attribution
    if source_country and theater:
        if is_adversary and theater in strategic_theaters:
            relevance = "DIRECT"
        elif theater in strategic_theaters:
            relevance = "INDIRECT"
        else:
            relevance = "AMBIENT"
    else:
        relevance = "AMBIENT"

    return {
        "target_relevance": relevance,
        "is_core_theater": is_core,
        "adversary_involvement": is_adversary,
    }
