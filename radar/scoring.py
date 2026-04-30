"""radar.scoring -- Sequence scorer, HOD Z-score, CF helpers, misc scoring functions,
   and Context-Aware Convergence (CAC) direction classification."""
from __future__ import annotations
import hashlib
import logging
import math
import requests
import threading
import time
import os as _os
from dataclasses import dataclass, field
from typing import Optional
from radar.config import (
    CF_HEADERS, GLOBAL_PROXIES, SSL_VERIFY, CURRENT_DATE_RANGE,
    BASELINE_DATE_RANGE, CACHE_EXPIRY,
    HOD_BASELINE_DAYS, HOD_MIN_SAME_HOUR, HOD_MAX_ENTRIES,
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


# ── Signal dataclass (scenario-refactor Phase 1) ────────────────────────────

@dataclass
class Signal:
    """Atomic observation emitted by a sensor — input unit for scoring engine.

    See docs/_archive/scenario-refactor-v1.8.1.md §6.3 for field semantics
    and ADR-022 for the Signal.countries convention.
    """
    signal_source: str
    sensor: str
    observed_at: float
    domain: str
    countries: list[str]
    country_weights: dict[str, float] = field(default_factory=dict)
    raw_score: float = 0.0
    value_display: str = ""
    evidence_url: Optional[str] = None
    llm_reasoning: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "signal_source": self.signal_source,
            "sensor": self.sensor,
            "observed_at": self.observed_at,
            "domain": self.domain,
            "countries": self.countries,
            "raw_score": self.raw_score,
            "value_display": self.value_display,
        }
        if self.country_weights:
            d["country_weights"] = self.country_weights
        if self.evidence_url:
            d["evidence_url"] = self.evidence_url
        if self.llm_reasoning:
            d["llm_reasoning"] = self.llm_reasoning
        return d


def rationale_to_signal(rat, source_country: str = "", observed_at: float = 0.0,
                        evidence_url: str | None = None,
                        llm_reasoning: str | None = None) -> Optional[Signal]:
    """Convert a legacy RationaleEntry to a Signal for scenario scoring.

    Skips suppressed/non-FIRED rationale entries. Determines countries
    from source_country (per-country sensor) or empty list (global sensor).
    """
    if rat.suppressed or rat.status != "FIRED" or rat.score <= 0:
        return None
    countries = [source_country] if source_country else []
    return Signal(
        signal_source=rat.signal_source or rat.sensor,
        sensor=rat.sensor,
        observed_at=observed_at or time.time(),
        domain=rat.domain,
        countries=countries,
        country_weights={source_country: 1.0} if source_country else {},
        raw_score=float(rat.score),
        value_display=str(rat.value),
        evidence_url=evidence_url or None,
        llm_reasoning=llm_reasoning or None,
    )


def resolve_seq_fire_targets(
    core_theater: str | None,
    effective_cores: list,
    scenario_wide: bool = False,
) -> list[str]:
    """Decide which countries should receive a sequence event registration.

    Single-core scenarios (core_theater present): always [core_theater].

    Dual-core scenarios (ADR-009: core_country=null, two principal
    belligerents):
      - scenario_wide=True (NARRATIVE_BURST, SYNC_DDOS — semantics are
        theater-aggregate, the underlying signal applies symmetrically
        to every belligerent): every effective_core is targeted so each
        principal belligerent's escalation chain accrues the event.
      - scenario_wide=False (per-country events whose data was only
        checked against primary): only [core_theater]. Registering for
        secondary would attach a false-provenance event to a chain
        whose underlying sensor data was never inspected.

    Filters falsy entries (empty strings, None) and dedupes preserving
    insertion order so callers can pass effective_cores directly.
    """
    if scenario_wide and effective_cores:
        seen: set[str] = set()
        out: list[str] = []
        for t in effective_cores:
            if not t or t in seen:
                continue
            seen.add(t)
            out.append(t)
        return out
    if core_theater:
        return [core_theater]
    return [t for t in effective_cores if t]


def select_secondary_ec_hits(
    effective_cores: list,
    primary_ec: str,
    data: list,
    country_field: str,
) -> dict:
    """Group sensor data rows by secondary effective_core (ADR-009 stage 2).

    For dual-core scenarios, the existing _seq_fire path covers
    primary_ec only. This helper picks out the rows whose country
    matches each *secondary* effective_core so callers can register
    per-country sequence events (FIRMS_ANOMALY, ISR_SURGE, etc.)
    against each principal belligerent symmetrically.

    Returns ``{secondary_ec: [matching_row, ...]}`` — secondaries with
    no matching data are omitted so the caller's loop is a no-op for
    quiet belligerents. Sensor-agnostic: the country field name
    differs across sensors (FIRMS uses 'code', ISR uses 'country').
    """
    out: dict[str, list] = {}
    for ec in effective_cores:
        if not ec or ec == primary_ec:
            continue
        hits = [row for row in data if row.get(country_field) == ec]
        if hits:
            out[ec] = hits
    return out


def register_sequence_event(theater: str, event_type: str, meta: Optional[dict] = None,
                            dedup_window: int = 300,
                            scenario_id: str | None = None):
    """Register an event in the escalation chain log.

    dedup_window: seconds within which duplicate event_type entries are suppressed
        (default 300 s = 5 min).  Prevents double-counting when multiple sensors
        (e.g. RSS + Telegram) fire the same event type in the same scoring cycle.
    scenario_id: optional scenario association (ADR-020).
    """
    if not theater:
        # No country to anchor the event to (e.g. focused scenario has no
        # core_country per ADR-009). Skip rather than pollute seq_events
        # with an empty-theater row that can't be correlated later.
        return
    now = time.time()
    # Dedup: skip if the same event type was registered within the dedup window
    dedup_cutoff = now - dedup_window
    if _db.seq_exists_since(theater, event_type, dedup_cutoff):
        return
    _db.seq_append(theater, now, event_type, meta or {}, scenario_id=scenario_id)
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
        raw_bonus = int(_os.getenv("SEQUENCE_PARTIAL_BONUS", "2"))
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
    h = int(hashlib.md5((code or "Unknown").encode(), usedforsecurity=False).hexdigest(), 16)
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


def compute_idf_weights(distributions: dict) -> dict:
    """Build TF-IDF style inverse-document-frequency weights for ASN keys.

    distributions: {country_code: {asn_key: weight}}
    Returns: {asn_key: idf_weight in [0, 1]}, normalized so the rarest ASN has weight 1.

    Rationale: in dense scenarios, large global cloud/CDN ASNs (Google,
    Cloudflare, AWS) appear in every country's attack-origin distribution and
    dominate raw histogram intersection. IDF weighting suppresses these
    structural-baseline ASNs (idf ≈ 0 when N_docs == N_total) and amplifies
    rarer ASNs that are genuine signals of coordinated targeting.
    """
    if not distributions:
        return {}
    n_docs = sum(1 for d in distributions.values() if d)
    if n_docs <= 0:
        return {}
    df: dict[str, int] = {}
    for d in distributions.values():
        if not d:
            continue
        for k in d.keys():
            df[k] = df.get(k, 0) + 1
    if not df:
        return {}
    # Standard IDF: log(N / df). +1 in numerator avoids -inf for ubiquitous keys
    # while still driving them close to zero. We then normalize to [0, 1] so
    # the resulting overlap stays in a familiar 0-100 range.
    raw = {k: math.log((n_docs + 1) / (cnt + 1)) for k, cnt in df.items()}
    max_w = max(raw.values()) or 1.0
    if max_w <= 0:
        return {k: 0.0 for k in raw}
    return {k: max(0.0, w / max_w) for k, w in raw.items()}


def calculate_overlap_idf(dist1: dict, dist2: dict, idf_weights: dict) -> float:
    """IDF-weighted histogram intersection (Phase 4 candidate replacement).

    Behaves like calculate_overlap, but each ASN's contribution is multiplied
    by its IDF weight. Background-noise ASNs (present in all countries) get
    weight ≈ 0 and stop saturating the index; rare/coordinated ASNs dominate.
    Returns a value in [0, 100].
    """
    if not dist1 or not dist2 or not idf_weights:
        return 0.0
    s1 = sum(dist1.values()) or 1.0
    s2 = sum(dist2.values()) or 1.0
    all_keys = set(dist1) | set(dist2)
    # weighted intersection
    num = sum(
        min(dist1.get(k, 0.0) / s1, dist2.get(k, 0.0) / s2) * idf_weights.get(k, 0.0)
        for k in all_keys
    )
    # weighted self-intersection ceiling: if both distributions were identical
    # and concentrated entirely on the highest-IDF key, the result would equal
    # idf_max == 1.0 (post-normalization). So scaling by 100 keeps the index
    # comparable to the existing 0-100 range without further calibration.
    return round(num * 100, 2)


_asn_cache: dict = {}  # {target_code: {"time": float, "data": dict}}
_asn_cache_lock = threading.Lock()

def fetch_asn_origins(target_code: str) -> dict:
    now = time.time()
    with _asn_cache_lock:
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
            with _asn_cache_lock:
                _asn_cache[target_code] = {"time": now, "data": data}
            return data
    except Exception as e:
        log.debug("[ASN] Cloudflare ASN fetch failed for %s: %s", target_code, e)
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
                           strategic_theaters: list = None,
                           core_country: str = "") -> dict:
    """Compute target context: relationship between signal and monitored target.

    Returns dict with:
    - target_relevance: DIRECT / INDIRECT / AMBIENT
    - is_core_theater: boolean (theater == focused scenario's core_country)
    - adversary_involvement: boolean
    """
    adversary_states = adversary_states or []
    strategic_theaters = strategic_theaters or []
    is_core = bool(core_country) and theater == core_country
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


# ── Scenario scoring (Phase 2) ─────────────────────────────────────────────

@dataclass
class ScenarioContribution:
    """A single signal's contribution to a scenario via one participant country."""
    signal: Signal
    contributing_country: str
    llm_country_weight: float
    participant_weight: float
    participant_role: str
    final_contribution: float
    formula_trace: str
    suppress_reason: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "signal": self.signal.to_dict(),
            "contributing_country": self.contributing_country,
            "llm_country_weight": round(self.llm_country_weight, 3),
            "participant_weight": round(self.participant_weight, 3),
            "participant_role": self.participant_role,
            "final_contribution": round(self.final_contribution, 3),
            "formula_trace": self.formula_trace,
        }
        if self.suppress_reason:
            d["suppress_reason"] = self.suppress_reason
        return d


@dataclass
class ScenarioState:
    """Result of computing a scenario's score."""
    scenario_id: str
    is_focused: bool
    scoring_mode: str
    score: float
    domains: dict[str, float]
    active_countries: list[str]
    convergence_bonus: float
    tl: Optional[int]
    contributions: list[ScenarioContribution]

    def to_dict(self) -> dict:
        d = {
            "id": self.scenario_id,
            "is_focused": self.is_focused,
            "scoring_mode": self.scoring_mode,
            "score": round(self.score, 2),
            "tl": self.tl,
            "domains": {d_: round(v, 2) for d_, v in self.domains.items()},
            "convergence_bonus": round(self.convergence_bonus, 2),
            "active_countries": self.active_countries,
            "contributions": [c.to_dict() for c in self.contributions],
        }
        if not self.is_focused:
            domain_counts: dict[str, int] = {"cyber": 0, "physical": 0, "info": 0}
            seen: set[tuple[str, str]] = set()
            for c in self.contributions:
                key = (c.signal.signal_source, c.signal.sensor)
                if key not in seen:
                    seen.add(key)
                    domain_counts[c.signal.domain] = domain_counts.get(c.signal.domain, 0) + 1
            # Domain coverage analysis: identify blind spots in background
            # scenarios so the UI can flag degraded observability.
            _all_domains = {"cyber", "physical", "info"}
            _active_domains = {d_ for d_, cnt in domain_counts.items() if cnt > 0}
            _blind = sorted(_all_domains - _active_domains)
            d["indicators"] = {
                "active_countries": len(self.active_countries),
                "domain_signal_counts": domain_counts,
                "blind_domains": _blind,
                "coverage_completeness": round(len(_active_domains) / 3.0, 2),
            }
        return d


# ── Scenario velocity & acceleration (Phase A: temporal analysis) ──────────

# Velocity bonus caps — prevents feedback loops while allowing trend influence.
# ±1.5 pt is ~17% of the TL3→TL2 threshold gap (6pt), meaningful but not dominant.
VELOCITY_BONUS_CAP = 1.5
ACCELERATION_BONUS_MAX = 0.5
# Minimum observations to compute meaningful velocity
VELOCITY_MIN_OBSERVATIONS = 4


def _linear_regression_slope(xs: list[float], ys: list[float]) -> float:
    """Least-squares slope (shared with engine.py)."""
    n = len(xs)
    if n < 2:
        return 0.0
    sx = sum(xs)
    sy = sum(ys)
    sxy = sum(x * y for x, y in zip(xs, ys))
    sxx = sum(x * x for x in xs)
    denom = n * sxx - sx * sx
    return (n * sxy - sx * sy) / denom if denom != 0 else 0.0


def compute_scenario_velocity(score_series: list[tuple[float, float]]) -> float:
    """Compute scenario score velocity (pts/sec) from recent observations.

    score_series: [(observed_at, score), ...] ordered oldest-first.
    Returns smoothed velocity via linear regression slope.
    """
    if len(score_series) < VELOCITY_MIN_OBSERVATIONS:
        return 0.0
    t0 = score_series[0][0]
    xs = [p[0] - t0 for p in score_series]
    ys = [p[1] for p in score_series]
    return round(_linear_regression_slope(xs, ys), 6)


def compute_scenario_acceleration(score_series: list[tuple[float, float]]) -> float:
    """Compute scenario score acceleration (pts/sec²) from consecutive
    velocity estimates over the observation window."""
    if len(score_series) < 8:
        return 0.0
    # Build velocity series from consecutive pairs
    velocities: list[tuple[float, float]] = []
    for i in range(1, len(score_series)):
        dt = score_series[i][0] - score_series[i - 1][0]
        if dt > 0:
            v = (score_series[i][1] - score_series[i - 1][1]) / dt
            velocities.append((score_series[i][0], v))
    if len(velocities) < 2:
        return 0.0
    t0 = velocities[0][0]
    xs = [v[0] - t0 for v in velocities]
    ys = [v[1] for v in velocities]
    return round(_linear_regression_slope(xs, ys), 8)


def compute_velocity_bonus(velocity: float, acceleration: float) -> tuple[float, float]:
    """Compute scoring bonuses from scenario velocity and acceleration.

    Returns (velocity_bonus, acceleration_bonus).
    velocity_bonus: capped at ±VELOCITY_BONUS_CAP. Converts pts/sec to pts/hour
        and scales by 0.5 to produce a meaningful but bounded bonus.
    acceleration_bonus: 0.5 when rapid positive acceleration detected (ambush
        pattern at scenario level).
    """
    vel_bonus = 0.0
    if abs(velocity) > 0.0001:
        vel_pts_per_hour = velocity * 3600
        vel_bonus = max(-VELOCITY_BONUS_CAP,
                        min(vel_pts_per_hour * 0.5, VELOCITY_BONUS_CAP))
        vel_bonus = round(vel_bonus, 2)

    acc_bonus = 0.0
    if acceleration > 0:
        acc_pts_per_hour2 = acceleration * 3600 * 3600
        if acc_pts_per_hour2 > 0.1:
            acc_bonus = min(round(acc_pts_per_hour2 * 0.3, 2),
                            ACCELERATION_BONUS_MAX)

    return vel_bonus, acc_bonus


# Silent Divergence and Context Alignment bonuses (Phase B: pattern detection)
SILENT_DIVERGENCE_BONUS = 0.5
CONTEXT_ALIGNMENT_BONUS = 0.5
# Minimum context alignment score (out of 4 axes) to award bonus
CONTEXT_ALIGNMENT_THRESHOLD = 3


def compute_convergence_bonus_scenario(active_domains: list[str]) -> float:
    n = len(active_domains)
    if n >= 3:
        return 2.0
    if n == 2:
        return 1.0
    return 0.0


def derive_tl(total_score: float, active_domains: list[str],
              physical_score: float) -> int:
    if total_score >= 9 and physical_score >= 3.0:
        return 1
    if total_score >= 6 and len(active_domains) >= 2:
        return 2
    if total_score >= 4:
        return 3
    if total_score >= 2:
        return 4
    return 5


# v2.0 derive_tl version tag — bumped when thresholds or formula change.
# Persisted in Conclusion.formula_ref so analysts can trace which version
# produced a historical row.
DERIVE_TL_FORMULA_REF = "radar/scoring.py#derive_tl@v2.0.1"


def _maybe_persist_tl_conclusion(state: "ScenarioState") -> None:
    """v2.0 shadow-write: persist the focused TL as a Conclusion row.

    Gated by V2_CONCLUSION_LEDGER_ENABLED. v1 API responses are unchanged;
    this path only writes to the new conclusions ledger. ADR-V2-001.

    Skip background (unfocused) scenarios with no TL — they are not deeply
    scored and emit no actionable conclusion. The builder itself is total
    over ScenarioState (returns INSUFFICIENT_DATA when tl is None), but we
    only call it where a row is meaningful.
    """
    from radar import config
    if not config.V2_CONCLUSION_LEDGER_ENABLED:
        return
    if state.tl is None:
        return
    try:
        from radar.conclusions import save_conclusion
        from radar.conclusions.shadow_metrics import record_failure, record_success
        from radar.conclusions.threat_level import derive_threat_level
        c = derive_threat_level(_db, state)
        save_conclusion(_db, c)
        record_success("threat_level")
    except Exception as exc:
        # Phase 1 shadow-write must NEVER break v1 scoring. Log and swallow.
        log.exception("v2 conclusion persistence failed (non-fatal)")
        from radar.conclusions.shadow_metrics import record_failure
        record_failure("threat_level", exc)


def _maybe_persist_per_domain_conclusion(state: "ScenarioState") -> None:
    """v2.0 shadow-write: persist the per-domain (cyber/physical/info) row.

    Independent from the TL hook — emits even when state.tl is None, since
    the per-domain breakdown is meaningful for background scenarios that do
    not derive a TL. The builder itself returns INSUFFICIENT_DATA when all
    three domains are silent (NP5+8 + NP1).
    """
    from radar import config
    if not config.V2_CONCLUSION_LEDGER_ENABLED:
        return
    try:
        from radar.conclusions import save_conclusion
        from radar.conclusions.per_domain import derive_per_domain
        from radar.conclusions.shadow_metrics import record_success
        c = derive_per_domain(_db, state)
        save_conclusion(_db, c)
        record_success("per_domain")
    except Exception as exc:
        log.exception("v2 per_domain conclusion persistence failed (non-fatal)")
        from radar.conclusions.shadow_metrics import record_failure
        record_failure("per_domain", exc)


def _maybe_persist_trend_conclusion(state: "ScenarioState") -> None:
    """v2.0 shadow-write: derive the 3-window trend from THREAT_LEVEL ledger.

    Must fire AFTER _maybe_persist_tl_conclusion so the freshly-written TL
    row is part of the input set the trend deriver reads back. Calling it
    only on focused scenarios because background scoring emits no TL row,
    so the input ledger does not advance for them.
    """
    from radar import config
    if not config.V2_CONCLUSION_LEDGER_ENABLED:
        return
    if not state.is_focused:
        return
    try:
        from radar.conclusions import save_conclusion
        from radar.conclusions.shadow_metrics import record_success
        from radar.conclusions.trend import derive_trend
        c = derive_trend(_db, state.scenario_id)
        save_conclusion(_db, c)
        record_success("trend")
    except Exception as exc:
        log.exception("v2 trend conclusion persistence failed (non-fatal)")
        from radar.conclusions.shadow_metrics import record_failure
        record_failure("trend", exc)


def _maybe_persist_attack_mode_conclusion(state: "ScenarioState") -> None:
    """v2.0 shadow-write: persist the rule-based ATTACK_MODE classification.

    The deriver is pure over ScenarioState (no DB read), so this is the
    cheapest hook of the four. Emits on every tick — INSUFFICIENT_DATA
    rows are intentional (NP5+8 + NP1: a transient unavailable, NOT a
    "no attack" claim) and become input for continuity tracking.
    """
    from radar import config
    if not config.V2_CONCLUSION_LEDGER_ENABLED:
        return
    try:
        from radar.conclusions import save_conclusion
        from radar.conclusions.attack_mode import derive_attack_mode
        from radar.conclusions.attack_mode_llm import augment_attack_mode_with_llm
        from radar.conclusions.shadow_metrics import record_success
        c = derive_attack_mode(state)
        # NP3: augmentation never raises; on LLM failure it returns the
        # rule-based row unchanged so the ledger still advances.
        c = augment_attack_mode_with_llm(c, state)
        save_conclusion(_db, c)
        record_success("attack_mode")
    except Exception as exc:
        log.exception("v2 attack_mode conclusion persistence failed (non-fatal)")
        from radar.conclusions.shadow_metrics import record_failure
        record_failure("attack_mode", exc)


def _maybe_persist_anomaly_conclusions(state: "ScenarioState") -> None:
    """v2.0 shadow-write: persist top-N ANOMALY rows for this scoring tick.

    derive_anomaly returns either a list of ranked anomalies (top DEFAULT_LIMIT)
    or a single INSUFFICIENT_DATA row when no scorable contribution exists.
    Both shapes are valid ledger inputs and we persist them all so the 24h
    novelty scan in subsequent ticks (Phase 1.2e) has the full history.

    Each saved row counts as one success in the metrics; a single failure
    short-circuits the rest of the list (safe — the counter still advances
    once for the failure and v1 scoring is unaffected).
    """
    from radar import config
    if not config.V2_CONCLUSION_LEDGER_ENABLED:
        return
    try:
        from radar.conclusions import derive_anomaly, save_conclusion
        from radar.conclusions.shadow_metrics import record_success
        for c in derive_anomaly(_db, state):
            save_conclusion(_db, c)
            record_success("anomaly")
    except Exception as exc:
        log.exception("v2 anomaly conclusion persistence failed (non-fatal)")
        from radar.conclusions.shadow_metrics import record_failure
        record_failure("anomaly", exc)


def apply_hysteresis_to_tl(new_tl: Optional[int],
                           prev_tl: Optional[int]) -> tuple[Optional[int], bool]:
    """Scenario TL hysteresis: de-escalation (higher TL#) is limited to one
    step per observation. Escalation (lower TL#) is immediate.
    Returns (possibly-held-tl, held_flag).
    """
    if new_tl is None or prev_tl is None:
        return new_tl, False
    if new_tl > prev_tl:  # de-escalating (higher number = lower threat)
        held = min(new_tl, prev_tl + 1)
        return held, (held != new_tl)
    return new_tl, False


def dedup_by_source_country_max(
    contributions: list[ScenarioContribution],
) -> list[ScenarioContribution]:
    best: dict[tuple[str, str], ScenarioContribution] = {}
    for c in contributions:
        key = (c.signal.signal_source, c.contributing_country)
        if key not in best or c.final_contribution > best[key].final_contribution:
            best[key] = c
    return list(best.values())


def compute_scenario_score(
    scenario,
    all_signals: list[Signal],
    is_focused: bool,
    global_signal_weight: float = 0.5,
    domain_cap: float = 6.0,
) -> ScenarioState:
    from radar.scenarios import Scenario
    contributions: list[ScenarioContribution] = []

    for signal in all_signals:
        if not signal.countries:
            final = signal.raw_score * global_signal_weight
            contributions.append(ScenarioContribution(
                signal=signal,
                contributing_country="GLOBAL",
                llm_country_weight=1.0,
                participant_weight=global_signal_weight,
                participant_role="global",
                final_contribution=final,
                formula_trace=(
                    f"{signal.raw_score:.2f} (raw) "
                    f"× {global_signal_weight:.2f} (global) "
                    f"= {final:.2f}"
                ),
            ))
            continue

        for country in signal.countries:
            if country not in scenario.participants:
                continue

            participant = scenario.participants[country]
            llm_cw = signal.country_weights.get(country, 1.0)
            pw = participant.weight
            final = signal.raw_score * llm_cw * pw

            contributions.append(ScenarioContribution(
                signal=signal,
                contributing_country=country,
                llm_country_weight=llm_cw,
                participant_weight=pw,
                participant_role=participant.role.value,
                final_contribution=final,
                formula_trace=(
                    f"{signal.raw_score:.2f} (raw) "
                    f"× {llm_cw:.2f} (llm:{country}) "
                    f"× {pw:.2f} (participant:{country}) "
                    f"= {final:.2f}"
                ),
            ))

    deduped = dedup_by_source_country_max(contributions)

    domains: dict[str, float] = {"cyber": 0.0, "physical": 0.0, "info": 0.0}
    for c in deduped:
        d = c.signal.domain
        if d in domains:
            domains[d] += c.final_contribution

    for d in domains:
        domains[d] = min(domains[d], domain_cap)

    active_domains = [d for d, s in domains.items() if s > 0]
    active_countries = sorted(set(
        c.contributing_country for c in deduped
        if c.contributing_country != "GLOBAL"
    ))
    convergence_bonus = compute_convergence_bonus_scenario(active_domains)
    total_score = sum(domains.values()) + convergence_bonus

    scoring_mode = "full" if is_focused else "lite"
    tl = derive_tl(total_score, active_domains, domains["physical"]) if is_focused else None

    state = ScenarioState(
        scenario_id=scenario.id,
        is_focused=is_focused,
        scoring_mode=scoring_mode,
        score=total_score,
        domains=domains,
        active_countries=active_countries,
        convergence_bonus=convergence_bonus,
        tl=tl,
        contributions=deduped,
    )
    _maybe_persist_tl_conclusion(state)
    _maybe_persist_per_domain_conclusion(state)
    _maybe_persist_trend_conclusion(state)
    _maybe_persist_attack_mode_conclusion(state)
    _maybe_persist_anomaly_conclusions(state)
    _maybe_sample_v1_v2_diff(state)
    return state


def _maybe_sample_v1_v2_diff(state: "ScenarioState") -> None:
    """v2.0 Phase 1 priority 6: rollout monitoring shadow-write.

    Records one (v1, v2) TL diff row per cycle in conclusion_diff_log so
    analysts can verify default-on safety before the flag flip. Runs only
    for the focused scenario — background scenarios do not produce v2
    rows in C-lite mode, so any diff would be vacuously v2_missing.
    """
    if not state.is_focused:
        return
    try:
        from radar.conclusions.diff_sampler import sample_focused_tl_diff
        sample_focused_tl_diff(_db, state)
    except Exception:
        log.exception("v2 diff sampler failed (non-fatal)")


# ── Weight calibration advisory (Item 2.2) ───────────────────────────────────
# REPORTING ONLY. Static participant weights are never auto-mutated by this
# helper — it surfaces divergence so analysts can decide whether to retune.
# All flag strings carry the ADVISORY_ prefix per NP7 / P5 audit rule so
# downstream readers can grep tool-side recommendations vs system-detected
# facts (compromise indicators, sequence fires, etc.) without a parse step.

# Floor below which silence is expected — observers and low-weight
# participants need not generate alerts when they contribute nothing.
_LOW_WEIGHT_FLOOR = 0.30


def compute_weight_utilization(
    scenario,
    contributions: list[ScenarioContribution],
    divergence_threshold_pct: float = 30.0,
) -> list[dict]:
    """Per-participant weight utilization vs configured share.

    Underperformance flag fires when:
      - participant has configured_weight >= _LOW_WEIGHT_FLOOR, AND
      - utilization_pct < (100 - divergence_threshold_pct)

    Overperformance is informational only (note="overperforming") so the
    UI can hint at it without raising an alert. Auto-rebalancing weights
    on observed traffic would create a feedback loop where quiet weeks
    drag the weight down and the next escalation gets undercounted.
    """
    participants = getattr(scenario, "participants", {}) or {}
    if not participants:
        return []

    # Configured shares: weight / sum(weights). The denominator collapses
    # to all participants, so a 1.0/0.5 scenario yields 0.667/0.333 shares.
    total_weight = sum(p.weight for p in participants.values())
    configured_share = {
        cc: (p.weight / total_weight if total_weight > 0 else 0.0)
        for cc, p in participants.items()
    }

    # Observed shares: per-country contribution / total participant
    # contribution. GLOBAL contributions are explicitly excluded — they
    # are not attributable to any one participant and would distort the
    # ratio. dedup_by_source_country_max is assumed to have been applied
    # upstream, so each (signal_source, country) appears at most once.
    observed_total = 0.0
    observed_per_country: dict[str, float] = {cc: 0.0 for cc in participants}
    for c in contributions:
        country = c.contributing_country
        if country == "GLOBAL" or country not in participants:
            continue
        observed_per_country[country] += c.final_contribution
        observed_total += c.final_contribution

    out: list[dict] = []
    floor = 1.0 - (divergence_threshold_pct / 100.0)
    ceiling = 1.0 + (divergence_threshold_pct / 100.0)
    for cc, p in participants.items():
        cfg_share = configured_share[cc]
        obs_share = (observed_per_country[cc] / observed_total
                     if observed_total > 0 else 0.0)
        utilization = (obs_share / cfg_share if cfg_share > 0 else 0.0)
        utilization_pct = round(utilization * 100, 1)

        flag = "normal"
        reason = ""
        note: Optional[str] = None
        # Underperformance flag: only fires when configured_weight is
        # high enough that silence is genuinely surprising.
        if (p.weight >= _LOW_WEIGHT_FLOOR
                and observed_total > 0
                and utilization < floor):
            flag = "ADVISORY_REVIEW_NEEDED"
            reason = (
                f"configured share {cfg_share:.2f} vs observed "
                f"{obs_share:.2f} (utilization {utilization_pct:.0f}% < "
                f"{int(floor * 100)}% threshold)"
            )
        elif observed_total > 0 and utilization > ceiling:
            note = "overperforming"

        row = {
            "country": cc,
            "configured_weight": round(p.weight, 3),
            "configured_share": round(cfg_share, 3),
            "observed_share": round(obs_share, 3),
            "utilization_pct": utilization_pct,
            "flag": flag,
            "reason": reason,
        }
        if note:
            row["note"] = note
        out.append(row)
    return out


def compute_weight_utilization_timeseries(
    scenario,
    rows: list[tuple[float, str, float]],
    hours: int = 168,
    bucket_count: int = 12,
) -> dict:
    """Time-bucketed observed_share / utilization_pct per participant.

    Slices the lookback window into N equal buckets and computes the
    per-country observed share + configured-weight utilization for each
    bucket. Used by the weight_advisory timeseries variant so analysts
    can see whether a participant's underperformance is worsening or
    recovering before deciding whether to edit the static weight.

    rows: (logged_at_ts, country, contribution_total). GLOBAL rows are
    excluded from the share denominator (same convention as the point-
    in-time helper). Out-of-range rows are silently dropped.
    """
    participants = getattr(scenario, "participants", {}) or {}
    bucket_count = max(1, int(bucket_count))
    hours = max(1, int(hours))

    now = time.time()
    window_start = now - hours * 3600
    bucket_secs = (hours * 3600) / bucket_count
    midpoints = [
        window_start + bucket_secs * (i + 0.5)
        for i in range(bucket_count)
    ]

    total_weight = sum(p.weight for p in participants.values())
    configured_share = {
        cc: (p.weight / total_weight if total_weight > 0 else 0.0)
        for cc, p in participants.items()
    }

    # bucket_idx -> {country: total}
    per_bucket: list[dict[str, float]] = [
        {cc: 0.0 for cc in participants} for _ in range(bucket_count)
    ]
    per_bucket_total = [0.0] * bucket_count

    for ts, country, total in rows:
        if ts < window_start or ts > now:
            continue
        idx = int((ts - window_start) / bucket_secs)
        if idx >= bucket_count:
            idx = bucket_count - 1
        if country == "GLOBAL" or country not in participants:
            continue
        per_bucket[idx][country] += float(total)
        per_bucket_total[idx] += float(total)

    series: dict[str, list[dict]] = {cc: [] for cc in participants}
    for i in range(bucket_count):
        bucket_total = per_bucket_total[i]
        for cc in participants:
            obs = per_bucket[i][cc]
            obs_share = (obs / bucket_total) if bucket_total > 0 else 0.0
            cfg = configured_share[cc]
            util = (obs_share / cfg) if cfg > 0 else 0.0
            series[cc].append({
                "observed_share": round(obs_share, 4),
                "utilization_pct": round(util * 100, 1),
            })

    return {"buckets": midpoints, "series": series}
