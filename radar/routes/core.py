"""radar.routes.core -- Main API endpoints: app_config and threat_data scoring loop."""
from __future__ import annotations
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import jsonify, request
from radar.config import *  # noqa: F403
from radar.models import RationaleEntry
from radar import state as st
from radar.state import _global_cache_lock
from radar.database import db as _db
from radar.scoring import (
    register_sequence_event, compute_sequence_bonus,
    compute_hod_zscore, record_hod_sample,
    get_fallback_coord, fetch_cf_data_cached,
    parse_origins, calculate_overlap, fetch_asn_origins,
    compute_confidence, compute_adaptive_zscore,
    compute_origin_entropy, track_entropy_change,
)
from radar.ws import emit_threat_update, emit_ambush_alert, emit_sequence_event
from radar.notifications import notify_threat_level_change, notify_sequence_complete
from radar.sensors.checkhost import CHECKHOST_NODES
from radar.sensors.telegram import TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD, TelegramMirrorSensor
import radar.routes as _routes
from radar.routes import bp
from radar.engine import WeightedConvergenceEngine

@bp.route("/api/app_config", methods=["GET"])
def app_config():
    return jsonify({
        "default_core": DEFAULT_CORE,
        "default_correlates": DEFAULT_CORRELATES,
        "default_adversaries": DEFAULT_ADVERSARIES,
        "default_pins": DEFAULT_PINS,
        "strategic_blocs": STRATEGIC_BLOCS,
        "country_bloc_tags": COUNTRY_BLOC_TAGS,
        # Adversary options: hostile state actors monitored from a Western/allied-nation perspective.
        # Scope is intentionally limited to states formally designated as threats by US/EU/Japan/Five Eyes:
        # RU (Russia), CN (China), IR (Iran), KP (North Korea), BY (Belarus/RU proxy).
        # States with offensive cyber capability that are allies or partners (US, UK, IL, AU, etc.)
        # are excluded by design — this system monitors threats TO the allied network, not FROM it.
        # Proxy adversaries (e.g. BY under RUSSIA) are declared in geo_data.json under
        # their parent bloc's "proxy_adversaries" field to keep schema and code in sync.
        "adversary_options": [
            {"code": bloc["adversary"], "bloc": bloc_key, "label": bloc["label"], "color": bloc["color"]}
            for bloc_key, bloc in STRATEGIC_BLOCS.items()
            if "adversary" in bloc
        ] + [
            {"code": p["code"], "bloc": bloc_key, "label": p["label"], "color": p["color"]}
            for bloc_key, bloc in STRATEGIC_BLOCS.items()
            for p in bloc.get("proxy_adversaries", [])
        ],
        "available_countries": [
            {"code": code, "name": info["name"], "region": COUNTRY_REGIONS.get(code, "Other"),
             "lat": info["lat"], "lng": info["lng"]}
            for code, info in sorted(COUNTRY_COORDS.items(), key=lambda x: x[1]["name"])
        ],
    })

@bp.route("/api/threat_data", methods=["GET"])
def get_threat_data():
    current_time = time.time()
    targets_param  = request.args.get("targets", ",".join(DEFAULT_PINS)); requested_targets = [t.strip().upper() for t in targets_param.split(",") if t.strip()]
    correlates_param = request.args.get("correlates", ",".join(DEFAULT_CORRELATES)); correlate_targets = [t.strip().upper() for t in correlates_param.split(",") if t.strip()]
    adv_param = request.args.get("adversaries", ",".join(DEFAULT_ADVERSARIES)); adversary_states = [a.strip().upper() for a in adv_param.split(",") if a.strip()]
    core_theater = request.args.get("core", DEFAULT_CORE).strip().upper()
    force_sync   = request.args.get("force", "false").lower() == "true"
    
    # HITL Analyst MUTE parameters
    muted_sensors = [s.strip() for s in request.args.get("muted", "").split(",") if s.strip()]

    required_keys = set(requested_targets + correlate_targets)
    if core_theater: required_keys.add(core_theater)

    strategic_theaters_set = set([core_theater] + correlate_targets)
    
    sensor_context = {
        "all_targets": list(required_keys),
        "strategic_theaters": list(strategic_theaters_set),
        "adversary_states": adversary_states,
        "cf_headers": CF_HEADERS, "owm_api_key": OWM_API_KEY,
        "weather_conditions": {}, "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD,
        "gdelt_history_window": GDELT_HISTORY_WINDOW
    }

    # Sensors are individually scheduled in the background.
    # Immediate fetch only on force_sync (SYNC button). Do not wait on missing_data.
    # (At startup, background threads are fetching in parallel; waiting for sync would
    #  block for minutes on slow sensors like PeeringDB/AIS).
    if force_sync:
        executor = ThreadPoolExecutor(max_workers=10)
        futures = [executor.submit(sensor.fetch, sensor_context)
                   for sensor in _routes.registry._sensors.values() if sensor.enabled]
        try:
            for future in as_completed(futures, timeout=60):
                try:
                    future.result()
                except Exception:
                    pass
        except TimeoutError:
            # Use cached data for timed-out sensors.
            # Let them complete in the background and update the cache.
            pass
        finally:
            executor.shutdown(wait=False, cancel_futures=False)

    if (current_time - st.global_cache.get("time", 0) > SCORE_REFRESH_SEC) or force_sync:
        # Extract required states from caches
        cf_sensor = _routes.registry.get("cloudflare_radar")
        _cf_cache = cf_sensor.get_cache() if cf_sensor else {}
        cf_bgp_hijacks = _cf_cache.get("bgp_hijacks", [])
        cf_bgp_leaks = _cf_cache.get("bgp_leaks", [])
        ioda_sensor = _routes.registry.get("ioda_bgp")
        _ioda_cache = ioda_sensor.get_cache() if ioda_sensor else {}
        ioda_data = _ioda_cache.get("statuses", {})
        ioda_details = _ioda_cache.get("ioda_details", {})
        ioda_source = _ioda_cache.get("source", "unknown")
        owm_sensor = _routes.registry.get("openweather")
        weather_conditions = owm_sensor.get_cache().get("conditions", {}) if owm_sensor else {}
        opensky_sensor = _routes.registry.get("opensky")
        airspace_data = opensky_sensor.get_cache().get("airports", {}) if opensky_sensor else {}
        gdelt_sensor = _routes.registry.get("gdelt")
        gdelt_tones = gdelt_sensor.get_cache().get("gdelt_tones", {}) if gdelt_sensor else {}
        peeringdb_sensor = _routes.registry.get("peeringdb_ixp")
        ixp_data = peeringdb_sensor.get_cache().get("ixp_data", {}) if peeringdb_sensor else {}
        bgp_routing_sensor = _routes.registry.get("ripe_bgp")
        bgp_routing_data = bgp_routing_sensor.get_cache().get("routing_stats", {}) if bgp_routing_sensor else {}
        nasa_firms_sensor = _routes.registry.get("nasa_firms")
        nasa_firms_data = nasa_firms_sensor.get_cache().get("anomalies", []) if nasa_firms_sensor else []
        threatfox_sensor = _routes.registry.get("threatfox")
        threatfox_data = threatfox_sensor.get_cache().get("hits", {}) if threatfox_sensor else {}
        # Fetch additional sensor data (v8)
        rss_narrative_sensor = _routes.registry.get("rss_narrative")
        narrative_data = rss_narrative_sensor.get_cache().get("narratives", {}) if rss_narrative_sensor else {}
        isr_hotspot_sensor = _routes.registry.get("isr_hotspot")
        isr_data = isr_hotspot_sensor.get_cache().get("isr_data", {}) if isr_hotspot_sensor else {}
        ais_maritime_sensor = _routes.registry.get("ais_maritime")
        ais_dark_gaps        = ais_maritime_sensor.get_cache().get("dark_gaps", []) if ais_maritime_sensor else []
        ais_stationary       = ais_maritime_sensor.get_cache().get("stationary_anomalies", []) if ais_maritime_sensor else []
        ais_has_anomaly      = ais_maritime_sensor.get_cache().get("has_anomaly", False) if ais_maritime_sensor else False
        # Fetch additional sensor data (v9)
        telegram_mirror_sensor = _routes.registry.get("telegram_mirror")
        telegram_data          = telegram_mirror_sensor.get_cache().get("telegram", {}) if telegram_mirror_sensor else {}
        check_host_sensor      = _routes.registry.get("check_host")
        checkhost_data         = check_host_sensor.get_cache().get("check_host", {}) if check_host_sensor else {}
        greynoise_sensor       = _routes.registry.get("greynoise")
        greynoise_data         = greynoise_sensor.get_cache().get("greynoise", {}) if greynoise_sensor else {}
        # Phase 2: Space Weather sensor
        space_weather_sensor   = _routes.registry.get("space_weather")
        space_weather_data     = space_weather_sensor.get_cache().get("space_weather", {}) if space_weather_sensor else {}
        sw_suppress            = space_weather_data.get("suppress_physical", False)

        airspace_anomalies, noise_filters_applied = [], []
        for code, ainfo in airspace_data.items():
            count = ainfo.get("count", -1)
            if count < 0: ainfo["status"] = "ERROR"; continue
            bl = _db.airspace_get(code)
            if not bl: bl = {"readings": [], "avg": 0.0}
            bl["readings"] = bl.get("readings", [])
            bl["readings"].append(count); bl["readings"] = bl["readings"][-AIRSPACE_WINDOW:]
            n = len(bl["readings"])
            bl["avg"] = sum(bl["readings"]) / n if n > 0 else 0.0
            ainfo["baseline_avg"] = round(bl["avg"], 1); ainfo["baseline_n"] = n

            # HOD tracking: record one entry per UTC hour bucket per airport
            _as_hour_bucket = int(current_time // 3600) * 3600
            if "hod" not in bl: bl["hod"] = []
            _as_hod_entries = bl["hod"]
            if not _as_hod_entries or _as_hod_entries[-1][0] != _as_hour_bucket:
                _as_hod_entries.append((_as_hour_bucket, count))
                bl["hod"] = _as_hod_entries[-(HOD_BASELINE_DAYS * 24):]
            _cur_as_hod = (_as_hour_bucket // 3600) % 24
            _as_same_hour = [c for (ts, c) in bl["hod"]
                             if (ts // 3600) % 24 == _cur_as_hod and ts < _as_hour_bucket]
            _db.airspace_set(code, bl)

            if n < 3 or bl["avg"] < 1:
                ainfo["status"] = "BASELINE_BUILDING"; ainfo["drop_pct"] = 0.0; continue

            drop_ratio = max(0.0, (bl["avg"] - count) / bl["avg"]); ainfo["drop_pct"] = round(drop_ratio * 100, 1)
            weather_suppressed = weather_conditions.get(code, {}).get("is_severe", False)

            # HOD Z-score severity when enough same-hour samples exist
            _n_as_hod = len(_as_same_hour)
            if _n_as_hod >= HOD_MIN_SAME_HOUR:
                _ah_mean = sum(_as_same_hour) / _n_as_hod
                _ah_std  = max((sum((x - _ah_mean)**2 for x in _as_same_hour) / _n_as_hod) ** 0.5, 0.5)
                _ah_z    = (count - _ah_mean) / _ah_std
                ainfo["hod_z"] = round(_ah_z, 2); ainfo["hod_n"] = _n_as_hod
                severity = "CLOSURE" if _ah_z < -3.0 else "ANOMALY" if _ah_z < -2.0 else "NORMAL"
            else:
                ainfo["hod_z"] = None; ainfo["hod_n"] = _n_as_hod
                severity = "CLOSURE" if drop_ratio >= (1.0 - AIRSPACE_CLOSURE_THRESHOLD) else \
                           "ANOMALY" if drop_ratio >= (1.0 - AIRSPACE_ANOMALY_THRESHOLD) else "NORMAL"

            if severity in ("CLOSURE", "ANOMALY"):
                if weather_suppressed:
                    ainfo["status"] = "WEATHER_NOISE"; noise_filters_applied.append(f"weather_noise@{code}: airspace {severity.lower()} suppressed")
                else:
                    ainfo["status"] = severity
                    airspace_anomalies.append({"code": code, "airport": ainfo.get("airport", code), "count": count, "baseline": ainfo["baseline_avg"], "drop_pct": ainfo["drop_pct"], "severity": severity, "lat": ainfo.get("lat"), "lng": ainfo.get("lng")})
            else: ainfo["status"] = "NORMAL"

        degraded_targets_raw, degraded_targets_effective = [], []
        g_l3 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target", {"dateRange": CURRENT_DATE_RANGE, "format": "json"}))
        g_l7 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target", {"dateRange": CURRENT_DATE_RANGE, "format": "json"}))

        target_details, origin_distributions, origin_distributions_l3, origin_distributions_l7 = {}, {}, {}, {}
        adversary_strikes, vector_shifts = [], []

        for t in list(required_keys):
            if ioda_data.get(t, "NORMAL") == "BGP_OUTAGE":
                degraded_targets_raw.append(t)
                if weather_conditions.get(t, {}).get("is_severe", False): noise_filters_applied.append(f"weather_noise@{t}: BGP outage suppressed")
                else: degraded_targets_effective.append(t)

        for t in required_keys:
            b_data = _db.baseline_get(t)
            if not b_data or (current_time - b_data.get("time", 0) > 86400):
                b_l3 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin", {"location": t, "dateRange": BASELINE_DATE_RANGE, "format": "json"}, ttl=86400))
                b_l7 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin", {"location": t, "dateRange": BASELINE_DATE_RANGE, "format": "json"}, ttl=86400))
                _db.baseline_set(t, {"l3": b_l3, "l7": b_l7}, current_time)
                b_data = _db.baseline_get(t)
            g_l3_share_display, g_l7_share_display = g_l3.get(t, 0.0), g_l7.get(t, 0.0)
            g_l3_share, g_l7_share = max(g_l3_share_display, 0.1), max(g_l7_share_display, 0.1)
            global_target_share = (g_l3_share_display + g_l7_share_display) / 2.0

            o_l3 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin", {"location": t, "dateRange": CURRENT_DATE_RANGE, "format": "json"}))
            o_l7 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin", {"location": t, "dateRange": CURRENT_DATE_RANGE, "format": "json"}))

            state_asn_hits = {}
            if t in strategic_theaters_set:
                for asn_key in fetch_asn_origins(t):
                    if asn_key in STATE_ASNS: state_asn_hits.setdefault(STATE_ASNS[asn_key], []).append(asn_key)

            combined_sources, normalized_dist, normalized_dist_l3, normalized_dist_l7 = {}, {}, {}, {}
            target_weighted_spike, total_local_pct, target_l3_spike_sum, target_l7_spike_sum = 0.0, 0.0, 0.0, 0.0
            all_origin_codes = set(o_l3) | set(o_l7)

            # ── Spike anti-inflation guard ──
            # Skip spike computation when baseline data is empty (at startup or CF API error).
            # Computing with an empty baseline sets all origins to the 0.5% minimum, causing 90×+ false positives.
            has_baseline = bool(b_data.get("l3") or b_data.get("l7"))

            for code in all_origin_codes:
                local_l3_pct, local_l7_pct = o_l3.get(code, 0.0), o_l7.get(code, 0.0)
                current_local_pct = max(local_l3_pct, local_l7_pct)

                _bl3 = b_data.get("l3", {})
                _bl7 = b_data.get("l7", {})
                is_new_actor = (code not in _bl3) and (code not in _bl7)
                # Adversary states (CN/RU/KP etc.) use a lower baseline floor to detect even small attacks.
                # Non-adversary states use a higher floor (3%) to suppress noise.
                # Example: KP at baseline 0.1% → current 2% correctly detected as a 4× spike.
                is_adversary_origin = code in adversary_states
                _floor_new   = 0.5 if is_adversary_origin else 3.0  # new actor (not in baseline)
                _floor_exist = 0.5 if is_adversary_origin else 2.0  # existing actor
                base_l3 = max(_bl3.get(code, _floor_new), _floor_new if code not in _bl3 else _floor_exist)
                base_l7 = max(_bl7.get(code, _floor_new), _floor_new if code not in _bl7 else _floor_exist)
                l3_spike = (local_l3_pct / base_l3) if local_l3_pct > 0 else 0.0
                l7_spike = (local_l7_pct / base_l7) if local_l7_pct > 0 else 0.0
                # Cap spike multiplier at 25× (prevent extreme amplification from statistical noise)
                spike_factor = min(max(l3_spike, l7_spike), 25.0)

                normalized_dist_l3[code], normalized_dist_l7[code], normalized_dist[code] = local_l3_pct, local_l7_pct, current_local_pct

                # Include in spike aggregation only when baseline exists and absolute value is significant (≥1%)
                if has_baseline and current_local_pct >= 1.0:
                    target_weighted_spike += spike_factor * current_local_pct
                    target_l3_spike_sum += l3_spike * current_local_pct
                    target_l7_spike_sum += l7_spike * current_local_pct
                    total_local_pct += current_local_pct

                global_l3_weight = g_l3_share * (local_l3_pct / 100.0); global_l7_weight = g_l7_share * (local_l7_pct / 100.0)
                total_global_weight = global_l3_weight + global_l7_weight

                is_direct_strike = False
                if code in adversary_states and t in strategic_theaters_set and spike_factor >= 4.0 and current_local_pct > 3.0:
                    adversary_strikes.append({"actor": code, "target": t, "spike": round(spike_factor, 1), "pct": round(current_local_pct, 1)})
                    is_direct_strike = True

                per_origin_l7_shift = (l7_spike >= 2.5 and l7_spike > l3_spike * 1.5 and local_l7_pct > 1.5)
                is_state_asn = code in state_asn_hits
                confidence = compute_confidence(spike_factor, code, is_new_actor, is_state_asn)

                if total_global_weight > 0.01 or is_direct_strike:
                    coord = COUNTRY_COORDS.get(code) or get_fallback_coord(code)
                    combined_sources[code] = {"lat": coord["lat"], "lng": coord["lng"], "name": coord["name"], "code": code, "weight": total_global_weight, "l3_weight": global_l3_weight, "l7_weight": global_l7_weight, "spike_factor": round(spike_factor, 2), "l3_spike": round(l3_spike, 2), "l7_spike": round(l7_spike, 2), "is_l7_shift": per_origin_l7_shift, "is_new_actor": is_new_actor, "is_state_asn": is_state_asn, "state_asns": state_asn_hits.get(code, []), "confidence": confidence}

            origin_distributions[t], origin_distributions_l3[t], origin_distributions_l7[t] = normalized_dist, normalized_dist_l3, normalized_dist_l7
            # Floor normalization denominator at 5% (prevents avg_spike overestimation at low traffic)
            avg_l3_spike = target_l3_spike_sum / max(total_local_pct, 5.0); avg_l7_spike = target_l7_spike_sum / max(total_local_pct, 5.0)
            shift_actors = [s["code"] for s in combined_sources.values() if s.get("is_l7_shift")]
            is_vector_shift = ((avg_l7_spike >= 2.5 and avg_l7_spike > avg_l3_spike * 1.5) or len(shift_actors) > 0)
            if is_vector_shift and t in strategic_theaters_set: vector_shifts.append(t)

            avg_spike_record = round(target_weighted_spike / max(total_local_pct, 5.0), 2)
            _db.series_append(t, "combined", avg_spike_record)
            _db.series_append(t, "l3", round(avg_l3_spike, 2))
            _db.series_append(t, "l7", round(avg_l7_spike, 2))
            # Update timestamped time series (for derivative computation)
            _db.ts_append(t, current_time, avg_spike_record)
            # Record HOD (Hour-of-Day) sample for strategic theaters only
            if t in strategic_theaters_set:
                record_hod_sample(t, current_time, avg_spike_record)

            # Origin distribution entropy tracking
            _origin_entropy = compute_origin_entropy(normalized_dist)
            _entropy_track = track_entropy_change(t, _origin_entropy) if t in strategic_theaters_set else {"current": _origin_entropy, "moving_avg": _origin_entropy, "delta_pct": 0.0, "shift_label": "N/A"}

            target_details[t] = {"global_share": global_target_share, "global_share_l3": g_l3_share_display, "global_share_l7": g_l7_share_display, "avg_spike": avg_spike_record, "avg_l3_spike": round(avg_l3_spike, 2), "avg_l7_spike": round(avg_l7_spike, 2), "is_vector_shift": is_vector_shift, "shift_actors": shift_actors, "sources": list(combined_sources.values()), "origin_entropy": _entropy_track}

        correlations, correlations_l3, correlations_l7 = {}, {}, {}
        if core_theater in origin_distributions:
            for t in correlate_targets:
                if t != core_theater and t in origin_distributions:
                    key = f"{core_theater}-{t}"
                    correlations[key]    = calculate_overlap(origin_distributions[core_theater], origin_distributions[t])
                    correlations_l3[key] = calculate_overlap(origin_distributions_l3.get(core_theater, {}), origin_distributions_l3.get(t, {}))
                    correlations_l7[key] = calculate_overlap(origin_distributions_l7.get(core_theater, {}), origin_distributions_l7.get(t, {}))

        elevated_theaters = [t for t in strategic_theaters_set if target_details.get(t, {}).get("avg_spike", 0) > 3.0]
        is_coordinated = len(elevated_theaters) >= 2

        core_spike     = target_details.get(core_theater, {}).get("avg_spike", 0)
        core_degraded  = core_theater in degraded_targets_effective
        core_shifted   = core_theater in vector_shifts
        # State-directed coordinated ops typically show 20–35% overlap. 45%+ indicates large civilian botnet.
        high_correlation = any(v > 30.0 for v in correlations.values())
        major_adversary  = len(adversary_strikes) > 0
        tl1_hard = core_spike > 5.0 and core_degraded

        rationale: list[RationaleEntry] = []

        def _sensor_conf(sensor_obj, sample_count=0, baseline_samples=0):
            """Compute confidence for a sensor, returning 1.0 if sensor is None."""
            if sensor_obj is None:
                return 1.0
            return sensor_obj.compute_confidence(sample_count, baseline_samples)

        def add_rat(sensor, domain, status, value, score, fired_reason, is_suppressed=False, suppress_reason=None, confidence=1.0):
            _is_muted = (sensor in muted_sensors) or is_suppressed
            _s_reason = "Analyst Muted (HITL)" if (sensor in muted_sensors) else suppress_reason
            rationale.append(RationaleEntry(sensor=sensor, domain=domain, status=status, value=value, score=score, fired_reason=fired_reason, suppressed=_is_muted, suppress_reason=_s_reason, confidence=confidence))

        if not (cf_sensor and cf_sensor.enabled):
            add_rat("cloudflare_radar", "cyber", "DISABLED", "sensor off", 0, None)
        else:
            # HOD-normalized Z-score spike detection.
            # During warmup (<7 same-hour samples) fall back to raw ratio thresholds.
            hod_z, hod_valid, hod_n = compute_hod_zscore(core_theater, core_spike, current_time)
            if hod_valid:
                # Z-score thresholds: 1.5σ / 2.5σ / 3.5σ  → +1 / +2 / +3
                spike_score = (1 if hod_z > 1.5 else 0) + (1 if hod_z > 2.5 else 0) + (1 if hod_z > 3.5 else 0)
                spike_fired = hod_z > 1.5
                spike_value = f"HOD Z={hod_z:.2f} ({core_spike:.2f}x, n={hod_n})"
                spike_reason = f"HOD Z-score={hod_z:.2f} — spike anomalous vs same-hour 28d baseline" if spike_fired else None
            else:
                # Warmup fallback: raw ratio thresholds (2x / 4x / 6x)
                spike_score = (1 if core_spike > 2.0 else 0) + (1 if core_spike > 4.0 else 0) + (1 if core_spike > 6.0 else 0)
                spike_fired = core_spike > 2.0
                spike_value = f"{core_spike:.2f}x (HOD warmup {hod_n}/{HOD_MIN_SAME_HOUR})"
                spike_reason = f"Core theater spike exceeds 2x baseline (HOD warmup)" if spike_fired else None
            # Phase 2: Adaptive Z-score tracking (update running statistics)
            az_score, az_adaptive, az_threshold, az_n = compute_adaptive_zscore(
                "cf_spike_core", core_theater, core_spike, fallback_threshold=2.0)
            if az_adaptive and spike_value:
                spike_value += f" [AZ={az_score:.2f} n={az_n}]"
            _cf_conf = _sensor_conf(cf_sensor, sample_count=hod_n, baseline_samples=hod_n)
            add_rat("cf_spike_core", "cyber", "FIRED" if spike_fired else "OK", spike_value, spike_score, spike_reason, confidence=_cf_conf)
            max_overlap = max(correlations.values(), default=0.0)
            add_rat("cf_botnet_overlap", "cyber", "FIRED" if high_correlation else "OK", f"{max_overlap:.1f}% overlap", 1 if high_correlation else 0, "Shared botnet >30%" if high_correlation else None, confidence=_cf_conf)
            # Graduated L3→L7 vector shift scoring: moderate +1, severe +2
            _core_l7s = target_details.get(core_theater, {}).get("avg_l7_spike", 0)
            _core_l3s = target_details.get(core_theater, {}).get("avg_l3_spike", 0)
            _shift_severe = core_shifted and _core_l7s >= 5.0 and _core_l7s > _core_l3s * 2.0
            _shift_score = 2 if _shift_severe else (1 if core_shifted else 0)
            _shift_reason = (f"Severe L7 escalation (L7={_core_l7s:.1f}x vs L3={_core_l3s:.1f}x)" if _shift_severe
                             else "L7 application-layer escalation detected" if core_shifted else None)
            add_rat("cf_vector_shift", "cyber", "FIRED" if core_shifted else "OK", f"theaters={vector_shifts} L7={_core_l7s:.1f}x L3={_core_l3s:.1f}x", _shift_score, _shift_reason, confidence=_cf_conf)
            # Count-proportional adversary scoring: 1-2 actors → +2, ≥3 actors → +3
            _adv_count = len(adversary_strikes)
            _adv_score = 3 if _adv_count >= 3 else (2 if _adv_count >= 1 else 0)
            add_rat("cf_adversary_strike", "cyber", "FIRED" if major_adversary else "OK", f"{_adv_count} strike(s)", _adv_score, f"Adversary state direct strike ({_adv_count} actors)" if major_adversary else None, confidence=_cf_conf)
            add_rat("cf_coordinated", "cyber", "FIRED" if is_coordinated else "OK", f"theaters={elevated_theaters}", 1 if is_coordinated else 0, f"Simultaneous surge" if is_coordinated else None, confidence=_cf_conf)

        if not (ioda_sensor and ioda_sensor.enabled):
            add_rat("ioda_bgp", "physical", "DISABLED", "sensor off", 0, None)
        else:
            weather_suppressed_bgp = [t for t in degraded_targets_raw if t not in degraded_targets_effective]
            # Enrich BGP value with IODA datasource details when available
            _ioda_core_detail = ioda_details.get(core_theater, {})
            _ioda_src_count = _ioda_core_detail.get("source_count", 0)
            _ioda_level = _ioda_core_detail.get("level", "")
            bgp_value = f"bgp={'OUTAGE' if core_degraded else 'NORMAL'}"
            if _ioda_src_count > 0:
                bgp_value += f" ioda={_ioda_level}({_ioda_src_count}src)"
            bgp_value += f" [{ioda_source}]"
            if weather_suppressed_bgp: bgp_value += f" weather_muted={weather_suppressed_bgp}"
            _wx_suppressed = (core_theater in weather_suppressed_bgp)
            _sw_bgp_suppressed = sw_suppress and core_degraded and not _wx_suppressed
            _bgp_suppress = _wx_suppressed or _sw_bgp_suppressed
            _bgp_suppress_reason = (f"Weather-muted: {weather_suppressed_bgp}" if _wx_suppressed
                                    else space_weather_data.get("suppress_reason") if _sw_bgp_suppressed else None)
            # Multi-source corroboration: IODA proper with ≥2 datasources = higher confidence
            _ioda_fired_reason = "BGP anomaly confirmed" if core_degraded else None
            if core_degraded and _ioda_src_count >= 2:
                _ioda_fired_reason = (
                    f"BGP anomaly confirmed by {_ioda_src_count} independent IODA datasources "
                    f"({', '.join(_ioda_core_detail.get('sources', {}).keys())})"
                )
            add_rat("ioda_bgp", "physical", "FIRED" if core_degraded else "OK", bgp_value, 1 if core_degraded else 0, _ioda_fired_reason, is_suppressed=_bgp_suppress, suppress_reason=_bgp_suppress_reason, confidence=_sensor_conf(ioda_sensor))

        if not (opensky_sensor and opensky_sensor.enabled):
            add_rat("opensky", "physical", "DISABLED", "sensor off", 0, None)
        else:
            core_airspace = airspace_data.get(core_theater, {})
            airspace_status = core_airspace.get("status", "NO_DATA")
            airspace_score, airspace_fired, airspace_reason = 0, False, None
            if airspace_status == "CLOSURE": airspace_score, airspace_fired, airspace_reason = 3, True, f"Airport near-total closure"
            elif airspace_status == "ANOMALY": airspace_score, airspace_fired, airspace_reason = 2, True, f"Airspace anomaly"
            airspace_value = f"{core_airspace.get('airport','N/A')}: {core_airspace.get('count','?')} ac" if core_airspace else "No airport data"
            _as_wx_suppress = (airspace_status == "WEATHER_NOISE")
            _as_sw_suppress = sw_suppress and airspace_fired and not _as_wx_suppress
            _as_suppress = _as_wx_suppress or _as_sw_suppress
            _as_suppress_reason = ("Severe weather detected" if _as_wx_suppress
                                   else space_weather_data.get("suppress_reason") if _as_sw_suppress else None)
            add_rat("opensky", "physical", "FIRED" if airspace_fired else ("SUPPRESSED" if _as_suppress else "OK"), airspace_value, airspace_score, airspace_reason, is_suppressed=_as_suppress, suppress_reason=_as_suppress_reason, confidence=_sensor_conf(opensky_sensor))

        if not (owm_sensor and owm_sensor.enabled):
            add_rat("openweather", "physical", "DISABLED", "sensor off", 0, None)
        else:
            core_weather = weather_conditions.get(core_theater, {})
            add_rat("openweather", "physical", "OK", f"{core_theater}: {core_weather.get('severity', 'NORMAL')}", 0, None, suppress_reason=f"Active noise filter" if core_weather.get("is_severe") else None)

        if not (gdelt_sensor and gdelt_sensor.enabled):
            add_rat("gdelt", "info", "DISABLED", "sensor off", 0, None)
        else:
            core_tone = gdelt_tones.get(core_theater, {})
            tone_status, gdelt_alert = core_tone.get("status", "NO_DATA"), core_tone.get("status") == "ALERT"
            add_rat("gdelt", "info", "SUPPRESSED" if tone_status == "WEATHER_NOISE" else "FIRED" if gdelt_alert else "OK", tone_status, 1 if gdelt_alert else 0, "Media tone collapse" if gdelt_alert else None, is_suppressed=(tone_status == "WEATHER_NOISE"), suppress_reason="Severe weather detected" if tone_status == "WEATHER_NOISE" else None, confidence=_sensor_conf(gdelt_sensor))

        if not (bgp_routing_sensor and bgp_routing_sensor.enabled):
            add_rat("ripe_bgp", "cyber", "DISABLED", "sensor off", 0, None)
        else:
            core_bgp = bgp_routing_data.get(core_theater, {})
            bgp_anomaly = core_bgp.get("is_anomaly", False)
            _bgp_trend_label = core_bgp.get("trend_label", "")
            _bgp_trend_pct = core_bgp.get("prefix_trend_pct", 0.0)
            _bgp_value = "ANOMALY" if bgp_anomaly else "NORMAL"
            if _bgp_trend_label and _bgp_trend_label != "INSUFFICIENT_DATA":
                _bgp_value += f" trend={_bgp_trend_label}({_bgp_trend_pct:+.2f}%)"
            _bgp_reason = "BGP prefix withdrawal" if bgp_anomaly else None
            # Enrich reason with trend context when withdrawing
            if bgp_anomaly and _bgp_trend_label == "WITHDRAWING":
                _bgp_reason = f"BGP prefix withdrawal (trend: {_bgp_trend_pct:+.2f}% decline across time series)"
            add_rat("ripe_bgp", "cyber", "FIRED" if bgp_anomaly else "OK", _bgp_value, 1 if bgp_anomaly else 0, _bgp_reason, confidence=_sensor_conf(bgp_routing_sensor))

        # CF Radar BGP Hijack/Leak detection (Cyber)
        if cf_sensor and cf_sensor.enabled:
            _core_hijacks = [h for h in cf_bgp_hijacks if h.get("victim_country") == core_theater]
            _core_leaks = [l for l in cf_bgp_leaks if l.get("leak_country") == core_theater]
            _hijack_ongoing = [h for h in _core_hijacks if h.get("is_ongoing")]
            _bgp_event_count = len(_core_hijacks) + len(_core_leaks)
            _bgp_event_fired = len(_hijack_ongoing) > 0 or len(_core_leaks) >= 3
            _bgp_ev_value = f"hijack={len(_core_hijacks)}(ongoing={len(_hijack_ongoing)}) leak={len(_core_leaks)}"
            if _bgp_event_fired:
                _bgp_ev_reason = (
                    f"BGP manipulation detected: {len(_hijack_ongoing)} ongoing hijack(s), "
                    f"{len(_core_leaks)} route leak(s)"
                )
            else:
                _bgp_ev_reason = None
            add_rat("cf_bgp_hijack", "cyber",
                    "FIRED" if _bgp_event_fired else "OK",
                    _bgp_ev_value,
                    1 if _bgp_event_fired else 0,
                    _bgp_ev_reason,
                    confidence=_sensor_conf(cf_sensor))

        # NASA FIRMS (Physical)
        if nasa_firms_sensor and nasa_firms_sensor.enabled:
            has_firms = any(f["code"] == core_theater for f in nasa_firms_data)
            _firms_global_codes = sorted({f["code"] for f in nasa_firms_data})
            if has_firms:
                _firms_val = f"Thermal Anomaly [{core_theater}]"
            elif _firms_global_codes:
                _firms_val = f"Global only [{','.join(_firms_global_codes[:4])}]"
            else:
                _firms_val = "No Anomalies"
            add_rat("nasa_firms", "physical", "FIRED" if has_firms else "OK", _firms_val, 3 if has_firms else 0, "Kinetic Strike Precursor", confidence=_sensor_conf(nasa_firms_sensor))

        # ThreatFox (Cyber)
        if threatfox_sensor and threatfox_sensor.enabled:
            has_tf = core_theater in threatfox_data
            add_rat("threatfox", "cyber", "FIRED" if has_tf else "OK", "APT C2 Hit", 1 if has_tf else 0, "Known APT infra matched", confidence=_sensor_conf(threatfox_sensor))

        if peeringdb_sensor and peeringdb_sensor.enabled:
            add_rat("peeringdb_ixp", "physical", "OK", f"IXP(s) registered", 0, None)

        # ── Additional sensor rationale + Sequence Event registration ──────────────────────

        # RSS narrative burst
        core_narrative = narrative_data.get(core_theater, {})
        narrative_burst = core_narrative.get("is_burst", False)
        narrative_z     = core_narrative.get("z_score", 0.0)
        narrative_status = core_narrative.get("status", "NORMAL")
        if rss_narrative_sensor and rss_narrative_sensor.enabled:
            n_score = 2 if narrative_status == "CRITICAL_BURST" else 1 if narrative_burst else 0
            add_rat("rss_narrative", "info",
                    "FIRED" if narrative_burst else "OK",
                    f"Z={narrative_z:.2f} [{narrative_status}]",
                    n_score,
                    f"Narrative Burst Z={narrative_z:.2f}" if narrative_burst else None,
                    confidence=_sensor_conf(rss_narrative_sensor))
            if narrative_burst:
                register_sequence_event(core_theater, "NARRATIVE_BURST",
                                        {"z_score": narrative_z, "status": narrative_status})

        # ISR hotspot surge
        core_isr = isr_data.get(core_theater, {})
        isr_surge = core_isr.get("is_surge", False)
        isr_count = core_isr.get("count", 0)
        if isr_hotspot_sensor and isr_hotspot_sensor.enabled:
            add_rat("isr_hotspot", "physical",
                    "FIRED" if isr_surge else "OK",
                    f"{isr_count} ISR ac in hotspot",
                    2 if isr_surge else 0,
                    f"ISR surge: {isr_count} aircraft" if isr_surge else None,
                    confidence=_sensor_conf(isr_hotspot_sensor))
            if isr_surge:
                register_sequence_event(core_theater, "ISR_SURGE",
                                        {"count": isr_count, "hotspots": core_isr.get("hotspots", [])})

        # AIS maritime anomaly
        if ais_maritime_sensor and ais_maritime_sensor.enabled:
            core_gaps = [g for g in ais_dark_gaps if any(
                cp["country"] == core_theater for cp in CHOKEPOINTS if cp["name"] == g.get("chokepoint")
            )]
            ais_fired = ais_has_anomaly or len(core_gaps) > 0
            add_rat("ais_maritime", "physical",
                    "FIRED" if ais_fired else "OK",
                    f"dark_gaps={len(ais_dark_gaps)} stationary={len(ais_stationary)}",
                    1 if ais_fired else 0,
                    "AIS Dark Gap / Stationary Anomaly at chokepoint" if ais_fired else None,
                    confidence=_sensor_conf(ais_maritime_sensor))
            if ais_fired:
                register_sequence_event(core_theater, "AIS_DARK_GAP",
                                        {"dark_gaps": len(ais_dark_gaps), "stationary": len(ais_stationary)})

        # FIRMS → register Sequence Event (reuse existing sensor result)
        has_firms_core = any(f.get("code") == core_theater for f in nasa_firms_data)
        if has_firms_core:
            register_sequence_event(core_theater, "FIRMS_ANOMALY",
                                    {"hotspots": [f for f in nasa_firms_data if f.get("code") == core_theater]})

        # Sync DDoS detection → register Sequence Event (only at high sync + high score)
        if is_coordinated and high_correlation:
            register_sequence_event(core_theater, "SYNC_DDOS",
                                    {"coordinated_theaters": elevated_theaters,
                                     "max_overlap": max(correlations.values(), default=0.0)})

        # ── v9 sensor rationale ────────────────────────────────────────────────

        # Telegram Mirror (Info Domain)
        core_telegram        = telegram_data.get(core_theater, {})
        telegram_intent      = core_telegram.get("has_attack_intent", False)
        telegram_status      = core_telegram.get("status", "CLEAR")
        telegram_active_ch   = core_telegram.get("active_channels", [])
        telegram_z           = core_telegram.get("z_score", 0.0)
        telegram_burst       = core_telegram.get("is_burst", False)
        telegram_confidence  = core_telegram.get("claim_confidence", 1.0)
        if telegram_mirror_sensor and telegram_mirror_sensor.enabled:
            if telegram_status == "CRITICAL_BURST":
                tg_score = 2
            elif telegram_burst or telegram_intent:
                tg_score = 1
            elif telegram_status == "TARGETS_FOUND":
                tg_score = 1
            else:
                tg_score = 0
            # Confidence suppression: low-credibility channels reduce score by 1
            suppressed_by_confidence = False
            if tg_score > 0 and telegram_confidence < TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD:
                tg_score = max(0, tg_score - 1)
                suppressed_by_confidence = True
            fired = tg_score > 0
            detail = f"Z={telegram_z:.2f} [{telegram_status}] conf={telegram_confidence:.2f} ch={telegram_active_ch[:3]}"
            if suppressed_by_confidence:
                detail += " (confidence-suppressed)"
            add_rat("telegram_mirror", "info",
                    "FIRED" if fired else "OK",
                    detail,
                    tg_score,
                    f"Telegram Burst Z={telegram_z:.2f} (conf={telegram_confidence:.2f})" if telegram_burst else
                    f"Attack intent intercepted on Telegram: {telegram_active_ch}" if telegram_intent else
                    "Target URLs found in Telegram channels" if telegram_status == "TARGETS_FOUND" else None,
                    confidence=_sensor_conf(telegram_mirror_sensor))
            if telegram_burst or telegram_intent:
                register_sequence_event(core_theater, "NARRATIVE_BURST", {
                    "source": "telegram_mirror", "channels": telegram_active_ch,
                    "targets": core_telegram.get("target_urls", [])[:5],
                    "z_score": telegram_z,
                })

        # Check-Host (Physical Domain)
        core_checkhost   = checkhost_data.get(core_theater, {})
        ch_status        = core_checkhost.get("status", "UNKNOWN")
        ch_success_rate  = core_checkhost.get("theater_success_rate")
        if check_host_sensor and check_host_sensor.enabled:
            # PARTIAL = 1-2 node failures; capped at +1 for consistency with maskirovka policy.
            # BLACKOUT = all nodes unreachable = severe infra degradation; keep +3.
            ch_score = (3 if ch_status == "BLACKOUT" else 1 if ch_status == "PARTIAL" else 0)
            ch_fired = ch_status in ("BLACKOUT", "PARTIAL")
            _ch_sw_suppress = sw_suppress and ch_fired
            add_rat("check_host", "physical",
                    "FIRED" if ch_fired else ("OK" if ch_status == "OK" else "NO_DATA"),
                    f"{ch_status} success={ch_success_rate:.0%}" if ch_success_rate is not None else ch_status,
                    ch_score,
                    f"Infrastructure availability: {ch_status} (success_rate={ch_success_rate:.0%})" if ch_fired and ch_success_rate is not None else None,
                    is_suppressed=_ch_sw_suppress,
                    suppress_reason=space_weather_data.get("suppress_reason") if _ch_sw_suppress else None,
                    confidence=_sensor_conf(check_host_sensor))

        # GreyNoise (Cyber Domain — noise suppressor)
        core_greynoise     = greynoise_data.get(core_theater, {})
        gn_noise_class     = core_greynoise.get("noise_class", "UNKNOWN")
        gn_suppress        = core_greynoise.get("suppress_confidence", False)
        gn_noise_ratio     = core_greynoise.get("noise_ratio")
        if greynoise_sensor and greynoise_sensor.enabled:
            add_rat("greynoise", "cyber",
                    "SUPPRESSED" if gn_suppress else "OK",
                    f"{gn_noise_class} noise={gn_noise_ratio:.0%}" if gn_noise_ratio is not None else gn_noise_class,
                    0,   # GreyNoise provides suppression only, not a bonus
                    None,
                    is_suppressed=gn_suppress,
                    suppress_reason=f"GreyNoise: {gn_noise_class} — traffic classified as internet background noise" if gn_suppress else None)

        # ── Phase 2: Space Weather noise suppressor ────────────────────────────
        if space_weather_sensor and space_weather_sensor.enabled:
            sw_storm = space_weather_data.get("storm_level", "NONE")
            sw_kp = space_weather_data.get("kp_index", 0)
            sw_xray = space_weather_data.get("xray_class", "A")
            add_rat("space_weather", "physical",
                    "SUPPRESSED" if sw_suppress else "OK",
                    f"Kp={sw_kp:.1f} xray={sw_xray} [{sw_storm}]",
                    0,  # Suppressor only, no bonus score
                    None,
                    is_suppressed=sw_suppress,
                    suppress_reason=space_weather_data.get("suppress_reason") if sw_suppress else None)
            if sw_suppress:
                noise_filters_applied.append(
                    f"space_weather: {space_weather_data.get('suppress_reason', 'geomagnetic storm')}")

        # ── v9 Temporal Coherence analysis ─────────────────────────────────────
        # Build sequence_event_log dict for temporal coherence analysis
        _seq_events_dict = {th: _db.seq_all_events(th) for th in strategic_theaters_set}
        is_c2_sync, coherence_score, temporal_bonus, temporal_detail = \
            _routes.engine.compute_temporal_coherence(_seq_events_dict, list(strategic_theaters_set))

        # ── Asphyxiation flag from Check-Host (CDN masking detection) ───────────
        ch_asphyxiation = core_checkhost.get("asphyxiation", False)

        # ── Cross-theater sensor liveness for Maskirovka confidence upgrade ─────
        # Other sensors are considered "alive" if ≥1 non-core theater's Check-Host
        # or IODA sensor returned a valid (non-error) result recently.
        other_theater_live = False
        for _t in strategic_theaters_set:
            if _t == core_theater:
                continue
            _other_ch = checkhost_data.get(_t, {})
            if _other_ch.get("theater_success_rate") is not None:
                other_theater_live = True
                break
            if ioda_data.get(_t) in ("NORMAL", "BGP_OUTAGE"):
                other_theater_live = True
                break

        # ── v9 Maskirovka detection ─────────────────────────────────────────────
        is_maskirovka, maskirovka_conf, maskirovka_reason = _routes.engine.detect_maskirovka(
            core_degraded=core_degraded,
            narrative_burst=narrative_burst or telegram_intent,
            check_host_status=ch_status,
            telegram_intent=telegram_intent,
            other_sensors_alive=other_theater_live,
        )
        if is_maskirovka:
            # HIGH confidence = +2 score (cross-theater confirmed suppression),
            # MEDIUM confidence = +1 score (no corroborating cross-theater data)
            msk_score = 2 if maskirovka_conf == "HIGH" else 1
            add_rat("maskirovka_flag", "info",
                    "FIRED", f"conf={maskirovka_conf}",
                    msk_score, maskirovka_reason)

        # ── Derivative computation (Velocity / Acceleration / Ambush) ───────────────
        ts_series_core = _db.ts_get(core_theater)
        is_ambush, ambush_z, velocity_val, acceleration_val = _routes.engine.detect_ambush_pattern(ts_series_core)
        if is_ambush:
            add_rat("ddos_acceleration", "cyber",
                    "FIRED", f"Ambush Z={ambush_z:.2f} v={velocity_val:.4f}",
                    2, f"Exponential escalation detected (2nd derivative Z={ambush_z:.2f})")

        # ── (i) Blockade Index → scoring ─────────────────────────────────────────
        # Compute early so it can contribute to rationale before domain_scores
        _bi_ripe_drop = bgp_routing_data.get(core_theater, {}).get("drop_pct", 0.0)
        blockade_index = _routes.engine.compute_blockade_index(
            ddos_intensity=core_spike,
            ripe_drop_pct=_bi_ripe_drop,
            checkhost_success_rate=ch_success_rate,
            asphyxiation=ch_asphyxiation,
        )
        if blockade_index >= 7.0:
            add_rat("blockade_index", "cyber", "FIRED",
                    f"BI={blockade_index:.1f}/10",
                    1, f"Effective infrastructure blockade (BI={blockade_index:.1f})")

        # ── (ii) Asphyxiation → independent signal ───────────────────────────────
        # CDN masking: success_rate OK but latency ≥3× baseline reveals hidden strain
        if ch_asphyxiation:
            add_rat("cdn_asphyxiation", "cyber", "FIRED",
                    "CDN masking detected",
                    1, "CDN masks packet loss but latency tripling reveals infrastructure strain")

        # ── (vi) DDoS-BGP causality enrichment ──────────────────────────────────
        # When CF spike and BGP_OUTAGE co-occur, enrich IODA rationale with causal context
        _cf_fired = any(e.sensor == "cf_spike_core" and e.status == "FIRED" and not e.suppressed for e in rationale)
        _bgp_fired_entry = next((e for e in rationale if e.sensor == "ioda_bgp" and e.status == "FIRED" and not e.suppressed), None)
        if _cf_fired and _bgp_fired_entry:
            _bgp_fired_entry.fired_reason = (
                f"{_bgp_fired_entry.fired_reason} — DDoS-BGP causal link: "
                f"CF spike ({core_spike:.1f}x) concurrent with BGP outage"
            )

        # ── Sequence Bonus computation ──────────────────────────────────────────
        seq_bonus, seq_status, seq_chain = compute_sequence_bonus(core_theater)

        domain_scores = _routes.engine.compute_domain_scores(rationale)

        # ── Phase 2: Feint Detection ─────────────────────────────────────────
        is_feint, feint_primary, feint_distractions, feint_conf, feint_detail = \
            _routes.engine.detect_feint_pattern(domain_scores, rationale)
        if is_feint:
            add_rat("feint_detector", feint_primary, "FIRED", f"conf={feint_conf}",
                    0, feint_detail)

        # Confidence-weighted total: sum(score * confidence) for fired, non-suppressed entries
        total_score = sum(e.score * e.confidence for e in rationale if e.status == "FIRED" and not e.suppressed)
        total_score = round(total_score, 2)
        convergence_score = _routes.engine.compute_convergence_score(domain_scores)
        domain_confidences = _routes.engine.compute_domain_confidences(rationale)
        score_with_bonus, conv_bonus, convergence_level = _routes.engine.apply_convergence_bonus(total_score, domain_scores, domain_confidences)
        # Add Sequence Bonus and Temporal Coherence Bonus to final score
        score_with_bonus += seq_bonus + temporal_bonus
        # Cap final score to prevent bonus stacking from inflating beyond TL1 threshold ceiling
        score_with_bonus = min(score_with_bonus, 15)
        active_domains = sum(1 for s in domain_scores.values() if s > 0)
        tl_raw = _routes.engine.compute_threat_level(score_with_bonus, tl1_hard, active_domains)
        prev_threat = _db.threat_last()
        prev_threat_level = prev_threat[1] if prev_threat else 5
        threat_level, tl_held = _routes.engine.apply_hysteresis(tl_raw, _db.threat_list())
        _db.threat_append(current_time, threat_level)

        # TL Proximity: how close the current score is to TL boundaries
        tl_proximity = _routes.engine.compute_tl_proximity(score_with_bonus, threat_level)

        system_note = _routes.engine.build_system_note(threat_level, domain_scores, convergence_level, rationale, noise_filters_applied, tl_held)

        # Deep analysis result summary
        deep_analytics = {
            "velocity":        round(velocity_val, 6),
            "acceleration":    round(acceleration_val, 8),
            "is_ambush":       is_ambush,
            "ambush_z_score":  ambush_z,
            "sequence_bonus":  seq_bonus,
            "sequence_status": seq_status,
            "sequence_chain":  seq_chain,
            "narrative": {
                "z_score": narrative_z,
                "status":  narrative_status,
                "is_burst": narrative_burst,
            },
            "isr": {
                "count":    isr_count,
                "is_surge": isr_surge,
            },
            "ais": {
                "dark_gaps":   len(ais_dark_gaps),
                "stationary":  len(ais_stationary),
                "has_anomaly": ais_has_anomaly,
            },
            # Blockade Index v9: (DDoS intensity × RIPE delay) / Check-Host success rate
            # asphyxiation=True applies 1.5× weight when CDN masks packet loss but latency triples
            "blockade_index": blockade_index,
            # Temporal Coherence (v9 C2 synchrony analysis)
            "temporal_coherence": {
                "is_c2_sync":     is_c2_sync,
                "coherence_score": coherence_score,
                "bonus":          temporal_bonus,
                "detail":         temporal_detail,
            },
            # Maskirovka deception detection (v9)
            "maskirovka": {
                "detected":    is_maskirovka,
                "confidence":  maskirovka_conf,
                "reason":      maskirovka_reason,
            },
            # Check-Host Survival (v9) — includes detailed data + asphyxiation flag
            "check_host": {
                "theater_success_rate": ch_success_rate,
                "status":              ch_status,
                "url_results":         core_checkhost.get("urls", {}),
                "nodes":               CHECKHOST_NODES,
                "asphyxiation":        ch_asphyxiation,
                # Aggregate per-node OK/FAIL across all checked URLs
                # Aggregate per-node status across all checked URLs.
                # Uses worst-case: FAIL > TIMEOUT > OK > PENDING
                # (preserves TIMEOUT/PENDING so the frontend renders correct dot colors)
                "node_ok": {
                    node: WeightedConvergenceEngine._agg_node_status([
                        url_r["node_ok"][node]
                        for url_r in core_checkhost.get("urls", {}).values()
                        if isinstance(url_r, dict) and node in url_r.get("node_ok", {})
                    ])
                    for node in set(
                        n
                        for url_r in core_checkhost.get("urls", {}).values()
                        if isinstance(url_r, dict)
                        for n in url_r.get("node_ok", {}).keys()
                    )
                },
            },
            # Telegram Mirror (v9) — includes channel/URL details
            "telegram_mirror": {
                "has_intent":          telegram_intent,
                "status":              telegram_status,
                "active_channels":     telegram_active_ch,
                "channels_monitored":  core_telegram.get("channels_monitored", []),
                "target_urls":         core_telegram.get("target_urls", []),
                "theater_breakdown":   telegram_data,
                "recent_hits":         TelegramMirrorSensor._intercept_log[:10],
                "last_poll_ts":        TelegramMirrorSensor._last_poll_ts,
                "last_poll_ok":        TelegramMirrorSensor._last_poll_ok,
            },
            # GreyNoise (v9) — includes tier info
            "greynoise": {
                "noise_class":   gn_noise_class,
                "noise_ratio":   gn_noise_ratio,
                "suppressing":   gn_suppress,
                "gnql_tier":     core_greynoise.get("gnql_tier", "none"),
                "theater_data":  {t: greynoise_data.get(t, {}) for t in (strategic_theaters_set or set())},
            },
            # Origin distribution entropy (attack source diversity tracking)
            "origin_entropy": target_details.get(core_theater, {}).get("origin_entropy"),
            # Phase 2: Space Weather noise suppressor
            "space_weather": {
                "kp_index":           space_weather_data.get("kp_index", 0),
                "kp_forecast_24h":    space_weather_data.get("kp_forecast_24h", 0),
                "xray_class":         space_weather_data.get("xray_class", "A"),
                "storm_level":        space_weather_data.get("storm_level", "NONE"),
                "suppressing":        sw_suppress,
                "suppress_reason":    space_weather_data.get("suppress_reason", ""),
            },
            # BGP Hijack/Leak events from CF Radar
            "bgp_events": {
                "hijacks": cf_bgp_hijacks,
                "leaks": cf_bgp_leaks,
                "core_hijacks": [h for h in cf_bgp_hijacks if h.get("victim_country") == core_theater],
                "core_leaks": [l for l in cf_bgp_leaks if l.get("leak_country") == core_theater],
            },
            # IODA details (multi-datasource outage corroboration)
            "ioda": {
                "source": ioda_source,
                "core_detail": ioda_details.get(core_theater),
                "outage_countries": [code for code, status in ioda_data.items() if status == "BGP_OUTAGE"],
            },
            # Phase 2: Adaptive Z-score status
            "adaptive_zscore": {
                "z_score":    az_score,
                "is_adaptive": az_adaptive,
                "threshold":  az_threshold,
                "samples":    az_n,
                "mode":       "adaptive" if az_adaptive else "warmup",
            },
            # Phase 2: Feint Detection
            "feint": {
                "detected":              is_feint,
                "primary_domain":        feint_primary,
                "distraction_domains":   feint_distractions,
                "confidence":            feint_conf,
                "detail":                feint_detail,
            },
            # Phase 2: Escalation Progress (computed from threat history)
            "escalation": _routes.engine.compute_escalation_progress(
                _db.threat_list(), _db.alert_list(limit=100)),
            # Confidence Propagation: per-domain confidence and TL boundary proximity
            "confidence": {
                "domain_confidences": domain_confidences,
                "min_confidence": round(min(domain_confidences.values()), 3) if domain_confidences else 1.0,
            },
            "tl_proximity": tl_proximity,
        }

        score_breakdown = {
            "core_spike_val": round(core_spike, 2), "core_spike_2x": core_spike > 2.0, "core_spike_4x": core_spike > 4.0, "core_spike_6x": core_spike > 6.0,
            "high_correlation": high_correlation, "core_shifted": core_shifted, "major_adversary": major_adversary, "core_degraded": core_degraded,
            "is_coordinated": is_coordinated, "tl1_hard": tl1_hard, "total_score": total_score,
            "convergence_bonus": conv_bonus, "sequence_bonus": seq_bonus, "temporal_bonus": temporal_bonus,
            "score_with_bonus": score_with_bonus, "threat_raw": tl_raw, "threat_held": tl_held,
            "is_c2_sync": is_c2_sync, "is_maskirovka": is_maskirovka,
        }

        # ioda_overlays: extract BGP_OUTAGE countries from full IODA cache (global display)
        ioda_overlays = [
            {"code": code, "lat": COUNTRY_COORDS[code]["lat"], "lng": COUNTRY_COORDS[code]["lng"],
             "name": COUNTRY_COORDS[code]["name"], "status": "BGP_OUTAGE"}
            for code, status in ioda_data.items()
            if status == "BGP_OUTAGE" and code in COUNTRY_COORDS
        ]

        _new_cache = {
            "time": current_time,
            "data": target_details,
            "strategic": {
                "core_theater": core_theater, "threat_level": threat_level, "threat_score": total_score, "threat_breakdown": score_breakdown,
                "correlations": correlations, "correlations_l3": correlations_l3, "correlations_l7": correlations_l7,
                "adversary_strikes": adversary_strikes, "vector_shifts": vector_shifts,
                "degraded_theaters": [t for t in degraded_targets_effective if t in strategic_theaters_set],
                "degraded_theaters_raw": [t for t in degraded_targets_raw if t in strategic_theaters_set],
                "coordinated_theaters": elevated_theaters if is_coordinated else [],
                "domains": {
                    d: {"score": domain_scores.get(d, 0), "weight": _routes.engine.DOMAIN_WEIGHTS.get(d, 0), "weighted": round(min(domain_scores.get(d, 0), 10) * _routes.engine.DOMAIN_WEIGHTS.get(d, 0), 2), "status": "CRITICAL" if domain_scores.get(d, 0) >= 6 else "ELEVATED" if domain_scores.get(d, 0) >= 3 else "WATCH" if domain_scores.get(d, 0) >= 1 else "NORMAL"} for d in ("cyber", "physical", "info")
                },
                "convergence_score": round(convergence_score, 2), "convergence_level": convergence_level,
                "rationale_matrix": [e.to_dict() for e in rationale], "noise_filters_applied": noise_filters_applied, "system_note": system_note,
                "country_intel": {
                    code: {
                        "weather": weather_conditions.get(code), "airspace": airspace_data.get(code), "gdelt": gdelt_tones.get(code),
                        "bgp_routing": bgp_routing_data.get(code), "ixp_count": ixp_data.get(code, {}).get("count", 0),
                        "ixp_names": [ix["name"] for ix in ixp_data.get(code, {}).get("ixps", [])], "ioda_status": ioda_data.get(code, "NORMAL"),
                        "ioda_detail": ioda_details.get(code),
                        "ioda_source": ioda_source,
                        "is_bgp_degraded": code in degraded_targets_effective,
                    } for code in (strategic_theaters_set | {c for c, s in ioda_data.items() if s == "BGP_OUTAGE"}) if code in COUNTRY_COORDS
                },
                "map_overlays": {
                    "ioda_outages": ioda_overlays, "airspace_anomaly": airspace_anomalies,
                    "weather_events": [{"code": c, "lat": info.get("lat"), "lng": info.get("lng"), "condition": info.get("condition", ""), "description": info.get("description", ""), "severity": info.get("severity", "NORMAL"), "wind_speed": info.get("wind_speed", 0), "is_severe": info.get("is_severe", False)} for c, info in weather_conditions.items() if info.get("severity") in ("SEVERE", "MODERATE")],
                    "gdelt_events": [{"code": c, "lat": COUNTRY_COORDS[c]["lat"], "lng": COUNTRY_COORDS[c]["lng"], "name": COUNTRY_COORDS[c]["name"], "tone_current": info.get("tone_current"), "tone_baseline": info.get("tone_baseline"), "delta": info.get("delta"), "status": info.get("status", "NORMAL"), "is_alert": info.get("is_alert", False)} for c, info in gdelt_tones.items() if c in COUNTRY_COORDS and info.get("status") in ("ALERT", "WEATHER_NOISE")],
                    "critical_nodes": [{"type": "IXP", "id": ix["id"], "name": ix["name"], "aka": ix.get("aka", ""), "city": ix["city"], "country": c, "lat": ix["lat"], "lng": ix["lng"], "status": ix.get("status", "ok")} for c, cdata in ixp_data.items() for ix in cdata.get("ixps", []) if ix.get("lat") and ix.get("lng")],
                    "firms_anomalies": nasa_firms_data,
                    "chokepoints": (lambda dg_names={g["chokepoint"] for g in ais_dark_gaps}, st_names={s["chokepoint"] for s in ais_stationary}: [
                        {
                            "name":    c["name"],
                            "lat":     c["lat"],
                            "lng":     c["lng"],
                            "country": c["country"],
                            "type":    c.get("type", "cable_landing"),
                            "cables":  c.get("cables", []),
                            "status":  ("dark_gap"   if c["name"] in dg_names else
                                        "stationary" if c["name"] in st_names else
                                        "normal"),
                        }
                        for c in CHOKEPOINTS  # Display all chokepoints (no country filter)
                    ])(),
                    "cable_routes": CABLE_ROUTES,
                    # Additional overlays
                    "isr_hotspots": [
                        {
                            "name":      hs["name"],
                            "lat":       hs["lat"],
                            "lng":       hs["lng"],
                            "radius_km": hs.get("radius_km", 200),
                            "theater":   hs["theater"],
                            "isr_count": isr_data.get(hs["theater"], {}).get("count", 0),
                            "is_surge":  isr_data.get(hs["theater"], {}).get("is_surge", False),
                            "tracks":    next(
                                (h["tracks"] for h in isr_data.get(hs["theater"], {}).get("hotspots", [])
                                 if h["name"] == hs["name"]),
                                []
                            ),
                        }
                        for hs in ISR_HOTSPOTS if hs["theater"] in strategic_theaters_set
                    ],
                    "ais_dark_gaps":  ais_dark_gaps[:10],
                    "ais_stationary": ais_stationary[:10],
                },
                # Deep analysis block
                "analytics": deep_analytics,
            },
        }
        with _global_cache_lock:
            st.global_cache = _new_cache

        _db.alert_append({
            "ts": current_time, "threat_level": threat_level, "threat_raw": tl_raw, "threat_held": tl_held, "score": total_score, "score_with_bonus": score_with_bonus,
            "convergence_level": convergence_level, "convergence_bonus": conv_bonus,
            "sequence_bonus": seq_bonus, "sequence_status": seq_status,
            "domain_cyber": round(domain_scores.get("cyber", 0), 2), "domain_physical": round(domain_scores.get("physical", 0), 2), "domain_info": round(domain_scores.get("info", 0), 2),
            "core_theater": core_theater, "degraded_theaters": [t for t in degraded_targets_effective if t in strategic_theaters_set],
            "is_coordinated": is_coordinated, "system_note": system_note,
            "velocity": round(velocity_val, 5), "is_ambush": is_ambush,
            "blockade_index": deep_analytics["blockade_index"],
        })

        # ── WebSocket push + external notifications ──────────────────────────
        emit_threat_update(core_theater, _new_cache["strategic"])
        if threat_level != prev_threat_level:
            notify_threat_level_change(core_theater, prev_threat_level, threat_level, score_with_bonus)
        if is_ambush:
            emit_ambush_alert(core_theater, {
                "z_score": ambush_z, "acceleration": acceleration_val,
                "velocity": velocity_val, "score": score_with_bonus,
            })
        if seq_status in ("FULL_CHAIN", "PARTIAL"):
            emit_sequence_event(core_theater, {
                "status": seq_status, "chain": seq_chain, "bonus": seq_bonus,
            })
            notify_sequence_complete(core_theater, seq_status, seq_chain)

    results = []
    for t in requested_targets:
        t_info = COUNTRY_COORDS.get(t, {"lat": 0, "lng": 0, "name": t})
        data = st.global_cache["data"].get(t, {"global_share": 0, "global_share_l3": 0, "global_share_l7": 0, "is_vector_shift": False, "shift_actors": [], "sources": []})
        
        degraded_raw = st.global_cache["strategic"].get("degraded_theaters_raw", [])
        degraded_eff = st.global_cache["strategic"].get("degraded_theaters", [])
        
        # Compute velocity and acceleration per target
        ts_series_t = _db.ts_get(t)
        t_vel = _routes.engine.compute_velocity(ts_series_t)
        t_ambush, t_ambush_z, _, _ = _routes.engine.detect_ambush_pattern(ts_series_t)
        results.append({
            "lat": t_info["lat"], "lng": t_info["lng"], "info": t_info["name"], "code": t,
            "global_share": data.get("global_share", 0.0), "global_share_l3": data.get("global_share_l3", 0.0), "global_share_l7": data.get("global_share_l7", 0.0),
            "is_bgp_outage": t in degraded_raw,
            "is_bgp_effective": t in degraded_eff,
            "is_vector_shift": data.get("is_vector_shift", False), "shift_actors": data.get("shift_actors", []),
            "trend_history": _db.series_get(t, "combined"), "trend_history_l3": _db.series_get(t, "l3"), "trend_history_l7": _db.series_get(t, "l7"),
            "sources": data.get("sources", []),
            "velocity": round(t_vel, 5),
            "is_ambush": t_ambush,
            "ambush_z":  t_ambush_z,
        })

    return jsonify({
        "timestamp":       datetime.datetime.now().isoformat(),
        "sensor_health":   _routes.registry.health_report(),
        "strategic_alert": st.global_cache["strategic"],
        "targets":         results,
        "threat_history":  _db.threat_list(),
    })

