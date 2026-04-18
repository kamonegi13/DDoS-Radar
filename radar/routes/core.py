"""radar.routes.core -- Main API endpoints: app_config and threat_data scoring loop."""
from __future__ import annotations
import logging
import os
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
from radar.config import (  # noqa: E501
    AIRSPACE_WINDOW, BASELINE_DATE_RANGE, CABLE_ROUTES, CF_HEADERS,
    CHOKEPOINTS, COUNTRY_BLOC_TAGS, COUNTRY_COORDS, COUNTRY_REGIONS,
    CURRENT_DATE_RANGE, DEFAULT_FOCUSED_SCENARIO, DOMAIN_CAP,
    GDELT_HISTORY_WINDOW, GDELT_TONE_ALERT_THRESHOLD, GLOBAL_SIGNAL_WEIGHT,
    HOD_BASELINE_DAYS, HOD_MIN_SAME_HOUR, ISR_HOTSPOTS, OWM_API_KEY,
    SCORE_REFRESH_SEC, STATE_ASNS, STRATEGIC_BLOCS,
)
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
    classify_direction, compute_temporal_context,
    compute_spatial_context, compute_target_context,
)
from radar.ws import emit_threat_update, emit_ambush_alert, emit_sequence_event
from radar.notifications import (
    notify_threat_level_change, notify_sequence_complete,
    notify_scenario_tl_change,
)
from radar.sensors.checkhost import CHECKHOST_NODES
from radar.sensors.telegram import TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD, TelegramMirrorSensor
import radar.routes as _routes
from radar.routes import bp
from radar.engine import WeightedConvergenceEngine
from radar.scenarios import (
    SensorTier, scenario_store,
    derive_country_context, derive_global_fetch_targets,
)

log = logging.getLogger("radar")

_prev_focused_id: str | None = None
# Phase C: what-changed tracking — guarded by _global_cache_lock
_prev_scenario_domains: dict[str, dict[str, float]] = {}
_prev_scenario_signals: dict[str, set[str]] = {}

_FOCUSED_ONLY_SENSOR_NAMES = frozenset({
    "cloudflare_radar", "ioda_bgp", "ripe_bgp", "openweather",
    "check_host", "opensky", "notam", "ripe_atlas",
    "ais_maritime", "isr_hotspot", "nasa_firms", "mil_support_air",
})

@bp.route("/api/app_config", methods=["GET"])
def app_config():
    return jsonify({
        "default_focused_scenario": DEFAULT_FOCUSED_SCENARIO,
        "strategic_blocs": STRATEGIC_BLOCS,
        "country_bloc_tags": COUNTRY_BLOC_TAGS,
        "available_countries": [
            {"code": code, "name": info["name"], "region": COUNTRY_REGIONS.get(code, "Other"),
             "lat": info["lat"], "lng": info["lng"]}
            for code, info in sorted(COUNTRY_COORDS.items(), key=lambda x: x[1]["name"])
        ],
    })

@bp.route("/api/scenarios", methods=["GET"])
def list_scenarios():
    from radar.scenarios import scenario_store
    from radar.config import DEFAULT_FOCUSED_SCENARIO
    scenarios = scenario_store.all()
    return jsonify({
        "focused_scenario": DEFAULT_FOCUSED_SCENARIO,
        "scenarios": {
            sid: s.to_dict() for sid, s in sorted(scenarios.items())
        },
    })

@bp.route("/api/scenario/<scenario_id>/breakdown", methods=["GET"])
def scenario_breakdown(scenario_id: str):
    from radar.scenarios import scenario_store
    sc = scenario_store.get(scenario_id)
    if not sc:
        return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404

    breakdown = {}
    for cc, p in sorted(sc.participants.items()):
        breakdown[cc] = {
            "weight": p.weight,
            "role": p.role.value,
        }

    return jsonify({
        "scenario_id": scenario_id,
        "name_en": sc.name_en,
        "name_ja": sc.name_ja,
        "core_country": sc.core_country,
        "state": sc.state,
        "enabled": sc.enabled,
        "is_scorable": sc.is_scorable,
        "participants": breakdown,
    })

def _compute_airspace_status(airspace_data, weather_conditions, current_time,
                             db, airspace_window, hod_baseline_days, hod_min_same_hour):
    """Compute airspace anomaly status and noise filters.

    Returns (enriched_airspace, airspace_anomalies, noise_filters) where
    enriched_airspace is a new dict with status/drop_pct/hod_z added per airport.
    The original airspace_data is not mutated.
    """
    enriched = {}
    airspace_anomalies = []
    noise_filters = []

    for code, _raw in airspace_data.items():
        ainfo = dict(_raw)  # shallow copy — don't mutate sensor cache
        enriched[code] = ainfo
        count = ainfo.get("count", -1)
        if count < 0:
            ainfo["status"] = "ERROR"
            continue
        bl = db.airspace_get(code)
        if not bl:
            bl = {"readings": [], "avg": 0.0}
        bl["readings"] = bl.get("readings", [])
        bl["readings"].append(count)
        bl["readings"] = bl["readings"][-airspace_window:]
        n = len(bl["readings"])
        bl["avg"] = sum(bl["readings"]) / n if n > 0 else 0.0
        ainfo["baseline_avg"] = round(bl["avg"], 1)
        ainfo["baseline_n"] = n

        # HOD tracking: record one entry per UTC hour bucket per airport
        _as_hour_bucket = int(current_time // 3600) * 3600
        if "hod" not in bl:
            bl["hod"] = []
        _as_hod_entries = bl["hod"]
        if not _as_hod_entries or _as_hod_entries[-1][0] != _as_hour_bucket:
            _as_hod_entries.append((_as_hour_bucket, count))
            bl["hod"] = _as_hod_entries[-(hod_baseline_days * 24):]
        _cur_as_hod = (_as_hour_bucket // 3600) % 24
        _as_same_hour = [c for (ts, c) in bl["hod"]
                         if (ts // 3600) % 24 == _cur_as_hod and ts < _as_hour_bucket]
        db.airspace_set(code, bl)

        if n < 3 or bl["avg"] < 1:
            ainfo["status"] = "BASELINE_BUILDING"
            ainfo["drop_pct"] = 0.0
            continue

        drop_ratio = max(0.0, (bl["avg"] - count) / bl["avg"])
        ainfo["drop_pct"] = round(drop_ratio * 100, 1)
        weather_suppressed = weather_conditions.get(code, {}).get("is_severe", False)

        # HOD Z-score severity when enough same-hour samples exist
        _n_as_hod = len(_as_same_hour)
        if _n_as_hod >= hod_min_same_hour:
            _ah_mean = sum(_as_same_hour) / _n_as_hod
            _ah_std = max((sum((x - _ah_mean)**2 for x in _as_same_hour) / _n_as_hod) ** 0.5, 0.5)
            _ah_z = (count - _ah_mean) / _ah_std
            ainfo["hod_z"] = round(_ah_z, 2)
            ainfo["hod_n"] = _n_as_hod
            severity = "CLOSURE" if _ah_z < -3.0 else "ANOMALY" if _ah_z < -2.0 else "NORMAL"
        else:
            ainfo["hod_z"] = None
            ainfo["hod_n"] = _n_as_hod
            severity = (
                "CLOSURE" if drop_ratio >= (1.0 - float(os.getenv("AIRSPACE_CLOSURE_THRESHOLD", "0.05")))
                else "ANOMALY" if drop_ratio >= (1.0 - float(os.getenv("AIRSPACE_ANOMALY_THRESHOLD", "0.40")))
                else "NORMAL"
            )

        if severity in ("CLOSURE", "ANOMALY"):
            if weather_suppressed:
                ainfo["status"] = "WEATHER_NOISE"
                noise_filters.append(f"weather_noise@{code}: airspace {severity.lower()} suppressed")
            else:
                ainfo["status"] = severity
                airspace_anomalies.append({
                    "code": code, "airport": ainfo.get("airport", code),
                    "count": count, "baseline": ainfo["baseline_avg"],
                    "drop_pct": ainfo["drop_pct"], "severity": severity,
                    "lat": ainfo.get("lat"), "lng": ainfo.get("lng"),
                })
        else:
            ainfo["status"] = "NORMAL"

    return enriched, airspace_anomalies, noise_filters


def _read_sensor_caches(registry):
    """Extract all sensor cache data into a flat dict.

    Pure read-only operation — no side effects, no DB writes.
    Returns a dict keyed by logical field names.
    """
    def _get(name, key, default=None):
        s = registry.get(name)
        if not s:
            return (s, default if default is not None else {})
        c = s.get_cache()
        return (s, c.get(key, default if default is not None else {}))

    cf_sensor = registry.get("cloudflare_radar")
    _cf_cache = cf_sensor.get_cache() if cf_sensor else {}

    ioda_sensor = registry.get("ioda_bgp")
    _ioda_cache = ioda_sensor.get_cache() if ioda_sensor else {}

    owm_sensor = registry.get("openweather")
    opensky_sensor = registry.get("opensky")
    gdelt_sensor = registry.get("gdelt")
    peeringdb_sensor = registry.get("peeringdb_ixp")
    bgp_routing_sensor = registry.get("ripe_bgp")
    nasa_firms_sensor = registry.get("nasa_firms")
    threatfox_sensor = registry.get("threatfox")
    rss_narrative_sensor = registry.get("rss_narrative")
    isr_hotspot_sensor = registry.get("isr_hotspot")
    ais_maritime_sensor = registry.get("ais_maritime")
    telegram_mirror_sensor = registry.get("telegram_mirror")
    check_host_sensor = registry.get("check_host")
    greynoise_sensor = registry.get("greynoise")
    space_weather_sensor = registry.get("space_weather")

    ihr_sensor = registry.get("ihr_health")
    _ihr_cache = ihr_sensor.get_cache() if ihr_sensor else {}
    atlas_sensor = registry.get("ripe_atlas")
    _atlas_cache = atlas_sensor.get_cache() if atlas_sensor else {}
    tor_sensor = registry.get("tor_metrics")
    _tor_cache = tor_sensor.get_cache() if tor_sensor else {}

    notam_sensor = registry.get("notam")
    _notam_cache = notam_sensor.get_cache() if notam_sensor else {}
    travel_adv_sensor = registry.get("travel_advisory")
    _travel_cache = travel_adv_sensor.get_cache() if travel_adv_sensor else {}
    ooni_sensor = registry.get("ooni_censorship")
    _ooni_cache = ooni_sensor.get_cache() if ooni_sensor else {}
    usgs_sensor = registry.get("usgs_seismic")
    _usgs_cache = usgs_sensor.get_cache() if usgs_sensor else {}
    mil_air_sensor = registry.get("mil_support_air")
    _mil_air_cache = mil_air_sensor.get_cache() if mil_air_sensor else {}
    gps_jam_sensor = registry.get("gps_jamming")
    _gps_cache = gps_jam_sensor.get_cache() if gps_jam_sensor else {}
    ct_log_sensor = registry.get("ct_log")
    _ct_cache = ct_log_sensor.get_cache() if ct_log_sensor else {}

    _sw_cache = space_weather_sensor.get_cache().get("space_weather", {}) if space_weather_sensor else {}
    _ais_cache = ais_maritime_sensor.get_cache() if ais_maritime_sensor else {}

    return {
        # Sensor objects (needed for .enabled / .compute_confidence checks)
        "sensors": {
            "cf": cf_sensor, "ioda": ioda_sensor, "owm": owm_sensor,
            "opensky": opensky_sensor, "gdelt": gdelt_sensor,
            "peeringdb": peeringdb_sensor, "bgp_routing": bgp_routing_sensor,
            "nasa_firms": nasa_firms_sensor, "threatfox": threatfox_sensor,
            "rss_narrative": rss_narrative_sensor, "isr_hotspot": isr_hotspot_sensor,
            "ais_maritime": ais_maritime_sensor, "telegram_mirror": telegram_mirror_sensor,
            "check_host": check_host_sensor, "greynoise": greynoise_sensor,
            "space_weather": space_weather_sensor, "ihr": ihr_sensor,
            "atlas": atlas_sensor, "tor": tor_sensor,
            "notam": notam_sensor, "travel_adv": travel_adv_sensor,
            "ooni": ooni_sensor, "usgs": usgs_sensor,
            "mil_air": mil_air_sensor, "gps_jam": gps_jam_sensor,
            "ct_log": ct_log_sensor,
        },
        # Cache data
        "cf_bgp_hijacks": _cf_cache.get("bgp_hijacks", []),
        "cf_bgp_leaks": _cf_cache.get("bgp_leaks", []),
        "ioda_data": _ioda_cache.get("statuses", {}),
        "ioda_details": _ioda_cache.get("ioda_details", {}),
        "ioda_source": _ioda_cache.get("source", "unknown"),
        "weather_conditions": owm_sensor.get_cache().get("conditions", {}) if owm_sensor else {},
        "airspace_data": opensky_sensor.get_cache().get("airports", {}) if opensky_sensor else {},
        "gdelt_tones": gdelt_sensor.get_cache().get("gdelt_tones", {}) if gdelt_sensor else {},
        "ixp_data": peeringdb_sensor.get_cache().get("ixp_data", {}) if peeringdb_sensor else {},
        "bgp_routing_data": bgp_routing_sensor.get_cache().get("routing_stats", {}) if bgp_routing_sensor else {},
        "nasa_firms_data": nasa_firms_sensor.get_cache().get("anomalies", []) if nasa_firms_sensor else [],
        "threatfox_data": threatfox_sensor.get_cache().get("hits", {}) if threatfox_sensor else {},
        "narrative_data": rss_narrative_sensor.get_cache().get("narratives", {}) if rss_narrative_sensor else {},
        "isr_data": isr_hotspot_sensor.get_cache().get("isr_data", {}) if isr_hotspot_sensor else {},
        "ais_dark_gaps": _ais_cache.get("dark_gaps", []),
        "ais_stationary": _ais_cache.get("stationary_anomalies", []),
        "ais_has_anomaly": _ais_cache.get("has_anomaly", False),
        "telegram_data": telegram_mirror_sensor.get_cache().get("telegram", {}) if telegram_mirror_sensor else {},
        "checkhost_data": check_host_sensor.get_cache().get("check_host", {}) if check_host_sensor else {},
        "greynoise_data": greynoise_sensor.get_cache().get("greynoise", {}) if greynoise_sensor else {},
        "space_weather_data": _sw_cache,
        "sw_suppress": _sw_cache.get("suppress_physical", False),
        "ihr_disco": _ihr_cache.get("disconnections", {}),
        "ihr_hegemony": _ihr_cache.get("hegemony_alarms", {}),
        "ihr_delay": _ihr_cache.get("delay_alarms", {}),
        "ihr_country_status": _ihr_cache.get("country_status", {}),
        "atlas_probes": _atlas_cache.get("probe_counts", {}),
        "atlas_latency": _atlas_cache.get("latency", {}),
        "atlas_country_status": _atlas_cache.get("country_status", {}),
        "tor_relays": _tor_cache.get("relay_counts", {}),
        "tor_clients": _tor_cache.get("client_estimates", {}),
        "tor_country_status": _tor_cache.get("country_status", {}),
        "notam_data": _notam_cache.get("notam_data", {}),
        "notam_country_status": _notam_cache.get("country_status", {}),
        "travel_advisories": _travel_cache.get("advisories", {}),
        "ooni_data": _ooni_cache.get("censorship_data", {}),
        "ooni_country_status": _ooni_cache.get("country_status", {}),
        "seismic_data": _usgs_cache.get("seismic", {}),
        "seismic_suppress": _usgs_cache.get("seismic", {}).get("suppress_physical", False),
        "mil_air_data": _mil_air_cache.get("mil_air_data", {}),
        "gps_jam_data": _gps_cache.get("jamming_data", {}),
        "gps_country_status": _gps_cache.get("country_status", {}),
        "ct_data": _ct_cache.get("ct_data", {}),
        "ct_country_status": _ct_cache.get("country_status", {}),
    }


@bp.route("/api/threat_data", methods=["GET"])
def get_threat_data():
    current_time = time.time()
    # ADR-005/P1: scoring is scenario-driven. All per-country lists are derived
    # from the focused scenario's participants and roles. Legacy ?core=/?correlates=/
    # ?adversaries=/?targets= URL params are no longer accepted.
    focused_id = (request.args.get("focus") or DEFAULT_FOCUSED_SCENARIO).strip()
    focused_scenario_obj = scenario_store.get(focused_id)
    if not focused_scenario_obj or not focused_scenario_obj.is_scorable:
        # Fall back to DEFAULT_FOCUSED_SCENARIO, then to any scorable scenario.
        focused_scenario_obj = (
            scenario_store.get(DEFAULT_FOCUSED_SCENARIO)
            or (scenario_store.scorable()[0] if scenario_store.scorable() else None)
        )
        if focused_scenario_obj is None:
            return jsonify({"error": "No scorable scenario available"}), 503
        focused_id = focused_scenario_obj.id

    _ctx = derive_country_context(focused_scenario_obj)
    core_theater = (_ctx["core_theater"] or "").upper()
    correlate_targets = list(_ctx["correlate_targets"])
    adversary_states = list(_ctx["adversary_states"])
    strategic_theaters_set = set(_ctx["strategic_theaters"])

    # Union of all scorable scenarios — used for cross-scenario sensor coverage
    # (LLM sensors, HOD sampling scope, etc. — ADR-004).
    _global_targets = derive_global_fetch_targets()
    all_participant_countries = list(_global_targets["all_participant_countries"])

    _force_param = request.args.get("force", "false").lower() == "true"
    # Restrict force_sync to analyst/admin roles to prevent quota exhaustion
    force_sync = False
    if _force_param:
        try:
            _identity = get_jwt_identity()
            _role = _db.user_get_role(_identity) if _identity else "viewer"
            if _role in ("admin", "analyst"):
                force_sync = True
        except Exception as _e:
            log.warning("force_sync role check failed: %s", _e)

    # HITL Analyst MUTE parameters
    muted_sensors = [s.strip() for s in request.args.get("muted", "").split(",") if s.strip()]

    required_keys = set(correlate_targets)
    if core_theater: required_keys.add(core_theater)

    sensor_context = {
        "all_targets": sorted(required_keys),
        "strategic_theaters": sorted(strategic_theaters_set),
        "adversary_states": adversary_states,
        "all_participant_countries": all_participant_countries,
        "cf_headers": CF_HEADERS, "owm_api_key": OWM_API_KEY,
        "weather_conditions": {}, "gdelt_tone_threshold": float(os.getenv("GDELT_TONE_ALERT_THRESHOLD", "-15.0")),
        "gdelt_history_window": int(os.getenv("GDELT_HISTORY_WINDOW", "28"))
    }

    # Sensors are individually scheduled in the background.
    # Immediate fetch only on force_sync (SYNC button). Do not wait on missing_data.
    # (At startup, background threads are fetching in parallel; waiting for sync would
    #  block for minutes on slow sensors like PeeringDB/AIS).
    if force_sync:
        with ThreadPoolExecutor(max_workers=4) as executor:
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

    # Cache invalidation must also consider the focus parameter: scenario
    # scoring depends on focus (full vs lite mode, threat_level derivation),
    # so two requests within SCORE_REFRESH_SEC with different focus must
    # each trigger a fresh scoring pass — otherwise a focus change would
    # surface stale is_focused / tl / threat_level for up to 60s.
    _req_focus = focused_id
    with _global_cache_lock:
        _cache_ts = st.global_cache.get("time", 0)
        _cache_focus = st.global_cache.get("focus")
    _focus_changed = (_cache_focus is not None and _cache_focus != _req_focus)
    if (current_time - _cache_ts > SCORE_REFRESH_SEC) or force_sync or _focus_changed:
        # Read all sensor caches (extracted for readability)
        _sc = _read_sensor_caches(_routes.registry)
        _sensors = _sc["sensors"]
        cf_sensor = _sensors["cf"]; ioda_sensor = _sensors["ioda"]
        owm_sensor = _sensors["owm"]; opensky_sensor = _sensors["opensky"]
        gdelt_sensor = _sensors["gdelt"]; peeringdb_sensor = _sensors["peeringdb"]
        bgp_routing_sensor = _sensors["bgp_routing"]; nasa_firms_sensor = _sensors["nasa_firms"]
        threatfox_sensor = _sensors["threatfox"]; rss_narrative_sensor = _sensors["rss_narrative"]
        isr_hotspot_sensor = _sensors["isr_hotspot"]; ais_maritime_sensor = _sensors["ais_maritime"]
        telegram_mirror_sensor = _sensors["telegram_mirror"]; check_host_sensor = _sensors["check_host"]
        greynoise_sensor = _sensors["greynoise"]; space_weather_sensor = _sensors["space_weather"]
        ihr_sensor = _sensors["ihr"]; atlas_sensor = _sensors["atlas"]; tor_sensor = _sensors["tor"]
        notam_sensor = _sensors["notam"]; travel_adv_sensor = _sensors["travel_adv"]
        ooni_sensor = _sensors["ooni"]; usgs_sensor = _sensors["usgs"]
        mil_air_sensor = _sensors["mil_air"]; gps_jam_sensor = _sensors["gps_jam"]
        ct_log_sensor = _sensors["ct_log"]

        cf_bgp_hijacks = _sc["cf_bgp_hijacks"]; cf_bgp_leaks = _sc["cf_bgp_leaks"]
        ioda_data = _sc["ioda_data"]; ioda_details = _sc["ioda_details"]; ioda_source = _sc["ioda_source"]
        weather_conditions = _sc["weather_conditions"]; airspace_data = _sc["airspace_data"]
        gdelt_tones = _sc["gdelt_tones"]; ixp_data = _sc["ixp_data"]
        bgp_routing_data = _sc["bgp_routing_data"]; nasa_firms_data = _sc["nasa_firms_data"]
        threatfox_data = _sc["threatfox_data"]; narrative_data = _sc["narrative_data"]
        isr_data = _sc["isr_data"]
        ais_dark_gaps = _sc["ais_dark_gaps"]; ais_stationary = _sc["ais_stationary"]
        ais_has_anomaly = _sc["ais_has_anomaly"]
        telegram_data = _sc["telegram_data"]; checkhost_data = _sc["checkhost_data"]
        greynoise_data = _sc["greynoise_data"]
        space_weather_data = _sc["space_weather_data"]; sw_suppress = _sc["sw_suppress"]
        ihr_disco = _sc["ihr_disco"]; ihr_hegemony = _sc["ihr_hegemony"]
        ihr_delay = _sc["ihr_delay"]; ihr_country_status = _sc["ihr_country_status"]
        atlas_probes = _sc["atlas_probes"]; atlas_latency = _sc["atlas_latency"]
        atlas_country_status = _sc["atlas_country_status"]
        tor_relays = _sc["tor_relays"]; tor_clients = _sc["tor_clients"]
        tor_country_status = _sc["tor_country_status"]
        notam_data = _sc["notam_data"]; notam_country_status = _sc["notam_country_status"]
        travel_advisories = _sc["travel_advisories"]
        ooni_data = _sc["ooni_data"]; ooni_country_status = _sc["ooni_country_status"]
        seismic_data = _sc["seismic_data"]; seismic_suppress = _sc["seismic_suppress"]
        mil_air_data = _sc["mil_air_data"]
        gps_jam_data = _sc["gps_jam_data"]; gps_country_status = _sc["gps_country_status"]
        ct_data = _sc["ct_data"]; ct_country_status = _sc["ct_country_status"]

        airspace_data, airspace_anomalies, noise_filters_applied = _compute_airspace_status(
            airspace_data, weather_conditions, current_time,
            _db, AIRSPACE_WINDOW, HOD_BASELINE_DAYS, HOD_MIN_SAME_HOUR)

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
        # Compute all pairwise correlations (not just core vs correlates)
        _corr_seen = set()
        _corr_theaters = []
        for t in [core_theater] + correlate_targets:
            if t in origin_distributions and t not in _corr_seen:
                _corr_theaters.append(t)
                _corr_seen.add(t)
        for i, a in enumerate(_corr_theaters):
            for b in _corr_theaters[i + 1:]:
                key = f"{a}-{b}"
                correlations[key]    = calculate_overlap(origin_distributions[a], origin_distributions[b])
                correlations_l3[key] = calculate_overlap(origin_distributions_l3.get(a, {}), origin_distributions_l3.get(b, {}))
                correlations_l7[key] = calculate_overlap(origin_distributions_l7.get(a, {}), origin_distributions_l7.get(b, {}))

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

        def add_rat(sensor, domain, status, value, score, fired_reason,
                    is_suppressed=False, suppress_reason=None, confidence=1.0,
                    source_country="", signal_source="", **cac_kwargs):
            """Add a rationale entry. Returns True if the entry is effectively
            active (FIRED and not suppressed/muted), False otherwise.
            Callers should use this to gate sequence event registration."""
            _is_muted = (sensor in muted_sensors) or is_suppressed
            _s_reason = "Analyst Muted (HITL)" if (sensor in muted_sensors) else suppress_reason
            # Check noise exclusion rules
            _noise_rule = _db.noise_excl_match(sensor, core_theater, value)
            if _noise_rule and not _is_muted:
                _is_muted = True
                _s_reason = f"Noise exclusion: {_noise_rule['reason']} (rule #{_noise_rule['id']})"
                noise_filters_applied.append(f"noise_excl@{sensor}: {_noise_rule['reason']}")
            # CAC direction classification
            _dir, _dir_conf = classify_direction(
                sensor, domain, source_country=source_country,
                target_country=core_theater,
                adversary_states=adversary_states,
                strategic_theaters=list(strategic_theaters_set),
                **cac_kwargs)
            # CAC context computation
            _temporal = compute_temporal_context(sensor, current_time, core_theater)
            _spatial = compute_spatial_context(sensor, core_theater,
                                               source_country=source_country,
                                               adversary_states=adversary_states)
            _target = compute_target_context(sensor, core_theater,
                                              source_country=source_country,
                                              adversary_states=adversary_states,
                                              strategic_theaters=list(strategic_theaters_set),
                                              core_country=focused_scenario_obj.core_country or "")
            rationale.append(RationaleEntry(
                sensor=sensor, domain=domain, status=status, value=value,
                score=score, fired_reason=fired_reason,
                suppressed=_is_muted, suppress_reason=_s_reason,
                confidence=confidence,
                signal_source=signal_source,
                direction=_dir, direction_confidence=_dir_conf,
                temporal_context=_temporal, spatial_context=_spatial,
                target_context=_target))
            return status == "FIRED" and not _is_muted

        _overlap_active = False
        _coord_active = False
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
            _overlap_active = add_rat("cf_botnet_overlap", "cyber", "FIRED" if high_correlation else "OK", f"{max_overlap:.1f}% overlap", 1 if high_correlation else 0, "Shared botnet >30%" if high_correlation else None, confidence=_cf_conf)
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
            _adv_top_actor = adversary_strikes[0]["actor"] if adversary_strikes else ""
            add_rat("cf_adversary_strike", "cyber", "FIRED" if major_adversary else "OK", f"{_adv_count} strike(s)", _adv_score, f"Adversary state direct strike ({_adv_count} actors)" if major_adversary else None, confidence=_cf_conf, source_country=_adv_top_actor, is_state_asn=bool(state_asn_hits))
            _coord_active = add_rat("cf_coordinated", "cyber", "FIRED" if is_coordinated else "OK", f"theaters={elevated_theaters}", 1 if is_coordinated else 0, f"Simultaneous surge" if is_coordinated else None, confidence=_cf_conf)

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
            add_rat("ioda_bgp", "physical", "FIRED" if core_degraded else "OK", bgp_value, 1 if core_degraded else 0, _ioda_fired_reason, is_suppressed=_bgp_suppress, suppress_reason=_bgp_suppress_reason, confidence=_sensor_conf(ioda_sensor), signal_source="bgp")

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
            add_rat("ripe_bgp", "cyber", "FIRED" if bgp_anomaly else "OK", _bgp_value, 1 if bgp_anomaly else 0, _bgp_reason, confidence=_sensor_conf(bgp_routing_sensor), signal_source="bgp")

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
        _firms_active = False
        has_firms_core = False
        if nasa_firms_sensor and nasa_firms_sensor.enabled:
            has_firms = any(f["code"] == core_theater for f in nasa_firms_data)
            has_firms_core = has_firms
            _firms_global_codes = sorted({f["code"] for f in nasa_firms_data})
            if has_firms:
                _firms_val = f"Thermal Anomaly [{core_theater}]"
            elif _firms_global_codes:
                _firms_val = f"Global only [{','.join(_firms_global_codes[:4])}]"
            else:
                _firms_val = "No Anomalies"
            _firms_active = add_rat("nasa_firms", "physical", "FIRED" if has_firms else "OK", _firms_val, 3 if has_firms else 0, "Kinetic Strike Precursor", confidence=_sensor_conf(nasa_firms_sensor))

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
            _narr_active = add_rat("rss_narrative", "info",
                    "FIRED" if narrative_burst else "OK",
                    f"Z={narrative_z:.2f} [{narrative_status}]",
                    n_score,
                    f"Narrative Burst Z={narrative_z:.2f}" if narrative_burst else None,
                    confidence=_sensor_conf(rss_narrative_sensor))
            if narrative_burst and _narr_active:
                register_sequence_event(core_theater, "NARRATIVE_BURST",
                                        {"z_score": narrative_z, "status": narrative_status},
                                        scenario_id=focused_id)

        # ISR hotspot surge
        core_isr = isr_data.get(core_theater, {})
        isr_surge = core_isr.get("is_surge", False)
        isr_count = core_isr.get("count", 0)
        if isr_hotspot_sensor and isr_hotspot_sensor.enabled:
            _isr_active = add_rat("isr_hotspot", "physical",
                    "FIRED" if isr_surge else "OK",
                    f"{isr_count} ISR ac in hotspot",
                    2 if isr_surge else 0,
                    f"ISR surge: {isr_count} aircraft" if isr_surge else None,
                    confidence=_sensor_conf(isr_hotspot_sensor))
            if isr_surge and _isr_active:
                register_sequence_event(core_theater, "ISR_SURGE",
                                        {"count": isr_count, "hotspots": core_isr.get("hotspots", [])},
                                        scenario_id=focused_id)

        # AIS maritime anomaly
        if ais_maritime_sensor and ais_maritime_sensor.enabled:
            core_gaps = [g for g in ais_dark_gaps if any(
                cp["country"] == core_theater for cp in CHOKEPOINTS if cp["name"] == g.get("chokepoint")
            )]
            ais_fired = ais_has_anomaly or len(core_gaps) > 0
            _ais_active = add_rat("ais_maritime", "physical",
                    "FIRED" if ais_fired else "OK",
                    f"dark_gaps={len(ais_dark_gaps)} stationary={len(ais_stationary)}",
                    1 if ais_fired else 0,
                    "AIS Dark Gap / Stationary Anomaly at chokepoint" if ais_fired else None,
                    confidence=_sensor_conf(ais_maritime_sensor))
            if ais_fired and _ais_active:
                register_sequence_event(core_theater, "AIS_DARK_GAP",
                                        {"dark_gaps": len(ais_dark_gaps), "stationary": len(ais_stationary)},
                                        scenario_id=focused_id)

        # FIRMS → register Sequence Event (gated by add_rat suppression check)
        if has_firms_core and _firms_active:
            register_sequence_event(core_theater, "FIRMS_ANOMALY",
                                    {"hotspots": [f for f in nasa_firms_data if f.get("code") == core_theater]},
                                    scenario_id=focused_id)

        # Sync DDoS detection → register Sequence Event (gated by add_rat suppression checks)
        if is_coordinated and high_correlation and _coord_active and _overlap_active:
            register_sequence_event(core_theater, "SYNC_DDOS",
                                    {"coordinated_theaters": elevated_theaters,
                                     "max_overlap": max(correlations.values(), default=0.0)},
                                    scenario_id=focused_id)

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
            _tg_active = add_rat("telegram_mirror", "info",
                    "FIRED" if fired else "OK",
                    detail,
                    tg_score,
                    f"Telegram Burst Z={telegram_z:.2f} (conf={telegram_confidence:.2f})" if telegram_burst else
                    f"Attack intent intercepted on Telegram: {telegram_active_ch}" if telegram_intent else
                    "Target URLs found in Telegram channels" if telegram_status == "TARGETS_FOUND" else None,
                    confidence=_sensor_conf(telegram_mirror_sensor))
            if _tg_active and telegram_burst:
                register_sequence_event(core_theater, "NARRATIVE_BURST", {
                    "source": "telegram_mirror", "channels": telegram_active_ch,
                    "targets": core_telegram.get("target_urls", [])[:5],
                    "z_score": telegram_z,
                }, scenario_id=focused_id)

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

        # ── Phase 4: IHR rationale ────────────────────────────────────────────
        _ihr_suppress = sw_suppress  # IHR is physical domain; respect space weather
        _ihr_suppress_reason = space_weather_data.get("suppress_reason") if sw_suppress else None
        _ihr_core_disco = ihr_disco.get(core_theater, [])
        _ihr_core_delay = ihr_delay.get(core_theater, [])
        _ihr_core_status = ihr_country_status.get(core_theater, "NORMAL")
        if not (ihr_sensor and ihr_sensor.enabled):
            add_rat("ihr_disco", "physical", "DISABLED", "sensor off", 0, None)
        else:
            _ihr_disco_fired = len(_ihr_core_disco) > 0
            _ihr_disco_score = 2 if any(e.get("avglevel", 0) > 5 for e in _ihr_core_disco) else (1 if _ihr_disco_fired else 0)
            _ihr_disco_value = f"{len(_ihr_core_disco)} events" if _ihr_disco_fired else "—"
            _ihr_disco_reason = (f"IHR: Disconnection event in {core_theater} "
                                 f"({len(_ihr_core_disco)} events, "
                                 f"probes={_ihr_core_disco[0].get('nbprobes', '?') if _ihr_core_disco else 0})"
                                 ) if _ihr_disco_fired else None
            add_rat("ihr_disco", "physical",
                    "FIRED" if _ihr_disco_fired else "OK",
                    _ihr_disco_value, _ihr_disco_score, _ihr_disco_reason,
                    is_suppressed=_ihr_suppress, suppress_reason=_ihr_suppress_reason,
                    confidence=ihr_sensor.compute_confidence() if ihr_sensor else 0.0,
                    signal_source="bgp")

            _ihr_delay_fired = len(_ihr_core_delay) > 0
            add_rat("ihr_delay", "physical",
                    "FIRED" if _ihr_delay_fired else "OK",
                    f"{len(_ihr_core_delay)} alarms" if _ihr_delay_fired else "—",
                    1 if _ihr_delay_fired else 0,
                    f"IHR: Network delay anomaly ({len(_ihr_core_delay)} alarms)" if _ihr_delay_fired else None,
                    is_suppressed=_ihr_suppress, suppress_reason=_ihr_suppress_reason,
                    confidence=ihr_sensor.compute_confidence() if ihr_sensor else 0.0)

        # ── Phase 4: RIPE Atlas rationale ─────────────────────────────────────
        _atlas_core_status = atlas_country_status.get(core_theater, "NORMAL")
        _atlas_core_probes = atlas_probes.get(core_theater, {})
        _atlas_core_lat = atlas_latency.get(core_theater, {})
        if not (atlas_sensor and atlas_sensor.enabled):
            add_rat("ripe_atlas", "physical", "DISABLED", "sensor off", 0, None)
        else:
            _atlas_fired = _atlas_core_status in ("PROBE_DROP", "PROBE_BLACKOUT")
            _atlas_score = 2 if _atlas_core_status == "PROBE_BLACKOUT" else (1 if _atlas_fired else 0)
            _atlas_active = _atlas_core_probes.get("active", 0)
            _atlas_drop = _atlas_core_probes.get("drop_pct", 0)
            _atlas_avg_ms = _atlas_core_lat.get("avg_ms", 0)
            _atlas_value = (f"{_atlas_core_status} ({_atlas_active} probes"
                            f", drop={_atlas_drop:.0%}"
                            f", lat={_atlas_avg_ms:.0f}ms)"
                            if _atlas_fired
                            else f"{_atlas_active} probes, {_atlas_avg_ms:.0f}ms")
            _atlas_reason = (f"RIPE Atlas: {_atlas_core_status} — "
                             f"{_atlas_active} active probes (drop {_atlas_drop:.0%}), "
                             f"avg latency {_atlas_avg_ms:.0f}ms"
                             ) if _atlas_fired else None
            add_rat("ripe_atlas", "physical",
                    "FIRED" if _atlas_fired else "OK",
                    _atlas_value, _atlas_score, _atlas_reason,
                    is_suppressed=sw_suppress, suppress_reason=_ihr_suppress_reason,
                    confidence=atlas_sensor.compute_confidence() if atlas_sensor else 0.0)

        # ── Phase 4: Tor Metrics rationale ────────────────────────────────────
        _tor_core_status = tor_country_status.get(core_theater, "NORMAL")
        _tor_core_relays = tor_relays.get(core_theater, {})
        _tor_core_clients = tor_clients.get(core_theater, {})
        if not (tor_sensor and tor_sensor.enabled):
            add_rat("tor_metrics", "info", "DISABLED", "sensor off", 0, None)
        else:
            _tor_fired = _tor_core_status in ("RELAY_DROP", "CENSORSHIP_INDICATOR")
            _tor_score = 2 if _tor_core_status == "CENSORSHIP_INDICATOR" else (1 if _tor_fired else 0)
            _tor_running = _tor_core_relays.get("running", 0)
            _tor_drop = _tor_core_relays.get("drop_pct", 0)
            _tor_users = _tor_core_clients.get("bridge_users", 0)
            _tor_trend = _tor_core_clients.get("trend", "NORMAL")
            _tor_value = (f"{_tor_core_status} (relays={_tor_running}"
                          f", drop={_tor_drop:.0%}"
                          f", users={_tor_users} [{_tor_trend}])"
                          if _tor_fired
                          else f"relays={_tor_running}, users={_tor_users}")
            _tor_reason = (f"Tor: {_tor_core_status} — "
                           f"relays={_tor_running} (drop {_tor_drop:.0%}), "
                           f"bridge_users={_tor_users}"
                           ) if _tor_fired else None
            # Tor is NOT suppressed by space weather (censorship is deliberate)
            add_rat("tor_metrics", "info",
                    "FIRED" if _tor_fired else "OK",
                    _tor_value, _tor_score, _tor_reason,
                    confidence=tor_sensor.compute_confidence() if tor_sensor else 0.0)

        # ── Phase 4: Cross-sensor correlation enrichment ──────────────────────
        # IHR disco + IODA BGP_OUTAGE = multi-source physical outage
        _ihr_disco_entry = next((e for e in rationale if e.sensor == "ihr_disco" and e.status == "FIRED" and not e.suppressed), None)
        if _ihr_disco_entry and _bgp_fired_entry:
            _ihr_disco_entry.fired_reason += " — Multi-source confirmed (IODA + IHR)"
            _ihr_disco_entry.confidence = 1.0
            if _bgp_fired_entry:
                _bgp_fired_entry.confidence = 1.0

        # RIPE Atlas + CheckHost = confirmed infrastructure degradation
        _atlas_entry = next((e for e in rationale if e.sensor == "ripe_atlas" and e.status == "FIRED" and not e.suppressed), None)
        _ch_entry = next((e for e in rationale if e.sensor == "check_host" and e.status == "FIRED" and not e.suppressed), None)
        if _atlas_entry and _ch_entry:
            _ch_entry.fired_reason += f" — Confirmed by RIPE Atlas ({_atlas_core_probes.get('active', 0)} probes)"
            _ch_entry.confidence = 1.0
        elif _ch_entry and not _atlas_entry and atlas_sensor and atlas_sensor.enabled:
            # CheckHost fires but Atlas is normal — possible CDN-level issue
            _ch_entry.fired_reason += " — Note: RIPE Atlas probes nominal (CDN-layer issue possible)"

        # Tor relay_drop + IHR disco = censorship detection
        _tor_entry = next((e for e in rationale if e.sensor == "tor_metrics" and e.status == "FIRED" and not e.suppressed), None)
        if _tor_entry and _ihr_disco_entry:
            _tor_entry.fired_reason += " — Censorship chain: IHR disconnection concurrent with Tor relay drop"
            _tor_entry.confidence = 1.0
            register_sequence_event(core_theater, "CENSORSHIP_DETECTED",
                                    {"tor_status": _tor_core_status, "ihr_status": _ihr_core_status},
                                    scenario_id=focused_id)

        # ── Phase C: S1 NOTAM Anomaly rationale ──────────────────────────────
        _notam_core = notam_data.get(core_theater, {})
        _notam_surge = _notam_core.get("is_surge", False)
        _notam_mil = _notam_core.get("military", 0)
        _notam_total = _notam_core.get("total", 0)
        if notam_sensor and notam_sensor.enabled:
            _notam_score = 2 if (_notam_surge and _notam_mil >= 3) else (1 if _notam_surge else 0)
            _notam_fired = _notam_surge
            _notam_value = f"total={_notam_total} mil={_notam_mil} tfr={_notam_core.get('tfr', 0)}"
            _notam_reason = (f"NOTAM surge: {_notam_total} notices ({_notam_mil} military)"
                             if _notam_fired else None)
            _notam_active = add_rat("notam", "physical",
                    "FIRED" if _notam_fired else "OK",
                    _notam_value, _notam_score, _notam_reason,
                    confidence=_sensor_conf(notam_sensor))
            if _notam_fired and _notam_active:
                register_sequence_event(core_theater, "NOTAM_SURGE",
                                        {"total": _notam_total, "military": _notam_mil},
                                        scenario_id=focused_id)

        # ── Phase C: S2 Travel Advisory rationale ────────────────────────────
        _travel_core = travel_advisories.get(core_theater, {})
        _travel_level = _travel_core.get("level", 0)
        _travel_upgraded = _travel_core.get("upgraded", False)
        _travel_converged = _travel_core.get("converged", False)
        _travel_single_warn = _travel_core.get("single_source_warning", False)
        _travel_conv_count = _travel_core.get("convergence_count", 0)
        if travel_adv_sensor and travel_adv_sensor.enabled:
            _travel_fired = _travel_level >= 3 or _travel_upgraded
            _travel_score = (2 if _travel_level >= 4 else
                             1 if _travel_level >= 3 or _travel_upgraded else 0)
            # Convergence bonus: multiple governments agree → higher confidence
            _travel_conf = _sensor_conf(travel_adv_sensor)
            if _travel_converged:
                _travel_conf = min(_travel_conf + 0.15, 1.0)
            elif _travel_single_warn:
                _travel_conf = max(_travel_conf - 0.1, 0.1)
            _travel_label = _travel_core.get("level_label", "UNKNOWN")
            _travel_value = f"Level {_travel_level} ({_travel_label})"
            if _travel_upgraded:
                _travel_value += " UPGRADED"
            if _travel_converged:
                _travel_value += f" [{_travel_conv_count} sources converge]"
            elif _travel_single_warn:
                _travel_value += " [single-source]"
            _travel_reason = (f"Travel Advisory: Level {_travel_level} ({_travel_label})"
                              if _travel_fired else None)
            add_rat("travel_advisory", "info",
                    "FIRED" if _travel_fired else "OK",
                    _travel_value, _travel_score, _travel_reason,
                    confidence=_travel_conf)

        # ── Phase C: S3 OONI Censorship rationale ────────────────────────────
        _ooni_core = ooni_data.get(core_theater, {})
        _ooni_censoring = _ooni_core.get("is_censoring", False)
        _ooni_heavy = _ooni_core.get("is_heavy", False)
        _ooni_anomaly_rate = _ooni_core.get("anomaly_rate", 0)
        _ooni_confirmed_rate = _ooni_core.get("confirmed_rate", 0)
        if ooni_sensor and ooni_sensor.enabled:
            _ooni_fired = _ooni_censoring
            _ooni_score = 2 if _ooni_heavy else (1 if _ooni_censoring else 0)
            _ooni_value = (f"anomaly={_ooni_anomaly_rate:.1%} confirmed={_ooni_confirmed_rate:.1%}"
                           f" [{ooni_country_status.get(core_theater, 'NORMAL')}]")
            _ooni_reason = (f"OONI: Internet censorship detected "
                            f"(anomaly={_ooni_anomaly_rate:.1%}, confirmed={_ooni_confirmed_rate:.1%})"
                            if _ooni_fired else None)
            _ooni_active = add_rat("ooni_censorship", "cyber",
                    "FIRED" if _ooni_fired else "OK",
                    _ooni_value, _ooni_score, _ooni_reason,
                    confidence=_sensor_conf(ooni_sensor))
            if _ooni_heavy and _ooni_active:
                register_sequence_event(core_theater, "CENSORSHIP_DETECTED",
                                        {"source": "ooni", "anomaly_rate": _ooni_anomaly_rate},
                                        scenario_id=focused_id)

        # ── Phase C: S4 USGS Seismic rationale ──────────────────────────────
        _seismic_cable = seismic_data.get("has_cable_threat", False)
        _seismic_nuclear = seismic_data.get("has_nuclear_candidate", False)
        _seismic_total = seismic_data.get("total_events", 0)
        _seismic_near = seismic_data.get("near_cable", [])
        if usgs_sensor and usgs_sensor.enabled:
            _seismic_fired = _seismic_nuclear
            _seismic_score = 3 if _seismic_nuclear else 0
            _seismic_value = f"events={_seismic_total} near_cable={len(_seismic_near)}"
            if _seismic_nuclear:
                _seismic_value += f" NUCLEAR_CANDIDATE={len(seismic_data.get('nuclear_candidates', []))}"
            _seismic_reason = (f"USGS: Possible underground nuclear test signature "
                               f"({len(seismic_data.get('nuclear_candidates', []))} candidates)"
                               if _seismic_nuclear else None)
            # Cable threat = noise suppressor (explains physical disruption)
            _is_seismic_suppress = _seismic_cable and not _seismic_nuclear
            add_rat("usgs_seismic", "physical",
                    "FIRED" if _seismic_fired else ("SUPPRESSED" if _is_seismic_suppress else "OK"),
                    _seismic_value, _seismic_score, _seismic_reason,
                    is_suppressed=_is_seismic_suppress,
                    suppress_reason=f"Seismic event near submarine cable ({_seismic_near[0]['chokepoint'] if _seismic_near else 'unknown'})" if _is_seismic_suppress else None,
                    confidence=_sensor_conf(usgs_sensor))
            if _is_seismic_suppress:
                noise_filters_applied.append(
                    f"seismic_cable: earthquake near {_seismic_near[0]['chokepoint'] if _seismic_near else '?'}")

        # ── Phase C: S5 Military Support Aircraft rationale ──────────────────
        _mil_air_core = mil_air_data.get(core_theater, {})
        _mil_air_surge = _mil_air_core.get("is_surge", False)
        _mil_tanker = _mil_air_core.get("tanker", 0)
        _mil_transport = _mil_air_core.get("transport", 0)
        _mil_awacs = _mil_air_core.get("awacs", 0)
        _mil_air_total = _mil_air_core.get("total", 0)
        if mil_air_sensor and mil_air_sensor.enabled:
            _mil_fired = _mil_air_surge
            _mil_score = (2 if (_mil_air_core.get("is_awacs_active") and
                                _mil_air_core.get("is_tanker_surge"))
                          else 1 if _mil_air_surge else 0)
            _mil_value = f"T={_mil_tanker} C={_mil_transport} A={_mil_awacs}"
            _mil_reason = None
            if _mil_fired:
                parts = []
                if _mil_air_core.get("is_tanker_surge"):
                    parts.append(f"tanker surge ({_mil_tanker})")
                if _mil_air_core.get("is_transport_surge"):
                    parts.append(f"transport surge ({_mil_transport})")
                if _mil_air_core.get("is_awacs_active"):
                    parts.append(f"AWACS active ({_mil_awacs})")
                _mil_reason = f"Military support aircraft: {', '.join(parts)}"
            _mil_active = add_rat("mil_support_air", "physical",
                    "FIRED" if _mil_fired else "OK",
                    _mil_value, _mil_score, _mil_reason,
                    confidence=_sensor_conf(mil_air_sensor))
            if _mil_fired and _mil_active:
                register_sequence_event(core_theater, "MIL_AIR_SURGE",
                                        {"tanker": _mil_tanker, "transport": _mil_transport, "awacs": _mil_awacs},
                                        scenario_id=focused_id)

        # ── Phase C: S6 GPS Jamming rationale ────────────────────────────────
        _gps_core = gps_jam_data.get(core_theater, {})
        _gps_jammed = _gps_core.get("is_jammed", False)
        _gps_critical = _gps_core.get("is_critical", False)
        _gps_max = _gps_core.get("max_level", 0)
        _gps_avg = _gps_core.get("avg_level", 0)
        if gps_jam_sensor and gps_jam_sensor.enabled:
            _gps_fired = _gps_jammed
            _gps_score = 2 if _gps_critical else (1 if _gps_jammed else 0)
            _gps_value = f"max={_gps_max:.1f} avg={_gps_avg:.1f} [{gps_country_status.get(core_theater, 'NO_DATA')}]"
            _gps_reason = (f"GPS jamming: {gps_country_status.get(core_theater, 'DETECTED')} "
                           f"(max={_gps_max:.1f}, avg={_gps_avg:.1f})"
                           if _gps_fired else None)
            _gps_active = add_rat("gps_jamming", "physical",
                    "FIRED" if _gps_fired else "OK",
                    _gps_value, _gps_score, _gps_reason,
                    confidence=_sensor_conf(gps_jam_sensor))
            if _gps_fired and _gps_active:
                register_sequence_event(core_theater, "GPS_JAMMING",
                                        {"max_level": _gps_max, "is_critical": _gps_critical},
                                        scenario_id=focused_id)

        # ── Phase C: S7 CT Log Certificate rationale ─────────────────────────
        _ct_core = ct_data.get(core_theater, {})
        _ct_surge = _ct_core.get("is_surge", False)
        _ct_total = _ct_core.get("total_recent", 0)
        _ct_gov = _ct_core.get("gov_count", 0)
        _ct_wildcard = _ct_core.get("wildcard_count", 0)
        if ct_log_sensor and ct_log_sensor.enabled:
            _ct_fired = _ct_surge
            _ct_score = 2 if (_ct_surge and _ct_gov >= 5) else (1 if _ct_surge else 0)
            _ct_value = f"certs={_ct_total} gov={_ct_gov} wildcard={_ct_wildcard}"
            _ct_status_label = ct_country_status.get(core_theater, "NORMAL")
            _ct_reason = (f"CT Log: Certificate surge ({_ct_total} certs, {_ct_gov} gov) [{_ct_status_label}]"
                          if _ct_fired else None)
            add_rat("ct_log", "cyber",
                    "FIRED" if _ct_fired else "OK",
                    _ct_value, _ct_score, _ct_reason,
                    confidence=_sensor_conf(ct_log_sensor))

        # ── Phase C: Cross-sensor enrichment ─────────────────────────────────
        # OONI + Tor = strong censorship confirmation
        if _ooni_censoring and _tor_entry:
            _ooni_entry = next((e for e in rationale if e.sensor == "ooni_censorship" and e.status == "FIRED"), None)
            if _ooni_entry:
                _ooni_entry.fired_reason += " — Confirmed by Tor relay drop (multi-source censorship)"
                _ooni_entry.confidence = 1.0

        # GPS Jamming + ISR surge = electronic warfare preparation
        _gps_entry = next((e for e in rationale if e.sensor == "gps_jamming" and e.status == "FIRED"), None)
        _isr_entry = next((e for e in rationale if e.sensor == "isr_hotspot" and e.status == "FIRED"), None)
        if _gps_entry and _isr_entry:
            _gps_entry.fired_reason += " — EW pattern: GPS jamming concurrent with ISR surge"
            _gps_entry.confidence = 1.0

        # NOTAM surge + Airspace closure = confirmed military activity
        _notam_entry = next((e for e in rationale if e.sensor == "notam" and e.status == "FIRED"), None)
        _airspace_entry = next((e for e in rationale if e.sensor == "opensky" and e.status == "FIRED"), None)
        if _notam_entry and _airspace_entry:
            _notam_entry.fired_reason += " — Confirmed by concurrent airspace closure"
            _notam_entry.confidence = 1.0

        # ── Sequence Bonus computation ──────────────────────────────────────────
        seq_bonus, seq_status, seq_chain = compute_sequence_bonus(core_theater)

        # ── LLM Intel rationale injection ──────────────────────────────────────
        # Inject confirmed/auto_confirmed LLM intel items as scored rationale entries.
        # This makes LLM signals visible in the evidence matrix and contributes to
        # domain scores, exactly like any other sensor.
        try:
            from radar.intel_queue import intel_queue as _iq
            for _llm_entry in _iq.get_active_rationale():
                _llm_theater = _llm_entry.get("theater", "")
                # Only inject entries relevant to the current core theater
                if _llm_theater and _llm_theater != core_theater:
                    continue
                add_rat(
                    _llm_entry["sensor"],
                    _llm_entry["domain"],
                    _llm_entry["status"],
                    _llm_entry["detail"],
                    _llm_entry["score"],
                    _llm_entry["detail"],
                    confidence=_llm_entry["confidence"],
                    signal_source="llm_intel",
                )
        except Exception as _llm_err:
            log.debug(f"[LLM Intel] rationale injection error: {_llm_err}")

        domain_scores = _routes.engine.compute_domain_scores(rationale)

        # ── Phase 2: Feint Detection ─────────────────────────────────────────
        is_feint, feint_primary, feint_distractions, feint_conf, feint_detail = \
            _routes.engine.detect_feint_pattern(domain_scores, rationale)
        if is_feint:
            add_rat("feint_detector", feint_primary, "FIRED", f"conf={feint_conf}",
                    0, feint_detail)

        # ── CAC Phase D: Co-occurrence sensitivity boost (UP only) ──────────
        _fired_for_boost = [e.sensor for e in rationale if e.status == "FIRED" and not e.suppressed]
        cooc_boost = _routes.engine.compute_cooccurrence_boost(_db, _fired_for_boost, core_theater)
        _cooc_factor = cooc_boost["boost_factor"]

        # Confidence-weighted total: sum(score * confidence) for fired, non-suppressed entries
        total_score = sum(e.score * e.confidence for e in rationale if e.status == "FIRED" and not e.suppressed)
        # Apply co-occurrence boost (only increases, never decreases)
        total_score = round(total_score * _cooc_factor, 2)
        convergence_score = _routes.engine.compute_convergence_score(domain_scores)
        domain_confidences = _routes.engine.compute_domain_confidences(rationale)
        score_with_bonus, conv_bonus, convergence_level = _routes.engine.apply_convergence_bonus(total_score, domain_scores, domain_confidences)

        # ── A3: Triangulation bonus (3-domain quality confirmation) ────────
        tri_bonus, is_triangulated, tri_detail = \
            _routes.engine.compute_triangulation_bonus(domain_scores, domain_confidences)
        if is_triangulated:
            score_with_bonus += tri_bonus

        # ── A1: Silent Divergence detection ────────────────────────────────
        is_silent_div, silent_div_conf, silent_div_detail = \
            _routes.engine.detect_silent_divergence(domain_scores, rationale)
        if is_silent_div:
            _sd_score = 2 if silent_div_conf == "HIGH" else 1
            add_rat("silent_divergence", "cyber",
                    "FIRED", f"conf={silent_div_conf}",
                    _sd_score, silent_div_detail)
            # Recalculate domain_scores after adding silent divergence rationale
            domain_scores = _routes.engine.compute_domain_scores(rationale)
            total_score = sum(e.score * e.confidence for e in rationale if e.status == "FIRED" and not e.suppressed)
            total_score = round(total_score * _cooc_factor, 2)
            score_with_bonus, conv_bonus, convergence_level = _routes.engine.apply_convergence_bonus(total_score, domain_scores, domain_confidences)
            if is_triangulated:
                score_with_bonus += tri_bonus

        # Add Sequence Bonus and Temporal Coherence Bonus to final score
        score_with_bonus += seq_bonus + temporal_bonus
        # Cap final score to prevent bonus stacking from inflating beyond TL1 threshold ceiling
        score_with_bonus = min(score_with_bonus, 15)
        active_domains = sum(1 for s in domain_scores.values() if s > 0)

        # ── A2: Theater Baseline — record score and compute Z-score ────────
        _routes.engine.record_theater_score(core_theater, score_with_bonus)
        theater_baseline = _routes.engine.compute_theater_zscore(core_theater, score_with_bonus)

        # ── Scenario scoring — single source of truth for threat_level ────
        # This block computes all scenario scores AND drives the legacy
        # `threat_level` value so that HUD top TL == focused scenario TL.
        # Sequence and temporal bonuses are folded into the focused scenario
        # score before TL derivation; hysteresis is applied to the focused
        # scenario TL (not to a separate legacy timeseries).
        _focused_id = focused_id
        _scenario_results: dict = {}
        _focused_tl: int | None = None
        _focused_tl_raw: int | None = None
        _tl_held_focused = False
        try:
            from radar.scoring import (
                rationale_to_signal, compute_scenario_score, Signal,
                derive_tl, apply_hysteresis_to_tl,
                compute_scenario_velocity, compute_scenario_acceleration,
                compute_velocity_bonus,
                SILENT_DIVERGENCE_BONUS, CONTEXT_ALIGNMENT_BONUS,
                CONTEXT_ALIGNMENT_THRESHOLD,
            )

            _signals: list[Signal] = []
            for rat in rationale:
                if rat.signal_source == "llm_intel":
                    continue
                # FOCUSED_ONLY sensors observe the focused scenario's core country
                # (scenario.core_country, ADR-009), not a UI-configured theater.
                _src_country = (focused_scenario_obj.core_country or "") \
                    if rat.sensor in _FOCUSED_ONLY_SENSOR_NAMES else ""
                sig = rationale_to_signal(rat, source_country=_src_country,
                                          observed_at=current_time)
                if sig is not None:
                    _signals.append(sig)
            # IODA per-country signal injection: IODA fetches all countries
            # (GLOBAL coverage) but the rationale only covers core_theater.
            # Inject per-country signals for non-core BGP_OUTAGE countries
            # so background scenarios see IODA outages for their participants.
            _ioda_core = focused_scenario_obj.core_country or ""
            for _ioda_cc, _ioda_st in ioda_data.items():
                if _ioda_st != "BGP_OUTAGE" or _ioda_cc == _ioda_core:
                    continue
                # Apply weather suppression consistently
                if weather_conditions.get(_ioda_cc, {}).get("is_severe", False):
                    continue
                _signals.append(Signal(
                    signal_source="bgp",
                    sensor="ioda_bgp",
                    observed_at=current_time,
                    domain="physical",
                    countries=[_ioda_cc],
                    raw_score=1.0,
                    value_display=f"BGP_OUTAGE [{ioda_source}]",
                ))

            try:
                from radar.intel_queue import intel_queue as _iq_sc
                for _lr in _iq_sc.get_active_rationale():
                    if _lr.get("score", 0) <= 0:
                        continue
                    _signals.append(Signal(
                        signal_source="llm_intel",
                        sensor="llm_intel",
                        observed_at=current_time,
                        domain=_lr.get("domain", "info"),
                        countries=_lr.get("countries", []),
                        country_weights=_lr.get("country_weights", {}),
                        raw_score=float(_lr["score"]),
                        value_display=_lr.get("detail", ""),
                        evidence_url=_lr.get("raw_url", "") or None,
                        llm_reasoning=_lr.get("llm_reasoning", "") or None,
                    ))
            except Exception:
                pass

            _scorable = scenario_store.scorable()
            _sc_participants_map = {
                sc.id: set(sc.participants.keys())
                for sc in _scorable if sc.id != _focused_id
            }
            _intel_24h = _db.intel_count_24h_by_scenario(_sc_participants_map) if _sc_participants_map else {}

            for _sc in _scorable:
                _is_focused = (_sc.id == _focused_id)
                _state = compute_scenario_score(
                    _sc, _signals, _is_focused,
                    global_signal_weight=GLOBAL_SIGNAL_WEIGHT,
                    domain_cap=DOMAIN_CAP,
                )

                if _is_focused:
                    # Fold sequence + temporal + velocity + pattern bonuses
                    # into focused scenario score, then re-derive TL.
                    _scenario_bonus = 0.0
                    if _sc.core_country:
                        _sc_seq_b, _, _ = compute_sequence_bonus(_sc.core_country)
                        _scenario_bonus += _sc_seq_b
                    _scenario_bonus += temporal_bonus

                    # Phase A: Velocity & acceleration bonuses from score trend
                    _sc_series = _db.scenario_score_series(_sc.id, limit=20)
                    _sc_velocity = compute_scenario_velocity(_sc_series)
                    _sc_acceleration = compute_scenario_acceleration(_sc_series)
                    _vel_bonus, _acc_bonus = compute_velocity_bonus(
                        _sc_velocity, _sc_acceleration)
                    _scenario_bonus += _vel_bonus + _acc_bonus

                    # Phase B: Silent Divergence — cyber+physical active,
                    # info silent. Most dangerous pre-conflict indicator.
                    _sc_silent_div = False
                    _sc_silent_div_conf = "NONE"
                    if (_state.domains.get("cyber", 0) >= 1.0
                            and _state.domains.get("physical", 0) >= 1.0
                            and _state.domains.get("info", 0) == 0):
                        _sc_silent_div = True
                        _cp_total = (_state.domains["cyber"]
                                     + _state.domains["physical"])
                        _sc_silent_div_conf = (
                            "HIGH" if _cp_total >= 6 else
                            "MEDIUM" if _cp_total >= 3 else "LOW"
                        )
                        _scenario_bonus += SILENT_DIVERGENCE_BONUS

                    # Phase B: Context Alignment — when 3+ axes converge,
                    # the signal pattern is too coherent to be noise.
                    _sc_ctx_bonus = 0.0
                    _ctx_score = (context_alignment.get("alignment_score", 0)
                                  if context_alignment else 0)
                    if _ctx_score >= CONTEXT_ALIGNMENT_THRESHOLD:
                        _sc_ctx_bonus = CONTEXT_ALIGNMENT_BONUS
                        _scenario_bonus += _sc_ctx_bonus

                    if _scenario_bonus != 0:
                        _state.score += _scenario_bonus
                        _state.score = max(_state.score, 0)  # floor at 0
                        _active_doms = [d for d, s in _state.domains.items() if s > 0]
                        _state.tl = derive_tl(
                            _state.score, _active_doms,
                            _state.domains.get("physical", 0),
                        )
                    _focused_tl_raw = _state.tl
                    _prev_sc_tl = _db.scenario_tl_last(_sc.id)
                    _held_tl, _was_held = apply_hysteresis_to_tl(_state.tl, _prev_sc_tl)
                    _state.tl = _held_tl
                    _tl_held_focused = _was_held
                    _focused_tl = _state.tl

                _sd = _state.to_dict()
                _sd["name_en"] = _sc.name_en
                _sd["name_ja"] = _sc.name_ja
                if not _is_focused:
                    _sd["lite_bias_warning"] = (
                        "LITE mode: LLM intel + global signals only. "
                        "Physical and per-country cyber signals are not observed."
                    )
                    if "indicators" in _sd:
                        _sd["indicators"]["llm_intel_24h"] = _intel_24h.get(_sc.id, 0)
                    # B1: background score deltas over multiple windows
                    for _dkey, _dsec in (("score_delta_1h", 3600),
                                         ("score_delta_6h", 21600),
                                         ("score_delta_24h", 86400)):
                        try:
                            _prev_s = _db.scenario_score_at_or_before(
                                _sc.id, current_time - _dsec)
                            _sd[_dkey] = (round(_state.score - _prev_s, 2)
                                          if _prev_s is not None else None)
                        except Exception:
                            _sd[_dkey] = None
                    # Background scenario velocity for trend display
                    _bg_series = _db.scenario_score_series(_sc.id, limit=10)
                    _bg_vel = compute_scenario_velocity(_bg_series)
                    _sd["velocity"] = round(_bg_vel, 6)
                    _vel_h = _bg_vel * 3600
                    _sd["velocity_trend"] = (
                        "rising" if _vel_h > 0.1 else
                        "falling" if _vel_h < -0.1 else "stable"
                    )
                else:
                    _sd["tl_raw"] = _focused_tl_raw
                    _sd["tl_held"] = _tl_held_focused

                    # Phase A: Scenario velocity, acceleration, trend, ETA
                    _sd["velocity"] = round(_sc_velocity, 6)
                    _sd["acceleration"] = round(_sc_acceleration, 8)
                    _sd["velocity_bonus"] = _vel_bonus
                    _sd["acceleration_bonus"] = _acc_bonus
                    _vel_pts_h = _sc_velocity * 3600
                    _sd["velocity_trend"] = (
                        "rising" if _vel_pts_h > 0.1 else
                        "falling" if _vel_pts_h < -0.1 else "stable"
                    )
                    _sd["velocity_pts_per_hour"] = round(_vel_pts_h, 3)
                    # ETA to next TL boundary
                    _sd["eta_to_next_tl"] = (
                        _routes.engine.compute_eta_to_next_tl(
                            tl_proximity, _sc_velocity)
                        if tl_proximity else None
                    )

                    # Phase B: Pattern detection results
                    _sd["patterns"] = {
                        "silent_divergence": {
                            "detected": _sc_silent_div,
                            "confidence": _sc_silent_div_conf,
                            "bonus": SILENT_DIVERGENCE_BONUS if _sc_silent_div else 0,
                        },
                        "context_alignment": {
                            "score": _ctx_score,
                            "label": (context_alignment.get("label", "LOW")
                                      if context_alignment else "LOW"),
                            "bonus": _sc_ctx_bonus,
                            "axes": (context_alignment.get("axes", {})
                                     if context_alignment else {}),
                        },
                    }

                    # A1: TL duration — seconds at current TL since last transition.
                    try:
                        _sd["tl_duration_sec"] = _db.scenario_tl_duration_sec(
                            _sc.id, _state.tl)
                    except Exception:
                        _sd["tl_duration_sec"] = None

                    # A3: Intel corroboration — confirmed LLM intel touching
                    # any participant country, in 24h and last 1h windows.
                    try:
                        _focused_parts = set(_sc.participants.keys())
                        _sd["intel_active_24h"] = _db.intel_count_for_scenario_window(
                            _focused_parts, current_time - 86400)
                        _sd["intel_new_1h"] = _db.intel_count_for_scenario_window(
                            _focused_parts, current_time - 3600)
                    except Exception:
                        _sd["intel_active_24h"] = 0
                        _sd["intel_new_1h"] = 0

                    # A5: Adversary vs Target contribution split per domain.
                    _adv_roles = {"adversary", "proxy_front"}
                    _split = {
                        "cyber":    {"adversary": 0.0, "target": 0.0},
                        "physical": {"adversary": 0.0, "target": 0.0},
                        "info":     {"adversary": 0.0, "target": 0.0},
                    }
                    for _c in _state.contributions:
                        _side = "adversary" if _c.participant_role in _adv_roles else "target"
                        _dom = _c.signal.domain
                        if _dom in _split:
                            _split[_dom][_side] += _c.final_contribution
                    _sd["domain_split"] = {
                        _d: {_k: round(_v, 2) for _k, _v in _s.items()}
                        for _d, _s in _split.items()
                    }
                _scenario_results[_sc.id] = _sd

                try:
                    _db.tl_observation_append(
                        scenario_id=_sc.id,
                        observed_at=current_time,
                        score=_state.score,
                        tl=_state.tl,
                        cyber=_state.domains.get("cyber", 0),
                        physical=_state.domains.get("physical", 0),
                        info=_state.domains.get("info", 0),
                        convergence_bonus=_state.convergence_bonus,
                        scoring_mode=_state.scoring_mode,
                        active_countries=_state.active_countries,
                    )
                except Exception:
                    pass

            # Focus switch detection (Section 9.3.1).
            # is_miss is a C-medium migration indicator: it flags cases where
            # LITE mode underestimated a scenario that subsequently reveals
            # material signal on promotion to FULL. The measurement must
            # compare the SAME scenario's pre-switch LITE score to its
            # post-switch FULL score — not two different scenarios'
            # current-cycle scores.
            global _prev_focused_id
            if _prev_focused_id is not None and _prev_focused_id != _focused_id:
                _new_sd = _scenario_results.get(_focused_id, {})
                if _new_sd:
                    _full_score = _new_sd.get("score", 0)
                    _prev_lite = _db.scenario_prev_lite_score(
                        _focused_id, current_time)
                    _lite_score = _prev_lite if _prev_lite is not None else 0.0
                    _delta = abs(_full_score - _lite_score)
                    try:
                        _db.focus_switch_append(
                            scenario_id=_focused_id,
                            switched_at=current_time,
                            lite_score=_lite_score,
                            full_score=_full_score,
                            delta=_delta,
                            is_miss=(_delta >= 1.0),
                        )
                    except Exception:
                        pass
            _prev_focused_id = _focused_id
        except Exception as _sc_err:
            log.warning("[Scoring] Scenario scoring failed: %s", _sc_err)

        # Derive legacy threat_level from focused scenario TL.
        # This is the single source of truth — HUD top TL and scenario card
        # TL now always agree. Fallback to TL5 (normal) only if no focused
        # scenario is available (should not happen with DEFAULT_FOCUSED_SCENARIO).
        if _focused_tl is not None:
            threat_level = _focused_tl
            tl_raw = _focused_tl_raw if _focused_tl_raw is not None else _focused_tl
            tl_held = _tl_held_focused
        else:
            threat_level = 5
            tl_raw = 5
            tl_held = False
        prev_threat = _db.threat_last()
        prev_threat_level = prev_threat[1] if prev_threat else 5
        _db.threat_append(current_time, threat_level)

        # TL Proximity: distance to the TL thresholds from the score that
        # actually drove the TL. Must use the focused scenario's post-bonus
        # score (same one passed to derive_tl above) — not the legacy
        # rationale-based score_with_bonus, which measures a different
        # quantity and would contradict the HUD's TL badge.
        _prox_score = (
            _scenario_results.get(_focused_id, {}).get("score")
            if _focused_tl is not None else score_with_bonus
        )
        if _prox_score is None:
            _prox_score = score_with_bonus
        tl_proximity = _routes.engine.compute_tl_proximity(_prox_score, threat_level)

        # ── CAC Phase D: Forecast recording & resolution ──────────────────
        _escalation = _routes.engine.compute_escalation_progress(
            _db.threat_list(), _db.alert_list(limit=100))
        try:
            _routes.engine.record_forecast(
                _db, core_theater, current_time, threat_level, _escalation)
            _routes.engine.resolve_pending_forecasts(
                _db, core_theater, current_time, threat_level)
        except Exception:
            pass  # Non-critical

        system_note = _routes.engine.build_system_note(threat_level, domain_scores, convergence_level, rationale, noise_filters_applied, tl_held)
        # Append new analysis annotations
        if is_triangulated:
            system_note += f" TRIANGULATION: {tri_detail}"
        if is_silent_div:
            system_note += f" SILENT DIVERGENCE [{silent_div_conf}]: cyber+physical active, info silent."
        if theater_baseline.get("is_anomalous"):
            system_note += (f" THEATER BASELINE ANOMALY: Z={theater_baseline['z_score']:.1f} "
                            f"(mean={theater_baseline['baseline_mean']:.1f}, "
                            f"std={theater_baseline['baseline_std']:.1f}, "
                            f"n={theater_baseline['samples']})")

        # ── CAC: Context Alignment & Direction Summary ─────────────────────────
        context_alignment = _routes.engine.compute_context_alignment(rationale)
        direction_summary = _routes.engine.compute_direction_summary(rationale)

        # ── CAC: Daily summary recording ──────────────────────────────────────
        _day_bucket = int(current_time // 86400) * 86400
        try:
            _fired_sensors = [e.sensor for e in rationale if e.status == "FIRED" and not e.suppressed]
            _db.daily_summary_upsert(
                core_theater, _day_bucket,
                avg_score=score_with_bonus, max_score=score_with_bonus,
                min_tl=threat_level, max_tl=threat_level,
                fired_sensors=_fired_sensors,
                domain_scores=domain_scores,
                context_alignment=context_alignment,
                summary={"convergence_level": convergence_level})
        except Exception:
            pass  # Non-critical; never break scoring on summary recording

        # ── CAC: Co-occurrence statistics update ──────────────────────────────
        _fired_set = {e.sensor for e in rationale if e.status == "FIRED" and not e.suppressed}
        _fired_list = sorted(_fired_set)
        for i, sa in enumerate(_fired_list):
            for sb in _fired_list[i + 1:]:
                try:
                    _db.cooccurrence_update(sa, sb, core_theater, both_fired=True)
                except Exception:
                    pass

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
                "recent_hits":         list(TelegramMirrorSensor._intercept_log[:10]),
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
            "escalation": _escalation,
            # Confidence Propagation: per-domain confidence and TL boundary proximity
            "confidence": {
                "domain_confidences": domain_confidences,
                "min_confidence": round(min(domain_confidences.values()), 3) if domain_confidences else 1.0,
            },
            "tl_proximity": tl_proximity,
            # A2: Projected ETA to next TL boundary, in seconds. Computed
            # from velocity and TL distance — converts pt-based proximity
            # into a time the analyst can act on. Direction matches sign of
            # velocity: positive eta = escalating, negative eta = de-escalating.
            "eta_to_next_tl_sec": (
                _routes.engine.compute_eta_to_next_tl(tl_proximity, velocity_val)
                if tl_proximity else None
            ),
            # A4: HOD anomaly Z-score for the focused theater's cyber spike,
            # measuring deviation from the 28-day same-hour-of-day baseline.
            # Distinguishes "anomalous for this hour" from "anomalous overall".
            "hod_z": round(hod_z, 2) if hod_valid else None,
            "hod_n": hod_n,
            # CAC: Context-Aware Convergence
            "context_alignment": context_alignment,
            "direction_summary": direction_summary,
            # A2: Theater Baseline Risk (auto-calculated Z-score)
            "theater_baseline": theater_baseline,
            # A3: Triangulation (3-domain quality confirmation)
            "triangulation": {
                "is_triangulated": is_triangulated,
                "bonus":           tri_bonus,
                "detail":          tri_detail,
            },
            # A1: Silent Divergence (cyber+physical active, info silent)
            "silent_divergence": {
                "detected":    is_silent_div,
                "confidence":  silent_div_conf,
                "detail":      silent_div_detail,
            },
            # Phase 4: IHR / RIPE Atlas / Tor Metrics
            "ihr": {
                "core_disco": ihr_disco.get(core_theater, []),
                "core_delay": ihr_delay.get(core_theater, []),
                "core_hegemony": ihr_hegemony.get(core_theater, []),
                "status": ihr_country_status.get(core_theater, "NORMAL"),
                "disco_countries": [c for c, s in ihr_country_status.items() if s == "DISCO_EVENT"],
            },
            "ripe_atlas": {
                "core_probes": atlas_probes.get(core_theater),
                "core_latency": atlas_latency.get(core_theater),
                "status": atlas_country_status.get(core_theater, "NORMAL"),
            },
            "tor_metrics": {
                "core_relays": tor_relays.get(core_theater),
                "core_clients": tor_clients.get(core_theater),
                "status": tor_country_status.get(core_theater, "NORMAL"),
            },
            # Phase C: New sensors S1-S7
            "notam": {
                "core": notam_data.get(core_theater),
                "status": notam_country_status.get(core_theater, "NORMAL"),
            },
            "travel_advisory": {
                "core": travel_advisories.get(core_theater),
                "all": {t: travel_advisories.get(t) for t in strategic_theaters_set if travel_advisories.get(t)},
            },
            "ooni": {
                "core": ooni_data.get(core_theater),
                "status": ooni_country_status.get(core_theater, "NORMAL"),
                "adversary": {a: ooni_data.get(a) for a in adversary_states if ooni_data.get(a)},
            },
            "seismic": seismic_data,
            "mil_support_air": {
                "core": mil_air_data.get(core_theater),
                "all": mil_air_data,
            },
            "gps_jamming": {
                "core": gps_jam_data.get(core_theater),
                "status": gps_country_status.get(core_theater, "NO_DATA"),
            },
            "ct_log": {
                "core": ct_data.get(core_theater),
                "status": ct_country_status.get(core_theater, "NORMAL"),
            },
            # Phase D: Co-occurrence boost & Forecast accuracy
            "cooccurrence_boost": cooc_boost,
            "forecast_accuracy": _db.forecast_accuracy_summary(core_theater),
        }

        score_breakdown = {
            "core_spike_val": round(core_spike, 2), "core_spike_2x": core_spike > 2.0, "core_spike_4x": core_spike > 4.0, "core_spike_6x": core_spike > 6.0,
            "high_correlation": high_correlation, "core_shifted": core_shifted, "major_adversary": major_adversary, "core_degraded": core_degraded,
            "is_coordinated": is_coordinated, "tl1_hard": tl1_hard, "total_score": total_score,
            "convergence_bonus": conv_bonus, "sequence_bonus": seq_bonus, "temporal_bonus": temporal_bonus,
            "triangulation_bonus": tri_bonus, "is_triangulated": is_triangulated,
            "score_with_bonus": score_with_bonus, "threat_raw": tl_raw, "threat_held": tl_held,
            "is_c2_sync": is_c2_sync, "is_maskirovka": is_maskirovka,
            "is_silent_divergence": is_silent_div, "silent_divergence_conf": silent_div_conf,
            "theater_baseline": theater_baseline,
            "cooccurrence_boost": _cooc_factor,
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
            "focus": _req_focus,
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
                        "ihr_status": ihr_country_status.get(code, "NORMAL"),
                        "ihr_disco": ihr_disco.get(code),
                        "ripe_atlas": {"probes": atlas_probes.get(code), "latency": atlas_latency.get(code), "status": atlas_country_status.get(code, "NORMAL")} if atlas_probes.get(code) else None,
                        "tor_metrics": {"relays": tor_relays.get(code), "clients": tor_clients.get(code), "status": tor_country_status.get(code, "NORMAL")} if tor_relays.get(code) else None,
                    } for code in (strategic_theaters_set | {c for c, s in ioda_data.items() if s == "BGP_OUTAGE"} | {c for c, s in ihr_country_status.items() if s != "NORMAL"}) if code in COUNTRY_COORDS
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
        # Active theater set for frontend target filtering (Target Visibility,
        # Live Threat Telemetry) and Situation Board. Derived entirely from the
        # focused scenario's participants (ADR-005). Exposed under strategic_alert
        # so the frontend can read it as strat.active_theaters.
        _active_theaters = set()
        if core_theater:
            _active_theaters.add(core_theater)
        _active_theaters.update(correlate_targets)
        _active_theaters.update(adversary_states)
        _new_cache["strategic"]["active_theaters"] = sorted(_active_theaters)
        _new_cache["focused_scenario"] = _focused_id

        # Scenario results are computed upstream (see scenario scoring block
        # earlier in this function — it drives `threat_level` as the single
        # source of truth). Here we just propagate to cache.
        _new_cache["scenarios"] = _scenario_results
        _new_cache["scenario_history_starts_at"] = _db.scenario_history_start()

        # ── Phase C: What-changed diff (under lock with cache swap) ────────
        global _prev_scenario_domains, _prev_scenario_signals
        _what_changed = None
        with _global_cache_lock:
            st.global_cache = _new_cache
            if _focused_id and _focused_id in _scenario_results:
                _cur_doms = _scenario_results[_focused_id].get("domains", {})
                _cur_sigs = set()
                for _c in (_scenario_results[_focused_id]
                           .get("contributions", [])):
                    if isinstance(_c, dict):
                        _s = _c.get("signal", {})
                        _cur_sigs.add(_s.get("sensor", ""))
                _prev_doms = _prev_scenario_domains.get(_focused_id, {})
                _prev_sigs = _prev_scenario_signals.get(_focused_id, set())
                if _prev_doms:
                    _dom_deltas = {
                        d: round(_cur_doms.get(d, 0) - _prev_doms.get(d, 0), 2)
                        for d in ("cyber", "physical", "info")
                        if abs(_cur_doms.get(d, 0) - _prev_doms.get(d, 0)) > 0.01
                    }
                    _new_sigs = sorted(_cur_sigs - _prev_sigs - {""})
                    _lost_sigs = sorted(_prev_sigs - _cur_sigs - {""})
                    if _dom_deltas or _new_sigs or _lost_sigs:
                        _what_changed = {
                            "domain_deltas": _dom_deltas,
                            "new_signals": _new_sigs[:5],
                            "removed_signals": _lost_sigs[:5],
                        }
                _prev_scenario_domains[_focused_id] = dict(_cur_doms)
                _prev_scenario_signals[_focused_id] = _cur_sigs

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

        # ── Strategic Climate Engine update ───────────────────────────────────
        try:
            from radar.climate_state import climate_engine
            climate_engine.update(_routes.registry)
        except Exception as _ce:
            log.debug(f"[Climate] update error: {_ce}")

        # ── Situation Board update ────────────────────────────────────────────
        try:
            from radar.situation_state import situation_engine
            situation_engine.update(_routes.registry, _new_cache)
        except Exception as _se:
            log.debug(f"[Situation] update error: {_se}")

        # ── WebSocket push + external notifications ──────────────────────────
        emit_threat_update(core_theater, _new_cache["strategic"])
        if threat_level != prev_threat_level:
            notify_threat_level_change(core_theater, prev_threat_level, threat_level, score_with_bonus)
            # Phase C: scenario-aware notification with what-changed
            if _focused_id:
                _sc_name = _scenario_results.get(
                    _focused_id, {}).get("name_en", _focused_id)
                notify_scenario_tl_change(
                    _focused_id, _sc_name,
                    prev_threat_level, threat_level,
                    score_with_bonus, _what_changed,
                )
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

    # Snapshot global_cache under lock to prevent reading mid-update
    with _global_cache_lock:
        _cache_snap = st.global_cache
        _snap_data = _cache_snap.get("data", {})
        _snap_strategic = _cache_snap.get("strategic", {})

    results = []
    _degraded_raw = _snap_strategic.get("degraded_theaters_raw", [])
    _degraded_eff = _snap_strategic.get("degraded_theaters", [])
    # Participant role lookup from the focused scenario (for map marker differentiation).
    _focused_participants = focused_scenario_obj.participants if focused_scenario_obj else {}
    # Targets panel: show all focused scenario participants (ADR-005).
    for t in sorted(strategic_theaters_set):
        t_info = COUNTRY_COORDS.get(t)
        if t_info is None:
            log.warning("COUNTRY_COORDS missing for participant %s — using fallback", t)
            _fb = get_fallback_coord(t)
            t_info = {"lat": _fb["lat"], "lng": _fb["lng"], "name": t}
        data = _snap_data.get(t, {"global_share": 0, "global_share_l3": 0, "global_share_l7": 0, "is_vector_shift": False, "shift_actors": [], "sources": []})

        # Compute velocity and acceleration per target
        ts_series_t = _db.ts_get(t)
        t_vel = _routes.engine.compute_velocity(ts_series_t)
        t_ambush, t_ambush_z, _, _ = _routes.engine.detect_ambush_pattern(ts_series_t)
        # Participant role and weight from focused scenario
        _part = _focused_participants.get(t)
        _t_role = _part.role.value if _part else ""
        _t_weight = _part.weight if _part else 0.5
        results.append({
            "lat": t_info["lat"], "lng": t_info["lng"], "info": t_info["name"], "code": t,
            "role": _t_role,
            "participant_weight": _t_weight,
            "global_share": data.get("global_share", 0.0), "global_share_l3": data.get("global_share_l3", 0.0), "global_share_l7": data.get("global_share_l7", 0.0),
            "is_bgp_outage": t in _degraded_raw,
            "is_bgp_effective": t in _degraded_eff,
            "is_vector_shift": data.get("is_vector_shift", False), "shift_actors": data.get("shift_actors", []),
            "trend_history": _db.series_get(t, "combined"), "trend_history_l3": _db.series_get(t, "l3"), "trend_history_l7": _db.series_get(t, "l7"),
            "sources": data.get("sources", []),
            "velocity": round(t_vel, 5),
            "is_ambush": t_ambush,
            "ambush_z":  t_ambush_z,
        })

    # Climate gauge summary (lightweight, embedded in main response)
    try:
        from radar.climate_state import climate_engine
        _climate = climate_engine.get_summary()
        _climate_gauge = _climate.get("gauge", {})
    except Exception:
        _climate_gauge = {}

    _scenario_cached = _cache_snap.get("scenarios", {})
    _cache_age = int(current_time - _cache_snap.get("time", current_time))
    _scenario_results = {}
    for _sk, _sv in _scenario_cached.items():
        _sr = dict(_sv)
        _sr["data_freshness_sec"] = _cache_age
        _scenario_results[_sk] = _sr

    # Build participant map for map rendering (all participants with coordinates).
    # This enables the frontend to show non-active participants as role-colored
    # markers even when they have no active sensor signals.
    _active_codes = {r["code"] for r in results}
    _participant_map = {}
    for _pc, _pp in _focused_participants.items():
        _pc_coord = COUNTRY_COORDS.get(_pc)
        if _pc_coord is None:
            continue
        _participant_map[_pc] = {
            "lat": _pc_coord["lat"],
            "lng": _pc_coord["lng"],
            "name": _pc_coord["name"],
            "role": _pp.role.value,
            "weight": _pp.weight,
            "active": _pc in _active_codes,
        }

    _resp = jsonify({
        "timestamp":       datetime.datetime.now().isoformat(),
        "sensor_health":   _routes.registry.health_report(),
        "strategic_alert": _snap_strategic,
        "targets":         results,
        "threat_history":  _db.threat_list(),
        "climate_gauge":   _climate_gauge,
        "focused_scenario": focused_id,
        "scenarios":       _scenario_results,
        "scenario_history_starts_at": _cache_snap.get("scenario_history_starts_at"),
        "participants":    _participant_map,
    })
    _resp.headers["Deprecation"] = "true"
    _resp.headers["Sunset"] = "2026-10-01"
    _resp.headers["X-Deprecation-Notice"] = (
        "Fields 'targets', 'strategic_alert', 'threat_history' are deprecated. "
        "Use 'scenarios' for scenario-centric data. "
        "These fields will be removed after 2026-10-01."
    )
    return _resp

