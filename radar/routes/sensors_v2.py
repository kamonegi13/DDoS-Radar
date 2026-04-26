"""v2 sensor observation API — Layer 3 (Sensor Watchpane) backend.

Phase 3 task 4 (per docs/design/v2-ui.md §6, §7.1): expose a per-sensor
observation surface for the analyst watchpane. After the v25 migration
(Phase 3 follow-up) the scoring tick persists each sensor's score per
cycle into `sensor_observation_ts`, so this endpoint returns real
multi-point series for the requested window. Until at least 2 points have
accumulated for a sensor (fresh DB / first cycle) it falls back to the
prior **degraded mode** with `history_shallow: true`.

Gated behind `config.V2_API_ENABLED` and `_require_analyst()` consistent
with the rest of v2 surfaces.
"""

from __future__ import annotations

import time
from typing import Any

from flask import jsonify, request

from radar import state as st
from radar.routes import _require_analyst, _safe_int, bp
from radar.routes.conclusions_v2 import _v2_enabled_or_503
from radar.state import _global_cache_lock


# Sensor catalog: (sensor_id, domain, label_en) — mirrors WHATIF_SENSOR_CATALOG
# in analytics.py without coupling to its What-If specific fields. Maintained
# manually because rationale_matrix entries can be sparse (sensor only present
# when it fired or was suppressed in the current cycle).
SENSOR_CATALOG: list[dict[str, Any]] = [
    # Cyber
    {"sensor": "cf_spike_core",      "domain": "cyber",    "label": "Cloudflare DDoS Spike"},
    {"sensor": "cf_botnet_overlap",  "domain": "cyber",    "label": "Botnet Overlap"},
    {"sensor": "cf_vector_shift",    "domain": "cyber",    "label": "L7 Vector Shift"},
    {"sensor": "cf_adversary_strike","domain": "cyber",    "label": "Adversary State Strike"},
    {"sensor": "cf_coordinated",     "domain": "cyber",    "label": "Coordinated Multi-Theater"},
    {"sensor": "ripe_bgp",           "domain": "cyber",    "label": "RIPE BGP Anomaly"},
    {"sensor": "threatfox",          "domain": "cyber",    "label": "ThreatFox APT IoC"},
    {"sensor": "ddos_acceleration",  "domain": "cyber",    "label": "DDoS Ambush Pattern"},
    {"sensor": "greynoise",          "domain": "cyber",    "label": "GreyNoise Suppressor"},
    {"sensor": "ct_log",             "domain": "cyber",    "label": "CT Log Surge"},
    # Physical
    {"sensor": "ioda_bgp",           "domain": "physical", "label": "IODA BGP Outage"},
    {"sensor": "opensky",            "domain": "physical", "label": "Airspace Anomaly"},
    {"sensor": "nasa_firms",         "domain": "physical", "label": "NASA FIRMS Thermal"},
    {"sensor": "isr_hotspot",        "domain": "physical", "label": "ISR Surge"},
    {"sensor": "ais_maritime",       "domain": "physical", "label": "AIS Dark / Stationary"},
    {"sensor": "check_host",         "domain": "physical", "label": "Check-Host Survival"},
    {"sensor": "openweather",        "domain": "physical", "label": "Weather (Noise Filter)"},
    {"sensor": "gps_jamming",        "domain": "physical", "label": "GPS Jamming"},
    # Info
    {"sensor": "gdelt",              "domain": "info",     "label": "GDELT Media Tone"},
    {"sensor": "rss_narrative",      "domain": "info",     "label": "RSS Narrative Burst"},
    {"sensor": "telegram_mirror",    "domain": "info",     "label": "Telegram Mirror"},
    {"sensor": "maskirovka_flag",    "domain": "info",     "label": "Maskirovka Detection"},
]

_SENSOR_INDEX = {row["sensor"]: row for row in SENSOR_CATALOG}


@bp.route("/api/v2/sensors/catalog", methods=["GET"])
def v2_sensor_catalog():
    """Return the static sensor catalog for the watchpane add-sensor picker."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err
    return jsonify({
        "api_version": "v2",
        "sensors": SENSOR_CATALOG,
    })


def _lookup_sensor_observation(sensor: str, scope: str) -> dict[str, Any] | None:
    """Pull the most recent qualitative state for `sensor` from the global
    cache's rationale_matrix. `scope` is ignored — the scoring tick already
    filters per the focused scenario, and the persisted history (queried
    separately) carries the per-scope time series. This call only seeds the
    `current` block (status/fired_reason/suppressed) for the response.
    """
    with _global_cache_lock:
        cache = dict(st.global_cache) if st.global_cache else {}
    strat = cache.get("strategic", {})
    rationale = strat.get("rationale_matrix", []) or []
    for entry in rationale:
        if entry.get("sensor") == sensor:
            return entry
    return None


@bp.route("/api/v2/sensors/<sensor_name>/observations", methods=["GET"])
def v2_sensor_observations(sensor_name: str):
    """Per-sensor observation series for the analyst watchpane.

    Query params:
      scope=<country|global|...>  — passed through to response (degraded mode
                                    does not yet filter on scope).
      hours=<int 1..24>           — requested baseline window. Echoed in the
                                    response; degraded mode returns 1 point.

    Degraded mode contract (§7.1):
      observations = single-point list with the current cycle value.
      history_shallow = True so the UI can label the sparkline.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    if sensor_name not in _SENSOR_INDEX:
        return jsonify({
            "api_version": "v2",
            "error": "unknown sensor",
            "sensor": sensor_name,
        }), 404

    scope = request.args.get("scope", "focused") or "focused"
    hours = _safe_int(request.args.get("hours"), 1, min_val=1, max_val=24)

    now_ts = time.time()
    cutoff = now_ts - hours * 3600.0

    # Pull persisted history from sensor_observation_ts (v25 migration).
    persisted: list[tuple[float, float, float | None, str | None]] = []
    try:
        from radar.database import db as _db
        persisted = _db.sensor_obs_recent(sensor_name, scope, cutoff)
    except Exception:
        persisted = []  # Fall back to degraded mode below.

    observations: list[dict[str, Any]] = [
        {"ts": ts, "value": score, "baseline": baseline, "delta_vs_baseline": None}
        for (ts, score, baseline, _status) in persisted
    ]

    # Always overlay the current-cycle qualitative state from rationale_matrix
    # so the row colour reflects suppress/fired even when history is shallow.
    entry = _lookup_sensor_observation(sensor_name, scope)
    status: str | None = None
    fired_reason: str | None = None
    suppressed: bool = False
    suppress_reason: str | None = None
    raw_value: Any = None
    if entry is not None:
        status = entry.get("status")
        fired_reason = entry.get("fired_reason")
        suppressed = bool(entry.get("suppressed", False))
        suppress_reason = entry.get("suppress_reason")
        raw_value = entry.get("value")
        # If we have no persisted points yet (fresh DB / first cycle), seed
        # the chart with the current observation so the watchpane never
        # renders an empty box.
        if not observations:
            score_now = entry.get("score") or 0
            observations.append({
                "ts": now_ts, "value": score_now,
                "baseline": None, "delta_vs_baseline": None,
            })

    history_shallow = len(observations) < 2

    return jsonify({
        "api_version": "v2",
        "sensor": sensor_name,
        "scope": scope,
        "label": _SENSOR_INDEX[sensor_name].get("label"),
        "domain": _SENSOR_INDEX[sensor_name].get("domain"),
        "baseline_window_hours": hours,
        "observations": observations,
        "history_shallow": history_shallow,
        "current": {
            "status": status,
            "fired_reason": fired_reason,
            "suppressed": suppressed,
            "suppress_reason": suppress_reason,
            "raw_value": raw_value,
        },
    })
