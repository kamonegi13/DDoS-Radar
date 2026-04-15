"""radar.routes.admin -- Admin-only endpoints: config, sensor toggle, persist,
   noise exclusion, confirmed threats."""
from __future__ import annotations
import os
import re
import json
import datetime
import time as _time
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
from radar.config import PERSISTENCE_STATE_FILE
from radar.database import db as _db
from radar.persistence import save_state
from radar.sensors.telegram import TelegramMirrorSensor
import radar.routes as _routes
from radar.routes import bp, _require_admin

# -- Secret masking for GET /api/env_config -----------------------------------
_SECRET_PATTERNS = ("SECRET", "PASSWORD", "TOKEN", "WEBHOOK", "API_KEY")

def _mask_value(key: str, val: str) -> str:
    """Mask sensitive config values, showing only the last 4 characters."""
    if any(p in key.upper() for p in _SECRET_PATTERNS):
        return val[-4:].rjust(len(val), '*') if len(val) > 4 else '****'
    return val

@bp.route("/api/env_config", methods=["GET"])
def api_env_config_get():
    """Read config.env and return all key=value pairs as JSON (excluding comments).
    For keys missing from config.env, fall back to the currently running radar.config
    values so the CONFIG panel always shows meaningful defaults."""
    auth_err = _require_admin()
    if auth_err: return auth_err
    config = {}
    try:
        with open("config.env", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                # Strip inline comments and surrounding quotes
                if "  #" in val:
                    val = val.split("  #", 1)[0]
                val = val.strip().strip('"').strip("'")
                config[key] = val
    except FileNotFoundError:
        return jsonify({"error": "config.env not found"}), 404

    # Fill in missing keys from the currently running radar.config module
    # (these reflect the defaults baked into config.py for any key absent from config.env)
    import radar.config as _cfg
    _FALLBACK_KEYS = {
        "DOMAIN_WEIGHT_CYBER":           str(_cfg.DOMAIN_WEIGHT_CYBER),
        "DOMAIN_WEIGHT_PHYSICAL":        str(_cfg.DOMAIN_WEIGHT_PHYSICAL),
        "DOMAIN_WEIGHT_INFO":            str(_cfg.DOMAIN_WEIGHT_INFO),
        "THREAT_LEVEL_HYSTERESIS_CYCLES": str(_cfg.THREAT_LEVEL_HYSTERESIS_CYCLES),
        "AIRSPACE_ANOMALY_THRESHOLD":    str(_cfg.AIRSPACE_ANOMALY_THRESHOLD),
        "AIRSPACE_CLOSURE_THRESHOLD":    str(_cfg.AIRSPACE_CLOSURE_THRESHOLD),
        "AIRSPACE_WINDOW":               str(_cfg.AIRSPACE_WINDOW),
        "GDELT_TONE_ALERT_THRESHOLD":    str(_cfg.GDELT_TONE_ALERT_THRESHOLD),
        "GDELT_HISTORY_WINDOW":          str(_cfg.GDELT_HISTORY_WINDOW),
        "CONVERGENCE_DUAL_BONUS":        str(_cfg.CONVERGENCE_DUAL_BONUS),
        "CONVERGENCE_FULL_BONUS":        str(_cfg.CONVERGENCE_FULL_BONUS),
        "AMBUSH_ZSCORE_THRESHOLD":       str(_cfg.AMBUSH_ZSCORE_THRESHOLD),
        "DERIVATIVE_WINDOW":             str(_cfg.DERIVATIVE_WINDOW),
        "SYNC_DELTA_MS":                 str(_cfg.SYNC_DELTA_MS),
        "SYNC_C2_THRESHOLD":             str(_cfg.SYNC_C2_THRESHOLD),
        "NARRATIVE_ZSCORE_ALERT":        str(_cfg.NARRATIVE_ZSCORE_ALERT),
        "NARRATIVE_ZSCORE_CRITICAL":     str(_cfg.NARRATIVE_ZSCORE_CRITICAL),
        "NARRATIVE_BASELINE_DAYS":       str(_cfg.NARRATIVE_BASELINE_DAYS),
        "SEQUENCE_WINDOW":               str(_cfg.SEQUENCE_WINDOW),
        "SEQUENCE_FULL_BONUS":           str(_cfg.SEQUENCE_FULL_BONUS),
        "SEQUENCE_PARTIAL_BONUS":        str(_cfg.SEQUENCE_PARTIAL_BONUS),
        "ISR_SURGE_THRESHOLD":           str(_cfg.ISR_SURGE_THRESHOLD),
        "GPS_JAM_THRESHOLD":             str(_cfg.GPS_JAM_THRESHOLD),
        "GPS_JAM_CRITICAL_THRESHOLD":    str(_cfg.GPS_JAM_CRITICAL_THRESHOLD),
        "CT_LOG_SURGE_THRESHOLD":        str(_cfg.CT_LOG_SURGE_THRESHOLD),
        "USGS_MIN_MAGNITUDE":            str(_cfg.USGS_MIN_MAGNITUDE),
        "LLM_AUTO_CONFIRM_THRESHOLD":    str(_cfg.LLM_AUTO_CONFIRM_THRESHOLD),
        "LLM_CONFIDENCE_MIN":            str(_cfg.LLM_CONFIDENCE_MIN),
        "LLM_PENDING_AUTO_REJECT_HOURS":      str(_cfg.LLM_PENDING_AUTO_REJECT_HOURS),
        "INTEL_RETENTION_DAYS":               str(_cfg.INTEL_RETENTION_DAYS),
        "INTEL_ITEM_TTL_HOURS":               str(_cfg.INTEL_ITEM_TTL_HOURS),
        "INTEL_MAX_ITEMS_PER_SOURCE_THEATER": str(_cfg.INTEL_MAX_ITEMS_PER_SOURCE_THEATER),
        "CORROBORATION_WINDOW_HOURS":         str(_cfg.CORROBORATION_WINDOW_HOURS),
        "CORROBORATION_COOLDOWN_HOURS":       str(_cfg.CORROBORATION_COOLDOWN_HOURS),
        "CORROBORATION_MIN_SOURCES":          str(_cfg.CORROBORATION_MIN_SOURCES),
        "CORROBORATION_MIN_INDEPENDENCE":     str(_cfg.CORROBORATION_MIN_INDEPENDENCE),
    }
    for key, default_val in _FALLBACK_KEYS.items():
        if key not in config:
            config[key] = default_val

    # Mask sensitive values before returning
    masked = {k: _mask_value(k, v) for k, v in config.items()}
    return jsonify(masked)


@bp.route("/api/env_config", methods=["POST"])
def api_env_config_post():
    """Write updated key=value pairs to config.env, preserving comments and structure."""
    auth_err = _require_admin()
    if auth_err: return auth_err
    updates = request.json or {}
    if not updates:
        return jsonify({"error": "No data provided"}), 400

    # Sanitize: reject unknown keys and strip control characters from values
    _KNOWN_KEYS = set(_RELOADABLE_KEYS) | {
        "LLM_HOST", "LLM_MODEL", "SERVER_PORT", "SERVER_HOST",
        "JWT_SECRET_KEY", "DEFAULT_ADMIN_PASSWORD",
        "CF_API_TOKEN", "CF_ZONE_ID", "OWM_API_KEY",
        "NOTIFY_SLACK_WEBHOOK", "NOTIFY_TEAMS_WEBHOOK", "NOTIFY_WEBHOOK_URL",
        "CORS_ALLOWED_ORIGINS",
    }
    for key in list(updates.keys()):
        if key not in _KNOWN_KEYS:
            return jsonify({"error": f"Unknown config key: {key}"}), 400
        val = str(updates[key])
        # Strip newlines and control chars to prevent injection
        updates[key] = val.replace('\n', '').replace('\r', '').replace('\x00', '')

    try:
        with open("config.env", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return jsonify({"error": "config.env not found"}), 404

    updated_keys = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, _ = stripped.partition("=")
            key = key.strip()
            if key in updates:
                # Preserve any inline comment on the same line
                original_val_part = line.split("=", 1)[1]
                inline_comment = ""
                if "  #" in original_val_part:
                    inline_comment = "  " + original_val_part.split("  #", 1)[1].rstrip("\n")
                new_lines.append(f"{key}={updates[key]}{inline_comment}\n")
                updated_keys.add(key)
                continue
        new_lines.append(line)

    # Append new keys that were not found in the file
    new_keys = set(updates.keys()) - updated_keys
    # Skip non-config keys
    new_keys.discard("admin-token")
    new_keys.discard("LLM_MODEL_manual")  # UI-only fallback field, not a real config key
    if new_keys:
        new_lines.append("\n")
        for key in sorted(new_keys):
            new_lines.append(f"{key}={updates[key]}\n")
            updated_keys.add(key)

    try:
        with open("config.env", "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except OSError as exc:
        return jsonify({"error": f"Cannot write config.env: {exc}"}), 500

    return jsonify({"ok": True, "updated": sorted(updated_keys)})


# Keys that can be reloaded without a server restart
_RELOADABLE_KEYS = frozenset({
    # LLM intel queue thresholds
    "LLM_AUTO_CONFIRM_THRESHOLD", "LLM_CONFIDENCE_MIN",
    "LLM_PENDING_AUTO_REJECT_HOURS", "INTEL_RETENTION_DAYS",
    "INTEL_ITEM_TTL_HOURS", "INTEL_MAX_ITEMS_PER_SOURCE_THEATER",
    # Notifications (read dynamically in notifications.py)
    "NOTIFY_ENABLED", "NOTIFY_DEBOUNCE_SEC",
    "NOTIFY_SLACK_WEBHOOK", "NOTIFY_TEAMS_WEBHOOK", "NOTIFY_WEBHOOK_URL",
    # Threat scoring thresholds
    "GDELT_TONE_ALERT_THRESHOLD", "GDELT_HISTORY_WINDOW",
    "AIRSPACE_ANOMALY_THRESHOLD", "AIRSPACE_CLOSURE_THRESHOLD",
    "CONVERGENCE_DUAL_BONUS", "CONVERGENCE_FULL_BONUS",
    "THREAT_LEVEL_HYSTERESIS_CYCLES",
    "AMBUSH_ZSCORE_THRESHOLD", "SYNC_DELTA_MS", "SYNC_C2_THRESHOLD",
    "SEQUENCE_WINDOW", "SEQUENCE_FULL_BONUS", "SEQUENCE_PARTIAL_BONUS",
    # Narrative sensor
    "NARRATIVE_ZSCORE_ALERT", "NARRATIVE_ZSCORE_CRITICAL", "NARRATIVE_BASELINE_DAYS",
    # Sensor thresholds
    "ISR_SURGE_THRESHOLD",
    "GPS_JAM_THRESHOLD", "GPS_JAM_CRITICAL_THRESHOLD",
    "CT_LOG_SURGE_THRESHOLD",
    "USGS_MIN_MAGNITUDE",
    # Domain weights
    "DOMAIN_WEIGHT_CYBER", "DOMAIN_WEIGHT_PHYSICAL", "DOMAIN_WEIGHT_INFO",
    # Telegram
    "TELEGRAM_ATTACK_KEYWORDS", "TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD",
    # Cross-source corroboration
    "CORROBORATION_WINDOW_HOURS", "CORROBORATION_COOLDOWN_HOURS",
    "CORROBORATION_MIN_SOURCES", "CORROBORATION_MIN_INDEPENDENCE",
})


@bp.route("/api/env_config/reload", methods=["POST"])
def api_env_config_reload():
    """Re-read config.env and update os.environ for reloadable keys.
    Non-reloadable keys (LLM_HOST, SERVER_PORT, etc.) require a server restart.
    Returns which keys were updated and which require restart.
    """
    auth_err = _require_admin()
    if auth_err:
        return auth_err
    try:
        config = {}
        with open("config.env", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                # Strip inline comments
                if "  #" in val:
                    val = val.split("  #", 1)[0]
                config[key] = val.strip()
    except FileNotFoundError:
        return jsonify({"error": "config.env not found"}), 404

    reloaded = []
    needs_restart = []
    for key, val in config.items():
        if key in _RELOADABLE_KEYS:
            os.environ[key] = val
            reloaded.append(key)
        elif os.environ.get(key) != val:
            needs_restart.append(key)

    return jsonify({"ok": True, "reloaded": sorted(reloaded), "needs_restart": sorted(needs_restart)})


@bp.route("/api/sensor_config", methods=["GET", "POST"])
def sensor_config():
    if request.method == "GET": return jsonify({"sensors": _routes.registry.config_list(), "domain_weights": _routes.engine.DOMAIN_WEIGHTS})
    auth_err = _require_admin()
    if auth_err: return auth_err
    body = request.get_json(silent=True) or {}
    name, enabled = body.get("name", ""), body.get("enabled")
    if not name or enabled is None: return jsonify({"error": "name and enabled are required"}), 400
    if _routes.registry.get(name) is None: return jsonify({"error": f"Unknown sensor: {name}"}), 404
    _routes.registry.set_enabled(name, bool(enabled))
    return jsonify({"ok": True, "sensor": name, "enabled": _routes.registry.get(name).enabled})


@bp.route("/api/telegram_log/clear", methods=["POST"])
def api_telegram_log_clear():
    """Clear the Telegram SIGINT intercept log."""
    auth_err = _require_admin()
    if auth_err: return auth_err
    with TelegramMirrorSensor._intercept_lock:
        TelegramMirrorSensor._intercept_log.clear()
    return jsonify({"ok": True, "ts": datetime.datetime.now(datetime.timezone.utc).isoformat()})


@bp.route("/api/persist_save", methods=["POST"])
def api_persist_save():
    """Manually trigger an immediate state save.  POST /api/persist_save"""
    auth_err = _require_admin()
    if auth_err: return auth_err
    try:
        save_state()
        stat = os.stat(PERSISTENCE_STATE_FILE)
        return jsonify({
            "ok":        True,
            "file":      PERSISTENCE_STATE_FILE,
            "size_kb":   round(stat.st_size / 1024, 1),
            "saved_at":  datetime.datetime.now().isoformat(),
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── CAC: Noise Exclusion API ──────────────────────────────────────────────

@bp.route("/api/noise_exclusion", methods=["GET"])
def api_noise_exclusion_list():
    """List active noise exclusion rules."""
    sensor = request.args.get("sensor")
    theater = request.args.get("theater")
    return jsonify(_db.noise_excl_list(sensor=sensor, theater=theater))


@bp.route("/api/noise_exclusion", methods=["POST"])
def api_noise_exclusion_add():
    """Add a noise exclusion rule. Body: {sensor, theater, pattern, reason, expires_hours?}"""
    auth_err = _require_admin()
    if auth_err: return auth_err
    body = request.get_json(silent=True) or {}
    sensor = body.get("sensor", "")
    if not sensor:
        return jsonify({"error": "sensor is required"}), 400
    reason = body.get("reason", "")
    valid_reasons = ("exercise", "maintenance", "known_noise", "false_positive")
    if reason not in valid_reasons:
        return jsonify({"error": f"reason must be one of: {valid_reasons}"}), 400
    expires_hours = body.get("expires_hours")
    expires_at = _time.time() + float(expires_hours) * 3600 if expires_hours else None
    rule_id = _db.noise_excl_add(
        sensor=sensor,
        theater=body.get("theater", ""),
        pattern=body.get("pattern", ""),
        reason=reason,
        created_by=get_jwt_identity() or "analyst",
        expires_at=expires_at,
    )
    return jsonify({"ok": True, "id": rule_id})


@bp.route("/api/noise_exclusion/<int:rule_id>", methods=["DELETE"])
def api_noise_exclusion_delete(rule_id):
    """Remove a noise exclusion rule."""
    auth_err = _require_admin()
    if auth_err: return auth_err
    ok = _db.noise_excl_remove(rule_id)
    return jsonify({"ok": ok})


# ── CAC: Confirmed Threats API ────────────────────────────────────────────

@bp.route("/api/confirmed_threats", methods=["GET"])
def api_confirmed_threats_list():
    """List confirmed threat events."""
    theater = request.args.get("theater")
    try:
        limit = int(request.args.get("limit", "100"))
    except (ValueError, TypeError):
        limit = 100
    return jsonify(_db.confirmed_threat_list(theater=theater, limit=limit))


@bp.route("/api/confirmed_threats", methods=["POST"])
def api_confirmed_threats_add():
    """Classify an event. Body: {theater, classification, sensors_active[], threat_level, notes}"""
    auth_err = _require_admin()
    if auth_err: return auth_err
    body = request.get_json(silent=True) or {}
    theater = body.get("theater", "")
    classification = body.get("classification", "")
    valid_cls = ("exercise", "maintenance", "confirmed_threat", "false_positive")
    if classification not in valid_cls:
        return jsonify({"error": f"classification must be one of: {valid_cls}"}), 400
    ts = body.get("timestamp", _time.time())
    ct_id = _db.confirmed_threat_add(
        theater=theater,
        ts=ts,
        classification=classification,
        sensors_active=body.get("sensors_active", []),
        threat_level=body.get("threat_level", 5),
        notes=body.get("notes", ""),
        created_by=get_jwt_identity() or "analyst",
    )
    # Notify LLM intel queue to update source credibility based on classification
    from radar.intel_queue import intel_queue as _iq
    _iq.notify_classify_threat(theater, classification, ts)
    return jsonify({"ok": True, "id": ct_id})


# ── CAC: Daily Summary & Forecast API ────────────────────────────────────

@bp.route("/api/daily_summary", methods=["GET"])
def api_daily_summary():
    """Get daily summary for a theater."""
    theater = request.args.get("theater", "")
    try:
        days = int(request.args.get("days", "90"))
    except (ValueError, TypeError):
        days = 90
    return jsonify(_db.daily_summary_get(theater, days))


@bp.route("/api/forecast_accuracy", methods=["GET"])
def api_forecast_accuracy():
    """Get forecast accuracy summary."""
    theater = request.args.get("theater")
    return jsonify(_db.forecast_accuracy_summary(theater))


@bp.route("/api/cooccurrence", methods=["GET"])
def api_cooccurrence():
    """Get co-occurrence statistics."""
    theater = request.args.get("theater")
    return jsonify(_db.cooccurrence_get(theater))


# ── Scenario management (Phase 4) ──────────────────────────────────────────

def _scenario_reload_and_invalidate_cache() -> None:
    """Reload scenario_store from sources and force the next /api/threat_data
    request to rescore. Called after any mutation so that the scoring cache
    (SCORE_REFRESH_SEC gated) does not serve stale scenario definitions.
    """
    from radar.scenarios import scenario_store
    from radar import state as _st
    from radar.state import _global_cache_lock
    scenario_store.reload()
    # Zero out the cache timestamp so the next scoring pass runs immediately
    # regardless of SCORE_REFRESH_SEC. We keep the cache contents so in-flight
    # readers still see valid (if slightly stale) data until rescoring finishes.
    with _global_cache_lock:
        if isinstance(_st.global_cache, dict):
            _st.global_cache["time"] = 0


@bp.route("/api/admin/scenarios", methods=["GET"])
def api_admin_scenario_list():
    auth_err = _require_admin()
    if auth_err: return auth_err
    from radar.scenarios import scenario_store
    all_sc = scenario_store.all()
    db_rows = _db.scenario_list()
    db_ids = {r["id"] for r in db_rows}
    result = []
    for sid, sc in sorted(all_sc.items()):
        d = sc.to_dict()
        d["source"] = "db" if sid in db_ids else "preset"
        d["is_scorable"] = sc.is_scorable
        result.append(d)
    return jsonify({"scenarios": result})


@bp.route("/api/admin/scenarios", methods=["POST"])
def api_admin_scenario_create():
    auth_err = _require_admin()
    if auth_err: return auth_err
    data = request.get_json(silent=True) or {}
    scenario_id = data.get("id", "").strip().lower()

    from radar.scenarios import validate_scenario_id, ScenarioValidationError, scenario_store
    try:
        validate_scenario_id(scenario_id)
    except ScenarioValidationError as e:
        return jsonify({"error": str(e)}), 400

    if scenario_store.get(scenario_id):
        return jsonify({"error": f"Scenario '{scenario_id}' already exists"}), 409

    if not data.get("name_en") or not data.get("name_ja"):
        return jsonify({"error": "name_en and name_ja are required"}), 400
    if not data.get("participants"):
        return jsonify({"error": "At least one participant is required"}), 400

    from radar.scenarios import validate_participant, validate_state
    try:
        if "state" in data:
            validate_state(data["state"], scenario_id)
        for cc, pdata in data["participants"].items():
            validate_participant(cc, pdata, scenario_id)
    except ScenarioValidationError as e:
        return jsonify({"error": str(e)}), 400

    user = get_jwt_identity()
    _db.scenario_upsert(scenario_id, data, changed_by=user)
    _scenario_reload_and_invalidate_cache()
    return jsonify({"ok": True, "id": scenario_id}), 201


@bp.route("/api/admin/scenarios/<scenario_id>", methods=["PUT"])
def api_admin_scenario_update(scenario_id: str):
    auth_err = _require_admin()
    if auth_err: return auth_err
    data = request.get_json(silent=True) or {}

    from radar.scenarios import scenario_store, ScenarioValidationError, validate_participant
    sc = scenario_store.get(scenario_id)
    if not sc:
        return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404

    # PUT is the "edit scenario definition" endpoint. State transitions
    # are governed by ADR-011 and must go through POST /<id>/state so that
    # the transition machine (active→paused→archived→purge, or restore)
    # is enforced. Silently accepting "state" here would let a client jump
    # active→archived directly, bypassing the hysteresis that gives
    # analysts a "paused" buffer to recover from accidental deletes.
    if "state" in data:
        return jsonify({
            "error": "state changes are not allowed via PUT; "
                     "use POST /api/admin/scenarios/<id>/state (ADR-011)"
        }), 400

    merged = sc.to_dict()
    for key in ("name_en", "name_ja", "description_en", "description_ja",
                "core_country", "enabled", "tier"):
        if key in data:
            merged[key] = data[key]
    if "participants" in data:
        merged["participants"] = data["participants"]

    try:
        for cc, pdata in merged["participants"].items():
            validate_participant(cc, pdata, scenario_id)
    except ScenarioValidationError as e:
        return jsonify({"error": str(e)}), 400

    user = get_jwt_identity()
    _db.scenario_upsert(scenario_id, merged, changed_by=user)
    _scenario_reload_and_invalidate_cache()
    return jsonify({"ok": True, "id": scenario_id})


@bp.route("/api/admin/scenarios/<scenario_id>", methods=["DELETE"])
def api_admin_scenario_delete(scenario_id: str):
    auth_err = _require_admin()
    if auth_err: return auth_err

    from radar.scenarios import scenario_store
    purge = request.args.get("purge", "false").lower() == "true"
    user = get_jwt_identity()

    # Delete (active→paused) and purge (archived→hard delete) both require
    # a DB row. Preset-only scenarios (Layer 1) have no DB row until a
    # user mutates them. For delete, materialize the preset into DB so the
    # state-transition machine has a row to operate on. Purge cannot apply
    # to a preset-only scenario (it must first be deleted then archived).
    sc = scenario_store.get(scenario_id)
    if sc is None:
        return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404

    _db_rows = {r["id"] for r in _db.scenario_list()}
    if scenario_id not in _db_rows:
        if purge:
            return jsonify({
                "error": f"Scenario '{scenario_id}' is a preset with no DB row; "
                         f"it cannot be purged. Delete it first (active→paused), "
                         f"then archive (paused→archived), then purge."
            }), 409
        # Materialize the preset as an "active" DB row so scenario_delete
        # can transition it to paused. This preserves ADR-011 semantics.
        _db.scenario_upsert(scenario_id, sc.to_dict(), changed_by=user)

    if purge:
        ok, err = _db.scenario_purge(scenario_id, changed_by=user)
    else:
        ok, err = _db.scenario_delete(scenario_id, changed_by=user)
    if not ok:
        if err == "not_found":
            return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404
        return jsonify({"error": err}), 409

    _scenario_reload_and_invalidate_cache()
    return jsonify({"ok": True, "action": "purge" if purge else "delete"})


@bp.route("/api/admin/scenarios/<scenario_id>/state", methods=["POST"])
def api_admin_scenario_state(scenario_id: str):
    auth_err = _require_admin()
    if auth_err: return auth_err
    data = request.get_json(silent=True) or {}
    new_state = data.get("state", "")

    from radar.scenarios import validate_state, ScenarioValidationError, scenario_store
    try:
        validate_state(new_state, scenario_id)
    except ScenarioValidationError as e:
        return jsonify({"error": str(e)}), 400

    user = get_jwt_identity()
    # Materialize preset-only scenarios into DB so the state machine has
    # a row to operate on (see DELETE endpoint rationale).
    sc = scenario_store.get(scenario_id)
    if sc is None:
        return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404
    _db_rows = {r["id"] for r in _db.scenario_list()}
    if scenario_id not in _db_rows:
        _db.scenario_upsert(scenario_id, sc.to_dict(), changed_by=user)

    ok, err = _db.scenario_update_state(scenario_id, new_state, changed_by=user)
    if not ok:
        if err == "not_found":
            return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404
        return jsonify({"error": err}), 409
    _scenario_reload_and_invalidate_cache()
    return jsonify({"ok": True, "state": new_state})


@bp.route("/api/admin/scenarios/<scenario_id>/enabled", methods=["POST"])
def api_admin_scenario_enabled(scenario_id: str):
    auth_err = _require_admin()
    if auth_err: return auth_err
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", True))

    user = get_jwt_identity()
    from radar.scenarios import scenario_store
    sc = scenario_store.get(scenario_id)
    if sc is None:
        return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404
    _db_rows = {r["id"] for r in _db.scenario_list()}
    if scenario_id not in _db_rows:
        _db.scenario_upsert(scenario_id, sc.to_dict(), changed_by=user)
    ok = _db.scenario_set_enabled(scenario_id, enabled, changed_by=user)
    if not ok:
        return jsonify({"error": f"Scenario '{scenario_id}' not found"}), 404
    _scenario_reload_and_invalidate_cache()
    return jsonify({"ok": True, "enabled": enabled})


@bp.route("/api/admin/scenarios/<scenario_id>/reset", methods=["POST"])
def api_admin_scenario_reset(scenario_id: str):
    auth_err = _require_admin()
    if auth_err: return auth_err

    from radar.scenarios import scenario_store
    user = get_jwt_identity()
    _db.scenario_reset(scenario_id, changed_by=user)
    _scenario_reload_and_invalidate_cache()
    sc = scenario_store.get(scenario_id)
    if not sc:
        return jsonify({"error": f"Scenario '{scenario_id}' has no preset to reset to"}), 404
    return jsonify({"ok": True, "source": "preset"})


@bp.route("/api/admin/scenarios/<scenario_id>/changelog", methods=["GET"])
def api_admin_scenario_changelog(scenario_id: str):
    auth_err = _require_admin()
    if auth_err: return auth_err
    limit = int(request.args.get("limit", "50"))
    logs = _db.scenario_change_log(scenario_id, limit=limit)
    return jsonify({"scenario_id": scenario_id, "changes": logs})

