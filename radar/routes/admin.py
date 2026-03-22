"""radar.routes.admin -- Admin-only endpoints: config, sensor toggle, persist,
   noise exclusion, confirmed threats."""
from __future__ import annotations
import os
import re
import json
import datetime
import time as _time
from flask import jsonify, request
from radar.config import PERSISTENCE_STATE_FILE
from radar.database import db as _db
from radar.persistence import save_state
from radar.sensors.telegram import TelegramMirrorSensor
import radar.routes as _routes
from radar.routes import bp, _require_admin

@bp.route("/api/env_config", methods=["GET"])
def api_env_config_get():
    """Read config.env and return all key=value pairs as JSON (excluding comments)."""
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
                val = val.strip().strip('"').strip("'")
                config[key] = val
    except FileNotFoundError:
        return jsonify({"error": "config.env not found"}), 404
    return jsonify(config)


@bp.route("/api/env_config", methods=["POST"])
def api_env_config_post():
    """Write updated key=value pairs to config.env, preserving comments and structure."""
    auth_err = _require_admin()
    if auth_err: return auth_err
    updates = request.json or {}
    if not updates:
        return jsonify({"error": "No data provided"}), 400
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
    if new_keys:
        new_lines.append("\n")
        for key in sorted(new_keys):
            new_lines.append(f"{key}={updates[key]}\n")
            updated_keys.add(key)

    with open("config.env", "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    return jsonify({"ok": True, "updated": sorted(updated_keys)})


@bp.route("/api/sensor_config", methods=["GET", "POST"])
def sensor_config():
    if request.method == "GET": return jsonify({"sensors": _routes.registry.config_list(), "domain_weights": _routes.engine.DOMAIN_WEIGHTS})
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
        created_by=body.get("created_by", "analyst"),
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
    limit = int(request.args.get("limit", "100"))
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
    ct_id = _db.confirmed_threat_add(
        theater=theater,
        ts=body.get("timestamp", _time.time()),
        classification=classification,
        sensors_active=body.get("sensors_active", []),
        threat_level=body.get("threat_level", 5),
        notes=body.get("notes", ""),
        created_by=body.get("created_by", "analyst"),
    )
    return jsonify({"ok": True, "id": ct_id})


# ── CAC: Daily Summary & Forecast API ────────────────────────────────────

@bp.route("/api/daily_summary", methods=["GET"])
def api_daily_summary():
    """Get daily summary for a theater."""
    theater = request.args.get("theater", "")
    days = int(request.args.get("days", "90"))
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

