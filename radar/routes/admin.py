"""radar.routes.admin -- Admin-only endpoints: config, sensor toggle, persist."""
from __future__ import annotations
import os
import re
import json
import datetime
from flask import jsonify, request
from radar.config import PERSISTENCE_STATE_FILE
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

