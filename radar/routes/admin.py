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
from radar.config import PERSISTENCE_DIR, PERSISTENCE_STATE_FILE
from radar.database import db as _db
from radar.persistence import save_state
from radar.sensors.telegram import TelegramMirrorSensor
import radar.routes as _routes
from radar.routes import bp, _require_admin, _require_analyst, _safe_int, _country_param
from radar.audit_middleware import audit  # Phase 9.6 C20 — NP6 unified audit

# -- Secret-value indicator (used by /api/v2/config/values) -------------------
_SECRET_PATTERNS = ("SECRET", "PASSWORD", "TOKEN", "WEBHOOK", "API_KEY")


def _is_secret_key(key: str) -> bool:
    """True if a config key is a secret (API token, password, webhook URL)."""
    return any(p in key.upper() for p in _SECRET_PATTERNS)


def _secret_indicator(val: str) -> dict:
    """Return a structured indicator object for a secret value.

    The API NEVER returns the real secret value (this was the root cause of
    the 2026-05-04 mask-corruption incident — a UI fed mask-string back into
    POST and the backend wrote it to config.env). Instead we emit:
      {"set": bool, "last4": str|None}
    The frontend renders an empty input with a placeholder showing
    set/unset state + the last 4 characters as proof-of-identity.
    The POST handler refuses to accept a dict (or a mask-string) for secret
    keys, requiring an empty string ("no change") or the new plaintext value.
    """
    if val is None or val == "":
        return {"set": False, "last4": None}
    s = str(val)
    return {"set": True, "last4": s[-4:] if len(s) >= 4 else None}


# Mask-string regex used to defend against legacy clients that still try to
# send a masked string back as the value (defensive — should never trigger
# now that the API returns structured indicators instead of mask strings).
_MASK_STRING_RE = re.compile(r'^\*{3,}[A-Za-z0-9]{0,4}$')


def _looks_like_mask(val: str) -> bool:
    return isinstance(val, str) and bool(_MASK_STRING_RE.match(val))


# ════════════════════════════════════════════════════════════════════════
# v2 config endpoints (registry-driven)
#
# Reads / writes go through radar.config_layered which:
#   - returns the registered metadata (so the UI auto-renders forms)
#   - resolves values via DB → env → default chain
#   - audits every write to config_change_log (NP6)
#   - rejects secret/immutable/bootstrap keys with 403/422
#
# The legacy /api/env_config* endpoints were retired 2026-05-05 once the
# frontend (radar.js _v2ConfigLoad / _v2ConfigSave) was fully migrated.
# ════════════════════════════════════════════════════════════════════════

@bp.route("/api/v2/config/registry", methods=["GET"])
def api_v2_config_registry():
    """Return the full config registry (metadata only — no values).
    Drives the registry-driven Settings form generator. Admin-only.

    Optional query params:
      group=OPERATE|TUNE|LLM_HEALTH|INFRASTRUCTURE|ACCESS
      include_secrets=true|false (default false; secret metadata never
        includes the value, but the metadata itself can be restricted)
    """
    auth_err = _require_admin()
    if auth_err:
        return auth_err
    try:
        from radar.config_layered import all_keys, groups, ALL_GROUPS
    except Exception as exc:
        return jsonify({"error": f"registry unavailable: {exc}"}), 503

    inc_secrets = request.args.get("include_secrets", "true").lower() in ("1","true","yes")
    group = request.args.get("group") or None
    if group is not None and group not in ALL_GROUPS:
        return jsonify({"error": f"unknown group {group!r}"}), 400

    out = []
    for k in all_keys(include_secrets=inc_secrets, group=group):
        out.append({
            "key": k.key,
            "domain": k.domain,
            "group": k.group,
            "type": k.type_,
            "default": (None if k.secret else k.default),
            "description": k.description,
            "what": k.what,
            "why": k.why,
            "when": k.when,
            "secret": k.secret,
            "immutable": k.immutable,
            "restart_required": k.restart_required,
            "bootstrap": k.bootstrap,
            "apply_timing": k.apply_timing,
            "impact_level": k.impact_level,
            "impact_warning": k.impact_warning,
            "unit": k.unit,
            "min_value": k.min_value,
            "max_value": k.max_value,
            "enum": list(k.enum) if k.enum else [],
        })
    return jsonify({
        "registry": out,
        "groups": list(ALL_GROUPS),
        "generated_at": _time.time(),
    })


@bp.route("/api/v2/config/values", methods=["GET"])
def api_v2_config_values():
    """Return current effective values for non-secret keys.

    Each entry: {key, value, source, restart_pending}
      source: 'db' | 'env' | 'default'
      restart_pending: True if DB has an override on a restart_required key
                       and it differs from running env value.
    Secret values are NEVER returned; secret keys appear with value=None
    and source='secret' so the UI can render a masked field.
    """
    auth_err = _require_admin()
    if auth_err:
        return auth_err
    try:
        from radar.config_layered import (
            all_keys, get_config, get_value_source, is_restart_pending,
        )
    except Exception as exc:
        return jsonify({"error": f"registry unavailable: {exc}"}), 503

    out = []
    for k in all_keys(include_secrets=True):
        if k.secret:
            # Structured indicator — value is NEVER returned. last4 lets
            # the UI prove "this is the configured key" without exposing it.
            raw = os.environ.get(k.key, "")
            out.append({
                "key": k.key,
                "value": None,
                "source": "secret",
                "restart_pending": False,
                "indicator": _secret_indicator(raw),
            })
            continue
        out.append({
            "key": k.key,
            "value": get_config(k.key),
            "source": get_value_source(k.key),
            "restart_pending": is_restart_pending(k.key),
        })
    return jsonify({"values": out, "generated_at": _time.time()})


@bp.route("/api/v2/config", methods=["POST"])
@audit(domain="config.runtime",
       key_fn=lambda body, resp: (body or {}).get("key", "(missing)"),
       new_value_fn=lambda body, resp: (body or {}).get("value"))
def api_v2_config_post():
    """Persist a config override.
    Body: {key: str, value: any, reason: str?}
    Returns: {ok, source, restart_pending} or {error}.

    Errors:
      400 — body missing key/value
      403 — key is secret (UI must never write secrets)
      404 — key not in registry
      422 — validation failed (type / range / enum / impact-reason missing)
    """
    auth_err = _require_admin()
    if auth_err:
        return auth_err
    body = request.get_json(silent=True) or {}
    key = body.get("key")
    if not key:
        return jsonify({"error": "missing 'key'"}), 400
    if "value" not in body:
        return jsonify({"error": "missing 'value'"}), 400
    value = body.get("value")
    reason = (body.get("reason") or "").strip() or None

    try:
        from radar.config_layered import (
            set_config, get_meta, get_value_source, is_restart_pending,
        )
    except Exception as exc:
        return jsonify({"error": f"registry unavailable: {exc}"}), 503

    meta = get_meta(key)
    if meta is None:
        return jsonify({"error": f"unknown config key {key!r}"}), 404
    if meta.secret:
        return jsonify({"error": f"key {key!r} is secret — refuse to write"}), 403
    if meta.immutable or meta.bootstrap:
        return jsonify({
            "error": f"key {key!r} is env-only — edit config.env + restart"
        }), 422

    # Defense-in-depth — refuse mask-string writes. Should never trigger
    # because secret keys are rejected with 403 above, but if any future
    # non-secret key briefly passes a masked indicator, this catches it.
    if isinstance(value, str) and _looks_like_mask(value):
        return jsonify({
            "error": "Refusing mask-string write (anti-corruption guard)",
            "key": key,
            "hint": "The API never returns secret values; masked indicators "
                    "are display-only and must not be POSTed back.",
        }), 422

    by = get_jwt_identity() or "unknown"
    ok, msg = set_config(key, value, by=by, reason=reason)
    if not ok:
        # set_config returns False with a descriptive message for any
        # validator/coercion failure. Map all to 422 (semantic invalid).
        return jsonify({"error": msg}), 422
    return jsonify({
        "ok": True,
        "source": get_value_source(key),
        "restart_pending": is_restart_pending(key),
    })


@bp.route("/api/v2/config", methods=["DELETE"])
@audit(domain="config.runtime",
       key_fn=lambda body, resp: (body or {}).get("key", "(missing)"))
def api_v2_config_clear():
    """Drop the DB override for a key (revert to env / code default).
    Body: {key: str, reason: str?}
    """
    auth_err = _require_admin()
    if auth_err:
        return auth_err
    body = request.get_json(silent=True) or {}
    key = body.get("key")
    if not key:
        return jsonify({"error": "missing 'key'"}), 400
    reason = (body.get("reason") or "").strip() or None

    try:
        from radar.config_layered import clear_config, get_meta
    except Exception as exc:
        return jsonify({"error": f"registry unavailable: {exc}"}), 503

    meta = get_meta(key)
    if meta is None:
        return jsonify({"error": f"unknown config key {key!r}"}), 404
    if meta.immutable or meta.bootstrap:
        return jsonify({
            "error": f"key {key!r} is env-only — no DB override to clear"
        }), 422

    by = get_jwt_identity() or "unknown"
    ok, msg = clear_config(key, by=by, reason=reason)
    if not ok:
        return jsonify({"error": msg}), 422
    return jsonify({"ok": True})


@bp.route("/api/sensor_config", methods=["GET", "POST"])
@audit(domain="sensor.enabled",
       key_fn=lambda body, resp: (body or {}).get("name"),
       new_value_fn=lambda body, resp: {"enabled": (body or {}).get("enabled")})
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
        db_path = os.path.join(PERSISTENCE_DIR, "radar.db")
        size_kb = None
        if os.path.exists(db_path):
            stat = os.stat(db_path)
            size_kb = round(stat.st_size / 1024, 1)
        return jsonify({
            "ok":        True,
            "file":      db_path,
            "size_kb":   size_kb,
            "saved_at":  datetime.datetime.now().isoformat(),
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── CAC: Noise Exclusion API ──────────────────────────────────────────────

@bp.route("/api/noise_exclusion", methods=["GET"])
def api_noise_exclusion_list():
    """List active noise exclusion rules."""
    sensor = request.args.get("sensor")
    theater = _country_param("/api/noise_exclusion") or None
    return jsonify(_db.noise_excl_list(sensor=sensor, theater=theater))


@bp.route("/api/noise_exclusion", methods=["POST"])
@audit(domain="sensor.noise_exclusion",
       key_fn=lambda body, resp: (body or {}).get("sensor"))
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
    expires_at = None
    if expires_hours is not None:
        try:
            expires_h = float(expires_hours)
            if expires_h <= 0 or expires_h > 8760:
                return jsonify({"error": "expires_hours must be between 0 and 8760"}), 400
            expires_at = _time.time() + expires_h * 3600
        except (ValueError, TypeError):
            return jsonify({"error": "expires_hours must be a number"}), 400
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
@audit(domain="sensor.noise_exclusion",
       key_fn=lambda body, resp: f"rule_id={request.view_args.get('rule_id') if hasattr(request,'view_args') else '?'}")
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
    theater = _country_param("/api/confirmed_threats") or None
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
    try:
        ts = float(body.get("timestamp", _time.time()))
    except (TypeError, ValueError):
        ts = _time.time()
    now = _time.time()
    if ts < now - 30 * 86400 or ts > now + 60:
        ts = now
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
    """Get daily summary for a country."""
    theater = _country_param("/api/daily_summary")
    try:
        days = int(request.args.get("days", "90"))
    except (ValueError, TypeError):
        days = 90
    return jsonify(_db.daily_summary_get(theater, days))


@bp.route("/api/cooccurrence", methods=["GET"])
def api_cooccurrence():
    """Get co-occurrence statistics."""
    theater = _country_param("/api/cooccurrence") or None
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
        # Phase 3.2 (problem 49): expose admin-override status so the
        # UI can warn analysts when a preset-disabled scenario was
        # turned on via Layer-2 override.
        d["is_admin_override"] = scenario_store.is_enabled_overridden(sid)
        d["preset_enabled"] = scenario_store.preset_enabled(sid)
        d["preset_metadata"] = scenario_store.preset_metadata(sid)
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
@audit(domain="scenario.state",
       key_fn=lambda body, resp:
           (request.view_args or {}).get("scenario_id"))
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
@audit(domain="scenario.enabled",
       key_fn=lambda body, resp:
           (request.view_args or {}).get("scenario_id"))
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
@audit(domain="scenario.reset",
       key_fn=lambda body, resp:
           (request.view_args or {}).get("scenario_id"))
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
    limit = _safe_int(request.args.get("limit", "50"), 50, min_val=1, max_val=500)
    logs = _db.scenario_change_log(scenario_id, limit=limit)
    return jsonify({"scenario_id": scenario_id, "changes": logs})


@bp.route("/api/admin/sensor_health", methods=["GET"])
def api_admin_sensor_health():
    """Aggregate per-sensor health for the operator diagnostics panel.

    Three data sources are merged per sensor:
      1. live introspection from the registry (health enum, CB state,
         last_error, cache age) via to_config_dict()
      2. historical reliability over the requested window from
         sensor_fetch_log (success rate, avg duration)
      3. optional sensor-specific upstream telemetry from
         upstream_health() — duck-typed; only CtLogSensor exposes it
         today and ships ADR-024 failure_modes counters

    Without aggregation operators have to grep three separate panels to
    answer "is sensor X actually getting data?". The summary block at the
    bottom is for at-a-glance fleet status.
    """
    auth_err = _require_analyst()
    if auth_err: return auth_err
    hours = _safe_int(request.args.get("hours", "24"), 24, min_val=1, max_val=168)

    if _routes.registry is None:
        return jsonify({"error": "registry not initialized"}), 503

    reliability_rows = _db.fetch_log_reliability(hours=hours) or []
    reliability_by_name = {r["sensor_name"]: r for r in reliability_rows}

    with _routes.registry._lock:
        sensors_snapshot = list(_routes.registry._sensors.values())

    out_sensors = []
    summary = {
        "total": 0, "ok": 0, "degraded": 0, "stale": 0,
        "error": 0, "circuit_open": 0, "disabled": 0, "initializing": 0,
    }
    for s in sensors_snapshot:
        cfg = s.to_config_dict()
        name = cfg.get("name")
        rel = reliability_by_name.get(name, {})
        upstream = None
        if hasattr(s, "upstream_health"):
            try:
                upstream = s.upstream_health()
            except Exception as e:
                upstream = {"error": f"upstream_health() raised: {type(e).__name__}: {e}"}
        out_sensors.append({
            "name": name,
            "domain": cfg.get("domain"),
            "enabled": cfg.get("enabled"),
            "health": cfg.get("health"),
            "tier": cfg.get("tier"),
            "poll_interval_sec": cfg.get("poll_interval_sec"),
            "cache_age_sec": cfg.get("cache_age_sec"),
            "last_fetch_ts": cfg.get("last_fetch_ts"),
            "last_error": cfg.get("last_error"),
            "cb_state": cfg.get("cb_state"),
            "cb_fail_count": cfg.get("cb_fail_count"),
            "reliability": {
                "window_hours": hours,
                "total_fetches": rel.get("total_fetches", 0),
                "success_rate": rel.get("success_rate", 0.0),
                "avg_duration_ms": rel.get("avg_duration_ms", 0),
                "first_seen": rel.get("first_seen"),
                "last_seen": rel.get("last_seen"),
            },
            "upstream": upstream,
        })

        summary["total"] += 1
        h = (cfg.get("health") or "").lower()
        if not cfg.get("enabled"):
            summary["disabled"] += 1
        elif cfg.get("cb_state") == "OPEN":
            summary["circuit_open"] += 1
        elif h == "ok":
            summary["ok"] += 1
        elif h == "degraded":
            summary["degraded"] += 1
        elif h == "stale":
            summary["stale"] += 1
        elif h == "error":
            summary["error"] += 1
        elif h == "initializing":
            summary["initializing"] += 1

    out_sensors.sort(key=lambda x: (x["name"] or ""))
    return jsonify({
        "ts": _time.time(),
        "window_hours": hours,
        "summary": summary,
        "sensors": out_sensors,
    })


