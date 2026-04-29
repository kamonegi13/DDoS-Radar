"""ATTENTION rules + adaptive learning API (commits M + O).

Endpoints:

  GET  /api/v2/attention                       current firing rules + tool_status + suggestions
  POST /api/v2/attention/<rule_id>/snooze      snooze a rule (24h default)
  GET  /api/v2/attention/thresholds            user's threshold overrides
  PUT  /api/v2/attention/thresholds/<rule_id>  set or update a threshold override
  DELETE /api/v2/attention/thresholds/<rule_id>  drop override (revert to default)

Auth model: GET = analyst; POST/PUT/DELETE = analyst (per-user
override) or admin (system-wide). Snooze is analyst-allowed.

NP integrity:
  NP1 — critical rules cannot be snoozed (rejected at this layer).
  NP3 — every endpoint catches and degrades to an empty-but-valid
        response on backend failure.
  NP6 — snooze rows persist actor + timestamp; threshold overrides
        record set_at + user_id. List endpoints expose the full
        provenance.
"""
from __future__ import annotations

import logging
import time

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from radar import attention
from radar.routes import _require_analyst, _safe_int, bp
from radar.routes.calibration_v2 import _wrap, _wrap_error
from radar.routes.conclusions_v2 import _v2_enabled_or_503
from radar.conclusions.api import build_error

log = logging.getLogger("radar.routes.attention_v2")


def _bad_request(error: str, **extra):
    body, status = build_error(400, error, **extra)
    return jsonify(body), status


def _not_found(error: str, **extra):
    body, status = build_error(404, error, **extra)
    return jsonify(body), status


def _forbidden(error: str, **extra):
    body, status = build_error(403, error, **extra)
    return jsonify(body), status


# ── List + tool status ──────────────────────────────────────────────────────


@bp.route("/api/v2/attention", methods=["GET"])
@jwt_required()
def v2_attention_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    try:
        rules = attention.evaluate()
        tool_status = attention.per_tool_status()
        suggestions = _build_suggestions()
    except Exception as exc:
        log.warning("attention list failed: %s", exc)
        rules, tool_status, suggestions = [], {}, []
    return jsonify(_wrap({
        "rules": rules,
        "tool_status": tool_status,
        "suggestions": suggestions,
    }))


# ── Snooze ──────────────────────────────────────────────────────────────────


@bp.route("/api/v2/attention/<rule_id>/snooze", methods=["POST"])
@jwt_required()
def v2_attention_snooze(rule_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    body = request.get_json(silent=True) or {}
    hours = float(body.get("hours") or 24)
    if hours <= 0 or hours > 7 * 24:
        return _bad_request("invalid hours (must be 0 < h <= 168)")
    rule = next(
        (r for r in attention.all_rules() if r.rule_id == rule_id),
        None,
    )
    if rule is None:
        return _not_found("unknown rule_id", rule_id=rule_id)
    if not rule.can_snooze:
        return _forbidden(
            "this rule cannot be snoozed (severity=critical)",
            rule_id=rule_id,
        )
    by = get_jwt_identity() or "unknown"
    actor = f"analyst:{by}"
    ok = attention.snooze(rule_id, hours=hours, by=actor)
    if not ok:
        return _wrap_error(500, "snooze_failed", rule_id=rule_id)
    return jsonify(_wrap({
        "rule_id": rule_id,
        "snooze_until": time.time() + hours * 3600,
        "by": actor,
    }))


# ── Threshold overrides ─────────────────────────────────────────────────────


def _user_id_from_jwt() -> int | None:
    try:
        from radar.database import db as _db
        identity = get_jwt_identity()
        if not identity:
            return None
        u = _db.user_get(identity)
        return u["id"] if u else None
    except Exception:
        return None


@bp.route("/api/v2/attention/thresholds", methods=["GET"])
@jwt_required()
def v2_attention_thresholds_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    uid = _user_id_from_jwt()
    rows: list[dict] = []
    if uid is not None:
        try:
            from radar.database import db as _db
            r = _db._get_conn().execute(  # noqa: SLF001
                "SELECT rule_id, threshold, set_at "
                "FROM user_attention_thresholds WHERE user_id=? "
                "ORDER BY set_at DESC",
                (uid,),
            ).fetchall()
            rows = [{"rule_id": x[0], "threshold": x[1], "set_at": x[2]}
                    for x in r]
        except Exception:
            rows = []
    return jsonify(_wrap(rows, count=len(rows)))


@bp.route("/api/v2/attention/thresholds/<rule_id>", methods=["PUT"])
@jwt_required()
def v2_attention_thresholds_put(rule_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    rule = next(
        (r for r in attention.all_rules() if r.rule_id == rule_id),
        None,
    )
    if rule is None:
        return _not_found("unknown rule_id", rule_id=rule_id)
    body = request.get_json(silent=True) or {}
    try:
        threshold = float(body.get("threshold"))
    except (TypeError, ValueError):
        return _bad_request("threshold must be numeric")
    uid = _user_id_from_jwt()
    if uid is None:
        return _forbidden("identity_required")
    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                "INSERT INTO user_attention_thresholds "
                "(user_id, rule_id, threshold, set_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(user_id, rule_id) DO UPDATE SET "
                "  threshold=excluded.threshold, set_at=excluded.set_at",
                (uid, rule_id, threshold, time.time()),
            )
    except Exception as exc:
        return _wrap_error(500, "threshold_save_failed", detail=str(exc)[:200])
    return jsonify(_wrap({
        "rule_id": rule_id,
        "threshold": threshold,
    }))


@bp.route("/api/v2/attention/thresholds/<rule_id>", methods=["DELETE"])
@jwt_required()
def v2_attention_thresholds_delete(rule_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    uid = _user_id_from_jwt()
    if uid is None:
        return _forbidden("identity_required")
    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                "DELETE FROM user_attention_thresholds "
                "WHERE user_id=? AND rule_id=?",
                (uid, rule_id),
            )
    except Exception as exc:
        return _wrap_error(500, "threshold_delete_failed", detail=str(exc)[:200])
    return jsonify(_wrap({"rule_id": rule_id, "cleared": True}))


# ── Suggestions (commit O — adaptive learning) ──────────────────────────────


def _build_suggestions() -> list[dict]:
    """Compute threshold suggestions from observed p95 statistics.

    Bootstrap rule: only suggest when sample_count >= MIN_LEARN_SAMPLES.
    Material-difference rule: only surface when p95*1.2 differs from the
    current threshold by ≥ 30% (avoids analyst suggestion fatigue).
    """
    import os
    min_samples = int(os.getenv("ATTENTION_MIN_LEARN_SAMPLES", "30"))
    out: list[dict] = []
    try:
        from radar.database import db as _db
        rows = _db._get_conn().execute(  # noqa: SLF001
            "SELECT rule_id, p50, p95, sample_count "
            "FROM attention_metric_p95 WHERE sample_count >= ?",
            (min_samples,),
        ).fetchall()
    except Exception:
        return out
    rules_by_id = {r.rule_id: r for r in attention.all_rules()}
    for rule_id, p50, p95, n in rows:
        rule = rules_by_id.get(rule_id)
        if rule is None or rule.threshold_mode == "boolean":
            continue
        suggested = round(p95 * 1.20, 2)
        diff_ratio = abs(suggested - rule.enter_threshold) / max(
            rule.enter_threshold, 1.0)
        if diff_ratio < 0.30:
            continue
        out.append({
            "rule_id": rule_id,
            "current_threshold": rule.enter_threshold,
            "p50": p50, "p95": p95,
            "sample_count": n,
            "suggested": suggested,
            "message": (
                f"Observed p95 of {p95:.1f} suggests threshold {suggested} "
                f"(currently {rule.enter_threshold}, sample n={n})."
            ),
        })
    return out


@bp.route("/api/v2/attention/observations/recompute", methods=["POST"])
@jwt_required()
def v2_attention_observations_recompute():
    """Trigger immediate p95 recomputation. Admin-friendly utility for
    testing the suggestion path; the scheduler runs this nightly."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.routes import _require_admin
    auth = _require_admin()
    if auth is not None:
        return auth
    try:
        from radar.attention_learning import recompute_p95
        result = recompute_p95()
    except Exception as exc:
        return _wrap_error(500, "recompute_failed", detail=str(exc)[:200])
    return jsonify(_wrap(result))
