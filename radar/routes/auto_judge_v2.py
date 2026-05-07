"""Auto-judge decision-log feed (B3 of the 2026-05-07 audit).

The Layer 1 / LLM-recheck second-pass writes one row per item to
``auto_judge_decisions`` (see ``radar.database.RadarDB.auto_judge_decision_log``).
That table has been write-only — every row is an audit fact, but no
viewer existed and an analyst had to use ``sqlite3`` to see what the
auto-judge had been deciding. This module is the read-side: a single
endpoint with summary + items, mirroring the analyst_feedback feed
shape.

Endpoint:
  GET /api/v2/auto_judge/decisions
    hours    window (default 720 = 30d, max 8760 = 1y)
    limit    row cap (default 200, max 2000)
    action   filter to confirm / reject / pending
    applied  optional bool — only show items that were actually applied
    overridden optional bool — only show items the analyst later overrode

Response:
  {
    api_version, observed_at, final_judgment_disclaimer,
    summary: {
      window_hours, total, by_action: {confirm, reject, pending},
      applied_total, overridden_total, override_rate,
    },
    items: [{
      id, ts, item_id, action_proposed, confidence, reason,
      layer1_corroborators, layer1_satisfied, applied, applied_at,
      analyst_overrode, analyst_override_action, analyst_override_at,
      analyst_id,
    }, ...]
  }

Auth: analyst-or-admin. NP3-tolerant on DB errors.
"""
from __future__ import annotations

import time

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from radar import config
from radar.conclusions.api import API_VERSION
from radar.database import db as _db
from radar.routes import _require_analyst, _safe_int, bp
from radar.routes.conclusions_v2 import _v2_enabled_or_503


_VALID_ACTIONS = {"confirm", "reject", "pending"}


def _parse_bool(raw: str | None) -> "bool | None":
    if raw is None:
        return None
    s = raw.strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return None


def _list_decisions(*, hours: int, limit: int, action: "str | None",
                     applied: "bool | None",
                     overridden: "bool | None") -> list[dict]:
    cutoff = time.time() - hours * 3600.0
    where = ["ts >= ?"]
    params: list = [cutoff]
    if action in _VALID_ACTIONS:
        where.append("action_proposed = ?")
        params.append(action)
    if applied is not None:
        where.append("applied = ?")
        params.append(1 if applied else 0)
    if overridden is not None:
        where.append("analyst_overrode = ?")
        params.append(1 if overridden else 0)
    params.append(max(1, min(int(limit), 2000)))
    sql = (
        "SELECT id, ts, item_id, action_proposed, confidence, reason, "
        "       layer1_corroborators, layer1_satisfied, applied, "
        "       applied_at, analyst_overrode, analyst_override_action, "
        "       analyst_override_at, analyst_id "
        "FROM auto_judge_decisions "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY ts DESC LIMIT ?"
    )
    rows = _db._get_conn().execute(sql, tuple(params)).fetchall()  # noqa: SLF001
    return [
        {
            "id": r["id"], "ts": r["ts"], "item_id": r["item_id"],
            "action_proposed": r["action_proposed"],
            "confidence": r["confidence"],
            "reason": r["reason"],
            "layer1_corroborators": r["layer1_corroborators"],
            "layer1_satisfied": bool(r["layer1_satisfied"]),
            "applied": bool(r["applied"]),
            "applied_at": r["applied_at"],
            "analyst_overrode": bool(r["analyst_overrode"]),
            "analyst_override_action": r["analyst_override_action"],
            "analyst_override_at": r["analyst_override_at"],
            "analyst_id": r["analyst_id"],
        }
        for r in rows
    ]


def _summarize(*, hours: int) -> dict:
    cutoff = time.time() - hours * 3600.0
    rows = _db._get_conn().execute(  # noqa: SLF001
        "SELECT action_proposed, applied, analyst_overrode, COUNT(*) AS n "
        "FROM auto_judge_decisions WHERE ts >= ? "
        "GROUP BY action_proposed, applied, analyst_overrode",
        (cutoff,),
    ).fetchall()
    by_action = {a: 0 for a in _VALID_ACTIONS}
    total = 0
    applied_total = 0
    overridden_total = 0
    for r in rows:
        n = int(r["n"])
        total += n
        a = r["action_proposed"]
        if a in by_action:
            by_action[a] += n
        if int(r["applied"]) == 1:
            applied_total += n
        if int(r["analyst_overrode"]) == 1:
            overridden_total += n
    override_rate = (
        round(overridden_total / applied_total, 4)
        if applied_total > 0 else None
    )
    return {
        "window_hours":     float(hours),
        "total":            total,
        "by_action":        by_action,
        "applied_total":    applied_total,
        "overridden_total": overridden_total,
        "override_rate":    override_rate,
    }


@bp.route("/api/v2/auto_judge/decisions", methods=["GET"])
@jwt_required()
def v2_auto_judge_decisions():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    hours = _safe_int(request.args.get("hours"), 720,
                       min_val=1, max_val=8760)
    limit = _safe_int(request.args.get("limit"), 200,
                       min_val=1, max_val=2000)
    action = (request.args.get("action") or "").strip().lower() or None
    if action not in _VALID_ACTIONS:
        action = None
    applied = _parse_bool(request.args.get("applied"))
    overridden = _parse_bool(request.args.get("overridden"))

    body = {
        "api_version": API_VERSION,
        "observed_at": time.time(),
        "final_judgment_disclaimer": config.V2_NP7_DISCLAIMER,
    }
    try:
        body["summary"] = _summarize(hours=hours)
        body["items"] = _list_decisions(
            hours=hours, limit=limit, action=action,
            applied=applied, overridden=overridden,
        )
    except Exception as exc:  # noqa: BLE001
        body["summary"] = {
            "window_hours": float(hours),
            "total": 0, "by_action": {a: 0 for a in _VALID_ACTIONS},
            "applied_total": 0, "overridden_total": 0,
            "override_rate": None,
        }
        body["items"] = []
        body["error"] = str(exc)[:200]
    return jsonify(body)
