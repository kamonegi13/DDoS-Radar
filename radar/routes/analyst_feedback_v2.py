"""Cross-conclusion analyst_feedback ledger feed.

Existing surfaces (POST + per-conclusion GET) live in
``conclusions_v2.py``. This module adds the global read-only feed
the SETTINGS audit.feedback page consumes — closes Bucket B item B1
of the 2026-05-07 audit.

Endpoint:
  GET /api/v2/analyst_feedback
    hours          window (default 720 = 30d, max 8760 = 1y)
    limit          row cap (default 200, max 2000)
    analyst_kind   "human" | "auto" (default both)
    label          TRUE_POSITIVE / FALSE_POSITIVE /
                   TRUE_NEGATIVE / FALSE_NEGATIVE (default any)

Response:
  {
    api_version, observed_at, final_judgment_disclaimer,
    summary: {
      window_hours, total, human_total, auto_total,
      distinct_analysts, by_label, by_conclusion_type,
      recall, precision,
    },
    items: [{
      id, conclusion_id, conclusion_type, scenario_id,
      label, analyst_id, observed_at, notes, observed_outcome_url,
    }, ...]
  }

Auth: analyst-or-admin (read-only). NP3-tolerant — DB errors
degrade to an empty payload + ``error`` field rather than 500.
"""
from __future__ import annotations

import time

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from radar import config
from radar.conclusions.api import API_VERSION
from radar.conclusions.feedback import (
    aggregate_feedback_matrix,
    coerce_label,
    list_recent_feedback,
)
from radar.database import db as _db
from radar.routes import _require_analyst, _safe_int, bp
from radar.routes.conclusions_v2 import _v2_enabled_or_503


@bp.route("/api/v2/analyst_feedback", methods=["GET"])
@jwt_required()
def v2_analyst_feedback_list():
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
    analyst_kind = (request.args.get("analyst_kind") or "").strip().lower()
    if analyst_kind not in ("human", "auto"):
        analyst_kind = None
    label_raw = request.args.get("label")
    label = coerce_label(label_raw) if label_raw else None

    body = {
        "api_version": API_VERSION,
        "observed_at": time.time(),
        "final_judgment_disclaimer": config.V2_NP7_DISCLAIMER,
    }
    try:
        body["summary"] = aggregate_feedback_matrix(
            _db, hours=hours, analyst_kind=analyst_kind,
        )
        body["items"] = list_recent_feedback(
            _db, hours=hours, analyst_kind=analyst_kind,
            label=label, limit=limit,
        )
    except Exception as exc:  # noqa: BLE001
        body["summary"] = {
            "window_hours": float(hours),
            "total": 0, "human_total": 0, "auto_total": 0,
            "distinct_analysts": 0,
            "by_label": {}, "by_conclusion_type": {},
            "recall": None, "precision": None,
        }
        body["items"] = []
        body["error"] = str(exc)[:200]
    return jsonify(body)
