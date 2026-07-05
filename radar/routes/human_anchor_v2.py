"""Human-anchor queue — the API surface for weekly human labeling.

Why (2026-07-04): calibration was 100% self-graded (auto labels only,
zero human rows), and the auto-labeler shipped two consecutive silent
defects that no metric could catch. This endpoint serves a short,
deterministic queue of the conclusions whose HUMAN label buys the most
calibration information (see ``radar.conclusions.human_anchor`` for the
selection policy). Answers go through the existing
``POST /api/v2/conclusions/<id>/feedback`` — no new write path.

Endpoint:
  GET /api/v2/human_anchor/queue
    window_days   selection window (default 7, max 30)
    limit         queue size (default HUMAN_ANCHOR_QUEUE_SIZE=5, max 20)

Response:
  {
    api_version, generated_at, final_judgment_disclaimer,
    candidates: [{conclusion_id, scenario_id, conclusion_type, state,
                  observed_at, kind, rationale, suggested_labels}, ...],
    pending, human_labels_window, target_per_week,
  }

Auth: analyst-or-admin. NP3-tolerant: selection failures yield an empty
queue, never a 5xx.
"""
from __future__ import annotations

import os
import time

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from radar.conclusions.api import API_VERSION
from radar.conclusions.human_anchor import (
    DEFAULT_QUEUE_LIMIT,
    DEFAULT_WINDOW_DAYS,
    answer_model_for,
    human_label_count,
    select_anchor_candidates,
)
from radar.database import db as _db
from radar.routes import _require_analyst, _safe_int, bp
from radar.routes.conclusions_v2 import _v2_enabled_or_503


@bp.route("/api/v2/human_anchor/queue", methods=["GET"])
@jwt_required()
def v2_human_anchor_queue():
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard

    window_days = _safe_int(
        request.args.get("window_days"), DEFAULT_WINDOW_DAYS,
        min_val=1, max_val=30,
    )
    default_limit = int(os.getenv("HUMAN_ANCHOR_QUEUE_SIZE",
                                  str(DEFAULT_QUEUE_LIMIT)))
    limit = _safe_int(
        request.args.get("limit"), default_limit, min_val=1, max_val=20,
    )
    target = int(os.getenv("HUMAN_ANCHOR_TARGET_PER_WEEK", "5"))

    now = time.time()
    candidates = select_anchor_candidates(
        _db, now=now, window_days=window_days, limit=limit,
    )

    def _serialize(c):
        am = answer_model_for(c)
        return {
            "conclusion_id":    c.conclusion_id,
            "scenario_id":      c.scenario_id,
            "conclusion_type":  c.conclusion_type,
            "state":            c.state,
            "observed_at":      c.observed_at,
            "kind":             c.kind,
            "rationale":        c.rationale,
            "suggested_labels": list(c.suggested_labels),
            # Natural-language answering model (2026-07-05 UX): the analyst
            # answers `question` with `answer_options`; the confusion-matrix
            # label is pre-derived server-side so the UI never shows raw
            # TP/FP/TN/FN as a choice.
            "question":          am.question,
            "tool_stance":       am.tool_stance,
            "tool_stance_label": am.tool_stance_label,
            "answer_options": [{
                "label":         o.label,
                "maps_to":       o.maps_to,
                "is_escalation": o.is_escalation,
                "tone":          o.tone,
            } for o in am.options],
        }

    from radar import config as _config
    return jsonify({
        "api_version": API_VERSION,
        "generated_at": now,
        "final_judgment_disclaimer": _config.V2_NP7_DISCLAIMER,
        "candidates": [_serialize(c) for c in candidates],
        "pending": len(candidates),
        "human_labels_window": human_label_count(
            _db, since=now - window_days * 86400.0,
        ),
        "target_per_week": target,
    })
