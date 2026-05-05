"""Phase 3 — observability surface for the auto-apply tier governor.

Single read-only endpoint:

  GET /api/v2/calibration/tier_governor

Returns a snapshot identical to ``auto_apply_tier_governor.governor_snapshot()``
wrapped in the v2 envelope (``api_version`` / ``observed_at`` /
``final_judgment_disclaimer``). Auth: analyst-or-admin (read-only).

The endpoint lives in its own module rather than appending to the
already-large `calibration_v2.py` to keep the blast radius tight; it
re-uses the latter's `_wrap` envelope helper so behaviour stays
consistent.

NP3: governor_snapshot() is internally fault-tolerant — it never
raises — so this route doesn't need its own try/except scaffolding.
"""
from __future__ import annotations

import time

from flask import jsonify
from flask_jwt_extended import jwt_required

from radar import config
from radar.calibration.auto_apply_tier_governor import governor_snapshot
from radar.conclusions.api import API_VERSION
from radar.routes import _require_analyst, bp
from radar.routes.conclusions_v2 import _v2_enabled_or_503


def _wrap(data, **extra) -> dict:
    body = {
        "api_version": API_VERSION,
        "observed_at": time.time(),
        "final_judgment_disclaimer": config.V2_NP7_DISCLAIMER,
        "data": data,
    }
    body.update(extra)
    return body


@bp.route("/api/v2/calibration/tier_governor", methods=["GET"])
@jwt_required()
def v2_calibration_tier_governor():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    return jsonify(_wrap(governor_snapshot()))
