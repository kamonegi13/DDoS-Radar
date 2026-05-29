"""Phase C1 of the 2026-05-05 observability hardening.

Single read-only endpoint exposing the chronic-inconclusive detector
introduced for ADR-V2-010 / NP5+8 contract enforcement:

  GET /api/v2/observability/chronic_inconclusive

Returns the snapshot from
``radar.conclusions.inconclusive_continuity.chronic_snapshot()``
wrapped in the v2 envelope (``api_version`` / ``observed_at`` /
``final_judgment_disclaimer``). Auth: analyst-or-admin (read-only).

The endpoint lives in its own module rather than appending to
``calibration_v2.py`` to keep the blast radius tight; it follows the
same pattern as ``calibration_governor.py``.

NP3: ``chronic_snapshot`` is internally fault-tolerant — it never
raises — so this route doesn't need its own try/except scaffolding.
"""
from __future__ import annotations

import time

from flask import jsonify
from flask_jwt_extended import jwt_required

from radar import config
from radar.conclusions.api import API_VERSION
from radar.conclusions.inconclusive_continuity import chronic_snapshot
from radar.database import db as _db
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


@bp.route("/api/v2/observability/chronic_inconclusive", methods=["GET"])
@jwt_required()
def v2_observability_chronic_inconclusive():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    return jsonify(_wrap(chronic_snapshot(_db)))
