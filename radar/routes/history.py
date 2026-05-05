"""radar.routes.history -- Historical analysis API endpoints (/api/history/*)."""
from __future__ import annotations
import time
import json
import datetime
from flask import jsonify, request, Response
from radar.state import ALERT_TIMELINE_MAX
from radar.database import db as _db
from radar.routes import bp, _require_admin, _country_param
from radar.scenarios import scenario_store


def _resolve_default_country() -> str:
    """Pick a sensible default ISO country code from the first scorable scenario."""
    for sc in scenario_store.scorable():
        if sc.core_country:
            return sc.core_country.upper()
        if sc.participants:
            return next(iter(sc.participants.keys())).upper()
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# Historical Analysis API
# ─────────────────────────────────────────────────────────────────────────────


def _country_set_payload() -> list[str]:
    """Union of (a) countries with persisted time-series, and (b) participants
    of every scorable scenario."""
    db_countries = set(_db.ts_distinct_theaters())
    cfg_countries: set[str] = set()
    for sc in scenario_store.scorable():
        cfg_countries |= set(sc.participants.keys())
    return sorted(db_countries | cfg_countries)


@bp.route("/api/history/countries", methods=["GET"])
def api_history_countries():
    """Return all configured + historically recorded countries.

    Configured set = union of participants across all scorable scenarios.
    """
    return jsonify({"countries": _country_set_payload()})


@bp.route("/api/history/theaters", methods=["GET"])
def api_history_theaters():
    """Deprecated alias for /api/history/countries.

    Kept so any external/embedded caller still using the legacy path keeps
    working. Body includes BOTH ``theaters`` (legacy key) and ``countries``
    (canonical key); ``Deprecation`` and ``Sunset`` headers signal the move.
    """
    items = _country_set_payload()
    resp = jsonify({"theaters": items, "countries": items})
    resp.headers["Deprecation"] = "true"
    # Sunset 90 days out (RFC 8594 — informational only; we don't auto-cut).
    resp.headers["Sunset"] = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=90)
    ).strftime("%a, %d %b %Y %H:%M:%S GMT")
    resp.headers["Link"] = '</api/history/countries>; rel="successor-version"'
    return resp


@bp.route("/api/history/timeseries", methods=["GET"])
def api_history_timeseries():
    """Return time-series data for a country.
    GET /api/history/timeseries?country=TW&hours=168&series=combined,l3,l7
    (legacy ?theater= still accepted, recorded via SR4 telemetry).
    """
    theater = (_country_param("/api/history/timeseries") or _resolve_default_country()).upper()
    if not theater:
        return jsonify({"error": "theater required"}), 400
    try:
        hours = min(int(request.args.get("hours", "168")), 720)  # max 30 days
    except (ValueError, TypeError):
        hours = 168
    series_types = request.args.get("series", "combined").split(",")

    cutoff = time.time() - hours * 3600

    # ADR-V2-006 A-2: dual-write `country` alongside legacy `theater`.
    result = {"theater": theater, "country": theater, "hours": hours, "series": {}}

    # Timestamped series (ts_db)
    ts_data = _db.ts_get_since(theater, cutoff)
    result["series"]["scored"] = [{"ts": t, "value": v} for t, v in ts_data]

    # Value-only series
    for st in series_types:
        st = st.strip()
        if st in ("combined", "l3", "l7"):
            values = _db.series_get(theater, st)
            result["series"][st] = values

    return jsonify(result)


@bp.route("/api/history/hod_baseline", methods=["GET"])
def api_history_hod_baseline():
    """Return HOD baseline data for a country.
    GET /api/history/hod_baseline?country=TW&type=hod_baseline
    (legacy ?theater= still accepted, recorded via SR4 telemetry).
    """
    theater = (_country_param("/api/history/hod_baseline") or _resolve_default_country()).upper()
    if not theater:
        return jsonify({"error": "theater required"}), 400
    table = request.args.get("type", "hod_baseline")
    if table not in ("hod_baseline", "checkhost_hod", "bgp_hod"):
        return jsonify({"error": "Invalid type"}), 400

    entries = _db.hod_all_entries(table, theater)
    # Group by hour-of-day for analysis
    by_hod = {}
    for bucket, value in entries:
        hod = (bucket // 3600) % 24
        by_hod.setdefault(hod, []).append(value)

    # Compute stats per hour-of-day
    hod_stats = []
    for h in range(24):
        vals = by_hod.get(h, [])
        if vals:
            mean = sum(vals) / len(vals)
            std = (sum((x - mean) ** 2 for x in vals) / len(vals)) ** 0.5
            hod_stats.append({
                "hour": h, "mean": round(mean, 4), "std": round(std, 4),
                "min": round(min(vals), 4), "max": round(max(vals), 4),
                "n": len(vals),
            })
        else:
            hod_stats.append({"hour": h, "mean": None, "std": None,
                              "min": None, "max": None, "n": 0})

    return jsonify({
        # ADR-V2-006 A-2: dual-write `country` alongside legacy `theater`.
        "theater": theater, "country": theater, "type": table,
        "total_points": len(entries),
        "hod_stats": hod_stats,
        "raw": [{"ts": ts, "value": v} for ts, v in entries[-200:]],
    })


@bp.route("/api/history/alerts", methods=["GET"])
def api_history_alerts():
    """Return alert timeline with optional filtering.
    GET /api/history/alerts?limit=100&since=1710000000
    """
    try:
        limit = min(int(request.args.get("limit", "100")), 500)
    except (ValueError, TypeError):
        limit = 100
    try:
        since = float(request.args.get("since", "0"))
    except (ValueError, TypeError):
        since = 0.0

    alerts = _db.alert_list(limit=ALERT_TIMELINE_MAX)
    if since > 0:
        alerts = [a for a in alerts if a.get("ts", 0) >= since]
    alerts = alerts[-limit:]

    return jsonify({
        "total": _db.alert_count(),
        "returned": len(alerts),
        "alerts": alerts,
    })


@bp.route("/api/history/sequence_events", methods=["GET"])
def api_history_sequence_events():
    """Return sequence events with optional country filter.
    GET /api/history/sequence_events?country=TW&hours=48
    (legacy ?theater= still accepted, recorded via SR4 telemetry).
    """
    theater = _country_param("/api/history/sequence_events").upper()
    try:
        hours = min(int(request.args.get("hours", "24")), 168)
    except (ValueError, TypeError):
        hours = 24

    cutoff = time.time() - hours * 3600

    if theater:
        events = _db.seq_events_since(theater, cutoff)
        # ADR-V2-006 A-2: dual-write `country` alongside legacy `theater`.
        return jsonify({"theater": theater, "country": theater, "hours": hours, "events": events})
    else:
        # All theaters
        theaters = _db.seq_distinct_theaters()
        result = {}
        for th in theaters:
            result[th] = _db.seq_events_since(th, cutoff)
        # ADR-V2-006 A-2: dual-write `countries` alongside legacy `theaters`.
        return jsonify({"hours": hours, "theaters": result, "countries": result})


@bp.route("/api/history/threat_levels", methods=["GET"])
def api_history_threat_levels():
    """Return threat level history.
    GET /api/history/threat_levels
    """
    history = _db.threat_list()
    return jsonify({
        "count": len(history),
        "history": [{"ts": ts, "level": lvl} for ts, lvl in history],
    })


@bp.route("/api/history/export", methods=["GET"])
def api_history_export():
    """Export historical data as JSON for offline analysis.
    GET /api/history/export?country=TW&format=json
    (legacy ?theater= still accepted, recorded via SR4 telemetry).
    """
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    theater = (_country_param("/api/history/export") or _resolve_default_country()).upper()
    if not theater:
        return jsonify({"error": "theater required"}), 400

    export = {
        "theater": theater,
        # ADR-V2-006 A-2: dual-write `country` alongside legacy `theater`.
        "country": theater,
        "exported_at": datetime.datetime.now().isoformat(),
        "timeseries_scored": [{"ts": t, "value": v} for t, v in _db.ts_get(theater)],
        "timeseries_combined": _db.series_get(theater, "combined"),
        "timeseries_l3": _db.series_get(theater, "l3"),
        "timeseries_l7": _db.series_get(theater, "l7"),
        "hod_baseline": [{"ts": ts, "value": v}
                         for ts, v in _db.hod_all_entries("hod_baseline", theater)],
        "checkhost_hod": [{"ts": ts, "value": v}
                          for ts, v in _db.hod_all_entries("checkhost_hod", theater)],
        "sequence_events": _db.seq_all_events(theater),
        "threat_history": [{"ts": ts, "level": lvl} for ts, lvl in _db.threat_list()],
    }

    return Response(
        json.dumps(export, indent=2, default=str, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=radar_export_{theater}.json"},
    )

