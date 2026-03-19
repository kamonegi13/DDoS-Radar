"""radar.routes.history -- Historical analysis API endpoints (/api/history/*)."""
from __future__ import annotations
import time
import json
import datetime
from flask import jsonify, request, Response
from radar.state import ALERT_TIMELINE_MAX
from radar.database import db as _db
from radar.routes import bp, _require_admin

# ─────────────────────────────────────────────────────────────────────────────
# Historical Analysis API
# ─────────────────────────────────────────────────────────────────────────────

@bp.route("/api/history/timeseries", methods=["GET"])
def api_history_timeseries():
    """Return time-series data for a theater.
    GET /api/history/timeseries?theater=TW&hours=168&series=combined,l3,l7
    """
    theater = request.args.get("theater", "TW").upper()
    hours = min(int(request.args.get("hours", "168")), 720)  # max 30 days
    series_types = request.args.get("series", "combined").split(",")

    import time as _t
    cutoff = _t.time() - hours * 3600

    result = {"theater": theater, "hours": hours, "series": {}}

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
    """Return HOD baseline data for a theater.
    GET /api/history/hod_baseline?theater=TW&type=hod_baseline
    """
    theater = request.args.get("theater", "TW").upper()
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
        "theater": theater, "type": table,
        "total_points": len(entries),
        "hod_stats": hod_stats,
        "raw": [{"ts": ts, "value": v} for ts, v in entries[-200:]],
    })


@bp.route("/api/history/alerts", methods=["GET"])
def api_history_alerts():
    """Return alert timeline with optional filtering.
    GET /api/history/alerts?limit=100&since=1710000000
    """
    limit = min(int(request.args.get("limit", "100")), 500)
    since = float(request.args.get("since", "0"))

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
    """Return sequence events with optional theater filter.
    GET /api/history/sequence_events?theater=TW&hours=48
    """
    theater = request.args.get("theater", "").upper()
    hours = min(int(request.args.get("hours", "24")), 168)

    import time as _t
    cutoff = _t.time() - hours * 3600

    if theater:
        events = _db.seq_events_since(theater, cutoff)
        return jsonify({"theater": theater, "hours": hours, "events": events})
    else:
        # All theaters
        theaters = _db.seq_distinct_theaters()
        result = {}
        for th in theaters:
            result[th] = _db.seq_events_since(th, cutoff)
        return jsonify({"hours": hours, "theaters": result})


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
    GET /api/history/export?theater=TW&format=json
    """
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    theater = request.args.get("theater", "TW").upper()

    export = {
        "theater": theater,
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

    from flask import Response
    return Response(
        json.dumps(export, indent=2, default=str, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=radar_export_{theater}.json"},
    )

