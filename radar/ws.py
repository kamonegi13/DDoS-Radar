"""radar.ws -- WebSocket event handlers using Flask-SocketIO.

Event types pushed to clients:
  - threat_update:    Full strategic data (replaces polling /api/threat_data)
  - ambush_alert:     Ambush Pattern detection notification
  - sequence_event:   New escalation chain event registered
  - sensor_status:    Sensor health change notification

Clients subscribe to a theater room via 'subscribe_theater' event.
Polling fallback via /api/threat_data remains functional.
"""
from __future__ import annotations
import logging
import os
from flask import request as _flask_request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect

log = logging.getLogger("radar")

# SocketIO instance — initialized by init_socketio()
socketio: SocketIO | None = None


def init_socketio(app, **kwargs) -> SocketIO:
    """Create and configure the SocketIO instance on the Flask app."""
    global socketio
    _cors_origins = os.getenv("CORS_ALLOWED_ORIGINS", "*")
    _cors_list = (
        [o.strip() for o in _cors_origins.split(",")]
        if _cors_origins != "*" else "*"
    )
    socketio = SocketIO(app, cors_allowed_origins=_cors_list, async_mode="gevent", **kwargs)

    @socketio.on("connect")
    def on_connect():
        # Verify JWT token passed via auth query parameter
        token = _flask_request.args.get("token", "")
        if not token:
            log.warning("[WS] Connection rejected: no token")
            disconnect()
            return False
        try:
            from flask_jwt_extended import decode_token
            decode_token(token)
        except Exception:
            log.warning("[WS] Connection rejected: invalid token")
            disconnect()
            return False
        log.info("[WS] Client connected (authenticated)")

    @socketio.on("disconnect")
    def on_disconnect():
        log.info("[WS] Client disconnected")

    @socketio.on("subscribe_theater")
    def on_subscribe_theater(data):
        """Client joins a theater room to receive targeted updates.
        data: {"theater": "TW"} or just the theater code string.
        """
        theater = data if isinstance(data, str) else data.get("theater", "")
        theater = theater.strip().upper()
        if theater:
            join_room(f"theater:{theater}")
            log.info(f"[WS] Client joined room theater:{theater}")
            emit("subscribed", {"theater": theater, "status": "ok"})

    @socketio.on("unsubscribe_theater")
    def on_unsubscribe_theater(data):
        theater = data if isinstance(data, str) else data.get("theater", "")
        theater = theater.strip().upper()
        if theater:
            leave_room(f"theater:{theater}")

    return socketio


# ── Emit helpers (called from scoring loop / sensors) ──────────────────────

def emit_threat_update(theater: str, strategic_data: dict) -> None:
    """Push updated threat data to all clients subscribed to the theater."""
    if socketio is None:
        return
    socketio.emit("threat_update", strategic_data, room=f"theater:{theater}")


def emit_ambush_alert(theater: str, alert_data: dict) -> None:
    """Push ambush pattern detection alert + external notification."""
    if socketio is None:
        return
    socketio.emit("ambush_alert", alert_data, room=f"theater:{theater}")
    # External notification
    from radar.notifications import notify_ambush_alert
    notify_ambush_alert(theater, alert_data)


def emit_sequence_event(theater: str, event_data: dict) -> None:
    """Push new sequence chain event notification."""
    if socketio is None:
        return
    socketio.emit("sequence_event", event_data, room=f"theater:{theater}")


def emit_sensor_status(sensor_name: str, status: str) -> None:
    """Broadcast sensor health change to all connected clients."""
    if socketio is None:
        return
    socketio.emit("sensor_status", {"sensor": sensor_name, "status": status})


def emit_notification_result(entry: dict) -> None:
    """Broadcast notification delivery result to all connected clients."""
    if socketio is None:
        return
    socketio.emit("notification_result", entry)


def emit_intel_update(theater: str, item_summary: dict) -> None:
    """Push LLM intel item notification so the UI refreshes without polling.
    item_summary should contain at minimum: {id, headline, source_type, status}.
    Broadcast to all clients (global intel panel covers all theaters).
    """
    if socketio is None:
        return
    socketio.emit("intel_update", item_summary)
