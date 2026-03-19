"""radar -- MDO C4ISR Dashboard package.

This package is the modularized form of the original radar_api.py monolith.
Import the Flask app via: from radar import app
"""
from __future__ import annotations
import logging
import threading
from flask import Flask
from flask_cors import CORS

# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── App ──
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ── Config (triggers _load_env) ──
from radar import config  # noqa: E402

# ── Models ──
from radar.models import RationaleEntry  # noqa: E402,F401

# ── State (must be imported before sensors — some sensors reference state globals) ──
from radar import state  # noqa: E402,F401

# ── Engine ──
from radar.engine import SensorRegistry, WeightedConvergenceEngine  # noqa: E402

registry = SensorRegistry()
engine = WeightedConvergenceEngine()

# ── Sensors ──
from radar.sensors import (  # noqa: E402
    CloudflareSensor, IodaSensor, OpenSkySensor, OpenWeatherSensor,
    GDELTSensor, PeeringDbSensor, BgpRoutingSensor, NasaFirmsSensor, ThreatFoxSensor,
    RssNarrativeSensor, IsrHotspotSensor, AisMaritimeSensor,
    TelegramMirrorSensor, CheckHostSensor, GreyNoiseSensor,
)
for _s in [
    CloudflareSensor(), IodaSensor(), OpenSkySensor(), OpenWeatherSensor(),
    GDELTSensor(), PeeringDbSensor(), BgpRoutingSensor(), NasaFirmsSensor(), ThreatFoxSensor(),
    RssNarrativeSensor(), IsrHotspotSensor(), AisMaritimeSensor(),
    TelegramMirrorSensor(), CheckHostSensor(), GreyNoiseSensor(),
]:
    registry.register(_s)

# ── Plugin Sensors (dynamic loading from plugins/ directory) ──
from radar.plugin_loader import load_and_register_plugins  # noqa: E402
load_and_register_plugins(registry)

# ── Scoring (must come after state) ──
from radar.scoring import (  # noqa: E402,F401
    register_sequence_event, compute_sequence_bonus,
    compute_hod_zscore, record_hod_sample,
    calculate_overlap, compute_confidence,
)

# ── Auth (JWT + user management) ──
from radar.auth import init_auth, bp as _auth_bp  # noqa: E402
init_auth(app)
app.register_blueprint(_auth_bp)

# ── Global JWT enforcement on /api/* routes ──
from flask import request as _req, jsonify as _jsonify  # noqa: E402
from flask_jwt_extended import verify_jwt_in_request  # noqa: E402
from flask_jwt_extended.exceptions import NoAuthorizationError  # noqa: E402
from jwt.exceptions import PyJWTError  # noqa: E402

# Public routes that do NOT require authentication
_AUTH_PUBLIC_ENDPOINTS = frozenset({
    "auth.login",       # login endpoint
    "auth.refresh",     # token refresh (has its own @jwt_required(refresh=True))
    "api.index",        # serve index.html
    "api.static_files", # serve static assets
    "api.app_config",   # initial config needed before login
    "static",           # Flask default static
})

@app.before_request
def _enforce_jwt():
    """Require valid JWT for all /api/ routes except public whitelist."""
    endpoint = _req.endpoint
    if endpoint in _AUTH_PUBLIC_ENDPOINTS or endpoint is None:
        return None
    # Only enforce on /api/ paths
    if not _req.path.startswith("/api/"):
        return None
    try:
        verify_jwt_in_request()
    except (NoAuthorizationError, PyJWTError, Exception):
        return _jsonify({"error": "Authentication required"}), 401

# ── Routes ──
from radar import routes as _routes_mod  # noqa: E402
_routes_mod.init_routes(registry, engine)
app.register_blueprint(_routes_mod.bp)

# ── Persistence (restore + background save) ──
from radar.persistence import restore_state, save_state, _persistence_worker  # noqa: E402,F401
import atexit  # noqa: E402
atexit.register(save_state)
threading.Thread(target=_persistence_worker, daemon=True, name='persistence').start()
restore_state()

# ── Startup DB cleanup ──
from radar.database import db as _db  # noqa: E402
_db.startup_cleanup()

# ── Scheduler (background sensor fetch) ──
from radar.scheduler import _sensor_scheduler_worker, _cache_cleanup_worker  # noqa: E402
for _s in registry._sensors.values():
    threading.Thread(target=_sensor_scheduler_worker, args=(_s, registry),
                     daemon=True, name=f'sensor-{_s.name}').start()

# ── HOD Prefill ──
from radar.scoring import prefill_hod_baseline_bg  # noqa: E402
_hod_theaters = sorted(set([config.DEFAULT_CORE] + config.DEFAULT_PINS + config.DEFAULT_CORRELATES))
threading.Thread(
    target=prefill_hod_baseline_bg,
    args=(_hod_theaters, config.DEFAULT_ADVERSARIES),
    daemon=True, name='hod-prefill'
).start()

# ── Cache Cleanup ──
threading.Thread(target=_cache_cleanup_worker, args=(registry,),
                 daemon=True, name='cache-cleanup').start()

# ── WebSocket (Flask-SocketIO) ──
from radar.ws import init_socketio, socketio as _ws_ref  # noqa: E402,F401
socketio = init_socketio(app)
