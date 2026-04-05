"""radar -- MDO C4ISR Dashboard package.

This package is the modularized form of the original radar_api.py monolith.
Import the Flask app via: from radar import app
"""
from __future__ import annotations
import logging
import os
import threading
from flask import Flask
from flask_cors import CORS

# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── Limit urllib3 connection retries ──
# Without this, SSL errors cause Max-Retries loops that block greenlets
# for extended periods, starving the gevent event loop and causing DB locks.
import urllib3.util.retry as _uretry  # noqa: E402
_uretry.Retry.DEFAULT = _uretry.Retry(total=1, backoff_factor=0)

# ── App ──
app = Flask(__name__)
_cors_origins = os.getenv("CORS_ALLOWED_ORIGINS", "*")
_cors_list = [o.strip() for o in _cors_origins.split(",")] if _cors_origins != "*" else "*"
CORS(app, resources={r"/api/*": {"origins": _cors_list}})

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
    SpaceWeatherSensor, IhrSensor, RipeAtlasSensor, TorMetricsSensor,
    NotamSensor, TravelAdvisorySensor, OoniSensor, UsgsSeismicSensor,
    MilSupportAirSensor, GpsJammingSensor, CtLogSensor,
    HacktiivistIntelSensor, GroundOsintSensor, DiplomaticSensor, MilitaryExerciseSensor,
    AptIntelSensor, ConvergenceTrackerSensor, HacktivistNewsSensor,
)
for _s in [
    CloudflareSensor(), IodaSensor(), OpenSkySensor(), OpenWeatherSensor(),
    GDELTSensor(), PeeringDbSensor(), BgpRoutingSensor(), NasaFirmsSensor(), ThreatFoxSensor(),
    RssNarrativeSensor(), IsrHotspotSensor(), AisMaritimeSensor(),
    TelegramMirrorSensor(), CheckHostSensor(), GreyNoiseSensor(),
    SpaceWeatherSensor(), IhrSensor(), RipeAtlasSensor(), TorMetricsSensor(),
    NotamSensor(), TravelAdvisorySensor(), OoniSensor(), UsgsSeismicSensor(),
    MilSupportAirSensor(), GpsJammingSensor(), CtLogSensor(),
    HacktiivistIntelSensor(), GroundOsintSensor(), DiplomaticSensor(), MilitaryExerciseSensor(),
    AptIntelSensor(), ConvergenceTrackerSensor(), HacktivistNewsSensor(),
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

# ── Synchronous startup (must complete before serving requests) ──
from radar.scheduler import _sensor_scheduler_worker, _cache_cleanup_worker, _corroboration_worker  # noqa: E402
from radar.scoring import prefill_hod_baseline_bg  # noqa: E402
from radar.database import db as _db  # noqa: E402

_log = logging.getLogger("radar")

# Phase 1: restore persisted state + DB cleanup (must finish before any request)
restore_state()
_db.startup_cleanup()

# Phase 2: start persistence saver
threading.Thread(target=_persistence_worker, daemon=True, name='persistence').start()

# Phase 3: launch sensor scheduler threads with staggered start
# Spread sensor starts over ~60s to avoid DB write contention, API burst,
# and gevent event loop starvation (each initial fetch blocks its greenlet).
# OpenSky-dependent sensors get additional stagger for 429 avoidance.
_OPENSKY_STAGGER = {"opensky": 0, "isr_hotspot": 120, "mil_support_air": 240}
for _i, _s in enumerate(registry._sensors.values()):
    _delay = _OPENSKY_STAGGER.get(_s.name, 2.0 + _i * 1.5)  # 1.5s apart, 2s base
    threading.Thread(target=_sensor_scheduler_worker, args=(_s, registry, _delay),
                     daemon=True, name=f'sensor-{_s.name}').start()

# Phase 4: HOD prefill (background — not blocking request serving)
_hod_theaters = sorted(set([config.DEFAULT_CORE] + config.DEFAULT_PINS + config.DEFAULT_CORRELATES))
threading.Thread(
    target=prefill_hod_baseline_bg,
    args=(_hod_theaters, config.DEFAULT_ADVERSARIES),
    daemon=True, name='hod-prefill'
).start()

# Phase 5: cache cleanup + corroboration (background daemons)
threading.Thread(target=_cache_cleanup_worker, args=(registry,),
                 daemon=True, name='cache-cleanup').start()
threading.Thread(target=_corroboration_worker,
                 daemon=True, name='corroboration').start()

_log.info("[Startup] Initialization complete — all background workers launched")

# ── WebSocket (Flask-SocketIO) ──
from radar.ws import init_socketio, socketio as _ws_ref  # noqa: E402,F401
socketio = init_socketio(app)
