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

# ── Default timeout for all outbound HTTP requests ──
# Prevents hung connections from blocking the gevent event loop.
# Individual sensors can still override with explicit timeout= kwargs.
import requests as _requests  # noqa: E402
_requests.adapters.DEFAULT_RETRIES = 1
_DEFAULT_HTTP_TIMEOUT = (10, 20)  # (connect, read) seconds

_orig_get = _requests.Session.get
_orig_post = _requests.Session.post

def _timeout_get(self, url, **kwargs):
    kwargs.setdefault("timeout", _DEFAULT_HTTP_TIMEOUT)
    return _orig_get(self, url, **kwargs)

def _timeout_post(self, url, **kwargs):
    kwargs.setdefault("timeout", _DEFAULT_HTTP_TIMEOUT)
    return _orig_post(self, url, **kwargs)

_requests.Session.get = _timeout_get
_requests.Session.post = _timeout_post

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
    SpaceWeatherSensor, IhrSensor, RipeAtlasSensor, TorMetricsSensor,
    NotamSensor, TravelAdvisorySensor, OoniSensor, UsgsSeismicSensor,
    MilSupportAirSensor, GpsJammingSensor, CtLogSensor,
    HacktiivistIntelSensor, GroundOsintSensor, DiplomaticSensor, MilitaryExerciseSensor,
    AptIntelSensor, ConvergenceTrackerSensor,
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
    AptIntelSensor(), ConvergenceTrackerSensor(),
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

# ── Deferred startup ──
# Heavy initialization (DB cleanup, state restore, sensor fetch, HOD prefill)
# runs in a single background thread so the app can serve requests immediately.
from radar.scheduler import _sensor_scheduler_worker, _cache_cleanup_worker, _corroboration_worker  # noqa: E402
from radar.scoring import prefill_hod_baseline_bg  # noqa: E402
from radar.database import db as _db  # noqa: E402

_startup_ready = threading.Event()

def _deferred_startup():
    """Run all heavy startup tasks in background, then signal readiness."""
    log = logging.getLogger("radar")
    try:
        # Phase 1: restore persisted state + DB cleanup (fast, local I/O only)
        restore_state()
        _db.startup_cleanup()

        # Phase 2: start persistence saver
        threading.Thread(target=_persistence_worker, daemon=True, name='persistence').start()

        # Phase 3: launch sensor scheduler threads with staggered start
        # Spread sensor starts over ~60s to avoid DB write contention, API burst,
        # and gevent event loop starvation (each initial fetch blocks its greenlet).
        # OpenSky-dependent sensors get additional stagger for 429 avoidance.
        _OPENSKY_STAGGER = {"opensky": 0, "isr_hotspot": 120, "mil_support_air": 240}
        import time as _time
        for _i, _s in enumerate(registry._sensors.values()):
            _delay = _OPENSKY_STAGGER.get(_s.name, 2.0 + _i * 1.5)  # 1.5s apart, 2s base
            threading.Thread(target=_sensor_scheduler_worker, args=(_s, registry, _delay),
                             daemon=True, name=f'sensor-{_s.name}').start()

        # Phase 4: HOD prefill (wait for initial sensor batch to settle)
        _hod_theaters = sorted(set([config.DEFAULT_CORE] + config.DEFAULT_PINS + config.DEFAULT_CORRELATES))
        threading.Thread(
            target=prefill_hod_baseline_bg,
            args=(_hod_theaters, config.DEFAULT_ADVERSARIES),
            daemon=True, name='hod-prefill'
        ).start()

        # Phase 5: cache cleanup + corroboration
        threading.Thread(target=_cache_cleanup_worker, args=(registry,),
                         daemon=True, name='cache-cleanup').start()
        threading.Thread(target=_corroboration_worker,
                         daemon=True, name='corroboration').start()

        log.info("[Startup] Deferred initialization complete — all background workers launched")
    except Exception as e:
        log.error(f"[Startup] Deferred initialization error: {e}")
    finally:
        _startup_ready.set()

threading.Thread(target=_deferred_startup, daemon=True, name='deferred-startup').start()

# ── WebSocket (Flask-SocketIO) ──
from radar.ws import init_socketio, socketio as _ws_ref  # noqa: E402,F401
socketio = init_socketio(app)
