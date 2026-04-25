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
log = logging.getLogger("radar")

# ── Limit urllib3 connection retries ──
# Without this, SSL errors cause Max-Retries loops that block greenlets
# for extended periods, starving the gevent event loop and causing DB locks.
import urllib3.util.retry as _uretry  # noqa: E402
_uretry.Retry.DEFAULT = _uretry.Retry(total=1, backoff_factor=0)

# ── App ──
app = Flask(__name__)
_cors_origins = os.getenv("CORS_ALLOWED_ORIGINS", "")
if _cors_origins and _cors_origins != "*":
    _cors_list = [o.strip() for o in _cors_origins.split(",")]
else:
    # Default: allow same-origin only (no CORS header sent → browser blocks cross-origin)
    _cors_list = []
if _cors_list:
    CORS(app, resources={r"/api/*": {"origins": _cors_list}})

# ── Security headers ──
@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    if not app.debug:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

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

# ── Sensor Tier consistency check (scenario-refactor §6, §8.2) ──
# FOCUSED_ONLY_SENSOR_NAMES in radar/scenarios.py is the single source of truth.
# Each sensor class declares its own `tier`; this assertion catches drift between
# the canonical set and the class-level declarations.
from radar.scenarios import SensorTier, FOCUSED_ONLY_SENSOR_NAMES  # noqa: E402
_declared_focused = {
    _sname for _sname, _sensor in registry._sensors.items()
    if _sensor.tier == SensorTier.FOCUSED_ONLY
}
_missing = FOCUSED_ONLY_SENSOR_NAMES - _declared_focused
_extra = _declared_focused - FOCUSED_ONLY_SENSOR_NAMES
if _missing or _extra:
    _log_init = logging.getLogger("radar")
    if _missing:
        _log_init.warning(
            "[Startup] FOCUSED_ONLY sensors missing tier declaration: %s",
            sorted(_missing),
        )
    if _extra:
        _log_init.warning(
            "[Startup] Sensors declaring FOCUSED_ONLY not in canonical set: %s",
            sorted(_extra),
        )

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
from flask_jwt_extended.exceptions import (  # noqa: E402
    JWTExtendedException, NoAuthorizationError,
)
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
    except (NoAuthorizationError, PyJWTError, JWTExtendedException):
        # Includes RevokedTokenError, ExpiredSignatureError, etc.
        return _jsonify({"error": "Authentication required"}), 401
    except Exception:
        log.exception("[Auth] Unexpected error during JWT verification")
        return _jsonify({"error": "Internal server error"}), 500

# ── Routes ──
from radar import routes as _routes_mod  # noqa: E402
_routes_mod.init_routes(registry, engine)
app.register_blueprint(_routes_mod.bp)

# ── Persistence (restore + background save) ──
from radar.persistence import restore_state, save_state, _persistence_worker  # noqa: E402,F401
import atexit  # noqa: E402
import signal as _signal  # noqa: E402
atexit.register(save_state)

# Flush WAL to main DB file on shutdown (prevents data loss on Docker stop)
from radar.database import db as _shutdown_db  # noqa: E402
atexit.register(_shutdown_db.shutdown)

# Stop any push-source worker threads (e.g. CertstreamSource ws subscriber)
# before the interpreter tears down. Daemon threads exit on their own, but
# a clean ws close avoids a noisy server-side disconnect.
def _shutdown_sensors_with_workers():
    _log_sd = logging.getLogger("radar")
    for _sname, _sensor in registry._sensors.items():
        if hasattr(_sensor, "shutdown"):
            try:
                _sensor.shutdown()
            except Exception as e:
                _log_sd.warning(f"[Shutdown] sensor {_sname} shutdown failed: {e}")
atexit.register(_shutdown_sensors_with_workers)

# SIGTERM handler: docker stop sends SIGTERM, then SIGKILL after grace period.
# atexit is NOT guaranteed to run on SIGTERM, so we handle it explicitly.
def _sigterm_handler(signum, frame):
    _log_sig = logging.getLogger("radar")
    _log_sig.info("[Shutdown] SIGTERM received — flushing state and WAL")
    try:
        save_state()
    except Exception as e:
        _log_sig.warning(f"[Shutdown] save_state failed: {e}")
    try:
        _shutdown_db.shutdown()
    except Exception as e:
        _log_sig.warning(f"[Shutdown] DB shutdown failed: {e}")
    try:
        _shutdown_sensors_with_workers()
    except Exception as e:
        _log_sig.warning(f"[Shutdown] sensor workers shutdown failed: {e}")
    _log_sig.info("[Shutdown] Graceful shutdown complete")
    raise SystemExit(0)

_signal.signal(_signal.SIGTERM, _sigterm_handler)

# ── Synchronous startup (must complete before serving requests) ──
from radar.scheduler import _sensor_scheduler_worker, _cache_cleanup_worker, _corroboration_worker  # noqa: E402
from radar.scoring import prefill_hod_baseline_bg  # noqa: E402
from radar.database import db as _db  # noqa: E402

_log = logging.getLogger("radar")

# Phase 1: restore persisted state + DB cleanup (must finish before any request)
restore_state()
_db.startup_cleanup()

# Phase 1b: load scenario definitions (Layer 1 from geo_data.json + Layer 2 from SQLite)
from radar.scenarios import scenario_store as _scenario_store  # noqa: E402
_scenario_store.load(config._raw_geo)

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

# Phase 4: HOD prefill (background — not blocking request serving).
# HOD covers every country any scorable scenario participates in, and treats
# ADVERSARY-role participants as adversaries for baseline purposes (ADR-014).
from radar.scenarios import scenario_store as _scenario_store, Role as _Role
_hod_countries: set[str] = set()
_hod_adversaries: set[str] = set()
for _sc in _scenario_store.scorable():
    _hod_countries |= set(_sc.participants.keys())
    _hod_adversaries |= {_cc for _cc, _p in _sc.participants.items()
                         if _p.role == _Role.ADVERSARY}
threading.Thread(
    target=prefill_hod_baseline_bg,
    args=(sorted(_hod_countries), sorted(_hod_adversaries)),
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
