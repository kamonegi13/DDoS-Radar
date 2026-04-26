# radar_api.py -- Backward-compatibility shim.
# The application has been modularized into the radar/ package.
# This file re-exports key symbols so that existing imports continue to work.
#
# Usage:  python radar_api.py          (runs the dev server via gunicorn/eventlet)
#    or:  from radar_api import app    (WSGI entry point — prefer wsgi.py)
#
# gevent.monkey.patch_all() MUST precede all other imports when running directly.
from __future__ import annotations
from gevent import monkey as _monkey
_monkey.patch_all()  # noqa: E402 — must be before radar imports

# Import everything from the radar package (triggers full initialization)
from radar import app, registry, engine, config, socketio  # noqa: F401
from radar.models import RationaleEntry  # noqa: F401
from radar.engine import WeightedConvergenceEngine, SensorRegistry  # noqa: F401
from radar.scoring import (  # noqa: F401
    register_sequence_event, compute_sequence_bonus,
    compute_hod_zscore, record_hod_sample,
    calculate_overlap, calculate_overlap_idf, compute_idf_weights,
    compute_confidence,
    compute_adaptive_zscore,
    compute_origin_entropy, track_entropy_change,
    _entropy_history,
)
from radar.config import SEQUENCE_WINDOW  # noqa: F401
from radar.sensors.bgp_routing import BgpRoutingSensor, _linear_slope  # noqa: F401
from radar.sensors.ihr import IhrSensor  # noqa: F401
from radar.sensors.ripe_atlas import RipeAtlasSensor  # noqa: F401
from radar.sensors.tor_metrics import TorMetricsSensor  # noqa: F401
from radar.database import db as _db  # noqa: F401


# ── Test-compatibility wrappers ──
# These objects mimic dict-like .clear() / .get() / [] so that test_engine.py
# can continue to work without modification.
class _SeqLogProxy:
    """Proxy for sequence_event_log that delegates to SQLite."""
    def clear(self):
        _db.seq_clear()
    def get(self, theater, default=None):
        events = _db.seq_all_events(theater)
        return events if events else (default if default is not None else [])
    def __setitem__(self, theater, events):
        # Used by tests to inject expired events
        # Clear existing and insert new
        from radar.database import db
        conn = db._get_conn()
        conn.execute("DELETE FROM sequence_events WHERE theater=?", (theater,))
        for e in events:
            conn.execute(
                "INSERT INTO sequence_events (theater, ts, event_type, meta_json) "
                "VALUES (?, ?, ?, ?)",
                (theater, e["ts"], e["type"], __import__("json").dumps(e.get("meta", {}))),
            )
        conn.commit()

class _HodDbProxy:
    """Proxy for hod_baseline_db that delegates to SQLite."""
    def clear(self):
        conn = _db._get_conn()
        conn.execute("DELETE FROM hod_baseline")
        conn.commit()

sequence_event_log = _SeqLogProxy()
hod_baseline_db = _HodDbProxy()


if __name__ == "__main__":
    # Use socketio.run() with eventlet (monkey_patch already applied above)
    socketio.run(
        app,
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,
    )
