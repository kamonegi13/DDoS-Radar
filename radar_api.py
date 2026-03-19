# radar_api.py -- Backward-compatibility shim.
# The application has been modularized into the radar/ package.
# This file re-exports key symbols so that existing imports continue to work.
#
# Usage:  python radar_api.py          (runs the dev server)
#    or:  from radar_api import app    (WSGI entry point)
from __future__ import annotations

# Import everything from the radar package (triggers full initialization)
from radar import app, registry, engine, config, socketio  # noqa: F401
from radar.models import RationaleEntry  # noqa: F401
from radar.engine import WeightedConvergenceEngine, SensorRegistry  # noqa: F401
from radar.scoring import (  # noqa: F401
    register_sequence_event, compute_sequence_bonus,
    compute_hod_zscore, record_hod_sample,
    calculate_overlap, compute_confidence,
)
from radar.config import SEQUENCE_WINDOW  # noqa: F401

# Re-export mutable state globals for test_engine.py compatibility.
# These are the SAME dict/deque objects used by the radar package internals,
# so .clear() and mutation from tests will propagate correctly.
from radar.state import (  # noqa: F401
    sequence_event_log, hod_baseline_db,
)

if __name__ == "__main__":
    # Use socketio.run() instead of app.run() for WebSocket support
    socketio.run(
        app,
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        debug=config.FLASK_DEBUG,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
