"""radar.sensors.ct_log_sources -- pluggable CT log data sources.

The CtLogSensor orchestrator no longer fetches certs directly. Instead it
holds an ObservationBuffer that source workers write into, and on each
fetch() cycle it drains the buffer and applies the ADR-024 anomaly logic.

Sources fall in two kinds:

    pull (BaseCtLogPullSource) — answers `fetch_domain(domain)` synchronously.
        Used by the orchestrator's per-cycle backfill loop. Examples:
        CrtshSource, CertSpotterSource.

    push (BaseCtLogPushSource) — owns a long-lived background worker (ws,
        webhook receiver, ...). Calls buffer.record() asynchronously when
        a watched-domain match arrives. Examples: CertstreamSource.

Both kinds expose `health() -> dict` with a uniform shape so the
operator diagnostics panel can render them with the same template.
"""
from radar.sensors.ct_log_sources.base import (
    CertObservation,
    CtLogSource,
    BaseCtLogPullSource,
    BaseCtLogPushSource,
)
from radar.sensors.ct_log_sources.buffer import ObservationBuffer

__all__ = [
    "CertObservation",
    "CtLogSource",
    "BaseCtLogPullSource",
    "BaseCtLogPushSource",
    "ObservationBuffer",
    "CertstreamSource",
]


def __getattr__(name):
    # Lazy import: CertstreamSource pulls in websocket-client, which is an
    # optional runtime dep. Loading lazily lets test suites that don't touch
    # certstream skip the import entirely.
    if name == "CertstreamSource":
        from radar.sensors.ct_log_sources.certstream import CertstreamSource
        return CertstreamSource
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
