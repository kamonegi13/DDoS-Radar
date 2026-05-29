"""Background Observer sensor — first ``BACKGROUND_ELIGIBLE`` reference (ADR-V2-015).

Wraps :class:`radar.background_observer.BackgroundObserver` in the
``BaseSensor`` framework so the C-medium tier promotion path (ADR-002 /
ADR-017) has its first concrete implementation. This satisfies AP3
(self-evaluation) by exposing the observer to ``scenario_sensor_coverage``,
``sensor_fetch_log``, and the standard health / circuit-breaker
machinery — without breaking the broadcast scan logic that lives in
:mod:`radar.background_observer`.

Why a separate worker, not the standard sensor scheduler? The standard
scheduler in ``radar/scheduler.py`` is built around country-targeted
fetches driven by the focused scenario's ``ctx['all_targets']``. The
broadcast observer is structurally different — it scans across **all**
scorable scenarios' participants every cycle. Routing it through the
focused-only scheduler would either run it with an empty target set
(broken contract) or misrepresent the broadcast nature. Instead, the
sensor owns its own worker thread and reports cycle results back through
``set_cache`` / ``log_fetch`` so the registry sees every cycle.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from radar import config
from radar.scenarios import SensorTier
from radar.sensors.base import BaseSensor

log = logging.getLogger("bg_observer.sensor")


class BackgroundObserverSensor(BaseSensor):
    """First-class sensor wrapping the broadcast observer (ADR-V2-015 Phase 4).

    Owns its own ticker thread; the standard sensor scheduler is bypassed
    so the broadcast scan can run on its own cadence
    (``BG_OBSERVER_INTERVAL_SEC``). Health / circuit-breaker integration
    still flows through ``BaseSensor`` so the registry, fetch_log,
    and AP3 surfaces all see the observer.
    """

    tier: SensorTier = SensorTier.BACKGROUND_ELIGIBLE
    # bg_observer reads RSS feeds — DNS / 5xx flakes happen often.
    # Keep the default circuit-breaker thresholds; the observer keeps
    # itself running even when the breaker is open (signals stop
    # flowing, but the worker thread is not killed).

    def __init__(self) -> None:
        super().__init__(
            name="bg_observer_rss",
            domain="info",
            poll_interval=config.BG_OBSERVER_INTERVAL_SEC,
        )
        self._worker_thread: Optional[threading.Thread] = None
        self._observer = None  # Lazy: created on first fetch
        # Disable the sensor when the env flag is off so the standard
        # scheduler reports it as DISABLED in the UI.
        self.enabled = bool(config.BG_OBSERVER_ENABLED)

    # ── BaseSensor interface ──────────────────────────────────────────────

    def fetch(self, context: dict) -> dict:  # noqa: ARG002 — broadcast scan
        """Single-cycle entry point. Returns the cycle status dict.

        ``context`` is unused — the broadcast scan resolves participants
        from ``scenario_store`` directly. The method is provided so
        operators can manually trigger a cycle via the registry (e.g. for
        diagnostic flushes); the daemon thread invokes the same path on
        its own cadence.
        """
        observer = self._get_or_create_observer()
        started = time.time()
        try:
            result = observer.tick()
        except Exception as exc:  # noqa: BLE001
            duration_ms = int((time.time() - started) * 1000)
            self.log_fetch(success=False, duration_ms=duration_ms,
                           records=0, error=str(exc)[:300])
            return {"enabled": True, "error": str(exc)}
        duration_ms = int((time.time() - started) * 1000)
        if not result.get("enabled"):
            # Disabled cycle is still a "successful no-op" — don't
            # pollute the failure counter.
            self.log_fetch(success=True, duration_ms=duration_ms, records=0)
            self.set_cache(result)
            return result
        self.log_fetch(
            success=True,
            duration_ms=duration_ms,
            records=int(result.get("matches", 0)),
            # Surface failed feeds in the fetch_log error column so the
            # AP3 chip / sensor health UI can flag chronic feed outages.
            error=(
                f"feeds_failed={result.get('feeds_failed', 0)}"
                if result.get("feeds_failed")
                else ""
            ),
        )
        self.set_cache(result)
        return result

    # ── lifecycle ────────────────────────────────────────────────────────

    def _get_or_create_observer(self):
        """Lazily build the BackgroundObserver instance.

        Deferred so the import chain at module load time does not
        require scenario_store to be ready.
        """
        if self._observer is None:
            from radar.background_observer import BackgroundObserver
            from radar.scenarios import scenario_store
            from radar.config import DEFAULT_FOCUSED_SCENARIO

            def _scorable():
                return scenario_store.scorable() if scenario_store.loaded else []

            def _focused_id():
                return DEFAULT_FOCUSED_SCENARIO

            self._observer = BackgroundObserver(
                scorable_scenarios_fn=_scorable,
                focused_id_fn=_focused_id,
            )
        return self._observer

    def start(self) -> Optional[threading.Thread]:
        """Spawn the daemon ticker (idempotent).

        Returns the thread (or ``None`` if BG_OBSERVER_ENABLED=false).
        Owned by the sensor instance so the registry can introspect /
        restart it later.
        """
        if not config.BG_OBSERVER_ENABLED:
            log.info("[bg_observer.sensor] disabled (BG_OBSERVER_ENABLED=false)")
            return None
        if self._worker_thread is not None and self._worker_thread.is_alive():
            return self._worker_thread

        def _loop():
            while True:
                try:
                    self.fetch({})
                except Exception:  # noqa: BLE001
                    log.exception("[bg_observer.sensor] cycle error (continuing)")
                time.sleep(config.BG_OBSERVER_INTERVAL_SEC)

        t = threading.Thread(target=_loop, daemon=True,
                             name="bg_observer_sensor")
        t.start()
        self._worker_thread = t
        log.info(
            "[bg_observer.sensor] started — interval=%ds, feeds=%d",
            config.BG_OBSERVER_INTERVAL_SEC,
            len(config.BG_OBSERVER_FEEDS),
        )
        return t
