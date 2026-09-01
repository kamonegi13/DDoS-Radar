"""The thread. Exactly one, owned here, started only by an explicit call.

This is the entirety of v3's concurrency surface. Everything else under
`v3/` is a function you can call in a test with a dictionary, and the
boundary suites prove it by importing every module in a subprocess and
asserting `threading.active_count() == 1`.

What that discipline is buying is measurable. `radar/__init__.py` starts
the Flask app, runs migrations and spawns ~40 threads AT IMPORT, and three
separate defects follow from it: the legacy test suite talks to the
production database because importing the code connects it; WP-2.8's
parity driver has to run the old system in a subprocess because it cannot
be imported inertly; and `bg_observer` reached the network from its own
daemon thread, past the circuit breaker, while its docstring said
otherwise (B-01). B-01 is not possible here — not because the code is
careful, but because a private thread has nowhere to obtain work:
`run_due` is the only producer of fetches and `HttpClient` the only
egress.

**Stopping is part of the contract.** A loop that can only be killed is a
loop that can be killed mid-transaction. `stop()` sets an event the loop
checks between ticks, and `join()` waits for the tick in flight to finish
— so the ledger's unit of work is never the thing that gets interrupted.

**The wait is `Event.wait`, not `sleep`, and that is not a style choice.**
The first version slept in one-second slices so `stop()` would be honoured
promptly, with an injectable `sleeper` so tests could make the sleep
instant. Under the test suite it hung: the root conftest runs gevent's
`monkey.patch_all()` (it must, because it has to precede any `radar.*`
import), threads become greenlets, and a loop whose sleep returns
immediately never yields to the hub — so the stop flag is set by a
greenlet that never gets to run. `Event.wait(timeout)` yields under both
threading and gevent, honours `stop()` the instant it is set, and needs no
injected sleeper at all. Production runs under the same monkey-patch, so
this was a real hang and not a test artefact.

`clock` is the remaining injection seam: the tests run this loop for real
with a fake clock and finish in milliseconds, and a loop that could only
be tested by waiting is a loop nobody tests.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from v3.kernel.errors import DomainError

#: How long the loop waits between ticks by default. Not a threshold on
#: any measurement — a scheduling grain. Adapter cadences are declared per
#: adapter and read from `fetch_schedule`, so this only decides how often
#: the question "is anything due?" is asked.
DEFAULT_INTERVAL_SEC = 60.0
#: Longest a `stop()` can go unnoticed once a tick has finished: zero.
#: `Event.wait` returns the moment the flag is set, so the loop needs no
#: polling granularity of its own.
STOP_LATENCY_SEC = 0.0


@dataclass(frozen=True, slots=True)
class LoopStatus:
    """What the loop has actually managed to do. A measurement, not a flag.

    The shadow container reported HEALTHY for its whole run while every
    tick died at its first write. NP3 is why the loop survived that, and
    NP3 is right — but a contained failure nobody can see is worse than
    the failure, so this type has to carry enough for a health surface to
    tell "producing" from "alive and producing nothing".

    Four fields answer that and each one is needed:

      last_tick_at       when a tick last SUCCEEDED. `run_once` advances
                         it only after the tick returns, so it is already
                         the right clock; what was missing was anything
                         to compare it against.
      consecutive_errors the live fact. `errors` is a total, and a total
                         cannot tell one bad tick an hour ago from every
                         tick since boot — opposite operational states.
      last_error_at      when the last failure was, so a stale message is
                         not read as a current one.
      started_at         when the thread began, so "no tick has finished"
                         can be aged. Without it, a container 20 seconds
                         into its first 60-second tick and a container
                         that has failed 500 times look the same.
    """

    running: bool
    ticks: int
    errors: int
    #: The last SUCCESSFUL tick. A tick that raised never reaches here.
    last_tick_at: Optional[float]
    last_error: str = ""
    last_error_at: Optional[float] = None
    consecutive_errors: int = 0
    started_at: Optional[float] = None

    def as_dict(self) -> dict:
        return {"running": self.running, "ticks": self.ticks,
                "errors": self.errors, "last_tick_at": self.last_tick_at,
                "last_error": self.last_error,
                "last_error_at": self.last_error_at,
                "consecutive_errors": self.consecutive_errors,
                "started_at": self.started_at}


class Runtime:
    """Owns the thread, the clock and the stop. Nothing else does.

    `tick` is a callable of one argument (the instant). Injecting it keeps
    this class about lifecycle only: what a tick DOES is `v3.runtime.tick`'s
    business, and a lifecycle that also knew the pipeline would be a
    lifecycle nobody could test without a database.
    """

    def __init__(self, tick: Callable[[float], object], *,
                 interval_sec: float = DEFAULT_INTERVAL_SEC,
                 clock: Callable[[], float] = time.time,
                 on_error: Optional[Callable[[BaseException], None]] = None):
        if not callable(tick):
            raise DomainError("Runtime needs a callable tick")
        if interval_sec <= 0:
            raise DomainError(
                f"interval_sec must be positive, got {interval_sec}: a "
                f"non-positive interval is a busy loop holding the ledger's "
                f"write lock")
        self._tick = tick
        self._interval_sec = float(interval_sec)
        self._clock = clock
        self._on_error = on_error
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._ticks = 0
        self._errors = 0
        self._last_tick_at: Optional[float] = None
        self._last_error = ""
        self._last_error_at: Optional[float] = None
        self._consecutive_errors = 0
        self._started_at: Optional[float] = None

    # ── lifecycle ───────────────────────────────────────────────────────
    @property
    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive())

    def start(self) -> "Runtime":
        """Start the one thread. Explicit, and refused if already running.

        Refused rather than ignored: two loops on one ledger is two
        writers racing for the same `tick_id`, and the ledger's answer to
        that is either a DomainError or — for identical content — a row
        silently discarded (`store.py:290`).
        """
        with self._lock:
            if self.is_running:
                raise DomainError(
                    "this runtime is already running; a second loop over the "
                    "same ledger races for the same tick_id")
            self._stop.clear()
            # Stamped BEFORE the thread exists, so a health probe that
            # arrives between the two never sees a loop that is running
            # and claims never to have been started.
            self._started_at = float(self._clock())
            self._thread = threading.Thread(
                target=self._run, name="noroshi-v3-runtime", daemon=True)
            self._thread.start()
        return self

    def stop(self, *, timeout_sec: Optional[float] = None) -> "Runtime":
        """Ask the loop to finish the tick in flight and then exit."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=timeout_sec)
        return self

    def __enter__(self) -> "Runtime":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def status(self) -> LoopStatus:
        return LoopStatus(running=self.is_running, ticks=self._ticks,
                          errors=self._errors,
                          last_tick_at=self._last_tick_at,
                          last_error=self._last_error,
                          last_error_at=self._last_error_at,
                          consecutive_errors=self._consecutive_errors,
                          started_at=self._started_at)

    # ── the loop ────────────────────────────────────────────────────────
    def run_once(self) -> object:
        """One tick, in the CALLING thread. The whole loop, minus the loop.

        Every test of the pipeline uses this, and so does any operator who
        wants a single sweep. A runtime whose only entry point spawns a
        thread is a runtime whose failures are only ever visible in a log.
        """
        now = float(self._clock())
        try:
            report = self._tick(now)
        except BaseException as failure:      # noqa: BLE001
            self._errors += 1
            self._consecutive_errors += 1
            self._last_error = f"{type(failure).__name__}: {failure}"
            self._last_error_at = now
            raise
        self._ticks += 1
        self._last_tick_at = now
        # The streak ends; the total does not. One is "is it broken NOW",
        # the other is "has it been", and a health surface needs both.
        self._consecutive_errors = 0
        return report

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except BaseException as failure:  # noqa: BLE001
                # A loop that dies on the first bad tick is a monitoring
                # tool that stops monitoring the moment something goes
                # wrong — the failure mode NP3 exists to forbid. The error
                # is counted and surfaced through `status()`; it is never
                # swallowed into nothing.
                if self._on_error is not None:
                    self._on_error(failure)
            self._wait()

    def _wait(self) -> None:
        """Wait out the interval, or return the instant `stop()` is set.

        `Event.wait` rather than `sleep`: it yields under gevent (which
        the deployment monkey-patches in) AND it needs no polling
        granularity, so a stop is never delayed by a partially-elapsed
        slice.
        """
        self._stop.wait(self._interval_sec)


__all__ = ["Runtime", "LoopStatus", "DEFAULT_INTERVAL_SEC",
           "STOP_LATENCY_SEC"]
