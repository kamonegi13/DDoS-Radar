"""The entrypoint. Three supported invocations, and every other one refused.

    python -m v3.server              compose, start the loop, serve
    python -m v3.server --once       compose, run ONE tick, print it, exit
    python -m v3.server --check      compose, print the disclosure, exit
    gunicorn 'v3.server.main:build_wsgi()'      the container's form

**Why the refusal at the top of the file is where it is.** `python -m
v3.server.main` imports `v3` and `v3.server` first and then executes this
file a SECOND time under the name `__main__`, so the module's functions
exist twice and its module-level state is not shared with itself. That is
the shape that nearly started a second application inside the live
container when the ops_health check was invoked that way. `python
v3/server/main.py` is worse: `sys.path[0]` becomes `v3/server/`, so
`import v3` fails with a message about a package that is plainly present.
Both are caught before a single import runs, and both print the
invocation that works.

**Why gunicorn gets a factory rather than a module-level `app`.** A
module-level app is import-active, and import inertness is the invariant
the whole tree is built on — six boundary suites assert it, and it is what
keeps `radar/__init__.py`'s failure mode (~40 threads and a production
database connection at import) out of v3. Gunicorn's `module:callable()`
syntax calls the factory explicitly, which is the same act as `start()`.

**One worker, always.** The ledger serialises writers in-process; two
processes on one SQLite file is out of scope by design. The container's
command pins `-w 1`, and the runtime refuses a second loop in the same
process, so the remaining way to get two writers is to start the
container twice — which the runbook says not to do and which a second
bind on the same port prevents anyway.
"""
from __future__ import annotations

_REFUSAL = (
    "v3/server/main.py must not be run directly.\n"
    "  python -m v3.server.main  runs this file a second time under the "
    "name __main__, so the module exists twice with unshared state.\n"
    "  python v3/server/main.py  puts v3/server/ on sys.path instead of "
    "the repository root, so `import v3` fails.\n"
    "Use one of:\n"
    "  python -m v3.server            # compose, start the loop, serve\n"
    "  python -m v3.server --once     # one tick, printed, then exit\n"
    "  python -m v3.server --check    # composition disclosure, then exit\n"
    "  gunicorn 'v3.server.main:build_wsgi()'   # the container's form")

if __name__ == "__main__":       # pragma: no cover - invocation guard
    # Deliberately BEFORE the imports: the point is to fail without
    # composing anything, and `python v3/server/main.py` would otherwise
    # die on `import v3` with a message that blames the wrong thing.
    raise SystemExit(_REFUSAL)

import argparse                                              # noqa: E402
import json                                                  # noqa: E402
import logging                                               # noqa: E402
import signal                                                # noqa: E402
import sys                                                   # noqa: E402
from typing import Mapping, Optional                         # noqa: E402

from v3.kernel.errors import DomainError                     # noqa: E402
from v3.server import composition                            # noqa: E402
from v3.server import settings as SETTINGS                   # noqa: E402
from v3.server.app import create_app, mounted_paths          # noqa: E402

#: What the container's CMD names. Written here so the runbook, the
#: Dockerfile and the test that checks the shape all read one string.
GUNICORN_APP = "v3.server.main:build_wsgi()"

log = logging.getLogger("v3.server")


def build(settings=None, *, environment: Optional[Mapping[str, str]] = None,
          **seams) -> composition.Deployment:
    """Compose, without starting anything. The whole entrypoint's core."""
    return composition.compose(settings, environment=environment, **seams)


def build_wsgi():
    """The gunicorn factory: compose, START the loop, return the app.

    Starting the loop here rather than in a separate process is the point
    of a shadow deployment: the tick and the surface that shows what the
    tick produced must be looking at the same ledger handle, and a second
    process writing the same SQLite file is the thing `LedgerStore` says
    is out of scope.

    `atexit` is registered so a normal worker shutdown stops the loop
    between ticks instead of at an arbitrary point inside one.
    """
    import atexit

    deployment = build()
    application = create_app(deployment)
    deployment.runtime.start()
    if deployment.s9_runtime is not None:
        deployment.s9_runtime.start()
    atexit.register(deployment.close)
    _announce(deployment, application)
    return application


def _announce(deployment, application=None) -> None:
    """Everything degraded, said once, at start. Never a silence."""
    for line in deployment.announcements():
        log.warning("%s", line)
    log.info("v3 shadow: ledger=%s scenarios=%s interval=%.0fs",
             deployment.settings.ledger_name,
             ",".join(deployment.scenario_ids),
             deployment.settings.interval_sec)
    if application is not None:
        log.info("v3 shadow: %d routes mounted",
                 len(mounted_paths(application)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m v3.server",
        description="Noroshi v3 shadow deployment (R4: v1 stays "
                    "authoritative until parity passes)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true",
                       help="compose and print the disclosure; bind no "
                            "port, start no loop, run no tick")
    group.add_argument("--once", action="store_true",
                       help="compose and run exactly ONE tick in this "
                            "thread, print the report, then exit")
    parser.add_argument("--keys", action="store_true",
                        help="print the environment variables this "
                             "deployment honours, and exit")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")

    if args.keys:
        print(json.dumps(list(SETTINGS.describe()), ensure_ascii=False,
                         indent=2))
        return 0

    try:
        deployment = build()
    except DomainError as failure:
        print(str(failure), file=sys.stderr)
        return 2

    try:
        if args.check:
            print(json.dumps(deployment.disclosure(), ensure_ascii=False,
                             indent=2, default=str))
            return 0
        if args.once:
            report = deployment.tick()
            print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2,
                             default=str))
            return 0
        return _serve(deployment)
    finally:
        deployment.close()


def _serve(deployment) -> int:
    """Bind, start the loop, and wait. The operator-facing server.

    Flask's built-in server, and the runbook says so: the container runs
    gunicorn through `build_wsgi`, and this path exists for an operator
    running the shadow on a workstation. Making the difference visible
    beats a development server that quietly calls itself production.
    """
    application = create_app(deployment)
    deployment.runtime.start()
    if deployment.s9_runtime is not None:
        deployment.s9_runtime.start()
    _announce(deployment, application)

    def _stop(signum, frame):        # pragma: no cover - signal path
        log.info("signal %s: stopping the loop between ticks", signum)
        deployment.close()
        raise SystemExit(0)

    for name in ("SIGTERM", "SIGINT"):
        handler = getattr(signal, name, None)
        if handler is not None:
            signal.signal(handler, _stop)

    application.run(host=deployment.settings.host,
                    port=deployment.settings.port, debug=False,
                    use_reloader=False, threaded=True)
    return 0


__all__ = ["build", "build_wsgi", "main", "GUNICORN_APP"]
