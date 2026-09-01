"""L8 — the entrypoint. The one place that makes the rest of v3 run.

Phases 2-4 built a composition root, a route table, a web binding, a
frontend and an auth surface, and left them unconnected on purpose: a
thing that starts itself is a thing that starts in every test process,
which is what `radar/__init__.py` does and what six boundary suites exist
to keep out of v3. This package is the explicit call that ends the
inertness, and nothing above it may make that call for it.

What it composes, in order, and why the order is that:

    settings    the deployment facts, read ONCE from the environment
                through `v3/runtime/secrets.py` (the only licensed reader)
    isolation   the guards that make v1 unreachable BEFORE anything opens
    registry    the 34 adapters, from `v3/adapters/catalog.py`
    secrets     `{key_id: material}` + the posture of every declared
                credential, so anonymous operation is a fact, not a silence
    store       the v3 ledger — a SEPARATE SQLite file, path injected,
                never defaulted, and refused if it names a v1 file
    resolver    v3's own 3-layer chain (`v3/runtime/config.py`)
    auth        the session surface, or None — v3 never generates a key
    runtime     the one thread (`v3/runtime/loop.py`), started explicitly
    blueprint   `v3/api/binding.py::create_blueprint`, with the read and
                write context factories the composition root owns
    frontend    `v3/ui/`, served file by file rather than by a catch-all

**Shadow discipline (R4).** The old system stays authoritative until
parity passes, so this package is built to be unable to reach it: a
separate port (never v1's 8000), a separate database file (refused if it
names `radar.db`, its WAL siblings, `convergence_snapshots.db`, or
anything under `radar/persistence/`), and an import barrier that turns any
`radar.*` import into a raised error rather than a silent boot of the live
application. `tests/test_v3_server.py` proves all three, including a
whole-boot fingerprint of a v1 database file.

**Import is still inert.** Importing this package costs one docstring; it
re-exports nothing, so `import v3.server` cannot become the place a future
side effect hides. Starting is `python -m v3.server`, or gunicorn calling
`v3.server.main:build_wsgi()`. Every other invocation is refused loudly —
`python -m v3.server.main` would boot the parent packages and then run the
module a second time under a different name, which is the shape that
nearly started a second app inside the live container.
"""
