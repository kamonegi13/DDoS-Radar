"""L6 — the composition root. The one place with threads, clocks and keys.

Every other package under `v3/` was built inert on purpose: importing it
starts no thread, opens no socket, reads no environment variable and
touches no database. That discipline is enforced by
`scripts/check_kernel_discipline.py` and by six boundary suites, and it is
the deliberate inverse of `radar/__init__.py`, whose import-time boot made
B-01 possible (a daemon thread reaching the network past the circuit
breaker), pointed the legacy test suite at the production database, and
forced WP-2.8's parity driver into subprocess isolation.

Inertness has to end somewhere, and this is where. What lands here is
everything the pure layers deliberately could not express:

    secrets     the ONLY module under v3/ that may read os.environ
    geo         deployment geography, loaded from geo_data.json
    scenarios   participant model -> ExpansionInput / NormalizeContext
    reduce      N per-payload drafts -> the ONE row per (country, source)
    health      fetch outcomes + Evidence freshness -> InputHealth
    baselines   L1 statistics -> the adapters' withheld verdicts
    suppression cross-adapter joins normalize() cannot reach
    tick        fetch -> observations -> score -> conclusions, once
    loop        the thread, the stop, the schedule read from L1

Importing THIS package is still inert. Owning a thread and starting one
are different acts: `start()` is an explicit call, and nothing else in
the tree can make it.

Deliberately NOT re-exported at package import: nothing here pulls its
submodules in, so `import v3.runtime` costs one docstring. The submodules
are imported by name (`from v3.runtime.tick import run_tick`), which keeps
the import graph readable and keeps this file from becoming the place a
future side effect hides.
"""
