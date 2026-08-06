"""Noroshi v3 — the staged rebuild.

Deliberately a top-level package, NOT a subpackage of `radar`.

`radar/__init__.py` starts the application at import time: importing any
`radar.*` module boots the Flask app, runs database migrations and spawns
~30 sensor threads with live outbound HTTP (measured: 40 threads from
`import radar.config_layered` alone). Placing v3 code under `radar/` would
mean every v3 module import carried that, which is precisely the class of
defect this rebuild exists to remove — and it would make the kernel
untestable in isolation.

This package therefore has no import-time side effects at all, and every
module under it is expected to keep that property. The one permitted
dependency on the legacy system is `radar.config_layered`, used lazily by
`v3.kernel.Threshold.registry_backed` at resolution time only.
"""
