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
module under it is expected to keep that property.

**There is now no permitted dependency on the legacy system at all.** The
last one was `radar.config_layered`, imported lazily by
`v3.kernel.threshold._default_resolver` when a registry-backed threshold
resolved with no injected chain. Wiring WP-4.4 found that this made a
composed v3 process able to boot v1; the fallback was removed in the §7-2
#115 sweep, because v3's composition root always injects
`v3/config/resolution.py` and an unusable fallback that starts the legacy
application is worse than a loud failure. The composition root's
`LegacyImportBarrier` now guards a property the tree already has.
"""
