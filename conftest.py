"""pytest root conftest.

gevent's monkey-patch must run BEFORE any module imports `ssl`,
`socket`, `threading`, etc. When pytest collects multiple test files
in one session, files that import `radar.*` directly (without going
through `radar_api`) cause `ssl` to load unpatched. A subsequent
`from radar_api import ...` then triggers a second-pass patch_all()
which corrupts gevent's thread.get_ident, raising:
  "RuntimeError: cannot release un-acquired lock"
during collection of later files (e.g. test_engine, test_auth,
test_analyst_permissions).

Patching here, before any test module is imported, guarantees a
single consistent patched runtime for the entire test session.
"""
from gevent import monkey as _monkey

_monkey.patch_all()

# Phase 7.5a (audit Security H5): flask-limiter is initialised at import
# time in radar/__init__.py with default limits of 120/min + 2000/hour.
# pytest fires hundreds of requests per minute against the in-process
# Flask test client, which would trip the cap and convert legitimate
# behaviour-under-test into 429 storms. Set the opt-out env var BEFORE
# any test imports `radar` so the limiter constructor sees enabled=False.
import os as _os
_os.environ.setdefault("RADAR_RATE_LIMIT_ENABLED", "false")

# Phase 7.5g (audit Security H3): the cookie-based refresh flow uses
# CSRF double-submit by default. The Flask test client cannot easily
# round-trip the CSRF cookie through every fixture, so opt out at
# import time. Production keeps the protection on (default).
_os.environ.setdefault("RADAR_JWT_CSRF_DISABLED", "true")
# Cookie Secure=true would force the test client (HTTP, no TLS) to
# silently drop the refresh cookie. Disable for the test environment.
_os.environ.setdefault("JWT_COOKIE_SECURE", "false")
