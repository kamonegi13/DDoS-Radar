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
