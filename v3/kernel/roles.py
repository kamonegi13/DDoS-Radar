"""THE role vocabulary and its total order. One declaration, no imports.

It lived in `v3/api/vocabulary.py` until WP-4.1g, and that was the right
place until something below the API needed it: the auth store validates a
standing and the token authority refuses to sign an unknown one, and
neither may import `v3.api` — doing so runs `v3/api/__init__.py`, which
imports the route table, which imports the handlers, which import the
auth package. A cycle.

Moving the constants down rather than copying them is the whole point.
S2-PROP-021 asks for "a single constant every gate references" because
the legacy system spelled `not in ("admin", "analyst")` inline thirteen
times and the thirteenth read `("admin", "analysts")`. A second copy here
would reproduce that with two files instead of thirteen call sites.
`v3/api/vocabulary.py` re-exports these names, so every existing importer
is unchanged and there is still exactly one place the words are written.

This module imports nothing on purpose. Anything it imported could later
import something that imports it.
"""
from __future__ import annotations

ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"

#: Containment, expressed as a position in a tuple rather than as an
#: integer rank — an integer is a thing another module can compare its own
#: way, and "its own way" is how a gate comes to disagree with a gate.
ROLE_ORDER: tuple[str, ...] = (ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN)
ROLES: frozenset = frozenset(ROLE_ORDER)

__all__ = ["ROLE_VIEWER", "ROLE_ANALYST", "ROLE_ADMIN", "ROLE_ORDER",
           "ROLES"]
