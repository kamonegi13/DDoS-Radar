"""The API's closed vocabularies. One place, so there is one spelling.

Two of the words here are load-bearing:

* **the role names and their order.** S2-PROP-021 requires the
  `viewer < analyst < admin` order to be "a single constant every gate
  references", because the legacy system spelled it inline as
  `not in ("admin", "analyst")` in thirteen places, and the thirteenth
  place was the one that read `("admin", "analysts")`.
* **`theater`.** C-01's deepest layer. The word is not merely unused
  here — it is enumerated as forbidden, and a response containing it
  fails a test, because "we renamed it" is what the last two sweeps also
  said.

`TOOL_SCOPE` deserves a note. P7's derivation principle 2 says the
envelope is one shape with the NP7 sentence, no exceptions, and the one
shape is `v3.conclusions.ConclusionEnvelope`, which is scenario-scoped.
Endpoints like `/healthz` and `/api/v3/self_eval` are about the tool
rather than about a scenario, so they are served with this scenario id.
That is deliberately not a second envelope: inventing one is defect G-13,
and a sentinel scenario id costs a constant.
"""
from __future__ import annotations

API_PREFIX = "/api/v3"

#: The scenario id for projections that are about the tool, not a
#: scenario. Chosen so it cannot collide with a real id (which are
#: lowercase words like `taiwan_contingency`) and so it reads as a
#: sentinel rather than as data.
TOOL_SCOPE = "__tool__"

ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"

#: THE total order. S2-PROP-021: declared once, referenced by every gate.
#: Containment, not arithmetic — a role is a position in this tuple and
#: never an integer that some other module can compare its own way.
ROLE_ORDER: tuple[str, ...] = (ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN)
ROLES: frozenset = frozenset(ROLE_ORDER)

GET = "GET"
POST = "POST"
PUT = "PUT"
DELETE = "DELETE"
METHODS: frozenset = frozenset({GET, POST, PUT, DELETE})

#: Methods that may not have a side effect (completion condition 1).
#: A route declaring GET and a side effect is refused at declaration.
SAFE_METHODS: frozenset = frozenset({GET})

#: C-01. Vocabulary that must not appear in any response, at any depth.
#: `theater` conflated country with scenario for four years; the others
#: are the same conflation under different names (see CLAUDE.md's retired
#: terminology table).
FORBIDDEN_RESPONSE_KEYS: frozenset = frozenset({
    "theater", "theaters", "focused_country", "correlate_targets",
    "strategic_countries",
})

__all__ = ["API_PREFIX", "TOOL_SCOPE", "ROLE_VIEWER", "ROLE_ANALYST",
           "ROLE_ADMIN", "ROLE_ORDER", "ROLES", "GET", "POST", "PUT",
           "DELETE", "METHODS", "SAFE_METHODS", "FORBIDDEN_RESPONSE_KEYS"]
