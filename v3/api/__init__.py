"""L6 — the public API. Projections of the ledger, and nothing else.

The four things WP-4.1 had to make structurally true, and where each one
lives:

    readonly      condition 1 — a read handler holds a ReadOnlyLedger,
                  whose forwarded methods are verified by AST to use only
                  SQLite's `mode=ro` connection. A-01 (a GET that ran the
                  scoring tick) is unreachable rather than forbidden.
    routes        condition 4 — `Access` is a required field, `public` is
                  an explicit decision with a reason, and the handler
                  modules are AST-checked to contain no role vocabulary
                  at all. G-01 was a forgotten call; there is no call.
    registry      condition 2 — the ten v1/v2 duplicate pairs and their
                  single v3 destination, plus P7 §1 against what is
                  actually served.
    envelope      condition 5 (from WP-3.1) — ONE envelope, L3's, with
                  the NP7 sentence required by the type. Errors are the
                  same envelope with `error` set, not a body assembled in
                  an exception handler, which is where it went missing.

The vocabulary is country and scenario. `theater` is enumerated as
forbidden and checked at response construction, not only in a test: a
test sees the responses it thought to build.

Importing this package is inert — no thread, no socket, no environment
read, no database. The Flask binding lives in `v3/api/binding.py` and is
imported by the composition root, never by a handler; that separation is
what makes the whole surface testable without a server, which the legacy
surface never was (reaching an endpoint meant booting radar/__init__.py
and its ~40 threads).
"""
from v3.api.dispatch import handle
from v3.api.envelope import (ApiResponse, failure_response,
                             scenario_response, tool_response)
from v3.api.errors import ApiError, ApiFailure
from v3.api.readonly import ReadOnlyLedger
from v3.api.request import ANONYMOUS, ApiRequest, Principal, ReadContext, \
    ScenarioRef
from v3.api.routes import ROUTES, Route, match

__all__ = [
    "handle",
    "ApiRequest",
    "ApiResponse",
    "ReadContext",
    "ReadOnlyLedger",
    "Principal",
    "ANONYMOUS",
    "ScenarioRef",
    "ApiError",
    "ApiFailure",
    "ROUTES",
    "Route",
    "match",
    "scenario_response",
    "tool_response",
    "failure_response",
]
