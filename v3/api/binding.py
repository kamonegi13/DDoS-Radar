"""The web binding. Thin on purpose, and the only file here that imports Flask.

Everything above this line is a function from a typed request to a typed
response. This file turns a Flask request into an `ApiRequest`, calls
`dispatch.handle`, and turns the `ApiResponse` into JSON. It contains no
projection logic, no authorization decision and no error assembly — an
error body built here would be the exact place the NP7 sentence went
missing before (G-13).

Two v3 invariants deserve a note, because a server looks like the kind of
thing that would violate them:

* **no HTTP client.** The discipline gate forbids `requests`, `httpx`,
  `socket` and friends outside `v3/fetch/client.py`. A server binding is
  a different act from a fetch client — it answers calls, it does not
  make them — and Flask is not on that list, so this file needs no
  exemption and gets none. `tests/test_api_boundary.py` asserts the
  gate still passes over `v3/api/` with nothing added to its allow-list.
* **import is still inert.** `import v3.api.binding` defines a factory;
  it does not create an app, bind a port or start a thread. The
  composition root calls `create_blueprint()` explicitly, the same way
  it calls `loop.start()`.

Flask itself is imported lazily inside the factory, so importing this
module costs nothing and `v3/api/` stays importable in an environment
that has no web framework at all — which is how the handler suites run.
"""
from __future__ import annotations

from typing import Callable, Optional

from v3.api.dispatch import handle
from v3.api.request import ANONYMOUS, ApiRequest, Principal, ReadContext
from v3.api.routes import ROUTES
from v3.kernel.errors import DomainError

#: Flask's converter syntax differs from the table's `<name>`; the table
#: stays framework-free, so the translation lives here.
_METHOD_ATTR = "method"


def _flask_rule(path: str) -> str:
    """`/a/<x>/b` is already Flask's spelling; kept explicit anyway."""
    return path


def create_blueprint(context_factory: Callable[[], ReadContext], *,
                     principal_factory: Optional[Callable] = None,
                     name: str = "v3_api"):
    """Build a Flask blueprint over the route table.

    `context_factory` is supplied by the composition root and is the only
    way a request reaches the ledger — so the seam that makes reads
    side-effect-free (a `ReadOnlyLedger` inside a `ReadContext`) is also
    the seam the web layer has to go through.
    """
    from flask import Blueprint, jsonify, request as flask_request

    blueprint = Blueprint(name, __name__)

    def _principal():
        if principal_factory is None:
            return ANONYMOUS
        resolved = principal_factory()
        if resolved is None:
            return ANONYMOUS
        if not isinstance(resolved, Principal):
            raise DomainError(
                "principal_factory must return a Principal or None; a dict "
                "here is how a client-supplied string becomes a privilege")
        return resolved

    def _make_view(route):
        def view(**path_params):
            context = context_factory()
            api_request = ApiRequest(
                method=getattr(flask_request, _METHOD_ATTR),
                path=flask_request.path,
                params=dict(flask_request.args),
                body=(flask_request.get_json(silent=True) or {}),
                principal=_principal())
            response = handle(api_request, context)
            return jsonify(response.as_dict()), response.status

        view.__name__ = f"v3_{route.route_id}"
        return view

    for route in ROUTES:
        blueprint.add_url_rule(_flask_rule(route.path),
                               endpoint=f"v3_{route.route_id}",
                               view_func=_make_view(route),
                               methods=[route.method])
    return blueprint


__all__ = ["create_blueprint"]
