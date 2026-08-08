"""Request in, response out. The only place the fixed order lives.

S2-PROP-016 pins the evaluation order at
`503 (flag) -> 401 (authn) -> 403 (authz) -> 400/404 -> 200` for every
endpoint. The legacy surface decided it per endpoint, in whatever order
the body happened to run its checks, which is why some endpoints answered
403 to an unauthenticated caller and others answered 404 to a caller who
was merely not permitted.

Nothing here is a framework. `handle()` takes an `ApiRequest` and a
`ReadContext` and returns an `ApiResponse`, so the whole surface can be
exercised in a unit test without a socket — which is the property that
made the legacy surface untestable, because reaching an endpoint meant
booting `radar/__init__.py` and its ~40 threads.
"""
from __future__ import annotations

import inspect

from dataclasses import replace

from v3.api import errors as E
from v3.api import routes as R
from v3.api.authorization import authorize
from v3.api.envelope import ApiResponse, failure_response, with_freshness
from v3.api.request import ApiRequest, ReadContext
from v3.api.write import CommandJournal, WriteContext
from v3.kernel.errors import DomainError


def _handler_kwargs(route: R.Route, request: ApiRequest,
                    path_params: dict) -> dict:
    """Path params plus the query params the handler actually declares.

    Reading the handler's own signature rather than forwarding the query
    string wholesale: an unexpected parameter is then a 400 with the name
    in it, instead of being silently ignored — which is how
    `PUT /api/auth/settings` came to accept unknown keys without a word.
    """
    signature = inspect.signature(route.handler)
    accepted = {name for name, param in signature.parameters.items()
                if param.kind is param.KEYWORD_ONLY}
    unknown = sorted(set(request.params) - accepted)
    if unknown:
        raise E.bad_request(
            f"未知のクエリパラメータ: {', '.join(unknown)}",
            unknown=unknown, accepted=sorted(accepted))
    kwargs = dict(path_params)
    for name, value in request.params.items():
        kwargs[name] = value
    return kwargs


def _context_for(route: R.Route, context, request: ApiRequest):
    """The read half for a projection, the write seam for a command.

    A command handler is never handed a `ReadContext` and a read handler
    is never handed a `WriteContext`: the declaration on the route decides
    which, so "this handler can write" is a property of the table rather
    than of what the handler happens to reach for.
    """
    if not route.side_effect:
        return context.read if isinstance(context, WriteContext) else context
    if not isinstance(context, WriteContext):
        # First in S2-PROP-016's order, and the honest answer: this
        # deployment was given no way to write. Saying 404 or 405 would
        # describe the surface wrongly; saying 500 would blame the caller
        # for a composition-root decision.
        raise E.ApiFailure(503, E.ApiError(
            code=E.UNAVAILABLE,
            message="この配備は読み取り専用で構成されています",
            detail={"route": route.route_id, "method": route.method}))
    return replace(context, body=dict(request.body),
                   journal=CommandJournal())


def _audit_discipline(route: R.Route, context) -> None:
    """S2-PROP-019, checked from OUTSIDE the handler.

    "One change, one audit row" is unfalsifiable if the handler is the one
    asserting it. Here the journal is the dispatcher's, the handler cannot
    reach it, and a command that answered 200 having recorded nothing is a
    failure rather than a success nobody notices — which is precisely how
    E-17 (a suppression with no trace) and G-15 (a change with no reader)
    both stayed invisible.
    """
    committed = len(context.journal)
    if committed == 1:
        return
    raise DomainError(
        f"route {route.route_id} declares a side effect but committed "
        f"{committed} audit rows. S2-PROP-019 is one change, one row: zero "
        f"means a command answered 200 having recorded nothing, and more "
        f"than one means a single request moved several states with no "
        f"single row an auditor can point at.")


def handle(request: ApiRequest, context) -> ApiResponse:
    """Resolve, authorize, project or command. In that order, always."""
    if not isinstance(request, ApiRequest):
        raise DomainError(
            f"handle takes an ApiRequest, got {type(request).__name__}")
    if not isinstance(context, (ReadContext, WriteContext)):
        raise DomainError(
            f"handle takes a ReadContext or a WriteContext, got "
            f"{type(context).__name__}: the dispatcher holds no raw store")
    now = context.now
    try:
        route, path_params, path_seen = R.match(request.method, request.path)
        if route is None:
            raise _no_route(request, path_seen)
        # 401/403 BEFORE the handler runs: a refused caller must not be
        # able to learn whether the resource exists by timing or by the
        # difference between 403 and 404.
        failure = authorize(route.access, request.principal)
        if failure is not None:
            raise failure
        handler_context = _context_for(route, context, request)
        kwargs = _handler_kwargs(route, request, path_params)
        response = route.handler(handler_context, **kwargs)
        if not isinstance(response, ApiResponse):
            raise DomainError(
                f"route {route.route_id} returned "
                f"{type(response).__name__}; every route answers with the "
                f"one envelope (P7 derivation principle 2)")
        if route.side_effect:
            _audit_discipline(route, handler_context)
        # P7 §3: the freshness stamp is applied HERE, once, for every
        # route — including the ones a future contributor adds without
        # reading this file.
        return with_freshness(response, now)
    except E.ApiFailure as failure:
        return with_freshness(
            failure_response(failure, observed_at=now), now)


def _no_route(request: ApiRequest, path_seen: bool) -> E.ApiFailure:
    if path_seen:
        return E.ApiFailure(400, E.ApiError(
            code=E.METHOD_NOT_ALLOWED,
            message=f"{request.method} はこのパスでは許可されていません",
            detail={"path": request.path, "method": request.method}))
    return E.not_found(f"エンドポイント {request.path}", path=request.path,
                       method=request.method)


__all__ = ["handle"]
