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

from v3.api import errors as E
from v3.api import routes as R
from v3.api.authorization import authorize
from v3.api.envelope import ApiResponse, failure_response, with_freshness
from v3.api.request import ApiRequest, ReadContext
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


def handle(request: ApiRequest, context: ReadContext) -> ApiResponse:
    """Resolve, authorize, project. In that order, always."""
    if not isinstance(request, ApiRequest):
        raise DomainError(
            f"handle takes an ApiRequest, got {type(request).__name__}")
    if not isinstance(context, ReadContext):
        raise DomainError(
            f"handle takes a ReadContext, got {type(context).__name__}: "
            f"the dispatcher does not hold a writer either")
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
        kwargs = _handler_kwargs(route, request, path_params)
        response = route.handler(context, **kwargs)
        if not isinstance(response, ApiResponse):
            raise DomainError(
                f"route {route.route_id} returned "
                f"{type(response).__name__}; every route answers with the "
                f"one envelope (P7 derivation principle 2)")
        # P7 §3: the freshness stamp is applied HERE, once, for every
        # route — including the ones a future contributor adds without
        # reading this file.
        return with_freshness(response, context.now)
    except E.ApiFailure as failure:
        return with_freshness(
            failure_response(failure, observed_at=context.now), context.now)


def _no_route(request: ApiRequest, path_seen: bool) -> E.ApiFailure:
    if path_seen:
        return E.ApiFailure(400, E.ApiError(
            code=E.METHOD_NOT_ALLOWED,
            message=f"{request.method} はこのパスでは許可されていません",
            detail={"path": request.path, "method": request.method}))
    return E.not_found(f"エンドポイント {request.path}", path=request.path,
                       method=request.method)


__all__ = ["handle"]
