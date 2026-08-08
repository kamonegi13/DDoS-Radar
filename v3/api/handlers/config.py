"""P7 R14 / C7 — the operationally variable keys, read and changed.

The pair is deliberate and it is the only reason either half may ship.
WP-4.1c deferred C7 with a stated blocker — "an override written on the v3
side would not be read by the resolution path, so `commit()`'s effect
verification must fail; shipping it would BE G-15" — and deferred R14 on
the same dependency. The chain now exists (`v3/config/resolution.py`), so
both land together:

* **R14 serves the layer, not just the number.** For every key: the value,
  which of override / env / default answered, whether the environment holds
  it at all, the default, why the key is variable, and who reads it. G-15's
  damage was not that a wrong value was shown — it was that nobody could
  see that nothing consulted it.
* **C7 writes through the command surface.** The response's `effect` is the
  key re-resolved through the same chain R14 serves, after the append. A
  change the resolution path does not show is refused by `commit()` rather
  than answered 200.

Neither handler defaults a missing chain. A deployment composed without one
gets 503 with the reason, because answering from an empty chain would report
"default" for keys the environment sets — a confident wrong answer, which is
the failure mode this endpoint exists to end.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, command_response, tool_response
from v3.api.vocabulary import TOOL_SCOPE
from v3.api.write import Change
from v3.commands import spec as SPEC
from v3.commands import state as S
from v3.config import registry
from v3.config.resolution import LAYERS
from v3.kernel.errors import DomainError

_NO_CHAIN = ("この配備は設定解決チェーンを持ちません"
             "（合成ルートが ConfigResolver を供給していません）")


def _chain(read_context):
    if read_context.config is None:
        raise E.ApiFailure(503, E.ApiError(
            code=E.UNAVAILABLE, message=_NO_CHAIN,
            detail={"variable_keys": list(registry.variable_keys())}))
    return read_context.config


def _known_key(key: str) -> str:
    """Refuse a pinned or unknown key HERE, as a 400 with the reason.

    The registry raises a `DomainError` carrying the explanation — pinned
    keys name their provenance and say the change is a code change — and it
    is translated rather than replaced, so the analyst gets the same
    sentence the code enforces.
    """
    try:
        registry.refuse_if_not_variable(key)
    except DomainError as exc:
        raise E.bad_request(str(exc), key=key,
                            variable_keys=list(registry.variable_keys())
                            ) from exc
    return key


def read_config(context) -> ApiResponse:
    """R14 — every O-18 group (a) key, with the layer that answered."""
    chain = _chain(context)
    resolved = chain.resolve_all(ledger=context.ledger, at=context.now)
    return tool_response(
        observed_at=context.now,
        config=[value.as_dict() for value in resolved],
        variable_keys=list(registry.variable_keys()),
        layers=list(LAYERS),
        environment_layer_keys=list(chain.environment_keys),
        pinned_note=("O-18 群 (b) の定数は R10 が開示します。"
                     "本 endpoint は運用可変キーのみを扱います"))


def set_config(context, *, key: str) -> ApiResponse:
    """C7 — override a variable key. The reason is required."""
    _chain(context.read)
    _known_key(key)
    body = context.body
    if "value" not in body:
        raise E.bad_request("value を指定してください", key=key)
    committed = context.commit(Change(
        action=S.CONFIG_OVERRIDE,
        target=SPEC.Target(kind=S.TARGET_CONFIG, id=key),
        payload={"value": body.get("value"), "reason": body.get("reason")},
        reason=body.get("reason")))
    return command_response(TOOL_SCOPE, committed, observed_at=context.now,
                            key=key)


def clear_config(context, *, key: str) -> ApiResponse:
    """C7's DELETE — drop the override, back to env-or-default."""
    _chain(context.read)
    _known_key(key)
    committed = context.commit(Change(
        action=S.CONFIG_CLEAR,
        target=SPEC.Target(kind=S.TARGET_CONFIG, id=key),
        payload={}, reason=context.body.get("reason")))
    return command_response(TOOL_SCOPE, committed, observed_at=context.now,
                            key=key)


__all__ = ["read_config", "set_config", "clear_config"]
