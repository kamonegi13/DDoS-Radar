"""P7 C13 — the auth family's nine routes.

Who may call each of them is decided in the route table, like every other
route's, and this module contains none of that vocabulary — which is why
the register and update handlers forward the request body wholesale
instead of picking fields out of it. The apply functions in
`v3/auth/store.py` are where a standing is validated, and they are not
handlers, so the gate cannot end up in a body (G-01).

Two of the nine write nothing. `login` and `refresh` are projections over
the user fold plus a signature: they are declared in
`routes.SESSION_ROUTES` with the reason, they receive a `ReadContext`,
and so "a session is not ledger state" is the object they hold rather
than a claim in a comment. The other three commands (`logout`,
`register`, `password`, and the two administrative edges) each commit
exactly one row, which the dispatcher counts from outside.

The credential never leaves the fold. Command answers are built from
`public_view`, not from the committed effect, because `Committed.as_dict`
carries the resolved state and the resolved state is where the hash is.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, tool_response
from v3.auth import password as P
from v3.auth import session as SESSION
from v3.auth import store as US
from v3.commands import spec as SPEC
from v3.api.write import Change

_ABSENT = ("この配備は認証機構なしで構成されています。"
           "v3 は署名鍵を生成しません — 稼働系の鍵を回転させないためです")


def _guarded(call):
    """Translate the session layer's refusals into the declared statuses."""
    try:
        return call()
    except SESSION.SessionThrottled as exc:
        raise E.throttled(str(exc)) from None
    except SESSION.SessionRefused as exc:
        raise E.unauthenticated(str(exc)) from None


def _provider(context):
    provider = getattr(context, "auth", None)
    if provider is None:
        raise E.unavailable(_ABSENT, key_id=SESSION.SIGNING_KEY_ID)
    return provider


def _target(user_id: str):
    if not isinstance(user_id, str) or not user_id.strip():
        raise E.bad_request("user_id が必要です", field="user_id")
    return SPEC.Target(kind=US.TARGET_USER, id=user_id.strip())


def _reason(context):
    stated = context.body.get("reason")
    return None if stated is None else str(stated)


# ── the two that write nothing ──────────────────────────────────────────
def login(context) -> ApiResponse:
    """C13 — verify a credential, mint a pair. No ledger row.

    The source address comes from the transport (the dispatcher
    stamps it onto the context), never from the body: a client-supplied address would let an attacker
    pick a fresh bucket for every attempt and the guard would count
    nothing.
    """
    provider = _provider(context)
    session = _guarded(lambda: SESSION.login(
        context.ledger, provider,
        user_id=context.body.get("user_id"),
        password=context.body.get("password"),
        now=context.now, client_ip=context.client_ip))
    return tool_response(observed_at=context.now, session=session)


def refresh(context) -> ApiResponse:
    """C13 — a new access token at the CURRENT standing (S1-SVC-005)."""
    provider = _provider(context)
    session = _guarded(lambda: SESSION.refresh(
        context.ledger, provider,
        refresh_token=context.body.get("refresh_token"), now=context.now))
    return tool_response(observed_at=context.now, session=session)


# ── the commands ────────────────────────────────────────────────────────
def logout(context) -> ApiResponse:
    """C13 — revoke this actor's standing. One row, and it is read.

    `principal_for` compares a token's `iat` against the floor this
    command moves, so the effect has a reader before the row is written.
    """
    committed = context.commit(Change(
        action=US.USER_SESSIONS_REVOKE, target=_target(context.actor_id),
        payload={}, reason=_reason(context)))
    return tool_response(
        observed_at=context.now, user=US.public_view(committed.effective),
        command=committed.record.as_dict()["command_id"],
        note="このセッションは失効しました。以後は再ログインが必要です")


def register(context) -> ApiResponse:
    """C13 — create an identity and its first credential."""
    committed = context.commit(Change(
        action=US.USER_REGISTER,
        target=_target(context.body.get("user_id")),
        payload=dict(context.body), reason=_reason(context)))
    return tool_response(observed_at=context.now,
                         user=US.public_view(committed.effective),
                         command=committed.record.as_dict()["command_id"])


def change_password(context) -> ApiResponse:
    """C13 — the actor changes their own credential.

    The current one is verified HERE rather than inside `apply`, because
    `apply` is a pure function of `(before, payload)` and verifying a
    secret is exactly the kind of work that must not end up inside a fold
    replayed from the log.
    """
    state = US.user_state(context.read.ledger, context.actor_id,
                          until=context.now)
    if not P.verify(US.credential_of(state),
                    context.body.get("old_password")):
        raise E.unauthenticated("現在のパスワードが正しくありません")
    committed = context.commit(Change(
        action=US.USER_PASSWORD_SET, target=_target(context.actor_id),
        payload=dict(context.body), reason=_reason(context)))
    return tool_response(
        observed_at=context.now, user=US.public_view(committed.effective),
        command=committed.record.as_dict()["command_id"],
        note="このパスワード変更により当該利用者の全セッションが失効しました")


def set_user_standing(context, *, user_id: str) -> ApiResponse:
    """C13 — an administrator changes somebody's standing."""
    committed = context.commit(Change(
        action=US.USER_ROLE_SET, target=_target(user_id),
        payload=dict(context.body), reason=_reason(context)))
    return tool_response(
        observed_at=context.now, user=US.public_view(committed.effective),
        command=committed.record.as_dict()["command_id"],
        note="発行済みアクセストークンは即時失効します"
             "（refresh は生存し、次回更新で新しい標準が載ります）")


def remove_user(context, *, user_id: str) -> ApiResponse:
    """C13 — deactivation. The rows stay; the standing goes."""
    committed = context.commit(Change(
        action=US.USER_DEACTIVATE, target=_target(user_id),
        payload=dict(context.body), reason=_reason(context)))
    return tool_response(
        observed_at=context.now, user=US.public_view(committed.effective),
        command=committed.record.as_dict()["command_id"],
        note="削除ではなく無効化です。判断履歴（AP4）は保持されます")


# ── the two reads ───────────────────────────────────────────────────────
def read_users(context) -> ApiResponse:
    """C13 — the register. Never a credential (S1-SVC-008)."""
    listed = US.users(context.ledger, until=context.now)
    return tool_response(observed_at=context.now, users=listed,
                         user_count=len(listed))


def read_user(context, *, user_id: str) -> ApiResponse:
    state = US.user_state(context.ledger, user_id, until=context.now)
    if state is None:
        raise E.not_found(f"利用者 {user_id}", user_id=user_id)
    return tool_response(observed_at=context.now,
                         user=US.public_view(state))


__all__ = ["login", "refresh", "logout", "register", "change_password",
           "set_user_standing", "remove_user", "read_users", "read_user"]
