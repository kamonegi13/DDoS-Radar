"""The composition root's half of P7 C13: key material and the first user.

Two things happen here and nowhere else.

**The signing key is obtained.** Through `v3/runtime/secrets.py`, the one
module licensed to read the process environment, under v3's OWN key id
(`NOROSHI_V3_JWT_SECRET`). Never `JWT_SECRET_KEY`. That variable belongs
to the running v1 process, which generates it when it is missing and
appends it to `config.env` (`radar/auth.py:155-199`); a second process
reading — let alone writing — it is one bug away from rotating a secret
whose rotation ends every live analyst's session. Separate key ids also
mean a v1 token cannot verify here and a v3 token cannot verify there,
which is a property no operator has to remember.

**No key means no session surface.** `build_provider` returns `None`, the
composition root passes `None`, and the auth routes answer 503 with the
reason. The alternative — generating one — is what production does, and
it is exactly what must not happen twice.

**The first user is created here, not by a route.** A registration route
that admitted an anonymous caller "just for the first user" is a hole
that stays open, and an admin auto-created with a generated password is a
secret this layer would have to print. So: `bootstrap` is idempotent, it
acts ONLY when the user fold is empty, and it takes the password from
`NOROSHI_V3_BOOTSTRAP_PASSWORD`. Absent, it does nothing and says so —
an operator with no users and no bootstrap material has a deployment
nobody can log into, which is a safe failure and a loud one.
"""
from __future__ import annotations

import time
from typing import Any, Mapping, Optional

from v3.api.request import Principal, ReadContext
from v3.api.readonly import ReadOnlyLedger
from v3.api.write import Change, WriteContext
from v3.api.writeonly import CommandLedger
from v3.auth import session as SESSION
from v3.auth import store as US
from v3.auth import tokens as T
from v3.commands import spec as SPEC
from v3.kernel.errors import DomainError
from v3.kernel.roles import ROLE_ADMIN
from v3.runtime import secrets as SECRETS

#: The actor recorded for the bootstrap row. Not a login-able identity:
#: it is registered nowhere, so nothing can authenticate as it, and the
#: decision trail still names who created the first administrator.
BOOTSTRAP_ACTOR = Principal(user_id="system:bootstrap", role=ROLE_ADMIN)


def build_provider(source: Optional[Mapping[str, str]] = None,
                   *, guard: bool = True) -> Optional[SESSION.AuthProvider]:
    """The session surface, or `None` when no key was supplied."""
    key = SECRETS.optional_value(SESSION.SIGNING_KEY_ID, source)
    if key is None:
        return None
    return SESSION.AuthProvider(
        authority=T.TokenAuthority(key=key),
        guard=SESSION.LoginGuard() if guard else None)


def announcement(provider: Optional[SESSION.AuthProvider]) -> tuple[str, ...]:
    """One plain sentence about the posture. Returned, never logged here.

    Same shape as `CredentialPlan.announcement`: this module knows what
    happened, not where the operator reads.
    """
    if provider is None:
        return (
            f"session surface: ABSENT — {SESSION.SIGNING_KEY_ID} was not "
            f"supplied. Every /api/v3/auth/* route answers 503. v3 does not "
            f"generate a signing key, because production generates and "
            f"persists its own and a second writer would invalidate every "
            f"live session.",)
    return (
        f"session surface: active, issuer={T.ISSUER}, "
        f"access={provider.authority.access_ttl_sec:.0f}s "
        f"refresh={provider.authority.refresh_ttl_sec:.0f}s, "
        f"login guard "
        f"{'on' if provider.guard is not None else 'OFF'}.",)


def bootstrap(store, *, source: Optional[Mapping[str, str]] = None,
              now: Optional[float] = None,
              user_id: str = SESSION.BOOTSTRAP_USER_ID) -> dict:
    """Create the first administrator, once, from supplied material.

    Returns a report rather than raising, because a deployment with no
    bootstrap material is a legitimate state (someone else already
    created the users) and NP3 says the tool starts anyway.
    """
    at = time.time() if now is None else float(now)
    reader = ReadOnlyLedger(store)
    existing = US.user_count(reader, until=at)
    if existing:
        return {"created": False, "reason": "users_exist",
                "user_count": existing}
    material = SECRETS.optional_value(SESSION.BOOTSTRAP_KEY_ID, source)
    if material is None:
        return {"created": False, "reason": "no_bootstrap_material",
                "key_id": SESSION.BOOTSTRAP_KEY_ID,
                "note": "利用者が 0 件で、ブートストラップ資格情報も"
                        "供給されていません。誰もログインできません"}
    context = WriteContext(
        read=ReadContext(ledger=reader, now=at),
        ledger=CommandLedger(store), principal=BOOTSTRAP_ACTOR)
    committed = context.commit(Change(
        action=US.USER_REGISTER,
        target=SPEC.Target(kind=US.TARGET_USER, id=user_id),
        payload={"password": material, "role": ROLE_ADMIN},
        reason="composition root bootstrap: 利用者 0 件のため"))
    return {"created": True, "reason": "bootstrapped",
            "user": US.public_view(committed.effective),
            "command_id": committed.record.command_id}


def principal_resolver(store, provider: Optional[SESSION.AuthProvider],
                       *, now=None):
    """Build the callable `v3/api/binding.py` asks for.

    It is handed the `Authorization` header and returns a `Principal` or
    `None`. Deliberately NOT raising on a bad token: an unusable token and
    no token are the same fact for the route table, which answers 401
    from its own declaration — and a resolver that raised would turn every
    expired token into a 500.
    """
    def resolve(authorization: Optional[str] = None):
        if provider is None or not authorization:
            return None
        parts = str(authorization).split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        at = time.time() if now is None else float(now)
        try:
            return SESSION.principal_for(ReadOnlyLedger(store), provider,
                                         access_token=parts[1], now=at)
        except (SESSION.SessionRefused, DomainError):
            return None
    return resolve


def disclosure(provider: Optional[SESSION.AuthProvider]) -> dict[str, Any]:
    """What R15's app config may say about the session surface."""
    if provider is None:
        return {"present": False, "signing_key_id": SESSION.SIGNING_KEY_ID}
    return {"present": True, **provider.as_dict()}


__all__ = ["BOOTSTRAP_ACTOR", "announcement", "bootstrap", "build_provider",
           "disclosure", "principal_resolver"]
