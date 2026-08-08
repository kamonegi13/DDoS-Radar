"""The session lifecycle: login, refresh, logout, and who is asking.

Three rulings are implemented here rather than described somewhere.

**The role's primary source is the token claim** (S1-SVC-011's v3 norm).
Production re-reads the database on every request and rolls every
exception in that read into a 401, so a database hiccup presents as "your
session expired". Here the claim is authoritative and a failure of the
auth path is distinguishable from a lack of permission, which is what the
norm asks for.

**A change of standing still bites immediately.** Making the claim
authoritative would otherwise mean a demotion took up to an access
token's lifetime — strictly worse than what it replaced. So the user
state carries two floors:

    sessions_not_before   logout, password change, deactivation.
                          Both token types die.
    access_not_before     a role change. ACCESS tokens die; the refresh
                          token survives, so the client re-authenticates
                          silently and the new access token carries the
                          new role (S1-SVC-005's "refresh re-resolves the
                          role", achieved without a per-request read).

**Nothing here writes.** `login` and `refresh` are projections over the
user fold plus a signature; they hold a `ReadContext` and could not write
if they tried. `logout` is a command, because revoking a session IS a
state change and AP4 should hold the row.

`LoginGuard` is the one mutable object in the surface, and it is
deliberately not ledger state: it holds failed-attempt timestamps per
source address, in this process, exactly as production does
(`radar/auth.py:26-65`, 5 failures / 300 s / 1000 addresses). Its
limitations are production's too and are stated rather than fixed here —
it is per-process, it is lost on restart, and it counts addresses rather
than accounts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from v3.auth import password as P
from v3.auth import store as US
from v3.auth import tokens as T
from v3.kernel.errors import DomainError

#: v3's OWN key id. Not `JWT_SECRET_KEY`: see `v3/auth/tokens.py`.
SIGNING_KEY_ID = "NOROSHI_V3_JWT_SECRET"
#: The bootstrap material, also v3's own. Read once, by the composition
#: root, and only when the user fold is empty.
BOOTSTRAP_USER_ID = "admin"
BOOTSTRAP_KEY_ID = "NOROSHI_V3_BOOTSTRAP_PASSWORD"

#: S1-SVC-002's uniform answer. One string for "no such user" and for
#: "wrong password", so the surface cannot be used to enumerate accounts.
REFUSED_MESSAGE = "ユーザー名またはパスワードが正しくありません"
THROTTLED_MESSAGE = "ログイン試行が多すぎます。しばらく待って再試行してください"


class SessionRefused(DomainError):
    """401. Deliberately carries no detail the caller could learn from."""


class SessionThrottled(DomainError):
    """429. The source address has failed too often in the window."""


class LoginGuard:
    """Failed-login accounting, per source address, in this process."""

    #: `radar/auth.py:29-31`, transcribed.
    MAX_ATTEMPTS = 5
    WINDOW_SEC = 300.0
    MAX_IPS = 1000

    __slots__ = ("_attempts",)

    def __init__(self) -> None:
        self._attempts: dict = {}

    def tracked(self) -> tuple:
        return tuple(sorted(self._attempts))

    def _recent(self, address: str, now: float) -> list:
        return [stamp for stamp in self._attempts.get(address, ())
                if float(now) - stamp < self.WINDOW_SEC]

    def blocked(self, address: Optional[str], now: float) -> bool:
        if address is None:
            return False
        return len(self._recent(str(address), now)) >= self.MAX_ATTEMPTS

    def record_failure(self, address: Optional[str], now: float) -> None:
        if address is None:
            return
        key = str(address)
        self._attempts[key] = self._recent(key, now) + [float(now)]
        self._evict()

    def clear(self, address: Optional[str]) -> None:
        if address is not None:
            self._attempts[str(address)] = []

    def _evict(self) -> None:
        """Production's eviction, including its weakness.

        Empty lists first, then the address whose most recent attempt is
        oldest. That is gameable — an attacker with many addresses can
        push a victim's record out — and it is transcribed rather than
        improved because the guard is a transitional control and a v3 that
        behaved differently would make the parity window harder to read
        (ACCIDENTAL A1).
        """
        if len(self._attempts) <= self.MAX_IPS:
            return
        for key in [k for k, v in self._attempts.items() if not v]:
            del self._attempts[key]
            if len(self._attempts) <= self.MAX_IPS:
                return
        while len(self._attempts) > self.MAX_IPS:
            oldest = min(self._attempts,
                         key=lambda k: max(self._attempts[k], default=0.0))
            del self._attempts[oldest]


@dataclass(frozen=True, slots=True)
class AuthProvider:
    """What the composition root hands the surface. Never a raw secret.

    Held on the `ReadContext` beside the config chain, and `None` where a
    deployment was composed without one — in which case every auth route
    answers 503 rather than pretending to authenticate.
    """

    authority: T.TokenAuthority
    guard: Optional[LoginGuard] = field(default=None)

    def __post_init__(self) -> None:
        if not isinstance(self.authority, T.TokenAuthority):
            raise DomainError(
                f"an AuthProvider carries a TokenAuthority, got "
                f"{type(self.authority).__name__}")

    def as_dict(self) -> dict:
        """The disclosure. Lifetimes and a fingerprint; no key material."""
        return {"tokens": self.authority.as_dict(),
                "login_guard": self.guard is not None,
                "signing_key_id": SIGNING_KEY_ID}


def _provider(context_or_provider) -> AuthProvider:
    provider = getattr(context_or_provider, "auth", context_or_provider)
    if not isinstance(provider, AuthProvider):
        raise DomainError(
            "この配備は認証機構なしで構成されています"
            f"（{SIGNING_KEY_ID} が供給されていません）")
    return provider


def _active_state(ledger, user_id: str, now: float):
    state = US.user_state(ledger, user_id, until=now)
    if state is None or not state.get("active", False):
        return None
    return state


def _floor(state, name: str) -> float:
    value = state.get(name)
    return 0.0 if value is None else float(value)


def _session_payload(provider: AuthProvider, state, *, now: float,
                     refresh_token: Optional[str] = None) -> dict:
    authority = provider.authority
    user_id = str(state["user_id"])
    role = str(state["role"])
    payload = {
        "user_id": user_id,
        "role": role,
        "access_token": authority.issue(user_id=user_id, role=role,
                                        token_type=T.TYPE_ACCESS, now=now),
        "access_expires_sec": authority.access_ttl_sec,
        "issued_at": float(now),
    }
    if refresh_token is not None:
        payload["refresh_token"] = refresh_token
        payload["refresh_expires_sec"] = authority.refresh_ttl_sec
    return payload


def login(ledger, context_or_provider, *, user_id: Any, password: Any,
          now: float, client_ip: Optional[str] = None) -> dict:
    """Verify a credential and mint a pair. Writes nothing."""
    provider = _provider(context_or_provider)
    guard = provider.guard
    if guard is not None and guard.blocked(client_ip, now):
        raise SessionThrottled(THROTTLED_MESSAGE)
    if not isinstance(user_id, str) or not user_id.strip():
        raise SessionRefused(REFUSED_MESSAGE)
    state = _active_state(ledger, user_id.strip(), now)
    if state is None or not P.verify(US.credential_of(state), password):
        # One branch for both failures, and the counter moves for both.
        if guard is not None:
            guard.record_failure(client_ip, now)
        raise SessionRefused(REFUSED_MESSAGE)
    if guard is not None:
        guard.clear(client_ip)
    refresh_token = provider.authority.issue(
        user_id=str(state["user_id"]), role=str(state["role"]),
        token_type=T.TYPE_REFRESH, now=now)
    return _session_payload(provider, state, now=now,
                            refresh_token=refresh_token)


def refresh(ledger, context_or_provider, *, refresh_token: Any,
            now: float) -> dict:
    """Mint an access token from a refresh token, at the CURRENT role."""
    provider = _provider(context_or_provider)
    try:
        claims = provider.authority.verify(
            refresh_token, expected_type=T.TYPE_REFRESH, now=now)
    except T.TokenError as exc:
        raise SessionRefused(str(exc)) from None
    state = _active_state(ledger, claims.subject, now)
    if state is None:
        raise SessionRefused(REFUSED_MESSAGE)
    if T.revoked(claims, not_before=_floor(state, "sessions_not_before")):
        raise SessionRefused("このセッションは失効しています")
    return _session_payload(provider, state, now=now)


def principal_for(ledger, context_or_provider, *, access_token: Any,
                  now: float):
    """WHO is asking, resolved from the token and checked against the fold.

    `Principal` is imported inside the function on purpose: `v3.api` is
    the layer that consumes this module, and a module-level import here
    would make `v3.auth` and `v3.api` a cycle the moment either package's
    `__init__` grew an edge.
    """
    from v3.api.request import Principal

    provider = _provider(context_or_provider)
    try:
        claims = provider.authority.verify(
            access_token, expected_type=T.TYPE_ACCESS, now=now)
    except T.TokenError as exc:
        raise SessionRefused(str(exc)) from None
    state = _active_state(ledger, claims.subject, now)
    if state is None:
        raise SessionRefused("この利用者は無効です")
    floor = max(_floor(state, "sessions_not_before"),
                _floor(state, "access_not_before"))
    if T.revoked(claims, not_before=floor):
        raise SessionRefused("このセッションは失効しています")
    return Principal(user_id=claims.subject, role=claims.role)


__all__ = ["SIGNING_KEY_ID", "BOOTSTRAP_KEY_ID", "BOOTSTRAP_USER_ID",
           "REFUSED_MESSAGE", "THROTTLED_MESSAGE", "AuthProvider",
           "LoginGuard", "SessionRefused", "SessionThrottled", "login",
           "refresh", "principal_for"]
