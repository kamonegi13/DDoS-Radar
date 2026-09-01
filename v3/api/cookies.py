"""The cookie surface: typed request input, typed response directives.

§7-2 #103 was the only cutover blocker this programme registered, and its
cause was named precisely: not a design choice, a missing transport.
`ApiRequest(method, path, params, body, principal, client_ip)` had no
concept of a cookie, so the refresh token had nowhere to ride except the
JSON body — which S1-SVC-004 / S2-API-010 forbid and S1-UI-002 calls CORE,
because an httpOnly cookie closes XSS theft structurally rather than by
shortening the window.

Three decisions are worth stating.

**The cookie face is data, and only the binding turns it into a header.**
A handler stays a function from a typed request to a typed response — the
property that lets the whole surface be exercised without a socket. So a
cookie arrives as `PresentedCookies` on the read context and leaves as a
`SetCookie` / `ClearCookie` directive on the response. Nothing under
`v3/api/handlers/` names `Set-Cookie`, and a test asserts the absence.

**The CSRF pairing is a declaration, not a check.** Production pairs the
httpOnly refresh cookie with a readable companion the SPA echoes back in
`X-CSRF-TOKEN`; without the header the refresh is refused even when the
cookie was sent. Porting that as "the refresh handler also checks a
header" would reproduce G-01 exactly — one endpoint out of four forgetting
the gate, invisible because a missing call and an unneeded call look the
same. So `CookiePolicy` REFUSES TO EXIST with a cookie-borne credential
and no CSRF requirement. There is no spelling for the forgetting, and the
dispatcher enforces the declaration before the handler runs.

**A route may only emit what it declared.** `check_emissions` is called by
the dispatcher on the way out, so a handler that set a cookie the table
never mentioned is a failing build rather than a silent header.

The posture (httpOnly, SameSite, Secure, path scope, max-age) is
production's, verified against `radar/auth.py` and the installed
`flask_jwt_extended` by AST in `tests/test_api_cookies.py` — the standing
method rule, because WP-2.6 found 97 infidelities in values that looked
correctly copied. The one deliberate difference is the cookie NAME: v3
runs beside v1 on one host, and two cookies with one name are two cookies
nobody can tell apart.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Mapping, Optional

from v3.api.vocabulary import API_PREFIX
from v3.kernel.errors import DomainError

#: `radar/auth.py:227` (`JWT_COOKIE_SAMESITE`). The closed set is the
#: browser's, not ours.
SAME_SITE_VALUES: frozenset = frozenset({"Strict", "Lax", "None"})

#: `radar/auth.py:252` (`JWT_REFRESH_CSRF_HEADER_NAME`). The SPA echoes the
#: readable companion cookie here; the access token needs no such thing
#: because it rides in `Authorization`, which a cross-site form cannot set.
CSRF_HEADER = "X-CSRF-TOKEN"


@dataclass(frozen=True, slots=True)
class CookieSpec:
    """One cookie's posture. Declared once; never spelled at a call site."""

    name: str
    path: str
    http_only: bool
    same_site: str
    secure: bool = True
    #: `None` is a SESSION cookie — no `Max-Age`, gone when the browser
    #: closes. That is production's effective posture: it leaves
    #: `JWT_SESSION_COOKIE` at the library default (`True`), which makes
    #: `cookie_max_age` `None`. Spelled out because a default nobody wrote
    #: down is the kind of value a transcription silently changes.
    max_age: Optional[int] = None
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise DomainError("a cookie needs a name")
        if not isinstance(self.path, str) or not self.path.startswith("/"):
            raise DomainError(
                f"a cookie's path must be absolute, got {self.path!r}: the "
                f"path is what stops the browser sending a credential on "
                f"every request")
        if self.same_site not in SAME_SITE_VALUES:
            raise DomainError(
                f"unknown SameSite {self.same_site!r}; the browser accepts "
                f"{sorted(SAME_SITE_VALUES)}")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise DomainError(
                f"cookie {self.name!r} must state why it exists: a credential "
                f"in a header nobody explained is a credential nobody audits")

    def as_dict(self) -> dict:
        return {"name": self.name, "path": self.path,
                "http_only": self.http_only, "same_site": self.same_site,
                "secure": self.secure, "max_age": self.max_age,
                "reason": self.reason}


#: The refresh token's transport. httpOnly so no script can read it,
#: SameSite=Strict so no cross-site navigation carries it, and scoped to
#: the refresh route's own path so it is not attached to every request.
#: `radar/auth.py:224-227` is the same posture at production's path.
REFRESH_COOKIE = CookieSpec(
    name="noroshi_v3_refresh",
    path=f"{API_PREFIX}/auth/refresh",
    http_only=True,
    same_site="Strict",
    secure=True,
    max_age=None,
    reason=("refresh token の輸送。本文に載せることは S1-SVC-004 / "
            "S2-API-010 が MUST NOT とする（S1-UI-002 は CORE 判定）"))

#: The readable companion. NOT httpOnly and NOT path-scoped, both on
#: purpose: the SPA has to read it from a page at `/` and echo it back.
#: Production gets the same shape by leaving `JWT_REFRESH_CSRF_COOKIE_PATH`
#: at the library default.
CSRF_COOKIE = CookieSpec(
    name="noroshi_v3_csrf_refresh",
    path="/",
    http_only=False,
    same_site="Strict",
    secure=True,
    max_age=None,
    reason=("対 CSRF の対トークン。SPA が読んで X-CSRF-TOKEN へ返す "
            "— httpOnly cookie だけでは CSRF を防げないため"))

COOKIES: tuple[CookieSpec, ...] = (REFRESH_COOKIE, CSRF_COOKIE)


@dataclass(frozen=True, slots=True)
class SetCookie:
    """"Send this cookie." A value, not a header."""

    spec: CookieSpec
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.spec, CookieSpec):
            raise DomainError("a directive carries a CookieSpec")
        if not isinstance(self.value, str) or not self.value:
            raise DomainError(
                f"cookie {self.spec.name!r} would be set to an empty value; "
                f"clearing is `ClearCookie`, which says so")


@dataclass(frozen=True, slots=True)
class ClearCookie:
    """"Delete this cookie." Distinct from setting it to nothing."""

    spec: CookieSpec

    def __post_init__(self) -> None:
        if not isinstance(self.spec, CookieSpec):
            raise DomainError("a directive carries a CookieSpec")


DIRECTIVES = (SetCookie, ClearCookie)


@dataclass(frozen=True, slots=True)
class CookiePolicy:
    """What a route does with cookies. Declared in the route table.

    `presents` and `csrf` are ONE decision, enforced here: a route that
    accepts a credential from a cookie cannot be declared without the CSRF
    companion. That is the whole point — the alternative is a check inside
    a handler, and G-01 is what happens to checks inside handlers.
    """

    presents: tuple[CookieSpec, ...] = ()
    emits: tuple[CookieSpec, ...] = ()
    csrf: bool = False
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "presents", tuple(self.presents))
        object.__setattr__(self, "emits", tuple(self.emits))
        touches = bool(self.presents or self.emits or self.csrf)
        if touches and not (isinstance(self.reason, str)
                            and self.reason.strip()):
            raise DomainError(
                "a cookie policy states why the route touches a cookie")
        if self.presents and not self.csrf:
            raise DomainError(
                "a route that accepts a credential from a cookie must "
                "require the CSRF companion. The browser attaches a cookie "
                "to a cross-site request whether or not the caller meant it, "
                "so the header is the part that proves intent — and a check "
                "a handler performs is a check a handler can be written "
                "without (G-01).")
        if self.csrf and not self.presents:
            raise DomainError(
                "a CSRF requirement with no cookie-borne credential guards "
                "nothing: the access token rides in Authorization, which a "
                "cross-site form cannot set")

    @property
    def touches_cookies(self) -> bool:
        return bool(self.presents or self.emits)

    def as_dict(self) -> dict:
        return {"presents": [spec.name for spec in self.presents],
                "emits": [spec.name for spec in self.emits],
                "csrf": self.csrf, "reason": self.reason}


#: The overwhelming majority. A default is safe here precisely because the
#: two forgettable mistakes have no spelling: `presents` without `csrf` is
#: refused at construction, and emitting an undeclared cookie is refused by
#: `check_emissions` on the way out.
NO_COOKIES = CookiePolicy()


@dataclass(frozen=True, slots=True)
class PresentedCookies:
    """What the transport actually carried in, filtered by the declaration.

    A route sees only the cookies its policy names, so a handler cannot
    reach a credential the table did not admit — and `csrf_token` is only
    ever the value the dispatcher already matched against the companion
    cookie.
    """

    values: Mapping[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.values, Mapping):
            raise DomainError("presented cookies are a mapping")
        object.__setattr__(self, "values",
                           {str(k): str(v) for k, v in self.values.items()})

    def value(self, spec: CookieSpec) -> Optional[str]:
        if not isinstance(spec, CookieSpec):
            raise DomainError("ask for a declared CookieSpec, not a string")
        return self.values.get(spec.name)


NONE_PRESENTED = PresentedCookies()


def csrf_matches(presented: Optional[str], companion: Optional[str]) -> bool:
    """Double submit, compared without leaking length by timing."""
    if not presented or not companion:
        return False
    return hmac.compare_digest(str(presented), str(companion))


def admit(policy: CookiePolicy, cookies: Mapping[str, str],
          csrf_header: Optional[str]) -> PresentedCookies:
    """The declared cookies only. Everything else is dropped here."""
    if not policy.presents:
        return NONE_PRESENTED
    declared = {spec.name for spec in policy.presents}
    return PresentedCookies(
        values={name: value for name, value in (cookies or {}).items()
                if name in declared},
        csrf_token=csrf_header if policy.csrf else None)


def check_emissions(policy: CookiePolicy, directives) -> None:
    """A route may only emit what the table said it emits."""
    declared = {spec.name for spec in policy.emits}
    for directive in directives or ():
        if not isinstance(directive, DIRECTIVES):
            raise DomainError(
                f"a response's cookie directives are SetCookie or "
                f"ClearCookie, got {type(directive).__name__}")
        if directive.spec.name not in declared:
            raise DomainError(
                f"this route emits cookie {directive.spec.name!r} but its "
                f"CookiePolicy declares {sorted(declared)}. A cookie set "
                f"outside the table is a credential no reviewer of the route "
                f"table can see.")


__all__ = ["CSRF_HEADER", "SAME_SITE_VALUES", "CookieSpec", "REFRESH_COOKIE",
           "CSRF_COOKIE", "COOKIES", "SetCookie", "ClearCookie", "DIRECTIVES",
           "CookiePolicy", "NO_COOKIES", "PresentedCookies", "NONE_PRESENTED",
           "admit", "check_emissions", "csrf_matches"]
