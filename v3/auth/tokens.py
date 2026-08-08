"""HS256 tokens, and the two facts that keep them out of production's way.

**v3 signs with its own key.** Not `JWT_SECRET_KEY` — that key belongs to
the running v1 process, which auto-generates it and auto-appends it to
`config.env` (`radar/auth.py:155-199`). Sharing it would make a v1 token
verify here and a v3 token verify there, and reading the file at all puts
a second process one bug away from rotating a secret whose rotation logs
every live analyst out. `v3.runtime.secrets.signing_key` reads
`NOROSHI_V3_JWT_SECRET` and nothing else, and this module never reads an
environment at all.

**Every token names its issuer, and a token without it is refused.** So
even if an operator sets both variables to the same string, a v1 token
still fails here: it carries no `iss`. The reverse direction is not this
module's to enforce, which is why the key ids are separate — belt and
braces, because "the operator will not do that" is not a control.

`TokenAuthority` holds key material, so it does two things a value object
would not normally do: its `__repr__` omits the key, and `as_dict()`
returns only the non-secret parameters. A secret that reaches a
declaration is the failure this program spent WP-4.1a preventing.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from v3.kernel.roles import ROLES
from v3.kernel.errors import DomainError

ISSUER = "noroshi-v3"
ALGORITHM = "HS256"

TYPE_ACCESS = "access"
TYPE_REFRESH = "refresh"
TOKEN_TYPES: frozenset = frozenset({TYPE_ACCESS, TYPE_REFRESH})

#: `radar/auth.py:205-206`, transcribed. Both are the production defaults;
#: v3 does not make them configurable, because O-18 group (a) is the set
#: of keys with a reader in the scoring path and a token lifetime is not
#: one of them.
ACCESS_TTL_SEC = 3600.0
REFRESH_TTL_SEC = 86400.0


class TokenError(DomainError):
    """A token that will not be honoured, and why — for the log, not the
    caller. The caller is told 401 and nothing else (S1-SVC-002's uniform
    answer applied to the session surface)."""


def _jwt():
    try:
        import jwt as pyjwt
    except Exception as exc:  # pragma: no cover - dependency is declared
        raise DomainError(
            "PyJWT is required for the v3 session surface; it ships with "
            "flask-jwt-extended (requirements.txt)") from exc
    return pyjwt


def revoked(claims: "Claims", *, not_before: Optional[float]) -> bool:
    """S1-SVC-006 (b), including its integer floor — in ONE place.

    Production compares `token.iat < int(invalidate_ts)`. The truncation
    is not incidental: comparing floats instead would revoke a token
    production would honour (or the reverse) within one second of a
    password change, which is a difference nobody could reproduce.

    It lives here rather than inside `verify` because the floor is a fact
    about the USER, which the caller can only look up after the token has
    been decoded. A `not_before` parameter on `verify` would therefore be
    a parameter no caller could fill — a knob with no reader, which is the
    shape this programme refuses everywhere else.
    """
    if not_before is None:
        return False
    return claims.issued_at < int(float(not_before))


def encode(claims: Mapping[str, Any], *, key: str) -> str:
    """Sign an arbitrary claim set. Exposed for the suite's negative cases
    (a token with no issuer, a token signed by a stranger) — production
    paths go through `TokenAuthority.issue`, which cannot omit a claim."""
    return _jwt().encode(dict(claims), key, algorithm=ALGORITHM)


@dataclass(frozen=True, slots=True)
class Claims:
    """One verified token. Every field came from the signature's scope."""

    subject: str
    role: str
    token_type: str
    issued_at: float
    expires_at: float
    jti: str
    issuer: str
    #: The CSRF companion, on REFRESH tokens only. Empty on an access
    #: token, because an access token rides in `Authorization` — a header a
    #: cross-site form cannot set — so a CSRF value there would be a
    #: control with no reader.
    csrf: str = ""

    def as_dict(self) -> dict:
        """Deliberately WITHOUT `csrf`: it is a credential, and this dict
        is what a diagnostic prints."""
        return {"subject": self.subject, "role": self.role,
                "token_type": self.token_type, "issued_at": self.issued_at,
                "expires_at": self.expires_at, "jti": self.jti,
                "issuer": self.issuer}


@dataclass(frozen=True, slots=True)
class TokenAuthority:
    """The signer. Holds key material and discloses none of it."""

    key: str
    access_ttl_sec: float = ACCESS_TTL_SEC
    refresh_ttl_sec: float = REFRESH_TTL_SEC
    issuer: str = ISSUER

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or len(self.key.strip()) < 32:
            raise DomainError(
                "an HS256 signing key must be at least 32 bytes (RFC 7518 "
                "§3.2); a shorter one weakens the signature below the hash "
                "it is used with. v3 does not "
                "generate one: production generates and PERSISTS its key, "
                "and a second generator racing that file would invalidate "
                "every live session (ops record, 2026-08-07).")
        for name in ("access_ttl_sec", "refresh_ttl_sec"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or value <= 0:
                raise DomainError(f"{name} must be a positive number")
            # Normalised HERE so no reader has to coerce. The discipline
            # gate refuses `float(<attribute>)` anywhere in v3 — calibration
            # incident #2 was a ThreatLevel silently coerced to a number —
            # and the right answer to a gate like that is to make the field
            # already be what every reader needs.
            object.__setattr__(self, name, float(value))

    def __repr__(self) -> str:
        return (f"TokenAuthority<{self.issuer}, access="
                f"{self.access_ttl_sec}s, refresh={self.refresh_ttl_sec}s>")

    def as_dict(self) -> dict:
        """The disclosure. Key ids and lifetimes; never the material."""
        return {"issuer": self.issuer, "algorithm": ALGORITHM,
                "access_ttl_sec": self.access_ttl_sec,
                "refresh_ttl_sec": self.refresh_ttl_sec,
                "key_fingerprint": hashlib.sha256(
                    self.key.encode("utf-8")).hexdigest()[:12]}

    def csrf_for(self, jti: str) -> str:
        """The CSRF companion for a refresh token, derived from the key.

        Production draws it from `secrets.token_hex(16)`
        (flask-jwt-extended's `_create_csrf_token`). v3 derives it instead,
        for the same reason `jti` is derived: `issue` is a function of its
        arguments, so a replayed decision trail rebuilds the same session
        identifiers (NP6). Unguessability is not lost — the value is an
        HMAC under the signing key, which the cross-site attacker does not
        have — and it is the SAME value that travels inside the signed
        token, so the pair cannot be forged by anyone who can only write
        cookies.
        """
        return hmac.new(self.key.encode("utf-8"),
                        f"csrf\x1f{jti}".encode("utf-8"),
                        hashlib.sha256).hexdigest()[:32]

    def ttl_for(self, token_type: str) -> float:
        if token_type == TYPE_ACCESS:
            return self.access_ttl_sec
        if token_type == TYPE_REFRESH:
            return self.refresh_ttl_sec
        raise DomainError(f"unknown token type {token_type!r}")

    def issue(self, *, user_id: str, role: str, token_type: str,
              now: float) -> str:
        if token_type not in TOKEN_TYPES:
            raise DomainError(f"unknown token type {token_type!r}")
        if role not in ROLES:
            raise DomainError(
                f"unknown role {role!r}: a token is the primary source of "
                f"the role (S1-SVC-011 の v3 規範), so an unvetted string "
                f"here would be a privilege nobody declared")
        issued = float(now)
        expires = issued + self.ttl_for(token_type)
        # Deterministic jti: the same subject, type and instant produce the
        # same id, so a replay of the log rebuilds the same session
        # identifiers (NP6). Randomness would make the trail unreproducible.
        material = f"{self.issuer}\x1f{user_id}\x1f{token_type}\x1f{issued:.6f}"
        jti = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
        claims = {"iss": self.issuer, "sub": str(user_id), "role": role,
                  "typ": token_type, "jti": jti,
                  "iat": int(issued), "exp": int(expires)}
        if token_type == TYPE_REFRESH:
            # Inside the signature, exactly as production carries it: the
            # header the SPA echoes is checked against THIS, not merely
            # against a second cookie, so an attacker who can plant cookies
            # still cannot present a pair that belongs to a live token.
            claims["csrf"] = self.csrf_for(jti)
        return encode(claims, key=self.key)

    def verify(self, token: Any, *, expected_type: str,
               now: float) -> Claims:
        """Decode, then check the four things a signature does not say."""
        if expected_type not in TOKEN_TYPES:
            raise DomainError(f"unknown token type {expected_type!r}")
        if not isinstance(token, str) or not token.strip():
            raise TokenError("トークンがありません")
        pyjwt = _jwt()
        try:
            payload = pyjwt.decode(
                token, self.key, algorithms=[ALGORITHM], issuer=self.issuer,
                # The library's own clock is turned OFF and the expiry is
                # checked below against the `now` the composition root
                # passed in. A token layer that read the wall clock would
                # be the one place in v3 whose answer is not a function of
                # its inputs — and it would make every replay of the
                # decision trail depend on when the replay was run.
                options={"require": ["exp", "iat", "iss", "sub"],
                         "verify_exp": False, "verify_iat": False,
                         "verify_nbf": False})
        except Exception as exc:
            raise TokenError(f"トークンを検証できません: {exc}") from None
        if payload.get("typ") != expected_type:
            raise TokenError(
                f"token type {payload.get('typ')!r} presented where "
                f"{expected_type!r} is required")
        role = payload.get("role")
        if role not in ROLES:
            raise TokenError(f"token carries an unknown role {role!r}")
        issued_at = float(payload["iat"])
        expires_at = float(payload["exp"])
        if float(now) >= expires_at:
            raise TokenError("トークンの有効期限が切れています")
        return Claims(subject=str(payload["sub"]), role=role,
                      token_type=expected_type, issued_at=issued_at,
                      expires_at=expires_at, jti=str(payload.get("jti", "")),
                      issuer=str(payload["iss"]),
                      csrf=str(payload.get("csrf", "")))


__all__ = ["ISSUER", "ALGORITHM", "TYPE_ACCESS", "TYPE_REFRESH",
           "TOKEN_TYPES", "ACCESS_TTL_SEC", "REFRESH_TTL_SEC", "Claims",
           "TokenAuthority", "TokenError", "encode", "revoked"]
