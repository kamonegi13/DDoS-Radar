"""Password derivation and verification. Production's semantics, exactly.

S1-SVC-001 is a dual scheme and it is not decoration: argon2id is what
every new credential gets, PBKDF2-HMAC-SHA256 at 100,000 iterations is
what an environment without argon2 falls back to (NP3 — the tool starts
either way), and verification discriminates on the stored form rather
than on a column, because a credential that outlives its algorithm is the
normal case.

Three properties are asserted by the suite rather than left to review:

* **a malformed credential is `False`, never an exception.** An exception
  here reaches the login path, and a login that 500s tells an attacker
  that this username exists.
* **the comparison is constant time.** `hmac.compare_digest` for the
  PBKDF2 branch; argon2-cffi's `verify` for the other.
* **the derived value is not the password.** Trivially true, and tested,
  because the whole reason this module exists is that the plaintext must
  not survive the call.

The minimum length is 12 and there is nothing else: no character classes,
no dictionary, no reuse ban. That is production's rule (`radar/auth.py`
:414, :659, :686) and inventing a stricter one here would make a v3
password refuse to be set on the system it is being compared against.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any, Mapping, Optional

from v3.kernel.errors import DomainError

#: `radar/auth.py:414` — the literal, transcribed rather than relaxed.
MIN_PASSWORD_LENGTH = 12
#: `radar/auth.py:79-81`.
PBKDF2_ITERATIONS = 100_000
PBKDF2_SALT_BYTES = 16
ARGON2_PREFIX = "$argon2"

ALGORITHM_ARGON2 = "argon2id"
ALGORITHM_PBKDF2 = "pbkdf2-sha256"
ALGORITHMS: frozenset = frozenset({ALGORITHM_ARGON2, ALGORITHM_PBKDF2})

#: The fields a stored credential carries. `salt` is empty for argon2,
#: whose PHC string embeds its own — kept as a field anyway so the two
#: forms have one shape and the fold does not branch on presence.
CREDENTIAL_FIELDS: tuple[str, ...] = ("algorithm", "hash", "salt", "set_at")


def _hasher():
    """argon2-cffi's default `PasswordHasher`, or None.

    Default parameters on purpose: production instantiates the same class
    with no arguments (`radar/auth.py:94`), and a v3 credential derived
    with different cost parameters would not verify against the same
    password on the system this is being compared with.
    """
    try:
        from argon2 import PasswordHasher
    except Exception:
        return None
    try:
        return PasswordHasher()
    except Exception:
        return None


def argon2_available() -> bool:
    return _hasher() is not None


def validate(password: Any) -> str:
    """The one length rule, applied at every entry point."""
    if not isinstance(password, str):
        raise DomainError(
            f"パスワードは文字列です: {type(password).__name__}")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise DomainError(
            f"パスワードは {MIN_PASSWORD_LENGTH} 文字以上が必要です"
            f"（現行系と同一の規則）")
    return password


def _pbkdf2(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"),
        PBKDF2_ITERATIONS).hex()


def derive(password: str, *, salt: Optional[str] = None,
           prefer_argon2: bool = True, at: Optional[float] = None) -> dict:
    """A stored credential from a plaintext. Never the other direction."""
    validate(password)
    hasher = _hasher() if prefer_argon2 else None
    if hasher is not None:
        return {"algorithm": ALGORITHM_ARGON2, "hash": hasher.hash(password),
                "salt": "", "set_at": at}
    material = secrets.token_hex(PBKDF2_SALT_BYTES) if salt is None else salt
    return {"algorithm": ALGORITHM_PBKDF2,
            "hash": _pbkdf2(password, material), "salt": material,
            "set_at": at}


def is_argon2(stored_hash: Any) -> bool:
    return isinstance(stored_hash, str) and stored_hash.startswith(
        ARGON2_PREFIX)


def verify(credential: Any, password: Any) -> bool:
    """`True` only for a match. Every other outcome is `False`.

    Including a credential that is `None`, a hash that is empty, an
    algorithm nobody recognises, and an argon2 hash on a host without
    argon2 (S1-SVC-001's last clause). Each of those is a reason to refuse
    the login, and none of them is a reason to raise into it.
    """
    if not isinstance(credential, Mapping) or not isinstance(password, str):
        return False
    stored = credential.get("hash")
    if not isinstance(stored, str) or not stored:
        return False
    if is_argon2(stored):
        hasher = _hasher()
        if hasher is None:
            return False
        try:
            return bool(hasher.verify(stored, password))
        except Exception:
            return False
    if credential.get("algorithm") != ALGORITHM_PBKDF2:
        return False
    salt = credential.get("salt")
    if not isinstance(salt, str) or not salt:
        return False
    try:
        return hmac.compare_digest(_pbkdf2(password, salt), stored)
    except Exception:
        return False


def needs_upgrade(credential: Any) -> bool:
    """A stored PBKDF2 credential on a host that can do argon2.

    Production re-derives it during login (`radar/auth.py:469-477`). v3
    does not, and the reason is structural rather than an oversight: v3's
    login route writes no ledger row (it holds a `ReadContext`), so an
    upgrade there would be a write from a read path — defect A-01's shape.
    The fact is served instead, so an operator can act on it (§7-2 #101).
    """
    if not isinstance(credential, Mapping):
        return False
    return (credential.get("algorithm") == ALGORITHM_PBKDF2
            and argon2_available())


__all__ = ["MIN_PASSWORD_LENGTH", "PBKDF2_ITERATIONS", "ARGON2_PREFIX",
           "ALGORITHM_ARGON2", "ALGORITHM_PBKDF2", "ALGORITHMS",
           "CREDENTIAL_FIELDS", "argon2_available", "validate", "derive",
           "verify", "is_argon2", "needs_upgrade"]
