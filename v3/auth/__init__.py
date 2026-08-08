"""P7 C13 — identity, credentials and sessions.

Import is inert here as everywhere under `v3/`: this package defines
functions and value types and reads no environment, opens no socket and
holds no key. The composition root (`v3/runtime/auth.py`) is the only
place that obtains signing material, and it obtains it through
`v3/runtime/secrets.py` — the one module licensed to read the process
environment.
"""
from v3.auth.password import derive, validate, verify
from v3.auth.session import (AuthProvider, LoginGuard, SessionRefused,
                             SessionThrottled, login, principal_for, refresh)
from v3.auth.store import TARGET_USER, public_view, user_state, users
from v3.auth.tokens import Claims, TokenAuthority, TokenError

__all__ = ["AuthProvider", "Claims", "LoginGuard", "SessionRefused",
           "SessionThrottled", "TARGET_USER", "TokenAuthority", "TokenError",
           "derive", "login", "principal_for", "public_view", "refresh",
           "user_state", "users", "validate", "verify"]
