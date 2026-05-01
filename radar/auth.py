"""radar.auth -- JWT authentication and user management.

Provides user registration, login, and per-user theater settings.
Uses RadarDB public methods for all database operations.
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import secrets
import time
from functools import wraps
from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt,
)

log = logging.getLogger("radar")

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# ── Simple in-memory login rate limiter ──────────────────────────────────────
_login_attempts: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SEC = 300
_LOGIN_MAX_IPS = 1000

# Only trust X-Forwarded-For when explicitly enabled (behind a trusted reverse proxy).
# Without this guard, any client can spoof their IP via the XFF header.
_TRUST_XFF = os.getenv("TRUST_PROXY_XFF", "").lower() in ("1", "true", "yes")


def _get_client_ip() -> str:
    """Extract client IP.  Only reads X-Forwarded-For when TRUST_PROXY_XFF is enabled."""
    if _TRUST_XFF:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _check_login_rate(ip: str) -> bool:
    """Return False if rate limit exceeded."""
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < _LOGIN_WINDOW_SEC]
    _login_attempts[ip] = attempts
    # Evict oldest entries if dict exceeds max IPs to prevent memory exhaustion
    if len(_login_attempts) > _LOGIN_MAX_IPS:
        # Prune IPs with empty attempt lists first (already expired)
        empty_ips = [k for k, v in _login_attempts.items() if not v]
        if empty_ips:
            for k in empty_ips:
                _login_attempts.pop(k, None)
        else:
            oldest_ip = min(_login_attempts, key=lambda k: _login_attempts[k][-1])
            _login_attempts.pop(oldest_ip, None)
    return len(attempts) < _LOGIN_MAX_ATTEMPTS


def _record_login_attempt(ip: str):
    _login_attempts.setdefault(ip, []).append(time.time())

# ── JWT Setup ────────────────────────────────────────────────────────────────
jwt = JWTManager()


def _hash_password(password: str, salt: str) -> str:
    """Legacy PBKDF2-SHA256 hasher (100k iterations).

    Phase 7.5f (audit Security H2): retained for backward-compat with
    rows that have not yet been lazily rehashed to argon2id. See
    ``_hash_password_argon2`` and ``_verify_password`` below for the
    transitional contract.
    """
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()


# ── Argon2id transition (Phase 7.5f / audit Security H2) ─────────────────
# argon2-cffi's PasswordHasher is the production-recommended interface:
# it picks sane parameters (RFC 9106 second recommended set, m=64 MiB,
# t=3, p=4) and prepends them to the encoded hash so a future cost
# bump can re-derive without a schema migration. We reuse a single
# module-level instance — argon2.PasswordHasher is thread-safe and
# parameterless mutations carry through.
try:
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2.exceptions import VerifyMismatchError as _Argon2Mismatch
    _argon2 = _Argon2Hasher()
except ImportError:
    # NP3 — running without argon2-cffi keeps the legacy PBKDF2 path
    # working; the lazy rehash and new-account path simply fall back
    # to PBKDF2 with a warning rather than crashing the process.
    _argon2 = None
    _Argon2Mismatch = Exception  # type: ignore[assignment]
    log.warning("[Auth] argon2-cffi unavailable — using PBKDF2-SHA256 fallback. "
                "Install argon2-cffi to enable argon2id hashing.")


def _hash_password_argon2(password: str) -> str:
    """Return an argon2id-encoded hash. Falls back to PBKDF2 with a
    fresh hex-encoded salt (length 32) when argon2-cffi is missing.

    The encoded argon2 string starts with ``$argon2id$`` so
    ``_verify_password`` can identify the hash family at verify time.
    """
    if _argon2 is None:
        salt = secrets.token_hex(16)
        return _hash_password(password, salt)
    return _argon2.hash(password)


def _is_argon2_hash(stored_hash: str) -> bool:
    """Cheap discriminator. argon2 PHC strings always start with
    ``$argon2`` — PBKDF2 hashes in this codebase are bare hex strings."""
    return isinstance(stored_hash, str) and stored_hash.startswith("$argon2")


def _verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """Constant-time password verification with hash-format auto-detect.

    - argon2id hashes (PHC string starting ``$argon2``): the salt is
      embedded; ``stored_salt`` is ignored. argon2-cffi's verify is
      already constant-time.
    - PBKDF2 hashes (legacy): rederive with PBKDF2-SHA256 and the
      stored hex salt, compare with secrets.compare_digest.

    Returns True iff the password matches. Never raises on a wrong
    password — only on a malformed hash, which we treat as "wrong"
    rather than 500-ing.
    """
    if not stored_hash:
        return False
    if _is_argon2_hash(stored_hash):
        if _argon2 is None:
            # Hash exists but the library is gone — degrade safely.
            return False
        try:
            _argon2.verify(stored_hash, password)
            return True
        except _Argon2Mismatch:
            return False
        except Exception:
            return False
    return secrets.compare_digest(
        _hash_password(password, stored_salt), stored_hash
    )


def _get_or_create_jwt_secret() -> str:
    """Return JWT secret from env, or generate and persist to config.env on first run.
    Logs a critical warning if the secret had to be generated."""
    env_key = os.getenv("JWT_SECRET_KEY", "")
    if env_key:
        return env_key
    # Auto-generate on first run and persist
    generated = secrets.token_hex(32)
    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _config_path = os.path.join(_project_root, "config.env")
    persisted = False
    try:
        # Existence check: avoid appending duplicate JWT_SECRET_KEY entries
        # if config.env already contains one (python-dotenv would silently
        # take the last occurrence, but the duplication is confusing).
        already_present = False
        if os.path.exists(_config_path):
            with open(_config_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("JWT_SECRET_KEY=") and len(stripped) > len("JWT_SECRET_KEY="):
                        already_present = True
                        break
        if already_present:
            log.warning("[Auth] JWT_SECRET_KEY already exists in config.env; "
                        "skipping append to avoid duplicates. "
                        "Restart the process so dotenv reloads the existing value.")
            return generated  # ephemeral fallback; restart will pick up persisted value
        with open(_config_path, "a", encoding="utf-8") as f:
            f.write(f"\nJWT_SECRET_KEY={generated}\n")
        # Restrict file permissions to owner-only (ignored on Windows)
        try:
            os.chmod(_config_path, 0o600)
        except OSError:
            pass
        persisted = True
    except OSError as e:
        log.error("[Auth] CRITICAL: Could not persist JWT_SECRET_KEY to config.env: %s", e)
    if persisted:
        log.warning("[Auth] JWT_SECRET_KEY was not set. Generated and saved to config.env. "
                     "For production, set JWT_SECRET_KEY as an environment variable.")
    else:
        log.error("[Auth] JWT_SECRET_KEY is ephemeral (not persisted). "
                   "Tokens will be invalidated on restart. Set JWT_SECRET_KEY in environment.")
    return generated


def init_auth(app):
    """Initialize JWT and create default admin if no users exist."""
    app.config["JWT_SECRET_KEY"] = _get_or_create_jwt_secret()
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = int(os.getenv("JWT_ACCESS_EXPIRES", "3600"))
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = int(os.getenv("JWT_REFRESH_EXPIRES", "86400"))

    jwt.init_app(app)

    # Auth tables are now part of the main _SCHEMA_SQL (database.py).
    # Create default admin if no users exist.
    from radar.database import db
    if db.user_count() == 0:
        _create_default_admin(db)

    # Token revocation check — per-JTI revocation + per-user session invalidation
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        from radar.database import db as _db
        if _db.token_is_revoked(jwt_payload["jti"]):
            return True
        # Check if user's password was changed after this token was issued.
        # JWT iat is integer seconds, but invalidate_ts is float (sub-second).
        # Floor invalidate_ts to int so a token issued in the same wall-clock
        # second as the password change is honored (its iat == cutoff second is
        # logically "issued at the same time", not "issued before").
        invalidate_ts = _db.user_get_invalidate_ts(jwt_payload.get("sub", ""))
        if invalidate_ts is not None:
            token_iat = jwt_payload.get("iat", 0)
            if token_iat < int(invalidate_ts):
                return True
        return False


def _create_default_admin(db):
    """Create a default admin user on first run."""
    default_pw = os.getenv("DEFAULT_ADMIN_PASSWORD", "")
    if not default_pw:
        default_pw = secrets.token_urlsafe(16)
        # Avoid emitting the password through the structured logger; log
        # forwarders (ELK, Splunk, Datadog) commonly persist warnings with
        # long retention. Stdout is captured by the operator console only.
        import sys as _sys
        print("=" * 60, file=_sys.stdout, flush=True)
        print(f"[SECURITY] Generated temporary admin password: {default_pw}",
              file=_sys.stdout, flush=True)
        print("[SECURITY] Change this password immediately after first login.",
              file=_sys.stdout, flush=True)
        print("=" * 60, file=_sys.stdout, flush=True)
        log.warning("[Auth] No DEFAULT_ADMIN_PASSWORD set; "
                    "temporary admin password written to stdout. "
                    "Change immediately after first login.")
    # Phase 7.5f (audit Security H2): default admin uses argon2id.
    salt = secrets.token_hex(16)
    pw_hash = _hash_password_argon2(default_pw)
    now = time.time()
    user_id = db.user_create("admin", pw_hash, salt, "admin", now)
    db.user_settings_create(user_id, None, "[]", "en", now)
    log.info("[Auth] Created default admin user (username: admin)")


def require_role(*roles):
    """Decorator: require user to have one of the specified roles."""
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorated(*args, **kwargs):
            identity = get_jwt_identity()
            from radar.database import db
            role = db.user_get_role(identity)
            if not role or role not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper


# ── Routes ────────────────────────────────────────────────────────────────────

@bp.route("/register", methods=["POST"])
@jwt_required()
def register():
    """Register a new user (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    caller_role = db.user_get_role(caller)
    if caller_role != "admin":
        return jsonify({"error": "Admin only"}), 403

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "viewer")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if len(password) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400
    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "Invalid role"}), 400
    if db.user_exists(username):
        return jsonify({"error": "Username already exists"}), 409

    # Phase 7.5f (audit Security H2): new accounts are created with
    # argon2id directly. The schema still keeps a `salt` column for
    # backward compatibility with PBKDF2 rows; argon2id embeds its
    # salt in the PHC string, so we just store an unused random salt
    # to keep the column non-NULL.
    salt = secrets.token_hex(16)
    pw_hash = _hash_password_argon2(password)
    now = time.time()
    user_id = db.user_create(username, pw_hash, salt, role, now)
    db.user_settings_create(user_id, None, "[]", "en", now)
    return jsonify({"status": "ok", "username": username, "role": role}), 201


@bp.route("/login", methods=["POST"])
def login():
    """Authenticate and return JWT tokens."""
    ip = _get_client_ip()
    if not _check_login_rate(ip):
        return jsonify({"error": "Too many login attempts. Try again later."}), 429

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    from radar.database import db
    user = db.user_get(username)
    if not user:
        _record_login_attempt(ip)
        return jsonify({"error": "Invalid credentials"}), 401

    if not _verify_password(password, user["password_hash"], user["salt"]):
        _record_login_attempt(ip)
        return jsonify({"error": "Invalid credentials"}), 401

    # Reset attempt count on success but keep the IP entry for tracking
    _login_attempts[ip] = []
    db.user_update_last_login(user["id"], time.time())

    # Phase 7.5f (audit Security H2) — lazy rehash on successful login.
    # If the stored hash is still PBKDF2-SHA256 100k, transparently
    # upgrade it to argon2id. This means active users migrate over
    # the next login cycle; idle accounts retain their PBKDF2 hash
    # until they next log in (or are purged by a future idle-account
    # policy). Failure here must never block a successful login —
    # NP3 + the user has already authenticated successfully.
    if not _is_argon2_hash(user["password_hash"]) and _argon2 is not None:
        try:
            new_hash = _hash_password_argon2(password)
            new_salt = secrets.token_hex(16)  # unused for argon2 but keeps schema
            db.user_update_password(user["id"], new_hash, new_salt)
            log.info("[Auth] Lazy-rehashed user '%s' from PBKDF2 to argon2id", username)
        except Exception as exc:
            log.warning("[Auth] Lazy rehash failed for user '%s': %s",
                        username, exc)

    from flask import current_app
    access_token = create_access_token(identity=username, additional_claims={"role": user["role"]})
    refresh_token = create_refresh_token(identity=username)
    access_expires = current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES", 3600)
    if hasattr(access_expires, "total_seconds"):
        access_expires = int(access_expires.total_seconds())
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "username": username,
        "role": user["role"],
        "access_expires_sec": access_expires,
    })


@bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Get a new access token using refresh token."""
    identity = get_jwt_identity()
    from radar.database import db
    role = db.user_get_role(identity) or "viewer"
    access_token = create_access_token(identity=identity, additional_claims={"role": role})
    return jsonify({"access_token": access_token})


@bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """Revoke current access token and optionally the refresh token."""
    jti = get_jwt()["jti"]
    from radar.database import db
    db.token_revoke(jti, time.time())
    # Also revoke refresh token if the client provides its JTI
    body = request.get_json(silent=True) or {}
    refresh_jti = body.get("refresh_jti")
    if refresh_jti:
        db.token_revoke(refresh_jti, time.time())
    return jsonify({"status": "ok"})


@bp.route("/settings", methods=["GET"])
@jwt_required()
def get_settings():
    """Get current user's scenario-centric settings (ADR-005)."""
    identity = get_jwt_identity()
    from radar.database import db
    row = db.user_settings_get(identity)
    if not row:
        return jsonify({"error": "Settings not found"}), 404
    return jsonify({
        "focused_scenario": row["focused_scenario"],
        "muted": json.loads(row["muted"]),
        "lang": row["lang"],
    })


@bp.route("/settings", methods=["PUT"])
@jwt_required()
def update_settings():
    """Update current user's scenario-centric settings (ADR-005)."""
    identity = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    from radar.database import db
    user = db.user_get(identity)
    if not user:
        return jsonify({"error": "User not found"}), 404

    allowed = {"focused_scenario": str, "muted": list, "lang": str}
    updates = {}
    for field, expected_type in allowed.items():
        if field in data:
            val = data[field]
            if expected_type == list:
                if not isinstance(val, list):
                    return jsonify({"error": f"{field} must be a list"}), 400
                updates[field] = json.dumps(val)
            else:
                updates[field] = None if val is None else str(val)

    if not updates:
        return jsonify({"error": "No valid fields provided"}), 400

    updates["updated_at"] = time.time()
    db.user_settings_update(user["id"], updates)
    return jsonify({"status": "ok"})


@bp.route("/users", methods=["GET"])
@jwt_required()
def list_users():
    """List all users (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    if db.user_get_role(caller) != "admin":
        return jsonify({"error": "Admin only"}), 403
    users = db.user_list()
    return jsonify(users)


@bp.route("/users/<username>/role", methods=["PUT"])
@jwt_required()
def update_user_role(username):
    """Update a user's role (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    if db.user_get_role(caller) != "admin":
        return jsonify({"error": "Admin only"}), 403

    if username == caller:
        return jsonify({"error": "Cannot change own role"}), 400

    data = request.get_json(silent=True) or {}
    new_role = data.get("role", "")
    if new_role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "Invalid role"}), 400

    user = db.user_get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.user_update_role(user["id"], new_role)
    log.info(f"[Auth] Role updated: {username} → {new_role} (by {caller})")
    return jsonify({"status": "ok", "username": username, "role": new_role})


@bp.route("/users/<username>", methods=["DELETE"])
@jwt_required()
def delete_user(username):
    """Delete a user (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    if db.user_get_role(caller) != "admin":
        return jsonify({"error": "Admin only"}), 403

    if username == caller:
        return jsonify({"error": "Cannot delete own account"}), 400

    user = db.user_get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.user_delete(user["id"])
    log.info(f"[Auth] User deleted: {username} (by {caller})")
    return jsonify({"status": "ok"})


@bp.route("/users/<username>/reset-password", methods=["POST"])
@jwt_required()
def admin_reset_password(username):
    """Reset a user's password (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    if db.user_get_role(caller) != "admin":
        return jsonify({"error": "Admin only"}), 403

    data = request.get_json(silent=True) or {}
    new_pw = data.get("new_password", "")
    if not new_pw or len(new_pw) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400

    user = db.user_get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Phase 7.5f (audit Security H2): admin-driven resets emit argon2id.
    new_salt = secrets.token_hex(16)
    new_hash = _hash_password_argon2(new_pw)
    # user_update_password sets invalidate_tokens_before, revoking all of the
    # target user's sessions.  The admin's own session is unaffected.
    db.user_update_password(user["id"], new_hash, new_salt)
    log.info(f"[Auth] Password reset: {username} (by {caller})")
    return jsonify({"status": "ok", "note": "User should re-login with new password"})


@bp.route("/password", methods=["PUT"])
@jwt_required()
def change_password():
    """Change current user's password."""
    identity = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")
    if not old_pw or not new_pw:
        return jsonify({"error": "old_password and new_password required"}), 400
    if len(new_pw) < 12:
        return jsonify({"error": "Password must be at least 12 characters"}), 400

    from radar.database import db
    user = db.user_get(identity)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not _verify_password(old_pw, user["password_hash"], user["salt"]):
        return jsonify({"error": "Invalid current password"}), 401

    # Phase 7.5f (audit Security H2): emit argon2id on every password change.
    new_salt = secrets.token_hex(16)
    new_hash = _hash_password_argon2(new_pw)
    # user_update_password sets invalidate_tokens_before, which revokes all
    # existing sessions (access + refresh) for this user via the blocklist loader.
    db.user_update_password(user["id"], new_hash, new_salt)
    return jsonify({"status": "ok"})
