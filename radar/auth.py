"""radar.auth -- JWT authentication and user management.

Provides user registration, login, and per-user theater settings.
Uses SQLite (via radar.database) for user storage.
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

# ── JWT Setup ────────────────────────────────────────────────────────────────
jwt = JWTManager()

# Schema for user tables
_USER_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt        TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'viewer',
    created_at  REAL NOT NULL,
    last_login  REAL
);

CREATE TABLE IF NOT EXISTS user_settings (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id),
    core        TEXT NOT NULL DEFAULT 'TW',
    pins        TEXT NOT NULL DEFAULT '[]',
    correlates  TEXT NOT NULL DEFAULT '[]',
    adversaries TEXT NOT NULL DEFAULT '[]',
    muted       TEXT NOT NULL DEFAULT '[]',
    lang        TEXT NOT NULL DEFAULT 'en',
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    revoked_at  REAL NOT NULL
);
"""


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()


def init_auth(app):
    """Initialize JWT and create user tables."""
    app.config["JWT_SECRET_KEY"] = os.getenv(
        "JWT_SECRET_KEY", secrets.token_hex(32)
    )
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = int(os.getenv("JWT_ACCESS_EXPIRES", "3600"))
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = int(os.getenv("JWT_REFRESH_EXPIRES", "86400"))

    jwt.init_app(app)

    # Create user tables
    from radar.database import db
    conn = db._get_conn()
    conn.executescript(_USER_SCHEMA_SQL)
    conn.commit()

    # Create default admin if no users exist
    row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
    if row[0] == 0:
        _create_default_admin(conn)

    # Token revocation check
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        from radar.database import db as _db
        row = _db._get_conn().execute(
            "SELECT 1 FROM revoked_tokens WHERE jti=?", (jti,)
        ).fetchone()
        return row is not None


def _create_default_admin(conn):
    """Create a default admin user on first run."""
    default_pw = os.getenv("DEFAULT_ADMIN_PASSWORD", "admin")
    salt = secrets.token_hex(16)
    pw_hash = _hash_password(default_pw, salt)
    now = time.time()
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        ("admin", pw_hash, salt, "admin", now),
    )
    user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    from radar.config import DEFAULT_CORE, DEFAULT_PINS, DEFAULT_CORRELATES, DEFAULT_ADVERSARIES
    conn.execute(
        "INSERT INTO user_settings (user_id, core, pins, correlates, adversaries, muted, lang, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, DEFAULT_CORE, json.dumps(DEFAULT_PINS),
         json.dumps(DEFAULT_CORRELATES), json.dumps(DEFAULT_ADVERSARIES),
         "[]", "en", now),
    )
    conn.commit()
    log.info("[Auth] Created default admin user (username: admin)")


def require_role(*roles):
    """Decorator: require user to have one of the specified roles."""
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorated(*args, **kwargs):
            identity = get_jwt_identity()
            from radar.database import db
            row = db._get_conn().execute(
                "SELECT role FROM users WHERE username=?", (identity,)
            ).fetchone()
            if not row or row[0] not in roles:
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
    caller_row = db._get_conn().execute(
        "SELECT role FROM users WHERE username=?", (caller,)
    ).fetchone()
    if not caller_row or caller_row[0] != "admin":
        return jsonify({"error": "Admin only"}), 403

    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "viewer")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "Invalid role"}), 400

    conn = db._get_conn()
    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        return jsonify({"error": "Username already exists"}), 409

    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)
    now = time.time()
    conn.execute(
        "INSERT INTO users (username, password_hash, salt, role, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, salt, role, now),
    )
    user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    from radar.config import DEFAULT_CORE, DEFAULT_PINS, DEFAULT_CORRELATES, DEFAULT_ADVERSARIES
    conn.execute(
        "INSERT INTO user_settings (user_id, core, pins, correlates, adversaries, muted, lang, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, DEFAULT_CORE, json.dumps(DEFAULT_PINS),
         json.dumps(DEFAULT_CORRELATES), json.dumps(DEFAULT_ADVERSARIES),
         "[]", "en", now),
    )
    conn.commit()
    return jsonify({"status": "ok", "username": username, "role": role}), 201


@bp.route("/login", methods=["POST"])
def login():
    """Authenticate and return JWT tokens."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    from radar.database import db
    conn = db._get_conn()
    row = conn.execute(
        "SELECT id, password_hash, salt, role FROM users WHERE username=?",
        (username,),
    ).fetchone()
    if not row:
        return jsonify({"error": "Invalid credentials"}), 401

    if _hash_password(password, row["salt"]) != row["password_hash"]:
        return jsonify({"error": "Invalid credentials"}), 401

    # Update last_login
    conn.execute("UPDATE users SET last_login=? WHERE id=?", (time.time(), row["id"]))
    conn.commit()

    access_token = create_access_token(identity=username, additional_claims={"role": row["role"]})
    refresh_token = create_refresh_token(identity=username)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "username": username,
        "role": row["role"],
    })


@bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Get a new access token using refresh token."""
    identity = get_jwt_identity()
    from radar.database import db
    row = db._get_conn().execute(
        "SELECT role FROM users WHERE username=?", (identity,)
    ).fetchone()
    role = row["role"] if row else "viewer"
    access_token = create_access_token(identity=identity, additional_claims={"role": role})
    return jsonify({"access_token": access_token})


@bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """Revoke current access token."""
    jti = get_jwt()["jti"]
    from radar.database import db
    db._get_conn().execute(
        "INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)",
        (jti, time.time()),
    )
    db._get_conn().commit()
    return jsonify({"status": "ok"})


@bp.route("/settings", methods=["GET"])
@jwt_required()
def get_settings():
    """Get current user's theater settings."""
    identity = get_jwt_identity()
    from radar.database import db
    conn = db._get_conn()
    row = conn.execute(
        "SELECT us.core, us.pins, us.correlates, us.adversaries, us.muted, us.lang "
        "FROM user_settings us JOIN users u ON us.user_id = u.id "
        "WHERE u.username=?",
        (identity,),
    ).fetchone()
    if not row:
        return jsonify({"error": "Settings not found"}), 404
    return jsonify({
        "core": row["core"],
        "pins": json.loads(row["pins"]),
        "correlates": json.loads(row["correlates"]),
        "adversaries": json.loads(row["adversaries"]),
        "muted": json.loads(row["muted"]),
        "lang": row["lang"],
    })


@bp.route("/settings", methods=["PUT"])
@jwt_required()
def update_settings():
    """Update current user's theater settings."""
    identity = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    from radar.database import db
    conn = db._get_conn()
    user_row = conn.execute("SELECT id FROM users WHERE username=?", (identity,)).fetchone()
    if not user_row:
        return jsonify({"error": "User not found"}), 404

    # Build SET clause from provided fields
    allowed = {"core": str, "pins": list, "correlates": list,
               "adversaries": list, "muted": list, "lang": str}
    updates = {}
    for field, expected_type in allowed.items():
        if field in data:
            val = data[field]
            if expected_type == list:
                if not isinstance(val, list):
                    return jsonify({"error": f"{field} must be a list"}), 400
                updates[field] = json.dumps(val)
            else:
                updates[field] = str(val)

    if not updates:
        return jsonify({"error": "No valid fields provided"}), 400

    updates["updated_at"] = time.time()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    conn.execute(
        f"UPDATE user_settings SET {set_clause} WHERE user_id=?",
        (*updates.values(), user_row["id"]),
    )
    conn.commit()
    return jsonify({"status": "ok"})


@bp.route("/users", methods=["GET"])
@jwt_required()
def list_users():
    """List all users (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    caller_row = db._get_conn().execute(
        "SELECT role FROM users WHERE username=?", (caller,)
    ).fetchone()
    if not caller_row or caller_row[0] != "admin":
        return jsonify({"error": "Admin only"}), 403

    rows = db._get_conn().execute(
        "SELECT username, role, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    return jsonify([
        {"username": r["username"], "role": r["role"],
         "created_at": r["created_at"], "last_login": r["last_login"]}
        for r in rows
    ])


@bp.route("/users/<username>/role", methods=["PUT"])
@jwt_required()
def update_user_role(username):
    """Update a user's role (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    conn = db._get_conn()
    caller_row = conn.execute(
        "SELECT role FROM users WHERE username=?", (caller,)
    ).fetchone()
    if not caller_row or caller_row[0] != "admin":
        return jsonify({"error": "Admin only"}), 403

    if username == caller:
        return jsonify({"error": "Cannot change own role"}), 400

    data = request.get_json(silent=True) or {}
    new_role = data.get("role", "")
    if new_role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "Invalid role"}), 400

    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404

    conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, row["id"]))
    conn.commit()
    log.info(f"[Auth] Role updated: {username} → {new_role} (by {caller})")
    return jsonify({"status": "ok", "username": username, "role": new_role})


@bp.route("/users/<username>", methods=["DELETE"])
@jwt_required()
def delete_user(username):
    """Delete a user (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    conn = db._get_conn()
    caller_row = conn.execute(
        "SELECT role FROM users WHERE username=?", (caller,)
    ).fetchone()
    if not caller_row or caller_row[0] != "admin":
        return jsonify({"error": "Admin only"}), 403

    if username == caller:
        return jsonify({"error": "Cannot delete own account"}), 400

    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404

    conn.execute("DELETE FROM user_settings WHERE user_id=?", (row["id"],))
    conn.execute("DELETE FROM users WHERE id=?", (row["id"],))
    conn.commit()
    log.info(f"[Auth] User deleted: {username} (by {caller})")
    return jsonify({"status": "ok"})


@bp.route("/users/<username>/reset-password", methods=["POST"])
@jwt_required()
def admin_reset_password(username):
    """Reset a user's password (admin only)."""
    caller = get_jwt_identity()
    from radar.database import db
    conn = db._get_conn()
    caller_row = conn.execute(
        "SELECT role FROM users WHERE username=?", (caller,)
    ).fetchone()
    if not caller_row or caller_row[0] != "admin":
        return jsonify({"error": "Admin only"}), 403

    data = request.get_json(silent=True) or {}
    new_pw = data.get("new_password", "")
    if not new_pw or len(new_pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404

    new_salt = secrets.token_hex(16)
    new_hash = _hash_password(new_pw, new_salt)
    conn.execute(
        "UPDATE users SET password_hash=?, salt=? WHERE id=?",
        (new_hash, new_salt, row["id"]),
    )
    conn.commit()
    log.info(f"[Auth] Password reset: {username} (by {caller})")
    return jsonify({"status": "ok"})


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
    if len(new_pw) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    from radar.database import db
    conn = db._get_conn()
    row = conn.execute(
        "SELECT id, password_hash, salt FROM users WHERE username=?", (identity,)
    ).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404
    if _hash_password(old_pw, row["salt"]) != row["password_hash"]:
        return jsonify({"error": "Invalid current password"}), 401

    new_salt = secrets.token_hex(16)
    new_hash = _hash_password(new_pw, new_salt)
    conn.execute(
        "UPDATE users SET password_hash=?, salt=? WHERE id=?",
        (new_hash, new_salt, row["id"]),
    )
    conn.commit()
    return jsonify({"status": "ok"})
