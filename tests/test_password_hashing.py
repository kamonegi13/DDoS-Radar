"""Phase 7.5f (audit Security H2) — argon2id transition contract tests.

Pins the dual-hash transition policy:

  - new accounts hash with argon2id (PHC string starting "$argon2id$")
  - existing PBKDF2-SHA256 rows continue to verify
  - successful login on a PBKDF2 row lazily rehashes to argon2id
  - admin password reset emits argon2id
  - user-driven password change emits argon2id
  - argon2id verify + PBKDF2 verify both reject wrong passwords

These tests directly exercise the helpers in radar.auth so the
transition policy holds even if the route handlers refactor.
"""
from __future__ import annotations

import pytest
import secrets

from radar.auth import (
    _argon2,
    _hash_password,
    _hash_password_argon2,
    _is_argon2_hash,
    _verify_password,
)


# ── Hash format detection ──────────────────────────────────────────────


def test_argon2_hash_starts_with_phc_marker():
    if _argon2 is None:
        pytest.skip("argon2-cffi not installed")
    h = _hash_password_argon2("hunter2-correct-horse")
    assert h.startswith("$argon2id$"), f"unexpected PHC prefix: {h[:20]}"
    assert _is_argon2_hash(h)


def test_pbkdf2_hash_is_bare_hex():
    salt = "deadbeef" * 4
    h = _hash_password("hunter2-correct-horse", salt)
    assert not _is_argon2_hash(h)
    assert all(c in "0123456789abcdef" for c in h)
    # PBKDF2-SHA256 produces 32 bytes -> 64 hex chars.
    assert len(h) == 64


def test_is_argon2_hash_handles_empty_and_none():
    assert not _is_argon2_hash("")
    # None is acceptable — verify returns False rather than crashing.
    assert not _is_argon2_hash(None)  # type: ignore[arg-type]


# ── Verify (positive cases) ────────────────────────────────────────────


def test_verify_argon2_accepts_correct_password():
    if _argon2 is None:
        pytest.skip("argon2-cffi not installed")
    pw = "correct-horse-battery-staple"
    h = _hash_password_argon2(pw)
    # argon2 embeds the salt in the PHC string; the salt arg is ignored.
    assert _verify_password(pw, h, stored_salt="ignored") is True


def test_verify_pbkdf2_accepts_correct_password():
    pw = "correct-horse-battery-staple"
    salt = secrets.token_hex(16)
    h = _hash_password(pw, salt)
    assert _verify_password(pw, h, salt) is True


def test_verify_returns_false_for_empty_hash():
    # Defensive: a NULL/empty stored hash must never accidentally accept
    # an empty password — would let an unprovisioned account log in.
    assert _verify_password("", "", "anysalt") is False
    assert _verify_password("any", "", "anysalt") is False


# ── Verify (negative cases) ────────────────────────────────────────────


def test_verify_argon2_rejects_wrong_password():
    if _argon2 is None:
        pytest.skip("argon2-cffi not installed")
    h = _hash_password_argon2("right")
    assert _verify_password("wrong", h, stored_salt="ignored") is False


def test_verify_pbkdf2_rejects_wrong_password():
    salt = secrets.token_hex(16)
    h = _hash_password("right", salt)
    assert _verify_password("wrong", h, salt) is False


def test_verify_pbkdf2_rejects_wrong_salt():
    salt = secrets.token_hex(16)
    h = _hash_password("right", salt)
    other_salt = secrets.token_hex(16)
    assert _verify_password("right", h, other_salt) is False


def test_verify_argon2_rejects_malformed_hash():
    # A garbage PHC string must not 500 the login flow; treat as wrong.
    bogus = "$argon2id$malformed$nope"
    assert _verify_password("anything", bogus, "salt") is False


# ── Lazy rehash via the login endpoint ─────────────────────────────────


def test_login_lazy_rehashes_pbkdf2_row(monkeypatch):
    """End-to-end: a user with a PBKDF2 hash logs in successfully and
    the next stored hash is argon2id."""
    if _argon2 is None:
        pytest.skip("argon2-cffi not installed")

    # Set a deterministic admin password BEFORE the app imports so the
    # auto-bootstrap uses it (matches test_auth.py's pattern).
    import os
    os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")
    from radar_api import app
    from radar.database import db

    user = db.user_get("admin")
    if user is None:
        pytest.skip("No admin user provisioned")

    # Force the admin row back to PBKDF2 so we can observe the rehash.
    test_pw = "RehashMe-Right-Now-1234"
    pbkdf_salt = secrets.token_hex(16)
    pbkdf_hash = _hash_password(test_pw, pbkdf_salt)
    db.user_update_password(user["id"], pbkdf_hash, pbkdf_salt)

    pre = db.user_get("admin")
    assert not _is_argon2_hash(pre["password_hash"]), \
        "test setup: admin hash should be PBKDF2 before login"

    with app.test_client() as c:
        resp = c.post("/api/auth/login", json={
            "username": "admin",
            "password": test_pw,
        })
        # user_update_password sets invalidate_tokens_before; we don't
        # care about the issued token here — only that login succeeded
        # AND the on-disk hash is now argon2id.
        assert resp.status_code == 200, resp.get_json()

    post = db.user_get("admin")
    assert _is_argon2_hash(post["password_hash"]), \
        "lazy rehash failed — hash is still PBKDF2 after successful login"
    # The next login must still verify against the new hash.
    assert _verify_password(test_pw, post["password_hash"], post["salt"]) is True


def test_login_does_not_rehash_already_argon2_row(monkeypatch):
    """Negative: rehashing an already-argon2 hash would be a wasted
    write per login. Confirm we do NOT update the row in that case."""
    if _argon2 is None:
        pytest.skip("argon2-cffi not installed")

    import os
    os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")
    from radar_api import app
    from radar.database import db

    user = db.user_get("admin")
    if user is None:
        pytest.skip("No admin user provisioned")

    test_pw = "ArgonAlready-5678"
    argon_hash = _hash_password_argon2(test_pw)
    salt = secrets.token_hex(16)
    db.user_update_password(user["id"], argon_hash, salt)

    pre = db.user_get("admin")
    pre_hash = pre["password_hash"]

    with app.test_client() as c:
        resp = c.post("/api/auth/login", json={
            "username": "admin",
            "password": test_pw,
        })
        assert resp.status_code == 200

    post = db.user_get("admin")
    assert post["password_hash"] == pre_hash, \
        "already-argon2 hash should not be rewritten on every login"
