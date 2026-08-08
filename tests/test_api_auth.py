"""P7 C13 — the auth store, the session lifecycle, and the route bindings.

This is a cutover precondition (§7-2 #99): the v3 UI must not go live
unauthenticated. It is also the one slice on the L6 list with a security
consequence, so the tests below are about properties rather than about
shapes.

Four of them are load-bearing:

* **the live system is untouchable.** v3 signs with its OWN key id, never
  reads `JWT_SECRET_KEY`, never generates a secret and never writes
  `config.env`. Production's key auto-generates and auto-persists
  (`radar/auth.py:155-199`); a second process doing the same thing would
  race the file and invalidate every live session. The tests assert the
  absence, because an absence is what has to hold.
* **a credential never reaches a projection.** The user store is a fold of
  `command_record`, which R9 projects; the sweep below drives every
  registered action through R9 and fails if the material appears.
* **the role comes from the token, and a demotion still takes effect at
  once.** S1-SVC-011's v3 norm is "the claim is the primary source"; the
  operational property production bought with a per-request database read
  is bought here by bumping the user's `sessions_not_before` on every
  change of standing, so the old token stops verifying.
* **a command with no reader is not shipped.** Each of the five user
  actions is asserted to have a reader: login, refresh, or the principal
  resolution refuses because of it.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from v3.api import (ANONYMOUS, ApiRequest, Principal, ReadContext,
                    ReadOnlyLedger, handle)
from v3.api import cookies as COOKIES
from v3.api import routes as R
from v3.api import registry as REG
from v3.api.vocabulary import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.auth import password as P
from v3.auth import session as SESSION
from v3.auth import store as US
from v3.auth import tokens as T
from v3.commands import spec as SPEC
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore

REPO_ROOT = Path(__file__).resolve().parent.parent
NOW = 1_800_000_000.0
KEY = "v3-test-signing-key-not-a-production-secret-0123456789"
GOOD = "correct-horse-battery-staple"
ADMIN = Principal(user_id="root", role=ROLE_ADMIN)
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)
VIEWER = Principal(user_id="v-1", role=ROLE_VIEWER)


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "auth.db"))
    yield handle_
    handle_.close()


def _provider():
    return SESSION.AuthProvider(
        authority=T.TokenAuthority(key=KEY),
        guard=SESSION.LoginGuard())


def _read(store, *, now=NOW, provider=None):
    return ReadContext(ledger=ReadOnlyLedger(store), now=now,
                       auth=provider if provider is not None else _provider())


def _write(store, principal=ADMIN, *, now=NOW, provider=None):
    return WriteContext(read=_read(store, now=now, provider=provider),
                        ledger=CommandLedger(store), principal=principal)


def _register(store, user_id, *, role=ROLE_ANALYST, password=GOOD,
              principal=ADMIN, now=NOW, provider=None):
    return handle(ApiRequest(
        method="POST", path="/api/v3/auth/register",
        body={"user_id": user_id, "password": password, "role": role},
        principal=principal),
        _write(store, principal, now=now, provider=provider))


def _login(store, user_id, password, *, now=NOW, provider=None, ip=None):
    return handle(ApiRequest(method="POST", path="/api/v3/auth/login",
                             body={"user_id": user_id, "password": password},
                             client_ip=ip),
                  _read(store, now=now, provider=provider))


def _transport(response) -> tuple:
    """The refresh pair, taken from the COOKIES (§7-2 #103).

    It is not in the body and must never be: S1-SVC-004 / S2-API-010 forbid
    it and S1-UI-002 calls the cookie form CORE. `tests/test_api_cookies.py`
    is where that property is proved; here the pair is simply read from
    where the transport actually put it.
    """
    directives = {directive.spec.name: directive
                  for directive in response.cookies}
    return (directives[COOKIES.REFRESH_COOKIE.name].value,
            directives[COOKIES.CSRF_COOKIE.name].value)


def _refresh(store, *, refresh_token, csrf, now=NOW, provider=None):
    return handle(
        ApiRequest(method="POST", path="/api/v3/auth/refresh",
                   cookies={COOKIES.REFRESH_COOKIE.name: refresh_token,
                            COOKIES.CSRF_COOKIE.name: csrf},
                   csrf_header=csrf),
        _read(store, now=now, provider=provider))


# ────────────────────────────────────────────────────────────────────────
class TestTheLiveSystemIsNotTouched:
    """The ops record's caution, made into assertions.

    `config.env`'s `JWT_SECRET_KEY` and `DEFAULT_ADMIN_PASSWORD` are
    auto-generated on the running system. v3 must not read, write, rotate
    or race any of it.
    """

    def _auth_sources(self):
        paths = sorted((REPO_ROOT / "v3" / "auth").glob("*.py"))
        paths.append(REPO_ROOT / "v3" / "runtime" / "auth.py")
        assert paths
        return paths

    LIVE_SECRETS = ("JWT_SECRET_KEY", "DEFAULT_ADMIN_PASSWORD")

    def test_no_v3_module_names_the_live_secrets(self):
        """By AST, not by substring: prose explaining the ABSENCE is the
        point of the absence, and a grep would forbid saying why."""
        offences = []
        for path in list(self._auth_sources()) + [
                REPO_ROOT / "v3" / "runtime" / "secrets.py"]:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                named = None
                if isinstance(node, ast.Constant) and isinstance(node.value,
                                                                 str):
                    named = node.value
                elif isinstance(node, ast.Name):
                    named = node.id
                elif isinstance(node, ast.Attribute):
                    named = node.attr
                if named in self.LIVE_SECRETS:
                    offences.append(f"{path.name}:{node.lineno} {named}")
        assert offences == [], (
            f"v3 reads a live-system secret. Sharing the signing key would "
            f"make a v1 token valid on v3 and a v3 token valid on v1; "
            f"writing it would invalidate every live session: {offences}")

    def test_v3_never_generates_or_persists_a_signing_key(self):
        """`password.py` is exempt from the generation half and only that
        half: a per-credential salt IS meant to be random, and it is not
        key material — it is stored beside the hash it belongs to."""
        for path in self._auth_sources():
            forbidden = {"write_text", "write_bytes", "chmod"}
            if path.name != "password.py":
                forbidden |= {"token_hex", "token_urlsafe", "token_bytes"}
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute):
                    assert node.attr not in forbidden, (
                        f"{path.name}:{node.lineno} generates or persists "
                        f"key material. Production does this to config.env; "
                        f"a second writer races it and the loser's sessions "
                        f"all die.")

    def test_the_key_id_is_v3s_own(self):
        assert SESSION.SIGNING_KEY_ID == "NOROSHI_V3_JWT_SECRET"

    def test_an_absent_key_is_an_absent_slice_not_an_invented_one(self):
        from v3.runtime import auth as RA
        built = RA.build_provider(source={})
        assert built is None, (
            "no key means no auth provider. Minting one would either "
            "generate a secret (production's behaviour, which races "
            "config.env) or accept unsigned tokens.")

    def test_auth_routes_answer_503_when_the_slice_is_absent(self, store):
        response = handle(
            ApiRequest(method="POST", path="/api/v3/auth/login",
                       body={"user_id": "x", "password": GOOD}),
            ReadContext(ledger=ReadOnlyLedger(store), now=NOW))
        assert response.status == 503
        assert response.as_dict()["error"] == "api.unavailable"


class TestTheTokenIsV3sAlone:
    def test_a_token_declares_its_issuer_and_is_refused_without_one(self):
        authority = T.TokenAuthority(key=KEY)
        token = authority.issue(user_id="u", role=ROLE_ANALYST,
                                token_type=T.TYPE_ACCESS, now=NOW)
        claims = authority.verify(token, expected_type=T.TYPE_ACCESS, now=NOW)
        assert claims.issuer == T.ISSUER == "noroshi-v3"
        assert claims.role == ROLE_ANALYST
        foreign = T.encode({"sub": "u", "role": ROLE_ADMIN,
                            "typ": T.TYPE_ACCESS, "iat": NOW,
                            "exp": NOW + 60, "jti": "j"}, key=KEY)
        with pytest.raises(T.TokenError):
            authority.verify(foreign, expected_type=T.TYPE_ACCESS, now=NOW)

    def test_a_token_from_another_issuer_is_refused(self):
        """The `iss` claim is guarded twice — `require` catches an absent
        one and `issuer=` catches a wrong one — so a mutation of either
        alone survives. This is the case only the second guard sees."""
        stranger = T.TokenAuthority(key=KEY, issuer="noroshi-v1")
        token = stranger.issue(user_id="u", role=ROLE_ADMIN,
                               token_type=T.TYPE_ACCESS, now=NOW)
        with pytest.raises(T.TokenError):
            T.TokenAuthority(key=KEY).verify(
                token, expected_type=T.TYPE_ACCESS, now=NOW)

    def test_an_access_token_is_not_a_refresh_token(self):
        authority = T.TokenAuthority(key=KEY)
        access = authority.issue(user_id="u", role=ROLE_VIEWER,
                                 token_type=T.TYPE_ACCESS, now=NOW)
        with pytest.raises(T.TokenError):
            authority.verify(access, expected_type=T.TYPE_REFRESH, now=NOW)

    def test_the_revocation_floor_truncates_like_production(self):
        """S1-SVC-006 (b)'s integer floor, which is transcribed rather
        than rounded: a float comparison would disagree with production
        within one second of every password change."""
        authority = T.TokenAuthority(key=KEY)
        token = authority.issue(user_id="u", role=ROLE_VIEWER,
                                token_type=T.TYPE_ACCESS, now=NOW + 0.25)
        claims = authority.verify(token, expected_type=T.TYPE_ACCESS,
                                  now=NOW + 1)
        assert T.revoked(claims, not_before=None) is False
        assert T.revoked(claims, not_before=NOW + 0.75) is False
        assert T.revoked(claims, not_before=NOW + 1.0) is True

    def test_lifetimes_match_production(self):
        assert T.ACCESS_TTL_SEC == 3600.0
        assert T.REFRESH_TTL_SEC == 86400.0

    def test_an_expired_token_is_refused(self):
        authority = T.TokenAuthority(key=KEY)
        token = authority.issue(user_id="u", role=ROLE_VIEWER,
                                token_type=T.TYPE_ACCESS, now=NOW)
        with pytest.raises(T.TokenError):
            authority.verify(token, expected_type=T.TYPE_ACCESS,
                             now=NOW + T.ACCESS_TTL_SEC + 1)

    def test_a_token_signed_with_another_key_is_refused(self):
        token = T.TokenAuthority(key="another-key-entirely-different-0123456789").issue(
            user_id="u", role=ROLE_ADMIN, token_type=T.TYPE_ACCESS, now=NOW)
        with pytest.raises(T.TokenError):
            T.TokenAuthority(key=KEY).verify(
                token, expected_type=T.TYPE_ACCESS, now=NOW)

    def test_the_authority_never_reveals_its_key(self):
        authority = T.TokenAuthority(key=KEY)
        assert KEY not in repr(authority)
        assert KEY not in json.dumps(authority.as_dict())


class TestPasswordsAreProductionsSemantics:
    def test_minimum_length_is_twelve(self):
        assert P.MIN_PASSWORD_LENGTH == 12
        with pytest.raises(DomainError):
            P.validate("short")
        P.validate("a" * 12)

    def test_derive_then_verify_round_trips(self):
        credential = P.derive(GOOD)
        assert P.verify(credential, GOOD) is True
        assert P.verify(credential, GOOD + "x") is False

    def test_argon2id_is_produced_when_available(self):
        credential = P.derive(GOOD)
        if P.argon2_available():
            assert credential["algorithm"] == P.ALGORITHM_ARGON2
            assert credential["hash"].startswith(P.ARGON2_PREFIX)
        else:
            assert credential["algorithm"] == P.ALGORITHM_PBKDF2

    def test_pbkdf2_legacy_form_still_verifies(self):
        legacy = P.derive(GOOD, prefer_argon2=False)
        assert legacy["algorithm"] == P.ALGORITHM_PBKDF2
        assert P.PBKDF2_ITERATIONS == 100_000
        assert P.verify(legacy, GOOD) is True

    def test_a_malformed_credential_is_false_not_an_exception(self):
        for bad in ({}, {"algorithm": "x", "hash": "", "salt": ""},
                    {"algorithm": P.ALGORITHM_ARGON2, "hash": "nope",
                     "salt": ""}):
            assert P.verify(bad, GOOD) is False

    def test_the_derived_value_is_not_the_password(self):
        credential = P.derive(GOOD)
        assert GOOD not in json.dumps(credential)


class TestTheStoreIsTheSameFoldTheRestOfTheSurfaceUses:
    def test_registering_a_user_is_a_command_row_and_nothing_else(self, store):
        response = _register(store, "kamo")
        assert response.status == 200
        rows = store.command_records()
        assert [row["action"] for row in rows] == [US.USER_REGISTER]
        assert rows[0]["target_kind"] == US.TARGET_USER
        assert rows[0]["actor_id"] == "root"

    def test_the_state_is_the_fold(self, store):
        _register(store, "kamo", role=ROLE_ANALYST)
        state = US.user_state(ReadOnlyLedger(store), "kamo", until=NOW)
        assert state["role"] == ROLE_ANALYST
        assert state["active"] is True
        assert US.user_count(ReadOnlyLedger(store), until=NOW) == 1

    def test_registering_twice_is_refused(self, store):
        _register(store, "kamo")
        again = _register(store, "kamo", now=NOW + 1)
        assert again.status == 400

    def test_an_unknown_role_is_refused(self, store):
        assert _register(store, "kamo", role="superuser").status == 400

    def test_a_short_password_is_refused(self, store):
        assert _register(store, "kamo", password="short").status == 400

    def test_role_change_and_deactivation_fold(self, store):
        _register(store, "kamo", role=ROLE_VIEWER)
        assert handle(ApiRequest(
            method="PUT", path="/api/v3/auth/users/kamo",
            body={"role": ROLE_ANALYST, "reason": "promotion"},
            principal=ADMIN), _write(store, now=NOW + 1)).status == 200
        ledger = ReadOnlyLedger(store)
        assert US.user_state(ledger, "kamo",
                             until=NOW + 2)["role"] == ROLE_ANALYST
        assert handle(ApiRequest(
            method="DELETE", path="/api/v3/auth/users/kamo",
            body={"reason": "left"}, principal=ADMIN),
            _write(store, now=NOW + 2)).status == 200
        assert US.user_state(ledger, "kamo",
                             until=NOW + 3)["active"] is False

    def test_an_admin_cannot_change_or_remove_themselves(self, store):
        _register(store, "root", role=ROLE_ADMIN)
        demote = handle(ApiRequest(
            method="PUT", path="/api/v3/auth/users/root",
            body={"role": ROLE_VIEWER, "reason": "oops"}, principal=ADMIN),
            _write(store, now=NOW + 1))
        assert demote.status == 400
        remove = handle(ApiRequest(
            method="DELETE", path="/api/v3/auth/users/root",
            body={"reason": "oops"}, principal=ADMIN),
            _write(store, now=NOW + 1))
        assert remove.status == 400

    def test_the_listing_never_carries_a_credential(self, store):
        _register(store, "kamo")
        response = handle(ApiRequest(method="GET",
                                     path="/api/v3/auth/users",
                                     principal=ADMIN), _read(store))
        body = json.dumps(response.as_dict())
        assert "kamo" in body
        assert "hash" not in body and GOOD not in body


class TestTheSessionLifecycle:
    def test_login_returns_a_pair_and_the_access_token_carries_the_role(
            self, store):
        _register(store, "kamo", role=ROLE_ANALYST)
        provider = _provider()
        response = _login(store, "kamo", GOOD, now=NOW + 1, provider=provider)
        assert response.status == 200
        session = response.as_dict()["session"]
        claims = provider.authority.verify(
            session["access_token"], expected_type=T.TYPE_ACCESS, now=NOW + 1)
        assert claims.subject == "kamo"
        assert claims.role == ROLE_ANALYST
        assert session["access_expires_sec"] == T.ACCESS_TTL_SEC
        assert session["role"] == ROLE_ANALYST

    def test_a_wrong_password_and_an_unknown_user_are_the_same_answer(
            self, store):
        _register(store, "kamo")
        wrong = _login(store, "kamo", "wrong-password-x", now=NOW + 1)
        missing = _login(store, "ghost", GOOD, now=NOW + 1)
        assert wrong.status == missing.status == 401
        assert (wrong.as_dict()["error_detail"]["message"]
                == missing.as_dict()["error_detail"]["message"]
                == SESSION.REFUSED_MESSAGE)

    def test_a_deactivated_user_cannot_log_in(self, store):
        _register(store, "kamo")
        handle(ApiRequest(method="DELETE", path="/api/v3/auth/users/kamo",
                          body={"reason": "left"}, principal=ADMIN),
               _write(store, now=NOW + 1))
        assert _login(store, "kamo", GOOD, now=NOW + 2).status == 401

    def test_refresh_mints_a_new_access_token_with_the_current_role(
            self, store):
        _register(store, "kamo", role=ROLE_VIEWER)
        provider = _provider()
        login = _login(store, "kamo", GOOD, now=NOW + 1, provider=provider)
        refresh_token, csrf = _transport(login)
        handle(ApiRequest(method="PUT", path="/api/v3/auth/users/kamo",
                          body={"role": ROLE_ANALYST, "reason": "promotion"},
                          principal=ADMIN),
               _write(store, now=NOW + 2, provider=provider))
        refreshed = _refresh(store, refresh_token=refresh_token, csrf=csrf,
                             now=NOW + 3, provider=provider)
        assert refreshed.status == 200
        claims = provider.authority.verify(
            refreshed.as_dict()["session"]["access_token"],
            expected_type=T.TYPE_ACCESS, now=NOW + 3)
        assert claims.role == ROLE_ANALYST

    def test_an_access_token_is_refused_as_a_refresh_token(self, store):
        """Even when the CSRF pair is internally consistent: the pair has
        to belong to a REFRESH token, and an access token carries none."""
        _register(store, "kamo")
        provider = _provider()
        login = _login(store, "kamo", GOOD, now=NOW + 1, provider=provider)
        session = login.as_dict()["session"]
        _refresh_token, csrf = _transport(login)
        response = _refresh(store, refresh_token=session["access_token"],
                            csrf=csrf, now=NOW + 2, provider=provider)
        assert response.status == 401

    def test_logout_revokes_every_token_issued_before_it(self, store):
        _register(store, "kamo")
        provider = _provider()
        login = _login(store, "kamo", GOOD, now=NOW + 1, provider=provider)
        session = login.as_dict()["session"]
        refresh_token, _csrf = _transport(login)
        principal = SESSION.principal_for(
            ReadOnlyLedger(store), provider,
            access_token=session["access_token"], now=NOW + 2)
        assert principal.user_id == "kamo"
        response = handle(
            ApiRequest(method="POST", path="/api/v3/auth/logout",
                       principal=principal),
            _write(store, principal, now=NOW + 3, provider=provider))
        assert response.status == 200
        with pytest.raises(SESSION.SessionRefused):
            SESSION.principal_for(ReadOnlyLedger(store), provider,
                                  access_token=session["access_token"],
                                  now=NOW + 4)
        with pytest.raises(SESSION.SessionRefused):
            SESSION.principal_for(ReadOnlyLedger(store), provider,
                                  access_token=refresh_token, now=NOW + 4)

    def test_a_password_change_revokes_the_users_sessions(self, store):
        _register(store, "kamo")
        provider = _provider()
        session = _login(store, "kamo", GOOD, now=NOW + 1,
                         provider=provider).as_dict()["session"]
        principal = SESSION.principal_for(
            ReadOnlyLedger(store), provider,
            access_token=session["access_token"], now=NOW + 2)
        changed = handle(
            ApiRequest(method="POST", path="/api/v3/auth/password",
                       body={"old_password": GOOD,
                             "new_password": "another-long-password"},
                       principal=principal),
            _write(store, principal, now=NOW + 3, provider=provider))
        assert changed.status == 200
        with pytest.raises(SESSION.SessionRefused):
            SESSION.principal_for(ReadOnlyLedger(store), provider,
                                  access_token=session["access_token"],
                                  now=NOW + 4)
        assert _login(store, "kamo", GOOD, now=NOW + 5,
                      provider=provider).status == 401
        assert _login(store, "kamo", "another-long-password", now=NOW + 5,
                      provider=provider).status == 200

    def test_a_wrong_current_password_refuses_the_change(self, store):
        _register(store, "kamo")
        provider = _provider()
        session = _login(store, "kamo", GOOD, now=NOW + 1,
                         provider=provider).as_dict()["session"]
        principal = SESSION.principal_for(
            ReadOnlyLedger(store), provider,
            access_token=session["access_token"], now=NOW + 2)
        response = handle(
            ApiRequest(method="POST", path="/api/v3/auth/password",
                       body={"old_password": "not-the-password",
                             "new_password": "another-long-password"},
                       principal=principal),
            _write(store, principal, now=NOW + 3, provider=provider))
        assert response.status == 401

    def test_a_role_change_takes_effect_before_the_token_expires(self, store):
        """The property production bought with a per-request database read.

        S1-SVC-011's v3 norm makes the claim the primary source, so the
        demotion has to reach the OLD token some other way: the command
        bumps the user's `sessions_not_before`, and the token stops
        verifying at once rather than in an hour.
        """
        _register(store, "kamo", role=ROLE_ADMIN)
        provider = _provider()
        session = _login(store, "kamo", GOOD, now=NOW + 1,
                         provider=provider).as_dict()["session"]
        handle(ApiRequest(method="PUT", path="/api/v3/auth/users/kamo",
                          body={"role": ROLE_VIEWER, "reason": "demotion"},
                          principal=ADMIN),
               _write(store, ADMIN, now=NOW + 2, provider=provider))
        with pytest.raises(SESSION.SessionRefused):
            SESSION.principal_for(ReadOnlyLedger(store), provider,
                                  access_token=session["access_token"],
                                  now=NOW + 3)


class TestTheLoginGuard:
    def test_failures_are_counted_per_ip_and_successes_clear_them(self):
        guard = SESSION.LoginGuard()
        assert guard.MAX_ATTEMPTS == 5 and guard.WINDOW_SEC == 300.0
        for offset in range(5):
            guard.record_failure("10.0.0.1", NOW + offset)
        assert guard.blocked("10.0.0.1", NOW + 5) is True
        assert guard.blocked("10.0.0.2", NOW + 5) is False
        assert guard.blocked("10.0.0.1", NOW + 5 + guard.WINDOW_SEC) is False
        guard.clear("10.0.0.1")
        assert guard.blocked("10.0.0.1", NOW + 5) is False

    def test_a_blocked_ip_gets_429_not_401(self, store):
        _register(store, "kamo")
        provider = _provider()
        for offset in range(5):
            assert _login(store, "kamo", "wrong-password-x",
                          now=NOW + offset, provider=provider,
                          ip="10.0.0.9").status == 401
        assert _login(store, "kamo", GOOD, now=NOW + 6, provider=provider,
                      ip="10.0.0.9").status == 429

    def test_the_tracked_ip_set_is_bounded(self):
        guard = SESSION.LoginGuard()
        for index in range(guard.MAX_IPS + 50):
            guard.record_failure(f"10.1.{index // 256}.{index % 256}",
                                 NOW + index)
        assert len(guard.tracked()) <= guard.MAX_IPS


class TestTheRouteBindingsEnforceIt:
    ROUTE_IDS = ("C13login", "C13refresh", "C13logout", "C13register",
                 "C13password", "C13users", "C13user", "C13role",
                 "C13remove")

    def test_all_nine_routes_exist(self):
        for route_id in self.ROUTE_IDS:
            assert R.by_id(route_id) is not None, route_id

    def test_only_login_and_refresh_are_public(self):
        public = {route.route_id for route in R.ROUTES
                  if route.access.public}
        assert public == {"R15h", "C13login", "C13refresh"}

    def test_user_administration_is_admin_only(self):
        for route_id in ("C13register", "C13users", "C13user", "C13role",
                         "C13remove"):
            assert R.by_id(route_id).access.minimum_role == ROLE_ADMIN

    def test_self_service_is_open_to_any_authenticated_reader(self):
        for route_id in ("C13logout", "C13password"):
            route = R.by_id(route_id)
            assert route.access.minimum_role == ROLE_VIEWER
            assert route.side_effect is True

    def test_login_and_refresh_write_nothing(self):
        for route_id in ("C13login", "C13refresh"):
            route = R.by_id(route_id)
            assert route.side_effect is False
            assert route_id in R.SESSION_ROUTES

    def test_an_anonymous_caller_cannot_reach_user_administration(self, store):
        response = handle(ApiRequest(method="GET",
                                     path="/api/v3/auth/users"),
                          _read(store))
        assert response.status == 401

    def test_an_analyst_cannot_reach_user_administration(self, store):
        response = handle(ApiRequest(method="GET", path="/api/v3/auth/users",
                                     principal=ANALYST), _read(store))
        assert response.status == 403


class TestCoverageAndDeferral:
    def test_c13_is_served_not_deferred(self):
        assert "C13" in REG.served_ids()
        assert "C13" not in REG.deferred_ids()

    def test_the_partition_is_still_total(self):
        assert REG.unaccounted() == frozenset()
        assert REG.double_counted() == frozenset()


class TestNoCredentialReachesAProjection:
    """The sweep. R9 projects `command_record`; the store lives there."""

    def test_r9_redacts_every_secret_field_of_every_action(self, store):
        _register(store, "kamo")
        provider = _provider()
        principal = SESSION.principal_for(
            ReadOnlyLedger(store), provider,
            access_token=_login(store, "kamo", GOOD, now=NOW + 1,
                                provider=provider
                                ).as_dict()["session"]["access_token"],
            now=NOW + 2)
        handle(ApiRequest(method="POST", path="/api/v3/auth/password",
                          body={"old_password": GOOD,
                                "new_password": "another-long-password"},
                          principal=principal),
               _write(store, principal, now=NOW + 3, provider=provider))
        trail = handle(ApiRequest(method="GET", path="/api/v3/decisions",
                                  principal=ADMIN),
                       _read(store, now=NOW + 4, provider=provider))
        body = json.dumps(trail.as_dict(), ensure_ascii=False)
        assert GOOD not in body
        assert "another-long-password" not in body
        assert "$argon2" not in body
        for row in store.command_records():
            single = handle(
                ApiRequest(method="GET",
                           path=f"/api/v3/decisions/{row['command_id']}",
                           principal=ADMIN),
                _read(store, now=NOW + 4, provider=provider))
            single_body = json.dumps(single.as_dict(), ensure_ascii=False)
            assert GOOD not in single_body
            assert "$argon2" not in single_body

    def test_the_redactor_reaches_every_depth(self):
        payload = {"a": {"b": [{"password": "s3cret"}]},
                   "credential": {"hash": "$argon2id$x"}}
        redacted = SPEC.redact(payload)
        assert "s3cret" not in json.dumps(redacted)
        assert "$argon2id$x" not in json.dumps(redacted)
        assert payload["a"]["b"][0]["password"] == "s3cret", (
            "redaction must not mutate its input")


class TestEveryUserCommandHasAReader:
    """A command with no reader is not shipped (the standing rule)."""

    READERS = {
        US.USER_REGISTER: "login resolves the credential from this fold",
        US.USER_PASSWORD_SET: "login resolves the credential from this fold",
        US.USER_ROLE_SET: "refresh and the register listing read the role",
        US.USER_DEACTIVATE: "login and principal_for refuse a deactivated "
                            "user",
        US.USER_SESSIONS_REVOKE: "principal_for compares iat against "
                                 "sessions_not_before",
    }

    def test_every_registered_user_action_is_named_with_its_reader(self):
        registered = {spec.action for spec in SPEC.SPECS
                      if spec.target_kind == US.TARGET_USER}
        assert registered == set(self.READERS)

    def test_each_action_resolves_through_the_same_projection(self):
        for action in self.READERS:
            spec = SPEC.spec_for(action)
            assert spec.resolve is US.resolve_user
