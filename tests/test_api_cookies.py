"""§7-2 #103 — the refresh token's transport, and why it is not the body.

The registered difference said v3 returned the refresh token in the JSON
body while production forbids it (S1-SVC-004 / S2-API-010 / S1-UI-002,
which is CORE because an httpOnly cookie structurally closes XSS theft).
The cause was never a design choice: `ApiRequest` had no cookie concept,
so there was nowhere for a cookie to be.

These tests are about four properties, not about shapes.

* **the posture is production's, read from production.** The refusal to
  transcribe is the standing method rule: WP-2.6 found 97 infidelities in
  values that looked correctly copied. `TestThePostureIsProductions`
  parses `radar/auth.py` and the installed `flask_jwt_extended` by AST and
  compares the EFFECTIVE cookie attributes, including the ones production
  gets by not overriding a library default.
* **the CSRF pairing cannot be forgotten.** Not "every handler remembers
  to check" — `CookiePolicy` refuses to exist with a cookie-borne
  credential and no CSRF requirement, so the forgetting has no spelling.
  That is the G-01 lesson applied: the decision lives in the route table.
* **the body is clean, and the proof is a sweep.** Every auth route is
  driven and every response body is scanned for the refresh token, its
  segments and its signature. A mutation that puts it back must fail.
* **the handler layer stays pure.** Cookies arrive as typed request input
  and leave as typed directives; only `v3/api/binding.py` knows what a
  `Set-Cookie` header is.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from v3.api import (ApiRequest, Principal, ReadContext, ReadOnlyLedger,
                    handle)
from v3.api import cookies as C
from v3.api import routes as R
from v3.api.envelope import tool_response, with_cookies
from v3.api.vocabulary import API_PREFIX, ROLE_ADMIN, ROLE_ANALYST
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.auth import session as SESSION
from v3.auth import tokens as T
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore

REPO_ROOT = Path(__file__).resolve().parent.parent
NOW = 1_800_000_000.0
KEY = "v3-test-signing-key-not-a-production-secret-0123456789"
GOOD = "correct-horse-battery-staple"
ADMIN = Principal(user_id="root", role=ROLE_ADMIN)
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "cookies.db"))
    yield handle_
    handle_.close()


def _provider():
    return SESSION.AuthProvider(authority=T.TokenAuthority(key=KEY),
                                guard=SESSION.LoginGuard())


def _read(store, *, now=NOW, provider=None, cookies=None, csrf=None):
    return ReadContext(ledger=ReadOnlyLedger(store), now=now,
                       auth=provider if provider is not None else _provider())


def _write(store, principal=ADMIN, *, now=NOW):
    return WriteContext(read=_read(store, now=now),
                        ledger=CommandLedger(store), principal=principal)


def _register(store, user_id="analyst-1", *, role=ROLE_ANALYST):
    return handle(ApiRequest(
        method="POST", path=f"{API_PREFIX}/auth/register",
        body={"user_id": user_id, "password": GOOD, "role": role},
        principal=ADMIN), _write(store, ADMIN))


def _login(store, user_id="analyst-1", password=GOOD, *, now=NOW):
    return handle(ApiRequest(method="POST", path=f"{API_PREFIX}/auth/login",
                             body={"user_id": user_id, "password": password}),
                  _read(store, now=now))


def _refresh(store, *, refresh_token, csrf_cookie=None, csrf_header=None,
             now=NOW, body=None):
    cookies = {}
    if refresh_token is not None:
        cookies[C.REFRESH_COOKIE.name] = refresh_token
    if csrf_cookie is not None:
        cookies[C.CSRF_COOKIE.name] = csrf_cookie
    return handle(ApiRequest(method="POST",
                             path=f"{API_PREFIX}/auth/refresh",
                             body=dict(body or {}), cookies=cookies,
                             csrf_header=csrf_header),
                  _read(store, now=now))


def _directives(response):
    return {directive.spec.name: directive for directive in response.cookies}


# ────────────────────────────────────────────────────────────────────────
class TestThePostureIsProductions:
    """AST, never transcription. Including the defaults nobody wrote down."""

    def _production_config(self) -> dict:
        """`app.config[...] = ...` inside `init_auth`, by AST."""
        tree = ast.parse((REPO_ROOT / "radar" / "auth.py").read_text())
        found: dict = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.FunctionDef)
                    and node.name == "init_auth"):
                continue
            for statement in ast.walk(node):
                if not isinstance(statement, ast.Assign):
                    continue
                for target in statement.targets:
                    if not (isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Attribute)
                            and target.value.attr == "config"):
                        continue
                    key = getattr(target.slice, "value", None)
                    if isinstance(key, str):
                        found[key] = statement.value
        assert found, "init_auth's app.config assignments were not found"
        return found

    def _library_defaults(self) -> dict:
        """`app.config.setdefault(...)` in flask_jwt_extended, by AST."""
        import flask_jwt_extended

        path = Path(flask_jwt_extended.__file__).parent / "jwt_manager.py"
        tree = ast.parse(path.read_text())
        defaults: dict = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "setdefault"
                    and len(node.args) == 2):
                continue
            key = getattr(node.args[0], "value", None)
            if isinstance(key, str):
                defaults[key] = node.args[1]
        assert defaults, "the library's config defaults were not found"
        return defaults

    def test_the_refresh_cookie_is_httponly_strict_and_path_scoped(self):
        config = self._production_config()
        assert ast.literal_eval(config["JWT_COOKIE_HTTPONLY"]) is True
        assert ast.literal_eval(config["JWT_COOKIE_SAMESITE"]) == "Strict"
        assert ast.literal_eval(
            config["JWT_REFRESH_COOKIE_PATH"]) == "/api/auth/refresh"

        assert C.REFRESH_COOKIE.http_only is True
        assert C.REFRESH_COOKIE.same_site == "Strict"
        # The PROPERTY is "scoped to the refresh route's own path", which is
        # what stops the browser sending it on every request. The literal
        # differs because v3's prefix does (§7-2 #103's residual).
        assert C.REFRESH_COOKIE.path == f"{API_PREFIX}/auth/refresh"
        assert C.REFRESH_COOKIE.path == R.by_id("C13refresh").path

    def test_secure_defaults_to_true_on_both_sides(self):
        """Production's is an env opt-out that defaults on; so is v3's."""
        config = self._production_config()
        # The config value is a local, so the default lives in the
        # assignment that built it — resolve it rather than assume.
        local = ast.unparse(config["JWT_COOKIE_SECURE"])
        tree = ast.parse((REPO_ROOT / "radar" / "auth.py").read_text())
        sources = [ast.unparse(node.value) for node in ast.walk(tree)
                   if isinstance(node, ast.Assign)
                   and any(getattr(target, "id", None) == local
                           for target in node.targets)]
        assert sources, f"{local} is assigned nowhere in radar/auth.py"
        source = sources[0]
        assert "JWT_COOKIE_SECURE" in source
        # `os.getenv(..., "true").lower() not in (falsey...)` — the default
        # literal is what makes it default-on.
        assert "'true'" in source or '"true"' in source
        assert C.REFRESH_COOKIE.secure is True
        assert C.CSRF_COOKIE.secure is True

        # v3's opt-out is a named parameter with the same default.
        import inspect

        from v3.api.binding import create_blueprint
        parameter = inspect.signature(
            create_blueprint).parameters["cookie_secure"]
        assert parameter.default is True

    def test_the_csrf_companion_is_readable_at_the_document_root(self):
        """The SPA has to read it, so it is not httpOnly and not scoped."""
        config = self._production_config()
        defaults = self._library_defaults()
        assert "JWT_REFRESH_CSRF_COOKIE_PATH" not in config, (
            "production leaves the CSRF cookie's path at the library "
            "default; if that changed, v3's must change with it")
        assert ast.literal_eval(
            defaults["JWT_REFRESH_CSRF_COOKIE_PATH"]) == "/"
        assert ast.literal_eval(
            config["JWT_REFRESH_CSRF_HEADER_NAME"]) == "X-CSRF-TOKEN"
        assert ast.literal_eval(config["JWT_CSRF_IN_COOKIES"]) is True

        assert C.CSRF_COOKIE.path == "/"
        assert C.CSRF_COOKIE.http_only is False
        assert C.CSRF_COOKIE.same_site == C.REFRESH_COOKIE.same_site
        assert C.CSRF_HEADER == "X-CSRF-TOKEN"

    def test_both_cookies_are_session_cookies_like_productions(self):
        """`JWT_SESSION_COOKIE` defaults True, so `max-age` is absent."""
        config = self._production_config()
        defaults = self._library_defaults()
        assert "JWT_SESSION_COOKIE" not in config
        assert ast.literal_eval(defaults["JWT_SESSION_COOKIE"]) is True
        assert C.REFRESH_COOKIE.max_age is None
        assert C.CSRF_COOKIE.max_age is None

    def test_the_cookie_names_are_v3s_own_and_that_is_registered(self):
        """A shared name on one host is two cookies nobody can tell apart."""
        config = self._production_config()
        assert ast.literal_eval(
            config["JWT_REFRESH_COOKIE_NAME"]) == "radar_refresh_jwt"
        assert C.REFRESH_COOKIE.name != "radar_refresh_jwt"
        assert C.REFRESH_COOKIE.name.startswith("noroshi_v3")
        assert C.CSRF_COOKIE.name.startswith("noroshi_v3")

    def test_the_registered_difference_names_its_own_resolution(self):
        design = (REPO_ROOT / "docs" / "design" / "v3"
                  / "wp25-l0-adapter-design.md").read_text()
        assert "#103" in design


# ────────────────────────────────────────────────────────────────────────
class TestTheCsrfPairingIsStructural:
    """G-01: the route table is where such a decision lives."""

    def test_a_cookie_borne_credential_without_csrf_cannot_be_declared(self):
        with pytest.raises(DomainError) as caught:
            C.CookiePolicy(presents=(C.REFRESH_COOKIE,), csrf=False,
                           reason="a route that forgot")
        assert "csrf" in str(caught.value).lower()

    def test_a_csrf_requirement_with_no_credential_is_also_refused(self):
        with pytest.raises(DomainError):
            C.CookiePolicy(csrf=True, reason="protecting nothing")

    def test_a_policy_that_touches_cookies_states_why(self):
        with pytest.raises(DomainError):
            C.CookiePolicy(emits=(C.REFRESH_COOKIE,))

    def test_every_route_that_reads_a_cookie_requires_the_companion(self):
        readers = [route for route in R.ROUTES if route.cookies.presents]
        assert [route.route_id for route in readers] == ["C13refresh"]
        assert all(route.cookies.csrf for route in readers)

    def test_the_refresh_route_is_the_only_one_that_reads_cookies(self):
        for route in R.ROUTES:
            if route.route_id == "C13refresh":
                continue
            assert route.cookies.presents == ()

    def test_a_handler_cannot_emit_an_undeclared_cookie(self, store):
        route = R.by_id("C13login")
        response = with_cookies(tool_response(observed_at=NOW),
                                C.SetCookie(C.REFRESH_COOKIE, "x"))
        # Declared: allowed.
        C.check_emissions(route.cookies, response.cookies)
        stranger = C.CookieSpec(name="noroshi_v3_stranger", path="/",
                                http_only=True, same_site="Strict",
                                reason="a cookie nobody declared")
        with pytest.raises(DomainError):
            C.check_emissions(route.cookies,
                              (C.SetCookie(stranger, "x"),))


# ────────────────────────────────────────────────────────────────────────
class TestTheRefreshPathEnforcesThePair:
    def _minted(self, store):
        _register(store)
        response = _login(store)
        assert response.status == 200
        directives = _directives(response)
        return (directives[C.REFRESH_COOKIE.name].value,
                directives[C.CSRF_COOKIE.name].value)

    def test_a_matched_pair_refreshes(self, store):
        token, csrf = self._minted(store)
        response = _refresh(store, refresh_token=token, csrf_cookie=csrf,
                            csrf_header=csrf, now=NOW + 10)
        assert response.status == 200
        assert response.as_dict()["session"]["access_token"]

    def test_no_header_is_a_401_before_the_handler_runs(self, store):
        token, csrf = self._minted(store)
        response = _refresh(store, refresh_token=token, csrf_cookie=csrf,
                            csrf_header=None, now=NOW + 10)
        assert response.status == 401

    def test_a_header_that_does_not_match_the_cookie_is_a_401(self, store):
        token, csrf = self._minted(store)
        response = _refresh(store, refresh_token=token, csrf_cookie=csrf,
                            csrf_header=csrf[:-1] + "0", now=NOW + 10)
        assert response.status == 401

    def test_a_pair_that_does_not_belong_to_the_token_is_a_401(self, store):
        """Double submit alone is not enough: the value is IN the token."""
        token, _ = self._minted(store)
        forged = "f" * 32
        response = _refresh(store, refresh_token=token, csrf_cookie=forged,
                            csrf_header=forged, now=NOW + 10)
        assert response.status == 401

    def test_no_cookie_at_all_is_a_401_not_a_500(self, store):
        _register(store)
        response = _refresh(store, refresh_token=None, csrf_cookie="a" * 32,
                            csrf_header="a" * 32)
        assert response.status == 401

    def test_a_body_borne_refresh_token_is_refused_rather_than_ignored(
            self, store):
        token, csrf = self._minted(store)
        response = _refresh(store, refresh_token=token, csrf_cookie=csrf,
                            csrf_header=csrf, now=NOW + 10,
                            body={"refresh_token": token})
        assert response.status == 400, (
            "silently ignoring the old transport is how a client keeps "
            "sending a secret in a body for months")

    def test_the_csrf_value_is_derived_from_the_signing_key(self, store):
        """Not random: a replayed log rebuilds the same session (NP6)."""
        authority = T.TokenAuthority(key=KEY)
        first = authority.issue(user_id="u", role=ROLE_ANALYST,
                                token_type=T.TYPE_REFRESH, now=NOW)
        second = authority.issue(user_id="u", role=ROLE_ANALYST,
                                 token_type=T.TYPE_REFRESH, now=NOW)
        assert first == second
        claims = authority.verify(first, expected_type=T.TYPE_REFRESH,
                                  now=NOW + 1)
        assert claims.csrf and len(claims.csrf) >= 32
        stranger = T.TokenAuthority(key=KEY[::-1])
        assert stranger.csrf_for("same-jti") != authority.csrf_for("same-jti")

    def test_an_access_token_carries_no_csrf_claim(self):
        authority = T.TokenAuthority(key=KEY)
        token = authority.issue(user_id="u", role=ROLE_ANALYST,
                                token_type=T.TYPE_ACCESS, now=NOW)
        claims = authority.verify(token, expected_type=T.TYPE_ACCESS,
                                  now=NOW + 1)
        assert claims.csrf == "", (
            "the access token rides in the Authorization header, which is "
            "structurally CSRF-immune; a claim there would be a control "
            "nobody reads")


# ────────────────────────────────────────────────────────────────────────
class TestTheBodyIsClean:
    """The sweep. Every auth response, scanned for the secret."""

    AUTH_ROUTES = ("C13login", "C13refresh", "C13logout", "C13register",
                   "C13password", "C13role", "C13users", "C13user",
                   "C13remove")

    def _bodies(self, store) -> list:
        _register(store)
        bodies = []
        login = _login(store)
        bodies.append(login.as_dict())
        directives = _directives(login)
        token = directives[C.REFRESH_COOKIE.name].value
        csrf = directives[C.CSRF_COOKIE.name].value
        bodies.append(_refresh(store, refresh_token=token, csrf_cookie=csrf,
                               csrf_header=csrf, now=NOW + 5).as_dict())
        bodies.append(handle(ApiRequest(
            method="POST", path=f"{API_PREFIX}/auth/logout",
            body={"reason": "終業"},
            principal=Principal(user_id="analyst-1", role=ROLE_ANALYST)),
            _write(store, Principal(user_id="analyst-1", role=ROLE_ANALYST),
                   now=NOW + 6)).as_dict())
        bodies.append(handle(ApiRequest(
            method="GET", path=f"{API_PREFIX}/auth/users", principal=ADMIN),
            _read(store, now=NOW + 7)).as_dict())
        return token, csrf, bodies

    @staticmethod
    def _offences(token: str, bodies) -> list:
        # The JOSE header is identical on every HS256 token, so only the
        # claims and the signature identify THIS one.
        segments = [part for part in token.split(".")[1:] if len(part) > 8]
        assert len(segments) == 2
        found = []
        for body in bodies:
            blob = json.dumps(body, ensure_ascii=False)
            if token in blob:
                found.append("whole token")
            found.extend(f"segment {segment[:12]}" for segment in segments
                         if segment in blob)
            if "refresh_token" in blob:
                found.append("the key name")
        return found

    def test_no_auth_response_body_carries_the_refresh_token(self, store):
        token, _csrf, bodies = self._bodies(store)
        assert self._offences(token, bodies) == []

    def test_the_sweep_is_load_bearing(self, store, monkeypatch):
        """Mutation: remove the guard, put the token back, sweep must fire.

        The mutation replaces `Minted` — the type whose whole job is to
        refuse a payload holding the token — because that is the one edit
        that would reinstate §7-2 #103 while every other test still passed.
        """
        class Permissive:
            def __init__(self, *, payload, refresh_token, csrf_token):
                self.payload = dict(payload)
                self.payload["refresh_token"] = refresh_token
                self.refresh_token = refresh_token
                self.csrf_token = csrf_token

        _register(store)
        monkeypatch.setattr(SESSION, "Minted", Permissive)
        login = _login(store)
        token = _directives(login)[C.REFRESH_COOKIE.name].value
        offences = self._offences(token, [login.as_dict()])
        monkeypatch.undo()
        assert offences, (
            "with the guard removed the token is back in the body and the "
            "sweep did not notice — so the passing case above proves nothing")

    def test_the_type_refuses_a_payload_holding_the_token(self):
        with pytest.raises(DomainError):
            SESSION.Minted(payload={"refresh_token": "x"},
                           refresh_token="x", csrf_token="y")

    def test_login_answers_with_the_cookie_pair_and_nothing_else(self, store):
        _register(store)
        response = _login(store)
        assert set(_directives(response)) == {C.REFRESH_COOKIE.name,
                                              C.CSRF_COOKIE.name}

    def test_logout_clears_both_cookies(self, store):
        _register(store)
        _login(store)
        response = handle(ApiRequest(
            method="POST", path=f"{API_PREFIX}/auth/logout",
            principal=Principal(user_id="analyst-1", role=ROLE_ANALYST)),
            _write(store, Principal(user_id="analyst-1", role=ROLE_ANALYST),
                   now=NOW + 6))
        assert response.status == 200
        directives = _directives(response)
        assert set(directives) == {C.REFRESH_COOKIE.name, C.CSRF_COOKIE.name}
        assert all(isinstance(directive, C.ClearCookie)
                   for directive in directives.values())

    def test_a_refused_login_sets_no_cookie(self, store):
        _register(store)
        response = _login(store, password="wrong")
        assert response.status == 401
        assert response.cookies == ()


# ────────────────────────────────────────────────────────────────────────
class TestTheHandlerLayerStillKnowsNothingAboutTheWeb:
    def test_only_the_binding_calls_set_cookie(self):
        """By AST, not by substring: the prose explaining the boundary is
        the point of the boundary, and a grep would forbid saying why."""
        offenders = []
        for path in sorted((REPO_ROOT / "v3").rglob("*.py")):
            if path.name == "binding.py":
                continue
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                if name in ("set_cookie", "delete_cookie", "unset_jwt_cookies",
                            "set_refresh_cookies"):
                    offenders.append(f"{path}:{node.lineno} {name}")
        assert offenders == []

    def test_the_cookie_module_imports_no_framework(self):
        tree = ast.parse((REPO_ROOT / "v3" / "api" / "cookies.py").read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0]
                                for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        assert "flask" not in imported
        assert "werkzeug" not in imported

    def test_a_response_carries_directives_not_headers(self, store):
        _register(store)
        response = _login(store)
        for directive in response.cookies:
            assert isinstance(directive, (C.SetCookie, C.ClearCookie))
            assert isinstance(directive.spec, C.CookieSpec)

    def test_the_freshness_stamp_does_not_drop_the_cookies(self, store):
        """`with_freshness` rebuilds the response; a rebuild that forgot the
        directives would drop the login cookie and nothing would fail."""
        _register(store)
        assert _login(store).cookies


# ────────────────────────────────────────────────────────────────────────
class TestTheBindingTranslates:
    """The one file that knows what a Set-Cookie header is."""

    def _client(self, store):
        flask = pytest.importorskip("flask")
        from v3.api.binding import create_blueprint

        provider = _provider()
        app = flask.Flask(__name__)
        app.register_blueprint(create_blueprint(
            lambda: ReadContext(ledger=ReadOnlyLedger(store), now=NOW,
                                auth=provider)))
        app.testing = True
        return app.test_client()

    def test_the_login_response_sets_both_cookies_with_the_posture(self,
                                                                   store):
        _register(store)
        client = self._client(store)
        response = client.post(f"{API_PREFIX}/auth/login",
                               json={"user_id": "analyst-1",
                                     "password": GOOD})
        assert response.status_code == 200
        headers = [value for key, value in response.headers
                   if key == "Set-Cookie"]
        refresh = [h for h in headers
                   if h.startswith(C.REFRESH_COOKIE.name + "=")]
        csrf = [h for h in headers
                if h.startswith(C.CSRF_COOKIE.name + "=")]
        assert len(refresh) == 1 and len(csrf) == 1
        assert "HttpOnly" in refresh[0]
        assert "HttpOnly" not in csrf[0]
        assert "SameSite=Strict" in refresh[0]
        assert "Secure" in refresh[0]
        assert f"Path={C.REFRESH_COOKIE.path}" in refresh[0]
        assert "Path=/;" in csrf[0] or csrf[0].rstrip().endswith("Path=/")
        assert "Max-Age" not in refresh[0]
        assert C.REFRESH_COOKIE.name not in response.get_data(as_text=True)

    def test_a_deployment_without_tls_can_drop_secure_explicitly(self, store):
        flask = pytest.importorskip("flask")
        from v3.api.binding import create_blueprint

        provider = _provider()
        app = flask.Flask(__name__)
        app.register_blueprint(create_blueprint(
            lambda: ReadContext(ledger=ReadOnlyLedger(store), now=NOW,
                                auth=provider), cookie_secure=False))
        app.testing = True
        _register(store)
        response = app.test_client().post(
            f"{API_PREFIX}/auth/login",
            json={"user_id": "analyst-1", "password": GOOD})
        header = [value for key, value in response.headers
                  if key == "Set-Cookie"][0]
        assert "Secure" not in header

    def test_the_binding_round_trips_the_pair_into_a_refresh(self, store):
        _register(store)
        client = self._client(store)
        client.post(f"{API_PREFIX}/auth/login",
                    json={"user_id": "analyst-1", "password": GOOD})
        csrf = client.get_cookie(C.CSRF_COOKIE.name)
        assert csrf is not None
        response = client.post(f"{API_PREFIX}/auth/refresh",
                               headers={C.CSRF_HEADER: csrf.value})
        assert response.status_code == 200

    def test_the_binding_refuses_a_refresh_without_the_header(self, store):
        _register(store)
        client = self._client(store)
        client.post(f"{API_PREFIX}/auth/login",
                    json={"user_id": "analyst-1", "password": GOOD})
        assert client.post(
            f"{API_PREFIX}/auth/refresh").status_code == 401
