"""WP-4.1 completion condition 4 — authorization is declared, not called.

G-01: four conclusion-feedback endpoints, three of which called
`_require_analyst()` and one of which did not. Nothing failed; the
forgotten call was invisible because the enforcement lived in the body,
where "absent" and "not needed" look identical.

The v3 shape is that the route table is the only place authorization is
stated, `Access` is a required field with no default, and the handler
bodies are checked — by AST — to contain no role vocabulary at all. A
handler therefore *cannot* forget the call, because there is no call to
forget.

"Public" is a decision here, not a default: `Access.public()` is an
explicit constructor with a stated reason, and the totality test below
counts it as a decision.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from v3.api import routes as R
from v3.api.authorization import (Access, ROLE_ORDER, authorize,
                                  role_is_at_least)
from v3.api.request import ANONYMOUS, Principal
from v3.api.vocabulary import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from v3.kernel.errors import DomainError

REPO_ROOT = Path(__file__).resolve().parent.parent
HANDLER_DIR = REPO_ROOT / "v3" / "api" / "handlers"

#: Every spelling of "this body decides who may call me". If a handler
#: mentions any of these, the decision has left the route table.
_ROLE_TOKENS = frozenset({"viewer", "analyst", "admin", "role", "principal",
                          "require_analyst", "require_admin", "authorize",
                          "Access", "Principal"})


class TestTheTotalityOfTheDecision:
    def test_every_declared_route_states_an_access_decision(self):
        assert R.ROUTES, "the route table is empty"
        for route in R.ROUTES:
            assert isinstance(route.access, Access), route.route_id

    def test_access_cannot_be_constructed_without_a_decision(self):
        with pytest.raises(DomainError):
            Access(public=False, minimum_role=None, reason="")

    def test_access_cannot_be_both_public_and_role_gated(self):
        with pytest.raises(DomainError):
            Access(public=True, minimum_role=ROLE_ANALYST, reason="both")

    def test_a_route_cannot_be_declared_without_an_access_field(self):
        with pytest.raises(TypeError):
            R.Route(route_id="RX", method="GET", path="/api/v3/x",
                    handler=lambda ctx, **kw: None, serves=("O-1",))

    def test_public_is_a_decision_with_a_stated_reason(self):
        for route in R.ROUTES:
            if route.access.public:
                assert route.access.reason.strip(), route.route_id

    def test_no_route_is_declared_twice(self):
        keys = [(route.method, route.path) for route in R.ROUTES]
        assert len(keys) == len(set(keys))


class TestTheHandlersCannotDecide:
    def _handler_modules(self):
        modules = sorted(HANDLER_DIR.glob("*.py"))
        assert modules, "no handler modules found"
        return [path for path in modules if path.name != "__init__.py"]

    def test_no_handler_body_mentions_role_vocabulary(self):
        offences = []
        for path in self._handler_modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                name = None
                if isinstance(node, ast.Name):
                    name = node.id
                elif isinstance(node, ast.Attribute):
                    name = node.attr
                elif isinstance(node, ast.Constant) and \
                        isinstance(node.value, str):
                    name = node.value
                if name in _ROLE_TOKENS:
                    offences.append(f"{path.name}:{node.lineno} {name}")
        assert offences == [], (
            f"a handler is deciding authorization in its body, which is "
            f"exactly the shape G-01 took: {offences}")

    def test_no_handler_module_imports_the_authorization_module(self):
        for path in self._handler_modules():
            source = path.read_text(encoding="utf-8")
            assert "authorization" not in source, path.name


class TestTheSingleTotalOrder:
    def test_the_order_is_one_constant(self):
        assert ROLE_ORDER == (ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN)

    @pytest.mark.parametrize("role,minimum,expected", [
        (ROLE_VIEWER, ROLE_VIEWER, True),
        (ROLE_VIEWER, ROLE_ANALYST, False),
        (ROLE_ANALYST, ROLE_VIEWER, True),
        (ROLE_ANALYST, ROLE_ADMIN, False),
        (ROLE_ADMIN, ROLE_ANALYST, True),
    ])
    def test_containment_not_arithmetic(self, role, minimum, expected):
        assert role_is_at_least(role, minimum) is expected

    def test_an_unknown_role_is_refused_rather_than_ranked(self):
        with pytest.raises(DomainError):
            role_is_at_least("superuser", ROLE_VIEWER)

    def test_a_principal_cannot_carry_an_unknown_role(self):
        with pytest.raises(DomainError):
            Principal(user_id="u1", role="superuser")


class TestTheGate:
    def test_anonymous_on_a_role_gated_route_is_401_not_403(self):
        failure = authorize(Access.at_least(ROLE_VIEWER, reason="r"),
                            ANONYMOUS)
        assert failure is not None and failure.status == 401

    def test_an_underprivileged_principal_is_403(self):
        failure = authorize(Access.at_least(ROLE_ANALYST, reason="r"),
                            Principal(user_id="u", role=ROLE_VIEWER))
        assert failure is not None and failure.status == 403

    def test_a_public_route_admits_anonymous(self):
        assert authorize(Access.public_route(reason="probe"), ANONYMOUS) is None

    def test_a_public_route_also_admits_a_principal(self):
        assert authorize(Access.public_route(reason="probe"),
                         Principal(user_id="u", role=ROLE_VIEWER)) is None
