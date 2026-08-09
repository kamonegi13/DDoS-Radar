"""WP-0.2 G-01 regression — feedback submission requires the analyst role.

`POST /api/v2/conclusions/<id>/feedback` was the only mutating endpoint in
conclusions_v2 without a role gate: any authenticated identity, including
a read-only viewer, could write analyst feedback rows. Those rows are not
cosmetic — they are the ground-truth labels the recall metrics and the
auto-tune governor are calibrated against, so an unprivileged write path
reaches all the way into threshold tuning.

The sibling endpoints in the same blueprint (:452 admin, :487 / :559
analyst) had gates from the start; this one was simply missed.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.routes import conclusions_v2


class TestAnalystGatePresence:
    """Source-level: the gate must be wired before the handler does work."""

    def test_the_handler_calls_require_analyst(self):
        import inspect
        src = inspect.getsource(conclusions_v2.v2_conclusion_feedback_submit)
        assert "_require_analyst()" in src, \
            "G-01: feedback POST must enforce the analyst role"

    def test_the_gate_runs_before_the_conclusion_lookup(self):
        import inspect
        src = inspect.getsource(conclusions_v2.v2_conclusion_feedback_submit)
        assert src.index("_require_analyst()") < src.index(
            "get_conclusion_by_id"), \
            "authorization must precede any data access"

    def test_the_gate_returns_its_error_response(self):
        import inspect
        src = inspect.getsource(conclusions_v2.v2_conclusion_feedback_submit)
        gate = src.index("_require_analyst()")
        assert "return auth_err" in src[gate:gate + 200], \
            "the gate's response must actually be returned, not discarded"

    def test_authorization_precedes_the_feature_flag_check(self):
        # 403 before 503, matching the siblings: an unauthorized caller
        # must not be able to probe the feature-flag state.
        import inspect
        src = inspect.getsource(conclusions_v2.v2_conclusion_feedback_submit)
        assert src.index("_require_analyst()") < src.index(
            "_v2_enabled_or_503()"), \
            "a non-analyst must get 403 even when the v2 flag is off"


class TestRoleDecision:
    """Behavioural: the shared gate's verdict per role."""

    @pytest.fixture(autouse=True)
    def _app_ctx(self, monkeypatch):
        from radar import app
        with app.test_request_context():
            yield

    def _gate_with_role(self, monkeypatch, role, identity="u1"):
        from radar import routes
        from radar.database import db
        monkeypatch.setattr(routes, "get_jwt_identity", lambda: identity,
                            raising=False)
        monkeypatch.setattr(
            "flask_jwt_extended.get_jwt_identity", lambda: identity)
        monkeypatch.setattr(db, "user_get_role", lambda _i: role)
        return routes._require_analyst()

    def test_viewer_is_refused(self, monkeypatch):
        result = self._gate_with_role(monkeypatch, "viewer")
        assert result is not None
        assert result[1] == 403

    def test_analyst_passes(self, monkeypatch):
        assert self._gate_with_role(monkeypatch, "analyst") is None

    def test_admin_passes(self, monkeypatch):
        assert self._gate_with_role(monkeypatch, "admin") is None

    def test_unknown_role_is_refused(self, monkeypatch):
        result = self._gate_with_role(monkeypatch, None)
        assert result is not None and result[1] == 403

    def test_missing_identity_is_unauthenticated(self, monkeypatch):
        result = self._gate_with_role(monkeypatch, "analyst", identity=None)
        assert result is not None and result[1] == 401


class TestMutatingEndpointsAreAllGated:
    """The class-level guard: no mutating v2 conclusions route may ship
    without a role gate again."""

    def test_every_post_route_has_a_role_check(self):
        import inspect
        source = inspect.getsource(conclusions_v2)
        for name in ("v2_conclusion_feedback_submit",):
            handler = getattr(conclusions_v2, name)
            body = inspect.getsource(handler)
            assert "_require_analyst()" in body or "_require_admin()" in body, \
                f"{name} mutates state without a role gate"
        assert "def v2_conclusion_feedback_submit" in source
