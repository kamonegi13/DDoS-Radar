"""WP-0.2 G-16 regression — /api/analytics/scenario_phases returns.

The handler built each row with `_scenario_label(sc, lang)`, a helper that
existed nowhere in the repository. Every request therefore raised
NameError the moment the first scenario was reached — a guaranteed 500 on
an endpoint with no test.

The label is language-aware because Scenario carries `name_ja` / `name_en`
and the handler already parsed a `lang` query parameter. The UI is
Japanese-only since 2026-08-02, so Japanese is the default and English is
available on explicit request; neither branch may return an empty string.
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

import radar.config  # noqa: F401
from radar.routes.analytics import _scenario_label
from radar.scenarios import scenario_store


class _Stub:
    def __init__(self, sid="s1", name_ja="台湾有事", name_en="Taiwan"):
        self.id = sid
        self.name_ja = name_ja
        self.name_en = name_en


class TestScenarioLabel:
    def test_defaults_to_japanese(self):
        assert _scenario_label(_Stub(), None) == "台湾有事"

    def test_explicit_ja(self):
        assert _scenario_label(_Stub(), "ja") == "台湾有事"

    def test_english_on_request(self):
        assert _scenario_label(_Stub(), "en") == "Taiwan"

    def test_falls_back_when_the_requested_name_is_empty(self):
        assert _scenario_label(_Stub(name_ja=""), "ja") == "Taiwan"
        assert _scenario_label(_Stub(name_en=""), "en") == "台湾有事"

    def test_falls_back_to_the_id_when_both_are_empty(self):
        assert _scenario_label(_Stub(name_ja="", name_en=""), None) == "s1"

    def test_missing_attributes_do_not_raise(self):
        class _Bare:
            id = "bare"
        assert _scenario_label(_Bare(), None) == "bare"

    def test_unknown_lang_falls_back_to_japanese(self):
        assert _scenario_label(_Stub(), "fr") == "台湾有事"


class TestEndpointNoLongerRaises:
    """The defect was a NameError at the first scenario; prove the real
    loop body runs over the real scenario store."""

    def test_every_registered_scenario_gets_a_label(self):
        scenarios = list(scenario_store.all().values())
        assert scenarios, "need >=1 scenario for this to prove anything"
        for scenario in scenarios:
            label = _scenario_label(scenario, None)
            assert isinstance(label, str) and label

    def test_the_endpoint_builds_rows_without_a_nameerror(self):
        from radar import app
        with app.test_request_context("/api/analytics/scenario_phases"):
            from radar.routes import analytics
            # Call the undecorated handler body directly: the decorator is
            # auth, and G-16 was a pure NameError inside the loop.
            handler = analytics.api_scenario_phases.__wrapped__ \
                if hasattr(analytics.api_scenario_phases, "__wrapped__") \
                else analytics.api_scenario_phases
            response = handler()
            payload = response.get_json() if hasattr(response, "get_json") \
                else response
            assert payload is not None

    def test_helper_is_defined_in_the_module(self):
        from radar.routes import analytics
        assert callable(getattr(analytics, "_scenario_label", None)), \
            "G-16: the helper the handler calls must exist"
