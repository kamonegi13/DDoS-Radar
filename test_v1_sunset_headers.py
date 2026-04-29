"""Tests for v1 API sunset headers (Phase 1.4 priority 1, ADR-V2-003).

The two v1 routes superseded by v2 must carry RFC 9745 Deprecation +
RFC 8594 Sunset + RFC 8288 Link headers during the 90-day sunset window.
Other v1 routes and all v2 routes must NOT carry these headers.

Pure-function tests cover the matcher; integration tests via Flask
test_client cover the after_request wiring (deliberately don't depend on
the actual route implementations succeeding — even a 4xx response should
still carry the deprecation headers).
"""

from __future__ import annotations

import os
import secrets

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
_TEST_ADMIN_PW = os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar_api import app
from radar.auth import _hash_password
from radar.conclusions.v1_sunset import (
    SUNSET_DATE_HEADER,
    apply_sunset_headers_if_needed,
    build_deprecation_headers,
    match_sunsetted_route,
)
from radar.database import db


# ─────────────────────────────────────────────────────────────────────────
# Pure-function tests (no Flask, no DB)
# ─────────────────────────────────────────────────────────────────────────

def test_match_sunsetted_route_threat_data_no_longer_in_sunset_list():
    """2026-04-29 contract revision (PF7 / v1-sunset-inventory.md):
    /api/threat_data was removed from SUNSETTED_V1_ROUTES because v2
    conclusions endpoint cannot replace its kitchen-sink HUD/Lane/map
    response shape. The route stays as a permanent operational endpoint.
    """
    assert match_sunsetted_route("/api/threat_data") is None
    assert match_sunsetted_route("/api/threat_data/") is None


def test_match_sunsetted_route_breakdown_extracts_scenario_id():
    result = match_sunsetted_route("/api/scenario/taiwan_contingency/breakdown")
    assert result is not None
    template, groups, key = result
    assert groups == {"scenario_id": "taiwan_contingency"}
    assert template == "/api/v2/scenarios/{scenario_id}/conclusions"
    # Telemetry key is canonical — collapses across all scenario_ids
    assert key == "v1_sunset_route:/api/scenario/<id>/breakdown"


def test_match_sunsetted_route_v2_routes_unmatched():
    """v2 routes must never match — they're the successor, not the deprecated."""
    assert match_sunsetted_route("/api/v2/scenarios/foo/conclusions") is None
    assert match_sunsetted_route("/api/v2/admin/conclusion_diff_stats") is None


def test_match_sunsetted_route_other_v1_routes_unmatched():
    """Other v1 routes (history, analyst, intel, etc.) have no v2 successor
    and must NOT be advertised as sunsetted."""
    for path in (
        "/api/auth/login",
        "/api/intel/queue",
        "/api/analytics/focus_switches",
        "/api/llm_call_stats",
        "/api/scenarios",
        "/api/scenario/foo/breakdown/extra",  # path that goes deeper
        "/foo",
        "/",
    ):
        assert match_sunsetted_route(path) is None, f"unexpected match: {path}"


def test_build_deprecation_headers_full_substitution():
    headers = build_deprecation_headers(
        "/api/v2/scenarios/{scenario_id}/conclusions",
        {"scenario_id": "korea_contingency"},
    )
    assert headers["Deprecation"] == "true"
    assert headers["Sunset"] == SUNSET_DATE_HEADER
    assert headers["Link"] == (
        '</api/v2/scenarios/korea_contingency/conclusions>; '
        'rel="successor-version"'
    )


def test_build_deprecation_headers_no_substitution_needed():
    headers = build_deprecation_headers(
        "/api/v2/scenarios/{scenario_id}/conclusions", {}
    )
    # Missing placeholder falls back to literal — Link is still well-formed.
    assert headers["Link"].startswith("<")
    assert headers["Link"].endswith('rel="successor-version"')


def test_sunset_date_is_rfc8594_imf_fixdate():
    """RFC 8594 mandates IMF-fixdate (RFC 7231 §7.1.1.1):
    `<day-name>, <day> <month> <year> <hh:mm:ss> GMT`."""
    import re
    assert re.match(
        r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), "
        r"\d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
        r"\d{4} \d{2}:\d{2}:\d{2} GMT$",
        SUNSET_DATE_HEADER,
    ), SUNSET_DATE_HEADER


def test_apply_sunset_headers_idempotent():
    """Calling twice on the same response must leave headers in the same state."""
    headers: dict[str, str] = {}
    apply_sunset_headers_if_needed("/api/threat_data", headers)
    snapshot = dict(headers)
    apply_sunset_headers_if_needed("/api/threat_data", headers)
    assert headers == snapshot


def test_apply_sunset_headers_no_op_for_non_v1():
    headers: dict[str, str] = {}
    applied = apply_sunset_headers_if_needed("/api/v2/foo", headers)
    assert applied is False
    assert headers == {}


# ─────────────────────────────────────────────────────────────────────────
# Integration tests via Flask test_client
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def reset_admin_pw():
    user = db.user_get("admin")
    if user is not None:
        salt = secrets.token_hex(16)
        db.user_update_password(
            user["id"], _hash_password(_TEST_ADMIN_PW, salt), salt,
        )
    yield


@pytest.fixture
def auth_headers(client):
    resp = client.post("/api/auth/login", json={
        "username": "admin", "password": _TEST_ADMIN_PW,
    })
    assert resp.status_code == 200, resp.get_json()
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


def _assert_has_sunset_headers(resp, *, scenario_id: str | None = None):
    assert resp.headers.get("Deprecation") == "true", resp.headers
    assert resp.headers.get("Sunset") == SUNSET_DATE_HEADER, resp.headers
    link = resp.headers.get("Link", "")
    assert 'rel="successor-version"' in link, link
    assert "/api/v2/scenarios/" in link, link
    if scenario_id is not None:
        assert f"/api/v2/scenarios/{scenario_id}/conclusions" in link, link


def _assert_no_sunset_headers(resp):
    assert "Deprecation" not in resp.headers, resp.headers
    assert "Sunset" not in resp.headers, resp.headers
    link = resp.headers.get("Link")
    if link is not None:
        assert "successor-version" not in link, link


def test_threat_data_response_no_longer_carries_route_sunset_headers(client, auth_headers):
    """2026-04-29 contract revision: /api/threat_data is permanent at the
    ROUTE level (no longer in SUNSETTED_V1_ROUTES), but it still emits
    its own FIELD-level Deprecation/Sunset for `targets` /
    `strategic_alert` / `threat_history` (Sunset 2026-10-01, separate
    SR4 contract). Distinguish: the route-level sunset uses
    SUNSET_DATE_HEADER (2026-07-26) and a Link to `/api/v2/scenarios/`.
    """
    resp = client.get("/api/threat_data", headers=auth_headers)
    # Route-level sunset machinery (ADR-V2-003) must be absent:
    assert resp.headers.get("Sunset") != SUNSET_DATE_HEADER
    link = resp.headers.get("Link", "")
    assert "/api/v2/scenarios/" not in link, (
        f"route-level Link header still points to v2 successor: {link!r}"
    )
    # Field-level deprecation may still be present — that's a separate
    # contract not affected by the route sunset revision.


def test_breakdown_response_carries_sunset_headers_with_scenario_id(client, auth_headers):
    resp = client.get(
        "/api/scenario/test_phase14_sunset/breakdown",
        headers=auth_headers,
    )
    _assert_has_sunset_headers(resp, scenario_id="test_phase14_sunset")


def test_v2_routes_do_not_carry_sunset_headers(client, auth_headers):
    """v2 is the successor, not the deprecated. It must never advertise
    its own sunset (regression: would create a referential loop)."""
    resp = client.get(
        "/api/v2/scenarios/test_phase14_sunset/conclusions",
        headers=auth_headers,
    )
    _assert_no_sunset_headers(resp)


def test_other_v1_routes_do_not_carry_sunset_headers(client, auth_headers):
    """Non-superseded v1 routes (history/analyst/intel/etc.) must NOT
    advertise sunset — they have no v2 equivalent."""
    for path in (
        "/api/scenarios",
        "/api/intel/queue",
    ):
        resp = client.get(path, headers=auth_headers)
        _assert_no_sunset_headers(resp)


def test_unauthenticated_breakdown_response_still_carries_sunset_headers(client):
    """Even an unauthenticated 401 response on a sunsetted route must
    carry the headers — clients that don't yet have credentials still
    need to learn about the sunset. Uses /api/scenario/<id>/breakdown
    since it is the only remaining route in SUNSETTED_V1_ROUTES after
    the 2026-04-29 contract revision."""
    resp = client.get("/api/scenario/test_phase14_sunset/breakdown")
    _assert_has_sunset_headers(resp, scenario_id="test_phase14_sunset")


# ─────────────────────────────────────────────────────────────────────────
# Residual-access telemetry (P3) — leverages legacy_telemetry SR4 infra.
# Verifies that a v1 sunset hit increments the canonical telemetry key so
# operators can monitor 90-day window usage via /api/admin/legacy_access.
# ─────────────────────────────────────────────────────────────────────────

def test_apply_sunset_records_legacy_access_with_canonical_key():
    """Sunsetted route hits should increment the canonical telemetry key
    so operators can monitor 90-day window usage. Uses
    /api/scenario/<id>/breakdown (only remaining sunsetted route)."""
    from radar import legacy_telemetry as lt
    lt.reset_for_test()
    headers: dict[str, str] = {}
    apply_sunset_headers_if_needed(
        "/api/scenario/taiwan_contingency/breakdown", headers,
    )
    snap = lt.snapshot()
    assert "v1_sunset_route:/api/scenario/<id>/breakdown" in snap, snap
    assert snap["v1_sunset_route:/api/scenario/<id>/breakdown"].count == 1


def test_apply_sunset_collapses_scenario_id_into_canonical_key():
    """Every distinct scenario_id on the breakdown route must collapse
    into the same telemetry key — otherwise key cardinality grows
    unboundedly and the admin endpoint becomes useless."""
    from radar import legacy_telemetry as lt
    lt.reset_for_test()
    for sid in ("taiwan_contingency", "korea_contingency", "anything_else"):
        apply_sunset_headers_if_needed(
            f"/api/scenario/{sid}/breakdown", {},
        )
    snap = lt.snapshot()
    keys = [k for k in snap if k.startswith("v1_sunset_route:")]
    assert keys == ["v1_sunset_route:/api/scenario/<id>/breakdown"], keys
    assert snap["v1_sunset_route:/api/scenario/<id>/breakdown"].count == 3


def test_non_sunsetted_path_does_not_record_telemetry():
    from radar import legacy_telemetry as lt
    lt.reset_for_test()
    apply_sunset_headers_if_needed("/api/v2/scenarios/foo/conclusions", {})
    apply_sunset_headers_if_needed("/api/scenarios", {})
    snap = lt.snapshot()
    # No v1_sunset_route keys should have been recorded.
    assert not any(k.startswith("v1_sunset_route:") for k in snap), snap
