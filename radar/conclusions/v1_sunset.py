"""v1 API sunset machinery — RFC 9745 Deprecation + RFC 8594 Sunset headers.

Per ADR-V2-003 (`docs/design/v2-migration.md`), v2 was activated as the
default on 2026-04-26 (Mode C) and v1 will be removed on 2026-07-26 (T+90d).
During the 90-day window, the two v1 routes that v2 directly supersedes
must advertise their pending removal so any remaining clients can migrate.

Scope is intentionally narrow: only the two v1 routes that have a v2
successor get the sunset headers. Other `/api/*` routes (history, analyst,
analytics, admin, intel) have no v2 equivalent and stay unannounced.

Wired into the global Flask `after_request` hook in `radar/__init__.py`.
"""

from __future__ import annotations

import re
from typing import Mapping

# Mapping: v1 path pattern → (successor URL template, canonical telemetry
# key). Path pattern is a compiled regex; the named groups feed the
# successor URL via str.format(). The telemetry key is the canonical
# (parameter-collapsed) form used for SR4 access counting via
# legacy_telemetry — keeps key cardinality bounded regardless of how
# many distinct scenario_ids are queried. Keep this list in sync with
# ADR-V2-003 — adding a route here promises clients a 90-day migration
# window.
SUNSETTED_V1_ROUTES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # 2026-04-29 contract revision: /api/threat_data was originally listed
    # here with successor /api/v2/scenarios/{id}/conclusions, but PF7
    # inventory work revealed the v2 conclusions endpoint cannot replace
    # threat_data — they have completely different response shapes.
    # threat_data is the HUD/Lane/map kitchen-sink driver (latestData is
    # consumed at 14+ frontend sites for sensor caches, scenario state,
    # chain events, analytics envelopes etc.); v2 conclusions returns
    # only scoring conclusions (state/confidence/formula_ref tuples).
    #
    # The contract was technically infeasible. Rather than rush a
    # large-surface frontend rewrite to invent a non-existent v2
    # threat_data successor before 2026-07-26, threat_data is removed
    # from the sunset list and stays as a permanent operational
    # endpoint. The operational state stream is no longer 'v1' in any
    # meaningful sense — it just happens to have a /api/ prefix that
    # predates the /api/v2/ scoring conclusions surface.
    #
    # /api/scenario/<id>/breakdown stays in the sunset — it has zero
    # production hits and the v2 conclusions endpoint is a genuine
    # successor (it returns the same per-scenario conclusion data).
    (
        re.compile(r"^/api/scenario/(?P<scenario_id>[^/]+)/breakdown/?$"),
        "/api/v2/scenarios/{scenario_id}/conclusions",
        "v1_sunset_route:/api/scenario/<id>/breakdown",
    ),
)

# RFC 8594 IMF-fixdate format. Hard-coded to 2026-07-26 00:00 UTC because
# the date is a contract with downstream clients — it MUST NOT shift if the
# server's clock or env changes. ADR-V2-003 promotion to DONE is gated on
# this date passing.
SUNSET_DATE_HEADER = "Sat, 26 Jul 2026 00:00:00 GMT"

# Same instant as SUNSET_DATE_HEADER, expressed as a unix epoch seconds value.
# Derived once at import time from the canonical UTC datetime so the two
# representations cannot drift. Consumed by observation tooling (scheduler
# cleanup loop) to compute days_remaining_until_sunset.
import datetime as _datetime  # noqa: E402  (intentional late import for grouping)
SUNSET_DATE_EPOCH: float = _datetime.datetime(
    2026, 7, 26, 0, 0, 0, tzinfo=_datetime.timezone.utc,
).timestamp()


def match_sunsetted_route(
    path: str,
) -> tuple[str, Mapping[str, str], str] | None:
    """Return (successor_url_template, named_groups, telemetry_key) if
    `path` is a sunsetted v1 route, else None. Pure function — safe to
    call per-request.
    """
    for pattern, successor_template, telemetry_key in SUNSETTED_V1_ROUTES:
        m = pattern.match(path)
        if m is not None:
            return successor_template, m.groupdict(), telemetry_key
    return None


def build_deprecation_headers(
    successor_template: str,
    path_groups: Mapping[str, str],
) -> dict[str, str]:
    """Build the three RFC headers for a single v1 response.

    - Deprecation: true              (RFC 9745)
    - Sunset: <IMF-fixdate>          (RFC 8594)
    - Link: <successor>; rel="successor-version"  (RFC 8288 / 8594)

    successor_template may contain `{scenario_id}` placeholder; missing
    placeholders fall back to literal "{scenario_id}" so the Link header
    is always well-formed even if route registration drifts.
    """
    try:
        successor_url = successor_template.format(**path_groups)
    except KeyError:
        successor_url = successor_template
    return {
        "Deprecation": "true",
        "Sunset": SUNSET_DATE_HEADER,
        "Link": f'<{successor_url}>; rel="successor-version"',
    }


def apply_sunset_headers_if_needed(path: str, response_headers) -> bool:
    """Mutate `response_headers` (Flask Headers, MultiDict-like) to add the
    three RFC headers iff `path` matches a sunsetted v1 route.

    Side effect: also records one access via legacy_telemetry under the
    canonical (parameter-collapsed) key so SR4 sunset evaluation can
    track residual v1 traffic without exploding key cardinality.
    Telemetry failure is swallowed — it must never break the request path.

    Returns True if headers were applied (caller may use the signal for
    monitoring / logging). Idempotent on headers — calling twice on the
    same response leaves the headers in the same state. The telemetry
    counter is *not* idempotent: each call increments it (which is the
    intended behaviour for an access counter).
    """
    match = match_sunsetted_route(path)
    if match is None:
        return False
    successor_template, groups, telemetry_key = match
    for k, v in build_deprecation_headers(successor_template, groups).items():
        response_headers[k] = v
    try:
        from radar import legacy_telemetry as _lt
        _lt.record_legacy_access(telemetry_key)
    except Exception:  # noqa: BLE001
        pass  # Telemetry must never break the request path.
    return True
