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

# Mapping: v1 path pattern → v2 successor URL template.
# Path pattern is a compiled regex; the named groups feed the successor
# URL via str.format(). Keep this list in sync with ADR-V2-003 — adding a
# route here promises clients a 90-day migration window.
SUNSETTED_V1_ROUTES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^/api/threat_data/?$"),
        "/api/v2/scenarios/{scenario_id}/conclusions",
    ),
    (
        re.compile(r"^/api/scenario/(?P<scenario_id>[^/]+)/breakdown/?$"),
        "/api/v2/scenarios/{scenario_id}/conclusions",
    ),
)

# RFC 8594 IMF-fixdate format. Hard-coded to 2026-07-26 00:00 UTC because
# the date is a contract with downstream clients — it MUST NOT shift if the
# server's clock or env changes. ADR-V2-003 promotion to DONE is gated on
# this date passing.
SUNSET_DATE_HEADER = "Sat, 26 Jul 2026 00:00:00 GMT"


def match_sunsetted_route(path: str) -> tuple[str, Mapping[str, str]] | None:
    """Return (successor_url_template, named_groups) if `path` is a
    sunsetted v1 route, else None. Pure function — safe to call per-request.
    """
    for pattern, successor_template in SUNSETTED_V1_ROUTES:
        m = pattern.match(path)
        if m is not None:
            return successor_template, m.groupdict()
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

    Returns True if headers were applied (caller may use the signal for
    monitoring / logging). Idempotent — calling twice on the same response
    leaves the headers in the same state.
    """
    match = match_sunsetted_route(path)
    if match is None:
        return False
    successor_template, groups = match
    for k, v in build_deprecation_headers(successor_template, groups).items():
        response_headers[k] = v
    return True
