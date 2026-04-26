"""ACLED (Armed Conflict Location & Event Data) client.

Used by the v2.0 ground-truth ETL (ADR-V2-005) to auto-correlate
``conclusions`` ledger rows with confirmed political-violence events. Not a
``BaseSensor`` because it is invoked by the ETL job, not the scoring tick:
its cadence and consumer are different from per-scenario scoring sensors.

API docs: https://apidocs.acleddata.com/
Endpoint: ``https://api.acleddata.com/acled/read``

Auth requires both ``ACLED_API_KEY`` and ``ACLED_API_EMAIL``. If either is
missing, ``fetch_events()`` returns an empty list rather than raising — the
ETL is opt-in (gated on ``V2_GROUND_TRUTH_ETL_ENABLED``) and an unconfigured
key should silently degrade to "no external evidence available" rather than
crash the pipeline (NP3).
"""

from __future__ import annotations

import datetime
import logging
import time
from dataclasses import dataclass
from typing import Optional

import requests

from radar.config import (
    ACLED_API_EMAIL,
    ACLED_API_KEY,
    GLOBAL_PROXIES,
    SSL_VERIFY,
)

log = logging.getLogger("radar.acled")

_ACLED_BASE = "https://api.acleddata.com/acled/read"
_ACLED_TIMEOUT_SEC = 20

# Map ISO-2 codes to ACLED full country names. ACLED's ``country`` filter
# expects the human-readable name. Only includes the v1 strategic set; extend
# as new scenarios are introduced.
_ISO2_TO_ACLED_COUNTRY = {
    "TW": "Taiwan",
    "JP": "Japan",
    "KR": "South Korea",
    "PH": "Philippines",
    "UA": "Ukraine",
    "RU": "Russia",
    "IL": "Israel",
    "PS": "Palestine",
    "IR": "Iran",
    "US": "United States",
    "CN": "China",
    "AU": "Australia",
    "KP": "North Korea",
}


@dataclass(frozen=True)
class ACLEDEvent:
    """One ACLED political-violence event, normalized for ETL consumption.

    Frozen so downstream classifier code can pass it around without risk of
    mutation. ``event_at`` is a unix epoch (UTC) so it composes with ledger
    ``observed_at`` directly.
    """

    country: str           # ISO-2
    event_at: float        # epoch seconds, UTC
    event_type: str        # ACLED's event_type string
    sub_event_type: str
    fatalities: int
    location: str
    source_url: str        # event-level URL (ACLED preserves source link)
    notes: str


def _country_iso2_from_acled(name: str) -> Optional[str]:
    """Reverse ``_ISO2_TO_ACLED_COUNTRY`` so we can tag inbound rows.
    Returns ``None`` for countries we do not currently track — caller should
    skip those rows."""
    for iso2, aname in _ISO2_TO_ACLED_COUNTRY.items():
        if aname == name:
            return iso2
    return None


def _parse_event_at(raw_date: str, raw_time: Optional[str] = None) -> Optional[float]:
    """ACLED returns ``event_date`` as YYYY-MM-DD. Time-of-day is rarely
    populated; default to noon UTC so within-day ordering against conclusions
    is at least monotonic by day. Returns ``None`` on parse failure so the
    caller drops the row rather than seeing a spurious epoch-0."""
    try:
        dt = datetime.datetime.strptime(raw_date, "%Y-%m-%d").replace(
            hour=12, tzinfo=datetime.timezone.utc,
        )
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def fetch_events(
    countries: list[str],
    *,
    since_epoch: float,
    until_epoch: Optional[float] = None,
    limit: int = 500,
    api_key: Optional[str] = None,
    api_email: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> list[ACLEDEvent]:
    """Pull ACLED events for the given ISO-2 countries in [since, until].

    Returns ``[]`` on missing creds, unsupported country, HTTP error, or
    empty result. Never raises on transport errors — the ETL caller treats
    missing evidence as "no signal" not "broken pipeline" (NP3).

    ``api_key`` / ``api_email`` are exposed as kwargs for testability (tests
    can pass dummies and stub ``session.get``); production callers can rely
    on the config defaults.
    """
    key = api_key if api_key is not None else ACLED_API_KEY
    email = api_email if api_email is not None else ACLED_API_EMAIL
    if not key or not email:
        log.debug("ACLED creds missing; returning no events")
        return []

    acled_country_names = [
        _ISO2_TO_ACLED_COUNTRY[c] for c in countries
        if c in _ISO2_TO_ACLED_COUNTRY
    ]
    if not acled_country_names:
        return []

    sess = session or requests
    since_dt = datetime.datetime.fromtimestamp(
        since_epoch, tz=datetime.timezone.utc,
    ).strftime("%Y-%m-%d")
    until_dt = datetime.datetime.fromtimestamp(
        (until_epoch or time.time()), tz=datetime.timezone.utc,
    ).strftime("%Y-%m-%d")

    params = {
        "key": key,
        "email": email,
        "country": "|".join(acled_country_names),
        "event_date": f"{since_dt}|{until_dt}",
        "event_date_where": "BETWEEN",
        "limit": str(max(1, min(limit, 5000))),
    }
    try:
        resp = sess.get(
            _ACLED_BASE,
            params=params,
            timeout=_ACLED_TIMEOUT_SEC,
            proxies=GLOBAL_PROXIES,
            verify=SSL_VERIFY,
        )
    except requests.RequestException as exc:
        log.warning("ACLED request failed: %s", exc)
        return []

    if resp.status_code != 200:
        log.warning("ACLED returned HTTP %s", resp.status_code)
        return []

    try:
        payload = resp.json()
    except ValueError:
        log.warning("ACLED returned non-JSON body")
        return []

    raw_rows = payload.get("data") or []
    out: list[ACLEDEvent] = []
    for row in raw_rows:
        if not isinstance(row, dict):
            continue
        iso2 = _country_iso2_from_acled(row.get("country") or "")
        if iso2 is None:
            continue
        event_at = _parse_event_at(row.get("event_date") or "")
        if event_at is None:
            continue
        try:
            fatalities = int(row.get("fatalities") or 0)
        except (TypeError, ValueError):
            fatalities = 0
        out.append(ACLEDEvent(
            country=iso2,
            event_at=event_at,
            event_type=str(row.get("event_type") or ""),
            sub_event_type=str(row.get("sub_event_type") or ""),
            fatalities=fatalities,
            location=str(row.get("location") or ""),
            source_url=str(row.get("source") or ""),
            notes=str(row.get("notes") or "")[:240],
        ))
    return out
