"""`tor_metrics` — S1-SENSI-019..021. Censorship read off the Tor network.

Two free Onionoo endpoints, one country each: `/summary` gives the running
relay count, `/clients` gives the bridge-user estimate. The verdict is the
PAIR — a relay count that fell **and** a bridge-user count that surged is
`CENSORSHIP_INDICATOR`, because circumvention rising while capacity falls
is what deliberate blocking looks like from outside.

**DP12: both halves of that verdict were process memory.**
`_prev_relay_counts` and `_prev_user_counts` are instance dictionaries
(`radar/sensors/tor_metrics.py:34-35`), and production seeds a missing
entry with the CURRENT reading (`:70`, `:104`), so after a restart the
first cycle computes `drop_pct = 0` and `surge_pct = 0` — no drop, no
surge, status NORMAL. The sensor reports a calm network because it has
forgotten what the network looked like, and nothing in the output says so.
The two counters are declared as L1 baselines here and the verdict is
withheld until they arrive (§7-2 #9's family), rather than being computed
against a default that manufactures calm.

**One country, two payloads.** `normalize` sees exactly one already-fetched
body (§2-2 barrier 1), so the join that produces the four-way status cannot
happen in this layer. Each half lands under its own `signal_source` —
`tor_metrics` for the relay row (production's `add_rat` name, and WP-2.8's
join key) and `tor_clients` for the client row. That is a CONSTRAINT and
not a preference: L1 is `UNIQUE (tick_id, sensor, signal_source, country)`
and two rows under one name are either a `DomainError` or, when the scores
match — which is exactly the quiet case — silently dropped. §7-2 #11.

**A user surge alone does not fire.** `_tor_fired` tests membership of
`("RELAY_DROP", "CENSORSHIP_INDICATOR")` (`radar/routes/core.py:1560`), so
`USER_SURGE` scores zero. It looks like an oversight and it is production's
behaviour; changing it here would be an unregistered sensitivity change.
"""
from __future__ import annotations

from typing import Mapping

from v3.adapters.common import (as_float, as_int, country_of, list_or_empty,
                                load_json, mapping_or_empty)
from v3.adapters.types import (AdapterId, INFO, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_OBSERVED)
from v3.kernel import Window

TOR_METRICS = AdapterId("tor_metrics")

ONIONOO_BASE = "https://onionoo.torproject.org"
SUMMARY_URL = f"{ONIONOO_BASE}/summary"
CLIENTS_URL = f"{ONIONOO_BASE}/clients"

#: `radar/sensors/tor_metrics.py:25-26`, transcribed. Named "fallback"
#: there because they were meant to hold only until an adaptive z-score
#: warmed up; no such z-score was ever built, so these ARE the thresholds.
RELAY_DROP_FALLBACK_PCT = 0.40
USER_SURGE_FALLBACK_PCT = 1.00
#: The DROP arm (`:108`). Deliberately NOT the negation of the surge arm —
#: production's ladder is asymmetric, and symmetrising it while porting is
#: exactly the tidying that turns a transcription into a rewrite.
USER_DROP_PCT = -0.3

#: `add_rat("tor_metrics", "info", ...)` (`radar/routes/core.py:1576`).
#: The effective `signal_source` is the sensor name, because no explicit
#: kwarg is passed (`rat.signal_source or rat.sensor`,
#: `radar/scoring.py:81`).
SIGNAL_SOURCE = "tor_metrics"
#: The client half's name. Production has no second `add_rat` entry to
#: borrow from — the two readings are folded into one row before scoring —
#: so this name is new, and §7-2 records it as such. It exists because L1
#: refuses the collision, not because the reading deserves its own row.
CLIENT_SIGNAL_SOURCE = "tor_clients"

#: `radar/routes/core.py:1561`, and `tor_metrics.py:129-136` for the ladder
#: those scores are attached to.
STATUS_SCORES: dict = {
    "CENSORSHIP_INDICATOR": 2.0,
    "RELAY_DROP": 1.0,
    #: Zero on purpose — see the module docstring.
    "USER_SURGE": 0.0,
    "NORMAL": 0.0,
}
FIRING_STATUSES: tuple[str, ...] = ("RELAY_DROP", "CENSORSHIP_INDICATOR")

#: `time.sleep(0.5)` between per-country requests (`:81`, `:118`). Declared
#: rather than slept: a `sleep` inside the sensor is "how to fetch", and it
#: also made the legacy suite pay the delay in real seconds.
TOR_MIN_INTERVAL_SEC = 0.5
#: `super().__init__("tor_metrics", "info", 1800)` (`:33`).
_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
#: The Tor consensus refreshes roughly hourly (`:9`), so a reading older
#: than two consensus periods is describing a network that has moved.
_FRESHNESS_HORIZON_SEC = 2 * 3600.0

_SUMMARY = "summary"
_CLIENTS = "clients"


def running_relays(document: Mapping) -> tuple[int, int, int]:
    """`(running_relays, running_bridges, bandwidth)` — `:66-68`.

    The bandwidth sum is over RUNNING relays only, which is what makes it
    available capacity rather than an inventory of registered hardware.
    """
    relays = list_or_empty(document.get("relays"))
    bridges = list_or_empty(document.get("bridges"))
    running = sum(1 for entry in relays if mapping_or_empty(entry).get("r"))
    up_bridges = sum(1 for entry in bridges
                     if mapping_or_empty(entry).get("r"))
    bandwidth = sum(as_int(mapping_or_empty(entry).get("bw"), 0) or 0
                    for entry in relays if mapping_or_empty(entry).get("r"))
    return running, up_bridges, bandwidth


def bridge_users(document: Mapping, country: str) -> float:
    """The country's column of every bridge's `average_clients` (`:98-102`).

    The key is LOWER CASE. Onionoo publishes it that way and production
    looks it up that way (`cc_lower = code.lower()`), so an upper-case
    lookup would find nothing and report zero bridge users for every
    country — a floor that reads as "no circumvention traffic" rather than
    as a lookup that never matched.
    """
    code = str(country or "").lower()
    total = 0.0
    for entry in list_or_empty(document.get("bridges")):
        clients = mapping_or_empty(mapping_or_empty(entry).get(
            "average_clients"))
        if code in clients:
            total += as_float(clients[code], 0.0) or 0.0
    return total


def combined_status(relay_drop: bool, user_surge: bool) -> str:
    """The four-way ladder (`tor_metrics.py:129-136`).

    Exported because the join that can actually evaluate it belongs to
    WP-4.1 (§7-2 #11), and the reduction step must call this rather than
    write the ladder a second time — DP4 is what two copies of one rule
    costs.
    """
    if relay_drop and user_surge:
        return "CENSORSHIP_INDICATOR"
    if relay_drop:
        return "RELAY_DROP"
    if user_surge:
        return "USER_SURGE"
    return "NORMAL"


def _relay_draft(document: Mapping, country: str, url: str
                 ) -> ObservationDraft:
    running, bridges, bandwidth = running_relays(document)
    return ObservationDraft(
        signal_source=SIGNAL_SOURCE, domain=INFO, country=country,
        # OBSERVED, not OK: `drop_pct` needs the previous cycle, so no
        # verdict has been reached. OK would say "measured, nothing
        # wrong", and a blind spot reported as calm is the failure NP1 is
        # written against.
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"relays={running}, bridge_users=pending",
        flags={
            "running": running,
            "bridges": bridges,
            "bandwidth_kbps": bandwidth,
            # `drop_pct` is a NUMBER in production (`:78`) and `status` is
            # compared against a closed set of strings (`core.py:1560`).
            # Neither key may carry the marker: a consumer reading them as
            # their declared types would either raise or read the marker
            # as a permanent alarm. The verdict keys are ABSENT — "not
            # stated" — and a sibling names why (§7-2 #9's rule).
            "drop_verdict": "pending_l1_prev_relay_count",
        },
        evidence_url=url)


def _client_draft(document: Mapping, country: str, url: str
                  ) -> ObservationDraft:
    users = bridge_users(document, country)
    return ObservationDraft(
        signal_source=CLIENT_SIGNAL_SOURCE, domain=INFO, country=country,
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"bridge_users={users:g}",
        flags={
            "bridge_users": users,
            "trend_verdict": "pending_l1_prev_user_count",
        },
        evidence_url=url)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One Onionoo response for one country.

    Which endpoint answered is read from the request label, because both
    carry the same `?country=` parameter and the two documents share the
    key `bridges` with different meanings — a relay summary's bridges are
    bridge descriptors, a clients response's are usage series. Guessing
    from the body would read one as the other.
    """
    country = country_of(payload, context)
    if not country:
        return ()
    document = load_json(payload)
    if not isinstance(document, Mapping):
        return ()
    kind = str(payload.label or "").split(":", 1)[0]
    if kind == _CLIENTS:
        return (_client_draft(document, country, payload.url),)
    if kind == _SUMMARY:
        return (_relay_draft(document, country, payload.url),)
    return ()


TOR_METRICS_ADAPTER = SourceAdapter(
    adapter_id=TOR_METRICS, category=INFO,
    requests=(
        # `{country_lower}` rather than `{country}`: production sends
        # `code.lower()` (`:54`, `:89`) and Onionoo matches case-
        # sensitively, so an upper-case code returns HTTP 200 with an
        # empty relay list — which reads as a country with no Tor presence
        # rather than as a request the server refused.
        RequestSpec(url=SUMMARY_URL, expect_content="json",
                    params=(("country", "{country_lower}"),),
                    headers={"Accept": "application/json"},
                    label=f"{_SUMMARY}:{{country}}"),
        RequestSpec(url=CLIENTS_URL, expect_content="json",
                    params=(("country", "{country_lower}"),),
                    headers={"Accept": "application/json"},
                    label=f"{_CLIENTS}:{{country}}"),
    ),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="onionoo", min_interval_sec=TOR_MIN_INTERVAL_SEC,
    baseline_refs=("tor_prev_relay_count", "tor_prev_user_count"))

__all__ = ["TOR_METRICS", "TOR_METRICS_ADAPTER", "normalize",
           "running_relays", "bridge_users", "combined_status",
           "ONIONOO_BASE", "SUMMARY_URL", "CLIENTS_URL",
           "RELAY_DROP_FALLBACK_PCT", "USER_SURGE_FALLBACK_PCT",
           "USER_DROP_PCT", "STATUS_SCORES", "FIRING_STATUSES",
           "SIGNAL_SOURCE", "CLIENT_SIGNAL_SOURCE", "TOR_MIN_INTERVAL_SEC"]
