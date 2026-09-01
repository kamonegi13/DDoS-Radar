"""P8 §9 / NP9 — the observation board: what was seen, and where we looked.

The definition amendment of 2026-08-14 makes the visible representation
of observations a first-class product beside conclusions (NP9). This
projection feeds the situation map's observation layer: per-country
signal counts over a fixed window, each country carrying its SWEEP BAND.
The band is not decoration — a map that draws only counts shows "not
swept" as "quiet", which is G-17's newest shape: under C-lite the
focused scenario's participants are swept per-country every tick and
everyone else is reached only by globally-sweeping adapters.

Read-side only (P9 §1.8 audit ruling ①): the dense set derives from the
same focus state and scenario refs the tick's sweep scope is built from,
and the counts fold `signals_between` rows. No tick write path is
touched — the C-16 clock survives this projection existing.
"""
from __future__ import annotations

from v3.api.envelope import ApiResponse, tool_response
from v3.commands.state import focus_state

#: One day. Wide enough that a daily-cadence global adapter's reach is
#: visible, narrow enough that the map answers "now", and comfortably
#: inside SIGNAL_RETENTION_DAYS (60) — the projection never promises a
#: window the ledger cannot honour (P8 §9).
OBSERVATION_WINDOW_SEC = 86400.0

BAND_DENSE = "dense"     # focused participants: swept per-country each tick
BAND_GLOBAL = "global"   # reached only by globally-sweeping adapters
BAND_SILENT = "silent"   # on the roster, not densely swept, nothing landed

#: NP6 for the representation face: where each half of the projection
#: comes from, stated on the wire rather than in a doc nobody serves.
BASIS = {
    "bands_from": "focus_state × scenario participants — the same inputs "
                  "the tick's C-lite sweep scope is built from "
                  "(v3/runtime/tick.py); dense = focused participants",
    "counts_from": "signal_observation rows via ledger.signals_between; "
                   "suppressed rows are counted apart, never dropped (E-17)",
}


def _sweep_sets(context, focused) -> tuple[set, set]:
    """(densely swept countries, full roster) from the scenario refs."""
    dense: set = set()
    roster: set = set()
    for ref in context.scenarios:
        participants = {str(c).upper() for c in ref.participants}
        roster |= participants
        is_focused = (ref.scenario_id == focused if focused is not None
                      else ref.focused)
        if is_focused:
            dense = participants
    return dense, roster


def read_observation_board(context) -> ApiResponse:
    """R16. One row per country the tool watches or has heard from."""
    now = context.now
    focused = focus_state(context.ledger, until=now)
    dense, roster = _sweep_sets(context, focused)

    counts: dict = {}
    for row in context.ledger.signals_between(
            now - OBSERVATION_WINDOW_SEC, now):
        country = str(row.get("country") or "GLOBAL").upper()
        domain = str(row.get("domain") or "unknown")
        cell = counts.setdefault(country, {}).setdefault(
            domain, {"fired": 0, "suppressed": 0})
        # E-17 at fold granularity: a suppressed observation is evidence
        # of looking, counted apart from the fired ones, never dropped.
        cell["suppressed" if row.get("suppressed") else "fired"] += 1

    countries = []
    for country in sorted(roster | set(counts)):
        observed = counts.get(country, {})
        if country in dense:
            band = BAND_DENSE
        elif observed:
            band = BAND_GLOBAL
        else:
            band = BAND_SILENT
        countries.append({
            "country": country,
            "band": band,
            "domains": observed,
            "fired_total": sum(c["fired"] for c in observed.values()),
            "suppressed_total": sum(c["suppressed"]
                                    for c in observed.values()),
        })

    return tool_response(
        observed_at=now,
        window_sec=OBSERVATION_WINDOW_SEC,
        focused_scenario=focused,
        countries=countries,
        country_count=len(countries),
        bands=[BAND_DENSE, BAND_GLOBAL, BAND_SILENT],
        basis=BASIS)


__all__ = ["read_observation_board", "OBSERVATION_WINDOW_SEC",
           "BAND_DENSE", "BAND_GLOBAL", "BAND_SILENT"]
