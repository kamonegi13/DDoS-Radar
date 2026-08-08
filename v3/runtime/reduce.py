"""N per-payload drafts -> the ONE row production writes per country.

`normalize` is called once per fetched payload and sees exactly that
payload (§2-2 barrier 1). Production does not work that way: it sweeps a
country's ISR zones and sums the counts BEFORE asking whether the total
reached the surge threshold, pools three RIPE Atlas measurements' RTTs
BEFORE taking a p95, and folds BGP hijacks and route leaks into one
disjunction. None of those folds can happen in a function that can only
see one payload, so they happen here — design sheet §3-5 H-1(b)/(c) and
§7-2 #11/#12/#13/#23/#28/#29/#31/#41/#51.

**The order is the finding, not a detail.** Three aircraft over each of
two zones is a six-aircraft surge in production and two non-surges in a
per-zone threshold. Thresholding before summing does not merely round
differently; it removes a detection, which under NP1 is the worst
available outcome.

**A missing reduction is loud.** `signal_observation` is UNIQUE on
`(tick_id, sensor, signal_source, country)`; a re-record with different
content raises `DomainError` and — worse — a re-record with IDENTICAL
content is dropped without a word (`store.py:282-295`, S5-VERIF-019).
`reduce_drafts` therefore checks the uniqueness invariant for EVERY
adapter, reduced or not, and names the register entry in the failure. An
adapter that grows a second per-country row now fails here, at the layer
that can fix it, instead of at the ledger or in silence.

Everything in this module is a pure function of its arguments. Baseline
values arrive as a mapping the caller read from L1 (`v3/runtime/baselines.py`),
in the same shape and for the same reason `NormalizeContext` takes
geography rather than reading `geo_data.json`: a reduction that reads a
database mid-fold cannot be replayed, and replay is what parity rests on.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping, Optional, Sequence

from v3.adapters.cyber.cloudflare_radar import (BGP_HIJACK_SIGNAL,
                                                BGP_LEAK_SIGNAL,
                                                LEAK_FIRE_THRESHOLD)
from v3.adapters.info.gdelt import BASELINE_SIGNAL_SOURCE as \
    GDELT_BASELINE_SIGNAL
from v3.adapters.info.gdelt import SIGNAL_SOURCE as GDELT_SIGNAL
from v3.adapters.info.rss_narrative import feed_source as _feed_source
from v3.adapters.info.telegram_mirror import CHANNEL_SOURCE_PREFIX
from v3.adapters.info.tor_metrics import (CLIENT_SIGNAL_SOURCE as
                                          TOR_CLIENT_SIGNAL)
from v3.adapters.info.tor_metrics import FIRING_STATUSES as TOR_FIRING_STATUSES
from v3.adapters.info.tor_metrics import (RELAY_DROP_FALLBACK_PCT,
                                          USER_SURGE_FALLBACK_PCT,
                                          combined_status)
from v3.adapters.info.tor_metrics import SIGNAL_SOURCE as TOR_SIGNAL
from v3.adapters.info.tor_metrics import STATUS_SCORES as TOR_STATUS_SCORES
from v3.adapters.info.travel_advisory import SOURCE_PREFIX as \
    ADVISORY_SOURCE_PREFIX
from v3.adapters.physical.check_host import URL_OK_RATE as \
    CHECK_HOST_URL_OK_RATE
from v3.adapters.physical.ihr_health import LADDER_RANK
from v3.adapters.physical.opensky import (AWACS_ACTIVE, ISR_SURGE_THRESHOLD,
                                          TANKER_SURGE, TRANSPORT_SURGE,
                                          support_reason)
from v3.adapters.physical.ripe_atlas import (drop_pct, percentile_95,
                                             status_for)
from v3.adapters.physical.space_weather import storm_level
from v3.adapters.types import (INFO, PHYSICAL, STATUS_FIRED, STATUS_NO_DATA,
                               STATUS_OBSERVED, STATUS_OK, STATUS_SUPPRESSED,
                               ObservationDraft)
from v3.kernel.errors import DomainError

#: Production's per-URL "this URL is up" line (`checkhost.py:225-233`),
#: taken from the adapter that already declares it rather than restated.
CHECKHOST_URL_OK_RATE = CHECK_HOST_URL_OK_RATE
#: `space_weather.py:117` — the two suppressors are OR-ed, and the joined
#: sentence is rebuilt rather than concatenated from the halves.
SPACE_WEATHER_KP_THRESHOLD = 6.0
SPACE_WEATHER_XRAY_CLASS = "M"

#: `ripe_atlas` score ladder (`core.py:1536`).
ATLAS_BLACKOUT = "PROBE_BLACKOUT"
ATLAS_DROP = "PROBE_DROP"

#: The per-feed prefix `rss_narrative` invents (`feed_source("x")` ->
#: `"narrative_x"`). Derived by calling the adapter's own function rather
#: than written out: a second copy of a naming rule is a second thing to
#: keep in step, and this one exists only until the fold retires it.
NARRATIVE_SOURCE_PREFIX = _feed_source("")

#: Where a baseline the reduction needs but did not receive is named, so
#: an unfinished verdict says which value it is waiting for instead of
#: reporting a verdict it could not reach. Same discipline as §7-2 #9's:
#: the marker never occupies a key whose type a consumer relies on.
PENDING_PREFIX = "pending_l1_"


@dataclass(frozen=True, slots=True)
class Reduction:
    """One adapter's fold, with its provenance attached.

    `register_ref` and `production_ref` are carried so the disclosure can
    say WHY a row looks the way it does without a second table to keep in
    step — NP6 applied to the composition root's own arithmetic.
    """

    adapter_id: str
    fold: Callable[[Sequence[ObservationDraft], Mapping[str, Any]],
                   Sequence[ObservationDraft]]
    register_ref: str
    production_ref: str
    note: str = ""


def _by_country(drafts: Sequence[ObservationDraft]) -> dict:
    grouped: dict = {}
    for draft in drafts:
        grouped.setdefault(draft.country, []).append(draft)
    return grouped


def _first_url(drafts: Sequence[ObservationDraft]) -> Optional[str]:
    for draft in drafts:
        if draft.evidence_url:
            return draft.evidence_url
    return None


def _min_confidence(drafts: Sequence[ObservationDraft]) -> float:
    """The weakest input governs the fold.

    Taking the mean would let one healthy zone raise the confidence of a
    country whose other zone could not be read — the direction that hides
    a partial outage.
    """
    return min((draft.confidence for draft in drafts), default=1.0)


def _measured(drafts: Sequence[ObservationDraft],
              key: str) -> list[ObservationDraft]:
    """Zones whose payload was readable.

    An unmeasured zone contributes NOTHING, not zero. Production's
    equivalent is structural — a failed box never reaches
    `results[theater]` (`isr_hotspot.py:96-100`) — and a zero would sum in
    as a real observation of no aircraft.
    """
    return [d for d in drafts
            if d.status != STATUS_NO_DATA and int(d.flags.get(key, 0) or 0) >= 0]


def _coverage(measured: Sequence, total: Sequence) -> dict:
    """What the fold actually saw, always recorded (NP6).

    Partial coverage that is not disclosed is the same output as full
    coverage, and the difference is exactly a missed detection.
    """
    return {"zones_folded": len(measured),
            "zones_requested": len(total),
            "zones_unmeasured": len(total) - len(measured)}


# ── §3-5 H-1(b)(c): ISR hotspots ────────────────────────────────────────

def _fold_isr(drafts: Sequence[ObservationDraft],
              baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """Sum the country's zones, THEN threshold (`isr_hotspot.py:85-107`).

    `hotspots[]` is concatenated rather than summarised because two
    consumers read it per zone: `core.py:2929-2931` joins the ledger's
    `ISR_HOTSPOTS` to the observation on `name` to populate the map
    overlay's `tracks`, and `core.py:1231`'s ISR_SURGE sequence payload
    carries the array whole. Dropping it leaves the overlay rendering with
    every zone's track list empty — an absence that looks like calm.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        measured = _measured(group, "count")
        if not measured:
            reduced.append(replace(
                group[0],
                flags={**dict(group[0].flags), **_coverage(measured, group)}))
            continue
        count = sum(int(d.flags.get("count", 0)) for d in measured)
        is_surge = count >= ISR_SURGE_THRESHOLD
        hotspots = [zone for d in measured
                    for zone in list(d.flags.get("hotspots", ()))]
        tracks = [track for d in measured
                  for track in list(d.flags.get("tracks", ()))]
        reduced.append(ObservationDraft(
            signal_source="isr_hotspot", domain=PHYSICAL, country=country,
            status=STATUS_FIRED if is_surge else STATUS_OK,
            raw_score=2.0 if is_surge else 0.0,
            confidence=_min_confidence(measured),
            value=f"{count} ISR ac in hotspot",
            reason=f"ISR surge: {count} aircraft" if is_surge else "",
            flags={"count": count, "is_surge": is_surge,
                   "tracks": tracks[:5], "hotspots": hotspots,
                   **_coverage(measured, group)},
            evidence_url=_first_url(measured)))
    return reduced


def _fold_mil_air(drafts: Sequence[ObservationDraft],
                  baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """`mil_support_air.py:128-158`. Sum per category, then the OR ladder.

    Three thresholds, each applied to a country total: tankers >= 2,
    transports >= 3, AWACS >= 1. Per zone they would each need the whole
    formation over one box.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        measured = [d for d in group if d.status != STATUS_NO_DATA]
        if not measured:
            reduced.append(replace(
                group[0],
                flags={**dict(group[0].flags), **_coverage(measured, group)}))
            continue
        tanker = sum(int(d.flags.get("tanker", 0)) for d in measured)
        transport = sum(int(d.flags.get("transport", 0)) for d in measured)
        awacs = sum(int(d.flags.get("awacs", 0)) for d in measured)
        is_tanker_surge = tanker >= TANKER_SURGE
        is_transport_surge = transport >= TRANSPORT_SURGE
        is_awacs_active = awacs >= AWACS_ACTIVE
        is_surge = is_tanker_surge or is_transport_surge or is_awacs_active
        score = 2.0 if (is_awacs_active and is_tanker_surge) else (
            1.0 if is_surge else 0.0)
        hotspots = [zone for d in measured
                    for zone in list(d.flags.get("hotspots", ()))]
        tracks = [track for d in measured
                  for track in list(d.flags.get("tracks", ()))]
        reduced.append(ObservationDraft(
            signal_source="mil_support_air", domain=PHYSICAL, country=country,
            status=STATUS_FIRED if is_surge else STATUS_OK, raw_score=score,
            confidence=_min_confidence(measured),
            value=f"T={tanker} C={transport} A={awacs}",
            reason=support_reason(tanker, transport, awacs, is_tanker_surge,
                                  is_transport_surge, is_awacs_active),
            flags={"tanker": tanker, "transport": transport, "awacs": awacs,
                   "total": tanker + transport + awacs,
                   "is_tanker_surge": is_tanker_surge,
                   "is_transport_surge": is_transport_surge,
                   "is_awacs_active": is_awacs_active, "is_surge": is_surge,
                   "tracks": tracks[:5], "hotspots": hotspots,
                   **_coverage(measured, group)},
            evidence_url=_first_url(measured)))
    return reduced


# ── §7-2 #12/#13: Cloudflare BGP disjunction ────────────────────────────

def _fold_cf_bgp(drafts: Sequence[ObservationDraft],
                 baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """hijack OR leak -> the single `cf_bgp_hijack` entry (`core.py:1150-1170`).

    The port's docstring assumed S1-SCORE-008's MAX fold would reassemble
    the disjunction downstream. It would not have: the two halves shared a
    `signal_source`, so L1 rejected the second row before any scoring saw
    it (§7-2 #12). They were split into two names to survive the ledger,
    and rejoined here, where the country's whole picture exists.

    Untouched rows pass through: `cf_l3` / `cf_l7` are OBSERVED shares
    whose spike verdict belongs to the scoring layer's DDoS time series,
    not to this fold.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        hijack = next((d for d in group
                       if d.signal_source == BGP_HIJACK_SIGNAL), None)
        leak = next((d for d in group
                     if d.signal_source == BGP_LEAK_SIGNAL), None)
        reduced.extend(d for d in group
                       if d.signal_source not in (BGP_HIJACK_SIGNAL,
                                                  BGP_LEAK_SIGNAL))
        if hijack is None and leak is None:
            continue
        hijacks = int((hijack.flags.get("count", 0) if hijack else 0) or 0)
        ongoing = int((hijack.flags.get("ongoing", 0) if hijack else 0) or 0)
        leaks = int((leak.flags.get("count", 0) if leak else 0) or 0)
        fired = ongoing > 0 or leaks >= LEAK_FIRE_THRESHOLD
        present = [d for d in (hijack, leak) if d is not None]
        reduced.append(ObservationDraft(
            signal_source=BGP_HIJACK_SIGNAL, domain=present[0].domain,
            country=country,
            status=STATUS_FIRED if fired else STATUS_OK,
            raw_score=1.0 if fired else 0.0,
            confidence=_min_confidence(present),
            value=f"hijack={hijacks}(ongoing={ongoing}) leak={leaks}",
            reason=(f"BGP manipulation detected: {ongoing} ongoing "
                    f"hijack(s), {leaks} route leak(s)") if fired else "",
            flags={"hijacks": hijacks, "ongoing": ongoing, "leaks": leaks,
                   "leak_fire_threshold": LEAK_FIRE_THRESHOLD,
                   "events": [event for d in present
                              for event in list(d.flags.get("events", ()))],
                   "folded_sources": [d.signal_source for d in present]},
            evidence_url=_first_url(present)))
    return reduced


# ── §7-2 #11: space weather's two endpoints ─────────────────────────────

def _fold_space_weather(drafts: Sequence[ObservationDraft],
                        baselines: Mapping[str, Any]
                        ) -> list[ObservationDraft]:
    """Kp OR X-ray -> one suppressor row (`space_weather.py:102-140`).

    One of the two cases §7-2 #11 records as ALREADY colliding: both
    endpoints emit `signal_source="space_weather"` with `country=""`, so
    without this fold the second row either raises or vanishes.

    The joined sentence is rebuilt from the parts rather than concatenated
    from the halves' own `suppress_reason` strings: production's combined
    wording is "Geomagnetic storm: Kp=6.3 (>=6.0), X-ray M-class (>=M) —
    physical sensor noise expected", which is not either half's sentence.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        kp_row = next((d for d in group
                       if d.flags.get("endpoint") == "kp"), None)
        xray_row = next((d for d in group
                         if d.flags.get("endpoint") == "xray"), None)
        others = [d for d in group if d not in (kp_row, xray_row)]
        reduced.extend(others)
        present = [d for d in (kp_row, xray_row) if d is not None]
        if not present:
            continue
        kp_index = float(kp_row.flags.get("kp_index", 0.0) or 0.0) \
            if kp_row else 0.0
        kp_forecast = float(kp_row.flags.get("kp_forecast_24h", 0.0) or 0.0) \
            if kp_row else 0.0
        xray = str(xray_row.flags.get("xray_class", "")) if xray_row else ""
        kp_triggers = bool(kp_row and kp_row.flags.get("suppress_physical"))
        xray_triggers = bool(xray_row
                             and xray_row.flags.get("suppress_physical"))
        suppress = kp_triggers or xray_triggers
        level = storm_level(max(kp_index, kp_forecast))

        parts = []
        if kp_triggers:
            parts.append(f"Kp={kp_index:.1f} "
                         f"(≥{SPACE_WEATHER_KP_THRESHOLD})")
        if xray_triggers:
            parts.append(f"X-ray {xray}-class "
                         f"(≥{SPACE_WEATHER_XRAY_CLASS})")
        reason = (f"Geomagnetic storm: {', '.join(parts)} — physical "
                  f"sensor noise expected") if suppress else None
        reduced.append(ObservationDraft(
            signal_source="space_weather", domain=PHYSICAL, country=country,
            status=STATUS_SUPPRESSED if suppress else STATUS_OK,
            # A suppressor, never a contributor (`core.py:1407`).
            raw_score=0.0, confidence=_min_confidence(present),
            suppressed=suppress, suppress_reason=reason,
            value=f"Kp={kp_index:.1f} xray={xray} [{level}]",
            flags={"kp_index": kp_index, "kp_forecast_24h": kp_forecast,
                   "xray_class": xray, "storm_level": level,
                   "suppress_physical": suppress,
                   "kp_triggers": kp_triggers, "xray_triggers": xray_triggers,
                   "folded_endpoints": [str(d.flags.get("endpoint"))
                                        for d in present]},
            evidence_url=_first_url(present)))
    return reduced


# ── §7-2 #28/#29: RIPE Atlas probes + three measurements ────────────────

def _fold_ripe_atlas(drafts: Sequence[ObservationDraft],
                     baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """Pool the RTTs, THEN take p95 (`ripe_atlas.py:133,137-147`).

    A pooled p95 cannot be recovered from three per-measurement p95s,
    which is why the drafts carry `rtt_samples` rather than only their own
    summary. `collect_rtts` / `percentile_95` are called rather than
    re-derived: DP4 is a catalogue of the same arithmetic implemented
    twice and then drifting.

    `previous_probes` (baseline `atlas_prev_probe_count`) turns the probe
    row's withheld verdict into production's ladder. Absent, the row stays
    OBSERVED and says which value it is waiting for — an unreachable
    verdict is absent from the field that carries verdicts, never False
    (§7-2 #9's discipline).
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        probe_row = next((d for d in group
                          if d.signal_source == "ripe_atlas"), None)
        latency_rows = [d for d in group
                        if d.signal_source.startswith("atlas_latency")]
        reduced.extend(d for d in group
                       if d is not probe_row and d not in latency_rows)
        if probe_row is None:
            continue
        pooled = [float(sample) for d in latency_rows
                  for sample in d.flags.get("rtt_samples", ())]
        avg_ms = round(sum(pooled) / len(pooled), 2) if pooled else 0.0
        p95_ms = percentile_95(pooled) if pooled else 0.0

        active = int(probe_row.flags.get("active", 0) or 0)
        previous = baselines.get("atlas_prev_probe_count", {}).get(country)
        flags = {"active": active, "avg_ms": avg_ms, "p95_ms": p95_ms,
                 "probes_responding": len(pooled),
                 "pool_scope": "country",
                 "folded_measurements": [
                     int(d.flags.get("measurement_id", 0) or 0)
                     for d in latency_rows]}
        if previous is None:
            reduced.append(replace(
                probe_row, value=f"{active} probes, {avg_ms:.0f}ms",
                confidence=_min_confidence([probe_row] + latency_rows),
                flags={**flags,
                       "probe_drop_verdict": PENDING_PREFIX
                       + "prev_probe_count"}))
            continue
        drop = drop_pct(float(previous), active)
        status = status_for(drop)
        fired = status in (ATLAS_DROP, ATLAS_BLACKOUT)
        score = 2.0 if status == ATLAS_BLACKOUT else (1.0 if fired else 0.0)
        reduced.append(ObservationDraft(
            signal_source="ripe_atlas", domain=PHYSICAL, country=country,
            status=STATUS_FIRED if fired else STATUS_OK, raw_score=score,
            confidence=_min_confidence([probe_row] + latency_rows),
            value=(f"{status} ({active} probes, drop={drop:.0%}, "
                   f"lat={avg_ms:.0f}ms)") if fired
            else f"{active} probes, {avg_ms:.0f}ms",
            reason=(f"RIPE Atlas: {status} — {active} active probes "
                    f"(drop {drop:.0%}), avg latency {avg_ms:.0f}ms")
            if fired else "",
            flags={**flags, "drop_pct": drop, "probe_status": status,
                   "previous_probes": float(previous)},
            evidence_url=probe_row.evidence_url))
    return reduced


# ── §7-2 #11: check_host's up-to-three URLs ─────────────────────────────

def _fold_check_host(drafts: Sequence[ObservationDraft],
                     baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """`checkhost.py:225-239`: a URL is up at >= 80%, the country is the
    fraction of its URLs that are up.

    Three URLs per country all arrive as `signal_source="check_host"` with
    DIFFERENT `value` strings, so writing them unreduced raises at L1
    rather than halving anything — the right failure, and still a gap.

    The BLACKOUT / PARTIAL verdict needs `checkhost_hod`'s same-hour
    history, which L1 cannot yet answer (the migrated buckets hold raw
    epoch hours, not hour-of-day). Until it can, the row stays OBSERVED
    and names the baseline it wants.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        rated = [d for d in group
                 if d.flags.get("success_rate") is not None]
        if not rated:
            reduced.append(replace(
                group[0], flags={**dict(group[0].flags),
                                 "urls_folded": 0,
                                 "urls_requested": len(group)}))
            continue
        ok_count = sum(1 for d in rated
                       if float(d.flags["success_rate"])
                       >= CHECKHOST_URL_OK_RATE)
        rate = ok_count / len(rated)
        latencies = [float(d.flags["avg_latency_ms"]) for d in rated
                     if d.flags.get("avg_latency_ms") is not None]
        reduced.append(ObservationDraft(
            signal_source="check_host", domain=PHYSICAL, country=country,
            status=STATUS_OBSERVED, raw_score=0.0,
            confidence=_min_confidence(rated),
            value=f"success={rate:.0%}",
            flags={"success_rate": rate,
                   "urls_ok": ok_count, "urls_folded": len(rated),
                   "urls_requested": len(group),
                   "ok_nodes": sum(int(d.flags.get("ok_nodes", 0) or 0)
                                   for d in rated),
                   "total_nodes": sum(int(d.flags.get("total_nodes", 0) or 0)
                                      for d in rated),
                   "avg_latency_ms": (round(sum(latencies) / len(latencies), 2)
                                      if latencies else None),
                   "url_verdict": PENDING_PREFIX + "checkhost_hod",
                   "asphyxiation_verdict": PENDING_PREFIX
                   + "latency_history"},
            evidence_url=_first_url(rated)))
    return reduced


# ── §7-2 #23: AIS chokepoints ───────────────────────────────────────────

def _fold_ais(drafts: Sequence[ObservationDraft],
              baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """One row per country; the printed counts span the whole cycle.

    Production's `value` counts `len(ais_dark_gaps)` and
    `len(ais_stationary)` across EVERY chokepoint fetched this cycle
    (`core.py:1256`), not only the country's own — while the FIRED
    decision is the country's. Both facts are kept: the country's
    stationary anomalies decide, and the cycle-wide totals print.
    """
    cycle_stationary = sum(
        len(list(d.flags.get("stationary_anomalies", ()))) for d in drafts)
    reduced = []
    for country, group in _by_country(drafts).items():
        measured = [d for d in group if d.status != STATUS_NO_DATA]
        if not measured:
            reduced.append(replace(
                group[0], flags={**dict(group[0].flags),
                                 "chokepoints_folded": 0,
                                 "chokepoints_requested": len(group)}))
            continue
        stationary = [item for d in measured
                      for item in list(d.flags.get("stationary_anomalies", ()))]
        fired = bool(stationary)
        reduced.append(ObservationDraft(
            signal_source="ais_maritime", domain=PHYSICAL, country=country,
            status=STATUS_FIRED if fired else STATUS_OK,
            raw_score=1.0 if fired else 0.0,
            confidence=_min_confidence(measured),
            value=f"dark_gaps=0 stationary={cycle_stationary}",
            reason=("AIS Dark Gap / Stationary Anomaly at chokepoint"
                    if fired else ""),
            flags={"stationary_anomalies": stationary[:10],
                   "stationary_count": len(stationary),
                   "cycle_stationary_count": cycle_stationary,
                   "vessels_examined": sum(
                       int(d.flags.get("vessels_examined", 0) or 0)
                       for d in measured),
                   "vessel_reports": [report for d in measured
                                      for report in
                                      list(d.flags.get("vessel_reports", ()))],
                   "chokepoints": [str(d.flags.get("chokepoint", ""))
                                   for d in measured],
                   "chokepoints_folded": len(measured),
                   "chokepoints_requested": len(group),
                   "dark_gap_detection": PENDING_PREFIX + "vessel_history"},
            evidence_url=_first_url(measured)))
    return reduced


# ── §7-2 #31: IHR's three-rung ladder ───────────────────────────────────

def _fold_ihr(drafts: Sequence[ObservationDraft],
              baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """`min(ladder_rank)` decides the country's state (`ihr.py:167-177`).

    The three rows keep their own `signal_source` — `bgp`, `ihr_delay` and
    `ihr_hegemony` are scored (or not) independently in production, so
    folding them into one would DELETE two contributions. What the fold
    produces is the derived country label the precedence chain computes,
    written onto every row so the suppression join and the deep-analysis
    view read a fact rather than re-deriving the order a second time.
    """
    rank_to_status = {rank: status for status, rank in LADDER_RANK.items()}
    reduced = []
    for country, group in _by_country(drafts).items():
        ranks = [int(d.flags.get("ladder_rank", 0) or 0) for d in group
                 if d.flags.get("ladder_rank")]
        winner = rank_to_status.get(min(ranks)) if ranks else None
        for draft in group:
            reduced.append(replace(draft, flags={
                **dict(draft.flags),
                "country_status": winner or "NORMAL",
                "country_status_rank": min(ranks) if ranks
                else max(LADDER_RANK.values())}))
    return reduced


# ── §7-2 #41/#51: the info domain's per-source rows ─────────────────────

def _fold_tor(drafts: Sequence[ObservationDraft],
              baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """`/summary` + `/clients` -> one `tor_metrics` entry (`core.py:1553-1579`).

    Production reconciles the two responses before writing anything; the
    two rows exist in v3 only because `normalize` sees one response at a
    time and `signal_source` has to differ for both to survive L1.

    The four-rung status needs both previous counts. With neither, the row
    stays OBSERVED and names what it wants — `USER_SURGE` scores 0 in
    production anyway, so guessing here would buy nothing and could assert
    a relay drop that did not happen.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        relay = next((d for d in group if d.signal_source == TOR_SIGNAL), None)
        client = next((d for d in group
                       if d.signal_source == TOR_CLIENT_SIGNAL), None)
        present = [d for d in (relay, client) if d is not None]
        reduced.extend(d for d in group if d not in present)
        if not present:
            continue
        running = int((relay.flags.get("running", 0) if relay else 0) or 0)
        users = float((client.flags.get("bridge_users", 0)
                       if client else 0) or 0)
        prev_relays = baselines.get("tor_prev_relay_count", {}).get(country)
        prev_users = baselines.get("tor_prev_user_count", {}).get(country)
        flags = {"running": running, "bridge_users": users,
                 "bridges": int((relay.flags.get("bridges", 0)
                                 if relay else 0) or 0),
                 "bandwidth_kbps": (relay.flags.get("bandwidth_kbps")
                                    if relay else None),
                 "folded_sources": [d.signal_source for d in present]}
        if prev_relays is None or prev_users is None:
            reduced.append(ObservationDraft(
                signal_source=TOR_SIGNAL, domain=INFO, country=country,
                status=STATUS_OBSERVED, raw_score=0.0,
                confidence=_min_confidence(present),
                value=f"relays={running}, users={users:g}",
                flags={**flags,
                       "drop_verdict": PENDING_PREFIX + "prev_relay_count",
                       "trend_verdict": PENDING_PREFIX + "prev_user_count"},
                evidence_url=_first_url(present)))
            continue
        drop = drop_pct(float(prev_relays), running)
        surge = ((users - float(prev_users)) / max(float(prev_users), 1.0)
                 if float(prev_users) > 0 else 0.0)
        status = combined_status(drop >= RELAY_DROP_FALLBACK_PCT,
                                 surge >= USER_SURGE_FALLBACK_PCT)
        score = float(TOR_STATUS_SCORES.get(status, 0))
        fired = status in TOR_FIRING_STATUSES
        trend = "SURGE" if surge >= USER_SURGE_FALLBACK_PCT else "NORMAL"
        reduced.append(ObservationDraft(
            signal_source=TOR_SIGNAL, domain=INFO, country=country,
            status=STATUS_FIRED if fired else STATUS_OK, raw_score=score,
            confidence=_min_confidence(present),
            value=(f"{status} (relays={running}, drop={drop:.0%}, "
                   f"users={users:g} [{trend}])") if fired
            else f"relays={running}, users={users:g}",
            reason=(f"Tor: {status} — relays={running} (drop {drop:.0%}), "
                    f"bridge_users={users:g}") if fired else "",
            flags={**flags, "drop_pct": drop, "surge_pct": surge,
                   "combined_status": status, "trend": trend},
            evidence_url=_first_url(present)))
    return reduced


def _fold_gdelt(drafts: Sequence[ObservationDraft],
                baselines: Mapping[str, Any]) -> list[ObservationDraft]:
    """The 1d window and the history window -> one entry (`gdelt.py:57`).

    The baseline window's tone is carried into the surviving row's flags
    rather than discarded: it is the second half of the delta production
    computes, and the day the day-of-week baseline is wired the fold needs
    it in the same place.
    """
    reduced = []
    for country, group in _by_country(drafts).items():
        current = next((d for d in group
                        if d.signal_source == GDELT_SIGNAL), None)
        baseline = next((d for d in group
                         if d.signal_source == GDELT_BASELINE_SIGNAL), None)
        reduced.extend(d for d in group if d not in (current, baseline))
        if current is None:
            if baseline is not None:
                reduced.append(replace(baseline,
                                       signal_source=GDELT_SIGNAL))
            continue
        extra: dict = {"folded_sources": [
            d.signal_source for d in (current, baseline) if d is not None]}
        if baseline is not None:
            extra["baseline_tone"] = baseline.flags.get("tone")
            extra["baseline_window"] = baseline.flags.get("window")
            tone = current.flags.get("tone")
            if tone is not None and extra["baseline_tone"] is not None:
                extra["tone_delta"] = round(
                    float(tone) - float(extra["baseline_tone"]), 4)
        reduced.append(replace(
            current, flags={**dict(current.flags), **extra}))
    return reduced


def _fold_named_sources(signal_source: str, prefix_of,
                        detail_keys: Sequence[str]):
    """A fold for "N named rows, one production entry" (§7-2 #51).

    `telegram_mirror`, `rss_narrative` and `travel_advisory` share a
    shape: production folds channels / feeds / governments and only THEN
    names the entry, so no per-source name exists to borrow and the L0
    rows had to invent one. The invented names disappear here; what each
    contributed stays, in `sources`, because an analyst asked "which
    channel" needs an answer that survived the fold.

    The verdict itself is not synthesised. Each of the three needs a
    baseline (a 30-day keyword frequency, a previous advisory level) that
    L1 cannot yet answer, and a fold that guessed would be asserting a
    burst it did not measure.
    """
    def fold(drafts: Sequence[ObservationDraft],
             baselines: Mapping[str, Any]) -> list[ObservationDraft]:
        reduced = []
        for country, group in _by_country(drafts).items():
            members = [d for d in group
                       if d.signal_source.startswith(prefix_of)]
            reduced.extend(d for d in group if d not in members)
            if not members:
                continue
            usable = [d for d in members if d.status != STATUS_NO_DATA]
            carried = usable or members
            sources = [{"signal_source": d.signal_source,
                        "status": d.status, "value": d.value,
                        **{k: d.flags.get(k) for k in detail_keys}}
                       for d in members]
            pending = {k: v for d in members for k, v in d.flags.items()
                       if isinstance(v, str) and v.startswith(PENDING_PREFIX)}
            reduced.append(ObservationDraft(
                signal_source=signal_source, domain=INFO, country=country,
                status=STATUS_OBSERVED if usable else STATUS_NO_DATA,
                raw_score=0.0, confidence=_min_confidence(carried),
                value="; ".join(d.value for d in carried if d.value),
                flags={"sources": sources, "sources_folded": len(usable),
                       "sources_requested": len(members),
                       "folded_sources": [d.signal_source for d in members],
                       **pending},
                evidence_url=_first_url(carried)))
        return reduced
    return fold


REDUCTIONS: tuple[Reduction, ...] = (
    Reduction("isr_hotspot", _fold_isr, "§3-5 H-1(b)(c)",
              "radar/sensors/isr_hotspot.py:85-107 / core.py:1218-1246",
              "sum the country's zones, then threshold; concatenate "
              "hotspots[] so the overlay join on `name` still resolves"),
    Reduction("mil_support_air", _fold_mil_air, "§3-5 H-1(b)",
              "radar/sensors/mil_support_air.py:128-158 / core.py:1753-1800",
              "sum per category, then the three-threshold OR ladder"),
    Reduction("cloudflare_radar", _fold_cf_bgp, "§7-2 #12, #13",
              "radar/routes/core.py:1150-1170",
              "hijack OR leak into one cf_bgp_hijack entry"),
    Reduction("space_weather", _fold_space_weather, "§7-2 #11",
              "radar/sensors/space_weather.py:102-140 / core.py:1404-1410",
              "Kp OR X-ray; the joined sentence is rebuilt, not "
              "concatenated"),
    Reduction("ripe_atlas", _fold_ripe_atlas, "§7-2 #28, #29",
              "radar/sensors/ripe_atlas.py:133,137-147 / core.py:1533-1547",
              "pool RTTs across measurements, then p95"),
    Reduction("check_host", _fold_check_host, "§7-2 #11",
              "radar/sensors/checkhost.py:225-239 / core.py:1370-1383",
              "fraction of the country's URLs that are up"),
    Reduction("ais_maritime", _fold_ais, "§7-2 #11, #23",
              "radar/routes/core.py:1249-1259",
              "one row per country; printed counts span the cycle"),
    Reduction("ihr_health", _fold_ihr, "§7-2 #31",
              "radar/sensors/ihr.py:167-177",
              "min(ladder_rank) is the precedence chain, as data"),
    Reduction("tor_metrics", _fold_tor, "§7-2 #41",
              "radar/routes/core.py:1553-1579",
              "/summary and /clients reconciled into one entry"),
    Reduction("gdelt", _fold_gdelt, "§7-2 #41",
              "radar/sensors/gdelt.py:57 / core.py:1127-1132",
              "the two windows become one entry carrying the delta"),
    Reduction("telegram_mirror",
              _fold_named_sources("telegram_mirror", CHANNEL_SOURCE_PREFIX,
                                  ("channel", "detection_status",
                                   "keyword_hits", "target_urls")),
              "§7-2 #51", "radar/routes/core.py:1349-1356",
              "channels fold into one theatre entry"),
    Reduction("rss_narrative",
              _fold_named_sources("rss_narrative", NARRATIVE_SOURCE_PREFIX,
                                  ("feed", "adversary", "keyword_hits",
                                   "article_count", "normalized_freq")),
              "§7-2 #51", "radar/routes/core.py:1197-1216",
              "feeds fold into one theatre entry"),
    Reduction("travel_advisory",
              _fold_named_sources("travel_advisory", ADVISORY_SOURCE_PREFIX,
                                  ("source", "level", "level_label",
                                   "title")),
              "§7-2 #51", "radar/routes/core.py:1660-1690",
              "the three governments fold into one entry"),
)

BY_ADAPTER: Mapping[str, Reduction] = {r.adapter_id: r for r in REDUCTIONS}


def reduced_adapter_ids() -> tuple[str, ...]:
    return tuple(sorted(BY_ADAPTER))


def registry_disclosure() -> list[dict]:
    """Every fold this layer performs, with its provenance (NP6)."""
    return [{"adapter_id": r.adapter_id, "register_ref": r.register_ref,
             "production_ref": r.production_ref, "note": r.note}
            for r in REDUCTIONS]


def _require_writable(adapter_id: str,
                      drafts: Sequence[ObservationDraft]) -> None:
    """One row per `(signal_source, country)`, or say what collided.

    L1 would catch this too, but badly: a same-key row with different
    content raises from inside a transaction, and a same-key row with
    IDENTICAL content is discarded without a word (`store.py:290`). The
    second shape is how a fold that was never written becomes an
    observation that was never made.
    """
    seen: dict = {}
    for draft in drafts:
        key = (draft.signal_source, draft.country or "GLOBAL")
        if key in seen:
            raise DomainError(
                f"{adapter_id} produced {seen[key] + 1} rows for "
                f"signal_source={draft.signal_source!r} "
                f"country={draft.country or 'GLOBAL'!r} after reduction. "
                f"L1 is UNIQUE on (tick_id, sensor, signal_source, country): "
                f"identical rows are dropped SILENTLY and differing ones "
                f"raise inside the write. Give this adapter a fold in "
                f"v3/runtime/reduce.py (design sheet §7-2 #11) or give the "
                f"rows distinct signal_source values.")
        seen[key] = seen.get(key, 0) + 1


def reduce_drafts(adapter_id: str, drafts: Sequence[ObservationDraft], *,
                  baselines: Optional[Mapping[str, Any]] = None
                  ) -> tuple[ObservationDraft, ...]:
    """Fold one adapter's cycle output, and refuse to return an unwritable set.

    PURE. `baselines` is what the caller already read from L1; nothing
    here opens a database, so a fold can be replayed from recorded
    payloads exactly as it ran.

    Adapters with no declared fold pass through — and are still checked,
    which is the point: the check is what turns "nobody wrote a reducer
    for the adapter that grew a second row" from a silent halving into a
    sentence naming the adapter.
    """
    supplied = dict(baselines or {})
    reduction = BY_ADAPTER.get(adapter_id)
    result = tuple(reduction.fold(tuple(drafts), supplied)) if reduction \
        else tuple(drafts)
    _require_writable(adapter_id, result)
    return result


__all__ = ["Reduction", "REDUCTIONS", "BY_ADAPTER", "reduce_drafts",
           "reduced_adapter_ids", "registry_disclosure",
           "CHECKHOST_URL_OK_RATE", "PENDING_PREFIX"]
