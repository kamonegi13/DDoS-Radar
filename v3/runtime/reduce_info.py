"""The info-domain folds, plus the two that exist only to reach a withheld
verdict (`ripe_bgp`, `ct_log`). Half of the reductions, by module.

Split out of `reduce.py` for the 800-line house limit; the folds are
unchanged and the registry that names them stays in `reduce.py`.

Design sheet §7-2 #9/#41/#51.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping, Sequence

from v3.adapters.info.gdelt import BASELINE_SIGNAL_SOURCE as \
    GDELT_BASELINE_SIGNAL
from v3.adapters.info.gdelt import FIRED_REASON as GDELT_FIRED_REASON
from v3.adapters.info.gdelt import SIGNAL_SOURCE as GDELT_SIGNAL
from v3.adapters.info.tor_metrics import (CLIENT_SIGNAL_SOURCE as
                                          TOR_CLIENT_SIGNAL)
from v3.adapters.info.tor_metrics import FIRING_STATUSES as TOR_FIRING_STATUSES
from v3.adapters.info.tor_metrics import (RELAY_DROP_FALLBACK_PCT,
                                          USER_SURGE_FALLBACK_PCT,
                                          combined_status)
from v3.adapters.info.tor_metrics import SIGNAL_SOURCE as TOR_SIGNAL
from v3.adapters.info.tor_metrics import STATUS_SCORES as TOR_STATUS_SCORES
from v3.adapters.physical.ripe_atlas import drop_pct
from v3.adapters.types import (INFO, STATUS_FIRED, STATUS_NO_DATA,
                               STATUS_OBSERVED, STATUS_OK, ObservationDraft)
from v3.runtime import verdicts
from v3.runtime.reduce_common import (PENDING_PREFIX, _by_country,
                                      _first_url, _min_confidence)


# ── §7-2 #41/#51: the info domain's per-source rows ─────────────────────

def _fold_tor(drafts: Sequence[ObservationDraft],
              baselines: Mapping[str, Any],
              now: float) -> list[ObservationDraft]:
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
                baselines: Mapping[str, Any],
              now: float) -> list[ObservationDraft]:
    """The 1d window and the history window -> one entry (`gdelt.py:57`).

    The baseline window's tone is carried into the surviving row's flags
    rather than discarded: it is the second half of the delta production
    computes.

    The day-of-week arm of `is_alert`'s OR (`gdelt.py:73`) is decided
    here. Production ORs it with the fixed-threshold arm, which the
    adapter already fires on its own, so this can only ever ADD a firing —
    which is why a row that arrives already FIRED is left alone rather
    than re-derived.
    """
    dow = baselines.get("gdelt_dow_tone")
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
        merged = {**dict(current.flags), **extra}
        row = replace(current, flags=merged)
        tone = current.flags.get("tone")
        if dow is not None and tone is not None:
            merged.pop("dow_verdict", None)
            stat = verdicts.phase_zscore(
                dow.get(country, ()), float(tone),
                min_samples=verdicts.GDELT_DOW_MIN_SAMPLES,
                std_floor=verdicts.GDELT_DOW_STD_FLOOR)
            merged["dow_z"] = None if stat.z is None else round(stat.z, 2)
            merged["dow_n"] = stat.n
            merged["dow_mean"] = (None if stat.mean is None
                                  else round(stat.mean, 3))
            if current.status != STATUS_FIRED:
                alert = verdicts.gdelt_dow_alert(stat)
                merged["is_alert"] = alert
                merged["status"] = "ALERT" if alert else "NORMAL"
                row = replace(
                    row, flags=merged,
                    status=STATUS_FIRED if alert else STATUS_OK,
                    raw_score=1.0 if alert else 0.0,
                    value="ALERT" if alert else row.value,
                    reason=GDELT_FIRED_REASON if alert else row.reason)
        reduced.append(row)
    return reduced


# ── §7-2 #9: the two folds that exist only to reach a withheld verdict ──

def _fold_ripe_bgp(drafts: Sequence[ObservationDraft],
                   baselines: Mapping[str, Any],
                   now: float) -> list[ObservationDraft]:
    """The hour-of-day anomaly (`bgp_routing.py:67-77`, `core.py:1148`).

    `ripe_bgp` needs no cross-payload join — one country, one payload — so
    this fold exists purely because the verdict needs L1 and `normalize`
    may not read it. That is the same reason `_fold_ripe_atlas` resolves
    the probe ladder here, and doing it in one place keeps the baseline
    supply to a single channel rather than widening `NormalizeContext`
    into a second one (A-02).

    **The warm-up branch is v3's own, and it is registered (§7-2 #135).**
    Production falls back to `drop_ratio > 0.15` below seven same-hour
    samples, where `drop_ratio` compares against an in-process baseline
    refreshed hourly (`self._baseline[code]`, `:37-45`) — an A-03 memory
    baseline that v3 does not have and that `baseline_refs` does not
    declare, so transcribing it is not open to v3. Withholding instead was
    the state through WP-4.1d and it is a MISS: warm-up is not a corner,
    it is every newly registered scenario's first week.

    So the row now reaches a verdict by a route production does not have,
    from the same `bgp_hod` rows with the phase filter lifted
    (`verdicts.bgp_warmup_verdict`). The route is named on the row rather
    than hidden in the number, the band is production's 0-1, and the
    difference is registered in the SENSITIVE direction — v3 can fire
    where production's ladder would not have been consulted at all.

    Three outcomes, and they must stay three. A verdict (fired or not),
    a WITHHELD for want of history, and — when L1 supplied nothing at
    all — the untouched draft. G-17: an empty ledger must not read as a
    calm world, so `hod_verdict` carries a marker naming WHICH silence it
    is instead of `is_anomaly=False`.
    """
    hod = baselines.get("bgp_hod")
    if hod is None:
        return list(drafts)
    pooled = baselines.get("bgp_hod_pooled") or {}
    reduced = []
    for draft in drafts:
        prefixes = draft.flags.get("announced_prefixes")
        if draft.signal_source != "bgp" or prefixes is None:
            reduced.append(draft)
            continue
        stat = verdicts.bgp_hod_verdict(hod.get(draft.country, ()),
                                        float(prefixes))
        flags = {k: v for k, v in draft.flags.items() if k != "hod_verdict"}
        flags["hod_z"] = None if stat.z is None else round(stat.z, 2)
        flags["hod_n"] = stat.n
        if not stat.valid:
            reduced.append(_bgp_warmup(draft, flags, pooled, float(prefixes)))
            continue
        anomaly = verdicts.bgp_is_anomaly(stat)
        flags.update({"is_anomaly": anomaly,
                      "status": "ANOMALY" if anomaly else "NORMAL"})
        reduced.append(replace(
            draft, status=STATUS_FIRED if anomaly else STATUS_OK,
            raw_score=verdicts.BGP_ANOMALY_SCORE if anomaly else 0.0,
            value="ANOMALY" if anomaly else "NORMAL",
            reason="BGP prefix withdrawal" if anomaly else "",
            flags=flags))
    return reduced


#: Flag naming the route a `ripe_bgp` verdict took. A sibling key, never
#: the verdict field itself: §7-2 #9's discipline says a reader that asks
#: "is this an anomaly" must get an answer or nothing, and a reader that
#: asks "how was it decided" must be able to find out separately.
BGP_ROUTE = "verdict_route"
BGP_ROUTE_WARMUP = "warmup_pooled_all_hours"
#: The two silences, told apart. `_cold` is a ledger with fewer than
#: `BGP_WARMUP_MIN_SAMPLES` buckets for this country — including none.
BGP_PENDING_COLD = PENDING_PREFIX + "bgp_hod_cold"


def _bgp_warmup(draft: ObservationDraft, flags: dict,
                pooled: Mapping[str, Any], prefixes: float
                ) -> ObservationDraft:
    """§7-2 #135 — the same-hour baseline is cold; the series is not.

    Returns the row WITHHELD when the pooled series is too short as well,
    which is the genuine cold start: nothing to derive from, so nothing
    derived. The marker is a distinct string from the warm path's, so
    "seven same-hour samples away" and "seven samples of any kind away"
    are not one silence wearing one name.
    """
    stat = verdicts.bgp_warmup_verdict(pooled.get(draft.country, ()),
                                       prefixes)
    flags["warmup_n"] = stat.n
    if not stat.valid:
        flags["hod_verdict"] = BGP_PENDING_COLD
        return replace(draft, flags=flags)
    flags[BGP_ROUTE] = BGP_ROUTE_WARMUP
    flags["warmup_z"] = None if stat.z is None else round(stat.z, 2)
    flags["warmup_mean"] = None if stat.mean is None else round(stat.mean, 2)
    flags["warmup_drop_ratio"] = (None if stat.drop_ratio is None
                                  else round(stat.drop_ratio, 4))
    flags.update({"is_anomaly": stat.anomaly,
                  "status": "ANOMALY" if stat.anomaly else "NORMAL"})
    return replace(
        draft, status=STATUS_FIRED if stat.anomaly else STATUS_OK,
        raw_score=verdicts.BGP_ANOMALY_SCORE if stat.anomaly else 0.0,
        value="ANOMALY" if stat.anomaly else "NORMAL",
        reason="BGP prefix withdrawal" if stat.anomaly else "",
        flags=flags)


def _fold_ct_log(drafts: Sequence[ObservationDraft],
                 baselines: Mapping[str, Any],
                 now: float) -> list[ObservationDraft]:
    """Score 3 for an untrusted CA out of warm-up (`core.py:1836-1848`).

    §7-2 #8, the blocking-grade half of #9: production emits 3 and v3
    emitted at most 2. Two L1 facts decide it and neither is in the
    payload — the CAs this DOMAIN has used before, and when the domain was
    first seen. Both are `entity_marker` rows now.

    The wildcard verdict is untouched: it needs no history, the adapter
    already fires it at 2, and production's ladder puts untrusted ABOVE
    wildcard rather than adding them.
    """
    known = baselines.get("ct_log_known_ca_per_domain")
    first_seen = baselines.get("ct_log_domain_first_observed")
    if known is None or first_seen is None:
        # No baseline, no untrusted-CA verdict — but the per-country
        # merge is not optional: this early return once skipped it and
        # the two-domain rotation hit L1's UNIQUE key anyway.
        return _merge_ct_log_countries(list(drafts))
    reduced = []
    for draft in drafts:
        candidates = list(draft.flags.get("untrusted_ca_candidates", ()))
        domains = [str(d) for d in draft.flags.get("watched_domains", ())]
        domain = domains[0] if domains else ""
        in_warmup = verdicts.ct_log_in_warmup(first_seen.get(domain), now)
        untrusted = verdicts.ct_log_untrusted(
            candidates, known.get(domain, ()), in_warmup=in_warmup)
        flags = {k: v for k, v in draft.flags.items()
                 if k not in ("untrusted_ca_verdict", "warmup_verdict")}
        flags.update({"warmup_active": in_warmup,
                      "untrusted_ca_events": list(untrusted[:10]),
                      "untrusted_ca_count": len(untrusted)})
        wildcard = int(draft.flags.get("wildcard_count", 0) or 0) > 0
        if untrusted:
            score, reason = (verdicts.CT_LOG_UNTRUSTED_SCORE,
                             f"Untrusted CA issued for {domain or 'a watched '
                                                        'domain'}")
        elif wildcard:
            score, reason = (verdicts.CT_LOG_WILDCARD_SCORE,
                             draft.reason or "Gov-TLD wildcard certificate")
        else:
            score, reason = 0.0, ""
        fired = score > 0
        reduced.append(replace(
            draft, status=STATUS_FIRED if fired else STATUS_OK,
            raw_score=score, reason=reason,
            value=(f"untrusted={len(untrusted)} wildcard={int(wildcard)}"
                   + (" (warmup)" if in_warmup else "")),
            flags=flags))
    return _merge_ct_log_countries(reduced)


def _merge_ct_log_countries(
        reduced: Sequence[ObservationDraft]) -> list[ObservationDraft]:
    """One row per country, however many domains the rotation asked.

    Measured on the shadow, 2026-08-13, hours after the country-
    resolution fix: the rotation asks 2 domains per country, both drafts
    carried country='JP', and L1's UNIQUE (tick_id, sensor,
    signal_source, country) raised inside the write — the tick died
    whole. This fold never saw two same-country rows before that fix,
    because normalize returned () for every one of them.

    Production's shape: ONE add_rat per theater per cycle, carrying the
    verdict ladder's maximum across the theater's domains. The base row
    is the highest-scoring domain's (ties break on domain order for
    reproducibility — NP6); what every domain contributed survives in
    `domain_contributions`, the `_fold_named_sources` rule.
    """
    by_country: dict[str, list[ObservationDraft]] = {}
    for draft in reduced:
        by_country.setdefault(draft.country, []).append(draft)
    merged: list[ObservationDraft] = []
    for country, group in by_country.items():
        if len(group) == 1:
            merged.append(group[0])
            continue
        base = max(group, key=lambda d: (
            d.raw_score, -group.index(d)))
        domains = sorted({str(name) for d in group
                          for name in d.flags.get("watched_domains", ())})
        contributions = [{
            "domain": (list(d.flags.get("watched_domains", ())) or [""])[0],
            "raw_score": d.raw_score, "status": d.status,
            "value": d.value} for d in group]
        merged.append(replace(
            base,
            flags={**base.flags, "watched_domains": domains,
                   "domain_contributions": contributions,
                   "merged_rows": len(group)}))
    return merged


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
             baselines: Mapping[str, Any],
             now: float) -> list[ObservationDraft]:   # noqa: ARG001
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


def _fold_bg_observer(drafts: Sequence[ObservationDraft],
                      baselines: Mapping[str, Any],
                      now: float) -> list[ObservationDraft]:   # noqa: ARG001
    """The nine feeds' rows for one country become the ONE production scores.

    `normalize` already takes the MAX across the items INSIDE one feed body
    (`bg_observer_rss.py:181-195`), and said in the same breath that the
    fold ACROSS the nine feeds belonged here — the adapter declares nine
    `RequestSpec`s, `normalize` is called once per payload (§2-2 barrier 1),
    and two wires carrying the same war produce two rows for one country.
    That is the collision, and it is the last third of the same fold.

    **MAX, because MAX is what production computes.** The observer enqueues
    one Signal per (country, item) with no fold of its own
    (`background_observer.py:369-401`), and `dedup_by_source_country_max`
    (`radar/scoring.py:1424-1432`) keeps, per `(signal_source,
    contributing_country)`, the contribution with the largest
    `final_contribution`. For this family that ordering is the ordering of
    `raw_score`: the drain gives every bg_observer signal
    `country_weights={c: 1.0}` (`radar/routes/core.py:2103-2113`), so
    `final = raw_score x 1.0 x participant_weight` and the participant
    weight is one number per country per scenario. Ranking by `raw_score`
    here and by `final_contribution` there select the same row.

    Taking the SUM instead would be the one genuinely wrong answer. Nine
    wires reporting one strike is nine reports of one event, not nine
    events, and production is explicit that the duplicates exist to be
    deduplicated (`background_observer.py:276-279`).

    What loses is still disclosed. `feeds_matched` counts the wires that
    named this country and `folded` carries each one's score and display
    line, because "one feed mentioned Iran" and "seven did" are different
    facts about corroboration and only the winner's number survives the
    fold.
    """
    reduced: list[ObservationDraft] = []
    for country, group in _by_country(drafts).items():
        best = max(group, key=lambda draft: float(draft.raw_score))
        folded = [{"raw_score": float(d.raw_score), "value": d.value,
                   "evidence_url": d.evidence_url,
                   "items_in_feed": d.flags.get("items_in_feed")}
                  for d in group]
        items_seen = sum(int(d.flags.get("items_in_feed") or 0) for d in group)
        reduced.append(replace(
            best, flags={**dict(best.flags),
                         "feeds_matched": len(group),
                         "items_seen_total": items_seen,
                         "folded": folded}))
    return reduced
