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

    **The warm-up branch is NOT ported and the row keeps withholding.**
    Production falls back to `drop_ratio > 0.15` below seven same-hour
    samples, where `drop_ratio` compares against an in-process baseline
    refreshed hourly (`self._baseline[code]`, `:37-45`) — an A-03 memory
    baseline that v3 does not have and that `baseline_refs` does not
    declare. Inventing a substitute would be a difference nobody
    registered; withholding is visible.
    """
    hod = baselines.get("bgp_hod")
    if hod is None:
        return list(drafts)
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
            flags["hod_verdict"] = PENDING_PREFIX + "bgp_hod_warmup"
            reduced.append(replace(draft, flags=flags))
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
        return list(drafts)
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
