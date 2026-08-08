"""The write half of the baseline supply — an explicit, separate stage.

F-05 / S5-VERIF-019: statistics move in a stage of their own, never
inside a read. `v3/runtime/baselines.py` reads; this writes; the cycle
calls them in that order and nothing else calls either. The consequence
that matters is ordering — production records the current hour BEFORE
reading and its read excludes the current bucket, so recording first is
harmless there. Here the read happens at the top of the cycle and the
write at the bottom, which reaches the same place by a shorter route: a
reading is never compared with itself.

What is recorded is taken from the observations the cycle just WROTE,
not from the drafts in flight. A baseline built from something the ledger
does not hold is a baseline no replay can reproduce.
"""
from __future__ import annotations

import json
from typing import Any, Mapping, Optional, Sequence

from v3.ledger.baselines import record_bucket_sample
from v3.runtime.baselines import ENTITY_BASELINES, PHASE_BASELINES

#: `ref -> (sensor, signal_source, flag key holding the sample)`.
#: Only the refs whose sample v3 actually produces appear here;
#: `cf_attack_share_baseline` is absent because nothing in v3 computes
#: production's `avg_spike` (see `VERDICT_WITHHELD`), and recording a
#: different quantity under the same `baseline_id` would corrupt 28
#: migrated days with a series that means something else.
PHASE_SAMPLES: Mapping[str, tuple] = {
    "bgp_hod": ("ripe_bgp", "bgp", "announced_prefixes"),
    "checkhost_hod": ("check_host", "check_host", "success_rate"),
    "gdelt_dow_tone": ("gdelt", "gdelt", "tone"),
}


def _flags(row: Optional[Mapping]) -> dict:
    if not row:
        return {}
    flags = row.get("flags")
    if isinstance(flags, str):
        try:
            flags = json.loads(flags)
        except ValueError:
            return {}
    return dict(flags) if isinstance(flags, Mapping) else {}


def _row(store, *, now: float, sensor: str, signal_source: str,
         country: str) -> dict:
    return _flags(store.latest_signal_at(now, sensor=sensor, country=country,
                                         signal_source=signal_source))


def record_phase_samples(store, *, now: float,
                         countries: Sequence[str]) -> dict:
    """One sample per bucket per country. Returns `{ref: rows written}`."""
    written: dict = {}
    for ref, (sensor, signal_source, key) in PHASE_SAMPLES.items():
        baseline = PHASE_BASELINES[ref]
        count = 0
        for country in countries:
            value = _row(store, now=now, sensor=sensor,
                         signal_source=signal_source,
                         country=country).get(key)
            if value is None:
                continue
            count += int(record_bucket_sample(
                store, baseline_id=baseline.baseline_id,
                sensor=baseline.sensor, country=country,
                bucket=baseline.bucket_of(now), value=float(value),
                max_entries=baseline.max_entries, now=now))
        written[ref] = count
    return written


def record_entity_state(store, *, now: float,
                        countries: Sequence[str]) -> dict:
    """Per-entity state, from the rows the cycle wrote. `{ref: touched}`."""
    written = {"ct_log_domain_first_observed": 0,
               "ct_log_known_ca_per_domain": 0,
               "checkhost_latency_history": 0,
               "ais_vessel_history": 0}
    for country in countries:
        written["ct_log_domain_first_observed"] += _record_ct_log(
            store, now=now, country=country, written=written)
        written["checkhost_latency_history"] += _record_check_host(
            store, now=now, country=country)
        written["ais_vessel_history"] += _record_ais(store, now=now,
                                                     country=country)
    return written


def _record_ct_log(store, *, now: float, country: str, written: dict) -> int:
    flags = _row(store, now=now, sensor="ct_log", signal_source="ct_log",
                 country=country)
    domains = [str(name) for name in flags.get("watched_domains", ()) if name]
    for domain in domains:
        store.touch_entity_marker(series="ct_log_domain_first_observed",
                                  sensor="ct_log", entity=domain, now=now)
    # Production records the CA for EVERY observation it inspects,
    # including the one it is firing on (`ct_log.py:315-341`) — which is
    # what makes an untrusted issuer fire ONCE and then be known. Only the
    # candidates are recorded here because the globally trusted ones never
    # reach the membership test (`is_trusted or is_known_per_domain`), so
    # the verdict is identical and the ledger is smaller. Registered as
    # §7-2 #74: the SET differs, the verdict does not.
    seen = 0
    for candidate in flags.get("untrusted_ca_candidates", ()):
        domain = str(candidate.get("domain") or "").strip().lower()
        member = str(candidate.get("ca_normalized") or "").strip().lower()
        if not domain or not member:
            continue
        store.touch_entity_marker(series="ct_log_known_ca_per_domain",
                                  sensor="ct_log", entity=domain,
                                  member=member, now=now)
        seen += 1
    written["ct_log_known_ca_per_domain"] += seen
    return len(domains)


def _record_check_host(store, *, now: float, country: str) -> int:
    flags = _row(store, now=now, sensor="check_host",
                 signal_source="check_host", country=country)
    latencies = flags.get("url_latency") or {}
    baseline = ENTITY_BASELINES["checkhost_latency_history"]
    count = 0
    for url, latency in latencies.items():
        if latency is None or not url:
            continue
        store.append_entity_observation(
            series=baseline.ref, sensor=baseline.sensor, entity=str(url),
            observed_at=now, value=float(latency),
            max_samples=baseline.per_entity, now=now)
        count += 1
    return count


def _record_ais(store, *, now: float, country: str) -> int:
    flags = _row(store, now=now, sensor="ais_maritime",
                 signal_source="ais_maritime", country=country)
    baseline = ENTITY_BASELINES["ais_vessel_history"]
    count = 0
    for report in flags.get("vessel_reports", ()):
        mmsi = str(report.get("mmsi") or "")
        if not mmsi:
            continue
        store.append_entity_observation(
            series=baseline.ref, sensor=baseline.sensor, entity=mmsi,
            observed_at=now,
            # `last_ts` is the vessel's OWN timestamp, which is what the
            # gap is measured from (`ais_maritime.py:114`) — not the time
            # we happened to look.
            value=float(report.get("last_ts") or now),
            payload={"lat": report.get("lat"), "lng": report.get("lng"),
                     "last_ts": report.get("last_ts")},
            max_samples=baseline.per_entity, now=now)
        count += 1
    return count


def record_cycle(store, *, now: float, countries: Sequence[str]) -> dict:
    """Every baseline this cycle can advance. Called once, after the write."""
    recorded: dict[str, Any] = dict(
        record_phase_samples(store, now=now, countries=countries))
    recorded.update(record_entity_state(store, now=now, countries=countries))
    return recorded


__all__ = ["record_cycle", "record_phase_samples", "record_entity_state",
           "PHASE_SAMPLES"]
