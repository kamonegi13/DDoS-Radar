"""L1 history, read once per cycle and handed to the pure layers.

Nine adapters withhold a verdict behind a `pending_l1_*` marker because
the value they need is history, and `normalize` sees one payload
(§7-2 #8/#9/#40). The history lives in L1. Reading it is impure, so it
happens here and the result travels as a plain mapping — the same shape
and the same reason as `NormalizeContext`'s geography.

**Not every pending marker is the same kind of missing.** Three kinds, and
only the first is answerable today:

  (a) *previous-cycle scalars* — "how many relays were running last
      tick". `latest_signal_at` already returns the prior row with its
      flags, so no new storage is needed and no new job has to run.
  (b) *hour-of-day / day-of-week statistics* — `bgp_hod`, `checkhost_hod`,
      `gdelt_dow`, the Cloudflare spike baseline. The rows exist in
      `baseline_stat` but were migrated with the v1 RAW EPOCH hour as
      `bucket`, and production's query is `(hour_bucket/3600) % 24`. L1
      exposes exact-match reads only, so the same-hour history cannot be
      asked for. Closing this is a ledger decision (re-bucket forward and
      lose the migrated 28 days, or add a modulo read and keep it) and it
      is NOT taken here.
  (c) *set membership and per-entity state* — `ct_log`'s known-CA ledger
      and first-seen timestamps, `check_host`'s per-URL latency deque,
      `ais_maritime`'s per-MMSI history. `baseline_stat` is keyed
      `(baseline_id, sensor, country, bucket)` and none of these are
      keyed by country, so they need storage that does not exist.

Reporting (a) as done and (b)/(c) as done would retire §7-2 #9 while five
adapters still withhold scores — which #9 forbids in as many words. What
this module does instead is answer (a) and NAME the rest, so the gap is a
list rather than a silence.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Optional, Sequence

#: baseline name -> (sensor, flag key on the prior row).
#: The names are the adapters' own `baseline_refs` values, so the registry
#: and this table cannot drift apart without a test noticing.
PREVIOUS_CYCLE_SCALARS: Mapping[str, tuple] = {
    "atlas_prev_probe_count": ("ripe_atlas", "active"),
    "tor_prev_relay_count": ("tor_metrics", "running"),
    "tor_prev_user_count": ("tor_metrics", "bridge_users"),
    "ooni_prev_anomaly_count": ("ooni_censorship", "anomaly_count"),
    "gps_prev_ratio": ("gps_jamming", "ratio"),
    "travel_advisory_previous_level": ("travel_advisory", "level"),
}

#: Declared baselines this module cannot answer yet, with the reason.
#: Enumerated rather than omitted: an unanswerable baseline that is simply
#: absent from the mapping is indistinguishable from one nobody wired.
UNANSWERABLE: Mapping[str, str] = {
    "bgp_hod": "hour-of-day statistic; L1 has no bucket-modulo read",
    "checkhost_hod": "hour-of-day statistic; L1 has no bucket-modulo read",
    "airspace_hod": "hour-of-day statistic; not migrated (REGENERATE_ONLY)",
    "gdelt_dow_tone": "day-of-week statistic; L1 has no bucket-modulo read",
    "cf_attack_share_baseline":
        "hour-of-day statistic; L1 has no bucket-modulo read",
    "ct_log_known_ca_per_domain":
        "set membership keyed by domain; baseline_stat is keyed by country",
    "ct_log_domain_first_observed":
        "first-seen timestamp keyed by domain; no country dimension",
    "checkhost_latency_history":
        "rolling deque keyed by URL; no country dimension",
    "ais_vessel_history":
        "per-MMSI position history; not a mean/variance statistic",
    "narrative_keyword_frequency":
        "30-day rolling frequency; needs a windowed fold job",
    "telegram_keyword_frequency":
        "30-day rolling frequency; needs a windowed fold job",
    "apt_intel_dedup": "de-duplication set, not a statistic",
    "diplomatic_dedup": "de-duplication set, not a statistic",
    "military_exercise_dedup": "de-duplication set, not a statistic",
    "hacktivist_news_dedup": "de-duplication set, not a statistic",
}


def previous_cycle(store, *, now: float, countries: Sequence[str]
                   ) -> dict:
    """`{baseline_name: {country: value}}` from the prior tick's rows.

    Read strictly BEFORE this cycle writes. Reading afterwards would
    compare a count against itself and report a steady network on the day
    every relay went dark.
    """
    resolved: dict = {}
    for name, (sensor, key) in PREVIOUS_CYCLE_SCALARS.items():
        per_country = {}
        for country in countries:
            row = store.latest_signal_at(now, sensor=sensor, country=country)
            if row is None:
                continue
            value = _flag(row, key)
            if value is not None:
                per_country[country] = value
        if per_country:
            resolved[name] = per_country
    return resolved


def carried_values(store, *, now: float) -> dict:
    """Placeholders a later request needs and only a previous one knows.

    `gps_jamming` declares two plain `RequestSpec`s where the second's
    `{date}` is the newest date in the first's manifest. Two flat specs
    cannot express "B(A)" — `RequestContinuation` can and this adapter
    does not use it — so the date comes from the last cycle that read a
    manifest. Absent (a first run), the adapter is skipped as UNRESOLVED
    and counts against InputHealth; the alternative, sending the literal
    `{date}`, is a request the site answers with a 404 that this layer
    would read as "no jamming".
    """
    row = store.latest_signal_at(now, sensor="gps_jamming",
                                 country="GLOBAL")
    if row is None:
        return {}
    date = _flag(row, "date")
    return {"gps_jamming": {"date": str(date)}} if date else {}


def _flag(row: Mapping, key: str):
    flags = row.get("flags")
    if isinstance(flags, str):
        import json
        try:
            flags = json.loads(flags)
        except ValueError:
            return None
    if not isinstance(flags, Mapping):
        return None
    value = flags.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value if isinstance(value, str) and value else None
    return float(value)


def declared_names(adapters: Iterable) -> tuple[str, ...]:
    """Every `baseline_refs` entry across the registry, sorted."""
    names = set()
    for adapter in adapters:
        names.update(adapter.baseline_refs)
    return tuple(sorted(names))


def coverage(adapters: Iterable) -> dict:
    """Which declared baselines are answered, which are not, and why.

    This is the honest form of §7-2 #9's status: it cannot be retired
    while `unanswered` is non-empty, and the reasons are in the record
    rather than in a commit message.
    """
    declared = set(declared_names(adapters))
    answered = declared & set(PREVIOUS_CYCLE_SCALARS)
    unanswered = declared - answered
    return {
        "declared": sorted(declared),
        "answered": sorted(answered),
        "unanswered": sorted(unanswered),
        "reasons": {name: UNANSWERABLE.get(name, "no supply wired")
                    for name in sorted(unanswered)},
    }


__all__ = ["PREVIOUS_CYCLE_SCALARS", "UNANSWERABLE", "previous_cycle",
           "carried_values", "declared_names", "coverage"]
