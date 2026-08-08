"""L1 history, read once per cycle and handed to the pure layers.

Adapters withhold verdicts behind `pending_l1_*` markers because the value
they need is history, and `normalize` sees one payload (§7-2 #8/#9/#40).
The history lives in L1. Reading it is impure, so it happens here and the
result travels as a plain mapping — the same shape and the same reason as
`NormalizeContext`'s geography.

**Three kinds of missing, and the ledger now answers two of them.**

  (a) *previous-cycle scalars* — "how many relays were running last
      tick". `latest_signal_at` returns the prior row with its flags.
  (b) *hour-of-day / day-of-week statistics* — the rows were migrated with
      the v1 RAW EPOCH hour as `bucket`, and production's query is a
      modulo over it. Ruling 1 added the modulo read to L1
      (`baseline_phase_values`) rather than re-bucketing, because
      re-bucketing discards 28 migrated days AND swaps production's
      rolling window for an unwindowed cumulative statistic — F-06 at the
      storage layer. `PHASE_BASELINES` below is the naming reconciliation
      that read needed: the adapters' `baseline_refs` names and the
      migrated `baseline_id`s are NOT the same strings.
  (c) *set membership and per-entity state* — `ct_log`'s known-CA ledger
      and first-seen timestamps, `check_host`'s per-URL latency,
      `ais_maritime`'s per-MMSI snapshot. Ruling 2 gave L1 a table with an
      explicit entity dimension (`entity_observation` / `entity_marker`)
      rather than putting a domain in `baseline_stat`'s `country` column.

What is left is enumerated, with a MEASURED reason, in `UNANSWERABLE`.
Reporting the whole family as done while any consumer still withholds a
score is what §7-2 #9 forbids in as many words, so `coverage()` separates
"supply wired" from "the consumer can now decide" and the tripwire test
reads the second one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from v3.ledger import records

HOUR_SEC = 3600
DAY_SEC = 86400

#: 1970-01-01 was a Thursday, and `datetime.weekday()` counts Monday as 0.
#: Production stores `weekday` in its own column; the migration copied only
#: `day_bucket`, so the phase read has to derive it — and a wrong constant
#: here silently reads SOME other weekday's history, which looks exactly
#: like a working baseline. `tests/test_ledger_phase_baselines.py` checks
#: the derivation against `datetime` over 400 days rather than trusting it.
EPOCH_DAY_WEEKDAY = 3


def weekday_of(day_bucket: float) -> int:
    """Production's `datetime.fromtimestamp(ts, utc).weekday()`, derived."""
    return int((int(day_bucket) // DAY_SEC + EPOCH_DAY_WEEKDAY) % 7)


def weekday_phase(weekday: int) -> int:
    """The `(day_bucket / 86400) % 7` value that means `weekday`."""
    return int((int(weekday) - EPOCH_DAY_WEEKDAY) % 7)


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


@dataclass(frozen=True, slots=True)
class PhaseBaseline:
    """One hour-of-day / day-of-week series, and where its rows are.

    `ref` is what the adapter declares; `baseline_id` and `sensor` are what
    the ETL actually wrote (`v3/etl/mapping.py`). They differ for two of
    the four, which is how `cf_attack_share_baseline` could sit next to a
    populated `hod` series for a whole phase without anyone noticing. The
    mapping is pinned against `TABLE_MAPPINGS` by test, so a rename on
    either side breaks a build instead of orphaning a baseline.
    """

    ref: str
    baseline_id: str
    sensor: str
    divisor: int
    modulus: int
    max_entries: int
    migrated_from: Optional[str]
    production_ref: str

    def phase_of(self, now: float) -> int:
        return int((int(now) // self.divisor) % self.modulus)

    def bucket_of(self, now: float) -> int:
        return int(now // self.divisor) * self.divisor


#: 672 = `HOD_MAX_ENTRIES` = `HOD_BASELINE_DAYS * 24` (`radar/config.py:336-338`).
#: 140 = `DOW_MAX_PER_DAY * 7` (`radar/sensors/gdelt.py:22,64`).
PHASE_BASELINES: Mapping[str, PhaseBaseline] = {
    baseline.ref: baseline for baseline in (
        PhaseBaseline(
            ref="bgp_hod", baseline_id="bgp_hod", sensor="bgp_hod",
            divisor=HOUR_SEC, modulus=24, max_entries=672,
            migrated_from="bgp_hod",
            production_ref="radar/sensors/bgp_routing.py:63-77"),
        PhaseBaseline(
            ref="checkhost_hod", baseline_id="checkhost_hod",
            sensor="checkhost_hod", divisor=HOUR_SEC, modulus=24,
            max_entries=672, migrated_from="checkhost_hod",
            production_ref="radar/sensors/checkhost.py:247-268"),
        PhaseBaseline(
            ref="gdelt_dow_tone", baseline_id="gdelt_dow",
            sensor="gdelt_dow", divisor=DAY_SEC, modulus=7,
            max_entries=140, migrated_from="gdelt_dow",
            production_ref="radar/sensors/gdelt.py:60-77"),
        PhaseBaseline(
            ref="cf_attack_share_baseline", baseline_id="hod",
            sensor="hod_baseline", divisor=HOUR_SEC, modulus=24,
            max_entries=672, migrated_from="hod_baseline",
            production_ref="radar/scoring.py:463-497"),
    )}


@dataclass(frozen=True, slots=True)
class EntityBaseline:
    """One per-entity series or marker set, and what it is keyed by.

    `kind` decides which of L1's two entity tables holds it, and that
    follows from the lifetime: a first-seen must never expire (it is what
    ends a warm-up), a latency sample must (30 days of them is 700x what
    production ever holds).
    """

    ref: str
    kind: str          # "series" | "marker" | "member_set"
    sensor: str
    entity_kind: str
    per_entity: int
    production_ref: str


ENTITY_BASELINES: Mapping[str, EntityBaseline] = {
    baseline.ref: baseline for baseline in (
        EntityBaseline(
            ref="ct_log_known_ca_per_domain", kind="member_set",
            sensor="ct_log", entity_kind="domain", per_entity=0,
            production_ref="radar/database.py:5410-5447"),
        EntityBaseline(
            ref="ct_log_domain_first_observed", kind="marker",
            sensor="ct_log", entity_kind="domain", per_entity=0,
            production_ref="radar/database.py:5449-5475"),
        EntityBaseline(
            # `deque(maxlen=12)` — ~1h at the 5-minute poll interval.
            ref="checkhost_latency_history", kind="series",
            sensor="check_host", entity_kind="url", per_entity=12,
            production_ref="radar/sensors/checkhost.py:138-155"),
        EntityBaseline(
            # One snapshot per MMSI, not a series: production overwrites
            # `{last_ts, lat, lng}` every cycle (`ais_maritime.py:141`).
            ref="ais_vessel_history", kind="series", sensor="ais_maritime",
            entity_kind="mmsi", per_entity=1,
            production_ref="radar/sensors/ais_maritime.py:112-152"),
        EntityBaseline(
            # One snapshot per TARGET, and one is the whole of it: the
            # 28-day window this is a baseline OVER lives in the query
            # string (`dateRange=BASELINE_DATE_RANGE`), not in the
            # ledger, so production stores exactly one row per target and
            # replaces it when it is over a day old
            # (`core.py:738-742`). A deeper series here would be a window
            # production does not have and could not be replayed from.
            ref="cf_origin_baseline", kind="series", sensor="cloudflare_radar",
            entity_kind="country", per_entity=1,
            production_ref="radar/routes/core.py:738-742"),
    )}

#: NOT a baseline, and it travels in the same mapping anyway. The spike
#: floor is 0.5% for an adversary origin and 3.0%/2.0% for anyone else
#: (`core.py:775-777`), which is a six-fold difference in what counts as
#: an attack; the set comes from the scenario declarations, not from L1.
#: It rides here because a pure fold's only channel IS what the
#: composition root hands it, and a second argument on all fifteen folds
#: to carry one adapter's value would be the wider change.
ADVERSARY_ORIGINS = "adversary_origins"

#: The second entry that is not a baseline, and it rides here for the same
#: reason. `cf_vector_shift`'s STATUS is "did any EFFECTIVE CORE shift"
#: (`core.py:877`/`:886`) and its severity reads the primary core's own
#: means (`core.py:1064-1065`) — neither is answerable from an origin
#: distribution alone. Supplied as the union across the scored scenarios,
#: because one acquisition cycle serves all of them; production asks the
#: focused scenario only.
EFFECTIVE_CORES = "effective_cores"

#: Declared baselines nothing can answer yet, with a MEASURED reason —
#: measured, because each was read out of production rather than guessed.
#: An unanswerable baseline that is simply absent from every mapping is
#: indistinguishable from one nobody wired.
UNANSWERABLE: Mapping[str, str] = {
    "airspace_hod":
        "hour-of-day statistic keyed by AIRPORT in production "
        "(`airspace_baseline.airport_code`, radar/database.py:783-786) "
        "while v3's opensky row is per country; supplying it means "
        "CHOOSING a new key, which is a difference to register rather "
        "than a transcription. Not migrated either (REGENERATE_ONLY), so "
        "there is no history to preserve by keeping production's shape",
    "narrative_keyword_frequency":
        "30-day rolling frequency; storage now exists (entity series) but "
        "the consumer's Z-score ladder is not ported",
    "telegram_keyword_frequency":
        "30-day rolling frequency; storage now exists (entity series) but "
        "the consumer's Z-score ladder is not ported",
    "apt_intel_dedup":
        "a de-duplication GATE, not a withheld verdict: production drops "
        "an already-seen article before the LLM is called "
        "(`apt_intel.py:362-370`), so wiring it changes what is sent to a "
        "model rather than what a verdict says. Different WP",
    "diplomatic_dedup":
        "as apt_intel_dedup (`diplomatic.py:150-158`)",
    "military_exercise_dedup":
        "as apt_intel_dedup (`military_exercise.py:93-112`)",
    "hacktivist_news_dedup":
        "as apt_intel_dedup (`hacktivist_news_sensor.py:92-99`)",
}

#: Supply is wired and the read works, but the CONSUMER still cannot
#: decide — so the score is still withheld and §7-2 #9 still stands.
#:
#: EMPTY as of WP-4.1d. `cf_attack_share_baseline` was the last entry: its
#: rows were readable for a whole phase while the quantity they judge —
#: `avg_spike` — was neither computed NOR fetched, and a baseline cannot
#: make a verdict out of a measurement nobody takes. The adapter now
#: declares `attacks/layer{3,7}/top/locations/origin`,
#: `v3/runtime/spike.py` computes the ratio and
#: `reduce_cyber._fold_cf_spike` reaches production's ladder. The mapping
#: stays because the distinction it encodes is the one §7-2 #9 turns on:
#: storage being present is not the same fact as a consumer being able to
#: decide, and collapsing the two is how a family gets retired half-wired.
VERDICT_WITHHELD: Mapping[str, str] = {}


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


def phase_history(store, *, now: float, countries: Sequence[str]) -> dict:
    """`{ref: {country: (value, ...)}}` — same-phase history, oldest first.

    Every requested country gets a key, INCLUDING one whose history is
    empty. That is not a formality: production does not withhold a verdict
    during hour-of-day warm-up, it falls back to fixed thresholds
    (`core.py:1015-1019`, `checkhost.py:266-269`), and a consumer can only
    take that branch if it can tell "read, and there were three samples"
    from "never read at all".
    """
    resolved: dict = {}
    for ref, baseline in PHASE_BASELINES.items():
        phase = baseline.phase_of(now)
        before = baseline.bucket_of(now)
        resolved[ref] = {
            country: tuple(store.baseline_phase_values(
                baseline.baseline_id, sensor=baseline.sensor,
                country=country, phase=phase, divisor=baseline.divisor,
                modulus=baseline.modulus, before_bucket=before))
            for country in countries}
    return resolved


def entity_history(store) -> dict:
    """`{ref: {entity: state}}` — one read per series, as production holds
    one dict in memory.

    Not scoped by country on purpose: the entities are domains, URLs and
    MMSIs, and production's own structures are global dicts. Scoping would
    mean inventing a country for a vessel, which is the confusion the
    entity table exists to prevent.
    """
    resolved: dict = {}
    for ref, baseline in ENTITY_BASELINES.items():
        if baseline.kind == "member_set":
            resolved[ref] = store.entity_member_sets(ref,
                                                     sensor=baseline.sensor)
        elif baseline.kind == "marker":
            resolved[ref] = store.entity_first_seen(ref,
                                                    sensor=baseline.sensor)
        else:
            resolved[ref] = store.entity_series_tail(
                ref, sensor=baseline.sensor, per_entity=baseline.per_entity)
    return resolved


def for_cycle(store, *, now: float, countries: Sequence[str],
              adversaries: Sequence[str] = (),
              cores: Sequence[str] = ()) -> dict:
    """Every baseline this cycle can be given, in one mapping.

    One call so that the ordering obligation — read before write — is
    stated once, in the composition root, rather than remembered at each
    of three call sites.

    `adversaries` and `cores` are the two entries that are not history
    (see `ADVERSARY_ORIGINS` / `EFFECTIVE_CORES`). Both are ALWAYS set,
    including to an empty tuple: absent, a fold could not tell "none is
    declared" from "nobody supplied the list". For the adversary set the
    two answers produce spikes six times apart; for the core set, an
    unsupplied list silently turns `cf_vector_shift` off, which is the
    shape of failure WP-4.1d found in `expansion.context_for` and fixed by
    removing the default rather than by remembering to pass a value.
    """
    supplied = previous_cycle(store, now=now, countries=countries)
    supplied.update(phase_history(store, now=now, countries=countries))
    supplied.update(entity_history(store))
    supplied[ADVERSARY_ORIGINS] = tuple(
        sorted({str(code).upper() for code in adversaries}))
    supplied[EFFECTIVE_CORES] = tuple(
        sorted({str(code).upper() for code in cores}))
    return supplied


def refresh_state(supplied: Mapping[str, object]) -> dict:
    """`{adapter: {(label, scope_key): stored_at}}` — §7-2 #117's repair.

    A `RequestSpec` may declare `refresh_after_sec`, meaning "do not send
    me again while a stored answer is younger than this". The AGE has to
    come from somewhere the kernel cannot reach, and for the origin
    baseline that somewhere is the snapshot this module has already read:
    `cf_origin_baseline`'s `observed_at` is v3's `b_data["time"]`, and
    `core.py:739` is literally `current_time - b_data["time"] > 86400`.

    So this is not a second scheduler. Production has no scheduler for
    this either — it has a stored value with a timestamp, and one
    comparison. Both of the target's two baseline requests are keyed to
    the SAME timestamp because production refreshes them together, inside
    one `if` (`core.py:739-742`).

    Pure: it reads the mapping `for_cycle` returned and opens nothing.
    """
    from v3.adapters.cyber.cloudflare_radar import (CLOUDFLARE_RADAR,
                                                    ORIGIN_L3_BASELINE,
                                                    ORIGIN_L7_BASELINE)
    snapshot = supplied.get("cf_origin_baseline") or {}
    stored: dict = {}
    for entity, rows in dict(snapshot).items():
        country = str(entity or "").upper()
        stamps = [float(row["observed_at"]) for row in (rows or ())
                  if isinstance(row, Mapping) and row.get("observed_at")
                  is not None]
        if not country or not stamps:
            continue
        for label in (ORIGIN_L3_BASELINE, ORIGIN_L7_BASELINE):
            stored[(label, country)] = max(stamps)
    return {CLOUDFLARE_RADAR.value: stored}


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
    """ONE flag, typed for this module's use: a number as float, a
    non-empty string as itself, anything else as None.

    The decode is `records.flags_of`; only the per-key coercion is local,
    because what an absent key means differs by caller — a missing
    `gps_jamming` date skips an adapter, a missing spike skips a row.
    """
    value = records.flags_of(row).get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value if isinstance(value, str) and value else None
    return float(value)


def declared_names(adapters: Iterable) -> tuple[str, ...]:
    """Every `baseline_refs` entry across the registry, sorted."""
    names = set()
    for adapter in adapters:
        names.update(adapter.baseline_refs)
    return tuple(sorted(names))


def supplied_names() -> frozenset:
    """Everything some read in this module can now produce."""
    return frozenset(PREVIOUS_CYCLE_SCALARS) | frozenset(
        PHASE_BASELINES) | frozenset(ENTITY_BASELINES)


def coverage(adapters: Iterable) -> dict:
    """Which declared baselines are answered, which are not, and why.

    `answered` means the consumer can now reach its verdict. A baseline
    whose rows are readable but whose consumer still withholds a score is
    reported under `withheld` and counted as UNANSWERED, because §7-2 #9's
    condition is about the score, not about the storage — retiring it on
    "the data is there" is exactly the half-wired cutover that entry
    forbids.
    """
    declared = set(declared_names(adapters))
    withheld = {name: reason for name, reason in VERDICT_WITHHELD.items()
                if name in declared}
    answered = (declared & supplied_names()) - set(withheld)
    unanswered = declared - answered
    reasons = {}
    for name in sorted(unanswered):
        reasons[name] = (withheld.get(name) or UNANSWERABLE.get(name)
                         or "no supply wired")
    return {
        "declared": sorted(declared),
        "answered": sorted(answered),
        "unanswered": sorted(unanswered),
        "withheld": dict(sorted(withheld.items())),
        "reasons": reasons,
    }


__all__ = ["PREVIOUS_CYCLE_SCALARS", "PHASE_BASELINES", "ENTITY_BASELINES",
           "ADVERSARY_ORIGINS", "EFFECTIVE_CORES", "refresh_state",
           "UNANSWERABLE", "VERDICT_WITHHELD", "PhaseBaseline",
           "EntityBaseline", "previous_cycle", "phase_history",
           "entity_history", "for_cycle", "carried_values", "declared_names",
           "supplied_names", "coverage", "weekday_of", "weekday_phase",
           "EPOCH_DAY_WEEKDAY", "HOUR_SEC", "DAY_SEC"]
