"""radar.verification.flag_catalog -- declarative detection-flag catalog.

S5-VERIF-001: every sensor publishes its detection flags as a
machine-readable catalog. The current system has no such enumeration —
each flag is an ad-hoc key in a fetch() return dict — which is how F-08
(gps_jamming, permanently non-firing since it shipped) survived undetected.

This module is PURE: no DB, no Flask, no sensor imports. It is safe to
call from inside BaseSensor.set_cache().

Path resolution
---------------
A flag's location in the cached payload is one `path` tuple. The sentinel
``ANY`` ("*") means "descend into every value of this dict / every element
of this list; the flag fires if ANY of them fires". One wildcard walker
covers all four container shapes the sensors actually use:

    ("has_anomaly",)                                  scalar at the root
    ("seismic", "has_cable_threat")                   nested scalar
    ("jamming_data", ANY, "is_jammed")                dict of per-country dicts
    ("country_status", ANY)                           dict of bare strings
    ("bgp_hijacks", ANY, "is_ongoing")                list of event dicts
    ("notam_data", ANY, "recent", ANY, "is_military") list inside a dict

`scope` is declared separately for audit readability and is checked
against the path in tests; the resolver keys off the wildcard alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Wildcard sentinel for path resolution ("fire if any child fires").
ANY = "*"

# S5-VERIF-007: closed unit vocabulary. `unit` names the unit of the value
# that is compared against `threshold_key` — "bool" when the flag is not a
# numeric comparison at all. Recording the unit here is what makes the
# F-08 class of defect (ratio compared against a percent-scaled constant)
# machine-checkable by WP-1.2 / S5-VERIF-008.
UNIT_VOCABULARY = frozenset({
    "ratio", "percent", "count", "s", "min", "h", "d", "km", "z", "score", "bool",
})

# ── S5-VERIF-003 thresholds ────────────────────────────────────────────────
# Deliberately module constants rather than config-registry keys (P6 O-18):
# a verification gate whose thresholds can be relaxed at runtime is not a
# gate. Changing these is a code change with a diff and a review.
SILENCE_WARN_RATIO = 1.0        # silence >= 1x the expected interval  -> WARN
SILENCE_ANOMALY_RATIO = 3.0     # silence >= 3x the expected interval  -> ANOMALY
NEVER_FIRED_GRACE_DAYS = 30     # never fired since first sight        -> ANOMALY

# Fire-log retention. Matched to SIGNAL_LEDGER_RETENTION_DAYS (WP-0.1) so a
# 30-day parity replay can also replay the firing history behind it.
FIRE_LOG_RETENTION_DAYS = 60


@dataclass(frozen=True)
class FlagSpec:
    """One detection flag of one sensor."""

    sensor: str
    flag_id: str
    kind: str                       # "bool" | "enum"
    non_firing_values: tuple        # values that mean "did not fire"
    path: tuple                     # payload path, ANY = descend-any
    scope: str                      # "global" | "per_country" | "per_event"
    threshold_key: str              # config/env key, "" when not threshold-driven
    unit: str                       # unit of the compared value (UNIT_VOCABULARY)
    expected_fire_interval_days: int
    note: str = field(default="")   # rationale for the interval (required)


_BOOL_OFF = (False, None)


def _b(sensor, flag_id, path, scope, days, note, *, threshold_key="", unit="bool"):
    """Shorthand for a boolean FlagSpec."""
    return FlagSpec(
        sensor=sensor, flag_id=flag_id, kind="bool", non_firing_values=_BOOL_OFF,
        path=path, scope=scope, threshold_key=threshold_key, unit=unit,
        expected_fire_interval_days=days, note=note,
    )


def _e(sensor, flag_id, path, scope, clear, days, note):
    """Shorthand for an enum FlagSpec. `clear` lists the non-firing values."""
    return FlagSpec(
        sensor=sensor, flag_id=flag_id, kind="enum",
        non_firing_values=tuple(clear) + (None, ""),
        path=path, scope=scope, threshold_key="", unit="bool",
        expected_fire_interval_days=days, note=note,
    )


# ── The catalog ────────────────────────────────────────────────────────────
# expected_fire_interval_days is chosen per flag from the phenomenon's real
# cadence (WP-1.1 condition 2: thresholds MUST NOT be uniform). Rule of
# thumb used below: how long may this flag stay False before "nothing is
# happening" becomes less likely than "the detector is broken"?
CATALOG: tuple[FlagSpec, ...] = (
    # ── physical ───────────────────────────────────────────────────────────
    # F-08 lives here. `avg_level`/`max_level` are fractions in [0,1] but the
    # thresholds default to 3.0 / 7.0 (percent scale), so is_jammed and
    # is_critical are unreachable. Do not fix in WP-1.1 — this is the
    # acceptance target (tests/test_f08_acceptance.py).
    _b("gps_jamming", "is_jammed", ("jamming_data", ANY, "is_jammed"),
       "per_country", 30, threshold_key="GPS_JAM_THRESHOLD", unit="ratio",
       note="GPS interference near a monitored country is episodic; a quiet "
            "month is plausible, a quiet quarter is not."),
    _b("gps_jamming", "is_critical", ("jamming_data", ANY, "is_critical"),
       "per_country", 90, threshold_key="GPS_JAM_CRITICAL_THRESHOLD", unit="ratio",
       note="CRITICAL tier — sustained heavy jamming is a rare, high-severity "
            "event, so the silence budget is a full quarter."),
    _b("gps_jamming", "surge", ("jamming_data", ANY, "surge"),
       "per_country", 14,
       note="Day-over-day 1.5x jump on a noisy crowdsourced ratio; should "
            "trip somewhere in the watch set most fortnights."),
    _e("gps_jamming", "country_status", ("country_status", ANY), "per_country",
       ("NORMAL", "NO_DATA"), 30,
       note="Rolls up is_jammed/is_critical; NO_DATA is absence of "
            "measurement, not a detection."),
    _b("isr_hotspot", "is_surge", ("isr_data", ANY, "is_surge"), "per_country", 14,
       note="ISR orbit surges cluster around exercises and incidents; "
            "a fortnight without one across all theaters is unusual."),
    _b("mil_support_air", "is_transport_surge",
       ("mil_air_data", ANY, "is_transport_surge"), "per_country", 14,
       note="Threshold is >=3 transports in-window; routine logistics reaches "
            "it regularly."),
    _b("mil_support_air", "is_awacs_active",
       ("mil_air_data", ANY, "is_awacs_active"), "per_country", 14,
       note="A single AWACS track suffices; AEW&C flies far more often than "
            "fortnightly across the watch set."),
    _b("ais_maritime", "has_anomaly", ("has_anomaly",), "global", 7,
       note="Dark gaps and stationary anomalies at monitored chokepoints are "
            "near-continuous background; a silent week is suspicious."),
    _b("openweather", "is_severe", ("conditions", ANY, "is_severe"),
       "per_country", 30,
       note="Severe weather across the whole watch set is monthly-ish; used "
            "as a physical-domain noise suppressor."),
    _b("openweather", "is_moderate", ("conditions", ANY, "is_moderate"),
       "per_country", 7,
       note="Moderate conditions are common; a silent week means the "
            "classifier stopped classifying."),
    _b("usgs_seismic", "has_cable_threat", ("seismic", "has_cable_threat"),
       "global", 60,
       note="Submarine-cable-threatening quakes are rare but not exceptional; "
            "two months of global silence is implausible."),
    _b("usgs_seismic", "has_nuclear_candidate",
       ("seismic", "has_nuclear_candidate"), "global", 180,
       note="Shallow low-magnitude events at test-site geometry are genuinely "
            "rare; the widest silence budget in the catalog."),
    _b("usgs_seismic", "suppress_physical", ("seismic", "suppress_physical"),
       "global", 60,
       note="Suppressor. A dead suppressor is also a silent failure — it lets "
            "natural-event noise through as escalation signal."),
    _b("space_weather", "suppress_physical",
       ("space_weather", "suppress_physical"), "global", 90,
       note="Suppressor. Geomagnetic storms strong enough to mask GNSS/HF "
            "effects run on a roughly quarterly cadence at solar maximum."),
    _e("notam", "country_status", ("country_status", ANY), "per_country",
       ("NORMAL",), 14,
       note="Airspace restrictions churn constantly. NOTE: sensor is "
            "intentionally disabled (upstream API dead) — silence evaluation "
            "skips disabled sensors."),
    _b("notam", "is_surge", ("notam_data", ANY, "is_surge"), "per_country", 14,
       note="Same cadence as country_status; disabled sensor, catalogued for "
            "completeness so re-enabling is monitored from day one."),
    _b("notam", "is_military", ("notam_data", ANY, "recent", ANY, "is_military"),
       "per_event", 7,
       note="Military NOTAMs are routine near the watch set; per-NOTAM flag "
            "inside the truncated `recent` list."),
    _b("notam", "is_tfr", ("notam_data", ANY, "recent", ANY, "is_tfr"),
       "per_event", 30,
       note="Temporary flight restrictions are episodic rather than daily."),

    # ── cyber ──────────────────────────────────────────────────────────────
    _b("ripe_bgp", "is_anomaly", ("routing_stats", ANY, "is_anomaly"),
       "per_country", 14,
       note="Prefix-count deviation across a whole watch set; routing churn "
            "makes a fortnight of complete quiet unlikely."),
    _e("ioda_bgp", "statuses", ("statuses", ANY), "per_country",
       ("NORMAL",), 30,
       note="Country-scale BGP outages are monthly-ish events; NORMAL is the "
            "only clear value the sensor emits."),
    _b("cloudflare_radar", "is_ongoing", ("bgp_hijacks", ANY, "is_ongoing"),
       "per_event", 14,
       note="Per-hijack-event flag inside the bgp_hijacks list; ongoing "
            "hijacks appear in the global feed regularly."),
    _b("ct_log", "is_surge", ("ct_data", ANY, "is_surge"), "per_country", 14,
       note="Certificate issuance bursts for monitored domains; baseline is "
            "z-scored so surges recur."),
    _e("ct_log", "country_status", ("country_status", ANY), "per_country",
       ("NORMAL", "WARMUP"), 30,
       note="Untrusted-CA / wildcard-TLD detections are rarer than the raw "
            "surge; WARMUP means the baseline is immature, not a detection."),
    _e("check_host", "status", ("check_host", ANY, "status"), "per_country",
       ("OK",), 14,
       note="PARTIAL/BLACKOUT reachability for monitored endpoints; transient "
            "partial failures are common."),
    _b("check_host", "asphyxiation", ("check_host", ANY, "asphyxiation"),
       "per_country", 60,
       note="Full multi-vantage asphyxiation is a severe, infrequent state."),
    _e("ihr_health", "country_status", ("country_status", ANY), "per_country",
       ("NORMAL",), 14,
       note="Disconnection / hegemony / delay alarms fire often. NOTE: sensor "
            "is disabled in ops (chronic upstream errors)."),
    _b("ooni_censorship", "is_censoring",
       ("censorship_data", ANY, "is_censoring"), "per_country", 14,
       note="Baseline censorship in the adversary set means this should be "
            "near-permanently true; a fortnight of False is a dead detector."),
    _b("ooni_censorship", "is_heavy", ("censorship_data", ANY, "is_heavy"),
       "per_country", 60,
       note="Heavy-censorship tier is an escalation state, not the baseline."),
    _e("ooni_censorship", "country_status", ("country_status", ANY),
       "per_country", ("NORMAL",), 14,
       note="Enum rollup of is_censoring / is_heavy."),
    _e("ripe_atlas", "country_status", ("country_status", ANY), "per_country",
       ("NORMAL",), 30,
       note="Probe drop/blackout tracks infrastructure disruption; probe "
            "churn alone produces monthly PROBE_DROP events."),
    _e("tor_metrics", "country_status", ("country_status", ANY), "per_country",
       ("NORMAL",), 30,
       note="Relay drops and client surges follow censorship events; monthly "
            "cadence across the watch set."),
    _e("greynoise", "status", ("greynoise", ANY, "status"), "per_country",
       ("UNKNOWN",), 7,
       note="Suppressor. Internet background noise is continuous, so a week "
            "of UNKNOWN means classification stopped, not that noise stopped."),
    _b("greynoise", "suppress_confidence",
       ("greynoise", ANY, "suppress_confidence"), "per_country", 14,
       note="Suppressor. Only set under NOISE_DOMINANT, which is the common "
            "case for scanner-heavy theaters."),

    # ── information ────────────────────────────────────────────────────────
    _e("telegram_mirror", "status", ("telegram", ANY, "status"), "per_country",
       ("CLEAR",), 7,
       note="TARGETS_FOUND alone trips this; monitored channels mention watch "
            "targets most weeks."),
    _b("telegram_mirror", "is_burst", ("telegram", ANY, "is_burst"),
       "per_country", 14,
       note="Volume burst above baseline; narrower than status, so double "
            "the budget."),
    _b("telegram_mirror", "has_attack_intent",
       ("telegram", ANY, "has_attack_intent"), "per_country", 14,
       note="Keyword/LLM intent match — hacktivist channels post intent "
            "claims well inside a fortnight."),
    _e("rss_narrative", "status", ("narratives", ANY, "status"), "per_country",
       ("NORMAL",), 7,
       note="State-media narrative bursts around the watch set are a weekly "
            "phenomenon."),
    _b("rss_narrative", "is_burst", ("narratives", ANY, "is_burst"),
       "per_country", 14,
       note="Same signal at the boolean tier; kept separate because scoring "
            "reads both."),
    _b("gdelt", "is_alert", ("gdelt_tones", ANY, "is_alert"), "per_country", 7,
       note="Global event-tone deviation; GDELT's volume makes weekly alerts "
            "the norm."),
    _b("travel_advisory", "upgraded", ("advisories", ANY, "upgraded"),
       "per_country", 30,
       note="Advisory level upgrades are governmental actions on a monthly-ish "
            "cadence across the watch set."),
    _b("travel_advisory", "converged", ("advisories", ANY, "converged"),
       "per_country", 30,
       note="Two or more governments at level >=3 for the same country — the "
            "multi-source convergence NP2 depends on."),
    _b("convergence_tracker", "converged",
       ("convergence_tracker", "states", ANY, "converged"), "per_country", 14,
       note="Cross-domain sustained convergence; the whole point of the tool, "
            "so a fortnight of silence warrants a look."),
)

# ── Sensors with no detection flag in their cached payload ─────────────────
# S5-VERIF-001 totality: a sensor missing from BOTH this set and CATALOG is
# unmonitored. The test suite asserts CATALOG | NO_DETECTION_FLAGS covers
# every registered sensor exactly once.
NO_DETECTION_FLAGS: frozenset[str] = frozenset({
    # Raw-measurement sensors: the value, not a flag, is the signal. Their
    # thresholding happens in the scoring layer (add_rat call sites).
    "opensky",          # {"airports": {CC: {count, ...}}} — counts only
    "peeringdb_ixp",    # {"ixp_data": {CC: {ixps, count}}} — inventory only
    "nasa_firms",       # {"anomalies": [...]} — list presence is the signal
    "threatfox",        # {"hits": {CC: {count, description}}} — counts only
    # LLM sensors: they submit to intel_queue and cache only a counter. Their
    # booleans (is_strategically_relevant / is_credible_threat /
    # is_active_campaign / is_ongoing) live in intel_queue items under
    # `llm_fields`, never in the sensor cache — so set_cache cannot see them.
    # Monitoring those belongs to a later WP against the intel ledger.
    "apt_intel",
    "hacktivist_intel",
    "hacktivist_news",
    "ground_osint",
    "diplomatic",
    "military_exercise",
    # Background observer: emits match counters, not detections.
    "bg_observer_rss",
})


# ── Evaluation (pure) ──────────────────────────────────────────────────────
_INDEX_SRC: Any = None
_INDEX: dict[str, list[FlagSpec]] = {}


def _index() -> dict[str, list[FlagSpec]]:
    """Sensor -> specs, rebuilt whenever CATALOG is rebound (tests do this)."""
    global _INDEX_SRC, _INDEX
    if _INDEX_SRC is not CATALOG:
        built: dict[str, list[FlagSpec]] = {}
        for spec in CATALOG:
            built.setdefault(spec.sensor, []).append(spec)
        _INDEX, _INDEX_SRC = built, CATALOG
    return _INDEX


def specs_for(sensor_name: str) -> list[FlagSpec]:
    """Catalog entries for one sensor (empty when flagless/unknown)."""
    return list(_index().get(sensor_name, ()))


def _is_firing(spec: FlagSpec, value: Any) -> bool:
    """True when `value` means the flag fired."""
    if spec.kind == "bool":
        return value is True or (
            isinstance(value, (int, float)) and not isinstance(value, bool)
            and value != 0
        )
    if not isinstance(value, str):
        return False
    return value not in spec.non_firing_values


def _resolve(spec: FlagSpec, node: Any, path: tuple) -> bool:
    """Walk `path` from `node`; ANY descends into every child (any-fires)."""
    if not path:
        return _is_firing(spec, node)
    head, rest = path[0], path[1:]
    if head is ANY or head == ANY:
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, (list, tuple)):
            children = node
        else:
            return False
        return any(_resolve(spec, child, rest) for child in children)
    if not isinstance(node, dict):
        return False
    if head not in node:
        return False
    return _resolve(spec, node[head], rest)


def evaluate_flags(sensor_name: str, payload: Any) -> dict[str, bool]:
    """Evaluate every catalogued flag of `sensor_name` against `payload`.

    Pure and total: a missing key, a wrong type, or a non-dict payload
    yields False rather than an exception. This runs inside
    BaseSensor.set_cache(), where raising would convert a monitoring
    feature into a sensor outage (NP3).
    """
    specs = _index().get(sensor_name)
    if not specs:
        return {}
    if not isinstance(payload, dict):
        return {spec.flag_id: False for spec in specs}
    return {spec.flag_id: _resolve(spec, payload, spec.path) for spec in specs}
