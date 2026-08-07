"""What the ETL migrates, what it cannot yet, and why.

S3 lists 35 tables to migrate. L1 (WP-2.2) models five: signal_observation,
tl_observation, conclusion, baseline_stat and schema_meta. The rest have no
destination until their layer's WP lands, so this module holds two explicit
registries rather than letting the gap live in someone's head.

`NOT_YET_MIGRATABLE` is not a to-do list to be quietly ignored: the
reconciliation harness reports every entry by name, so a criterion that
cannot be checked yet reads as BLOCKED rather than as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True, slots=True)
class TableMapping:
    """One v1 table and where its rows land in v3."""

    source_table: str
    target: str                 # 'conclusion' | 'tl_observation' | 'baseline'
    order_by: str               # deterministic copy order (S3-DATA-021)
    identity_columns: tuple[str, ...]   # for quarantine identity
    stage: int                  # S3-DATA-020 dependency stage
    baseline_id: Optional[str] = None
    value_column: Optional[str] = None
    bucket_column: Optional[str] = None
    # Columns excluded from the acceptance-hash payload: surrogate ids whose
    # value spaces are uncorrelated between the two databases, and columns
    # that exist on only one side. Data, not code, so the hash rule is
    # reviewable without reading the hasher.
    hash_drop_columns: tuple[str, ...] = ()
    # JSON columns. Both sides are re-canonicalised before hashing, because
    # v1 wrote with ensure_ascii=True and v3 writes with False — identical
    # data, different bytes (Japanese metadata diverges immediately).
    hash_json_columns: tuple[str, ...] = ()
    # How the two sides are aligned for hashing. Must be VALUES that exist
    # and mean the same thing in both databases.
    hash_order_columns: tuple[str, ...] = ()
    note: str = ""


# theater -> country is a RENAME, not a value transform (S3-DATA-022).
#
# Correction to S3's stated reason: a GENERATED ALWAYS ... VIRTUAL column
# DOES appear in `SELECT *` (only HIDDEN columns are excluded), so "it is
# invisible to SELECT *" is empirically false. The real protection is that
# every migrator reads columns BY NAME, which makes an extra column inert;
# a positional rewrite would break, and a test pins that.
COUNTRY_SOURCE_COLUMN = "theater"

MIGRATABLE: dict[str, TableMapping] = {
    "conclusions": TableMapping(
        source_table="conclusions", target="conclusion",
        order_by="observed_at", identity_columns=("id",), stage=3,
        hash_json_columns=("metadata", "source_urls"),
        hash_order_columns=("observed_at", "id"),
        note="S3-DATA-021: 1M rows, chunked by observed_at ascending. `id` "
             "is a stable TEXT key that survives migration, so it can order "
             "both sides."),
    "scenario_tl_observation": TableMapping(
        source_table="scenario_tl_observation", target="tl_observation",
        order_by="observed_at", identity_columns=("id",), stage=1,
        hash_drop_columns=("id", "tick_id"),
        hash_json_columns=("active_countries",),
        hash_order_columns=("observed_at", "scenario_id"),
        note="P6 O-16's unthinned stream. Both `id`s are AUTOINCREMENT "
             "surrogates with uncorrelated value spaces and `tick_id` "
             "exists only on the v3 side, so all three are excluded from "
             "the hash."),
    "hod_baseline": TableMapping(
        source_table="hod_baseline", target="baseline",
        order_by="hour_bucket", identity_columns=("theater", "hour_bucket"),
        stage=1, baseline_id="hod", value_column="avg_spike",
        bucket_column="hour_bucket",
        hash_order_columns=("theater", "hour_bucket"),
        note="S3-DATA-011: backfill-impossible."),
    "checkhost_hod": TableMapping(
        source_table="checkhost_hod", target="baseline",
        order_by="hour_bucket", identity_columns=("theater", "hour_bucket"),
        stage=1, baseline_id="checkhost_hod", value_column="success_rate",
        bucket_column="hour_bucket",
        hash_order_columns=("theater", "hour_bucket"),
        note="S3-DATA-011: backfill-impossible."),
    "bgp_hod": TableMapping(
        source_table="bgp_hod", target="baseline",
        order_by="hour_bucket", identity_columns=("theater", "hour_bucket"),
        stage=1, baseline_id="bgp_hod", value_column="prefix_count",
        bucket_column="hour_bucket",
        hash_order_columns=("theater", "hour_bucket"),
        note="S3-DATA-011: backfill-impossible."),
    "gdelt_dow": TableMapping(
        source_table="gdelt_dow", target="baseline",
        order_by="day_bucket", identity_columns=("theater", "day_bucket"),
        stage=1, baseline_id="gdelt_dow", value_column="tone",
        bucket_column="day_bucket",
        hash_order_columns=("theater", "day_bucket"),
        note="S3-DATA-011: full recovery takes 20 weeks."),
}

_L3 = "WP-3.1 (L3 conclusions layer)"
_L4 = "WP-3.2 (L4 calibration layer)"
_L0 = "WP-2.5 (L0 acquisition kernel)"
_L6 = "WP-4.1 (L6 public API)"

NOT_YET_MIGRATABLE: dict[str, dict] = {
    table: {"reason": reason, "target_wp": wp}
    for table, reason, wp in (
        ("llm_prompts",
         "NP6 prompt retrieval store; the conclusion envelope that "
         "references it is L3's shape.", _L3),
        ("analyst_feedback",
         "Ground-truth labels. Blocks acceptance criterion 3 until L3 "
         "defines the conclusion identity it references.", _L3),
        ("inconclusive_continuity_log",
         "Null-zone continuity. P6 O-16 makes it a DERIVED view over the "
         "TL stream, so it is re-derived rather than migrated — the run "
         "lengths criterion 4 checks come from the view.", _L3),
        ("threshold_history", "Calibration ledger.", _L4),
        ("scenario_proposals", "Calibration proposals.", _L4),
        ("scenario_drift_events", "Drift watchdog output.", _L4),
        ("cooccurrence_stats", "Co-occurrence statistics.", _L4),
        ("cooccurrence_matrix_snapshot", "Discovery chain head.", _L4),
        ("scenario_discovery_run", "Discovery chain.", _L4),
        ("discovery_cluster", "Discovery chain tail.", _L4),
        ("confirmed_threats", "Human ground truth, retention-exempt.", _L4),
        ("sequence_events", "Escalation chain state.", _L3),
        ("ct_log_known_ca_per_domain", "Sensor-side baseline.", _L0),
        ("ct_log_domain_first_observed", "Sensor-side baseline.", _L0),
        ("daily_summary", "Reporting rollup.", _L6),
        ("alert_timeline", "Presentation ring buffer.", _L6),
        ("users", "Authentication.", _L6),
        ("user_settings", "Per-user settings.", _L6),
        ("scenario_change_log", "Scenario audit, retention-exempt.", _L6),
        ("auto_judge_decisions", "Auto-judge subsystem.", _L4),
        ("attention_metric_observation", "ATTENTION metrics.", _L4),
        ("config_runtime_value", "Config overrides — K-layer scope.", _L4),
        ("config_change_log", "Config audit — K-layer scope.", _L4),
        ("llm_sources", "LLM source credibility.", _L3),
        ("llm_routing_override_history", "LLM routing overrides.", _L3),
        ("auto_apply_tier_state", "Auto-apply governor state.", _L4),
        ("auto_apply_tier_marker", "Auto-apply governor marker.", _L4),
        ("scenarios",
         "Layer-2 analyst overrides on the scenario presets. Losing these "
         "silently reverts every scenario to its preset at cutover, with "
         "no signal — which is why it must be accounted for even though "
         "its destination is not L1's.", _L6),
        ("scenario_reserved_ids",
         "Reserved scenario identifiers; paired with `scenarios`.", _L6),
    )
}

# S3-DATA-050: schema only, data starts empty. NOT migration backlog — a
# table here is deliberately not migrated, and reporting it as pending
# would misrepresent the work remaining.
REGENERATE_ONLY: frozenset = frozenset({
    "scenario_contribution_log", "time_series", "time_series_ts",
    "llm_call_log", "sensor_observation_ts", "sensor_fetch_log",
    "bg_observer_cycle_log", "threat_history", "llm_intel", "climate_events",
    "llm_embed_call_log", "sensor_caches", "scenario_sensor_coverage",
    "baseline_cache", "airspace_baseline", "attention_metric_p95",
    "hidden_signal_log", "llm_embed_dedup_log", "sensor_zscore_stats",
    "decisions", "attention_snooze", "auto_apply_cooldown",
    "llm_feature_state", "llm_feature_state_history", "llm_routing_override",
    "llm_shadow_invocation", "noise_exclusion", "revoked_tokens",
    "user_attention_thresholds", "scenario_participants",
})

# S3 §2.2's canonical migrate-35 list, transcribed from its CREATE TABLE
# definitions. The completeness test compares this against the two
# registries so a table added to S3 cannot silently escape the ETL's
# accounting — that gap is how `scenarios` went missing.
S3_MIGRATE_35: frozenset = frozenset({
    "alert_timeline", "analyst_feedback", "attention_metric_observation",
    "auto_apply_tier_marker", "auto_apply_tier_state", "auto_judge_decisions",
    "bgp_hod", "checkhost_hod", "conclusions", "config_change_log",
    "config_runtime_value", "confirmed_threats",
    "cooccurrence_matrix_snapshot", "cooccurrence_stats",
    "ct_log_domain_first_observed", "ct_log_known_ca_per_domain",
    "daily_summary", "discovery_cluster", "gdelt_dow", "hod_baseline",
    "inconclusive_continuity_log", "llm_prompts",
    "llm_routing_override_history", "llm_sources", "scenario_change_log",
    "scenario_discovery_run", "scenario_drift_events", "scenario_proposals",
    "scenario_reserved_ids", "scenario_tl_observation", "scenarios",
    "sequence_events", "threshold_history", "user_settings", "users",
})

# JSON payload columns that S3-DATA-022 requires be free of the old
# vocabulary after migration.
JSON_PAYLOAD_COLUMNS: dict[str, tuple[str, ...]] = {
    "conclusions": ("metadata", "source_urls"),
    "scenario_tl_observation": ("active_countries",),
}
FORBIDDEN_JSON_KEY = "theater"

__all__ = ["TableMapping", "MIGRATABLE", "NOT_YET_MIGRATABLE",
           "REGENERATE_ONLY", "S3_MIGRATE_35",
           "JSON_PAYLOAD_COLUMNS", "FORBIDDEN_JSON_KEY",
           "COUNTRY_SOURCE_COLUMN"]
