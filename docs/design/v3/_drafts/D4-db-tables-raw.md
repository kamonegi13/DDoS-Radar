# D4 素材: 本番 DB テーブル台帳（生データ）

取得: 2026-08-03、`docker exec -i noroshi python3`（read-only 接続）。
DB: `radar/persistence/radar.db`（コンテナ内）、**79 テーブル**。

## 全テーブルと行数

| テーブル | 行数 | | テーブル | 行数 |
|---|---:|---|---|---:|
| ach_evidence | 0 | | llm_call_log | 26,503 |
| ach_hypotheses | 0 | | llm_embed_call_log | 188 |
| ach_matrices | 164 | | llm_embed_dedup_log | 9 |
| ach_scores | 0 | | llm_feature_state | 0 |
| airspace_baseline | 19 | | llm_feature_state_history | 0 |
| alert_timeline | 288 | | llm_intel | 259 |
| analyst_feedback | 269 | | llm_prompts | 15,928 |
| attention_metric_observation | 7,517 | | llm_routing_override | 0 |
| attention_metric_p95 | 11 | | llm_routing_override_history | 4 |
| attention_snooze | 0 | | llm_shadow_invocation | 0 |
| auto_apply_cooldown | 0 | | llm_sources | 20 |
| auto_apply_tier_marker | 1 | | noise_exclusion | 0 |
| auto_apply_tier_state | 3 | | premortem_entries | 82 |
| auto_judge_decisions | 10,103 | | revoked_tokens | 0 |
| baseline_cache | 28 | | scenario_change_log | 3 |
| bg_observer_cycle_log | 8,170 | | scenario_contribution_log | 1,051,800 |
| bgp_hod | 5,398 | | scenario_discovery_run | 92 |
| checkhost_hod | 4,724 | | scenario_drift_events | 110 |
| climate_events | 165 | | scenario_participants | 0 |
| conclusions | 1,047,254 | | scenario_proposals | 193 |
| config_change_log | 23 | | scenario_reserved_ids | 1 |
| config_runtime_value | 50 | | scenario_sensor_coverage | 34 |
| confirmed_threats | 104 | | scenario_tl_observation | 114,160 |
| cooccurrence_matrix_snapshot | 77 | | scenarios | 5 |
| cooccurrence_stats | 101 | | schema_version | 1 |
| ct_log_domain_first_observed | 68 | | sensor_caches | 32 |
| ct_log_known_ca_per_domain | 118 | | sensor_fetch_log | 14,108 |
| daily_summary | 114 | | sensor_observation_ts | 19,480 |
| decision_ledger | 984 | | sensor_zscore_stats | 2 |
| decisions | 0 | | sequence_events | 209 |
| disconfirming_evidence | 164 | | shadow_sampler_state | 3 |
| discovery_cluster | 86 | | sqlite_sequence | 41 |
| dissenting_views | 82 | | threat_history | 1,000 |
| focus_switch_log | 3,326 | | threshold_history | 100 |
| gdelt_dow | 693 | | time_series | 178,335 |
| hidden_signal_log | 15 | | time_series_ts | 59,445 |
| hod_baseline | 18,144 | | user_attention_thresholds | 0 |
| inconclusive_continuity_log | 28,503 | | user_settings | 1 |
| key_assumption_change_log | 328 | | users | 1 |
| key_assumptions | 246 | | | |

## 一次観察（D4 統合時に分類の起点にする）

### 巨大 ledger（移行コストの主対象）
- `scenario_contribution_log` 1.05M / `conclusions` 1.05M / `time_series` 178k / `scenario_tl_observation` 114k
- conclusions は 90d retention 中（365d 化は 2026-10 予定の保留事項）。移行時に retention 方針を同時決定できる

### 空テーブル 13 件（休眠機能 / dead schema の候補 — 要判定）
`ach_evidence`, `ach_hypotheses`, `ach_scores`, `attention_snooze`, `auto_apply_cooldown`,
`decisions`, `llm_feature_state`, `llm_feature_state_history`, `llm_routing_override`,
`llm_shadow_invocation`, `noise_exclusion`, `revoked_tokens`, `scenario_participants`

- ACH 系（tradecraft）は 2026-04-30 に統合棚上げ済み（メモリ記録あり）と整合。ach_matrices 164 行だけ
  データがあるのは要調査
- `scenario_participants` が 0 行なのは要注意 — participants は geo_data.json 側のプリセットから
  ロードされている可能性。スキーマと実装の乖離候補
- `noise_exclusion` 0 / `revoked_tokens` 0 は機能未使用なだけの可能性（正常）
- `llm_shadow_invocation` / `shadow_sampler_state` は v1→v2 移行足場の残滓候補

### 較正資産（R1 データ連続の中核 — 絶対移行）
- `analyst_feedback` 269（AP3 anchor ラベル含む）/ `confirmed_threats` 104 / `threshold_history` 100 /
  `auto_judge_decisions` 10,103 / ベースライン群（`hod_baseline` 18,144, `bgp_hod`, `checkhost_hod`,
  `gdelt_dow`, `airspace_baseline`, `baseline_cache`, `sensor_zscore_stats`）
