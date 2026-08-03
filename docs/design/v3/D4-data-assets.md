# D4 データ資産台帳 — 本番 DB 79 テーブル + convergence_snapshots.db の分類

作成: 2026-08-03。入力: `_drafts/D4-db-tables-raw.md`（行数実測）+ コード Grep 全数調査
（radar/ 配下・scripts/ 配下、database.py はテーブル→メソッド→外部呼び出し元の 2 段解決）。

分類定義:
- **移行** — v3 に必ず持ち越す（較正資産・運用台帳・認証・アナリスト判断履歴）
- **再生成可** — キャッシュ・導出値・短期 retention 運用ログ。v3 で空から再構築可能
- **破棄可** — dead / dormant スキーマ、またはデータがテスト残骸で資産価値なし

## 1. 分類サマリ

| 分類 | テーブル数 | 総行数概算 |
|---|---:|---:|
| 移行 | 35 | **約 1,254,000 行**（conclusions 単独で 83.5%、上位 2 表で 92.6%） |
| 再生成可 | 31 + convergence_snapshots.db::snapshots | 約 1,370,000 行（移行不要） |
| 破棄可 | 13 | 約 2,100 行（大半がテスト残骸） |

移行対象のうち 1 万行超は conclusions (1,047,254) / scenario_tl_observation (114,160) /
inconclusive_continuity_log (28,503) / hod_baseline (18,144) / llm_prompts (15,928) /
auto_judge_decisions (10,103) の 6 表のみ。残り 29 表は合計 3 万行未満で移行コストは無視できる。

## 2. 台帳（全 79 + 1 テーブル）

ライター/リーダーは主要モジュールのみ（`radar/` prefix 省略）。database.py 経由のものは
実際の呼び出し元モジュールを記載。行数は 2026-08-03 実測（raw ドラフト値）。

### 2a. 移行（35）

| テーブル | 行数 | ライター | リーダー | 根拠 |
|---|---:|---|---|---|
| conclusions | 1,047,254 | conclusions/persistence.py（scoring tick）+ scripts/backfill_v2_ledger.py | calibration/*、conclusions/*、routes/conclusions_v2.py、recall scripts | v2 結論 ledger。AP4 replay・較正・recall 検証の中核。retention 90d |
| scenario_tl_observation | 114,160 | routes/core.py (tl_observation_append) | routes/core・analytics.py、conclusions_v2 (tl_calibration_stats) | TL 較正窓 42d の原データ。破棄すると較正 2 サイクル分を失う |
| inconclusive_continuity_log | 28,503 | conclusions/persistence.py | conclusions/inconclusive_continuity.py、calibration/drift_watchdog.py | NP5+8 null-zone 継続日数（AP3 自己評価）。60d retention |
| hod_baseline | 18,144 | scoring.py (record_hod_sample / prefill_hod_baseline_bg) | scoring.py (compute_hod_zscore) | HOD ベースライン。CF Radar prefill で再生成可能だが移行が最安全（§4 Q6） |
| llm_prompts | 15,928 | llm_client.py (llm_call_log_append 経由) | llm_prompts.py、scripts/llm_model_bench.py | NP6 prompt 遡及（conclusions→llm_prompt_sha256 解決）。conclusions を移行するなら必須ペア。retention 120d (≥ conclusions+30d 床) |
| auto_judge_decisions | 10,103 | intel_auto_judge.py | intel_auto_judge、routes/auto_judge_v2.py、scripts/backtest_auto_judge_layer1.py | 自動判断台帳（AP4）+ Layer1 backtest の ground truth |
| attention_metric_observation | 7,517 | attention_learning.py | attention_learning.py | AP1 attention_score p95 正規化の学習観測（原資産） |
| bgp_hod | 5,398 | sensors/bgp_routing.py (db.hod_* 動的テーブル名 — 静的 Grep では見えない) | 同左 | 外部 backfill 不能。破棄すると z 有効まで 7 日・全深度 28 日の検知力低下 |
| checkhost_hod | 4,724 | sensors/checkhost.py (db.hod_*) | 同左 | 同上 |
| gdelt_dow | 693 | sensors/gdelt.py (gdelt_dow_record) | sensors/gdelt.py、scripts/run_ground_truth_etl.py | DoW ベースライン。backfill 不能、z 有効まで 3 週・全深度 20 週 |
| alert_timeline | 288 | routes/core.py (alert_append、ring 288) | routes/core・history・analytics.py | AP4 alert lane 履歴。再生成不可（最新 288 件のみだが） |
| analyst_feedback | 269 | conclusions/feedback.py + remediation scripts | calibration/* 全般、conclusions/*、observability/followup_watch.py | AP3 anchor ラベル（TP/FP/FN）。R1 データ連続の最重要資産。retention 180d |
| sequence_events | 209 | scoring.py (seq_append) | scoring.py、routes/analytics・history.py | エスカレーションチェーン状態（30d）。NP1 上 cutover 時に持ち越すのが安全 |
| scenario_proposals | 193 | calibration/{proposal_lifecycle, scenario_apply, scenario_discoverer, scenario_improver, sensor_disable_proposer}.py | calibration/*、attention.py、routes/calibration_v2.py | 較正ガバナンス lifecycle（アナリスト accept/snooze 判断を含む） |
| ct_log_known_ca_per_domain | 118 | sensors/ct_log.py | 同左 | 既知 CA ベースライン。リセットすると新規 CA 誤検知が再発 |
| daily_summary | 114 | routes/core.py (daily_summary_upsert) | routes/admin.py | 長期分析メモリ（730d 保持設計、year-over-year 比較用）。再生成不可 |
| scenario_drift_events | 110 | calibration/drift_watchdog.py、proposal_lifecycle.py | calibration/*、attention.py、routes/calibration_v2.py | drift 検知台帳（AP3 DRIFT chip の履歴） |
| confirmed_threats | 104 | routes/admin.py、routes/conclusions_v2.py | routes/admin.py、routes/core.py (noise_excl_match) | 人手 ground truth。retention 除外（恒久保持指定、database.py L5430 コメント） |
| cooccurrence_stats | 101 | routes/core.py (cooccurrence_update) | **engine.py**（収斂ゲーティング入力）、routes/admin.py | 収斂学習統計。再構築には長期の共起観測が必要 |
| threshold_history | 100 | calibration/threshold_history.py + remediation scripts | calibration/{auto_apply_tier_governor, lineage, tl_threshold_calibrator}.py | 較正系譜（NP6 lineage） |
| scenario_discovery_run | 92 | calibration/scenario_discoverer.py | routes/calibration_v2.py | proposal 由来 trace（NP6 検証経路） |
| discovery_cluster | 86 | calibration/{scenario_discoverer, g3b_llm_annotator}.py | g3b_llm_annotator.py、routes/calibration_v2.py | 同上（proposal の根拠クラスタ） |
| cooccurrence_matrix_snapshot | 77 | analytics/cooccurrence.py | 同左 + routes/calibration_v2.py | 収斂行列スナップショット（較正資産） |
| ct_log_domain_first_observed | 68 | sensors/ct_log.py | 同左 | first-seen ベースライン。リセットすると既知ドメインを新規と誤認 |
| config_runtime_value | 50 | config_layered.py | config_layered.py | 運用中に調整した layered config 現在値 |
| config_change_log | 23 | config_layered.py、audit_middleware.py | routes/llm_routing_v2.py | 設定変更監査（AP4） |
| llm_sources | 20 | intel_queue.py (intel_source_*) | intel_queue.py、intel_auto_judge.py | ソース credibility 学習（outcome 蓄積で成長する較正資産） |
| scenarios | 5 | routes/admin.py、calibration/scenario_apply.py (scenario_upsert) | scenarios.py (Layer 2)、calibration/proposal_lifecycle.py | シナリオ state/enabled の永続化（Layer 2） |
| llm_routing_override_history | 4 | llm_routing.py | llm_routing.py | routing 変更監査（4 行、実運用履歴） |
| auto_apply_tier_state | 3 | calibration/auto_apply_tier_repository.py | 同左 | tier governor の現在状態。失うと TIER0 リセット（保守化）で自動適用が停滞 |
| scenario_change_log | 3 | routes/admin.py | routes/admin.py | シナリオ変更監査（恒久保持指定） |
| auto_apply_tier_marker | 1 | calibration/auto_apply_tier_repository.py | 同左 | 同上 |
| scenario_reserved_ids | 1 | database.py (scenario_purge 時) | scenarios.py | purge 済 ID の再利用防止（整合性資産） |
| users | 1 | auth.py | auth.py、routes/__init__.py (_require_admin) ほか | 認証。移行必須 |
| user_settings | 1 | auth.py | auth.py | 同上 |

### 2b. 再生成可（31 + 1）

| テーブル | 行数 | ライター | リーダー | 根拠 |
|---|---:|---|---|---|
| scenario_contribution_log | 1,051,800 | routes/core.py (scenario_contribution_append、~1 行/国/30 秒) | calibration/_proposal_guards.py、routes/core (weight_advisory) | 導出値。90d retention、advisory の参照窓は最大 30d → 30 日で実用回復（§4 Q4） |
| time_series | 178,335 | routes/core.py (series_append、per-key ring) | routes/core・history.py | UI 履歴チャート用導出系列。28d 相当で自然回復 |
| time_series_ts | 59,445 | routes/core.py (ts_append、ring 8064/国 = 28d@5min) | routes/analytics・core・history.py | 同上 |
| llm_call_log | 26,503 | llm_client.py | routes/intel.py、calibration/{g3b, sensor_disable_proposer}.py | LLM 呼び出し監査。設計上 30d で消える運用ログ（新環境で再蓄積が設計通り） |
| sensor_observation_ts | 19,480 | routes/core.py (sensor_obs_record、TTL 24h) | routes/sensors_v2.py、calibration/_proposal_guards.py | 24 時間ローリング。1 日で完全回復 |
| sensor_fetch_log | 14,108 | sensors/base.py (fetch_log_append) | routes/admin・analytics.py、calibration/sensor_disable_proposer.py | 7d retention の信頼性ログ |
| bg_observer_cycle_log | 8,170 | background_observer.py | observability/followup_watch.py、routes/conclusions_v2.py | 30d retention のサイクル監査 |
| threat_history | 1,000 | routes/core.py (threat_append_scoped、ring 1000/シナリオ) | routes/core・history.py、conclusions_v2.py | v1 系 TL 履歴。background worker が継続 populate、TL 履歴の正は conclusions/scenario_tl_observation |
| focus_switch_log | 3,326※ | **なし（writer RETIRED 2026-05-30）** | database.py 内部 (bg_observer_cycle_summary が参照) | ※実質 dead。評価エンドポイント撤去済（analytics.py L998 コメント）。180d retention で自然消滅中。破棄可に近いが読み経路が残るため当面は再生成可扱い |
| llm_intel | 259 | intel_queue.py (intel_upsert) | intel_queue、intel_auto_judge、intel_corroboration、sensors/convergence_tracker.py | 7d retention の intel キュー。判断結果は auto_judge_decisions 側に永続 |
| climate_events | 165 | climate.py | climate.py | 48h retention のキャッシュ |
| llm_embed_call_log | 188 | llm_embedding.py | routes/conclusions_v2.py (stats) | 運用ログ |
| sensor_caches | 32 | persistence.py (sensor_cache_set) | persistence.py | 最新 fetch キャッシュ。次回 fetch で回復 |
| scenario_sensor_coverage | 34 | routes/analyst.py::update_coverage_for_scenario（scoring loop から自動 upsert） | routes/analyst.py (F5 panel) | 現在状態スナップショット。次の scoring tick で全量再構築 |
| baseline_cache | 28 | scoring.py、routes/core.py (baseline_set) | scoring.py、routes/core.py | CF Radar API を BASELINE_DATE_RANGE=28d で refetch すれば即日回復 |
| airspace_baseline | 19 | routes/core.py (airspace_set) | routes/core.py → scoring.py (_compute_airspace_status) | AIRSPACE_WINDOW=20 readings/空港のローリング。1 日以内に回復 |
| attention_metric_p95 | 11 | attention_learning.py | routes/attention_v2.py | observation からの導出値（observation は移行） |
| hidden_signal_log | 15 | intel_queue.py、routes/core.py | routes/analyst.py | F4 自動ログ（期待信号の欠落）。短命・再蓄積可 |
| llm_embed_dedup_log | 9 | llm_embedding.py | routes/conclusions_v2.py | 運用ログ |
| sensor_zscore_stats | 2 | scoring.py (zscore_stats_update) | scoring.py、routes/analytics.py | 適応 z-score 統計。ADAPTIVE_ZSCORE_MIN_SAMPLES=50 で回復（数時間〜数日） |
| decisions | 0 | decisions.py ← routes/decisions.py (v2 Decision Layer) | 同左 | live スキーマだが行 0（§4 Q3）。v3 で新設すればよい |
| attention_snooze | 0 | attention.py | attention.py | live 機能、未使用 |
| auto_apply_cooldown | 0 | calibration/auto_apply_tier_repository.py | 同左 | governance runtime、現在空 |
| llm_feature_state | 0 | llm_features.py | llm_features.py | Feature Hub 状態、未使用（デフォルト運用） |
| llm_feature_state_history | 0 | llm_features.py | llm_features.py | 同上 |
| llm_routing_override | 0 | llm_routing.py | llm_routing.py | override 現在なし |
| llm_shadow_invocation | 0 | llm_client.py (llm_shadow_invocation_append) | routes/conclusions_v2.py (llm_routing_stats) | SHADOW_DUAL 用 live スキーマ、発火時のみ書き込み |
| noise_exclusion | 0 | routes/admin.py | routes/admin.py、routes/core.py | live 機能、ルール未登録 |
| revoked_tokens | 0 | auth.py | auth.py、ws.py | JWT TTL 分しか意味を持たない（retention = refresh TTL+1h） |
| user_attention_thresholds | 0 | routes/attention_v2.py | 同左 | live 機能、未使用 |
| scenario_participants | 0 | routes/admin.py、calibration/scenario_apply.py (scenario_upsert) | scenarios.py (Layer 2) | live スキーマだが未使用（§4 Q2）。Layer 1 (geo_data.json) が実源 |
| **convergence_snapshots.db::snapshots** | (別 DB) | sensors/convergence_tracker.py (_SnapshotDB.record) | 同左 (get_snapshots) | 72h ローリング（CONVERGENCE_SNAPSHOT_RETENTION_H=72）。3 日で完全回復（§4 Q5） |

### 2c. 破棄可（13 + 実質 1）

| テーブル | 行数 | ライター | リーダー | 根拠 |
|---|---:|---|---|---|
| ach_matrices | 164 | routes/analyst.py (F8) | routes/analyst.py | データ全量がテスト残骸（§4 Q1）。tradecraft 統合は 2026-04-30 棚上げ |
| ach_hypotheses | 0 | routes/analyst.py | 同左 | tradecraft 休眠、行 0 |
| ach_evidence | 0 | routes/analyst.py | 同左 | 同上 |
| ach_scores | 0 | routes/analyst.py | 同左 | 同上 |
| disconfirming_evidence | 164 | routes/analyst.py (F6) | 同左 | 82 回テスト実行 × 2 の残骸（実アナリスト入力ではない） |
| key_assumptions | 246 | routes/analyst.py (F10) | 同左 | 82 × 3 のテスト残骸 |
| key_assumption_change_log | 328 | routes/analyst.py | 同左 | 82 × 4 のテスト残骸 |
| dissenting_views | 82 | routes/analyst.py (F11) | 同左 | 82 × 1 のテスト残骸 |
| premortem_entries | 82 | routes/analyst.py (F13) | 同左 | 同上 |
| decision_ledger | 984 | routes/analyst.py (_autolog write-through) | routes/analyst.py | 984 = 82 × 12。テスト由来 auto=true 行が全量（§4 Q3） |
| shadow_sampler_state | 3 | **なし**（CREATE TABLE のみ、参照コードなし） | なし | v1→v2 shadow sampler 足場の残滓。dead schema 確定 |
| schema_version | 1 | migration 機構 | migration 機構 | v3 は新スキーマ管理で出発 |
| sqlite_sequence | 41 | SQLite 内部 | SQLite 内部 | AUTOINCREMENT 管理。移行対象外 |
| (focus_switch_log) | — | — | — | 上表※参照。writer 撤去済で実質こちらに属す。v3 で schema ごと不要 |

## 3. 疑問 6 点の回答

### Q1. ach_matrices 164 行 vs ach_evidence/ach_scores 0 行

**自動テストの残骸。手動実験ですらない。**
`tests/test_analyst_permissions.py` が `from radar.database import db` で**本物のシングルトン DB** に
接続し（temp DB 分離なし、L25-27）、1 回のフル実行で ACH matrix 2 件 (L183, L295)・disconf 2 件・
assumption 3 件・dissent 1 件・premortem 1 件を実 POST で作成する。テストは matrix しか作らず
hypothesis/evidence/score は一切追加しない — これが「matrices 164 / 下位 3 表 0」の直接原因。
全 tradecraft 表が 82 の倍数（164=82×2、246=82×3、328=82×4、984=82×12）で、**82 回のテスト実行**
と完全一致。`scripts/smoke_tradecraft.sh`（post-deploy smoke、BASE_URL=本番）も同型の書き込みを行う。
→ tradecraft 系のデータに資産価値はゼロ。v3 では「テストが本番 DB に書ける」構造自体を禁止すべき
（S3 への教訓）。

### Q2. scenario_participants 0 行 — participants の実ロード元

**geo_data.json["SCENARIOS"]（Layer 1 プリセット）が実源。スキーマと実装の乖離ではなく「Layer 2 未使用」。**
`radar/scenarios.py` は 2 層設計: Layer 1 = geo_data.json プリセット（L311-329）、Layer 2 = SQLite
（scenarios + scenario_participants、L334-412）の override。L387 で participants が DB に無ければ
`base.participants`（= Layer 1）へフォールバックする明示コードがある。書き込み経路
（`scenario_upsert` が DELETE→INSERT、database.py L3969-3972）は commit 57b1846 で修理済かつ live
だが、**participant 構成を DB で上書きした scenario が一件もない**のが 0 行の意味。scenarios 5 行は
5 プリセットの state/enabled 永続化のみ。

### Q3. decisions (0) と decision_ledger (984) の関係

**両者は意図的併存で、`decisions` が新・正、`decision_ledger` は旧 F14 tradecraft 台帳。**
`radar/decisions.py` docstring (L9-18) が関係を明文化: decision_ledger = Phase 5 以前の tradecraft
ad-hoc ノート台帳（routes/analyst.py の `_autolog` write-through が書く）、decisions = Phase 5
(2026-04-30) の構造化 governance 台帳（supersede lifecycle、AP4 Decision Trail、retention は
superseded 行のみ 90d）。decisions が 0 行なのは v2 Decision Layer API（routes/decisions.py、
snooze/dismiss 等）が本番でまだ一度も使われていないため。decision_ledger の 984 行は Q1 の通り
82×12 のテスト残骸。→ v3 は `decisions` 型（構造化 governance）のみ持ち越し、decision_ledger は
スキーマごと破棄。

### Q4. conclusions 1.05M / scenario_contribution_log 1.05M の書き込み経路と retention

- **conclusions**: ライター = `radar/conclusions/persistence.py`（scoring tick 経由）+
  `scripts/backfill_v2_ledger.py`（過去分 backfill）。retention = **90d**
  （`CONCLUSIONS_RETENTION_DAYS` env、database.py L5443）。
- **scenario_contribution_log**: ライター = `db.scenario_contribution_append` ← `routes/core.py`
  （scoring tick、~1 行/国/サイクル ≈30 秒 → 4 participant シナリオで ~11.5k 行/日）。
  retention = **90d**（`SCENARIO_CONTRIB_RETENTION_DAYS`、L5411）。参照窓は weight_advisory の
  最大 720h (30d) なので 90d は 60d マージン込み。
- **retention の制御主体**: `database.py::_prune_stale_rows`。起動時 `startup_cleanup`
  （radar/__init__.py:281）+ 日次 `periodic_cleanup`（radar/scheduler.py:714）の 2 経路で実行。
  365d 化（2026-10 判断予定）は未実施 — v3 移行時に retention 方針を同時決定するのが合理的。

### Q5. convergence_snapshots.db（第 2 SQLite）

`radar/sensors/convergence_tracker.py` の `_SnapshotDB`（コードからスキーマ読取、DB ファイル未読）:
テーブルは **`snapshots` 1 つのみ** — `(id INTEGER PK AUTOINCREMENT, theater TEXT, ts REAL,
elevated_sensors TEXT/*JSON list*/)` + index `idx_theater_ts`。パスは
`$DB_PATH/convergence_snapshots.db`（L54-58）。ライター/リーダーとも convergence_tracker.py のみ。
retention は 72h ローリング（`CONVERGENCE_SNAPSHOT_RETENTION_H=72`、tick ごとに prune）。
判定窓は `CONVERGENCE_MIN_HOURS=6`。→ **再生成可**（破棄しても 6 時間で判定可能、72 時間で全深度回復）。
v3 では main DB への統合を推奨（第 2 DB は WAL 管理・バックアップの死角）。

### Q6. ベースライン系の再構築所要期間（破棄した場合の検知力回復日数）

| テーブル | 蓄積機構 | z/判定が有効になるまで | 全深度回復 |
|---|---|---|---|
| hod_baseline | CF Radar API から **起動時 prefill 可**（`prefill_hod_baseline_bg`、HOD_BASELINE_DAYS=28 を API が返す） | **即日**（prefill 成功時）/ API 不通時 7 日 | 即日 / 28 日 |
| baseline_cache | CF API refetch（BASELINE_DATE_RANGE=28d） | **即日** | 即日 |
| checkhost_hod | ライブ観測のみ（backfill 不能）。HOD_MIN_SAME_HOUR=7 | **7 日** | 28 日（672 buckets/国） |
| bgp_hod | 同上（BGP_HOD_MIN=HOD_MIN_SAME_HOUR=7） | **7 日** | 28 日 |
| gdelt_dow | ライブ観測のみ。DOW_MIN_SAMPLES=3（同一曜日 3 サンプル） | **3 週** | 20 週（140 日次 buckets/国） |
| airspace_baseline | ローリング readings（AIRSPACE_WINDOW=20/空港） | **≤1 日** | ≤1 日 |
| sensor_zscore_stats | ADAPTIVE_ZSCORE_MIN_SAMPLES=50/センサー/国 | 数時間〜数日（fetch 周期依存） | 同左 |

**結論**: 全破棄した場合のクリティカルパスは gdelt_dow の 3 週、次点で bgp/checkhost HOD の 7 日。
その間 HOD/DoW z-score は warmup フォールバック（固定閾値）で動作 = NP1 感度の実質低下。
backfill 不能な 3 表（bgp_hod / checkhost_hod / gdelt_dow）は行数も小さく（計 1.1 万行）**移行が唯一の
合理解**。hod_baseline / baseline_cache は CF API 依存を許容するなら再生成でもよいが、移行コストが
ほぼゼロなので hod_baseline は移行に分類した。

## 4. v3 移行マップへの示唆（Phase S3 入力）

1. **theater 語彙カラムの正規化が移行対象 15 表に波及**: `_A4_THEATER_TABLES`（database.py L29-44）=
   baseline_cache, hod_baseline, checkhost_hod, bgp_hod, gdelt_dow, time_series_ts, time_series,
   sequence_events, sensor_zscore_stats, noise_exclusion, confirmed_threats, daily_summary,
   cooccurrence_stats, climate_events, llm_intel。現状は v24 の GENERATED `country` ミラー併存。
   **v3 スキーマは `country` を実カラムにして移行 ETL で rename する**（A-5 sunset を移行と同時に完了）。
   convergence_snapshots.db::snapshots も `theater` カラムを持つ（統合時に同時 rename）。
2. **conclusions の retention 決定を移行と同時に**: 90d→365d 保留（2026-10 予定）を S3 で確定。
   365d 化なら llm_prompts の床（conclusions+30d）も連動して ~395d に伸びる点に注意。
3. **テスト分離の構造的強制**: Q1 の教訓。v3 の repository 層（D1 §3c）はコンストラクタ注入の
   DB パスを必須にし、シングルトン `db` の import だけでテストが本番へ書ける構造を廃止する。
   tradecraft 系 9 表（ach_* 4、disconf、dissent、premortem、key_assumptions + change_log、
   decision_ledger）はスキーマごと v3 から除外（復活条件はメモリ記録の通り棚上げ文書に従う）。
4. **scenario 永続化の再設計**: scenario_participants が 0 行のまま Layer 2 が事実上未使用。
   v3 では「geo_data.json プリセット + DB override」の 2 層を維持するか、DB 一本化するかを
   S3 で決める。維持する場合も participants を scenarios テーブル内 JSON に畳む選択肢がある
   （現行の別テーブルは JOIN 1 回分のコストに見合う利用実績がない）。
5. **第 2 SQLite の廃止**: convergence_snapshots.db は main DB へ統合（72h ローリングなので
   移行データは不要、スキーマ統合のみ）。
6. **移行 ETL の規模感**: 実質は conclusions (1.05M) + scenario_tl_observation (114k) の 2 表で
   92.6%。両者とも observed_at 単調・追記型なので、チャンク分割コピーで機械的に移行可能。
   残り 33 表は合計 9 万行未満で 1 トランザクションでも終わる。
7. **decisions（v2 Decision Layer）は v3 の governance 台帳の出発点**: スキーマ設計
   （supersede lifecycle、actor+reason+parameters、AP4）は NP 群に整合済。0 行なのでデータ移行
   不要、スキーマだけ v3 に引き継ぐ。
