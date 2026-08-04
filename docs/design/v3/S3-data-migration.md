# S3 — データスキーマ仕様 + 新旧移行マップ

**スコープ**: v3 が保持すべき永続データ資産の定義（スキーマ・キー・retention）と、現行本番 DB
（79 表 + `convergence_snapshots.db`）から v3 スキーマへの移行 ETL の受け入れ条件。
リビルド原則 **R1（データ連続）** の実行文書。

**隣接仕様との境界**:
- 各データの**意味論**（TL の導出、conclusions envelope、attention_score 等）は S1 系列が持つ。
  本書は「その値をどの器に、どの粒度で、どれだけの期間置くか」だけを規定する
- API から見た読み書き契約は S2、テスト移植計画は S5
- **本書は資産定義であるため、S0 §3 の例外として CREATE TABLE 形式の転載を行う**
  （実装構造の記述ではなく、v3 実装が現行 DB を読まずに移行 ETL を書けるようにするための資産目録）

**一次ソース**: `radar/database.py` の `_SCHEMA_SQL` / `_migration_v*` / `_prune_stale_rows`、
`radar/sensors/convergence_tracker.py::_SnapshotDB`、`scripts/backup_radar_db.sh`。
分類の起点は [D4-data-assets.md](D4-data-assets.md)（移行 35 / 再生成可 31 / 破棄可 13）。

---

## 1. 用語

CLAUDE.md の用語定義に従う（country / scenario / participant / focused / background / C-lite）。本書固有:

- **移行表**: v3 へデータごと持ち越す表。失うと較正・判断履歴・認証が復元不能
- **再生成可表**: スキーマのみ持ち越し、データは v3 稼働開始後に自然蓄積する表
- **破棄表**: スキーマごと v3 に持ち込まない表
- **backfill 不能**: 外部 API から過去分を取得できず、ライブ観測の経過時間でしか埋まらないベースライン
- **cutover**: v1/v2 系を停止し v3 を本番昇格させる瞬間。移行 ETL はこの直前に確定実行する
- **theater 語彙**: 現行スキーマに残る旧カラム名。v3 では `country` に統一（CLAUDE.md 廃止用語）

---

## 2. 挙動条項

### 2.1 移行原則

#### S3-DATA-001: v3 は移行 35 表のデータを完全に引き継ぐ
**挙動**: v3 の初回起動時点で、§2.2 に列挙する 35 表のデータが移行済みであること **MUST**。そのうち **backfill 不能な 3 表（`checkhost_hod` / `bgp_hod` / `gdelt_dow`）は移行必須**であり、再生成で代替してはならない **MUST NOT**。破棄した場合、HOD z-score は 7 日、DoW z-score は 3 週にわたり warmup フォールバック（固定閾値）で動作し、NP1（感度優先）の実質的な低下を招く。
**根拠**: D4 §3 Q6 の回復期間表、`radar/scoring.py`（HOD_MIN_SAME_HOUR=7）、`radar/sensors/gdelt.py`（DOW_MIN_SAMPLES=3） ／ **検証**: 未検証（移行 ETL は未実装。S3-DATA-025〜029 が受け入れ条件を定義する） ／ **分類**: CORE

#### S3-DATA-002: v3 スキーマは `country` を実カラムとし、`theater` 語彙を持たない
**挙動**: v3 のいかなる表も `theater` という名のカラムを持ってはならない **MUST NOT**。現行の 15 表（+ `convergence_snapshots.db::snapshots`）が持つ `theater TEXT` は、v3 では `country TEXT`（ISO2 code）として定義し、移行 ETL がカラム名を変換する **MUST**。現行の `country` は v24 migration が追加した `GENERATED ALWAYS AS (theater) VIRTUAL` の読み取り専用ミラーであり、v3 ではこの dual-read 構造を持たない **MUST NOT**。
**対象 15 表**: `baseline_cache` / `hod_baseline` / `checkhost_hod` / `bgp_hod` / `gdelt_dow` / `time_series_ts` / `time_series` / `sequence_events` / `sensor_zscore_stats` / `noise_exclusion` / `confirmed_threats` / `daily_summary` / `cooccurrence_stats` / `climate_events` / `llm_intel`。うち**データ移行を伴うのは 8 表**（hod_baseline, checkhost_hod, bgp_hod, gdelt_dow, sequence_events, confirmed_threats, daily_summary, cooccurrence_stats）。残る 7 表 + snapshots は再生成可のためスキーマ定義のみの rename。
**根拠**: `radar/database.py:29-45`（`_A4_THEATER_TABLES`）、`:622-649`（`_migration_v24_generated_country`） ／ **検証**: tests/test_a4_country_generated_column.py（7 tests、現行 dual-read の回帰。v3 では SCAFFOLD として破棄） ／ **分類**: CORE（D2 A-5 sunset を移行と同時に完了させる）

#### S3-DATA-003: 永続層は単一 DB が管轄する
**挙動**: v3 は `convergence_snapshots.db` のような第 2 SQLite ファイルを持ってはならない **MUST NOT**。収斂スナップショットは main DB の表として定義する **MUST**。
**根拠**: D2 A-09（バックアップ / WAL / スキーマ管理の盲点）、`radar/sensors/convergence_tracker.py:54-107` ／ **検証**: 未検証 ／ **分類**: CORE

#### S3-DATA-004: 台帳表は append-only とし、行の意味を事後に書き換えない
**挙動**: `conclusions` / `analyst_feedback` / `threshold_history` / `auto_judge_decisions` / `scenario_drift_events` / `config_change_log` / `scenario_change_log` / `llm_routing_override_history` / `auto_apply_tier_state` は append-only **MUST**。既存行の訂正は新しい行の追記と状態遷移カラム（`state` / `ack_state` / `applied` 等）の更新でのみ表現する **MUST**。これは AP4（判断履歴の時系列再生）と NP6（導出開示）の前提条件である。
**根拠**: `radar/database.py:1232-1260`（threshold_history の `state IN ('active','reverted','superseded')`）、`:1255-1275`（scenario_drift_events の ack_state）
**検証**: tests/test_conclusions_persistence.py（14 tests、append-only 不変条件） ／ **分類**: CORE

#### S3-DATA-005: 移行対象外の表は v3 スキーマに存在しない
**挙動**: §2.5 の破棄 13 表 + `focus_switch_log` は、v3 のスキーマ定義に現れてはならない **MUST NOT**。データの export 保全も不要（S3-DATA-060/061 に根拠）。
**分類**: CORE

---

### 2.2 移行 35 表のスキーマ定義

以下 5 群、計 35 表。DDL は現行 `_SCHEMA_SQL` からの転載に S3-DATA-002 の rename を適用した
**v3 規範形**である（`theater` は `country` に置換済み、v24 の GENERATED 列は除去済み）。
行数は 2026-08-03 実測。

#### S3-DATA-010: 較正コア群（5 表）— 失うと較正が 2 サイクル分後退する
**挙動**: 以下 5 表を移行 **MUST**。`conclusions.llm_prompt_sha256` は `llm_prompts.prompt_sha256` への論理参照であり、**両表は必ずペアで移行 MUST**（片方のみの移行は NP6 の遡及経路を切断する）。`analyst_feedback.conclusion_id` は `conclusions(id)` への FK 実体を持つため、移行順序は conclusions → analyst_feedback **MUST**（S3-DATA-020）。

```sql
-- conclusions (1,047,254) — v2 結論 ledger。AP4 replay / 較正 / recall 検証の中核
CREATE TABLE conclusions (
  id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, conclusion_type TEXT NOT NULL, state TEXT,
  confidence REAL NOT NULL,            -- [0,1] クランプ済
  observed_at REAL NOT NULL,           -- unix epoch 秒。retention / 較正窓のキー
  formula_ref TEXT NOT NULL, threshold_ref TEXT NOT NULL,  -- NP6: 式 / 閾値セットのバージョンタグ
  source_urls TEXT NOT NULL,           -- JSON list。NP6 一次ソース
  llm_prompt_sha256 TEXT,              -- llm_prompts への論理参照（NULL = LLM 非使用）
  calibration_status TEXT NOT NULL,    -- NP5+8
  conclusion_unavailable_reason TEXT,  -- 結論不可の理由（NULL = 結論あり）
  metadata TEXT NOT NULL );            -- JSON。型別ペイロード
CREATE INDEX idx_conclusions_scenario_time  ON conclusions (scenario_id, observed_at DESC);
CREATE INDEX idx_conclusions_type_time      ON conclusions (conclusion_type, observed_at DESC);
CREATE INDEX idx_conclusions_scen_type_time ON conclusions (scenario_id, conclusion_type, observed_at DESC);
-- llm_prompts (15,928) — NP6 プロンプト遡及。sha256 キーの dedup ストア
CREATE TABLE llm_prompts ( prompt_sha256 TEXT PRIMARY KEY, prompt_text TEXT NOT NULL,
  model TEXT NOT NULL, temperature REAL, prompt_version TEXT,
  first_seen_at REAL NOT NULL, last_seen_at REAL NOT NULL,   -- last_seen_at が retention キー
  use_count INTEGER NOT NULL DEFAULT 1 );
CREATE INDEX idx_llm_prompts_last_seen ON llm_prompts (last_seen_at DESC);
-- analyst_feedback (269) — AP3 anchor ラベル。R1 最重要資産（recall の唯一の ground truth）
CREATE TABLE analyst_feedback ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  conclusion_id TEXT NOT NULL REFERENCES conclusions(id),
  label TEXT NOT NULL CHECK (label IN ('TRUE_POSITIVE','FALSE_POSITIVE','TRUE_NEGATIVE','FALSE_NEGATIVE')),
  observed_outcome_url TEXT,
  analyst_id TEXT NOT NULL,            -- 'auto:*' prefix は自動ラベル（human-only 集計時に除外）
  observed_at REAL NOT NULL, notes TEXT );
CREATE INDEX idx_feedback_conclusion   ON analyst_feedback (conclusion_id);
CREATE INDEX idx_feedback_analyst_time ON analyst_feedback (analyst_id, observed_at DESC);
-- scenario_tl_observation (114,160) — TL 較正窓 42d の原データ
CREATE TABLE scenario_tl_observation ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario_id TEXT NOT NULL, observed_at REAL NOT NULL, score REAL NOT NULL,
  tl INTEGER,                          -- 1=CRITICAL … 5=NORMAL。NULL = INSUFFICIENT_DATA
  cyber REAL NOT NULL DEFAULT 0, physical REAL NOT NULL DEFAULT 0, info REAL NOT NULL DEFAULT 0,
  convergence_bonus REAL NOT NULL DEFAULT 0,
  scoring_mode TEXT NOT NULL DEFAULT 'full',    -- full / c_lite（背景シナリオ）
  active_countries TEXT NOT NULL DEFAULT '[]' );  -- JSON list of ISO2
CREATE INDEX idx_scenario_tl_obs_sid ON scenario_tl_observation (scenario_id, observed_at DESC);
CREATE INDEX idx_tl_obs_sid_mode_ts  ON scenario_tl_observation (scenario_id, scoring_mode, observed_at DESC);
-- inconclusive_continuity_log (28,503) — NP5+8 null-zone 継続日数（AP3 自己評価の入力）
CREATE TABLE inconclusive_continuity_log ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  observed_at REAL NOT NULL, scenario_id TEXT NOT NULL, conclusion_type TEXT NOT NULL,
  is_available INTEGER NOT NULL DEFAULT 0,   -- 0 = 結論不可
  reason TEXT,                               -- insufficient_data 等
  run_length_sec REAL NOT NULL DEFAULT 0,    -- 同一状態の継続秒数（恒常的結論不可の検知値）
  first_seen_at REAL NOT NULL, metadata TEXT NOT NULL DEFAULT '{}' );
CREATE INDEX idx_continuity_scen_type_time ON inconclusive_continuity_log (scenario_id, conclusion_type, observed_at DESC);
CREATE INDEX idx_continuity_observed_at    ON inconclusive_continuity_log (observed_at DESC);
```
**根拠**: `radar/database.py:972-998`, `:957-967`, `:1215-1229`, `:1868-1882`, `:1198-1212` ／ **検証**: tests/test_conclusions_persistence.py（14）、tests/test_llm_prompt_persistence.py（12）、tests/test_threat_level_derive.py（15、tl=None の意味論）
**分類**: CORE

#### S3-DATA-011: ベースライン群（7 表）— backfill 不能・語彙 rename 対象
**挙動**: 以下 7 表を移行 **MUST**。`hod_baseline` / `checkhost_hod` / `bgp_hod` / `gdelt_dow` / `cooccurrence_stats` は S3-DATA-002 の rename 対象（`theater` → `country`）**MUST**。HOD 系はバケット数上限でローリング trim される（時間 retention ではない）。

```sql
-- hod_baseline (18,144) / checkhost_hod (4,724) / bgp_hod (5,398) — hour-of-day ベースライン
CREATE TABLE hod_baseline  ( country TEXT NOT NULL, hour_bucket INTEGER NOT NULL,
                             avg_spike    REAL NOT NULL, PRIMARY KEY (country, hour_bucket) );
CREATE TABLE checkhost_hod ( country TEXT NOT NULL, hour_bucket INTEGER NOT NULL,
                             success_rate REAL NOT NULL, PRIMARY KEY (country, hour_bucket) );
CREATE TABLE bgp_hod       ( country TEXT NOT NULL, hour_bucket INTEGER NOT NULL,
                             prefix_count REAL NOT NULL, PRIMARY KEY (country, hour_bucket) );
-- gdelt_dow (693) — day-of-week ベースライン（backfill 不能、全深度回復 20 週）
CREATE TABLE gdelt_dow ( country TEXT NOT NULL, day_bucket INTEGER NOT NULL,  -- day_bucket = epoch 日
                         weekday INTEGER NOT NULL, tone REAL NOT NULL,        -- weekday = 0-6
                         PRIMARY KEY (country, day_bucket) );
CREATE INDEX idx_gdelt_dow_weekday ON gdelt_dow (weekday);
-- ct_log_known_ca_per_domain (118) — 既知 CA ベースライン。リセットで新規 CA 誤検知が再発
CREATE TABLE ct_log_known_ca_per_domain (
  domain TEXT NOT NULL, ca_normalized TEXT NOT NULL, ca_raw TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL, cert_count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (domain, ca_normalized) );
CREATE INDEX idx_ct_known_ca_domain ON ct_log_known_ca_per_domain (domain);
-- ct_log_domain_first_observed (68) — first-seen ベースライン
CREATE TABLE ct_log_domain_first_observed ( domain TEXT PRIMARY KEY, first_observed REAL NOT NULL );
-- cooccurrence_stats (101) — 収斂ゲーティングの学習統計（engine の入力）
CREATE TABLE cooccurrence_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_a TEXT NOT NULL, sensor_b TEXT NOT NULL,
  country TEXT NOT NULL DEFAULT '',    -- '' = グローバル（ACCIDENTAL A4）
  co_count INTEGER NOT NULL DEFAULT 0,
  solo_a_count INTEGER NOT NULL DEFAULT 0, solo_b_count INTEGER NOT NULL DEFAULT 0,
  last_updated REAL NOT NULL, UNIQUE (sensor_a, sensor_b, country) );
```
**根拠**: `radar/database.py:684-716`, `:1167-1182`, `:1043-1056`、trim は `:2997`, `:3017`, `:3100` ／ **検証**: tests/test_ct_log_redesign.py（21、first_observed / known_cas 評価） ／ **分類**: CORE

#### S3-DATA-012: 較正ガバナンス群（8 表）— NP6 lineage と提案 lifecycle
**挙動**: 以下 8 表を移行 **MUST**。`discovery_cluster.run_id` → `scenario_discovery_run.id` → `cooccurrence_matrix_snapshot.id` の FK 鎖があるため、移行順序は snapshot → run → cluster **MUST**。`threshold_history.revertible_to_id` は同一表への自己参照 FK であり、**単一トランザクション内で id 順に挿入 MUST**（分割コミットは参照切れを生む）。

```sql
-- threshold_history (100) — 較正系譜（NP6 lineage）
CREATE TABLE threshold_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, emitted_at REAL NOT NULL,
  key TEXT NOT NULL, value TEXT NOT NULL,      -- key = 閾値の config キー
  scope_scenario_id TEXT,                      -- NULL = グローバル
  effective_from REAL NOT NULL, effective_to REAL,   -- effective_to NULL = 現行
  derived_from TEXT NOT NULL,                  -- 導出元（NP6）
  applied_by TEXT NOT NULL,                    -- analyst id / 'auto:<tier>'
  revertible_to_id INTEGER REFERENCES threshold_history(id),   -- 自己参照 FK
  sample_n INTEGER NOT NULL DEFAULT 0, formula_ref TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}', magnitude_pct REAL NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','reverted','superseded')) );
CREATE INDEX idx_threshold_history_key_time     ON threshold_history (key, effective_from DESC);
CREATE INDEX idx_threshold_history_scope_active ON threshold_history (scope_scenario_id, state);
-- scenario_proposals (193) — 較正提案 lifecycle（アナリスト accept/snooze 判断を含む）
CREATE TABLE scenario_proposals (
  id INTEGER PRIMARY KEY AUTOINCREMENT, emitted_at REAL NOT NULL,
  scenario_id TEXT NOT NULL, proposal_type TEXT NOT NULL, target_country TEXT,
  suggested_value_json TEXT NOT NULL DEFAULT '{}', evidence_json TEXT NOT NULL DEFAULT '{}',
  formula_ref TEXT NOT NULL, sample_n INTEGER NOT NULL DEFAULT 0,
  why_string TEXT,          -- AP2 自己説明（テンプレート生成）
  evidence_strength TEXT,   -- strong | moderate | weak | insufficient
  vitality_state TEXT,      -- active | dormant | data_gap
  state TEXT NOT NULL DEFAULT 'pending'
      CHECK (state IN ('pending','applied','dismissed','snoozed_30d','reverted','superseded')),
  state_changed_at REAL, state_changed_by TEXT, revertible_to_json TEXT );
CREATE INDEX idx_scenario_proposals_scenario ON scenario_proposals (scenario_id, emitted_at DESC);
CREATE INDEX idx_scenario_proposals_pending  ON scenario_proposals (state, emitted_at DESC);
-- scenario_drift_events (110) — drift 検知台帳（AP3 DRIFT chip の履歴）
CREATE TABLE scenario_drift_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, emitted_at REAL NOT NULL, scenario_id TEXT NOT NULL,
  drift_signal TEXT NOT NULL, severity TEXT NOT NULL CHECK (severity IN ('amber','red')),
  target_country TEXT, evidence_json TEXT NOT NULL DEFAULT '{}',
  formula_ref TEXT NOT NULL, sample_n INTEGER NOT NULL DEFAULT 0, why_string TEXT,
  ack_state TEXT NOT NULL DEFAULT 'unack'
      CHECK (ack_state IN ('unack','acknowledged','dismissed_as_false_positive')),
  ack_at REAL, ack_by TEXT, consecutive_runs INTEGER NOT NULL DEFAULT 1 );
CREATE INDEX idx_scenario_drift_events_scenario ON scenario_drift_events (scenario_id, emitted_at DESC);
CREATE INDEX idx_scenario_drift_events_unack    ON scenario_drift_events (ack_state, emitted_at DESC);
-- cooccurrence_matrix_snapshot (77) → scenario_discovery_run (92) → discovery_cluster (86)
CREATE TABLE cooccurrence_matrix_snapshot (
  id           INTEGER PRIMARY KEY AUTOINCREMENT, emitted_at REAL NOT NULL,
  window_days  INTEGER NOT NULL, bucket_hours INTEGER NOT NULL DEFAULT 24,
  cell_count   INTEGER NOT NULL, matrix_json TEXT NOT NULL,
  formula_ref  TEXT NOT NULL, evidence_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_cooccurrence_emitted_at ON cooccurrence_matrix_snapshot (emitted_at DESC);
CREATE TABLE scenario_discovery_run ( id INTEGER PRIMARY KEY AUTOINCREMENT, emitted_at REAL NOT NULL,
  matrix_snapshot_id INTEGER NOT NULL REFERENCES cooccurrence_matrix_snapshot(id),
  algorithm TEXT NOT NULL DEFAULT 'dbscan', eps REAL, min_samples INTEGER,
  n_clusters INTEGER NOT NULL DEFAULT 0, n_noise INTEGER NOT NULL DEFAULT 0,
  formula_ref TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}' );
CREATE INDEX idx_discovery_run_emitted_at ON scenario_discovery_run (emitted_at DESC);
CREATE TABLE discovery_cluster ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES scenario_discovery_run(id), cluster_index INTEGER NOT NULL,
  countries_json TEXT NOT NULL, centroid_json TEXT, annotation_json TEXT,
  annotation_state TEXT NOT NULL DEFAULT 'none' CHECK (annotation_state IN ('none','shadow','production')),
  suggested_scenario_id TEXT, formula_ref TEXT NOT NULL );
CREATE INDEX idx_discovery_cluster_run ON discovery_cluster (run_id);
-- auto_apply_tier_state (3) / auto_apply_tier_marker (1) — tier governor の現在状態
CREATE TABLE auto_apply_tier_state ( id INTEGER PRIMARY KEY AUTOINCREMENT, observed_at REAL NOT NULL,
  tier INTEGER NOT NULL, transition TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '', metrics_json TEXT NOT NULL DEFAULT '{}' );
CREATE TABLE auto_apply_tier_marker ( marker_key TEXT PRIMARY KEY, tier INTEGER NOT NULL,
  entered_at REAL NOT NULL, updated_at REAL NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}' );
```
**挙動（追加）**: `auto_apply_tier_state` / `auto_apply_tier_marker` を失った場合、tier governor は TIER0（最も保守的）にリセットされ自動適用が停滞する。両表は 4 行しかないが**移行必須 MUST**。
**根拠**: `radar/database.py:1232-1352`, `:2810-2850` ／ **検証**: tests/test_lineage.py（9）、tests/test_scenario_discoverer.py（11）、tests/test_auto_apply_tier_governor.py（`_block_live_db_access` の先例、S3-DATA-070 参照）
**分類**: CORE

#### S3-DATA-013: 判断・観測台帳群（6 表）
**挙動**: 以下 6 表を移行 **MUST**。`sequence_events` / `confirmed_threats` / `daily_summary` は S3-DATA-002 の rename 対象 **MUST**。

```sql
-- auto_judge_decisions (10,103) — 自動判断台帳（AP4）+ Layer1 backtest の ground truth
CREATE TABLE auto_judge_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, item_id TEXT NOT NULL,
  action_proposed TEXT NOT NULL CHECK (action_proposed IN ('confirm','reject','pending')),
  confidence REAL NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '',
  layer1_corroborators INTEGER NOT NULL DEFAULT 0, layer1_satisfied INTEGER NOT NULL DEFAULT 0,
  applied INTEGER NOT NULL DEFAULT 0, applied_at REAL, analyst_overrode INTEGER NOT NULL DEFAULT 0,
  analyst_override_action TEXT, analyst_override_at REAL, analyst_id TEXT );
CREATE INDEX idx_auto_judge_decisions_ts      ON auto_judge_decisions (ts DESC);
CREATE INDEX idx_auto_judge_decisions_item    ON auto_judge_decisions (item_id);
CREATE INDEX idx_auto_judge_decisions_applied ON auto_judge_decisions (applied, ts DESC);
-- attention_metric_observation (7,517) — AP1 attention_score p95 正規化の学習観測（原資産）
CREATE TABLE attention_metric_observation ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL, observed_at REAL NOT NULL, observed_value REAL NOT NULL );
CREATE INDEX idx_attention_metric_obs_rule_ts ON attention_metric_observation (rule_id, observed_at DESC);
-- alert_timeline (288) — AP4 alert lane 履歴。ring buffer 288 件（再生成不可）
CREATE TABLE alert_timeline ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, data_json TEXT NOT NULL );
CREATE INDEX idx_alert_timeline_ts ON alert_timeline (ts DESC);
-- sequence_events (209) — エスカレーションチェーン状態（30d retention + 国別 ring）
CREATE TABLE sequence_events ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  country TEXT NOT NULL, ts REAL NOT NULL, event_type TEXT NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}', scenario_id TEXT );
CREATE INDEX idx_seq_events_country_ts    ON sequence_events (country, ts DESC);
CREATE INDEX idx_sequence_events_scenario ON sequence_events (scenario_id, ts DESC);
-- confirmed_threats (104) — 人手 ground truth。retention 除外（恒久保持）
CREATE TABLE confirmed_threats ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  country TEXT NOT NULL, ts REAL NOT NULL, classification TEXT NOT NULL DEFAULT '',
  sensors_json TEXT NOT NULL DEFAULT '[]',
  threat_level INTEGER NOT NULL DEFAULT 5,   -- TL（1=CRITICAL … 5=NORMAL）
  notes TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT '' );
CREATE INDEX idx_confirmed_country_ts ON confirmed_threats (country, ts);
-- daily_summary (114) — 長期分析メモリ（730d 保持、year-over-year 比較用）。再生成不可
CREATE TABLE daily_summary ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  country TEXT NOT NULL, day_bucket INTEGER NOT NULL,
  avg_score REAL NOT NULL DEFAULT 0.0, max_score REAL NOT NULL DEFAULT 0.0,
  min_tl INTEGER NOT NULL DEFAULT 5, max_tl INTEGER NOT NULL DEFAULT 5,
  fired_sensors TEXT NOT NULL DEFAULT '[]', domain_scores TEXT NOT NULL DEFAULT '{}',
  context_alignment TEXT NOT NULL DEFAULT '{}', summary_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE (country, day_bucket) );
```
**根拠**: `radar/database.py:1447-1468`, `:1386-1393`, `:735-742`, `:746-757`, `:1013-1024`, `:1026-1041` ／ **検証**: tests/test_attention.py（18、p95 適応学習）、tests/test_threat_history_scoped.py（16、per-scenario スコープ） ／ **分類**: CORE

#### S3-DATA-014: シナリオ・設定・認証群（9 表）
**挙動**: 以下 9 表を移行 **MUST**。`scenarios` は geo_data.json プリセット（Layer 1）に対する state/enabled の override（Layer 2）であり、**プリセット本体は移行対象ではない**（静的資産）。

```sql
-- scenarios (5) — Layer 2 override。プリセットに対する state / enabled / tier の永続化
CREATE TABLE scenarios ( id TEXT PRIMARY KEY,
  name_en TEXT NOT NULL, name_ja TEXT NOT NULL,          -- *_en は ACCIDENTAL A2
  description_en TEXT, description_ja TEXT, core_country TEXT,
  state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','paused','archived')),
  enabled INTEGER NOT NULL DEFAULT 1, tier INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL, updated_at REAL NOT NULL, updated_by TEXT );
-- scenario_change_log (3) — シナリオ変更監査（retention 除外・恒久保持）
CREATE TABLE scenario_change_log ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  scenario_id TEXT NOT NULL, changed_at REAL NOT NULL, changed_by TEXT,
  change_type TEXT NOT NULL
      CHECK (change_type IN ('create','update','delete','archive','restore','purge','reset')),
  diff_json TEXT );
CREATE INDEX idx_scenario_change_log_sid ON scenario_change_log (scenario_id, changed_at DESC);
-- scenario_reserved_ids (1) — purge 済 ID の再利用防止（整合性資産）
CREATE TABLE scenario_reserved_ids ( id TEXT PRIMARY KEY, reserved_at REAL NOT NULL,
  reserved_by TEXT, reason TEXT );
-- config_runtime_value (50) — 3 層 config の DB override 現在値
CREATE TABLE config_runtime_value ( config_key TEXT PRIMARY KEY, value_json TEXT NOT NULL,
  set_at REAL NOT NULL, set_by TEXT NOT NULL );
-- config_change_log (23) — 設定変更監査（AP4）
CREATE TABLE config_change_log ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, domain TEXT NOT NULL, config_key TEXT NOT NULL,
  old_value TEXT, new_value TEXT, changed_by TEXT NOT NULL, reason TEXT, request_id TEXT );
CREATE INDEX idx_config_change_log_ts     ON config_change_log (ts DESC);
CREATE INDEX idx_config_change_log_domain ON config_change_log (domain, ts DESC);
CREATE INDEX idx_config_change_log_key    ON config_change_log (config_key, ts DESC);
-- llm_sources (20) — ソース credibility 学習（outcome 蓄積で成長する較正資産）
CREATE TABLE llm_sources ( source_id TEXT PRIMARY KEY, source_type TEXT NOT NULL,
  credibility_weight REAL NOT NULL DEFAULT 0.70, confirmed_count INTEGER NOT NULL DEFAULT 0,
  false_positive_count INTEGER NOT NULL DEFAULT 0, last_updated REAL NOT NULL );
-- llm_routing_override_history (4) — routing 変更監査
CREATE TABLE llm_routing_override_history ( id INTEGER PRIMARY KEY AUTOINCREMENT,
  use_case TEXT NOT NULL, slot TEXT NOT NULL, old_json TEXT, new_json TEXT,
  changed_at REAL NOT NULL, changed_by TEXT NOT NULL, reason TEXT );
CREATE INDEX idx_llm_routing_override_hist_ts ON llm_routing_override_history (changed_at DESC);
-- users (1) / user_settings (1) — 認証。移行必須（失うと全アクセス不能）
CREATE TABLE users ( id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'viewer',
  created_at REAL NOT NULL, last_login REAL,
  invalidate_tokens_before REAL );       -- この時刻より前に発行された JWT を無効化
CREATE TABLE user_settings ( user_id INTEGER PRIMARY KEY REFERENCES users(id),
  focused_scenario TEXT, muted TEXT NOT NULL DEFAULT '[]',
  lang TEXT NOT NULL DEFAULT 'en',       -- 日本語専用 UI 化により死んだカラム（ACCIDENTAL A3）
  updated_at REAL NOT NULL );
```
**挙動（追加）**: `password_hash` / `salt` はハッシュ形式ごと移行 **MUST**（再ハッシュ不可）。`user_settings.user_id` は `users(id)` FK のため移行順序は users → user_settings **MUST**。
**根拠**: `radar/database.py:1809-1856`, `:891-899`, `:871-888`, `:1073-1081`, `:854-869`, `:1109-1127`, `:1931` ／ **検証**: 未検証（認証系の移行テストは存在しない — S5 で新規追加すべき） ／ **分類**: CORE

---

### 2.3 移行 ETL 仕様

#### S3-DATA-020: 移行順序は参照整合の依存グラフに従う
**挙動**: ETL は以下の 5 ステージ順で実行 **MUST**。同一ステージ内は任意順。
1. **独立表 28 表**（FK 参照なし = §2.2 の 35 表から下記 7 表を除いた全て）。うち
   `threshold_history` は自己参照 FK のため単一トランザクション内で id 昇順に挿入 **MUST**
2. `user_settings`（→ users）
3. `conclusions`（大容量。ステージ 4 の前提）
4. `analyst_feedback`（→ conclusions）
5. `cooccurrence_matrix_snapshot` → `scenario_discovery_run` → `discovery_cluster`（3 段の直列 FK）

**挙動（追加）**: ETL 中は `PRAGMA foreign_keys = ON` **MUST**。FK 違反を検出した行はスキップせず ETL 全体を失敗させる **MUST**（部分移行は S3-DATA-025 の行数照合をすり抜ける）。
**根拠**: `radar/database.py:1216`（analyst_feedback→conclusions）、`:1321`, `:1337`（discovery 鎖）、`:1253`（threshold_history 自己参照）、`:1121`（user_settings→users）
**検証**: 未検証 ／ **分類**: CORE

#### S3-DATA-021: 大容量 2 表はチャンク分割コピーで移行する
**挙動**: `conclusions`（1,047,254 行）と `scenario_tl_observation`（114,160 行）は `observed_at` 昇順のチャンク（推奨 50,000 行）に分割してコピー **MUST**。両表とも observed_at 単調・ 追記型なので、チャンク境界に跨る更新は発生しない。残り 33 表は合計 9 万行未満のため単一トランザクションで移行してよい **MAY**。
**根拠**: D4 §4-6 ／ **検証**: 未検証 ／ **分類**: CORE

#### S3-DATA-022: theater→country の変換はカラム名の rename であり、値変換を伴わない
**挙動**: 現行 `theater` カラムの値は既に ISO2 country code であり、ETL は `INSERT INTO <t> (country, …) SELECT theater, … FROM old.<t>` の形で**値をそのまま移送 MUST**。v24 の `country` GENERATED VIRTUAL 列は**読まない MUST NOT**（値は theater と同一だが、GENERATED 列は `SELECT *` に現れないため列位置依存のコピーが破綻する）。
**挙動（追加）**: JSON ペイロード列（`alert_timeline.data_json`、`daily_summary.summary_json`、`conclusions.metadata`、`*_json` 全般）内に `"theater"` キーが残存していないことを ETL 後に検査 **MUST**（残存時は ETL を失敗させる）。
**根拠**: `radar/database.py:645-648`（GENERATED VIRTUAL）、`:634`（table_xinfo が必要な理由 = table_info では見えない） ／ **検証**: 未検証（現行の tests/test_a4_country_generated_column.py は dual-read の回帰であり、rename 後の検証ではない） ／ **分類**: CORE

#### S3-DATA-023: 移行 ETL はコンテナ内から実行する
**挙動**: 本番 DB への読み書きは**すべてコンテナ内プロセスから行う MUST**。ホスト側から `sqlite3 radar/persistence/radar.db` 等で直接操作してはならない **MUST NOT** （WAL の可視性不整合により DB が破損する）。読み取りは `sqlite3.connect("file:<path>?mode=ro", uri=True)` の read-only 接続を用いる **MUST**。
**挙動（追加）**: 本番 DB は docker named volume `noroshi_radar-data` にあり、リポジトリ作業ツリーの `radar/persistence/radar.db` は**古いコピーである**。ETL の入力にリポジトリ側のファイルを指定してはならない **MUST NOT**。
**根拠**: CLAUDE.md「運用上の落とし穴」2、`scripts/backup_radar_db.sh:3-8,36` ／ **検証**: 未検証 ／ **分類**: CORE

#### S3-DATA-024: 移行の直前にバックアップを取得する
**挙動**: ETL 開始前に SQLite online backup API による整合スナップショットを取得し、
**そのスナップショットを ETL の入力とする MUST**（稼働中 DB を直接読まない）。
スナップショットは cutover 完了まで保持 **MUST**。
**根拠**: `scripts/backup_radar_db.sh:29-43` ／ **検証**: 未検証 ／ **分類**: CORE

#### S3-DATA-025: 受け入れ条件① — 全 35 表の行数が一致する
**挙動**: ETL 後、移行 35 表それぞれについて `COUNT(*)` が移行元スナップショットと**完全一致 MUST**。不一致が 1 表でもあれば cutover を中止 **MUST**。
**分類**: CORE

#### S3-DATA-026: 受け入れ条件② — 決定論的サンプル照合が一致する
**挙動**: 各表について、主キー順で先頭 100 行・末尾 100 行・ランダム 100 行（固定 seed）を抽出し、全カラム値の SHA-256 が移行元と一致 **MUST**。`theater`→`country` の rename 対象カラムはカラム名を正規化してからハッシュする。
**分類**: CORE

#### S3-DATA-027: 受け入れ条件③ — recall / precision が移行前後で完全一致する
**挙動**: `analyst_feedback` × `conclusions` から算出する混同行列（TP / FP / TN / FN）と、そこから導く `recall = TP / (TP + FN)`、`precision = TP / (TP + FP)` が、
**移行前スナップショットと移行後 v3 DB で（scenario_id, conclusion_type）セルごとに完全一致 MUST**。
浮動小数の許容差は 0（同一整数カウントからの同一演算であるため）。
一致しない場合、移行 ETL が結論とラベルの対応を壊している。**cutover を中止 MUST**。
**挙動（追加）**: 比較は human-only（`analyst_id` が `auto:` で始まる行を除外）と全件の
**両系列で実施 MUST**。過去 3 回の較正事故はいずれもラベル生成側の欠陥だったため、
recall 異常を検出したらツールではなくラベル対応関係をまず疑う。
**根拠**: `scripts/report_recall_metrics.py:10,100-117`、`scripts/check_recall_baseline.py:82-196` ／ **検証**: 未検証（現行 `check_recall_baseline.py` は時系列 drift ゲートであり、移行前後の同一性検証ではない。S5 で ETL 検証モードの追加が必要） ／ **分類**: CORE（**R1 の中核受け入れ条件**）

#### S3-DATA-028: 受け入れ条件④ — 較正窓の連続性が保たれる
**挙動**: 移行後の v3 DB において以下が成立 **MUST**:
- `scenario_tl_observation` の最古 `observed_at` が「cutover 時刻 − TL 較正窓（42 日）」以前であること
  （= 較正窓を満たすだけの履歴が移行されている）
- `inconclusive_continuity_log` の各 (scenario_id, conclusion_type) について、cutover を跨いで
  `run_length_sec` が単調増加を継続すること（リセットされないこと）
- `conclusions` の最古 `observed_at` が「cutover 時刻 − conclusions retention」以前であること
**分類**: CORE

#### S3-DATA-029: 受け入れ条件⑤ — NP6 遡及経路が 100% 解決する
**挙動**: 移行後、`llm_prompt_sha256 IS NOT NULL` である全 `conclusions` 行について、対応する `llm_prompts.prompt_sha256` が存在 **MUST**（解決率 100%）。同様に `analyst_feedback.conclusion_id` の全値が `conclusions.id` に解決 **MUST**。解決率が 100% 未満の場合、移行順序（S3-DATA-020）または retention 差（S3-DATA-042）の違反。
**分類**: CORE

#### S3-DATA-030: ETL は冪等であり、再実行が安全である
**挙動**: ETL は移行先を空にしてから再実行できる **MUST**。部分的な再開ではなく「全消し → 全コピー」を規範とする（総容量 1.25M 行はこの単純さに見合う）。移行元スナップショットは読み取り専用で開くため、ETL 実行が本番に影響を与えない **MUST**。
**分類**: CORE

#### S3-DATA-031: cutover は移行元を書き込み停止してから確定する
**挙動**: 最終 ETL の実行中、移行元（v2 系）は**書き込みを停止 MUST**（スコアリングループ停止）。稼働中コピーは受け入れ条件①（行数一致）を原理的に満たせない。停止時間の見積りは 1.25M 行のチャンクコピー ≒ 数分。
**分類**: CORE

---

### 2.4 再生成可 31 表 + convergence snapshots

#### S3-DATA-050: 再生成可表はスキーマのみ移行し、データは空から出発する
**挙動**: D4 §2b の 31 表（`scenario_contribution_log` / `time_series` / `time_series_ts` / `llm_call_log` / `sensor_observation_ts` / `sensor_fetch_log` / `bg_observer_cycle_log` / `threat_history` / `llm_intel` / `climate_events` / `llm_embed_call_log` / `sensor_caches` / `scenario_sensor_coverage` / `baseline_cache` / `airspace_baseline` / `attention_metric_p95` / `hidden_signal_log` / `llm_embed_dedup_log` / `sensor_zscore_stats` / `decisions` / `attention_snooze` / `auto_apply_cooldown` / `llm_feature_state` / `llm_feature_state_history` / `llm_routing_override` / `llm_shadow_invocation` / `noise_exclusion` / `revoked_tokens` / `user_attention_thresholds` / `scenario_participants` / `focus_switch_log`）は
**データ移行を行わない MUST NOT**。ただし `focus_switch_log` は S3-DATA-061 により
スキーマごと破棄する（したがって v3 に持ち込むのは 30 表）。
うち `baseline_cache` / `time_series_ts` / `time_series` / `sensor_zscore_stats` /
`noise_exclusion` / `climate_events` / `llm_intel` は S3-DATA-002 の rename 対象 **MUST**。

**再構築のデータ源と所要時間**:

| 表 | データ源 | 判定有効まで | 全深度 |
|---|---|---|---|
| baseline_cache | Cloudflare Radar API refetch（BASELINE_DATE_RANGE=28d） | 即日 | 即日 |
| airspace_baseline | ライブ観測（AIRSPACE_WINDOW=20 readings/空港） | ≤1 日 | ≤1 日 |
| sensor_observation_ts | ライブ観測（TTL 24h ローリング） | 即時 | 1 日 |
| sensor_zscore_stats | ライブ観測（ADAPTIVE_ZSCORE_MIN_SAMPLES=50/センサー/国） | 数時間 | 数日 |
| sensor_caches / scenario_sensor_coverage | 次の fetch / scoring tick | 即時 | 即時 |
| llm_intel | ライブ intel（7d retention） | 即時 | 7 日 |
| climate_events | ライブ（48h retention） | 即時 | 2 日 |
| time_series / time_series_ts / threat_history | scoring tick の副産物（ring buffer） | 即時 | 28 日 |
| scenario_contribution_log | scoring tick（~11.5k 行/日/4-participant） | 即時 | 30 日（advisory 参照窓） |
| llm_call_log / bg_observer_cycle_log / sensor_fetch_log / hidden_signal_log / llm_embed_* | 運用ログ（設計上 7〜30d で消える） | 即時 | retention 期間 |
| attention_metric_p95 | attention_metric_observation（**移行表**）からの導出 | 即時 | 即時 |
| decisions / attention_snooze / auto_apply_cooldown / llm_feature_state* / llm_routing_override / llm_shadow_invocation / noise_exclusion / revoked_tokens / user_attention_thresholds / scenario_participants | 現在 0 行。v3 で新規運用 | — | — |

**根拠**: D4 §2b, §3 Q4-Q6 ／ **検証**: tests/test_contribution_log_retention.py（3）、tests/test_llm_log_retention.py（4） ／ **分類**: CORE

#### S3-DATA-051: 再構築中の感度低下を結論に開示する
**挙動**: ベースライン蓄積が閾値サンプル数に達していないセンサー・国について、その旨を結論の `calibration_status` に反映し UI に開示 **MUST**（NP5+8 / AP3）。「ベースライン不足で warmup フォールバック中」を沈黙させてはならない **MUST NOT**。これは S3-DATA-001 で移行必須とした 3 表を万一失った場合の唯一の緩和策でもある。
**根拠**: NP5+8、D4 §3 Q6 の結論 ／ **検証**: tests/test_inconclusive_continuity.py（17） ／ **分類**: CORE

#### S3-DATA-052: 収斂スナップショットは main DB の表として再定義する
**挙動**: `convergence_snapshots.db::snapshots` は main DB の表 `convergence_snapshots` として定義 **MUST**。**データ移行は不要**（72h ローリングであり、判定は 6 時間で復帰、72 時間で全深度回復）。

```sql
CREATE TABLE convergence_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  country TEXT NOT NULL,               -- 旧 theater（S3-DATA-002）
  ts REAL NOT NULL,
  elevated_sensors TEXT NOT NULL       -- JSON list of sensor names
);
CREATE INDEX idx_convergence_snapshots_country_ts ON convergence_snapshots (country, ts);
```
**閾値**: 保持 72h（`CONVERGENCE_SNAPSHOT_RETENTION_H`, default 72）、判定窓 6h（`CONVERGENCE_MIN_HOURS`, default 6）
**根拠**: `radar/sensors/convergence_tracker.py:47,54-99`、D2 A-09 ／ **検証**: 未検証 ／ **分類**: CORE

---

### 2.5 破棄 13 表

#### S3-DATA-060: tradecraft 系 9 表を破棄する
**挙動**: `ach_matrices` / `ach_hypotheses` / `ach_evidence` / `ach_scores` / `disconfirming_evidence` / `key_assumptions` / `key_assumption_change_log` / `dissenting_views` / `premortem_entries` / `decision_ledger` を v3 に持ち込まない **MUST NOT**。データの export 保全も**不要**。
**根拠**: 全表の行数が 82 の倍数（164=82×2、246=82×3、328=82×4、984=82×12）で
**82 回のテスト実行と完全一致**する。`tests/test_analyst_permissions.py` が本物のシングルトン DB へ
実 POST を行っていたことが直接原因（D4 §3 Q1、D2 B-08）。実アナリスト入力はゼロ。
tradecraft 統合は 2026-04-30 に棚上げ済で、復活時は v3 上での再実装が空機能の移送より安い（D3 §3-1）。
**オーナー判断**: D3 §3-1 の (a)「v3 に持ち込まない」が推奨。**本条項は当該裁定の成立を前提とする**。
**分類**: CORE（オーナー裁定 1 件に条件付き）

#### S3-DATA-061: 移行足場・遺構 4 表を破棄する
**挙動**: 以下を v3 に持ち込まない **MUST NOT**:
- `shadow_sampler_state`（3 行）— CREATE TABLE のみで参照コードなし。dead schema 確定
- `schema_version`（1 行）— v3 は新しいスキーマ管理で出発（S3-DATA-072）
- `sqlite_sequence`（41 行）— SQLite 内部表。移行対象の概念に含まれない
- `focus_switch_log`（3,326 行）— writer は 2026-05-30 に撤去済。評価エンドポイントも撤去済で実質 dead
**分類**: CORE

---

### 2.6 retention 方針

#### S3-DATA-040: retention は宣言的レジストリで一元管理する
**挙動**: 全表の retention（対象カラム・日数・env キー・除外指定）は**単一の宣言的レジストリ**に定義 **MUST**。prune 実行はレジストリを走査する汎用処理とし、表ごとの手書き DELETE を持ってはならない **MUST NOT**。現行は 20 個の DELETE 文がメソッド内に直列に並び、「ハードコード 7d DELETE が config を dead code にしていた」事故（2026-07-04 修正）を生んだ。
**根拠**: `radar/database.py:5311-5510`、`:5353-5355`（当該事故のコメント） ／ **検証**: tests/test_llm_log_retention.py（4、dead-code 修正の回帰） ／ **分類**: DEFECT-PRESERVE（現行は手書き列挙。v3 は宣言的レジストリ **MUST**）

#### S3-DATA-041: conclusions の retention を移行時に 365 日へ延長する
**挙動**: `CONCLUSIONS_RETENTION_DAYS` の既定値を **90 → 365** に変更し、移行 ETL と同時に適用 **MUST**。移行時に決めれば ETL は 1 回で済み、後日変更した場合に必要となる「切り詰められた履歴の再 backfill」（`scripts/backfill_v2_ledger.py` の再実行）を回避できる。
**容量見積り**: 現行 1,047,254 行 / 90d ≒ 11,636 行/日 → 365d で **約 4,247,000 行**（現行比 4.06 倍）。
`scenario_contribution_log` も同様に 90d → 365d とすると 1,051,800 → 約 4,265,000 行。
両表合計で約 850 万行。現行 DB 実サイズ約 1.9 GB に対し、**移行後の定常サイズは 6〜8 GB 規模**と
見積もる。日次バックアップ（gzip、14 世代保持）の保存容量もこれに追随する。
**閾値**: `CONCLUSIONS_RETENTION_DAYS` = 365（現行 default 90）、`SCENARIO_CONTRIB_RETENTION_DAYS` = 365（現行 default 90）
**根拠**: `radar/database.py:5443`, `:5411`、D3 §3-3（オーナー推奨: 移行時に 365d 化） ／ **検証**: 未検証 ／ **分類**: CORE（オーナー裁定 D3 §3-3 の実装）

#### S3-DATA-042: llm_prompts の retention は conclusions retention + 30 日を下回らない
**挙動**: `LLM_PROMPTS_RETENTION_DAYS` の実効値は `max(設定値, CONCLUSIONS_RETENTION_DAYS + 30)` **MUST**。この床は運用者がどれだけ低い値を設定しても保たれる **MUST**。S3-DATA-041 で conclusions を 365d にすると、llm_prompts の実効床は自動的に **395 日**に伸びる。
**理由**: 生存中の conclusion は常に `llm_prompt_sha256` を解決できなければならない（NP6）。
**閾値**: `LLM_PROMPTS_RETENTION_DAYS` default 120、床 = `CONCLUSIONS_RETENTION_DAYS + 30`
**根拠**: `radar/database.py:5457-5458` ／ **検証**: 未検証（床のロジックに専用テストがない） ／ **分類**: CORE

#### S3-DATA-043: retention 除外表を明示的に宣言する
**挙動**: `confirmed_threats`（人手 ground truth、~3 KB/年）と `scenario_change_log` （監査証跡、~4 MB/10 年）は自動 prune の対象外 **MUST**。除外は暗黙の「DELETE 文を書き忘れた」状態ではなく、レジストリ上の明示宣言でなければならない **MUST**。
**根拠**: `radar/database.py:5430-5433` ／ **分類**: CORE

#### S3-DATA-044: retention 未設定の表を残してはならない
**挙動**: v3 の全表は「retention 日数」か「上限行数（ring）」か「明示的な無期限宣言」のいずれかを持つ **MUST**。現行は移行 35 表のうち **17 表が無制限**（`auto_judge_decisions`, `attention_metric_observation`, `threshold_history`, `scenario_proposals`, `scenario_drift_events`, `cooccurrence_matrix_snapshot`, `scenario_discovery_run`, `discovery_cluster`, `cooccurrence_stats`, `ct_log_known_ca_per_domain`, `ct_log_domain_first_observed`, `llm_sources`, `config_runtime_value`, `config_change_log`, `llm_routing_override_history`, `auto_apply_tier_state`, `auto_apply_tier_marker`）で、成長速度が小さいために顕在化していないだけである。`llm_prompts` が「唯一の真に無制限な表」だったことが 2026-07-03 の監査で判明した前例がある。
**根拠**: `radar/database.py:5311-5510` に当該 17 表の DELETE が存在しないこと ／ **分類**: DEFECT-PRESERVE（現行は無制限。v3 は宣言必須 **MUST**）

#### S3-DATA-045: prune の実行契機は起動時と日次の 2 経路
**挙動**: retention prune は (a) 起動時、(b) 日次スケジュールの 2 経路で実行 **MUST**。日次ジョブは**永続的な次回実行時刻を DB に保持 MUST**（プロセス内カウンタ駆動にしない）。現行の保守ワーカはプロセス内 `_cycle` カウンタ駆動で、再起動が頻繁だと高オフセットのジョブが一度も走らない（D2 F-01）。prune がこれに該当すると容量が無言で膨張する。
**根拠**: `radar/__init__.py:281`（startup_cleanup）、`radar/scheduler.py:714`（periodic_cleanup）、D2 F-01 ／ **分類**: DEFECT-PRESERVE

---

### 2.7 テスト隔離（D2 B-08 の恒久対策）

#### S3-DATA-070: データ層は接続注入を前提とする
**挙動**: v3 のデータアクセス層は、**DB 接続（またはパス）をコンストラクタで受け取る MUST**。モジュールレベルのシングルトンを import しただけで本番 DB に到達できる構造を持ってはならない **MUST NOT**。
**根拠**: D2 B-08（tradecraft 全表がテスト残骸で汚染された直接原因）、D4 §4-3 ／ **検証**: tests/test_auto_apply_tier_governor.py（`tier_governor_repo` / `tier_governor_conn` fixture が既存の良い先例） ／ **分類**: CORE

#### S3-DATA-071: テストからの本番 DB アクセスは構造的に失敗する
**挙動**: テストスイートは、注入された隔離 DB 以外への接続試行を**即座に例外で失敗させる MUST**。現行の `_block_live_db_access` autouse fixture（`radar.database.db._get_conn` を raise へ差し替え）がこの契約の既知の実装であり、**v3 では全テストに適用 MUST**（現行では 1 ファイルのみ）。
**根拠**: `tests/test_auto_apply_tier_governor.py:26-52`、D2 §E 補足「良い先例」 ／ **検証**: 同上 ／ **分類**: CORE

#### S3-DATA-072: スキーマ定義は単一の宣言から隔離 DB を構築できる
**挙動**: v3 のスキーマは、テストが**任意の空 DB に対して本番と同一のスキーマを構築できる単一の宣言 MUST**。現行は `_SCHEMA_SQL`（新規 DB 用ベースライン）と 50 本超の `_migration_v*`（既存 DB 用）の二重定義になっており、テストが検証しているスキーマが本番のスキーマと一致する保証がない。
**挙動（追加）**: v3 は既存 DB を持たない状態から出発するため、**移行足場としての `_migration_v*` 系列を引き継がない MUST NOT**。v3 の migration 番号は 1 から再出発する。
**根拠**: `radar/database.py:653`（_SCHEMA_SQL）、`:48-620`（migration 群）、D5「database.py は専用テスト無し」 ／ **検証**: 未検証（`radar/database.py` 6,629 行に専用テストが存在しない） ／ **分類**: DEFECT-PRESERVE

---

### 2.8 バックアップ・復旧

#### S3-DATA-080: 日次オンラインバックアップを v3 でも継続する
**挙動**: 本番 DB の整合スナップショットを**日次で取得 MUST**。取得は SQLite online backup API （read-only ソース接続、WAL 安全）で行い、ファイルコピーや `.dump` に置き換えてはならない
**MUST NOT**。世代保持は 14 世代 **SHOULD**。
**根拠**: `scripts/backup_radar_db.sh:29-55` ／ **検証**: 未検証 ／ **分類**: CORE

#### S3-DATA-081: バックアップの失敗は可視化される
**挙動**: バックアップジョブの失敗は**通知経路に到達 MUST**。実行環境の PATH やコンテナ名などの外部依存を暗黙に前提としてはならない **MUST NOT**。
**事故記録**: 2026-07-04〜08-03 の約 1 か月間、cron の最小 PATH に docker CLI が含まれず毎回 `docker: command not found` で失敗していたが、ログにしか記録されないため
**無言で停止していた**（現在は PATH を明示して修正済）。
**根拠**: `scripts/backup_radar_db.sh:14-18` ／ **検証**: 未検証 ／ **分類**: DEFECT-PRESERVE（現行は sink がログのみ。v3 は失敗の可視化 **MUST**）

#### S3-DATA-082: 復旧手順は定期的に実演する
**挙動**: 最新バックアップから隔離環境へ復元し、S3-DATA-025〜029 の受け入れ条件のうち ①（行数）と③（recall 一致）を実行する drill を **SHOULD**（頻度は運用判断）。移行 ETL の検証器をそのまま復旧 drill に流用できる設計とする **SHOULD**。
**分類**: CORE

---

## 3. retention カタログ

| 表 | 対象カラム | 現行既定 | v3 規範 | env キー | 分類 |
|---|---|---:|---:|---|---|
| conclusions | observed_at | 90d | **365d** | `CONCLUSIONS_RETENTION_DAYS` | 移行 |
| llm_prompts | last_seen_at | 120d（床 = conc+30） | **395d**（床連動） | `LLM_PROMPTS_RETENTION_DAYS` | 移行 |
| analyst_feedback | observed_at | 180d | 180d | `ANALYST_FEEDBACK_RETENTION_DAYS` | 移行 |
| scenario_tl_observation | observed_at | 42d | 42d | `TL_OBSERVATION_RETENTION_DAYS` | 移行 |
| inconclusive_continuity_log | observed_at | 60d | 60d | `INCONCLUSIVE_LOG_RETENTION_DAYS` | 移行 |
| sequence_events | ts | 30d（ハードコード）+ 国別 ring | 30d（宣言化 **MUST**） | 未設定 → 新設 **MUST** | 移行 |
| daily_summary | day_bucket | 730d | 730d | `DAILY_SUMMARY_RETENTION_DAYS` | 移行 |
| alert_timeline | — | ring 288 件 | ring 288 件 | — | 移行 |
| hod_baseline / checkhost_hod / bgp_hod | hour_bucket | バケット数上限 trim | 同左 | `HOD_BASELINE_DAYS`（28） | 移行 |
| gdelt_dow | day_bucket | バケット数上限 trim（140） | 同左 | — | 移行 |
| confirmed_threats | — | **除外（恒久）** | 除外（明示宣言 **MUST**） | — | 移行 |
| scenario_change_log | — | **除外（恒久）** | 除外（明示宣言 **MUST**） | — | 移行 |
| 上記以外の移行 17 表 | — | **無制限** | 宣言必須（S3-DATA-044） | 新設 **MUST** | 移行 |
| scenario_contribution_log | logged_at | 90d | **365d** | `SCENARIO_CONTRIB_RETENTION_DAYS` | 再生成可 |
| llm_call_log | ts | 30d | 30d | `LLM_CALL_LOG_RETENTION_DAYS` | 再生成可 |
| bg_observer_cycle_log | started_at | 30d | 30d | `BG_OBSERVER_CYCLE_LOG_RETENTION_DAYS` | 再生成可 |
| llm_intel | created_at | 7d | 7d | `INTEL_RETENTION_DAYS` | 再生成可 |
| sensor_fetch_log | ts | 7d | 7d | — | 再生成可 |
| climate_events | ts | 48h | 48h | — | 再生成可 |
| sensor_observation_ts | ts | 24h | 24h | — | 再生成可 |
| revoked_tokens | revoked_at | max(refresh TTL + 1h, 24h) | 同左 | `JWT_REFRESH_EXPIRES` | 再生成可 |
| decisions（superseded 行のみ） | decided_at | 90d | 90d | `DECISIONS_SUPERSEDED_RETENTION_DAYS` | 再生成可 |
| convergence_snapshots | ts | 72h | 72h | `CONVERGENCE_SNAPSHOT_RETENTION_H` | 新設（統合） |

**出典**: `radar/database.py:5311-5510`、`radar/sensors/convergence_tracker.py:47`

---

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | 移行 35 表のうち **17 表に retention が無い**（S3-DATA-044）。成長が遅いため顕在化していないだけ | v3 で一律に日数を設定するか、「監査台帳は恒久」として明示除外するか。`threshold_history` / `scenario_drift_events` は NP6 lineage なので恒久が妥当に見えるが、`attention_metric_observation`（7,517 行、学習観測）は窓で足りるはず |
| A2 | `scenarios` テーブルが `name_en` / `description_en` を持つ（日本語専用 UI 化後も残存） | 日本語専用 UI（2026-08-02）により EN 列は表示経路を失った。v3 で削るか、将来の多言語化に備えて残すか。**CLAUDE.md は多言語切替機構を持たないと宣言している**ため、削る方が整合する |
| A3 | `user_settings.lang TEXT NOT NULL DEFAULT 'en'` が日本語専用 UI 化により死んだカラム | 同上。移行時に削除すべきか |
| A4 | `daily_summary` / `cooccurrence_stats` の `country` が空文字 `''` を既定値に持つ（グローバル行を表す） | 「国に紐づかない観測」をセンチネル値 `''` で表すのは NP6 の可読性を損なう。v3 で NULL か専用値 `GLOBAL` にすべきか |
| A5 | `conclusions.id` が TEXT PRIMARY KEY（決定論的 ID）だが、その生成規則がスキーマからは読めない | 移行 ETL は ID をそのまま移送するため実害はないが、v3 で ID 規則を仕様化すべきか（S1-conclusions の担当範囲かもしれない） |
| A6 | `scenario_participants`（0 行）を v3 に持ち込むか — Layer 2 が事実上未使用で、`geo_data.json` プリセットが実源 | D4 §4-4 の論点。(a) 別テーブル維持、(b) `scenarios` 内 JSON に畳む、(c) DB 一本化。**JOIN 1 回分のコストに見合う利用実績が無い**ため (b) が有力 |
| A7 | `alert_timeline` の ring 288 件は「5 分間隔 × 24 時間」の暗黙前提 | tick 間隔が変われば保持時間が変わる。時間ベースの retention に変えるべきか |

---

## 5. テストトレーサビリティ

D5 台帳のうち、データ層（スキーマ・retention・migration）に関わるものの対応。

| テスト（D5 分類） | 対応条項 |
|---|---|
| test_conclusions_persistence.py（14, STRUCTURAL） | S3-DATA-004, S3-DATA-010 |
| test_llm_prompt_persistence.py（12, BEHAVIOR） | S3-DATA-010, S3-DATA-042 |
| test_threat_level_derive.py（15, BEHAVIOR） | S3-DATA-010（tl=None の意味論） |
| test_inconclusive_continuity.py（17, BEHAVIOR） | S3-DATA-010, S3-DATA-028, S3-DATA-051 |
| test_ct_log_redesign.py（21, BEHAVIOR） | S3-DATA-011 |
| test_attention.py（18, BEHAVIOR） | S3-DATA-013 |
| test_lineage.py（9, STRUCTURAL） | S3-DATA-012 |
| test_scenario_discoverer.py（11, STRUCTURAL） | S3-DATA-012, S3-DATA-020 |
| test_scenario_apply.py（13, STRUCTURAL） | S3-DATA-012, S3-DATA-014 |
| test_proposal_writer.py（14, STRUCTURAL） | S3-DATA-012 |
| test_threat_history_scoped.py（16, STRUCTURAL） | S3-DATA-050（threat_history は再生成可） |
| test_contribution_log_retention.py（3, STRUCTURAL） | S3-DATA-040, S3-DATA-041 |
| test_llm_log_retention.py（4, SCAFFOLD） | S3-DATA-040（dead-code 事故の回帰。値のみ §3 に転記） |
| test_a4_country_generated_column.py（7, SCAFFOLD） | S3-DATA-002, S3-DATA-022（v3 では破棄。rename 後の新テストが必要） |
| test_auto_apply_tier_governor.py（fixture 部, STRUCTURAL） | S3-DATA-070, S3-DATA-071 |
| test_decisions.py（32, CONTRACT） | S3-DATA-050（decisions は 0 行、スキーマのみ継承） |
| test_intel_multicountry.py（12, BEHAVIOR、theater 互換部は SCAFFOLD） | S3-DATA-002 |
| test_analyst_permissions.py（tradecraft 系） | S3-DATA-060, S3-DATA-071（**このテストが破棄根拠そのもの**） |

### GAP（仕様化したが検証が無い）

| ID | 内容 |
|---|---|
| GAP-01 | **移行 ETL そのものが未実装**のため、S3-DATA-020〜031 の全条項に検証が存在しない。S5 で ETL 検証器（行数照合 / サンプルハッシュ / recall 再計算）をテスト資産として新規に設計する必要がある |
| GAP-02 | `radar/database.py` 6,629 行に**専用テストが 1 件も無い**（D5 §3）。migration v6/v11/v24/v33/v34/v41-42/v52-53 は機能テストで部分カバーされるのみ。スキーマ管理の正しさは現状ほぼ無検証 |
| GAP-03 | `LLM_PROMPTS_RETENTION_DAYS` の床ロジック（`max(設定値, conc+30)`）に専用テストが無い。S3-DATA-042 は NP6 遡及の生命線だが、運用者が低い値を設定した際の床が効くことを誰も検証していない |
| GAP-04 | 認証系（`users` / `user_settings`）の移行に関するテストが無い。password_hash / salt の移送失敗は cutover 後に全アクセス不能を招く最悪ケースだが、S3-DATA-014 の検証は空欄 |
| GAP-05 | バックアップスクリプトに回帰テストが無い（S3-DATA-080/081）。1 か月の無言停止事故は「テストがあれば防げた」類ではないが、**失敗の可視化**（S3-DATA-081）は検証可能な性質である |

---

## 6. 未決事項

1. **S3-DATA-041（conclusions 365d 化）はオーナー裁定 D3 §3-3 の成立が前提**。裁定が
   「移行時ではなく後日」となった場合、本条項と S3-DATA-042 の床値（395d）を差し戻す必要がある。
   容量見積り（定常 6〜8 GB、現行比 4 倍強）が受容可能かの判断も同時に要る
2. **S3-DATA-060（tradecraft 破棄）はオーナー裁定 D3 §3-1 の成立が前提**。(b)「凍結のまま移植」に
   なった場合、9 表のスキーマを v3 に持ち込む条項へ差し替える（データは依然として移行不要 —
   全量テスト残骸であることは裁定によらず事実）
3. **ACCIDENTAL A6（scenario_participants の処遇）は S3 単独では決められない**。
   「geo_data.json プリセット + DB override」の 2 層構造を維持するかは Phase P の
   シナリオ永続化設計に属する。本書は現行スキーマの記録に留め、v3 規範形を示していない
4. **cutover 時の停止時間**が未検証。1.25M 行のチャンクコピーが数分で終わる想定は実測されていない。
   S3-DATA-031 の「書き込み停止」窓が実際にどれだけ必要かは、移行リハーサルで測る必要がある
5. **移行元スナップショットと v3 DB の間で `sqlite_sequence` をどう扱うか**が未定義。
   AUTOINCREMENT の連番を移行先で継続させるか 1 から振り直すかで、
   `threshold_history.revertible_to_id` のような自己参照 FK の移送方式が変わる。
   S3-DATA-020 は「id 順に単一トランザクションで挿入」としたが、これは
   **元の id を保存する**前提である。連番振り直しを選ぶ場合は ID マッピング表が要る
6. **JSON ペイロード内の `theater` キー残存**（S3-DATA-022）の実態が未調査。
   コード側の書き込み経路を grep した限りでは静的プリセット由来の 1 系統のみだが、
   過去に書き込まれた古い行に残っている可能性は排除できていない。ETL 前に実データ検査が要る
