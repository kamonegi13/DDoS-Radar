# D1 インベントリ — バックエンドコア（センサー層除く）

Phase D 診断ドラフト（2026-08-03）。対象: `radar_api.py` + `radar/*.py` + `radar/routes/` + `radar/conclusions/` + `radar/calibration/` + `radar/analytics/` + `radar/observability/`（`radar/sensors/` は別担当、依存エッジのみ記録）。
**規模**: 100 ファイル / 約 47,500 行（トップレベル 34、routes 22、conclusions 21、calibration 18、analytics 3、observability 2）。

## 1. インベントリ表

フラグ: `god` = god-module、`LV` = layer-violation、`dorm` = dormant-scaffolding、`dual` = dual-write / 旧用語残滓、`circ` = circular-import-workaround、`junk` = 不要ファイル

### エントリポイント / アプリコア

| ファイル | 行数 | 責務 | 主要 radar.* import | フラグ |
|---|---|---|---|---|
| `radar_api.py` | 77 | エントリポイント。gevent monkey-patch + re-export 束 | radar(app), engine, scoring, database, sensors.* ×4 | re-export専用 |
| `radar/__init__.py` | 355 | app factory。Flask/CORS/Limiter/JWT/socketio 初期化、センサー登録、blueprint 登録 | config, engine, sensors, scoring, scenarios, database, auth, ws, scheduler, persistence, plugin_loader | hub |
| `radar/config.py` | 1,612 | env 読込 + 全閾値定数 + declarative config registry | config_layered(遅延) | god気味 |
| `radar/config_layered.py` | 457 | 3層 config 解決（DB override → env → default） | database(遅延) | |
| `radar/state.py` | 62 | in-memory transient cache（global_cache, _active_focus） | なし | mutable-global |
| `radar/models.py` | 125 | dataclass（RationaleEntry 等） | なし | |
| `radar/database.py` | 6,629 | SQLite 永続層。RadarDB 1クラス約170メソッド + migration 13関数 + 全スキーマ | config, config_layered/decisions(遅延) | **god, dual** |
| `radar/persistence.py` | 139 | センサーキャッシュ定期保存 + 起動時 restore | config, database, migration(遅延) | |
| `radar/migration.py` | 126 | 一回きり JSON→SQLite 移行 | database(遅延) | **dorm** |
| `radar/auth.py` | 702 | JWT 認証 + user 管理（blueprint `/api/auth`、11 endpoint） | database(遅延), conclusions.shadow_metrics(遅延) | routes層が別置 |
| `radar/audit_middleware.py` | 151 | legacy endpoint の mutation 監査 decorator | database(遅延) | 過渡期 |
| `radar/ws.py` | 154 | SocketIO handler + emit 関数 6 種 | database/notifications(遅延) | **dual**(theater語彙) |
| `radar/scheduler.py` | 823 | バックグラウンドループ（fetch/cleanup/calibration cron 起動） | config, database, scoring, state, sensors.base, calibration.*(遅延多数) | hub |
| `radar/plugin_loader.py` | 130 | plugins/ 動的ロード | sensors.base(遅延) | |
| `radar/diagnostics.py` | 144 | 週次 observability runner（CLI 診断のラッパ） | — | |

### スコアリング / エンジン / シナリオ

| ファイル | 行数 | 責務 | 主要 radar.* import | フラグ |
|---|---|---|---|---|
| `radar/engine.py` | 1,008 | SensorRegistry + WeightedConvergenceEngine（収斂・速度・ambush 検知） | config, models, sensors.base | scoring.py と重複あり |
| `radar/scoring.py` | 1,735 | sequence scorer, HOD Z-score, CF helper, scenario score, conclusions shadow-write | config, database, models, state, conclusions.*(遅延) | god気味 |
| `radar/scenarios.py` | 623 | scenario store（participants/weights/state 管理） | database/config(遅延) | **dual**(core_theater 互換keys L600-604) |
| `radar/climate.py` | 1,026 | Strategic Climate Engine（間接指標） | config/database(遅延) | |
| `radar/climate_state.py` | 8 | climate engine singleton（循環 import 回避） | climate | **circ** |

### インテル / LLM

| ファイル | 行数 | 責務 | 主要 radar.* import | フラグ |
|---|---|---|---|---|
| `radar/intel_queue.py` | 1,211 | LLM インテルキュー（submit/dedup/decay/score 寄与） | config, database, ws/llm_embedding/llm_features(遅延) | **dual**(theater キー多数) |
| `radar/intel_auto_judge.py` | 646 | pending インテルの自動判定スイープ | database, intel_queue, llm_client(遅延) | |
| `radar/intel_corroboration.py` | 345 | 独立ソース間の LLM 照合合成 | config, database, intel_queue/llm_client(遅延) | |
| `radar/llm_client.py` | 697 | Ollama クライアント（JSON 解析・ログ・ルーティング接続） | config, database/llm_features/llm_prompts/llm_routing(遅延) | |
| `radar/llm_routing.py` | 921 | use-case 別 5 モデルルーティング + SHADOW_DUAL 状態機械 | database/config/llm_features(遅延) | SHADOW_DUAL は live |
| `radar/llm_features.py` | 578 | LLM Feature Hub（機能別 on/shadow/off 制御） | database(遅延) | |
| `radar/llm_embedding.py` | 372 | embedding クライアント（dedupe/クラスタ用） | config, config_layered(遅延) | |
| `radar/llm_prompts.py` | 123 | プロンプト sha256 永続化（NP6） | database(遅延) | |
| `radar/llm_client.py.bak` | — | 旧版バックアップがリポジトリに残存 | — | **junk** |

### AP1-AP4 / 分析系

| ファイル | 行数 | 責務 | 主要 radar.* import | フラグ |
|---|---|---|---|---|
| `radar/attention.py` | 508 | ATTENTION rules engine（AP1 triage 提案） | routes(遅延・registry参照), database, intel_queue(遅延) | **LV** |
| `radar/attention_learning.py` | 147 | attention 閾値の p95 適応学習 | attention, database(遅延) | |
| `radar/triage.py` | 216 | triage 優先度式の pure functions | なし | pure・良好 |
| `radar/decisions.py` | 415 | Decision Layer 統一台帳（AP4） | database 経由 | |
| `radar/notifications.py` | 534 | webhook 通知（Slack/Teams/Discord） | ws(遅延) | |
| `radar/background_observer.py` | 454 | per-scenario 観測健全性（AP3 OBS chip） | radar, conclusions.rss_extractor, database(遅延) | |
| `radar/analytics/cooccurrence.py` | 251 | 国ペア共起行列 | database 経由 | |
| `radar/analytics/dbscan_cluster.py` | 198 | pure-Python DBSCAN | — | pure・良好 |
| `radar/observability/followup_watch.py` | 362 | 保留 backlog のトリガー条件監視 | database, conclusions.*(遅延) | |

### conclusions パッケージ（v2 結論台帳）

| ファイル | 行数 | 責務 | フラグ |
|---|---|---|---|
| `base.py` | 136 | Conclusion dataclass + ConclusionType/UnavailableReason | |
| `api.py` | 99 | v2 envelope 構築（NP7 disclaimer 強制） | 良設計 |
| `persistence.py` | 361 | conclusions ledger 保存/読出（gated write） | |
| `threat_level.py` / `trend.py` / `per_domain.py` / `anomaly.py` | 192/234/173/246 | 各結論タイプの導出（TL/トレンド/ドメイン別/異常） | threat_level に C-lite 分岐 |
| `attack_mode.py` + `_extensions.py` + `_llm.py` | 184/227/215 | 攻撃シナリオ推定 + 拡張 + LLM 補強 | |
| `calibration.py` / `sensitivity.py` / `severity.py` | 207/313/43 | calibration_status 付記 / NP1 感度プロファイル / severity=6−TL 変換 | |
| `feedback.py` / `human_anchor.py` / `ground_truth_etl.py` | 306/376/567 | analyst feedback 台帳 / 週次人間ラベルキュー / ground-truth ETL | |
| `inconclusive_continuity.py` / `markdown.py` | 376/165 | 慢性結論不可検知（ADR-V2-010）/ conclusions.md レンダラ | |
| `shadow_metrics.py` | 125 | v1/v2 dual-write 成否カウンタ | **dorm**(Mode B 足場) |
| `rss_extractor.py` | 586 | bg observer 用 RSS 抽出 | conclusions 配下にあるのは違和感（種別違い） |

### calibration パッケージ（自動較正）

| ファイル | 行数 | 責務 | フラグ |
|---|---|---|---|
| `auto_apply_tier_governor.py` / `_repository.py` | 887/351 | 提案自動適用の tier 統治 + 永続化 | |
| `scenario_improver.py` / `scenario_apply.py` / `scenario_discoverer.py` / `scenario_structure_proposer.py` | 770/314/296/348 | シナリオ改善提案 / 適用 / 発見 / 構造提案 | |
| `drift_watchdog.py` / `proposal_lifecycle.py` / `_proposal_guards.py` / `_proposal_writer.py` | 656/527/500/250 | drift 監視 / 提案の状態遷移 / ガード / 書込み | |
| `sensor_disable_proposer.py` | 406 | センサー無効化提案 + 自動エスカレーション適用 | **LV**（§3-b） |
| `tl_threshold_calibrator.py` / `threshold_history.py` / `lineage.py` | 363/329/180 | TL 閾値較正 / 履歴 / 系譜 | |
| `g3b_llm_annotator.py` / `llm_confidence_calibrator.py` / `auto_tune_governor.py` / `auto_feedback_etl.py` / `run_now.py` | 346/216/284/167/208 | LLM 注釈 / confidence 較正 / auto-tune 統治 / feedback ETL / 手動一括実行 | |
| `v1_sunset_audit.py` | 347 | v1 残滓監査ジョブ | **dorm**候補（sunset 完了後は不要） |

### routes パッケージ（22 ファイル / 167 REST endpoint）

| ファイル | 行数 | 責務 | フラグ |
|---|---|---|---|
| `__init__.py` | 104 | 共有 Blueprint + registry/engine 注入 + `_require_admin`/`_require_analyst` | **circ** の中心（§2） |
| `core.py` | 3,174 | app_config / scenarios / **threat_data スコアリングループ** | **god, LV, dual** |
| `analytics.py` | 1,134 | 読み取り専用分析 17 endpoint（sitrep/salute/whatif/spof…） | 一部で採点再計算 |
| `admin.py` | 786 | config registry / scenario CRUD / noise exclusion 等 23 endpoint | |
| `analyst.py` | 687 | tradecraft 25 endpoint（ACH/disconf/dissent/assumption/premortem） | 機能はほぼ休眠（MEMORY: 空ノート） |
| `intel.py` | 405 | インテルキュー確認/棄却/統計 10 endpoint | |
| `history.py` | 225 | 履歴系 7 endpoint | |
| `conclusions_v2.py` | 937 | v2 結論 API 11 endpoint + 他 v2 モジュール共有 helper | v2 hub 化 |
| `calibration_v2.py` | 813 | 較正・提案・drift 17 endpoint | |
| `decisions.py` | 448 | Decision Layer 10 endpoint | |
| `attention_v2.py` / `llm_features_v2.py` / `llm_routing_v2.py` | 293/243/322 | ATTENTION / Feature Hub / ルーティング制御 | |
| `sensors_v2.py` / `auto_judge_v2.py` / `analyst_feedback_v2.py` / `human_anchor_v2.py` / `chronic_inconclusive.py` / `calibration_governor.py` / `triage_narrative.py` | 184/185/95/116/55/53/180 | 各 1-2 endpoint の v2 読み出し面 | 小粒ファイル乱立 |
| `static.py` / `climate.py` | 31/23 | 静的配信 / climate 2 endpoint | |

## 2. 依存エッジ一覧

**総数**: 内部 import 文 457（モジュールレベル 187 / 関数内遅延 270）。遅延 import が全体の 59% を占め、循環回避が常態化している。

### ハブ（被依存の集中点）

- `radar.database`（db singleton）: **約 30 モジュール**から直接参照。routes・scoring・intel・LLM・calibration・conclusions・auth・ws すべてが同一 god-object に依存
- `radar.config`: 約 20 モジュール。`radar.state`: scoring, scheduler, routes/core, intel, calibration/scenario_apply
- `radar.routes.conclusions_v2`: **9 つの v2 route モジュール**が横方向依存（attention_v2, auto_judge_v2, calibration_governor, calibration_v2, chronic_inconclusive, analyst_feedback_v2, human_anchor_v2, llm_features_v2, llm_routing_v2, sensors_v2, triage_narrative）— 共有 helper が hub 化
- `radar.conclusions.api`: 上記 v2 routes 全部 + conclusions_v2

### `import radar.routes as _routes` 遅延バインド参照（全列挙）

| 参照元 | 行 | 目的 |
|---|---|---|
| `radar/routes/intel.py` | 5 | module-level。`_routes.registry` 参照 |
| `radar/routes/core.py` | 42 | 同上 |
| `radar/routes/admin.py` | 15 | 同上 |
| `radar/routes/analytics.py` | 21 | 同上 |
| `radar/routes/climate.py` | 3 | 同上 |
| `radar/attention.py` | 205 | 関数内。`registry._sensors` private 参照（**LV**） |
| `radar/calibration/sensor_disable_proposer.py` | 118, 290 | 関数内。`registry._sensors` 参照 + `sensor.enabled=False` 書換（**LV**） |
| `radar/__init__.py` | 223 | `_routes_mod` として import し blueprint 登録 + init_routes() 注入 |

パターンの実態: `radar/routes/__init__.py` L24-32 が `registry`/`engine` のグローバル変数を持ち、`radar/__init__.py` が起動時に注入。routes パッケージが **DI コンテナ兼 service locator** を兼務しており、routes 以外の層（attention, calibration）までこれを経由してセンサーレジストリへ到達している。

### sensors 層への依存エッジ（記録のみ、詳細は別エージェント）

- `radar/__init__.py` → `radar.sensors`（全センサー登録）
- `radar/engine.py`, `radar/scheduler.py`, `radar/plugin_loader.py` → `radar.sensors.base`
- `radar/routes/core.py` → `radar.sensors.checkhost`, `radar.sensors.telegram`
- `radar/routes/admin.py` → `radar.sensors.telegram`
- `radar_api.py` → `radar.sensors.bgp_routing` / `ihr` / `ripe_atlas` / `tor_metrics`（re-export のみ）

### 逆流エッジ（下位層→上位層。すべて遅延 import で成立）

- calibration → routes（sensor_disable_proposer）、attention → routes
- auth / intel_queue / scheduler / notifications → ws（emit）
- scoring → conclusions（shadow-write。scoring が結論導出を起動する構造は設計通りだが、遅延 import 11 箇所に分散）
- database → decisions / config_layered（遅延。永続層が上位ドメインを参照）

## 3. レイヤー違反・構造的問題の所見

### a) `get_threat_data` god-function（最重要・アーキテクチャ起因）

`radar/routes/core.py:509-3173` — **単一関数 2,665 行**。REST ハンドラの中に:
センサーキャッシュ読出し（`_read_sensor_caches` L383）→ `add_rat` ゲーティング（**L923 で closure として定義**、ミュート/noise exclusion/confidence suppression 判定）→ 収斂スコア計算 → sequence event 登録 → conclusions 派生 → **WS emit（L3031, 3048, 3053）** → global_cache 書込み、まで全部が入っている。CLAUDE.md §5 の「スコアリング層 = routes/core.py」という規約自体が、スコアリングと HTTP 層の癒着を追認してしまっている。**GET リクエストが採点という副作用を駆動する**構造（polling 時代の遺構）が根本原因。

### b) calibration / attention → routes 逆依存 + private access（アーキテクチャ起因）

- `radar/calibration/sensor_disable_proposer.py:118,290` — `_routes.registry._sensors` を private 参照し、L290 側では `sensor.enabled = False` を**直接書換**。較正層がセンサーレジストリを routes 経由で変異させている
- `radar/attention.py:205-210` — 同じく `registry._sensors` を舐めて health を集計
- 修正方向: registry を routes から独立したモジュール（`radar/registry.py` 等）に昇格し、enable/disable は公開 API 経由に

### c) `radar/database.py` god-module の分割線

RadarDB 約 170 メソッドはプレフィックスで綺麗にドメイン分類でき、呼び出し元も分離している（Grep 実測）:

| グループ（メソッド prefix） | 行範囲目安 | 主な呼び出し元 | 提案 repository |
|---|---|---|---|
| baseline_/airspace_/hod_/gdelt_/ts_/series_/sensor_obs_/sensor_cache_/zscore_ | L2920-3220, L4189-4255, L5063-5091 | sensors, scoring, persistence, migration, routes/history | `sensor_stats_repo` |
| seq_/alert_/tl_observation/scenario_contribution/focus_switch/bg_observer | L3223-3690 | scoring, routes/core, background_observer | `scoring_obs_repo` |
| scenario_*（CRUD）/threat_* | L3918-4186 | scenarios.py, routes/admin, routes/core, calibration/scenario_apply | `scenario_repo` |
| intel_* | L5595-5985 | intel_queue, intel_corroboration, intel_auto_judge, routes/intel | `intel_repo` |
| llm_call/llm_routing/llm_embedding/llm_shadow/auto_judge_decision | L4390-4941, L5011-5060 | llm_client, llm_routing, intel_queue, routes | `llm_ledger_repo` |
| user_/token_/user_settings | L5989-6131 | auth.py, ws.py, routes/__init__(_require_admin) | `auth_repo` |
| ach_/disconf_/dissent_/assumption_/premortem_/decision_/hidden_signal_/coverage_ | L6134-6614 | **routes/analyst.py のみ** | `tradecraft_repo`（休眠機能ごと分離可能） |
| config_change_log/noise_excl/confirmed_threat/daily_summary/cooccurrence/ct_log/climate_events | L4300-4387, L4944-5009, L5094-5268, L5548-5592 | config_layered, admin, climate, sensors/ct_log | `ops_repo`（さらに分割可） |
| _migration_v* 13 関数 + _SCHEMA_SQL + _CooperativeConn | L48-2917 | 内部のみ | `schema.py` + `connection.py` |

tradecraft 系は呼び出し元が routes/analyst.py 単独なので**最も安全な第一切断線**。

### d) 休眠足場・旧用語残滓の判定

| 対象 | 所在 | 判定 |
|---|---|---|
| `theater` 旧用語 | database.py ほぼ全メソッド引数名 + `_A4_THEATER_TABLES`(L29) + `_migration_v24_generated_country`(country GENERATED 列の dual-read) | **live**（内部語彙として現役。rename 未完の最大残滓） |
| `theater` WS 語彙 | ws.py: `subscribe_theater`/`unsubscribe_theater` イベント名、room `theater:{X}`、`emit_intel_update(theater,…)` は**引数未使用** | **live**（WS プロトコル境界が旧語のまま。dead param あり） |
| `theater` intel | intel_queue.py L438-1032 `item["theater"]` 後方互換パス | **live**（fallback 経路） |
| `core_theater`/`strategic_theaters` | scenarios.py L600-604（API 互換キー）、routes/core.py L3048 変数名 | **live**（レスポンス互換のため維持） |
| `scoring_mode` / C-lite | scoring.py L1538 `"full" if is_focused else "lite"`、conclusions/threat_level.py L144 | **live**（現役機構。C-medium 評価 knob のみ config.py L179 で RETIRED 済） |
| `SHADOW_DUAL` | llm_routing.py L550-618 状態機械、database llm_shadow_invocation 表 | **live**（Feature Hub の正規状態。使用時のみ発火） |
| `V2_API_ENABLED` | config.py L244（default true）、13 route モジュールの gate | **dead-ish**（常時 true。v1 sunset 後は gate ごと撤去可能） |
| `conclusions/shadow_metrics.py` | scoring.py / auth.py / intel_queue.py から record_* 呼び出し | **live だが移行足場**（dual-write 監視。v2 完全移行後に撤去対象） |
| `migration.py` | persistence.py:72 からのみ参照（JSON 存在時のみ実行） | **dormant**（初回移行済み環境では dead path） |
| `calibration/v1_sunset_audit.py` | scheduler から起動 | **過渡的**（sunset 完了で不要化） |
| `llm_client.py.bak` | radar/ 直下 | **junk**（即削除可） |
| `audit_middleware.py` | admin 系 endpoint に適用中 | **live だが「migrate できない legacy 向け」と自認する過渡層** |

### e) その他の欠陥候補（D2 の種）

1. **GET 副作用スコアリング**（§a 再掲）— アーキテクチャ起因。scheduler 駆動へ倒すのが v3 の本丸
2. **スコアリング二重実装**: engine.py（WeightedConvergenceEngine）と scoring.py に velocity/acceleration/`_linear_regression_slope` が重複（scoring.py L1060 に "shared with engine.py" と自認コメント）。routes/core.py が両方を編んでいる — アーキテクチャ起因（DRY 違反）
3. **`_LATEST_SIGNALS_SNAPSHOT`**（routes/core.py 定数欄）と `state.global_cache` の mutable module-global 並存。lock 規律が state.py 側にしかない — ロジックバグ類（競合リスク）
4. **v2 routes の横依存**: 10 モジュールが routes/conclusions_v2.py の helper に依存。共通 helper は routes/__init__ か専用モジュールへ — アーキテクチャ起因（軽）
5. **`_require_admin`/`_require_analyst` が毎リクエスト DB role lookup**（routes/__init__.py L53-87）。JWT クレームに role を載せれば不要 — ロジックバグ類ではないが性能・設計両面の改善候補
6. **rss_extractor.py の置き場**: RSS 取得器が conclusions/ 配下（background_observer 専用）。パッケージ責務と不一致 — アーキテクチャ起因（軽）
7. **auth.py が認証ロジックと 11 endpoint を同居**（702 行）。routes 層分離の例外 — アーキテクチャ起因(軽)
8. **routes/analyst.py の tradecraft 25 endpoint はほぼ休眠**（MEMORY: 空テーブル。統合は 2026-04-30 に棚上げ済）。DB メソッド群と合わせて縮退候補

## 4. D6 素材: API サーフェス

**REST 167 endpoint**（`@bp.route` 全数。auth blueprint は `/api/auth` prefix 付与済で表記）。抽出コマンド: `grep -nE '@bp\.route\(' radar/routes/*.py radar/auth.py` — ファイル別件数と本表の行数は一致確認済（audit_middleware.py の 1 件は docstring 内の使用例であり実 route ではない）。

| Method | Path | Handler | 位置 |
|---|---|---|---|
| GET | `/api/v2/config/registry` | `api_v2_config_registry` | routes/admin.py:69 |
| GET | `/api/v2/config/values` | `api_v2_config_values` | routes/admin.py:123 |
| POST | `/api/v2/config` | `api_v2_config_post` | routes/admin.py:167 |
| DELETE | `/api/v2/config` | `api_v2_config_clear` | routes/admin.py:235 |
| GET,POST | `/api/sensor_config` | `sensor_config` | routes/admin.py:271 |
| POST | `/api/telegram_log/clear` | `api_telegram_log_clear` | routes/admin.py:287 |
| POST | `/api/persist_save` | `api_persist_save` | routes/admin.py:297 |
| GET | `/api/noise_exclusion` | `api_noise_exclusion_list` | routes/admin.py:321 |
| POST | `/api/noise_exclusion` | `api_noise_exclusion_add` | routes/admin.py:329 |
| DELETE | `/api/noise_exclusion/<int:rule_id>` | `api_noise_exclusion_delete` | routes/admin.py:365 |
| GET | `/api/confirmed_threats` | `api_confirmed_threats_list` | routes/admin.py:378 |
| POST | `/api/confirmed_threats` | `api_confirmed_threats_add` | routes/admin.py:389 |
| GET | `/api/daily_summary` | `api_daily_summary` | routes/admin.py:424 |
| GET | `/api/cooccurrence` | `api_cooccurrence` | routes/admin.py:435 |
| GET | `/api/admin/scenarios` | `api_admin_scenario_list` | routes/admin.py:461 |
| POST | `/api/admin/scenarios` | `api_admin_scenario_create` | routes/admin.py:484 |
| PUT | `/api/admin/scenarios/<scenario_id>` | `api_admin_scenario_update` | routes/admin.py:520 |
| DELETE | `/api/admin/scenarios/<scenario_id>` | `api_admin_scenario_delete` | routes/admin.py:563 |
| POST | `/api/admin/scenarios/<scenario_id>/state` | `api_admin_scenario_state` | routes/admin.py:606 |
| POST | `/api/admin/scenarios/<scenario_id>/enabled` | `api_admin_scenario_enabled` | routes/admin.py:641 |
| POST | `/api/admin/scenarios/<scenario_id>/reset` | `api_admin_scenario_reset` | routes/admin.py:666 |
| GET | `/api/admin/scenarios/<scenario_id>/changelog` | `api_admin_scenario_changelog` | routes/admin.py:684 |
| GET | `/api/admin/sensor_health` | `api_admin_sensor_health` | routes/admin.py:693 |
| GET | `/api/analyst/hidden_signals` | `hidden_signals_list` | routes/analyst.py:85 |
| GET | `/api/analyst/coverage` | `coverage_get` | routes/analyst.py:105 |
| GET | `/api/analyst/disconf` | `disconf_list` | routes/analyst.py:121 |
| POST | `/api/analyst/disconf` | `disconf_add` | routes/analyst.py:134 |
| POST | `/api/analyst/disconf/<int:item_id>/retract` | `disconf_retract` | routes/analyst.py:169 |
| GET | `/api/analyst/ach` | `ach_list` | routes/analyst.py:191 |
| POST | `/api/analyst/ach` | `ach_create` | routes/analyst.py:203 |
| GET | `/api/analyst/ach/<int:matrix_id>` | `ach_get` | routes/analyst.py:227 |
| POST | `/api/analyst/ach/<int:matrix_id>/hypothesis` | `ach_add_hypothesis` | routes/analyst.py:239 |
| POST | `/api/analyst/ach/<int:matrix_id>/evidence` | `ach_add_evidence` | routes/analyst.py:268 |
| POST | `/api/analyst/ach/<int:matrix_id>/score` | `ach_set_score` | routes/analyst.py:300 |
| GET | `/api/analyst/dissent` | `dissent_list` | routes/analyst.py:329 |
| POST | `/api/analyst/dissent` | `dissent_add` | routes/analyst.py:342 |
| POST | `/api/analyst/dissent/<int:view_id>/resolve` | `dissent_resolve` | routes/analyst.py:374 |
| GET | `/api/analyst/assumptions` | `assumption_list` | routes/analyst.py:397 |
| POST | `/api/analyst/assumptions` | `assumption_add` | routes/analyst.py:410 |
| PATCH | `/api/analyst/assumptions/<int:aid>` | `assumption_edit` | routes/analyst.py:441 |
| POST | `/api/analyst/assumptions/<int:aid>/lock` | `assumption_lock` | routes/analyst.py:472 |
| POST | `/api/analyst/assumptions/<int:aid>/invalidate` | `assumption_invalidate` | routes/analyst.py:497 |
| GET | `/api/analyst/assumptions/<int:aid>/log` | `assumption_log` | routes/analyst.py:519 |
| GET | `/api/analyst/premortem` | `premortem_list` | routes/analyst.py:529 |
| POST | `/api/analyst/premortem` | `premortem_add` | routes/analyst.py:542 |
| POST | `/api/analyst/premortem/<int:eid>/resolve` | `premortem_resolve` | routes/analyst.py:577 |
| GET | `/api/analyst/decisions` | `decision_list` | routes/analyst.py:599 |
| POST | `/api/analyst/decisions` | `decision_log` | routes/analyst.py:621 |
| GET | `/api/v2/analyst_feedback` | `v2_analyst_feedback_list` | routes/analyst_feedback_v2.py:52 |
| GET | `/api/data_status` | `data_status` | routes/analytics.py:35 |
| GET | `/api/sensor_reliability` | `sensor_reliability` | routes/analytics.py:60 |
| GET | `/api/alert_timeline` | `api_alert_timeline` | routes/analytics.py:68 |
| GET | `/api/sitrep` | `api_sitrep` | routes/analytics.py:75 |
| GET | `/api/sequence_chain` | `api_sequence_chain` | routes/analytics.py:161 |
| GET | `/api/deep_analytics` | `api_deep_analytics` | routes/analytics.py:190 |
| GET | `/api/salute_report` | `api_salute_report` | routes/analytics.py:300 |
| GET | `/api/weather_brief` | `api_weather_brief` | routes/analytics.py:476 |
| GET | `/api/ip_check` | `api_ip_check` | routes/analytics.py:595 |
| GET | `/api/score_breakdown` | `api_score_breakdown` | routes/analytics.py:642 |
| GET | `/api/whatif/catalog` | `whatif_catalog` | routes/analytics.py:722 |
| POST | `/api/whatif/simulate` | `whatif_simulate` | routes/analytics.py:729 |
| GET | `/api/spof_analysis` | `spof_analysis` | routes/analytics.py:836 |
| GET | `/api/adaptive_zscore_status` | `adaptive_zscore_status` | routes/analytics.py:975 |
| GET | `/api/analytics/calibration_advisory` | `api_calibration_advisory` | routes/analytics.py:1007 |
| GET | `/api/analytics/confidence_distribution` | `api_confidence_distribution` | routes/analytics.py:1082 |
| GET | `/api/analytics/scenario_phases` | `api_scenario_phases` | routes/analytics.py:1096 |
| GET | `/api/v2/attention` | `v2_attention_list` | routes/attention_v2.py:57 |
| POST | `/api/v2/attention/<rule_id>/snooze` | `v2_attention_snooze` | routes/attention_v2.py:83 |
| GET | `/api/v2/attention/thresholds` | `v2_attention_thresholds_list` | routes/attention_v2.py:134 |
| PUT | `/api/v2/attention/thresholds/<rule_id>` | `v2_attention_thresholds_put` | routes/attention_v2.py:161 |
| DELETE | `/api/v2/attention/thresholds/<rule_id>` | `v2_attention_thresholds_delete` | routes/attention_v2.py:204 |
| POST | `/api/v2/attention/observations/recompute` | `v2_attention_observations_recompute` | routes/attention_v2.py:276 |
| GET | `/api/v2/auto_judge/decisions` | `v2_auto_judge_decisions` | routes/auto_judge_v2.py:145 |
| GET | `/api/v2/calibration/tier_governor` | `v2_calibration_tier_governor` | routes/calibration_governor.py:44 |
| GET | `/api/v2/threshold_history` | `v2_threshold_history_list` | routes/calibration_v2.py:97 |
| GET | `/api/v2/threshold_history/<int:row_id>` | `v2_threshold_history_get` | routes/calibration_v2.py:131 |
| GET | `/api/v2/threshold_history/<int:row_id>/lineage` | `v2_threshold_history_lineage` | routes/calibration_v2.py:147 |
| POST | `/api/v2/threshold_history/<int:row_id>/revert` | `v2_threshold_history_revert` | routes/calibration_v2.py:167 |
| GET | `/api/v2/proposals/sensor_disable` | `v2_proposals_sensor_disable_list` | routes/calibration_v2.py:203 |
| POST | `/api/v2/proposals/sensor_disable/<int:proposal_id>/ack` | `v2_proposals_sensor_disable_ack` | routes/calibration_v2.py:220 |
| GET | `/api/v2/proposals/scenario_improver` | `v2_proposals_scenario_improver_list` | routes/calibration_v2.py:252 |
| POST | `/api/v2/proposals/scenario_improver/<int:proposal_id>/apply` | `v2_proposals_scenario_improver_apply` | routes/calibration_v2.py:352 |
| POST | `/api/v2/proposals/scenario_improver/<int:proposal_id>/dismiss` | `v2_proposals_scenario_improver_dismiss` | routes/calibration_v2.py:365 |
| POST | `/api/v2/proposals/scenario_improver/<int:proposal_id>/defer` | `v2_proposals_scenario_improver_defer` | routes/calibration_v2.py:378 |
| GET | `/api/v2/drift_signals` | `v2_drift_signals_list` | routes/calibration_v2.py:394 |
| POST | `/api/v2/drift_signals/<int:event_id>/ack` | `v2_drift_signals_ack` | routes/calibration_v2.py:425 |
| POST | `/api/v2/calibration/run_now` | `v2_calibration_run_now` | routes/calibration_v2.py:457 |
| GET | `/api/v2/calibration/health` | `v2_calibration_health` | routes/calibration_v2.py:504 |
| GET | `/api/v2/discovery/cooccurrence` | `v2_discovery_cooccurrence` | routes/calibration_v2.py:625 |
| GET | `/api/v2/discovery/clusters` | `v2_discovery_clusters` | routes/calibration_v2.py:643 |
| GET | `/api/v2/discovery/clusters/<int:run_id>/replay` | `v2_discovery_replay` | routes/calibration_v2.py:703 |
| GET | `/api/v2/observability/chronic_inconclusive` | `v2_observability_chronic_inconclusive` | routes/chronic_inconclusive.py:46 |
| GET | `/api/climate` | `climate_summary` | routes/climate.py:10 |
| GET | `/api/climate/feed` | `climate_feed` | routes/climate.py:17 |
| GET | `/api/v2/scenarios/<scenario_id>/threat_history` | `v2_scenario_threat_history` | routes/conclusions_v2.py:77 |
| GET | `/api/v2/scenarios/<scenario_id>/conclusions` | `v2_scenario_conclusions` | routes/conclusions_v2.py:126 |
| GET | `/api/v2/scenarios/<scenario_id>/conclusions/<conclusion_type>` | `v2_scenario_conclusion_single` | routes/conclusions_v2.py:146 |
| GET | `/api/v2/conclusions/<conclusion_id>` | `v2_conclusion_by_id` | routes/conclusions_v2.py:169 |
| GET | `/api/v2/conclusions/<conclusion_id>/audit_trace` | `v2_conclusion_audit_trace` | routes/conclusions_v2.py:185 |
| GET | `/api/v2/scenarios/<scenario_id>/conclusions.md` | `v2_scenario_conclusions_markdown` | routes/conclusions_v2.py:227 |
| POST | `/api/v2/conclusions/<conclusion_id>/feedback` | `v2_conclusion_feedback_submit` | routes/conclusions_v2.py:281 |
| GET | `/api/v2/conclusions/<conclusion_id>/feedback` | `v2_conclusion_feedback_list` | routes/conclusions_v2.py:387 |
| GET | `/api/v2/admin/shadow_write_metrics` | `v2_shadow_write_metrics` | routes/conclusions_v2.py:437 |
| GET | `/api/v2/replay/<scenario_id>` | `v2_replay` | routes/conclusions_v2.py:468 |
| GET | `/api/v2/self_eval` | `v2_self_eval` | routes/conclusions_v2.py:544 |
| GET | `/api/app_config` | `app_config` | routes/core.py:118 |
| GET | `/api/scenarios` | `list_scenarios` | routes/core.py:137 |
| GET | `/api/scenarios/compare` | `scenarios_compare` | routes/core.py:162 |
| POST | `/api/scenarios/<scenario_id>/whatif_weights` | `scenario_whatif_weights` | routes/core.py:219 |
| GET | `/api/threat_data` | `get_threat_data` | routes/core.py:507 |
| POST | `/api/v2/decisions/triage/snooze` | `triage_snooze` | routes/decisions.py:81 |
| DELETE | `/api/v2/decisions/triage/snooze` | `triage_snooze_release` | routes/decisions.py:119 |
| POST | `/api/v2/decisions/triage/visibility` | `triage_visibility` | routes/decisions.py:140 |
| POST | `/api/v2/decisions/triage/dismiss` | `triage_dismiss` | routes/decisions.py:170 |
| GET | `/api/v2/decisions/triage/state` | `triage_state` | routes/decisions.py:205 |
| PUT | `/api/v2/decisions/threshold` | `triage_threshold_set` | routes/decisions.py:269 |
| GET | `/api/v2/decisions/threshold` | `triage_threshold_get` | routes/decisions.py:307 |
| GET | `/api/v2/decisions/history` | `decisions_history` | routes/decisions.py:340 |
| GET | `/api/v2/decisions/<decision_id>` | `decisions_get` | routes/decisions.py:382 |
| POST | `/api/v2/decisions/<decision_id>/revoke` | `decisions_revoke` | routes/decisions.py:400 |
| GET | `/api/history/countries` | `api_history_countries` | routes/history.py:37 |
| GET | `/api/history/timeseries` | `api_history_timeseries` | routes/history.py:46 |
| GET | `/api/history/hod_baseline` | `api_history_hod_baseline` | routes/history.py:80 |
| GET | `/api/history/alerts` | `api_history_alerts` | routes/history.py:125 |
| GET | `/api/history/sequence_events` | `api_history_sequence_events` | routes/history.py:151 |
| GET | `/api/history/threat_levels` | `api_history_threat_levels` | routes/history.py:179 |
| GET | `/api/history/export` | `api_history_export` | routes/history.py:191 |
| GET | `/api/v2/human_anchor/queue` | `v2_human_anchor_queue` | routes/human_anchor_v2.py:49 |
| GET | `/api/intel` | `intel_list` | routes/intel.py:47 |
| GET | `/api/intel/pending/triage` | `intel_pending_triage` | routes/intel.py:108 |
| GET | `/api/intel/stats` | `intel_stats` | routes/intel.py:169 |
| POST | `/api/intel/<item_id>/confirm` | `intel_confirm` | routes/intel.py:249 |
| POST | `/api/intel/<item_id>/reject` | `intel_reject` | routes/intel.py:263 |
| POST | `/api/intel/<item_id>/revert` | `intel_revert` | routes/intel.py:287 |
| POST | `/api/intel/<item_id>/override` | `intel_override` | routes/intel.py:301 |
| GET | `/api/intel/sources` | `intel_sources` | routes/intel.py:315 |
| GET | `/api/intel/llm_call_stats` | `intel_llm_call_stats` | routes/intel.py:323 |
| GET | `/api/llm_models` | `llm_models` | routes/intel.py:346 |
| GET | `/api/v2/llm_features` | `v2_llm_features_list` | routes/llm_features_v2.py:72 |
| GET | `/api/v2/llm_features/<key>` | `v2_llm_features_get` | routes/llm_features_v2.py:85 |
| POST | `/api/v2/llm_features/<key>/set` | `v2_llm_features_set` | routes/llm_features_v2.py:113 |
| POST | `/api/v2/llm_features/<key>/clear` | `v2_llm_features_clear` | routes/llm_features_v2.py:156 |
| POST | `/api/v2/llm_features/kill_switch` | `v2_llm_features_kill_switch` | routes/llm_features_v2.py:187 |
| GET | `/api/v2/llm_features/audit` | `v2_llm_features_audit` | routes/llm_features_v2.py:230 |
| GET | `/api/v2/llm_routing` | `v2_llm_routing_list` | routes/llm_routing_v2.py:52 |
| GET | `/api/v2/llm_routing/overrides` | `v2_llm_routing_overrides_list` | routes/llm_routing_v2.py:67 |
| POST | `/api/v2/llm_routing/overrides` | `v2_llm_routing_overrides_set` | routes/llm_routing_v2.py:79 |
| DELETE | `/api/v2/llm_routing/overrides` | `v2_llm_routing_overrides_clear` | routes/llm_routing_v2.py:139 |
| GET | `/api/v2/config_audit` | `v2_config_audit` | routes/llm_routing_v2.py:168 |
| GET | `/api/v2/llm_routing/audit` | `v2_llm_routing_audit` | routes/llm_routing_v2.py:212 |
| GET | `/api/v2/llm_preflight` | `v2_llm_preflight` | routes/llm_routing_v2.py:231 |
| GET | `/api/v2/sensors/catalog` | `v2_sensor_catalog` | routes/sensors_v2.py:63 |
| GET | `/api/v2/sensors/<sensor_name>/observations` | `v2_sensor_observations` | routes/sensors_v2.py:95 |
| GET | `/` | `index` | routes/static.py:11 |
| GET | `/<path:filename>` | `static_files` | routes/static.py:16 |
| POST | `/api/v2/triage/narrate` | `v2_triage_narrate` | routes/triage_narrative.py:102 |
| POST | `/api/auth/register` | `register` | auth.py:397 |
| POST | `/api/auth/login` | `login` | auth.py:434 |
| POST | `/api/auth/refresh` | `refresh` | auth.py:504 |
| POST | `/api/auth/logout` | `logout` | auth.py:517 |
| GET | `/api/auth/settings` | `get_settings` | auth.py:541 |
| PUT | `/api/auth/settings` | `update_settings` | auth.py:557 |
| GET | `/api/auth/users` | `list_users` | auth.py:589 |
| PUT | `/api/auth/users/<username>/role` | `update_user_role` | auth.py:601 |
| DELETE | `/api/auth/users/<username>` | `delete_user` | auth.py:627 |
| POST | `/api/auth/users/<username>/reset-password` | `admin_reset_password` | auth.py:648 |
| PUT | `/api/auth/password` | `change_password` | auth.py:676 |

### SocketIO イベント（すべて `radar/ws.py`）

| 方向 | イベント | 定義位置 | 発火元 / 備考 |
|---|---|---|---|
| on | `connect` | ws.py:37 | JWT 検証 |
| on | `disconnect` | ws.py:70 | |
| on | `subscribe_theater` | ws.py:74 | **旧用語**。room `theater:{X}` join |
| on | `unsubscribe_theater` | ws.py:86 | 同上 |
| emit | `threat_update` | ws.py:113 | routes/core.py:3031（room 宛） |
| emit | `ambush_alert` | ws.py:120 | routes/core.py:3048（room 宛） |
| emit | `sequence_event` | ws.py:130 | routes/core.py:3053（room 宛） |
| emit | `sensor_status` | ws.py:137 | scheduler.py（全体 broadcast） |
| emit | `notification_result` | ws.py:144 | notifications.py:280（全体 broadcast） |
| emit | `intel_update` | ws.py:154 | intel_queue.py（全体 broadcast。theater 引数は**未使用**） |
