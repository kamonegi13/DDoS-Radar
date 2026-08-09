# D5 テスト資産分類 — リビルドへ移植可能な「実行可能な仕様書」の選別

> Phase D 調査。対象: `tests/*.py` 101 ファイル + `tests/*.js` 6 ファイル（計 33,206 行 / 1,939 test 関数）。
> 目的: v3 リビルドで仕様書として移植できるテストと、現行実装構造に結合したテストを分ける。
> 分類軸: **BEHAVIOR**（挙動仕様級・実装が変わっても意味を持つ）/ **CONTRACT**（API 形状・S2 の v3 API 契約へ移植可）/
> **STRUCTURAL**(内部構造依存・v3 で書き直し) / **SCAFFOLD**（移行足場・一回きり修正の回帰・持ち込まない）。

## 1. サマリ

| 分類 | ファイル数 | test 関数数 | 行数 | 移植方針 |
|---|---|---|---|---|
| **BEHAVIOR** (py) | 60 | 1,241 | 19,374 | 仕様として抽出 → Phase S トレーサビリティ表の起点 |
| **BEHAVIOR** (js) | 6 | 160 | 1,902 | pure module ごと移植可（依存ゼロの Node テスト） |
| **CONTRACT** | 17 | 271 | 5,253 | v3 API 契約 (S2) に写像。エンドポイント名は変わってよい |
| **STRUCTURAL** | 19 | 223 | 5,802 | v3 で書き直し。中に埋まる閾値・ルールのみ仕様へ救出 |
| **SCAFFOLD** | 5 | 44 | 875 | 持ち込まない（v1→v2 移行足場・一回きり remediation） |
| **合計** | 107 | 1,939 | 33,206 | |

- テスト資産の **72%（行数ベース）が BEHAVIOR 級**。現行テストスイートは「コードにしか存在しない仕様」の最大の保管庫である。
- BEHAVIOR 内でも migration 検証や fixture 構築が混じるファイルは台帳の「混在」注記で示した。
  移植時はクラス単位で仕様部分だけ抜く。

## 2. 全ファイル台帳

### 2.1 BEHAVIOR — 挙動仕様級（60 py + 6 js）

| ファイル | test数 | 対象サブシステム | 移植メモ |
|---|---|---|---|
| test_engine.py | 162 | 収斂エンジン/scoring/CB | **最重要**。25 クラス: 収斂・sequence 減衰・HOD Z・feint・CB 閾値・DDoS→BGP 因果 |
| test_scenario_scoring.py | 60 | シナリオスコアリング | dedup・収斂ボーナス・TL 導出・dual-weight・adversary 寄与・lite 割引 |
| test_rss_extractor.py | 56 | RSS 抽出 (regex+LLM) | regex 決定論 + LLM 失敗時 regex fallback (NP3)。国/死者数抽出コーナーケース |
| test_scenarios.py | 43 | シナリオモデル | ID/participant/state 検証・Layer1 loader・is_scorable・Signal 不変条件 |
| test_llm_routing.py | 40 | LLM ルーティング | UseCase→Model 解決 + OFF/SHADOW/ON。混在: v41/v42 migration クラスは STRUCTURAL |
| test_ground_truth_etl.py | 39 | ground-truth 分類器 | ラベル優先順位 FN>TP>FP>TN・severity floor・provenance タグ |
| test_proposal_guards.py | 36 | calibration ガード | 提案ガード設計原則 P1-P5 の focused unit + E2E |
| test_proposal_lifecycle.py | 30 | 提案状態遷移 | auto_dismiss / supersede / 再ゲート処理の状態機械 |
| test_triage.py | 29 | AP1 triage | 優先度式・ゲートラダー・pulse 集約（2 endpoint の一致性保証） |
| test_anomaly_derive.py | 29 | v2 ANOMALY 導出 | importance 式 (recency×relevance×novelty)・INSUFFICIENT_DATA 経路 |
| test_ct_log_certstream.py | 28 | CT push ソース | 粗フィルタ→watched-apex 厳密照合→observation 構築の純関数パイプライン |
| test_per_domain_derive.py | 27 | v2 PER_DOMAIN 導出 | ACTIVE_FLOOR=3.0 / ELEVATED=1.5 / DEGRADE_DELTA=1.5（spec §6.3 と意図的乖離を明記） |
| test_llm_features.py | 27 | LLM Feature Hub | 機能別 OFF/SHADOW/ON 状態機械 |
| test_auto_apply_tier_governor.py | 27 | tier governor | T0-T3 tier 統治規則。混在: :memory: fixture 依存は書き直し |
| test_attack_mode_derive.py | 26 | ATTACK_MODE 分類器 | ルール閾値: DDOS_PRECURSOR (cyber≥5.0∧info≥1.5) / KINETIC (phys≥3.0) / HYBRID |
| test_attack_mode_extensions.py | 26 | 攻撃モード拡張 | scenario_extensions の domain_floors 等 ALL 条件発火契約 |
| test_rss_narrative.py | 24 | RSS ナラティブ | 地理関連度フィルタ (_classify_article_geo) |
| test_trend_derive.py | 23 | v2 TREND 導出 | velocity+acceleration による状態語彙（spec §6.2 との乖離を明記） |
| test_age_decay.py | 21 | インテル経年減衰 | exp 曲線 age=τ→1/e・per-source τ override・無効時 1.0 |
| test_ct_log_certspotter.py | 21 | CT poll ソース | HTTP mock で決定論化。レスポンス形状は実 API 検証済みと明記 |
| test_ct_log_redesign.py | 21 | CT trust-class | issuer 解析 (O=→CN=→raw)・first_observed/known_cas 評価 (ADR-024)。混在: v11 migration |
| test_dbscan_cluster.py | 19 | DBSCAN | pure-Python クラスタリングのアルゴリズム検証 |
| test_attention.py | 18 | AP1 attention | ルール + p95 適応学習。混在: routes 部分は CONTRACT |
| test_background_observer.py | 18 | AP3 観測健全性 | broadcast scan の participant union スコープ規則 |
| test_human_anchor.py | 17 | 人間アンカー選定 | 週次人間ラベルキューの選定方針（auto-label drift 検知の独立脚） |
| test_inconclusive_continuity.py | 17 | 慢性結論不可 | NP5+8 設計失敗検知の判定規則。混在: endpoint 部分は CONTRACT |
| test_intel_auto_judge.py | 17 | 自動判定 | corroboration/staleness/duplicate/source-drift ルールと auto:rule_* マーカー |
| test_sanitize_llm_input.py | 17 | プロンプト防御 | homoglyph・制御文字を含む injection 緩和契約（Security H6） |
| test_followup_watch.py | 15 | followup 監視 | 条件成立→初回 WARN 1 回のみ、以降 INFO の遷移規則 |
| test_threat_level_derive.py | 15 | v2 TL 導出 | schema・INSUFFICIENT_DATA (tl=None)・confidence [0,1] クランプ |
| test_attack_mode_llm_augment.py | 14 | 攻撃モード LLM 補強 | flag gate + LLM 不達時ルール結論を不変で返す (NP3) |
| test_cooccurrence.py | 14 | 共起分析 | 国ペア共起行列の計算仕様 |
| test_autotune_proposer_guards.py | 13 | autotune ガード | fetch 健全なら sensor_disable 提案を抑止する等の Phase A-F ガード |
| test_calibration_governor.py | 12 | auto_tune governor | threshold_history 台帳 + 安全規則 |
| test_check_recall_post_autotune.py | 12 | recall 事後ゲート | autotune 後 recall 劣化検知の判定分岐 |
| test_conclusion_write_gating.py | 12 | 台帳書込ゲート | 遷移+毎時 heartbeat のみ書く。**latest-row-at-T の replay 意味論を保存** |
| test_falsification.py | 12 | NP1 反証レポート | threshold_distance (to_higher/lower TL)・signal_sensitivity 仮想 TL |
| test_intel_multicountry.py | 12 | 多国インテル | countries/country_weights 導出。混在: v6 migration + theater 互換は SCAFFOLD |
| test_llm_prompt_persistence.py | 12 | NP6 プロンプト台帳 | sha256 安定性・UPSERT で use_count 増分・system 別 dedup |
| test_password_hashing.py | 12 | 認証ハッシュ | argon2id 新規 + PBKDF2 検証継続 + ログイン時 lazy rehash |
| test_tl_calibrator_guards.py | 11 | TL 較正ガード | degenerate-data と genuine no-action の rejection_reason 区別 |
| test_weight_utilization.py | 10 | weight 助言 | 静的 weight vs 実寄与の乖離検出仕様 |
| test_notifications.py | 9 | 通知 | NP7 footer 全 payload 必須・severity tier→色/絵文字・scenario TL 変化のみ通知 |
| test_scenario_admin_override.py | 9 | preset override | preset 整合/admin override の区別シグナル |
| test_check_recall_baseline.py | 16 | recall ゲート | Design W: bootstrap 不失敗・許容内 drop は info 等 6 分岐 |
| test_ooni_degraded.py | 8 | OONI degraded | 自己回復 degraded mode (NP3) |
| test_conclusion_calibration.py | 8 | calibration_status | ground-truth 由来の per-conclusion 較正状態（2026-05-29 再設計後） |
| test_drift_watchdog.py | 8 | drift 監視 | calibration drift 検知規則 (Phase F3) |
| test_intel_tier3_corroborated.py | 8 | tier3 自動確認 | tier1 (0.85/0.80)・tier2 (0.80/0.75)・tier3 corroborated の閾値ラダー |
| test_per_ec_event_firing.py | 8 | dual-core seq | secondary effective_core の per-country イベント発火 |
| test_report_recall_metrics.py | 8 | recall 集計 | 混同行列・ゼロ分母 None・latest-row-wins dedup |
| test_seq_fire_targets.py | 8 | dual-core seq | 対称シナリオでの scenario-wide イベント対称登録 (ADR-009) |
| test_severity.py | 8 | **TL 方向哨戒** | severity=6−TL。TL1=CRITICAL 逆転事故 (較正災害) の再発防止番兵 |
| test_dual_core_observability.py | 6 | dual-core 可観測性 | core_country=null 対称シナリオの採点観測 |
| test_tl_threshold_calibrator.py | 6 | TL 閾値較正 | Phase B 較正規則 |
| test_weight_advisory_timeseries.py | 6 | weight 時系列 | N 等分バケット・空バケット share=0・global 行除外 |
| test_proposal_snooze_revival.py | 5 | snooze 復活 | snoozed_30d→30 日後 pending 復帰スイープ |
| test_greynoise_gnql.py | 3 | GreyNoise 縮退 | GNQL 410 でも恒常 DEGRADED 化しない (NP3) |
| test_scheduler_chronic_hook.py | 3 | 慢性フック | chronic 状態→record_failure 発火、INCONCLUSIVE_CHRONIC は NP1 圏外 |
| test_scenario_structure_proposer.py | 20 | 構造提案 | dominant source_type→role 提案の floor/share 閾値規則 |
| **test_triage_score.js** | 21 | AP1 attention_score | novelty×confidence_delta×blindness 式 + ランキング（pure） |
| **test_triage_display_mode.js** | 34 | triage 表示状態機械 | dormant / pin-dock / critical-banner の遷移（pure） |
| **test_self_explanation.js** | 18 | AP2 自己説明 | テンプレート+スロットの決定論ナラティブ生成（pure） |
| **test_wp_alarm.js** | 46 | WP アラーム | 評価器 + 正規化器（pure） |
| **test_hud_v2_overlay.js** | 21 | HUD↔v2 整合 | HUD と v2 結論の reconcile 規則（pure） |
| **test_map_dim.js** | 20 | 地図 dim | focus 変更 dim 状態機械（pure） |

### 2.2 CONTRACT — API 契約級（17 ファイル、S2 の v3 API 契約へ写像）

| ファイル | test数 | 対象サブシステム | 移植メモ |
|---|---|---|---|
| test_auth.py | 49 | 認証 API | login/refresh/cookie/登録/rate limit/JWT 強制。混在: airspace 計算・retention は BEHAVIOR |
| test_decisions.py | 32 | AP4 Decision Layer | 台帳 API + v34 migration。決定台帳の read/write 契約 |
| test_routes_calibration_v2.py | 29 | calibration v2 routes | 503/401/403 ゲートラダー + レスポンス形状 |
| test_conclusions_markdown.py | 21 | .md エクスポート | レンダラのデータ形状契約（golden-string でなく構造検証 — 良手本） |
| test_conclusions_api.py | 19 | v2 conclusions API | flag off→503・bundle 5 種・単一タイプ取得 |
| test_analyst_permissions.py | 18 | role ゲート | viewer/analyst/admin × 全 tradecraft endpoint 権限行列 |
| test_routes_llm_features.py | 16 | Feature Hub routes | 制御面契約 |
| test_conclusions.py | 14 | Conclusion schema | 統一 schema + NP7 disclaimer 必須 (制約⑥) |
| test_conclusions_feedback.py | 14 | feedback API | JWT 由来 analyst_id・CHECK 制約・集約 |
| test_analyst_feedback_v2.py | 13 | feedback v2 面 | SETTINGS audit.feedback が読む契約 |
| test_routes_triage_narrative.py | 10 | triage narrative | AP2 ナラティブ配信面 |
| test_auto_judge_v2.py | 9 | auto_judge 監査面 | SETTINGS audit.auto_judge が読む契約 |
| test_self_eval.py | 9 | AP3 self_eval | DRIFT chip データパス（~12 chip 合成の一部） |
| test_config_audit_endpoint.py | 7 | config 監査面 | {domains, rows} 形状 + 行フィールド |
| test_intel_confidence_distribution.py | 5 | インテル統計 | source_type 別ヒストグラム形状 |
| test_history_routes.py | 3 | 履歴 API | /countries 正 + /theaters 非推奨 alias（alias 部分は SCAFFOLD） |
| test_sensor_tier_exposure.py | 3 | センサー管理面 | 全センサー行に tier (FOCUSED_ONLY 等) 露出 |

### 2.3 STRUCTURAL — 構造依存（19 ファイル、v3 で書き直し）

| ファイル | test数 | 対象サブシステム | 書き直し理由 / 救出すべき断片 |
|---|---|---|---|
| conftest.py | 0 | 共有 fixture | tier_governor_repo 等。v3 の DB 抽象で再設計 |
| test_run_rss_etl.py | 23 | RSS ETL runner | スクリプト orchestration 結合。fallback 規則のみ仕様へ |
| test_check_i18n_keys.py | 22 | CI i18n 監査 | 現行 i18n.js/regex 構造に結合。**ja-only ポリシー自体は仕様として保存** |
| test_calibration_run_now.py | 20 | 手動一括較正 | phase dispatch 配線。1 phase 失敗が他を止めない規則のみ救出 |
| test_ct_log_orchestrator.py | 16 | CT orchestrator | source 分割 seam 固有（ObservationBuffer 構造） |
| test_threat_history_scoped.py | 16 | threat_history | DB メソッド名 (threat_append_scoped 等) に結合。per-scenario スコープ意味論は仕様へ |
| test_run_ground_truth_etl.py | 15 | GT ETL runner | 実 DB 列挙 orchestration。分類器本体は test_ground_truth_etl (BEHAVIOR) が持つ |
| test_conclusions_persistence.py | 14 | 台帳 round-trip | 現 SQLite schema 結合。append-only + disclaimer 注入不変条件は仕様へ |
| test_proposal_writer.py | 14 | 提案書込み | writer 内部 API 結合 |
| test_scenario_apply.py | 13 | 提案適用 | live テーブル直接 mutation の seam 検証 |
| test_auto_apply_seam.py | 12 | auto-apply seam | `scenario_improver._emit` 出口という private seam に結合。flag OFF→全 pending 規則は仕様へ |
| test_phase_cdf1.py | 11 | C/D/F1 較正 | 統合点の疎通確認と自認（ルール本体は他ファイル） |
| test_scenario_discoverer.py | 11 | シナリオ発見 | snapshot/cluster 永続配線。既存シナリオ重複 skip 規則は仕様へ |
| test_lineage.py | 9 | 提案系譜 | 祖先/子孫 walk・max_depth。台帳構造に結合するが graph 意味論は移植候補 |
| test_g3b_llm_annotator.py | 9 | LLM 注釈 | shadow/production 状態と cap。Feature Hub 側 (BEHAVIOR) と重複 |
| test_diagnostics.py | 6 | 週次診断 runner | cadence gate + import 配線 |
| test_ui_integrity.py | 5 | UI 静的整合 | 現行 index.html/i18n.js 構造の静的 grep 検査 |
| test_apt_prompt_dedup.py | 4 | APT prompt 節約 | Stage1/2 プロンプト再利用というトークン最適化実装詳細 |
| test_contribution_log_retention.py | 3 | 寄与ログ retention | v18 テーブル固有。retention 方針値は ops 仕様へ転記 |

### 2.4 SCAFFOLD — 足場/回帰（5 ファイル、v3 に持ち込まない）

| ファイル | test数 | 対象 | 捨てる理由 |
|---|---|---|---|
| test_v1_sunset_audit.py | 17 | v1 残滓監査 | v1 sunset 完了で不要（D1 でも dorm 候補判定） |
| test_shadow_metrics.py | 10 | dual-write カウンタ | Mode B 移行足場（D1: dorm）。v3 に dual-write は無い |
| test_a4_country_generated_column.py | 7 | theater→country 移行 | v24 GENERATED 列の dual-read。v3 は country のみで出発 |
| test_remediate_cross_scenario_labels.py | 6 | 2026-08-02 remediation | 一回きり本番修正スクリプトの回帰 |
| test_llm_log_retention.py | 4 | LLM ログ retention | dead-code 修正 (2026-07-04) の回帰。retention 既定値 30 日のみ ops 仕様へ転記 |

## 3. 仕様の宝 — コードにしか無い挙動仕様を最も濃く encode する上位 15

Phase S トレーサビリティ表の起点。各行 = 「このテストが消えると失われる不変条件」。

| # | テスト | 保存している不変条件（1 行） |
|---|---|---|
| 1 | test_engine.py | 収斂エンジンの全式: 収斂ゲート・sequence 時間減衰・HOD Z-score・feint 検知・DDoS→BGP 因果・origin entropy・circuit breaker 開閉閾値 |
| 2 | test_scenario_scoring.py | scenario score = dedup 済み寄与 × dual-weight + adversary 寄与 + 収斂ボーナス → TL 導出、lite モードは confidence 割引 |
| 3 | test_severity.py | **severity = 6 − TL**（TL1=CRITICAL の DEFCON 方向）。逆転すると較正層全体が静かに反転する（実事故 2 回の番兵） |
| 4 | test_ground_truth_etl.py | ground-truth ラベル優先順位 FN > TP > FP > TN（NP1: 見逃し最優先）+ expected severity floor + ソース provenance |
| 5 | test_attack_mode_derive.py | 攻撃モード分類規則: DDOS_PRECURSOR=cyber≥5.0∧info≥1.5 / KINETIC_PREPARATION=physical≥3.0 / HYBRID_PRESSURE=3 domain≥1.5∧4 国以上 |
| 6 | test_triage.py + test_triage_score.js | AP1 優先度式・ゲートラダー・attention_score(novelty×confidence_delta×blindness) — 2 API と HUD pulse の一致性 |
| 7 | test_per_domain_derive.py / test_trend_derive.py | v2 導出閾値の現行実装値 (ACTIVE=3.0/ELEVATED=1.5/DEGRADE_DELTA=1.5、TREND 語彙) — **spec 文書と意図的に乖離しており、テストだけが実値を持つ** |
| 8 | test_conclusion_write_gating.py | 台帳は遷移+毎時 heartbeat のみ書いても latest-row-at-T の replay 意味論 (AP4) を破らない |
| 9 | test_age_decay.py | インテル経年重み = exp(−age/τ)（age=τ→1/e）、source_type 別 τ override、無効時 1.0 |
| 10 | test_intel_tier3_corroborated.py | 自動確認 tier ラダー: tier1=conf≥0.85∧cred≥0.80 / tier2=0.80∧0.75 / tier3=独立ソース corroboration で救済 |
| 11 | test_sanitize_llm_input.py | LLM 入力防御は英語命令句だけでなく Unicode homoglyph・制御文字経由の injection も無害化する |
| 12 | test_proposal_guards.py + test_proposal_lifecycle.py | 較正提案の安全規則 P1-P5 と状態機械（auto_dismiss / supersede / snooze 復活） |
| 13 | test_ct_log_redesign.py (+certstream/certspotter) | CT 証明書の trust-class 評価: issuer 解析フォールバック連鎖・first_observed/known_cas・watched-apex 厳密照合 |
| 14 | test_inconclusive_continuity.py + test_scheduler_chronic_hook.py | 慢性結論不可 = 設計失敗 (NP5+8) の判定規則と silent-failure 台帳への自動起票 |
| 15 | test_falsification.py | NP1 反証レポート: TL 昇降格までの threshold_distance と寄与除去時の仮想 TL (signal_sensitivity) |

次点（Phase S で拾う）: test_human_anchor（人間ラベル選定方針）、test_check_recall_baseline（recall ゲート 6 分岐）、
test_intel_auto_judge（自動判定 4 規則）、test_password_hashing（argon2id lazy rehash）、test_wp_alarm.js。

## 4. カバレッジの穴 — テスト不在モジュール（Phase S の仕様化危険地帯）

D1 (D1-backend-core.md §1 / D1-sensors.md) と突合。**ここは仕様の根拠がコードのみ**になる。

### 4.1 バックエンドコア（重大な穴）

| モジュール | 行数 | 危険度メモ |
|---|---|---|
| `radar/climate.py` + `climate_state.py` | 1,026+8 | **Strategic Climate Engine が完全無テスト**。間接指標の式・閾値が全てコードのみ |
| `radar/routes/core.py` | 3,174 | **threat_data スコアリングループ（god）に専用テスト無し**。E2E 挙動は間接カバーのみ |
| `radar/database.py` | 6,629 | 専用テスト無し。migration v6/v11/v24/v33/v34/v41-42/v52-53 は機能テストで部分カバー、他は未検証 |
| `radar/scheduler.py` | 823 | chronic hook 3 test のみ。fetch ループ・cron 起動・cadence は無テスト |
| `radar/intel_corroboration.py` | 345 | 独立ソース LLM 照合合成が無テスト（tier3 auto-confirm の前提部品なのに） |
| `radar/llm_client.py` | 697 | 専用テスト無し（JSON 解析・リトライは test_llm_routing 経由の断片のみ） |
| `radar/config.py` / `config_layered.py` | 1,612/457 | 3 層 config 解決の優先順位が無テスト |
| `radar/ws.py` | 154 | WS プロトコル（subscribe_theater 等）無テスト |
| `radar/__init__.py` (app factory) / `state.py` / `models.py` / `persistence.py` / `plugin_loader.py` / `audit_middleware.py` | ~1,000 計 | 起動配線・in-mem cache・監査 decorator いずれも無テスト |
| `radar/calibration/auto_feedback_etl.py` | 167 | 無テスト |
| `radar/calibration/scenario_improver.py` | 770 | seam (`_emit`) のみテスト。**提案生成ルール本体は未検証** |
| `radar/routes/` admin.py / intel.py / analytics.py / climate.py / static.py | ~2,900 計 | 167 endpoint 中、上記 5 モジュールの契約が無テスト（intel.py は機能テストで部分間接） |

### 4.2 センサー層（39 ファイル中、直接テストがあるのは 13）

テストあり: ct_log 系 (4)、ooni、greynoise（GNQL 縮退のみ）、rss_narrative（geo filter のみ）、
ihr / ripe_atlas / tor_metrics（test_engine 内クラス）、apt_intel（prompt dedup のみ）、bg_observer（委譲先経由）、base.py（CB は test_engine）。

**無テスト 26 センサー**: cloudflare, bgp_routing, threatfox, opensky, opensky_auth, isr_hotspot,
mil_support_air, ais_maritime, gps_jamming, notam(無効化中), nasa_firms, openweather, usgs_seismic,
space_weather, peeringdb, ioda, checkhost, gdelt, telegram, travel_advisory, diplomatic,
military_exercise, hacktivist_intel, hacktivist_news, ground_osint, convergence_tracker。

特に危険: **bgp_routing**（HOD Z-score z<−2.0 + drop_ratio フォールバック）、**checkhost**（成功率閾値 + 深夜保守帯除外）、
**telegram**（in-mem 30 日 Z-score）、**convergence_tracker**（≥3 センサー×≥6h 昇格規則）、**gdelt**（DOW トーンベースライン）
— いずれも検知閾値を持つのにテストが無く、D5 の「仕様の宝」からも漏れている。Phase S ではコード読解のみが根拠になる。

### 4.3 フロントエンド

`radar.js` 14,819 行のうちテストがあるのは切り出し済み pure module 6 個（§2.1 js）のみ。
モノリス側の描画・状態管理・fetch オーバーライド（JWT 注入）は無テスト。

---

*生成: Phase D 調査 D5（2026-08-03）。数値は `grep -c "def test_"` / `wc -l` 実測。*

---

## 訂正（2026-08-04、S1-conclusions 執筆時に判明）

本台帳の「PER_DOMAIN / TREND / ATTACK_MODE の実閾値はテストのみが保持する」という記載は**誤り**。

1. **テストは値を pin していない**: 当該テスト群は閾値を**モジュール定数として import し、
   定数に対する相対比較で境界を検証**している。したがって定数値を変更してもテストは全通過する
   （例: `CYBER_DDOS_FLOOR` を 0.1 に変えても 26 件全通過）。**値の唯一の所在はコード定数**である
2. **本台帳に記録した値自体も古い**（実測 2026-08-04）:

| 対象 | 本台帳の記載 | 実装の実値 | 設計文書の記載 |
|---|---|---|---|
| PER_DOMAIN | 3.0 / 1.5 / 1.5 | **ACTIVE_FLOOR=2.5 / ELEVATED_FLOOR=1.5**（per_domain.py:51-52） | — |
| ATTACK_MODE | 5.0 / 1.5 / 3.0 / 1.5 | **1.2 / 0.8 / 1.0 / 0.8**（attack_mode.py:50-53） | 5.0 / 1.5 / 3.0 / 1.5（**2026-05-10 の再較正が未反映**） |

**含意**: 「テストが実行可能な仕様書である」という D5 の中心前提は、**定数を import して相対検証する
テストには当てはまらない**。v3 のテスト移植方針（S5）では、**閾値そのものを pin するテストと
相対検証のテストを区別し、前者を明示的に用意する MUST**。これは D2 E-18（記述ドリフト）と同根で、
ATTACK_MODE は設計文書と実装が 4 倍以上乖離している。

## 訂正 2（2026-08-09、v3 shadow の初起動で判明）— スイートは実マルチスレッドを検証できない

root `conftest.py` が **pytest セッション全体に `gevent.monkey.patch_all()` を適用**している（v1 互換のため）。
その帰結として `threading.Thread` は**グリーンレットを生み、実 OS スレッドを生まない**。全グリーンレットは
1 本の OS スレッドを共有するので、**C レベルのスレッド同一性を見る検査は一度も発火しない**。

**実害（実測）**: `LedgerStore._read_connection()` は読み取り接続を 1 本キャッシュしており、SQLite の
`check_same_thread=True` により**作成元スレッド以外からは使えない**。v3 の合成ルートは tick スレッドと
HTTP ワーカースレッドを持つため、shadow コンテナは起動直後に全リクエストが
`sqlite3.ProgrammingError` で落ちた。**この時点でスイートは 7,399 件緑**だった。

さらに悪いのは、この欠陥に対する回帰テストを `threading.Thread` で書くと**修正前も後も通る**ことである
（実測。偽陰性）。捕まえたのは「**修正前に落ちることを確認せよ**」という手続き要求だけであり、
テスト自体は無力だった。

**含意**: 「テストが実行可能な仕様書である」という D5 の中心前提は、**並行性に関する仕様には
当てはまらない**。スイートの構造上、スレッド安全性を主張するテストは**主張しているつもりで
単一スレッドを走らせている**。したがって:

- v3 で並行性を検証するテストは `gevent.get_hub().threadpool`（monkey-patch 下でも実 OS スレッドを
  得る gevent 自身の機構）を使う **MUST**。`Dockerfile.v3` は gunicorn `-k gthread` で gevent パッチを
  当てないため、これが実配備の形と一致する
- **v3 の他のスレッド前提はすべて未検証**である。`_read_connection` は起動して初めて露見した 1 件目に
  すぎず、同族が残っている可能性を前提に扱うこと
- これは D2 F-13（定数を import する相対検証テストは値の変更を検出しない）と同根 — **テストが
  検証していると称している対象を、実際には検証していない**族である
