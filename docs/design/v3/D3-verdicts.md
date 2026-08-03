# D3 — keep / port / rewrite 判定表（Phase D 診断）

編纂: 2026-08-03。判定は **挙動とコードの処遇**であり、構造の設計ではない（ADR-V3-003:
構造は Phase P で目的から導出する。「port」でも実装は新構造に合わせて書き直されうる）。

**判定の定義**:
- **keep**: ファイル/資産をほぼそのまま v3 へ（変更は命名・配置程度)
- **port**: 挙動・ロジック・知識を移植する。実装は新構造に載せ替え
- **rewrite**: Phase S の仕様から新規実装（現行実装は参照しない。パリティゲートで挙動一致を検証)
- **discard**: v3 に持ち込まない
- **owner**: オーナー判断が必要（§3）

## 1. バックエンド

| モジュール | 判定 | 根拠 |
|---|---|---|
| センサー 34 基の fetch ロジック + 外部 API 知識 | **port** | D1-sensors §4 の 20 項目は再発見コスト最大の資産。ingestion kit（新設計）の上に載せ替え |
| sensors/base.py（BaseSensor） | **rewrite** | 外形契約（health/CB/confidence）は仕様として保存。ヘルパー未採用問題（A-10）は基底の再設計で解消 |
| メタセンサー（convergence_tracker / ground_osint / bg_observer） | **rewrite** | 層所属そのものが未定義だった（A-09, B-01, B-03）。P で「派生センサー」の座席を設計してから仕様移植 |
| engine.py + scoring.py | **rewrite**（統合） | 式の二重実装（A-02）。収斂数式・ゲート・C-lite 分岐は S1 仕様として完全保存し、単一のスコアリングコアへ |
| routes/core.py（get_threat_data） | **rewrite**（解体） | A-01。スコアリングは scheduler 駆動へ、API は読み取り専用へ。add_rat のゲーティング規則は S1 で仕様化 |
| conclusions/ パッケージ | **port** | 粒度・設計文化ともに v3 規範（D1-inventory §3）。envelope/NP7 強制/型別導出は現設計を踏襲 |
| calibration/ パッケージ | **port** | インシデント #1-#3 を生き延びた較正機構。ガード群（direction-keyed 鮮度ゲート等）は挙動を厳密保存 |
| ground_truth_etl / human_anchor | **port** + 強化 | D2 D-01: ラベル系譜監査を S5 で仕様追加 |
| intel_queue / auto_judge / corroboration | **port** | dedup・decay・状態機械の挙動は保存。LLM 投入の共有パイプライン化（A-02）で呼び出し側を再設計 |
| llm_client / llm_routing / llm_features / llm_embedding / llm_prompts | **port** | SHADOW_DUAL 状態機械・kill switch・NP6 プロンプト永続化は現役の良設計 |
| database.py | **rewrite**（分割） | A-04。スキーマは S3 で移行マップ化、repository 分割線は実測済（D1-backend-core §3c） |
| auth.py | **port** | JWT + refresh + 役割管理は実証済み。endpoint 分離（C-08）と role クレーム化のみ改善 |
| ws.py | **rewrite** | プロトコル語彙が theater のまま（C-01 の最深部）。イベント意味論は S2 で仕様化し、v3 プロトコルは country/scenario 語彙で再定義 |
| scheduler.py | **rewrite** | v3 では採点パイプラインのオーナーに昇格する（A-01 の帰結）。cron 的ジョブ一覧は S1 で仕様化 |
| config.py + config_layered.py | **port**（統合） | 3 層解決と宣言的 registry は良設計。閾値カタログは S1 の一部として全数仕様化 |
| attention / triage / decisions / notifications / climate / analytics/ | **port** | AP1/AP4 の中核。attention の routes 依存（A-05）だけ新構造で解消 |
| state.py / audit_middleware / migration.py / shadow_metrics / v1_sunset_audit / llm_client.py.bak | **discard** | 移行足場・遺構（C-03, C-05）。state の機能は新データ同期層が吸収 |
| routes/ 全 22 ファイル | **rewrite** | API 面は D6 の用途分類に基づき S2 で再契約（UNREFERENCED は原則 drop） |

## 2. フロントエンド

| 資産 | 判定 | 根拠 |
|---|---|---|
| pure module 6 本（triage_score / triage_display_mode / self_explanation / map_dim / wp_alarm / hud_v2_overlay）+ Node テスト | **keep** | 抽出済み・テスト済み・依存ゼロ（D1-frontend §1） |
| i18n.js STRINGS 辞書（約 1,556 キー） | **keep**（剪定） | 未使用 472 キーは v3 契約確定後に剪定。CI 監査ゲートも keep |
| radar.js / index.html / radar.css | **rewrite** | A-07/A-08。保存するのは挙動（HUD 意味論、TRIAGE フロー、NP6 ドリルダウン、Replay UI）で S1-frontend として仕様化 |
| auth-fetch ラッパ（JWT 注入 / 401 リフレッシュ） | **port** | 実証済みフロー。実装は新 API クライアントへ |
| SETTINGS の registry 駆動レンダラ | **port**（概念） | 宣言的 UI 生成の考え方は良い。2,900 行の実装は仕様から再実装 |
| パネルクローム契約（panel-chrome.md） | **keep**（契約として） | 契約は正しく、違反実装（A-13）だけが問題。v3 は factory 一本化を構造で強制 |
| DDoS レガシーパネル群 / L3-L7 vector UI / blockade チップ / legacy shim | **discard** | C-04, C-05 |
| tradecraft.js + tradecraft.css | **owner** | §3-1 |
| INTEL GUIDE Ch.1-14（コンテンツ） | **port** | 内容は資産。配置は index.html から分離（A-14） |

## 3. オーナー判断事項（D 出口ゲートで裁定を仰ぐ）

| # | 論点 | 選択肢と推奨 |
|---|---|---|
| 1 | **tradecraft スタックの処遇**（C-02。25 endpoint + DB + JS 1,016 行、2026-04-30 棚上げ済） | (a) v3 に持ち込まない **← 推奨（D4 で根拠強化: 実データは全量テスト残骸 = 82 回のテスト実行と一致。export 保全の必要すら無い）**。(b) 凍結のまま移植。トリガー条件成立時に v3 上で再実装する方が、空機能を運ぶより安い |
| 2 | **UNREFERENCED endpoint の扱い** | D6 で 8 件確定、curl 暗黙契約の可能性も否定済み → **全 drop 推奨で決着可能** |
| 3 | **conclusions retention**（現 90d、365d 化は 2026-10 予定だった） | v3 スキーマ設計（S3）に 365d を織り込むか、移行時に同時変更するか。**移行時に 365d 化を推奨**（二度手間回避） |
| 4 | **v1 API の sunset**（V2_API_ENABLED 撤去含む） | v3 cutover と同時に v1 契約を終了し、フロントも v3 契約のみ参照 **← 推奨**（ADR-V2-003 の 90 日 sunset は v2 内の話。v3 では境界を 1 本化） |

## 4. 集計

- バックエンド: keep 0 / port 11 群 / rewrite 7 群 / discard 6 / owner 0
- フロントエンド: keep 3 / port 4 / rewrite 1（本体） / discard 2 群 / owner 1
- **rewrite 対象の行数概算**: バックエンド約 13k 行（core/engine/scoring/database/routes/ws/scheduler/base）+ フロント約 23k 行（radar.js/index.html/radar.css）
- **port 対象**: 約 20k 行相当の挙動（実装は載せ替えでも、挙動は S でトレース可能に保存）
- scripts/: **keep 15 / port 3（ETL 2 + smoke）/ retire 9**（remediation 一回きり・移行足場・実施済バックテスト。内訳は D6-api-surface.md 付録）
