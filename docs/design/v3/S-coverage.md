# S — 仕様カバレッジ表（Phase S 出口ゲート）

作成: 2026-08-04。原則 R5（網羅性の証明）の実行文書。
**出口条件**: D1 の全モジュールが「仕様化済み」または「理由付き除外」であり、
D5 の BEHAVIOR / CONTRACT 級テストが全件いずれかの仕様書に登場すること。

## 1. 仕様書一覧と規模

| 文書 | 条項数 | 行数 | スコープ |
|---|---:|---:|---|
| [S0-spec-conventions.md](S0-spec-conventions.md) | — | 53 | 条項フォーマット規約（全仕様書の上位規範） |
| [S1-scoring-core.md](S1-scoring-core.md) | 44 | 515 | 収斂数式・TL 導出・dedup・重み付け・CB 契約 |
| [S1-scoring-pipeline.md](S1-scoring-pipeline.md) | 47 | 538 | 採点ティックの順序・ゲーティング・scheduler 34 ジョブ |
| [S1-sensors-cyber-physical.md](S1-sensors-cyber-physical.md) | 56 | 600 | BaseSensor 契約 + Cyber 7 + Physical 15 |
| [S1-sensors-info-llm.md](S1-sensors-info-llm.md) | 74 | 599 | Information 6 + LLM 6 + メタ + 共通取得基盤 |
| [S1-intel.md](S1-intel.md) | 41 | 550 | インテルキュー・auto-judge・LLM 基盤・ルーティング |
| [S1-conclusions.md](S1-conclusions.md) | 45 | 709 | 全結論型の導出・envelope・台帳・replay・self_eval |
| [S1-calibration.md](S1-calibration.md) | 68 | 800 | ラベル生成・閾値較正・提案系・tier governor |
| [S1-services.md](S1-services.md) | 43 | 500 | 認証・WS・通知・AP1 attention・AP4 decisions |
| [S1-frontend-behavior.md](S1-frontend-behavior.md) | 72 | 655 | HUD・TRIAGE・ドリルダウン・Replay・地図・SETTINGS |
| S1-analytics-config.md | 進行中 | — | climate・BG observer・analytics 17 endpoint・config 3 層解決 |
| [S2-api-contract.md](S2-api-contract.md) | 52 (+21 PROPOSAL) | 747 | REST 167 + WS 10 の契約 + v3 契約提案 |
| [S3-data-migration.md](S3-data-migration.md) | 39 | 653 | 移行 35 表・ETL 受け入れ条件 5・retention |
| [S4-nonfunctional.md](S4-nonfunctional.md) | 67 | 596 | 耐障害・セキュリティ・i18n・UI 契約・運用 |
| [S5-verification.md](S5-verification.md) | 66 | 667 | パリティ・沈黙失敗監視・系譜監査・cutover 19 条件 |
| **計** | **714** | **8,182** | |

## 2. D1 モジュールカバレッジ

| D1 領域 | ファイル数 | 担当仕様書 | 状態 |
|---|---:|---|---|
| radar/ 採点コア（engine, scoring, scenarios） | 4 | S1-scoring-core / -pipeline | ✅ |
| radar/routes/core.py（採点ティック） | 1 | S1-scoring-pipeline | ✅ |
| radar/scheduler.py, state.py | 2 | S1-scoring-pipeline | ✅ |
| radar/sensors/（41） | 41 | S1-sensors-cyber-physical / -info-llm | ✅ |
| radar/intel_*.py, llm_*.py（8） | 8 | S1-intel | ✅ |
| radar/conclusions/（21） | 21 | S1-conclusions（ground_truth_etl は S1-calibration） | ✅ |
| radar/calibration/（18） | 18 | S1-calibration | ✅ |
| radar/auth.py, ws.py, notifications.py, attention*.py, triage.py, decisions.py, audit_middleware.py | 8 | S1-services | ✅ |
| radar/climate*.py, background_observer.py, observability/, analytics/, routes/analytics.py | 8 | S1-analytics-config | ⏳ 進行中 |
| radar/config.py, config_layered.py | 2 | S1-analytics-config | ⏳ 進行中 |
| radar/routes/（22 の API 面） | 22 | S2-api-contract | ✅ |
| radar/database.py, persistence.py, migration.py | 3 | S3-data-migration | ✅ |
| フロントエンド（16） | 16 | S1-frontend-behavior（i18n/クローム契約は S4） | ✅ |
| scripts/（27） | 27 | D6 付録で分類済（keep 15 / port 3 / retire 9）。挙動仕様は S5（検証系）が担当 | ✅ |
| **理由付き除外** | | | |
| radar_api.py, radar/__init__.py, plugin_loader.py | 3 | — | 除外: 起動・配線のみ。v3 では構造が変わるため仕様化に意味がない |
| radar/models.py | 1 | 各仕様書のデータ形状記述に吸収 | 除外 |
| radar/migration.py（JSON→SQLite 一回きり） | 1 | — | 除外: D3 で discard 判定済 |
| radar/diagnostics.py | 1 | S1-analytics-config | ⏳ |

**未仕様化ゼロの達成見込み**: S1-analytics-config の完了をもって全モジュールがカバーされる。

## 3. テスト → 仕様トレーサビリティ

D5 分類（107 ファイル / 1,939 テスト）に対する対応状況:

| D5 分類 | ファイル数 | 対応状況 |
|---|---:|---|
| BEHAVIOR（挙動仕様級） | 66 | 各仕様書の §6 トレーサビリティ表に対応付け済。**対応条項の無いテストは 0 件**（S1-conclusions が 20 ファイル 338 件、S1-scoring-core が 2 ファイル 222 件を全件対応と報告） |
| CONTRACT（API 契約級） | 17 | S2-api-contract §6 に対応付け |
| STRUCTURAL（構造依存） | 19 | v3 で書き直し。**仕様の根拠には使わない**（S5 のテスト移植計画で扱う） |
| SCAFFOLD（足場・回帰） | 5 | v3 に持ち込まない |

### 逆方向 GAP（条項はあるが検証が無い）

各仕様書の §6 に記録。集計:

| 仕様書 | GAP 数 | 特筆 |
|---|---:|---|
| S1-scoring-core | 3 | ambush 発火閾値、境界値（`>=` か `>` か） |
| S1-scoring-pipeline | 12 | ゲーティング真理値表が全面無テスト、force 経路無テスト（→ F-02 の温床） |
| S1-sensors-cyber-physical | 12 | **22 基中 17 基がテスト 0 件**、抑制系 3 基の消費側意味論が無検証 |
| S1-sensors-info-llm | 8 | — |
| S1-intel | 8 | — |
| S1-conclusions | 7 | — |
| S1-calibration | 13 | — |
| S1-services | 8 | **ws.py と audit_middleware.py がテスト 0 件**（認証境界で唯一の無検証面） |
| S1-frontend-behavior | 61 条項が未検証（85%） | radar.js カバレッジ 0% の帰結 |
| S2-api-contract | — | `/api/v2/replay` に HTTP テスト 0 件、config registry 98 キーの契約が実装のみ |
| S3-data-migration | 5 | 移行 ETL 未実装、database.py に専用テスト 0 件 |
| S4-nonfunctional | 8 | — |
| S5-verification | — | 並走装置が全て新規実装 |

**この GAP 群がそのまま S5 のテスト整備計画の入力になる。**

## 4. ACCIDENTAL / オーナー裁定待ち

各仕様書の §4 に記録。合計 **約 100 件**。特に判断が重いもの:

| # | 論点 | 出典 |
|---|---|---|
| 1 | **TL1（最重要結論）がドメイン数を要求しない** — TL2 は 2 ドメイン必須なのに上位の TL1 は単一ドメインで発火。NP2 と逆転 | S1-scoring-core A6 |
| 2 | **空ドメインの信頼度が既定 1.0**（観測ゼロを「完全に信頼」と表現）、**Blockade Index が CheckHost 欠測を健全扱い** — いずれも NP1 に反する fail-open | S1-scoring-core A2/A3 |
| 3 | **結論不可 4 種のうち 3 種に生成経路が無く、全て `insufficient_data` に潰れている** — NP5+8 の中核が実質失われている | S1-conclusions A1 |
| 4 | **FN 1 件が全世界の recall-negative 提案を止める**（国フィルタ無しのグローバル集計） | S1-calibration / D2 E-02 |
| 5 | **What-If が 2 系統ある**（純クライアント側と、ヘッダでサーバ採点に反映される側）。同じ語で異なる意味 | S1-frontend-behavior §7-4 |
| 6 | **HUD Row 3 のチップは 12 種で、境界値は全てフロントのハードコード** | S1-frontend-behavior A4 |
| 7 | tradecraft スタックの処遇、UNREFERENCED 8 の drop、retention 365d 化、v1 API sunset | D3 §3 |
| 8 | 移行 35 表のうち 17 表に retention が無い | S3-DATA-044 |

## 5. 出口判定

| 条件 | 状態 |
|---|---|
| D1 全モジュールが仕様化済 or 理由付き除外 | ⏳ S1-analytics-config の完了待ち（他は達成） |
| BEHAVIOR / CONTRACT テストが全件いずれかの仕様書に登場 | ✅ 達成（対応条項の無いテスト 0 件） |
| GAP と ACCIDENTAL が裁定リストに集約 | ✅ 達成（本書 §3・§4） |

**Phase S は S1-analytics-config の着地をもって完了とする。**
