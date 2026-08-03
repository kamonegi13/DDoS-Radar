# D1 — モジュールインベントリ統合版（Phase D 診断）

調査: 2026-08-03、並列調査 3 系統 + 親セッション素材の統合。
詳細は領域別ドキュメントへ（本書は横断所見とカバレッジ検証のみ）:

- [D1-backend-core.md](D1-backend-core.md) — バックエンドコア 100 ファイル / 約 47,500 行（インベントリ表・依存エッジ 457・レイヤー違反・REST 167 endpoint 全列挙）
- [D1-sensors.md](D1-sensors.md) — センサー層 41 ファイル / 9,718 行（34 センサー・契約適合度・外部 API 知識棚卸し）
- [D1-frontend.md](D1-frontend.md) — フロントエンド 16 ファイル / 30,440 行（radar.js 19 サブシステム分解・グローバル状態・fetch 契約 約 78 点）
- [D1-line-inventory.md](D1-line-inventory.md) — 行数・規模の生データ

## 1. カバレッジ検証（completeness oracle）

| 領域 | ファイル数 | 分類状態 |
|---|---:|---|
| radar/（sensors 除く全サブパッケージ含む） | 100 | ✅ D1-backend-core §1 で全分類 |
| radar/sensors/（ct_log_sources/ 含む） | 41 | ✅ D1-sensors §1 で全分類 |
| フロントエンド（.js/.html/.css + JS テスト） | 16+6 | ✅ D1-frontend §1 で全分類 |
| tests/*.py | 101 | ⏳ **D5 で分類**（設計どおり後続） |
| scripts/（.py 21 + .sh 6） | 27 | ⚠️ **未分類 — D1 残ギャップ**。次セッションで分類（ETL/replay/remediation/codemap 系。S5 検証仕様と D4 に直結するため省略不可） |
| plugins/ | 0（空ディレクトリ） | ✅ plugin_loader の休眠拡張点として記録のみ |
| 静的データ（geo_data.json / config.env.example / docker 系） | — | D4/S4 で扱う |

## 2. 横断所見（複数領域で独立に観測された病理）

### 2.1 支配的病理は「コピペドリフト」— 全 3 領域で独立に検出

横断関心が共有基盤に昇格されず、複製のたびに劣化している。

| 領域 | 複製 | 実害 |
|---|---|---|
| センサー | RSS 取得/パース 4〜5 系統（tolerant パーサは diplomatic のみ） | 同じ壊れた XML でセンサーごとに挙動が違う = NP2 の入力品質が不均一 |
| センサー | LLM intel 投入骨格 8 複製（max_tokens 200〜400 バラバラ） | 判定品質の較正が個別化、AP2/AP3 一貫性を損なう |
| センサー | HOD Z-score ×2、30 日 Z-score ×2（in-mem 揮発と DB 永続が混在） | 再起動でベースライン喪失 → 検知力低下 = **NP1 直撃** |
| コア | engine.py / scoring.py に velocity・回帰 slope 重複（scoring.py L1060 自認） | 修正が片系に入る危険 |
| フロント | 経過時間フォーマット×4、ts 整形×3、エスケープ×3、状態カラー×4 | UI 表現の不一致・修正漏れ |

git 共変更分析（[D2 素材](_drafts/D2-cochange-raw.md)）の diplomatic↔military_exercise Jaccard 0.77 はこの複製の直接実測。

### 2.2 god-module 3 点の分割線は既に自明

| 対象 | 実態 | 自然な分割 |
|---|---|---|
| database.py 6,629 行 | RadarDB 約 170 メソッド | prefix で 9 repository に機械的分割可（D1-backend-core §3c）。tradecraft 系は呼び出し元が routes/analyst.py 単独 = 最安全な第一切断線 |
| routes/core.py `get_threat_data` | **単一関数 2,665 行**（L509-3173） | GET ハンドラ内にセンサー読出→add_rat→収斂→sequence→conclusions→WS emit まで内包 |
| radar.js 14,833 行 | IIFE なし、top-level 関数 312 個が全て window 化 | codemap 110 セクション → 19 サブシステムに整理済（D1-frontend §2）。※現状の分解の証拠資料であり、新設計の境界はここからではなく目的から導出する（ADR-V3-003） |

### 2.3 最深のアーキテクチャ所見: GET 副作用スコアリング

`GET /api/threat_data` が採点・sequence event 登録・WS emit・cache 書込みという**書き込み副作用を駆動する**（polling 時代の遺構）。CLAUDE.md §5 の「スコアリング層 = routes/core.py」という規約自体が HTTP 層とスコアリングの癒着を追認している。**v3 の本丸は「scheduler 駆動の採点 + 読み取り専用 API」への転換**。

### 2.4 routes パッケージの service-locator 化

`radar/routes/__init__.py` が registry/engine のグローバル注入点を兼ね、routes 以外の層（attention.py:205、calibration/sensor_disable_proposer.py:118,290）まで `_routes.registry._sensors` を private 参照。後者は `sensor.enabled=False` を直接書換。遅延 import 270 箇所（全 import の 59%）は循環回避の常態化の証拠。修正方向: registry の独立モジュール昇格 + 公開 API 化。

### 2.5 永続層の管轄漏れ

- convergence_tracker が radar.database 管轄外の**第 2 SQLite**（convergence_snapshots.db）を自前保有 — バックアップ/WAL/スキーマ管理の盲点
- ベースライン永続戦略の不統一（DB 永続 vs in-mem 揮発）— §2.1 と同根
- D4 素材の空テーブル 13 件と突合: tradecraft 系（backend 25 endpoint + DB メソッド群 + tradecraft.js 1,016 行が**全部そろって休眠**）、shadow 系は移行足場残滓

### 2.6 rename 残滓の正確な残存箇所が確定

`theater`: database.py ほぼ全メソッド引数 + WS プロトコル（`subscribe_theater` イベント、`theater:` room）+ intel_queue 互換パス + scenarios.py 互換キー + radar.js 60 箇所 + センサー層変数/DB キー。**WS プロトコル境界が旧語のまま**なのが最も深い。

### 2.7 診断中に発見された現役バグ候補（D2 へ登録）

- `window.showToast` が全コードベース未定義（controls_panel.js:562 / autotune_wizard.js:370 が参照、通知が silent no-op / alert() fallback に落ちる）
- bg_observer のサーキットブレーカー実質不活性（自前 thread が cb_should_skip/cb_record_* を経由せず、docstring と乖離 = NP3）
- ground_osint が相手センサーの STALE/ERROR を確認せず相関判定（劣化が沈黙）

## 3. 良品の確認（v3 に引き継ぐ設計文化）

- **conclusions/ パッケージ**（21 ファイル、平均 246 行）: envelope 構築で NP7 強制、型別導出の分離 — v3 の粒度規範
- **pure module 6 本 + Node テスト**（triage_score / triage_display_mode / self_explanation / map_dim / wp_alarm / hud_v2_overlay）: そのまま移植可。「テスト可能な形に抽出する」パターンは既に成功している
- **BaseSensor の外形契約**: 34 センサー全てがオーバーライドなしで health/CB 骨格を共有（違反ゼロ）。問題は基底ヘルパーの未採用であって契約設計ではない
- **センサー層の外部 API 知識**（D1-sensors §4 の 20 項目）: リビルドで再発見コスト最大の資産。**コードでなく知識として移植する**
- i18n STRINGS 辞書 約 1,556 キー + CI 監査ゲート

## 4. 数値サマリと相互検証

| 指標 | 値 | 出典 |
|---|---:|---|
| REST endpoint 総数 | 167 | backend Grep 全数（ファイル別件数照合済） |
| うちフロントエンドが呼ぶもの | 約 78 | frontend fetch 全列挙 |
| **フロント未参照の API 面** | **約 89** | 差分。scripts/curl 運用・INTEL GUIDE 文書化 API・dead API の切り分けが **D2/D3 の宿題** |
| SocketIO | on 4 / emit 6 | 両側の突合一致（フロントは 6 emit 全購読 + connect 系 3） |
| 内部 import 文 | 457（遅延 59%） | backend |
| radar.js グローバル結合点 | window 代入 137 + onclick 直書き 136 + ファイル間共有 14 系統 | frontend |
| localStorage キー | 18 + sessionStorage 2 | frontend 全列挙 |

## 5. D1 残作業

1. scripts/ 27 ファイルの分類（次セッション冒頭、小規模）
2. フロント未参照 89 endpoint の用途切り分け（D2 と併合して実施）
3. D5（テスト資産分類 101 ファイル）は独立成果物として次セッション以降
