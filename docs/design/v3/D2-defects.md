# D2 — 欠陥リスト（Phase D 診断）

編纂: 2026-08-03。証拠源: D1 三領域調査（file:line 引用）、git 共変更実測（[_drafts/D2-cochange-raw.md](_drafts/D2-cochange-raw.md)）、
インシデント記録（calibration #1〜#3、移行足場 teardown）。
重大度は code-review 標準（CRITICAL / HIGH / MEDIUM / LOW）。

**「書き直しで直るか」列の凡例**:
- ◎ = 設計で構造的に解消（v3 の設計要件になる）
- ○ = 設計で解消するが、規律がなければ再発する（P で防止機構を設計する）
- × = **アーキテクチャでは直らない**（プロセス/検証系で対処。リビルドへの過剰期待を防ぐ行）

## A. 構造欠陥（アーキテクチャ起因）

| ID | 欠陥 | 重大度 | 証拠 | 影響原則 | 直るか |
|----|------|--------|------|----------|--------|
| A-01 | **GET 副作用スコアリング**: `get_threat_data` 単一関数 2,665 行が センサー読出→ゲーティング→収斂→sequence 登録→conclusions→WS emit→cache 書込を GET ハンドラ内で駆動。polling 遺構 | **CRITICAL** | routes/core.py:509-3173、add_rat は L923 の closure | NP6（導出の追跡性）、NP3 | ◎ v3 本丸: scheduler 駆動採点 + 読み取り専用 API |
| A-02 | **横断関心のコピペドリフト**: RSS 取得/パース 4-5 複製（tolerant パーサは diplomatic のみ）、LLM 投入骨格 8 複製（max_tokens 200-400 ばらつき）、HOD Z-score ×2、30 日 Z-score ×2、フロント整形系 3-4 複製、engine/scoring の式重複 | **HIGH** | D1-sensors §2、D1-frontend §5.3、scoring.py L1060 自認、共変更 Jaccard 0.77 (diplomatic↔military_exercise) | NP2（入力品質不均一）、NP1、AP2/AP3 一貫性 | ○ 共有基盤（ingestion kit / LLM 投入パイプライン / UI util）へ昇格。**昇格規律がないと再発** |
| A-03 | **ベースライン永続戦略の不統一**: DB 永続（hod_/gdelt_dow_/ct_log_）と in-mem 揮発（bgp_routing、telegram、ooni、rss_narrative）が混在。再起動で Z-score 系の検知力が数日低下 | **HIGH** | D1-sensors §1 ベースライン列・§3 | **NP1 直撃** | ◎ ベースライン基盤の一元化（v3 設計要件） |
| A-04 | **database.py god-module**: RadarDB 約 170 メソッド 6,629 行に全ドメインの永続化が同居。約 30 モジュールが同一 god-object に依存 | HIGH | database.py、D1-backend-core §2 ハブ・§3c | 保守性（変更影響が全域） | ◎ 9 repository 分割線は実測済（D1-backend-core §3c） |
| A-05 | **routes の service-locator 化**: routes/__init__ が registry/engine の注入点を兼務し、calibration/attention が `_routes.registry._sensors` を private 参照。sensor_disable_proposer は `sensor.enabled=False` を直接書換 | HIGH | routes/__init__.py:24-32、attention.py:205、sensor_disable_proposer.py:118,290 | NP3（状態変更の追跡不能） | ◎ registry の独立昇格 + 公開 API 化 |
| A-06 | **循環 import の常態化**: 遅延 import 270 箇所（全 457 の 59%）、`import radar.routes as _routes` 遅延バインド 8 箇所、climate_state.py のような回避専用モジュール | HIGH | D1-backend-core §2 | 保守性・初期化順序の脆さ | ◎ レイヤー方向の強制（P で依存規則を定義） |
| A-07 | **radar.js モノリス**: 14,833 行 IIFE なし、top-level 関数 312 個全 window 化、window 代入 137、onclick 直書き 136。フロント 4 ファイルの共変更 Jaccard 0.21-0.45 | **HIGH** | D1-frontend §3、共変更実測 | 保守性（全機能追加が 4 ファイルに波及） | ◎ モジュール化 + 型付き API クライアント |
| A-08 | **フロントのテスト不能構造**: radar.js 本体カバレッジ 0%。テスト可能なのは抽出済み pure module 6 本のみ | HIGH | D1-frontend §1.2, §5.8 | 品質保証全般 | ◎ 全モジュールを pure-core + 薄い DOM 層で設計 |
| A-09 | **第 2 SQLite**: convergence_tracker が radar.database 管轄外の convergence_snapshots.db を自前保有 + intel ledger 直接読取。バックアップ/WAL/スキーマ管理の盲点 | HIGH | convergence_tracker.py:54-107, 265-287 | NP3、データ保全 | ◎ 永続層の単一管轄（メタセンサーの層所属を P で定義） |
| A-10 | **基底ヘルパー全面未採用**: `_safe_get`/`_safe_post`/`handle_rate_limit` の呼出ゼロ。全 28 fetch 実装が raw requests。timeout 指定漏れは gevent ループ閉塞リスク | HIGH | base.py:173-225 vs 全センサー、D1-sensors §5-1 | NP3（可用性） | ○ ingestion kit で構造化。「基底に足すだけ」では再発済みの実績あり |
| A-11 | **HUD チップのポーリング分散**: 6 本が個別 setInterval + 個別 fetch（30min〜60s）。集約フェッチ層なし | MEDIUM | D1-frontend §4.3 | 効率・一貫性 | ◎ データ同期層の一元化 |
| A-12 | **conclusions_v2.py の hub 化**: v2 route 10 モジュールが共有 helper に横依存 | MEDIUM | D1-backend-core §2 | 保守性 | ◎ |
| A-13 | **config の肥大**: config.py 1,612 行（env + 全閾値 + registry）に 3 層解決（config_layered）が別置 | MEDIUM | config.py、config_layered.py | NP6（閾値の所在） | ◎ 宣言的 registry へ統合 |
| A-14 | **INTEL GUIDE の物理同居**: ガイド Ch.1-14 が index.html 内にあり、バックエンド変更→ガイド更新義務→index.html 共変更 223 回の一因 | MEDIUM | index.html、共変更実測 top1 | 保守性 | ◎ ガイドの分離配信 |
| A-15 | **fetch_log 二重記録回避の暗黙協調**: `_from_log_fetch` フラグに依存する脆い契約 | LOW | base.py:43-61 | 保守性 | ◎ |

## B. 実装欠陥（現役バグ / 劣化の沈黙）

| ID | 欠陥 | 重大度 | 証拠 | 影響原則 | 直るか |
|----|------|--------|------|----------|--------|
| B-01 | **bg_observer の CB 不活性**: 自前 daemon thread が cb_should_skip/cb_record_* を経由せず、docstring（CB 統合維持）と乖離。RSS 障害が続いても抑制がかからない | **HIGH** | bg_observer.py:47-51,144-155 vs scheduler.py:122-145 | **NP3 直撃** | ◎ + **Phase D 完了後に現行系でも修正**（v3 を待たない） |
| B-02 | **`window.showToast` 全コードベース未定義**: controls_panel/autotune_wizard が参照、通知が silent no-op / alert() fallback に落ちる | HIGH | controls_panel.js:562、autotune_wizard.js:370、rg "toast" 0 件 | AP2（操作結果の可視性） | ◎ + 現行系でも修正候補 |
| B-03 | **ground_osint の STALE 無視**: 相手センサー cache の鮮度/健全性を確認せず相関判定。劣化が沈黙 | MEDIUM | ground_osint_sensor.py:67-104 | NP2（収斂の入力品質） | ◎ クロスセンサー参照の公式化 |
| B-04 | **mutable module-global の並存**: `_LATEST_SIGNALS_SNAPSHOT`（routes/core.py）と `state.global_cache` が並存、lock 規律は state.py 側のみ | MEDIUM | routes/core.py 定数欄、state.py | 競合リスク | ◎ |
| B-05 | **再起動で消える運用状態**: convergence_tracker の `_alerted` クールダウン dict、rss_narrative の dedup 集合 → 再起動直後の重複アラート/重複投入 | MEDIUM | convergence_tracker.py:50、rss_narrative.py:59 | アナリスト信頼 | ◎ |
| B-06 | **localStorage キーの生リテラル迂回**: `_alLoadState`/`_AL_STORAGE_KEY` を迂回する生読み 1 箇所。キー変更時に追従漏れ | LOW | radar.js:8695 vs 5946 | 保守性 | ◎ |
| B-07 | **ws.py の dead param**: `emit_intel_update(theater,…)` の theater 引数未使用 | LOW | ws.py:154 | — | ◎ |
| B-08 | **テストが本番 DB へ直書きできる**: tests が singleton `db` import 経由で稼働 DB に書込み。tradecraft 全表の行数が「82 回のテスト実行 × 固定件数」と完全一致（164=82×2、246=82×3、984=82×12）。decision_ledger 984 行は全量テスト残骸 | **HIGH** | tests/test_analyst_permissions.py、D4-data-assets.md 疑問 1/3 | データ保全・較正データの純度 | ◎ v3: repository 層への接続注入を強制し、テストは構造的に隔離 DB のみ + **現行系でも即修正推奨** |
| B-09 | **UI 参照が消失した endpoint**: `GET/PUT /api/auth/settings` と `GET/PUT /api/v2/decisions/threshold` が GUIDE+TEST のみで UI から不達（設定 UI のリグレッション疑い） | MEDIUM | D6-api-surface.md 副次発見 | 操作可用性 | 要調査（現行系）。v3 では S2 契約で明示裁定 |

## C. 負債・残滓（休眠足場 / 旧語彙 / dead code）

**先例**: 移行足場 teardown インシデント（2026-05-30）— 足場の残置は「無害な塵」ではなく prod を黙って劣化させた実績がある。

| ID | 欠陥 | 重大度 | 証拠 | 直るか |
|----|------|--------|------|--------|
| C-01 | **theater 旧用語の広範残存**: database.py 全域の引数名 / **WS プロトコル**（`subscribe_theater`、`theater:` room）/ intel_queue 互換パス / scenarios.py 互換キー / radar.js 60 箇所 / センサー層変数・DB キー | MEDIUM（ただし WS 境界は契約債務） | D1 各冊 | ◎ v3 語彙は country/scenario で統一（S2/S3 で契約から排除） |
| C-02 | **tradecraft フルスタック休眠**: 25 endpoint + tradecraft_repo（DB メソッド群）+ tradecraft.js 1,016 行 + 空テーブル群。統合は 2026-04-30 棚上げ済 | MEDIUM | routes/analyst.py、D4 素材空テーブル、MEMORY | **オーナー判断事項**（D3 §3 参照）: v3 に持ち込むか凍結アーカイブか |
| C-03 | **移行足場の残置**: V2_API_ENABLED（常時 true の gate 13 箇所）、migration.py（dormant）、shadow_metrics.py、v1_sunset_audit.py、audit_middleware.py | MEDIUM | D1-backend-core §3d | ◎ v3 に持ち込まない。現行系でも C-03 は撤去可能 |
| C-04 | **DDoS 時代レガシー UI が現役パスに混在**: fetchDDoSData（心臓部の旧名）、L3/L7 vector UI、GreyNoise/TG SIGINT/CheckHost Survival/Maskirovka パネル約 900 行、blockade チップ | MEDIUM | D1-frontend §5.4 | ◎ v3 で廃棄（D3 判定表） |
| C-05 | **確認済み dead code**: switchMapCenter、toggleContent、legacy shim 3 本、tradecraft の不達 fallback、llm_client.py.bak、ddos_radar_triage_state 移行 shim | LOW | D1-frontend §5.5、D1-backend-core §1 | ◎ |
| C-06 | **i18n バイパス**: TIER_LABELS 直書き、login-init エラー文言、controls_panel トースト文言（CI 監査網の外） | LOW | D1-frontend §5.6 | ◎ v3 は全 UI 文字列を辞書経由で設計 |
| C-07 | **命名の誤誘導**: `HacktiivistIntelSensor` typo（公開名まで伝播）、nasa_firms の実ソースは EONET | LOW（NP6 上は MEDIUM） | hacktivist_intel_sensor.py:43、nasa_firms.py:11-28 | ◎ |
| C-08 | **配置違和感**: acled.py（sensors 内の孤立モジュール、実利用は GT ETL）、rss_extractor.py（conclusions 配下）、auth.py の endpoint 同居 | LOW | D1 各所 | ◎ |

## D. アーキテクチャでは直らない欠陥（× 行 — リビルド過剰期待の防波堤)

| ID | 欠陥 | 重大度 | 証拠 | 対処 |
|----|------|--------|------|------|
| D-01 | **ラベル生成器のバグ類**: calibration インシデント #1〜#3 はすべて測定系（blanket-TP / TL 反転 / 帰属汚染）のロジックバグ。全テスト通過のまま数週間 prod を劣化させた。**構造をどう変えてもこのクラスは再発しうる** | **CRITICAL**（過去実績） | メモリ: calibration-degenerate、be12bd8 ほか | × 検証系で対処: S5 でラベル系譜（lineage）の常時監査・反事実チェック（「平穏期に FN が湧いたら生成器を疑う」）を**仕様として**設計。AP3 human-anchor の独立レグ維持 |
| D-02 | **外部 API の脆さ**: ソース側の廃止・仕様変更・ブロック（IHR 400、CISA URL rot、ThreatFox 認証化、NOTAM API 消滅…）は v3 でも起き続ける | HIGH（恒常） | D1-sensors §4 | × 対処は設計でなく運用容易性: ソース死活の可視化（既にある）+ 差し替え容易な ingestion kit（A-02 の副産物） |
| D-03 | **単独運用の錬度依存**: TL 直接比較禁止（severity=6−TL）のような「知っていないと壊す」規約は構造では強制しきれない | MEDIUM | 反転事故 2 回 | × 型で表現できるものは型へ（P で SeverityScale 型等を検討）、残りは検証ゲート |

## 統計

- 総数 35 件: CRITICAL 2 / HIGH 13 / MEDIUM 14 / LOW 6
- 「◎ 設計で構造的に解消」26 / 「○ 規律併用」2 / 「× 構造では直らない」3 / オーナー判断 1 /
  現行系でも即修正推奨 4（B-01, B-02, B-08, C-03 の一部）+ 要調査 1（B-09）
