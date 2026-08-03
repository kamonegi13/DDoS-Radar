# S1 — LLM インテルパイプライン 挙動仕様

**スコープ**: センサーがインテル候補をキューへ投入した瞬間から、重複排除 → 自動確認判定 →
アナリスト/自動判定による状態遷移 → 採点層へのスコア寄与 → 経年減衰 → 消滅 までの全ライフサイクル、
および その基盤となる LLM 呼出し層（呼出し契約 / JSON 解析防御 / モデルルーティング /
Feature Hub / embedding / プロンプト永続化）。

**隣接仕様との境界**:
- センサーが何を観測し、どのテキストを LLM に渡すか → **S1-sensors-\*** 担当（本書は投入以降）
- 寄与が入った後のドメイン集計・収斂・TL 導出 → **S1-scoring-core**（[S1-scoring-core.md](S1-scoring-core.md)）担当
- conclusions / calibration / recall 指標での LLM 由来寄与の扱い → **S1-conclusions / S1-calibration** 担当
- インテル閲覧・判定 API のエンドポイント形状 → **S2-API** 担当（本書は状態遷移の意味論のみ）
- G.3b クラスタ注釈（DISCOVERY 系 LLM 機能） → **S3-discovery** 担当（Feature Hub 登録のみ本書）

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md) に従う。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソースについて**: 本領域はテストカバレッジが不均一である。
`test_age_decay.py`(21) / `test_intel_auto_judge.py`(17) / `test_intel_tier3_corroborated.py`(8) /
`test_intel_multicountry.py`(12) / `test_llm_features.py`(27) / `test_llm_routing.py`(40) /
`test_llm_prompt_persistence.py`(12) / `test_sanitize_llm_input.py`(17) が pin している値は
テストを一次ソースとした。一方 **投入時 dedup の Layer 0/2、LLM クライアント本体、
corroboration 合成は全て無テスト**であり、これらの条項の根拠は実装のみである（§6 GAP）。
設計メモ [intel-pipeline.md](../intel-pipeline.md) との乖離は実装値を CORE とし、乖離自体を §4 に回した。

---

## 1. 用語

CLAUDE.md の用語定義に従う（country / scenario / participant / adversary / focused / background）。本書固有:

- **item**: LLM が構造化した 1 件のインテル。`id` は UUID4（センサー指定があればそれを優先）
- **source_type**: センサー系統ラベル。`hacktivist` / `diplomatic` / `military` / `ground_osint` /
  `apt_intel` / `narrative` / `corroborated` の 7 値
- **source_id**: フィード/チャンネル単位の識別子（例 `cert_cisa_advisories`）。credibility 追跡の単位
- **credibility**: source_id ごとの信頼度重み [0.30, 0.95]。アナリスト判定で更新される
- **ecosystem**: source_id が属するメディア生態系（`ru_state` / `cn_state` / `ir_state` / `us_gov` /
  `independent` / `cert` / `hacktivist` / 未分類 `""`）。独立性判定と auto-confirm ゲートに使う
- **verdict tag**: 1 件の LLM 呼出しに紐づく最終処遇ラベル（`auto_confirmed` /
  `auto_confirmed_corroborated` / `pending` / `discarded_low_conf` / `discarded_dedup` /
  `discarded_dedup_xtype` / `discarded_dedup_embed` / `sensor_filtered:<reason>`）
- **Feature Hub state**: LLM 機能ごとの実行状態。`off` / `shadow` / `shadow_dual` / `on` の 4 値
- **use case**: モデルルーティングのバケット。`sensor_extract` / `verdict` / `conclusion` /
  `discovery` / `narrative` の 5 値

---

## 2. 挙動条項

### 2.1 投入（submit）パイプライン

### S1-INTEL-001: LLM 無効時は投入を一切受け付けない
**挙動**: グローバル LLM 有効フラグが false のとき、投入は **即座に None を返し、DB 書込・ログ記録・
WS 通知のいずれも行わない MUST**。この判定は Feature Hub を経由せず、プロセス起動時に環境から
確定した値を用いる。
**閾値**: `LLM_ENABLED` **既定 false**（config.py:646）
**根拠**: radar/intel_queue.py:452-453、radar/config.py:646
**検証**: 未検証（各テストは fixture で真値を注入）
**分類**: **DEFECT-PRESERVE** — LLM 呼出し層は Feature Hub キー `sensor_intel_extraction` 経由で
解決する（llm_client.py:410-419）のに、キュー投入側は起動時定数を直読みする。
結果として **Feature Hub の kill switch は投入を止められず、DB override で ON にしても
env が false なら投入は動かない**（§5 DP1）

### S1-INTEL-002: countries は明示指定を優先し、無ければ単一 country から導出する
**挙動**: 投入 item が `countries` を持てばそれを採用 **MUST**。空でかつ単一 country タグ
（レガシー `theater` フィールド）があれば `countries = [theater]`、`country_weights = {theater: 1.0}`
に展開する **MUST**。両方空ならグローバル信号として扱う。
**根拠**: radar/intel_queue.py:463-468
**検証**: tests/test_intel_multicountry.py::TestSubmitBackwardCompat::test_theater_only_derives_countries /
test_explicit_countries_preserved；::TestDBCountryColumns::（5 件）
**分類**: **DEFECT-PRESERVE** — レガシー単一 country フィールドは導出元であるだけでなく、
以降の dedup・corroboration・寄与キャップの**主キーとして使われ続ける**（S1-INTEL-032/038/039/045）。
v3 では country リストを唯一の識別軸とする **MUST**（D2 C-01）

### S1-INTEL-003: 最低 confidence 未満は破棄し、破棄を可視化する
**挙動**: `confidence < LLM_CONFIDENCE_MIN` の item は破棄 **MUST**。破棄時は
(a) 直近の LLM 呼出しログに verdict `discarded_low_conf` を付す、(b) 隠れ信号台帳に
`hide_reason = "intel_low_confidence (<値> < <閾値>)"` を country・sensor・domain 付きで記録する **MUST**。
台帳書込みの失敗は破棄処理を止めない **MUST**（NP3）。
**閾値**: `LLM_CONFIDENCE_MIN` **既定 0.35**（env のみ、DB override 不可）
**根拠**: radar/intel_queue.py:37-38, 471-485、radar/database.py:6134-6148
**検証**: 未検証
**分類**: CORE（NP1: 破棄は必ず観測可能でなければならない）

### S1-INTEL-004: 重複排除は 4 層を固定順で適用する
**挙動**: 投入は以下の順で dedup を試み、いずれかで一致したら **item を新規作成せずに終了 MUST**:
1. **URL 完全一致**（source_type をまたぐ）
2. **埋込ベクトル近傍**（Feature Hub `embedding_dedupe` が active のときのみ）
3. **同一 source_type 内の見出し Jaccard**
4. **異 source_type 間の見出し Jaccard**（より厳しい閾値）

層 1 が最優先である理由は、URL 一致は計算量ゼロかつ誤判定確率が最も低いため。
**根拠**: radar/intel_queue.py:487-718
**検証**: 層 3 のみ検証（tests/test_intel_multicountry.py::TestDedupMultiCountry）。層 1/2/4 は §6 GAP-03/04
**分類**: CORE

### S1-INTEL-005: URL 正規化は scheme 統一・追跡パラメータ除去・末尾スラッシュ除去
**挙動**: dedup 用 URL 正規化は **MUST**: scheme を `https` に固定 / クエリから
`utm_*` および `ref` `source` `fbclid` `gclid` を除去 / 残るクエリをキー昇順に再構築 /
path 末尾のスラッシュを除去（空になれば `/`）。解析例外時は入力をそのまま返す **MUST**。
正規化 URL が **16 文字以上のときのみ**照合に用いる **MUST**。正規化後の一致が無ければ
**正規化前の生 URL でも 1 回照合する MUST**。照合窓は 48 時間。
**閾値**: dedup 窓 `_DEDUP_WINDOW_SECONDS` = **48h**（ハードコード）、最小 URL 長 > 15
**根拠**: radar/intel_queue.py:312, 317-335, 490-497、radar/database.py:5668-5679
**検証**: 未検証（GAP-03）
**分類**: CORE

### S1-INTEL-006: URL 一致時は既存 item に corroborator を追記して破棄する
**挙動**: URL が既存 item と一致した場合、投入元 source_id が既存の corroborator 一覧にも
既存 item の source_id にも含まれないなら **corroborator として追記 MUST**。
追記後は遅延昇格判定（S1-INTEL-027）を実行 **MUST**。新規 item は作成せず、
verdict `discarded_dedup_xtype` を記録して終了 **MUST**。
**根拠**: radar/intel_queue.py:498-511
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — この経路だけ corroborator 一覧を単独で書き、
**ecosystem 一覧を同時更新しない**（他の 3 経路は両者を必ず対で書く、intel_queue.py:210-225）。
結果として triage UI が読む「独立生態系数」が経路によって欠落する（§5 DP2）

### S1-INTEL-007: 埋込近傍 dedup は Feature Hub の 3 状態で挙動を変える
**挙動**: `embedding_dedupe` が **off なら埋込呼出しを一切行わない MUST**。
active（shadow または on）のとき、見出し + 本文先頭 500 文字を埋め込み、
**同一 source_type の直近 24 時間・最大 50 件**と総当たりで cosine を計算し、
**0.95 以上の最大一致**を採る **MUST**。一致があれば言語ラベル付きで判定台帳に記録 **MUST**。
`on` のときのみ item を破棄し verdict `discarded_dedup_embed` を記録 **MUST**。
`shadow` のときは `applied=0` で記録し、**次層の Jaccard dedup へ素通しする MUST**。
本ブロック内のあらゆる例外は握り潰し、レガシー経路を継続 **MUST**（NP3）。
**閾値**: cosine 閾値 **0.95**（ハードコード）、比較窓 86400s、比較件数 50、`embedding_dedupe` 既定 **off**
**根拠**: radar/intel_queue.py:513-581、radar/llm_features.py:282-300
**検証**: 未検証（GAP-04）
**分類**: CORE。**比較のたびに過去 50 件を毎回再埋込する**点は §4 A6

### S1-INTEL-008: 見出し類似度は stop-word 除去後の Jaccard 係数
**挙動**: 見出しを小文字化し **3 文字以上の英字語のみ**抽出、固定 stop-word 集合
（冠詞・前置詞・be 動詞・`near` `over` `after` `before` `during` `amid` 等 34 語）を除去した
集合を作る **MUST**。類似度は `|A ∩ B| / |A ∪ B|`、いずれかが空集合なら **0.0 MUST**。
**根拠**: radar/intel_queue.py:305-310, 338-350
**検証**: tests/test_intel_multicountry.py::TestDedupMultiCountry::test_same_countries_same_headline_deduped
**分類**: CORE。**非ラテン文字（日本語・中国語・アラビア語・キリル文字）の見出しは
トークンが 1 つも抽出されず、常に類似度 0.0 = 決して dedup されない** → §4 A1

### S1-INTEL-009: 同一 source_type 内 dedup は国重なりを前提とし、同一ソースなら無条件破棄
**挙動**: 同一 source_type の直近 48h・最大 50 件を走査 **MUST**。
双方が country を持ちかつ **共通 country が 1 つも無ければ別事象として比較を打ち切る MUST**。
見出し類似度が **0.60 未満なら別事象 MUST**。0.60 以上でかつ **source_id が同一なら
再スクレイプの重複とみなし無条件で破棄** し verdict `discarded_dedup` を記録 **MUST**。
**閾値**: `_JACCARD_THRESHOLD` = **0.60**（ハードコード）、走査上限 50 件、窓 48h
**根拠**: radar/intel_queue.py:313, 596-623
**検証**: tests/test_intel_multicountry.py::TestDedupMultiCountry::test_same_countries_same_headline_deduped /
test_non_overlapping_countries_not_deduped / test_overlapping_countries_deduped
**分類**: CORE

### S1-INTEL-010: 帰属アクターまたは外交アクションが異なれば同一見出しでも別事象
**挙動**: 異なる source_id 間で見出しが閾値を超えても、両者が **帰属アクターを持ちかつ
（大小無視で）異なる**場合、または両者が **外交アクション種別を持ちかつ異なる**場合は
**別事象として dedup しない MUST**（走査を次候補へ継続）。
**根拠**: radar/intel_queue.py:626-637
**検証**: 未検証
**分類**: CORE（NP1: 似た見出しの別事象を潰すのは見逃しに直結する）

### S1-INTEL-011: 新着の confidence が高ければ既存 item の分析内容を置換する
**挙動**: 異ソース・見出し類似・別事象条件に該当しない場合で、**新着 confidence が既存より
厳密に大きい**なら、既存 item の 見出し / confidence / score_delta / 本文 / URL を
新着で上書き **MUST**。このとき **旧 source_id を corroborator 一覧に追加し、
corroborator 一覧と ecosystem 一覧を対で書き込む MUST**。item は新規作成しない **MUST**。
本文は 1000 文字、見出しは 200 文字で切り詰める **MUST**。
**根拠**: radar/intel_queue.py:639-660, 210-225
**検証**: 未検証
**分類**: CORE

### S1-INTEL-012: 既存が同等以上なら corroborator を記録して破棄する
**挙動**: 新着 confidence が既存以下なら、投入元 source_id を corroborator 一覧に追加し
（未登録の場合のみ）、corroborator + ecosystem 一覧を対で書き込み、遅延昇格判定を実行 **MUST**。
新着は破棄し verdict `discarded_dedup` を記録 **MUST**。
**根拠**: radar/intel_queue.py:661-677
**検証**: tests/test_intel_tier3_corroborated.py::TestLateCorroboratorPromotion::test_pending_promoted_when_dedup_adds_corroborator
**分類**: CORE

### S1-INTEL-013: 異 source_type 間 dedup はより厳しい閾値を用いる
**挙動**: 全 source_type 横断の直近 48h・最大 80 件を走査し、**自分と同じ source_type はスキップ MUST**
（前段で処理済み）。国重なり条件は同一 source_type 内と同じ。見出し類似度が **0.70 以上**なら
corroborator を追記（+ ecosystem 対書き込み + 遅延昇格判定）して破棄し、
verdict `discarded_dedup_xtype` を記録 **MUST**。
閾値が厳しい理由は、source_type ごとに LLM プロンプトが異なるため同一記事でも見出しが乖離するため。
**閾値**: `_XTYPE_JACCARD_THRESHOLD` = **0.70**（ハードコード）、走査上限 80 件
**根拠**: radar/intel_queue.py:314, 685-717
**検証**: 未検証（GAP-03）
**分類**: CORE

### S1-INTEL-014: 未知 source_id の credibility は archetype でシードする
**挙動**: 初出の source_id は archetype 表から**最長前置一致**で初期 credibility を決め、
ソース台帳に登録 **MUST**。一致が無ければ **0.70**。
| archetype | 初期値 | 前置例 |
|---|---|---|
| 政府 CERT / 国家サイバー機関 | **0.85** | `cert_cisa_advisories`, `cert_ncsc_uk`, `cert_jpcert` 等 7 件 |
| 確立した防衛報道 | **0.75** | `military_usni_news`, `military_janes` 等 5 件 |
| 国家系プロパガンダ | **0.60** | `military_tass_military`, `military_pla_daily` |
| ハクティビスト系 | **0.60** | `hacktivist_` |
| 既定 | **0.70** | — |
既存ソースの credibility は**この経路では上書きしない MUST**（アナリスト判定のみが更新する）。
**根拠**: radar/intel_queue.py:147-158, 279-294, 720-728
**検証**: 未検証（GAP-06）
**分類**: CORE

### S1-INTEL-015: ecosystem 分類は最長前置一致、未知は空文字
**挙動**: source_id を **最長前置一致**でメディア生態系に写像 **MUST**。
一致が無ければ空文字を返す **MUST**。生態系集合は
`ru_state` / `cn_state` / `ir_state`（国家系メディア）、`us_gov`、`independent`、`cert`、`hacktivist`。
**根拠**: radar/intel_queue.py:165-207
**検証**: tests/test_intel_tier3_corroborated.py::TestTier3Corroborated::test_tier3_state_media_never_auto_confirms
**分類**: CORE

### S1-INTEL-016: 自動確認は生態系ゲート → 3 段 tier ラダーで決まる
**挙動**: 初期状態は以下の順で決定 **MUST**（最初に成立した段で確定）:

| 段 | 条件 | 出力 status / verdict tag |
|---|---|---|
| **生態系ゲート** | ecosystem ∉ {`independent`, `cert`, `us_gov`} | `pending` / `pending`（**confidence・credibility を問わない**） |
| **tier 1** | conf ≥ **0.85** かつ cred ≥ **0.80** | `auto_confirmed` / `auto_confirmed` |
| **tier 2** | conf ≥ **LLM_AUTO_CONFIRM_THRESHOLD**(0.80) かつ cred ≥ **0.75** | `auto_confirmed` / `auto_confirmed` |
| **tier 3** | conf ≥ **0.70** かつ cred ≥ **0.75** かつ corroborator ≥ **1** | `auto_confirmed` / `auto_confirmed_corroborated` |
| それ以外 | — | `pending` / `pending` |

生態系ゲートは fail-closed であり **tier 3 でも緩和されない MUST**
（同一プロパガンダ生態系内の相互言及は corroboration ではない）。
各段の成立はログに tier 名とともに記録 **MUST**（NP6）。
**閾値**: tier1 0.85/0.80（ハードコード）、tier2 `LLM_AUTO_CONFIRM_THRESHOLD` 既定 **0.80** + cred 0.75（ハードコード）、
tier3 `LLM_AUTO_CONFIRM_TIER3_CONF` 既定 **0.70** / `LLM_AUTO_CONFIRM_TIER3_CRED` 既定 **0.75**
**根拠**: radar/intel_queue.py:34-47, 228-276, 737-751
**検証**: tests/test_intel_tier3_corroborated.py::TestTier3Corroborated::（6 件全て）/ test_tier1_strict_unchanged
**分類**: CORE。**生態系ゲートにより `diplomatic_*` `ground_osint_*` `narrative_*` `hacknews_*`
`corroborated_*` は構造的に自動確認され得ない** → §4 A2

### S1-INTEL-017: 処遇ラベルは直近の LLM 呼出しログ行へ後追いで書き込む
**挙動**: 全ての処遇（自動確認 / pending / 各種破棄）は、**source_type から caller 名への
静的写像**を引き、直近 **60 秒以内**の **verdict が空の**呼出しログ行 1 件に書き込む **MUST**。
写像に無い source_type は**何も記録しない MUST**。書込み失敗は投入を止めない **MUST**。
**根拠**: radar/intel_queue.py:356-383、radar/database.py:5011-5036
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — (a) 1 回の fetch で N 件投入すると、N 個の処遇が
**同一 caller の別 item に属するログ行へ順に付く**ため処遇と呼出しの対応が崩れる。
(b) 写像に `corroborated` が無いため corroboration 合成の処遇は永久に記録されない。
(c) `apt` と `apt_intel` の不一致で長期間欠測していた既往がコメントに残る（§5 DP3）

### S1-INTEL-018: 永続レコードの必須フィールドと既定値
**挙動**: 受理された item は以下を持って永続化 **MUST**:
`id`（UUID4 または投入指定）/ `source_type` / `source_id` / country 群 / `ts`（無指定なら投入時刻）/
`status` / `confidence` / 本文 / URL / 見出し / LLM 抽出フィールド / `score_delta`（float、既定 0.0）/
`domain`（既定 `info`）/ `confirmed_by`（既定 None）/ `confirmed_at`（自動確認なら投入時刻、他は None）/
`override_at`（None）/ `created_at`（投入時刻）。
**根拠**: radar/intel_queue.py:730-774、radar/database.py:5595-5617
**検証**: tests/test_intel_multicountry.py::TestDBCountryColumns::（5 件）
**分類**: CORE

### S1-INTEL-019: 受理時に全接続クライアントへ通知する
**挙動**: item 永続化後、`id` / 見出し（120 文字まで）/ `source_type` / `status` を含む通知を
**全クライアントへブロードキャスト MUST**（country による絞り込みは行わない）。
WS 未初期化を含むあらゆる例外は握り潰す **MUST**。
**根拠**: radar/intel_queue.py:776-784、radar/ws.py:147-154
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — 通知関数は country 引数を受け取るが**使用していない**（D2 B-07）。
v3 では購読スコープを契約として定義する **MUST**

### 2.2 状態機械

### S1-INTEL-020: item の状態集合と許可された遷移
**挙動**: 状態は `auto_confirmed` / `pending` / `confirmed` / `rejected` / `overridden` /
`review_needed` の 6 値 **MUST**。許可される遷移は以下のみ **MUST**:

| 遷移 | 前提状態 | 契機 | 後状態 |
|---|---|---|---|
| 手動確認 | `pending` | アナリスト or 自動判定 | `confirmed` |
| 却下 | `pending` | アナリスト or 自動判定 | `rejected` |
| 差戻し | `confirmed` / `rejected` | アナリスト | `pending` |
| 上書き | `auto_confirmed` | アナリスト | `overridden` |
| 遅延昇格 | `pending` | corroborator 追加 | `auto_confirmed` |
| 期限切れ却下 | `pending` | 定期スイープ | `rejected` |
| 起動時昇格 | `pending` | 起動シーケンス | `auto_confirmed` |
| 要再確認 | `auto_confirmed` / `confirmed` | 脅威分類イベント | `review_needed` |

前提状態を満たさない要求は **false を返し、状態を変更しない MUST**。
**根拠**: radar/intel_queue.py:788-934, 385-430, 1110-1149
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgePending::test_non_pending_item_returns_pending_action；
tests/test_intel_tier3_corroborated.py::TestLateCorroboratorPromotion
**分類**: **DEFECT-PRESERVE** — `review_needed` から出る遷移が存在しない。
到達した item は永久に滞留し、注意喚起指標にのみ計上される（§5 DP4）

### S1-INTEL-021: 手動確認は寄与を有効化し、ソース信頼度を加点する
**挙動**: `pending` の item を `confirmed` にし、確認者と確認時刻を記録 **MUST**。
アクティブ集合に加え、ソースの確認回数を +1、credibility を **+0.05**（[0.30, 0.95] にクランプ）**MUST**。
確認者名が `auto:` で始まらない（= 人間）場合、自動判定台帳の直近の適用済み判断を
**「人間に上書きされた」と記録 MUST**。この台帳書込みの失敗は **警告ログ + 障害台帳への記録が必須 MUST**
（沈黙の失敗は自動判定の recall/precision 指標を静かに狂わせる）。
**閾値**: 確認加点 +0.05、credibility クランプ [0.30, 0.95]
**根拠**: radar/intel_queue.py:788-826、radar/database.py:5826-5843, 4501-4519
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeApply::test_apply_confirm_marks_analyst_marker /
test_human_override_marks_ledger
**分類**: CORE

### S1-INTEL-022: 却下は分類によって信頼度への影響が変わる
**挙動**: `pending` の item を `rejected` にする **MUST**。分類が
**`false_positive`（誤情報）のときのみ**ソースの誤検知回数を +1 し credibility を **−0.10** **MUST**。
**`irrelevant`（正確だが対象外、既定）のときは credibility を変更しない MUST**
（報告自体はソースの責任ではない）。人間による却下は自動判定台帳へ上書きを記録 **MUST**。
**閾値**: 誤検知減点 **−0.10**、既定分類 `irrelevant`
**根拠**: radar/intel_queue.py:828-867、radar/database.py:5837-5843
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeApply::test_apply_reject_marks_analyst_marker
**分類**: CORE

### S1-INTEL-023: 差戻しは確認加点のみを取り消す
**挙動**: `confirmed` / `rejected` の item を `pending` に戻し、確認者・確認時刻を消去 **MUST**。
`confirmed` からの差戻しのときのみアクティブ集合から除去し credibility に **−0.05** を適用 **MUST**。
`rejected` からの差戻しは credibility に影響しない **MUST**。
**根拠**: radar/intel_queue.py:869-894
**検証**: 未検証（GAP-05）
**分類**: **DEFECT-PRESERVE** — credibility は戻すが**確認回数カウンタは戻さない**ため、
確認回数と重みが乖離する。信頼度スイープ（S1-INTEL-028）は確認回数 0 のみを対象とするため、
差戻された item のソースは以後シード対象から永久に外れる（§5 DP5）

### S1-INTEL-024: 上書きは自動確認を無効化し、誤検知として減点する
**挙動**: `auto_confirmed` の item のみを `overridden` にできる **MUST**。時間制限は無い **MUST**。
アクティブ集合から除去し、ソースを誤検知として扱い credibility −0.10 **MUST**。
**根拠**: radar/intel_queue.py:917-934
**検証**: 未検証（GAP-05）
**分類**: CORE

### S1-INTEL-025: 未判定の pending は一定時間後に自動却下される
**挙動**: `created_at` が **LLM_PENDING_AUTO_REJECT_HOURS** より古い `pending` item を
最大 500 件、確認者 `auto` として `rejected` にする **MUST**。閾値 0 以下なら無効化 **MUST**。
自動却下は **credibility に影響しない MUST**。実行周期は 1 時間。
**閾値**: `LLM_PENDING_AUTO_REJECT_HOURS` 既定 **24h**、1 回あたり上限 500 件、周期 3600s
**根拠**: radar/intel_queue.py:59-62, 896-915、radar/scheduler.py:172, 217
**検証**: 未検証
**分類**: CORE

### S1-INTEL-026: 脅威分類イベントは近傍のアクティブ item を再評価対象にする
**挙動**: アナリストが脅威分類を提出したとき、**その時刻の 1 時間前以降**にアクティブだった
最大 20 件の item のソースについて、分類が `confirmed_threat` なら確認、
`false_positive` / `exercise` なら誤検知として credibility を更新 **MUST**。
誤検知側でかつ item がまだアクティブ集合に居る場合、状態を `review_needed` にし
アクティブ集合から除去 **MUST**。
**閾値**: 遡及窓 3600s、対象上限 20 件
**根拠**: radar/intel_queue.py:936-966、radar/database.py:5762-5773
**検証**: 未検証（GAP-05）
**分類**: **DEFECT-PRESERVE** — 状態変更時に確認者・確認時刻を渡さないため
**元の確認 provenance が消去される**（NP6 違反）。加えて到達先が終端（S1-INTEL-020）（§5 DP4）

### S1-INTEL-027: corroborator 追加のたびに pending を再判定する
**挙動**: dedup 経路で既存 pending item に corroborator が追加されたら、
**その場で自動確認判定を再実行 MUST**。tier 3 を満たすなら `auto_confirmed` に昇格し、
確認者を空のまま確認時刻のみ記録、アクティブ集合へ追加、処遇ラベルを記録 **MUST**。
再判定は最新の DB 状態を読み直して行う **MUST**（投入時点の item は corroborator 0 件であり、
自力では tier 3 に到達し得ないため、この経路が無いと tier 3 は死に機能となる）。
**根拠**: radar/intel_queue.py:385-430
**検証**: tests/test_intel_tier3_corroborated.py::TestLateCorroboratorPromotion::test_pending_promoted_when_dedup_adds_corroborator
**分類**: CORE

### S1-INTEL-028: 起動時に信頼度の再シード・下限適用・遡及昇格を行う
**挙動**: プロセス起動の復元シーケンスで以下を順に 1 回ずつ実行 **MUST**:
1. **再シード** — archetype 初期値と乖離し、かつ**確認回数も誤検知回数も 0** のソースの
   credibility を archetype 値に戻す（学習済み状態は保護）
2. **下限適用** — 全ソースに対し `max(archetype − 0.20, 0.30)` を下限とし、
   下回るものを下限まで引き上げる。**学習済み状態のソースにも適用する MUST**
   （過去の「対象外」却下が不当に減点していた分の是正）
3. **遡及昇格** — `pending` かつ conf ≥ 自動確認閾値 かつ cred ≥ 0.75 かつ生態系が適格な
   item を最大 500 件 `auto_confirmed`（確認者 `system_reseed`）に昇格

**閾値**: archetype 下限 = `max(seed − 0.20, 0.30)`、遡及昇格の cred 下限 0.75、上限 500 件
**根拠**: radar/intel_queue.py:1058-1149、radar/persistence.py:118-128
**検証**: 未検証（GAP-06）
**分類**: CORE。適格生態系集合が**共有定数ではなくリテラル再掲**である点は §5 DP6

### 2.3 スコア寄与と経年減衰

### S1-INTEL-029: 寄与対象は override されていない TTL 内の確認済み item
**挙動**: 採点入力となるのは `auto_confirmed` と `confirmed` の item のみ **MUST**
（各状態から最大 100 件）。**上書き時刻を持つ item は除外 MUST**。
`ts` からの経過が **INTEL_ITEM_TTL_HOURS** を超えるものは除外 **MUST**（ハード下限）。
**閾値**: `INTEL_ITEM_TTL_HOURS` 既定 **48h**、状態あたり取得上限 100 件
**根拠**: radar/intel_queue.py:49-53, 983-1003
**検証**: tests/test_age_decay.py::TestGetActiveRationaleDecay::test_item_beyond_ttl_excluded /
test_overridden_items_excluded
**分類**: CORE

### S1-INTEL-030: 寄与スコアは指数的経年減衰を乗じる
**挙動**: 各 item の寄与は `score_delta × exp(−max(0, age_sec) / (τ_hours × 3600))` **MUST**。
- age = 0 → 重み **1.0**
- age = τ → 重み **1/e ≈ 0.3679**
- age = 2τ → 重み **e⁻² ≈ 0.1353**
- 負の age（未来 ts）は **0 にクランプ MUST**

τ は **source_type ごとに上書き可能 MUST**（`INTEL_AGE_DECAY_TAU_HOURS_<SOURCE_TYPE 大文字>`）。
上書き値が数値として解釈できなければ**全体既定へフォールバック MUST**。
τ ≤ 0、または減衰機能が無効なら重みは **常に 1.0 MUST**。
無効化判定は `false` / `0` / `no` / `off` / 空文字（大小・前後空白無視）**のみ**を偽とする **MUST**。
**閾値**: `INTEL_AGE_DECAY_TAU_HOURS` 既定 **12h**、`INTEL_AGE_DECAY_ENABLED` 既定 **true**
**根拠**: radar/intel_queue.py:64-106
**検証**: tests/test_age_decay.py::TestAgeWeight::（10 件全て）；::TestDecayEnabled::（4 件全て）；
::TestGetActiveRationaleDecay::test_fresh_item_gets_full_score / test_aged_item_decays /
test_decay_disabled_uses_raw_score
**分類**: CORE（ADR-023。確認 → 満額という段差と TTL 境界での崖を同時に解消する）

### S1-INTEL-031: 寄与件数は (source_type, country) 単位で上限を設け、減衰後スコアで順位付ける
**挙動**: 寄与は **(source_type, country) の組ごとに上限 INTEL_MAX_ITEMS_PER_SOURCE_THEATER 件**まで **MUST**。
順位付けは **減衰後スコアの降順、同点は confidence の降順 MUST**。
これにより古い高スコア item は上限枠から押し出される **MUST**。組が違えば互いに独立 **MUST**。
**閾値**: `INTEL_MAX_ITEMS_PER_SOURCE_THEATER` 既定 **2**
**根拠**: radar/intel_queue.py:55-57, 1005-1017
**検証**: tests/test_age_decay.py::TestGetActiveRationaleDecay::test_cap_ranks_by_decayed_score /
test_multiple_groups_independent
**分類**: CORE。**グループ化キーが country リストではなくレガシー単一 country フィールド**である点は
S1-INTEL-002 の系（countries のみを持つ item は全て空キーで同一グループに畳まれる）

### S1-INTEL-032: 寄与ペイロードは検証可能な来歴を必ず含む
**挙動**: 各寄与は以下を含む **MUST**: 減衰後スコア / 減衰前スコア / 経過時間（時間単位）/ 減衰重み /
confidence / domain / country 群 / 状態 `FIRED` / 非抑止 / **一次ソース URL** / **LLM の判断理由** /
**原文の観測時刻** / **見出し** / **原文** / `source_type` / `source_id`。
表示文字列は `[SOURCE_TYPE] 見出し (age N.Nh, w=0.NN)` の形 **MUST**（NP6: 減衰が目視で追える）。
信号系統は `llm_intel` に固定 **MUST**（S1-scoring-core の dedup 単位となる）。
**根拠**: radar/intel_queue.py:1019-1047
**検証**: tests/test_age_decay.py::TestGetActiveRationaleDecay::test_detail_string_contains_age_and_weight；
tests/test_intel_multicountry.py::TestActiveRationale::（2 件）
**分類**: CORE（NP6）

### S1-INTEL-033: 採点層への関連性フィルタ（境界条項）
**挙動**: 寄与がシナリオに算入されるのは以下のいずれかが成立するときのみ **MUST**:
(a) country も countries も空（グローバル信号 → 常に関連）、
(b) countries とシナリオ参加国に共通要素がある、
(c) レガシー単一 country がシナリオ参加国に含まれる。
以降のドメイン集計・収斂・TL 導出は **S1-scoring-core の管轄**。
寄与の取り込みに失敗した場合は **警告ログ + 障害台帳記録 MUST**（沈黙の欠落は脅威の隠蔽と等価）。
**根拠**: radar/routes/core.py:1892-1930, 2059-2082
**検証**: 未検証（間接のみ）
**分類**: CORE。(a) の「グローバル信号は常に関連」は S1-SCORE-012（グローバル信号は既定でシナリオ
スコアから分離）と**方向が逆**であり、境界が二重定義になっている → §4 A3

### 2.4 自動判定（auto-judge）

### S1-INTEL-034: 自動判定スイープは毎時・LLM 非依存で走る
**挙動**: `pending` item を最大 200 件取得し、1 件ずつ評価・適用する **MUST**。
1 件の失敗は他を止めない **MUST**。結果は 評価数 / confirm / reject / pending / errors の
集計で返す **MUST**。**LLM が利用不能でも決定論部分は完全に動作する MUST**（空気遮断環境要件）。
**閾値**: 周期 3600s（自動却下と同一）、1 回あたり 200 件
**根拠**: radar/intel_auto_judge.py:604-634、radar/scheduler.py:220-236
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeApply::test_run_sweep_returns_counts
**分類**: CORE（NP3）

### S1-INTEL-035: 決定論規則は 4 つの却下条件 → 確認条件 → 中間帯 の順で評価する
**挙動**: `pending` 以外の item は即座に「pending（理由 `not_pending`）」を返す **MUST**。
以下を**この順で**評価し、最初に成立したものを返す **MUST**:

| 順 | 判定 | 条件 | 理由コード |
|---|---|---|---|
| 1 | reject | 既に受理済みの item と見出しが重複 | `duplicate_of_accepted` |
| 2 | reject | ソースの誤検知比率が閾値超 | `source_reputation_drift` |
| 3 | reject | conf ≤ **0.40** かつ corroborator 0 | `low_confidence_no_corroboration` |
| 4 | reject | 経過 ≥ **48h** かつ corroborator 0 | `stale_no_corroboration` |
| 5 | confirm | conf ≥ **0.70** かつ corroborator ≥ 1 かつ生態系が適格 | `confidence_plus_corroboration` |
| 6 | pending | 上記いずれも不成立 | `ambiguous_middle_band` |

内部例外は全て「pending」に落とす **MUST**（NP1: 迷ったら人間へ）。
**閾値**: `AUTO_JUDGE_CONF_CONFIRM_FLOOR` 既定 **0.70**、`AUTO_JUDGE_CONF_REJECT_CEILING` 既定 **0.40**、
`AUTO_JUDGE_STALE_HOURS` 既定 **48h**、`AUTO_JUDGE_CORROBORATION_HOURS` 既定 **72h**
**根拠**: radar/intel_auto_judge.py:55-96, 349-441
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeReject::（3 件）；::TestAutoJudgeConfirm::（1 件）；
::TestAutoJudgePending::（3 件）
**分類**: CORE

### S1-INTEL-036: corroborator は「同一 country・別 source_type・非却下」の異種数
**挙動**: corroborator 数は、**同一 country（レガシー単一フィールド）・窓 72h・最大 200 件**の中で
自分自身でなく、状態が `rejected` でなく、**source_type が自分と異なる**ものの
**source_type 種類数** **MUST**。country が空の item は **corroborator 0 とする MUST**。
独立性の粒度は source_type 止まりであり、より細かい生態系単位の独立性判定は
corroboration 側（S1-INTEL-041）の責務 **MUST**。
**根拠**: radar/intel_auto_judge.py:178-209
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeConfirm::test_confidence_plus_corroboration_confirms；
::TestAutoJudgePending::test_high_confidence_no_corroborator_stays_pending
**分類**: **DEFECT-PRESERVE** — country 空 → 0 という規則により、
**countries のみを持ち単一 country フィールドが空の item は永久に corroborator を得られず、
tier 3・自動確認・重複却下の全経路から外れる**（§5 DP7）

### S1-INTEL-037: 受理済み item との見出し重複は無条件却下
**挙動**: 同一 country・窓内・状態が `confirmed` / `auto_confirmed` の peer と
見出し Jaccard が **0.70 以上**なら重複とみなし却下 **MUST**。見出しが空、
トークンが空、country が空のときは重複判定を行わない **MUST**。
**閾値**: `AUTO_JUDGE_DUP_JACCARD` 既定 **0.70**
**根拠**: radar/intel_auto_judge.py:81-83, 212-245
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeReject::test_duplicate_of_accepted_rejects
**分類**: CORE

### S1-INTEL-038: ソース評判ドリフトは誤検知比率で判定する
**挙動**: ソースの `誤検知回数 / (確認回数 + 誤検知回数)` が閾値以上、
かつ判定総数が最小件数以上のとき評判ドリフトとみなす **MUST**。
総数が最小件数未満なら**ドリフトなしとする MUST**（新規ソースを 1〜2 件の却下で潰さない）。
分母には**「対象外」却下を含めない**（誤検知回数のみを使う）**MUST**。
**閾値**: `AUTO_JUDGE_SOURCE_REJECT_RATIO` 既定 **0.75**、`AUTO_JUDGE_SOURCE_MIN_DECISIONS` 既定 **5**
**根拠**: radar/intel_auto_judge.py:85-96, 248-270
**検証**: 未検証（GAP-08）
**分類**: CORE

### S1-INTEL-039: LLM 第 2 パスは中間帯のみ・交差証拠必須・冪等ガード付き
**挙動**: 決定論判定が中間帯に落ちた item に限り、`auto_judge_recheck` が
shadow または on のとき LLM 再評価を行う **MUST**。以下の 4 ゲートを**全て**満たさない限り
決定論の pending を覆せない **MUST**:
1. **冪等ガード** — 同一 item の直近台帳行が **50 分以内**かつ **corroborator 数が同一**なら
   LLM 呼出しを**丸ごとスキップ MUST**（入力不変なら出力も不変）
2. **交差証拠ゲート（ハードコード）** — corroborator ≥ 1 でなければ、LLM が何を返しても
   **反転しない MUST**。shadow 時もこのゲートは有効 **MUST**
3. **confidence 下限** — LLM 自己申告 confidence が **0.85 未満**なら反転しない **MUST**
4. **適用ゲート** — `auto_judge_recheck` が **on のときのみ**判定を適用する **MUST**。
   shadow では台帳に記録するが決定論の pending が優先 **MUST**

LLM 応答の `action` は `{confirm, reject, pending}` に限定して検証 **MUST**、
`pending` は反転しない **MUST**。理由文字列は 120 文字で切る **MUST**。
LLM が到達不能・呼出し例外・解析失敗のときは反転しない **MUST**（NP3）。
**閾値**: `AUTO_JUDGE_LLM_CONF_FLOOR` 既定 **0.85**、`AUTO_JUDGE_LLM_SKIP_WINDOW_SEC` 既定 **3000s**、
`auto_judge_recheck` 既定 **off**、LLM 呼出し use case = `verdict`、temperature 0.0、max_tokens 200
**根拠**: radar/intel_auto_judge.py:123-159, 273-318, 414-441, 456-564
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeApply::test_llm_recheck_gated_off_by_default /
test_llm_recheck_blocked_by_layer1_when_no_corroborator / test_llm_recheck_flips_when_layer1_satisfied /
test_llm_recheck_skip_guard_avoids_redundant_calls / test_llm_recheck_skip_guard_re_runs_when_corroborators_change
**分類**: CORE（非対称 NP1: 幻覚由来の反転は構造的に阻止するが、阻止自体は見逃しを生まない）

### S1-INTEL-040: LLM 第 2 パスは呼び出したら必ず台帳に記録する
**挙動**: LLM を呼び出した場合、**判定が pending でも下限未満でも必ず**台帳へ 1 行記録 **MUST**:
item ID / 提案アクション / LLM confidence / 理由 / corroborator 数 / 交差証拠充足フラグ /
適用フラグ。記録は最初 `applied=0` で行い、実際に適用する場合のみ直近行を `applied=1` に更新 **MUST**。
これにより ECE 較正が**採用した反転だけでなく LLM 出力分布全体**に対して計算できる **MUST**。
台帳書込みの失敗は判定を止めない **MUST**。
**根拠**: radar/intel_auto_judge.py:321-347, 518-529, 561-563、radar/database.py:4461-4519
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeApply::test_llm_recheck_writes_calibration_ledger
**分類**: CORE（AP4 判断履歴）

### S1-INTEL-041: 自動判定の適用は決定論と LLM を別マーカーで区別する
**挙動**: 適用は通常の確認/却下経路を通す **MUST**。確認者マーカーは
決定論確認 `auto:rule_confirm` / 決定論却下 `auto:rule_reject` /
LLM 確認 `auto:llm_recheck_confirm` / LLM 却下 `auto:llm_recheck_reject` の 4 種 **MUST**。
自動却下は必ず分類 **`irrelevant`** を用いる **MUST**（自動判定はファクトチェックではないため
ソース信頼度を減点しない）。pending 判定は無操作で成功扱い **MUST**。
**根拠**: radar/intel_auto_judge.py:115-120, 567-601
**検証**: tests/test_intel_auto_judge.py::TestAutoJudgeApply::test_apply_confirm_marks_analyst_marker /
test_apply_reject_marks_analyst_marker
**分類**: CORE（NP7: 自動判断は人間の判断と統計上分離できねばならない）

### 2.5 独立ソース照合（corroboration）

### S1-INTEL-042: 照合パスは 30 分周期・起動 5 分遅延で走る
**挙動**: 照合パスは **1800 秒周期**で実行し、起動直後は **300 秒待ってから**初回を走らせる **MUST**
（センサーが DB を満たす時間を確保）。LLM 無効時・LLM 到達不能時は**何もせず 0 を返す MUST**。
**根拠**: radar/intel_corroboration.py:143-153、radar/scheduler.py:719-739
**検証**: 未検証（GAP-01）
**分類**: CORE

### S1-INTEL-043: 候補は「実センサー由来 × 非却下 × 窓内 × country 付き」
**挙動**: 窓内（既定 8 時間）の最大 500 件から、source_type が実センサー 6 種
（`hacktivist` / `ground_osint` / `diplomatic` / `military` / `narrative` / `apt_intel`）で、
状態が `auto_confirmed` / `confirmed` / `pending` のものを候補とする **MUST**。
**合成済み item（`corroborated`）は候補から除外 MUST**（再帰防止）。
候補は country 単位でグループ化し、**country が空の item は捨てる MUST**。
**閾値**: `CORROBORATION_WINDOW_HOURS` 既定 **8h**、取得上限 500 件
**根拠**: radar/intel_corroboration.py:104-105, 155-178
**検証**: 未検証（GAP-01）
**分類**: CORE

### S1-INTEL-044: 独立性は対称行列 + 貪欲選択で決まる
**挙動**: source_type 対ごとの独立性スコア（0.0 = 同一データ流、1.0 = 完全独立）を
**対称な参照表**から引く **MUST**。未登録の対は既定 **0.70**。
同一 source_type 同士（例 `military` × `military`）は**単一要素集合として引かれる MUST**。
選択は入力順の貪欲法で、**既選択の全メンバーとの独立性が閾値以上**のものだけを追加 **MUST**。
選択結果が最小ソース数に満たなければ照合しない **MUST**。
主要な低独立性の対: `ground_osint`×`hacktivist` = **0.15**（同一 Telegram 流）、
`military`×`military` = **0.20**（同一プレスリリースの通信社増幅）、
`narrative`×`diplomatic` = 0.50、`narrative`×`hacktivist` / `narrative`×`ground_osint` = 0.45。
**閾値**: `CORROBORATION_MIN_INDEPENDENCE` 既定 **0.70**、`CORROBORATION_MIN_SOURCES` 既定 **2**、
未登録対の既定独立性 **0.70**
**根拠**: radar/intel_corroboration.py:54-137
**検証**: 未検証（GAP-01）
**分類**: CORE（NP2 の中核）。貪欲法は順序依存で最大独立集合を保証しない → §4 A4

### S1-INTEL-045: 照合発火後は同一 country を一定時間ロックする
**挙動**: 照合 item を生成したら、その country を **CORROBORATION_COOLDOWN_HOURS** の間
再照合対象から外す **MUST**（進行中の同一事象での連続発火防止）。
期限切れのロックは毎パスで掃除する **MUST**（無制限成長の防止）。
**閾値**: `CORROBORATION_COOLDOWN_HOURS` 既定 **12h**
**根拠**: radar/intel_corroboration.py:95-96, 108-109, 182-186, 209-223
**検証**: 未検証（GAP-01）
**分類**: CORE

### S1-INTEL-046: 合成は同一事象判定 + confidence 下限を通過したときのみ行う
**挙動**: 独立群の各 source_type から **confidence 最大の 1 件**を代表として選び、
LLM に「同一事象か」を判定させる **MUST**。以下のいずれかで合成を中止 **MUST**:
LLM 応答が解析不能 / `same_event` が偽 / confidence < **0.55**。
通過した場合、以下を計算 **MUST**:
- `confidence = min(LLM confidence + min((n_sources − 2) × 0.03, 0.06), 0.95)`
- `score_delta = round(urgency 基礎点 + min((n_sources − 2) × 0.3, 0.9), 1)`
  urgency 基礎点: critical **3.0** / high **2.5** / medium **2.0**（既定）/ low **1.5**
- `domain` は `{cyber, physical, info, mixed}` に限定検証、既定 `mixed`

生成 item は `source_type = "corroborated"`、`source_id = "corroborated_<country>"`、
`countries = [country]`（重み 1.0）、貢献ソース種別・貢献 source_id・貢献 item ID・
LLM の判断理由・独立ソース数を LLM 抽出フィールドに含める **MUST**（NP6）。
生成 item は**通常の投入経路を通す MUST**（重複排除も自動確認判定も等しく適用される）。
**閾値**: 同一事象 confidence 下限 **0.55**、ソース数ボーナス上限 **+0.06** / **+0.9**、confidence 上限 **0.95**
**根拠**: radar/intel_corroboration.py:193-207, 229-341
**検証**: 未検証（GAP-01）
**分類**: CORE。生成 item の生態系が未分類となり**恒久的に pending に留まる**点は §5 DP8

### 2.6 LLM 呼出し基盤

### S1-INTEL-047: 構造化呼出しは JSON 強制 + 単発試行（リトライなし）
**挙動**: 構造化応答が必要な呼出しは、Ollama の JSON 強制モードを用いる **MUST**。
**リトライは行わない MUST** — HTTP 非 200 / タイムアウト / 例外はいずれも
1 回の試行で確定し、`{ok: false, data: {}, error: <理由>}` を返す **MUST**。
理由コードは `HTTP <code>` / `timeout` / 例外文字列 / `json_parse_failed` / `LLM_ENABLED=false` **MUST**。
呼出しの成否によらず **必ず 1 行の呼出しログを残す MUST**。
**根拠**: radar/llm_client.py:532-697
**検証**: 未検証（GAP-02）
**分類**: CORE。**リトライ不在は設計判断か放置かが不明** → §4 A5

### S1-INTEL-048: JSON 解析は 3 段の防御を持つ
**挙動**: 応答テキストの解析は以下の順 **MUST**:
1. **コードフェンス除去** — テキストに ``` が含まれるとき、行頭が ``` の行を全削除
2. **直接解析** — 残りをそのまま JSON として解析
3. **部分抽出** — 失敗時、最初の `{` から最後の `}` までを切り出して再解析

3 段すべて失敗したら `parse_failed` として記録し、**応答先頭 200 文字をエラー欄に保存 MUST**
（NP6: 何が返ってきたか事後に見える）。
数値フィールドは **範囲外なら既定値ではなくクランプ MUST**（1.001 → 1.0）、
型変換不能・None なら既定値 **MUST**。列挙フィールドは許可集合に**厳密一致**しなければ既定値 **MUST**、
予期しない値はデバッグログに残す **MUST**（モデル品質劣化の検知）。
**根拠**: radar/llm_client.py:117-149, 648-697
**検証**: 未検証（GAP-02）。間接: tests/test_rss_extractor.py（regex fallback 側）
**分類**: CORE

### S1-INTEL-049: 応答本文が空なら推論フィールドを本文として採用する
**挙動**: 応答本文が空文字のとき、モデルが推論フィールドに出力している場合があるため
**推論フィールドを本文として採用する MUST**。この場合、推論トレースは別途保存しない **MUST**
（本文として消費済み）。本文が非空でルーティングが推論を有効にしている場合のみ、
推論テキストを**別カラムとして呼出しログに保存する MUST**（NP6）。
推論が無効なルーティングでは推論トレースを保存しない **MUST**。
**根拠**: radar/llm_client.py:620-630, 519-522
**検証**: 未検証（GAP-02）
**分類**: CORE（intel-pipeline.md の既知の落とし穴 #1 に対応）

### S1-INTEL-050: タイムアウトは実行時に再解決する
**挙動**: 呼出しタイムアウトは**毎回 3 層 config から読み直す MUST**（DB override が
コンテナ再起動なしで効く）。解決に失敗したら起動時に環境から取得した値へフォールバック **MUST**。
**閾値**: `LLM_TIMEOUT` 既定 **30 秒**（DB override 可）
**根拠**: radar/llm_client.py:33-44、radar/config.py:649
**検証**: 未検証
**分類**: CORE

### S1-INTEL-051: 呼出しログの記録項目
**挙動**: 1 呼出しにつき以下を記録 **MUST**: 時刻 / 呼び元モジュール名 / **実際に走ったモデル** /
所要ミリ秒 / 結果コード（`ok` / `http_error` / `timeout` / `exception` / `parse_failed` /
`disabled` / `pre_filter`）/ 処遇ラベル（後追いで埋まる、初期は空）/ confidence / 見出し(200) /
エラー(300) / **プロンプト sha256** / **use case** / **shadow モデル名** / **推論トレース(4000)**。
呼び元名はスタックから自動推定し、推定失敗時は `unknown` **MUST**。
**この記録の失敗は本処理を絶対に止めてはならない MUST**（例外を握り潰し −1 を返す）。
**根拠**: radar/llm_client.py:192-242、radar/database.py:4390-4425
**検証**: tests/test_llm_routing.py::TestLlmClientUseCaseLog::test_disabled_path_logs_use_case；
::TestRoutingStats::（4 件）
**分類**: CORE（NP6）

### S1-INTEL-052: センサー層の投入前後の脱落も記録する
**挙動**: 2 種の脱落を区別して記録 **MUST**:
- **投入前スキップ**（LLM を呼ばずに諦めた: フィード取得失敗 / 記事なし / 国ヒントなし 等）
  → 結果コード `pre_filter` の**合成行を新規挿入 MUST**
- **投入後ドロップ**（LLM は呼んだがセンサーが結果を捨てた）
  → 直近呼出し行の処遇を `sensor_filtered:<理由>` に**後追い更新 MUST**

いずれも失敗は本処理を止めない **MUST**。
**根拠**: radar/llm_client.py:362-405
**検証**: 未検証
**分類**: CORE（AP3: 沈黙したセンサーの理由が UI から見える）

### S1-INTEL-053: 外部テキストの無害化は 4 段の固定パイプライン
**挙動**: LLM に渡す非信頼テキストは以下の順で処理 **MUST**:
1. 空入力は空文字を返す / 最大長で**先に切り詰める**（既定 1000 文字）
2. **NFKC 正規化**（全角・互換・丸囲み文字を正準 ASCII へ畳む）
3. **制御文字除去** — C0（タブ・改行・復帰を除く）/ DEL / C1 / ゼロ幅文字群 /
   行・段落区切り / **双方向テキスト明示上書き** / 単語結合子・BOM
4. **命令上書きパターン置換** — 一致箇所を `[...]` に置換

パターン集合は英語（命令無効化・ペルソナ乗っ取り・jailbreak・プロンプト暴露）/ 日本語 /
中国語 / ロシア語 / **チャットテンプレート区切りトークン**を含む **MUST**（大小無視の単一走査）。
**正当な文章に含まれる単語（`ignore` 単独等）は検閲してはならない MUST**。
タブ・改行・復帰は保存する **MUST**。
**閾値**: 既定最大長 **1000 文字**
**根拠**: radar/llm_client.py:61-112, 152-183
**検証**: tests/test_sanitize_llm_input.py::（17 件全て。homoglyph 連鎖攻撃・双方向上書き・
4 言語の命令句・テンプレート区切りを含む）
**分類**: CORE（S4 セキュリティ仕様と相互参照）

### S1-INTEL-054: 並行 shadow 呼出しは主呼出しに一切影響しない
**挙動**: ルーティングが `shadow_dual` のとき、主呼出しの**成功後に**候補モデルへ
同一プロンプトで並行呼出しを行い、結果を主呼出し行に紐づけて記録 **MUST**。
記録項目: 主呼出し ID / モデル / 所要ミリ秒 / 結果 / 応答本文(8000) / 応答 sha256 /
抽出 confidence / プロンプト sha256 / エラー。
**主呼出し ID が有効（> 0）でなければ実行しない MUST**。
**あらゆる例外を握り潰し、主呼出しの戻り値を変えてはならない MUST**（NP3）。
**根拠**: radar/llm_client.py:245-342, 666-668, 686-688、radar/database.py:4427-4459
**検証**: 未検証（GAP-07）
**分類**: CORE。コスト倍増のため測定窓限定の運用を前提とする

### S1-INTEL-055: プロンプトは sha256 でデデュープして永続化する
**挙動**: プロンプト識別子は `sha256(system ‖ 0x00 ‖ prompt)` **MUST**
（同一 user プロンプトでも system が違えば別行）。
永続化は sha256 を主キーとする upsert で、既存なら **最終使用時刻を更新し使用回数を +1 MUST**。
本文は `system ‖ "\n\x00\n" ‖ prompt`（system が空なら prompt のみ）**MUST**。
**秘密値を含むプロンプトは永続化を拒否 MUST** — 監視対象の環境変数
（JWT 秘密鍵 / 既定管理者パスワード / 各種 API トークン）の値が **8 文字以上**でプロンプト中に
現れたら、警告ログを出して**保存せず None を返す MUST**。空の環境値は照合対象外 **MUST**。
保存失敗（秘密検出含む）でも **LLM 呼出しは続行する MUST**（呼出しログの sha256 欄が空になるのみ）。
**閾値**: `V2_LLM_PROMPT_PERSISTENCE_ENABLED` 既定 **false**、秘密値の最小長 8
**根拠**: radar/llm_prompts.py:34-107、radar/llm_client.py:345-359, 580-582、radar/config.py:235
**検証**: tests/test_llm_prompt_persistence.py::（12 件全て）
**分類**: CORE（NP6「プロンプトまで遡及可能」の実装）。**既定 OFF である点は §4 A7**

### S1-INTEL-056: プロンプト台帳は結論の保持期間を必ず上回る
**挙動**: プロンプト行は**最終使用時刻**を基準に剪定 **MUST**。
保持日数は設定値と **「結論保持日数 + 30 日」の大きい方を採る MUST**
（運用者がいくら短く設定しても、生存中の結論は必ず自分のプロンプトを解決できる — NP6 の下限保証）。
呼出しログは時刻基準で剪定 **MUST**。
**閾値**: `LLM_PROMPTS_RETENTION_DAYS` 既定 **120 日**（下限 = `CONCLUSIONS_RETENTION_DAYS` + 30）、
`LLM_CALL_LOG_RETENTION_DAYS` 既定 **30 日**
**根拠**: radar/database.py:5451-5475
**検証**: tests/test_llm_log_retention.py::TestLlmCallLogRetention::（2 件）；
::TestLlmPromptsRetention::（2 件、下限保証を含む）
**分類**: CORE

### 2.7 モデルルーティング

### S1-INTEL-057: use case ごとに主・副モデルの連鎖を持つ
**挙動**: 5 つの use case それぞれに (主, 副) のモデル選択連鎖を持つ **MUST**。
コード既定値:

| use case | 主 | 副 | 主の代表サンプリング |
|---|---|---|---|
| `sensor_extract` | mistral-small3.2:24b | gemma4:26b | temp 0.1 / top_p 1.0 / num_predict 512 |
| `verdict` | gemma4:26b | mistral-small3.2:24b | temp **0.0** / top_k **1** / **seed 42** / num_predict 128 |
| `conclusion` | gemma4:31b | gemma4:26b | temp 1.0 / top_p 0.95 / top_k 64 / num_predict 1024 |
| `discovery` | gemma4:31b | gpt-oss-safeguard:20b | temp 0.5 / top_p 0.95 / top_k 64 / num_predict 1024 |
| `narrative` | gemma4:26b | （なし） | temp 0.7 / top_p 0.95 / top_k 64 / num_predict 512 |

`verdict` は**決定性が要件**であるため temperature 0・top_k 1・固定 seed **MUST**。
**全 use case で推論モードは既定 OFF MUST** — 構造化呼出しは JSON 応答を要求するのに対し、
推論有効時はトークン予算が内部思考に費やされ本文が空になるため（実測: 解析成功率 0%）。
モデル選択が推論 OFF のときは**呼出しペイロードで明示的に無効化する MUST**
（推論可能モデルは既定でオンになるため）。
**根拠**: radar/llm_routing.py:120-254
**検証**: tests/test_llm_routing.py::TestChooseModelOn::（4 件全て）
**分類**: CORE

### S1-INTEL-058: ルーティング設定はコード → env → DB の 3 層をパラメータ単位で解決する
**挙動**: 各 (use case, スロット) の設定は以下の順で**パラメータごとに独立に**上書きされる **MUST**:
1. **コード既定**（S1-INTEL-057）
2. **env**: `LLM_ROUTING_<USECASE>_<SLOT>_{MODEL|TEMP|TOP_P|TOP_K|SEED|NUM_PREDICT|THINK|REPEAT_PENALTY}`
3. **DB override**: (use case, スロット) キーの行。**NULL 列は下層を継承 MUST**

数値として解釈できない env 値は**警告して無視 MUST**（下層を継承）。
推論フラグの扱い **MUST**: 明示 true かつモデル系統が gemma4 系 → 前置トークン `<|think|>`、
gpt-oss 系 → `Reasoning: high`。明示 false → 前置なし・推論無効。
**未指定のときはモデルが変わっていなければ下層を継承、変わっていれば推論 OFF**。
**根拠**: radar/llm_routing.py:260-276, 321-445
**検証**: tests/test_llm_routing.py::TestEnvOverride::（4 件）；::TestDbOverride::（5 件、
DB > env の優先順位・不正 use case/スロットの拒否を含む）
**分類**: CORE

### S1-INTEL-059: モデル可用性プローブは fail-open かつ 60 秒キャッシュ
**挙動**: 連鎖の先頭から順に「そのモデルがローカルに存在するか」を確認し、
**最初に存在したものを採用 MUST**。どれも存在しなければ **連鎖の先頭を返す MUST**
（呼出し時の HTTP エラーで理由が表面化する）。
プローブ結果はモデル名ごとに **60 秒キャッシュ MUST**。
プローブが非 200 または例外のときは **True（存在する）とみなす MUST**（fail-open、NP3）。
一致判定はタグ完全一致または**コロン前の系統名前方一致**。
**閾値**: 可用性キャッシュ TTL **60 秒**、プローブタイムアウト 5 秒
**根拠**: radar/llm_routing.py:485-532
**検証**: 未検証
**分類**: CORE。fail-open は NP3 由来だが、存在しないモデルを「存在する」と誤答して
副モデルへの退避を妨げる → §4 A8

### S1-INTEL-060: ルーティング状態機械の全遷移
**挙動**: use case が未指定なら**常にレガシー単一モデル・状態 `off` MUST**。
use case 指定時は Feature Hub の対応キーを解決し、以下 **MUST**:

| 状態 | 実行するモデル | shadow モデル名の記録 | 並行呼出し |
|---|---|---|---|
| `on` | v10 解決結果 | なし | なし |
| `shadow_dual` | **レガシー** | v10 主モデル名 | **あり**（v10 を並行実行し別台帳へ） |
| `shadow` | **レガシー** | v10 主モデル名 | なし |
| `off` / 未知 | レガシー | なし | なし |

`shadow` / `shadow_dual` で v10 解決に失敗した場合、**状態ラベルは維持したまま
shadow 記録を諦めてレガシーを返す MUST**。
Feature Hub 解決自体が例外を投げた場合は **状態 `off` + レガシー MUST**。
**この関数は決して例外を送出してはならない MUST**（NP3）。
use case → Feature Hub キーの写像: `sensor_extract`→`model_routing_sensor` /
`verdict`→`model_routing_verdict` / `conclusion` と `narrative`→**`model_routing_conclusion`（共有）** /
`discovery`→`model_routing_etl`。
**根拠**: radar/llm_routing.py:269-276, 543-644
**検証**: tests/test_llm_routing.py::TestChooseModelOff::（2 件）/ TestChooseModelShadow::（2 件）/
TestChooseModelOn::（4 件）/ TestNP3::（2 件）/ TestFeatureHubKeys::（3 件）
**分類**: CORE。**`shadow_dual` を選べる UI/API 経路と、`conclusion`/`narrative` がキーを
共有して個別制御できない点は §4 A9**

### S1-INTEL-061: ルーティング上書きは監査台帳と対で書く
**挙動**: 上書きの設定・解除は**必ず変更前後の値を JSON で追記型台帳へ記録 MUST**
（変更者・理由・時刻を含む）。設定と台帳追記は**同一トランザクション MUST**。
スロットは `primary` / `secondary` のみ許可、不正な use case / スロットは拒否して false **MUST**。
解除時は変更後を NULL として記録 **MUST**。既に無い行の解除は成功扱い **MUST**。
**根拠**: radar/llm_routing.py:650-844
**検証**: tests/test_llm_routing.py::TestDbOverride::test_set_override_persists_and_audit /
test_clear_override_reverts / test_invalid_use_case_rejected / test_invalid_slot_rejected
**分類**: CORE（NP6）

### S1-INTEL-062: 実効ルーティングは LLM を呼ばずに全件可視化できる
**挙動**: 全 (use case, スロット) について、**3 層解決後の実効設定**（モデル / 全サンプリング
パラメータ / 推論可否 / system 前置 / Feature Hub 状態 / 可用性）を返す手段を持つ **MUST**。
これは実 LLM 呼出しを伴わない **MUST**。
**根拠**: radar/llm_routing.py:448-458, 874-906
**検証**: tests/test_llm_routing.py::TestEffectiveRouting::test_snapshot_covers_every_use_case /
test_snapshot_reflects_db_override
**分類**: CORE（NP6: 「次に何が走るか」が事前に見える）

### 2.8 Feature Hub

### S1-INTEL-063: 機能状態の解決は 4 段の優先順位で決まる
**挙動**: 状態解決は以下の順 **MUST**（上位が成立したら下位を見ない）:
1. **グローバル kill switch** — 環境変数、**または** 台帳の予約キー行が `on`
   → **全機能を無条件 `off` MUST**
2. **機能ごとの DB 上書き** — 存在すればその値。解釈不能な値は「上書きなし」扱い **MUST**
3. **env** — 主フラグが真値なら `on`、shadow フラグが真値なら `shadow`、
   **主フラグが優先 MUST**。真値集合は `1` / `true` / `yes` / `on`（大小・前後空白無視）
4. **レジストリ既定値**（env が主・shadow ともに未設定のときのみ）

未登録キーは **`off` を返す MUST**。DB 障害は必ず env + 既定へフォールバックし、
**例外を送出してはならない MUST**（NP3）。
**根拠**: radar/llm_features.py:318-398
**検証**: tests/test_llm_features.py::TestResolveStateEnvDefault::（5 件）/ TestKillSwitch::（3 件）/
TestDBOverride::（5 件）
**分類**: CORE

### S1-INTEL-064: 3 つの述語の意味を分離する
**挙動**: 「適用してよいか」は **`on` のときのみ真 MUST**。
「記録のみ行うか」は **`shadow` のときのみ真 MUST**。
「何か動くか」は **`on` または `shadow` のとき真 MUST**。
**`shadow_dual` はいずれの述語でも真にならない MUST**（呼び出し側は状態値を直接見る必要がある）。
**根拠**: radar/llm_features.py:401-418
**検証**: tests/test_llm_features.py::TestPredicates::（3 件全て）
**分類**: **DEFECT-PRESERVE** — `shadow_dual` が述語群の穴に落ちる。
埋込 dedup が `shadow_dual` に設定されると「何も動かない」扱いになる（§5 DP9）

### S1-INTEL-065: 状態変更は検証 + 追記型監査台帳と対で行う
**挙動**: 状態変更は **MUST**: 未登録キー（予約キーを除く）を拒否 /
不正な状態値を拒否 / **shadow を宣言していない機能への shadow 設定を拒否**。
成功時は現在状態表を upsert し、**変更前状態・変更後状態・変更者・理由・時刻**を
追記型台帳へ記録 **MUST**（同一トランザクション）。
上書き解除は台帳に変更後 `auto` として記録 **MUST**。既に無い行の解除は成功扱い **MUST**。
**根拠**: radar/llm_features.py:424-510
**検証**: tests/test_llm_features.py::TestDBOverride::test_shadow_rejected_when_unsupported /
test_shadow_accepted_when_supported / test_unknown_feature_reject；::TestHistory::（2 件）
**分類**: CORE（NP6）

### S1-INTEL-066: 機能カタログは 4 階層 × 宣言的メタデータで構成する
**挙動**: 全 LLM 機能は**単一のレジストリに宣言 MUST**。各機能は
キー / 階層 / 表示名 / 説明 / 主 env フラグ / shadow env フラグ / 既定状態 /
**NP7 懸念フラグ** / 管理者権限要否 / shadow 対応可否 を持つ **MUST**。
階層は `core`（土台）/ `augment`（判断補強）/ `narrative`（表示のみ）/ `discovery`（構造提案）。
NP7 懸念フラグが立つ機能は **既定状態が shadow 以下でなければならない MUST**。
**キーは DB 行の主キーであり、改名は migration を要する破壊的変更 MUST**。
現行 10 機能: `sensor_intel_extraction`(core, 既定 **on**) /
`auto_judge_recheck`(augment, off, shadow 可) / `attack_mode_augment`(augment, off) /
`triage_narrative`(narrative, off, 非管理者可) / `g3b_cluster_annotator`(discovery, off,
**NP7 懸念**, shadow 可) / `model_routing_{verdict,sensor,etl,conclusion}`(off, shadow 可) /
`embedding_dedupe`(augment, off, shadow 可)。
カタログ照会時は**実効状態と「どの層で決まったか」（`ui_override` / `env` / `default`）を
併せて返す MUST**（NP6）。
**根拠**: radar/llm_features.py:60-104, 113-301, 513-534
**検証**: tests/test_llm_features.py::TestRegistry::（4 件）；::TestListStates::（3 件）
**分類**: CORE

### 2.9 埋込（embedding）

### S1-INTEL-067: 埋込は機能ゲート・空入力・失敗のいずれでもベクトル無しを返す
**挙動**: 埋込は**別 API 経路・別モデル**を用いる **MUST**（構造化生成とは独立した失敗系）。
空文字・空白のみ → 結果 `empty_input`、機能が非 active → `feature_disabled`、
HTTP 非 200 → `http_error`、応答にベクトルが無い → `no_vector`、
タイムアウト・例外 → 対応コード。**いずれもベクトル無しを返し、例外を送出しない MUST**（NP3）。
応答形状は「ベクトルの配列」と「単一ベクトル」の**両形式を受理 MUST**。
バッチ埋込は入力と**同じ添字で整列した結果を返し、失敗要素はベクトル無しにする MUST**。
**閾値**: `LLM_EMBEDDING_MODEL` 既定 **granite-embedding:278m**
**根拠**: radar/llm_embedding.py:96-101, 137-143, 205-291
**検証**: tests/test_llm_routing.py::TestEmbedding::test_disabled_feature_returns_none / test_empty_input
**分類**: CORE

### S1-INTEL-068: 埋込キャッシュは挿入順序を保つ辞書型 LRU
**挙動**: プロセス内キャッシュのキーは **`<モデル名>:<原文>`** **MUST**。
キャッシュ実装は**挿入順序を保持する構造 MUST**（順序リスト + 辞書）— 参照時は
該当キーを最新位置へ移動、追加時に容量超過なら**最古を 1 件退去 MUST**。
**順序を持たない集合型で置き換えてはならない MUST**（LRU 退去が成立しなくなる）。
同じ規律はセンサー層の投入済みキー集合にも適用され、`dict[str, None]` で挿入順を保ち
上限超過時に**先頭半分を一括退去する MUST**。
**閾値**: 埋込 LRU 容量 **2048**、センサー投入済み上限 **1000**（`hacktivist_news` / `ground_osint` は 500）、
超過時の退去量は上限の **1/2**
**根拠**: radar/llm_embedding.py:106-134；radar/sensors/apt_intel.py:157-159, 364-370；
radar/sensors/hacktivist_intel_sensor.py:32-34, 76-83
**検証**: 未検証
**分類**: CORE（intel-pipeline.md の既知の落とし穴 #3）

### S1-INTEL-069: 類似度・近傍判定・言語判定の定義
**挙動**: cosine 類似度は、**片方が空 / 長さ不一致 / ノルム 0 のとき 0.0 MUST**（例外ではない）。
近傍判定は全対 (i < j) を走査し閾値以上の組を返す **MUST**、
**埋込に失敗した要素は誰ともマッチしない MUST**。
言語判定は Unicode ブロック比率による軽量分類 **MUST**で、判定順は
**かな > ハングル > 漢字 > キリル > アラビア**（かなが漢字より先: 日本語は漢字と重なるため）。
比率閾値: かな **> 0.05** / ハングル **> 0.10** / 漢字 **> 0.10** / キリル **> 0.20** / アラビア **> 0.20**。
いずれも満たさなければ `en`、空文字も `en` **MUST**。
**根拠**: radar/llm_embedding.py:61-88, 294-337
**検証**: tests/test_llm_routing.py::TestEmbedding::test_cosine_basic / test_near_duplicates_skips_failed_encodes
**分類**: CORE

### S1-INTEL-070: 埋込呼出しと dedup 判定はそれぞれ台帳に残す
**挙動**: 埋込呼出しは**キャッシュヒットを含め毎回 1 行記録 MUST**:
時刻 / 呼び元 / モデル / 所要ミリ秒 / **原文 sha256** / ベクトル次元 / キャッシュヒット有無 /
結果コード / エラー。
近傍 dedup 判定は別台帳に記録 **MUST**: 対象 item / 一致 item / cosine / 閾値 /
**適用フラグ**（on=1 / shadow=0）/ 言語ラベル / 発生源。
いずれも記録失敗は本処理を止めない **MUST**。
**根拠**: radar/llm_embedding.py:154-202
**検証**: 未検証（GAP-04）
**分類**: CORE（AP3: 言語別の precision 代理指標の算出基盤）

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー | DB override | 出典条項 |
|---|---|---|---|---|
| LLM 有効 | false | `LLM_ENABLED` | 可（ただし投入側は不可） | 001 |
| 最低 confidence | 0.35 | `LLM_CONFIDENCE_MIN` | 不可（env のみ） | 003 |
| dedup 窓 | 48h | — （ハードコード） | 不可 | 005 |
| 埋込 dedup cosine | 0.95 | — （ハードコード） | 不可 | 007 |
| 埋込比較窓 / 件数 | 24h / 50 | — | 不可 | 007 |
| 同型 Jaccard | 0.60 | — （ハードコード） | 不可 | 009 |
| 異型 Jaccard | 0.70 | — （ハードコード） | 不可 | 013 |
| credibility 初期値 | 0.85 / 0.75 / 0.60 / 0.70 | — （表、ハードコード） | 不可 | 014 |
| credibility クランプ | [0.30, 0.95] | — | 不可 | 021 |
| 確認加点 / 誤検知減点 | +0.05 / −0.10 | — | 不可 | 021, 022 |
| archetype 下限 | max(seed − 0.20, 0.30) | — | 不可 | 028 |
| tier1 | conf 0.85 / cred 0.80 | — （ハードコード） | 不可 | 016 |
| tier2 | conf 0.80 / cred 0.75 | `LLM_AUTO_CONFIRM_THRESHOLD`（conf のみ） | 不可 | 016 |
| tier3 | conf 0.70 / cred 0.75 / corr ≥ 1 | `LLM_AUTO_CONFIRM_TIER3_CONF` / `_CRED` | 不可 | 016 |
| 自動確認適格生態系 | {independent, cert, us_gov} | — | 不可 | 016 |
| pending 自動却下 | 24h / 上限 500 | `LLM_PENDING_AUTO_REJECT_HOURS` | 不可 | 025 |
| item TTL | 48h | `INTEL_ITEM_TTL_HOURS` | 不可 | 029 |
| 経年減衰 τ | 12h | `INTEL_AGE_DECAY_TAU_HOURS`（+ source 別） | 不可 | 030 |
| 経年減衰 有効 | true | `INTEL_AGE_DECAY_ENABLED` | 不可 | 030 |
| 寄与キャップ | 2 / (source_type, country) | `INTEL_MAX_ITEMS_PER_SOURCE_THEATER` | 不可 | 031 |
| auto-judge confirm 下限 | 0.70 | `AUTO_JUDGE_CONF_CONFIRM_FLOOR` | 不可 | 035 |
| auto-judge reject 上限 | 0.40 | `AUTO_JUDGE_CONF_REJECT_CEILING` | 不可 | 035 |
| auto-judge 陳腐化 | 48h | `AUTO_JUDGE_STALE_HOURS` | 不可 | 035 |
| auto-judge 照合窓 | 72h / 200 件 | `AUTO_JUDGE_CORROBORATION_HOURS` | 不可 | 035, 036 |
| auto-judge 重複 Jaccard | 0.70 | `AUTO_JUDGE_DUP_JACCARD` | 不可 | 037 |
| 評判ドリフト | 比率 0.75 / 最小 5 件 | `AUTO_JUDGE_SOURCE_REJECT_RATIO` / `_MIN_DECISIONS` | 不可 | 038 |
| LLM 再判定 confidence 下限 | 0.85 | `AUTO_JUDGE_LLM_CONF_FLOOR` | 不可 | 039 |
| LLM 再判定スキップ窓 | 3000s | `AUTO_JUDGE_LLM_SKIP_WINDOW_SEC` | 不可 | 039 |
| 照合窓 / cooldown | 8h / 12h | `CORROBORATION_WINDOW_HOURS` / `_COOLDOWN_HOURS` | 不可 | 043, 045 |
| 照合最小ソース / 独立性 | 2 / 0.70 | `CORROBORATION_MIN_SOURCES` / `_MIN_INDEPENDENCE` | 不可 | 044 |
| 照合 same_event 下限 | 0.55 | — （ハードコード） | 不可 | 046 |
| LLM タイムアウト | 30s | `LLM_TIMEOUT` | **可** | 050 |
| 無害化 最大長 | 1000 | — （引数既定） | 不可 | 053 |
| プロンプト永続化 | false | `V2_LLM_PROMPT_PERSISTENCE_ENABLED` | 不可 | 055 |
| プロンプト保持 | 120d（下限 結論+30d） | `LLM_PROMPTS_RETENTION_DAYS` | 不可 | 056 |
| 呼出しログ保持 | 30d | `LLM_CALL_LOG_RETENTION_DAYS` | 不可 | 056 |
| モデル可用性キャッシュ | 60s | — （ハードコード） | 不可 | 059 |
| 埋込 LRU 容量 | 2048 | — （ハードコード） | 不可 | 068 |
| センサー投入済み上限 | 1000 / 500 | — （ハードコード） | 不可 | 068 |
| スイープ周期 | 3600s（自動却下・auto-judge）/ 1800s（照合） | — | 不可 | 025, 034, 042 |

**v3 への示唆**: **DB override が効くのは `LLM_TIMEOUT` のみ**。dedup 閾値・tier 閾値・
減衰 τ という**結論の強度を直接左右する値が全て再起動なしでは変えられない**。
NP6 の観点では、これら全てが宣言的 registry に載って UI から可視・調整可能であるべき。

---

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | 見出しトークン化が **3 文字以上の英字語のみ**を抽出するため、日本語・中国語・アラビア語・キリル文字の見出しは常に Jaccard 0.0 = 決して dedup されない（S1-INTEL-008） | 多言語 OSINT が主要入力であるのに dedup が英語専用。埋込 dedup が既定 OFF であるため実質無防備。**v3 では言語非依存のトークン化が必須ではないか** |
| A2 | 自動確認適格生態系が {independent, cert, us_gov} の 3 種に固定され、`diplomatic_*` `ground_osint_*` `narrative_*` `hacknews_*` `corroborated_*` は**構造的に自動確認され得ない**（S1-INTEL-016） | 生態系表が military/cert 系だけを網羅した歴史的経緯の結果と読める。全 pending の主因である可能性。**意図的な fail-closed か、単なる表の未整備か** |
| A3 | 採点層の関連性フィルタは「country 空 = グローバル信号 = 常に関連」とするが、S1-SCORE-012 は「グローバル信号は既定でシナリオスコアから分離」と規定（S1-INTEL-033） | 二重定義。LLM intel のグローバル信号がどちらの規則に従うのかが仕様上不定 |
| A4 | 独立ソース群の選択が**入力順依存の貪欲法**で、最大独立集合を保証しない（S1-INTEL-044） | source_type 数が 6 以下なら全探索可能。決定論性（NP6）の観点でも順序依存は望ましくない |
| A5 | LLM 呼出しに**リトライが一切無い**（S1-INTEL-047）。タイムアウト 1 回で当該インテルは失われる | NP1（感度優先）の観点では、一過性の失敗で観測を落とすのは見逃しに直結する。**意図的な単発設計か放置か** |
| A6 | 埋込 dedup が比較のたびに過去 50 件を**毎回再埋込**する（S1-INTEL-007） | 1 投入あたり 51 回の埋込呼出し。ベクトルを永続化しない設計は測定窓限定なら許容だが、ON 昇格時に破綻する |
| A7 | プロンプト永続化が**既定 OFF**（S1-INTEL-055） | NP6 は「LLM プロンプトまで遡及可能であること」を要求する。既定 OFF は NP6 と正面から矛盾する疑い |
| A8 | モデル可用性プローブが fail-open（S1-INTEL-059） | プローブ失敗時に「存在する」と誤答すると副モデルへの退避が起きず、呼出しが確実に失敗する。fail-closed（次候補へ）の方が NP3 の趣旨に合うのではないか |
| A9 | `conclusion` と `narrative` が Feature Hub キーを共有し個別制御できない（S1-INTEL-060）。また `shadow_dual` を設定する UI/API 経路が Feature Hub 側に無い | 表示専用の narrative と結論生成が同時にしか切り替えられない。段階的ロールアウト設計（verdict → sensor → ETL → conclusion）と整合しない |
| A10 | 設計メモ [intel-pipeline.md](../intel-pipeline.md) が実装と乖離: 「auto_confirm = conf 0.80 ∧ cred 0.75」（tier ラダー・生態系ゲート未記載）/「Layer 1 Jaccard ≥ 0.50」（実装 0.60、corroboration の docstring も 0.50）/「Active slots: 2 per group, TTL 24h」（実装 48h） | ドキュメントを実装に合わせるか、実装がドキュメント通りであるべきかの裁定。**現状はどちらを読んでも別の閾値が出てくる** |

---

## 5. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | 条項 / D2 |
|---|---|---|---|
| DP1 | キュー投入は起動時定数 `LLM_ENABLED` を直読みし、Feature Hub の kill switch も DB override も効かない | LLM 機能の有効性は**単一の解決経路**を通る **MUST** | 001 |
| DP2 | URL dedup 経路だけ corroborator 一覧を単独更新し、ecosystem 一覧を同時に書かない | corroborator と ecosystem は**常に対で書く MUST** | 006 |
| DP3 | 処遇ラベルが「同一 caller の直近 60 秒・verdict 空」の行に付くため、1 fetch で複数投入すると処遇と呼出しの対応が崩れる。写像未登録の source_type（`corroborated`）は永久に無記録 | 処遇は**呼出し ID を明示的に引き回して紐づける MUST** | 017 |
| DP4 | `review_needed` は入るだけで出る遷移が無く、到達時に確認者・確認時刻が消去される | 全状態に脱出経路を定義し、provenance を消さない **MUST** | 020, 026 |
| DP5 | 差戻しは credibility を戻すが確認回数カウンタを戻さないため、再シード対象から永久に外れる | 判定の取消は**全ての派生カウンタを整合させる MUST** | 023, 028 |
| DP6 | 適格生態系集合が起動時昇格経路でリテラル再掲されており、共有定数と乖離し得る | 単一定義 **MUST** | 028 / D2 A-02 |
| DP7 | corroborator 計数・重複判定・寄与キャップが**レガシー単一 country フィールド**をキーとするため、countries のみを持つ item は自動確認・重複却下・キャップの全経路から外れる | 識別軸は country リストのみ **MUST** | 002, 031, 036, 037 / D2 C-01 |
| DP8 | 照合合成 item の source_id が生態系表に無く、**自動確認され得ない**。加えて処遇ラベルも記録されない | 合成 item の信頼度・生態系を**明示的に定義する MUST** | 046 |
| DP9 | `shadow_dual` が「有効か」「shadow か」「何か動くか」のいずれの述語でも偽になる | 状態述語は**全状態を網羅する MUST** | 064 |
| DP10 | WS 通知が country 引数を受け取りながら使用せず、全クライアントへ無差別配信 | 購読スコープを契約として定義する **MUST** | 019 / D2 B-07 |

---

## 6. テストトレーサビリティ

### 6.1 BEHAVIOR 級（本仕様が受け持つ全件）

| テストファイル | test 数 | 対応条項 |
|---|---|---|
| test_age_decay.py | 21 | 029, 030, 031, 032 |
| test_intel_auto_judge.py | 17 | 021, 022, 034, 035, 036, 037, 039, 040, 041 |
| test_sanitize_llm_input.py | 17 | 053 |
| test_intel_multicountry.py | 12（うち 2 は SCAFFOLD） | 002, 008, 009, 018, 032 |
| test_llm_prompt_persistence.py | 12 | 051, 055 |
| test_intel_tier3_corroborated.py | 8 | 012, 015, 016, 027 |
| test_llm_features.py | 27（うち 2 は migration = STRUCTURAL） | 063, 064, 065, 066 |
| test_llm_routing.py | 40（うち 6 は migration = STRUCTURAL） | 051, 057, 058, 060, 061, 062, 067, 069 |
| test_llm_log_retention.py | 4（D5 分類 SCAFFOLD、保持値のみ救出） | 056 |

**GAP なしの領域**: 経年減衰 / 自動判定 / 無害化 / tier ラダー / Feature Hub / ルーティング。

### 6.2 CONTRACT 級（S2-API へ写像。本仕様は状態意味論のみ受け持つ）

`test_routes_llm_features.py`(16) → Feature Hub 制御面 /
`test_auto_judge_v2.py`(9) → 自動判定監査面 / `test_intel_confidence_distribution.py`(5) → インテル統計面。

### 6.3 GAP（仕様化できたが検証が無い）

| ID | 内容 | 影響 |
|---|---|---|
| GAP-01 | **照合エンジン全体（S1-INTEL-042〜046）が無テスト** | tier 3 自動確認の前提部品であり、独立性行列・貪欲選択・confidence/score 合成式が全て無検証 |
| GAP-02 | **LLM クライアント本体（047〜052）が無テスト** | JSON 解析 3 段防御・タイムアウト・推論フィールドフォールバック・呼出しログの全てが実装のみ根拠 |
| GAP-03 | 投入 dedup の Layer 0（URL）と Layer 2（異型 Jaccard）が無テスト | URL 正規化規則・80 件走査・0.70 閾値が未検証 |
| GAP-04 | 埋込 dedup の投入内配線（off/shadow/on 分岐、判定台帳記録）が無テスト | shadow → ON 昇格の安全性が測定できない |
| GAP-05 | 差戻し / 上書き / 脅威分類イベント連動（023, 024, 026）が無テスト | credibility の取消規則と `review_needed` 遷移が未検証 |
| GAP-06 | credibility bootstrap / 再シード / archetype 下限 / 遡及昇格（014, 028）が無テスト | 起動シーケンスが本番の pending 分布を書き換えるのに無検証 |
| GAP-07 | 並行 shadow 呼出し（054）が無テスト | 「主呼出しに影響しない」という中核不変条件が未検証 |
| GAP-08 | 評判ドリフト（038）に直接テストが無い | 自動却下の 4 規則のうち 1 つだけ無検証 |

---

## 7. 未決事項

1. **投入前段（センサー → LLM → 投入 dict）の境界が曖昧**。センサー層が LLM を呼ぶ骨格が
   8 箇所に複製され `max_tokens` が 200〜400 でばらつく（D2 A-02）ため、
   「投入される item の品質」がセンサーごとに不均一である。本仕様は投入以降のみを規定したが、
   **P の層設計では投入契約（必須フィールド・確度の意味・domain の決め方）を明文化する必要がある**。
2. **corroborator の定義が 3 箇所で異なる**: dedup 経路（source_id 一覧）/
   auto-judge（同一 country の異 source_type 種類数）/ 照合エンジン（独立性行列）。
   tier 3 は 1 番目を数え、auto-judge の confirm は 2 番目を数える。**統一の要否は裁定待ち**。
3. **`shadow_dual` の運用主体が不明**。Feature Hub の状態値としては存在し、
   ルーティングも並行呼出しを実装しているが、設定 API 側に到達経路があるか未確認（S2 側で確認要）。
4. **credibility の学習則が recall にどう効くかが未評価**。確認 +0.05 / 誤検知 −0.10 の
   非対称性と archetype 下限の相互作用は、較正担当（S1-calibration）と突き合わせる必要がある。
5. GAP-01 / GAP-02 の解消には v3 で**先にテストを書く**判断が要る（S5 のテスト移植計画へ）。
