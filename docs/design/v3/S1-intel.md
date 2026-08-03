# S1 — LLM インテルパイプライン 挙動仕様

**スコープ**: センサーがインテル候補をキューへ投入した瞬間から、重複排除 → 自動確認判定 → 状態遷移 →
採点層へのスコア寄与 → 経年減衰 → 消滅 までの全ライフサイクル、および基盤となる LLM 呼出し層
（呼出し契約 / JSON 解析防御 / モデルルーティング / Feature Hub / embedding / プロンプト永続化）。

**隣接仕様との境界**: センサーが何を観測し何を LLM に渡すか → **S1-sensors-\***。寄与が入った後の
ドメイン集計・収斂・TL 導出 → **S1-scoring-core**。conclusions / calibration での LLM 寄与の扱い →
**S1-conclusions / S1-calibration**。判定 API のエンドポイント形状 → **S2-API**（本書は状態遷移の
意味論のみ）。G.3b クラスタ注釈 → **S3-discovery**（Feature Hub 登録のみ本書）。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソース**: カバレッジが不均一。`test_age_decay`(21) / `test_intel_auto_judge`(17) /
`test_intel_tier3_corroborated`(8) / `test_intel_multicountry`(12) / `test_llm_features`(27) /
`test_llm_routing`(40) / `test_llm_prompt_persistence`(12) / `test_sanitize_llm_input`(17) が pin する
値はテストを一次ソースとした。**投入 dedup の Layer 0/2、LLM クライアント本体、corroboration 合成は
全て無テスト**（§6.3）。設計メモ [intel-pipeline.md](../intel-pipeline.md) との乖離は実装値を CORE とし、
乖離自体を §4 A10 に回した。

---

## 1. 用語

CLAUDE.md の定義に従う（country / scenario / participant / adversary / focused / background）。本書固有:

- **item**: LLM が構造化した 1 件のインテル。`id` は UUID4（センサー指定があればそれを優先）
- **source_type**: `hacktivist` / `diplomatic` / `military` / `ground_osint` / `apt_intel` / `narrative` /
  `corroborated` の 7 値。**source_id**: フィード/チャンネル単位の識別子（例 `cert_cisa_advisories`）
- **credibility**: source_id ごとの信頼度重み [0.30, 0.95]。アナリスト判定でのみ更新される
- **ecosystem**: source_id が属するメディア生態系（`ru_state` / `cn_state` / `ir_state` / `us_gov` /
  `independent` / `cert` / `hacktivist` / 未分類 `""`）
- **verdict tag**: 1 呼出しに紐づく最終処遇（`auto_confirmed` / `auto_confirmed_corroborated` /
  `pending` / `discarded_low_conf` / `discarded_dedup` / `discarded_dedup_xtype` /
  `discarded_dedup_embed` / `sensor_filtered:<reason>`）
- **Feature Hub state**: `off` / `shadow` / `shadow_dual` / `on`。**use case**: `sensor_extract` /
  `verdict` / `conclusion` / `discovery` / `narrative`

---

## 2. 挙動条項

### 2.1 投入パイプライン

### S1-INTEL-001: LLM 無効時は投入を一切受け付けない
**挙動**: グローバル LLM 有効フラグ（`LLM_ENABLED`、既定 false）が偽なら投入は即座に失敗を返し、
DB 書込・ログ記録・WS 通知のいずれも行わない **MUST**。判定は起動時に環境から確定した値を用いる。
**根拠**: radar/intel_queue.py:452-453、radar/config.py:646
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — 呼出し層は Feature Hub 経由で解決する（llm_client.py:410-419）のに
投入側は起動時定数を直読みし、kill switch も DB override も効かない（§5 DP1）

### S1-INTEL-002: countries は明示指定を優先し、無ければ単一 country から導出する
**挙動**: countries があればそれを採用 **MUST**。空でレガシー単一 country があれば `countries=[c]`、
`country_weights={c:1.0}` に展開 **MUST**。両方空ならグローバル信号。
**根拠**: radar/intel_queue.py:463-468
**検証**: test_intel_multicountry::TestSubmitBackwardCompat(2) / TestDBCountryColumns(5)
**分類**: **DEFECT-PRESERVE** — レガシー単一 country は導出元であるだけでなく、dedup・corroboration・
寄与キャップの**主キーとして使われ続ける**（§5 DP7 / D2 C-01）

### S1-INTEL-003: 最低 confidence 未満は破棄し、破棄を可視化する
**挙動**: `confidence < 0.35` の item は破棄 **MUST**。破棄時は (a) 直近呼出しログに verdict
`discarded_low_conf` を付し、(b) 隠れ信号台帳に閾値・実測値・country・sensor・domain を記録 **MUST**。
台帳書込みの失敗は破棄処理を止めない **MUST**（NP3）。
**根拠**: radar/intel_queue.py:37-38, 471-485、radar/database.py:6134-6148
**検証**: 未検証
**分類**: CORE（NP1: 破棄は必ず観測可能でなければならない）

### S1-INTEL-004: 重複排除は 4 層を固定順で適用する
**挙動**: **(1) URL 完全一致（source_type 横断） → (2) 埋込ベクトル近傍 → (3) 同一 source_type 内の
見出し Jaccard → (4) 異 source_type 間の見出し Jaccard** の順で試み、いずれかで一致したら
**item を新規作成せず終了 MUST**。層 1 が最優先なのは計算量ゼロかつ誤判定確率が最小のため。
**根拠**: radar/intel_queue.py:487-718
**検証**: 層 3 のみ（test_intel_multicountry::TestDedupMultiCountry）。層 1/2/4 は GAP-03/04
**分類**: CORE

### S1-INTEL-005: URL 層は正規化 48h 窓で照合し、一致時は corroborator を追記して破棄する
**挙動**: 正規化は scheme を https 固定 / `utm_*` `ref` `source` `fbclid` `gclid` 除去 / 残クエリを
キー昇順に再構築 / path 末尾スラッシュ除去（空なら `/`）、解析例外時は入力をそのまま返す **MUST**。
**16 文字以上のときのみ**照合し、一致が無ければ**生 URL でも 1 回照合 MUST**（窓 48h）。一致時は
投入元 source_id を corroborator に追記（既存と重複しない場合のみ）→ 遅延昇格判定（019）→
verdict `discarded_dedup_xtype` を記録して破棄 **MUST**。
**根拠**: radar/intel_queue.py:312, 317-335, 490-511、radar/database.py:5668-5679
**検証**: 未検証（GAP-03）
**分類**: **DEFECT-PRESERVE** — この経路だけ corroborator を単独更新し **ecosystem 一覧を同時に
書かない**（他 3 経路は必ず対で書く、intel_queue.py:210-225）。独立生態系数が欠落する（§5 DP2）

### S1-INTEL-006: 埋込近傍 dedup は Feature Hub の 3 状態で挙動を変える
**挙動**: `embedding_dedupe` が off なら**埋込呼出しを一切行わない MUST**。active のとき見出し +
本文先頭 500 文字を埋め込み、**同一 source_type の直近 24h・最大 50 件**と総当たりで cosine を計算し
**0.95 以上の最大一致**を採る **MUST**。一致は言語ラベル付きで判定台帳へ記録 **MUST**。
**on のときのみ**破棄し verdict `discarded_dedup_embed`、**shadow では `applied=0` で記録し次層へ
素通し MUST**。本ブロックの例外は全て握り潰しレガシー経路を継続 **MUST**（NP3）。
**根拠**: radar/intel_queue.py:513-581、radar/llm_features.py:282-300
**検証**: 未検証（GAP-04）
**分類**: CORE。過去 50 件を毎回再埋込する点は §4 A6

### S1-INTEL-007: 見出し類似度は stop-word 除去後の Jaccard 係数
**挙動**: 見出しを小文字化し **3 文字以上の英字語のみ**抽出、固定 stop-word 34 語（冠詞・前置詞・
be 動詞・`near` `over` `after` `before` `during` `amid` 等）を除いた集合を作る **MUST**。
類似度は `|A∩B| / |A∪B|`、いずれかが空集合なら **0.0 MUST**。
**根拠**: radar/intel_queue.py:305-310, 338-350
**検証**: test_intel_multicountry::TestDedupMultiCountry::test_same_countries_same_headline_deduped
**分類**: CORE。**非ラテン文字（日/中/ア/キリル）の見出しはトークンが抽出されず常に 0.0 =
決して dedup されない** → §4 A1

### S1-INTEL-008: 同型層は国重なりを前提とし、同一ソースは無条件破棄・別属性は別事象
**挙動**: 同一 source_type の直近 48h・最大 50 件を走査 **MUST**。双方が country を持ちかつ
**共通 country が無ければ別事象として打ち切る MUST**。類似度 **0.60 未満は別事象 MUST**。
0.60 以上で **source_id が同一なら再スクレイプとして無条件破棄**（verdict `discarded_dedup`）**MUST**。
異ソースでは、**帰属アクターが両方存在し（大小無視で）異なる**、または**外交アクション種別が
両方存在し異なる**とき**別事象として dedup しない MUST**（走査継続）。
**根拠**: radar/intel_queue.py:313, 596-637
**検証**: test_intel_multicountry::TestDedupMultiCountry(3 件全て)
**分類**: CORE（NP1: 似た見出しの別事象を潰すのは見逃しに直結する）

### S1-INTEL-009: 同型層の決着は confidence 比較（置換 or corroborator 記録）
**挙動**: 新着 confidence が既存より**厳密に大きい**なら既存の 見出し(200) / confidence /
score_delta / 本文(1000) / URL を上書きし、**旧 source_id を corroborator に加えて corroborator 一覧と
ecosystem 一覧を対で書き込む MUST**。そうでなければ投入元 source_id を corroborator に加え
（未登録時のみ、同じく対で書込み）、遅延昇格判定を実行し verdict `discarded_dedup` を記録 **MUST**。
**いずれの場合も新規 item は作成しない MUST**。
**根拠**: radar/intel_queue.py:210-225, 639-677
**検証**: test_intel_tier3_corroborated::TestLateCorroboratorPromotion
**分類**: CORE

### S1-INTEL-010: 異型層はより厳しい閾値を用いる
**挙動**: 全 source_type 横断の直近 48h・最大 80 件を走査し**自分と同じ source_type はスキップ MUST**。
国重なり条件は同型層と同一。類似度 **0.70 以上**なら corroborator 追記（+ ecosystem 対書込み +
遅延昇格判定）して破棄、verdict `discarded_dedup_xtype` **MUST**。閾値が厳しいのは source_type ごとに
プロンプトが異なり同一記事でも見出しが乖離するため。
**根拠**: radar/intel_queue.py:314, 685-717
**検証**: 未検証（GAP-03）
**分類**: CORE

### S1-INTEL-011: 未知 source_id の credibility は archetype でシードする
**挙動**: 初出 source_id は archetype 表から**最長前置一致**で初期値を決めて台帳へ登録 **MUST**:
政府 CERT（7 前置）**0.85** / 確立した防衛報道（5 前置）**0.75** / 国家系プロパガンダ（2 前置）**0.60** /
ハクティビスト（`hacktivist_`）**0.60** / 一致なし **0.70**。既存ソースは**この経路では上書きしない MUST**。
**根拠**: radar/intel_queue.py:147-158, 279-294, 720-728
**検証**: 未検証（GAP-06）
**分類**: CORE

### S1-INTEL-012: 自動確認は生態系ゲート → 3 段 tier ラダーで決まる
**挙動**: source_id を**最長前置一致**で生態系に写像（一致なしは空文字）**MUST**。初期状態は以下の順で
決定し、最初に成立した段で確定 **MUST**:

| 段 | 条件 | status / verdict tag |
|---|---|---|
| 生態系ゲート | ecosystem ∉ {`independent`, `cert`, `us_gov`} | `pending` / `pending`（**conf・cred を問わない**） |
| tier 1 | conf ≥ **0.85** ∧ cred ≥ **0.80** | `auto_confirmed` / `auto_confirmed` |
| tier 2 | conf ≥ **0.80** ∧ cred ≥ **0.75** | `auto_confirmed` / `auto_confirmed` |
| tier 3 | conf ≥ **0.70** ∧ cred ≥ **0.75** ∧ corroborator ≥ **1** | `auto_confirmed` / `auto_confirmed_corroborated` |
| 既定 | — | `pending` / `pending` |

生態系ゲートは fail-closed で **tier 3 でも緩和されない MUST**。成立段はログに tier 名とともに記録 **MUST**。
**根拠**: radar/intel_queue.py:34-47, 165-276, 737-751
**検証**: test_intel_tier3_corroborated::TestTier3Corroborated(6 件) / test_tier1_strict_unchanged
**分類**: CORE。**`diplomatic_*` `ground_osint_*` `narrative_*` `hacknews_*` `corroborated_*` は
構造的に自動確認され得ない** → §4 A2

### S1-INTEL-013: 処遇ラベルは直近の LLM 呼出しログ行へ後追いで書き込む
**挙動**: 全処遇は **source_type → caller 名の静的写像**を引き、直近 **60 秒以内**の **verdict が空の**
呼出しログ行 1 件に書き込む **MUST**。写像に無い source_type は**何も記録しない MUST**。失敗は投入を止めない。
**根拠**: radar/intel_queue.py:356-383、radar/database.py:5011-5036
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — 1 fetch で N 件投入すると処遇が**同一 caller の別 item の行**へ順に付き
対応が崩れる。写像に `corroborated` が無く照合合成の処遇は永久に無記録（§5 DP3）

### S1-INTEL-014: 永続レコードの必須フィールドと受理通知
**挙動**: 受理 item は以下を持って永続化 **MUST**: `id` / source_type / source_id / country 群 /
`ts`（無指定なら投入時刻）/ status / confidence / 本文 / URL / 見出し / LLM 抽出フィールド /
`score_delta`（float、既定 0.0）/ `domain`（既定 `info`）/ `confirmed_by`(None) /
`confirmed_at`（自動確認なら投入時刻、他は None）/ `override_at`(None) / `created_at`。
永続化後、`id` / 見出し(120) / source_type / status を**全クライアントへブロードキャスト MUST**。
WS 未初期化を含む例外は握り潰す **MUST**。
**根拠**: radar/intel_queue.py:730-784、radar/ws.py:147-154、radar/database.py:5595-5617
**検証**: test_intel_multicountry::TestDBCountryColumns(5 件)
**分類**: CORE。通知が country 引数を未使用で無差別配信する点は §5 DP10 / D2 B-07

### 2.2 状態機械

### S1-INTEL-015: item の状態集合と許可された遷移
**挙動**: 状態は `auto_confirmed` / `pending` / `confirmed` / `rejected` / `overridden` /
`review_needed` の 6 値 **MUST**。許可される遷移は以下のみ **MUST**:

| 遷移 | 前提状態 | 契機 | 後状態 |
|---|---|---|---|
| 手動確認 / 却下 | `pending` | アナリスト / 自動判定 | `confirmed` / `rejected` |
| 差戻し | `confirmed` / `rejected` | アナリスト | `pending` |
| 上書き | `auto_confirmed` | アナリスト（**時間制限なし**） | `overridden` |
| 遅延昇格 | `pending` | corroborator 追加 | `auto_confirmed` |
| 期限切れ却下 | `pending` | 毎時スイープ | `rejected` |
| 起動時昇格 | `pending` | 起動シーケンス | `auto_confirmed` |
| 要再確認 | `auto_confirmed` / `confirmed` | 脅威分類イベント | `review_needed` |

前提状態を満たさない要求は**失敗を返し状態を変更しない MUST**。
**根拠**: radar/intel_queue.py:385-430, 788-934, 1110-1149
**検証**: test_intel_auto_judge::TestAutoJudgePending::test_non_pending_item_returns_pending_action；
test_intel_tier3_corroborated::TestLateCorroboratorPromotion
**分類**: **DEFECT-PRESERVE** — `review_needed` から出る遷移が無く到達 item は永久に滞留（§5 DP4）

### S1-INTEL-016: 遷移の副作用（信頼度更新と自動判定台帳の上書き記録）
**挙動**: **確認** → アクティブ集合へ追加、確認回数 +1、credibility **+0.05**。**却下** → 分類
`false_positive` のときのみ誤検知回数 +1・**−0.10**、`irrelevant`（既定）では**変更しない MUST**
（報告自体はソースの責任ではない）。**差戻し** → `confirmed` からのときのみ除去し **−0.05**、
`rejected` からは無影響。**上書き** → 除去し誤検知として **−0.10**。以上すべて **MUST**、
credibility は常に **[0.30, 0.95] にクランプ MUST**。実行者が `auto:` で始まらない（= 人間）場合、
自動判定台帳の直近の適用済み判断を**「人間に上書きされた」と記録 MUST**。この記録の失敗は
**警告ログ + 障害台帳への記録が必須 MUST**（沈黙の失敗は自動判定の recall/precision を静かに狂わせる）。
**根拠**: radar/intel_queue.py:788-934、radar/database.py:5815-5843, 4501-4519
**検証**: test_intel_auto_judge::TestAutoJudgeApply::test_apply_confirm_marks_analyst_marker /
_apply_reject_marks_analyst_marker / _human_override_marks_ledger（差戻し・上書きは GAP-05）
**分類**: CORE。差戻しが確認回数カウンタを戻さない点は §5 DP5

### S1-INTEL-017: 放置された pending の自動却下と脅威分類イベントによる再確認要求
**挙動**: **自動却下** — `created_at` が **24h** より古い `pending` を最大 500 件、実行者 `auto` として
却下 **MUST**（閾値 0 以下なら無効化、**credibility に影響しない MUST**、周期 3600s）。
**脅威分類イベント** — 提出時刻の 1 時間前以降にアクティブだった最大 20 件の item のソースについて、
分類 `confirmed_threat` なら確認・`false_positive` / `exercise` なら誤検知として credibility を更新 **MUST**。
誤検知側で item がまだアクティブなら `review_needed` にしアクティブ集合から除去 **MUST**。
**根拠**: radar/intel_queue.py:59-62, 896-966、radar/scheduler.py:172, 217
**検証**: 未検証（GAP-05）
**分類**: **DEFECT-PRESERVE** — `review_needed` への遷移時に実行者・確認時刻を渡さないため
**元の確認 provenance が消去される**（NP6 違反）。加えて到達先が終端（§5 DP4）

### S1-INTEL-018: corroborator 追加のたびに pending を再判定する
**挙動**: dedup 経路で既存 pending に corroborator が追加されたら**その場で自動確認判定を再実行 MUST**。
tier 3 を満たすなら昇格し（実行者は空、確認時刻のみ記録）アクティブ集合へ追加、処遇を記録 **MUST**。
再判定は**最新の DB 状態を読み直す MUST** — 投入時点の item は corroborator 0 件で自力では tier 3 に
到達し得ないため、この経路が無いと tier 3 は死に機能となる。
**根拠**: radar/intel_queue.py:385-430
**検証**: test_intel_tier3_corroborated::TestLateCorroboratorPromotion::test_pending_promoted_when_dedup_adds_corroborator
**分類**: CORE

### S1-INTEL-019: 起動時に信頼度の再シード・下限適用・遡及昇格を行う
**挙動**: 起動の復元シーケンスで順に 1 回ずつ **MUST**: (1) **再シード** — archetype 値と乖離しかつ
**確認回数も誤検知回数も 0** のソースを archetype 値へ戻す（学習済み状態は保護）。(2) **下限適用** —
全ソースに `max(archetype − 0.20, 0.30)` を下限として適用、**学習済み状態のソースにも適用する MUST**
（過去の「対象外」却下による不当な減点の是正）。(3) **遡及昇格** — `pending` かつ conf ≥ 自動確認閾値
かつ cred ≥ 0.75 かつ生態系が適格な item を最大 500 件、実行者 `system_reseed` として昇格。
**根拠**: radar/intel_queue.py:1058-1149、radar/persistence.py:118-128
**検証**: 未検証（GAP-06）
**分類**: CORE。適格生態系集合が共有定数ではなくリテラル再掲である点は §5 DP6

### 2.3 スコア寄与と経年減衰

### S1-INTEL-020: 寄与対象の選別・指数的経年減衰・件数上限
**挙動**: 採点入力は `auto_confirmed` と `confirmed` のみ（各最大 100 件）**MUST**。**上書き時刻を持つ
item は除外**、`ts` からの経過が **48h**（ハード下限）を超えるものも除外 **MUST**。
寄与は `score_delta × exp(−max(0, age_sec) / (τ_hours × 3600))` **MUST**: age=0 → **1.0** /
age=τ → **1/e ≈ 0.3679** / age=2τ → **e⁻² ≈ 0.1353**、負の age は **0 にクランプ MUST**。
τ は **source_type ごとに上書き可能 MUST**（数値解釈不能なら全体既定へフォールバック **MUST**）、
τ ≤ 0 または減衰無効なら重みは **常に 1.0 MUST**（無効判定は `false`/`0`/`no`/`off`/空文字のみを偽とする）。
寄与は **(source_type, country) の組ごとに 2 件**まで **MUST**、順位付けは**減衰後スコアの降順、
同点は confidence の降順 MUST**（古い高スコア item は枠から押し出される）。組が違えば互いに独立 **MUST**。
**根拠**: radar/intel_queue.py:49-57, 64-106, 983-1017
**検証**: test_age_decay::TestAgeWeight(10) / TestDecayEnabled(4) / TestGetActiveRationaleDecay の
_fresh_item_gets_full_score / _aged_item_decays / _item_beyond_ttl_excluded / _overridden_items_excluded /
_decay_disabled_uses_raw_score / _cap_ranks_by_decayed_score / _multiple_groups_independent
**分類**: CORE（ADR-023）。グループ化キーがレガシー単一 country である点は §5 DP7

### S1-INTEL-021: 寄与ペイロードは検証可能な来歴を必ず含む
**挙動**: 各寄与は以下を含む **MUST**: 減衰後スコア / 減衰前スコア / 経過時間 / 減衰重み / confidence /
domain / country 群 / 状態 `FIRED` / 非抑止 / **一次ソース URL** / **LLM の判断理由** /
**原文の観測時刻** / **見出し** / **原文** / source_type / source_id。表示文字列は
`[SOURCE_TYPE] 見出し (age N.Nh, w=0.NN)` の形 **MUST**（減衰が目視で追える）。
信号系統は `llm_intel` 固定 **MUST**（S1-scoring-core の dedup 単位となる）。
**根拠**: radar/intel_queue.py:1019-1047
**検証**: test_age_decay::TestGetActiveRationaleDecay::test_detail_string_contains_age_and_weight；
test_intel_multicountry::TestActiveRationale(2 件)
**分類**: CORE（NP6）

### S1-INTEL-022: 採点層への関連性フィルタ（境界条項）
**挙動**: 寄与がシナリオに算入されるのは、(a) country も countries も空（グローバル信号 → 常に関連）、
(b) countries とシナリオ参加国に共通要素がある、(c) レガシー単一 country が参加国に含まれる、の
いずれかのときのみ **MUST**。以降の集計・収斂・TL 導出は **S1-scoring-core の管轄**。
寄与の取り込み失敗は**警告ログ + 障害台帳記録 MUST**（沈黙の欠落は脅威の隠蔽と等価）。
**根拠**: radar/routes/core.py:1892-1930, 2059-2082
**検証**: 未検証（間接のみ）
**分類**: CORE。(a) は S1-SCORE-012（グローバル信号は既定でシナリオスコアから分離）と方向が逆 → §4 A3

### 2.4 自動判定

### S1-INTEL-023: 自動判定は毎時・LLM 非依存で走り、6 段の決定論規則で決まる
**挙動**: `pending` を最大 200 件取得し 1 件ずつ評価・適用 **MUST**。1 件の失敗は他を止めず、結果は
評価数 / confirm / reject / pending / errors で返す **MUST**。**LLM 利用不能でも決定論部分は完全に
動作する MUST**（空気遮断環境要件）。`pending` 以外は即座に「pending（`not_pending`）」**MUST**。
規則は**この順**で評価し最初の成立を返す **MUST**:

| 順 | 判定 | 条件 | 理由コード |
|---|---|---|---|
| 1 | reject | 受理済み item と見出しが重複 | `duplicate_of_accepted` |
| 2 | reject | ソースの誤検知比率が閾値超 | `source_reputation_drift` |
| 3 | reject | conf ≤ **0.40** ∧ corroborator 0 | `low_confidence_no_corroboration` |
| 4 | reject | 経過 ≥ **48h** ∧ corroborator 0 | `stale_no_corroboration` |
| 5 | confirm | conf ≥ **0.70** ∧ corroborator ≥ 1 ∧ 生態系が適格 | `confidence_plus_corroboration` |
| 6 | pending | 上記いずれも不成立 | `ambiguous_middle_band` |

内部例外は全て pending に落とす **MUST**（NP1: 迷ったら人間へ）。
**根拠**: radar/intel_auto_judge.py:55-96, 349-441, 604-634、radar/scheduler.py:220-236
**検証**: test_intel_auto_judge::TestAutoJudgeReject(3) / TestAutoJudgeConfirm(1) /
TestAutoJudgePending(3) / TestAutoJudgeApply::test_run_sweep_returns_counts
**分類**: CORE（NP3）

### S1-INTEL-024: corroborator は「同一 country・別 source_type・非却下」の異種数
**挙動**: corroborator 数は、**同一 country（レガシー単一フィールド）・窓 72h・最大 200 件**の中で
自分自身でなく、状態が `rejected` でなく、**source_type が自分と異なる**ものの **source_type 種類数** **MUST**。
country が空の item は **corroborator 0 とする MUST**。独立性の粒度は source_type 止まりで、
生態系単位の独立性判定は照合エンジン（027）の責務 **MUST**。
**根拠**: radar/intel_auto_judge.py:178-209
**検証**: test_intel_auto_judge::TestAutoJudgeConfirm::test_confidence_plus_corroboration_confirms /
TestAutoJudgePending::test_high_confidence_no_corroborator_stays_pending
**分類**: **DEFECT-PRESERVE** — country 空 → 0 という規則により、**countries のみを持つ item は永久に
corroborator を得られず tier 3・自動確認・重複却下の全経路から外れる**（§5 DP7）

### S1-INTEL-025: 重複却下とソース評判ドリフトの定義
**挙動**: **重複却下** — 同一 country・窓内・状態 `confirmed` / `auto_confirmed` の peer と見出し
Jaccard **0.70 以上**なら却下 **MUST**（見出し・トークン・country のいずれかが空なら判定しない **MUST**）。
**評判ドリフト** — `誤検知回数 / (確認回数 + 誤検知回数)` が **0.75 以上**かつ判定総数 **5 件以上**の
ときドリフトとみなす **MUST**。総数 5 件未満なら**ドリフトなし MUST**（新規ソースを 1〜2 件の却下で
潰さない）。分母には**「対象外」却下を含めない**（誤検知回数のみ）**MUST**。
**根拠**: radar/intel_auto_judge.py:81-96, 212-270
**検証**: test_intel_auto_judge::TestAutoJudgeReject::test_duplicate_of_accepted_rejects（ドリフトは GAP-08）
**分類**: CORE

### S1-INTEL-026: LLM 第 2 パスは中間帯のみ・交差証拠必須・冪等ガード付き
**挙動**: 決定論が中間帯に落ちた item に限り `auto_judge_recheck` が shadow / on のとき LLM 再評価を
行う **MUST**。以下 4 ゲートを**全て**満たさない限り pending を覆せない **MUST**:
(1) **冪等ガード** — 同一 item の直近台帳行が **50 分以内**かつ **corroborator 数が同一**なら LLM 呼出しを
**丸ごとスキップ**（入力不変なら出力も不変）。(2) **交差証拠ゲート（ハードコード）** — corroborator ≥ 1
でなければ LLM が何を返しても**反転しない**、shadow 時も有効。(3) **confidence 下限** — LLM 自己申告が
**0.85 未満**なら反転しない。(4) **適用ゲート** — **on のときのみ適用**、shadow では台帳に記録するが
決定論の pending が優先。応答 `action` は `{confirm, reject, pending}` に限定検証 **MUST**、`pending` は
反転しない **MUST**、理由は 120 文字で切る **MUST**。LLM 到達不能・例外・解析失敗では反転しない **MUST**
（NP3）。呼出しは use case `verdict`、temperature 0.0、max_tokens 200。
**根拠**: radar/intel_auto_judge.py:123-159, 273-318, 414-441, 456-564
**検証**: test_intel_auto_judge::TestAutoJudgeApply::test_llm_recheck_gated_off_by_default /
_blocked_by_layer1_when_no_corroborator / _flips_when_layer1_satisfied /
_skip_guard_avoids_redundant_calls / _skip_guard_re_runs_when_corroborators_change
**分類**: CORE（非対称 NP1: 幻覚由来の反転は構造的に阻止するが、阻止自体は見逃しを生まない）

### S1-INTEL-027: 自動判定は必ず台帳に記録し、決定論と LLM を別マーカーで区別する
**挙動**: LLM を呼び出したら**判定が pending でも下限未満でも必ず**台帳へ 1 行記録 **MUST**:
item ID / 提案アクション / LLM confidence / 理由 / corroborator 数 / 交差証拠充足フラグ / 適用フラグ。
初回は `applied=0`、実際に適用するときのみ直近行を `applied=1` に更新 **MUST**（ECE 較正が採用した
反転だけでなく LLM 出力分布全体に対して計算できるため）。台帳失敗は判定を止めない **MUST**。
適用は通常の確認/却下経路を通す **MUST**。マーカーは `auto:rule_confirm` / `auto:rule_reject` /
`auto:llm_recheck_confirm` / `auto:llm_recheck_reject` の 4 種 **MUST**。自動却下は必ず分類
**`irrelevant`** を用いる **MUST**（ファクトチェックではないため信頼度を減点しない）。
**根拠**: radar/intel_auto_judge.py:115-120, 321-347, 518-563, 567-601、radar/database.py:4461-4519
**検証**: test_intel_auto_judge::TestAutoJudgeApply::test_llm_recheck_writes_calibration_ledger /
_apply_confirm_marks_analyst_marker / _apply_reject_marks_analyst_marker
**分類**: CORE（AP4 判断履歴 / NP7: 自動判断は人間の判断と統計上分離できねばならない）

### 2.5 独立ソース照合

### S1-INTEL-028: 照合パスの周期・候補条件・cooldown
**挙動**: 照合は **1800 秒周期**、起動直後は **300 秒待って**初回を走らせる **MUST**。LLM 無効・到達
不能なら**何もしない MUST**。候補は窓 **8h** 内の最大 500 件から、source_type が実センサー 6 種
（`hacktivist` / `ground_osint` / `diplomatic` / `military` / `narrative` / `apt_intel`）で状態が
`auto_confirmed` / `confirmed` / `pending` のもの **MUST**。**合成済み item は除外 MUST**（再帰防止）。
候補は country 単位でグループ化し **country が空の item は捨てる MUST**。発火した country は
**12h** ロック **MUST**、期限切れロックは毎パスで掃除 **MUST**。
**根拠**: radar/intel_corroboration.py:95-96, 104-109, 143-186, 209-223、radar/scheduler.py:719-739
**検証**: 未検証（GAP-01）
**分類**: CORE

### S1-INTEL-029: 独立性は対称行列 + 貪欲選択で決まる
**挙動**: source_type 対ごとの独立性（0.0 = 同一データ流、1.0 = 完全独立）を**対称な参照表**から引く **MUST**、
未登録の対は既定 **0.70**。同一 source_type 同士は**単一要素集合として引かれる MUST**。選択は入力順の
貪欲法で**既選択の全メンバーとの独立性が 0.70 以上**のものだけを追加 **MUST**、選択数が最小ソース数
（既定 2）未満なら照合しない **MUST**。主要な低独立性の対: `ground_osint`×`hacktivist` = **0.15**
（同一 Telegram 流）、`military`×`military` = **0.20**（通信社増幅）、`narrative`×`diplomatic` = 0.50、
`narrative`×`hacktivist` / `narrative`×`ground_osint` = 0.45。
**根拠**: radar/intel_corroboration.py:54-137
**検証**: 未検証（GAP-01）
**分類**: CORE（NP2 の中核）。貪欲法は順序依存で最大独立集合を保証しない → §4 A4

### S1-INTEL-030: 合成は同一事象判定 + confidence 下限を通過したときのみ行う
**挙動**: 独立群の各 source_type から **confidence 最大の 1 件**を代表に選び LLM に同一事象性を判定
させる **MUST**。応答が解析不能 / `same_event` が偽 / confidence < **0.55** のいずれかで中止 **MUST**。
通過時 **MUST**: `confidence = min(LLM conf + min((n−2)×0.03, 0.06), 0.95)`、
`score_delta = round(urgency 基礎点 + min((n−2)×0.3, 0.9), 1)`（critical **3.0** / high **2.5** /
medium **2.0**(既定) / low **1.5**）、domain は `{cyber, physical, info, mixed}` に限定検証・既定 `mixed`。
生成 item は source_type `corroborated`、source_id `corroborated_<country>`、`countries=[country]`(重み 1.0)、
LLM 抽出フィールドに**貢献ソース種別・貢献 source_id・貢献 item ID・判断理由・独立ソース数**を含める **MUST**。
生成 item は**通常の投入経路を通す MUST**（dedup も自動確認判定も等しく適用）。
**根拠**: radar/intel_corroboration.py:193-207, 229-341
**検証**: 未検証（GAP-01）
**分類**: CORE。生成 item の生態系が未分類となり**恒久的に pending に留まる**点は §5 DP8

### 2.6 LLM 呼出し基盤

### S1-INTEL-031: 構造化呼出しは JSON 強制の単発試行 + 3 段の解析防御
**挙動**: 構造化応答は JSON 強制モードを用いる **MUST**。**リトライは行わない MUST** — HTTP 非 200 /
タイムアウト / 例外は 1 回の試行で確定し、理由コード（`HTTP <code>` / `timeout` / 例外文字列 /
`json_parse_failed` / `LLM_ENABLED=false`）付きで失敗を返す **MUST**。解析は **(1) コードフェンス除去**
（行頭が ``` の行を全削除）→ **(2) 直接解析** → **(3) 最初の `{` から最後の `}` を切り出して再解析** の
順 **MUST**。3 段すべて失敗なら `parse_failed` として記録し**応答先頭 200 文字をエラー欄に保存 MUST**。
数値は**範囲外なら既定値ではなくクランプ MUST**（1.001 → 1.0）、型変換不能・None は既定値 **MUST**。
列挙は許可集合に**厳密一致**しなければ既定値 **MUST**、予期しない値はログに残す **MUST**（品質劣化検知）。
応答本文が空なら**推論フィールドを本文として採用 MUST**（この場合トレースは別途保存しない **MUST**）、
本文が非空で推論有効なら推論テキストを**別欄として呼出しログに保存 MUST**。タイムアウトは
**毎回 3 層 config から読み直す MUST**（既定 30s、DB override 可）、失敗時は起動時の環境値へフォールバック。
**根拠**: radar/llm_client.py:33-44, 117-149, 519-522, 532-697、radar/config.py:649
**検証**: 未検証（GAP-02）
**分類**: CORE（推論フィールド採用は intel-pipeline.md 落とし穴 #1）。リトライ不在は §4 A5

### S1-INTEL-032: 呼出しログとセンサー層の脱落記録
**挙動**: 1 呼出しにつき **MUST**: 時刻 / 呼び元モジュール名（スタック推定、失敗時 `unknown`）/
**実際に走ったモデル** / 所要ミリ秒 / 結果コード（`ok` / `http_error` / `timeout` / `exception` /
`parse_failed` / `disabled` / `pre_filter`）/ 処遇ラベル（初期は空）/ confidence / 見出し(200) /
エラー(300) / **プロンプト sha256** / **use case** / **shadow モデル名** / **推論トレース(4000)**。
さらに 2 種の脱落を区別 **MUST**: **投入前スキップ**（LLM を呼ばず諦めた）→ `pre_filter` の**合成行を
新規挿入**、**投入後ドロップ**（LLM は呼んだが結果を捨てた）→ 直近行を `sensor_filtered:<理由>` に
**後追い更新**。**これらの記録の失敗は本処理を絶対に止めてはならない MUST**。
**根拠**: radar/llm_client.py:192-242, 362-405、radar/database.py:4390-4425
**検証**: test_llm_routing::TestLlmClientUseCaseLog(1) / TestRoutingStats(4)
**分類**: CORE（NP6 / AP3: 沈黙したセンサーの理由が UI から見える）

### S1-INTEL-033: 外部テキストの無害化は 4 段の固定パイプライン
**挙動**: LLM に渡す非信頼テキストは順に **MUST**: (1) 空入力は空文字 / 最大長（既定 **1000 文字**）で
**先に切り詰め**、(2) **NFKC 正規化**（全角・互換・丸囲みを正準 ASCII へ）、(3) **制御文字除去** —
C0（タブ・改行・復帰を除く）/ DEL / C1 / ゼロ幅文字群 / 行・段落区切り / **双方向テキスト明示上書き** /
単語結合子・BOM、(4) **命令上書きパターンを `[...]` へ置換**。パターン集合は英語（命令無効化・
ペルソナ乗っ取り・jailbreak・プロンプト暴露）/ 日本語 / 中国語 / ロシア語 / **チャットテンプレート
区切りトークン**を含む **MUST**（大小無視の単一走査）。**正当な文章に含まれる単語（`ignore` 単独等）を
検閲してはならない MUST**。タブ・改行・復帰は保存 **MUST**。
**根拠**: radar/llm_client.py:61-112, 152-183
**検証**: test_sanitize_llm_input(17 件全て。homoglyph 連鎖・双方向上書き・4 言語命令句・区切りトークン)
**分類**: CORE（S4 セキュリティ仕様と相互参照）

### S1-INTEL-034: 並行 shadow 呼出しは主呼出しに一切影響しない
**挙動**: ルーティングが `shadow_dual` のとき、主呼出しの**成功後に**候補モデルへ同一プロンプトで
並行呼出しし、主呼出し ID に紐づけて記録 **MUST**（モデル / 所要ミリ秒 / 結果 / 応答本文(8000) /
応答 sha256 / 抽出 confidence / プロンプト sha256 / エラー）。**主呼出し ID が有効でなければ実行しない MUST**。
**あらゆる例外を握り潰し、主呼出しの戻り値を変えてはならない MUST**（NP3）。
**根拠**: radar/llm_client.py:245-342, 666-688、radar/database.py:4427-4459
**検証**: 未検証（GAP-07）
**分類**: CORE。コスト倍増のため測定窓限定の運用を前提とする

### S1-INTEL-035: プロンプトは sha256 でデデュープして永続化し、結論より長く保持する
**挙動**: 識別子は `sha256(system ‖ 0x00 ‖ prompt)` **MUST**（同一 user プロンプトでも system が違えば
別行）。永続化は sha256 主キーの upsert で、既存なら**最終使用時刻を更新し使用回数 +1 MUST**。本文は
`system ‖ "\n\x00\n" ‖ prompt`（system が空なら prompt のみ）**MUST**。**秘密値を含むプロンプトは
永続化を拒否 MUST** — 監視対象環境変数（JWT 秘密鍵 / 既定管理者パスワード / 各種 API トークン）の値が
**8 文字以上**でプロンプト中に現れたら警告して**保存しない MUST**（空の環境値は照合対象外 **MUST**）。
保存失敗でも **LLM 呼出しは続行 MUST**。剪定は**最終使用時刻**基準で、保持日数は設定値と
**「結論保持日数 + 30 日」の大きい方を採る MUST**（運用者がいくら短く設定しても生存中の結論は必ず
プロンプトを解決できる — NP6 の下限保証）。
**根拠**: radar/llm_prompts.py:34-107、radar/llm_client.py:345-359, 580-582、radar/database.py:5451-5475
**検証**: test_llm_prompt_persistence(12 件全て)；test_llm_log_retention(4 件)
**分類**: CORE（NP6「プロンプトまで遡及可能」の実装）。**既定 OFF である点は §4 A7**

### 2.7 モデルルーティング

### S1-INTEL-036: use case ごとに主・副モデルの連鎖を持つ
**挙動**: 5 use case それぞれに (主, 副) の連鎖を持つ **MUST**。コード既定:

| use case | 主 | 副 | 主のサンプリング |
|---|---|---|---|
| `sensor_extract` | mistral-small3.2:24b | gemma4:26b | temp 0.1 / top_p 1.0 / num_predict 512 |
| `verdict` | gemma4:26b | mistral-small3.2:24b | temp **0.0** / top_k **1** / **seed 42** / 128 |
| `conclusion` | gemma4:31b | gemma4:26b | temp 1.0 / top_p 0.95 / top_k 64 / 1024 |
| `discovery` | gemma4:31b | gpt-oss-safeguard:20b | temp 0.5 / top_p 0.95 / top_k 64 / 1024 |
| `narrative` | gemma4:26b | （なし） | temp 0.7 / top_p 0.95 / top_k 64 / 512 |

`verdict` は**決定性が要件**であるため temperature 0・top_k 1・固定 seed **MUST**。**全 use case で
推論モードは既定 OFF MUST** — 構造化呼出しは JSON 応答を要求するのに推論有効時はトークン予算が
内部思考に費やされ本文が空になるため（実測: 解析成功率 0%）。推論 OFF のときは**呼出しペイロードで
明示的に無効化する MUST**（推論可能モデルは既定でオンになるため）。
**根拠**: radar/llm_routing.py:120-254
**検証**: test_llm_routing::TestChooseModelOn(4 件全て)
**分類**: CORE

### S1-INTEL-037: 設定はコード → env → DB の 3 層をパラメータ単位で解決し、可用性は fail-open
**挙動**: 各 (use case, スロット) の設定は **(1) コード既定 → (2) env
`LLM_ROUTING_<USECASE>_<SLOT>_{MODEL|TEMP|TOP_P|TOP_K|SEED|NUM_PREDICT|THINK|REPEAT_PENALTY}` →
(3) DB override 行** の順で**パラメータごとに独立に**上書きされる **MUST**（DB の NULL 列は下層を継承、
数値解釈不能な env 値は**警告して無視**）。推論フラグ **MUST**: 明示 true かつ gemma4 系 → 前置
`<|think|>`、gpt-oss 系 → `Reasoning: high`、明示 false → 前置なし・推論無効、**未指定はモデル不変なら
下層継承・モデル変更なら推論 OFF**。連鎖は先頭から可用性を確認し**最初に存在したものを採用 MUST**、
どれも無ければ**先頭を返す MUST**。プローブは **60 秒キャッシュ MUST**、**非 200 または例外時は
「存在する」とみなす MUST**（fail-open、NP3）。
**根拠**: radar/llm_routing.py:260-276, 321-445, 485-532
**検証**: test_llm_routing::TestEnvOverride(4) / TestDbOverride(5、DB > env・不正値拒否を含む)
**分類**: CORE。fail-open が副モデルへの退避を妨げる点は §4 A8

### S1-INTEL-038: ルーティング状態機械の全遷移
**挙動**: use case が未指定なら**常にレガシー単一モデル・状態 `off` MUST**。指定時は Feature Hub の
対応キーを解決し以下 **MUST**:

| 状態 | 実行モデル | shadow モデル名の記録 | 並行呼出し |
|---|---|---|---|
| `on` | v10 解決結果 | なし | なし |
| `shadow_dual` | **レガシー** | v10 主モデル名 | **あり**（別台帳へ記録） |
| `shadow` | **レガシー** | v10 主モデル名 | なし |
| `off` / 未知 | レガシー | なし | なし |

`shadow` / `shadow_dual` で v10 解決に失敗した場合、**状態ラベルは維持したまま shadow 記録を諦めて
レガシーを返す MUST**。Feature Hub 解決自体が例外なら **状態 `off` + レガシー MUST**。
**この解決は決して例外を送出してはならない MUST**（NP3）。キー写像:
`sensor_extract`→`model_routing_sensor` / `verdict`→`model_routing_verdict` /
`conclusion` と `narrative`→**`model_routing_conclusion`（共有）** / `discovery`→`model_routing_etl`。
**根拠**: radar/llm_routing.py:269-276, 543-644
**検証**: test_llm_routing::TestChooseModelOff(2) / TestChooseModelShadow(2) / TestNP3(2) / TestFeatureHubKeys(3)
**分類**: CORE。キー共有と `shadow_dual` 設定経路の不在は §4 A9

### S1-INTEL-039: ルーティング上書きは監査台帳と対で書き、実効値は LLM なしで可視化できる
**挙動**: 上書きの設定・解除は**必ず変更前後の値を JSON で追記型台帳へ記録 MUST**（変更者・理由・
時刻を含む）。設定と台帳追記は**同一トランザクション MUST**。スロットは `primary` / `secondary` のみ
許可、不正な use case / スロットは拒否 **MUST**。解除は変更後を NULL として記録 **MUST**、既に無い行の
解除は成功扱い **MUST**。全 (use case, スロット) の**3 層解決後の実効設定**（モデル / 全サンプリング /
推論可否 / system 前置 / Feature Hub 状態 / 可用性）を**実 LLM 呼出しなしで返す手段を持つ MUST**。
**根拠**: radar/llm_routing.py:448-458, 650-844, 874-906
**検証**: test_llm_routing::TestDbOverride(4) / TestEffectiveRouting(2)
**分類**: CORE（NP6: 「次に何が走るか」が事前に見える）

### 2.8 Feature Hub

### S1-INTEL-040: 機能状態の解決は 4 段の優先順位で決まり、3 述語で消費される
**挙動**: 解決は **(1) グローバル kill switch**（環境変数**または**台帳の予約キー行が `on`）→
**全機能を無条件 `off` MUST**、**(2) 機能ごとの DB 上書き**（解釈不能な値は「上書きなし」扱い **MUST**）、
**(3) env**（主フラグが真値なら `on`、shadow フラグが真値なら `shadow`、**主フラグが優先 MUST**。
真値集合は `1`/`true`/`yes`/`on`、大小・前後空白無視）、**(4) レジストリ既定値**（env が主・shadow
ともに未設定のときのみ）の順 **MUST**。未登録キーは **`off` MUST**。DB 障害は必ず env + 既定へ
フォールバックし**例外を送出しない MUST**（NP3）。述語は「適用してよいか」= `on` のみ真 **MUST**、
「記録のみか」= `shadow` のみ真 **MUST**、「何か動くか」= `on` または `shadow` **MUST**。
**根拠**: radar/llm_features.py:318-418
**検証**: test_llm_features::TestResolveStateEnvDefault(5) / TestKillSwitch(3) / TestDBOverride(5) / TestPredicates(3)
**分類**: **DEFECT-PRESERVE** — `shadow_dual` がいずれの述語でも偽になり、埋込 dedup を
`shadow_dual` にすると「何も動かない」扱いになる（§5 DP9）

### S1-INTEL-041: 状態変更は検証 + 追記型監査台帳と対で行う
**挙動**: 状態変更は **MUST**: 未登録キー（予約キーを除く）を拒否 / 不正な状態値を拒否 /
**shadow を宣言していない機能への shadow 設定を拒否**。成功時は現在状態表を upsert し、
**変更前状態・変更後状態・変更者・理由・時刻**を追記型台帳へ記録 **MUST**（同一トランザクション）。
上書き解除は台帳に変更後 `auto` として記録 **MUST**、既に無い行の解除は成功扱い **MUST**。
**根拠**: radar/llm_features.py:424-510
**検証**: test_llm_features::TestDBOverride の shadow 可否 3 件 / TestHistory(2)
**分類**: CORE（NP6）

### S1-INTEL-042: 機能カタログは 4 階層 × 宣言的メタデータで構成する
**挙動**: 全 LLM 機能は**単一レジストリに宣言 MUST**。各機能は キー / 階層 / 表示名 / 説明 /
主 env フラグ / shadow env フラグ / 既定状態 / **NP7 懸念フラグ** / 管理者権限要否 / shadow 対応可否 を
持つ **MUST**。階層は `core` / `augment` / `narrative`（表示のみ）/ `discovery`（構造提案）。
NP7 懸念フラグが立つ機能は**既定状態が shadow 以下 MUST**。**キーは DB 行の主キーであり改名は
migration を要する破壊的変更 MUST**。現行 10 機能: `sensor_intel_extraction`(core, 既定 **on**) /
`auto_judge_recheck`(augment, off, shadow 可) / `attack_mode_augment`(augment, off) /
`triage_narrative`(narrative, off, 非管理者可) / `g3b_cluster_annotator`(discovery, off, **NP7 懸念**,
shadow 可) / `model_routing_{verdict,sensor,etl,conclusion}`(off, shadow 可) / `embedding_dedupe`(augment,
off, shadow 可)。照会時は**実効状態と「どの層で決まったか」（`ui_override`/`env`/`default`）を併せて返す MUST**。
**根拠**: radar/llm_features.py:60-104, 113-301, 513-534
**検証**: test_llm_features::TestRegistry(4) / TestListStates(3)
**分類**: CORE（NP6）

### 2.9 埋込

### S1-INTEL-043: 埋込の失敗モードと類似度・言語判定の定義
**挙動**: 埋込は**別 API 経路・別モデル**を用いる **MUST**（構造化生成と独立した失敗系）。空文字/空白
のみ → `empty_input`、機能が非 active → `feature_disabled`、HTTP 非 200 → `http_error`、ベクトル欠落 →
`no_vector`、タイムアウト・例外 → 対応コード。**いずれもベクトル無しを返し例外を送出しない MUST**（NP3）。
応答は「ベクトルの配列」と「単一ベクトル」の**両形式を受理 MUST**。バッチは**入力と同じ添字で整列し
失敗要素はベクトル無し MUST**。cosine は**片方が空 / 長さ不一致 / ノルム 0 のとき 0.0 MUST**（例外では
ない）。近傍判定は全対 (i<j) 走査で**埋込失敗要素は誰ともマッチしない MUST**。言語判定は Unicode
ブロック比率による軽量分類で、判定順は**かな > ハングル > 漢字 > キリル > アラビア**（かなが漢字より
先: 日本語は漢字と重なる）、閾値 かな **>0.05** / ハングル・漢字 **>0.10** / キリル・アラビア **>0.20**、
いずれも満たさなければ `en`、空文字も `en` **MUST**。
**根拠**: radar/llm_embedding.py:61-101, 137-143, 205-337
**検証**: test_llm_routing::TestEmbedding(4 件全て)
**分類**: CORE

### S1-INTEL-044: dedup キャッシュは挿入順序を保つ辞書型 LRU でなければならない
**挙動**: 埋込キャッシュのキーは **`<モデル名>:<原文>`** **MUST**。実装は**挿入順序を保持する構造 MUST**
（順序リスト + 辞書）— 参照時は該当キーを最新位置へ移動、追加時に容量超過なら**最古を 1 件退去 MUST**。
**順序を持たない集合型で置き換えてはならない MUST**（LRU 退去が成立しなくなる）。同じ規律はセンサー層の
投入済みキー集合にも適用され、挿入順を保つ辞書で上限超過時に**先頭半分を一括退去する MUST**。
容量は 埋込 **2048**、センサー投入済み **1000**（`hacktivist_news` / `ground_osint` は 500）。
**根拠**: radar/llm_embedding.py:106-134；radar/sensors/apt_intel.py:157-159, 364-370；
radar/sensors/hacktivist_intel_sensor.py:32-34, 76-83
**検証**: 未検証
**分類**: CORE（intel-pipeline.md 落とし穴 #3。集合型への置換は明示的に禁止されている）

### S1-INTEL-045: 埋込呼出しと dedup 判定はそれぞれ台帳に残す
**挙動**: 埋込呼出しは**キャッシュヒットを含め毎回 1 行記録 MUST**: 時刻 / 呼び元 / モデル /
所要ミリ秒 / **原文 sha256** / ベクトル次元 / キャッシュヒット有無 / 結果コード / エラー。近傍 dedup
判定は別台帳に記録 **MUST**: 対象 item / 一致 item / cosine / 閾値 / **適用フラグ**（on=1 / shadow=0）/
言語ラベル / 発生源。いずれも記録失敗は本処理を止めない **MUST**。
**根拠**: radar/llm_embedding.py:154-202
**検証**: 未検証（GAP-04）
**分類**: CORE（AP3: 言語別 precision 代理指標の算出基盤）

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー | DB override | 条項 |
|---|---|---|---|---|
| LLM 有効 | false | `LLM_ENABLED` | 不可（投入側） | 001 |
| 最低 confidence | 0.35 | `LLM_CONFIDENCE_MIN` | 不可 | 003 |
| dedup 窓 / 走査上限 | 48h / 50・80 件 | — （ハードコード） | 不可 | 005, 008, 010 |
| 埋込 cosine / 窓 / 件数 | 0.95 / 24h / 50 | — （ハードコード） | 不可 | 006 |
| 同型 / 異型 Jaccard | 0.60 / 0.70 | — （ハードコード） | 不可 | 008, 010 |
| credibility 初期値 | 0.85 / 0.75 / 0.60 / 0.70 | — （表、ハードコード） | 不可 | 011 |
| credibility クランプ / 加点 / 減点 | [0.30,0.95] / +0.05 / −0.10 | — | 不可 | 016 |
| archetype 下限 | max(seed − 0.20, 0.30) | — | 不可 | 019 |
| tier1 / tier2 / tier3 | 0.85∧0.80 / 0.80∧0.75 / 0.70∧0.75∧corr≥1 | tier2 conf=`LLM_AUTO_CONFIRM_THRESHOLD`、tier3=`LLM_AUTO_CONFIRM_TIER3_CONF`/`_CRED` | 不可 | 012 |
| 自動確認適格生態系 | {independent, cert, us_gov} | — | 不可 | 012 |
| pending 自動却下 | 24h / 上限 500 | `LLM_PENDING_AUTO_REJECT_HOURS` | 不可 | 017 |
| item TTL | 48h | `INTEL_ITEM_TTL_HOURS` | 不可 | 020 |
| 経年減衰 τ / 有効 | 12h（source 別 override 可）/ true | `INTEL_AGE_DECAY_TAU_HOURS` / `_ENABLED` | 不可 | 020 |
| 寄与キャップ | 2 / (source_type, country) | `INTEL_MAX_ITEMS_PER_SOURCE_THEATER` | 不可 | 020 |
| auto-judge confirm / reject | 0.70 / 0.40 | `AUTO_JUDGE_CONF_CONFIRM_FLOOR` / `_REJECT_CEILING` | 不可 | 023 |
| auto-judge 陳腐化 / 照合窓 | 48h / 72h・200 件 | `AUTO_JUDGE_STALE_HOURS` / `_CORROBORATION_HOURS` | 不可 | 023, 024 |
| auto-judge 重複 Jaccard | 0.70 | `AUTO_JUDGE_DUP_JACCARD` | 不可 | 025 |
| 評判ドリフト | 比率 0.75 / 最小 5 件 | `AUTO_JUDGE_SOURCE_REJECT_RATIO` / `_MIN_DECISIONS` | 不可 | 025 |
| LLM 再判定 conf 下限 / スキップ窓 | 0.85 / 3000s | `AUTO_JUDGE_LLM_CONF_FLOOR` / `_LLM_SKIP_WINDOW_SEC` | 不可 | 026 |
| 照合窓 / cooldown | 8h / 12h | `CORROBORATION_WINDOW_HOURS` / `_COOLDOWN_HOURS` | 不可 | 028 |
| 照合最小ソース / 独立性 | 2 / 0.70（未登録対も 0.70） | `CORROBORATION_MIN_SOURCES` / `_MIN_INDEPENDENCE` | 不可 | 029 |
| 照合 same_event 下限 / 上限 | 0.55 / 0.95 | — （ハードコード） | 不可 | 030 |
| LLM タイムアウト | 30s | `LLM_TIMEOUT` | **可** | 031 |
| 無害化 最大長 | 1000 | — （引数既定） | 不可 | 033 |
| プロンプト永続化 | false | `V2_LLM_PROMPT_PERSISTENCE_ENABLED` | 不可 | 035 |
| プロンプト / 呼出しログ保持 | 120d（下限 結論+30d）/ 30d | `LLM_PROMPTS_RETENTION_DAYS` / `LLM_CALL_LOG_RETENTION_DAYS` | 不可 | 035 |
| モデル可用性キャッシュ | 60s | — （ハードコード） | 不可 | 037 |
| 埋込 LRU / センサー投入済み上限 | 2048 / 1000・500 | — （ハードコード） | 不可 | 044 |
| スイープ周期 | 3600s（自動却下・auto-judge）/ 1800s（照合、起動遅延 300s） | — | 不可 | 017, 023, 028 |

**v3 への示唆**: **DB override が効くのは `LLM_TIMEOUT` のみ**。dedup 閾値・tier 閾値・減衰 τ という
**結論の強度を直接左右する値が全て再起動なしでは変えられない**。NP6 の観点では、これら全てが
宣言的 registry に載って UI から可視・調整可能であるべき。

---

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | 見出しトークン化が **3 文字以上の英字語のみ**を抽出するため、日/中/ア/キリル文字の見出しは常に Jaccard 0.0 = 決して dedup されない（007） | 多言語 OSINT が主要入力なのに dedup が英語専用。埋込 dedup が既定 OFF のため実質無防備。v3 では言語非依存トークン化が必須ではないか |
| A2 | 自動確認適格生態系が 3 種に固定され `diplomatic_*` `ground_osint_*` `narrative_*` `hacknews_*` `corroborated_*` は**構造的に自動確認され得ない**（012） | 生態系表が military/cert 系だけを網羅した歴史的経緯と読める。pending 滞留の主因の可能性。**意図的 fail-closed か、単なる表の未整備か** |
| A3 | 採点層は「country 空 = グローバル信号 = 常に関連」とするが、S1-SCORE-012 は「グローバル信号は既定でシナリオスコアから分離」と規定（022） | 二重定義。LLM intel のグローバル信号がどちらの規則に従うのか仕様上不定 |
| A4 | 独立ソース群の選択が**入力順依存の貪欲法**で最大独立集合を保証しない（029） | source_type ≤ 6 なら全探索可能。決定論性（NP6）の観点でも順序依存は望ましくない |
| A5 | LLM 呼出しに**リトライが一切無い**（031）。タイムアウト 1 回で当該インテルは失われる | NP1（感度優先）の観点では一過性の失敗で観測を落とすのは見逃しに直結。意図的な単発設計か放置か |
| A6 | 埋込 dedup が比較のたびに過去 50 件を**毎回再埋込**する（006） | 1 投入あたり 51 回の埋込呼出し。ベクトル非永続は測定窓限定なら許容だが ON 昇格時に破綻する |
| A7 | プロンプト永続化が**既定 OFF**（035） | NP6 は「LLM プロンプトまで遡及可能」を要求する。既定 OFF は NP6 と正面から矛盾する疑い |
| A8 | モデル可用性プローブが fail-open（037） | プローブ失敗時に「存在する」と誤答すると副モデルへ退避せず呼出しが確実に失敗する。fail-closed の方が NP3 の趣旨に合うのではないか |
| A9 | `conclusion` と `narrative` が Feature Hub キーを共有し個別制御できない。また `shadow_dual` を設定する経路が Feature Hub 側に無い（038, 040） | 表示専用 narrative と結論生成が同時にしか切り替えられず、段階的ロールアウト設計（verdict→sensor→ETL→conclusion）と整合しない |
| A10 | 設計メモ [intel-pipeline.md](../intel-pipeline.md) が実装と乖離: 「auto_confirm = conf 0.80 ∧ cred 0.75」（tier ラダー・生態系ゲート未記載）/「Layer 1 Jaccard ≥ 0.50」（実装 0.60、corroboration の docstring も 0.50）/「Active slots: 2 per group, TTL 24h」（実装 48h） | どちらを正とするかの裁定。**現状はどちらを読んでも別の閾値が出てくる** |

---

## 5. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | 条項 / D2 |
|---|---|---|---|
| DP1 | 投入は起動時定数を直読みし、Feature Hub の kill switch も DB override も効かない | LLM 機能の有効性は**単一の解決経路**を通る **MUST** | 001 |
| DP2 | URL dedup 経路だけ corroborator 一覧を単独更新し ecosystem 一覧を同時に書かない | 両者は**常に対で書く MUST** | 005 |
| DP3 | 処遇ラベルが「同一 caller の直近 60 秒・verdict 空」の行に付くため 1 fetch 複数投入で対応が崩れる。写像未登録の `corroborated` は永久に無記録 | 処遇は**呼出し ID を明示的に引き回して紐づける MUST** | 013 |
| DP4 | `review_needed` は入るだけで出る遷移が無く、到達時に実行者・確認時刻が消去される | 全状態に脱出経路を定義し provenance を消さない **MUST** | 015, 017 |
| DP5 | 差戻しは credibility を戻すが確認回数カウンタを戻さず、再シード対象から永久に外れる | 判定の取消は**全ての派生カウンタを整合させる MUST** | 016, 019 |
| DP6 | 適格生態系集合が起動時昇格経路でリテラル再掲され共有定数と乖離し得る | 単一定義 **MUST** | 019 / D2 A-02 |
| DP7 | corroborator 計数・重複判定・寄与キャップが**レガシー単一 country**をキーとするため、countries のみを持つ item は自動確認・重複却下・キャップの全経路から外れる | 識別軸は country リストのみ **MUST** | 002, 020, 024 / D2 C-01 |
| DP8 | 照合合成 item の source_id が生態系表に無く**自動確認され得ない**。処遇ラベルも記録されない | 合成 item の信頼度・生態系を**明示的に定義する MUST** | 030 |
| DP9 | `shadow_dual` が 3 述語のいずれでも偽になる | 状態述語は**全状態を網羅する MUST** | 040 |
| DP10 | WS 通知が country 引数を未使用で、全クライアントへ無差別配信 | 購読スコープを契約として定義する **MUST** | 014 / D2 B-07 |

---

## 6. テストトレーサビリティ

### 6.1 BEHAVIOR 級（**対応条項なしのテストは無し**）

| テストファイル | test 数 | 対応条項 |
|---|---|---|
| test_age_decay.py | 21 | 020, 021 |
| test_intel_auto_judge.py | 17 | 015, 016, 023, 024, 025, 026, 027 |
| test_sanitize_llm_input.py | 17 | 033 |
| test_intel_multicountry.py | 12（2 件は SCAFFOLD） | 002, 007, 008, 014, 021 |
| test_llm_prompt_persistence.py | 12 | 032, 035 |
| test_intel_tier3_corroborated.py | 8 | 009, 012, 015, 018 |
| test_llm_features.py | 27（2 件は migration = STRUCTURAL） | 040, 041, 042 |
| test_llm_routing.py | 40（6 件は migration = STRUCTURAL） | 032, 036, 037, 038, 039, 043 |
| test_llm_log_retention.py | 4（D5 分類 SCAFFOLD、保持値のみ救出） | 035 |

**CONTRACT 級**（S2-API へ写像。本書は状態意味論のみ）: `test_routes_llm_features.py`(16) /
`test_auto_judge_v2.py`(9) / `test_intel_confidence_distribution.py`(5)。

### 6.2 GAP（仕様化できたが検証が無い）

| ID | 内容 | 影響 |
|---|---|---|
| GAP-01 | **照合エンジン全体（028〜030）が無テスト** | tier 3 の前提部品。独立性行列・貪欲選択・confidence/score 合成式が全て無検証 |
| GAP-02 | **LLM クライアント本体（031）が無テスト** | JSON 解析 3 段防御・タイムアウト・推論フィールドフォールバックが実装のみ根拠 |
| GAP-03 | 投入 dedup の Layer 0 と Layer 2（005, 010）が無テスト | URL 正規化規則・80 件走査・0.70 閾値が未検証 |
| GAP-04 | 埋込 dedup の投入内配線と判定台帳（006, 045）が無テスト | shadow → ON 昇格の安全性が測定できない |
| GAP-05 | 差戻し / 上書き / 脅威分類イベント連動（016, 017）が無テスト | credibility の取消規則と `review_needed` 遷移が未検証 |
| GAP-06 | credibility bootstrap / 再シード / 下限 / 遡及昇格（011, 019）が無テスト | 起動シーケンスが本番の pending 分布を書き換えるのに無検証 |
| GAP-07 | 並行 shadow 呼出し（034）が無テスト | 「主呼出しに影響しない」という中核不変条件が未検証 |
| GAP-08 | 評判ドリフト（025 後段）に直接テストが無い | 自動却下 4 規則のうち 1 つだけ無検証 |

---

## 7. 未決事項

1. **投入前段（センサー → LLM → 投入 dict）の境界が曖昧**。LLM 投入骨格が 8 箇所に複製され
   `max_tokens` が 200〜400 でばらつく（D2 A-02）ため投入 item の品質がセンサーごとに不均一。
   **P の層設計では投入契約（必須フィールド・確度の意味・domain の決め方）の明文化が要る**。
2. **corroborator の定義が 3 箇所で異なる**: dedup 経路（source_id 一覧）/ 自動判定（同一 country の
   異 source_type 種類数）/ 照合エンジン（独立性行列）。tier 3 は 1 番目、自動判定の confirm は
   2 番目を数える。**統一の要否は裁定待ち**。
3. **`shadow_dual` の運用主体が不明**。状態値として存在しルーティングも並行呼出しを実装しているが、
   設定 API 側に到達経路があるか未確認（S2 側で確認要）。
4. **credibility の学習則が recall にどう効くかが未評価**。確認 +0.05 / 誤検知 −0.10 の非対称性と
   archetype 下限の相互作用は S1-calibration と突き合わせる必要がある。
5. GAP-01 / GAP-02 の解消には v3 で**先にテストを書く**判断が要る（S5 のテスト移植計画へ）。
