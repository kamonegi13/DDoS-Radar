# S1 — 較正機構 挙動仕様

**スコープ**: ground-truth ラベル生成 → recall/precision メトリクス → 閾値較正（提案・台帳・系譜）→
提案系（生成・ガード・状態機械・適用）→ 自動適用 tier 統治 → LLM 較正系（注釈・信頼度下限・ETL・手動実行）。
スコアリング式そのものは S1-scoring-core、結論 envelope と `calibration_status` の**出力形**は S1-conclusions、
較正 API の HTTP 契約は S2-api、センサー健全性の一次判定は S1-sensors-* が担当する。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**最重要要件**: 較正層は運用開始後 **3 回壊れた**。各インシデントの修正で入ったガードは v3 で
**挙動として厳密に保存する**。該当条項には「由来: インシデント #n」を明記した。

| # | 日付 | 事象 | 主要な修正 |
|---|------|------|-----------|
| #1 | 2026-05-29 | blanket-TP: RSS ETL が全マッチを TRUE_POSITIVE にし FN≡0・recall 1.0 固定 | 17,758 行 purge、内部ソース由来 FN の廃止（循環性） |
| #2 | 2026-07-03 | **TL 反転**: 分類器が 5=最悪として実装され約 30k ラベルが逆転。middle_east 閾値が −5% ×12 | `severity.py` 新設、全比較を severity 空間へ、エピソード粒度、鮮度ゲート |
| #3 | 2026-08-02 | **クロスシナリオ帰属汚染**: 支援役の言及で他紛争の記事が別シナリオの ground truth に。korea 閾値が −5% ×4 | 帰属を conflict-party role に限定、kinetic tier を action 動詞必須化、鮮度ゲートの direction-keyed 化 |

**一次ソース**: 実装 + テスト。docstring は**一次ソースとして採用しない**（E-18 が示すとおり
記述ドリフトが systemic）。素材: [_drafts/S1-calibration-llm-raw.md](_drafts/S1-calibration-llm-raw.md)、
[_drafts/S1-calibration-proposals-raw.md](_drafts/S1-calibration-proposals-raw.md)。

---

## 1. 用語

CLAUDE.md の用語定義に従う。本書固有:

- **TL**: 脅威レベル。**1=CRITICAL … 5=NORMAL（DEFCON 式）**。大小比較は必ず `severity = 6 − TL`
  に変換してから行う（S1-CALIB-001）。この規約の違反がインシデント #2 の直接原因
- **ラベル**: `TRUE_POSITIVE` / `FALSE_POSITIVE` / `TRUE_NEGATIVE` / `FALSE_NEGATIVE` の 4 値のみ
- **エピソード**: ground truth の**トライアル単位**。`(scenario_id, country, UTC 日)`。1 外部事象 = 1 トライアル
- **cell**: recall 集計の単位。`(scenario_id, conclusion_type)`
- **提案 (proposal)**: 較正が生成する変更案。適用は別経路（アナリスト API または auto-apply）
- **impact**: 提案の危険度 low / med / high。「recall を増やす方向は low、減らす方向は high」
- **tier**: 自動適用の許可レベル 0-3。0 = 提案のみ、3 = 全 impact 自動適用
- **rejection reason**: 提案が出なかった理由コード（文字列）

---

## 2. 挙動条項

### A. ラベル生成（ground truth ETL）

#### S1-CALIB-001: TL の順序比較は severity 空間を経由しなければならない
**挙動**: TL の大小比較・閾値比較を行うすべての箇所は `severity = 6 − TL` に変換した値で比較 **MUST**。
生の TL 整数を `<` / `>` で比較してはならない **MUST NOT**。変換関数は 1..5 の範囲外に対し
**例外を送出 MUST**（未パース状態文字列を静かに誤採点させない）。
**根拠**: radar/conclusions/severity.py:32-43、TL_CRITICAL=1 … TL_NORMAL=5（:23-27）
**検証**: tests/test_severity.py（8 件、逆転番兵）
**分類**: CORE。**由来: インシデント #2**（5 週間、平穏な誤判定を報酬していた）

#### S1-CALIB-002: ground truth の帰属は conflict-party role に限定する
**挙動**: あるシナリオのラベル生成に使ってよい国は、role が
`{adversary, primary_target, principal_belligerent, proxy_front}` の participant のみ **MUST**。
`primary_ally` / `forward_base` / `strategic_observer` 等の支援役は**帰属に使ってはならない MUST NOT**。
センシング（bg_observer）側は全 participant の広い網を維持 **MUST**（NP1、ラベルとセンシングで
要求精度が異なる）。RSS ETL と ACLED/GDELT ETL の**両方**に同一ゲートを適用 **MUST**。
**根拠**: radar/scenarios.py:49-61（CONFLICT_PARTY_ROLES）, :130-139；
scripts/run_rss_etl.py:162-174；scripts/run_ground_truth_etl.py:278-290
**検証**: tests/test_scenarios.py:380,392,399；tests/test_run_rss_etl.py:576；
tests/test_remediate_cross_scenario_labels.py::test_supporting_role_episode_is_contaminated / _conflict_party_episode_is_kept
**分類**: CORE。**由来: インシデント #3**（korea の FN 15 件中 12 件がイラン/ウクライナ記事）

#### S1-CALIB-003: 帰属国が空のシナリオはスキップし、失敗させない
**挙動**: シナリオが未知（削除・改名）または conflict-party role の participant が 0 の場合、
当該シナリオの conclusions は**ラベル付けせずスキップ MUST**（例外を投げない）。
スキップ件数はカウンタに計上 **MUST**。
**根拠**: scripts/run_ground_truth_etl.py:285-290,338-342；scripts/run_rss_etl.py:352-354
**検証**: tests/test_run_ground_truth_etl.py
**分類**: CORE

#### S1-CALIB-004: ラベル規則の評価順序は FN > TP > FP > TN
**挙動**: 分類規則は**この順に評価し、最初に成立したものを採用 MUST**。いずれも成立しなければ
ラベルを付けない（`None` = 「現時点の証拠と矛盾しないが TN を宣言できるだけの horizon が未経過」）**MUST**。
この順序は NP1（見逃しを最優先で表面化する）を encode したものであり、順序変更は仕様変更 **MUST NOT**。
**根拠**: radar/conclusions/ground_truth_etl.py:241-377（規則 1-4 の直列評価）
**検証**: tests/test_ground_truth_etl.py（39 件、D5 §重要度 4 位）
**分類**: CORE

#### S1-CALIB-005: FALSE_NEGATIVE は「TL=5 かつ外部の高強度事象」でのみ成立する
**挙動**: conclusion が THREAT_LEVEL かつ state が **TL=5（NORMAL）** であり、forward window 内の
participant 国で **ACLED 由来**かつ `severity >= fn_severity` の事象が 1 件以上あるとき FN **MUST**。
`fn_severity` の既定は 10（`GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES`）。
**根拠**: ground_truth_etl.py:231-238（_is_quiet_threat_level）, :311-325；config.py:306-307
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #2**（旧実装は TL==1 = CRITICAL を「平穏」と判定していた）

#### S1-CALIB-006: 内部ソースは FALSE_NEGATIVE の根拠にしてはならない
**挙動**: `llm_intel` / `sequence_events` 由来の証拠は FN 判定に**使ってはならない MUST NOT**
（これらはスコアリングエンジンが消費するのと同じ信号であり、発火すれば TL 自体が上がるため
「ツール自身が見逃したもの」を原理的に暴けない = 循環）。TRUE_POSITIVE の corroboration
としては引き続き有効 **MUST**（そこでは「正しかったこと」の確認であり循環しない）。
**根拠**: ground_truth_etl.py:299-315（除去理由をコード内に明記）
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #1**

#### S1-CALIB-007: TRUE_POSITIVE は alert 結論 + window 内の任意の適格事象
**挙動**: conclusion が alert（S1-CALIB-008）であり、forward window 内に適格事象が 1 件以上あるとき
TP **MUST**。forward window は `[observed_at, observed_at + window_hours×3600]` の**両端閉区間 MUST**
（結論時刻ちょうどの participant 事象は corroboration であってノイズではない）。
**閾値**: `GROUND_TRUTH_WINDOW_HOURS` 既定 **72**
**根拠**: ground_truth_etl.py:124-139,290-297,327-337；config.py:296
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE

#### S1-CALIB-008: alert の定義は TL≤3 または FIRED な ATTACK_MODE に限る
**挙動**: alert = (THREAT_LEVEL かつ `severity_of(TL) >= 3`、すなわち **TL ≤ 3**) または
(ATTACK_MODE かつ state が非空で `INSUFFICIENT_DATA` でない) **MUST**。
**TREND / PER_DOMAIN は alert に含めない MUST NOT**（診断面であり、自動ラベル化は Design W の
主 recall 指標を汚すだけのノイズを生む）。state の数値化に失敗したら alert でない **MUST**。
**根拠**: ground_truth_etl.py:202-228
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #2**（旧実装 `int(state) >= 3` は CRITICAL/SEVERE を除外していた）

#### S1-CALIB-009: FALSE_POSITIVE / TRUE_NEGATIVE は horizon 全経過後にのみ宣言できる
**挙動**: `now >= observed_at + fp_horizon_days×86400` を満たさない限り FP も TN も宣言しない **MUST**
（`None` を返し次パスで再評価）。経過後、horizon 窓内に適格事象が **0 件**のとき、
alert 結論 → FP、TL=5 結論 → TN **MUST**。
**閾値**: `GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS` 既定 **7**
**根拠**: ground_truth_etl.py:339-375；config.py:300-301
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE

#### S1-CALIB-010: 不在を主張するラベルは corroboration 由来を騙ってはならない
**挙動**: FP / TN の `analyst_id` は **`auto:horizon` MUST**。これらは事象の**不在**を主張する
ラベルであり、いかなる証拠ソースにも corroborate されていないため、ソース名を名乗ってはならない **MUST NOT**。
**根拠**: ground_truth_etl.py:74-77,355,368
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #1**（ACLED 未設定でも `auto:acled` を騙っていた）

#### S1-CALIB-011: 自動ラベルの identity は「ソースごとに 1 票」を表現する
**挙動**: corroboration ラベルの `analyst_id` は次の優先順で決定 **MUST**:
ACLED∧GDELT→`auto:both` / ACLED→`auto:acled` / GDELT→`auto:gdelt` /
LLM∧SEQUENCE→`auto:mixed` / LLM→`auto:llm_intel` / SEQUENCE→`auto:sequence`。
これは `distinct_analysts` 集計が自動一致を **N 独立投票者ではなく 1 投票者**として数えるための
契約 **MUST**（自動ラベルが人手フィードバックを recall 較正で押し流すのを防ぐ）。
`observed_outcome_url` は最高 severity の事象のもの、`notes` はソース内訳と top_severity を
機械可読形式で記録し 240 文字で切る **MUST**。
**根拠**: ground_truth_etl.py:22-28,66-77,146-199
**検証**: tests/test_ground_truth_etl.py；tests/test_report_recall_metrics.py::test_distinct_analysts_counts_auto_sources_as_separate_voters
**分類**: CORE

#### S1-CALIB-012: graded under-rating は期待 severity floor との比較で判定する
**挙動**: 外部 kinetic 事象の規模から**ツールが示しているべきだった最小 severity** を導出 **MUST**:
`fatalities >= mass_casualty_threshold`（既定 10）→ **4**（SEVERE 以上 = TL≤2）／
`fatalities >= 1` または `confidence >= 0.60` → **3**（HIGH 以上 = TL≤3）／
それ以外 → **2**（ELEVATED 以上 = TL≤4）。判定は `severity_of(tool_tl) < floor` → FN、
それ以外 → TP **MUST**。TL→severity 変換はこの 1 箇所でのみ行う **MUST**。
**根拠**: ground_truth_etl.py:380-450
**検証**: tests/test_ground_truth_etl.py（severity floor 群）
**分類**: CORE（NP1: TL=5 の二値トリップワイヤでは段階的な過小評価を捕捉できない）

#### S1-CALIB-013: kinetic tier は action 動詞を要求し、裸の武器名詞では発火しない
**挙動**: kinetic（暴力が起きた）tier の認定には**行為を表す動詞**を要求 **MUST**
（airstrike / shelling / bombardment / invasion / "missiles strike|launch|fired" 等）。
`missile` / `rocket` / `artillery` 等の**裸の武器名詞だけでは kinetic tier を発火させてはならない MUST NOT** —
兵器試験・配備・防衛産業報道が同じ名詞を含むため。これらは posture として
**escalation tier（floor severity 2）に落とす MUST**。
**根拠**: radar/conclusions/rss_extractor.py:72-90（_KINETIC_VERBS）, :92-109（_ESCALATION_VERBS）
**検証**: tests/test_ground_truth_etl.py / tests/test_run_rss_etl.py（tier 分離）
**分類**: CORE。**由来: インシデント #3**（korea の FN 15 件中 12 件が posture 記事）

#### S1-CALIB-014: 死者数を捏造してはならない
**挙動**: 死者数の記載が無い kinetic マッチの `fatalities` は **0 MUST**（1 を代入してはならない **MUST NOT**）。
confidence ラダーは 死者数あり→**0.85**、kinetic action のみ→**0.60**、escalation posture のみ→**0.40** **MUST**。
下流の severity floor は `(fatalities, confidence)` の組でのみ決まる **MUST**。
**根拠**: rss_extractor.py:362-406
**検証**: tests/test_run_rss_etl.py
**分類**: CORE。**由来: インシデント #3**

#### S1-CALIB-015: ラベル用証拠は escalation-relevance ゲートを通過しなければならない
**挙動**: ETL がラベルに使う記事は次の 3 段ラダーを通過 **MUST**:
①固有に軍事的な語彙（strong kinetic または escalation 動詞）は単独で適格、noise veto を上書きする。
②弱い kinetic 動詞（attack / shooting / explosion 等）は、軍事アクター名詞または**認識国 2 か国以上**が
併存する場合のみ適格。③非紛争ノイズ語彙（台風・事故・野生動物・street crime 等）は②経由の適格を veto。
このゲートは **ETL 側にのみ適用し、bg_observer のセンシング経路には適用しない MUST NOT**（NP1）。
**根拠**: rss_extractor.py:111-186
**検証**: tests/test_run_rss_etl.py
**分類**: CORE。**由来: インシデント #2 の後続修正**（熊スプレー事件と台風が台湾有事の証拠になっていた）

#### S1-CALIB-016: 国別名の照合は末尾に `(?!\w)` を用いる
**挙動**: 国 alias の照合は `\b<alias>(?!\w)` **MUST**。末尾 `\b` を使ってはならない **MUST NOT** —
`"U.S."` のようにピリオドで終わる alias は後続空白との間に `\b` を形成せず、静かに脱落する。
**根拠**: rss_extractor.py:268-273,315-319
**検証**: 未検証（境界バグとして修正されたが専用テストなし）
**分類**: CORE。**由来: インシデント #3 の副次発見**

#### S1-CALIB-017: 1 外部事象 = 1 トライアル（エピソード粒度）
**挙動**: ground truth のトライアル単位は `(scenario_id, country, 事象の UTC 日)` **MUST**。
1 記事は**シナリオごとに高々 1 エピソード**にしか紐づかない **MUST**（記事中の最初の
conflict-party 国に anchor する。言及国ごとに 1 件ずつ作ってはならない **MUST NOT**）。
同一エピソードに複数証拠が集まる場合、**最も重い floor が期待値を決め**（NP1）、
**最も早い報道時刻**が事前窓の起点となる **MUST**。
**根拠**: ground_truth_etl.py:514-537；run_rss_etl.py:343-374
**検証**: tests/test_run_rss_etl.py（23 件）
**分類**: CORE。**由来: インシデント #2 の後続修正**（1 記事が 72h 窓の全結論を採点し 30 日で
約 23,000 ラベルを生成、sample_n が統計的に無意味化していた）

#### S1-CALIB-018: エピソードの採点は事前窓の最良 severity に対して行う
**挙動**: エピソードは窓 `[event_at − window_hours×3600, event_at]` 内の当該シナリオ結論群に対して
**1 回だけ**採点 **MUST**。窓内に結論が無ければ採点しない **MUST**。
窓内で**一度でも** floor に到達していれば TP とし、ラベルは**最良 severity を達成した結論**に付与 **MUST**。
一度も到達しなければ FN とし、ラベルは**事象直前の最新結論**（事象発生時にツールが表示していたもの）に
付与 **MUST**。TL が数値化できない結論（`INSUFFICIENT_DATA` 等）は採点対象外 **MUST**。
**根拠**: run_rss_etl.py:332-341,379-400
**検証**: tests/test_run_rss_etl.py
**分類**: CORE

#### S1-CALIB-019: 冪等性は 3 つの鍵で担保する
**挙動**: 再実行で重複ラベルを生成してはならない **MUST NOT**。鍵は次の 3 種:
①`(conclusion_id, analyst_id)` の既存検出、②RSS エピソード鍵を `notes` 先頭に
`episode=<scenario>/<country>/<day> ` の形で刻印し LIKE 判定、
③ACLED/GDELT 側の day-cap `(scenario_id, label, 結論の UTC 日)` — 約 2 分ごとに書かれる結論が
1 つの世界状態を混同行列の数百エントリへ擬似複製するのを防ぐ **MUST**。
day-cap は同一 run 内のメモリ集合と DB 検査の**両方**で判定 **MUST**（dry-run の件数を実態に合わせる）。
**根拠**: ground_truth_etl.py:497-511,540-567；run_ground_truth_etl.py:372-395；run_rss_etl.py:402-404
**検証**: tests/test_ground_truth_etl.py / tests/test_run_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #2 の後続修正**

### B. TL 閾値較正

#### S1-CALIB-020: 較正入力は THREAT_LEVEL 結論に紐づく全期間のラベル集計
**挙動**: シナリオごとに `analyst_feedback ⨝ conclusions` を `conclusion_type='threat_level'` で
絞って label 別に集計 **MUST**。`total = tp+fp+fn+tn` が `TL_CALIB_MIN_FEEDBACK_PER_CELL`（既定 **30**）
**未満なら較正を行わない MUST**（rejection reason `insufficient_feedback`、境界 `total == 30` は通過）。
**この集計に時間窓は存在しない**（全履歴）。
**根拠**: radar/calibration/tl_threshold_calibrator.py:57-58,87-107
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibratorInsufficientData
**分類**: **DEFECT-PRESERVE** — 窓なし集計は他の全 recall 経路（30 日窓）と非対称であり、
インシデント由来の系列断絶（S1-CALIB-032）とも整合しない。v3 では**明示的な窓を必須とする MUST**

#### S1-CALIB-021: recall / precision の分母はゼロ除算を回避するが None にはならない
**挙動**: `recall = tp / max(1, tp+fn)`、`precision = tp / max(1, tp+fp)` **MUST**。
**帰結**: `tp+fn == 0` のとき recall は 0.0 となり「recall 低下」と誤読される。この誤読を止めるのは
S1-CALIB-024 の鮮度ゲートのみ（FN が 0 件なら `no_motivating_evidence` で棄却される）。
**両ガードは組で機能する**ため、片方の撤去はもう片方の前提を壊す **MUST NOT**。
**根拠**: tl_threshold_calibrator.py:108-109
**検証**: 未検証（ゼロ分母経路の直接テストなし）
**分類**: **DEFECT-PRESERVE** — v3 では分母 0 は `None`（判定不能）とし、集計経路と統一 **MUST**（D2 E 系）

#### S1-CALIB-022: 方向判定は 4 分岐を固定順で評価する
**挙動**: ①`recall < TL_CALIB_RECALL_FLOOR`（既定 **0.80**）→ **looser**（境界 0.80 は発火しない）／
②degenerate-data guard 成立 → 無action（`degenerate_data_guard`）／
③`recall >= 0.99` かつ `precision < TL_CALIB_PRECISION_CEILING`（既定 **0.30**）→ **tighter**
（境界 precision 0.30 は発火しない）／④それ以外 → 無action（`no_action_needed`）**MUST**。
recall 不足時は precision を見ない（①が先）**MUST**。
**根拠**: tl_threshold_calibrator.py:61-70,222-239
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibratorLowRecall / ::TestCalibratorLowPrecision；
tests/test_tl_calibrator_guards.py::test_no_action_when_recall_and_precision_ok
**分類**: CORE

#### S1-CALIB-023: degenerate なラベル分布では較正しない
**挙動**: `tn == 0` かつ `fn == 0` かつ `precision < TL_CALIB_PRECISION_MIN_FLOOR + 0.20`（既定 0.10+0.20 = **0.30**）
のとき、方向を決めず `degenerate_data_guard` で終了 **MUST**。
**根拠**: tl_threshold_calibrator.py:207-220
**検証**: tests/test_tl_calibrator_guards.py::test_degenerate_data_guard_fires_for_tn0_fn0_low_precision /
::test_precision_min_floor_env_override
**分類**: CORE。ただし既定値が tighten 上限と数値一致し tighten 分岐を不到達にする点は §4-A3

#### S1-CALIB-024: 緩和には新しい FN、厳格化には新しい FP を要求する（direction-keyed 鮮度ゲート）
**挙動**: 提案発行の前に**方向ごとに異なる動機証拠の鮮度**を検査 **MUST**:
- looser の動機証拠は **FALSE_NEGATIVE の最新 `observed_at`**、tighter は **FALSE_POSITIVE の最新 `observed_at`** **MUST**
- 動機証拠が 1 件も無ければ `no_motivating_evidence` で棄却 **MUST**
- 前回適用時刻が存在し `motivating_at <= last_applied` なら `no_new_evidence` で棄却 **MUST**
  （**境界の等号は棄却側 MUST** — 厳密に新しい証拠のみが次の調整を正当化する）
- 前回適用が存在しない（初回）場合は通過 **MUST**

不変条件: **1 つの動機証拠状態は高々 1 回の調整しか正当化しない MUST**。
**根拠**: tl_threshold_calibrator.py:253-293
**検証**: tests/test_tl_calibrator_guards.py::test_freshness_gate_blocks_reapplying_stale_evidence /
_allows_action_on_new_evidence / _permissive_when_no_prior_change /
**test_looser_blocked_when_only_non_fn_labels_are_new** / _blocked_when_no_fn_labels_exist /
_tighter_keyed_on_fp_recency
**分類**: CORE。**由来: インシデント #3**。前身（2026-07-04 の「任意の新ラベル」形）は
TP が毎週届くため素通りし、凍結した FN 群で korea 閾値を 4 回追加緩和した

#### S1-CALIB-025: 鮮度ゲートの前回適用時刻はシナリオ単位・自動較正由来のみを見る
**挙動**: 「前回適用時刻」は `threshold_history` の `scope_scenario_id` 一致かつ
`applied_by` が当該較正器マーカー一致の行の `MAX(emitted_at)` **MUST**。
**band（key）では絞らない** — 5 band が 1 つの鮮度クロックを共有する。state も絞らない
（superseded / reverted も計上）。人手変更・revert（`admin:*`）はクロックをリセットしない。
**根拠**: tl_threshold_calibrator.py:125-134
**検証**: 未検証（SQL 経路のテスト無し。ガードテストは monkeypatch）
**分類**: **DEFECT-PRESERVE** — 比較する 2 つの時刻が異なるクロック
（`observed_at` = アナリスト申告の観測時刻／`emitted_at` = 書込み時の実時刻）であり、
バックデートされたラベルは常に stale と判定され、未来日付ラベルは恒久的にゲートを満たす。
v3 では**同一クロック同士の比較 MUST**、かつ band 単位の鮮度クロック **MUST**

#### S1-CALIB-026: 較正ステップは全 band 一律の ±5%
**挙動**: looser → `round(current × 0.95, 3)`、tighter → `round(current × 1.05, 3)` **MUST**。
基準値 `current` は当該 band の直近**採択値**（無ければ既定値）**MUST**。
5 band（`tl1_total` 9.0 / `tl1_physical` 3.0 / `tl2_total` 6.0 / `tl3_total` 4.0 / `tl4_total` 2.0）
**全てに毎回提案が出る** — band 単位の証拠帰属は行われない。
**根拠**: tl_threshold_calibrator.py:45-53,141-150,298-304
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibratorLowRecall
**分類**: **DEFECT-PRESERVE** — ①絶対下限・上限が無く反復緩和が幾何級数的に 0 へ収束しうる
（governor の 10% magnitude 予算は 5% を素通しする）②band 単位の証拠が無いのに band 単位で動かす。
v3 では**絶対レンジのクランプ MUST** かつ **証拠と band の対応 MUST**

#### S1-CALIB-027: 較正の提案は台帳へ、適用は別ゲート
**挙動**: 較正器は `Proposal` を統治層に渡すのみで、シナリオや採点に**直接副作用を持たない MUST NOT**。
Proposal は `key = tl_thresholds.<scenario_id>.<band>`、`applied_by = auto:tl_calibrator`、
`sample_n = total`、`formula_ref = <calibrator_version>#<band>_<direction>`、
`evidence = {recall, precision, tp, fp, fn, tn, direction, prior_value}` を持つ **MUST**。
**根拠**: tl_threshold_calibrator.py:137-169
**検証**: tests/test_tl_threshold_calibrator.py
**分類**: CORE（NP6）。ただし evidence に**鮮度ゲートの入力（動機証拠時刻・前回適用時刻）が
含まれない**ため、台帳から「どの FN がこの変更を正当化したか」を再構成できない → §5-DP2

#### S1-CALIB-028: 較正値は現時点で採点に消費されない
**挙動**: TL 導出は既定値をハードコードしており、較正された閾値を読まない。
提案は台帳に記録されるが**採点に影響しない**（Phase B 設計の意図的な段階分け）。
**根拠**: radar/scoring.py:1218-1228（threshold_history を参照しない）；
tl_threshold_calibrator.py:24-28（「将来のフィーチャーフラグでゲート」と宣言、実体は未実装）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — 「動いているつもりで動いていない」機構。インシデント #2/#3 で
live TL への影響が無かったのはこの休眠状態のおかげであり、有効化する前に S1-CALIB-024/026 の
欠陥解消が前提 **MUST**（D2 E 系の代表例）

#### S1-CALIB-029: シナリオ間の較正失敗は伝播しない
**挙動**: 全シナリオ較正では 1 シナリオの例外が他を止めてはならない **MUST NOT**。
失敗シナリオは `{"error": <200 字}` 形で結果に残す **MUST**。
シナリオ列挙自体の失敗は**空 dict を返す**（エラーと「シナリオ 0 件」が区別できない）。
**根拠**: tl_threshold_calibrator.py:329-355
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibrateAllScenarios
**分類**: CORE（NP3）。列挙失敗の沈黙は §4-A4

### C. 閾値台帳と系譜

#### S1-CALIB-030: 閾値台帳は append-only、状態は 3 値
**挙動**: 状態は `active` / `superseded` / `reverted` **MUST**。新規記録時、同一 `(key, scope)` の
`active` 行を `state='superseded'` かつ `effective_to = 新行の effective_from` で**同一トランザクション内に**
クローズ **MUST**。scope が NULL の場合と非 NULL の場合で WHERE を分岐 **MUST**（SQL の NULL 意味論）。
窓は半開区間で連続 — 境界時刻ちょうどでは**新行が勝つ MUST**（`effective_from <= ts < effective_to`）。
**根拠**: radar/calibration/threshold_history.py:167-228
**検証**: tests/test_calibration_governor.py::TestThresholdHistory::test_supersedes_prior_active_row /
_value_at_returns_active_at_timestamp
**分類**: CORE

#### S1-CALIB-031: 時点照会は state を無視し、現行照会は active に限る
**挙動**: 「時刻 ts に有効だった値」の照会は **state で絞らない MUST**（後に superseded / reverted に
なった行が当時有効だったのは事実）。「現在の値」の照会は `state='active'` に限る **MUST**。
いずれもスコープ解決は **scenario スコープ → グローバル（scope IS NULL）→ 未定義**の順 **MUST**。
**根拠**: threshold_history.py:88-164
**検証**: tests/test_calibration_governor.py::TestThresholdHistory::test_scenario_scope_overrides_global
**分類**: CORE（NP6: 過去の結論を当時の閾値で再現できることが導出開示の前提）

#### S1-CALIB-032: revert は前任行の値を復元し、新しい行として記録する
**挙動**: revert は次の 4 条件をすべて満たすときのみ実行 **MUST**: 対象行が存在／`state='active'`／
`revertible_to_id` が非 NULL／前任行が存在。実行時は対象行を `state='reverted'` にし、
**前任行の値を持つ新規行**を `derived_from = revert_of:<id>`、`formula_ref = <台帳>#revert`、
`evidence = {reverted_row_id, restored_from_row_id}` で記録 **MUST**。
**根拠**: threshold_history.py:231-276
**検証**: tests/test_calibration_governor.py::TestThresholdHistory::test_revert_creates_new_row_with_prior_value；
tests/test_routes_calibration_v2.py::test_threshold_history_revert_without_predecessor_returns_409
**分類**: CORE。**由来: インシデント #2/#3 の修復経路**（korea/middle_east 閾値の巻き戻しに使用）

#### S1-CALIB-033: 系譜は `revertible_to_id` のみを辺とする読み取り専用の探索
**挙動**: 系譜グラフは台帳行の `revertible_to_id` を唯一の辺として祖先方向（線形）と
子孫方向（BFS、fan-out 対応）を辿る **MUST**。深さ上限を持ち **MUST**（既定 50）、
循環を検出したら打ち切る **MUST**。系譜は**何も書き込まない MUST NOT**。
各ノードは行の全フィールド（formula_ref / evidence / applied_by / sample_n / magnitude_pct）を
保持 **MUST**（NP6: 1 回の探索で判断を再現できる）。
**根拠**: radar/calibration/lineage.py:87-173
**検証**: tests/test_lineage.py（9 件）
**分類**: CORE

#### S1-CALIB-034: 系譜と結論の間に永続的な紐付けは存在しない
**挙動**: どの結論がどの閾値行の下で生成されたかは**記録されず**、読み取り時に
「結論の観測時刻で時点照会する」ことで再計算される。
**根拠**: lineage.py 全域（conclusions への参照なし）；threshold_history.py 全域（同）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — 「この閾値変更がどの結論を変えたか」を系譜から答えられない。
v3 では結論 ↔ 有効閾値の**明示的な紐付け MUST**（NP6）

#### S1-CALIB-035: 系譜の部分グラフは完全グラフと区別できない
**挙動**: DB エラー・欠損行に遭遇した場合、探索は**部分グラフを黙って返す**（打ち切りフラグを持たない）。
**根拠**: lineage.py:122-148（3 経路とも DEBUG ログのみ）；threshold_history.py:285-292（唯一の例外握り潰し）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE** — v3 では **`complete: bool` / `truncated_at` を出力に含める MUST**（NP6）

### D. recall メトリクスと Design W ゲート

#### S1-CALIB-036: 混同行列の cell は (scenario_id, conclusion_type)
**挙動**: `analyst_feedback ⨝ conclusions` を cell 単位で集計 **MUST**。
`(conclusion_id, analyst_id)` について**最新行が勝つ MUST**（同一投票者の更新は上書き）。
4 ラベル以外の値は 4 カウンタから黙って落とすが `distinct_analysts` には計上 **MUST**。
`exclude_auto` 指定時は `analyst_id LIKE 'auto:%'` を除外 **MUST**。窓指定は `observed_at >=`（閉区間）。
**根拠**: scripts/report_recall_metrics.py:100-164
**検証**: tests/test_report_recall_metrics.py（8 件全て）
**分類**: CORE

#### S1-CALIB-037: 集計層の recall は分母 0 で None を返す
**挙動**: `recall = tp/(tp+fn)`、`precision = tp/(tp+fp)`、**分母 0 のときは 0.0 ではなく `None` MUST**。
`None` は「測れない」を意味し、後段のゲートでは**カバレッジ喪失（FAIL）**として扱われる **MUST**。
**根拠**: report_recall_metrics.py:74-86
**検証**: tests/test_report_recall_metrics.py::test_zero_denominator_returns_none_not_zero
**分類**: CORE（NP5+8: 結論不可の明示）

#### S1-CALIB-038: per-scenario の較正状態は 30 日窓・3 値
**挙動**: シナリオごとに直近 **30 日**の `threat_level` フィードバックを集計し、
`tp+fn < 5` または recall が None → **`INSUFFICIENT_DATA`**、`recall < 0.70` → **`DEGRADED`**、
それ以外 → **`OK`** **MUST**（境界: denom == 5 は充足、recall == 0.70 は OK）。
判定軸は recall の分母であり総ラベル数ではない **MUST**（TN/FP しか無いシナリオは INSUFFICIENT のまま）。
この関数は**決して例外を送出してはならない MUST NOT**（失敗時は INSUFFICIENT_DATA）。結果は 300 秒 memo 化。
**閾値**: 窓 30 日（`CALIBRATION_WINDOW_DAYS` を getattr するが**どこにも定義が無く実質ハードコード**）、
最小正例 5、DEGRADED 閾値 0.70
**根拠**: radar/conclusions/calibration.py:68-76,135-207
**検証**: tests/test_conclusion_calibration.py（8 件全て）
**分類**: CORE。窓キーの未配線は §5-DP4

#### S1-CALIB-039: 自己評価の recall は全 cell 横断・同一 30 日窓
**挙動**: AP3 の RECALL チップは全 cell を横断合算した `tp/(tp+fn)`（3 桁丸め）を返す **MUST**。
窓は per-scenario 較正状態と**同一の 30 日 MUST**（全期間集計をしてはならない **MUST NOT**）。
併せて `{window_days, labels_total, labels_human, labels_auto, source}` を返す **MUST**
（人手ラベルと自動ラベルの比率を隠さない）。例外時は `recall = None` + `recall_error` **MUST**。
DRIFT は per-scenario の miss rate `1 − recall` の平均（INSUFFICIENT_DATA と None は除外）**MUST**。
**根拠**: radar/routes/conclusions_v2.py:580-623,660-698
**検証**: tests/test_self_eval.py::test_self_eval_recall_uses_calibration_window_and_reports_breakdown
**分類**: CORE。**由来: インシデント #2 の後続修正**（窓不統一の解消）

#### S1-CALIB-040: Design W ゲートは cell ごとの recall 低下を 6 分岐で判定する
**挙動**: baseline スナップショットと現行スナップショットを cell 単位で比較 **MUST**:
①baseline にあり現行に無い → **warn（失敗させない）**／②baseline の recall が None → skip（bootstrap）／
③baseline が数値で現行が None → **FAIL（カバレッジ喪失）**／④`drop > max_drop` → **FAIL**／
⑤`0 < drop <= max_drop` → info（PASS、**境界の等号は PASS 側 MUST**）／⑥現行のみに存在 → info。
**閾値**: `--max-drop` 既定 **0.05**
**根拠**: scripts/check_recall_baseline.py:133-191
**検証**: tests/test_check_recall_baseline.py（16 件、6 分岐を網羅）
**分類**: CORE

#### S1-CALIB-041: baseline 不在時のゲートは失敗しない（bootstrap）
**挙動**: baseline ファイルが存在しない場合、ゲートは**警告を出して成功終了 MUST**
（データ蓄積前の CI を落とさない = NP5+8 の「過渡的結論不可は許容」）。
比較時の窓と `exclude_auto` は **baseline 側の値を継承 MUST**（同条件比較の担保）。
**根拠**: check_recall_baseline.py:247-278（CLI）；scripts/check_ci.sh:45-49（4 番目のゲートとして無引数実行）
**検証**: tests/test_check_recall_baseline.py::test_check_inherits_baseline_window
**分類**: CORE

#### S1-CALIB-042: baseline スナップショットの構造
**挙動**: `{schema_version, generated_at, since, exclude_auto, opt_in, cells[]}` **MUST**。
cell は `{scenario_id, conclusion_type, tp, fp, tn, fn, total, recall, precision, distinct_analysts}` **MUST**。
`since = null` は全履歴を意味する **MUST**。`conclusion_type` は文字列完全一致で照合される **MUST**
（大小文字が意味を持つ）。
**根拠**: docs/baselines/recall_metrics.json:1-105；report_recall_metrics.py:88-97
**検証**: tests/test_report_recall_metrics.py
**分類**: CORE

#### S1-CALIB-043: 2026-07-04 より前の recall 数値は別系列であり比較してはならない
**挙動**: recall / precision の時系列は **2026-07-04 の再スタート以降のみ連続 MUST**。
それ以前の数値と以後の数値を同一系列として比較・トレンド化してはならない **MUST NOT**
（インシデント #1 の blanket-TP と #2 の TL 反転により、以前のラベル母集団は
測定アーティファクトである）。同様に 2026-08-02 の帰属修復も系列に断絶を生む。
現行の担保は**手続き的**（汚染ラベルの purge、baseline の再生成、30 日ローリング窓による自然な排出）であり、
**コードによる強制は存在しない**。
**根拠**: docs/design/v2-migration.md:31,38,41-44；scripts/remediate_inverted_calibration.py:48,51-87；
scripts/remediate_cross_scenario_labels.py
**検証**: tests/test_remediate_cross_scenario_labels.py（6 件、purge と閾値 revert の検証）
**分類**: **DEFECT-PRESERVE** — v3 では**系列エポックを一級市民として持つ MUST**
（ラベル行にラベル生成器バージョン、baseline に epoch id、比較時のエポック不一致で FAIL）。
現行は「CI ゲートが `since: null` の全履歴を比較する」ため、再 baseline を人手で怠れば断絶をまたぐ

#### S1-CALIB-044: 自動チューニングの recall ゲートは現在恒久的に開いている
**挙動**: 提案単位の統治層は「recall が red なら拒否」という規則を持つが、
**呼び出す関数が実在せず**、例外が握り潰されて常に「red でない」を返す。
**根拠**: radar/calibration/auto_tune_governor.py:131-151（`evaluate_against_baseline` を呼ぶが
check_recall_baseline.py には存在しない。`scripts/__init__.py` も無いため import 自体が失敗）
**検証**: 未検証（このゲートを実行するテストが存在しない）
**分類**: **DEFECT-PRESERVE** — NP1 の最終防衛線が沈黙している。
v3 では recall ゲートは**実在し、テストされ、例外時は fail-closed MUST**

#### S1-CALIB-045: autotune 直後の recall 劣化検知は warn-only の 2 段構成
**挙動**: グローバルトレンド（`[now−2h, now−h)` 対 `[now−h, now)`）と、
`threshold_history` の active 行ごとの前後比較の 2 段。`overall_ok = global_ok and autotune_ok` **MUST**。
`drop > max_drop`（既定 0.10）で False、**境界の等号は OK 側**。
pre/post いずれかが None なら skip（データ不足で落とさない）**MUST**。
NP6 のため、失敗メッセージには必ず `threshold_history` の行 id を含める **MUST**。
既定は **warn-only（exit 0）**、`--strict` でのみ exit 1 **MUST**。判定軸は recall のみ（NP1）。
**閾値**: `--hours` 既定 168、`--max-drop` 0.10、`--min-samples` 10、lookback `max(14d, 2h)`
**根拠**: scripts/check_recall_post_autotune.py:14-23,65-217,224-285；check_ci.sh:51-58
**検証**: tests/test_check_recall_post_autotune.py（12 件）
**分類**: CORE

### E. 提案の生成とガード

#### S1-CALIB-046: 提案タイプは 9 種、生成器ごとに責務が分かれる
**挙動**: `weight_too_low` / `weight_too_high` / `missing_participant` / `sensor_gap_detected` /
`scenario_dormant`（改善器）、`dormant_participant` / `role_reclassify`（構造提案器）、
`scenario_discovery`（発見器）、`sensor_disable`（センサー無効化提案器）**MUST**。
適用プリミティブが対応するのは前 5 種のうち構造変更を伴う 5 種
（`weight_too_low` / `weight_too_high` / `missing_participant` / `dormant_participant` / `role_reclassify`）**のみ MUST** —
診断 3 種・発見・センサー無効化に自動適用経路を持たせてはならない **MUST NOT**（NP7）。
**根拠**: scenario_improver.py:432,519,571；_proposal_writer.py:139,173；scenario_apply.py:56-62
**検証**: tests/test_proposal_writer.py / tests/test_routes_calibration_v2.py
**分類**: CORE

#### S1-CALIB-047: recall を増やす提案（weight_too_low）の発火条件
**挙動**: 直近 **30 日**（ハードコード）の国別寄与量を数え、参加者が **3 未満なら提案しない MUST**。
`contribs[cc] >= p75` かつ `weight <= p25_weight` の両方（等号含む）で発火 **MUST**。
`p75 == 0` なら全体スキップ **MUST**。新重み `round(min(0.95, w + step), 2)`、
`SCENARIO_IMPROVER_WEIGHT_STEP` 既定 **0.15**、同値なら発行しない **MUST**。
**根拠**: scenario_improver.py:70-71,396-440
**検証**: tests/test_proposal_guards.py（E2E）
**分類**: CORE。p75/p25 が真の分位点でなくインデックス近似である点は §5-DP5

#### S1-CALIB-048: recall を減らす提案（weight_too_high）は最も厳格な多層ガードを通す
**挙動**: 次の順で評価し、いずれかで停止 **MUST**:
①シナリオ vitality が `active` でなければシナリオ単位で空／
②全球のセンサー被覆が健全でなければシナリオ単位で空／
③参加者ごとに `weight <= 0` → skip、`role ∈ PROTECTED_ROLES` → skip、
`evidence_strength != "strong"` → skip。
`PROTECTED_ROLES = {primary_target, principal_belligerent, adversary, core_country}` **MUST**。
新重みは `round(max(0.10, w − step), 2)` **MUST**。
**根拠**: scenario_improver.py:468-529；_proposal_guards.py:342-343,382-385
**検証**: tests/test_proposal_guards.py（36 件）
**分類**: CORE。**由来: 2026-04-29 事故**（25 件の weight_too_high が全 5 シナリオの primary_target に発火）

#### S1-CALIB-049: 多ソース三角測量は 5 ソース全ゼロを要求する
**挙動**: 「本当に休眠している」の判定は 5 ソース（`llm_intel` / `sequence_events` /
`sensor_observation_ts` / アナリスト FN / `conclusions_contribution`）が**全て 0 MUST**。
`llm_intel` は二重計上防止のため `COUNT(DISTINCT id)` **MUST**。
**根拠**: _proposal_guards.py（P2、5/5 判定）
**検証**: tests/test_proposal_guards.py
**分類**: CORE。**由来: 2026-04-29 事故後の締め直し**（docstring は「≥4 of 5」のまま = E-18）

#### S1-CALIB-050: FN の集計に国スコープが無く、1 件の FN が全世界の提案を止める
**挙動**: アナリスト FN の集計は**国フィルタ無しのグローバル集計**であり、
30 日窓内にどこか 1 件でも FN が付くと、あらゆる国の `weight_too_high` / `dormant_participant` が
`evidence_strength = insufficient` となり発行不能になる。
**根拠**: _proposal_guards.py:189-193 × :412-413（コード内で「保守的に過剰計上」と自認）
**検証**: tests/test_proposal_guards.py
**分類**: **DEFECT-PRESERVE**（D2 E-02）— NP1 的には安全側だが、意図した設計か要裁定（§4-A5）。
v3 では**スコープ付き集計 MUST**

#### S1-CALIB-051: 証拠強度は 6 段ラダーで決まる
**挙動**: ①role 保護 → `insufficient`／②アナリスト FN > 0 → `insufficient`／
③ゼロソース ≥5 → `strong`／④≥3 → `moderate`／⑤≥1 → `weak`／⑥else `insufficient` **MUST**。
**根拠**: _proposal_guards.py（P5 ラダー）
**検証**: tests/test_proposal_guards.py
**分類**: CORE。docstring の「strong=4+/moderate=2-3」および「FN ≥ 1」（実装は FN == 0 の否定）との
乖離は E-18（§5-DP1）

#### S1-CALIB-052: シナリオ活性は 3 状態で、データ欠損をセンサー側に帰す
**挙動**: ①参加者 0 → `dormant`／②総信号 < floor **かつ** 被覆 < min_cov → **`data_gap`**
（両方悪いときはセンサー側を先に疑う）／③被覆 < min_cov → `data_gap`／④総信号 < floor → `dormant`／
⑤else `active` **MUST**。**閾値**: floor 既定 5、min_cov 既定 0.3
**根拠**: _proposal_guards.py（P3）
**検証**: tests/test_proposal_guards.py
**分類**: CORE

#### S1-CALIB-053: 全センサー沈黙時に全滅提案を出してはならない
**挙動**: 30 日窓の `llm_intel` + `sequence_events` + `sensor_observation_ts` の**全球合計**が
`min_global_signals`（既定 **50**）未満なら、recall を減らす提案をシナリオ単位で抑止 **MUST**。
任意テーブル（`scenario_contribution_log`）は集計に**含めない MUST NOT**（欠損で判定を下げないため）。
**根拠**: _proposal_guards.py:342-343,382-385
**検証**: tests/test_proposal_guards.py
**分類**: CORE。**由来: 上流 API 障害で「5/5 ゼロ = strong」が全参加国に成立した全滅提案事故**

#### S1-CALIB-054: missing_participant はシナリオスコープを強制する
**挙動**: 証拠となる `sequence_events` は**必ず `scenario_id` で絞る MUST**。
窓 30 日固定、閾値 `SCENARIO_IMPROVER_MISSING_EVENT_N` 既定 **3**。
既存参加者・国コード空はスキップ **MUST**。初期値は保守的固定
（`weight = 0.30`、`role = strategic_observer`）**MUST**。
**根拠**: scenario_improver.py:550-575
**検証**: tests/test_proposal_guards.py（回帰テストあり）
**分類**: CORE。**由来: 2026-04-29 二次事故**（UA が全 5 シナリオに提案された）

#### S1-CALIB-055: 提案発行は dedup → cap → INSERT の 3 出口
**挙動**: ①同一 `(scenario_id, proposal_type, target_country)` が
**`state IN ('pending','applied')`** かつ `emitted_at > now − DEDUP_DAYS×86400`（既定 **7**）で
存在するなら発行しない **MUST**／②当該シナリオの pending 数が `SCENARIO_IMPROVER_MAX_ACTIVE`（既定 **5**）
以上なら発行しない **MUST**／③それ以外は `state='pending'` で INSERT、JSON 列は
`sort_keys=True` で正規化 **MUST**。INSERT 後の supersede と auto-apply フックは**非致命 MUST**。
**根拠**: scenario_improver.py:97-192,201-228
**検証**: tests/test_proposal_writer.py / tests/test_proposal_lifecycle.py
**分類**: CORE。dedup 対象を pending のみ → pending|applied に拡張したのは
**auto-apply 済み行の再発火で重みが発振した事故**の対策

#### S1-CALIB-056: dedup / cap のカウント失敗はフェイルオープンする
**挙動**: dedup 判定の DB 例外は「重複なし」（発行する）、cap カウント失敗は 0 扱い（発行する）。
**根拠**: scenario_improver.py:97-138,141-151
**検証**: 未検証
**分類**: **ACCIDENTAL**（§4-A6）— NP1 的には発行側が安全だが、発振事故の再発経路でもある

#### S1-CALIB-057: 抑止の理由は永続化されない
**挙動**: ガードが発行を止めた場合、**行が作られないため永続的痕跡が残らない**
（`rejection_reason` 列が存在しない）。残るのはログとプロセス内オブジェクトのみ。
「結論不可の明示」を担う代替イベント生成関数は**本番から呼ばれていない**。
**根拠**: radar/database.py:1280-1298（列定義）；_proposal_writer.py:208-237 vs scenario_improver.py:508-511
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 E-05 / E-17）— NP6 の「なぜ結論を出さなかったか」が追えない。
v3 では**抑止イベントの永続化 MUST**

#### S1-CALIB-058: ガード本体と本番経路が二重化している
**挙動**: 統合ガード関数（`evaluate_for_country` / `is_truly_dormant`）は**本番から一度も呼ばれず**、
実際の `weight_too_high` は 4 ヘルパーを個別に呼ぶ再実装経路を通る。
統合ガードの 3 フラグ算出式は**テストでのみ実行される仕様**。
**根拠**: scenario_improver.py:468-511 vs _proposal_guards.py:441-483
**検証**: tests/test_proposal_guards.py（本番が通らない経路を検証している）
**分類**: **DEFECT-PRESERVE**（D2 E-03）— v3 では**単一経路 MUST**

#### S1-CALIB-059: auto-apply 判定木は impact / 証拠強度 / role 再検査 / tier の 4 段
**挙動**: フラグ ON 時のみ評価 **MUST**（既定 **OFF**）。
①impact 分類（`weight_too_low` / `missing_participant` → low、`role_reclassify` → med、
`weight_too_high` / `dormant_participant` → high、他 → 対象外）②証拠強度の下限
（low 系 weak / missing moderate / recall 削減系 strong、**未知型は strong**）
③recall を減らす 2 型は**現在の**シナリオ定義から role 保護を**再検査 MUST**（発行後の role 変更への多層防御）
④tier ゲート（low は tier≥1、med ≥2、high ≥3、low/med は HIGH cooldown 中なら拒否）**MUST**。
high の適用成功後のみ HIGH cooldown を起動 **MUST**。
**根拠**: scenario_improver.py:265-386
**検証**: tests/test_proposal_lifecycle.py / tests/test_auto_apply_tier_governor.py
**分類**: CORE

#### S1-CALIB-060: role_reclassify の自動適用は構造上到達不能
**挙動**: 構造提案器は evidence に証拠強度を書かないが、auto-apply は `strong` を要求するため、
フラグ ON でも**永久に適用されない**。
**根拠**: scenario_structure_proposer.py:197-218 × scenario_improver.py:268,303-311
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 E-04）

#### S1-CALIB-061: 適用プリミティブは 7 段検証を順に通す
**挙動**: ①提案行ロード ②pending 検査 ③型検査 ④提案値 JSON パース
⑤シナリオロード + `state=="active"` ⑥型別 mutation ⑦参加者検証 → 永続化 → ストア再読込 → 台帳 flip **MUST**。
**不変条件: ①〜⑤で失敗した場合、DB 変更はゼロで台帳は pending のまま MUST**。
失敗コードは 16 種の文字列で識別 **MUST**。`applied_by` はアクター非依存に透過 **MUST**
（`admin:<id>` も `auto:*` も同一 mutation、`scenario_change_log` に記録 = NP6）。
**根拠**: scenario_apply.py:56-62,118-306
**検証**: tests/test_routes_calibration_v2.py
**分類**: CORE

#### S1-CALIB-062: 適用後の台帳更新失敗は不整合として残る
**挙動**: mutation 永続化後に台帳 flip が失敗した場合、`ok=False` を返すが
**mutation は反映済み**であり「シナリオは新状態・台帳は pending」の不整合が残る（再適用で二重変更しうる）。
**根拠**: scenario_apply.py:274-294
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 E-14）— v3 では**トランザクション境界で不可分 MUST**

#### S1-CALIB-063: 重み範囲の強制は参加者検証層のみが担う
**挙動**: 適用プリミティブ自身は重みをクランプせず、範囲強制（0.0–1.0）は参加者検証が担う。
発行時の floor（0.10 / 0.95）とは**別レイヤ**であり、提案 JSON を手で書き換えれば 0.0 や 1.0 も通る。
参加者検証は**変更対象だけでなく mutation 後の全参加者**に走るため、
既存の不正参加者 1 件で無関係な提案も適用不能になる。
**根拠**: scenario_apply.py:243-249；radar/scenarios.py:248-265
**検証**: 未検証
**分類**: **ACCIDENTAL**（§4-A7）

#### S1-CALIB-064: 構造提案器の閾値群は改善器と別値である
**挙動**: source_type → role マップ 10 エントリ固定、未登録は曖昧としてスキップ **MUST**。
dominant 判定は件数 `STRUCTURE_PROPOSER_MIN_DOMINANT`（既定 **5**）かつシェア
`STRUCTURE_PROPOSER_MIN_SHARE`（既定 **0.50**）の 2 段 floor **MUST**。窓は既定 **30 日**。
dormant の減算幅は **0.20 ハードコード**（改善器の 0.15 と別値）、下限 0.10 **MUST**。
dedup / cap / auto-apply は改善器の発行経路を private import で継承 **MUST**。
**根拠**: scenario_structure_proposer.py:43-61,74-104,107-192,237-287,327-341
**検証**: tests/test_scenario_structure_proposer.py（20 件）
**分類**: CORE。減算幅の不一致は §4-A8

#### S1-CALIB-065: シナリオ発見は共通発行経路を迂回する
**挙動**: DBSCAN（`DISCOVERY_DBSCAN_EPS` 既定 **0.6** / `MIN_SAMPLES` 既定 **3**）。
スナップショットは既定 **23 時間**以内なら再利用 **MUST**。既存シナリオとの重複は
**Jaccard >= 0.7** でスキップ **MUST**（シナリオ列挙に失敗すると `existing = []` にフォールバックし
**全クラスタが提案される**）。提案行は `scenario_id='__discovery__'` 固定。
**根拠**: scenario_discoverer.py:51-76,127-154,165-174,208-247
**検証**: tests/test_scenario_discoverer.py（11 件）
**分類**: **DEFECT-PRESERVE**（D2 E-15 / E-16）— 共通発行経路を通らないため
dedup 窓・active cap・auto-apply フック・証拠強度刻印を一切受けない。
supersede の LIKE フォールバックは**先頭国の一致だけで別クラスタを誤 supersede しうる**。
v3 では**全提案が単一発行経路を通る MUST**

#### S1-CALIB-066: drift 監視は 7 種の信号を出し、シナリオを変更しない
**挙動**: 信号は `sensor_outage` / `participant_silent` / `adversary_mismatch` / `recall_underperform` /
`chronic_insufficient` / `participant_orphan` / `proposal_quality_inversion` の 7 種 **MUST**。
監視はシナリオを**一切変更してはならない MUST NOT**（監視専用ゾーン）。
発行は upsert で、同一 `(scenario_id, drift_signal, target_country)` の未確認行が**直近 24 時間**に
存在すれば連続回数の加算と時刻更新のみ **MUST**。
**UI に出るのは連続 3 回以上のみ MUST**（dwell-time ガードレール、既定窓 168h）。
確認操作は未確認行のみを更新し、発行時刻と連続回数は保存 **MUST**（NP6）。
**閾値**: 重み停滞窓 30 日、adversary 窓 60 日 + conclusions ≥ 50 件、recall コホート最小 3、
慢性不足 14 日、提案品質反転 recall_negative > 0.30 または (closed ≥ 10 かつ dismissed > 0.50)
**根拠**: drift_watchdog.py:43-56,75-118,150-522,554-563,580-653
**検証**: tests/test_drift_watchdog.py（8 件）
**分類**: CORE

#### S1-CALIB-067: センサー無効化提案は fetch 層の健全性で抑止される
**挙動**: 対象は LLM ゲート済み 7 センサ固定。broken 判定は 7 日窓の LLM 呼出ログで
`pre_ratio >= 0.95` **または** `err_ratio >= 0.20` **MUST**。
呼出が `SENSOR_DISABLE_MIN_CALLS`（既定 **100**）未満なら分類自体を行わない **MUST**（未稼働センサの誤 disable 防止）。
**fetch 層が健全（直近 24h の成功 ≥ 10 かつ最終エラー無し）なら、LLM 側が broken でも提案しない MUST**
（「動いているセンサを切るよりプロンプトを締めろ」）。
**根拠**: sensor_disable_proposer.py:62-89,133-194
**検証**: tests/test_autotune_proposer_guards.py（13 件）
**分類**: CORE

#### S1-CALIB-068: センサー無効化のエスカレーションは dry-run でも台帳を applied にする
**挙動**: ack 窓（既定 **24h**）超過時、自動無効化フラグが false でも台帳は
`state='applied'` に更新され `state_changed_by='auto:escalation_dry_run'` になる。
また `already_disabled` ガードは「再提案しない」意図で False（= 提案続行）を返す。
確認操作は「ack」と称して実際には `state='dismissed'` を書く。
**根拠**: sensor_disable_proposer.py:117-155,260-287,388-398
**検証**: 未検証（エスカレーション経路）
**分類**: **DEFECT-PRESERVE**（D2 E-06 / E-07）— AP3 スコアボードと drift の closed/applied 集計が
「実際には無効化していない」行で汚染される

### F. 提案の状態機械

#### S1-CALIB-069: 提案の状態は 6 値のみ
**挙動**: `pending` / `applied` / `dismissed` / `snoozed_30d` / `reverted` / `superseded` **MUST**（既定 pending、
DB CHECK 制約が正）。`accepted` / `rejected` / `auto_dismissed` / `expired` は**存在しない MUST NOT** —
区別は `state_changed_by` のマーカー文字列のみで表現される。
提案台帳に `reverted` を書く経路は**存在しない**（閾値台帳専用）。
アナリスト遷移は **pending からのみ MUST**（非 pending は静かに失敗）。
**根拠**: radar/database.py:1294；scenario_improver.py:743-762；routes/calibration_v2.py:278-388
**検証**: tests/test_proposal_lifecycle.py（30 件）
**分類**: CORE。マーカー文字列でしか区別できない設計は §4-A9

#### S1-CALIB-070: 自動 dismiss は 3 フックで条件・閾値・マーカーが異なる
**挙動**: ①非アクティブシナリオ: `pending` かつシナリオが `paused|archived` → **時間条件なし**、
マーカー `auto:inactive_scenario`／②診断型: `pending` かつ診断 3 種かつ `emitted_at < now − 7d`、
マーカー `auto:diagnostic_acknowledged`／③実行可能型: `pending` かつ `emitted_at < now − 30d` かつ
非診断型かつシナリオ active、マーカー `auto:timeout_no_action` **MUST**。
判定基準は **`emitted_at`**（状態変更時刻ではない）**MUST**。3 フックは同一ティックで連続実行される。
**根拠**: proposal_lifecycle.py:309,350；scheduler.py:531-591
**検証**: tests/test_proposal_lifecycle.py
**分類**: CORE

#### S1-CALIB-071: Defer した提案は復活直後に必ず自動 dismiss される
**挙動**: snooze 復活は `state_changed_at` を基準に判定して `pending` に戻すが、**`emitted_at` を更新しない**。
自動 dismiss は `emitted_at` で判定するため、既定設定（snooze 30 日 = stale 30 日）では
**Defer した提案は復活直後の次ティックで必ず `auto:timeout_no_action` になる**。
**根拠**: database.py:5522-5545（:5534, :5542）vs proposal_lifecycle.py:309,350
**検証**: tests/test_proposal_snooze_revival.py（5 件、この相互作用は未検証）
**分類**: **DEFECT-PRESERVE**（D2 E-01、HIGH）— Defer が構造的に機能していない。
v3 では**状態機械の再設計 MUST**（時刻基準の統一）。**現行系でも要修正**

#### S1-CALIB-072: supersede は 2 系統あり、いずれもマーカーで監査可能
**挙動**: 通常系は `(scenario_id, proposal_type, target_country)` の素の 3 カラム等値
（NULL 意味論を明示分岐、自己排除あり、DB 例外は 0 件として握り潰し）**MUST**。
発見系のみ fingerprint 系統 **MUST**。マーカーは `auto:supersede_by_id_<新ID>` /
`auto:phase_d_fingerprint` / `admin:<user>` の 3 種 **MUST**。
dedup 窓 7 日内は発行自体がブロックされるため、supersede の実効対象は**窓外に生き残った古い pending のみ**。
**根拠**: proposal_lifecycle.py:474-527
**検証**: tests/test_proposal_lifecycle.py
**分類**: CORE

#### S1-CALIB-073: 既存 pending の auto-apply ゲート再投入は 1 ティック 3 件まで
**挙動**: 再投入対象は 30 日以内かつ impact 分類を持つ型のみ、1 ティック **3 件**まで **MUST**。
過剰フェッチ（3×8 = 24 件）で型/年齢スキップがレート枠を飢餓させないようにする **MUST**。
直前の再読込で非 pending なら skip **MUST**（同一ティック内の自動 dismiss との競合対策）。
**根拠**: proposal_lifecycle.py（`reprocess_pending_through_gate`）
**検証**: tests/test_proposal_lifecycle.py
**分類**: CORE

### G. 自動適用 tier 統治

#### S1-CALIB-074: tier は 4 状態、impact ごとに許可が異なる
**挙動**: tier 0 = いかなる impact も台帳に書かない／1 = low のみ／2 = low+med／3 = 全部 **MUST**。
impact 分類の規範は「**recall を増やす方向は low、減らす方向は high**」**MUST**
（保留それ自体が recall 削減であるという NP1 論拠）。許可判定は**例外時に必ず不許可 MUST**（NP3）。
`impact_override` は厳密に low/med/high のときのみテーブル参照をスキップ **MUST**（タイポは無視して迂回防止）。
**根拠**: auto_apply_tier_governor.py（`APPLIED_BY_IMPACT` 13 エントリ、`is_apply_allowed`）
**検証**: tests/test_auto_apply_tier_governor.py::TestTierGovernorBasics
**分類**: CORE

#### S1-CALIB-075: 未知の適用者は最も緩い impact に落ちる
**挙動**: `APPLIED_BY_IMPACT` に無い `applied_by` は impact=low に既定分類される（「保守的既定」と
称するが実際には**最も緩い**分類）。
**根拠**: auto_apply_tier_governor.py:247
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 E-13）— v3 では**未知は fail-closed（適用不可）MUST**

#### S1-CALIB-076: 昇格は 3 段、降格は全 tier 共通の単一条件
**挙動**: 0→1 は `auto_feedback_rows >= 100` の**単一条件 MUST**（dwell 要件も revert_rate 要件も無い。
tier 0 では閾値台帳が構造的に空であるため提案数を要件にすると鶏卵デッドロックになる）。
1→2 は `days_at_tier >= 7.0` かつ `revert_rate_7d <= 0.05`、2→3 は `>= 14.0` かつ `revert_rate_14d <= 0.05` **MUST**。
1 回の評価で**最大 1 段階 MUST**。降格は全 tier 共通で `revert_rate_24h >= 0.20` **MUST**。
**降格判定を昇格より先に行う MUST**（安全側バイアス）。
ヒステリシスは「昇格 ≤0.05（7d/14d 窓）対 降格 ≥0.20（24h 窓）」の非対称性で実現 **MUST**。
**根拠**: auto_apply_tier_governor.py（昇降格ゲート）
**検証**: tests/test_auto_apply_tier_governor.py::TestPromotion（昇格成立と降格の直接テストは無い）
**分類**: CORE。tier 遷移が recall 劣化を直接の軸にしない点は §4-A10

#### S1-CALIB-077: revert 率は隣接ペアの方向反転で数え、系統的に過小評価される
**挙動**: 閾値台帳を `emitted_at >= now − 窓×2.0` で読み、`(key, scope)` ごとに時系列順の
隣接ペアを走査。`long_delta = next − prev`、`short_delta = curr − prev` として
`long_delta != 0` かつ `short_delta × long_delta < 0` を revert と判定 **MUST**。
ペア間隔が窓を超えたらスキップ **MUST**。`pairs == 0` / DB 例外は 0.0 **MUST**。
**根拠**: auto_apply_tier_governor.py:529-535,551-569
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 E-11）— ①系列の最終ペアは分母に入るが分子に決して入らない
②float 変換失敗も分母のみ増やす ③`applied_by` フィルタが無く**人間の手動 revert も降格の母数に混入**
④データが疎な環境では昇格ゲートが常に通過し降格が常に不成立

#### S1-CALIB-078: 滞留時間の解決は 4 段で、marker 復旧が書き込みを起こす
**挙動**: ①marker が一致かつ tier > 0 → marker 由来／②状態変更行 → 行由来／
③marker のみ生存 → 警告 + 復旧行を書き込み + marker 由来／④無し → 0.0 **MUST**。
**marker と state が矛盾する場合は state を優先 MUST**（状態行が記録上の台帳）。
marker は tier が実際に変わるときのみ更新 **MUST**（同一 tier への再遷移では滞留をリセットしない）。
**根拠**: auto_apply_tier_governor.py:616-624,814-816
**検証**: tests/test_auto_apply_tier_governor.py::TestTierEnteredMarker
**分類**: **DEFECT-PRESERVE**（D2 E-12）— スナップショット取得が「純粋読み取り」契約を破り
DB 書き込みを起こす。v3 では**読み取りと復旧を分離 MUST**

#### S1-CALIB-079: HIGH 適用後の cooldown は low/med を止め、high 自身は止めない
**挙動**: HIGH 適用後 `AUTO_APPLY_HIGH_COOLDOWN_HOURS`（既定 **24.0h**）の間、
**low と med を同時に停止 MUST**。**high 自身は対象外**（HIGH 直後も HIGH は通る）。
絶対時刻で保存し、HIGH のたびに窓を再計測 **MUST**。
tier 昇降格・サーキットブレーカー・キルスイッチは cooldown をクリアしない **MUST NOT**（自然失効のみ）。
発火判定はテーブル参照のみで `impact_override` を考慮しない。env 不正値では cooldown が
**設定されないまま無音で終了**する。
**根拠**: auto_apply_tier_governor.py（cooldown 群）
**検証**: tests/test_auto_apply_tier_governor.py::TestHighCooldown
**分類**: CORE。override 非考慮と無音失敗は §4-A11

#### S1-CALIB-080: 連続評価失敗と tier 上限はいずれも強制降格を起こす
**挙動**: 連続 **3 回**の評価失敗で tier を 0 に強制し、遷移種別 `circuit_breaker` を記録 **MUST**。
連続失敗数は直近 6 行を走査し、成功・昇格・降格・ハートビートのいずれでもリセット **MUST**。
復帰経路は**通常の昇格のみ**（専用の復帰ゲート・手動リセット API は存在しない）。
tier 上限（キルスイッチ）は `cap < 生の格納 tier` で判定 **MUST**（cap 適用後の値で判定すると
真のキルスイッチ事象が記録されない）。キルスイッチ降格は**1 段階ずつでなく cap の値へ一気に落とす MUST**。
上限の不正値は 3 にフォールバック（フェイルオープン）。
**根拠**: auto_apply_tier_governor.py（`CONSECUTIVE_FAILURE_LIMIT = 3`、`AUTO_CALIBRATION_TIER_CAP`）
**検証**: tests/test_auto_apply_tier_governor.py::TestCircuitBreaker / ::TestKillSwitchDemotion
**分類**: CORE。不正値フェイルオープンは §4-A12

#### S1-CALIB-081: 提案単位の統治は 7 規則を固定順で評価する
**挙動**: ①サンプル数（`AUTO_TUNE_MIN_SAMPLE_N` 既定 **30**、境界 `== 30` は通過）
②recall ゲート（red なら拒否）③tier ゲート ④cooldown（`AUTO_TUNE_COOLDOWN_HOURS` 既定 **72h**、
`(key, scope)` 単位、境界 `elapsed == cooldown` は通過）⑤無変更ショートサーキット
⑥magnitude クランプ ⑦永続化 **MUST**。この順序により **tier ゲート拒否が cooldown より優先**され、
tier 0 環境では全提案が `tier_gate` で落ちて以降の規則に到達しない。
recall ゲートは**例外時に許可（フェイルオープン）**、tier ゲートは**例外時に拒否（フェイルクローズ）MUST**。
**根拠**: auto_tune_governor.py:56-64,149-151,154-274
**検証**: tests/test_calibration_governor.py::TestGovernorSampleSize / ::TestGovernorCooldown /
::TestGovernorRecallGate / ::TestGovernorUnchanged
**分類**: CORE

#### S1-CALIB-082: magnitude 超過は拒否ではなくクランプして受理する
**挙動**: `abs((new − prior)/prior)×100` が `AUTO_TUNE_MAX_MAGNITUDE_PCT`（既定 **10.0%**）を超える場合、
拒否せず `prior + sign(delta)×abs(prior)×(max_pct/100)` にクランプして受理 **MUST**。
台帳の記録値は要求値でなく**上限値**である **MUST**。degenerate: `prior == 0` かつ `new != 0` → 100.0、
非数値（bool 含む）→ 常に 100.0。**`prior == 0` はクランプせず new をそのまま返す**。
初出キー（前値なし）は `magnitude_pct = 0.0` で**上限チェックなしに verbatim コミット MUST**。
**方向制限は実装されていない**（絶対値で符号を無視。方向の唯一の制約は impact 分類という上位ゲート）。
**根拠**: auto_tune_governor.py:227-266
**検証**: tests/test_calibration_governor.py::TestGovernorMagnitude
**分類**: CORE。`prior == 0` の予算外扱いと初出 verbatim は §4-A13

### H. LLM 較正系

#### S1-CALIB-083: LLM 注釈の状態は 3 値で shadow-first、既定は両 OFF
**挙動**: 状態は `production` > `shadow` > `none` の 3 値で production が shadow を上書き **MUST**。
`none` では **DB に一切触れない no-op MUST**。フラグ解決は
kill switch → DB override → env → registry 既定（**OFF**）の順 **MUST**（NP7 shadow-first）。
shadow 行は明示要求が無い限り UI から除外 **MUST**。
注釈は suggest-only であり、シナリオを自動生成してはならない **MUST NOT**（NP1/NP7）。
**根拠**: g3b_llm_annotator.py:94-123,186-201,292-297；llm_features.py:376-411,183-198
**検証**: tests/test_g3b_llm_annotator.py::TestEnvGate（2 件）
**分類**: CORE

#### S1-CALIB-084: LLM 注釈の日次上限はソフトガードであり過大計上する
**挙動**: 日次コール上限（`G3B_DAILY_CALL_CAP` 既定 **50**）の計測は呼出ログの直近 86400 秒を数えるが、
**例外を握り潰して 0 を返す**ため、ログが読めない環境では上限が事実上無効化される。
また消費カウントは実際に LLM を呼んだかに無関係に加算される（CB open / 国不明で呼ばなかった分も消費扱い）。
サーキットブレーカーは連続失敗 `G3B_CIRCUIT_BREAKER_FAILURES`（既定 **5**）で開き、
**run 冒頭で毎回リセットされる**ため実効スコープは 1 run である。
LLM 失敗時は注釈を書かず未注釈のまま残す **MUST**（次 run で自動リトライ）。
例外を投げず skipped 化する **MUST**（NP3）。
**根拠**: g3b_llm_annotator.py:86-91,134-150,242-256,288-290,318-333
**検証**: tests/test_g3b_llm_annotator.py（cap）。CB スコープと過大計上は未検証
**分類**: **DEFECT-PRESERVE**（D2 E-18 の CB スコープ乖離を含む）

#### S1-CALIB-085: LLM 注釈は導出開示の鎖が切れている
**挙動**: 注釈に記録されるのはプロンプトバージョンのみで、**プロンプトのハッシュも生応答も記録されない**
（docstring は記録すると宣言している）。LLM パラメータは固定
（temperature 0.1 / max_tokens 300）、永続化時に切り詰め（name 120 / description 500 / rationale 300）、
JSON は `sort_keys=True` で決定化 **MUST**。
**根拠**: g3b_llm_annotator.py:37-39（宣言）vs :258-269（実装）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 E-08）— NP6 違反。
v3 では **LLM 由来の全結論に prompt ハッシュと生応答を紐づける MUST**

#### S1-CALIB-086: LLM 信頼度下限の較正は収束しない ±0.05 ヒューリスティック
**挙動**: 対象は 7 センサ固定。母数は `TP+FP+FN`、`LLM_CONF_CALIB_MIN_FEEDBACK`（既定 **30**）未満は
`insufficient_feedback` **MUST**。分岐 A（緩め）: `recall < floor`（既定 **0.85**）→
`max(floor_lo, global_min − 0.05)`／分岐 B（締め）: `precision < 0.5` かつ `recall >= floor + 0.10` →
`min(floor_hi, global_min + 0.05)`。**A が先に評価され、recall 不足時は precision を見ない**。
**根拠**: llm_confidence_calibrator.py:49-69,93-119,136-167
**検証**: tests/test_phase_cdf1.py::TestLLMConfidenceCalibrator（**提案を発火させる 2 分岐は未カバー**）
**分類**: **DEFECT-PRESERVE**（D2 E-09 / E-10）— ①提案値は常に `global_min ± 0.05` で
**直近採択値を読まない**ため同方向の再提案が常に同値（収束しない）②「変化量 0.02 未満なら提案しない」
ガードは差分が常に 0.05 のため**常に通過** ③許容レンジのクランプは既定設定で実効しない
④sample_n の JOIN がセンサ単位でなくシナリオ単位のため**意味が歪む**

#### S1-CALIB-087: 自動フィードバック ETL は単一ダイヤルで、dedup を下流に委譲する
**挙動**: ground truth 系と RSS 系の両パスは**同一のフラグ 1 つ**でゲートされる **MUST**
（`V2_GROUND_TRUTH_ETL_ENABLED` 既定 **false**）。ACLED は API キーと email の**両方**が
揃ったときのみ有効化し、片方欠落で GDELT-only に自動縮退 **MUST**。
`None` は失敗ではなく**ガード終了のシグナル MUST**。dedup は下流 ETL の冪等性
（S1-CALIB-019）に委譲 **MUST**。既定は ground truth 窓 14 日 / limit 1000、RSS 窓 14 日 / **limit 4000**。
**根拠**: auto_feedback_etl.py:54-58,60-70,88-90,107-126；config.py:290-294
**検証**: **専用テスト不在**
**分類**: CORE。limit の非対称（1000 vs 4000）は §4-A14

#### S1-CALIB-088: 手動一括較正は決定的な 8 段順序で、1 段の失敗が他を止めない
**挙動**: 実行順は `tl → llm_conf → sensor_disable → scenario → structure → discovery → g3b → drift` **MUST**。
phase 関数は遅延 import し、1 つの import 失敗が他を妨げない **MUST**。
個別実行は**決して例外を送出しない MUST NOT**（失敗は結果オブジェクトの `error` に 200 字で格納）。
例外を送出するのは**未知 phase 名の場合のみ MUST**（空文字も未知扱い）。
戻り値は常にリスト（単一 phase でも長さ 1）**MUST**。終了コードは 1 件でも失敗なら 1 **MUST**。
NP7: センサー自動無効化を除き production scoring への副作用は無い **MUST**。
**根拠**: run_now.py:44-55,58-68,101-143,146-196
**検証**: tests/test_calibration_run_now.py::TestDispatchAll::test_runs_phases_in_order（20 件）
**分類**: CORE

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー | DB override | 条項 |
|---|---|---|---|---|
| ground truth forward 窓 | 72h | `GROUND_TRUTH_WINDOW_HOURS` | 不可 | 007 |
| FP/TN horizon | 7d | `GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS` | 不可 | 009 |
| FN 死者数閾値 / mass-casualty | 10 | `GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES` | 不可 | 005, 012 |
| ETL 一括ゲート | false | `V2_GROUND_TRUTH_ETL_ENABLED` | 不可 | 087 |
| severity floor（mass/kinetic/escalation） | 4 / 3 / 2 | — | 不可 | 012 |
| confidence ラダー | 0.85 / 0.60 / 0.40 | — | 不可 | 014 |
| TL 較正 最小フィードバック | 30 | `TL_CALIB_MIN_FEEDBACK_PER_CELL` | 不可 | 020 |
| TL 較正 recall floor | 0.80 | `TL_CALIB_RECALL_FLOOR` | 不可 | 022 |
| TL 較正 precision 上限（tighten） | 0.30 | `TL_CALIB_PRECISION_CEILING` | 不可 | 022 |
| TL 較正 precision 下限（degenerate） | 0.10（+0.20 で実効 0.30） | `TL_CALIB_PRECISION_MIN_FLOOR` | 不可 | 023 |
| TL 較正ステップ | ×0.95 / ×1.05 | — | 不可 | 026 |
| TL 既定閾値 5 band | 9.0 / 3.0 / 6.0 / 4.0 / 2.0 | — | 不可 | 026 |
| 閾値台帳 list 窓 | 168h | — | 不可 | 030 |
| 系譜 深さ上限 | 50（API は 1-200 にクランプ） | — | 不可 | 033 |
| calibration_status 窓 | 30d | `CALIBRATION_WINDOW_DAYS`（**未配線**） | 不可 | 038 |
| calibration_status 最小正例 / DEGRADED | 5 / 0.70 | — | 不可 | 038 |
| Design W 許容 drop | 0.05 | `--max-drop` | 不可 | 040 |
| post-autotune 許容 drop / 最小サンプル | 0.10 / 10 | CLI | 不可 | 045 |
| 提案 dedup 窓 | 7d | `SCENARIO_IMPROVER_DEDUP_DAYS` | 不可 | 055 |
| シナリオあたり pending 上限 | 5 | `SCENARIO_IMPROVER_MAX_ACTIVE` | 不可 | 055 |
| 重み step（改善器 / 構造提案器） | 0.15 / **0.20** | `SCENARIO_IMPROVER_WEIGHT_STEP` / — | 不可 | 047, 064 |
| 重み上下限 | 0.95 / 0.10 | — | 不可 | 047, 048 |
| missing_participant 閾値 | 3 events / 30d | `SCENARIO_IMPROVER_MISSING_EVENT_N` | 不可 | 054 |
| vitality floor / min coverage | 5 / 0.3 | — | 不可 | 052 |
| 全球最小信号数 | 50 | **キーワード引数のみ** | 不可 | 053 |
| 構造提案 dominant 件数 / シェア / 窓 | 5 / 0.50 / 30d | `STRUCTURE_PROPOSER_*` | 不可 | 064 |
| 発見 DBSCAN eps / min_samples / 鮮度 | 0.6 / 3 / 23h | `DISCOVERY_*` | 不可 | 065 |
| 発見 既存重複 Jaccard | 0.7 | — | 不可 | 065 |
| drift dwell / upsert 窓 | 3 回 / 24h | — | 不可 | 066 |
| センサー disable α（pre / err）/ 最小呼出 | 0.95 / 0.20 / 100 | `SENSOR_DISABLE_*` | 不可 | 067 |
| センサー disable ack 窓 | 24h | `SENSOR_DISABLE_ACK_HOURS` | 不可 | 068 |
| 自動 dismiss（診断 / 実行可能） | 7d / 30d | `DIAGNOSTIC_AUTO_ACK_DAYS` / `PROPOSAL_STALE_TIMEOUT_DAYS` | 不可 | 070 |
| snooze 期間 | 30d | `PROPOSAL_SNOOZE_DAYS` | 不可 | 071 |
| 再ゲート 上限 / 最大年齢 | 3 件/tick / 30d | — | 不可 | 073 |
| tier 昇格（0→1 / 1→2 / 2→3） | 100 行 / 7d+0.05 / 14d+0.05 | — | 不可 | 076 |
| tier 降格 | revert_rate_24h ≥ 0.20 | — | 不可 | 076 |
| tier 上限 | 3 | `AUTO_CALIBRATION_TIER_CAP` | 不可 | 080 |
| 連続失敗上限 | 3 | — | 不可 | 080 |
| HIGH cooldown | 24.0h | `AUTO_APPLY_HIGH_COOLDOWN_HOURS` | 不可 | 079 |
| autotune 最小サンプル / cooldown / magnitude | 30 / 72h / 10.0% | `AUTO_TUNE_*` | 不可 | 081, 082 |
| g3b 日次上限 / CB 失敗数 / バッチ | 50 / 5 / 20 | `G3B_*` | 不可 | 083, 084 |
| LLM 信頼度較正 最小 / recall floor | 30 / 0.85 | `LLM_CONF_CALIB_*` | 不可 | 086 |

**v3 への示唆**: 較正系の閾値は **DB override が 1 つも実装されていない**（提案の適用値のみが
台帳経由で可変）。NP6 の観点では、結論と自動判断に影響する全閾値を宣言的 registry に載せるべき（D2 A-13）。

---

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | TL 較正の入力集計に時間窓が無い（全履歴）。他の全 recall 経路は 30 日窓 | 系列断絶（S1-CALIB-043）と両立しない。窓を入れるべきか |
| A2 | degenerate guard の実効 precision 境界（0.30）が tighten 上限（0.30）と数値一致し、`tn==0 かつ fn==0` では tighten が構造的に不到達 | 意図的な結合か偶然か |
| A3 | 較正ステップ ±5% が governor の magnitude 予算 10% を常に下回るため、magnitude クランプが較正器に対して実効しない | 二重防御の意図があったのでは |
| A4 | シナリオ列挙失敗が空 dict を返し「シナリオ 0 件」と区別できない | NP5+8 的にはエラーを表明すべき |
| A5 | FN のグローバル集計で 1 件の FN が全世界の recall 削減提案を止める | NP1 的には安全側。意図した設計かの確認（D2 E-02） |
| A6 | dedup / cap のカウント失敗がフェイルオープン（提案を通す） | 発振事故の再発経路。fail-closed にすべきか |
| A7 | 重み範囲の強制が適用層に無く、提案 JSON を書き換えれば 0.0 / 1.0 が通る | 権限を持つアナリストのみが触れる前提でよいか |
| A8 | 重み減算幅が改善器 0.15 / 構造提案器 0.20 と別値 | 意図的な差か、コピペドリフトか |
| A9 | 提案の終端状態が 6 値しかなく、accept / auto-dismiss / expire の区別が `state_changed_by` 文字列でしか表現されない | AP4（判断履歴）の再生に十分か |
| A10 | tier 遷移が recall 劣化を直接の判定軸にしない（recall ゲートは提案単位のみ） | NP1 的に tier 側の再チェックが要るか |
| A11 | HIGH cooldown の発火判定が `impact_override` を考慮せず、env 不正値で無音失敗する | 迂回経路として許容するか |
| A12 | tier 上限の不正値が 3（最大許可）にフォールバックする | キルスイッチの意味が消える。fail-closed にすべきか |
| A13 | magnitude 予算が `prior == 0` のとき適用されず、初出キーは verbatim コミットされる | 0 起点の変更を予算外にする根拠 |
| A14 | 自動 ETL の limit が ground truth 1000 / RSS 4000 と非対称 | 意図的か |
| A15 | 較正系の閾値に DB override が 1 つも実装されていない（docstring は「DB-stored config」と述べる） | 運用中の調整可能性をどこまで持たせるか |

---

## 5. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 | 条項 |
|---|---|---|---|---|
| DP1 | docstring と実装の乖離が systemic（P2「≥4 of 5」vs 5/5、evidence_strength のリテラル誤り、P5 の不等号反転、run_now の phase 欠落、tier governor の「DB-stored config」、CB スコープ 等） | 仕様書が正本。docstring は仕様書を参照するのみ **MUST**。CI で乖離を検出する仕組みが要る | E-18 | 049, 051, 084, 088 |
| DP2 | 較正 evidence に鮮度ゲートの入力（動機証拠時刻・前回適用時刻）が含まれず、台帳から変更の正当化根拠を再構成できない | 判断に使った全入力を evidence に記録 **MUST** | — | 027 |
| DP3 | 較正値が採点に消費されない休眠状態（「動いているつもりで動いていない」） | 休眠機構を検出する仕組みを持つ **MUST**（S5） | E 系総論 | 028 |
| DP4 | `CALIBRATION_WINDOW_DAYS` がどこにも定義されず getattr の既定 30 が常に勝つ | 全閾値は宣言的 registry 経由 **MUST** | A-13 | 038 |
| DP5 | p75 / p25 が真の分位点でなくインデックス近似（n=4 で最大値を指す等の境界ずれ） | 分位点は定義どおり **MUST** | — | 047 |
| DP6 | Defer が構造的に機能しない（復活直後に必ず自動 dismiss） | 状態機械の時刻基準を統一 **MUST**。**現行系でも要修正** | E-01 | 071 |
| DP7 | ガード本体（統合関数）が本番から呼ばれず、4 ヘルパーの再実装経路が動く | 単一経路 **MUST** | E-03 | 058 |
| DP8 | role_reclassify の自動適用が構造上到達不能 | 証拠強度の刻印を全提案型で必須化 **MUST** | E-04 | 060 |
| DP9 | 抑止の痕跡がゼロ（`rejection_reason` 列なし、代替イベント生成は未呼出） | 抑止イベントを永続化 **MUST**（NP6） | E-05, E-17 | 057 |
| DP10 | センサー disable の dry-run が台帳を `applied` に汚す／`already_disabled` が提案を止めない | dry-run は台帳を変更しない **MUST** | E-06, E-07 | 068 |
| DP11 | LLM 注釈が prompt ハッシュ・生応答を記録しない | LLM 由来の全結論に prompt ハッシュ + 生応答 **MUST** | E-08 | 085 |
| DP12 | LLM 信頼度較正が収束せず、0.02 差分ガードが常に通過し、sample_n の JOIN が歪む | 較正は直近採択値を基準にし、集計単位を対象と一致させる **MUST** | E-09, E-10 | 086 |
| DP13 | revert 率が系統的に過小評価され、人手 revert も母数に混入 | 母数を `applied_by` で絞り、最終ペアの扱いを定義 **MUST** | E-11 | 077 |
| DP14 | スナップショット取得が「純粋読み取り」契約を破り DB 書き込みを起こす | 読み取りと復旧を分離 **MUST** | E-12 | 078 |
| DP15 | 未知の `applied_by` が最も緩い impact に落ちる | fail-closed **MUST** | E-13 | 075 |
| DP16 | 適用の部分失敗で「シナリオは新状態・台帳は pending」が残る | トランザクション境界で不可分 **MUST** | E-14 | 062 |
| DP17 | 発見が共通発行経路を迂回し、supersede が LIKE で誤爆しうる | 全提案が単一発行経路を通る **MUST** | E-15, E-16 | 065 |
| DP18 | recall ゲートが存在しない関数を呼び、例外握り潰しで恒久的に開いている | ゲートは実在・テスト済・fail-closed **MUST** | — | 044 |
| DP19 | 系列断絶（2026-07-04 / 08-02）がコードで強制されず手続きのみ | 系列エポックを一級市民として持つ **MUST** | D-01 | 043 |
| DP20 | 系譜の部分グラフが完全グラフと区別できない／結論との紐付けが存在しない | 完全性フラグ + 結論↔閾値の明示的紐付け **MUST** | — | 034, 035 |
| DP21 | 鮮度ゲートが異なるクロック（申告時刻 vs 書込時刻）を比較し、band 単位でない | 同一クロック比較 + band 単位のクロック **MUST** | — | 025 |
| DP22 | 較正ステップに絶対レンジのクランプが無く、反復緩和が幾何級数的に減衰しうる | 絶対レンジのクランプ **MUST** | — | 026 |
| DP23 | recall / precision の分母 0 が較正器では 0.0、集計層では None と非対称 | 全経路で「測れない = None」に統一 **MUST** | — | 021, 037 |
| DP24 | スケジューラのログ集計キーが ETL の実カウンタ名と不一致で常に 0 表示 | — | E-19 | 087 |
| DP25 | 収集されるが判定に使われない死んだメトリクス（提案数・受理率） | 収集するなら使う、使わないなら消す **MUST** | E-20 | 076 |

---

## 6. テストトレーサビリティ

D5 台帳の BEHAVIOR / CONTRACT 級テストのうち、較正領域に属するもの全件:

| テスト（件数） | 対応条項 |
|---|---|
| test_ground_truth_etl.py (39) | 004-012, 019 |
| test_severity.py (8) | 001 |
| test_run_rss_etl.py (23) | 002, 013-018 |
| test_run_ground_truth_etl.py (15) | 003, 019 |
| test_remediate_cross_scenario_labels.py (6) | 002, 043 |
| test_scenarios.py（GT 帰属部分） | 002 |
| test_tl_threshold_calibrator.py (6) | 020, 022, 026, 029 |
| test_tl_calibrator_guards.py (11) | 022, 023, **024** |
| test_calibration_governor.py (12) | 030-032, 081, 082 |
| test_lineage.py (9) | 033 |
| test_routes_calibration_v2.py (29) | 032, 046, 061, 069 |
| test_report_recall_metrics.py (8) | 011, 036, 037 |
| test_conclusion_calibration.py (8) | 038 |
| test_self_eval.py（recall 節） | 039 |
| test_check_recall_baseline.py (16) | 040-042 |
| test_check_recall_post_autotune.py (12) | 045 |
| test_proposal_guards.py (36) | 047-054, 058 |
| test_proposal_writer.py (14) | 046, 055 |
| test_proposal_lifecycle.py (30) | 059, 069, 070, 072, 073 |
| test_proposal_snooze_revival.py (5) | 071（相互作用は未検証） |
| test_scenario_structure_proposer.py (20) | 064 |
| test_scenario_discoverer.py (11) | 065 |
| test_drift_watchdog.py (8) | 066 |
| test_autotune_proposer_guards.py (13) | 067 |
| test_auto_apply_tier_governor.py (27) | 074, 076, 078-080 |
| test_g3b_llm_annotator.py (9) | 083, 084 |
| test_phase_cdf1.py（LLM conf 節） | 086 |
| test_calibration_run_now.py (20) | 088 |

**対応条項の無いテストは無い（GAP なし側）。逆方向の GAP（条項はあるが検証が無い）**:

| ID | 内容 | 条項 |
|---|---|---|
| GAP-01 | `auto_feedback_etl.py` に**専用テストが一切存在しない**（ラベル生成パイプラインの起動点） | 087 |
| GAP-02 | LLM 信頼度較正の**提案を発火させる 2 分岐（recall 低下 / precision 低下）が両方とも未カバー** | 086 |
| GAP-03 | 鮮度ゲートの SQL 経路（per-scenario スコープ、`applied_by` フィルタ、クロック不一致）が未検証。ガードテストは monkeypatch | 024, 025 |
| GAP-04 | tier の昇格成立（1→2 / 2→3）と降格の**直接テストが無い** | 076 |
| GAP-05 | revert 率の計算式（最終ペアの非計上、非数値の扱い）が未検証 | 077 |
| GAP-06 | recall ゲートを実行するテストが無いため、DP18（恒久 open）が検出されなかった | 044 |
| GAP-07 | auto-apply が **OFF のとき全提案が pending に留まる**ことを pin するテストが無い | 059 |
| GAP-08 | 提案のアナリスト遷移（非 pending が静かに失敗する）の単体テストが無い | 069 |
| GAP-09 | センサー disable のエスカレーション経路（ack 窓超過 → dry-run 台帳更新）が未検証 | 068 |
| GAP-10 | 較正器の例外伝播経路（鮮度ゲート・台帳読み・commit）と**band 途中失敗による部分コミット**が未検証 | 029 |
| GAP-11 | 国 alias の末尾境界 `(?!\w)` の専用テストが無い | 016 |
| GAP-12 | Design W ゲートの境界値ちょうど（`drop == max_drop` → PASS）が未検証 | 040 |
| GAP-13 | 系譜の部分グラフ（DB エラー時）と revert 後の `effective_to` 未設定が未検証 | 032, 035 |

**良い先例（v3 に持ち込む）**: tier governor のテストは autouse フィクスチャで
本番 DB アクセスを構造的に遮断している（リファクタ前のスイートが毎回本番 tier 履歴を
truncate していたことへの対策）。**v3 では全テストにこのパターンを適用 MUST**（D2 B-08）。

---

## 7. 未決事項

1. **ラベル生成器の検証系（D2 D-01）が仕様化できていない**。3 インシデントはすべて測定系の
   ロジックバグで、全テスト通過のまま数週間 prod を劣化させた。「平穏期に FN が湧いたら
   生成器を疑う」型の反事実チェックは S5（検証系）で**仕様として**設計する必要がある。
   本書は現行のガード群を保存するにとどまる
2. **系列エポックの表現**（S1-CALIB-043 / DP19）は設計判断が要る。ラベル行にラベル生成器
   バージョンを刻むのか、baseline 側にエポック id を持つのか、両方か。P で決める
3. **TL 閾値較正の有効化条件**（S1-CALIB-028）。現在は休眠しているため
   インシデント #2/#3 が live TL に波及しなかった。有効化の前提として、
   DP21（クロック不一致）/ DP22（絶対レンジ）/ GAP-03 の解消を先行させるべきかをオーナー裁定
4. **提案系の「休眠フルスタック」判断**。DP7 / DP8 / DP17 は「機能していない機構」であり、
   v3 で復活させるか凍結するかはオーナー判断（D2 C-02 の tradecraft と同種の論点）
5. `_proposal_guards` の 5 ソース定義と drift 監視の被覆判定が**別の集計を別の場所で持つ**。
   統合可能かは P の層設計で判断する
