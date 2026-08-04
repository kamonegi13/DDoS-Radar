# S1 — 較正機構 挙動仕様

**スコープ**: ground-truth ラベル生成 → recall メトリクス → 閾値較正（提案・台帳・系譜）→ 提案系（生成・
ガード・状態機械・適用）→ 自動適用 tier 統治 → LLM 較正系。スコアリング式は S1-scoring-core、
`calibration_status` の**出力形**は S1-conclusions、較正 API の HTTP 契約は S2-api、センサー健全性の一次判定は
S1-sensors-* が担当する。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**最重要要件**: 較正層は運用開始後 **3 回壊れた**。修正で入ったガードは v3 で挙動として厳密に保存する（該当条項に「由来: インシデント #n」を明記）。

| # | 日付 | 事象 | 主要な修正 |
|---|------|------|-----------|
| #1 | 2026-05-29 | blanket-TP: RSS ETL が全マッチを TRUE_POSITIVE にし FN≡0・recall 1.0 固定 | 17,758 行 purge、内部ソース由来 FN の廃止（循環性） |
| #2 | 2026-07-03 | **TL 反転**: 分類器が 5=最悪として実装され約 30k ラベルが逆転。middle_east 閾値が −5% ×12 | severity 空間の強制、エピソード粒度、鮮度ゲート、relevance ゲート |
| #3 | 2026-08-02 | **クロスシナリオ帰属汚染**: 支援役の言及で他紛争の記事が別シナリオの ground truth に。korea 閾値が −5% ×4 | 帰属を conflict-party role に限定、kinetic tier の action 動詞必須化、鮮度ゲートの direction-keyed 化 |

**一次ソース**: 実装 + テスト。**docstring は一次ソースとして採用しない**（DP1 のとおり記述ドリフトが systemic）。
素材: [_drafts/S1-calibration-llm-raw.md](_drafts/S1-calibration-llm-raw.md)、[_drafts/S1-calibration-proposals-raw.md](_drafts/S1-calibration-proposals-raw.md)。

## 1. 用語

CLAUDE.md の用語定義に従う。本書固有:

- **TL**: 脅威レベル。**1=CRITICAL … 5=NORMAL（DEFCON 式）**。順序比較は必ず `severity = 6 − TL` を経由（条項 001）
- **ラベル**: `TRUE_POSITIVE` / `FALSE_POSITIVE` / `TRUE_NEGATIVE` / `FALSE_NEGATIVE` の 4 値のみ
- **エピソード**: ground truth のトライアル単位 `(scenario_id, country, UTC 日)`。1 外部事象 = 1 トライアル
- **cell**: recall 集計の単位 `(scenario_id, conclusion_type)`
- **提案 (proposal)**: 較正が生成する変更案。適用は別経路（アナリスト API / auto-apply）
- **impact**: 提案の危険度 low / med / high。「recall を増やす方向は low、減らす方向は high」
- **tier**: 自動適用の許可レベル 0-3。0 = 提案のみ、3 = 全 impact 自動適用

## 2. 挙動条項

### A. ラベル生成（ground truth ETL）

#### S1-CALIB-001: TL の順序比較は severity 空間を経由しなければならない
**挙動**: TL の大小・閾値比較を行う全箇所は `severity = 6 − TL` に変換した値で比較 **MUST**。生の TL 整数を
`<` / `>` で比較してはならない **MUST NOT**。変換は 1..5 の範囲外で**例外を送出 MUST**（未パース状態文字列を
静かに誤採点させない）。
**根拠**: radar/conclusions/severity.py:23-27,32-43
**検証**: tests/test_severity.py（8 件、逆転番兵）
**分類**: CORE。**由来: インシデント #2**（5 週間、平穏な誤判定を報酬していた）

#### S1-CALIB-002: ground truth の帰属は conflict-party role に限定する
**挙動**: ラベル生成に使える国は role が `{adversary, primary_target, principal_belligerent, proxy_front}` の
participant のみ **MUST**。`primary_ally` / `forward_base` / `strategic_observer` を帰属に使ってはならない
**MUST NOT**。RSS と ACLED/GDELT の**両 ETL に同一ゲートを適用 MUST**。センシング（bg_observer）側は
全 participant の広い網を維持 **MUST**（NP1）。帰属国が空・シナリオ未知なら**スキップし例外を投げない MUST**。
**根拠**: radar/scenarios.py:49-61,130-139；run_rss_etl.py:162-174,352-354；run_ground_truth_etl.py:278-290,338-342
**検証**: tests/test_scenarios.py:380,392,399；tests/test_run_rss_etl.py:576；tests/test_remediate_cross_scenario_labels.py（帰属 2 件）
**分類**: CORE。**由来: インシデント #3**（korea の FN 15 件中 12 件がイラン/ウクライナ記事）

#### S1-CALIB-003: ラベル規則の評価順序は FN > TP > FP > TN
**挙動**: 規則は**この順に評価し最初に成立したものを採用 MUST**。いずれも不成立ならラベルを付けない
（=「現時点の証拠と矛盾しないが TN を宣言できる horizon が未経過」）**MUST**。この順序は NP1（見逃しを
最優先で表面化する）の encode であり、順序変更は仕様変更 **MUST NOT**。
**根拠**: radar/conclusions/ground_truth_etl.py:241-377
**検証**: tests/test_ground_truth_etl.py（39 件）
**分類**: CORE

#### S1-CALIB-004: FALSE_NEGATIVE は「TL=5 かつ外部の高強度事象」でのみ成立する
**挙動**: THREAT_LEVEL かつ **TL=5（NORMAL）** で、forward window 内の帰属国に **ACLED 由来**かつ
`severity >= fn_severity`（既定 **10**）の事象が 1 件以上あるとき FN **MUST**。`llm_intel` / `sequence_events` 由来の
証拠を FN 根拠に**使ってはならない MUST NOT** — スコアリングが消費するのと同じ信号であり、発火すれば
TL 自体が上がるため「ツールが見逃したもの」を原理的に暴けない（循環）。TP の corroboration には有効 **MUST**。
**根拠**: ground_truth_etl.py:231-238,299-325；config.py:306-307
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #2**（旧実装は TL==1=CRITICAL を「平穏」と判定）**+ #1**（循環証拠）

#### S1-CALIB-005: TRUE_POSITIVE は alert 結論 + forward window 内の適格事象
**挙動**: alert = (THREAT_LEVEL かつ `severity >= 3` すなわち **TL ≤ 3**) または (ATTACK_MODE かつ state が
非空で `INSUFFICIENT_DATA` でない) **MUST**。**TREND / PER_DOMAIN を alert に含めてはならない MUST NOT**
（診断面であり自動ラベル化は Design W の主 recall 指標を汚す）。state を数値化できない場合は alert でない **MUST**。
alert かつ forward window `[observed_at, observed_at + 72h]`（**両端閉区間 MUST**）に適格事象が 1 件以上あれば TP **MUST**。
**根拠**: ground_truth_etl.py:124-139,202-228,290-297,327-337；config.py:296
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #2**（旧 `int(state) >= 3` は CRITICAL/SEVERE を除外していた）

#### S1-CALIB-006: FP / TN は horizon 全経過後にのみ宣言でき、不在の主張は騙らない
**挙動**: `now >= observed_at + 7d` を満たすまで FP も TN も宣言しない **MUST**（`None` を返し次パスで再評価）。
経過後、horizon 窓内の適格事象が **0 件**のとき alert 結論 → FP、TL=5 結論 → TN **MUST**。両者の `analyst_id` は
**`auto:horizon` MUST** — 事象の**不在**を主張するラベルはどの証拠ソースにも corroborate されておらず、
ソース名を名乗ってはならない **MUST NOT**。
**根拠**: ground_truth_etl.py:74-77,339-375；config.py:300-301
**検証**: tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #1**（ACLED 未設定でも `auto:acled` を騙っていた）

#### S1-CALIB-007: 自動ラベルの identity は「ソースごとに 1 票」を表現する
**挙動**: `analyst_id` は優先順に ACLED∧GDELT→`auto:both` / ACLED / GDELT / LLM∧SEQUENCE→`auto:mixed` /
LLM / SEQUENCE **MUST**。これは `distinct_analysts` 集計が自動一致を **N 独立投票者ではなく 1 投票者**として
数えるための契約 **MUST**（自動ラベルが人手フィードバックを recall 較正で押し流すのを防ぐ）。
`observed_outcome_url` は最高 severity の事象のもの、`notes` はソース内訳を機械可読形式で 240 字以内 **MUST**。
**根拠**: ground_truth_etl.py:22-28,66-77,146-199
**検証**: tests/test_ground_truth_etl.py；tests/test_report_recall_metrics.py::test_distinct_analysts_counts_auto_sources_as_separate_voters
**分類**: CORE

#### S1-CALIB-008: graded under-rating は期待 severity floor との比較で判定する
**挙動**: 外部 kinetic 事象の規模から**ツールが示しているべきだった最小 severity** を導出 **MUST**:
`fatalities >= 10` → **4**（TL≤2）／`fatalities >= 1` または `confidence >= 0.60` → **3**（TL≤3）／else → **2**（TL≤4）。
判定は `severity_of(tool_tl) < floor` → FN、else TP **MUST**。TL→severity 変換はこの 1 箇所でのみ行う **MUST**
（TL=5 の二値トリップワイヤでは段階的過小評価を捕捉できない）。
**根拠**: ground_truth_etl.py:380-450
**検証**: tests/test_ground_truth_etl.py（severity floor 群）
**分類**: CORE（NP1）

#### S1-CALIB-009: kinetic tier は action 動詞を要求し、死者数を捏造しない
**挙動**: kinetic tier の認定には**行為を表す動詞**を要求 **MUST**（airstrike / shelling / bombardment /
invasion / "missiles strike|launch|fired" 等）。`missile` / `rocket` / `artillery` 等の**裸の武器名詞で
発火させてはならない MUST NOT** — 兵器試験・配備報道が同じ名詞を含むため posture として
**escalation tier（floor severity 2）へ落とす MUST**。死者数の記載が無いマッチの `fatalities` は **0 MUST**
（1 を代入してはならない **MUST NOT**）。confidence は 死者数あり **0.85** / kinetic **0.60** / posture **0.40** **MUST**。
**根拠**: radar/conclusions/rss_extractor.py:72-109,362-406
**検証**: tests/test_run_rss_etl.py / tests/test_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #3**（korea の FN 15 件中 12 件が posture 記事）

#### S1-CALIB-010: ラベル用証拠は escalation-relevance ゲートを通過しなければならない
**挙動**: ETL がラベルに使う記事は 3 段ラダーを通過 **MUST**: ①固有に軍事的な語彙は単独で適格で noise veto を
上書き ②弱い kinetic 動詞（attack / shooting / explosion 等）は軍事アクター名詞または**認識国 2 か国以上**が
併存する場合のみ適格 ③非紛争ノイズ語彙（台風・事故・野生動物・street crime）は②経由の適格を veto。
このゲートは **ETL のみに適用し bg_observer には適用しない MUST NOT**（NP1）。国 alias の照合は末尾 `\b` でなく
`(?!\w)` **MUST**（`"U.S."` の脱落防止）。
**根拠**: rss_extractor.py:111-186,268-273,315-319
**検証**: tests/test_run_rss_etl.py（alias 境界は未検証）
**分類**: CORE。**由来: インシデント #2 の後続修正**（熊スプレー事件と台風が台湾有事の証拠になっていた）+ **#3**（alias 境界）

#### S1-CALIB-011: 1 外部事象 = 1 トライアル（エピソード粒度）
**挙動**: トライアル単位は `(scenario_id, country, 事象の UTC 日)` **MUST**。1 記事は**シナリオごとに高々
1 エピソード**にしか紐づかない **MUST**（記事中の最初の conflict-party 国に anchor。言及国ごとに 1 件ずつ
作ってはならない **MUST NOT**）。同一エピソードに複数証拠が集まる場合、**最も重い floor が期待値を決め**（NP1）、
**最も早い報道時刻**が事前窓の起点となる **MUST**。
**根拠**: ground_truth_etl.py:514-537；run_rss_etl.py:343-374
**検証**: tests/test_run_rss_etl.py（23 件）
**分類**: CORE。**由来: インシデント #2 の後続修正**（1 記事が 72h 窓の全結論を採点し 30 日で約 23,000 ラベルを生成、sample_n が統計的に無意味化していた）

#### S1-CALIB-012: エピソードの採点は事前窓の最良 severity に対して 1 回だけ行う
**挙動**: 窓 `[event_at − window_h, event_at]` 内の当該シナリオ結論群に対し**1 回だけ**採点 **MUST**。窓内に
結論が無ければ採点しない **MUST**。窓内で**一度でも** floor に到達していれば TP とし、ラベルは**最良 severity を
達成した結論**に付与 **MUST**。一度も到達しなければ FN とし、ラベルは**事象直前の最新結論**（事象発生時に
ツールが表示していたもの）に付与 **MUST**。TL を数値化できない結論は採点対象外 **MUST**。
**根拠**: run_rss_etl.py:332-341,379-400
**検証**: tests/test_run_rss_etl.py
**分類**: CORE

#### S1-CALIB-013: 冪等性は 3 つの鍵で担保する
**挙動**: 再実行で重複ラベルを生成してはならない **MUST NOT**。鍵は ①`(conclusion_id, analyst_id)` の既存検出
②RSS エピソード鍵を `notes` 先頭に `episode=<scenario>/<country>/<day> ` の形で刻印し LIKE 判定
③ACLED/GDELT 側の day-cap `(scenario_id, label, 結論の UTC 日)` — 約 2 分ごとの結論が 1 つの世界状態を
混同行列の数百エントリへ擬似複製するのを防ぐ **MUST**。day-cap は同一 run 内のメモリ集合と DB 検査の
**両方**で判定 **MUST**。
**根拠**: ground_truth_etl.py:497-511,540-567；run_ground_truth_etl.py:372-395；run_rss_etl.py:402-404
**検証**: tests/test_ground_truth_etl.py / tests/test_run_ground_truth_etl.py
**分類**: CORE。**由来: インシデント #2 の後続修正**

### B. TL 閾値較正

#### S1-CALIB-014: 較正入力は THREAT_LEVEL 結論に紐づくラベル集計
**挙動**: シナリオごとに `analyst_feedback ⨝ conclusions` を `conclusion_type='threat_level'` で絞り label 別に
集計 **MUST**。`total = tp+fp+fn+tn` が既定 **30** 未満なら較正しない **MUST**（reason `insufficient_feedback`、
境界 `== 30` は通過）。`recall = tp/max(1,tp+fn)`、`precision = tp/max(1,tp+fp)`。
**根拠**: radar/calibration/tl_threshold_calibrator.py:57-58,87-109
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibratorInsufficientData
**分類**: **DEFECT-PRESERVE**（§5-DP23）— ①**時間窓が無い**（全履歴）ため他の recall 経路（30 日窓）と非対称
②`max(1,·)` により `tp+fn == 0` でも recall 0.0 となり誤読される（止めるのは条項 016 の鮮度ゲートのみ。
**両ガードは組で機能する**）

#### S1-CALIB-015: 方向判定は 4 分岐を固定順で評価する
**挙動**: ①`recall < 0.80` → **looser**（境界 0.80 は発火しない）②degenerate-data guard（`tn == 0` かつ `fn == 0`
かつ `precision < precision_min_floor + 0.20`）→ 無action ③`recall >= 0.99` かつ `precision < 0.30` → **tighter**
（境界 0.30 は発火しない）④else 無action **MUST**。recall 不足時は precision を見ない（①が先）**MUST**。
**根拠**: tl_threshold_calibrator.py:61-70,207-239
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibratorLowRecall / ::TestCalibratorLowPrecision；tests/test_tl_calibrator_guards.py（degenerate 2 件）
**分類**: CORE。degenerate の実効境界が tighten 上限と数値一致し tighten を不到達にする点は §4-A2

#### S1-CALIB-016: 緩和には新しい FN、厳格化には新しい FP を要求する（direction-keyed 鮮度ゲート）
**挙動**: 提案発行の前に**方向ごとに異なる動機証拠の鮮度**を検査 **MUST**。looser の動機証拠は
**FALSE_NEGATIVE の最新観測時刻**、tighter は **FALSE_POSITIVE の最新観測時刻** **MUST**。動機証拠が 1 件も
無ければ `no_motivating_evidence` で棄却 **MUST**。前回適用時刻が存在し `motivating_at <= last_applied` なら
`no_new_evidence` で棄却 **MUST**（**境界の等号は棄却側 MUST** — 厳密に新しい証拠のみが次の調整を正当化する）。
前回適用が無い初回は通過 **MUST**。**不変条件: 1 つの動機証拠状態は高々 1 回の調整しか正当化しない MUST**。
**根拠**: tl_threshold_calibrator.py:253-293
**検証**: tests/test_tl_calibrator_guards.py::test_freshness_gate_blocks_reapplying_stale_evidence / _allows_action_on_new_evidence /
_permissive_when_no_prior_change / **test_looser_blocked_when_only_non_fn_labels_are_new** / _blocked_when_no_fn_labels_exist / _tighter_keyed_on_fp_recency
**分類**: CORE。**由来: インシデント #3**。前身（2026-07-04 の「任意の新ラベル」形）は TP が毎週届くため素通りし、凍結した FN 群で korea 閾値を 4 回追加緩和した

#### S1-CALIB-017: 鮮度ゲートの前回適用時刻はシナリオ単位・自動較正由来のみを見る
**挙動**: 「前回適用時刻」は閾値台帳の `scope_scenario_id` 一致かつ `applied_by` が当該較正器マーカー一致の行の
`MAX(emitted_at)`。**band では絞らない**（5 band が 1 つの鮮度クロックを共有）。state でも絞らない。人手変更・
revert はクロックをリセットしない。DB エラーは伝播し提案は出ない（実質 fail-closed）。
**根拠**: tl_threshold_calibrator.py:125-134,281
**検証**: 未検証（SQL 経路。ガードテストは monkeypatch）
**分類**: **DEFECT-PRESERVE**（§5-DP21）— 比較する 2 時刻が**異なるクロック**（申告の `observed_at` vs 書込みの
`emitted_at`）であり、バックデートは常に stale、未来日付は恒久的にゲートを満たす

#### S1-CALIB-018: 較正ステップは全 band 一律の ±5%
**挙動**: looser → `round(current × 0.95, 3)`、tighter → `round(current × 1.05, 3)` **MUST**。基準値は当該 band の
直近**採択値**（無ければ既定値）**MUST**。5 band（`tl1_total` 9.0 / `tl1_physical` 3.0 / `tl2_total` 6.0 /
`tl3_total` 4.0 / `tl4_total` 2.0）**全てに毎回提案が出る**。
**根拠**: tl_threshold_calibrator.py:45-53,141-150,298-304
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibratorLowRecall
**分類**: **DEFECT-PRESERVE**（§5-DP22）— ①絶対下限・上限が無く反復緩和が幾何級数的に 0 へ収束しうる
（統治層の 10% magnitude 予算は 5% を素通しする）②band 単位の証拠が無いのに band 単位で動かす

#### S1-CALIB-019: 較正の提案は台帳へ渡すのみで、採点に直接副作用を持たない
**挙動**: 較正器はシナリオや採点を**直接変更してはならない MUST NOT**。提案は `key = tl_thresholds.<sid>.<band>`、
`applied_by = auto:tl_calibrator`、`sample_n = total`、`formula_ref = <version>#<band>_<direction>`、
`evidence = {recall, precision, tp, fp, fn, tn, direction, prior_value}` を持つ **MUST**。
**根拠**: tl_threshold_calibrator.py:137-169
**検証**: tests/test_tl_threshold_calibrator.py
**分類**: CORE（NP6）。evidence に**鮮度ゲートの入力が含まれない**ため台帳から「どの FN がこの変更を正当化したか」を再構成できない → §5-DP2

#### S1-CALIB-020: 較正値は現時点で採点に消費されない
**挙動**: TL 導出は既定値をハードコードし、較正された閾値を読まない。提案は台帳に記録されるが**採点に
影響しない**（Phase B 設計の意図的な段階分け）。
**根拠**: radar/scoring.py:1218-1228（台帳を参照しない）；tl_threshold_calibrator.py:24-28（「将来のフラグでゲート」と宣言するが実体なし）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§5-DP3）— インシデント #2/#3 が live TL に波及しなかったのはこの休眠状態の
おかげであり、有効化には条項 017/018 の欠陥解消が前提 **MUST**

#### S1-CALIB-021: シナリオ間の較正失敗は伝播しない
**挙動**: 1 シナリオの例外が他を止めてはならない **MUST NOT**。失敗は `{"error": <200 字>}` 形で結果に残す **MUST**。
シナリオ列挙自体の失敗は**空 dict を返す**（エラーと「シナリオ 0 件」が区別できない）。
**根拠**: tl_threshold_calibrator.py:329-355
**検証**: tests/test_tl_threshold_calibrator.py::TestCalibrateAllScenarios
**分類**: CORE（NP3）。列挙失敗の沈黙は §4-A4

### C. 閾値台帳と系譜

#### S1-CALIB-022: 閾値台帳は append-only、状態 3 値、時点照会と現行照会を区別する
**挙動**: 状態は `active` / `superseded` / `reverted` **MUST**。新規記録時、同一 `(key, scope)` の `active` 行を
`state='superseded'` かつ `effective_to = 新行の effective_from` で**同一トランザクション内に**クローズ **MUST**
（scope の NULL / 非 NULL で WHERE を分岐 **MUST**）。窓は半開区間で連続し、境界時刻ちょうどは**新行が勝つ MUST**。
「時刻 ts に有効だった値」の照会は **state で絞らない MUST**（後に superseded / reverted になった行が当時
有効だったのは事実）。「現在の値」の照会は `state='active'` に限る **MUST**。スコープ解決は
**scenario → グローバル（scope IS NULL）→ 未定義**の順 **MUST**。
**根拠**: radar/calibration/threshold_history.py:88-228
**検証**: tests/test_calibration_governor.py::TestThresholdHistory::test_supersedes_prior_active_row / _value_at_returns_active_at_timestamp / _scenario_scope_overrides_global
**分類**: CORE（NP6: 過去の結論を当時の閾値で再現できることが導出開示の前提）

#### S1-CALIB-023: revert は前任行の値を復元し、新しい行として記録する
**挙動**: 対象行が存在／`state='active'`／前任参照が非 NULL／前任行が存在の**4 条件をすべて満たすときのみ**実行
**MUST**。対象行を `state='reverted'` にし、**前任行の値を持つ新規行**を `derived_from = revert_of:<id>`、
`formula_ref = <台帳>#revert`、`evidence = {reverted_row_id, restored_from_row_id}` で記録 **MUST**。
**根拠**: threshold_history.py:231-276
**検証**: tests/test_calibration_governor.py::TestThresholdHistory::test_revert_creates_new_row_with_prior_value；tests/test_routes_calibration_v2.py（409 経路）
**分類**: CORE。**由来: インシデント #2/#3 の修復経路**（korea / middle_east 閾値の巻き戻しに使用）

#### S1-CALIB-024: 系譜は前任参照のみを辺とする読み取り専用の探索
**挙動**: 台帳行の前任参照を唯一の辺として祖先方向（線形）と子孫方向（BFS、fan-out 対応）を辿る **MUST**。
深さ上限（既定 50）を持ち **MUST**、循環を検出したら打ち切る **MUST**。系譜は**何も書き込まない MUST NOT**。
各ノードは行の全フィールド（formula_ref / evidence / applied_by / sample_n / magnitude_pct）を保持 **MUST**。
**根拠**: radar/calibration/lineage.py:87-173
**検証**: tests/test_lineage.py（9 件）
**分類**: CORE（NP6: 1 回の探索で判断を再現できる）

#### S1-CALIB-025: 系譜は結論と紐づかず、部分グラフを完全グラフと区別できない
**挙動**: どの結論がどの閾値行の下で生成されたかは**記録されず**、読み取り時に「結論の観測時刻で時点照会する」
ことで再計算される。また DB エラー・欠損行に遭遇した場合、探索は**部分グラフを黙って返す**（打ち切りフラグ無し）。
**根拠**: lineage.py:122-148（3 経路とも DEBUG ログのみ）；threshold_history.py:285-292
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§5-DP20）

### D. recall メトリクスと Design W ゲート

#### S1-CALIB-026: 混同行列の cell は (scenario_id, conclusion_type)、分母 0 は None
**挙動**: `analyst_feedback ⨝ conclusions` を cell 単位で集計 **MUST**。`(conclusion_id, analyst_id)` は
**最新行が勝つ MUST**。4 ラベル以外の値は 4 カウンタから落とすが `distinct_analysts` には計上 **MUST**。
`exclude_auto` 時は `analyst_id LIKE 'auto:%'` を除外 **MUST**。窓は `observed_at >=`（閉区間）。
`recall = tp/(tp+fn)`、`precision = tp/(tp+fp)`、**分母 0 は 0.0 ではなく `None` MUST**（= 測れない。後段ゲートでは
カバレッジ喪失として FAIL 扱い）。
**根拠**: scripts/report_recall_metrics.py:74-97,100-164
**検証**: tests/test_report_recall_metrics.py（8 件全て）
**分類**: CORE（NP5+8: 結論不可の明示）

#### S1-CALIB-027: per-scenario の較正状態は 30 日窓・3 値
**挙動**: 直近 **30 日**の `threat_level` フィードバックを集計し、`tp+fn < 5` または recall が None →
**`INSUFFICIENT_DATA`**、`recall < 0.70` → **`DEGRADED`**、else **`OK`** **MUST**（境界: denom == 5 は充足、
recall == 0.70 は OK）。判定軸は recall の分母であり総ラベル数ではない **MUST**（TN/FP しか無いシナリオは
INSUFFICIENT のまま）。この関数は**決して例外を送出してはならない MUST NOT**。結果は 300 秒 memo 化。
**根拠**: radar/conclusions/calibration.py:68-76,135-207
**検証**: tests/test_conclusion_calibration.py（8 件全て）
**分類**: CORE。窓キー `CALIBRATION_WINDOW_DAYS` が未定義で実質ハードコードである点は §5-DP4

#### S1-CALIB-028: 自己評価の recall は全 cell 横断・同一 30 日窓
**挙動**: AP3 の RECALL チップは全 cell を横断合算した `tp/(tp+fn)`（3 桁丸め）を返す **MUST**。窓は per-scenario
較正状態と**同一の 30 日 MUST**（全期間集計をしてはならない **MUST NOT**）。併せて `{window_days, labels_total,
labels_human, labels_auto, source}` を返す **MUST**（人手と自動の比率を隠さない）。例外時は `recall = None` +
`recall_error` **MUST**。DRIFT は per-scenario の miss rate `1 − recall` の平均（INSUFFICIENT と None は除外）**MUST**。
**根拠**: radar/routes/conclusions_v2.py:580-623,660-698
**検証**: tests/test_self_eval.py::test_self_eval_recall_uses_calibration_window_and_reports_breakdown
**分類**: CORE。**由来: インシデント #2 の後続修正**（窓不統一の解消）

#### S1-CALIB-029: Design W ゲートは cell ごとの recall 低下を 6 分岐で判定し、baseline 不在では失敗しない
**挙動**: baseline と現行スナップショットを cell 単位で比較 **MUST**: ①baseline にあり現行に無い →
**warn（失敗させない）**②baseline の recall が None → skip ③baseline が数値で現行が None → **FAIL（カバレッジ喪失）**
④`drop > max_drop`（既定 **0.05**）→ **FAIL** ⑤`0 < drop <= max_drop` → info（PASS、**境界の等号は PASS 側 MUST**）
⑥現行のみに存在 → info。baseline ファイルが無い場合は**警告を出して成功終了 MUST**（NP5+8「過渡的結論不可は
許容」）。比較時の窓と `exclude_auto` は **baseline 側の値を継承 MUST**。スナップショットは
`{schema_version, generated_at, since, exclude_auto, opt_in, cells[]}`、cell は
`{scenario_id, conclusion_type, tp, fp, tn, fn, total, recall, precision, distinct_analysts}` **MUST**。
`conclusion_type` は文字列完全一致で照合される **MUST**（大小文字が意味を持つ）。
**根拠**: scripts/check_recall_baseline.py:82-119,133-191,247-278；docs/baselines/recall_metrics.json；scripts/check_ci.sh:45-49（4 番目のゲート、無引数）
**検証**: tests/test_check_recall_baseline.py（16 件、6 分岐 + 窓継承）
**分類**: CORE

#### S1-CALIB-030: 2026-07-04 より前の recall 数値は別系列であり比較してはならない
**挙動**: recall / precision の時系列は **2026-07-04 の再スタート以降のみ連続 MUST**。それ以前と以後を同一系列
として比較・トレンド化してはならない **MUST NOT**（#1 の blanket-TP と #2 の TL 反転により、以前のラベル母集団は
測定アーティファクトである）。2026-08-02 の帰属修復も同様に系列を断つ。現行の担保は**手続き的**（汚染ラベルの
purge、baseline の再生成、30 日ローリング窓による自然な排出）であり、**コードによる強制は存在しない**。
**根拠**: docs/design/v2-migration.md:31,38,41-44；scripts/remediate_inverted_calibration.py:48,51-87；scripts/remediate_cross_scenario_labels.py
**検証**: tests/test_remediate_cross_scenario_labels.py（6 件、purge と閾値 revert）
**分類**: **DEFECT-PRESERVE**（§5-DP19）— CI ゲートが `since: null` の全履歴を比較するため、再 baseline を人手で怠れば断絶をまたぐ

#### S1-CALIB-031: 自動チューニングの recall ゲートは現在恒久的に開いている
**挙動**: 提案単位の統治層は「recall が red なら拒否」という規則を持つが、**呼び出す関数が実在せず**、例外が
握り潰されて常に「red でない」を返す。
**根拠**: radar/calibration/auto_tune_governor.py:131-151（`evaluate_against_baseline` は不在、`scripts/__init__.py` も無く import 自体が失敗）
**検証**: 未検証（このゲートを実行するテストが存在しない）
**分類**: **DEFECT-PRESERVE**（§5-DP18）— NP1 の最終防衛線が沈黙している

#### S1-CALIB-032: autotune 直後の recall 劣化検知は warn-only の 2 段構成
**挙動**: グローバルトレンド（`[now−2h, now−h)` 対 `[now−h, now)`）と、閾値台帳の active 行ごとの前後比較の 2 段。
`overall_ok = global_ok and autotune_ok` **MUST**。`drop > max_drop`（既定 0.10）で False、**境界の等号は OK 側**。
pre/post いずれかが None なら skip（データ不足で落とさない）**MUST**。NP6 のため失敗メッセージには必ず台帳の
行 id を含める **MUST**。既定は **warn-only（exit 0）**、`--strict` でのみ exit 1 **MUST**。判定軸は recall のみ（NP1）。
**根拠**: scripts/check_recall_post_autotune.py:14-23,65-217,224-285；check_ci.sh:51-58
**検証**: tests/test_check_recall_post_autotune.py（12 件）
**分類**: CORE

### E. 提案の生成とガード

#### S1-CALIB-033: 提案タイプは 9 種、自動適用の対象は 5 種のみ
**挙動**: `weight_too_low` / `weight_too_high` / `missing_participant` / `sensor_gap_detected` /
`scenario_dormant` / `dormant_participant` / `role_reclassify` / `scenario_discovery` / `sensor_disable` **MUST**。
適用プリミティブが対応するのは構造変更 5 種（前 3 種 + `dormant_participant` + `role_reclassify`）**のみ MUST** —
診断 3 種・発見・センサー無効化に自動適用経路を持たせてはならない **MUST NOT**（NP7）。
**根拠**: scenario_improver.py:432,519,571；_proposal_writer.py:139,173；scenario_apply.py:56-62
**検証**: tests/test_proposal_writer.py / tests/test_routes_calibration_v2.py
**分類**: CORE

#### S1-CALIB-034: recall を増やす提案（weight_too_low）の発火条件
**挙動**: 直近 **30 日**（ハードコード）の国別寄与量を数え、参加者が **3 未満なら空 MUST**。`contribs[cc] >= p75`
かつ `weight <= p25_weight`（両方等号含む）で発火 **MUST**。`p75 == 0` なら全体スキップ **MUST**。新重み
`round(min(0.95, w + step), 2)`、step 既定 **0.15**、同値なら発行しない **MUST**。
**根拠**: scenario_improver.py:70-71,396-440
**検証**: tests/test_proposal_guards.py（E2E）
**分類**: CORE。p75/p25 が真の分位点でなくインデックス近似である点は §5-DP5

#### S1-CALIB-035: recall を減らす提案（weight_too_high）は最も厳格な多層ガードを通す
**挙動**: 次の順で評価し、いずれかで停止 **MUST**: ①シナリオ活性が `active` でなければシナリオ単位で空
②全球のセンサー被覆が健全でなければシナリオ単位で空 ③参加者ごとに `weight <= 0` → skip、
`role ∈ PROTECTED_ROLES` → skip、証拠強度 `!= strong` → skip。
`PROTECTED_ROLES = {primary_target, principal_belligerent, adversary, core_country}` **MUST**。
新重みは `round(max(0.10, w − step), 2)` **MUST**。
**根拠**: scenario_improver.py:468-529；_proposal_guards.py:342-343,382-385
**検証**: tests/test_proposal_guards.py（36 件）
**分類**: CORE。**由来: 2026-04-29 事故**（25 件の weight_too_high が全 5 シナリオの primary_target に発火）

#### S1-CALIB-036: 多ソース三角測量は 5 ソース全ゼロを要求し、証拠強度は 6 段ラダーで決まる
**挙動**: 「本当に休眠している」の判定は 5 ソース（`llm_intel` / `sequence_events` / `sensor_observation_ts` /
アナリスト FN / `conclusions_contribution`）が**全て 0 MUST**。`llm_intel` は二重計上防止のため
`COUNT(DISTINCT id)` **MUST**。証拠強度は ①role 保護 → `insufficient` ②アナリスト FN > 0 → `insufficient`
③ゼロソース ≥5 → `strong` ④≥3 → `moderate` ⑤≥1 → `weak` ⑥else `insufficient` **MUST**。
**根拠**: _proposal_guards.py（P2 / P5）
**検証**: tests/test_proposal_guards.py
**分類**: CORE。**由来: 2026-04-29 事故後の締め直し**。docstring の「≥4 of 5」「strong=4+」「FN ≥ 1」との乖離は §5-DP1

#### S1-CALIB-037: FN の集計に国スコープが無く、1 件の FN が全世界の提案を止める
**挙動**: アナリスト FN の集計は**国フィルタ無しのグローバル集計**であり、30 日窓内にどこか 1 件でも FN が付くと、
あらゆる国の `weight_too_high` / `dormant_participant` が証拠強度 `insufficient` となり発行不能になる。
**根拠**: _proposal_guards.py:189-193 × :412-413（コード内で「保守的に過剰計上」と自認）
**検証**: tests/test_proposal_guards.py
**分類**: **DEFECT-PRESERVE**（§5-DP26）— NP1 的には安全側だが意図した設計か要裁定（§4-A5）

#### S1-CALIB-038: シナリオ活性は 3 状態、全センサー沈黙時は提案を全面抑止する
**挙動**: 活性判定は ①参加者 0 → `dormant` ②総信号 < floor **かつ** 被覆 < min_cov → **`data_gap`**（両方悪いときは
センサー側を先に疑う）③被覆 < min_cov → `data_gap` ④総信号 < floor → `dormant` ⑤else `active` **MUST**
（floor 既定 5、min_cov 既定 0.3）。加えて 30 日窓の `llm_intel` + `sequence_events` + `sensor_observation_ts` の
**全球合計**が `min_global_signals`（既定 **50**）未満なら、recall を減らす提案をシナリオ単位で抑止 **MUST**。
任意テーブル（`scenario_contribution_log`）は集計に**含めない MUST NOT**（欠損で判定を下げないため）。
**根拠**: _proposal_guards.py:342-343,382-385（P3 / Phase B）
**検証**: tests/test_proposal_guards.py
**分類**: CORE。**由来: 上流 API 障害で「5/5 ゼロ = strong」が全参加国に成立した全滅提案事故**

#### S1-CALIB-039: missing_participant はシナリオスコープを強制する
**挙動**: 証拠となる `sequence_events` は**必ず `scenario_id` で絞る MUST**。窓 30 日固定、閾値既定 **3**。
既存参加者・国コード空はスキップ **MUST**。初期値は保守的固定（`weight = 0.30`、`role = strategic_observer`）**MUST**。
**根拠**: scenario_improver.py:550-575
**検証**: tests/test_proposal_guards.py（回帰テストあり）
**分類**: CORE。**由来: 2026-04-29 二次事故**（UA が全 5 シナリオに提案された）

#### S1-CALIB-040: 提案発行は dedup → cap → INSERT の 3 出口
**挙動**: ①同一 `(scenario_id, proposal_type, target_country)` が **`state IN ('pending','applied')`** かつ
`emitted_at > now − 7d` で存在するなら発行しない **MUST** ②当該シナリオの pending 数が既定 **5** 以上なら
発行しない **MUST** ③else `state='pending'` で INSERT、JSON 列は `sort_keys=True` で正規化 **MUST**。INSERT 後の
supersede と auto-apply フックは**非致命 MUST**。dedup 判定の DB 例外は「重複なし」、cap カウント失敗は 0 扱い
（いずれもフェイルオープン）。
**根拠**: scenario_improver.py:97-192,201-228
**検証**: tests/test_proposal_writer.py / tests/test_proposal_lifecycle.py
**分類**: CORE。dedup 対象を pending のみ → pending|applied に拡張したのは
**由来: auto-apply 済み行の再発火で重みが発振した事故**。フェイルオープンは §4-A6

#### S1-CALIB-041: 抑止の理由は永続化されない
**挙動**: ガードが発行を止めた場合、**行が作られないため永続的痕跡が残らない**（`rejection_reason` 列が無い）。
残るのはログとプロセス内オブジェクトのみ。「結論不可の明示」を担う代替イベント生成関数は**本番から呼ばれていない**。
**根拠**: radar/database.py:1280-1298；_proposal_writer.py:208-237 vs scenario_improver.py:508-511
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§5-DP9）— NP6 の「なぜ結論を出さなかったか」が追えない

#### S1-CALIB-042: ガード本体と本番経路が二重化している
**挙動**: 統合ガード関数は**本番から一度も呼ばれず**、実際の `weight_too_high` は 4 ヘルパーを個別に呼ぶ
再実装経路を通る。統合ガードの 3 フラグ算出式は**テストでのみ実行される仕様**。
**根拠**: scenario_improver.py:468-511 vs _proposal_guards.py:441-483
**検証**: tests/test_proposal_guards.py（本番が通らない経路を検証している）
**分類**: **DEFECT-PRESERVE**（§5-DP7）

#### S1-CALIB-043: auto-apply 判定木は impact / 証拠強度 / role 再検査 / tier の 4 段
**挙動**: フラグ ON 時のみ評価 **MUST**（既定 **OFF**）。①impact 分類（`weight_too_low` / `missing_participant` → low、
`role_reclassify` → med、`weight_too_high` / `dormant_participant` → high、他 → 対象外）②証拠強度の下限
（low 系 weak / missing moderate / recall 削減系 strong、**未知型は strong**）③recall を減らす 2 型は**現在の**
シナリオ定義から role 保護を**再検査 MUST**（発行後の role 変更への多層防御）④tier ゲート（low は tier≥1、
med ≥2、high ≥3、low/med は HIGH cooldown 中なら拒否）**MUST**。high の適用成功後のみ HIGH cooldown を起動 **MUST**。
**根拠**: scenario_improver.py:265-386
**検証**: tests/test_proposal_lifecycle.py / tests/test_auto_apply_tier_governor.py
**分類**: CORE

#### S1-CALIB-044: role_reclassify の自動適用は構造上到達不能
**挙動**: 構造提案器は evidence に証拠強度を書かないが auto-apply は `strong` を要求するため、フラグ ON でも
**永久に適用されない**。
**根拠**: scenario_structure_proposer.py:197-218 × scenario_improver.py:268,303-311
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§5-DP8）

#### S1-CALIB-045: 適用プリミティブは 7 段検証を順に通す
**挙動**: ①提案行ロード ②pending 検査 ③型検査 ④提案値 JSON パース ⑤シナリオロード + `state=="active"`
⑥型別 mutation ⑦参加者検証 → 永続化 → ストア再読込 → 台帳 flip **MUST**。**不変条件: ①〜⑤で失敗した場合、
DB 変更はゼロで台帳は pending のまま MUST**。失敗コードは 16 種の文字列で識別 **MUST**。`applied_by` は
アクター非依存に透過 **MUST**（変更ログに記録 = NP6）。重み範囲の強制は参加者検証（0.0–1.0）のみが担い、
発行時 floor（0.10/0.95）とは別レイヤ。参加者検証は**変更対象だけでなく mutation 後の全参加者**に走る。
**根拠**: scenario_apply.py:56-62,118-306,243-249；radar/scenarios.py:248-265
**検証**: tests/test_routes_calibration_v2.py
**分類**: CORE。重み範囲の別レイヤ化は §4-A7

#### S1-CALIB-046: 適用後の台帳更新失敗は不整合として残る
**挙動**: mutation 永続化後に台帳 flip が失敗した場合、`ok=False` を返すが**mutation は反映済み**であり
「シナリオは新状態・台帳は pending」の不整合が残る（再適用で二重変更しうる）。
**根拠**: scenario_apply.py:274-294
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§5-DP16）

#### S1-CALIB-047: 構造提案器の閾値群は改善器と別値である
**挙動**: source_type → role マップ 10 エントリ固定、未登録は曖昧としてスキップ **MUST**。dominant 判定は件数
既定 **5** かつシェア既定 **0.50** の 2 段 floor **MUST**。窓は既定 **30 日**。dormant の減算幅は
**0.20 ハードコード**（改善器の 0.15 と別値）、下限 0.10 **MUST**。dedup / cap / auto-apply は改善器の発行経路を継承 **MUST**。
**根拠**: scenario_structure_proposer.py:43-61,74-104,107-192,237-287,327-341
**検証**: tests/test_scenario_structure_proposer.py（20 件）
**分類**: CORE。減算幅の不一致は §4-A8

#### S1-CALIB-048: シナリオ発見は共通発行経路を迂回する
**挙動**: DBSCAN（eps 既定 **0.6** / min_samples 既定 **3**）。スナップショットは既定 **23 時間**以内なら再利用 **MUST**。
既存シナリオとの重複は **Jaccard >= 0.7** でスキップ **MUST**（シナリオ列挙に失敗すると `existing = []` に
フォールバックし**全クラスタが提案される**）。提案行は `scenario_id='__discovery__'` 固定。
**根拠**: scenario_discoverer.py:51-76,127-154,165-174,208-247
**検証**: tests/test_scenario_discoverer.py（11 件）
**分類**: **DEFECT-PRESERVE**（§5-DP17）— 共通発行経路を通らないため dedup 窓・active cap・auto-apply
フック・証拠強度刻印を一切受けず、supersede の LIKE フォールバックが別クラスタを誤 supersede しうる

#### S1-CALIB-049: drift 監視は 7 種の信号を出し、シナリオを変更しない
**挙動**: 信号は `sensor_outage` / `participant_silent` / `adversary_mismatch` / `recall_underperform` /
`chronic_insufficient` / `participant_orphan` / `proposal_quality_inversion` **MUST**。監視はシナリオを
**一切変更してはならない MUST NOT**。発行は upsert で、同一 `(scenario_id, drift_signal, target_country)` の
未確認行が**直近 24 時間**に存在すれば連続回数の加算と時刻更新のみ **MUST**。**UI に出るのは連続 3 回以上のみ MUST**
（dwell-time ガードレール、既定窓 168h）。確認操作は未確認行のみ更新し、発行時刻と連続回数は保存 **MUST**（NP6）。
**根拠**: drift_watchdog.py:43-56,75-118,150-522,554-563,580-653
**検証**: tests/test_drift_watchdog.py（8 件）
**分類**: CORE

#### S1-CALIB-050: センサー無効化提案は fetch 層の健全性で抑止される
**挙動**: 対象は LLM ゲート済み 7 センサ固定。broken 判定は 7 日窓の LLM 呼出ログで `pre_ratio >= 0.95`
**または** `err_ratio >= 0.20` **MUST**。呼出が既定 **100** 未満なら分類自体を行わない **MUST**（未稼働センサの
誤 disable 防止）。**fetch 層が健全（直近 24h の成功 ≥ 10 かつ最終エラー無し）なら LLM 側が broken でも
提案しない MUST**（「動いているセンサを切るよりプロンプトを締めろ」）。
**根拠**: sensor_disable_proposer.py:62-89,133-194
**検証**: tests/test_autotune_proposer_guards.py（13 件）
**分類**: CORE

#### S1-CALIB-051: センサー無効化のエスカレーションは dry-run でも台帳を applied にする
**挙動**: ack 窓（既定 **24h**）超過時、自動無効化フラグが false でも台帳は `state='applied'` に更新され
`state_changed_by='auto:escalation_dry_run'` になる。`already_disabled` ガードは「再提案しない」意図で
False（= 提案続行）を返す。確認操作は「ack」と称して実際には `state='dismissed'` を書く。
**根拠**: sensor_disable_proposer.py:117-155,260-287,388-398
**検証**: 未検証（エスカレーション経路）
**分類**: **DEFECT-PRESERVE**（§5-DP10）— AP3 スコアボードと drift の集計が「実際には無効化していない」行で汚染される

### F. 提案の状態機械

#### S1-CALIB-052: 提案の状態は 6 値のみ
**挙動**: `pending` / `applied` / `dismissed` / `snoozed_30d` / `reverted` / `superseded` **MUST**（既定 pending、
DB CHECK 制約が正）。`accepted` / `rejected` / `auto_dismissed` / `expired` は**存在しない MUST NOT** — 区別は
`state_changed_by` のマーカー文字列のみ。提案台帳に `reverted` を書く経路は**存在しない**（閾値台帳専用）。
アナリスト遷移は **pending からのみ MUST**（非 pending は静かに失敗）。
**根拠**: radar/database.py:1294；scenario_improver.py:743-762；routes/calibration_v2.py:278-388
**検証**: tests/test_proposal_lifecycle.py（30 件）
**分類**: CORE。マーカー文字列でしか区別できない設計は §4-A9

#### S1-CALIB-053: 自動 dismiss は 3 フックで条件・閾値・マーカーが異なる
**挙動**: ①非アクティブシナリオ: `pending` かつシナリオが `paused|archived` → **時間条件なし**、マーカー
`auto:inactive_scenario` ②診断型: `pending` かつ診断 3 種かつ `emitted_at < now − 7d`、マーカー
`auto:diagnostic_acknowledged` ③実行可能型: `pending` かつ `emitted_at < now − 30d` かつ非診断型かつシナリオ
active、マーカー `auto:timeout_no_action` **MUST**。判定基準は **`emitted_at`**（状態変更時刻ではない）**MUST**。
3 フックは同一ティックで連続実行される。
**根拠**: proposal_lifecycle.py:309,350；scheduler.py:531-591
**検証**: tests/test_proposal_lifecycle.py
**分類**: CORE

#### S1-CALIB-054: Defer した提案は復活直後に必ず自動 dismiss される
**挙動**: snooze 復活は `state_changed_at` を基準に判定して `pending` に戻すが**`emitted_at` を更新しない**。
自動 dismiss は `emitted_at` で判定するため、既定設定（snooze 30 日 = stale 30 日）では**Defer した提案は
復活直後の次ティックで必ず `auto:timeout_no_action` になる**。
**根拠**: database.py:5522-5545（:5534, :5542）vs proposal_lifecycle.py:309,350
**検証**: tests/test_proposal_snooze_revival.py（5 件、この相互作用は未検証）
**分類**: **DEFECT-PRESERVE**（§5-DP6、HIGH）— Defer が構造的に機能していない。**現行系でも要修正**

#### S1-CALIB-055: supersede は 2 系統、再ゲート再投入は 1 ティック 3 件まで
**挙動**: supersede の通常系は `(scenario_id, proposal_type, target_country)` の素の 3 カラム等値（NULL 意味論を
明示分岐、自己排除あり、DB 例外は 0 件として握り潰し）**MUST**。発見系のみ fingerprint 系統 **MUST**。マーカーは
`auto:supersede_by_id_<新ID>` / `auto:phase_d_fingerprint` / `admin:<user>` の 3 種 **MUST**。dedup 窓 7 日内は
発行自体がブロックされるため、supersede の実効対象は**窓外に生き残った古い pending のみ**。
既存 pending の auto-apply ゲート再投入は 30 日以内かつ impact 分類を持つ型のみ、1 ティック **3 件**まで **MUST**
（過剰フェッチ 3×8 で型/年齢スキップがレート枠を飢餓させない）。直前の再読込で非 pending なら skip **MUST**。
**根拠**: proposal_lifecycle.py:474-527（supersede）、`reprocess_pending_through_gate`
**検証**: tests/test_proposal_lifecycle.py
**分類**: CORE

### G. 自動適用 tier 統治

#### S1-CALIB-056: tier は 4 状態、impact ごとに許可が異なる
**挙動**: tier 0 = いかなる impact も台帳に書かない／1 = low のみ／2 = low+med／3 = 全部 **MUST**。impact 分類の
規範は「**recall を増やす方向は low、減らす方向は high**」**MUST**（保留それ自体が recall 削減であるという NP1 論拠）。
許可判定は**例外時に必ず不許可 MUST**（NP3）。`impact_override` は厳密に low/med/high のときのみテーブル参照を
スキップ **MUST**（タイポは無視して迂回防止）。
**根拠**: auto_apply_tier_governor.py（`APPLIED_BY_IMPACT` 13 エントリ、`is_apply_allowed`）
**検証**: tests/test_auto_apply_tier_governor.py::TestTierGovernorBasics
**分類**: CORE

#### S1-CALIB-057: 未知の適用者は最も緩い impact に落ちる
**挙動**: impact テーブルに無い `applied_by` は impact=low に既定分類される（「保守的既定」と称するが実際には
**最も緩い**分類）。
**根拠**: auto_apply_tier_governor.py:247
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§5-DP15）

#### S1-CALIB-058: 昇格は 3 段、降格は全 tier 共通の単一条件
**挙動**: 0→1 は `auto_feedback_rows >= 100` の**単一条件 MUST**（dwell も revert_rate も要求しない。tier 0 では
閾値台帳が構造的に空のため提案数を要件にすると鶏卵デッドロックになる）。1→2 は `days_at_tier >= 7.0` かつ
`revert_rate_7d <= 0.05`、2→3 は `>= 14.0` かつ `revert_rate_14d <= 0.05` **MUST**。1 回の評価で**最大 1 段階 MUST**。
降格は全 tier 共通で `revert_rate_24h >= 0.20` **MUST**。**降格判定を昇格より先に行う MUST**（安全側バイアス）。
ヒステリシスは「昇格 ≤0.05（7d/14d 窓）対 降格 ≥0.20（24h 窓）」の非対称性で実現 **MUST**。
**根拠**: auto_apply_tier_governor.py（昇降格ゲート）
**検証**: tests/test_auto_apply_tier_governor.py::TestPromotion（昇格成立と降格の直接テストは無い）
**分類**: CORE。tier 遷移が recall 劣化を直接の軸にしない点は §4-A10、死んだメトリクスは §5-DP25

#### S1-CALIB-059: revert 率は隣接ペアの方向反転で数え、系統的に過小評価される
**挙動**: 閾値台帳を `emitted_at >= now − 窓×2.0` で読み、`(key, scope)` ごとに時系列順の隣接ペアを走査。
`long_delta = next − prev`、`short_delta = curr − prev` として `long_delta != 0` かつ `short_delta × long_delta < 0`
を revert と判定 **MUST**。ペア間隔が窓を超えたらスキップ **MUST**。`pairs == 0` / DB 例外は 0.0 **MUST**。
**根拠**: auto_apply_tier_governor.py:529-535,551-569
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§5-DP13）— ①最終ペアは分母に入るが分子に入らない ②float 変換失敗も分母のみ
増やす ③`applied_by` フィルタが無く**人手 revert も降格の母数に混入** ④疎なデータでは昇格が常に通過

#### S1-CALIB-060: 滞留時間の解決は 4 段で、marker 復旧が書き込みを起こす
**挙動**: ①marker が一致かつ tier > 0 → marker 由来 ②状態変更行 → 行由来 ③marker のみ生存 → 警告 +
復旧行を書き込み + marker 由来 ④無し → 0.0 **MUST**。**marker と state が矛盾する場合は state を優先 MUST**
（状態行が記録上の台帳）。marker は tier が実際に変わるときのみ更新 **MUST**（同一 tier への再遷移では
滞留をリセットしない）。
**根拠**: auto_apply_tier_governor.py:616-624,814-816
**検証**: tests/test_auto_apply_tier_governor.py::TestTierEnteredMarker
**分類**: **DEFECT-PRESERVE**（§5-DP14）— スナップショット取得が「純粋読み取り」契約を破り DB 書き込みを起こす

#### S1-CALIB-061: HIGH cooldown と強制降格（CB / キルスイッチ）
**挙動**: HIGH 適用後 既定 **24.0h** の間、**low と med を同時に停止 MUST**。**high 自身は対象外**（HIGH 直後も
HIGH は通る）。絶対時刻で保存し HIGH のたびに窓を再計測 **MUST**。tier 昇降格・CB・キルスイッチは cooldown を
クリアしない **MUST NOT**（自然失効のみ）。発火判定はテーブル参照のみで `impact_override` を考慮せず、
env 不正値では cooldown が**設定されないまま無音で終了**する。連続 **3 回**の評価失敗で tier を 0 に強制し
遷移種別 `circuit_breaker` を記録 **MUST**（連続失敗数は成功・昇格・降格・ハートビートのいずれでもリセット、
復帰経路は**通常の昇格のみ**）。tier 上限は `cap < 生の格納 tier` で判定 **MUST**（cap 適用後の値で判定すると
真のキルスイッチ事象が記録されない）。キルスイッチ降格は**1 段階ずつでなく cap の値へ一気に落とす MUST**。
**根拠**: auto_apply_tier_governor.py（cooldown 群、`CONSECUTIVE_FAILURE_LIMIT = 3`、`AUTO_CALIBRATION_TIER_CAP`）
**検証**: tests/test_auto_apply_tier_governor.py::TestHighCooldown / ::TestCircuitBreaker / ::TestKillSwitchDemotion
**分類**: CORE。override 非考慮・無音失敗・上限不正値のフェイルオープンは §4-A11 / A12

#### S1-CALIB-062: 提案単位の統治は 7 規則を固定順で評価する
**挙動**: ①サンプル数（既定 **30**、境界 `== 30` は通過）②recall ゲート ③tier ゲート ④cooldown（既定 **72h**、
`(key, scope)` 単位、境界 `elapsed == cooldown` は通過）⑤無変更ショートサーキット ⑥magnitude クランプ
⑦永続化 **MUST**。この順序により **tier ゲート拒否が cooldown より優先**され、tier 0 環境では全提案が
`tier_gate` で落ちる。recall ゲートは**例外時に許可（フェイルオープン）**、tier ゲートは**例外時に拒否
（フェイルクローズ）MUST**。
**根拠**: auto_tune_governor.py:56-64,149-151,154-274
**検証**: tests/test_calibration_governor.py::TestGovernorSampleSize / ::TestGovernorCooldown / ::TestGovernorRecallGate / ::TestGovernorUnchanged
**分類**: CORE

#### S1-CALIB-063: magnitude 超過は拒否ではなくクランプして受理する
**挙動**: `abs((new − prior)/prior)×100` が既定 **10.0%** を超える場合、拒否せず
`prior + sign(delta)×abs(prior)×(max_pct/100)` にクランプして受理 **MUST**。台帳の記録値は要求値でなく
**上限値** **MUST**。degenerate: `prior == 0` かつ `new != 0` → 100.0、非数値（bool 含む）→ 100.0。
**`prior == 0` はクランプせず new をそのまま返す**。初出キーは `magnitude_pct = 0.0` で**上限チェックなしに
verbatim コミット MUST**。**方向制限は実装されていない**（絶対値で符号を無視。方向の唯一の制約は impact 分類）。
**根拠**: auto_tune_governor.py:227-266
**検証**: tests/test_calibration_governor.py::TestGovernorMagnitude
**分類**: CORE。`prior == 0` の予算外扱いと初出 verbatim は §4-A13

### H. LLM 較正系

#### S1-CALIB-064: LLM 注釈の状態は 3 値で shadow-first、既定は両 OFF
**挙動**: 状態は `production` > `shadow` > `none` の 3 値で production が shadow を上書き **MUST**。`none` では
**DB に一切触れない no-op MUST**。フラグ解決は kill switch → DB override → env → registry 既定（**OFF**）の順 **MUST**
（NP7 shadow-first）。shadow 行は明示要求が無い限り UI から除外 **MUST**。注釈は suggest-only であり、
シナリオを自動生成してはならない **MUST NOT**（NP1/NP7）。
**根拠**: g3b_llm_annotator.py:94-123,186-201,292-297；llm_features.py:183-198,376-411
**検証**: tests/test_g3b_llm_annotator.py::TestEnvGate（2 件）
**分類**: CORE

#### S1-CALIB-065: LLM 注釈は上限がソフトで、導出開示の鎖が切れている
**挙動**: 日次コール上限（既定 **50**）の計測は**例外を握り潰して 0 を返す**ため、ログが読めない環境では上限が
事実上無効化される。消費カウントは実際に LLM を呼んだかに無関係に加算される。CB は連続失敗（既定 **5**）で
開くが**run 冒頭で毎回リセットされる**ため実効スコープは 1 run。LLM 失敗時は注釈を書かず未注釈のまま残し、
例外を投げず skipped 化する **MUST**（NP3）。注釈に記録されるのはプロンプトバージョンのみで、
**プロンプトのハッシュも生応答も記録されない**。パラメータは固定（temperature 0.1 / max_tokens 300）、
永続化時に切り詰め（name 120 / description 500 / rationale 300）、JSON は `sort_keys=True` で決定化 **MUST**。
**根拠**: g3b_llm_annotator.py:37-39 vs :258-269；:86-91,134-150,242-256,288-290,318-333
**検証**: tests/test_g3b_llm_annotator.py（cap のみ。CB スコープ・過大計上・NP6 欠落は未検証）
**分類**: **DEFECT-PRESERVE**（§5-DP11、DP1）

#### S1-CALIB-066: LLM 信頼度下限の較正は収束しない ±0.05 ヒューリスティック
**挙動**: 対象は 7 センサ固定。母数は `TP+FP+FN`、既定 **30** 未満は `insufficient_feedback` **MUST**。
分岐 A（緩め）: `recall < floor`（既定 **0.85**）→ `max(floor_lo, global_min − 0.05)`／分岐 B（締め）:
`precision < 0.5` かつ `recall >= floor + 0.10` → `min(floor_hi, global_min + 0.05)`。**A が先に評価され、
recall 不足時は precision を見ない**。
**根拠**: llm_confidence_calibrator.py:49-69,93-119,136-167
**検証**: tests/test_phase_cdf1.py::TestLLMConfidenceCalibrator（**提案を発火させる 2 分岐は未カバー**）
**分類**: **DEFECT-PRESERVE**（§5-DP12）— ①提案値は常に `global_min ± 0.05` で**直近採択値を読まない**
②0.02 差分ガードは差分が常に 0.05 のため**常に通過** ③レンジのクランプは既定設定で実効しない
④sample_n の JOIN がセンサ単位でなくシナリオ単位

#### S1-CALIB-067: 自動フィードバック ETL は単一ダイヤルで、dedup を下流に委譲する
**挙動**: ground truth 系と RSS 系の両パスは**同一のフラグ 1 つ**でゲートされる **MUST**
（`V2_GROUND_TRUTH_ETL_ENABLED` 既定 **false**）。ACLED は API キーと email の**両方**が揃ったときのみ有効化し、
片方欠落で GDELT-only に自動縮退 **MUST**。`None` は失敗ではなく**ガード終了のシグナル MUST**。dedup は下流 ETL の
冪等性（条項 013）に委譲 **MUST**。既定は ground truth 窓 14d / limit 1000、RSS 窓 14d / **limit 4000**。
**根拠**: auto_feedback_etl.py:54-58,60-70,88-90,107-126；config.py:290-294
**検証**: **専用テスト不在**（GAP-01）
**分類**: CORE。limit の非対称は §4-A14。スケジューラのログ集計キー不一致は §5-DP24

#### S1-CALIB-068: 手動一括較正は決定的な 8 段順序で、1 段の失敗が他を止めない
**挙動**: 実行順は `tl → llm_conf → sensor_disable → scenario → structure → discovery → g3b → drift` **MUST**。
phase 関数は遅延 import し、1 つの import 失敗が他を妨げない **MUST**。個別実行は**決して例外を送出しない MUST NOT**
（失敗は結果の `error` に 200 字で格納）。例外を送出するのは**未知 phase 名の場合のみ MUST**（空文字も未知扱い）。
戻り値は常にリスト **MUST**。終了コードは 1 件でも失敗なら 1 **MUST**。NP7: センサー自動無効化を除き
production scoring への副作用は無い **MUST**。
**根拠**: run_now.py:44-55,58-68,101-143,146-196
**検証**: tests/test_calibration_run_now.py::TestDispatchAll::test_runs_phases_in_order（20 件）
**分類**: CORE

## 3. 閾値カタログ

| 閾値 | 値 | config キー | DB override | 条項 |
|---|---|---|---|---|
| GT forward 窓 / FP-TN horizon / FN 死者数 | 72h / 7d / 10 | `GROUND_TRUTH_WINDOW_HOURS` / `..._FALSE_POSITIVE_HORIZON_DAYS` / `..._FALSE_NEGATIVE_FATALITIES` | 不可 | 004,005,006 |
| ETL 一括ゲート / 既定 limit（GT / RSS） | false / 1000 / 4000 | `V2_GROUND_TRUTH_ETL_ENABLED` / — | 不可 | 067 |
| severity floor（mass / kinetic / escalation） | 4 / 3 / 2 | — | 不可 | 008 |
| confidence ラダー | 0.85 / 0.60 / 0.40 | — | 不可 | 009 |
| TL 較正 最小フィードバック | 30 | `TL_CALIB_MIN_FEEDBACK_PER_CELL` | 不可 | 014 |
| TL 較正 recall floor / precision 上限 / 下限 | 0.80 / 0.30 / 0.10 | `TL_CALIB_RECALL_FLOOR` / `..._PRECISION_CEILING` / `..._PRECISION_MIN_FLOOR` | 不可 | 015 |
| TL 較正ステップ / 既定閾値 5 band | ×0.95, ×1.05 / 9.0, 3.0, 6.0, 4.0, 2.0 | — | 不可 | 018 |
| 閾値台帳 list 窓 / 系譜深さ上限 | 168h / 50（API は 1-200） | — | 不可 | 022,024 |
| calibration_status 窓 / 最小正例 / DEGRADED | 30d / 5 / 0.70 | `CALIBRATION_WINDOW_DAYS`（**未配線**） | 不可 | 027 |
| Design W 許容 drop | 0.05 | `--max-drop` | 不可 | 029 |
| post-autotune 窓 / 許容 drop / 最小サンプル | 168h / 0.10 / 10 | CLI | 不可 | 032 |
| 提案 dedup 窓 / pending 上限 | 7d / 5 | `SCENARIO_IMPROVER_DEDUP_DAYS` / `..._MAX_ACTIVE` | 不可 | 040 |
| 重み step（改善器 / 構造提案器）/ 上下限 | 0.15 / **0.20** / 0.95, 0.10 | `SCENARIO_IMPROVER_WEIGHT_STEP` / — | 不可 | 034,035,047 |
| missing_participant 閾値 / 窓 | 3 / 30d | `SCENARIO_IMPROVER_MISSING_EVENT_N` | 不可 | 039 |
| vitality floor / min coverage / 全球最小信号 | 5 / 0.3 / 50 | — / — / **キーワード引数のみ** | 不可 | 038 |
| 構造提案 dominant / シェア / 窓 | 5 / 0.50 / 30d | `STRUCTURE_PROPOSER_*` | 不可 | 047 |
| 発見 eps / min_samples / 鮮度 / Jaccard | 0.6 / 3 / 23h / 0.7 | `DISCOVERY_*` | 不可 | 048 |
| drift dwell / upsert 窓 / 表示窓 | 3 回 / 24h / 168h | — | 不可 | 049 |
| センサー disable α(pre/err) / 最小呼出 / ack 窓 | 0.95, 0.20 / 100 / 24h | `SENSOR_DISABLE_*` | 不可 | 050,051 |
| 自動 dismiss（診断 / 実行可能）/ snooze | 7d / 30d / 30d | `DIAGNOSTIC_AUTO_ACK_DAYS` / `PROPOSAL_STALE_TIMEOUT_DAYS` / `PROPOSAL_SNOOZE_DAYS` | 不可 | 053,054 |
| 再ゲート 上限 / 最大年齢 | 3 件/tick / 30d | — | 不可 | 055 |
| tier 昇格（0→1 / 1→2 / 2→3）/ 降格 | 100 行 / 7d+0.05 / 14d+0.05 / 0.20(24h) | — | 不可 | 058 |
| tier 上限 / 連続失敗上限 / HIGH cooldown | 3 / 3 / 24.0h | `AUTO_CALIBRATION_TIER_CAP` / — / `AUTO_APPLY_HIGH_COOLDOWN_HOURS` | 不可 | 061 |
| autotune 最小サンプル / cooldown / magnitude | 30 / 72h / 10.0% | `AUTO_TUNE_*` | 不可 | 062,063 |
| g3b 日次上限 / CB 失敗数 / バッチ | 50 / 5 / 20 | `G3B_*` | 不可 | 064,065 |
| LLM 信頼度較正 最小 / recall floor | 30 / 0.85 | `LLM_CONF_CALIB_*` | 不可 | 066 |

**v3 への示唆**: 較正系の閾値は **DB override が 1 つも実装されていない**（提案の適用値のみが台帳経由で可変）。NP6 の観点では、結論と自動判断に影響する全閾値を宣言的 registry に載せるべき（D2 A-13）。

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | TL 較正の入力集計に時間窓が無い（全履歴）。他の全 recall 経路は 30 日窓 | 系列断絶（030）と両立しない。窓を入れるべきか |
| A2 | degenerate guard の実効 precision 境界（0.30）が tighten 上限（0.30）と一致し `tn==0 かつ fn==0` では tighten 不到達 | 意図的な結合か偶然か |
| A3 | 較正ステップ ±5% が magnitude 予算 10% を常に下回るため、クランプが較正器に実効しない | 二重防御の意図があったか |
| A4 | シナリオ列挙失敗が空 dict を返し「シナリオ 0 件」と区別できない | NP5+8 的にはエラーを表明すべき |
| A5 | FN のグローバル集計で 1 件の FN が全世界の recall 削減提案を止める | NP1 的には安全側。意図した設計かの確認（D2 E-02） |
| A6 | dedup / cap のカウント失敗がフェイルオープン（提案を通す） | 発振事故の再発経路。fail-closed にすべきか |
| A7 | 重み範囲の強制が適用層に無く、提案 JSON を書き換えれば 0.0 / 1.0 が通る | 権限を持つアナリストのみが触れる前提でよいか |
| A8 | 重み減算幅が改善器 0.15 / 構造提案器 0.20 と別値 | 意図的な差か、コピペドリフトか |
| A9 | 提案の終端状態が 6 値しかなく、accept / auto-dismiss / expire の区別がマーカー文字列でしか表現されない | AP4（判断履歴）の再生に十分か |
| A10 | tier 遷移が recall 劣化を直接の判定軸にしない（recall ゲートは提案単位のみ） | tier 側の再チェックが要るか |
| A11 | HIGH cooldown の発火判定が `impact_override` を考慮せず、env 不正値で無音失敗する | 迂回経路として許容するか |
| A12 | tier 上限の不正値が 3（最大許可）にフォールバックする | キルスイッチの意味が消える。fail-closed にすべきか |
| A13 | magnitude 予算が `prior == 0` のとき適用されず、初出キーは verbatim コミットされる | 0 起点の変更を予算外にする根拠 |
| A14 | 自動 ETL の limit が ground truth 1000 / RSS 4000 と非対称 | 意図的か |
| A15 | 較正系の閾値に DB override が 1 つも実装されていない（docstring は「DB-stored config」と述べる） | 運用中の調整可能性をどこまで持たせるか |

## 5. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 | 条項 |
|---|---|---|---|---|
| DP1 | docstring と実装の乖離が systemic（P2「≥4 of 5」vs 5/5、evidence_strength のリテラル誤り、P5 の不等号反転、run_now の phase 欠落、tier governor の「DB-stored config」、CB スコープ） | 仕様書が正本。docstring は仕様書を参照するのみ **MUST**。CI で乖離を検出する仕組みが要る | E-18 | 036,065,068 |
| DP2 | 較正 evidence に鮮度ゲートの入力が含まれず、台帳から変更の正当化根拠を再構成できない | 判断に使った全入力を evidence に記録 **MUST** | — | 019 |
| DP3 | 較正値が採点に消費されない休眠状態（「動いているつもりで動いていない」） | 休眠機構を検出する仕組みを持つ **MUST**（S5） | E 総論 | 020 |
| DP4 | `CALIBRATION_WINDOW_DAYS` がどこにも定義されず getattr の既定 30 が常に勝つ | 全閾値は宣言的 registry 経由 **MUST** | A-13 | 027 |
| DP5 | p75 / p25 が真の分位点でなくインデックス近似（n=4 で最大値を指す等の境界ずれ） | 分位点は定義どおり **MUST** | — | 034 |
| DP6 | Defer が構造的に機能しない（復活直後に必ず自動 dismiss） | 状態機械の時刻基準を統一 **MUST**。**現行系でも要修正** | E-01 | 054 |
| DP7 | ガード本体が本番から呼ばれず、4 ヘルパーの再実装経路が動く | 単一経路 **MUST** | E-03 | 042 |
| DP8 | role_reclassify の自動適用が構造上到達不能 | 証拠強度の刻印を全提案型で必須化 **MUST** | E-04 | 044 |
| DP9 | 抑止の痕跡がゼロ（`rejection_reason` 列なし、代替イベント生成は未呼出） | 抑止イベントを永続化 **MUST**（NP6） | E-05,E-17 | 041 |
| DP10 | センサー disable の dry-run が台帳を `applied` に汚す／`already_disabled` が提案を止めない | dry-run は台帳を変更しない **MUST** | E-06,E-07 | 051 |
| DP11 | LLM 注釈が prompt ハッシュ・生応答を記録しない／日次上限がソフト | LLM 由来の全結論に prompt ハッシュ + 生応答 **MUST**、上限は fail-closed **MUST** | E-08 | 065 |
| DP12 | LLM 信頼度較正が収束せず、0.02 差分ガードが常に通過し、sample_n の JOIN が歪む | 直近採択値を基準にし、集計単位を対象と一致させる **MUST** | E-09,E-10 | 066 |
| DP13 | revert 率が系統的に過小評価され、人手 revert も母数に混入 | 母数を `applied_by` で絞り、最終ペアの扱いを定義 **MUST** | E-11 | 059 |
| DP14 | スナップショット取得が「純粋読み取り」契約を破り DB 書き込みを起こす | 読み取りと復旧を分離 **MUST** | E-12 | 060 |
| DP15 | 未知の `applied_by` が最も緩い impact に落ちる | fail-closed **MUST** | E-13 | 057 |
| DP16 | 適用の部分失敗で「シナリオは新状態・台帳は pending」が残る | トランザクション境界で不可分 **MUST** | E-14 | 046 |
| DP17 | 発見が共通発行経路を迂回し、supersede が LIKE で誤爆しうる | 全提案が単一発行経路を通る **MUST** | E-15,E-16 | 048 |
| DP18 | recall ゲートが存在しない関数を呼び、例外握り潰しで恒久的に開いている | ゲートは実在・テスト済・fail-closed **MUST** | — | 031 |
| DP19 | 系列断絶（2026-07-04 / 08-02）がコードで強制されず手続きのみ | 系列エポックを一級市民として持つ **MUST**（ラベル行に生成器バージョン、baseline にエポック id、不一致で FAIL） | D-01 | 030 |
| DP20 | 系譜の部分グラフが完全グラフと区別できない／結論との紐付けが存在しない | 完全性フラグ + 結論↔閾値の明示的紐付け **MUST** | — | 025 |
| DP21 | 鮮度ゲートが異なるクロック（申告時刻 vs 書込時刻）を比較し、band 単位でない | 同一クロック比較 + band 単位のクロック **MUST** | — | 017 |
| DP22 | 較正ステップに絶対レンジのクランプが無く、反復緩和が幾何級数的に減衰しうる | 絶対レンジのクランプ **MUST** | — | 018 |
| DP23 | 較正入力に窓が無く、recall の分母 0 が較正器では 0.0、集計層では None と非対称 | 明示的窓 **MUST**、全経路で「測れない = None」に統一 **MUST** | — | 014,026 |
| DP24 | スケジューラのログ集計キーが ETL の実カウンタ名と不一致で常に 0 表示 | キー名の単一定義 **MUST** | E-19 | 067 |
| DP25 | 収集されるが判定に使われない死んだメトリクス（提案数・受理率） | 収集するなら使う、使わないなら消す **MUST** | E-20 | 058 |
| DP26 | アナリスト FN が国スコープ無しのグローバル集計で、1 件で全世界の recall 削減提案が止まる | スコープ付き集計 **MUST**（抑止範囲を証拠の範囲に一致させる） | E-02 | 037 |

## 6. テストトレーサビリティ

D5 台帳のうち較正領域に属するテスト全件:

| テスト（件数） | 対応条項 | | テスト（件数） | 対応条項 |
|---|---|---|---|---|
| test_ground_truth_etl.py (39) | 003-008, 013 | | test_proposal_guards.py (36) | 034-039, 042 |
| test_severity.py (8) | 001 | | test_proposal_writer.py (14) | 033, 040 |
| test_run_rss_etl.py (23) | 002, 009-012 | | test_proposal_lifecycle.py (30) | 043, 052, 053, 055 |
| test_run_ground_truth_etl.py (15) | 002, 013 | | test_proposal_snooze_revival.py (5) | 054 |
| test_remediate_cross_scenario_labels.py (6) | 002, 030 | | test_scenario_structure_proposer.py (20) | 047 |
| test_scenarios.py（GT 帰属部分） | 002 | | test_scenario_discoverer.py (11) | 048 |
| test_tl_threshold_calibrator.py (6) | 014, 015, 018, 021 | | test_drift_watchdog.py (8) | 049 |
| test_tl_calibrator_guards.py (11) | 015, **016** | | test_autotune_proposer_guards.py (13) | 050 |
| test_calibration_governor.py (12) | 022, 023, 062, 063 | | test_auto_apply_tier_governor.py (27) | 056, 058, 060, 061 |
| test_lineage.py (9) | 024 | | test_g3b_llm_annotator.py (9) | 064, 065 |
| test_routes_calibration_v2.py (29) | 023, 033, 045, 052 | | test_phase_cdf1.py（LLM conf 節） | 066 |
| test_report_recall_metrics.py (8) | 007, 026 | | test_calibration_run_now.py (20) | 068 |
| test_conclusion_calibration.py (8) | 027 | | test_check_recall_baseline.py (16) | 029 |
| test_self_eval.py（recall 節） | 028 | | test_check_recall_post_autotune.py (12) | 032 |

**対応条項の無いテストは無い。逆方向の GAP（条項はあるが検証が無い）**:

| ID | 内容 | 条項 |
|---|---|---|
| GAP-01 | `auto_feedback_etl.py` に**専用テストが一切存在しない**（ラベル生成パイプラインの起動点） | 067 |
| GAP-02 | LLM 信頼度較正の**提案を発火させる 2 分岐（recall 低下 / precision 低下）が両方とも未カバー** | 066 |
| GAP-03 | 鮮度ゲートの SQL 経路（per-scenario スコープ、`applied_by` フィルタ、クロック不一致）が未検証 | 016, 017 |
| GAP-04 | tier の昇格成立（1→2 / 2→3）と降格の**直接テストが無い** | 058 |
| GAP-05 | revert 率の計算式（最終ペアの非計上、非数値の扱い）が未検証 | 059 |
| GAP-06 | recall ゲートを実行するテストが無いため DP18（恒久 open）が検出されなかった | 031 |
| GAP-07 | auto-apply が **OFF のとき全提案が pending に留まる**ことを pin するテストが無い | 043 |
| GAP-08 | 提案のアナリスト遷移（非 pending が静かに失敗する）の単体テストが無い | 052 |
| GAP-09 | センサー disable のエスカレーション経路（ack 窓超過 → dry-run 台帳更新）が未検証 | 051 |
| GAP-10 | 較正器の例外伝播経路と**band 途中失敗による部分コミット**が未検証 | 018, 021 |
| GAP-11 | 国 alias の末尾境界 `(?!\w)` の専用テストが無い | 010 |
| GAP-12 | Design W ゲートの境界値ちょうど（`drop == max_drop` → PASS）が未検証 | 029 |
| GAP-13 | 系譜の部分グラフ（DB エラー時）と revert 後の `effective_to` 未設定が未検証 | 023, 025 |

**良い先例（v3 に持ち込む）**: tier governor のテストは autouse フィクスチャで本番 DB アクセスを構造的に遮断
している（リファクタ前のスイートが毎回本番 tier 履歴を truncate していたことへの対策）。**v3 では全テストにこのパターンを適用 MUST**（D2 B-08）。

## 7. 未決事項

1. **ラベル生成器の検証系（D2 D-01）が仕様化できていない**。3 インシデントはすべて測定系のロジックバグで、全テスト通過のまま数週間 prod を劣化させた。
   「平穏期に FN が湧いたら生成器を疑う」型の反事実チェックは S5（検証系）で**仕様として**設計する必要がある。本書は現行のガード群を保存するにとどまる
2. **系列エポックの表現**（条項 030 / DP19）。ラベル行に生成器バージョンを刻むのか、baseline 側にエポック id を持つのか、両方か。P で決める
3. **TL 閾値較正の有効化条件**（条項 020）。現在は休眠しているためインシデント #2/#3 が live TL に波及しなかった。
   有効化の前提として DP21 / DP22 / GAP-03 の解消を先行させるべきかをオーナー裁定
4. **提案系の「休眠フルスタック」判断**。DP7 / DP8 / DP17 は「機能していない機構」であり、v3 で復活させるか凍結するかはオーナー判断（D2 C-02 の tradecraft と同種の論点）
5. 提案ガードの 5 ソース定義と drift 監視の被覆判定が**別の集計を別の場所で持つ**。統合可能かは P の層設計で判断する
