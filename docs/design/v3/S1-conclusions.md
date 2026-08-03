# S1 — 結論導出 (conclusions) 挙動仕様

**スコープ**: ツールの**出力そのもの**の定義。5 種の結論 (THREAT_LEVEL / TREND / PER_DOMAIN /
ANOMALY / ATTACK_MODE) の統一スキーマ・導出式・閾値・**結論不可 (UnavailableReason) の全パターン**・
v2 envelope・台帳への書込ゲート・慢性結論不可検知・replay/self_eval・markdown エクスポート・
analyst feedback 台帳・週次人間アンカーキュー。

**隣接仕様との境界**:
- スコア → TL の写像（数式・収斂・ヒステリシス）は **S1-SCORE-004 ほか S1-scoring-core が優越**。
  本書は「その TL を結論としてどう組み立て、何を添えて公開するか」だけを扱う
- ground-truth ラベル生成 (auto:acled / auto:gdelt ETL、severity floor ラダー) は **S1-calibration** 担当。
  本書は生成済みラベルを**読む**側 (calibration_status / recall) のみ
- 採点ティックの順序と副作用は S1-scoring-pipeline 担当。本書は「どのフックがどの型を出すか」の
  ゲート条件のみ記述する
- `radar/conclusions/rss_extractor.py` は物理的に本パッケージ配下にあるが**責務はセンサー層**
  （D2 C-08 配置違和感）。S1-sensors 担当とし本書では扱わない
- `radar/conclusions/shadow_metrics.py` は v1→v2 移行足場 (D2 C-03)。v3 に持ち込まないため
  **仕様化しない**（本書は成功/失敗カウンタの存在のみ前提とする）

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md) に従う。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソースについて**: PER_DOMAIN / TREND / ATTACK_MODE の閾値は D5 の指示どおり実装値を CORE とした。
ただし **D5 §3-7 の前提（「実値はテストのみが保持」）は誤り**である。当該テスト群は閾値を
**モジュール定数として import し、定数相対で境界を検証する**設計であり、数値そのものは pin していない。
数値の唯一の所在はモジュール定数であり、テストは「threshold_ref が定数を漏れなく公開しているか」の
ドリフト検知装置である（§7 GAP-01/02）。

---

## 1. 用語

CLAUDE.md の用語定義に従う。本書固有:

- **conclusion**: ツールが公開する 1 個の判断。5 型のいずれか。台帳 (ledger) に append-only で蓄積される
- **envelope**: 結論を API 応答として包む外殻。`api_version` / `scenario_id` / `observed_at` /
  `final_judgment_disclaimer` / `conclusions[]`
- **結論不可 (unavailable)**: 状態を出せないこと。`state=None` かつ `conclusion_unavailable_reason` 非 None
- **packed state**: 複数の下位状態を 1 本の文字列に詰めた state 表現（`cyber=ACTIVE;physical=STABLE;info=STABLE`）
- **change gate**: 状態が変化したときと heartbeat 周期だけ台帳に書く間引き機構
- **open run**: ある (scenario, type) が結論不可であり続けている連続区間
- **TL**: 脅威レベル。**1=CRITICAL … 5=NORMAL（DEFCON 式）**。大小比較は必ず `severity = 6 − TL` に
  変換してから行う（反転事故 2 回の教訓）

---

## 2. 挙動条項

### 2.1 統一スキーマと不変条件

### S1-CONC-001: 結論は 5 型のみ
**挙動**: 結論の型は `threat_level` / `trend` / `per_domain` / `anomaly` / `attack_mode` の
5 値のいずれか **MUST**。この 5 型は CLAUDE.md ツール定義の「全体脅威レベル、トレンド、ドメイン別兆候、
個別異常事象、推定攻撃シナリオ」と 1:1 対応する。
**根拠**: radar/conclusions/base.py:20-27
**検証**: tests/test_conclusions.py::test_all_conclusion_types_construct
**分類**: CORE

### S1-CONC-002: state と結論不可理由は排他
**挙動**: 結論は「状態あり」か「結論不可」のいずれか一方 **MUST**。
`conclusion_unavailable_reason is None` なら `state` は非 None **MUST**、
`conclusion_unavailable_reason` が非 None なら `state is None` **MUST**。
両条件違反は**構築時に拒否する MUST**（沈黙の半端な結論を作らせない）。
**根拠**: base.py:76-83
**検証**: test_conclusions.py::test_unavailable_conclusion_requires_null_state /
::test_available_conclusion_requires_non_null_state / ::test_unavailable_conclusion_with_null_state_is_valid
**分類**: CORE（NP5+8 の型レベル強制）

### S1-CONC-003: confidence は [0.0, 1.0] を構築時に強制
**挙動**: `confidence` が [0.0, 1.0] の外なら**構築を拒否する MUST**（クランプではなく拒否）。
**根拠**: base.py:72-75
**検証**: test_conclusions.py::test_confidence_must_be_between_zero_and_one（パラメタライズ）
**分類**: CORE

### S1-CONC-004: NP7 disclaimer は空文字を許さない
**挙動**: `final_judgment_disclaimer` が空文字列 / None の結論は**構築を拒否する MUST**。
既定文言は config キー `V2_NP7_DISCLAIMER`
（既定 `"Tool conclusion only — final judgment by organizational process."`）。
**根拠**: base.py:84-87、config.py:227-230
**検証**: test_conclusions.py::test_disclaimer_is_required；
test_threat_level_derive.py::test_disclaimer_uses_config_value；
test_trend_derive.py::test_disclaimer_attached_per_np7；
test_per_domain_derive.py::test_disclaimer_attached_per_np7；
test_attack_mode_derive.py::test_disclaimer_uses_config_value；
test_anomaly_derive.py::test_disclaimer_uses_config_value
**分類**: CORE（NP7 を型で強制。5 型すべてが独立に検証されている）

### S1-CONC-005: 結論は生成後に変更不能
**挙動**: 結論オブジェクトは**不変 MUST**。下流の加工（LLM 補強等）は**複製を返す MUST**。
**根拠**: base.py:48（frozen）
**検証**: test_conclusions.py::test_conclusion_is_frozen；
test_attack_mode_llm_augment.py::test_rule_conclusion_is_not_mutated
**分類**: CORE（NP6: 公開済み結論の事後改変を構造的に禁止）

### S1-CONC-006: 結論 ID は生成ごとに一意
**挙動**: 各結論は生成時に一意 ID（UUID 形式）を持つ **MUST**。同一内容の再導出でも ID は異なる。
**根拠**: base.py:43-45
**検証**: test_conclusions.py::test_conclusion_id_is_unique
**分類**: CORE

### S1-CONC-007: 直列化契約
**挙動**: API 表現では列挙型は**文字列値に落とす MUST**（`conclusion_type` / `conclusion_unavailable_reason`）。
永続表現では `threshold_ref` / `source_urls` / `calibration_status` / `metadata` を
**JSON 文字列化 MUST**、辞書は**キー昇順で安定化 MUST**（差分可読性・ハッシュ安定性のため）。
`source_urls` は API 表現ではリスト、内部表現では不変列。
**根拠**: base.py:93-136
**検証**: test_conclusions.py::test_to_dict_serialization_round_trip / ::test_to_db_row_serializes_json_fields /
::test_unavailable_reason_serializes_to_string
**分類**: CORE

### S1-CONC-008: disclaimer は行に保存せず読み出し時に注入する
**挙動**: 台帳から結論を復元する際、`final_judgment_disclaimer` は**行の値ではなく現行 config 値を
注入する MUST**。文言を改訂したとき過去行が古い文言を持ち続けることを防ぐ。
**根拠**: persistence.py:336-354
**検証**: 未検証（§7 GAP-08）
**分類**: CORE

### S1-CONC-009: 結論不可理由は 4 値の閉じた列挙 — **本書の中核 (NP5+8)**
**挙動**: 結論不可の理由は以下 4 値のみ **MUST**。理由なしの結論不可は表現できない（S1-CONC-002）。

| 値 | 意味 | 発生条件（実装上の全経路） |
|---|---|---|
| `insufficient_data` | 判断に足るデータが集まっていない | (a) TL が導出できない (S1-CONC-020) / (b) TREND の 3 窓すべてが標本不足 (S1-CONC-032) / (c) PER_DOMAIN の 3 ドメインすべてが無信号 (S1-CONC-038) / (d) ANOMALY に採点可能な寄与が 1 件も無い (S1-CONC-047) / (e) ATTACK_MODE でどの規則も発火しない (S1-CONC-054) / (f) 台帳に当該 (scenario, type) の行がまだ無い (S1-CONC-014) |
| `calibration_pending` | calibration 未成立のため結論を保留 | **現行実装で生成する経路が存在しない**（§6 DP2） |
| `sensor_degraded` | センサー劣化により結論不可 | **同上、生成経路なし**（§6 DP2） |
| `upstream_failure` | 上流障害により結論不可 | **同上、生成経路なし**（§6 DP2） |

**根拠**: base.py:30-40（列挙定義）、threat_level.py:126、trend.py:121、per_domain.py:106、
anomaly.py:128、attack_mode.py:107、api.py:63
**検証**: test_threat_level_derive.py::test_tl_none_yields_insufficient_data；
test_trend_derive.py::test_empty_db_yields_insufficient_data；
test_per_domain_derive.py::test_all_domains_silent_yields_insufficient_data；
test_anomaly_derive.py::test_no_contributions_yields_single_insufficient_data；
test_attack_mode_derive.py::test_no_signals_yields_insufficient_data / ::test_below_all_floors_yields_insufficient_data；
test_conclusions_api.py::test_bundle_endpoint_returns_unavailable_for_empty_scenario
**分類**: CORE。**ただし 4 値中 3 値が未使用であることは ACCIDENTAL**（§5-A1）

### S1-CONC-010: 結論不可は「否定の主張」ではない
**挙動**: 結論不可の結論は、**当該事象が存在しないことを主張してはならない MUST**。
とくに ATTACK_MODE の結論不可は「攻撃なし」ではなく「規則が判断を放棄した」を意味する。
結論不可行には `metadata.is_transient`（真偽）と `metadata.reason_detail`（平文の理由）を
**必ず添える MUST**。
**根拠**: attack_mode.py:96-113、threat_level.py:127-135、trend.py:122-126、per_domain.py:107-112、anomaly.py:129-134
**検証**: test_attack_mode_derive.py::test_no_signals_yields_insufficient_data（is_transient を検証）；
test_trend_derive.py::test_empty_db_yields_insufficient_data；
test_anomaly_derive.py::test_no_contributions_yields_single_insufficient_data
**分類**: CORE（NP1: 見逃しを「無害」と誤読させない）

### 2.2 v2 API envelope

### S1-CONC-011: envelope は 5 フィールド固定 + disclaimer 二重掲示
**挙動**: 成功応答は `api_version` / `scenario_id` / `observed_at` / `final_judgment_disclaimer` /
`conclusions[]` を持つ **MUST**。**各結論オブジェクト自身も disclaimer を保持する MUST**
（envelope を剥がしても NP7 が残る）。`api_version` は `"2.0"`。
**根拠**: api.py:20-43
**検証**: test_conclusions_api.py::test_bundle_endpoint_returns_latest_of_each_type；
test_analyst_feedback_v2.py::TestEndpoint::test_returns_v2_envelope
**分類**: CORE

### S1-CONC-012: envelope の observed_at は最新結論に従う
**挙動**: `observed_at` 未指定時は**同梱結論の観測時刻の最大値 MUST**。結論が空なら現在時刻。
**根拠**: api.py:33-36
**検証**: 未検証（§7 GAP-08）
**分類**: CORE

### S1-CONC-013: エラー応答にも disclaimer と api_version を載せる
**挙動**: 4xx / 5xx を含む**すべての v2 応答**が `api_version` と
`final_judgment_disclaimer` を持つ **MUST**。
**根拠**: api.py:46-56
**検証**: test_conclusions_api.py::test_v2_error_responses_carry_disclaimer（パラメタライズ）
**分類**: CORE（NP7 の抜け穴封じ）

### S1-CONC-014: 台帳行が無い (scenario, type) は「まだ言うことがない」を返す
**挙動**: 台帳に行が無い場合、404 ではなく**結論不可 envelope を 200 で返す MUST**。
理由は `insufficient_data`、`confidence=0.0`、`formula_ref=null`、`threshold_ref={}`、
`source_urls=[]`、`metadata.is_transient=true`。
「試みて失敗した」ではなく「まだ何も言えない」を表現する。
**根拠**: api.py:59-99
**検証**: test_conclusions_api.py::test_bundle_endpoint_returns_unavailable_for_empty_scenario
**分類**: CORE。**結論オブジェクトを経由せず dict を手組みしている点は ACCIDENTAL**（§5-A2）

### S1-CONC-015: v2 面はフラグで一括無効化でき、無効時は 503
**挙動**: v2 API 全体を単一フラグで無効化でき、無効時は全エンドポイントが
**503 + NP7 準拠エラー body を返す MUST**。
**閾値**: `V2_API_ENABLED` 既定 **True**
**根拠**: routes/conclusions_v2.py:56-66、config.py:244
**検証**: test_conclusions_api.py::test_v2_returns_503_when_flag_off / ::test_md_export_503_when_v2_disabled；
test_conclusions_feedback.py::test_post_503_when_v2_disabled / ::test_get_503_when_v2_disabled
**分類**: CORE。**恒常 true の移行足場である点は D2 C-03**（v3 では撤去 MUST）

### S1-CONC-016: bundle は 5 型それぞれの最新行を返す
**挙動**: シナリオ単位の bundle は 5 型それぞれについて**最新 1 行**を集めて返す **MUST**。
型ごとに独立に「最新」を判定する（1 型が古くても他型は最新を返す）。1 型も無ければ S1-CONC-014。
**根拠**: routes/conclusions_v2.py:134-143
**検証**: test_conclusions_api.py::test_bundle_endpoint_returns_latest_of_each_type / ::test_bundle_endpoint_picks_newest_per_type
**分類**: CORE

### S1-CONC-017: 不正な型は 400、不明な結論 ID は 404
**挙動**: 未知の conclusion_type 指定は **400 MUST**（有効値一覧を detail に含む）。
未知の結論 ID は **404 MUST**。いずれも S1-CONC-013 に従う。
**根拠**: routes/conclusions_v2.py:153-160, 176-181
**検証**: test_conclusions_api.py::test_single_type_endpoint_rejects_unknown_type /
::test_single_id_endpoint_returns_404_when_unknown / ::test_single_type_endpoint_returns_only_that_type /
::test_single_id_endpoint_returns_envelope_when_found
**分類**: CORE

### S1-CONC-018: 監査トレースは導出鎖を全部開示する
**挙動**: 結論 1 件の監査トレースは `formula_ref` / `threshold_ref` / `source_urls` /
`calibration_status` / `metadata` を**そのまま開示する MUST**。
LLM プロンプト sha256 が紐づく場合は**プロンプト全文を解決して返す MUST**。
プロンプト行が retention で消えている場合は**「欠落」を明示する MUST**（沈黙の null にしない）。
sha256 が無い場合は明示的な null。
**根拠**: routes/conclusions_v2.py:185-224
**検証**: test_conclusions_api.py::test_audit_trace_returns_full_disclosure_without_llm /
::test_audit_trace_resolves_llm_prompt_when_sha_set / ::test_audit_trace_marks_llm_prompt_missing_when_row_purged /
::test_audit_trace_returns_404_when_unknown
**分類**: CORE（NP6 の到達点）

### 2.3 THREAT_LEVEL 結論

### S1-CONC-019: TL の state は整数の文字列、比較は必ず severity 経由
**挙動**: `state` は TL 整数の文字列表現（`"1"`〜`"5"`）**MUST**。
**TL は 1=CRITICAL / 2=SEVERE / 3=HIGH / 4=ELEVATED / 5=NORMAL（DEFCON 式）**であり、
**深刻度の大小比較は `severity = 6 − TL` に変換してから行う MUST**。生の TL 整数を `<` / `>` で
比較してはならない。
**根拠**: threat_level.py:168、severity.py:22-43
**検証**: test_threat_level_derive.py::test_state_is_string_of_tl_int；
test_severity.py::test_tl_constants_are_defcon_style / ::test_severity_of_is_monotonically_decreasing_in_tl /
::test_derive_tl_agrees_with_severity_direction / ::test_more_alarmed_tool_never_scores_worse_than_calmer_tool
**分類**: CORE（較正災害 2 件の再発防止番兵）

### S1-CONC-020: TL が出せないときも行を出す
**挙動**: スコアリングが TL を決められなかった場合、行を**黙って捨ててはならない MUST**。
`insufficient_data` の結論を発行し、`metadata.reason_detail` に導出関数が None を返した旨を記す **MUST**。
これにより慢性結論不可検知 (§2.9) の観測列が途切れない。
**根拠**: threat_level.py:113-136
**検証**: test_threat_level_derive.py::test_tl_none_yields_insufficient_data /
::test_rationale_matrix_present_on_insufficient_data_branch
**分類**: CORE（NP1 + NP5+8）

### S1-CONC-021: TL の confidence はスコアの線形写像をクランプしたもの
**挙動**: `confidence = clamp(score / 12.0, 0.0, 1.0)` を小数 3 桁に丸める **MUST**。
負のスコアは 0.0、12.0 以上は 1.0。
**閾値**: 分母 12.0（ハードコード、≈ domain_cap × 2 を上限と見なす暫定値）
**根拠**: threat_level.py:58, 138
**検証**: test_threat_level_derive.py::test_confidence_clamped_to_unit_interval
**分類**: CORE。**分母 12.0 が暫定 calibration である点は ACCIDENTAL**（§5-A3）

### S1-CONC-022: lite (background) の TL は confidence を割り引き、注記を添える
**挙動**: scoring_mode が lite の結論は confidence に **0.6 を乗じる MUST**（TL 値自体は変えない）。
lite の結論には `metadata.lite_tl_note` を**付与する MUST**、full には**付与しない MUST**。
**閾値**: lite 係数 0.6（ハードコード）
**根拠**: threat_level.py:62, 144-146, 184-190
**検証**: tests/test_scenario_scoring.py::TestLiteTlConfidenceDiscount::test_lite_confidence_below_full /
::test_lite_metadata_carries_note（S1-SCORE-017 と共有）
**分類**: CORE（NP4 で結論は出す、NP5+8 で品質差を可視化する）

### S1-CONC-023: TL 結論は使用した閾値表を自ら公開する
**挙動**: TL 結論は導出に使った閾値を `threshold_ref` として**公開する MUST**。
公開されるキーは `tl1_total` / `tl1_physical` / `tl2_total` / `tl2_active_domains_min` /
`tl3_total` / `tl4_total` の 6 個。値は S1-SCORE-004 の閾値と**一致していなければならない MUST**。
**閾値**: 9.0 / 3.0 / 6.0 / 2 / 4.0 / 2.0
**根拠**: threat_level.py:46-53
**検証**: test_threat_level_derive.py::test_threshold_ref_matches_derive_tl（導出関数の境界も同時に検証）/
::test_formula_ref_matches_derive_tl_version
**分類**: CORE。**S1-SCORE-004 が TL1 に課している「3 ドメイン」条件は実装・閾値表のいずれにも
存在しない**（§5-A4、姉妹仕様側の訂正が要る）

### S1-CONC-024: 一次ソース URL は重複排除して昇順に並べる
**挙動**: `source_urls` は寄与信号の evidence_url を**集合化し昇順ソート MUST**。空 URL は除外。
**根拠**: threat_level.py:83-87
**検証**: test_threat_level_derive.py::test_source_urls_are_deduplicated_and_sorted
**分類**: CORE（NP6）

### S1-CONC-025: 導出根拠マトリクスを全寄与について添える
**挙動**: TL 結論の metadata に、寄与信号 1 件ごとの行からなる **rationale_matrix を添える MUST**。
各行は sensor / domain / signal_source / value_display / raw_score / contributing_country /
participant_role / final_contribution / **formula_trace** / evidence_url / suppress_reason を持つ。
並び順は `|final_contribution|` の**降順 MUST**。数値は小数 3 桁に丸める。
寄与が無ければ**空配列 MUST**（キー自体は存在する）。**結論不可の行にも添える MUST**。
**根拠**: threat_level.py:92-111
**検証**: test_threat_level_derive.py::test_metadata_includes_rationale_matrix_when_contributions_exist /
::test_rationale_matrix_is_empty_list_when_no_contributions / ::test_rationale_matrix_sorted_by_absolute_contribution /
::test_rationale_matrix_carries_suppress_reason / ::test_rationale_matrix_present_on_insufficient_data_branch /
::test_metadata_captures_replay_fields
**分類**: CORE（NP6 の最小単位。S1-SCORE-009 の formula_trace をそのまま搬送する）

### S1-CONC-026: 反証レポート — 「何が変われば結論が変わるか」を決定論的に添える
**挙動**: TL 結論の metadata に `falsification` を添える **MUST**。内容は 2 部:

1. **threshold_distance.to_higher_tl**: 1 段深刻な TL（TL 番号 −1）に到達するために不足している
   条件を、`{field, current, target, gap}` の配列で列挙 **MUST**。**TL1 では target を null MUST**。
   全条件充足なら `all_satisfied=true`
2. **threshold_distance.to_lower_tl**: 現在の段が依存している閾値を `{field, current, trigger_below, gap}`
   で列挙 **MUST**。**TL5 では target を null MUST**
3. **signal_sensitivity**: 寄与上位 N 件（既定 3）について、その信号がゼロに落ちた場合の仮想 TL と
   移動段数を算出 **MUST**。GLOBAL 寄与・抑制済み寄与・非正寄与は**除外 MUST**

計算は rationale_matrix に対する純粋な算術 **MUST**（LLM 不使用、再採点なし、冪等）。
TL が結論不可なら**空辞書 MUST**。
**閾値**: 上位 N = 3、domain_cap = 6.0（引数既定）
**根拠**: sensitivity.py:59-313
**検証**: test_falsification.py::test_tl_rungs_match_threshold_ref / ::test_derive_tl_mirror_matches_production /
::test_to_higher_tl_at_tl3_reports_score_gap_to_tl2 / ::test_to_higher_tl_at_tl1_returns_none_target /
::test_to_higher_tl_all_conditions_met / ::test_to_lower_tl_reports_trigger_below_score /
::test_to_lower_tl_at_tl5_returns_none / ::test_signal_sensitivity_top_n_sorted_descending /
::test_signal_sensitivity_excludes_suppressed_and_global / ::test_signal_sensitivity_predicts_tl_drop_when_signal_zeroes /
::test_insufficient_data_returns_empty_dict / ::test_no_rationale_matrix_returns_empty_signal_sensitivity
**分類**: CORE（NP1 反証性 / AP2 の入力）。**TL 導出式が 2 箇所に複製されている点は DEFECT-PRESERVE**（§6 DP1）

### 2.4 TREND 結論

### S1-CONC-027: TREND は 3 窓を 1 行に詰める
**挙動**: TREND は `short_term`(24h) / `medium_term`(7d) / `long_term`(30d) の 3 窓を評価し、
**1 個の結論行**に packed state `short_term=X;medium_term=Y;long_term=Z` として格納 **MUST**。
順序は上記固定 **MUST**。同じ内容を `metadata.windows` にも辞書で持つ。
**閾値**: 86400s / 604800s / 2592000s
**根拠**: trend.py:50-54, 208-217
**検証**: test_trend_derive.py::test_state_string_packs_all_three_windows_in_canonical_order /
::test_state_string_uses_module_window_order / ::test_returns_single_conclusion_of_trend_type /
::test_threshold_ref_mirrors_module_constants / ::test_formula_ref_is_versioned
**分類**: CORE

### S1-CONC-028: 窓の評価は「現在期間の平均 severity − 直前期間の平均 severity」
**挙動**: 窓幅 W に対し、`[now−W, now)` を現在期間、`[now−2W, now−W)` を直前期間とし、
各期間内の THREAT_LEVEL 台帳行の **severity 平均の差 `delta = cur_mean − prev_mean`** で分類 **MUST**。
severity は TL1→4 / TL2→3 / TL3→2 / TL4→1 / TL5→0 の写像 **MUST**（大きいほど深刻）。
他シナリオの行、state が null の行、1..5 以外の state 文字列は**除外 MUST**。
**根拠**: trend.py:48, 149-193
**検証**: test_trend_derive.py::test_window_seam_classifies_rows_into_correct_slice /
::test_rows_for_other_scenarios_are_ignored / ::test_unknown_tl_state_is_ignored
**分類**: CORE

### S1-CONC-029: 5 状態語彙と分類順序
**挙動**: delta に対し以下の順に評価し最初に成立した状態を採る **MUST**:
`delta >= 1.50` → **ESCALATING** / `delta >= 0.50` → **RISING** /
`delta <= −1.50` → **DEEPER_DECAY** / `delta <= −0.50` → **COOLING** / それ以外 → **STABLE**。
境界値は**いずれも当該状態に含める（`>=` / `<=`）MUST**。
**閾値**: `RISING_DELTA` = **0.50**、`ESCALATE_DELTA` = **1.50**（いずれもハードコード定数）
**根拠**: trend.py:69-70, 196-205
**検証**: test_trend_derive.py::test_stable_when_delta_within_rising_band /
::test_rising_when_delta_above_rising_below_escalate / ::test_escalating_when_delta_at_or_above_escalate_delta /
::test_cooling_when_negative_delta_at_or_above_rising / ::test_deeper_decay_when_negative_delta_at_or_above_escalate /
::test_rising_delta_boundary_inclusive
**分類**: CORE。**設計文書 §6.2 の目標語彙 (RAPIDLY_ESCALATING 等) との乖離は ACCIDENTAL**（§5-A5）

### S1-CONC-030: 標本数は現在・直前の両期間で 3 件以上を要求する
**挙動**: 現在期間・直前期間の**いずれか**が 3 件未満なら当該窓は判定不能 **MUST**。
判定不能の窓は packed state で `INSUFFICIENT_DATA` と表記 **MUST**。
標本数は `metadata.sample_counts[window] = {current_n, previous_n}` として**常に開示 MUST**。
**閾値**: `MIN_SAMPLES` = **3**（ハードコード）
**根拠**: trend.py:71, 175-180
**検証**: test_trend_derive.py::test_below_min_samples_in_one_window_marks_that_window_unavailable /
::test_insufficient_data_reports_zero_sample_counts
**分類**: CORE

### S1-CONC-031: 1 窓でも判定できれば結論は available
**挙動**: 3 窓のうち **1 つでも判定できたら結論は available MUST**（部分的に判定不能でも結論を出す）。
**3 窓すべてが判定不能のときのみ `insufficient_data` MUST**。
**根拠**: trend.py:99-127
**検証**: test_trend_derive.py::test_empty_db_yields_insufficient_data /
::test_below_min_samples_in_one_window_marks_that_window_unavailable
**分類**: CORE（NP4 結論最大化）

### S1-CONC-032: TREND の confidence は標本密度で決まり 0.95 で頭打ち
**挙動**: 各窓について `n = min(current_n, previous_n)` が MIN_SAMPLES 以上なら
`min(0.30, 0.15 + n × 0.01)` を加算 **MUST**。合計を **0.95 で上限クリップ MUST**。
1 窓でも判定不能があれば **0.15 減点 MUST**（下限 0.0）。小数 3 桁に丸める。
結論不可時は **0.0 MUST**。
**根拠**: trend.py:220-234
**検証**: test_trend_derive.py::test_partial_availability_penalises_confidence /
::test_confidence_caps_at_zero_to_one / ::test_confidence_zero_when_unavailable
**分類**: CORE

### S1-CONC-033: TREND は一次ソース URL を持たない
**挙動**: TREND は台帳の TL 行から算出されるため `source_urls` は**常に空 MUST**
（生センサー URL を偽って添えない）。
**根拠**: trend.py:140
**検証**: test_trend_derive.py::test_source_urls_empty_trend_synthesizes_no_evidence /
::test_round_trip_via_save_then_re_derive
**分類**: CORE（NP6: 出典を捏造しない）

### 2.5 PER_DOMAIN 結論

### S1-CONC-034: PER_DOMAIN は 3 ドメインを 1 行に詰める
**挙動**: cyber / physical / info の 3 ドメイン状態を packed state `cyber=X;physical=Y;info=Z` として
**1 行に格納 MUST**。順序は上記固定 **MUST**。`metadata.domain_scores`（小数 3 桁）と
`metadata.domain_states`、`metadata.domain_source_counts` を添える **MUST**。
**根拠**: per_domain.py:41, 128-132, 148-149
**検証**: test_per_domain_derive.py::test_state_string_packs_all_three_domains_in_canonical_order /
::test_state_string_uses_module_domain_order / ::test_returns_single_conclusion_of_per_domain_type /
::test_metadata_records_per_domain_scores / ::test_metadata_records_source_counts_per_domain /
::test_formula_ref_is_versioned / ::test_threshold_ref_mirrors_module_constants
**分類**: CORE

### S1-CONC-035: ドメイン状態の分類は 5 値・順序依存
**挙動**: 各ドメインの現スコア `cur` と直近 PER_DOMAIN 行の同ドメインスコア `prior` から、
**以下の順に**評価し最初に成立した状態を採る **MUST**:

1. `cur <= 0` → **INSUFFICIENT_SIGNAL**（負値も同じ扱い MUST）
2. `cur >= 2.5` → **ACTIVE**
3. `prior` が存在し `prior − cur >= 1.0` → **DEGRADING**
4. `cur >= 1.5` → **ELEVATED**
5. それ以外 → **STABLE**

境界値は**当該状態に含める（`>=`）MUST**。直近行が無ければ DEGRADING は起こらない **MUST**。
**閾値**: `ACTIVE_FLOOR` = **2.5**、`ELEVATED_FLOOR` = **1.5**、`DEGRADE_DELTA` = **1.0**
（いずれもハードコード。2026-04-26 Phase 1.3 の実分布較正値）
**根拠**: per_domain.py:51-53, 136-145
**検証**: test_per_domain_derive.py::test_active_state_at_or_above_active_floor / ::test_elevated_state_between_floors /
::test_stable_state_below_elevated_with_signal / ::test_insufficient_signal_when_score_zero /
::test_negative_score_treated_as_insufficient_signal / ::test_active_floor_boundary_inclusive /
::test_elevated_floor_boundary_inclusive / ::test_degrading_when_drop_at_or_above_degrade_delta /
::test_no_degrading_when_drop_below_threshold / ::test_active_overrides_degrading /
::test_no_prior_row_yields_no_degrading / ::test_round_trip_via_save_then_latest_for_degrading
**分類**: CORE。**DEGRADING が ELEVATED より優先される順序は ACCIDENTAL**（§5-A6）

### S1-CONC-036: 1 ドメインでも信号があれば結論は available
**挙動**: 3 ドメインすべてが INSUFFICIENT_SIGNAL のときのみ `insufficient_data` **MUST**。
1 ドメインでも信号があれば結論を出す **MUST**（NP1: 単一ドメイン ACTIVE も使える結論）。
**根拠**: per_domain.py:83-84, 94-113
**検証**: test_per_domain_derive.py::test_all_domains_silent_yields_insufficient_data /
::test_confidence_zero_when_all_domains_silent
**分類**: CORE

### S1-CONC-037: PER_DOMAIN の confidence は「広がり」と「大きさ」の等分合成
**挙動**: `confidence = 0.5 × (信号のあるドメイン数 / 3) + 0.5 × min(1.0, ドメインスコア合計 / 12.0)`
を小数 3 桁に丸める **MUST**。
**閾値**: magnitude 分母 12.0（ハードコード）
**根拠**: per_domain.py:165-173
**検証**: test_per_domain_derive.py::test_confidence_combines_breadth_and_magnitude /
::test_confidence_caps_magnitude_at_one / ::test_confidence_max_when_all_three_active
**分類**: CORE

### S1-CONC-038: PER_DOMAIN の一次ソースは既知 3 ドメインの寄与のみ
**挙動**: `source_urls` は cyber / physical / info いずれかに属する寄与の evidence_url のみを
集合化し昇順ソート **MUST**。未知ドメインの寄与 URL は**含めない MUST**。
**根拠**: per_domain.py:71-76, 90-92
**検証**: test_per_domain_derive.py::test_source_urls_deduplicated_and_sorted_across_domains /
::test_source_urls_only_count_known_domains
**分類**: CORE

### 2.6 ANOMALY 結論

### S1-CONC-039: ANOMALY は 1 ティックに複数行、重要度上位 N 件
**挙動**: ANOMALY は他 4 型と異なり**1 ティックで複数行を生成する MUST**。
重要度降順にソートし**上位 `limit` 件（既定 10）だけを返す MUST**。
**閾値**: `DEFAULT_LIMIT` = **10**（`?limit=` で調整可）
**根拠**: anomaly.py:64, 245-246
**検証**: test_anomaly_derive.py::test_returns_list_of_anomaly_conclusions / ::test_top_n_limit_truncates /
::test_default_limit_is_documented_constant / ::test_results_sorted_by_importance_descending
**分類**: CORE

### S1-CONC-040: 重要度は 4 因子の積 × 100、上限 100
**挙動**: `importance = raw_score × recency_decay × scenario_relevance × novelty_factor × 100`、
**[0, 100] にクランプ MUST**。`confidence = importance / 100` を小数 3 桁に丸める **MUST**。
`raw_score <= 0` の寄与は**除外 MUST**。
4 因子と elapsed_hours は**すべて metadata に個別開示 MUST**（NP6）。
**閾値**: 上限 100.0
**根拠**: anomaly.py:204-206, 221-238
**検証**: test_anomaly_derive.py::test_metadata_captures_every_formula_component /
::test_importance_clamped_to_unit_confidence / ::test_zero_raw_score_contributions_filtered /
::test_older_signal_has_lower_importance / ::test_threshold_ref_constants_match_implementation /
::test_formula_ref_is_stable_constant
**分類**: CORE

### S1-CONC-041: 経年減衰は時定数 12h の指数減衰
**挙動**: `recency_decay = exp(−elapsed_hours / 12.0)` **MUST**。
elapsed は負にならないよう 0 で下限クリップ **MUST**（未来時刻の信号は減衰なし）。
elapsed=0 → 1.0、elapsed=12h → 1/e ≈ 0.368、実半減期は 12·ln2 ≈ 8.32h。
**閾値**: 時定数 **12.0 時間**（ハードコード）
**根拠**: anomaly.py:66, 73-75
**検証**: test_anomaly_derive.py::test_recency_decay_at_one_time_constant / ::test_recency_decay_at_actual_half_life /
::test_recency_decay_at_zero_elapsed_is_one
**分類**: CORE。**設計文書が 12h を "half-life" と誤記していた点は ACCIDENTAL**（§5-A7）

### S1-CONC-042: 新規性は同一 signal_source の直近 24h 出現数で減衰する
**挙動**: `novelty = clamp(1.0 − similar_count / 10, 0.3, 1.0)` **MUST**。
`similar_count` は**同一シナリオかつ同一 signal_source** の ANOMALY 台帳行を
直近 24h で数えた値 **MUST**。シナリオ間・signal_source 間で**混線してはならない MUST**。
台帳読み出しに失敗した場合は **count=0（novelty=1.0）にフォールバック MUST**（NP1: 履歴欠落で
重要度を下げない）。フォールバック経路は `metadata.novelty_source` に
`"ledger_24h_fallback_empty"` として**明示 MUST**（正常時は `"ledger_24h"`）。
**閾値**: 窓母数 **10**、下限 **0.3**、lookback **86400s**
**根拠**: anomaly.py:67-69, 78-80, 138-163
**検証**: test_anomaly_derive.py::test_novelty_factor_drops_for_repeated_signal_source /
::test_novelty_factor_one_for_singleton_source / ::test_novelty_drops_across_ticks_after_save /
::test_novelty_lookback_window_excludes_older_rows / ::test_novelty_isolated_per_scenario /
::test_novelty_isolated_per_signal_source / ::test_novelty_falls_back_when_ledger_query_fails
**分類**: CORE。**change gate 導入後に台帳行数が減り novelty が上振れする相互作用は ACCIDENTAL**（§5-A8）

### S1-CONC-043: シナリオ関連度は寄与の二重重みの積、GLOBAL は例外
**挙動**: `scenario_relevance = llm_country_weight × participant_weight` **MUST**。
ただし寄与国が `GLOBAL` の場合は **participant_weight のみ MUST**
（global_signal_weight が既に participant_weight に吸収済のため二重計上しない）。
**根拠**: anomaly.py:83-93
**検証**: test_anomaly_derive.py::test_global_contribution_relevance_uses_participant_weight_only /
::test_per_country_relevance_multiplies_llm_cw_and_participant_weight
**分類**: CORE

### S1-CONC-044: ANOMALY の state は統制語彙 (signal_source) に限る
**挙動**: `state` は **signal_source のみ MUST**。自由記述の要約文字列を state に入れてはならない
（行ごとに一意な state になり「同種異常の集計」が不可能になるため）。
自由記述の値表現は `metadata.value_display` に置く **MUST**。
**根拠**: anomaly.py:96-112, 232-236
**検証**: test_anomaly_derive.py::test_state_summary_uses_signal_source_with_value_in_metadata /
::test_state_summary_falls_back_to_signal_source_when_no_value
**分類**: CORE（NP6: 結論履歴の集計可能性）。**設計文書 §6.4 は旧仕様のまま**（§5-A9）

### S1-CONC-045: 採点可能な寄与が皆無なら単一の結論不可行を出す
**挙動**: 寄与が 0 件、または全寄与の raw_score が非正の場合、**単一の `insufficient_data` 行を返す MUST**
（空リストを返してはならない — 慢性結論不可検知の観測列が切れる）。
**根拠**: anomaly.py:186-187, 242-243
**検証**: test_anomaly_derive.py::test_no_contributions_yields_single_insufficient_data /
::test_zero_raw_score_contributions_filtered
**分類**: CORE（NP5+8）

### S1-CONC-046: ANOMALY の一次ソースは当該信号の evidence_url 1 件のみ
**挙動**: 各 ANOMALY 行の `source_urls` は**その信号自身の evidence_url のみ MUST**。
無ければ空。各行に calibration_status を**添える MUST**。
**根拠**: anomaly.py:218-220
**検証**: test_anomaly_derive.py::test_source_urls_emitted_when_evidence_present /
::test_source_urls_empty_when_no_evidence / ::test_calibration_status_attached_to_each_row
**分類**: CORE

### 2.7 ATTACK_MODE 結論

### S1-CONC-047: 攻撃モードは複数同時発火し、最上位を state に、全件を metadata に置く
**挙動**: 規則は排他ではない **MUST**。発火した全モードを confidence **降順**にソートし、
先頭を `state`、全件を `metadata.ranked_modes`（`{mode, confidence, rule}` の配列）に格納 **MUST**。
各エントリは**発火した規則を平文で説明する `rule` 文字列を持つ MUST**（NP6）。
`metadata.domain_scores`（小数 3 桁）と `metadata.active_countries_n` を添える **MUST**。
**根拠**: attack_mode.py:72-78, 116-137
**検証**: test_attack_mode_derive.py::test_multi_mode_records_top_in_state_and_full_ranked_list /
::test_each_ranked_entry_carries_rule_string / ::test_metadata_carries_active_country_count /
::test_metadata_domain_scores_rounded / ::test_returns_single_conclusion_of_type_attack_mode /
::test_formula_ref_is_stable_constant / ::test_threshold_ref_exposes_every_floor
**分類**: CORE

### S1-CONC-048: 4 つの基本モードの発火規則
**挙動**: 現ティックのドメインスコア (cyber / physical / info) と active_countries 数 n に対し、
以下を**独立に**評価する **MUST**（境界値は発火側 = `>=`）:

| モード | 発火条件 | confidence |
|---|---|---|
| `DDOS_PRECURSOR` | `cyber >= 1.2` **かつ** `info >= 0.8` | `min(0.95, 0.55 + 0.4 × min(1, (cyber−1.2)/1.2))` |
| `KINETIC_PREPARATION` | `physical >= 1.0` | `min(0.95, 0.55 + 0.4 × min(1, (physical−1.0)/1.0))` |
| `HYBRID_PRESSURE` | `cyber >= 0.8` **かつ** `physical >= 0.8` **かつ** `info >= 0.8` **かつ** `n >= 4` | `min(0.95, 0.50 + 0.05n + 0.02×(cyber+physical+info))` |
| `INFO_OPS_DOMINANT` | `info >= 0.8` **かつ** `max(cyber, physical) > 0` **かつ** `info / max(cyber,physical) >= 1.5` | `min(0.95, 0.55 + 0.10 × info/max(other, 0.1))` |
| `INFO_OPS_DOMINANT`（純 info 分岐） | `info >= 0.8` **かつ** `cyber == 0` **かつ** `physical == 0` | **固定 0.65** |

confidence は小数 3 桁に丸める **MUST**。
**閾値**: `CYBER_DDOS_FLOOR`=**1.2** / `INFO_NARRATIVE_FLOOR`=**0.8** / `PHYSICAL_KINETIC_FLOOR`=**1.0** /
`ALL_DOMAIN_HYBRID_FLOOR`=**0.8** / `HYBRID_INTEL_CLUSTER_MIN`=**4** / `INFO_DOMINANCE_RATIO`=**1.5**
（すべてハードコード。2026-05-10 の実分布再較正値）
**根拠**: attack_mode.py:50-56, 140-184
**検証**: test_attack_mode_derive.py::test_ddos_precursor_fires_at_floors / ::test_ddos_precursor_blocks_below_cyber_floor /
::test_ddos_precursor_blocks_below_info_floor / ::test_kinetic_preparation_fires_at_floor /
::test_kinetic_preparation_blocks_below_floor / ::test_hybrid_pressure_requires_all_three_domains_and_cluster /
::test_hybrid_pressure_blocks_when_cluster_too_small / ::test_hybrid_pressure_blocks_when_one_domain_silent /
::test_info_dominance_fires_with_ratio / ::test_info_only_signal_mix_classifies_info_ops /
::test_info_below_floor_does_not_dominate / ::test_confidence_clamped_below_unit
（**いずれも定数相対。数値そのものは未 pin** — §7 GAP-01）
**分類**: CORE。**設計文書 §6.5 が再較正前の値のままである点は ACCIDENTAL**（§5-A10）

### S1-CONC-049: どの規則も発火しなければ結論不可 — 「攻撃なし」ではない
**挙動**: マッチ 0 件は `insufficient_data` **MUST**。`metadata.reason_detail` に
「規則が現信号構成に一致しなかった」旨を記す **MUST**。
`metadata.domain_scores` と `metadata.active_countries_n` は**結論不可行にも添える MUST**。
**根拠**: attack_mode.py:93-114
**検証**: test_attack_mode_derive.py::test_no_signals_yields_insufficient_data /
::test_below_all_floors_yields_insufficient_data / ::test_insufficient_metadata_carries_domain_scores
**分類**: CORE（NP5+8 の中核: 否定を証明しない）

### S1-CONC-050: 低確信のモードは暫定として旗を立てる
**挙動**: 最上位モードの confidence が **0.6 未満なら `metadata.is_tentative = true` MUST**。
**閾値**: 0.6（ハードコード）
**根拠**: attack_mode.py:135
**検証**: test_attack_mode_derive.py::test_tentative_flag_set_when_confidence_low
**分類**: CORE

### S1-CONC-051: シナリオ固有拡張モードは宣言的設定のみで定義される
**挙動**: シナリオ固有の攻撃モードは**設定データ（シナリオプリセット）で宣言 MUST**であり、
コード内のシナリオ別分岐で実装してはならない **MUST**。拡張 1 件は
`mode` / `domain_floors`（全ドメインが下限以上）/ `active_n_min` / `requires_participant`
（指定 ISO2 が active_countries に全て含まれること、大文字小文字非依存）/
`base_confidence` / `rule_summary` を持つ。**全条件 AND で発火 MUST**。
拡張は基本モードを**置換せず追加 MUST**（合算後に confidence 降順で再ソート）。
**根拠**: attack_mode_extensions.py:106-227、attack_mode.py:71-77
**検証**: test_attack_mode_extensions.py::test_extension_fires_when_all_floors_and_countries_match /
::test_extension_does_not_fire_when_required_country_absent / ::test_extension_does_not_fire_when_one_floor_unmet /
::test_extension_does_not_fire_when_active_n_below_min / ::test_extension_appears_in_ranked_modes_metadata /
::test_extension_can_become_top_mode_when_confidence_dominates / ::test_no_extensions_means_pure_base_behavior /
::test_live_config_declares_expected_rule_count / ::test_live_config_every_scenario_with_extensions_has_unique_modes /
::test_live_rule_fires_at_threshold / ::test_live_rule_silent_below_floor /
::test_live_rule_silent_when_required_participant_missing / ::test_live_rule_does_not_leak_across_scenarios /
::test_extension_match_dataclass_is_immutable
**分類**: CORE（ADR-V2-002）

### S1-CONC-052: 拡張の confidence は保守帯にクランプし、不正宣言は黙って捨てる
**挙動**: 拡張の confidence は `clamp(base_confidence, 0.55, 0.85) + 0.30 × min(1, max(margin))` を
**0.95 で上限クリップ MUST**（margin = 各 domain_floor に対する相対超過。floor が 0 なら除外）。
以下は**黙って捨てる MUST**（設定不備でツールを止めない — NP3）:
mode が非文字列 / 空 / 基本 5 モード名と衝突（警告ログのみ）、辞書でないエントリ、
同一 mode の重複宣言（**最初の宣言が勝つ MUST**）、拡張ブロックが配列でない、設定が読めない。
**閾値**: 下限 0.55 / base 上限 0.85 / 全体上限 0.95 / 既定 base 0.60 / margin 係数 0.30
**根拠**: attack_mode_extensions.py:62-64, 125-188, 191-227
**検証**: test_attack_mode_extensions.py::test_confidence_floor_and_ceiling_applied /
::test_strong_margin_increases_confidence_but_caps_at_0_95 / ::test_zero_margin_returns_base_confidence /
::test_extension_without_mode_is_silently_dropped / ::test_extension_using_reserved_base_mode_is_dropped /
::test_duplicate_mode_only_first_wins / ::test_non_dict_extension_entries_ignored /
::test_returns_empty_when_scenario_has_no_extensions / ::test_returns_empty_when_scenario_id_unknown /
::test_returns_empty_when_geo_data_missing / ::test_returns_empty_when_extensions_block_is_not_a_list
**分類**: CORE

### S1-CONC-053: 拡張は結論不可を救済しない
**挙動**: 基本規則が 1 件も発火せず、拡張も発火しない場合、結論は `insufficient_data` のまま **MUST**。
拡張だけで「結論不可を無理に結論化する」ことはしない。
**根拠**: attack_mode.py:93-114（マッチ合算後に空判定）
**検証**: test_attack_mode_extensions.py::test_extension_does_not_rescue_insufficient_signal_when_base_is_empty
**分類**: CORE

### S1-CONC-054: LLM 補強は規則結論を上書きしない
**挙動**: LLM 補強が有効な場合でも、以下 **MUST**:
1. **`state`（最上位モード）は規則の値を保持 MUST**。LLM の異議は
   `metadata.llm_augmentation.suggested_alternative_mode` に記録するのみ
2. confidence の調整は **±0.10 を上限**とし、結果は [0.0, 1.0] にクランプ **MUST**
3. 規則が結論不可なら **LLM を呼ばずそのまま返す MUST**（LLM にモードを発明させない — NP1）
4. LLM 不達 / パース失敗時は**規則結論をそのまま返す MUST**。ただし
   `metadata.llm_augmentation = {attempted: true, ok: false, error: ...}` を付す **MUST**（NP3）
5. 成功時は `llm_prompt_sha256` を結論に**刻印 MUST**（NP6）。プロンプトは決定論的に組み立て、
   同一状態が同一 sha256 に落ちること
6. LLM 出力の値域強制: `agreement` は 5 値以外なら `"unknown"`、
   `suggested_alternative_mode` は既知 5 モード以外なら null、`narrative` は 240 文字で切り詰め、
   `key_evidence` は **4 件・各 120 文字**で切り詰め **MUST**

**閾値**: `V2_ATTACK_MODE_LLM_AUGMENT_ENABLED` 既定 **False**、nudge 上限 **0.10**、
narrative 240 字、evidence 4 件 × 120 字、temperature 0.1、max_tokens 384
**根拠**: attack_mode_llm.py:44-57, 103-206、config.py:276-278
**検証**: test_attack_mode_llm_augment.py::test_disabled_flag_returns_original_unchanged /
::test_llm_unavailable_returns_original_unchanged / ::test_insufficient_data_rule_passes_through /
::test_augmented_row_carries_state_and_narrative / ::test_confidence_nudge_clamped_at_positive_max /
::test_confidence_nudge_clamped_at_negative_max / ::test_state_never_overwritten_by_llm_disagreement /
::test_prompt_sha256_stamped_on_augmented_row / ::test_unknown_alternative_mode_collapses_to_none /
::test_unknown_agreement_collapses_to_unknown / ::test_evidence_capped_to_four_items_and_120_chars /
::test_narrative_truncated_at_240_chars / ::test_llm_call_failure_records_attempt_and_preserves_confidence /
::test_rule_conclusion_is_not_mutated
**分類**: CORE（NP1 + NP3 + NP6 の三点同時充足）

### 2.8 calibration_status（結論への較正状態付記）

### S1-CONC-055: 全結論に較正スナップショットを添える
**挙動**: 結論には、それを生んだ系の較正状態を `calibration_status` として添える **MUST**。
内容は `source` / `status` / `recall` / `precision` / `tp` / `fp` / `tn` / `fn` /
`sample_n` / `window_days` / `last_label_at`。**headline は recall（NP1: 感度）MUST**。
出典は **ground-truth 混同行列（analyst_feedback ⋈ conclusions）MUST** であり、
lite/full スコア差分のような**自己参照的な指標を使ってはならない**（そうした指標はスコア経路統合後に
恒等的に 0 となり、360k 件の結論すべてで「異常なし」を報告した実績がある）。
**根拠**: calibration.py:27-51, 135-191
**検証**: test_threat_level_derive.py::test_calibration_status_is_attached；
test_anomaly_derive.py::test_calibration_status_attached_to_each_row
**分類**: CORE（NP5+8）

### S1-CONC-056: 較正状態は 3 値、判定は recall の分母で決まる
**挙動**: `recall = tp/(tp+fn)`、`precision = tp/(tp+fp)`（分母 0 なら null）**MUST**。
状態は以下 **MUST**:
- 観測陽性数 `tp+fn < 5`、または recall が null → **INSUFFICIENT_DATA**
- `recall < 0.70` → **DEGRADED**
- それ以外 → **OK**

**precision は報告するが状態判定に用いない MUST**。TRUE_NEGATIVE だけが蓄積しても
INSUFFICIENT_DATA のまま **MUST**（recall は陽性がなければ定義できない）。
**閾値**: 最小陽性標本 **5**、recall 下限 **0.70**、窓 `CALIBRATION_WINDOW_DAYS` 既定 **30 日**
**根拠**: calibration.py:69-74, 194-207
**検証**: test_conclusion_calibration.py::test_insufficient_data_when_no_labels /
::test_insufficient_data_when_too_few_positives / ::test_ok_when_recall_holds /
::test_degraded_when_recall_below_floor / ::test_precision_reported_but_does_not_drive_status /
::test_true_negatives_alone_stay_insufficient
**分類**: CORE

### S1-CONC-057: ラベルは (結論, アナリスト) ごとに最新 1 件だけ数える
**挙動**: 同一 (conclusion_id, analyst_id) に複数ラベルがある場合、**最新 1 件のみ集計 MUST**。
アナリストがラベルを改訂しても二重計上しない。
**根拠**: calibration.py:143-170
**検証**: 未検証（§7 GAP-08。集計側 tests/test_report_recall_metrics.py が同一規則を独立に検証）
**分類**: CORE

### S1-CONC-058: 較正の読み出しは決してスコアリングを壊さない
**挙動**: 較正スナップショットの取得は**読み取り専用 MUST**、失敗時は
**INSUFFICIENT_DATA の封筒を返し例外を伝播させない MUST**（NP3: 観測系が本流を止めない）。
結果はシナリオ単位で **300 秒メモ化 MUST**、新ラベル投入後は明示的に無効化できる **MUST**。
**閾値**: キャッシュ TTL **300s**
**根拠**: calibration.py:76, 98-132
**検証**: test_conclusion_calibration.py::test_never_raises_on_bad_db / ::test_cache_returns_same_until_invalidated
**分類**: CORE

### 2.9 台帳への書込と結論不可の継続性

### S1-CONC-059: 台帳は append-only
**挙動**: 結論台帳は追記のみ **MUST**。既存行の UPDATE / DELETE を行ってはならない **MUST**
（retention による一括削除を除く）。訂正は新しい ID の行を追記して行う。
**根拠**: persistence.py:1-11, 29-55
**検証**: tests/test_conclusions_persistence.py（round-trip 群）
**分類**: CORE（ADR-V2-008 / AP4 の前提）

### S1-CONC-060: 単一値型の書込は「変化 + heartbeat」でゲートする
**挙動**: 単一値型（threat_level / trend / per_domain / attack_mode）は、
**同一 (scenario, type) の最新行と比較して** `state` と `conclusion_unavailable_reason` が
ともに等しく、かつ経過時間が heartbeat 周期未満なら**書込を省略 MUST**。
比較対象は**型の最新行であって「同じ state の最新行」ではない MUST**
（A→B→A のフラップで 3 行書かれないと、任意時点の再構成が B のまま固まる）。
ゲート無効時は毎ティック書く **MUST**。
**閾値**: `V2_CONCLUSION_WRITE_ON_CHANGE` 既定 **True**、`V2_CONCLUSION_HEARTBEAT_SEC` 既定 **3600**
**根拠**: persistence.py:84-110、config.py:264-269
**検証**: test_conclusion_write_gating.py::TestSingleValuedGate::test_unchanged_state_is_deduplicated /
::test_state_change_writes_immediately / ::test_flap_writes_every_transition /
::test_heartbeat_forces_periodic_write / ::test_gate_off_writes_every_tick
**分類**: CORE

### S1-CONC-061: 複数行型は「集合シグネチャ」でゲートする
**挙動**: ANOMALY は 1 ティック分の**集合シグネチャ**で比較 **MUST**。
シグネチャの単位は (state, unavailable_reason, signal_source|sensor, contributing_country, domain)。
**同一シグネチャの重複件数（多重度）はシグネチャに含めない MUST**
（同一種別の件数はインテル項目の出入りで毎ティック揺れるため、含めるとゲートが機能しない）。
比較対象の「前バッチ」は**最新観測時刻から 5 秒以内の行の集合 MUST**
（1 ティック内の各行は個別に時刻を採るためマイクロ秒単位でずれる）。
集合が変化したら**バッチ全体を書き直す MUST**（部分書込は任意時点の集合再構成を壊す）。
空バッチは何もしない **MUST**。
**閾値**: バッチ窓 **5.0s**
**根拠**: persistence.py:113-204
**検証**: test_conclusion_write_gating.py::TestBatchGate::test_identical_anomaly_set_is_deduplicated /
::test_set_change_rewrites_full_batch / ::test_empty_batch_is_noop；
::TestBatchGateTimestampJitter::test_batch_rows_with_jittered_timestamps_still_dedup；
::TestBatchGateIdentitySet::test_multiplicity_flap_does_not_rewrite / ::test_new_identity_in_metadata_rewrites
**分類**: CORE

### S1-CONC-062: 継続性の記録はゲートに関わらず毎ティック行う
**挙動**: 書込が間引かれたティックでも、**結論不可の継続性記録は必ず行う MUST**。
慢性結論不可の検知には間引き前の観測列が要る。
**根拠**: persistence.py:78-81, 106-108, 198-201
**検証**: test_conclusion_write_gating.py::TestSingleValuedGate::test_deduplicated_tick_still_feeds_continuity
**分類**: CORE（NP5+8 と AP4 の両立点）

### S1-CONC-063: 継続性台帳は遷移だけを記録する
**挙動**: (scenario, type) ごとに以下 **MUST**:
- 結論不可 かつ 直近行が無い / 直近行が「解消済」→ **新しい run を開く**（run_length=0、first_seen=現時刻）
- 結論不可 かつ 直近行が「未解消」→ **run を延長**（run_length = 現時刻 − first_seen）
- 結論が available かつ 直近行が「未解消」→ **run を閉じる**（is_available=1、reason=`resolved`）
- 結論が available かつ 直近行が無い / 既に解消済 → **何も書かない MUST**（定常状態は記録しない）

判定は「`conclusion_unavailable_reason` が非 None、**または** state が文字列 `"INSUFFICIENT_DATA"`」。
書込失敗は**握り潰す MUST**（観測系が本流を止めない — NP3）。
**根拠**: persistence.py:207-293
**検証**: test_conclusions_persistence.py::TestContinuityLog::test_unavailable_conclusion_opens_run /
::test_consecutive_unavailable_extends_run_length / ::test_available_after_unavailable_closes_run /
::test_steady_state_available_writes_nothing
**分類**: CORE。**state 文字列による二重判定は ACCIDENTAL**（§5-A11）

### S1-CONC-064: 慢性結論不可は 2 基準の論理和で判定する — NP5+8 の設計失敗検知
**挙動**: (scenario, type) が慢性結論不可であることは、以下 **いずれか**で判定 **MUST**:

1. **連続日数基準**: 現在 open な run の経過日数 `(now − first_seen_at)/86400` が閾値以上
2. **デューティ比基準**: 直近 W 日の窓において、結論不可であった**時間の総和 / 窓幅**が閾値以上

デューティ比基準は、run が短時間で閉じる**フラッピング**を連続日数基準が取りこぼすために要る
（実測: attack_mode が 2 か月間ティックの 20-30% を結論不可で過ごしながら慢性件数 0 だった）。
デューティ比は**閉じた run（first_seen〜observed_at）と現在 open な run の合計時間**を積算し、
窓境界で**クランプ MUST**、1.0 で上限クリップ **MUST**。
**閾値**: 連続日数 `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS` 既定 **7.0**（**下限 3.0 を下回れない MUST**、
DB override 可）、デューティ窓 既定 **14.0 日**（下限 7.0）、デューティ閾値 既定 **0.20**（下限 0.05、上限 1.0）
**根拠**: inconclusive_continuity.py:56-68, 95-150, 165-264
**検証**: test_inconclusive_continuity.py::TestComputeStates::test_open_run_under_threshold_is_transient /
::test_open_run_at_threshold_is_chronic / ::test_intervening_close_resets_clock / ::test_closed_run_not_returned /
::test_empty_table_returns_no_states / ::test_multi_pair_isolation_and_ordering / ::test_threshold_floor_is_three_days；
::TestDutyCycleStates::test_flapping_unavailability_is_duty_chronic / ::test_low_duty_is_not_chronic /
::test_open_run_counts_toward_duty / ::test_run_straddling_window_start_is_clamped
**分類**: CORE（ADR-V2-010 + 2026-07-04 拡張）。**デューティ側パラメータが設定 registry に
登録されておらず運用者が調整できない点は DEFECT-PRESERVE**（§6 DP3）

### S1-CONC-065: 慢性スナップショットは 2 基準を重複なくマージする
**挙動**: 慢性スナップショットは `chronic` / `transient` / `duty` / `summary` を返す **MUST**。
デューティ基準で慢性となった対は、**連続日数基準で既に計上済なら重複追加しない MUST**。
各エントリは**どちらの基準で慢性と判定されたかを `criterion` で明示 MUST**
（`consecutive_days` / `duty_cycle`）。並び順は慢性優先・滞留の長い順 **MUST**。
DB エラー時は**空の慢性リストと error フィールドを返す MUST**（例外を投げない — NP3）。
**根拠**: inconclusive_continuity.py:300-376
**検証**: test_inconclusive_continuity.py::TestChronicSnapshot::test_envelope_shape / ::test_swallows_db_errors；
::TestChronicSnapshotDutyMerge::test_snapshot_includes_duty_chronic_entry / ::test_consecutive_chronic_not_duplicated_by_duty
**分類**: CORE

### S1-CONC-066: 個々の結論不可行は自分の滞留時間を自己申告する
**挙動**: ATTACK_MODE の結論不可行には、現在の open run の長さから
`metadata.null_run_minutes`（分、小数 1 桁）と `metadata.null_severity` を**付与 MUST**:
`>= 7 日` → `chronic` / `>= 24 時間` → `extended` / それ未満 → `transient`。
この付与は**失敗しても保存を妨げてはならない MUST**。
**閾値**: chronic 7 日 / extended 24 時間（ハードコード）
**根拠**: scoring.py:1341-1360、inconclusive_continuity.py:267-297
**検証**: 未検証（§7 GAP-05）
**分類**: CORE（AP3: 日次スナップショットを待たずに滞留が見える）

### S1-CONC-067: 台帳は保持期間で刈られる
**挙動**: 結論台帳は既定 **90 日**で刈る **MUST**。LLM プロンプト台帳は
**「結論保持期間 + 30 日」を下限として刈る MUST**（生存中の結論が
`llm_prompt_sha256` を必ず解決できること — NP6）。
**閾値**: `CONCLUSIONS_RETENTION_DAYS` 既定 **90**、`LLM_PROMPTS_RETENTION_DAYS` 既定 **120**
（実効値は `max(設定値, 結論保持日数 + 30)`）
**根拠**: database.py:5443-5465
**検証**: 未検証（§7 GAP-03）
**分類**: CORE

### 2.10 replay と self_eval（AP4 / AP3）

### S1-CONC-068: replay は台帳の時間旅行であり、物語の再生成ではない
**挙動**: 指定時刻 `at` に対し、各結論型について **`observed_at <= at` を満たす最新行**を返す **MUST**。
`at` 省略時は現在時刻。不正な `at` は 400 **MUST**。
返す行は**実際に永続化された台帳行 MUST**（再導出・再生成してはならない）。
JSON 文字列で格納された `metadata` / `threshold_ref` / `calibration_status` / `source_urls` は
**通常の結論取得と同一の形に再水和 MUST**（フロントが分岐しないため）。
応答は `api_version` / `scenario_id` / `replay_at` / `conclusions` / disclaimer。
本エンドポイントは**アナリスト権限を要求 MUST**。
**根拠**: routes/conclusions_v2.py:468-541
**検証**: test_conclusion_write_gating.py 群が「latest-row-at-T の意味論」を間接的に保証
（S1-CONC-060/061）。**endpoint 自体の as-of 意味論は未検証**（§7 GAP-04）
**分類**: CORE（AP4）

### S1-CONC-069: self_eval は 3 つの信頼メトリクスを返し、決して失敗しない
**挙動**: 自己評価は `recall` / `null_zone_days` / `drift` を返す **MUST**。
**各メトリクスは独立に失敗し得る MUST**（1 つの失敗が他を巻き込まない）。
失敗したメトリクスは **null + `<name>_error` フィールドで理由を開示 MUST**。
応答全体が 5xx になってはならない **MUST**。アナリスト権限を要求 **MUST**。
**根拠**: routes/conclusions_v2.py:544-851
**検証**: test_self_eval.py::test_self_eval_drift_handles_db_error
**分類**: CORE（AP3 + NP3）

### S1-CONC-070: recall は CI ゲートと同一経路・同一窓で算出する
**挙動**: self_eval の recall は、**CI の recall ゲートが使うのと同一の集計経路 MUST**
（チップとゲートが別の数字を出すことを構造的に禁止する）。窓は
**per-conclusion 較正 (§S1-CONC-056) と同一の日数 MUST**。
`recall = ΣTP / (ΣTP + ΣFN)`、分母 0 なら null。
`recall_meta` に **窓日数・総ラベル数・人手ラベル数・自動ラベル数を開示 MUST**
（recall が完全に自己採点である状態＝人手ラベル 0 をアナリストが検知できること）。
**根拠**: routes/conclusions_v2.py:578-623
**検証**: test_self_eval.py::test_self_eval_recall_uses_calibration_window_and_reports_breakdown
**分類**: CORE（AP3 + D2 D-01 への構造的対抗）

### S1-CONC-071: null-zone は「今日から遡る連続全滅日数」
**挙動**: 直近 30 日を日付でバケット化し、**当日から遡って「観測はあるが available が 0 件」の
連続日数**を数える **MUST**。available が 1 件でもある日、または観測 0 件の日で**打ち切る MUST**。
**閾値**: 走査範囲 30 日
**根拠**: routes/conclusions_v2.py:625-652
**検証**: 未検証（§7 GAP-05）
**分類**: CORE

### S1-CONC-072: drift は「平均見逃し率」であり自己参照指標ではない
**挙動**: `drift = mean(1 − recall)` を、**較正状態が INSUFFICIENT_DATA でなく recall が非 null の
シナリオについてのみ**平均する **MUST**。対象シナリオが 0 件なら **null + 理由 MUST**
（0.0 を返してはならない — 「異常なし」に見える）。
`drift_meta` に手法名・対象シナリオ数・最悪シナリオとその見逃し率・窓日数を開示 **MUST**。
**根拠**: routes/conclusions_v2.py:654-700
**検証**: test_self_eval.py::test_self_eval_drift_null_when_no_calibration_data /
::test_self_eval_drift_mean_miss_rate / ::test_self_eval_drift_skips_insufficient_scenarios /
::test_self_eval_drift_handles_db_error
**分類**: CORE（NP1: 見逃しが増えたときに動く指標であること）

### S1-CONC-073: TL 分布の偏りを独立に監視する
**挙動**: 転がし窓における **TL5（平時）の出現割合**が下限を下回り、かつ観測数が最小値以上なら
警報フラグを立てる **MUST**。観測数不足なら**警報を出さない MUST**（`have_enough_data=false`）。
機能が無効なら `{enabled: false, calibration_skew_alert: false}` **MUST**。
これは drift（大きさのドリフト）では検知できない「TL5 の割合が 0% に落ちる」型の劣化を捉える。
**閾値**: `CALIBRATION_SKEW_TL5_MIN_PCT` / `CALIBRATION_SKEW_WINDOW_DAYS` /
`CALIBRATION_SKEW_MIN_OBSERVATIONS` / `CALIBRATION_SKEW_METRIC_ENABLED`
**根拠**: routes/conclusions_v2.py:808-849
**検証**: 未検証（§7 GAP-06）
**分類**: CORE

### 2.11 Markdown エクスポート

### S1-CONC-074: エクスポートは 1 シナリオの最新結論を 1 ファイルにまとめる
**挙動**: エクスポートは 5 型それぞれの最新行を集め、**単一の Markdown 文書**として返す **MUST**。
文書は以下を**必ず含む MUST**: シナリオ名（無ければ ID）/ シナリオ ID / 生成時刻（UTC, ISO8601 秒精度）/
API バージョン / **NP7 disclaimer（文書先頭に 1 回のみ、引用ブロック）**。
結論が 1 件も無ければ**その旨のプレースホルダ文を出す MUST**（空文書にしない）。
出力は**末尾改行 1 個で終わる MUST**。
**根拠**: markdown.py:123-165
**検証**: test_conclusions_markdown.py::test_renders_scenario_header_with_id_and_disclaimer /
::test_falls_back_to_id_when_no_scenario_name / ::test_disclaimer_appears_only_once_per_report /
::test_renders_placeholder_when_no_conclusions / ::test_output_ends_with_single_newline /
::test_renders_iterable_input_not_just_list / ::test_fmt_ts_returns_iso_utc_seconds / ::test_fmt_ts_handles_zero_epoch；
test_conclusions_api.py::test_md_export_returns_markdown_content_type / ::test_md_export_renders_each_saved_conclusion /
::test_md_export_returns_placeholder_for_empty_scenario
**分類**: CORE

### S1-CONC-075: 各結論節は導出鎖を欠落なく含む
**挙動**: 結論 1 件の節は以下を**含む MUST**: 型の日本語見出し / **状態**（結論不可なら
「結論不可」と理由コード）/ 確信度（小数 2 桁）/ 観測時刻 / 結論 ID / 導出式参照 / **閾値（JSON）**。
`source_urls` / `calibration_status` / `metadata` は**存在するときのみ節を出す MUST**（空節を作らない）。
JSON は**キー昇順で整形 MUST**（差分安定性）。
監査トレースが渡され、かつプロンプトが欠落でない場合は **LLM プロンプト全文を折りたたみ節で埋め込む MUST**
（sha256 / model / temperature 付き）。トレースが無い、または欠落マーク付きなら**出さない MUST**。
**根拠**: markdown.py:54-120
**検証**: test_conclusions_markdown.py::test_renders_conclusion_section_with_human_title /
::test_renders_state_confidence_observed_at_id_formula / ::test_renders_thresholds_as_json_fenced_block /
::test_renders_source_urls_as_bullets / ::test_omits_sources_section_when_empty / ::test_renders_calibration_when_present /
::test_omits_calibration_when_empty / ::test_renders_metadata_when_present / ::test_renders_unavailable_state_with_reason /
::test_embeds_llm_prompt_details_when_audit_trace_provided / ::test_omits_llm_prompt_block_when_no_trace_for_conclusion /
::test_omits_llm_prompt_block_when_marked_missing / ::test_fmt_json_sorts_keys_for_diff_stability；
test_conclusions_api.py::test_md_export_includes_audit_trace_when_requested / ::test_md_export_omits_audit_trace_by_default
**分類**: CORE（NP6 の可搬形）

### 2.12 アナリスト feedback 台帳

### S1-CONC-076: ラベルは 4 値の混同行列で、追記のみ
**挙動**: ラベルは `TRUE_POSITIVE` / `FALSE_POSITIVE` / `TRUE_NEGATIVE` / `FALSE_NEGATIVE` の
4 値のみ **MUST**。**永続層でも 4 値制約を強制 MUST**（アプリ層のバリデーションだけに頼らない）。
訂正は**新しい行の追記 MUST**（既存行を書き換えない）。
API 境界で未知のラベル文字列は **400 MUST**。
**根拠**: feedback.py:28-75, 145-153
**検証**: test_conclusions_feedback.py::test_db_check_constraint_rejects_unknown_label /
::test_post_returns_400_for_unknown_label / ::test_post_returns_400_for_missing_label /
::test_save_then_list_returns_newest_first
**分類**: CORE（ADR-V2-011）

### S1-CONC-077: analyst_id と observed_at はサーバが決める
**挙動**: ラベル行の `analyst_id` は**認証情報から導出 MUST**、`observed_at` は**サーバ時刻 MUST**。
クライアントがいずれも詐称できてはならない **MUST**。
`notes` は **2000 文字で切り詰め MUST**。存在しない結論への投稿は **404 MUST**。
**根拠**: routes/conclusions_v2.py:314-328
**検証**: test_conclusions_feedback.py::test_post_creates_row_with_server_derived_analyst_id /
::test_post_returns_404_for_unknown_conclusion / ::test_post_truncates_overlong_notes
**分類**: CORE

### S1-CONC-078: 集計は「単一の評決」ではなく「誰が何と言ったか」を返す
**挙動**: 結論単位の集計は **4 ラベルすべてのカウント（0 を含む）と延べ数と相異なるアナリスト数**を
返す **MUST**。単一の合成評決を返してはならない **MUST**（アナリストバイアス緩和）。
ラベルが 1 件も無い結論でも **404 ではなくゼロ集計を返す MUST**。
一覧は新しい順、既定 50 件・上限 1000 件（内部 API は上限 1000）**MUST**。
**根拠**: feedback.py:84-130、routes/conclusions_v2.py:387-425
**検証**: test_conclusions_feedback.py::test_summarize_returns_zero_counts_for_empty_conclusion /
::test_summarize_counts_distinct_analysts_separately_from_total / ::test_get_returns_summary_and_items /
::test_get_empty_returns_zero_summary_not_404 / ::test_get_returns_404_for_unknown_conclusion
**分類**: CORE

### S1-CONC-079: 横断集計は人手ラベルと自動ラベルを分離できる
**挙動**: 結論横断の集計は、**アナリスト種別（人手 / 自動）で絞り込める MUST**。
自動ラベルは analyst_id が `auto:` 接頭辞を持つもの **MUST**。
返す内容は窓時間 / 総数 / 人手数 / 自動数 / 相異なるアナリスト数 / ラベル別内訳 /
**結論型別内訳** / recall / precision（分母 0 なら null）**MUST**。
既定窓 720 時間（30 日）、最大 1 年、行上限 2000 **MUST**。
**根拠**: feedback.py:165-300
**検証**: test_analyst_feedback_v2.py::TestListRecentFeedback::（6 件全て）；
::TestAggregateFeedbackMatrix::test_empty_returns_zero_counts_and_null_recall /
::test_recall_and_precision_when_signal_exists / ::test_human_vs_auto_breakdown / ::test_per_conclusion_type_breakdown；
::TestEndpoint::test_requires_authentication / ::test_returns_v2_envelope / ::test_returns_planted_rows_in_summary
**分類**: CORE（AP3: recall が自己採点だけになっていないかを見える化する）

### S1-CONC-080: 人手が確認した実事象は独立の ground-truth 台帳にも記録する
**挙動**: **人手**（自動でない）ラベルが `TRUE_POSITIVE` または `FALSE_NEGATIVE` で、
**かつ根拠 URL が付いている**場合のみ、実事象を独立台帳に記録 **MUST**。
- `FALSE_NEGATIVE`（ツールは平穏と判断したが実際は起きた）→ **TL3 相当の下限**で記録し、
  分類名に「見逃し」を明示 **MUST**（ツールの平穏判定を実事象の記述として使わない）
- `TRUE_POSITIVE` → ツールの TL をそのまま記録

書込失敗は**握り潰す MUST**（feedback 本体を壊さない）。
**根拠**: routes/conclusions_v2.py:331-376
**検証**: test_human_anchor.py::TestConfirmedThreatsRevival::test_human_tp_with_url_writes_confirmed_threat /
::test_human_fn_with_url_writes_confirmed_miss / ::test_tp_without_url_does_not_write_confirmed_threat
**分類**: CORE

### 2.13 週次人間アンカーキュー

### S1-CONC-081: 人手ラベルの独立性が calibration の唯一の構造的担保である
**挙動**: ツールは毎週、**人手ラベルの価値が最も高い結論**を短いキューとして提案 **MUST**。
選定は 3 種を**優先順に**充填する **MUST**:
1. `auto_fn_review` — 自動ラベラーが当週 FALSE_NEGATIVE と判定した結論（NP1 最重要クラスであり、
   かつ過去に分類器が正反対に誤った箇所）
2. `peak_severity` — 当週のシナリオごとの**最深刻**な TL 判定（severity 最大。**生 TL 比較禁止**）
3. `calm_anchor` — 誤検知判定地平が完全に経過した平穏側判定（TL4/TL5）

**人手ラベルが 1 件でも付いた結論はキューから外す MUST**。同一シナリオからは各種別 1 件 **MUST**。
同一結論の重複投入禁止 **MUST**。`limit` 到達で打ち切り **MUST**。
DB エラー時は**空リスト MUST**（例外を投げない）。
**閾値**: 既定キュー長 **5**、既定窓 **7 日**（endpoint では窓 1-30 日・件数 1-20 に制限）、
`GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS` 既定 **7**
**根拠**: human_anchor.py:19-35, 200-362
**検証**: test_human_anchor.py::TestSelection::test_auto_fn_review_candidate_surfaces /
::test_human_answered_conclusion_leaves_queue / ::test_peak_severity_picks_most_severe_call /
::test_calm_anchor_requires_elapsed_horizon / ::test_limit_respected_and_fn_prioritized；
::TestQueueEndpoint::test_queue_returns_candidates_and_progress / ::test_queue_requires_auth
**分類**: CORE（D2 D-01「測定系のバグ」への唯一の構造的対抗策）

### S1-CONC-082: アナリストには自然言語の 1 問だけを問い、ラベルはツールが導出する
**挙動**: アナリストに **TP/FP/TN/FN を選ばせてはならない MUST**。
問うのは「この時点から約 N 日以内に、〈シナリオ固有の事象〉は実際に起きましたか?」の 1 問 **MUST**。
ツール自身の立場（alert / calm）から混同行列のセルを**サーバ側で導出 MUST**:

| ツールの立場 | 「はい（起きた）」 | 「いいえ（平穏）」 |
|---|---|---|
| alert（severity >= 3、すなわち TL <= 3、または攻撃モード検知あり） | TRUE_POSITIVE | FALSE_POSITIVE |
| calm（それ以外） | FALSE_NEGATIVE | TRUE_NEGATIVE |

立場判定は**必ず severity 変換を経由 MUST**。問い・立場ラベル・選択肢は日本語 **MUST**。
N は `GROUND_TRUTH_WINDOW_HOURS`（既定 72h）から日数化 **MUST**。
選定理由は**決定論的テンプレート MUST**（LLM 不使用 — AP2）。
**閾値**: alert 判定の最小 severity **3**
**根拠**: human_anchor.py:70-197
**検証**: test_human_anchor.py::TestSelection::test_answer_model_alert_stance_maps_yes_to_true_positive /
::test_answer_model_calm_stance_maps_yes_to_false_negative / ::test_answer_model_question_names_the_scenario /
::test_answer_model_attack_mode_fired_is_alert
**分類**: CORE（AP2）

### S1-CONC-083: 外部調査リンクは調査を自動化するが判断は自動化しない
**挙動**: 各候補に**外部ニュース検索の深リンクを添える MUST**。クエリはシナリオ別検索語 +
`escalation` + 前方判定窓の日付範囲（**終端に 1 日の余裕を足す MUST**）。
URL エンコード必須 **MUST**。検索エンジンは**設定可能なテンプレート MUST**（`{query}` 置換）。
**リンク先の内容をツールに取り込んではならない MUST** — アナリストの答えが独立信号であることが
このキューの存在理由そのもの（同じ公開フィードを読む自動チェックでは相関する盲点を再生産する）。
**閾値**: `HUMAN_ANCHOR_SEARCH_URL`（既定は公開ニュース検索）、日付余裕 1 日
**根拠**: human_anchor.py:106-130
**検証**: test_human_anchor.py::TestSelection::test_search_url_has_terms_and_date_window /
::test_search_url_is_url_encoded / ::test_search_url_respects_config_template
**分類**: CORE

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー | DB override | 出典条項 |
|---|---|---|---|---|
| NP7 disclaimer 文言 | "Tool conclusion only — final judgment by organizational process." | `V2_NP7_DISCLAIMER` | 不可（env のみ） | S1-CONC-004 |
| v2 API 有効 | True | `V2_API_ENABLED` | 不可 | S1-CONC-015 |
| 結論台帳書込有効 | False | `V2_CONCLUSION_LEDGER_ENABLED` | 不可 | S1-CONC-059 |
| TL confidence 分母 | 12.0 | — （ハードコード） | 不可 | S1-CONC-021 |
| lite confidence 係数 | 0.6 | — | 不可 | S1-CONC-022 |
| TL 閾値表（公開値） | 9.0/3.0/6.0/2/4.0/2.0 | — | 不可 | S1-CONC-023（S1-SCORE-004 が原典） |
| falsification 上位 N / domain_cap | 3 / 6.0 | — | 不可 | S1-CONC-026 |
| TREND 窓 | 24h / 7d / 30d | — | 不可 | S1-CONC-027 |
| TREND RISING_DELTA | 0.50 | — | 不可 | S1-CONC-029 |
| TREND ESCALATE_DELTA | 1.50 | — | 不可 | S1-CONC-029 |
| TREND MIN_SAMPLES | 3 | — | 不可 | S1-CONC-030 |
| TREND confidence 上限 / 減点 | 0.95 / 0.15 | — | 不可 | S1-CONC-032 |
| PER_DOMAIN ACTIVE_FLOOR | **2.5** | — | 不可 | S1-CONC-035 |
| PER_DOMAIN ELEVATED_FLOOR | **1.5** | — | 不可 | S1-CONC-035 |
| PER_DOMAIN DEGRADE_DELTA | **1.0** | — | 不可 | S1-CONC-035 |
| PER_DOMAIN magnitude 分母 | 12.0 | — | 不可 | S1-CONC-037 |
| ANOMALY 既定件数 | 10 | — （`?limit=`） | 不可 | S1-CONC-039 |
| ANOMALY 重要度上限 | 100.0 | — | 不可 | S1-CONC-040 |
| ANOMALY 経年時定数 | 12.0 h | — | 不可 | S1-CONC-041 |
| ANOMALY novelty 母数 / 下限 / 窓 | 10 / 0.3 / 86400s | — | 不可 | S1-CONC-042 |
| ATTACK_MODE CYBER_DDOS_FLOOR | **1.2** | — | 不可 | S1-CONC-048 |
| ATTACK_MODE INFO_NARRATIVE_FLOOR | **0.8** | — | 不可 | S1-CONC-048 |
| ATTACK_MODE PHYSICAL_KINETIC_FLOOR | **1.0** | — | 不可 | S1-CONC-048 |
| ATTACK_MODE ALL_DOMAIN_HYBRID_FLOOR | **0.8** | — | 不可 | S1-CONC-048 |
| ATTACK_MODE HYBRID_INTEL_CLUSTER_MIN | 4 | — | 不可 | S1-CONC-048 |
| ATTACK_MODE INFO_DOMINANCE_RATIO | 1.5 | — | 不可 | S1-CONC-048 |
| ATTACK_MODE is_tentative 閾値 | 0.6 | — | 不可 | S1-CONC-050 |
| 拡張 confidence 帯 | [0.55, 0.85] → 上限 0.95、margin 係数 0.30 | — | 不可 | S1-CONC-052 |
| LLM 補強有効 | False | `V2_ATTACK_MODE_LLM_AUGMENT_ENABLED` | 不可 | S1-CONC-054 |
| LLM nudge 上限 | ±0.10 | — | 不可 | S1-CONC-054 |
| 較正窓 | 30 日 | `CALIBRATION_WINDOW_DAYS` | 不可（起動時読取） | S1-CONC-056 |
| 較正最小陽性標本 | 5 | — | 不可 | S1-CONC-056 |
| 較正 DEGRADED recall 下限 | 0.70 | — | 不可 | S1-CONC-056 |
| 較正キャッシュ TTL | 300s | — | 不可 | S1-CONC-058 |
| 変化ゲート有効 | True | `V2_CONCLUSION_WRITE_ON_CHANGE` | 不可 | S1-CONC-060 |
| heartbeat 周期 | 3600s | `V2_CONCLUSION_HEARTBEAT_SEC` | 不可 | S1-CONC-060 |
| バッチ同一性窓 | 5.0s | — | 不可 | S1-CONC-061 |
| 慢性連続日数閾値 | 7.0（下限 3.0） | `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS` | **可** | S1-CONC-064 |
| デューティ窓 / 閾値 | 14.0 日（下限 7.0） / 0.20（下限 0.05） | `CHRONIC_DUTY_WINDOW_DAYS` / `CHRONIC_DUTY_THRESHOLD` | **不可（registry 未登録 — §6 DP3）** | S1-CONC-064 |
| null_severity 段階 | 7 日 / 24 時間 | — | 不可 | S1-CONC-066 |
| 結論台帳保持 | 90 日 | `CONCLUSIONS_RETENTION_DAYS` | 不可 | S1-CONC-067 |
| プロンプト台帳保持 | 120 日（下限 = 結論保持 + 30） | `LLM_PROMPTS_RETENTION_DAYS` | 不可 | S1-CONC-067 |
| null-zone 走査範囲 | 30 日 | — | 不可 | S1-CONC-071 |
| feedback 既定窓 / 行上限 | 720h / 2000 | — | 不可 | S1-CONC-079 |
| 人間アンカー キュー長 / 窓 | 5 / 7 日 | `HUMAN_ANCHOR_QUEUE_SIZE` / — | 不可 | S1-CONC-081 |
| ground-truth 前方窓 / FP 地平 | 72h / 7 日 | `GROUND_TRUTH_WINDOW_HOURS` / `GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS` | 不可 | S1-CONC-081/082 |
| alert 判定の最小 severity | 3 | — | 不可 | S1-CONC-082 |

**v3 への示唆**: 本領域だけで**ハードコード閾値が 30 件**あり、DB override 可能なのは 1 件のみ。
NP6（導出開示）は「結論が threshold_ref で自己申告する」ところまでは達成しているが、
**運用者がどれを調整できるかは不透明**。P では結論に影響する全閾値を単一の宣言的 registry に
載せることを検討する（D2 A-13 と同根）。

---

## 4. 文書との乖離（実装/テストを CORE とし、文書側の訂正を要する）

| # | 文書側の記述 | 実装（CORE） | 扱い |
|---|---|---|---|
| 1 | v2-migration §6.5: ATTACK_MODE 閾値 5.0 / 1.5 / 3.0 / 1.5 | **1.2 / 0.8 / 1.0 / 0.8**（2026-05-10 再較正） | §5-A10 |
| 2 | D5 §3-7: PER_DOMAIN 閾値 3.0 / 1.5 / 1.5 | **2.5 / 1.5 / 1.0**（2026-04-26 再較正） | D5 台帳訂正要 |
| 3 | D5 §2.1: attack_mode 閾値 cyber≥5.0 ∧ info≥1.5 / phys≥3.0 | 同 #1 | D5 台帳訂正要 |
| 4 | D5 §3-7: 「実値はテストのみが保持」 | テストは**定数相対**で値を pin していない | D5 台帳訂正要（§7 GAP-01/02） |
| 5 | S1-SCORE-004: TL1 は `len(active_domains) >= 3` を要求 | **その条件は存在しない**（score>=9 ∧ physical>=3.0 の 2 条件） | §5-A4（姉妹仕様の訂正要） |
| 6 | v2-migration §6.1: threshold_ref を「動的に埋める」 | **凍結された 6 キー定数** | 軽微・文書訂正 |
| 7 | v2-migration §6.1: frequency「5 分間隔」 | 採点ティック周期 + 変化ゲート（heartbeat 3600s） | 軽微・文書訂正 |
| 8 | v2-migration §6.2: TREND 目標語彙 RAPIDLY_* 系 | ESCALATING / RISING / STABLE / COOLING / DEEPER_DECAY | §5-A5（文書側は drift として自認済） |
| 9 | v2-migration §6.2: velocity + acceleration ベース | 窓平均 severity 差分ベース | 文書側 drift 記載済 |
| 10 | v2-migration §6.3: ACTIVE は raw>5.0 ∧ signal_count>=5、DEGRADING は 30% 相対 | 絶対閾値のみ、signal_count ゲート無し | 文書側 drift 記載済 |
| 11 | v2-migration §6.4: ANOMALY state は要約文字列 | **signal_source の統制語彙**（Phase G 2026-04-30） | §5-A9 |
| 12 | v2-migration §6.5: DDOS は cyber_signal_count>=5 ∧ narrative_burst>=3 | 現ティックのドメインスコア | 文書側 drift 記載済 |
| 13 | ADR-V2-010: 慢性判定は 7 日連続のみ | **連続日数 ∨ デューティ比の 2 基準**（2026-07-04 追加） | 文書追記要 |
| 14 | inconclusive_continuity docstring: 「SETTINGS から調整可能」 | デューティ側パラメータは registry 未登録で**調整不能** | §6 DP3 |

---

## 5. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | `ConclusionUnavailableReason` 4 値のうち `calibration_pending` / `sensor_degraded` / `upstream_failure` を**生成する経路が存在しない**。全結論不可が `insufficient_data` に潰れている | NP5+8 は「なぜ結論できないか」の区別を要求している。センサー劣化と較正待ちを区別できないと、アナリストは「待てば直る」のか「壊れている」のか判断できない。v3 で 3 値を実装するか、列挙から落とすか |
| A2 | 台帳行が無いときの結論不可応答が `Conclusion` 型を経由せず dict を手組みしている（S1-CONC-014）。スキーマ不変条件の検証を通らない | 「試みて失敗した」と「まだ何も無い」を型で区別する設計意図は理解できるが、NP7/スキーマ強制が効かない抜け穴になっている |
| A3 | TL confidence の分母 12.0 が明示的な暫定値（isotonic 回帰は ADR-V2-010 で予定されたまま未着手） | confidence が線形写像である限り「確信度」の意味が薄い。v3 で確率的較正を入れるか、名称を変えるか |
| A4 | S1-SCORE-004 の TL1「3 ドメイン」条件が実装に無い（文書乖離 #5） | 実装が正しいのか仕様が正しいのか。**TL1 = 最も重い結論**の発火条件なので NP1 上重要 |
| A5 | TREND 語彙が設計目標（RAPIDLY_* 5 値）と別物のまま 1 年以上定着 | UI/通知/自己説明がすべて現語彙に依存済。目標形に戻す価値があるか |
| A6 | PER_DOMAIN の分類順序で **DEGRADING が ELEVATED より優先**。prior 4.0 → cur 2.0 は ELEVATED ではなく DEGRADING になる | 「高いが下がっている」を DEGRADING と呼ぶのは妥当だが、絶対水準の情報が state から消える。packed state 1 本の設計上、両方は表現できない |
| A7 | ANOMALY の 12h を設計文書が長く "half-life" と誤記（実際は 1/e 時定数、半減期は 8.32h） | 実装は式どおり。呼称のみ訂正すればよいか、意図が半減期 12h だったのか |
| A8 | 変化ゲート導入（2026-07-04）により ANOMALY 台帳行が激減 → novelty の `similar_count` が構造的に小さくなり **importance が上振れ**する。両機能は独立に設計され相互作用が未評価 | novelty の定義を「台帳行数」から「観測ティック数」に変えるべきか。NP1 上は安全側（重要度が上がる）だが、順位付けの意味が変質している |
| A9 | ANOMALY state を signal_source だけにしたため、**同一 signal_source の異なる異常が state 上で区別できない**（識別情報は metadata 側） | 集計可能性（Phase G の狙い）と個別識別のトレードオフ。v3 では state を構造化値にする選択肢がある |
| A10 | ATTACK_MODE 閾値が「観測分布に合わせて下げる」方向で 2 回動いており、現在 cyber 1.2 / info 0.8 は**ほぼベースライン水準**。結論不可を減らすために感度を上げた結果、DDOS_PRECURSOR が常時点灯しうる | NP5+8（恒常的結論不可＝設計失敗）と NP1（感度）を満たすための調整だが、「常に何か言う」状態は結論の情報量を下げる。閾値を観測分布に追従させる運用自体の是非 |
| A11 | 継続性判定が `conclusion_unavailable_reason` に加えて **state 文字列 `"INSUFFICIENT_DATA"` も結論不可と見なす**。TREND の packed state は `short_term=INSUFFICIENT_DATA;...` 形式なので一致しないが、将来の型で誤判定しうる | 二重判定を残すか、理由フィールド一本にするか |
| A12 | `V2_CONTINUITY_FAILURE_SEC`（7 日）が config に定義されているが**どこからも参照されていない**デッドキー | 削除か、慢性判定への統合か |
| A13 | Markdown エクスポートが `calibration_status` と `metadata`（rationale_matrix / falsification を含む）を**生 JSON のまま**出す。アナリスト向け成果物としては読めない | NP6（全開示）を優先した結果。v3 で人間可読な整形を入れるか |
| A14 | `V2_API_ENABLED` は既定 true で 13 箇所のゲートが恒常通過（D2 C-03 と同一） | v3 に持ち込まない前提だが、v1 sunset 完了の確認が要る |

---

## 6. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | TL 導出式が **3 箇所に複製**（scoring.py 本体 / threat_level.py の THRESHOLD_REF / sensitivity.py の `_TL_RUNGS` + `_derive_tl_from_components`）。同期はテストのみが担保し、sensitivity 側の複製は TL1 条件が本体と**構造的に異なる**（active_domains を持たない） | TL 導出は**単一実装 MUST**。閾値表は実装から機械的に導出 **MUST** | A-02 |
| DP2 | `ConclusionUnavailableReason` の 4 値中 3 値に生成経路が無く、全結論不可が `insufficient_data` に潰れている | 結論不可の理由は**実際に区別して発行 MUST**（区別できないなら列挙から落とす MUST） | — (NP5+8) |
| DP3 | 慢性判定のデューティ側パラメータ（窓・閾値）が config registry に**未登録**。`get_config()` が失敗しハードコード既定値にフォールバックするため、docstring が謳う「SETTINGS から即時調整」が**実際には効かない** | 結論に影響する全パラメータは registry 経由 **MUST**。フォールバックは**警告を伴う MUST**（沈黙のフォールバックは NP6 違反） | A-13 |
| DP4 | 較正状態・self_eval・慢性検知のすべてが例外を握り潰して「正常に見える既定値」に落ちる（INSUFFICIENT_DATA / 空リスト / null）。NP3 上は正しいが、**壊れているのか本当にデータが無いのかを区別する経路が metadata の一部にしか無い** | 縮退経路は**必ず観測可能な標識を伴う MUST**（ANOMALY の `novelty_source` が良い先例） | D-01 |
| DP5 | `radar/conclusions/rss_extractor.py`（586 行）が結論パッケージに同居しているが責務はセンサー層 | 層の所属を構造で表す **MUST** | C-08 |
| DP6 | 結論台帳へ「ティック毎に同一結論を書く」設計だったため 1 週間で 89,884 行（distinct 12 状態）まで膨張し、DB の 83% を占めた。変化ゲートで是正済だが、**ゲートを外すと再発する** | 台帳の書込単位は**状態変化 MUST**。時系列観測は別レイヤ **MUST** | — |

---

## 7. テストトレーサビリティ

対象は D5 台帳の conclusions 系全ファイル。**BEHAVIOR 234 件 / CONTRACT 90 件 / STRUCTURAL 14 件 = 338 件**。

| テストファイル | 件数 | D5 分類 | 対応条項 |
|---|---|---|---|
| test_anomaly_derive.py | 29 | BEHAVIOR | S1-CONC-004, 009, 010, 039〜046, 055 |
| test_per_domain_derive.py | 27 | BEHAVIOR | S1-CONC-004, 009, 034〜038 |
| test_attack_mode_derive.py | 26 | BEHAVIOR | S1-CONC-004, 009, 010, 047〜050 |
| test_attack_mode_extensions.py | 26 | BEHAVIOR | S1-CONC-051, 052, 053 |
| test_trend_derive.py | 23 | BEHAVIOR | S1-CONC-004, 009, 027〜033 |
| test_conclusions_markdown.py | 21 | CONTRACT | S1-CONC-074, 075 |
| test_conclusions_api.py | 19 | CONTRACT | S1-CONC-011, 013, 014, 015, 016, 017, 018, 074, 075 |
| test_human_anchor.py | 17 | BEHAVIOR | S1-CONC-080, 081, 082, 083 |
| test_inconclusive_continuity.py | 17 | BEHAVIOR（混在: endpoint は CONTRACT） | S1-CONC-064, 065 |
| test_threat_level_derive.py | 15 | BEHAVIOR | S1-CONC-004, 009, 019〜025 |
| test_conclusions.py | 14 | CONTRACT | S1-CONC-001〜007 |
| test_conclusions_feedback.py | 14 | CONTRACT | S1-CONC-015, 076, 077, 078 |
| test_attack_mode_llm_augment.py | 14 | BEHAVIOR | S1-CONC-005, 054 |
| test_conclusions_persistence.py | 14 | STRUCTURAL | S1-CONC-059, 063 |
| test_analyst_feedback_v2.py | 13 | CONTRACT | S1-CONC-011, 079 |
| test_conclusion_write_gating.py | 12 | BEHAVIOR | S1-CONC-060, 061, 062, 068 |
| test_falsification.py | 12 | BEHAVIOR | S1-CONC-026 |
| test_conclusion_calibration.py | 8 | BEHAVIOR | S1-CONC-055, 056, 058 |
| test_severity.py | 8 | BEHAVIOR | S1-CONC-019（うち 3 件は ground-truth ラダー = **S1-calibration 担当**） |
| test_self_eval.py | 9 | CONTRACT | S1-CONC-069, 070, 072 |

**境界外**（本書では扱わない）: test_ground_truth_etl.py(39) / test_report_recall_metrics.py(8) /
test_check_recall_baseline.py(16) → **S1-calibration**。test_rss_extractor.py(56) → **S1-sensors**。
test_shadow_metrics.py(10) → SCAFFOLD、v3 に持ち込まない。

**対応条項の無いテスト（GAP）: 0 件。** 上記 20 ファイル全件がいずれかの条項に対応する。

### GAP（仕様化したが検証が無い）

| ID | 内容 | 影響 |
|---|---|---|
| GAP-01 | ATTACK_MODE の**数値閾値そのもの**を pin するテストが無い（全て定数相対）。誰かが `CYBER_DDOS_FLOOR = 0.1` にしても全 26 件が通る | **高**。分類器の感度が無検知で変わる。D5 §3-5 の「仕様の宝」評価は再考を要する |
| GAP-02 | 同じく PER_DOMAIN / TREND の数値閾値が未 pin | **高**（同上） |
| GAP-03 | 台帳 retention（90 日 / プロンプト下限 +30 日）の挙動テストが無い | 中。NP6 の監査経路が沈黙で切れうる |
| GAP-04 | replay endpoint の as-of 意味論（`observed_at <= at` の型ごと最新）に専用テストが無い。write-gating テストが間接保証するのみ | 中。AP4 の中核 |
| GAP-05 | 結論不可行の `null_run_minutes` / `null_severity` 付与（S1-CONC-066）が未検証 | 低〜中 |
| GAP-06 | self_eval の `null_zone_days`（S1-CONC-071）と `tl_distribution_skew`（S1-CONC-073）が未検証 | 中。後者は「TL5 が 0% に落ちる」型の較正劣化の唯一の検知器 |
| GAP-07 | LLM 補強で sha256 計算が失敗（空文字）した場合に元の値を保持する分岐が未検証 | 低 |
| GAP-08 | S1-CONC-008（disclaimer の読み出し時注入）/ 012（envelope observed_at）/ 057（(結論, アナリスト) 最新 1 件 dedup）が未検証 | 中。057 は recall の分母に直結 |

---

## 8. 未決事項

1. **`ConclusionUnavailableReason` の設計意図**（§5-A1 / §6 DP2）: 4 値の列挙は NP5+8 の
   「なぜ結論できないか」を区別する意図だったはずだが、3 値が未実装のまま定着している。
   v3 で区別を実装するのか列挙を縮めるのかは**オーナー裁定が要る**。本書は現行を CORE として記述した
2. **ATTACK_MODE 閾値の追従運用**（§5-A10）: 「観測分布に合わせて閾値を下げる」調整が
   2 回行われ、現在ほぼベースライン水準にある。NP5+8（恒常的結論不可の回避）と
   結論の情報量のトレードオフが未評価。v3 では**閾値の由来と改訂履歴を結論に添える**設計を検討したい
3. **novelty × 変化ゲートの相互作用**（§5-A8）: 定量評価が未実施。実データでの
   importance 分布シフトを測る必要がある
4. **人間アンカーの実効性**: 週次キューは実装済だが、実際に人手ラベルが供給されているか
   （`recall_meta.labels_human` の実測）は D4 の範囲。**人手ラベル 0 が続く場合、
   §S1-CONC-081 の存在意義が形骸化する**ため、v3 では供給量そのものを AP3 の監視対象にすべき
5. GAP-01/02 の解消（数値閾値の直接 pin）は**現行系でも即時に着手可能**であり、
   v3 パリティゲートの前提として先行実施を推奨する

---

*Phase S。一次ソース: `radar/conclusions/*.py`（19 ファイル、rss_extractor / shadow_metrics を除く）、
`radar/routes/conclusions_v2.py`、`radar/routes/human_anchor_v2.py`、conclusions 系テスト 20 ファイル 338 件。*
