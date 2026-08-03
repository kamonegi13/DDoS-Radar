# S1 — 結論導出 (conclusions) 挙動仕様

**スコープ**: ツールの**出力そのもの**の定義。5 種の結論 (THREAT_LEVEL / TREND / PER_DOMAIN / ANOMALY /
ATTACK_MODE) の統一スキーマ・導出式・閾値・**結論不可 (UnavailableReason) の全パターン**・v2 envelope・
台帳への書込ゲート・慢性結論不可検知・replay/self_eval・markdown エクスポート・analyst feedback 台帳・
週次人間アンカーキュー。

**隣接仕様との境界**:
- スコア → TL の写像（式・収斂・ヒステリシス）は **S1-SCORE-004 ほか S1-scoring-core が優越**。本書は
  「その TL を結論としてどう組み立て、何を添えて公開するか」のみ
- ground-truth ラベル**生成**（auto:acled / auto:gdelt ETL、severity floor ラダー）は **S1-calibration**。
  本書は生成済みラベルを**読む**側（calibration_status / recall）のみ
- 採点ティックの順序と副作用は S1-scoring-pipeline。本書は「どのフックがどの型を出すか」のゲート条件のみ
- `radar/conclusions/rss_extractor.py` は本パッケージ配下だが責務はセンサー層（D2 C-08）→ **S1-sensors**
- `radar/conclusions/shadow_metrics.py` は v1→v2 移行足場（D2 C-03）。v3 に持ち込まないため**仕様化しない**

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソースについて**: PER_DOMAIN / TREND / ATTACK_MODE の閾値は D5 の指示どおり実装値を CORE とした。
ただし **D5 §3-7 の前提「実値はテストのみが保持」は誤り**である。当該テスト群は閾値を**モジュール定数として
import し、定数相対で境界を検証する**設計であり、数値そのものは pin していない。数値の唯一の所在は
モジュール定数であり、テストは「threshold_ref が定数を漏れなく公開しているか」のドリフト検知装置である
（§7 GAP-01/02）。

---

## 1. 用語

CLAUDE.md の用語定義に従う。本書固有:

- **conclusion**: ツールが公開する 1 個の判断。5 型のいずれか。台帳に append-only で蓄積される
- **envelope**: 結論を API 応答として包む外殻（api_version / scenario_id / observed_at / disclaimer / conclusions[]）
- **結論不可 (unavailable)**: `state=None` かつ `conclusion_unavailable_reason` 非 None の状態
- **packed state**: 複数の下位状態を 1 本の文字列に詰めた state（`cyber=ACTIVE;physical=STABLE;info=STABLE`）
- **change gate**: 状態変化時と heartbeat 周期だけ台帳に書く間引き機構
- **open run**: ある (scenario, type) が結論不可であり続けている連続区間
- **TL**: 脅威レベル。**1=CRITICAL … 5=NORMAL（DEFCON 式）**。大小比較は必ず `severity = 6 − TL` 経由

**検証欄のテスト略号**（全て `tests/` 配下）: `TL`=test_threat_level_derive / `TR`=test_trend_derive /
`PD`=test_per_domain_derive / `AN`=test_anomaly_derive / `AM`=test_attack_mode_derive /
`AX`=test_attack_mode_extensions / `AL`=test_attack_mode_llm_augment / `SC`=test_conclusions /
`API`=test_conclusions_api / `CAL`=test_conclusion_calibration / `GATE`=test_conclusion_write_gating /
`PER`=test_conclusions_persistence / `MD`=test_conclusions_markdown / `FB`=test_conclusions_feedback /
`FB2`=test_analyst_feedback_v2 / `IC`=test_inconclusive_continuity / `HA`=test_human_anchor /
`FAL`=test_falsification / `SEV`=test_severity / `SE`=test_self_eval。「全件」は当該ファイルの全テスト。

---

## 2. 挙動条項

### 2.1 統一スキーマと不変条件

### S1-CONC-001: 結論は 5 型のみ、ID は生成ごとに一意
**挙動**: 型は `threat_level` / `trend` / `per_domain` / `anomaly` / `attack_mode` の 5 値のみ **MUST**
（CLAUDE.md ツール定義の 5 出力と 1:1）。各結論は生成時に一意 ID（UUID 形式）を持つ **MUST**。
**根拠**: base.py:20-27, 43-45
**検証**: SC::test_all_conclusion_types_construct / ::test_conclusion_id_is_unique
**分類**: CORE

### S1-CONC-002: 構築時に 3 つの不変条件を強制する（違反は拒否、クランプしない）
**挙動**: 以下を満たさない結論は**構築を拒否 MUST**。沈黙の補正をしてはならない。

| 不変条件 | 内容 |
|---|---|
| state / reason 排他 | `reason is None` なら `state` 非 None **MUST**、`reason` 非 None なら `state is None` **MUST** |
| confidence 値域 | `0.0 <= confidence <= 1.0` **MUST** |
| NP7 disclaimer | 空文字 / None を許さない **MUST** |

**閾値**: `V2_NP7_DISCLAIMER` 既定 `"Tool conclusion only — final judgment by organizational process."`
**根拠**: base.py:71-87、config.py:227-230
**検証**: SC::test_unavailable_conclusion_requires_null_state / ::test_available_conclusion_requires_non_null_state /
::test_unavailable_conclusion_with_null_state_is_valid / ::test_confidence_must_be_between_zero_and_one /
::test_disclaimer_is_required；disclaimer は 5 型が独立検証 (TL/TR/PD/AM/AN の `test_disclaimer_*` 各 1 件)
**分類**: CORE（NP5+8 と NP7 を型で強制）

### S1-CONC-003: 結論は生成後に変更不能、直列化は安定
**挙動**: 結論オブジェクトは**不変 MUST**（下流の加工は複製を返す **MUST**）。API 表現では列挙型を
**文字列値に落とす MUST**。永続表現では threshold_ref / source_urls / calibration_status / metadata を
**JSON 文字列化 MUST**、辞書は**キー昇順で安定化 MUST**（差分可読性）。
**根拠**: base.py:48, 93-136
**検証**: SC::test_conclusion_is_frozen / ::test_to_dict_serialization_round_trip / ::test_to_db_row_serializes_json_fields /
::test_unavailable_reason_serializes_to_string；AL::test_rule_conclusion_is_not_mutated
**分類**: CORE（NP6: 公開済み結論の事後改変を構造的に禁止）

### S1-CONC-004: disclaimer は行に保存せず読み出し時に注入する
**挙動**: 台帳から結論を復元する際、`final_judgment_disclaimer` は**行の値ではなく現行 config 値を注入 MUST**。
文言改訂時に過去行が古い文言を持ち続けることを防ぐ。
**根拠**: persistence.py:336-354
**検証**: 未検証（§7 GAP-06）
**分類**: CORE

### S1-CONC-005: 結論不可理由は 4 値の閉じた列挙 — **本書の中核 (NP5+8)**
**挙動**: 結論不可の理由は以下 4 値のみ **MUST**。理由なしの結論不可は表現できない (S1-CONC-002)。

| 値 | 意味 | 発生条件（実装上の全経路） |
|---|---|---|
| `insufficient_data` | 判断に足るデータが無い | (a) TL が導出できない (013) / (b) TREND の 3 窓すべてが標本不足 (021) / (c) PER_DOMAIN の 3 ドメインすべてが無信号 (025) / (d) ANOMALY に採点可能な寄与が皆無 (026) / (e) ATTACK_MODE でどの規則も発火しない (032) / (f) 台帳に当該 (scenario, type) の行がまだ無い (008) |
| `calibration_pending` | 較正未成立で保留 | **生成経路が存在しない**（§6 DP2） |
| `sensor_degraded` | センサー劣化 | **同上、生成経路なし** |
| `upstream_failure` | 上流障害 | **同上、生成経路なし** |

**根拠**: base.py:30-40（列挙）、threat_level.py:126 / trend.py:121 / per_domain.py:106 / anomaly.py:128 /
attack_mode.py:107 / api.py:63（発行点）
**検証**: TL::test_tl_none_yields_insufficient_data；TR::test_empty_db_yields_insufficient_data；
PD::test_all_domains_silent_yields_insufficient_data；AN::test_no_contributions_yields_single_insufficient_data；
AM::test_no_signals_yields_insufficient_data / ::test_below_all_floors_yields_insufficient_data；
API::test_bundle_endpoint_returns_unavailable_for_empty_scenario
**分類**: CORE。**4 値中 3 値が未使用である点は ACCIDENTAL**（§5-A1）

### S1-CONC-006: 結論不可は「否定の主張」ではない
**挙動**: 結論不可の結論は、**当該事象が存在しないことを主張してはならない MUST**。とくに ATTACK_MODE の
結論不可は「攻撃なし」ではなく「規則が判断を放棄した」を意味する。結論不可行には
`metadata.is_transient`（真偽）と `metadata.reason_detail`（平文の理由）を**必ず添える MUST**。
**根拠**: attack_mode.py:96-113、threat_level.py:127-135、trend.py:122-126、per_domain.py:107-112、anomaly.py:129-134
**検証**: AM::test_no_signals_yields_insufficient_data / ::test_insufficient_metadata_carries_domain_scores；
TR::test_empty_db_yields_insufficient_data；AN::test_no_contributions_yields_single_insufficient_data
**分類**: CORE（NP1: 見逃しを「無害」と誤読させない）

### 2.2 v2 API envelope

### S1-CONC-007: envelope は固定 5 フィールド、disclaimer は二重掲示、エラーも例外でない
**挙動**: 成功応答は `api_version`(="2.0") / `scenario_id` / `observed_at` / `final_judgment_disclaimer` /
`conclusions[]` **MUST**。**各結論オブジェクト自身も disclaimer を保持 MUST**（envelope を剥がしても NP7 が残る）。
`observed_at` 未指定時は**同梱結論の観測時刻の最大値 MUST**（空なら現在時刻）。
**4xx / 5xx を含むすべての v2 応答**が api_version と disclaimer を持つ **MUST**。
**根拠**: api.py:20-56
**検証**: API::test_bundle_endpoint_returns_latest_of_each_type / ::test_v2_error_responses_carry_disclaimer；
FB2::TestEndpoint::test_returns_v2_envelope（observed_at 既定は未検証 — §7 GAP-06）
**分類**: CORE（NP7 の抜け穴封じ）

### S1-CONC-008: 台帳行が無い (scenario, type) は「まだ言うことがない」を 200 で返す
**挙動**: 台帳に行が無い場合、404 ではなく**結論不可 envelope を 200 で返す MUST**。理由は
`insufficient_data`、`confidence=0.0`、`formula_ref=null`、`threshold_ref={}`、`source_urls=[]`、
`metadata.is_transient=true`。「試みて失敗した」ではなく「まだ何も言えない」を表現する。
**根拠**: api.py:59-99
**検証**: API::test_bundle_endpoint_returns_unavailable_for_empty_scenario
**分類**: CORE。**結論オブジェクトを経由せず dict を手組みしている点は ACCIDENTAL**（§5-A2）

### S1-CONC-009: v2 面はフラグで一括無効化でき、無効時は 503
**挙動**: v2 API 全体を単一フラグで無効化でき、無効時は全エンドポイントが **503 + NP7 準拠 body MUST**。
**閾値**: `V2_API_ENABLED` 既定 **True**
**根拠**: routes/conclusions_v2.py:56-66、config.py:244
**検証**: API::test_v2_returns_503_when_flag_off / ::test_md_export_503_when_v2_disabled；
FB::test_post_503_when_v2_disabled / ::test_get_503_when_v2_disabled
**分類**: CORE。**恒常 true の移行足場である点は D2 C-03**（v3 では撤去 MUST）

### S1-CONC-010: bundle は 5 型それぞれの最新行、不正入力は 400/404
**挙動**: シナリオ単位の bundle は 5 型それぞれについて**独立に最新 1 行**を集めて返す **MUST**（1 型が古くても
他型は最新を返す）。1 型も無ければ S1-CONC-008。未知の conclusion_type は **400 MUST**（有効値一覧を detail に）、
未知の結論 ID は **404 MUST**。
**根拠**: routes/conclusions_v2.py:134-143, 153-166, 176-182
**検証**: API::test_bundle_endpoint_returns_latest_of_each_type / ::test_bundle_endpoint_picks_newest_per_type /
::test_single_type_endpoint_returns_only_that_type / ::test_single_type_endpoint_rejects_unknown_type /
::test_single_id_endpoint_returns_404_when_unknown / ::test_single_id_endpoint_returns_envelope_when_found
**分類**: CORE

### S1-CONC-011: 監査トレースは導出鎖を全部開示する
**挙動**: 結論 1 件の監査トレースは formula_ref / threshold_ref / source_urls / calibration_status / metadata を
**そのまま開示 MUST**。LLM プロンプト sha256 が紐づく場合は**全文を解決して返す MUST**。プロンプト行が
retention で消えている場合は**「欠落」を明示 MUST**（沈黙の null にしない）。sha256 が無い場合は明示的な null。
**根拠**: routes/conclusions_v2.py:185-224
**検証**: API::test_audit_trace_returns_full_disclosure_without_llm / ::test_audit_trace_resolves_llm_prompt_when_sha_set /
::test_audit_trace_marks_llm_prompt_missing_when_row_purged / ::test_audit_trace_returns_404_when_unknown
**分類**: CORE（NP6 の到達点）

### 2.3 THREAT_LEVEL 結論

### S1-CONC-012: state は TL 整数の文字列、比較は必ず severity 経由
**挙動**: `state` は TL 整数の文字列表現（`"1"`〜`"5"`）**MUST**。**TL は 1=CRITICAL / 2=SEVERE / 3=HIGH /
4=ELEVATED / 5=NORMAL（DEFCON 式）**であり、**深刻度の大小比較は `severity = 6 − TL` に変換してから行う MUST**。
生の TL 整数を `<` / `>` で比較してはならない。範囲外 TL の severity 変換は**即座に失敗 MUST**
（沈黙の誤採点より速い失敗を優先）。
**根拠**: threat_level.py:168、severity.py:22-43
**検証**: TL::test_state_is_string_of_tl_int；SEV::test_tl_constants_are_defcon_style /
::test_severity_of_is_monotonically_decreasing_in_tl / ::test_severity_of_rejects_out_of_range_tl /
::test_derive_tl_agrees_with_severity_direction / ::test_more_alarmed_tool_never_scores_worse_than_calmer_tool
**分類**: CORE（較正災害 2 件の再発防止番兵）

### S1-CONC-013: TL が出せないときも行を出す
**挙動**: スコアリングが TL を決められなかった場合、行を**黙って捨ててはならない MUST**。`insufficient_data` の
結論を発行し、`metadata.reason_detail` に導出関数が None を返した旨を記す **MUST**。これにより慢性結論不可検知
(§2.9) の観測列が途切れない。
**根拠**: threat_level.py:113-136
**検証**: TL::test_tl_none_yields_insufficient_data / ::test_rationale_matrix_present_on_insufficient_data_branch
**分類**: CORE（NP1 + NP5+8）

### S1-CONC-014: TL の confidence はスコアの線形写像をクランプしたもの、lite は割引
**挙動**: `confidence = clamp(score / 12.0, 0, 1)` を小数 3 桁に丸める **MUST**。scoring_mode が lite の結論は
さらに **0.6 を乗じる MUST**（TL 値自体は変えない）。lite の結論には `metadata.lite_tl_note` を**付与 MUST**、
full には**付与しない MUST**。
**閾値**: 分母 **12.0**（暫定較正）、lite 係数 **0.6**（いずれもハードコード）
**根拠**: threat_level.py:58, 62, 138-146, 184-190
**検証**: TL::test_confidence_clamped_to_unit_interval；test_scenario_scoring.py::TestLiteTlConfidenceDiscount::（2 件、
S1-SCORE-017 と共有）
**分類**: CORE（NP4 で結論は出す、NP5+8 で品質差を可視化）。**分母 12.0 は ACCIDENTAL**（§5-A3）

### S1-CONC-015: TL 結論は使用した閾値表を自ら公開する
**挙動**: TL 結論は導出に使った閾値を `threshold_ref` として**公開 MUST**。キーは `tl1_total` / `tl1_physical` /
`tl2_total` / `tl2_active_domains_min` / `tl3_total` / `tl4_total` の 6 個。値は S1-SCORE-004 の閾値と
**一致していなければならない MUST**。
**閾値**: 9.0 / 3.0 / 6.0 / 2 / 4.0 / 2.0
**根拠**: threat_level.py:46-53
**検証**: TL::test_threshold_ref_matches_derive_tl（導出関数の境界も同時検証）/ ::test_formula_ref_matches_derive_tl_version
**分類**: CORE。**S1-SCORE-004 が TL1 に課す「3 ドメイン」条件は実装にも閾値表にも存在しない**（§5-A4）

### S1-CONC-016: 導出根拠マトリクスと一次ソースを添える
**挙動**: TL 結論の metadata に、寄与信号 1 件ごとの **rationale_matrix を添える MUST**。各行は sensor / domain /
signal_source / value_display / raw_score / contributing_country / participant_role / final_contribution /
**formula_trace** / evidence_url / suppress_reason を持つ。並び順は `|final_contribution|` の**降順 MUST**、
数値は小数 3 桁。寄与が無ければ**空配列 MUST**（キーは存在する）。**結論不可の行にも添える MUST**。
`source_urls` は寄与の evidence_url を**集合化し昇順ソート MUST**。
**根拠**: threat_level.py:83-111
**検証**: TL::test_metadata_includes_rationale_matrix_when_contributions_exist / ::test_rationale_matrix_is_empty_list_when_no_contributions /
::test_rationale_matrix_sorted_by_absolute_contribution / ::test_rationale_matrix_carries_suppress_reason /
::test_rationale_matrix_present_on_insufficient_data_branch / ::test_metadata_captures_replay_fields /
::test_source_urls_are_deduplicated_and_sorted
**分類**: CORE（NP6 の最小単位。S1-SCORE-009 の formula_trace をそのまま搬送する）

### S1-CONC-017: 反証レポート — 「何が変われば結論が変わるか」を決定論的に添える
**挙動**: TL 結論の metadata に `falsification` を添える **MUST**。内容 3 部:
1. **to_higher_tl**: 1 段深刻な TL（番号 −1）に不足している条件を `{field, current, target, gap}` で列挙 **MUST**。
   **TL1 では target を null MUST**。全条件充足なら `all_satisfied=true`
2. **to_lower_tl**: 現在の段が依存する閾値を `{field, current, trigger_below, gap}` で列挙 **MUST**。
   **TL5 では target を null MUST**
3. **signal_sensitivity**: 寄与上位 N 件について、その信号がゼロに落ちた場合の仮想 TL と移動段数を算出 **MUST**。
   GLOBAL 寄与・抑制済み寄与・非正寄与は**除外 MUST**

計算は rationale_matrix への純粋な算術 **MUST**（LLM 不使用、再採点なし、冪等）。TL が結論不可なら**空辞書 MUST**。
**閾値**: 上位 N = **3**、domain_cap = **6.0**
**根拠**: sensitivity.py:59-313
**検証**: FAL::全件（12）
**分類**: CORE（NP1 反証性 / AP2 の入力）。**TL 導出式の複製は DEFECT-PRESERVE**（§6 DP1）

### 2.4 TREND 結論

### S1-CONC-018: TREND は 3 窓を 1 行に詰め、一次ソースを持たない
**挙動**: `short_term`(24h) / `medium_term`(7d) / `long_term`(30d) の 3 窓を評価し、**1 個の結論行**に packed state
`short_term=X;medium_term=Y;long_term=Z` として格納 **MUST**（順序固定）。同内容を `metadata.windows` にも辞書で持つ。
TREND は台帳の TL 行から算出されるため `source_urls` は**常に空 MUST**（生センサー URL を偽って添えない）。
**閾値**: 86400s / 604800s / 2592000s
**根拠**: trend.py:50-54, 140, 208-217
**検証**: TR::test_state_string_packs_all_three_windows_in_canonical_order / ::test_state_string_uses_module_window_order /
::test_returns_single_conclusion_of_trend_type / ::test_threshold_ref_mirrors_module_constants / ::test_formula_ref_is_versioned /
::test_source_urls_empty_trend_synthesizes_no_evidence / ::test_round_trip_via_save_then_re_derive
**分類**: CORE（NP6: 出典を捏造しない）

### S1-CONC-019: 窓の評価は「現在期間の平均 severity − 直前期間の平均 severity」
**挙動**: 窓幅 W に対し `[now−W, now)` を現在期間、`[now−2W, now−W)` を直前期間とし、各期間内の THREAT_LEVEL
台帳行の **severity 平均の差 `delta = cur_mean − prev_mean`** で分類 **MUST**。severity は TL1→4 / TL2→3 / TL3→2 /
TL4→1 / TL5→0 の写像 **MUST**（大きいほど深刻）。他シナリオの行、state が null の行、1..5 以外の state 文字列は
**除外 MUST**。
**根拠**: trend.py:48, 149-193
**検証**: TR::test_window_seam_classifies_rows_into_correct_slice / ::test_rows_for_other_scenarios_are_ignored /
::test_unknown_tl_state_is_ignored
**分類**: CORE

### S1-CONC-020: 5 状態語彙と分類順序
**挙動**: delta に対し以下の順に評価し最初に成立した状態を採る **MUST**: `delta >= 1.50` → **ESCALATING** /
`delta >= 0.50` → **RISING** / `delta <= −1.50` → **DEEPER_DECAY** / `delta <= −0.50` → **COOLING** /
それ以外 → **STABLE**。境界値は**いずれも当該状態に含める（`>=` / `<=`）MUST**。
**閾値**: `RISING_DELTA` = **0.50**、`ESCALATE_DELTA` = **1.50**（ハードコード）
**根拠**: trend.py:69-70, 196-205
**検証**: TR::test_stable_when_delta_within_rising_band / ::test_rising_when_delta_above_rising_below_escalate /
::test_escalating_when_delta_at_or_above_escalate_delta / ::test_cooling_when_negative_delta_at_or_above_rising /
::test_deeper_decay_when_negative_delta_at_or_above_escalate / ::test_rising_delta_boundary_inclusive（定数相対 — GAP-02）
**分類**: CORE。**設計文書 §6.2 の目標語彙 (RAPIDLY_* 系) との乖離は ACCIDENTAL**（§5-A5）

### S1-CONC-021: 標本数は両期間 3 件以上、1 窓でも判定できれば結論は available
**挙動**: 現在期間・直前期間の**いずれか**が 3 件未満なら当該窓は判定不能 **MUST**（packed state 上は
`INSUFFICIENT_DATA`）。標本数は `metadata.sample_counts[window] = {current_n, previous_n}` として**常に開示 MUST**。
3 窓のうち **1 つでも判定できたら結論は available MUST**。**3 窓すべて判定不能のときのみ `insufficient_data` MUST**。
**閾値**: `MIN_SAMPLES` = **3**（ハードコード）
**根拠**: trend.py:71, 99-127, 175-180
**検証**: TR::test_below_min_samples_in_one_window_marks_that_window_unavailable / ::test_insufficient_data_reports_zero_sample_counts /
::test_empty_db_yields_insufficient_data
**分類**: CORE（NP4 結論最大化）

### S1-CONC-022: TREND の confidence は標本密度で決まり 0.95 で頭打ち
**挙動**: 各窓で `n = min(current_n, previous_n)` が MIN_SAMPLES 以上なら `min(0.30, 0.15 + n × 0.01)` を加算 **MUST**。
合計を **0.95 で上限クリップ MUST**。1 窓でも判定不能があれば **0.15 減点 MUST**（下限 0.0）。小数 3 桁。
結論不可時は **0.0 MUST**。
**根拠**: trend.py:220-234
**検証**: TR::test_partial_availability_penalises_confidence / ::test_confidence_caps_at_zero_to_one / ::test_confidence_zero_when_unavailable
**分類**: CORE

### 2.5 PER_DOMAIN 結論

### S1-CONC-023: PER_DOMAIN は 3 ドメインを 1 行に詰め、既知ドメインの出典のみ載せる
**挙動**: cyber / physical / info の 3 状態を packed state `cyber=X;physical=Y;info=Z` として**1 行に格納 MUST**
（順序固定）。`metadata.domain_scores`（小数 3 桁）/ `domain_states` / `domain_source_counts` を添える **MUST**。
`source_urls` は**この 3 ドメインに属する寄与の evidence_url のみ**を集合化し昇順ソート **MUST**。
**根拠**: per_domain.py:41, 71-92, 128-132, 148-149
**検証**: PD::test_state_string_packs_all_three_domains_in_canonical_order / ::test_state_string_uses_module_domain_order /
::test_returns_single_conclusion_of_per_domain_type / ::test_metadata_records_per_domain_scores /
::test_metadata_records_source_counts_per_domain / ::test_formula_ref_is_versioned / ::test_threshold_ref_mirrors_module_constants /
::test_source_urls_deduplicated_and_sorted_across_domains / ::test_source_urls_only_count_known_domains
**分類**: CORE

### S1-CONC-024: ドメイン状態の分類は 5 値・順序依存
**挙動**: 現スコア `cur` と直近 PER_DOMAIN 行の同ドメインスコア `prior` から、**以下の順に**評価し最初に成立した
状態を採る **MUST**: (1) `cur <= 0` → **INSUFFICIENT_SIGNAL**（負値も同扱い **MUST**）/ (2) `cur >= 2.5` → **ACTIVE** /
(3) `prior` が存在し `prior − cur >= 1.0` → **DEGRADING** / (4) `cur >= 1.5` → **ELEVATED** / (5) それ以外 → **STABLE**。
境界値は**当該状態に含める（`>=`）MUST**。直近行が無ければ DEGRADING は起こらない **MUST**。
**閾値**: `ACTIVE_FLOOR` = **2.5** / `ELEVATED_FLOOR` = **1.5** / `DEGRADE_DELTA` = **1.0**
（ハードコード。2026-04-26 Phase 1.3 の実分布較正値）
**根拠**: per_domain.py:51-53, 136-145
**検証**: PD::test_active_state_at_or_above_active_floor / ::test_elevated_state_between_floors / ::test_stable_state_below_elevated_with_signal /
::test_insufficient_signal_when_score_zero / ::test_negative_score_treated_as_insufficient_signal / ::test_active_floor_boundary_inclusive /
::test_elevated_floor_boundary_inclusive / ::test_degrading_when_drop_at_or_above_degrade_delta / ::test_no_degrading_when_drop_below_threshold /
::test_active_overrides_degrading / ::test_no_prior_row_yields_no_degrading / ::test_round_trip_via_save_then_latest_for_degrading
（**すべて定数相対** — §7 GAP-02）
**分類**: CORE。**DEGRADING が ELEVATED より優先される順序は ACCIDENTAL**（§5-A6）

### S1-CONC-025: 1 ドメインでも信号があれば結論を出し、confidence は広がりと大きさの等分合成
**挙動**: 3 ドメインすべてが INSUFFICIENT_SIGNAL のときのみ `insufficient_data` **MUST**（1 ドメインでも信号が
あれば結論を出す — NP1）。`confidence = 0.5 × (信号のあるドメイン数 / 3) + 0.5 × min(1.0, ドメインスコア合計 / 12.0)`
を小数 3 桁に丸める **MUST**。
**閾値**: magnitude 分母 **12.0**
**根拠**: per_domain.py:83-84, 94-115, 165-173
**検証**: PD::test_all_domains_silent_yields_insufficient_data / ::test_confidence_zero_when_all_domains_silent /
::test_confidence_combines_breadth_and_magnitude / ::test_confidence_caps_magnitude_at_one / ::test_confidence_max_when_all_three_active
**分類**: CORE

### 2.6 ANOMALY 結論

### S1-CONC-026: ANOMALY は 1 ティックに複数行、重要度上位 N 件、皆無なら単一の結論不可行
**挙動**: ANOMALY は他 4 型と異なり**1 ティックで複数行を生成 MUST**。重要度降順にソートし**上位 `limit` 件
（既定 10）だけ返す MUST**。寄与が 0 件、または全寄与の raw_score が非正なら**単一の `insufficient_data` 行を
返す MUST**（空リストを返してはならない — 慢性検知の観測列が切れる）。
**閾値**: `DEFAULT_LIMIT` = **10**（`?limit=` で調整可）
**根拠**: anomaly.py:64, 186-187, 242-246
**検証**: AN::test_returns_list_of_anomaly_conclusions / ::test_top_n_limit_truncates / ::test_default_limit_is_documented_constant /
::test_results_sorted_by_importance_descending / ::test_no_contributions_yields_single_insufficient_data / ::test_zero_raw_score_contributions_filtered
**分類**: CORE（NP5+8）

### S1-CONC-027: 重要度は 4 因子の積 × 100、全因子を開示する
**挙動**: `importance = raw_score × recency_decay × scenario_relevance × novelty_factor × 100`、**[0, 100] に
クランプ MUST**。`confidence = importance / 100`（小数 3 桁）**MUST**。`raw_score <= 0` の寄与は**除外 MUST**。
4 因子と elapsed_hours を**すべて metadata に個別開示 MUST**（NP6）。各因子:
- `recency_decay = exp(−elapsed_hours / 12.0)` **MUST**。elapsed は 0 で下限クリップ **MUST**（未来時刻の信号は
  減衰なし）。elapsed=12h → 1/e ≈ 0.368、実半減期は 12·ln2 ≈ 8.32h
- `scenario_relevance = llm_country_weight × participant_weight` **MUST**。ただし寄与国が `GLOBAL` の場合は
  **participant_weight のみ MUST**（global_signal_weight は既に participant_weight に吸収済で二重計上になる）

**閾値**: 上限 **100.0**、経年時定数 **12.0 時間**（ハードコード）
**根拠**: anomaly.py:66, 73-93, 204-238
**検証**: AN::test_metadata_captures_every_formula_component / ::test_importance_clamped_to_unit_confidence /
::test_older_signal_has_lower_importance / ::test_threshold_ref_constants_match_implementation / ::test_formula_ref_is_stable_constant /
::test_recency_decay_at_one_time_constant / ::test_recency_decay_at_actual_half_life / ::test_recency_decay_at_zero_elapsed_is_one /
::test_global_contribution_relevance_uses_participant_weight_only / ::test_per_country_relevance_multiplies_llm_cw_and_participant_weight
**分類**: CORE。**設計文書が 12h を "half-life" と誤記していた点は ACCIDENTAL**（§5-A7）

### S1-CONC-028: 新規性は同一 signal_source の直近 24h 出現数で減衰し、読み失敗は必ず標識を残す
**挙動**: `novelty = clamp(1.0 − similar_count / 10, 0.3, 1.0)` **MUST**。`similar_count` は**同一シナリオかつ同一
signal_source** の ANOMALY 台帳行を直近 24h で数えた値 **MUST**。シナリオ間・signal_source 間で**混線しては
ならない MUST**。台帳読み出しに失敗した場合は **count=0（novelty=1.0）にフォールバック MUST**（NP1: 履歴欠落で
重要度を下げない）。フォールバック経路は `metadata.novelty_source` に `"ledger_24h_fallback_empty"` として
**明示 MUST**（正常時は `"ledger_24h"`）。
**閾値**: 窓母数 **10**、下限 **0.3**、lookback **86400s**
**根拠**: anomaly.py:67-69, 78-80, 138-163
**検証**: AN::test_novelty_factor_drops_for_repeated_signal_source / ::test_novelty_factor_one_for_singleton_source /
::test_novelty_drops_across_ticks_after_save / ::test_novelty_lookback_window_excludes_older_rows / ::test_novelty_isolated_per_scenario /
::test_novelty_isolated_per_signal_source / ::test_novelty_falls_back_when_ledger_query_fails
**分類**: CORE。**change gate との相互作用（台帳行減 → novelty 上振れ）は ACCIDENTAL**（§5-A8）

### S1-CONC-029: ANOMALY の state は統制語彙 (signal_source) に限る
**挙動**: `state` は **signal_source のみ MUST**。自由記述の要約文字列を state に入れてはならない（行ごとに一意な
state になり「同種異常の集計」が不可能になる）。自由記述の値表現は `metadata.value_display` に置く **MUST**。
各行の `source_urls` は**その信号自身の evidence_url のみ MUST**。各行に calibration_status を**添える MUST**。
**根拠**: anomaly.py:96-112, 218-236
**検証**: AN::test_state_summary_uses_signal_source_with_value_in_metadata / ::test_state_summary_falls_back_to_signal_source_when_no_value /
::test_source_urls_emitted_when_evidence_present / ::test_source_urls_empty_when_no_evidence / ::test_calibration_status_attached_to_each_row
**分類**: CORE（NP6: 結論履歴の集計可能性）。**設計文書 §6.4 は旧仕様のまま**（§5-A9）

### 2.7 ATTACK_MODE 結論

### S1-CONC-030: 攻撃モードは複数同時発火し、最上位を state に、全件を metadata に置く
**挙動**: 規則は排他ではない **MUST**。発火した全モードを confidence **降順**にソートし、先頭を `state`、全件を
`metadata.ranked_modes`（`{mode, confidence, rule}`）に格納 **MUST**。各エントリは**発火した規則を平文で説明する
`rule` 文字列を持つ MUST**（NP6）。`metadata.domain_scores`（小数 3 桁）と `active_countries_n` を添える **MUST**。
最上位の confidence が **0.6 未満なら `metadata.is_tentative = true` MUST**。
**閾値**: is_tentative 閾値 **0.6**
**根拠**: attack_mode.py:72-78, 116-137
**検証**: AM::test_multi_mode_records_top_in_state_and_full_ranked_list / ::test_each_ranked_entry_carries_rule_string /
::test_metadata_carries_active_country_count / ::test_metadata_domain_scores_rounded / ::test_tentative_flag_set_when_confidence_low /
::test_returns_single_conclusion_of_type_attack_mode / ::test_formula_ref_is_stable_constant / ::test_threshold_ref_exposes_every_floor
**分類**: CORE

### S1-CONC-031: 4 つの基本モードの発火規則
**挙動**: 現ティックのドメインスコア (cyber / physical / info) と active_countries 数 n に対し、以下を**独立に**
評価 **MUST**（境界値は発火側 = `>=`）。confidence は小数 3 桁に丸める **MUST**。

| モード | 発火条件 | confidence |
|---|---|---|
| `DDOS_PRECURSOR` | `cyber >= 1.2` ∧ `info >= 0.8` | `min(0.95, 0.55 + 0.4·min(1, (cyber−1.2)/1.2))` |
| `KINETIC_PREPARATION` | `physical >= 1.0` | `min(0.95, 0.55 + 0.4·min(1, (physical−1.0)/1.0))` |
| `HYBRID_PRESSURE` | `cyber >= 0.8` ∧ `physical >= 0.8` ∧ `info >= 0.8` ∧ `n >= 4` | `min(0.95, 0.50 + 0.05n + 0.02·Σdomain)` |
| `INFO_OPS_DOMINANT` | `info >= 0.8` ∧ `max(cyber,physical) > 0` ∧ `info/max(cyber,physical) >= 1.5` | `min(0.95, 0.55 + 0.10·info/max(other, 0.1))` |
| `INFO_OPS_DOMINANT`（純 info） | `info >= 0.8` ∧ `cyber == 0` ∧ `physical == 0` | **固定 0.65** |

**閾値**: `CYBER_DDOS_FLOOR`=**1.2** / `INFO_NARRATIVE_FLOOR`=**0.8** / `PHYSICAL_KINETIC_FLOOR`=**1.0** /
`ALL_DOMAIN_HYBRID_FLOOR`=**0.8** / `HYBRID_INTEL_CLUSTER_MIN`=**4** / `INFO_DOMINANCE_RATIO`=**1.5**
（すべてハードコード。2026-05-10 の実分布再較正値）
**根拠**: attack_mode.py:50-56, 140-184
**検証**: AM::test_ddos_precursor_fires_at_floors / ::test_ddos_precursor_blocks_below_cyber_floor / ::test_ddos_precursor_blocks_below_info_floor /
::test_kinetic_preparation_fires_at_floor / ::test_kinetic_preparation_blocks_below_floor / ::test_hybrid_pressure_requires_all_three_domains_and_cluster /
::test_hybrid_pressure_blocks_when_cluster_too_small / ::test_hybrid_pressure_blocks_when_one_domain_silent / ::test_info_dominance_fires_with_ratio /
::test_info_only_signal_mix_classifies_info_ops / ::test_info_below_floor_does_not_dominate / ::test_confidence_clamped_below_unit
（**すべて定数相対。数値そのものは未 pin** — §7 GAP-01）
**分類**: CORE。**設計文書 §6.5 が再較正前の値のままである点は ACCIDENTAL**（§5-A10）

### S1-CONC-032: どの規則も発火しなければ結論不可 — 「攻撃なし」ではない
**挙動**: マッチ 0 件は `insufficient_data` **MUST**。`metadata.reason_detail` に「規則が現信号構成に一致しなかった」
旨を記す **MUST**。`domain_scores` と `active_countries_n` は**結論不可行にも添える MUST**。
**根拠**: attack_mode.py:93-114
**検証**: AM::test_no_signals_yields_insufficient_data / ::test_below_all_floors_yields_insufficient_data / ::test_insufficient_metadata_carries_domain_scores
**分類**: CORE（NP5+8 の中核: 否定を証明しない）

### S1-CONC-033: シナリオ固有拡張モードは宣言的設定のみで定義される
**挙動**: シナリオ固有の攻撃モードは**設定データ（シナリオプリセット）で宣言 MUST**であり、コード内のシナリオ別
分岐で実装してはならない **MUST**。拡張 1 件は `mode` / `domain_floors`（全ドメインが下限以上）/ `active_n_min` /
`requires_participant`（指定 ISO2 が active_countries に全て含まれること、大小文字非依存）/ `base_confidence` /
`rule_summary` を持ち、**全条件 AND で発火 MUST**。拡張は基本モードを**置換せず追加 MUST**（合算後に confidence
降順で再ソート）。基本規則も拡張も発火しなければ**結論不可のまま MUST**（拡張で結論不可を無理に結論化しない）。
**根拠**: attack_mode_extensions.py:106-227、attack_mode.py:71-77, 93-114
**検証**: AX::test_extension_fires_when_all_floors_and_countries_match / ::test_extension_does_not_fire_when_required_country_absent /
::test_extension_does_not_fire_when_one_floor_unmet / ::test_extension_does_not_fire_when_active_n_below_min /
::test_extension_appears_in_ranked_modes_metadata / ::test_extension_can_become_top_mode_when_confidence_dominates /
::test_no_extensions_means_pure_base_behavior / ::test_extension_does_not_rescue_insufficient_signal_when_base_is_empty /
::test_extension_match_dataclass_is_immutable / ::test_live_* 5 件（実設定の 5 シナリオを parametrize）
**分類**: CORE（ADR-V2-002）

### S1-CONC-034: 拡張の confidence は保守帯にクランプし、不正宣言は黙って捨てる
**挙動**: 拡張の confidence は `clamp(base_confidence, 0.55, 0.85) + 0.30 × min(1, max(margin))` を**0.95 で上限
クリップ MUST**（margin = 各 domain_floor に対する相対超過。floor が 0 なら除外）。以下は**黙って捨てる MUST**
（設定不備でツールを止めない — NP3）: mode が非文字列 / 空 / 基本 5 モード名と衝突（警告ログのみ）、辞書でない
エントリ、同一 mode の重複宣言（**最初の宣言が勝つ MUST**）、拡張ブロックが配列でない、設定が読めない。
**閾値**: 下限 0.55 / base 上限 0.85 / 全体上限 0.95 / 既定 base 0.60 / margin 係数 0.30
**根拠**: attack_mode_extensions.py:62-64, 125-188, 191-227
**検証**: AX::test_confidence_floor_and_ceiling_applied / ::test_strong_margin_increases_confidence_but_caps_at_0_95 /
::test_zero_margin_returns_base_confidence / ::test_extension_without_mode_is_silently_dropped / ::test_extension_using_reserved_base_mode_is_dropped /
::test_duplicate_mode_only_first_wins / ::test_non_dict_extension_entries_ignored / ::test_returns_empty_when_* 4 件
**分類**: CORE

### S1-CONC-035: LLM 補強は規則結論を上書きしない
**挙動**: LLM 補強が有効な場合でも以下 **MUST**:
1. **`state`（最上位モード）は規則の値を保持 MUST**。LLM の異議は `metadata.llm_augmentation.suggested_alternative_mode` に記録
2. confidence の調整は **±0.10 を上限**とし [0.0, 1.0] にクランプ **MUST**
3. 規則が結論不可なら **LLM を呼ばずそのまま返す MUST**（LLM にモードを発明させない — NP1）
4. LLM 不達 / パース失敗時は**規則結論をそのまま返す MUST**。ただし `metadata.llm_augmentation =
   {attempted: true, ok: false, error: ...}` を付す **MUST**（NP3）
5. 成功時は `llm_prompt_sha256` を**刻印 MUST**（NP6）。プロンプトは決定論的に組み立て、同一状態が同一 sha256 に落ちる
6. LLM 出力の値域強制: `agreement` は 5 値以外なら `"unknown"`、`suggested_alternative_mode` は既知 5 モード以外なら
   null、`narrative` は 240 文字、`key_evidence` は **4 件 × 各 120 文字**で切り詰め **MUST**

**閾値**: `V2_ATTACK_MODE_LLM_AUGMENT_ENABLED` 既定 **False**、nudge 上限 **±0.10**、narrative 240 字、
evidence 4 件 × 120 字、temperature 0.1、max_tokens 384
**根拠**: attack_mode_llm.py:44-57, 103-206、config.py:276-278
**検証**: AL::全件（14）
**分類**: CORE（NP1 + NP3 + NP6 の三点同時充足）

### 2.8 calibration_status（結論への較正状態付記）

### S1-CONC-036: 全結論に較正スナップショットを添え、出典は ground-truth 混同行列に限る
**挙動**: 結論には、それを生んだ系の較正状態を `calibration_status` として添える **MUST**。内容は `source` /
`status` / `recall` / `precision` / `tp` / `fp` / `tn` / `fn` / `sample_n` / `window_days` / `last_label_at`。
**headline は recall（NP1: 感度）MUST**。出典は **ground-truth 混同行列（analyst_feedback ⋈ conclusions）MUST**
であり、lite/full スコア差分のような**自己参照的な指標を使ってはならない MUST**（そうした指標はスコア経路統合後に
恒等的に 0 となり、360k 件の結論すべてで「異常なし」を報告した実績がある）。
**根拠**: calibration.py:27-51, 135-191
**検証**: TL::test_calibration_status_is_attached；AN::test_calibration_status_attached_to_each_row
**分類**: CORE（NP5+8）

### S1-CONC-037: 較正状態は 3 値、判定は recall の分母で決まる
**挙動**: `recall = tp/(tp+fn)`、`precision = tp/(tp+fp)`（分母 0 なら null）**MUST**。状態は観測陽性数 `tp+fn < 5`
または recall が null → **INSUFFICIENT_DATA**、`recall < 0.70` → **DEGRADED**、それ以外 → **OK** **MUST**。
**precision は報告するが状態判定に用いない MUST**。TRUE_NEGATIVE だけが蓄積しても INSUFFICIENT_DATA のまま **MUST**
（recall は陽性がなければ定義できない）。同一 (conclusion_id, analyst_id) に複数ラベルがあれば**最新 1 件のみ集計 MUST**。
**閾値**: 最小陽性標本 **5**、recall 下限 **0.70**、窓 `CALIBRATION_WINDOW_DAYS` 既定 **30 日**
**根拠**: calibration.py:69-74, 143-170, 194-207
**検証**: CAL::test_insufficient_data_when_no_labels / ::test_insufficient_data_when_too_few_positives / ::test_ok_when_recall_holds /
::test_degraded_when_recall_below_floor / ::test_precision_reported_but_does_not_drive_status / ::test_true_negatives_alone_stay_insufficient
（dedup 規則は未検証 — §7 GAP-06）
**分類**: CORE

### S1-CONC-038: 較正の読み出しは決してスコアリングを壊さない
**挙動**: 較正スナップショットの取得は**読み取り専用 MUST**、失敗時は **INSUFFICIENT_DATA の封筒を返し例外を
伝播させない MUST**（NP3）。結果はシナリオ単位で **300 秒メモ化 MUST**、新ラベル投入後は明示的に無効化できる **MUST**。
**閾値**: キャッシュ TTL **300s**
**根拠**: calibration.py:76, 98-132
**検証**: CAL::test_never_raises_on_bad_db / ::test_cache_returns_same_until_invalidated
**分類**: CORE

### 2.9 台帳への書込と結論不可の継続性

### S1-CONC-039: 台帳は append-only
**挙動**: 結論台帳は追記のみ **MUST**。既存行の UPDATE / DELETE を行ってはならない **MUST**（retention による
一括削除を除く）。訂正は新しい ID の行を追記して行う。
**根拠**: persistence.py:1-11, 29-55
**検証**: PER::（round-trip 群）
**分類**: CORE（ADR-V2-008 / AP4 の前提）

### S1-CONC-040: 単一値型の書込は「変化 + heartbeat」でゲートする
**挙動**: 単一値型（threat_level / trend / per_domain / attack_mode）は、**同一 (scenario, type) の最新行と比較して**
`state` と `conclusion_unavailable_reason` がともに等しく、かつ経過時間が heartbeat 周期未満なら**書込を省略 MUST**。
比較対象は**型の最新行であって「同じ state の最新行」ではない MUST**（A→B→A のフラップで 3 行書かれないと、
任意時点の再構成が B のまま固まる）。ゲート無効時は毎ティック書く **MUST**。
**閾値**: `V2_CONCLUSION_WRITE_ON_CHANGE` 既定 **True**、`V2_CONCLUSION_HEARTBEAT_SEC` 既定 **3600**
**根拠**: persistence.py:84-110、config.py:264-269
**検証**: GATE::TestSingleValuedGate::test_unchanged_state_is_deduplicated / ::test_state_change_writes_immediately /
::test_flap_writes_every_transition / ::test_heartbeat_forces_periodic_write / ::test_gate_off_writes_every_tick
**分類**: CORE

### S1-CONC-041: 複数行型は「集合シグネチャ」でゲートする
**挙動**: ANOMALY は 1 ティック分の**集合シグネチャ**で比較 **MUST**。単位は (state, unavailable_reason,
signal_source|sensor, contributing_country, domain)。**同一シグネチャの重複件数（多重度）はシグネチャに含めない MUST**
（件数はインテル項目の出入りで毎ティック揺れるため、含めるとゲートが機能しない）。比較対象の「前バッチ」は
**最新観測時刻から 5 秒以内の行の集合 MUST**（1 ティック内の各行は個別に時刻を採るためマイクロ秒単位でずれる）。
集合が変化したら**バッチ全体を書き直す MUST**（部分書込は任意時点の集合再構成を壊す）。空バッチは何もしない **MUST**。
**閾値**: バッチ窓 **5.0s**
**根拠**: persistence.py:113-204
**検証**: GATE::TestBatchGate::（3 件）/ ::TestBatchGateTimestampJitter::test_batch_rows_with_jittered_timestamps_still_dedup /
::TestBatchGateIdentitySet::（2 件）
**分類**: CORE

### S1-CONC-042: 継続性の記録はゲートに関わらず毎ティック行う
**挙動**: 書込が間引かれたティックでも、**結論不可の継続性記録は必ず行う MUST**。慢性結論不可の検知には間引き前の
観測列が要る。
**根拠**: persistence.py:78-81, 106-108, 198-201
**検証**: GATE::TestSingleValuedGate::test_deduplicated_tick_still_feeds_continuity
**分類**: CORE（NP5+8 と AP4 の両立点）

### S1-CONC-043: 継続性台帳は遷移だけを記録する
**挙動**: (scenario, type) ごとに以下 **MUST**: 結論不可 ∧ 直近行が無い/解消済 → **新しい run を開く**
（run_length=0、first_seen=現時刻）/ 結論不可 ∧ 直近行が未解消 → **run を延長**（run_length = 現時刻 − first_seen）/
available ∧ 直近行が未解消 → **run を閉じる**（is_available=1、reason=`resolved`）/ available ∧ 直近行が無い or
既に解消済 → **何も書かない MUST**（定常状態は記録しない）。判定は「`conclusion_unavailable_reason` が非 None、
**または** state が文字列 `"INSUFFICIENT_DATA"`」。書込失敗は**握り潰す MUST**（NP3）。
**根拠**: persistence.py:207-293
**検証**: PER::TestContinuityLog::test_unavailable_conclusion_opens_run / ::test_consecutive_unavailable_extends_run_length /
::test_available_after_unavailable_closes_run / ::test_steady_state_available_writes_nothing
**分類**: CORE。**state 文字列による二重判定は ACCIDENTAL**（§5-A11）

### S1-CONC-044: 慢性結論不可は 2 基準の論理和で判定する — NP5+8 の設計失敗検知
**挙動**: (scenario, type) が慢性結論不可であることは、以下**いずれか**で判定 **MUST**:
1. **連続日数基準**: 現在 open な run の経過日数 `(now − first_seen_at)/86400` が閾値以上
2. **デューティ比基準**: 直近 W 日の窓で、結論不可であった**時間の総和 / 窓幅**が閾値以上

デューティ比基準は、run が短時間で閉じる**フラッピング**を連続日数基準が取りこぼすために要る（実測: attack_mode が
2 か月間ティックの 20-30% を結論不可で過ごしながら慢性件数 0 だった）。デューティ比は**閉じた run と現在 open な
run の合計時間**を積算し、窓境界で**クランプ MUST**、1.0 で上限クリップ **MUST**。
**閾値**: 連続日数 `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS` 既定 **7.0**（**下限 3.0 を下回れない MUST**、DB override 可）、
デューティ窓 既定 **14.0 日**（下限 7.0）、デューティ閾値 既定 **0.20**（下限 0.05、上限 1.0）
**根拠**: inconclusive_continuity.py:56-68, 95-150, 165-264
**検証**: IC::TestComputeStates::（7 件）/ ::TestDutyCycleStates::（4 件）
**分類**: CORE（ADR-V2-010 + 2026-07-04 拡張）。**デューティ側パラメータが registry 未登録で運用者が調整できない点は
DEFECT-PRESERVE**（§6 DP3）

### S1-CONC-045: 慢性スナップショットは 2 基準を重複なくマージし、個別行は滞留を自己申告する
**挙動**: 慢性スナップショットは `chronic` / `transient` / `duty` / `summary` を返す **MUST**。デューティ基準で慢性と
なった対は、**連続日数基準で計上済なら重複追加しない MUST**。各エントリは**どちらの基準か `criterion` で明示 MUST**。
並び順は慢性優先・滞留の長い順 **MUST**。DB エラー時は**空の慢性リストと error を返す MUST**（例外を投げない — NP3）。
加えて ATTACK_MODE の結論不可行には現 open run の長さから `metadata.null_run_minutes`（分、小数 1 桁）と
`metadata.null_severity`（`>= 7 日` → chronic / `>= 24 時間` → extended / 未満 → transient）を**付与 MUST**。
この付与は**失敗しても保存を妨げてはならない MUST**。
**閾値**: null_severity 段階 **7 日 / 24 時間**（ハードコード）
**根拠**: inconclusive_continuity.py:267-297, 300-376、scoring.py:1341-1360
**検証**: IC::TestChronicSnapshot::（2 件）/ ::TestChronicSnapshotDutyMerge::（2 件）
（null_run_minutes 付与は未検証 — §7 GAP-05）
**分類**: CORE（AP3）

### S1-CONC-046: 台帳は保持期間で刈られ、プロンプトは結論より長く残る
**挙動**: 結論台帳は既定 **90 日**で刈る **MUST**。LLM プロンプト台帳は**「結論保持期間 + 30 日」を下限として刈る MUST**
（生存中の結論が `llm_prompt_sha256` を必ず解決できること — NP6）。
**閾値**: `CONCLUSIONS_RETENTION_DAYS` 既定 **90**、`LLM_PROMPTS_RETENTION_DAYS` 既定 **120**
（実効値 = `max(設定値, 結論保持日数 + 30)`）
**根拠**: database.py:5443-5465
**検証**: 未検証（§7 GAP-03）
**分類**: CORE

### 2.10 replay と self_eval（AP4 / AP3）

### S1-CONC-047: replay は台帳の時間旅行であり、物語の再生成ではない
**挙動**: 指定時刻 `at` に対し、各結論型について **`observed_at <= at` を満たす最新行**を返す **MUST**。`at` 省略時は
現在時刻、不正な `at` は **400 MUST**。返す行は**実際に永続化された台帳行 MUST**（再導出・再生成してはならない）。
JSON 文字列で格納された metadata / threshold_ref / calibration_status / source_urls は**通常の結論取得と同一の形に
再水和 MUST**（フロントが分岐しないため）。応答は `api_version` / `scenario_id` / `replay_at` / `conclusions` /
disclaimer。**アナリスト権限を要求 MUST**。
**根拠**: routes/conclusions_v2.py:468-541
**検証**: GATE 群が「latest-row-at-T の意味論」を間接保証（S1-CONC-040/041）。**endpoint 自体は未検証**（§7 GAP-04）
**分類**: CORE（AP4）

### S1-CONC-048: self_eval は信頼メトリクスを独立に算出し、決して失敗しない
**挙動**: 自己評価は以下を返す **MUST**。**各メトリクスは独立に失敗し得る MUST**（1 つの失敗が他を巻き込まない）。
失敗したメトリクスは **null + `<name>_error` で理由を開示 MUST**。応答全体が 5xx になってはならない **MUST**。
アナリスト権限を要求 **MUST**。

| メトリクス | 定義 |
|---|---|
| `recall` | **CI ゲートと同一の集計経路 MUST**（チップとゲートが別の数字を出すことを構造的に禁止）。窓は per-conclusion 較正 (037) と**同一日数 MUST**。`ΣTP / (ΣTP + ΣFN)`、分母 0 なら null。`recall_meta` に**窓日数・総/人手/自動ラベル数を開示 MUST**（人手 0 = 完全な自己採点を検知できること） |
| `null_zone_days` | 直近 30 日を日付でバケット化し、**当日から遡って「観測はあるが available が 0 件」の連続日数** **MUST**。available が 1 件でもある日、または観測 0 件の日で**打ち切る MUST** |
| `drift` | `mean(1 − recall)` を**較正状態が INSUFFICIENT_DATA でなく recall が非 null のシナリオについてのみ**平均 **MUST**。対象 0 件なら **null + 理由 MUST**（0.0 は「異常なし」に見えるため禁止）。`drift_meta` に手法名・対象数・最悪シナリオ・窓日数を開示 **MUST** |
| `tl_distribution_skew` | 転がし窓の **TL5（平時）出現割合**が下限を下回り、かつ観測数が最小値以上なら警報 **MUST**（観測数不足なら**警報を出さない MUST**）。drift では検知できない「TL5 が 0% に落ちる」型の劣化を捉える |

**閾値**: null-zone 走査 **30 日**、`CALIBRATION_SKEW_TL5_MIN_PCT` / `CALIBRATION_SKEW_WINDOW_DAYS` /
`CALIBRATION_SKEW_MIN_OBSERVATIONS` / `CALIBRATION_SKEW_METRIC_ENABLED`
**根拠**: routes/conclusions_v2.py:544-851
**検証**: SE::test_self_eval_drift_null_when_no_calibration_data / ::test_self_eval_drift_mean_miss_rate /
::test_self_eval_drift_skips_insufficient_scenarios / ::test_self_eval_drift_handles_db_error /
::test_self_eval_recall_uses_calibration_window_and_reports_breakdown（null_zone / skew は未検証 — §7 GAP-06）
**分類**: CORE（AP3 + NP3 + D2 D-01 への構造的対抗）

### 2.11 Markdown エクスポート

### S1-CONC-049: エクスポートは 1 シナリオの最新結論を、導出鎖ごと 1 ファイルにまとめる
**挙動**: 5 型それぞれの最新行を集め、**単一の Markdown 文書**として返す **MUST**。
文書レベルで**必ず含む MUST**: シナリオ名（無ければ ID）/ シナリオ ID / 生成時刻（UTC, ISO8601 秒精度）/
API バージョン / **NP7 disclaimer（先頭に 1 回のみ、引用ブロック）**。結論が 1 件も無ければ**プレースホルダ文を
出す MUST**（空文書にしない）。出力は**末尾改行 1 個で終わる MUST**。
節レベルで**必ず含む MUST**: 型見出し / **状態**（結論不可なら「結論不可」と理由コード）/ 確信度（小数 2 桁）/
観測時刻 / 結論 ID / 導出式参照 / **閾値（JSON）**。source_urls / calibration_status / metadata は**存在するときのみ
節を出す MUST**（空節を作らない）。JSON は**キー昇順で整形 MUST**。監査トレースが渡され、かつプロンプトが欠落でない
場合は **LLM プロンプト全文を折りたたみ節で埋め込む MUST**（sha256 / model / temperature 付き）。トレースが無い、
または欠落マーク付きなら**出さない MUST**。
**根拠**: markdown.py:54-165
**検証**: MD::全件（21）；API::test_md_export_returns_markdown_content_type / ::test_md_export_renders_each_saved_conclusion /
::test_md_export_returns_placeholder_for_empty_scenario / ::test_md_export_includes_audit_trace_when_requested /
::test_md_export_omits_audit_trace_by_default
**分類**: CORE（NP6 の可搬形）

### 2.12 アナリスト feedback 台帳

### S1-CONC-050: ラベルは 4 値の混同行列で追記のみ、analyst_id と時刻はサーバが決める
**挙動**: ラベルは `TRUE_POSITIVE` / `FALSE_POSITIVE` / `TRUE_NEGATIVE` / `FALSE_NEGATIVE` の 4 値のみ **MUST**。
**永続層でも 4 値制約を強制 MUST**（アプリ層の検証だけに頼らない）。訂正は**新しい行の追記 MUST**。API 境界で未知の
ラベル文字列は **400 MUST**、存在しない結論への投稿は **404 MUST**。`analyst_id` は**認証情報から導出 MUST**、
`observed_at` は**サーバ時刻 MUST**（いずれもクライアントが詐称できてはならない）。`notes` は **2000 文字で切り詰め MUST**。
**根拠**: feedback.py:28-75, 145-153、routes/conclusions_v2.py:304-328
**検証**: FB::test_db_check_constraint_rejects_unknown_label / ::test_post_returns_400_for_unknown_label / ::test_post_returns_400_for_missing_label /
::test_save_then_list_returns_newest_first / ::test_post_creates_row_with_server_derived_analyst_id / ::test_post_returns_404_for_unknown_conclusion /
::test_post_truncates_overlong_notes
**分類**: CORE（ADR-V2-011）

### S1-CONC-051: 集計は「単一の評決」ではなく「誰が何と言ったか」を返す
**挙動**: 結論単位の集計は **4 ラベルすべてのカウント（0 を含む）と延べ数と相異なるアナリスト数**を返す **MUST**。
単一の合成評決を返してはならない **MUST**（アナリストバイアス緩和）。ラベルが 1 件も無い結論でも **404 ではなく
ゼロ集計を返す MUST**。一覧は新しい順、既定 50 件・上限 1000 件 **MUST**。
**根拠**: feedback.py:84-130、routes/conclusions_v2.py:387-425
**検証**: FB::test_summarize_returns_zero_counts_for_empty_conclusion / ::test_summarize_counts_distinct_analysts_separately_from_total /
::test_get_returns_summary_and_items / ::test_get_empty_returns_zero_summary_not_404 / ::test_get_returns_404_for_unknown_conclusion
**分類**: CORE

### S1-CONC-052: 横断集計は人手ラベルと自動ラベルを分離できる
**挙動**: 結論横断の集計は**アナリスト種別（人手 / 自動）で絞り込める MUST**。自動ラベルは analyst_id が `auto:`
接頭辞を持つもの **MUST**。返す内容は窓時間 / 総数 / 人手数 / 自動数 / 相異なるアナリスト数 / ラベル別内訳 /
**結論型別内訳** / recall / precision（分母 0 なら null）**MUST**。
**閾値**: 既定窓 **720 時間**（最大 1 年）、行上限 **2000**
**根拠**: feedback.py:165-300
**検証**: FB2::全件（13）
**分類**: CORE（AP3: recall が自己採点だけになっていないかを見える化する）

### S1-CONC-053: 人手が確認した実事象は独立の ground-truth 台帳にも記録する
**挙動**: **人手**（自動でない）ラベルが `TRUE_POSITIVE` または `FALSE_NEGATIVE` で、**かつ根拠 URL が付いている**
場合のみ、実事象を独立台帳に記録 **MUST**。`FALSE_NEGATIVE`（ツールは平穏と判断したが実際は起きた）は
**TL3 相当の下限**で記録し分類名に「見逃し」を明示 **MUST**（ツールの平穏判定を実事象の記述として使わない）。
`TRUE_POSITIVE` はツールの TL をそのまま記録。書込失敗は**握り潰す MUST**。
**根拠**: routes/conclusions_v2.py:331-376
**検証**: HA::TestConfirmedThreatsRevival::（3 件）
**分類**: CORE

### 2.13 週次人間アンカーキュー

### S1-CONC-054: 人手ラベルの独立性が calibration の唯一の構造的担保である
**挙動**: ツールは毎週、**人手ラベルの価値が最も高い結論**を短いキューとして提案 **MUST**。選定は 3 種を
**優先順に**充填 **MUST**: (1) `auto_fn_review` — 自動ラベラーが当週 FALSE_NEGATIVE と判定した結論（NP1 最重要
クラスであり、かつ過去に分類器が正反対に誤った箇所）/ (2) `peak_severity` — 当週のシナリオごとの**最深刻**な
TL 判定（severity 最大。**生 TL 比較禁止**）/ (3) `calm_anchor` — 誤検知判定地平が完全に経過した平穏側判定 (TL4/TL5)。
**人手ラベルが 1 件でも付いた結論はキューから外す MUST**。同一シナリオからは各種別 1 件 **MUST**、同一結論の重複投入
禁止 **MUST**、`limit` 到達で打ち切り **MUST**。DB エラー時は**空リスト MUST**。選定理由は**決定論的テンプレート MUST**
（LLM 不使用 — AP2）。
**閾値**: 既定キュー長 **5**、既定窓 **7 日**（endpoint では窓 1-30 日・件数 1-20）、
`GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS` 既定 **7**
**根拠**: human_anchor.py:19-35, 200-362
**検証**: HA::TestSelection::test_auto_fn_review_candidate_surfaces / ::test_human_answered_conclusion_leaves_queue /
::test_peak_severity_picks_most_severe_call / ::test_calm_anchor_requires_elapsed_horizon / ::test_limit_respected_and_fn_prioritized；
::TestQueueEndpoint::（2 件）
**分類**: CORE（D2 D-01「測定系のバグ」への唯一の構造的対抗策）

### S1-CONC-055: アナリストには自然言語の 1 問だけを問い、ラベルはツールが導出する
**挙動**: アナリストに **TP/FP/TN/FN を選ばせてはならない MUST**。問うのは「この時点から約 N 日以内に、
〈シナリオ固有の事象〉は実際に起きましたか?」の 1 問 **MUST**。ツール自身の立場（alert / calm）から混同行列の
セルを**サーバ側で導出 MUST**:

| ツールの立場 | 「はい（起きた）」 | 「いいえ（平穏）」 |
|---|---|---|
| alert（severity >= 3 すなわち TL <= 3、または攻撃モード検知あり） | TRUE_POSITIVE | FALSE_POSITIVE |
| calm（それ以外） | FALSE_NEGATIVE | TRUE_NEGATIVE |

立場判定は**必ず severity 変換を経由 MUST**。問い・立場ラベル・選択肢は日本語 **MUST**。N は
`GROUND_TRUTH_WINDOW_HOURS`（既定 72h）から日数化 **MUST**。
**閾値**: alert 判定の最小 severity **3**
**根拠**: human_anchor.py:70-197
**検証**: HA::TestSelection::test_answer_model_alert_stance_maps_yes_to_true_positive / ::test_answer_model_calm_stance_maps_yes_to_false_negative /
::test_answer_model_question_names_the_scenario / ::test_answer_model_attack_mode_fired_is_alert
**分類**: CORE（AP2）

### S1-CONC-056: 外部調査リンクは調査を自動化するが判断は自動化しない
**挙動**: 各候補に**外部ニュース検索の深リンクを添える MUST**。クエリはシナリオ別検索語 + `escalation` + 前方判定窓の
日付範囲（**終端に 1 日の余裕を足す MUST**）。URL エンコード必須 **MUST**。検索エンジンは**設定可能なテンプレート MUST**
（`{query}` 置換）。**リンク先の内容をツールに取り込んではならない MUST** — アナリストの答えが独立信号であることが
このキューの存在理由そのもの（同じ公開フィードを読む自動チェックでは相関する盲点を再生産する）。
**閾値**: `HUMAN_ANCHOR_SEARCH_URL`（既定は公開ニュース検索）、日付余裕 **1 日**
**根拠**: human_anchor.py:106-130
**検証**: HA::TestSelection::test_search_url_has_terms_and_date_window / ::test_search_url_is_url_encoded / ::test_search_url_respects_config_template
**分類**: CORE

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー | DB override | 条項 |
|---|---|---|---|---|
| NP7 disclaimer 文言 | "Tool conclusion only — final judgment by organizational process." | `V2_NP7_DISCLAIMER` | 不可 | 002 |
| v2 API 有効 / 台帳書込有効 | True / False | `V2_API_ENABLED` / `V2_CONCLUSION_LEDGER_ENABLED` | 不可 | 009, 039 |
| TL confidence 分母 / lite 係数 | 12.0 / 0.6 | — | 不可 | 014 |
| TL 閾値表（公開値） | 9.0 / 3.0 / 6.0 / 2 / 4.0 / 2.0 | — | 不可 | 015（原典 S1-SCORE-004） |
| falsification 上位 N / domain_cap | 3 / 6.0 | — | 不可 | 017 |
| TREND 窓 | 24h / 7d / 30d | — | 不可 | 018 |
| TREND RISING / ESCALATE_DELTA | **0.50 / 1.50** | — | 不可 | 020 |
| TREND MIN_SAMPLES / confidence 上限・減点 | 3 / 0.95・0.15 | — | 不可 | 021, 022 |
| PER_DOMAIN ACTIVE / ELEVATED / DEGRADE | **2.5 / 1.5 / 1.0** | — | 不可 | 024 |
| PER_DOMAIN magnitude 分母 | 12.0 | — | 不可 | 025 |
| ANOMALY 既定件数 / 重要度上限 / 経年時定数 | 10 / 100.0 / 12.0h | — （`?limit=`） | 不可 | 026, 027 |
| ANOMALY novelty 母数 / 下限 / 窓 | 10 / 0.3 / 86400s | — | 不可 | 028 |
| ATTACK_MODE cyber / info / physical / hybrid floor | **1.2 / 0.8 / 1.0 / 0.8** | — | 不可 | 031 |
| ATTACK_MODE cluster_min / dominance_ratio / tentative | 4 / 1.5 / 0.6 | — | 不可 | 030, 031 |
| 拡張 confidence 帯 | [0.55, 0.85] → 上限 0.95、margin 係数 0.30 | — | 不可 | 034 |
| LLM 補強有効 / nudge 上限 | False / ±0.10 | `V2_ATTACK_MODE_LLM_AUGMENT_ENABLED` | 不可 | 035 |
| 較正窓 / 最小陽性 / DEGRADED 下限 / TTL | 30 日 / 5 / 0.70 / 300s | `CALIBRATION_WINDOW_DAYS` | 不可 | 037, 038 |
| 変化ゲート / heartbeat / バッチ窓 | True / 3600s / 5.0s | `V2_CONCLUSION_WRITE_ON_CHANGE` / `V2_CONCLUSION_HEARTBEAT_SEC` | 不可 | 040, 041 |
| 慢性連続日数閾値 | 7.0（下限 3.0） | `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS` | **可** | 044 |
| デューティ窓 / 閾値 | 14.0 日 / 0.20 | `CHRONIC_DUTY_WINDOW_DAYS` / `CHRONIC_DUTY_THRESHOLD` | **不可（registry 未登録 — §6 DP3）** | 044 |
| null_severity 段階 | 7 日 / 24 時間 | — | 不可 | 045 |
| 結論 / プロンプト台帳 保持 | 90 日 / 120 日（下限 = 結論 +30） | `CONCLUSIONS_RETENTION_DAYS` / `LLM_PROMPTS_RETENTION_DAYS` | 不可 | 046 |
| null-zone 走査範囲 | 30 日 | — | 不可 | 048 |
| feedback 既定窓 / 行上限 | 720h / 2000 | — | 不可 | 052 |
| 人間アンカー キュー長 / 窓 | 5 / 7 日 | `HUMAN_ANCHOR_QUEUE_SIZE` | 不可 | 054 |
| ground-truth 前方窓 / FP 地平 / alert 最小 severity | 72h / 7 日 / 3 | `GROUND_TRUTH_WINDOW_HOURS` / `GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS` | 不可 | 054, 055 |

**v3 への示唆**: 本領域だけで**ハードコード閾値が 30 件**あり、DB override 可能なのは 1 件のみ。NP6 は
「結論が threshold_ref で自己申告する」ところまで達成しているが、**運用者がどれを調整できるかは不透明**。
P では結論に影響する全閾値を単一の宣言的 registry に載せることを検討する（D2 A-13 と同根）。

---

## 4. 文書との乖離（実装/テストを CORE とし、文書側の訂正を要する）

| # | 文書側の記述 | 実装（CORE） | 扱い |
|---|---|---|---|
| 1 | v2-migration §6.5: ATTACK_MODE 閾値 5.0 / 1.5 / 3.0 / 1.5 | **1.2 / 0.8 / 1.0 / 0.8**（2026-05-10 再較正） | §5-A10 |
| 2 | D5 §3-7: PER_DOMAIN 閾値 3.0 / 1.5 / 1.5 | **2.5 / 1.5 / 1.0**（2026-04-26 再較正） | D5 台帳訂正要 |
| 3 | D5 §2.1: attack_mode cyber≥5.0 ∧ info≥1.5 / phys≥3.0 | 同 #1 | D5 台帳訂正要 |
| 4 | D5 §3-7: 「実値はテストのみが保持」 | テストは**定数相対**で値を pin していない | D5 台帳訂正要（GAP-01/02） |
| 5 | S1-SCORE-004: TL1 は `len(active_domains) >= 3` を要求 | **その条件は存在しない**（score≥9 ∧ physical≥3.0 の 2 条件） | §5-A4（姉妹仕様の訂正要） |
| 6 | v2-migration §6.1: threshold_ref を「動的に埋める」 | **凍結された 6 キー定数** | 軽微・文書訂正 |
| 7 | v2-migration §6.1: frequency「5 分間隔」 | 採点ティック周期 + 変化ゲート（heartbeat 3600s） | 軽微・文書訂正 |
| 8 | v2-migration §6.2: TREND 目標語彙 RAPIDLY_* 系 | ESCALATING / RISING / STABLE / COOLING / DEEPER_DECAY | §5-A5（文書側は drift として自認済） |
| 9 | v2-migration §6.2: velocity + acceleration ベース | 窓平均 severity 差分ベース | 文書側 drift 記載済 |
| 10 | v2-migration §6.3: ACTIVE は raw>5.0 ∧ signal_count≥5、DEGRADING は 30% 相対 | 絶対閾値のみ、signal_count ゲート無し | 文書側 drift 記載済 |
| 11 | v2-migration §6.4: ANOMALY state は要約文字列 | **signal_source の統制語彙**（Phase G 2026-04-30） | §5-A9 |
| 12 | v2-migration §6.5: DDOS は cyber_signal_count≥5 ∧ narrative_burst≥3 | 現ティックのドメインスコア | 文書側 drift 記載済 |
| 13 | ADR-V2-010: 慢性判定は 7 日連続のみ | **連続日数 ∨ デューティ比の 2 基準**（2026-07-04 追加） | 文書追記要 |
| 14 | inconclusive_continuity docstring: 「SETTINGS から調整可能」 | デューティ側は registry 未登録で**調整不能** | §6 DP3 |

---

## 5. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | `ConclusionUnavailableReason` 4 値のうち `calibration_pending` / `sensor_degraded` / `upstream_failure` を**生成する経路が存在しない**。全結論不可が `insufficient_data` に潰れている | NP5+8 は「なぜ結論できないか」の区別を要求している。センサー劣化と較正待ちを区別できないと、アナリストは「待てば直る」のか「壊れている」のか判断できない。v3 で 3 値を実装するか、列挙から落とすか |
| A2 | 台帳行が無いときの結論不可応答が `Conclusion` 型を経由せず dict を手組み（008）。スキーマ不変条件の検証を通らない | 「試みて失敗した」と「まだ何も無い」を型で区別する意図は理解できるが、NP7/スキーマ強制の抜け穴になっている |
| A3 | TL confidence の分母 12.0 が明示的な暫定値（isotonic 回帰は ADR-V2-010 で予定されたまま未着手） | confidence が線形写像である限り「確信度」の意味が薄い。v3 で確率的較正を入れるか、名称を変えるか |
| A4 | S1-SCORE-004 の TL1「3 ドメイン」条件が実装に無い（文書乖離 #5） | 実装が正しいのか仕様が正しいのか。**TL1 = 最も重い結論**の発火条件なので NP1 上重要 |
| A5 | TREND 語彙が設計目標（RAPIDLY_* 5 値）と別物のまま定着 | UI/通知/自己説明がすべて現語彙に依存済。目標形に戻す価値があるか |
| A6 | PER_DOMAIN の分類順序で **DEGRADING が ELEVATED より優先**。prior 4.0 → cur 2.0 は ELEVATED でなく DEGRADING | 「高いが下がっている」を DEGRADING と呼ぶのは妥当だが、絶対水準の情報が state から消える。packed state 1 本では両立できない |
| A7 | ANOMALY の 12h を設計文書が長く "half-life" と誤記（実際は 1/e 時定数、半減期 8.32h） | 実装は式どおり。呼称のみ訂正でよいか、意図が半減期 12h だったのか |
| A8 | 変化ゲート導入（2026-07-04）で ANOMALY 台帳行が激減 → novelty の `similar_count` が構造的に小さくなり **importance が上振れ**。両機能は独立に設計され相互作用が未評価 | novelty の定義を「台帳行数」から「観測ティック数」に変えるべきか。NP1 上は安全側だが順位付けの意味が変質している |
| A9 | ANOMALY state を signal_source だけにしたため、**同一 signal_source の異なる異常が state 上で区別できない**（識別情報は metadata 側） | 集計可能性（Phase G の狙い）と個別識別のトレードオフ。v3 では state を構造化値にする選択肢がある |
| A10 | ATTACK_MODE 閾値が「観測分布に合わせて下げる」方向で 2 回動き、現在 cyber 1.2 / info 0.8 は**ほぼベースライン水準**。結論不可を減らすため感度を上げた結果、DDOS_PRECURSOR が常時点灯しうる | NP5+8（恒常的結論不可＝設計失敗）と NP1 を満たす調整だが、「常に何か言う」状態は結論の情報量を下げる。**閾値を観測分布に追従させる運用自体の是非** |
| A11 | 継続性判定が理由フィールドに加えて **state 文字列 `"INSUFFICIENT_DATA"` も結論不可と見なす**。TREND の packed state は形式が異なり一致しないが、将来の型で誤判定しうる | 二重判定を残すか、理由フィールド一本にするか |
| A12 | `V2_CONTINUITY_FAILURE_SEC`（7 日）が config に定義されているが**どこからも参照されていない**デッドキー | 削除か、慢性判定への統合か |
| A13 | Markdown エクスポートが calibration_status と metadata（rationale_matrix / falsification を含む）を**生 JSON のまま**出す。アナリスト向け成果物としては読めない | NP6（全開示）優先の結果。v3 で人間可読な整形を入れるか |
| A14 | `V2_API_ENABLED` は既定 true で 13 箇所のゲートが恒常通過（D2 C-03 と同一） | v3 に持ち込まない前提だが、v1 sunset 完了の確認が要る |

---

## 6. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | TL 導出式が **3 箇所に複製**（scoring.py 本体 / threat_level.py の THRESHOLD_REF / sensitivity.py の `_TL_RUNGS` + 数値版ミラー）。同期はテストのみが担保し、**sensitivity 側の複製は TL1 条件が本体と構造的に異なる**（active_domain_count を引数に取りながら TL1 判定で使っていない） | TL 導出は**単一実装 MUST**。閾値表は実装から機械的に導出 **MUST** | A-02 |
| DP2 | `ConclusionUnavailableReason` の 4 値中 3 値に生成経路が無く、全結論不可が `insufficient_data` に潰れている | 結論不可の理由は**実際に区別して発行 MUST**（区別できないなら列挙から落とす MUST） | — (NP5+8) |
| DP3 | 慢性判定のデューティ側パラメータ（窓・閾値）が config registry に**未登録**。解決が失敗しハードコード既定値にフォールバックするため、docstring が謳う「SETTINGS から即時調整」が**実際には効かない** | 結論に影響する全パラメータは registry 経由 **MUST**。フォールバックは**警告を伴う MUST**（沈黙のフォールバックは NP6 違反） | A-13 |
| DP4 | 較正状態・self_eval・慢性検知のすべてが例外を握り潰して「正常に見える既定値」に落ちる（INSUFFICIENT_DATA / 空リスト / null）。NP3 上は正しいが、**壊れているのか本当にデータが無いのかを区別する経路が metadata の一部にしか無い** | 縮退経路は**必ず観測可能な標識を伴う MUST**（ANOMALY の `novelty_source` が良い先例） | D-01 |
| DP5 | `radar/conclusions/rss_extractor.py`（586 行）が結論パッケージに同居しているが責務はセンサー層 | 層の所属を構造で表す **MUST** | C-08 |
| DP6 | ティック毎に同一結論を書く設計だったため 1 週間で 89,884 行（distinct 12 状態）まで膨張し DB の 83% を占めた。変化ゲートで是正済だが、**ゲートを外すと再発する** | 台帳の書込単位は**状態変化 MUST**。時系列観測は別レイヤ **MUST** | — |

---

## 7. テストトレーサビリティ

対象は D5 台帳の conclusions 系全ファイル。**BEHAVIOR 234 件 / CONTRACT 90 件 / STRUCTURAL 14 件 = 338 件**。

| テストファイル | 件数 | D5 分類 | 対応条項 (S1-CONC-) |
|---|---|---|---|
| test_anomaly_derive | 29 | BEHAVIOR | 002, 005, 006, 026〜029, 036 |
| test_per_domain_derive | 27 | BEHAVIOR | 002, 005, 023, 024, 025 |
| test_attack_mode_derive | 26 | BEHAVIOR | 002, 005, 006, 030, 031, 032 |
| test_attack_mode_extensions | 26 | BEHAVIOR | 033, 034 |
| test_trend_derive | 23 | BEHAVIOR | 002, 005, 018〜022 |
| test_conclusions_markdown | 21 | CONTRACT | 049 |
| test_conclusions_api | 19 | CONTRACT | 005, 007〜011, 049 |
| test_human_anchor | 17 | BEHAVIOR | 053, 054, 055, 056 |
| test_inconclusive_continuity | 17 | BEHAVIOR（endpoint 部は CONTRACT） | 044, 045 |
| test_threat_level_derive | 15 | BEHAVIOR | 002, 005, 012〜016, 036 |
| test_conclusions | 14 | CONTRACT | 001, 002, 003 |
| test_conclusions_feedback | 14 | CONTRACT | 009, 050, 051 |
| test_attack_mode_llm_augment | 14 | BEHAVIOR | 003, 035 |
| test_conclusions_persistence | 14 | STRUCTURAL | 039, 043 |
| test_analyst_feedback_v2 | 13 | CONTRACT | 007, 052 |
| test_conclusion_write_gating | 12 | BEHAVIOR | 040, 041, 042, 047 |
| test_falsification | 12 | BEHAVIOR | 017 |
| test_conclusion_calibration | 8 | BEHAVIOR | 036, 037, 038 |
| test_severity | 8 | BEHAVIOR | 012（うち 3 件は ground-truth ラダー = **S1-calibration 担当**） |
| test_self_eval | 9 | CONTRACT | 048 |

**境界外**（本書では扱わない）: test_ground_truth_etl(39) / test_report_recall_metrics(8) /
test_check_recall_baseline(16) → **S1-calibration**。test_rss_extractor(56) → **S1-sensors**。
test_shadow_metrics(10) → SCAFFOLD、v3 に持ち込まない。

**対応条項の無いテスト (GAP): 0 件。** 上記 20 ファイル全件がいずれかの条項に対応する。

### GAP（仕様化したが検証が無い）

| ID | 内容 | 影響 |
|---|---|---|
| GAP-01 | ATTACK_MODE の**数値閾値そのもの**を pin するテストが無い（全て定数相対）。`CYBER_DDOS_FLOOR = 0.1` にしても全 26 件が通る | **高**。分類器の感度が無検知で変わる。D5 §3-5 の「仕様の宝」評価は再考を要する |
| GAP-02 | 同じく PER_DOMAIN / TREND の数値閾値が未 pin | **高**（同上） |
| GAP-03 | 台帳 retention（90 日 / プロンプト下限 +30 日）の挙動テストが無い | 中。NP6 の監査経路が沈黙で切れうる |
| GAP-04 | replay endpoint の as-of 意味論（型ごと `observed_at <= at` の最新）に専用テストが無い。write-gating が間接保証するのみ | 中。AP4 の中核 |
| GAP-05 | 結論不可行の `null_run_minutes` / `null_severity` 付与（045）が未検証 | 低〜中 |
| GAP-06 | 004（disclaimer の読み出し時注入）/ 007（envelope observed_at 既定）/ 037（(結論, アナリスト) 最新 1 件 dedup）/ 048 の null_zone・skew が未検証 | 中。037 は recall の分母に、048 は「TL5 が 0% に落ちる」型の較正劣化検知に直結 |
| GAP-07 | LLM 補強で sha256 計算が失敗（空文字）した場合に元の値を保持する分岐が未検証 | 低 |

---

## 8. 未決事項

1. **`ConclusionUnavailableReason` の設計意図**（§5-A1 / §6 DP2）: 4 値の列挙は NP5+8 の「なぜ結論できないか」を
   区別する意図だったはずだが、3 値が未実装のまま定着している。v3 で区別を実装するのか列挙を縮めるのかは
   **オーナー裁定が要る**。本書は現行を CORE として記述した
2. **ATTACK_MODE 閾値の追従運用**（§5-A10）: 「観測分布に合わせて閾値を下げる」調整が 2 回行われ、現在ほぼ
   ベースライン水準にある。NP5+8（恒常的結論不可の回避）と結論の情報量のトレードオフが未評価。v3 では
   **閾値の由来と改訂履歴を結論に添える**設計を検討したい
3. **novelty × 変化ゲートの相互作用**（§5-A8）: 定量評価が未実施。実データでの importance 分布シフトを測る必要がある
4. **人間アンカーの実効性**: 週次キューは実装済だが、実際に人手ラベルが供給されているか（`recall_meta.labels_human`
   の実測）は D4 の範囲。**人手ラベル 0 が続く場合、S1-CONC-054 の存在意義が形骸化する**ため、v3 では供給量そのものを
   AP3 の監視対象にすべき
5. GAP-01/02 の解消（数値閾値の直接 pin）は**現行系でも即時に着手可能**であり、v3 パリティゲートの前提として
   先行実施を推奨する

---

*Phase S。一次ソース: `radar/conclusions/*.py`（19 ファイル、rss_extractor / shadow_metrics を除く）、
`radar/routes/conclusions_v2.py`、`radar/routes/human_anchor_v2.py`、conclusions 系テスト 20 ファイル 338 件。*
