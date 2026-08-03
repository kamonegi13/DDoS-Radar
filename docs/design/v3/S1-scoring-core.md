# S1 — 収斂スコアリング・コア 挙動仕様

**スコープ**: センサー信号 → ドメインスコア → 収斂判定 → シナリオスコア → TL 導出 までの数式と閾値。
TL の**結論としての**組み立て（envelope / calibration_status / UnavailableReason）は S1-conclusions 担当。
採点ティックの**順序と副作用**は S1-scoring-pipeline 担当。センサー個別の状態判定は S1-sensors-* 担当。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md) に従う。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソースについて**: 本仕様の数値の多くは `tests/test_engine.py`（162 tests）と
`tests/test_scenario_scoring.py`（60 tests）が pin している実値から採取した。テストが仕様の
一次ソースである（D5 の判定どおり）。設計文書 `docs/design/scoring-internals.md` との乖離は
ACCIDENTAL 欄に回す。

---

## 1. 用語

CLAUDE.md の用語定義に従う（country / scenario / participant / coupling weight / role / adversary /
focused / background / C-lite）。本書固有:

- **domain**: cyber / physical / info の 3 値
- **RationaleEntry**: センサー 1 基の 1 観測を表す採点入力（status, score, domain, source_country, signal_source, suppressed, confidence）
- **Signal**: シナリオ採点用に正規化された観測（raw_score, countries[], domain, signal_source）
- **TL**: 脅威レベル。**1=CRITICAL … 5=NORMAL（DEFCON 式）**。大小比較は必ず `severity = 6 − TL` に変換してから行う

---

## 2. 挙動条項

### S1-SCORE-001: ドメインスコアは FIRED かつ非 suppressed のエントリのみを合算する
**挙動**: 各 domain のスコアは、その domain に属する RationaleEntry のうち `status == "FIRED"`
かつ `suppressed == False` のものの score を合計した値で **MUST**。`status != "FIRED"` のエントリは
score が正でも寄与しない。suppressed エントリも寄与しない。
**根拠**: radar/engine.py（WeightedConvergenceEngine のドメイン集計）
**検証**: tests/test_engine.py::TestWeightedConvergenceEngine::test_domain_scores_basic /
::test_domain_scores_suppressed_excluded / ::test_domain_scores_non_fired_excluded
**分類**: CORE

### S1-SCORE-002: ドメインスコアは重み付け前に 10 で上限クリップする
**挙動**: ドメイン合計は重み適用の**前**に `min(total, 10)` でクリップ **MUST**。
その後 domain weight を乗じる。例: cyber 合計 20、cyber weight 0.50 → `min(20,10) × 0.50 = 5.0`。
**閾値**: ドメイン上限 = 10（ハードコード）、cyber domain weight = 0.50（config: `DOMAIN_WEIGHT_CYBER`）
**根拠**: radar/engine.py
**検証**: tests/test_engine.py::TestWeightedConvergenceEngine::test_convergence_score_capped
**分類**: CORE

### S1-SCORE-003: 収斂レベルはアクティブなドメイン数で決まる
**挙動**: スコアが 0 より大きい domain の数 n に対し、n=0 → `NONE`、n=1 → `SINGLE_DOMAIN`、
n=2 → `DUAL_DOMAIN`、n=3 → `FULL_CONVERGENCE` **MUST**。
**根拠**: radar/engine.py
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_convergence_none / _single / _dual / _full
**分類**: CORE

### S1-SCORE-004: TL 導出は 3 条件（スコア帯 / ドメイン数 / physical 下限）の複合
**挙動**: `derive_tl(score, active_domains, physical_score)` は以下を満たす **MUST**:

| TL | 条件 |
|----|------|
| 1 (CRITICAL) | `score >= 9` **かつ** `len(active_domains) >= 3` **かつ** `physical_score >= 3.0` |
| 2 (SEVERE) | `score >= 6` **かつ** `len(active_domains) >= 2` |
| 3 (HIGH) | `4 <= score < 6` |
| 4 (ELEVATED) | `2 <= score < 4` |
| 5 (NORMAL) | `score < 2` |

上位条件から順に評価し、最初に成立した TL を返す。ゲート不成立時は 1 段下へ落ちる
（score 10 / 3 domain / physical 2.9 → TL2、score 7 / 1 domain → TL3）。
**閾値**: TL1 floor 9 + physical 3.0、TL2 floor 6 + 2 domains、TL3 floor 4、TL4 floor 2
**根拠**: radar/engine.py（derive_tl）
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_tl5_low_score / _tl4_moderate /
_tl3_elevated / _tl2_requires_dual_domain / _tl1_requires_physical；
test_scenario_scoring.py::TestDeriveTL::test_tl1 / _tl1_needs_physical / _tl2 /
_tl2_needs_two_domains / _tl3 / _tl4 / _tl5（**2 ファイルが独立に同一境界を pin している**）
**分類**: CORE

### S1-SCORE-005: ヒステリシスは緩和方向のみ 1 段ずつに制限する
**挙動**: 前回 TL が存在する場合、**エスカレーション（TL が小さくなる方向 = severity 上昇）は
即時反映 MUST**（held=False）。**デエスカレーション（TL が大きくなる方向）は 1 サイクルにつき
1 段までに制限 MUST**（held=True）。初回観測（prev=None）は素通し。
例: prev=2 で raw=5 → 出力 TL3、held=True。prev=5 で raw=2 → 出力 TL2、held=False。
**根拠**: radar/engine.py
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_hysteresis_first_entry /
_escalation_instant / _de_escalation_capped
**分類**: CORE（NP1 感度優先の実装。危険側へは速く、安全側へは遅く）

### S1-SCORE-006: 収斂ボーナスは最小ドメイン信頼度でゲートする
**挙動**: FULL_CONVERGENCE で +`CONVERGENCE_FULL_BONUS`、DUAL_DOMAIN で +1、SINGLE_DOMAIN で +0 **MUST**。
domain_confidences が与えられた場合、ボーナスは**アクティブドメインの信頼度の最小値**を乗じる **MUST**
（例: full bonus 2 × min(1.0, 0.5, 1.0) = 1.0、dual bonus 1 × min(0.6, 0.6) = 0.6）。
**閾値**: `CONVERGENCE_FULL_BONUS` 既定 2（config.py:330）、dual bonus 1（ハードコード）
**根拠**: radar/engine.py、radar/config.py:330
**検証**: test_engine.py::TestConvergenceGating::test_full_convergence_no_gating /
_gated_by_low_confidence / _dual_domain_gated / _single_domain_no_bonus
**分類**: CORE（NP2 の実装: 収斂の強度は最も弱いソースで律速される）

### S1-SCORE-007: シナリオ固有の収斂ボーナスは参加国数で降格する
**挙動**: `CONVERGENCE_SCENARIO_SPECIFIC` が有効なとき、3 ドメイン収斂であっても
**寄与している participant が 1 国のみなら bonus を 2.0 → 1.0 に降格 MUST**。
2 国以上なら full bonus。フラグ無効時は participant 数を無視して legacy 挙動（常に 2.0）。
dual-domain ボーナスは participant 数の影響を受けない。
**閾値**: `CONVERGENCE_SCENARIO_SPECIFIC` **既定 False**
**根拠**: radar/scoring.py
**検証**: test_scenario_scoring.py::TestConvergenceBonusScenarioSpecific::
test_three_domains_multi_participant_full_bonus / _single_participant_downgraded /
test_flag_off_keeps_legacy / test_two_domains_still_bonus；
::TestComputeScenarioScore::test_convergence_bonus_default_off_keeps_legacy
**分類**: CORE。**ただし既定 OFF であること自体は ACCIDENTAL 候補**（§5-A1）

### S1-SCORE-008: 信号の dedup は (signal_source, country) 単位で MAX を採る
**挙動**: 同一 `signal_source` かつ同一 country の寄与は **1 件に畳み込み、raw_score の最大値を採る MUST**。
異なる country、または異なる signal_source は別寄与として保持 **MUST**。
これは複数センサーが同じ `signal_source` を共有する場合（例: `ioda_bgp` と `ripe_bgp` が
ともに `signal_source="bgp"`）に、単一の物理的事象が二重計上されるのを防ぐ。
**根拠**: radar/scoring.py
**検証**: test_scenario_scoring.py::TestDedup::test_same_source_same_country_keeps_max /
_different_country_both_kept / _different_source_same_country_both_kept；
::TestEdgeCases::test_dedup_across_multiple_sensors_same_source
**分類**: CORE（NP2 の中核。過去の pitfall として scoring-internals.md に記録あり）

### S1-SCORE-009: 寄与スコアは raw × llm_country_weight × participant_weight
**挙動**: 各寄与のスコアは `raw_score × llm_country_weight × participant_weight` **MUST**。
LLM 由来でない信号の llm_country_weight は 1.0。formula_trace には各因子を小数 2 桁で
記録 **MUST**（例: `"3.00 (raw) × 1.00 (llm:US) × 0.80 (participant:US) = 2.40"`）。
**根拠**: radar/scoring.py
**検証**: test_scenario_scoring.py::TestComputeScenarioScore::test_basic_focused；
::TestDualWeight::test_llm_signal_dual_country / test_formula_trace_format；
::TestAdversaryContribution::test_cn_threatfox_contributes
**分類**: CORE（NP6: 導出開示の最小単位）

### S1-SCORE-010: シナリオ非参加国の信号は寄与しない
**挙動**: 信号の country がシナリオの participants に含まれない場合、寄与は 0 **MUST**
（例: taiwan_contingency に対する FR の信号）。
**根拠**: radar/scoring.py
**検証**: test_scenario_scoring.py::TestComputeScenarioScore::test_signal_countries_not_in_scenario_ignored
**分類**: CORE

### S1-SCORE-011: adversary ロールも自身の participant weight で寄与する
**挙動**: role が `adversary` の participant も、他ロールと同様に coupling weight を乗じて
寄与し、`active_countries` に含まれる **MUST**（ADR-014）。
**根拠**: radar/scoring.py
**検証**: test_scenario_scoring.py::TestAdversaryContribution::test_cn_threatfox_contributes /
test_adversary_counted_in_active_countries
**分類**: CORE

### S1-SCORE-012: グローバル信号は既定でシナリオスコアから分離する
**挙動**: country を持たない信号（`countries == []`）は、`GLOBAL_SIGNALS_DECOUPLED` が有効な場合
**シナリオスコアに一切寄与しない MUST**（寄与 0 件、収斂ボーナスにも算入しない）。
無効な場合のみ legacy 挙動として country `"GLOBAL"` の寄与を作り、`global_signal_weight` を乗じる。
**理由（Phase 9 回帰）**: グローバル信号がドメインを点灯させると、実体のない収斂で TL2 の
floor（2 ドメイン）を満たしてしまう。
**閾値**: `GLOBAL_SIGNALS_DECOUPLED` **既定 True**、`global_signal_weight` 例 0.5
**根拠**: radar/scoring.py
**検証**: test_scenario_scoring.py::TestComputeScenarioScore::test_global_signal_decoupled_default /
_legacy_when_flag_off / **test_global_signals_do_not_inflate_convergence**；
::TestEdgeCases::test_empty_countries_decoupled_no_contribution / _legacy_global_contribution /
test_mixed_global_and_per_country_decoupled / _legacy
**分類**: CORE（NP2 の防衛。回帰テストが明示的に存在する）

### S1-SCORE-013: グローバル脅威は別envelope として集計する
**挙動**: countryless 信号のみを集約した `global_threat` を別に算出 **MUST**。
weight は線形に乗り、応答に echo back する。global 信号が無ければ score 0.0 / 全ドメイン 0.0 /
sources 空配列。
**検証**: test_scenario_scoring.py::TestComputeGlobalThreat::test_aggregates_global_signals_only /
_empty_when_no_global_signals / _global_signal_weight_applied
**分類**: CORE

### S1-SCORE-014: LLM 多国信号は主要国比率でフィルタする
**挙動**: LLM 由来信号が複数国を持つ場合、`LLM_INTEL_PRIMARY_COUNTRY_ONLY` が有効なら
**最大重みに対する比率が `LLM_INTEL_PRIMARY_THRESHOLD` 以上の国のみを残す MUST**。
比較は **`>=`（境界値は残す）MUST**。フラグ無効時は全国が dual-weight で寄与（legacy bleed）。
**閾値**: `LLM_INTEL_PRIMARY_COUNTRY_ONLY` 既定 True、`LLM_INTEL_PRIMARY_THRESHOLD` 既定 **0.8**（DB override 可）
**根拠**: radar/scoring.py（Phase 9-E）
**検証**: test_scenario_scoring.py::TestLlmIntelPrimaryCountry::（6 件全て。
borderline 0.8 == 0.8 が残ること、override 0.95 で 0.9 が落ちることを含む）
**分類**: CORE

### S1-SCORE-015: ドメインごとに上限クリップを適用する（シナリオ採点側）
**挙動**: シナリオ採点でもドメイン合計に `domain_cap` を適用 **MUST**（例: raw 10.0、cap 6.0 → 6.0）。
**根拠**: radar/scoring.py
**検証**: test_scenario_scoring.py::TestComputeScenarioScore::test_domain_cap
**分類**: CORE

### S1-SCORE-016: background シナリオも同一式で lite TL を導出する
**挙動**: background（非 focused）シナリオも focused と**同じ TL 導出式**を lite スコアに適用して
TL を得る **MUST**（NP4: 結論最大化）。scoring_mode は `"full"`（focused）/ `"lite"`（background）を
出力に含める **MUST**。
**検証**: test_scenario_scoring.py::TestComputeScenarioScore::test_basic_focused / _background_derives_lite_tl
**分類**: CORE

### S1-SCORE-017: lite モードの confidence は full より厳密に低い
**挙動**: 同一の状態に対し、lite モードの結論 confidence は full モードより**厳密に小さい MUST**。
lite の結論には `lite_tl_note` メタデータを付与 **MUST**（full には付けない）。TL 値自体は同じ。
**検証**: test_scenario_scoring.py::TestLiteTlConfidenceDiscount::test_lite_confidence_below_full /
_lite_metadata_carries_note
**分類**: CORE（NP5+8: 結論品質の規律）

### S1-SCORE-018: RationaleEntry → Signal 変換の採択条件
**挙動**: 以下のいずれかに該当する RationaleEntry は Signal に変換しない（None を返す）**MUST**:
`suppressed == True` / `status != "FIRED"` / `score == 0`。
変換時、`source_country` が空なら `countries = []`（グローバル信号）、
`signal_source` が空なら**センサー名にフォールバック MUST**。score は float 化。
**検証**: test_scenario_scoring.py::TestRationaleToSignal::（6 件全て）
**分類**: CORE

### S1-SCORE-019: 信頼度は寄与スコアに線形に乗る
**挙動**: confidence が与えられた場合、ドメインスコアは `score × confidence` **MUST**。
confidence 0.0 は寄与を消す。suppressed は confidence 1.0 でも寄与を消す（suppression が優先 MUST）。
**検証**: test_engine.py::TestConfidenceWeighting::（4 件全て）
**分類**: CORE

### S1-SCORE-020: ドメイン信頼度は同一ドメイン内センサーの単純平均
**挙動**: 各ドメインの confidence は、そのドメインの非 suppressed センサーの confidence の
**単純平均 MUST**。センサーが 1 つも無いドメインは **1.0 を既定値とする MUST**。
suppressed エントリは平均から除外 **MUST**。
**検証**: test_engine.py::TestDomainConfidences::test_all_high_confidence / _mixed_confidence_averaged /
_suppressed_excluded
**分類**: CORE。**空ドメインの既定 1.0 は ACCIDENTAL 候補**（§5-A2）

### S1-SCORE-021: シーケンスボーナスは連鎖長と時間減衰の積
**挙動**: シーケンスイベント連鎖に対し、**3 件未満なら bonus 0 MUST**。
3 件以上で `SEQUENCE_FULL_BONUS` を基準に、連鎖の齢に応じた線形減衰を掛け、四捨五入する **MUST**:
`weight = max(0.3, 1 − age_hours / 24)`、`bonus = round(SEQUENCE_FULL_BONUS × weight)`。
- age ≈ 0 → weight 1.0 → bonus 3
- age 8h → weight ≈ 0.667 → bonus 2
- age 20h → weight = max(0.3, 0.167) = **0.3**（フロアが効く）→ bonus 1
**閾値**: `SEQUENCE_FULL_BONUS` 既定 3（config.py:364）、減衰地平 24h、減衰フロア 0.3、最小連鎖長 3
**検証**: test_engine.py::TestSequenceTemporalDecay::（4 件全て）；
::TestSequenceScorer::test_no_events / _partial_chain / _full_chain
**分類**: CORE

### S1-SCORE-022: シーケンスイベントは 300s 内で dedup、窓外は 0 点
**挙動**: 同一イベント種別は **300 秒以内なら重複として 1 件に畳む MUST**。
`SEQUENCE_WINDOW` より古いイベントは bonus に寄与しない **MUST**。
**閾値**: dedup 窓 300s、`SEQUENCE_WINDOW` 既定 **86400s**（config.py:363）
**検証**: test_engine.py::TestSequenceScorer::test_dedup_within_window / _events_expire_after_window
**分類**: CORE

### S1-SCORE-023: HOD Z-score は同時刻帯サンプルの標準化
**挙動**: hour-of-day ベースラインは同一時刻帯の過去サンプルから算出 **MUST**。
サンプル数が不足なら `invalid`（n=0）を返す **MUST**。
典型: 10 日分の同時刻サンプルが 2.0、観測 2.1 → `|z| < 3.0`。ベースライン 1.0 × 10 日、観測 20.0 → `z > 3.0`。
**閾値**: 有効判定に n >= 7 相当
**検証**: test_engine.py::TestHodZscore::test_insufficient_samples / _normal_spike / _anomalous_spike
**分類**: CORE

### S1-SCORE-024: 速度・加速度・回帰 slope の定義
**挙動**: 時系列に対し、velocity は単位時間あたりの変化率、acceleration はその変化率 **MUST**。
`_linear_regression_slope` は最小二乗の傾きで、n=0 と n=1 は **0.0 を返す MUST**。
- 平坦系列 → `|velocity| < 1e-6`
- 定速系列 → `|acceleration| < 1e-4`
- `[1,2,3,4,5]` → slope 1.0、`[5,5,5,5]` → 0.0、`[5,4,3,2,1]` → −1.0
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_velocity_static / _linear_increase /
_acceleration_constant_velocity；::TestLinearSlope::（5 件全て）
**分類**: **DEFECT-PRESERVE** — 同等の実装が engine.py と scoring.py に**重複して存在**する
（scoring.py:1060 に "shared with engine.py" の自認コメント）。v3 では単一実装 **MUST**（D2 A-02）

### S1-SCORE-025: ambush（急襲）検知は速度と Z-score の同時成立
**挙動**: 平坦な系列では ambush を検知しない **MUST**。末尾が指数的に立ち上がる系列
（15 点平坦 + 5 点 ×3.0 成長）では `velocity > 0` かつ `z > 0` を満たす **MUST**。
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_ambush_not_triggered_on_flat /
_triggered_on_exponential
**分類**: CORE。**具体的な発火閾値がテストに pin されていない**（§6 GAP-01）

### S1-SCORE-026: feint（陽動）検知は 1 ドメイン突出 + 他 2 ドメイン低位
**挙動**: 1 ドメインが突出し他 2 ドメインが低位のとき feint と判定し、primary domain と
distraction domains を出力 **MUST**。以下は feint と**しない MUST**:
均衡（3,3,3）/ 単一ドメインのみ（7,0,0 — distraction が存在しない）/ 全ドメイン高位（6,5,5 — 真の収斂）。
primary が **7 以上なら confidence HIGH MUST**。
**検証**: test_engine.py::TestFeintDetection::（5 件全て）
**分類**: CORE

### S1-SCORE-027: 同期スコアは複数ソースのタイムスタンプ一致度
**挙動**: 3 ソースのタイムスタンプが同一 → 1.0 **MUST**。単一ソース → **0.0 MUST**（同期は定義不能）。
4000 秒離れたタイムスタンプ → 0.0。
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_sync_score_identical_timestamps /
_single_source / _no_sync
**分類**: CORE

### S1-SCORE-028: 時間的整合ボーナスは 2 シナリオ間 10 秒以内で +2
**挙動**: イベントが無ければ bonus 0 **MUST**。2 つの theater/scenario のイベントが **10 秒以内**なら
同期と判定し **bonus +2 MUST**。
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_temporal_coherence_no_events / _synchronized
**分類**: CORE

### S1-SCORE-029: Blockade Index は DDoS・BGP・CheckHost の合成
**挙動**: BI は DDoS スコア・RIPE 値・CheckHost 健全度から算出 **MUST**。
- 健全（ddos 1.0 / ripe 0.0 / ch 1.0）→ BI < 1.0
- 最大 DDoS + CH ブラックアウト（10.0 / 0.0 / 0.0）→ BI >= 9.0
- 高 DDoS + CH 不良（8.0 / 10.0 / 0.1）→ BI >= 7.0
- asphyxiation フラグは BI を**厳密に増加させる MUST**（docstring は 1.5 倍と記述）
- **CheckHost が None のときは 1.0（健全）と同一に扱う MUST**（fail-open）
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_blockade_index_normal / _blackout /
_asphyxiation / **_ch_none_conservative**；::TestBlockadeIndexScoring::（3 件）
**分類**: CORE。fail-open の是非は §5-A3

### S1-SCORE-030: Maskirovka（偽装）検知の 3 条件
**挙動**: コア劣化 + narrative 沈黙 + CheckHost BLACKOUT + 他センサー生存 → confidence **HIGH MUST**。
`narrative_burst == True` は検知を**拒否する MUST**（veto）。
CheckHost が OK かつ他センサー生存が False → **MEDIUM**（HIGH ではない）。
**検証**: test_engine.py::TestWeightedConvergenceEngine::test_maskirovka_outage_and_silence /
_not_triggered_when_narrative_active / _medium_without_cross_theater
**分類**: CORE

### S1-SCORE-031: 発信源エントロピーは Shannon エントロピー（bit）
**挙動**: 国別分布に対する Shannon エントロピーを bit 単位で算出 **MUST**。
単一ソース → 0.0 / 2 等分 → 1.0 / 4 等分 → 2.0（許容 ±0.01）/ 空分布 → 0.0。
**0% のシェアは log 項から除外 MUST**。偏った分布（90/5/3/2）→ 0.0 < H < 1.5。
**検証**: test_engine.py::TestOriginEntropy::（6 件全て）
**分類**: CORE

### S1-SCORE-032: エントロピー変化は移動平均比 ±20% で分類
**挙動**: 読み取りが **3 件未満なら INSUFFICIENT_DATA MUST**。
移動平均に対する変化率が **−20% 未満 → CONCENTRATING**、**+20% 超 → DISPERSING**、
その間 → STABLE **MUST**。
**検証**: test_engine.py::TestEntropyTracking::（4 件全て）
**分類**: CORE

### S1-SCORE-033: BGP トレンドは prefix / ASN 数の回帰 slope
**挙動**: エントリが **3 件未満なら INSUFFICIENT_DATA MUST**。
prefix の傾きが **−0.5% 未満 → WITHDRAWING**、**+0.5% 超 → GROWING**、その間 → STABLE **MUST**。
seen_ases の傾きも同様に算出 **MUST**。
**検証**: test_engine.py::TestBgpTrend::（5 件全て）
**分類**: CORE

### S1-SCORE-034: ASN 重複率は IDF 重み付きで算出する
**挙動**: 素の重複率は正規化後の min-sum（例: {A:5,B:3} vs {A:2,C:10} → 16.67%）**MUST**。
IDF 重みは、全ての国に出現する ASN をほぼ 0 に、単一国のみの ASN を 1.0 にする **MUST**。
IDF 適用により、ユビキタスな ASN の共有による見かけの重複は**抑制される MUST**
（素 >= 70% → IDF 適用後 < 10%）。稀な ASN の共有は**増幅される MUST**。
空入力（分布 or 重み）は 0.0 **MUST**。
**検証**: test_engine.py::TestHelpers::test_calculate_overlap_empty / _identical / _partial /
_compute_idf_weights_ubiquitous_zero / _empty / _idf_suppresses_global_baseline /
_idf_amplifies_rare_coincidence / _idf_empty_inputs
**分類**: CORE

### S1-SCORE-035: 攻撃者 confidence の 3 分岐
**挙動**: `compute_confidence(score, country, is_new_actor, is_state_asn)` は以下 **MUST**:
- `is_state_asn == True` → **HIGH**（スコア 3.0 でも）
- `is_new_actor == True` → **LOW**（スコア 5.0 でも。新規アクターは信頼できない）
- 既知アクター + スコア 4.0 → MEDIUM
- スコア 1.5 → LOW
**検証**: test_engine.py::TestHelpers::test_compute_confidence_state_asn / _new_actor / _medium / _low
**分類**: CORE

### S1-SCORE-036: エスカレーション進行の 5 状態
**挙動**: TL 履歴から NO_DATA / STABLE / ESCALATING / DE-ESCALATING / OSCILLATING を判定 **MUST**。
空履歴 → NO_DATA、`current_tl` 既定 **5**。定常 TL5 → STABLE、遷移 0。
5→4→3 → ESCALATING、遷移 2、最初の方向 `"ESCALATE"`。2→3→4 → DE-ESCALATING。
3→4→3→4→3 → OSCILLATING。score_with_bonus の上昇は正の score_trend を生む **MUST**。
**検証**: test_engine.py::TestEscalationProgress::（6 件全て）
**分類**: CORE

### S1-SCORE-037: TL 近接度は上下の距離と 1.5 の閾値で分類
**挙動**: 現在スコアと隣接 TL の floor との距離を算出 **MUST**。
`distance_up <= 1.5` なら **NEAR_ESCALATION（優先）MUST**。それを満たさず floor に近ければ NEAR_DE_ESCALATION。
- **TL5 では下位が存在しないため `distance_down is None` MUST**
- **TL1 は終端であり `distance_up` / `next_tl_up` ともに None MUST**
- TL 帯（TL4: 2–4、TL3: 4–6、TL2: 6–9、TL1: 9–）は近接判定 1.5 に対して狭いため、
  TL3/TL4 の多くのスコアが NEAR_ESCALATION に分類される
**閾値**: 近接判定 1.5
**検証**: test_engine.py::TestTlProximity::（8 件全て）
**分類**: CORE。TL 帯幅と近接閾値の関係は §5-A4

### S1-SCORE-038: サーキットブレーカーの状態機械（採点側から見た契約）
**挙動**: 連続失敗が `CB_FAILURE_THRESHOLD` に**達した時点で OPEN MUST**（閾値−1 では CLOSED を維持）。
OPEN 中は fetch をスキップ **MUST**。`recovery_delay` 経過後 HALF_OPEN に遷移しスキップしない **MUST**。
HALF_OPEN で成功 → CLOSED、`fail_count` 0、`recovery_delay` を `CB_INITIAL_DELAY` にリセット **MUST**。
HALF_OPEN で失敗 → OPEN に戻り `recovery_delay` を **2 倍 MUST**、`CB_MAX_DELAY` で上限クリップ **MUST**。
OPEN のとき health は `CIRCUIT_OPEN`、**confidence は 0.0 MUST**。
**閾値**: `CB_FAILURE_THRESHOLD` = **5**、`CB_INITIAL_DELAY` = **300s**、`CB_MAX_DELAY` = **3600s**
（radar/sensors/base.py:17-19、ハードコード定数）
**検証**: test_engine.py::TestCircuitBreaker::（14 件全て。full cycle 2 件を含む）
**分類**: CORE（NP3 の中核）

### S1-SCORE-039: シークレット値は UI に平文を出さない
**挙動**: `_is_secret_key` は API トークン・パスワード・webhook URL 等を秘匿対象と判定し、
閾値等のチューナブルは判定しない **MUST**。秘匿値のインジケータは **`{set: bool, last4: str|None}` のみ MUST**。
値長が 4 以下なら `last4 = None` **MUST**。未設定（""/None）→ `{set: False, last4: None}`。
**平文がインジケータ出力に現れてはならない MUST**。
マスク検出の正規表現は**先頭の `*` 連続 + 末尾 4 文字以内にアンカーする MUST**
（"****abcde" のような 5 文字末尾は棄却、32 文字 hex や "0.40" も棄却）。
**検証**: test_engine.py::TestSecretIndicator::（7 件全て）
**分類**: CORE（S4 セキュリティ仕様と相互参照）

### S1-SCORE-040: SensorRegistry の列挙契約
**挙動**: `SensorRegistry.all()` は登録済みセンサーを返す **MUST**（空なら空リスト）。
**根拠/検証**: test_engine.py::test_sensor_registry_all_lists_registered_sensors
（**F5 回帰テスト、2026-05-30 の移行足場 teardown インシデント由来**）
**分類**: CORE

### S1-SCORE-041: 空の scenario_id では coverage を更新しない
**挙動**: `scenario_id` が falsy（`""` / `None`）のとき coverage 更新は **no-op MUST**
（NULL upsert を発生させない）。
**検証**: test_engine.py::test_update_coverage_skips_empty_scenario_id
**分類**: CORE

### S1-SCORE-042: 無効化シナリオは採点対象外
**挙動**: `enabled: False` のシナリオは `is_scorable == False` **MUST**。
**検証**: test_scenario_scoring.py::TestDisabledScenario::test_disabled_not_scorable；
::TestRealGeoData（実 geo_data.json で scorable 4 件 = SCS 無効を除いた数）
**分類**: CORE

### S1-SCORE-043: 信号ゼロのシナリオは TL5 で floor する
**挙動**: 信号が無いシナリオは score 0.0、**TL は 5（NORMAL）MUST**、寄与リストは空。
**検証**: test_scenario_scoring.py::TestEdgeCases::test_no_signals
**分類**: CORE

### S1-SCORE-044: core_country を持たないシナリオは対称に採点する
**挙動**: `core_country` が None のシナリオ（例: middle_east）では、複数の
principal_belligerent がそれぞれの weight（ともに 1.0）で対称に寄与 **MUST**。
**検証**: test_scenario_scoring.py::TestMiddleEast::test_symmetric_belligerents
**分類**: CORE

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー | DB override | 出典 |
|---|---|---|---|---|
| ドメインスコア上限 | 10 | — （ハードコード） | 不可 | S1-SCORE-002 |
| cyber ドメイン重み | 0.50 | `DOMAIN_WEIGHT_CYBER` | 可 | S1-SCORE-002 |
| TL1 floor | score 9 + 3 domains + physical 3.0 | — | 不可 | S1-SCORE-004 |
| TL2 floor | score 6 + 2 domains | — | 不可 | S1-SCORE-004 |
| TL3 floor | score 4 | — | 不可 | S1-SCORE-004 |
| TL4 floor | score 2 | — | 不可 | S1-SCORE-004 |
| 収斂 full ボーナス | 2 | `CONVERGENCE_FULL_BONUS` | 可 | config.py:330 |
| 収斂 dual ボーナス | 1 | — （ハードコード） | 不可 | S1-SCORE-006 |
| シナリオ固有収斂 | False | `CONVERGENCE_SCENARIO_SPECIFIC` | 可 | S1-SCORE-007 |
| グローバル信号分離 | True | `GLOBAL_SIGNALS_DECOUPLED` | 可 | S1-SCORE-012 |
| LLM 主要国のみ | True | `LLM_INTEL_PRIMARY_COUNTRY_ONLY` | 可 | S1-SCORE-014 |
| LLM 主要国閾値 | 0.8 | `LLM_INTEL_PRIMARY_THRESHOLD` | 可 | S1-SCORE-014 |
| シーケンス窓 | 86400s | `SEQUENCE_WINDOW` | 可 | config.py:363 |
| シーケンス full ボーナス | 3 | `SEQUENCE_FULL_BONUS` | 可 | config.py:364 |
| シーケンス dedup 窓 | 300s | — | 不可 | S1-SCORE-022 |
| シーケンス減衰地平 / フロア | 24h / 0.3 | — | 不可 | S1-SCORE-021 |
| 最小連鎖長 | 3 | — | 不可 | S1-SCORE-021 |
| エントロピー変化閾値 | ±20% | — | 不可 | S1-SCORE-032 |
| エントロピー最小サンプル | 3 | — | 不可 | S1-SCORE-032 |
| BGP トレンド閾値 | ±0.5% | — | 不可 | S1-SCORE-033 |
| TL 近接判定 | 1.5 | — | 不可 | S1-SCORE-037 |
| 時間的整合窓 | 10s | — | 不可 | S1-SCORE-028 |
| CB 失敗閾値 | 5 | — | 不可 | base.py:17 |
| CB 初期遅延 / 最大遅延 | 300s / 3600s | — | 不可 | base.py:18-19 |

**v3 への示唆**: ハードコード閾値が 15 件ある。NP6（導出開示）の観点では、
**結論に影響する全閾値は宣言的 registry に載せて可視化すべき**（P で設計）。

---

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | `CONVERGENCE_SCENARIO_SPECIFIC` が既定 OFF。単一 participant の 3 ドメイン収斂が full bonus 2.0 を得る | NP2 の趣旨では「1 国だけの収斂」は弱いはず。既定 ON にすべきか |
| A2 | センサーが 1 つも無いドメインの confidence 既定が 1.0（= 完全に信頼） | 観測が無いことを「信頼度 1.0」と表現するのは NP5+8 に反する疑い。0.0 か None が適切ではないか |
| A3 | Blockade Index で CheckHost None を 1.0（健全）扱いする fail-open | NP1（感度優先）に反する。センサー欠測を「健全」と読むと封鎖を見逃す |
| A4 | TL 帯幅（TL4:2、TL3:2、TL2:3）が近接判定 1.5 に対して狭く、多くのスコアが NEAR_ESCALATION に分類される | 近接警告の実効性。閾値を帯幅に対する相対値にすべきか |
| A5 | `derive_tl` の TL1 条件は「score >= 9」だがテストは 10.0 でしか検証していない（9.0 ちょうどの境界が未検証） | 境界の意図確認 |

---

## 5. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | velocity / acceleration / `_linear_regression_slope` が engine.py と scoring.py に重複実装 | 単一実装 **MUST** | A-02 |
| DP2 | 閾値 15 件がハードコードで registry に載らない | 結論に影響する閾値は全て宣言的 registry 経由 **MUST** | A-13 |
| DP3 | `TestRealGeoData` が `geo_data.json` を相対パスで開くため CWD 依存 | テストは CWD 非依存 **MUST** | — |

---

## 6. テストトレーサビリティ

**test_engine.py（162 tests / 25 クラス + 2 モジュール関数）**: 全件が本仕様のいずれかの条項に対応。
対応表は §2 各条項の「検証」欄。**GAP なし**。

**test_scenario_scoring.py（60 tests / 15 クラス）**: 全件対応。**GAP なし**。

### 特記: テストが本番ロジックを呼ばず**インライン再実装**している箇所（仕様の根拠が弱い）

以下は数値を pin しているが**本番コードを実行していない**ため、実装が変わってもテストは通る:

| テスト | 再実装している内容 |
|---|---|
| `TestGraduatedVectorShift`（L780） | severe = L7 >= 5.0 かつ L7 > L3 × 2.0 |
| `TestAdversaryCountScoring`（L804） | 段階式 count>=3→3、>=1→2、else 0 |
| `TestDdosBgpCausality`（L891） | CF fired + IODA fired → 因果リンク文字列付与 |
| `TestCfBgpHijackScoring._score_bgp_events`（L1071） | fired = 継続中 hijack OR leak >= 3 |
| `TestTorMetricsSensor::test_censorship_indicator`（L1233） | relay_drop AND user_surge の優先順位 |
| `TestRipeAtlasSensor` / `TestTorMetricsSensor` の drop_pct 算術 | しきい値比較 |

**v3 では、これら 6 箇所は本番関数を呼ぶテストに置き換える MUST**（S5 のテスト移植計画へ）。

### GAP（仕様化できたが検証が無い）

| ID | 内容 |
|---|---|
| GAP-01 | ambush 検知の具体的発火閾値（velocity / z の下限値）がテストに pin されていない。実装読解が必要 |
| GAP-02 | Maskirovka の「コア劣化」判定の具体条件 |
| GAP-03 | `derive_tl` の score 境界値ちょうど（2.0 / 4.0 / 6.0 / 9.0）の挙動が未検証（`>=` か `>` か） |

---

## 7. 未決事項

1. **engine.py と scoring.py の責務境界**が仕様レベルで不明瞭。engine は「単一シナリオ内の
   ドメイン集計と収斂判定」、scoring は「シナリオ横断の集約と participant 重み付け」と読めるが、
   TL 導出が両方から呼べる構造になっている。**P での層設計時に一本化の判断が要る**
2. GAP-01〜03 の解消には実装読解が必要（次セッションで補完）
3. `scoring-internals.md` との突合が未実施（本仕様は実装 + テストのみを一次ソースとした）
