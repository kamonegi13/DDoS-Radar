# S1 素材: 提案系・状態機械・ガード・tier governor（生データ）

生存した子調査 3 件の統合（2026-08-03）。S1-calibration 正本へ編入する。証拠は file:line。
条項番号は元調査の通し番号を保持（A/B/C = 提案系、D = 状態機械、E = tier governor）。

---

## A. scenario_improver（提案生成本体）

- **ルール 4 本**、run_once 登録順 `scenario_diagnostic → weight_too_low → weight_too_high → missing_participant`（:633-638）。診断を先頭に置き、構造ルールは各自の vitality ガードで短絡
- **書き出す proposal_type は 5 種**: weight_too_low / weight_too_high / missing_participant / sensor_gap_detected / scenario_dormant（:432,519,571 + _proposal_writer.py:139,173）。dormant_participant と role_reclassify は structure_proposer 側

### weight_too_low（recall-positive）
- 窓 **30 日ハードコード**（`_stale_days()` 非使用）。寄与量は `sensor_observation_ts` を `scope='theater:<CC>'` で COUNT（:396,401-406）
- 参加者 < 3 なら無条件で空（:412-413）
- **「p75」は真の分位点でなくインデックス近似** `sorted[int(len*0.75)]`、p25 重みは `weights[len//4]`。n=4 で int(3.0)=3 → 最大値を指す等の境界ずれ（:414-416）
- 発火は `contribs[cc] >= p75` かつ `weight <= p25_w`（両方等号含む）。`p75 == 0` なら全体スキップ（:417-424）
- 新重み `round(min(0.95, w + WEIGHT_STEP), 2)`、`SCENARIO_IMPROVER_WEIGHT_STEP` 既定 0.15、上限 0.95。同値なら emit しない（:425-427,70-71）
- `sample_n` は当該国でなく**コホート総和**（:433-440）

### weight_too_high（recall-reducing、最厳格）
- P3: `scenario_vitality(days=_stale_days())` が active でなければ即空（:470-475）
- Phase B: `sensor_coverage_healthy(days=_stale_days())` False で scenario 単位に空。健全判定は llm_intel + sequence_events + sensor_observation_ts の**全球**合計 ≥ `min_global_signals`（既定 50、**キーワード引数のみで env 化されていない**）（:481-493、_proposal_guards.py:342-343,382-385）
- 参加者単位 3 段: `weight <= 0` → `is_role_protected` → `evidence_strength != "strong"`（:496-511）
- PROTECTED_ROLES = {primary_target, principal_belligerent, adversary, core_country}
- 新重み `round(max(0.10, w − WEIGHT_STEP), 2)`、下限 0.10（:512-514）
- `sample_n` は 5 ソース信号の総和（strong 時は常に 0）（:520-529）

### missing_participant
- `sequence_events` を **`scenario_id=?` で必ずスコープ**（2026-04-29 二次事故 = UA が全 5 シナリオに提案された件の回帰防止）（:553-557、検証あり）
- 窓 30 日固定、閾値 `SCENARIO_IMPROVER_MISSING_EVENT_N` 既定 3。既存参加者・空 theater はスキップ（:550,562-567）
- 初期値は保守的固定 `weight=0.30 / role="strategic_observer"`（:572-575）

### scenario_diagnostic（NP5+8 の結論不可明示）
- vitality active → 空、data_gap → `sensor_gap_detected`、dormant → `scenario_dormant` を 1 件ずつ。**Apply 経路を持たない情報系**（:607-614）

### `_emit` の 3 出口
1. **dedup skip**: 同一 `(scenario_id, proposal_type, target_country)` が `state IN ('pending','applied')` かつ `emitted_at > now − DEDUP_DAYS*86400`（既定 7）で存在 → None。Phase 3 で pending のみ → pending|applied に拡張（理由: auto-apply 済み行が再発火して**重みが発振する**事故）。**DB 例外時は False にフォールバック = dedup せず通す**（:168-170,97-138）
2. **cap skip**: 当該 scenario の pending 数 ≥ `SCENARIO_IMPROVER_MAX_ACTIVE`（既定 5）→ None。カウント失敗時は 0 扱い（フェイルオープン）（:171-176,141-151）
3. **成功**: `state='pending'` 固定 INSERT。JSON 2 列は `sort_keys=True` 正規化（:177-192）
- INSERT 後の非致命フック 2 つ: (a) `supersede_duplicate_pending`、(b) `_auto_apply_enabled()` が True のときだけ `_maybe_auto_apply`。両方 except → log.debug（:201-228）
- **戻り値の意味論が曖昧**: 「新規行を作ったか」であり「pending のまま残ったか」ではない。auto-apply 成功で applied になっても emitted として計上（:229,668-674、DEFECT 候補）
- AUTO_APPLY 既定 False（DB override → env → False の順、真値は `("1","true","yes","on")`）。**OFF 時に全提案が pending に留まることを pin するテストが存在しない**（:222-258、監査上の穴）

### auto-apply 判定木（フラグ ON 時）
- impact マップ: weight_too_low / missing_participant → low、role_reclassify → med、weight_too_high / dormant_participant → high、他 → None で即 return（:278-287,297-300）
- evidence floor: weight_too_low→weak、missing_participant→moderate、role_reclassify/weight_too_high/dormant_participant→strong。未知型は strong。ランク `{None/""/insufficient:0, weak:1, moderate:2, strong:3}`（:265-275,303-311）
- recall-reducing 2 型は**現在の** scenario_store から role 保護を再検査（emit 後のロール変更への多層防御）。scenario 不在・target None・participant 不在・例外は全て return（:317-334）
- tier gate: marker `auto:scenario_improver:{type}` + `impact_override`。low は Tier≥1、med ≥2、high ≥3。low/med は HIGH cooldown 中なら拒否（:338-347）
- 適用は `scenario_apply.apply_scenario_improver_proposal`。例外は `shadow_metrics.record_failure` + WARNING、`ok` False は INFO のみで pending 維持（:350-372）
- impact=high の成功後のみ `trigger_high_cooldown`（既定 24h、low/med を停止）（:379-386）

### 台帳 API
- `list_pending`: `state='pending'` かつ `emitted_at > now − hours*3600`（既定 168h）を新しい順。`is_recall_reducing` = type ∈ {weight_too_high, participant_remove} を付与。JSON パース失敗は空 dict、DB 例外は空リスト（:680-740,91-94）
- `update_state`: 遷移先は {applied, dismissed, snoozed_30d, reverted, superseded} のみ、かつ `WHERE state='pending'`。台帳のみ更新（:743-762）

---

## B. scenario_apply（適用プリミティブ）

- サポート型は 5 種のみ: weight_too_low / weight_too_high / missing_participant / dormant_participant / role_reclassify。**scenario_discovery / 診断 3 種 / sensor_disable は明示的に非対応**（NP7）（:56-62）
- 検証順序 7 段: ①提案行ロード ②pending 検査 ③型検査 ④suggested JSON パース ⑤scenario ロード + `state=="active"` ⑥型別 mutation ⑦`validate_participant` → `scenario_upsert` → store reload → 台帳 flip（:118-306）
- 失敗コード 16 種の文字列（db_read_failed / proposal_not_found / proposal_not_pending / unsupported_proposal_type / suggested_value_json_invalid / scenario_not_found / scenario_not_active / target_country_required / target_not_a_participant / target_already_participant / weight not numeric / weight_to not numeric / role_to required / validation_failed / scenario_upsert_failed / ledger_flip_failed_after_mutation）
- **重み範囲クランプは scenario_apply 内に無い**。範囲強制は `validate_participant`（0.0–1.0）が担う。`_emit` の floor（0.10/0.95）とは別レイヤ → **提案 JSON を手で書き換えれば 0.0 や 1.0 も通る**（:243-249、scenarios.py:248-265）
- 型別 mutation: weight 系は role 保存 / missing は既存拒否・既定 0.30+strategic_observer / dormant は **`weight_to`** キー（weight 系と名前が違う）/ role_reclassify は `role_to` のみ変更（:180-240）
- `validate_participant` は**変更対象だけでなく mutation 後の全参加者**に走る → 既存の不正参加者 1 件で無関係な提案も適用不能（:244-249）
- 永続化は `scenario_upsert`、`changed_by=applied_by` が `scenario_change_log` に残る（NP6）（:252-268）
- **不変条件**: ステップ①〜⑤の失敗では DB 変更ゼロ・台帳 pending のまま
- **部分失敗を意図的に許容**: mutation 永続化後の台帳 flip 失敗は `ok=False` + `ledger_flip_failed_after_mutation` だが mutation は反映済み → **シナリオは新状態・台帳は pending という不整合が残り、再適用で二重変更しうる**（:274-294、DEFECT 候補）
- `_reload_scenario_store_and_invalidate_cache` は `routes.admin` の**意図的なコード複製**（循環 import 回避）。失敗は WARNING のみで適用は成功扱い（:76-93,271、DEFECT 候補: 二重メンテ）
- `applied_by` はアクター非依存で透過（`admin:<id>` も `auto:...` も同一 mutation）（:264,280）

---

## C. scenario_discoverer / structure_proposer / drift_watchdog / sensor_disable_proposer

### scenario_discoverer
- DBSCAN。`DISCOVERY_DBSCAN_EPS` 既定 0.6 / `DISCOVERY_DBSCAN_MIN_SAMPLES` 既定 3。距離は共起行列由来（:51-56,269-277）
- snapshot は `DISCOVERY_SNAPSHOT_FRESH_HOURS` 既定 23 以内なら再利用、超過で再計算（:59-76）
- 早期 skip 4 種: no_snapshot / empty_matrix / no_countries / persist_failed（:261-281）
- 永続 2 表: `scenario_discovery_run`（algorithm='dbscan', formula_ref=`scenario_discoverer/v1#dbscan`）+ `discovery_cluster`（annotation_state='none'）。1 トランザクション、失敗は WARNING + None（:82-124）
- **既存シナリオ重複 skip は Jaccard ≥ 0.7**。scenario_store 列挙失敗時は `existing = []` にフォールバック（= **全クラスタが提案される**）（:127-154）
- fingerprint = ソート済み国コード CSV（順序不変）（:165-174）
- 同一 fingerprint の既存 pending を INSERT 前に superseded 化。マッチは `json_extract(...)=?` **OR** `suggested_value_json LIKE '%"<先頭国>"%'` → **LIKE 側は先頭国が一致するだけの別クラスタを誤 supersede しうる**（:208-225、DEFECT 候補）
- 提案行は `scenario_id='__discovery__'` 固定。**`_emit` を経由しないため dedup 窓・active cap・auto-apply フック・evidence_strength 刻印を一切通らない**（:226-247）
- NP7: `scenario_discovery` は `_SUPPORTED_TYPES` に無く自動作成経路が存在しない

### scenario_structure_proposer
- source_type → role マップ 10 エントリ固定（apt_intel/hacktivist 系→adversary、military_exercise/ground_osint→forward_base、diplomatic→primary_ally、narrative 系→strategic_observer）。未登録は曖昧としてスキップ（:74-85,184-186）
- dominant の 2 段 floor: 件数 `STRUCTURE_PROPOSER_MIN_DOMINANT` 既定 5、シェア `STRUCTURE_PROPOSER_MIN_SHARE` 既定 0.50（:88-97,151-165）
- signal mix は `llm_intel` を `theater IN (participants) AND ts > cutoff` で `GROUP BY theater, source_type`。窓 `STRUCTURE_PROPOSER_LOOKBACK_DAYS` 既定 30。参加者 0 / 例外は `{}`（:107-148）
- role_reclassify: 推論 role == 現行 role ならスキップ。国コードは `mix.get(iso) or mix.get(iso.upper())`（:176-192）
- **role_reclassify は evidence に `evidence_strength` を書かないため、auto-apply の要求値 strong を構造上永久に満たせない（フラグ ON でもデッドパス）**（:197-218 × scenario_improver.py:268,303-311、DEFECT 候補）
- dormant_participant のガードは weight_too_high と鏡像 5 段。weight < `STRUCTURE_PROPOSER_DORMANT_WEIGHT` 既定 0.30 でスキップ（:100-104,237-273）
- 提案値 `weight_to = max(0.10, w − 0.20)`（**減算幅 0.20 ハードコードで improver の 0.15 と別値**）、action_hint="review_relevance"（:283-287）
- dedup / cap / auto-apply は `scenario_improver._emit` から private import で継承（:43-61,327-341）

### drift_watchdog
- drift_signal 実値は 7 種: sensor_outage / participant_silent / adversary_mismatch / recall_underperform / chronic_insufficient / participant_orphan / proposal_quality_inversion。**run_once の per-signal キー名は関数名由来の `weight_stale` のままで実際の signal 文字列と不一致**（:196-219,554-563）
- `_signal_weight_stale` 発火は AND: `weight > 0` かつ 30 日窓（`DRIFT_WEIGHT_STALE_DAYS`）の `sensor_observation_ts`(`scope='theater:<CC>'`) が 0 件、かつ同窓の当該シナリオ FN が 0 件。**DB 例外は「観測 0」扱いで signal は依然発火**（:43-44,150,161-192）
- 分岐: 全球被覆 degraded → `sensor_outage`/red、健全 → `participant_silent`/amber。被覆判定はループ前に 1 回計算して共有（:153-159,194-226）
- adversary_mismatch: amber、窓 `DRIFT_ADVERSARY_WINDOW_DAYS` 既定 60。3 条件 AND（adversaries 非空 / conclusions **≥ 50 件のハードコード floor** / adversaries の sequence_events 0 件）（:47-48,243-295、未検証）
- recall_underperform: red、コホート最小 `DRIFT_RECALL_COHORT_MIN` 既定 3。p25 はインデックス近似、`my_recall >= p25` なら空。母数は `conclusion_type='threat_level'` の feedback で `TP+FN < 10` のシナリオを除外（:51-52,298-331,405-425、未検証）
- chronic_insufficient: red、`DRIFT_CHRONIC_INSUFFICIENT_DAYS` 既定 14（:55-56,334-374、未検証）
- participant_orphan: amber、`COUNTRY_COORDS` に無い参加者ごと 1 件（:377-402）
- proposal_quality_inversion（`scenario_id='__system__'`）: 窓 30 日。`recall_negative_pct > 0.30` または（`closed_total ≥ 10` かつ `dismissed_pct > 0.50`）。最小サンプル `pending < 10 かつ closed < 10` で不発火。severity は breach ≥ 2 件 or `recall_negative_pct > 0.60` で red（:428-522、未検証）
- **emit は upsert**: 同一 `(scenario_id, drift_signal, target_country)` の unack 行が**直近 24 時間**に存在すれば `consecutive_runs += 1` と `emitted_at` 更新のみ（:75-118）
- **dwell-time ガードレール**: UI に出るのは `consecutive_runs >= 3` のみ（`list_unack_events(min_consecutive_runs=3, hours=168)`）（:580-608）
- watchdog はシナリオを一切変更しない（監視専用ゾーン）。`acknowledge` は unack 行のみ更新し emitted_at / consecutive_runs は保存（NP6）（:6-8,629-653）

### sensor_disable_proposer
- 対象は LLM ゲート済み 7 センサ固定タプル（:62-70）
- α（broken）判定: 7 日窓 `llm_call_log` で `pre_ratio >= SENSOR_DISABLE_ALPHA_PRE_FILTER`（既定 0.95）**または** `err_ratio >= SENSOR_DISABLE_ALPHA_ERROR`（既定 0.20）。errors = parse_failed + timeout + http_error（:77-83,158-194）
- 最小サンプル `SENSOR_DISABLE_MIN_CALLS` 既定 100 未満は分類自体を None（未稼働センサの誤 disable 防止）（:86-89,174-175）
- **fetch-layer 健全性ガード**（Phase A）合格条件は AND 3 つ: `ok_24h is not None and ok_24h >= 10 and not last_err`。合格すると LLM 側 α が真でも提案しない（「動いているセンサを切るよりプロンプトを締めろ」）（:133-155）
- ガードの早期 False 理由 6 種: registry_lookup_failed / sensor_not_in_registry / **already_disabled** / cb_open / fetch_telemetry_unavailable / fetch_unhealthy
  - **`already_disabled` は「再提案しない」意図なのに False（= 提案続行）を返す**（:117-155、DEFECT 候補）
- 提案行はスキーマ流用: `scenario_id='__system__'`、`proposal_type='sensor_disable'`、**`target_country` カラムにセンサ名を格納**、`suggested_value_json={"action":"disable","ack_due_at":...}`（:216-257）
- ack 窓 `SENSOR_DISABLE_ACK_HOURS` 既定 24h。既存 pending/applied は `_existing_pending` で検出、pending かつ ack 窓超過のときのみエスカレーション（:73-74,206-222,337-352、**エスカレーション経路は未検証**）
- **エスカレーション自動適用**は「ack 窓超過」+「`V2_AUTO_DISABLE_ENABLED`」の 2 段。**フラグ false でも台帳は必ず `state='applied'` に更新され `state_changed_by='auto:escalation_dry_run'` になる** → AP3 スコアボードや drift の closed/applied 集計が「実際には無効化していない」行で汚染される（:260-287、DEFECT 候補）
- `acknowledge` は「ack」と称して実際には `state='dismissed'` を書く → エスカレーションが恒久的にキャンセルされる（:388-398）

---

## D. 提案状態機械（scenario_proposals）

### 状態語彙
- **6 値のみ**（DB CHECK 制約が正規）: pending / applied / dismissed / snoozed_30d / reverted / superseded。既定 pending（database.py:1294）
- `accepted`/`rejected`/`auto_dismissed`/`expired` は**実在しない**。accepted≒applied、他は全て dismissed に畳み込まれ、区別は `state_changed_by` マーカー文字列のみ
- **`reverted` を `scenario_proposals` に書く経路は存在しない**（threshold_history 専用）
- 遷移主体は 4 経路: アナリスト API / scenario_apply / ライフサイクルフック D1-D5 / snooze 復活スイープ
- アナリスト遷移は `pending` からのみ（ホワイトリスト + `WHERE state='pending'`）。非 pending は静かに失敗（scenario_improver.py:743-762、**単体テストなし**）
- API 3 種: apply → applied（実配置も変更、`admin:<jwt>`）/ dismiss → dismissed / defer → snoozed_30d。エラー写像 404/409/500（routes/calibration_v2.py:278-388、**未検証**）

### auto_dismiss 4 種（条件・閾値・マーカーが全て別）
| フック | 条件 | マーカー |
|---|---|---|
| **D1** 非アクティブシナリオ | `sp.state='pending' AND s.state IN ('paused','archived')` — **時間条件なし**（0 秒前の行も対象） | `auto:inactive_scenario` |
| **D3** 診断型 | `pending` かつ type ∈ 診断 3 種 かつ `emitted_at < now − 7d`（`DIAGNOSTIC_AUTO_ACK_DAYS=7.0`）。シナリオ状態は見ない | `auto:diagnostic_acknowledged` |
| **D5** 実行可能型 | `pending` かつ `emitted_at < now − 30d`（`PROPOSAL_STALE_TIMEOUT_DAYS=30.0`）かつ 非診断型 かつ `s.state='active'` | `auto:timeout_no_action` |
- D1/D3/D5 は同一ティック（`_cycle % 24 == 10`）で連続実行。**1 つ例外を投げると以降がスキップ**（try 一括）（scheduler.py:531-591）
- 判定基準は **`emitted_at`**（D3/D5）であり `state_changed_at` ではない

### supersede 2 系統
- **D2**: `(scenario_id, proposal_type, target_country)` の素の 3 カラム等値（fingerprint ハッシュ不使用）。NULL 意味論を明示分岐（`IS NULL` vs `= ?`）。自己排除 `id != ?`。DB 例外は 0 で握り潰し（proposal_lifecycle.py:474-527）
- 起動点は INSERT 直後（`_emit` 内）。dedup 窓 7 日内は emit 自体がブロックされるため、**supersede の実効対象は窓外に生き残った古い pending だけ**
- **Discovery 型のみ fingerprint 系統**（C 節参照）
- マーカー 3 種で監査可能: `auto:supersede_by_id_<新ID>` / `auto:phase_d_fingerprint` / `admin:<user>`

### snooze 復活
- `state='snoozed_30d' AND state_changed_at < now − snooze_days*86400` → pending、`auto:snooze_expired`。`PROPOSAL_SNOOZE_DAYS` 既定 `"30"`（**int パース**）（database.py:5522-5545）
- **基準時刻は `state_changed_at`**（Defer を押した時刻）で D3/D5 と非対称
- 呼び出しは `cleanup_old_data()` 末尾、結果は `deleted["proposals_snooze_revived"]`（キー名は deleted だが実際は復活数）
- **【重大な相互作用の穴・未検証】** 復活は `state_changed_at` を更新するが `emitted_at` は据え置く。D5 は `emitted_at` で判定するため、**emit から 30 日以上経った提案が snooze 満了で pending に戻った瞬間、次ティックで即 `auto:timeout_no_action` で dismissed になる**。既定設定（snooze 30d = stale 30d）では **Defer した提案は必ずこの経路に落ちる**

### ガード設計原則 P1〜P5 と実装の乖離
- **P1 Role-Tier Protection**: PROTECTED_ROLES 4 種。`REQUIRES_CONFIRM_ROLES = {primary_ally, forward_base, extended_deterrence}` は Wizard の NP7 確認モーダルを要求する別層
- **P2 Multi-Source Triangulation**: SOURCE_NAMES 5 種。`is_truly_dormant(min_zero_sources=5, require_zero_fn=True)`。**docstring は「≥4 of 5」だが実装は 5/5**（2026-04-29 事件後に締めた際の記述ドリフト）
- 5 ソース収集クエリ: llm_intel は `COUNT(DISTINCT id) WHERE ts > ? AND (theater=? OR countries LIKE ...)`（二重計上防止）/ sequence_events / sensor_observation_ts / **analyst_feedback_fn は国フィルタ無し（グローバル集計、コード内で「保守的に過剰計上」と自認）** / conclusions_contribution
- **【副作用】FN のグローバル集計により、30 日窓内にどこか 1 件でも FN ラベルが付くと、あらゆる国の weight_too_high / dormant_participant が emit 不能になる**（_proposal_guards.py:189-193 × :412-413）
- **P3 Scenario Vitality**: 3 状態。分岐順 ①参加者 0 → dormant ②`total < floor AND coverage < min_cov` → **data_gap**（両方悪いときはセンサー側を先に疑う）③`coverage < min_cov` → data_gap ④`total < floor` → dormant ⑤ else active。floor 既定 5、min_cov 既定 0.3
- **P5 evidence_strength ラダー**: ①role_protected → insufficient ②`analyst_feedback_fn > 0` → insufficient ③zeros≥5 → strong ④zeros≥3 → moderate ⑤zeros≥1 → weak ⑥else insufficient。**docstring は「strong=4+, moderate=2-3」でリテラルに誤り**
- Phase B 追加ガード `sensor_coverage_healthy(days=30, min_global_signals=50)`: 上流 API 障害で全センサーが黙り「5/5 ゼロ=strong」が全参加国で成立する全滅提案事故の防止。**scenario_contribution_log は集計に含めない**（任意テーブルの欠損で判定を下げないため）
- **【重要】`evaluate_for_country` と `is_truly_dormant` は本番コードから一度も呼ばれていない**。実際の weight_too_high は 4 ヘルパーを個別に呼ぶ再実装経路。**GuardDecision の 3 フラグ算出式はテストでのみ実行される仕様**（scenario_improver.py:468-511 vs _proposal_guards.py:441-483）
- 2026-04-29 事件（25 件の weight_too_high が全 5 シナリオの primary_target に発火）の回帰テストが TW/CN/US/UA/RU の遮断を固定

### 抑止時の記録
- **`rejection_reason` 列は存在しない**。ガードが emit を止めた場合、行が作られないため**永続的痕跡はゼロ**（database.py:1280-1298）
- 残るのは 3 種の非永続記録: ログ / `GuardDecision.blocking_reasons`（プロセス内のみ、`needs_more_data` 経由でのみ別行に転記）/ emit された行の `evidence_strength`・`vitality_state` 列からの事後推論
- **`build_needs_more_data_event` の本番呼び出し元は存在しない**（`_rule_weight_too_high` は単に continue するだけ）→ P4 の代替表現は現状死んでいる

### D4: 既存 pending の auto-apply ゲート再投入
- `reprocess_pending_through_gate()` 返却 7 キー。`REPROCESS_MAX_AGE_DAYS=30.0`、`REPROCESS_MAX_PER_TICK=3`、過剰フェッチ `LIMIT 3*8=24`（型/年齢スキップがレート枠を飢餓させないため）
- スキップ条件: impact None（型外）/ 30 日超 / 直前再読込で非 pending（同一ティック内の D1-D3 との競合対策）

### 記述ドリフト一覧（全て未検証）
1. P2 docstring「≥4 of 5」vs 実装 5/5（`scenario_improver.py:457` にも複製）
2. evidence_strength docstring「strong=4+/moderate=2-3」vs 実装 5/3-4/1-2
3. P5 docstring「analyst FN ≥ 1」vs 実装 **FN == 0**（不等号が反転）
4. writer docstring の RECALL_NEGATIVE に `participant_remove` があるが `TYPE_TO_KIND` に無い。一方 `_is_recall_reducing()` は真とする → **2 箇所で recall-negative の定義が食い違う**
5. scenario_improver docstring「pending 行が毎 cron パスで evidence を更新する」— そのコードパスは存在しない
6. `_INACTIVE_SCENARIO_STATES` 定数は宣言されているが SQL はリテラル直書きで、定数を変えても挙動が変わらない

---

## E. auto_apply_tier_governor

### tier 状態機械
- 4 状態 0-3（proposal_only / low_apply / low_med_apply / full_apply）。表示名は別系統で 2 種併存
- Tier 0: いかなる impact も live ledger に書かない。Tier 1: low のみ。Tier 2: low+med。Tier 3: 全部
- `APPLIED_BY_IMPACT` 13 エントリ。規範は「recall を増やす方向は LOW、減らす方向は HIGH」（保留自体が recall 削減という NP1 論拠）
- **未知の `applied_by` は impact=low に既定分類**（「保守的既定」と称するが実際には**最も緩い**分類）
- `impact_override` は厳密に low/med/high のときのみテーブル参照をスキップ。タイポは無視してフォールスルー（迂回防止）
- `is_apply_allowed()` は例外時に必ず False（NP3 セーフデフォルト）

### 昇格・降格
- **0→1**: `auto_feedback_rows >= 100` の単一条件。dwell 要件も revert_rate 要件も無し。`governor_proposal_count` を要件にしないのは**鶏卵デッドロック回避**（Tier 0 では threshold_history が構造的に空）
- **1→2**: `days_at_tier >= 7.0` かつ `revert_rate_7d <= 0.05`（**昇格成立の直接テストなし**）
- **2→3**: `days_at_tier >= 14.0` かつ `revert_rate_14d <= 0.05`（未検証）
- 1 回の評価で最大 1 段階。`prior >= cap` なら常に None
- **v1-vs-v2 diff-log ゲートは 2026-05-29 に恒久削除**（v2 default-on 後は差異が期待動作であり移行比較の意味を失った。実測 0.45 が governor を恒久的に Tier 2 で頭打ちにしていた）。関連表は v54 で DROP 済み
- **降格は全 tier 共通で `revert_rate_24h >= 0.20` の単一条件**（3 定数は別々に定義されているが値は同一）。**直接テストなし**
- 降格判定が昇格より先（安全側バイアス）
- **降格は recall 劣化を直接の判定軸としない**。recall ゲートは提案単位（auto_tune_governor）の話で tier 遷移には影響しない → docstring の「NP1 — recall_gate は昇格評価前に成立」は継承前提であって tier 側での再チェックは未実装
- ヒステリシスは「昇格 ≤0.05（7d/14d 窓）」対「降格 ≥0.20（24h 窓）」の非対称性で実現
- **`governor_proposal_count` と `governor_accept_rate` は収集されるが判定に一切使われない死んだメトリクス**。後者は真の受理率でなく「窓内に 1 件でも受理があれば 1.0」のプロキシ

### revert_rate 計算式
- `threshold_history` を `emitted_at >= now − window*2.0` で読み、`(key, scope)` でグルーピングして時系列順に隣接ペアを走査
- ペア間隔が window を超えたらスキップ（pairs にも計上しない）
- **revert 判定は 3 点**: `long_delta = next − prev`、`short_delta = curr − prev`。`long_delta != 0` かつ **`short_delta * long_delta < 0`**（長期軌道と逆方向に動いた中間サンプル）
- **系統的過小評価バイアス**: 系列の最終ペアは pairs に計上されるが reverts には決して計上されない。float 変換失敗時も分母のみ増える
- `pairs == 0` / DB 例外で 0.0 → **データが疎な環境では昇格ゲートが常に通過し、降格が常に不成立**
- **`applied_by` による絞り込みが無い** → 人間の手動 revert や種まきデータも降格判定の母数に混入

### dwell time と marker 復旧
- `_days_at_current_tier()` の解決順序 4 段: ①marker が一致かつ `raw_tier > 0` → marker 由来 ②state-changing 行 → 行由来 ③marker のみ生存 → **WARNING + 復旧 `init` 行を書き込み** + marker 由来 ④無し → 0.0
- **marker と state が矛盾する場合は state が優先**（state 行が「記録上の台帳」という規範）
- **【契約違反】`governor_snapshot()` は「Pure read — no DB writes」と謳うが、marker 復旧経路により間接的に DB 書き込みが起きうる**（:814-816 vs :616-624）
- marker 更新は `_TIER_CHANGE_TRANSITIONS`（promote/demote/circuit_breaker/kill_switch_engaged/init）かつ tier が変わるときのみ。unchanged / evaluation_failed のハートビートは触れない。**同一 tier への再遷移も entered_at を更新しない（dwell がリセットされない）**

### cooldown
- HIGH 後の cooldown 既定 **24.0h**（`AUTO_APPLY_HIGH_COOLDOWN_HOURS`、DB override なし）、low と med の 2 レベルに同時設定。**high 自身は対象外**（HIGH 直後も HIGH は通る）
- 絶対時刻で保存、UPSERT により HIGH のたびに窓が再計測。**tier 昇降格・circuit breaker・キルスイッチは cooldown をクリアしない。明示的削除 API も無い（自然失効のみ）**
- 発火判定は `APPLIED_BY_IMPACT.get(applied_by) == "high"` のテーブル参照のみで **`impact_override` を考慮しない** → 未知マーカー + override='high' では cooldown が発火しない
- env が不正値なら `float()` が ValueError → **cooldown が設定されないまま無音で終了**

### circuit breaker / キルスイッチ
- `CONSECUTIVE_FAILURE_LIMIT = 3`（env/DB override なし）。連続 3 回で tier を 0 に強制、`transition="circuit_breaker"`
- 連続失敗数は直近 6 行を走査し `evaluation_failed` が続く限り加算。**成功・昇格・降格・ハートビートのいずれでもリセット**
- **復帰経路は通常の昇格のみ**（0→1 = auto_feedback_rows ≥ 100）。専用の復帰ゲート・手動リセット API は存在しない
- `AUTO_CALIBRATION_TIER_CAP` は `[0,3]` にクランプ、**不正値は 3 にフォールバック（フェイルオープン）**。**DB override は未実装だが docstring は「or DB-stored config」と述べる**
- キルスイッチ判定は `cap < raw_prior`（生の格納 tier）で行う。cap 適用後の値を使うと真のキルスイッチ事象が記録されない
- キルスイッチ降格は 1 段階ずつでなく cap の値へ一気に落とす

### 遷移種別と監査行
- DB に書かれる transition は 6 種（init/promote/demote/circuit_breaker/kill_switch_engaged/evaluation_failed）。`unchanged` は返却値のみで**DB には書かれない**
- `init` 行はプロセス起動後の最初の評価（state 行 0 件）のときのみ
- `governor_snapshot()` は API/HUD/SETTINGS の単一真実源。15 キー。例外時は最小 well-formed ペイロード + `snapshot_error`
- **昇格ゲートの表示名が判定定数のキー名と一致しない**（定数 `max_revert_rate` vs 表示 `max_revert_rate_7d`/`_14d`）

### auto_tune_governor（提案単位の安全規則）
- `commit(proposal)` の**固定順序**: ①sample-size（`AUTO_TUNE_MIN_SAMPLE_N` 既定 30）②recall ゲート（red → 拒否）③tier ゲート ④cooldown（`AUTO_TUNE_COOLDOWN_HOURS` 既定 72h、`(key, scope)` 単位）⑤無変更ショートサーキット ⑥magnitude クランプ（`AUTO_TUNE_MAX_MAGNITUDE_PCT` 既定 10.0%）⑦永続化
- **ルール順序により tier ゲート拒否が cooldown より優先** → Tier 0 環境では全提案が `tier_gate` で落ち、以降のルールに到達しない
- magnitude 超過は**拒否せずクランプして受理**。台帳の `magnitude_pct` 列には要求値でなく**上限値（10.0）を記録**
- magnitude 式 `abs((new−prior)/prior)*100`。degenerate: `prior==0` かつ `new!=0` → 100.0、非数値（bool 含む）→ 常に 100.0
- クランプ式 `prior + sign(delta)*abs(prior)*(max_pct/100)`。**`prior == 0` はクランプせず new をそのまま返す** → 0 基準からの変更は magnitude 予算の対象外
- 初出キー（`prior_value is None`）は `magnitude_pct=0.0` で**上限チェックなしに verbatim コミット**
- **方向制限は未実装**（`abs()` で符号を無視）。方向の唯一の制約は impact 分類という上位ゲート
- cooldown をリセットするのは「同一キーへの成功コミット」のみ。失敗・拒否は窓を動かさない
- recall ゲートは `check_recall_baseline.evaluate_against_baseline(db_path=ハードコード, tolerance=0.05 ハードコード)` を遅延 import。**評価自体が例外なら False（= 許可）にフォールバック**（「不確実なときはブロックするより許可する」明示的判断）
- tier governor が import 不能なら `tier_gate` で**フェイルクローズ**（v52 未適用環境では全提案が落ちる）
- `ProposalOutcome.reason` の docstring に `'tier_gate'` が欠落（実際は 7 種）
- `Proposal`/`ProposalOutcome` は frozen dataclass（その場変更を構造的に禁止）
- `threshold_history` は新規行記録時に直前の active 行を `state='superseded'` + `effective_to` でクローズ。scope 解決はシナリオ付き → グローバルのフォールバック

### 永続化スキーマ
- `auto_apply_tier_state`（v52）: append-only、`idx_..._observed ON (observed_at DESC)`
- `auto_apply_cooldown`（v52）: `impact_level` PK の UPSERT 管理
- `auto_apply_tier_marker`（v53）: 単一キー `current_tier_entered_at`。v53 は既存履歴から `INSERT OR IGNORE` でバックフィル（冪等）
- 再起動時の復元は完全に DB 駆動でプロセス内キャッシュを持たない
- repository は `conn_factory` の依存注入形式。必要なインタフェースは `execute` と `writing()` の 2 つのみ
- **全メソッドが DB エラーを握り潰して良性デフォルトを返す**（NP3）。テーブル欠損時も tier 0 相当で動作
- `_STATE_CHANGING_TRANSITIONS`（repository）と `_TIER_CHANGE_TRANSITIONS`（governor）は内容同一だが**別々に定義され同期は手動**

### スケジューラ統合
- `_cycle % 24 == 8`（日次、オフセット 8）。docstring は「毎時でも問題ない（cooldown/dwell ゲートが支配的）」と規定
- スケジューラ側で例外を捕捉（governor 内部でも捕捉 = 二重防御）

### CI ガードレール（テスト側の重要事実）
- `_block_live_db_access` autouse フィクスチャが `db._get_conn` を例外送出に差し替え、注入 repository を迂回する経路を即失敗させる。**Phase 1 で「リファクタ前のスイートが毎回本番 tier 履歴を truncate していた」ことを受けて導入** ← D2 B-08（テストの本番 DB 汚染）の既知の先例

### 設定キー総括（env のみ、DB override は一切未実装）
| env var | 既定 | 効果 |
|---|---|---|
| `AUTO_CALIBRATION_TIER_CAP` | 3 | tier 上限。0 で auto-apply 全停止 |
| `AUTO_APPLY_HIGH_COOLDOWN_HOURS` | 24.0 | HIGH 後の LOW/MED 停止時間 |
| `AUTO_TUNE_MAX_MAGNITUDE_PCT` | "10.0" | 1 コミットの変化上限（%） |
| `AUTO_TUNE_COOLDOWN_HOURS` | "72" | 同一キー再チューンの最短間隔 |
| `AUTO_TUNE_MIN_SAMPLE_N` | "30" | 提案受理の最小サンプル数 |

**ハードコードで変更不能**: `CONSECUTIVE_FAILURE_LIMIT=3`、全昇格閾値（100/7.0/14.0/0.05）、全降格閾値（0.20）、recall ゲートの tolerance=0.05 と db_path、recent_transitions 表示件数 10、reason 切り詰め 200 文字、失敗走査幅 6、revert_rate クエリ窓倍率 2.0
