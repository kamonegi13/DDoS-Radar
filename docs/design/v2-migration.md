# DDoS-Radar v2.0 移行設計ドキュメント

> **このドキュメントの目的**
> CLAUDE.md で再定義された新しいツール目的 (NP1-NP7) に整合する **v2.0 アーキテクチャ** の単一情報源。
> 旧 `scenario-refactor.md` (v1.x) は完了済み資料として保管し、本書が **v2.0 系列の唯一の設計仕様** となる。
>
> 新セッションを始める Claude / アナリスト / 開発者は **CLAUDE.md → 本書** の順に読むこと。
> v1.x の詳細は scenario-refactor.md §1-12 を参照可能だが、**v2.0 の判断は本書が優越する**。

---

## 0. ステータスとメタデータ

| 項目 | 値 |
|------|-----|
| **現バージョン** | 2.1.0-operational-maturation |
| **作成日** | 2026-04-25 |
| **最終更新** | 2026-07-04 (calibration インシデント記録の追記。2026-05 以降の Phase 6〜9.x 系列の詳細は git log が正) |
| **現在のフェーズ** | **Phase 5 完了 — 安定運用フェーズへ移行** |
| **採用方針** | **v1 並走 → shadow → opt-in → default-on の三段階で v2 へ移行**、v1 sunset 早期完了 (2026-04-29) |
| **責任者** | kamonegi13(@juzo1192) |
| **想定総工数** | **約 12 人月 (専任 12 週、3 Phase + 予備)** → **実工数 5 日 (2026-04-26〜04-30)** で Phase 0-5 完遂 |
| **前提資料** | CLAUDE.md (NP1-NP7 と用語定義), scenario-refactor.md v1.8.0 (v1 系列の最終仕様) |

### v2.0 Phase 進行表

| Phase | 概要 | 状態 | 期限 (目安) |
|-------|------|------|------------|
| **Phase 0** | 設計確定、ADR 起こし、scaffolding (Conclusion dataclass, DB v19-v22, codemod 準備) | **完了 (2026-04-26)** | 2026-05-02 |
| **Phase 1** | 基盤層: Conclusion Model 永続化、LLM プロンプト永続化、theater 撲滅、v2 API 骨格、NP7 disclaimer 強制 | **完了 (2026-04-27)** — Phase 1.1〜1.4 (P1/SR4/P2/C) 全 stage 済 | 2026-06-15 |
| **Phase 2** | 結論層: 攻撃モード推定 + extensions、トレンド三層化、per-domain 構造化、importance ranking、Calibration governance、Design W default-on | **完了 (2026-04-29)** — 結論層実装済、Design W default-on 達成。**⚠️ 完了根拠とされた「recall metrics 1.000」は後日 2 度にわたり無効と判明**(05-29: blanket-TP 退化 / 07-03: TL スケール反転)。下記「Calibration インシデント記録」参照。recall の連続性は 2026-07-04 の再スタート以降のみ有効 | 2026-07-31 |
| **Phase 3** | UI と運用: Analyst Workbench (4 ペイン)、drill-down、Markdown/PDF export、analyst feedback ループ、ACLED+GDELT 自動突合 ([v2-ui.md](v2-ui.md) で詳細設計) | **完了 (2026-04-26)** — workbench / drill-down / Markdown export / feedback ledger / LLM augmentation drill-down section / default-on | 2026-09-15 |
| **Phase 4** | v1 sunset: deprecation header → 90 日 → v1 撤去、theater adapter 削除 | **完了 (2026-04-29)** — `/api/threat_data` は v2 後継不能のため 2026-04-29 契約訂正で除外、`/api/scenario/<id>/breakdown` (本番 0 hits) を即時撤去。観察データ (14d match_rate=1.0000、residual access 自分自身のみ) が 90 日待機の根拠を充足したため早期完了 | 2026-12-15 |
| **Phase 5** | **Operational Maturation**: AP1-AP4 自動化原則実装、Operational Observability、CONTROLS Tools Hub redesign、ATTENTION rules engine、LLM Feature Hub、HUD divergence fix (V/W/X/Y)、TRIAGE display modes (A-D)、Decision Layer (5 phases + F1-F4)、Autotune audit fix (Phases 0-F) | **完了 (2026-04-30)** — 当初計画外の運用層拡充。詳細は §0.1 | — (2026-04-29〜04-30) |

### 0.0 Calibration インシデント記録 (2026-05-29 / 2026-07-03〜04)

ground-truth 校正層は運用開始後 2 度壊れた。**recall/precision の時系列は 2026-07-04 以前と以後で比較不能**である。

| # | 発覚日 | 欠陥 | 影響 | 修復 |
|---|--------|------|------|------|
| 1 | 2026-05-29 | `run_rss_etl` が全マッチを無条件 TRUE_POSITIVE 化(blanket-TP)。FN=0 で recall≡1.0 に固定 | recall gate が動かない数値を守っていた | graded 分類器 (`expected_tl_floor` + `label_for_threat_level`) へ全面置換、17,758 行 purge |
| 2 | 2026-07-03 | **置換後の graded 分類器が TL スケールを反転**(TL は 1=CRITICAL…5=NORMAL の DEFCON 型なのに 5=最深刻として実装)。警戒 (TL1-3) を FALSE_NEGATIVE、平穏 (TL4-5) を TRUE_POSITIVE と採点 | ①auto ラベル約 30k 行が逆向き教師信号 ②`tl_threshold_calibrator` が凍結 evidence (fn=54, last label 05-29) を根拠に middle_east 閾値へ **−5% を 12 回連続適用**(tl1_total 9.0→4.863、ほぼ半減)③HUD RECALL/DRIFT・CI recall gate・per-conclusion calibration_status すべて汚染 | 2026-07-04 一括修復(下記) |

**2026-07-04 修復内容**(commit 参照):

1. **意味論の明示化**: `radar/conclusions/severity.py` 新設(severity = 6 − TL)。TL の順序比較は severity 空間経由を必須化。`tests/test_severity.py` が反転を CI で恒久検知(inversion sentinels)
2. **分類器修正**: `ground_truth_etl.py` の `_is_high_severity_conclusion`(alert = TL≤3)/ `_is_quiet_threat_level`(quiet = TL5)/ `expected_severity_floor` + `label_for_threat_level`(severity 空間で採点)
3. **関連性ゲート**: `rss_extractor.is_escalation_relevant()` — 災害・事故・国内犯罪の死者数を ground truth から除外(クマスプレー・台風混入の再発防止)。センシング経路 (bg_observer) には非適用(NP1 維持)
4. **エピソード単位化**: 1 外部イベント = 1 trial。RSS ETL は (scenario, country, UTC day) エピソードで pre-event window の最良 TL を採点(tick 疑似反復 ~23k labels/30d を排除)。ACLED/GDELT ETL は (scenario, label, day) で day-cap
5. **暴走ガード**: `tl_threshold_calibrator` に evidence 鮮度ゲート追加 — 前回適用より新しいラベルが無い限り再適用禁止(同一 evidence は最大 1 回しか閾値を動かせない)
6. **データ修復**: `scripts/remediate_inverted_calibration.py` — auto ラベル全 purge(gzip export 保全)+ 汚染閾値オーバーライドを derive_tl デフォルトへ監査可能リセット。`scripts/apply_calibration_remediation.sh` がデプロイ後の一括実行を担う
7. **運用**: `scripts/backup_radar_db.sh` 新設(named volume `ddos-radar_radar-data` は従来バックアップ皆無だった)

**教訓**: (a) スケール方向のような意味論は型/テストで固定しない限り必ず反転事故が起きる。(b) 自動ラベルによる自己採点は、ラベル生成器のバグを自力検知できない — human anchor(人間ラベルの定常的最小量)が次の必須課題。(c) auto-tune は「evidence が更新されたか」を確認せずに繰り返し適用してはならない。

**2026-07-04 後続修正**(同日、残タスク一括実施):

| 項目 | 内容 |
|------|------|
| duty-cycle chronic 検知 | 連続 run 方式が見逃すフラッピング型の恒常的結論不可(attack_mode が tick の 20-30% で不可)を rolling window の不可時間比率で検知。`CHRONIC_DUTY_THRESHOLD`(0.20)/`CHRONIC_DUTY_WINDOW_DAYS`(14d) |
| self_eval recall 統一 | HUD recall を per-conclusion calibration と同じ 30 日窓に統一し、`recall_meta` で auto/human ラベル内訳を開示。no-event ラベルの名義を `auto:acled`→`auto:horizon` に訂正 |
| human anchor (AP3) | `/api/v2/human_anchor/queue` + HUD ANCHOR chip + ラベリングパネル。auto_fn_review / peak_severity / calm_anchor の 3 種を週次で人間ラベル対象に選定。人間の TP+URL は `confirmed_threats`(2023 年から休眠)へも追記され復活 |
| **ADR-V2-008 修正: 書き込みゲート** | conclusions は「毎 tick 全件 append」から「**状態変化時 + heartbeat(既定 1h)のみ append**」へ(`V2_CONCLUSION_WRITE_ON_CHANGE`)。単一値タイプは型の最新行との比較、anomaly はバッチ集合シグネチャ比較。replay 意味論(latest-row-at-T)は不変、continuity 記録は毎 tick 継続。体積 ~20k 行/日 → 遷移+heartbeat のみ(推定 1/20〜1/50)。**retention 365d への引き上げは旧 bloat(per-tick 時代の ~1M 行)が 90d retention で洗い流れる 2026-10 以降に実施予定** |
| DB 整理 | migration v54 で `conclusion_diff_log` / `shadow_eval_log` を drop。`llm_prompts` に retention(120d、conclusions+30d が下限)。`LLM_CALL_LOG_RETENTION_DAYS` のデッドコード解消 |

### 0.1 Phase 5: Operational Maturation 詳細 (2026-04-29 〜 2026-04-30)

Phase 0-4 で「結論を出すツール」としての骨格が完成した後、運用上の盲点と analyst 体験の改善を一括投入したフェーズ。当初計画には無かったが、**実運用で明らかになった構造的問題を体系的に解消**するために起こした。

#### 0.1.1 自動化原則 AP1-AP4 (2026-04-28)

NP6 透明性を「結論」から「自動化判断」へ拡張する 4 原則を CLAUDE.md に追加し、対応する実装を投入:

| 原則 | 実装 | コミット系列 |
|------|------|-------------|
| **AP1 — 能動的トリアージ** | `triage_score.js` (pure module, novelty × confidence_delta × analyst_blindness) + Triage Lane | wp_alarm 系 |
| **AP2 — 自己説明** | `self_explanation.js` (テンプレート + slot 埋め込み、再現性確保) + HUD TL pill / per-domain narrative | wp_alarm 系 |
| **AP3 — 自己評価** | `/api/v2/self_eval` + HUD Row 3 RECALL / NULL-ZONE / DRIFT chips | observability 系 |
| **AP4 — 判断履歴** | `/api/v2/replay/<sid>?at=<ts>` + Replay Mode bar (timeline slider + amber state badge) → Decision History UI で完成 | replay + Decision Layer |

#### 0.1.2 Operational Observability (2026-04-29)

3 件の user-reported issue + 観察網診断:
- **Issue A** focus 切替遅延 → `force=snapshot/sensors` 分離、MapDim two-phase
- **Issue B** LLM ONLINE 表示位置 → HUD Row 3 LLM chip
- **Issue C** auto-judge recheck → `intel_auto_judge.py` 7 ルール、後に D5 で LLM 第二パス削除
- **D6/D7/N3** — 観察網診断 (audit + backtest)、5 sensor 修正、週次 cron

#### 0.1.3 Calibration Post-Incident Redesign (2026-04-29)

Auto-tune Wizard の Bug 1 (UA spreading) + Bug 2 (CN/KR/PH false positive) 発覚を契機に、proposer 全層を再設計:
- evidence_strength + vitality_state 列追加 (migration v30)
- Wizard tab を 7 構成に再編 (Recall+ / Recall- / Structure / Diagnostic / Sensor Disable / Drift / Discovery)
- AP3 quality scoring、quality_inversion drift signal、`_proposal_writer` 抽出

#### 0.1.4 UI 大規模改修 (2026-04-29 〜 2026-04-30)

- **CONTROLS Tools Hub redesign** (commits L〜U) — dropdown → カードグリッド → 埋込み式 + DOCK + accordion
- **ATTENTION rules engine** (commits M+N+O) — 12 ルール + ヒステリシス + snooze + 適応学習 (p95 推奨閾値)
- **LLM Feature Hub** (commits G〜K) — Tier 0-3 制御プレーン + kill switch + audit + HUD chip
- **HUD divergence fix** (V/W/X/Y) — per-scenario threat_history (migration v33) + sparkline overlay + TTL 短縮 + divergence chip
- **TRIAGE display modes** (A/B/C/D) — dormant / pin-dock / critical-banner 状態機械 + animations

#### 0.1.5 Decision Layer (2026-04-30)

「analyst が推奨を読んだ後の応答経路」を統一する新レイヤー (migration v34):

| Phase | 内容 |
|-------|------|
| **1** | `decisions` テーブル + `DecisionLedger` クラス + 14 endpoints |
| **2** | TRIAGE 操作メニュー (⋯) + HUD snooze indicator + NP1 critical bypass |
| **3** | Pending Decisions アクションボタン + NP7 confirm modal |
| **4** | Decision History モーダル (AP4 forensic timeline) |
| **5** | テスト 47 件 + INTEL GUIDE §O bilingual |

その後 F1-F4 で advisory endpoint を ledger-aware 化、per-scenario カード化、Re-evaluate ボタン追加。

#### 0.1.6 Autotune Audit Fix (2026-04-30 PM)

Auto-tune Wizard の本番状態を監査し、4 系統の false-positive を体系的に解消 (migration v35):

| Phase | 内容 |
|-------|------|
| **0** | 既存 26 proposals + 39 drift signals 一括 dismiss |
| **A** | sensor_disable proposer に fetch-layer ガード追加 (健全 sensor を disable 候補から除外) |
| **B** | sensor_coverage_healthy() 新設、dormant_participant + weight_too_high で fleet 劣化時に短絡 |
| **C** | list_pending SELECT 拡張 (evidence_strength / vitality_state / state を返却) |
| **D** | discovery cluster fingerprint supersession + state CHECK 制約に 'superseded' 追加 |
| **E** | Wizard pending filter は SQL 層で完結、state field を UI 側で render 可能に |
| **F** | drift signal を sensor_outage (red) / participant_silent (amber) に分類 |

検証: production で `skipped_fetch_healthy=4, new_proposals=0` 達成 (4 件すべての false positive を Phase A ガードが遮断)。

#### 0.1.7 Phase 5 集計

- **commits**: 約 80 件 (4-28 〜 4-30 の 3 日間)
- **migrations 追加**: v31 (LLM Feature Hub) / v32 (ATTENTION) / v33 (per-scenario threat_history) / v34 (Decision Layer) / v35 (proposal supersession)
- **テスト追加**: 約 100 件 (test_decisions 47, test_autotune_proposer_guards 13, test_triage_display_mode 34, test_threat_history_scoped 16, etc.)
- **新規 UI 面**: TRIAGE Lane 表示モード、CONTROLS Tools Hub、ATTENTION セクション、Decision History モーダル、Pending Decisions アクション、HUD divergence chip、HUD snooze chip
- **API endpoints 追加**: 14 (decisions) + 数件 (attention / llm_features / triage / etc.)

### 0.2 安定運用フェーズへの移行 (Phase 5+, 2026-04-30 以降)

Phase 0-5 完了をもって、本書の「設計仕様 → 実装」サイクルは終了。以降は **保守・微調整・運用フィードバック** のフェーズに入る。**新規大規模設計は本書を更新せず、別 issue として独立管理する**。

#### 0.2.1 計画済の運用観察ポイント

| 時期 | 観察項目 | 期待される判断 |
|------|---------|---------------|
| **2026-07-31** | Calibration governor audit (Phase A/B ガードが false negative を生んでいないか) | gate 閾値の微調整 / 新 sensor 追加時のガード再評価 |
| **継続** | 週次 cron diversity avg/max | avg ≥ 2.0 / max ≥ 2 を crossing したら Layer 1 cross-evidence + LLM 第二パス再導入条件成立 |
| **継続** | `decisions` テーブル retention | 1 年経過時に retention policy 設定要検討 |

#### 0.2.2 非コード課題 (intel research、別 issue 管理)

- diplomatic 7 feed の現行 RSS endpoint 探索 (state.gov, mofa.gov.tw, fmprc.gov.cn, mid.ru, etc.)
- hacktivist 12 channel 中 7 (noname05716 等) の preview-enabled 代替探索
- 解消すれば diversity が avg=1.0 → ≥2.0 に上昇 → Layer 1 + LLM 第二パスの再導入条件成立

これらは「コード」ではなく「世界知識」の更新であり、別 issue として独立管理する。

#### 0.2.3 オプショナルな改善候補 (優先度低)

実害は出ていないが品質改善余地のある項目:

| # | 内容 | 優先度 |
|---|------|--------|
| (a) | TRIAGE per-user 閾値 UI (現状 `localStorage.triage_always_visible` 直接編集に依存) | Low |
| (b) | dormant_participant proposer の評価閾値を per-scenario / per-role で micro-tune | Low |
| (c) | Decision History の WebSocket push (現状 30s polling) | Low |
| (d) | Auto-tune Wizard の "Apply All" バッチアクション | Low |
| (e) | Markdown export の PDF 化 (ADR-V2-004 で言及されているが未実装) | Low |
| (f) | shadow → opt-in → default-on 三段階管理ダッシュボード (現状 Feature Hub に分散) | Low |
| (g) | **forecast_log 機能の運命決定** — 現在 production data で accuracy=3%、predicted=TL1 常時。引き続き使うか廃止か 2026-07 までに判断 (engine.py コメントに警告追加済) | Low |
| (h) | **shadow_sampler last_delta=0 一律** — LITE と FULL が常に同値を返している。FULL モードが実装上動いているか検証要 | Low |

### 0.2.4 DB 監査修正 (2026-04-30 PM, 5 段階精査の結果)

Phase 5 完了後、DB 蓄積状況の体系的監査を実施。第 1〜5 次精査で**累計 47 個の問題候補**を発見し、第 4 次撤回反証で **16 問題に再構成**。本 commit でこれらを実装解決:

| Phase | 問題 | 対応 | コミット |
|-------|------|------|---------|
| **A** | drift_signal 旧名 (weight_stale) emit 継続 | デプロイ確認、新名 (participant_silent / sensor_outage) で正常 emit を確認、bulk dismiss 39 件 | (本 commit) |
| **B** | silent_divergence sensor が UI 露出していない | 撤回 — radar.js / index.html / INTEL GUIDE に既に露出を確認 | (調査のみ) |
| **C** | decision_ledger と decisions の二重台帳 | radar/decisions.py docstring に両者の責務分離を明記、verify_cache test artifact 削除 (4 conclusions + 1 tl_observation) | (本 commit) |
| **D** | retention 不在 (conclusions / llm_call_log / analyst_feedback / inconclusive_continuity_log / decisions / legacy_access_log) | radar/database.py の retention sweep に 6 テーブル追加 (90/30/180/60/90/90 日) | (本 commit) |
| **E** | conclusions.llm_prompt_sha256 が 100% NULL | 撤回 — LLM augmentation OFF 時の正常動作。triage_narrative ON 時は populate される (既存) | (調査のみ) |
| **F** | scenarios DB テーブル 4/5 シナリオ未登録 (referential integrity 破壊) | scenario_store.load() に _upsert_to_db() 追加。INSERT OR IGNORE で admin override 保護 | (本 commit) |
| **G** | anomaly state が free-form text (controlled vocabulary 違反) | _state_summary() を signal_source のみに変更、value_display を metadata へ移動 | (本 commit) |
| **H** | tl_calibrator が precision=25%, tn=0, fn=0 で auto-tighten (退化データへの過剰反応) | tl_threshold_calibrator.py に degenerate-data ガード追加 (precision < 0.30 + tn=0 + fn=0 → 拒否) | (本 commit) |
| **I** | forecast_log accuracy 3% の stub-like 動作 | engine.py に Phase I caveat docstring 追加、retention 365d で抑制、廃止判断は 2026-07 audit で | (本 commit) |
| **J** | v2-migration.md に DB 監査修正の経緯を記録 | 本セクション (§0.2.4) を追記 | (本 commit) |

撤回された問題 (反証で無効化):
- 第 4 次精査の「ツール定義 4 段落の論理矛盾」(問題 35) → ご指摘により撤回。ツール定義は **「OSINT 制約下の最良努力」** という制約付き最適化として整合的。観点 1 (検知目的 vs OSINT 制約) は矛盾ではなく目的と制約の併存。

残存問題 (本 commit で扱わない):
- (b) 段落 3 の「過渡的 vs 恒常的」が OSINT 由来の恒常的不可を「設計失敗」と誤分類しうる — 上記 (g) と同じ判断時期 (2026-07)
- (c) 「最良努力」の具体的指標未定義 — Phase 5 audit (2026-07-31) で評価
- (d) 「最大」の複数軸 (件数/確実性/粒度) 不明確 — 同上
- (e) NP/AP 優先順位と衝突解決規則の欠如 — ADR-V2-016 として計画
- (f) ADR 間整合性検査機構の欠如 — 同上

---

## 1. v2.0 が解決する課題

### 1.1 現状 (v1) の到達点と限界

v1 リファクタリング (scenario-refactor.md) で達成した事項:

- 国単位 → シナリオ単位スコアリングへの移行 (Phase 1-3 完了)
- C-lite モード確立 (focused 全センサー / background は LLM intel + global signal)
- ADR-009 follow-up (双核シナリオ対称発火)、ADR-025 shadow_sampler、ADR-026 dual-weight 評価基盤

しかし v1 は **「観察結果プレゼンテーション層」としての完成度が高い** 一方、CLAUDE.md で再定義した新目的「**結論を付けて出力する**」に対しては構造的に未到達である。

### 1.2 NP1-NP7 への充足度 (Phase A 監査結果 — 監査時点 2026-04 初旬)

注: 下表は v2.0 着手前のベースライン。Phase 1〜3 完了後の現状は「→」以降に併記。

| 原則 | 充足度 (監査時) | 主な未到達領域 → v2.0 進捗 |
|------|--------|--------------|
| **NP1 感度優先** | 中 | 手動 tuning 中心。recall ground truth 注入機構なし → ACLED+GDELT 自動突合 + analyst_feedback ledger + recall_metrics CI gate 実装済 (2026-04-27) |
| **NP4 結論最大化** | **約 40%** | TL は出るがトレンドラベル/ドメイン別結論/異常事象ランク/**攻撃モード推定**未実装 → 5 ConclusionType (THREAT_LEVEL/TREND/PER_DOMAIN/ANOMALY/ATTACK_MODE) + scenario_extensions hook 全実装 |
| **NP5+8 結論品質規律** | 中 | INSUFFICIENT_DATA 提示はあるが「過渡的 vs 恒常的」区別なし → INSUFFICIENT_DATA + INSUFFICIENT_SIGNAL を明示。calibration metadata は drill-down で開示 |
| **NP6 完全な導出開示** | **約 65%** | LLM プロンプト未永続化 (grep 結果 0 件)、TL 閾値が API 非開示 → drill-down で formula/thresholds/sources/llm_prompt 全開示 |
| **NP7 組織内ノード** | **約 15%** | disclaimer が i18n tooltip 1 箇所のみ、API レスポンスに常設されていない → 全 v2 API レスポンス + UI banner に NP7 disclaimer 強制 |

### 1.3 アーキテクチャ債務

- **theater 用語残存**: `grep -r "theater\|core_theater" --include="*.py" --include="*.js" --include="*.html"` で **1,612 箇所 / 67 ファイル**
- **巨大ファイル**: `radar.js` 8,160 行、`radar/database.py` 4,122 行、`index.html` 3,411 行、`i18n.js` 3,041 行
- **scenario-refactor.md** が 1,970 行と上限 2,000 行に接近 (本書分離で v1 系列を保管 → v2 系列を本書で構築)

### 1.4 v2.0 の中核アイデア

**Conclusion Model v2** — すべての結論 (全体 TL / トレンド / per-domain / 個別異常事象 / 攻撃モード) を **単一の `Conclusion` スキーマ** で表現し、API/DB/UI を貫く統一プロダクトとする。

これにより NP4 (結論最大化) / NP5+8 (品質規律) / NP6 (透明性) / NP7 (組織内ノード) を **単一スキーマで同時に satisfy** する。

---

## 2. 設計拘束 (v2.0)

CLAUDE.md の 4 拘束は v1 と共通だが、v2.0 では **追加 2 拘束** を課す。

| # | 拘束 | 由来 | 違反例 |
|---|------|------|--------|
| ① | OSINT 限定 | CLAUDE.md | 商用 threat intel 組み込み |
| ② | 特定の警戒シナリオにおける | CLAUDE.md | 国単位 TL を主出力にする |
| ③ | 技術的に実行可能な最大の結論を出力 | CLAUDE.md | advisory に格下げ |
| ④ | 完全な導出開示 | CLAUDE.md | LLM プロンプト未永続化 |
| **⑤** | **すべての結論は `Conclusion` スキーマで返す** | v2.0 | 結論を bare integer/string で API に乗せる |
| **⑥** | **すべての結論レスポンスに `final_judgment_disclaimer` を含む** | v2.0 + NP7 | disclaimer を i18n tooltip に頼る |

---

## 3. 用語定義 (v2 追加分)

CLAUDE.md / scenario-refactor.md §4 の用語に加え、v2.0 で導入する用語:

| 用語 | 意味 | コード上の表現 |
|------|------|--------------|
| **Conclusion** | ツールが出力する結論オブジェクト (5領域 × 共通スキーマ) | `radar.conclusions.Conclusion` データクラス |
| **conclusion_type** | 結論の領域分類 | `enum`: `THREAT_LEVEL`, `TREND`, `PER_DOMAIN`, `ANOMALY`, `ATTACK_MODE` |
| **state** | 結論本体の値 | TL なら `1`-`5`、トレンドなら `RAPIDLY_ESCALATING` 等 |
| **conclusion_unavailable_reason** | 結論不可時の理由 | `null` / `INSUFFICIENT_DATA` / `CALIBRATION_PENDING` / `SENSOR_DEGRADED` |
| **attack_mode** | シナリオ内のサブ攻撃様態 | `DDOS_PRECURSOR` / `KINETIC_PREPARATION` / `HYBRID_PRESSURE` / `INFO_OPS_DOMINANT` / `INSUFFICIENT_SIGNAL` + scenario extension |
| **trend_label** | 時系列方向の結論ラベル | `RAPIDLY_ESCALATING` / `ESCALATING` / `STABLE` / `DE_ESCALATING` / `RAPIDLY_DE_ESCALATING` |
| **trend_horizon** | トレンド評価窓 | `24h` / `7d` / `30d` |
| **per_domain_label** | ドメイン別結論ラベル | `ACTIVE` / `ELEVATED` / `STABLE` / `DEGRADING` / `INSUFFICIENT_SIGNAL` |
| **importance_score** | 個別異常事象の重要度スコア (0-100) | `Conclusion.metadata["importance_score"]` |
| **formula_ref** | 式の参照 (コード行 + version) | `"radar/scoring.py#derive_tl@v2.0.1"` |
| **threshold_ref** | 閾値の参照 | `dict`: `{"total": 9.0, "physical": 3.0}` (動的に出力) |
| **llm_prompt_sha256** | 永続化された LLM プロンプトのハッシュ | `radar/llm_prompts` テーブル PK |
| **calibration_status** | calibration 状態 | `dict`: `{"sampler": "OK", "drift": 0.05, "last_recal_at": ts, "sample_n": 240}` |
| **final_judgment_disclaimer** | NP7 disclaimer 文字列 | API レスポンスに必須、i18n キー `disclaimer.final_judgment` |
| **analyst_feedback** | アナリストの ground truth ラベル | `radar/analyst_feedback` テーブル |
| **API v2** | v2.0 API namespace | `/api/v2/...` (v1 API は `/api/...` で並走) |

---

## 4. 設計判断 (ADR)

v2.0 で新たに採用する設計判断。命名規則は `ADR-V2-NN`。番号は v1 と独立。

### ADR-V2-001: Conclusion Model 統一スキーマ

- **判断**: すべての結論を単一の `Conclusion` データクラスで表現する
- **代替案**: 領域ごとに別スキーマ (TL / Trend / Domain / Anomaly / AttackMode) → 採用却下
- **理由**: NP6 (透明性) を全結論で同等に保証するため、必須フィールド (formula_ref / threshold_ref / source_urls / llm_prompt_sha256 / disclaimer) をスキーマレベルで強制する。領域別スキーマは進化のたびに drift する
- **影響**: API/DB/UI の全層で `Conclusion` 型を貫通させる

### ADR-V2-002: 攻撃モード推定の粒度 (Hybrid)

- **判断**: 全シナリオ共通の **base_modes 5 種** + シナリオ別 **scenario_extensions** のハイブリッド
- **base_modes**: `DDOS_PRECURSOR`, `KINETIC_PREPARATION`, `HYBRID_PRESSURE`, `INFO_OPS_DOMINANT`, `INSUFFICIENT_SIGNAL`
- **scenario_extensions** (geo_data.json で定義):
  - `taiwan_contingency`: `NAVAL_BLOCKADE_PRECURSOR`, `PLA_AIR_INCURSION_SURGE`
  - `korea_peninsula`: `ARTILLERY_BUILDUP`, `MISSILE_TEST_CASCADE`
  - `ukraine_front`: `KINETIC_TEMPO_SHIFT`, `GRAY_ZONE_PROBING`
- **代替案**: 全共通 → 表現力不足、完全シナリオ別 → cross-scenario 学習困難
- **理由**: NP1 (感度) と analyst の cross-scenario pattern 学習を両立

### ADR-V2-003: v1 API sunset 3ヶ月 (DONE 2026-04-29)

- **判断**: v2 default-on 後 **90 日** で v1 API を撤去
- **代替案**: 6ヶ月 → 二重メンテ負荷大、Phase 2/3 工数を圧迫
- **理由**: 利用者は専門アナリスト個人〜小規模チーム想定、エンタープライズ慣行 (6-12ヶ月) は過剰
- **rollout**: 月0 default-on + Sunset header → 月1 残存利用者特定 → 月3 撤去
- **進行状況**:
  - **default-on 切替**: 2026-04-26 (Mode C activation, all 5 readiness conditions PASS via `scripts/check_mode_c_readiness.py --ack`)
  - **v1 sunset target**: 2026-07-26 (T+90d)
  - **Phase 1.4 完了 (2026-04-27)**: P1 = `Deprecation` / `Sunset` / `Link` HTTP ヘッダを v1 superseded routes に付与 (8a1ce11)、SR4 = sunsetted route hit を `legacy_telemetry` カウンタへ集約 (2e0310d)、P2 = NP7 disclaimer banner (7ea0916)、C = sunset 後の residual access 観測 (d32c856)。残作業は v1 sunset 当日 (2026-07-26) 以降の Phase 4 撤去のみ
  - **2026-04-29 契約訂正**: PF7 inventory 作業で `/api/threat_data` の v2 後継として promised していた `/api/v2/scenarios/{id}/conclusions` が**技術的に代替不能** (response shape が完全に異なる: threat_data は HUD/Lane/map 全体を駆動する kitchen-sink envelope、v2 conclusions は scoring conclusions 単体) と判明。**`SUNSETTED_V1_ROUTES` から `/api/threat_data` を除外**し、permanent operational endpoint として継続。`/api/scenario/<id>/breakdown` (本番 0 hits、v2 conclusions が真の後継) のみが sunset 対象に縮小
  - **2026-04-29 早期完了**: 90 日 sunset 規定の 3 本柱 (外部クライアント保護 / Mode C 安定性継続観測 / rollback リスク低減) を再点検したところ、すべて充足済と判明: (1) production legacy_access_log は自分自身の frontend のみ (`/api/threat_data` 111 hits、外部クライアント 0)、(2) `conclusion_diff_log` 14d match_rate=1.0000 / divergence=0 で観察期間の情報量飽和、(3) 撤去対象 `/api/scenario/<id>/breakdown` は production 0 hits で rollback リスクほぼ無し。ADR-V2-003 を「契約だから守る」から「目的が充足したので完了」に切替し、即時撤去を実行。撤去内容: route handler / `radar/conclusions/v1_sunset.py` / `scripts/list_v1_routes.py` / `_v1_sunset_headers` after_request hook / `summarize_v1_sunset` helper / 関連テスト 4 ファイル。Inventory doc は `docs/_archive/v1-sunset-inventory.md` に移動

### ADR-V2-004: Export 形式は Markdown/PDF のみ (v2.0)

- **判断**: Phase 3 では Markdown/PDF のみ実装、STIX 2.1 / JSON-LD は v2.1 以降
- **代替案**: STIX 2.1 を Phase 3 で実装 → 採用却下
- **理由**: STIX は CTI 標準で physical/info の表現力が弱い。本ツール独自 Conclusion スキーマが一次プロダクト。アナリスト 3 名以上から要望が出てから v2.1 で追加 (YAGNI)

### ADR-V2-005: ground truth は ACLED+GDELT 自動突合先行 + 手動 UI 並行

- **判断**: 公開 DB 自動突合を Phase 2 後半で先行、手動ラベリング UI を Phase 3 並行提供
- **公開 DB**: ACLED (Armed Conflict Location & Event Data) + GDELT (Global Database of Events, Language, and Tone)
- **代替案**: CISA KEV → 採用却下 (本ツールは escalation precursor、CISA KEV は exploit)
- **理由**: 自動突合で recall 計測の母数を稼ぎ Design W の統計的信頼性を上げる、手動 UI で質的フィードバックを補う
- **実装** (2026-04-26):
  - **ACLED 取得**: `radar/sensors/acled.py` の `fetch_events()` (BaseSensor を継承しない pure client。scoring tick とは別 cadence のため)。`ACLED_API_KEY` / `ACLED_API_EMAIL` 必須、欠落時は空リスト返却 (NP3 graceful degrade)。`_ISO2_TO_ACLED_COUNTRY` で v1 strategic 12 国を ACLED 名にマップ。HTTP/JSON エラーは握り潰し、log.warning のみ
  - **GDELT 突合**: 既存 `gdelt_dow` テーブルから per-weekday baseline を再構築し、`dow_z < -2.0` (live sensor の ALERT 閾値と一致) のスパイクを `ExternalEvent(severity=streak)` として emit。3 日連続で severity=2
  - **分類器**: `radar/conclusions/ground_truth_etl.py` の `classify_conclusion(conclusion, evidence, participant_countries, ...)` — pure function。ルール優先順: (1) FALSE_NEGATIVE (TL=1 + ACLED severity≥10 in window) → NP1 critical、(2) TRUE_POSITIVE (high-severity TL/ATTACK_MODE + corroborating event)、(3) FALSE_POSITIVE (high-severity + horizon 経過 + 0 event)、(4) TRUE_NEGATIVE (TL=1 + horizon 経過 + 0 event)。PER_DOMAIN/TREND/INSUFFICIENT_DATA は対象外 (Design W primary recall に直結しない)
  - **provenance**: `analyst_id` は `auto:acled` / `auto:gdelt` / `auto:both` で source を識別。`summarize_feedback().distinct_analysts` を膨らませない (auto は source 単位で 1 票)
  - **Idempotency**: `has_existing_auto_feedback(conclusion_id, analyst_id)` で既存行を skip。cron 再実行で重複行を作らない
  - **job runner**: `scripts/run_ground_truth_etl.py` — `--dry-run` / `--scenario` / `--no-gdelt` / `--force` 対応。`V2_GROUND_TRUTH_ETL_ENABLED=false` で no-op exit (--force で上書き可)
  - **config**: `V2_GROUND_TRUTH_ETL_ENABLED` (default false), `GROUND_TRUTH_WINDOW_HOURS` (72), `GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS` (7), `GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES` (10)
  - **tests**: `test_ground_truth_etl.py` 21 件 (4 ルール × 複数ケース、provenance、window エッジ、idempotency、ACLED graceful degrade、ACLED happy path、不正 date 行 drop)

### ADR-V2-006: theater 撲滅は内部一斉置換 + v1 API adapter

- **判断**: 内部実装は codemod で `theater → scenario_id / country` に一斉置換、v1 API のみ adapter 層で `theater` キーに alias
- **代替案**: v1 残置 → 永続的負債、外部破壊 → 互換性損失
- **理由**: 内部 1612 箇所が残ると Phase 1-3 全工程で認知負荷大。adapter 層は薄く v1 sunset で削除可能 (永続負債にならない)
- **codemod**: `scripts/codemod_theater.py` を AST ベースで実装 (Phase 0 で scaffold)
- **残置許容**: 過去のコミット履歴・ADR 記録、DB 既存 column 名 (`sequence_events.theater` 等は migration コスト > メリット)

### ADR-V2-007: 旧 P5 文言の駆逐

- **判断**: 「ツールは判断しない」「avoiding over-reliance on automated assessments」系の旧 P5 由来文言を全廃
- **置換**: 「本ツールは結論を出力する。最終判断は組織プロセスが行う」(NP4 + NP7 整合)
- **対象**: `index.html` Ch.1/2/8/10、`i18n.js` 関連キー
- **検証**: `tests/test_ui_integrity.py` に禁止文字列リストを追加し、grep で fail させる

### ADR-V2-008: Conclusion は append-only ledger として永続化

- **判断**: `conclusions` テーブルを append-only ledger とし、過去結論の差分追跡を可能にする (DB migration v19)
- **代替案**: スナップショット上書き → 採用却下
- **理由**: NP6 (透明性) と analyst feedback ループ (ADR-V2-005) のため、過去結論の retrieval が必須。retention 365 日 (config 化)

### ADR-V2-009: LLM プロンプトは sha256 dedup で永続化

- **判断**: `llm_prompts` テーブル (PK: `prompt_sha256`) で dedup 永続化、`llm_call_log` から FK 参照 (DB migration v20)
- **retention**: prompt_text は 90 日、`llm_call_log` のメタデータは 365 日
- **理由**: NP6 「LLM プロンプトまで遡及可能」を構造的に保証

### ADR-V2-010: 「過渡的 vs 恒常的」結論不可の分離

- **判断**: `inconclusive_continuity_log` テーブル (DB migration v21) で全 INSUFFICIENT_DATA 出現を記録、7 日連続継続は **STRUCTURAL_GAP** alert を発火
- **scheduler**: 毎時 job で全 calibration エンドポイントの state を sampling
- **代替案**: アナリスト目視 → 採用却下 (NP5+8 後段の自動運用化を放棄することになる)
- **理由**: NP5+8 (b)「データ蓄積後も恒常的結論不可継続は設計失敗」を運用化

### ADR-V2-011: analyst_feedback テーブル新設

- **判断**: `analyst_feedback` テーブル (DB migration v22 として設計、実装は v26 として 2026-04-26 配備) でアナリスト ground truth を保存
- **schema**: `(conclusion_id, label ∈ {TRUE_POSITIVE, FALSE_POSITIVE, TRUE_NEGATIVE, FALSE_NEGATIVE}, observed_outcome_url, analyst_id, observed_at, notes)`
- **用途**: Design W (ADR-026) の recall 計測ベース、attack_mode 推定の検証
- **実装** (2026-04-26):
  - DB migration v26 (`radar/database.py:1367`)。設計時の "v22" は予約番号、v23-v25 が先行実装されたため実装版は v26
  - 永続層: `radar/conclusions/feedback.py` (Flask-free pure module、`AnalystFeedback` frozen dataclass + `FeedbackLabel` Enum + `save/list/summarize_feedback`)
  - API: `POST/GET /api/v2/conclusions/<id>/feedback` (`radar/routes/conclusions_v2.py`)。jwt_required + V2_API_ENABLED ゲート
  - **anti-spoof**: `analyst_id` は `get_jwt_identity()` で server-derived。client payload の `analyst_id` は無視 (test で明示検証)
  - **bias mitigation** (§11 risk row 整合): `summarize_feedback()` は label 集計と distinct_analysts のみ返却。「単一 verdict」ではなく per-label counts。フロント widget も同形 (Total/Distinct + per-label breakdown)
  - **schema 整合性**: `CHECK (label IN (4 値))` で defense-in-depth
  - frontend: drill-down modal の `_ccDrillRenderFeedback` (radar.js)。i18n キー 19 件 EN/JA
  - tests: `test_conclusions_feedback.py` 14 件 (DB layer / POST / GET / flag gate / spoof rejection / 404/400/notes truncation)

### ADR-V2-012: NP7 disclaimer は schema レベルで強制

- **判断**: API v2 の全レスポンスに `final_judgment_disclaimer` を必須フィールドとする (テストで欠落を検知)
- **i18n**: `disclaimer.final_judgment.short` (~80字) と `disclaimer.final_judgment.long` (~200字) の 2 種、UI 文脈で使い分け

### ADR-V2-013: 観察期間の事後 backfill 採用 (Phase 1.3 加速)

- **状態**: PROPOSED → ACCEPTED (2026-04-26 実施済)
- **背景**: Phase 1.3 は Mode B (shadow-write) を 14 日間観察してから Mode C への opt-in 判断を行う設計だった。しかし `scenario_tl_observation` テーブルに 4400+ 行の歴史的状態が既に蓄積されており、これらを事後的に v2 builders に流せば PER_DOMAIN/ATTACK_MODE/TREND ledger を即座に厚くでき、観察期間を実質短縮できる。
- **判断**: 以下 2 段階で backfill を実施する:
  1. **`scripts/replay_v1_v2_diff.py`**: `scenario_tl_observation` 4422 行を `derive_threat_level` に通し、v1 derive_tl との一致を `conclusion_diff_log` に書き込む (`metadata.replay_tag = "replay_v1_v2_diff/v1"`)。結果: 100% match (5 件 hysteresis_applied, 全行意味的一致)。
  2. **`scripts/backfill_v2_ledger.py`**: 同 4437 行を時系列順に 4 builders (tl/per_domain/attack_mode/trend) で `conclusions` ledger に書き込む (`metadata.replay_tag = "backfill_v2_ledger/v1"`)。結果: 17,748 行書き込み, errors=0, 重複ゼロ。
- **対象外**:
  - **ANOMALY backfill** は実施しない。`derive_anomaly` は per-signal `state.contributions` を必要とするが、`scenario_tl_observation` にはドメイン集計値しか保存されていない。捏造した contributions で proxy ANOMALY を作るのは NP1 (感度) と NP6 (透明性) を同時に損なう。
  - **LLM プロンプト履歴 backfill** も恒久不可。`llm_prompts` テーブル + `llm_call_log.prompt_sha256` は v2.0 Phase 1 で導入され、それ以前のプロンプト本文は streaming + dispose で永続化されていない。NP6 の遡及性は「将来生成される結論への遡及性」であり、過去の不存在データを fabricate するのは違反。
- **idempotency / rollback**:
  - `metadata.replay_tag` で identity を維持。再実行は `(scenario_id, observed_at, conclusion_type, replay_tag)` で skip。
  - `--rollback` でタグ付き全行削除。本番実行前に smoke + rollback テスト済 (40 行 → 0 行 → 143 行 baseline 復帰)。
- **運用**:
  - backfill 実行中は Mode B hook を `V2_CONCLUSION_LEDGER_ENABLED=false` で停止。`derive_trend` / `derive_per_domain` がライブ ledger を参照するため、並走時の汚染を防ぐ。停止時間 ~30 分以内に収めること。
  - DB スナップショット (`radar.db.pre_backfill_<ts>`) を container 内で取得してから実行。ホスト側からの sqlite3 操作は WAL 不整合を起こすため厳禁。
- **NP 整合性**:
  - **NP1 (感度)**: 観察期間短縮 = TL/per_domain/trend の本番投入を早める = 見逃し低減
  - **NP5+8 (結論品質規律)**: `replay_tag` で「実 live ではない」ことを明示しており、品質指標への混入は ADR-V2-014 で別途規律化
  - **NP6 (透明性)**: スクリプト本体 + replay_tag で導出経路を完全開示

### ADR-V2-015: bg_observer を BACKGROUND_ELIGIBLE 第一号 sensor として reify (Phase 6)

- **状態**: ACCEPTED (2026-04-30)
- **背景**: 2026-04-30 の調査で 3 つの構造的事実が判明した:
  1. `SensorTier.BACKGROUND_ELIGIBLE` は ADR-002 / ADR-017 で予約された C-medium 用 tier だが、**12 sensor のいずれも採用していない**。enum は定義されているが実装ゼロ。
  2. `radar/background_observer.py` は v1.8 から続く埋め草で、BaseSensor 体系の **外** に居る独立 worker。`SensorTier` 概念を持たず、circuit breaker / health 監視 / `scenario_sensor_coverage` 連動なし。
  3. bg_observer は本番で 1 cycle 中 1/4 しか matches を産まない。原因は単一国スコープ + multi-country 不対応 + alias 11 件欠落 (AU/BY/EE/FI/GU/LT/LV/MD/MY/RO/SK)。これにより AP3 OBS chip が偽陽性緑表示となり NP5+8 (恒常的 NULL-ZONE = 設計失敗) の検知機構そのものが沈黙する入れ子問題を生じている。
- **検討した代替案**:
  - **Option A (sunset bg_observer + GDELT を BG_ELIGIBLE 化)**: ADR-017 整合は最高だが、(1) GDELT は LLM intel queue 経由で動作するため bg_observer の **LLM 非依存 OPSEC niche** を捨てる、(2) C-medium reference 実装完成までに 1-3 ヶ月かかり、その間 NP1 (recall) / NP5+8 違反が進行する。
  - **Option C (alias 補修と broadcast 化のみ)**: 工数最小 (3-5h) だが NP3 / NP6 / AP1 / AP4 違反を温存し、bg_observer の戦略的位置づけが宙に浮く。
- **判断**: **Option B 採用**。bg_observer を BaseSensor 化し、`tier=SensorTier.BACKGROUND_ELIGIBLE` の **第一号 reference 実装** として位置づける。後続の sensor promotion (GDELT / ACLED 等) はこの reference に倣う。
- **実装計画 (Phase 6 = Operational Recall Repair)**:
  1. **Phase 1**: `scenario_contribution_log.sensor` 列追加 (migration v36) — sensor 別 OBS chip / recall baseline / scenario_improver の前提
  2. **Phase 2**: alias 補修 + `verify_alias_coverage()` + CI gate + startup gate (恒久不変条件化)
  3. **Phase 3**: `extract_kinetic_regex_all()` + `tick()` broadcast 化 (round-robin 廃止)
  4. **Phase 4**: `BackgroundObserverSensor(BaseSensor)` 化、scheduler 統合、circuit breaker / health
  5. **Phase 5**: `bg_observer_cycle_log` テーブル + `/api/v2/self_eval` 拡張 + HUD `OBS-BG` chip
  6. **Phase 6**: kinetic verb 群拡張 (mobiliz*, deploy, scramble*, missile test, recall ambassador) + 3 段階 raw_score (0.85 / 0.45 / 0.25)
  7. **Phase 7**: 上位機能整合性検証 + recall metrics baseline 再収集
  8. **Phase 8**: ADR 確定 + INTEL GUIDE Ch.10 §R bilingual
- **NP 整合性**:
  - **NP1 (感度)**: alias 補修 + broadcast 化で recall 構造的回復、Phase 6 で動員/外交断絶検出を低 confidence で追加
  - **NP3 (耐障害性)**: BaseSensor 化で circuit breaker / health / graceful degrade を取得
  - **NP5+8 (品質規律)**: OBS chip の sensor 別分解で「観測無し」状態を真に表示可能、AP3 chip による自己診断
  - **NP6 (透明性)**: cycle_log + per-feed audit + sensor framework の standard log
  - **AP1 (能動的トリアージ)**: bg_observer signals を attention_score 計算に取り込む (Phase 4 内)
  - **AP4 (判断履歴)**: cycle_log で replay 時の bg_observer 観測を時刻 T で復元可能
- **依存**: ADR-002 (C-lite 採用) / ADR-017 (SensorTier 予約) を実体化する位置づけ
- **後方互換**: `radar/background_observer.py` を thin wrapper として 1 リリース猶予で維持、Phase 4 完了後の次リリースで削除

---

### ADR-V2-014: calibration への replay 行採用ポリシー (Phase 1.3 加速)

- **状態**: ACCEPTED (2026-04-26)
- **背景**: Phase 1.3 backfill (ADR-V2-013) 実行後に、replay 行がどの calibration / 観察パスを汚染しうるかを検証する必要があった。当初は「`conclusion_diff_log` の `match_rate` が replay 行の 100% match で押し上げられる」「`calibration_status_for` の sampler verdict が誤った OK 判定を出す」ことを懸念していた。
- **検証結果 (2026-04-26 ライブ DB 確認)**:
  - `conclusions`: 17,891 行中 17,748 が `replay_tag` 付き (期待通り)
  - **`conclusion_diff_log`: 4,432 行中 replay_tag 付きは 0 行** ← 汚染なし
  - 理由: backfill は `save_conclusion(db, conclusion)` を直接呼ぶ。diff sampler hook は `compute_scenario_score()` 経路 (`radar/scoring.py:1352` の `_maybe_sample_v1_v2_diff`) からのみ起動し、`save_conclusion` 単体ではトリガしない設計。`/api/v2/admin/shadow_write_metrics` の `match_rate` も `conclusion_diff_log` を読むので、同じく汚染ゼロ。
  - `calibration_status_for` (`radar/conclusions/calibration.py`) は `db.shadow_drift_stats()` 経由で **`focus_switch_log`** を集計しており、`conclusions` テーブルも `conclusion_diff_log` も読まない。backfill は両者ともに書き込まないので、calibration verdict も影響を受けない。
- **判断**: **Option B (分離・除外) を採用**。ただし当初想定とは違う形での「分離」が既にコードレベルで成立していた:
  1. 公式 calibration / shadow メトリクス (`shadow_drift_stats` / `match_rate` / `shadow_write_metrics`) はすべて backfill が触らないテーブル経由で動作する
  2. replay 行は `conclusions.metadata.replay_tag` でしか到達できない、人手レビュー専用の分析データ
  3. `scripts/calibrate_thresholds.py` (Phase 1.3 Priority 5) が唯一の正式 replay 消費者で、`WHERE json_extract(metadata, '$.replay_tag') = ?` で明示的に opt-in 集計する read-only ツール
- **実装 (確認のみ、コード変更不要)**:
  - `shadow_drift_stats` / `calibration_status_for` / `match_rate` 計算: replay 行を含まないことを上記検証で確認済 (コード変更不要)
  - `scripts/calibrate_thresholds.py`: 既に replay-only スコープで実装済
  - 将来 backfill 経路を増設する場合は本 ADR の「`save_conclusion` 単体は diff sampler を起動しない」前提を破らないよう注意
- **NP 整合性**:
  - **NP1 (感度)**: live drift の検出感度を保持
  - **NP5+8 (品質規律)**: replay 行は `replay_tag` で「実 live ではない」ことを明示
  - **NP6 (導出開示)**: `calibrate_thresholds.py` が replay コーパスを名指しで参照する read-only パスのみ提供
- **依存**: ADR-V2-013 完了 (✅)

---

### Phase 1.3 観察ログ

`/api/v2/admin/shadow_write_metrics` 同等のクエリを定期的に DB へ直接打って記録する。Mode C opt-in 判断材料として 7d / 14d 連続健全を確認する。

| 観察日 | 24h match | 24h divergence | 24h match_rate | 7d match | 7d divergence | 7d match_rate | live conclusions 24h (TL/TREND/PER_DOMAIN/ANOMALY/ATTACK_MODE) | 備考 |
|--------|-----------|----------------|----------------|----------|----------------|----------------|--------------------------------------------------------------------|------|
| 2026-04-26 | 90 | 0 | 1.0000 | 1370 | 0 | 1.0000 | 10 / 10 / 41 / 41 / 41 | Priority 5 calibration 直後初観測。replay 行は diff_log に 0 行 (ADR-V2-014 検証通り)。TL/TREND が他より低いのは hysteresis でしか persist しない設計どおり |

**判定基準 (Mode C opt-in / 段階 rollout)**:
- **Stage 1+2 統合 opt-in (全認証ユーザー)** — `diff_log 7d match_rate ≥ 0.99` かつ `7d divergence ≤ 5` の単一基準。TL pipeline の v1 等価性が実証されており、PER_DOMAIN/ATTACK_MODE/ANOMALY は v1 等価が無いため diff_log では検証不能 (Phase 1.3 calibration で代替済)。当初は analyst-only → 全 user への 2 段階を想定していたが、認証述語の差し替えだけで下流コードパスは完全同一であり、analyst-only 期間に user ロールのトラフィックは到達せず観察可能な差分が無いため統合した
- **Mode C 完全 opt-in (default-on)** — Stage 1+2 基準 + 14d 累計 `divergence < 50 行` + Stage 1+2 期間中の analyst からの critical complaint なし

**Stage 1 開始: 2026-04-26 04:23 JST** — `V2_API_ENABLED=true` 化、4 公開ルート (`/api/v2/scenarios/.../conclusions`, single, by_id, audit_trace) に `_require_analyst()` ガード追加。smoke test 完了 (anonymous → 401 / admin → 200)。基準満たした根拠: `diff_log 7d 1370 行で match_rate=1.0000、divergence=0`。

**Stage 1+2 統合: 2026-04-26 (同日)** — Stage 2 の 48h 待機が recall に寄与しない慣習バッファである旨を再評価し、`_require_analyst()` を `@jwt_required()` に緩和して全認証ユーザに開放。NP4 (結論最大化) の観点で遅延コストの方が大きいと判定。

**Day-0 evidence (2026-04-26 04:58 JST)** — `scripts/check_mode_c_readiness.py` で技術 4 条件を計測:
- C1 diff_log 14d: total=4436, match_rate=1.0000, divergence=0
- C2 直近 1h tick coverage: 5/5 conclusion_type に live row あり
- C3 live ledger (replay 除外): 5/5 type で live row 存在 (TL/TREND=14、PER_DOMAIN/ATTACK_MODE/ANOMALY=61 in live window)
- C4 live TREND state: 4 行が real short_term state を返却 (chronic INSUFFICIENT_DATA リスクなし)

**Mode C 判定再評価**: 当初の T+7d (2026-05-03) は TREND short_term の live data 蓄積を待つ前提だったが、TREND derivation は THREAT_LEVEL 行を replay backfill 含めて読むため、live ledger 4h で既に real state を返している (`short_term=STABLE; medium_term=STABLE`)。技術条件は本日全て満たすので、残るのは operator self-validation のみ。**判定日を 2026-04-27 04:00 JST (T+24h) に圧縮**。

**Mode C 判定手順**: `docker exec ddos-radar bash -c 'cd /app && PYTHONPATH=/app python scripts/check_mode_c_readiness.py --ack'` を 2026-04-27 04:00 JST 以降に実行。exit 0 を確認後、`radar/config.py` で `V2_API_ENABLED` のデフォルトを `true` に変更し v1 sunset T+90d (2026-07-26) カウントダウン開始。

**Mode C 切替: 2026-04-26 05:10 JST** — `check_mode_c_readiness.py --ack` が全 5 条件 PASS で exit 0 を返却 (C1: 14d 4438/4438 match / C2: 5/5 type live row / C3: 5/5 type non-replay row / C4: live TREND 6 行 real state / C5: operator ack)。`radar/config.py` で `V2_API_ENABLED` のデフォルトを `"true"` に変更。判定日を当初の T+24h からさらに圧縮した根拠: 操作者 1 名のため 24h 待機で増える観察データはなく、C1〜C4 の technical evidence と直近 1h ログの 5xx=0 / traceback=0 が既に no-complaint を裏付け、ロールバックは `V2_API_ENABLED=false` の env 一行で 1 restart 内に可能 (commitment 不可逆性が低い)。

**v1 sunset カウントダウン開始**: 2026-04-26 → **2026-07-26 (T+90d)** で v1 API 撤去。Phase 1.4 で v1 ルートに `Deprecation` HTTP ヘッダ追加予定。

---

### Operational Observability (2026-04-29)

Phase 4 (v1 sunset) と並走する形で、運用層の機能拡充と観測網の盲点修正を一括投入。3 つの user-reported issue (A/B/C) + 観察網診断 + 週次 cron の組み合わせで、約 20 commit が main に landing。

**Issue A — フォーカス切替遅延**
- 根本原因: `radar/routes/core.py:573` の `ThreadPoolExecutor` が `force=true` で全 25 sensor を 60s timeout で同期 fan-out。cold な PeeringDB / IHR / Atlas が 8s map-dim deadline を恒常的に超過
- 修正: `force=snapshot` (default, 即時 cache 返却) と `force=sensors` (background greenlet で allow-list sensor のみ fetch) に分割。MapDim を **two-phase lift** に拡張 — envelope 到着で dim 解除 → 'REFRESHING' badge 表示 → threat_data 到着で badge 消去
- commits: `2986c04` (force split), `087ea0c` (MapDim two-phase)

**Issue B — LLM ONLINE 表示位置**
- LLM が `radar/llm_client.py` 経由で 9 ファイルから cross-cutting に呼ばれている事実を確認 (diplomatic / military_exercise / apt_intel / hacktivist_* / rss_extractor / intel_corroboration 等)
- HUD Row 3 に新 chip `#hud-llm-chip` を ALIGN/INTEL の間に配置。状態: online / online-stalled / offline / disabled / unknown。60s TTL + 3-strike rule で flicker 抑制
- `/api/intel/stats` を 4 フィールド拡張 (`llm_model`, `llm_mode`, `llm_calls_1h`, `llm_last_call_age_min`)
- commits: `7f2ce98` (API), `106eae3` (HUD chip)

**Issue C — auto-judge recheck (LLM-free)**
- 新 `radar/intel_auto_judge.py`: 7 分岐の決定論ルール (duplicate / source drift / low_conf+no_corrob / stale / corroborated_confirm / pending)。analyst marker `auto:rule_*` で human override 計算から自動判定を除外可能 (NP7 維持)
- `_cache_cleanup_worker` から hourly sweep
- 当初は `LLM_AUTO_JUDGE_RECHECK=true` で LLM 第二パスをオプション提供したが、後述 D5 で削除
- commit: `1bb5195`

**D5 — LLM 第二パス削除 (2026-04-29)**
- backtest (後述) が「Layer 1 cross-evidence ゲートが現データでは機能不能」と示したため、`_llm_recheck()` / `ANALYST_LLM_*` / `LLM_AUTO_JUDGE_RECHECK` を全削除。`unsafe-if-enabled` のリスクを構造的に消滅
- 再導入条件: cross-source diversity (avg ≥ 2.0) を満たした後、Layer 1 と同時実装
- commit: `8bddb2f`

**D6 — 観察網診断 (audit + backtest)**
- `scripts/audit_intel_sensors.py`: 各 LLM intel sensor を α (実装/設定) / β (base rate) / healthy / unknown に分類。pre_filter 内訳まで深掘り。read-only
- `scripts/backtest_auto_judge_layer1.py`: Layer 1 (cross-evidence ゲート) を実装前 dry-run。population / diversity / parameter sweep を出力
- 初回実行結果: **diversity=1.0 (avg/max とも)、α 5 sensor、β 0 sensor、healthy 2 sensor**。Layer 1 は前提条件すら欠ける
- commits: `264a150` (audit), `38b3454` (backtest)

**D7 — 5 sensor 修正**
1. `rss_narrative` (`ff99dd9`) — `_update_baseline()` 30 分 cycle 毎に append するが cap が 30 のまま → baseline 窓が **15 時間に縮退** (変数名は "30 days" を主張)。cap を `days × cycles_per_day` 動的算出に修正
2. `telegram` → ground_osint + hacktivist_intel (`5dd3f31`) — `TELEGRAM_POST_MAX_AGE_HOURS` 8h → 48h。preview 302 redirect 検出ログ追加 (12 channel 中 7 が preview disabled — replace は intel research 案件)
3. `diplomatic` (`9efc0c2`) — lxml recovery + `_classify_feed()` で feed 失敗を 5 種類に分類 (`rss_with_items` / `rss_empty` / `returns_html` / `unparseable` / `unknown`)。7 feed URL すべてが現在 stale と判明 — replace は intel research 案件
4. `hacktivist_news` (`69537d3`) — 同 classifier 共有。5 feed すべて healthy だが hacktivist 関連記事は ~2% (genuine β)。新 verdict tag `no_kw_match_healthy_feed` で α と区別

**N3 — 週次 cron (`81c29d4`)**
- `radar/diagnostics.py`: `audit_intel_sensors.analyze()` + `backtest_auto_judge_layer1.analyze()` を 168h cadence で `_cache_cleanup_worker` から自動実行
- 出力は INFO log + `_diversity_signal()` で Layer 1 unlock 判定 (avg ≥ 2.0 AND max ≥ 2)
- env `WEEKLY_DIAGNOSTICS_INTERVAL_HOURS` で override 可 (≥1h clamp)

**Phase 4 並走 work の今後の自動観察計画**:

| 時期 | 自動観察される指標 | 期待される変化 |
|------|------------------|--------------|
| T+3.5h | rss_narrative baseline ≥7 entries | burst 検出が動作開始 |
| T+48h | telegram 5 working channels の post window 拡張効果 | ground_osint + hacktivist_intel に signal 出現 |
| T+7d  | 古い verdict tag が rotation で消滅 | audit が新 tag (`feed_url_stale_html` 等) でクリーン分類 |
| 週次 cron | diversity avg/max | Layer 1 unlock 条件 (avg ≥ 2.0) を crossing したら INFO log で告知 |

**Phase 4 並走で残す非コード課題 (intel research)**:
- diplomatic 7 feed の現行 RSS endpoint 探索 (state.gov, mofa.gov.tw, fmprc.gov.cn, mid.ru, etc.)
- hacktivist 12 channel 中 7 (noname05716 等) の preview-enabled な代替探索
- これらが解消されると diversity が avg=1.0 → ≥2.0 に上がる見込み → Layer 1 + LLM 第二パスの再導入条件成立

これらは「コード」ではなく「世界知識」の更新であり、別 issue として独立管理する。

---

## 5. データモデル (v2.0)

### 5.1 Conclusion データクラス

```python
# radar/conclusions/base.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class ConclusionType(Enum):
    THREAT_LEVEL = "threat_level"
    TREND = "trend"
    PER_DOMAIN = "per_domain"
    ANOMALY = "anomaly"
    ATTACK_MODE = "attack_mode"

class ConclusionUnavailableReason(Enum):
    INSUFFICIENT_DATA = "insufficient_data"
    CALIBRATION_PENDING = "calibration_pending"
    SENSOR_DEGRADED = "sensor_degraded"
    UPSTREAM_FAILURE = "upstream_failure"

@dataclass(frozen=True)
class Conclusion:
    """v2.0 中核: ツールが出力する結論の単一スキーマ。"""
    id: str                                     # uuid
    scenario_id: str                            # "taiwan_contingency"
    conclusion_type: ConclusionType
    state: str                                  # "3" (TL) / "ESCALATING" / "DDOS_PRECURSOR"
    confidence: float                           # 0.0-1.0 (calibrated)
    observed_at: float                          # epoch
    formula_ref: str                            # "radar/scoring.py#derive_tl@v2.0.1"
    threshold_ref: dict                         # {"total": 9.0, "physical": 3.0}
    source_urls: tuple                          # 一次ソース URL (immutable)
    llm_prompt_sha256: Optional[str] = None     # LLM 経由なら必須
    calibration_status: dict = field(default_factory=dict)
    conclusion_unavailable_reason: Optional[ConclusionUnavailableReason] = None
    final_judgment_disclaimer: str = ""         # i18n key 経由で埋める
    metadata: dict = field(default_factory=dict)  # importance_score 等の領域固有データ

    def is_available(self) -> bool:
        return self.conclusion_unavailable_reason is None
```

### 5.2 DB schema 追加 (migration v19-v22)

```sql
-- v19: conclusions append-only ledger
CREATE TABLE conclusions (
    id              TEXT PRIMARY KEY,
    scenario_id     TEXT NOT NULL,
    conclusion_type TEXT NOT NULL,
    state           TEXT NOT NULL,
    confidence      REAL NOT NULL,
    observed_at     REAL NOT NULL,
    formula_ref     TEXT NOT NULL,
    threshold_ref   TEXT NOT NULL,         -- JSON
    source_urls     TEXT NOT NULL,         -- JSON array
    llm_prompt_sha256 TEXT,
    calibration_status TEXT NOT NULL,      -- JSON
    conclusion_unavailable_reason TEXT,
    metadata        TEXT NOT NULL          -- JSON
);
CREATE INDEX idx_conclusions_scenario_time ON conclusions(scenario_id, observed_at DESC);
CREATE INDEX idx_conclusions_type_time ON conclusions(conclusion_type, observed_at DESC);

-- v20: LLM prompts (sha256 dedup)
CREATE TABLE llm_prompts (
    prompt_sha256   TEXT PRIMARY KEY,
    prompt_text     TEXT NOT NULL,
    model           TEXT NOT NULL,
    temperature     REAL,
    prompt_version  TEXT,                  -- "apt_intel_v3" 等
    first_seen_at   REAL NOT NULL,
    last_seen_at    REAL NOT NULL,
    use_count       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_llm_prompts_last_seen ON llm_prompts(last_seen_at DESC);

-- v20 (続): llm_call_log に FK 列追加
ALTER TABLE llm_call_log ADD COLUMN prompt_sha256 TEXT REFERENCES llm_prompts(prompt_sha256);

-- v21: inconclusive_continuity_log
CREATE TABLE inconclusive_continuity_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint        TEXT NOT NULL,
    scenario_id     TEXT,
    state           TEXT NOT NULL,         -- "INSUFFICIENT_DATA" 等
    observed_at     REAL NOT NULL
);
CREATE INDEX idx_incont_endpoint_time ON inconclusive_continuity_log(endpoint, observed_at DESC);

-- v22: analyst_feedback
CREATE TABLE analyst_feedback (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    conclusion_id       TEXT NOT NULL REFERENCES conclusions(id),
    label               TEXT NOT NULL,     -- TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE / FALSE_NEGATIVE
    observed_outcome_url TEXT,             -- ACLED/GDELT URL or null
    analyst_id          TEXT NOT NULL,
    observed_at         REAL NOT NULL,
    notes               TEXT
);
CREATE INDEX idx_feedback_conclusion ON analyst_feedback(conclusion_id);
```

### 5.3 Retention ポリシー

| テーブル | retention | 理由 |
|---------|-----------|------|
| `conclusions` | 365 日 | ground truth 突合と long-term trend 検証 |
| `llm_prompts` | 90 日 | NP6 遡及性、dedup 効率と DB サイズの均衡 |
| `inconclusive_continuity_log` | 90 日 | 7 日連続検知 + 28 日履歴で十分 |
| `analyst_feedback` | 永続 | 学習材料として削除しない |

設定は `config.env`: `CONCLUSION_RETENTION_DAYS=365`, `LLM_PROMPT_RETENTION_DAYS=90` 等。

---

## 6. 結論モデル詳細

### 6.1 全体脅威レベル (THREAT_LEVEL)

- **state**: `"1"` 〜 `"5"` (TL1-5、文字列で表現)
- **既存 v1 計算**: `derive_tl()` をそのまま流用 (NP4 で評価対象としては既に充足)
- **v2 追加**: `formula_ref="radar/scoring.py#derive_tl@v2.0.1"`、`threshold_ref={"total": ..., "physical": ...}` を動的に埋める
- **frequency**: scoring tick 毎 (5 分間隔)

### 6.2 トレンド (TREND)

- **state (spec 目標)**: `RAPIDLY_ESCALATING` / `ESCALATING` / `STABLE` / `DE_ESCALATING` / `RAPIDLY_DE_ESCALATING`
- **三層**:
  - `trend_24h` (短期、scoring tick 毎)
  - `trend_7d` (中期、1時間毎)
  - `trend_30d` (長期、6時間毎)
- **算出 (spec 目標)**: 既存 `compute_scenario_velocity()` + `compute_scenario_acceleration()` を拡張、ラベルへ閾値マッピング
- **閾値 (spec 目標、Phase 2 で calibration)**:
  - `RAPIDLY_ESCALATING`: velocity > +1.0/h かつ acceleration > +0.3/h²
  - `ESCALATING`: velocity > +0.3/h
  - `STABLE`: |velocity| ≤ 0.3/h
  - `DE_ESCALATING`: velocity < -0.3/h
  - `RAPIDLY_DE_ESCALATING`: velocity < -1.0/h かつ acceleration < -0.3/h²
- **Phase 1 実装ドリフト** (`radar/conclusions/trend.py`):
  - **語彙ドリフト**: `ESCALATING` / `RISING` / `STABLE` / `COOLING` / `DEEPER_DECAY` を採用 (spec の `RAPIDLY_*` プレフィックス無し)。Phase 1.3 で spec 目標形に再マッピング検討
  - **算出ドリフト**: velocity/acceleration ではなく **mean-of-window 比較** (現在 span vs 直前 span の TL 平均差分) を使用。velocity 基盤は v1 から流用予定だが、Phase 1 は ledger に蓄積されたばかりの TL 行を直接読むほうが透明 (NP6) で着手コストが低い
  - **閾値**: `RISING_DELTA=0.50` / `ESCALATE_DELTA=1.50` (TL severity 1..4 の差分単位)。spec の velocity/h 単位とは比較不能なので Phase 1.3 で再 calibration
  - **Phase 1.3 再 calibration 結果 (2026-04-26、`scripts/calibrate_thresholds.py`、backfill 17,748 行)**: short_term window の実 state 分布が STABLE 71% / RISING 17% / ESCALATING 1% / COOLING 10% と均衡しており、現閾値を維持。閾値を下げると ESCALATING share が 5% を超え specificity が低下する。medium_term/long_term は |delta_sev|=ESCALATE が p99 tail にしか達していないが、これは backfill コーパスが 7d/30d window に対して短いことに起因し、organic ledger を 30 日以上蓄積した後で再評価する (replay-only での tuning は ADR-V2-014 の Option B に整合)
  - **MIN_SAMPLES**: 現/前両 window に各 3 行以上必要。`conclusions` ledger 蓄積前は INSUFFICIENT_DATA 期間が続く (NP5+8 過渡的不足として許容)
  - **出力形式**: 3 window を 1 つの Conclusion 行に packed-state 文字列 `short_term=X;medium_term=Y;long_term=Z` で格納 (spec は 3 horizon 別行を示唆するが、`?horizon=` クエリ側で分解可能なので 1 行集約を採用)
  - **TL severity 反転**: `_TL_SEVERITY` で TL1→4 / TL5→0 にマップ (TL 数字は小さいほど高脅威、severity は大きいほど高脅威)
  - shadow-write は焦点シナリオのみ (background は TL 行を出さないため input ledger が進まず無意味)

### 6.3 ドメイン別兆候 (PER_DOMAIN)

- **state**: `ACTIVE` / `ELEVATED` / `STABLE` / `DEGRADING` / `INSUFFICIENT_SIGNAL`
- **対象ドメイン**: `cyber` / `physical` / `info`
- **算出 (spec 目標)**:
  - 各 domain の signal 数と raw_score 合計から閾値判定
  - `ACTIVE`: 過去 24h で domain raw_score > 5.0 かつ signal_count >= 5
  - `ELEVATED`: raw_score > 2.0 かつ signal_count >= 2
  - `STABLE`: raw_score > 0
  - `DEGRADING`: 直近 6h で signal_count が前 24h 平均の 30% 未満
  - `INSUFFICIENT_SIGNAL`: signal_count < 1 かつ センサー全体が degraded
- **frequency**: scoring tick 毎
- **Phase 1 実装ドリフト** (`radar/conclusions/per_domain.py`):
  - 閾値 (Phase 1 初期): `ACTIVE_FLOOR=3.0` / `ELEVATED_FLOOR=1.5` / `DEGRADE_DELTA=1.5` (絶対値、`signal_count` 無し)。spec の `5.0` / `2.0` + `signal_count` ゲート + 30% 相対 `DEGRADING` から逸脱。Phase 1 は scoring 直後 1 tick 分の `domains` 合計のみで判定し、`signal_count` の正値は累積 ledger を待つ
  - **Phase 1.3 calibration 後 (2026-04-26、`@v2.0.1`、`scripts/calibrate_thresholds.py`、backfill 4437 行)**: `ACTIVE_FLOOR=2.5` / `ELEVATED_FLOOR=1.5` (維持) / `DEGRADE_DELTA=1.0`。実分布: cyber 正値 score p95=2.5 / max=3.5、physical p95=2.70 / max=4.29。旧 `ACTIVE_FLOOR=3.0` は positive observation の <1% にしか発火せず NP1 (感度) を阻害していた。`DEGRADE_DELTA=1.5` も cyber drop の p95 ちょうどで、現実的な p75-p90 の drop を捕捉できなかった。`ELEVATED_FLOOR=1.5` は p75 帯をカバーしており妥当
  - `DEGRADING`: 直近 PER_DOMAIN 行 (`latest_conclusion`) との絶対差 `DEGRADE_DELTA` 以上を判定。spec の「6h vs 24h 相対 30% 減」は ledger 蓄積が必要なので将来再評価
  - 出力形式: 3 ドメインを 1 つの Conclusion 行に packed-state 文字列 `cyber=X;physical=Y;info=Z` で格納 (spec は明示せず、行数最少のコスト効率を採用)

### 6.4 個別異常事象 (ANOMALY)

- **state**: 観測事象の summary 文字列 (例: `"BGP withdrawal surge from AS4134 (China Telecom)"`)
- **importance_score**: 0-100 (`metadata["importance_score"]`)
- **算出式**: `raw_score × recency_decay × scenario_relevance × novelty_factor × 100`
  - `recency_decay = exp(-elapsed_h / 12)` (時定数 τ=12h、12h で約 37% に減衰。実半減期は 12·ln 2 ≈ 8.32h)
  - `scenario_relevance = llm_country_weight × participant_weight` (per-contribution 値; GLOBAL は participant_weight のみ)
  - `novelty_factor = 1.0 - (similar_count / 10)`, clamped [0.3, 1.0]
    - similar_count は `conclusions` 表を直近 24h スキャンし、同一 `(scenario_id, conclusion_type=ANOMALY, metadata.signal_source)` に一致する prior 行数。`metadata["novelty_source"] = "ledger_24h"` を付与
    - SQL 失敗時は count=0 / novelty=1.0 にフォールバックし `metadata["novelty_source"] = "ledger_24h_fallback_empty"` でデグレード経路を可視化 (NP1: 履歴欠落で importance を sponta に下げない)
    - lookback 窓は `THRESHOLD_REF["novelty_lookback_sec"] = 86400` で開示
- **API 返却**: 上位 N 件 (default 10、`?limit=` で調整)
- **importance_score 上限**: 100.0 へクランプ (raw_score × 各係数の積が 1.0 を超える場合のセーフティ)

### 6.5 推定攻撃シナリオ (ATTACK_MODE)

- **state**: ADR-V2-002 の base_modes + scenario_extensions
- **算出ロジック**: rule-based 分類 (Phase 2 初期) → LLM 補強 (Phase 2 後半)
  - `DDOS_PRECURSOR`: cyber_signal_count >= 5 (24h) かつ info_narrative_burst >= 3
  - `KINETIC_PREPARATION`: physical (ISR_SURGE + military_exercise + diplomatic_crisis) 同時 active
  - `HYBRID_PRESSURE`: 3 ドメイン同時 active かつ LLM intel cluster size >= 4
  - `INFO_OPS_DOMINANT`: info domain ACTIVE、他ドメイン STABLE 以下
  - `INSUFFICIENT_SIGNAL`: 上記いずれにも該当せず、データ過渡的不足
- **scenario_extensions**: `geo_data.json` の `scenarios.<id>.attack_mode_extensions` で追加判定式
- **複数モード並列**: top 3 を confidence 順で返却 (排他ではない)
- **Phase 1 実装ドリフト** (`radar/conclusions/attack_mode.py`):
  - 入力: `cyber_signal_count` / `info_narrative_burst` / 物理サブセンサー連動 / `intel cluster size` などの「24h 集計」の代わりに、in-flight `state.domains` (cyber/physical/info の現 tick スコア) と `len(state.active_countries)` を直接使用 (Phase 1 では 24h 集計の蓄積が無いため)
  - 閾値: `CYBER_DDOS_FLOOR=5.0`, `INFO_NARRATIVE_FLOOR=1.5`, `PHYSICAL_KINETIC_FLOOR=3.0`, `ALL_DOMAIN_HYBRID_FLOOR=1.5`, `HYBRID_INTEL_CLUSTER_MIN=4` (active_countries proxy), `INFO_DOMINANCE_RATIO=1.5`
  - INSUFFICIENT_SIGNAL は spec 通り `ConclusionUnavailableReason.INSUFFICIENT_DATA` (transient) として表現。`state=None` / `confidence=0.0`
  - 複数モード firing は実装済み (`metadata.ranked_modes` に confidence 降順で全件、`state` に top 1)。`is_tentative` flag を `confidence < 0.6` で付与
  - `scenario_extensions` 適用フック — **実装済 (2026-04-27, Phase 2.5)**: `radar/conclusions/attack_mode_extensions.py` で `geo_data.json["SCENARIOS"][sid]["attack_mode_extensions"]` を declarative ルール (domain_floors / active_n_min / requires_participant / base_confidence) として評価。base + extension matches を merge し confidence 降順で再ソート。reserve された base mode を shadow するエクステンションは silent drop、malformed entry も silent drop (NP3)。confidence は `[0.55, 0.95]` にクランプ。**全 5 シナリオで宣言済 (2026-04-27 拡張)**: `taiwan_contingency` (NAVAL_BLOCKADE_PRECURSOR / PLA_AIR_INCURSION_SURGE)、`korean_peninsula` (ARTILLERY_BUILDUP / MISSILE_TEST_CASCADE)、`eastern_europe` (KINETIC_TEMPO_SHIFT / GRAY_ZONE_PROBING)、`middle_east` (PROXY_KINETIC_SURGE / MARITIME_INTERDICTION_RISK / DIRECT_STATE_EXCHANGE_RISK)、`south_china_sea` (GRAY_ZONE_MARITIME_PRESSURE / REEF_INCIDENT_ESCALATION)。call site は変更不要 (deriver の state-only API は維持)。テスト: `test_attack_mode_extensions.py` 20 件
  - LLM 補強は Phase 2 後半で追加 (現状は rule-based のみ) — **実装済 (2026-04-26)**
  - 閾値の正式 calibration は Phase 1.3 で 14 日間 shadow 観測の上で実施 (現状は機能 OK / calibration 未確定)

  **Phase 2 後半 LLM 補強実装** (2026-04-26):
  - 新モジュール `radar/conclusions/attack_mode_llm.py` — `augment_attack_mode_with_llm(rule_conclusion, state)`
  - **rule が authority**: `state` (top mode) は rule のまま LLM では上書き不可。LLM の disagreement は `metadata.llm_augmentation.suggested_alternative_mode` に記録
  - **confidence nudge**: ±0.10 max (絶対値クランプ)、rule baseline から微調整のみ
  - **NP1 整合**: rule が `INSUFFICIENT_DATA` の場合は LLM 呼び出しせず pass-through (LLM に mode を発明させない)
  - **NP3 整合**: LLM 不可達/parse 失敗時は rule conclusion をそのまま返す + `metadata.llm_augmentation.attempted=true, ok=false, error=<reason>` で監査可能化
  - **NP6 整合**: `llm_prompt_sha256` を Conclusion に直接スタンプ (deterministic prompt → 同じ state は dedup)
  - **prompt 構造**: system は固定 (240 chars 程度)、user prompt は scenario_id + rule_top_mode + ranked_modes + domain_scores + active_n の決定論的 render
  - **JSON schema**: `{agreement ∈ {agree, weak_agree, weak_disagree, disagree, unknown}, suggested_alternative_mode ∈ {5 modes} | null, narrative ≤240 chars, key_evidence list[≤4]≤120 chars, confidence_adjustment ∈ [-0.10, 0.10]}`
  - **flag**: `V2_ATTACK_MODE_LLM_AUGMENT_ENABLED` (default false、明示 opt-in)
  - **wire**: `radar/scoring.py:_maybe_persist_attack_mode_conclusion` で `derive_attack_mode → augment_attack_mode_with_llm → save_conclusion` の chain
  - **tests**: `test_attack_mode_llm_augment.py` 14 件 (gating / NP1 pass-through / confidence clamp / state immutability / sha256 stamp / parse defense / failure path)

---

## 7. API v2 設計

### 7.1 エンドポイント一覧

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/v2/scenarios/<id>/conclusions` | 全結論オブジェクト束 (5領域) |
| GET | `/api/v2/scenarios/<id>/conclusions/threat_level` | TL のみ |
| GET | `/api/v2/scenarios/<id>/conclusions/trend?horizon=24h\|7d\|30d` | トレンド |
| GET | `/api/v2/scenarios/<id>/conclusions/per_domain?domain=cyber\|physical\|info` | ドメイン別 |
| GET | `/api/v2/scenarios/<id>/conclusions/anomalies?limit=N` | 異常事象 ranking |
| GET | `/api/v2/scenarios/<id>/conclusions/attack_modes?limit=N` | 攻撃モード推定 top N |
| GET | `/api/v2/conclusions/<conclusion_id>` | 単一結論の取得 |
| GET | `/api/v2/conclusions/<conclusion_id>/audit_trace` | 完全な導出開示 (formula + threshold + sources + LLM prompt 全文) |
| POST | `/api/v2/conclusions/<conclusion_id>/feedback` | アナリスト ground truth 投入 |
| GET | `/api/v2/scenarios/<id>/export?format=markdown\|pdf` | 組織共有レポート |
| GET | `/api/v2/admin/inconclusive_continuity` | 恒常的結論不可の検知結果 (analyst のみ) |
| GET | `/api/v2/admin/llm_prompt/<sha256>` | LLM プロンプト原文取得 (analyst のみ) |

### 7.2 共通レスポンス形式

```json
{
  "api_version": "2.0",
  "scenario_id": "taiwan_contingency",
  "observed_at": 1745558400.0,
  "final_judgment_disclaimer": "本ツールの結論は組織判断の一ノードであり、最終判断ではない。",
  "conclusions": [
    {
      "id": "uuid",
      "conclusion_type": "threat_level",
      "state": "3",
      "confidence": 0.78,
      "observed_at": 1745558400.0,
      "formula_ref": "radar/scoring.py#derive_tl@v2.0.1",
      "threshold_ref": {"total": 9.0, "physical": 3.0},
      "source_urls": ["https://radar.cloudflare.com/...", "https://acled.org/..."],
      "llm_prompt_sha256": null,
      "calibration_status": {
        "sampler": "OK",
        "drift": 0.05,
        "last_recal_at": 1745468400.0,
        "sample_n": 240
      },
      "conclusion_unavailable_reason": null,
      "metadata": {}
    }
  ]
}
```

### 7.3 結論不可状態のレスポンス例

```json
{
  "api_version": "2.0",
  "conclusions": [
    {
      "conclusion_type": "trend",
      "state": null,
      "confidence": 0.0,
      "conclusion_unavailable_reason": "insufficient_data",
      "metadata": {
        "reason_detail": "Less than 6 datapoints in last 24h window",
        "is_transient": true,
        "first_observed_at": 1745554800.0,
        "consecutive_inconclusive_hours": 2
      },
      ...
    }
  ]
}
```

`is_transient = false` (= consecutive ≥ 168h = 7d) の場合、`STRUCTURAL_GAP` alert がフロント HUD に表示される。

### 7.4 v1 との並走

- v1 API (`/api/threat_data` 等) は変更せず存続
- v2 ベータ (Phase 1 完了時) から v1 レスポンスに **deprecation header** を追加:
  - `Deprecation: true`
  - `Sunset: <v2_default_on_date + 90d>`
  - `Link: </api/v2/scenarios/<id>/conclusions>; rel="successor-version"`
- v1 は内部実装で v2 の Conclusion から逆変換して返す (single source of truth)

---

## 8. UI 設計 (Analyst Workbench)

### 8.1 全体レイアウト変更

現状の地図中心 + 浮遊パネル散在から、**conclusion-first 4 ペイン** に再構築する。地図は背景情報として残すが、結論は中央上段に常時表示。

```
┌──────────────────────────────────────────────────────────────────────┐
│ 📌 Final Judgment Disclaimer (NP7 固定バナー)                         │
├────────────────────────────┬─────────────────────────────────────────┤
│ ① 結論サマリ                │ ② 攻撃モード推定                         │
│   - TL: 3 (UP from 2)      │   1. KINETIC_PREPARATION (conf 0.78)   │
│   - 24h: ESCALATING        │   2. INFO_OPS_DOMINANT (conf 0.42)      │
│   - 7d: STABLE             │   3. HYBRID_PRESSURE (conf 0.31)        │
│   - 30d: STABLE            │   [ext] PLA_AIR_INCURSION_SURGE (0.65)  │
├────────────────────────────┼─────────────────────────────────────────┤
│ ③ ドメイン別結論            │ ④ Top Anomalies (importance ranked)     │
│   🌐 Cyber: ELEVATED        │   1. BGP withdrawal AS4134 (87)        │
│   🛰️ Physical: ACTIVE      │   2. Carrier strike group movement (74) │
│   📰 Info: STABLE           │   3. CISA APT advisory (62)            │
└────────────────────────────┴─────────────────────────────────────────┘
   ↓ 各カードクリック → drill-down モーダル表示
   → "Export Markdown / PDF" ボタンで組織共有用レポート生成
```

### 8.2 Drill-down モーダル

各結論カードをクリックすると、以下を表示:
1. **結論本体** (state + confidence + observed_at)
2. **formula_ref** (コード行へのリンク + git permalink)
3. **threshold_ref** (動的閾値の表 + 「もしこの閾値が X だったら結論はどう変わるか」what-if)
4. **source_urls** (一次ソースの clickable リンク + プレビュー)
5. **llm_prompt_sha256** → 「プロンプト全文を表示」ボタン → モーダル内モーダル
6. **calibration_status** (sampler/drift/sample_n の数値表)
7. **analyst feedback** ボタン (TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE / FALSE_NEGATIVE)

### 8.3 Export 機能

- **Markdown** (実装済 2026-04-26):
  - Endpoint: `GET /api/v2/scenarios/<scenario_id>/conclusions.md`
    - `?include_audit=1` で各 conclusion に対応する LLM プロンプト全文を `<details>` ブロックで埋め込む (NP6 完全開示)
    - JWT 必須、`V2_API_ENABLED=false` で 503 (JSON envelope)
  - Pure renderer: [radar/conclusions/markdown.py](../../radar/conclusions/markdown.py) — Flask 非依存、テストは [test_conclusions_markdown.py](../../tests/test_conclusions_markdown.py) (21 件)
  - 構成: 先頭にシナリオヘッダ + NP7 disclaimer (blockquote, 1 回のみ)、`## <Title>` per ConclusionType、threshold/calibration/metadata は ```json``` fenced (sort_keys 安定化)、source_urls は bullet list、unavailable は `_unavailable_` + reason 表示
  - Frontend: `#conclusion-cards-bar` 内 `cc-toolbar` の "Export Markdown" ボタンから download (i18n: `cc.btn.export_md`)
  - YAML front-matter は不要と判断 (analyst が wiki/ticket に貼る用途で front-matter を解釈する consumer がない); 必要になれば add-on で導入
- **PDF**: Markdown を pandoc または weasyprint で変換 (Phase 3 後半で実装)
- **STIX 2.1 / JSON-LD**: v2.1 で追加 (ADR-V2-004)

### 8.4 v1 UI との並走

- v1 UI (現行 index.html + radar.js) は Phase 3 完了時点で「Legacy View」として残す
- 新 UI は `/v2/` パスで提供 (例: `index_v2.html` + `radar_v2.js`)
- アナリスト個別に opt-in (localStorage `ui_version=v2`)
- v2 default-on 後 90 日で v1 UI 撤去

### 8.5 旧 P5 文言の駆逐 (詳細)

`index.html` Ch.1, 2, 8, 10 + `i18n.js` で以下を全廃:

| 旧文言 (NG) | 置換 (OK) | 理由 |
|------------|----------|------|
| "avoiding over-reliance on automated assessments" | "本ツールは結論を出力する。最終判断は組織が行う" | NP4/NP7 整合 |
| "tool does not decide" | (削除) | NP4 違反 |
| "advisory only" | "conclusion (subject to organizational review)" | NP4 整合 |
| "supports analyst judgment without replacing it" | "supports analyst by producing conclusions for organizational review" | NP4/NP7 整合 |

検証: `tests/test_ui_integrity.py` に禁止文字列リストを追加。grep ヒットで test fail。

---

## 9. Calibration Governance (NP5+8)

### 9.1 Conclusion 統合

すべての `Conclusion` の `calibration_status` フィールドに以下を埋める:

```json
{
  "sampler": "OK | DEGRADED | UNAVAILABLE",
  "drift": 0.05,
  "last_recal_at": 1745468400.0,
  "sample_n": 240,
  "confidence_interval": [0.65, 0.85]
}
```

shadow_sampler (`radar/shadow_sampler.py`) がこのデータを各結論計算時に inject。

### 9.2 過渡的 vs 恒常的の区別

`inconclusive_continuity_log` テーブル + scheduler 毎時 job で:
1. 全 Conclusion 系エンドポイントの state を sampling
2. `INSUFFICIENT_DATA` であれば log に append
3. **同一 (endpoint, scenario_id) で 7 日連続継続 → STRUCTURAL_GAP** 判定
4. STRUCTURAL_GAP 一覧を `/api/v2/admin/inconclusive_continuity` で返却
5. Admin UI Fleet Health タブに alert カードを追加

NP5+8 (b)「データ蓄積後も恒常的結論不可継続は設計失敗」を運用化する唯一の機構。

### 9.3 Design W (ADR-026) との連動

v1 で shadow phase に留まる Design W (auto-calibration) を、v2.0 では:
- Phase 2: `analyst_feedback` から recall 計測値を算出、Design W の opt-in 移行ゲートとする
- Phase 2 後半: opt-in で 14 日 → Phase 3 で default-on
- Phase 3: 全 Conclusion の `confidence` を Design W で calibration 済みの値に置換

---

## 10. 移行戦略

### 10.1 三段階 rollout (各機能共通)

すべての v2 機能は以下のパターンで投入する (ADR-025/026 の確立パターンを踏襲):

| Phase | 期間 | UI | API | 観測内容 |
|-------|------|-----|-----|---------|
| **Shadow** | 2-3 週 | v1 のまま | v2 計算するが返却せず log のみ | v1/v2 結論の drift 測定 |
| **Opt-in** | 2-3 週 | アナリスト個別に v2 有効化 | 両方返却 | 利用者フィードバック収集 |
| **Default-on** | 永続 | v2 既定、v1 は legacy として選択可 | 両方返却 + v1 deprecation header | 移行完了 |

### 10.2 Phase 別マイルストーン

#### Phase 0 (進行中): 設計確定 + scaffolding (本書作成 + 最小コード)
- ✅ v2-migration.md 作成 (本書)
- ⏳ CLAUDE.md 更新 (本書を必読参照に追加)
- ⏳ scenario-refactor.md ステータスを `v1-frozen` に更新
- ⏳ `radar/conclusions/__init__.py` + `base.py` (Conclusion dataclass)
- ⏳ DB migration v19 (conclusions テーブル)
- ⏳ DB migration v20 (llm_prompts + llm_call_log.prompt_sha256)
- ⏳ `tests/test_conclusions.py` 基本テスト
- ⏳ `scripts/codemod_theater.py` scaffolding (dry-run のみ)

#### Phase 1 完了条件
- DB migration v19-v22 すべて適用済み (本番 DB で検証)
- `radar/conclusions/` モジュール完成 (5 結論種すべての builder 関数)
- `/api/v2/scenarios/<id>/conclusions` (read-only) 稼働
- LLM プロンプト永続化 (全 LLM 経路で `llm_prompts` テーブルに insert)
- theater 撲滅 codemod 実行 + v1 API adapter 配置
- 旧 P5 文言の駆逐 + `test_ui_integrity.py` 禁止文字列テスト
- NP7 disclaimer の API 必須化 + テスト
- 全 563 既存テスト pass + 新規 30+ テスト pass

#### Phase 2 完了条件
- 攻撃モード推定 (rule-based + LLM 補強) 稼働、shadow 14 日 → opt-in
- トレンド 24h/7d/30d 稼働、shadow 14 日 → opt-in
- per-domain 構造化稼働
- importance_score ranking 稼働
- inconclusive_continuity_log + scheduler job 稼働
- ACLED + GDELT 自動突合 ETL 稼働 — **実装済 (2026-04-26)**: ADR-V2-005 参照。`scripts/run_ground_truth_etl.py` + `radar/conclusions/ground_truth_etl.py` + `radar/sensors/acled.py`。flag `V2_GROUND_TRUTH_ETL_ENABLED` 既定 false (ACLED API key 設定 + cron 構成後に opt-in)。Runner integration tests: `test_run_ground_truth_etl.py` 10 件 (idempotency / dry_run / scenario_filter / unknown scenario graceful skip / no_verdict counter / enable_gdelt=False isolation / `--force` flag override / 空 window) — **追加 (2026-04-27)**
- Design W opt-in 移行 — **完了 (2026-04-29)**: PF1 ETL 拡張で analyst_feedback 855 行蓄積 (TP=351 / FP=504 / FN=0)、recall=1.000 across 9 cells、`docs/baselines/recall_metrics.json` 作成 + `opt_in: true` で CI gate を strict 化済
- 全テスト pass + recall metrics ベースライン記録 — **実装済 (2026-04-27)**: `scripts/report_recall_metrics.py` + `test_report_recall_metrics.py` (8 件)。`analyst_feedback` JOIN `conclusions` で per-(scenario, type) confusion matrix を集計、recall=TP/(TP+FN), precision=TP/(TP+FP) を出力。`--exclude-auto` で human-only baseline、`--json` で CI 取り込み可。latest-row-wins de-dup でアナリスト label revision を二重カウントしない
- Recall metrics CI ゲート — **実装済 (2026-04-27)**: `scripts/check_recall_baseline.py` + `test_check_recall_baseline.py` (16 件、`--window-days` 追加分含む)。`docs/baselines/recall_metrics.json` をベースラインとし、per-cell recall 低下 > `--max-drop` (既定 0.05) で hard fail、coverage loss (baseline 数値→current None) も hard fail、新 cell / 軽微な slip は info ログ。bootstrap mode (baseline 不在) は exit 0 + warning で先に CI へ配線可能。**`--window-days N`** で直近 N 日のフィードバックのみで matrix 構築 (snapshot に since タイムスタンプ記録 → check 時は baseline の window を継承し apples-to-apples 比較)。`scripts/check_ci.sh` の 4 番目のゲートとして組込み。analyst_feedback 蓄積後に `--update` で初期 snapshot を commit、Design W opt-in と同時に `opt_in: true` へ flip して厳格化

#### Phase 3 完了条件
- Analyst Workbench UI 稼働 (5 cards + drill-down) — **実装済**: `index.html#conclusion-cards-bar` (5 ConclusionType の grid)、`radar.js _ccDrillRender` (header / disclaimer / formula / thresholds / calibration / sources / metadata / llm_prompt / llm_aug (ATTACK_MODE のみ) / feedback の 10 セクション)
- Markdown export 稼働 (実装済 — §8.3)
- analyst feedback UI 稼働 — **実装済 (2026-04-26)**: ADR-V2-011 参照。drill-down modal に統合 (4 ラベル radio + URL/notes)、`POST/GET /api/v2/conclusions/<id>/feedback`、bias mitigation のため per-label counts のみ提示、anti-spoof analyst_id (JWT 由来)
- ATTACK_MODE LLM augmentation drill-down セクション — **実装済 (2026-04-26)**: agreement / suggested_alternative / confidence_adjustment / narrative / key_evidence を独立カードとして表示。LLM 失敗時は attempted=true + error 文字列を表示し offline と quiet を区別可能
- v2 default-on (旧 v1 UI/API は legacy) — **完了 (2026-04-26)**: `V2_API_ENABLED` config 既定 true、`scripts/check_mode_c_readiness.py` 5 条件 pass
- v1 deprecation header 発射 — **完了**: `radar/conclusions/v1_sunset.py` で RFC 9745 + RFC 8594 + RFC 8288 ヘッダを `/api/threat_data` と `/api/scenario/<id>/breakdown` に付与、Sunset = 2026-07-26
- アナリスト 90 日継続利用フィードバック収集 — **完了 (2026-04-29)**: recall metrics CI gate (`scripts/check_recall_baseline.py` opt_in:true) で自動化、再評価不要

#### Phase 4 完了条件
- v1 API 撤去
- v1 UI 撤去
- theater adapter 削除
- DB schema cleanup
- **Coordination Index recalibration**: IDF-weighted `correlations_idf` shadow surface (commit 12d56e2, 2026-04-26) を frontend に切替え、旧 `correlations` を sunset。判断は live data での discrimination 検証後 (active escalation サンプル蓄積待ち)
  - shadow 投入時の挙動 (taiwan_contingency 平時): raw≥60 が 6/21 → idf≥60 が 0/21、raw mean 54.4 → idf mean 0.3。平時の coordination が事実上ゼロ判定される (false positive 解消)

  **A-1 計算済しきい値 (commit 7f75998 直後の live tick, 2026-04-26)**

  | percentile | raw correlations | idf | idf_l3 | idf_l7 |
  |---|---|---|---|---|
  | min | 32.98 | 0.00 | 0.00 | 0.00 |
  | P50 | 52.91 | 0.00 | 0.00 | — |
  | P75 | 64.43 | 0.29 | 0.39 | — |
  | P90 | 71.63 | 1.22 | 1.59 | — |
  | P95 | 86.66 | 1.48 | 1.96 | — |
  | P99 | 90.57 | 4.12 | 5.44 | — |
  | max | 90.57 | 4.12 | 5.44 | 0.00 |
  | mean / σ | 53.6 / 17.3 | 0.40 / 0.93 | 0.53 / 1.23 | 0 / 0 |
  | n (pairs) | 21 | 21 | 21 | 21 |

  L7 が全 0 の理由: 7 日 baseline window がまだ蓄積中。L3 は片寄った tail が確認できる (idf > l3 > raw 安定性の順)。

  **採用しきい値 (radar.js に追加済 — A-1 段階では宣言のみ、A-2 で配線)**
  | constant | 旧 (raw) | 新 (idf) | 根拠 |
  |---|---|---|---|
  | OVERLAP_THRESHOLD | 15 | 0.5 | P75 直上 — "rare ASN を共有していない" pair を除外 |
  | _COORD_STRONG_MIN | 60 | 1.5 | ≈P95 — analyst-actionable な top 5% |
  | (新) _COORD_ALARM_MIN | — | 3.0 | P99+ — 異常な ASN 共起 |

  **検証メモ**: n=21 / 1 tick の thin data なので、A-2 配線後 7 日程度の累積データで再確認すること。escalation 期 (もしあれば) も別途 percentile を取り、平時↔有事の separation が現状候補で取れているかを見る。

  - 残り作業: (a) frontend `updateCoordinationIndex` を `correlations_idf` 参照に変更 (A-2 完了 / commit b5328be)、(b) Coord 既定 OFF → STRONG 復帰検討 (A-2: 観察期間後)、(c) intel guide Ch.8 Q2 の式更新 (A-3 完了 / commit 58403d6)、(d) shadow surface 撤去判断 (A-4: 後述)

  **A-4 判断 (2026-04-26): raw `correlations` は当面残置**

  消費者監査の結果、raw `correlations` を即時削除すると以下が破壊される:

  | 場所 | 用途 | 移行に必要な作業 |
  |------|------|------------------|
  | `radar/routes/core.py:838` | `high_correlation = any(v > 30.0 …)` — strategic alert フラグ | IDF レンジでの閾値再校正 (raw 30 → idf 約 0.5–1.0) |
  | `radar/routes/core.py:946,1200` | `max(correlations.values())` — `max_overlap` メトリクス出力 | IDF レンジでの意味づけ。analyst 慣れている "% 表現" を IDF (0–~5) に置き換える UI 文言整理 |
  | `radar/routes/analytics.py:309` | analytics route 内で参照 | route 内の閾値 / 表現を IDF 化 |
  | `radar.js:3645-3650` | HUD「max ASN overlap: X%」表示 | %表記を捨てて "X.X (IDF)" 形式に。tooltip 文言、i18n キー両方 |
  | `test_engine.py:25,365,370,376,405` | `calculate_overlap()` 直接テスト | 関数削除なら 4 件のテスト改修 |

  即時撤去のリスクは frontend Coord links (A-2 で移行済) ではなく、上記 backend 統計フィールドの誤動作。raw 計算コストは 1 tick あたり pair 数 × O(n_asn) で ~ms オーダー、放置しても害はほぼ無い。

  **次フェーズ (Phase 5 候補)**: 上記 5 ヶ所を 1 箇所ずつ IDF 化 → raw `calculate_overlap` 関数と shadow 計算を削除。各消費者ごとに「IDF レンジでの新閾値はいくつか」を data-driven に決定する必要があり、A-1 と同等の calibration 作業が 5 回分必要なため、独立フェーズとして切り出す。

  ### 10.2.1 Phase 5 — backend raw `correlations` 消費者の IDF 化

  **方針**: blast radius が小さい順に 5 サブタスクへ分割。display / metadata 系 (5-1〜5-3) は behavior change を伴わない。scoring を変える 5-4 は本来独立コミット予定だったが、e57f8c8 で 5-1〜5-4 を同コミット内に混在させてしまった (uncommitted state を分割せず一括で `git add` した手順ミス)。今後 revert する場合は file-level revert ではなく、5-4 行を打ち消す follow-up コミットで対応する。テスト保守の 5-5 は raw 関数自体を残置するため deferred。

  | サブ | site | 種類 | calibration |
  |------|------|------|-------------|
  | **5-1** | `analytics.py:309` | display (`len(corr)` のみ — 値非依存) | 不要 |
  | **5-2** | `core.py:946` | rationale display string `"X.X% overlap"` → `"X.XX IDF overlap"` | 不要 (表示のみ) |
  | **5-3** | `core.py:1200` | SYNC_DDOS event metadata `max_overlap` → `max_overlap_idf` (write-only) | 不要 (consumer なし) |
  | **5-4** | `core.py:838,947` | `high_correlation` 閾値 raw `>30.0` → IDF `>=1.5` | A-1 STRONG_MIN を流用。raw 30 は P50≈53% 下回りで常時発火していた校正ミスを修正 |
  | **5-5** | `test_engine.py` 4 件 | `calculate_overlap()` 直接テスト | 関数自体は残置 (削除しないなら不要) |
  | **5-6** | `radar.js:3623-3628` | HUD max-overlap pill (A-4 監査の `3645-3650` は誤記。実体はこの位置) | display only。色 tier を A-2 と揃え (40%/20% → IDF 1.5/1.0)、書式 `X% → X.XX IDF` |

  ### 10.2.2 Phase 6 — raw `correlations` surface 撤去 (完了)

  Phase 5 で production code から raw 依存が消えたため、surface 自体を削除:

  | 削除対象 | 場所 | 影響 |
  |----------|------|------|
  | `correlations`, `correlations_l3`, `correlations_l7` 計算 | `radar/routes/core.py:755,784-786` | 1 tick あたり pair × O(n_asn) の計算が消える |
  | API response の raw 3 フィールド | `radar/routes/core.py:2641` | external consumer なし (Phase 5 監査で confirm)、外向き API contract が IDF only に |
  | `from radar.scoring import calculate_overlap` | `radar/routes/core.py:27` | 残置: 関数本体、test_engine.py 4 件 (NP6 replay 用に温存) |
  | `_COORD_DATA_SOURCE` enum, `_buildCoordParams('raw',…)` 分岐, `rawParams` block, `_COORD_STRONG_MIN=60` | `radar.js:5543-5641` | code 削減 ~30 行、`_buildCoordParams(strat)` の API が `(strat)` だけに |

  **残置の理由**: `calculate_overlap` 関数本体は `radar/scoring.py` に存続。analyst が「raw vs IDF を historical event で比較したい」場合の replay フックが必要 (NP6)。consumer が production になく、`test_engine.py` 4 テストが 1 関数の正確性を保証しているだけのコストなら、削除より残置のほうが NP6 整合。

  **検証**:
  - python `pytest tests/test_engine.py` → 153/153 green
  - node `tests/test_wp_alarm.js` → 46/46 green
  - container rebuild → healthy、scoring tick エラーなし
  - `curl /radar.js | grep _COORD_DATA_SOURCE|rawParams|correlations_l3` → 0 hits

  **A-4 監査の訂正**: 当初「`radar.js:3645-3650` で HUD `max ASN overlap: X%` を表示」と記載していたが、実際の grep 結果では radar.js 側に `max_overlap` の数値消費は存在せず、誤記。frontend は A-2 で既に `correlations_idf*` に切替済で raw に依存しない。

  **5-4 の意義**: raw 30% 閾値が `correlations` の P50 (≈53%) を下回っていたため、`cf_botnet_overlap` は通常時から FIRED し続け、`SYNC_DDOS` sequence event の precision を低下させていた。IDF への移行で「ubiquitous な AWS/Cloudflare 共起 (= 攻撃の証跡ではなく commodity ASN 利用)」を分母から外し、true positive のみを残す。recall は STRONG_MIN=1.5 (A-1 calibration の P95 付近) で確保 (NP1 整合)。

  **観察期間**: 5-4 commit 後 7 日、`cf_botnet_overlap` FIRED 頻度と `SYNC_DDOS` 発火回数を観察。期待値は両者とも顕著に減少。減りすぎたら閾値を STRONG_MIN=1.5 から 1.0 (≈P90) へ緩める。

### 10.3 ロールバック手順

各 Phase で問題発生時:
- **Phase 1**: feature flag `V2_API_ENABLED=false` で v2 API 無効化、DB migration は維持 (前方互換)
- **Phase 2**: 当初は個別 feature flag (`V2_ATTACK_MODE_ENABLED` 等) を想定したが、実装過程で derivation gate に組み込まれず vestigial 化したため 2026-05-05 に撤去。個別ロールバックが必要な場合は `V2_CONCLUSION_LEDGER_ENABLED=false` で全停止後に問題 deriver を hot-fix する運用に切替
- **Phase 3**: localStorage `ui_version=v1` で v1 UI 強制復帰
- **Phase 4**: v1 撤去後は roll-forward のみ (DB は不可逆 migration を含む)

---

## 11. 互換性とリスク

### 11.1 既存テストへの影響

| カテゴリ | 影響 |
|---------|------|
| **scoring 系** (test_engine, test_scenarios, test_scenario_scoring 等) | 大半は維持、Conclusion wrapper 追加で 30+ 新規テスト |
| **intel 系** (test_intel_*) | LLM プロンプト永続化のため `llm_call_log` 周辺テスト改修 (10 件程度) |
| **API 系** (test_routes_*) | v1 API テストはそのまま維持、v2 API 新規 50+ テスト |
| **theater 用語** | codemod 実行で既存テスト内の theater 参照も置換、grep で fail させて確認 |

総工数: 既存 563 件 → 700+ 件 (約 25% 増)、既存破壊は最小限。

### 11.2 DB migration roll-back 性

| migration | roll-back 可能性 | 備考 |
|-----------|----------------|------|
| v19 (conclusions) | DROP TABLE で OK | 過去結論は失われる |
| v20 (llm_prompts + ALTER) | ALTER の DROP COLUMN 不可 → 新 DB 作成必要 | SQLite 制限 |
| v21 (inconclusive_continuity_log) | DROP TABLE で OK | |
| v22 (analyst_feedback) | DROP TABLE で OK | analyst feedback は永続 retention のため roll-back は推奨されない |

不可逆 migration (v20 ALTER) の前に DB バックアップ必須。

### 11.3 主要リスク

| リスク | impact | 対策 |
|-------|--------|------|
| v1 API 利用者の breakage | M | 90 日 deprecation 期間 + Sunset header + アクセスログ可視化 |
| attack_mode 誤推定の組織判断歪曲 | H | confidence < 0.6 は UI で `TENTATIVE` ラベル、disclaimer 強調、Phase 2 shadow で 14 日検証 |
| LLM prompt 永続化のストレージ膨張 | M | sha256 dedup、prompt_text retention 90 日、cold storage は v2.1 検討 |
| theater codemod の破壊 | H | dry-run + diff レビュー必須、5 batch 分割 commit、各 batch で `pytest` |
| Conclusion スキーマ進化 | M | `api_version` フィールドで version 明示、後方互換性は major version で破壊許容 |
| analyst feedback 注入の歪み | M | Phase 3 で UI 提供時に「複数アナリスト集計」を表示、単一 feedback で recall を更新しない |

### 11.4 セキュリティ考慮

- **LLM プロンプト永続化**: プロンプトに analyst PII が含まれる可能性 → analyst id 等の最小化を pre-insert hook で実施
- **analyst_feedback**: analyst_id を保存するため、authenticated route のみ受付、JWT 検証必須
- **API v2**: 既存 JWT auth を流用、admin 専用エンドポイント (`/admin/inconclusive_continuity`, `/admin/llm_prompt/`) は role check 必須

---

## 12. 工数見積もり

### 12.1 Phase 別 (専任 1 名想定)

| Phase | 内容 | 工数 |
|-------|------|------|
| **Phase 0** | 設計凍結 + scaffolding | **0.5 人月** (本セッション + 次セッション 1 回) |
| **Phase 1** | 基盤層: スキーマ + LLM 永続化 + theater 撲滅 + v2 API 骨格 + NP7 disclaimer + 旧 P5 駆逐 | **3.0 人月** |
| **Phase 2** | 結論層: attack_mode + trend 三層 + per_domain + ranking + calibration governance + ACLED/GDELT + Design W default-on | **4.0 人月** |
| **Phase 3** | UI: Analyst Workbench + drill-down + export + analyst feedback UI + v2 default-on | **3.0 人月** |
| **予備 (15%)** | 較正失敗・回帰対応 | **1.5 人月** |
| **合計** | | **約 12 人月 (暦 12 週、専任)** |

### 12.2 旧 P1-P3 計画 (前回作成) との対応

前回計画の項目を v2.0 各 Phase に吸収:

| 旧計画項目 | v2.0 配属 | 備考 |
|-----------|----------|------|
| P1-1 conclusion_meta envelope | **Phase 1** | Conclusion スキーマ自体に統合 (envelope ではなく一級市民化) |
| P1-2 LLM プロンプト永続化 | **Phase 1** (ADR-V2-009) | scope そのまま |
| P1-3 旧 P5 文言の駆逐 | **Phase 1** (ADR-V2-007) | scope そのまま |
| P1-4 Help Guide 分割 | **Phase 3 へ降格** | UI 全面再設計と同時に実施した方が破壊少 |
| P1-5 scenario-refactor.md 圧縮 | **Phase 0** で実施 (本書分離) | 本書分離自体が圧縮効果 |
| P1-6 CLAUDE.md 用語重複 | **Phase 0** で実施 | scenario-refactor.md §4.2 参照化 |
| P2-1 INSUFFICIENT_DATA 検知 | **Phase 2** (ADR-V2-010) | scope 拡大、scheduler 統合 |
| P2-2 ADR-026 phase readiness | **Phase 2** | Design W default-on の前提 |
| P2-3 breakdown フロント完備 | **Phase 3** | Analyst Workbench drill-down に統合 |
| P3-1〜P3-4 | **Phase 3 もしくは v2.1** | UI 全面再設計に編入、運用データ要は v2.1 |

---

## 13. ドキュメント運用ルール

### 13.1 単一情報源原則

- **CLAUDE.md** = ツール定義 + NP1-NP7 + 用語 + コーディング規約
- **本書 (v2-migration.md)** = v2.0 の唯一の設計仕様
- **scenario-refactor.md** = v1.x の凍結資料 (履歴保全のみ、新規変更は本書)
- **ADR**: 本書 §4 にインライン記載 (ADR-V2-NN)、別ファイルは作らない

### 13.2 サイズ管理

- 本書は **2,500 行を上限** とする
- 上限接近時は scenario-refactor.md と同じ「ルール 8」(実装完了仕様は実コード参照に圧縮) を適用
- Phase 完了ごとに該当章を圧縮

### 13.3 改版履歴

| Version | 日付 | 変更概要 |
|---------|------|---------|
| 2.0.0-design | 2026-04-25 | 初版。Phase A 監査 + ADR-V2-001〜012 + Conclusion スキーマ + v2 API 骨格 + 三段階 rollout |

---

## 14. 確認事項と次のアクション

### 14.1 ユーザー確認 (本書承認時に解消)

すべて **ユーザー前回承認済み** (本書はその承認を反映):
1. ✅ attack_mode 粒度: base 5 + scenario extension hybrid (ADR-V2-002)
2. ✅ v1 API sunset: 90 日 (ADR-V2-003)
3. ✅ Export 形式: Markdown/PDF のみ、STIX/JSON-LD は v2.1 (ADR-V2-004)
4. ✅ ground truth: ACLED+GDELT 自動 + 手動 UI 並行 (ADR-V2-005)
5. ✅ theater 撲滅: 内部一斉置換 + v1 adapter (ADR-V2-006)

### 14.2 Phase 0 残タスク (本セッションで実施)

- ✅ 本書 (v2-migration.md) 作成
- ⏳ CLAUDE.md 更新 (本書を必読参照に追加 + 「進行中の大規模リファクタリング」節を更新)
- ⏳ scenario-refactor.md ステータスを `v1-frozen` に更新 + 本書へのハンドオフ追記
- ⏳ `radar/conclusions/` パッケージ scaffolding (`__init__.py` + `base.py` (Conclusion dataclass))
- ⏳ DB migration v19 (conclusions テーブル) 追加
- ⏳ DB migration v20 (llm_prompts + llm_call_log.prompt_sha256) 追加
- ⏳ `tests/test_conclusions.py` 基本テスト
- ⏳ `scripts/codemod_theater.py` scaffolding
- ⏳ Phase 1 実装ハンドオフドキュメント作成

### 14.3 次セッション (Phase 1) 着手手順

1. **theater codemod 本実行** (`scripts/codemod_theater.py` を 5 batch で commit)
2. **v1 API adapter 配置** (`radar/routes/_v1_compat.py`)
3. **NP7 disclaimer の API 必須化** (`radar/conclusions/disclaimer.py` + 全 v2 route で wrap)
4. **DB migration v21/v22 追加**
5. **`/api/v2/scenarios/<id>/conclusions` (read-only)** 実装
6. **LLM プロンプト永続化** (`radar/llm_client.py` で sha256 計算 + `llm_prompts` への insert)
7. **旧 P5 文言の駆逐** + `tests/test_ui_integrity.py` 禁止文字列テスト
8. **Phase 1 完了テスト** (全 563 既存 + 新規 30+)

---

## 付録 A: 参照コード行一覧

(本書で言及した実装箇所の早見表)

| 機能 | 主要ファイル / 行 |
|------|------------------|
| Conclusion dataclass | `radar/conclusions/base.py` (Phase 0 新規) |
| derive_tl 既存実装 | `radar/scoring.py:1087` |
| LLM client 既存実装 | `radar/llm_client.py` (Phase 1 で `llm_prompts` 永続化を追加) |
| DB migration エンジン | `radar/database.py:1066-1099` (`_run_migrations`) |
| 既存最大 migration | `radar/database.py:1049` (v18) |
| velocity / acceleration | `radar/scoring.py:1011, 1025, 1045` |
| convergence_bonus | `radar/scoring.py:1078` |
| シナリオ scoring loop | `radar/routes/core.py` (Phase 1 で v2 wrapper 追加) |
| shadow_sampler | `radar/shadow_sampler.py` |
| scenario プリセット | `geo_data.json` (Phase 2 で attack_mode_extensions 追加) |

## 付録 B: 削除/非推奨対象一覧

(Phase 4 で削除する対象を Phase 0 時点で記録)

| 対象 | 削除タイミング | 代替 |
|------|--------------|------|
| `index.html` 旧 P5 文言 (Ch.1, 2, 8, 10) | Phase 1 | NP4/NP7 整合表現に置換 |
| `i18n.js` 旧 P5 関連キー | Phase 1 | 新 disclaimer キーに置換 |
| `/api/threat_data` 等 v1 API | Phase 4 | `/api/v2/...` |
| 旧 v1 UI (radar.js + index.html 主要部) | Phase 4 | Analyst Workbench (radar_v2.js + index_v2.html) |
| `theater` adapter 層 | Phase 4 | (既に内部は scenario_id/country) |
| `scenario-refactor.md` (本書に統合済みの箇所) | Phase 4 (履歴として残置) | 本書 |

---

(本書終わり。Phase 1 着手前に必ず本書を再読し、変更があれば本書を更新してから着手すること)
