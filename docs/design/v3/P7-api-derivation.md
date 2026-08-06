# P7 — API 導出設計(WP-4.0 成果物 1/2)

**位置づけ**: P6 O-19 の裁定に基づく WP-4.0 の成果物。**現行 167 endpoint を出発点にせず、
P4 の出力 O-1〜O-12 + 入力 I-2 から順方向に v3 の API 面を導出し、現行は §5 で突合する**(ADR-V3-003 の API への適用)。
本書の裁定も P6 と同様「**推奨 = 実装既定**」。WP-4.1 の完了条件は本書のマトリクスを正とする。
**オーナー承認（2026-08-06）**: 報告 1 系統化（SALUTE / weather_brief / sitrep / daily_summary 廃止）を含め、
本書の裁定は**全件承認済**（P8 の 4 裁定承認と同時）。

**導出原則**(P1 §10 / S2-PROP-016〜021 を継承):
1. **読み取りは射影・指令は明示** — GET に副作用ゼロ。focus 登録・採点トリガ・キュードレインは GET から消える
2. **envelope は 1 形・NP7 必須** — 例外なし(現行 `/api/intel/pending/triage` の NP7 欠落も解消)
3. **1 出力 1 供給源** — 同じ情報を返す endpoint を 2 本持たない。二重供給は v1 sunset(ADR-V3-009)と同時に消す
4. **replay と live は同形** — 過去断面は同じ射影の `?at=` パラメータで取る(現行 DP9 の構造的解消)

---

## 1. v3 API 面(順方向導出の結果)

### 1.1 読み取り(射影)— 15 本

| # | Endpoint | 仕える出力 | 内容 |
|---|---|---|---|
| R1 | `GET /api/v3/scenarios` | 基盤 / I-2 | シナリオ台帳 + focus 状態 + 各シナリオの TL/変化量サマリ(シナリオバー用の軽量射影)。compare は本射影 2 回のクライアント合成で足りる |
| R2 | `GET /api/v3/scenarios/<sid>/conclusions` | **O-1〜O-5, O-7, O-8, O-10, O-12** | 5 結論型 + 結論不可(理由・解消条件つき)。`calibration_status` を**全 5 型に**付記(現行は 2/5 型のみ)。`?include=narrative` で AP2 平文(§4)。**`?at=<ts>` で過去断面(O-12)— live と完全同形** |
| R3 | `GET /api/v3/scenarios/<sid>/conclusions/history` | **O-2, O-7** | **L1 の無間引き TL ストリームへの派生ビュー**(P6 O-16)。TL 系列・トレンド窓・null-zone 連続日数・慢性判定を 1 本で供給。間引き済み形も `?resolution=` で射影 |
| R4 | `GET /api/v3/conclusions/<id>` / `<id>/derivation` | **O-6** | 結論単体 + **完全導出**(式 ID・実効閾値・一次ソース URL・LLM プロンプト sha + 本文・寄与内訳・**反証レポート**(to_higher/lower — SCORE-037 近接度を吸収)) |
| R5 | `GET /api/v3/scenarios/<sid>/evidence` | **O-4, O-6** | 兆候行列(FIRED/OK/**抑制済+理由**)・個別異常事象・シーケンス連鎖・観測参照。`?domain=` `?sensor=` で絞る。異常イベントの供給はここと R2 anomaly 型の**2 面のみ**(現行 3+形を統合) |
| R6 | `GET /api/v3/attention` | **O-9** | 順位付き注目リスト。**S8 が台帳に書いた順位をそのまま射影**(フロント再計算しない — P5 O-8)。各行に score の導出(novelty × confidence_delta × blindness の実効値)と per-user 状態(ack/snooze)を含む。**L5 の drift signal も注目行として合流** |
| R7 | `GET /api/v3/self_eval` | **O-11** | **合成信頼度 1 値 + 内訳**(P8 §4): recall / null-zone / drift / L5 5 監視 / L5 heartbeat / バックアップ経過 / LLM 健全性 / データ鮮度。現行の calibration/health・chronic_inconclusive・adaptive_zscore_status・data_status・llm_preflight・intel/stats の情報はここの内訳ブロックに吸収 |
| R8 | `GET /api/v3/sensors` / `<id>/observations` | O-11 詳細 / O-4 詳細 | センサー健全性の**単一形**(現行 4〜5 形を統合: sensor_health / sensor_reliability / catalog / data_status.sensors)+ 観測系列(スパークライン・WP-0.1 の 60 日台帳への射影) |
| R9 | `GET /api/v3/decisions` / `<id>` | **O-12** | **統一判断台帳**(AP4): 較正適用・auto-judge・triage 操作・抑制発火・設定変更・S8 順位スナップショットを `?type=` で射影。現行の decisions/history・auto_judge/decisions・config_audit・llm_routing/audit・llm_features/audit の 5 面を 1 本化 |
| R10 | `GET /api/v3/thresholds` / `<id>/lineage` | **O-6** | 閾値レジストリの現在値 + 変更系譜(NP6)。O-18 の二分(可変キー / provenance 付き定数)を**両方**露出 — 定数も「開示」はする |
| R11 | `GET /api/v3/intel` / `/pending` | I-2 | インテルキュー読み取り。**NP7 envelope 必須**(現行の欠落を解消)、認可は analyst |
| R12 | `GET /api/v3/scenarios/<sid>/report.md` | O-6/O-8 | **唯一の報告出力**(結論 Markdown)。SALUTE / weather_brief / sitrep / daily_summary は持たない(§5 理由) |
| R13 | `GET /api/v3/proposals` | I-2 | 較正・センサー無効化・シナリオ改善の**統一提案キュー**(`?kind=`)。現行 3 家族を 1 本化 |
| R14 | `GET /api/v3/config` | I-2 | O-18 の可変キー(20〜30)のみ。値・出所層・反映タイミング |
| R15 | `GET /api/v3/app_config` + `GET /healthz` | infra | 起動設定 / 死活 probe |

### 1.2 指令(I-2)— 約 26 本

| # | Endpoint 族 | 本数 | 内容 |
|---|---|---|---|
| C1 | `POST /api/v3/focus` | 1 | focus 登録(読み取りの副作用から分離 — PROP-001) |
| C2 | `POST /api/v3/conclusions/<id>/feedback` | 1 | ラベル投稿(analyst+、G-01 恒久化)。読み取りは R4 に含む |
| C3 | `POST /api/v3/intel/<id>/{confirm,reject,override,revert}` | 4 | インテル裁定(現行 4 動詞を維持) |
| C4 | `POST /api/v3/attention/<id>/{ack,snooze,dismiss}` + `PUT /api/v3/attention/thresholds` | 4 | **per-user + サーバ台帳**(P5 O-7)。閾値調整は PROP-015 どおり keep + UI 接続 |
| C5 | `POST /api/v3/proposals/<id>/{apply,dismiss,defer}` | 3 | 提案裁定(R13 と対)。単一ガード評価器経由(P4 S9) |
| C6 | `POST /api/v3/whatif` | 1 | **反実仮想 1 系統**(現行 2 系統 + `X-Scenario-Overlay` を統合 — PROP-009)。**サーバの L2 カーネルを dry-run で呼ぶ**(フロント再実装 G-09 の禁止) |
| C7 | `POST /api/v3/config/<key>` + `DELETE` | 2 | 可変キーの変更・解除(全件 decisions 台帳へ) |
| C8 | `GET/POST/DELETE /api/v3/suppressions` | 3 | ノイズ除外規則(現行 noise_exclusion。GET/DELETE の UI 導線欠落は P8 で解消) |
| C9 | `GET/POST /api/v3/ground_truth` | 2 | 人手 ground truth(現行 confirmed_threats。S9 の教師信号) |
| C10 | `GET /api/v3/human_anchor/queue` + `POST .../answer` | 2 | AP3 人間アンカー(独立性を壊さない設問形式は S1-UI-028 を継承) |
| C11 | `/api/v3/admin/scenarios` CRUD 族 | 6 | シナリオ登録・重み・状態・reset(NP7: 登録判断は組織側、ツールは CRUD を提供するのみ)。changelog は R9 `?type=scenario` に吸収 |
| C12 | LLM 運用族: `features`(get/set/clear/kill_switch)+ `routing`(get/set/delete) | 7 | NP3/緊急停止に必要な運用面。監査は R9 へ |
| C13 | auth 族: login/refresh/logout/register/password + users CRUD | 9 | `auth/settings` は廃止(PROP-014: per-user 設定は attention thresholds + config へ) |

### 1.3 WebSocket — 1 チャネル・4 イベント

room は `scenario:{sid}`(`theater` 語彙は消滅 — C-01 最深部)。
イベント: `conclusion_update`(R2 差分)/ `attention_update`(R6 差分)/ `sensor_status` / `notification_result`。
`ambush_alert`・`sequence_event` は conclusion_update(anomaly 型)に統合。

### 1.4 規模

**REST 約 61 本(読み取り 15 + 指令 26 + auth/infra 20)+ WS 4 イベント** — 現行 167 + WS 10 から**約 63% 削減**。
全 endpoint が §2 のマトリクスで O-x または I-2 に写像される。**写像の無い endpoint は存在しない**。

---

## 2. O × endpoint 必要性マトリクス

| 出力 | 一次供給 | 詳細/drill | 現行の二重供給(v1 sunset で消える) |
|---|---|---|---|
| O-1 TL | R2 | R3(系列) | threat_data.strategic_alert / threat_history 3 形 |
| O-2 トレンド | R2(trend 型) | R3(窓の生データ) | SCORE-036 系(P6 O-15 で廃止) |
| O-3 ドメイン別 | R2(per_domain 型) | R5(兆候行列) | threat_data.domains |
| O-4 異常事象 | R2(anomaly 型) | R5(事象詳細 + 連鎖) | alert_timeline / history/alerts の 3 面 |
| O-5 攻撃シナリオ | R2(attack_mode 型) | R4(導出) | — |
| O-6 導出根拠 | R4(derivation) | R10(閾値系譜)/ R5(観測参照) | score_breakdown(drop 済) |
| O-7 結論不可 | R2(state=null + 理由・解消条件) | R3(null-zone 連続) | chronic_inconclusive 単独面 |
| O-8 NP7 | **全 endpoint の envelope 必須フィールド** | R12(報告にも常設) | (D) 形 envelope の欠落 → 解消 |
| O-9 注目順位 | R6(**S8 台帳の射影** — 新設) | R9(順位スナップショット履歴) | フロント専用 triage_score(台帳に残らない → 解消) |
| O-10 平文説明 | R2 `?include=narrative`(**決定論** — §4) | — | POST triage/narrate(LLM — 廃止) |
| O-11 信頼性 | R7(合成 + 内訳) | R8(センサー個別) | calibration/health ほか 6 面に分散 → 吸収 |
| O-12 判断再生 | R2 `?at=` + R9(判断台帳) | R3(系列) | replay 専用形(live と不一致 → 同形化) |
| I-2 入力 | C1〜C13 | — | GET 副作用(focus/force/muted)→ 全廃 |
| I-3 事後事実 | (scheduler 内部。API 面には出ない) | — | — |

---

## 3. threat_data の分解(最大の god-endpoint)

`GET /api/threat_data`(トップ 13 キー + analytics 約 40 サブオブジェクト、UI メインポーリング)は
**R1 + R2 + R5 + R7 + R8 の 5 射影に分解**して消滅する。ポーリングは「R1(軽量・全シナリオ)+
focused の R2/R5」の 2 段になり、WS 主導へ移行可能(PROP-001)。`observed_at` / `data_freshness_sec` は
全射影の必須フィールド(「いつの採点か」を UI が常時表示)。

## 4. O-10 の AP2 準拠化(narrate の置換)

現行 `POST /api/v2/triage/narrate` は **LLM 駆動で P4 S7(テンプレート + スロット、LLM 不使用)と矛盾**するため
v3 に持ち込まない。置換設計:

- **単一のテンプレートエンジンをバックエンドに置く**(現行フロント pure module `self_explanation.js` の
  ロジックを昇格・一本化)。R2 `?include=narrative` と R6 の行ナラティブが同じ実装を使う
- テンプレートは **ID + バージョンを持ち、provenance に `narrative_template_ref` として記録**(AP4 で再生可能)
- スロット値はすべて envelope 内の数値・状態から埋める。**同じ結論からは常に同じ説明が出る**(AP2)
- 文字列は日本語専用(i18n 辞書はテンプレート本文を保持)

## 5. 現行 167 endpoint の処遇(全数・族単位)

分類の凡例: **吸収** = v3 射影に統合 / **置換** = 同機能の新形 / **drop** = 目的写像なし(理由付き)/ **CLI** = 管理スクリプト化。
v1 契約は cutover と同時に終了(ADR-V3-009)。GUIDE(102 本の文書化契約)は v1 遺産であり、v3 GUIDE は本書の面で書き直す。

| 現行族 | 本数 | 処遇 | 先 / 理由 |
|---|---:|---|---|
| threat_data | 1 | 分解 | §3 |
| v2 conclusions 族(per-type/by-id/audit_trace/.md/feedback×2 含む) | 7 | 吸収 | R2/R4/R12/C2 |
| v2 replay / self_eval | 2 | 吸収 | R2 `?at=` / R7 |
| threat_history / history/{threat_levels,timeseries,countries,hod_baseline,alerts,export} | 7 | 吸収 | R3/R5/R8(export は R12 + R3 で代替) |
| alert_timeline / sequence_chain / history/sequence_events | 3 | 吸収 | R5(異常 3 面 → 2 面) |
| v2 attention 族 + intel/pending/triage + decisions/triage 族 + decisions/threshold | 13 | 吸収 | R6/C4(AP1 一本化。NP7 欠落解消、PROP-015 採用) |
| decisions/history・by-id・revoke + auto_judge/decisions + config_audit + llm_routing/audit + llm_features/audit | 7 | 吸収 | R9(監査 5 面 → 1 本) |
| threshold_history 族 | 4 | 吸収 | R10 |
| calibration/{health,tier_governor} + chronic_inconclusive + adaptive_zscore_status + data_status + llm_preflight + intel/stats + llm_call_stats | 8 | 吸収 | R7(AP3 内訳へ) |
| admin/sensor_health + sensor_reliability + sensors/catalog + sensors/observations | 4 | 吸収 | R8 |
| proposals 3 家族 + drift_signals×2 | 8 | 吸収 | R13/C5(drift は R6 の注目行としても合流) |
| intel 読み書き(intel/pending/confirm/reject/revert/override) | 6 | 吸収 | R11/C3 |
| whatif 2 系統 + whatif_weights + `X-Scenario-Overlay` | 3 | 置換 | C6(1 系統) |
| noise_exclusion / confirmed_threats / human_anchor | 7 | 置換 | C8/C9/C10 |
| v2 config 族 + sensor_config | 5 | 置換 | R14/C7(O-18: 可変 20〜30 キーのみ) |
| scenarios + compare + admin/scenarios 族 + app_config | 11 | 吸収 | R1/C11/R15(compare はクライアント合成) |
| llm_features / llm_routing / llm_models | 12 | 置換 | C12(7 本に圧縮) |
| auth 族 | 11 | 置換 | C13(9 本。auth/settings 2 本は PROP-014 で廃止) |
| SPA 配信 | 2 | keep | infra |
| **salute_report / weather_brief / sitrep / daily_summary** | 4 | **drop** | 報告 1 系統化(R12)。**salute/weather は空キャッシュで ROUTINE/CLEAR を返す G-17 の当事者**であり、結論捏造の構造ごと廃止。sitrep の需要は R2+R12 が満たす |
| **ip_check** | 1 | **drop** | 単発 IP 照会ユーティリティ。O 写像なし。GreyNoise 文脈は R5 の evidence が結論に紐づけて出す |
| **spof_analysis** | 1 | **drop** | 第 2 採点エンジンによる反実仮想(DP12)。センサー喪失の影響は R7 の L5 内訳(取得生存・発火生存)が実測で示す。需要が再確認されたら C6 の一種として単一カーネルで再実装 |
| **deep_analytics** | 1 | **drop** | GUIDE のみ・UI 導線なし(D6 判定)。内訳は R5/R7 に散在吸収 |
| discovery(cooccurrence v1+v2 / clusters / clusters replay) | 4 | **drop(凍結)** | 実消費者ゼロ(D6)。シナリオ発見は NP7 上、組織側判断の支援 — 価値実証後に R13 の提案 kind として再設計 |
| climate + climate/feed | 2 | 凍結 | ADR-V3-008 |
| tradecraft analyst/* | 25 | drop | ADR-V3-007(decision_ledger の自動記録思想は R9 が継承) |
| UNREFERENCED 8(persist_save / score_breakdown / analytics×3 / intel/sources / shadow_write_metrics / attention…recompute) | 8 | drop | ADR-V3-009(recompute のみ CLI 化) |
| telegram_log/clear + calibration/run_now | 2 | CLI | 運用フックは API 面から降ろす |
| triage/narrate | 1 | 置換 | §4(決定論ナラティブ) |
| **計** | **167** | | 吸収/置換 ≈ 118 → v3 の 61 本へ縮退、drop/凍結/CLI ≈ 49 |

## 6. WP-4.1 への引き渡し

- 完了条件は「**本書 §1 の面がすべて実装され、§1 に無い endpoint が存在しない**」に読み替える(S2 の 52 条項は
  意味論の参照元として有効。矛盾時は本書が優越)
- envelope 不変条件(S2-API-018 の構築時拒否)を**全 endpoint に拡張**(PROP-017/018 の契約化)
- 認可は宣言的単一デコレータ(PROP-016)+ 目的ベースマトリクス(PROP-021: AP3 情報は viewer 開放)
- INTEL GUIDE Ch.12(API リファレンス)は本書の面で全面改稿(CLAUDE.md ルール 2)
