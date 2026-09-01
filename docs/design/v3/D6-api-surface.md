# D6 — API サーフェス用途分類（Phase D 診断ドラフト）

作成日: 2026-08-03 / 入力: `docs/design/v3/D1-backend-core.md` §4（167 REST endpoint 全数表）、`docs/design/v3/D1-frontend.md` §4

**手法**: D1 の endpoint 表を起点に、各パスの静的部分を正規表現化（パラメータ部 `<...>` はワイルドカード化、HTML エンティティ復元、`{a,b,c}` 展開）して以下のコーパスを機械照合した。文字列連結による動的組立て（例 `'/api/intel/' + id + '/confirm'`、`` `/api/analyst/assumptions/${id}/lock` `` 内のクォート断絶）は正規表現照合から漏れるため、UI 無し判定となった全 endpoint に対して個別 Grep で追検証し、17 件を UI へ補正した（§2 の表は補正後）。

| 分類 | 定義 | 照合対象 |
|---|---|---|
| **UI** | フロントエンドから fetch される | radar.js / tradecraft.js / autotune_wizard.js / controls_panel.js / llm_features_hub.js / login-init.js / hud_v2_overlay.js ほか全 JS、index.html（GUIDE 章 L1506–2852 を除く） |
| **GUIDE** | INTEL GUIDE に文書化（外部利用者向け公開契約） | index.html L1506–2852（help-modal、Ch.12 API リファレンス含む） |
| **OPS** | scripts/ から実行時に呼ばれる | scripts/*.py, scripts/*.sh（実呼び出しは `smoke_tradecraft.sh` のみ） |
| **TEST** | tests/ から参照 | tests/*.py, tests/*.js |
| **UNREFERENCED** | 上のいずれにも該当しない | —（設計文書での言及のみの場合は「docs言及のみ」と付記） |

docs/ 内の言及（v2-migration.md、v2-ui.md、tradecraft-qa.md、CLAUDE.md 等）は**恒常的な運用手順ではなく設計・移行記録**であるため OPS には数えない（curl 実行例を含む v2-migration.md の該当箇所は Mode C 移行時の一回性の検証手順）。判断材料として §3 に個別記載する。

## 1. 分類サマリ

延べ所属数（複数分類の重複込み）:

| 分類 | 該当 endpoint 数 |
|---|---|
| UI | 132（+ SPA/静的配信 infra 2） |
| GUIDE | 102 |
| TEST | 80（うち TEST のみ 5） |
| OPS | 12（すべて smoke_tradecraft.sh 経由の analyst/auth 系） |
| UNREFERENCED | 8（完全無参照 6 + docs 言及のみ 2） |

組み合わせ別の件数（167 endpoint の排他的分割）:

| 組み合わせ | 件数 |
|---|---|
| UI+GUIDE+TEST | 42 |
| UI+GUIDE | 38 |
| UI のみ | 23 |
| UI+TEST | 17 |
| GUIDE のみ | 11 |
| UI+OPS+TEST | 10 |
| GUIDE+TEST | 9 |
| UNREFERENCED | 6 |
| TEST-ONLY | 5 |
| UNREFERENCED（docs 言及のみ） | 2 |
| UI(infra) | 2 |
| UI+GUIDE+OPS+TEST | 2 |

要点:
- **UI が最大の消費者**（167 中 134）。API サーフェスの 8 割はフロントエンド専用であり、v3 で UI と API を再設計する際に外部契約として保護すべき面は GUIDE 記載の 102 に絞られる。
- **GUIDE のみ**の 11 件は「文書化されたが誰も呼ばない」端点。外部 curl 利用者向けの意図的契約か、死に契約かの判断が必要（§3）。
- **OPS はほぼ空集合**。スクリプト群は DB 直接読取り（docker exec + SQLite）で動作しており、REST を呼ぶのは smoke_tradecraft.sh だけ。v3 で「運用は API 経由」に寄せるか、逆に管理系 API を削る余地がある。
- パスは同一でもメソッドで消費者が異なるケースあり（例: `/api/noise_exclusion` は POST のみ UI、GET/DELETE は GUIDE 記載のみで UI 一覧・削除導線が存在しない）。

## 2. 全 167 endpoint 分類表

| Method | Path | 分類 | v3 への示唆 |
|---|---|---|---|
| GET | `/api/v2/config/registry` | UI | keep（v2 設定基盤） |
| GET | `/api/v2/config/values` | UI | keep |
| POST | `/api/v2/config` | UI | keep |
| DELETE | `/api/v2/config` | UI | keep |
| GET,POST | `/api/sensor_config` | UI+GUIDE | merge→v2/config 検討 |
| POST | `/api/telegram_log/clear` | UI+GUIDE | keep（小） |
| POST | `/api/persist_save` | UNREFERENCED | drop |
| GET | `/api/noise_exclusion` | GUIDE | keep（UI 一覧導線が無い） |
| POST | `/api/noise_exclusion` | UI+GUIDE | keep |
| DELETE | `/api/noise_exclusion/<int:rule_id>` | GUIDE | keep（UI 削除導線が無い） |
| GET | `/api/confirmed_threats` | GUIDE | keep（UI 一覧導線が無い） |
| POST | `/api/confirmed_threats` | UI+GUIDE | keep |
| GET | `/api/daily_summary` | GUIDE | drop or merge→sitrep |
| GET | `/api/cooccurrence` | GUIDE | merge→v2/discovery/cooccurrence |
| GET | `/api/admin/scenarios` | UI+GUIDE | keep |
| POST | `/api/admin/scenarios` | UI+GUIDE | keep |
| PUT | `/api/admin/scenarios/<scenario_id>` | UI+GUIDE | keep |
| DELETE | `/api/admin/scenarios/<scenario_id>` | UI+GUIDE | keep |
| POST | `/api/admin/scenarios/<scenario_id>/state` | UI+GUIDE | keep |
| POST | `/api/admin/scenarios/<scenario_id>/enabled` | UI+GUIDE | keep |
| POST | `/api/admin/scenarios/<scenario_id>/reset` | UI+GUIDE | keep |
| GET | `/api/admin/scenarios/<scenario_id>/changelog` | GUIDE | keep（UI 導線なし・契約のみ） |
| GET | `/api/admin/sensor_health` | UI+GUIDE+TEST | keep |
| GET | `/api/analyst/hidden_signals` | UI | keep |
| GET | `/api/analyst/coverage` | UI | keep |
| GET | `/api/analyst/disconf` | UI+OPS+TEST | keep |
| POST | `/api/analyst/disconf` | UI+OPS+TEST | keep |
| POST | `/api/analyst/disconf/<int:item_id>/retract` | UI | keep |
| GET | `/api/analyst/ach` | UI+OPS+TEST | keep |
| POST | `/api/analyst/ach` | UI+OPS+TEST | keep |
| GET | `/api/analyst/ach/<int:matrix_id>` | UI | keep |
| POST | `/api/analyst/ach/<int:matrix_id>/hypothesis` | UI | keep |
| POST | `/api/analyst/ach/<int:matrix_id>/evidence` | UI | keep |
| POST | `/api/analyst/ach/<int:matrix_id>/score` | UI | keep |
| GET | `/api/analyst/dissent` | UI+TEST | keep |
| POST | `/api/analyst/dissent` | UI+TEST | keep |
| POST | `/api/analyst/dissent/<int:view_id>/resolve` | UI | keep |
| GET | `/api/analyst/assumptions` | UI+OPS+TEST | keep |
| POST | `/api/analyst/assumptions` | UI+OPS+TEST | keep |
| PATCH | `/api/analyst/assumptions/<int:aid>` | UI+OPS+TEST | keep |
| POST | `/api/analyst/assumptions/<int:aid>/lock` | UI+OPS+TEST | keep |
| POST | `/api/analyst/assumptions/<int:aid>/invalidate` | UI | keep |
| GET | `/api/analyst/assumptions/<int:aid>/log` | UI | keep |
| GET | `/api/analyst/premortem` | UI+TEST | keep |
| POST | `/api/analyst/premortem` | UI+TEST | keep |
| POST | `/api/analyst/premortem/<int:eid>/resolve` | UI | keep |
| GET | `/api/analyst/decisions` | UI+OPS+TEST | keep |
| POST | `/api/analyst/decisions` | UI+OPS+TEST | keep |
| GET | `/api/v2/analyst_feedback` | UI+TEST | keep（AP4） |
| GET | `/api/data_status` | UI+GUIDE | keep |
| GET | `/api/sensor_reliability` | GUIDE | merge→admin/sensor_health |
| GET | `/api/alert_timeline` | UI+GUIDE | keep |
| GET | `/api/sitrep` | UI+GUIDE | keep |
| GET | `/api/sequence_chain` | UI+GUIDE | keep |
| GET | `/api/deep_analytics` | GUIDE | 要判断（GUIDE のみ・v1-sunset 候補） |
| GET | `/api/salute_report` | UI+GUIDE | keep |
| GET | `/api/weather_brief` | UI+GUIDE | keep |
| GET | `/api/ip_check` | UI+GUIDE | keep |
| GET | `/api/score_breakdown` | UNREFERENCED(docs言及のみ) | drop（v2 audit_trace が代替） |
| GET | `/api/whatif/catalog` | UI+GUIDE | keep |
| POST | `/api/whatif/simulate` | UI+GUIDE | keep（whatif_weights と統合検討） |
| GET | `/api/spof_analysis` | UI+GUIDE | keep |
| GET | `/api/adaptive_zscore_status` | GUIDE | 要判断（GUIDE のみ） |
| GET | `/api/analytics/calibration_advisory` | UNREFERENCED | drop（v2 calibration が代替） |
| GET | `/api/analytics/confidence_distribution` | UNREFERENCED | drop（v2 llm_conf 較正が代替） |
| GET | `/api/analytics/scenario_phases` | UNREFERENCED | drop |
| GET | `/api/v2/attention` | UI+GUIDE+TEST | keep（AP1） |
| POST | `/api/v2/attention/<rule_id>/snooze` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/attention/thresholds` | UI+GUIDE+TEST | keep |
| PUT | `/api/v2/attention/thresholds/<rule_id>` | UI+GUIDE+TEST | keep |
| DELETE | `/api/v2/attention/thresholds/<rule_id>` | GUIDE+TEST | keep |
| POST | `/api/v2/attention/observations/recompute` | UNREFERENCED | drop or 管理 CLI 化 |
| GET | `/api/v2/auto_judge/decisions` | UI+TEST | keep |
| GET | `/api/v2/calibration/tier_governor` | UI+GUIDE | keep |
| GET | `/api/v2/threshold_history` | GUIDE+TEST | keep（NP6） |
| GET | `/api/v2/threshold_history/<int:row_id>` | GUIDE+TEST | keep |
| GET | `/api/v2/threshold_history/<int:row_id>/lineage` | GUIDE+TEST | keep |
| POST | `/api/v2/threshold_history/<int:row_id>/revert` | TEST-ONLY | keep（安全弁・UI 導線なし） |
| GET | `/api/v2/proposals/sensor_disable` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/proposals/sensor_disable/<int:proposal_id>/ack` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/proposals/scenario_improver` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/proposals/scenario_improver/<int:proposal_id>/apply` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/proposals/scenario_improver/<int:proposal_id>/dismiss` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/proposals/scenario_improver/<int:proposal_id>/defer` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/drift_signals` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/drift_signals/<int:event_id>/ack` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/calibration/run_now` | GUIDE+TEST | keep（管理 curl 契約） |
| GET | `/api/v2/calibration/health` | UI+TEST | keep（AP3） |
| GET | `/api/v2/discovery/cooccurrence` | TEST-ONLY | keep（v1 cooccurrence の受け皿） |
| GET | `/api/v2/discovery/clusters` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/discovery/clusters/<int:run_id>/replay` | TEST-ONLY | 要判断（TEST のみ） |
| GET | `/api/v2/observability/chronic_inconclusive` | UI+GUIDE+TEST | keep（NP5+8） |
| GET | `/api/climate` | UI+GUIDE | keep |
| GET | `/api/climate/feed` | GUIDE | 要判断（GUIDE のみ） |
| GET | `/api/v2/scenarios/<scenario_id>/threat_history` | UI+TEST | keep（v2 コア） |
| GET | `/api/v2/scenarios/<scenario_id>/conclusions` | UI+GUIDE+TEST | keep（v2 コア） |
| GET | `/api/v2/scenarios/<scenario_id>/conclusions/<conclusion_type>` | TEST-ONLY | keep（個別型取得） |
| GET | `/api/v2/conclusions/<conclusion_id>` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/conclusions/<conclusion_id>/audit_trace` | UI+GUIDE+TEST | keep（NP6 コア） |
| GET | `/api/v2/scenarios/<scenario_id>/conclusions.md` | UI+TEST | keep（NP7 出力） |
| POST | `/api/v2/conclusions/<conclusion_id>/feedback` | UI+TEST | keep（AP3/AP4） |
| GET | `/api/v2/conclusions/<conclusion_id>/feedback` | UI+TEST | keep（AP3/AP4） |
| GET | `/api/v2/admin/shadow_write_metrics` | UNREFERENCED(docs言及のみ) | drop（移行観測完了） |
| GET | `/api/v2/replay/<scenario_id>` | UI | keep（AP4） |
| GET | `/api/v2/self_eval` | UI+GUIDE+TEST | keep（AP3） |
| GET | `/api/app_config` | UI+GUIDE+TEST | keep |
| GET | `/api/scenarios` | UI+GUIDE | keep |
| GET | `/api/scenarios/compare` | UI | keep |
| POST | `/api/scenarios/<scenario_id>/whatif_weights` | UI | keep |
| GET | `/api/threat_data` | UI+GUIDE | v3 で分解（god-endpoint） |
| POST | `/api/v2/decisions/triage/snooze` | UI+GUIDE+TEST | keep（AP1/AP4） |
| DELETE | `/api/v2/decisions/triage/snooze` | UI+GUIDE+TEST | keep（AP1/AP4） |
| POST | `/api/v2/decisions/triage/visibility` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/decisions/triage/dismiss` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/decisions/triage/state` | UI+GUIDE+TEST | keep |
| PUT | `/api/v2/decisions/threshold` | GUIDE+TEST | 要調査（UI 未接続） |
| GET | `/api/v2/decisions/threshold` | GUIDE+TEST | 要調査（UI 未接続） |
| GET | `/api/v2/decisions/history` | UI+GUIDE+TEST | keep（AP4） |
| GET | `/api/v2/decisions/<decision_id>` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/decisions/<decision_id>/revoke` | TEST-ONLY | keep（監査系・UI 導線なし） |
| GET | `/api/history/countries` | UI+GUIDE+TEST | keep |
| GET | `/api/history/timeseries` | UI+GUIDE | keep |
| GET | `/api/history/hod_baseline` | UI+GUIDE | keep |
| GET | `/api/history/alerts` | UI+GUIDE | keep |
| GET | `/api/history/sequence_events` | UI+GUIDE | keep |
| GET | `/api/history/threat_levels` | GUIDE | merge→v2 threat_history |
| GET | `/api/history/export` | UI+GUIDE | keep |
| GET | `/api/v2/human_anchor/queue` | UI+GUIDE+TEST | keep（AP3） |
| GET | `/api/intel` | UI+GUIDE+TEST | keep |
| GET | `/api/intel/pending/triage` | UI+GUIDE+TEST | keep（AP1） |
| GET | `/api/intel/stats` | UI+TEST | keep |
| POST | `/api/intel/<item_id>/confirm` | UI | keep |
| POST | `/api/intel/<item_id>/reject` | UI | keep |
| POST | `/api/intel/<item_id>/revert` | UI | keep |
| POST | `/api/intel/<item_id>/override` | UI | keep |
| GET | `/api/intel/sources` | UNREFERENCED | drop |
| GET | `/api/intel/llm_call_stats` | UI+GUIDE+TEST | keep |
| GET | `/api/llm_models` | UI | keep |
| GET | `/api/v2/llm_features` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/llm_features/<key>` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/llm_features/<key>/set` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/llm_features/<key>/clear` | UI+GUIDE+TEST | keep |
| POST | `/api/v2/llm_features/kill_switch` | UI+GUIDE+TEST | keep（緊急停止） |
| GET | `/api/v2/llm_features/audit` | UI+GUIDE+TEST | keep |
| GET | `/api/v2/llm_routing` | UI+GUIDE | keep |
| GET | `/api/v2/llm_routing/overrides` | UI+GUIDE | keep |
| POST | `/api/v2/llm_routing/overrides` | UI+GUIDE | keep |
| DELETE | `/api/v2/llm_routing/overrides` | UI+GUIDE | keep |
| GET | `/api/v2/config_audit` | UI+TEST | merge→llm_routing/audit 検討 |
| GET | `/api/v2/llm_routing/audit` | UI+GUIDE | keep |
| GET | `/api/v2/llm_preflight` | UI+GUIDE | keep |
| GET | `/api/v2/sensors/catalog` | UI+GUIDE | keep |
| GET | `/api/v2/sensors/<sensor_name>/observations` | UI+GUIDE | keep |
| GET | `/` | UI(infra) | keep（SPA 配信） |
| GET | `/<path:filename>` | UI(infra) | keep（静的配信） |
| POST | `/api/v2/triage/narrate` | UI+TEST | keep（AP2） |
| POST | `/api/auth/register` | UI+GUIDE+OPS+TEST | keep |
| POST | `/api/auth/login` | UI+GUIDE+OPS+TEST | keep |
| POST | `/api/auth/refresh` | UI+TEST | keep |
| POST | `/api/auth/logout` | UI+TEST | keep |
| GET | `/api/auth/settings` | GUIDE+TEST | 要調査（UI 参照消失・v2/config と重複疑い） |
| PUT | `/api/auth/settings` | GUIDE+TEST | 要調査（UI 参照消失・v2/config と重複疑い） |
| GET | `/api/auth/users` | UI+GUIDE+TEST | keep |
| PUT | `/api/auth/users/<username>/role` | UI+GUIDE+TEST | keep |
| DELETE | `/api/auth/users/<username>` | UI+GUIDE+TEST | keep |
| POST | `/api/auth/users/<username>/reset-password` | UI+GUIDE+TEST | keep |
| PUT | `/api/auth/password` | UI+TEST | keep |

## 3. UNREFERENCED の考察（dead API 候補 8 件）

完全無参照（UI / GUIDE / OPS / TEST / docs のいずれからも参照なし）6 件:

| Endpoint | 考察 |
|---|---|
| `POST /api/persist_save` | 手動の即時状態保存トリガ。UI ボタンも文書も存在せず、自動 persist が稼働している現在は役目がない。curl 暗黙契約の形跡なし。**drop** |
| `GET /api/analytics/calibration_advisory` | v1 期の較正助言 API。v2 の自動較正パイプライン（threshold_history / calibration/health）が同機能を代替済。**drop** |
| `GET /api/analytics/confidence_distribution` | 下層の DB 関数 `intel_confidence_distribution()` は tests/test_intel_confidence_distribution.py が直接ユニットテストしているが、**endpoint 自体はどこからも呼ばれない**。v2 llm_conf 較正が内部で同じ分布を消費する。**drop**（DB 関数は残る） |
| `GET /api/analytics/scenario_phases` | 同上の v1 分析系。UI 接続されないまま v2 に置換された。**drop** |
| `POST /api/v2/attention/observations/recompute` | AP1 attention の手動再計算フック。管理者向け curl を想定した形跡はあるがどこにも文書化されていない。**GUIDE に載せて契約化するか、管理 CLI に落とすかの二択** |
| `GET /api/intel/sources` | インテルソース一覧。完全無参照。**drop** |

docs 言及のみ（設計文書に登場するが実行系から呼ばれない）2 件:

| Endpoint | 考察 |
|---|---|
| `GET /api/score_breakdown` | docs/design/v2-ui.md にのみ言及。v1 期に UI 接続を予定して実装されたが未接続のまま、NP6 導出開示の役目は `GET /api/v2/conclusions/<id>/audit_trace` が引き継いだ。**drop** |
| `GET /api/v2/admin/shadow_write_metrics` | v1→v2 移行の shadow-write 観測用。v2-migration.md の検証手順（curl）が唯一の利用実績で、Mode C 移行完了後は役目を終えた。**drop**（移行足場の残滓） |

**curl 運用の暗黙契約について**: 実行可能スクリプトで REST を呼ぶのは `scripts/smoke_tradecraft.sh` のみで、上記 8 件はどれも触っていない。したがって「実は運用で curl されている」可能性は、履歴上 v2-migration の一回性検証（shadow_write_metrics）を除き否定できる。8 件すべて v3 に持ち込まない判断で問題ない。

**関連する注意（UNREFERENCED ではないが同根の問題）**:
- `GET/PUT /api/auth/settings` — GUIDE と tests のみで**フロントエンドの参照が存在しない**。GUIDE には「ユーザー別設定の保存」と記載されているが、現行 UI は設定を localStorage と `/api/v2/config` 系で扱っている疑いが強い。v3 では per-user 設定の置き場を `/api/v2/config` に一本化し、auth/settings は廃止候補として要調査。
- `GET/PUT /api/v2/decisions/threshold` — GUIDE と tests のみ。per-user TRIAGE 閾値の契約だが UI 未接続。実装予定が落ちたのか、意図的な API-first なのかの確認が必要。
- GUIDE のみの 11 件（`daily_summary` / `cooccurrence` / `adaptive_zscore_status` / `climate/feed` / `history/threat_levels` / `deep_analytics` / `sensor_reliability` / `admin/scenarios/<sid>/changelog` / `noise_exclusion` GET+DELETE / `confirmed_threats` GET）— 公開契約として文書化した以上、v3 で落とすなら GUIDE の改訂が必須。逆に `noise_exclusion` の GET/DELETE と `confirmed_threats` の GET は「UI に一覧・削除導線が無い」という UI 側の欠落が原因であり、endpoint ではなく UI を直すのが筋。

## 4. SocketIO イベント分類（on 4 / emit 6）

すべて radar.js（S13 WebSocket セクション）が唯一の対向。tests/ からの参照なし、GUIDE には接続状態インジケーターの説明のみで個別イベントの契約記載なし。

| 方向 | イベント | 分類 | 参照 | v3 への示唆 |
|---|---|---|---|---|
| on | `connect` | UI | radar.js:9521 | keep |
| on | `disconnect` | UI | radar.js:9531 | keep |
| on | `subscribe_theater` | UI | radar.js:8203, 9526 | keep（**旧用語**。v3 で `subscribe_scenario` に改名） |
| on | `unsubscribe_theater` | UI | radar.js:8202 | 同上 |
| emit | `threat_update` | UI | radar.js:9549 | keep（room 宛） |
| emit | `ambush_alert` | UI | radar.js:9581 | keep（room 宛） |
| emit | `sequence_event` | UI | radar.js:9586 | keep（room 宛） |
| emit | `sensor_status` | UI | radar.js:9604 | keep（全体 broadcast） |
| emit | `notification_result` | UI | radar.js:9591 | keep（全体 broadcast） |
| emit | `intel_update` | UI | radar.js:9620 | keep（全体 broadcast。theater 引数は未使用 — v3 で引数削除） |

room 設計（`theater:{country}`）が旧用語のまま国単位になっている点は、v2 のシナリオ中心設計と不整合。v3 では room を `scenario:{scenario_id}` に揃えるのが自然。

## 5. v1/v2 重複対 — v3 統合候補

同種の情報を返す v1/v2 の対（または v1 内の重複）。v3 では右列に一本化するのが原則。

| v1（旧） | v2（新） | 備考 |
|---|---|---|
| `GET /api/cooccurrence` | `GET /api/v2/discovery/cooccurrence` | v1 は GUIDE のみ、v2 は TEST のみ。**どちらも実消費者がいない**ので統合先の UI 導線ごと再設計 |
| `GET /api/history/threat_levels` | `GET /api/v2/scenarios/<sid>/threat_history` | v1 は GUIDE のみ。v2 が UI で現役 |
| `GET /api/score_breakdown` | `GET /api/v2/conclusions/<id>/audit_trace` | NP6 導出開示の新旧。v1 は無参照 |
| `GET /api/analytics/calibration_advisory` | `GET /api/v2/calibration/health` + `threshold_history` | v1 は助言のみ、v2 は自動適用+監査。v1 無参照 |
| `GET /api/analytics/confidence_distribution` | v2 llm_conf 較正（calibration pipeline 内部） | v1 endpoint 無参照。分布計算自体は DB 関数として存続 |
| `GET /api/sensor_reliability` | `GET /api/admin/sensor_health` | 両方 v1 だが同じセンサー健全性。後者が UI 現役、前者は GUIDE のみ |
| `GET /api/daily_summary` | `GET /api/sitrep` | 両方 v1。要約系の重複。sitrep が UI 現役 |
| `GET /api/whatif/catalog` + `POST /api/whatif/simulate` | `POST /api/scenarios/<sid>/whatif_weights` | what-if 系が 2 系統。v3 でシナリオ単位に統合 |
| `GET /api/v2/config_audit` | `GET /api/v2/llm_routing/audit` | 同じ監査テーブルの汎用/限定ビュー（両方 llm_routing_v2.py 実装）。v3 で汎用側に一本化 |
| `GET /api/threat_data` | `GET /api/v2/scenarios/<sid>/conclusions` + `threat_history` ほか | 最大の対。v1 god-endpoint（core.py:507、UI メインポーリング）は v3 で conclusions/観測系に分解する前提（D1 §3a 参照） |

## 付録: scripts/ 分類（D1 補完 — .py 21 + .sh 6）

カテゴリ: CI-gate 8 / ops 4 / ETL 2 / bench-backtest 4 / remediation（一回きり）7 / codegen 2。
v3 判定: keep 15 / port 3 / retire 9。

| ファイル | 行数 | 用途（1 行） | カテゴリ | v3 判定 |
|---|---|---|---|---|
| check_ci.sh | 97 | ローカル CI ゲート束（codemap/rename/recall を順次実行） | CI-gate | keep |
| check_i18n_keys.py | 368 | i18n キー監査（未定義参照・未訳・日本語専用シェル、fatal） | CI-gate | keep |
| check_recall_baseline.py | 282 | recall 回帰ゲート（Design W、baseline スナップショット比較） | CI-gate | keep |
| check_recall_post_autotune.py | 289 | autotune 前後の短期 recall 低下検知（warn-only） | CI-gate | keep |
| check_alias_coverage.py | 102 | participant ↔ RSS alias 整合ゲート（ADR-V2-015、silent recall loss 防止） | CI-gate | keep |
| check_secrets.py | 290 | 秘密情報スキャナ（pure Python、staged+worktree） | CI-gate | keep |
| check_secrets.sh | 45 | gitleaks による staged スキャン（pre-commit） | CI-gate | keep |
| check_rename_coverage.py | 186 | theater→country rename 完遂ゲート（ADR-V2-006） | CI-gate | retire（v3 で旧用語が消えた時点で不要） |
| backup_radar_db.sh | 55 | docker volume 上の本番 DB バックアップ（cron 04:00） | ops | keep |
| smoke_tradecraft.sh | 130 | /api/analyst/* の権限マトリクス post-deploy スモーク | ops | keep（v3 API 形状に追従して port） |
| report_recall_metrics.py | 249 | analyst_feedback から混同行列・recall/precision レポート（AP3 補助） | ops | keep |
| audit_intel_sensors.py | 368 | intel センサー出力低下の α（実装起因）/β（世界が静か）診断 | ops | keep |
| run_ground_truth_etl.py | 495 | ACLED+GDELT 相関による conclusions 自動ラベル ETL（ADR-V2-005） | ETL | port（v3 では常駐ジョブ化を検討） |
| run_rss_etl.py | 481 | RSS 決定論抽出による ground-truth ラベル ETL（B1、API キー不要） | ETL | port（同上） |
| llm_model_bench.py | 443 | 実プロンプト replay による Ollama モデル比較ベンチ | bench-backtest | keep |
| calibrate_thresholds.py | 281 | trend/per_domain 閾値の実測分布分析（Phase 1.3） | bench-backtest | retire（v2 自動較正に吸収済） |
| backtest_auto_judge_layer1.py | 358 | auto_judge Layer 1（cross-evidence 必須）の効果バックテスト | bench-backtest | retire（判断済） |
| phase9_backtest_simulation.py | 265 | Phase 9 の TL 発火パターン遡及シミュレーション | bench-backtest | retire（判断済） |
| backfill_v2_ledger.py | 387 | v1 観測から conclusions ledger を遡及バックフィル（Phase 1.3） | remediation | retire（実施済） |
| check_mode_c_readiness.py | 151 | Mode C（v2 default-on）移行可否のワンショット判定 | remediation | retire（移行完了） |
| codemod_theater.py | 300 | theater→country/scenario の一括 codemod（manifest 駆動） | remediation | retire（rename 完了） |
| remediate_inverted_calibration.py | 164 | 2026-07-03 TL 反転 incident のワンショット修復 | remediation | retire（記録として git 履歴に残る） |
| remediate_cross_scenario_labels.py | 268 | 2026-08-02 cross-scenario 帰属 incident のワンショット修復 | remediation | retire（同上） |
| apply_calibration_remediation.sh | 44 | 07-03 修復のデプロイ後ドライバ | remediation | retire |
| apply_attribution_remediation.sh | 44 | 08-02 修復のデプロイ後ドライバ | remediation | retire |
| gen_codemap.py | 341 | Python 構造インデックス（docs/CODEMAPS/）生成 | codegen | keep |
| gen_frontend_codemap.py | 218 | JS/CSS 構造インデックス生成（radar.js 等の全文 Read 防止） | codegen | keep |

**非スクリプト残滓**: `scripts/_codemod_manifest.json`（164 KB、rename 追跡）、`_bench_*.json` 3 件（ベンチ結果アーティファクト）、`__pycache__/`。いずれも v3 リポジトリには持ち込まない（manifest は rename 完了とともに退役、bench 結果は docs/baselines か .gitignore へ）。
