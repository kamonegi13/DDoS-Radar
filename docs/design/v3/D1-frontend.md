# D1 — フロントエンド全体インベントリ（Phase D 診断ドラフト）

> 調査日: 2026-08-03 / branch: phase9/legacy-cleanup
> 対象: リポジトリ直下の全 JS / HTML / CSS（テスト含む）。radar.js は
> `docs/CODEMAPS/radar.js.md`（110 セクション / 312 top-level 関数）を起点に部分 Read で確認。
> 目的: v3 全面書き換え時の「引き継ぐ / 捨てる」判断材料。

---

## 1. ファイルインベントリ表

### 1.1 プロダクションファイル（16 本、計 30,440 行）

| ファイル | 行数 | 責務 | 他ファイルへの依存（参照するグローバル） | フラグ |
|---|---|---|---|---|
| `radar.js` | 14,833 | モノリス本体: auth/fetch ラッパ、地図、HUD、全パネル、SETTINGS、TRIAGE、WS/ポーリング、シナリオ管理 | `_t`/`STRINGS`(i18n.js)、`io`(socket.io CDN)、`L`(Leaflet CDN)、`MapDim`/`HudV2Overlay`/`TriageScore`/`TriageDisplayMode`/`SelfExplanation`/`WatchpaneAlarm`(pure modules) | **書き換え最有力**。IIFE なし＝全識別子がグローバル |
| `i18n.js` | 1,976 | `STRINGS` 単一言語(日本語)辞書 約 1,556 キー + `_t()` + `_applyStaticTranslations()` | なし（最初にロード） | 引き継ぎ候補（辞書は資産）。runtime 部コメントが「EN-only as of 2026-04-28」のまま stale |
| `tradecraft.js` | 1,016 | アナリスト・トレードクラフトパネル（ACH/前提/premortem 等 10 タブ） | `window._t`, `window._escHtml`, `window.createFloatingPanel`（全て guard 付き fallback あり） | 独自の `_fetchJSON`/`_esc`/`_fmtTs`/`_ago` を重複実装。機能自体は shelved 状態（MEMORY 参照） |
| `controls_panel.js` | 645 | CONTROLS Tools Hub（アコーディオン型ツール起動盤） | `window.toggle*` 14 種、`window._wizardOpen`、`window._t`、`window.showToast`（**未定義**） | radar.js の toggle 群への薄い結合層 |
| `autotune_wizard.js` | 443 | オートチューンウィザード（calibration_v2 提案の閲覧/適用、NP7 confirm ゲート） | `openModal`, `closeAllModals`, `_t`, `_escHtml`, `window.showToast`（**未定義**） | |
| `self_explanation.js` | 338 | AP2: 結論→平文ナラティブ生成（テンプレート、LLM なし） | なし（UMD pure module、`window.SelfExplanation`） | **そのまま引き継ぎ可**（Node テストあり） |
| `llm_features_hub.js` | 334 | LLM 機能ハブ UI + HUD チップ 60s ポーリング | `_escHtml`, `window._settingsOpen`（guard 付き） | `TIER_LABELS` 等に i18n バイパスの直書き日本語 |
| `map_dim.js` | 241 | focus 切替時の dim 状態機械（2 フェーズ lift/done/stale） | なし（UMD pure、`window.MapDim`） | **そのまま引き継ぎ可** |
| `triage_display_mode.js` | 218 | TRIAGE Lane 表示モード解決（dormant/pin-dock/critical-banner、ヒステリシス付き） | なし（UMD pure、`window.TriageDisplayMode`） | **そのまま引き継ぎ可** |
| `wp_alarm.js` | 203 | Watchpane アラーム純粋評価器（`<field> <op> <value>`） | なし（UMD pure、`window.WatchpaneAlarm`） | **そのまま引き継ぎ可** |
| `triage_score.js` | 164 | AP1: attention_score = novelty × confidence_delta × analyst_blindness | なし（UMD pure、`window.TriageScore`） | **そのまま引き継ぎ可** |
| `hud_v2_overlay.js` | 102 | HUD↔v2 結論の純粋リコンサイラ（immutable merge） | なし（UMD pure、`window.HudV2Overlay`） | **そのまま引き継ぎ可** |
| `login-init.js` | 95 | ログインゲート制御（radar.js より先に実行） | `window._radarMap`, `window._resetRenderSig`, `window.forceDataSync`（radar.js 側の後付けグローバルに依存） | エラーメッセージ直書き日本語（_t 不使用） |
| `index.html` | 3,246 | SPA シェル + 全パネル body + INTEL GUIDE Ch.1–14（`guide-ch-1`〜`guide-ch-14`） | onclick 直書き 136 箇所で radar.js グローバル関数を呼ぶ | `.panel-header-unified` 手書きチローム 21 箇所（契約違反、§5.2） |
| `radar.css` | 5,008 | 全スタイル（CSS 変数パレット、32 セクション） | — | codemap の対象セクションは L1315 以降のみ（前半 1,314 行は未マップ） |
| `tradecraft.css` | 281 | tradecraft パネル body スタイル | — | |

### 1.2 テスト（6 本、pure module のみカバー）

`tests/test_hud_v2_overlay.js`, `test_map_dim.js`, `test_self_explanation.js`,
`test_triage_display_mode.js`, `test_triage_score.js`, `test_wp_alarm.js`
— Node `require()` で UMD 側を読む。**radar.js 本体・パネル UI・fetch 層のテストはゼロ**。

### 1.3 スクリプトロード順（index.html）

```
L8   leaflet 1.9.4 (CDN, SRI)
L9   i18n.js
L10  socket.io 4.8.1 (CDN, SRI)
L32  login-init.js          ← body 先頭。radar.js のグローバルを setTimeout 越しに参照
L3234-3239 wp_alarm / hud_v2_overlay / triage_score / triage_display_mode / self_explanation / map_dim
L3240 radar.js
L3241-3244 tradecraft / autotune_wizard / llm_features_hub / controls_panel
```

---

## 2. radar.js 内部セクションマップ（新設計モジュール境界候補）

codemap の 110 セクションを 16 サブシステムに集約。行範囲は概算（間に他系の断片が挟まる）。

| # | サブシステム | 概算行範囲 | 責務 | 他サブシステムとの結合点 |
|---|---|---|---|---|
| S1 | Auth / fetch ラッパ | L6–182 | `window.fetch` 上書きで JWT 自動注入、401 リフレッシュ+リトライ、httpOnly refresh cookie、proactive refresh、login gate | 全 fetch 呼び出しが暗黙依存。`/api/threat_data` への `?focus=` 注入もここ（L114） |
| S2 | パネルクローム / ドック / ドラッグ | L451–783, L1326–1959 | `_createPanelToggle`, `_panelClose`, `createFloatingPanel`(L550), `setupDockablePanel`/`setupFloatingOnlyPanel`(L1435/1482), sidebar 並べ替え、layout 永続化 | 全パネルの土台。controls_panel.js の `toggle*` 経由でも呼ばれる |
| S3 | DDoS 時代レガシーパネル | L268–450, L1075–1325 | GreyNoise Investigator、Telegram SIGINT、CheckHost Survival HUD、Maskirovka、C2 coherence | Evidence Chain パネルに sub-metric を書き込む。**v3 で捨てる判断の筆頭候補** |
| S4 | モーダル / ツールチップ / TOOLS メニュー | L804–1022 | `openModal`/`closeModal`/`closeAllModals`、custom tooltip、TOOLS dropdown | autotune_wizard.js・llm_features_hub.js が `openModal` に依存 |
| S5 | Evidence Chain パネル | L1023–1074, L1139–1229 | シーケンスイベント連鎖表示 | `resolveChainTargetCountry`(L183 — Auth セクションに誤配置) |
| S6 | v2 envelope キャッシュ + NP7 バナー | L1960–2071 | `_hudFreshEnvelopeByType`、結論 Markdown export、NP7 常時表示 | HUD(S10)・TRIAGE(S9)・Drill-down(S11) が envelope キャッシュを共有 |
| S7 | Map Dim 配線 + Replay Mode (AP4) | L2072–2315 | MapDim 純粋機械への DOM コールバック注入、`/api/v2/replay` タイムトラベル | fetchDDoSData(S13) が `_mapDimNotify('threat_data')` を呼ぶ |
| S8 | HUD チップ群 (AP3) | L2316–2610, L5526–5931 | self_eval / LLM / MODEL / AUTO-CAL / CHRONIC / ANCHOR チップ + Human-Anchor labeling queue | 各自が個別 setInterval（30min/60s/5min/60s/60s/5min）で独立ポーリング |
| S9 | TRIAGE / Alert Lane (AP1) | L5932–7028 | `_al*` 状態管理(localStorage)、表示モード glue、actions popover、snooze/dismiss サーバ同期、LLM ナラティブ enrich | TriageScore/TriageDisplayMode(pure) を消費。HUD compact bar に描画 |
| S10 | HUD 更新本体 | L8940–9065, L10123–10890 | TL/domain/blockade チップ、TL duration/ETA/HOD-Z/INTEL チップ、waterfall、counter-signals、weather brief、SALUTE、radio silence、sparkline | `latestData`/`strat` 共有 mutable に全面依存 |
| S11 | Conclusion Drill-down モーダル (NP6) | L7029–7681 | audit_trace 全開示（式・閾値・rationale matrix・LLM プロンプト・feedback） | envelope キャッシュ(S6) + `/api/v2/conclusions/*` |
| S12 | Sensor Watchpane (Layer 3) | L7682–8281 | センサー監視・スパークライン・アラーム編集 | WatchpaneAlarm(pure)、`createFloatingPanel` 利用（数少ない契約準拠パネル） |
| S13 | データ同期: fetchDDoSData + WebSocket | L8151–8281, L9516–10122 | 15 分ポーリング + socket.io push、visibility でポーリング間隔切替、country detail / evidence panel | **アプリの心臓**。`latestData` を書き、renderTelemetry/HUD/チップ全系を起動 |
| S14 | 地図描画 | L8282–8939, L9066–9515, L10869–11142, L11543–11843 | Leaflet 上の signal/physical/military overlay、participant markers、threat terrain、coordination index、sensor markers、halo | `renderTelemetry`(L8631) がハブ。`_radarMap` グローバル |
| S15 | SETTINGS メガパネル | L2611–5525 | registry 駆動レンダラ、4 系統バッジ、domain renderer 20+、analyst_feedback/auto_judge ビューア、auto-cal status、legacy tab 移植 | **約 2,900 行 = radar.js の 20%**。`_settingsOpen` を llm_features_hub からも呼ぶ |
| S16 | 分析ツールパネル群 | L12093–12806, L12902–13135 | History Analysis(チャート canvas 直描画)、What-If、SPOF、Corr Heatmap | S2 のパネル土台。History は独自チャート実装 |
| S17 | LLM Intel パネル + Climate | L13135–13758 | インテルキュー閲覧/override、LLM 診断、strategic climate feed | `_escHtml`/`_escAttr` の定義がここ(L13744) — 他ファイルはこれに依存 |
| S18 | Scenario Bar / Detail / Manager | L13759–14833 | シナリオ切替バー、2 行レイアウト詳細、What-If overlay(sessionStorage)、Admin CRUD | `switchScenarioFocus` → S13 再フェッチ → S7 dim |
| S19 | Admin 系 | L11284–11542, L11844–12062 | Fleet Health、env_config(/api/v2/config shim)、User Management | `_adminHeaders`/`_umgrHeaders` の 2 重ヘッダヘルパ |

**v3 モジュール境界の示唆**: S1(auth-fetch) / S2(panel-kit) / S6+S11(conclusions) /
S8+S9(triage+chips) / S13(data-sync) / S14(map) / S15(settings) / S18(scenario) が自然な分割単位。
S3 は移植せず廃棄、S16/S17/S19 は個別パネルとして薄く再実装が妥当。

---

## 3. グローバル状態インベントリ

### 3.1 スコープ構造の重要事実

- **radar.js は IIFE で包まれていない**（L1 がインデント付きコメントで開始、ラッパなし）。
  top-level `function` 宣言 312 個は**すべて `window` プロパティ化**され、
  `let`/`const` はグローバル lexical binding として後続スクリプトから可視。
- 明示的 `window.*` 代入は radar.js だけで **137 箇所**（`toggle*` 26、`scMgr*` 12、
  `_settingsRender*` 20、`umgr*` 7、`_wp*` 7、`_llm*` 9 ほか）。
- index.html の onclick 直書き **136 箇所**がこのグローバル群を呼ぶ（HTML↔JS の暗黙契約）。

### 3.2 radar.js top-level mutable state（93 個の let/var、主要なもの）

| 変数 | 行 | 役割 |
|---|---|---|
| `latestData` | L153 | 最新 threat_data 全体（描画系全部が参照） |
| `currentVector` / `mapCenterMode` | L154–155 | L3/L7 ベクター切替 / 地図中心（DDoS 遺産） |
| `THEATERS` / `STRATEGIC_BLOCS_DATA` / `ADVERSARY_OPTIONS` | L1846, L169–171 | 旧 theater 語彙のシナリオ/国データ |
| `_wsSocket` / `_wsConnected` / `_wsSubscribedTheater` | L1944–1946 | WebSocket 状態（変数名に theater 残存） |
| `mutedSensors` / `_evCollapsedDomains` / `_chainCollapsedGroups` | L174, 203, 219 | localStorage ミラー |
| `_replayActive` / `_replayAtSec` | L2204–2205 | AP4 リプレイ状態 |
| `_ccLastFocus` / `_ccInflightFocus` / `_ccAbort` | L1997–1999 | envelope フェッチ競合制御 |
| `_settingsRegistryCache` / `_settingsCurrentDomain` | L3031, 2899 | SETTINGS キャッシュ |
| `_gnLog` / `_tgFilter` / `_tgLastData` | L352, 448–449 | レガシーパネル状態 |

### 3.3 ファイル間共有グローバル（結合点 14）

| グローバル | 定義元 | 依存側 |
|---|---|---|
| `_t` / `STRINGS` | i18n.js | radar.js, tradecraft.js, controls_panel.js, autotune_wizard.js（guard 付き） |
| `_escHtml` / `_escAttr` | radar.js L13744–13745 | tradecraft.js, autotune_wizard.js, llm_features_hub.js |
| `createFloatingPanel` | radar.js L550 | tradecraft.js, radar.js 内部(anchor L5917, watchpane L8112) |
| `openModal` / `closeAllModals` | radar.js L904/919 | autotune_wizard.js |
| `_settingsOpen` | radar.js L2901 | llm_features_hub.js |
| `toggle*` 系 14 関数 | radar.js | controls_panel.js（Tools Hub の起動テーブル） |
| `_wizardOpen` | autotune_wizard.js | controls_panel.js |
| `_radarMap` / `_resetRenderSig` / `forceDataSync` | radar.js | login-init.js |
| `MapDim` / `HudV2Overlay` / `TriageScore` / `TriageDisplayMode` / `SelfExplanation` / `WatchpaneAlarm` | 各 pure module | radar.js |
| `showToast` | **どこにも定義なし** | controls_panel.js L562, autotune_wizard.js L370（→ §5.1） |

### 3.4 localStorage キー全列挙（18 + sessionStorage 2）

| キー | 書き込み元 | 用途 |
|---|---|---|
| `radar_access_token` / `radar_username` / `radar_role` / `radar_token_lifetime` | radar.js S1, login-init.js | 認証 |
| `radar_focused_scenario` | radar.js | focus 復元 |
| `radar_dbg_focus` | radar.js | デバッグ用 focus 上書き |
| `noroshi_triage_state` (`_AL_STORAGE_KEY` L5946) | radar.js S9 | TRIAGE ack/viewed/prior |
| `ddos_radar_triage_state` (`PRE_RENAME_KEY` L5952) | — | **移行 shim**: L5955 で読み → 新キーへ移し → L5958 で removeItem。一回限りの片道移行として現存。v3 では削除可（移行済みユーザーのみ想定なら shim ごと捨てる） |
| `triage_pinned` / `triage_always_visible` | radar.js | TRIAGE 表示設定 |
| `watchpane.v1.state` (`_WP_STORAGE_KEY` L7689) | radar.js S12 | watch 行 + アラーム |
| `radar_coord_link_mode` (L10899) | radar.js | coordination link 表示 |
| `gnLookupLog` / `mutedSensors` / `evCollapsedDomains` / `ctiIntelAlerts` / `chainCollapsedGroups` | radar.js | パネル個別状態 |
| `cp_section_open` | controls_panel.js | アコーディオン開閉 |
| sessionStorage `sc_overlay:<scenarioId>` | radar.js L14307 | What-If overlay |
| sessionStorage tradecraft `SESSION_KEY` | tradecraft.js L20 | タブ単位セッション ID |

---

## 4. バックエンド契約（D6 素材）

### 4.1 REST エンドポイント（fetch 呼び出し全列挙、約 78 点）

**auth (S1 + login-init + User Mgmt)**:
`/api/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/password`, `/auth/register`,
`/auth/users`, `/auth/users/<u>`, `/auth/users/<u>/role`, `/auth/users/<u>/reset-password`

**v1 コア**:
`/api/threat_data?focus=` (メインポーリング L8182), `/api/data_status`, `/api/app_config`,
`/api/sensor_config`, `/api/confirmed_threats`, `/api/sequence_chain?country=`,
`/api/noise_exclusion`, `/api/alert_timeline`, `/api/climate`, `/api/sitrep`,
`/api/salute_report?lang=ja`, `/api/weather_brief?lang=ja`, `/api/spof_analysis`,
`/api/whatif/catalog`, `/api/whatif/simulate`, `/api/ip_check?ip=`, `/api/telegram_log/clear`,
`/api/llm_models?host=`

**v1 history**: `/api/history/timeseries`, `/history/sequence_events`, `/history/hod_baseline`,
`/history/countries`, `/history/alerts`

**v1 intel**: `/api/intel/`, `/intel/stats`, `/intel/llm_call_stats`

**v1 analyst (tradecraft.js)**: `/api/analyst/{ach,assumptions,decisions,disconf,dissent,premortem,hidden_signals,coverage}`,
`/api/scenarios`, `/api/scenarios/compare?ids=`

**v1 admin**: `/api/admin/scenarios` (+ `/<sid>/state|enabled|reset`, `?purge=true`),
`/api/admin/sensor_health`

**v2 (30+)**:
`/api/v2/scenarios/<sid>/conclusions`(+`.md`), `/v2/scenarios/<sid>/threat_history`,
`/v2/conclusions/<id>/{audit_trace,feedback}`, `/v2/replay/<sid>?at=`,
`/v2/self_eval`, `/v2/observability/chronic_inconclusive`,
`/v2/triage/narrate`, `/v2/decisions/triage/{state,snooze,dismiss,visibility}`, `/v2/decisions/history`,
`/v2/human_anchor/queue`, `/v2/analyst_feedback`, `/v2/auto_judge/decisions`,
`/v2/config`, `/v2/config/{values,registry}`, `/v2/config_audit`,
`/v2/llm_features`(+`/<key>/set|clear`, `/kill_switch`, `/audit`), `/v2/llm_routing`(+`/overrides`),
`/v2/llm_preflight`, `/v2/sensors/catalog`, `/v2/sensors/<name>/observations`,
`/v2/calibration/{health,tier_governor}`, `/v2/proposals/{scenario_improver,sensor_disable}`,
`/v2/drift_signals`, `/v2/discovery/clusters`, `/v2/attention`(+`/thresholds/`)

### 4.2 SocketIO 購読イベント（radar.js S13、9 点）

`connect`, `connect_error`, `disconnect`,
`threat_update`, `intel_update`, `sensor_status`, `sequence_event`, `ambush_alert`, `notification_result`

### 4.3 ポーリング契約（WS フォールバック + チップ独立系）

- `fetchDDoSData`: 15 分（hidden 時は延長、visibility 切替 L9631–9642）
- チップ独立ポーリング 6 本: self_eval 30min / LLM chip 60s / MODEL 5min / AUTO-CAL 60s / CHRONIC 60s / ANCHOR 5min（L5502–5523）
- llm_features_hub.js: 60s

---

## 5. 欠陥候補（D2 の種）

### 5.1 `window.showToast` が全コードベースで未定義（HIGH）
- 参照: `controls_panel.js:562`, `autotune_wizard.js:370`（typeof guard 付き）
- `rg -in "toast" radar.js index.html radar.css` → 0 件。トースト通知系は常に fallback 側へ落ち、
  controls_panel は `alert()`、autotune は無通知になる経路がある。設計上存在するはずの共有トースト基盤が消失している。

### 5.2 パネルクローム契約違反が多数残存（panel-chrome.md 違反）
- `createFloatingPanel` 準拠は 3 パネルのみ: tradecraft (tradecraft.js:984)、human-anchor (radar.js:5917)、watchpane (radar.js:8112)
- 手書き `.panel-header-unified` が **index.html に 21 箇所**残存
- 旧経路 `setupDockablePanel`/`setupFloatingOnlyPanel` 直配線 12 パネル（radar.js:1715–1729:
  target/dashboard/chain/weather-brief/gn/tg-sigint/history/whatif/spof/corr-heatmap/climate/llm-intel）
- v3 では factory 一本化（もしくは宣言的パネル定義）が必須

### 5.3 重複実装（DRY 違反、フォーマッタ/エスケープ/カラー）
- 経過時間フォーマット 4 実装: `_formatAge`(radar.js:10224, ts 引数) / `_fmtAge`(11144, sec 引数) /
  `_fleetFmtAge`(11286, ほぼ `_fmtAge` + i18n) / tradecraft.js `_ago`(72)
- タイムスタンプ整形 3 実装: `_fmtTs`(radar.js:13729) / `_ccFmtTimestamp`(7039) / tradecraft.js `_fmtTs`(63)
- HTML エスケープ 3 実装: `esc`(radar.js:2) → `_escHtml`(13744, esc の別名) / tradecraft.js `_esc`(38)
- 状態カラー 4 実装: `_tlColor`(12127) / `_statusColor`(11152) / `_fleetHealthColor`(11293) / `_coordColor`(10967)
- fetch+JSON ヘルパも tradecraft.js `_fetchJSON`(45) が radar.js と別系

### 5.4 DDoS 時代レガシーが現役コードパスに混在（v3 で捨てる/改名する判断が必要）
- `fetchDDoSData`(radar.js:8151) — アプリの心臓のポーリング関数が旧名のまま
- `buildTheaterUI`(1867) / `THEATERS`(1846) / `_wsSubscribedTheater`(1946) — 廃止用語 theater が radar.js に 60 箇所
- L3/L7 vector 切替 UI (`switchVector`, index.html:366–368) — DDoS レイヤ概念の残骸
- GreyNoise / Telegram SIGINT / CheckHost Survival HUD / Maskirovka（S3、約 900 行）
- `hud-blockade` チップ（index.html:165–168, radar.js:8961）

### 5.5 dead code / legacy shim（確認済みの未参照）
- `switchMapCenter`(radar.js:867) — 全ファイルで呼び出し 0 件
- `toggleContent`(radar.js:882) — 呼び出し 0 件
- `_llmRoutingOpenLegacy`(radar.js:2720)、`_llmFeaturesOpenLegacy`(llm_features_hub.js:42)、
  `_settingsRenderSystemLegacy`(radar.js:4773) — SETTINGS 統合後の escape hatch
- `tradecraft.js:993–998` の createFloatingPanel フォールバック — 「older radar.js」向けで現行では不達
- `ddos_radar_triage_state` 移行 shim(radar.js:5952–5958) — 移行完了後は削除可

### 5.6 i18n バイパス（STRINGS 監査網の外にある UI 文字列）
- `llm_features_hub.js:21–26` `TIER_LABELS` 直書き日本語、同 L57–90 の confirm/prompt 文言
- `controls_panel.js:563–565` トースト/alert 文言直書き
- `login-init.js` エラーメッセージ直書き（i18n.js ロード後なのに `_t` 不使用）
- ※ canvas/toast の直書きは CLAUDE.md 上許容だが、上記は `_t()` 到達可能な DOM/dialog 文字列

### 5.7 状態管理の一貫性欠如
- `localStorage.getItem('noroshi_triage_state')` の生リテラル読み(radar.js:8695)が
  `_alLoadState`/`_AL_STORAGE_KEY`(5946) を迂回 — キー変更時に追従漏れするコピー
- HUD チップ 6 本が個別 setInterval + 個別 fetch（§4.3）— 集約フェッチ層がなく、v2 API への
  リクエストがチップ数に比例
- `resolveChainTargetCountry` 等が「Auth」セクション内(L183–267)に誤配置 — セクションコメントと
  実体の乖離が既に始まっており、モノリス内の論理境界は信頼できない

### 5.8 テストカバレッジの構造的偏り
- テストがあるのは抽出済み pure module 6 本のみ（radar.js 14,833 行は 0%）
- 「テスト可能な形に抽出する」パターン自体は成功しており（§1.1 フラグ列）、
  v3 は全モジュールをこの形（UMD or ESM + Node テスト）で始めるべき

---

## 付記: 引き継ぎ/廃棄の初期判定サマリ

| 区分 | 対象 |
|---|---|
| **そのまま引き継ぐ** | pure modules 6 本（triage_score / triage_display_mode / self_explanation / map_dim / wp_alarm / hud_v2_overlay）+ テスト、i18n STRINGS 辞書(キー整理の上) |
| **設計を引き継ぎ実装を書き直す** | S1 auth-fetch ラッパ、S2 パネル factory(契約は panel-chrome.md 通り)、S6/S11 conclusions 描画、S13 データ同期、S18 シナリオ管理 |
| **捨てる** | S3 レガシーパネル群、theater/DDoS 語彙、L3/L7 vector UI、blockade チップ、legacy shim 群(§5.5)、手書きチローム 21 箇所 |
| **要再設計** | S15 SETTINGS(2,900 行 → registry 駆動を活かして分割)、HUD チップのポーリング集約、showToast 基盤の新設 |
