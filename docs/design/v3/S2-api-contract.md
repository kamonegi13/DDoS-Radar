# S2 — API 契約 挙動仕様

**スコープ**: フロントとバックエンドを分離する境界の契約 — REST endpoint（D6 の UI 分類 132 + OPS 生存分 + GUIDE 公開分）の
**リクエスト（パラメータ・認可要件）/ レスポンス payload の構造 / エラー形**、および SocketIO プロトコル。採点の数式は
S1-scoring-core、結論の導出意味論は S1-conclusions、センサーの観測意味論は S1-sensors-* が担当。本書は「その値がどのキーで、
どの型で、どの認可の下に、どの HTTP 形で出てくるか」だけを語る。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。条項 ID は
`S2-API-nnn`（連番・欠番なし）。**v3 への提案は `S2-PROP-nnn` の別系列**（§15）で、Phase P の入力であって現行契約の記述では
ない。紙幅の都合により **根拠 / 検証 / 分類は各条項末尾の 1 行に併記**する。

**深度 3 段**: **[完全]** = `/api/threat_data`(§3) / v2 conclusions envelope(§4) / triage state・self_eval・replay(§5) /
config registry(§6) — フロントを greenfield で書ける全フィールド。**[一覧]** = その他 UI endpoint(§7) — レスポンスキーを
1 行ずつ。**[参照]** = OPS・drop 候補(§8)。形状は **routes 実装と D5 CONTRACT 級 17 ファイルの両方**から確認し、乖離は §12
に記録した。GUIDE（index.html Ch.12）は外部公開契約だが実装より古く、一次ソースには採らない。

## 1. 用語

CLAUDE.md の定義に従う（country / scenario / participant / focused / background / C-lite）。本書固有:
**envelope** = v2 API が返す統一 payload（結論本体 + 導出メタ + NP7 disclaimer）。**conclusion_type** =
`threat_level`/`trend`/`per_domain`/`anomaly`/`attack_mode` の 5 種。**feature gate** = `V2_API_ENABLED` 等に
よる endpoint 単位の有効化（OFF は 503）。**role** = `viewer`/`analyst`/`admin`（JWT クレームでなく DB 参照
で毎回解決）。**TL** = 1=CRITICAL … 5=NORMAL（DEFCON 式）。API 上も生値で、比較は `severity = 6 − TL` 経由 **MUST**。

## 2. 共通契約（全 endpoint 横断） — **[完全]**
### S2-API-001: 全 `/api/*` は JWT 必須。公開は 6 endpoint のみ
**挙動**: `before_request` が `/api/` 配下の全パスに有効な JWT を要求 **MUST**。公開例外は `auth.login` /
`auth.refresh` / SPA index / 静的配信 / `api.app_config` / Flask static の**6 つのみ**。失敗は
`{"error":"Authentication required"}` 401、想定外例外は `{"error":"Internal server error"}` 500。
**根拠** radar/__init__.py:195-221 ／ **検証** test_auth.py（app_config 無認証 200・settings 無認証 401）／ **分類** CORE
### S2-API-002: ロールは 3 値、順序定数を持たず包含判定のみ。強制機構は 3 系統に分裂
**挙動**: `admin`/`analyst`/`viewer` の 3 値 **MUST**。実効包含は `admin ⊃ analyst ⊃ viewer` だが、
**数値順序やランク定数は存在せず**各ゲートが所属集合の判定を個別に書く。ロールは access token の `role`
クレームにも載るが、**どのゲートもクレームを読まず毎回 DB を引く MUST**（権限変更がトークン再発行なしで
即時反映される）。強制機構は (a) `require_role(*roles)` デコレータ（403 `Insufficient permissions`）、
(b) admin ヘルパ（403 `Admin access required`）、(c) analyst ヘルパ（403 `Analyst access required`）の 3 系統。
**(b)(c) はデコレータでなく手動 return パターンで、呼び出し側の return 忘れがゲートを無言で無効化する**。
(b)(c) は**あらゆる例外を 401 に丸める**ため DB 障害が認証失敗に化ける。
**根拠** auth.py:379-392,416,480、routes/__init__.py:53-87 ／ **検証** test_analyst_permissions.py（18 件）／
**分類** CORE（3 値と DB 解決）+ **DEFECT-PRESERVE**（3 系統分裂 = §12-DP3）
### S2-API-003: 呼び出し元 ID は JWT identity（username 文字列）
**挙動**: 監査列（`changed_by`/`created_by`/`analyst_id`/`by`/`actor`）は**すべて JWT identity = username
文字列 MUST**。数値 analyst_id は存在しない。body に `analyst_id` や `observed_at` を渡しても**無視 MUST**
（サーバ側 identity / 時刻で上書き）。decisions 台帳の actor は `"<role>:<identity>"`。
**根拠** auth.py:480、conclusions_v2.py:324-325、decisions.py:49-57 ／ **検証** test_conclusions_feedback.py ／ **分類** CORE
### S2-API-004: エラー body が 4 系統・成功 body が 3 系統に分裂している
**挙動**: (1) `{"error":"<英文>"}` 約 123 箇所（de-facto 標準。**機械可読なコードもフィールド名も持たない**）／(2) v2 NP7 envelope
`{api_version, final_judgment_disclaimer, error, **extra}`（v2 の一部のみ。**同じ `/api/v2/` でも `POST /api/v2/config` の 4xx は
(1) の裸形**）／(3) `{"ok":false, "error":…}` 7 箇所／(4) **HTTP 200 の body に `error` を埋める** — `config_audit` 例外時、
`llm_models` の上流失敗、`llm_preflight` の `snapshot_error`、`auto_judge`/`analyst_feedback`/`attention` の NP3 縮退経路。
成功形も `{"ok":true}` / `{"status":"ok"}` / 裸のドメインオブジェクトの 3 系統。`{"success": false}` は HTTP body としては
**一度も使われていない**。
**根拠** conclusions/api.py:46-56、llm_routing_v2.py:208、intel.py:398 ／ **検証** 未検証（横断的な形状テストが無い）／
**分類** **DEFECT-PRESERVE**（§12-DP4）
### S2-API-005: v2 面は単一フラグで全停止し、503 は 404 より先に返る
**挙動**: `V2_API_ENABLED` が false のとき v2 endpoint は**全て 503 MUST**。判定順序は
**503 → 401 → 403 → 400/404 → 200**。したがってフラグ OFF 時は存在しない ID への要求も 503 となり
リソースの存在有無が隠蔽される。**ただし self_eval / replay / human_anchor の 3 本のみ 403 が先**（§12-DP8）。
**根拠** conclusions_v2.py:56-66,487-492,559-564、chronic_inconclusive.py:49-54 ／
**検証** test_conclusions_api.py::test_v2_returns_503_when_flag_off；test_conclusions_feedback.py::test_post_503_when_v2_disabled ／
**分類** CORE（順序）。フラグ自体が恒常 true の移行足場である点は D2 C-03
### S2-API-006: v2 応答 envelope が 4 形に分裂し、NP7 が欠ける形がある
**挙動**: (A) 結論 envelope `{api_version, scenario_id, observed_at, final_judgment_disclaimer, conclusions[]}` ／
(B) `data` ラップ `{api_version, observed_at, final_judgment_disclaimer, data, …filters}`（calibration /
llm_features / attention / chronic_inconclusive）／ (C) 平坦 dict + NP7（self_eval / replay / auto_judge /
analyst_feedback / human_anchor）／ (D) **裸 dict（NP7 無し）**（llm_routing* / llm_preflight / decisions / config*）。
**根拠** conclusions/api.py:23-43、calibration_v2.py:67、decisions.py:243-259 ／
**検証** test_conclusions_api.py（A）/ test_config_audit_endpoint.py（D）／ **分類** **DEFECT-PRESERVE**（§12-DP5）
### S2-API-007: クエリ整数は clamp、パース不能は既定値に落とす（400 にしない）
**挙動**: `hours`/`limit` 等は `max(min_val, min(v, max_val))` に clamp **MUST**、非数値は**既定値へ
フォールバック MUST**。応答は **clamp 後の実効値をエコーする MUST**（要求値ではない）。例外は
`/api/v2/decisions/history` の `since_ts`/`until_ts`/`limit` のみで、ここだけ 400 を返す。
**根拠** routes/__init__.py:35-40、conclusions_v2.py:97-104、decisions.py:365-366 ／
**検証** test_config_audit_endpoint.py / test_threat_history_scoped.py ／ **分類** CORE
### S2-API-008: 国パラメータは `?country=` のみ。`?theater=` は撤去済
**挙動**: 国を受けるクエリ名は `country` **MUST**。旧 `?theater=` は 14 日のテレメトリで呼び出し 0 を確認後に
削除済で、**受理してはならない MUST**。ただし DB 列・内部引数・**WS プロトコル**・intel 行の生データには
`theater` が残り、`/api/intel` は表示層でのみ `country` に改名している。
**根拠** routes/__init__.py:43-50、intel.py:32-44 ／ **検証** test_history_routes.py ／ **分類** CORE。内部残存は D2 C-01
### S2-API-009: レート制限は 2 層。ログインのみ 429 を返す
**挙動**: (1) ログイン専用の IP 別インメモリガード — 300 秒窓で**失敗 5 回**超過は
`{"error":"Too many login attempts. Try again later."}` 429 **MUST**、成功でリセット。IP は
`X-Forwarded-For` を `TRUST_PROXY_XFF` 設定時のみ信頼。(2) 全体 Flask-Limiter（120/min + 2000/h、auth 5/min）。
**上流障害時に例外を握り潰すため、レート制限機構の故障が可用性を落とさない**（NP3）。
**根拠** auth.py:26-65,451-459、__init__.py:162-186 ／ **検証** test_auth.py（5 回失敗 → 429）。(2) は pytest で無効化 ／ **分類** CORE
### S2-API-010: フロントエンドクライアントの契約
**挙動**: クライアントは以下 **MUST**: `/api/` 宛全リクエストに `Authorization: Bearer` を自動付与／**401 を受けたら refresh を
1 回試み、成功時に元リクエストを 1 回だけ再送**（login と refresh 自身は除外）／access token は localStorage（既定 1h）、
refresh token は **httpOnly + SameSite=Strict + Path=/api/auth/refresh の Cookie MUST（body に載せてはならない）**／CSRF は
`X-CSRF-TOKEN` ヘッダ／メインポーリング 15 分で**WS 接続中も止めない**（GET が採点を駆動するため）／HUD チップ 6 系統が
独立ポーリング（30min / 60s / 5min / 60s / 60s / 5min）。
**根拠** radar.js:106-144,1948,9631-9642、auth.py:223-252 ／ **検証** test_auth.py（Cookie 属性・body に refresh_token 非在）／
**分類** CORE。ポーリング必須は §12-DP2

## 3. `GET /api/threat_data` — **[完全]**

v1 の god-endpoint。フロントの地図・HUD・全パネルの初期描画がこの 1 応答に依存する。
**本節 S2-API-011〜017 はすべて検証が「未検証」**（core.py に専用テストが無い — §13 GAP-04）。
### S2-API-011: 認可は 3 ロール全許可、focus 不能時のみ 503。パラメータは 3 query + 1 header
**挙動**: `viewer`/`analyst`/`admin` のいずれでも 200 **MUST**。JWT 欠落・失効は 401、ロール不一致は
`{"error":"Insufficient permissions"}` 403。`?focus` が未知または非 scorable なら既定シナリオ → 任意の
scorable シナリオの順に**暗黙フォールバック MUST**（エラーにしない）。scorable が皆無のときのみ
`{"error":"No scorable scenario available"}` 503。受理するパラメータ:

| 名前 | 位置 | 型 / 既定 | 意味 |
|---|---|---|---|
| `focus` | query | scenario_id / `DEFAULT_FOCUSED_SCENARIO` | 採点対象の focused シナリオ。**副作用として analyst focus を登録する** |
| `force` | query | `off`\|`snapshot`\|`sensors` / `off` | `snapshot`（後方互換 `true`/`1`）= 採点キャッシュ TTL のバイパス。`sensors` = さらに許可リストセンサーを背景 greenlet で再取得。**`viewer` は常に `off` へ降格 MUST**（外部 API クォータ保護） |
| `muted` | query | CSV of sensor name / `""` | アナリストが手動でミュートしたセンサー名 |
| `X-Scenario-Overlay` | header | JSON `{"CC": weight}` / 無し | Layer 3 セッション weight 上書き（永続しない）。`analyst`/`admin` のみ適用。**viewer とパース失敗は無言で無視** |

旧 `?core=` / `?correlates=` / `?adversaries=` / `?targets=` は**受理しない MUST**。
**根拠** core.py:507-524,535-551,599-621,648-652、auth.py:379-392 ／ **分類** CORE。overlay の無言無視は ACCIDENTAL（§11-A2）
### S2-API-012: トップレベル 13 キー
**挙動**: 200 応答は以下を持つ **MUST**（★は S2-API-016 の条件付き）。`timestamp`(str, 応答組立時刻 ISO-8601
ローカル) ／ `sensor_health`(obj, sensor_name → `{status, domain, last_fetch_ts, cb_state}`) ／
`strategic_alert`(obj, S2-API-013) ／ `targets`(arr, S2-API-015) ／ `threat_history`(arr, `[[ts, threat_level]]`。
**全シナリオ横断・非スコープの legacy**) ／ `climate_gauge`(obj, `{level, score, levels[], baseline_maturity,
baseline_maturity_pct}`。例外時 `{}`) ／ `focused_scenario`(str, フォールバック適用後の実効 id) ／
`scenarios`(obj, S2-API-016) ／ `scenario_history_starts_at`(float|null, TL 観測台帳の最古 ts) ／
`participants`(obj, country → `{lat, lng, name, role, weight, active}`) ／ `global_threat`(obj|null,
`{score, domains{}, sources[], global_signal_weight}`。採点失敗時 null) ／ ★`scoring_error`(bool) ／
★`scoring_error_reason`(str) ／ ★`scoring_error_disclaimer`(str)。
**根拠** core.py:3135-3155,3173 ／ **分類** CORE
### S2-API-013: `strategic_alert` — 初回採点前は空オブジェクト
**挙動**: 初回の採点成功までは `{}` **MUST**（キー欠落ではなく空オブジェクト）。以後のキー: `core_country` / `effective_cores[]` /
`primary_ec` / `secondary_ecs[]`（採点対象国の解決結果）／**`threat_level`(int|null — 採点失敗時 null MUST。TL5 を捏造しない)** /
`threat_score`(float, legacy rationale ベース) / `threat_breakdown`(S2-API-014a)／`correlations_idf`・`_l3`・`_l7`（`"A-B"` →
IDF 重み付き ASN 重複）／`adversary_strikes[{actor,target,spike,pct}]` / `vector_shifts[]` / `degraded_countries[]` /
`degraded_countries_raw[]` / `coordinated_countries[]`／`domains{cyber|physical|info: {score, weight, weighted, status}}`
（status = CRITICAL≥6 / ELEVATED≥3 / WATCH≥1 / NORMAL）／`convergence_score` / `convergence_level`／
**`rationale_matrix[]`**（採点入力の全観測 = NP6 ドリルダウンの一次データ、S2-API-014b）／`noise_filters_applied[]`（抑制理由の
**整形済み文字列** — D2 F-03: 文言変更で除外規則が無言で壊れる）／`system_note`(str)／`country_intel{country: {weather,
airspace, gdelt, bgp_routing, ixp_count, ixp_names[], ioda_status, ioda_detail, ioda_source, is_bgp_degraded, ihr_status,
ihr_disco, ripe_atlas|null, tor_metrics|null}}`／`map_overlays{ioda_outages[], airspace_anomaly[], weather_events[],
gdelt_events[], critical_nodes[], firms_anomalies[], chokepoints[], cable_routes[], isr_hotspots[], ais_dark_gaps[先頭10],
ais_stationary[先頭10]}`／`analytics`(S2-API-014c)／`active_countries[]`（core ∪ correlates ∪ adversaries のソート済み和集合）。
**根拠** core.py:2857-2946、state.py:10 ／ **分類** CORE
### S2-API-014: `threat_breakdown` / `rationale_matrix[]` / `analytics` の下位構造
**挙動**: **(a) `threat_breakdown`**: `core_spike_val` / `core_spike_2x|4x|6x` / `high_correlation` / `core_shifted` /
`major_adversary` / `core_degraded` / `is_coordinated` / `tl1_hard` / `total_score` / `convergence_bonus` / `sequence_bonus` /
`temporal_bonus` / `triangulation_bonus` / `is_triangulated` / `score_with_bonus` / `threat_raw` / `threat_held` /
`is_c2_sync` / `is_maskirovka` / `is_silent_divergence` / `silent_divergence_conf` / `cooccurrence_boost` /
**`theater_baseline` + `country_baseline`（同一オブジェクトの二重書き）**。
**(b) `rationale_matrix[]`** の各要素は**常時** `sensor` / `domain` / `status` / `value` / `score` / `fired_reason` /
`suppressed` / `suppress_reason` / `confidence` / `direction` / `direction_confidence`、**truthy のときのみ** `signal_source` /
`temporal_context` / `spatial_context` / `target_context` / `raw_value` / `observed_at` / `evidence_url` / `llm_reasoning` /
`sensor_chain`。条件付き出力のため**クライアントは全オプショナルキーの欠落を許容する MUST**。
**(c) `analytics`**（約 40 サブオブジェクト）: `velocity` / `acceleration` / `is_ambush` / `ambush_z_score` / `sequence_bonus` /
`sequence_status` / `sequence_chain[]` / `narrative` / `isr` / `ais` / `blockade_index` / `temporal_coherence` / `maskirovka` /
`check_host` / `telegram_mirror` / `greynoise` / `origin_entropy|null` / `space_weather` / `bgp_events` / `ioda` /
`adaptive_zscore` / `feint` / `escalation` / `confidence{domain_confidences, min_confidence}` / `tl_proximity` /
`eta_to_next_tl_sec|null` / `hod_z|null` / `hod_n` / `context_alignment` / `direction_summary` / **`theater_baseline` +
`country_baseline`** / `triangulation` / `silent_divergence` / `ihr` / `ripe_atlas` / `tor_metrics` / `notam` /
**`travel_advisory{core, all, country_all}`** / **`ooni{core, status, adversary, country_adversary}`** / `seismic` /
**`mil_support_air{core, all, country_all}`** / `gps_jamming` / `ct_log` / `cooccurrence_boost`。
**根拠** core.py:2609-2843、models.py:55-83 ／ **分類** CORE。`theater`/`all` 系の二重書き 5 対は §12-DP1
### S2-API-015: `targets[]` は participant ごとの地図行
**挙動**: `lat` / `lng` / `info`(国名) / `code` / `role` / `participant_weight` / `global_share` /
`global_share_l3` / `global_share_l7` / `is_bgp_outage` / `is_bgp_effective` / `is_vector_shift` /
`shift_actors[]` / `trend_history[]` / `trend_history_l3[]` / `trend_history_l7[]` / `sources[]` / `velocity` /
`is_ambush` / `ambush_z` **MUST**。座標未登録の participant は fallback 座標 + `name = code` で**必ず 1 行
出す MUST**（地図から落とさない）。`sources[]` の要素 = `{lat, lng, name, code, weight, l3_weight, l7_weight,
spike_factor, l3_spike, l7_spike, is_l7_shift, is_new_actor, is_state_asn, state_asns[], confidence}`。
**根拠** core.py:3068-3099 ／ **分類** CORE
### S2-API-016: `scenarios[sid]` は focused / background で形が変わる
**挙動**: **共通**: `id` / `is_focused` / `scoring_mode`(`full`\|`lite`) / `score` / `tl` /
`domains{cyber,physical,info}` / `convergence_bonus` / `active_countries[]` / `contributions[]` / `name_en` /
`name_ja` / `is_admin_override` / `preset_enabled` / `preset_metadata` / `participants{cc:{weight, base_weight,
role}}` / `data_freshness_sec`。`contributions[]` の要素 = `{signal{signal_source, sensor, observed_at, domain,
countries[], raw_score, value_display, country_weights?, evidence_url?, llm_reasoning?}, contributing_country,
llm_country_weight, participant_weight, participant_role, final_contribution, formula_trace, suppress_reason?}`
（**NP6 の最小開示単位**）。
**background のみ**: `indicators{active_countries, domain_signal_counts, blind_domains[],
coverage_completeness, llm_intel_24h, signal_volume_24h, signal_distinct_countries_24h, signal_last_at,
signal_top_countries[]}` / `lite_bias_warning` / `score_delta_1h|6h|24h` / `velocity` / `velocity_trend`。
**`tl` は `SHOW_BACKGROUND_TL=true` のときのみ含む MUST**（既定は除去）。
**focused のみ**: `tl_raw` / `tl_held` / `velocity` / `acceleration` / `velocity_bonus` / `acceleration_bonus` /
`velocity_trend` / `velocity_pts_per_hour` / `score_delta_1h|6h|24h` / `indicators.signal_*` /
`eta_to_next_tl|null` / `patterns.silent_divergence` / `patterns.context_alignment` / `tl_duration_sec` /
`intel_active_24h` / `intel_new_1h` / `domain_split{domain:{adversary, target}}`。
**根拠** scoring.py:988-1047、core.py:2225-2404,3109-3116 ／ **分類** CORE
### S2-API-017: 採点失敗は 200 + 明示フラグ。この GET は 20 種の副作用を持つ
**挙動**: focused シナリオの採点が例外で失敗した場合、**200 を返し** `scoring_error=true`、
`scoring_error_reason="focused_scoring_failure"`、`scoring_error_disclaimer`（平文）を付し、`strategic_alert.threat_level` を
**null** にする **MUST**。TL 履歴への追記は行わない **MUST**。これは NP5+8（結論不可の明示）の HTTP 表現であり、
**TL5（NORMAL）を捏造してはならない**。ただし次のキャッシュヒットティックでフラグは再掲されず消える。
本 endpoint は読み取り専用では**ない**。`SCORE_REFRESH_SEC`（既定 60s）超過・`force != off`・focus 変更のいずれかで再計算分岐に
入り、以下を実行する: analyst focus 登録（毎回）／背景センサー再取得 greenlet／Cloudflare Radar への HTTP fetch／spike 時系列の
DB 追記／**エスカレーションシーケンスイベント登録（約 20 箇所）**／**LLM インテルキューの破壊的ドレイン**／TL・TREND 結論の
台帳永続化／TL 観測行追記／寄与ログ行追記／What-If 用シグナルスナップショット書込／TL 履歴追記／センサーカバレッジ更新／
日次サマリ upsert／センサー共起統計更新／グローバルキャッシュ差し替え／センサー観測行記録／アラートタイムライン追記／
Climate Engine 更新／**WS emit 3 種**（`threat_update`、条件付き `ambush_alert`、条件付き `sequence_event`）／TL 遷移時の外部通知。
**根拠** core.py:529,667,648-652,718-742,811-815,1207-1813,2060,2222,2407,2444,2472-2476,2513-2527,2540-2544,2550,2587,2604,
2853-3007,3010-3056,3156-3162 ／ **分類** **DEFECT-PRESERVE**（D2 A-01。v3 では S2-PROP-001 で読み取り専用化）

## 4. v2 結論 API 群 — **[完全]**

導出意味論（4 不変条件・結論不可の 4 値・disclaimer 二重掲示）は S1-conclusions が規範。本節は HTTP 表現のみ。
### S2-API-018: 結論 envelope は固定 5 キー、結論オブジェクトは 14 フィールド
**挙動**: 成功 envelope = `{api_version:"2.0", scenario_id, observed_at, final_judgment_disclaimer, conclusions[]}` **MUST**
（S1-CONC-005）。`observed_at` は同梱結論の観測時刻の最大値、空なら現在時刻。`conclusions[]` の各要素は以下 14 フィールドを
**キーとして必ず持つ MUST**: `id`(str UUID4。未導出の合成 payload でのみ null)／`scenario_id`(str)／`conclusion_type`(str, 5 種)／
**`state`(str|null — 常に文字列。TL も `"3"` のような十進文字列。null ⇔ `conclusion_unavailable_reason` が非 null という双方向の
不変条件)**／`confidence`(float, [0.0,1.0] 閉区間。範囲外は構築時に拒否。結論不可時 0.0)／`observed_at`(float)／
`formula_ref`(str `path#func@semver`。未導出時のみ null)／`threshold_ref`(obj, `{}` 可)／`source_urls`(arr, `[]` 可)／
`llm_prompt_sha256`(str64|null)／`calibration_status`(obj `{source, status(OK|INSUFFICIENT_DATA|DEGRADED), recall, precision,
tp, fp, tn, fn, sample_n, window_days, last_label_at}`。`threat_level` と `anomaly` のみ埋め、他 3 型は `{}`)／
`conclusion_unavailable_reason`(str|null。`insufficient_data`\|`calibration_pending`\|`sensor_degraded`\|`upstream_failure`)／
**`final_judgment_disclaimer`(str。空文字は構築時に拒否 MUST — NP7 / 制約⑥)**／`metadata`(obj, S2-API-020)。
**根拠** conclusions/base.py:48-114、api.py:20-99 ／ **検証** test_conclusions.py（4 不変条件 + frozen）；
test_conclusions_api.py::test_bundle_endpoint_returns_latest_of_each_type ／ **分類** CORE
### S2-API-019: 結論 API の HTTP 面
**挙動**:

| Method / Path | 認可 | パラメータ | 主要ステータス |
|---|---|---|---|
| GET `/api/v2/scenarios/<sid>/conclusions` | JWT のみ | — | 200（0〜5 件）。行ゼロは **404 でなく 200 の結論不可 payload MUST** |
| GET `/api/v2/scenarios/<sid>/conclusions/<type>` | JWT のみ | — | 200 ／ **400 未知 type（有効値一覧を `detail` に MUST）** |
| GET `/api/v2/conclusions/<cid>` | JWT のみ | — | 200 ／ 404 `{error, conclusion_id}` |
| GET `/api/v2/conclusions/<cid>/audit_trace` | JWT のみ | — | 200（envelope でない平坦 dict）／ 404 |
| GET `/api/v2/scenarios/<sid>/conclusions.md` | JWT のみ | `include_audit`（真値は `1`/`true`/`yes` のみ） | 200 `text/markdown` + `Content-Disposition: attachment` ／ **503 のときだけ JSON** |
| POST `/api/v2/conclusions/<cid>/feedback` | **JWT のみ（viewer も書ける）** | `label`(必須) / `observed_outcome_url` / `notes`(2000 字切詰) | 201 `{api_version, disclaimer, feedback_id, summary}` ／ 400 ／ 404 |
| GET `/api/v2/conclusions/<cid>/feedback` | JWT のみ | `limit`(50, 1..1000) | 200 `{…, conclusion_id, summary, items[]}`。**新しい順 MUST** |
| GET `/api/v2/scenarios/<sid>/threat_history` | JWT のみ | `hours`(24, 1..168) / `limit`(1000, 1..5000) | 200 `{api_version, scenario_id, hours, history[[ts,level]], disclaimer}` |
| GET `/api/v2/observability/chronic_inconclusive` | JWT + **analyst** | — | 200 `{api_version, observed_at, disclaimer, data}` ／ 403 |

`label` の有効値は `TRUE_POSITIVE`/`FALSE_POSITIVE`/`TRUE_NEGATIVE`/`FALSE_NEGATIVE` の 4 値のみ。`summary` =
`{conclusion_id, total, distinct_analysts, label_counts{4 値すべてゼロ埋め}}`。`items[]` = `{id, label,
analyst_id, observed_at, observed_outcome_url, notes}`。**未知シナリオ・空シナリオはすべて 200**。
`chronic_inconclusive` の `data` = `{computed_at, threshold_days, summary{total, chronic_count,
transient_count, duty_chronic_count}, chronic[], transient[], duty{window_days, threshold, states[]}, error?}`
（NP3: 縮退時も 200）。
**根拠** conclusions_v2.py:77-425、chronic_inconclusive.py:35-55 ／ **検証** test_conclusions_api.py(19) /
test_conclusions_feedback.py(14) / test_conclusions_markdown.py(21) / test_threat_history_scoped.py /
test_inconclusive_continuity.py ／ **分類** CORE。feedback のロールゲート欠如は §12-DP6
### S2-API-020: 型別 metadata と audit_trace の開示範囲
**挙動**: 型別 `metadata` — `threat_level`: `score` / `active_countries[]` / `convergence_bonus` /
`scoring_mode` / `active_domain_count` / `physical_score` / `rationale_matrix` / `falsification` /
`lite_tl_note`(lite 時)。`trend`: `windows{24h,7d,30d}` / `sample_counts{}`。`per_domain`: `domain_scores{}` /
`domain_states{}` / `domain_source_counts{}`。`anomaly`: `importance_score` / `raw_score` / `recency_decay` /
`scenario_relevance` / `novelty_factor` / `novelty_similar_count` / `elapsed_hours` / `domain` /
`contributing_country` / `signal_source` / `value_display` / `sensor` / `novelty_source`（**`state` は
signal_source の統制語彙**）。`attack_mode`: `ranked_modes[{mode, confidence, rule}]` / `domain_scores{}` /
`active_countries_n` / `is_tentative`。結論不可分岐は `is_transient:true` + `reason_detail` を追加し、型別
診断値は保持 **MUST**。
`audit_trace` = `{api_version, conclusion_id, scenario_id, conclusion_type, observed_at,
final_judgment_disclaimer, formula_ref, threshold_ref, source_urls, calibration_status, metadata, llm_prompt}`
**MUST**。`llm_prompt` は sha256 未設定なら null、行があれば `{sha256, model, temperature, prompt_text,
first_seen_at, last_seen_at, use_count}`、**retention で消えていれば `{sha256, missing:true}` MUST**
（沈黙の null にしない）。
**根拠** conclusions/{threat_level,trend,per_domain,anomaly,attack_mode}.py、conclusions_v2.py:185-224,920-937 ／
**検証** test_conclusions_api.py::test_audit_trace_* 4 件 ／ **分類** CORE（NP6 の到達点）。結論本体を含まない点は §12-DP7

## 5. AP1 / AP3 / AP4 自動化透明性 API — **[完全]**
### S2-API-021: TRIAGE state は 3 キー。snooze/dismiss は**全体共有**、visibility のみ per-user
**挙動**: `GET /api/v2/decisions/triage/state`（JWT + analyst）は以下 3 キーのみ **MUST**: `snooze`(obj|null —
未失効の snooze があるときのみ `{active:true, expires_at, minutes:int|null, decision_id}`。**`active:false`
形は返さない MUST**) ／ `visibility`(str `"default"`\|`"always"`。**per-user**、**null にしない MUST**) ／
`dismiss`(obj|null — `{active:true, expires_at, fingerprint:str|null}`。**`decision_id` を持たず snooze と非対称**)。
**snooze と dismiss は `target_kind="global"` であり、1 人の操作が全アナリストの lane を黙らせる**（現行契約）。
台帳の active 判定は `superseded_by`/`revoked_at` が null であることのみで、**失効判定は route 側が行う**。
**根拠** decisions.py:205-259、radar/decisions.py:165-199 ／ **検証** test_decisions.py ／
**分類** CORE。global スコープは ACCIDENTAL（§11-A4）
### S2-API-022: TRIAGE 書込 4 本と閾値 2 本
**挙動**（すべて JWT + analyst + v2 フラグ）:

| Method / Path | body | 200 | 特記 |
|---|---|---|---|
| POST `/…/triage/snooze` | `minutes`(既定 30、非数値も 30、**1..1440 clamp**) / `reason` | `{decision_id, minutes, expires_at}` | 先行 snooze を supersede |
| DELETE `/…/triage/snooze` | — | `{released:true, decision_id}` | **未 active でも 200** `{released:false, reason:"no active snooze"}` |
| POST `/…/triage/visibility` | `mode` ∈ `default`\|`always` / `reason` | `{decision_id, mode}` | 不正 mode 400。**失効しない**（次回設定まで永続） |
| POST `/…/triage/dismiss` | `fingerprint`(既定 `""`) / `reason` | `{decision_id, fingerprint, expires_at}` | TTL 固定 24h。fingerprint 無検証 |
| PUT `/…/decisions/threshold` | `dormant_enter`(0.40) / `critical_enter`(0.85) / `reason` | `{decision_id, dormant_enter, critical_enter}` | 非数値 400。両者 [0,1] clamp。**大小逆転はサーバで補正しない** |
| GET `/…/decisions/threshold` | — | override 有 `{dormant_enter, critical_enter, set_at, is_default:false}` ／ 無 `{dormant_enter:0.40, critical_enter:0.85, is_default:true}`（**`set_at` はキーごと欠落**） | per-user |

**根拠** decisions.py:81-335 ／ **検証** test_decisions.py ／ **分類** CORE
### S2-API-023: 判断履歴（AP4）の読み取りと revoke
**挙動**: `GET /api/v2/decisions/history`（JWT + analyst）はクエリ `decision_type` / `target_kind` /
`target_id` / `actor` / `action` / `since_ts` / `until_ts` / `limit`（既定 200、台帳側で 1..1000 に再 clamp）を
AND 結合し `{decisions[], count}` を返す **MUST**。空文字は未指定と等価。**`since_ts`/`until_ts`/`limit` の
非数値のみ 400**（S2-API-007 の例外）。行 = `{id, decision_type, target_kind, target_id, action, actor,
reason, parameters(JSON 展開済), decided_at, expires_at, superseded_by, revoked_at, revoked_by}`、
`decided_at DESC`。`GET /api/v2/decisions/<id>` は同じ行 1 件 / 404。`POST /api/v2/decisions/<id>/revoke` は
**対象行の `decision_type` で認可が変わる MUST** — `tl_recal_*` / `dual_weight_*` は admin、それ以外は
analyst。200 `{revoked:true, decision_id}`、二重 revoke は 409。revoke は `revoked_at`/`revoked_by` を書き
`superseded_by` は触らない。
**根拠** decisions.py:340-448、radar/decisions.py:334-415 ／ **検証** test_decisions.py ／ **分類** CORE
### S2-API-024: `GET /api/v2/self_eval` は平坦 payload。全ブロックが個別に NP3 縮退する
**挙動**: JWT + **analyst**（**403 が 503 より先**）。クエリ無し。`data` ラップを持たない平坦 dict **MUST**。**各ブロックは個別に
try/except され、データ障害で 5xx にしない MUST**（失敗ブロックは `<block>_error` キーを立て、値を null / `{}` にする。★は条件付き）。
キー: `api_version`("2.0") / `generated_at`(float) / `final_judgment_disclaimer`(str) ／ `recall`(float|null — Σtp/(Σtp+Σfn)、
窓は較正窓の既定 30 日) + `recall_meta{window_days, labels_total, labels_human, labels_auto, source:"ground_truth"}` +
★`recall_error` ／ `null_zone_days`(int|null — threat_level が全て結論不可だった連続末尾日数、上限 30) + ★`null_zone_error` ／
`drift`(float|null — 較正十分なシナリオの平均 miss-rate。HUD 帯 good≤0.05 / warn≤0.10) + `drift_meta{method:
"mean_miss_rate_ground_truth", scenarios_n, max_miss_rate, worst_scenario, window_days, source, reason?, error?}` ／
`bg_observer{enabled, cycles_24h, empty_rate_24h, matches_per_cycle_avg, matches_total_24h, alias_gap[], last_cycle_at, error?}` ／
`silent_failures{uptime_sec, by_category{}, np1_categories[4], np1_failure_count_lifetime, error?}`（**lifetime 累計。窓化は
クライアントの責務**）／ `attention_collection_errors`(int|null) + ★`attention_error` ／ `by_model{model: {n, ok_rate,
parse_failed, timeout, http_error, exception, auto_confirmed_rate, avg_duration_ms, avg_confidence, use_cases[]}}` ／
`by_use_case{uc: {n, ok_rate, auto_confirmed_rate, avg_confidence, primary_model}}` ／ `shadow_diff{uc: {n, same_family_rate,
v2_model}}` ／ `shadow_dual_diff{uc: {n_paired, schema_compliance{}, agreement_rate, v10_model, verdict_reproducibility,
p99_latency_ms{}, avg_confidence{}}}` + ★`routing_error`（上 4 ブロックが `{}` になる）／ `embedding_dedupe{bucket: {detected,
would_dedup, applied, precision_proxy, avg_score}}` + ★`embedding_error` ／ `phase8_go_status{by_use_case{uc:
{schema_compliance{value, ok, threshold:0.99}, agreement_rate{…0.60}, verdict_reproducibility{…1.00}, n_paired, use_case_go}},
overall_go:bool|null, have_data:bool}` ／ `tl_distribution_skew{tl5_pct, tl5_min_pct, window_days, n_observations,
min_observations, have_enough_data, calibration_skew_alert, distribution_pct{TL1..TL5}, method}`（フラグ OFF 時
`{enabled:false, calibration_skew_alert:false}`、例外時 `{…, error}`）。
**根拠** conclusions_v2.py:544-851 ／ **検証** test_self_eval.py（drift + NP3 縮退 / by_model / recall 窓と auto-human 分割）／
**分類** CORE（AP3）
### S2-API-025: `GET /api/v2/replay/<sid>?at=<ts>` は「その時刻の最新行」を型ごとに 1 件返す
**挙動**: JWT + **analyst**（403 が 503 より先）。`at` は unix 秒。**`observed_at <= at` の行を型ごとに 1 件
（最新）選ぶ MUST**。省略時は現在時刻。非数値は 400 `{api_version, disclaimer, error:"invalid 'at'
parameter", detail:…}`。**未知 `scenario_id` は検証せず 200 + `conclusions: []` MUST**。200 =
`{api_version:"2.0", scenario_id, replay_at:float, conclusions[≤5], final_judgment_disclaimer}`。
`conclusions[i]` は**生の台帳行**（`id, scenario_id, conclusion_type, state, confidence, observed_at,
formula_ref, threshold_ref, source_urls, llm_prompt_sha256, calibration_status,
conclusion_unavailable_reason, metadata`）で JSON 列は再展開される。**行に per-conclusion の
`final_judgment_disclaimer` は無く**（列が存在しない）、**存在しない型は配列から欠落する**（live 側のような
結論不可スタブを挿入しない）。Replay の状態バッジ（amber 表示・時刻ラベル・`data-replay-on`）は
**サーバでなくクライアントが生成する**。
**根拠** conclusions_v2.py:468-541、radar.js:2231-2312 ／ **検証** **未検証**（§13 GAP-01）／
**分類** CORE（AP4）。envelope が docstring と異なる点は §12-DP9
### S2-API-026: AP1 attention の 6 endpoint
**挙動**（JWT + v2 フラグ + analyst。`observations/recompute` のみ **admin**）。すべて `data` ラップ形。
`GET /api/v2/attention` → `data{rules[], tool_status{}, suggestions[]}`。`rules[]` = `{rule_id, tool_id, severity, value,
enter_threshold, exit_threshold, message, can_snooze, description}`（**snooze 中の rule は一覧から除外するがヒステリシス追跡は
継続 MUST**）、`tool_status` = `{tool_id: {severity, text(≤60 字)}}`、`suggestions[]` = `{rule_id, current_threshold, p50, p95,
sample_count, suggested, message}`（`sample_count ≥ 30` かつ相対差 ≥ 30% のときのみ）。**例外時は 3 つとも空で 200**（NP3）。
`POST /api/v2/attention/<rule_id>/snooze` → body `hours`（既定 24、`0 < h ≤ 168`、サーバ側下限 0.5h）、200 `data{rule_id,
snooze_until, by:"analyst:<identity>"}`。**`can_snooze=false`（severity=critical）は 403 MUST**（NP1: 最重要警告は黙らせられ
ない）。**保存は rule 単位のグローバル**。`GET/PUT/DELETE /api/v2/attention/thresholds[/<rule_id>]` → **per-user**（数値
users.id で解決）。GET は `data` が**リスト** `[{rule_id, threshold, set_at}]` + `count`、PUT は `{threshold:float}`
（非数値 400、identity 未解決 403）、DELETE は行が無くても `cleared:true`。
**根拠** attention_v2.py:57-293、radar/attention.py:416-501 ／ **検証** test_attention.py（routes 部）／ **分類** CORE
### S2-API-027: AP2 narrative は二段ゲート、個別失敗も 200 の行として返す
**挙動**: `POST /api/v2/triage/narrate`（JWT + v2 フラグ + analyst + **Feature Hub key `triage_narrative` が ON か SHADOW**）。
OFF は 503 `{api_version, error:"triage_narrative_disabled", feature_state:"off"}` で**LLM を呼ばない MUST**。body
`{items:[{id(必須), kindLabel?, scenario_id?, confidence?, age_minutes?, rank?, why?[]}]}`。`items` 欠落・空・非リストは 400。
**バッチは 8 件で切詰 MUST**。入力は `kindLabel[:80]` / `scenario_id[:60]` / `why[:5]` 各 `[:120]` に境界化 **MUST**
（プロンプト注入対策）。200 `data{feature_state, results[], n_items, n_ok}`。`results[]` は成功 `{id, narrative(**≤240 字・
制御文字と改行を除去 MUST**), ok:true, prompt_version}` ／ 失敗 `{id, narrative:"", ok:false, error}`。**個別失敗を HTTP エラーに
しない MUST**。
**根拠** triage_narrative.py:40-180 ／ **検証** test_routes_triage_narrative.py(10) ／ **分類** CORE
### S2-API-028: AP3/AP4 の読み取り 4 本
**挙動**:

| Path | 認可 | パラメータ | レスポンス |
|---|---|---|---|
| GET `/api/v2/auto_judge/decisions` | analyst | `hours`(720,1..8760) / `limit`(200,1..2000) / `action`∈confirm\|reject\|pending / `applied` / `overridden`（三値 bool） | `{api_version, observed_at, disclaimer, summary{window_hours, total, by_action{3 値常在}, applied_total, overridden_total, override_rate(**分母 0 は null**)}, items[]}`。`items[]` = `{id, ts, item_id, action_proposed, confidence, reason, layer1_corroborators, layer1_satisfied, applied, applied_at, analyst_overrode, analyst_override_action, analyst_override_at, analyst_id}`。**`summary` は `hours` のみを見てフィルタを無視する** |
| GET `/api/v2/analyst_feedback` | analyst | `hours`(720) / `limit`(200) / `analyst_kind`∈human\|auto / `label` | `{…, summary{window_hours, total, human_total, auto_total, distinct_analysts, by_label{4 値常在}, by_conclusion_type{}, recall, precision}, items[{id, conclusion_id, conclusion_type, scenario_id, label, analyst_id, observed_at, notes, observed_outcome_url}]}`。human/auto は `analyst_id` の `auto:` 接頭辞で判別 |
| GET `/api/v2/human_anchor/queue` | analyst（**403 が 503 より先**） | `window_days`(7,1..30) / `limit`(5,1..20) | `{api_version, generated_at, disclaimer, candidates[], pending, human_labels_window, target_per_week}`。`candidates[]` = `{conclusion_id, scenario_id, conclusion_type, state, observed_at, kind∈auto_fn_review\|peak_severity\|calm_anchor, rationale(**決定論テンプレート・LLM 不使用 MUST**), suggested_labels[], question, tool_stance, tool_stance_label, answer_options[{label, maps_to, is_escalation, tone}], search_url}`。**読み取り専用**（書込は結論 feedback） |
| GET `/api/intel/pending/triage` | **viewer 含む 3 ロール、v2 フラグ無し** | `limit`(50,1..200) / `min_pr`(0.0,0..1) | `{items[], total_pending, shown, ts}`。**NP7 envelope も api_version も無い**。`items[]` = intel 行 + `priority` / `gate_reason` / `source_credibility` / `ecosystem` / `corroboration_count` / `corroborating_sources[]` / `corroborating_ecosystems[]` / `top_scenario` / `matched_scenarios[]` / `age_hours` / `age_decay` / `max_scenario_coupling` / `country`。`priority DESC` |

上 3 本は**例外時も 200 で `error` 文字列（≤200 字）を付す MUST**（NP3）。
**根拠** {auto_judge_v2,analyst_feedback_v2,human_anchor_v2}.py、intel.py:108-166 ／ **検証** test_auto_judge_v2.py(9) /
test_analyst_feedback_v2.py(13) / test_human_anchor.py。`/api/intel/pending/triage` は **HTTP レベル未検証**（GAP-02）／ **分類** CORE

## 6. 設定 registry — **[完全]**

**本節 S2-API-029〜031 はすべて検証が「未検証」**（§13 GAP-06）。
### S2-API-029: `GET /api/v2/config/registry` は 98 キーの宣言的メタデータを返す
**挙動**: 認可 **admin**。クエリ `group` ∈ `OPERATE`\|`TUNE`\|`LLM_HEALTH`\|`INFRASTRUCTURE`\|`ACCESS`
（未知は 400）、`include_secrets`（**実装既定 true**、docstring は false と矛盾）。200 = `{registry[],
groups[5], generated_at}`。各エントリは `key`(str, 環境変数名) / `domain`(str, 24 種の名前空間で SETTINGS
左ナビの単位) / `group`(str) / `type`(`str`\|`int`\|`float`\|`bool`\|`list[str]`\|`json`) / `default`(any。
**secret のときは強制的に null**) / `description` / `what` / `why` / `when`(3 行の説明) / `secret`(bool, 12 キー) /
`immutable`(bool, env 専用で DB 書込 422、15 キー) / `restart_required`(bool, 25 キー) / `bootstrap`(bool,
DB override 不可、6 キー) / `apply_timing`(str, 5 種の平文ラベル) / `impact_level`(`low`\|`med`\|`high`。
**high は POST に reason 必須**、8 キー) / `impact_warning` / `unit` / `min_value` / `max_value` / `enum` を
持つ **MUST**。並び順は `(group, domain, key)`。`validator` は非直列化のため HTTP に出さない。
**根拠** admin.py:69-120、config_layered.py:55-83,111、config.py:711 ／ **分類** CORE。
`enum`/`validator` の利用キーが 0 件である点は ACCIDENTAL（§11-A5）
### S2-API-030: `GET /api/v2/config/values` は 3 層解決の結果と provenance を返す
**挙動**: 認可 **admin**、クエリ無し。200 = `{values[], generated_at}`。非 secret は `{key, value, source, restart_pending}`、
secret は `{key, value:null, source:"secret", restart_pending:false, indicator:{set:bool, last4:str|null}}` — **実値もマスク
文字列も返してはならない MUST**（マスク文字列を POST に往復させた 2026-05-04 の設定破損インシデントの再発防止）。解決順は
**(1) DB override（`immutable`/`bootstrap` はスキップ）→ (2) env → (3) コード既定値 MUST**。各層は型強制を通し、失敗した層は
次へ落ちる。`source` は `db`/`env`/`default`/`secret`。`restart_pending` は `restart_required` かつ DB override が env 実効値と
異なるときのみ true。実行時は 30 秒 TTL + 世代カウンタのキャッシュが挟まるが、**書込操作は世代を進めて即時反映する MUST**。
**根拠** admin.py:123-164、config_layered.py:185-315 ／ **分類** CORE
### S2-API-031: `POST` / `DELETE /api/v2/config` の検証ラダーと監査面
**挙動**: 認可 **admin**。POST body `{key, value, reason?}`、DELETE body `{key, reason?}`。順序とコードは以下 **MUST**:
`key`/`value` 欠落 → **400**；registry 利用不可 → **503**；未登録キー → **404**；`secret` → **403**；`immutable`/`bootstrap` →
**422**；**マスク文字列**（`^\*{3,}[A-Za-z0-9]{0,4}$`）→ **422 `{error, key, hint}`**（唯一の 3 フィールドエラー）；型不一致・
enum 外・min/max 逸脱・validator 失敗・high impact で reason 欠落・DB 失敗 → **422 `{"error": <理由文>}`**。成功は POST
`{ok:true, source, restart_pending}` / DELETE `{ok:true}`。**override が無いキーの DELETE は 404 でなく 200 の no-op MUST**。
`value == ""` を非文字列キーに送ると**エラーではなく clear へ委譲され 200** を返す。監査面は 2 系統で payload が交わらない
（両方 JWT + v2 フラグ + **analyst**）: `GET /api/v2/config_audit` — `hours`(720,1..8760) / `limit`(200,1..2000) / `domain`
（完全一致）、200 = `{domains:[{domain, count}], rows:[{id, ts, domain, config_key, old_value, new_value, changed_by, reason,
request_id}]}`（**値は JSON 文字列**、8000 字切詰）。`GET /api/v2/llm_routing/audit` — `domain` 無し、200 =
`{history:[{id, use_case, slot, old, new, changed_at, changed_by, reason}]}` で**別テーブル**。
**根拠** admin.py:167-268、config_layered.py:321-425、llm_routing_v2.py:168-225、database.py:4317-4374 ／
**検証** test_config_audit_endpoint.py(7: 401/空/集計/行フィールド/domain/hours/limit)。config 4 本は未検証 ／
**分類** CORE。成功 POST が監査行を 2 行書く点は §12-DP10

## 7. その他の UI 分類 endpoint — **[一覧]**

各行のレスポンスキー列がその endpoint の**全トップレベルキー**。特記なき認可は「JWT のみ」、エラーは
S2-API-004 の (1) 形。
### S2-API-032: 履歴 API（7 本）と小規模 CRUD / GUIDE のみの面（11 本）
**挙動**:

| Path | 認可 | params | レスポンスキー |
|---|---|---|---|
| GET `/api/history/countries` | JWT | — | `countries[]`（TS 記録国 ∪ 全 scorable シナリオの participant） |
| GET `/api/history/timeseries` | JWT | `country` / `hours`(168, max 720) / `series`(CSV of combined\|l3\|l7) | `country`, `hours`, `series{scored:[{ts,value}], combined[], l3[], l7[]}` |
| GET `/api/history/hod_baseline` | JWT | `country` / `type`∈hod_baseline\|checkhost_hod\|bgp_hod（他 400） | `country`, `type`, `total_points`, `hod_stats[24]{hour,mean,std,min,max,n}`, `raw[直近200]` |
| GET `/api/history/alerts` | JWT | `limit`(100, max 500) / `since` | `total`, `returned`, `alerts[]`（アラート全文スナップショット） |
| GET `/api/history/sequence_events` | JWT | `country`? / `hours`(24, max 168) | country 指定時 `country, hours, events[{ts,type,meta}]` ／ 非指定時 `hours, countries{}` |
| GET `/api/history/threat_levels` | JWT | — | `count`, `history[{ts,level}]`（**全シナリオ横断。v2 threat_history が後継**） |
| GET `/api/history/export` | **admin** | `country` | JSON 添付。`country`, `exported_at`, `timeseries_scored`, `timeseries_combined/l3/l7`, `hod_baseline`, `checkhost_hod`, `sequence_events`, `threat_history` |
| GET,POST `/api/sensor_config` | GET **全ロール** / POST admin | — | `{sensors[], domain_weights}`。**トグルはインメモリのみで永続しない** |
| POST `/api/telegram_log/clear` | admin | — | `{ok}` |
| GET,POST `/api/noise_exclusion`、DELETE `/api/noise_exclusion/<id>` | admin | — | ルール CRUD。**GET と DELETE に UI 導線が無い** |
| GET,POST `/api/confirmed_threats` | admin | — | 確認済み脅威 CRUD。**GET に UI 導線が無い** |
| GET `/api/daily_summary` ／ `/api/cooccurrence` ／ `/api/deep_analytics` ／ `/api/adaptive_zscore_status` ／ `/api/sensor_reliability` ／ `/api/climate/feed` | JWT | `climate/feed` は `axis` / `limit`(1..200) | **6 本とも GUIDE のみで UI 導線を持たない** |

**根拠** history.py:27-215、admin.py:271-458、analytics.py、climate.py:17 ／ **検証** test_history_routes.py(3)。他は未検証 ／ **分類** CORE
### S2-API-033: インテル API（10 本）
**挙動**: `require_role` 系。読み取りは 3 ロール、状態変更は analyst 以上、`llm_models` のみ admin。

| Path | params | レスポンスキー |
|---|---|---|
| GET `/api/intel` | `source_type` / `status` / `country` / `limit`(100, max 200) | `items[]`, `stats{}`, `ts`。行 = `{id, source_type, source_id, country(theater から改名), ts, status, confidence, raw_text, raw_url, headline, llm_fields, score_delta, domain, confirmed_by, confirmed_at, override_at, created_at, countries, country_weights, source_credibility}`。**終端状態の古い行は表示窓（既定 8h）で除外** |
| GET `/api/intel/stats` | — | `auto_confirmed`, `auto_confirmed_total`, `manual_confirmed`, `pending`, `confirmed`, `rejected`, `overridden`, `review_needed`, `total`, `llm_enabled`, `auto_threshold`, `confidence_min`, `item_ttl_hours`, `max_items_per_source_theater`, `llm_online`, `llm_model`, `llm_mode`, `llm_calls_1h`, `llm_last_call_age_min`, `triage_pulse{}` |
| GET `/api/intel/llm_call_stats` | `hours`(24, max 168) / `recent=1` | `window_hours`, `total_calls`, `ok_calls`, `per_caller[]`, `sensor_filter_breakdown[{caller,reason,count}]`, `lifecycle{}`, `recent[]`(条件付き) |
| POST `/api/intel/<id>/{confirm,reject,revert,override}` | reject のみ body `classification` | `{ok, item_id, status}`（reject は `classification` も）。**analyst+** |
| GET `/api/intel/sources` | — | `sources[{source_id, source_type, credibility_weight, confirmed_count, false_positive_count, last_updated}]`。**UNREFERENCED（drop 候補）** |
| GET `/api/llm_models` | `host`（SSRF ガード付き） | `{ok, models[], error?}`。**admin**。**上流失敗も HTTP 200 + `ok:false`** |

**根拠** intel.py:32-405、database.py:4546-5845 ／ **検証** test_intel_*.py（機能側）。HTTP 形状は部分的 ／ **分類** CORE
### S2-API-034: センサー・LLM 制御面（14 本、v2 フラグ + analyst 基準）
**挙動**:

| Path | 認可 | レスポンスキー |
|---|---|---|
| GET `/api/v2/sensors/catalog` | analyst | `api_version`, `sensors[{sensor, domain, label}]`（22 件） |
| GET `/api/v2/sensors/<name>/observations` | analyst | `api_version`, `sensor`, `scope`, `label`, `domain`, `baseline_window_hours`, `observations[{ts,value,baseline,delta_vs_baseline}]`, `history_shallow`, `current{status, fired_reason, suppressed, suppress_reason, raw_value}`。未知センサー 404。`hours` 1..24 |
| GET `/api/v2/llm_features` | analyst | `count`, `data[{key, tier, name, description, env_var, shadow_env_var, default_state, np7_concern, requires_admin, supports_shadow, current_state, source, kill_switch_active}]` |
| GET `/api/v2/llm_features/<key>` | analyst | `data`（上記 + `history[{id, feature_key, old_state, new_state, changed_at, changed_by, reason}]`）。404 あり |
| POST `/api/v2/llm_features/<key>/set` ／ `/clear` | **feature 別**（`requires_admin` なら admin） | body `{state∈on\|off\|shadow, reason?}` → `data{key, new_state, by:"<role>:<id>"}`。400（不正 state / shadow 非対応）/ 404 / 500 |
| POST `/api/v2/llm_features/kill_switch` | **admin** | body `{state∈on\|off, reason?}` → `data{kill_switch_state, by, reason}` |
| GET `/api/v2/llm_features/audit` | analyst | `count`, `filters{hours,limit}`, `data[]` |
| GET `/api/v2/llm_routing` | analyst | `effective[{use_case, slot, feature_state, model, temperature, top_p, top_k, seed, num_predict, repeat_penalty, thinking_enabled, system_prefix, available}]` |
| GET `/api/v2/llm_routing/overrides` | analyst | `overrides[{id, use_case, slot, …params…, set_at, set_by, reason}]` |
| POST / DELETE `/api/v2/llm_routing/overrides` | **admin** | `{ok, use_case, slot}`（POST は `effective[]` も）。400 に `valid` 一覧 |
| GET `/api/v2/llm_preflight` | analyst | `ollama{reachable, version, error, host}`, `model`, `models[]`, `embedding`, `go_no_go`, `missing[]`, `version_ok`, `snapshot_error?` |

**根拠** {sensors_v2,llm_features_v2,llm_routing_v2}.py ／ **検証** test_routes_llm_features.py(16) /
test_sensor_tier_exposure.py(3) / test_llm_routing.py ／ **分類** CORE
### S2-API-035: シナリオ管理面（13 本）
**挙動**:

| Path | 認可 | レスポンスキー |
|---|---|---|
| GET `/api/admin/scenarios` | admin | `scenarios[]` = Scenario 全体（`id, name_en, name_ja, description_en, description_ja, core_country, state, enabled, tier, participants{cc:{country,weight,role}}, created_at, updated_at, updated_by, preset_metadata`）+ `source`(db\|preset), `is_scorable`, `is_admin_override`, `preset_enabled` |
| POST `/api/admin/scenarios` ／ PUT `/<sid>` ／ DELETE `/<sid>` | admin | 201 `{ok, id}` ／ `{ok, id}` ／ `{ok, action∈delete\|purge}`。**PUT の `state` 同時更新は 400 で拒否 MUST**（ADR-011）。`?purge=true` は DB 行必須、preset の purge は 409 |
| POST `.../state` ／ `.../enabled` ／ `.../reset` | admin + 監査 | `{ok, state}` ／ `{ok, enabled}` ／ `{ok, source:"preset"}`。不正遷移 409 |
| GET `.../changelog` | admin | `scenario_id`, `changes[]`。`limit`(50, 1..500) |
| GET `/api/admin/sensor_health` | **analyst**（パス接頭辞と不一致） | `ts`, `window_hours`, `summary{total, ok, degraded, stale, error, circuit_open, disabled, initializing}`, `sensors[{name, domain, enabled, health, tier, poll_interval_sec, cache_age_sec, last_fetch_ts, last_error, cb_state, cb_fail_count, reliability{}, upstream}]` |
| GET `/api/scenarios` | 3 ロール | `focused_scenario`, `scenarios{sid: Scenario dict}`（**マップ形**） |
| GET `/api/scenarios/compare` | 3 ロール | `snapshot_age_sec`, `scenarios[{scenario_id, name_en, name_ja, lite{}, full{}, baseline_score, baseline_tl}]`。`ids` 必須・上限 10。未知 id は `{scenario_id, error:"unknown"}` |
| POST `/api/scenarios/<sid>/whatif_weights` | **analyst+** | ScenarioState 平坦 dict + `scenario_id, snapshot_age_sec, baseline_score, baseline_tl, delta_score, applied_weights{cc:{applied, base}}`。スナップショット不在 503 |

**根拠** admin.py:461-733、core.py:137-260 ／ **検証** test_scenarios.py / test_scenario_admin_override.py（機能側）。HTTP 形状は未検証 ／
**分類** CORE。`/api/admin/sensor_health` が admin でない点は ACCIDENTAL（§11-A6）
### S2-API-036: 状況認識・分析面（11 本、すべて 3 ロール読み取り）
**挙動**:

| Path | params | レスポンスキー |
|---|---|---|
| GET `/api/data_status` | — | `ts`, `sensors[{sensor, domain, enabled, health, poll_interval_sec, cache_age_sec, cache_size_chars, last_error, last_fetch, fetch_log, upstream?}]` |
| GET `/api/alert_timeline` | `limit`(288, 1..288) | `ts`, `count`, `timeline[]` |
| GET `/api/sitrep` | — | `ts`, `text`(整形済み複数行), `summary{threat_current, threat_trend, threat_min_1h, threat_max_1h, threat_avg_1h, convergence, active_domains[], core_country, span_minutes, cycle_count}`（無データ時 `{}`） |
| GET `/api/sequence_chain` | `country`? | `ts`, `chains{cc: {sequence_bonus, chain_status, chain_found[], events[{ts,dt,type,meta}], window_hours}}` |
| GET `/api/salute_report` | `lang`(en\|ja) | `ts`, `report{dtg, size, activity, location, unit, time, equipment, assessment, threat_level, convergence, velocity, blockade_interpretation, blockade_index, sequence_status, cross_ref}` |
| GET `/api/weather_brief` | `lang` | `ts`, `brief{cyber, maritime, info, air, infra: {state, detail}}` |
| GET `/api/ip_check` | `ip`(必須 IPv4) | `ip, noise, riot, classification, name, last_seen, message, cached, fetched_at, daily_remaining, error`。400 / 503 / 502 |
| GET `/api/whatif/catalog` | — | `sensors[{sensor, domain, label, max_score, is_suppressor?}]`（20 件） |
| POST `/api/whatif/simulate` | body `{events[{sensor,score,suppressed}], tl1_hard?, sequence_bonus?, temporal_bonus?}` | `ts, simulation, threat_level, total_score, score_with_bonus(上限 15), convergence_score, convergence_level, convergence_bonus, sequence_bonus, temporal_bonus, tl1_hard, active_domains, domain_scores{}, rationale[], system_note` |
| GET `/api/spof_analysis` | — | `ts, current_threat_level, baseline_total_score, baseline_convergence, spof_entries[{sensor, domain, current_score, score_impact, domain_lost, convergence_downgrade, convergence_from, convergence_to, health, enabled, last_error, cache_age_sec, has_fallback, criticality}], domain_summary{}`。無データ 503 |
| GET `/api/climate` | — | `gauge{}`, `feed[直近50]`, `indicators_active{}`, `last_update`, `calendar[]` |

**根拠** analytics.py:33-870、climate.py:10-24 ／ **検証** **未検証**（§13 GAP-08）／ **分類** CORE
### S2-API-037: 較正・提案・発見面（8 本、v2 フラグ + analyst、`data` ラップ形）
**挙動**:

| Path | params | `data` の中身 |
|---|---|---|
| GET `/api/v2/threshold_history` | `key` / `scope` / `hours`(168,1..720) / `limit`(50,1..500) | `[{id, emitted_at, key, value, scope_scenario_id, effective_from, effective_to, derived_from, applied_by, revertible_to_id, sample_n, formula_ref, evidence, magnitude_pct, state}]` + `count`, `filters` |
| GET `/api/v2/proposals/sensor_disable` | — | `[{id, sensor_name, emitted_at, ack_due_at, evidence, why_string, state}]` + `count` |
| GET `/api/v2/proposals/scenario_improver` | `scenario_id` / `hours` | `[{id, scenario_id, proposal_type, target_country, suggested_value, evidence, formula_ref, sample_n, why_string, emitted_at, evidence_strength, vitality_state, state, is_recall_reducing}]` |
| GET `/api/v2/drift_signals` | `severity` / `hours` / `min_consecutive_runs`(3,1..24) | `[{id, scenario_id, drift_signal, severity, target_country, evidence, why_string, consecutive_runs, emitted_at}]` |
| GET `/api/v2/calibration/health` | `hours`(168) | `{threshold_history{state:count}, scenario_proposals{"type\|state":count}, scenario_drift_events{"severity\|ack":count}, actionable_drift_count, proposal_quality{}, window_hours}`（**`window_hours` だけ `data` の内側**） |
| GET `/api/v2/calibration/tier_governor` | — | `{current_tier, current_tier_name, raw_stored_tier, cap, kill_switch_engaged, tier_entered_at, days_at_current_tier, next_tier, promotion_gates[{…met}], gates_met, gates_total, metrics{}, active_cooldowns[], recent_transitions[], consecutive_failures}` |
| GET `/api/v2/discovery/clusters` | `hours`(168) / `limit`(50) | `[{id, run_id, cluster_index, countries[], centroid, annotation, annotation_state, suggested_scenario_id, formula_ref, run_emitted_at, run_eps, run_min_samples, run_algorithm}]` |
| POST `.../ack` ／ `.../apply` ／ `.../dismiss` ／ `.../defer` | — | 提案の状態遷移。`{ok}` 系 |

**根拠** calibration_v2.py:97-733、calibration_governor.py:44 ／ **検証** test_routes_calibration_v2.py(29) ／ **分類** CORE
### S2-API-038: 認証・ユーザー管理（11 本 + app_config）
**挙動**:

| Path | 認可 | 契約 |
|---|---|---|
| POST `/api/auth/login` | 公開 | 200 `{access_token, username, role, access_expires_sec}`。**`refresh_token` を body に含めてはならない MUST**。401 `Invalid credentials`（**ユーザー存在を区別しない MUST**）／400／429 |
| POST `/api/auth/refresh` | 公開（refresh Cookie） | 200 `{access_token}`（role は毎回 DB から再解決）。Cookie 無し／access token 提示は 401 or 422 |
| POST `/api/auth/logout` | JWT | 200 `{status:"ok"}`。access JTI を失効、refresh Cookie をクリア |
| POST `/api/auth/register` | JWT + **admin** | 201 `{status:"ok", username, role}`。400（12 文字未満 / 不正 role）／403／409 |
| GET / PUT `/api/auth/settings` | JWT（自分の行のみ） | GET 200 `{focused_scenario, muted(list), lang}` ／ 404。PUT の allow-list は同 3 フィールド、未知キーは無言で無視、全滅時 400。**UI からの参照が存在しない**（D2 B-09、裁定は S2-PROP-014） |
| GET `/api/auth/users` ／ PUT `/users/<u>/role` ／ DELETE `/users/<u>` ／ POST `/users/<u>/reset-password` | JWT + **admin** | 自分自身の role 変更・削除は 400 |
| PUT `/api/auth/password` | JWT（自己） | 400（12 文字未満）／401 `Invalid current password`／404／200。成功時**当該ユーザーの全既発行トークンを失効させる MUST** |
| GET `/api/app_config` | **公開** | `default_focused_scenario`, `strategic_blocs`, `country_bloc_tags`, `available_countries[{code,name,region,lat,lng}]` |

**根拠** auth.py:397-712、core.py:118-129 ／ **検証** test_auth.py(49) / test_password_hashing.py(12) ／ **分類** CORE

## 8. OPS / drop 候補 — **[参照]**
### S2-API-039: OPS から実際に呼ばれる REST は 12 本のみ
**挙動**: 実行系スクリプトで REST を呼ぶのは `scripts/smoke_tradecraft.sh` だけで、対象は
`/api/auth/{register,login}` と `/api/analyst/{disconf,ach,assumptions,decisions}` 系（権限マトリクスの
post-deploy スモーク）。他の運用スクリプトは**すべて DB 直読み**（docker exec + SQLite）で動作する。
**根拠** D6-api-surface.md §1、scripts/smoke_tradecraft.sh ／ **検証** 未検証 ／ **分類** CORE
### S2-API-040: tradecraft 25 本と UNREFERENCED 8 本
**挙動**: tradecraft（`/api/analyst/*`）25 本は全て JWT + analyst（唯一
`POST /api/analyst/assumptions/<aid>/lock` のみ **admin**）。レスポンスは `{items[]}` / `{views[]}` /
`{matrices[]}` / `{entries[]}` / `{id}` / `{ok}` のいずれか、エラーは 400/403/404。**書込は必ず
`decision_ledger` に `detail.auto=true` の行を追記する MUST**（自動記録）。手動
`POST /api/analyst/decisions` は `auto` を立てない。UNREFERENCED 8 本は `POST /api/persist_save` ／
`GET /api/analytics/{calibration_advisory, confidence_distribution, scenario_phases}` ／
`POST /api/v2/attention/observations/recompute` ／ `GET /api/intel/sources` ／ `GET /api/score_breakdown` ／
`GET /api/v2/admin/shadow_write_metrics`。
**根拠** analyst.py:85-651、D6-api-surface.md §3 ／ **検証** test_analyst_permissions.py(18: 権限行列 +
auto ledger 6 + 台帳不変 2) ／ **分類** CORE（記録）。v3 での処遇は S2-PROP-012 / S2-PROP-013

## 9. SocketIO プロトコル — **[完全]**

**本節 S2-API-041〜043 はすべて検証が「未検証」**（radar/ws.py に専用テストが無い — §13 GAP-05）。
### S2-API-041: 接続は JWT 必須。トークンは auth dict、query param は非推奨
**挙動**: `connect` 時にトークンを検証 **MUST**。取得順は (1) Socket.IO `auth` dict の `token`、
(2) query param `token`（**非推奨**）。トークン欠落・復号失敗・**失効済み JTI** はいずれも `disconnect()` +
`False` **MUST**。CORS は `CORS_ALLOWED_ORIGINS` 未設定時**同一オリジンのみ MUST**。
**根拠** radar/ws.py:27-67 ／ **分類** CORE
### S2-API-042: クライアント→サーバのイベントは 2 種。room は `theater:{country}`
**挙動**: `subscribe_theater` / `unsubscribe_theater` の 2 種のみ **MUST**。payload は文字列（国コード）または
`{"theater": "TW"}`。国コードは strip + 大文字化して **room `theater:{COUNTRY}`** に join/leave。subscribe
成功時のみ `subscribed` `{theater, status:"ok"}` を返す（unsubscribe には応答が無い）。
**room 単位は country であってシナリオではない**。
**根拠** radar/ws.py:74-92、radar.js:8202-8204,9526 ／ **分類** **DEFECT-PRESERVE**（D2 C-01 の最深部。v3 語彙は S2-PROP-020）
### S2-API-043: サーバ→クライアントのイベントは 6 種。WS は代替でなく補完
**挙動**: `threat_update`(room) = `strategic_alert` 全体 + **`__ws_scenario_id`**。クライアントは**focus 不一致の
push を破棄 MUST**（focus 切替レース対策）。`ambush_alert`(room) = ambush 検知データ、**同時に外部通知も
発火 MUST**。`sequence_event`(room) = `{status, …}`。`sensor_status`(broadcast) = `{sensor, status}`、
クライアントは `__proto__`/`constructor`/`prototype` を**拒否 MUST**（prototype 汚染対策）。
`notification_result`(broadcast) = `{channel, title, success, detail}`。`intel_update`(broadcast) =
`{id, headline, source_type, status}`、**emit 関数の `theater` 引数は未使用**（D2 B-07）。
`threat_update` は `strategic_alert` のみを運ぶため、クライアントは**受信データで `latestData` を置換せず
`strategic_alert` フィールドのみを差し替える MUST**（`targets`/`sensor_health`/`scenarios` は保持）。さらに
**採点は GET が駆動するため、WS 接続中も 15 分ポーリングを継続する MUST**（S2-API-017 の帰結）。接続失敗は
`connect_error` で degraded 表示にする **MUST**（「接続済み」と「無言でポーリング」を区別できるように）。
**根拠** radar/ws.py:98-154、radar.js:9543-9623,9628-9642 ／ **分類** CORE（`intel_update` の dead param は §12-DP11）

## 10. パラメータ・閾値カタログ

| 閾値 | 値 | config キー | DB override |
|---|---|---|---|
| 採点キャッシュ TTL ／ 既定 focused シナリオ | 60 s ／ `taiwan_contingency` | `SCORE_REFRESH_SEC` ／ `DEFAULT_FOCUSED_SCENARIO` | 可 |
| v2 API 有効化 ／ NP7 文言 | true ／ 固定文 | `V2_API_ENABLED` ／ `V2_NP7_DISCLAIMER` | 可 |
| access ／ refresh token 有効期限 | 1 h ／ 24 h | `JWT_ACCESS_EXPIRES` ／ `JWT_REFRESH_EXPIRES` | **不可**（immutable） |
| ログイン失敗上限 / 窓 ／ 全体レート制限 | 5 回 / 300 s ／ 120/min + 2000/h（auth 5/min） | —（ハードコード） | 不可 |
| メインポーリング周期 | 15 min | —（フロント定数） | 不可 |
| `hours` の一般上限 / 監査系 ／ `limit` の一般上限 | 168 / 8760 ／ 200〜5000（endpoint 別） | — | 不可 |
| TRIAGE snooze ／ dismiss TTL ／ 閾値既定 | 30 min(1..1440) ／ 86400 s ／ dormant 0.40・critical 0.85 | — | 不可 |
| attention snooze ／ 学習下限 | 24 h(0<h≤168、下限 0.5 h) ／ sample 30 件・相対差 30% | `ATTENTION_MIN_LEARN_SAMPLES` | 可（後者のみ） |
| narrate バッチ / 文字数 ／ feedback notes ／ 監査値切詰 | 8 件 / 240 字 ／ 2000 字 ／ 8000 字 | — | 不可 |
| config registry キー数 | 98（secret 12 / immutable 15 / bootstrap 6 / restart 25 / high impact 8） | — | — |

**v3 への示唆**: **API 層のハードコード閾値が 10 件ある**。NP6 の観点では、**クライアント挙動を規定する値
（ポーリング周期・バッチ上限・snooze 既定）も registry に載せるべき**。

## 11. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | `POST /api/v2/conclusions/<id>/feedback` に**ロールゲートが無く viewer が ground-truth を書ける**。同 endpoint は条件付きで `confirmed_threats`（較正の教師データ）にも書き込む | 較正災害 3 件の原因はすべて「ラベル生成器の汚染」だった。書込権限を analyst 以上に上げるべきか。**最重要** |
| A2 | `X-Scenario-Overlay` のパース失敗を**無言で無視**する（viewer も同様） | 分析仮説の検証操作が黙って効かないのは AP2（操作結果の可視性）に反する。400 にすべきか |
| A3 | `/api/v2/config/registry` の `include_secrets` が**実装既定 true・docstring 既定 false** | どちらが意図か。secret の `default` は null 化されるので実害は小さいが契約としては不定 |
| A4 | TRIAGE の snooze / dismiss が **global スコープ**（1 人の操作が全員を黙らせる） | 単独運用では実害が無いが複数アナリスト運用では NP1 に反する。per-user 化すべきか |
| A5 | config registry の `enum` / `validator` を使うキーが**0 件**（検証分岐が死んでいる） | 意図的な未使用か、登録漏れか |
| A6 | `GET /api/admin/sensor_health` が `/api/admin/` 配下でありながら **analyst で通る** | パス接頭辞と認可の不一致。パスを変えるか認可を上げるか |
| A7 | 未認証時のステータスがテスト間で不統一（401 固定と `(401, 422)` 許容が混在） | 同じ `@jwt_required()` なのにクライアントが 1 コードに依存できない。401 に固定すべきか |
| A8 | `/api/intel/pending/triage` が **viewer にも開いており v2 フラグの対象外** | AP1 の主要面が v2 の停止スイッチから外れている。意図的か |

## 12. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | `theater_baseline`/`country_baseline`、`travel_advisory.all`/`.country_all`、`ooni.adversary`/`.country_adversary`、`mil_support_air.all`/`.country_all` が**同一オブジェクトの二重書き**（5 対） | 語彙を country に一本化し**旧キーを出力しない MUST** | C-01 |
| DP2 | GET が採点・台帳書込・WS emit を駆動するため**ポーリングを止められない**。採点失敗フラグも次ティックで消える | 採点は scheduler 所有、API は**読み取り専用 MUST**（S2-PROP-001） | A-01 |
| DP3 | 認可強制が 3 系統・403 文言 3 種。ヘルパは手動 return で、return 忘れがゲートを無言で無効化する | **単一のデコレータ機構 MUST**。403 body は 1 形 | — |
| DP4 | エラー body 4 系統 + 成功 body 3 系統。**例外を HTTP 200 に埋める箇所が 5 本** | **単一 envelope MUST**。障害は必ず 4xx/5xx で表す | — |
| DP5 | v2 応答 envelope が 4 形に分裂し、NP7 disclaimer が (D) 形に無い | **全 v2 応答（成功・失敗とも）が NP7 を持つ MUST** | — |
| DP6 | feedback 書込にロールゲートが無い（§11-A1） | ground-truth 書込は **analyst 以上 MUST** | — |
| DP7 | `audit_trace` が `state`/`confidence`/`conclusion_unavailable_reason` を含まず、**トレースだけでは「何を結論したか」が分からない** | 監査トレースは結論本体も含む **MUST** | — |
| DP8 | 認可とフラグの評価順が不統一（flag→auth 5 本、auth→flag 3 本）。同じ状況で 503 と 403 が分かれる | 判定順序を**全 endpoint で固定 MUST** | — |
| DP9 | `/api/v2/replay` の envelope が docstring の主張と 3 点で異なる（`replay_at` vs `observed_at`、per-conclusion disclaimer 欠落、欠損型のスタブ無し） | replay は live と**同一 envelope MUST**（time-travel は形が同じでなければ比較にならない） | — |
| DP10 | `POST /api/v2/config` の成功が**監査行を 2 行**書く。`GET /api/sensor_config` すら監査行を書く | 1 変更 1 行 **MUST**。読み取りは監査しない | — |
| DP11 | `emit_intel_update(theater, …)` の `theater` 引数が未使用 | 引数削除 **MUST** | B-07 |
| DP12 | `POST /api/v2/decisions/<id>/revoke` の `already_inactive` 409 が**到達不能**（`revoked_at` を見ず `superseded_by` を見る）。二重 revoke は `revoke_race` になる | 状態判定は revoke/supersede の両方を見る **MUST** | — |
| DP13 | `decisions` 系の 503 body だけが v2 NP7 envelope でない（`{"error":"v2 API disabled…"}`） | DP5 で解消 | — |
| DP14 | NP7 確認（`np7_confirmed`）を要求するヘルパの**呼び出し元がゼロ**。さらに `not X is True` の優先順位バグで、再配線しても真値以外を通す | 破壊的操作の確認要求を**実配線 MUST** | — |
| DP15 | `POST /api/v2/attention/<rule>/snooze` の `hours` が非数値のとき 500（兄弟の threshold PUT は 400） | 入力検証は全 endpoint 一様 **MUST** | — |

## 13. テストトレーサビリティ（D5 CONTRACT 級 17 ファイル全件）

| テスト | 条項 | テスト | 条項 |
|---|---|---|---|
| test_auth.py (49) | 001,002,003,009,010,038 | test_conclusions_feedback.py (14) | 003, 019 |
| test_decisions.py (32) | 021, 022, 023 | test_analyst_feedback_v2.py (13) | 028 |
| test_routes_calibration_v2.py (29) | 005, 037 | test_routes_triage_narrative.py (10) | 027 |
| test_conclusions_markdown.py (21) | 019（`.md` 構造契約） | test_auto_judge_v2.py (9) | 028 |
| test_conclusions_api.py (19) | 005, 018, 019, 020 | test_self_eval.py (9) | 024 |
| test_analyst_permissions.py (18) | 002, 040 | test_config_audit_endpoint.py (7) | 007, 031 |
| test_routes_llm_features.py (16) | 034 | test_intel_confidence_distribution.py (5) | **GAP-03** |
| test_conclusions.py (14) | 018（4 不変条件） | test_history_routes.py (3) | 008, 032 |
| | | test_sensor_tier_exposure.py (3) | 034 |

**GAP（仕様化できたが検証が無い）**: **GAP-01** `/api/v2/replay/<sid>` に HTTP テストが 1 件も無い（AP4 中核 endpoint の
envelope・`at` の意味論・400 経路が完全に未固定）／**GAP-02** `/api/intel/pending/triage` の HTTP 面（envelope・clamp・
`theater`→`country` 改名）が未検証、pure helper のみ検証済／**GAP-03** `/api/analytics/confidence_distribution` は DB 関数のみ
検証、endpoint は無参照（drop 候補）／**GAP-04 `/api/threat_data` に専用テストが無い** — 最大の endpoint がパリティ検証の
足場を持たない（011〜017 が全て未検証）／**GAP-05** `radar/ws.py` の全プロトコル（認証・room・6 イベント）が無テスト
（041〜043）／**GAP-06** `/api/v2/config*` 4 本が無テスト — **98 キーの契約が実装のみに存在する**（029〜031）／**GAP-07**
認可ラダーの 403 段が v2 結論族で未検証（全テストが admin トークンで認証している）／**GAP-08** `analytics.py` の 11 endpoint
（sitrep / salute / spof 等）が無テスト（036）。

## 14. 未決事項

1. **`/api/threat_data` の分解粒度**は S2 では決められない。読み取り専用化（S2-PROP-001）は確定だが、「1 本の集約読み取り」か
   「観測系・結論系・地図系の 3 本」かは**フロントの描画境界に依存する**ため、S1-frontend（HUD 意味論）と合わせて Phase P で決める
2. **GUIDE（外部公開契約 102 endpoint）の扱い**。GUIDE のみの 11 本を落とすなら GUIDE 改訂が必須だが、`noise_exclusion`
   GET/DELETE と `confirmed_threats` GET は**UI 側の導線欠落が原因**であり endpoint でなく UI を直すのが筋（D6 §3）。
   **この 3 本は drop 対象から外すべき**
3. `X-Scenario-Overlay` を v3 でもヘッダに置くかは未決。冪等な GET の意味論を変える副作用があるため what-if endpoint への
   吸収案を S2-PROP-009 に置いたが、確定は Phase P

## 15. PROPOSAL — v3 契約への提案（**Phase P の入力**）

> 以下は**現行契約の記述ではない**。すべてオーナー裁定または Phase P での設計判断を要する。
### S2-PROP-001: `/api/threat_data` を読み取り専用にする（D2 A-01 の帰結）
D3 の判定「scheduler が採点パイプラインのオーナーに昇格」により v3 の採点 API は副作用を持たない。
**契約変更の影響範囲**（クライアント側の再設計が必要な箇所）:

| 現行の暗黙契約 | v3 での帰結 |
|---|---|
| GET が採点を駆動するので WS 接続中もポーリングが必要 | **ポーリングは表示鮮度のためだけになり WS 主導へ移行できる**。周期を自由に選べる |
| `?force=snapshot`/`sensors` で「今すぐ採点し直す」ができた | **採点トリガは別 endpoint か不要**。`force` は API から消え、SYNC ボタンの意味論が「再取得要求」から「表示更新」へ変わる |
| `?focus=` が analyst focus をサーバに登録していた | **focus 登録は明示的な別 endpoint MUST**。読み取りの副作用にしない |
| `?muted=` がその場の採点結果に効いた | ミュートは**永続設定**（config / user settings）へ移し、読み取りパラメータでなくす |
| `X-Scenario-Overlay` がその場の採点に効いた | what-if は**独立 endpoint** へ（S2-PROP-009） |
| `scoring_error` が「このリクエストの採点が失敗した」を表した | 「**最後の採点ティックが失敗した**」を表すサーバ状態に変わる。キャッシュヒットで消える現象（§12-DP2）は解消 |
| 採点結果の鮮度がリクエスト時刻とほぼ一致 | **`observed_at`/`data_freshness_sec` が契約上の必須フィールドになる**。UI は「いつの採点か」を常時表示する MUST |
| LLM インテルキューの破壊的ドレインが GET に紐付いていた | ドレインは scheduler 側。**同じ GET を 2 回叩いても結果が変わらない（冪等）MUST** |

**前提条件**: D2 F-05（採点ティックが非冪等 — Z-score の走行統計更新が採点と同居）の解消。これを直さない
限り scheduler 駆動にしても S5 の replay パリティが成立しない。
### S2-PROP-002〜011: v1/v2 重複 10 対の統合案

| ID | v1（旧） | v2（新） | 統合先 | 理由 |
|---|---|---|---|---|
| PROP-002 | `/api/cooccurrence` | `/api/v2/discovery/cooccurrence` | **v2**（UI 導線ごと再設計） | どちらも実消費者がいない。v2 は discovery 名前空間に属し一貫する。導線を作らないなら両方 drop |
| PROP-003 | `/api/history/threat_levels` | `/api/v2/scenarios/<sid>/threat_history` | **v2** | v1 は全シナリオ横断で**シナリオ中心設計と非整合**。v2 は UI 現役。ただし v2 側の envelope 欠陥（`observed_at` 欠落・hand-roll）を S2-PROP-018 で直す |
| PROP-004 | `/api/score_breakdown` | `/api/v2/conclusions/<id>/audit_trace` | **v2** | NP6 の導出開示は結論単位であるべき。v1 は無参照 |
| PROP-005 | `/api/analytics/calibration_advisory` | `/api/v2/calibration/health` + `threshold_history` | **v2** | v1 は助言のみ、v2 は自動適用 + 監査。NP6 の遡及性が v2 にしかない |
| PROP-006 | `/api/analytics/confidence_distribution` | 較正パイプライン内部 | **endpoint を持たない** | 分布計算は DB 関数として存続。必要なら `self_eval` の 1 ブロックとして出す |
| PROP-007 | `/api/sensor_reliability` | `/api/admin/sensor_health` | **後者。ただし `/api/admin/` から移動** | 同じセンサー健全性。**認可 analyst なのにパスが admin**（§11-A6）なので `/api/observability/sensors` 等へ |
| PROP-008 | `/api/daily_summary` | `/api/sitrep` | **sitrep** | sitrep が UI 現役で日次サマリはその特殊化。`?window=24h` で吸収 |
| PROP-009 | `/api/whatif/catalog` + `POST /api/whatif/simulate` | `POST /api/scenarios/<sid>/whatif_weights` | **シナリオ単位に統合** | what-if が 2 系統（センサー単位 / weight 単位）に分裂。v3 は**「シナリオに対する反実仮想」1 系統**にし、センサー・weight を同じ body で受ける。`X-Scenario-Overlay` もここへ吸収（§14-3） |
| PROP-010 | `/api/v2/config_audit` | `/api/v2/llm_routing/audit` | **汎用側（config_audit）** | 別テーブルだが、監査台帳を 1 本化すれば `?domain=llm.routing` で表現できる。専用 endpoint を持つ理由が無い |
| PROP-011 | `/api/threat_data` | `/api/v2/scenarios/<sid>/conclusions` + `threat_history` ほか | **v2 系へ分解**（粒度は §14-1 で保留） | 最大の対。S2-PROP-001 の前提 |
### S2-PROP-012: UNREFERENCED 8 本を drop（**条件付き**）
D6 §3 が curl 暗黙契約の可能性まで否定済み、D3 オーナー判断 2 が「全 drop 推奨で決着可能」と判定済み。**条件**:
`POST /api/v2/attention/observations/recompute` のみは AP1 の運用フックなので**drop ではなく管理 CLI 化**を推奨（endpoint を
消して機能は残す）。残り 7 本は無条件 drop。
### S2-PROP-013: tradecraft 25 endpoint を drop（**オーナー判断 1 の推奨 (a) を前提とする条件付き提案**）
D3 §3-1 の推奨 (a)「v3 に持ち込まない」が採択された場合にのみ成立する。**前提が覆り (b)（凍結のまま移植）が選ばれた場合、
本提案は無効**であり、25 endpoint は S2-API-040 の契約のまま移植される。根拠の補強: D4 で実データが全量テスト残骸（82 回の
テスト実行と行数が一致）と確認済みのため**export による保全すら不要**。ただし `decision_ledger` への auto 書込契約
（S2-API-040）は、tradecraft を落としても**「アナリスト操作の自動記録」という設計思想として AP4 に引き継ぐべき**。
### S2-PROP-014: `GET/PUT /api/auth/settings` を drop（D2 B-09 の裁定案）
**per-user 設定を `/api/v2/config` 系に一本化**する。保持する 3 フィールドのうち `lang` は**日本語専用 UI 化（2026-08-02）で
無意味**になり、`focused_scenario` と `muted` は現行 SPA が localStorage で扱っている。GUIDE の記述（「core, pinned,
correlated, adversary countries を保存」）は実スキーマ（3 フィールド）と乖離しており**契約として既に壊れている**。UI 参照消失は
リグレッションではなく**設計の置き去り**と判断する。
### S2-PROP-015: `GET/PUT /api/v2/decisions/threshold` は keep し UI を接続する（D2 B-09 の裁定案）
per-user の TRIAGE 閾値であり、AP1 の「順位の根拠が常時可視」という要求に直結する。API-first で先行実装されたまま UI が
追いついていない状態。**閾値をアナリストが調整できないと AP1 の attention_score が固定式になり、AP3 の自己評価と噛み合わない**。
drop ではなく UI 側の欠落を埋める。S2-PROP-014 と併せ **v3 では両方を S2 契約に明示的に載せる**（「GUIDE と test にしか
存在しない」状態を解消）。
### S2-PROP-016〜019: 横断的な契約の統一
**PROP-016（認可）**: 強制機構を**単一デコレータに統一**し 403 body を 1 形に。評価順序を全 endpoint で
`503(flag) → 401(authn) → 403(authz) → 400/404 → 200` に固定（§12-DP3 / DP8 解消）。
**PROP-017（エラー形）**: 全応答を**単一 envelope** `{api_version, observed_at, final_judgment_disclaimer, data|error}` に統一。
**HTTP 200 の body に `error` を埋める 5 箇所を廃止 MUST**（§12-DP4）。エラーは `{code, message, detail}` の**機械可読な形**に
し `code` を UI の i18n キーに対応させる（現行の英文プロース 123 箇所は i18n 不能）。
**PROP-018（NP7）**: 例外なく全応答が `final_judgment_disclaimer` を持ち、結論オブジェクト自身も保持する（§12-DP5 / DP13 解消）。
**PROP-019（監査）**: 1 変更 1 監査行。**読み取りは監査しない**（§12-DP10）。
### S2-PROP-020: WS プロトコル v3 案 — theater 語彙の全廃

| 現行 | v3 案 | 備考 |
|---|---|---|
| `subscribe_theater` / `unsubscribe_theater` | **`subscribe_scenario` / `unsubscribe_scenario`** | 引数は `{"scenario_id": "…"}` の dict 単一形（文字列許容は廃止） |
| room `theater:{COUNTRY}` | **room `scenario:{scenario_id}`** | v2 のシナリオ中心設計に整合。1 シナリオが複数国を含むため、国単位 room では focus と room が 1 対 1 にならない現行の歪みが解消する |
| `subscribed {theater, status}` | **`subscribed {scenario_id, status}`** | **`unsubscribe` にも応答を返す**（現行は無応答） |
| `threat_update`（`__ws_scenario_id` タグ付き） | **`scenario_update`** `{scenario_id, observed_at, …}` | **後付けタグが不要になる** — room 自体がシナリオ単位なので focus 切替レースが構造的に消える |
| `ambush_alert` | **`anomaly_alert`** `{scenario_id, …}` | 「ambush」は DDoS 時代の語彙（D2 C-04）。結論型 `anomaly` に揃える |
| `sequence_event` | **`sequence_event`** `{scenario_id, …}` | 名前は維持。payload に `scenario_id` を必須化 |
| `sensor_status`（broadcast） | 維持（broadcast） | センサーはシナリオ横断なので broadcast が正しい。payload に `domain`/`cb_state` を含める（現行はクライアントが前値とマージして補っている） |
| `notification_result`（broadcast） | 維持 | — |
| `intel_update`（`theater` 引数未使用） | **`intel_update`（引数削除）** | §12-DP11 |

**追加提案**: v3 では WS に**再接続時の差分同期**（`last_event_id` を送って取りこぼしを補う）を入れる。現行は
再接続後に次のポーリングまで穴が空く。S2-PROP-001 でポーリングが表示専用になると、この穴が**検知遅延に
直結する**（NP1）ため。
### S2-PROP-021: 認可モデル（role → endpoint 群のマトリクス）

**現行の非対称を整理し、「読めるものは読める / 変えるものは analyst / 系全体を変えるものは admin」の 3 層に
揃える**提案。

| endpoint 群 | viewer | analyst | admin | 現行からの変更 |
|---|---|---|---|---|
| 採点・結論の読み取り（threat_data 後継 / conclusions / audit_trace / threat_history / .md） | ○ | ○ | ○ | 変更なし |
| 状況認識の読み取り（sitrep / salute / weather / spof / climate / history / センサー観測） | ○ | ○ | ○ | 変更なし |
| **自己評価・透明性の読み取り**（self_eval / replay / chronic_inconclusive / decisions history / attention 一覧 / auto_judge / analyst_feedback） | **○** | ○ | ○ | **viewer に開放**。AP3 の「今このツールをどこまで信じるか」は**全利用者が見るべき情報**で、analyst 限定にする理由が無い |
| インテル読み取り（intel / triage / stats） | ○ | ○ | ○ | 変更なし |
| **アナリスト判断の書込**（intel confirm/reject、feedback、human anchor 回答、TRIAGE snooze/dismiss/visibility、attention threshold、what-if） | × | ○ | ○ | **feedback を viewer から analyst へ引き上げ**（§11-A1 / §12-DP6）。較正の教師データ汚染を防ぐ |
| 較正提案の受理・却下（proposals apply/dismiss/defer、drift ack、threshold revert） | × | ○ | ○ | 変更なし |
| シナリオ定義の変更（admin/scenarios 全操作） | × | × | ○ | 変更なし |
| 設定の変更（config POST/DELETE、sensor 有効化、LLM routing override、kill switch） | × | × | ○ | `requires_admin=false` の LLM feature のみ analyst 可（現行維持） |
| ユーザー管理（register / users / role / reset-password） | × | × | ○ | 変更なし |
| 自己管理（password 変更、自分の per-user 設定） | ○ | ○ | ○ | 変更なし |
| 監査台帳の読み取り（config_audit / llm_features audit / decisions detail） | × | ○ | ○ | 変更なし |
| 破壊的操作（decisions revoke の `tl_recal_*` / `dual_weight_*`） | × | × | ○ | **確認要求（`np7_confirmed`）を実配線 MUST**（§12-DP14） |

**設計上の判断**: v3 でも**ロール階層は数値化せず包含集合で表現する**が、`viewer < analyst < admin` の全順序を
**単一の定数として宣言し全ゲートがそれを参照する MUST**（現行のように各所で `not in ("admin","analyst")` を
書かない）。ロールを毎回 DB から引く現行挙動（S2-API-002）は**保存する** — 即時反映はトークン再発行を待たずに
権限剥奪できる運用上の利点である。
