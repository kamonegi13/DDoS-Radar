# S1 — センサー挙動仕様その 1: BaseSensor 契約 + Cyber 7 基 + Physical 15 基

**スコープ**: センサー基底の外形契約（health 状態機械 / confidence / cache / fetch ログ / CB）と、Cyber 7 基・Physical 15 基の外部ソース・取得プロトコル・周期と適応則・出力 cache 構造・状態判定式・ベースライン数式・degraded モード。

**隣接仕様との境界**: 採点側から見た CB 契約は [S1-scoring-core.md](S1-scoring-core.md) `S1-SCORE-038` が正本（本書はセンサー側視点で補完し重複しない）。センサー出力 → RationaleEntry → ドメインスコアの変換は S1-scoring-core /
S1-scoring-pipeline 担当（本書は**抑制系 3 基の消費側意味論のみ**を、出力の意味を確定させるため記述）。Information 6 基・LLM インテル 6 基・メタセンサー 3 基は S1-sensors-info-llm 担当。`intel_queue.submit()`
後のキュー状態機械・auto_confirm・dedup・decay は S1-intel 担当（本書は apt_intel が**何を投入するか**まで）。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。**一次ソースについて**: センサー層は 39 基中 26 基が無テスト（D5 §4.2）。本書の根拠は**大半がコード読解のみ**である。
`未検証` 条項は v3 のパリティ比較基準に使えない — S5 のテスト新規作成対象になる。

## 1. 用語

CLAUDE.md の用語定義に従う。本書固有:
- **sensor_id**: cache 参照キー・fetch ログキー・UI 表示名を兼ねる単一識別子
- **tier**: 取得対象決定規則。`GLOBAL` / `FOCUSED_ONLY` / `BACKGROUND_ELIGIBLE`
- **context**: スケジューラがセンサーへ渡す取得対象記述。**現行の語彙は旧用語 `theater` のまま**（C-01）
- **cache**: `set_cache()` で書き `get_cache()` で読む単一 dict。センサーの唯一の正規出力面
- **suppressor（抑制系）**: 自らは加点せず他信号の `is_suppressed` を立てるためだけに存在するセンサー
- **health**: `OK` / `DEGRADED` / `STALE` / `ERROR` / `CIRCUIT_OPEN` / `INITIALIZING` / `DISABLED`

## 2. 挙動条項 — BaseSensor 契約

### S1-SENSBASE-001: センサーは (sensor_id, domain, poll_interval, tier, enabled) で同定される
**挙動**: 生成時に `sensor_id`（一意）・`domain`（cyber / physical / info）・`poll_interval`（秒）を確定 **MUST**。 `tier` 既定 `GLOBAL`。`enabled` 既定 True で実行時に切替可能 **MUST**。
**根拠**: radar/sensors/base.py:22-38、radar/scenarios.py:64-79 **検証**: tests/test_engine.py::TestIhrSensor::test_init / ::TestRipeAtlasSensor::test_init（identity のみ） **分類**: CORE

### S1-SENSBASE-002: 具象センサーが実装するのは fetch(context) → dict のみ
**挙動**: 必須実装は `fetch(context) -> dict` 1 つ **MUST**。基底が提供する health / confidence / CB / fetch ログ / 設定シリアライズは**オーバーライド不可の共通挙動 MUST**（現行 34
基でオーバーライドゼロ）。`context` は少なくとも `strategic_theaters`（focused シナリオ participant の ISO2 和集合、ソート済）・`adversary_states`・`all_targets`（両者の和）・ `all_participant_countries`（全
scorable シナリオの和）・`cf_headers`・`owm_api_key`・`weather_conditions`・ `gdelt_tone_threshold`・`gdelt_history_window`・`_registry` を含む **MUST**。
シナリオストア未ロード時は国リストが**空配列**で渡され、センサーは空でクラッシュしない **MUST**。
**根拠**: base.py:39-40、radar/scheduler.py:19-106 **検証**: 未検証 **分類**: CORE

### S1-SENSBASE-003: cache は排他制御下でコピー授受する
**挙動**: `get_cache()` は内部 dict の**浅いコピーを返す MUST**。`set_cache(data)` は内部 dict を置換し書込時刻を記録 **MUST**。両者は同一ロックで保護 **MUST**。
**根拠**: base.py:41-45 **検証**: tests/test_engine.py::TestRipeAtlasSensor::test_cache_roundtrip / ::TestIhrSensor::test_country_status_logic **分類**: CORE

### S1-SENSBASE-004: set_cache / set_error は fetch ログへ自動追記する
**挙動**: `set_cache()` は直近ログが `log_fetch()` 由来でない場合に限り成功エントリを 1 件追記 **MUST**。追記の `records` は **data の値のうち list または dict であるものの len の総和
MUST**（スカラーは数えない）。`set_error(e)` は同条件で失敗エントリ（records=0）を追記し、エラー文字列を**先頭 300 文字に切り詰める MUST**。fetch ログは**直近 10 件のリングバッファ MUST**。
**根拠**: base.py:43-57 **検証**: 未検証 **分類**: CORE。records 算出規則（ネスト非考慮）は §6-A6

### S1-SENSBASE-005: log_fetch は fetch ログと health の同期点である
**挙動**: `log_fetch(success, duration_ms, http_status, records, error)` は **MUST**: 失敗 → 最終エラーを `error` （空なら `"fetch_failed"`）に設定 / **部分成功（success かつ error 非空）→ `"PARTIAL: " +
error[:280]`** / 完全成功 → 最終エラーを空にクリア。同内容を永続ログへ side-write **MUST**、**永続化失敗はセンサーを壊してはならない MUST NOT**。
**根拠**: base.py:58-74 **検証**: 未検証 **分類**: CORE（`PARTIAL:` 接頭辞が DEGRADED health の唯一の入口 — S1-SENSBASE-007 と対）

### S1-SENSBASE-006: fetch ログの二重記録回避は暗黙フラグの協調に依存する
**挙動**（現行の記録）: `log_fetch()` が書いたエントリだけに内部フラグが立ち、`set_cache()` / `set_error()` は**直近 1 件のフラグのみ**を見て自動追記を抑止する。`log_fetch()` → `set_cache()` なら 1 件、逆順なら 2
件記録される。呼び順は仕様化されていない。
**v3 規範**: 取得結果の記録は**単一の入口を持つ MUST**。呼び順依存の暗黙協調を持ってはならない **MUST NOT**。
**根拠**: base.py:43-61 **検証**: 未検証 **分類**: **DEFECT-PRESERVE**（D2 A-15）

### S1-SENSBASE-007: health は 7 状態の優先順位付き判定である
**挙動**: 以下の順に評価し最初に成立した値を返す **MUST**: (1) `enabled == False` → `DISABLED` / (2) CB が OPEN → `CIRCUIT_OPEN` / (3) 最終エラーが `"PARTIAL:"` 始まり → `DEGRADED` / (4) 最終エラー非空 →
`ERROR` / (5) cache 経過 > `poll_interval × 3` かつ cache 非空 → `STALE` / (6) 同・cache 空 → `INITIALIZING` / (7) → `OK`。 **CB OPEN は他の全条件に優先 MUST**。HALF_OPEN は health に現れない **MUST**。
**閾値**: STALE 判定 = `poll_interval × 3`（ハードコード、config キー無し）
**根拠**: base.py:134-148 **検証**: tests/test_engine.py::TestCircuitBreaker::test_health_returns_circuit_open / test_health_ok_after_recovery **分類**: CORE

### S1-SENSBASE-008: confidence は health × sample × baseline の 3 因子の積
**挙動**: `compute_confidence(sample_count, baseline_samples)` は **MUST**（N = `CONFIDENCE_MIN_SAMPLES`）:
```
health_f = {OK:1.0, DEGRADED:0.8, STALE:0.5, ERROR:0.0, CIRCUIT_OPEN:0.0, INITIALIZING:0.1, DISABLED:0.0}[health]
if health_f == 0.0: return 0.0                                   # 早期リターン（他因子を見ない）
sample_f   = 0.3 + 0.7 × (sample_count / N)     if N > 0 and sample_count < N     else 1.0
baseline_f = 0.5 + 0.5 × (baseline_samples / N) if 0 < baseline_samples < N       else 1.0
return round(min(health_f × sample_f × baseline_f, 1.0), 3)
```
**`baseline_samples == 0` は無罰（baseline_f = 1.0）MUST** — 「ベースライン皆無」が「十分」と同値になる。
**閾値**: `CONFIDENCE_MIN_SAMPLES` 既定 **10**（config.py:455、env 可）
**根拠**: base.py:149-171 **検証**: tests/test_engine.py::TestCircuitBreaker::test_confidence_zero_when_circuit_open のみ **分類**: CORE。**baseline 0 の無罰分岐は ACCIDENTAL**（§6-A5）

### S1-SENSBASE-009: サーキットブレーカーの状態遷移（センサー側）
**挙動**: 状態機械・閾値・遅延倍化は `S1-SCORE-038` が正本（`CB_FAILURE_THRESHOLD`=5 / `CB_INITIAL_DELAY`=300s / `CB_MAX_DELAY`=3600s、いずれもクラス定数でハードコード）。センサー側の追加規範: 状態は CLOSED /
OPEN / HALF_OPEN の 3 値 **MUST**。`cb_should_skip()` は **OPEN → HALF_OPEN 遷移を副作用として起こす MUST** ため **1 サイクルに厳密に 1 回だけ呼ばれる MUST**（複数回で probe 予算が壊れる）。成功記録は状態を
CLOSED、失敗カウンタ 0、回復遅延を `CB_INITIAL_DELAY` へ**戻す MUST**。CB 状態はプロセス内メモリのみで、**再起動で CLOSED にリセットされる**。
**根拠**: base.py:16-19, 78-132 **検証**: tests/test_engine.py::TestCircuitBreaker::（14 件全て） **分類**: CORE（NP3 の中核）。再起動リセットは §6-A7

### S1-SENSBASE-010: CB を駆動するのはセンサーではなくスケジューラである
**挙動**: センサーは `fetch()` 内で CB を参照してはならない **MUST NOT**。駆動は外部ループ **MUST**: `cb_should_skip()` →（skip でなければ）`fetch()` → **fetch ログ末尾の成功可否**で成功／失敗を記録。fetch
が例外を投げた場合も失敗として記録 **MUST**。帰結として **fetch ログに何も書かないセンサーは常に失敗と判定される**。
**根拠**: radar/scheduler.py:101-145 **検証**: 未検証 **分類**: CORE

### S1-SENSBASE-011: スケジューラのセンサーループ規則
**挙動**: 各センサーは専用ワーカーで駆動 **MUST**。(a) `enabled == False` のセンサーは fetch せず**60 秒間隔で再有効化を待ち続ける MUST**（スレッドは終了しない）。(b) 起動時はスタッガ遅延後に初回 fetch
**MUST**（既定 `2.0 + index × 1.5` 秒、 **OpenSky 共有 3 基は固定**: opensky=0 / isr_hotspot=120 / mil_support_air=240 秒）。(c) 初回失敗時は **[60, 300, 600] 秒間隔で最大 3 回リトライ MUST**。(d) 以後
`poll_interval` 秒間隔で反復 **MUST**、 **poll_interval はセンサーが実行時に書き換えてよい**（適応周期）。(e) health 変化で通知イベント発行 **MUST**。 (f) 回復遅延 > `CB_INITIAL_DELAY` の状態では**1
回だけ**永続 CIRCUIT_OPEN 警告を出す **MUST**。
**根拠**: scheduler.py:77-160、radar/__init__.py:299-306 **検証**: 未検証 **分類**: CORE

### S1-SENSBASE-012: tier は取得対象の決定規則である
**挙動**: `FOCUSED_ONLY` は `context.strategic_theaters` **のみ**を対象にする **MUST**。`GLOBAL` は国を絞らない（または全 `COUNTRY_COORDS`）。`BACKGROUND_ELIGIBLE` は background
シナリオも走査対象に含む。FOCUSED_ONLY 名簿は **クラス宣言とは別に定数集合としても保持され、起動時アサーションで整合を検証する MUST**。現行 FOCUSED_ONLY 12 基: cloudflare_radar, ioda_bgp, ripe_bgp,
openweather, check_host, opensky, notam, ripe_atlas, ais_maritime, isr_hotspot, nasa_firms, mil_support_air。
**根拠**: radar/scenarios.py:64-79 **検証**: tests/test_sensor_tier_exposure.py（tier 露出のみ） **分類**: CORE。名簿の二重管理は §6-A8

### S1-SENSBASE-013: レート制限ヘルパーと安全 HTTP ヘルパーは提供されるが使われていない
**挙動**（現行の記録）: 基底は (a) 429 を検出し `Retry-After` をログして cache 有無に応じた fetch ログを書くレート制限ハンドラ、 (b) 既定 timeout `(connect=10, read=20)` を注入し 429 を自動処理する GET/POST
ラッパを提供する。**(b) の呼び出しはコードベース全体でゼロ**であり、全 28 の fetch 実装が生の HTTP 呼び出しを行う。timeout は 5〜45 秒でばらつく。
**v3 規範**: 外部取得は**共有 ingestion 層を経由する MUST**。timeout 未指定の外部呼び出しを許してはならない **MUST NOT**。
**根拠**: base.py:173-225 vs 全センサー fetch **検証**: 未検証 **分類**: **DEFECT-PRESERVE**（D2 A-10）

### S1-SENSBASE-014: fetch 失敗時の cache 保持規約が統一されていない
**挙動**（現行の記録）: 3 系統が併存する。(1) **前回 cache を返し cache を更新しない**（opensky / isr_hotspot / mil_support_air / ripe_atlas / ihr / ioda / usgs_seismic / gps_jamming / notam / nasa_firms / ooni /
ct_log / threatfox(401)）、 (2) **空または部分結果で cache を上書きする**（cloudflare / ripe_bgp / greynoise / peeringdb / openweather / check_host / ais_maritime / space_weather）、(3)
**上書きしたうえで前回値を per-country にマージ**（ripe_bgp・openweather の 429 分岐、peeringdb の例外分岐）。系統 2 は**上流障害時に cache が空になり、health は OK/DEGRADED のまま
消費側には「信号なし」に見える**。
**v3 規範**: 取得失敗は cache を破壊してはならない **MUST NOT**。「最後に成功した観測」と「その鮮度」を分離保持し、消費側が鮮度で判断できる **MUST**。
**根拠**: 各センサー fetch 末尾分岐（§3/§4 の根拠欄） **検証**: 未検証 **分類**: **DEFECT-PRESERVE**（NP1 直撃: 障害時の沈黙が「平穏」と区別できない）

### S1-SENSBASE-015: 設定シリアライズの出力形状
**挙動**: 管理面向けに `name` / `domain` / `enabled` / `health` / `poll_interval_sec` / `last_error` / `cache_age_sec`（未取得なら null）/ `last_fetch_ts`（同）/ `cb_state` / `cb_fail_count` / `tier` を出力
**MUST**。
**根拠**: base.py:227-243 **検証**: tests/test_engine.py::TestCircuitBreaker::test_to_config_dict_includes_cb_fields **分類**: CORE（S2 API 契約と相互参照）

## 3. 挙動条項 — Cyber ドメイン 7 基

### S1-SENS-001: cloudflare_radar — L3/L7 攻撃対象と BGP イベントの取得
**挙動**: id=`cloudflare_radar` / cyber / poll 900s / FOCUSED_ONLY。CF Radar API v4 の 4 エンドポイント（L3 攻撃対象上位・ L7 攻撃対象上位・BGP hijack・BGP leak）を取得 **MUST**。攻撃データの `dateRange` は
`CURRENT_DATE_RANGE`、BGP は `"1d"` 固定。 **L3 が 200 のときのみ L7 と BGP を続行 MUST**。**BGP 取得の失敗は非致命 MUST**（空リストで継続）。 cache: `{active, date_range, l3_targets[], l7_targets[],
bgp_hijacks[], bgp_leaks[]}`。エラー時は `{active, date_range}` のみで **上書きする**（S1-SENSBASE-014 系統 2）。本センサーは状態フラグを持たない **MUST**（spike / vector shift 判定は採点層）。
**閾値**: `CURRENT_DATE_RANGE` 既定 `"1d"`（config.py:147、env 可）、HTTP timeout 10s
**根拠**: radar/sensors/cloudflare.py:26-64 **検証**: 未検証（tests/test_engine.py::TestCfBgpHijackScoring はインライン再実装で本番未実行） **分類**: CORE

### S1-SENS-002: cloudflare_radar の BGP イベントは hijack のみ confidence 50 でフィルタする
**挙動**: hijack は `confidence >= 50` のみ採用 **MUST**、`{type:"hijack", confidence, prefix, victim_asn, hijacker_asn, victim_country, hijacker_country, is_ongoing, duration}` に正規化
**MUST**。国コードは**大文字化 MUST**。 leak は**confidence フィルタを適用せず全件採用 MUST**、`{type:"leak", leak_asn, leak_country, leaked_prefix_count, origin_asn, peer_count}` に正規化 **MUST**。
**閾値**: BGP イベント最小 confidence = **50**（cloudflare.py:21、ハードコード）
**根拠**: cloudflare.py:66-125 **検証**: 未検証 **分類**: CORE。hijack / leak の非対称は §6-A9

### S1-SENS-003: cloudflare_radar は cache 以外に採点層の共有 dict へ side-write する
**挙動**（現行の記録）: L3/L7 の生データを `set_cache()` とは別に**採点層と共有するモジュールレベル dict** へ `(URL, params)` をキーとして書き込む。採点層は同じ dict を読み、TTL 超過を掃除し上限 1000
件で打ち切る。センサー → 採点層の経路が cache 面の外に 1 本存在する。
**v3 規範**: センサーの出力面は cache **のみ MUST**。層をまたぐ共有可変状態を持ってはならない **MUST NOT**。
**根拠**: cloudflare.py:16, 44-46 / radar/scoring.py:24, 641-656 / radar/scheduler.py:165 **検証**: 未検証 **分類**: **DEFECT-PRESERVE**（D2 B-04 の系）

### S1-SENS-004: ripe_bgp — 国別ルーティング統計の取得
**挙動**: id=`ripe_bgp` / cyber / poll 1800s / FOCUSED_ONLY。`strategic_theaters` の各国について RIPE Stat の国別ルーティング統計を取得 **MUST**。**2 件目以降の前に 0.3 秒の courtesy delay MUST**、HTTP timeout
12s。 **429 では当該国のみ前回値を流用し、ループを打ち切らず次国へ進む MUST**（前回値が無ければ `{status:"RATE_LIMITED", is_anomaly:False}`）。cache: `{routing_stats: {国: {announced_prefixes,
baseline_prefixes, seen_ases, drop_pct, is_anomaly, status, hod_z, hod_n, prefix_trend, prefix_trend_pct, ases_trend, trend_entries, trend_label}}}`。統計が空なら `{status:"NO_DATA", is_anomaly:False}`
を**成功として計上 MUST**、非 200/例外は `{status:"ERROR", …}`。
**根拠**: radar/sensors/bgp_routing.py:26-101 **検証**: 未検証 **分類**: CORE

### S1-SENS-005: ripe_bgp の異常判定は HOD Z-score、不足時のみ drop_ratio へ縮退
**挙動**: 国ごとに **UTC 時間バケット（3600 秒粒度）につき 1 件**、announced_prefixes を永続ベースラインへ記録 **MUST** （同一バケットの二重記録を禁止 **MUST NOT**）。同時刻帯（バケット ÷ 3600 mod
24）の過去サンプル数 n に対し **MUST**:
```
n >= HOD_MIN_SAME_HOUR:  m = mean(samples); s = max(population_stddev(samples), 1.0)   # 分母フロア 1.0
                         z = (prefixes_now − m) / s;  is_anomaly = (z < −2.0)          # 減少方向のみ
n <  HOD_MIN_SAME_HOUR:  is_anomaly = (drop_ratio > BGP_DROP_THRESHOLD)                # 縮退経路
```
`hod_z` は n 不足時 **null MUST**、`hod_n` は常に出力 **MUST**。
**閾値**: `HOD_MIN_SAME_HOUR` = **7**（config.py:337）、`HOD_MAX_ENTRIES` = `HOD_BASELINE_DAYS × 24` = **672**（同 338）、 Z 異常判定 **−2.0**、標準偏差フロア 1.0（いずれもハードコード）
**根拠**: bgp_routing.py:62-78、config.py:337-338 **検証**: 未検証（一般式のみ tests/test_engine.py::TestHodZscore が採点層側で pin） **分類**: CORE

### S1-SENS-006: ripe_bgp の drop_ratio ベースラインは揮発する
**挙動**（現行の記録）: drop_ratio の基準値（prefix / ASN 数）は**プロセス内メモリのみ**に保持され、**1 時間経過で現在値へ更新**される。更新は drop_ratio
計算の**前**に行う（時間リセット直後の初回読取が古い基準を使わないため）。 `drop_ratio = max(0, (base − now) / base)`（base が 0 なら 0.0）。**再起動でこの基準は失われ、再起動直後の 1 サイクルは drop_ratio
が必ず 0 になる**。HOD ベースラインは永続だが n < 7 の間は本経路が使われる。
**v3 規範**: 検知に用いるベースラインは**永続必須 MUST**。プロセス寿命に依存する検知力を持ってはならない **MUST NOT**。
**閾値**: `BGP_DROP_THRESHOLD` = **0.15**（bgp_routing.py:22）、基準更新間隔 3600s
**根拠**: bgp_routing.py:27, 52-59 **検証**: 未検証 **分類**: **DEFECT-PRESERVE**（D2 A-03）

### S1-SENS-007: ripe_bgp のトレンドは統計配列全体の最小二乗傾き
**挙動**: エントリが **3 件未満なら `trend_label = "INSUFFICIENT_DATA"`、全傾き 0.0 MUST**。3 件以上では announced_prefixes と seen_ases それぞれの**逐次インデックスに対する最小二乗傾き**を算出 **MUST**（分母
`n·Σx² − (Σx)²` が 0 なら 0.0）。`prefix_trend_pct = slope / max(mean(prefixes), 1.0) × 100`（小数 4 桁丸め）**MUST**。ラベルは `< −0.5% → WITHDRAWING` / `> +0.5% → GROWING` / 他 `STABLE` **MUST**。
**根拠**: bgp_routing.py:103-158 **検証**: tests/test_engine.py::TestBgpTrend::（5 件、採点層側の同型実装を pin） **分類**: CORE。**同一の傾き計算が engine.py / scoring.py / bgp_routing.py の 3
箇所に存在**（S1-SCORE の DP1 と同根）

### S1-SENS-008: greynoise — ノイズ比の取得と二層動作
**挙動**: id=`greynoise` / cyber / poll 1800s / GLOBAL。API キーがある場合のみ国ごとに GNQL 統計（`metadata.destination_country:<CC>`、count=500）を取得 **MUST**、**2 件目以降に 0.5s delay MUST**、timeout
10s。 GNQL が非 200（401=Community キー / 410=v2 廃止(2026) / 403・429=tier/レート制限）を返したら**恒久的に GNQL 不可フラグを立て以後リクエストしない MUST**、警告は**初回 1 回のみ
MUST**。**この状態は正常動作であり fetch 成功として扱う MUST** （恒常 DEGRADED を作らない）。API キー無し・GNQL 不可・対象国ゼロも成功 **MUST**。 cache: `{greynoise: {国: {noise_ratio, noise_class,
suppress_confidence, total_ips, malicious_ips, api_key_configured, gnql_tier, status}}}`。`gnql_tier` ∈ `community_limited` / `enterprise` / `none`。
**根拠**: radar/sensors/greynoise.py:155-259 **検証**: tests/test_greynoise_gnql.py::test_non_200_gnql_degrades_to_unknown_success_true / ::test_gnql_unavailable_warned_once / ::test_no_key_is_success_unknown
**分類**: CORE（NP3 の良実装例）

### S1-SENS-009: greynoise のノイズ分類は固定 2 閾値
**挙動**: `noise_ratio = benign 分類の IP 数 / 全分類 IP 数`（総数 0 なら 0.0、小数 3 桁丸め）**MUST**。 **クエリに `classification:malicious` フィルタを掛けてはならない MUST NOT**（benign が除外され ratio
が常に 0 になる）。分類は `> 0.70 → NOISE_DOMINANT` / `> 0.40 → MIXED` / 他 `TARGETED` **MUST**。取得不能時は `noise_class="UNKNOWN"` かつ `suppress_confidence=False`
**MUST**（**取得不能を抑制根拠にしてはならない MUST NOT**）。 `suppress_confidence` が真になるのは NOISE_DOMINANT のときのみ **MUST**。
**根拠**: greynoise.py:163, 233-240 **検証**: 未検証 **分類**: CORE

### S1-SENS-010: greynoise の消費側意味論 — スコアを持たない抑制専用センサー
**挙動**: greynoise の観測は**常に score 0 で採点入力へ渡る MUST**（加点しない）。`suppress_confidence` が真なら当該観測の status を `SUPPRESSED` とし抑制理由文を付す
**MUST**。抑制対象は**自らのエントリのみ**で、他センサーの cyber 信号は抑制しない。
**根拠**: radar/routes/core.py:1379-1390 **検証**: 未検証 **分類**: CORE。抑制範囲の設計意図は §6-A10

### S1-SENS-011: greynoise の単発 IP 照会は日次 50 件で自前レート制限する
**挙動**: 個別 IP 照会（Community API）は **MUST**: IPv4 書式検証 → API キー必須 → **日次カウンタは UTC 日付変更でリセット**、上限到達でエラー返却 → **24h TTL
のプロセス内キャッシュをヒットさせる**（カウンタを消費しない）。404 は「未観測」として正常結果 **MUST**。429・非 200・例外では**消費したカウントを 1 戻す MUST**。キャッシュが 200 件超で TTL 超過分を掃除
**MUST**。
**閾値**: 日次上限 **50 req/day**、IP cache TTL **86400s**、掃除トリガ 200 件、timeout 8s（すべてハードコード）
**根拠**: greynoise.py:32-35, 52-153 **検証**: 未検証 **分類**: CORE（定期 fetch ではなく on-demand 経路）

### S1-SENS-012: ooni_censorship — 検閲測定の集計と判定式
**挙動**: id=`ooni_censorship` / cyber / poll 1800s（適応、S1-SENS-013）/ GLOBAL。対象は `strategic_theaters ∪ adversary_states`、**両方空なら `COUNTRY_COORDS` 先頭 10 件へフォールバック MUST**。過去 7 日の
web_connectivity 集計を国ごとに取得 **MUST**（timeout 20s、成功時 0.5s delay）。**429 ではループを打ち切る MUST**。 4xx/5xx/JSON エラーは当該国をスキップして継続 **MUST**（0.5s 待機）。判定 **MUST**:
```
anomaly_rate   = anomaly_count / max(total_measurements, 1)     # total 0 なら 0
confirmed_rate = confirmed_count / max(total_measurements, 1)
anomaly_surge  = (anomaly_count > prev × 1.5) if prev > 10 else False
is_censoring   = (confirmed_rate > 0.05) or (anomaly_rate > 0.20) or anomaly_surge
is_heavy       = (confirmed_rate > 0.15) or (anomaly_rate > 0.40)
status = HEAVY_CENSORSHIP if is_heavy else CENSORSHIP_DETECTED if is_censoring else NORMAL
```
`prev` は **anomaly_count > 0 のときのみ更新 MUST**。cache: `{censorship_data: {国: {total_measurements, anomaly_count, confirmed_count, failure_count, anomaly_rate, confirmed_rate, anomaly_surge, is_censoring,
is_heavy, daily_anomaly_rates(直近7)}}, country_status}`。**1 国も成功しなければ cache を更新せず前回値（無ければ全 NORMAL）を返す MUST**。
**根拠**: radar/sensors/ooni.py:60-237 **検証**: 未検証（判定式そのもの） **分類**: CORE。`prev` がプロセス内揮発である点は **DEFECT-PRESERVE**（D2 A-03）

### S1-SENS-013: ooni_censorship の自己回復 degraded モード
**挙動**: 1 サイクルで**全対象国が失敗**した場合を失敗サイクルと数える **MUST**。**連続 3 失敗で degraded へ遷移 MUST**。 degraded 中は (a) `poll_interval` を **7200s へ書き換える MUST**、(b) **対象を先頭 1
国のみに絞る MUST**（回復検知 probe）、 (c) 国ごとのエラーログを **DEBUG へ降格 MUST**。1 国でも成功したら**即座に healthy へ戻し poll_interval を 1800s に復帰、失敗カウンタを 0 に MUST**。診断用に `{status,
consecutive_failures, last_success_ts, current_interval_sec, success_count, failure_modes:{timeout, conn_error, http_5xx, http_4xx, json_error}}` を公開 **MUST**。
**閾値**: 通常 1800s / degraded 7200s / 遷移閾値 3 サイクル（すべてクラス定数、config キー無し）
**根拠**: ooni.py:38-40, 60-76, 201-252 **検証**: tests/test_ooni_degraded.py::（8 件全て） **分類**: CORE（NP3 の中核実装。他センサーが倣うべき先例）

### S1-SENS-014: threatfox — IoC 取得と国名タグ照合
**挙動**: id=`threatfox` / cyber / poll 3600s / GLOBAL。`get_iocs`（直近 1 日）を POST で取得 **MUST**（timeout 15s）。 **API キー未設定なら HTTP を発行せず、空 hits で成功として記録し cache を書く MUST**（401
由来の恒常 ERROR を作らない）。キーがあれば `Auth-Key` ヘッダを付与 **MUST**。**ブラウザ User-Agent（Chrome 120 相当）を送出 MUST**（abuse.ch のボット遮断回避）。国ごとの hit 数は「IoC の tags に `"apt"`
を含む**または**対象国の英語国名を含む」件数 **MUST**（小文字化比較）。 **0 件の国は hits に含めない MUST**。cache: `{hits: {国: {count, description}}}`。`query_status` が `ok` / `no_result` 以外なら失敗記録
**MUST**。**401 では cache を保持したまま前回値を返す MUST**。
**閾値**: 取得期間 1 日。config キー `THREATFOX_API_KEY`（env、既定空）
**根拠**: radar/sensors/threatfox.py:14-84 **検証**: 未検証 **分類**: CORE。APT タグと国名タグの等価計上は §6-A11

### S1-SENS-015: ct_log — 多重ソースのフォールバック鎖と「200-empty は権威ある成功」
**挙動**: id=`ct_log` / cyber / poll 3600s（適応）/ GLOBAL。監視対象は国ごとのドメイン台帳（現行 27 国 238 ドメイン）。国ごとに**ラウンドロビンで最大 `CT_LOG_MAX_QUERIES_PER_THEATER`
ドメイン**を選び、カーソルを `(cursor + budget) mod n` で進める **MUST**。取得は pull ソースを**宣言順（CertSpotter → crt.sh）に試し、最初に `None` 以外を返したソースで打ち切る MUST**。ソース契約 **MUST**:
戻り値 `list`（空でも可）= 転送成功 / `None` = 硬故障。**HTTP 200 + 空配列は「証明書が見つからなかった」という権威ある成功であり、次ソースへフォールバックしてはならない MUST NOT**。空配列でも生存扱いとし、
**初回接触時にウォームアップ基準時刻を永続化 MUST**（かつて「データが取れた時のみ」だったため、CertSpotter の初回応答が 24h 窓で全件除外され基準が永久に立たない不具合があった）。ドメイン間に
`CT_LOG_INTER_QUERY_SLEEP_SEC` 待機 **MUST**。
**閾値**: `CT_LOG_MAX_QUERIES_PER_THEATER` 既定 **2**、`CT_LOG_INTER_QUERY_SLEEP_SEC` 既定 **4.0s**、 `CT_LOG_OBSERVATION_WINDOW_HOURS` 既定 **24**、`CT_LOG_BUFFER_MAX_OBS` 既定 **5000**（すべて env）
**根拠**: radar/sensors/ct_log.py:366-382, 431-473 / ct_log_sources/base.py:93-101 / config.py:501-533 **検証**: tests/test_ct_log_redesign.py::test_round_robin_*（3 件）；test_ct_log_certspotter.py（21
件、HTTP mock） **分類**: CORE（多重ソース戦略は移植すべき知識資産）

### S1-SENS-016: ct_log の障害応答 — ソース parking と degraded 周期
**挙動**: **ソース parking MUST**: 連続失敗が **5 回**に達した pull ソースを **1800 秒**「死亡」としてマークし、その間の取得要求は即 `None` を返す。**ただし他に healthy なソースが 1 つも無ければ parking
を行ってはならない MUST NOT** （全滅時に全ソースを止めない）。復帰は**時間経過による暗黙復帰**で、次の成功時にのみ healthy に戻す **MUST**。 **degraded 周期 MUST**: 1 サイクルで pull
を試みたが**どのソースからも実応答が無い**場合を失敗サイクルとし、 **連続 3 回で `poll_interval` を `CT_LOG_DEGRADED_INTERVAL_SEC` に切替え、かつ国ごとの対象ドメインを 1 件に絞る MUST**。実応答が 1
件でもあれば**即座に 3600s へ復帰し失敗カウンタを 0 に MUST**。 push ソース（certstream）は parking の対象外 **MUST**、その生存はバッファ鮮度が `CT_LOG_CERTSTREAM_LIVENESS_SEC` 以内かで判定
**MUST**。全滅サイクルでは **cache を更新せず**前回値（無ければ全 NORMAL）を返す **MUST**。
**閾値**: parking 閾値 5 / cooldown 1800s / degraded 遷移 3 サイクル（すべてハードコード）、 `CT_LOG_DEGRADED_INTERVAL_SEC` 既定 **14400s**、`CT_LOG_CERTSTREAM_LIVENESS_SEC` 既定 **900s**
**根拠**: ct_log.py:123-134, 415-416, 475-485, 590-668 **検証**: 未検証（parking / degraded 切替とも） **分類**: CORE。**OONI（S1-SENS-013）と同型の自己回復を別実装で解いている**点は §9-5

### S1-SENS-017: ct_log の certstream WebSocket（既定無効）
**挙動**: `CT_LOG_CERTSTREAM_ENABLED` が真かつ監視ドメイン集合が非空のときのみ push ソースを起動 **MUST**（既定は **false**）。規範 **MUST**: (a) **RFC 6455 ping を使わない**（gevent 下で機能しないため
ping_interval / ping_timeout 既定 0）。代わりに**アプリ層ハートビート監視スレッド**が 5 秒間隔で確認し、最終メッセージから `heartbeat_budget_sec` 秒（既定 120s ≈ 上流 30s 周期の 4
倍）無音なら接続を閉じる。(b) 再接続は**指数バックオフ 1s から `reconnect_max_sec` 上限まで倍化**（1,2,4,8,16,32,60,60…）。**再接続回数の上限は存在せず、停止要求まで無限に試行する**。「予算切れ」は health
表現のみ: 連続失敗 **6 回以上 → dead** / 生存線超過または連続失敗 1 以上 → degraded / メッセージ受信済 → healthy / 他 unknown。(c) 照合は**粗フィルタ（監視 apex の下位 2 ラベル集合）→ 厳密照合（apex
完全一致または `"." + apex` 終端、先頭 `*.` は除去）の 2 段 MUST**。1 メッセージにつき**一致 apex ごとに観測 1 件 MUST**。
**閾値**: `CT_LOG_CERTSTREAM_ENABLED` 既定 **false**、liveness 900s（下限 60s にクランプ）、 heartbeat budget 120s（下限 30s）、reconnect max 60s（下限 1s）、dead 判定 6 連続失敗
**根拠**: ct_log.py:184-239 / ct_log_sources/certstream.py:87-128, 157-231, 412-525 / config.py:557-575 **検証**: tests/test_ct_log_certstream.py::（28 件、純関数パイプラインを網羅） **分類**: CORE

### S1-SENS-018: ct_log の trust-class 評価（ADR-024）と出力
**挙動**: ドメインごとに観測を**最大 200 件**、`not_before` が観測窓内のもののみ評価 **MUST**。判定順 **MUST**: 1. **ワイルドカード検知**（trust class と直交、常に先に評価）: `common_name` と SAN の各名が `*.`
で始まり、除去後の残りが **政府 TLD 集合（23 件: `gov`, `mil`, `gov.tw`, `go.jp`, `gov.ru`, `gov.cn` …）の完全一致メンバ**のときのみ発火 **MUST**。 `*.api.mofa.gov.tw`
のような下位名前空間は**発火させてはならない MUST NOT** 2. 発行者を正規化: DN をカンマ分割し **`O=` → `CN=` → 生文字列**の順にフォールバック（引用符除去、小文字化）**MUST**。正規化結果が `"unknown"`
の観測は各ソースで**破棄 MUST** 3. **グローバル信頼 CA（44 件の部分文字列台帳、敵対国 CA は意図的に不在）に一致**、または当該ドメインの既知 CA 台帳に存在 → 台帳を更新して**発火させない MUST NOT** 4.
**ウォームアップ中**（初回観測から `CT_LOG_WARMUP_DAYS` 未満）→ 台帳に記録し**発火を抑止 MUST** 5. 上記いずれでもなければ untrusted 事象として計上し、台帳へ記録し、**同一サイクル内の再発火を防ぐため
メモリ上の既知 CA 集合にも追加 MUST**

出力 cache: `{ct_data: {国: {total_recent, gov_count(**常に 0** — 廃止済フィールド), wildcard_count, is_surge, recent_certs(最大5), untrusted_ca_count, untrusted_ca_events(最大10), wildcard_tld_detected,
wildcard_tld_events(最大5), watched_domains, observed_domains, warmup_active, scoring_model:"adr_024_signal_redesign"}}, country_status}`。 **`is_surge = (untrusted_ca_count > 0) or (wildcard_count > 0)` —
数値閾値も config キーも存在しない MUST**。 `country_status` は `UNTRUSTED_CA_DETECTED` > `WILDCARD_TLD_DETECTED` > `WARMUP`（ウォームアップ中かつ観測 0）> `NORMAL` の優先順 **MUST**。
永続するのは**ドメイン別既知 CA 台帳と初回観測時刻の 2 表のみ MUST**（観測バッファ・異常カウンタ・ラウンドロビンカーソルは揮発）。
**閾値**: `CT_LOG_WARMUP_DAYS` 既定 **14 日**、観測窓 24h、ドメイン別観測上限 200 件、信頼 CA 台帳 44 件、政府 TLD 23 件
**根拠**: ct_log.py:78-91, 242-363, 511-566 / ct_log_sources/issuer_parse.py:17-48 / config.py:501, 593-606 **検証**: tests/test_ct_log_redesign.py::（issuer 解析 4 件・信頼判定 2 件・ウォームアップ/発火 6
件・ワイルドカード 2 件） **分類**: CORE。`gov_count` が常に 0 の死んだフィールドを出力し続ける点は §6-A18

### S1-SENS-019: apt_intel — 政府 CERT の RSS 取得（strict パーサのみ）
**挙動**: id=`apt_intel` / cyber / poll 3600s（env `APT_INTEL_POLL_INTERVAL`、**import 時に 1 回だけ読む**）/ GLOBAL。フィードは 5 件 **MUST**: CISA 勧告 / CISA アラート / JPCERT / NCSC-UK /
CERT-Bund。各フィードは `url` / `authority` / `region`（**読み出されない死にメタデータ**）/ `theater_hints` を持つ。**死んだフィードは残さず削除する方針 MUST** （2026-04 監査で ENISA=RSS 廃止 / BSI=WID へ移転 /
ACSC=非 AU IP を geo-block を削除、CISA は `/cybersecurity-advisories/` へ移転、JPCERT の英語 RSS は廃止）。取得は**生の HTTP GET**（基底ヘルパー不使用、timeout **15 秒スカラー**）で、**ブラウザ
User-Agent（Chrome 121 相当）を送出 MUST**（CISA が Akamai 経由でスクリプト UA を 403 にするため）。**フィード間の courtesy delay は無い**。非 200 も例外も空文字を返して次フィードへ進む **MUST**（非致命）。
パースは **strict XML パーサのみ MUST**（**tolerant フォールバックもフィード死活診断も持たない** — diplomatic 系のみが保有）。したがって**死んだ URL の HTML ページと本当に空のフィードが同じログ行に潰れる**。
記事は RSS 1.0 名前空間を含む `item` のみ走査（**Atom `entry` は走査されず 0 件になる**）、日付解析失敗の記事は**保持 MUST**。
**閾値**: 記事の齢窓 **168 時間**（docstring の「72h」は誤り）、timeout 15s
**根拠**: radar/sensors/apt_intel.py:53-100, 182-308 **検証**: 未検証 **分類**: **DEFECT-PRESERVE**（D2 A-02: RSS 耐性のドリフト。同じ壊れ方でセンサーごとに結果が違う）

### S1-SENS-020: apt_intel の記事選別と dedup
**挙動**: フィードごとに順に **MUST**: (1) タイトル正規化キー（小文字先頭 60 文字の英数のみ）で**フィード内 dedup**、 (2) 宣伝文句の**強制破棄**（`"we blocked"` / `"case study"` / `"webinar"` / `"free
download"` 等 14 語。 **単語 `"download"` 単独は CISA の "Download PDF" を誤爆するため意図的に多語句にしてある**）、 (3) タイトル接頭辞 `"weekly report"` の破棄（JPCERT 週報）、(4)
**キーワード事前フィルタで最大 5 件** （勧告語・脆弱性語・日本語 3 語・ドイツ語 4 語・国家アクター名 23 種・重要セクタ語・事前配置 TTP 語。 **`"blocked"` / `"prevented"` / `"stopped"` は意図的に除外**）、(5)
対象国名のみ一致で**追加 2 件**。 → **フィードあたり最大 7 件、1 サイクル最大 35 件 MUST**。 **サイクル間 dedup MUST**: キーは `md5("cert-" + source_name + title[:60])`。**プロセス内メモリのみ（永続しない）**、
上限 1000 件で古い 500 件を落とす。**キー登録は LLM 呼び出しの前に行われるため、LLM 失敗で記事が恒久的に消費される**。
**根拠**: apt_intel.py:104-175, 259-306, 363-370 **検証**: 未検証 **分類**: CORE。dedup 集合の揮発は **DEFECT-PRESERVE**（D2 B-05: 再起動直後の重複投入）

### S1-SENS-021: apt_intel の LLM 二段ゲートと intel 投入内容
**挙動**: LLM 無効／不達なら `{apt_intel: {llm_disabled|llm_offline: True}}` を返し**cache を書かない MUST**。 **Stage 1（トリアージ、max_tokens 200）MUST**:
`is_strategically_relevant`（国家アクターによる能動的悪用／事前配置／諜報／サプライチェーン／持続的偵察／破壊能力開発のいずれか。アクター帰属も標的文脈も無い単なる CVE 公開は false）と
`has_geographic_target`（特定国・既知の国家支援 APT 名・特定重要セクタのいずれかを名指し）を判定し、 **Stage 2 は両方が真のときのみ実行 MUST**。Stage 1 は**本文を再送しないための要約も同時に返す
MUST**（トークン節約）。 **Stage 2（構造化抽出、max_tokens 280）MUST**: `headline` / `theater`（対象外なら null）/ `countries` / `country_weights` / `attributed_actor` / `actor_nexus` / `targeted_sector` /
`ttp_category` / `urgency` / `confidence`。 **投入前の硬ゲート MUST**: theater が空／`"NULL"`／`"NONE"` なら破棄、`strategic_theaters` が非空でそこに含まれなければ破棄、 **confidence < 0.35 なら破棄**（この値は
config の同名既定を**読まずに複製したリテラル**であり drift しうる）。投入 item: `source_type="apt_intel"` / `source_id="cert_" + フィード名小文字` / `theater` / `countries`（**theater を先頭に必ず含める
MUST**）/ `country_weights`（[0,1] にクランプ、既定 1.0）/ `ts`（**投入時刻。記事の発行時刻ではない**）/ `confidence` / `raw_text`（**未サニタイズの原文 1000 文字**）/ `raw_url` / `headline` / `llm_fields` /
`domain="cyber"` / `score_delta = ttp_base + urgency_bonus`（sabotage 2.5 / active-exploitation 2.0 / pre-positioning 2.0 / disruption 1.5 / espionage 1.5 / financial 1.0 / unknown 1.0、+ critical 0.5 / high
0.2 / 他 0.0。上限 3.0）。 cache: `{apt_intel: {submitted: int}}` **のみ MUST**。**status フラグも直接スコアも持たない MUST NOT** （`score_delta` はキュー確定後に初めて効く payload である）。
**閾値**: max_tokens 200 / 280、confidence 下限 **0.35**（リテラル）、score_delta 上限 3.0
**根拠**: apt_intel.py:311-330, 378-446, 461-505, 511-608 **検証**: 未検証（tests/test_apt_prompt_dedup.py は D5 で STRUCTURAL 判定 = トークン最適化の実装詳細） **分類**: CORE。confidence 下限のリテラル複製は
§6-A19

## 4. 挙動条項 — Physical ドメイン 15 基

### S1-SENS-022: opensky_auth — OAuth2 と 3 センサー共有レートリミッタ
**挙動**: OpenSky を叩く 3 基（opensky / isr_hotspot / mil_support_air）は**単一の共有機構を経由する MUST**: (a) OAuth2 client_credentials でトークンを取得し**失効 300 秒前に自動更新 MUST**（`expires_in`
未提供時は 1800s とみなす）。クレデンシャル未設定なら空トークン（**匿名 = 400 req/day**）で継続 **MUST**。 (b) 全リクエストを共有ロックで直列化し、**直前から `OPENSKY_MIN_INTERVAL` 秒未満なら差分だけ待つ
MUST**。 (c) 429 では `X-Rate-Limit-Retry-After-Seconds`（既定 60）を読み、**120 秒以下のときのみ待って 1 回だけ再試行 MUST**。超える値は匿名 quota 超過とみなし**429 のまま呼び出し側へ返す MUST**（待たない）。
(d) 429 のスリープは**ロックの外で行う MUST**（他センサーを長時間ブロックしない）。
**閾値**: `OPENSKY_MIN_INTERVAL` 既定 **10s**（config.py:470、env + DB 可）、先行更新 300s、リトライ上限 120s、timeout 12s
**根拠**: radar/sensors/opensky_auth.py:14-89 **検証**: 未検証 **分類**: CORE（module-level 共有状態だが共有 API に対する設計として妥当）

### S1-SENS-023: opensky — 主要空港上空の機数
**挙動**: id=`opensky` / physical / poll 1800s / FOCUSED_ONLY。対象国の代表空港座標を中心に **±0.5° の矩形**で状態ベクタを取得 **MUST**。cache: `{airports: {国: {airport, count, lat, lng, error}}}`。
**取得失敗の国は `count = −1` と error を記録 MUST**（0 と区別する）。**1 国も成功しなければ cache を更新せず前回値を返す MUST**。本センサーは状態フラグを持たない **MUST**（surge 判定は採点層）。
**根拠**: radar/sensors/opensky.py:11-42 **検証**: 未検証 **分類**: CORE

### S1-SENS-024: isr_hotspot — ISR 機体の識別と surge 判定
**挙動**: id=`isr_hotspot` / physical / poll 1800s / FOCUSED_ONLY。設定済み ISR ホットスポットのうち**所属 theater が focused 対象に含まれるものだけ**を、中心から **±1.8°（≈200km）の矩形**で走査
**MUST**。地上機は除外 **MUST**。 ISR 判定は次の **OR MUST**: (1) `気圧高度 > 9000m` **かつ** `速度 < 160 m/s` / (2) `squawk == "7777"`（軍・政府コード）/ (3) コールサインが既知 ISR 接頭辞（NATO/西側 10・露空軍
3・中国 PLAAF 2・ベラルーシ 1）で始まる。欠損値の既定は**高度 0 / 地上 True / 速度 999** **MUST**（欠損機は条件 1 を満たさない）。 cache: `{isr_data: {theater: {count, hotspots:[{name, lat, lng, isr_count,
tracks(最大5)}], is_surge}}}`。同一 theater の複数ホットスポットは count を積み上げる **MUST**。`is_surge = count >= ISR_SURGE_THRESHOLD` **MUST**。
**閾値**: 半径 1.8°、高度 9000m、速度 160 m/s、`ISR_SURGE_THRESHOLD` 既定 **3**（env、**fetch のたびに読み直す**）
**根拠**: radar/sensors/isr_hotspot.py:16-113 **検証**: 未検証 **分類**: CORE

### S1-SENS-025: mil_support_air — 支援機の 3 分類と surge 判定
**挙動**: id=`mil_support_air` / physical / poll 1800s / FOCUSED_ONLY。走査範囲は S1-SENS-024 と同一。地上機は除外 **MUST**。コールサイン接頭辞で `TANKER` / `TRANSPORT` / `AWACS` に分類 **MUST**。**照合順序は
TANKER → TRANSPORT → AWACS の固定順で、最初に一致した分類を採る MUST**（多重一致しない）。判定 **MUST**: `is_tanker_surge = tanker >= 2` / `is_transport_surge = transport >= 3` / `is_awacs_active = awacs >= 1`
/ `is_surge = いずれかの OR`。cache: `{mil_air_data: {theater: {tanker, transport, awacs, total, hotspots, 上記 4 フラグ}}}`。
**閾値**: tanker 2 / transport 3 / awacs 1（すべてハードコード、config キー無し）
**根拠**: radar/sensors/mil_support_air.py:24-182 **検証**: 未検証 **分類**: CORE。接頭辞に `NAF`/`RAF`/`GAF`/`SAM`/`CARGO` 等の汎用語を含む点は §6-A12

### S1-SENS-026: ais_maritime — チョークポイント近傍の 2 異常
**挙動**: id=`ais_maritime` / physical / poll 1800s / FOCUSED_ONLY。チョークポイントごとに **±0.5° の矩形**で AIS 船舶を取得 **MUST**、**2 件目以降の前に 2 秒待つ MUST**、timeout 15s。**上流が HTTP 200 + 空
body を返した場合はレート制限であり、エラーではなく「データ無し」として次へ進む MUST**（AISHub guest API はエラーコードを返さない）。非 JSON・要素 2 未満の配列も同様にスキップ **MUST**。判定 **MUST**:
```
AIS dark gap : 前回観測からの経過 > AIS_DARK_GAP_THRESHOLD かつ CP 距離 < AIS_ANCHOR_RADIUS_KM
停泊異常     : 船種 ∈ {35,36,37}（軍用）または 60–89（商用）の範囲外
               かつ速度 < 0.5kt かつ CP 距離 < AIS_ANCHOR_RADIUS_KM
```
距離は Haversine（地球半径 6371km）**MUST**。船舶履歴はプロセス内に保持し、**24 時間より古いものを毎サイクル削除 MUST**、 **5000 件超で古い順に削る MUST**。cache: `{dark_gaps[], stationary_anomalies[],
has_anomaly}`。 fetch 成功判定は「1 CP でも成功」**または**「エラーが 1 件も無い」**MUST**（全件レート制限を成功扱いにする）。
**閾値**: `AIS_DARK_GAP_THRESHOLD` 既定 **3600s**、`AIS_ANCHOR_RADIUS_KM` 既定 **50km**（ともに env + DB 可）、停泊速度 0.5kt、矩形半幅 0.5°、delay 2s、履歴 24h / 5000 件
**根拠**: radar/sensors/ais_maritime.py:22-165、config.py:367-368, 1115-1128 **検証**: 未検証 **分類**: CORE。船舶履歴の揮発は **DEFECT-PRESERVE**（D2 A-03: 再起動で dark gap 検知が全滅する）

### S1-SENS-027: gps_jamming — 日次 H3 タイルからの妨害率算出
**挙動**: id=`gps_jamming` / physical / poll 1800s / GLOBAL。対象は `strategic_theaters ∪ adversary_states` （空なら `COUNTRY_COORDS` 先頭 10 件）。取得は 2 段 **MUST**: (1) manifest
から**利用可能な最新日付**を取得（**当日分は存在しない前提 = 日次ラグ**）、(2) その日付の H3 解像度 4 タイル CSV を**全世界分 1 リクエストで**取得。 **前回処理日と同一なら CSV を取得せず cache を返す
MUST**。manifest が 429／非 200 なら**前回の日付を流用 MUST**。国ごとに中心から**緯度・経度とも ±3.0°**（経度差 180° 超は 360 − diff に折り返す **MUST**）のタイルを集計 **MUST**:
```
jam_ratio = Σbad / (Σgood + Σbad)                    # 機体 0 なら 0.0
jammed_tiles = |{tile : bad/(good+bad) >= GPS_JAM_THRESHOLD}| ;  max_ratio = max(同上の比)  # 無ければ 0.0
surge = jam_ratio > prev × 1.5  (prev > 0 のときのみ, else False)   # prev は jam_ratio > 0 のときのみ更新
is_jammed   = (jammed_tiles >= 3) or (max_ratio >= GPS_JAM_CRITICAL_THRESHOLD) or (jam_ratio >= GPS_JAM_THRESHOLD)
is_critical = max_ratio >= GPS_JAM_CRITICAL_THRESHOLD
status = CRITICAL_JAMMING if is_critical else JAMMING_DETECTED if is_jammed else NORMAL
```
座標未知の国は `NO_DATA` **MUST**。cache: `{jamming_data: {国: {total_tiles, jammed_tiles, total_aircraft, bad_aircraft, max_level, avg_level, prev_avg, surge, is_jammed, is_critical, date}}, country_status}`。
**閾値**: `GPS_JAM_THRESHOLD` 既定 **"3.0"**、`GPS_JAM_CRITICAL_THRESHOLD` 既定 **"7.0"**（env、fetch ごとに読み直す）、探索半径 3.0°、H3 解像度 4、タイル数閾値 3、surge 倍率 1.5、timeout 15s / 30s
**根拠**: radar/sensors/gps_jamming.py:31-244 **検証**: 未検証 **分類**: **DEFECT-PRESERVE（新規発見）** — **閾値の単位が壊れている**。`jam_ratio` / `max_ratio` / タイル別比はすべて **0–1
の比率**だが既定閾値は **3.0 / 7.0**（百分率想定の値）。したがって既定設定では `max_ratio >= 7.0` も `jam_ratio >= 3.0` も `bad/(good+bad) >= 3.0` も**恒久的に成立せず**、 `jammed_tiles` は常に 0 なので
`jammed_tiles >= 3` も成立しない → **`is_jammed` / `is_critical` は常に False、本センサーは 1 件も発火しない**。v3 規範: 閾値は値域の単位で定義し型で表現する **MUST**

### S1-SENS-028: notam — 無効化中（無料の国際 NOTAM API が存在しない）
**挙動**（現行の記録）: id=`notam` / physical / poll 1800s / FOCUSED_ONLY。**生成時に `enabled = False` を設定するためスケジューラは fetch を一切行わない**（60 秒ループで再有効化を待ち続ける）。health は常に
`DISABLED`、confidence は 0.0。無効化理由: FAA の NOTAM 検索は米国のみ、ICAO API は無料枠 100 コールで実用にならない。物理ドメインは gps_jamming / isr_hotspot / mil_support_air が代替する。 **保存すべき知識**:
FAA notamSearch への POST ペイロード形式（度分秒 3 分割、`radius=100`、`notamType="N"`、 `pageSize=50`）と、境界矩形が無い国に中心 ±3.0° 矩形を使うフォールバック。判定式は `is_surge = (total >=
NOTAM_SURGE_THRESHOLD) or (military >= 3) or (surge_pct > 0.5 and total > 5)`、 `surge_pct = (total − prev) / max(prev, 1)`、状態は `NOTAM_SURGE` / `ELEVATED`（軍事 or TFR ≥ 1）/ `NORMAL`。
**閾値**: `NOTAM_SURGE_THRESHOLD` 既定 **20**、`NOTAM_MILITARY_KEYWORDS`（ともに env 可）、軍事件数 3、 surge_pct 0.5 + 最小 6 件、timeout (10, 45)、国間 1.0s
**根拠**: radar/sensors/notam.py:42-200、config.py:474-475 **検証**: 未検証 **分類**: CORE（無効化は意図的判断）。無効化センサーの座席は §6-A13

### S1-SENS-029: nasa_firms — 実データソースは EONET（命名が誤誘導）
**挙動**: id=`nasa_firms` / physical / poll 3600s / FOCUSED_ONLY。**実際に取得するのは NASA EONET events API （`category=wildfires`, `status=open`, `days=1`）であり NASA FIRMS ではない**（FIRMS
サーバ到達不能のため切替、 EONET はプロキシ環境で到達確認済）。timeout 15s。 **イベント集合が前回と同一なら（件数 + 先頭 10 件 ID の指紋一致）空間走査をスキップして cache を返す MUST**。
探索半径は**国別テーブル優先、無ければ既定 3.0° MUST**（小国 TW/IL/KR/KW/LB/GE/EE/LV/LT = 2.0°、JP/UA/PH = 3.0°）。 **EONET の座標は [経度, 緯度] の順である MUST**。1 イベントが 1
国に複数ジオメトリで一致しても**1 件だけ登録 MUST**。 cache: `{anomalies: [{lat, lng, code, confidence:"HIGH", title}]}`。**confidence は常に文字列 `"HIGH"` 固定 MUST** （実際の信頼度ではない）。
**根拠**: radar/sensors/nasa_firms.py:11-109 **検証**: 未検証 **分類**: **DEFECT-PRESERVE**（D2 C-07）— sensor_id が一次ソースを誤示し、NP6 でソースを追うアナリストを誤誘導する。 v3 規範: sensor_id
は**実データソースを反映する MUST**

### S1-SENS-030: openweather — 作戦気象コンテキスト
**挙動**: id=`openweather` / physical / poll 1800s / FOCUSED_ONLY。**`strategic_theaters` のみ**を対象にする **MUST** （全対象国は API quota を消費し過ぎる）。**API
キー未設定ならエラーを記録して即座に空結果を返し cache を書かない MUST**。 timeout 5s。**429 では当該国の前回値を流用して継続 MUST**（ループを打ち切らない）。判定 **MUST**: `is_severe = (weather_id ∈
SEVERE_WEATHER_IDS) or (wind > 25)` / `is_moderate = (500 <= id < 600) or (300 <= id < 400) or (wind > 15)` / `severity = SEVERE|MODERATE|NORMAL`。 cache: `{conditions: {国: {weather_id, condition, description,
wind_speed, temp_c, is_severe, is_moderate, severity, lat, lng}}}`。
**閾値**: 風速 severe 25 / moderate 15 m/s、`SEVERE_WEATHER_IDS`（config.py:340）、既定 weather_id 800
**根拠**: radar/sensors/openweather.py:11-44 **検証**: 未検証 **分類**: CORE（抑制系。消費は S1-SENS-034 参照）

### S1-SENS-031: usgs_seismic — 海底ケーブル近接と核実験候補の 2 系統
**挙動**: id=`usgs_seismic` / physical / poll 900s / GLOBAL。過去 24 時間・`USGS_MIN_MAGNITUDE` 以上の地震を最大 100 件取得 **MUST**（timeout 20s）。**イベント集合が前回と同一なら（先頭 20 件 ID
の指紋一致）近接走査をスキップ MUST**。 2 系統の判定 **MUST**: **ケーブル脅威** = いずれかのチョークポイントから `USGS_CABLE_RADIUS_KM` 以内（1 件一致で打ち切り）。 **核実験候補** = `mag >= 4.0` かつ `depth <
10km` かつ**敵対国領内**（敵対国中心座標から緯度・経度とも ±5.0° の粗矩形）。 `suppress_physical = has_cable_threat and not has_nuclear_candidate` **MUST**。距離は Haversine（6371km、atan2 形式）**MUST**。
cache: `{seismic: {earthquakes(先頭20), near_cable(先頭10), nuclear_candidates(全件), total_events, has_cable_threat, has_nuclear_candidate, suppress_physical}}`。
**閾値**: `USGS_MIN_MAGNITUDE` 既定 **"4.0"**（env、fetch ごと）、核候補 mag 4.0 / 深さ 10km / 領内 ±5.0°、 `USGS_CABLE_RADIUS_KM` 既定 **200km**（env 可）、取得上限 100 件 / 24h
**根拠**: radar/sensors/usgs_seismic.py:45-182 **検証**: 未検証 **分類**: CORE（CTBTO 風の検知基準は移植資産）

### S1-SENS-032: usgs_seismic の消費側意味論 — 抑制と加点が同一センサーに同居する
**挙動**: 消費側の解釈 **MUST**: (a) `has_nuclear_candidate` 真 → status `FIRED`、**score 3**、理由文に候補数を含む / (b) そうでなく `has_cable_threat` 真 → status `SUPPRESSED`、score
0、**抑制理由に該当チョークポイント名を含む MUST**、適用済ノイズフィルタ一覧へ追記 **MUST** / (c) 他 → `OK`、score 0。 **核実験候補が 1 件でもあればケーブル抑制は効かない MUST**（抑制より検知が優先）。
**根拠**: radar/routes/core.py:1721-1745 **検証**: 未検証 **分類**: CORE（NP1 に沿った優先順位）。層の分離は §6-A14

### S1-SENS-033: space_weather — Kp と X 線フラックスの取得
**挙動**: id=`space_weather` / physical / poll 1800s / GLOBAL。NOAA SWPC の 2 エンドポイント（惑星 Kp 予報 / GOES X 線 6 時間）を**並列に取得 MUST**（各 timeout 15s）。いずれかが失敗しても既定値（Kp=0.0 /
flux=0.0, class="A"）で継続 **MUST**。`kp_index` は observed 行の**最終値**、`kp_forecast_24h` は**全行の最大値** **MUST**。 X 線クラスは flux から `>=1e-4 X` / `>=1e-5 M` / `>=1e-6 C` / `>=1e-7 B` / 他 `A`
**MUST**。嵐レベルは `max(kp_index, kp_forecast_24h)` に対し `>=9 EXTREME / >=8 SEVERE / >=7 STRONG / >=6 MODERATE / >=5 MINOR / 他 NONE` **MUST**。 cache: `{space_weather: {kp_index, kp_forecast_24h,
xray_class, xray_flux, storm_level, suppress_physical, suppress_reason}}`。 **本センサーは常に fetch 成功として記録する MUST**（両エンドポイント全滅でも既定値で成功）。
**根拠**: radar/sensors/space_weather.py:25-148 **検証**: 未検証 **分類**: CORE。全滅時も成功記録する点は §6-A15

### S1-SENS-034: space_weather の抑制判定と消費側意味論
**挙動**: 抑制判定 **MUST**: `kp_triggers = kp_index >= SPACE_WEATHER_KP_SUPPRESS_THRESHOLD`（**予報値ではなく観測値のみ**）、 `xray_triggers = order(xray_class) >=
order(SPACE_WEATHER_XRAY_SUPPRESS_CLASS)`（order = A:0, B:1, C:2, M:3, X:4）、 `suppress_physical = kp_triggers or xray_triggers`。抑制時は**トリガした指標と閾値を含む人間可読の理由文を生成 MUST**。消費側
**MUST**: (a) space_weather 自身のエントリは **score 0**、抑制時 status `SUPPRESSED` / (b) 抑制は**他の physical センサーへ伝播する MUST**。ただし**「そのセンサーが発火している場合のみ」抑制する**: BGP =
`sw_suppress and core_degraded and not 気象抑制`、空域 = `sw_suppress and airspace_fired and not 気象抑制`、 check_host = `sw_suppress and ch_fired`、ihr = `sw_suppress`（**無条件**）/ (c)
**気象（openweather）抑制が既に効いている場合、宇宙天気抑制は上書きしない MUST**（理由文の一貫性）。
**閾値**: `SPACE_WEATHER_KP_SUPPRESS_THRESHOLD` 既定 **6**、`SPACE_WEATHER_XRAY_SUPPRESS_CLASS` 既定 **"M"**（ともに env 可）
**根拠**: space_weather.py:112-141、config.py:377-378、radar/routes/core.py:1085, 1108-1111, 1368-1375, 1488-1543 **検証**: 未検証 **分類**: CORE（D1 §4 が「層分離の正しい先例」と評価:
センサーはフラグを出すだけ、適用は採点層）。 ihr のみ無条件である非対称は §6-A16

### S1-SENS-035: peeringdb_ixp — IXP 台帳の低頻度取得と 24h 国別キャッシュ
**挙動**: id=`peeringdb_ixp` / physical / poll 14400s / GLOBAL。国ごとに IXP 一覧を取得 **MUST**（timeout 10s）。 **国別に 24h TTL のプロセス内カウントを持ち、TTL 内かつ前回 cache の件数が一致するなら API
を叩かず再利用 MUST**。 API を叩く場合**2 件目以降の前に 10 秒待つ MUST**。**429 では 20 秒待って 1 回だけ再試行 MUST**、再試行後も 429 なら **前回 cache の当該国データを流用 MUST**（件数 > 0
のときのみ、無ければ `{ixps:[], count:0, error:"rate_limited"}`）。例外時も前回値を優先 **MUST**。cache: `{ixp_data: {国: {ixps:[{id, name, city, country, lat, lng, status, aka}], count}}}`。
**閾値**: 国別 TTL **86400s**、国間 delay 10s、429 待機 20s（すべてハードコード）
**根拠**: radar/sensors/peeringdb.py:13-110 **検証**: 未検証 **分類**: CORE

### S1-SENS-036: ihr_health — 無効化中（上流 API 契約変更による慢性 400）
**挙動**（現行の記録）: id=`ihr_health` / physical / poll 300s / GLOBAL。**生成時に `enabled = False`**。理由: 3 エンドポイント（disco / hegemony / network_delay）すべてが 2026-Q1 以降**慢性 HTTP 400**（上流の API
契約変更にクエリ形式が追従できていない）。加えて信号が IODA + ripe_bgp と冗長（3 者とも `signal_source="bgp"` を共有し MAX で dedup される、S1-SCORE-008）。 **保存すべき知識**: 正規ホストは
`www.ihr.live`（`ihr.iijlab.net` は 301 するため、プロキシ環境の二重ホップを避け直接叩く）。 3 エンドポイントは**並列取得 MUST**（直列 3×30s を ~30s に短縮）。判定は「disco → hegemony → delay」の優先順で
最初に該当したものを国状態にする（`DISCO_EVENT` / `HEGEMONY_ALARM` / `DELAY_ANOMALY` / `NORMAL`）。 cache: `{disconnections, hegemony_alarms, delay_alarms, country_status}`。**1
エンドポイントでも成功なら部分成功 MUST**。
**閾値**: 取得窓直近 2 時間、timeout 30s、並列度 3
**根拠**: radar/sensors/ihr.py:28-194 **検証**: tests/test_engine.py::TestIhrSensor::（3 件、identity と cache のみ） **分類**: CORE（無効化は意図的判断）

### S1-SENS-037: ioda_bgp — 二重ソースの障害検知と回復の反映
**挙動**: id=`ioda_bgp` / physical / poll 300s / FOCUSED_ONLY。**2 段のフォールバック MUST**: (1) IODA v2 の国別アラート（直近 2 時間、上限 200 件、timeout 20s）、(2) IODA 到達不能なら CF Radar の
traffic_anomalies（`dateRange="1d"`、timeout 15s）。 **429 では前回 cache があればそれを返し、無ければフォールバックへ進む MUST**。IODA 応答の解釈 **MUST**: (a) **国 × データソース（`bgp` / `merit-nt` /
`ping-slash24`）の組ごとに最新時刻のアラートのみを残す** — これにより **`level="normal"` による回復が正しく反映される**（古い critical が残らない）/ (b) 国の `max_level` は `critical` > `warning` > `normal`
の優先順 / (c) `max_level ∈ {warning, critical}` の国だけ `BGP_OUTAGE`、他は `NORMAL`。 cache（IODA 経路）: `{statuses, ioda_details: {国: {level, sources, source_count}}, source:"ioda_proper"}`。 CF 経路:
`{statuses, source:"cf_fallback"}`。両方失敗時は `{statuses: 全 NORMAL, source:"cache_or_default"}`。
**閾値**: 遡及窓 7200s、上限 200 件、採用レベル {warning, critical}
**根拠**: radar/sensors/ioda.py:25-189 **検証**: 未検証（tests/test_engine.py::TestDdosBgpCausality はインライン再実装で本番未実行） **分類**: CORE。domain が `physical` でありながらネットワーク観測である点は
§6-A17

### S1-SENS-038: check_host — 二段 API による到達性測定
**挙動**: id=`check_host` / physical / poll `CHECKHOST_POLL_INTERVAL` / FOCUSED_ONLY。国ごとに**最大 3 URL** を **最大 5 ノード**から測定 **MUST**。取得は 2 段 **MUST**: (1) チェック要求 → `request_id`（timeout
15s）、 (2) **5 秒待機**して結果取得（timeout 12s）。**URL ごとに 300 秒のクールダウン MUST** — クールダウン内なら前回 cache の当該 URL 結果を再利用し、**その再利用も fetch 成功・レコード数に計上する
MUST**（計上しないと全 URL がクールダウンの回で「成功 0 件」の偽の失敗ログになる。実測で fetch ログ行の約 53% がこれに該当していた）。結果配列 `[ok_flag, time_seconds, status_msg, http_code_str, ip]` の解釈
**MUST**:
- **`null`（ノード単位・個別チェック単位のいずれも）は「保留中」であり分母に数えてはならない MUST NOT**（希釈を招く）
- 成功条件は `ok_flag == 1` **かつ**（HTTP コード取得不能、または `< 400`）
- `success_rate = ok / all`、**ただし応答ノードが 2 未満なら null MUST**（単一ノードは根拠として不十分）
- **レイテンシによる success_rate への減点を行ってはならない MUST NOT** — 大陸間チェックは正常時も 3000ms を超える。
遅延は `node_ok` の `TIMEOUT` ラベルと窒息検知でのみ表現する
- URL 単位 status: `>= 0.8 OK` / `>= 0.3 PARTIAL` / 他 `BLACKOUT`
**閾値**: `CHECKHOST_POLL_INTERVAL` 既定 **600s**、`CHECKHOST_NODES` 既定 jp1/us1/de1/nl1/fr1、 `CHECKHOST_TIMEOUT_MS` 既定 **3000**（すべて env）、URL クールダウン 300s、URL 上限 3、ノード上限 5、結果待機
5s、最小応答ノード 2
**根拠**: radar/sensors/checkhost.py:15-170, 197-236 **検証**: 未検証 **分類**: CORE（「200-empty は成功」「保留は分母外」「遅延は減点しない」の 3 知識は再発見コストが高い）

### S1-SENS-039: check_host の窒息（CDN マスク）検知
**挙動**: URL ごとに**直近 12 件のレイテンシ履歴**を保持 **MUST**。**移動平均は現在サンプルを追記する前に計算 MUST** （スパイクが自らの基準を汚さない）。履歴が **3 件未満なら移動平均を null とし判定しない
MUST**。 `asphyxiation = (success_rate >= 0.99) and (avg_latency > rolling_avg × 3.0)` **MUST**。意味: 「成功率は 100% に見えるがレイテンシが 3 倍化した」= CDN が背後の障害を隠している疑い。履歴は URL
単位のクラス変数で、**24 時間更新の無い URL エントリを毎サイクル削除 MUST**。
**閾値**: 履歴長 12（≈1h @5min）、最小サンプル 3、成功率下限 0.99、倍率 3.0（すべてハードコード）
**根拠**: checkhost.py:32-36, 138-156, 180-185 **検証**: 未検証 **分類**: CORE。レイテンシ履歴の揮発は **DEFECT-PRESERVE**（D2 A-03）

### S1-SENS-040: check_host の国別 status は HOD 正規化、不足時のみ固定閾値
**挙動**: `theater_success_rate = ok_url_count / valid_url_count`（有効 URL 0 件なら **null**）**MUST**。 null のときの status は `UNKNOWN` **MUST**（`BLACKOUT` ではない — API 到達不能と対象ダウンを区別する）。
非 null なら **UTC 時間バケットごとに 1 件を永続ベースラインへ記録 MUST**（二重記録禁止）。同時刻帯サンプル数 n に対し **MUST**:
```
n >= HOD_MIN_SAME_HOUR:  m = mean; s = max(population_stddev, 0.05)      # 分母フロア 0.05（成功率スケール）
                         z = (rate − m) / s
                         BLACKOUT if z < −3.0 and rate < 0.3 ; PARTIAL if z < −2.0 and rate < 0.8 ; else OK
n <  HOD_MIN_SAME_HOUR:  OK if rate >= 0.8 else PARTIAL if rate >= 0.3 else BLACKOUT      # ウォームアップ
```
**HOD 正規化の目的は深夜 UTC 保守帯による定常的低下を PARTIAL と誤判定しないこと MUST**。 cache: `{check_host: {国: {urls: {URL: {…}}, theater_success_rate, status, asphyxiation}}}`。
**根拠**: checkhost.py:241-276、config.py:337-338 **検証**: 未検証 **分類**: CORE。HOD Z ブロックが ripe_bgp とほぼ同一実装（テーブル名と分母フロアのみ差異）である点は **DEFECT-PRESERVE**（D2 A-02）

### S1-SENS-041: ripe_atlas — プローブ可用性と公開測定 RTT
**挙動**: id=`ripe_atlas` / physical / poll 600s / FOCUSED_ONLY。対象は `strategic_theaters` （**空なら `COUNTRY_COORDS` 先頭 20 件へフォールバック MUST**）。2 系統を**それぞれ並列度 5 で並列実行 MUST**（各
timeout 10s）: (1) 国別アクティブプローブ数、(2) 常時稼働の公開測定 3 件（k-root=1001 / f-root=1004 / Google DNS=10509）× 国の最新 RTT。 RTT は各プローブの `avg` と各結果の `rt` の**両方を（正の値のみ）収集
MUST**。国ごとに昇順ソートし `avg_ms`、 `p95_ms`（インデックス `int(n × 0.95)` を上限 `n−1` でクリップ）、`probes_responding` を出力 **MUST**。判定 **MUST**: `drop_pct = (prev − active) / max(prev, 1)`（prev ==
0 なら 0.0）→ `>= 0.70 PROBE_BLACKOUT` / `>= 0.30 PROBE_DROP` / 他 `NORMAL`。 `prev` は **active > 0 のときのみ更新 MUST**。**初回は prev = active となり drop_pct = 0**。 cache: `{probe_counts: {国: {active,
prev, drop_pct}}, latency: {国: {avg_ms, p95_ms, probes_responding}}, country_status}`。
**閾値**: `PROBE_DROP_PCT` = **0.30**、`PROBE_BLACKOUT_PCT` = **0.70**（ハードコード）、並列度 5、測定 ID [1001, 1004, 10509]
**根拠**: radar/sensors/ripe_atlas.py:27-180 **検証**: tests/test_engine.py::TestRipeAtlasSensor::test_probe_drop_detection / test_probe_blackout_detection （**閾値定数は本番からインポートするが drop_pct
計算はテスト内で再実装**）／ ::test_init / ::test_cache_roundtrip **分類**: CORE。`prev` の揮発は **DEFECT-PRESERVE**（D2 A-03）

## 5. 閾値カタログ

| 閾値 | 値 | config キー | 上書き | 条項 |
|---|---|---|---|---|
| CB 失敗閾値 / 初期遅延 / 最大遅延、STALE 判定 | 5 / 300s / 3600s、`poll_interval × 3` | — | 不可 | SENSBASE-007/009 |
| confidence 最小サンプル数 | 10 | `CONFIDENCE_MIN_SAMPLES` | env | SENSBASE-008 |
| fetch ログ保持・エラー切詰、起動リトライ、OpenSky スタッガ | 10 件 / 300 文字、[60,300,600]s、0/120/240s | — | 不可 | SENSBASE-004/011 |
| CF BGP hijack 最小 confidence | 50 | — | 不可 | SENS-002 |
| CF 取得期間 | "1d" | `CURRENT_DATE_RANGE` | env | SENS-001 |
| HOD 最小同時刻サンプル / 最大保持 | 7 / 672 | — | 不可 | SENS-005 |
| ripe_bgp Z 異常 / drop 閾値 / トレンド閾値・最小エントリ | −2.0 / 0.15 / ±0.5%・3 | — | 不可 | SENS-005〜007 |
| greynoise ノイズ分類 / 日次上限 / IP cache TTL | 0.70・0.40 / 50 / 86400s | — | 不可 | SENS-009/011 |
| OONI 検閲 / 重度判定 | conf 0.05,anom 0.20 / conf 0.15,anom 0.40 | — | 不可 | SENS-012 |
| OONI degraded 遷移 / 間隔 | 3 サイクル / 7200s | — | 不可 | SENS-013 |
| ct_log 国別クエリ / ドメイン間待機 / 観測窓 / バッファ上限 | 2 / 4.0s / 24h / 5000 | `CT_LOG_MAX_QUERIES_PER_THEATER`, `..._INTER_QUERY_SLEEP_SEC`, `..._OBSERVATION_WINDOW_HOURS`, `..._BUFFER_MAX_OBS` | env | SENS-015 |
| ct_log parking / degraded 遷移・間隔 | 5 失敗,1800s / 3 サイクル,14400s | `CT_LOG_DEGRADED_INTERVAL_SEC` のみ | env | SENS-016 |
| certstream 有効化 / liveness / heartbeat | false / 900s / 120s | `CT_LOG_CERTSTREAM_*` | env | SENS-017 |
| ct_log ウォームアップ / 観測上限 | 14 日 / 200 件 | `CT_LOG_WARMUP_DAYS` | env | SENS-018 |
| apt_intel 記事齢窓 / 記事上限 / dedup 上限 / max_tokens | 168h / 7 件・フィード / 1000 件 / 200・280 | — | 不可 | SENS-019〜021 |
| apt_intel confidence 下限 | 0.35（**リテラル複製**） | （`LLM_CONFIDENCE_MIN` を読まない） | 不可 | SENS-021 |
| ISR 高度 / 速度 / surge | 9000m / 160 m/s / 3 | `ISR_SURGE_THRESHOLD` | env | SENS-024 |
| 支援機 surge | tanker 2 / transport 3 / awacs 1 | — | 不可 | SENS-025 |
| AIS dark gap / 停泊半径 / 速度 | 3600s / 50km / 0.5kt | `AIS_DARK_GAP_THRESHOLD`, `AIS_ANCHOR_RADIUS_KM` | env + DB | SENS-026 |
| GPS 妨害 / 危険閾値 | 3.0 / 7.0（**単位破綻**） | `GPS_JAM_THRESHOLD`, `GPS_JAM_CRITICAL_THRESHOLD` | env | SENS-027 |
| NOTAM surge / 軍事件数 | 20 / 3 | `NOTAM_SURGE_THRESHOLD` | env | SENS-028 |
| EONET 探索半径、気象 severe / moderate 風速 | 3.0°・2.0°（小国）、25 / 15 m/s | — | 不可 | SENS-029/030 |
| USGS 最小 mag / 核候補深さ / ケーブル半径 | 4.0 / 10km / 200km | `USGS_MIN_MAGNITUDE`, `USGS_CABLE_RADIUS_KM` | env | SENS-031 |
| 宇宙天気抑制 Kp / X 線クラス | 6 / M | `SPACE_WEATHER_KP_SUPPRESS_THRESHOLD`, `..._XRAY_SUPPRESS_CLASS` | env | SENS-034 |
| PeeringDB TTL / 待機 / 429 待機、check_host 窒息（履歴 / 成功率 / 倍率） | 86400s / 10s / 20s、12 / 0.99 / 3.0 | — | 不可 | SENS-035/039 |
| check_host ポーリング / ノード / TIMEOUT / クールダウン / 最小ノード | 600s / 5 / 3000ms / 300s / 2 | `CHECKHOST_POLL_INTERVAL`, `CHECKHOST_NODES`, `CHECKHOST_TIMEOUT_MS`（後 2 者は不可） | env | SENS-038 |
| check_host HOD Z（BLACKOUT / PARTIAL） | −3.0 / −2.0 | — | 不可 | SENS-040 |
| Atlas プローブ低下 / 遮断 | 0.30 / 0.70 | — | 不可 | SENS-041 |
| OpenSky 最小間隔 / 429 リトライ上限 | 10s / 120s | `OPENSKY_MIN_INTERVAL` | env + DB | SENS-022 |

**v3 への示唆**: 本書が確定した閾値 50 件超のうち **config キーを持つのは 22 件、DB 上書き可能なのは 3 件のみ**。残りはクラス定数・モジュール定数・関数内リテラルに散っている。NP6 の観点では
**結論に影響する全閾値は宣言的 registry 経由 MUST**（S1-SCORE の DP2 と同一の指摘）。

## 6. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A5 | `compute_confidence` の baseline 因子が `baseline_samples == 0` を無罰（1.0）とする。1 件だけあると 0.55 に下がるのに 0 件なら 1.0 | 「無い」と「十分」が同値。S1-SCORE の A2（空ドメイン confidence 1.0）と同型 |
| A6 | `set_cache` の自動 records 算出がトップレベル list/dict の len のみ。ネスト国別 dict では「国数」が記録される | records の意味がセンサーごとに変わる。AP3 健全性表示の解釈可能性 |
| A7 | CB 状態がプロセス内メモリのみで再起動で必ず CLOSED に戻る | 慢性障害センサーが再起動のたび 5 回の無駄な fetch を行う。永続化すべきか |
| A8 | FOCUSED_ONLY 名簿がクラス宣言と定数集合の二重管理（起動時 assert で整合検証） | assert は守るが単一情報源ではない。どちらを正とするか |
| A9 | CF BGP で hijack には confidence ≥ 50 があるが leak には無い | leak の信頼度が低くても全件通る。意図的な非対称か |
| A10 | greynoise が NOISE_DOMINANT でも抑制するのは自分のエントリのみ。他の cyber 信号は素通し | 「ノイズ支配的」の判定が実質何も抑制していない。抑制対象の設計意図 |
| A11 | threatfox が「APT タグ」と「対象国の英語国名タグ」を等価に数える | 国名タグは無関係文脈でも付く。閾値なしの単純合算でよいか |
| A12 | 支援機の接頭辞に `NAF`/`RAF`/`GAF`/`SAM`/`CARGO`/`HAWK` 等の汎用語 | 誤検知源。NP1 では許容とも読めるが surge 閾値が 2〜3 機と低く影響が大きい |
| A13 | 無効化センサー（notam / ihr_health）がレジストリに残り health=DISABLED / confidence=0.0 を出し続け、スレッドも 60 秒ループで常駐 | AP3 で「無効化」と「故障」が区別できているか。v3 で座席を残すか |
| A14 | usgs_seismic が「抑制（ケーブル近接）」と「加点（核実験候補）」を単一センサーで兼務 | 抑制系と検知系を層で分けるか。現行は消費側で分岐 |
| A15 | space_weather が両エンドポイント全滅でも fetch 成功として記録（既定値 Kp=0 / X 線 A で継続） | 上流障害時に health が OK のまま「静穏」と読める fail-open。S1-SCORE の A3 と同型 |
| A16 | 宇宙天気抑制が ihr のみ無条件、他 physical は「発火中のみ」抑制 | 非対称の理由が不明。ihr は無効化中で実害は無いが規則として不整合 |
| A17 | ioda_bgp が domain=`physical` だがネットワーク観測（ripe_bgp は cyber） | 同じ `signal_source="bgp"` の 2 基が別ドメインに属し収斂ドメイン数に影響する |
| A18 | ct_log が `gov_count` を**常に 0** で出力し続ける（廃止済み概念の死にフィールド） | 消費側が誤読する余地。v3 契約から落とすか |
| A19 | apt_intel の confidence 下限 0.35 が `LLM_CONFIDENCE_MIN` の既定値をリテラルで複製（読んでいない） | 設定変更が片方にしか効かない drift。config 参照に統一するか |

## 7. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | fetch ログの二重記録回避が暗黙フラグの呼び順協調に依存 | 記録の入口を単一化 **MUST**。呼び順依存を持たない **MUST NOT** | A-15 |
| DP2 | 基底の安全 HTTP / レート制限ヘルパーが全センサー未採用。timeout が 5〜45s でばらつき、指定漏れは gevent 閉塞リスク | 外部取得は共有 ingestion 層経由 **MUST**。timeout 未指定を許さない **MUST NOT** | A-10 |
| DP3 | ベースライン永続戦略の不統一。**揮発**: ripe_bgp drop 基準 / ooni 前回異常数 / ais 船舶履歴 / gps_jamming 前回妨害率 / check_host レイテンシ履歴 / ripe_atlas 前回プローブ数 / peeringdb 国別カウント / apt_intel dedup 集合 / ct_log 観測バッファ。**永続**: ripe_bgp HOD / check_host HOD / ct_log 既知 CA・初回観測 | 検知に用いるベースラインは永続必須 **MUST**。プロセス寿命に依存する検知力を持たない **MUST NOT** | A-03 |
| DP4 | HOD Z-score ブロックが ripe_bgp と check_host にほぼ同一実装で二重に存在（テーブル名と分母フロアのみ差異）。最小二乗傾きも 3 箇所に重複 | 単一実装 **MUST** | A-02 |
| DP5 | 取得失敗時の cache 保持規約が 3 系統に分裂（前回保持 / 空上書き / per-country マージ） | 失敗は cache を破壊しない **MUST**。観測と鮮度を分離保持 **MUST** | — |
| DP6 | `nasa_firms` の実データソースは NASA EONET であり FIRMS ではない | sensor_id は実データソースを反映 **MUST** | C-07 |
| DP7 | **`gps_jamming` の閾値が比率（0–1）に対し 3.0 / 7.0 と設定され、全判定が恒久的に False。センサーは 1 件も発火しない** | 閾値は値域の単位で定義し型で表現 **MUST**。境界値のセルフテストを持つ **MUST** | **新規（本仕様で発見）** |
| DP8 | cloudflare_radar が cache 面の外で採点層と可変 dict を共有 | センサーの出力面は cache のみ **MUST** | B-04 系 |
| DP9 | apt_intel が strict XML パーサのみで tolerant フォールバックもフィード死活診断も持たない（diplomatic 系のみ保有）。死んだ URL の HTML と空フィードが同一ログに潰れる | RSS 取得・パース・死活診断を共有 ingestion kit へ昇格 **MUST** | A-02 |
| DP10 | センサー層のコンテキストキーが `strategic_theaters` / `adversary_states` など旧用語 `theater` のまま | v3 語彙は country / scenario で統一 **MUST** | C-01 |

## 8. テストトレーサビリティ

### 8.1 本書が対応する既存テスト（D5 台帳の BEHAVIOR / CONTRACT 級）

`test_engine.py::TestCircuitBreaker`（14）→ SENSBASE-007 / -008 / -009 / -015。`::TestIhrSensor`（3）→ SENSBASE-001 / -003、SENS-036。`::TestRipeAtlasSensor`（4）→ SENSBASE-001 / -003、SENS-041。
`::TestBgpTrend`（5）→ SENS-007（採点層側の同型実装を pin）。`::TestHodZscore`（3）→ SENS-005 / SENS-040（一般式のみ）。`test_ooni_degraded.py`（8）→ SENS-013。`test_greynoise_gnql.py`（3）→ SENS-008。
`test_ct_log_certstream.py`（28）→ SENS-017。`test_ct_log_certspotter.py`（21）→ SENS-015。`test_ct_log_redesign.py`（21）→ SENS-015（round-robin 3）/ SENS-018（issuer 解析・信頼判定・ウォームアップ・
ワイルドカード 14）。`test_sensor_tier_exposure.py`（3）→ SENSBASE-012 / -015。
`test_ct_log_orchestrator.py`（16）と `test_apt_prompt_dedup.py`（4）は D5 で **STRUCTURAL** 判定のため載せない（内部 seam / トークン最適化の実装詳細）。

### 8.2 GAP — 仕様化したが検証が存在しない

**本書 56 条項のうち 41 条項が `未検証`**。本書が扱う 22 基のうち **17 基が直接テストゼロ** （テストがあるのは ct_log / ooni / greynoise / ihr / ripe_atlas の 5 基、うち ihr / ripe_atlas は identity
検証のみ）。

| ID | 内容 |
|---|---|
| GAP-S1 | ripe_bgp の HOD Z 経路と drop_ratio 縮退経路の切替（n=7 境界）が未検証。**再起動直後の検知力低下も未検証** |
| GAP-S2 | check_host の「保留を分母に数えない」規則が未検証。回帰すると success_rate が系統的に低く出て偽 BLACKOUT を生む |
| GAP-S3 | check_host の HOD 正規化 status（Z −3.0 / −2.0 の 2 段）が未検証 |
| GAP-S4 | **gps_jamming の閾値単位破綻（DP7）を検出するテストが存在しない**。「センサーが一度も発火しない」ことが誰にも観測されていない |
| GAP-S5 | ISR / 支援機のコールサイン分類と surge 閾値が未検証（誤検知率が測れない） |
| GAP-S6 | ais_maritime の dark gap 判定（履歴依存）が未検証 |
| GAP-S7 | ioda_bgp の「最新アラートのみ残す」回復処理が未検証。回帰すると復旧が反映されず BGP_OUTAGE が張り付く |
| GAP-S8 | **抑制系 3 基（greynoise / usgs_seismic / space_weather）の消費側意味論が 1 件も検証されていない**。抑制の適用漏れ・過剰適用は NP1 に直撃する |
| GAP-S9 | `compute_confidence` の sample / baseline 因子（CB=0.0 以外）が未検証 |
| GAP-S10 | `set_cache` / `log_fetch` の二重記録回避（DP1）が未検証 |
| GAP-S11 | ct_log の parking（5 失敗 / 1800s / healthy-peer ゲート）と degraded 周期切替が未検証 |
| GAP-S12 | apt_intel の LLM 二段ゲート判定基準と 4 つの硬ゲート（theater 空 / 非戦略 / confidence 下限）が未検証 |

**v3 への要件**: S5 のテスト移植計画で **GAP-S1〜S12 を新規テストの必須項目とする**。特に GAP-S4 は
「仕様書を書いて初めて発見された恒久的無発火」であり、**全センサーに「既定設定で発火し得ることを示す境界テスト」を課す MUST**（無発火センサーの静かな死を検出する）。

## 9. 未決事項

1. **抑制系センサーの座席**: greynoise / usgs_seismic / space_weather / openweather は「加点せず他信号を抑制する」点で通常センサーと別種だが、現行はレジストリに同居し抑制適用ロジックが採点層に散在する（core.py の 6 箇所）。P で「抑制器」の層を明示設計するか要判断
2. **無効化センサーの扱い**（§6-A13）: notam / ihr_health を v3 で「一時停止中のソース」という第一級状態として持つか、外すか
3. **`gps_jamming` の閾値修正（DP7）を現行系でも直すか**: 物理ドメインのセンサー 1 基が恒久的に無発火である状態は NP1 に直撃する。D2 の「現行系でも即修正推奨」に該当し得る。**オーナー裁定を仰ぐべき最優先事項**
4. **ISR / 支援機のコールサイン台帳の出所**が不明（コメントに根拠 URL が無い）。移植時に一次ソースの再確認が要る
5. **自己回復機構の重複**: ct_log の parking / degraded（SENS-016）と OONI の degraded（SENS-013）は同型の問題を別実装で解いている。P で「上流健全性に応じた自己回復」を共通機構へ昇格させるか要判断
6. **ct_log の観測バッファが揮発**（DP3）: 再起動で窓内観測が消え既知 CA 台帳のみが残る。ウォームアップ基準は永続なので誤発火は起きないが、再起動直後の観測欠落は仕様上どう扱うか未定義
