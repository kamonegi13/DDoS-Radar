# D1: センサー層インベントリ（radar/sensors/）

Phase D 診断ドラフト。調査日: 2026-08-03、ブランチ: phase9/legacy-cleanup。
対象: `radar/sensors/*.py` 全 41 ファイル（総 9,718 行）+ サブパッケージ `ct_log_sources/`。

構成: BaseSensor 基底 1、具象センサー 34、非センサーヘルパー 2（`opensky_auth.py`、`acled.py`）。

## 1. センサーインベントリ表

凡例: 周期は秒（`env:` は環境変数で上書き可、`適応` は実行時に self.poll_interval を書換え）。
tier 無記載は GLOBAL。F = FOCUSED_ONLY、BG = BACKGROUND_ELIGIBLE。

### Cyber（7）

| sensor_id | ファイル | 行 | 外部ソース | 周期 | 状態フラグ | ベースライン/統計 | フラグ |
|---|---|---|---|---|---|---|---|
| cloudflare_radar | cloudflare.py | 125 | CF Radar API v4（L3/L7 attacks, BGP hijack/leak の 4 endpoint） | 900, F | attacks[国] = {l3, l7} リスト | なし（上流集計値をパススルー） | CF API token 必須 |
| ripe_bgp | bgp_routing.py | 158 | RIPE Stat country-routing-stats | 1800, F | is_anomaly / status=ANOMALY | in-mem baseline + DB HOD Z-score（z<-2.0）、フォールバックは drop_ratio 閾値 | in-mem baseline は再起動で消失 |
| greynoise | greynoise.py | 260 | GreyNoise v3 community / v2 GNQL stats / RIOT | 1800 | noise_class（NOISE_DOMINANT 等）、suppress_confidence | noise_ratio 固定閾値 0.70 | 補助（ノイズ抑制）。community/enterprise 二層動作 |
| ooni_censorship | ooni.py | 265 | api.ooni.io v1 aggregation | 1800→7200 適応 | is_censoring / is_heavy / anomaly_surge | 前回比 1.5 倍 surge + confirmed/anomaly rate 固定閾値（in-mem 前回値） | 自己回復 degraded mode（下記 §4） |
| ct_log | ct_log.py + ct_log_sources/ (8 files) | 746+ | certstream WS / CertSpotter / crt.sh | 3600→degraded 適応 | is_surge（untrusted CA or wildcard） | DB 永続の first_observed / known_cas による trust-class 評価（ADR-024） | 最大センサー。慢性障害ソースの parking 機構 |
| threatfox | threatfox.py | 86 | abuse.ch ThreatFox API | 3600 | IOC 件数 | なし | Auth-Key 必須化（2024〜）、ブラウザ UA 偽装 |
| apt_intel | apt_intel.py | 608 | CISA×2 / JPCERT / NCSC / CERT-Bund の RSS | 3600 env: | intel_queue 投入（LLM 二段ゲート） | なし（記事単位 LLM 判定） | LLM カテゴリ。domain="cyber" |

### Physical（15）

| sensor_id | ファイル | 行 | 外部ソース | 周期 | 状態フラグ | ベースライン/統計 | フラグ |
|---|---|---|---|---|---|---|---|
| opensky | opensky.py | 42 | OpenSky states/all | 1800, F | 機数カウント | なし | opensky_auth 経由（共有レートリミッタ） |
| isr_hotspot | isr_hotspot.py | 114 | OpenSky states/all（ISR_HOTSPOTS 矩形） | 1800, F | is_surge（count ≥ env ISR_SURGE_THRESHOLD=3） | 固定閾値 | opensky_auth 経由 |
| mil_support_air | mil_support_air.py | 182 | OpenSky states/all | 1800, F | is_surge（tanker surge 等の OR） | 固定閾値 | opensky_auth 経由 |
| ais_maritime | ais_maritime.py | 165 | AISHub ws.php | 1800, F | 船舶カウント | なし | guest API: 200+空 body = レート制限（§4） |
| gps_jamming | gps_jamming.py | 254 | gpsjam.org 日次 H3 tile CSV | 1800 | is_jammed（3 tile 以上）/ is_critical | 固定 tile 数閾値 | manifest.csv で最新日付発見（日次ラグあり） |
| notam | notam.py | 200 | FAA notamSearch (POST) | 1800, F | is_surge（NOTAM_SURGE_THRESHOLD） | 固定閾値 | **無効化中**（無料の国際 NOTAM API 不在、:49） |
| nasa_firms | nasa_firms.py | 109 | NASA **EONET** events API | 3600, F | イベント件数 | なし | sensor_id と実ソース不一致（FIRMS ではなく EONET） |
| openweather | openweather.py | 44 | OpenWeatherMap current | 1800, F | 気象値パススルー | なし | 補助（作戦気象コンテキスト） |
| usgs_seismic | usgs_seismic.py | 182 | USGS FDSN event query | 900 | nuclear_candidates | 固定基準（mag≥4.0 + 浅発 + 敵対国領内、CTBTO 風） | 補助（ノイズ抑制 + 核実験検知） |
| space_weather | space_weather.py | 148 | NOAA SWPC（Kp 予報 + GOES X-ray） | 1800 | Kp/X-ray class 抑制フラグ | 固定閾値（Kp≥6, X-ray≥M class） | 補助。消費側は scoring.py:835（層分離は正しい） |
| peeringdb_ixp | peeringdb.py | 110 | PeeringDB /api/ix | 14400 | IXP 件数 | なし | 補助。10s/req + 429→20s 待ち 1 回リトライ |
| ihr_health | ihr.py | 194 | IHR API（www.ihr.live ミラー） | 300 | disco/hegemony/delay アラーム | 上流アラーム値パススルー | iijlab 本家は 2026-Q1 から慢性 400（既知、:37） |
| ioda_bgp | ioda.py | 189 | GaTech IODA v2 + CF Radar traffic_anomalies | 300, F | outage alert level（recovery=normal 処理あり） | 上流アラートレベル | 二重ソース。domain="physical" だがネット観測 |
| check_host | checkhost.py | 282 | check-host.net（check-http → check-result 二段） | 600 env:, F | status=OK/DEGRADED（success_rate 0.8/…）、overall_status | DB HOD Z-score + success_rate 固定閾値 | 変数名 `theater` 残存。深夜保守帯の誤 PARTIAL 除外実装 |
| ripe_atlas | ripe_atlas.py | 180 | RIPE Atlas v2 公開測定 | 600, F | RTT 異常 | レイテンシ異常検知 | — |

### Information（6）

| sensor_id | ファイル | 行 | 外部ソース | 周期 | 状態フラグ | ベースライン/統計 | フラグ |
|---|---|---|---|---|---|---|---|
| gdelt | gdelt.py | 91 | GDELT DOC 2.0 API | 1800 | tone delta / dow_z_score | DB DOW（曜日別）トーンベースライン | 0.5s courtesy delay |
| rss_narrative | rss_narrative.py | 761 | 多数ニュース RSS | 1800 | is_burst（z ≥ ALERT/CRITICAL） | 30 日ローリング正規化頻度 Z-score | 統計 + LLM 検証のハイブリッド。intel_queue 投入 |
| telegram_mirror | telegram.py | 449 | t.me/s/{channel} スクレイプ | config: TELEGRAM_MIRROR_POLL | is_burst / has_attack_intent | クラス変数 in-mem 30 日 Z-score（rss_narrative と同型と明記 :275） | UA ローテ + 403/429 指数バックオフ。in-mem baseline 再起動消失 |
| tor_metrics | tor_metrics.py | 161 | Onionoo | 1800 | 国別 relay/bridge 変動 | — | — |
| travel_advisory | travel_advisory.py | 391 | 米 RSS / 英 Atom / 加 HTML scrape | 3600 | 勧告レベル引上げ検知 | 前回値比較（prev dict） | 3 ソース 3 パーサ（_parse_level / _parse_level_fcdo / _parse_gac_html） |
| bg_observer_rss | bg_observer.py | 161 | BG_OBSERVER_FEEDS（RSS 広域走査） | config: BG_OBSERVER_INTERVAL_SEC, BG | matches / feeds_failed | 委譲先 background_observer.py | ADR-V2-015。**自前 worker thread でスケジューラをバイパス** |

### LLM インテル（6、上記 apt_intel / rss_narrative を含めると 8）

| sensor_id | ファイル | 行 | 外部ソース | 周期 | 状態フラグ | ベースライン/統計 | フラグ |
|---|---|---|---|---|---|---|---|
| diplomatic | diplomatic.py | 571 | TASS / KCNA Watch / NK News / Google News RSS | 3600 env: | intel_queue 投入 | 記事単位 LLM 判定 | `_parse_xml_tolerant`（lxml recover）と `_classify_feed` を唯一保有 |
| military_exercise | military_exercise.py | 441 | USNI / PACOM / Stripes / Janes / DefenseNews / 中国軍網 RSS | 3600 env: | intel_queue 投入 | 記事単位 LLM 判定 | RSS ヘルパー独自コピー |
| hacktivist_intel | hacktivist_intel_sensor.py | 243 | Telegram ミラー経由（TELEGRAM_CHANNEL_META） | 1800 env: | intel_queue 投入（≥0.80 auto-confirm） | LLM 判定 | クラス名 typo: `HacktiivistIntelSensor` |
| hacktivist_news | hacktivist_news_sensor.py | 469 | HackerNews / BleepingComputer / TheRecord / DarkReading / CyberScoop RSS | 1800 env: | intel_queue 投入 | キーワード事前フィルタ + LLM | `_classify_feed` を diplomatic から関数内 import（:263） |
| ground_osint | ground_osint_sensor.py | 299 | Telegram 宣言 × CF/CheckHost ライブ照合 | 1800 env: | intel_queue 投入 | キーワード + クロスセンサー照合 | **他センサー cache を registry 経由で読む**（:67-104） |
| convergence_tracker | convergence_tracker.py | 433 | 他センサーの cache + intel ledger（メタ） | 3600 env: | intel_queue 投入（source_type="convergence"） | ≥3 センサー × ≥6h 持続昇格の収斂検知 | **自前 SQLite**（convergence_snapshots.db）+ db.intel_list 読取。module-level クールダウン dict |

### 非センサーヘルパー

| ファイル | 行 | 役割 | フラグ |
|---|---|---|---|
| base.py | 243 | BaseSensor（§2） | — |
| opensky_auth.py | 89 | OAuth2 トークンキャッシュ + 3 センサー共有レートリミッタ | module-level global 状態（設計意図どおり） |
| acled.py | 199 | ACLED API fetch ヘルパー（ACLEDEvent dataclass） | **__init__.py 非登録・radar/ 内から未参照の孤立モジュール**。実利用は scripts/run_ground_truth_etl.py（ground-truth ETL）側 |

## 2. BaseSensor 契約への適合度

### 共通インターフェース（base.py:15-243）

- 必須実装: `fetch(context) -> dict` のみ（@abstractmethod）
- 提供機構: `set_cache`/`get_cache`（lock 付き、fetch_log 自動追記）、`set_error`、`log_fetch`（SQLite `fetch_log_append` へ非致命 side-write）、`health` プロパティ（OK/DEGRADED/STALE/ERROR/CIRCUIT_OPEN/INITIALIZING/DISABLED）、`compute_confidence`（health × sample × baseline の 3 因子）
- サーキットブレーカー: CLOSED→OPEN（5 連続失敗）→HALF_OPEN（指数バックオフ 300s〜3600s）。**遷移の駆動はセンサー自身ではなく scheduler.py:122-145**（`cb_should_skip` → fetch → `cb_record_success/failure`）
- レート制限支援: `handle_rate_limit`（429 + Retry-After）、`_safe_get`/`_safe_post`（timeout デフォルト (10,20) + 429 自動処理）

### 適合度の総括

- **基底メソッドのオーバーライドはゼロ**。全 34 センサーが health / CB / log_fetch / to_config_dict を素のまま使う。契約の骨格は保たれている
- **一方で `_safe_get`/`_safe_post`/`handle_rate_limit` の採用もゼロ**。全 28 の fetch 実装が raw `requests.get/post` を直接呼び、429/timeout 対策を各自ハンドロール（ais_maritime.py:55、peeringdb.py:49-60、gdelt.py:43、bgp_routing.py:36、greynoise.py:217、telegram.py:84-119、opensky_auth.py:70-88）。基底のヘルパーは呼び出し箇所ゼロの死蔵資産
- スケジューラ迂回: `bg_observer` は自前 daemon thread（bg_observer.py:144-155）。docstring は「CB 統合は BaseSensor 経由で維持」と主張するが、ループは `cb_should_skip` を見ず `cb_record_*` も呼ばれないため **CB は実質不活性**（開くことがない）。`convergence_tracker` と `ground_osint` は scheduler 駆動だが入力が他センサーの cache というメタ構造

### コピペ実装ドリフト（D2 の最重要種）

1. **RSS 取得・パース 4 重複製**: `_fetch_rss` + `_parse_articles` + UA ヘッダーが apt_intel.py:193/208、diplomatic.py:172/262、hacktivist_news_sensor.py:102/118、military_exercise.py:115/131 に各自コピー（rss_narrative.py:134 の `_fetch_rss_text` を含めれば 5 系統）。**耐性がドリフト済**: 壊れた XML への lxml recover フォールバック（`_parse_xml_tolerant`）と死活診断（`_classify_feed`: returns_html/rss_empty/unparseable）は diplomatic.py:199/225 のみが持ち、hacktivist_news は関数内 import で借用（:263）、apt_intel / military_exercise は strict パーサのみ → 同じ malformed RSS でセンサーごとに挙動が違う
2. **HOD（hour-of-day）Z-score ブロック複製**: bgp_routing.py:32-68 と checkhost.py:247-254 が同一の hour-bucket 記録+同時刻比較ロジック（テーブル名だけ違う）。gdelt.py:40-66 は DOW（曜日）変種
3. **30 日ローリング Z-score 複製**: telegram.py:275 が「RssNarrativeSensor と同じロジック」と自己申告するクラス変数実装。片方は in-mem、もう片方も揮発 → 再起動でベースライン喪失
4. **LLM intel 投入パイプライン 6+ 重複製**: prompt 構築 → `llm_analyze_json` → confidence → item dict → `intel_queue.submit` の骨格が apt_intel / diplomatic / military_exercise / hacktivist_intel / hacktivist_news / ground_osint / convergence_tracker / rss_narrative に各自実装。max_tokens が 200/250/256/280/400 とばらつき、dedup 方式も「HacktiivistIntelSensor と同じ dedup ロジック」（ground_osint_sensor.py:43 コメント）とコピー宣言

## 3. 境界違反スキャン

### register_sequence_event（禁止事項）

**違反ゼロ**。`radar/sensors/*.py` および `ct_log_sources/*.py` に呼び出しなし（grep exit 1 で確認）。契約は守られている。

### intel_queue.submit（許可例外）

8 箇所、すべて LLM インテル系で例外条件内:
apt_intel.py:591 / convergence_tracker.py:426 / diplomatic.py:552 / ground_osint_sensor.py:279 / hacktivist_intel_sensor.py:225 / hacktivist_news_sensor.py:452 / military_exercise.py:429 / rss_narrative.py:578

### set_cache() 以外の DB 書き込み・状態変更

ベースライン永続化（「ベースライン更新は許可」の範囲内と解釈できるが、専用 db ヘルパー経由でセンサー→database の直結合を作っている）:

- bgp_routing.py:63-68 — `db.hod_last_bucket/hod_record/hod_same_hour("bgp_hod", ...)`
- checkhost.py:248-254 — 同上（"checkhost_hod"）
- gdelt.py:61-66 — `db.gdelt_dow_last_bucket/gdelt_dow_record/gdelt_dow_same_weekday`
- ct_log.py:269-271, 277, 319-340, 452-468 — `db.ct_log_first_observed/set_first_observed/known_cas/record_ca`

**グレー〜黒に近い逸脱**:

- convergence_tracker.py:54-107 — **radar.database を経由しない自前 SQLite**（`persistence/convergence_snapshots.db`、`sqlite3.connect` 直呼び）。バックアップ・WAL 運用・スキーマ管理の管轄外に置かれた第 2 の永続層
- convergence_tracker.py:265-287 — `db.intel_list` を読み、インテル台帳（スコアリング層の管轄データ）をセンサーが直接参照
- ground_osint_sensor.py:67-104 — registry 経由で cloudflare_radar / check_host の cache を読むクロスセンサー結合。fetch 順序に依存し、相手が STALE でも黙って相関判定が劣化する
- module-level 可変状態: convergence_tracker.py:50（`_alerted` クールダウン dict、再起動で消失 → 再起動直後に重複アラートの可能性）、rss_narrative.py:59（投入済 dedup 集合）、telegram.py:63-67（クラス変数ベースライン）。opensky_auth.py:14-52 の global token/limiter は共有設計として妥当

## 4. 外部 API 知識の棚卸し（リビルドでそのまま移植すべき資産）

再発見コストが高い順に近い形で列挙。**この知識の大半はコメントと分岐にしか存在しない**。

| 知識 | 場所 |
|---|---|
| OpenSky OAuth2 client-credentials + 失効 5 分前自動更新 + 3 センサー共有 min-interval リミッタ + 429 の `X-Rate-Limit-Retry-After-Seconds` を 120s 以下のみリトライ（匿名 quota 超過は即諦める）。匿名モードは 400 req/day | opensky_auth.py 全体 |
| AISHub guest API はレート制限時に **HTTP 200 + 空 body** を返す（エラーコードでない）。2s/request | ais_maritime.py:55, 78-84 |
| check-host.net は二段 API（check-http で request_id → 5s 待って check-result）。結果は `[ok_flag, time, msg, http_code, ip]` 配列。レイテンシによる success_rate ペナルティは**意図的に撤去**（正常時も 3000ms 超があるため）。深夜 UTC 保守帯の誤 PARTIAL 除外 | checkhost.py:52-134, 242 |
| api.ooni.io は数時間規模の全面 500/timeout がある → 3 連続空サイクルで degraded mode（2h 間隔・1 theater だけ probe・ログを DEBUG に降格）、回復で自動復帰 | ooni.py:13-20, 39-48, 204-218 |
| CT log 多重ソース戦略: certstream WS（liveness/heartbeat/reconnect 予算付き）→ CertSpotter（API token）→ crt.sh。「200-empty は権威ある成功」セマンティクス、慢性障害ソースの parking、degraded interval 切替 | ct_log.py:184-230, 425-473, 601-670 + ct_log_sources/ |
| IHR 本家（ihr.iijlab.net）は 2026-Q1 から API 契約変更で慢性 HTTP 400 → www.ihr.live ミラーを既定に | ihr.py:28-42 |
| 外交 RSS の死活台帳: JP_MOFA=404/WAF、CN_MFA=returns_html（RSS 廃止）、RU_MFA=geo-block、KCNA=間欠 rss_empty。死んだ feed も別ネットワーク環境からの再試行のため残す方針 | diplomatic.py:42-105 |
| 壊れた RSS への 2 段パース（defusedxml strict → lxml recover=True）と feed 死因分類（returns_html/rss_empty/unparseable） | diplomatic.py:199-260 |
| CISA の RSS URL rot（/cybersecurity-advisories/ へ移転済、2026-04 監査） | apt_intel.py:59 |
| abuse.ch ThreatFox は 2024 年から get_iocs にも Auth-Key 必須。401 の運用メッセージ | threatfox.py:20-29, 70 |
| GreyNoise: v2 GNQL stats は 410=endpoint 廃止(2026)、community tier は日次 quota、enterprise 判定分岐 | greynoise.py:32, 158-255 |
| gpsjam.org は日次 H3 res-4 tile CSV。manifest.csv から最新利用可能日を発見（当日分は無い＝日次ラグ前提） | gps_jamming.py:10-77 |
| t.me/s/ スクレイプは UA プールローテーション + 403/429 指数バックオフ 3 回。失敗時はスロットリングかネットワーク断かを区別 | telegram.py:84-119 |
| 無料の国際 NOTAM API は存在しない（ICAO API は停止）→ センサー無効化。FAA notamSearch の POST payload 形式は保存済 | notam.py:42-112 |
| courtesy delay 群: RIPE Stat 0.3s、GDELT 0.5s、GreyNoise 0.5s、PeeringDB 10s（429→20s 1 回リトライ）、OONI 0.5s | 各 fetch 内（§2 参照） |
| USGS 核実験候補基準: mag≥4.0 + 浅発 + 敵対国領内（CTBTO 風）。env USGS_MIN_MAGNITUDE | usgs_seismic.py:10-11, 60-125 |
| NOAA 宇宙天気: Kp≥6 / X-ray M class 以上で GPS 妨害等の誤検知抑制。**消費は scoring 層**（scoring.py:835）で層分離の正しい先例 | space_weather.py + config.py:377-378 |
| GDELT トーンは曜日バイアスがある → DOW 別ベースライン | gdelt.py:40-66 |
| IODA + CF Radar traffic_anomalies の二重ソースで outage 検知、recovery(level=normal) の扱い | ioda.py:31-88 |
| 渡航勧告 3 政府 3 形式（米 RSS / 英 Atom / 加 HTML テーブル scrape）の個別パーサ | travel_advisory.py:5-44, 245-334 |

## 5. 欠陥候補（D2 の種）

| # | 候補 | 証拠 | 起因 |
|---|---|---|---|
| 1 | **基底のレート制限・timeout 機構が全センサー未採用**。`_safe_get`/`_safe_post`/`handle_rate_limit` の呼出ゼロ、全員 raw requests + 個別ハンドロール。timeout 指定漏れのセンサーは gevent ループを塞ぐリスク | base.py:173-225 vs 全 fetch 実装 | アーキテクチャ（基底整備後の移行が未実施のまま定着） |
| 2 | **RSS 基盤の 4〜5 重複製と耐性ドリフト**。tolerant パーサと feed 死活診断が diplomatic 系にしかなく、同一の壊れ方でセンサーごとに結果が違う。NP2（多ソース収斂）の入力品質が不均一 | §2 ドリフト 1 | アーキテクチャ（共有 RSS 取得層の不在） |
| 3 | **convergence_tracker の第 2 SQLite** が radar.database の管轄外（バックアップ/WAL 運用から漏れる）。加えて intel ledger 読取 + module-level クールダウンでセンサー層の責務を超過 | convergence_tracker.py:54-107, 265-287, 50 | 個別実装（ただし「メタセンサーをどの層に置くか」という設計不在が根） |
| 4 | **bg_observer の CB 不活性**。自前 thread が cb_should_skip/cb_record_* を経由しないため、docstring の主張（CB 統合維持）と裏腹にブレーカーが永久 CLOSED。RSS 障害が続いても抑制がかからない | bg_observer.py:47-51, 144-155 vs scheduler.py:122-145 | 個別実装（スケジューラ迂回時の CB 責務の取り決め不在） |
| 5 | **ベースライン永続戦略の不統一**。DB 永続（hod_/gdelt_dow_/ct_log_）と in-mem 揮発（bgp_routing._baseline、telegram._baseline_tg、ooni._prev_anomaly_counts、rss_narrative）が混在。再起動で Z-score 系センサーの検知力が数日間低下 = NP1（感度優先）への直接影響 | §1 ベースライン列、§3 | アーキテクチャ（ベースライン基盤の不在） |
| 6 | ground_osint のクロスセンサー cache 依存が暗黙結合。相手センサーの STALE/ERROR を確認せず相関判定するため、劣化が沈黙する | ground_osint_sensor.py:67-104 | 個別実装 |
| 7 | 旧用語 `theater` がセンサー層に広範残存（checkhost.py:248、convergence_tracker、telegram、rss_narrative、ground_osint 等の変数・DB キー）。CLAUDE.md の廃止用語規約と乖離 | grep "theater" radar/sensors/ | リネーム負債（横断） |
| 8 | acled.py がセンサーパッケージ内の孤立モジュール（__init__ 非登録、radar/ 内未参照）。実際の消費者は ground-truth ETL。置き場所が誤解を招く | acled.py + scripts/run_ground_truth_etl.py | 個別（配置の問題） |
| 9 | クラス名 typo `HacktiivistIntelSensor`（i 重複）が __init__ 公開名にまで伝播 | hacktivist_intel_sensor.py:43, __init__.py:29 | 個別（コピペ文化の症状） |
| 10 | nasa_firms の sensor_id と実データソース不一致（FIRMS ではなく EONET events API）。NP6（導出開示）で一次ソースを追う際に誤誘導 | nasa_firms.py:11-28 | 個別実装 |
| 11 | LLM intel 投入骨格の 8 重複製（max_tokens・dedup・確信度閾値がセンサーごとに微妙に違う）。判定品質の較正が個別化し、AP2/AP3 の一貫性を損なう | §2 ドリフト 4 | アーキテクチャ（intel 投入の共有パイプライン不在） |
| 12 | set_cache の fetch_log 自動追記と log_fetch の二重記録回避が `_from_log_fetch` フラグの暗黙協調に依存。呼び順を変えると重複記録が発生する脆い契約 | base.py:43-61 | アーキテクチャ（基底の API 設計） |

### 総括

センサー層は「fetch → set_cache」の外形契約と CB 骨格は健全に守られている（違反ゼロ、オーバーライドゼロ）。一方で、**基底が提供する共通機構の採用がゼロで、レート制限・RSS パース・Z-score ベースライン・LLM 投入という 4 つの横断関心がすべてセンサー個別のコピペに退化している**。リビルドでは §4 の API 知識を資産として移植しつつ、この 4 つを共有基盤に昇格させることが D2 の中心論点になる。
