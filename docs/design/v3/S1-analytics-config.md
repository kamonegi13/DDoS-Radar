# S1 — 分析系・観測系・設定系 挙動仕様

**スコープ**: (1) Strategic Climate Engine（間接指標 T2/T4/S1/S2/S3/O1/O3/CAL の全式・イベント生成規則・Climate Gauge）、
(2) Background Observer サイクルと RSS kinetic 抽出、(3) 保留 backlog トリガー監視・週次診断、
(4) 分析系 endpoint の**導出ロジック**、(5) 国ペア共起行列と DBSCAN、(6) **3 層 config 解決の意味論**。

**境界**: endpoint の**形状・認証・エラーコード**は S2-api-contract（本書は「何をどう計算して出すか」のみ）。
センサー自身の状態判定は S1-sensors-*。TL 導出・収斂・シナリオ採点は S1-scoring-*。calibration 提案の生成規則は
S1-calibration（本書は followup watch が**観測する側**のみ）。全 config キーのカタログは各領域の S1 文書が持ち、
本書 §5 は**解決機構そのもの**を規定する。**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。

**一次ソースについて（重要）**: `radar/climate.py`（1,026 行）、`radar/routes/analytics.py`（1,134 行）、
`radar/config.py` + `config_layered.py`（1,612 + 457 行）には**専用テストが 1 件も存在しない**（D5 §4.1）。
これらの条項の根拠は**コード読解のみ**であり検証欄は `未検証` である。意図が読み取れない挙動は規範化せず
ACCIDENTAL または §10 へ落とした。bg observer / rss_extractor / followup_watch / diagnostics / cooccurrence /
dbscan には専用テストがあり、そちらはテスト ID を記載する（対応表は §9）。

## 1. 用語

CLAUDE.md の定義に従う。本書固有: **indicator**（`T2` `T4` `S1` `S2` `S3` `O1` `O3` `CAL` の 8 値）、
**axis**（`time`/`space`/`target`/`context`）、**ClimateEvent**（ts, indicator, axis, headline, detail, severity,
theater, meta）、**Climate Gauge**（直近 6 時間のイベント群から算出するスコアと 5 段階ラベル `FROZEN`/`COOL`/
`WARMING`/`HOT`/`FLASHPOINT`。**TL とは独立で TL 導出に一切寄与しない**）、**SeasonalBaseline**（(曜日, 6 時間
バケット) 粒度のベースライン）、**retained buffer**（BG observer の findings を TTL 窓の間**消費せず**保持する
バッファ）、**3 層解決**（DB override → 環境変数 → 既定値）、**registry 迂回**（registry 登録済みキーが 3 層解決を
経ず環境変数から直読みされ DB override が無効になる状態）。climate.py の `theater` は廃止用語で、意味に応じ
**country** と読み替える（実体は ISO2・空港コード・空文字）。TL は 1=CRITICAL…5=NORMAL、比較は `severity = 6 − TL` 経由。

---

## 2. 挙動条項 — Strategic Climate Engine

### S1-ANLYT-001: ベースラインは (曜日, 6h バケット) 粒度で 3 段フォールバックする
**挙動**: 時刻 ts のバケットを `(weekday(ts), hour(ts)//6)`（**UTC**）で定め、① 同一 (曜日, バケット) の値が 3 件以上 → `exact`、
② 同一バケット（曜日不問）が 3 件以上 → `hour`、③ 全履歴 → `all` の順で最初に成立した母集団を使う **MUST**。系列長 2 未満は
`(mean=0.0, std=1.0, n=0, level="none")` **MUST**。`mean=Σv/n`、`std=sqrt(Σ(v−mean)²/n)`（**母標準偏差**）、
`std=max(std, std_floor)` **MUST**。当該サイクルの観測でベースラインを汚染しないため `get_baseline()` → `record()` の順で
呼ぶ **MUST**。保持期間は T2/S1 = 7 日、S2 = 14 日、S3 = 30 日、剪定は系列長が 50 の倍数になった `record()` でのみ実行 **MUST**。
**根拠**: radar/climate.py:79-141, 254, 316, 357, 445 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A1, A2）

### S1-ANLYT-002: キャッシュ再利用型 Z 指標（T2 / S1 / S2）は共通形で発火する
**挙動**: 3 指標はいずれも既存センサーのキャッシュ値を SeasonalBaseline で `z = (値 − mean)/std` に変換して判定する **MUST**。
センサー未登録なら空を返す **MUST**。パラメータは以下 **MUST**:

| 指標 | 入力 | std_floor | スキップ | 発火 | severity | axis / theater |
|---|---|---|---|---|---|---|
| T2 テンポ surge | RSS narrative の country 別記事数 | 0.5 | `n<4` | `z>1.5` | `z>3.5`→2、`z>2.5`→1、他 0 | time / country |
| T2 テンポ silence | 同上 | 0.5 | `n<4` | `z<−1.5` **かつ** `mean>2` | `z<−2.0`→1、他 0 | time / country |
| S1 民間航空 | OpenSky の空港別機体数（負値=欠測） | 1.0 | `n<6` / `mean<3` | `z<−1.5`（**下振れのみ**） | `z<−3.0`→2、`z<−2.0`→1、他 0 | space / 空港コード |
| S2 商船 | AIS dark gap の**総件数** | 0.5 | `n<4` / 件数 0 | `z>1.5` | `z>3.0`→2、`z>2.0` **or** 件数≥3→1、他 0 | space / **空文字** |

T2 silence の `mean>2` は記事数が極小な country での常時発火防止、S1 の `mean<3` は母数の薄い空港での偽陽性防止。
S1 は `drop_pct = round((1 − 値/mean)×100)` を、S2 は detail にチョークポイント名 3 件（meta は 5 件）併記 **MUST**。
**根拠**: radar/climate.py:240-283, 301-339, 360-392 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A3, A4, A5）

### S1-ANLYT-003: S3（為替）は 8 通貨を 4 時間間隔で取得し、USD 共通成分を中央値で除去する
**挙動**: 監視は TWD/JPY/KRW/CNY/PHP/UAH/RUB/ILS の 8 通貨（TW/JP/KR/CN/PH/UA/RU/IL に対応）**MUST**。対 USD レートを
timeout 15 秒で取得し、**前回取得から 14400 秒未満なら取得せずキャッシュ値のみで分析 MUST**。HTTP 非 200 / 例外時は
警告ログのみで最終取得時刻を**更新しない MUST**。サンプル 7 件未満／最新レート未取得の通貨は除外 **MUST**:

```
std_floor=0.01 でベースライン取得 → std = max(std, mean × 0.005)   # mean > 0 のとき
z = (latest − mean) / std ／ prev = 直前に記録された値（無ければ mean）
daily_change_pct = (latest − prev) / prev × 100                    # prev が 0 なら 0
median_z = 対象 3 通貨以上のとき全 z の中央値（偶数個は中央 2 値の平均）、未満なら 0.0 ／ adj_z = z − median_z
```

中央値除去は Fed 利上げ等の USD 起因の一斉変動を地政学シグナルと誤認しないための補正である。発火は `adj_z > 2.0`
**または** `daily_change_pct > 2.0` **MUST**。severity は `adj_z>3.5`→2、`adj_z>2.5` **or** `daily_change_pct>2.0`→1、
他 0。`|median_z|>0.3` のときのみ detail に調整値を併記 **MUST**。axis=`space`。
**根拠**: radar/climate.py:407-519 ／ **検証**: 未検証 ／ **分類**: CORE（通貨安のみ検知する非対称性は意図的。§8-DP1）

### S1-ANLYT-004: T4（検索行動）は依存不在時に無音で無効化される
**挙動**: Google Trends クライアントの利用可否を初回に 1 度だけ判定し、不可なら INFO ログ 1 回のみで
**以後常に空を返す MUST**（エラーにしない）。監視は TW/JP/KR/UA の 4 国 × 各 5 キーワード、取得間隔 21600 秒、
直近 7 日・国指定、国ごとに 2 秒スリープ、国単位の例外は次の国へ進む **MUST**。判定は `latest = 最新値`、
`avg = 最新を除く平均`（要素 1 件なら 0）とし、`avg>0` かつ `latest > avg×1.5` をスパイクとする **MUST**。
比の降順上位 3 件を detail に載せ、severity は最大比が `>4.0`→2、`>2.0`→1、他 0。axis=`time`。
**根拠**: radar/climate.py:533-627 ／ **検証**: 未検証 ／ **分類**: CORE（縮退は NP3）。**キャッシュに失効が無い** → §8-DP2

### S1-ANLYT-005: O1（証明書異常）は CT Log の 2 状態のみをイベント化する
**挙動**: country ごとの CT Log 状態のうち `UNTRUSTED_CA_DETECTED`（かつ件数>0）→ **severity 3**、
`WILDCARD_TLD_DETECTED`（かつ検出フラグ真）→ severity 2 のみをイベント化する **MUST**。`NORMAL` / `WARMUP` は
**イベントを生成しない MUST**。判定は排他で、両状態同時成立時は**先に評価される untrusted CA 側のみ**を出力 **MUST**。
meta のイベント配列は最大 5 件。axis=`target`。
**根拠**: radar/climate.py:639-699 ／ **検証**: 未検証 ／ **分類**: CORE（**severity 3 は定義域外** §8-DP3）

### S1-ANLYT-006: O3（ナラティブ標的）は英語圏バイアスを中央値で除去し敵対方向のみを出す
**挙動**: GDELT キャッシュの country 別トーン差分について、差分を持つ country が 3 件以上あるとき**中央値** `median_delta`
（偶数個は中央 2 値の平均）を求め `adj_delta = delta − median_delta` **MUST**、3 件未満なら 0.0 **MUST**（GDELT の約 6 割が
英語メディアであることに起因する一斉変動の除去）。`adj_delta < −1.5` の country のみを **`adj_delta` 昇順**（最も敵対的な
ものが先頭）で出力 **MUST**。severity は `adj_delta<−5`→2、`adj_delta<−3` **or** センサー側 alert フラグ真→1、他 0。
`|median_delta|>0.3` のときのみ detail に調整値を併記 **MUST**。
**根拠**: radar/climate.py:720-782 ／ **検証**: 未検証 ／ **分類**: CORE（**トーン履歴のデッドステート** §8-DP4）

### S1-ANLYT-007: CAL は記念日を同日一致で、予定イベントを 7 日先読みで出す
**挙動**: 記念日（コード内固定 5 件）は UTC 現在日の (月, 日) 完全一致で severity 1 **MUST**。予定イベント（geo_data.json 由来）は
`0 ≤ 予定日 − 今日 ≤ 7` 日で発火し、差 ≤ 1 日 → severity 1、他 0 **MUST**。日付として不正なエントリはスキップ **MUST**。
予定イベントは **import 時に 1 度だけ**読み込む **MUST**。axis=`context`。
**根拠**: radar/climate.py:147-220 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A6）

### S1-ANLYT-008: 気候サイクルは 7 分析器 + カレンダーを固定順で実行する
**挙動**: 1 サイクルは T2 → S1 → S2 → O1 → O3（既存キャッシュのみを読む安価な 5 種）→ S3 → T4（外部 HTTP、自己レート制限あり）
→ CAL の順 **MUST**。サイクルは**採点ティック内から同期的に呼ばれ、例外は debug ログのみで握り潰される**。
**根拠**: radar/climate.py:840-857、radar/routes/core.py:3022-3027 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP5）

### S1-ANLYT-009: イベントは (indicator, country, 時単位) で 1 件に畳み、48 時間 / 200 件で上限する
**挙動**: 生成イベントは `(indicator, theater, floor(ts/3600))` をキーに重複排除し、**同一キー内では最後に生成されたものを残す
MUST**（元の相対順序は保存）。フィード反映時は同一キーの既存エントリを削除してから追加 **MUST**。各サイクルで
`ts ≤ now − 48h` を落とし末尾 200 件へ切り詰める **MUST**。起動時は DB から直近 48 時間を復元して Gauge を再計算し、
復元失敗は debug ログのみで無視 **MUST**。
**根拠**: radar/climate.py:808-825, 859-879 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A5）

### S1-ANLYT-010: Gauge は直近 6 時間の「異なるシグナル数」と country 内ドメイン収斂で決まる
**挙動**: **MUST**:

```
recent  = feed のうち ts > now − 6h かつ axis != "context"       # 空なら (0.0, FROZEN)
sev_cap = 1 if 成熟度 == immature else 2
signal_max[(indicator, theater)] = max(min(severity, sev_cap))    # 窓内で 1 本に畳む
base_score = Σ{sev1→1.0, sev2→2.0} + min(sev0 のシグナル本数 × 0.2, 2.0)
domain(indicator) = {T2:info, T4:info, S1:physical, S2:physical, S3:economic, O1:cyber, O3:info}
severity ≥ 1 かつ theater 非空のシグナルで country ごとの異なるドメイン数を数え、
2 以上の country につき (ドメイン数 − 1) × 0.5 を加算、合計は 3.0 で上限 ／ total = base_score + convergence_bonus
```

レベルは `total ≥ 15`→`FLASHPOINT`、`≥8`→`HOT`、`≥3`→`WARMING`、`>0`→`COOL`、他 `FROZEN` **MUST**。同一
(indicator, country) は窓内で何回発火しても 1 本と数える（持続的低 severity のスコア膨張防止）。`axis == "context"` は
Gauge にも indicator 別件数にも**寄与させない MUST**（暦の到来だけで脅威スコアを動かさない）。
**根拠**: radar/climate.py:922-992, 935, 1002 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A7、境界の根拠は §10-1）

### S1-ANLYT-011: ベースライン未成熟時は severity 2 を 1 に抑える
**挙動**: 成熟度は T2 / S1 / S3 の各ベースライン（country・空港・通貨ごとに 1 本）のうち**観測件数 21 件（=3×7）以上の比率**
`pct` で決まり、`pct ≥ 0.8`→`mature`、`≥0.3`→`developing`、他 `immature` **MUST**。ベースライン 0 本なら `("immature", 0.0)`
**MUST**。`immature` のとき Gauge の severity 上限を 1 とする **MUST**（コールドスタート時の偽エスカレーション防止 = NP5+8）。
**根拠**: radar/climate.py:891-920, 940-942 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A8）

### S1-ANLYT-012: Climate 出力は 24 時間 / 50 件、永続化は時単位上書きで剪定されない
**挙動**: サマリは Gauge（レベル・スコア小数 1 桁・成熟度ラベル・成熟度百分率）、直近 24 時間のイベントの**末尾 50 件を逆順**に
したフィード、context を除く indicator 別件数、最終更新時刻、直近 24 時間の context イベント**全件**を返す **MUST**。軸フィルタ付き
フィードは軸で絞ってから末尾 `limit` 件を逆順で返す **MUST**（`limit` は 1..200 に丸める）。DB 保存は同一 `(indicator, theater)`
かつ同一の時単位境界内 `[floor(ts/3600)×3600, +3600)` の既存行を削除してから挿入する **MUST**。
**根拠**: radar/climate.py:994-1026、radar/routes/climate.py:17-23、radar/database.py:5548-5592 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP6）

---

## 3. 挙動条項 — Background Observer / RSS 抽出 / 監視 / クラスタリング

### S1-ANLYT-013: BG observer は既定無効、有効時は全対象シナリオの participant 和集合を走査する
**挙動**: 既定は無効（`BG_OBSERVER_ENABLED`、default false）で、無効時はサイクルを実行しない **MUST**。有効時は採点対象
シナリオ全件の participant の**和集合**を観測対象とする **MUST**（focused も除外しない）。和集合が空ならフィードを取得せず
理由 `no_participants` のサイクルログを残す **MUST**。
**根拠**: radar/background_observer.py:271-347 ／ **分類**: CORE ／ **検証**: test_background_observer.py::test_tick_no_op_when_disabled / _broadcast_scope_respects_participant_union（他 2 件 §9）

### S1-ANLYT-014: フィード取得は 1 本の失敗でサイクルを止めず、空結果も失敗として数える
**挙動**: 設定された全フィード（既定 3 本、全て HTTPS）を順に取得し、例外**および空結果**を失敗として計上して次へ進む **MUST**。
取得は匿名 GET（timeout 15 秒、固定 User-Agent）で RSS の item と Atom の entry の双方を解析し、HTTP / XML 解析の失敗は空リストを
返す **MUST**。**空結果を失敗と数えるのは**「取得できたが 0 件」と「取得失敗」がいずれも同じ recall 低下だからである。
**根拠**: radar/background_observer.py:155-199, 245-269、radar/config.py:628-636 ／ **分類**: CORE
**検証**: test_background_observer.py::test_cycle_log_counts_failed_feeds / _fetch_error_does_not_crash_cycle

### S1-ANLYT-015: 1 記事から検出された全 country にシグナルを出す（broadcast）
**挙動**: 各記事の `title + " — " + summary` に対し participant 和集合へスコープした多国抽出を行い、**検出された country ごとに
1 件ずつ**シグナルを生成する **MUST**。記事単位の例外はその記事のみスキップ **MUST**。シグナルは domain=`info`、
signal_source=`bg_observer`、evidence_url は常に未設定 **MUST**。`raw_score` は抽出 confidence により **MUST**:
`≥0.85`（死者数あり）→ `min(1.0, 0.4 + 0.05 × 死者数)`、`≥0.60`（kinetic のみ）→ 0.45、それ未満（escalation のみ）→ 0.25。
**根拠**: radar/background_observer.py:349-401 ／ **分類**: CORE ／ **検証**: test_background_observer.py::test_broadcast_emits_one_signal_per_country_per_match（§9-GAP1）

### S1-ANLYT-016: findings は TTL 窓の間、消費されずに保持される（retained buffer）
**挙動**: 採点ティックからの読み出しは **consume-on-read であってはならない MUST**。読み出しは
`observed_at ≥ now − BG_OBSERVER_SIGNAL_TTL_SEC`（既定 1800 秒）を満たす全エントリを返し、**期限切れのみをその場で剪定する
MUST**。「TTL 窓内に kinetic 言及が観測された」という事実は窓の全ティックで真であり続けるため、これは状態意味論（state
semantics）であってキュー意味論ではない。**本規範は 2026-07-04 の strobe 修正で確立した**: 旧実装は読み出しでバッファを空に
したため実効寿命は「次の採点ティックまで（≤2 分）」で 30 分の TTL は虚構であり、5 分の観測サイクルと 2 分の採点ティックが
エイリアシングして info 寄与が明滅し、focused の TL が TL4↔TL5 を往復した。
**根拠**: radar/background_observer.py:96-117 ／ **分類**: CORE（NP1 直結。**最も壊してはならない条項の 1 つ**）
**検証**: test_background_observer.py::test_active_signals_retains_buffer_within_ttl / _visible_to_consecutive_ticks /
_expire_after_ttl / _phase_alias_simulation_no_strobe（他 2 件 §9）

### S1-ANLYT-017: 同一 finding の再観測は TTL をスライドさせ、重複を作らない
**挙動**: finding の同一性は `(signal_source, domain, countries, evidence_url または value_display)` **MUST**。一致する既存
エントリがあれば**削除してから末尾に追加**して TTL をスライド **MUST**（重複を積まない）。バッファ長が上限
（`BG_OBSERVER_MAX_QUEUE`、既定 200）に達したら**最古を捨てる MUST**。
**根拠**: radar/background_observer.py:126-149 ／ **分類**: CORE ／ **検証**: test_background_observer.py::test_reenqueue_same_identity_slides_ttl_without_duplicating /
_distinct_identities_coexist / _max_queue_cap_evicts_oldest

### S1-ANLYT-018: サイクルログはゲート別カウンタと alias gap を残し、gap があっても観測は続行する
**挙動**: 各サイクルは 開始時刻・所要ミリ秒・試行/失敗フィード数・総記事数・country 検出記事数・kinetic 記事数・死者数付き
記事数・出力シグナル数・country 別内訳・alias gap・観測シナリオ ID 一覧・drop 理由 を残す **MUST**。永続化失敗は握り潰す **MUST**
（観測が自分自身を壊さない = NP3）。alias 表に無い participant は列挙してログに残すが**サイクルは中断しない MUST**
（一部でも観測がある方が無観測より良い = NP1）。同じ検査は CI では失敗として扱う **MUST**。
**根拠**: radar/background_observer.py:289-345, 403-418、radar/conclusions/rss_extractor.py:234-241, 538-573
**分類**: CORE（AP3/AP4）／ **検証**: test_background_observer.py::test_cycle_log_records_per_gate_counters / _cycle_log_surfaces_alias_gap；
test_rss_extractor.py::test_alias_coverage_against_geo_data_json

### S1-ANLYT-019: country 検出は alias 表の語境界一致、死者数は 3 系統の最大値
**挙動**: ISO2 → alias 群の表に対し `\b<alias>(?!\w)` の大小無視一致で検出する **MUST**。末尾に `\b` でなく否定
先読みを使うのは、ピリオドで終わる alias（`U.S.`）が後続空白との間に語境界を作らないためである。単一検出版は
**最初に一致したもの**を、多国版は一致した全 ISO2 を重複無く返す **MUST**。許可リストが与えられた場合は
**そのリストの並び順で走査する MUST**。死者数は (a) 数詞前置形、(b) 数詞後置形（`toll rose to N`）、(c) 英単語形
（`one`〜`twenty`、数詞と動詞の間に修飾語 4 語まで許容）の 3 系統を全件走査し**最大値**を採る **MUST**。
`twenty` 超の単語形は認識せず、数値は 1〜4 桁のみ受け付ける **MUST**（推測より過少報告を選ぶ）。
**根拠**: radar/conclusions/rss_extractor.py:44-70, 244-346 ／ **分類**: CORE（§7-A9）／ **検証**: test_rss_extractor.py::test_dotted_alias_matches_before_whitespace /
_regex_extracts_{numeric,inverted,word_form}_fatalities / _regex_takes_max_when_multiple_counts_present（他 3 件 §9）

### S1-ANLYT-020: 抽出 confidence は 3 段で、姿勢（posture）を暴力から分離する
**挙動**: country が検出され、かつ {死者数, kinetic 動詞, escalation 動詞} のいずれも無いときは抽出しない **MUST**。成立時は
死者数あり → confidence 0.85 / 解析値、kinetic 動詞あり死者数なし → 0.60 / 0、escalation 動詞のみ → 0.40 / 0 **MUST**。
**裸の兵器名詞（`missile` / `rocket` / `artillery` 単独）は kinetic 動詞に含めない MUST** — 兵器試験・配備・防衛産業の発表が
同じ名詞を含むためで、それらは escalation 段に属する。summary は 240 文字に切り詰める **MUST**。1 記事に複数 country が現れる
場合、動詞ゲートは**テキスト全体で 1 度だけ判定し、検出された全 country に同じ値を配る MUST**（加害/被害は区別しない）。
**根拠**: radar/conclusions/rss_extractor.py:81-109, 353-455 ／ **分類**: CORE（NP1 側に倒した意図的選択）
**検証**: test_rss_extractor.py::test_weapons_test_is_posture_not_kinetic_action / _kinetic_verb_outranks_escalation_verb /
_tier_confidence_maps_to_expected_severity_floor / _extract_all_returns_multi_country_for_dual_actor_headline（他 8 件 §9）

### S1-ANLYT-021: エスカレーション関連性ゲートはラベル生成にのみ適用し、観測には適用しない
**挙動**: 判定は以下の順 **MUST**: ① 本質的に軍事的な語彙（strong kinetic または escalation 動詞）があれば**無条件で真**
（ノイズ拒否より優先）、② 弱い kinetic 動詞のみなら軍事主体名詞があるか**認識 country が 2 つ以上**あるときに限り候補、
③ 候補が災害・事故・犯罪・催事のノイズ語彙を含めば偽。**このゲートは ground truth ラベル生成にのみ適用し、BG observer の
観測経路には適用しない MUST** — 誤ラベルは recall 指標を壊すがラベル漏れは標本数を減らすだけだからである。
**根拠**: radar/conclusions/rss_extractor.py:111-186 ／ **分類**: CORE（2026-07-04 の本番 ground truth 汚染への対処）
**検証**: test_rss_extractor.py::test_strong_kinetic_is_relevant / _disaster_with_fatalities_is_not_relevant /
_noise_does_not_veto_strong_kinetic（他 5 件 §9）

### S1-ANLYT-022: LLM 拡張は決定的ベースラインを置換しない
**挙動**: LLM 拡張が有効なとき、出力が (a) 文字列でない/空、(b) JSON 解析失敗、(c) country が alias 表に無い、
(d) country が許可リスト外、(e) 死者数が非整数または負、のいずれかなら**必ず正規表現の結果へフォールバックする
MUST**。confidence は欠落時 0.80、**[0.0, 0.95] にクランプする MUST**。LLM 経路のいかなる例外も debug ログのみで
ベースラインへ戻す **MUST**。
**根拠**: radar/conclusions/rss_extractor.py:458-532 ／ **分類**: CORE（NP3: LLM 不在環境でも同じ観測能力を保つ）
**検証**: test_rss_extractor.py::test_llm_path_overrides_regex_when_output_valid / _llm_path_falls_back_{to_regex_on_exception,
when_json_invalid, when_country_outside_allowed} / _llm_confidence_clamped_to_0_95_max（他 4 件 §9）

### S1-ANLYT-023: トリガー監視は日次で全条件を評価し、成立の立ち上がりのみ WARN する
**挙動**: 各監視は「条件成立か否か」と説明文字列を返す関数として登録し、日次で全件評価する **MUST**。**初回成立のみ WARN、
成立継続は INFO MUST**。不成立に戻ったら記憶を消去し次の成立で再び WARN **MUST**。個別監視の例外は debug ログのみで飲み込み、
**他の監視を止めない MUST**。状態はプロセス内メモリのみで再起動により消える **MUST**（重複 WARN は見落としより安価）。
**根拠**: radar/observability/followup_watch.py:325-362 ／ **分類**: CORE ／ **検証**: test_followup_watch.py::test_met_condition_warns_first_time / _subsequent_observations_demote_to_info /
_clearing_condition_resets_cache_so_re_warns / _failing_check_does_not_block_others（他 2 件 §9）

### S1-ANLYT-024: 監視条件は 7 件、うち 3 件は提案処理プロセス自身の設計失敗を検知する
**挙動**: 登録される監視は以下 7 件 **MUST**:

| 監視 | 成立条件 |
|---|---|
| analyst feedback ビューア | 人間由来（`auto:` 前置でない）の feedback 行が 100 件以上 |
| 慢性 chip 詳細 | 慢性エントリが 1 件以上、かつ最古の滞留が 14 日以上 |
| silent failure バケット化 | NP1 4 種別（focused 採点 / LLM intel シグナル / bg observer drain / 自動判定上書き追跡）の生涯失敗数合計 100 以上 |
| alias gap エディタ | 直近 24 時間の bg observer サイクルの alias gap が非空 |
| 提案の慢性保留 | recall を狭める 3 種別（weight 過大 / 休眠 participant / role 再分類）が 60 日超 pending |
| 非活性シナリオ上の提案 | pending 提案の対象シナリオが paused / archived（年齢不問） |
| 却下率反転の持続 | 直近 14 日と 30 日の**両方**で終結済み提案が各 10 件以上かつ却下率 > 50% |

慢性保留の 60 日は 30 日スヌーズ 1 巡を生き延びた提案を意味する **MUST**。
**根拠**: radar/observability/followup_watch.py:57-319 ／ **分類**: CORE（NP5+8 をアナリスト判断プロセスへ拡張した対称性）
**検証**: test_followup_watch.py::TestProposalChronicPending（4）/ ::TestProposalDismissedInversion（3）/
::TestProposalInactiveScenario / ::test_production_watch_returns_well_formed_tuple

### S1-ANLYT-025: 監視の個別失敗は「条件不成立」として扱われる
**挙動**: 各監視の内部例外は捕捉し `(False, "check_failed: <理由>")` を返す。
**根拠**: radar/observability/followup_watch.py:69-70 ほか全 7 監視で同形
**検証**: test_followup_watch.py::test_failing_check_does_not_block_others
**分類**: **DEFECT-PRESERVE**（§8-DP7。検査不能を条件不成立と同一視するのは NP5+8 の「結論不可の明示」に反する。
v3 では第 3 状態 `unknown` を持つ **MUST**）

### S1-ANLYT-026: 週次診断は 2 種の読み取り専用診断を 1 プロセス 1 週間隔で実行する
**挙動**: intel センサー監査と Layer 1 バックテストを実行して結果を INFO ログに出す **MUST**。既定間隔 168 時間、
**1 時間未満には設定できない MUST**（下限クランプ）。間隔判定はプロセス内タイムスタンプのみで再起動によりリセット
される **MUST**。実行前に楽観的にタイムスタンプを進め、失敗してもロールバックしない **MUST**（壊れた DB に対して
回り続けるより 1 週飛ばす方が良い）。個別診断の例外は警告ログのみで他方は実行する **MUST**。country あたりの独立
ソース数は `max ≥ 2` かつ `avg ≥ 2.0` → Layer 1 解禁条件充足、`max ≥ 2` のみ → 出現中、他 → 単一ソース の 3 段 **MUST**。
**根拠**: radar/diagnostics.py:37-133 ／ **検証**: test_diagnostics.py 全 6 件（§9）／ **分類**: CORE

### S1-ANLYT-027: 共起行列は時間バケット内の同時出現回数で数え、空行列も保存する
**挙動**: 直近 `window_days`（既定 30）の LLM intel 行のうち country が非空のものを `floor(ts / (bucket_hours × 3600))`
（既定 24 時間）でバケット化し、バケットごとの country 集合の**全 2 要素組み合わせ**の計数を 1 増やす **MUST**
（ペアキーは辞書順で正規化）。`share = count / 総バケット数`（総バケット 0 なら 0.0）を小数 4 桁で丸め、ペアは count
降順に並べる **MUST**。DB 照会の失敗は空行集合として扱い例外にしない **MUST**。**セル数 0 の行列も保存する MUST**
（「ETL は走ったが何も出なかった」と「ETL が走っていない」の区別 = AP3）。セル数が上限（既定 5000）超なら**保存を
拒否して警告ログを残す MUST**。保存行には式参照子と根拠（総イベント数・総バケット数・country 数）を添える **MUST**（NP6）。
**根拠**: radar/analytics/cooccurrence.py:43-46, 95-191 ／ **分類**: CORE
**検証**: test_cooccurrence.py::TestComputeMatrix（6 件）/ ::TestSnapshot（4 件）

### S1-ANLYT-028: 距離は 1 − share、未観測ペアは最大距離 1.0、DBSCAN は eps 0.6 / min_samples 3
**挙動**: country ペア距離は `round(1.0 − clamp(share, 0, 1), 6)` **MUST**。行列に現れないペアは**距離 1.0（無限大では
ない）として扱う MUST**（eps 比較が期待どおり働くため）。自己距離 0.0 **MUST**。`distance ≤ eps` の近傍を求め、
**自身を含めた数が `min_samples` 以上ならコア点**（既定 eps=0.6、min_samples=3）とし、コア点から幅優先でクラスタ ID を
伝播する **MUST**。コア点でもコア点から到達もできない点は**ノイズ（cluster_id = −1）MUST**。入力が空なら空の結果、
距離が空なら全ノイズを返す **MUST**（例外にしない）。代表点は「他の全メンバへの平均距離が最小のメンバ」**MUST**。
**根拠**: radar/analytics/dbscan_cluster.py:60-190 ／ **分類**: CORE ／ **検証**: test_dbscan_cluster.py::TestCluster（7）/ ::TestDist（3）/ ::TestClusteringResult（3）/ ::TestMatrixToDistances（4）

---

## 4. 挙動条項 — 分析系 endpoint の導出ロジック

（**API 形状ではなく計算内容**の規定。形状は S2-api-contract。`radar/routes/analytics.py` には専用テストが無く
endpoint 組み立ては原則 `未検証`。委譲先の式のみ検証欄に記す。）

### S1-ANLYT-029: SITREP は直近 12 サイクルの統計をテンプレート充填で生成する
**挙動**: アラート時系列（リングバッファ、最大 288 行）から `recent = 末尾 12 件` を取り、TL の最小/最大/平均（小数 1 桁）、
収斂レベルの最頻値（同数なら**最初に出現したもの**）、最新行のドメインスコアが正のドメイン一覧（CYBER, PHYSICAL, INFO の
固定順）を出す **MUST**。トレンドは `recent` が 3 件未満なら「データ不足」、そうでなければ `latest.TL − recent[0].TL` の符号で
**負→エスカレーション / 正→デエスカレーション / 0→安定**とする **MUST**（TL は DEFCON 式のため符号が反転する）。観測窓の
表示は**全バッファの時間幅**を使う。テキストは**完全テンプレート + スロット充填で LLM を用いない MUST**。
**根拠**: radar/routes/analytics.py:75-155 ／ **検証**: 未検証 ／ **分類**: CORE（§8-DP8）

### S1-ANLYT-030: シーケンス連鎖は 4 種の共存を窓内で数え、時間順は要求しない
**挙動**: 連鎖定義は `NARRATIVE_BURST` → `ISR_SURGE` → `SYNC_DDOS` → `FIRMS_ANOMALY` の 4 種で、判定は窓内（既定 86400 秒）の
**集合所属のみ MUST**（厳密な時間順は要求しない）。種別ごとに**最新イベント**を取り `age_hours` から
`weight = max(0.3, 1.0 − age_hours/24.0)` を求め、その平均 `avg_weight` を係数とする **MUST**。4/4 →
`bonus = max(1, round(SEQUENCE_FULL_BONUS × avg_weight))`、3/4 → `max(1, round(SEQUENCE_PARTIAL_BONUS × avg_weight))`、他 → 0
**MUST**。**`max(1, …)` の床があるため完全減衰した 3 連鎖でも bonus 1 が残る**。イベント無しは bonus 0。
**根拠**: radar/routes/analytics.py:161-187、radar/scoring.py:185-234 ／ **分類**: CORE
**検証**: test_engine.py::TestSequenceScorer / ::TestSequenceTemporalDecay（委譲先）。endpoint 組み立ては未検証

### S1-ANLYT-031: deep analytics の velocity は 2 種類の推定量が併存し、封鎖指数はキャッシュ値を使う
**挙動**: 見出しの velocity は**直近 5 点の最小二乗回帰の傾き**（2 点未満なら 0.0、単位は pt/秒）**MUST**、加速度は 4 点未満なら
0.0・差分速度系列の回帰傾き **MUST**、ambush 判定は 5 点未満なら偽、`z = (現在加速度 − 直前系列の平均)/母標準偏差` が閾値
（既定 2.0）超**かつ**現在加速度 > 0 **かつ** velocity > 0 **MUST**。一方で応答に載せる velocity 系列は**隣接 2 点の単純差分**
（末尾 20 点）**MUST**。country が解決できないときは**明示的に 400 を返す MUST**（本 endpoint 群で唯一の結論不可表明）。
封鎖指数は採点ティックが書いたキャッシュ値を用い（再計算枝は到達しない）、式は `ripe_factor = min(drop_pct/100, 1.0)`、
`intensity = min(ddos, 10.0)`、`attack_weight = intensity × (1 + ripe_factor)`、`ch_rate` = CheckHost 成功率（**None なら 1.0**）、
`infra_deg = max(0, 1 − ch_rate)`、`index = attack_weight × (0.10 + 0.90 × infra_deg)` **MUST**。解釈は `≥7.0`→基盤無力化、
`≥4.0`→重度混乱、`≥1.5`→政治的ノイズ、他 正常 **MUST**。
**根拠**: radar/routes/analytics.py:190-297、radar/engine.py:237-284, 391-421
**検証**: test_engine.py::TestBlockadeIndexScoring（4 件）ほか委譲先。endpoint 組み立ては未検証
**分類**: **DEFECT-PRESERVE**（§8-DP9。CheckHost 欠測を 1.0（健全）と読む fail-open は S1-scoring-core §4-A3 と同一論点）

### S1-ANLYT-032: SALUTE と天候ブリーフは完全テンプレートで、無データを「平穏」と描く
**挙動**: SALUTE の 6 節（規模 / 活動 / 位置 / 部隊 / 装備 / 評価）と天候ブリーフの 5 ブロック（cyber / maritime / info / air /
infra）はいずれも**閾値ラダーとスロット充填のみで生成し LLM を用いない MUST**。主要ラダーは 天候 cyber: `spike>6` 大嵐 /
`>3` 活発 / `>1` うねり / 他 快晴、maritime: dark gap `>2` 濃霧 / `>0` 部分霧 / 停船 `>0` 制限水域 / 他 良好、infra: 封鎖指数
`≥7` 破滅的 / `≥4` 重度 / `≥1.5` 上昇 / 他 平常。評価節の重要度写像は `{1:CRITICAL, 2:HIGH, 3:SIGNIFICANT, 4:MODERATE,
5:ROUTINE}` で、**TL 欠落時の既定は 5 MUST**。
**根拠**: radar/routes/analytics.py:300-592 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP10。加えて日本語文字列が Python 側に直書きされ i18n キー監査の網から外れる）

### S1-ANLYT-033: 無データ時の応答方針が endpoint 間で不統一
**挙動**: 現行の無データ時挙動は 5 通りに分裂している: 503 = score_breakdown / spof_analysis、400 = deep_analytics（country
未解決時のみ）、200 + 明示テキスト = sitrep、200 + 平穏既定 = salute_report / weather_brief、200 + 空コレクション =
sensor_reliability / sequence_chain / adaptive_zscore_status / calibration_advisory / confidence_distribution / scenario_phases。
**根拠**: radar/routes/analytics.py:80-81, 203, 653, 849 ほか ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP11。v3 では「結論不可」を単一の表現に統一する **MUST**）

### S1-ANLYT-034: スコア内訳は保存済みの導出トレースを読むだけで、再計算しない
**挙動**: スコア内訳は採点ティックが書いた rationale をドメイン別に再分類し、score 降順（None は 0 扱い、同点は元の挿入順）に
並べるだけ **MUST**。**再計算してはならない MUST**。cyber / physical / info **以外の domain を持つエントリは黙って捨てられる**。
抑制済みおよび非 FIRED のエントリも除外せずフラグ付きで含める **MUST**。グローバルキャッシュは**ロックを取って**読む **MUST**。
**根拠**: radar/routes/analytics.py:642-690、radar/routes/core.py:2876 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A10）

### S1-ANLYT-035: what-if は 4 種の摂動を受け付け、本番エンジンを再利用して反実仮想 TL を出す
**挙動**: 受け付ける摂動は ① センサー別イベント（sensor, score, suppressed）、② TL1 強制フラグ、③ シーケンス加点、④ 時間的
加点 の 4 種のみ **MUST**。score は**カタログの上限で切り詰める**（下限は無い）**MUST**。カタログに無いセンサー名は黙って
無視される。カタログは 20 件の**ハードコード**で実センサー登録との突合検査を持たない。再計算は**本番の収斂エンジンと本番の
TL 導出関数を呼ぶ MUST**（再実装してはならない）。`total_score` は FIRED かつ非抑制の score の**単純和**、`score_with_bonus` は
収斂加点 + ②③ を足して**15 で上限**する **MUST**。TL1 強制が真かつ `score_with_bonus ≥ 9` かつ TL > 1 なら TL を 1 に上書き
**MUST**。ドメイン状態は `≥6` CRITICAL / `≥3` ELEVATED / `≥1` WATCH / 他 NORMAL。
**根拠**: radar/routes/analytics.py:698-829、radar/scoring.py:1218-1228 ／ **分類**: CORE（§7-A11）
**検証**: test_scenario_scoring.py::TestDeriveTL（委譲先の TL 導出）。摂動処理と 15 上限は未検証

### S1-ANLYT-036: 反実仮想エンジンは confidence と signal_source を落として再構築する
**挙動**: what-if と SPOF はいずれも採点入力を再構築する際に `confidence`（既定 1.0）と `signal_source`（既定 空文字）を
**渡さない**。結果としてドメインスコア計算で**confidence 重み付けも signal_source dedup も適用されない**。what-if はさらに収斂
加点をドメイン信頼度なしで呼ぶため信頼度ゲートも外れる。両者とも本番採点より**構造的にスコアが高く出る**。
**根拠**: radar/routes/analytics.py:770-780, 859-864, 895-900、radar/models.py:31,36 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP12。NP6 の「導出の再現性」に反する）

### S1-ANLYT-037: SPOF は 1 センサー除去の反実仮想でドメイン喪失と収斂降格を判定する
**挙動**: 対象は `FIRED` かつ非抑制かつ score > 0 のエントリのみ **MUST**（健全だが無発火のセンサーは分析対象にならない）。
センサー名でエントリを除いて再採点し、`score_impact = baseline_total − sim_total`、`domain_lost` = 当該ドメインが正から 0 に
なったか、`convergence_downgrade` = 収斂レベルが変化したか、を求める **MUST**。重大度は `domain_lost` **or**
`convergence_downgrade` → CRITICAL、`score_impact ≥ 3` → HIGH、`≥ 2` → MEDIUM、他 LOW **MUST**。並びは (重大度, −score_impact)
昇順 **MUST**。ドメイン別の冗長性は **FIRED 数 ≥ 2** で真 **MUST**。グローバルキャッシュは**ロックを取って**読む **MUST**。
**根拠**: radar/routes/analytics.py:836-968 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A12, A13）

### S1-ANLYT-038: 適応 Z-score 状態と信頼度分布は単一閾値・固定バケットで刻む
**挙動**: 適応 Z は Welford 累積器の各行について `sample_count ≥ ADAPTIVE_ZSCORE_MIN_SAMPLES`（既定 50）なら `adaptive`、
未満なら `warmup` とする **MUST**。分散は `m2/n`（**母分散**、`n ≤ 1` なら 0.0）**MUST**。時間窓もフィルタも無く累積済みの
全行を返す **MUST**。信頼度分布は指定窓（既定 168 時間）の LLM intel の confidence を `bucket = min(floor(conf × 10), 9)` で
バケット化する **MUST**（左閉右開、最上位のみ両端閉）。**状態フィルタは無く pending / rejected / overridden も含める MUST**。
`source_type` が NULL のものは `unknown` に集約 **MUST**。自動確定可能率は `conf ≥ 0.80` の割合（総数 0 なら 0）**MUST**。
**根拠**: radar/routes/analytics.py:975-995, 1082-1093、radar/database.py:4241-4255, 5873-5938
**検証**: 未検証 ／ **分類**: CORE（§7-A14, A16）

### S1-ANLYT-039: calibration advisory は 3 種のルールのみを純閾値で生成する
**挙動**: 採点対象シナリオごとに、**adversary 役を除いた** participant 重みについて以下を出す **MUST**: ① `重み数 ≥ 3` かつ
`最大重み > 0` かつ `最大重み / 平均重み > 3.0` → 重み集中（MEDIUM）、② adversary 以外に重み 0 の participant がある →
重み 0 participant（LOW）、③ 指定窓（既定 168 時間）に TL 観測が 1 件も無い → 未観測（LOW）。adversary 以外の participant を
持たないシナリオは**①②③ のいずれも評価されない MUST**。併せて 2 つ以上のシナリオに現れる country の一覧を返す **MUST**
（adversary も含む）。生成は**完全ルールベースで LLM を用いない MUST**。
**根拠**: radar/routes/analytics.py:1007-1079 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A15）

### S1-ANLYT-040: シナリオ位相は観測数 100 件で 3 段に分ける — ただし現行は必ず 500 エラーになる
**挙動**: シナリオごとに直近 720 時間の TL 観測数を数え、`0` → 未較正、`< 100` → warmup、他 → 運用中 **MUST**。
**根拠**: radar/routes/analytics.py:1096-1132 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP13。①観測数の取得に上限 500 が掛かるため 500 で飽和する。②**未定義の識別子
`_scenario_label` を呼んでおり、シナリオが 1 件でも存在すれば必ず 500 エラー**。定義はリポジトリ内に無い。
**D2 未登録の新規欠陥**）

### S1-ANLYT-041: IP 照会は外部センサーへの薄い委譲で、エラー種別を文字列一致で分岐する
**挙動**: IP 未指定は 400、GreyNoise センサー未登録は 503 **MUST**。それ以外は委譲先の結果をそのまま返し、
**エラーがあり、かつその文言に "limit" も "Invalid" も含まれないときのみ 502** とする **MUST**（レート制限と
検証エラーは 200 + エラー本文になる）。
**根拠**: radar/routes/analytics.py:595-634 ／ **検証**: 未検証 ／ **分類**: **DEFECT-PRESERVE**（§8-DP14）

---

## 5. 挙動条項 — 3 層 config 解決（S1-CONF）

### S1-CONF-001: 宣言的 registry は 21 属性 × 98 キーで、登録失敗は起動を止めない
**挙動**: 各キーは キー名 / ドメイン名前空間 / 既定値 / 型 / 説明 / 秘匿・不変・再起動要否・bootstrap の 4 フラグ / 検証関数 /
列挙値 / UI グループ / 反映タイミング / 影響度 / 影響警告 / 単位 / 最小値 / 最大値 / what・why・when の 3 行解説 を持つ **MUST**。
型は `str` / `int` / `float` / `bool` / `list[str]` / `json` の 6 種 **MUST**。5 つの UI グループと 24 のドメイン名前空間で
二重にグループ化する **MUST**。
**根拠**: radar/config_layered.py:55-82、radar/config.py:702-1612 ／ **検証**: 未検証 ／ **分類**: CORE
（§7-A17。**検証関数と列挙値の機構は存在するが使用キーが 0 件**）

### S1-CONF-002: 解決順は DB override → 環境変数 → 既定値、型変換は例外を投げない
**挙動**: 登録済みキーの解決は **MUST**: ① 不変フラグ・bootstrap フラグのいずれも立っていなければ DB override を型変換して
試し、非 None ならそれを返す。② 環境変数を型変換して試し、非 None ならそれを返す。③ 既定値を返す。**未登録キーは環境変数の
生文字列をそのまま返す MUST**（型変換も既定値も適用されない）。`0` / `0.0` / `False` / `""` / `[]` は有効値として扱う **MUST**
（None のみが「不在」）。DB 読み出しの例外および JSON 解析失敗は debug ログのみで None に落とす **MUST**。型変換は
`str` → `str(v)`、`int` → `int(v)` の後 `int(float(v))` を再試行、`float` → `float(v)`、`bool` → 真偽値はそのまま・他は小文字化後
`{"1","true","yes","on"}` に含まれるか、`list[str]` → リストはそのまま・他はカンマ分割 + strip + 空要素除去、`json` →
dict/list はそのまま・他は JSON 解析 **MUST**。**いかなる入力でも例外を送出しない MUST**。
**根拠**: radar/config_layered.py:127-168, 229-271 ／ **検証**: 未検証 ／ **分類**: **DEFECT-PRESERVE**（§8-DP15）

### S1-CONF-003: 検証は書き込み時のみで拒否のみ。読み出し時は一切検査しない
**挙動**: 書き込み時に ① 型変換不能 → 拒否、② 非 `str`/`list[str]` への空文字 → **override 削除に振り替え**、③ 列挙値・最小値・
最大値・検証関数のいずれかに反する → 拒否、④ 影響度が高のキーは**理由が必須** を検査する **MUST**。**丸め込み（clamp）は
行わない MUST**。**読み出し経路には検査が無く**、範囲外の環境変数や registry 変更前に書かれた DB 行はそのまま解決される。
**根拠**: radar/config_layered.py:337-355 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A18）

### S1-CONF-004: 解決結果は 30 秒の世代付きプロセス内キャッシュに載る
**挙動**: 解決結果を `(有効期限, 世代, 値)` の形でプロセス内にキャッシュし TTL 30 秒 **MUST**。キャッシュは再入可能
ロックで保護する **MUST**。値の設定・削除は当該キーのキャッシュを無効化し、registry への登録は**世代を進めて
全体を無効化する MUST**。
**根拠**: radar/config_layered.py:185-223, 395, 429 ／ **検証**: 未検証 ／ **分類**: CORE（§7-A19）

### S1-CONF-005: 変更監査台帳は値の前後を残すが、どの層が有効だったかを残さない
**挙動**: 設定変更は 時刻 / ドメイン / キー / 変更前値 / 変更後値 / 実行者 / 理由 / リクエスト ID を台帳に追記 **MUST**。値は
JSON 符号化し 8000 文字で、ドメイン 64 / キー 128 / 実行者 64 / 理由 300 文字で切り詰める **MUST**。**台帳追記の失敗は値の
書き込みをロールバックしない MUST**（NP3）。override 削除時は変更後値を空として記録 **MUST**。
**根拠**: radar/database.py:294-338, 4300-4338、radar/config_layered.py:383-394, 421-428 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP16）

### S1-CONF-006: 読み出し公開 API は型なしの単一関数のみ
**挙動**: 解決の公開 API は `Any` を返す単一の取得関数のみ **MUST**。型別の取得関数（int / bool / float）は
**存在せず**呼び出し側が毎回キャストする。併せて メタデータ取得 / 全キー列挙 / ドメイン一覧 / グループ一覧 /
再起動保留判定 / **実効層の判定（`db` / `env` / `default`）** / 値の設定 / override 削除 / キャッシュ無効化 を公開する **MUST**。
**根拠**: radar/config_layered.py:97-315, 438-457 ／ **検証**: 未検証 ／ **分類**: ACCIDENTAL（§7-A20）

### S1-CONF-007: 起動時に registry 既定値は DB へ実体化されず、環境変数が 1 度だけ複写される
**挙動**: registry の既定値は DB に書き込まれない **MUST**。代わりに 1 回限りの移行処理が、**環境変数に設定済みかつ非空**で、
可変・非秘匿・非 bootstrap で、既存の override 行が無いキーについて、**環境変数の値を DB override として複写する MUST**。
起動時に既存 DB 行を registry の範囲制約に照らし直す検査は**存在しない MUST**。未登録キーの解決は環境変数の生値を返す経路に
落ちるため、**登録解除されたキーの override 行は永久に読まれず**、設定・削除 API も未登録キーを拒否するため UI からも消せない。
**根拠**: radar/database.py:92-183, 2779、radar/config_layered.py:256-259, 330, 407 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP17 / DP18）

### S1-CONF-008: 【最重要】registry 登録キーの 95/98 は 3 層解決を経由していない
**挙動**: 現行の実態は以下である。**v3 では全 registry 登録キーが 3 層解決を経由する MUST**:

| 区分 | 件数 | 内容 |
|---|---|---|
| registry 登録キー | **98** | — |
| うち 3 層解決を経由して読まれるキー | **3** | `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS` / `LLM_TIMEOUT`（部分）/ `SCENARIO_IMPROVER_AUTO_APPLY_ENABLED`（部分） |
| **迂回① 本番モジュールでの環境変数直読み** | **58 キー / 65 箇所** | DB override が無効。§6.2 に全件 |
| **迂回② config.py の import 時定数** | **38 キー** | `from radar.config import X` で取り込まれ**プロセス生存期間中 凍結**。§6.3 に全件 |
| ①②の重複 | 33 キー | 直読みと定数の両方 |
| いずれでもない | 2 キー | `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS`（健全）/ `LLM_OVERRIDE_WINDOW`（**消費者ゼロの死んだキー**） |

**帰結**: 設定 UI は取得関数経由の実効値を表示し、書き込みは override 行と監査行を残すが、**98 キー中 95 キーに
ついて実行時は誰もその値を読まない**。アナリストが閾値を編集すると成功応答と新しい値の表示が返るのに、
採点エンジンは環境変数／import 時の値を使い続ける。
**根拠**: radar/config_layered.py:12-13（CI ゲート宣言）、§6.2 / §6.3 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（§8-DP19。D2 G-04 は `GPS_JAM_THRESHOLD` 1 件の問題として登録されているが、
**実際には登録キーのほぼ全数に及ぶ系統的欠陥である**。NP6 と NP5+8 の双方に直撃）

### S1-CONF-009: registry 既定値と直読み既定値が食い違うキーが 5 件ある
**挙動**: 迂回①のキーのうち直読み箇所のハードコード既定値が registry 宣言と一致しないものが 5 件あり、
**override を削除すると UI の予告と異なる挙動になる**: `PLUGIN_ENABLED`（registry `'*'` = 全ロード vs 直読み `''` =
何もロードしない、**意味論の反転**）、`CHECKHOST_NODES`（`[]` vs 5 ノード）、`TELEGRAM_ATTACK_KEYWORDS`（`[]` vs
9 キーワード）、`CHECKHOST_TIMEOUT_MS`（5000 vs 3000）、`TELEGRAM_MIRROR_POLL_INTERVAL`（300 vs 900）。
**根拠**: §6.2 の該当行 ／ **検証**: 未検証 ／ **分類**: **DEFECT-PRESERVE**（§8-DP20）

### S1-CONF-010: 3 層解決経由なのに registry 未登録という逆向きの欠陥が 2 件ある
**挙動**: 慢性検知のデューティ側 2 キー（`CHRONIC_DUTY_WINDOW_DAYS` / `CHRONIC_DUTY_THRESHOLD`）は**取得関数経由で
読まれているのに registry に登録が無い**。未登録キーの解決は環境変数の生値（未設定なら None）を返すため数値化が
例外になりモジュール定数へ黙って落ちる。値の設定 API も未登録として拒否するため**恒久的に上書き不能**である。
**根拠**: radar/conclusions/inconclusive_continuity.py:170,175 ／ **検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 F-15 と同一。§8-DP21）

---

## 6. 閾値カタログ / registry 迂回キー一覧

### 6.1 本書が仕様化した閾値（大半が config キーを持たないハードコード）

| 領域 | 閾値 | 値 | config | 条項 |
|---|---|---|---|---|
| baseline / T2・S1・S2 | バケット最小サンプル / 保持日数 / z 閾値・最小 n・mean 下限（§2 表） | 3 / 7・14・30 / 1.5 / 4・6 / 2・3 | 無 | 001-002 |
| S3 / T4 / O3 | 取得間隔 / 最小サンプル / std 相対床 / adj_z / 日次率 / スパイク比 / adj_delta 下限 | 14400s・21600s / 7 / 0.005 / 2.0 / 2.0% / 1.5 / −1.5 | 無 | 003-004, 006 |
| CAL / feed / Gauge | 先読み / 保持・件数 / 窓 / 成熟度サンプル / sev0・収斂上限 / レベル境界 | 7d / 48h・200 / 6h / 21 / 2.0・3.0 / 15・8・3 | 無 | 007, 009-011 |
| BG observer | 有効化 / 周期 / TTL / キュー上限 / フィード | false / 300s / 1800s / 200 / 3 本 | 環境変数のみ（**registry 未登録**） | 013-017 |
| 共起 / DBSCAN | 窓 / バケット / セル上限 / eps / min_samples | 30d / 24h / 5000 / 0.6 / 3 | 環境変数のみ（未登録） | 027-028 |
| シーケンス / 封鎖指数 | 窓 / 減衰床 / full・partial 加点 / 解釈境界 | 86400s / 0.3 / 3・2 / 7.0・4.0・1.5 | `SEQUENCE_*`（**迂回①**）/ 無 | 030-031 |
| what-if / SPOF | 合計上限 / TL1 床 / HIGH・MEDIUM / 冗長性 | 15 / 9 / 3・2 / FIRED ≥ 2 | 無 | 035, 037 |
| 適応 Z / 信頼度分布 | warmup 境界 / バケット幅 / 自動確定 | 50 / 0.1 / 0.80 | `ADAPTIVE_ZSCORE_MIN_SAMPLES`（**迂回②**）/ 無 / **無** | 038 |
| advisory / 位相 / followup / 診断 | 重み集中比 / 窓 / warmup 観測数 / 提案慢性 / 却下率 / dwell / 標本床 / 診断間隔 | 3.0 / 168h / 100 / 60d / 50% / 14d / 10 / 168h・下限 1h | 無 / 一部環境変数のみ | 024, 026, 039-040 |

**climate.py は結論に影響する閾値を 30 件以上ハードコードしており config registry に 1 件も載っていない**（NP6 の観点で最も遅れた領域）。

### 6.2 registry 登録済みなのに環境変数を直読みしているキー（迂回①、58 キー / 65 箇所）

`engine.py`: `DOMAIN_WEIGHT_CYBER`(20) `DOMAIN_WEIGHT_PHYSICAL`(21) `DOMAIN_WEIGHT_INFO`(22) `CONVERGENCE_FULL_BONUS`(104,216)
`CONVERGENCE_DUAL_BONUS`(105,217) `AMBUSH_ZSCORE_THRESHOLD`(283) `SYNC_DELTA_MS`(301) ／ `scoring.py`: `SEQUENCE_WINDOW`(182,195)
`SEQUENCE_FULL_BONUS`(226) `SEQUENCE_PARTIAL_BONUS`(230) ／ `routes/core.py`: `AIRSPACE_CLOSURE_THRESHOLD`(360)
`AIRSPACE_ANOMALY_THRESHOLD`(361) `GDELT_TONE_ALERT_THRESHOLD`(635) `GDELT_HISTORY_WINDOW`(636) ／ `intel_queue.py`:
`LLM_AUTO_CONFIRM_THRESHOLD`(35) `LLM_CONFIDENCE_MIN`(38) `INTEL_ITEM_TTL_HOURS`(53,118) `INTEL_MAX_ITEMS_PER_SOURCE_THEATER`(57)
`LLM_PENDING_AUTO_REJECT_HOURS`(62) `INTEL_AGE_DECAY_ENABLED`(66) `INTEL_AGE_DECAY_TAU_HOURS`(86) ／ `intel_corroboration.py`:
`CORROBORATION_WINDOW_HOURS`(105) `CORROBORATION_COOLDOWN_HOURS`(109) `CORROBORATION_MIN_SOURCES`(113)
`CORROBORATION_MIN_INDEPENDENCE`(117) ／ `auth.py`: `JWT_SECRET_KEY`(158) `JWT_ACCESS_EXPIRES`(205) `JWT_REFRESH_EXPIRES`(206)
`DEFAULT_ADMIN_PASSWORD`(312,354) ／ `notifications.py`: `NOTIFY_SLACK_WEBHOOK`(53) `NOTIFY_TEAMS_WEBHOOK`(55)
`NOTIFY_WEBHOOK_URL`(56) `NOTIFY_DEBOUNCE_SEC`(57) `NOTIFY_ENABLED`(58) ／ `plugin_loader.py`: `PLUGIN_DIR`(111)
`PLUGIN_ENABLED`(115) `PLUGIN_DISABLED`(116) ／ `database.py`: `JWT_REFRESH_EXPIRES`(5329) `INTEL_RETENTION_DAYS`(5368)
／ `calibration/`: `AUTO_APPLY_HIGH_COOLDOWN_HOURS`(auto_apply_tier_governor.py:313) `AUTO_CALIBRATION_TIER_CAP`(:718)
`SCENARIO_IMPROVER_AUTO_APPLY_ENABLED`(scenario_improver.py:257、**部分迂回**) `LLM_CONFIDENCE_MIN`(llm_confidence_calibrator.py:69)
／ `llm_embedding.py`: `LLM_EMBEDDING_MODEL`(98) ／ `llm_features.py`: `LLM_FEATURE_KILL_SWITCH`(341)
／ センサー: `CHECKHOST_NODES`(checkhost.py:15) `CHECKHOST_POLL_INTERVAL`(:19) `CHECKHOST_TIMEOUT_MS`(:20)
`GREYNOISE_API_KEY`(greynoise.py:15) `GPS_JAM_THRESHOLD`(gps_jamming.py:182) `GPS_JAM_CRITICAL_THRESHOLD`(:183)
`ISR_SURGE_THRESHOLD`(isr_hotspot.py:107) `NARRATIVE_BASELINE_DAYS`(rss_narrative.py:627) `NARRATIVE_ZSCORE_CRITICAL`(:707)
`NARRATIVE_ZSCORE_ALERT`(:709) `TELEGRAM_MIRROR_POLL_INTERVAL`(telegram.py:16) `TELEGRAM_ATTACK_KEYWORDS`(:17)
`TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD`(:22) `THREATFOX_API_KEY`(threatfox.py:23) `USGS_MIN_MAGNITUDE`(usgs_seismic.py:66)。
**57/58 は 3 層解決による読み出しがどこにも無い完全迂回**。

### 6.3 registry 登録済みだが import 時定数として凍結されるキー（迂回②、38 キー）

`ACLED_API_EMAIL` `ACLED_API_KEY` `ADAPTIVE_ZSCORE_ENABLED` `ADAPTIVE_ZSCORE_MIN_SAMPLES` `ADAPTIVE_ZSCORE_SENSITIVITY`
`AIRSPACE_WINDOW` `AIS_ANCHOR_RADIUS_KM` `AIS_DARK_GAP_THRESHOLD` `CACHE_EXPIRY` `CERTSPOTTER_API_TOKEN` `CF_API_TOKEN`
`DEFAULT_FOCUSED_SCENARIO` `DERIVATIVE_WINDOW` `DOMAIN_CAP` `FLASK_DEBUG` `GLOBAL_SIGNAL_WEIGHT` `HTTPS_PROXY`* `HTTP_PROXY`
`LLM_ENABLED` `LLM_HOST` `LLM_MODEL` `LLM_TIMEOUT` `NARRATIVE_POLL_INTERVAL`* `OPENSKY_CLIENT_ID` `OPENSKY_CLIENT_SECRET`
`OPENSKY_MIN_INTERVAL` `OWM_API_KEY` `PERSISTENCE_SAVE_INTERVAL` `SERVER_HOST` `SERVER_PORT` `SHOW_BACKGROUND_TL`
`SILENT_DIVERGENCE_THRESHOLD` `SSL_VERIFY` `SYNC_C2_THRESHOLD` `THEATER_BASELINE_MIN_SAMPLES` `THEATER_BASELINE_WINDOW`
`THREAT_LEVEL_HYSTERESIS_CYCLES`* `TRIANGULATION_BONUS`（`*` = 消費者が無い死にキー）。影響が大きいのは `DOMAIN_CAP` /
`GLOBAL_SIGNAL_WEIGHT`（採点式に直結）、`ADAPTIVE_ZSCORE_*`、`DEFAULT_FOCUSED_SCENARIO`。

### 6.4 逆向き — registry 未登録キーの直読み、および CI ゲートの不在

未登録キーの環境変数直読みは **159 種**（本番モジュールに現れるのは 92 種）。`RADAR_DB_PATH`（17 箇所、リポジトリ内で最多）、
`AUTO_JUDGE_*` 系（約 11 キー、自動判定サブシステムの調整面が丸ごと設定 UI から不可視）、`AUTO_TUNE_*` / `ATTENTION_*` /
`V2_*` フラグ群、`CORS_ALLOWED_ORIGINS` / `TRUST_PROXY_XFF` / `JWT_COOKIE_SECURE` / `RADAR_JWT_CSRF_DISABLED`、
`BG_SCORING_*` / `SCORE_REFRESH_SEC`、`BG_OBSERVER_*` 4 キー。`config_layered.py:12-13` は「登録キーの `os.getenv` 直読みが
無いことを CI が保証する」と宣言しているが**該当するゲートは存在しない**（`scripts/check_ci.sh` の 4 ゲートに含まれず、
`scripts/` 配下に registry を参照するスクリプトが 1 本も無い）。**v3 は設定到達性検査を CI ゲートとして持つ MUST**（S5-VERIF-013）。

---

## 7. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | S3 のみ「取得時に record → 分析時に get_baseline」の順で当該観測がベースラインに混入する | 他 4 指標と非対称。Z が構造的に過小になる |
| A2 | ベースライン剪定が「50 件ごと」だが剪定で長さが変わるため以降の周期がずれる | 保持期間が近似にしかならない |
| A3 | T2 の silence は severity 上限 1、surge は 2 | 「国営メディアの異常な沈黙」は開戦直前の古典的兆候。NP1 では上限を揃えるべきでは |
| A4 | S1 の theater 欄に ISO2 でなく空港コードが入る | Gauge の収斂加点で country 集約が空港粒度に分裂する |
| A5 | S2 と theater 未指定の CAL が theater 空文字を共有し、時単位 dedup で互いに潰し合う | 同時刻の複数予定イベントが 1 件に消える |
| A6 | 予定イベントを import 時に 1 度だけ読む | geo_data.json 更新に再起動が要る |
| A7 | Gauge の収斂写像に `economic` という第 4 ドメインが登場する | 3 ドメイン規約との整合。S3 を寄せるか 4 ドメインを正式化するか |
| A8 | 成熟度の母集団に S2 が入らず S2 用の分岐が到達不能。宣言（exact 到達率）と実装（21 件以上の比率）も不一致 | S2 の成熟が severity cap に反映されない |
| A9 | 単一 country 検出が許可リストの並び順に依存する | 同一記事でも呼び出し側の並びで結果が変わる |
| A10 | スコア内訳が 3 ドメイン外のエントリをカウンタも残さず捨てる | LLM・補助ドメインの寄与が UI から消える |
| A11 | what-if の加点入力に上下限検査が無く、負値・巨大値・非数値を受け付ける | 非数値は 500。境界の意図確認 |
| A12 | SPOF の「代替手段あり」欄が常に偽の固定値 | 未実装のまま UI に出ている |
| A13 | SPOF はセンサーのエラー文字列を無加工で返す（データ状態 endpoint は 1 行目 100 文字に切詰） | 情報漏洩面の非対称 |
| A14 | Welford 分散が `n == 1` で 0.0（未定義でなく） | 「サンプル 1 件で分散 0」は NP5+8 的に誤り |
| A15 | advisory の空リストが「健全」と「対象シナリオ無し」を区別しない | 結論不可の表明が要る |
| A16 | 自動確定閾値 0.80 が DB 層にハードコードされ intel キューの実閾値と独立に動く。空バケットも出力されない | 乖離検知の仕組みが無い |
| A17 | registry 登録全体が 1 つの例外捕捉に包まれ、失敗時は部分 registry で起動する | 設定面の silent failure。起動失敗にすべきでは |
| A18 | 読み出し経路に範囲検査が無く、範囲外の環境変数・古い DB 行がそのまま通る | 書き込み時のみの検査で足りるか |
| A19 | キャッシュ一括 flush の外部経路が撤去済で docstring だけが残る | 30 秒 TTL で足りるか、明示 flush を復活させるか |
| A20 | 型別取得関数が無く呼び出し側が毎回キャストする | registry の型宣言が実行時に効いていない |

---

## 8. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | S3 の `daily_change_pct` が実際は「4 時間前との差」 | 期間を名前と単位型で表す **MUST** | — |
| DP2 | T4 のキャッシュに失効が無く、Trends 到達不能後も無期限にイベントを出す | 観測の鮮度が結論に反映される **MUST** | — |
| DP3 | O1 が定義域外の severity 3 を出し Gauge では 2 に潰れるが API では 3 のまま | severity 尺度を単一定義に **MUST** | — |
| DP4 | O3 のトーン履歴が書かれるだけで読まれない | 未使用状態を持たない **MUST** | — |
| DP5 | 気候サイクルが採点ティック内で外部 HTTP を同期実行し、失敗が debug に消える | 外部 IO は採点経路外 + 失敗を AP3 に露出 **MUST** | B-01 と同型 |
| DP6 | 気候イベント DB が剪定されず無限に成長（剪定 API に呼び出し元が無い。削除もトランザクション外） | 全永続表に保持方針 **MUST** | — |
| DP7 | followup watch が「検査不能」を「条件不成立」と同一視 | 第 3 状態 `unknown` **MUST** | — |
| DP8 | SITREP が「直近 1 時間」と表示しつつ 12 サイクル（約 24 分）の統計を出す | 表示窓と計算窓の一致 **MUST** | E-18 と同型 |
| DP9 | 同名 `velocity` に回帰推定と単純差分の 2 実装が併存し値が一致しない | 単一実装 **MUST** | A-02 |
| DP10 | SALUTE / 天候ブリーフが無データを「平穏」と描き、結論不可を表明できない | 欠測と平穏を区別する **MUST** | — |
| DP11 | 無データ時の応答方針が endpoint 間で 5 通りに分裂 | 結論不可の表現を単一化 **MUST** | — |
| DP12 | 反実仮想（what-if / SPOF）が confidence と signal_source を落として再構築し、本番より高スコアに偏る | 反実仮想は本番と同一入力型 **MUST** | — |
| DP13 | シナリオ位相 endpoint が未定義識別子 `_scenario_label` を呼び、シナリオが 1 件でもあれば必ず 500。観測数も上限 500 で飽和 | — | **D2 未登録の新規欠陥** |
| DP14 | IP 照会がエラー種別を英語散文の部分一致で分類 | 型付きエラー **MUST** | — |
| DP15 | 型変換の `str` / `bool` / `list[str]` が None を返せずフォールスルーが働かない（env の空文字が既定値を潰す） | 全型で「不在」を表現可能に **MUST** | — |
| DP16 | 設定監査台帳に実効層の列が無く、1 編集で 2 行が異なるドメイン名で残る | 実効層を記録 + 単一行 **MUST** | — |
| DP17 | 起動時移行が環境変数を DB override に複写し、実効層判定が `db` を返す | env と分析者編集を区別 **MUST** | — |
| DP18 | 登録解除されたキーの override 行が永久に読まれず UI からも消せない | 孤児行の回収 **MUST** | — |
| DP19 | **registry 98 キー中 95 キーが 3 層解決を経由しない**（直読み 58 / import 定数 38） | 全登録キーが 3 層解決経由 **MUST** + CI ゲート **MUST** | **G-04 の一般化**、A-13 |
| DP20 | registry 既定値と直読み既定値が 5 件不一致（1 件は意味論反転） | 既定値の単一の所在 **MUST** | F-13 と同型 |
| DP21 | 取得関数経由なのに registry 未登録の 2 キーが恒久的に上書き不能 | 登録漏れを CI で検出 **MUST** | F-15 |

---

## 9. テストトレーサビリティ

| テストファイル | 件数 | 対応条項 | GAP |
|---|---|---|---|
| `tests/test_background_observer.py` / `test_rss_extractor.py` / `test_followup_watch.py` | 15 / 56 / 17 | S1-ANLYT-013〜018, 019〜022, 023〜025 | 無し |
| `tests/test_diagnostics.py` / `test_cooccurrence.py` / `test_dbscan_cluster.py` | 6 / 15 / 18 | S1-ANLYT-026, 027, 028 | 無し |
| `test_engine.py`（BlockadeIndex / Sequence 系）／ `test_scenario_scoring.py::TestDeriveTL` | 委譲先 | S1-ANLYT-030, 031, 035 | 無し |
| **`radar/climate.py`** | **0** | S1-ANLYT-001〜012（**全 12 条項が未検証**） | **GAP-C** |
| **`radar/routes/analytics.py`** | **0** | S1-ANLYT-029〜041（**全 13 条項が未検証**） | **GAP-A** |
| **`radar/config.py` / `config_layered.py`** | **0** | S1-CONF-001〜010（**全 10 条項が未検証**） | **GAP-F** |

上記 6 テストファイル（127 件）はいずれも本書の条項に対応し、**対応条項の無いテストは無い**。

- **GAP-C**: Climate Engine 全体（12 条項）。Gauge のレベル境界・成熟度・severity cap・7 指標の全閾値が無テスト。
  v3 では最低限 Gauge 式・成熟度・severity cap・各指標の発火境界を pin する **MUST**
- **GAP-A**: 分析 endpoint 全体（13 条項）。what-if / SPOF の反実仮想は「本番エンジンを呼ぶ」ことが唯一の正しさの
  根拠なのに等価性を検査するテストが無い。DP13 が見逃されたのも同じ原因
- **GAP-F**: 3 層解決全体（10 条項）。解決順・型変換・キャッシュ世代・監査追記のいずれも無テスト。
  **DP19 のような系統的欠陥が 98 キー規模で成立し得たのはこれが原因**
- **GAP1 / GAP2**: BG observer の `raw_score` 3 段写像（0.4+0.05n / 0.45 / 0.25）が未 pin ／ 分析 endpoint の無データ時応答（DP11 の 5 分岐）が未検証

---

## 10. 未決事項

1. **Climate Gauge のレベル境界 15 / 8 / 3 の根拠が不明**。コード・コメント・設計文書のいずれにも導出が無い。
   climate.py で唯一「結論らしきラベル」を出す箇所なのに TL のような導出根拠を持たない。**オーナー確認が必要**
2. **Climate Gauge と TL の関係が仕様レベルで未定義**。「間接指標が HOT なのに TL5」をアナリストがどう読むべきかが
   規定されていない。NP4 の観点では Gauge を結論に接続するか「参考情報」と明示宣言するかの裁定が要る
3. **S3 の `economic` ドメイン**を 3 ドメイン体系にどう位置づけるか（§7-A7）。4 ドメイン化は収斂判定に波及する。
   併せて指標間の独立性も未検証（T2 と O3 は写像上 info に畳まれるが S3 は独立に数えられる。NP2 の定義との整合が未確認）
4. **迂回②（import 時定数 38 キー）の修正手順が未設計**。`from radar.config import X` は数百箇所あり機械的置換の影響範囲が
   D1 では未評価。P 段階で「遅延評価アクセサへの一括移行」の可否判断が要る
5. 本書は climate.py / analytics.py / config.py について**設計文書との突合を行っていない**（一次ソースは実装のみ）。
   E-18（記述ドリフト）の前例に照らし docstring の記述は根拠に採用しなかった
