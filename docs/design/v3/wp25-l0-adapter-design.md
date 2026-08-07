# WP-2.5/2.6/2.7 — L0 取得層 詳細設計

**位置づけ**: P3 が WP-2.7 に課す「着手時に詳細設計 1 枚を先行させる」の成果物。本書は WP-2.5（取得カーネル）/
WP-2.6（cyber・physical アダプタ）/ WP-2.7（info・LLM・補助アダプタ）の 3 WP を貫く設計を確定する。
**本書の決定は実装既定**。覆す場合は ADR として記録する。

**前提文書**: P1 §4（L0 構造）、P6 O-17（収斂機構の統合とインテルの位置づけ）、S1-sensors-cyber-physical、
S1-sensors-info-llm、D1-sensors §4（外部 API 知識 20 項目）、S4-NF-003/004/061、D2 A-02/A-10/B-01/D-02/F-01/F-02/F-09。

**既存 v3 資産との関係**: 本層は K 層（`v3/kernel`）の型を語彙とし、出力は L1（`v3/ledger`）へ落ちる。
L2（`v3/scoring`）とは直接結合しない — アダプタはスコアを作らない。WP-2.8 のパリティハーネス
（`v3/parity`）は L1 の観測台帳から両系を駆動するため、**本層の出力形が変わってもパリティの駆動形は変わらない**。

---

## 1. 取得カーネルの構造

### 1-1. パッケージ配置

```
v3/fetch/            取得カーネル（共有。ここを通らない外界アクセスは存在しない）
  client.py          唯一の HTTP 出口。requests を import する v3 で唯一のモジュール
  policy.py          timeout / retry / backoff / courtesy delay の宣言型
  breaker.py         サーキットブレーカー（純粋な状態機械。状態は値）
  limiter.py         レートリミッタ（アダプタ横断の共有 min-interval を含む）
  parse.py           tolerant RSS/XML パーサ + feed 死活分類
  llm.py             LLM 投入（プロンプト構築 → 投入 → tolerant 解析 → 確信度）
  recorder.py        取得記録（fetch_log / llm_call）
  registry.py        アダプタ登録簿。識別子は型であって文字列リテラルではない
  schedule.py        取得期日の判定（純関数）
  runner.py          1 取得サイクルの実行。**スレッドは持たない**
v3/adapters/         34 アダプタ（宣言 + 正規化フックのみ）
  cyber/ physical/ info/ llm/ meta/
v3/matching/         言語非依存照合（F-09 の解消。純粋・I/O なし）
```

**決定**: パッケージ名は `v3/fetch`。`v3/sensors` は採らない — 「センサー」は現行系の語であり、
v3 の L0 が持つのは *取得* の責務であって計測器ではない。アダプタ側を `v3/adapters` と分けるのは、
**共有基盤とアダプタで守るべき規律が違う**（後者は I/O を書けない）ため、規律検査を
ディレクトリ単位で分けられるようにする。

### 1-2. 実行モデル — import は不活性、スレッドは合成ルートが持つ

**決定**: `v3.fetch` および `v3.adapters` の **import は一切の副作用を持たない**。
スレッド・グリーンレット・ソケット・タイマーを生成してはならない。

**根拠**: 現行 `radar/__init__.py` は import 時に Flask app を起動し migration を走らせ約 40 スレッドを
生成する。この構造が (a) テストを本番 DB に接続させ、(b) WP-2.8 のパリティ駆動をサブプロセス隔離に追い込み、
(c) B-01（bg_observer が独自 daemon thread から CB を迂回）を可能にした。
**独自スレッドから外界へ出る経路が無ければ B-01 は表現できない**（P1 §4）。

実行の形:

```
runner.run_due(now, adapters, schedule_state, client, ledger) -> FetchCycleResult
```

- `run_due` は**関数**である。呼ぶと 1 サイクル走り、値を返す。常駐しない。
- 並行度は**呼び出し側（合成ルート）が決める**。合成ルートは `v3/runtime/`（WP-4.1 で新設）に置き、
  スレッドプール・シグナルハンドラ・停止手順を**そこだけ**が持つ。
- したがって「テストは 1 スレッドで全アダプタを回せる」。これは検証可能な性質であり、
  境界テスト（`import v3.fetch` でスレッド数 1）で守る。既存 4 パッケージ（ledger / etl / scoring / parity）と同じ規律。

### 1-3. 取得期日 — 揮発カウンタを禁じる（F-01）

**決定**: 取得・周期ジョブの起動判定は **L1 に永続した `last_run_at` と cadence から純関数で導く**。
プロセス内カウンタに依存してはならない。

**根拠**: F-01 実測 — 保守ワーカが毎時 `_cycle += 1` し `_cycle % 24 == N` でジョブを割り当てるが、
`_cycle` は再起動で 0 に戻る。稼働が N 時間未満で再起動されると **offset N 以降のジョブは一度も走らない**。
2026-08-02〜03 の頻繁な再起動期間中、offset 10-12 は実行されていない公算が高い。

形:

```
schedule.due(now, last_run_at, cadence: Window) -> bool          # 純関数
schedule.next_run_at(now, last_run_at, cadence: Window) -> float # 純関数
```

cadence は K 層の `Window`（`declared_days` + `cadence_sec`）で表す。**素の秒数を受け取らない** —
F-06（30 日と宣言して 30 サンプルを保持）と同型の取り違えを構造的に閉じる。
`last_run_at` の保存は L1 の責務（新表 `fetch_schedule`、§1-6）。

### 1-4. HTTP 依存の裁定 — requests を採る

**決定**: HTTP クライアントは **`requests`**。`v3/fetch/client.py` **のみ**が import する。
stdlib `urllib.request` / `httpx` / `aiohttp` は採らない。

**根拠**:
1. **並走期間のリスク最小化**。cutover まで旧系と v3 は同一プロセス群で並走しうる。旧系は requests +
   gevent monkey-patch で運用実績がある。第 2 の HTTP スタックを持ち込むと、
   monkey-patch 適用範囲・コネクションプール・TLS 設定が二重化し、**パリティ差分の原因候補が増える**。
2. **依存の広さは 1 ファイルに閉じる**。S4-NF-061 が要求するのは「共有クライアントの採用を構造的に強制」であり、
   ライブラリの選択そのものではない。出口が 1 モジュールなら差し替えは 1 ファイルの変更で済む。
3. httpx の非同期は本層に不要。並行度は合成ルートのスレッドプールが与える（§1-2）。

**強制の仕方**（S4-NF-061 が「型で到達不能にするか CI で直接呼出しを禁じるか」と定める二択のうち後者を採る）:
`scripts/check_kernel_discipline.py` を拡張し、`v3/` 配下で
`requests` / `httpx` / `aiohttp` / `urllib.request` / `http.client` / `socket` の import を
**`v3/fetch/client.py` 以外では検出即 fail** とする。既存の legacy-import / direct-env-read 検査と同じ機構に載る。

禁止を機械化する根拠は A-10 の実測である — `_safe_get`/`_safe_post`/`handle_rate_limit` の呼出は **0 件**、
全 28 fetch 実装が raw requests、429 ハンドラ採用は 36 センサー中 8 基。
S4-NF-061 が明記するとおり「基底に足すだけ」では採用されない実績がある。

### 1-5. サーキットブレーカーとレート制限

**決定**: CB は**全取得経路に適用**し、例外を作らない（S4-NF-003/004、B-01 の解消）。
CB 判定は**取得サイクルにつき厳密に 1 回**（複数回呼ぶと HALF_OPEN のプローブ枠を多重消費する）。

CB は **純粋な状態機械**として実装する — `breaker.step(state, outcome, now) -> BreakerState`。
状態は値であり、`runner` が保持して L1 に永続する。閾値（失敗 5 / 初期遅延 300s / 最大 3600s）は
K 層 `Threshold.pinned` で開示する（S1-SCORE-038 が現行値を pin 済み）。

レートリミッタは **アダプタ横断の共有 min-interval** を表現できなければならない。
根拠: OpenSky は 3 センサーが 1 つのリミッタを共有する（D1 §4）。
したがってリミッタのキーは adapter_id ではなく **`rate_limit_group`**（アダプタが宣言する）とする。
courtesy delay 群（RIPE Stat 0.3s / GDELT 0.5s / GreyNoise 0.5s / PeeringDB 10s / OONI 0.5s）は
同機構の 1 パラメータとして宣言する。

### 1-6. 取得の記録 — S5-VERIF-022 への前方互換

**決定**: 取得は 2 系統で記録する。L1 に記録用の新表を 2 つ追加する（§1-3 の `fetch_schedule` と合わせ計 3 表。裁定要求 3）。

| 表 | 1 行の内容 | retention | 必須性 |
|---|---|---|---|
| `fetch_log` | adapter_id, requested_at, url_sha256, http_status, latency_ms, outcome, body_sha256, breaker_state | 60 日（信号台帳に合わせる） | **常時 MUST** |
| `llm_call` | prompt 全文, prompt_sha256, response 全文, model_id, temperature, adapter_id, at | 365 日（結論台帳に合わせる） | **LLM 経路で MUST** |

`llm_call` が必須である根拠は S5-VERIF-022: パリティ実行時に LLM は
**記録済み応答を `prompt_sha256` で引き当てて再生 MUST**、実 LLM を呼んでは MUST NOT。
再生に必要な記録（プロンプト・応答本文・モデル ID・温度）が欠ける結論型は
**パリティ対象外として明示 MUST**。現行は `prompt_sha256` は永続化されるが LLM 注釈経路は
`prompt_version` しか記録しない（E-08）。**本層で記録を作らなければ L3 の再生は原理的に不可能になる**。

**生 body の保存は既定 OFF**。アダプタが `record_body=True` を宣言した場合のみ、7 日 retention の
別表に保存する。根拠: 60 日 × 34 アダプタの全 body 保存は S3 試算の外にある容量判断であり、
承認されていない。同一性の証明は `body_sha256` で足りる。

### 1-7. tolerant パーサと feed 死活

**決定**: RSS/XML の解析は `v3/fetch/parse.py` の 1 実装のみ。2 段パース
（defusedxml strict → lxml `recover=True`）と feed 死因分類（`returns_html` / `rss_empty` / `unparseable` /
`http_error` / `geo_block`）を持つ。アダプタは**パーサを選べない**。

**根拠**: A-02 実測 — RSS 取得/パースが 4〜5 複製し、**tolerant パーサは diplomatic のみ**が持つ。
つまり同じ壊れ方の feed が、どのアダプタから来たかで解析可否が変わる。
死んだ feed も台帳に残す方針（JP_MOFA=404/WAF、CN_MFA=returns_html、RU_MFA=geo-block、
KCNA=間欠 rss_empty）は D1 §4 の資産であり、**feed 死活台帳として L1 に持つ**（`fetch_log.outcome` に分類を格納）。

---

## 2. アダプタ宣言モデル

### 2-1. 宣言できるもの / できないもの

**決定**: アダプタが宣言するのは **何を取りに行くか（`requests`）** と **どう正規化するか（`normalize`）** の 2 つだけ。
timeout・リトライ・CB・レート制限・パーサ選択・出力先は**宣言できない**。

```python
@dataclass(frozen=True)
class SourceAdapter:
    adapter_id: AdapterId                 # 型。文字列リテラルではない（F-02）
    category: Category                    # cyber | physical | info | llm | meta
    requests: tuple[RequestSpec, ...]     # WHAT
    cadence: Window                       # K 層 Window（素の秒数を受けない）
    normalize: NormalizeFn                # HOW to normalize
    auth: AuthRequirement                 # none | api_key(key_id) | oauth2(...)
    rate_limit_group: str                 # 共有リミッタのキー（OpenSky 3 基）
    freshness_horizon: float              # 観測の鮮度地平（K 層 Evidence へ）
    record_body: bool = False
    knowledge_refs: tuple[str, ...] = ()  # D1 §4 の知識項目 ID（§3 で照合）

NormalizeFn = Callable[[FetchedPayload, NormalizeContext],
                       tuple[ObservationDraft, ...]]
```

`RequestSpec` は URL テンプレート・メソッド・パラメータ・期待 content-type・ページング方針の宣言。
**`RequestSpec` は関数を持たない** — 「取りに行き方」を式で書けてしまう余地を残さない。

### 2-2. アダプタが I/O を書けないことの構造的保証

4 重に閉じる。宣言だけでは A-10 の再発を招くため、**どれか 1 つが破られても残りが効く**構成にする。

| # | 機構 | 何を防ぐか |
|---|---|---|
| 1 | `normalize` は**既に取得済みのバイト列**を受け取る。クライアントハンドルはスコープに存在しない | 正規化中の追加取得 |
| 2 | 規律ゲート拡張（§1-4）: `v3/adapters/` 配下の HTTP/socket ライブラリ import を fail | 独自クライアントの生成 |
| 3 | 境界テスト: 各アダプタモジュールの import でスレッド 0・radar import 0（既存 4 パッケージと同形） | import 時副作用 |
| 4 | 実行時テスト: `socket.socket` を例外送出に差し替えた状態で全 `normalize` を fixture 実行 | 経路を問わない外界アクセス |

**決定**: アダプタは **L1 へ書かない**。`normalize` は `ObservationDraft`（純粋な値）を返し、
**`runner` が** K 層 `Evidence` で包んで `LedgerStore.append_signal` する。

**根拠**: 現行はセンサーが自分で `set_cache` し、ベースラインを in-mem で持ち、第 2 SQLite まで作った
（A-03 / A-09）。書き込み口をアダプタに与えなければこの系統の欠陥は表現できない。
副次的な利得として、**鮮度地平の設定箇所が 1 つになる** — B-03（STALE 印を無視した消費）の入口を塞ぐ。

### 2-3. 識別子の型（F-02 の解消）

**決定**: `AdapterId` は登録簿から生成される型付き値。文字列リテラルによる許可リストを作らない。

**根拠**: F-02 実測 — `_FORCE_SYNC_SENSORS` は `"cf"` / `"ioda"` を含むが実登録名は
`"cloudflare_radar"` / `"ioda_bgp"`。突合が文字列一致であるため、**最重要 2 センサーが force 取得から
永久に外れていた**。参照整合性を型で持てば、この不一致は書けない。

---

## 3. 34 アダプタ棚卸しとバッチ割当

（本節の表は S1-sensors 2 書からの転写。**「K」欄は D1 §4 の 20 項目のどれが該当するかを示す** —
P3 が「再発見コストが最大の資産」と呼ぶ知識の着地先を、アダプタ単位で明示するのが本節の主目的。）

### 3-0. 母数と条項範囲の確定

**決定**: 移植母数は **34**（S1 2 書が個別条項で規定する全アダプタクラス。無効化済みを含む）。

| 書 | 条項接頭辞 | 範囲 | 件数 |
|---|---|---|---|
| S1-sensors-cyber-physical | `S1-SENSBASE-` / `S1-SENS-` | 001–015 / 001–041 | 15 + 41 = **56** |
| S1-sensors-info-llm | `S1-INGEST-` / `S1-SENSI-` | 001–020 / 001–054 | 20 + 54 = **74** |

いずれも欠番なし。34 という数は S1-SENSBASE-002 の自己申告（「現行 34 基でオーバーライドゼロ」）と一致する。
**他文書の 39 / 28 との差は母数定義の差**であり、本書は以下を正典とする:
- **39**（D5 §4.2 引用）: 本 2 書が個別規定しない補助部品を含む数。`opensky_auth` のような共有部品が
  別台帳で 1 基として数えられている。本書は共有部品をアダプタとして数えない（§1-5 の共有リミッタとして扱う）
- **28**（S1-SENSBASE-013）: **生 HTTP を自分で叩く実装数**。無効 2 基と、HTTP を持たないメタ 3 基
  （`hacktivist_intel` / `ground_osint` / `convergence_tracker`）を除いた population

**バッチ割当は書の境界と完全に一致する**: cyber 7 + physical 15 = **22 → WP-2.6**、
info 6 + LLM/meta 6 = **12 → WP-2.7**。P3 の想定どおりであり、境界を動かす理由が無い。

### 3-1. D1 §4 外部 API 知識 20 項目の ID 付与

K01 OpenSky OAuth2 + 3 基共有リミッタ + 429 は 120s 以下のみリトライ ／ K02 AISHub はレート制限時に HTTP 200 + 空 body ／
K03 check-host 二段 API + レイテンシ penalty 撤去 + 深夜 UTC 保守帯 ／ K04 OONI 3 連続空で degraded ／
K05 CT log 多重ソース + 「200-empty は権威ある成功」 ／ K06 IHR は www.ihr.live ミラー ／
K07 外交 RSS 死活台帳（JP_MOFA/CN_MFA/RU_MFA/KCNA） ／ K08 2 段パース + feed 死因分類 ／
K09 CISA の RSS URL rot ／ K10 ThreatFox は get_iocs にも Auth-Key 必須 ／
K11 GreyNoise v2 GNQL 410 + community 日次 quota + enterprise 分岐 ／ K12 gpsjam は manifest から最新日を発見（日次ラグ） ／
K13 t.me/s/ は UA プール + 403/429 指数バックオフ ／ K14 無料 NOTAM API は存在しない ／
K15 courtesy delay 群（RIPE 0.3s / GDELT 0.5s / GreyNoise 0.5s / PeeringDB 10s / OONI 0.5s） ／
K16 USGS 核実験候補基準（mag≥4.0 + 浅発 + 敵対国領内） ／ K17 NOAA 宇宙天気（Kp≥6 / X-ray M 以上で誤検知抑制） ／
K18 GDELT トーンの曜日バイアス → DOW 別ベースライン ／ K19 IODA + CF Radar の二重ソース ／
K20 渡航勧告 3 政府 3 形式（RSS/Atom/HTML）

### 3-2. WP-2.6 — cyber 7 + physical 15 = 22 アダプタ

複雑度は**共有カーネル完成後の移植コスト**で評価する（S=フィールド抽出のみ / M=統計導出 or 複数エンドポイント合成のいずれか /
L=両方、または固有ルール群が大きい）。

| # | adapter | 上流 | S1 条項 | K | 複 | DEFECT-PRESERVE / 処分 |
|---|---|---|---|---|---|---|
| 1 | `cloudflare_radar` | Cloudflare Radar v4（4 endpoint） | SENS-001..003 | — | M | **DP8**: 採点層の module-level dict へ side-write。→ **廃止**。出力面は `ObservationDraft` のみ（§2-2） |
| 2 | `ripe_bgp` | RIPE Stat | SENS-004..007 | K15 | L | **DP3** baseline 揮発 → L1 永続。**DP4** HOD Z / 最小二乗が 3 重複 → L1 ベースライン基盤 + L2 `trend.py`（実装済）に一本化 |
| 3 | `greynoise` | GNQL + Community | SENS-008..011 | K11,K15 | S | A10（NOISE_DOMINANT が自分しか抑制しない）→ 抑制は L2 gating の責務。アダプタは観測を出すのみ |
| 4 | `ooni_censorship` | OONI web_connectivity | SENS-012..013 | K04,K15 | M | degraded mode は**カーネルの適応 cadence に一般化**（§1-3）。NP3 の良い先例として保存 |
| 5 | `threatfox` | abuse.ch ThreatFox | SENS-014 | K10 | S | A11（APT タグと国名タグを等価計上）→ ACCIDENTAL、現行踏襲 |
| 6 | `ct_log` | CertSpotter → crt.sh（+ certstream WS 既定 OFF） | SENS-015..018 | K05 | **L** | A18: `gov_count` が恒久 0 の死にフィールド → **出力から削除** |
| 7 | `apt_intel` | 政府 CERT RSS 5 本 | SENS-019..021 + INGEST-001..020 | K09 | M | **DP9** strict のみ・死活診断なし → 共有パーサへ（§1-7）。**B-05** dedup 揮発 → L1。A19 confidence 床の literal 複製 → `Threshold` 参照に統一 |
| 8 | `opensky` | OpenSky state vectors | SENS-023（共有 SENS-022） | K01 | S | DP5 系（失敗時 cache 保持）→ §1-6 の記録分離で解消 |
| 9 | `isr_hotspot` | OpenSky | SENS-024 | K01 | S | A12: callsign prefix に一般語（NAF/RAF/SAM/CARGO 等）→ ACCIDENTAL、現行踏襲 |
| 10 | `mil_support_air` | OpenSky | SENS-025 | K01 | S | A12 同上 |
| 11 | `ais_maritime` | AISHub guest | SENS-026 | K02 | **L** | **DP3** 船舶履歴が in-process のみ → 再起動で dark-gap 検知能力が消える。L1 永続 **MUST** |
| 12 | `gps_jamming` | gpsjam 日次 H3 tile CSV | SENS-027 | K12 | M | **DP7（本仕様が新規発見）**: 閾値 3.0/7.0 が 0–1 比率と単位不整合で**恒久無発火**。v3 は K 層 `Ratio` で単位を型に持たせる（F-08 と同型。WP-0.2 で現行系は修正済） |
| 13 | `notam` | （実行可能な無料 API 無し） | SENS-028 | K14 | S | **無効のまま移植**。FAA payload 形式は資産として宣言に残す。A13: 無効基が registry 席を占める件は、v3 では `enabled=False` 宣言 + スレッド不使用（§1-2）で無害化 |
| 14 | `nasa_firms` | **実体は NASA EONET** | SENS-029 | — | S | **DP6**: `sensor_id` が実ソースを偽る（NP6 違反）→ **`nasa_eonet` に改名**。旧 ID は ETL の別名として 1 世代のみ残す |
| 15 | `openweather` | OpenWeatherMap | SENS-030 | — | S | DP5 系（失敗時に空で上書き）→ §1-6 |
| 16 | `usgs_seismic` | USGS earthquake feed | SENS-031..032 | K16 | M | A14: 抑制（海底ケーブル近接）と検知（核実験候補）が同居 → **抑制は L2 gating へ分離**（S1-PIPE-009 の呼出側抑制フラグとして供給） |
| 17 | `space_weather` | NOAA SWPC（Kp + X-ray、2 並列） | SENS-033..034 | K17 | M | A15: 両 endpoint 失敗でも成功記録（fail-open で Kp=0）→ **fail-closed 化**。NP1 上、欠測を「静穏」と読むのは許容しない |
| 18 | `peeringdb_ixp` | PeeringDB | SENS-035 | K15 | S | CORE。指摘なし |
| 19 | `ihr_health` | IIJ IHR（3 並列） | SENS-036 | K06 | S | **無効のまま移植**。2026-Q1 の API 契約変更で慢性 400、かつ IODA/ripe_bgp と `signal_source="bgp"` が重複（S1-SCORE-008 の MAX dedup 対象） |
| 20 | `ioda_bgp` | IODA v2 → CF Radar fallback | SENS-037 | K19 | M | A17: `physical` 分類だが `ripe_bgp`（cyber）と signal_source を共有 → **ドメイン分類の裁定は L2 の収斂計数に効く**。現行踏襲とし、裁定は cutover 後 |
| 21 | `check_host` | check-host.net（二段） | SENS-038..040 | K03 | **L** | **DP4** HOD Z が ripe_bgp とほぼ重複 → 一本化。**DP3** レイテンシ履歴が class 変数 → L1 |
| 22 | `ripe_atlas` | RIPE Atlas（2 並列） | SENS-041 | K15 | **L** | **DP3** prev probe 数が揮発 → L1 |

**WP-2.6 内訳**: S=11 / M=7 / L=4。**無効 2 基（notam / ihr_health）は宣言のみ移植し fetch 経路を持たない。**

### 3-3. WP-2.7 — info 6 + LLM/meta 6 = 12

| # | adapter | 上流 | S1 条項 | K | 複 | DEFECT-PRESERVE / 処分 |
|---|---|---|---|---|---|---|
| 23 | `gdelt` | GDELT tone search（1d + 28d 並列） | SENSI-001..004 | K15,K18 | M | A7: DOW 標準偏差の床 0.5 がハードコードで出典不明 → `Threshold.pinned` で出典を開示 |
| 24 | `rss_narrative` | RSS 群 + LLM クラスタ解析 | SENSI-005..011 + INGEST-* | K08 | M | A8: 初回シグナル Z=3.0 が env 専用で registry 外 → **NP1 直結の値なので運用可変キーに登録**（O-18 の (a) 群） |
| 25 | `telegram_mirror` | `t.me/s/` スクレイプ | SENSI-012..018 | K13 | M | **DP6（本仕様が新規発見）**: ベースライン保持数が「日数」を標本数上限に流用（30 標本 ≈ 15h）。**F-06 と同型**。v3 は K 層 `Window`（日数 × cadence）で表現し、型で再発不能にする |
| 26 | `tor_metrics` | Tor Onionoo | SENSI-019..021 | — | M | DP12 prev 揮発 → L1 |
| 27 | `travel_advisory` | 米 RSS / 英 Atom / 加 HTML | SENSI-022..025 | K20 | **L** | A1 初回観測が構造的に検知不能 / A2 昇格追跡が揮発 / **A3 英パーサの最終 fallback「body に travel を含む → level 2」がほぼ全記事に当たり収斂の母数を汚す** → **A3 は fallback 廃止**（`unknown` を返す）。NP2 上、偽の裏付けは裏付けより悪い |
| 28 | `bg_observer_rss` | RSS 群（regex のみ、LLM/API 鍵に依存しない） | SENSI-026..030 | K08 | S | **DP1（B-01）**: 専用スレッドで CB を迂回 → §1-2/§1-5 で構造的に消える。A10「取得成功だが 0 件」を障害と同一計上 → **feed 死活分類（§1-7）で分離** |
| 29 | `diplomatic` | 各国 MFA/報道集約 RSS（Appendix A 台帳） | SENSI-032,034 + INGEST-* | K07,K08 | M | 指摘なし。**2 段パースと死活分類の唯一の実装であり、共有パーサ（§1-7）の抽出元**とする |
| 30 | `military_exercise` | 軍事演習 RSS | SENSI-035..037 + INGEST-* | K08 | S | A6: item domain が `physical` 固定で **TL1 の physical≥3.0 ゲートに直結** — RSS 記事への LLM 判断が最上位 TL を開けうる。現行踏襲とし、裁定は cutover 後（ADR-V3-004 の趣旨） |
| 31 | `hacktivist_intel` | telegram 傍受ログ（新規 HTTP 無し） | SENSI-038..040 + INGEST-* | — | S | 8 系中唯一「LLM 出力が上流メタデータを上書き」する系（SENSI-039）。O-17 に従い観測として L1 へ |
| 32 | `hacktivist_news` | セキュリティニュース RSS | SENSI-041..043 + INGEST-* | K08 | M | **A9**: 8 系中唯一、LLM 判定国が対象外の item を破棄する — **自身のプロンプトと矛盾**（プロンプトは「絞り込みは Python の仕事」と告げている）。→ **プロンプト側に統一し破棄を廃止**。DP13 diplomatic の私有関数を関数内 import で借用 → 共有パーサで解消 |
| 33 | `ground_osint` | telegram ログ + 他センサー cache 相互参照 | SENSI-044..047 + INGEST-* | — | **L** | **DP2（B-03）**: 参照先 cache の鮮度・健全性を検査せず読む。STALE/ERROR/CIRCUIT_OPEN が健全と同一視され、裏付け能力が無言で劣化 → **K 層 `Evidence.fresh()` 経由に置換**。型が鮮度検査を強制する |
| 34 | `convergence_tracker` | 8 センサー状態 + intel 台帳直読 | SENSI-048..054 + INGEST-* | — | — | **アダプタとして移植しない**（§4-3）。**DP3（A-09）** 専用 SQLite を直接開く / **DP10** 採点層所有データへの越境読み / **A5** domain=`mixed`（語彙外の第 4 値）— いずれも移植先を持たない。判定結果は独立性メタデータへ還元 |

**WP-2.7 内訳**: S=3 / M=6 / L=2 / 移植せず=1（`convergence_tracker`）。**実移植は 11 アダプタ**。

### 3-4. 全体の複雑度分布

| | S | M | L | 移植せず | 計 |
|---|---|---|---|---|---|
| WP-2.6（cyber 7 + physical 15） | 11 | 7 | 4 | 0 | 22 |
| WP-2.7（info 6 + LLM/meta 6） | 3 | 6 | 2 | 1 | 12 |
| **計** | **14** | **13** | **6** | **1** | **34** |

L 判定 6 基（`ct_log` / `ais_maritime` / `check_host` / `ripe_atlas` / `travel_advisory` / `ground_osint`）は
**共有カーネルが吸収できない固有ロジックを持つ**ものであり、WP-2.6/2.7 の工数の大半を占める。
逆に S 判定 14 基は、共有カーネルが完成していれば宣言 + 正規化関数のみで済む — **これが §1/§2 に投資する理由**である。

---

## 4. O-17 準拠形（WP-2.7）

O-17 は現行のインテル周辺を「事実上の第二の採点パイプライン」と認定し、4 点を裁定している。
その 4 点に対する L0 側の着地を確定する。

### 4-1. LLM 抽出は S2 の 1 アダプタ

**決定**: LLM 抽出は `v3/adapters/llm/` の **1 アダプタ**。投入骨格は `v3/fetch/llm.py` の 1 実装。

**根拠**: A-02 実測 — LLM 投入骨格が **8 複製**し `max_tokens` が 200〜400 でばらついている。
複製が 8 あるということは、プロンプト・温度・解析の癖が 8 通りあるということであり、
S5-VERIF-022 の「記録済み応答の再生」はそのすべてに対して成立しなければならない。**投入口を 1 つにする**。

### 4-2. intel item は L1 の観測として落ちる

**決定**: LLM が抽出した intel item は **`SignalObservation`（`origin=llm_intel`）として L1 に落ちる**。
採点のための独立キューは持たない。

**帰結**: L2 は intel を「観測」として既存経路（S1-SCORE-009/014 の country 重み付け、
S1-SCORE-008 の dedup）で扱う。WP-2.4 で実装済みの `Observation.origin` / `CountryWeight` が
そのまま受け皿になる — **L2 に変更は要らない**（§8 の裁定要求 1 を除く）。

**人間レビューの状態機械は存続する**（NP7）。ただし観測台帳の上に載る L3/L6 の関心事であり、
第二の採点系ではない。到達不能状態（`review_needed` 終端・`shadow_dual`）は移植しない。

### 4-3. convergence_tracker と照合エンジンの処分

**決定**: どちらも**独立した収斂スコアラーとしては移植しない**。

| 現行機構 | v3 での処分 |
|---|---|
| `convergence_tracker` | **廃止**。「複数ソースが同じ事象を見ているか」の判定結果は、観測に付く**独立性メタデータ**（`signal_source` と corroboration group）に還元する。スコアは一切生成しない |
| 照合（corroboration）エンジン | **照合関数のみ存続**し、`v3/matching`（§5）へ移す。用途は (a) 投入時の同一性判定、(b) corroboration group の付与。**採点上の帰結は S5 の収斂式 1 箇所が全て負う** |
| `score_delta` / 独自減衰 / 独自 dedup | **廃止**。dedup は「投入時の同一性判定（S2）」と「採点時の二重計上防止（S5-SCORE-008、実装済み）」の 2 責務のみに整理する。減衰は §8 裁定要求 1 |
| corroborator の 3 定義 | **1 つに統合**。定義は「同一事象を独立に観測した別 signal_source が存在すること」とし、判定は `v3/matching` が行う |

**根拠**: O-17 は「収斂の数式は S5 の 1 箇所のみ」と定める。v3 の収斂式は
`v3/scoring/convergence.py` に既に 1 本だけ存在し（S1-SCORE-003/007、WP-2.4 で実装・テスト済み）、
その入力はドメイン数と参加国数である。**照合はその入力を作る側であって、点を付ける側ではない**。

---

## 5. F-09 の解消 — 言語非依存照合

### 5-1. 現状と害

`_headline_tokens` は `re.findall(r"[a-z]{3,}", headline.lower())`（intel_queue.py:341）である。
**日本語・中国語・ロシア語・アラビア語の見出しはトークン 0 個**になり、`_jaccard` は空集合に 0.0 を返す。
害は dedup に留まらない — 同じトークナイザが**クロスソース corroboration の記録**にも使われており（:697-702）、
**TASS / 新華社 / KCNA / 日本語ソース同士は互いを裏付けとして記録できない**。
D2 は本件を **CRITICAL / NP2 直撃**と分類している。

### 5-2. 設計

**決定**: `v3/matching/` に 2 層の照合を置く。**I/O を持たない純粋モジュール**とする。

**第 1 層（決定論・常時 ON）— 正規化 + スクリプト対応トークン化**

1. Unicode NFKC 正規化 → casefold
2. Unicode カテゴリ（`P*` / `S*`）による記号除去。正規表現による文字クラス列挙はしない
3. スクリプト別セグメンテーション:
   - **語境界のある文字体系**（Latin / Cyrillic / Greek / Arabic / Hebrew）: 空白・句読点で分割、**最小長 2**
     （現行の 3 は Latin 前提。キリル文字・アラビア語は 2 字語が有意）
   - **語境界の無い文字体系**（Han / Kana / Hangul / Thai）: **文字 2-gram**。
     形態素辞書・外部セグメンタに依存しない
4. 類似度は現行同様 Jaccard。ただし**全文字体系で非空集合が出る**

**第 2 層（既定 OFF）— 埋め込みによる言語横断照合**

第 1 層は同一言語内の照合を解く。TASS（露語）と新華社（中国語）が同一事象を報じた場合の照合は
文字 n-gram では解けない。これは埋め込み類似度で解くが、**v3.0 では既定 OFF** とする。

**根拠**: 埋め込みは外部モデル呼び出しであり、S5-VERIF-022 の決定論要件の対象になる。
既定 ON にすると、**パリティ実行のたびにモデル応答の再生記録が必要**になり、
記録が欠けた瞬間に照合結果が変わる。第 1 層だけで dedup の大半（同一言語内）は解けるため、
第 2 層は「記録済み埋め込みが揃ってから」入れる（§7 の繰延先）。

### 5-3. 決定論の担保

- 第 1 層は**文字列の純関数**。同一入力 → 同一出力。fixture テストで全文字体系を pin する
- 第 2 層は text の sha256 をキーに**記録済み埋め込みを引き当てる**。記録が無ければ第 2 層をスキップし、
  **スキップした事実を出力に記載する**（S5-VERIF-022 の「除外の事実を出力に記載 MUST」と同形）
- どちらの層も**スコアを返さない**。返すのは「同一事象か」の真偽と類似度であり、
  それを採点にどう使うかは S5 が決める（O-17）

---

## 6. テスト戦略

### 6-1. アダプタ単位 — fixture 駆動、ネットワーク不使用

**決定**: 各アダプタは `tests/fixtures/adapters/<adapter_id>/` に**記録済み上流ペイロード**を持ち、
`normalize(fixture) -> 期待観測列` を検証する。**テスト中のライブネットワークアクセスは全面禁止**。

強制: autouse fixture が `socket.socket` を例外送出に差し替える。加えて境界テストで
「全アダプタ import でスレッド 0 / radar import 0」を検査する（既存 4 パッケージと同形）。

### 6-2. D1 §4 の 20 項目を pin テストに変換する

**決定**: D1 §4 の外部 API 知識 20 項目は、**1 項目 = 1 テスト**として固定する。
テスト名に知識の内容を書く。

**根拠**: D1 が明記するとおり「この知識の大半はコメントと分岐にしか存在しない」。
コメントは破られても落ちない。テストは落ちる。例:

| 知識項目 | テスト名（例） |
|---|---|
| AISHub はレート制限時に HTTP 200 + 空 body | `test_aishub_rate_limit_is_http_200_with_empty_body` |
| check-host は二段 API（request_id → 5s → result） | `test_checkhost_two_stage_request_id_flow` |
| OONI 3 連続空サイクルで degraded（2h・1 theater・DEBUG） | `test_ooni_degrades_after_three_empty_cycles` |
| CT log の「200-empty は権威ある成功」 | `test_ct_log_empty_200_is_authoritative_success` |

**網羅メタテスト**: 20 項目それぞれに ID を振り、`knowledge_refs` を宣言したアダプタと
テストの対応表を突合する。どちらかが欠けたら fail。ETL の `S3_MIGRATE_35` レジストリ、
L2 の条項レジストリと同じ機構であり、**転写のドリフトが自動で落ちる**。

### 6-3. 共有カーネルのテスト面

| 対象 | 検証内容 |
|---|---|
| `breaker` | 状態遷移表（純関数。CLOSED→OPEN 閾値、HALF_OPEN の成功/失敗、遅延の倍化と上限クリップ） |
| `limiter` | 共有 min-interval（OpenSky 3 アダプタが 1 リミッタを共有すること）、courtesy delay 群 |
| `parse` | 2 段パースの縮退、死因 5 分類、実在の壊れた feed fixture |
| `schedule` | 再起動を跨いだ期日判定（F-01 回帰: `last_run_at` からの導出で offset が飛ばないこと） |
| `client` | timeout 必須、429 処理、`fetch_log` 記録、CB 記録が 1 サイクル 1 回であること（S4-NF-003） |
| `llm` | `llm_call` 記録の完全性（prompt/response/model/temperature が欠けないこと。S5-VERIF-022 の前提） |
| 規律 | `v3/` 配下で `v3/fetch/client.py` 以外が HTTP ライブラリを import しないこと |

---

## 7. 非目標・繰延

### 7-1. 非目標（着地 WP を明記）

| 項目 | 扱い | 着地先 |
|---|---|---|
| 新規センサーの追加 | **やらない**。本 WP は移植であり、母数を増やすとパリティの比較対象が定義できない | cutover 後 |
| NOTAM の復活 | **やらない**。無料の国際 NOTAM API は存在せず ICAO API は停止（D1 §4）。FAA payload 形式のみ資産として保存 | 対象外 |
| ACLED | **やらない**（恒久的に却下済。雇用主情報の要求 = OPSEC） | 対象外 |
| 言語横断の埋め込み照合（第 2 層） | 記録済み埋め込みが揃うまで既定 OFF | WP-3.1 以降 |
| アダプタ健全性の UI 露出 | L0 は `fetch_log` を出すのみ。画面化は導出済みの P8 に従う | WP-4.1 / 4.2 |
| 生 body の全件長期保存 | 既定 OFF。容量判断が未承認（§1-6） | 要件が出た時点で ADR |
| 現行系の bg_observer 修正（B-01） | v3 を待たず現行系で直す方針が D2 に記載済 | 現行系側 |

### 7-2. 予期された差分の事前登録（P2 §5-C）

§3 の処分のうち **6 件は現行系と異なる出力を生む**。P2 §5-C は「登録外の差分が出た場合は cutover 中止」と定めるため、
**実装前に以下を予期された差分として登録する**。方向欄は S5-VERIF-029 の分類
（insensitive = v3 が低く出る = NP1 上 blocking）。

| # | アダプタ | 差分 | 方向 | 扱い |
|---|---|---|---|---|
| 1 | `gps_jamming` | DP7 の単位不整合を解消 → **恒久無発火から発火するようになる** | sensitive | 差分は大きいが NP1 側。WP-0.2 で現行系も修正済のため、**現行系の修正後データで窓を取れば差分は消える** |
| 2 | `space_weather` | fail-open → fail-closed。両 endpoint 失敗時に Kp=0 を記録しない | sensitive（抑制が減る） | 登録 |
| 3 | `hacktivist_news` | A9 の破棄を廃止（プロンプトの宣言に合わせる） | sensitive | 登録 |
| 4 | `travel_advisory` | **A3 の最終 fallback（body に "travel" → level 2）を廃止** | **insensitive** | **裁定要求 4**。C-02/C-03 に直接抵触しうる唯一の項目 |
| 5 | `nasa_firms` → `nasa_eonet` | `sensor_id` を実ソースに合わせる（DP6 / NP6） | 中立 | 台帳の別名解決で吸収。dedup キーは `signal_source` 側なので収斂には影響しない |
| 6 | `ct_log` | 恒久 0 の `gov_count` を出力から削除 | 中立 | 消費者ゼロ（A18）。登録のみ |

---

## 8. 裁定要求

以下 3 件は本書の権限を超える。**各件に推奨を付す**。

### 裁定要求 1 — LLM インテルの時間減衰をどこに置くか（O-17 との整合）

**問題**: O-17 は「score_delta・独自減衰・独自 dedup は **L2 の一元機構に吸収**」と定める。
一方 **WP-2.4 で実装済みの L2 は、段階的な時間減衰を表現できない**。実測:

- `v3.scoring.Observation` のフィールドは `sensor / domain / status / score / signal_source /
  countries / confidence / suppressed / suppress_reason / origin / value` — **`observed_at` が無い**
- L2 の減衰項はシーケンス連鎖（S1-SCORE-021）のみで、観測の齢に対する減衰は存在しない

つまり L2 は観測の齢を知らないため、現状のままでは減衰を計算しようがない。
一方 S1-PIPE-023 は intel を「確認済み・TTL 内・**時間減衰済み**」で注入すると定める。
L0 のアダプタが減衰済みスコアを吐けば動くが、それは O-17 が名指しで廃止した「独自減衰」を
L0 に温存することになる。

**推奨（案 A）**: `Observation` に `observed_at` を追加し、**L2 に intel 減衰項を 1 つ置く**。
減衰式・閾値は `Threshold.pinned` で開示する。WP-2.4 の条項レジストリに新条項として登録する。
ADR-V3-004 が凍結したのは **TL 導出式**であって減衰ではないため、パリティ凍結には抵触しない。
ただし**現行の減衰式を実効経路から転写する**必要があり（WP-2.4 と同じ手続き）、
その転写作業は WP-2.7 に含めるか WP-2.4 の追補とするかの割当も併せて裁定を要する。

**案 B（非推奨）**: L0 が減衰済みスコアを出す。実装は最小だが O-17 に正面から反する。

---

### 裁定要求 2 — F-09 の「解消」の定義（第 2 層を必須とするか）

**問題**: F-09 は CRITICAL / NP2 直撃と分類されている。本書 §5 の第 1 層（正規化 + スクリプト対応
トークン化）は、**非ラテン文字ソースがトークン 0 個になる**という欠陥本体を解消し、
日本語・中国語・ロシア語・アラビア語の**同一言語内**の dedup と corroboration を成立させる。
解消しないのは**言語をまたぐ**照合（TASS 露語記事 ↔ 新華社中国語記事）である。

**推奨**: **第 1 層をもって F-09 の解消とする**。根拠は D2 の欠陥記述そのものが
「トークン 0 個 → 決して一致しない」という構造的排除を指しており、
言語横断照合はその先の機能拡張である。第 2 層を v3.0 の必須にすると、
照合結果が外部モデル応答に依存し、**S5-VERIF-022 の再生記録が無い限りパリティが非決定的になる** —
cutover の前提を新しく壊すことになる。第 2 層は記録済み埋め込みが揃った時点で ON にする。

**裁定が要る点**: この線引きを受け入れるなら、D2 の F-09 は「第 1 層完了をもって解消」と
判定基準を明記する必要がある（現在の記述は解消条件を「言語非依存の照合 MUST」とだけ書いており、
言語横断を含むと読む余地がある）。

---

### 裁定要求 3 — L1 スキーマの拡張（コミット済みパッケージへの変更）

**問題**: 本書は L1 に 3 表を追加する（§1-3 / §1-6）: `fetch_schedule`（F-01 の解消に必須）、
`fetch_log`（取得記録）、`llm_call`（S5-VERIF-022 の前提）。
これは **WP-2.2 でコミット済みの `v3/ledger/schema.py` を変更し `SCHEMA_VERSION` を上げる**ことを意味する。

**推奨**: **L1 に置く**。P1 §5 の「単一管轄: 永続層はここだけ。第 2 SQLite は存在しない（A-09）」に
従えば L0 が自前ストアを持つ選択肢は無い。各表には S3-DATA-044 が要求する retention policy を
宣言する（§1-6 の表のとおり）。ETL（WP-2.3）は新表を「移行対象外・v3 で新規生成」として
`REGENERATE_ONLY` 相当に登録し、`S3_MIGRATE_35` の突合を壊さないこと。

**裁定が要る点**: `SCHEMA_VERSION` を上げると、既に移行済みのストアがある場合に
マイグレーション手順が要る。v3 ストアはまだ本番運用に入っていない（パリティ窓は 2026-09-05 開始）ため
**再生成で足りる**と判断しているが、既存 v3 ストアの有無はオーナー側の情報である。

---

### 裁定要求 4 — `travel_advisory` の A3 fallback 廃止は insensitive 差分になる

**問題**: 英 FCDO パーサの最終 fallback は「本文に `travel` を含めば level 2」である（A3）。
渡航勧告の記事はほぼ全て `travel` を含むため、これは実質「判定不能 = level 2」であり、
**収斂の母数を偽の裏付けで膨らませている**。NP2 の観点では、偽の裏付けは裏付けが無いより悪い —
複数ソース収斂という結論強度の根拠そのものを汚すためである。

一方、これを廃止すると v3 は**現行より発火が減る**。S5-VERIF-029 の分類では **insensitive**（v3 が低く出る）であり、
**C-02（v3 のみの見逃し 0 件、override 禁止）と C-03（insensitive があれば一致率に関係なく FAIL）に
直接抵触しうる**。WP-2.8 のハーネスはこれを blocking として正しく報告する。

**推奨**: **廃止する。ただし「予期された差分」として事前登録し、C-03 の 5% 枠で説明する。**
根拠は、この fallback が生む level 2 は*観測*ではなく*パーサの諦め*であり、
それを検知として数えることは NP1 の「見逃しを減らす」に寄与していない — 分母を汚しているだけである。
NP1 が守るべきは真の検知であって、偽陽性の量ではない。

**裁定が要る理由**: 予期された差分の登録は「登録外なら cutover 中止」という重い規律に紐づくため、
insensitive 方向の登録はオーナー承認を要すると判断する。
**代案**: 廃止せず現行踏襲し、cutover 後に別途裁定する（パリティは通るが NP2 の汚染は残る）。


---

## 9. 裁定（Fable、2026-08-07）

| # | 裁定 | 補足 |
|---|------|------|
| 1 | **WP-2.4 補遺として L2 に実装**（`Observation.observed_at` 追加 + pin 済み減衰項 1 本）。着地は WP-2.7 と同時（インテルアダプタが存在して初めてフィクスチャで検証可能になるため）だが、**L2 変更として独立にラベル**し、採点カーネルと同じ忠実性規律（実効経路の実測トレース・条項対応テスト・レジストリ更新）を課す。ADR-V3-004 が凍結したのは TL 梯子であり減衰ではない — ただし引用行の変異先確認（WP-2.4 の教訓）を必須とする | 裁定要求 1 |
| 2 | **第 1 層で F-09 解消と定義する**。決定論正規化 + スクリプト認識分節で非ラテン見出しが空トークンにならないこと = 欠陥の定義そのものの解消。第 2 層（埋め込み）は enhancement であり既定 OFF — 有効化するなら VERIF-022 記録が前提（決定論を壊してまで欠陥を直さない）。D2 F-09 の閉鎖注記にこの定義を明記する | 裁定要求 2 |
| 3 | **承認 — L1 が 3 表を所有**（A-09 単一管轄）。WP-2.2 完了時に予告した**最小 migration リスト機構をこの拡張で実装**する（schema v2）。稼働中の v3 store は存在しない（パリティ窓未開放・本番 ETL 未実行）ため開発 store の再生成は許容 | 裁定要求 3 |
| 4 | **廃止 + 事前登録で進める。ただし登録エントリは「承認待ち（オーナー）」を明記**。fallback はほぼ全記事に発火する parser-gives-up 判定であり、除去はノイズ除去であって実信号の recall 低下ではない（NP2: 偽の裏付けは収斂を汚染する）。§7-2 の 6 件登録全体の最終承認は cutover 判定前のオーナー事項として申し送る | 裁定要求 4 |
