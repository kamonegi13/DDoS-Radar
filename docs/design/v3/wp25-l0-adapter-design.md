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

> **改訂（2026-08-07、WP-2.6 忠実性掃引の結果を遡及反映）**
> 本節の初版モデルは **22 アダプタのうち 8 基が本番のリクエストを発行できない**ものだった。
> 掃引が検出した 97 件の不忠実のうち相当数は、アダプタ側の書き損じではなく**モデルの表現力不足**に由来する。
> 経緯と裁定は §2-4 に記す。以下の宣言モデルは**実装された形**である。

**決定**: アダプタが宣言するのは **何を取りに行くか（`requests`）** と **どう正規化するか（`normalize`）** の 2 つだけ。
timeout・リトライ・CB・レート制限・パーサ選択・出力先は**宣言できない**。

```python
@dataclass(frozen=True)
class SourceAdapter:
    adapter_id: AdapterId                 # 型。文字列リテラルではない（F-02）
    category: Category                    # cyber | physical | info | llm | meta
    requests: tuple[RequestSpec | RequestChain, ...]   # WHAT
    cadence: Window                       # K 層 Window（素の秒数を受けない）
    normalize: NormalizeFn                # HOW to normalize
    auth: AuthRequirement                 # 資格情報の「名前・置き場所・書式・要否」
    rate_limit_group: str                 # 共有リミッタのキー（OpenSky 3 基）
    freshness_horizon: float              # 観測の鮮度地平（K 層 Evidence へ）
    record_body: bool = False
    knowledge_refs: tuple[str, ...] = ()  # D1 §4 の知識項目 ID（§3 で照合）
    baseline_refs: tuple[str, ...] = ()   # 判定に要する L1 ベースライン（DP3）

NormalizeFn = Callable[[FetchedPayload, NormalizeContext],
                       tuple[ObservationDraft, ...]]
```

```python
@dataclass(frozen=True)
class RequestSpec:
    url: str                              # 絶対 URL。{placeholder} を含みうる
    method: str = "GET"                   # GET | POST
    params: tuple[tuple[str, str], ...] = ()   # 順序付きペア列。写像ではない
    headers: Mapping[str, str] = {}
    body: Optional[Mapping[str, Any]] = None   # JSON ボディ（POST のみ）
    body_content_type: str = ""                # "application/json"
    auth: Optional[AuthRequirement] = None     # リクエスト個別の資格情報
    expect_content: str = "any"
    label: str = ""                       # {placeholder} 可。normalize が読む

@dataclass(frozen=True)
class RequestChain:
    alternatives: tuple[RequestSpec, ...]      # 2 件以上。先頭が primary
    advance_on: str = FALLBACK_ON_FAILURE      # failure | failure_or_empty
    reason: str = ""                           # 必須。fallback が在る理由
    label: str = ""

@dataclass(frozen=True)
class AuthRequirement:
    kind: str = AUTH_NONE                 # none | api_key | oauth2
    key_id: Optional[str] = None          # 秘密の**名前**。値ではない
    placement: str = AUTH_IN_HEADER       # header | query
    name: str = ""                        # ヘッダ名 / クエリパラメータ名（既定なし）
    value_template: str = ""              # "{secret}" / "Bearer {secret}"（既定なし）
    optional: bool = False                # 欠落時は匿名で取得する（失敗にしない）
    note: str = ""
```

`RequestSpec` は URL テンプレート・メソッド・パラメータ・ボディ・期待 content-type の宣言。
**`RequestSpec` は関数を持たない** — 「取りに行き方」を式で書けてしまう余地を残さない。
`RequestChain.advance_on` も**閉じた定数集合**であって述語ではない（述語を許せば「取りに行き方」になる）。

**この「宣言データ / 振る舞い」の区別は本書を貫く一般則である**（裁定要求 10、2026-08-08 裁定）。
`RequestSpec`（取りに行く先はデータ、取りに行き方は関数ではない）、
`RequestContinuation.carries`（どのフィールドが取っ手かはデータ、どう復号するかはカーネル）、
`IntelProfile.dispositions`（どの値がどの処分になるかはデータ、評価は共有実装 1 本）は**同一の形**である。
守っている不変条件は「フィールド数の上限」ではなく **「実装が 1 本であること」**。
表（データ）にはセンサー固有の分岐を隠す場所が無いが、callable にはある — だから
**規則はどこでも同じ: 表に callable が入ったら `DomainError`**（`ResponseValue.path` と同一の論拠）。

4 点の設計上の要点:

| # | 形 | なぜその形か |
|---|-----|------------|
| 1 | `params` は**順序付きペア列**（写像ではない） | 写像は 1 名前 1 値しか保てない。`check_host` は `node[]` を 5 回、`ct_log` は `expand` を 2 回送る。順序も忠実性の一部（掃引は並べ替えられた半径表を検出している）。写像を渡すと `DomainError`。**変換しない**のは、辞書リテラルの時点で値が落ちてしまい、ここに届く頃には訴えるべき情報が残らないため |
| 2 | `AuthRequirement.name` / `value_template` に**既定値を置かない** | 修理対象の欠陥そのものが「既定値」だった。既定を残せば宣言し忘れたアダプタが「もっともらしいが読まれない資格情報」を送り続ける。省略は書いた場所で失敗しなければならない |
| 3 | `RequestChain.reason` は**必須** | 理由の書かれていない fallback は「消し忘れた二重問い合わせ」と区別できない。`disabled_reason` と同じ論拠 |
| 4 | `optional` の判定基準は「**本番が匿名で取得しているか**」 | ThreatFox は鍵が無いと*呼ばない*（`log_fetch(True, …)` で 0 件成功を記録する = NP1 が禁じる沈黙）ので optional に**しない**。§2-4 参照 |

**プレースホルダ展開はカーネル側（`v3/fetch/expand.py`）に置く**。論拠は HTTP クライアントを 1 ファイルに閉じたのと同じ（§1-4）—
呼び出し側ごとに置換すれば呼び出し側ごとに間違えられ、間違えた結果は「成功したが何も答えていないリクエスト」になる。
K02 が記録するとおり AISHub は拒否したリクエストに HTTP 200 + 空ボディで答えるので、**この失敗は必ず平穏として読まれる**。

```python
@dataclass(frozen=True)
class ExpansionScope:                     # 1 scope = 1 具体リクエスト
    values: Mapping[str, str] = {}        # {country} → "TW" 等
    scope_key: str = ""                   # "TW" / "TW/strait_midline"

@dataclass(frozen=True)
class ExpansionInput:                     # 1 アダプタ 1 サイクル分の入力
    scopes: tuple[ExpansionScope, ...] = ()
    common: Mapping[str, str] = {}        # 実行全体で共通の値（{since_iso} 等）
```

- **1 宣言 → N 具体リクエスト**（scope ごと）。§3-5 H-1（1 国 N ゾーン）はこの形で表現できる（→ §2-4）
- scope を跨いで**文面が変わらない宣言は 1 回だけ**取得する。`usgs_seismic` は世界に 1 つ問うのであって、5 国 scope で同一クエリを 5 回投げてはならない
- **未解決プレースホルダは `DomainError`**。`run_due` はこれを `SkippedFetch(UNRESOLVED)` として**記録**に変換する（1 基の設定漏れで 21 基を巻き添えにしない）が、**送信は決してしない**
- 展開器は資格情報を持たない。秘密が具体リクエストに載るのは `client.py` の 1 箇所だけで、**計画（plan）は宛先を持つが認証は持たない**

`ObservationDraft` は `reason`（スコアリング層が記録する `fired_reason`）を持つ。
L1 `signal_observation` に列は無い（スキーマは WP-2.4 でコミット済、列追加は**裁定要求 3** の管轄）ため、
`runner` が `flags["fired_reason"]` として**1 箇所で**書く。アダプタ各自が `flags` に流儀を発明するのとは別物である。

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

### 2-4. 宣言モデルは不十分だった（WP-2.6 掃引、2026-08-07）

**事実**: WP-2.6 で 22 アダプタを移植し終えた時点で AST 忠実性掃引を実施したところ、97 件の不忠実が出た。
そのうち相当数の原因はアダプタではなく **§2-1 初版の宣言モデル**であり、
**8 基は宣言された本番リクエストをそもそも発行できなかった**。

| # | 表現できなかったもの | 影響を受けたアダプタ | 沈黙の形 |
|---|---|---|---|
| 1 | 資格情報の**置き場所と名前** | `cloudflare_radar` / `greynoise` / `openweather` | `client.py:185-189` が全アダプタに `{"Auth-Key": secret}` を固定送出。正しいのは abuse.ch のみ。CF は `Authorization: Bearer`（`radar/config.py:322`）、GreyNoise は文字どおり `key`（`greynoise.py:49`）、OpenWeather は**ヘッダを読まない**（クエリ `appid`）。3 基が「サーバが読まない資格情報」を提示し、401/403 が「データ無し」として記録される |
| 2 | 資格情報の**任意性** | `opensky` / `isr_hotspot` / `mil_support_air`（+ `ct_log`） | 本番は匿名で動く（`config.env.example:90-91` は空、`opensky_auth.py:17` が anonymous mode をログ）。必須宣言のため**ソケットを開く前に AUTH_MISSING** で中断。既定配備で物理センサー 3 基が暗転 |
| 3 | **JSON ボディ** | `threatfox` | 本番は `requests.post(url, json={"query": "get_iocs", "days": 1})`。移植版はクエリ文字列にした。abuse.ch はこれを読まない |
| 4 | **同名パラメータの反復** | `check_host` / `ct_log` | `node[]` × 5（JP/US/DE/NL/FR）、`expand` × 2（`dns_names` と `issuer`）。`issuer` が無いと全証明書が `unknown` に落ちて破棄され、`ct_log` は**恒久的に無発火**になる |
| 5 | **条件付き fallback** | `ct_log`（K05）/ `ioda_bgp`（K19） | 本番は primary 失敗時のみ第 2 ソースへ行く（`ioda.py:49-55`）。`runner.py:205-215` は宣言された spec を無条件に全部取得するため、**Cloudflare の異常が IODA の OK を FIRED で上書きしうる**。データではなくカーネルが作る sensitive 方向の構造差 |
| 6 | **プレースホルダ展開器の不在** | `{country}` を宣言する 15 基 | `v3/fetch` のどこにも置換が無く、`{country}` / `{lat}` / `{since_iso}` が**そのまま送信される**。K02 より、拒否されたリクエストは HTTP 200 + 空ボディで返る |
| 7 | `ObservationDraft.reason` の不在 | `check_host` | `fired_reason` の置き場が無く、`flags["reason"]` に流儀を発明していた |
| 8 | **継続（A の後に B(A)）** | `check_host` | 第 2 リクエストのアドレスが第 1 応答の中にある。独立した 2 リクエストとして宣言したため `{request_id}` が計画時に解決できず、`run_due` が **毎サイクル `unresolved_placeholder` でアダプタ全体を飛ばしていた**。台帳で最も直接的な到達性センサーが、記録済みの理由と共に沈黙する |

**なぜ移植中に露見しなかったか**（再発防止のための記録）:
展開器が存在しなかったため `{country}` を送る経路自体が存在せず、**「まだ誰も呼んでいない」ことが不忠実を隠した**。
§3-5 H-1 を WP-4.1 へ引き渡した際の前提 —「モデルは運べるはずで、残るのは合成ルートの仕事」— も同じ盲点の上にあった。
教訓は DP7 / H-2 と同型である: **発火し得ない経路の沈黙は平穏として読まれる**。
移植の完了条件に「宣言を実際にワイヤまで通す」テストが無かったことが、この 8 件を WP-2.6 まで運んだ。

**処置**: §2-1 を上記のとおり改訂し（placement / optional / body / 反復パラメータ / `RequestChain` / 展開器 / `reason`）、
`tests/test_adapters_request_fidelity.py` が **8 基それぞれについて「宣言 → 展開器 → クライアント → セッション」を通し、
ワイヤに出るバイト列を本番ソースと突き合わせて pin する**。以後、モデルが運べない形は
「呼ぶ人がいないので分からない」ではなく、テストの失敗として出る。

**1 件だけ掃引の示唆どおりにしなかったもの**: `threatfox` の Auth-Key は **optional にしない**。
optional の基準は「本番が匿名で取得しているか」であり、ThreatFox はそうではない —
鍵が無いと**呼ばずに** `log_fetch(True, 0, 0, 0, "")` で 0 件成功を記録する（`threatfox.py:35-38`）。
これは NP1 が禁じる沈黙そのものなので再現しない。v3 は AUTH_MISSING（「訊けなかった」）を記録する。

**裁定を仰いだ 1 件とその決着（R4、2026-08-08）**: `check_host` の第 2 リクエストは fallback ではなく**継続**である —
`check-result/{request_id}` の `request_id` は第 1 応答から来て、間に 5 秒の待機が入る（`checkhost.py:60-72`）。
`RequestChain` は「A または B」を表現するのであって「A の後に B(A)」ではない。
**裁定はモデル化**。`RequestContinuation` を追加した（`v3/adapters/types.py`）。形は次のとおりで、
不変条件は変わっていない — **アダプタは WHAT（どのフィールドが取っ手か、どれだけ待つか）を宣言し、
カーネルが HOW（いつ復号するか、どう待つか、取っ手が来なかったとき何を記録するか）を決める**。

| 宣言 | 意味 | 実装 |
|---|---|---|
| `carries=(ResponseValue(placeholder=..., path=(...)),)` | 第 1 応答のどこを、次のどのスロットへ運ぶか。`path` は**データ**であって lookup 関数ではない（callable は `DomainError`） | `expand.carried_values()` — 純関数。「取っ手が来なかった」をソケット無しで再現できる |
| `delay_sec=5.0` | upstream が結果を作るのに要する時間。**宣言であって sleep ではない** | `HttpClient.pause()` — `sleeper` 注入シームを既に持つ層が待つ。`checkhost.py:66` の裸の `time.sleep(5)` はスイートが 5 秒を実費で払わないと通せなかった |
| — | 展開器は `carries` のスロットだけを**未解決のまま残す**（`expand_spec(..., deferred=...)`）。「まだ分からない」と「誰も渡さなかった」は別の事実で、defect は後者だけである | `ResolvedStep.continuation` に載る |

第 1 応答が取っ手を持たなかった場合（`checkhost.py:62-63` の `if not request_id:`）は
**`fetch_log` に `continuation_unresolved` として残る**。取得は成功しており、これを HTTP 失敗に畳むと
ブレーカーが誤った対象を追う。何も記録しなければ、その国は「測って何も無かった」ように見える —
本型を追加した理由そのものである。
pin は `tests/test_adapters_request_fidelity.py::TestCheckHostContinuation`（宣言 → 展開器 → クライアント → recorder を
`execute_plan` まで通し、L1 に観測が 1 件だけ落ちること・第 2 リクエストが第 1 応答で番地付けされることを固定）と
`tests/test_fetch_declaration_model.py::TestRequestContinuation`。

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

**WP-2.7 内訳**: S=3 / M=6 / L=2 / 移植せず=1（`convergence_tracker`）。当初想定の実移植は 11 アダプタ。

**着地（2026-08-08、WP-2.7 完了時点）**: **build されたのは 9 基** —
`gdelt` / `tor_metrics` / `bg_observer_rss` / `telegram_mirror` / `rss_narrative` / `travel_advisory`（info 6）
＋ `diplomatic` / `military_exercise` / `hacktivist_news`（LLM 3）。
残り 3 行の処分はいずれも裁定済みで、**保留ではない**:
`hacktivist_intel` / `ground_osint` は **WP-4.1 へ繰延**（裁定要求 9 / §3-5 H-3 — 入力が別アダプタの出力）、
`convergence_tracker` は **移植せず**（§4-3）。
総和は **34 declared / 33 buildable / 2 deferred / 31 built**（WP-2.6 の 22 ＋ WP-2.7 の 9）であり、
`catalog.PENDING_WP27` は**空**になった — 以後この列に行が現れたら、それは新しい負債である。

### 3-4. 全体の複雑度分布

| | S | M | L | 移植せず | 計 |
|---|---|---|---|---|---|
| WP-2.6（cyber 7 + physical 15） | 11 | 7 | 4 | 0 | 22 |
| WP-2.7（info 6 + LLM/meta 6） | 3 | 6 | 2 | 1 | 12 |
| **計** | **14** | **13** | **6** | **1** | **34** |

L 判定 6 基（`ct_log` / `ais_maritime` / `check_host` / `ripe_atlas` / `travel_advisory` / `ground_osint`）は
**共有カーネルが吸収できない固有ロジックを持つ**ものであり、WP-2.6/2.7 の工数の大半を占める。
逆に S 判定 14 基は、共有カーネルが完成していれば宣言 + 正規化関数のみで済む — **これが §1/§2 に投資する理由**である。

### 3-5. 移植中に確定した引き継ぎ事項（WP-2.6 実装レビュー、2026-08-07）

§7-2 が「**すでに差分を生んでいる**もの」の登録簿であるのに対し、本節は
「**まだ差分を生んでいないが、放置すれば必ず生むもの**」を置く。2 件ある。

#### H-1（引き継ぎ）— ISR ホットスポットの複数ゾーンを現行の宣言型が表現できない

**事実**: `geo_data.json` の `ISR_HOTSPOTS` は **1 国に複数の名前付きゾーン**を持つ
（TW×2 = 台湾海峡中線 / 東シナ海 ADIZ 重複部、CN×3、RU×3、KP×2、AU×2）。
<!-- 訂正 2026-08-08: 上の census は 2 国分欠けていた。実測は §H-1 追補の表を正とする -->

海洋チョークポイント台帳と同じ形である。現行の `isr_hotspot` / `mil_support_air` は
`for hotspot in ISR_HOTSPOTS` で全ゾーンを走査し、
`results[theater]["count"] += isr_count` と **theater 単位で合算**してから
`is_surge = count >= 3` を判定する（`radar/sensors/isr_hotspot.py:29, 85-94, 106-107`。
`mil_support_air.py:76` も同型）。

**現状の v3**: `NormalizeContext` は `ais_maritime` の複数チョークポイント問題のために
`chokepoints` フィールドを**専用に**持つが、ISR ホットスポットに対応するフィールドは**無い**。
`v3/adapters/physical/opensky.py::_box_request(label, half_degrees)` は
**1 国につき 1 ボックス**をテンプレート化する。

**帰結**: `{country}` を展開する合成ルートがまだ存在しないため**実害は出ていない**。
しかし現在の `RequestSpec` / `NormalizeContext` の形のままでは
**現行系のカバレッジを再現できない** — TW なら台湾海峡中線しか見ず、東シナ海 ADIZ 重複部を見ない。
NP1 上、カバレッジの縮小は検知漏れそのものである。

**引き渡し先**: **WP-4.1（合成ルート `v3/runtime/`、§1-2）**。解くべきは 2 点 —
(a) 1 国 N ゾーンへの request 展開、(b) **surge 判定は全ゾーン合算後**という順序の保存
（ゾーン毎に 3 機の閾値を当てると現行より鈍る）。
本 WP では `NormalizeContext` を再設計**しない**: 消費者が存在しない段階での型拡張は
YAGNI であり、`chokepoints` を足した時と同じく「実際の展開者が決まってから形が決まる」。

**痕跡**: `v3/adapters/physical/opensky.py` のモジュール docstring に同旨を記載。

> **更新（2026-08-07、§2-4 のモデル修正後）— H-1 は半分閉じた。**
>
> **(a) は閉じた**。`v3/fetch/expand.py` の `ExpansionInput.scopes` により
> **1 宣言 → N 具体リクエスト**が表現できる（`tests/test_fetch_expand.py::TestH1IsHalfClosed`
> が TW の 2 ゾーンで pin）。本引き渡しの前提「モデルは運べるはず」は**誤りだった**ので、
> WP-4.1 に渡す前にモデル側で直した。
>
> **(b) は開いたまま**で、これは L0 では閉じられない。`normalize` は取得したペイロード 1 件ごとに
> 呼ばれてゾーン 1 つしか見ないので、この層に「2 ゾーンを足す」立場のコードは存在しない。
> `signal_observation` は `(tick_id, sensor, signal_source, country)` で UNIQUE、かつ
> 同キー・異内容の再記録は **`DomainError` で落ちる**（S5-VERIF-019）ため、
> **欠落している合算は静かな半減ではなく硬いエラーになる** — 失敗の仕方としては正しいが、依然として穴である。
> WP-4.1 が持つべきは **reduction ステップ**（ゾーン群 → 国単位の 1 draft → 閾値）であって、
> モデルの再設計ではない。
>
> なお `isr_hotspot` / `mil_support_air` の `label` は現状 `{country}` しか展開しないため
> 2 つの TW ボックスは下流で見分けられない。`{zone}` の追加はアダプタ側の変更であり、
> **(b) の裁定が先**である（ゾーンに名前が要るのは、何かがゾーン単位で束ねる場合だけ）。

> **追補（2026-08-08、R6）— H-1 は request 側しか書いていなかった。出力側も引き渡す。**
>
> **(c) 出力側**: 「ゾーンに名前が要るのは、何かがゾーン単位で束ねる場合だけ」— **束ねている**。
> 実測（`ast` / `grep` で確認）:
>
> | 何を | どこ | 形 |
> |---|---|---|
> | ゾーン毎のレコード | `radar/sensors/isr_hotspot.py:87-93` | `{"name", "lat", "lng", "isr_count", "tracks"[:5]}` を `results[theater]["hotspots"]` に **append**。国の `count` は `existing["count"] += isr_count`（同 :86）で**合算**される — つまり **count は国単位、hotspots[] はゾーン単位**という二重の粒度を 1 レコードが持つ |
> | 結合キー | `radar/routes/core.py:2929-2931` | `next((h["tracks"] for h in isr_data[t]["hotspots"] if h["name"] == hs["name"]), [])`。**`name` が結合キー**。API が返す `isr_hotspots[]` は `ISR_HOTSPOTS` 台帳と観測を `name` で突き合わせて組み立てる |
> | `ISR_SURGE` の payload | `core.py:1231`（primary）/ `:1243-1245`（secondary、ADR-009 stage 2） | `{"count": <国合算>, "hotspots": <ゾーン配列そのまま>}`。**シーケンスイベントがゾーン配列を丸ごと運ぶ**ので、ゾーン識別子はシーケンス連鎖の証跡にまで到達する |
> | `MIL_AIR_SURGE` の payload | `core.py:1781-1783`（primary）/ `:1794-1799`（secondary） | `{"tanker", "transport", "awacs"}` — **ゾーン配列は運ばない**。`mil_support_air` は全ゾーンを走査して機種別カウントを国単位に合算するだけなので、ゾーン名は出力に現れない |
>
> したがって **WP-4.1 の reduction ステップは「合算した数」だけでなく「ゾーン毎のレコード配列」も
> 作らなければならない**。`name` / `lat` / `lng` / `isr_count` / `tracks` を落とすと、
> API の `isr_hotspots[]` は台帳側だけが残って `tracks` が空になり（結合が空を返す）、
> `ISR_SURGE` の証跡からゾーンが消える。**地図オーバーレイが静かに空になる**類の欠落である。
> `{zone}` をアダプタの label に足す判断は、この (c) があるので **(b) と同時に決まる**
> — 束ねる主体が `hotspots[]` を作る以上、ゾーンには名前が要る。
>
> **census 訂正**（`geo_data.json` `ISR_HOTSPOTS` 全 30 ゾーン / 21 国を実測）:
> **CN×3、RU×3、TW×2、JP×2、KP×2、AU×2、IN×2**、残る 14 国は各 1。
> 初版は **JP×2 と IN×2 を落としていた**。JP の 2 つは
> **宮古海峡パトロール回廊（Miyako Strait Patrol Corridor）**と
> **沖縄-台湾 ISR 回廊（Okinawa-Taiwan ISR Corridor）**であり、
> TW の 2 つ（台湾海峡中線 / 東シナ海 ADIZ 重複部）と**地理的に重なる**。
> 台湾シナリオで JP を forward_base として採点する以上、この 2 ゾーンの欠落は
> **注目シナリオの中心部の検知漏れ**に直結する。
> なお台帳のフィールド名は `country` ではなく **`theater`** である（廃止用語が `geo_data.json` に残存。
> 用語統一の対象だが、本 WP では読み替えるに留める）。

#### H-3（引き継ぎ、WP-2.7 実装中に確定、2026-08-08）— 入力が「別アダプタの出力」であるアダプタを宣言型が表現できない

**事実**: WP-2.7 の 12 基のうち **3 基は HTTP を持たない**（§3-0 が母数 28 から除外した「メタ 3 基」）。
`hacktivist_intel` は `telegram_mirror` のクラス変数 `_intercept_log` を読み、
`ground_osint` は同じログに加えて **`cloudflare_radar` と `check_host` の live cache** を読む
（`radar/sensors/ground_osint_sensor.py:67-82`、`ast` で確認。**鮮度も健全性も検査していない** = DP2/B-03 そのもの）。
`convergence_tracker` は 8 センサーの状態を読む（移植しない、§4-3）。

**現状の v3**: `SourceAdapter.requests` は `RequestSpec | RequestChain | RequestContinuation` しか取れず、
`normalize` は **取得済みバイト列 1 件**しか受け取らない（§2-2 の barrier 1）。
「別アダプタの出力を入力とする」ことを宣言する語彙が**無い**。
`NormalizeContext` に足すのは H-1 で退けたのと同じ理由（消費者が決まる前の型拡張は YAGNI）で採らない。

**帰結**: `hacktivist_intel` / `ground_osint` の 2 基は、**宣言モデルの現状では移植できない**。
無理に移植すれば (a) `normalize` に他アダプタの cache ハンドルを渡す（barrier 1 の破壊）か、
(b) アダプタが自前で読む（barrier 2/4 の破壊）のどちらかになる。
**§2-4 の教訓の反復**: 表現できないものを表現できるふりをすると、沈黙が平穏として読まれる。

**引き渡し先**: **WP-4.1（合成ルート）**。解くべきは「L1 に落ちた観測を次サイクルの別アダプタの入力にする」
配線であり、これは §7-2 #11 / #35 の reduction・suppression と**同じ層の同じ問題**
（どれも「別アダプタの出力を要する」）。3 件をまとめて 1 つの機構で解くべきである。
**裁定要求 9** に上げる。

**痕跡**: 本 WP は 2 基を移植せず、`v3/adapters/llm/extraction.py` の共有機構
（4 スロット・エンベロープ・投入層）だけを先に着地させた。上流入力が配線され次第、
両基は `IntelProfile` を 1 つ書くだけで載る。

> **裁定（オーナー、2026-08-08）— H-3 は裁定済み。推奨 (c) を採用し、2 基は WP-4.1 へ繰延。**
>
> **裁定内容**: `hacktivist_intel` / `ground_osint` は **WP-4.1 へ DEFERRED**。
> 理由は本節の記述どおり — 入力が別アダプタの**出力**であり、宣言モデルに語彙が無い。
> 無理に通せば barrier 1 か barrier 2/4 のどちらかが壊れ、**それは §2-4 の教訓の反復**である。
> §7-2 #11（reduction）・#35（suppression）と**同じ構造ギャップ**なので、
> **3 件を 1 つの機構で解く**（別々に解けば A-02 = 同一計算の複数実装の再生産になる）。
>
> **母数への影響**: WP-2.7 の対象は **12 行から 10 行**（12 − 繰延 2）。
> このうち `convergence_tracker` は §4-3 が既にアダプタとして移植対象外としているため、
> **実際に build されるのは 9 基**。全体の総和は次の形になる:
>
> | 量 | 値 | 導出 |
> |---|---|---|
> | declared | **34** | §3-2 の 22 + §3-3 の 12（両表を文書からパースして突合） |
> | buildable | **33** | 34 − NOT_PORTED 1（`convergence_tracker`、§4-3） |
> | deferred | **2** | `hacktivist_intel` / `ground_osint`（本裁定） |
> | built（完了時） | **31** | 33 − 2 = WP-2.6 の 22 + WP-2.7 の 9 |
>
> 裁定文中の「22+10」は §3-3 の**行数**（12 − 2 = 10）で数えたもので、
> そこから `convergence_tracker` を引くと build 数は 9 になる。
> **数はコードで導出する**（`expected_adapter_ids()` = buildable − pending − deferred）ので、
> 表の値は主張ではなく計算結果であり、`tests/test_adapters_catalog.py::TestTotalityAcrossBothBatches`
> が両方向で fail する（繰延を striking せずに ship しても、ship せずに striking しても落ちる）。
>
> **実装**: `v3/adapters/catalog.py::DEFERRED_WP41`。理由・着地 WP・#11/#35 との同一機構性を
> エントリ本文に持たせ、テストがその 3 点の存在を検査する。
> **DEFERRED は PENDING と別の状態である** — pending は「本 WP がまだ負っている」、
> deferred は「本 WP には表現できず、表現できる WP を名指した」。
> `ground_osint` のエントリには**配線側への申し送り**を含めた: 本番は参照先 cache の鮮度も健全性も
> 検査していない（裸の `try/except Exception: pass`）ので、`Evidence.fresh()` を通さない配線は
> DP2/B-03 ごと移植することになる。

#### H-4（引き継ぎ、WP-2.7 実装中に確定、2026-08-08）— `hacktivist_news` の `attack_type` 既定値が「DDoS」である

**事実**: `safe_enum(data.get("attack_type"), {"DDoS","defacement","data_leak","combined","none"}, "DDoS")`
（`hacktivist_news_sensor.py:411-414`、`ast` 確認）。すなわち **LLM 応答が当該フィールドを欠落・破損させた場合、
表中で最大の `type_bonus`（+0.5、確認済み DDoS キャンペーンと同値）が付く**。
結果、**中身の無い応答（1.5）が、正しく報告された低緊急度のデータ漏洩（0.7）より高く出る**。

**なぜ §7-2 ではないか**: 現時点で差分は無い。**現行踏襲で移植した**（`v3/adapters/llm/hacktivist_news.py::ATTACK_TYPE_DEFAULT`）。
移植中に既定値を変えることは「転写を書き換えに変える手直し」そのものであり、
保守的な `"none"` への変更は**登録して承認を得るべき変更**であって黙って直すものではない。

**放置すれば必ず差分になる理由**: この既定値は**モデルの故障モードとスコアが結び付いている**唯一の箇所である。
モデル・プロンプト・`max_tokens` のいずれかが変われば欠落率が変わり、スコア分布が理由なく動く。
**着地先**: cutover 判定時のオーナー裁定（A6 と同じ扱い — 現行踏襲、裁定は cutover 後）。
**証跡**: `test_a_malformed_answer_is_scored_as_a_ddos_campaign`（既定値・スコア・順序関係を pin）。

#### H-2（裁定要求・オーナー保留）— AISHub エンベロープの欠陥を保存した

**欠陥**: AISHub の応答は `[header, [vessel, ...]]` である。現行系は
`vessels = vessels_raw[1:]`（`radar/sensors/ais_maritime.py:90`）で header 以降を取り、
続くループが `if not isinstance(vessel, dict): continue` で dict 以外を捨てる（同 96-98）。
`vessels_raw[1:]` の唯一の要素は**船舶の配列**であって dict ではないため、
**実船舶レコードは 1 件も検査されない**。`ais_maritime` は構造上発火し得ない。

**証拠**: `tests/test_adapters_physical.py::TestAisMaritime::test_the_nested_aishub_envelope_yields_no_vessels`
（`vessels_examined == 0` を pin）と、`::test_a_flat_envelope_does_detect_a_stationary_warship`
（平坦なエンベロープを与えれば停泊軍艦を正しく検出する = **規則自体は正しく、届いていないだけ**）。

**v3 の処置**: **保存**（`v3/adapters/physical/ais_maritime.py::_vessels`）。
移植中の無登録修正は P2 §5-C 違反そのものであり、直すこと自体が規律違反になる。
**DP7（`gps_jamming` の単位不整合 = 恒久無発火）と同型**の欠陥である —
発火し得ないセンサーの沈黙が平穏として読まれる。§3-2 の DP7 行と対にして読むこと。

**裁定を要する点**: 修正すれば `ais_maritime` は初めて発火し得るようになる。
方向は **sensitive**（v3 が高く出る）で、§7-2 への登録を要する差分になる。
DP7 の前例（§7-2 #1）は「NP1 側なので登録して進む」だが、そこには前提があった —
**WP-0.2 で現行系を先に直したため、修正後データで窓を取れば差分が消える**。
本件も同じ手順を踏むなら、**現行系の `ais_maritime` を先に直す**必要がある
（さもなくばパリティ窓が「v3 だけが発火する」で汚れ、C-02 に抵触する）。

**状態**: **オーナー裁定待ち**。裁定が下るまで v3 は欠陥を保存し、上記テストで pin し続ける。
選択肢は (a) 現行系を先に修正 → v3 も修正 → §7-2 に sensitive として登録、
(b) cutover 後に両系同時修正、(c) 保存継続（**非推奨** — 発火し得ないセンサーを 1 基抱えたまま
パリティを測ることになり、収斂の母数が構造的に 1 基分欠ける）。

> **拡張（2026-08-08、R6）— H-2 は `_vessels` だけの話ではない。**
>
> 本節は当初 `_vessels` の 1 件だけを扱っていたが、AST 掃引で **同じアダプタに 4 件の別欠陥**が出た。
> 重要な区別: `_vessels` は**本番の欠陥を保存したもの**（裁定待ち）だが、以下 3 件は
> **移植で v3 が持ち込んだもの**で本番に根拠が無い。したがって裁定を待たず**現行系に合わせて直す**
> （§7-2 の標準規律の (a) 側）。うち 2 件は**捏造アラーム**であり、掃引の中でも悪い方向に属する。
>
> | # | 欠陥 | 本番 | 方向 | 処置 |
> |---|---|---|---|---|
> | H-2b | チョークポイントの**国**がラベルに無い | `CHOKEPOINTS[i]["country"]` を持ち、`core.py:1254-1256` が `cp["name"]` 経由で国に結び付ける | 誤帰属 | `normalize` は `context.chokepoints` の `(name, lat, lon, country)` から解決する。現状の `countries[0] if len==1 else ""` は、2 国以上が視野に入った瞬間に全チョークポイント観測を `GLOBAL` に落とす |
> | H-2c | 船舶の **`TIME`** を読んでいない | `last_ts = float(vessel.get("TIME", now) or now)`（`ais_maritime.py:104`）— dark gap の唯一の入力 | insensitive | 出力に載せる。L1 の vessel history が来ても、**タイムスタンプが出力に無ければ dark gap は永久に計算できない** |
> | H-2d | 中心座標が無いとき `distance_km = 0.0` に**フェイルオープン** | 本番は `cp_lat/cp_lng` を常に持つ。0.0 は `< ANCHOR_RADIUS_KM (50)` を必ず満たす | **sensitive（捏造）** | 距離が計算できないなら判定しない。0.0 は「チョークポイントの真上」であって「不明」ではない |
> | H-2e | 壊れた船舶レコードを既定値に**強制変換**する | 本番は `except (ValueError, TypeError): continue` で**捨てる**（`ais_maritime.py:105`） | **sensitive（捏造）** | 捨てる。`SHIPTYPE` 欠損 → `0` は「非商用」= suspicious、`SOG` 欠損 → `0.0` は「停泊」— 壊れた 1 行が停泊中の軍艦として計上される |
>
> H-2d と H-2e は組み合わさると最悪になる: 座標を欠いたペイロードの壊れた行が、
> **距離 0 km に停泊する非商用船**として `stationary_anomalies` に入り、`score=1` で FIRED する。
> DP7 / `_vessels` が「発火し得ないセンサー」だったのに対し、こちらは「何も無くても発火するセンサー」であり、
> 沈黙の裏返しとして同じく NP1 に反する（誤検知はアナリストの信頼を削り、次の本物を見逃させる）。

---

## 4. O-17 準拠形（WP-2.7）

O-17 は現行のインテル周辺を「事実上の第二の採点パイプライン」と認定し、4 点を裁定している。
その 4 点に対する L0 側の着地を確定する。

### 4-1. LLM 抽出は S2 の 1 アダプタ

**決定**: LLM 抽出は `v3/adapters/llm/` の **1 アダプタ**。投入骨格は `v3/fetch/llm.py` の 1 実装。

**根拠**: A-02 実測 — LLM 投入骨格が **8 複製**し `max_tokens` が 200〜400 でばらついている。
複製が 8 あるということは、プロンプト・温度・解析の癖が 8 通りあるということであり、
S5-VERIF-022 の「記録済み応答の再生」はそのすべてに対して成立しなければならない。**投入口を 1 つにする**。

#### 4-1-1. 着地形（実装済み、2026-08-08）— 4 スロットは「振る舞い」の上限である

S1-sensors-info-llm §4 表 2 の「per-sensor は 4 スロット」を、実装は次のとおり解釈して着地させた
（裁定要求 10、オーナー裁定 7）。

| `IntelProfile` の面 | 種別 | 内容 |
|---|---|---|
| `prefilter` / `prompt` / `score_delta` / `domain` | **振る舞い（4 スロット）** | S1 表 2 のとおり。callable は**この 3 つだけ**であり、スイートが callable 集合を pin する |
| `dispositions` | 宣言データ | 応答処分表。`(field, values) → DROP(reason) / CAP(cap) / ACCEPT`。`matches_unrecognised` が `safe_enum` の既定値を表す |
| `signal_field` / `signal_absent_reason` | 宣言データ | 「どのキーがモデル自身の signal 判定を運ぶか」と「否のときの沈黙名」。7 系は `escalation_signal`、`hacktivist_news` だけ `is_active_campaign`（`:362`）で沈黙名も `not_active_campaign`（`:367`） |
| `response_items_key` | 宣言データ | 1 応答が**複数の答え**を返すキー名。`rss_narrative` の `clusters` のみ。空なら 1 応答 1 item |
| `llm_field_keys` / `max_tokens` / `schema_keys` | 宣言データ | 従来どおり |

**なぜ 4 スロットを「フィールド数」と読まないか**: 4 スロットが防いでいるのは
**センサー固有の振る舞いが抽出経路に戻ってくること**（A-02 の 8 複製）であって、データクラスの
フィールド数ではない。処分表は**分岐を隠す場所を持たない** — 行を読んで DROP/CAP/ACCEPT を適用するだけで、
そこにセンサーの癖を書き込む余地が無い。逆に**第 5 の callable にはそれがある**。
したがって守るべき不変条件は **「抽出の実装が 1 本であること」** であり、スイートはフィールド数ではなく
**callable 集合**を pin する（`TestTheProfileIsFourSlots`）。

**表が持つ不変条件**（型が強制、`DispositionRule.__post_init__`）:
- **callable は `DomainError`**（`ResponseValue.path` と同形）
- **DROP は reason 必須**（S1-INGEST-020「どの沈黙だったか」が共有名に潰れない）
- **CAP の値が confidence 床（0.35）を下回ることを禁じる**。本番は上限適用を床判定の**前**（`military_exercise.py:348`）と**後**（`:385`）の 2 箇所で行っており、
  両順序が一致するのは「すべての上限が床以上」である間だけである。この不変条件があるので
  **共有実装は 1 つの評価順序で足りる**（順序が観測可能にならない）。
- 同一 `(field, value)` を 2 行が主張することを禁じる（到達不能な行を作らない）

**評価順序**: 表は共有チェック**より前**に評価する。本番で非 relevance 規則を持つ唯一の系
（`military_exercise`）がその順序であり（`:343` が `escalation_signal` 判定より前）、
かつ**より具体的な沈黙を残す**（S1-INGEST-020）。二重失格 item の理由名だけが変わる — §7-2 #48 に登録。

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

**#7 以降は事前登録ではなく事後登録**である（#7/#8 は WP-2.6 実装レビュー 2026-08-07、
#9 以降は WP-2.6 remediation の AST 掃引 2026-08-08 で発見）。
事前登録の原則に反するが、P2 §5-C が禁じているのは「登録**外**の差分で cutover すること」であり、
**発見時点で登録すること**が規律の実体である。

> **標準規律（本表の全アダプタ、および今後の全アダプタ作業に適用）**
> 移植中に現行系との差分が生まれた場合の選択肢は **2 つしかない** —
> **(a) コードを現行系に合わせて戻す**か、**(b) 本表に登録する**か。
> **黙って残す選択肢は存在しない。**
> これは #7 に限った措置ではなく、**WP-2.6 の残作業・WP-2.7 で着地する 12 アダプタ・
> それ以降のアダプタ作業すべてに適用される常設ルール**である。
> 判断に迷う場合は登録側に倒すこと — 登録した差分が後に無意味になっても費用はゼロだが、
> 登録漏れの差分は cutover 中止事由になる。
> insensitive 方向（v3 が低く出る）は C-02/C-03 に直撃するため、**特に登録を優先する**。

> **承認状態（2026-08-08 追記）**: §9 のオーナー包括承認は **#1〜#53** を対象とする。
> **#54〜#70 は WP-3.1（L3 結論層）/ WP-3.2（L4 較正層）で新規に登録したもので、同種の包括承認を待つ**
> （#59〜#62 は WP-3.1 の敵対的レビューで発見された 3 CRITICAL / 4 HIGH の是正に伴うもの。
> **#63〜#70 は WP-3.2**。うち #63・#64 は本番関数との差分スイープ 122,284 入力で**実測検出**したもの、
> #65〜#70 は S1-calibration §5 の DEFECT-PRESERVE に対する v3 規範の実装）。
> 本表は L0 アダプタ以外の層の差分も受ける — 登録簿を層ごとに分ければ「どこにも
> 登録されていない差分」の生息域ができるため、**単一の登録簿を維持する**。
> #57（結論不可 4 分岐）には**オーナー裁定要求が 1 件**含まれる（`calibration_pending`
> の 30 日窓）。

| # | アダプタ | 差分 | 方向 | 扱い |
|---|---|---|---|---|
| 1 | `gps_jamming` | DP7 の単位不整合を解消 → **恒久無発火から発火するようになる** | sensitive | 差分は大きいが NP1 側。WP-0.2 で現行系も修正済のため、**現行系の修正後データで窓を取れば差分は消える** |
| 2 | `space_weather` | fail-open → fail-closed。両 endpoint 失敗時に Kp=0 を記録しない | sensitive（抑制が減る） | 登録 |
| 3 | `hacktivist_news` | A9 の破棄を廃止（プロンプトの宣言に合わせる） | sensitive | 登録 |
| 4 | `travel_advisory` | **A3 の最終 fallback（body に "travel" → level 2）を廃止** | **insensitive** | **裁定要求 4**。C-02/C-03 に直接抵触しうる唯一の項目 |
| 5 | `nasa_firms` → `nasa_eonet` | `sensor_id` を実ソースに合わせる（DP6 / NP6） | 中立 | 台帳の別名解決で吸収。dedup キーは `signal_source` 側なので収斂には影響しない |
| 6 | `ct_log` | 恒久 0 の `gov_count` を出力から削除 | 中立 | 消費者ゼロ（A18）。登録のみ |
| 7 | `threatfox` | S1-SENS-014 の「**0 件の国は hits に含めない MUST**」を反転し、**hits 0 の国にも `STATUS_OK` / `raw_score=0.0` の観測を出す**（`v3/adapters/cyber/threatfox.py::normalize`） | **採点に対しては中立**（発火国の集合・スコアともに不変。hits 0 の観測は `raw_score=0.0` で S1-SCORE-008 の MAX 畳み込みに寄与しない）。**観測面では sensitive**（観測件数が「シナリオ内対象国数」まで増え、鮮度・空白の判別材料が増える） | **登録**（WP-2.6 で発生。設計判断は NP1 由来 — 「hits 0」と「そもそも見ていない」が現行系では同一の不在として表現され、区別できない。区別可能にすることは NP1 の要求であり、S1-SENS-014 の MUST は cache サイズの都合であって検知規律ではないと判断した）。**パリティ上の注意**: WP-2.8 ハーネスは観測件数を突合対象に含めるため、本行を登録しないと「登録外差分」として cutover 中止事由になる。**採点系列の一致は本差分の影響を受けない** |
| 8 | `ct_log` | **untrusted-CA 判定が L1 待ちの間、score 3 が出ない**。現行系は「未知 CA × warmup 明け」で score 3 を出す（`radar/routes/core.py:1843-1848`）が、v3 の L0 は判定に要る 2 表（`ct_log_known_ca_per_domain` / `ct_log_domain_first_observed`）を持たないため `STATUS_OBSERVED` / 0.0 に留まる。結果、**現行系が 3 を出すペイロードで v3 は最大 2（wildcard）または 0** | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃の blocking 級**） | **登録**（WP-2.6 実装レビューで発見、2026-08-07）。**解消条件**: L1 の既知 CA 台帳 + warmup マーカーをアダプタへ供給する配線 — 実装先は **WP-4.1（合成ルート `v3/runtime/`）**。`normalize` は純関数で `NormalizeContext` しか受け取らないため、ベースライン値の供給は §3-5 H-1 と**同型の構造的ギャップ**（合成ルートが `NormalizeContext` に載せる形を決める）。**配線完了時点で本エントリは retire する**。それまでは `untrusted_ca_verdict: pending_l1_known_ca_ledger` と `untrusted_ca_candidate_count` が観測面に露出し、**取りこぼしは OBSERVED として可視**（OK として沈黙しない — §7-2 #6 と併せて `ct_log` の 2 件目の登録） |
| 9 | `ripe_bgp` / `cloudflare_radar` / `ooni_censorship` / `ripe_atlas` / `check_host` / `gps_jamming` / `ct_log`（**family、#8 を吸収**） | **L1 のベースライン／既知 CA 台帳／warmup マーカーが未配線の間、判定を保留してスコアを出さない**。該当アダプタは `STATUS_OBSERVED` / `raw_score=0.0` を出し、`flags` に `pending_l1_*` マーカーを置く。保留しているスコア幅と、本番でそれを出す条件（すべて `radar/routes/core.py` で実測）: `ripe_bgp` 0-1（`:1148` hour-of-day Z-score による BGP anomaly）／`cloudflare_radar` 0-3（`:1008-1025` HOD Z-score 1.5σ/2.5σ/3.5σ の段階、warmup 時は 2x/4x/6x）／`ooni_censorship` 0-2（`:1700` heavy=2 / censoring=1、前サイクル anomaly 数との比較）／`ripe_atlas` 0-2（`:1536` PROBE_BLACKOUT=2 / PROBE_DROP=1、前サイクル probe 数との比較）／`check_host` 0-3（`:1373` BLACKOUT=3 / PARTIAL=1、`checkhost_hod` による HOD 正規化）／`gps_jamming` 0-2（`:1810` critical=2 / jammed=1、前サイクル比）／`ct_log` 0-3（`:1843-1848` 未知 CA × warmup 明け） | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃の blocking 級**） | **登録**（R2 裁定、2026-08-08）。**#8 は本行に吸収する**（1 つの原因に 2 つの形を残さない。#8 の記述は `ct_log` 固有の詳細として参照可能なまま残す）。**解消条件**: L1 のベースライン供給配線 — 実装先は **WP-4.1（合成ルート `v3/runtime/`）**。`normalize` は純関数で `NormalizeContext` しか受け取らないため、ベースライン値の供給は §3-5 H-1 と**同型の構造的ギャップ**である。**retire 条件**: WP-4.1 が `NormalizeContext` にベースラインを載せ、上記 7 基すべてが本番と同じスコア幅を出すようになった時点で本行を削除する。**部分的に配線された段階で本行を残したまま cutover してはならない** — 残り 1 基でも保留していれば insensitive 差分は残る。**規律**: `pending_l1_*` マーカーは、**消費者が型を当てにしているキーを占有してはならない**。マーカーは非空文字列であり、bool として読まれるキーに置けば「永久に発火中」になり、同じキーを見る沈黙検出器を無効化する（`gps_jamming` の `surge`、`check_host` の `asphyxiation` が実例）。`ct_log` の `untrusted_ca_verdict` が定めた形に倣い、**到達できない判定は判定を運ぶフィールドから不在にし、兄弟キーで名指す**。不在は「述べていない」であり、`False` / `0.0` は偽陰性である |
| 10 | `threatfox` | **鍵が無いとき AUTH_MISSING を記録する**（現行系は「呼ばずに成功 0 件」）。現行系は `radar/sensors/threatfox.py:35-38` で `if not tf_api_key:` → `log_fetch(True, 0, 0, 0, "")` → `set_cache({"hits": {}})` → return。すなわち **(a) 訊いていないのに「訊いた、何も無かった」と記録し、(b) それまでの hits をキャッシュごと空で上書きする**。v3 は `client.py` の AUTH_MISSING（「訊けなかった」）を `fetch_log` に残す | **観測面 sensitive / 採点面 neutral**（v3 は空観測を作らない = 誤った平穏を作らない。採点は両系とも 0） | **登録**（R4-R3 裁定、2026-08-08）。optional にはしない — optional の基準は「本番が匿名で取得しているか」であり ThreatFox はそうではない（§2-4）。**方向は正直に言えば「v3 が『訊けなかった』と言う場所で現行系は『訊いたが何も無かった』と言う」であり、null-zone / 観測軸では sensitive、スコア軸では中立**。パリティ窓では threatfox の観測件数が両系で一致しないことが期待される。**解消条件**: 現行系側の同修正（NP1 由来なので現行系を直すのが筋）、または cutover |
| 11 | `cloudflare_radar` / `ripe_atlas` / `check_host` / `isr_hotspot` / `mil_support_air` / `space_weather` / `ais_maritime`（family） | **L0 は取得ペイロード 1 件につき観測 1 件を出すが、現行系は N 件のペイロードを 1 サイクル 1 国あたり **1 個の rationale エントリ**に畳んでいる**。`cf_spike_core`（core.py:1025）は L3 と L7 の合成、`cf_bgp_hijack`（core.py:1165）は hijacks と leaks の論理和、`ripe_atlas`（core.py:1547）は probes と 3 本の measurement RTT の合成（RTT は `ripe_atlas.py:133,137-147` で**国単位に pool してから** p95）、`check_host`（core.py:1376）は最大 3 URL の合成（`checkhost.py:197,239`）、`isr_hotspot` / `mil_support_air` は 1 国 N ゾーンの合算（§3-5 H-1）、`space_weather` は Kp と X 線の 2 endpoint、`ais_maritime` は 1 国 N チョークポイント。**このうち `space_weather` と `ais_maritime` は現時点で実際に衝突する** — 前者は country="" の 2 draft、後者は TW に 3 つのチョークポイントが紐づく（`geo_data.json` `CHOKEPOINTS`）。`normalize` は構造上 1 ペイロードしか見ないため（§2-2）、この畳み込みは L0 では実行できない | **観測面 sensitive**（行数が現行系より多い）／**採点面は畳み込み後に判定**（MAX・比率演算は WP-4.1 が行う） | **登録**（WP-2.6 remediation で発見、2026-08-08）。§3-5 H-1(b) と**同型**の構造ギャップであり、着地先も同じ **WP-4.1 の reduction ステップ**（ゾーン群／ペイロード群 → 国単位 1 draft → 閾値）。**畳み込みまでは各行が異なる `signal_source` を持たなければならない** — L1 は `UNIQUE (tick_id, sensor, signal_source, country)`（`schema.py:157`）で、同キー・**異内容**は `DomainError`、同キー・**同 `raw_score`/`status`/`observed_at`** は**黙って捨てられる**（`store.py:282-295`）。OBSERVED/0.0 の行同士は後者に当たるため、「本番の名前に揃える」ことが**静かなデータ喪失**になる。よって R1（signal_source を本番値に戻す）は本 family に対しては**採点を担う行にのみ適用**する（`ripe_atlas` の probes 行 = `ripe_atlas`）。**retire 条件**: WP-4.1 の reduction が入り、畳み込み後の行が本番の `signal_source` を持った時点 |
| 12 | `cloudflare_radar` | **BGP leak ペイロードの `signal_source` を `cf_bgp_leak` に分離**。現行系は hijack / leak を 1 エントリ `cf_bgp_hijack` に畳む（`core.py:1165`）が、v3 では別ペイロードとして到着するため同一キーだと L1 で衝突する。移植時の「MAX 畳み込みが論理和を再構成する」という docstring の前提は**誤り**で、畳み込みに到達する前に L1 が 2 行目を拒否（内容不一致なら `DomainError`、一致なら黙って破棄）していた | 中立（採点は WP-4.1 の reduction 後に一致）。ただし収斂カウント上は `signal_source` が 2 個になるため、NP2 の多ソース収斂で 1 事象が 2 ソースとして数えられうる | **登録**（2026-08-08）。#11 の family の具体例。**解消条件**: WP-4.1 が country 単位に reduce し、現行系と同じ 1 エントリ（`hijack=N(ongoing=M) leak=K` / `BGP manipulation detected: ...`）を再構成した時点 |
| 13 | `cloudflare_radar` | **BGP 論理和の合成 `value` / `fired_reason` が L0 では出せない**。現行系は country ごとに 1 レコード（`value="hijack=N(ongoing=M) leak=K"`、`fired_reason="BGP manipulation detected: M ongoing hijack(s), K route leak(s)"`、`core.py:1157-1176`）。v3 は endpoint ごとに `value="hijacks=N"` / `"leaks=K"`、`reason=""` | 中立（各半分の閾値は保存 — `ongoing>0` は無閾値、leak は 3 件） | **登録**（2026-08-08）。#12 と同じ WP-4.1 reduction で解消 |
| 14 | `ripe_bgp` | **stats 空応答を `STATUS_NO_DATA` / `value="NO_DATA"` として出す**。現行系のセンサーは `{"status": "NO_DATA", "is_anomaly": False}` を返すが、採点層は `is_anomaly` しか見ないため rationale は `OK` / `value="NORMAL"` / score 0 になる（`core.py:1140-1148`）。すなわち「RIPE がこの国のデータを持っていない」と「経路は正常」が現行系では**同一表現**になっている | 採点面 中立（score は両系 0）／**観測面 sensitive**（沈黙と正常が区別可能になる） | **登録**（2026-08-08）。NP1 由来 — 沈黙と正常の区別はツール定義の責務 (3)「結論不可の明示」そのもの |
| 15 | `greynoise` | **診断フィールド `api_key_configured` / `gnql_tier` / `noise_ips` / `status` を出力しない**（`radar/sensors/greynoise.py:242-251`）。前 2 者は環境変数の読み取りを要し、`v3/` 配下は `os.getenv` を規律ゲートで禁じているため L0 では原理的に出せない。`status` は `noise_class` の重複、`noise_ips` は `total_ips - malicious_ips` から復元可能 | 中立（採点・抑制ともに不変。`noise_ratio` / `noise_class` / `suppress_confidence` / `total_ips` / `malicious_ips` は一致） | **登録**（2026-08-08）。`gnql_tier` 相当の情報は AUTH_MISSING / HTTP status として `fetch_log` に出る |
| 16 | `opensky` | **`value` が空港名を含まない**。v3 は `f"{count} ac"`、現行系は `f"{airport}: {count} ac"`（`core.py:1114`、`AIRPORT_BOXES[code]["airport"]` 由来） | 中立（表示文字列のみ。status / score は一致） | **登録**（2026-08-08）。空港名は L0 に到達しない — ペイロードにもラベルにも無く `NormalizeContext` にフィールドも無い。`{airport}` プレースホルダの追加は WP-4.1 の展開器の判断 |
| 17 | `opensky` / `isr_hotspot` / `mil_support_air` | **body が読めないとき `STATUS_NO_DATA` を出す**。現行系のセンサーは `self.get_cache()` を返し、**前サイクルの読み（FIRED だったかもしれない）を再主張する** | v3 が 1 tick 分 **insensitive** になりうる | **登録**（2026-08-08）。取得できなかった読みの再主張は `freshness_horizon_sec` が禁じるもの（B-03）であり、L1 の horizon が置き換え機構である。アダプタの記憶で代替してはならない |
| 18 | `isr_hotspot` | **squawk を `str()` で正規化してから `== "7777"` を判定する**。現行系は生値を比較する（`isr_hotspot.py:59`）ため、JSON の数値 `7777` は現行系では一致せず v3 では一致する | **sensitive**（v3 が多く検知） | **登録**（2026-08-08）。戻すと JSON 数値表現の ISR 検知を落とすことになり、NP1 上は誤検知より悪い |
| 19 | `nasa_eonet` | **国ボックス判定に `within_box`（子午線で経度を折り返す）を使う**。現行系は折り返さない素の `abs(elng - tlng) <= radius`（`nasa_firms.py:83-84`） | **sensitive**（±180 度をまたぐ事象を拾う） | **登録**（2026-08-08）。`within_box` は `v3/adapters/common.py` の共有ヘルパで、単独アダプタのために fork すると A-02（同一計算の複数実装）を再生産する。`_THEATER_RADIUS` の全対象国は子午線から 3 度以上離れているため、現時点で実差は空集合 |
| 20 | `nasa_eonet` | **`flags` に `global_codes` を追加**（"Global only [...]" 分岐の導出根拠） | 中立（追加のみ） | **登録**（2026-08-08）。NP6 — 検証経路の無い文字列を出さないため |
| 21 | `usgs_seismic` | **`flags` に `candidate_countries` を追加** | 中立（追加のみ） | **登録**（2026-08-08）。核実験候補レコードは per-record `country` を持つが観測自体は global（country=""）なので、「どこで」をアナリストが読むための集合を別に出す |
| 22 | `usgs_seismic` | **数値フィールドを `as_float` の既定値で受ける**。現行系の素の `float()` / `props.get("mag", 0) >= 4.0` は null や非数値で例外を上げ、外側の `except Exception` が**その窓のフィード全件を捨てる**（`usgs_seismic.py:130-132`） | **sensitive**（1 レコードの破損で他の全事象を失わない） | **登録**（2026-08-08）。戻すと 1 行の破損で全損する失敗モードを復活させることになる |
| 23 | `ais_maritime` | **`value` の件数が「与えられた 1 チョークポイント」の範囲**。現行系の `core.py:1256` はサイクル内の全チョークポイントを跨いで `len(ais_dark_gaps)` / `len(ais_stationary)` を数える | 中立（当該チョークポイントの FIRED 判定は不変。印字される件数だけが狭い） | **登録**（2026-08-08）。#11 の family。チョークポイントの join は WP-4.1 の reduction |
| 24 | `ais_maritime` | **`flags` に `vessel_reports`（`{mmsi, last_ts, lat, lng}`、無制限）を追加** | 中立（採点に寄与しない） | **登録**（2026-08-08）。現行系は同じ組を `self._vessel_history` にプロセス記憶として書き（`ais_maritime.py:141`）rationale には出さない。L1 の dark-gap ベースラインには他に入力が無いため、出力に載せないと §7-2 #9 の `ais_maritime` 行は永久に解消できない。現行系は 24h TTL / 5000 件で大域的に上限を掛けている（`:143-152`）。**per-payload の上限は裁定事項**（裁定要求 6） |
| 25 | `gps_jamming` | **座標を持たない国に `STATUS_NO_DATA` を出す**。現行系の `add_rat` status は同じ国に対して `"OK"` であり、`country_status = "NO_DATA"` は value 文字列内の `[NO_DATA]` ラベルとしてしかアナリストに届かない（`core.py:1810`） | **sensitive**（v3 は盲点を宣言し、現行系は平穏を報告する） | **登録**（2026-08-08）。v3 の status 語彙には「ソースは動いたがこの国を測れなかった」があり現行系には無い。`flag_catalog.py:128-131` は `country_status` の NO_DATA を既に non-firing として扱うため L5 の予算に変化は無い |
| 26 | `gps_jamming` | **CSV 行が `TypeError` を上げる場合（短い行 → `csv.DictReader` が `None` で埋め → `int(None)`）にその行だけを捨てる**。現行系は `(KeyError, ValueError)` しか捕まえない（`gps_jamming.py:104`）ため例外が `fetch` の外側ハンドラまで抜け、**そのサイクルの全国を NO_DATA に落とす** | **sensitive**（v3 は測り続ける） | **登録**（2026-08-08）。センサー全体の暗転を純関数の per-payload `normalize` で再現する表現は無く、再現すること自体が insensitive 方向である |
| 27 | `openweather` | **クエリパラメータの順序が `lat, lon, units, appid`**。現行系は `lat, lon, appid, units`（`radar/sensors/openweather.py:25`） | 無し（OpenWeather は順序を区別しない。名前と値は同一） | **登録**（2026-08-08）。資格情報は fetch カーネルが末尾に付けるため、3 番目に差し込む形は宣言型 `RequestSpec` では表現できない（表現できるようにすると資格情報がアダプタ宣言に近づく） |
| 28 | `ripe_atlas` | 現行系は `add_rat("ripe_atlas", …)` の **1 エントリ**のみを出し、FIRED 判定は probe drop 由来、latency は value 文字列に混ぜて出る（`core.py:1533-1547`）。v3 の L0 は probe 用ペイロードと 3 本の measurement ペイロードを別々に受け取り 1 行に畳めないため **4 行**を出す: `signal_source="ripe_atlas"`（probe 半分 = WP-2.8 の突合行）＋ `atlas_latency_{1001,1004,10509}`。value も `f"{active} probes, {avg_ms:.0f}ms"`（`core.py:1544`）ではなく `f"{active} probes"` と `f"{avg}ms"` に分かれる | **観測面 sensitive**（行数増）／**採点は中立**（latency 行は `STATUS_OBSERVED` / `raw_score=0.0` で S1-SCORE-008 の MAX 畳み込みに寄与しない） | **登録**（2026-08-08）。#11 の family。名前を分けるのは選択ではなく**制約**（同キー・同内容の行は DomainError ではなく**沈黙して落ちる** — `store.py:290`, S5-VERIF-019）。**retire 条件**: WP-4.1 の reduction が 4 行を 1 行へ畳んだ時点 |
| 29 | `ripe_atlas` | **S1-SENS-041 の「国ごとに RTT を蓄積してから `avg_ms` / `p95_ms` / `probes_responding` を出す MUST」を L0 で満たせない**。現行系は 3 measurement の RTT を `latency_rtts[code]` へ蓄積し（`ripe_atlas.py:133`）ループ後に計算する（`:137-147`）が、`normalize` は 1 ペイロードずつしか見ないため v3 の値は **measurement 単位**になる（`pool_scope="single_measurement"` と `measurement_id` を併記）。国単位 p95 は measurement 別 p95 3 つから復元できないため、生サンプルを `rtt_samples` として搬送する | 中立（現行系でも `avg_ms` しか採点面に露出しない — `core.py:1538/1544` の value 文字列のみ） | **登録**（2026-08-08）。§3-5 H-1(b) と**同型の構造的ギャップ**。実装先は **WP-4.1**。`collect_rtts` / `percentile_95` は export 済で reduction は同じ算術を呼ぶ（DP4 の二重実装を作らない）。**配線完了時点で retire** |
| 30 | `ihr_health` | 現行系は hegemony に `add_rat` を持たず `country_status` と `deep_analysis.ihr.core_hegemony`（`core.py:2783`）にしか流さない。v3 は 3 エンドポイントを別ペイロードで受けるため hegemony にも観測行が要り、`signal_source="ihr_hegemony"`（`core.py:490` のキャッシュキー名を借用）で `STATUS_OK` / `raw_score=0.0` 固定の行を出す | **観測面 sensitive**（行が 1 本増える）／採点は中立 | **登録**（2026-08-08）。名前が要るのは**制約**（disco=`bgp` / delay=`ihr_delay` と同一 tick・同一国で衝突する）。スコアを付けないのは現行系に根拠が無いため。**パリティ上の注意**: WP-2.8 は観測件数を突合対象に含めるため、本行が無いと登録外差分になる |
| 31 | `ihr_health` | 現行系は `disco → hegemony → delay` の優先順で国状態を 1 つに確定する（`radar/sensors/ihr.py:167-177`）。v3 の L0 は各ペイロードが自分の段（`DISCO_EVENT` / `HEGEMONY_ALARM` / `DELAY_ANOMALY` / `NORMAL`）と `ladder_rank`（1/2/3/4）を報告するのみで、勝者の確定は 3 ペイロードの join を要する | 中立 | **登録**（2026-08-08）。実装先は **WP-4.1**（`ladder_rank` の min を取るだけ — 優先順を二度書かないためのデータ化）。**配線完了時点で retire** |
| 32 | `peeringdb_ixp` | 現行系は `?country=<code>` の応答レコード**全件を要求国でタグ付け**する（`radar/sensors/peeringdb.py:75,77`）。v3 はレコード自身の `country` フィールドで分類し、欠落時のみ要求国へフォールバックする | 中立（`STATUS_OK` / `raw_score=0.0` の台帳で採点に寄与しない。単一国クエリでは両者一致） | **登録のみ**（2026-08-08）。差し戻しは感度上の利得がゼロで、既存 pin（混在ペイロードを国別に割る前提）を壊す |
| 33 | `ioda_bgp` | 現行系は `alert.get("level", "normal")` を素のまま `"critical" in levels` で比較する（`radar/sensors/ioda.py:116-122`、大小文字を区別）。v3 は `.lower()` してから `LEVEL_RANK` で比較する | **sensitive**（上流が `"CRITICAL"` を返した場合、現行系は normal と読み v3 は critical と読む） | **登録**（2026-08-08）。IODA は小文字で publish しているため実データ上の差はゼロ。NP1 側なので revert しない |
| 34 | 全アダプタ（**cross-cutting**） | **ペイロードが言及しなかった国に対して観測行を出さない**。現行系は `COUNTRY_COORDS` の**全エントリ**に `"NORMAL"` を書く（`radar/sensors/ioda.py:139,174`、`ihr.py:177`、`ripe_atlas.py:158`）。v3 のアダプタはペイロードに現れた対象にのみ行を出す（`ihr_health` のみスコープ内の沈黙国を `OK` / `"—"` として出すよう修正済） | 採点面 中立／**観測面 insensitive**（「不在」と「測って何も無かった」が区別できなくなる — §7-2 #7 が `threatfox` について既に裁定した NP1 の形と同型） | **登録**（2026-08-08、WP-2.6 remediation で発見）。**未裁定**: 22 基すべてに跨る規約であり、アダプタごとに 4 通りの判断をするより 1 行で覆うべきと判断した。**裁定要求 7** を参照。#7 の前例（「見ていない」と「見たが 0」を区別可能にすることは NP1 の要求）が適用されるなら全アダプタで沈黙国にも行を出す方向になるが、その決定は観測件数を大きく増やすためオーナー裁定を要する |
| 35 | 全アダプタ（**cross-cutting**） | **抑制（suppression）は採点層の join であり L0 では表現できない**。`is_suppressed=sw_suppress`（space weather）は `ihr_disco` / `ihr_delay` / `ripe_atlas` に届き（`core.py:1495-1496,1550`）、weather と space weather の対は `ioda_bgp` に届く（`core.py:1090-1095`、value の ` weather_muted={…}` 断片は `:1090`）。いずれも**別アダプタの出力**を要するため、`normalize` が構造上到達できない（§2-2 barrier 4） | **sensitive**（v3 は抑制されるべき観測を抑制せずに出す = 誤検知側） | **登録**（2026-08-08）。実装先は **WP-4.1** の合成ルート（`suppressed` / `suppress_reason` は `ObservationDraft` に既にフィールドがあるので、決めるのは「誰が誰を抑制するか」の配線のみ）。**配線完了時点で retire** |
| 36 | **L2（WP-2.4 補遺）** | **LLM インテルの経年減衰が L0/L3 から L2 へ移る**。現行系は `intel_queue.get_active_rationale`（`radar/intel_queue.py:1001-1003`）で `score_delta × exp(−max(0,age)/τ)` を計算し、**減衰後の値**を消費者に渡す（`core.py:1925` の第 5 位置引数 = `add_rat` の `score`／`core.py:2078` の `raw_score`。いずれも `ast` で確認）。v3 は L0 が**未減衰の `score_delta` と item 自身の `observed_at`** を出し、`v3/scoring/decay.py` が唯一の減衰項を持つ。τ は `Threshold.pinned` で 12.0h（`config.env:96` の実配備値と一致）。**現行系の env スイッチ 2 件（`INTEL_AGE_DECAY_ENABLED`、source_type 別 τ 上書き）は移植しない** — `v3/` は env 読取を規律ゲートで禁じており、かつ実配備でどちらも既定のまま | **実配備の設定下では中立**（同じ式・同じ τ）。設定を変えた場合のみ差分 | **登録**（WP-2.7、§9 裁定 1 の実装）。**注意**: 現行系は `Signal(observed_at=current_time)`（`core.py:2074`）で **tick の時刻**を刻むため、下流で齢を復元すると常に 0 になる。v3 が `observed_at` を運ぶのはこの破壊を避けるため |
| 37 | **L2（WP-2.4 補遺）** | **48h TTL の打ち切りと (source_type, country) あたり 2 件の上限を L2 に置かない**。どちらも `get_active_rationale` の同じ関数内にあるが（`intel_queue.py:999` / `:1005-1017`）、**信号集合の構成**（S1-PIPE-023）であって算術ではない。v3 では合成ルート（WP-4.1）の責務 | **sensitive**（v3 は現行系が捨てる寄与を保持しうる。48h で weight は e^-4 ≈ 0.018 まで落ちるので影響は小さいが 0 ではない） | **登録**（WP-2.7）。**retire 条件**: WP-4.1 が信号集合構成に TTL と cap を置いた時点。近似で L2 に置かない理由は、置けば「減衰は L2、選抜も L2」となり O-17 が畳んだ責務が再び分かれるため |
| 38 | ~~**パリティハーネス（WP-2.8）**~~ | ~~**intel 行について両系の入力が非対称になる**~~ | ~~insensitive~~ | **RETIRED（2026-08-08、オーナー裁定により本 WP で修正）**。登録時の差分は「v2 ドライバが未減衰の `raw_score` を `radar.scoring` に渡す」ことだった。**`v3/parity/_v2_subprocess.py` が本番の `radar.intel_queue._age_weight` を*呼ぶ*ようにした**（S5-VERIF-031 — 式の再実装は禁止。`rationale_to_signal` と同じ扱いで、この層は引数を整えるだけ）。齢は **item の `observed_at` から tick まで**で測る（`get_active_rationale` の `now = time.time()` の意味であり、その 1 ステップ後には `core.py:2074` が tick 時刻で上書きして齢が消える）。**証跡**: `tests/test_parity_harness.py::TestIntelRowsAreAgedOnBothSides` — 6h 齢・score 6.0 の intel 行 1 件で、修正前は legacy が TL3・v3 が TL4（半 τ の減衰が閾値 4.0 をまたぐ）、修正後は両系 TL4 で一致率 1.0。`TestTheDriverUsesProductionsOwnDecay` が「`exp(` を書いていないこと」と「両系の `llm_intel` 綴りが一致すること」を pin。**残る差分**: `INTEL_AGE_DECAY_TAU_HOURS` を既定の 12.0 から動かした場合のみ（v2 は env を実読、v3 は pin）。それは #36 が既に登録済みの内容であり、本行に固有の差分は残らない。**副作用の記録**: `_age_weight` を呼ぶため sandbox に `radar.intel_queue` が 1 モジュール増えた。import 時の面（logger 1・`threading.Lock` 1・データ定数・`__init__` を持たない `IntelQueue()`・stub 済み `db`）を審査のうえ `EXPECTED_MODULES` に追加し、`test_reaching_for_the_production_term_did_not_widen_the_sandbox` が thread 1・boot なし・DB 呼出 1 件（既知の refused read）を pin する |
| 39 | `v3/adapters/llm/extraction.py` | **プロンプト注入フレーズ集合を移植していない**。`sanitize()` は切り詰め・NFKC・制御文字除去・チャットテンプレート区切りの除去を持つが、`radar/llm_client.py:61-99` の 4 言語ぶんの注入フレーズ正規表現は転写していない | 検知感度には中立（セキュリティ管理面の差分） | **登録**（WP-2.7）。S1-INGEST-011 が「関数本体は S4 担当」と明記しており、本 WP の範囲外。**解消条件**: S4 のサニタイズ管理が v3 に着地した時点。**それまで本番と同等の注入耐性は無い** |
| 40 | `tor_metrics` / `gdelt`（**#9 family、WP-2.7**） | **L1 のベースラインが未配線の間、判定を保留してスコアを出さない**。`tor_metrics` は `drop_pct` / `surge_pct` の双方が前サイクルの計数（`_prev_relay_counts` / `_prev_user_counts`、`radar/sensors/tor_metrics.py:34-35`）を要するため 4 段ステータス（`CENSORSHIP_INDICATOR` 2 / `RELAY_DROP` 1 / `USER_SURGE` **0** / `NORMAL` 0、`core.py:1560-1561`）を一切評価できず、両行とも `STATUS_OBSERVED` / 0.0。`gdelt` は `is_alert` が OR の 2 項（`gdelt.py:73`）のうち **固定閾値の項は評価して FIRED まで出す**が、**曜日別 Z の項（K18）は L1 待ち**なので、固定閾値に達しない場合は `OK` ではなく `STATUS_OBSERVED` にする | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃**） | **登録**（WP-2.7、2026-08-08）。#9 と同一原因・同一着地先（**WP-4.1** の `NormalizeContext` ベースライン供給）。**gdelt の固定閾値項をあえて発火させる**のは、保留に倒すと本番が出す発火を落とすことになり、それ自体が insensitive を増やすため。**規律は #9 のもの**: 保留マーカーは型を当てにされているキーを占有しない — `drop_pct` は数値（`tor_metrics.py:78`）、`status` / `is_alert` は閉じた語彙（`core.py:1131,1560`）なので、判定キーは**不在**にし兄弟キー（`drop_verdict` / `trend_verdict` / `dow_verdict`）で名指す。**retire 条件**: WP-4.1 が両基にベースラインを供給した時点 |
| 41 | `tor_metrics` / `gdelt`（**#11 family、WP-2.7**） | **1 国 1 サイクルにつき本番 1 エントリのところ v3 は 2 行出す**。`tor_metrics` は `/summary` と `/clients` の 2 応答（本番は両者を突合してから 1 つの `add_rat("tor_metrics")` に畳む、`core.py:1576`）、`gdelt` は `1d` と `{history_window}d` の 2 窓（本番は `delta` を計算して 1 エントリ、`gdelt.py:57`）。`normalize` は構造上 1 ペイロードしか見ない（§2-2 barrier 1）ため畳み込めない。命名は `tor_metrics` + `tor_clients` / `gdelt` + `gdelt_baseline` | **観測面 sensitive**（行数増）／**採点面 中立**（増える側は `STATUS_OBSERVED` / 0.0 で S1-SCORE-008 の MAX 畳み込みに寄与しない） | **登録**（WP-2.7、2026-08-08）。#11 の family。**名前を分けるのは選択ではなく制約** — L1 は `UNIQUE (tick_id, sensor, signal_source, country)` で、同キー・同内容の行は `DomainError` ですらなく**沈黙して落ちる**（`store.py:290`）。`ripe_atlas`（#28）/ `ihr_health`（#30）と違い**本番に借りられる別名が無い**ため、新しい名前を作っている — これは裁定要求 5 が「発明になる」と指摘した形そのものであり、**推奨 (b)（WP-4.1 の reduction）で一括解消されるまでの暫定**である。**retire 条件**: WP-4.1 の reduction が 2 行を 1 行へ畳んだ時点 |
| 42 | `gdelt` | **`WEATHER_NOISE` / `SUPPRESSED` を出せない**。本番は `weather_conditions[code]["is_severe"]` で `is_alert` を打ち消し `status="WEATHER_NOISE"` → `add_rat(..., "SUPPRESSED", ..., is_suppressed=True, suppress_reason="Severe weather detected")`（`gdelt.py:58,73,83` / `core.py:1132`）。`weather_conditions` は **別アダプタ（`openweather`）の出力**であり `normalize` は到達できない（§2-2 barrier 4） | **sensitive**（抑制されるべき観測が抑制されずに出る = 誤検知側） | **登録**（WP-2.7、2026-08-08）。#35 の family、着地先も同じ **WP-4.1** の合成ルート。`suppressed=False` を黙って残すと「悪天候ではなかった」と読まれるため、`flags["weather_verdict"] = "pending_wp41_weather_join"` で**検査していない事実**を明示する。**retire 条件**: #35 の配線と同時 |
| 43 | `gdelt` | **`STATUS_NO_DATA` を出す**。本番のセンサーは `{"status": "NO_DATA"}` を書く（`gdelt.py:55`）が、採点層は `core_tone.get("status", "NO_DATA")` を **`add_rat` の value 文字列**として渡すだけで status は `OK`（`core.py:1132`）。すなわち「GDELT が答えなかった」と「トーンは平穏」が同じ `OK` になる。v3 は 429/503（`gdelt.py:27`）・空 timeline（`:29`）・解析不能をすべて `STATUS_NO_DATA` として出す | 採点面 中立（両系 score 0）／**観測面 sensitive**（沈黙と平穏が区別可能になる） | **登録**（WP-2.7、2026-08-08）。#14（`ripe_bgp` の NO_DATA）と**同型**であり、根拠も同じ — 沈黙と正常の区別はツール定義の責務 (3)「結論不可の明示」そのもの。**特に本件は捏造の回避でもある**: レート制限応答をトーン 0.0 として読むと、閾値 −15.0 より上の「中立な報道」を情報源が report していないのに publish することになる || 44 | `bg_observer_rss` | **フィード台帳は `config.py:654-661` の既定 3 本ではなく `config.env:187` の実配備 9 本を pin する**。既定は BBC / Al Jazeera / AP の西側 3 本のみで、本センサーは**西側ソース偏重を是正するために存在する**。実配備が足している 6 本（SCMP・TASS・新華社・CNA・Japan Times・聯合ニュース・台北時報）が台湾・朝鮮半島シナリオを可視にしている当のソースである。稼働ログ `[bg_observer.sensor] started — interval=300s, feeds=9` で実配備値を確認 | コード既定を転写していたら **insensitive**（フィード 2/3 と非西側全滅）。実配備を pin したので**差分なし** | **登録**（WP-2.7、2026-08-08）。pin の根拠は `gdelt` のトーン閾値と同じ「実配備値を pin する」原則。`config.env` が変わったら CI が落ちるよう `test_the_deployed_ledger_matches_config_env_exactly` が突合する |
| 45 | `bg_observer_rss` | **feed 死因の分類が `fetch_log.outcome` に届かない**。`classify_feed` は §1-7 の死因を返すが、fetch カーネルは HTTP 結果からしか `outcome` を書かないため、`returns_html` / `rss_empty` は台帳に載らない。現行系の `feeds_failed` カウンタ（A10: 「取得成功だが 0 件」を障害と同一計上）も再現していない | 観測面のみ（採点中立）。A10 の**分離自体は達成**（`parse_feed` が原因を返す）だが、**記録先が無い** | **登録**（WP-2.7、2026-08-08）。**解消条件**: WP-4.1 が `classify_feed` を `record_fetch` に配線した時点。バイト列を二度パースしないため、アダプタに台帳ハンドルを渡すのではなく**カーネルに関数を渡す**形にしてある |
| 46 | `bg_observer_rss` | **実配備フィードのうち 3 本が平文 HTTP**（新華社・TASS・台北時報）。`config.py:648-653` は「網路経路上の攻撃者が悪意ある RSS を注入できないよう既定リストは TLS のみにする」と明記し、**新華社エントリはまさにその理由で既定から外された**と書いてあるが、実配備はそれを上書きして 3 本を戻している | セキュリティ管理面（検知感度は中立） | **登録・現行踏襲**（WP-2.7、2026-08-08）。`https://` へ書き換えて 404 になればフィードが消える = insensitive 方向であり、スキームは S4 が持つ判断。`PLAINTEXT_FEEDS` に名前を出してあるので修理は 1 行 |
| 47 | `bg_observer_rss` | **`evidence_url` に記事リンクを載せる**。現行系は `evidence_url=None`（`background_observer.py:398`）で表示文字列しか持たないため、**アナリストがスコアの出所の記事に到達できない** | 中立（追加のみ） | **登録**（WP-2.7、2026-08-08）。NP6 — 検証経路の無い結論を出さない |
| 48 | LLM 抽出全系（**cross-cutting**） | **二重失格 item の drop reason 名が変わりうる**。共有実装は処分表を最初に評価する（§4-1-1）。本番は `military_exercise` が `event_type` を先（`:343`）、`theater_link` を scope 判定の後（`:374`）に置き、`diplomatic` は `escalation_signal` と床を同時に見る（`:479`）。**スコアと採否は不変**（CAP が床を下回れない不変条件が保証する）。変わるのは「どの理由で落ちたか」の名前だけ | 中立（採否・スコア不変）／診断面のみ | **登録**（WP-2.7、2026-08-08）。1 実装に 8 通りの評価順序を持たせないための代償。**併せて修正した 2 件の不忠実**: (a) `escalation_signal` を `is False` で判定していた（本番は `not data.get(..., False)` なので**キー欠落は drop**）、(b) `theater_link` の未知値を direct 扱いしていた（本番は `safe_enum` 既定 `none` = **drop**）。どちらも v3 が**多く通す** sensitive 方向だったので、本番に合わせて戻した |
| 49 | `diplomatic` / `hacktivist_news` | **feed 死因の `unknown` を持たない**。本番の `_classify_feed` は 5 値（`rss_with_items` / `rss_empty` / `returns_html` / `unparseable` / `unknown`）を返す。共有パーサは前 4 者を保ち、catch-all の `unknown` の代わりに `http_error` / `geo_block` / `entity_attack` を返す | 観測面 sensitive（原因が特定される）／採点中立 | **登録**（WP-2.7、2026-08-08）。`unknown` は原因が調べられなくなる場所であり、K08 の資産価値は「5 通りに分ける」ことではなく「**名前の付いた原因を返す**」ことにある |
| 50 | `telegram_mirror` | **UA プールを回さない**。K13 のプール 5 本は**宣言データとして持つ**が、リクエストは先頭 1 本を送る。リクエストごとの選択を宣言型が表現できない（`RequestSpec.headers` は固定写像）ため | 未知（`t.me` が単一 UA を throttle する可能性）。**potentially insensitive** | **登録**（WP-2.7、2026-08-08）。**着地先: WP-4.1**（`USER_AGENT_POOL` は export 済で、配線側はそれを引くだけ — 二重台帳を作らない）。retry/backoff は既にカーネル（`v3/fetch/policy.py`）が持つ |
| 51 | `telegram_mirror` / `rss_narrative` / `travel_advisory`（**#11 family、WP-2.7**） | **1 サイクル 1 国につき本番 1 エントリのところ、v3 は入力ペイロードごとに 1 行出し、行ごとに別 `signal_source` を持つ**（`telegram_{channel}` / `narrative_{feed}` / `advisory_{us,uk,ca}`）。本番はチャンネル群・フィード群・3 政府をそれぞれ**畳んでから**命名するため、借りられる名前が存在しない | 観測面 sensitive（行数増）／**採点中立**（増える側は `STATUS_OBSERVED` / 0.0 で S1-SCORE-008 の MAX 畳み込みに寄与しない） | **登録**（WP-2.7、2026-08-08）。**名前を分けるのは選択ではなく制約** — L1 は `UNIQUE (tick_id, sensor, signal_source, country)` で、同キー・同内容の行は `DomainError` ですらなく**沈黙して落ちる**（`store.py:290`、S5-VERIF-019）。#41 と同型の暫定であり、**retire 条件**: WP-4.1 の reduction が畳んだ時点。畳み込みに要る算術（`theater_status` / `claim_confidence` / `converge` / `burst_status` / `first_signal_zscore`）は**すべて export 済**で、reduction は書き直さず呼ぶ（DP4） |
| 52 | `rss_narrative` | **A8 の `NARRATIVE_ZSCORE_FIRST_SIGNAL` を `Threshold.pinned` で出典開示する**（既定 3.0 = CRITICAL）。本番は比較地点で `os.getenv` を直読し（`:610`）どのレジストリにも無い。`v3/` は env 読取を規律ゲートで禁じている | 実配備の設定下では中立（同じ値） | **登録**（WP-2.7、2026-08-08）。§3-3 は「NP1 直結の値なので**運用可変キーに登録**」（O-18 (a) 群）と定めており、pin はその registry が着地するまでの形。**retire 条件**: 運用可変キーのレジストリが v3 に着地した時点。**本項が重要な理由**: 静穏なベースラインに対する最初の活動を CRITICAL バーストに変える分岐であり、**センサー中最も感度の高い数値が設定画面から見えない** |
| 53 | `rss_narrative` | **`TACTICAL_KEYWORDS`（110 国）と `NARRATIVE_GEO_TERMS`（36 国）を転写せず `NormalizeContext` で受ける**（`tactical_keywords` / `geo_terms` を追加）。フィード台帳（9 本）は転写する — 取得先を決めるため | 中立（同じデータを別経路で受ける） | **登録**（WP-2.7、2026-08-08）。座標を受けるのと同じ論拠: **コードリリース無しに変わる配備データ**であり、`v3/` 側の複製は同期させ続ける第 2 台帳になる |
| 54 | L3 `trend`（**WP-3.1**） | **TREND の severity 写像を `5−TL` から `6−TL` に統一する**（`v3/ledger/views.severity_window_pair`）。本番 `radar/conclusions/trend.py::_TL_SEVERITY` は `{1:4,2:3,3:2,4:1,5:0}` = `5−TL` で、用語規約およびカーネル `ThreatLevel.severity()` の `6−TL` と切片が異なる | **分類は完全中立**（delta = 現在平均 − 直前平均 で定数シフトは相殺、5 状態の境界判定は一致）。`metadata.windows[*].current_mean_severity` / `previous_mean_severity` は**ちょうど +1.0 ずれる** | **登録**（WP-3.1、2026-08-08。P6 O-15 の実施）。TL 反転事故 2 回の前歴があるプロジェクトで同語二系統を残す方が危険という判断。証跡: `TestSeverityWindowPair::test_a_constant_shift_leaves_the_delta_unchanged` が両スケールの delta 一致と平均の +1.0 差を同時に pin する |
| 55 | L3 `anomaly`（**WP-3.1**） | **novelty の `similar_count` を「ANOMALY 台帳行数」から「L1 signal_observation ストリームの出現回数」に変える**（シナリオの participants + GLOBAL で絞る）。本番は `radar/conclusions/anomaly.py::_ledger_similar_count` が同一シナリオ・同一 signal_source の ANOMALY 行を 24h 数える | **importance の順位が動く**（台帳が間引かれている本番では count が構造的に小さく、novelty＝importance が上振れしていた。ストリーム側は間引かれないので count は増え、**novelty は下がる = importance は下がる**）。方向は **insensitive**（v3 が低く出る）だが、対象は**順位付けのみ**で TL・発火判定には影響しない | **登録**（WP-3.1、2026-08-08）。S1-conclusions ACCIDENTAL A8 が「変化ゲートと novelty の相互作用が未評価」として提起し、**「台帳行数から観測ティック数へ」という再定義を推奨していた**もの。O-16 が変化ゲートを廃した v3 では台帳依存を残す方が危険（結論台帳の書込規律を変えるたびに公開数値が動く）。**副作用**: シナリオ隔離が participants 経由になるため、**participant を共有する 2 シナリオは互いの観測を数える**（本番は完全隔離）。証跡: `TestAnomaly::test_novelty_counts_come_from_the_unthinned_signal_stream` |
| 56 | L3 `threat_level`（**WP-3.1**） | **rationale_matrix の 3 列が空になる** — `value_display` / `suppress_reason` は L2 の `Contribution` に存在せず、`evidence_url` は `ScenarioContext.evidence_urls`（呼び出し側が L1 の観測から組む写像）経由でのみ入る。本番 `radar/conclusions/threat_level.py:83-111` は `ScenarioContribution.signal` からこの 3 つを直接読む | 観測面 **insensitive**（NP6 の開示が痩せる）／**採点中立** | **登録**（WP-3.1、2026-08-08）。**解消条件**: L2 `Contribution` に 3 フィールドを足すか、合成ルート（WP-4.1 `v3/runtime/`）が `evidence_urls` と同じ形で供給するか。**#9 family と同型の構造的ギャップ**（純関数が受け取る文脈に何を載せるかを合成ルートが決める）。`age_weight` は逆に v3 側だけが持つ（L2 が S1-INTEL-020 の減衰を分離して運ぶため）ので、**列は 1 増 3 減** |
| 57 | L3 全型（**WP-3.1**） | **結論不可が 4 理由に分岐する**。本番は 3 値に生成経路が無く全て `insufficient_data`（F-12）。v3 は `upstream_failure`（全ソース fetch 失敗）/ `sensor_degraded`（過半が失敗または鮮度期限切れ）/ `calibration_pending`（シナリオ観測履歴が較正窓 30 日未満）/ `insufficient_data`（ソース 0 件、または型固有の導出不成立）を出し分ける | **理由コードの分岐は sensitive**（区別が増える）。**追加で、健全でない入力の下では平穏側判定が結論不可になる** — 本番が TL5 / STABLE を返す tick で v3 が `state=null` を返しうる。方向は「平穏を主張しない」= NP1 上 sensitive | **登録**（WP-3.1、2026-08-08）。P2 §5-C は既に「結論不可の理由: v3 は 4 種を区別、旧系は実質 1 種（F-12）→ 意図的差分」を計上しており、本行はその**実装形の確定**（閾値と発火条件を数値で固定）。cutover 条件 **C-08（override 禁止）**の充足物。**パリティ上の注意**: パリティ比較は severity 空間で行われるため、`state=null` の tick は比較対象外（両系で null になる tick 以外は差分として現れる）。**要オーナー裁定**: `calibration_pending` の 30 日窓は S1-CONC-029 の較正窓に合わせたが、**新規シナリオは登録後 30 日間、平穏側の結論を出さない**（警報側は NP1 により常に出る）。より短い窓を選ぶ余地がある |
| 58 | L3 永続化（**WP-3.1**） | **結論台帳の heartbeat 書込を持たない**。本番は「state 不変かつ heartbeat 周期（3600s）未満なら省略」（S1-CONC-031）で、周期到達時には同一 state でも 1 行書く。v3 は**変化のみ**（heartbeat 無し） | 台帳行数が減る／**検知は中立** | **登録**（WP-3.1、2026-08-08）。heartbeat が存在した理由は「間引きが慢性結論不可検知を壊す」ことへの補償であり、O-16 が慢性検知を無間引き TL ストリームの派生ビューに移した時点で補償対象が消えた。証跡: `TestThinningCannotBreakDetection::test_it_is_unchanged_when_every_duplicate_write_is_suppressed`（結論行 0 件でも慢性判定が成立することを示す）。**retire しない**（恒久的な設計差分） |
| 59 | L3 `anomaly`（**WP-3.1**、#55 の補正） | **novelty の計数対象を `status='FIRED'` の観測に限定する**。`signal_observation` は**ポーリング 1 回につき 1 行**（`v3/fetch/runner.py:419`、status 不問）であり、無条件に数えると健全で静穏なセンサーが 900s 周期で 1 日 96 回「反復」したことになり、`novelty_factor` が全ソースで下限 0.3 に張り付く | **是正前は insensitive**（importance と confidence が 3.3 倍過小、しかも `novelty_source` は健全ラベルのまま = D-01 の再生産）。是正後は「発火回数」= 本番台帳計数の無間引き版 | **登録**（WP-3.1 レビュー指摘 C-2、2026-08-08 是正）。#55 の「ストリームで数える」裁定は維持し、**分母の意味を「観測された回数」から「発火した回数」に正す**。証跡: `TestAnomaly::test_polls_do_not_count_as_repetitions` / `::test_a_saturating_number_of_firings_still_reaches_the_floor` / `::test_the_lookback_window_is_twenty_four_hours`。**participants 未設定時**は GLOBAL のみに絞られ過小計数（= importance 過大 = 安全側）になるため `novelty_source: signal_stream_fired_24h_unscoped` で明示する |
| 60 | L3 `availability`（**WP-3.1**） | **NP1 の override はソース 0 件のとき適用しない**。警報側の候補でも「一件も参照していない」状態では発表せず結論不可にする | sensitive 方向の**制限**だが、代替は「例外で 5 型すべてが消える」であり、欠落 tick は全下流ビューで健全 tick と区別できない | **登録**（WP-3.1 レビュー指摘 C-3、2026-08-08 是正）。部分的な証拠からの警報は発表する（NP1）。**無い証拠からの警報は発表しない** — `Conclusion` が G-17 として state を拒否するため、override すると `DomainError` が `derive_all` を貫通し、**平穏シナリオは 5 行そろって記録され警報シナリオだけが消える**。証跡: `TestNP1Asymmetry::test_an_alerting_candidate_with_no_basis_is_not_overridden` / `::test_that_alerting_scenario_still_produces_a_conclusion` |
| 61 | L3 永続化（**WP-3.1**、#58 の補正） | **書込同一性に「どのガードが発言したか」を含める**（state / reason に加え `suppression.(guard_id, reason, overridden)`）。ANOMALY バッチ署名には加えて **importance の 10 点バンド**と scenario_id を含める | 台帳行数が増える方向（= 記録が増える）。**是正前は insensitive**: 全ソース死亡でも TL が動かなければ「変化なし」で書かれず、台帳最新行が健全な 4 ソースを主張し続けた（G-17 の 1 層下） | **登録**（WP-3.1 レビュー指摘 C-1 / H-1 / H-3、2026-08-08 是正）。S1-CONC-032 が署名から除くのは**多重度**であって**規模**ではない。バンド化により減衰ドリフト（900s tick で約 2%）では署名が動かず、8→100 の変化では動く。scenario_id 追加は**シナリオ横断の取り違え**（別シナリオの初回異常が消える）の封じ込め。証跡: `TestHealthCollapseIsAlwaysWritten` / `TestImportanceIsNotMultiplicity` / `TestScenariosDoNotCollapseIntoEachOther` |
| 62 | L3 `per_domain` / `views`（**WP-3.1**、軽微 2 件） | (a) `confidence` の magnitude 項に**下限 0 クランプ**を追加（本番 `per_domain.py:172` は上限のみ。同モジュールの `classify` は負のドメインスコアが起こると明記しており、負値では confidence が負になり `Conclusion` が拒否 → v3 では tick 全体が消える）。(b) `severity_window_pair` の窓幅に `Window.effective_seconds`（cadence 刻みで floor）ではなく**宣言値**を使う | (a) 本番も同じ式で壊れる入力でのみ差が出る。(b) floor すると窓が短くなり標本不足→INSUFFICIENT に倒れる = **insensitive** ので宣言値が正 | **登録**（WP-3.1 レビュー指摘 M-1 / L-1、2026-08-08）。証跡: `TestSeverityWindowPair::test_the_span_is_the_declared_window_not_a_floored_sample_count` |
| 63 | L4 `history.clamp_magnitude`（**WP-3.2**） | `prior == 0` で**記録する `magnitude_pct` を 100.0（センチネル）にする**。本番 `auto_tune_governor.commit` は candidate=100.0 → 上限超過と判定 → `_clamp_to_magnitude` が prior==0 では new をそのまま返すのに、**台帳には `magnitude = max_pct`（10.0）を書く** | 中立（採点に影響しない台帳表記のみ）。ただし本番の記録は**無制限の変更を「予算ちょうど」と申告**しており NP6 に反する | **登録**（差分スイープ 122,284 入力中 9,961 件で検出、2026-08-08）。ACCIDENTAL A13 の隣接。値そのもの（クランプしない）は本番と一致 |
| 64 | L4 `status.design_w_gate`（**WP-3.2**） | recall 低下の境界比較を**有理数で行う**（`Fraction`）。本番は float 減算のため `1.0 - 0.95 = 0.050000000000000044 > 0.05` となり、S1-CALIB-029 分岐⑤の「**境界の等号は PASS 側 MUST**」が**二進表現できない recall 対では成立していない** | v3 が PASS、本番が FAIL。**条項どおりなのは v3**。方向としては v3 が緩い側だが、差は許容幅ちょうど 1 単位に限られる | **登録**（差分スイープ 6,000 対中 3 件で検出、2026-08-08）。S5-VERIF-034 の「丸め前の有理数で比較 MUST」の実装でもある |
| 65 | L4 較正入力（**WP-3.2**、DP23） | 較正入力の窓を**明示（`EpochStamp`）**し、`tp+fn == 0` を **`None`（測れない）**とする。本番 `tl_threshold_calibrator` は窓を持たず（全履歴）、`tp/max(1,tp+fn)` で **0.0（測った、そして最悪）**を返す | **sensitive 側**（0.0 は recall floor を必ず下回るため本番は緩和提案を出す。v3 は測定不能として提案しない） | **登録**。DP23 の v3 規範そのもの。証跡: `TestDirectionDecision::test_an_unmeasurable_recall_never_loosens` |
| 66 | L4 `proposals.stepped_value`（**WP-3.2**、DP22） | ±5% ステップに**絶対上下限**（band 既定値の 0.5〜2.0 倍）を追加。本番は下限が無く、反復緩和が幾何級数的に 0 へ収束する（middle_east は 12 連続緩和） | 中立〜sensitive（閾値が下がり切るのを止める＝発火しやすさの暴走を止める） | **登録**。DP22 の v3 規範。証跡: `TestStep::test_repeated_loosening_stops_at_an_absolute_floor` |
| 67 | L4 `proposals.generate`（**WP-3.2**、DP2） | 提案の `Provenance.inputs` に**鮮度ゲートの入力**（`motivating_at` / `last_applied_at`）と**エポック・窓・exclude_auto** を含める。本番 evidence は `{recall, precision, tp, fp, fn, tn, direction, prior_value}` のみ | 中立（記録が増える方向） | **登録**。NP6: 台帳から「どの FN がこの変更を正当化したか」を再構成できるようにする |
| 68 | L4 `history.lineage`（**WP-3.2**、DP20） | 探索結果に **`complete` / `truncated_because`** を持たせる。本番は欠損行・深さ上限・循環のいずれでも**部分グラフを黙って返す** | 中立（記録が増える方向） | **登録**。証跡: `TestLineage::test_a_missing_predecessor_makes_the_walk_incomplete` |
| 69 | L4 `guards.evaluate`（**WP-3.2**、DP18 / G-07） | ガード述語が例外を投げた場合を**発火（拒否）として扱う**。本番 `auto_tune_governor._recall_gate_is_red` は裸の `except` で False（= red でない）を返し、呼ぶ関数が存在しないため**恒久的に開いている** | **sensitive 側**（v3 は較正変更を止める方向に倒れる） | **登録**。ADR-V3-006（fail-closed）の適用であり、WP-3.2 完了条件 1 の一部。証跡: `TestGuardsFailClosed`（4 件） |
| 70 | L4 `status.design_w_gate`（**WP-3.2**、S5-VERIF-037/038） | (a) ゲートは **strict**（本番 `check_recall_post_autotune.py` は既定 warn-only、`check_ci.sh` が `--strict` を付けないため構造上 CI を落とせない）。(b) **退化 cell（`fn==0 ∧ tn==0`）は判定の根拠にできない** — baseline 側は warn、現行側で新たに退化したら FAIL | (a) sensitive 側。(b) sensitive 側（本番は退化 cell の recall=1.0 を「改善」として通す） | **登録**。S5-VERIF-037 の「件数でなく述語で」を型で強制（`CalibrationEvidence` が退化 cell を含めない）。証跡: `TestDegenerateCellsCannotBecomeEvidence` / `TestDesignWGate::test_a_cell_that_becomes_degenerate_fails` |

---

## 8. 裁定要求

以下 10 件は本書の権限を超える。**各件に推奨を付す**。（1〜4 は 2026-08-07、5〜8 は WP-2.6 remediation で追加、9・10 は WP-2.7 実装中に追加、いずれも 2026-08-08。**9 と 10 は裁定済み**）

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

### 裁定要求 5 — 1 国 N ペイロードの `signal_source` 命名（§7-2 #11 の未決部分）

**問題**: §7-2 #11 に登録したとおり、L0 は取得ペイロード 1 件につき観測 1 件を出す。
`check_host` は 1 国あたり最大 3 URL を問い合わせる（`checkhost.py:197` の `for url in urls[:3]`）ため、
**同一 tick / 同一 sensor / 同一 country で 3 行**が出る。R1 に従って `signal_source` を本番値
（`check_host`）に揃えると 3 行は同一キーになり、`store.py:282-295` の規則により
**`raw_score`/`status`/`observed_at` が一致する限り黙って捨てられる** — 3 URL のうち 2 URL の測定が
記録されずに消える。OBSERVED/0.0 が並ぶ通常時こそ一致するので、**平常時ほど静かに消える**。

**なぜ本書で決めないか**: 解は 2 つあり、どちらも本 WP の権限を超える。
(a) スコープ由来のキー命名規約を作る（例: 対象 URL / ゾーン名を `signal_source` に含める）。
これは L1 の dedup 同一性と WP-2.8 の結合キーの意味を変える。
(b) L1 書き込み前に reduction を置き、国単位 1 行に畳んでから書く（§7-2 #11 の retire 条件そのもの）。
**移植中に命名規約を発明することは P2 §5-C 違反そのもの**なので、発明せず登録して上げる。

**推奨: (b)**。(a) は「1 国 1 行」という現行系の観測粒度を恒久的に変えてしまい、
retire 条件を満たせなくなる。(b) は §3-5 H-1(b) / §7-2 #11 と着地先が同じ（WP-4.1 の reduction）で、
新しい概念を増やさない。**それまでの間、`check_host` は合成ルートが存在しないため実害は出ていない**が、
WP-4.1 が reduction を置く前に 1 国 N URL を配線すると、その瞬間に静かな欠落が始まる。

**対象は `check_host` だけではない**（掃引で確定した全件）:

| アダプタ | 1 国 N 行になる理由 | 現在の処置 |
|---|---|---|
| `check_host` | 1 国最大 3 URL（`checkhost.py:197`） | **未解決** — 本裁定要求の主題 |
| `space_weather` | Kp と X 線の 2 endpoint、いずれも `country=""` | **未解決** — 本番名 `space_weather` のまま。`raw_score`/`status` が一致すれば沈黙落ち、違えば `DomainError` |
| `ais_maritime` | 1 国 N チョークポイント（`geo_data.json` `CHOKEPOINTS` は TW に 3 件） | **未解決** — 本番名 `ais_maritime` のまま |
| `isr_hotspot` / `mil_support_air` | 1 国 N ゾーン（§3-5 H-1） | **未解決** — 本番名のまま |
| `cloudflare_radar` | l3/l7、hijacks/leaks | 解決済（`cf_l3`/`cf_l7`、`cf_bgp_hijack`/`cf_bgp_leak`、§7-2 #12） |
| `ripe_atlas` | probes + 3 measurement | 解決済（`ripe_atlas` + `atlas_latency_{id}`、§7-2 #28） |
| `ihr_health` | disco / hegemony / delay | 解決済（`bgp` / `ihr_hegemony` / `ihr_delay`、§7-2 #30） |

解決済の 3 基は**本番に別名の根拠があった**（別 `add_rat` エントリ名、または別 measurement id）。
未解決の 5 基には無い — 名前を作ることが発明になる。**推奨 (b) はこの 5 基を一括で解く**。

### 裁定要求 6 — `ais_maritime` の `vessel_reports` に上限を置くか

**問題**: §7-2 #24 で追加した `vessel_reports`（`{mmsi, last_ts, lat, lng}`）は dark gap 判定の唯一の入力で、
現行系は距離に関係なく**全船舶**を `self._vessel_history` に書く（`ais_maritime.py:141`）。
1°×1° の AISHub ボックスは数百行を返しうるので、これが L1 の `flags` に丸ごと入る。
現行系は 24h TTL / 5000 件で**大域的に**上限を掛けている（`:143-152`）が、
それは L1 のベースライン表がやるべき境界であって、アダプタが per-payload に切る話ではない。

**推奨**: **上限を置かない**（現状のまま）。アダプタ側で切ると、切った先が
「その船は居なかった」と読める — dark gap は**居たものが消えること**を見る規則なので、
入力を黙って切ることは検知漏れそのものである。境界は L1 の保持方針（S3 / retention）で決める。

### 裁定要求 7 — ペイロードが言及しなかった国に観測行を出すか（§7-2 #34）

**問題**: 現行系は `COUNTRY_COORDS` の全エントリに `"NORMAL"` を書く。v3 のアダプタは
ペイロードに現れた対象にのみ行を出す。結果、v3 では「不在」と「測って何も無かった」が
再び区別できなくなる — §7-2 #7 が `threatfox` について「区別可能にすることは NP1 の要求」と
判断したのと**同じ形**である。ただし #7 は 1 アダプタの話で、これは 22 基に跨る。

**推奨**: **#7 の前例に従い、スコープ内の沈黙国にも `STATUS_OK` / `raw_score=0.0` の行を出す**。
ただし**観測件数が「シナリオ内対象国数 × アダプタ数」まで増える**ため、
WP-2.8 のパリティ突合（観測件数を含む）と L1 の保持容量に効く。
**実装は WP-4.1 で一括**（合成ルートが「このサイクルで問い合わせたスコープ」を知っている唯一の層であり、
アダプタは自分が問い合わせられなかった国を知らない）。本 WP では `ihr_health` のみ先行修正済で、
残り 21 基は現状維持。裁定が (推奨) と異なる場合は `ihr_health` を戻す。

### 裁定要求 8 — `parse_origins` の ISO2 総当たり走査（現行系の欠陥）

**問題**: `radar/scoring.py:661-663` は Cloudflare の `top_0` 行から国を取るのに
`origin1` → `location` → `clientCountryAlpha2` を試し、いずれも無ければ
**「値が 2 文字の大文字英字である最初のフィールド」**を走査する。
`targetCountryAlpha2` が解決できているのはこの総当たりのおかげであり、
**行に ISO2 らしき値が 2 つあると、辞書の反復順で勝者が決まる**。
これは移植の問題ではなく**現行系の誤帰属ハザード**である
（掃引中、テストフィクスチャが実際にこの誤帰属を「期待動作」として固定していたのを発見・修正した）。

**推奨**: v3 側で `targetCountryAlpha2` を走査より**前**に明示的に名指す。
差分は小さく、感度中立、正しさは向上する。ただし現行系との差分なので §7-2 への登録を要する。
**現行系側も直すべき**だが、それは本 WP の範囲外（D2 の欠陥台帳に起票する）。


### 裁定要求 9 — 「別アダプタの出力を入力とする」アダプタをどう表現するか（§3-5 H-3） 〔**裁定済み 2026-08-08 — 推奨 (c) 採択。§3-5 H-3 の裁定ブロックと §9 の裁定 5 が正**〕

**問題**: WP-2.7 の 12 基のうち `hacktivist_intel` / `ground_osint` の 2 基は HTTP を持たず、
入力が**他アダプタの出力**である（前者は telegram の傍受ログ、後者はそれに加えて
`cloudflare_radar` / `check_host` の live cache）。現行の宣言モデルは
`RequestSpec | RequestChain | RequestContinuation` しか取れず、`normalize` は取得済みバイト列 1 件しか見ない
（§2-2 barrier 1）。**表現する語彙が無い**ため、本 WP では 2 基を移植していない。

**なぜ本書で決めないか**: 解は 3 つあり、いずれも L0 の外に波及する。
(a) `NormalizeContext` に「他アダプタの直近観測」を載せる（H-1 で退けた形の再導入。消費者が決まる前の型拡張）。
(b) L1 の観測台帳を入力とする**第 2 種のアダプタ**を宣言型に足す（`requests` の無いアダプタ = 新しい種類）。
(c) 合成ルート（WP-4.1）に「前サイクルの観測 → 次サイクルの入力」の 1 機構を置き、
    §7-2 #11（reduction）・#35（suppression）・本件を**同じ配線で解く**。

**推奨: (c)**。3 件はいずれも「別アダプタの出力を要する」という同一の構造ギャップであり、
別々に解けば 3 通りの機構ができる — A-02（同一計算の複数実装）の再生産そのものである。
(b) はアダプタの種類を 2 つにするため、規律検査（barrier 2/3/4）も 2 通りになる。

**裁定が要る理由**: (c) を採ると **WP-2.7 の母数が 12 から 10 に減り**、残る 2 基の着地が WP-4.1 になる。
これは P3 のバッチ境界（§3-0「バッチ割当は書の境界と完全に一致する」）を動かす判断であり、本書の権限を超える。

**併記すべき事実**: 現行系の `ground_osint` は参照先 cache の**鮮度も健全性も検査していない**
（`ground_osint_sensor.py:67-82`、`ast` で確認。裸の `try/except Exception: pass` で
`cf.get_cache()` / `ch.get_cache()` を読む）。DP2/B-03 そのものであり、
配線を作る側は `Evidence.fresh()` を通す形にしなければ欠陥ごと移植することになる。


### 裁定要求 10 — `IntelProfile` の 4 スロットに応答処分（drop / cap）が収まらない 〔**裁定済み 2026-08-08 — §4-1-1 が正**〕

**問題**: S1-sensors-info-llm §4 表 2 は per-sensor の面を
`prefilter | prompt | score_delta | domain` の **4 スロット**に限る。
しかし `military_exercise` は本番で **LLM 応答後の処分**を 2 つ持つ（`military_exercise.py:343-349`）—
`event_type=="none"` を**自前の drop code** で捨て、`status_report` / `historical_analysis` は
**捨てずに confidence 上限 0.50 で保持**する（S1-SENSI-035、NP1: 自動確認はさせないがレビュー対象には残す）。
4 スロットのどれでもない。3 つの選択肢があった:
(a) 第 5 スロット（callable）を足す — A-02 の 8 複製が戻る入口を開ける。
(b) 処分を捨てる — S1-SENSI-035 の MUST 違反、かつ「どの沈黙だったか」（S1-INGEST-020）が消える。
(c) 処分を**宣言データ**として持ち、評価は共有実装 1 本に置く。

**裁定（オーナー、2026-08-08）: (c)**。**4 スロットの上限は「振る舞い」に対するものであり、
アダプタが宣言する「データ」を禁じてはいない**。`RequestSpec`（取得関数ではなく宣言データ）と
`RequestContinuation`（どのフィールドが取っ手か、であって取り方ではない）と**同一の形**である。
守るべき不変条件は **「抽出の実装が 1 本であること」**。表には分岐を隠す場所が無く、callable にはある。

**実装**: §4-1-1 の表を正とする。`DispositionRule` は callable を `DomainError` で拒否し（`ResponseValue.path` と同形）、
DROP には reason を必須とし（S1-INGEST-020 の沈黙名が保存される）、
**CAP が confidence 床を下回ることを禁じる**（これにより共有実装の単一評価順序が観測可能にならない）。
`signal_field` / `signal_absent_reason` / `response_items_key` も同じ論拠の宣言データである。
スイートは**フィールド数ではなく callable 集合**を pin する。

**残る差分**: 評価順序に起因する drop reason 名の変化のみ — §7-2 #48 に登録済。

---

## 9-0. オーナー承認（2026-08-08）

**オーナーが以下を一括承認**（本セッションの明示指示）。以後これらは実装既定であり、覆す場合は ADR を記録する。

| 対象 | 承認内容 |
|---|---|
| **§7-2 予期差分の登録 53 件** | **全件承認**。P2 §5-C の事前登録要件を満たすものとして cutover 判定に持ち込んでよい。insensitive 方向の登録（#9 family / #38 系 / ct_log score-3 上限 等）も含む |
| **§3-5 構造ギャップ H-1〜H-4** | **承認**。着地先 WP-4.1（合成ルート）で一括解消する |
| **§8 裁定要求 4〜10** | **承認**（各項の推奨どおり）。うち `travel_advisory` A3 廃止（裁定 4）、`ais_maritime` の AISHub `_vessels` 欠陥保存（H-2）、`military_exercise` の physical ドメイン（A6）、`hacktivist_news` の `attack_type` 既定 `"DDoS"`（H-4）は**現行系挙動を保存したまま cutover 後に再評価**する方針を承認 |
| **裁定要求 8（現行系ハザード）** | **承認**。`radar/scoring.py` の ISO2 総当たり走査による国の誤帰属を **D2 に起票**し、v3 側は `targetCountryAlpha2` 明示で回避する |
| **WP-0.4 v2 案** | **承認**（S9 較正ステップの早期実装 + FN draft-confirm + CUT-07 改定検討）。実施時期は Phase 3 以降のオーナー指示による |

**残る唯一の未決事項は cutover 判定そのもの**（P2 §5 の 14 条件）であり、条件付き承認や部分承認は本承認に含まれない。

---

## 9. 裁定（Fable、2026-08-07）

| # | 裁定 | 補足 |
|---|------|------|
| 1 | **WP-2.4 補遺として L2 に実装**（`Observation.observed_at` 追加 + pin 済み減衰項 1 本）。着地は WP-2.7 と同時（インテルアダプタが存在して初めてフィクスチャで検証可能になるため）だが、**L2 変更として独立にラベル**し、採点カーネルと同じ忠実性規律（実効経路の実測トレース・条項対応テスト・レジストリ更新）を課す。ADR-V3-004 が凍結したのは TL 梯子であり減衰ではない — ただし引用行の変異先確認（WP-2.4 の教訓）を必須とする | 裁定要求 1 |
| 2 | **第 1 層で F-09 解消と定義する**。決定論正規化 + スクリプト認識分節で非ラテン見出しが空トークンにならないこと = 欠陥の定義そのものの解消。第 2 層（埋め込み）は enhancement であり既定 OFF — 有効化するなら VERIF-022 記録が前提（決定論を壊してまで欠陥を直さない）。D2 F-09 の閉鎖注記にこの定義を明記する | 裁定要求 2 |
| 3 | **承認 — L1 が 3 表を所有**（A-09 単一管轄）。WP-2.2 完了時に予告した**最小 migration リスト機構をこの拡張で実装**する（schema v2）。稼働中の v3 store は存在しない（パリティ窓未開放・本番 ETL 未実行）ため開発 store の再生成は許容 | 裁定要求 3 |
| 4 | **廃止 + 事前登録で進める。ただし登録エントリは「承認待ち（オーナー）」を明記**。fallback はほぼ全記事に発火する parser-gives-up 判定であり、除去はノイズ除去であって実信号の recall 低下ではない（NP2: 偽の裏付けは収斂を汚染する）。§7-2 の 6 件登録全体の最終承認は cutover 判定前のオーナー事項として申し送る | 裁定要求 4 |

## 10. 裁定（オーナー、2026-08-08）

| # | 裁定 | 補足 |
|---|------|------|
| 5 | **推奨 (c) を採択 — `hacktivist_intel` / `ground_osint` は WP-4.1 へ繰延**。入力が別アダプタの出力であり、宣言モデルに語彙が無い。無理に通せば barrier 1 か barrier 2/4 が壊れ、それは §2-4 の教訓の反復である。§7-2 #11（reduction）・#35（suppression）と同一機構で一括して解く。WP-2.7 の対象は 12 → **10 行**（build されるのは 9 基）。総和は **34 declared / 33 buildable / 2 deferred / 31 built** | 裁定要求 9。詳細と導出は §3-5 H-3 の裁定ブロック。実装は `catalog.DEFERRED_WP41` |
| 6 | **§7-2 #38 は登録で終わらせず、本 WP で v2 ドライバを修正する**。`v3/parity/_v2_subprocess.py` は intel 行に**本番の減衰**を適用する。式の再実装は S5-VERIF-031 が禁じるので、`rationale_to_signal` と同じく**本番の関数 `radar.intel_queue._age_weight` を呼ぶ**。齢を含むパリティフィクスチャで両系一致を証明すること | 裁定要求なし（オーナー発意のエスカレーション）。実施済 — #38 は RETIRED、証跡は `TestIntelRowsAreAgedOnBothSides` / `TestTheDriverUsesProductionsOwnDecay` |
| 7 | **裁定要求 10 — 推奨 (c) を採択**。4 スロットの上限は**振る舞い**に対するもので、宣言データを禁じない。`IntelProfile` に応答処分表（`dispositions`）・signal キー名（`signal_field` / `signal_absent_reason`）・複数答えキー（`response_items_key`）を**データとして**持たせ、評価は `build_item` 1 本のまま。表に callable が入れば `DomainError`。守る不変条件は「抽出実装が 1 本であること」であり、スイートは callable 集合を pin する | 裁定要求 10。実装と不変条件は §4-1-1。残差分は §7-2 #48（drop reason 名のみ） |
