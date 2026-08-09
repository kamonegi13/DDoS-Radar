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
「**まだ差分を生んでいないが、放置すれば必ず生むもの**」を置く。H-1(b)(c) と H-5 は解消済、H-2 はオーナー保留、H-3 は開いたまま、H-4 は登録済。

#### H-5（解消、WP-4.1b、2026-08-08）— L1 に「国でないキー」の置き場が無かった

**事実**: `ct_log` の既知 CA（domain × CA）、`check_host` の URL 別レイテンシ、`ais_maritime` の
MMSI 別スナップショットは **country で keyed されない**。`baseline_stat` の PK は
`(baseline_id, sensor, country, bucket)` なので、これらを収めるには `country` 列にドメインや
MMSI を書くしかなく、**スキーマが保持物と異なることを述べる**状態になる（宣言した窓を実装が守らない
F-06 と同型の欠陥）。

**処置（オーナー裁定 2）**: L1 に実体次元を持つ表を新設した。**2 表**なのは寿命が 2 種類あるためで、
1 つの retention 方針では両方に対して正直になれない:

| 表 | 性質 | retention | 理由 |
|---|---|---|---|
| `entity_observation` | 実体別の**系列**（レイテンシ、船位、頻度） | 30 日（`observed_at`）+ 書き込み側の件数上限 | 30 日は**実在する最長の参照期間**（`NARRATIVE_BASELINE_DAYS`）から採った。件数上限（`deque(maxlen=12)` 等）は本番が書き込み側で掛けている形をそのまま転写 |
| `entity_marker` | 初観測 / 集合membership | **恒久** | `first_seen` は warm-up を終わらせる値であり、失効させると warm-up が再開して**一度卒業した検知が再び沈黙する**（insensitive）。初観測は backfill もできない。本番の 2 表も一度も prune されていない |

追記専用トリガは系列側に付き、marker 側には **`first_seen` を動かす UPDATE を ABORT する**トリガが付く
（保持物の性質に合わせた同等の措置）。スキーマは v3 → v4。

**副次的な解消**: §7-2 #73（`check_host` の URL クールダウン）は、同じ保管形の問題として一括で解くべく
調べた結果、**登録内容自体が誤りだった**ことが判明して retire した（本番も URL を回していない）。

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
> **決着（WP-4.1、2026-08-08）— H-1(b) と H-1(c) は閉じた。**
>
> **(b)**: `v3/runtime/reduce.py::_fold_isr` / `_fold_mil_air` が国のゾーン群を合算してから閾値を当てる。
> 順序が保存されている証拠は算術で述べてある — `tests/test_runtime_reduce.py::TestTheOrderIsSumThenThreshold::
> test_two_zones_of_two_are_a_surge_together`（各ゾーン 2 機 = 単独では非発火、合算 4 機 = 発火）。
> `mil_support_air` も同型（tanker>=2 / transport>=3 / AWACS>=1 を**国合計**に当てる）。
> 逆向きの変異（ゾーン毎に閾値）は変異テストで**殺される**ことを確認済み。
>
> **(c)**: 同 reduction が `flags["hotspots"]` を**連結**し、各ゾーンの `name` / `lat` / `lng` /
> `isr_count` / `tracks` を保存する。`core.py:2929-2931` の `name` 結合と `core.py:1231` の
> ISR_SURGE payload が読む形はそのまま。加えて `zones_folded` / `zones_requested` /
> `zones_unmeasured` を出して**部分カバレッジを開示**する — 読めなかったゾーンは 0 ではなく
> **不在**として扱う（本番も失敗ボックスを `results[theater]` に入れない）。
>
> **供給側**: `v3/runtime/expansion.py` が `ExpansionInput.scopes` に 30 ゾーンを載せる。
> census は `Geography.zone_census()` が `geo_data.json` から**導出**する（初版が JP×2 / IN×2 を
> 落としたのは手書き census だったため。導出なら同じ間違いは起きない）。
> `tests/test_runtime_expansion.py::TestTheCensusIsDerivedNotTranscribed` が
> 30 ゾーン / 21 国 / 7 つの多ゾーン国を pin する。
>
> **`{zone}` の判断**: (c) が「束ねる主体が `hotspots[]` を作る」と定めたとおり、label は既に
> `{zone}` を運ぶ（WP-2.6 の `_zone_request`）。展開器がその値を供給する側を埋めただけで、
> 追加の判断は要らなかった。

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

> **WP-4.1h（#121 の 3 行の実装 と #117 の日次ゲート）の更新（2026-08-09）**:
> 本 WP は **retire 2 件（#117 / #121）**、**新規登録 5 件（#122〜#126）**、**事実訂正 1 件（#118）**。
>
> **#121 の「合計最大 6 点」は誇張だった**。3 行はいずれも本番自身が **countryless Signal** として
> 出しており（`core.py:2039-2041` は `rat.sensor in FOCUSED_ONLY_SENSOR_NAMES` のときだけ国を与え、
> 3 行はシグナル名で登録されているので一致しない）、`GLOBAL_SIGNALS_DECOUPLED` 既定 true の下で
> **どのシナリオのスコアにも入らない**。シナリオスコアへの欠落は 0 点、global envelope への欠落が
> 最大 1.5 点、加えて SYNC_DDOS 系列イベントの門が 1 つ開かない、が実際の規模である。
> **同じ発見が #118 の記述を訂正させた** — `cf_spike_core` も同じ経路で countryless なので、
> 本番のあの行もシナリオスコアに 0 点しか入れていない。#118 の方向（sensitive）は変わらないが、
> 規模は「1 行 vs N 行」ではなく「0 点 vs 参加国ぶん × 結合重み」である。
>
> **#117 は「わずかに insensitive だから受容」をオーナー裁定で却下されて retire した**。
> 修正の途中で**ゲートを無効化する沈黙欠陥が 1 件見つかった**: `record.py` がベースライン
> スナップショットを毎サイクル再押印しており、齢を読むゲートは一度も発火しないまま行は
> `stored` と表示し続ける形になっていた。齢の供給側を直さずにゲートだけ足していれば、
> 「実装したのに効いていない」がテスト緑のまま成立した。
>
> **変異試験が掃引の設計欠陥を 1 件検出した**。`GLOBAL_SHARE_FLOOR` と
> `PER_ORIGIN_L7_PCT_MIN` の変異は初回の掃引（`uniform(0, 45)`）を**生き延びた**。定数が
> 死んでいたのではなく、両方とも**小さい値の隅**でしか効かない（前者は対象国が世界攻撃
> トラフィックの 0.1% 未満のとき、後者は 1.5% 未満の攻撃元が adversary フロア 0.5% に対して
> 跳ねているとき）ため、一様分布の掃引がその領域にほとんど質量を置いていなかった。
> 生成器を**値ではなくスケールを引く**形に変えて 19/19 撃墜。**生き延びた変異は報告対象である**
> という規律が、掃引そのものの不足を暴いた例として記録する。
>
> **WP-4.1d（攻撃元スパイク — `avg_spike` の取得・転写・判定・順位付け）の更新（2026-08-08）**:
> 本 WP は **新規登録 5 件（#117〜#121）**、**範囲縮小 3 件（#9 / #11 / #116）**、**retire 0 件**。
> **retire ゼロは意図した結果ではなく、実測の結果である** — #9 と #116 は「1 つの取得で両方畳める」
> という見立てで着手したが、両方とも**残余が本物**だった。
>
> **#9 の残余**: `cloudflare_radar` の保留は解消した（`VERDICT_WITHHELD` は空、`coverage()` は
> 13/21 → **15/22**）。しかし本行の retire 条件は「7 基**すべて**が本番と同じスコア幅を出す」で、
> `ripe_bgp` は HOD ベースラインが冷えている間（同時刻標本 7 未満）に依然として判定を保留する。
> 本番は同じ `:1148` のスコア幅をメモリベースライン経由の fallback で出し続けるので、これは
> 条件未達である。WP-4.1b の注記が既に名指ししていた 1 件がそのまま残った。
>
> **#116 の残余**: 順位付けの既定量は本番の `avg_spike` になった。残るのは「そのティックで
> どの core も測定を持たない場合」の fallback で、これは**残すことを選んだ** — 本番のその
> 場面での答えは退化しており（全 core が 0.0 → ソート順の先頭）、証跡の多い側を選ぶ方が
> NP1 に整合する。どちらの量を使ったかは `TickReport.chain_ranking` で開示する。
>
> **登録時の記述に事実誤認が 1 件あった**: #116 と `v3/runtime/chain.py` は「90 日の攻撃元
> ベースライン」と書いていたが、実体は `BASELINE_DATE_RANGE`（`radar/config.py:148` の既定
> **28d**）という**問い合わせ窓**である。本番は同じエンドポイントを長い窓で叩き直しているだけで、
> 系列を蓄積していない。したがって台帳が持つのは 1 対象 1 スナップショットであり、
> **保持方針の変更は不要だった**（`entity_observation` の 30 日は、日次で置き換わる 1 行に対して
> 一桁長い）。「90 日が既存方針を超えるなら保持の裁定事項」という当初の見立ては、
> 前提そのものが成り立たなかった。
>
> **#121 は本 WP のスコープ外の発見**である。同じ攻撃元分布から本番が出す 3 行
> （`cf_vector_shift` / `cf_adversary_strike` / `cf_coordinated`、合計最大 6 点）を v3 は出さない。
> 本 WP まではそもそも入力が無く到達不能だったが、いまは**実装されていないだけ**になった。
> insensitive 方向なので #9 の規律どおり発見時点で登録した。追加の取得は要らない。

> **WP-4.1b（ベースライン供給）の更新（2026-08-08）**: 本 WP は **#8 / #73 の 2 件を retire**、
> **#9 / #40 を範囲縮小**、**#74 / #75 を新規登録**した。オーナー裁定 1（HOD/DOW は再バケットせず
> L1 に剰余読みを足す）と裁定 2（実体別キーの表を L1 に新設し `baseline_stat` に相乗りさせない）の実装。
> 供給済ベースラインは **6/21 → 13/21**（`v3/runtime/baselines.py::coverage()` 実測）。
> **#9 が retire できない残り 1 件は `cloudflare_radar`** で、阻害は台帳ではなく入力側
> （本番の `avg_spike` は L2 から除外された派生観測で、v3 はどこでも計算しない）。
> L1 スキーマは **v3 → v4**（`entity_observation` / `entity_marker` の 2 表 + 追記専用トリガ +
> `first_seen` 不変トリガ）。#73 は「本番は URL を回している」という**登録内容自体が事実誤認**
> であったことを AST で実測して畳んだ。

> **WP-4.2（L7 フロントエンド）の更新（2026-08-08）**: 本 WP は **#94〜#99 を新規登録**した。
> retire は **1 件（#93 の解消条件の半分）**— v3 は通知系を持たないままなので `notification_result`
> の不発行は解消していないが、#93 の解消条件に書かれた「WP-4.2 で着地」は**成立しなかった**ことを
> ここで明示する（P8 §2 の画面インベントリに通知面が無く、P7 §1 にも通知 endpoint が無い。
> 解消条件を「通知スライスが設計されたとき」へ読み替える）。範囲縮小は 0 件。
> 本 WP は L0 アダプタにも L1 台帳にも触れていない — **読み取りは L6 の射影のみ**を消費する。
> **#52（`NARRATIVE_ZSCORE_FIRST_SIGNAL` の pin）は retire できない**: R14 は着地したが
> 当該キーは可変キー登録の対象になっておらず、L7 からは触れない。

> **WP-4.1（L6 公開 API 面）の更新（2026-08-08）**: 本 WP（合成ルート／ベースライン供給とは別スライス、
> P7 §1 の面の実装）は **#76 を新規登録**した。retire・範囲縮小は **0 件** — 本 WP は L0 アダプタの
> 転写に一切触れず、L1 の**読み取り 1 本**（`LedgerStore.conclusion_by_id`、P7 R4 の主キー引き）
> のみを追加したため、既存エントリの解消条件に触れない。
> **#52（`NARRATIVE_ZSCORE_FIRST_SIGNAL` の pin）と #56（`rationale_matrix` 3 列）は retire できない**:
> #52 の retire 条件は「運用可変キーのレジストリが v3 に着地した時点」で、それは P7 R14 / C7 であり
> 本 WP では**繰延（`v3/api/registry.py` の DEFERRED に owner 付きで登録済）**。#56 は L2 `Contribution`
> か合成ルートの供給側の問題で API 面の射影では埋まらない。

> **WP-4.1c（L6 指令面・書込シーム）の更新（2026-08-08）**: 本 WP は **#77 / #78 / #79 を新規登録**、
> **retire 0 件・範囲縮小 0 件**（L0 アダプタの転写に触れないため既存エントリの解消条件に触れない）。
> 着地は指令 3 族（P7 C1 focus / C2 結論フィードバック / C9 人手 ground truth）と、その土台となる
> **指令台帳**（L1 schema v5 `command_record`、追記専用・保持恒久）。
> **#52 の retire 条件について、本 WP は「まだ着地していない」ではなく「今着地させてはならない」を実測で確定した**:
> v3 の 3 層解決は `v3/kernel/threshold.py::Threshold.registry_backed` が legacy `radar.config_layered` に
> 委譲して終端する。v3 側に override 行を書いても解決経路がそれを読まないため、
> 本 WP が導入した**効果検証**（commit が射影経路で読み戻し、一致しなければ拒否）が必ず失敗する。
> つまり現状で C7 を出すことは **G-15 の再生産そのもの**であり、
> 先に必要なのは「解決経路を v3 に移すか、L1 override 層を `Threshold` に接続するか」の設計判断である。
> #52 / #56 は引き続き retire 不能（#56 は WP-4.1 の記述のとおり）。

> **WP-4.1g（L6 の残り: C13 auth / R11+C3 intel / R7 ops_health）の更新（2026-08-08）**: 本 WP は
> **#100〜#108 を新規登録**、**retire 1 件（#94）**、**範囲縮小 1 件（#99）**。
> L0 アダプタの転写には触れないため既存エントリの解消条件に触れない（#94/#99 は L6/L7 側）。
> P7 §1 の被覆は **21/28 → 24/28**（`v3/api/registry.py::coverage()` 実測）。
> 残る 4 件はいずれも**読み手が存在しない**という同一理由での繰延で、
> 各エントリに阻害を実測で書き直した: 抑制規則 C8（fold を読む辺が無い）、
> 人間アンカー C10（出題器も取り込み口も無い）、シナリオ CRUD C11（**裁定**: 第 2 の供給源は
> 作らない。正しい形は C7 と同じ 3 層解決で、それは採点入力のスライス）、
> LLM 運用 C12（**実測**: `v3/fetch/llm.py::submit` を呼ぶ本番経路が v3 に 1 つも無い）。
> **#103 は cutover 阻害**として登録した唯一の項目である（refresh token の輸送）。
> 利用者ストアは表を作らず `command_record` の fold にした — 繰延理由に書かれていた
> 「キューの裁定状態を持つ表」も同様に不要で、**表が要ると読んだこと自体が誤り**だった。

> **WP-4.4（L8 合成の配線 — entrypoint / 影配備）の更新（2026-08-08）**: 本 WP は
> **新規登録 4 件（#112〜#115）**、**retire 0 件・範囲縮小 0 件**（L0 アダプタの転写にも
> L1 台帳にも触れず、既存の全部品を**接続しただけ**であるため既存エントリの解消条件に触れない）。
> 着地は `v3/server/`（`isolation` / `settings` / `ui` / `composition` / `app` / `main`）、
> `Dockerfile.v3` + `requirements-v3.txt` + compose の `v3_shadow` サービス（profile 後置）、
> 運用手順書 `docs/design/v3/OPS-shadow-runbook.md`。
> **本 WP の登録 4 件のうち #113 / #115 は insensitive 方向であり、Phase 5 で実測すべき対象である。**
>
> 配線して初めて分かった事実を 2 件記録する。
> **(1) 唯一生きていた「v1 を起動する経路」は転写漏れではなく解決経路だった。**
> `v3/kernel/threshold.py::_default_resolver` は registry-backed な `Threshold` が
> resolver 無しで解決されたときに `from radar import config_layered` を実行する。
> 規律ゲートは「モジュール毎の import」を禁じているだけなので、この**関数内 import は
> 合法**であり、静的検査では影のプロセスが v1 を起動しうることを排除できない。
> 対策は文書ではなく構造にした: 合成ルートが `sys.meta_path` に
> `LegacyImportBarrier` を立て、`radar.*` の import を**例外にする**。
> 地雷は「静かに v1 が起動する」から「スタックトレース」に変わった。
> **(2) focus を設定すると採点が静かに止まる状態が存在した。**
> `ScoringInputs.chain_country_for` は「dual-core の所有国は導出しない」という裁定どおり
> **例外を投げる**が、`v3/runtime/scoring.py::scenarios_for` は `core_country` をどのシナリオにも
> 設定しない。起動直後は focus が無いので露見せず、最初の C1 で以後のティックが毎回失敗し、
> NP3 がループを生かすため症状は「落ちる」ではなく「結論行が静かに増えなくなる」になる。
> 導出で埋めることは裁定違反なので、合成ルートは**起動時に所有国未供給のシナリオを名指しで
> 告知する**（`Deployment.scenarios_without_chain_owner` / `absent.sequence_chain_owner`）。
> これが #115 の登録内容である。

> **#115 追補 — オーナー裁定による是正（2026-08-08）**: 上記 2 件の「対策」は
> **どちらも不十分だった**と裁定され、両方が構造で解かれた。**retire 1 件（#115）・
> 新規登録 1 件（#116）**。
>
> **(1') 障壁は正しいが、地雷は除去できた。** `_default_resolver` は
> **削除した**。障壁（`LegacyImportBarrier`）が変えたのは「静かに v1 が起動する」→
> 「スタックトレース」までであって、v3 はそもそもこの fallback を望んでいない —
> 合成ルートは常に自前の解決チェーンを注入する（`v3/config/resolution.py`、
> `resolver=` の唯一の許諾先）。使えない fallback が残っている状態の到達可能な結果は
> 「障壁の外では v1 起動」「障壁の内では不可解な ImportError」の 2 つだけで、
> どちらも解決ではない。不在にすれば失敗は**求めていたシームを名指す**。
> registry-backed な `Threshold` を resolver 無しで解決すると
> `ThresholdResolutionError` になり、`resolve_settings()` も注入無しでは同様に失敗する。
> pinned は resolver を参照しないので無影響。`v3/__init__.py` の「唯一許された legacy
> 依存」の記述も撤回した — **v3 から `radar.*` への依存は 0 件**になり、それを
> AST で強制する（`tests/test_kernel_threshold.py::TestTheLegacyFallbackIsGone`、
> `_v2_subprocess.py` のみ許諾）。障壁は残す: 守る対象が「転写漏れ」から
> 「将来の編集・依存」に変わっただけで、必要性は変わらない。
>
> **(2') 「運用者が供給する」は同じ欠陥に人の名前を付けただけだった。**
> 環境変数 `NOROSHI_V3_CHAIN_COUNTRIES` は**廃止**。定数はどの由来であれ
> 「middle_east の IL/IR が同重みで、静的な答えはエスカレートしている側を永久に
> 選ばない」という当初裁定の失敗そのものになる。正しい解は、**合成ルートがその
> ティックの観測を持っている**という事実を使うこと — 本番の選択規則を転写し
> （`v3/runtime/chain.py`、AST で照合）、毎ティック計算して
> `ScoringInputs.chain_countries` に渡す。カーネルは純粋なまま、
> 裁定（「選択はオーケストレータの仕事」）も維持され、**今度はオーケストレータが
> 実際に選択を行う**。順位付けに使う量だけが差分として残り、#116 に登録した
> （`avg_spike` は v3 が計算していないだけでなく**入力を取得していない**ため、
> L1 配線では解けない）。
>
> 同時に、`assemble` / `score_cycle` / `run_tick` / `parity.driver_v3.replay` から
> `chain_countries` 引数を**削除**した。供給シームを残せば定数は別の扉から戻る。
> whatif（C6）も供給をやめ、`assemble` が測る — 反実仮想と実ティックが
> 同じ belligerent の連鎖を読むようになった。

> **WP-4.3（cutover 阻害の解消・L7 ログインゲート・裁定要求 13 の実装）の更新（2026-08-08）**:
> 本 WP は **retire 2 件（#103 / #99）**、**範囲縮小 1 件（#105）**、**新規登録 3 件（#109〜#111）**。
> **#103 は本プログラム唯一の cutover 阻害項目であり、これで阻害はゼロになった**。
> 解消手段は登録時の解消条件どおり: `v3/api/cookies.py` に cookie 面（`CookieSpec` / `SetCookie` /
> `ClearCookie` / `CookiePolicy` / `PresentedCookies`）が着地し、`ApiRequest` が cookie と
> `X-CSRF-TOKEN` を型付き入力として受け、`ApiResponse` が set/clear 指令を型付き出力として運び、
> Flask 束縛だけがそれを `Set-Cookie` に翻訳する。**CSRF の対は宣言そのもので強制される** —
> `CookiePolicy` は `presents` を持ちながら `csrf=False` である状態を構築時に拒否するため、
> 「ハンドラが検査を忘れる」という綴りが存在しない（G-01 の恒久化をルート表側で反復）。
> 姿勢（httpOnly / SameSite=Strict / Secure 既定 on / パス限定 / session cookie）は
> `radar/auth.py` と導入済 `flask_jwt_extended` の**両方を AST で実測**して一致を証明した
> （本番が「既定を上書きしていない」ことに由来する 2 値 — CSRF cookie の `/` パスと
> `JWT_SESSION_COOKIE=True` による `Max-Age` 不在 — を含む）。
> **#105 は裁定要求 13 のオーナー裁定により反転**した: 未裁定インテルは採点されない。
> 述語は `v3/intel/adjudication.py::scoreable_rows` 1 本で、live ティック
> （`v3/runtime/scoring.py::observations_at`）と parity 両ドライバが同じものを呼ぶ。
> **#99 は L7 実装で解消**（`v3/ui/auth.js` + ゲート DOM + 401 の 1 回再試行 + refresh 直列化）。

> **WP-4.1f（S8 注目台帳と、それが解いた L6 の残り）の更新（2026-08-08）**: 本 WP は **#86〜#93 を新規登録**、
> **retire 1 件（#87 が置換した本番挙動ではなく、下記の DEFERRED 側）・範囲縮小 0 件**。
> L0 アダプタの転写には触れないため既存エントリの解消条件に触れない。
> **#82（Defer の構造的欠陥）は保存のまま**で、オーナー裁定（§8 裁定要求 11）により
> **稼働系の修正は cutover 後**へ回し、D2 に 1 件を owe している。
> P7 §1 の被覆は **13/28 → 21/28**（`v3/api/registry.py::coverage()` 実測）。
> 残る 7 件の内訳は intel 2（R11/C3）、抑制規則 1（C8）、人間アンカー 1（C10）、
> シナリオ CRUD 1（C11）、LLM 運用 1（C12）、auth 1（C13）。


> **WP-4.1d（v3 自身の 3 層解決 / R14 / C7）の更新（2026-08-08）**: 本 WP は **retire 0 件・範囲縮小 1 件（#52）・新規登録 0 件**。
> WP-4.1c が要求した設計判断は **「カーネルは純粋のまま、合成ルートが連鎖を供給する」** で裁定した。
> `Threshold.registry_backed` が既に受け取る `resolver` シームがその答えであり、終端を legacy から v3 に差し替えるだけでよい:
> `v3/config/registry.py`（O-18 (a) 群 = どの鍵が可変か + **誰が読むか**）、`v3/config/resolution.py`（override → env → default、**どの層が答えたかを値と一緒に運ぶ**）、
> `v3/runtime/config.py`（合成ルートが env スナップショットを `v3/runtime/secrets.py` 経由で取り、連鎖を組んで注入する）。
> **override 層に新しい表は作らなかった** — override は「監査行と理由を伴う指令」そのものであり、`command_record` の fold（`v3/commands/state.py`）で表現できる。
> 第 2 の書込経路を作ることは、G-15 が実際に起きた形（override 行 + 監査行 + 読み手ゼロ）の再生産である。
> その結果 **C7 の効果検証は「解決経路が override を読むことの証明」になった**: `commit` は追記後に 3 層連鎖で読み戻し、
> 一致しなければ拒否する（`tests/test_api_config_surface.py::TestTheEffectVerificationIsTheWholePoint` が連鎖を盲目にして再現する）。
> `resolver=` の licence は **1 ファイル（`v3/config/resolution.py`）に限定**し、規律ゲート `_RESOLVER_OWNER` と AST 掃引テストで固定した（env licence と同形）。
> **#52 の扱いは上表のとおり範囲縮小**（レジストリは着地したが、v3 に読み手が無いため登録しない）。

> **WP-4.1（合成ルート）の更新（2026-08-08）**: 本 WP は **#12 / #13 / #28 / #29 / #31 / #35 / #41 / #42 /
> #45 / #50 / #51 の 11 件を retire**（行番号を `~~n~~` で打ち消し、旧記述と証跡テストは残す）、
> **#9 / #11 / #16 / #23 / #40 の 5 件を範囲縮小**（retire ではない — #9 の規律に従い、
> 1 件でも保留が残る family は畳まない）、**#71〜#73 を新規登録**した。
> §3-5 の構造ギャップ **H-1(b) / H-1(c) は閉じた**。**H-3 は開いたまま** —
> 本 WP が実装したのは同一サイクル内の join（reduction / suppression）であり、
> サイクル跨ぎの供給は形（`v3/runtime/baselines.py::carried_values`）が定まっただけで、
> `hacktivist_intel` / `ground_osint` の 2 基は未着地。

> **承認状態（2026-08-08 追記、WP-4.1c で範囲更新）**: §9 のオーナー包括承認は **#1〜#53** を対象とする。
> **#54〜#79 は WP-3.1（L3 結論層）/ WP-3.2（L4 較正層）/ WP-4.1（合成ルート）/ WP-4.1b（ベースライン供給）/
> WP-4.1（L6 読み取り面）/ WP-4.1c（L6 指令面）で新規に登録したもので、同種の包括承認を待つ**
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
| ~~8~~ | `ct_log` | **untrusted-CA 判定が L1 待ちの間、score 3 が出ない**。現行系は「未知 CA × warmup 明け」で score 3 を出す（`radar/routes/core.py:1843-1848`）が、v3 の L0 は判定に要る 2 表（`ct_log_known_ca_per_domain` / `ct_log_domain_first_observed`）を持たないため `STATUS_OBSERVED` / 0.0 に留まる。結果、**現行系が 3 を出すペイロードで v3 は最大 2（wildcard）または 0** | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃の blocking 級**） | **登録**（WP-2.6 実装レビューで発見、2026-08-07）。**解消条件**: L1 の既知 CA 台帳 + warmup マーカーをアダプタへ供給する配線 — 実装先は **WP-4.1（合成ルート `v3/runtime/`）**。`normalize` は純関数で `NormalizeContext` しか受け取らないため、ベースライン値の供給は §3-5 H-1 と**同型の構造的ギャップ**（合成ルートが `NormalizeContext` に載せる形を決める）。**配線完了時点で本エントリは retire する**。それまでは `untrusted_ca_verdict: pending_l1_known_ca_ledger` と `untrusted_ca_candidate_count` が観測面に露出し、**取りこぼしは OBSERVED として可視**（OK として沈黙しない — §7-2 #6 と併せて `ct_log` の 2 件目の登録） | **retire（WP-4.1b、2026-08-08）**: 裁定 2 の実体別テーブル（`entity_marker`）が既知 CA 台帳と初観測マーカーを保持し、`_fold_ct_log` が本番のラダー（untrusted>0 → 3 / wildcard → 2 / else 0、warmup 中は無発火）を再現する。証跡: `tests/test_runtime_baseline_supply.py::TestCtLogNowReachesScoreThree`（6 件、うち `test_an_unknown_ca_out_of_warmup_scores_three` が score 3 を実測）。**残る差分は #74 に登録**（既知 CA 集合の内容が本番より小さい。判定は同値）
| 9 | `ripe_bgp` / `cloudflare_radar` / `ooni_censorship` / `ripe_atlas` / `check_host` / `gps_jamming` / `ct_log`（**family、#8 を吸収**） | **L1 のベースライン／既知 CA 台帳／warmup マーカーが未配線の間、判定を保留してスコアを出さない**。該当アダプタは `STATUS_OBSERVED` / `raw_score=0.0` を出し、`flags` に `pending_l1_*` マーカーを置く。保留しているスコア幅と、本番でそれを出す条件（すべて `radar/routes/core.py` で実測）: `ripe_bgp` 0-1（`:1148` hour-of-day Z-score による BGP anomaly）／`cloudflare_radar` 0-3（`:1008-1025` HOD Z-score 1.5σ/2.5σ/3.5σ の段階、warmup 時は 2x/4x/6x）／`ooni_censorship` 0-2（`:1700` heavy=2 / censoring=1、前サイクル anomaly 数との比較）／`ripe_atlas` 0-2（`:1536` PROBE_BLACKOUT=2 / PROBE_DROP=1、前サイクル probe 数との比較）／`check_host` 0-3（`:1373` BLACKOUT=3 / PARTIAL=1、`checkhost_hod` による HOD 正規化）／`gps_jamming` 0-2（`:1810` critical=2 / jammed=1、前サイクル比）／`ct_log` 0-3（`:1843-1848` 未知 CA × warmup 明け） | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃の blocking 級**） | **登録**（R2 裁定、2026-08-08）。**#8 は本行に吸収する**（1 つの原因に 2 つの形を残さない。#8 の記述は `ct_log` 固有の詳細として参照可能なまま残す）。**解消条件**: L1 のベースライン供給配線 — 実装先は **WP-4.1（合成ルート `v3/runtime/`）**。`normalize` は純関数で `NormalizeContext` しか受け取らないため、ベースライン値の供給は §3-5 H-1 と**同型の構造的ギャップ**である。**retire 条件**: WP-4.1 が `NormalizeContext` にベースラインを載せ、上記 7 基すべてが本番と同じスコア幅を出すようになった時点で本行を削除する。**部分的に配線された段階で本行を残したまま cutover してはならない** — 残り 1 基でも保留していれば insensitive 差分は残る。**規律**: `pending_l1_*` マーカーは、**消費者が型を当てにしているキーを占有してはならない**。マーカーは非空文字列であり、bool として読まれるキーに置けば「永久に発火中」になり、同じキーを見る沈黙検出器を無効化する（`gps_jamming` の `surge`、`check_host` の `asphyxiation` が実例）。`ct_log` の `untrusted_ca_verdict` が定めた形に倣い、**到達できない判定は判定を運ぶフィールドから不在にし、兄弟キーで名指す**。不在は「述べていない」であり、`False` / `0.0` は偽陰性である **進捗（WP-4.1、2026-08-08）— retire しない（本行の規律どおり）。** `v3/runtime/baselines.py` が**前サイクルスカラー系 6 件**（`atlas_prev_probe_count` / `tor_prev_relay_count` / `tor_prev_user_count` / `ooni_prev_anomaly_count` / `gps_prev_ratio` / `travel_advisory_previous_level`）を `latest_signal_at` から供給し、reduction がそれを使って `ripe_atlas` / `tor_metrics` の本番ラダーを再現するところまで配線した。**残り 15 件は供給できない。実測した阻害要因**: (a) HOD/DOW 系（`bgp_hod` / `checkhost_hod` / `airspace_hod` / `gdelt_dow_tone` / `cf_attack_share_baseline`）は `baseline_stat` に**移行済だが `bucket` が v1 の生 epoch 時刻**で入っており、本番の照会は `(hour_bucket/3600) % 24` の剰余レンジである。L1 は完全一致読み（`read_baseline`）しか持たないため**問い合わせ自体が書けない**。解は 2 つ — (A) 今後は `bucket=hour-of-day` で Welford 再構築（移行済 28 日を捨て、かつ無窓累積になり本番の rolling と乖離）、(B) `baseline_stat` に剰余レンジ読みを足す（移行済履歴を保全）。**台帳側の裁定であり本 WP では採らない（裁定要求）**。(b) 集合／実体別状態（`ct_log_known_ca_per_domain` / `ct_log_domain_first_observed` / `checkhost_latency_history` / `ais_vessel_history`）は **domain / URL / MMSI で keyed** であり、`baseline_stat` の PK `(baseline_id, sensor, country, bucket)` に country 次元が無い形では収まらない。(c) 30 日ローリング頻度（`narrative_keyword_frequency` / `telegram_keyword_frequency`）は窓付き fold ジョブが要る（`fold_observations` は無窓累積）。**この一覧はコードから導出される**（`v3/runtime/baselines.py::coverage()`）ので、1 件でも供給されないうちは `tests/test_runtime_expansion.py::TestTheBaselineAccountIsHonest::test_the_register_entry_cannot_be_retired_yet` が本行の存続を要求する。なお `baseline_refs` の名（`hod` / `gdelt_dow` 等）と移行済 `baseline_id` の綴りが一致しない箇所があり、名寄せも (A)/(B) 裁定と同時に決める必要がある | **進捗（WP-4.1b、2026-08-08）— 範囲縮小、retire しない（本行の規律どおり）。** 裁定 1（剰余読みを L1 へ）と裁定 2（実体別テーブル）により、**供給済ベースラインは 6 → 13 / 21**（`coverage()` 実測）。本 family のうち **`ripe_bgp` / `check_host` / `ct_log` は判定が発火するようになった**（`ooni_censorship` / `ripe_atlas` / `gps_jamming` は WP-4.1a で着地済）。**残るのは `cloudflare_radar` 1 基のみ** — 阻害要因は台帳ではなく**入力**である: 本番の HOD Z は `avg_spike`（`core.py:817`、攻撃元分布から導出される観測）と比較するが、S1-SCORE-025/029/030 は派生観測生成器として L2 から除外されており、v3 はこの量をどこでも計算しない。読み出しは配線済（`baseline_id=hod` / `sensor=hod_baseline`、名寄せ完了）だが、**測っていない量にベースラインは判定を与えられない**。この状態は `coverage()` の `withheld` に理由付きで載り、`answered` には**入らない**（storage が揃っただけで retire する経路を塞ぐため）。`ripe_bgp` の warm-up 分岐（同時刻標本 7 未満）は**依然として保留**する — 本番の fallback はプロセス内で毎時リセットされる `self._baseline[code]`（A-03 のメモリベースライン、`baseline_refs` にも無い）に依存するため、代替を発明すれば未登録差分になる。証跡: `tests/test_runtime_baseline_supply.py`（56 件）、`tests/test_ledger_phase_baselines.py`（102 件）、`tests/test_ledger_entity_state.py`（20 件）。ミューテーション試験 22/22 検出 | **進捗（WP-4.1d、2026-08-08）— 範囲縮小、retire しない。** `cloudflare_radar` の保留は**解消した**。阻害要因は入力であり（本行の WP-4.1b 注記のとおり）、それは**取得の欠落**だった: `CLOUDFLARE_RADAR_ADAPTER` に `attacks/layer{3,7}/top/locations/origin` の 4 リクエスト（現行窓 × 2 層 + ベースライン窓 × 2 層、`{country}` で参加国ごとに展開）を宣言し、`v3/runtime/spike.py::origin_spike` が `core.py:762-817` を転写、`reduce_cyber._fold_cf_spike` が本番の HOD Z ラダー（`core.py:1006-1018`、warm-up 分岐込み）まで到達して `cf_spike_core` を 0-3 で発火させる。`VERDICT_WITHHELD` は**空になった**（`coverage()` 実測: 供給済 13/21 → **15/22**、withheld 1 → 0、未供給 8 → 7）。**なお登録時の「90 日ベースライン」は事実誤認**で、実体は `BASELINE_DATE_RANGE`（`radar/config.py:148` の既定 **28d**）という**問い合わせ窓**であり、台帳に蓄積する系列ではない（AST 実測: `tests/test_runtime_cf_spike.py::TestTheOriginRequestIsDeclared::test_the_baseline_window_is_28_days_not_90`）。**本行が retire できない残り 1 件は `ripe_bgp` の warm-up 分岐**（同時刻標本 7 未満、WP-4.1b 注記が既に名指ししたもの）— 本番は `:1148` の同じスコア幅をメモリベースライン経由の fallback で出し続けるが v3 は保留するため、「7 基すべてが本番と同じスコア幅を出す」という retire 条件を満たさない。**残余の原因は cf のもの（入力）と異なる**（A-03 のメモリベースラインが `baseline_refs` に無い）ので、本行を「ripe_bgp warm-up 専用行」へ分割して本行を retire する整理は**裁定事項**として残す。証跡: `tests/test_runtime_cf_spike.py`（94 件、うち差分スイープ 3×4,000 入力・ミューテーション 14/14 検出・end-to-end ティック 8 件） **訂正（G-15、2026-08-09）— 「前サイクルスカラー系 6 件」は事実誤認だった。実質 5 件。** `gps_prev_ratio`（`("gps_jamming", "ratio")`）は `coverage()` に ANSWERED と数えられていたが、`gps_jamming._flags()`（`v3/adapters/physical/gps_jamming.py`）は `max_level` / `avg_level` を書くだけで `"ratio"` キーを一度も書かない。加えて `surge_verdict: "pending_l1_prev_ratio"` の解決値も、その withheld マーカーも、v3 のどの fold からも読まれていない（`gps_jamming` の score は `is_critical` / `is_jammed` という絶対閾値だけで決まり、本番 `core.py:1810` も同じ — `radar/sensors/gps_jamming.py` が計算する `surge` / `prev_avg` は本番側でも `core.py` のどこからも読まれない、production 自身の dead value）。つまり `gps_prev_ratio` は読めば必ず空を返す**登録だけの baseline**であり、G-15（読まれない登録値）の同型。**是正**: `gps_prev_ratio` を `PREVIOUS_CYCLE_SCALARS`（false ANSWERED の側）から `UNANSWERABLE`（測定済の理由付き）へ移した。`GPS_JAMMING_ADAPTER.baseline_refs` は**削除しなかった** — `tests/test_adapters_catalog.py::TestTheDeclarationsAreWellFormed::test_baseline_dependencies_are_declared_where_they_exist` が DP3（本番は `self._prev_levels` という再起動で消えるインスタンス辞書に前サイクル比を保持しており、その依存は台帳から見える宣言であるべきで、個々のインスタンス変数であってはならない）を根拠に `gps_jamming` を宣言ありの集合に pin しているため、`baseline_refs` を空にする第一稿の是正はこのテストを red にした。**是正の最終形は「宣言は残す・ANSWERED の主張だけ剥がす」**: `declared_names()`（`baseline_refs` 由来）は変わらず `gps_prev_ratio` を含み、`coverage()` の `unanswered` に測定済の理由（本パラグラフの内容）付きで移る。`surge_verdict` マーカー自体は別の目的（bool 型 flag catalog への型混入防止、`tests/test_adapters_physical_geo.py::TestGpsJammingSurgeIsWithheldNotAsserted` が pin）のため変更していない。**再発防止**: `tests/test_runtime_baseline_supply.py::TestNoDeclaredScalarIsDecorative` が `PREVIOUS_CYCLE_SCALARS` の全エントリについて、宣言された flag key を対象アダプタが実際に書けることを AST で検査する（`UNANSWERABLE` 側は対象外 — そちらは「まだ答えられない」の申告であり、キーが存在しないことを理由に含めて既に明示している） **裁定（Fable、2026-08-09）— #9 は分割して RETIRE、残余は #134 へ。これは完了による retire ではない。** 本行の規律は「残り 1 基でも保留していれば cutover してはならない」と自らに課しており、分割はその規律を迂回する手口になりうる。それでも分割を採るのは、**残余の原因が本行の主題と違う**からである。本行の主題は「L1 のベースライン供給が未配線」であり、7 基中 6 基はその意味で解決した。`ripe_bgp` の warm-up 分岐に残っているのは配線の欠落ではない — **ベースラインは配線済**で、本番がその局面だけ**別の、揮発性のベースライン**（`self._baseline[code]`、プロセス内・毎時リセット・`baseline_refs` に無い = A-03 そのもの）を使っており、v3 がそれを再現すべきかどうかが未決なのである。配線の話として扱い続けると、**実装で解けない問題が実装待ちに見える**。**したがって: 本行は「分割による retire」と明記して閉じ、残余は #134 として立てる。#134 は本行の阻害クラス（insensitive、cutover 阻害）をそのまま継承し、解消には実装ではなく**オーナー裁定**（A-03 の揮発ベースラインを v3 が再現するか、差分として受容するか）を要する。台帳が空に見えることを retire の目的にしてはならない — #9 の retire は「6/7 が解決した」という事実の記録であり、「family が完了した」という主張ではない |
| 10 | `threatfox` | **鍵が無いとき AUTH_MISSING を記録する**（現行系は「呼ばずに成功 0 件」）。現行系は `radar/sensors/threatfox.py:35-38` で `if not tf_api_key:` → `log_fetch(True, 0, 0, 0, "")` → `set_cache({"hits": {}})` → return。すなわち **(a) 訊いていないのに「訊いた、何も無かった」と記録し、(b) それまでの hits をキャッシュごと空で上書きする**。v3 は `client.py` の AUTH_MISSING（「訊けなかった」）を `fetch_log` に残す | **観測面 sensitive / 採点面 neutral**（v3 は空観測を作らない = 誤った平穏を作らない。採点は両系とも 0） | **登録**（R4-R3 裁定、2026-08-08）。optional にはしない — optional の基準は「本番が匿名で取得しているか」であり ThreatFox はそうではない（§2-4）。**方向は正直に言えば「v3 が『訊けなかった』と言う場所で現行系は『訊いたが何も無かった』と言う」であり、null-zone / 観測軸では sensitive、スコア軸では中立**。パリティ窓では threatfox の観測件数が両系で一致しないことが期待される。**解消条件**: 現行系側の同修正（NP1 由来なので現行系を直すのが筋）、または cutover |
| 11 | `cloudflare_radar` / `ripe_atlas` / `check_host` / `isr_hotspot` / `mil_support_air` / `space_weather` / `ais_maritime`（family） | **L0 は取得ペイロード 1 件につき観測 1 件を出すが、現行系は N 件のペイロードを 1 サイクル 1 国あたり **1 個の rationale エントリ**に畳んでいる**。`cf_spike_core`（core.py:1025）は L3 と L7 の合成、`cf_bgp_hijack`（core.py:1165）は hijacks と leaks の論理和、`ripe_atlas`（core.py:1547）は probes と 3 本の measurement RTT の合成（RTT は `ripe_atlas.py:133,137-147` で**国単位に pool してから** p95）、`check_host`（core.py:1376）は最大 3 URL の合成（`checkhost.py:197,239`）、`isr_hotspot` / `mil_support_air` は 1 国 N ゾーンの合算（§3-5 H-1）、`space_weather` は Kp と X 線の 2 endpoint、`ais_maritime` は 1 国 N チョークポイント。**このうち `space_weather` と `ais_maritime` は現時点で実際に衝突する** — 前者は country="" の 2 draft、後者は TW に 3 つのチョークポイントが紐づく（`geo_data.json` `CHOKEPOINTS`）。`normalize` は構造上 1 ペイロードしか見ないため（§2-2）、この畳み込みは L0 では実行できない | **観測面 sensitive**（行数が現行系より多い）／**採点面は畳み込み後に判定**（MAX・比率演算は WP-4.1 が行う） | **登録**（WP-2.6 remediation で発見、2026-08-08）。§3-5 H-1(b) と**同型**の構造ギャップであり、着地先も同じ **WP-4.1 の reduction ステップ**（ゾーン群／ペイロード群 → 国単位 1 draft → 閾値）。**畳み込みまでは各行が異なる `signal_source` を持たなければならない** — L1 は `UNIQUE (tick_id, sensor, signal_source, country)`（`schema.py:157`）で、同キー・**異内容**は `DomainError`、同キー・**同 `raw_score`/`status`/`observed_at`** は**黙って捨てられる**（`store.py:282-295`）。OBSERVED/0.0 の行同士は後者に当たるため、「本番の名前に揃える」ことが**静かなデータ喪失**になる。よって R1（signal_source を本番値に戻す）は本 family に対しては**採点を担う行にのみ適用**する（`ripe_atlas` の probes 行 = `ripe_atlas`）。**retire 条件**: WP-4.1 の reduction が入り、畳み込み後の行が本番の `signal_source` を持った時点 **範囲縮小（WP-4.1、2026-08-08）— retire ではない。** `v3/runtime/reduce.py` の reduction が `isr_hotspot` / `mil_support_air` / `cloudflare_radar`（BGP）/ `space_weather` / `ripe_atlas` / `check_host` / `ais_maritime` を country 単位 1 行へ畳み、畳み込み後の行は本番の `signal_source` を持つ。**残るのは `cf_spike_core`（L3+L7 の合成）のみ** — この 1 件は L0 の畳み込みではなく DDoS 時系列ベースライン（S1-SCORE-025/029/030）を要するため採点層の仕事であり、本行の残余スコープはそれに限る。**畳み込み漏れは沈黙しない**: `reduce_drafts` が全アダプタに対し `(signal_source, country)` の一意性を検査し、違反したアダプタ名と本行番号を挙げて `DomainError` を投げる（L1 は同キー同内容を**黙って捨てる**ため、L1 に到達させてはならない）。証跡: `tests/test_runtime_reduce.py::TestAMissingReductionIsLoud` | **範囲縮小（WP-4.1d、2026-08-08）— retire しない。** `cf_spike_core`（L3+L7 の合成）は**着地した**: `reduce_cyber._fold_cf_spike` が 4 つの攻撃元ペイロード（現行 L3/L7 + ベースライン窓 L3/L7）を country 単位 1 行へ畳み、本番の `signal_source="cf_spike_core"`（`core.py:1025`）と本番の value/reason 文字列を復元する。中間 4 行は L1 に**到達しない**（証跡: `TestTheFoldProducesProductionsEntry::test_the_intermediate_rows_do_not_reach_the_ledger`）。**残るのは `cf_l3` / `cf_l7`（対象国ランキングの global share）2 行** — 本番はこの量を rationale エントリにせず `target_details["global_share"]` に置くだけなので、v3 の OBSERVED 2 行は本番に対応行が無い。畳み込み先が無い（本番に 1 行が存在しない）ため #11 の「N→1」の形では解けず、**処分は「本番と同じく採点面に出さない」か「観測面の増分として恒久登録する」かの裁定**になる **裁定（Fable、2026-08-09）— 観測面の増分として恒久登録し、行は残す。** 判断材料は 3 つ。(1) この 2 行は `STATUS_OBSERVED` / `raw_score=0.0` で、`admits()` を通らないため**採点面に一切出ていない** — 「採点面に出さない」という選択肢は既に満たされており、争点は観測面に残すか消すかだけである。(2) 消す理由は「本番に対応行が無い」の一点だが、**同じ形を本 WP 群で 3 回採用している**（`cf_spike_target` #118 / `ooni_heavy` #131 / 本行）。いずれも「本番が作業構造（`target_details` 等）に持つ量を、v3 の fold は純関数なので L1 経由でしか下流に渡せない」という**同一の構造的理由**による。3 回とも同じ理由で採るなら、それは場当たりではなく規則である。(3) NP6 は導出の開示を要求する。`avg_spike` の入力である国別シェアが台帳に無ければ、「TW が 8.4x」という結論の検証経路が 1 段欠ける。**したがって #11 は本行をもって恒久登録とし、retire しない。解消条件: 無し**（設計上の相違）。**規律**: 観測面の増分は `raw_score=0.0` かつ `admits()` を通らないことを**テストで固定**する — 増分が採点面に漏れた瞬間、それは登録済みでない sensitive 差分になる |
| ~~12~~ | `cloudflare_radar` | **BGP leak ペイロードの `signal_source` を `cf_bgp_leak` に分離**。現行系は hijack / leak を 1 エントリ `cf_bgp_hijack` に畳む（`core.py:1165`）が、v3 では別ペイロードとして到着するため同一キーだと L1 で衝突する。移植時の「MAX 畳み込みが論理和を再構成する」という docstring の前提は**誤り**で、畳み込みに到達する前に L1 が 2 行目を拒否（内容不一致なら `DomainError`、一致なら黙って破棄）していた | 中立（採点は WP-4.1 の reduction 後に一致）。ただし収斂カウント上は `signal_source` が 2 個になるため、NP2 の多ソース収斂で 1 事象が 2 ソースとして数えられうる | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 の reduction（`v3/runtime/reduce.py::_fold_cf_bgp`）が `cf_bgp_hijack` / `cf_bgp_leak` の 2 行を country ごとに 1 行へ畳み、本番の `signal_source="cf_bgp_hijack"` を復元した。収斂カウント上の二重計上も同時に解消（畳み込み後は 1 ソース）。 証跡: `tests/test_runtime_reduce.py::TestTheCloudflareDisjunction`。 以下は retire 前の記述（履歴として残す）: **登録**（2026-08-08）。#11 の family の具体例。**解消条件**: WP-4.1 が country 単位に reduce し、現行系と同じ 1 エントリ（`hijack=N(ongoing=M) leak=K` / `BGP manipulation detected: ...`）を再構成した時点 |
| ~~13~~ | `cloudflare_radar` | **BGP 論理和の合成 `value` / `fired_reason` が L0 では出せない**。現行系は country ごとに 1 レコード（`value="hijack=N(ongoing=M) leak=K"`、`fired_reason="BGP manipulation detected: M ongoing hijack(s), K route leak(s)"`、`core.py:1157-1176`）。v3 は endpoint ごとに `value="hijacks=N"` / `"leaks=K"`、`reason=""` | 中立（各半分の閾値は保存 — `ongoing>0` は無閾値、leak は 3 件） | **RETIRED（WP-4.1、2026-08-08）** — 同 reduction が `value="hijack=N(ongoing=M) leak=K"` と `fired_reason="BGP manipulation detected: M ongoing hijack(s), K route leak(s)"` を本番テンプレートどおりに再構成し、発火条件 `ongoing>0 OR leaks>=3` も復元した。 証跡: `tests/test_runtime_reduce.py::TestTheCloudflareDisjunction::test_the_value_is_productions_string`。 以下は retire 前の記述（履歴として残す）: **登録**（2026-08-08）。#12 と同じ WP-4.1 reduction で解消 |
| 14 | `ripe_bgp` | **stats 空応答を `STATUS_NO_DATA` / `value="NO_DATA"` として出す**。現行系のセンサーは `{"status": "NO_DATA", "is_anomaly": False}` を返すが、採点層は `is_anomaly` しか見ないため rationale は `OK` / `value="NORMAL"` / score 0 になる（`core.py:1140-1148`）。すなわち「RIPE がこの国のデータを持っていない」と「経路は正常」が現行系では**同一表現**になっている | 採点面 中立（score は両系 0）／**観測面 sensitive**（沈黙と正常が区別可能になる） | **登録**（2026-08-08）。NP1 由来 — 沈黙と正常の区別はツール定義の責務 (3)「結論不可の明示」そのもの |
| 15 | `greynoise` | **診断フィールド `api_key_configured` / `gnql_tier` / `noise_ips` / `status` を出力しない**（`radar/sensors/greynoise.py:242-251`）。前 2 者は環境変数の読み取りを要し、`v3/` 配下は `os.getenv` を規律ゲートで禁じているため L0 では原理的に出せない。`status` は `noise_class` の重複、`noise_ips` は `total_ips - malicious_ips` から復元可能 | 中立（採点・抑制ともに不変。`noise_ratio` / `noise_class` / `suppress_confidence` / `total_ips` / `malicious_ips` は一致） | **登録**（2026-08-08）。`gnql_tier` 相当の情報は AUTH_MISSING / HTTP status として `fetch_log` に出る |
| 16 | `opensky` | **`value` が空港名を含まない**。v3 は `f"{count} ac"`、現行系は `f"{airport}: {count} ac"`（`core.py:1114`、`AIRPORT_BOXES[code]["airport"]` 由来） | 中立（表示文字列のみ。status / score は一致） | **登録**（2026-08-08）。空港名は L0 に到達しない — ペイロードにもラベルにも無く `NormalizeContext` にフィールドも無い。`{airport}` プレースホルダの追加は WP-4.1 の展開器の判断 **WP-4.1 の状況（2026-08-08）**: 展開器は `AIRPORT_BOXES` を `Geography.airport_boxes` として読み込むところまで実装したが、`{airport}` を `opensky` の label に足す変更は**アダプタ側の変更**であり本 WP では行っていない。配線の材料は揃ったので、次に触る者が判断できる |
| 17 | `opensky` / `isr_hotspot` / `mil_support_air` | **body が読めないとき `STATUS_NO_DATA` を出す**。現行系のセンサーは `self.get_cache()` を返し、**前サイクルの読み（FIRED だったかもしれない）を再主張する** | v3 が 1 tick 分 **insensitive** になりうる | **登録**（2026-08-08）。取得できなかった読みの再主張は `freshness_horizon_sec` が禁じるもの（B-03）であり、L1 の horizon が置き換え機構である。アダプタの記憶で代替してはならない |
| 18 | `isr_hotspot` | **squawk を `str()` で正規化してから `== "7777"` を判定する**。現行系は生値を比較する（`isr_hotspot.py:59`）ため、JSON の数値 `7777` は現行系では一致せず v3 では一致する | **sensitive**（v3 が多く検知） | **登録**（2026-08-08）。戻すと JSON 数値表現の ISR 検知を落とすことになり、NP1 上は誤検知より悪い |
| 19 | `nasa_eonet` | **国ボックス判定に `within_box`（子午線で経度を折り返す）を使う**。現行系は折り返さない素の `abs(elng - tlng) <= radius`（`nasa_firms.py:83-84`） | **sensitive**（±180 度をまたぐ事象を拾う） | **登録**（2026-08-08）。`within_box` は `v3/adapters/common.py` の共有ヘルパで、単独アダプタのために fork すると A-02（同一計算の複数実装）を再生産する。`_THEATER_RADIUS` の全対象国は子午線から 3 度以上離れているため、現時点で実差は空集合 |
| 20 | `nasa_eonet` | **`flags` に `global_codes` を追加**（"Global only [...]" 分岐の導出根拠） | 中立（追加のみ） | **登録**（2026-08-08）。NP6 — 検証経路の無い文字列を出さないため |
| 21 | `usgs_seismic` | **`flags` に `candidate_countries` を追加** | 中立（追加のみ） | **登録**（2026-08-08）。核実験候補レコードは per-record `country` を持つが観測自体は global（country=""）なので、「どこで」をアナリストが読むための集合を別に出す |
| 22 | `usgs_seismic` | **数値フィールドを `as_float` の既定値で受ける**。現行系の素の `float()` / `props.get("mag", 0) >= 4.0` は null や非数値で例外を上げ、外側の `except Exception` が**その窓のフィード全件を捨てる**（`usgs_seismic.py:130-132`） | **sensitive**（1 レコードの破損で他の全事象を失わない） | **登録**（2026-08-08）。戻すと 1 行の破損で全損する失敗モードを復活させることになる |
| 23 | `ais_maritime` | **`value` の件数が「与えられた 1 チョークポイント」の範囲**。現行系の `core.py:1256` はサイクル内の全チョークポイントを跨いで `len(ais_dark_gaps)` / `len(ais_stationary)` を数える | 中立（当該チョークポイントの FIRED 判定は不変。印字される件数だけが狭い） | **登録**（2026-08-08）。#11 の family。チョークポイントの join は WP-4.1 の reduction **範囲縮小（WP-4.1、2026-08-08）。** reduction（`_fold_ais`）が国のチョークポイント群を 1 行へ畳み、`value` の件数を**サイクル全体**（本番 `core.py:1256` と同じ範囲）で数えるようになった。**残るのは `dark_gaps` が常に 0 である点のみ** — 船舶履歴ベースライン（`ais_vessel_history`）待ちであり、本質は #9 family。証跡: `tests/test_runtime_reduce.py::TestAisFoldsChokepoints` |
| 24 | `ais_maritime` | **`flags` に `vessel_reports`（`{mmsi, last_ts, lat, lng}`、無制限）を追加** | 中立（採点に寄与しない） | **登録**（2026-08-08）。現行系は同じ組を `self._vessel_history` にプロセス記憶として書き（`ais_maritime.py:141`）rationale には出さない。L1 の dark-gap ベースラインには他に入力が無いため、出力に載せないと §7-2 #9 の `ais_maritime` 行は永久に解消できない。現行系は 24h TTL / 5000 件で大域的に上限を掛けている（`:143-152`）。**per-payload の上限は裁定事項**（裁定要求 6） |
| 25 | `gps_jamming` | **座標を持たない国に `STATUS_NO_DATA` を出す**。現行系の `add_rat` status は同じ国に対して `"OK"` であり、`country_status = "NO_DATA"` は value 文字列内の `[NO_DATA]` ラベルとしてしかアナリストに届かない（`core.py:1810`） | **sensitive**（v3 は盲点を宣言し、現行系は平穏を報告する） | **登録**（2026-08-08）。v3 の status 語彙には「ソースは動いたがこの国を測れなかった」があり現行系には無い。`flag_catalog.py:128-131` は `country_status` の NO_DATA を既に non-firing として扱うため L5 の予算に変化は無い |
| 26 | `gps_jamming` | **CSV 行が `TypeError` を上げる場合（短い行 → `csv.DictReader` が `None` で埋め → `int(None)`）にその行だけを捨てる**。現行系は `(KeyError, ValueError)` しか捕まえない（`gps_jamming.py:104`）ため例外が `fetch` の外側ハンドラまで抜け、**そのサイクルの全国を NO_DATA に落とす** | **sensitive**（v3 は測り続ける） | **登録**（2026-08-08）。センサー全体の暗転を純関数の per-payload `normalize` で再現する表現は無く、再現すること自体が insensitive 方向である |
| 27 | `openweather` | **クエリパラメータの順序が `lat, lon, units, appid`**。現行系は `lat, lon, appid, units`（`radar/sensors/openweather.py:25`） | 無し（OpenWeather は順序を区別しない。名前と値は同一） | **登録**（2026-08-08）。資格情報は fetch カーネルが末尾に付けるため、3 番目に差し込む形は宣言型 `RequestSpec` では表現できない（表現できるようにすると資格情報がアダプタ宣言に近づく） |
| ~~28~~ | `ripe_atlas` | 現行系は `add_rat("ripe_atlas", …)` の **1 エントリ**のみを出し、FIRED 判定は probe drop 由来、latency は value 文字列に混ぜて出る（`core.py:1533-1547`）。v3 の L0 は probe 用ペイロードと 3 本の measurement ペイロードを別々に受け取り 1 行に畳めないため **4 行**を出す: `signal_source="ripe_atlas"`（probe 半分 = WP-2.8 の突合行）＋ `atlas_latency_{1001,1004,10509}`。value も `f"{active} probes, {avg_ms:.0f}ms"`（`core.py:1544`）ではなく `f"{active} probes"` と `f"{avg}ms"` に分かれる | **観測面 sensitive**（行数増）／**採点は中立**（latency 行は `STATUS_OBSERVED` / `raw_score=0.0` で S1-SCORE-008 の MAX 畳み込みに寄与しない） | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 の reduction（`_fold_ripe_atlas`）が probe 行 + 3 本の latency 行の計 4 行を `signal_source="ripe_atlas"` 1 行へ畳んだ。value も本番の `f"{active} probes, {avg_ms:.0f}ms"` に戻った。 証跡: `tests/test_runtime_reduce.py::TestRipeAtlasPoolsBeforeItPercentiles`。 以下は retire 前の記述（履歴として残す）: **登録**（2026-08-08）。#11 の family。名前を分けるのは選択ではなく**制約**（同キー・同内容の行は DomainError ではなく**沈黙して落ちる** — `store.py:290`, S5-VERIF-019）。**retire 条件**: WP-4.1 の reduction が 4 行を 1 行へ畳んだ時点 |
| ~~29~~ | `ripe_atlas` | **S1-SENS-041 の「国ごとに RTT を蓄積してから `avg_ms` / `p95_ms` / `probes_responding` を出す MUST」を L0 で満たせない**。現行系は 3 measurement の RTT を `latency_rtts[code]` へ蓄積し（`ripe_atlas.py:133`）ループ後に計算する（`:137-147`）が、`normalize` は 1 ペイロードずつしか見ないため v3 の値は **measurement 単位**になる（`pool_scope="single_measurement"` と `measurement_id` を併記）。国単位 p95 は measurement 別 p95 3 つから復元できないため、生サンプルを `rtt_samples` として搬送する | 中立（現行系でも `avg_ms` しか採点面に露出しない — `core.py:1538/1544` の value 文字列のみ） | **RETIRED（WP-4.1、2026-08-08）** — 同 reduction が `rtt_samples` を国単位に pool してから `percentile_95` を呼ぶ（export 済関数を呼ぶ = DP4 の二重実装を作らない）。`pool_scope` は `"single_measurement"` から `"country"` になった。 証跡: `tests/test_runtime_reduce.py::TestRipeAtlasPoolsBeforeItPercentiles::test_the_p95_is_the_exported_function_over_the_pool`。 以下は retire 前の記述（履歴として残す）: **登録**（2026-08-08）。§3-5 H-1(b) と**同型の構造的ギャップ**。実装先は **WP-4.1**。`collect_rtts` / `percentile_95` は export 済で reduction は同じ算術を呼ぶ（DP4 の二重実装を作らない）。**配線完了時点で retire** |
| 30 | `ihr_health` | 現行系は hegemony に `add_rat` を持たず `country_status` と `deep_analysis.ihr.core_hegemony`（`core.py:2783`）にしか流さない。v3 は 3 エンドポイントを別ペイロードで受けるため hegemony にも観測行が要り、`signal_source="ihr_hegemony"`（`core.py:490` のキャッシュキー名を借用）で `STATUS_OK` / `raw_score=0.0` 固定の行を出す | **観測面 sensitive**（行が 1 本増える）／採点は中立 | **登録**（2026-08-08）。名前が要るのは**制約**（disco=`bgp` / delay=`ihr_delay` と同一 tick・同一国で衝突する）。スコアを付けないのは現行系に根拠が無いため。**パリティ上の注意**: WP-2.8 は観測件数を突合対象に含めるため、本行が無いと登録外差分になる |
| ~~31~~ | `ihr_health` | 現行系は `disco → hegemony → delay` の優先順で国状態を 1 つに確定する（`radar/sensors/ihr.py:167-177`）。v3 の L0 は各ペイロードが自分の段（`DISCO_EVENT` / `HEGEMONY_ALARM` / `DELAY_ANOMALY` / `NORMAL`）と `ladder_rank`（1/2/3/4）を報告するのみで、勝者の確定は 3 ペイロードの join を要する | 中立 | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 の reduction（`_fold_ihr`）が `min(ladder_rank)` で国状態を確定し、全 3 行の flags に `country_status` として書く。優先順は二度書かれていない（データのまま読む）。 証跡: `tests/test_runtime_reduce.py::TestIhrKeepsItsRowsAndDerivesTheLabel`。 以下は retire 前の記述（履歴として残す）: **登録**（2026-08-08）。実装先は **WP-4.1**（`ladder_rank` の min を取るだけ — 優先順を二度書かないためのデータ化）。**配線完了時点で retire** |
| 32 | `peeringdb_ixp` | 現行系は `?country=<code>` の応答レコード**全件を要求国でタグ付け**する（`radar/sensors/peeringdb.py:75,77`）。v3 はレコード自身の `country` フィールドで分類し、欠落時のみ要求国へフォールバックする | 中立（`STATUS_OK` / `raw_score=0.0` の台帳で採点に寄与しない。単一国クエリでは両者一致） | **登録のみ**（2026-08-08）。差し戻しは感度上の利得がゼロで、既存 pin（混在ペイロードを国別に割る前提）を壊す |
| 33 | `ioda_bgp` | 現行系は `alert.get("level", "normal")` を素のまま `"critical" in levels` で比較する（`radar/sensors/ioda.py:116-122`、大小文字を区別）。v3 は `.lower()` してから `LEVEL_RANK` で比較する | **sensitive**（上流が `"CRITICAL"` を返した場合、現行系は normal と読み v3 は critical と読む） | **登録**（2026-08-08）。IODA は小文字で publish しているため実データ上の差はゼロ。NP1 側なので revert しない |
| 34 | 全アダプタ（**cross-cutting**） | **ペイロードが言及しなかった国に対して観測行を出さない**。現行系は `COUNTRY_COORDS` の**全エントリ**に `"NORMAL"` を書く（`radar/sensors/ioda.py:139,174`、`ihr.py:177`、`ripe_atlas.py:158`）。v3 のアダプタはペイロードに現れた対象にのみ行を出す（`ihr_health` のみスコープ内の沈黙国を `OK` / `"—"` として出すよう修正済） | 採点面 中立／**観測面 insensitive**（「不在」と「測って何も無かった」が区別できなくなる — §7-2 #7 が `threatfox` について既に裁定した NP1 の形と同型） | **登録**（2026-08-08、WP-2.6 remediation で発見）。**未裁定**: 22 基すべてに跨る規約であり、アダプタごとに 4 通りの判断をするより 1 行で覆うべきと判断した。**裁定要求 7** を参照。#7 の前例（「見ていない」と「見たが 0」を区別可能にすることは NP1 の要求）が適用されるなら全アダプタで沈黙国にも行を出す方向になるが、その決定は観測件数を大きく増やすためオーナー裁定を要する |
| ~~35~~ | 全アダプタ（**cross-cutting**） | **抑制（suppression）は採点層の join であり L0 では表現できない**。`is_suppressed=sw_suppress`（space weather）は `ihr_disco` / `ihr_delay` / `ripe_atlas` に届き（`core.py:1495-1496,1550`）、weather と space weather の対は `ioda_bgp` に届く（`core.py:1090-1095`、value の ` weather_muted={…}` 断片は `:1090`）。いずれも**別アダプタの出力**を要するため、`normalize` が構造上到達できない（§2-2 barrier 4） | **sensitive**（v3 は抑制されるべき観測を抑制せずに出す = 誤検知側） | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 の合成ルート（`v3/runtime/suppression.py`）が 7 本の抑制ルールを宣言表として持ち、tick が producer（`space_weather` / `openweather`）を consumer より先に実行するようプランを並べ替える（`tick.order_producers_first` — filter ではなく reorder）。抑制された行はスコアを保持する（本番同様、除外は集約側）。`only_when_fired` も本番どおり（OK 行は「抑制」ではなく静穏）。 証跡: `tests/test_runtime_tick.py::TestSuppressionNeedsItsProducerFirst`。 以下は retire 前の記述（履歴として残す）: **登録**（2026-08-08）。実装先は **WP-4.1** の合成ルート（`suppressed` / `suppress_reason` は `ObservationDraft` に既にフィールドがあるので、決めるのは「誰が誰を抑制するか」の配線のみ）。**配線完了時点で retire** |
| 36 | **L2（WP-2.4 補遺）** | **LLM インテルの経年減衰が L0/L3 から L2 へ移る**。現行系は `intel_queue.get_active_rationale`（`radar/intel_queue.py:1001-1003`）で `score_delta × exp(−max(0,age)/τ)` を計算し、**減衰後の値**を消費者に渡す（`core.py:1925` の第 5 位置引数 = `add_rat` の `score`／`core.py:2078` の `raw_score`。いずれも `ast` で確認）。v3 は L0 が**未減衰の `score_delta` と item 自身の `observed_at`** を出し、`v3/scoring/decay.py` が唯一の減衰項を持つ。τ は `Threshold.pinned` で 12.0h（`config.env:96` の実配備値と一致）。**現行系の env スイッチ 2 件（`INTEL_AGE_DECAY_ENABLED`、source_type 別 τ 上書き）は移植しない** — `v3/` は env 読取を規律ゲートで禁じており、かつ実配備でどちらも既定のまま | **実配備の設定下では中立**（同じ式・同じ τ）。設定を変えた場合のみ差分 | **登録**（WP-2.7、§9 裁定 1 の実装）。**注意**: 現行系は `Signal(observed_at=current_time)`（`core.py:2074`）で **tick の時刻**を刻むため、下流で齢を復元すると常に 0 になる。v3 が `observed_at` を運ぶのはこの破壊を避けるため |
| 37 | **L2（WP-2.4 補遺）** | **48h TTL の打ち切りと (source_type, country) あたり 2 件の上限を L2 に置かない**。どちらも `get_active_rationale` の同じ関数内にあるが（`intel_queue.py:999` / `:1005-1017`）、**信号集合の構成**（S1-PIPE-023）であって算術ではない。v3 では合成ルート（WP-4.1）の責務 | **sensitive**（v3 は現行系が捨てる寄与を保持しうる。48h で weight は e^-4 ≈ 0.018 まで落ちるので影響は小さいが 0 ではない） | **登録**（WP-2.7）。**retire 条件**: WP-4.1 が信号集合構成に TTL と cap を置いた時点。近似で L2 に置かない理由は、置けば「減衰は L2、選抜も L2」となり O-17 が畳んだ責務が再び分かれるため |
| 38 | ~~**パリティハーネス（WP-2.8）**~~ | ~~**intel 行について両系の入力が非対称になる**~~ | ~~insensitive~~ | **RETIRED（2026-08-08、オーナー裁定により本 WP で修正）**。登録時の差分は「v2 ドライバが未減衰の `raw_score` を `radar.scoring` に渡す」ことだった。**`v3/parity/_v2_subprocess.py` が本番の `radar.intel_queue._age_weight` を*呼ぶ*ようにした**（S5-VERIF-031 — 式の再実装は禁止。`rationale_to_signal` と同じ扱いで、この層は引数を整えるだけ）。齢は **item の `observed_at` から tick まで**で測る（`get_active_rationale` の `now = time.time()` の意味であり、その 1 ステップ後には `core.py:2074` が tick 時刻で上書きして齢が消える）。**証跡**: `tests/test_parity_harness.py::TestIntelRowsAreAgedOnBothSides` — 6h 齢・score 6.0 の intel 行 1 件で、修正前は legacy が TL3・v3 が TL4（半 τ の減衰が閾値 4.0 をまたぐ）、修正後は両系 TL4 で一致率 1.0。`TestTheDriverUsesProductionsOwnDecay` が「`exp(` を書いていないこと」と「両系の `llm_intel` 綴りが一致すること」を pin。**残る差分**: `INTEL_AGE_DECAY_TAU_HOURS` を既定の 12.0 から動かした場合のみ（v2 は env を実読、v3 は pin）。それは #36 が既に登録済みの内容であり、本行に固有の差分は残らない。**副作用の記録**: `_age_weight` を呼ぶため sandbox に `radar.intel_queue` が 1 モジュール増えた。import 時の面（logger 1・`threading.Lock` 1・データ定数・`__init__` を持たない `IntelQueue()`・stub 済み `db`）を審査のうえ `EXPECTED_MODULES` に追加し、`test_reaching_for_the_production_term_did_not_widen_the_sandbox` が thread 1・boot なし・DB 呼出 1 件（既知の refused read）を pin する |
| 39 | `v3/adapters/llm/extraction.py` | **プロンプト注入フレーズ集合を移植していない**。`sanitize()` は切り詰め・NFKC・制御文字除去・チャットテンプレート区切りの除去を持つが、`radar/llm_client.py:61-99` の 4 言語ぶんの注入フレーズ正規表現は転写していない | 検知感度には中立（セキュリティ管理面の差分） | **登録**（WP-2.7）。S1-INGEST-011 が「関数本体は S4 担当」と明記しており、本 WP の範囲外。**解消条件**: S4 のサニタイズ管理が v3 に着地した時点。**それまで本番と同等の注入耐性は無い** |
| 40 | `tor_metrics` / `gdelt`（**#9 family、WP-2.7**） | **L1 のベースラインが未配線の間、判定を保留してスコアを出さない**。`tor_metrics` は `drop_pct` / `surge_pct` の双方が前サイクルの計数（`_prev_relay_counts` / `_prev_user_counts`、`radar/sensors/tor_metrics.py:34-35`）を要するため 4 段ステータス（`CENSORSHIP_INDICATOR` 2 / `RELAY_DROP` 1 / `USER_SURGE` **0** / `NORMAL` 0、`core.py:1560-1561`）を一切評価できず、両行とも `STATUS_OBSERVED` / 0.0。`gdelt` は `is_alert` が OR の 2 項（`gdelt.py:73`）のうち **固定閾値の項は評価して FIRED まで出す**が、**曜日別 Z の項（K18）は L1 待ち**なので、固定閾値に達しない場合は `OK` ではなく `STATUS_OBSERVED` にする | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃**） | **登録**（WP-2.7、2026-08-08）。#9 と同一原因・同一着地先（**WP-4.1** の `NormalizeContext` ベースライン供給）。**gdelt の固定閾値項をあえて発火させる**のは、保留に倒すと本番が出す発火を落とすことになり、それ自体が insensitive を増やすため。**規律は #9 のもの**: 保留マーカーは型を当てにされているキーを占有しない — `drop_pct` は数値（`tor_metrics.py:78`）、`status` / `is_alert` は閉じた語彙（`core.py:1131,1560`）なので、判定キーは**不在**にし兄弟キー（`drop_verdict` / `trend_verdict` / `dow_verdict`）で名指す。**retire 条件**: WP-4.1 が両基にベースラインを供給した時点 **進捗（WP-4.1、2026-08-08）**: `tor_prev_relay_count` / `tor_prev_user_count` は供給済で、reduction が `combined_status` の 4 段ラダーを本番どおり再現する（`tests/test_runtime_reduce.py::TestTorReconcilesItsTwoResponses`）。`gdelt` の曜日別 Z は #9 の (a) 阻害要因のため未供給。**本行は retire しない** | **進捗（WP-4.1b、2026-08-08）— 範囲縮小、retire しない。** `gdelt` の曜日別 Z は**供給済・発火する**（裁定 1 の剰余読み `baseline_phase_values` + `_fold_gdelt`）。`is_alert` の OR は本番どおり両腕で評価され、警戒閾値 −2.0σ／標準偏差フロア 0.5／最小 3 標本まで一致する。証跡: `tests/test_runtime_baseline_supply.py::TestGdeltNowDecidesTheDayOfWeekArm`（6 件）＋ 20,000 入力 ×4 パラメータの差分スイープ（`TestTheStatisticMatchesProduction`、本番 `radar/scoring.py:484-497` と全一致）。**本行が残る理由は `tor_metrics` ではなく本表 #9 の family 規律** — #9 が retire できない以上、同一原因の本行も畳まない
| ~~41~~ | `tor_metrics` / `gdelt`（**#11 family、WP-2.7**） | **1 国 1 サイクルにつき本番 1 エントリのところ v3 は 2 行出す**。`tor_metrics` は `/summary` と `/clients` の 2 応答（本番は両者を突合してから 1 つの `add_rat("tor_metrics")` に畳む、`core.py:1576`）、`gdelt` は `1d` と `{history_window}d` の 2 窓（本番は `delta` を計算して 1 エントリ、`gdelt.py:57`）。`normalize` は構造上 1 ペイロードしか見ない（§2-2 barrier 1）ため畳み込めない。命名は `tor_metrics` + `tor_clients` / `gdelt` + `gdelt_baseline` | **観測面 sensitive**（行数増）／**採点面 中立**（増える側は `STATUS_OBSERVED` / 0.0 で S1-SCORE-008 の MAX 畳み込みに寄与しない） | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 の reduction が `tor_metrics`+`tor_clients` を 1 行に、`gdelt`+`gdelt_baseline` を 1 行に畳んだ。**採点の保留は #9/#40 のまま残る**（本行が登録していたのは行数差分のみ）。 証跡: `tests/test_runtime_reduce.py::TestTorReconcilesItsTwoResponses, ::TestGdeltFoldsItsTwoWindows`。 以下は retire 前の記述（履歴として残す）: **登録**（WP-2.7、2026-08-08）。#11 の family。**名前を分けるのは選択ではなく制約** — L1 は `UNIQUE (tick_id, sensor, signal_source, country)` で、同キー・同内容の行は `DomainError` ですらなく**沈黙して落ちる**（`store.py:290`）。`ripe_atlas`（#28）/ `ihr_health`（#30）と違い**本番に借りられる別名が無い**ため、新しい名前を作っている — これは裁定要求 5 が「発明になる」と指摘した形そのものであり、**推奨 (b)（WP-4.1 の reduction）で一括解消されるまでの暫定**である。**retire 条件**: WP-4.1 の reduction が 2 行を 1 行へ畳んだ時点 |
| ~~42~~ | `gdelt` | **`WEATHER_NOISE` / `SUPPRESSED` を出せない**。本番は `weather_conditions[code]["is_severe"]` で `is_alert` を打ち消し `status="WEATHER_NOISE"` → `add_rat(..., "SUPPRESSED", ..., is_suppressed=True, suppress_reason="Severe weather detected")`（`gdelt.py:58,73,83` / `core.py:1132`）。`weather_conditions` は **別アダプタ（`openweather`）の出力**であり `normalize` は到達できない（§2-2 barrier 4） | **sensitive**（抑制されるべき観測が抑制されずに出る = 誤検知側） | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 の suppression が `openweather.is_severe` → `gdelt` を配線し、`status="SUPPRESSED"` / `raw_score=0.0` / `suppress_reason="Severe weather detected"` を本番どおり出す。`pending_wp41_weather_join` マーカーは reduction 後の行から消える。 証跡: `tests/test_runtime_tick.py::TestSuppressionNeedsItsProducerFirst::test_severe_weather_zeroes_gdelt_because_production_does`。 以下は retire 前の記述（履歴として残す）: **登録**（WP-2.7、2026-08-08）。#35 の family、着地先も同じ **WP-4.1** の合成ルート。`suppressed=False` を黙って残すと「悪天候ではなかった」と読まれるため、`flags["weather_verdict"] = "pending_wp41_weather_join"` で**検査していない事実**を明示する。**retire 条件**: #35 の配線と同時 |
| 43 | `gdelt` | **`STATUS_NO_DATA` を出す**。本番のセンサーは `{"status": "NO_DATA"}` を書く（`gdelt.py:55`）が、採点層は `core_tone.get("status", "NO_DATA")` を **`add_rat` の value 文字列**として渡すだけで status は `OK`（`core.py:1132`）。すなわち「GDELT が答えなかった」と「トーンは平穏」が同じ `OK` になる。v3 は 429/503（`gdelt.py:27`）・空 timeline（`:29`）・解析不能をすべて `STATUS_NO_DATA` として出す | 採点面 中立（両系 score 0）／**観測面 sensitive**（沈黙と平穏が区別可能になる） | **登録**（WP-2.7、2026-08-08）。#14（`ripe_bgp` の NO_DATA）と**同型**であり、根拠も同じ — 沈黙と正常の区別はツール定義の責務 (3)「結論不可の明示」そのもの。**特に本件は捏造の回避でもある**: レート制限応答をトーン 0.0 として読むと、閾値 −15.0 より上の「中立な報道」を情報源が report していないのに publish することになる || 44 | `bg_observer_rss` | **フィード台帳は `config.py:654-661` の既定 3 本ではなく `config.env:187` の実配備 9 本を pin する**。既定は BBC / Al Jazeera / AP の西側 3 本のみで、本センサーは**西側ソース偏重を是正するために存在する**。実配備が足している 6 本（SCMP・TASS・新華社・CNA・Japan Times・聯合ニュース・台北時報）が台湾・朝鮮半島シナリオを可視にしている当のソースである。稼働ログ `[bg_observer.sensor] started — interval=300s, feeds=9` で実配備値を確認 | コード既定を転写していたら **insensitive**（フィード 2/3 と非西側全滅）。実配備を pin したので**差分なし** | **登録**（WP-2.7、2026-08-08）。pin の根拠は `gdelt` のトーン閾値と同じ「実配備値を pin する」原則。`config.env` が変わったら CI が落ちるよう `test_the_deployed_ledger_matches_config_env_exactly` が突合する |
| ~~45~~ | `bg_observer_rss` | **feed 死因の分類が `fetch_log.outcome` に届かない**。`classify_feed` は §1-7 の死因を返すが、fetch カーネルは HTTP 結果からしか `outcome` を書かないため、`returns_html` / `rss_empty` は台帳に載らない。現行系の `feeds_failed` カウンタ（A10: 「取得成功だが 0 件」を障害と同一計上）も再現していない | 観測面のみ（採点中立）。A10 の**分離自体は達成**（`parse_feed` が原因を返す）だが、**記録先が無い** | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 が `classify_feed` を `CycleHooks.classify_outcome` 経由でカーネルに渡し、`fetch_log.outcome` に `returns_html` / `rss_empty` が載るようになった。バイト列は二度パースされない（カーネルが関数を受け取る形、設計どおり）。分類は**成功した取得にのみ**適用される（`timeout` を上書きできない）。 証跡: `v3/fetch/runner.py::CycleHooks.outcome_for + tests/test_fetch_kernel.py`。 以下は retire 前の記述（履歴として残す）: **登録**（WP-2.7、2026-08-08）。**解消条件**: WP-4.1 が `classify_feed` を `record_fetch` に配線した時点。バイト列を二度パースしないため、アダプタに台帳ハンドルを渡すのではなく**カーネルに関数を渡す**形にしてある |
| 46 | `bg_observer_rss` | **実配備フィードのうち 3 本が平文 HTTP**（新華社・TASS・台北時報）。`config.py:648-653` は「網路経路上の攻撃者が悪意ある RSS を注入できないよう既定リストは TLS のみにする」と明記し、**新華社エントリはまさにその理由で既定から外された**と書いてあるが、実配備はそれを上書きして 3 本を戻している | セキュリティ管理面（検知感度は中立） | **登録・現行踏襲**（WP-2.7、2026-08-08）。`https://` へ書き換えて 404 になればフィードが消える = insensitive 方向であり、スキームは S4 が持つ判断。`PLAINTEXT_FEEDS` に名前を出してあるので修理は 1 行 |
| 47 | `bg_observer_rss` | **`evidence_url` に記事リンクを載せる**。現行系は `evidence_url=None`（`background_observer.py:398`）で表示文字列しか持たないため、**アナリストがスコアの出所の記事に到達できない** | 中立（追加のみ） | **登録**（WP-2.7、2026-08-08）。NP6 — 検証経路の無い結論を出さない |
| 48 | LLM 抽出全系（**cross-cutting**） | **二重失格 item の drop reason 名が変わりうる**。共有実装は処分表を最初に評価する（§4-1-1）。本番は `military_exercise` が `event_type` を先（`:343`）、`theater_link` を scope 判定の後（`:374`）に置き、`diplomatic` は `escalation_signal` と床を同時に見る（`:479`）。**スコアと採否は不変**（CAP が床を下回れない不変条件が保証する）。変わるのは「どの理由で落ちたか」の名前だけ | 中立（採否・スコア不変）／診断面のみ | **登録**（WP-2.7、2026-08-08）。1 実装に 8 通りの評価順序を持たせないための代償。**併せて修正した 2 件の不忠実**: (a) `escalation_signal` を `is False` で判定していた（本番は `not data.get(..., False)` なので**キー欠落は drop**）、(b) `theater_link` の未知値を direct 扱いしていた（本番は `safe_enum` 既定 `none` = **drop**）。どちらも v3 が**多く通す** sensitive 方向だったので、本番に合わせて戻した |
| 49 | `diplomatic` / `hacktivist_news` | **feed 死因の `unknown` を持たない**。本番の `_classify_feed` は 5 値（`rss_with_items` / `rss_empty` / `returns_html` / `unparseable` / `unknown`）を返す。共有パーサは前 4 者を保ち、catch-all の `unknown` の代わりに `http_error` / `geo_block` / `entity_attack` を返す | 観測面 sensitive（原因が特定される）／採点中立 | **登録**（WP-2.7、2026-08-08）。`unknown` は原因が調べられなくなる場所であり、K08 の資産価値は「5 通りに分ける」ことではなく「**名前の付いた原因を返す**」ことにある |
| ~~50~~ | `telegram_mirror` | **UA プールを回さない**。K13 のプール 5 本は**宣言データとして持つ**が、リクエストは先頭 1 本を送る。リクエストごとの選択を宣言型が表現できない（`RequestSpec.headers` は固定写像）ため | 未知（`t.me` が単一 UA を throttle する可能性）。**potentially insensitive** | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 が `CycleHooks.request_headers` でリクエスト毎の UA 選択を配線した（`USER_AGENT_POOL` を引くだけ、二重台帳なし）。**新規差分を 1 件登録**（#71）: 本番は `random.choice`、v3 は決定論的ローテーション。 証跡: `v3/runtime/tick.py::build_hooks`。 以下は retire 前の記述（履歴として残す）: **登録**（WP-2.7、2026-08-08）。**着地先: WP-4.1**（`USER_AGENT_POOL` は export 済で、配線側はそれを引くだけ — 二重台帳を作らない）。retry/backoff は既にカーネル（`v3/fetch/policy.py`）が持つ |
| ~~51~~ | `telegram_mirror` / `rss_narrative` / `travel_advisory`（**#11 family、WP-2.7**） | **1 サイクル 1 国につき本番 1 エントリのところ、v3 は入力ペイロードごとに 1 行出し、行ごとに別 `signal_source` を持つ**（`telegram_{channel}` / `narrative_{feed}` / `advisory_{us,uk,ca}`）。本番はチャンネル群・フィード群・3 政府をそれぞれ**畳んでから**命名するため、借りられる名前が存在しない | 観測面 sensitive（行数増）／**採点中立**（増える側は `STATUS_OBSERVED` / 0.0 で S1-SCORE-008 の MAX 畳み込みに寄与しない） | **RETIRED（WP-4.1、2026-08-08）** — WP-4.1 の reduction が `telegram_{channel}` / `narrative_{feed}` / `advisory_{us,uk,ca}` を本番名（`telegram_mirror` / `rss_narrative` / `travel_advisory`）1 行へ畳んだ。各寄与は `flags["sources"]` に残るため「どのチャンネルか」は畳み込み後も答えられる。**採点の保留は #9 のまま**。 証跡: `tests/test_runtime_reduce.py::TestTheNamedSourceFamily`。 以下は retire 前の記述（履歴として残す）: **登録**（WP-2.7、2026-08-08）。**名前を分けるのは選択ではなく制約** — L1 は `UNIQUE (tick_id, sensor, signal_source, country)` で、同キー・同内容の行は `DomainError` ですらなく**沈黙して落ちる**（`store.py:290`、S5-VERIF-019）。#41 と同型の暫定であり、**retire 条件**: WP-4.1 の reduction が畳んだ時点。畳み込みに要る算術（`theater_status` / `claim_confidence` / `converge` / `burst_status` / `first_signal_zscore`）は**すべて export 済**で、reduction は書き直さず呼ぶ（DP4） |
| 52 | `rss_narrative` | **A8 の `NARRATIVE_ZSCORE_FIRST_SIGNAL` を `Threshold.pinned` で出典開示する**（既定 3.0 = CRITICAL）。本番は比較地点で `os.getenv` を直読し（`:610`）どのレジストリにも無い。`v3/` は env 読取を規律ゲートで禁じている | 実配備の設定下では中立（同じ値） | **登録**（WP-2.7、2026-08-08）。§3-3 は「NP1 直結の値なので**運用可変キーに登録**」（O-18 (a) 群）と定めており、pin はその registry が着地するまでの形。**retire 条件**: ~~運用可変キーのレジストリが v3 に着地した時点~~ → **範囲縮小（WP-4.1d、2026-08-08）**。レジストリは着地した（`v3/config/registry.py`、P7 R14 / C7 は SERVED）ので**旧 retire 条件は満たされたが、本項は retire しない**。阻害が移動したためである: 本キーを登録すると **v3 側に読み手が存在しない**（`first_signal_zscore` の v3 呼び出し元がゼロ — `v3/runtime/reduce.py::_fold_named_sources` は 30 日キーワード頻度ベースラインが L1 に無いため narrative の verdict を合成しない）。到達性検査（`tests/test_config_registry.py::TestEveryVariableKeyIsActuallyConsulted`）は読み手のないキーの登録を**拒否する**ため、いま登録することは「レジストリに載っているが誰も読まない鍵」= G-15 の v3 版を自ら作ることになる。**新 retire 条件**: v3 の narrative 縮約が z-score 消費者を得た時点（＝ narrative ベースラインが L1 に着地した時点）で `NARRATIVE_ZSCORE_FIRST_SIGNAL` を O-18 (a) 群へ登録する。**本項が重要な理由**: 静穏なベースラインに対する最初の活動を CRITICAL バーストに変える分岐であり、**センサー中最も感度の高い数値が設定画面から見えない** |
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
| 71 | `telegram_mirror` | **UA ローテーションが決定論的**。本番は `radar/sensors/telegram.py:97` で `random.choice(_SCRAPER_UA_POOL)` をリトライ毎に引き直す。v3 は `CycleHooks.request_headers` がサイクル内リクエスト連番 `index % len(POOL)` で選ぶ。プール（5 本、本番と同一・同順・index 4 の重複も含めて同一）は `USER_AGENT_POOL` を引くだけで二重台帳を作らない | 中立（throttle 回避という目的は同じで、分布のみ異なる） | **登録**（WP-4.1、2026-08-08、#50 の retire に伴う新規差分）。決定論を採る理由は NP6 — 乱数を含む要求列は記録から再現できず、S5-VERIF-022 が「同じプロンプトに同じ応答」を要求するのと同じ理由で、要求側も再現可能でなければならない。**解消条件**: なし（意図的差分）。cutover 時にオーナー確認のみ |
| 72 | `gps_jamming` | **`{date}` を宣言モデルが運べない**。`tiles` 要求の `{date}` は `manifest` 要求の応答の最終行から来る =「A then B(A)」だが、アダプタは `RequestContinuation` ではなく**独立した 2 本の `RequestSpec`** を宣言している。WP-4.1 は前サイクルの観測 `flags["date"]` から供給する（`v3/runtime/baselines.py::carried_values`）ため定常運転では埋まるが、**初回起動／台帳消去後の 1 サイクルは `UNRESOLVED` としてスキップされる** | **insensitive**（1 サイクル分の観測欠落）。ただし**可視** — `run_due` が `UNRESOLVED` を記録し `InputHealth.sources_failed` に載るため「静かな不在」にはならない | **登録**（WP-4.1、2026-08-08、実測で発見）。`{date}` をリテラルのまま送ると gpsjam.org は 404 を返し、本層はそれを「妨害なし」と読む — それが避けられている点が本差分の眼目。**解消条件**: `gps_jamming` の 2 本の `RequestSpec` を `RequestContinuation` へ書き換えること。アダプタ側の変更なので本 WP では行わない（転写を書き換えに変えない）。証跡: `tests/test_runtime_expansion.py::TestEveryEnabledAdapterResolves::test_gps_jamming_is_the_one_that_needs_a_carried_value` |
| ~~73~~ | `check_host` | **URL のローテーション／クールダウンを配線していない**。本番は `URL_COOLDOWN_SEC` で 1 国の URL 群を回すが、WP-4.1 の展開器は台帳順の先頭 `MAX_URLS_PER_COUNTRY`（=3）本を**毎サイクル同じ順で**問い合わせる | **potentially insensitive**（4 本目以降の URL は永久に観測されない。本番は回して全て見る） | **登録**（WP-4.1、2026-08-08）。**解消条件**: 展開器が `fetch_log` から最終問い合わせ時刻を読み、クールダウン明けの URL を選ぶ配線。これは #9 の (b)「URL で keyed な状態」と同じ保管形の問題であり、**同じ裁定で一括して解くべき**（別々に解けば A-02 = 同一計算の複数実装の再生産になる） | **retire（WP-4.1b、2026-08-08）— 登録内容そのものが事実誤認だった。** 本番は URL 群を**回していない**: `for url in urls[:3]`（`checkhost.py:197`）で**毎サイクル台帳順の先頭 3 本**を見ており、4 本目以降は本番でも永久に観測されない。v3 の展開器（`MAX_URLS_PER_COUNTRY=3`）と**選択は同一**である。`_URL_COOLDOWN_SEC=300` は「回すため」ではなく**スパイク時の臨時起動で再問い合わせを抑える**ためのもので、定時 cadence（本番 `CHECKHOST_POLL_INTERVAL=600` / v3 `cadence_sec=600`）では到達しない分岐である。証跡（AST で本番定数と slice を直接読む）: `tests/test_runtime_baseline_supply.py::TestTheCheckHostCooldownClaim`（3 件）
| 74 | `ct_log` | **既知 CA 台帳の内容が本番より小さい**。本番は検査した全証明書の CA を`ct_log_known_ca_per_domain` に記録する（`ct_log.py:315-341` — trusted も warmup 記録も含む）。v3 は `untrusted_ca_candidates` のみを記録する | **中立（判定は同値）** | **登録**（WP-4.1b、2026-08-08）。グローバル信頼済 CA は `is_trusted or is_known_per_domain` の第 1 項で短絡するため集合到達性が無く、判定は完全一致する（台帳の**内容**のみが異なる）。**解消条件**: アダプタが全 issuer の正規化名を flags に載せること。根拠コメントは `v3/runtime/record.py::_record_ct_log` に併記 |
| 75 | `check_host` / `ais_maritime` | **プロセスメモリだった状態を L1 に永続化した**。本番の`_url_latency_history`（`deque(maxlen=12)`）と `self._vessel_history` は再起動で消える（A-03）。v3 は `entity_observation` に持つため**再起動を跨いで生き残る** | **sensitive**（v3 の方が発火しやすい — 再起動直後に本番が出せない asphyxiation / dark gap を出す） | **登録**（WP-4.1b、2026-08-08）。A-03 は本プログラムが明示的に修理対象としたもので、NP1 上も望ましい方向だが**差分は差分**なので登録する。標本上限（12）と初観測の扱い（前スナップショット無しは gap ではない）は本番どおり転写済。**解消条件**: なし（意図的差分）|
| 76 | L6 公開 API（**WP-4.1**） | **読み取りが台帳の射影であり、要求時点で採点し直さない**。本番 `GET /api/threat_data` は GET のたびに採点ティックを回して「今」の TL を返す（A-01）。v3 の R2 は L1 に**書かれた最新行**を返すため、返る結論は最大 1 cadence 分（既定 900s）古い。§7-2 #58（heartbeat 書込を持たない＝変化時のみ書く）と重なると、静穏なシナリオでは `observed_at` が数時間〜数日前になりうる | 観測面 **insensitive**（表示が古くなりうる）／**採点中立**（採点そのものは runtime が cadence どおり回す）。ただし A-01 の解消と引き換えであり、本番側の「新しさ」は GET が副作用を持つことで買われていた | **登録**（WP-4.1、2026-08-08）。**緩和は実装済**: P7 §3 が全射影に必須とする `observed_at` / `data_freshness_sec` を**ディスパッチャが 1 箇所で全 route に押す**（ハンドラが個別に付ける形にしない — 付け忘れが起こりうる形は本層が構造で潰した対象そのもの）。アナリストは「いつ採点された値か」を引き算せずに読める。**解消条件**: なし（意図的差分。A-01 の構造的解消と同一物）。証跡: `tests/test_api_projections.py::TestTheFreshnessStamp` / `::TestReadsHaveNoSideEffects` |
| 77 | L6 指令面 focus（**WP-4.1c**） | **focus をサーバ単一状態にした**。本番は per-user 行（`GET/PUT /api/auth/settings` の `focused_scenario`、JWT で自分の行のみ）と API param `?focus=` の 2 系統。v3 は指令台帳の fold 1 系統（最後の指令が勝つ）で、誰が動かしたかは `actor_id` に残る | **理屈上 insensitive**（複数アナリストが別シナリオを focus した場合、C-lite の全センサー稼働先が 1 つに定まる）／**実測差は生じない見込み** — 本番の per-user focus は **UI からの参照が存在しない**（D2 B-09、S2-PROP-014 が drop を裁定済）ため実効性が無い | **登録**（WP-4.1c、2026-08-08）。単一状態を採る理由は C-lite の意味論 — focus は「どのシナリオに全センサー予算を使うか」というサーバ側の資源配分であり、per-user にすると「focused」がスコアリングモードの言う focused と別物になる。**解消条件**: なし（意図的差分）。cutover 時にオーナー確認のみ。証跡: `tests/test_api_commands.py::TestFocusIsACommandAndItsEffectIsReal` |
| 78 | L6 指令面 feedback（**WP-4.1c**） | **ラベル投稿に理由（`reason`）を必須化した**。本番 `POST /api/v2/conclusions/<id>/feedback` の body は `{label, observed_outcome_url?, notes?}` で、`notes` は任意（`radar/routes/conclusions_v2.py:286`） | **insensitive 寄り**（本番が受け入れるラベルを v3 は 400 で拒否する = 人手ラベルの収集数が減りうる。較正の人手比率 `labels_human` が下がる方向） | **登録**（WP-4.1c、2026-08-08）。理由を要求する根拠は較正災害 3 件がすべてラベル汚染だったこと — 事後に監査できないラベルは誤ったラベルと区別がつかない。`observed_outcome_url` は**本番と同名で保持**しており（`conclusions_v2.py:344-347` が人手ラベルを ground truth に昇格させる条件）、こちらを落とせば別種の insensitive 差分になるため落としていない。**解消条件**: 運用で摩擦が報告された場合に `CommandSpec.requires_reason=False` へ戻す（1 行）。証跡: `TestG01IsStructurallyDead::test_a_label_without_a_reason_is_refused` / `::test_the_outcome_url_survives_into_the_projection` |
| 79 | L6 指令面 feedback の集計（**WP-4.1c**） | **ラベルは (結論, アナリスト) ごとに最新 1 件が有効**。本番 `radar/conclusions/feedback.py:110-111` は `SELECT label, COUNT(*) ... GROUP BY label` で**全行を数える**ため、同一アナリストが TRUE_POSITIVE を後から FALSE_POSITIVE に訂正しても**旧ラベルが票として残り続ける** | **中立〜sensitive**（本番は訂正前の TP が残るため recall が実態より高く出る＝楽観側。v3 は訂正のみを数えるため recall が下がりうる → 較正系は緩和方向の提案を出しやすくなる＝発火しやすい側） | **登録**（WP-4.1c、2026-08-08）。**旧ラベルは失われない** — 指令台帳は追記専用で全改訂を保持し、AP4 の判断履歴として再生できる。差分は「射影が何を有効票と見なすか」だけ。**解消条件**: なし（意図的差分）。ラベル台帳を較正系へ配線する WP-3.3 が本規範を前提とすること。証跡: `tests/test_api_write_seam.py::TestOneProjectionOnly::test_the_fold_equals_a_replay_of_every_row` |
| 80 | L1 `calibration_label`（**WP-3.3**） | **ラベル台帳を追記専用にし、生成器同一性 4 列（`generator_id` / `generator_version` / `rule_id` / `epoch_id`）を NOT NULL + CHECK にする**。本番 `analyst_feedback` は `(conclusion_id, analyst_id)` を UPDATE で上書きし、epoch 列を持たない | 中立〜**sensitive**（記録が増える方向）。再ラベルが行として残るため「そのラベルは以前どう書かれていたか」に答えられる — 較正事故 3 件はいずれもこの問いで発見された | **登録**（WP-3.3、2026-08-08）。F-16 は**まさにこの位置の null**（recall baseline の `since: null`）であり、epoch を任意列にした瞬間に 2 母集団のプールが再発する。二重扉: 型（`LabelRecord`）が空文字を拒否し、DB CHECK が生 SQL を拒否し、AST 監査（`labels.unexpected_construction_sites`）が第 2 の構築点を拒否する。**cross-epoch 読取は存在しない**（`labels_in_epoch` は `epoch_id` 必須で、跨ぐメソッドが無い）。証跡: `TestALabelCannotExistWithoutItsEpoch` / `TestTwoEpochsCannotBePooled` |
| 81 | L4 `lifecycle`（**WP-3.3**、A9 / S1-CALIB-052） | **提案の状態を列ではなく指令台帳の fold にする**。本番は `state` 列を UPDATE で動かし、アナリスト裁定と自動裁定は `state_changed_by` のマーカー文字列でしか区別できない。加えて **非 pending からの遷移を例外にする**（本番は UPDATE が 0 行に一致して成功を返す） | 中立（6 状態・遷移可能集合は条項どおり）。ただし**アナリストが「却下した」と信じた操作が記録されない**経路が消える = G-01 と同型の穴の封鎖 | **登録**（WP-3.3、2026-08-08）。actor / 時刻 / 理由が遷移ごとに書込面の既存規律で載るため、マーカー文字列が意味を担わなくなる。`reverted` は条項どおり**宣言され到達不能**（閾値台帳専用）。証跡: `TestTheStateMachineIsTheClause`（8 件） |
| 82 | L4 `lifecycle.defer_survives_revival`（**WP-3.3**、DP6 HIGH） | **本番の欠陥をそのまま移植した**: snooze 復活は `state_changed_at` で判定して `pending` に戻すが `emitted_at` を更新せず、自動 dismiss は `emitted_at` で判定する。既定（snooze 30 日 = stale 30 日）では Defer は「30 日後に必ず却下」と同義 | **insensitive**（アナリストが保留したつもりの提案が消える）。ただし本番と同一 | **登録 + 裁定要求 11**（WP-3.3、2026-08-08）。S1-CALIB-054 は DEFECT-PRESERVE かつ「**現行系でも要修正**」。港で黙って直すと本番との差分になり、黙って残すと欠陥が二重化する。よって**移植して証明した** — `TestDeferIsStructurallyBroken` が条項が「未検証」と記す相互作用を初めて pin する。境界は等号なので復活の瞬間は生存し、次ティックで死ぬ（`revival_boundary_is_equality`）。**retire 条件**: 本番修正の裁定が下りた時点で両系同時に修正 |
| 83 | L4 `queue.pending_count`（**WP-3.3**、A6 / ADR-V3-006） | **cap 用の pending 計数が例外時に fail-CLOSED**（例外を伝播）。本番 `scenario_improver` は計数失敗を 0 件として扱うため、DB 障害中は**上限が消える** | **sensitive 側**（v3 は提案を出さない方向に倒れる） | **登録**（WP-3.3、2026-08-08）。ADR-V3-006 の適用。負荷時に消える上限は、最も必要な瞬間に不在の上限である |
| 84 | L2 採点ティック配線（**WP-4.1e**） | **採点ティックが v3 自身の 3 層解決で settings を解決する**（`v3/runtime/scoring.py::settings_for`）。WP-4.1d 以前は `Threshold.resolve` の registry-backed 分岐が legacy `radar.config_layered` に落ちており、C7 override は台帳・監査行・設定画面には届くが**式には届かなかった** | **中立**（override 不在時の解決値は同一）。override 存在時は**本番と同じ値**になる — つまり本項は差分ではなく**差分の解消** | **登録**（WP-4.1e、2026-08-08）。「解消」を登録するのは、G-15 が「読まれない登録値」であり、その反転（読まれるようになった）は**公開数値が動きうる変更**だから。加えて `at=now` で override fold を束縛するため、**過去ティックの再生は当時の override で解決する**（P7 導出原則 4）。証跡: `TestAnOverrideChangesAScoredOutcome`（3 件）+ 4 つの mutation  **追補（2026-08-08、§7-2 #115 の掃引）— retire しない（本行は「解消の登録」であり、公開数値が動きうる事実の記録として残す）。** 本行が言う「落ちていた」経路は**削除した**: `Threshold._default_resolver` を除去し、registry-backed な `Threshold` を resolver 無しで解決すると `ThresholdResolutionError` になる。`resolve_settings()` も注入無しでは同様。配線（#84 の内容）に加えて、**配線を迂回する経路そのものが存在しなくなった** — 「合成ルートが注入し忘れる」という綴りは型で消えている。証跡: `tests/test_kernel_threshold.py::TestTheLegacyFallbackIsGone`（5 件）/ `tests/test_scoring_registry.py::test_resolve_settings_without_an_injection_refuses` |
| 85 | L1 `tl_observation` の書き手（**WP-4.1e**） | **採点ティックが TL ストリームを書く**。WP-4.1d までこの表の書き手は `v3/etl/migrate.py` だけで、稼働中の v3 は 1 行も書かなかった（= R3 の系列・トレンド窓・null-zone がすべて空） | **sensitive**（結論不可だった読み取りが結論を返すようになる） | **登録**（WP-4.1e、2026-08-08）。ヒステリシスの `previous_tl` も同じ表から読む（`prior_state`）ため、**再起動が保持中の TL を一斉に解放する**（= 配備が引き起こす見かけの de-escalation）経路も同時に閉じる。自分が書いた行を自分の prior として読まないよう `observed_at >= now` を除外する — 除外しないと同一 tick の再実行が別結果になり `append_tl` が冪等再生を拒否する。証跡: `TestHysteresisSurvivesTheProcess`（3 件） |
| 86 | L6/S8 注目スコアの ack 取り扱い（**WP-4.1f**、AP1 / G-03） | **確認済み（ack）を保存スコアに畳み込まない**。`triage_score.js:79-82` は ack 済みの結論を 3 因子の計算前に score 0 へ固定する。v3 は「ツールがその所見をどう見ているか」を台帳に書き、ack/snooze/dismiss は**射影時に利用者ごとに付す注記**にする | **中立〜sensitive**（利用者から見える行は増える方向。本番は ack 後に行が消え、v3 は状態付きで残る） | **登録**（WP-4.1f、2026-08-08）。理由は保存形の一貫性: スナップショットは共有の 1 記録であり、**誰が見ているかで値が変わるスコアは 1 記録たりえない**。加えて ack 後に行が消える形は「対処した」と「見ていない」が外から同一に見える（NP1 上望ましくない）。**解消条件**: なし（意図的差分）。証跡: `tests/test_api_attention.py::TestAckHasTwoReaders` |
| 87 | L6/S8 `analyst_blindness` の出所（**WP-4.1f**） | **組織の最終操作時刻から測る**。本番は `analystState.lastViewTs`（`localStorage`、ブラウザ単位、サーバから不可視、キャッシュ削除で消滅）。v3 は指令台帳の最新行（ラベル / ack / snooze / dismiss）を読む | **中立**（同一ブラウザで運用している限り実質同値）／**理屈上 sensitive**（別端末での操作も blindness を下げるため、複数人運用では v3 の方が blindness が低く出る＝スコアが下がる方向もある） | **登録**（WP-4.1f、2026-08-08）。ブラウザ内の時刻はサーバにも AP4 にも見えないため、その値で採点した順位は**原理的に再生できない**（= G-03 の中核）。**解消条件**: なし（意図的差分。台帳が見られる事実に置き換えたもの）。証跡: `tests/test_attention_ledger.py::TestSupplyReadsOneSourcePerFactor` + mutation「blindness stops reading the command ledger」 |
| 88 | L6/S8 同点時の順序（**WP-4.1f**） | **同点の tie-break を宣言する**（score → `order_hint`（結論型の宣言順）→ scenario_id → item_kind → item_id）。本番は score のみでソートし、同点は `Array.prototype.sort` の安定性、すなわち**呼び出し側が配列を組んだ順**（`radar.js:6698-6715` は attack_mode を anomaly より先に積む）で決まる | **中立**（既定配置では同じ順序 — attack_mode は `CONCLUSION_TYPES` 上も anomaly より前） | **登録**（WP-4.1f、2026-08-08）。永続化された順位は**保存行から再現できなければならない**（NP6）。呼び出し側の配列構築順は行のどこにも無い情報であり、tie-break にできない。**解消条件**: なし（意図的差分）。証跡: `TestTheOrderIsTotalAndDeclared`（5 件） |
| 89 | L6/S8 順位付けの母集団（**WP-4.1f**） | **全シナリオ × 全 5 結論型を順位付ける**。本番は focus 中シナリオの `attack_mode` / `anomaly` の 2 型のみをフロントで候補化する | **sensitive**（注目対象が増える。とくに background シナリオの所見が初めて順位に載る） | **登録**（WP-4.1f、2026-08-08）。「別のところを見ろ」と言えないトリアージ一覧はトリアージの主目的を果たさない（NP1）。R6 は `?scenario_id=` で絞れるため、focus 相当の見え方は射影側で作れる。**解消条件**: なし（意図的差分） |
| 90 | L6/S8 `MIN_FIRE_THRESHOLD` の適用位置（**WP-4.1f**、G-02） | **床は台帳ではなく射影に置く**。本番 `rankItems` は 0.05 未満を**順位付け前に捨てる**ため、捨てられた候補はどこにも残らない。v3 は全候補を score つきで保存し、床は利用者ごとの `min_score` として R6 で適用する | **中立**（既定 0.05 で見える行は同一）。台帳は本番より多くの行を持つ | **登録**（WP-4.1f、2026-08-08）。NP6 は「結論を出さなかった理由の開示」を求めており、床で落ちた候補が残らない形はそれを満たさない。**利用者別閾値が読まれること自体が G-02 の解消**であり、床を射影に置くことがその実装（`resolve` は R6 が呼ぶ関数そのもの）。応答は `filtered_below_min_score` を返し、**黙って隠さない**（E-17）。**解消条件**: なし（意図的差分）。証跡: `TestThePerUserThresholdIsRead`（8 件）+ mutation「the per-user floor is never read」 |
| 91 | L6/S8 per-rule 閾値の不在（**WP-4.1f**、G-02） | **本番の per-user `enter_threshold` 上書き（`user_attention_thresholds`）に v3 の対応物は存在しない**。v3 に ATTENTION ルールエンジンが無い（P7 §5 が当該 8 endpoint 群を R7 の自己評価内訳へ吸収）ため、閾値を持つルール自体が無い | **中立**（本番の当該行は評価経路から**一度も読まれていない** — `radar/attention.py::evaluate` は凍結された `_DEFAULT_RULES` を回す。`gate_lineage.py:202` が全行を ANOMALY と判定する） | **登録**（WP-4.1f、2026-08-08）。**裁定**: 利用者別閾値は「読まれるか、存在しないか」のいずれかである。読まれるものは `min_score` 1 件のみで、v3 はそれだけを持つ。存在しないルールのために鍵を作れば G-02 を v3 の綴りで再生産する。`GET/PUT /api/v2/decisions/threshold`（`dormant_enter`/`critical_enter`）も同型の死んだつまみであり、表示モードは L7 の領分なので同じ理由で持ち込まない。**解消条件**: なし（意図的差分）。証跡: `v3/attention/thresholds.py::coerce_per_user` が未登録キーを拒否 |
| 92 | L1 `attention_rank` の書込頻度（**WP-4.1f**） | **順位が動いたときだけ書く**（順序・構成の変化、または順序据置きでスコアが 1 バンド = 0.05 動いたとき）。本番は台帳を持たないため比較対象が無い | **中立**（本番に相当物が無い） | **登録**（WP-4.1f、2026-08-08）。因子 2 つが時計とともに動くため無条件書込は cadence ごとのスナップショットになり、**順序が実際に動いた 1 ティックが埋もれる**。丸めたスコアでの比較を最初に試して**実測で失敗**した（1 秒差・同順序で 0.18750 と 0.18749 が別の千分位に丸まる）。証跡: `test_clock_drift_alone_never_writes_a_snapshot` / `test_a_score_moving_a_whole_band_does_write` |
| 93 | L6 WS `notification_result` の不発行（**WP-4.1f**） | **4 イベント中 3 件のみ発行する**。本番は Telegram 送出結果を返す通知系を持つが、v3 には**通知系そのものが無い**（送出も結果表も無い） | **中立**（存在しない機能の結果を空で流す方が誤読を生む） | **登録**（WP-4.1f、2026-08-08）。空で流すと「通知は成功した」と読める。`ws_publish.PUBLISHED_EVENTS` と `UNPUBLISHED_EVENTS` が `ws.EVENTS` を過不足なく分割し、クライアントは契約の穴を**列挙で**知る。**解消条件**: v3 に通知スライスが着地した時点（WP-4.2）。証跡: `tests/test_ws_transport.py::TestTheContractIsPartitioned` |
| ~~94~~ | L7 AP3 合成チップの `ops_health` 欠落（**WP-4.2**、P8 §4） | **合成 min-fold の 5 要素のうち `ops_health`（L5 の 5 監視 / heartbeat / バックアップ / LLM 健全性）が R7 に存在しない**。v3 のチップは当該要素を `unsupplied` として畳み込み、**結果として恒常的に琥珀（reserved）を表示する**。供給済みの 4 要素だけを畳んで青を出すことはしない | **中立**（本番 HUD Row 3 は 12 チップ並列で合成値そのものを持たないため比較対象が無い）。ただし**表示は本番より悲観側**に出る | **登録**（WP-4.2、2026-08-08）。4/5 を畳んで「通常」と表示する形は **G-17 の同型**（何から作られたかを言えない結論）。NP1 上、1 系統でも疑わしければ全体を疑うのが正であり、**未供給は健全ではない**。`unsupplied`（サーバが供給しない）と `unmeasurable`（供給されたが null、サーバ自身の理由つき）を別状態として保持するのは F-12 の教訓。**解消条件**: R7 が `self_eval.ops_health`（`worst_band` / `failing_count` / `worst_monitor`）を供給した時点で自動的に解消し、チップは青に到達し得る。証跡: `tests/ui_v3/test_trust.js::todays_server: the chip cannot read TRUSTED while ops_health is unserved` | **【retire — WP-4.1g、2026-08-08】R7 が `ops_health` を供給した。解消条件を満たしたため畳む。後継は #106（供給された 4 監視のうち 2 件が構造的に未供給であるという、より狭い差分）**
| 95 | L7 O-10 ナラティブの供給範囲（**WP-4.2**、P8 §5 / P7 §4） | **結論面の全文ナラティブが無い**。R6 の注目レーン行は `narrative` を返すが、R2 の `?include=narrative` は現状 **400 で拒否される**（未実装）。v3 の結論面はナラティブ欄を持たず、代わりに導出ビュー（R4d）へ導線を出す | **中立**（本番はフロント `self_explanation.js` が生成していたが、P7 §4 がサーバ単一テンプレートエンジンへ昇格させた。ブラウザで再実装すれば昇格の意味が消える） | **登録**（WP-4.2、2026-08-08）。**フロントで代替生成しない**のが本項の要点 — P8 §5 は「本文はサーバ生成。フロントは表示のみ」であり、供給が無い間は**無いと言う**（`ui.lane.narrative.unsupplied`）。**解消条件**: R2 の `?include=narrative` が実装された時点。証跡: `tests/ui_v3/test_lane.js::a missing narrative is declared, never composed in the browser` |
| 96 | L7 鮮度表示の帯（**WP-4.2**、P5 O-13 の残余） | **`FRESHNESS_AGING_SEC = 900` / `FRESHNESS_STALE_SEC = 3600` の 2 値だけがフロント宣言の境界である**。他の全境界（recall / drift / null-zone / 鮮度上限 / calibration 標本下限 / ドメインバーの分母）は R7・R10・結論の `threshold_ref` から取得し、供給が無ければ `boundary_undisclosed` と表示して数値を発明しない | **中立**（採点に影響しない表示帯のみ。本番 HUD Row 3 は 12 チップの境界を**全てフロント直書き**していた） | **登録**（WP-4.2、2026-08-08）。由来は採点ティックの cadence 900 秒（`v3/runtime/tick.py`）— 1 cadence 超過が「やや古い」、4 cadence 超過が「古い」。**tooltip で値そのものを開示**する（`ui.freshness.boundaries`）ため NP6 は満たす。**解消条件**: R14 の可変キーに鮮度帯が登録された時点。証跡: `tests/test_v3_ui_discipline.py::ALLOWED_LITERALS`（この 2 値のみが数値掃引の許可リストに載る） |
| 97 | L7 「前回確認からの変化」のローカル保持（**WP-4.2**、P8 §2 Tier 0） | **シナリオカードの「前回確認からの変化量」はブラウザローカルの記憶（`noroshi.v3.ui.v1` の `lastSeen`）から算出する**。サーバは「この画面が最後に表示した TL」を射影しない（R6 の `analyst_blindness` は §7-2 #87 により**組織の最終指令時刻**から測る別概念） | **中立**（本番に相当表示が無い） | **登録**（WP-4.2、2026-08-08）。2 つを混同すると v1 の「ack が 1 ブラウザの localStorage にしか無い」（A6）を綴り直すことになるため、**別物として別名で保持**する。記憶が無い場合は 0 を捏造せず「初回表示」と明示する。永続キーと形は 1 箇所（`app.js` の `STORE_KEY` / `STORE_SHAPE`）でのみ定義（DP9）。**解消条件**: なし（意図的差分。サーバ化するなら AP4 の判断台帳に載せる設計判断が要る） |
| 98 | L7 pure module 6 本のうち 4 本が v3 で家を失う（**WP-4.2**、P1 §11 / P8 §7） | **`triage_score.js`・`self_explanation.js`・`hud_v2_overlay.js`・`wp_alarm.js` は v3 から参照しない**。順位付けはサーバ台帳の射影（P5 O-8）、ナラティブはサーバ昇格（P7 §4）、v3 に overlay すべき v1 は無く、Watchpane は廃止（P8 §7）。**ファイルは削除しない** — v1 は cutover まで稼働し続ける（ADR-V3-009） | **中立**（v1 側は無変更） | **登録**（WP-4.2、2026-08-08）。P1 §11 の「6 本を規範実装として keep」は**形（pure-core + 薄い DOM）の keep** であり、v3 の画面インベントリが 4 本の需要そのものを消した以上、機能としての keep は成立しない。`triage_display_mode.js`（表示モードの状態機械）と `map_dim.js`（focus 切替の 2 相ロード）の**意味論は生きている**が、v3 では地図が Tier 1 に降格し画面構造が違うため未移植（下記「残作業」）。**解消条件**: cutover 時に 4 本と v1 側テスト 106 件を削除する。証跡: `tests/test_v3_ui_discipline.py::TestRetiredSurfacesAreAbsent` が v3 側の不在を強制 |
| 99 | L7 ログインゲートの不在（**WP-4.2**、S1-UI-001〜005） | **未認証遮蔽ゲートを実装しない**。C13（auth 族 9 本）が L6 に未着地のため、ゲートが呼ぶべき endpoint が存在しない。クライアントは `localStorage` のトークンがあれば `Authorization: Bearer` を付けるが、取得・更新・失効の経路は無い | **insensitive 方向ではない**（認可はサーバ側 `Access` 宣言が全ルートで強制しており、UI ゲートの不在は権限逸脱を生まない）。ただし**UX 上の退行**（401 が操作に到達する） | **登録**（WP-4.2、2026-08-08）。満たせないゲートを作ると「ログインできない画面」になるため、**未接続であることを明示**する（`ui.deferred.auth`）。S1-UI-003 の先行更新・401 の 1 回再試行・リフレッシュ直列化も同じ理由で未実装。**解消条件**: C13 の着地時。**cutover 前提条件**（認証なしで cutover してはならない） | **【範囲縮小 — WP-4.1g、2026-08-08】阻害要因は解消した: C13 の 9 本が着地し、ゲートが呼ぶべき endpoint (`POST /api/v3/auth/login` / `refresh` / `logout`) が実在する。残るのは L7 の実装そのもの。**認可はサーバ側 `Access` 宣言が全ルートで強制しているため、ゲート不在は依然として権限逸脱を生まない**（未認証 UI は 401 を受けるだけ）。解消条件を「L7 がゲートを実装したとき」へ読み替える** | **【RETIRED — WP-4.3、2026-08-08】L7 がゲートを実装した。`v3/ui/auth.js`（純モジュール、Node で 29 件）が状態機械（`checking` / `locked` / `open`）と閉じた lock 理由集合（never / expired / revoked / signed_out / refused / throttled / unavailable / transport）を持ち、`index.html` の `#auth-gate` が `<main hidden>` の手前に立つ。**未認証は空のダッシュボードではなくゲートを見る**（射影を 1 本も fetch しない）。**再読込でセッションは生き残る** — 生き残るのは httpOnly refresh cookie であり、`begin()` がそれをサーバに問う（access token は localStorage に置かない = #111）。**セッション中の 401 は理由付きでゲートへ戻る**: `client.js` が 1 回だけ再試行し、`auth.js` が refresh を直列化（同時 401 は refresh 1 本）、修復不能なら `revoked` で施錠して画面に理由を出す（黙って白紙化する G-10 型の否定）。証跡: `tests/ui_v3/test_auth.js`（29 件）/ `test_gate.js`（13 件）/ `test_client.js` の 401 群 5 件 / `test_app_smoke.js` のゲート 9 件** |

| 100 | L6 C13 署名鍵の出所（**WP-4.1g**、S1-SVC-010） | **v3 は自分の鍵 ID `NOROSHI_V3_JWT_SECRET` で署名し、`JWT_SECRET_KEY` を読まない。鍵が無ければ生成せず、auth ルート全 9 本が 503 を返す** | 中立（稼働系は無変更） | **登録**（WP-4.1g、2026-08-08）。本番は鍵が無いと生成して `config.env` へ追記する（`radar/auth.py:155-199`）。第 2 のプロセスが同じことをすれば同ファイルを競合し、負けた側の鍵変更で**稼働中の全セッションが失効する**。鍵 ID を分けたことで v1 トークンは v3 で検証されず、逆も成立しない（v3 は `iss` を要求し v1 トークンは持たない）。**解消条件**: なし（意図的差分・恒久） |
| 101 | L6 C13 役割の一次ソース（**WP-4.1g**、S1-SVC-011 / DP1） | **認可判定は access token の `role` クレームのみを読む**。本番は保護 endpoint ごとに DB を引き直し、その読み取り中の例外をすべて 401 に潰す。v3 は認証基盤の障害（401）と権限不足（403）を分離する | 中立。ただし本番が DB 都度読みで買っていた「役割変更の即時反映」は、**`access_not_before` を役割変更時に進める**ことで買い直している（発行済み access token は即失効、refresh は生存し次回更新で新しい役割が載る） | **登録**（WP-4.1g、2026-08-08）。S1-SVC-011 の v3 規範をそのまま実装。**解消条件**: なし（規範どおり） |
| 102 | L6 C13 失効の粒度（**WP-4.1g**、S1-SVC-006 / ACCIDENTAL A2） | **JTI 失効台帳を持たない**。失効は利用者単位の床（`sessions_not_before` / `access_not_before`）で表現し、ログアウト・パスワード変更・無効化は access と refresh の**両方**を殺す | **sensitive**（本番より多く失効する）。本番のログアウトは提示された access token の JTI だけを台帳に載せ、httpOnly cookie 内の refresh token は読めないため失効させられず、cookie を事前に持ち出されていれば 24h 生存する | **登録**（WP-4.1g、2026-08-08）。台帳を持たない代わりに床が 2 本ある。他端末のセッションが一緒に落ちる点は本番と異なるが、方向は安全側 |
| 103 | L6 C13 refresh token の輸送（**WP-4.1g**、S1-SVC-004 / S2-API-010） | **refresh token を応答本文で返す。httpOnly + SameSite=Strict cookie も、対になる CSRF cookie / `X-CSRF-TOKEN` ヘッダも持たない** | **insensitive（セキュリティ軸）**。本番は本文に載せることを MUST NOT とし、XSS による refresh token 窃取を構造的に塞いでいる（S1-UI-002 は CORE 判定） | **登録 + cutover 阻害**（WP-4.1g、2026-08-08）。阻害は設計判断ではなく**輸送層の不在**: v3 の面は `ApiRequest(method, path, params, body, principal, client_ip)` でありクッキーの概念が無い。**cutover 前に必ず解消すること**。解消条件: `v3/api/binding.py` に cookie 面（set/clear + CSRF ペア）が着地し、C13login/refresh がそれを使うこと | **【RETIRED — WP-4.3、2026-08-08】解消条件を満たした。cutover 阻害はこれでゼロ**。本文は access token / user_id / role / 各寿命のみを運び、refresh token は `SetCookie(REFRESH_COOKIE, ...)` で出る。`v3/auth/session.py::Minted` は **payload に `refresh_token` が入っている状態を構築時に拒否する**ので、漏洩は「規律」ではなく「綴りが無い」。掃引テストは全 auth 応答本文を token 本体・claims 断片・signature 断片・キー名で走査し、`Minted` を寛容な代替に差し替える mutation が掃引を発火させることまで示す。CSRF は 2 層: ディスパッチャがルート宣言に従って header と companion cookie の一致を要求し（401、ハンドラ到達前）、`session.refresh` が **token 自身の `csrf` クレーム**との一致を要求する（cookie を書ける攻撃者が対を偽造できない = 本番 flask-jwt-extended と同じ束縛）。証跡: `tests/test_api_cookies.py`（34 件） |
| 104 | L6 C3 `override` 動詞の不在（**WP-4.1g**、P7 C3） | **インテル裁定は confirm / reject / revert の 3 動詞**。本番の 4 番目 `override`（抽出結果の訂正）は出さない | **insensitive**（アナリストが LLM の誤抽出を訂正できない。訂正できないものは reject するしかない） | **登録**（WP-4.1g、2026-08-08）。理由は読み手ゼロ: v3 の L1 は追記専用で、override は「訂正済み観測を新規に書く」以外に効果を持てず、それは指令面から観測台帳へ書く別スライス（provenance の問い「この行のセンサーは誰か」を伴う）。訂正を記録して誰も読まない形は G-15。**解消条件**: 指令由来観測の provenance 規範が定まったとき |
| 105 | L6 C3 裁定と採点の関係（**WP-4.1g**、O-17 / S1-INTEL-020） | **未裁定（pending）のインテルも採点される**。本番は confirmed / auto_confirmed のみが収斂に入る。v3 では `reject` が唯一の採点レバーで、`v3/runtime/scoring.py::observations_at` が当該行を落とす | **sensitive**（v3 の方が多く採点する = 大きく出る方向）。ただし WP-2.7 の O-17 着地時点で既に成立していた性質で、本項はその**明示登録**と、初めて付いた減算レバー（reject）の登録 | **登録**（WP-4.1g、2026-08-08）。裁定待ちを採点しない設計に戻すことは可能だが、それは L2 の入力規則の変更であり API 面のスライスではない。**解消条件**: なし（意図的差分。反転するなら L2 スライスで） | **【範囲縮小 — WP-4.3、2026-08-08、裁定要求 13 のオーナー裁定】登録内容は反転した。未裁定（pending）インテルは採点されない**。述語は「明示的に reject されたか」ではなく「本番が採点する状態か」に変わった（`v3/intel/adjudication.py::scoreable_rows`）。本番の実測値（AST）は `get_active_rationale` の `db.intel_list(status=...)` 2 本 = `{auto_confirmed, confirmed}` で、`pending` / `rejected` / `overridden` / `review_needed` は WHERE 節で落ちる。**残る差分は方向が逆転した**: v3 は `auto_confirmed` 段を持たない（本番の自動確認は信頼度モデル・情報生態系ゲート・裏付け件数を読む `_resolve_auto_confirm_status` で、v3 にはどれも無い。信頼度だけの模倣は対応物の無い新しい魔法数であり、これは選択肢 (c) を退けた理由そのもの）ため、**v3 は `confirmed` のみを容れる = 本番より少なく採点する（insensitive）**。述語は live ティックと parity 両ドライバ（v2 側も含む）が同じ関数を呼ぶ — 片側だけが容れれば一致率はハーネスが作った不一致で汚れる（#38 の教訓の第 2 適用）。**解消条件**: v3 に自動裁定の一次情報（信頼度＋生態系＋裏付け）が着地したとき。証跡: `TestOnlyAdjudicatedIntelIsScored`（8 件、うち mutation 2 本 = 「全状態を容れる」と「intel 行と観測行を区別しない」）/ `TestTheAdmittedSetIsProductions`（4 件、本番側は AST 実測） |
| 106 | L6 R7 `ops_health` の供給範囲（**WP-4.1g**、#94 の後継） | **4 監視のうち 2 件しか答えられない**: `backup`（v3 台帳用のマーカーが存在すれば）と `capacity`（台帳ファイル × 保持期間目標）は実測、`l5_checks` と `llm_health` は **v3 に L5 検証層と LLM 健全性ロールアップが存在しない**ため `UNSUPPLIED`。ブロックは 4 件すべてを判定つきで返し、fold は最悪値 | 中立（本番 HUD Row 3 は合成値を持たないため比較対象が無い）。表示は本番より悲観側 | **登録**（WP-4.1g、2026-08-08）。#94 を retire した後継。**答えられない 2 件を畳んで trusted を出さない**のが本項の要点で、これは #94 と同じ規律の 1 階層下への適用。`capacity` は本番の日次サンプル線形外挿ではなく**保持期間目標に対する比**（v3 に容量サンプル系列が無いため）で、`early_estimate` でその旨を明示する。**解消条件**: L5 スライスが着地して 4/4 になったとき |
| 107 | L6 C13 argon2 への遅延再ハッシュの不在（**WP-4.1g**、S1-SVC-001） | **ログイン時に PBKDF2 ハッシュを argon2 へ張り替えない**。本番は成功ログインのたびに再生成して保存する | 中立（v3 は新規ストアで、argon2 が使える環境では最初から argon2） | **登録**（WP-4.1g、2026-08-08）。理由は構造: v3 の login は台帳に 1 行も書かない射影（`ReadContext` を持つ）であり、そこで書けば読み取り経路からの書込 = A-01 の形。代わりに `credential_upgradable` を利用者射影に出し、運用者がパスワード再設定で上げる。**解消条件**: なし（意図的差分） |
| 108 | L6 C13 ログインガードの発信元判定（**WP-4.1g**、S1-SVC-003 / ACCIDENTAL A1） | **`X-Forwarded-For` を一切信頼しない**（本番は `TRUST_PROXY_XFF` 設定時に先頭要素を採用）。5 回 / 300 秒 / 追跡 1000 件と退避規則は本番どおり転写 | 中立〜**sensitive**（プロキシ配下では全要求が同一アドレスに見え、ガードが厳しく効きすぎる可能性） | **登録**（WP-4.1g、2026-08-08）。v3 の前段にプロキシがまだ無く、既定で信頼するヘッダは攻撃者が打ち直せるガードである。**解消条件**: 配備形態が確定し、信頼境界を宣言できたとき |
| 109 | L6 refresh cookie の名前とパス（**WP-4.3**、S1-SVC-004） | **cookie 名は v3 独自** (`noroshi_v3_refresh` / `noroshi_v3_csrf_refresh`)、**refresh cookie のパスは v3 の refresh ルート自身** (`/api/v3/auth/refresh`)。本番は `radar_refresh_jwt` / `csrf_refresh_token` を `/api/auth/refresh` に置く | 中立（姿勢は同一 — httpOnly / SameSite=Strict / Secure 既定 on / session cookie / CSRF cookie は `/` かつ非 httpOnly。差分は識別子とプレフィックスだけ） | **登録**（WP-4.3、2026-08-08）。v1 と v3 は同一ホストに並走する（ADR-V3-009）。同名 cookie が 2 本あると、どちらがどちらか**ブラウザの側でも人の側でも見分けられない**。鍵 ID を分けた #100 と同じ理由の輸送層版。**解消条件**: なし（意図的差分・恒久）。証跡: `TestThePostureIsProductions`（6 件、本番側は `radar/auth.py` と導入済 `flask_jwt_extended` の AST 実測） |
| 110 | L6 CSRF トークンの生成（**WP-4.3**、S1-SVC-004 / NP6） | **署名鍵からの決定論的導出** (`hmac(key, "csrf\x1f" + jti)` の先頭 32 桁)。本番 flask-jwt-extended は `secrets.token_hex(16)` の乱数 | 中立（強度は同じ — 攻撃者が持たない鍵の HMAC。値は本番と同じく**署名済トークンの内側**にも入るため、cookie を書ける攻撃者は対を偽造できない） | **登録**（WP-4.3、2026-08-08）。`jti` を決定論にしたのと同じ理由: `issue` が引数の関数であることで、判断履歴の再生が同じセッション識別子を再構築する（NP6）。乱数はこの性質を 1 か所だけ壊す。**解消条件**: なし（意図的差分）。証跡: `test_the_csrf_value_is_derived_from_the_signing_key` / `test_an_access_token_carries_no_csrf_claim` |
| 111 | L7 access token の保持場所（**WP-4.3**、S1-UI-002） | **access token はメモリのみ。`localStorage` に書かない**。本番 SPA は `localStorage` に保存する（`app.js` の旧 `noroshi.v3.token` 読み取りは**誰も書かないキー**だった） | 中立〜**sensitive（セキュリティ軸）**（v3 の方が強い。永続化された bearer token は、ブラウザが生きている限りページが実行する任意のスクリプトから読める） | **登録**（WP-4.3、2026-08-08）。再読込を越えて生き残るのは httpOnly refresh cookie の方であり、それは JS から読めない — つまり「セッションが再読込を生き延びる」(S1-UI-004) は**サーバに訊く**ことで満たせる。#103 が refresh token について閉じた窃取経路を、access token についても縮める。**解消条件**: なし（意図的差分）。証跡: `test_no_bearer_token_is_ever_written_to_localStorage` |
| 112 | L8 WebSocket チャネルを合成しない（**WP-4.4**、P7 §1.3） | **影配備は socket 面を一切マウントしない**。本番は socket.io で `threat_update` 等を押し出す。v3 のイベント語彙と発行者の有無は `v3/api/ws_publish.py` に着地済だが、`create_channel` を呼ぶ合成が存在しない | 中立（画面はポーリングで同じ射影を読む。検知内容は変わらない） | **登録**（WP-4.4、2026-08-08）。理由は実測: **`v3/ui/` に socket クライアントが 1 つも無い**（`grep -n "socket" v3/ui/*.js` が 0 件）。読み手ゼロの並行面を影稼働に足すのは、parity と無関係な故障要因を増やすだけである。`notification_result` の不発行（#93）とは別の話で、あちらは**発行者**が無く、こちらは**受け手**が無い。**解消条件**: `v3/ui/` に socket クライアントが着地したとき（P8 のライブ更新スライス）。証跡: `TestDeliberateAbsences::test_no_socket_channel_is_mounted` / `composition.WEBSOCKET_ABSENT` |
| 113 | L8 実行モデル（**WP-4.4**、S4-NF / P4） | **1 プロセス・gunicorn gthread ワーカー 1・取得ループ 1 スレッド・gevent monkey-patch 無し**。本番は gevent + `GeventWebSocketWorker` で、import 時に約 40 スレッドを起こし、センサーを並行に走らせる。v3 の 1 サイクルはアダプタを**逐次**に回る | **insensitive になりうる**（サイクル所要時間が取得間隔を超えると、周期内に全アダプタを回りきれず、遅い側の観測が落ちる。落ちた観測は「静かな世界」と区別がつかない） | **登録**（WP-4.4、2026-08-08）。並行度とサイクル順序は明示的に合成ルートの決定事項（§1-2）であり、**逐次は「まだ測っていない既定」であって最適化の結論ではない**。並行化を先に入れると、レート制限・サーキットブレーカー・抑制の生産者順序（`order_producers_first`）が同時に動くため、遅延の原因が特定できなくなる。**解消条件**: Phase 5 の影稼働で 1 サイクルの実測所要時間が `NOROSHI_V3_TICK_INTERVAL_SEC` を超えることが観測された時点。まず間隔を伸ばし、それでも足りなければ並行度を入れる（順序は逆にしない）。証跡: `TickReport.planned` / `skipped` と `fetch_log` |
| 114 | L8 設定の入口（**WP-4.4**、G-15 / S1-SVC-010） | **影配備はプロセス内で `config.env` を読まない**。環境変数は docker CLI がホスト側で `env_file` として読み、コンテナに渡す。v3 が読む名前は `v3/server/settings.py::KEY_IDS` + 設定レジストリの可変キー + アダプタが宣言した資格情報 ID の**合併に限定**され、その集合は宣言から導出される。本番は python-dotenv でプロセス内に読み込み、鍵が無ければ生成して `config.env` に**追記**する | 中立（読む値は同じ。書かない点が違う） | **登録**（WP-4.4、2026-08-08）。#100 が「鍵を生成しない」を閉じたのに対し、こちらは「**あのファイルへの書き込みハンドルを持たない**」を配備の形で閉じる（`Dockerfile.v3` は `config.env` を COPY せず、compose はマウントしない）。稼働中の秘密を持つファイルに第 2 の書き手が現れると、負けた側の鍵の変更が全アナリストをログアウトさせる。さらに `env_file` はファイルを丸ごと渡すため、compose の `environment:` が **`JWT_SECRET_KEY` と `DEFAULT_ADMIN_PASSWORD` を空で上書き**する — v3 はどちらも読まないが、影が侵害されたときに v1 のトークンを偽造できる材料を持たせない（最小権限）。**解消条件**: なし（意図的差分・恒久）。証跡: `TestTheDeploymentShapeIsBesideV1NotInsteadOfIt`（`test_v1s_own_secrets_are_blanked_in_the_shadow` を含む）/ `--check` の `environment_keys` |
| ~~115~~ | ~~L8 系列連鎖の所有国が既定で未供給~~（**WP-4.4**、S1-PIPE-016） | ~~`NOROSHI_V3_CHAIN_COUNTRIES` を供給しない限り、どのシナリオにも chain owner が無い~~。本番は生スパイク平均で dual-core の primary_ec を選ぶ（`radar/routes/core.py:878-881`）。v3 は裁定どおり導出せず、未供給のまま focus されると `chain_country_for` が例外を投げる | ~~**insensitive**（focused ボーナスの系列・時間的一貫性の加点が出ない。さらに例外により当該ティック全体が失敗するため、その周期の結論行が書かれない）~~ | **RETIRED（2026-08-08、オーナー裁定）**。登録時の緩和（環境変数による供給）は**裁定で却下**された — 定数は「いま誰がエスカレートしているか」を永久に固定するため、静的導出を禁じた当初の裁定が防ごうとした失敗そのものであり、**運用者の名前が付くだけで欠陥は同じ**。解消は登録時の解消条件どおり「生スパイクから所有国を選ぶ供給側」の着地: `v3/runtime/chain.py` が本番の 2 段（(a) `radar/scenarios.py::derive_country_context` の effective_cores = 宣言 `core_country`、無ければ weight 0.9 以上の `principal_belligerent` を**ソートして**列挙／(b) `core.py:878-881` の `max(cores, key=強度)` — `max` は**先頭の最大要素**を返すのでソート順が同点時の決定規則）を転写し、**そのティックの観測から毎ティック選ぶ**。`scenarios_for` は宣言された `core_country` を読む（宣言の読み取りであって所有国の導出ではない）。選ばれた国は `TickReport.chain_owners` に開示される（NP6）。**残る差分は #116（順位付け量）に登録**。合成ルートの告知は残るが意味が変わり、「未設定のシナリオ」ではなく**候補が 1 国も無いシナリオ**（`core_country` 未宣言かつ weight 0.9 以上の principal_belligerent 不在 = シナリオ定義の穴）を名指す。証跡: `tests/test_runtime_chain_owner.py`（37 件、うち AST 転写照合 3 件・受入 7 件・ミューテーション 5/5 検出・silent-stop 回帰 5 件）、`tests/test_v3_server.py::TestDeliberateAbsences`（告知の意味変更 3 件） |
| 116 | L8 系列連鎖の所有国を選ぶ**量**（**WP-4.4 後続**、S1-PIPE-016 / §7-2 #9） | **候補国の順位付けに `avg_spike` ではなく「そのティックで採点に寄与した観測スコアの合計」を使う**。本番は `avg_spike`（`core.py:817` = 対象国あたりの攻撃元分布 × ベースライン比の加重平均）で primary_ec を選ぶ。v3 はこの量を持たない — §7-2 #9 が記録するとおり計算していないだけでなく、**入力そのものを取得していない**: `CLOUDFLARE_RADAR_ADAPTER` の 4 リクエストに `attacks/layer{3,7}/top/locations/origin`（`core.py:747-748` が対象国ごとに叩く攻撃元分布、および `core.py:741-742` の 90 日ベースライン）が無い。したがって L1 配線では解けない。代替は**生きた測定**であること（定数ではないこと）を最優先に選んだ最小の量: カーネル自身の `Observation.admits()` を述語に、その国を名指す観測の `score` を合計する。結合重みは掛けない（`avg_spike` も掛けていない） | **中立〜sensitive**（v3 は 3 ドメイン全部を見るが本番は cyber の DDoS スパイクのみ。cyber 以外でエスカレーションが見えている局面で v3 は本番と違う belligerent を選びうる。選択が変えるのは focused ボーナスが**どちらの系列連鎖を読むか**であり、より多くの証跡を持つ側を選ぶ方向は recall 側 = NP1 整合。同点時の決定規則は本番と同一〔ソート順の先頭〕なので、静穏ティックでは両者一致する） | **登録**（2026-08-08、#115 の retire と同時）。**解消条件**: v3 が `attacks/layer{3,7}/top/locations/origin` を取得し攻撃元分布ベースラインを L1 に持ったとき — そのとき §7-2 #9 の `cloudflare_radar` 行も同時に解消しうる（両者は同じ入力を待っている）。**規律**: 代替量を「本番の規則」と称してはならない。本行が差分であること、方向が上記であることを明示したうえで進める。証跡: `tests/test_runtime_chain_owner.py::TestTheAvgSpikeObstacleIsRealAndRegistered`（本番が origin エンドポイントを叩くこと・v3 が叩かないことの両方を実測） | **範囲縮小（WP-4.1d、2026-08-08）— retire しない。** 解消条件の前半（origin エンドポイントの取得と攻撃元分布ベースラインの L1 保持）は**満たした**ので、**順位付けの既定量は本番の `avg_spike` になった**: `v3/runtime/scoring.py::spike_intensity` がそのティックの `cf_spike_target` 行から `{country: avg_spike}` を読み（**WP-4.1i 訂正**: #118 の retire で `cf_spike_core` は countryless になったため、per-country の量は観測面に移った）、`chain.ranking_for` がシナリオの core にそれを適用する。測定済 core が 1 つでもあれば `avg_spike` 基準で、未測定の core は本番と同じ既定値 0.0 になる（`target_details.get(ec, {}).get("avg_spike", 0)`）。**残差は「そのティックでどの core も測定を持たない場合」に限る**（新規配備、または全 core の取得が失敗したサイクル）— そこでは従来どおり「採点に寄与した観測スコアの合計」で順位付ける。本番のその場面での答えは退化しており（全 core が 0.0 → `max` がソート順の先頭を返す）、証跡の多い側を選ぶ方が NP1 に整合するため fallback を残した。**どちらの量で順位付けたかは開示する**（`TickReport.chain_ranking` の `basis` / `values` / `production_ref`、NP6 は順位付けにも及ぶ）。retire 条件は「fallback 経路が到達不能になったとき」— すなわち cf の取得が全 core で恒常的に成功する運用実績が取れた時点で、fallback ごと畳んでよいかを裁定する。証跡: `tests/test_runtime_cf_spike.py::TestTheChainOwnerIsRankedByAvgSpike`（8 件）/ `::TestTheWholeThingRuns`（end-to-end 8 件、うち 1 件は fallback 側の開示を実測）/ `tests/test_runtime_chain_owner.py::TestTheAvgSpikeObstacleIsGone` |
| ~~117~~ | ~~`cloudflare_radar` — 攻撃元ベースラインの取得周期~~（**WP-4.1d**） | **攻撃元ベースラインを毎サイクル取り直す。本番は 24 時間に 1 回しか取り直さない**（`core.py:738-742` — `_db.baseline_get` が 86400 秒より古いときだけ再取得し、`fetch_cf_data_cached` は空応答時に古いキャッシュを保持する `scoring.py:648-654`）。v3 の取得カーネルは**リクエスト単位の周期を表現できない**（`fetch_schedule` はアダプタ単位）ため、4 本の origin リクエストはアダプタ周期（900 秒）で一律に飛ぶ。取得失敗時の退避は台帳側で行う（`entity_observation` の `cf_origin_baseline` に 1 対象 1 スナップショット、`baseline_source` フラグで `fetched` / `stored` / `absent` を開示） | **わずかに insensitive**（28 日集計が最大 24 時間ぶん新しくなるため、持続的な攻撃下では直近の上昇を分母に取り込みやすく spike がわずかに低く出る。重みは 1 日あたり概ね 1/28）。**取得負荷は本番比で対象国あたり 1 日 +190 リクエスト前後**（CF 無料枠 1200 req/5min に対し十分小さい。rate_limit_group `cloudflare` / 0.35 秒間隔で整流される） | **登録**（2026-08-08）。**解消条件**: 取得カーネルがリクエスト単位の周期（または「台帳の値が N 秒より新しければ送らない」という宣言）を表現できるようになった時点で、本番の 24 時間規則を転写する。**代替案を採らなかった理由**: (a) 取得して捨てる = 実装がバグに見える、(b) ベースライン専用アダプタを立てる = 1 ソース 2 アダプタになり `reduce` が adapter_id で引かれる以上、現行窓とベースライン窓が別の畳み込みに分かれる。証跡: `tests/test_runtime_cf_spike.py::TestTheStoredBaselineIsTheFallback`（3 件）  **RETIRED（WP-4.1h、2026-08-09）— オーナー裁定により「わずかに insensitive だから受容」を却下。** insensitive は既定では受容しない方向であり、かつ「わずか」は見積りであって測定ではない。**本番の日次ゲートを転写した**: `RequestSpec.refresh_after_sec`（宣言）+ `v3/runtime/baselines.py::refresh_state`（保管済スナップショットの `observed_at` を齢として供給）+ `run_due` の `_withhold_fresh`（展開後のステップ単位で withhold）。**第 2 のスケジューラは作っていない** — 本番にも無いからである。本番が持つのは タイムスタンプ付きの保管値と 1 つの比較（`core.py:739` = `not b_data or (current_time - b_data["time"]) > 86400`）だけで、v3 の `cf_origin_baseline` の `observed_at` がその `b_data["time"]` にあたる。齢は L1 にあり、カーネルは何も開かない。**周期は per-adapter ではなく per-request**（`fetch_schedule` の表は触っていない = L1 スキーマ変更なし、裁定要求 3 に触れない）で、展開後に効くので**対象国ごとに別日**に更新される。**同時に 1 件の沈黙欠陥を潰した**: `record.py::_record_cf_origin_baseline` は スナップショットを**毎サイクル `observed_at=now` で再押印**しており（読み直しただけのサイクルも）、ゲートがその齢を読む以上、齢は 900 秒ごとに 0 に戻り**日次ゲートは一度も発火しない**。しかも行は `stored` と表示し続けるので、外からは正常に見える。修正は本番と同じ 「`baseline_set` は再取得した `if` の中だけ」（`core.py:739-742`）で、`baseline_source == "fetched"` のときにだけ押印する。**取得負荷**: 対象国あたり 1 日 192 送信 → 2 送信（登録時の見積り「+190」と一致）。**withhold は開示する**（`PlannedFetch.withheld` / `FetchPlan.withheld` / `TickReport.withheld` に `(label, scope_key, due_at)`）— 宣言より少なく送るプランが黙っていると、展開が壊れた状態と見分けが付かない。証跡: `tests/test_runtime_cf_spike.py::TestTheRefreshWindowIsDeclared` / `::TestTheRefreshPredicateIsProductions`（本番条件との 20,000 件スイープ含む）/ `::TestTheStoredAgeReachesThePlanner` / `::TestThePlannerWithholdsAFreshBaseline` / `::TestTheRecorderDoesNotResetTheAge` / `::TestTheDailyGateHoldsEndToEnd` |
| ~~118~~ | ~~`cloudflare_radar` — `cf_spike_core` の適用範囲~~（**WP-4.1d**、**WP-4.1i で retire**） | **v3 は参加国**全部**について spike を計算し判定する。本番は 1 シナリオにつき 1 行**（`primary_ec` = 系列連鎖の所有国のみ）**を出す**（`core.py:1006` が `compute_hod_zscore(primary_ec, core_spike, ...)`、`:1025` が `add_rat` 1 回）。v3 の観測は国単位なので、各国が自分の avg_spike を自分の HOD ベースラインと比べる。HOD 標本の記録範囲も同様に広い（本番 `record_hod_sample` は `strategic_theaters` = **focused シナリオ**の参加国のみ、`core.py:824-825`。v3 は採点対象シナリオ参加国の**和集合**） | **sensitive**（本番が黙る場所で v3 が発火する。判定式・閾値・ウォームアップ分岐は同一で、適用範囲だけが真に広い） | **登録**（2026-08-08）。方向が NP1 側なので revert しない。**留意（2026-08-08 レビュー指摘を受けて実測）**: 行数が本番より増えることで収斂（NP2）に効く経路を 2 つとも辿った結果、**片方だけが影響を受ける**。`convergence_level` は `len(active_domains)` を読む（`v3/scoring/kernel.py:97`）ので、同じ cyber ドメイン内で `cf_spike_core` が何行立とうとドメイン数は 1 のまま — **影響なし**。一方 `convergence_bonus` は第 2 引数に `len(active_countries)` を取る（同 `:94-96`）ので、他のセンサーがまだ立てていない国で `cf_spike_core` が発火すると **participant 数が増えてボーナスが上がる**。cyber ドメイン合計そのものは `domain_cap` で頭打ちになるが、このボーナス経路には cap が効かない。方向は sensitive のままで NP1 側だが、「行が増えるだけ」ではなく**スコアの別経路にも波及する**ことを明記する。**解消条件**: 無し（設計上の相違として恒久登録）。証跡: `tests/test_runtime_cf_spike.py::TestTheFoldProducesProductionsEntry::test_two_countries_fold_independently`  **事実訂正（WP-4.1h、2026-08-09）— 本行の記述は本番側の前提を取り違えていた。方向（sensitive）は正しいが、機序と規模が違う。** 本番の `cf_spike_core` は**どのシナリオのスコアにも入らない**。`add_rat` の第 1 引数は `RationaleEntry.sensor` になり、`core.py:2039-2041` は `rat.sensor in FOCUSED_ONLY_SENSOR_NAMES` のときだけ国を与える。この frozenset (`radar/scenarios.py:75-79`) が持つのは**センサー名**（`cloudflare_radar` 等）であって `cf_spike_core` ではないので、`rationale_to_signal` は `countries=[]` の Signal を作り (`radar/scoring.py:79`)、`GLOBAL_SIGNALS_DECOUPLED` 既定 true (`radar/config.py:421`) の下で `compute_scenario_score` は `continue` する (`radar/scoring.py:1452-1453`)。本番のこの行は `compute_global_threat` の envelope（×0.5）にしか寄与しない。つまり差分は「1 行 vs 参加国ぶんの行」ではなく **「シナリオスコアに 0 vs 参加国ぶん × 結合重み」**であり、cyber ドメインに対しては `domain_cap`(6.0) までの全幅が v3 側にだけ乗る。方向は **sensitive**（NP1 側）なので revert しないが、規模の記述を訂正して残す。**解消条件**: 無し（v3 側を countryless に 揃えるのは cyber 検知を丸ごと捨てる insensitive 変更であり、NP1 に反する）。証跡: `tests/test_runtime_cf_spike.py::TestTheThreeRowsAreProductionsAndCountryless`（本番側 3 点を AST/実測で固定）  **RETIRED（2026-08-09、オーナー裁定）— v3 の `cf_spike_core` も countryless になった。** 裁定は前回の処分（sensitive だから revert しない）を 2 つの理由で覆した。**(a) パリティゲートがこの差分を構造的に測れない** — `v3/parity/adapter.py:175-177` は `country` を**保管済みの履歴行**から読むため、本番の countryless 行はハーネスを通っても countryless のままで、差分は v3 の**生の畳み込みの中にしか存在しない**（ハーネスは畳み込みを実行しない。`driver_v3.py` は 保管行を直接カーネルへ射影する）。ゲートが測れない差分をゲートで検証したとは言えない。実測で確認済 (`tests/test_v3_country_attribution.py::TestTheGateCannotSeeAnyOfThis`)。**(b) 本番が既に直した欠陥の再導入である** — Phase 9 (2026-05-13) が global signal を decouple したのは 「`the ~1.5 constant floor that previously contaminated every scenario`」を消すため（`radar/scoring.py:1448-1451`）。静穏日にも等しく立つ床は検知ではなく**バイアス**なので NP1 は保護しない。**着地**: `cf_spike_core` は `country=""` の 1 行、判定は本番と同じく **primary core の HOD 判定**（`core.py:872-884` の `core_spike` = primary の `avg_spike`、`:1006` が 1 回だけ `compute_hod_zscore`）。**per-target の量は失われない** — 本番が `target_details`（`core.py:831`、rationale entry ではない作業構造）に持つのと同じものを、v3 は `cf_spike_target` という **OBSERVED / raw_score 0.0 の観測面**に置いた（`passes_gate()` も `admits()` も False。カーネルの述語そのもので実測）。`spike_intensity` / `record.py::PHASE_SAMPLES` / `_record_cf_origin_baseline` の 3 読者はそこを読む — 本番も HOD 標本 (`core.py:824-825`) と origin ベースライン (`core.py:739-742`) を per-target 構造から取っており、countryless な行に「TW が今時間どう読んだか」は答えられない。**#116 の順位付けは退行していない**ことを掃引ではなく**対立するテスト**で固定した: `avg_spike` と admitted-evidence が**互いに逆の国を選ぶ**入力を作り、basis が `avg_spike` であることと fallback なら別の国になることの両方を主張する (`TestTheRankingReadsTheLedger::test_assemble_ranks_by_the_spike_row_it_finds`)。**残余は #124 に移した**（HOD 標本範囲）／**同型の未処分が #127 に出た**（本番が countryless で v3 が per-country の 15 家系）。証跡: `tests/test_runtime_cf_spike.py::TestTheFoldProducesProductionsEntry`（countryless 化・primary core の判定・観測面が採点も gate もしないこと）、`tests/test_v3_country_attribution.py` |
| 119 | `cloudflare_radar` — `cf_spike_core` の攻撃元フロア（**WP-4.1d**） | **adversary 集合が採点対象シナリオの和集合。本番は focused シナリオの `adversary_states` のみ**（`core.py:590` が `_ctx["adversary_states"]`、`_ctx` は `derive_country_context(focused)`）。この集合は spike のフロアを決める — adversary 由来なら 0.5%、それ以外は新規 3.0% / 既存 2.0%（`core.py:775-777`）で、同じ 2% の観測が 4 倍にも 0.67 倍にもなる | **sensitive**（和集合 ⊇ focused 集合なので、より多くの攻撃元が低いフロアで測られ spike が高く出る） | **登録**（2026-08-08）。1 サイクルが全シナリオぶんを一度に取得する v3 の構造から出る差分で、focused を見て取得内容を変えることは C-lite の再導入になるため採らない。**供給経路**: `run_tick` → `fetch_cycle(adversaries=...)` → `baselines.for_cycle` の `adversary_origins` キー（履歴ではない唯一のキー、`v3/runtime/baselines.py` に理由を明記）。**不在と空集合は区別する** — 常に設定するので、フォールドが「宣言が無い」と「誰も渡さなかった」を取り違えない。証跡: `tests/test_runtime_cf_spike.py::TestTheWholeThingRuns::test_the_declared_adversary_reaches_the_floor` |
| 120 | `cloudflare_radar` — `cf_spike_core` の value 文字列（**WP-4.1d**） | **適応 Z（S1-SCORE-030）の装飾 ` [AZ=<z> n=<n>]` が付かない**。本番は `compute_adaptive_zscore("cf_spike_core", ...)` を呼び、adaptive なら `spike_value` に追記する（`core.py:1020-1023`）。同関数は running statistics を**更新する副作用**も持ち、その状態は `core.py:2726-2729` の API 開示に出る | **観測面 insensitive**（印字が痩せる）／**採点中立**（`spike_score` は追記の前に確定しており AZ は score に触れない。AST 実測） | **登録**（2026-08-08）。S1-SCORE-025/029/030 は派生観測生成器として L2 から除外されており、適応 Z はそのうちの 1 つ。**解消条件**: 適応 Z を L1 の系列として持つ設計判断がなされた時点（`cf_attack_share_baseline` と同じ形が取れる）。それまで v3 の value は HOD 分岐の文字列のみ |
| ~~121~~ | ~~`cloudflare_radar` — `cf_vector_shift` / `cf_adversary_strike` / `cf_coordinated` の 3 行~~（**WP-4.1d で可視化**） | **同じ攻撃元分布から本番が出す 3 行を v3 は出さない**。本 WP まではそもそも入力が無く到達不能だったが、`avg_spike` / `avg_l3_spike` / `avg_l7_spike` / per-origin `spike_factor` が揃った今は**実装されていないだけ**になった。保留しているスコア幅（すべて `radar/routes/core.py` で実測）: `cf_vector_shift` 0-2（`:1070`、`core_shifted` で +1、`avg_l7_spike >= 5.0` かつ `> avg_l3_spike * 2.0` で +2。`is_vector_shift` は `:814`）／`cf_adversary_strike` 0-3（`:1075`、`adversary_strikes` 1-2 件で +2、3 件以上で +3。strike の条件は `:798` = 攻撃元が adversary かつ対象が strategic かつ `spike_factor >= 4.0` かつ `current_local_pct > 3.0`）／`cf_coordinated` 0-1（`:1077`、`elevated_theaters` = `avg_spike > 3.0` の strategic 国、`:863`） | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃の blocking 級**。cyber ドメインで最大 6 点ぶんの検知が出ない） | **登録**（2026-08-08）。**本 WP のスコープ外**（本 WP は `avg_spike` の取得・転写・判定・順位付けに限る）だが、#9 の規律どおり**発見時点で登録する**。3 行はいずれも本 WP が着地させた量の上に載る派生判定であり、`v3/runtime/spike.py::OriginSpike` は per-origin の `spike_factor` / `is_adversary` / `l3_spike` / `l7_spike` を既に開示しているので、**追加の取得は要らない**。**解消条件**: 3 つのラダーを `v3/runtime/spike.py` に転写し `_fold_cf_spike` が 3 行を追加で出した時点。`cf_botnet_overlap`（`:1055`）は**含まない** — あれは別エンドポイント（`layer7/top/ases/origin`、`scoring.py:753`）の ASN 分布を要し、未取得のままである（別途 §7-2 に登録が要る）  **RETIRED（WP-4.1h、2026-08-09）— 3 行とも着地。** ラダーは `v3/runtime/spike.py` に転写し (`vector_shift_verdict` / `adversary_strike_verdict` / `coordinated_verdict` + `elevated_targets`)、`reduce_cyber::_derived_rows` が**サイクルごとに 1 組**出す。登録時の見立てどおり**追加取得は不要**だった（per-origin の `is_l7_shift` / `is_direct_strike` は丸め前の比が要るので `origin_spike` の中で決める形にした。`combined_sources` の所属判定 `core.py:806` だけは対象国の global target share を要するが、これは既に取得している `cf_l3` / `cf_l7` の `share_pct` である）。**per-scenario か per-country かの裁定**: **どちらでもなく countryless**。settle する行は `radar/routes/core.py:2039-2041` — `rat.sensor in FOCUSED_ONLY_SENSOR_NAMES` のときだけ国が付き、3 行はいずれも**シグナル名**で登録されるため `FOCUSED_ONLY_SENSOR_NAMES`（`radar/scenarios.py:75-79`）に一致せず、本番自身が countryless Signal を作る。`core.py:1075` の `source_country=_adv_top_actor` は反証にならない — この引数は `add_rat` 内の `classify_direction` と 2 つの context ヘルパ（`core.py:956-971`）が 消費するだけで `RationaleEntry` に届かず、CAC の direction confidence を飾るのみ（AST 実測）。したがって 3 行は `is_global` 観測として **S1-SCORE-012 で全シナリオから decouple され global envelope（×0.5）に入る** — 本番と同じ着地であり、しかも「シナリオを跨いだ誤帰属」が 構造的に起きない。**登録時の「cyber ドメインで最大 6 点」は誇張**だった: シナリオスコアに 効くのは 0 点（3 行とも countryless）、global envelope に効くのが最大 3 点 × 0.5 = 1.5。ただし `passes_gate()` は真になるので、`_coord_active`（`core.py:1076`）が門番をしている SYNC_DDOS 系列イベント（`core.py:1309`）への経路は復活する。検証: 差分掃引 3 seed × 4,000 ティック（本番の `core.py:737-919` / `:1063-1076` を独立に 再打鍵した実装と照合）、変異 **19/19 撃墜**。**掃引の設計自体が 1 つの発見を生んだ**（下記 §変異の項）。残余は #124 / #125 / #126 に登録。`cf_botnet_overlap` は本行の宣言どおり別行 **#122** に登録した |
| ~~122~~ | ~~`cloudflare_radar` — `cf_botnet_overlap` と IDF 相関ファミリ~~（**WP-4.1k で着地**） | **本番の 5 つ目の cyber 行と、それが読む相関量を v3 は一切持たない**。本番は対象国ごとに `attacks/layer7/top/ases/origin` を叩いて ASN 分布を取り（`radar/scoring.py:742-754`）、focused シナリオ参加国の総当たりペアで IDF 重み付き重なりを計算し（`core.py:838-861`）、`cf_botnet_overlap` を **0-2** で出す（`core.py:1042-1062`: IDF>=3.5 で 2、>=2.0 で 1、>=1.5 は FIRED だが 0）。さらに `high_correlation`（`core.py:918`、IDF>=1.5）は `cf_coordinated` と組んで **SYNC_DDOS 系列イベントの門**（`core.py:1309`）でもある。v3 は ASN 分布を**取得しておらず**、`correlations_idf` に相当する計算もどこにも無い | **insensitive**（v3 が低く出る = **C-02 / C-03 直撃の blocking 級**。global envelope で最大 2 点 × 0.5、加えて SYNC_DDOS 連鎖が一方の門から開かない） | **登録**（WP-4.1h、2026-08-09）。#121 の本文が「別途 §7-2 に登録が要る」と明記していた行を、その約束どおり起こしたもの。**#121 とは要件が違う** — あちらは既存の取得で足りたが、本行は `layer7/top/ases/origin` の**新規取得**（対象国ごと 1 本）と、IDF 重み・ペア総当たりという**シナリオ単位の計算**を要する。後者は畳み込み層（アダプタ単位・国単位）では書けないので、着地先は `cf_spike_core` と同じ形にはならない。**留意**: 本番のこの行も countryless（`cf_botnet_overlap` は `FOCUSED_ONLY_SENSOR_NAMES` に無い）なので、着地時の帰属は #121 と同じ裁定で足りる。**解消条件**: ASN 分布の取得 + IDF 相関の転写 + `cf_botnet_overlap` の 0-2 ラダー。**方向が insensitive である以上、cutover 前に本行の処分（実装 or オーナー受容）が要る** |  **RETIRED（WP-4.1k、2026-08-09）— 着地。ただし登録時の見立ての中核が誤りだった。** **追加取得は不要だった。** `correlations_idf_l3` に入るのは `origin_distributions_l3`（`core.py:853-855` → `:810` → `:785`）で、その鍵は `parse_origins`（`radar/scoring.py:659-668`）が返す**2 文字の攻撃元国コード**であり ASN ではない。`fetch_asn_origins` の ASN 分布は `core.py:751-754` の `state_asn_hits` — つまり #125(b) の `is_state_asn` 装飾 — にしか使われず、相関には 1 度も届かない。登録が「ASN 分布の新規取得が要る」と 書いたのは `compute_idf_weights` の docstring（"Build TF-IDF style ... for ASN keys"）を読んだためで、**docstring とデータ経路が食い違っている本番側の記述誤り**である。したがって本行は「取得の宣言」ではなく **純粋な転写**であり、材料は WP-4.1d 以降 `OriginSpike.origins[code]["l3_pct"]`（= `normalized_dist_l3[code]`）として v3 に既に在った。**実装**: `v3/runtime/correlation.py`（`idf_weights` / `overlap_idf` / `pairwise_idf` / `high_correlation` / `botnet_overlap_verdict`）＋ `reduce_cyber::_derived_rows` が**5 行目**を出す。**帰属は #121 と同じ countryless**（`cf_botnet_overlap` は `FOCUSED_ONLY_SENSOR_NAMES` に無い）。`v3/runtime/attribution.FAMILIES` のロスターには**入れない** — あれは「v3 が per-country で畳んでいる家系」の表で、本行は唯一の構築点が `country=""` なので `collapse` に動かすスコアが無い（`tests/test_v3_country_attribution.py` の 派生ロスターが空のままであることと、`A.collapse` が本行を素通しすることを実測）。**per-country 読者は増えても減ってもいない** — 入力は既存の `cf_spike_target` OBSERVED 行 （`flags["origins"]`）で、L7 だけに現れた攻撃元が `l3_pct=0.0` として載ることが載る条件である（0 を落とすと document frequency が下がり全重みが膨らむ。行は出続けるので外からは正常に見える形）。**SYNC_DDOS が到達可能になった（本 WP でいちばん大きい帰結）**: `core.py:1309` の 4 連言は `_overlap_active`（= `cf_botnet_overlap` が FIRED 非ミュート、status 自体が `high_correlation`）と `_coord_active` の 2 つに縮約されるので、`v3/runtime/events.py` に `Conjunction` を足して供給した。`chain_coverage()` は **2/4 → 3/4** になり、`SEQUENCE_MIN_CHAIN` が 3 なので **`chain_bonus_reachable` が 初めて True** になる。残る欠落は `NARRATIVE_BURST` のみ。**L3 のみ転写**（本番は 3 マップ作るが、`:918` と `:1042` が読むのは L3 だけで、他 2 つは `:2874` の API ペイロード専用 = v3 に読者が無い）。検証: 差分掃引 3 seed × 4,000 分布集合（`radar/scoring.py:679-736` と `core.py:917-918,1042-1062` を独立に再打鍵した実装と照合、**4 段すべてに到達したことを assert**）＋ 既存の畳み込み掃引 3 seed × 4,000 ティックに 5 行目を追加、変異 **29/29 撃墜**（spike 20 + correlation 9）。**新規登録 #133**（`calculate_overlap_idf` は plain set 上の浮動小数和なので本番の生の指数はプロセス間で bit 再現しない。v3 はソートする。丸め単位未満・中立）
| 123 | L2 系列連鎖に**イベントが 1 件も届かない**（**WP-4.1h で登録**） | **`ScoringInputs.arriving_events` を供給する呼び出しが v3 に存在しない**（`v3/scoring/inputs.py:432` の既定 `()` のまま、`v3/runtime/scoring.py::assemble` は設定しない。`prior_state` の `sequence_events` も同様に既定 `()` のまま呼ばれる）。本番は `_seq_fire` / `register_sequence_event` を 10 か所以上で呼び（`NARRATIVE_BURST` / `ISR_SURGE` / `SYNC_DDOS` / `FIRMS_ANOMALY` の 4 種、`core.py:1302-1320` 他）、連鎖が揃うと focused シナリオに加点する（S1-ANALYTICS の連鎖定義、窓 86400 秒） | **insensitive**（連鎖ボーナスが**構造的に 0 のまま**。カーネル側の状態機械 `v3/scoring/sequence.py` は完成していて入力が無いだけなので、テストは緑で検知だけが死んでいる — 本プログラム署名の欠陥形） | **登録**（WP-4.1h、2026-08-09）。#121 の `_coord_active`（`core.py:1076` の戻り値が SYNC_DDOS の門）を辿る過程で発見。**3 行を出した今も連鎖は動かない**ので、#121 の retire がこの穴を塞いだと読まれないよう別行にする。**解消条件**: 観測から連鎖イベントを起こす供給側（`passes_gate()` を述語とする、CLAUDE.md §5 のゲーティング規律どおり）が `assemble` の手前に入り、`arriving_events` が非空になった時点。**規律**: 供給側を持たない状態機械は「テスト済みで永久に沈黙」という WP-4.1d の `usgs_seismic` と同型なので、着地時は**合成ルート経由の供給テスト**を必ず書く  **範囲縮小（WP-4.1i、2026-08-09）— 供給側は入った。retire しない。** `v3/runtime/events.py` が本番の登録表を転写し、**生ティック（`scoring.assemble`）とパリティドライバの両方**が同じ関数で供給する（#38 の教訓: ハーネスが独自の入力を作れば、一致も不一致もハーネスが製造したものになる）。ゲートは CLAUDE.md §5 のとおり `passes_gate()`（FIRED かつ非ミュート、**score 条件なし** — `core.py:997`）。**形の裁定に従い `ScoringInputs.arriving_events` は既定値を廃した**: 供給を忘れると検知箇所の沈黙ではなく構築箇所の `TypeError` になる。イベントを持たない呼び出し側は `()` と**明示して**そう述べる。**もう半分の穴も塞いだ** — `run_tick` は状態を持ち越さないので、`prior.sequence_events` が `()` のままなら連鎖の記憶は 1 ティックしかなく、3 種類を 24h 以内に揃える連鎖は永久に成立しない。`scoring.sequence_history` が保持窓ぶんの L1 行から**再導出**する（L1 スキーマ変更なし、1 クエリ、再起動で答えが変わらない）。`occurred_at` は**観測自身のタイムスタンプ**で、`now` ではない — 在force のまま 4 ティック残る行が毎回新しいリンクを作ればdecay 項が永久に新鮮を報告する。同一値になるので `advance()` の 300 秒 dedup が畳む。**転写できたのは 4 連鎖種のうち 2 種**（`ISR_SURGE` / `FIRMS_ANOMALY`）。`NARRATIVE_BURST` は `rss_narrative` / `telegram_mirror` の畳み込みが OBSERVED 止まり（30 日ベースライン待ち、#9/#11 家系）、`SYNC_DDOS` は `cf_botnet_overlap` が無い（#122）。**したがって chain_bonus は依然として構造的に 0**（partial の最小は 3 種）。これは `events.chain_coverage()` が明示的に開示し、テストが `chain_bonus_reachable is False` を主張する — 「連鎖が動くようになった」と読まれないため。**live になったのは `temporal_coherence_bonus`**（2 国のイベントが 10 秒以内）。非連鎖種のうち `AIS_DARK_GAP` / `MIL_AIR_SURGE` / `GPS_JAMMING` / `CENSORSHIP_DETECTED`(OONI) も供給する（OONI は本番が `_ooni_heavy` で門を張るので score 2 の段だけ — ラダーと flag の等価を 4,000 件差分掃引で固定）。`NOTAM_SURGE` と tor+ihr の `CENSORSHIP_DETECTED` は**両系で source が disabled** なので parity 中立。**残余の方向**: `NARRATIVE_BURST` / `SYNC_DDOS` ともに **insensitive**。連鎖ボーナス（partial 2 / full 3 点）がcutover まで 0 のままである事実は #122 と本行の両方で追跡する。**新規差分 #128**（dual-core の primary→secondary spill を再現しない）。証跡: `tests/test_runtime_events.py`（43 件: 本番登録サイトの AST 全数照合・ゲート 6 件・帰属 5 件・両呼び出し側の同一供給・履歴・形の強制・開示・変異 5/5） |  **さらに範囲縮小（WP-4.1k、2026-08-09）— 4 種のうち 3 種が供給され、chain_bonus は構造的 0 でなくなった。** `SYNC_DDOS` は #122 の着地で入った。ただし形が他の 3 種と違う: 門は**countryless 2 行の連言**（`core.py:1309`）で、しかも `scenario_wide=True` なので `resolve_seq_fire_targets` は 1 国ではなく全 effective core を返す（`radar/scoring.py:117-124`）。行ごとの `Registration` として転写していれば、countryless 行は `countries` を 持たないため**存在してテストも通り永久に沈黙する**規則になっていた。`Conjunction` を別型にし、**同一ティック内**（`observed_at` が一致 — `v3/fetch/runner.py:562` がサイクルの `now` を全行に押す）でのみ 連言が成立することを強制した。保持窓ぶんを 1 回で渡す `sequence_history` の経路で、月曜の `cf_coordinated` と 火曜の `cf_botnet_overlap` が SYNC_DDOS を捏造しうる — 方向は sensitive で、連鎖に入った偽リンクは 本物と見分けがつかないので拒否した。`SUPPLIED_SOURCES` は `CONJUNCTIONS` から**導出**する（列挙のままなら「live では動くが次ティックで消える」形になる）。**残る欠落は `NARRATIVE_BURST` の 1 種のみ**、方向 insensitive、full tier（4 種）は依然到達不能
| 124 | `cloudflare_radar` — 派生 3 行の**適用範囲**（**WP-4.1h**） | **3 行がまたぐ対象国集合が「そのサイクルの参加国の和集合」であり、本番の「focused シナリオの `strategic_theaters`」ではない**（`core.py:604` = focused の全 participants）。影響は 3 行それぞれで違う: `cf_adversary_strike` は strike の母数が広がる（本番の `required_keys` は adversary role の participant を**対象から除く**〔`core.py:630-634`〕が、v3 は participants 全部を叩くので adversary 国自身も被攻撃対象になりうる）／`cf_coordinated` の `elevated_theaters >= 2` は**別シナリオの 2 国**でも成立しうる／`cf_vector_shift` の `core_shifted` は全シナリオの effective_cores の和集合に対して評価され、`primary_ec` も和集合上の 1 国になる | **sensitive**（v3 が高く出る）。ただし `cf_coordinated` の 1 件は**捏造アラームの形**であり、掃引の中では悪い方向に属する | **登録**（WP-4.1h、2026-08-09）。#118 / #119 と同じ「1 サイクルで全シナリオぶんを取得する」構造から出る差分。**緩和は構造的に効いている**: 3 行は countryless（#121）なので、どのシナリオのスコアにも帰属せず global envelope に入る。global envelope は定義上「特定の紛争についての証拠を持たない信号」の置き場なので、シナリオを跨いだ集計はそこでは誤帰属にならない。focus を見て取得内容を変えることは C-lite の再導入になるため採らない（#119 と同じ理由）。**解消条件**: 無し（設計上の相違として恒久登録）。開示: 3 行の flags に `targets_measured` / `effective_cores` / `primary_core` が載るので、どの集合の上で判定したかは行から読める  **範囲拡大（WP-4.1i、2026-08-09）**: #118 の retire により `cf_spike_core` も同じ countryless 家系に入ったので、本行は **4 行**を対象とする。あわせて #118 の残余だった **HOD 標本の記録範囲**を本行に移す — 本番の `record_hod_sample` は `strategic_theaters`（focused シナリオの参加国、`core.py:824-825`）に限るが、v3 は採点対象シナリオ参加国の**和集合**で記録する。方向は **sensitive**（より多くの国が自分の HOD 系列を持つ）だが、系列は per-country に閉じているのでシナリオを跨いだ誤帰属にはならない。**解消条件**: 無し（#124 本体と同じ設計上の相違） |  **範囲拡大（WP-4.1k、2026-08-09）**: #122 の着地により本行は **5 行**を対象とする。`cf_botnet_overlap` だけは広がりの方向が単調でない — `idf_weights` は比較対象国集合に scope されるので（`core.py:846-855`）、集合が広がるとペアが増えて `max` は上がりうる一方、document frequency も上がって 全鍵の重みが変わる。**ペア追加は sensitive、再重み付けは双方向**。行の flags に `correlation_targets` と `idf_weights_l3` を載せてどの scope で判定したかを開示する。**SYNC_DDOS の anchor 集合**も同じ広がりを持つ — 本番は focused シナリオの effective cores、v3 は採点対象シナリオの和集合（sensitive）
| 125 | `cloudflare_radar` — 派生 3 行の `confidence` と `is_state_asn` 装飾（**WP-4.1h**） | **(a)** 3 行の `confidence` は寄与ドラフトの最小値（`_min_confidence`）で、本番は `_sensor_conf(cf_sensor, sample_count=hod_n, baseline_samples=hod_n)`（`core.py:1024`、primary core の HOD 標本数に対するセンサー固有の信頼度カーブ）。これは既存の `cf_spike_core` にも当てはまる。**(b)** `cf_adversary_strike` の `is_state_asn=bool(state_asn_hits)`（`core.py:1075`）を v3 は渡さない。v3 は `attacks/layer7/top/ases/origin` を取得しないため `STATE_ASNS` 突合ができない | **中立**（(a) confidence は S1-SCORE の式で raw_score に掛からない。(b) `is_state_asn` は `classify_direction` の kwargs として `direction_confidence` にしか効かず、score には触れない — AST 実測） | **登録**（WP-4.1h、2026-08-09）。**(b) には本番側の欠陥が伴う**ので記録する: `core.py:1075` が読む `state_asn_hits` は `for t in required_keys:` ループ（`core.py:737-831`）の**漏出したループ変数**であり、`required_keys` は `set` なので「最後に回った対象国」の値が非決定的に入る。つまり本番のこの装飾は特定の対象国について何も述べていない。v3 は不在にする（誤った値を再現しない）。**解消条件**: (a) センサー信頼度カーブを v3 の畳み込みが持てるようになった時点。(b) #122 の ASN 分布取得が着地した時点 |  **解消条件の訂正（WP-4.1k、2026-08-09）**: (b) の解消条件は「#122 の ASN 分布取得が着地した時点」と 書いていたが、**#122 は ASN 分布を要さなかった**（相関は攻撃元**国**分布で回る）ため、この条件は成立しない。`attacks/layer7/top/ases/origin` は現在**どの登録行にも所有されていない**取得であり、(b) は独立した 解消条件を持つ: `STATE_ASNS` 突合のために v3 が同エンドポイントを宣言した時点。方向は中立のままなので優先度は上げない（本番側のこの装飾自体が漏出ループ変数を読んでおり、特定の対象国について何も述べていない）
| 126 | `cloudflare_radar` — 派生 3 行の**沈黙条件・順序・flags**（**WP-4.1h**） | **(a)** そのサイクルでどの対象国も現行の攻撃元分布を出さなかった場合、v3 は 3 行を**出さない**。本番は cf センサーが enabled なら常に OK/0 の 3 行を出す。**(b)** value 文字列に載る集合（`vector_shifts` / `elevated_theaters`）と `_adv_top_actor`（`core.py:1074` の `adversary_strikes[0]["actor"]`）は、本番では `set` 反復順に依存する**非決定的**な値である。v3 はすべてソートする。**(c)** `cf_spike_core` の `flags["origins"]` に per-origin の `local_pct` / `is_l7_shift` / `is_direct_strike` / `in_combined_sources` が増えた | **(a) 観測面 insensitive（採点中立 — 本番側も score 0）／(b)(c) 中立** | **登録**（WP-4.1h、2026-08-09）。(a) は per-country ループが「現行ペイロードの無い国に行を出さない」ことと同じ規律の適用で、「取得しなかった」を「静穏だった」と書かないため。(b) は再現性の改善であり、**本番の値を「規則」と称してはならない**（同点時の答えが本番には無い）。(c) は NP6 側の増分で、`is_l7_shift` は丸め前の比で決まるため行から再計算できない値である |
| 127 | **本番が countryless、v3 が per-country の 15 家系**（**WP-4.1i で登録** — #118 の retire が同型を掘り当てた） | 本番の `add_rat` 第 1 引数は 39 名のうち **27 名がシグナル名**で、`core.py:2039-2041` は `rat.sensor in FOCUSED_ONLY_SENSOR_NAMES`（12 名のセンサー名、`radar/scenarios.py:75-79`）のときだけ国を与える。つまり本番はそれら 27 行を **countryless Signal** として作り、`GLOBAL_SIGNALS_DECOUPLED` 既定 true の下で `compute_scenario_score` は `continue` する（`radar/scoring.py:1452-1453`）— **どのシナリオスコアにも 0 点**、global envelope に ×0.5 のみ。v3 はこのうち **15 家系に国を付けている**: `cf_bgp_hijack` / `ct_log` / `gdelt` / `gps_jamming` / `greynoise` / `ihr_delay` / `ihr_hegemony` / `ooni_censorship` / `peeringdb_ixp` / `rss_narrative` / `space_weather` / `telegram_mirror` / `threatfox` / `tor_metrics` / `travel_advisory`（うち `ihr_delay` / `ihr_hegemony` は adapter が disabled で当面到達不能） | **sensitive**（v3 が高く出る。本番 0 点に対し v3 は participant weight × score がシナリオに乗る） | **登録（要オーナー裁定、WP-4.1i、2026-08-09）— 既定で受容してはならない行**。#118 を覆した 2 つの論拠が**そのまま 15 家系に当てはまる**: (a) パリティゲートは `country` を保管行から読むのでこの差分を構造的に測れない、(b) Phase 9 が消した「全シナリオを汚染する定数の床」の再導入である。それでも本 WP で修正しなかったのは、countryless 化が **v3 のシナリオ別検知の大半を削る insensitive 変更**であり、畳み込み層の判断ではなくプログラム規模の裁定だからである。**代わりに測定可能にした** — `tests/test_v3_country_attribution.py` が本番側（AST）と v3 側（draft 構築の静的解決）を毎回突き合わせ、**この 15 家系ちょうど**であることを主張する。新しい per-country 行が countryless な本番行に対して増えれば CI が落ちる（#118 は「3 兄弟が countryless の中で 1 つだけ国を持つ」形で紛れ込んだ）。**解消条件**: オーナーが (i) 15 家系を countryless に揃える、(ii) 恒久差分として受容する、のいずれかを裁定した時点。**cutover 前に処分が要る**（C-02 / C-03 の判定が「本番が黙る場所で v3 が鳴る」量に依存するため）  **RETIRED（2026-08-09、オーナー裁定 (i)）— ただし 15 家系ではなく 9 家系だった。** 裁定前に停止条件（「本番の per-scenario 検知が別経路から来ているのか」の実測）を先に走らせ、**本番で `compute_scenario_score` に国付き Signal が入る経路は 4 つしかない**ことを全数列挙した: (1) `rationale_to_signal` — 国は `rat.sensor ∈ FOCUSED_ONLY_SENSOR_NAMES` の 12 名のときだけ（`core.py:2039-2041`。`RationaleEntry` は `source_country` を保持しないので `add_rat` の同名 kwarg は CAC 装飾にしか届かない）、(2) IODA per-country 注入（`core.py:2045-2065`、`signal_source="bgp"`）、(3) `llm_intel`（`core.py:2069-2082`、`intel_queue.get_active_rationale()` の `countries`）、(4) `bg_observer`（`core.py:2103-2113`）。`rationale` を作る入口は `add_rat` の 1 か所のみ（`core.py:972`）。**15 家系のどれもこの 4 経路に現れない** — `rss_narrative` だけは内容が `intel_queue.submit()`（`radar/sensors/rss_narrative.py:578`）経由で per-scenario に届くが、その Signal の名前は `llm_intel` であり、v3 も同じ経路を持つ（`v3/adapters/info/rss_narrative.py:536` の `ex.IntelProfile` → `v3/adapters/llm/extraction.py:380`）。よって停止条件は発火せず、裁定どおり整列した。  **さらに「15」は過大計上だった**。シナリオスコアを動かす述語は `country != ""` ではなく `Observation.admits()`（`v3/scoring/inputs.py:249` = FIRED かつ非 suppressed かつ score > 0）である。`greynoise` / `space_weather` / `peeringdb_ixp` は全構築点で `raw_score=0.0` の抑制器・在庫行、`rss_narrative` / `telegram_mirror` / `travel_advisory` は `_fold_named_sources` が OBSERVED 止まり（30 日ベースライン待ち）。**この 6 家系は国を持っていてもシナリオスコアに 1 点も入れていない**ので、そもそも帰属差分ではない（`cf_spike_target` をロスターから外した論拠と同一）。→ **#130 に移管**。  **着地（残る 9 家系）**: `v3/runtime/attribution.py` が **スコアだけを countryless 行へ移す**。per-country 行は国・status・suppression・flags をそのまま保ち、`raw_score` のみ 0.0 になり、元の値は `flags["country_score"]` に残る。これで `passes_gate()` は真のまま（系列イベントは死なない）、`admits()` だけが偽になる（シナリオスコアが 0 になる）。**行名を変えなかったのは意図的** — 列挙した per-country 読者（`baselines.previous_cycle` の tor/gdelt/ooni/gps/travel、`record.record_phase_samples` の gdelt DOW、`record._record_ct_log`、`suppression` の gdelt×openweather join、`events.arriving_from` の GPS_JAMMING、`conclusions/anomaly.novelty_counts` の FIRED 件数）は全て `(signal_source, country)` と flags で引くので、名前を変える方が壊れる面が広い。**1 行に畳むのは選好ではなく台帳の規則** — L1 は `(tick_id, sensor, signal_source, country)` で UNIQUE、`reduce._require_writable` は countryless 行を `(signal_source, "GLOBAL")` で数えるので、N 本の countryless 行は書けない。**畳む位置は suppression の後**（`tick.py::build_hooks.fold`）— `suppression.apply` は `severe_weather.get(draft.country)` を引くので、先に countryless にすると GDELT の天候抑制が黙って効かなくなる（本番は `core_theater` の天候で抑制する）。証跡: `tests/test_runtime_attribution.py`（38 件）/ `tests/test_v3_country_attribution.py`（ロスターは**空**、9 家系が畳み込み無しなら差分になることを反証テストで固定） |
| 128 | 系列イベントの dual-core spill を再現しない（**WP-4.1i**） | 本番の `_seq_fire` は `resolve_seq_fire_targets(_original_core_theater, effective_cores, ...)` を通り（`radar/scoring.py:94-127`）、dual-core シナリオでは `_original_core_theater` が空なので第 3 分岐が**全 effective core** を返す。したがって **primary の観測が secondary の連鎖にも登録される**。この関数の docstring 自身が「secondary へ登録すると、そのセンサーデータを一度も見ていない連鎖にfalse-provenance のイベントが付く」と書いて禁じているが、`if core_theater:` の判定が dual-core では偽になるため**ガードが自分の条件で迂回されている**（本番側の欠陥として記録する）。v3 は各国の**自分の観測**からのみ登録する | **insensitive**（v3 のイベント集合は本番の部分集合。dual-core シナリオの secondary で連鎖が短くなる） | **登録**（WP-4.1i、2026-08-09）。再現しない理由は NP1 より上位の規律 — 「センサーデータを見ていない国にイベントを付ける」は 2026-08-02 の calibration 事故（cross-scenario attribution）と同型であり、`project_calibration_degenerate` が「recall 異常が出たらまずラベル生成器を疑え」と記録した失敗の形そのもの。**解消条件**: 本番側のガード迂回が修正され、意図された帰属が確定した時点。証跡: `tests/test_runtime_events.py::TestTheEventBelongsToAnEffectiveCore::test_each_core_answers_for_itself` |
| 129 | **countryless 9 行の判定国の選び方**（**WP-4.1j**、#127 の着地から派生） | 本番は 15 家系すべてを **focused シナリオの `core_theater` 1 国**で判定して 1 行出す（`core.py:1128` gdelt / `:1189` threatfox / `:1391` greynoise / `:1498` ihr / `:1553` tor / `:1693` ooni / `:1804` gps / `:1836` ct_log — いずれも `<data>.get(core_theater)`）。v3 は 1 回の取得で全シナリオを採点するので focused が無く、判定国は **`EFFECTIVE_CORES`（採点対象シナリオの effective core の和集合、#124 と同じ集合）の中でその家系の読みが最大の国**、同点はソート順の先頭（`attribution.primary_core`）。これは本番が選ばざるを得ない分岐で使う規則そのもの（`core.py:878-881` の `max(effective_cores, key=avg_spike)`、未測定 core は 0.0 既定）を家系ごとの読みに読み替えたもので、和集合に測定済 core が 1 つしかなければ本番と同じ答になる | **中立〜sensitive**（行は countryless なのでどのシナリオスコアにも入らず、影響は global envelope の 1 行の値のみ。本番が focused の core を読む場面で v3 は和集合の最大を読むので、静穏な focused core と騒がしい別シナリオ core が同時に存在するとき v3 の envelope が高く出る。NP1 側） | **登録（WP-4.1j、2026-08-09）**。#124 と同じ「1 サイクルで全シナリオぶんを取得する」構造から出る差分で、緩和も同じ — countryless なのでシナリオ跨ぎの誤帰属にはならない。**開示**: 行の flags に `primary_core` / `countries_measured` / `effective_cores` が載るので、どの集合のどの国が判定したかは行から読める（NP6 は判定国の選択にも及ぶ）。**和集合に測定済 core が 1 つも無いサイクルでは行を出さない** — 本番はセンサーが enabled なら OK/0 行を出すが、測定していない core について「平穏だった」と述べる行は測定の不在と区別できない（`_fold_cf_spike` が同じ理由で同じ判断をしている）。score は両側 0 なので数値は動かない。**解消条件**: 無し（設計上の相違として恒久登録）。証跡: `tests/test_runtime_attribution.py::TestThePrimaryCoreRule`（4,000 件の差分掃引＋2,000 件の畳み込み掃引、独立に再打鍵した argmax と照合）|
| 130 | **本番 countryless・v3 per-country のうち、採点に到達し得ない 6 家系**（**WP-4.1j**、#127 から移管） | `greynoise` / `space_weather` / `peeringdb_ixp` / `rss_narrative` / `telegram_mirror` / `travel_advisory` は v3 側で国を持つが、**全構築点で `raw_score=0.0` か OBSERVED 止まり**なので `admits()` が真になる経路が無い。したがってシナリオスコアにも `active_countries`（収斂ボーナス）にも 1 点も入らない | **中立**（数値差 0。ただし L1 の行の見え方だけが本番と違う） | **登録（WP-4.1j、2026-08-09）— 是正しない**。countryless 化は数値を 1 も動かさない一方で、`suppression.read_suppressors` が `greynoise` / `space_weather` を**国ごとに**読み、`baselines.previous_cycle` が `travel_advisory` の前回レベルを国ごとに読むため、**読者を壊して何も直さない**変更になる。`cf_spike_target` をロスターから外した論拠と同一。**解消条件（＝再審査の引き金）**: これら 6 家系のいずれかが FIRED かつ score > 0 の分岐を得た時点で `tests/test_v3_country_attribution.py` が落ちる（ロスターが空でなくなる）ので、そのとき #127 と同じ処分を適用する。証跡: `tests/test_v3_country_attribution.py::test_the_six_measurement_only_families_are_left_alone` |
| 131 | **`ooni_heavy` — 本番に無い行名を 1 つ足した**（**WP-4.1j**） | 本番は CENSORSHIP_DETECTED を `_ooni_heavy`（bool、`core.py:1710`）で登録し、v3 は同じ条件を `min_score=2.0` として**スコアの段**で読んでいた。#127 でそのスコアが countryless 行へ移った結果、段が per-country 行から読めなくなる（`v3/scoring/inputs.py::Observation` は `flags` を持たない）。そこで段そのものを 1 行にした: `ooni_heavy`、FIRED / `raw_score=0.0`、heavy かつ元行が gate を通ったときだけ per-country に出る | **中立**（イベント集合は変更前と同一。`passes_gate()` は真・`admits()` は偽なので採点には一切入らない） | **登録（WP-4.1j、2026-08-09）**。本番に存在しない `signal_source` を L1 に足す判断は `cf_spike_target`（#118 の着地）と同型 — countryless 行が答えられない作業値に読者がいるとき、その値を**行として書く**のが v3 の唯一の伝達路だからである。**足さなければ何が起きたかを明示する**: per-country のスコアが 0 になった瞬間 `min_score=2.0` が永久に偽になり、CENSORSHIP_DETECTED が**テスト緑のまま消える** — 本プログラム署名の沈黙欠陥の形。**解消条件**: `Observation` が flags を運ぶようになったとき（そのときは条件を行ではなくフラグで読める）。証跡: `tests/test_runtime_events.py::TestTheOoniRungIsTheHeavyBranch`（4,000 件の差分掃引で `is_heavy` と段の一致を実測）/ `tests/test_runtime_attribution.py::TestTheReadersAreStillFed` |
| 132 | **9 家系は個別異常事象（ANOMALY）を出せない — code review が CRITICAL と呼び、実測で NEUTRAL と裁定した**（#127 の帰結、**WP-4.1j 後の code review 指摘**） | `attribution._face()`（`v3/runtime/attribution.py:288-301`）は 9 家系の per-country 行の `raw_score` を 0.0 にする。`Observation.admits()`（`v3/scoring/inputs.py:249` = `passes_gate() and score > 0`）はこれで偽になり、`build_contributions`（`v3/scoring/contributions.py:149`）は非 admit の観測を `Contribution` にする前にスキップするため、`ScoringResult.contributions` — したがって `ScenarioContext.contributions`（`v3/conclusions/context.py:91-92`）— にその観測は一度も現れない。`v3/conclusions/anomaly.py::derive`（`:145-149`）は `context.contributions` を走査して `raw <= 0` を弾くので、二重にこの観測を落とす。**結果、9 家系は per-country の個別異常事象に永久になれない** | **中立（v3 と本番が一致した、という意味で）**。**production で全く同じ限界を実測した**: `derive_anomaly`（`radar/conclusions/anomaly.py:187`、`if not state.contributions:`）は `state.contributions` を読み、それは `compute_scenario_score` が組む `deduped`（`radar/scoring.py:1555`）である。同関数 `radar/scoring.py:1447-1453` は `GLOBAL_SIGNALS_DECOUPLED` 下で国なし signal を `continue` で落とす。`GLOBAL_SIGNALS_DECOUPLED` は既定 `true`（`radar/config.py:421`）で `config.env` に上書きが無い（実機 grep で確認）。9 家系はいずれも countryless signal（§7-2 #127 の裁定そのもの）なので、**本番も同じ 9 家系の個別異常事象を出さない**。v3 が本番に合わせただけであり、新しい乖離ではない | **登録（NEUTRAL、WP-4.1j 後、2026-08-09）**。code review は本件を CRITICAL と分類したが、オーナーが本番を確認した結果 **差分ではなく登録**である。**レビューが提案した代替案（`derive()` が `flags["country_score"]` にフォールバックする）は採らない** — 採れば v3 は本番が構造的に出せない個別異常事象を出すことになり、#127 がちょうど閉じた敏感な乖離（本番が黙る場所で v3 が鳴る）を新しく開け直す。加えて実装上も筋が悪い: `Contribution`（`v3/scoring/contributions.py:35-57`）は `flags` を持たないフィールド構成なので、`derive()` 単独へのフォールバック追記では値そのものに手が届かず、`build_contributions` あるいは `admits()` まで遡って変更しないと機能しない。**「countryless signal がそもそも個別異常事象になれるべきか」という上位の問いは v3 の実装課題ではなく、cutover 後に現行系ごと問い直す設計課題**として **D2-defects.md §H の H-03** に既に記録済み（H-03 は本番の同じ 3 行 `radar/conclusions/anomaly.py:187` / `radar/scoring.py:1452,1555` を根拠に、27 家系が個別異常事象に構造的に現れないことを HIGH として記録し、「v3 側だけ変えない」と明記している）。**解消条件**: なし（本行は「解消すべき差分」ではなく「一致の記録」。H-03 の裁定が動けばそちらから波及する）。証跡: `tests/test_runtime_attribution.py::TestNoIndividualAnomalyForTheNineFamilies`（実際に `tick.run_tick()` を走らせ、`threatfox` 家系の FIRED・スコア付き・参加国一致の観測が `taiwan_contingency` の ANOMALY 結論に一度も現れないことを実測。`ripe_atlas`（帰属を動かされない家系）が同じティックで ANOMALY に現れることを陽性対照として同時に主張。加えて `attribution.collapse` を経由しない同一ペイロードが `build_contributions` で 1 件の寄与を作ることを反証として実測し、消えたのが collapse の効果であることを示す）。フォールバックが将来どの層に足されても、本テストは最終結果（ANOMALY 結論の集合）を見ているため落ちる |
| 133 | `cloudflare_radar` — IDF 指数の浮動小数和がプロセス依存（**WP-4.1k で登録**） | `calculate_overlap_idf`（`radar/scoring.py:729-732`）は `set(dist1) | set(dist2)` を**そのまま反復**して 重み付き交差を合計する。浮動小数加算は結合的でなく、CPython の `str` ハッシュはプロセスごとに異なるので、**本番の生の指数は自分自身に対しても再起動をまたいで bit 再現しない**。v3 はソートして反復する | **中立**（差は `round(num*100, 2)` の丸め単位を下回る。3 seed × 4,000 の差分掃引で判定〔fired / score〕の 不一致はゼロ、指数は `abs=0.01` 以内で一致） | **登録**（WP-4.1k、2026-08-09）。理論上は丸め後の値が 閾値（1.5 / 2.0 / 3.5）にちょうど乗る入力で判定が割れうるが、掃引では 1 件も観測されていない。**解消条件**: 無し（v3 側の再現性改善として恒久登録。本番の値を「規則」と称してはならない — #126(b) と同型）|
| 134 | `ripe_bgp` — warm-up 中の BGP anomaly 判定（**#9 から分割、2026-08-09**） | **同時刻標本が 7 件未満の間、v3 は `:1148` のスコア幅（0-1）を出さない。本番は出す。** 本番の fallback は `self._baseline[code]` — **プロセス内に持たれ、毎時リセットされ、`baseline_refs` にも載っていない**揮発ベースライン（D2 A-03 そのもの）。v3 がこれを再現するには、台帳に無く再起動で消える量を発明することになり、それは NP6（導出の開示）と R1（データ連続性）の両方に反する。**#9 の残余はこれ 1 件であり、原因は #9 の主題（L1 ベースライン供給の未配線）とは別物**である — ベースラインは既に配線済で、欠けているのは配線ではなく**裁定**である | **insensitive**（本番が出すスコア幅を v3 が出さない。warm-up は再起動直後と新規シナリオ登録直後に必ず通る局面であり、「まれ」ではない） | **オーナー裁定待ち（cutover 阻害を #9 から継承）**。選択肢は 3 つ: **(a)** 本番の揮発ベースラインを v3 でも再現する（A-03 を移植する = 診断が欠陥と認定したものを新系に持ち込む）／**(b)** 差分として受容し、warm-up 中は判定を保留する現状を恒久登録する（insensitive を承知で残す = NP1 に対する明示的な譲歩）／**(c)** warm-up 中の代替判定を v3 独自に設計する（本番に無い挙動 = 未登録差分ではなく**新規の登録差分**として、sensitive 方向で立てる）。**推奨は (c)** — (a) は欠陥の移植、(b) は NP1 が最も嫌う「見逃しの受容」であり、(c) だけが台帳に載る形で感度を保つ。ただし (c) は「本番に無い挙動を v3 が持つ」ことを意味し、パリティ計測に現れる差として**オーナーが承認すべき**判断である。**解消条件**: 上記いずれかの裁定が下り、実装と登録が一致した時点 **裁定（オーナー、2026-08-09）— (c) 採択。本行は CLOSE、v3 独自挙動は #135 として立てる。** (a) は「診断が欠陥と認定したもの（A-03）を新系に移植する」ため退けた。(b) は「見逃しの受容」であり NP1 が存在する理由そのものを裏切るため退けた。warm-up は稀な局面ではない — 新規シナリオ登録のたびに必ず通る。**実装**: `verdicts.bgp_warmup_verdict`（純関数）＋ `store.baseline_series_values`（`baseline_phase_values` から phase 述語だけを外した読み）＋ `baselines.pooled_history` / `POOLED_PHASE_READS`。**台帳から導出しており、プロセス内状態を一切増やしていない**（`tests/test_v3_bgp_warmup.py::TestTheSupplyIsL1::test_the_verdict_survives_a_restart_because_the_store_does` が再起動を跨いで発火することを実証 = A-03 の再実装ではない）。本行は「裁定により閉じる」であり「完了により閉じる」ではない — 差分は消滅せず、**#135 として形を変えて登録簿に残る** |
| 135 | `ripe_bgp` — warm-up 中の pooled-series 判定（**v3 独自挙動、#134 の (c) 裁定により新設、2026-08-09**） | **同時刻標本が 7 件未満の間、v3 は本番が持たない経路で `:1148` の判定に到達する。** 本番はこの局面で `drop_ratio > 0.15` を使い、その `drop_ratio` はプロセス内・毎時リセットの `self._baseline[code]`（A-03）を基準にする。v3 はこれを移植せず、**同じ `bgp_hod` 台帳の行を hour-of-day 述語なしで読む**（`store.baseline_series_values`）。`bgp_hod` は 1 時間に 1 バケットなので、同時刻系列が 7 標本に達するのに **7 日**かかるところ、系列そのものは **7 時間**で達する — その間を埋めるのが本判定である。**統計**: pooled Z（分散は n 除算、標準偏差フロア 1.0 — 本番と同一）が **-3.0 未満**、**かつ** pooled 平均に対する相対低下が **0.15 超**（本番 `BgpRoutingSensor.BGP_DROP_THRESHOLD`、本番がまさにこの分岐で使う定数）。両方を要求する連言は本番自身の形（`checkhost_status` — 「Z 分岐は絶対値も悪いことを追加で要求する」）に倣う。**閾値を -2.0 から -3.0 へ広げた理由は測定済**: pooled 分散は σ_a²=σ_w²+σ_b² であり、当該時刻が平常時に低い時間帯だと日内オフセット d_h が Z を押し下げる。σ_w=σ_b なら**完全に平均的な読み（z_hod=0）ですら z_pooled≈-0.71** になり、-2.0 のままでは warm 経路より**先に**発火する。**スコア幅は本番のまま 0-1**（`verdicts.BGP_ANOMALY_SCORE=1.0`、`core.py:1148`）— 経路は違ってよいが尺度は発明しない | **sensitive**（本番が出さない局面で v3 が発火しうる。**パリティ計測には不一致として現れる。これは想定内であり、抑止せず開示する**） | **恒久登録（解消条件なし）**。これは配線待ちでも移行途上でもなく、**オーナーが承認した v3 の設計判断**である。本番側に対応物が生まれない限り retire されない。**規律 3 点**: (1) **cold start は合成しない** — pooled 標本が 7 未満（新規台帳を含む）なら `hod_verdict = pending_l1_bgp_hod_cold` で保留し、`is_anomaly` は**キーごと不在**にする（G-17: 空のキャッシュが平穏な世界に読めてはならない。warm 経路の `pending_l1_bgp_hod` とは**別の文字列**であり、「同時刻 7 標本待ち」と「あらゆる時刻で 7 標本待ち」を 1 つの沈黙に潰さない）。(2) **warm 経路が答えられる時は warm 経路が勝つ** — 本判定は `stat.valid` が False の時だけ走る。(3) **warm 経路より緩くなってはならない** — 4,000 世界の差分スイープで、同時刻標本 7 件以上の世界において本判定が warm 経路より先に発火する事例が **0 件**であることを実測（`TestTheWarmupRuleIsTheStricterOfTheTwo`）。**恩恵も実測**: warm 経路が保留になる 8〜160 時間の世界 4,000 件で、真の崩落の **50% 超**を捕捉する（従来はそのすべてが保留 = 見逃し）。**台帳依存の証明**: 新規 baseline 名を増やしていない（`bgp_hod_pooled` は同一 `baseline_id` の第 2 の**読み**であり第 2 の**依存**ではないため `baseline_refs` / `supplied_names()` / `coverage()` のいずれにも入れない — 入れれば 1 つの依存を 2 重計上して family が実際より未完に見える）。**重大な併発所見（本行の前提を無効化しうる、別途裁定を要する）**: 判定対象の量そのものが**本番・v3 双方で死んでいる**。RIPE の `country-routing-stats` は `v4_prefixes_ris` / `v6_prefixes_ris` / `asns_ris` を返し、**`announced_prefixes` というキーを返さない**（当日実測）。本番 `bgp_routing.py:52` の `latest.get("announced_prefixes", 0)` は恒久的に 0 を読み、**稼働 DB の `bgp_hod` 全 5,398 行（8 か国 × 672 バケット窓）がすべて 0.0**。したがって本番の Z は `(0-0)/max(0,1.0)=0.0`、drop_ratio も 0.0 で、**本番の 2 分岐とも到達不能**である。v3 は同じ読みを転写しているので**パリティは保たれ、欠陥は本番側**。ここで v3 だけ別の量を読めば「測る対象」の未登録差分になり、かつ移行済 `bgp_hod` 系列を別物で汚染するため、**修正せず所見として登録する**。`tests/test_v3_bgp_warmup.py::TestTheMeasuredQuantityIsDead` が pin しており、キーを直した者は必ず本行に到達する。**証跡**: `tests/test_v3_bgp_warmup.py`（40 件、うち差分スイープ 2×4,000 世界・性質検査 1×4,000 入力・ミューテーション **29/29 検出・生存 0**）  **追補（2026-08-09、D2 H-05 の修理）— 併発所見は RESOLVED、本行は存続、ただし射程が狭まった。** 上に「修正せず所見として登録する」と書いた量の死は**修理した**（§7-2 #136）。本行が判定する対象は今や実測値であり、`TestTheMeasuredQuantityIsDead` は `TestTheMeasuredQuantityIsAliveAgain` に置き換えた。**射程の変化**: `scripts/backfill_bgp_hod.py` は監視対象 27 か国すべてに hour-of-day バケットあたり 28 標本を入れる（`HOD_MIN_SAME_HOUR` = 7 の 4 倍、24/24 バケットが warm、実測）。したがって**現在監視している国について本行の経路は走らない** — warm 経路が答えられるとき warm 経路が勝つ、という規律 (2) がそのまま効く。**それでも retire しない。本行が支えているのは「7 日の盲窓」ではなく「ゼロからの立ち上がり」だからである**: (a) **バックフィル後に登録された新規シナリオが連れてくる新しい国**は台帳に履歴を持たない — 同時刻系列が 7 標本に達するのに 7 日、系列そのものは 7 時間。埋めるのは依然として本行である。(b) バックフィルは**運用手順であって構造的保証ではない**。新環境・移行し直し・バックフィルを走らせ忘れた配備では warm-up がそのまま初期状態になる。(c) 規律 (1)（cold start を合成しない）は本行の中で最も重要な部分であり、標本が 7 未満なら `pending_l1_bgp_hod_cold` で保留する — バックフィルの有無に依存しない。**派生する運用要求（本書のスコープ外、要起票）**: シナリオ登録フローが新規参加国について `scripts/backfill_bgp_hod.py --countries <新規国>` を走らせれば、(a) の盲窓も構造的に消える。現状はアナリストが手で走らせる必要があり、**走らせなかった場合に静かに感度が落ちる**（本行があるので「無音」にはならないが、warm 経路より緩くはならない） |
| 136 | `ripe_bgp` — **判定対象の量そのものを選び直した（D2 H-05 の修理、両系同時、2026-08-09）** | **本番が一度も成功して読めなかった量を v3（と本番）が読むようになる。** RIPE の `country-routing-stats` は `announced_prefixes` / `seen_ases` を返さない。本番 `bgp_routing.py:51` はそれを `.get(key, 0)` で読んでいたため `pfx_now` は恒久的に 0 で、**稼働 DB の `bgp_hod` 全 5,398 行（19 か国、うち 8 か国が 672 バケット窓を充填）が 0.0**、Z も drop_ratio も trend も全分岐が到達不能だった。v3 は同じ読みを転写していたのでパリティは保たれていた。**量が一度も解決していない以上、忠実性の陰に隠れる余地は無い** — 量は選択であり、登録を要する。**採択**: プレフィックス数 = `v4_prefixes_ris + v6_prefixes_ris`、AS 数 = `asns_ris`。**(a)** `_stats` 系は**レジストリ視点が使えないとき -1 をセンチネルとして返す**（実測: サンプルした全か国・全エントリで `v4_prefixes_stats: -1`）。センチネルを数値として読むのは H-05 の罠を 1 段上でやり直すこと。**(b)** v4 のみでは **v6 単独の撤回**を見逃す。NP1 はそれを許さない。**(c)** 欠測は `None` → NO_DATA であって 0 ではない（`.get(key, 0)` が「未回答」を「経路 0 件」に翻訳したことが H-05 そのもの）。**同時に `starttime` を送るようになった。これも量の一部である**: `starttime` 無しの問い合わせは 2004 年以降の全系列を `resolution: 1w` に自動ダウンサンプルして返すので `stats[-1]` は最大 6 日古い**週次**値になり、それを毎時バケットに書くと同一値が約 168 バケット続いた末の段差を Z が百シグマ級として読む。4 日窓は `1h` で返る（一時点の実測、2026-08-09: 4/8/16/20/24/28 日はすべて `1h`、29 日で `1d` に切り替わった。upstream のダウンサンプリング仕様がその観測時点でそうだったというだけで、恒久的な保証ではない）ので `STATS_WINDOW_DAYS = 4` を両系に置き、v3 は `{since_iso}`（`v3/runtime/expansion.py` が adapter 自身の定数から供給）で表現する。**trend も同じキーで死んでいた**ので同時に修理し、RIS 視点を持たないエントリは**0 にせず落とす** | **sensitive**（本番も v3 も、これまで一度も発火し得なかった行が発火し得るようになる。方向は NP1 側であり #1〔gps_jamming〕の前例と同型 — 「本番も同時に修正済みなので、修正後データで窓を取れば差分は消える」）。**ただし量そのものの誤差方向は「本番 = 恒久 0」対「v3 = 実測値」であり、修理前の窓で採ったパリティ計測は本行について無意味**。修理を跨ぐ窓は破棄すること | **登録（2026-08-09）。解消条件: 本番・v3 双方が修理済のデータで 1 窓（28 日）を採り終えた時点で retire 候補**。**系列エポックは同一変更で実施した** — `scripts/backfill_bgp_hod.py` が RIPE の実履歴で `bgp_hod` を作り直す。**D2 の当初の見立ては方向が逆だった**: 「最初の正常な観測が最大級の偽陽性として発火する」ではなく、0 を混ぜると平均が全実測値より下に引きずられるので真の撤回は**大きな正の Z** になり drop_ratio も 0 にクランプされる — **発火するのではなく沈黙する**。F-16 の系列断絶という形は同じだが方向は insensitive で、NP1 が最も嫌う側である。結論（「キー修正と系列リセットは同一の変更で行うこと」）は変わらず、理由がより強い。**バックフィルの実測**（本番 DB のコピーに対する試行、コンテナ内で `mode=ro` に対し SQLite backup API で取得）: 27 か国 × 672 バケット = **18,144 行**、hour-of-day バケットあたり **28 標本**（`HOD_MIN_SAME_HOUR` = 7 の 4 倍）、**24/24 バケットが warm、短いバケットは 0 件**、**5,398 件の死んだ 0 行を削除**、**54 リクエスト / 416 秒**（3 秒間隔、14 日窓 × 2）。再実行は冪等（同一国の再走で行ハッシュ不変・削除 0）。**RIPE の系列は run-length encoding である**という実測が本作業の中核の発見: `stats` 1 エントリ = 1 **値**であり 1 時点ではない。`timeline` がその値の成立した**全区間**を列挙するので、`timeline[0].starttime` だけを読むと 4 日窓で約 50 点の不規則系列になり、**後続区間の時間帯が最初の区間の時間帯に誤って記帳される** — hour-of-day ベースラインにとっては「そのバケットが自分の時間帯を測っていない」ことを意味する。展開すれば毎時 1 点・欠落 0・重複 0（実測: 14 日窓 = 336 時間、サンプルした全か国で gap 0）。**証跡**: `tests/test_bgp_prefix_quantity.py`（52 件、うち本番 × v3 の差分掃引 3 seed × 4,000 入力、変異 **7/7 撃墜**）、`tests/test_v3_bgp_warmup.py::TestTheMeasuredQuantityIsAliveAgain`。**fixture が欠陥を隠していた**: `country_routing_stats.json` は `announced_prefixes` を中心に手書きされた架空のスキーマで、移植先が欠陥を再現しつつ自分のテストに通った理由がこれである。実捕捉レスポンスに差し替えた  **掃引が実際に 1 件見つけた（本行を書いている最中に）**: 数値**文字列**（`"9601"`）に対し、本番は「int/float でなければ None」と厳格に拒否し、v3 は `as_float` が強制変換して 9601.0 を読んでいた — **同じバイト列から 2 系が違う数を読む**、すなわち「1 つの規則の 2 つの転写が静かに 2 つの規則になる」形であり、H-05 と同族である。生成器が数値文字列・NaN・Inf を作るまで**見えなかった**。両系の強制変換を `as_float` に揃えて解消（bool 拒否 / NaN・Inf 拒否 / 数値文字列は受理 / 負値は不在）。修正前の本番側強制変換に対して掃引は 12,000 入力中 **2,266 件**の不一致を出す（実測）ので、本掃引は装飾ではない  **解像度ガードを両系に置いた**: RIPE が `1h` 以外で答えたとき、本番は `STALE_RESOLUTION` を返して**記録も採点もせず**（測定値は開示する）、v3 は `announced_prefixes` フラグ自体を落とす（`record_phase_samples` も L2 の fold も同じ鍵で読むので、書き込みと判定が 1 か所で同時に止まり、どちらの層にも「覚えておくべき分岐」が増えない。`hod_verdict = withheld_resolution_not_hourly` が沈黙に名前を付ける）。**仮想的な上流変更への防御ではなく、自分たちの `starttime` を失う退行への防御である** — `starttime` が消えれば応答は `1w` に戻り、672 バケットが同一の週次値で埋まる。バックフィル側の同じガードは `fetch_window` の `ResolutionTooCoarse`（窓を半分にして再試行、`MIN_WINDOW_DAYS` = 2 まで）  **バックフィルが 3 つ目の同型欠陥を掘り当てた（実測、K02 × H-05）**: RIPE は**認識できない国コード**に対し HTTP 200 / `status: ok` / `resolution: 1h` で答え、`v4_prefixes_ris: 0` / `v6_prefixes_ris: 0` を**全時間について**返す（`resource=ZZ` で実測）。すなわち `--countries` の打ち間違い 1 つで、**本作業が消しているのとまったく同じ 672 行の捏造ゼロ**がその国に入る。K02（拒否されたリクエストが 200 と空 body で「測ったが何も無い」に読める）と H-05 が同じ場所で交差する形である。`AllZeroSeries` で拒否する — 「ゼロを 1 つも含まない」ではなく「**全標本がゼロ**」を条件にする（KP は正当に 3〜4 を報告する）。28 日間ほんとうに 0 件だった国が在るなら、それは最大級の経路異常であり、ベースラインではなくアナリストが要る  **「バックフィルが書く量 = ライブが読む量」の直接実測**: 本番が読む 4 日窓と、バックフィルが使う 14 日窓を同時刻に取得して展開し、**重なる 95 時間すべてで値が一致**（不一致 0、最新値も一致）。窓長は解像度が `1h` である限り値を変えない — ベースラインと読みが別物を測るという H-05 の族を、文書ではなく測定で否定している |

---

## 8. 裁定要求

以下 13 件は本書の権限を超える。**各件に推奨を付す**。（1〜4 は 2026-08-07、5〜8 は WP-2.6 remediation で追加、9・10 は WP-2.7 実装中に追加、11 は WP-3.3 で追加、いずれも 2026-08-08。**9・10・11・12・13 は裁定済み**。11 はオーナー裁定により**推奨 (a) を採らず保存**、稼働系への修正は cutover 後 — D2 に 1 件を owe している）

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

### 裁定要求 11 — Defer は構造的に機能していない（S1-CALIB-054 / DP6、HIGH）

**問題**: snooze 復活は `state_changed_at` を基準に `pending` へ戻すが **`emitted_at` を更新しない**。
自動 dismiss（S1-CALIB-053 の実行可能型フック）は `emitted_at` を基準に判定する。既定値は
snooze 30 日 = stale 30 日なので、**Defer した提案は復活直後の次ティックで必ず
`auto:timeout_no_action` になる**。アナリストから見れば「保留」は「30 日後の却下予約」と同義であり、
UI にはその区別が出ない。

**現状**: WP-3.3 は本欠陥を**そのまま移植した**（§7-2 #82）。`v3/calibration/lifecycle.py::
defer_survives_revival` が「復活後の最初の評価で生き残るか」を計算し、全型で `False` を返す。
S1-CALIB-054 が「この相互作用は未検証」と記すとおり本番にテストは無く、
`TestDeferIsStructurallyBroken` が初めてこれを pin した。境界は等号なので**復活の瞬間だけ生存**する
（`revival_boundary_is_equality`）— これが欠陥を見落としやすくしている実態でもある。

**なぜ本書の権限を超えるか**: 条項の分類は **DEFECT-PRESERVE** でありながら注記は「**現行系でも要修正**」。
港で黙って直せば本番との差分（提案が 30 日を超えて生き残る = パリティ窓で mismatch）になり、
黙って残せば欠陥が二重化して修正コストが倍になる。どちらも移植者が単独で選ぶ判断ではない。

**推奨 (a) — 両系同時修正**: 復活時に `emitted_at` を復活時刻へ進める（＝ staleness 時計を再始動する）。
Defer の意味が「30 日後にもう一度見る」になり、UI の語と一致する。パリティ窓では
「本番で消えた提案が v3 で残る」差分が出るため、修正は**本番先行 → v3 追随**の順で行う（§7-2 の標準規律 (a) 側）。

**推奨 (b) — 語を実態に合わせる**: 状態名を `snoozed_30d` から変えず、UI 文言を
「30 日後に自動却下」に改める。修正コストはゼロだが、状態機械の意味は壊れたまま残る。

**推奨は (a)**。NP7（組織内ノード）は「シナリオ登録判断はアナリスト組織側が行う」と定めており、
提案の保留はその判断プロセスそのものである。保留が黙って却下になる仕組みは、
ツールが組織の判断を上書きしている状態にあたる。

> **裁定（オーナー、2026-08-08）— 推奨 (a) は採らない。本番も直さず、保存・登録し、cutover 後へ回す。**
>
> 理由は 3 点:
> 1. **パリティ窓が 2026-09-05 に開く**。較正ライフサイクルの変更は、後日のパリティ差分を
>    「どちらの変更が原因か」に帰属できなくする典型例であり、ADR-V3-006 のベースライン保存論理に反する。
> 2. **欠陥の作用方向が保守側**である。Defer が Dismiss として振る舞う＝提案が適用されずに落ちる、
>    であり、較正災害 3 件を生んだ層においては安全側に倒れている。
> 3. **A6 / H-2 / H-4 と同じ扱い**である（欠陥を保存し、登録し、cutover 後に本番側で処置）。
>
> **実装側の措置（WP-4.1f、実施済）**: §7-2 #82 として登録済のものを維持し、
> `tests/test_api_proposals.py::TestTheDeferDefectIsPreservedNotFixed` が
> 「黙って直す」ことを失敗させる（30 日窓の等値・`defer_survives_revival` の False・
> C5 の defer が保存された辺に着地することの 3 点を pin）。
> P7 C5 の `defer` ハンドラ docstring にも裁定を明記した。
>
> **稼働系に負っているもの**: 本欠陥は **D2（現行系の欠陥台帳）に 1 件のエントリを owe している**
> （裁定要求 8 の誤帰属ハザードと同じ扱い）。cutover 後に本番側で `emitted_at` を復活時刻へ
> 進める修正を行い、その時点で本項を retire する。**修正は cutover 後であり、パリティ窓の内側では行わない。**

### 裁定要求 12 — refresh token の輸送（§7-2 #103、**cutover 阻害**、CRITICAL） 〔**裁定済み 2026-08-08 — 推奨 (a) 採択・実装完了。§7-2 #103 は RETIRED、cutover 阻害はゼロ**〕

**事実**: v3 の C13 は refresh token を応答本文で返す。本番 (S1-SVC-004 / S2-API-010 / S1-UI-002) は
本文に載せることを **MUST NOT** とし、httpOnly + SameSite=Strict + `/api/auth/refresh` へパス限定した
cookie で発行し、非 httpOnly の対 CSRF cookie を SPA が `X-CSRF-TOKEN` へエコーバックしない限り
refresh を拒否する。S1-UI-002 はこれを **CORE**（XSS による refresh token 窃取を構造的に塞ぐ）と判定している。

**なぜこうなったか**: 設計判断ではなく輸送層の不在である。v3 の面は
`ApiRequest(method, path, params, body, principal, client_ip)` であり、クッキーという概念を持たない。
`v3/api/binding.py` だけが Flask を知る唯一のファイルで、そこに cookie 面はまだ無い。
本文で返す形は**セキュリティ軸で insensitive**（本番より弱い）であり、
これは本 WP が登録した 9 件のうち唯一の cutover 阻害項目である。

**選択肢**:
- **(a) cookie 面を `v3/api/binding.py` に足す（推奨）**。`Route` に「この応答は cookie を設定する」を
  宣言させ、binding がそれを Set-Cookie に翻訳する。CSRF は refresh の 1 経路だけに要る
  （access token は Authorization ヘッダで運ぶため構造的に CSRF 免疫）。本番と同形になる。
- (b) 本文のまま、refresh の寿命を大幅に短縮して被害窓を縮める。**非推奨** — 窃取を防ぐのではなく
  窃取後の時間を削るだけで、S1-UI-002 の CORE 判定に応えていない。
- (c) refresh を持たず access token のみ（寿命を延ばす）。**非推奨** — 失効性がさらに悪化する。

**推奨**: (a)。**cutover 前に必須**。着地までは v3 UI を本番相当のネットワークに出さないこと。

### 裁定要求 13 — 未裁定インテルを採点するか（§7-2 #105、HIGH） 〔**裁定済み 2026-08-08 — オーナー裁定により推奨 (a) を退け (b) を採択。§10 の裁定 7 が正**〕

**事実**: WP-2.7 の O-17 着地により、v3 では LLM インテルが L1 の通常観測として落ち、
**裁定を待たずに採点される**。本番は `auto_confirmed` / `confirmed` のみが収斂に入り、
`pending` は入らない。WP-4.1g で入った `reject` は、この既定に対する唯一の減算レバーである。

**方向**: v3 の方が多く採点する = **sensitive**（NP1 側）。ただし LLM 抽出の誤りが
そのまま結論に入る経路でもあり、較正事故 3 件がすべてラベル汚染だったことを踏まえると、
「人が見る前に採点に入る自動生成の主張」は精度側のリスクを持つ。

**選択肢**:
- **(a) 現状維持（推奨）**。NP1（見逃しは誤検知より悪い）に整合し、`reject` が事後の減算を提供する。
  インテル由来の寄与は `signal_source="llm_intel"` で L2 のゲートに識別されており、
  収斂の重みづけはそこで扱える。
- (b) 本番に合わせ、confirmed のみ採点。**アナリストが見るまで結論が出ない**ため、
  NP5+8 の「データ蓄積後の恒常的結論不可は設計失敗」に触れやすい。
- (c) pending を減衰つきで採点（半分の重み等）。新しい魔法数を 1 つ増やす。

**推奨**: (a)。ただし本項が**登録済みの sensitive 差分**であることを parity 窓で明示的に読むこと。

> **オーナー裁定（2026-08-08）**: **(a) を退け (b) を採る**。理由は 3 つ。
> (1) キューの状態は「未裁定の LLM 出力はまだ証拠ではない」という理由で存在しており、
> それを採点することは**仮説を所見として発表する**ことに等しく、NP6 の規律を反転させる。
> (2) NP1 上は安全側であっても、v3 側だけの追加行は**一致率を汚し**、parity 窓で
> 見るべき本当の差分を見えにくくする。
> (3) 機構は既にある — C3 の `reject` は `observations_at` に読み手を持っているので、
> 必要なのは**述語の変更**（本番が採点する状態だけを採点する）であって新しい機構ではない。
> **実装は §10 の裁定 7**。なお (b) の全部は取れない: v3 に `auto_confirmed` 段は無く、
> それを作ることは選択肢 (c) が退けられたのと同じ「新しい魔法数」になる。
> よって v3 は `confirmed` のみを容れ、**残差（本番より少なく採点する insensitive 方向）を
> §7-2 #105 の範囲縮小として登録する**。


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
| 8 | **裁定要求 12 — 推奨 (a) を採択し、本 WP で実装した**。cookie 面は束縛／ディスパッチャ層に置く（ハンドラは型付き要求から型付き応答への関数のまま — それがサーバ無しで試験できる性質そのもの）。CSRF の対は**ルート宣言で構造的に強制**し、ハンドラの検査には落とさない: `CookiePolicy` は `presents` を持ちながら `csrf=False` である状態を構築時に拒否する。姿勢は条項からの転記ではなく `radar/auth.py` と `flask_jwt_extended` の **AST 実測**で一致させ、差分（名前・パス・CSRF の導出）は #109 / #110 に登録した | 裁定要求 12。**§7-2 #103 RETIRED — 本プログラムの cutover 阻害はゼロになった**。証跡: `tests/test_api_cookies.py`（34 件、うち mutation 1 本） |
| 9 | **裁定要求 13 — オーナー裁定により推奨 (a) を退け (b) を採択**。採点は**裁定状態**でゲートする（明示的 reject だけではない）。本番が容れる状態は AST で実測して一致させる = `{auto_confirmed, confirmed}`。v3 は `auto_confirmed` 段を持たないため `confirmed` のみを容れ、**残差は insensitive 方向として §7-2 #105 に登録**する。述語は 1 本（`scoreable_rows`）で、live ティックと parity の**両ドライバ**が呼ぶ | 裁定要求 13。理由は §8 の裁定ブロック。証跡: `TestOnlyAdjudicatedIntelIsScored`（mutation 2 本）/ `TestTheAdmittedSetIsProductions` |
| 10 | **§7-2 #99 の残り（L7 ログインゲート）を実装した**。未認証は空のダッシュボードではなくゲートを見る。再読込を越えて生き残るのは httpOnly refresh cookie であり、access token は**メモリのみ**（#111）。セッション中の 401 は 1 回だけ再試行し、修復不能なら**理由を画面に出して**施錠する（黙って白紙化する G-10 型の否定） | 裁定要求なし（#99 の解消条件の履行）。**§7-2 #99 RETIRED**。証跡: `tests/ui_v3/test_auth.js`（29 件、状態機械）/ `test_gate.js`（13 件、表示の決定は純関数）/ `test_app_smoke.js` のゲート 9 件。表示の決定は `v3/ui/gate.js` に分離し、`app.js` は要素書き込みだけを持つ（DOM を書くファイルは 2 本になったので `TestTheWiringResolves` は両方を走査する） |
