# v3 影稼働 運用手順書（shadow start / stop / inspect）

WP-4.4（合成の配線）で v3 は**起動できる**ようになった。本書はその起動・停止・
確認の手順である。対象は Phase 5（影並走）の運用者。

> **前提となる裁定（R4）**: **権威は v1 のままである。** v3 は parity を通過する
> まで並走する「第 2 の意見」であり、その出力を最終判断の根拠にしてはならない。
> 全応答が `X-Noroshi-Mode: shadow` を、`/api/v3/app_config` が
> `"authoritative": false` を返すのはこのためである。
>
> **Phase 5 の開始可能日は 2026-09-05**（WP-0.1 の保持延長 + 30 日窓、
> `v3/parity/procedure.py`）。それ以前に parity を回すと、台帳が部分的にしか
> 覆っていない窓を比較することになり、S5-VERIF-023 が one-side-missing で
> 無効化する — 走らせた分がそのまま無駄になる。**影稼働そのものは今日から
> 開始してよい**（むしろ窓を作るために開始する必要がある）。

---

## 0. 起動前に確認すること（信じる前に見るもの）

WP-0.3 の教訓は「**バックアップが死んでいた 1 か月間、問題は『バックアップが
無い』ことではなく『誰も言えない』ことだった**」である。以下は起動してから
確認するのではなく、**起動前に**確認する。

| # | 確認 | コマンド | 期待 |
|---|---|---|---|
| 1 | v1 が動いている | `docker ps --filter name=noroshi --format '{{.Names}} {{.Status}}'` | `noroshi Up ...` |
| 2 | 8300 が空いている | `lsof -nP -iTCP:8300 -sTCP:LISTEN` | 出力なし |
| 3 | `config.env` が存在する | `test -f config.env && echo ok` | `ok`（compose の `env_file` が読む。**マウントはしない**） |
| 4 | v1 の DB を触らない構成である | `grep -n "radar-data\|/app/radar" docker-compose.yml` | 一致行が `radar:` サービス内だけ |
| 5 | 合成が通る（**ポートも束縛せず、ティックも回さない**） | `python -m v3.server --check`（下記 §1） | 終了コード 0 |

**#5 を飛ばしてはならない。** `--check` は合成だけを行い、資格情報の姿勢・
セッション面の有無・繰延項目・`legacy_modules` を JSON で吐いて終了する。
ここで `legacy_modules` が `[]` でなければ、その処理系は既に v1 を起動して
いる — その状態で影を合成することは拒否される（`assert_legacy_absent`）。

---

## 1. ローカルでの合成確認（コンテナを起動しない）

```bash
# 環境変数の一覧と意味
python -m v3.server --keys

# 合成の開示。ポート束縛なし、ループ起動なし、ティックなし、取得なし
NOROSHI_V3_LEDGER_PATH=/tmp/noroshi_v3_check.db python -m v3.server --check
```

`--check` の出力で**必ず読む 5 か所**:

| キー | 読み方 |
|---|---|
| `legacy_modules` | **`[]` 以外は即中止**。v1 が同じ処理系に載っている |
| `announcements` | 劣化しているものが 1 行 1 件。`NO FETCH` は資格情報が無く**そのアダプタは 1 回も外に出ない** |
| `credentials.unsatisfied` | 上に同じ。ここが空でない影は、その分だけ v1 より見えていない（**insensitive 方向 = NP1 上 blocking**） |
| `auth.present` | `false` なら `/api/v3/auth/*` は全部 503。v3 は鍵を**生成しない**（本番の `config.env` を書き換えないため） |
| `absent` | 意図的に無いもの。`websocket`・繰延中の P7 4 件・`sequence_chain_owner` |

> **`absent.sequence_chain_owner` が空でない状態で focus を設定してはならない。**
> focused ボーナスの畳み込みは `chain_country_for` を呼び、所有国を決められない
> シナリオでは**例外を投げる**。ループは NP3 により死なないので、症状は
> 「落ちる」ではなく「**結論行が静かに増えなくなる**」になる。
>
> **これは運用者が供給する項目ではない（2026-08-08 改訂、§7-2 #115 retire）。**
> 所有国は毎ティック、そのティックの観測から選ばれる（`v3/runtime/chain.py` —
> 本番の `max(effective_cores, key=avg_spike)` の転写）。設定用の環境変数
> `NOROSHI_V3_CHAIN_COUNTRIES` は**廃止した**: 定数は「いま誰がエスカレート
> しているか」を永久に固定するため、導出禁止の裁定が防ごうとした失敗そのものに
> なる（運用者の名前が付くだけで欠陥は同じ）。
>
> したがってこの欄が空でないときは**設定漏れではなくシナリオ定義の穴**である —
> `core_country` が未宣言で、weight 0.9 以上の `principal_belligerent` 参加国も
> 居ない。`geo_data.json` の当該シナリオを直すか、focus しないこと。
> 誰が選ばれたかは各ティックの `TickReport.chain_owners` に出る（NP6）。

一度だけティックを回して中身を見たいとき（**実際に外部 API を叩く**）:

```bash
NOROSHI_V3_LEDGER_PATH=/tmp/noroshi_v3_check.db python -m v3.server --once
```

`--once` は**呼び出しスレッドで 1 ティックだけ**回して `TickReport` を印字して
終了する。ループを起動しないので、失敗はログの奥ではなく標準エラーに出る。

---

## 2. 影の起動

```bash
# 1) 鍵の材料を用意する（任意。無ければ auth は 503 のまま動く）
export NOROSHI_V3_JWT_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export NOROSHI_V3_BOOTSTRAP_PASSWORD='...'      # 利用者 0 件のときだけ使われる

# 2) 起動（profile 指定が必須 — 指定しない限りこのサービスは存在しないのと同じ）
docker compose --profile shadow up -d --build v3_shadow
```

> **`--profile shadow` を付けない `docker compose up -d` は影を起動しない。**
> これは事故防止のための設計であり、同時に「v1 のサービス定義は 1 行も
> 変更していない」ことの担保でもある（`git diff docker-compose.yml` は
> 追加のみ）。**v1 の再起動は起こらない。**

> **`NOROSHI_V3_JWT_SECRET` を `config.env` に書いてはならない。** あのファイルは
> v1 が自動生成した秘密を持ち、v1 自身が追記する。第 2 の書き手を作ると、
> 負けた側の鍵の変更が**稼働中のアナリスト全員をログアウトさせる**。
> 影の鍵はシェルの環境変数か、別ファイル（`config.v3.env` を作って
> `--env-file` で渡す）で供給する。

起動直後の確認:

```bash
docker compose --profile shadow ps v3_shadow
curl -sS -D- http://127.0.0.1:8300/healthz     # X-Noroshi-Mode: shadow
```

### `/healthz` の 4 値（2026-08-09 改訂）

以前の `/healthz` は `{"status": "ok"}` を**リテラルで**返していた。その結果、
影コンテナは稼働中ずっと `healthy` を出し続け、その間 1 度もティックは完走せず
`tl_observation` は空だった。**これは G-17（空のキャッシュから ROUTINE を
返す）がコンテナ層で再現したもの**である。現在は `ops_health` の `tick_loop`
モニタ（`v3/runtime/ops_health.py`）を読み、次の 4 値を返す:

| status | HTTP | 意味 | オーケストレータの取るべき動作 |
|---|---|---|---|
| `ok` | 200 | 稼働中かつ**結論を生産している** | 通常運用 |
| `starting` | 200 | 初回ティックが未完了、まだ予算内 | **再起動しない**（起動中のものを起動し直すだけ） |
| `unknown` | 200 | 応答はしたが、この配備は loop プローブを渡していない | 配線の欠落。健全でも故障でもない |
| `degraded` | 503 | 稼働中だが**生産していない**（未完走 / 停止 / 遅延） | 台帳と `tick failed` を見る |

500 は使わない。500 は「プローブ自身が答えられなかった」という**別の事実**で
あり、2 つの状態が 1 つの答えを共有したことが今回の欠陥そのものだから。

`compose` の healthcheck は `status == "ok"` を検査する（200 だけを見る検査は
`starting` と `unknown` を healthy と読む）。

> **冷起動では `docker ps` が数分間 `unhealthy` を出す。これは既知かつ意図的**。
> 空の台帳では `fetch_schedule` が無く全 adapter が同時に due になるため、初回
> ティックの掃引は**実測で 15 分以上**かかる。エンドポイント側はこれを
> `starting` と呼ぶ（`first_tick_grace` = 30 分）が、compose の `start_period`
> は 180 秒しかない — **わざと短くしてある**。両者が食い違う理由は NP1:
>
> - 遅いだけの冷起動 → 初回掃引の間 `unhealthy`（誤報）
> - 本当に壊れたループ → 30 分ではなく約 5 分で `unhealthy`（本報）
>
> 見逃しは誤報より悪い。**どちらであるかは `docker ps` ではなく `/healthz` の
> `status` と `tick_loop.errors` で判別する**（`starting` かつ `errors: 0` なら
> 掃引中、`degraded` かつ `errors > 0` なら失敗中）。

同じ測定は `GET /api/v3/self_eval` の `ops_health.monitors[]` にも出る（AP3）。
**プローブは 1 つで、面が 2 つある。**

---

## 3. ティックが回っていることの確認

**「コンテナが Up」はティックが回っている証拠ではない。**（2026-08-09 以降、
`healthy` はその証拠になった — 上表参照。ただし `docker ps` の `Up` は依然
として証拠ではない。）見るのは 3 つ。

```bash
# (a) 起動時の開示。劣化しているものが WARNING で 1 行ずつ出ている
docker compose --profile shadow logs --tail 80 v3_shadow | grep -E "WARNING|shadow:"

# (b) ティックの失敗。NP3 によりループは 1 回の失敗で死なないので、
#     「静かに失敗し続けている」状態が存在しうる。ここが唯一の入口
docker compose --profile shadow logs --tail 200 v3_shadow | grep "tick failed"

# (c) 台帳が実際に伸びているか（最も確実）
docker compose --profile shadow exec v3_shadow python -c "
from v3.ledger.store import LedgerStore
s = LedgerStore('/app/v3data/noroshi_v3.db')
print('oldest:', s.oldest_observed_at('signal_observation'))
print('file bytes:', __import__('pathlib').Path(s.path).stat().st_size)
s.close()"
```

**(c) が動かない = ティックが回っていない**、と読んでよい。ファイルサイズが
2 ティック分の間隔（既定 60 秒 × 2）を跨いで変わらないなら、取得が全滅して
いるか、ループが起動していない。次は (b) を見る。

> **判断の順序**: 「静か」を「平穏」と読まないこと。v3 の観測が 0 行である
> ことは、世界が静かであることの証拠ではなく、**取得が死んでいることの
> 証拠でもありうる**。両者を分けるのは `announcements` と `fetch_log` であって、
> 結論行の数ではない。

---

## 4. 画面と API

| 用途 | URL |
|---|---|
| 画面（アナリストのループ、P8） | http://127.0.0.1:8300/ |
| 生存確認（唯一の public route） | http://127.0.0.1:8300/healthz |
| 配備の開示 | `GET /api/v3/app_config`（**viewer 以上。匿名は 401**） |
| 自己評価 / ops_health | `GET /api/v3/self_eval` |

`NOROSHI_V3_JWT_SECRET` を供給していない場合、画面はログインゲートで止まり、
`/api/v3/auth/login` は 503 を返す。**これは故障ではなく、鍵を持たない配備の
正しい姿である**（v3 は鍵を生成しない）。

---

## 5. 停止

```bash
docker compose --profile shadow stop v3_shadow      # 通常停止
docker compose --profile shadow down v3_shadow      # コンテナ削除（volume は残る）
```

停止は**ティックの途中で切らない**。`Runtime.stop()` はティック間の
`Event` を立て、実行中のティックの完了を待って抜ける — 台帳の作業単位が
中断されることはない。compose の `stop_grace_period: 60s` はその待ち時間である。

> **`docker compose down`（サービス名なし）を実行してはならない。** v1 も落ちる。
> 影だけを止めるときは必ずサービス名を付ける。

台帳を捨てるとき（**parity の窓も同時に消える**）:

```bash
docker compose --profile shadow down v3_shadow
docker volume rm noroshi_v3-shadow-data
```

---

## 6. parity レポートの読み方

parity は影とは別の作業であり、**2026-09-05 以降**に回す。手順の正は
`v3/parity/procedure.py::PROCEDURE`（コード側が自分の運用手順を持つ）。

```bash
docker compose --profile shadow exec v3_shadow python -c "
from v3.parity.procedure import PROCEDURE; print(PROCEDURE)"
```

レポートを読むときの 4 点:

| 見る場所 | 意味 |
|---|---|
| `report.blocked` | その層がまだ存在しない条件。**失敗ではない** |
| `report.failed` | 直すべきもの。**C-03 は一致率に関係なく、insensitive な不一致が 1 件でもあれば落ちる**（NP1 は「v3 の方が見えていない」を一致率で買えないものとして扱う） |
| `summary.is_void` | one-side-missing が 5% 超（S5-VERIF-023）。**その走行は何の測定でもない**。両系が覆う窓で回し直す |
| `SCOPE_NOTES` | 測っていないもの。focused ボーナスの畳み込みと threat_level 以外の結論型 |

走行後の安全確認（手順書自身が要求している）:

```bash
docker exec noroshi stat -c '%y %s' /app/radar/persistence/radar.db
# 走行前後で mtime とサイズが変わらないこと
```

---

## 7. 影が v1 に触れないことの根拠（疑ったときに読む）

主張ではなく、実行できる証拠として置いてある。

| 主張 | 根拠 |
|---|---|
| 台帳ファイルは v1 のものになりえない | `v3/server/isolation.py::assert_isolated_ledger` — `radar.db` / その WAL 兄弟 / `convergence_snapshots.db` / `radar/persistence/` 配下を**構築時に拒否**。`tests/test_v3_server.py::TestTheLedgerPathCannotBeAV1File` |
| 起動しても v1 の DB は 1 バイトも変わらない | `TestTheV1DatabaseIsUntouchedByABoot` — 1 ティック + 全公開ルート + 画面配信の後で mtime + sha256 + ディレクトリ一覧を照合 |
| `radar.*` を import しない（推移的にも） | `TestNoLegacyModuleIsReachable` — 別プロセスで合成して `sys.modules` を検査、+ 規律ゲート、+ `v3/server/` の AST 掃引 |
| import できてしまう経路も塞いである | `LegacyImportBarrier`（`sys.meta_path`）。**registry-backed な `Threshold` を resolver 無しで解決すると `radar.config_layered` を import する**（`_default_resolver`）— 唯一の生きた地雷であり、影の中では例外になる |
| 起動中に開く DB は v3 台帳だけ | `test_every_database_a_boot_opens_is_the_v3_ledger` — 起動全体の `sqlite3.connect` を記録して照合 |
| イメージに v1 が入っていない | `Dockerfile.v3` は `radar/` を COPY しない。`requirements-v3.txt` は v1 依存を入れない |
| 影は v1 の署名鍵を持たない | compose の `environment:` が `JWT_SECRET_KEY=` / `DEFAULT_ADMIN_PASSWORD=` を**空で上書き**する（`env_file` は config.env を丸ごと渡すため）。v3 はどちらの名前も読まないが、影が侵害されたときに v1 のトークンを偽造できる状態を残さない。`docker compose --profile shadow config \| grep JWT_SECRET_KEY` が `""` |
| v1 のサービス定義を変えていない | `git diff docker-compose.yml` が追加のみ（67 行）。影は compose profile の後ろ |

---

## 8. 意図的に「無い」もの（故障と読まないこと）

| 無いもの | 理由 |
|---|---|
| WebSocket チャネル | `v3/ui/` に socket クライアントが 1 つも無い（画面はポーリング）。読み手ゼロの並行面を影に足さない。語彙と発行者の有無は `v3/api/ws_publish.py` が正 |
| `notification_result` イベント | **v3 に通知系が存在しない**。空で流すと「通知は成功した」と読めるため出さない |
| P7 の 4 件（C8 / C10 / C11 / C12） | いずれも**読み手が存在しない**。`--check` の `absent.deferred_p7_detail` に各件の阻害が入っている |
| `ops_health` の `l5_checks` / `llm_health` | v3 に L5 検証層と LLM 健全性ロールアップが無い。`UNSUPPLIED` として**明示的に**出る（`OK` に畳まない） |
| 自動バックアップ | v3 台帳のバックアップ job はまだ無い。`ops_health.backup` は `INSUFFICIENT`（`backup_marker_absent`）を返す — **これが正しい答えである** |

最後の行は WP-0.3 の教訓そのものである。**「分からない」は「問題なし」ではない。**
影の台帳を長期保存する必要が出た時点で、v1 側と同じくバックアップ job と
マーカー（`backup_state.json`）を用意すること。それまでは `backup` が緑に
ならないのが正常であり、緑になっていたら疑うべきはツールの方である。
