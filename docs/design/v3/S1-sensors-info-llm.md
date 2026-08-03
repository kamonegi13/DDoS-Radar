# S1 — Information / LLM インテルセンサー 挙動仕様

**スコープ**: Information ドメイン 6 基（gdelt / rss_narrative / telegram_mirror / tor_metrics /
travel_advisory / bg_observer_rss）、LLM インテル 6 基（diplomatic / military_exercise /
hacktivist_intel / hacktivist_news / ground_osint / convergence_tracker）、および
**共通 RSS 取得・パース基盤**と**共通 LLM intel 投入基盤**の統合仕様。

**隣接仕様書との境界**:
- **intel_queue の `submit()` 以降**（dedup、credibility、auto-confirm tier、ledger 書込）は
  **本書の対象外**。本書はセンサーが投入する item のエンベロープと、その値を決める式までを扱う
- Cyber / Physical ドメインのセンサー個別挙動は S1-sensors-cyber-phys 担当。
  ただし `apt_intel`（Cyber 分類だが LLM 投入骨格の 8 複製の 1 つ）は
  **§4 の差分表にのみ登場**し、個別条項は持たない
- センサー cache → RationaleEntry 変換、ミュート・suppression 判定、`register_sequence_event` は
  スコアリング層（S1-scoring-pipeline）担当。本書はセンサーが `set_cache` に置く値までを規定する
- BaseSensor の health / circuit-breaker / `log_fetch` の共通契約は S1-sensor-base 担当。
  本書は「その契約からの逸脱」のみを条項化する
- `radar/conclusions/rss_extractor.py` の抽出規則本体は S1-conclusions 担当。
  本書は bg_observer_rss がその出力（3 段 confidence）をどう scoring 入力に写像するかを扱う

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md) に従う。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソースについて**: 本書の対象 12 基のうち**直接テストがあるのは 2 基のみ**
（rss_narrative の geo filter、bg_observer_rss の委譲先）。残り 10 基は D5 §4.2 の判定どおり
**コード読解のみが根拠**であり、条項の「検証」欄は大半が `未検証` になる。これは仕様の弱さではなく
**現行系の検証カバレッジの穴の忠実な記録**であり、S5 のテスト移植計画への入力である。

---

## 1. 用語

CLAUDE.md の用語定義に従う（country / scenario / participant / adversary / focused / background /
C-lite）。本書固有:

- **feed**: 1 本の RSS/Atom エンドポイント。センサー 1 基が複数 feed を持つ
- **feed 死活クラス**: feed の応答を 5 値に分類したもの（§3-B）。HTTP ステータスとは別概念
- **intel item**: センサーが LLM 解析結果として intel_queue へ渡す 1 レコード（§3-C）
- **elevation**: メタセンサーが「あるセンサーがある country で警戒状態にある」と判定した状態
- **normalized frequency**: キーワード出現数を記事数（または走査チャンネル数）で割った値。Z-score の入力
- **intercept log**: telegram_mirror がクラス変数に保持する検知リングバッファ。
  hacktivist_intel / ground_osint の入力になる
- 旧用語 `theater` は現行コードとデータ契約（intel item のキー名を含む）に残存する。
  本書の規範文では **country / scenario** を用い、残存は DEFECT-PRESERVE（§5-DP11）として記録する

---

## 2. 共通 RSS 取得・パース仕様（S1-INGEST-0nn）

現行は 6 系統に複製されている（§4 表 1）。以下は**あるべき単一仕様**として記述する。

### S1-INGEST-001: RSS 取得は単一の HTTP 契約に従う
**挙動**: feed 取得は GET のみを用い、**timeout 必須（接続・読取とも上限を持つ）MUST**、
プロキシ設定と TLS 検証設定を全 feed で共有 **MUST**。HTTP 200 のみを成功とし、
本文テキストを返す **MUST**。200 以外は空文字列を返し、ステータスをログに残す **MUST**。
例外送出時も空文字列を返し、**呼び出し元のサイクルを中断してはならない MUST NOT**。
**閾値**: timeout = 15s（diplomatic / apt_intel / military_exercise / hacktivist_news）、
10s（rss_narrative）、15s（bg_observer_rss）。**config キー無し・ハードコード**
**根拠**: diplomatic.py:172-185、apt_intel.py:193-205、military_exercise.py:115-128、
hacktivist_news_sensor.py:102-115、rss_narrative.py:134-145、background_observer.py:159-175
**検証**: 未検証
**分類**: CORE（timeout 値の分散は §5-DP7）

### S1-INGEST-002: RSS のパースは strict → tolerant の 2 段でなければならない
**挙動**: XML パースは (1) 安全な strict パーサ、(2) 失敗時に**回復モードの寛容パーサ**、の
順で試行 **MUST**。両方失敗した場合のみ「パース不能」として扱う **MUST**。
strict パースの失敗を**空記事リストとして黙って返してはならない MUST NOT**
（feed 側の破損とフィルタの厳しさが区別できなくなる）。
**理由**: 2026-04-29 の実地監査で、KCNA_WATCH を除く全外交 feed が strict パーサで失敗していた。
当時のコードは ParseError で `[]` を返し、`no_articles_post_filter` として記録していた
**根拠**: diplomatic.py:199-222（2 段実装）／ apt_intel.py:218-222・military_exercise.py:140-144・
hacktivist_news_sensor.py:124-128・rss_narrative.py:168-172（strict のみ）
**検証**: 未検証
**分類**: DEFECT-PRESERVE（現行は 6 系統中 1 系統のみが 2 段 → §5-DP7 / D2 A-02）

### S1-INGEST-003: feed の死活は 5 クラスに分類して記録する
**挙動**: feed 応答は `rss_with_items` / `rss_empty` / `returns_html` / `unparseable` / `unknown`
の 5 値に分類し、記事 0 件時の理由として記録 **MUST**。判定順序は
(1) 本文先頭が HTML 宣言なら `returns_html`、(2) 2 段パース不能なら `unparseable`、
(3) ルート要素が RSS/Atom なら item/entry 要素の有無で `rss_with_items` / `rss_empty`、
(4) それ以外は `unknown` **MUST**。
「健全な feed だがフィルタが全棄却した」ケースは上記 5 値と**別の理由コード**で記録 **MUST**
（URL の陳腐化と、検知率の基準率の低さを取り違えないため）。
**根拠**: diplomatic.py:225-259（分類器本体）、diplomatic.py:394-406・
hacktivist_news_sensor.py:262-280（消費側）
**検証**: 未検証
**分類**: CORE

### S1-INGEST-004: 記事はタイトル正規化キーで feed 内 dedup する
**挙動**: 記事のタイトルを**小文字化し先頭 60 文字を取り、英数字以外を除去した文字列**を
dedup キーとする **MUST**。同一 feed 内で既出キーの記事は棄却 **MUST**。
キーが空文字列（タイトル無し・記号のみ）の記事は dedup 対象外として通過させる **MUST**。
**根拠**: diplomatic.py:296-300、military_exercise.py:163-167、apt_intel.py:259-263、
hacktivist_news_sensor.py:159-163、rss_narrative.py:191-195
**検証**: 未検証
**分類**: CORE（6 系統で完全一致している唯一の共通ロジック）

### S1-INGEST-005: 記事の鮮度カットオフは fail-open である
**挙動**: 記事の公開日時が解析でき、かつカットオフより古い場合のみ棄却 **MUST**。
**日時が欠落または解析不能な記事は棄却してはならない MUST NOT**（NP1 感度優先）。
日時解析は RFC 2822 形式を第一に、失敗時 ISO 8601 を試行 **SHOULD**。
**閾値**: 鮮度窓 = 48h（diplomatic / military_exercise / hacktivist_news）、
168h（apt_intel）。**config キー無し・引数既定値としてハードコード**
**根拠**: diplomatic.py:278・302-312、military_exercise.py:146・169-177、
apt_intel.py:224・265-279、hacktivist_news_sensor.py:130・165-181
**検証**: 未検証
**分類**: CORE

### S1-INGEST-006: 記事の選抜はスロット制で上限を持つ
**挙動**: LLM に渡す記事は feed ごとに以下のスロット制で選抜 **MUST**:
- Slot 1: 事前フィルタキーワードに一致する記事、**最大 5 件**
- Slot 2: キーワード不一致だが対象国名に一致する記事、**最大 2 件**
- Slot 3: Slot 1+2 がともに空のとき、**最新 1 件**を fallback として採用

Slot 1 に入った記事は Slot 2 の評価対象にしない **MUST**（`continue` によるスロット排他）。
Slot 3 は非英語の公式声明でキーワード・国名フィルタが空振りした際の完全失明を防ぐ。
**根拠**: diplomatic.py:262-341（Slot 1-3）、military_exercise.py:131-196・apt_intel.py:208-310
（Slot 1-2 のみ）、hacktivist_news_sensor.py:118-208（キーワード必須・スロット無し）
**検証**: 未検証
**分類**: DEFECT-PRESERVE（Slot 3 は 1 系統のみ保有 → §5-DP7）

### S1-INGEST-007: 事前フィルタは「採用キーワード」と「ハード棄却キーワード」の 2 層である
**挙動**: 記事本文（タイトル + 要約、小文字化）に対し、**ハード棄却キーワードの一致を先に評価し、
一致すれば LLM 呼出前に棄却 MUST**。その後に採用キーワードを評価する **MUST**。
ハード棄却対象は「解決済み事案」「マーケティング」「定型ダイジェスト」の語彙とする。
**根拠**: apt_intel.py:140-154・284-290、hacktivist_news_sensor.py:86-90・191-196
**検証**: 未検証
**分類**: CORE

### S1-INGEST-008: 記事の跨サイクル dedup はプレフィクス付きハッシュの LRU で行う
**挙動**: 記事 1 件の恒久 dedup キーは `<センサー固有プレフィクス>-<feed 名>-<タイトル先頭 60 文字>`
のハッシュ **MUST**。**country を鍵に含めてはならない MUST NOT**（同一記事が複数 country へ
重複投入されるため）。保持数が上限を超えたら**古い側から半数を削除 MUST**。
**閾値**: 上限 1000 件（diplomatic / military_exercise / apt_intel）、500 件
（hacktivist_news / hacktivist_intel / ground_osint）、500 件（rss_narrative の burst dedup）。
**すべてハードコード・プロセス内 in-memory・再起動で消失**
**根拠**: diplomatic.py:150-158・414-422、military_exercise.py:93-95・244-251、
hacktivist_news_sensor.py:92-99・287-294、hacktivist_intel_sensor.py:32-40・76-83、
ground_osint_sensor.py:44-52・150-157、rss_narrative.py:59-61・119・330-342
**検証**: 未検証
**分類**: DEFECT-PRESERVE（揮発 = 再起動直後の重複投入 → §5-DP5 / D2 B-05）

### S1-INGEST-009: RSS 2.0 / RSS 1.0(RDF) / Atom の 3 形式を扱う
**挙動**: item 要素の走査は RSS 2.0 の `item`、RSS 1.0 の名前空間付き `item`、
Atom の名前空間付き `entry` を**すべて対象とする MUST**。
Atom のリンクは属性から取得 **MUST**（テキストノードではない）。
**根拠**: apt_intel.py:231-252（RSS 2.0 + RDF）、hacktivist_news_sensor.py:136-156（RSS 2.0 + Atom）、
background_observer.py:183-198（RSS 2.0 + Atom）、diplomatic.py:284（RSS 2.0 のみ）
**検証**: 未検証
**分類**: DEFECT-PRESERVE（対応形式が系統ごとに違う → §5-DP7）

### S1-INGEST-010: 死んだ feed は設定から削除せず監視対象に残す
**挙動**: 継続的に失敗している feed も**設定から除去してはならない SHOULD NOT**。
別ネットワーク環境からの再試行余地と、復活検知の機会を残す。
死活状態は feed 単位の理由コードとして毎サイクル記録 **MUST**（§3 付録 A の台帳が根拠資産）。
**根拠**: diplomatic.py:38-65（feed 監査コメント）、diplomatic.py:104-110（KCNA_WATCH 保持理由）
**検証**: 未検証
**分類**: CORE

---

## 3. 共通 LLM intel 投入仕様（S1-INGEST-02n）

現行は 8 系統に複製されている（§4 表 2）。骨格は
`事前フィルタ → prompt 構築 → llm_analyze_json → 出力検証 → confidence 決定 → item 組立 → submit`。

### S1-INGEST-020: LLM 不在時は成功として no-op で終える
**挙動**: LLM 機能が無効、または LLM エンドポイントが利用不能な場合、
**fetch は成功として記録し（失敗カウンタを進めず）MUST**、理由コードを付けて即座に戻る **MUST**。
これにより LLM 停止がサーキットブレーカーを開かせない（LLM 停止 = センサー故障ではない）。
**根拠**: diplomatic.py:351-362、military_exercise.py:206-216、hacktivist_intel_sensor.py:50-62、
hacktivist_news_sensor.py:218-232、ground_osint_sensor.py:107-119、
convergence_tracker.py:321-331、rss_narrative.py:315-326
**検証**: 未検証
**分類**: CORE（NP3 障害耐性）

### S1-INGEST-021: LLM へ渡す外部由来テキストは長さ上限付きでサニタイズする
**挙動**: 記事タイトル・要約・スニペット等の外部由来文字列は、
**LLM に渡す前に必ずサニタイズ関数を通し、文字数上限を明示 MUST**。
**閾値**: タイトル 120 字、要約 200/400/500 字（センサーごとに異なる）、スニペット 400 字。
すべてハードコード
**根拠**: diplomatic.py:425-426、military_exercise.py:253-254、hacktivist_news_sensor.py:297-298、
ground_osint_sensor.py:170-173、rss_narrative.py:346-349、apt_intel.py:372-373
**検証**: tests/test_sanitize_llm_input.py（サニタイズ関数本体。S4 セキュリティ仕様と相互参照）
**分類**: CORE

### S1-INGEST-022: プロンプトは system / user の 2 部構成で、基準日と JSON 専用指示を含む
**挙動**: system プロンプトは分析者ロールと**「JSON オブジェクトのみを返す」指示を含む MUST**。
user プロンプトは (1) 当日日付、(2) ソース識別、(3) 対象 country リスト、(4) 記事本文、
(5) 出力 JSON スキーマ、(6) confidence 帯の言語化ガイド、を含む **MUST**。
当日日付の明示は、モデルが記事の新旧を判断できるようにするために必須 **MUST**。
**根拠**: diplomatic.py:429-466、military_exercise.py:257-312、hacktivist_news_sensor.py:303-342、
apt_intel.py:384-425（Stage 1）・462-501（Stage 2）、convergence_tracker.py:336-367、
rss_narrative.py:352-406
**検証**: tests/test_apt_prompt_dedup.py::test_stage1_prompt_requests_summary_field ほか 3 件
（apt_intel の 2 段プロンプト構造のみ）
**分類**: CORE（NP6: prompt まで遡及可能であることの実装）

### S1-INGEST-023: LLM 応答は構造検証を通ったときのみ採用する
**挙動**: LLM 呼出は JSON 解析結果の成否フラグを返し、**失敗時は当該記事をスキップ MUST**
（フォールバック値での続行を**してはならない MUST NOT**）。
数値は安全変換関数で既定値付きに、列挙値は許容集合と既定値を与えた安全変換関数で正規化 **MUST**。
**根拠**: diplomatic.py:469-477、military_exercise.py:315-323、hacktivist_intel_sensor.py:145-154、
hacktivist_news_sensor.py:344-358、ground_osint_sensor.py:220-229、convergence_tracker.py:369-380
**検証**: 未検証
**分類**: CORE

### S1-INGEST-024: 棄却理由は「信号なし」と「閾値未満」を分離して記録する
**挙動**: LLM が escalation 無しと判定した場合と、confidence がフロア未満だった場合は
**別々の理由コードで記録 MUST**。前者はプロンプト/モデルの調整対象、
後者は閾値の調整対象であり、混同すると診断が不能になる。
**閾値**: confidence フロア = **0.35**（diplomatic / military_exercise / hacktivist_intel /
hacktivist_news / ground_osint / apt_intel Stage 2）、**0.35**（rss_narrative クラスタ）、
**0.50**（convergence_tracker）。**すべてハードコード・config キー無し**
**根拠**: military_exercise.py:351-361（分離の明示コメント）、diplomatic.py:479-482、
hacktivist_news_sensor.py:360-374、rss_narrative.py:524-529、convergence_tracker.py:382-384
**分類**: CORE

### S1-INGEST-025: LLM の多国出力は 2 文字コードに正規化し重みを [0,1] にクランプする
**挙動**: `countries` は**空白除去・大文字化した結果が 2 文字のものだけを残す MUST**。
`country_weights` は大文字キー・小文字キーの順で探索し、欠落時は 1.0 を既定 **MUST**、
値は `[0.0, 1.0]` にクランプ **MUST**。
主 country が `countries` に含まれない場合は**先頭に挿入し重み 1.0 を与える MUST**。
**根拠**: diplomatic.py:485-504、military_exercise.py:326-333・392-394、
hacktivist_intel_sensor.py:163-186、hacktivist_news_sensor.py:377-405、rss_narrative.py:480-490
**検証**: tests/test_intel_multicountry.py（12 件。ただし検証面は intel_queue 側）
**分類**: CORE

### S1-INGEST-026: 主 country を特定できない item は破棄する（強制フォールバック禁止）
**挙動**: LLM が主 country を null または対象リスト外で返した場合、item を**破棄 MUST**。
**「最も近い対象国」への強制割当をしてはならない MUST NOT**
（LLM の過剰関連付けが、実体のない収斂を作るため）。
**根拠**: diplomatic.py:495-500、military_exercise.py:364-369、
hacktivist_intel_sensor.py:174-182、hacktivist_news_sensor.py:387-401
**検証**: 未検証
**分類**: CORE（Phase 9-E の帰属汚染インシデントの再発防止に対応）

### S1-INGEST-027: 関連度が間接の item は confidence に上限を課す
**挙動**: LLM に「対象 country との結び付きが直接 / 間接 / 無し」を自己申告させ、
**「無し」は破棄 MUST**、**「間接」は confidence を上限値でクリップ MUST**。
**閾値**: 間接時の上限 = **0.45**（diplomatic）／ **0.50**（military_exercise）。ハードコード
**根拠**: diplomatic.py:506-523、military_exercise.py:371-390
**検証**: 未検証
**分類**: CORE（上限値の不一致は §4 表 2）

### S1-INGEST-028: score_delta は加法合成であり乗法を用いない
**挙動**: item の `score_delta` は `base + bonus` の**加法 MUST**。
乗法合成は値が跳ねるため**用いてはならない MUST NOT**。
上限を持つ場合は合成後にクリップ **MUST**。
**根拠**: military_exercise.py:396-401（「avoids multiplicative inflation」）、
apt_intel.py:552-563、hacktivist_intel_sensor.py:196-201、convergence_tracker.py:388-392
**検証**: 未検証
**分類**: CORE

### S1-INGEST-029: intel item のエンベロープは 13 フィールド固定である
**挙動**: intel_queue へ渡す item は以下を必ず含む **MUST**:
`source_type` / `source_id` / `theater`（=主 country、§5-DP11）/ `countries` / `country_weights` /
`ts` / `confidence`（小数 3 桁丸め）/ `raw_text`（1000 字上限）/ `raw_url` / `headline`（100 字上限）/
`llm_fields`（センサー固有の構造化抽出結果）/ `score_delta` / `domain`。
`domain` は **cyber / physical / info のいずれか MUST**。
**根拠**: diplomatic.py:528-550、military_exercise.py:403-427、hacktivist_intel_sensor.py:203-223、
hacktivist_news_sensor.py:426-450、ground_osint_sensor.py:255-277、
convergence_tracker.py:398-424、rss_narrative.py:554-576、apt_intel.py:565-589
**検証**: 未検証
**分類**: CORE（`domain` に 3 値外が入りうる現行挙動は §5-A5）

### S1-INGEST-030: サイクル単位の沈黙は理由コードで説明可能でなければならない
**挙動**: 1 サイクルで 1 件も投入しなかった場合、**その理由を判別できるコードを記録 MUST**。
最低限「入力ゼロ」「全件 dedup 済」「全件本文空」「全 feed 死亡」「burst 無し」を
区別できること **MUST**（沈黙が正常なのか壊れているのかをアナリストが秒で判断できるため）。
**根拠**: hacktivist_intel_sensor.py:231-237、ground_osint_sensor.py:287-293、
rss_narrative.py:747-755、diplomatic.py:560-561、hacktivist_news_sensor.py:462-463
**検証**: 未検証
**分類**: CORE（AP3 自己評価の入力）

---

## 4. コピペ複製の挙動差分表（DEFECT-PRESERVE）

### 表 1: RSS 取得・パース 6 系統の差分（D2 A-02）

| 系統 | HTTP | timeout | UA | 429 扱い | tolerant パーサ | 死活分類 | 形式対応 | 鮮度窓 | 記事上限 |
|---|---|---|---|---|---|---|---|---|---|
| diplomatic | requests | 15s | ブラウザ 3 ヘッダ | 200 以外一律ログ | **有** | **有（唯一の定義元）** | RSS 2.0 | 48h | 5+2+1 |
| apt_intel | requests | 15s | ブラウザ 3 ヘッダ | 200 以外一律ログ | 無 | 無 | RSS 2.0 + RDF | **168h** | 5+2 |
| military_exercise | requests | 15s | `OSINT-Radar/8.0` | 429 のみ個別ログ | 無 | 無 | RSS 2.0 | 48h | 5+2 |
| hacktivist_news | requests | 15s | `OSINT-Radar/8.0` | 429 のみ個別ログ | 無 | **借用**（diplomatic を関数内 import） | RSS 2.0 + Atom | 48h | 5 |
| rss_narrative | requests | **10s** | `OSINT-Radar/8.0` | **429 で空返し** | 無 | 無 | RSS 2.0 | **窓なし** | 2/ソース |
| bg_observer_rss | **urllib** | 15s | `news-aggregator` | **区別なし** | 無 | **空 = 失敗計上** | RSS 2.0 + Atom | **窓なし** | 無制限 |

**帰結**: 同一の malformed RSS に対し、diplomatic は記事を回収し、他 5 系統は静かに 0 件を返す。
NP2（多ソース収斂）の入力品質がセンサーごとに不均一。
**v3 規範**: S1-INGEST-001〜010 を単一の取得層として実装 **MUST**。
`hacktivist_news` が他センサーの private 関数を関数内 import する構造（hacktivist_news_sensor.py:263）は
複製の症状であり、共有層で解消される。

### 表 2: LLM 投入 8 系統の差分（D2 A-02 / D2 #11）

| センサー | max_tokens | 事前フィルタ | conf フロア | 主 country 規則 | conf 上限規則 | dedup 鍵 | score_delta 式 | domain |
|---|---|---|---|---|---|---|---|---|
| apt_intel | **200（Stage1）+ 280（Stage2）** | キーワード + ハード棄却 + 定型接頭辞 | 0.35 | 対象外なら破棄 | — | 記事ハッシュ 1000 | ttp_base(1.0-2.5) + urgency(0-0.5) | cyber |
| diplomatic | 256 | escalation キーワード + 国名 + 最新 1 件 | 0.35 | 対象外なら破棄 | 間接 → **0.45** | 記事ハッシュ 1000 | urgency 1.0/1.5/2.0/3.0 | info |
| military_exercise | 300 | exercise キーワード + 国名 | 0.35 | 対象外なら破棄 | 間接 → **0.50**、status/historical → **0.50** | 記事ハッシュ 1000 | urgency(1.0-2.5) + scale(0-0.5) | **physical** |
| hacktivist_intel | 256 | **無し**（intercept log 全件） | 0.35 | null なら破棄。2 文字英字なら LLM 上書き採用 | — | ts+channel+country 500 | sector(1.0/2.0) + timeline(0-1.0)、cap 3.0 | attack_type で cyber/info |
| hacktivist_news | 250 | hacktivist キーワード必須 + ハード棄却 | 0.35 | **対象リスト外も破棄**（唯一） | — | 記事ハッシュ 500 | urgency(0.5-2.0) + type(0-0.5) | info |
| ground_osint | 256 | status 絞込 + ongoing 語 or target≥2 | 0.35 | 上流 country をそのまま採用 | **+0.10 ブースト**、cap 0.95 | ts+channel+country 500 | 3.0/2.0/1.0 の 3 段 | cyber |
| convergence_tracker | **400** | 持続収斂ゲート（§6） | **0.50** | 上流 country をそのまま採用 | — | **country 単位 24h クールダウン** | urgency(1.5-3.0) + sensor(0-1.0) | **LLM 出力（mixed 含む）** |
| rss_narrative | **512** | Z-score burst ゲート | 0.35 | LLM 出力 + 対象国を先頭挿入 | — | **burst 単位 日次ハッシュ 500** | type(0.5-2.5) + urgency(0-0.5) | info |

**特記 1**: D1-sensors §2 は「max_tokens 200-400」と記録しているが、実測レンジは **200〜512**
（rss_narrative の 512 が未計上）。
**特記 2**: 主 country の扱いが 4 通りに分岐している（破棄 / LLM 上書き / 上流採用 / 先頭挿入）。
**特記 3**: `domain` の決定主体が 4 通り（固定値 / attack_type 写像 / LLM 出力 / 固定だが実体と不一致）。
**v3 規範**: S1-INGEST-020〜030 を単一の投入層として実装し、
**センサー固有部分は「事前フィルタ」「プロンプト本文」「score_delta 式」「domain」の 4 スロットに
限定 MUST**。閾値（max_tokens / conf フロア / conf 上限 / dedup 上限）は宣言的 registry 経由 **MUST**。

---

## 5. Information センサー個別条項

### gdelt

### S1-SENSI-001: トーンは当日窓と履歴窓を並列取得して差分を採る
**挙動**: country ごとに検索クエリを組み、**当日窓（1d）と履歴窓（既定 28d）を並列に取得 MUST**。
各窓のトーンは時系列点の値の**単純平均を小数 3 桁で丸めた値 MUST**。
HTTP 429 / 503、時系列空、値配列空のいずれも `None`（データ無し）**MUST**。
当日トーンが `None` の country は状態 `NO_DATA` とし、以降の判定を行わない **MUST**。
country 間には **0.5 秒の courtesy delay を置く MUST**（2 件目以降）。
**閾値**: 履歴窓 = 28 日（`GDELT_HISTORY_WINDOW`、DB override 可、config.py:328）
**根拠**: gdelt.py:24-32・41-56
**検証**: 未検証
**分類**: CORE

### S1-SENSI-002: DOW ベースラインは UTC 日バケット単位で 1 日 1 回だけ記録する
**挙動**: 当日の UTC 日バケット（`floor(now/86400)*86400`）が前回記録バケットと異なる場合のみ、
当日トーンを曜日ラベル付きで永続記録 **MUST**。同一バケット内の再取得は記録しない **MUST**。
保持上限は `曜日あたり上限 × 7` **MUST**。
**閾値**: 曜日あたり上限 = 20（≈20 週）。ハードコード
**根拠**: gdelt.py:21-22・38-40・60-64
**検証**: 未検証
**分類**: CORE

### S1-SENSI-003: DOW Z-score は同曜日・当日除外・標準偏差フロア付きで計算する
**挙動**: 同一曜日の**当日を除く**過去サンプル集合を取得し、件数 n が最小サンプル数以上のときのみ
Z-score を算出 **MUST**。式は母集団標準偏差を用い、**下限 0.5 でフロアする MUST**:
```
mean = Σx / n
std  = max( sqrt( Σ(x − mean)² / n ), 0.5 )
z    = (tone_today − mean) / std
```
n が最小サンプル数未満のときは Z-score を `None` として出力 **MUST**（0 で埋めない）。
**閾値**: 最小サンプル数 = 3、標準偏差フロア = 0.5。**ともにハードコード**
**根拠**: gdelt.py:21・66-77
**検証**: 未検証
**分類**: CORE（トーンには曜日バイアスがあるという外部 API 知識の実装）

### S1-SENSI-004: alert 判定は Z-score と絶対閾値の OR、悪天候で抑制する
**挙動**: `is_alert = (悪天候でない) AND (z < −2.0 OR tone_today < 絶対閾値)` **MUST**。
Z-score が使えない（サンプル不足）場合は `is_alert = (悪天候でない) AND (tone < 絶対閾値)` **MUST**。
**トーンは負が敵対的**であり、大きな負の Z が異常な敵意を意味する。
状態は `WEATHER_NOISE`（悪天候 かつ トーンが絶対閾値未満）→ `ALERT` → `NORMAL` の
**優先順で決定 MUST**。
**閾値**: Z 下限 = **−2.0**（ハードコード）、絶対閾値 = **−15.0**
（`GDELT_TONE_ALERT_THRESHOLD`、DB override 可、config.py:327）
**根拠**: gdelt.py:73-86
**検証**: 未検証
**分類**: CORE

### rss_narrative

### S1-SENSI-010: キーワードは語句と原子語の 2 層に展開する
**挙動**: 設定キーワードを (1) 空白またはハイフンを含む**語句**、(2) 各エントリから抽出した
**4 文字以上かつストップワードでない単語**（原子語）、の 2 層に展開 **MUST**。
原子語は重複除去して昇順ソート **MUST**。
**根拠**: rss_narrative.py:15-50
**検証**: 未検証
**分類**: CORE

### S1-SENSI-011: 記事のヒット判定は「語句 1 件」または「原子語 2 種以上」である
**挙動**: 記事が語句のいずれかを部分一致で含めばヒット **MUST**。
語句が一致しない場合、**単語境界一致した原子語の異なり数が 2 以上のときのみヒット MUST**。
単語 1 個の一致でベースラインが膨らむのを防ぐための非対称設計である。
**根拠**: rss_narrative.py:206-214・271-273
**検証**: tests/test_rss_narrative.py::TestCountKeywordsGeoFilter（4 件、間接）
**分類**: CORE

### S1-SENSI-012: 地理関連度は 3 分類し、他 country 記事のみをキーワード計数から除く
**挙動**: 記事本文を対象 country の地名語彙と照合し、
`match`（当該 country に言及）/ `other`（他の監視対象 country にのみ言及）/
`generic`（いずれにも言及なし）に分類 **MUST**。**`other` のみキーワード計数から除外 MUST**、
`generic` は除外しない（グローバル・曖昧記事は残す = NP1）。
地名語彙の照合規則は、**多語または 6 文字以上は部分一致、それ未満の単語は単語境界一致 MUST**。
**根拠**: rss_narrative.py:69-118・200-204・265-269
**検証**: tests/test_rss_narrative.py::TestClassifyArticleGeo（14 件）／
::TestCountKeywordsGeoFilter::test_excludes_other_theater_articles ／
::TestGetBurstArticlesGeoFilter（2 件）／::TestGeoFilterIntegration::test_tass_mixed_articles_ua_theater
**分類**: CORE

### S1-SENSI-013: Z-score の分母（記事数）は地理フィルタを適用しない
**挙動**: 正規化頻度は `キーワードヒット数 / max(総記事数, 1)` **MUST**。
**総記事数は地理フィルタで減らしてはならない MUST NOT**（分母が揺れると Z-score が不安定になる）。
**根拠**: rss_narrative.py:160-163・197-198・701
**検証**: tests/test_rss_narrative.py::TestCountKeywordsGeoFilter::test_article_count_always_unfiltered
**分類**: CORE

### S1-SENSI-014: 30 日ローリング Z-score は母分散を用い、無音ベースラインを特別扱いする
**挙動**: 保持サンプル数が **7 未満なら (z, mean, std) = (0,0,0) を返す MUST**（ウォームアップ）。
7 以上のとき:
```
mean = Σx / n ;  var = Σ(x − mean)² / n ;  std = sqrt(var) if var > 0 else 0
z = (today − mean) / std                     … std > 0
z = NARRATIVE_ZSCORE_FIRST_SIGNAL            … std == 0 かつ mean == 0 かつ today > 0
z = 0.0                                      … それ以外
```
**第 2 分岐は必須 MUST**: 平坦なゼロ列に対する最初の非ゼロ活動は、それ自体が burst 信号であり、
これが無いと無音期からの立ち上がりが z=0 として黙殺される（NP1 感度優先）。
**閾値**: 最小サンプル 7（ハードコード）、初回信号 Z = **3.0**（環境変数
`NARRATIVE_ZSCORE_FIRST_SIGNAL` のみ。**config registry 非登録** → §6-A8）
**根拠**: rss_narrative.py:588-613
**検証**: tests/test_rss_narrative.py::TestBaselineRetention::test_baseline_zscore_warmup
**分類**: CORE

### S1-SENSI-015: ローリング窓の上限は「日数 × 1 日あたり取得回数」で導出する
**挙動**: ベースライン保持上限は `保持日数 × floor(86400 / poll 間隔)` **MUST**。
**保持日数をそのままサンプル数上限にしてはならない MUST NOT**。
**理由**: 30 分間隔のセンサーは 1 日 48 サンプルを生む。上限を 30 サンプルにすると窓が
実質 15 時間になり、Z-score が自分自身に対して正規化されて burst が原理的に検知不能になる
（2026-04-29 の本番回帰: 前置フィルタ棄却率 100%）。
**閾値**: 保持日数 = 30（`NARRATIVE_BASELINE_DAYS`、DB override 可、config.py:360）
**根拠**: rss_narrative.py:615-634
**検証**: tests/test_rss_narrative.py::TestBaselineRetention::
test_baseline_cap_matches_days_times_cycles_per_day / test_baseline_cap_obeys_env_override
**分類**: CORE

### S1-SENSI-016: burst 状態は 2 段閾値で決まる
**挙動**: `z ≥ CRITICAL 閾値` → `CRITICAL_BURST`、`z ≥ ALERT 閾値` → `BURST`、
それ以外 `NORMAL` **MUST**。`is_burst` は前 2 者で真 **MUST**。
**閾値**: ALERT = **2.0**（`NARRATIVE_ZSCORE_ALERT`、DB override 可、config.py:358）、
CRITICAL = **3.0**（`NARRATIVE_ZSCORE_CRITICAL`、同 config.py:359）
**根拠**: rss_narrative.py:706-710
**検証**: 未検証
**分類**: CORE

### S1-SENSI-017: burst 時の LLM 解析は主題クラスタに分割して投入する
**挙動**: burst 検知時のみ、ヒット記事を集めて LLM に渡す **MUST**。
LLM には**主題が異なる記事を別クラスタに分けるよう指示 MUST**、
**無関係記事群に共通ナラティブを捏造させてはならない MUST NOT**。
クラスタごとに独立した intel item を投入 **MUST**（アナリストが主題単位で採否できる）。
クラスタ検証規則: 記事インデックスは 1 始まり、プール範囲外は無視、
**有効インデックスが 0 件のクラスタは破棄 MUST**（ただし旧形式フォールバック時のみ先頭 4 件を割当）。
LLM が `clusters` を返さない場合は**応答全体を単一クラスタとして扱う後方互換パス MUST**。
burst 単位の LLM 呼出は `country + 状態 + UTC 日` のハッシュで**日次 dedup MUST**。
**閾値**: LLM プール上限 6 件、ソースあたり収集 2 件、max_tokens 512。すべてハードコード
**根拠**: rss_narrative.py:284-427・429-503・712-732
**検証**: 未検証
**分類**: CORE

### S1-SENSI-018: クラスタは非エスカレーションまたはフロア未満で破棄する
**挙動**: `escalation_signal` が偽のクラスタ、および confidence が 0.35 未満のクラスタは
投入しない **MUST**。`score_delta` は narrative_type の基礎値に urgency ボーナスを加えた値 **MUST**:
基礎値 = pre-operation_conditioning 2.5 / threat_escalation 2.0 / response_to_incident 1.5 /
propaganda_routine 0.5 / unknown 1.0、ボーナス = critical 0.5 / high 0.2 / medium 0 / low 0。
**根拠**: rss_narrative.py:521-552
**検証**: 未検証
**分類**: CORE

### telegram_mirror

### S1-SENSI-020: 公開プレビュー取得は UA ローテーションと指数バックオフを持つ
**挙動**: 公開チャンネルプレビューの取得は、リクエストごとに **UA プールから無作為選択 MUST**。
403 / 429 応答時は `2.0 × 2^試行回数 × ジッタ(0.8-1.2)` 秒だけ待って**最大 3 回まで再試行 MUST**、
待機は 30 秒で上限 **MUST**。それ以外の非 200 応答および例外は即座に諦める **MUST**。
**3 つの失敗モード（プレビュー無効化 / スロットリング / ネットワーク断）を
ログ上で区別できること MUST**（すべて空文字列を返すため、区別が無いと診断不能）。
**閾値**: UA プール 5 種、初期遅延 2.0s、最大試行 3、待機上限 30s。すべてハードコード
**根拠**: telegram.py:42-48・80-128
**検証**: 未検証
**分類**: CORE

### S1-SENSI-021: 取得成功の判定は本文長と投稿コンテナの存在の 2 条件である
**挙動**: 最終 URL からプレビュー無効化リダイレクトを検出したら空を返す **MUST**。
HTTP 200 かつ**本文長が下限を超え、かつ投稿コンテナ要素を含む場合のみ成功 MUST**。
本文長のみを満たしコンテナが無いページは、非公開/空チャンネルとして空を返す **MUST**。
**閾値**: 本文長下限 = 2000 バイト。ハードコード
**根拠**: telegram.py:74-78・106-118
**検証**: 未検証
**分類**: CORE

### S1-SENSI-022: 投稿は個別にタイムスタンプ抽出し鮮度窓で絞る
**挙動**: 投稿コンテナ境界で本文を分割し、各投稿から公開時刻を抽出 **MUST**。
時刻が抽出できない、または解析不能な投稿は**破棄 MUST**（ページ全体を捨てない）。
鮮度窓より古い投稿は破棄 **MUST**。残った投稿本文を連結して解析対象とする **MUST**。
**閾値**: 鮮度窓 = **48 時間**（`TELEGRAM_POST_MAX_AGE_HOURS`、環境変数のみ、telegram.py:31）。
2026-04-29 に 8h → 48h へ変更。ハクティビストチャンネルは 24-72h のバースト間欠投稿であり、
8h 窓は健全なチャンネルでも全投稿を落としていた
**根拠**: telegram.py:23-31・130-175・340-345
**検証**: 未検証
**分類**: CORE

### S1-SENSI-023: キーワード照合は長さと形態で規則を切り替える
**挙動**: 2 文字以下のキーワードは**照合しない MUST**（雑音源）。
空白を含む語句、および `#` 始まりのハッシュタグは**部分一致 MUST**。
それ以外の単語は**単語境界一致 MUST**（"target" が "targeting" に一致しない）。
この規則はヒット計数・意図判定・スニペット抽出の**3 箇所で同一 MUST**。
**根拠**: telegram.py:187-232・300-312
**検証**: 未検証
**分類**: CORE

### S1-SENSI-024: チャンネルは 1 サイクル 1 回だけ取得し、country へ扇出する
**挙動**: 複数 country が同一チャンネルを監視する場合でも、
**チャンネルの取得と解析は 1 サイクルにつき 1 回 MUST**。結果を country ごとに集約 **MUST**。
チャンネル間には **1.5〜4.0 秒の無作為ジッタを置く MUST**。
**根拠**: telegram.py:321-357・359-388
**検証**: 未検証
**分類**: CORE

### S1-SENSI-025: 正規化頻度は「取得成功チャンネル数」で割る
**挙動**: `normalized = 総キーワードヒット数 / max(取得成功チャンネル数, 1)` **MUST**。
取得失敗チャンネルは分母に含めない **MUST**（feed 障害が burst に化けるのを防ぐ）。
**根拠**: telegram.py:371-393
**検証**: 未検証
**分類**: CORE

### S1-SENSI-026: 状態はバースト優先のラダーで決定する
**挙動**: `CRITICAL_BURST`（z ≥ CRITICAL）→ `BURST`（z ≥ ALERT）→ `INTENT_DETECTED`（意図あり）
→ `TARGETS_FOUND`（標的 URL あり）→ `CLEAR` の**優先順で決定 MUST**。
統計的 burst は個別検知より上位 **MUST**。
**閾値**: rss_narrative と同一の `NARRATIVE_ZSCORE_ALERT` / `NARRATIVE_ZSCORE_CRITICAL` を共有
**根拠**: telegram.py:395-407
**検証**: 未検証
**分類**: CORE

### S1-SENSI-027: 主張の確度は裏付けの強さで 4 段に決まる
**挙動**: `claim_confidence` は以下の**排他ラダー MUST**:
バースト裏付けあり **0.6** > 意図あり かつ 政府系標的 URL あり **0.4** > 意図のみ **0.2** >
主張なし **0.0**。政府系判定は標的 URL に `.gov` / `.mil` / `.parliament` のいずれかを含むこと。
**閾値**: 0.6 / 0.4 / 0.2 / 0.0 すべてハードコード（telegram.py:38-40）。
下流の抑制閾値 `TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD` 既定 **0.5**（telegram.py:22）
は**スコアリング層で消費**（S1-scoring-pipeline 担当）
**根拠**: telegram.py:33-40・409-421
**検証**: 未検証
**分類**: CORE

### S1-SENSI-028: 検知ログは CLEAR を記録せず、内容ハッシュで重複を抑制する
**挙動**: 状態 `CLEAR` の検知は**記録してはならない MUST NOT**。
`チャンネル + country + スニペット先頭 200 字 + 標的 URL 先頭 5 件` のハッシュが
前回と同一なら**記録を抑制 MUST**（固定投稿の再取得によるログ汚染防止）。
リングバッファは新しいものを先頭に挿入し、上限超過時に末尾を落とす **MUST**。
**閾値**: リングバッファ上限 = 200 件。ハードコード・プロセス内・再起動で消失
**根拠**: telegram.py:62-70・234-271
**検証**: 未検証
**分類**: CORE（本ログが hacktivist_intel / ground_osint の唯一の入力源）

### tor_metrics

### S1-SENSI-030: relay 減少率と bridge 利用者急増率を前サイクル比で算出する
**挙動**: country ごとに稼働 relay 数・稼働 bridge 数・帯域合計を集計 **MUST**。
`drop_pct = (prev − running) / max(prev, 1)`（prev > 0 のときのみ、それ以外 0）**MUST**。
bridge 利用者は `surge_pct = (users − prev_users) / max(prev_users, 1)`（prev_users > 0 のときのみ）**MUST**。
利用者トレンドは `SURGE`（surge_pct > 上限）/ `DROP`（surge_pct < −0.3）/ `NORMAL` **MUST**。
リクエスト間に **0.5 秒の delay を置く MUST**。429 応答時は relay ループを打ち切る **MUST**。
**閾値**: relay 減少率閾値 = **0.40**、利用者急増率閾値 = **1.00**、DROP 閾値 = **−0.3**。
すべてハードコード（tor_metrics.py:25-26・108）
**根拠**: tor_metrics.py:50-120
**検証**: tests/test_engine.py::TestTorMetricsSensor::test_relay_drop_detection /
test_user_surge_detection（**いずれも本番関数を呼ばずインライン再実装** → §7-GAP-06）
**分類**: CORE

### S1-SENSI-031: country 状態は relay 減少と利用者急増の論理積で最上位が決まる
**挙動**: `relay_drop = drop_pct ≥ 閾値`、`user_surge = トレンド == SURGE` として、
`CENSORSHIP_INDICATOR`（両方）→ `RELAY_DROP`（前者のみ）→ `USER_SURGE`（後者のみ）
→ `NORMAL` **MUST**。**両方の合致のみが検閲指標である MUST**
（遮断だけなら障害の可能性、迂回増だけなら他要因の可能性がある）。
**根拠**: tor_metrics.py:122-136
**検証**: tests/test_engine.py::TestTorMetricsSensor::test_censorship_indicator（インライン再実装）
**分類**: CORE

### S1-SENSI-032: 前サイクル値は正値のときのみ更新し、全失敗時は前回 cache を返す
**挙動**: 前サイクル比較値は**新値が 0 より大きいときのみ更新 MUST**
（取得失敗による 0 でベースラインを潰さない）。
1 件も成功しなかったサイクルは **cache を更新してはならない MUST NOT**。
その場合は前回 cache、無ければ全 country `NORMAL` の既定構造を返す **MUST**。
**根拠**: tor_metrics.py:138-161
**検証**: tests/test_engine.py::TestTorMetricsSensor::test_cache_roundtrip（cache 往復のみ）
**分類**: CORE（前サイクル値がプロセス内揮発である点は §6-DP12）

### travel_advisory

### S1-SENSI-040: 3 政府ソースを並列取得し、1 ソースの失敗を他に波及させない
**挙動**: 米（RSS）/ 英（Atom）/ 加（HTML）の 3 ソースを**並列に取得 MUST**。
各ソースは `(データ, 成否)` を独立に返し、**例外・429・非 200 はいずれも失敗として
空データを返す MUST**（他ソースの処理を止めない）。1 件でも成功すれば cache を更新 **MUST**、
全滅時は前回 cache を返す **MUST**。
**閾値**: timeout = 20s。ハードコード。取得周期 3600s
**根拠**: travel_advisory.py:31-48・82-104・150-172・239-242
**検証**: 未検証
**分類**: CORE（NP2 独立ソース収斂の実装）

### S1-SENSI-041: 3 ソースそれぞれに固有のレベル抽出規則を持つ
**挙動**: 勧告レベルは 1〜4 の共通尺度に写像 **MUST**。抽出規則はソースごとに:
- **米**: 大文字化本文に `LEVEL 4` / `DO NOT TRAVEL` → 4、`LEVEL 3` / `RECONSIDER TRAVEL` → 3、
  `LEVEL 2` / `INCREASED CAUTION` → 2、`LEVEL 1` / `NORMAL PRECAUTIONS` → 1、不一致 0
- **英**: 定型フレーズ表（`advise(s) against all travel` → 4、
  `advise(s) against all but essential travel` → 3）を優先。不一致時は重症度語
  （`extreme risk` / `war zone` / `armed conflict` → 4、`high risk` / `significant risk` → 3）、
  **最後に `travel` を含めば 2 を返す fail-open**
- **加**: 定型フレーズ表（`avoid all travel` 4 / `avoid non-essential travel` 3 /
  `exercise a high degree of caution` 2 / `take normal security precautions` 1）→
  数値表記 `risk level N` → **行内のアイコンファイル名**（`do-not-travel` 4 /
  `reconsider-travel` 3 / `increased-caution` 2 / `normal-precautions` 1）の 3 段フォールバック

**根拠**: travel_advisory.py:50-64・245-302・320-366
**検証**: 未検証
**分類**: CORE（英の fail-open は §6-A3）

### S1-SENSI-042: country 照合は対象集合を優先し全 country へフォールバックする
**挙動**: 記事タイトル（加は国名セル）を大文字化し、**まず対象 country 集合の国名で照合 MUST**、
一致しなければ**既知 country 全件へフォールバック MUST**。
一致しない、またはレベル 0 の項目は破棄 **MUST**。
**根拠**: travel_advisory.py:379-391・129-131・274-277
**検証**: 未検証
**分類**: CORE

### S1-SENSI-043: 引上げ判定は前回値との比較であり、前回値の既定は現在値である
**挙動**: `upgraded = (今回レベル > 前回レベル)` **MUST**。
前回値が未記録の country では**前回値に今回値を代入する MUST**
（= 初回観測では必ず `upgraded = False`）。前回値はソースごとに独立保持 **MUST**。
**根拠**: travel_advisory.py:77-80・132-142・289-300
**検証**: 未検証
**分類**: CORE（初回必ず False であること・前回値がプロセス内揮発であることは §6-A2 / §6-DP12）

### S1-SENSI-044: 多政府収斂は「レベル 3 以上を出しているソース数」で測る
**挙動**: country ごとに全ソースのレベルを集め、**最大レベルの項目を代表とする MUST**。
`convergence_count = レベル 3 以上を報告したソース数` **MUST**、
`converged = convergence_count ≥ 2` **MUST**。
報告ソースが 1 件のみでレベル 3 以上のときは**単一ソース警告フラグを立てる MUST**
（政治的動機による単独引上げの可能性を明示するため）。
1 ソースも報告しない country は、全ソースの前回値の最大をフォールバックレベルとし、
`upgraded = False` / `converged = False` / ラベル `UNKNOWN`（レベル 0 時）**MUST**。
**閾値**: 収斂ソース数 = 2、収斂対象レベル下限 = 3。ハードコード
**根拠**: travel_advisory.py:174-229
**検証**: 未検証
**分類**: CORE

### bg_observer_rss

### S1-SENSI-050: 既定無効であり、有効化は運用上の明示判断である
**挙動**: 本センサーは**既定で無効 MUST**。無効時の 1 サイクルは
「成功した no-op」として記録し、失敗カウンタを進めない **MUST**。
外向き HTTP トラフィックの追加は運用者の明示的な意思決定であるべき（OPSEC）。
**閾値**: `BG_OBSERVER_ENABLED` 既定 **false**（config.py:618）
**根拠**: bg_observer.py:52-62・84-90、background_observer.py:23-25・319-320
**検証**: tests/test_background_observer.py::test_tick_no_op_when_disabled
**分類**: CORE

### S1-SENSI-051: 走査は全 scorable シナリオの participant 和集合に対する broadcast である
**挙動**: 1 サイクルで全 feed を 1 回ずつ取得し、**取得した全項目を participant 和集合の
全 country に対して評価 MUST**。focused シナリオも和集合に含める **MUST**。
1 項目が複数 country に一致した場合、**country ごとに 1 信号を発行 MUST**
（シナリオ側の participant フィルタが振り分けを担う）。
**理由**: 取得コストは走査範囲に依存しないため、1 サイクル 1 country のラウンドロビンは
取得済みデータの 8/9 を捨てていた。改善は統計的ではなく構造的である。
participant が空のサイクルは理由コード付きで記録し、取得を行わない **MUST**。
**根拠**: background_observer.py:205-222・271-287・322-347
**検証**: tests/test_background_observer.py::test_broadcast_emits_one_signal_per_country_per_match /
test_broadcast_scope_respects_participant_union / test_broadcast_includes_focused_in_participant_union /
test_broadcast_records_no_participants_when_empty
**分類**: CORE

### S1-SENSI-052: LLM に依存せず、regex 抽出のみで動作する
**挙動**: 本センサーは **API キー・登録・LLM のいずれにも依存してはならない MUST NOT**。
決定論的な regex 抽出のみを用い、オフライン / LLM 不在の配備でも稼働 **MUST**。
**根拠**: background_observer.py:19-25
**検証**: tests/test_background_observer.py 全 18 件（fetcher と時計を注入してオフライン実行）
**分類**: CORE（NP3）

### S1-SENSI-053: 抽出の 3 段 confidence を raw_score に写像する
**挙動**: 抽出結果の confidence 段階に応じて信号の raw_score を決定 **MUST**:
```
conf ≥ 0.85（死者数あり）: raw_score = min(1.0, 0.4 + 0.05 × 死者数)
conf ≥ 0.60（kinetic 動詞のみ）: raw_score = 0.45
それ以外（escalation 動詞のみ）: raw_score = 0.25
```
信号のドメインは `info` 固定 **MUST**、`signal_source` は全信号で共通 **MUST**
（同一 country の複数記事がスコアリング層の dedup で 1 件に畳まれる）。
**閾値**: 0.4 / 0.05 / 1.0 / 0.45 / 0.25 すべてハードコード
**根拠**: background_observer.py:376-401、radar/conclusions/rss_extractor.py:353-407（段階の定義元）
**検証**: tests/test_rss_extractor.py（段階境界。抽出器本体は S1-conclusions 担当）
**分類**: CORE

### S1-SENSI-054: 信号は「キュー」ではなく「状態」の意味論を持つ
**挙動**: 発行された信号は TTL 窓の内側にある限り、**採点ティックが何回読んでも消えない MUST**
（読み取りは非消費、期限切れのみをその場で除去）。
同一 identity（signal_source + domain + country 群 + 証拠 URL または表示値）の再観測は
**重複追加せず、既存項目を除去して再追加することで TTL を滑らせる MUST**。
キュー長が上限に達したら**最古から破棄 MUST**。
**理由（2026-07-04 のストロボ回帰）**: 読み取りで空にする実装では信号の実効寿命が
「次の採点ティックまで」（≤2 分）になり、文書化された 30 分 TTL が虚構だった。
5 分の観測周期が 2 分の採点周期とエイリアシングし、info ドメインの寄与が明滅して
focused シナリオの TL が TL4↔TL5 を交互に往復した。
**閾値**: TTL = **1800s**（`BG_OBSERVER_SIGNAL_TTL_SEC`、config.py:620）、
キュー上限 = **200**（`BG_OBSERVER_MAX_QUEUE`、config.py:621）、
観測周期 = **300s**（`BG_OBSERVER_INTERVAL_SEC`、config.py:619）
**根拠**: background_observer.py:96-149
**検証**: tests/test_background_observer.py::test_active_signals_filters_stale /
test_active_signals_returns_fresh / test_active_signals_retains_buffer_within_ttl /
test_active_signals_visible_to_consecutive_ticks / test_active_signals_expire_after_ttl /
test_reenqueue_same_identity_slides_ttl_without_duplicating / test_distinct_identities_coexist /
test_max_queue_cap_evicts_oldest / **test_phase_alias_simulation_no_strobe**（回帰の番兵）
**分類**: CORE

### S1-SENSI-055: サイクルごとに監査行を永続化し、失敗が観測を止めない
**挙動**: 各サイクルで開始時刻 / 所要 / feed 試行数 / feed 失敗数 / 項目総数 /
country 一致数 / kinetic 一致数 / 死者数一致数 / 発行信号数 / country 別内訳 /
別名網羅ギャップ / 観測シナリオ一覧 / 中断理由、を 1 行として永続化 **MUST**。
**永続化の失敗はサイクルを壊してはならない MUST NOT**（黙って握りつぶす）。
個別 feed と個別項目の例外も同様に吸収 **MUST**。
別名網羅にギャップがあっても**処理を継続 MUST**（一部でも観測がある方が無いよりよい = NP1）。
**根拠**: background_observer.py:245-269・289-302・326-329・403-418
**検証**: tests/test_background_observer.py::test_cycle_log_records_per_gate_counters /
test_cycle_log_surfaces_alias_gap / test_cycle_log_counts_failed_feeds /
test_fetch_error_does_not_crash_cycle
**分類**: CORE（AP3 / AP4）

### S1-SENSI-056: 本センサーはスケジューラに統合されなければならない
**挙動**: **すべてのセンサーはサーキットブレーカーのスキップ判定を経て取得し、
成否をブレーカーへ通知 MUST**。broadcast 型センサーであっても例外としない **MUST**。
**現行挙動（DEFECT-PRESERVE）**: 本センサーは専用の daemon スレッドを持ち、
スケジューラの登録から明示的に除外されている。ループはブレーカーのスキップ判定を参照せず、
成否の通知も行わないため、**ブレーカーは永久に閉のままで開くことがない**。
docstring は「CB 統合は基底経由で維持」と主張するが実態と乖離している。
RSS 障害が継続しても取得抑制がかからない。
**根拠**: bg_observer.py:36-51・144-155、radar/__init__.py:295-306（`_SCHEDULER_BYPASS`）
vs radar/scheduler.py:119-147（`cb_should_skip` → fetch → `cb_record_success/failure`）
**検証**: 未検証（現行の迂回を pin するテストは無い）
**分類**: **DEFECT-PRESERVE**（D2 B-01。**v3 規範: スケジューラ統合 MUST**。
broadcast 型の取得対象解決はスケジューラ側の関心として設計すること）

---

## 6. LLM インテルセンサー個別条項

### diplomatic

### S1-SENSI-060: 公式発表の代替として集約ニュース検索 feed を用いる
**挙動**: 外務省系の一次 RSS が失われた場合、**country ごとの絞り込みクエリによる
ニュース集約 feed を代替として用いる SHOULD**。ウェブサイト改装に対して耐久性があり、
主要通信社による当該省庁の報道を拾えるため、下流 LLM が求める信号と等価である。
一次 feed が健全なソース（露国営メディア、DPRK 専門メディア）は**補完として併用 MUST**。
**根拠**: diplomatic.py:38-135（feed 台帳は付録 A）
**検証**: 未検証
**分類**: CORE

### S1-SENSI-061: 対象 country は全 scorable シナリオの participant 和集合である
**挙動**: 本センサーの走査対象は **focused シナリオの参加国ではなく、
全 scorable シナリオの participant 和集合 MUST**（ADR-004。background シナリオにも
LLM インテルが供給されるため）。和集合が空の場合は全 feed の全対象を走査 **MUST**。
feed の対象 country が 1 つも和集合に含まれない場合、その feed は取得しない **MUST**。
**根拠**: diplomatic.py:364-380、military_exercise.py:218-230、hacktivist_news_sensor.py:234-237、
rss_narrative.py:636-641
**検証**: 未検証
**分類**: CORE（gdelt / telegram / tor / travel / convergence は本規則に従っていない → §6-A4）

### S1-SENSI-062: 外交 item の score_delta は urgency の 4 段写像である
**挙動**: `score_delta` = critical 3.0 / high 2.0 / medium 1.5 / low 1.0 **MUST**
（既定 low = 1.0）。ドメインは `info` 固定 **MUST**。
LLM 抽出フィールドは外交行動種別 / 対象国 / urgency / 発信国 / 地理的焦点 / 関連度 **MUST**。
**根拠**: diplomatic.py:525-550
**検証**: 未検証
**分類**: CORE

### military_exercise

### S1-SENSI-070: 事象種別ゲートで「非事象」を捨て「定期報告」を減点する
**挙動**: LLM に事象種別（新規展開 / 演習開始 / 即応度上昇 / 定期報告 / 過去分析 / 該当なし）を
判定させ、**「該当なし」は破棄 MUST**。
**「定期報告」「過去分析」は破棄せず、confidence に上限を課して保持 MUST**
（自動確認はさせないが、アナリストのレビュー対象には残す = NP1）。
**閾値**: 定期報告 / 過去分析の confidence 上限 = **0.50**。ハードコード
**根拠**: military_exercise.py:294-302・335-349
**検証**: 未検証
**分類**: CORE

### S1-SENSI-071: score_delta は urgency 基礎値と規模ボーナスの加法である
**挙動**: `score_delta = urgency 基礎値 + 規模ボーナス` **MUST**。
基礎値 = critical 2.5 / high 2.0 / medium 1.5 / low 1.0、
ボーナス = strategic 0.5 / operational 0.2 / tactical 0.0。上限 3.0。
**根拠**: military_exercise.py:396-401
**検証**: 未検証
**分類**: CORE

### S1-SENSI-072: 本センサーの item は physical ドメインに計上される
**挙動**: 本センサーの item のドメインは **`physical` 固定 MUST**。
本センサーは情報系の RSS を入力とするが、報告対象が兵力の物理的展開であるため
physical に計上する。この値は **TL1 の physical スコア下限ゲートに直接効く**
（S1-SCORE-004 参照）ため、誤設定は最上位 TL の成立可否を左右する。
**根拠**: military_exercise.py:426
**検証**: 未検証
**分類**: CORE（RSS 由来の LLM 判定が最上位 TL のゲートに寄与する設計自体は §6-A6）

### hacktivist_intel

### S1-SENSI-080: 入力は他センサーの検知ログであり、新規 HTTP を発生させない
**挙動**: 本センサーは telegram の検知ログ全件を入力とし、**新たな外部 HTTP 取得を
行ってはならない MUST NOT**。キーワード事前フィルタを持たず、**全文を LLM に渡す MUST**
（`CLEAR` を除く全検知が対象）。
dedup 鍵は `検知時刻 + チャンネル + country` **MUST**。
本文（スニペット優先、無ければ全文抜粋）が空の項目は破棄 **MUST**。
**根拠**: hacktivist_intel_sensor.py:1-16・37-40・70-97
**検証**: 未検証
**分類**: CORE

### S1-SENSI-081: 主 country は LLM の判定を優先し、null は破棄する
**挙動**: LLM が主 country を null / "NULL" / "NONE" / 空で返した場合は**破棄 MUST**
（チャンネルのメタデータへフォールバック**してはならない MUST NOT**）。
LLM の返した値が**2 文字の英字なら、チャンネルのメタデータを上書きして採用 MUST**。
**根拠**: hacktivist_intel_sensor.py:172-186
**検証**: 未検証
**分類**: CORE（8 系統中、唯一の「LLM 上書き採用」規則 → §4 表 2）

### S1-SENSI-082: ドメインは攻撃種別から写像する
**挙動**: 攻撃種別が DDoS / defacement / flood / disruption のいずれかを含めば `cyber`、
それ以外（データ漏洩 / フィッシング等）は `info` **MUST**。
`score_delta = 標的セクター基礎値 + タイムライン加算`、**上限 3.0 でクリップ MUST**。
基礎値 = 政府 / 金融 / エネルギー / 通信 / 軍のいずれかを含めば 2.0、それ以外 1.0。
加算 = imminent 1.0 / soon 0.5 / planned 0.2 / それ以外 0.0。
**根拠**: hacktivist_intel_sensor.py:188-201
**検証**: 未検証
**分類**: CORE

### hacktivist_news

### S1-SENSI-090: 「観測者の観測」層としてキーワード必須の事前フィルタを持つ
**挙動**: セキュリティ報道 feed に対し、**ハクティビスト関連キーワードの一致を必須とする MUST**
（一致しない記事は LLM に渡さない）。マーケティング語彙は先に棄却 **MUST**。
本文の HTML タグは除去 **MUST**。feed あたりの採用上限 5 件 **MUST**。
**根拠**: hacktivist_news_sensor.py:65-90・183-208
**検証**: 未検証
**分類**: CORE

### S1-SENSI-091: 主 country が対象集合外の item は破棄する
**挙動**: LLM が返した主 country が対象 country 集合に含まれない場合、**破棄 MUST**。
**現行の特異性**: 8 系統中、本センサーのみがこの追加ゲートを持つ。
プロンプトでは「対象リストは文脈であり、リスト外でも ISO コードを返せ、
フィルタリングは system 側が行う」と指示しているため、
**LLM に無駄な生成をさせた上で Python 側が捨てている**構造になっている。
**根拠**: hacktivist_news_sensor.py:331-336（プロンプト）vs :395-401（破棄）
**検証**: 未検証
**分類**: ACCIDENTAL（§6-A9）

### S1-SENSI-092: score_delta は urgency 基礎値と攻撃種別ボーナスの加法である
**挙動**: 基礎値 = critical 2.0 / high 1.5 / medium 1.0 / low 0.5、
ボーナス = DDoS 0.5 / combined 0.5 / defacement 0.3 / data_leak 0.2 / none 0.0。
ドメインは `info` 固定 **MUST**（telegram 由来の hacktivist_intel が cyber に落ちうるのと非対称）。
**根拠**: hacktivist_news_sensor.py:417-424・449
**検証**: 未検証
**分類**: CORE

### ground_osint

### S1-SENSI-100: 対象は「進行中」を示す検知に絞り込む
**挙動**: 検知ログのうち状態が `INTENT_DETECTED` / `TARGETS_FOUND` / `BURST` /
`CRITICAL_BURST` のいずれかである項目のみを対象 **MUST**。
さらに**標的 URL が存在するか、進行中を示す語彙を含むか、標的が 2 件以上あること MUST**。
進行中語彙は英語・日本語の両方を含む **MUST**。
**根拠**: ground_osint_sensor.py:36-58・136-148
**検証**: 未検証
**分類**: CORE

### S1-SENSI-101: 宣言はライブセンサーとの照合で裏付けを測る
**挙動**: telegram 上の攻撃宣言を、**同時刻のライブセンサー観測と照合 MUST**。
照合条件は `裏付けあり = (CF の当該 country の攻撃記録が非空) OR (到達性成功率 < 0.7)` **MUST**。
照合結果は LLM プロンプトの文脈として渡すが、
**LLM には「文脈のセンサー情報を判断に混ぜるな」と明示 MUST**（循環論法の防止）。
裏付けがあり、かつ LLM の confidence がフロア以上のときのみ、
**Python 側で一度だけ confidence を加算 MUST**、上限でクリップ **MUST**。
**閾値**: 到達性劣化閾値 = **0.7**、加算 = **+0.10**、加算後上限 = **0.95**。すべてハードコード
**根拠**: ground_osint_sensor.py:84-104・166-168・216-217・231-235
**検証**: 未検証
**分類**: CORE

### S1-SENSI-102: 照合に用いる他センサー観測は鮮度と健全性を検証しなければならない
**挙動**: 他センサーの観測を相関判定に用いる場合、
**その観測の鮮度（最終取得時刻）と健全性（health 状態）を検証 MUST**。
劣化・失効した観測に基づく相関判定は**行ってはならない MUST NOT**、
行えない場合は「照合不能」として明示 **MUST**（NP5+8: 結論不可の明示）。
**現行挙動（DEFECT-PRESERVE）**: 参照先センサーの cache を無検証で読み、
STALE / ERROR / CIRCUIT_OPEN のいずれであっても**成功時と同じ経路で「裏付けなし」と判定する**。
参照先の取得順序にも暗黙に依存する。結果として、相関検知能力の劣化が完全に沈黙する。
**根拠**: ground_osint_sensor.py:67-104（health 未参照の cache 直読）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 B-03。**v3 規範: 入力鮮度検証 MUST**。
クロスセンサー参照は公式化された API を通し、鮮度と健全性を返り値に含めること）

### S1-SENSI-103: score_delta は「進行中」と「裏付け」の 2 条件で 3 段に決まる
**挙動**: 進行中 かつ 裏付けあり → **3.0**、いずれか一方 → **2.0**、宣言のみ → **1.0** **MUST**。
裏付けは LLM の自己申告と Python 側の照合結果の**論理和 MUST**。
`countries` は主 country 単一・重み 1.0 **MUST**（本センサーは LLM に多国抽出をさせない）。
ドメインは `cyber` 固定 **MUST**。
**根拠**: ground_osint_sensor.py:242-253・276
**検証**: 未検証
**分類**: CORE

### convergence_tracker

### S1-SENSI-110: 監視対象 8 センサーの elevation 判定は個別規則である
**挙動**: 以下の規則で各センサーの elevation を判定 **MUST**（判定中の例外は「非 elevation」）:

| センサー | elevation 条件 |
|---|---|
| rss_narrative | 当該 country の `is_burst` が真 |
| telegram_mirror | `is_burst` が真 **または** 攻撃意図フラグが真 |
| gdelt | Z-score > **1.5**、または トーン差分 < **−2.0** |
| diplomatic / military_exercise / apt_intel | 直近サイクルの投入件数 > 0 |
| ioda | 停止フラグが真、または停止スコア > **0.3** |
| bgp_routing | 異常フラグが真 |

**閾値**: 1.5 / −2.0 / 0.3 すべてハードコード（convergence_tracker.py:113-153）
**根拠**: convergence_tracker.py:20-28・113-166
**検証**: 未検証
**分類**: CORE

### S1-SENSI-111: スナップショットは非 elevation でも毎サイクル記録する
**挙動**: 各サイクルで country ごとに「今 elevation しているセンサー名の一覧」を
**空リストであっても記録 MUST**（連続的な履歴が持続判定の分母になるため）。
保持期間を超えた行は毎サイクル削除 **MUST**。
**閾値**: 保持 = **72 時間**（`CONVERGENCE_SNAPSHOT_RETENTION_H`、環境変数のみ）、
取得周期 = 3600s（`CONVERGENCE_TRACKER_INTERVAL`、環境変数のみ）
**根拠**: convergence_tracker.py:44-47・85-108・189・204-205
**検証**: 未検証
**分類**: CORE

### S1-SENSI-112: 持続収斂は「窓内スナップショットの過半で elevation」が閾値本数以上のとき成立する
**挙動**: 判定窓（現在から遡って持続時間分）のスナップショットを取得 **MUST**。
**スナップショットが 2 件未満のときは収斂不成立 MUST**（判定材料不足）。
各センサーについて窓内で elevation していたスナップショット数を数え、
`最小ヒット数 = max(1, floor(スナップショット数 / 2))` 以上のセンサーを
**「持続 elevation」とする MUST**。持続 elevation センサー数が閾値本数以上のとき収斂成立 **MUST**。
```
sustained = { s | count(s) ≥ max(1, ⌊N/2⌋) }        N = 窓内スナップショット数
converged = |sustained| ≥ CONVERGENCE_MIN_SENSORS
```
**単発スパイクを収斂と誤認させないための過半数条件は必須 MUST**。
**閾値**: 最小センサー本数 = **3**（`CONVERGENCE_MIN_SENSORS`、環境変数のみ）、
持続時間 = **6 時間**（`CONVERGENCE_MIN_HOURS`、環境変数のみ）。**いずれも DB override 不可**
**根拠**: convergence_tracker.py:45-46・186・207-230
**検証**: 未検証（**D5 §4.2 が「特に危険」と名指しした無テスト検知式**）
**分類**: CORE

### S1-SENSI-113: 収斂成立時の警報は country ごとに 24 時間のクールダウンを持つ
**挙動**: 収斂が成立していても、同一 country の前回警報から**クールダウン未経過なら
LLM 合成を行わない MUST**。クールダウンの記録は**投入に成功したときのみ更新 MUST**
（LLM が雑音と判定した場合は再試行の余地を残す）。
**閾値**: クールダウン = **86400 秒**。ハードコード・**プロセス内 in-memory・再起動で消失**
**根拠**: convergence_tracker.py:49-51・235-247
**検証**: 未検証
**分類**: CORE（揮発は §6-DP4）

### S1-SENSI-114: LLM 合成には各センサーの実データを文脈として与える
**挙動**: LLM に渡すのは**センサー名の羅列ではなく、各センサーの実測値または実際の見出し MUST**
（Z-score 値、トーン差分、直近インテル見出し、チャンネル状態、停止スコア等）。
名前だけでは合成の材料が無く、モデルが一般論を生成するため。
**現行の特異性**: 見出しの取得は**インテル台帳を直接読む**ことで行われている
（センサー層がスコアリング層管轄のデータを参照する越境）。
**根拠**: convergence_tracker.py:259-310（うち :265・:284-288 が台帳直読）
**検証**: 未検証
**分類**: CORE（台帳直読の構造は §6-DP10 / D2 A-09）

### S1-SENSI-115: 合成結果は confidence と pattern 種別の両方でゲートする
**挙動**: confidence が **0.50 未満、または pattern 種別が「雑音収斂」の場合は投入しない MUST**。
プロンプトには**「情報ドメインの信号（ナラティブ escalation、影響工作）は物理・サイバーと
同等に扱え」と明示 MUST**（情報信号は物理行動に先行する早期指標であるため）。
`score_delta = urgency 基礎値 + センサー本数ボーナス` **MUST**:
基礎値 = critical 3.0 / high 2.5 / medium 2.0 / low 1.5、
ボーナス = `min((持続センサー数 − 最小本数) × 0.2, 1.0)`。合成上限 4.0。
**根拠**: convergence_tracker.py:358-366・379-392
**検証**: 未検証
**分類**: CORE

### S1-SENSI-116: 本センサーの item ドメインは LLM 出力に従う
**挙動**: item のドメインは LLM が返す支配的ドメインをそのまま用いる **MUST**。
許容集合は cyber / physical / info / **mixed** であり、既定は mixed。
**`mixed` は 3 ドメイン語彙に存在しない値**であり、S1-INGEST-029 の
「domain は 3 値のいずれか」規範に反する。
**根拠**: convergence_tracker.py:394-396・423
**検証**: 未検証
**分類**: ACCIDENTAL（§6-A5）

### S1-SENSI-117: 永続化はシステムの単一の永続層管轄下になければならない
**挙動**: センサーが生成する状態は、**バックアップ・WAL 運用・スキーマ管理の対象である
単一の永続層を経由 MUST**。
**現行挙動（DEFECT-PRESERVE）**: 本センサーは共通永続層を経由せず、
専用の SQLite ファイルを直接開いてスナップショットを保持する。
このファイルはバックアップ運用・WAL 規律・スキーマ移行の管轄外に置かれている。
**根拠**: convergence_tracker.py:54-110（`sqlite3.connect` 直呼び）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 A-09。**v3 規範: 永続層の単一管轄 MUST**。
メタセンサーの層所属は P で定義する）

---

## 7. 閾値カタログ

| 閾値 | 値 | config キー | 3 層解決 | 出典条項 |
|---|---|---|---|---|
| GDELT 履歴窓 | 28 日 | `GDELT_HISTORY_WINDOW` | DB override 可 | S1-SENSI-001 |
| GDELT トーン絶対閾値 | −15.0 | `GDELT_TONE_ALERT_THRESHOLD` | DB override 可 | S1-SENSI-004 |
| GDELT DOW Z 下限 | −2.0 | — | 不可 | S1-SENSI-004 |
| GDELT DOW 最小サンプル / std フロア | 3 / 0.5 | — | 不可 | S1-SENSI-003 |
| GDELT 曜日別保持上限 | 20 (×7) | — | 不可 | S1-SENSI-002 |
| ナラティブ Z ALERT / CRITICAL | 2.0 / 3.0 | `NARRATIVE_ZSCORE_ALERT` / `_CRITICAL` | DB override 可 | S1-SENSI-016 |
| ナラティブ初回信号 Z | 3.0 | `NARRATIVE_ZSCORE_FIRST_SIGNAL` | **env のみ** | S1-SENSI-014 |
| ナラティブ保持日数 | 30 | `NARRATIVE_BASELINE_DAYS` | DB override 可 | S1-SENSI-015 |
| ナラティブ最小サンプル | 7 | — | 不可 | S1-SENSI-014 |
| ナラティブ LLM プール / ソース別収集 | 6 / 2 | — | 不可 | S1-SENSI-017 |
| Telegram 投稿鮮度窓 | 48h | `TELEGRAM_POST_MAX_AGE_HOURS` | env のみ | S1-SENSI-022 |
| Telegram 取得周期 | 900s | `TELEGRAM_MIRROR_POLL_INTERVAL` | registry 登録あり | D1 §1 |
| Telegram 本文長下限 / 再試行 / 待機上限 | 2000B / 3 / 30s | — | 不可 | S1-SENSI-020/021 |
| Telegram 主張確度 3 段 | 0.6 / 0.4 / 0.2 | — | 不可 | S1-SENSI-027 |
| Telegram 検知ログ上限 | 200 | — | 不可 | S1-SENSI-028 |
| Tor relay 減少 / 利用者急増 / DROP | 0.40 / 1.00 / −0.3 | — | 不可 | S1-SENSI-030 |
| 渡航勧告 収斂ソース数 / 対象レベル | 2 / 3 | — | 不可 | S1-SENSI-044 |
| bg_observer 有効化 | false | `BG_OBSERVER_ENABLED` | env のみ | S1-SENSI-050 |
| bg_observer 周期 / TTL / キュー上限 | 300s / 1800s / 200 | `BG_OBSERVER_INTERVAL_SEC` / `_SIGNAL_TTL_SEC` / `_MAX_QUEUE` | env のみ | S1-SENSI-054 |
| bg_observer raw_score 3 段 | 0.4+0.05n / 0.45 / 0.25 | — | 不可 | S1-SENSI-053 |
| LLM confidence フロア | 0.35（7 系統） / 0.50（収斂） | — | 不可 | S1-INGEST-024 |
| LLM 間接関連度 上限 | 0.45（外交） / 0.50（軍事演習） | — | 不可 | S1-INGEST-027 |
| LLM max_tokens | 200 / 250 / 256 / 280 / 300 / 400 / 512 | — | 不可 | §4 表 2 |
| 記事 dedup 上限 | 1000 / 500 | — | 不可 | S1-INGEST-008 |
| 記事鮮度窓 | 48h / 168h | — | 不可 | S1-INGEST-005 |
| 収斂 最小センサー本数 / 持続時間 | 3 / 6h | `CONVERGENCE_MIN_SENSORS` / `_MIN_HOURS` | **env のみ** | S1-SENSI-112 |
| 収斂 スナップショット保持 / クールダウン | 72h / 86400s | `CONVERGENCE_SNAPSHOT_RETENTION_H` / — | env のみ / 不可 | S1-SENSI-111/113 |
| 収斂 elevation 閾値（gdelt / ioda） | 1.5 / −2.0 / 0.3 | — | 不可 | S1-SENSI-110 |
| ground_osint 到達性劣化 / 加算 / 上限 | 0.7 / +0.10 / 0.95 | — | 不可 | S1-SENSI-101 |

**v3 への示唆**: 本領域だけで**ハードコード閾値 30 件超、env のみ 8 件**。
S1-scoring-core の DP2 と同じ問題であり、**検知に影響する全閾値を宣言的 registry へ載せる MUST**
（NP6）。特に S1-SENSI-112 の収斂式は「結論に直接効く 2 閾値がともに env のみ・無テスト」である。

---

## 8. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | Tor / 渡航勧告の前サイクル値の既定が「現在値」。初回観測は必ず変化なしと判定される | 起動直後〜1 サイクルは原理的に検知不能。NP1 上、初回を「判定不能」として明示すべきでは |
| A2 | 渡航勧告の引上げ判定がソースごとの独立 in-mem。再起動で全 country が初回状態に戻る | 上と同根。永続化すべきか |
| A3 | 英 FCDO パーサの最終フォールバック「本文に `travel` を含めばレベル 2」 | 渡航勧告 feed の記事はほぼ全て `travel` を含む。実質「不明 = レベル 2」であり、収斂カウントの分母を汚す |
| A4 | 対象 country の解決規則が 2 系統に分裂。LLM 系 4 基は participant 和集合、gdelt / telegram / tor / travel / convergence の 5 基は focused の対象のみ | C-lite（background も採点する）契約と不整合。background シナリオの country は統計系センサーのベースラインが育たない |
| A5 | 収斂センサーの item ドメインに `mixed` が入りうる（3 ドメイン語彙外） | S1-INGEST-029 違反。スコアリング層でどう扱われるかを含めて裁定要 |
| A6 | 軍事演習センサー（RSS + LLM 判定）の item が physical に計上され、TL1 の physical ≥ 3.0 ゲートに寄与する | 最上位 TL の成立に「ニュース記事の LLM 判定」が効いてよいか。NP4 と NP5+8 の緊張点 |
| A7 | GDELT の標準偏差フロア 0.5 がハードコード | トーンのスケール依存。値の由来が記録されていない |
| A8 | ナラティブ初回信号 Z = 3.0 が環境変数のみで config registry 非登録 | NP1 に直結する値（無音期からの立ち上がり検知）が導出開示の外にある |
| A9 | hacktivist_news のみ「主 country が対象集合外なら破棄」。プロンプトは逆を指示している | 8 系統で唯一の非対称。プロンプトと実装が矛盾しており、どちらが意図か |
| A10 | bg_observer が「取得成功だが 0 件」を feed 失敗として計上する | 静かな feed と壊れた feed が同一カウンタに乗る。AP3 の feed 死活可視化の精度 |

---

## 9. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | bg_observer が専用スレッドで動きサーキットブレーカーを迂回。ブレーカーは永久に閉 | 全センサーはスケジューラ経由 **MUST**。broadcast 型の対象解決はスケジューラの関心 | **B-01** |
| DP2 | ground_osint が参照先センサーの鮮度・健全性を検証せず相関判定。劣化が沈黙 | クロスセンサー参照は公式 API 経由・鮮度と健全性を返り値に含める **MUST** | **B-03** |
| DP3 | 収斂センサーが共通永続層外の専用 SQLite を持つ | 永続層の単一管轄 **MUST** | **A-09** |
| DP4 | 収斂センサーの警報クールダウンがプロセス内 in-memory。再起動直後に重複警報しうる | 運用状態は永続化 **MUST** | B-05 |
| DP5 | ナラティブの burst 投入済み集合、および 6 系統の記事 dedup 集合がすべて in-memory | 同上 | B-05 |
| DP6 | telegram のベースラインがクラス変数 in-memory。かつ**保持上限が「日数」の生値**（30 サンプル = 実質 15 時間窓）。同型と自己申告する rss_narrative は 2026-04-29 に `日数 × 1 日あたり回数` へ修正済で、telegram には反映されていない | ベースライン基盤の一元化 **MUST**。窓長は時間で定義し取得周期から導出 **MUST** | **A-03**（本仕様で新規発見。片側だけ修正された複製の典型） |
| DP7 | RSS 取得・パースが 6 系統に複製。2 段パースと死活分類は 1 系統のみ、timeout / UA / 429 扱い / 対応形式 / 鮮度窓がすべて系統ごとに異なる（§4 表 1） | 単一の取得層 **MUST**（S1-INGEST-001〜010） | A-02 |
| DP8 | LLM 投入骨格が 8 系統に複製。max_tokens 200〜512、主 country 規則 4 通り、domain 決定主体 4 通り（§4 表 2） | 単一の投入層 + 4 スロットのみセンサー固有 **MUST**（S1-INGEST-020〜030） | A-02 |
| DP9 | 対象 12 基すべてが基底の HTTP ヘルパー（timeout / 429 自動処理）を使わず raw HTTP を直呼び | 取得は共有層のみを経路とする **MUST** | A-10 |
| DP10 | 収斂センサーがインテル台帳を直接読む（センサー層 → スコアリング層管轄データ） | メタセンサーの層所属を P で定義し、参照は公式 API 経由 **MUST** | A-09 |
| DP11 | intel item のキー名 `theater` が主 country の意味で残存。センサー内部変数・検知ログのキーも同様 | 語彙は country / scenario で統一 **MUST** | C-01 |
| DP12 | tor / 渡航勧告 / ナラティブの前サイクル値・ベースラインが in-memory | ベースライン基盤の一元化 **MUST** | A-03 |
| DP13 | hacktivist_news が diplomatic の private 関数を関数内 import して死活分類を借用 | 共有層で解消 **MUST** | A-02 |

---

## 10. テストトレーサビリティ

| テスト | 件数 | 対応条項 |
|---|---|---|
| tests/test_rss_narrative.py::TestClassifyArticleGeo | 14 | S1-SENSI-012 |
| ::TestCountKeywordsGeoFilter | 4 | S1-SENSI-011 / -012 / -013 |
| ::TestGetBurstArticlesGeoFilter | 2 | S1-SENSI-012 / -017 |
| ::TestGeoFilterIntegration | 1 | S1-SENSI-012 |
| ::TestBaselineRetention | 3 | S1-SENSI-014 / -015 |
| tests/test_background_observer.py（無効時 no-op / broadcast 4 件） | 5 | S1-SENSI-050 / -051 |
| ::cycle log 系 4 件 | 4 | S1-SENSI-055 |
| ::TTL / identity / キュー上限 / ストロボ回帰 8 件 | 8 | S1-SENSI-054 |
| ::test_fetch_error_does_not_crash_cycle | 1 | S1-SENSI-052 / -055 |
| tests/test_apt_prompt_dedup.py | 4 | S1-INGEST-022（apt_intel 個別は S1-sensors-cyber-phys 担当） |
| tests/test_engine.py::TestTorMetricsSensor | 5 | S1-SENSI-030 / -031 / -032（うち 3 件は本番関数を呼ばない） |
| tests/test_rss_extractor.py | 56 | S1-SENSI-053（段階境界のみ。抽出器本体は S1-conclusions 担当） |
| tests/test_sanitize_llm_input.py | — | S1-INGEST-021（関数本体は S4 担当） |
| tests/test_intel_multicountry.py | 12 | S1-INGEST-025（検証面は intel_queue 側 = 別担当） |

### GAP（仕様化できたが検証が存在しない）

| ID | 内容 |
|---|---|
| GAP-01 | **gdelt の DOW ベースライン式全体**（日バケット記録・同曜日集計・std フロア 0.5・Z 下限 −2.0）が無テスト |
| GAP-02 | **telegram の Z-score / 状態ラダー / 主張確度 4 段 / 検知ログ dedup** が全て無テスト。ベースライン窓の欠陥（DP6）も無テスト |
| GAP-03 | **渡航勧告 3 パーサ**（米 / 英 / 加 HTML + アイコンフォールバック）と収斂集計が無テスト |
| GAP-04 | **収斂センサーの持続昇格式**（過半数条件・≥3 センサー・≥6h 窓・クールダウン）が無テスト。D5 が「特に危険」と名指しした 5 件のうち 2 件が本書の対象 |
| GAP-05 | **LLM 投入経路 6 系統**（diplomatic / military_exercise / hacktivist_intel / hacktivist_news / ground_osint / convergence_tracker）が全て無テスト。confidence 上限規則・主 country 破棄規則・score_delta 式のいずれも pin されていない |
| GAP-06 | tor_metrics のテスト 5 件中 3 件が**本番関数を呼ばずインライン再実装**（S1-scoring-core §6 の同種問題と同じ。実装を変えてもテストが通る） |
| GAP-07 | rss_narrative は geo filter とベースライン保持のみテスト済。**Z-score 式・burst 閾値・クラスタ解析・legacy fallback** は無テスト |
| GAP-08 | 共通条項 S1-INGEST-001〜010 / -020〜030 のうち、テストで pin されているのは -021 / -022 / -025 の 3 件のみ |

---

## 11. 未決事項

1. **メタセンサー 2 基（convergence_tracker / ground_osint）の層所属**が仕様レベルで未確定。
   入力が他センサーの cache とインテル台帳であり、「センサー」の定義（外部からデータを取得する）
   に当てはまらない。P で「派生指標」層を定義するか、スコアリング層へ移すかの判断が要る
2. **S1-SENSI-112 の持続収斂式と S1-SCORE-003/006 のドメイン収斂の関係が未定義**。
   前者は「≥3 センサー × ≥6h」、後者は「≥2 ドメインの同時発火」で、
   独立に TL へ寄与しうる（収斂センサーの item が intel 経由でドメインスコアに入る）。
   **同一の物理事象が 2 経路で計上される可能性**があり、S1-SCORE-008 の dedup が
   これを捕捉するかは未検証
3. `bg_observer_rss` を既定有効にするかは**オーナー判断事項**。
   現状 false であるため、C-lite の background 観測供給は実質 LLM インテル 4 基のみに依存している
4. 対象 12 基のうち 10 基が無テストのため、本書の条項の大半は**コード読解のみが根拠**。
   docstring と実装の乖離（D2 E-18 の系譜）が本領域にも存在する可能性は排除できていない。
   特に telegram.py:275 の「rss_narrative と同じロジック」という自己申告は **DP6 で偽と判明済**
5. `apt_intel` は Cyber 分類のため個別条項を持たないが、**LLM 投入の 8 複製の 1 つであり
   唯一の 2 段ゲート構造**（Stage 1 で戦略的関連性と地理的標的を判定 → Stage 2 で本分析）を持つ。
   共通投入層の設計時に「2 段ゲートを共通仕様に含めるか、apt_intel 固有とするか」の裁定が要る

---

## 付録 A: feed 死活台帳（外部 API 知識の保存 — D1 §4 の資産）

2026-04-18 / 2026-04-29 の 2 回の実地監査記録。**この情報はコメントと分岐にしか存在しない**。

| feed | 監査結果 | 対処 |
|---|---|---|
| US_STATE `state.gov/press-releases/feed/` | `returns_html`（URL 陳腐化） | ニュース集約検索クエリへ置換 |
| JP_MOFA `mofa.go.jp/rss/rss.xml` | 404 / WAF 403（コンテナの DC-IP 由来） | 同上 |
| CN_MFA `fmprc.gov.cn/mfa_eng/rss.xml` | `returns_html`（RSS 廃止） | 同上 |
| TW_MOFA `en.mofa.gov.tw/rss.aspx` | `returns_html`（SPA 移行） | 同上 |
| RU_MFA `mid.ru/en/rss.xml` | `returns_html`（破損 / geo-block） | TASS 一次 feed + 集約検索の 2 系統へ |
| KCNA_WATCH `kcnawatch.org/feed/` | `rss_empty`（間欠） | 保持（復活監視）+ NK News で補完 |
| NATO `nato.int/cps/en/natolive/news_rss` | 404（RSS 廃止） | 集約検索クエリへ置換 |
| CISA | `/cybersecurity-advisories/` へ移転（2026-04 監査） | URL 更新済 |
| JPCERT | 英語 RSS 廃止、`.rdf`（RSS 1.0）のみ存続 | RDF 名前空間対応で維持 |
| ENISA | RSS 廃止 | 削除（silent failure を残さない方針） |
| BSI | CERT-Bund WID エンドポイントへ移転 | URL 更新済 |
| ACSC `cyber.gov.au` | 非 AU IP を geo-block | 削除 |
| 一次 MFA feed 全般 | 7 本すべてが retire / 非 RSS 化 | **代替戦略: country 別ブーリアンクエリの
ニュース集約 RSS。サイト改装に耐え、1 クエリ 30-100 件を返す** |

**保存すべき運用知**:
- 死んだ feed も**設定から消さない**（別ネットワーク環境からの再試行余地・復活検知のため）
- `t.me/s/` スクレイプは UA プールローテーション + 403/429 指数バックオフ 3 回。
  失敗は「プレビュー無効化 / スロットリング / ネットワーク断」の 3 モードを区別する
- courtesy delay: GDELT 0.5s（country 間）、Onionoo 0.5s（リクエスト間）、
  Telegram 1.5-4.0s 無作為（チャンネル間）
- GDELT のトーンには**曜日バイアスがある** → 曜日別ベースラインが必須
- 渡航勧告は **3 政府 3 形式**（米 RSS / 英 Atom / 加 HTML テーブル + SVG アイコン名）
