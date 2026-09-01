# S1 — Information / LLM インテルセンサー 挙動仕様

**スコープ**: Information 6 基（gdelt / rss_narrative / telegram_mirror / tor_metrics /
travel_advisory / bg_observer_rss）、LLM インテル 6 基（diplomatic / military_exercise /
hacktivist_intel / hacktivist_news / ground_osint / convergence_tracker）、および
**共通 RSS 取得・パース基盤**と**共通 LLM intel 投入基盤**の統合仕様。

**隣接仕様書との境界**:
- **intel_queue の `submit()` 以降**（dedup / credibility / auto-confirm tier / 台帳書込）は**対象外**。
  本書はセンサーが投入する item のエンベロープと、その値を決める式までを扱う
- Cyber / Physical 個別は S1-sensors-cyber-phys 担当。`apt_intel`（Cyber 分類だが LLM 投入 8 複製の 1 つ）は
  **§4 表 2 にのみ登場**し、個別条項を持たない
- cache → RationaleEntry 変換、ミュート／suppression、`register_sequence_event` はスコアリング層
  （S1-scoring-pipeline）担当。本書は `set_cache` に置く値までを規定する
- BaseSensor の health / CB / fetch_log 共通契約は S1-sensor-base 担当。本書は**逸脱のみ**を条項化する
- `radar/conclusions/rss_extractor.py` の抽出規則本体は S1-conclusions 担当

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソースについて**: 対象 12 基のうち**直接テストがあるのは 2 基のみ**（rss_narrative の geo filter、
bg_observer_rss の委譲先）。残り 10 基は D5 §4.2 の判定どおり**コード読解のみが根拠**であり、
条項の「検証」欄は大半が `未検証` になる。これは仕様の弱さではなく現行系の検証カバレッジの穴の
忠実な記録であり、S5 のテスト移植計画への入力である。

## 1. 用語

CLAUDE.md の用語定義に従う。本書固有:
- **feed**: 1 本の RSS/Atom エンドポイント。センサー 1 基が複数 feed を持つ
- **feed 死活クラス**: feed 応答の 5 値分類（S1-INGEST-003）。HTTP ステータスとは別概念
- **intel item**: センサーが LLM 解析結果として intel_queue へ渡す 1 レコード（S1-INGEST-019）
- **elevation**: メタセンサーが「あるセンサーがある country で警戒状態にある」と判定した状態
- **normalized frequency**: キーワード出現数を記事数（または走査チャンネル数）で割った値。Z-score の入力
- **intercept log**: telegram_mirror がクラス変数に持つ検知リングバッファ。hacktivist_intel / ground_osint の入力
- 旧用語 `theater` は現行コードと**データ契約（intel item のキー名）に残存**。規範文では country /
  scenario を用い、残存は §9-DP11 として記録する

## 2. 共通 RSS 取得・パース仕様

現行は 6 系統に複製（§4 表 1）。以下は**あるべき単一仕様**として記述する。
### S1-INGEST-001: RSS 取得は単一の HTTP 契約に従う
**挙動**: GET のみを用い **timeout 必須 MUST**、プロキシと TLS 検証設定を全 feed で共有 **MUST**。HTTP 200 のみ成功として本文を返し、非 200 は空文字列 + ステータスをログ記録 **MUST**。例外時も空文字列を返し、**サイクルを中断してはならない MUST NOT**。閾値: timeout 15s（diplomatic / apt_intel / military_exercise / hacktivist_news / bg_observer）、10s（rss_narrative）。config キー無し
**根拠**: diplomatic.py:172-185、rss_narrative.py:134-145、background_observer.py:159-175
**検証**: 未検証
**分類**: CORE（timeout 値の分散は §9-DP7）
### S1-INGEST-002: RSS のパースは strict → tolerant の 2 段でなければならない
**挙動**: (1) 安全な strict パーサ、(2) 失敗時に**回復モードの寛容パーサ**、の順で試行 **MUST**。両方失敗時のみ「パース不能」とする **MUST**。strict 失敗を**空記事リストとして黙って返してはならない MUST NOT**。理由: 2026-04-29 の実地監査で KCNA_WATCH を除く全外交 feed が strict で失敗しており、当時のコードは feed 破損をフィルタ空振りとして記録していた
**根拠**: diplomatic.py:199-222（2 段）vs apt_intel.py:218-222 / military_exercise.py:140-144 / hacktivist_news_sensor.py:124-128 / rss_narrative.py:168-172（strict のみ）
**検証**: 未検証
**分類**: DEFECT-PRESERVE（6 系統中 1 系統のみ 2 段 → §9-DP7 / D2 A-02）
### S1-INGEST-003: feed 死活は 5 クラスに分類して記録し、死んだ feed も設定に残す
**挙動**: feed 応答を `rss_with_items` / `rss_empty` / `returns_html` / `unparseable` / `unknown` に分類し、記事 0 件時の理由として記録 **MUST**。判定順は (1) 本文先頭が HTML 宣言 → `returns_html`、(2) 2 段パース不能 → `unparseable`、(3) ルートが RSS/Atom → item/entry の有無で `rss_with_items` / `rss_empty`、(4) 他 → `unknown` **MUST**。「健全な feed だがフィルタが全棄却」は**別の理由コード MUST**（URL 陳腐化と基準率の低さの取り違え防止）。継続失敗 feed も**設定から除去してはならない SHOULD NOT**（別ネットワークからの再試行余地と復活検知のため、付録 A）
**根拠**: diplomatic.py:225-259（分類器）、diplomatic.py:394-406 / hacktivist_news_sensor.py:262-280（消費側）、diplomatic.py:38-65・104-110（保持方針）
**検証**: 未検証
**分類**: CORE
### S1-INGEST-004: 記事はタイトル正規化キーで feed 内 dedup する
**挙動**: タイトルを小文字化し**先頭 60 文字を取り英数字以外を除去した文字列**を dedup キーとする **MUST**。同一 feed 内で既出キーの記事は棄却 **MUST**。キーが空（タイトル無し・記号のみ）の記事は dedup 対象外として通過 **MUST**
**根拠**: diplomatic.py:296-300、military_exercise.py:163-167、apt_intel.py:259-263、hacktivist_news_sensor.py:159-163、rss_narrative.py:191-195
**検証**: 未検証
**分類**: CORE（6 系統で完全一致している唯一の共通ロジック）
### S1-INGEST-005: 記事の鮮度カットオフは fail-open である
**挙動**: 公開日時が解析でき、かつカットオフより古い場合のみ棄却 **MUST**。**日時が欠落または解析不能な記事を棄却してはならない MUST NOT**（NP1）。解析は RFC 2822 → ISO 8601 の順 **SHOULD**。閾値: 鮮度窓 48h（diplomatic / military_exercise / hacktivist_news）、168h（apt_intel）。引数既定値としてハードコード
**根拠**: diplomatic.py:278・302-312、apt_intel.py:224・265-279、hacktivist_news_sensor.py:130・165-181
**検証**: 未検証
**分類**: CORE
### S1-INGEST-006: 記事の選抜はスロット制で上限を持つ
**挙動**: feed ごとに Slot 1 = 事前フィルタキーワード一致 **最大 5 件**、Slot 2 = キーワード不一致だが対象国名一致 **最大 2 件**、Slot 3 = Slot 1+2 がともに空のとき**最新 1 件**、で選抜 **MUST**。Slot 1 に入った記事は Slot 2 の評価対象にしない **MUST**（スロット排他）。Slot 3 は非英語の公式声明でフィルタが空振りした際の完全失明を防ぐ
**根拠**: diplomatic.py:262-341（Slot 1-3）vs military_exercise.py:131-196・apt_intel.py:208-310（1-2 のみ）・hacktivist_news_sensor.py:118-208（スロット無し）
**検証**: 未検証
**分類**: DEFECT-PRESERVE（Slot 3 は 1 系統のみ → §9-DP7）
### S1-INGEST-007: 事前フィルタは採用キーワードとハード棄却キーワードの 2 層である
**挙動**: 記事本文（タイトル + 要約、小文字化）に対し、**ハード棄却キーワードを先に評価し一致すれば LLM 呼出前に棄却 MUST**、その後に採用キーワードを評価 **MUST**。ハード棄却対象は「解決済み事案」「マーケティング」「定型ダイジェスト接頭辞」の語彙
**根拠**: apt_intel.py:140-154・284-290、hacktivist_news_sensor.py:86-90・191-196
**検証**: 未検証
**分類**: CORE
### S1-INGEST-008: 記事の跨サイクル dedup はプレフィクス付きハッシュの LRU で行う
**挙動**: 恒久 dedup キーは `<センサー固有プレフィクス>-<feed 名>-<タイトル先頭 60 文字>` のハッシュ **MUST**。**country を鍵に含めてはならない MUST NOT**（同一記事が複数 country へ重複投入されるため）。上限超過時は**古い側から半数を削除 MUST**。閾値: 上限 1000（diplomatic / military_exercise / apt_intel）、500（hacktivist_news / hacktivist_intel / ground_osint / rss_narrative burst）。すべてハードコード・in-memory・再起動で消失
**根拠**: diplomatic.py:150-158・414-422、hacktivist_intel_sensor.py:32-40・76-83、ground_osint_sensor.py:44-52・150-157、rss_narrative.py:59-61・330-342
**検証**: 未検証
**分類**: DEFECT-PRESERVE（揮発 → §9-DP5 / D2 B-05）
### S1-INGEST-009: RSS 2.0 / RSS 1.0(RDF) / Atom の 3 形式を扱う
**挙動**: item 走査は RSS 2.0 の `item`、RSS 1.0 名前空間の `item`、Atom 名前空間の `entry` を**すべて対象 MUST**。Atom のリンクは属性から取得 **MUST**
**根拠**: apt_intel.py:231-252（2.0+RDF）、hacktivist_news_sensor.py:136-156 / background_observer.py:183-198（2.0+Atom）、diplomatic.py:284（2.0 のみ）
**検証**: 未検証
**分類**: DEFECT-PRESERVE（対応形式が系統ごとに違う → §9-DP7）

## 3. 共通 LLM intel 投入仕様

現行は 8 系統に複製（§4 表 2）。骨格は `事前フィルタ → prompt 構築 → llm_analyze_json → 出力検証 →
confidence 決定 → item 組立 → submit`。
### S1-INGEST-010: LLM 不在時は成功として no-op で終える
**挙動**: LLM 機能が無効、または LLM が利用不能な場合、**fetch を成功として記録し（失敗カウンタを進めず）MUST**、理由コードを付けて即座に戻る **MUST**。これにより LLM 停止がサーキットブレーカーを開かせない（LLM 停止 = センサー故障ではない）
**根拠**: diplomatic.py:351-362、military_exercise.py:206-216、hacktivist_intel_sensor.py:50-62、ground_osint_sensor.py:107-119、convergence_tracker.py:321-331、rss_narrative.py:315-326
**検証**: 未検証
**分類**: CORE（NP3）
### S1-INGEST-011: LLM へ渡す外部由来テキストは長さ上限付きでサニタイズする
**挙動**: 記事タイトル・要約・スニペット等は**LLM に渡す前に必ずサニタイズ関数を通し文字数上限を明示 MUST**。閾値: タイトル 120 字、要約 200/400/500 字（センサー別）、スニペット 400 字。すべてハードコード
**根拠**: diplomatic.py:425-426、hacktivist_news_sensor.py:297-298、ground_osint_sensor.py:170-173、rss_narrative.py:346-349
**検証**: tests/test_sanitize_llm_input.py（関数本体は S4 担当）
**分類**: CORE
### S1-INGEST-012: プロンプトは system / user の 2 部構成で基準日と JSON 専用指示を含む
**挙動**: system は分析者ロールと**「JSON オブジェクトのみを返す」指示を含む MUST**。user は (1) 当日日付、(2) ソース識別、(3) 対象 country リスト、(4) 記事本文、(5) 出力 JSON スキーマ、(6) confidence 帯の言語化ガイド、を含む **MUST**。当日日付の明示はモデルが記事の新旧を判断するために必須 **MUST**
**根拠**: diplomatic.py:429-466、military_exercise.py:257-312、apt_intel.py:384-425（Stage1）・462-501（Stage2）、convergence_tracker.py:336-367、rss_narrative.py:352-406
**検証**: tests/test_apt_prompt_dedup.py（4 件、apt_intel の 2 段構造のみ）
**分類**: CORE（NP6: prompt まで遡及可能であることの実装）
### S1-INGEST-013: LLM 応答は構造検証を通ったときのみ採用する
**挙動**: LLM 呼出は JSON 解析の成否フラグを返し、**失敗時は当該記事をスキップ MUST**（フォールバック値での続行を**してはならない MUST NOT**）。数値は既定値付き安全変換、列挙値は許容集合 + 既定値付き安全変換で正規化 **MUST**
**根拠**: diplomatic.py:469-477、military_exercise.py:315-323、hacktivist_intel_sensor.py:145-154、convergence_tracker.py:369-380
**検証**: 未検証
**分類**: CORE
### S1-INGEST-014: 棄却理由は「信号なし」と「閾値未満」を分離して記録する
**挙動**: LLM が escalation 無しと判定した場合と confidence フロア未満の場合は**別々の理由コードで記録 MUST**。前者はプロンプト／モデルの調整対象、後者は閾値の調整対象であり、混同すると診断が不能になる。閾値: confidence フロア = **0.35**（7 系統）、**0.50**（convergence_tracker）。すべてハードコード
**根拠**: military_exercise.py:351-361（分離の明示コメント）、diplomatic.py:479-482、hacktivist_news_sensor.py:360-374、rss_narrative.py:524-529、convergence_tracker.py:382-384
**検証**: 未検証
**分類**: CORE
### S1-INGEST-015: LLM の多国出力は 2 文字コードに正規化し重みを [0,1] にクランプする
**挙動**: `countries` は**空白除去・大文字化した結果が 2 文字のものだけを残す MUST**。`country_weights` は大文字キー → 小文字キーの順で探索し欠落時 1.0 を既定 **MUST**、値は `[0.0, 1.0]` にクランプ **MUST**。主 country が `countries` に無い場合は**先頭に挿入し重み 1.0 を与える MUST**
**根拠**: diplomatic.py:485-504、military_exercise.py:326-333・392-394、hacktivist_intel_sensor.py:163-186、rss_narrative.py:480-490
**検証**: tests/test_intel_multicountry.py（12 件。検証面は intel_queue 側 = 別担当）
**分類**: CORE
### S1-INGEST-016: 主 country を特定できない item は破棄する（強制フォールバック禁止）
**挙動**: LLM が主 country を null または対象リスト外で返した場合は item を**破棄 MUST**。**「最も近い対象国」への強制割当をしてはならない MUST NOT**（LLM の過剰関連付けが実体のない収斂を作るため）
**根拠**: diplomatic.py:495-500、military_exercise.py:364-369、hacktivist_intel_sensor.py:174-182、hacktivist_news_sensor.py:387-401
**検証**: 未検証
**分類**: CORE（Phase 9-E の帰属汚染インシデントの再発防止に対応）
### S1-INGEST-017: 関連度が間接の item は confidence に上限を課す
**挙動**: LLM に「対象 country との結び付きが直接 / 間接 / 無し」を自己申告させ、**「無し」は破棄 MUST**、**「間接」は confidence を上限でクリップ MUST**。閾値: 上限 = **0.45**（diplomatic）／**0.50**（military_exercise）。ハードコード
**根拠**: diplomatic.py:506-523、military_exercise.py:371-390
**検証**: 未検証
**分類**: CORE（上限値の不一致は §4 表 2）
### S1-INGEST-018: score_delta は加法合成であり乗法を用いない
**挙動**: `score_delta` は `base + bonus` の**加法 MUST**。乗法合成は値が跳ねるため**用いてはならない MUST NOT**。上限を持つ場合は合成後にクリップ **MUST**
**根拠**: military_exercise.py:396-401（「avoids multiplicative inflation」）、apt_intel.py:552-563、hacktivist_intel_sensor.py:196-201、convergence_tracker.py:388-392
**検証**: 未検証
**分類**: CORE
### S1-INGEST-019: intel item のエンベロープは 13 フィールド固定である
**挙動**: item は `source_type` / `source_id` / `theater`（= 主 country、§9-DP11）/ `countries` / `country_weights` / `ts` / `confidence`（小数 3 桁丸め）/ `raw_text`（1000 字上限）/ `raw_url` / `headline`（100 字上限）/ `llm_fields` / `score_delta` / `domain` を必ず含む **MUST**。`domain` は **cyber / physical / info のいずれか MUST**
**根拠**: diplomatic.py:528-550、military_exercise.py:403-427、hacktivist_intel_sensor.py:203-223、ground_osint_sensor.py:255-277、convergence_tracker.py:398-424、rss_narrative.py:554-576
**検証**: 未検証
**分類**: CORE（3 値外が入りうる現行挙動は S1-SENSI-053）
### S1-INGEST-020: サイクル単位の沈黙は理由コードで説明可能でなければならない
**挙動**: 1 サイクルで 1 件も投入しなかった場合、**理由を判別できるコードを記録 MUST**。最低限「入力ゼロ」「全件 dedup 済」「全件本文空」「全 feed 死亡」「burst 無し」を区別できること **MUST**（沈黙が正常か故障かをアナリストが秒で判断できるため）
**根拠**: hacktivist_intel_sensor.py:231-237、ground_osint_sensor.py:287-293、rss_narrative.py:747-755、diplomatic.py:560-561
**検証**: 未検証
**分類**: CORE（AP3 自己評価の入力）

## 4. コピペ複製の挙動差分表（DEFECT-PRESERVE）

### 表 1: RSS 取得・パース 6 系統の差分（D2 A-02）

| 系統 | HTTP | timeout | UA | 429 扱い | tolerant パーサ | 死活分類 | 形式 | 鮮度窓 | 記事上限 |
|---|---|---|---|---|---|---|---|---|---|
| diplomatic | requests | 15s | ブラウザ 3 ヘッダ | 一律ログ | **有** | **有（唯一の定義元）** | 2.0 | 48h | 5+2+1 |
| apt_intel | requests | 15s | ブラウザ 3 ヘッダ | 一律ログ | 無 | 無 | 2.0+RDF | **168h** | 5+2 |
| military_exercise | requests | 15s | `OSINT-Radar/8.0` | 429 個別ログ | 無 | 無 | 2.0 | 48h | 5+2 |
| hacktivist_news | requests | 15s | `OSINT-Radar/8.0` | 429 個別ログ | 無 | **借用**（関数内 import） | 2.0+Atom | 48h | 5 |
| rss_narrative | requests | **10s** | `OSINT-Radar/8.0` | **空返し** | 無 | 無 | 2.0 | **無** | 2/ソース |
| bg_observer_rss | **urllib** | 15s | `news-aggregator` | **区別なし** | 無 | **空 = 失敗計上** | 2.0+Atom | **無** | 無制限 |

**帰結**: 同一の malformed RSS に対し diplomatic は記事を回収し、他 5 系統は静かに 0 件を返す。
NP2（多ソース収斂）の入力品質がセンサーごとに不均一。
**v3 規範**: S1-INGEST-001〜009 を単一の取得層として実装 **MUST**。
hacktivist_news が他センサーの private 関数を関数内 import する構造（hacktivist_news_sensor.py:263）は
複製の症状であり共有層で解消される。

### 表 2: LLM 投入 8 系統の差分（D2 A-02 / D1-sensors §5-11）

| センサー | max_tokens | 事前フィルタ | conf フロア | 主 country 規則 | conf 上限規則 | dedup 鍵 | score_delta | domain |
|---|---|---|---|---|---|---|---|---|
| apt_intel | **200 + 280（2 段ゲート）** | キーワード + ハード棄却 + 定型接頭辞 | 0.35 | 対象外は破棄 | — | 記事 1000 | ttp(1.0-2.5)+urgency(0-0.5) | cyber |
| diplomatic | 256 | escalation kw + 国名 + 最新 1 件 | 0.35 | 対象外は破棄 | 間接 → **0.45** | 記事 1000 | urgency 1.0/1.5/2.0/3.0 | info |
| military_exercise | 300 | exercise kw + 国名 | 0.35 | 対象外は破棄 | 間接 **0.50** / 定期報告 **0.50** | 記事 1000 | urgency(1.0-2.5)+scale(0-0.5) | **physical** |
| hacktivist_intel | 256 | **無し**（検知ログ全件） | 0.35 | null は破棄、2 文字英字なら **LLM 上書き** | — | ts+ch+country 500 | sector(1.0/2.0)+timeline(0-1.0) cap3.0 | attack_type 写像 |
| hacktivist_news | 250 | hacktivist kw 必須 + ハード棄却 | 0.35 | **対象集合外も破棄**（唯一） | — | 記事 500 | urgency(0.5-2.0)+type(0-0.5) | info |
| ground_osint | 256 | status 絞込 + ongoing 語 or target≥2 | 0.35 | 上流 country をそのまま | **+0.10 ブースト** cap0.95 | ts+ch+country 500 | 3.0/2.0/1.0 の 3 段 | cyber |
| convergence_tracker | **400** | 持続収斂ゲート（S1-SENSI-050） | **0.50** | 上流 country をそのまま | — | **country 単位 24h クールダウン** | urgency(1.5-3.0)+sensor(0-1.0) | **LLM 出力（mixed 含む）** |
| rss_narrative | **512** | Z-score burst ゲート | 0.35 | LLM 出力 + 対象国を先頭挿入 | — | **burst 単位 日次 500** | type(0.5-2.5)+urgency(0-0.5) | info |

**特記 1**: D1-sensors §2 は「max_tokens 200-400」と記録するが実測レンジは **200〜512**（rss_narrative の 512 が未計上）。
**特記 2**: 主 country の扱いが**4 通り**に分岐（破棄 / LLM 上書き / 上流採用 / 先頭挿入）。
**特記 3**: `domain` の決定主体が**4 通り**（固定値 / attack_type 写像 / LLM 出力 / 固定だが入力実体と不一致）。
**v3 規範**: S1-INGEST-010〜020 を単一の投入層とし、**センサー固有部分は「事前フィルタ」「プロンプト本文」
「score_delta 式」「domain」の 4 スロットに限定 MUST**。閾値は宣言的 registry 経由 **MUST**。

## 5. Information センサー個別条項
### S1-SENSI-001: GDELT トーンは当日窓と履歴窓を並列取得して差分を採る
**挙動**: country ごとに検索クエリを組み**当日窓（1d）と履歴窓（既定 28d）を並列取得 MUST**。各窓のトーンは時系列点の値の**単純平均を小数 3 桁で丸めた値 MUST**。HTTP 429/503、時系列空、値配列空はいずれも `None` **MUST**。当日トーンが `None` の country は状態 `NO_DATA` とし以降の判定を行わない **MUST**。country 間に **0.5 秒の courtesy delay MUST**（2 件目以降）。閾値: 履歴窓 28 日（`GDELT_HISTORY_WINDOW`、DB override 可）
**根拠**: gdelt.py:24-32・41-56、config.py:328
**検証**: 未検証
**分類**: CORE
### S1-SENSI-002: DOW ベースラインは UTC 日バケット単位で 1 日 1 回だけ記録する
**挙動**: 当日の UTC 日バケット（`floor(now/86400)*86400`）が前回記録バケットと異なる場合のみ当日トーンを曜日ラベル付きで永続記録 **MUST**。同一バケット内の再取得は記録しない **MUST**。保持上限は `曜日あたり上限 × 7` **MUST**。閾値: 曜日あたり 20（≈20 週）。ハードコード
**根拠**: gdelt.py:21-22・38-40・60-64
**検証**: 未検証
**分類**: CORE
### S1-SENSI-003: DOW Z-score は同曜日・当日除外・標準偏差フロア付きで計算する
**挙動**: 同一曜日の**当日を除く**過去サンプル集合を取得し、件数 n が最小サンプル数以上のときのみ Z を算出 **MUST**。母集団標準偏差を用い**下限 0.5 でフロア MUST**:
`mean = Σx/n` ; `std = max(sqrt(Σ(x−mean)²/n), 0.5)` ; `z = (tone_today − mean)/std`
n が最小未満のときは Z を `None` として出力 **MUST**（0 で埋めない）。閾値: 最小サンプル 3、std フロア 0.5。ともにハードコード
**根拠**: gdelt.py:21・66-77
**検証**: 未検証
**分類**: CORE（トーンには曜日バイアスがあるという外部 API 知識の実装）
### S1-SENSI-004: GDELT alert は Z と絶対閾値の OR、悪天候で抑制する
**挙動**: `is_alert = (悪天候でない) AND (z < −2.0 OR tone_today < 絶対閾値)` **MUST**。Z が使えない場合は `is_alert = (悪天候でない) AND (tone < 絶対閾値)` **MUST**。**トーンは負が敵対的**であり大きな負の Z が異常な敵意を意味する。状態は `WEATHER_NOISE`（悪天候 かつ トーン < 絶対閾値）→ `ALERT` → `NORMAL` の**優先順で決定 MUST**。閾値: Z 下限 **−2.0**（ハードコード）、絶対閾値 **−15.0**（`GDELT_TONE_ALERT_THRESHOLD`、DB override 可）
**根拠**: gdelt.py:73-86、config.py:327
**検証**: 未検証
**分類**: CORE
### S1-SENSI-005: ナラティブのヒット判定は「語句 1 件」または「原子語 2 種以上」である
**挙動**: 設定キーワードを (1) 空白/ハイフンを含む**語句**、(2) 各エントリから抽出した**4 文字以上かつストップワードでない単語**（原子語、重複除去・昇順）の 2 層に展開 **MUST**。記事が語句のいずれかに部分一致すればヒット **MUST**。語句不一致時は**単語境界一致した原子語の異なり数が 2 以上のときのみヒット MUST**。単語 1 個の一致でベースラインが膨らむのを防ぐ非対称設計である
**根拠**: rss_narrative.py:15-50・206-214・271-273
**検証**: tests/test_rss_narrative.py::TestCountKeywordsGeoFilter（4 件、間接）
**分類**: CORE
### S1-SENSI-006: 地理関連度は 3 分類し、他 country 記事のみをキーワード計数から除く
**挙動**: 記事本文を地名語彙と照合し `match`（当該 country に言及）/ `other`（他の監視対象 country にのみ言及）/ `generic`（いずれにも言及なし）に分類 **MUST**。**`other` のみキーワード計数から除外 MUST**、`generic` は除外しない（グローバル・曖昧記事は残す = NP1）。照合規則は**多語または 6 文字以上は部分一致、それ未満の単語は単語境界一致 MUST**
**根拠**: rss_narrative.py:69-118・200-204・265-269
**検証**: tests/test_rss_narrative.py::TestClassifyArticleGeo（14 件）／::TestCountKeywordsGeoFilter::test_excludes_other_theater_articles ／::TestGetBurstArticlesGeoFilter（2 件）／::TestGeoFilterIntegration
**分類**: CORE
### S1-SENSI-007: Z-score の分母（記事数）は地理フィルタを適用しない
**挙動**: 正規化頻度は `キーワードヒット数 / max(総記事数, 1)` **MUST**。**総記事数を地理フィルタで減らしてはならない MUST NOT**（分母が揺れると Z-score が不安定になる）
**根拠**: rss_narrative.py:160-163・197-198・701
**検証**: tests/test_rss_narrative.py::TestCountKeywordsGeoFilter::test_article_count_always_unfiltered
**分類**: CORE
### S1-SENSI-008: 30 日ローリング Z-score は母分散を用い、無音ベースラインを特別扱いする
**挙動**: 保持サンプル数が **7 未満なら (z, mean, std) = (0,0,0) MUST**（ウォームアップ）。7 以上のとき `mean = Σx/n` ; `var = Σ(x−mean)²/n` ; `std = sqrt(var) if var>0 else 0` として:
`z = (today − mean)/std`（std > 0）／`z = 初回信号 Z`（std == 0 かつ mean == 0 かつ today > 0）／`z = 0.0`（他）
**第 2 分岐は必須 MUST**: 平坦なゼロ列に対する最初の非ゼロ活動はそれ自体が burst 信号であり、これが無いと無音期からの立ち上がりが z=0 として黙殺される（NP1）。閾値: 最小サンプル 7（ハードコード）、初回信号 Z **3.0**（`NARRATIVE_ZSCORE_FIRST_SIGNAL`、**env のみ・registry 非登録** → §8-A8）
**根拠**: rss_narrative.py:588-613
**検証**: tests/test_rss_narrative.py::TestBaselineRetention::test_baseline_zscore_warmup
**分類**: CORE
### S1-SENSI-009: ローリング窓の上限は「日数 × 1 日あたり取得回数」で導出する
**挙動**: ベースライン保持上限は `保持日数 × floor(86400 / poll 間隔)` **MUST**。**保持日数をそのままサンプル数上限にしてはならない MUST NOT**。理由: 30 分間隔のセンサーは 1 日 48 サンプルを生む。上限を 30 サンプルにすると窓が実質 15 時間になり Z-score が自分自身に正規化されて burst が原理的に検知不能になる（2026-04-29 の本番回帰: 前置フィルタ棄却率 100%）。閾値: 保持日数 30（`NARRATIVE_BASELINE_DAYS`、DB override 可）
**根拠**: rss_narrative.py:615-634、config.py:360
**検証**: tests/test_rss_narrative.py::TestBaselineRetention::test_baseline_cap_matches_days_times_cycles_per_day / test_baseline_cap_obeys_env_override
**分類**: CORE（telegram_mirror は本規則に従っていない → §9-DP6）
### S1-SENSI-010: ナラティブ burst 状態は 2 段閾値で決まる
**挙動**: `z ≥ CRITICAL` → `CRITICAL_BURST`、`z ≥ ALERT` → `BURST`、他 `NORMAL` **MUST**。`is_burst` は前 2 者で真 **MUST**。閾値: ALERT **2.0** / CRITICAL **3.0**（`NARRATIVE_ZSCORE_ALERT` / `_CRITICAL`、DB override 可）
**根拠**: rss_narrative.py:706-710、config.py:358-359
**検証**: 未検証
**分類**: CORE
### S1-SENSI-011: burst 時の LLM 解析は主題クラスタに分割して投入する
**挙動**: burst 検知時のみヒット記事を LLM に渡す **MUST**。LLM には**主題が異なる記事を別クラスタに分けるよう指示 MUST**、**無関係記事群に共通ナラティブを捏造させてはならない MUST NOT**。クラスタごとに独立した intel item を投入 **MUST**（アナリストが主題単位で採否できる）。記事インデックスは 1 始まり、プール範囲外は無視、**有効インデックス 0 件のクラスタは破棄 MUST**（旧形式フォールバック時のみ先頭 4 件を割当）。LLM が `clusters` を返さない場合は**応答全体を単一クラスタとして扱う後方互換パス MUST**。burst 単位の LLM 呼出は `country + 状態 + UTC 日` のハッシュで**日次 dedup MUST**。`escalation_signal` 偽 または confidence < 0.35 のクラスタは投入しない **MUST**。`score_delta` = narrative_type 基礎値（pre-operation_conditioning 2.5 / threat_escalation 2.0 / response_to_incident 1.5 / propaganda_routine 0.5 / unknown 1.0）+ urgency（critical 0.5 / high 0.2 / 他 0）**MUST**。閾値: LLM プール 6 件、ソースあたり収集 2 件、max_tokens 512。ハードコード
**根拠**: rss_narrative.py:284-427・429-503・521-552・712-732
**検証**: 未検証
**分類**: CORE
### S1-SENSI-012: Telegram 取得は UA ローテーションと指数バックオフを持ち、成功を 2 条件で判定する
**挙動**: リクエストごとに **UA プールから無作為選択 MUST**。403/429 時は `2.0 × 2^試行 × ジッタ(0.8-1.2)` 秒待って**最大 3 回まで再試行 MUST**、待機は 30 秒上限 **MUST**。他の非 200 と例外は即座に諦める **MUST**。最終 URL からプレビュー無効化リダイレクトを検出したら空を返す **MUST**。HTTP 200 かつ**本文長が下限超 かつ 投稿コンテナ要素を含む場合のみ成功 MUST**（コンテナが無いページは非公開/空として空を返す）。**3 つの失敗モード（プレビュー無効化 / スロットリング / ネットワーク断）をログ上で区別できること MUST**（すべて空文字列を返すため区別が無いと診断不能）。閾値: UA プール 5 種、初期遅延 2.0s、最大試行 3、待機上限 30s、本文長下限 2000B。すべてハードコード
**根拠**: telegram.py:42-48・74-78・80-128
**検証**: 未検証
**分類**: CORE
### S1-SENSI-013: Telegram 投稿は個別にタイムスタンプ抽出し鮮度窓で絞る
**挙動**: 投稿コンテナ境界で本文を分割し各投稿から公開時刻を抽出 **MUST**。時刻が抽出できない/解析不能な投稿は**破棄 MUST**（ページ全体を捨てない）。鮮度窓より古い投稿は破棄 **MUST**。残った投稿本文を連結して解析対象とする **MUST**。閾値: 鮮度窓 **48h**（`TELEGRAM_POST_MAX_AGE_HOURS`、env のみ）。2026-04-29 に 8h → 48h へ変更。ハクティビストチャンネルは 24-72h のバースト間欠投稿であり 8h 窓は健全なチャンネルでも全投稿を落としていた
**根拠**: telegram.py:23-31・130-175・340-345
**検証**: 未検証
**分類**: CORE
### S1-SENSI-014: Telegram のキーワード照合は長さと形態で規則を切り替える
**挙動**: 2 文字以下のキーワードは**照合しない MUST**（雑音源）。空白を含む語句と `#` 始まりのハッシュタグは**部分一致 MUST**。それ以外の単語は**単語境界一致 MUST**（"target" が "targeting" に一致しない）。この規則はヒット計数・意図判定・スニペット抽出の**3 箇所で同一 MUST**
**根拠**: telegram.py:187-232・300-312
**検証**: 未検証
**分類**: CORE
### S1-SENSI-015: Telegram はチャンネルを 1 サイクル 1 回だけ取得し country へ扇出する
**挙動**: 複数 country が同一チャンネルを監視する場合でも**取得と解析は 1 サイクルにつき 1 回 MUST**、結果を country ごとに集約 **MUST**。チャンネル間に **1.5〜4.0 秒の無作為ジッタ MUST**。正規化頻度は `総キーワードヒット数 / max(取得成功チャンネル数, 1)` **MUST** — 取得失敗チャンネルを分母に含めない **MUST**（feed 障害が burst に化けるのを防ぐ）
**根拠**: telegram.py:321-357・359-393
**検証**: 未検証
**分類**: CORE
### S1-SENSI-016: Telegram の状態はバースト優先のラダーで決定する
**挙動**: `CRITICAL_BURST`（z ≥ CRITICAL）→ `BURST`（z ≥ ALERT）→ `INTENT_DETECTED`（意図あり）→ `TARGETS_FOUND`（標的 URL あり）→ `CLEAR` の**優先順で決定 MUST**。統計的 burst は個別検知より上位 **MUST**。閾値: rss_narrative と同一の `NARRATIVE_ZSCORE_ALERT` / `_CRITICAL` を共有
**根拠**: telegram.py:395-407
**検証**: 未検証
**分類**: CORE
### S1-SENSI-017: 攻撃主張の確度は裏付けの強さで 4 段に決まる
**挙動**: `claim_confidence` は**排他ラダー MUST**: バースト裏付けあり **0.6** > 意図あり かつ 政府系標的 URL あり **0.4** > 意図のみ **0.2** > 主張なし **0.0**。政府系判定は標的 URL が `.gov` / `.mil` / `.parliament` のいずれかを含むこと。閾値: 4 値すべてハードコード。下流の抑制閾値 `TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD` 既定 **0.5** はスコアリング層で消費（別担当）
**根拠**: telegram.py:22・33-40・409-421
**検証**: 未検証
**分類**: CORE
### S1-SENSI-018: Telegram 検知ログは CLEAR を記録せず内容ハッシュで重複を抑制する
**挙動**: 状態 `CLEAR` の検知を**記録してはならない MUST NOT**。`チャンネル + country + スニペット先頭 200 字 + 標的 URL 先頭 5 件` のハッシュが前回と同一なら**記録を抑制 MUST**（固定投稿の再取得によるログ汚染防止）。リングバッファは新しいものを先頭に挿入し上限超過時に末尾を落とす **MUST**。閾値: 上限 200 件。ハードコード・in-memory・再起動で消失
**根拠**: telegram.py:62-70・234-271
**検証**: 未検証
**分類**: CORE（本ログが hacktivist_intel / ground_osint の唯一の入力源）
### S1-SENSI-019: Tor は relay 減少率と bridge 利用者急増率を前サイクル比で算出する
**挙動**: country ごとに稼働 relay 数・稼働 bridge 数・帯域合計を集計 **MUST**。`drop_pct = (prev − running)/max(prev,1)`（prev > 0 のときのみ、他 0）**MUST**。`surge_pct = (users − prev_users)/max(prev_users,1)`（prev_users > 0 のときのみ）**MUST**。利用者トレンドは `SURGE`（surge_pct > 閾値）/ `DROP`（surge_pct < −0.3）/ `NORMAL` **MUST**。リクエスト間に **0.5 秒の delay MUST**、429 時は relay ループを打ち切る **MUST**。閾値: relay 減少 **0.40**、利用者急増 **1.00**、DROP **−0.3**。すべてハードコード
**根拠**: tor_metrics.py:25-26・50-120
**検証**: tests/test_engine.py::TestTorMetricsSensor::test_relay_drop_detection / test_user_surge_detection（**本番関数を呼ばずインライン再実装** → §10-GAP-06）
**分類**: CORE
### S1-SENSI-020: Tor の country 状態は relay 減少と利用者急増の論理積で最上位が決まる
**挙動**: `relay_drop = drop_pct ≥ 閾値`、`user_surge = トレンド == SURGE` として `CENSORSHIP_INDICATOR`（両方）→ `RELAY_DROP`（前者のみ）→ `USER_SURGE`（後者のみ）→ `NORMAL` **MUST**。**両方の合致のみが検閲指標である MUST**（遮断だけなら障害、迂回増だけなら他要因の可能性がある）
**根拠**: tor_metrics.py:122-136
**検証**: tests/test_engine.py::TestTorMetricsSensor::test_censorship_indicator（インライン再実装）
**分類**: CORE
### S1-SENSI-021: Tor の前サイクル値は正値時のみ更新し、全失敗サイクルは cache を更新しない
**挙動**: 前サイクル比較値は**新値が 0 より大きいときのみ更新 MUST**（取得失敗による 0 でベースラインを潰さない）。1 件も成功しなかったサイクルは **cache を更新してはならない MUST NOT**。その場合は前回 cache、無ければ全 country `NORMAL` の既定構造を返す **MUST**
**根拠**: tor_metrics.py:138-161
**検証**: tests/test_engine.py::TestTorMetricsSensor::test_cache_roundtrip（cache 往復のみ）
**分類**: CORE（前サイクル値が in-memory 揮発である点は §9-DP12）
### S1-SENSI-022: 渡航勧告は 3 政府ソースを並列取得し、1 ソースの失敗を他に波及させない
**挙動**: 米（RSS）/ 英（Atom）/ 加（HTML）を**並列取得 MUST**。各ソースは `(データ, 成否)` を独立に返し、**例外・429・非 200 はいずれも失敗として空データを返す MUST**（他ソースの処理を止めない）。1 件でも成功すれば cache 更新 **MUST**、全滅時は前回 cache を返す **MUST**。閾値: timeout 20s、周期 3600s。ハードコード
**根拠**: travel_advisory.py:31-48・82-104・150-172・239-242
**検証**: 未検証
**分類**: CORE（NP2 独立ソース収斂の実装）
### S1-SENSI-023: 渡航勧告のレベル抽出は 3 ソース 3 規則で 1〜4 尺度に写像する
**挙動**: 勧告レベルは 1〜4 の共通尺度に写像 **MUST**。**米**: 大文字化本文に `LEVEL 4`/`DO NOT TRAVEL` → 4、`LEVEL 3`/`RECONSIDER TRAVEL` → 3、`LEVEL 2`/`INCREASED CAUTION` → 2、`LEVEL 1`/`NORMAL PRECAUTIONS` → 1、不一致 0。**英**: 定型フレーズ表（`advise(s) against all travel` → 4、`…all but essential travel` → 3）優先 → 重症度語（`extreme risk`/`war zone`/`armed conflict` → 4、`high risk`/`significant risk` → 3）→ **最後に `travel` を含めば 2 を返す fail-open**。**加**: 定型フレーズ表（`avoid all travel` 4 / `avoid non-essential travel` 3 / `exercise a high degree of caution` 2 / `take normal security precautions` 1）→ `risk level N` → **行内のアイコンファイル名**（`do-not-travel` 4 / `reconsider-travel` 3 / `increased-caution` 2 / `normal-precautions` 1）の 3 段フォールバック
**根拠**: travel_advisory.py:50-64・245-302・320-366
**検証**: 未検証
**分類**: CORE（英の fail-open は §8-A3）
### S1-SENSI-024: 渡航勧告の country 照合はフォールバック付き、引上げ判定の前回値既定は現在値である
**挙動**: 記事タイトル（加は国名セル）を大文字化し**まず対象 country 集合の国名で照合 MUST**、不一致なら**既知 country 全件へフォールバック MUST**。不一致またはレベル 0 の項目は破棄 **MUST**。`upgraded = (今回 > 前回)` **MUST**、前回値未記録の country では**前回値に今回値を代入する MUST**（= 初回観測は必ず `upgraded = False`）。前回値はソースごとに独立保持 **MUST**
**根拠**: travel_advisory.py:129-142・274-300・379-391
**検証**: 未検証
**分類**: CORE（初回必ず False・in-memory 揮発は §8-A1 / §8-A2 / §9-DP12）
### S1-SENSI-025: 多政府収斂は「レベル 3 以上を出しているソース数」で測る
**挙動**: country ごとに全ソースのレベルを集め**最大レベルの項目を代表とする MUST**。`convergence_count = レベル 3 以上を報告したソース数` **MUST**、`converged = convergence_count ≥ 2` **MUST**。報告ソースが 1 件のみでレベル 3 以上のときは**単一ソース警告フラグを立てる MUST**（政治的動機による単独引上げの可能性を明示）。1 ソースも報告しない country は全ソース前回値の最大をフォールバックレベルとし `upgraded`/`converged` を偽、レベル 0 時ラベル `UNKNOWN` **MUST**。閾値: 収斂ソース数 2、対象レベル下限 3。ハードコード
**根拠**: travel_advisory.py:174-229
**検証**: 未検証
**分類**: CORE
### S1-SENSI-026: bg_observer は既定無効であり、LLM にも API キーにも依存しない
**挙動**: 本センサーは**既定で無効 MUST**。無効サイクルは「成功した no-op」として記録し失敗カウンタを進めない **MUST**（外向き HTTP の追加は運用者の明示的意思決定であるべき = OPSEC）。**API キー・登録・LLM のいずれにも依存してはならない MUST NOT**。決定論的な regex 抽出のみを用い、オフライン / LLM 不在の配備でも稼働 **MUST**。閾値: `BG_OBSERVER_ENABLED` 既定 **false**（config.py:618）
**根拠**: bg_observer.py:52-62・84-90、background_observer.py:19-25・319-320
**検証**: tests/test_background_observer.py::test_tick_no_op_when_disabled ほか全 18 件（fetcher と時計を注入してオフライン実行）
**分類**: CORE（NP3）
### S1-SENSI-027: bg_observer の走査は全 scorable シナリオの participant 和集合に対する broadcast である
**挙動**: 1 サイクルで全 feed を 1 回ずつ取得し、**取得した全項目を participant 和集合の全 country に対して評価 MUST**。focused シナリオも和集合に含める **MUST**。1 項目が複数 country に一致した場合**country ごとに 1 信号を発行 MUST**（シナリオ側の participant フィルタが振り分けを担う）。理由: 取得コストは走査範囲に依存しないため、1 サイクル 1 country のラウンドロビンは取得済みデータの 8/9 を捨てていた（改善は統計的ではなく構造的）。participant が空のサイクルは理由コード付きで記録し取得を行わない **MUST**
**根拠**: background_observer.py:205-222・271-287・322-347
**検証**: tests/test_background_observer.py::test_broadcast_emits_one_signal_per_country_per_match / test_broadcast_scope_respects_participant_union / test_broadcast_includes_focused_in_participant_union / test_broadcast_records_no_participants_when_empty
**分類**: CORE
### S1-SENSI-028: bg_observer は抽出の 3 段 confidence を raw_score に写像する
**挙動**: 抽出結果の confidence 段階に応じて信号の raw_score を決定 **MUST**: conf ≥ 0.85（死者数あり）→ `min(1.0, 0.4 + 0.05 × 死者数)`、conf ≥ 0.60（kinetic 動詞のみ）→ `0.45`、他（escalation 動詞のみ）→ `0.25`。信号のドメインは `info` 固定 **MUST**、`signal_source` は全信号で共通 **MUST**（同一 country の複数記事がスコアリング層の dedup で 1 件に畳まれる）。閾値: 5 値すべてハードコード
**根拠**: background_observer.py:376-401、radar/conclusions/rss_extractor.py:353-407（段階の定義元）
**検証**: tests/test_rss_extractor.py（段階境界。抽出器本体は S1-conclusions 担当）
**分類**: CORE
### S1-SENSI-029: bg_observer の信号は「キュー」ではなく「状態」の意味論を持つ
**挙動**: 発行信号は TTL 窓の内側にある限り**採点ティックが何回読んでも消えない MUST**（読み取りは非消費、期限切れのみその場で除去）。同一 identity（signal_source + domain + country 群 + 証拠 URL または表示値）の再観測は**重複追加せず既存項目を除去して再追加することで TTL を滑らせる MUST**。キュー長が上限に達したら**最古から破棄 MUST**。理由（2026-07-04 のストロボ回帰）: 読み取りで空にする実装では信号の実効寿命が「次の採点ティックまで」（≤2 分）になり文書化された 30 分 TTL が虚構だった。5 分の観測周期が 2 分の採点周期とエイリアシングし、info ドメインの寄与が明滅して focused シナリオの TL が TL4↔TL5 を交互に往復した。閾値: TTL **1800s** / キュー上限 **200** / 周期 **300s**（`BG_OBSERVER_SIGNAL_TTL_SEC` / `_MAX_QUEUE` / `_INTERVAL_SEC`、env のみ）
**根拠**: background_observer.py:96-149、config.py:619-621
**検証**: tests/test_background_observer.py::test_active_signals_filters_stale / _returns_fresh / _retains_buffer_within_ttl / _visible_to_consecutive_ticks / _expire_after_ttl / test_reenqueue_same_identity_slides_ttl_without_duplicating / test_distinct_identities_coexist / test_max_queue_cap_evicts_oldest / **test_phase_alias_simulation_no_strobe**（回帰の番兵）
**分類**: CORE
### S1-SENSI-030: bg_observer はサイクルごとに監査行を永続化し、失敗が観測を止めない
**挙動**: 各サイクルで開始時刻 / 所要 / feed 試行数 / feed 失敗数 / 項目総数 / country 一致数 / kinetic 一致数 / 死者数一致数 / 発行信号数 / country 別内訳 / 別名網羅ギャップ / 観測シナリオ一覧 / 中断理由、を 1 行として永続化 **MUST**。**永続化の失敗はサイクルを壊してはならない MUST NOT**。個別 feed と個別項目の例外も同様に吸収 **MUST**。別名網羅にギャップがあっても**処理を継続 MUST**（一部でも観測がある方が無いよりよい = NP1）
**根拠**: background_observer.py:245-269・289-302・326-329・403-418
**検証**: tests/test_background_observer.py::test_cycle_log_records_per_gate_counters / _surfaces_alias_gap / _counts_failed_feeds / test_fetch_error_does_not_crash_cycle
**分類**: CORE（AP3 / AP4）
### S1-SENSI-031: すべてのセンサーはスケジューラに統合されなければならない
**挙動**: **すべてのセンサーはサーキットブレーカーのスキップ判定を経て取得し、成否をブレーカーへ通知 MUST**。broadcast 型センサーであっても例外としない **MUST**。**現行挙動**: 本センサーは専用の daemon スレッドを持ちスケジューラ登録から明示的に除外されている。ループはブレーカーのスキップ判定を参照せず成否通知も行わないため**ブレーカーは永久に閉のままで開くことがない**。docstring は「CB 統合は基底経由で維持」と主張するが実態と乖離しており、RSS 障害が継続しても取得抑制がかからない
**根拠**: bg_observer.py:36-51・144-155、radar/__init__.py:295-306（`_SCHEDULER_BYPASS`）vs scheduler.py:119-147
**検証**: 未検証（現行の迂回を pin するテストは無い）
**分類**: **DEFECT-PRESERVE**（D2 B-01。**v3 規範: scheduler 統合 MUST**。broadcast 型の取得対象解決はスケジューラ側の関心として設計する）

## 6. LLM インテルセンサー個別条項
### S1-SENSI-032: 一次 feed が失われた領域では集約ニュース検索 feed を代替とする
**挙動**: 外務省系の一次 RSS が失われた場合、**country ごとの絞り込みクエリによるニュース集約 feed を代替として用いる SHOULD**。ウェブサイト改装に対して耐久性があり主要通信社による当該省庁の報道を拾えるため、下流 LLM が求める信号と等価である。一次 feed が健全なソース（露国営メディア、DPRK 専門メディア）は**補完として併用 MUST**
**根拠**: diplomatic.py:38-135（feed 台帳は付録 A）
**検証**: 未検証
**分類**: CORE
### S1-SENSI-033: LLM センサーの対象 country は全 scorable シナリオの participant 和集合である
**挙動**: 走査対象は **focused シナリオの対象国ではなく全 scorable シナリオの participant 和集合 MUST**（ADR-004。background シナリオにも LLM インテルが供給されるため）。和集合が空なら全 feed の全対象を走査 **MUST**。feed の対象 country が 1 つも和集合に含まれない場合その feed は取得しない **MUST**
**根拠**: diplomatic.py:364-380、military_exercise.py:218-230、hacktivist_news_sensor.py:234-237、rss_narrative.py:636-641
**検証**: 未検証
**分類**: CORE（gdelt / telegram / tor / travel / convergence は本規則に従っていない → §8-A4）
### S1-SENSI-034: 外交 item の score_delta は urgency の 4 段写像である
**挙動**: `score_delta` = critical 3.0 / high 2.0 / medium 1.5 / low 1.0 **MUST**（既定 low = 1.0）。ドメインは `info` 固定 **MUST**。LLM 抽出フィールドは外交行動種別 / 対象国 / urgency / 発信国 / 地理的焦点 / 関連度 **MUST**
**根拠**: diplomatic.py:525-550
**検証**: 未検証
**分類**: CORE
### S1-SENSI-035: 軍事演習は事象種別ゲートで「非事象」を捨て「定期報告」を減点する
**挙動**: LLM に事象種別（新規展開 / 演習開始 / 即応度上昇 / 定期報告 / 過去分析 / 該当なし）を判定させ**「該当なし」は破棄 MUST**。**「定期報告」「過去分析」は破棄せず confidence に上限を課して保持 MUST**（自動確認はさせないがアナリストのレビュー対象には残す = NP1）。閾値: 上限 **0.50**。ハードコード
**根拠**: military_exercise.py:294-302・335-349
**検証**: 未検証
**分類**: CORE
### S1-SENSI-036: 軍事演習の score_delta は urgency 基礎値と規模ボーナスの加法である
**挙動**: `score_delta = 基礎値 + 規模ボーナス` **MUST**。基礎値 = critical 2.5 / high 2.0 / medium 1.5 / low 1.0、ボーナス = strategic 0.5 / operational 0.2 / tactical 0.0。上限 3.0
**根拠**: military_exercise.py:396-401
**検証**: 未検証
**分類**: CORE
### S1-SENSI-037: 軍事演習の item は physical ドメインに計上される
**挙動**: 本センサーの item のドメインは **`physical` 固定 MUST**。情報系 RSS を入力とするが報告対象が兵力の物理的展開であるため physical に計上する。この値は **TL1 の physical スコア下限ゲートに直接効く**（S1-SCORE-004）ため誤設定は最上位 TL の成立可否を左右する
**根拠**: military_exercise.py:426
**検証**: 未検証
**分類**: CORE（RSS 由来の LLM 判定が最上位 TL のゲートに寄与する設計自体は §8-A6）
### S1-SENSI-038: hacktivist_intel の入力は他センサーの検知ログであり新規 HTTP を発生させない
**挙動**: telegram の検知ログ全件を入力とし**新たな外部 HTTP 取得を行ってはならない MUST NOT**。キーワード事前フィルタを持たず**全文を LLM に渡す MUST**（`CLEAR` を除く全検知が対象）。dedup 鍵は `検知時刻 + チャンネル + country` **MUST**。本文（スニペット優先、無ければ全文抜粋）が空の項目は破棄 **MUST**
**根拠**: hacktivist_intel_sensor.py:1-16・37-40・70-97
**検証**: 未検証
**分類**: CORE
### S1-SENSI-039: hacktivist_intel の主 country は LLM 判定を優先し、null は破棄する
**挙動**: LLM が主 country を null / "NULL" / "NONE" / 空で返した場合は**破棄 MUST**（チャンネルのメタデータへフォールバック**してはならない MUST NOT**）。LLM の返した値が**2 文字の英字ならチャンネルのメタデータを上書きして採用 MUST**
**根拠**: hacktivist_intel_sensor.py:172-186
**検証**: 未検証
**分類**: CORE（8 系統中唯一の「LLM 上書き採用」規則 → §4 表 2）
### S1-SENSI-040: hacktivist_intel のドメインは攻撃種別から写像する
**挙動**: 攻撃種別が DDoS / defacement / flood / disruption のいずれかを含めば `cyber`、他（データ漏洩 / フィッシング等）は `info` **MUST**。`score_delta = 標的セクター基礎値 + タイムライン加算`、**上限 3.0 でクリップ MUST**。基礎値 = 政府 / 金融 / エネルギー / 通信 / 軍のいずれかを含めば 2.0、他 1.0。加算 = imminent 1.0 / soon 0.5 / planned 0.2 / 他 0.0
**根拠**: hacktivist_intel_sensor.py:188-201
**検証**: 未検証
**分類**: CORE
### S1-SENSI-041: hacktivist_news は「観測者の観測」層としてキーワード必須の事前フィルタを持つ
**挙動**: セキュリティ報道 feed に対し**ハクティビスト関連キーワードの一致を必須とする MUST**（不一致記事は LLM に渡さない）。マーケティング語彙は先に棄却 **MUST**。本文の HTML タグは除去 **MUST**。feed あたり採用上限 5 件 **MUST**
**根拠**: hacktivist_news_sensor.py:65-90・183-208
**検証**: 未検証
**分類**: CORE
### S1-SENSI-042: hacktivist_news は主 country が対象集合外の item を破棄する
**挙動**: LLM が返した主 country が対象 country 集合に含まれない場合**破棄**。8 系統中、本センサーのみがこの追加ゲートを持つ。プロンプトでは「対象リストは文脈であり、リスト外でも ISO コードを返せ、フィルタリングは system 側が行う」と指示しているため、**LLM に無駄な生成をさせた上で Python 側が捨てている**構造になっている
**根拠**: hacktivist_news_sensor.py:331-336（プロンプト）vs :395-401（破棄）
**検証**: 未検証
**分類**: ACCIDENTAL（§8-A9）
### S1-SENSI-043: hacktivist_news の score_delta は urgency 基礎値と攻撃種別ボーナスの加法である
**挙動**: 基礎値 = critical 2.0 / high 1.5 / medium 1.0 / low 0.5、ボーナス = DDoS 0.5 / combined 0.5 / defacement 0.3 / data_leak 0.2 / none 0.0。ドメインは `info` 固定 **MUST**（telegram 由来の hacktivist_intel が cyber に落ちうるのと非対称）
**根拠**: hacktivist_news_sensor.py:417-424・449
**検証**: 未検証
**分類**: CORE
### S1-SENSI-044: ground_osint の対象は「進行中」を示す検知に絞り込む
**挙動**: 検知ログのうち状態が `INTENT_DETECTED` / `TARGETS_FOUND` / `BURST` / `CRITICAL_BURST` のいずれかである項目のみを対象 **MUST**。さらに**標的 URL が存在するか、進行中を示す語彙を含むか、標的が 2 件以上あること MUST**。進行中語彙は英語・日本語の両方を含む **MUST**
**根拠**: ground_osint_sensor.py:36-58・136-148
**検証**: 未検証
**分類**: CORE
### S1-SENSI-045: 宣言はライブセンサーとの照合で裏付けを測る
**挙動**: telegram 上の攻撃宣言を**同時刻のライブセンサー観測と照合 MUST**。`裏付けあり = (CF の当該 country の攻撃記録が非空) OR (到達性成功率 < 0.7)` **MUST**。照合結果は LLM プロンプトの文脈として渡すが**LLM には「文脈のセンサー情報を判断に混ぜるな」と明示 MUST**（循環論法の防止）。裏付けがあり LLM の confidence がフロア以上のときのみ**Python 側で一度だけ confidence を加算 MUST**、上限でクリップ **MUST**。閾値: 到達性劣化 **0.7** / 加算 **+0.10** / 上限 **0.95**。ハードコード
**根拠**: ground_osint_sensor.py:84-104・166-168・216-217・231-235
**検証**: 未検証
**分類**: CORE
### S1-SENSI-046: 照合に用いる他センサー観測は鮮度と健全性を検証しなければならない
**挙動**: 他センサーの観測を相関判定に用いる場合、**その観測の鮮度（最終取得時刻）と健全性（health 状態）を検証 MUST**。劣化・失効した観測に基づく相関判定を**行ってはならない MUST NOT**、行えない場合は「照合不能」として明示 **MUST**（NP5+8: 結論不可の明示）。**現行挙動**: 参照先センサーの cache を無検証で読み、STALE / ERROR / CIRCUIT_OPEN のいずれであっても**成功時と同じ経路で「裏付けなし」と判定する**。参照先の取得順序にも暗黙に依存し、相関検知能力の劣化が完全に沈黙する
**根拠**: ground_osint_sensor.py:67-104（health 未参照の cache 直読）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 B-03。**v3 規範: 入力鮮度検証 MUST**。クロスセンサー参照は公式化された API を通し鮮度と健全性を返り値に含める）
### S1-SENSI-047: ground_osint の score_delta は「進行中」と「裏付け」の 2 条件で 3 段に決まる
**挙動**: 進行中 かつ 裏付けあり → **3.0**、いずれか一方 → **2.0**、宣言のみ → **1.0** **MUST**。裏付けは LLM の自己申告と Python 側照合結果の**論理和 MUST**。`countries` は主 country 単一・重み 1.0 **MUST**（本センサーは LLM に多国抽出をさせない）。ドメインは `cyber` 固定 **MUST**
**根拠**: ground_osint_sensor.py:242-253・276
**検証**: 未検証
**分類**: CORE
### S1-SENSI-048: 収斂トラッカーの監視対象 8 センサーの elevation 判定は個別規則である
**挙動**: 以下の規則で各センサーの elevation を判定 **MUST**（判定中の例外は「非 elevation」）: rss_narrative = `is_burst` 真 ／ telegram_mirror = `is_burst` 真 **または** 攻撃意図フラグ真 ／ gdelt = Z > **1.5** または トーン差分 < **−2.0** ／ diplomatic・military_exercise・apt_intel = 直近サイクルの投入件数 > 0 ／ ioda = 停止フラグ真 または 停止スコア > **0.3** ／ bgp_routing = 異常フラグ真。閾値: 1.5 / −2.0 / 0.3 すべてハードコード
**根拠**: convergence_tracker.py:20-28・113-166
**検証**: 未検証
**分類**: CORE
### S1-SENSI-049: スナップショットは非 elevation でも毎サイクル記録する
**挙動**: 各サイクルで country ごとに「今 elevation しているセンサー名の一覧」を**空リストであっても記録 MUST**（連続的な履歴が持続判定の分母になる）。保持期間を超えた行は毎サイクル削除 **MUST**。閾値: 保持 **72 時間**（`CONVERGENCE_SNAPSHOT_RETENTION_H`、env のみ）、周期 3600s（`CONVERGENCE_TRACKER_INTERVAL`、env のみ）
**根拠**: convergence_tracker.py:44-47・85-108・189・204-205
**検証**: 未検証
**分類**: CORE
### S1-SENSI-050: 持続収斂は「窓内スナップショットの過半で elevation」が閾値本数以上のとき成立する
**挙動**: 判定窓（現在から持続時間分だけ遡る）のスナップショットを取得 **MUST**。**スナップショットが 2 件未満のときは収斂不成立 MUST**（判定材料不足）。各センサーについて窓内で elevation していたスナップショット数を数え、`最小ヒット数 = max(1, floor(N/2))`（N = 窓内スナップショット数）以上のセンサーを**「持続 elevation」とする MUST**:
`sustained = { s | count(s) ≥ max(1, ⌊N/2⌋) }` ; `converged = |sustained| ≥ 最小センサー本数`
**単発スパイクを収斂と誤認させないための過半数条件は必須 MUST**。閾値: 最小センサー本数 **3**（`CONVERGENCE_MIN_SENSORS`）、持続時間 **6 時間**（`CONVERGENCE_MIN_HOURS`）。**ともに env のみ・DB override 不可**
**根拠**: convergence_tracker.py:45-46・186・207-230
**検証**: 未検証（**D5 §4.2 が「特に危険」と名指しした無テスト検知式**）
**分類**: CORE
### S1-SENSI-051: 収斂警報は country ごとに 24 時間のクールダウンを持つ
**挙動**: 収斂成立中でも同一 country の前回警報から**クールダウン未経過なら LLM 合成を行わない MUST**。クールダウンの記録は**投入に成功したときのみ更新 MUST**（LLM が雑音と判定した場合は再試行の余地を残す）。閾値: **86400 秒**。ハードコード・in-memory・再起動で消失
**根拠**: convergence_tracker.py:49-51・235-247
**検証**: 未検証
**分類**: CORE（揮発は §9-DP4）
### S1-SENSI-052: 収斂の LLM 合成は実データを文脈として与え、confidence と pattern 種別でゲートする
**挙動**: LLM に渡すのは**センサー名の羅列ではなく各センサーの実測値または実際の見出し MUST**（Z 値、トーン差分、直近インテル見出し、チャンネル状態、停止スコア等）。名前だけではモデルが一般論を生成するため。confidence **0.50 未満、または pattern 種別が「雑音収斂」なら投入しない MUST**。プロンプトには**「情報ドメインの信号は物理・サイバーと同等に扱え」と明示 MUST**（情報信号は物理行動に先行する早期指標であるため）。`score_delta = urgency 基礎値（critical 3.0 / high 2.5 / medium 2.0 / low 1.5）+ min((持続センサー数 − 最小本数) × 0.2, 1.0)`、上限 4.0 **MUST**。現行では見出し取得が**インテル台帳の直接読取**で行われている（センサー層 → スコアリング層管轄データの越境）
**根拠**: convergence_tracker.py:259-310（うち :265・:284-288 が台帳直読）・358-366・379-392
**検証**: 未検証
**分類**: CORE（台帳直読の構造は §9-DP10 / D2 A-09）
### S1-SENSI-053: 収斂 item のドメインは LLM 出力に従う
**挙動**: item のドメインは LLM が返す支配的ドメインをそのまま用いる。許容集合は cyber / physical / info / **mixed** であり既定は mixed。**`mixed` は 3 ドメイン語彙に存在しない値**であり S1-INGEST-019 の「domain は 3 値のいずれか」規範に反する
**根拠**: convergence_tracker.py:394-396・423
**検証**: 未検証
**分類**: ACCIDENTAL（§8-A5）
### S1-SENSI-054: センサーが生成する状態は単一の永続層管轄下になければならない
**挙動**: センサーが生成する状態は**バックアップ・WAL 運用・スキーマ管理の対象である単一の永続層を経由 MUST**。**現行挙動**: 収斂トラッカーは共通永続層を経由せず専用の SQLite ファイルを直接開いてスナップショットを保持する。このファイルはバックアップ運用・WAL 規律・スキーマ移行の管轄外に置かれている
**根拠**: convergence_tracker.py:54-110（`sqlite3.connect` 直呼び）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（D2 A-09。**v3 規範: 永続層の単一管轄 MUST**。メタセンサーの層所属は P で定義する）

## 7. 閾値カタログ

| 閾値 | 値 | config キー | 3 層解決 | 出典 |
|---|---|---|---|---|
| GDELT 履歴窓 / トーン絶対閾値 | 28 日 / −15.0 | `GDELT_HISTORY_WINDOW` / `GDELT_TONE_ALERT_THRESHOLD` | DB override 可 | SENSI-001/004 |
| GDELT DOW Z 下限 / 最小サンプル / std フロア / 曜日別保持 | −2.0 / 3 / 0.5 / 20 | — | 不可 | SENSI-002/003/004 |
| ナラティブ Z ALERT / CRITICAL / 保持日数 | 2.0 / 3.0 / 30 | `NARRATIVE_ZSCORE_ALERT` / `_CRITICAL` / `NARRATIVE_BASELINE_DAYS` | DB override 可 | SENSI-008/009/010 |
| ナラティブ初回信号 Z | 3.0 | `NARRATIVE_ZSCORE_FIRST_SIGNAL` | **env のみ** | SENSI-008 |
| ナラティブ最小サンプル / LLM プール / ソース別収集 | 7 / 6 / 2 | — | 不可 | SENSI-008/011 |
| Telegram 投稿鮮度窓 / 取得周期 | 48h / 900s | `TELEGRAM_POST_MAX_AGE_HOURS` / `TELEGRAM_MIRROR_POLL_INTERVAL` | env のみ / registry 登録あり | SENSI-013 |
| Telegram 本文長下限 / 再試行 / 待機上限 / ジッタ | 2000B / 3 / 30s / 1.5-4.0s | — | 不可 | SENSI-012/015 |
| Telegram 主張確度 4 段 / 検知ログ上限 | 0.6-0.4-0.2-0.0 / 200 | — | 不可 | SENSI-017/018 |
| Telegram 下流抑制閾値 | 0.5 | `TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD` | env のみ | SENSI-017（消費は別担当）|
| Tor relay 減少 / 利用者急増 / DROP | 0.40 / 1.00 / −0.3 | — | 不可 | SENSI-019 |
| 渡航勧告 収斂ソース数 / 対象レベル / timeout | 2 / 3 / 20s | — | 不可 | SENSI-022/025 |
| bg_observer 有効化 / 周期 / TTL / キュー上限 | false / 300s / 1800s / 200 | `BG_OBSERVER_ENABLED` / `_INTERVAL_SEC` / `_SIGNAL_TTL_SEC` / `_MAX_QUEUE` | **env のみ** | SENSI-026/029 |
| bg_observer raw_score 3 段 | 0.4+0.05n / 0.45 / 0.25 | — | 不可 | SENSI-028 |
| LLM confidence フロア | 0.35（7 系統） / 0.50（収斂） | — | 不可 | INGEST-014 |
| LLM 間接関連度 上限 / 定期報告上限 | 0.45 / 0.50 / 0.50 | — | 不可 | INGEST-017、SENSI-035 |
| LLM max_tokens | 200 / 250 / 256 / 280 / 300 / 400 / 512 | — | 不可 | §4 表 2 |
| 記事 dedup 上限 / 鮮度窓 | 1000・500 / 48h・168h | — | 不可 | INGEST-005/008 |
| RSS timeout | 15s（5 系統） / 10s（1 系統） | — | 不可 | INGEST-001 |
| 収斂 最小センサー本数 / 持続時間 | 3 / 6h | `CONVERGENCE_MIN_SENSORS` / `_MIN_HOURS` | **env のみ** | SENSI-050 |
| 収斂 保持 / クールダウン / elevation 閾値 | 72h / 86400s / 1.5・−2.0・0.3 | `CONVERGENCE_SNAPSHOT_RETENTION_H` / — | env のみ / 不可 | SENSI-048/049/051 |
| ground_osint 到達性劣化 / 加算 / 上限 | 0.7 / +0.10 / 0.95 | — | 不可 | SENSI-045 |

**v3 への示唆**: 本領域だけで**ハードコード閾値 30 件超・env のみ 8 件**。S1-scoring-core の DP2 と
同じ問題であり、**検知に影響する全閾値を宣言的 registry へ載せる MUST**（NP6）。特に S1-SENSI-050 の
収斂式は「結論に直接効く 2 閾値がともに env のみ・無テスト」である。

## 8. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | Tor / 渡航勧告の前サイクル値の既定が「現在値」。初回観測は必ず変化なしと判定される | 起動直後〜1 サイクルは原理的に検知不能。NP1 上、初回を「判定不能」として明示すべきでは |
| A2 | 渡航勧告の引上げ判定がソースごとの独立 in-mem。再起動で全 country が初回状態に戻る | 上と同根。永続化すべきか |
| A3 | 英 FCDO パーサの最終フォールバック「本文に `travel` を含めばレベル 2」 | 渡航勧告 feed の記事はほぼ全て `travel` を含む。実質「不明 = レベル 2」であり収斂カウントの分母を汚す |
| A4 | 対象 country の解決規則が 2 系統に分裂。LLM 系 4 基は participant 和集合、gdelt / telegram / tor / travel / convergence の 5 基は focused の対象のみ | C-lite（background も採点する）契約と不整合。background の country は統計系センサーのベースラインが育たない |
| A5 | 収斂センサーの item ドメインに `mixed` が入りうる（3 ドメイン語彙外） | S1-INGEST-019 違反。スコアリング層での扱いを含めて裁定要 |
| A6 | 軍事演習センサー（RSS + LLM 判定）の item が physical に計上され TL1 の physical ≥ 3.0 ゲートに寄与する | 最上位 TL の成立に「ニュース記事の LLM 判定」が効いてよいか。NP4 と NP5+8 の緊張点 |
| A7 | GDELT の標準偏差フロア 0.5 がハードコード | トーンのスケール依存。値の由来が記録されていない |
| A8 | ナラティブ初回信号 Z = 3.0 が env のみで config registry 非登録 | NP1 に直結する値（無音期からの立ち上がり検知）が導出開示の外にある |
| A9 | hacktivist_news のみ「主 country が対象集合外なら破棄」。プロンプトは逆を指示している | 8 系統で唯一の非対称。プロンプトと実装が矛盾しており、どちらが意図か |
| A10 | bg_observer が「取得成功だが 0 件」を feed 失敗として計上する | 静かな feed と壊れた feed が同一カウンタに乗る。AP3 の feed 死活可視化の精度 |

## 9. DEFECT-PRESERVE（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | bg_observer が専用スレッドで動き CB を迂回。ブレーカーは永久に閉 | 全センサーはスケジューラ経由 **MUST** | **B-01** |
| DP2 | ground_osint が参照先センサーの鮮度・健全性を検証せず相関判定。劣化が沈黙 | クロスセンサー参照は公式 API 経由・鮮度と健全性を返り値に含める **MUST** | **B-03** |
| DP3 | 収斂センサーが共通永続層外の専用 SQLite を持つ | 永続層の単一管轄 **MUST** | **A-09** |
| DP4 | 収斂センサーの警報クールダウンが in-memory。再起動直後に重複警報しうる | 運用状態は永続化 **MUST** | B-05 |
| DP5 | ナラティブの burst 投入済み集合と 6 系統の記事 dedup 集合がすべて in-memory | 同上 | B-05 |
| DP6 | telegram のベースラインがクラス変数 in-memory。かつ**保持上限が「日数」の生値**（30 サンプル = 実質 15 時間窓）。同型と自己申告する rss_narrative は 2026-04-29 に `日数 × 1 日あたり回数` へ修正済で telegram には未反映 | ベースライン基盤の一元化 **MUST**。窓長は時間で定義し取得周期から導出 **MUST** | **A-03**（本仕様で新規発見。片側だけ修正された複製の典型） |
| DP7 | RSS 取得・パースが 6 系統に複製。2 段パースと死活分類は 1 系統のみ、timeout / UA / 429 扱い / 対応形式 / 鮮度窓が系統ごとに異なる（§4 表 1） | 単一の取得層 **MUST**（INGEST-001〜009） | A-02 |
| DP8 | LLM 投入骨格が 8 系統に複製。max_tokens 200〜512、主 country 規則 4 通り、domain 決定主体 4 通り（§4 表 2） | 単一の投入層 + 4 スロットのみセンサー固有 **MUST**（INGEST-010〜020） | A-02 |
| DP9 | 対象 12 基すべてが基底の HTTP ヘルパー（timeout / 429 自動処理）を使わず raw HTTP を直呼び | 取得は共有層のみを経路とする **MUST** | A-10 |
| DP10 | 収斂センサーがインテル台帳を直接読む（センサー層 → スコアリング層管轄データ） | メタセンサーの層所属を P で定義し参照は公式 API 経由 **MUST** | A-09 |
| DP11 | intel item のキー名 `theater` が主 country の意味で残存。センサー内部変数・検知ログのキーも同様 | 語彙は country / scenario で統一 **MUST** | C-01 |
| DP12 | tor / 渡航勧告 / ナラティブの前サイクル値・ベースラインが in-memory | ベースライン基盤の一元化 **MUST** | A-03 |
| DP13 | hacktivist_news が diplomatic の private 関数を関数内 import して死活分類を借用 | 共有層で解消 **MUST** | A-02 |

## 10. テストトレーサビリティ

| テスト | 件数 | 対応条項 |
|---|---|---|
| test_rss_narrative.py::TestClassifyArticleGeo | 14 | SENSI-006 |
| ::TestCountKeywordsGeoFilter | 4 | SENSI-005 / -006 / -007 |
| ::TestGetBurstArticlesGeoFilter / ::TestGeoFilterIntegration | 3 | SENSI-006 / -011 |
| ::TestBaselineRetention | 3 | SENSI-008 / -009 |
| test_background_observer.py（無効時 no-op / broadcast 4 件） | 5 | SENSI-026 / -027 |
| ::cycle log 系 + fetch 例外 | 5 | SENSI-030（+ SENSI-026） |
| ::TTL / identity / キュー上限 / ストロボ回帰 | 8 | SENSI-029 |
| test_apt_prompt_dedup.py | 4 | INGEST-012（apt_intel 個別は S1-sensors-cyber-phys 担当） |
| test_engine.py::TestTorMetricsSensor | 5 | SENSI-019 / -020 / -021（うち 3 件は本番関数を呼ばない） |
| test_rss_extractor.py | 56 | SENSI-028（段階境界のみ。抽出器本体は S1-conclusions 担当） |
| test_sanitize_llm_input.py | — | INGEST-011（関数本体は S4 担当） |
| test_intel_multicountry.py | 12 | INGEST-015（検証面は intel_queue 側 = 別担当） |

### GAP（仕様化できたが検証が存在しない）

| ID | 内容 |
|---|---|
| GAP-01 | **gdelt の DOW ベースライン式全体**（日バケット記録・同曜日集計・std フロア 0.5・Z 下限 −2.0）が無テスト |
| GAP-02 | **telegram の Z-score / 状態ラダー / 主張確度 4 段 / 検知ログ dedup** が全て無テスト。窓長の欠陥（DP6）も無テスト |
| GAP-03 | **渡航勧告 3 パーサ**（米 / 英 / 加 HTML + アイコンフォールバック）と収斂集計が無テスト |
| GAP-04 | **収斂の持続昇格式**（過半数条件・≥3 センサー・≥6h 窓・クールダウン）が無テスト。D5 が「特に危険」とした 5 件中 2 件が本書対象 |
| GAP-05 | **LLM 投入経路 6 系統**が全て無テスト。confidence 上限規則・主 country 破棄規則・score_delta 式のいずれも pin されていない |
| GAP-06 | tor_metrics のテスト 5 件中 3 件が**本番関数を呼ばずインライン再実装**（S1-scoring-core §6 と同種。実装を変えてもテストが通る） |
| GAP-07 | rss_narrative は geo filter とベースライン保持のみテスト済。**Z-score 式・burst 閾値・クラスタ解析・legacy fallback** は無テスト |
| GAP-08 | 共通条項 INGEST-001〜020 のうちテストで pin されているのは -011 / -012 / -015 の 3 件のみ |

## 11. 未決事項

1. **メタセンサー 2 基（convergence_tracker / ground_osint）の層所属**が未確定。入力が他センサーの
   cache とインテル台帳であり「センサー」の定義（外部からデータを取得する）に当てはまらない。
   P で「派生指標」層を定義するか、スコアリング層へ移すかの判断が要る
2. **S1-SENSI-050 の持続収斂式と S1-SCORE-003/006 のドメイン収斂の関係が未定義**。前者は
   「≥3 センサー × ≥6h」、後者は「≥2 ドメインの同時発火」で、収斂センサーの item が intel 経由で
   ドメインスコアに入るため**同一の物理事象が 2 経路で計上されうる**。S1-SCORE-008 の dedup が
   これを捕捉するかは未検証
3. `bg_observer_rss` を既定有効にするかは**オーナー判断事項**。現状 false のため、C-lite の
   background 観測供給は実質 LLM インテル 4 基のみに依存している
4. 対象 12 基のうち 10 基が無テストのため本書の条項の大半は**コード読解のみが根拠**。
   docstring と実装の乖離（D2 E-18 の系譜）が本領域にも存在する可能性は排除できない。
   実際 telegram.py:275 の「rss_narrative と同じロジック」という自己申告は **DP6 で偽と判明した**
5. `apt_intel` は Cyber 分類のため個別条項を持たないが**LLM 投入 8 複製で唯一の 2 段ゲート構造**
   （Stage 1 で戦略的関連性と地理的標的を判定 → Stage 2 で本分析）を持つ。共通投入層の設計時に
   「2 段ゲートを共通仕様に含めるか apt_intel 固有とするか」の裁定が要る

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
| ENISA / ACSC | RSS 廃止 / 非 AU IP を geo-block | 削除（silent failure を残さない方針） |
| BSI | CERT-Bund WID エンドポイントへ移転 | URL 更新済 |
| 一次 MFA feed 全般 | 7 本すべてが retire / 非 RSS 化 | **代替戦略: country 別ブーリアンクエリのニュース集約 RSS。改装に耐え 1 クエリ 30-100 件を返す** |

**保存すべき運用知**: 死んだ feed も**設定から消さない**（別ネットワーク環境からの再試行余地・復活検知）／
`t.me/s/` スクレイプは UA プールローテーション + 403/429 指数バックオフ 3 回で、失敗は
「プレビュー無効化 / スロットリング / ネットワーク断」の 3 モードを区別する／
courtesy delay は GDELT 0.5s（country 間）・Onionoo 0.5s（リクエスト間）・Telegram 1.5-4.0s 無作為
（チャンネル間）／GDELT のトーンには**曜日バイアスがある**（曜日別ベースラインが必須）／
渡航勧告は**3 政府 3 形式**（米 RSS / 英 Atom / 加 HTML テーブル + SVG アイコン名）。
