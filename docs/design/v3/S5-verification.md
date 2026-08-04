# S5 — 検証・パリティ仕様

**スコープ**: v3 が現行系と同等以上に検知できることを**数値で証明する**手続きの仕様。(1) 沈黙した検知失敗の常時監視、(2) replay パリティハーネス、(3) recall 連続性、(4) shadow 並走と cutover の数値条件、(5) ラベル系譜監査、(6) テスト移植計画と v3 CI、(7) カットオーバー後 30 日の強化監視。原則 **R3（パリティゲート）** と **R4（旧系を止めない）** の実行文書。

**隣接仕様との境界**: 採点の式と閾値は S1-scoring-core / S1-scoring-pipeline、結論の組み立ては S1-conclusions、較正機構の**現行挙動**は S1-calibration（特に §D の S1-CALIB-026〜032）が担当する。本書はそれらを**検証する側**のみを規定し、既出条項は再掲せず引用する。API 契約は S2、スキーマ移行は S3、セキュリティは S4。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md) に従う。
**分類欄の拡張**: S5 は現行に対応実装が無い検証機構を多く規定するため、S0 の
CORE / ACCIDENTAL / DEFECT-PRESERVE に **NEW**（v3 で新設する検証要件）を加える。
NEW 条項の「根拠」欄には、要件を要求する D2 欠陥 ID と実測の file:line を書く。

**中心課題**: Phase D 診断は「センサーは fetch 成功・health OK だが**判定だけが死んでいる**」欠陥を 4 件発見した（F-02 / F-06 / F-08 / F-09）。過去 3 回の calibration インシデントも**全テスト通過のまま** 数週間 prod を劣化させた。§2.1 と §2.5 はこの族の再発を**検出可能にする**ための仕様である。

---

## 1. 用語

CLAUDE.md の用語定義に従う（country / scenario / participant / focused / background / C-lite）。本書固有:

- **TL**: 脅威レベル。**1=CRITICAL … 5=NORMAL（DEFCON 式）**。比較は必ず `severity = 6 − TL` を経由する
- **判定フラグ (detection flag)**: センサーが観測から導く真偽値または離散状態（`is_burst` / `is_surge` /
  `is_jammed` / `country_status` 等）。スコアリング層への入力となる最小の判定単位
- **沈黙した検知失敗**: fetch が成功し health が OK でありながら、判定フラグが構造的に成立不能な状態
- **パリティ窓**: 旧系と v3 を同一入力で再採点し比較する時間幅。既定 **30 日**
- **エポック (label epoch)**: ラベル生成器の意味論が変わった境界。異なるエポックの recall 系列は比較不能
- **insensitive / sensitive 方向**: v3 が旧系より severity を**低く**出す不一致を insensitive、
  **高く**出す不一致を sensitive と呼ぶ。NP1 により両者は非対称に扱う
- **旧系 (legacy)**: 現行 v1/v2 併存系。**v3 default-on までは旧系が正**（R4）

---

## 2. 挙動条項

### 2.1 沈黙した検知失敗の常時監視

#### S5-VERIF-001: センサーは判定フラグを宣言的カタログとして公開する
**挙動**: 各センサーは判定フラグを機械可読カタログとして公開 **MUST**。1 エントリは `{flag_id, 型, 取りうる値, 対応閾値キー, 被比較値の識別子と単位, expected_fire_interval_days}` を持つ **MUST**。カタログに無い判定フラグをスコアリング層へ渡してはならない **MUST NOT**。
**根拠**: D2 F-06/F-08。現行は fetch() 戻り dict の ad-hoc キーで中央列挙が無い（radar/sensors/telegram.py:395-432、radar/sensors/gps_jamming.py:195-218、radar/sensors/isr_hotspot.py:107）
**検証**: 未検証（現行に対応機構なし）
**分類**: **NEW**

#### S5-VERIF-002: 各判定フラグの最終発火時刻を永続記録する
**挙動**: フラグが True（enum は非既定値）になるたび `last_fired_at` を更新し**永続化 MUST**。併せて `first_observed_at` と `fire_count_30d` を保持 **MUST**。再起動で失われてはならない **MUST NOT**。
**根拠**: D2 F-08。現行 BaseSensor は `last_fetch_ts` / `health` / CB 状態のみを持ち、`last_fired` 相当のフィールドはコードベースに存在しない（radar/sensors/base.py:24-38,227-243）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-003: 長期無発火を数値規則で異常と判定する
**挙動**: 毎日 `silence_ratio = (now − last_fired_at) / (expected_fire_interval_days × 86400)` を評価し、`>= 1.0` → **WARN**、`>= 3.0` → **ANOMALY MUST**。一度も発火せず `now − first_observed_at >= 30 日` なら **ANOMALY MUST**（実装当初から無発火 = F-08 の症状）。
**閾値**: WARN 倍率 1.0 / ANOMALY 倍率 3.0 / 未発火猶予 30 日
**根拠**: D2 F-08（gps_jamming が実装当初から恒久無発火、テスト 0 件で長期未発見）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-004: health は「取得の生存」と「判定の生存」の 2 軸で表明する
**挙動**: 健全性は `fetch_health` と `detection_health` の**独立 2 軸 MUST**、総合 health は悪い方を採る **MUST**。`fetch_health == OK` かつ `detection_health == ANOMALY` の状態を UI・API・台帳のいずれでも「OK」と表示してはならない **MUST NOT**。
**根拠**: D2 F-06/F-08 の共通構造。現行 health は fetch 成否のみで定義され判定側に盲目（radar/sensors/base.py）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-005: 観測台帳は判定フラグの真偽と抑制理由を保持する
**挙動**: 観測台帳の 1 行は `{ts, sensor, scope, country, raw_value, baseline, status, flags{}, fired_reason, suppressed, suppress_reason}` を保持 **MUST**。判定に関わる項目を永続化の境界で落としてはならない **MUST NOT**。
**根拠**: RationaleEntry は 4 項目を持つ（radar/models.py:22-52）が `sensor_observation_ts` は `(sensor, scope, ts, score, baseline, status)` のみで `fired_reason` / `suppressed` / `suppress_reason` を落とす（radar/database.py:1184-1195）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-006: 監視経路は語彙が一致し、構造エラーを 0 件へ潰さない
**挙動**: 観測台帳の `scope` 値域を宣言的に定義し、**書込側の生成規則と読取側の照会規則が同一語彙を使うことを CI で機械検証 MUST**。監視クエリが列不在・表不在で失敗した場合は**例外を伝播 MUST**、「安全側の 0」として握り潰してはならない **MUST NOT**。集計 0 と照会失敗は別状態 **MUST**。
**根拠**: 書込は `scope="focused"` 固定（radar/routes/core.py:2993-3008）、読取は `scope='theater:{cc}'` （radar/calibration/drift_watchdog.py:170、scenario_improver.py:402）→ drift 信号が恒久飢餓。`_safe_count` は存在しない `theater` 列への照会の OperationalError を log.debug で 0 に潰す（radar/calibration/_proposal_guards.py:130-138,178-181）
**検証**: tests/test_drift_watchdog.py（8 件。scope 不一致は検出できていない）
**分類**: **DEFECT-PRESERVE**（NP5+8: 測れないことを 0 と表現している）

#### S5-VERIF-007: すべての閾値キーは単位を必須宣言する
**挙動**: 閾値キーのメタデータは `unit` を**必須 MUST**、値域は閉じた語彙 `{ratio, percent, count, s, min, h, d, km, z, score, bool}` **MUST**。空文字を許してはならない **MUST NOT**。
**根拠**: D2 F-08。現行 `ConfigKey.unit` は既定 `""` の任意フィールドで、98 登録中 27 のみ注釈済、
**`percent` 相当の注釈は 0 件**（radar/config_layered.py:74、radar/config.py の登録群）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-008: 異単位の比較を起動時に拒否する
**挙動**: 判定フラグカタログの被比較値は単位を持つ **MUST**。閾値と被比較値の単位が異なる比較は
**起動時 FAIL MUST**（実行時に黙って比較してはならない **MUST NOT**）。
**`ratio` と `percent` は異単位として扱う MUST**。
**根拠**: D2 F-08（`jam_ratio` は 0–1 の比率、閾値 `GPS_JAM_THRESHOLD=3.0` は百分率想定。radar/sensors/gps_jamming.py:178,182-197,209,213）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-009: 閾値の到達可能性を静的検査と分布監視の両方で検証する
**挙動**: (a) 被比較値の定義域が既知（比率 = `[0,1]` 等）なら、閾値の既定値・`min_value`・`max_value` が
**定義域と交わらない場合は起動時 FAIL MUST**。(b) 直近 30 日の被比較値分布の p99 が
`threshold × 0.5` 未満なら**到達不能疑いとして WARN MUST**（サンプル 100 件未満なら
`INSUFFICIENT_DATA` を表明し WARN にしない **MUST**）。
**閾値**: 到達不能疑い倍率 0.5 / 最小サンプル 100
**根拠**: `GPS_JAM_THRESHOLD` は default 3.0 / min 0.5 / max 20.0（radar/config.py:1134-1145）だが被比較値は `[0,1]` → 既定でもチューニング範囲の大半でも成立不能。(b) は較正で閾値を動かした後の恒久無発火を捕捉する
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-010: ベースライン窓は時間で宣言し、サンプル上限は取得周期から導出する
**挙動**: 移動ベースラインの保持上限は
**`cap = window_days × floor(86400 / poll_interval_sec)` で導出 MUST**。
設定値の「日数」を直接サンプル数として使ってはならない **MUST NOT**。
**根拠**: 正しい実装は radar/sensors/rss_narrative.py:625-634（`cycles_per_day` を掛け、docstring に 2026-04-29 の修正理由を明記）。誤った実装は radar/sensors/telegram.py:291-298 （`[-NARRATIVE_BASELINE_DAYS:]` = 30 サンプル、poll 900s → 実効窓約 7.5 時間）
**検証**: 未検証（telegram は無テスト）
**分類**: **DEFECT-PRESERVE**（D2 F-06。CRITICAL・NP1 直撃）

#### S5-VERIF-011: 実効ベースライン窓を常時検査し、周期変更時に再計算する
**挙動**: `effective_window_h = n_samples × poll_interval_sec / 3600` を算出し、`|effective_window_h / designed_window_h − 1| > 0.20` なら **ANOMALY MUST**。取得周期を実行時に変える設計のセンサーは**周期変更のたびに上限を再計算 MUST**、起動時に一度だけ計算した上限を保持し続けてはならない **MUST NOT**。
**閾値**: 許容乖離 20%
**根拠**: D2 F-06（設計 30 日 vs 実効 7.5 時間 = 乖離 99%）。`ct_log` / `ooni` は `_NORMAL_INTERVAL` を実行時に変更する
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-012: ベースラインは永続し、未成熟を health に表明する
**挙動**: すべての統計ベースラインは**永続 MUST**（再起動で失われてはならない **MUST NOT**）。Z-score が有効になる最小サンプル数に達するまでは `detection_health = IMMATURE` を表明 **MUST**、OK と表示してはならない **MUST NOT**。
**根拠**: D2 A-03。揮発側 = radar/sensors/rss_narrative.py:130、telegram.py（class 変数 `_baseline_tg`）、bgp_routing.py:27。永続側 = `hod_baseline` / `checkhost_hod` / `bgp_hod` / `gdelt_dow` / `sensor_zscore_stats`（radar/database.py:671-712）と不統一
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-013: 設定値は registry 経由でのみ読み、未登録キーは起動時に失敗させる
**挙動**: 結論に影響する設定値は**宣言的 registry の解決経路からのみ読む MUST**、環境変数の直読みを行ってはならない **MUST NOT**（違反は CI で検出 **MUST**）。registry に登録の無いキーの解決要求は**起動時 FAIL MUST**、型強制・範囲検証・既定値・DB 層をすべて迂回した生値を返してはならない **MUST NOT**。
**根拠**: D2 F-15。現行は未登録キーで `os.getenv` の未変換文字列（未設定なら None）を返しログも出ない（radar/config_layered.py:256-259）。registry 登録自体も best-effort な try 内にあり import 失敗で空のまま起動する（radar/config.py:703 付近）。センサー層に直読み 28 箇所、`radar/` 全体で 304 箇所。`GPS_JAM_THRESHOLD` は registry 登録済（config.py:1134）なのにセンサーは `_os.getenv` で直読みする（radar/sensors/gps_jamming.py:182-183）ため、**SETTINGS の DB override が効かないまま「チューナブル」として露出している**
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-014: 設定到達性を双方向で監査する
**挙動**: 「登録済みだが一度も読まれていないキー」と「読まれたが未登録のキー」の
**双方向を列挙する監査を提供 MUST**（前者は死んだツマミ、後者は沈黙フォールバック）。
監査は起動から 24 時間以上稼働した実績に基づく **MUST**。
**根拠**: 現行 `GET /api/v2/config_audit` は変更台帳のみを返し読み取り経路を追跡しない（radar/routes/llm_routing_v2.py:168-208）。`/api/v2/config/registry` / `/values` は登録側のみ（radar/routes/admin.py:69,123）
**検証**: tests/test_config_audit_endpoint.py（7 件。形状のみで到達性は未検証）
**分類**: **NEW**

#### S5-VERIF-015: 識別子による突合は実在検証を伴う
**挙動**: 識別子集合による突合（許可リスト・除外リスト・ルーティング表）は、参照側の識別子が
**実在集合の部分集合であることを起動時に検証 MUST**、不一致は FAIL **MUST**
（黙って空集合として振る舞ってはならない **MUST NOT**）。除外規則の突合対象は**構造化キー MUST**、
表示用に整形された文字列への部分一致で突合してはならない **MUST NOT**。
**根拠**: D2 F-02（許可リストは `"cf"` / `"ioda"`、実登録名は `"cloudflare_radar"` / `"ioda_bgp"` → force 経路でこの 2 基は決して取得されない。radar/routes/core.py:59-61,80 vs radar/sensors/cloudflare.py:26, radar/sensors/ioda.py:42）、D2 F-03（noise 除外が整形文字列への部分一致）
**検証**: 未検証（force 経路は完全無テスト）
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-016: 沈黙検知失敗検査は 1 日 1 回の単一ジョブとして実行し結果を公開する
**挙動**: S5-VERIF-003 / 009 / 011 / 014 / 015 を **1 日 1 回の単一ジョブに束ねて実行 MUST**。結果は追記専用台帳に `{検査 ID, 対象, 判定, 実測値, 期待値, 初回検出時刻}` で記録 **MUST**、ANOMALY が 1 件でもあれば AP3 自己評価面に表明 **MUST**。ジョブは**永続スケジュール（次回実行時刻を永続化）で駆動 MUST**、揮発カウンタで駆動してはならない **MUST NOT**。
**根拠**: D2 F-01（保守ワーカのオフセットジョブがプロセス内カウンタ駆動で、再起動が 24 時間を下回ると offset 10-12 が一度も走らない。radar/scheduler.py:175-179,480-633）。現行の silent-failure 台帳はプロセスローカル in-memory registry で再起動で消える（radar/conclusions/shadow_metrics.py:54）
**検証**: tests/test_scheduler_chronic_hook.py（3 件。chronic フックのみ）
**分類**: **NEW**

### 2.2 Replay パリティハーネス

#### S5-VERIF-017: 台帳は latest-row-at-T 意味論を満たす
**挙動**: パリティ入力台帳は**追記専用 MUST**、任意時刻 T に対し型ごとの `WHERE observed_at <= T ORDER BY observed_at DESC LIMIT 1` が
**T 時点にアナリストが見た状態を返す MUST**。「遷移 + 定期ハートビート」のみを書いてよいが、
A→B→A の復帰は**必ず 3 行として記録 MUST**。多値型（ANOMALY）は集合が変わったとき
**集合全体を単一タイムスタンプで書き直す MUST**。
**根拠**: radar/conclusions/persistence.py:58-204、radar/routes/conclusions_v2.py:468-541
**検証**: tests/test_conclusion_write_gating.py（12 件）
**分類**: CORE（AP4 の中核。v3 でも同一意味論を維持）

#### S5-VERIF-018: 30 日パリティ窓に耐える信号レベルの入力台帳を持つ
**挙動**: v3 は**信号レベル（センサー × 国 × tick）の入力台帳を持ち、retention はパリティ窓の 2 倍以上 MUST**（既定 **60 日**）。1 行は `{tick_ts, sensor, signal_source, domain, country, raw_score, status, flags{}, confidence, suppressed, suppress_reason, evidence_url}` **MUST**。
**根拠**: 現行 retention は sensor_observation_ts **24h**、llm_intel 7d、scenario_tl_observation 42d、scenario_contribution_log 90d、conclusions 90d（radar/database.py:5354-5503）。
**信号レベルで 30 日を再生できる表は存在しない**。既存の replay 実装が `contributions=[]` で
採点せざるを得ないのはこのためで、ANOMALY と source_urls は原理的に replay 不能
（scripts/backfill_v2_ledger.py）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-019: 採点ティックは冪等でなければならない
**挙動**: 同一入力に対する採点ティックの 2 回実行は**同一結果 MUST**。走行統計（Welford・時間帯別ベースライン・適応 Z-score）の更新は**採点入力の算出とは分離した明示的な独立段 MUST**、採点の読み取り経路が統計を書き換えてはならない **MUST NOT**。
**根拠**: D2 F-05。現行は `compute_adaptive_zscore` が読み取りのたび `sensor_zscore_stats` へ走行統計を書き込む（radar/scoring.py:500-524 → radar/database.py:4207）
**検証**: 未検証（S1-PIPE GAP-12）
**分類**: **DEFECT-PRESERVE**（S1-PIPE-035 の再掲。**パリティ検証の前提条件**）

#### S5-VERIF-020: 経路依存の状態は replay の入力として明示的に受け取る
**挙動**: 前ティックに依存する状態（TL ヒステリシス、前回 PER_DOMAIN 状態、シーケンス連鎖、CB 状態、dedup 窓）は**パリティ実行の開始時点の値を入力として受け取る MUST**、暗黙に本番の現在値を読んではならない **MUST NOT**。
**根拠**: ヒステリシスは `db.scenario_tl_last()` を読む（radar/scoring.py:1410、radar/routes/core.py:2193-2213）。`derive_trend` は TL 台帳を、`derive_per_domain` は前回 PER_DOMAIN 行を読み戻す（radar/conclusions/per_domain.py:65）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-021: パリティ実行は本番状態を一切書き換えない
**挙動**: パリティハーネスは**本番台帳への書き込みを行ってはならない MUST NOT**、出力は隔離された比較台帳のみ **MUST**。副次的な書き込み（統計更新・continuity 記録・固定パスへの一時ファイル）も禁止 **MUST NOT**。
**根拠**: 現行 scripts/backfill_v2_ledger.py は `conclusions` と `inconclusive_continuity_log` へ INSERT する。そのため scripts/check_mode_c_readiness.py は「live（非 replay）台帳」を選別する必要がある
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-022: LLM 依存部は記録済み応答の再生で決定論化する
**挙動**: LLM を経由する導出は、パリティ実行時に**記録済み応答を `prompt_sha256` で引き当てて再生 MUST**（実 LLM を呼んではならない **MUST NOT**）。再生に必要な記録（プロンプト・応答本文・モデル ID・温度）が欠ける結論型は**パリティ対象外として明示 MUST**（一致率の分母から除外し、除外の事実を出力に記載 **MUST**）。
**根拠**: NP6。現行は `prompt_sha256` は永続化されるが LLM 注釈経路は `prompt_version` しか記録しない（D2 E-08）
**検証**: tests/test_llm_prompt_persistence.py（12 件。sha256 安定性）
**分類**: **NEW**

#### S5-VERIF-023: パリティ比較の粒度と片側欠落の扱い
**挙動**: 比較は `(scenario_id, conclusion_type, tick_ts)` を主キーとする **MUST**。両系のいずれかに行が無い tick は**「片側欠落」として独立に計上 MUST**（一致にも不一致にも算入しない）。片側欠落率が **5% を超えたらパリティ実行そのものを無効とする MUST**（比較の前提が崩れている）。
**閾値**: 片側欠落率上限 5%
**根拠**: v1/v2 の `conclusion_diff_log` は migration v54 で削除済（radar/database.py:2273-2290, 2873-2877）。両系比較の粒度定義は現行に存在しない
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-024: 比較は必ず severity 空間で行う
**挙動**: TL の一致判定・大小比較・方向分類は**すべて `severity = 6 − TL` に変換してから行う MUST**、生の TL 数値を大小比較してはならない **MUST NOT**。パリティ出力にも severity を併記 **MUST**。
**根拠**: 較正インシデント #2（2026-07-03、TL スケール反転）。TL1=CRITICAL の DEFCON 方向
**検証**: tests/test_severity.py（8 件。反転哨戒の番兵）
**分類**: CORE

#### S5-VERIF-025: TL 系列一致率の定義
**挙動**: `tl_agreement = （severity が完全一致した tick 数）/（両系に行が存在する tick 数）` **MUST**。`INSUFFICIENT_DATA`（tl=None）同士は**一致として数える MUST**。片方のみが None の場合は不一致とし、
**None を出した側を insensitive として分類 MUST**。
**根拠**: NEW（現行に両系一致率の定義は無い）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-026: 遷移タイミング差の定義
**挙動**: 両系の TL 遷移列を突合し、同方向・同遷移先の最近傍遷移をペアリングして `|t_v3 − t_legacy|` を求める **MUST**。ペアが作れない遷移は**片側のみの遷移として独立計上 MUST**。報告値は中央値・p95・片側遷移件数の 3 つ **MUST**。
**根拠**: NEW
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-027: conclusion type 別の一致基準
**挙動**: 型ごとに一致の定義を分ける **MUST**。`conclusion_unavailable_reason` は
**一致判定に含める MUST**（reason が違えば不一致）:

| conclusion_type | 一致の定義 |
|---|---|
| threat_level | severity 完全一致（`INSUFFICIENT_DATA` 同士も一致） |
| per_domain | 3 ドメインすべての state 文字列が一致 |
| attack_mode | state 文字列が一致（`INSUFFICIENT_DATA` 同士も一致） |
| trend | state 文字列が一致。方向のみの一致は**部分一致として別集計** |
| anomaly | 集合比較。`{state, reason, signal_source, contributing_country, domain}` のキー集合が一致（多重度は無視） |

**根拠**: radar/conclusions/persistence.py（gated 保存の同一性判定と同じ軸を使う）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-028: 寄与センサー集合の一致基準
**挙動**: 各 tick の寄与集合を `{(sensor, signal_source, country)}` として取り、`jaccard = |A ∩ B| / |A ∪ B|` を算出 **MUST**。報告は中央値と p05 **MUST**。両系とも空集合の tick は **jaccard = 1.0 とする MUST**。
**根拠**: 寄与集合が一致しないまま TL だけ一致する状態は**偶然の一致**であり NP6 上パリティとして無効
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-029: 不一致は方向で分類し、非対称に扱う
**挙動**: すべての不一致を **insensitive**（v3 が severity を低く出した）と **sensitive**（高く出した）に分類 **MUST**。NP1 により **insensitive は blocking、sensitive は非 blocking として扱う MUST** （sensitive は件数と代表例の報告にとどめる）。方向を持たない型（anomaly の集合差）は、
**v3 側にのみ欠けている要素を insensitive として数える MUST**。
**根拠**: NP1（見逃しは誤検知より悪い）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-030: パリティ結果は追記専用台帳に記録し、導出開示を伴う
**挙動**: 1 行は `{sampled_at, parity_run_id, scenario_id, conclusion_type, tick_ts, legacy_state, v3_state, is_match, mismatch_direction, evidence_json}` **MUST**。`parity_run_id` から入力窓・入力台帳のスナップショット ID・両系のコードバージョンを解決できる **MUST**。不一致 1 件ごとに両系の `{寄与内訳, 適用閾値と config キー, 式のバージョンタグ, 一次ソース URL}` を解決できる情報を出力 **MUST**。一致率だけを報告して原因に到達できない出力を可としてはならない **MUST NOT**。
**根拠**: NP6。v1→v2 では `conclusion_diff_log` が同役を担ったが migration v54 で削除済（radar/database.py:2273-2290, 2873-2877）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-031: 両系は同一の入力アダプタから読み、式を複製しない
**挙動**: 旧系と v3 は**同一の入力アダプタ経由でのみ**パリティ入力を受け取る **MUST**。比較対象の式（`derive_tl` 等）をハーネス側に複製してはならない **MUST NOT**（本番実装を import する **MUST**）。
**根拠**: scripts/phase9_backtest_simulation.py:43-53 は `derive_tl` を「radar/scoring.py を写す」コメント付きで手写ししており、本体が変わっても追従しない
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

### 2.3 Recall 連続性

#### S5-VERIF-032: ラベルエポックを一級市民として持つ
**挙動**: ラベル 1 行は `{generator_id, generator_version, rule_id, epoch_id}` を
**構造化列として持つ MUST**、自由文フィールドに埋め込んではならない **MUST NOT**。
ラベル生成器の意味論を変える改修は `epoch_id` を進める **MUST**。
**根拠**: 現行 `analyst_feedback` は `{id, conclusion_id, label, observed_outcome_url, analyst_id, observed_at, notes}` のみで、provenance は `analyst_id` の接頭辞規約と自由文 `notes` に依存する（radar/database.py:1215-1229）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（S1-CALIB §5-DP19 と同一要求）

#### S5-VERIF-033: baseline はエポックを持ち、跨いだ比較を機械的に拒否する
**挙動**: recall baseline スナップショットは `epoch_id` を持つ **MUST**、現行スナップショットと不一致ならゲートは **FAIL MUST**（再 baseline を促す）。`since` を `null`（全履歴）にしてはならない **MUST NOT**。
**根拠**: 現行 docs/baselines/recall_metrics.json は `{schema_version:1, generated_at, exclude_auto:false, since:**null**, opt_in:false, cells[]}` で、**`since: null` のまま 2026-07-04 と 2026-08-02 の 2 つの断絶を跨いで比較している**。`schema_version` はファイル形式の版であって生成器の版ではない
**検証**: tests/test_check_recall_baseline.py（16 件。エポック検査は不在）
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-034: 移行前後で同一ラベル集合に対する recall は厳密に一致する
**挙動**: 同一のラベル集合・窓・`exclude_auto` に対し、v3 の recall / precision は旧系と
**cell 単位で厳密一致 MUST**（許容差 **0**、丸め前の有理数で比較）。混同行列 4 値と
`distinct_analysts` も一致 **MUST**。不一致は cutover の blocking 条件 **MUST**。
**根拠**: scripts/report_recall_metrics.py:62-164（`recall = tp/(tp+fn)`、`precision = tp/(tp+fp)`、分母 0 は `None`、`(conclusion_id, analyst_id)` の最新行勝ち dedup）
**検証**: tests/test_report_recall_metrics.py（8 件）
**分類**: CORE（S1-CALIB-026 の検証側要件）

#### S5-VERIF-035: recall の実装は 1 つでなければならない
**挙動**: recall / precision / miss_rate の算出実装は**単一 MUST**。窓・dedup 規則・ conclusion_type フィルタが異なる複数実装を持ってはならない **MUST NOT**。利用側（CI ゲート / AP3 自己評価 / per-scenario 較正状態）は**同一関数にパラメータを与える形 MUST**。
**根拠**: 現行は 3 実装が併存 — scripts/report_recall_metrics.py:62-164（全型・dedup 有）、radar/conclusions/calibration.py:135-191（`threat_level` のみ・30 日窓）、scripts/check_recall_post_autotune.py:65-115（**dedup 無し・JOIN 無し**）
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-036: 2026-07-04 より前の recall 数値と比較してはならない
**挙動**: recall / precision の時系列は **2026-07-04 の再スタート以降のみ連続 MUST**、それ以前と同一系列として比較・トレンド化してはならない **MUST NOT**。
**2026-08-02 の帰属修復も同様に系列を断つ MUST**。v3 では S5-VERIF-032/033 の `epoch_id` により
**コードで強制 MUST**、手続きに委ねてはならない **MUST NOT**。
**根拠**: docs/design/v2-migration.md:31,38,41-44；S1-CALIB-030
**検証**: tests/test_remediate_cross_scenario_labels.py（6 件）
**分類**: CORE（S1-CALIB-030 の強制化）

#### S5-VERIF-037: 退化した cell を検知能力の証拠にしてはならない
**挙動**: `fn == 0` かつ `tn == 0` の cell は recall が構成上 1.0 に固定されるため **`DEGENERATE` として表示 MUST**、ゲートの合否根拠にしてはならない **MUST NOT**。`tp + fn < 5` の cell も `INSUFFICIENT_DATA` として扱う **MUST**。cutover 判定では**非退化 cell のみを数える MUST**。
**根拠**: 較正インシデント #1（2026-05-29、blanket-TP により recall が 1.0 に固定され、ゲートは動かない数値を守っていた）。**実測: 現行 baseline の 8 cell 中 4 件（attack_mode 全 4 シナリオ）が `fn=0 ∧ tn=0` で recall=1.0**、precision は 0.235〜0.50
**検証**: tests/test_check_recall_baseline.py（16 件。退化検出は不在）
**分類**: **NEW**

#### S5-VERIF-038: Design W ゲートの 6 分岐を保存し、warn-only を strict 化する
**挙動**: cell 単位比較の 6 分岐（①baseline のみ→warn ②baseline recall None→skip ③現行 None→FAIL ④`drop > max_drop`→FAIL ⑤`0 < drop <= max_drop`→info（**境界の等号は PASS 側**）⑥現行のみ→info）と、baseline 不在時の**警告付き成功終了**を保存 **MUST**。窓と `exclude_auto` は **baseline 側から継承 MUST**。検知能力に関わるゲートは cutover 時点で**すべて strict MUST**、warn-only のまま cutover してはならない
**MUST NOT**。CI からの呼び出しは**閾値を明示引数で渡す MUST**。
**閾値**: `max_drop` 既定 **0.05**
**根拠**: scripts/check_recall_baseline.py:133-191,247-278（S1-CALIB-029）。現行 scripts/check_recall_post_autotune.py は既定 warn-only で check_ci.sh は `--strict` を付けないため
**構造上 CI を落とせない**。check_recall_baseline.py も無引数呼び出しで `max_drop` は既定値依存
**検証**: tests/test_check_recall_baseline.py（16 件）、tests/test_check_recall_post_autotune.py（12 件）
**分類**: CORE ＋ **DEFECT-PRESERVE**（strict 化の部分）

#### S5-VERIF-039: ゲート自身が実際に評価されたことを検証する
**挙動**: 各 CI ゲート・各 recall ゲートについて**「呼ばれ、判定を返した」ことを検証するテストを持つ MUST**。例外を握り潰して「red でない」を返す経路を持ってはならない **MUST NOT**。実行結果は台帳に記録し、**期待実行間隔を超えて記録が無ければ ANOMALY MUST**。
**根拠**: D2 D-01 族の実例。radar/calibration/auto_tune_governor.py:131-151 は存在しない関数 `evaluate_against_baseline` を呼び、`scripts/__init__.py` も無いため import 自体が失敗する。裸の `except` が False（= red でない）を返すため **NP1 の最終防衛線が恒久的に開いている**（S1-CALIB-031）
**検証**: 未検証（このゲートを実行するテストが存在しない）
**分類**: **DEFECT-PRESERVE**

### 2.4 Shadow 並走と cutover

#### S5-VERIF-040: 移行は 4 段階で進め、default-on まで旧系が正で v3 は副作用を持たない
**挙動**: **並走 → shadow → opt-in → default-on** の 4 段階 **MUST**（ADR-V2-003 プレイブックの v3 適用）。default-on までは**旧系の出力が正 MUST**（R4）、段階の後戻りは常に可能 **MUST**。default-on より前の段階で v3 は**通知の送出・提案の自動適用・本番台帳への書込を行ってはならない MUST NOT**、出力は隔離台帳のみ **MUST**。
**根拠**: docs/design/v2-migration.md:311-322（ADR-V2-003）。移行足場 teardown インシデント（2026-05-30。休眠足場が prod を黙って劣化させた）
**検証**: tests/test_shadow_metrics.py / test_v1_sunset_audit.py（SCAFFOLD。先例としてのみ参照）
**分類**: CORE

#### S5-VERIF-041: 各段階の最小期間と比較頻度
**挙動**: 各段階は**最小期間を満たす MUST**（上限は設けない）: 並走 **14 日** / shadow **30 日** / opt-in **14 日**。shadow 期間中は **1 日 1 回の 30 日 replay パリティ実行 MUST**、かつ**毎ティックの live diff 記録 MUST**（S5-VERIF-030 の台帳へ）。
**閾値**: 並走 14d / shadow 30d / opt-in 14d / パリティ実行 1 回/日
**根拠**: NEW（ADR-V2-003 は段階を定めるが期間を数値化していない）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-042: cutover 条件は 14 の数値条件をすべて満たすことである
**挙動**: default-on への切替は以下を**すべて満たすこと MUST**。形容詞による条件を用いてはならない
**MUST NOT**。すべて自動計測可能でなければならない **MUST**。

| # | 条件 | 数値 |
|---|---|---|
| CUT-01 | 30 日パリティ窓の TL 系列一致率（severity 空間、S5-VERIF-025） | **≥ 0.98** |
| CUT-02 | 不一致のうち **insensitive 方向**（S5-VERIF-029） | **= 0 件** |
| CUT-03 | TL 遷移タイミング差の p95（S5-VERIF-026） | **≤ 300 秒** |
| CUT-04 | 型別 state 一致率（threat_level / per_domain / attack_mode / trend） | **≥ 0.98 / 0.95 / 0.95 / 0.90** |
| CUT-05 | 寄与センサー集合 jaccard（中央値 / p05） | **≥ 0.95 / ≥ 0.80** |
| CUT-06 | 非退化 cell すべてで `recall_v3 − recall_legacy` | **≥ 0**（丸め前） |
| CUT-07 | 非退化 cell 数（`fn+tn > 0` かつ `tp+fn >= 5`） | **≥ 4** |
| CUT-08 | 沈黙検知失敗検査（S5-VERIF-016）の未解消 ANOMALY | **= 0 件** |
| CUT-09 | 単位整合・到達可能性検査（S5-VERIF-008/009）の FAIL | **= 0 件** |
| CUT-10 | 設定到達性: 未登録キー読取 + registry 外の環境変数直読み | **= 0 件** |
| CUT-11 | null-zone: 全 (scenario × conclusion_type) の最長 UNAVAILABLE 継続 | **≤ 7 日** かつ chronic **= 0 件** |
| CUT-12 | v3 CI 全ゲート（すべて strict）の連続 PASS 日数 | **≥ 14 日** |
| CUT-13 | S1-S4 の CORE 条項に対応するテストの割合 / 未対応の CRITICAL・HIGH 条項 | **≥ 0.95 / = 0 件** |
| CUT-14 | shadow 期間の v3 側 unhandled exception 率 | **≤ 0.001 /tick** |

**根拠**: CUT-11 の 7 日は `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS` 既定（radar/config.py:1545-1551）。CUT-06 は Design W と同じ「低下を許さない」方向。CUT-03 の 300 秒は採点ティック 1 周期相当
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-043: 未達が 1 つでもあれば cutover 不可、override は監査行を残す
**挙動**: 14 条件のうち 1 つでも未達なら **cutover してはならない MUST NOT**。オーナーが例外的に override する場合、`{override した条件 ID, 実測値, 理由, 承認者, 時刻}` を**追記専用台帳に記録 MUST**。override は **CUT-02 / CUT-08 / CUT-11 に対しては認めない MUST NOT**（いずれも NP1 の見逃しに直結する）。
**根拠**: NP1
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-044: 判定はオーナーが下し、スクリプトは ready / not ready のみを返す
**挙動**: 14 条件の充足は**必要条件であって十分条件ではない MUST**。cutover の可否判断はオーナーが行う **MUST**（NP7）。判定は**単一スクリプトで一括実行 MUST**、出力は条件ごとに `{条件 ID, PASS|FAIL, 実測値, 閾値}` を 1 行ずつ **MUST**。全条件 PASS かつ `--ack` 指定で exit 0、それ以外は exit 1 **MUST**。閾値と窓は**引数として明示 MUST**（暗黙の既定値に依存してはならない **MUST NOT**）。
**根拠**: 先例 scripts/check_mode_c_readiness.py:6-19,106-135（5 条件 + `--ack`、条件ごとの理由出力）
**検証**: 未検証
**分類**: CORE（先例の一般化）

#### S5-VERIF-045: rollback は 5 つの数値条件で発火する
**挙動**: default-on 後、以下のいずれかが成立したら**旧系へ戻す MUST**。実行事実の通知は必須 **MUST**:

| # | 条件 | 数値 |
|---|---|---|
| RB-01 | 直近 24 時間の TL 系列一致率 | **< 0.95** |
| RB-02 | 直近 24 時間の insensitive 方向の不一致 | **≥ 1 件** |
| RB-03 | 任意 cell の recall 低下（baseline 比） | **> 0.05** |
| RB-04 | 沈黙検知失敗検査の新規 ANOMALY | **≥ 1 件** |
| RB-05 | chronic null-zone の新規発生 | **≥ 1 件** |

**根拠**: RB-03 は Design W の `max_drop` と同値、RB-05 は `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS`
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-046: 旧系は default-on から 90 日で撤去する
**挙動**: 旧系は default-on 後 **90 日**保持 **MUST**、うち**最初の 30 日は hot standby （即時切替可能な稼働状態）MUST**。90 日経過かつ §2.7 の卒業判定が成立した時点で撤去可 **MUST**。
**閾値**: sunset 90 日 / hot standby 30 日
**根拠**: ADR-V2-003（docs/design/v2-migration.md:311-322）。ただし v3 では境界を 1 本化するため、旧系 API の外部利用者保護は対象外（D3 §3-4）
**検証**: 未検証
**分類**: CORE

### 2.5 ラベル系譜監査（D-01 対策）

#### S5-VERIF-047: ラベルの系譜を構造化して記録する
**挙動**: 1 ラベル行から**「どの一次ソース → どの規則 → どの判定」を構造化列で辿れる MUST**: `{source_kind, source_id, source_url, source_published_at, rule_id, rule_inputs_json, attribution_role, episode_key, generator_version, epoch_id}`。自由文 `notes` を系譜の唯一の担い手にしてはならない **MUST NOT**。
**根拠**: 現行の provenance は `analyst_id`（`auto:acled` / `auto:gdelt` / `auto:both` / `auto:mixed` / `auto:llm_intel` / `auto:sequence` / `auto:horizon` / `auto:rss`）と 240 文字に切り詰めた `notes` のみ（radar/conclusions/ground_truth_etl.py:146-199、radar/database.py:1215-1229）
**検証**: tests/test_ground_truth_etl.py（39 件。ラベル優先順位と provenance タグ）
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-048: ラベルは再生成可能でなければならない
**挙動**: 同一の一次ソース集合と同一 `generator_version` から**同一ラベルが再生される MUST**。再生結果と台帳の差分を**週次で検査 MUST**、差分が 1 件でもあれば ANOMALY **MUST** （生成器が非決定論であるか、台帳が改変されている）。
**根拠**: D2 D-01（生成器のロジックバグが全テスト通過のまま数週間 prod を劣化させた）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-049: 反事実チェック A — 平穏期の FN 増加は生成器を疑う
**挙動**: あるシナリオについて、**そのシナリオ自身のセンサー信号が平穏**（30 日の domain score 合計の p95 が前 30 日比 **+10% 未満**）であるにもかかわらず **FN 件数が前 30 日比 2 倍以上かつ絶対 3 件以上** 増えた場合、**ツールの検知劣化ではなくラベル生成器の欠陥を第一容疑として ANOMALY を上げる MUST**。アラート文面は「生成器を先に疑え」を明示 **MUST**。
**閾値**: 信号平穏 +10% 未満 / FN 増加 2 倍かつ +3 件
**根拠**: インシデント #3（korean_peninsula の miss rate 0.44 は測定アーティファクトで、シナリオ自体は正しく平穏だった。ground truth の方が間違っていた）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-050: 反事実チェック B — 閾値緩和の偏りを検知する
**挙動**: 自動閾値調整の適用履歴について、**直近 30 日の緩和方向の適用が単一シナリオに 60% 以上集中**し、かつ根拠となった FN 群の**過半が同一 `epoch_id` の同一 `rule_id` 由来**である場合、**ANOMALY を上げ、以降の同方向の自動適用を停止 MUST**。
**閾値**: 集中率 60% / 同一規則由来 50%
**根拠**: インシデント #3（凍結した FN 集合が korean_peninsula に −5% 緩和を 4 回連続で適用させた。鮮度ゲートが「任意の新ラベル」で通過していたため止まらなかった）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-051: インシデント #1（退化ラベル）の再発検知条件
**挙動**: 以下のいずれかで ANOMALY **MUST**: (a) 任意の `generator_id` について直近 30 日の出力ラベルが
**単一種別 95% 以上**、(b) 全 cell 横断の `fn + tn` が **0**、(c) 非退化 cell が **4 件未満**。
**閾値**: 単一種別率 95% / 非退化 cell 下限 4
**根拠**: インシデント #1（`auto:rss` が TRUE_POSITIVE のみを出力し FN が系全体で 0 → recall が
1.0 に固定。ゲートは動かない数値を守っていた）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-052: インシデント #2（方向反転）の再発検知条件
**挙動**: **ツール severity とラベル極性の相関を毎日検査 MUST**。severity が高い結論ほど FN 比率が高い（Spearman 相関係数が **−0.3 以下**）状態は**方向反転の疑いとして ANOMALY MUST**。併せて TL を扱うすべての比較経路に `severity = 6 − TL` 変換が存在することを CI で検証 **MUST**。
**閾値**: 相関係数 −0.3
**根拠**: インシデント #2（より警戒している TL1-3 に FALSE_NEGATIVE、より平穏な TL4-5 に TRUE_POSITIVE が付いた。約 30,000 ラベルが汚染）
**検証**: tests/test_severity.py（8 件）
**分類**: **NEW**

#### S5-VERIF-053: インシデント #3（帰属汚染）の再発検知条件
**挙動**: ラベルの帰属は**紛争当事者ロールに限定 MUST**（`adversary` / `primary_target` / `principal_belligerent` / `proxy_front`）。支援ロール（`primary_ally` / `forward_base` / `strategic_observer`）経由の帰属を**禁止 MUST NOT**。各ラベルの `attribution_role` が当事者集合に含まれることを毎日検証 **MUST**、1 件でも違反があれば ANOMALY **MUST**。
**1 記事 = 1 シナリオ 1 エピソード MUST**。
**根拠**: インシデント #3（`Scenario.ground_truth_countries` 導入以前は全 participant へファンアウトし、`auto:rss` 222 行中 83 行が汚染、korean_peninsula の FN 15 件中 12 件が偽）
**検証**: tests/test_remediate_cross_scenario_labels.py（6 件）、tests/test_run_ground_truth_etl.py（15 件）
**分類**: CORE

#### S5-VERIF-054: 人間アンカーの独立レグを構造的に維持する
**挙動**: 人手ラベルと自動ラベルの区別は**型または専用列で表現 MUST**、識別子の文字列接頭辞規約に依存してはならない **MUST NOT**。人間アンカーの調査支援は**リンクの提示にとどめ、外部取得結果をツールへ取り込んではならない MUST NOT**（自動ラベルと同じ一次ソースを読むと相関した盲点を再生産する）。人間への提示は**自然言語の 1 問 MUST**、混同行列の語彙はツール側で導出 **MUST**。
**根拠**: radar/conclusions/human_anchor.py:106-130,167-205,200-205（独立性の唯一の境界が `analyst_id NOT LIKE 'auto:%'` という文字列述語である）
**検証**: tests/test_human_anchor.py（17 件）
**分類**: **DEFECT-PRESERVE**（意味論は CORE、実現手段が文字列規約なのが欠陥）

#### S5-VERIF-055: 人手ラベルの最低流量を数値で維持し、系譜監査を毎日回す
**挙動**: 人手ラベルは**週 4 件以上 MUST**、うち**FN 候補（自動 FN の人手確認）を週 1 件以上含む MUST**。4 週連続で下回ったら **AP3 に「較正の独立レグが痩せている」を表明 MUST**、その状態では自動閾値調整の緩和方向を停止 **MUST**。S5-VERIF-049〜053 は**毎日**、S5-VERIF-048 は**週次**で実行 **MUST**。結果は S5-VERIF-016 と同一の追記専用台帳へ **MUST**、ANOMALY は該当エポックの recall 数値に
**「生成器疑義あり」の注記を付す MUST**。
**閾値**: 週 4 件 / うち FN 候補 1 件 / 猶予 4 週
**根拠**: radar/conclusions/human_anchor.py:325-362（既定キュー 5 件 / 窓 7 日、3 プールの優先順は auto_fn_review → peak_severity → calm_anchor）
**検証**: tests/test_human_anchor.py（17 件）
**分類**: **NEW**

### 2.6 テスト移植計画と v3 CI

#### S5-VERIF-056: 条項 ID とテストは双方向に対応づける
**挙動**: v3 の各テストは**対応する仕様条項 ID を宣言 MUST**、各 CORE 条項は**最低 1 件のテストを持つ MUST**。対応の無いテスト（= 仕様の穴）とテストの無い CORE 条項（= 検証の穴）を **CI で列挙 MUST**。
**根拠**: S0 §5（S 出口ゲート）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-057: テスト資産は分類別の移植方針に従う
**挙動**: D5 台帳の分類ごとに以下 **MUST**:

| 分類 | 規模 | 移植方針 |
|---|---|---|
| BEHAVIOR (py) | 60 file / 1,241 test | **まず S1-S4 の条項に写像し、条項からテストを再生成 MUST**。現行テストのコードを直接移植してはならない **MUST NOT**（構造依存を持ち込む）。写像先の条項が無いテストは **GAP としてオーナー裁定へ MUST** |
| BEHAVIOR (js) | 6 file / 160 test | pure module ごと **keep 可**（依存ゼロ。D3 §2） |
| CONTRACT | 17 file / 271 test | **S2 の API 契約条項へ写像 MUST**。パス形状は変わってよいが、ゲートラダー（503/401/403 の順序）とレスポンス構造は保存 **MUST**。NP7 免責文言の全 payload 検証は必ず引き継ぐ **MUST** |
| STRUCTURAL | 19 file / 223 test | **書き直し MUST**。中に埋まる閾値・ルールは仕様へ救出 **MUST**（救出リストを移植計画に明記 **MUST**） |
| SCAFFOLD | 5 file / 44 test | **持ち込まない MUST NOT**。ただし tests/test_remediate_cross_scenario_labels.py は **S5-VERIF-053 の再発検知条件の根拠として保存 MUST** |

**根拠**: D5 §2.1-2.4、D3 §2
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-058: 閾値を pin するテストを明示的に用意する
**挙動**: 結論に影響する**すべての閾値について、値をテスト側にリテラルで書いて突合するテストを持つ MUST**。定数を import して相対比較するテストのみで閾値を守ってはならない **MUST NOT**。pin テストと相対テストは**別ファイルまたは別クラスに分離 MUST**。閾値変更時は pin テストの更新が**必ず差分に現れる MUST**。
**根拠**: D5 訂正節（2026-08-04）。ATTACK_MODE の実装値は 1.2/0.8/1.0/0.8 （radar/conclusions/attack_mode.py:50-53）だが設計文書は 5.0/1.5/3.0/1.5 のまま。PER_DOMAIN は実値 2.5/1.5（per_domain.py:51-52）。**当該テスト群は定数を import して相対検証するため、値を変えても全通過する**
**検証**: tests/test_attack_mode_derive.py（26 件）、tests/test_per_domain_derive.py（27 件） — いずれも現状は相対検証で pin していない
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-059: テストは本番ロジックを呼ばなければならない
**挙動**: 値を pin するテストが**本番関数を呼ばずにロジックをインライン再実装してはならない MUST NOT**。再実装テストは CI で検出 **MUST**（呼び出しグラフに本番シンボルが現れないテストを列挙）。
**根拠**: S1-scoring-core §6 が 6 箇所を実測（TestGraduatedVectorShift / TestAdversaryCountScoring / TestDdosBgpCausality / TestCfBgpHijackScoring / TestTorMetricsSensor::test_censorship_indicator / TestRipeAtlasSensor の drop_pct 算術）。scripts/phase9_backtest_simulation.py:43-53 も同族
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-060: テストは構造的に隔離 DB のみへ接続する
**挙動**: テストは**隔離 DB 以外へ接続できてはならない MUST NOT**。接続の注入を必須とし、既定接続へのフォールバックを持たない **MUST**。本番 DB への接続試行はテスト実行時に**例外 MUST**。
**根拠**: D2 B-08。現行は 101 テストファイル中 **33 が singleton `db` を import** し稼働 DB へ書き込みうる。tradecraft 全表の行数が「82 回のテスト実行 × 固定件数」と一致（164=82×2、246=82×3、984=82×12）。良い先例は tests/test_auto_apply_tier_governor.py:37 の `_block_live_db_access` autouse fixture
**検証**: tests/conftest.py（tier governor のみ隔離）
**分類**: **DEFECT-PRESERVE**

#### S5-VERIF-061: v3 CI ゲート構成
**挙動**: CI は以下をこの順で実行 **MUST**。すべて strict（失敗で非ゼロ終了）**MUST**:

| # | ゲート | 判定内容 |
|---|---|---|
| G01 | codemap 鮮度 | 構造変更に対する目次の追従 |
| G02 | 依存方向 | レイヤー境界違反の検出 |
| G03 | 語彙 | 廃止用語（theater 等）の非出現 |
| G04 | i18n | 日本語専用シェル・未訳・未定義参照・未使用キー |
| G05 | シークレット | 平文シークレットの非出現 |
| G06 | **設定到達性** | S5-VERIF-013/014（未登録読取 = 0、直読み = 0） |
| G07 | **単位・到達可能性** | S5-VERIF-007/008/009（unit 必須、異単位比較 0、定義域外閾値 0） |
| G08 | **テスト隔離** | S5-VERIF-060（本番 DB 接続経路 0） |
| G09 | **閾値 pin** | S5-VERIF-058（pin テストの存在と網羅） |
| G10 | **再実装検出** | S5-VERIF-059（本番シンボルを呼ばない pin テスト 0） |
| G11 | **条項カバレッジ** | S5-VERIF-056（CORE 条項の未検証 0） |
| G12 | **recall baseline** | S5-VERIF-033/038（エポック一致 + 6 分岐、閾値は明示引数） |
| G13 | **沈黙検知失敗** | S5-VERIF-016 の最新実行結果に未解消 ANOMALY が無いこと |
| G14 | **系譜監査** | S5-VERIF-055 の最新実行結果に ANOMALY が無いこと |

**根拠**: 現行 scripts/check_ci.sh は 9 ゲート（うち 1 は `|| true` で非致命、1 は warn-only スクリプトのため構造上落ちない）。G06-G14 は新設
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-062: ゲート自身の生存をメタゲートで検証する
**挙動**: CI は**各ゲートが実際に評価を実行し判定を返したことを検証 MUST**。「実行されたが 0 件を検査して PASS した」ゲートは **FAIL 扱い MUST** （各ゲートは検査対象件数を出力し、**0 件なら FAIL MUST**）。
**根拠**: S5-VERIF-039 と同根。D2 D-01 族への最も安価な防御
**検証**: 未検証
**分類**: **NEW**

### 2.7 カットオーバー後 30 日の強化監視

#### S5-VERIF-063: 強化監視の対象と頻度
**挙動**: default-on 後 30 日間、以下を**規定頻度で実行し結果を台帳へ MUST**:

| 項目 | 頻度 | 異常条件 |
|---|---|---|
| 24h replay パリティ（旧系 hot standby と） | 1 日 1 回 | RB-01 / RB-02 |
| 沈黙検知失敗検査（S5-VERIF-016） | 1 日 1 回 | ANOMALY ≥ 1 |
| 系譜監査（S5-VERIF-055） | 1 日 1 回（再生成一致は週次） | ANOMALY ≥ 1 |
| recall cell 比較（S5-VERIF-038） | 1 日 1 回 | drop > 0.05 |
| null-zone 継続日数 | 1 日 1 回 | 最長 > 7 日 |
| 全センサーの発火実績（S5-VERIF-003） | 1 日 1 回 | ANOMALY ≥ 1 |
| 人手ラベル流量（S5-VERIF-055） | 週次 | 週 4 件未満 |
| unhandled exception 率 | 1 日 1 回 | > 0.001 /tick |

**根拠**: CUT / RB 条件の継続監視
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-064: 旧系は 30 日間 hot standby として保持し、rollback を実演する
**挙動**: default-on 後 30 日間、旧系を**同一入力で稼働させ続ける MUST**（出力は隔離台帳のみ）。30 日間で**最低 1 回 rollback リハーサルを実施 MUST**（実切替を伴い、切替所要時間を計測して台帳へ **MUST**）。
**根拠**: R4。移行足場 teardown インシデントの教訓（休眠状態の足場は劣化を検出できない）
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-065: 30 日後の卒業判定
**挙動**: 強化監視の解除は以下を**すべて満たすこと MUST**: (a) 30 日連続で CUT-01 / CUT-02 / CUT-08 / CUT-11 を充足、(b) 人手ラベルが 4 週連続で週 4 件以上、(c) rollback リハーサル 1 回以上の完了、(d) 期間中に新規検出された沈黙検知失敗が**すべて解消済**。未達なら**強化監視を 30 日延長 MUST**（旧系の撤去も同期間延期 **MUST**）。
**根拠**: S5-VERIF-042 / 046 / 055
**検証**: 未検証
**分類**: **NEW**

#### S5-VERIF-066: 強化監視の状態を AP3 面に常時可視化する
**挙動**: 強化監視期間中は AP3 自己評価面に**「移行監視中（残 N 日）」と直近のパリティ一致率・未解消 ANOMALY 件数を常時表示 MUST**。「今このツールの結論をどこまで信じるか」を秒で判断できる形 **MUST**。
**根拠**: AP3（自己評価）
**検証**: tests/test_self_eval.py（9 件。既存 3 メトリクスのみ）
**分類**: **NEW**

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー（v3 で新設） | DB override | 出典 |
|---|---|---|---|---|
| 無発火 WARN / ANOMALY 倍率 | 1.0 / 3.0 | `SILENCE_WARN_RATIO` / `SILENCE_ANOMALY_RATIO` | 可 | S5-VERIF-003 |
| 未発火猶予 | 30 d | `NEVER_FIRED_GRACE_DAYS` | 可 | S5-VERIF-003 |
| 到達不能疑い倍率 / 最小サンプル | 0.5 / 100 | `REACHABILITY_P99_RATIO` / `REACHABILITY_MIN_SAMPLES` | 可 | S5-VERIF-009 |
| 実効ベースライン窓の許容乖離 | 20% | `BASELINE_WINDOW_TOLERANCE` | 可 | S5-VERIF-011 |
| パリティ窓 | 30 d | `PARITY_WINDOW_DAYS` | 可 | S5-VERIF-018 |
| 信号台帳 retention | 60 d | `SIGNAL_LEDGER_RETENTION_DAYS` | 可 | S5-VERIF-018 |
| 片側欠落率上限 | 5% | `PARITY_MISSING_CEILING` | 可 | S5-VERIF-023 |
| recall baseline 許容低下 | 0.05 | `RECALL_MAX_DROP` | 可 | S5-VERIF-038 |
| 非退化 cell 下限 / recall 分母下限 | 4 / 5 | `MIN_NONDEGENERATE_CELLS` / `MIN_RECALL_DENOM` | 可 | S5-VERIF-037 / 051 |
| 並走 / shadow / opt-in 最小期間 | 14 / 30 / 14 d | `STAGE_MIN_DAYS_*` | 不可 | S5-VERIF-041 |
| TL 一致率下限（cutover / rollback） | 0.98 / 0.95 | `PARITY_TL_FLOOR` / `ROLLBACK_TL_FLOOR` | 不可 | S5-VERIF-042 / 045 |
| 遷移タイミング差 p95 上限 | 300 s | `PARITY_TRANSITION_P95_SEC` | 不可 | S5-VERIF-042 |
| 型別 state 一致率下限 | 0.98 / 0.95 / 0.95 / 0.90 | `PARITY_STATE_FLOOR_<TYPE>` | 不可 | S5-VERIF-042 |
| jaccard 中央値 / p05 下限 | 0.95 / 0.80 | `PARITY_JACCARD_MEDIAN` / `_P05` | 不可 | S5-VERIF-042 |
| chronic null-zone 閾値 | 7 d | `CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS`（既存） | 可 | radar/config.py:1545-1551 |
| CI 連続 PASS 日数 | 14 d | `CUTOVER_CI_GREEN_DAYS` | 不可 | S5-VERIF-042 |
| CORE 条項カバレッジ下限 | 0.95 | `CLAUSE_COVERAGE_FLOOR` | 不可 | S5-VERIF-042 |
| unhandled exception 率上限 | 0.001 /tick | `EXCEPTION_RATE_CEILING` | 不可 | S5-VERIF-042 |
| 平穏判定 / FN 増加（反事実 A） | +10% 未満 / 2 倍かつ +3 件 | `CF_CALM_DELTA` / `CF_FN_SURGE_*` | 可 | S5-VERIF-049 |
| 緩和集中率 / 同一規則由来率（反事実 B） | 60% / 50% | `CF_LOOSEN_CONCENTRATION` / `CF_SAME_RULE_SHARE` | 可 | S5-VERIF-050 |
| 単一種別率（退化検知） | 95% | `DEGENERATE_SINGLE_LABEL_SHARE` | 可 | S5-VERIF-051 |
| 方向反転の相関係数 | −0.3 | `INVERSION_CORR_CEILING` | 可 | S5-VERIF-052 |
| 人手ラベル週間下限 / 猶予 | 4 件（うち FN 1）/ 4 週 | `HUMAN_LABEL_WEEKLY_FLOOR` / `_GRACE_WEEKS` | 可 | S5-VERIF-055 |
| sunset / hot standby | 90 d / 30 d | `LEGACY_SUNSET_DAYS` / `HOT_STANDBY_DAYS` | 不可 | S5-VERIF-046 |

**注**: cutover / rollback に関わる閾値は **DB override 不可 MUST**（判定基準を実行時に緩められてはゲートの意味が無い）。すべての閾値は S5-VERIF-007 に従い `unit` を宣言する。

---

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | パリティ一致率の下限 0.98（CUT-01）と型別下限（CUT-04）は**実測に基づかない設定値** | 並走 14 日の実測分布を見てから確定するか、先に固定して未達なら v3 側を直すか。**後者を推奨**（先に緩めると根拠が消える） |
| A2 | 現行 baseline 8 cell 中 4 件（attack_mode 全件）が退化しており、CUT-07（非退化 cell ≥ 4）は **threat_level の 4 cell でぎりぎり満たす** | cutover 前にラベル生成器側で attack_mode の TN/FN を出せるようにするか、attack_mode を recall 判定の対象外と明示するか |
| A3 | LLM 補強を伴う結論型（attack_mode LLM augment、既定 OFF）をパリティ対象に含めるか | 含めるなら S5-VERIF-022 の応答再生が必須。除外するなら「パリティ未検証の経路」として台帳に明記が要る |
| A4 | 信号台帳 retention 60 日（S5-VERIF-018）と conclusions の 90d→365d 化保留（D3 §3-3）の整合 | 365d 化するなら信号台帳も揃えるか、パリティ窓だけ 60 日で足りるとするか |
| A5 | rollback（S5-VERIF-045）を自動発火にするか手動にするか | 自動は誤検知で不安定化するリスク、手動は反応遅延のリスク。NP1 では自動側、NP7 では人間判断側 |
| A6 | 旧系 hot standby 30 日は**同一入力での二重稼働**を意味し、外部 API のレート制限を 2 倍消費する | 二重取得を許すか、旧系を信号台帳からの replay 専用にするか（後者なら hot standby の即時性が落ちる） |

---

## 5. テストトレーサビリティ

D5 台帳のうち **S5 が管轄する BEHAVIOR / CONTRACT 級テスト**（他は S1-S4 の表が持つ）:

| テスト | test 数 | 対応条項 |
|---|---|---|
| tests/test_check_recall_baseline.py | 16 | S5-VERIF-033 / 037 / 038 |
| tests/test_check_recall_post_autotune.py | 12 | S5-VERIF-038 |
| tests/test_report_recall_metrics.py | 8 | S5-VERIF-034 / 035 |
| tests/test_conclusion_write_gating.py | 12 | S5-VERIF-017 |
| tests/test_severity.py | 8 | S5-VERIF-024 / 052 |
| tests/test_human_anchor.py | 17 | S5-VERIF-054 / 055 |
| tests/test_ground_truth_etl.py | 39 | S5-VERIF-047 / 051 / 052 |
| tests/test_run_ground_truth_etl.py | 15 | S5-VERIF-053（STRUCTURAL だが帰属規則の根拠） |
| tests/test_remediate_cross_scenario_labels.py | 6 | S5-VERIF-036 / 053（SCAFFOLD だが再発検知の根拠として保存） |
| tests/test_inconclusive_continuity.py | 17 | S5-VERIF-042（CUT-11）/ 063 |
| tests/test_scheduler_chronic_hook.py | 3 | S5-VERIF-016 |
| tests/test_drift_watchdog.py | 8 | S5-VERIF-006 |
| tests/test_self_eval.py | 9 | S5-VERIF-066 |
| tests/test_config_audit_endpoint.py | 7 | S5-VERIF-014 |
| tests/test_auto_apply_tier_governor.py | 27 | S5-VERIF-060（`_block_live_db_access` の先例） |
| tests/test_llm_prompt_persistence.py | 12 | S5-VERIF-022 |
| tests/test_attack_mode_derive.py / test_per_domain_derive.py | 26 / 27 | S5-VERIF-058（**現状は相対検証。pin テストが無い**） |
| tests/test_v1_sunset_audit.py / test_shadow_metrics.py | 17 / 10 | S5-VERIF-040（SCAFFOLD。**先例としてのみ参照、移植しない**） |

### GAP（仕様化したが検証が無い）

| ID | 内容 |
|---|---|
| GAP-01 | `GET /api/v2/replay/<sid>?at=<ts>` に**テストが 1 件も無い**（S1-CONC GAP-04）。latest-row-at-T は書込ゲート側のテストで**間接的にしか**担保されていない。S5-VERIF-017 は v3 で直接検証 **MUST** |
| GAP-02 | 沈黙検知失敗の 4 実例（F-02 / F-06 / F-08 / F-09）は**いずれも無テスト経路**にあった。S5-VERIF-001〜016 に対応する既存テストは存在しない |
| GAP-03 | 単位・到達可能性・設定到達性（S5-VERIF-007〜009, 013〜014）に対応する既存テストは存在しない |
| GAP-04 | パリティハーネス自体が存在しない。`scripts/replay_*.py` は 1 本もなく、v1/v2 用の `replay_v1_v2_diff.py` は削除済、`conclusion_diff_log` は migration v54 で drop 済。**S5-VERIF-017〜031 は全て新規実装** |
| GAP-05 | recall ゲートを実行するテストが無いため S1-CALIB-031 の「恒久的に開いたゲート」を検出できなかった（S5-VERIF-039 の動機） |

---

## 6. 未決事項

1. **信号台帳のスキーマ確定は P に持ち越し**。S5-VERIF-018 は要件（粒度・retention・必須フィールド）
   のみを定め物理設計は行っていない。`_LATEST_SIGNALS_SNAPSHOT`（radar/routes/core.py:105-112）の形が
   自然な出発点だが、これは in-memory 構造であり永続化形の検証は未実施
2. **旧系側のパリティ実行方法が未確定**。現行の採点は GET ハンドラ内で駆動される（D2 A-01）ため、
   旧系を「入力を与えて採点だけさせる」形に切り出せるかは未検証。切り出せない場合、旧系側は
   **本番稼働の live diff 記録のみ**となり 30 日 replay は v3 側単独になる
   （その場合 CUT-01〜CUT-05 の比較相手が失われるため、**代替の受け入れ条件が要る**）
3. **CUT-13（条項カバレッジ 0.95）の分母が未確定**。S1-S4 の CORE 条項総数は S 出口のカバレッジ表
   （S-coverage.md）確定後にしか数えられない
4. **反事実チェックの閾値（S5-VERIF-049〜052）は過去 3 インシデントの症状から逆算した値**であり
   統計的妥当性の検証を経ていない。過去データへの遡及適用で「3 インシデントを実際に検出できるか」を
   確認する作業が要る（#1・#2 の汚染ラベルは purge 済のため、バックアップ
   `auto_labels_purged-20260704-*.json.gz` 等からの再構成が必要）
5. **S5-VERIF-058（閾値 pin テスト）の対象閾値リストが未作成**。S1-* の閾値カタログ全件を統合した
   一覧が要る（S1-scoring-core だけで 24 件、うちハードコード 15 件）
