# S1 — 補助サービス群 挙動仕様（認証 / WS / 通知 / AP1 / AP4 / 監査）

**スコープ**: 採点・結論・較正の周囲にある支援サービス層。(1) 認証・認可（JWT ライフサイクル、role、パスワード、user 管理、レート制限）、(2) WebSocket プロトコル意味論、(3) 外部通知配信、(4) AP1 能動的トリアージ（ATTENTION ルールエンジン + 適応学習 + attention_score + triage 純関数）、(5) AP4 判断履歴（統一 decision 台帳）、(6) 設定変更監査。

**境界**: 採点式は S1-scoring-core / S1-scoring-pipeline、結論 envelope は S1-conclusions、較正提案・drift 判定は S1-calibration、インテル採否規則は S1-intel。本書は「それらの結果をどう外へ出すか / アナリストの応答をどう記録するか」のみを扱う。API のパス・ステータス・レスポンス形状の**契約**は S2 が正本。

**規約**: [S0-spec-conventions.md](S0-spec-conventions.md)。分類 CORE / ACCIDENTAL / DEFECT-PRESERVE。

**一次ソースについて**: 本領域はテスト密度が不均一。認証・triage 純関数・decision 台帳はテストが実値を pin するが、**`radar/ws.py` と `radar/audit_middleware.py` は専用テスト 0 件**（D5 §4.1）で、該当条項の根拠は**コード読解のみ**である（検証欄に明記）。

---

## 1. 用語

CLAUDE.md の定義に従う。本書固有:

- **role**: `admin` / `analyst` / `viewer` の 3 値。**CLAUDE.md 記載の 2 値は不完全**（§7-4）
- **access token**: JS 可読・`Authorization` ヘッダ搬送・短寿命 / **refresh token**: httpOnly cookie 搬送・path スコープ限定
- **room**: WS 購読単位（現行 `theater:{CODE}`） / **alert_key**: 通知 debounce の単位キー
- **rule**: ATTENTION の 1 発火条件（`rule_id` で一意） / **decision**: AP4 台帳の 1 行。`(decision_type, target_kind, target_id)` で現行性を管理
- **TL**: 1=CRITICAL … 5=NORMAL（DEFCON 式）。比較は `severity = 6 − TL` 経由

---

## 2. 挙動条項

### 2.1 認証・認可

### S1-SVC-001: パスワードは argon2id を新規生成し、PBKDF2 は検証継続 + ログイン時に遅延移行する
**挙動**: 新規作成・自己変更・admin リセットの全経路で argon2id（PHC 文字列、先頭 `$argon2`）を生成 **MUST**。検証はハッシュ形式を自動判別し、argon2 なら埋め込み salt で検証（保存 salt 列は無視）、そうでなければ PBKDF2-SHA256 100,000 回 + 保存 salt を再導出して**定数時間比較 MUST**。空ハッシュ・不正形式は**例外を投げず False MUST**。argon2 が利用不能な環境は PBKDF2 へ縮退して起動継続 **MUST**（NP3）だが、その環境で既存 argon2 ハッシュの検証要求は **False MUST**（安全側）。ログイン成功時、保存ハッシュが argon2 でなく argon2 が利用可能なら**同一パスワードから再生成して保存 MUST**。**この再ハッシュの失敗はログイン成功を妨げてはならない MUST**。既に argon2 の行は再ハッシュしない **MUST**。
**根拠**: radar/auth.py:71-152, 462-477
**検証**: tests/test_password_hashing.py::（12 件全て）
**分類**: CORE

### S1-SVC-002: パスワード最小長は 12 文字、認証失敗は原因を区別せず単一メッセージで返す
**挙動**: 登録・自己変更・admin リセットのいずれも `len < 12` を 400 で拒否 **MUST**。文字種・辞書照合・履歴再利用禁止は**課さない**。存在しない username と誤パスワードは**同一 401 + 同一文言 MUST**（列挙攻撃対策）。入力欠落のみ 400 で区別。username は前後空白を除去して照合 **MUST**。
**閾値**: 最小長 12（ハードコード、config 化なし）
**根拠**: radar/auth.py:414, 445-456, 659, 686
**検証**: test_auth.py::TestLogin::（5 件）；::TestRegistration::test_register_rejects_short_password；::TestPasswordChange::test_change_password_too_short
**分類**: CORE

### S1-SVC-003: ログインレート制限は IP 単位・失敗のみ計数・成功でリセット
**挙動**: 同一 IP からの**失敗**が窓内で上限に達したら以降 429 **MUST**。計数は失敗時のみ **MUST**、窓外の記録は評価時に除去 **MUST**、**成功時は当該 IP の記録を空にする MUST**。追跡 IP 数が上限超過なら空リストの IP を全削除、無ければ**最終試行が最も古い IP を 1 件退避 MUST**。IP は既定で接続元アドレス、`X-Forwarded-For` は**明示許可時のみ**先頭要素を採用 **MUST**（許可フラグは**起動時に一度だけ評価**され実行中の変更は反映されない）。取得不能時は `"unknown"`。状態は**プロセス内メモリのみ**（再起動で全消失）。
**閾値**: 上限 5 / 窓 300s / 追跡 IP 上限 1000（ハードコード）、`TRUST_PROXY_XFF`（env、既定 無効）
**根拠**: radar/auth.py:26-65
**検証**: test_auth.py::TestRateLimiting::test_login_rate_limit（XFF 経路は未検証）
**分類**: CORE。IP 退避規則と再起動消失は §4-A1

### S1-SVC-004: token は 2 クラスに分離し、refresh は httpOnly cookie + CSRF ヘッダで守る
**挙動**: ログイン応答は access token・username・role・access 残存秒数を返す **MUST**。access token には**発行時点の role を追加クレームとして埋める MUST**。**refresh token を JSON 本文に含めてはならない MUST**（旧仕様からの意図的削除。旧フィールドを読む古いクライアントは再ログインへ落ちる＝破壊的 4xx を出さない移行）。refresh token は **httpOnly + SameSite=Strict + refresh パスへスコープ限定** cookie で発行 **MUST**。Secure 属性は既定有効 **MUST**、無効化時は起動時警告 **MUST**。cookie 経路は CSRF 保護を適用し、**非 httpOnly の対 CSRF cookie を SPA が読んで指定ヘッダにエコーバックしない限り refresh を拒否 MUST**。フォーム経由の CSRF トークンは受理しない **MUST**。
**閾値**: `JWT_ACCESS_EXPIRES`（既定 3600s）、`JWT_REFRESH_EXPIRES`（既定 86400s）、`JWT_COOKIE_SECURE`（既定 true）、`RADAR_JWT_CSRF_DISABLED`（既定 false、**テスト専用の抜け道**）
**根拠**: radar/auth.py:205-252, 479-501
**検証**: test_auth.py::TestLogin::test_login_success；::TestRefreshCookie::test_login_sets_httponly_secure_samesite_strict
**分類**: CORE

### S1-SVC-005: refresh は role を再解決して新しい access token を発行する
**挙動**: refresh は cookie 内の refresh token のみで認証 **MUST**。**access token を refresh として提示した要求は拒否 MUST**。cookie 不在も拒否 **MUST**。role は**その時点の永続値を再取得**し、取得不能なら `viewer` を既定とする **MUST**（role 変更は次回 refresh で反映＝昇格も降格も遅延する）。
**根拠**: radar/auth.py:504-514
**検証**: test_auth.py::TestTokenRefresh::（3 件全て）
**分類**: CORE

### S1-SVC-006: 失効は「JTI 失効」または「発行時刻 < ユーザー無効化時刻」の論理和
**挙動**: 全保護要求で以下のいずれかが成立したら**トークンを無効として扱う MUST**: (a) JTI が失効台帳に存在、(b) 当該ユーザーの無効化時刻が存在し `token.iat < int(invalidate_ts)`。**(b) の右辺は整数へ切り捨てる MUST** — `iat` は整数秒・無効化時刻は小数秒であり、切り捨てなしでは「パスワード変更と同一秒に発行されたトークン」が不当に失効する。ログアウトは提示された **access token の JTI のみ**を失効台帳に追記（重複は無視）し、refresh cookie を消去 **MUST**。**refresh token の JTI は台帳に載らない**（httpOnly のため読めない）。他端末のセッションは影響を受けない。
**根拠**: radar/auth.py:264-280, 517-538、database.py:6109-6121
**検証**: test_auth.py::TestLogout::test_logout_revokes_token；::TestRefreshCookie::test_logout_clears_refresh_cookie
**分類**: CORE。refresh JTI が失効しない点は §4-A2

### S1-SVC-007: パスワード変更・admin リセットは対象ユーザーの全セッションを一括無効化する
**挙動**: パスワードを更新する全経路で**対象ユーザーの無効化時刻を現在時刻に設定 MUST**（S1-SVC-006 (b) 経由で access / refresh 双方が失効）。**操作者自身のセッションは影響を受けない MUST**。自己変更は現在パスワードの検証を要求し、不一致 401 **MUST**。
**根拠**: radar/auth.py:666-702、database.py:6035-6042
**検証**: test_auth.py::TestPasswordChange::test_change_own_password / _wrong_current；::TestUserManagement::test_admin_reset_password
**分類**: CORE

### S1-SVC-008: role は 3 値、user 管理は admin 専用かつ自己操作を禁止する
**挙動**: role は `admin` / `analyst` / `viewer` に限定し列挙外は 400 **MUST**。包含関係は **admin ⊃ analyst ⊃ viewer**（admin 専用 = user 管理・設定変更系・assumption ロック・p95 再計算 / analyst 以上 = 較正・triage・attention・decision の読み書き / viewer = 読み取りのみ）。登録・一覧・role 更新・削除・パスワードリセットは admin のみ **MUST**。**自分自身の role 変更と自分自身の削除は 400 で拒否 MUST**（最後の admin を失う事故の防止）。重複 username は 409、対象不在は 404 **MUST**。削除は設定行も削除 **MUST**。一覧は password_hash / salt を**返さない MUST**。
**根拠**: radar/auth.py:397-431, 589-645、routes/__init__.py:53-87、database.py:6044-6054
**検証**: test_auth.py::TestRegistration::（6 件）/ ::TestUserManagement::（5 件）；test_analyst_permissions.py::TestViewerForbidden / ::TestAnalystAllowed / ::TestAnalystBlockedFromAdmin / ::TestAdminCanLock
**分類**: CORE。削除の 2 文が単一トランザクションでない点は §4-A3

### S1-SVC-009: user 設定は 3 フィールドに限定し、更新句を静的 SQL 断片で構成する
**挙動**: 更新可能フィールドは focused_scenario / muted / lang の 3 つのみ **MUST**。列挙外キーは**黙って無視 MUST**、結果として有効フィールド 0 件なら 400 **MUST**。`muted` が配列でなければ 400 **MUST**。永続化層は**列名の許可リストと静的 SQL 断片**で更新句を構成し、**呼び出し側文字列を SQL に混ぜない MUST**。設定行が無ければ取得は 404 **MUST**。
**現行の欠陥**: 設定行は言語 `"en"` で作成されるが、UI は日本語専用で言語切替機構を持たない（ja-localization.md）。この列は誰にも読まれず「言語選択が存在する」という誤った含意を持つ。**v3 規範**: 単一言語 UI では**言語列を持たない MUST**。
**根拠**: radar/auth.py:375, 430, 541-586、database.py:6075-6107
**検証**: test_auth.py::TestSettings::（3 件全て）
**分類**: CORE + 言語列は **DEFECT-PRESERVE**（D2 C-03）

### S1-SVC-010: 起動時プロビジョニング — JWT 署名鍵 / 既定 admin / 整合検査
**挙動**:
- **署名鍵**: env にあればそれを使う **MUST**。無ければ乱数生成して設定ファイルへ追記 **MUST**。同名キーが既にあれば**追記せず**警告し**その回は生成鍵を揮発利用 MUST**（重複エントリを作らない）。永続化成功時はファイル権限を所有者のみへ制限 **MUST**、失敗時は **CRITICAL ログで「再起動で全トークンが無効になる」ことを明示 MUST**。
- **既定 admin**: ユーザーが 1 件も存在しないときのみ作成 **MUST**。パスワードは env 値、無ければ乱数生成 **MUST**。**生成値を構造化ログに出してはならない MUST**（ログ転送基盤が長期保持するため）。標準出力へ「即時変更せよ」の警告とともに出し、ログ側は値を伴わない警告のみ **MUST**。
- **整合検査**: admin が既存で env 値が設定されているときのみ検査 **MUST**。一致 → INFO 1 行（肯定的証跡）、不一致 → **CRITICAL ログ + AP3 自己評価への失敗記録 MUST**、env が空なら**沈黙してスキップ MUST**。**いかなる場合も起動を中断してはならない MUST**（NP3）。本検査は 2026-05-10 の障害（設定ファイル復元で env と DB が乖離し、既存セッションの refresh が成功し続けるため lockout が新規ログインまで露見しなかった）への恒久対策である。

**閾値**: `JWT_SECRET_KEY`（env / 設定ファイル）、`DEFAULT_ADMIN_PASSWORD`（env、既定 空 → 自動生成）
**根拠**: radar/auth.py:155-199, 283-376
**検証**: test_auth.py::TestStartupPasswordVerification::（4 件）。署名鍵と既定 admin 生成は**未検証**
**分類**: CORE（NP5+8: 沈黙する劣化を検出可能にする）。設定ファイルへの自動追記は §4-A4

### S1-SVC-011: role ゲートは毎リクエストで永続層を参照する
**挙動（現行）**: 保護エンドポイントの role 判定は要求ごとに**永続層の role を都度読み直す**。判定中の例外はすべて **401 に潰す**（権限不足と認証基盤障害が区別できない）。
**問題**: access token には発行時に role クレームが埋まっている（S1-SVC-004）のにゲートは読まない。結果として (a) 全保護要求が 1 回の追加 DB 読み取りを発生させ、(b) role の真偽が JWT と DB に分裂し、(c) DB 障害が一律 401 として現れる。
**v3 規範**: 認可判定は **JWT クレームの role のみを一次ソースとする MUST**。即時反映が要る場合は S1-SVC-007 と同型の無効化タイムスタンプで表現し、**認可経路から同期 DB 参照を排除する MUST**。**認証基盤の障害は 401、権限不足は 403 と区別する MUST**。
**根拠**: radar/routes/__init__.py:53-87、radar/auth.py:379-392（`require_role` も同型）
**検証**: test_analyst_permissions.py::（権限行列 18 件が現行挙動を pin）
**分類**: **DEFECT-PRESERVE**（D2 A-05）

### 2.2 WebSocket プロトコル

### S1-SVC-012: 接続確立時に JWT を検証し、失効トークンと検証失敗を拒否する
**挙動**: 接続イベントでトークンを要求 **MUST**。解決順は **(1) 接続時 auth 辞書（推奨）→ (2) クエリパラメータ（レガシー、警告ログ）MUST**。不在・復号失敗・失効台帳ヒットは**切断して拒否 MUST**。**失効確認中の例外も拒否 MUST**（fail-closed）。許可オリジンは env から読み、`*` は全許可、カンマ区切りはリスト、**未設定は空リスト＝クロスオリジン接続を一切許可しない MUST**。
**閾値**: `CORS_ALLOWED_ORIGINS`（env、既定 空＝同一オリジンのみ）
**根拠**: radar/ws.py:27-68
**検証**: **未検証**（ws.py は専用テスト 0 件）
**分類**: CORE

### S1-SVC-013: 購読は `theater:{CODE}` room 単位で、参加時の認可検査を行わない
**挙動（現行）**: 購読イベントに文字列または `{theater: CODE}` を渡すと、大文字化・空白除去された値で `theater:{CODE}` room へ参加する。空値は無視。**参加成功時のみ確認イベントを返す**（解除時は返さない＝非対称）。
**問題 1（語彙）**: `theater` は廃止用語であり、購読単位の実体は「focused scenario の中核 country」である。**WS は旧語彙が契約として外部に露出している唯一の境界**。
**問題 2（認可）**: 認証済みクライアントは**任意の room に参加できる**。room 単位の可視性制御も role による購読範囲制限も存在しない。現行は全認証ユーザーが全 scenario を見る前提なので実害は無いが、**権限モデルを持つ設計と無認可 join は整合しない**。
**v3 規範**: 購読語彙は `scenario:{id}` / `country:{ISO2}` を**用いる MUST**（`theater` を契約から排除）。参加要求は**要求者の role と focus 権限に対して検査する MUST**。購読・解除の応答は**対称にする MUST**。
**根拠**: radar/ws.py:74-91、routes/core.py:3031（`core_theater` を渡す側）
**検証**: **未検証**
**分類**: **DEFECT-PRESERVE**（D2 C-01: WS 境界の契約債務）

### S1-SVC-014: 6 種の emit イベントの発火意味・宛先
**挙動**: 以下 6 イベントを定義する。**socket 層が未初期化なら全 emit は例外を出さず無操作で返る MUST**（起動途中・テスト時の耐性）。

| イベント | 発火条件 | 宛先 | payload 要旨 |
|---|---|---|---|
| `threat_update` | 採点ティックで focused scenario の集計完了（**毎回**） | room | 戦略データ一式 + 発火時点の focused scenario id |
| `ambush_alert` | 同ティックで ambush 判定が真 | room | z-score / 加速度 / 速度 / スコア。**併せて外部通知を発火** |
| `sequence_event` | 同ティックで連鎖状態が FULL_CHAIN または PARTIAL | room | 状態 / 連鎖 / ボーナス。**併せて外部通知を発火** |
| `sensor_status` | センサー健全性が前回と変化 / CB が複数回の復旧試行に失敗（後者は 1 回のみ） | **全体配信** | センサー名 + 状態文字列 |
| `notification_result` | 外部通知 1 チャネル分の配信結果が確定するたび | **全体配信** | 時刻 / チャネル / 事象 / 成否 / 詳細 |
| `intel_update` | LLM インテル項目がキューへ投入されたとき | **全体配信** | id / 見出し（120 字切詰） / source_type / 状態 |

`threat_update` には**その push がどの focused scenario の採点結果かを識別する値を含める MUST** — 受信側が focus 切替後に到着した古い push を破棄できるようにするため（focus 変更と push の競合、2026-04-29 修正）。値が空文字なら添付しない。
**根拠**: radar/ws.py:96-155、routes/core.py:3031-3056、scheduler.py:111-134、intel_queue.py:776-784、notifications.py:278-282
**検証**: **未検証**
**分類**: CORE

### S1-SVC-015: `intel_update` は対象識別子を受け取るが使用しない
**挙動（現行）**: インテル更新 emit は第 1 引数に対象識別子を取るが、**payload にも宛先決定にも一切使われず常に全体配信される**。
**v3 規範**: 全体配信を意図するなら**引数を持たない MUST**。対象別配信が要るなら**宛先決定に使う MUST**。どちらでもない現状は署名が嘘をついている。
**根拠**: radar/ws.py:147-154
**検証**: **未検証**
**分類**: **DEFECT-PRESERVE**（D2 B-07）

### 2.3 外部通知

### S1-SVC-016: 4 チャネルへ独立に配信し、1 チャネルの失敗が他を止めない
**挙動**: 設定されたチャネル（Slack 互換 / Discord ネイティブ / Teams / 汎用 JSON）**それぞれに独立した並行実行で配信 MUST**。1 チャネルの例外・タイムアウトが他チャネルや呼び出し元（採点ティック）を**ブロックしてはならない MUST**（NP3）。各チャネルの成否は個別に記録 **MUST**。URL 未設定のチャネルは配信対象から外す **MUST**。通信タイムアウトは全チャネル 10 秒 **MUST**。成功と見なす HTTP ステータスは**チャネルごとに異なる**: Slack/Discord = {200,204}、Teams = {200} のみ、汎用 = {200,201,202,204}。
**閾値**: `NOTIFY_{SLACK,DISCORD,TEAMS}_WEBHOOK` / `NOTIFY_WEBHOOK_URL`（env、既定 空）、`NOTIFY_ENABLED`（既定 true。`false` で全停止）
**根拠**: radar/notifications.py:163-256, 288-337
**検証**: tests/test_notifications.py::test_channel_failure_does_not_block_others
**分類**: CORE

### S1-SVC-017: 全チャネルの全メッセージに NP7 免責文言を含める
**挙動**: 配信される**すべての**メッセージに「最終判断はアナリスト組織が行う / 単一の信号ノードであり完全な評価ではない」旨の固定文言を含める **MUST**。Slack は attachment footer、Discord は embed footer、Teams は末尾セクション、汎用 JSON は専用フィールドに載せる **MUST**。
**根拠**: radar/notifications.py:63-66, 151, 185, 230, 252
**検証**: test_notifications.py::test_scenario_tl_change_sends_discord_embed_with_np7_and_deep_link / ::test_slack_compat_path_includes_title_link_and_footer / ::test_generic_webhook_includes_disclaimer
**分類**: CORE（NP7）

### S1-SVC-018: 重大度は 3 段で、TL 遷移から機械的に導く
**挙動**: `(旧TL, 新TL)` から以下で導出 **MUST**（TL は 1=CRITICAL の DEFCON 式なので「新 < 旧」がエスカレーション）: エスカレーションかつ **新TL ≤ 2 → critical** / **新TL == 3 → warn** / 新TL ≥ 4 → info、**デエスカレーションおよび変化なしは常に info MUST**。未知の重大度名は **warn を既定とする MUST**。重大度は色（赤 / 橙 / 緑）と絵文字（🔴 / 🟠 / 🟢）を一意に決める **MUST**。
**根拠**: radar/notifications.py:81-105
**検証**: test_notifications.py::test_severity_for_tl（5 パラメータ）
**分類**: CORE

### S1-SVC-019: 同一 alert_key の再送は debounce 窓で抑止する
**挙動**: 事象ごとに alert_key を構成し、**窓内に同一キーの配信があれば送らない MUST**。判定と最終送信時刻の更新は**排他制御下 MUST**。alert_key は事象種別ごとに固定 **MUST**: TL 変化 = `sc_tl_change:{scenario_id}` / ambush = `ambush:{対象}` / 連鎖 = `sequence:{対象}:{状態}` / drift 未確認 = `drift_unack:{件数}:{最古ID}` / センサー障害 = `sensor_fail:{センサー名}`。状態は**プロセス内メモリのみ**（再起動直後は必ず 1 通目が通る）。
**閾値**: `NOTIFY_DEBOUNCE_SEC`（env、既定 300s）
**根拠**: radar/notifications.py:110-122
**検証**: test_notifications.py::test_debounce_blocks_second_call_within_window
**分類**: CORE。drift のキー構成は §4-A5

### S1-SVC-020: 5 種の通知事象と発火条件、深リンクの付与規則
**挙動**: 以下 5 事象のみを配信 **MUST**。

| 事象 | 発火条件 | 重大度 |
|---|---|---|
| scenario TL 変化 | 採点ティックで**脅威レベルが前回と異なり、かつ focused scenario が特定されている**とき | S1-SVC-018 で導出 |
| ambush | ambush 判定が真（WS emit の副作用） | 常に critical |
| 連鎖完成 | 連鎖状態が FULL_CHAIN または PARTIAL。**それ以外では送らない MUST** | FULL_CHAIN=critical / PARTIAL=warn |
| drift 未確認 | 日次フックで赤重大度の未確認 drift が残存 | 常に critical |
| センサー障害 | リトライ枯渇後の恒常的失敗 | 常に warn |

TL 変化通知の本文はスコアと scenario id、フィールドは**変化の理由**（ドメイン別増減 / 増えた信号 / 消えた信号）のみを載せる **MUST** — 表題の再掲をフィールドに重複させてはならない。**旧 theater ベースの TL 変化通知を再導入してはならない MUST**（2026-05-12 削除。同一遷移で二重発火し重複通知を生んでいた）。深リンクは**公開 URL が設定され対象 id が非空のときのみ** `{base}/?focus={id}` 形式で添付 **MUST**、未設定なら**リンク項目を出さない MUST**。
**閾値**: `RADAR_PUBLIC_URL`（env、既定 空。末尾スラッシュ除去）
**根拠**: radar/notifications.py:340-534、routes/core.py:3039-3056、scheduler.py:582-583
**検証**: test_notifications.py::test_legacy_theater_notifier_is_gone / ::test_drift_unack_uses_critical_severity / ::test_scenario_tl_change_omits_url_when_public_url_unset
**分類**: CORE。ambush / 連鎖が country を `?focus=` に渡す点は §7-5

### S1-SVC-021: 配信結果は直近 50 件のリングバッファに保持し、確定ごとに全体配信する
**挙動**: チャネル 1 件分の配信が確定するたびに `{時刻, チャネル, 事象, 表題, 成否, 詳細}` を追記 **MUST**。保持は**直近 50 件の固定長リングバッファ**（プロセス内メモリのみ）**MUST**。追記と同時に WS で全体配信 **MUST**。**この WS 配信の失敗は無視する MUST**（通知の通知で落ちない）。
**閾値**: リングバッファ長 50（ハードコード）
**根拠**: radar/notifications.py:259-282
**検証**: 未検証
**分類**: CORE

### 2.4 AP1 — ATTENTION ルールエンジン

### S1-SVC-022: ATTENTION は 12 個の宣言的ルールから成る
**挙動**: 各ルールは `rule_id`（一意）/ 所属ツール / 重大度 / 進入閾値 / 退出閾値 / 閾値モード / 評価関数 / メッセージ雛形 / snooze 可否 を持つ **MUST**。登録ルールは以下 12 件 **MUST**。

| rule_id | ツール | 重大度 | 進入 | 退出 | モード | snooze |
|---|---|---|---|---|---|---|
| autotune_recall_negative | autotune | critical | 1 | 1 | absolute | **不可** |
| autotune_drift_unack | autotune | warning | 1 | 1 | absolute | 可 |
| autotune_pending_volume | autotune | info | 20 | 15 | absolute | 可 |
| autotune_sensor_disable_imminent | autotune | critical | 1 | 1 | absolute | **不可** |
| autotune_quality_inversion | autotune | warning | 0.50 | 0.40 | absolute | 可 |
| llm_kill_switch | llm-features | critical | 1 | 1 | boolean | **不可** |
| llm_feature_long_shadow | llm-features | info | 1 | 1 | absolute | 可 |
| llm_intel_review_needed | llm-intel | warning | 1 | 1 | absolute | 可 |
| llm_intel_stale_pending | llm-intel | warning | 4.0 | 2.0 | absolute | 可 |
| sensor_error | watchpane | critical | 1 | 1 | absolute | **不可** |
| sensor_stale_multi | watchpane | warning | 3 | 2 | absolute | 可 |
| sensor_stale_single | watchpane | info | 1 | 0 | absolute | 可 |

**snooze 不可のルールは重大度 critical のものに限る MUST**（NP1: recall に影響する事象は黙らせない）。ツール別バッジは発火中ルールをツール単位で集約し **critical > warning > info の順で最も重い 1 件**をそのツールの状態とする **MUST**（表示文言は 60 文字で切り詰め）。
**根拠**: radar/attention.py:229-345, 488-501
**検証**: test_attention.py::TestEvaluate::test_critical_rule_fires_on_recall_negative / _per_tool_status_picks_highest_severity；::TestSnooze::test_snooze_blocks_critical
**分類**: CORE

### S1-SVC-023: ヒステリシスは「進入は以上、退出は未満」の非対称判定
**挙動**: 観測値が None のルールは**発火しない MUST**（欠測 = 非発火）。boolean モードはヒステリシスを持たず真偽そのもので発火 **MUST**。それ以外は前回状態で分岐 **MUST**: 前回**非発火** → `value >= enter_threshold` で発火 / 前回**発火** → `value >= exit_threshold` **かつ** `value > 0` を満たす限り維持。進入と退出の間の値では**直前の状態を保つ**。値 0 は必ず非発火。発火状態は**プロセス内メモリのみ**（再起動で数秒間ヒステリシスが失われるのは許容）。
**根拠**: radar/attention.py:355-383
**検証**: test_attention.py::TestHysteresis::（3 件全て）
**分類**: CORE

### S1-SVC-024: メトリクス収集は収集器ごとに隔離し、失敗を件数として計上する
**挙動**: 全メトリクスを 1 パスで収集 **MUST**。**1 収集器の失敗が他を汚染してはならない MUST**（NP3）。失敗した収集器は該当メトリクスを**未設定のまま残す MUST**（0 を書かない —「観測できなかった」と「0 だった」を混同しない）。失敗回数は累積カウンタとして計上し、AP3 自己評価が劣化を surface できる **MUST**。収集対象: 提案キュー種別内訳（7 日窓）/ 未確認 drift（7 日窓、連続 3 回以上）/ センサー無効化提案の確認期限逼迫（4 時間以内）/ 提案却下率（30 日窓、**母数 10 件未満なら 0.0**）/ LLM kill switch と長期 shadow（7 日）/ インテルキュー滞留と最古 pending 経過 / センサー健全性内訳。
**根拠**: radar/attention.py:63-223
**検証**: test_attention.py::TestEvaluate::test_returns_list（間接）
**分類**: CORE。母数不足時 0.0 は §4-A6

### S1-SVC-025: snooze は永続化され、snooze 中も発火状態の追跡は継続する
**挙動**: snooze は `(rule_id, 解除時刻, 実行者)` として永続化 **MUST**（再起動で失われない）。同一ルールの再 snooze は上書き **MUST**。snooze 不可のルールは**ルール層と API 層の両方で拒否 MUST**（多層防御）。**snooze 中のルールは出力に現れないが、ヒステリシス上は発火として追跡し続ける MUST** — 解除時に進入閾値の再突破を要求しない。時間はルール層で最小 0.5h へ切り上げ、API 層で `0 < h <= 168` を検証 **MUST**（既定 24h）。
**閾値**: 既定 24h / 下限 0.5h / 上限 168h（ハードコード）
**根拠**: radar/attention.py:389-431, 466-470、routes/attention_v2.py:83-116
**検証**: test_attention.py::TestSnooze::（3 件）；test_attention.py::test_attention_snooze_critical_returns_403 / _warning_succeeds / _unknown_rule_404
**分類**: CORE

### S1-SVC-026: p95 適応学習は観測 → 集計 → 提案の 3 段で、bootstrap 中は提案しない
**挙動**:
- **観測**: 5 分周期で各ルールの観測値を追記 **MUST**。boolean モードと値 None は記録せずスキップ計上 **MUST**。1 ルールの失敗が他を止めてはならない **MUST**。
- **集計**: 窓内観測から `p50 / p95 / p99 / サンプル数 / 算出時刻 / 窓日数` を算出し upsert **MUST**。p50 は中央値。**n=1 なら p95 = p99 = その値 MUST**。n ≥ 2 で 20 分位の第 19 要素を p95、**n ≥ 5 のときのみ** 100 分位の第 99 要素を p99、n が 2〜4 なら p99 = 最大値 **MUST**。観測 0 件のルールは「サンプル僅少」として計上しスキップ **MUST**。
- **提案**: サンプル数が下限以上の行のみ対象 **MUST**、boolean は対象外 **MUST**。提案値 = `round(p95 × 1.20, 2)`。**現行進入閾値との相対差が 30% 未満なら提案しない MUST**（提案疲れ回避）。相対差の分母は `max(現行閾値, 1.0)`。提案には p50 / p95 / サンプル数を添えて**導出経路を開示 MUST**（NP6）。
- **保持**: 窓を超えた観測は削除 **MUST**。

**閾値**: `ATTENTION_OBS_RETENTION_DAYS`（env、既定 30 日。集計窓の既定も同値）、`ATTENTION_MIN_LEARN_SAMPLES`（env、既定 30）、提案係数 1.20 / 有意差 30%（ハードコード）
**根拠**: radar/attention_learning.py:33-144、routes/attention_v2.py:233-273
**検証**: test_attention.py::TestLearning::（3 件全て）
**分類**: CORE（NP7: 提案は surface のみ。適用は明示操作が要る）

### S1-SVC-027: 利用者ごとの閾値上書きは保存されるが、評価に一切効かない
**挙動（現行）**: 閾値上書きの設定・一覧・削除 API が存在し値は利用者単位で永続化されるが、**ルール評価は常に登録時のハードコード閾値を読み、上書き値を参照する経路が存在しない**。上書きテーブルの読み取り元は「自分の上書き一覧を返す API」1 箇所のみで、書いた値は**表示以外のいかなる効果も持たない**。
**症状の見え方**: 閾値を調整すると API は 200 を返し一覧にも反映されるため、**UI 上は正常に見えるが ATTENTION の発火は一切変わらない**。これは D2 が「沈黙した検知失敗」として類型化した F-08 / F-06 と同じ構造（テストが無い経路 + UI 上は健全 + 判定だけが死んでいる）である。
**v3 規範**: 閾値の解決は**単一の解決関数を経由する MUST**（既定 → 利用者上書き → 適応提案の適用値）。**「設定できるが効かない」制御面を露出してはならない MUST**。
**根拠**: radar/routes/attention_v2.py:134-227（唯一の読み取り元）vs radar/attention.py:361-383（上書きを見ない）
**検証**: test_attention.py::test_attention_thresholds_put_get_delete_roundtrip（**往復のみ検証。評価への反映は無検証** — この穴が本欠陥を隠した）
**分類**: **DEFECT-PRESERVE**（新規発見。D2 未収載、重大度 HIGH 相当 — §7-2）

### S1-SVC-028: センサー健全性はレジストリ内部辞書を直接参照し、一覧要求で収集が 2 回走る
**挙動（現行）**: (a) センサー数の集計は、ルート層に注入されたレジストリの**非公開属性を直接列挙**し、各センサーの内部状態属性を 2 つの候補名で順に試す。(b) 一覧 API は発火ルール一覧とツール別バッジを別々に取得するが後者が内部で一覧評価を再実行するため、**1 要求につきメトリクス収集が 2 回走り、ヒステリシス状態の入れ替えも 2 回起きる**（フロントは 5 秒周期でポーリングする）。
**v3 規範**: レジストリは**公開された列挙 API と健全性照会 API を提供する MUST**。1 要求につきメトリクス収集は 1 回 **MUST**、派生ビューは**同一評価結果から導出する MUST**。
**根拠**: radar/attention.py:204-221；routes/attention_v2.py:67-68 → attention.py:488-490
**検証**: 未検証
**分類**: **DEFECT-PRESERVE**（(a) は D2 A-05）/ (b) は §4-A7

### 2.5 AP1 — attention_score と triage 純関数

### S1-SVC-029: attention_score は 3 成分の積で、順位付けは降順・下限足切り・非破壊
**挙動**: `attention_score = novelty × confidence_delta × analyst_blindness` **MUST**。各成分は [0,1] にクランプ **MUST**。LLM も乱数も用いず**入力から決定論的に定まる MUST**（AP2 / NP6: 順位の導出が常に再現可能）。
- **novelty**: 同種結論の直前発火からの経過で 1 → 0 へ線形減衰。履歴なしなら **1.0 MUST**。`novelty = clamp01(1 − age / 48h)`
- **confidence_delta**: 前回 confidence があれば `clamp01(|current − prev|)`、無ければ**現在の confidence をそのまま採用 MUST**（新規項目を「変化なし」で消さない）
- **analyst_blindness**: 当該 scenario の最終閲覧からの経過で 0 → 1 へ線形増加。閲覧記録なしなら **1.0 MUST**。`blindness = clamp01(since / 6h)`

以下は入力によらず **score 0 MUST**: 結論 id が無い / 結論が「結論不可」/ アナリスト確認済み（ack 集合に含まれる）。非数値・非有限値は 0 として扱う **MUST**。
順位付けは**降順ソート MUST**、**最小表示スコア未満は除外 MUST**、1 始まりの順位を付与 **MUST**。配列でない入力は空配列 **MUST**。**入力配列および要素オブジェクトを変更してはならない MUST**。各項目は**なぜそのスコアになったかの平文説明列を必ず持ち MUST**（AP2）、そこには novelty / confidence 差分 / blindness の 3 行が常に含まれる **MUST**。
**閾値**: novelty 地平 48h / blindness 地平 6h / 最小表示スコア 0.05（ハードコード）
**根拠**: triage_score.js:51-155
**検証**: tests/test_triage_score.js::（21 件全て）
**分類**: CORE

### S1-SVC-030: attention_score の実装はフロントエンドにのみ存在する
**挙動（現行）**: AP1 の中核式である attention_score は**ブラウザ側の純モジュールにしか実装されていない**（バックエンドに同等の実装・API・永続化は存在しない。全コード検索で該当なし）。
**含意**: (a) 順位付けはクライアント端末上でのみ成立し、**サーバ側に「何が上位だったか」の記録が残らない**。AP4 が要求する「過去の自動化判断の事後検証」に対し **AP1 の順位は再生不能**である。(b) blindness の入力（最終閲覧時刻）と ack 集合はクライアント状態であり端末・ブラウザを跨がない。
**v3 規範**: attention_score は**サーバ側で算出し、順位と成分値を台帳へ記録する MUST**。UI は算出結果を表示するだけとし、**同一式の二重実装を禁止する MUST**。
**根拠**: triage_score.js（唯一の実装）
**検証**: フロント側のみ（test_triage_score.js 21 件）
**分類**: **DEFECT-PRESERVE**（新規発見。AP1 × AP4 の整合欠落 — §7-3）

### S1-SVC-031: triage 優先度は confidence × coupling × 経年減衰の積
**挙動**: `priority = confidence × coupling_factor × exp(−max(0, age_sec) / τ)` **MUST**。`coupling_factor` は最大 scenario 結合度が正ならその値、**そうでなければ床値 MUST**（scenario に紐付かない項目を永久に最下位へ沈めない）。負の経過時間は 0 へクランプ **MUST**。
**閾値**: τ = 12h（`PRIORITY_AGE_TAU_SEC`、ハードコード。age = τ で約 0.368 倍）、未マッチ床 0.30
**根拠**: radar/triage.py:18-67
**検証**: tests/test_triage.py::TestComputePriority::（5 件全て）
**分類**: CORE

### S1-SVC-032: 対象国の導出と scenario 結合度の算出
**挙動**: 明示的な国コードリストがあればそれを採用 **MUST**（空要素除去、常に大文字化）。空の場合のみレガシー単一文字列にフォールバックし、`-` を含むなら分解、含まなければ 1 要素として扱う **MUST**（前後空白除去）。どちらも空なら空リスト **MUST**。結合度は**全 scenario × 全対象国の総当たり**で、対象国が participant として登場する組から**最大の coupling weight とその scenario を返す MUST**。同時に**マッチした全組（国 / scenario / weight / role）を記録して返す MUST**（ドリルダウン用、NP6）。マッチ無しは 0.0 と None。
**v3 規範**: レガシー文字列からの分解経路は**持ち込まない MUST**（D2 C-01 / F-11 の同族）。
**根拠**: radar/triage.py:36-104
**検証**: test_triage.py::TestDeriveCountries::（6 件）；::TestMaxScenarioCoupling::（4 件）
**分類**: CORE の骨格 + レガシー分岐は **DEFECT-PRESERVE**

### S1-SVC-033: 保留理由は評価順に最初に落ちたゲートを返す
**挙動**: 「なぜまだ自動確認されないか」を**キュー本体の評価順と同じ順序で判定し、最初に不成立となったゲート名を返す MUST**: (1) confidence が自動確認閾値未満 → 低信頼、(2) ソース信頼度が床未満 → 低ソース信頼度、(3) ecosystem が許可集合外 → `ecosystem_blocked:{値}`、(4) ecosystem が空 → 未分類、(5) 全通過 → 手動レビュー待ち。
**閾値**: ソース信頼度の床 0.75、許可 ecosystem = `{independent, cert, us_gov}`、未知ソースの既定信頼度 0.70（すべてハードコード）
**根拠**: radar/triage.py:27-33, 107-127, 154
**検証**: test_triage.py::TestClassifyGate::（6 件）；::TestEnrichPending::test_unknown_source_uses_default_credibility
**分類**: CORE。ゲート定義がキュー本体と二重管理である点は §4-A8。未分類 ecosystem が恒久 pending になる問題は D2 F-10 が既収載

### S1-SVC-034: 保留一覧の enrich と HUD pulse は同一の優先度式を共有する
**挙動**: 一覧提示と HUD の脈動指標は**同一の優先度関数・結合度関数を用いる MUST** —「脈動しているのに一覧が空」という不整合を構造的に起こさないため。一覧は優先度降順にソート **MUST**、各項目に優先度 / ゲート理由 / ソース信頼度 / ecosystem / 裏付け件数 / 最上位 scenario / 全マッチ / 経過時間 / 減衰係数 / 最大結合度を添付 **MUST**（NP6）。脈動は**優先度が閾値以上かつ経過時間が下限以上**の項目のみ計数 **MUST**（新着高信頼項目で毎回点滅しない＝「既に見ているべきだったもの」だけを浮かせる）。最大優先度は**計数条件と無関係に全項目から追跡する MUST**。
**根拠**: radar/triage.py:130-216
**検証**: test_triage.py::TestEnrichPending::（4 件）；::TestComputePulse::（4 件）
**分類**: CORE

### 2.6 AP4 — 統一 decision 台帳

### S1-SVC-035: decision は 4 属性を検証してから追記する
**挙動**: 追記時に以下を検証し、不正なら**書き込まず例外 MUST**: 決定種別が非空 / 対象種別が `{global, scenario, conclusion, user}` / 行為が `{accept, extend, raise, rollback, snooze, dismiss, set, apply}` / 実行者が非空。決定 id は不透明な短い一意文字列を生成 **MUST**。パラメータは JSON 保存し読み出し時に構造へ復元 **MUST**（復元失敗時は None）。
**根拠**: radar/decisions.py:57-161, 403-415
**検証**: tests/test_decisions.py::test_record_writes_row / _validates_target_kind / _validates_action / _requires_actor
**分類**: CORE

### S1-SVC-036: supersede は「先に追記、後に旧行を差し替え」の順で行う
**挙動**: 同一の `(決定種別, 対象種別, 対象id)` について**現行は常に高々 1 件 MUST**。新規追記時、**先に新しい行を挿入し、その後に旧行の後継参照を新 id へ更新する MUST** — 逆順では後継参照の参照先が未存在となり参照整合性制約に反する。更新対象は「後継未設定 かつ 未失効 かつ 自分自身でない」行に限る **MUST**。対象 id が NULL の場合は NULL 一致で照合 **MUST**。**失効済みの行を supersede で書き換えてはならない MUST**（失効 ≠ 被後継）。異なる対象 id の行は互いに影響しない **MUST**。
**根拠**: radar/decisions.py:114-161（docstring L20-33 が正本）
**検証**: test_decisions.py::test_supersede_chains_correctly / _supersede_target_isolated / _latest_returns_only_current
**分類**: CORE

### S1-SVC-037: 「有効な decision」の述語は 3 条件の連言
**挙動**: `後継未設定 かつ 未失効 かつ (期限なし または 期限 > 現在時刻)` **MUST**。「最新の現行行を返す」操作は**期限を評価しない MUST**（期限判定は呼び出し側に委ねる）。「有効か」を問う操作のみが期限を評価する **MUST**。複数の決定種別が同一対象で同時に有効なら**決定時刻が最も新しいものを採る MUST**。一括問い合わせは対象 id をキーに、有効な決定を持つ対象のみを**1 回の問い合わせで返す MUST**。
**根拠**: radar/decisions.py:29-33, 201-315
**検証**: test_decisions.py::test_is_active_respects_expiry / _is_active_no_expiry_means_always_active
**分類**: CORE

### S1-SVC-038: 履歴問い合わせは 7 条件の AND 結合で、件数上限は 1000 に固定する
**挙動**: 決定種別 / 対象種別 / 対象id / 実行者 / 行為 / 開始時刻 / 終了時刻 を任意に組み合わせ**すべて AND で結合 MUST**。条件が無ければ台帳全体から新しい順 **MUST**。並びは**決定時刻の降順 MUST**。件数は `[1, 1000]` にクランプ **MUST**（既定 200）。
**根拠**: radar/decisions.py:317-365
**検証**: test_decisions.py::test_history_filters_combine / _history_limit_capped_at_1000
**分類**: CORE

### S1-SVC-039: 現在稼働している決定種別は TRIAGE 系 4 種のみ
**挙動**: 稼働中の決定種別は以下 4 種 **MUST**。

| 決定種別 | 対象種別 | 行為 | 期限 | 意味 |
|---|---|---|---|---|
| triage_snooze | global | snooze | 指定分後（1〜1440 分、既定 30） | TRIAGE レーンの一時消音 |
| triage_visibility | user | set | **なし**（次回設定まで） | 常時表示モード切替（`default` / `always` の 2 値。他は 400） |
| triage_dismiss | global | dismiss | 24 時間後 | 次の新規発火まで非表示。期限到来で自動復帰 |
| triage_threshold_override | user | set | **なし** | 表示閾値の利用者別上書き（各 [0,1] にクランプ、既定 0.40 / 0.85） |

**snooze と dismiss は critical 事象を黙らせてはならない MUST**（NP1）。台帳は**事実を記録するだけであり、抑止の可否は表示層が critical 判定と組み合わせて決める MUST**。TL 較正と重み governance の決定種別は 2026-05-29 に廃止された（移行ゲートが無操作のまま経過し、TL 較正は tier governor による自律運用へ移行）。**再導入してはならない**。
**閾値**: snooze 1〜1440 分（既定 30）/ dismiss 24h / 表示閾値既定 0.40 / 0.85（ハードコード）
**根拠**: radar/routes/decisions.py:81-335
**検証**: test_decisions.py::test_api_triage_snooze_records_decision / _clamps_minutes / _snooze_release / _state_reflects_active_snooze / _visibility_modes / _visibility_rejects_bad_mode / _threshold_get_returns_defaults / _threshold_put_then_get / _threshold_clamps_out_of_range
**分類**: CORE

### S1-SVC-040: revoke は専用列に記録し初回のみ成功を返す。API 側の権限分岐は到達不能
**挙動**: 失効は**専用の失効時刻列と失効者列**へ書く **MUST**。**後継参照列に合成マーカーを詰め込んではならない MUST** — 当該列は decision id への参照制約を持ち、マーカー混入が参照整合性の有効化を妨げていた（Phase 5 で是正済み）。対象は「後継未設定 かつ 未失効」の行に限り、**既に失効済みの行への再失効は False を返す MUST**（冪等）。
**現行の欠陥**: (a) API 層の権限分岐は決定種別の接頭辞（governance 系なら admin、他は analyst 以上）で行うが、**governance 系は全廃済みで到達不能な死んだ枝**である。(b) 409 の判定は**後継参照のみを見て失効列を見ない**ため、既に失効済みの行は判定を通過し、その後の失効操作が False を返して**「競合」を意味する 409 が返る** — 実際には競合ではなく単なる再失効。(c) 当該 docstring は是正前の「合成マーカー」実装を記述しており実装と食い違う（D2 E-18）。
**v3 規範**: 権限は**決定種別ごとの宣言的な権限表から解決する MUST**（接頭辞の文字列判定を禁止）。無効性の判定は S1-SVC-037 の述語を**単一の関数として共有する MUST**。
**根拠**: radar/decisions.py:375-399、routes/decisions.py:400-448
**検証**: test_decisions.py::test_revoke_marks_inactive / _revoke_idempotent_returns_false / _api_revoke_marks_decision_inactive / _api_revoke_404_on_unknown / _api_revoke_409_on_already_inactive
**分類**: CORE（台帳側）+ **DEFECT-PRESERVE**（API 側）

### S1-SVC-041: NP7 確認強制のガードはどこからも呼ばれていない
**挙動（現行）**: 「recall を減らす破壊的操作には明示確認フラグと理由を要求する」という NP7 由来のガード関数が定義されているが、**呼び出し元が 1 箇所も存在しない**（使っていた governance エンドポイント群が廃止されたため）。モジュール docstring は「破壊的操作は確認フラグを要求する」と現在形で述べており、**仕様として読むと嘘になる**。
**v3 規範**: recall を減らす操作の確認強制は**維持する MUST**（NP7）。ただし**実際に強制される経路に接続する MUST**。呼ばれない安全機構は安全機構ではない。
**根拠**: radar/routes/decisions.py:20-24（docstring）vs :60-76（唯一の定義、参照ゼロ）
**検証**: 未検証（呼び出し元が無いためテスト不能）
**分類**: **DEFECT-PRESERVE**（D2 E-05 / E-18 の同族）

### S1-SVC-042: 旧 tradecraft 台帳との関係 — 新台帳が正、旧台帳は破棄する
**挙動（現行）**: 決定の記録先が 2 つ存在する。(a) 本書が規定する構造化 governance 台帳（supersede ライフサイクル・失効・AP4 再生を持つ）、(b) tradecraft のアドホックなメモ台帳（`threshold` / `disconf_add` / `assumption_add` 等のドメイン語彙、supersede も失効も持たない）。両者は意図的に併存し、履歴 UI は両方を統合表示する。
**D4 疑問 3 の結論**: **(a) が新・正である。(b) の現存 984 行は全量がテスト残骸**（tradecraft 全表の行数が「テスト実行回数 × 固定件数」と完全一致）であり資産価値はゼロ。
**v3 規範**: 構造化 governance 台帳のみを持ち越す **MUST**。tradecraft 台帳は**スキーマごと破棄 MUST**。テストが本番永続層へ書き込める構造そのものを**禁止する MUST**（D2 B-08）。
**根拠**: radar/decisions.py:9-18（docstring が関係を明文化）、D4-data-assets.md §3 Q1/Q3
**検証**: test_analyst_permissions.py::TestAutoLogWriteThrough；::TestDecisionLedgerImmutable
**分類**: **DEFECT-PRESERVE**

### 2.7 設定変更監査

### S1-SVC-043: 監査は応答生成後に走り、2xx のときのみ 7 項目を記録する。範囲は 8 経路に限定
**挙動**: 監査は**主たる応答の生成を妨げてはならない MUST**（NP3）。記録処理中のいかなる例外も**握り潰してログのみ MUST**。記録は**応答ステータスが 2xx のときに限る MUST**（失敗した変更を履歴に載せない）。ステータスが数値化できない場合は 200 とみなす **MUST**。要求本文と変更前の値は**ルート実行前に取得する MUST** — 実行中に要求ストリームが消費されるため事後に読むと空になる。記録項目は ドメイン / 変更対象キー / 変更前値 / 変更後値 / 実行者 / 理由 / 要求id **MUST**。実行者は認証 identity、取得できない場合（バックグラウンド処理・テスト等）は **`"unknown"` を入れる MUST**（行自体を欠落させない）。対象キーは 128 文字で切り詰め、決定できなければ `"?"` **MUST**。
**現行の欠陥**: 監査が付与されているのは `config.runtime`（2）/ `sensor.enabled`（1）/ `sensor.noise_exclusion`（2）/ `scenario.state`（1）/ `scenario.enabled`（1）/ `scenario.reset`（1）の 6 ドメイン 8 経路のみ。これは「3 層 config へ移行できなかった旧エンドポイントの暫定的な穴埋め」という出自のままで、**監査範囲が移行の都合で決まっていて変更の重要度で決まっていない**。結論に影響する変更でもこの 8 経路の外にあるものは履歴に残らない。
**v3 規範**: **結論に影響しうる設定変更はすべて単一の変更経路を通り、その経路が無条件に監査を発行する MUST**（NP6）。個別ルートへの装飾で網羅性を担保してはならない **MUST**。
**根拠**: radar/audit_middleware.py:1-13, 49-146、radar/routes/admin.py（8 箇所）
**検証**: **未検証**（audit_middleware.py は専用テスト 0 件）
**分類**: CORE + 範囲限定は **DEFECT-PRESERVE**（D2 A-13 / C-03）

---

## 3. 閾値カタログ

| 閾値 | 値 | config キー | 3 層解決 | 条項 |
|---|---|---|---|---|
| access / refresh token 寿命 | 3600s / 86400s | `JWT_ACCESS_EXPIRES` / `JWT_REFRESH_EXPIRES` | env のみ | 004 |
| refresh cookie Secure / CSRF 無効化 | true / false | `JWT_COOKIE_SECURE` / `RADAR_JWT_CSRF_DISABLED`（**テスト専用**） | env のみ | 004 |
| JWT 署名鍵 / 既定 admin パスワード | 自動生成 | `JWT_SECRET_KEY` / `DEFAULT_ADMIN_PASSWORD` | env（鍵は設定ファイルにも） | 010 |
| XFF 信頼 | 無効 | `TRUST_PROXY_XFF` | env のみ（起動時固定） | 003 |
| ログイン失敗上限 / 窓 / 追跡IP上限 | 5 / 300s / 1000 | — | 不可 | 003 |
| パスワード最小長 | 12 | — | 不可 | 002 |
| WS 許可オリジン | 同一オリジンのみ | `CORS_ALLOWED_ORIGINS` | env のみ | 012 |
| 通知有効化 / webhook 4 種 | true / 空 | `NOTIFY_ENABLED` / `NOTIFY_*_WEBHOOK` | env のみ | 016 |
| 通知 debounce / タイムアウト / ログ保持 | 300s / 10s / 50 件 | `NOTIFY_DEBOUNCE_SEC` のみ config 化 | env のみ | 019 / 016 / 021 |
| 公開 URL | 空 | `RADAR_PUBLIC_URL` | env のみ | 020 |
| ATTENTION 各ルール閾値 | 表 S1-SVC-022 | — | **不可**（上書き経路は無効 — 027） | 022 |
| snooze 既定 / 下限 / 上限 | 24h / 0.5h / 168h | — | 不可 | 025 |
| 観測保持・集計窓 / 最小サンプル | 30 日 / 30 | `ATTENTION_OBS_RETENTION_DAYS` / `ATTENTION_MIN_LEARN_SAMPLES` | env のみ | 026 |
| 提案係数 / 有意差 / 却下率の最小母数 | 1.20 / 30% / 10 | — | 不可 | 026 / 024 |
| novelty 地平 / blindness 地平 / 最小表示 | 48h / 6h / 0.05 | — | 不可 | 029 |
| triage 経年 τ / 未マッチ床 | 12h / 0.30 | — | 不可 | 031 |
| ソース信頼度の床 / 未知既定 | 0.75 / 0.70 | — | 不可 | 033 |
| triage snooze / dismiss / 表示閾値 | 1〜1440 分（既定 30）/ 24h / 0.40・0.85 | — | 不可 | 039 |
| 履歴件数 既定 / 上限 | 200 / 1000 | — | 不可 | 038 |

**v3 への示唆**: 本領域のハードコード閾値は **21 系統**。うち ATTENTION の 12 ルール分は「UI に上書き面があるのに評価に効かない」（S1-SVC-027）という最悪の形をとる。S1-scoring-core §3 の指摘（結論に影響する全閾値を宣言的 registry へ）は本領域にも同じ強さで及ぶ。

---

## 4. ACCIDENTAL（オーナー裁定待ち）

| ID | 事象 | 裁定の論点 |
|---|---|---|
| A1 | ログインレート制限が**プロセス内メモリのみ**。再起動で全解除、複数プロセス構成では実効上限が台数倍。IP 上限超過時の退避が「最終試行が最も古い IP」なので、攻撃者は多数 IP を投げて正規利用者の記録を押し出せる | 単一プロセス運用前提を仕様に固定するか、永続化するか |
| A2 | ログアウトが access token の JTI のみ失効させ、refresh token の JTI は台帳に載らない（cookie 消去のみ） | 同一 refresh token を別経路で保持していた場合の残存リスクは許容範囲か |
| A3 | ユーザー削除で設定行の削除と本体の削除が**単一トランザクションに入っていない**（設定削除だけが書き込み文脈の外） | 中断時に設定行のみ消える孤児状態。トランザクション境界の是正要否 |
| A4 | JWT 署名鍵が不在時に**設定ファイルへ自動追記される**（アプリがアプリの設定を書き換える） | 利便性 vs「設定は外部から与える」原則。v3 で起動失敗にすべきか |
| A5 | drift 未確認通知の debounce キーに**件数と最古 ID が入る**ため、件数が 1 増えるだけで debounce を貫通して再送される | 通知圧の設計意図か。キーを対象種別のみにすべきか |
| A6 | 提案却下率は**母数 10 件未満のとき 0.0 を返す**（「観測不能」ではなく「良好」として振る舞う） | NP5+8 は「データ不足」を明示すべきとする。None を返して非発火にする設計との比較 |
| A7 | ATTENTION 一覧要求 1 回につきメトリクス収集が 2 回走る（5 秒ポーリング × 2 倍の DB 負荷、ヒステリシス入替も 2 回） | 性能上の実害の有無。v3 では構造的に 1 回 |
| A8 | 自動確認ゲートの定義（信頼度床 0.75 / 許可 ecosystem 3 種）が **triage 純関数側とインテルキュー本体で二重管理** | 片方だけ変更したときの silent drift。単一定義へ寄せるか（S1-intel と要調整） |

---

## 5. DEFECT-PRESERVE 一覧（現行挙動の記録 + v3 規範）

| ID | 現行 | v3 規範 | D2 |
|---|---|---|---|
| DP1 | role 判定が毎リクエスト DB 参照。JWT の role クレームは無視。判定中の例外は一律 401 | role は JWT クレームを一次ソースに **MUST**。認証障害 401 と権限不足 403 を区別 **MUST** | A-05 |
| DP2 | WS 購読が `theater:{CODE}` room。参加時の認可検査なし。購読/解除の応答が非対称 | 語彙は `scenario:` / `country:` **MUST**。参加を role と focus 権限で検査 **MUST** | C-01 |
| DP3 | インテル更新 emit の第 1 引数が未使用 | 引数を廃止するか宛先決定に使う **MUST** | B-07 |
| DP4 | **利用者別 ATTENTION 閾値が保存されるが評価に一切効かない**（API が 200 を返すため健全に見える） | 閾値解決は単一関数経由 **MUST**。効かない制御面を露出しない **MUST** | **新規** |
| DP5 | ATTENTION がセンサーレジストリの非公開辞書を直接列挙 | レジストリは公開列挙 API を提供 **MUST** | A-05 |
| DP6 | **attention_score の実装がフロントにのみ存在**。順位がサーバに記録されず AP4 で再生不能 | サーバ側算出 + 台帳記録 **MUST**。同一式の二重実装を禁止 **MUST** | **新規** |
| DP7 | revoke API の権限分岐が到達不能な接頭辞判定。409 が「競合」と「既に失効」を区別しない。docstring が是正前の実装を記述 | 権限は宣言的表から解決 **MUST**。無効性判定は単一述語を共有 **MUST** | E-18 |
| DP8 | NP7 確認強制のガードが**呼び出し元ゼロ**。docstring は現在形で強制を主張 | recall 減少操作の確認強制を実経路に接続 **MUST** | E-05/E-18 |
| DP9 | 旧 tradecraft 台帳が併存。現存 984 行は全量テスト残骸 | 構造化 governance 台帳のみ持ち越し **MUST**。テストの本番書込みを構造的に禁止 **MUST** | B-08 |
| DP10 | 監査対象が 6 ドメイン 8 経路のみ（移行の都合で決まった範囲） | 設定変更は単一経路を通り無条件に監査 **MUST** | A-13 |
| DP11 | user 設定に言語列があるが UI は日本語専用で誰も読まない | 単一言語 UI では言語列を持たない **MUST** | C-03 |
| DP12 | triage の対象国導出にレガシー単一文字列の分解経路が残存 | 国リストのみを受け付ける **MUST** | C-01/F-11 |

---

## 6. テストトレーサビリティ

| テスト（D5 分類） | 件数 | 対応条項 |
|---|---|---|
| test_auth.py（CONTRACT） | 49 | 002/003/004/005/006/007/008/009/010。**うち 14 件は領域外**: `TestComputeAirspaceStatus`（7、S1-sensors-cyber-physical）、`TestDataRetention`（5、S3）。**混在ファイルであり v3 では分割 MUST** |
| test_password_hashing.py（BEHAVIOR） | 12 | S1-SVC-001（12 件全て） |
| test_analyst_permissions.py（CONTRACT） | 18 | 008（8）/ 042（8）/ 011（間接）。**tradecraft 面のため DP9 で破棄予定** |
| test_attention.py（BEHAVIOR + CONTRACT 混在） | 18 | 022/023/024/025/026、027（**往復のみ**） |
| test_triage.py（BEHAVIOR） | 29 | 031（5）/ 032（10）/ 033（7）/ 034（8）。**GAP なし** |
| test_notifications.py（BEHAVIOR） | 9 | 016/017/018/019/020。**GAP なし** |
| test_decisions.py（CONTRACT） | 32 | 035/036/037/038/039/040。うち 2 件は永続層 migration 検証（S3 領域） |
| test_triage_score.js（BEHAVIOR） | 21 | S1-SVC-029（21 件全て）。**GAP なし** |

### GAP（仕様化できたが検証が無い）

| ID | 内容 | 危険度 |
|---|---|---|
| GAP-01 | **WS プロトコル全体が無検証**（012〜015）。接続時 JWT 検証、失効拒否、room 語彙、6 emit の宛先、focus race 対策のいずれもテストが無い。**認証境界がテストされていない唯一の面** | **高** |
| GAP-02 | **監査 middleware 全体が無検証**（043）。「2xx のみ記録」「本文をルート前に読む」という壊れやすい前提を機械的に確認する手段が無い | 高 |
| GAP-03 | 利用者別閾値が**評価に効くこと**を検証するテストが無い（往復のみ）。**この穴が DP4 を長期に隠した** | 高 |
| GAP-04 | JWT 署名鍵の生成・永続化・重複回避と既定 admin 生成（010 の前 2 項）が無検証 | 中 |
| GAP-05 | XFF 信頼フラグの挙動（003）が無検証。IP 詐称の防御境界そのもの | 中 |
| GAP-06 | 失効判定 (b) の**同一秒境界**（切り捨ての要否、006）が無検証 | 中 |
| GAP-07 | 通知の並行配信が**採点ティックを塞がないこと**自体は無検証（チャネル間の独立性のみ検証済） | 低 |
| GAP-08 | 配信結果リングバッファの上限挙動（021）が無検証 | 低 |

**特記**: test_auth.py の `TestComputeAirspaceStatus` / `TestDataRetention`（計 14 件）は認証と無関係であり、**ファイル配置の事故**である。仕様の穴ではなく分類の誤り。対応先は S1-sensors-cyber-physical と S3。

---

## 7. 未決事項

1. **AP1 の責務境界が仕様レベルで割れている**。`radar/attention.py` は「ツールの運用状態を監視するルールエンジン」、`triage_score.js` は「結論を順位付けする AP1 本体」であり、名前が近いだけで対象も所在も異なる。CLAUDE.md は AP1 の実装を「`triage_score.js`（pure module）+ Triage Lane」と記し、**`attention.py` を AP1 の実装として位置づけていない**。P でどちらを AP1 の正統実装とするか（統合するか）の裁定が要る。

2. **S1-SVC-027（利用者別閾値が効かない）は現行系でも修正候補**。D2 の「沈黙した検知失敗」表（F-08 / F-06 / F-02 / F-09）に**追加すべき 5 件目**であり、共通構造（テスト無し経路 + UI 上は健全 + 判定だけが死んでいる）に完全に一致する。

3. **S1-SVC-030（attention_score のサーバ不在）は AP4 の前提を壊している**。CLAUDE.md は AP4 を「conclusions ledger + analyst_feedback ledger + alert_lane_history の combined な time-travel UI」と定義するが、AP1 の順位はどの台帳にも入らない。「過去の自動化判断が事後検証できる」という要件に対し **AP1 の判断だけが再生対象から抜けている**。P で AP1 出力の台帳化設計が要る。

4. **role モデルの記述が CLAUDE.md と実装で食い違う**（2 値 vs 3 値）。S 出口で CLAUDE.md 側を実装に合わせるか、viewer を廃止するかの裁定が要る。

5. **通知の「対象」引数が scenario id と country code で混在している**。TL 変化は scenario id を渡すが、ambush と連鎖は country（`core_theater`）を渡し、深リンク生成は一律に `?focus={値}` を組み立てる。`?focus=` は scenario id を期待するため、**ambush / 連鎖の深リンクは country を scenario id として渡している**。フロント側の `?focus=` ハンドラが未知値をどう扱うかは未確認のため、実害の有無は実機確認を要する（本仕様では未確定）。
