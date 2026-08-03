# 日本語化方針と CTI 用語集

| 項目 | 値 |
|------|-----|
| **決定日** | 2026-08-02 |
| **方針** | UI は**日本語専用**。多言語切替機構は持たない |
| **対象読者** | CTI / インテリジェンス実務者（アナリスト本人が単独運用） |
| **上位規範** | [CLAUDE.md](../../CLAUDE.md) のツール定義・用語定義・NP1〜NP7 / AP1〜AP4 |

## 1. なぜ日本語専用か

本ツールは単一の日本語話者アナリストが運用する。EN-only + ブラウザ自動翻訳という
従来方針（2026-04-28）は、(a) 機械翻訳が CTI 用語を破壊する（"recall" を「思い出す」、
"drift" を「漂流」と訳す）、(b) 自動翻訳は DOM を書き換えるため canvas 描画テキストや
動的更新部分に効かない、(c) 訳語がセッション毎に揺れて NP6 の監査可能性を損なう、
という三点で実務に耐えなかった。

多言語化は行わない。`STRINGS` は単一言語テーブルとして維持する（キー監査
`scripts/check_i18n_keys.py` の undefined_refs / unused_keys 検出を残すため。
文字列を各所へ直接埋め込むと、この安全網を失う）。

## 2. 翻訳しないもの（CTI 実務者にとって英語のままが正しい語）

過剰な和訳は専門家の可読性を下げる。以下は**英語のまま**とする。

| 分類 | 例 | 理由 |
|------|-----|------|
| **脅威レベル階梯** | `CRITICAL` `SEVERE` `HIGH` `ELEVATED` `NORMAL` | DEFCON 型の階梯名は固有の符牒。訳すと TL 番号との対応が崩れる |
| **評価指標** | `recall` `precision` `drift` `F1` `Z-score` | ML / 統計の確立語。「再現率」等は実務会話で使われない |
| **Calibration** | `Calibration` `calibration_status` | CLAUDE.md 本文が英語で通している（NP5+8） |
| **技術略語** | `BGP` `ASN` `OSINT` `HUMINT` `SIGINT` `LLM` `RSS` `C2` `ISR` `AIS` `NOTAM` `TTP` `IoC` `TL` | 訳語が存在しないか、英語が業界標準 |
| **プロジェクト符号** | `NP1`〜`NP7` `AP1`〜`AP4` `ADR-V2-xxx` `Design W` | 設計文書との相互参照キー |
| **センサー ID** | `ripe_bgp` `opensky` `gdelt` `acled` `cloudflare_radar` | API・DB・ログと一致させる識別子 |
| **API 状態値** | `INSUFFICIENT_DATA` `CALIBRATION_PENDING` 等の生値 | drill-down（導出開示）では**生値を表示**する。NP6 の追跡可能性はコード一致に依存する |
| **固有名** | `GDELT` `ACLED` `Ollama` `Cloudflare` | 製品・データセット名 |

**API 状態値の扱い（重要）**: 一覧・バッジ等の要約表示では和訳ラベル（例
`INSUFFICIENT_DATA` → 「データ不足」）を用いてよいが、drill-down / 監査経路では
API が返した生値をそのまま併記する。要約は読みやすさ、監査は同一性を優先する。

## 3. 訳語対応表（統一必須）

旧 JA 辞書（2026-04-28 に撤去、本作業で復元）には揺れがあった。以下を正とし、
再利用する旧訳もこの表に合わせて正規化する。

| 英語 | 採用訳 | 不採用（揺れ） | 根拠 |
|------|--------|----------------|------|
| convergence | **収斂** | ~~収束~~ | CLAUDE.md「多ソース収斂」。収束は数学的意味に寄る |
| trend | **トレンド** | ~~推移~~ | CLAUDE.md 用語定義 |
| confidence | **確信度** | ~~信頼度~~ / 英語のまま | ICD 203 の confidence level に対応する定訳 |
| feedback | **フィードバック** | ~~feedback~~（英語混在） | 片仮名で統一 |
| evidence | **根拠** | — | 一般の裏付け |
| primary source | **一次ソース** | — | CLAUDE.md |
| conclusion | **結論** | — | CLAUDE.md「結論最大化」「結論不可」 |
| inconclusive / no conclusion | **結論不可** | — | CLAUDE.md（NP5+8） |
| threat level | **脅威レベル** | — | CLAUDE.md |
| anomaly | **異常事象** | — | CLAUDE.md「個別異常事象」 |
| attack mode | **攻撃モード** | — | CLAUDE.md「推定攻撃シナリオ」 |
| indicator / indication | **兆候** | — | CLAUDE.md「開戦兆候」「ドメイン別兆候」 |
| escalation | **エスカレーション** | ~~激化~~ | CLAUDE.md |
| scenario | **シナリオ** | — | CLAUDE.md 用語定義 |
| participant | **参加国** | — | CLAUDE.md `scenario.participants` |
| adversary | **敵対国** | — | CLAUDE.md 用語定義 |
| country | **国** | ~~戦域~~ ~~シアター~~（**廃止**） | CLAUDE.md 廃止用語（theater 撲滅） |
| focused scenario | **注目シナリオ** | ~~フォーカス国~~ | CLAUDE.md（focused_country は廃止語） |
| background scenario | **背景シナリオ** | — | CLAUDE.md |
| sensor | **センサー** | — | 定着 |
| signal | **シグナル** | — | 定着 |
| threshold | **閾値** | — | CLAUDE.md |
| baseline | **ベースライン** | — | 定着 |
| derivation | **導出** | — | CLAUDE.md「完全な導出開示」(NP6) |
| audit trace | **監査経路** | — | NP6 |
| ledger | **台帳** | — | ADR-V2-008 |
| replay | **リプレイ** | — | AP4 |
| triage | **トリアージ** | — | AP1 |
| attention score | **注目度スコア** | — | AP1 |
| human anchor | **人間アンカー** | — | AP3 |
| analyst | **アナリスト** | — | CLAUDE.md |
| severity | **深刻度** | — | `severity = 6 − TL` |
| domain | **ドメイン** | — | CLAUDE.md |
| coupling weight | **結合重み** | — | CLAUDE.md |
| circuit breaker | **サーキットブレーカー** | — | NP3 |
| auto-tune | **オートチューン** | — | AP1 系 |
| pending / applied | **保留 / 適用済み** | — | — |
| acknowledge | **確認済みにする** | ~~了承~~ | 操作の意味を明示 |
| discovery (scenario) | **シナリオ探索** | ~~発見~~ | DBSCAN で候補を探す工程。事実の発見ではない |
| tier governor | **ティアガバナ** | — | 定訳なし。音写 |
| silent failure | **サイレント障害** | ~~無言障害~~ | `record_failure()` 由来のコード語 |
| miss rate | **見逃し率** | — | 1 − recall。`drill_modal.calib.fn`「見逃し」と整合 |
| analyst blindness | **最終閲覧からの経過時間** | — | AP1 の実測プロキシを訳語にした。式中の識別子 `analyst_blindness` は不変 |
| inspect (drill) | **精査** | — | 監査経路 drill-down を開く操作 |

**TL 階梯と対応する severity**（`severity = 6 − TL`。比較は必ず severity 空間で行う）:
`TL1 CRITICAL` / `TL2 SEVERE` / `TL3 HIGH` / `TL4 ELEVATED` / `TL5 NORMAL`。
階梯名は訳さない（§2）。周辺の説明文のみ日本語にする。

## 4. 文体

- **常体（だ・である）ではなく敬体を避けた簡潔体**を基本とする。UI ラベルは体言止め、
  操作ボタンは動詞（「送信」「再実行」）、説明文・ツールチップは「〜する」「〜を表示」。
- エラー・警告文のみ「〜できませんでした」「〜してください」の丁寧体を許容する
  （アナリストへの依頼・報告であるため）。
- 数値の単位・記号（`24h` `7d` `Δ` `×` `▶`）はそのまま。
- 半角英数字・ラテン文字と日本語の境界には**半角スペースを 1 つ入れる**
  （例: `TL3 に上昇`、`NP6 の導出開示`、`recall が低下`）。旧 JA 辞書がこの流儀のため踏襲。
  ただし句読点・括弧に隣接する場合は入れない（例: `（recall）`、`recall。`）。
- プレースホルダ `{n}` `{name}` は位置のみ変更可。名前は不変。

## 5. 適用範囲

| 領域 | 方針 |
|------|------|
| `i18n.js` の `STRINGS` | 全キー日本語。単一言語テーブルとして維持 |
| `index.html` の `data-i18n*` | キー参照のまま（値が日本語化される） |
| INTEL GUIDE (Ch.1–Ch.10) | **JA のみ**。`guide-lang-en` ブロックと `setGuideLang()` は撤去 |
| canvas 描画テキスト・トースト | 日本語へ直接書き換え（`_t()` を経由しない領域） |
| `self_explanation.js` (AP2) | テンプレート文を日本語化。スロット名は不変 |
| `<html lang>` | `ja`（WCAG 3.1.2） |
| Markdown エクスポート (`radar/conclusions/markdown.py`) | **見出し・ラベルは日本語**。アナリストが読み回覧する成果物。ただし `state` / `formula_ref` / JSON ペイロードは生値のまま（NP6） |
| サーバー生成の**画面表示**文言（AP3 の質問文 `human_anchor.py` 等） | **日本語**。「サーバー側だから英語」ではなく「画面に出るか」で判断する |
| **サーバーログ・例外文言** | **英語のまま**。運用者＝開発者向けであり、grep 互換性を優先 |
| **コードコメント・コミットメッセージ** | **英語のまま**（CLAUDE.md §3 を維持） |
| **API のキー名・状態値** | **英語のまま**（契約であり表示物ではない） |

## 6. CI ゲート

`scripts/check_i18n_keys.py`:
- 撤去: INTEL GUIDE の EN/JA parity 検査（EN ブロックが存在しなくなるため）
- 維持: `undefined_refs`（`_t()` 参照先が `STRINGS` に無い） / `unused_keys` / `opaque_calls`
- 追加: **未翻訳検出** — `STRINGS` の値が日本語文字（かな・漢字）を 1 文字も含まず、
  かつ §2 の除外パターン（全大文字コード、数値、記号のみ、既知略語、単位）にも
  該当しない場合は fatal。訳し忘れを構造的に防ぐ。
