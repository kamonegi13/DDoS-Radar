# v2.0 Phase 1 実装ハンドオフ

> **このドキュメントの目的**
> Phase 0 (設計確定 + scaffolding) の完了状態を記録し、Phase 1 (基盤実装)
> の最初の具体的アクションを次セッションへ引き渡す。
> 設計の根拠は [v2-migration.md](v2-migration.md) を参照。本書は実装着手の
> 入口メモであり、設計の権威ではない。

| 項目 | 値 |
|------|-----|
| 作成日 | 2026-04-25 |
| 最終更新 | 2026-04-25 (Phase 1 priority 1, 2, 4, 6, 7 完了 / priority 3 未着手) |
| Phase 0 完了基準 | Conclusion dataclass + DB v19/v20 + tests 17/17 pass + codemod scaffolding |
| 次セッションでまず読むもの | CLAUDE.md → v2-migration.md §0-§5 → 本書 |

---

## Phase 0 で出来上がったもの

### 1. ドキュメント

| パス | 役割 |
|------|------|
| `docs/design/v2-migration.md` | v2.0 設計の単一情報源 (約 880 行) |
| `docs/_archive/scenario-refactor-v1.8.1.md` | v1.8.1 として **凍結 + アーカイブ移動済**。冒頭に handoff バナー (誤読防止のため `docs/_archive/` に物理隔離) |
| `CLAUDE.md` | 「進行中の大規模リファクタリング」セクションを v2 へ更新済 |

### 2. コード scaffolding

| パス | 内容 | テスト |
|------|------|--------|
| `radar/conclusions/__init__.py` | re-export (Conclusion, ConclusionType, ConclusionUnavailableReason, new_conclusion_id) | — |
| `radar/conclusions/base.py` | frozen dataclass、5 ConclusionType、4 UnavailableReason、`__post_init__` バリデーション、`to_dict` / `to_db_row` | `test_conclusions.py` |
| `radar/database.py` | migration v19 (conclusions ledger) + v20 (llm_prompts + llm_call_log.prompt_sha256) を `_MIGRATIONS` と `_SCHEMA_SQL` 両方に追加 | smoke test 2 件 (v19/v20) |
| `test_conclusions.py` | **17 ケース全 PASS** (id 一意性、状態と unavailable_reason の排他、disclaimer 必須、confidence 範囲、frozen、シリアライズ、5 ConclusionType、DB マイグレーション 2 件) | — |
| `scripts/codemod_theater.py` | discover / diff / apply 3 サブコマンド。491 occurrences 分類済 (rename_to_country=313, rename_to_focused_country=166, user_facing_text=8, keep_v1_api_param=4) | — |

### 3. 解決済みの設計判断

| 項目 | 決定 | 出典 |
|------|------|------|
| `attack_mode` 分類体系 | ハイブリッド: 5 共通基本モード + シナリオ拡張 | ADR-V2-005 |
| トレンドラベル粒度 | 24h/7d/30d × 5 状態 | ADR-V2-003 |
| per-domain 結論 | 5 状態 (ACTIVE / ELEVATED / STABLE / DEGRADING / INSUFFICIENT_SIGNAL) | ADR-V2-004 |
| importance スコア | `raw × recency_decay × scenario_relevance × novelty × 100` | ADR-V2-007 |
| ground truth | ACLED + GDELT 自動 + アナリスト手動 UI (CISA KEV は不採用) | ADR-V2-009 |
| theater 撲滅 | AST/regex codemod + v1 API は adapter で `?theater=` 受理 | ADR-V2-006 |
| v1 sunset | 90 日 (3 段階 rollout 完了から) | ADR-V2-002 |
| STIX 出力 | 不採用 (YAGNI、cyber 単一ドメインを強制するため) | ADR-V2-011 |

---

## Phase 1 で着手するもの (優先順)

### 優先度 1: Conclusion 永続化 配線 (Phase 0 を活かす)

**ゴール**: TL 計算結果を `Conclusion` インスタンスでラップして
`conclusions` テーブルに insert する経路を 1 本通す。
現状: dataclass は存在するが、書き込む側のコードはまだない。

**着手手順**:
1. `radar/conclusions/persistence.py` を新規作成。`save_conclusion(db, c: Conclusion) -> None` を `to_db_row()` ベースで実装。
2. `radar/scoring.py` の `derive_tl()` 直後に Conclusion 化を挟む (フィーチャーフラグ `V2_CONCLUSION_LEDGER_ENABLED` で gate)。
3. `formula_ref` は `radar/scoring.py#derive_tl@v2.0.1` のような git-trackable 文字列。
4. test: `test_conclusions_persistence.py` で round-trip (save → SELECT → reconstruct → equality)。

**触ってはいけないもの**: 既存 `/api/threat_data` レスポンス。Phase 1 は ledger を埋めるだけで、API 形は変えない。

---

### 優先度 2: LLM プロンプト永続化 (NP6 達成率を 65% → 90% へ)

**ゴール**: 全 LLM 呼び出しのプロンプトを sha256 で dedup 保存し、
`llm_call_log.prompt_sha256` で逆引き可能にする。

**着手手順**:
1. `radar/llm_client.py` の呼び出し関数 (要 grep) に `prompt_text` パラメータを追加。
2. sha256 計算 + UPSERT into `llm_prompts` (use_count++)。
3. `llm_call_log` insert 時に `prompt_sha256` を含める。
4. 既存全センサー (apt_intel, diplomatic, hacktivist_*, military_exercise, rss_narrative, ground_osint) を漏れなく更新する。これは大規模 grep が必要。
5. test: `test_llm_prompt_persistence.py` (新規) で 1 LLM call → llm_prompts に 1 行 + 同じプロンプトで 2 回呼ぶと use_count=2。

**注意**: プロンプトに PII / シークレットが入らないことを念のため検証 (sha256 化しても plain text を保存するため)。`config.env` 由来の値は含めない契約をテストで強制。

---

### 優先度 3: theater codemod 適用 ❌ **撤回** (2026-04-25, cbfc113 を revert)

**経緯**:
1. cbfc113 で 484 occurrences / 38 files をリネーム済とした
2. しかし codemod の正規表現 `[A-Za-z_][A-Za-z0-9_]*theater[A-Za-z0-9_]*` には致命的バグがあり、theater 前に **少なくとも 1 文字の word-char を必須** としていた
3. 結果、standalone `theater` (例: `WHERE theater=?`, `def f(theater: str)`) と plural `theaters` を**取り逃した**。実カバレッジ **44%** (484/1094)
4. 残り 56% が未リネームのまま混在 → cross-module 参照、dict キー、JSON ペイロード、未テスト code path で潜在的破損リスク
5. 「テスト 636/636 通る」は安全保証ではない (untested path / 動的属性アクセスは静的解析不能)
6. **「破損は確実に回避する」要件 (ユーザー指示)** に従い cbfc113 を revert

**判断根拠**: in-place rename は v2-migration の核心原則 **「v1 並走 → shadow → opt-in → default-on」(ADR-V2-002)** に違反。v2 移行は parallel API パターンで実施すべき。

**正しい前進方針**: [docs/design/safe-rename-pattern.md](safe-rename-pattern.md) を参照。要点:
- Rename は additive。古い名前と新しい名前を併存させる
- module-level identifier: `old = new` alias
- function param: `**kwargs` で両キー受理
- dict / JSON: dual-write
- DB column: SQLite generated column or runtime alias
- 古い名前の削除は 100% consumer 移行確認後 (ADR-V2-002 90日サンセット)

**v2 移行で codemod を再投入しない**。代わりに Phase 1 残りスコープ (優先度 4-7) で **新規 v2 API/モジュールを並走** で構築し、consumer 側を順次切替える。

---

### 優先度 4 以降 (Phase 1 残りスコープ)

| # | タスク | 想定工数 |
|---|--------|---------|
| 4 | v2 API 骨格 (`/api/v2/conclusion/...` 4 endpoint、空実装で OK) | 2 日 |
| 5 | NP7 disclaimer をすべての v2 API レスポンスへ強制 (decorator) | 1 日 |
| 6 | shadow_sampler を v1 と v2 結論の差分計測モードに拡張 | 3 日 |
| 7 | Calibration status の per-conclusion 注入経路 | 2 日 |

詳細は v2-migration.md §10 (移行戦略) と §12 (工数) を参照。

---

## 着手前チェックリスト (次セッション必読)

- [ ] `git status` がクリーン (Phase 0 の変更が commit 済 or stash 済)
- [ ] `python -m pytest test_conclusions.py -v` が 17/17 pass
- [ ] `python scripts/codemod_theater.py discover` が走る
- [ ] CLAUDE.md と v2-migration.md を読み直し、NP4 と NP6 の責務が頭に入っている
- [ ] **Phase 1 は API 互換性を壊さない** ことに合意 (壊すのは Phase 4 sunset)

---

## コンテキスト消費の注意 (Phase 0 で観測した問題)

新セッションで Read してはならないもの (代替がある):

| ファイル | 行数 | 代替 |
|----------|------|------|
| `docs/_archive/scenario-refactor-v1.8.1.md` | 1,975 | v2-migration.md §1.1 で要点要約済。**読むな** (アーカイブ済) |
| `radar.js` | 8,160 | 必要な関数だけ Grep してから Read with offset/limit |
| `radar/database.py` | 4,255 | `_MIGRATIONS` / `_SCHEMA_SQL` セクション、または該当 method のみ |
| `index.html` | 3,411 | help-modal 章は非常に長い。該当章だけ |
| `i18n.js` | 3,041 | 翻訳キー追加なら末尾だけ Read |
| `radar/routes/core.py` | 2,840 | 該当 endpoint 関数だけ |
| `radar/routes/analytics.py` | 1,739 | 同上 |
| `radar/scoring.py` | 1,452 | scenario scoring の単一モノリス。dataclass / function 単位で Grep |
| `test_engine.py` | 1,390 | 個別テストクラス単位で Read with offset/limit |
| `radar/intel_queue.py` | 1,056 | submit / dedup / verdict patch のいずれかに絞る |
| `radar/engine.py` | 1,056 | WeightedConvergenceEngine のメソッド単位 |

**強い推奨**: Phase 1 着手の最初のターンで、これらのファイルを丸ごと
Read で読み込まないこと。Grep で当たりをつけ、`offset` / `limit` で
必要範囲だけ読む。Phase 0 のコンテキスト消費の半分以上はこれらの
モノリスファイルの再読込で発生していた。

---

## ロールバック手順

Phase 1 のいずれかで重大な不具合が出た場合:

```
git checkout main
git branch -D v2/<feature-branch>
```

`conclusions` テーブルは append-only ledger なので、誤データが入っても
SELECT 側で is_available=false でフィルタ可能。**DROP TABLE は不要**
(ADR-V2-008)。

migration v19/v20 は backward-compatible (新規テーブル追加 + 列追加のみ)
なので、コードを v1 に戻しても DB は問題なく動く。
