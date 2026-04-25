# Safe Rename Pattern (additive, dual-write, deferred sunset)

> **このドキュメントの位置付け**
> v2 移行で `theater → country / focused_country` のような大規模リネームを
> 行う際の **唯一の正しい手順** を定義する。
> 2026-04-25 の cbfc113 (in-place rename) revert を受けて作成。
> 以後、in-place rename を新規導入してはならない (ADR-V2-002 と整合)。

| 項目 | 値 |
|------|-----|
| 作成日 | 2026-04-25 |
| 適用範囲 | v2 migration での識別子・DB 列・API パラメータ・JSON キーの改名すべて |
| 上位原則 | ADR-V2-002 (v1 並走 → shadow → opt-in → default-on, 90 日 sunset) |
| 反例 | cbfc113 (in-place codemod、coverage 44%、revert 済) |

---

## 1. なぜ in-place rename は破綻するか

cbfc113 で実証された 5 つの破綻モードを記録する。

### 1.1 静的解析の限界 (Python は dynamic)

- 動的属性アクセス (`getattr(obj, "theater")`)、文字列キー dict (`d["theater"]`)、
  reflection、テンプレート展開は静的 grep / regex / AST いずれでも完全捕捉不能
- テストカバレッジが 100% でも、untested 動的パスは保証外
- cbfc113 の codemod は **44% (484/1094)** しかカバーしなかったが、
  「テスト 636/636 pass」だけで安全と誤判定した

### 1.2 cross-module / cross-runtime 参照

- Python ↔ JavaScript ↔ HTML ↔ JSON ↔ SQL の境界をまたぐ識別子
  (例: `?theater=` API param、`{"theater": ...}` レスポンス、`WHERE theater=?` SQL)
  は **どれか 1 つを変えると他がすべて壊れる**
- 「同時に全部直す」は理論上可能だが、realistic な PR では必ず漏れる

### 1.3 外部 consumer の不可視性

- API consumer (フロントエンド、外部スクリプト、保存済みクエリ) は
  ソースリポジトリから見えない。サーバー側 rename だけでは契約破壊
- DB スナップショット、バックアップ、ログファイル、設定ファイルに残る
  旧名は migration では追えない

### 1.4 部分適用の二重リスク

- 一部だけリネームして残りを後回しにすると、**新名と旧名が混在** する状態になる
- 旧名参照が残った code path は dynamic に発火するまで気付かない (silent breakage)
- 「次の PR で残りをやる」は永久に来ない ("rename debt" として固定化)

### 1.5 ロールバック困難

- in-place rename は revert する以外に巻き戻し手段がない
- DB 列名の rename は SQLite では `ALTER TABLE RENAME COLUMN` (v3.25+) で
  可能だが、データ移行と consumer 移行を atomic にできない

---

## 2. Safe Rename Pattern の 5 原則

| # | 原則 | 内容 |
|---|------|------|
| **SR1** | **Additive** | 旧名を消すのではなく、新名を **追加** する。両方が同時に動く |
| **SR2** | **Single source of truth** | 内部実装は新名で書き、旧名は **alias / adapter** にする |
| **SR3** | **Dual-write / dual-read** | 永続化層 (DB, JSON) は両キーに書き、両キーで読める |
| **SR4** | **Telemetry on legacy access** | 旧名アクセスをログ・カウンタで観測。0 になるまで削除しない |
| **SR5** | **Sunset only after observation** | ADR-V2-002 の 90 日サンセット完了 + telemetry 0 の両方で初めて旧名削除 |

---

## 3. 実装パターン (5 レイヤー × 5 原則の対応表)

### 3.1 Module-level identifier (Python / JS variable, function, class)

```python
# radar/scenarios.py — internal canonical name is `country`
class Scenario:
    @property
    def country(self) -> str:
        return self._country

    # SR2: alias for legacy callers (deprecated, removed in v2 sunset)
    @property
    def theater(self) -> str:
        _record_legacy_access("Scenario.theater")  # SR4
        return self._country
```

```javascript
// radar.js — additive global
const country = computeCountry();
const theater = country;  // SR1: legacy alias kept until sunset
```

**判定規準**: 内部実装は新名で統一。旧名は **read-only property / alias** で
新名へ転送。書き込み API は新名のみ受理 (write-side breakage を避けるため)。

### 3.2 Function parameter

```python
def submit_intel(*, country: str | None = None, theater: str | None = None, **rest):
    # SR1+SR2: accept both, prefer new
    actual_country = country if country is not None else theater
    if theater is not None and country is None:
        _record_legacy_access("submit_intel(theater=)")  # SR4
    ...
```

**判定規準**: 新名を主、旧名を fallback にする。両方指定された場合は新名優先
+ warning。`**kwargs` で受けるのは安全だが型情報が落ちるので、明示宣言を推奨。

### 3.3 Dict / JSON payload (API response, internal data)

```python
def serialize_scenario(s: Scenario) -> dict:
    return {
        "country": s.country,          # SR1: new key
        "theater": s.country,          # SR3: dual-write for legacy consumers
        "_legacy_keys": ["theater"],   # SR4: telemetry hint for log scrapers
        ...
    }
```

```python
def parse_scenario(d: dict) -> Scenario:
    country = d.get("country") or d.get("theater")  # SR3: dual-read
    if "theater" in d and "country" not in d:
        _record_legacy_access("parse_scenario:theater key")  # SR4
    ...
```

**判定規準**: serialize は **両方書く**、parse は **新名優先で fallback**。
レスポンスサイズ増加は許容 (~数 bytes / scenario)。

### 3.4 DB column

SQLite の選択肢は 2 つ:

#### Option A: Generated column (推奨、SQLite 3.31+)

```sql
-- migration vXX
ALTER TABLE scenarios ADD COLUMN country TEXT
  GENERATED ALWAYS AS (theater) VIRTUAL;
```

- 旧 `theater` 列を canonical に保ち、`country` は read-only view
- INSERT / UPDATE は `theater` のみ受理 (consumer 移行完了まで)
- 全 SELECT が両名で動く

#### Option B: Trigger-backed dual write

```sql
-- migration vXX
ALTER TABLE scenarios ADD COLUMN country TEXT;
UPDATE scenarios SET country = theater WHERE country IS NULL;

CREATE TRIGGER scenarios_country_sync_insert AFTER INSERT ON scenarios
BEGIN
  UPDATE scenarios SET country = NEW.theater WHERE id = NEW.id AND NEW.theater IS NOT NULL;
  UPDATE scenarios SET theater = NEW.country WHERE id = NEW.id AND NEW.country IS NOT NULL;
END;

CREATE TRIGGER scenarios_country_sync_update AFTER UPDATE ON scenarios
WHEN NEW.theater IS NOT OLD.theater OR NEW.country IS NOT OLD.country
BEGIN
  UPDATE scenarios
    SET country = COALESCE(NEW.country, NEW.theater),
        theater = COALESCE(NEW.theater, NEW.country)
    WHERE id = NEW.id;
END;
```

**判定規準**: 読み専用なら Option A。書き込み consumer が複数残っているなら
Option B。どちらも migration は backward-compatible (列追加のみ)。

### 3.5 API route / query parameter

```python
@app.route("/api/v2/threat_data")
def threat_data_v2():
    country = request.args.get("country") or request.args.get("theater")
    if request.args.get("theater") and not request.args.get("country"):
        _record_legacy_access("/api/v2/threat_data?theater=")  # SR4
    ...

# v1 endpoint kept verbatim (ADR-V2-002 90-day sunset)
@app.route("/api/threat_data")
def threat_data_v1():
    return _v1_adapter(threat_data_v2)
```

**判定規準**: v1 endpoint は **そのまま** 残す。v2 endpoint は両 param 受理。
Sunset 後に v1 endpoint と `?theater=` 受理を同時削除。

---

## 4. Telemetry スキーマ (SR4 の実装契約)

`_record_legacy_access(key: str)` は以下を満たす:

```python
# radar/legacy_telemetry.py (新規, Phase 1 で作成)
_legacy_access_counts: dict[str, int] = defaultdict(int)
_legacy_access_first_seen: dict[str, float] = {}
_legacy_access_last_seen: dict[str, float] = {}

def _record_legacy_access(key: str) -> None:
    """Increment counter. Caller-cheap (no I/O on hot path)."""
    now = time.time()
    _legacy_access_counts[key] += 1
    _legacy_access_first_seen.setdefault(key, now)
    _legacy_access_last_seen[key] = now
```

集計エンドポイント `/api/admin/legacy_access` で 1 日 1 回 dump、
**24 時間連続で count=0** が確認できた legacy alias から sunset 候補に上げる。

---

## 5. Sunset 手順 (SR5)

旧名を削除する条件 (**全て満たすこと**):

1. ADR-V2-002 の 90 日サンセット期間 完了
2. `_legacy_access_counts[key]` が直近 30 日 0
3. v1 並走モードの shadow_sampler で v1/v2 結論 diff が baseline 以下
4. 削除 PR はその 3 つの観測ログを **本文に貼り付ける**

削除 PR の前提となる `legacy_access` 観測が 0 にならないなら、
そのまま並走を継続する (90 日は最短保証であって最大ではない)。

---

## 6. このパターンを使わない選択肢 (negative space)

Safe Rename Pattern が **過剰** な状況:

| 状況 | 推奨手順 |
|------|---------|
| ローカル変数 (関数内のみ) | 直接 rename。スコープが閉じているので破壊なし |
| 未公開 helper (`_underscore_prefix`、テスト・呼び出し元同居) | grep で全 caller 確認後に直接 rename |
| 新規追加コード (旧名がそもそも無い) | 最初から新名で書く。alias 不要 |
| ドキュメント / コメント | 直接書き換え可。runtime 影響なし |

**判定基準**: rename 対象が **import 経由で外部から参照されている可能性** が
あるなら Safe Rename Pattern。ないなら通常 rename で良い。

---

## 7. レビュー時のチェックリスト

PR レビュアー向け:

- [ ] 旧名と新名が両方存在するか (削除されていないか)
- [ ] 内部実装が新名で統一されているか
- [ ] 旧名アクセス時の `_record_legacy_access` 呼び出しがあるか
- [ ] DB 変更が backward-compatible (列追加 / generated column のみ) か
- [ ] API 旧 endpoint / 旧 param が残っているか
- [ ] sunset 期日が CLAUDE.md or v2-migration.md に記録されているか

---

## 8. 関連 ADR

- [ADR-V2-002](v2-migration.md) — v1 並走 → shadow → opt-in → default-on, 90 日 sunset
- [ADR-V2-006](v2-migration.md) — theater 概念分割の意図
- [v2-phase1-handoff.md](v2-phase1-handoff.md) §優先度 3 — cbfc113 revert の経緯
