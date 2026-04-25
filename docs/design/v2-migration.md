# DDoS-Radar v2.0 移行設計ドキュメント

> **このドキュメントの目的**
> CLAUDE.md で再定義された新しいツール目的 (NP1-NP7) に整合する **v2.0 アーキテクチャ** の単一情報源。
> 旧 `scenario-refactor.md` (v1.x) は完了済み資料として保管し、本書が **v2.0 系列の唯一の設計仕様** となる。
>
> 新セッションを始める Claude / アナリスト / 開発者は **CLAUDE.md → 本書** の順に読むこと。
> v1.x の詳細は scenario-refactor.md §1-12 を参照可能だが、**v2.0 の判断は本書が優越する**。

---

## 0. ステータスとメタデータ

| 項目 | 値 |
|------|-----|
| **現バージョン** | 2.0.0-design |
| **作成日** | 2026-04-25 |
| **最終更新** | 2026-04-25 |
| **現在のフェーズ** | **Phase 0: 設計確定 / Phase 0 scaffolding 着手中** |
| **採用方針** | **v1 並走 → shadow → opt-in → default-on の三段階で v2 へ移行**、v1 sunset 3ヶ月 |
| **責任者** | kamonegi13(@juzo1192) |
| **想定総工数** | **約 12 人月 (専任 12 週、3 Phase + 予備)** |
| **前提資料** | CLAUDE.md (NP1-NP7 と用語定義), scenario-refactor.md v1.8.0 (v1 系列の最終仕様) |

### v2.0 Phase 進行表

| Phase | 概要 | 状態 | 期限 (目安) |
|-------|------|------|------------|
| **Phase 0** | 設計確定、ADR 起こし、scaffolding (Conclusion dataclass, DB v19-v22, codemod 準備) | **進行中** | 2026-05-02 |
| **Phase 1** | 基盤層: Conclusion Model 永続化、LLM プロンプト永続化、theater 撲滅、v2 API 骨格、NP7 disclaimer 強制 | 未着手 | 2026-06-15 |
| **Phase 2** | 結論層: 攻撃モード推定、トレンド三層化、per-domain 構造化、importance ranking、Calibration governance、Design W default-on | 未着手 | 2026-07-31 |
| **Phase 3** | UI と運用: Analyst Workbench (4 ペイン)、drill-down、Markdown/PDF export、analyst feedback ループ、ACLED+GDELT 自動突合 | 未着手 | 2026-09-15 |
| **Phase 4** | v1 sunset: deprecation header → 90 日 → v1 撤去、theater adapter 削除 | 未着手 | 2026-12-15 |

---

## 1. v2.0 が解決する課題

### 1.1 現状 (v1) の到達点と限界

v1 リファクタリング (scenario-refactor.md) で達成した事項:

- 国単位 → シナリオ単位スコアリングへの移行 (Phase 1-3 完了)
- C-lite モード確立 (focused 全センサー / background は LLM intel + global signal)
- ADR-009 follow-up (双核シナリオ対称発火)、ADR-025 shadow_sampler、ADR-026 dual-weight 評価基盤

しかし v1 は **「観察結果プレゼンテーション層」としての完成度が高い** 一方、CLAUDE.md で再定義した新目的「**結論を付けて出力する**」に対しては構造的に未到達である。

### 1.2 NP1-NP7 への充足度 (Phase A 監査結果)

| 原則 | 充足度 | 主な未到達領域 |
|------|--------|--------------|
| **NP1 感度優先** | 中 | 手動 tuning 中心。recall ground truth 注入機構なし |
| **NP4 結論最大化** | **約 40%** | TL は出るがトレンドラベル/ドメイン別結論/異常事象ランク/**攻撃モード推定**未実装 |
| **NP5+8 結論品質規律** | 中 | INSUFFICIENT_DATA 提示はあるが「過渡的 vs 恒常的」区別なし |
| **NP6 完全な導出開示** | **約 65%** | LLM プロンプト未永続化 (grep 結果 0 件)、TL 閾値が API 非開示 |
| **NP7 組織内ノード** | **約 15%** | disclaimer が i18n tooltip 1 箇所のみ、API レスポンスに常設されていない |

### 1.3 アーキテクチャ債務

- **theater 用語残存**: `grep -r "theater\|core_theater" --include="*.py" --include="*.js" --include="*.html"` で **1,612 箇所 / 67 ファイル**
- **巨大ファイル**: `radar.js` 8,160 行、`radar/database.py` 4,122 行、`index.html` 3,411 行、`i18n.js` 3,041 行
- **scenario-refactor.md** が 1,970 行と上限 2,000 行に接近 (本書分離で v1 系列を保管 → v2 系列を本書で構築)

### 1.4 v2.0 の中核アイデア

**Conclusion Model v2** — すべての結論 (全体 TL / トレンド / per-domain / 個別異常事象 / 攻撃モード) を **単一の `Conclusion` スキーマ** で表現し、API/DB/UI を貫く統一プロダクトとする。

これにより NP4 (結論最大化) / NP5+8 (品質規律) / NP6 (透明性) / NP7 (組織内ノード) を **単一スキーマで同時に satisfy** する。

---

## 2. 設計拘束 (v2.0)

CLAUDE.md の 4 拘束は v1 と共通だが、v2.0 では **追加 2 拘束** を課す。

| # | 拘束 | 由来 | 違反例 |
|---|------|------|--------|
| ① | OSINT 限定 | CLAUDE.md | 商用 threat intel 組み込み |
| ② | 特定の警戒シナリオにおける | CLAUDE.md | 国単位 TL を主出力にする |
| ③ | 技術的に実行可能な最大の結論を出力 | CLAUDE.md | advisory に格下げ |
| ④ | 完全な導出開示 | CLAUDE.md | LLM プロンプト未永続化 |
| **⑤** | **すべての結論は `Conclusion` スキーマで返す** | v2.0 | 結論を bare integer/string で API に乗せる |
| **⑥** | **すべての結論レスポンスに `final_judgment_disclaimer` を含む** | v2.0 + NP7 | disclaimer を i18n tooltip に頼る |

---

## 3. 用語定義 (v2 追加分)

CLAUDE.md / scenario-refactor.md §4 の用語に加え、v2.0 で導入する用語:

| 用語 | 意味 | コード上の表現 |
|------|------|--------------|
| **Conclusion** | ツールが出力する結論オブジェクト (5領域 × 共通スキーマ) | `radar.conclusions.Conclusion` データクラス |
| **conclusion_type** | 結論の領域分類 | `enum`: `THREAT_LEVEL`, `TREND`, `PER_DOMAIN`, `ANOMALY`, `ATTACK_MODE` |
| **state** | 結論本体の値 | TL なら `1`-`5`、トレンドなら `RAPIDLY_ESCALATING` 等 |
| **conclusion_unavailable_reason** | 結論不可時の理由 | `null` / `INSUFFICIENT_DATA` / `CALIBRATION_PENDING` / `SENSOR_DEGRADED` |
| **attack_mode** | シナリオ内のサブ攻撃様態 | `DDOS_PRECURSOR` / `KINETIC_PREPARATION` / `HYBRID_PRESSURE` / `INFO_OPS_DOMINANT` / `INSUFFICIENT_SIGNAL` + scenario extension |
| **trend_label** | 時系列方向の結論ラベル | `RAPIDLY_ESCALATING` / `ESCALATING` / `STABLE` / `DE_ESCALATING` / `RAPIDLY_DE_ESCALATING` |
| **trend_horizon** | トレンド評価窓 | `24h` / `7d` / `30d` |
| **per_domain_label** | ドメイン別結論ラベル | `ACTIVE` / `ELEVATED` / `STABLE` / `DEGRADING` / `INSUFFICIENT_SIGNAL` |
| **importance_score** | 個別異常事象の重要度スコア (0-100) | `Conclusion.metadata["importance_score"]` |
| **formula_ref** | 式の参照 (コード行 + version) | `"radar/scoring.py#derive_tl@v2.0.1"` |
| **threshold_ref** | 閾値の参照 | `dict`: `{"total": 9.0, "physical": 3.0}` (動的に出力) |
| **llm_prompt_sha256** | 永続化された LLM プロンプトのハッシュ | `radar/llm_prompts` テーブル PK |
| **calibration_status** | calibration 状態 | `dict`: `{"sampler": "OK", "drift": 0.05, "last_recal_at": ts, "sample_n": 240}` |
| **final_judgment_disclaimer** | NP7 disclaimer 文字列 | API レスポンスに必須、i18n キー `disclaimer.final_judgment` |
| **analyst_feedback** | アナリストの ground truth ラベル | `radar/analyst_feedback` テーブル |
| **API v2** | v2.0 API namespace | `/api/v2/...` (v1 API は `/api/...` で並走) |

---

## 4. 設計判断 (ADR)

v2.0 で新たに採用する設計判断。命名規則は `ADR-V2-NN`。番号は v1 と独立。

### ADR-V2-001: Conclusion Model 統一スキーマ

- **判断**: すべての結論を単一の `Conclusion` データクラスで表現する
- **代替案**: 領域ごとに別スキーマ (TL / Trend / Domain / Anomaly / AttackMode) → 採用却下
- **理由**: NP6 (透明性) を全結論で同等に保証するため、必須フィールド (formula_ref / threshold_ref / source_urls / llm_prompt_sha256 / disclaimer) をスキーマレベルで強制する。領域別スキーマは進化のたびに drift する
- **影響**: API/DB/UI の全層で `Conclusion` 型を貫通させる

### ADR-V2-002: 攻撃モード推定の粒度 (Hybrid)

- **判断**: 全シナリオ共通の **base_modes 5 種** + シナリオ別 **scenario_extensions** のハイブリッド
- **base_modes**: `DDOS_PRECURSOR`, `KINETIC_PREPARATION`, `HYBRID_PRESSURE`, `INFO_OPS_DOMINANT`, `INSUFFICIENT_SIGNAL`
- **scenario_extensions** (geo_data.json で定義):
  - `taiwan_contingency`: `NAVAL_BLOCKADE_PRECURSOR`, `PLA_AIR_INCURSION_SURGE`
  - `korea_peninsula`: `ARTILLERY_BUILDUP`, `MISSILE_TEST_CASCADE`
  - `ukraine_front`: `KINETIC_TEMPO_SHIFT`, `GRAY_ZONE_PROBING`
- **代替案**: 全共通 → 表現力不足、完全シナリオ別 → cross-scenario 学習困難
- **理由**: NP1 (感度) と analyst の cross-scenario pattern 学習を両立

### ADR-V2-003: v1 API sunset 3ヶ月

- **判断**: v2 default-on 後 **90 日** で v1 API を撤去
- **代替案**: 6ヶ月 → 二重メンテ負荷大、Phase 2/3 工数を圧迫
- **理由**: 利用者は専門アナリスト個人〜小規模チーム想定、エンタープライズ慣行 (6-12ヶ月) は過剰
- **rollout**: 月0 default-on + Sunset header → 月1 残存利用者特定 → 月3 撤去

### ADR-V2-004: Export 形式は Markdown/PDF のみ (v2.0)

- **判断**: Phase 3 では Markdown/PDF のみ実装、STIX 2.1 / JSON-LD は v2.1 以降
- **代替案**: STIX 2.1 を Phase 3 で実装 → 採用却下
- **理由**: STIX は CTI 標準で physical/info の表現力が弱い。本ツール独自 Conclusion スキーマが一次プロダクト。アナリスト 3 名以上から要望が出てから v2.1 で追加 (YAGNI)

### ADR-V2-005: ground truth は ACLED+GDELT 自動突合先行 + 手動 UI 並行

- **判断**: 公開 DB 自動突合を Phase 2 後半で先行、手動ラベリング UI を Phase 3 並行提供
- **公開 DB**: ACLED (Armed Conflict Location & Event Data) + GDELT (Global Database of Events, Language, and Tone)
- **代替案**: CISA KEV → 採用却下 (本ツールは escalation precursor、CISA KEV は exploit)
- **理由**: 自動突合で recall 計測の母数を稼ぎ Design W の統計的信頼性を上げる、手動 UI で質的フィードバックを補う

### ADR-V2-006: theater 撲滅は内部一斉置換 + v1 API adapter

- **判断**: 内部実装は codemod で `theater → scenario_id / country` に一斉置換、v1 API のみ adapter 層で `theater` キーに alias
- **代替案**: v1 残置 → 永続的負債、外部破壊 → 互換性損失
- **理由**: 内部 1612 箇所が残ると Phase 1-3 全工程で認知負荷大。adapter 層は薄く v1 sunset で削除可能 (永続負債にならない)
- **codemod**: `scripts/codemod_theater.py` を AST ベースで実装 (Phase 0 で scaffold)
- **残置許容**: 過去のコミット履歴・ADR 記録、DB 既存 column 名 (`sequence_events.theater` 等は migration コスト > メリット)

### ADR-V2-007: 旧 P5 文言の駆逐

- **判断**: 「ツールは判断しない」「avoiding over-reliance on automated assessments」系の旧 P5 由来文言を全廃
- **置換**: 「本ツールは結論を出力する。最終判断は組織プロセスが行う」(NP4 + NP7 整合)
- **対象**: `index.html` Ch.1/2/8/10、`i18n.js` 関連キー
- **検証**: `tests/test_ui_integrity.py` に禁止文字列リストを追加し、grep で fail させる

### ADR-V2-008: Conclusion は append-only ledger として永続化

- **判断**: `conclusions` テーブルを append-only ledger とし、過去結論の差分追跡を可能にする (DB migration v19)
- **代替案**: スナップショット上書き → 採用却下
- **理由**: NP6 (透明性) と analyst feedback ループ (ADR-V2-005) のため、過去結論の retrieval が必須。retention 365 日 (config 化)

### ADR-V2-009: LLM プロンプトは sha256 dedup で永続化

- **判断**: `llm_prompts` テーブル (PK: `prompt_sha256`) で dedup 永続化、`llm_call_log` から FK 参照 (DB migration v20)
- **retention**: prompt_text は 90 日、`llm_call_log` のメタデータは 365 日
- **理由**: NP6 「LLM プロンプトまで遡及可能」を構造的に保証

### ADR-V2-010: 「過渡的 vs 恒常的」結論不可の分離

- **判断**: `inconclusive_continuity_log` テーブル (DB migration v21) で全 INSUFFICIENT_DATA 出現を記録、7 日連続継続は **STRUCTURAL_GAP** alert を発火
- **scheduler**: 毎時 job で全 calibration エンドポイントの state を sampling
- **代替案**: アナリスト目視 → 採用却下 (NP5+8 後段の自動運用化を放棄することになる)
- **理由**: NP5+8 (b)「データ蓄積後も恒常的結論不可継続は設計失敗」を運用化

### ADR-V2-011: analyst_feedback テーブル新設

- **判断**: `analyst_feedback` テーブル (DB migration v22) でアナリスト ground truth を保存
- **schema**: `(conclusion_id, label ∈ {TRUE_POSITIVE, FALSE_POSITIVE, TRUE_NEGATIVE, FALSE_NEGATIVE}, observed_outcome_url, analyst_id, observed_at)`
- **用途**: Design W (ADR-026) の recall 計測ベース、attack_mode 推定の検証

### ADR-V2-012: NP7 disclaimer は schema レベルで強制

- **判断**: API v2 の全レスポンスに `final_judgment_disclaimer` を必須フィールドとする (テストで欠落を検知)
- **i18n**: `disclaimer.final_judgment.short` (~80字) と `disclaimer.final_judgment.long` (~200字) の 2 種、UI 文脈で使い分け

---

## 5. データモデル (v2.0)

### 5.1 Conclusion データクラス

```python
# radar/conclusions/base.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class ConclusionType(Enum):
    THREAT_LEVEL = "threat_level"
    TREND = "trend"
    PER_DOMAIN = "per_domain"
    ANOMALY = "anomaly"
    ATTACK_MODE = "attack_mode"

class ConclusionUnavailableReason(Enum):
    INSUFFICIENT_DATA = "insufficient_data"
    CALIBRATION_PENDING = "calibration_pending"
    SENSOR_DEGRADED = "sensor_degraded"
    UPSTREAM_FAILURE = "upstream_failure"

@dataclass(frozen=True)
class Conclusion:
    """v2.0 中核: ツールが出力する結論の単一スキーマ。"""
    id: str                                     # uuid
    scenario_id: str                            # "taiwan_contingency"
    conclusion_type: ConclusionType
    state: str                                  # "3" (TL) / "ESCALATING" / "DDOS_PRECURSOR"
    confidence: float                           # 0.0-1.0 (calibrated)
    observed_at: float                          # epoch
    formula_ref: str                            # "radar/scoring.py#derive_tl@v2.0.1"
    threshold_ref: dict                         # {"total": 9.0, "physical": 3.0}
    source_urls: tuple                          # 一次ソース URL (immutable)
    llm_prompt_sha256: Optional[str] = None     # LLM 経由なら必須
    calibration_status: dict = field(default_factory=dict)
    conclusion_unavailable_reason: Optional[ConclusionUnavailableReason] = None
    final_judgment_disclaimer: str = ""         # i18n key 経由で埋める
    metadata: dict = field(default_factory=dict)  # importance_score 等の領域固有データ

    def is_available(self) -> bool:
        return self.conclusion_unavailable_reason is None
```

### 5.2 DB schema 追加 (migration v19-v22)

```sql
-- v19: conclusions append-only ledger
CREATE TABLE conclusions (
    id              TEXT PRIMARY KEY,
    scenario_id     TEXT NOT NULL,
    conclusion_type TEXT NOT NULL,
    state           TEXT NOT NULL,
    confidence      REAL NOT NULL,
    observed_at     REAL NOT NULL,
    formula_ref     TEXT NOT NULL,
    threshold_ref   TEXT NOT NULL,         -- JSON
    source_urls     TEXT NOT NULL,         -- JSON array
    llm_prompt_sha256 TEXT,
    calibration_status TEXT NOT NULL,      -- JSON
    conclusion_unavailable_reason TEXT,
    metadata        TEXT NOT NULL          -- JSON
);
CREATE INDEX idx_conclusions_scenario_time ON conclusions(scenario_id, observed_at DESC);
CREATE INDEX idx_conclusions_type_time ON conclusions(conclusion_type, observed_at DESC);

-- v20: LLM prompts (sha256 dedup)
CREATE TABLE llm_prompts (
    prompt_sha256   TEXT PRIMARY KEY,
    prompt_text     TEXT NOT NULL,
    model           TEXT NOT NULL,
    temperature     REAL,
    prompt_version  TEXT,                  -- "apt_intel_v3" 等
    first_seen_at   REAL NOT NULL,
    last_seen_at    REAL NOT NULL,
    use_count       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_llm_prompts_last_seen ON llm_prompts(last_seen_at DESC);

-- v20 (続): llm_call_log に FK 列追加
ALTER TABLE llm_call_log ADD COLUMN prompt_sha256 TEXT REFERENCES llm_prompts(prompt_sha256);

-- v21: inconclusive_continuity_log
CREATE TABLE inconclusive_continuity_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint        TEXT NOT NULL,
    scenario_id     TEXT,
    state           TEXT NOT NULL,         -- "INSUFFICIENT_DATA" 等
    observed_at     REAL NOT NULL
);
CREATE INDEX idx_incont_endpoint_time ON inconclusive_continuity_log(endpoint, observed_at DESC);

-- v22: analyst_feedback
CREATE TABLE analyst_feedback (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    conclusion_id       TEXT NOT NULL REFERENCES conclusions(id),
    label               TEXT NOT NULL,     -- TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE / FALSE_NEGATIVE
    observed_outcome_url TEXT,             -- ACLED/GDELT URL or null
    analyst_id          TEXT NOT NULL,
    observed_at         REAL NOT NULL,
    notes               TEXT
);
CREATE INDEX idx_feedback_conclusion ON analyst_feedback(conclusion_id);
```

### 5.3 Retention ポリシー

| テーブル | retention | 理由 |
|---------|-----------|------|
| `conclusions` | 365 日 | ground truth 突合と long-term trend 検証 |
| `llm_prompts` | 90 日 | NP6 遡及性、dedup 効率と DB サイズの均衡 |
| `inconclusive_continuity_log` | 90 日 | 7 日連続検知 + 28 日履歴で十分 |
| `analyst_feedback` | 永続 | 学習材料として削除しない |

設定は `config.env`: `CONCLUSION_RETENTION_DAYS=365`, `LLM_PROMPT_RETENTION_DAYS=90` 等。

---

## 6. 結論モデル詳細

### 6.1 全体脅威レベル (THREAT_LEVEL)

- **state**: `"1"` 〜 `"5"` (TL1-5、文字列で表現)
- **既存 v1 計算**: `derive_tl()` をそのまま流用 (NP4 で評価対象としては既に充足)
- **v2 追加**: `formula_ref="radar/scoring.py#derive_tl@v2.0.1"`、`threshold_ref={"total": ..., "physical": ...}` を動的に埋める
- **frequency**: scoring tick 毎 (5 分間隔)

### 6.2 トレンド (TREND)

- **state (spec 目標)**: `RAPIDLY_ESCALATING` / `ESCALATING` / `STABLE` / `DE_ESCALATING` / `RAPIDLY_DE_ESCALATING`
- **三層**:
  - `trend_24h` (短期、scoring tick 毎)
  - `trend_7d` (中期、1時間毎)
  - `trend_30d` (長期、6時間毎)
- **算出 (spec 目標)**: 既存 `compute_scenario_velocity()` + `compute_scenario_acceleration()` を拡張、ラベルへ閾値マッピング
- **閾値 (spec 目標、Phase 2 で calibration)**:
  - `RAPIDLY_ESCALATING`: velocity > +1.0/h かつ acceleration > +0.3/h²
  - `ESCALATING`: velocity > +0.3/h
  - `STABLE`: |velocity| ≤ 0.3/h
  - `DE_ESCALATING`: velocity < -0.3/h
  - `RAPIDLY_DE_ESCALATING`: velocity < -1.0/h かつ acceleration < -0.3/h²
- **Phase 1 実装ドリフト** (`radar/conclusions/trend.py`):
  - **語彙ドリフト**: `ESCALATING` / `RISING` / `STABLE` / `COOLING` / `DEEPER_DECAY` を採用 (spec の `RAPIDLY_*` プレフィックス無し)。Phase 1.3 で spec 目標形に再マッピング検討
  - **算出ドリフト**: velocity/acceleration ではなく **mean-of-window 比較** (現在 span vs 直前 span の TL 平均差分) を使用。velocity 基盤は v1 から流用予定だが、Phase 1 は ledger に蓄積されたばかりの TL 行を直接読むほうが透明 (NP6) で着手コストが低い
  - **閾値**: `RISING_DELTA=0.50` / `ESCALATE_DELTA=1.50` (TL severity 1..4 の差分単位)。spec の velocity/h 単位とは比較不能なので Phase 1.3 で再 calibration
  - **MIN_SAMPLES**: 現/前両 window に各 3 行以上必要。`conclusions` ledger 蓄積前は INSUFFICIENT_DATA 期間が続く (NP5+8 過渡的不足として許容)
  - **出力形式**: 3 window を 1 つの Conclusion 行に packed-state 文字列 `short_term=X;medium_term=Y;long_term=Z` で格納 (spec は 3 horizon 別行を示唆するが、`?horizon=` クエリ側で分解可能なので 1 行集約を採用)
  - **TL severity 反転**: `_TL_SEVERITY` で TL1→4 / TL5→0 にマップ (TL 数字は小さいほど高脅威、severity は大きいほど高脅威)
  - shadow-write は焦点シナリオのみ (background は TL 行を出さないため input ledger が進まず無意味)

### 6.3 ドメイン別兆候 (PER_DOMAIN)

- **state**: `ACTIVE` / `ELEVATED` / `STABLE` / `DEGRADING` / `INSUFFICIENT_SIGNAL`
- **対象ドメイン**: `cyber` / `physical` / `info`
- **算出 (spec 目標)**:
  - 各 domain の signal 数と raw_score 合計から閾値判定
  - `ACTIVE`: 過去 24h で domain raw_score > 5.0 かつ signal_count >= 5
  - `ELEVATED`: raw_score > 2.0 かつ signal_count >= 2
  - `STABLE`: raw_score > 0
  - `DEGRADING`: 直近 6h で signal_count が前 24h 平均の 30% 未満
  - `INSUFFICIENT_SIGNAL`: signal_count < 1 かつ センサー全体が degraded
- **frequency**: scoring tick 毎
- **Phase 1 実装ドリフト** (`radar/conclusions/per_domain.py`):
  - 閾値: `ACTIVE_FLOOR=3.0` / `ELEVATED_FLOOR=1.5` / `DEGRADE_DELTA=1.5` (絶対値、`signal_count` 無し)。spec の `5.0` / `2.0` + `signal_count` ゲート + 30% 相対 `DEGRADING` から逸脱。Phase 1 は scoring 直後 1 tick 分の `domains` 合計のみで判定し、`signal_count` の正値は累積 ledger を待つ
  - `DEGRADING`: 直近 PER_DOMAIN 行 (`latest_conclusion`) との絶対差 `DEGRADE_DELTA` 以上を判定。spec の「6h vs 24h 相対 30% 減」は ledger 蓄積が必要なので Phase 1.3 で再キャリブレーション
  - 出力形式: 3 ドメインを 1 つの Conclusion 行に packed-state 文字列 `cyber=X;physical=Y;info=Z` で格納 (spec は明示せず、行数最少のコスト効率を採用)
  - 閾値の正式 calibration は Phase 1.3 で 14 日間 shadow 観測の上で実施 (現状は機能 OK / calibration 未確定)

### 6.4 個別異常事象 (ANOMALY)

- **state**: 観測事象の summary 文字列 (例: `"BGP withdrawal surge from AS4134 (China Telecom)"`)
- **importance_score**: 0-100 (`metadata["importance_score"]`)
- **算出式**: `raw_score × recency_decay × scenario_relevance × novelty_factor × 100`
  - `recency_decay = exp(-elapsed_h / 12)` (時定数 τ=12h、12h で約 37% に減衰。実半減期は 12·ln 2 ≈ 8.32h)
  - `scenario_relevance = llm_country_weight × participant_weight` (per-contribution 値; GLOBAL は participant_weight のみ)
  - `novelty_factor = 1.0 - (similar_count / 10)`, clamped [0.3, 1.0]
    - Phase 1 では similar_count を *現在の scoring tick 内* の同 `signal_source` 数で近似 (NP1 寄り)。Phase 1.x 以降で `conclusions` 表 24h 走査に置換。`metadata["novelty_source"]` で算出元を区別
- **API 返却**: 上位 N 件 (default 10、`?limit=` で調整)
- **importance_score 上限**: 100.0 へクランプ (raw_score × 各係数の積が 1.0 を超える場合のセーフティ)

### 6.5 推定攻撃シナリオ (ATTACK_MODE)

- **state**: ADR-V2-002 の base_modes + scenario_extensions
- **算出ロジック**: rule-based 分類 (Phase 2 初期) → LLM 補強 (Phase 2 後半)
  - `DDOS_PRECURSOR`: cyber_signal_count >= 5 (24h) かつ info_narrative_burst >= 3
  - `KINETIC_PREPARATION`: physical (ISR_SURGE + military_exercise + diplomatic_crisis) 同時 active
  - `HYBRID_PRESSURE`: 3 ドメイン同時 active かつ LLM intel cluster size >= 4
  - `INFO_OPS_DOMINANT`: info domain ACTIVE、他ドメイン STABLE 以下
  - `INSUFFICIENT_SIGNAL`: 上記いずれにも該当せず、データ過渡的不足
- **scenario_extensions**: `geo_data.json` の `scenarios.<id>.attack_mode_extensions` で追加判定式
- **複数モード並列**: top 3 を confidence 順で返却 (排他ではない)

---

## 7. API v2 設計

### 7.1 エンドポイント一覧

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/v2/scenarios/<id>/conclusions` | 全結論オブジェクト束 (5領域) |
| GET | `/api/v2/scenarios/<id>/conclusions/threat_level` | TL のみ |
| GET | `/api/v2/scenarios/<id>/conclusions/trend?horizon=24h\|7d\|30d` | トレンド |
| GET | `/api/v2/scenarios/<id>/conclusions/per_domain?domain=cyber\|physical\|info` | ドメイン別 |
| GET | `/api/v2/scenarios/<id>/conclusions/anomalies?limit=N` | 異常事象 ranking |
| GET | `/api/v2/scenarios/<id>/conclusions/attack_modes?limit=N` | 攻撃モード推定 top N |
| GET | `/api/v2/conclusions/<conclusion_id>` | 単一結論の取得 |
| GET | `/api/v2/conclusions/<conclusion_id>/audit_trace` | 完全な導出開示 (formula + threshold + sources + LLM prompt 全文) |
| POST | `/api/v2/conclusions/<conclusion_id>/feedback` | アナリスト ground truth 投入 |
| GET | `/api/v2/scenarios/<id>/export?format=markdown\|pdf` | 組織共有レポート |
| GET | `/api/v2/admin/inconclusive_continuity` | 恒常的結論不可の検知結果 (analyst のみ) |
| GET | `/api/v2/admin/llm_prompt/<sha256>` | LLM プロンプト原文取得 (analyst のみ) |

### 7.2 共通レスポンス形式

```json
{
  "api_version": "2.0",
  "scenario_id": "taiwan_contingency",
  "observed_at": 1745558400.0,
  "final_judgment_disclaimer": "本ツールの結論は組織判断の一ノードであり、最終判断ではない。",
  "conclusions": [
    {
      "id": "uuid",
      "conclusion_type": "threat_level",
      "state": "3",
      "confidence": 0.78,
      "observed_at": 1745558400.0,
      "formula_ref": "radar/scoring.py#derive_tl@v2.0.1",
      "threshold_ref": {"total": 9.0, "physical": 3.0},
      "source_urls": ["https://radar.cloudflare.com/...", "https://acled.org/..."],
      "llm_prompt_sha256": null,
      "calibration_status": {
        "sampler": "OK",
        "drift": 0.05,
        "last_recal_at": 1745468400.0,
        "sample_n": 240
      },
      "conclusion_unavailable_reason": null,
      "metadata": {}
    }
  ]
}
```

### 7.3 結論不可状態のレスポンス例

```json
{
  "api_version": "2.0",
  "conclusions": [
    {
      "conclusion_type": "trend",
      "state": null,
      "confidence": 0.0,
      "conclusion_unavailable_reason": "insufficient_data",
      "metadata": {
        "reason_detail": "Less than 6 datapoints in last 24h window",
        "is_transient": true,
        "first_observed_at": 1745554800.0,
        "consecutive_inconclusive_hours": 2
      },
      ...
    }
  ]
}
```

`is_transient = false` (= consecutive ≥ 168h = 7d) の場合、`STRUCTURAL_GAP` alert がフロント HUD に表示される。

### 7.4 v1 との並走

- v1 API (`/api/threat_data` 等) は変更せず存続
- v2 ベータ (Phase 1 完了時) から v1 レスポンスに **deprecation header** を追加:
  - `Deprecation: true`
  - `Sunset: <v2_default_on_date + 90d>`
  - `Link: </api/v2/scenarios/<id>/conclusions>; rel="successor-version"`
- v1 は内部実装で v2 の Conclusion から逆変換して返す (single source of truth)

---

## 8. UI 設計 (Analyst Workbench)

### 8.1 全体レイアウト変更

現状の地図中心 + 浮遊パネル散在から、**conclusion-first 4 ペイン** に再構築する。地図は背景情報として残すが、結論は中央上段に常時表示。

```
┌──────────────────────────────────────────────────────────────────────┐
│ 📌 Final Judgment Disclaimer (NP7 固定バナー)                         │
├────────────────────────────┬─────────────────────────────────────────┤
│ ① 結論サマリ                │ ② 攻撃モード推定                         │
│   - TL: 3 (UP from 2)      │   1. KINETIC_PREPARATION (conf 0.78)   │
│   - 24h: ESCALATING        │   2. INFO_OPS_DOMINANT (conf 0.42)      │
│   - 7d: STABLE             │   3. HYBRID_PRESSURE (conf 0.31)        │
│   - 30d: STABLE            │   [ext] PLA_AIR_INCURSION_SURGE (0.65)  │
├────────────────────────────┼─────────────────────────────────────────┤
│ ③ ドメイン別結論            │ ④ Top Anomalies (importance ranked)     │
│   🌐 Cyber: ELEVATED        │   1. BGP withdrawal AS4134 (87)        │
│   🛰️ Physical: ACTIVE      │   2. Carrier strike group movement (74) │
│   📰 Info: STABLE           │   3. CISA APT advisory (62)            │
└────────────────────────────┴─────────────────────────────────────────┘
   ↓ 各カードクリック → drill-down モーダル表示
   → "Export Markdown / PDF" ボタンで組織共有用レポート生成
```

### 8.2 Drill-down モーダル

各結論カードをクリックすると、以下を表示:
1. **結論本体** (state + confidence + observed_at)
2. **formula_ref** (コード行へのリンク + git permalink)
3. **threshold_ref** (動的閾値の表 + 「もしこの閾値が X だったら結論はどう変わるか」what-if)
4. **source_urls** (一次ソースの clickable リンク + プレビュー)
5. **llm_prompt_sha256** → 「プロンプト全文を表示」ボタン → モーダル内モーダル
6. **calibration_status** (sampler/drift/sample_n の数値表)
7. **analyst feedback** ボタン (TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE / FALSE_NEGATIVE)

### 8.3 Export 機能

- **Markdown**: シナリオ全結論を Markdown 文書として download
  - YAML front-matter (scenario, observed_at, disclaimer)
  - 各結論を H2 セクション、formula/threshold/sources を表/リストで
  - 末尾に NP7 disclaimer (long form)
- **PDF**: Markdown を pandoc または weasyprint で変換 (Phase 3 後半で実装)
- **STIX 2.1 / JSON-LD**: v2.1 で追加 (ADR-V2-004)

### 8.4 v1 UI との並走

- v1 UI (現行 index.html + radar.js) は Phase 3 完了時点で「Legacy View」として残す
- 新 UI は `/v2/` パスで提供 (例: `index_v2.html` + `radar_v2.js`)
- アナリスト個別に opt-in (localStorage `ui_version=v2`)
- v2 default-on 後 90 日で v1 UI 撤去

### 8.5 旧 P5 文言の駆逐 (詳細)

`index.html` Ch.1, 2, 8, 10 + `i18n.js` で以下を全廃:

| 旧文言 (NG) | 置換 (OK) | 理由 |
|------------|----------|------|
| "avoiding over-reliance on automated assessments" | "本ツールは結論を出力する。最終判断は組織が行う" | NP4/NP7 整合 |
| "tool does not decide" | (削除) | NP4 違反 |
| "advisory only" | "conclusion (subject to organizational review)" | NP4 整合 |
| "supports analyst judgment without replacing it" | "supports analyst by producing conclusions for organizational review" | NP4/NP7 整合 |

検証: `tests/test_ui_integrity.py` に禁止文字列リストを追加。grep ヒットで test fail。

---

## 9. Calibration Governance (NP5+8)

### 9.1 Conclusion 統合

すべての `Conclusion` の `calibration_status` フィールドに以下を埋める:

```json
{
  "sampler": "OK | DEGRADED | UNAVAILABLE",
  "drift": 0.05,
  "last_recal_at": 1745468400.0,
  "sample_n": 240,
  "confidence_interval": [0.65, 0.85]
}
```

shadow_sampler (`radar/shadow_sampler.py`) がこのデータを各結論計算時に inject。

### 9.2 過渡的 vs 恒常的の区別

`inconclusive_continuity_log` テーブル + scheduler 毎時 job で:
1. 全 Conclusion 系エンドポイントの state を sampling
2. `INSUFFICIENT_DATA` であれば log に append
3. **同一 (endpoint, scenario_id) で 7 日連続継続 → STRUCTURAL_GAP** 判定
4. STRUCTURAL_GAP 一覧を `/api/v2/admin/inconclusive_continuity` で返却
5. Admin UI Fleet Health タブに alert カードを追加

NP5+8 (b)「データ蓄積後も恒常的結論不可継続は設計失敗」を運用化する唯一の機構。

### 9.3 Design W (ADR-026) との連動

v1 で shadow phase に留まる Design W (auto-calibration) を、v2.0 では:
- Phase 2: `analyst_feedback` から recall 計測値を算出、Design W の opt-in 移行ゲートとする
- Phase 2 後半: opt-in で 14 日 → Phase 3 で default-on
- Phase 3: 全 Conclusion の `confidence` を Design W で calibration 済みの値に置換

---

## 10. 移行戦略

### 10.1 三段階 rollout (各機能共通)

すべての v2 機能は以下のパターンで投入する (ADR-025/026 の確立パターンを踏襲):

| Phase | 期間 | UI | API | 観測内容 |
|-------|------|-----|-----|---------|
| **Shadow** | 2-3 週 | v1 のまま | v2 計算するが返却せず log のみ | v1/v2 結論の drift 測定 |
| **Opt-in** | 2-3 週 | アナリスト個別に v2 有効化 | 両方返却 | 利用者フィードバック収集 |
| **Default-on** | 永続 | v2 既定、v1 は legacy として選択可 | 両方返却 + v1 deprecation header | 移行完了 |

### 10.2 Phase 別マイルストーン

#### Phase 0 (進行中): 設計確定 + scaffolding (本書作成 + 最小コード)
- ✅ v2-migration.md 作成 (本書)
- ⏳ CLAUDE.md 更新 (本書を必読参照に追加)
- ⏳ scenario-refactor.md ステータスを `v1-frozen` に更新
- ⏳ `radar/conclusions/__init__.py` + `base.py` (Conclusion dataclass)
- ⏳ DB migration v19 (conclusions テーブル)
- ⏳ DB migration v20 (llm_prompts + llm_call_log.prompt_sha256)
- ⏳ `tests/test_conclusions.py` 基本テスト
- ⏳ `scripts/codemod_theater.py` scaffolding (dry-run のみ)

#### Phase 1 完了条件
- DB migration v19-v22 すべて適用済み (本番 DB で検証)
- `radar/conclusions/` モジュール完成 (5 結論種すべての builder 関数)
- `/api/v2/scenarios/<id>/conclusions` (read-only) 稼働
- LLM プロンプト永続化 (全 LLM 経路で `llm_prompts` テーブルに insert)
- theater 撲滅 codemod 実行 + v1 API adapter 配置
- 旧 P5 文言の駆逐 + `test_ui_integrity.py` 禁止文字列テスト
- NP7 disclaimer の API 必須化 + テスト
- 全 563 既存テスト pass + 新規 30+ テスト pass

#### Phase 2 完了条件
- 攻撃モード推定 (rule-based + LLM 補強) 稼働、shadow 14 日 → opt-in
- トレンド 24h/7d/30d 稼働、shadow 14 日 → opt-in
- per-domain 構造化稼働
- importance_score ranking 稼働
- inconclusive_continuity_log + scheduler job 稼働
- ACLED + GDELT 自動突合 ETL 稼働
- Design W opt-in 移行
- 全テスト pass + recall metrics ベースライン記録

#### Phase 3 完了条件
- Analyst Workbench UI 稼働 (4 ペイン + drill-down)
- Markdown export 稼働
- analyst feedback UI 稼働
- v2 default-on (旧 v1 UI/API は legacy)
- v1 deprecation header 発射
- アナリスト 90 日継続利用フィードバック収集

#### Phase 4 完了条件
- v1 API 撤去
- v1 UI 撤去
- theater adapter 削除
- DB schema cleanup

### 10.3 ロールバック手順

各 Phase で問題発生時:
- **Phase 1**: feature flag `V2_API_ENABLED=false` で v2 API 無効化、DB migration は維持 (前方互換)
- **Phase 2**: 個別機能ごとに feature flag (`V2_ATTACK_MODE_ENABLED` 等) で個別無効化
- **Phase 3**: localStorage `ui_version=v1` で v1 UI 強制復帰
- **Phase 4**: v1 撤去後は roll-forward のみ (DB は不可逆 migration を含む)

---

## 11. 互換性とリスク

### 11.1 既存テストへの影響

| カテゴリ | 影響 |
|---------|------|
| **scoring 系** (test_engine, test_scenarios, test_scenario_scoring 等) | 大半は維持、Conclusion wrapper 追加で 30+ 新規テスト |
| **intel 系** (test_intel_*) | LLM プロンプト永続化のため `llm_call_log` 周辺テスト改修 (10 件程度) |
| **API 系** (test_routes_*) | v1 API テストはそのまま維持、v2 API 新規 50+ テスト |
| **theater 用語** | codemod 実行で既存テスト内の theater 参照も置換、grep で fail させて確認 |

総工数: 既存 563 件 → 700+ 件 (約 25% 増)、既存破壊は最小限。

### 11.2 DB migration roll-back 性

| migration | roll-back 可能性 | 備考 |
|-----------|----------------|------|
| v19 (conclusions) | DROP TABLE で OK | 過去結論は失われる |
| v20 (llm_prompts + ALTER) | ALTER の DROP COLUMN 不可 → 新 DB 作成必要 | SQLite 制限 |
| v21 (inconclusive_continuity_log) | DROP TABLE で OK | |
| v22 (analyst_feedback) | DROP TABLE で OK | analyst feedback は永続 retention のため roll-back は推奨されない |

不可逆 migration (v20 ALTER) の前に DB バックアップ必須。

### 11.3 主要リスク

| リスク | impact | 対策 |
|-------|--------|------|
| v1 API 利用者の breakage | M | 90 日 deprecation 期間 + Sunset header + アクセスログ可視化 |
| attack_mode 誤推定の組織判断歪曲 | H | confidence < 0.6 は UI で `TENTATIVE` ラベル、disclaimer 強調、Phase 2 shadow で 14 日検証 |
| LLM prompt 永続化のストレージ膨張 | M | sha256 dedup、prompt_text retention 90 日、cold storage は v2.1 検討 |
| theater codemod の破壊 | H | dry-run + diff レビュー必須、5 batch 分割 commit、各 batch で `pytest` |
| Conclusion スキーマ進化 | M | `api_version` フィールドで version 明示、後方互換性は major version で破壊許容 |
| analyst feedback 注入の歪み | M | Phase 3 で UI 提供時に「複数アナリスト集計」を表示、単一 feedback で recall を更新しない |

### 11.4 セキュリティ考慮

- **LLM プロンプト永続化**: プロンプトに analyst PII が含まれる可能性 → analyst id 等の最小化を pre-insert hook で実施
- **analyst_feedback**: analyst_id を保存するため、authenticated route のみ受付、JWT 検証必須
- **API v2**: 既存 JWT auth を流用、admin 専用エンドポイント (`/admin/inconclusive_continuity`, `/admin/llm_prompt/`) は role check 必須

---

## 12. 工数見積もり

### 12.1 Phase 別 (専任 1 名想定)

| Phase | 内容 | 工数 |
|-------|------|------|
| **Phase 0** | 設計凍結 + scaffolding | **0.5 人月** (本セッション + 次セッション 1 回) |
| **Phase 1** | 基盤層: スキーマ + LLM 永続化 + theater 撲滅 + v2 API 骨格 + NP7 disclaimer + 旧 P5 駆逐 | **3.0 人月** |
| **Phase 2** | 結論層: attack_mode + trend 三層 + per_domain + ranking + calibration governance + ACLED/GDELT + Design W default-on | **4.0 人月** |
| **Phase 3** | UI: Analyst Workbench + drill-down + export + analyst feedback UI + v2 default-on | **3.0 人月** |
| **予備 (15%)** | 較正失敗・回帰対応 | **1.5 人月** |
| **合計** | | **約 12 人月 (暦 12 週、専任)** |

### 12.2 旧 P1-P3 計画 (前回作成) との対応

前回計画の項目を v2.0 各 Phase に吸収:

| 旧計画項目 | v2.0 配属 | 備考 |
|-----------|----------|------|
| P1-1 conclusion_meta envelope | **Phase 1** | Conclusion スキーマ自体に統合 (envelope ではなく一級市民化) |
| P1-2 LLM プロンプト永続化 | **Phase 1** (ADR-V2-009) | scope そのまま |
| P1-3 旧 P5 文言の駆逐 | **Phase 1** (ADR-V2-007) | scope そのまま |
| P1-4 Help Guide 分割 | **Phase 3 へ降格** | UI 全面再設計と同時に実施した方が破壊少 |
| P1-5 scenario-refactor.md 圧縮 | **Phase 0** で実施 (本書分離) | 本書分離自体が圧縮効果 |
| P1-6 CLAUDE.md 用語重複 | **Phase 0** で実施 | scenario-refactor.md §4.2 参照化 |
| P2-1 INSUFFICIENT_DATA 検知 | **Phase 2** (ADR-V2-010) | scope 拡大、scheduler 統合 |
| P2-2 ADR-026 phase readiness | **Phase 2** | Design W default-on の前提 |
| P2-3 breakdown フロント完備 | **Phase 3** | Analyst Workbench drill-down に統合 |
| P3-1〜P3-4 | **Phase 3 もしくは v2.1** | UI 全面再設計に編入、運用データ要は v2.1 |

---

## 13. ドキュメント運用ルール

### 13.1 単一情報源原則

- **CLAUDE.md** = ツール定義 + NP1-NP7 + 用語 + コーディング規約
- **本書 (v2-migration.md)** = v2.0 の唯一の設計仕様
- **scenario-refactor.md** = v1.x の凍結資料 (履歴保全のみ、新規変更は本書)
- **ADR**: 本書 §4 にインライン記載 (ADR-V2-NN)、別ファイルは作らない

### 13.2 サイズ管理

- 本書は **2,500 行を上限** とする
- 上限接近時は scenario-refactor.md と同じ「ルール 8」(実装完了仕様は実コード参照に圧縮) を適用
- Phase 完了ごとに該当章を圧縮

### 13.3 改版履歴

| Version | 日付 | 変更概要 |
|---------|------|---------|
| 2.0.0-design | 2026-04-25 | 初版。Phase A 監査 + ADR-V2-001〜012 + Conclusion スキーマ + v2 API 骨格 + 三段階 rollout |

---

## 14. 確認事項と次のアクション

### 14.1 ユーザー確認 (本書承認時に解消)

すべて **ユーザー前回承認済み** (本書はその承認を反映):
1. ✅ attack_mode 粒度: base 5 + scenario extension hybrid (ADR-V2-002)
2. ✅ v1 API sunset: 90 日 (ADR-V2-003)
3. ✅ Export 形式: Markdown/PDF のみ、STIX/JSON-LD は v2.1 (ADR-V2-004)
4. ✅ ground truth: ACLED+GDELT 自動 + 手動 UI 並行 (ADR-V2-005)
5. ✅ theater 撲滅: 内部一斉置換 + v1 adapter (ADR-V2-006)

### 14.2 Phase 0 残タスク (本セッションで実施)

- ✅ 本書 (v2-migration.md) 作成
- ⏳ CLAUDE.md 更新 (本書を必読参照に追加 + 「進行中の大規模リファクタリング」節を更新)
- ⏳ scenario-refactor.md ステータスを `v1-frozen` に更新 + 本書へのハンドオフ追記
- ⏳ `radar/conclusions/` パッケージ scaffolding (`__init__.py` + `base.py` (Conclusion dataclass))
- ⏳ DB migration v19 (conclusions テーブル) 追加
- ⏳ DB migration v20 (llm_prompts + llm_call_log.prompt_sha256) 追加
- ⏳ `tests/test_conclusions.py` 基本テスト
- ⏳ `scripts/codemod_theater.py` scaffolding
- ⏳ Phase 1 実装ハンドオフドキュメント作成

### 14.3 次セッション (Phase 1) 着手手順

1. **theater codemod 本実行** (`scripts/codemod_theater.py` を 5 batch で commit)
2. **v1 API adapter 配置** (`radar/routes/_v1_compat.py`)
3. **NP7 disclaimer の API 必須化** (`radar/conclusions/disclaimer.py` + 全 v2 route で wrap)
4. **DB migration v21/v22 追加**
5. **`/api/v2/scenarios/<id>/conclusions` (read-only)** 実装
6. **LLM プロンプト永続化** (`radar/llm_client.py` で sha256 計算 + `llm_prompts` への insert)
7. **旧 P5 文言の駆逐** + `tests/test_ui_integrity.py` 禁止文字列テスト
8. **Phase 1 完了テスト** (全 563 既存 + 新規 30+)

---

## 付録 A: 参照コード行一覧

(本書で言及した実装箇所の早見表)

| 機能 | 主要ファイル / 行 |
|------|------------------|
| Conclusion dataclass | `radar/conclusions/base.py` (Phase 0 新規) |
| derive_tl 既存実装 | `radar/scoring.py:1087` |
| LLM client 既存実装 | `radar/llm_client.py` (Phase 1 で `llm_prompts` 永続化を追加) |
| DB migration エンジン | `radar/database.py:1066-1099` (`_run_migrations`) |
| 既存最大 migration | `radar/database.py:1049` (v18) |
| velocity / acceleration | `radar/scoring.py:1011, 1025, 1045` |
| convergence_bonus | `radar/scoring.py:1078` |
| シナリオ scoring loop | `radar/routes/core.py` (Phase 1 で v2 wrapper 追加) |
| shadow_sampler | `radar/shadow_sampler.py` |
| scenario プリセット | `geo_data.json` (Phase 2 で attack_mode_extensions 追加) |

## 付録 B: 削除/非推奨対象一覧

(Phase 4 で削除する対象を Phase 0 時点で記録)

| 対象 | 削除タイミング | 代替 |
|------|--------------|------|
| `index.html` 旧 P5 文言 (Ch.1, 2, 8, 10) | Phase 1 | NP4/NP7 整合表現に置換 |
| `i18n.js` 旧 P5 関連キー | Phase 1 | 新 disclaimer キーに置換 |
| `/api/threat_data` 等 v1 API | Phase 4 | `/api/v2/...` |
| 旧 v1 UI (radar.js + index.html 主要部) | Phase 4 | Analyst Workbench (radar_v2.js + index_v2.html) |
| `theater` adapter 層 | Phase 4 | (既に内部は scenario_id/country) |
| `scenario-refactor.md` (本書に統合済みの箇所) | Phase 4 (履歴として残置) | 本書 |

---

(本書終わり。Phase 1 着手前に必ず本書を再読し、変更があれば本書を更新してから着手すること)
