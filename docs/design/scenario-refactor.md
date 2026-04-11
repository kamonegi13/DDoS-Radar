# シナリオ中心リファクタリング 設計ドキュメント

> **このドキュメントの目的**
> DDoS-Radar を「国(country)単位の脅威モニタ」から「**選択したシナリオ単位の脅威評価ツール**」へ
> 段階的にリファクタリングするための単一の真実源(Single Source of Truth)。
>
> 新しいセッションを始める Claude / アナリスト / 開発者は **まずこのファイルを読むこと**。
> これまでの議論文脈・設計判断・未決事項がすべてここに集約されている。

---

## 0. ステータスとメタデータ

| 項目 | 値 |
|------|-----|
| **作成日** | 2026-04-11 |
| **最終更新** | 2026-04-11 |
| **現在のフェーズ** | Phase 0(設計確定済み、Phase 1 着手前) |
| **採用方針** | **C-lite** で開始、運用知見をもとに **C-medium** へ進化 |
| **責任者** | kamonegi13(@juzo1192) |
| **想定総工数** | 約 14-18 日(Phase 1〜5)|

### Phase 進行表

| Phase | 概要 | 状態 | 完了日 |
|-------|------|------|--------|
| **Phase 0** | 設計確定、ドキュメント整備 | **進行中** | — |
| **Phase 1** | シナリオデータモデルと用語整理 | 未着手 | — |
| **Phase 2** | シナリオスコアリングエンジン | 未着手 | — |
| **Phase 3** | LLM プロンプトと intel queue の country 化 | 未着手 | — |
| **Phase 4** | HUD のシナリオ単位再設計 | 未着手 | — |
| **Phase 5** | 検証 UX と bias インジケータ | 未着手 | — |
| **(将来)** | C-medium への移行 | 条件待ち | — |

---

## 1. ツールの定義(ユーザー定義文)

> **フリーかつオープンの情報ソースを統合して、選択したシナリオにおける国家レベルの脅威の上昇や開戦兆候を把握するための、直接的なスコアと、アナリスト検証可能な情報を提供するツール**

この一文がツールのすべての設計判断の起点。**いかなる変更もこの定義に整合しなければならない**。

### 定義から導かれる本質
- **観察対象は紛争シナリオ**(国ではない)
- **scoring の出力は直接的**(複雑な集計の結果ではなく、その場で読める数値)
- **アナリストは判断する主体**(ツールは判断を支援する)
- **すべての情報は無料で再現可能**

---

## 2. 設計拘束(4つ)

定義文から導かれる、絶対に犯してはならない拘束。

| # | 拘束 | 意味 | 違反例 |
|---|------|------|--------|
| **①** | **OSINT 限定** | 有償・機密ソースは使わない | 商用 threat intel feed の組み込み |
| **②** | **選択したシナリオにおける** | 分析の単位は scenario(国ではない) | 国単位の TL を主出力にする |
| **③** | **直接的なスコア** | 1つの数値で「いま何点か」が即読める | ML 出力の確率分布を主表示にする |
| **④** | **アナリスト検証可能** | あらゆる寄与点が原典に追跡できる | ブラックボックス aggregation |

---

## 3. 設計原則(P1〜P5)

設計拘束を実装に翻訳した、コードレベルの判断基準。

### P1: シナリオは第一級の出力単位
**根拠**: 拘束② から直接導出
**意味**:
- API レスポンスの主体は scenario(country ではない)
- HUD の主表示単位は scenario
- TL は scenario ごとに付与
- アラート/通知は scenario 単位で発火

### P2: シナリオ内の cross-country シグナルは自動集約
**根拠**: 開戦兆候は本質的に複数国に分散して現れるため
**意味**:
- 「US で観測された APT 活動」は Taiwan Contingency シナリオの cyber スコアに自動寄与
- 寄与の重みは scenario.participants で定義
- アナリストが手動で関連付けを行う必要はない

### P3: スコア合成式は完全に透明
**根拠**: 拘束③④
**意味**:
- スコアは `Σ (signal.score × participant.weight)` の形で展開可能
- すべての項を数値とラベル付きで表示できる
- ブラックボックス ML や隠れたヒューリスティックは禁止
- HOD baseline 等の統計的処理は許可だが、式と入力値は表示可能でなければならない

### P4: 全ての rationale は原典追跡可能
**根拠**: 拘束④
**意味**:
- 各 rationale entry は次を持つ:
  - sensor 名 + 観測タイムスタンプ
  - 生の観測値
  - LLM 由来の場合: 原典 URL + LLM の reasoning + confidence
  - 計算過程: `value × weight × coupling = contribution`
- 「これを除外したら TL がどうなるか」の what-if が UI から可能

### P5: ツールは判断を支援する、判断しない
**根拠**: 拘束④ の最も深い含意
**意味**:
- 自律行動はしない(自動ブロック、自動通報など)
- 通知は「人間の注意を引く」ためであり、「人間の代わりに判断する」ためではない
- シナリオ自動検出はしない(シナリオはアナリストが定義)
- 予測はしない(現状の警告のみ)

---

## 4. 用語定義

このプロジェクトの用語は **コード、ドキュメント、UI のすべてで統一する**。揺れがあったらコード側を直す。

### 4.1 主要用語

| 用語 | 意味 | コード上の表現 |
|------|------|--------------|
| **country** | 国(データの一次タグ) | ISO2 code: `"TW"`, `"US"`, `"JP"` |
| **scenario** | 紛争/警戒シナリオ(scoring の単位) | `scenario_id: "taiwan_contingency"` |
| **participant** | シナリオを構成する国 | `scenario.participants[country]` |
| **coupling weight** | 国がシナリオに寄与する重み(0.0-1.0) | `participant.weight` |
| **role** | participant の役割ラベル | `"primary_target"`, `"forward_base"`, `"primary_ally"` 等 |
| **adversary** | シナリオの攻撃側国家 | `scenario.adversaries: list[str]` |
| **focused scenario** | アナリストが現在 focus しているシナリオ | API param `?focus=...`, UI で展開中 |
| **background scenario** | 構成済みだが focus されていないシナリオ | C-lite では LLM/global のみで採点 |

### 4.2 廃止用語(以下は使わない)

| 旧用語 | 理由 | 移行先 |
|--------|------|--------|
| **theater** | country と scenario を混同していた | 文脈に応じて `country` または `scenario` |
| **core_theater** | 「最高スコアの国」と誤解されやすい | `focused_scenario`(scenario id) |
| **correlate_targets** | scenario.participants に統合 | `scenario.participants` |
| **strategic_theaters** | 同上 | `scenario.participants` |
| **DEFAULT_PINS** | scenario 化により不要 | scenario プリセット |

### 4.3 採点方針の用語

| 用語 | 意味 |
|------|------|
| **C-lite** | focused scenario のみ全センサー稼働、background は LLM intel + global signal のみで採点 |
| **C-medium** | focused は通常頻度、background も per-country センサーを稼働するが低頻度(30-60min) |
| **C-heavy** | 全 scenario を等速で全センサー稼働(rate limit 観点で非現実的、参考のみ) |

---

## 5. アーキテクチャ決定記録(ADR)

各 ADR は **「決まった瞬間に Open Questions から昇格」** させる。一度決めたら破棄せず、将来覆す場合は Supersedes 関係で新 ADR を追加する。

### ADR-001: シナリオを scoring の単位とする(country ではない)

**Status**: Accepted (2026-04-11)
**Context**: 既存実装は country ごとに TL を計算していた。しかし「TW: TL3」という表示は文脈なしには意味を持たない。「Taiwan Contingency: TL3」という表示こそが警告の単位。
**Decision**: scoring engine の出力単位を country から scenario に変更する。country は signal タグとして残るが、TL や HUD 主表示の単位ではない。
**Consequences**:
- ✅ 警告の意味が明確になる
- ✅ 同じ国が複数 scenario に異なる重みで参加できる
- ✅ cross-country aggregation が自然に実現
- ⚠️ 既存 API のレスポンス形式が変わる
- ⚠️ 既存 DB スキーマの一部に migration が必要

### ADR-002: C-lite で開始し、運用知見をもとに C-medium へ進化

**Status**: Accepted (2026-04-11)
**Context**: 全 scenario を全センサーで採点する C-heavy は API rate limit を超える。一方で、focused のみでは他 scenario の状況が見えない。
**Decision**: 第1段階として C-lite を実装(focused のみ全センサー、background は LLM/global のみ)。運用しながら background の盲点が実用上の問題か判定し、必要なら C-medium へ進化する。
**Consequences**:
- ✅ 追加センサーコストなしで scenario 第一級設計を実現
- ✅ 失敗モードが「見えていないものは見えない」と明確
- ⚠️ background scenario は info 偏重 + 英語報道 bias を持つ
- ⚠️ 物理主体の事象(演習、艦艇移動)を background では検出不能
- ⚠️ background TL と focused TL は厳密には比較不可
**Migration criteria**: 9章「C-medium 移行設計」を参照

### ADR-003: シナリオ構成は動的に編集可能

**Status**: Accepted (2026-04-11)
**Context**: 国際情勢は変化し、シナリオの participants や重みも変化する必要がある(例: 韓国の台湾有事関与度の変化)。
**Decision**: シナリオ定義を3層構造とする:
1. **Layer 1**: 静的デフォルト(`geo_data.json`)
2. **Layer 2**: 永続カスタマイズ(SQLite `scenarios` テーブル)
3. **Layer 3**: セッション override(in-memory)
**Consequences**:
- ✅ 起動時にプリセットが必ず存在
- ✅ アナリストの仮説をデータモデルに反映できる
- ✅ 一時的な検証は永続変更を伴わずに可能
- ⚠️ admin UI と権限モデルが必要(ADR-006 で詳細化)

### ADR-004: country タグ付けは LLM の責務、scenario マッピングは scoring engine の責務

**Status**: Accepted (2026-04-11)
**Context**: LLM intel に country を付けるか scenario を付けるかの選択。
**Decision**: LLM は **country** をタグ付けする(複数可)。scenario への配分は scoring engine が `scenario.participants` を引いて計算する。
**Rationale**:
- LLM が scenario を知らなくて済む(scenario 追加時に過去 intel の再処理不要)
- scenario 定義変更が即座に反映される(LLM 出力に依存しない)
- country タグは scenario タグより安定で再利用性が高い
**Consequences**:
- ✅ scenario 追加・編集が低コスト
- ✅ LLM プロンプトがシンプル
- ⚠️ LLM プロンプトを multi-country 出力に変更する必要(Phase 3)

### ADR-005: focused_scenario が core_theater を置き換える

**Status**: Accepted (2026-04-11)
**Context**: 既存の `core_theater` は「最高スコアの国を選ぶロジック」と「アナリストが宣言した主要対象国」の2つの意味で混在使用されていた。
**Decision**: `core_theater` を廃止し、`focused_scenario` に置き換える。意味は「アナリストが現在フォーカスしているシナリオ ID」。最高スコア検出のロジックは存在しない。
**Consequences**:
- ✅ 概念が明確になる
- ⚠️ API パラメータ `?core=TW` が `?focus=taiwan_contingency` に変わる
- ⚠️ 既存 UI コードの core 参照を全て書き換える

### ADR-006: シナリオ編集の権限モデル

**Status**: Accepted (2026-04-11)
**Decision**: 3層に対応する権限モデル:
- **admin**: グローバル設定(Layer 1, 2)を編集可能
- **analyst**: セッション override(Layer 3)のみ可能
- **viewer**: 編集不可、閲覧のみ
**Consequences**:
- ✅ 既存 JWT 認証の role と整合
- ✅ アナリストは「今だけ KR の重みを上げて見る」ができる
- ⚠️ Layer 2 への変更は admin 承認フローが必要(将来課題)

### ADR-007: signal_source dedup は scenario 内で MAX

**Status**: Accepted (2026-04-11)
**Context**: 既存の WeightedConvergenceEngine は同一 `signal_source`(例: "bgp")を持つ複数センサー(IODA/BGPRouting/IHR)を MAX で dedup している。scenario 単位スコアリングでも同じ原則を維持するか。
**Decision**: scenario 内で同一 signal_source の rationale entry が複数存在する場合、MAX のみを採用する(合算しない)。これは現状の仕様継承。
**Consequences**:
- ✅ 同一情報源の二重計上を防止
- ✅ 既存の dedup ロジックを再利用可能

### ADR-008: background scenario には TL を出さず、indicator のみ表示

**Status**: Accepted (2026-04-11)
**Context**: C-lite の background TL は focused TL と比較不可なので、表示すると誤読リスクが大きい。
**Decision**: 当面、background scenario には TL を出さない。代わりに次のインジケータを表示:
- LLM intel 件数(24h)
- active countries 数
- 直近の signal 種類カウント(cyber/physical/info)
**Consequences**:
- ✅ TL 誤読リスクを排除
- ✅ アナリストは「数値が増えている」を見て focus 切替を判断
- ⚠️ TL 表示がほしいケースは admin 設定で有効化可能とする(将来課題)
- 📝 C-medium 移行時に再評価(C-medium では TL 比較性が回復するため)

---

## 6. データモデル

### 6.1 シナリオ JSON スキーマ

`geo_data.json` の `scenarios` セクションに格納。

```json
{
  "scenarios": {
    "taiwan_contingency": {
      "name_en": "Taiwan Contingency",
      "name_ja": "台湾有事",
      "description_en": "PRC contingency operations against Taiwan",
      "description_ja": "中国による台湾に対する有事対応",
      "core_country": "TW",
      "participants": {
        "TW": { "weight": 1.0, "role": "primary_target" },
        "JP": { "weight": 0.8, "role": "forward_base" },
        "US": { "weight": 0.8, "role": "primary_ally" },
        "PH": { "weight": 0.6, "role": "southern_flank" },
        "KR": { "weight": 0.4, "role": "distraction_risk" },
        "AU": { "weight": 0.4, "role": "aukus_posture" }
      },
      "adversaries": ["CN"],
      "enabled": true,
      "tier": 1
    }
  }
}
```

**フィールド説明**:
| フィールド | 型 | 必須 | 意味 |
|----------|---|------|------|
| `name_en`, `name_ja` | str | ✓ | i18n 表示名 |
| `description_en`, `description_ja` | str | – | 詳細説明(ツールチップ) |
| `core_country` | str | ✓ | シナリオの主要対象国 |
| `participants` | dict | ✓ | 国 → {weight, role} |
| `participants[].weight` | float [0.0-1.0] | ✓ | scoring 寄与重み |
| `participants[].role` | str | ✓ | 表示用役割ラベル |
| `adversaries` | list[str] | – | 攻撃側国家 |
| `enabled` | bool | – | デフォルト true |
| `tier` | int | – | 1=主要、2=副次、3=実験的(UI ソート用) |

### 6.2 SQLite スキーマ

```sql
-- 永続カスタマイズ層 (Layer 2)
CREATE TABLE IF NOT EXISTS scenarios (
    id TEXT PRIMARY KEY,
    name_en TEXT NOT NULL,
    name_ja TEXT NOT NULL,
    description_en TEXT,
    description_ja TEXT,
    core_country TEXT NOT NULL,
    adversaries TEXT NOT NULL DEFAULT '[]',  -- JSON array
    enabled INTEGER NOT NULL DEFAULT 1,
    tier INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS scenario_participants (
    scenario_id TEXT NOT NULL,
    country TEXT NOT NULL,
    weight REAL NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (scenario_id, country),
    FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scenario_change_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL,
    changed_at REAL NOT NULL,
    changed_by TEXT,
    change_type TEXT NOT NULL,  -- 'create' | 'update' | 'delete' | 'reset'
    diff TEXT  -- JSON diff
);
```

### 6.3 LLM intel item スキーマ変更

```python
# 旧 (現状)
{
  "headline": "...",
  "theater": "US",        # ← 単一 str
  "domain": "cyber",
  "confidence": 0.85,
  "source_url": "...",
  ...
}

# 新 (Phase 3 以降)
{
  "headline": "...",
  "countries": ["US", "TW"],   # ← list[str]
  "country_weights": { "US": 1.0, "TW": 0.6 },  # オプション、LLM が weight を返す場合
  "domain": "cyber",
  "confidence": 0.85,
  "source_url": "...",
  "llm_reasoning": "...",      # ← 検証用に追加
  ...
}
```

### 6.4 RationaleEntry 変更

```python
# 旧
@dataclass
class RationaleEntry:
    signal_source: str
    theater: str          # 単一国
    domain: str
    score: float
    sensor: str
    value: str
    suppress_reason: str | None

# 新
@dataclass
class RationaleEntry:
    signal_source: str
    countries: list[str]              # ← 関連国(複数可)
    domain: str
    raw_score: float                  # 元のスコア
    sensor: str
    value: str
    evidence_url: str | None          # ← 原典 URL (P4)
    formula_trace: str                # ← 計算過程 "value × weight × coupling = contribution"
    suppress_reason: str | None

@dataclass
class ScenarioContribution:
    """RationaleEntry が特定 scenario に寄与した結果"""
    rationale: RationaleEntry
    contributing_country: str         # どの participant 経由か
    coupling_weight: float            # その participant の weight
    final_contribution: float         # raw_score * coupling_weight
```

### 6.5 API レスポンス形式

```json
GET /api/threat_data?focus=taiwan_contingency

{
  "focused_scenario": "taiwan_contingency",
  "scenarios": {
    "taiwan_contingency": {
      "id": "taiwan_contingency",
      "name": "Taiwan Contingency",
      "is_focused": true,
      "scoring_mode": "full",
      "tl": 3,
      "score": 5.4,
      "domains": {
        "cyber": 3.2,
        "physical": 1.2,
        "info": 1.0
      },
      "active_countries": ["TW", "US", "JP"],
      "convergence_bonus": 1.0,
      "rationales": [...],
      "data_freshness_sec": 287
    },
    "eastern_europe": {
      "id": "eastern_europe",
      "name": "Eastern Europe",
      "is_focused": false,
      "scoring_mode": "lite",
      "tl": null,
      "score_lite": 4.1,
      "indicators": {
        "llm_intel_24h": 12,
        "active_countries": 4,
        "domain_signal_counts": {
          "cyber": 2,
          "physical": 1,
          "info": 9
        }
      },
      "rationales": [...],
      "data_freshness_sec": 287
    }
  },
  "global_data_freshness_sec": 287
}
```

---

## 7. スコアリングアルゴリズム

### 7.1 シナリオスコア計算(疑似コード)

```python
def compute_scenario_score(
    scenario: Scenario,
    all_signals: list[Signal],
    is_focused: bool,
) -> ScenarioState:
    """
    Compute scenario-level score from country-tagged signals.
    """
    contributions: list[ScenarioContribution] = []
    
    for signal in all_signals:
        for country in signal.countries:
            if country not in scenario.participants:
                continue
            
            participant = scenario.participants[country]
            contribution = ScenarioContribution(
                rationale=signal.rationale,
                contributing_country=country,
                coupling_weight=participant.weight,
                final_contribution=signal.score * participant.weight,
            )
            contributions.append(contribution)
    
    # signal_source MAX dedup (ADR-007)
    deduped = dedup_by_signal_source_max(contributions)
    
    # Domain aggregation
    domains = {"cyber": 0.0, "physical": 0.0, "info": 0.0}
    for c in deduped:
        domains[c.rationale.domain] += c.final_contribution
    
    # Convergence bonus (within scenario)
    active_domains = [d for d, s in domains.items() if s > 0]
    convergence_bonus = compute_convergence_bonus(
        active_domains=active_domains,
        active_countries=set(c.contributing_country for c in deduped),
        physical_score=domains["physical"],
    )
    
    total = sum(domains.values()) + convergence_bonus
    
    # TL judgement (only for focused or C-medium background)
    if is_focused or scenario.scoring_mode == "full":
        tl = derive_tl(total, active_domains)
    else:
        tl = None  # C-lite background: no TL (ADR-008)
    
    return ScenarioState(
        scenario=scenario,
        is_focused=is_focused,
        scoring_mode="full" if is_focused else "lite",
        score=total,
        domains=domains,
        active_countries=list(set(c.contributing_country for c in deduped)),
        convergence_bonus=convergence_bonus,
        tl=tl,
        contributions=deduped,
    )
```

### 7.2 Convergence bonus 計算

```python
def compute_convergence_bonus(
    active_domains: list[str],
    active_countries: set[str],
    physical_score: float,
) -> float:
    """
    既存の WeightedConvergenceEngine の convergence bonus を継承。
    - FULL (3 domains active): +2.0
    - DUAL (2 domains active): +1.0
    - SINGLE: +0.0
    
    シナリオ内に複数 country が active な場合、追加でわずかな boost も検討可能(将来課題)。
    """
    n = len(active_domains)
    if n >= 3:
        return 2.0
    elif n == 2:
        return 1.0
    return 0.0
```

### 7.3 TL 判定式

既存の閾値を継承(調整は別途):

| TL | 条件 |
|----|------|
| **TL1** | score ≥ 9 AND physical degradation present |
| **TL2** | score ≥ 6 AND active domains ≥ 2 |
| **TL3** | score ≥ 4 |
| **TL4** | score ≥ 2 |
| **TL5** | score < 2 |

---

## 8. C-lite 実装仕様

### 8.1 動作概要

```
[fetch サイクル]
  global sensors        ─┐
                         ├─→ 共通プール (全 scenario が参照)
  LLM intel sensors     ─┘
  
  per-country sensors  ───→ focused.participants の国だけ fetch

[scoring サイクル]
  for each configured scenario:
      collect signals where signal.countries ∩ scenario.participants
      compute_scenario_score(scenario, signals, is_focused=...)
```

### 8.2 センサー分類(C-lite で background が見るもの)

| 群 | センサー | background で利用可能か |
|---|---|:---:|
| **A: グローバル取得型** | GreyNoise, ThreatFox, CT log, Tor metrics, USGS seismic, NASA FIRMS, GDELT global, IHR, RSS narrative, Telegram mirror, GPS jamming, space weather, hacktivist_intel, ground_osint, diplomatic, military_exercise, apt_intel, hacktivist_news_sensor | ✅ |
| **B: Per-country クエリ型** | Cloudflare Radar per-country, IODA, BGP routing per-country, OpenWeather, CheckHost, OpenSky per-airport, NOTAM per-FIR, RIPE Atlas | ❌(focused のみ) |
| **C: 領域指定型** | AIS チョークポイント, ISR hotspot, NASA FIRMS bbox | ❌(focused のみ) |

### 8.3 background scenario の出力

ADR-008 に従い、background scenario には TL を出さず、以下のインジケータを返す:

```json
{
  "scoring_mode": "lite",
  "tl": null,
  "score_lite": 4.1,        // 参考値、TL に変換しない
  "indicators": {
    "llm_intel_24h": 12,
    "active_countries": 4,
    "domain_signal_counts": {"cyber": 2, "physical": 1, "info": 9}
  }
}
```

### 8.4 既知の bias と HUD 表示要件

| Bias | 影響 | HUD 対応 |
|------|------|---------|
| **LLM/英語報道偏重** | 英語報道が多い地域(中東、ウクライナ)が過大評価 | カードに「LITE」バッジ + ツールチップで明示 |
| **Info domain 偏重** | per-country physical/cyber データが欠落 | indicator に domain breakdown を表示 |
| **物理事象の盲点** | 演習、艦艇移動、兵站などが LLM に出るまで見えない | 「物理シグナルなし」を明示しない(沈黙ではない) |

### 8.5 失敗モード

| 失敗 | 検出方法 | 対処 |
|------|---------|------|
| **物理 buildup の見逃し** | 後追い検証(focused 切替後の発覚) | 移行判定の入力(C-medium へ) |
| **LLM bias による誤誘導** | 重要事象の見逃し率の追跡 | LLM プロンプトの多言語化 |
| **focused 切替の遅延** | アナリストフィードバック | 切替時の即時 fetch を最適化 |

---

## 9. C-medium 移行設計

### 9.1 C-medium とは何か

**変更点(C-lite からの差分)**:
- background scenario も per-country センサーを fetch する
- ただし fetch 頻度は低い(focused 5min / background 30-60min)
- 一部の重い B 群センサーは除外可能(per-sensor toggle)

**変更しない点**:
- データモデル(SQL スキーマ、LLM intel item 形式)は完全に同じ
- scoring engine ロジックは同じ(`is_focused` フラグの扱いが変わるだけ)
- API レスポンス形式は同じ(`scoring_mode: "lite"` → `"medium"` または `"full"`)
- HUD は同じ(TL 表示の有無が ADR-008 の再評価次第)

つまり **C-medium 移行はアーキテクチャ変更ではなく、polling 層の拡張のみ**。

### 9.2 C-medium 実装の概要

#### (a) センサー tier 属性の追加

各センサークラスに tier 属性を追加:

```python
class BaseSensor:
    name: str
    tier: SensorTier  # NEW
    
class SensorTier(Enum):
    GLOBAL = "global"              # 全 scenario が共有、country 引数なし
    FOCUSED_ONLY = "focused_only"  # focused.participants の国のみ fetch
    BACKGROUND_ELIGIBLE = "background_eligible"  # focused + background 両方
```

C-lite 時点では:
- すべての A 群センサー → `GLOBAL`
- すべての B 群、C 群センサー → `FOCUSED_ONLY`

C-medium 移行時:
- 一部の B 群センサーを `BACKGROUND_ELIGIBLE` に昇格
- 例: BGP routing(rate limit に余裕がある場合)

#### (b) Polling scheduler の拡張

```python
class TieredScheduler:
    def get_fetch_targets(self, sensor: BaseSensor) -> list[str]:
        if sensor.tier == SensorTier.GLOBAL:
            return []  # no country needed
        
        if sensor.tier == SensorTier.FOCUSED_ONLY:
            return list(self.focused_scenario.participants.keys())
        
        if sensor.tier == SensorTier.BACKGROUND_ELIGIBLE:
            focused_set = set(self.focused_scenario.participants.keys())
            background_set = set()
            for s in self.background_scenarios:
                background_set |= set(s.participants.keys())
            
            if self.is_focused_cycle():
                return list(focused_set)
            else:
                return list(background_set - focused_set)
    
    def is_focused_cycle(self) -> bool:
        """focused は 5min ごと、background は 30-60min ごと"""
        return (time.time() - self.last_background_fetch) < self.background_interval
```

#### (c) Per-sensor rate limit budget

各センサーに日次/時間単位のクォータを定義:

```python
class BaseSensor:
    daily_quota: int | None  # None = 無制限
    quota_used_today: int = 0
    quota_reset_at: float = 0
    
    def can_fetch(self, n_targets: int) -> bool:
        if self.daily_quota is None:
            return True
        return self.quota_used_today + n_targets <= self.daily_quota
```

スケジューラは focused を優先的に処理し、quota が枯渇したら background をスキップ:

```python
def schedule_fetch(self, sensor):
    focused_targets = self.get_focused_targets(sensor)
    if sensor.can_fetch(len(focused_targets)):
        self.fetch(sensor, focused_targets)
    
    if self.is_background_cycle(sensor):
        bg_targets = self.get_background_targets(sensor)
        if sensor.can_fetch(len(bg_targets)):
            self.fetch(sensor, bg_targets)
        else:
            log.warning(f"[C-medium] {sensor.name} skipping background: quota exhausted")
```

#### (d) Cache 鮮度の表示

各センサーキャッシュに `(country, last_fetched_at)` を持たせ、API レスポンスで scenario ごとに最古値を返す:

```python
"data_freshness_per_country": {
    "TW": 287,    # 5分前
    "JP": 287,
    "US": 287,
    "UA": 1842,   # 30分前 (background fetched)
}
```

HUD はこれを使って「データが古い国」を視覚的に示す。

### 9.3 C-medium 移行判定基準

以下の **いずれか** が成立したら C-medium への移行を検討する:

| 種類 | 基準 | 計測方法 |
|------|------|---------|
| **定量(検出力)** | background の見逃しが4週間で3件以上 | 後追い検証ログ |
| **定量(運用)** | focus 切替が平均 5回/日以上 | アナリスト操作ログ |
| **定量(余力)** | 主要センサーの quota 利用率が60%未満 | sensor stats |
| **定性(フィードバック)** | アナリストが「他のシナリオの状況も常時見たい」と要望 | 直接ヒアリング |

逆に、以下の場合は C-lite を継続:

- 主要センサー(Cloudflare Radar, OpenSky, OpenWeather)の quota が80%以上利用済み
- 単独アナリスト運用で focus 切替が低頻度
- background TL が必要な状況が実際には発生しない

### 9.4 段階移行の手順

C-lite → C-medium は **一度に全センサーを切り替えない**。順次拡張する。

#### Step 1: 軽量センサーから開始
最初に `BACKGROUND_ELIGIBLE` に昇格すべきセンサー(rate limit 余裕がある):
- BGP routing(RIPE Stat) — 公共 API、緩い制限
- IODA — 公共 API
- Tor metrics — global、国別不要だが既に使用

#### Step 2: 中量センサー
- CheckHost — レート緩い
- Cloudflare Radar — 有料/auth key 前提

#### Step 3: 重量センサー
- OpenSky — quota 厳しい、注意深く
- OpenWeather — quota 厳しい

#### Step 4: 領域型センサー
- AIS、ISR、NASA FIRMS — bbox の組み合わせを最小化

各 step は **2週間の運用観察期間** を置き、quota と検出力の変化を確認してから次へ。

### 9.5 C-medium ロールバック戦略

C-medium 移行後に問題が発生した場合の戻し方:

| 問題 | 対処 |
|------|------|
| 特定センサーの rate limit 枯渇 | そのセンサーのみ `FOCUSED_ONLY` に戻す(per-sensor toggle) |
| 全体的な遅延 | background interval を 30min → 60min に延長 |
| 運用上の混乱 | `C_MEDIUM_ENABLED=false` で全 background を停止し C-lite に戻す |

ロールバックは **1コミット内で完了** すべき。

### 9.6 C-medium 移行時の ADR 再評価

以下の ADR は C-medium 移行時に再評価が必要:

- **ADR-008**: background TL を表示するか
  - C-medium では TL の比較性が回復するため、表示を有効化する選択肢が現実的になる
  - admin 設定で切替可能にすることを検討
- **ADR-002**: C-lite 採用の妥当性
  - C-medium が安定運用できれば「C-lite で開始」の前提は満たされた

---

## 10. 実装フェーズ

各フェーズは **完了条件を満たさなければ次に進まない**。Phase 完了時にこのドキュメントの「Phase 進行表」を更新する。

### Phase 1: シナリオデータモデルと用語整理(~3-4日)

**スコープ**:
- `geo_data.json` にプリセットシナリオ4件を追加(taiwan_contingency, eastern_europe, middle_east, korean_peninsula)
- SQLite に scenarios テーブル + scenario_participants テーブル + scenario_change_log テーブルを追加
- migration スクリプト(既存 DB に新テーブルを足すだけ、データ消失なし)
- コード上の用語整理: `theater` → `country` / `scenario` の置換(段階的、一気にやらない)
- `radar/scenarios.py` モジュール新設(scenario CRUD と loader)
- `CLAUDE.md` 用語セクションの追加(本ドキュメントと併存)

**完了条件**:
- ✅ プリセット4シナリオが起動時にロードされ、`/api/scenarios` で取得できる
- ✅ SQLite migration が既存 DB を破損させずに実行される
- ✅ 既存の `/api/threat_data` は引き続き動作(後方互換維持)
- ✅ test_engine.py の既存テストが全てパス
- ✅ `radar/scenarios.py` に対する単体テストが追加されている

**依存**: なし

**リスク**:
- 既存コードの `theater` 参照が膨大で、段階的置換が進まない
- → 対策: Phase 1 では用語置換は最小限(scenario モジュールの追加のみ)、置換は Phase 2-4 で順次

### Phase 2: シナリオスコアリングエンジン(~3日)

**スコープ**:
- `radar/scoring.py` に `compute_scenario_score()` を追加
- `WeightedConvergenceEngine` を per-scenario 対応に
- `radar/routes/core.py` に scenario 単位の scoring loop を追加
- API `/api/threat_data` に scenario 形式のレスポンスを追加(旧形式と並行)
- `?focus=...` パラメータの追加

**完了条件**:
- ✅ `/api/threat_data?focus=taiwan_contingency` がシナリオ単位 TL を返す
- ✅ background scenario には TL を出さず、indicators を返す
- ✅ 既存 API レスポンスとの後方互換が維持されている(deprecated フラグ付き)
- ✅ scoring 結果の rationale が evidence_url と formula_trace を含む
- ✅ 単体テスト: 4シナリオ × 各種シグナルパターンで期待値検証

**依存**: Phase 1

### Phase 3: LLM プロンプトと intel queue の country 化(~3日)

**スコープ**:
- 6種類の LLM intel sensor のプロンプトを multi-country 出力に変更
  - apt_intel, ground_osint, military_exercise, hacktivist_intel, hacktivist_news_sensor, diplomatic
- `intel_queue.submit()` の引数を `theater: str` → `countries: list[str]` に
- `RationaleEntry` を `countries: list[str]` 化
- LLM intel の dedup ロジックを multi-country 対応に(Jaccard 類似度 + countries の集合演算)
- DB スキーマ migration: 既存 LLM intel item の `theater` カラムを `countries` (JSON) に変換

**完了条件**:
- ✅ LLM が `["US", "TW"]` のような multi-country タグを返す
- ✅ 既存 LLM intel item の migration 後も読み込み可能
- ✅ scenario filter が集合演算で動作(`country in scenario.participants`)
- ✅ 「Iranian APT exploit US PLCs」が TW シナリオの rationale に出現することを確認(統合テスト)

**依存**: Phase 2

**リスク**:
- LLM プロンプト変更で出力品質が劣化
- → 対策: 1センサーずつ段階的に変更、各々で 2-3日の観察期間

### Phase 4: HUD のシナリオ単位再設計(~3-4日)

**スコープ**:
- `radar.js` の HUD レンダリングを scenario カード単位に
- focused scenario のフル詳細表示
- background scenario カード(LITE バッジ + indicators)
- scenario 切替 UI(クリックで focus 変更)
- Scenario Manager 管理画面(admin パネル内)
  - シナリオ一覧、編集、新規作成、削除、reset
  - participants の追加/削除/重み調整
- `i18n.js` に scenario 関連の翻訳キー追加(EN/JA)
- `index.html` Help Guide Ch.8 (Intuition UI), Ch.9 (API Reference), Ch.10 (Admin) の更新

**完了条件**:
- ✅ HUD に focused scenario の詳細とその他 scenario カードが並列表示される
- ✅ クリックで focus 切替が可能(切替時にデータ再 fetch)
- ✅ admin が新規シナリオを作成・編集・削除できる
- ✅ analyst がセッション override(Layer 3)で重みを一時変更できる
- ✅ EN/JA すべて翻訳済み、ハードコード文字列なし
- ✅ Help Guide が新 UI と整合

**依存**: Phase 2, Phase 3

### Phase 5: 検証 UX と bias インジケータ(~2-3日)

**スコープ**:
- rationale entry のクリック展開 UX
  - source, sensor, raw value, weight, formula trace, evidence URL の表示
  - LLM 由来の場合は LLM reasoning も表示
- background scenario の bias 警告表示
  - 「LITE 採点: LLM intel + global signal のみ」を明示
  - domain breakdown(cyber/physical/info の signal 件数)
- "what-if" 機能(rationale を一時的に除外したらスコアがどうなるか)
- evidence URL のクリックで原典 fetch(任意)

**完了条件**:
- ✅ すべての rationale entry が原典に追跡可能
- ✅ background scenario の表示に LITE バッジが必ずある
- ✅ what-if が動作する
- ✅ Help Guide に「rationale の検証方法」の章が追加されている

**依存**: Phase 4

---

## 11. 未決事項(Open Questions)

決定したら ADR に昇格し、このセクションから削除する。

### Q1: 初期プリセットシナリオの core_country 確認

**現状の提案**:
- Taiwan Contingency → core: TW
- Eastern Europe → core: UA
- Middle East → core: IL(または IR? どちらの視点で見るか)
- Korean Peninsula → core: KR

**論点**: 中東の core を IL とするか IR とするか。視点によって参加国の重み配分が変わる。

**期限**: Phase 1 着手前

### Q2: 各シナリオの初期 participants と weight

**現状の提案**(本ドキュメント 6.1 節の例):
- TW(1.0), JP(0.8), US(0.8), PH(0.6), KR(0.4), AU(0.4) etc.

**論点**: 重みの絶対値は校正前の推測値。運用しながら調整する前提。

**期限**: Phase 1 着手前(初期値の妥当性のみ)

### Q3: scenario_id の命名規則

**候補**:
- snake_case: `taiwan_contingency`
- kebab-case: `taiwan-contingency`
- 短縮: `tw_contingency`

**推奨**: snake_case + 完全名(可読性優先)

**期限**: Phase 1 着手時

### Q4: 既存 country-level 出力を残すか

**論点**: Phase 2 で API を scenario 化したあと、country-level の出力を完全廃止するか、drill-down 用に保持するか。

**推奨**: drill-down 用に内部保持し、HUD には出さない

**期限**: Phase 2 設計時

### Q5: scenario 削除時の挙動

**論点**: シナリオを削除すると過去の rationale や履歴データはどうなるか。

**選択肢**:
- (a) シナリオ削除 = 関連データも削除
- (b) シナリオは disabled にするのみ、データは残す
- (c) シナリオ ID は予約語化、再利用不可

**推奨**: (b) — 情報損失を避ける

**期限**: Phase 1 設計時

### Q6: シナリオ間の coupling(将来課題)

**論点**: 「東欧の激化が中東のイラン関与にも波及」のような cross-scenario 関係を表現するか。

**現状**: 範囲外(Phase 5 完了後の将来課題)

**期限**: 未定

---

## 12. 範囲外(Out of Scope)

このリファクタリングで **意図的に実装しない** もの。要望が出ても断る根拠。

| 項目 | 理由 |
|------|------|
| **シナリオ自動検出** | P5 違反(ツールは判断しない) |
| **scenario auto-suggestion** | P5 違反 |
| **未来予測(forecasting)** | P5 違反、また OSINT のみでは精度確保困難 |
| **自律行動(自動ブロック等)** | P5 違反 |
| **scenario 間の coupling**(cross-scenario 相関) | Phase 5 完了後の将来課題 |
| **ML ベースのスコアリング** | P3 違反(透明性欠如) |
| **商用 threat intel 統合** | 拘束① 違反(OSINT 限定) |
| **scenario テンプレートマーケットプレイス** | スコープ過大 |

---

## 13. リスク登録簿

| ID | リスク | 影響 | 確率 | 対策 |
|----|-------|------|------|------|
| **R1** | LLM プロンプト変更で intel 品質劣化 | 検出力低下 | 中 | 1センサーずつ段階的変更、観察期間 |
| **R2** | DB migration の失敗 | データ消失 | 低 | dry-run, バックアップ必須, ロールバック手順 |
| **R3** | rate limit 計算ミス(Phase 1 で誤って quota 超過) | センサー停止 | 低 | C-lite では既存 quota と同等、影響小 |
| **R4** | 用語置換が中途半端で混乱 | コード品質低下 | 中 | Phase 1 では最小限、置換は段階的 |
| **R5** | アナリストが新 HUD に適応できない | 採用失敗 | 中 | Help Guide 更新 + 旧 view を deprecated として残す |
| **R6** | scenario 設定の動的変更で history が壊れる | 過去データの解釈不能 | 中 | scenario_change_log で変更履歴を保持 |
| **R7** | C-lite の bias でアナリストが他シナリオを過小評価 | 重要事象の見逃し | 高 | LITE バッジを目立たせる、Help Guide で注意喚起 |
| **R8** | 後方互換 API のメンテ負荷 | 開発速度低下 | 中 | Phase 5 完了から3ヶ月後に旧 API を削除 |

---

## 14. ドキュメント運用ルール

このドキュメントを腐らせないために、以下のルールを **厳守** する。

### ルール 1: Phase 完了時に必ず更新
Phase 完了コミットには **必ず** このドキュメントの「Phase 進行表」と各 Phase の完了条件チェックリストを更新する。完了条件が満たされていない Phase は完了とみなさない。

### ルール 2: 設計から外れる変更には ADR を追加
実装中に「設計と違うやり方が良い」と気づいた場合、コードを変える前に **ADR を追加** して理由を記録する。事後ではなく事前に。
ADR の番号は連番(ADR-009, ADR-010, ...)。

### ルール 3: Open Question は決まったら ADR に昇格
Q1〜Q6 等は決定された瞬間に Open Questions セクションから削除し、ADR として永続化する。

### ルール 4: 用語定義はコードと同期
変数名・関数名・SQL カラム名が用語定義と食い違ったら **コード側を直す**(ドキュメントを変えるのではない)。

### ルール 5: ADR を覆すときは Supersedes 関係を明示
将来 ADR を覆す場合、新 ADR の冒頭に `Supersedes: ADR-xxx` と書き、旧 ADR の冒頭に `Superseded by: ADR-yyy` と追記する。削除はしない。

### ルール 6: このドキュメントは1ファイルで完結する
分割しない。検索性と一覧性を優先する。1500 行を超えそうになったら章構成を見直す。

---

## 15. セッション開始チェックリスト

**新しいセッションで Claude が最初にやること**:

1. このドキュメント(`docs/design/scenario-refactor.md`)を読む
2. Phase 進行表で現在の Phase を確認
3. Open Questions を確認(未決事項があればユーザーに確認)
4. 直前の commit log(`git log -10 --oneline`)を確認
5. 該当 Phase の完了条件を再確認
6. 必要なら関連ファイル(`CLAUDE.md`, `geo_data.json`, `radar/scenarios.py` 等)を読む

**ユーザーが Claude に指示する際の推奨書式**:
> 「scenario-refactor の Phase 2 を進めて」
> 「設計ドキュメントの ADR-005 を再評価したい」
> 「Open Question Q1 について決めたい」

---

## Appendix A: 既存実装からの差分マッピング

| 既存ファイル | 既存の概念 | 新しい概念 | 変更時期 |
|------------|----------|----------|---------|
| `radar/config.py` | `DEFAULT_CORE = "TW"` | `DEFAULT_FOCUSED_SCENARIO = "taiwan_contingency"` | Phase 1 |
| `radar/config.py` | `DEFAULT_CORRELATES` | scenario.participants | Phase 1 |
| `radar/config.py` | `DEFAULT_PINS` | scenario プリセット | Phase 1 |
| `radar/routes/core.py` | `core_theater` 変数 | `focused_scenario` | Phase 2 |
| `radar/routes/core.py` | `correlate_targets` | `scenario.participants.keys()` | Phase 2 |
| `radar/routes/core.py` | per-country scoring loop | scenario scoring loop | Phase 2 |
| `radar/intel_queue.py` | `theater: str` | `countries: list[str]` | Phase 3 |
| `radar/sensors/apt_intel.py` 他 LLM | `theater = data.get("theater")` | `countries = data.get("countries", [])` | Phase 3 |
| `radar.js` | `core_theater` UI | `focused_scenario` UI | Phase 4 |
| `radar.js` | `domains` 単一 dict | scenario カード並列表示 | Phase 4 |
| `index.html` Ch.8 | core_theater 説明 | scenario 説明 | Phase 4 |
| `i18n.js` | "Primary Theater" | "Focused Scenario" | Phase 4 |

---

## Appendix B: 用語の英訳と命名規則

| 日本語 | 英語 | コード上の表現 |
|--------|------|--------------|
| シナリオ | scenario | `scenario`, `scenario_id` |
| フォーカス中シナリオ | focused scenario | `focused_scenario` |
| 背景シナリオ | background scenario | `background_scenario`, `is_background` |
| 参加国 | participant | `participant`, `participants` |
| 結合重み | coupling weight | `weight`, `coupling_weight` |
| 役割 | role | `role` |
| 主要対象 | primary target | role 値: `"primary_target"` |
| 前線基地 | forward base | role 値: `"forward_base"` |
| 主要同盟国 | primary ally | role 値: `"primary_ally"` |
| 攻撃側 | adversary | `adversaries` |

**命名規則**:
- scenario_id: snake_case, lowercase, ASCII (`taiwan_contingency`)
- country code: ISO 3166-1 alpha-2, uppercase (`TW`, `JP`)
- role: snake_case, lowercase (`primary_target`)
- API パラメータ: snake_case (`?focus=taiwan_contingency`)
- DB テーブル: snake_case 複数形 (`scenarios`, `scenario_participants`)

---

## 改訂履歴

| 日付 | バージョン | 変更内容 | 担当 |
|------|----------|---------|------|
| 2026-04-11 | 1.0.0 | 初版作成。Phase 0 完了。 | Claude (Opus 4.6) + kamonegi13 |

---

**END OF DOCUMENT**
