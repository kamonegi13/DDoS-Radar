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
| **現バージョン** | 1.8.0 |
| **作成日** | 2026-04-11 |
| **最終更新** | 2026-04-25 |
| **現在のフェーズ** | **Phase 5 実装完了（TL 閾値再校正は 2026-04-28 期限、ADR-015 dual-weight 評価は 2026-05-12 期限）** |
| **採用方針** | **C-lite** で開始、運用知見をもとに **C-medium** へ進化 |
| **責任者** | kamonegi13(@juzo1192) |
| **想定総工数** | 約 22-28 日(Phase 1〜5、v1.2 で現実化)|

### Phase 進行表

| Phase | 概要 | 状態 | 完了日 |
|-------|------|------|--------|
| **Phase 0** | 設計確定、ドキュメント整備 | **完了** | 2026-04-12 |
| **Phase 1** | シナリオデータモデルと用語整理 | **完了** | 2026-04-12 |
| **Phase 2** | シナリオスコアリングエンジン | **完了** | 2026-04-12 |
| **Phase 3** | LLM プロンプトと intel queue の country 化 | **完了** | 2026-04-13 |
| **Phase 4** | HUD のシナリオ単位再設計 | **完了** | 2026-04-13 |
| **Phase 5** | 検証 UX と bias インジケータ | **実装完了（TL 再校正と dual-weight 評価は運用データ蓄積待ち）** | 2026-04-14 |
| **(将来)** | C-medium への移行 | 条件待ち | — |

---

## 1. ツールの定義(ユーザー定義文)

> **特定の警戒シナリオにおける国家間エスカレーションと開戦兆候を検知することを目的に、フリーかつオープンの情報ソースを統合し、専門アナリストに対し、現時点で技術的に実行可能な最大の評価結論(全体脅威レベル、トレンド、ドメイン別兆候、個別異常事象、推定攻撃シナリオ)を、その導出に用いた式・閾値・一次ソースと併せて出力するツール。**
>
> **本ツールは、組織的なインテリジェンス判断プロセスにおける一つのノードとして機能することを前提とする。最終的な状況判断は、本ツールの出力を含む複数の情報源を統合した、組織のプロセスによって行われる。本ツールの責任範囲は、(1) 透明な計算過程に基づく結論の導出、(2) すべての結論の根拠に至る検証経路の提示、(3) データまたは calibration の不足により結論を出せない状態(結論不可)の明示、に限定される。**
>
> **結論不可状態は過渡的なものとして許容されるが、データ蓄積後も恒常的に結論不可が継続する状態は本ツールの設計失敗として扱う。**
>
> **本ツールは OSINT のみという制約下での最良努力であり、HUMINT・SIGINT 等を持つ機関と同等の検知能力を主張するものではない。検知漏れの可能性は構造的に存在する。**

この 4 文がツールのすべての設計判断の起点。**いかなる変更もこの定義に整合しなければならない**。

### 定義から導かれる本質
- **観察対象は特定の警戒シナリオ**(国ではない、また網羅的世界監視でもない)
- **出力は「現時点で技術的に実行可能な最大の結論」**(advisory に留めず、結論を出す)
- **アナリストは結論を活用して組織判断を下す主体**(ツールは結論ノードとしてその判断を支援)
- **計算過程・閾値・一次ソース・LLM プロンプトまで完全に追跡可能**
- **結論不可は過渡的に許容されるが、恒常化は設計失敗**(NP5+8)
- **OSINT 限界を明示**(検知漏れの構造的存在を認める)

---

## 2. 設計拘束(4つ)

定義文から導かれる、絶対に犯してはならない拘束。これらは下位の **設計原則 NP1〜NP7**(3 章)へ昇華され、実装層を制約する。

| # | 拘束 | 意味 | 違反例 |
|---|------|------|--------|
| **①** | **OSINT 限定** | 有償・機密ソースは使わない | 商用 threat intel feed の組み込み |
| **②** | **特定の警戒シナリオにおける** | 分析の単位は scenario(国ではない、また全世界網羅でもない) | 国単位の TL を主出力にする / 未登録 scenario の自動拡張 |
| **③** | **技術的に実行可能な最大の結論を出力** | 1つの数値で「いま何点か」を出し、トレンド・ドメイン別兆候・推定シナリオまで結論として返す | ML 出力の確率分布を主表示にする / 結論を advisory に格下げする |
| **④** | **完全な導出開示** | あらゆる寄与点が式・閾値・一次ソース・LLM プロンプトに追跡できる | ブラックボックス aggregation / プロンプトを sensor コードに埋め込んで履歴に残さない |

> **拘束 → NP マッピング**: 拘束① → NP1/NP5+8(感度と OSINT 限界の正直な校正)、拘束② → NP1/NP4(対象シナリオに対し最大結論)、拘束③ → NP4(結論最大化)、拘束④ → NP6(全面開示)。NP7(組織内ノード)は 4 拘束すべての帰結として、結論を「最終判断ではない」位置付けに据える。

---

## 3. 設計原則(NP1〜NP7)

設計拘束を実装に翻訳した、コードレベルの判断基準。**旧 P1〜P5 は本章末のマッピング表で旧呼称→新呼称を保持** する(過去 ADR 文中の `P3` 等の参照が意味を失わないように)。

### 3.0 優先度ピラミッド

原則間が衝突した場合は上位が下位を制約する。

```
        NP1 (感度優先)               ← 最上位: 見逃しの忌避
            │
        NP4 (結論最大化)             ← 結論を出す姿勢
            │
        NP6 (全面開示)               ← 結論の正当化方法
            │
       NP5+8 (結論品質規律)          ← 結論不可の扱いと calibration
            │
        NP7 (組織内ノード)           ← 出力の位置付け
            │
   NP2 (多ソース収斂) / NP3 (障害耐性)  ← 実装層の手段
```

### NP1: 感度優先(sensitivity-first)
**根拠**: ツール定義「検知することを目的に」+ 拘束②(対象範囲は限定するが、その範囲内での見逃しは許容しない)
**意味**:
- recall を precision より優先する。誤検知は分析プロセスで除外できるが、見逃しは取り戻せない
- 閾値設定は迷ったら下げる(より多く拾う)
- 境界事例(borderline signal)はデフォルトで採用、analyst が reject 可能にする
- 感度低下を伴う最適化(LLM コスト削減、quota 節約)は NP4 / NP6 と独立に評価し、NP1 を最優先で守る

### NP4: 結論最大化(maximum-conclusion)
**根拠**: ツール定義「現時点で技術的に実行可能な最大の評価結論」
**意味**:
- 「データから言えること」を最大限に言う。結論を advisory に後退させない
- 出力対象: 全体脅威レベル(TL)、トレンド、ドメイン別兆候、個別異常事象、推定攻撃シナリオ
- 「LLM が判断したから」「自動 calibration が動いたから」を理由に結論を弱めない(代わりに NP6 で完全開示する)
- 旧 P5「ツールは判断しない」は **完全廃止**。本ツールは判断・予測・自律的アクションを行う

### NP6: 完全な導出開示(full-disclosure)
**根拠**: ツール定義「導出に用いた式・閾値・一次ソースと併せて出力」+ 拘束④
**意味**:
- 各 rationale entry は次を持つ:
  - sensor 名 + 観測タイムスタンプ
  - 生の観測値
  - LLM 由来の場合: 原典 URL + LLM の reasoning + confidence + **使用したプロンプトのバージョンタグ**
  - 計算過程: `value × llm_weight × participant_weight = contribution`
- 「これを除外したら TL がどうなるか」の what-if が UI から可能
- スコア式は展開可能な積和式(→ 正規定義: 7.1 節)。ブラックボックス ML や隠れたヒューリスティックは禁止
- HOD baseline 等の統計的処理は許可だが、式と入力値は表示可能でなければならない
- **NP4 で結論を出す力を獲得した代償として、NP6 は妥協不可**

### NP5+8: 結論品質規律(conclusion-quality discipline)
**根拠**: ツール定義「データ・calibration 不足による結論不可の明示」+「恒常的結論不可は設計失敗」
**意味**(2 つの責務を統合):
1. **(a) Calibration 継続評価**: 各結論には calibration 状態(sample_n、最終 calibration 時刻、信頼区間)を付記する。calibration 不足の結論は「結論不可」状態として返す
2. **(b) 過渡的結論不可は許容、恒常的結論不可は設計失敗**: データ蓄積後も `INSUFFICIENT_DATA` が継続するエンドポイントは構造欠陥として扱い、ADR を起こして根治する(例: ADR-025 shadow_sampler が解決した focus_switch_log の構造的欠陥)

### NP7: 組織内ノード(organizational-node)
**根拠**: ツール定義「組織的なインテリジェンス判断プロセスにおける一つのノード」
**意味**:
- 出力には常時「最終判断ではない」を含める(API レスポンス、HUD バナー、通知)
- シナリオ登録判断はアナリスト組織側が行う(ツール側で auto-suggestion を出さない理由は NP7、旧 P5 ではない)
- 自律行動(自動ブロック、自動通報)は NP7 違反: ツールは判断ノードであり、実行ノードではない
- 通知は「人間の注意を引く」ためであり、「組織判断を肩代わりする」ためではない

### NP2: 多ソース収斂(implementation layer)
**根拠**: 単一ソース依存は OSINT のノイズ特性と衝突するため、結論強度を担保するための実装手段
**意味**:
- 単一センサー単独で TL を引き上げない設計(convergence_bonus、domain_signal_counts)
- 複数ドメイン(cyber/physical/info)横断の収斂を加算的にスコアに反映する(DUAL +1.0 / FULL +2.0)
- これは NP1(感度) と NP6(透明性) を実装で達成するための手段であり、原則間の優先度では下位

### NP3: 障害耐性(implementation layer)
**根拠**: センサー個別障害は OSINT 環境の常態。全体停止は NP1(感度) を直接損なう
**意味**:
- センサーごとのサーキットブレーカー、degraded モード、self-healing
- 上流障害時は `failure_modes` で観察可能にし(NP6)、結論を出せる範囲では出し続ける
- NP2 と並ぶ実装層の手段

---

### 旧 P1〜P5 と NP1〜NP7 の対応(履歴保全)

過去 ADR 文中の `P1`〜`P5` 参照は、以下の対応で読み替える。**旧呼称は新規ドキュメントでは使わない**。

| 旧 | 旧の意味 | 新 | 備考 |
|----|--------|-----|------|
| P1 | シナリオは第一級の出力単位 | (拘束② に格下げ、NP4 が結論単位を規定) | scenario 単位は手段ではなく分析対象そのもの |
| P2 | cross-country シグナルの自動集約 | NP2(多ソース収斂)+ NP1(見逃し回避) | 実装手段として位置付けを明確化 |
| P3 | スコア合成式の透明性 | **NP6(全面開示)** | 完全互換 |
| P4 | rationale の原典追跡可能性 | **NP6(全面開示)** | P3 と統合 |
| P5 | ツールは判断を支援する、判断しない | **完全廃止** | NP4(結論最大化)+ NP7(組織内ノード)が責務を分担 |

### 旧 ADR-025 の再定式化(本章での要約、実体は ADR-025 章)

旧 ADR-025 は「観察可能性 > 自動化」を掲げていたが、本版で **「自動化は許容、観察可能性は不可欠」** に再定式化。NP4(結論最大化)が自動化を要請し、NP6(全面開示)が観察可能性を不可侵とする。両者は対立しない。

---

## 4. 用語定義

このプロジェクトの用語は **コード、ドキュメント、UI のすべてで統一する**。揺れがあったらコード側を直す。

### 4.1 主要用語

| 用語 | 意味 | コード上の表現 |
|------|------|--------------|
| **country** | 国(データの一次タグ) | ISO2 code: `"TW"`, `"US"`, `"JP"` |
| **scenario** | 紛争/警戒シナリオ(scoring の単位) | `scenario_id: "taiwan_contingency"` |
| **participant** | シナリオを構成する国(味方・敵含む) | `scenario.participants[country]` |
| **participant weight** | 国がシナリオに寄与する重み(0.0-1.0) | `participant.weight` |
| **role** | participant の役割ラベル(enum、4.3節) | `Role.PRIMARY_TARGET` 等 |
| **signal** | sensor が生成する1件の観測データ(countries と domain を持つ) | `Signal` データクラス(6.3節) |
| **llm_country_weight** | LLM が判定したシグナルの各国への関連度(0.0-1.0) | `signal.country_weights[country]` |
| **rationale** | scoring に寄与した個別のシグナル記録 | `RationaleEntry`(6.4節) |
| **contribution** | rationale が特定 scenario に寄与した最終値 | `ScenarioContribution`(6.4節) |
| **focused scenario** | アナリストが現在 focus しているシナリオ | API param `?focus=...` |
| **background scenario** | 構成済みだが focus されていないシナリオ | C-lite では LLM/global のみで採点 |
| **scenario state** | scenario のライフサイクル状態 | `"active"` / `"paused"` / `"archived"` |
| **scoring mode** | scoring 計算時のランタイムモード(scenario 属性ではない) | `"full"` / `"lite"` / `"medium"` |

### 4.2 廃止用語(以下は使わない)

| 旧用語 | 理由 | 移行先 |
|--------|------|--------|
| **theater** | country と scenario を混同していた | 文脈に応じて `country` または `scenario` |
| **core_theater** | 「最高スコアの国」と誤解されやすい | `focused_scenario`(scenario id) |
| **correlate_targets** | scenario.participants に統合 | `scenario.participants` |
| **strategic_theaters** | 同上 | `scenario.participants` |
| **DEFAULT_PINS** | scenario 化により不要 | scenario プリセット |
| **adversaries**(フィールド) | participants の role="adversary" に統合 | `scenario.participants[X].role == Role.ADVERSARY`(ADR-014) |

### 4.3 Role enum(固定値、バリデーション必須)

**ADR-016** に従い、role は有限 enum として定義する。不明な値は Phase 1 の loader で検証エラーとする。

```python
class Role(Enum):
    # 主要当事者
    PRIMARY_TARGET = "primary_target"            # 攻撃対象(非対称紛争)
    PRINCIPAL_BELLIGERENT = "principal_belligerent"  # 主要当事者(対称紛争)
    ADVERSARY = "adversary"                      # 攻撃側(敵対国家)

    # 同盟・支援側
    PRIMARY_ALLY = "primary_ally"                # 主要同盟国
    FORWARD_BASE = "forward_base"                # 前線基地保有国
    SECONDARY_ALLY = "secondary_ally"            # 二次同盟国
    EXTENDED_DETERRENCE = "extended_deterrence"  # 拡張抑止・遠隔同盟
    STRATEGIC_OBSERVER = "strategic_observer"    # 戦略的監視

    # 戦線・プロキシ
    PROXY_FRONT = "proxy_front"                  # プロキシ戦線
    FORCE_PROJECTION = "force_projection"        # 戦力投射拠点
    SECONDARY_PARTY = "secondary_party"          # 副次当事者
    SPILLOVER_RISK = "spillover_risk"            # 波及リスク

    # その他
    REGIONAL_POWER = "regional_power"            # 域内パワー
```

**新規 role 追加時**: ADR として記録し、enum に追加後に使用する。直接文字列で指定することは禁止。

### 4.4 採点方針の用語

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
**Context**: 国際情勢は変化し、シナリオの participants や重みも変化する必要がある。
**Decision**: シナリオ定義を3層構造とする:
1. **Layer 1**: 静的デフォルト(`geo_data.json`)
2. **Layer 2**: 永続カスタマイズ(SQLite `scenarios` テーブル)
3. **Layer 3**: セッション override(in-memory、JWT claim または URL param 経由)
**Consequences**:
- ✅ 起動時にプリセットが必ず存在
- ✅ アナリストの仮説をデータモデルに反映できる
- ✅ 一時的な検証は永続変更を伴わずに可能
- ⚠️ admin UI と権限モデルが必要(ADR-006)
- ⚠️ Layer 3 は stateless。セッション間で保持しない(Phase 4 で再評価可)

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

**Status**: Accepted (2026-04-11) — フロント側の段階的移行を 2026-04-21 に開始
**Context**: 既存の `core_theater` は「最高スコアの国を選ぶロジック」と「アナリストが宣言した主要対象国」の2つの意味で混在使用されていた。
**Decision**: `core_theater` を廃止し、`focused_scenario` に置き換える。意味は「アナリストが現在フォーカスしているシナリオ ID」。
**Consequences**:
- ✅ 概念が明確になる
- ⚠️ API パラメータ `?core=TW` が `?focus=taiwan_contingency` に変わる
- ⚠️ 既存 UI コードの core 参照を全て書き換える

**Implementation note (2026-04-21)**: CHAIN パネルおよびその他 UI 全 15 箇所(minimap renderer / quick toggles / config payload / WS resubscribe / TSM map markers / CIP modal coord label / SITREP P8 / LLM intel filter / heatmap "Core only" gating × 4 / corr-matrix header / classify submit payload)を `resolveChainTargetCountry(strat)` ヘルパー経由に切替済み。`core_theater` は API で引き続き送出されているため、ヘルパー内のフォールバックとして残置。フロント単独の deprecation 移行は完了 — API Sunset (2026-10-01) を待ってヘルパー内フォールバックを除去すれば完全移行となる。

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

### ADR-007: signal_source dedup は (signal_source, contributing_country) 単位で MAX

**Status**: Accepted (2026-04-12, v1.1 で仕様明確化)
**Context**: 既存実装は signal_source(例: "bgp")単位で MAX dedup していた。しかし scenario 単位スコアリングでは、異なる国で観測された同一 signal_source シグナルは独立した事実として扱うべき。
**Decision**: scenario 内の dedup は `(signal_source, contributing_country)` 複合キー単位で MAX。
- 例: `(bgp, TW)` と `(bgp, JP)` は独立して採用される
- 例: `(bgp, TW)` の複数 sensor エントリは TW 内で MAX される
**Consequences**:
- ✅ TW の BGP 異常と JP の BGP 異常が両方採用される
- ✅ IODA/BGPRouting/IHR が同じ TW を観測した場合の二重計上は防止
- ⚠️ 既存 country-level の挙動とは微妙に異なる(既存は signal_source 単位)

### ADR-008: background scenario には TL を出さず、indicator のみ表示

**Status**: Accepted (2026-04-11)
**Context**: C-lite の background TL は focused TL と比較不可なので、表示すると誤読リスクが大きい。
**Decision**: 当面、background scenario には TL を出さない。代わりに次のインジケータを表示:
- LLM intel 件数(24h)
- active countries 数
- 直近の signal 種類カウント(cyber/physical/info)
- 参考値としての `score_lite`(TL には変換しない)
**Consequences**:
- ✅ TL 誤読リスクを排除
- ✅ アナリストは「数値が増えている」を見て focus 切替を判断
- ⚠️ TL 表示がほしいケースは admin 設定で有効化可能とする(将来課題)
- 📝 C-medium 移行時に再評価(C-medium では TL 比較性が回復するため)

### ADR-009: core_country を optional 化、対称紛争用 role を導入

**Status**: Accepted (2026-04-12)
**Context**: Middle East シナリオのように対称的な紛争(IL ⇔ IR)では「主要対象国 1 つ」というモデルが歪む。
**Decision**:
- `core_country` フィールドを **optional** にする(`null` 許容)
- 対称紛争用の role `PRINCIPAL_BELLIGERENT` を導入
- `core_country` は UI 表示(国旗等)のための補助フィールドと位置づけ、scoring には一切関与しない
- 必要に応じて `participants` から `role == PRIMARY_TARGET or PRINCIPAL_BELLIGERENT` を絞り込んで取得する
**Consequences**:
- ✅ 対称紛争を自然に表現できる
- ✅ core_country の意味が明確になる(UI 補助)
- ⚠️ 既存コードの core_country 参照を optional 前提に書き直し必要

**ADR-009 follow-up (2026-04-25, Phase 5 partial)**:
- 現在の core.py 実装は dual-core scenario で primary_ec(spike 最大の belligerent)を core_theater に昇格させ、per-country の `_seq_fire()` 系はその一国のみで発火する
- secondary belligerent の per-country sensor data は `compute_scenario_score()` の Signal pipeline で正しく集計され、scenario score / TL は対称的に扱われる
- ただし sequence event(NARRATIVE_BURST / ISR_SURGE / AIS_DARK_GAP / FIRMS_ANOMALY / SYNC_DDOS / TELEGRAM_INTENT 等)は primary_ec のみで登録される
- API response の `strategic.secondary_ecs` で「sequence log で silent な belligerent」を可視化(NP6)
- 完全な per-country sequence event 対称化は将来の refactor とする(add_rat() / suppression / confidence gating の interaction が大きいため、TDD で段階的に導入予定)

**ADR-009 follow-up: Stage 1 + 2 完了 (2026-04-25)**:
- **Stage 1** (commit `437e86c`): scenario-wide events を両 belligerent に対称登録。pure helper `resolve_seq_fire_targets(core_theater, effective_cores, scenario_wide)` を `radar/scoring.py` に追加し、`_seq_fire(...)` に `scenario_wide: bool` 引数を導入。`NARRATIVE_BURST` (theater-aggregate Z-score) と `SYNC_DDOS` (multi-target ddos) を `scenario_wide=True` に変更
- **Stage 2.1** (commit `31e9f9d`): per-country `FIRMS_ANOMALY` を secondary に対称登録。pure helper `select_secondary_ec_hits(effective_cores, primary_ec, data, country_field)` を `radar/scoring.py` に追加(list-of-dicts 形のセンサーデータに対応)
- **Stage 2.2** (commit `c3d1b51`): dict-keyed センサーデータ 5 種類を per-country 対称登録: `ISR_SURGE`, `AIS_DARK_GAP` (CHOKEPOINTS の country 一致のみ), `NOTAM_SURGE`, `OONI CENSORSHIP_DETECTED`, `MIL_AIR_SURGE`(tanker/transport/awacs surge)。各々 `_<sensor>_active` flag で循環ブレーカ判定を共有
- **Stage 2.3** (commit `761f4e4`): Tor+IHR cross-sensor `CENSORSHIP_DETECTED` を secondary に対称登録。rationale entry が 1-per-sensor のため raw status dict (`tor_country_status`, `ihr_disco`, `ihr_country_status`) を per-secondary 直接参照
- ADR-009 follow-up は Stage 2.3 をもって完了。dual-core scenario における sequence event 登録は scenario-wide / per-country 両系統で対称になった
- 設計判断: per-country 系では「データ存在ベース」(各 secondary の sensor cache に該当国の hit が存在する場合のみ発火)を採用。NP6(透明性 / honest provenance)を NP1(感度)よりも優先し、false-provenance event を避ける

### ADR-010: country-level 出力は内部保持、API は scenario 中心、drill-down は専用エンドポイント

**Status**: Accepted (2026-04-12)
**Context**: Phase 2 で API を scenario 化した後、country-level 出力をどうするか。
**Decision**:
- メイン API `/api/threat_data` は scenario 単位レスポンスのみ
- country 単位のスコアは scoring engine 内部で計算するが、主 API には含めない
- drill-down 専用エンドポイントを新設:
  - `/api/scenario/{id}/breakdown` — participant 国別の寄与内訳
  - `/api/scenario/{id}/country/{cc}/timeseries` — 特定 scenario 内の特定国の時系列
- 既存 country-level API は Phase 2-5 中は deprecated フラグ付きで並行運用、Phase 5 完了3ヶ月後に削除
**Consequences**:
- ✅ メイン API が clean
- ✅ 高度分析・デバッグは専用エンドポイントで対応可能
- ⚠️ 旧 API の deprecation 期間が必要

### ADR-011: scenario lifecycle state(active/paused/archived)

**Status**: Accepted (2026-04-12)
**Context**: 「シナリオ削除」の意味が文脈で異なる。誤作成、紛争終結、統合、構成変更など。
**Decision**: scenario に `state` カラムを追加。lifecycle 状態を明示化:

| state | 意味 | scoring 対象 | UI 表示 |
|-------|------|:---:|:---:|
| `active` | 通常稼働 | ✅ | ✅ |
| `paused` | 一時停止、データ保持 | ❌ | 非表示(設定で閲覧可) |
| `archived` | 終了、履歴のみ保持 | ❌ | 非表示(change_log のみ表示) |

**操作定義**:
- `delete` = active → paused(意味的削除、データ保持)
- `archive` = paused → archived(明示的終了)
- `restore` = paused/archived → active
- `purge` = archived → 完全削除(admin 専用、change_log 必須、scenario_id は予約語化)

**`enabled` と `state` の関係(v1.3 明確化)**:

`enabled` と `state` は **直交する 2 軸**。混同を防ぐためにここで意味論を確定する。

| `state` | `enabled` | 意味 | scoring 対象 | UI 表示 | 用途 |
|---------|-----------|------|:---:|:---:|------|
| `active` | `true` | 通常稼働 | ✅ | ✅ | 既定の状態 |
| `active` | `false` | 定義済みだが scoring 除外 | ❌ | 一覧に表示（グレーアウト） | 初期 disabled（south_china_sea）、一時的な scoring 除外 |
| `paused` | (無視) | 意味的削除、データ保持 | ❌ | 非表示 | delete 操作の結果 |
| `archived` | (無視) | 終了、履歴のみ | ❌ | 非表示 | archive 操作の結果 |

- `state != "active"` の場合、`enabled` は無視される（paused/archived は常に scoring 対象外）
- scoring 対象 = `state == "active" AND enabled == true`
- `enabled` は **admin の軽量スイッチ**（state 遷移を伴わず、change_log に記録するが diff_json は `{"enabled": false}` のみ）
- `state` は **lifecycle 遷移**（delete/archive/restore/purge は ADR-011 の操作定義に従う）

**Consequences**:
- ✅ 「削除」の意味が明確
- ✅ NP6(全面開示)を保てる(履歴を不用意に失わない)
- ⚠️ scenario_id 予約語表の管理が必要

### ADR-012: meta-scenario layer は将来課題として保留

**Status**: Accepted (2026-04-12)
**Context**: 「複数シナリオの同時激化」をメタイベントとして検出する機能を議論したが、初期スコープから外す判断が必要。
**Decision**:
- cross-scenario coupling / meta-scenario layer は Phase 5 完了後の将来課題とする
- 現フェーズでは「複数シナリオの同時激化」はアナリストが HUD を目視で判定する
- 将来実装時は本ドキュメント 11章「将来課題」から独立した設計ドキュメントを起こす
**Consequences**:
- ✅ 初期スコープが明確
- ⚠️ 同時複合危機の自動検出は当面行わない

### ADR-013: 初期シナリオセット(5 シナリオ)と scenario_id 命名規則

**Status**: Accepted (2026-04-12)
**Decision**:

**Tier 1(主要、デフォルト enabled)**:
- `taiwan_contingency` — 台湾有事
- `eastern_europe` — 東欧紛争(露宇戦争)
- `middle_east` — 中東紛争(IL-IR-proxies、対称紛争)

**Tier 2(副次、デフォルト enabled)**:
- `korean_peninsula` — 朝鮮半島(突発性監視、low-signal 校正)

**Tier 2(副次、デフォルト disabled、定義のみ用意)**:
- `south_china_sea` — 南シナ海(動的構成機能のデモ)

**scenario_id 命名規則**:
- snake_case、英小文字、ASCII
- 正規表現: `^[a-z][a-z0-9_]{2,29}$`(3-30文字、英小文字始まり)
- 予約語: `default`, `none`, `null`, `all`, `test`, `admin`, `system` は使用禁止
- `test_` prefix は開発・QA 用に予約、production では warning
- **バージョニングなし**(定義変更は `scenario_change_log` で追跡)
- 範囲外(明示的に初期含めない):Sino-Indian, India-Pakistan, Sahel, Caucasus, Arctic 等

**Consequences**:
- ✅ 異なる紛争形態をカバー(非対称、対称、低 signal、海洋中心)
- ✅ 動的構成機能の実例を SCS で提供
- ✅ C-lite のセンサーコスト試算が成立(最大 9 国/focus)
- ⚠️ 追加シナリオは ADR を伴う変更として管理する

### ADR-014: adversaries を participants に統合、scoring に算入する

**Status**: Accepted (2026-04-12)
**Context**: 既存設計では `adversaries: list[str]` を participants と別フィールドで保持し、scoring に算入していなかった。しかし「CN の cyber 動員」は Taiwan Contingency の重要な前兆であり、scoring に算入されないのは **NP1(感度: 見逃し回避)** および **NP2(多ソース収斂: cross-country シグナル集約)** に反する。
**Decision**:
- `adversaries` フィールドを廃止
- 攻撃側国家は `participants` に role `ADVERSARY` として登録する
- adversary の weight は通常の participant と同じ仕組みで指定(デフォルト 0.7 を推奨)
- scoring engine は role を問わず全 participant の signals を集約する
- role は **表示と分類のためのラベル** であり、scoring ロジックは weight のみを使う
**Consequences**:
- ✅ 「CN の cyber spike」が Taiwan Contingency の TL に自然に寄与
- ✅ 対称紛争(Middle East)でも同じロジックで扱える
- ✅ データモデルが1つ少ないフィールドで済む
- ⚠️ ADR-014 以前の設計との差分: 旧 `adversaries: list[str]` → 新 `participants[X].role == ADVERSARY`
- ⚠️ 敵対国の OSINT 取得の難しさ(別問題、センサー層で対処)

### ADR-015: 寄与計算は LLM country_weight と participant weight の両方を掛ける

**Status**: Accepted (2026-04-12)
**Context**: LLM は signal の各 country への関連度 `country_weights` を返しうるが、scoring engine がこれを無視していた。「US=1.0, TW=0.6」の signal は TW に 60% の関連度なので、participant weight だけでは過大評価になる。
**Decision**:

寄与計算式:
```
contribution = signal.raw_score
             × signal.country_weights.get(country, 1.0)   # LLM 判定の関連度
             × participant.weight                          # analyst 判定のシナリオ重要度
```

- LLM が country_weights を返さない場合はデフォルト 1.0
- 非 LLM signal(Cloudflare Radar 等)は常に country_weights = {country: 1.0}
- 計算式は rationale の `formula_trace` に完全に記録される(NP6)
**Consequences**:
- ✅ LLM 判断と analyst 判断の両方が scoring に反映
- ✅ NP6(全面開示)を保ちつつ、より精度の高いスコアリング
- ⚠️ LLM プロンプトで country_weights を返させる必要(Phase 3)
- ⚠️ 既存 test は両方の weight を考慮した期待値に更新

**リスク注記(v1.2 追記)**:
この ADR は **将来 single-weight 方式に後退する選択肢を残す** 形で Accepted している。以下の懸念を Phase 2-3 の実運用で観察する:

1. **LLM 非決定性**: 同じ記事を別時刻に再分析すると `country_weights` が変わりうる。これは signal.raw_score に直接掛かるため、scoring 安定性の外乱源になる。
2. **ハルシネーション**: LLM が「TW に関連あり」と 0.8 を返した根拠が原典に無い場合、scoring が過大化する。拘束④(検証可能)を守るには `llm_reasoning` と evidence URL を厳密に保持する必要がある。
3. **NP6(全面開示)との緊張**: 「なぜ TW 経由が 0.6 で US 経由が 1.0 なのか」の問いに対して「LLM がそう判定したから」という答えは、検証経路の直接性を弱める。アナリストにとっての可読性を Phase 4 の HUD 設計で実証する必要がある。LLM プロンプトと reasoning を `formula_trace` に保持することが NP6 充足の最低条件。
4. **後退オプション**: 上記 3 つのいずれかが運用上の問題になった場合、将来の ADR で `country_weights` を **metadata 保存のみに留め、scoring には participant_weight のみを使う** single-weight 方式へ戻す。この場合の `formula_trace` は `raw × participant_weight` の 2 段になる。

**観察指標(Phase 2 完了後から収集開始)**:
- 同じ LLM intel item の再分析結果に対する `country_weights` のばらつき(標本数 >= 20)
- `country_weights` が 0.5 を下回る寄与の割合(これらは scoring 値が小さくなりノイズ化しやすい)
- アナリストレビューで「この country tag は根拠が弱い」と reject された intel 件数

### ADR-016: role は固定 enum、loader でバリデーション

**Status**: Accepted (2026-04-12)
**Decision**:
- 4.3節で定義した enum のみ許容
- geo_data.json のシナリオ定義 loader は、未定義 role を起動エラーとする
- SQLite `scenario_participants.role` は CHECK 制約で enum 値のみ許容
- 新 role 追加は必ず ADR を伴う変更
**Consequences**:
- ✅ typo や drift を防止
- ✅ UI i18n で role 別ラベルを決定的にマッピング可能
- ⚠️ 新 role 追加時に複数ファイル変更が必要

### ADR-017: SensorTier enum は Phase 1 で導入(C-lite では2値、C-medium で3値目を使用)

**Status**: Accepted (2026-04-12)
**Context**: C-medium 移行時に大幅な構造変更を避けるため、tier 概念を先に導入する。
**Decision**:
- Phase 1 で `SensorTier` enum を `BaseSensor` に追加
- 値: `GLOBAL` / `FOCUSED_ONLY` / `BACKGROUND_ELIGIBLE`
- C-lite では `BACKGROUND_ELIGIBLE` は未使用(すべての per-country センサーは `FOCUSED_ONLY`)
- C-medium 移行は「個別センサーを `FOCUSED_ONLY` → `BACKGROUND_ELIGIBLE` に昇格」するだけで済む
**Consequences**:
- ✅ C-medium 移行がアーキテクチャ変更にならない
- ✅ C-lite 段階でも polling scheduler の契約が完成している
- ⚠️ 全センサーに tier 属性を付ける Phase 1 の作業増(小さいが)

### ADR-018: 既存の country-level 履歴データは保持、新 scenario データは Phase 2 以降から蓄積

**Status**: Accepted (2026-04-12)
**Context**: 既存の TL 履歴・time series・alert データは country 単位で蓄積されている。これをどう扱うか。
**Decision**:
- 既存履歴は **破棄せず保持**(NP6: 過去の検証可能性)
- country 単位の履歴は Phase 2 以降も drill-down API で参照可能
- scenario 単位の履歴は Phase 2 稼働後から新規に蓄積開始
- retroactive な再分類(過去データを新 scenario に再マッピング)は行わない
- アナリストへの表示時は「scenario 単位履歴の開始日」を明示
**Consequences**:
- ✅ 過去データの情報が失われない
- ✅ migration の複雑性を下げる
- ⚠️ scenario 単位時系列は Phase 2 以降の期間のみ
- ⚠️ UI に「scenario history starts from YYYY-MM-DD」を表示する必要

### ADR-019: scoring_mode は scenario の属性ではなく compute 結果

**Status**: Accepted (2026-04-12)
**Context**: 設計初期案で scenario クラスに `scoring_mode` 属性を持たせていたが、これは Layer 1〜3 のどれを正とするか曖昧になる。
**Decision**:
- `scoring_mode` は scenario クラスに持たせない
- `compute_scenario_score()` の返り値 `ScenarioState` のフィールドとして提供
- `scoring_mode` は呼び出し側の文脈(is_focused、C-lite/C-medium 設定)から決定される
**Consequences**:
- ✅ scenario 定義が clean
- ✅ 同じ scenario を異なるモードで複数回 compute できる

### ADR-020: sequence events を scenario 単位に拡張(country 単位は保持)

**Status**: Accepted (2026-04-12)
**Context**: 既存の `register_sequence_event(theater, ...)` は theater(=country)でキー化されている。scenario 単位スコアリングでは scenario 跨ぎのシーケンス(例: US の APT → TW の AIS 異常)を検出したい。
**Decision**:
- sequence event のキーを `(scenario_id, country, event_type)` に拡張
- 既存の country 単位イベントも移行期間中は読み書き可能に保持
- 1つのイベントが複数 scenario に関連する場合は、scenario × country の直積で複数レコードを記録
- Phase 2 で scoring 経路を新キーに切替
**Consequences**:
- ✅ scenario 単位のシーケンス検出が可能
- ✅ 既存イベントデータが失われない
- ⚠️ DB スキーマに scenario_id カラム追加(nullable、既存データは null)

### ADR-021: scenario scoring では domain weight を廃止し、participant weight に一元化する

**Status**: Accepted (2026-04-12)
**Context**: 既存 country 単位の scoring engine（WeightedConvergenceEngine）は domain weight `cyber=0.50, physical=0.30, info=0.20` を乗じていた。scenario 単位の scoring ではこの domain weight をどうするか。
**Decision**: scenario scoring では **domain weight を使用しない**。理由:
1. participant weight がすでに「この国の観測はどれだけ重要か」を表現しており、domain weight との二重の重み付けは NP6(全面開示)の検証経路を損なう
2. domain weight `info=0.20` は country 単位では妥当だったが、scenario 単位では background（C-lite）が info 偏重になるため、info を 0.20 で抑えると background scenario の score_lite がほぼ無意味になる
3. convergence bonus（DUAL +1.0 / FULL +2.0）がすでに「物理ドメインの重要性」を間接的に表現している（physical がないと FULL bonus は取れない）
4. 「cyber の 1 点は physical の 1 点と等価か」という問いは、participant weight の校正で各シナリオに合わせて調整するのがより柔軟

**Consequences**:
- ✅ scoring 式がシンプルになる（`raw × llm_cw × pw` の 3 項のみ）
- ✅ domain 間の相対重要度は convergence bonus + TL 判定式の physical 閾値で間接的に反映
- ⚠️ 既存 country-level API（deprecated 並行運用中）は従来通り domain weight を使用。混在期間中は「scenario API と country API で同じセンサーデータから異なるスコアが出る」ことの説明が必要
- ⚠️ Phase 2 のベースライン計測で「info 偏重により TL3 以上が頻発する」ことが判明した場合、domain weight を再導入するか DOMAIN_CAP（ADR-022）で調整するかを再評価

### ADR-022: global signal の countries 規約と per-domain 寄与上限

**Status**: Accepted (2026-04-12)
**Context**: 非 LLM の global sensor（GreyNoise, GDELT, USGS 等）が `Signal.countries` に全 participant を列挙した場合、1 つの global 事象が participant 数に比例して score を膨張させる。例: BGP global instability が 8 participant の Taiwan Contingency に寄与すると、`raw_score × Σ(participant_weights) ≈ raw × 5.4` となり、1 signal だけで TL3 に到達する。

**Decision**:

**(a) Signal.countries の規約（センサー層に義務付け）**:
- **per-country sensor**（SensorTier.FOCUSED_ONLY）: `countries` は **観測対象の単一国**。例: `countries=["TW"]`
- **global sensor**（SensorTier.GLOBAL）の非 LLM: `countries` は **空リスト `[]`**。scoring engine が別経路で処理する（下記 b 参照）
- **global sensor の LLM**: `countries` は **LLM が判定した関連国のみ**（全 participant を列挙しない）。LLM が特定国に帰属させた根拠が必要(NP6)

**(b) global signal の scoring 経路**:
`Signal.countries == []` の signal は、scenario の全 participant に展開するのではなく、**scenario 全体への flat な寄与** として扱う:

```python
if not signal.countries:
    # Global signal: contribute as scenario-level, no country attribution
    final = signal.raw_score * GLOBAL_SIGNAL_WEIGHT
    contributions.append(ScenarioContribution(
        contributing_country="GLOBAL",
        llm_country_weight=1.0,
        participant_weight=GLOBAL_SIGNAL_WEIGHT,
        ...
    ))
```

`GLOBAL_SIGNAL_WEIGHT` のデフォルト値: **0.5**（global signal は特定国に帰属しないため、最高 participant weight の半分程度で寄与させる。Phase 2 のベースライン計測で校正対象）。

**(c) per-domain 寄与上限（安全弁）**:
participant 展開後の寄与合算にも安全弁を設ける:

```python
DOMAIN_CAP = 6.0  # 1 domain が単独で TL2 相当を超えない
for domain in domains:
    domains[domain] = min(domains[domain], DOMAIN_CAP)
```

`DOMAIN_CAP` は Phase 2 のベースライン計測で校正する。初期値 6.0 は「1 ドメインのみで TL2 条件(score ≥ 6)に到達させない」ための設定。

**Consequences**:
- ✅ global BGP instability が participant 数に比例して膨張する問題を排除
- ✅ global signal の寄与が predictable になる
- ✅ per-domain cap で異常な単一ドメイン偏重を防止
- ⚠️ 全 global sensor の `countries` 出力を空リストに統一する Phase 2 の作業が必要
- ⚠️ `GLOBAL_SIGNAL_WEIGHT` と `DOMAIN_CAP` の初期値は保守的に設定し、運用で校正

---

### ADR-023: LLM intel の age-decay による contribution 時系列平滑化

**Status**: Accepted (2026-04-20)

**Context**:
`get_active_rationale()` は confirmed / auto_confirmed な LLM intel を TTL（24h）が切れるまで **full score_delta のまま** contribution に注入していた。この実装には 2 つの cliff effect があった:

1. **confirm cliff**: アナリストが pending intel を confirm した瞬間、contribution が 0 から full（例: 2.0〜3.0）に飛ぶ。1 件の confirm で TL が step-up する事例が実運用で発生（2026-04-20、Iran 関連 intel を confirm → TL2 → TL1）。
2. **TTL cliff**: 24h+1s で急に 0 になる。同じ intel が 24h では full weight、25h では無寄与、という二値挙動。

センサー側では `participant_weight × llm_country_weight` で「空間的重要度」は表現できていたが、**時間的減衰**は表現できていなかった。

**Decision**:
LLM intel の contribution に指数関数的 age-decay を適用する:

```
effective_score = score_delta × exp(-age_sec / (τ × 3600))
```

- **τ（time constant）** = 12h（デフォルト）
- age = τ で weight ≈ 0.37（= 1/e）
- age = 2τ で weight ≈ 0.14
- age = 3τ で weight ≈ 0.05
- TTL（48h に延長）は **hard floor** として残し、τ で自然減衰したあと最終的にドロップ

**Implementation points**:
- `get_active_rationale()` は各 item の decayed score を前段で算出
- `(source_type, theater)` cap（ADR-019）は **decayed score で降順ランク**する。raw ランクだと stale high-raw が cap を占有し、fresh low-raw が排除される不具合を防ぐ
- Per-source_type オーバーライド: `INTEL_AGE_DECAY_TAU_HOURS_<SOURCE_TYPE>`（例: `..._DIPLOMATIC=6` で外交 signal をより短寿命に）
- 無効化: `INTEL_AGE_DECAY_ENABLED=false` or `INTEL_AGE_DECAY_TAU_HOURS=0`

**τ=12h を選んだ根拠**:
- 短すぎ（τ=3h 等）→ 有効な intel が数時間で消え、センサー・収集間隔と噛み合わない
- 長すぎ（τ=36h 等）→ cliff effect を解消しない
- 12h は 1 業務サイクル（日中→深夜）相当で、「前のシフトが見た intel が次のシフトでは半減する」感覚と整合
- Phase C で DB 実データに対してシミュレーション: τ=12h で active intel の合計 contribution が **10.40 → 3.48（-66.6%）**、stale item（>24h）は実質 0、fresh item（<6h）は原寄与の 80〜95% を保持

**Signal 露出 (observability)**:
contribution dict に `score_raw`, `age_hours`, `age_weight` を追加。`detail` 文字列に `(age X.Xh, w=Y.YY)` を付与。Intel Panel / API で decayed / raw / weight を確認できる。

**Consequences**:
- ✅ Confirm 時の TL step-up を平滑化（confirm 直後でも低スコアから漸増）
- ✅ 24h TTL cliff の二値挙動を排除
- ✅ Cap ランキングが fresh signal を優先し、stale signal を自動的に追い出す（persistence 整理が不要）
- ✅ TL 閾値（ADR 未変更）との整合を保ったまま、運用感度を調整可能
- ⚠️ 全体的な intel contribution は -65% 程度に低下。Phase 2 ベースライン計測（§7.3.1）に影響する可能性があり、TL 閾値を追随調整する必要があるかは再計測で判断
- ⚠️ 感度優先（CLAUDE.md 基本方針）との緊張: stale item の寄与が急速に 0 に近づくため、「数日前の intel が徐々に残らなくなる」特性になる。fresh intel が複数コンファームされている限り補償される想定だが、長期監視では要注視

**Open Questions**:
- τ を source_type ごとに分離する場合の推奨値（例: hacktivist は短め、cert_* は長め？）— 運用知見を蓄積してから ADR 追記
- Raw score と decayed score を UI で並列表示すべきか？（現状は `score_raw` フィールドで露出のみ）

---

### ADR-024: CTLog sensor — シグナルモデル再設計（identity-match × untrusted-CA 検出）

**Status**: Accepted (2026-04-21)
**Revised**: Superseded by signal-model redesign (2026-04-22). Original transport-only hardening was insufficient — see "Why the v1 hardening was wrong" below.

**Context**:
CTLog センサー（`radar/sensors/ct_log.py`）は crt.sh の REST 上流を唯一のデータ源としているが、本セッション中の実測で 4 層にわたる根本問題を確認した:

| Layer | 症状 | 根本原因 |
|-------|------|---------|
| **L1: Transport** | `/?q=%.gov.tw&output=json` が **nginx 502 を 1.5 秒で返す**（タイムアウト前にエッジで蹴られる） | 上流 crt.sh は volunteer 運営の不安定サービスで、ピーク時に backend pool が枯渇する |
| **L2: Query shape** | 同じ上流に `?Identity=mofa.gov.tw` を投げると **200 OK で約 10 秒**で正常応答 | `name_value ILIKE '%.gov.xx'` は PostgreSQL の trigram GIN index 上で leading-wildcard が効かず、**最遅コードパス**を踏む。30s `statement_timeout` を必ず超過し nginx 層で 502 になる。`?Identity=` は btree exact-match で別系統 |
| **L3: Signal-to-noise** | gov-TLD ワイルドカードクエリは Let's Encrypt の自動更新で常に数千件返る — **ノイズ床が高すぎる** | gov ドメイン全体に対する「件数サージ」は LE 普及により事実上恒常状態 |
| **L4: Purpose misfit** | スコアが「count surge」を測っていたが、本来検出したい脅威は「**普段と異なる CA が gov ドメインに発行している**」事象 | 件数の増減ではなく **発行者(issuer)の異常**こそが MITM 準備や DNS hijacking の前兆 |

**Why the v1 hardening was wrong**:
2026-04-21 の最初の修正は L1 のみを対象とし、タイムアウト緩和・5xx リトライ・failure-mode 細分化を入れた。しかし L2 が真因のため、`%.gov.xx` クエリは **どれだけリトライしても 502 を返す**。さらに L3/L4 を放置したため、仮に上流が安定しても「LE による日常的更新を毎サイクル誤検知する」設計のままだった。ユーザーの指摘「DISABLE では問題が解決しない、なぜ取れないのか深く考えるべき」を 4 層で受け止め直した結果、シグナルモデル自体を再設計する判断に至った。

**Decision**:
4 つの設計変更を一括導入する:

1. **クエリ形態の刷新（L1+L2 解決）**: `%wildcard%` を捨て `?Identity=<exact_domain>` に切り替え。`CT_LOG_WATCHED_DOMAINS`（`geo_data.json`、27 ヶ国 × 約 9 ドメイン = 計 238）を curated set として保持し、各 watched domain を順番にプローブ
2. **per-domain CA 履歴（L4 解決）**: DB v11 マイグレーションで `ct_log_known_ca_per_domain` と `ct_log_domain_first_observed` を追加。各 watched domain について「過去観測した CA の集合」を保持し、新規 CA 出現時のみアラート
3. **2 段階トラスト判定（L3+L4 解決）**:
   - **グローバルトラスト**: `CT_LOG_TRUSTED_CAS_GLOBAL`（LE/DigiCert/Sectigo/GlobalSign/SwissSign/HARICA など 43 substrings）に substring マッチする issuer は常に許可（履歴更新のみ）
   - **per-domain トラスト**: グローバル不一致でも、当該 domain の known-CA 履歴に既登録の CA は許可
4. **Warm-up window（false-positive 抑制）**: `CT_LOG_WARMUP_DAYS=14`。新規 watched domain は 14 日間あらゆる CA を「暗黙に学習」（履歴登録のみ、アラートは出さない）。これにより監視開始時点の **bootstrap 偽陽性**を回避

加えて、検査中に `*.gov.xx` 等 gov-TLD レベルのワイルドカード証明書を観測した場合は issuer によらず `WILDCARD_TLD_DETECTED` を fire（rare かつ高シグナル）。

**Curation rationale（重要 — ユーザー指示「初期セットなどの妥当性については、深く考えたうえで実装してください」）**:

watched domain set は以下の原則で選定:
- 各国の **head of state（大統領府/首相府）/ MoFA / MoD / parliament / central bank / security agency** を必ず含める（attestation 価値が最も高い entities）
- ISR2 コードキー、FQDN 値（`?Identity=` 直接照合用）。サブドメインは原則含めない（sub-namespace の cert は単体監視対象外）
- 27 ヶ国（TW/JP/KR/CN/RU/UA/IR/IL/US/GB/DE/FR/PH/VN/IN/PK/BY/GE/PL/EE/LV/LT/FI/SE/NO/RO/AU）×8〜13 ドメイン。crt.sh 1 query あたり最悪 10 秒として、`CT_LOG_MAX_QUERIES_PER_THEATER=8`、theater あたり最大 80 秒。アクティブ theater が 8 ヶ国の時 worst-case 10 分／cycle、1 時間 poll 間隔に対して許容範囲

trusted CA allowlist は以下の原則で選定:
- **ACME / ISRG ecosystem** を網羅（LE は世界の gov domain で最大シェア）
- **西側商用 CA（DigiCert/Sectigo/GlobalSign/Entrust/IdenTrust など）** を網羅
- **EU eIDAS QWAC 発行者（SwissSign/HARICA/D-TRUST/Buypass など）** を含める（EU gov の正規 CA）
- **意図的に除外**: ロシア・中国・イランの state-aligned CA（GDCA、Russian Trusted CA、IRCA など）。これにより「敵対国 CA が NATO 加盟国 MoFA に発行する」という攻撃シグネチャに **非対称な検出感度**を与える。逆に当該国自身が自国 CA を正規に使っている場合は per-domain history が learning して許可するので false-positive にはならない

**スコアリング**:
- `untrusted_ca_count > 0` → score 3、status `UNTRUSTED_CA_DETECTED`、TL3 級の signal
- `wildcard_tld_detected = True` → score 2、status `WILDCARD_TLD_DETECTED`、TL3 級の signal
- それ以外 → score 0、status `NORMAL` または `WARMUP`

**後方互換**:
ct_data の legacy フィールド（`total_recent`, `gov_count`, `wildcard_count`, `is_surge`, `recent_certs`）は全て保持。新フィールド（`untrusted_ca_count`, `untrusted_ca_events`, `wildcard_tld_detected`, `wildcard_tld_events`, `watched_domains`, `observed_domains`, `warmup_active`, `scoring_model`）を追加。`gov_count` は常に 0（旧概念は廃止）。`is_surge` は意味を変更し「anomaly が fire したか」を表す。

**自己治癒機構の保持**:
3 サイクル連続無応答で `degraded` モード（4h interval、theater あたり 1 ドメインのみプローブ）。1 cycle 成功で即時復帰。`upstream_health()` は T1.B sensor_health endpoint がポーリングする。

**運用上の意味**:
- crt.sh が落ちている間 CTLog がデータ無しになるのは正常動作（OSINT 依存設計の honest behavior）
- Health panel で `failure_modes` と `anomaly_counts` を観察すれば、上流障害・スロットル・実 anomaly fire を区別可能
- 14 日 warm-up 中は false-positive がほぼ 0 になる代わりに、true-positive も同期間遅延する。trade-off として受容

**Consequences**:
- ✅ L1〜L4 すべての層に対処。データが取れる + シグナルが正しい
- ✅ false-positive レート激減（LE 自動更新を全シグナルから除外）
- ✅ true-positive シグナルの semantic value 上昇（issuer 異常 = MITM 準備の直接指標）
- ✅ 既存 consumer（`core.py` rationale, `climate.py` ClimateEvent）は backward-compat フィールドで動作継続。新シグナルは新フィールド経由で受け取る
- ⚠️ `warmup_days=14` 期間中の検出感度は意図的に 0。watched domain 追加時は warm-up 終了まで signal が出ないことを運用者に明示する必要あり
- ⚠️ adversary 国 CA を allowlist から除外する非対称設計は、ロシア／中国／イラン側の正規 gov 通信を「未学習なら anomaly」と扱う。warm-up + per-domain history で吸収するが、新規ドメイン追加時は意図的に偽陽性が出る可能性あり
- ⚠️ crt.sh の per-query 待ち時間はそのまま（10s × 8 query × 8 theater = 最悪 10 分／cycle）。1 時間 poll 間隔に対して budget 内だが、theater 数が増える場合は `CT_LOG_MAX_QUERIES_PER_THEATER` の調整を要する

**Test coverage**:
`test_ct_log_redesign.py` で 21 ケース:
- DB v11 テーブル作成・helpers 冪等性
- issuer parser（O= 抽出 / CN= フォールバック / quoted handling）
- グローバル trust マッチング（LE/DigiCert pass、RU/CN state CA reject）
- トラスト決定木（trusted CA pass / known per-domain pass / warm-up suppress / out-of-warmup fire / 同サイクル重複 non-refire）
- ワイルドカード TLD 検出（`*.gov.tw` fire、`*.api.mofa.gov.tw` no-fire）
- round-robin domain selection（13 ドメイン × budget 8 を 2 cycle で完全網羅）
- `upstream_health()` redesign metadata 露出

**Open Questions**:
- watched domain set の continuous curation: 加盟国増減・新規 ministry 設立に追従する運用プロセスをどう設計するか — Phase 6 で検討
- trusted CA allowlist の review cadence: 年 1 回程度のレビューを Phase 5 完了後に確立
- per-domain CA 履歴のディスク使用量: 238 domain × 5 CA average × 200B = 約 240KB。長期では SBR 検討

### ADR-025: Shadow Sampling — focus 切替に依存しない C-medium 評価データ生成

**Status**: Accepted (2026-04-24)

**Context**:
§9.3.1 で定義した `focus_switch_log` ベースの C-medium 移行判定は **構造的欠陥** を抱えていた:

- `focus_switch_log` への書き込みはアナリストが background → focused に切替えた瞬間にしか発生しない
- 単独アナリスト + 既定 focused scenario の継続運用では、この切替が長期間発生しない
- 結果として `cmedium_recommendation` は半永久的に `INSUFFICIENT_DATA` を返す
- 「移行すべきか否か」という判定は、移行を判断するための観測機構そのものが動かないため永遠に保留される

これは **NP4(結論最大化)** および **NP5+8(結論品質規律)** に反する:
- NP4 観点: C-medium 移行可否という「結論」を出すために必要な観測機構が、アナリスト操作待ちで動かない構造になっていた
- NP5+8 観点: データ蓄積後も `INSUFFICIENT_DATA` から抜け出せない設計は、本ドキュメントが定義する「恒常的結論不可 = 設計失敗」に該当する

なお、本 ADR は旧 P5(観察可能性 > 自動化)を再定式化した **「自動化は許容、観察可能性は不可欠」** の最初の適用例である: shadow_sampler は新規 I/O ゼロという制約下で自動化を行いつつ、`source` カラムによる provenance 保存で観察可能性を担保している。

**Decision**:
focused scoring サイクルに **piggyback する形で** background scenario の (lite, full) スコアペアを合成し、`focus_switch_log` に `source='shadow_sampler'` として記録する。これにより analyst の focus 切替に依存せず C-medium 評価データが蓄積される。

設計の核心は **「signal を再取得しない」** こと:
1. focused サイクルが既に収集した `_signals` リストをそのまま借用
2. 同一の signal 集合に対し `compute_scenario_score(target, _signals, is_focused=False)` と `compute_scenario_score(target, _signals, is_focused=True)` を計算
3. 前者が **lite_score**（background scoring path 相当）、後者が **full_score**（focused scoring path 相当）
4. 差分を `focus_switch_log` に書く

これは新規 I/O を発生させない。LLM 呼び出しもセンサー fetch も増えない。CPU コストはサイクルあたり scenario 1 件の追加スコアリング 2 回（数 ms）のみ。

scenario の選択は **round-robin LRU**: 直近サンプリング時刻が最も古い候補を選ぶ。これによりすべての background scenario が公平にカバーされる。

**Invariants（実装で必ず守る 7 つの不変条件）**:

| ID | 不変条件 | 担保箇所 |
|----|---------|---------|
| **I-1** | TL 値は shadow score から導出されない（focus_switch_log のスコア欄のみ） | `shadow_sampler.py` は `derive_tl()` を呼ばない |
| **I-2** | shadow scoring から sequence_event を発火させない | `compute_scenario_score()` 経路のみ通り、`register_sequence_event()` は呼ばれない |
| **I-3** | intel queue を一切汚染しない | shadow path は `intel_queue.submit()` を呼ばない |
| **I-4** | provenance を保存する（analyst rows と shadow rows を区別可能） | `focus_switch_log.source` カラム必須 |
| **I-5** | 決定論的等価性: 同一 signal set に対し shadow_lite == background-mode score、shadow_full == focused-mode score | `compute_scenario_score()` は純関数 |
| **I-6** | 並行性安全: 複数 worker greenlet が同時に同一 scenario を選ばない | `ShadowSampler._lock` で selection を直列化 |
| **I-7** | signal が空のサイクルでは記録しない（ゼロ-ゼロ row を作らない） | `_record_inner()` で early-return |

**Schema 変更（migration v13）**:
```sql
ALTER TABLE focus_switch_log ADD COLUMN source TEXT NOT NULL DEFAULT 'analyst';
ALTER TABLE focus_switch_log ADD COLUMN shadow_score_kind TEXT;
CREATE INDEX idx_focus_switch_log_source_time
  ON focus_switch_log (source, switched_at DESC);

CREATE TABLE shadow_sampler_state (
  scenario_id      TEXT PRIMARY KEY,
  last_sampled_at  REAL NOT NULL,
  sample_count     INTEGER NOT NULL DEFAULT 0,
  last_lite_score  REAL,
  last_full_score  REAL,
  last_delta       REAL
);
```

`source='analyst'` の DEFAULT により既存行は無変更で analyst 起源として扱える（破壊的変更ではない）。

**Config knobs（既定値の根拠）**:
| 変数 | 既定 | 根拠 |
|------|------|-----|
| `SHADOW_SAMPLING_ENABLED` | `true` | 当機能は本 ADR の主目的そのもの。off にする理由は debug／A/B 比較のみ |
| `SHADOW_SAMPLING_INTERVAL_SEC` | `0` | 0 = piggyback。dedicated cadence は本 v1 では不実装（将来拡張枠） |
| `SHADOW_SAMPLING_MIN_GAP_SEC` | `300` | 同一 scenario の連続再選択を抑止。HUD poll 間隔 5 分と整合 |
| `SHADOW_SAMPLING_MAX_PER_DAY` | `200` | 5 scenario × 24h × 60min / 5min ≒ 1440 上限の 14% に抑え focus_switch_log 肥大化を防ぐ |
| `SHADOW_SAMPLING_REQUIRE_OVERLAP` | `false` | 既定 off。on にすると参加国オーバーラップが無い scenario はスキップされ、global signal のみで評価される lite_score の偏りを排除可能だが、サンプル機会を大きく削る |
| `SHADOW_SAMPLING_WARMUP_SEC` | `600` | プロセス起動直後はベースラインが未収束のため最初の 10 分はスキップ |
| `C_MEDIUM_DELTA_MISS_SHADOW` | `1.4` | analyst 起源の `C_MEDIUM_DELTA_MISS=2.0` より保守的。shadow は同一 signal 集合で比較するため delta は構造的に小さい(global signal のみで lite が動かないケースが頻出) |

**API への影響**:
- `/api/analytics/focus_switches`、`clite_evaluation`、`cmedium_recommendation` に `?source=` クエリパラメータを追加(`all`/`analyst`/`shadow_sampler`、既定 `all`)
- レスポンスに `source` フィールドを含めて起源を明示
- `cmedium_recommendation.config` に `delta_miss_shadow` を追加

**Verification**:
- migration v13 適用後、既存行が `source='analyst'` でラベル付けされていること
- `scorable()` が N シナリオを返す環境で N-1 サイクル走らせると、N-1 番目までに全 background scenario が 1 度ずつサンプリングされること(round-robin の公平性)
- lite_score と full_score の差分が 0 になるサンプル(全 signal が global)が観測されること(I-5 の側面検証)
- `SHADOW_SAMPLING_ENABLED=false` で起動した場合に `shadow_sampler` 由来行が 1 件も増えないこと

**Open Questions**:
- `INTERVAL_SEC > 0` の dedicated cadence をいつ実装するか — focused サイクルが極端に長い(>5min)環境で背景観測が薄くなる場合のみ意味がある。現状は要否不明
- `REQUIRE_PARTICIPANT_OVERLAP=true` を既定にすべきか — 数週間の運用データを見て判断
- C-medium 移行判定での analyst rows と shadow rows の重み付け — 現状は単純合算。将来は kind ごとに別系列で表示する可能性

### ADR-026: 設計 W — participant weight の制約付き自動 calibration

**Status**: Accepted (2026-04-25)

**Context**:
`scenario.participants[X].weight` は Phase 1 以降、analyst が geo_data.json または admin UI で **静的に設定** する設計だった。これは旧 P5(ツールは判断しない)と整合していたが、**新原則 NP4(結論最大化)** の下では以下が問題化する:

1. weight 校正の **遅延**: 「TW の weight が高すぎ/低すぎ」という気付きは、TL 系列を眺めて初めて生じる。analyst が手動で +0.1 / -0.1 を試行する loop は数日〜数週間スケールで、その間 TL は systematically biased なまま結論を出し続ける
2. **NP5+8 違反の温床**: calibration 状態が結論に付記されない。analyst は「現在の TL が calibration 済みか否か」を区別できない
3. **NP4 の結論最大化要請**: ツールは「現時点で技術的に実行可能な最大の結論」を出す責務を負う。weight 自動調整は技術的に実行可能であり、これを analyst 操作待ちにするのは責務放棄

旧設計は「自動調整は判断 = P5 違反」として禁じていたが、本版は P5 を廃止した。NP6(全面開示)+ NP7(組織内ノード)の枠組み下では、自動調整は **「analyst が把握可能な制約内で行われ、override 可能であること」** さえ満たせば許容される。

**Decision**:
participant weight に **制約付き自動 calibration**(設計 W)を導入する。

#### W.1 二層モデル

weight は次の 2 値の積で表現される:

```
effective_weight = configured_weight × adjustment_factor
```

- `configured_weight ∈ [0.0, 1.0]`: analyst が geo_data.json / admin UI で設定する **戦略的アンカー値**(従来の `participant.weight` をそのまま継承)
- `adjustment_factor ∈ [0.7, 1.3]`: calibration エンジンが自動更新する **微調整係数**。±30% を hard bound とし、bound を超える adjustment 提案は飽和(clip)される

`effective_weight` は scoring engine に渡される最終値。`configured_weight` と `adjustment_factor` は **常に separately 保存される**(NP6: 結論寄与の追跡可能性)。

#### W.2 Calibration ゲート(全 AND 条件)

`adjustment_factor` の更新は次の 5 つを **全て満たす** 場合のみ実行:

| ゲート | 閾値 | 根拠 |
|-------|------|------|
| **G1: sample_n** | ≥ 30 | 統計的に意味のある最小標本(per-participant の signal 寄与件数) |
| **G2: sensor health** | 関連 sensor の `failure_rate < 0.3`(7d window) | 障害中の sensor 由来 signal で calibration を歪めない |
| **G3: continuity** | 直近 7d で signal が均等(no >50% gap) | サンプル偏在期間を除外 |
| **G4: cooldown** | 前回 calibration から ≥ 24h | 振動防止 |
| **G5: shadow validation** | shadow_sampler の delta 履歴で adjustment 候補が **少なくとも中立**(改悪しない) | NP4 の結論品質を悪化させない安全弁 |

ゲートが満たされない場合、`adjustment_factor` は **直前の値を保持** し、`calibration_status = INSUFFICIENT_DATA` を結論メタデータに付記する(NP5+8(a))。

#### W.3 Adjustment 算出

`adjustment_factor` の更新は次の規則に従う:

```
target_factor = clip(observed_contribution_ratio / expected_contribution_ratio, 0.7, 1.3)
new_factor    = old_factor × (1 - α) + target_factor × α    # EMA、α = 0.1
```

- `expected_contribution_ratio`: 当該 participant の `configured_weight` から導出される期待寄与比率(scenario 内の total weight に対する割合)
- `observed_contribution_ratio`: 直近 7d window の実測寄与比率(`focus_switch_log` shadow rows + analyst rows)
- α=0.1: EMA 平滑化定数。1 cycle で最大 ±3%(=0.3 × 0.1)の動き

#### W.4 Audit と Override

- 全 calibration イベントは `weight_calibration_log` テーブルに記録(migration v14):
  ```sql
  CREATE TABLE weight_calibration_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scenario_id TEXT NOT NULL,
      country TEXT NOT NULL,
      calibrated_at REAL NOT NULL,
      old_factor REAL NOT NULL,
      new_factor REAL NOT NULL,
      sample_n INTEGER NOT NULL,
      gate_pass_mask INTEGER NOT NULL,  -- bitmask of G1..G5
      reason TEXT NOT NULL,             -- "ema_step" | "saturation_low" | "saturation_high" | "rollback"
      source TEXT NOT NULL DEFAULT 'auto'  -- 'auto' | 'analyst_override' | 'analyst_reset'
  );
  ```
- Analyst は admin UI から:
  - `adjustment_factor` を任意の値で **override**(`source='analyst_override'`)
  - **reset to 1.0**(`source='analyst_reset'`)
  - per-scenario または per-participant で **calibration を一時停止**

#### W.5 Phased Rollout(必須)

新規 calibration ロジックは結論に直接影響するため、3 段階で展開する:

| Phase | フラグ | 期間 | 内容 |
|-------|-------|------|------|
| **Shadow** | `WEIGHT_CALIB_MODE='shadow'` | 14 日 | calibration を計算・log に記録するが scoring には使わない(`adjustment_factor=1.0` 固定)。`weight_calibration_log` で挙動観察 |
| **Opt-in** | `WEIGHT_CALIB_MODE='opt_in'` | 14 日 | per-scenario flag(`scenario.calibration_enabled`)で有効化。analyst が明示的に on にした scenario のみで実 scoring に反映 |
| **Default-on** | `WEIGHT_CALIB_MODE='default'` | 以降 | 全 scenario で既定 on。opt-out フラグで個別停止可能 |

各 phase 移行は本ドキュメントへの追記 + ADR を伴う(本 ADR とは別の Phase 移行 ADR)。

#### W.6 NP マッピング

- **NP1(感度)**: clip ±30% により weight が極端に下がって signal が無視される事態を防止
- **NP4(結論最大化)**: 自動 calibration により analyst 操作待ちを排除
- **NP5+8(品質規律)**: G1〜G5 ゲートで `INSUFFICIENT_DATA` を honest に出す。calibration 履歴は結論メタデータに含む
- **NP6(全面開示)**: `configured_weight` と `adjustment_factor` を分離保存、`weight_calibration_log` で全イベント追跡可能、formula_trace に両値を含める
- **NP7(組織内ノード)**: analyst override / reset / 一時停止が常時可能。ツールは calibration 提案を出すが、最終決定権は analyst にある

#### W.7 実装上の再利用

- ADR-025 の `shadow_sampler` を `observed_contribution_ratio` 計算の一次データソースとして再利用(focus 切替に依存せず参加国寄与履歴が蓄積される)
- G5(shadow validation)は同 sampler の delta 履歴を直接参照

**Consequences**:
- ✅ NP4(結論最大化)を実装層で実現。analyst は戦略的アンカーの設定のみに集中できる
- ✅ ±30% bound + EMA + 5 つのゲートで calibration 暴走を防止
- ✅ shadow → opt-in → default-on の段階展開で本番影響をコントロール
- ✅ analyst override が常時可能(NP7)
- ⚠️ 計算負荷増(per-cycle で adjustment 算出)。実測で focused サイクル時間 +10ms 程度を許容
- ⚠️ `weight_calibration_log` の容量(5 scenario × 8 participant × 1 entry/day = 40 rows/day)。年間 1.5 万 rows、無視可能
- ⚠️ shadow phase でアナリストが calibration の挙動を観察する負荷が新規発生。Help Guide に観察手順を追記

**Verification**:
- migration v14 適用後、`weight_calibration_log` テーブル存在確認
- shadow phase で `effective_weight = configured_weight` が成立(adjustment が scoring に反映されない)こと
- ゲート G1〜G5 のいずれかが false の cycle では `adjustment_factor` が更新されないこと
- analyst override 後 24h は auto calibration が cooldown により skip されること

**Open Questions**:
- shadow phase の長さ 14 日は十分か(scenario によっては signal 蓄積が遅い可能性)
- ゲート G3(continuity)の「均等」定義 — 現状は >50% gap 検出。より精緻な metric が必要か Phase 観察で判定

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
      "state": "active",
      "enabled": true,
      "tier": 1,
      "participants": {
        "TW": { "weight": 1.0, "role": "primary_target" },
        "US": { "weight": 0.8, "role": "primary_ally" },
        "JP": { "weight": 0.8, "role": "forward_base" },
        "GU": { "weight": 0.7, "role": "forward_base" },
        "PH": { "weight": 0.6, "role": "secondary_ally" },
        "AU": { "weight": 0.4, "role": "extended_deterrence" },
        "KR": { "weight": 0.4, "role": "strategic_observer" },
        "CN": { "weight": 0.7, "role": "adversary" }
      }
    },
    "eastern_europe": {
      "name_en": "Eastern Europe (Russia-Ukraine)",
      "name_ja": "東欧紛争",
      "core_country": "UA",
      "state": "active",
      "enabled": true,
      "tier": 1,
      "participants": {
        "UA": { "weight": 1.0, "role": "primary_target" },
        "PL": { "weight": 0.8, "role": "forward_base" },
        "RO": { "weight": 0.6, "role": "secondary_ally" },
        "EE": { "weight": 0.6, "role": "secondary_ally" },
        "LV": { "weight": 0.6, "role": "secondary_ally" },
        "LT": { "weight": 0.6, "role": "secondary_ally" },
        "FI": { "weight": 0.6, "role": "secondary_ally" },
        "MD": { "weight": 0.5, "role": "spillover_risk" },
        "SK": { "weight": 0.4, "role": "extended_deterrence" },
        "RU": { "weight": 0.8, "role": "adversary" },
        "BY": { "weight": 0.6, "role": "adversary" }
      }
    },
    "middle_east": {
      "name_en": "Middle East (Israel-Iran-Proxies)",
      "name_ja": "中東紛争",
      "core_country": null,
      "state": "active",
      "enabled": true,
      "tier": 1,
      "participants": {
        "IL": { "weight": 1.0, "role": "principal_belligerent" },
        "IR": { "weight": 1.0, "role": "principal_belligerent" },
        "LB": { "weight": 0.7, "role": "proxy_front" },
        "YE": { "weight": 0.6, "role": "proxy_front" },
        "US": { "weight": 0.6, "role": "force_projection" },
        "SY": { "weight": 0.5, "role": "proxy_front" },
        "IQ": { "weight": 0.5, "role": "proxy_front" },
        "SA": { "weight": 0.3, "role": "regional_power" }
      }
    },
    "korean_peninsula": {
      "name_en": "Korean Peninsula",
      "name_ja": "朝鮮半島",
      "core_country": "KR",
      "state": "active",
      "enabled": true,
      "tier": 2,
      "participants": {
        "KR": { "weight": 1.0, "role": "primary_target" },
        "US": { "weight": 0.8, "role": "primary_ally" },
        "JP": { "weight": 0.7, "role": "forward_base" },
        "CN": { "weight": 0.4, "role": "strategic_observer" },
        "KP": { "weight": 0.8, "role": "adversary" }
      }
    },
    "south_china_sea": {
      "name_en": "South China Sea",
      "name_ja": "南シナ海",
      "core_country": "PH",
      "state": "active",
      "enabled": false,
      "tier": 2,
      "participants": {
        "PH": { "weight": 1.0, "role": "primary_target" },
        "US": { "weight": 0.7, "role": "primary_ally" },
        "VN": { "weight": 0.5, "role": "secondary_party" },
        "MY": { "weight": 0.4, "role": "secondary_party" },
        "TW": { "weight": 0.4, "role": "secondary_party" },
        "JP": { "weight": 0.4, "role": "extended_deterrence" },
        "CN": { "weight": 0.7, "role": "adversary" }
      }
    }
  }
}
```

**フィールド説明**:

| フィールド | 型 | 必須 | 意味 |
|----------|---|:----:|------|
| `name_en`, `name_ja` | str | ✓ | i18n 表示名 |
| `description_en`, `description_ja` | str | – | 詳細説明(ツールチップ) |
| `core_country` | str \| null | – | UI 補助。scoring には関与しない(ADR-009) |
| `state` | str | – | `"active"` / `"paused"` / `"archived"`。デフォルト `"active"`。→ ADR-011 参照 |
| `enabled` | bool | – | デフォルト true。`state` との関係 → ADR-011 参照 |
| `tier` | int | – | 1=主要 / 2=副次 / 3=実験的(UI ソート用のみ、scoring には影響しない) |
| `participants` | dict | ✓ | 国 → {weight, role}。味方・敵を問わず全 participant を含む |
| `participants[].weight` | float [0.0-1.0] | ✓ | scoring 寄与重み |
| `participants[].role` | str(enum) | ✓ | 4.3節の Role enum 値 |

### 6.2 SQLite スキーマ

```sql
-- Layer 2: 永続カスタマイズ
CREATE TABLE IF NOT EXISTS scenarios (
    id TEXT PRIMARY KEY,
    name_en TEXT NOT NULL,
    name_ja TEXT NOT NULL,
    description_en TEXT,
    description_ja TEXT,
    core_country TEXT,  -- nullable (ADR-009)
    state TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active', 'paused', 'archived')),
    enabled INTEGER NOT NULL DEFAULT 1,
    tier INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS scenario_participants (
    scenario_id TEXT NOT NULL,
    country TEXT NOT NULL,
    weight REAL NOT NULL CHECK (weight >= 0.0 AND weight <= 1.0),
    role TEXT NOT NULL
        CHECK (role IN (
            'primary_target', 'principal_belligerent', 'adversary',
            'primary_ally', 'forward_base', 'secondary_ally',
            'extended_deterrence', 'strategic_observer',
            'proxy_front', 'force_projection', 'secondary_party',
            'spillover_risk', 'regional_power'
        )),
    PRIMARY KEY (scenario_id, country),
    FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scenario_change_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL,
    changed_at REAL NOT NULL,
    changed_by TEXT,
    change_type TEXT NOT NULL
        CHECK (change_type IN (
            'create', 'update', 'delete', 'archive',
            'restore', 'purge', 'reset'
        )),
    diff_json TEXT  -- JSON Merge Patch 形式
);

-- 予約語テーブル(purge された scenario_id を再利用禁止)
CREATE TABLE IF NOT EXISTS scenario_reserved_ids (
    id TEXT PRIMARY KEY,
    reserved_at REAL NOT NULL,
    reserved_by TEXT,
    reason TEXT
);

-- sequence events に scenario_id を追加 (ADR-020)
-- 既存テーブルに ALTER で追加(nullable、既存行は null)
ALTER TABLE sequence_events ADD COLUMN scenario_id TEXT;
CREATE INDEX IF NOT EXISTS idx_sequence_events_scenario
    ON sequence_events(scenario_id);
```

**diff_json フォーマット**: [JSON Merge Patch (RFC 7396)](https://datatracker.ietf.org/doc/html/rfc7396) 形式で変更前→変更後の差分を保存。

**change_log のリテンション**: 永続保持(NP6 重視、変更頻度が低いためサイズ問題は発生しない)。

### 6.3 Signal データクラス

**新規導入**: scoring への入力を統一するための atomic なデータ単位。

```python
@dataclass
class Signal:
    """
    センサーが emit する1件の観測データ。
    scoring engine の入力の atomic unit。
    """
    signal_source: str                     # dedup キー (例: "bgp", "cyber_firestorm")
    sensor: str                            # センサー名
    observed_at: float                     # UNIX timestamp
    domain: str                            # "cyber" | "physical" | "info"
    countries: list[str]                   # 関連国。ADR-022 の規約参照:
                                           #   per-country sensor: 単一国 ["TW"]
                                           #   global sensor (非LLM): 空 []
                                           #   global sensor (LLM): LLM判定の関連国 ["US","TW"]
    country_weights: dict[str, float]      # LLM が判定した国別関連度 (0.0-1.0)
                                           # 非 LLM は {country: 1.0}、未指定は default 1.0
    raw_score: float                       # scoring engine が使う元値
    value_display: str                     # UI 表示用の生の観測値文字列
    evidence_url: str | None               # 原典 URL(NP6)
    llm_reasoning: str | None              # LLM 由来の reasoning trace
```

**センサー層の責務**: 各センサーは自身の観測を `Signal` に変換して scoring engine に供給する。`countries` フィールドの設定規約は → ADR-022(正規定義)を参照。

### 6.4 RationaleEntry と ScenarioContribution

```python
@dataclass
class RationaleEntry:
    """
    scoring に寄与した1件のシグナル記録。
    Signal をほぼそのまま保持し、加えて scenario 適用前の計算前情報を含む。
    """
    signal: Signal
    suppress_reason: str | None  # noise filter / mute 等で抑制された場合の理由

@dataclass
class ScenarioContribution:
    """
    RationaleEntry が特定 scenario に寄与した結果の記録。
    rationale × (participant country) の組み合わせで生成される。
    1つの RationaleEntry が複数 ScenarioContribution を生むことがある
    (例: countries=["US","TW"] の LLM signal が TW シナリオで US, TW 両方経由で寄与)。
    """
    rationale: RationaleEntry
    contributing_country: str              # どの participant 経由の寄与か
    llm_country_weight: float              # signal.country_weights[contributing_country]
    participant_weight: float              # scenario.participants[contributing_country].weight
    participant_role: str                  # 表示用 role ラベル
    final_contribution: float              # 計算式 → 7.1 節参照
    formula_trace: str                     # 人間可読の計算過程文字列
```

### 6.5 API レスポンス形式(実装参照)

実装は `radar/routes/core.py:/api/threat_data` ハンドラ。レスポンス構築は `_serialize_scenario_state()` 系ヘルパー。

**focused scenario フィールド**:
`id` / `name` / `is_focused: true` / `scoring_mode: "full"` / `tl` (1-5) / `score` / `domains` (cyber/physical/info) / `convergence_bonus` / `active_countries` / `contributions` (each: `rationale`, `contributing_country`, `llm_country_weight`, `participant_weight`, `participant_role`, `final_contribution`, `formula_trace`) / `data_freshness_sec`

**background scenario フィールド** (ADR-008、TL 出さない):
`is_focused: false` / `scoring_mode: "lite"` / `tl: null` / `score_lite` / `domains_lite` / `indicators` (`llm_intel_24h`, `active_countries`, `domain_signal_counts`) / `contributions` (LLM intel + global signal のみ) / `lite_bias_warning` / `data_freshness_sec`

**top-level**: `focused_scenario` / `scenarios` (dict) / `global_data_freshness_sec` / `scenario_history_starts_at`

**重要な数値関係**(NP6):
- `score = sum(domains) + convergence_bonus`
- `formula_trace`: `"{raw:.2f} (raw) × {llm_cw:.2f} (llm:{cc}) × {pw:.2f} (participant:{cc}) = {final:.2f}"` (per contribution)
- **convergence_bonus は contribution に掛からない**（domain 合計への加算であり、個別寄与の乗数ではない）

**同一 signal が複数 contribution を生む仕様**: LLM signal `countries=["US","TW"], country_weights={"US":1.0,"TW":0.6}` が Taiwan Contingency に寄与する場合、US 経由と TW 経由の 2 contribution が独立に生成される(ADR-015 dual-weight)。signal_source dedup (ADR-007) は `(signal_source, contributing_country)` 単位で MAX。

---

## 7. スコアリングアルゴリズム

### 7.1 シナリオスコア計算(実装参照、ルール 8)

実装は `radar/scoring.py:compute_scenario_score()` (L1059)。

**寄与計算式** (per contribution):
- per-country: `contribution = signal.raw_score × signal.country_weights[country] × participant.weight`
- global signal (`signal.countries==[]`, ADR-022): `contribution = signal.raw_score × GLOBAL_SIGNAL_WEIGHT`

**処理順**: signals → contributions → `dedup_by_source_country_max()` (L1048, ADR-007) → domain aggregation with `DOMAIN_CAP` (ADR-022) → convergence bonus (within scenario) → `total_score = Σdomain + bonus` → focused のみ `derive_tl()` (L1021, ADR-008)。

**`scoring_mode`** は runtime 派生(`"full" if is_focused else "lite"`、ADR-019)。

**`formula_trace`** は contribution ごとに `"{raw:.2f} (raw) × {llm_cw:.2f} (llm:{cc}) × {pw:.2f} (participant:{cc}) = {final:.2f}"` 形式で残す(NP6 完全な導出開示)。

### 7.2 Convergence bonus 計算(実装参照)

実装は `radar/scoring.py:compute_convergence_bonus_scenario()` (L1012)。

| active domains | bonus |
|----------------|-------|
| 3 (FULL) | +2.0 |
| 2 (DUAL) | +1.0 |
| ≤1 | +0.0 |

将来拡張(複数 active_country による追加 boost)は ADR-012 meta-scenario layer の課題。

### 7.3 TL 判定式(実装参照)

実装は `radar/scoring.py:derive_tl()` (L1021)。閾値は §7.3.1 calibration の対象。

| TL | 条件 |
|----|------|
| TL1 | `total_score ≥ 9` かつ `physical_score ≥ 3.0` (physical degradation gate) |
| TL2 | `total_score ≥ 6` かつ `len(active_domains) ≥ 2` |
| TL3 | `total_score ≥ 4` |
| TL4 | `total_score ≥ 2` |
| TL5 | それ以外 |

**physical degradation の定義**: 暫定で「physical ドメイン合計 ≥ 3.0」。将来「N 参加国で物理センサーが degraded」へ厳格化可能(校正対象)。

### 7.3.1 TL 閾値の再校正計画(v1.2 追記)

**問題の所在**: 7.3 の TL 閾値(TL1≥9, TL2≥6, TL3≥4, TL4≥2)は既存 country 単位スコアリングから継承した値。しかし scenario 単位では、**同じ数値でも寄与構造が大きく異なる**:

- 既存(country 単位): TW 単独の signal だけで 6 点 → TL2
- 新(scenario 単位): TW + US + JP + CN 4 カ国の寄与合算で 6 点 → TL2

これは合算構造が異なるため、**scenario 単位では同じ閾値で TL が出やすくなる可能性が高い**。継承した閾値のままでは TL2/TL3 のインフレーションを起こし、警告値が希薄化するリスクがある。

**校正手順**:

| 段階 | タイミング | 作業 |
|------|---------|------|
| **ベースライン収集** | Phase 2 稼働開始から 2 週間 | 5 シナリオ × 24h ごとの score / domain breakdown / TL 分布を DB に記録。 |
| **閾値検証** | Phase 2 完了時点 | 記録した分布と既存 country 単位の同期間の分布を比較。TL3 以上の発火頻度が既存比で 2 倍以上になっていれば閾値再校正対象。 |
| **再校正実施** | Phase 5 実施中 | 運用ログとアナリストフィードバックをもとに TL1〜TL4 閾値を調整。調整は ADR を伴う変更として記録(ADR-022 以降を予約)。 |
| **回帰防止** | Phase 5 完了後 | `test_engine.py` に scenario 単位の expected TL テストを追加し、閾値変更時に必ず更新される構造にする。 |

**原則**: 閾値は「scenario あたり 1-2 週間に 1 回は TL4 以上が発火」「TL2 は月 1-2 回」「TL1 は四半期に 1 回以下」を目安とし、過剰発火は意味の希薄化、過少発火は検出力不足とみなす。具体値は Phase 5 で決定する。

### 7.4 scoring engine の依存方向

- `radar/scoring.py` は scenario データを直接 import しない
- 呼び出し側(`radar/routes/core.py`)が `scenarios.get(focused_id)` で `Scenario` オブジェクトを取得し、`compute_scenario_score(scenario, signals, is_focused)` を呼ぶ
- `scoring.py` は `Scenario` の dict-like インターフェースのみに依存(循環 import 回避)

### 7.5 edge cases

| ケース | 挙動 |
|--------|------|
| **scenario の participants が 0 件** | Phase 1 loader で unprocessable entity として起動失敗 |
| **focused_scenario が存在しない・disabled・paused** | `DEFAULT_FOCUSED_SCENARIO` にフォールバック。それも無効なら `enabled=true, state=active` の tier 1 先頭(`scenarios` table 順)。全滅時は 503 Service Unavailable |
| **enabled scenario が 0 件** | 起動 warning。API は空の `scenarios: {}` と警告メッセージを返す |
| **Layer 3 override で weight が 0.0** | participant を除外したのと同等に扱う |
| **Layer 3 override で weight が範囲外(負数/1.0超)** | Phase 1 loader と同じ CHECK を in-memory で適用。reject して warning ログ(v1.3 追加) |
| **signal.countries が空** | rationale に残すが scoring には寄与しない(UI debug 用) |
| **scoring 対象判定** | → ADR-011 参照(v1.3 追加) |

---

## 8. C-lite 実装仕様

### 8.1 動作概要

```
[fetch サイクル]
  global sensors (SensorTier.GLOBAL)        ─┐
                                              ├─→ 共通プール (全 scenario が参照)
  LLM intel sensors (SensorTier.GLOBAL)     ─┘

  per-country sensors (SensorTier.FOCUSED_ONLY)
      ───→ focused.participants の国だけ fetch

[scoring サイクル]
  for each enabled & active scenario:
      is_focused = (scenario.id == focused_id)
      collect signals where signal.countries ∩ scenario.participants
      compute_scenario_score(scenario, signals, is_focused)
```

### 8.2 センサー分類(SensorTier)

| Tier | 意味 | Phase 1 初期所属 |
|---|---|---|
| **GLOBAL** | 国引数なしの global fetch。全 scenario が同じデータを参照 | GreyNoise, ThreatFox, CT log, Tor metrics, USGS, NASA FIRMS(global), GDELT, IHR, RSS narrative, Telegram mirror, GPS jamming, space weather, 全 LLM intel sensors(apt_intel, ground_osint, military_exercise, hacktivist_intel, hacktivist_news_sensor, diplomatic) |
| **FOCUSED_ONLY** | focused.participants の国のみ fetch。C-lite では background は fetch しない | Cloudflare Radar per-country, IODA, BGP routing per-country, OpenWeather, CheckHost, OpenSky per-airport, NOTAM per-FIR, RIPE Atlas, AIS チョークポイント, ISR hotspot, NASA FIRMS bbox |
| **BACKGROUND_ELIGIBLE** | Phase 1 時点では該当なし。C-medium 移行時に FOCUSED_ONLY から昇格 | (なし) |

### 8.3 background scenario の出力

ADR-008 に従い、TL を出さず、rationale は A 群由来のみを返す:

```json
{
  "scoring_mode": "lite",
  "tl": null,
  "score_lite": 4.1,
  "domains_lite": { "cyber": 0.8, "physical": 0.3, "info": 3.0 },
  "indicators": {
    "llm_intel_24h": 12,
    "active_countries": 4,
    "domain_signal_counts": {"cyber": 2, "physical": 1, "info": 9}
  },
  "contributions": [ /* A 群 signal 由来の ScenarioContribution のリスト */ ],
  "lite_bias_warning": "LITE mode: LLM intel + global signals only..."
}
```

`contributions` は C-lite でも返す(NP6 検証可能性)。ただし **per-country sensor 由来の contribution は含まれない**(該当データが fetch されていないため)。

### 8.4 既知の bias と HUD 表示要件

| Bias | 影響 | HUD 対応 |
|------|------|---------|
| **LLM/英語報道偏重** | 英語報道が多い地域(中東、ウクライナ)が過大評価 | カードに `LITE` バッジ + ツールチップで明示 |
| **Info domain 偏重** | per-country physical/cyber データが欠落 | indicators の domain_signal_counts で内訳表示 |
| **物理事象の盲点** | 演習、艦艇移動、兵站などが LLM に出るまで見えない | `lite_bias_warning` フィールドで明示、HUD で注意喚起バナー |

### 8.5 失敗モード

| 失敗 | 検出方法 | 対処 |
|------|---------|------|
| **物理 buildup の見逃し** | 後追い検証(focused 切替後の発覚) | 移行判定の入力(C-medium へ) |
| **LLM bias による誤誘導** | 重要事象の見逃し率の追跡 | LLM プロンプトの多言語化(将来課題) |
| **focused 切替の遅延** | アナリストフィードバック | 切替時の即時 fetch を最適化 |
| **focused_scenario 不在** | 起動時/実行時チェック | DEFAULT_FOCUSED_SCENARIO にフォールバック(7.5 節) |

### 8.6 データ鮮度表示

C-lite では background の per-country データは存在しないため:

```json
"data_freshness_per_country": {
    "TW": 287,   // focused、通常 fetch 済み
    "JP": 287,
    "US": 287,
    "UA": null,  // background country、C-lite では fetch されない
    "PL": null
}
```

HUD は `null` の国を「LITE mode: not fetched」として表示する。

---

## 9. C-medium 移行設計

### 9.1 C-medium とは何か

**変更点(C-lite からの差分)**:
- background scenario も per-country センサーを fetch する
- ただし fetch 頻度は低い(focused 5min / background 30-60min)
- 一部の重い B 群センサーは除外可能(per-sensor toggle)

**変更しない点**:
- データモデル(SQL スキーマ、LLM intel item 形式、Signal クラス)は完全に同じ
- scoring engine ロジックは同じ(`is_focused` フラグの扱いが変わるだけ)
- API レスポンス形式は同じ(`scoring_mode: "lite"` → `"medium"` または `"full"`)
- HUD は同じ(TL 表示の有無は ADR-008 の再評価次第)

つまり **C-medium 移行はアーキテクチャ変更ではなく、polling 層の拡張のみ**。

### 9.2 C-medium 実装の概要

#### (a) SensorTier enum(Phase 1 で導入済、ADR-017)

```python
class SensorTier(Enum):
    GLOBAL = "global"                    # 全 scenario が共有、country 引数なし
    FOCUSED_ONLY = "focused_only"        # focused.participants の国のみ
    BACKGROUND_ELIGIBLE = "background_eligible"  # focused + background 両方
```

**C-lite 時点(Phase 1〜5)**:
- A 群センサー → `GLOBAL`
- B 群・C 群センサー → `FOCUSED_ONLY`
- `BACKGROUND_ELIGIBLE` 使用なし

**C-medium 移行時**:
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

            if self._is_focused_sub_cycle():
                return sorted(focused_set)
            else:
                return sorted(background_set - focused_set)

    def _is_focused_sub_cycle(self) -> bool:
        """focused は 5min ごと、background は 30-60min ごと"""
        return (time.time() - self.last_background_fetch) < self.background_interval
```

#### (c) Per-sensor rate limit budget

```python
class BaseSensor:
    daily_quota: int | None = None  # None = 無制限
    quota_used_today: int = 0
    quota_reset_at: float = 0

    def can_fetch(self, n_targets: int) -> bool:
        if self.daily_quota is None:
            return True
        return self.quota_used_today + n_targets <= self.daily_quota
```

スケジューラは focused を優先的に処理し、quota が枯渇したら background をスキップ。

#### (d) Cache 鮮度の表示

```python
"data_freshness_per_country": {
    "TW": 287,    # focused, 5min ago
    "JP": 287,
    "US": 287,
    "UA": 1842,   # background, 30min ago
    "PL": 1842,
}
```

### 9.3 C-medium 移行判定基準

以下の **いずれか** が成立したら C-medium への移行を検討:

| 種類 | 基準 | 計測方法 |
|------|------|---------|
| **定量(検出力)** | background の見逃しが4週間で3件以上 | 後追い検証ログ |
| **定量(運用)** | focus 切替が平均 5回/日以上 | アナリスト操作ログ |
| **定量(余力)** | 主要センサーの quota 利用率が60%未満 | sensor stats |
| **定性(フィードバック)** | アナリストが「他のシナリオの状況も常時見たい」と要望 | 直接ヒアリング |

C-lite を継続すべき条件:
- 主要センサー(Cloudflare Radar, OpenSky, OpenWeather)の quota が80%以上利用済み
- 単独アナリスト運用で focus 切替が低頻度
- background TL が必要な状況が実際には発生しない

### 9.3.1 「見逃し」の定義と後追い検証手順(v1.2 追記)

移行判定基準の「4週間で見逃し3件以上」を運用可能にするための定義と手順。

**見逃し(miss)の定義**:
> 「focused scenario に切り替えた際に、**C-lite では検出不能だった** per-country signal が存在し、かつそれが TL を 1 段階以上変動させうる寄与量(≥ 1.0 contribution)を持っていたケース」

具体的には:
1. アナリストが background → focused に切り替える
2. 切替後の最初の full fetch で、新たに per-country sensor から得られた signal を記録
3. それらの signal を **切替前の** background scoring に仮投入し、score 差分を計算
4. score 差分 ≥ 1.0 かつ TL が変動する場合を「見逃し」としてカウント

**後追い検証の実装**:

```python
def record_focus_switch_delta(
    old_focused: str,
    new_focused: str,
    pre_switch_lite_score: float,
    post_switch_full_score: float,
    new_signals: list[Signal],
):
    """
    focus 切替時に呼ばれる。C-lite では見えなかった signal の
    scoring 影響を記録する。
    """
    lite_only_signals = [
        s for s in new_signals
        if s.sensor_tier == SensorTier.FOCUSED_ONLY
    ]
    hypothetical_contribution = sum(
        compute_contribution(s, scenario)
        for s in lite_only_signals
    )
    db.insert_focus_switch_log(
        scenario_id=new_focused,
        switched_at=time.time(),
        lite_score=pre_switch_lite_score,
        full_score=post_switch_full_score,
        delta=hypothetical_contribution,
        is_miss=(hypothetical_contribution >= 1.0),
    )
```

**集計テーブル**: `focus_switch_log`(Phase 2 で追加)

```sql
CREATE TABLE IF NOT EXISTS focus_switch_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL,
    switched_at REAL NOT NULL,
    lite_score REAL NOT NULL,
    full_score REAL NOT NULL,
    delta REAL NOT NULL,
    is_miss INTEGER NOT NULL DEFAULT 0
);
```

**reporting**: `/api/analytics/focus_switches` で過去 N 日間の miss 件数を返す。C-medium 移行判定は **このエンドポイントの出力を根拠** とする。

### 9.3.2 Shadow Sampling — focus 切替に依存しない観測（ADR-025, v1.7.0 追記）

§9.3.1 の判定機構は **アナリストが focus を切り替えた瞬間にのみ** データが生まれる構造であり、単独アナリスト運用では半永久的に `INSUFFICIENT_DATA` から抜け出せない構造的欠陥を抱えていた。この節は、その欠陥を埋めるために追加された background harness の仕様を記述する。

**目的**:
focused scoring サイクルが既に収集した `_signals` を再利用し、非-focused scenario のうち 1 件を per-cycle で選んで (lite, full) スコアペアを合成、`focus_switch_log` に `source='shadow_sampler'` として記録する。これにより:

- 新規 I/O ゼロ（LLM もセンサーも追加で叩かない）
- analyst の focus 切替に依存せず C-medium 評価データが蓄積される
- analyst 起源の行と区別可能（provenance 保存）

**選択アルゴリズム**:
1. `scenario_store.scorable()` から focused を除外した候補集合を作る
2. `SHADOW_SAMPLING_REQUIRE_OVERLAP=true` の場合、focused との participant 国オーバーラップ 0 の scenario を除外
3. `SHADOW_SAMPLING_MIN_GAP_SEC` 以内に既にサンプリングされている scenario を除外
4. 残った候補から `shadow_sampler_state.last_sampled_at` が最も古い scenario を選ぶ（未サンプル scenario は `-inf` 扱いで最優先）

これにより background scenario 全てが長期的には公平にカバーされる（round-robin LRU）。

**スコア計算（signal-identity invariant）**:
```python
lite_state = compute_scenario_score(target, signals, is_focused=False, ...)
full_state = compute_scenario_score(target, signals, is_focused=True,  ...)
```

`compute_scenario_score()` は純関数であり、同一入力に対し同一出力を返す。`is_focused` フラグは per-country 処理のみを変えるため、global signal だけで成立する scenario では `lite == full` となり delta=0 が観測される。この「delta=0 サンプル」自体が C-lite 十分性の有力な証拠となる（per-country signal の差分が無いため full 化しても見えるものが無い）。

**Miss 判定**:
`is_miss = delta >= C_MEDIUM_DELTA_MISS_SHADOW` (既定 1.4)。analyst 起源の `C_MEDIUM_DELTA_MISS` (既定 2.0) とは別閾値: shadow は analyst 起源のような「後追い full fetch」を経ずに signal set を共有しているため、同一条件下での delta は構造的に小さい。

**provenance カラム**:
- `source = 'analyst' | 'shadow_sampler'` — 起源を必ず保存
- `shadow_score_kind = 'piggyback'` — shadow の場合、今後 dedicated cadence 等が追加されたときの識別子枠

**Reporting**:
`/api/analytics/focus_switches`、`clite_evaluation`、`cmedium_recommendation` に `?source=` クエリパラメータを追加し、`all`（既定、混合）/`analyst`/`shadow_sampler` で絞り込める。UI 側が「shadow のみ表示」「analyst のみ表示」を切り替えられるようにする設計余地を残した。

**ADR-025 Invariants の実装マッピング**:
| Invariant | 実装上の担保 |
|-----------|-------------|
| I-1 TL 不変 | `shadow_sampler.py` は `derive_tl()` を import していない |
| I-2 sequence 不発火 | shadow path は `register_sequence_event()` を呼ばない |
| I-3 intel queue 不汚染 | shadow path は `intel_queue.submit()` / `.override_*()` を呼ばない |
| I-4 provenance 保存 | `focus_switch_log.source` NOT NULL, `DEFAULT 'analyst'` |
| I-5 決定論的等価性 | `compute_scenario_score()` は純関数 |
| I-6 並行性安全 | `ShadowSampler._lock: threading.Lock` で selection + insert を直列化 |
| I-7 stale 時 degraded | `if not signals: return None` で空サイクルをスキップ |

### 9.4 段階移行の手順

#### Step 1: 軽量センサーから開始
最初に `BACKGROUND_ELIGIBLE` に昇格すべきセンサー:
- BGP routing(RIPE Stat) — 公共 API、緩い制限
- IODA — 公共 API
- CheckHost — レート緩い

#### Step 2: 中量センサー
- Cloudflare Radar — 有料/auth key 前提

#### Step 3: 重量センサー
- OpenSky — quota 厳しい、注意深く
- OpenWeather — quota 厳しい

#### Step 4: 領域型センサー
- AIS、ISR、NASA FIRMS — bbox の組み合わせを最小化

各 step は **2週間の運用観察期間** を置き、quota と検出力の変化を確認してから次へ。

### 9.5 ロールバック戦略

| 問題 | 対処 |
|------|------|
| 特定センサーの rate limit 枯渇 | そのセンサーのみ `FOCUSED_ONLY` に戻す |
| 全体的な遅延 | background interval を 30min → 60min に延長 |
| 運用上の混乱 | `C_MEDIUM_ENABLED=false` で全 background を停止し C-lite に戻す |

ロールバックは **1コミット内で完了** すべき。

### 9.6 C-medium 移行時の ADR 再評価

- **ADR-008**: background TL を表示するか(C-medium では比較性が回復するので有効化検討)
- **ADR-002**: C-lite 採用の前提が満たされたか

---

## 10. 実装フェーズ

Phase 1〜5 は実装完了済(0 章「Phase 進行表」を参照)。詳細スコープ・完了条件は git 履歴に保持。本章は **Phase 完了サマリと未完了の運用評価項目のみ** を記載する。

### Phase 1〜5 完了サマリ

| Phase | 完了日 | 主成果 | 残課題 |
|-------|--------|--------|--------|
| **Phase 1** | 2026-04-12 | scenarios/Signal データモデル、5 プリセット、`/api/scenarios`、SensorTier 分類 | なし |
| **Phase 2** | 2026-04-12 | `compute_scenario_score()`、dedup、convergence_bonus、derive_tl、`/api/threat_data?focus=`、scenario_tl_observation | なし |
| **Phase 3** | 2026-04-13 | 7 LLM sensor の multi-country 化(一括変更、観察 OK)、`intel_queue.submit(countries, country_weights)`、migration v6 | なし |
| **Phase 4** | 2026-04-13 | scenario HUD カード、Scenario Manager(CRUD + lifecycle)、focus_switch_log、indicators、Layer 3 は Phase 5 へ繰り延べ | なし |
| **Phase 5** | 2026-04-14 | rationale 展開 UX、LITE/BIAS バッジ、what-if、evidence URL、deprecation ヘッダ、drill-down API、Layer 3 session overlay | TL 再校正(2026-04-28 期限)、ADR-015 dual-weight 評価(2026-05-12 期限)— 10.5 節参照 |

**テスト結果**: `python -m pytest test_engine.py -v` → 164 passed (2026-04-14)

**依然として Phase 5 完了後に再評価する項目(絶対期限付き)**:

| 項目 | 評価期限 | 観察ウィンドウ | 決定基準 → アクション |
|------|---------|--------------|--------------------|
| **TL 閾値再校正(§7.3.1)** | **2026-04-28** | Phase 5 完了(2026-04-14)から 14 日 | (a) `scenario_tl_observation` で TL3 以上の発火が country 単位の同期間比 2x 以上 → ADR-023 で閾値を引き上げ。 (b) TL2 が 月 1-2 回 / TL1 が 四半期 1 回以下に収まっていれば → 現閾値を確定として ADR-023 にコミット。 (c) サンプル不足(scenario あたり TL2 以上の事例が 5 件未満) → 期限を 2026-05-12 まで延長し再評価。 |
| **ADR-015 dual-weight 評価** | **2026-05-12** | Phase 5 完了(2026-04-14)から 28 日 | (a) 同一 LLM intel の再分析で `country_weights` の標準偏差が 0.20 を超える(標本 ≥ 20) → ADR-024 で single-weight にロールバック。 (b) `country_weights < 0.5` の寄与が全寄与件数の 30% 超 → 同上。 (c) アナリストが「country tag の根拠が弱い」として reject した intel が同期間の confirm 件数の 20% 超 → 同上。 (d) 上記 3 つすべてを下回れば → 現方式(LLM × participant)を確定として ADR-024 で Accepted のまま固定。 |

両方とも、評価期限を 1 度だけ 14 日延長することを許容(理由: 観察期間中に該当事象が発生しなかった場合のみ)。延長は本ドキュメントに「延長理由 + 新期限」として記録すること。

---

## 11. 将来課題(Open Questions と範囲外)

### 11.1 当面範囲外(Phase 5 完了後に再評価)

| 項目 | 理由 | 再評価トリガ |
|------|------|------------|
| **meta-scenario layer**(cross-scenario 相関)(ADR-012) | 複雑性が高い、まず単一 scenario の精度を上げる | Phase 5 安定運用後 |
| **シナリオ自動検出** | NP7(組織内ノード)違反: scenario 登録判断はアナリスト組織側の責務。ツール側 auto-suggestion は組織判断を肩代わりする | 運用で必要性が確認された場合 |
| **scenario テンプレート共有機構** | スコープ過大 | コミュニティ要求があれば |
| **LLM 多言語化(非英語 feed の充実)** | LLM bias 軽減の手段だが工数大 | bias による見逃しが問題化した場合(NP1 直接関連) |

### 11.2 意図的に実装しない(Out of Scope)

要望が出ても断る根拠。**旧版は「P5 違反」を理由に多くの項目を範囲外としていたが、本版は P5 を廃止したため、各項目の根拠を NP1〜NP7 で再定義した**。

| 項目 | 理由 |
|------|------|
| **scenario auto-suggestion** | **NP7(組織内ノード)違反**: シナリオ登録は組織判断の対象。ツール側で suggestion を出すと組織判断を肩代わりすることになる。ただし「shadow_sampler が拾った未登録 anomaly の通知」は NP1 の延長として将来検討余地あり(NP7 と矛盾しない範囲で) |
| **未来予測(forecasting)** | **NP5+8(品質規律)違反**: OSINT のみで forecasting 結論の calibration を満たせない(永続的に `INSUFFICIENT_DATA` になる構造) |
| **自律行動(自動ブロック等)** | **NP7(組織内ノード)違反**: 本ツールは判断ノードであり実行ノードではない。実行は組織プロセスの別ノードが行う |
| **ML ベースのスコアリング** | **NP6(全面開示)違反**: 検証経路が「重み行列を学習した」で終わってしまい、analyst が原典まで遡れない |
| **商用 threat intel 統合** | 拘束① 違反(OSINT 限定) |
| **scenario テンプレートマーケットプレイス** | スコープ過大 |

### 11.3 残 Open Question(Phase ごとに決定)

| Q | 論点 | 決定期限 |
|---|------|--------|
| **OQ-1** | `DEFAULT_FOCUSED_SCENARIO` を環境変数で設定可能にするか、DB で設定するか | Phase 1 実装時 |
| **OQ-2** | C-lite の `domains_lite` を UI で表示するか(scoring mode 間の混同リスク) | Phase 4 実装時 |
| **OQ-3** | Layer 3 session override を URL param(`?override=...`)で渡すか、temporary UI control で渡すか | Phase 4 実装時 |
| **OQ-4** | 動的編集の反映タイミング — (a) 次 scoring サイクル、(b) 即時キャッシュ無効化、(c) 明示的 re-compute | Phase 4 実装時(推奨: a) |
| **OQ-5** | Phase 1 のシナリオ投入数 — (a) 5 シナリオ一括(現計画)、(b) Taiwan Contingency のみで動作確認後に Phase 2 完了後に残り 4 追加 | Phase 1 着手時 |
| **OQ-6** | 設計 W(ADR-026)の opt-in → default-on 移行判定基準 — (a) shadow phase で `weight_calibration_log` の adjustment_factor が ±15% 以内に収束、(b) opt-in phase で 3 scenario 以上が 14 日以上連続有効化、(c) analyst override / reset 件数が calibration 件数の 20% 以下、の 3 条件全て満たしたら default-on へ。複数条件のうちどれを必須/推奨とするか | ADR-026 opt-in phase 完了時 |

**OQ-5 の背景(v1.2 追記)**:
5 シナリオ一括は設計検証の幅が広いが、Phase 1 の完了条件(loader、validator、migration、SensorTier、test)が 5 シナリオ分の組み合わせを要求するため工数が膨らむ。代替案として **1 シナリオ(taiwan_contingency)のみで Phase 1-2 を完走** し、scoring engine の動作を実証した後に残り 4 シナリオを追加する段階化が考えられる。
- **一括のメリット**: 対称紛争(middle_east, core_country=null)や disabled(south_china_sea)の edge cases を Phase 1 で早期検証
- **段階化のメリット**: Phase 1 の完了条件を絞り込み、早期に Phase 2 へ進める。edge cases は Phase 2 完了後に追加テストで対応
- **推奨**: Phase 1 で 5 シナリオの **geo_data.json 定義とloader** は全て実装するが、**scoring engine のテストは taiwan_contingency + middle_east(core_country=null の edge case)の 2 シナリオ** に絞る。残り 3 シナリオの scoring テストは Phase 2 で追加

---

## 12. リスク登録簿

| ID | リスク | 影響 | 確率 | 対策 |
|----|-------|------|------|------|
| **R1** | LLM プロンプト変更で intel 品質劣化 | 検出力低下 | 中 | 1センサーずつ段階的変更、観察期間、ロールバック手順 |
| **R2** | DB migration の失敗 | データ消失 | 低 | dry-run, バックアップ必須, ロールバック手順、既存テーブルは ALTER のみ(DROP 禁止) |
| **R3** | rate limit 計算ミス(Phase 1 で誤って quota 超過) | センサー停止 | 低 | C-lite では既存 quota と同等、影響小 |
| **R4** | 用語置換が中途半端で混乱 | コード品質低下 | 中 | Phase 1 では最小限、置換は段階的 |
| **R5** | アナリストが新 HUD に適応できない | 採用失敗 | 中 | Help Guide 更新 + 旧 view を deprecated として並行運用 |
| **R6** | scenario 設定の動的変更で履歴が壊れる | 過去データの解釈不能 | 中 | scenario_change_log で変更履歴を保持、Layer 2 変更は admin 承認 |
| **R7** | C-lite の bias でアナリストが他シナリオを過小評価 | 重要事象の見逃し | 高 | LITE バッジを目立たせる、`lite_bias_warning` を HUD で常設、Help Guide で注意喚起 |
| **R8** | 後方互換 API のメンテ負荷 | 開発速度低下 | 中 | Phase 5 完了から3ヶ月後に旧 API を削除、事前に deprecation ヘッダで通知 |
| **R9** | role enum の追加漏れで geo_data.json のロードエラー | 起動失敗 | 低 | CI で validate、ADR 追加を強制 |
| **R10** | LLM country_weights の過学習(1つのニュース記事で過剰な TW 関連度を主張) | TL 過大評価 | 中 | country_weights の上限を 1.0 に、observation で監視、必要ならプロンプトに抑制条項 |
| **R11** | signal_source dedup の複合キー変更で既存テスト破壊 | test 失敗 | 中 | Phase 2 で既存テストの期待値を更新 |
| **R12** | sequence_events の scenario_id 移行で既存イベントが null のままになる | 将来データ解析の断絶 | 低 | ADR-018 に従い意図的に許容、UI で「scenario 単位履歴開始日」を明示 |
| **R13** | GLOBAL_SIGNAL_WEIGHT / DOMAIN_CAP の初期値が不適切で scenario score が過大/過小 | TL 精度低下 | 中 | Phase 2 ベースライン計測で校正。初期値は保守的(0.5 / 6.0) |
| **R14** | domain weight 廃止(ADR-021)により info 偏重が悪化 | background scenario の score_lite が info に支配される | 中 | DOMAIN_CAP で安全弁、Phase 2 計測で判明時に domain weight 再導入を ADR で検討 |
| **R15** | 設計 W(ADR-026)の auto calibration が暴走し participant weight が分布的に偏る | TL の系統的な過大/過小評価、analyst の戦略的アンカーが無視される | 中 | (1) `adjustment_factor ∈ [0.7, 1.3]` の hard clip、(2) EMA α=0.1 で 1 cycle 最大 ±3%、(3) ゲート G1〜G5 の AND 条件で更新ゲーティング、(4) shadow → opt-in → default-on の段階展開、(5) `weight_calibration_log` で全イベント追跡、(6) analyst override / reset / 一時停止が常時可能。万が一 default-on 後に問題化したら `WEIGHT_CALIB_MODE='shadow'` への即時 rollback で全 scenario の adjustment を 1.0 固定に戻せる |

---

## 13. ドキュメント運用ルール

このドキュメントを腐らせないために、以下のルールを **厳守** する。

### ルール 1: Phase 完了時に必ず更新
Phase 完了コミットには **必ず** このドキュメントの「Phase 進行表」と各 Phase の完了条件チェックリストを更新する。完了条件が満たされていない Phase は完了とみなさない。

### ルール 2: 設計から外れる変更には ADR を追加
実装中に「設計と違うやり方が良い」と気づいた場合、コードを変える前に **ADR を追加** して理由を記録する。事後ではなく事前に。ADR の番号は連番(ADR-023, ADR-024, ...)。

### ルール 3: Open Question は決まったら ADR に昇格
OQ-1 〜 等は決定された瞬間に Open Questions セクションから削除し、ADR として永続化する。

### ルール 4: 用語定義はコードと同期
変数名・関数名・SQL カラム名が用語定義と食い違ったら **コード側を直す**(ドキュメントを変えるのではない)。

### ルール 5: ADR を覆すときは Supersedes 関係を明示
将来 ADR を覆す場合、新 ADR の冒頭に `Supersedes: ADR-xxx` と書き、旧 ADR の冒頭に `Superseded by: ADR-yyy` と追記する。削除はしない。

### ルール 6: このドキュメントは1ファイルで完結する
分割しない。検索性と一覧性を優先する。2000 行を超えそうになったら章構成を見直す。

### ルール 7: 数値例は式と一緒に書く
本ドキュメント内の数値例(スコア、重み、計算結果)は必ず式と共に記載する。式なしで数字だけ書かない(6.5 API レスポンスの「検算」節のように)。

### ルール 8: 実装完了した仕様は実コード参照に圧縮する
Phase N の完了時に、その Phase で実装された **疑似コード・SQL スキーマ・API レスポンス例・データクラス定義** は、実ファイルへの参照に置き換えて圧縮する。
- 形式: `→ 実装: radar/scoring.py:compute_scenario_score() を参照`
- 圧縮前の疑似コードは git 履歴に残るため情報は失われない
- **ADR・設計判断・計算式の説明文** は圧縮対象外(長命な設計知識)
- 目的: 疑似コードと実コードの二重管理を防止し、ルール 6 の 2000 行上限を維持する

### ルール 9: 各情報の正規定義箇所は 1 つ、他は参照
同じ情報が複数箇所に現れる場合、**正規の定義箇所(canonical location)を 1 つだけ持ち**、他は `→ X 章参照` で済ませる。変更時は正規箇所のみ更新すればよい。正規箇所は以下の表で管理する:

| 情報 | 正規定義箇所 |
|------|------------|
| scoring 計算式 | 7.1 節 |
| Signal.countries の規約 | ADR-022 |
| Signal データクラスのフィールド | 6.3 節 |
| enabled と state の意味論 | ADR-011 |
| Role enum | 4.3 節 |
| TL 閾値 | 7.3 節 |
| scenario JSON スキーマ | 6.1 節 |
| GLOBAL_SIGNAL_WEIGHT / DOMAIN_CAP | ADR-022 |

---

## 14. セッション開始チェックリスト

**新しいセッションで Claude が最初にやること**:

1. このドキュメント(`docs/design/scenario-refactor.md`)を読む
2. Phase 進行表で現在の Phase を確認
3. Open Questions(11.3節)を確認(未決事項があればユーザーに確認)
4. 直前の commit log(`git log -10 --oneline`)を確認
5. 該当 Phase の完了条件を再確認
6. 必要なら関連ファイル(`CLAUDE.md`, `geo_data.json`, `radar/scenarios.py` 等)を読む

**ユーザーが Claude に指示する際の推奨書式**:
> 「scenario-refactor の Phase 2 を進めて」
> 「設計ドキュメントの ADR-005 を再評価したい」
> 「Open Question OQ-1 について決めたい」

---

## Appendix A: 既存実装からの差分マッピング

| 既存ファイル | 既存の概念 | 新しい概念 | 変更時期 |
|------------|----------|----------|---------|
| `radar/config.py` | `DEFAULT_CORE = "TW"` | `DEFAULT_FOCUSED_SCENARIO = "taiwan_contingency"` | Phase 1 |
| `radar/config.py` | `DEFAULT_CORRELATES` | scenario.participants から導出 | Phase 1 |
| `radar/config.py` | `DEFAULT_PINS` | scenario プリセット | Phase 1 |
| `radar/routes/core.py` | `core_theater` 変数 | `focused_scenario` | Phase 2 |
| `radar/routes/core.py` | `correlate_targets` | `scenario.participants.keys()` | Phase 2 |
| `radar/routes/core.py` | per-country scoring loop | scenario scoring loop | Phase 2 |
| `radar/routes/core.py` | `register_sequence_event(theater, ...)` | `register_sequence_event(scenario_id, country, ...)` | Phase 2 |
| `radar/intel_queue.py` | `theater: str` | `countries: list[str], country_weights: dict[str, float]` | Phase 3 |
| `radar/sensors/apt_intel.py` 他 LLM | `theater = data.get("theater")` | `countries = data.get("countries", [])` + `country_weights` | Phase 3 |
| `radar/sensors/base.py` | tier 属性なし | `tier: SensorTier = GLOBAL | FOCUSED_ONLY` | Phase 1 |
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
| 結合重み | participant weight | `weight`, `participant_weight` |
| LLM 関連度 | LLM country weight | `country_weights`, `llm_country_weight` |
| 役割 | role | `role`(enum) |
| 寄与 | contribution | `contribution`, `ScenarioContribution` |
| 攻撃側 | adversary | `role == Role.ADVERSARY` |
| 採点モード | scoring mode | `scoring_mode`(ランタイム) |
| シナリオ状態 | scenario state | `state`(`active`/`paused`/`archived`) |

**Role 日本語ラベル**(i18n 用):

| Role(enum 値) | 日本語 | 英語 |
|--------------|--------|------|
| `primary_target` | 主要対象 | Primary Target |
| `principal_belligerent` | 主要当事者 | Principal Belligerent |
| `adversary` | 攻撃側 | Adversary |
| `primary_ally` | 主要同盟国 | Primary Ally |
| `forward_base` | 前線基地 | Forward Base |
| `secondary_ally` | 二次同盟国 | Secondary Ally |
| `extended_deterrence` | 拡張抑止 | Extended Deterrence |
| `strategic_observer` | 戦略的監視 | Strategic Observer |
| `proxy_front` | プロキシ戦線 | Proxy Front |
| `force_projection` | 戦力投射 | Force Projection |
| `secondary_party` | 副次当事者 | Secondary Party |
| `spillover_risk` | 波及リスク | Spillover Risk |
| `regional_power` | 域内パワー | Regional Power |

**命名規則**:
- scenario_id: snake_case, lowercase, ASCII, 3-30 chars (`^[a-z][a-z0-9_]{2,29}$`)
- country code: ISO 3166-1 alpha-2, uppercase (`TW`, `JP`)
- role: snake_case, lowercase, enum 値 (`primary_target`)
- API パラメータ: snake_case (`?focus=taiwan_contingency`)
- DB テーブル: snake_case 複数形 (`scenarios`, `scenario_participants`)

---

## Appendix C: 参加国重みのルブリック

`scenario.participants[X].weight` の初期値を決めるときの基準:

| weight | 意味 | 該当 role の例 |
|--------|------|--------------|
| **1.0** | 直接の当事国 | PRIMARY_TARGET, PRINCIPAL_BELLIGERENT |
| **0.8** | major ally with forward bases / 主要当事者に準ずる | PRIMARY_ALLY, FORWARD_BASE(米軍基地・前線基地保有) |
| **0.7** | major adversary / 主要敵対国 | ADVERSARY(主要) |
| **0.6** | secondary ally / proxy front / 条約同盟だが基地なし | SECONDARY_ALLY, PROXY_FRONT, FORCE_PROJECTION(副次) |
| **0.5** | coalition partner / proxy 副次 | 集団防衛枠組み参加、SPILLOVER_RISK |
| **0.4** | strategic observer / extended deterrence | STRATEGIC_OBSERVER, EXTENDED_DETERRENCE, SECONDARY_PARTY |
| **0.3** | peripheral actor / regional power | REGIONAL_POWER(限定的関与) |
| **<0.3** | **追加しない** | ノイズ寄与の方が大きくなる可能性 |

**運用原則**:
- シナリオあたり **6-10 participants** が望ましい
- 校正は ±0.1 刻みで実施、大幅な変更は ADR を伴う
- 同じ国が複数シナリオに異なる重みで登場するのは正常

---

## 改訂履歴

| 日付 | Ver | 変更概要 | commit |
|------|-----|---------|--------|
| 2026-04-11 | 1.0.0 | 初版。ADR-001〜008、データモデル、4 シナリオ想定 | `e7e321b` |
| 2026-04-12 | 1.1.0 | Phase 0 完了。ADR-009〜020 追加、5 シナリオ確定、Signal クラス導入、scoring 疑似コード全面改訂 | `e7e321b` 内 |
| 2026-04-12 | 1.2.0 | 批判的レビュー。ADR-015 リスク注記、TL 再校正計画(7.3.1)、C-medium 見逃し定義(9.3.1)、工数現実化、OQ-5 追加 | `198a0c2` |
| 2026-04-12 | 1.3.0 | 数理・一貫性修正。formula_trace 数値修正、enabled/state 意味論確定、ADR-021(domain weight 廃止)、ADR-022(global signal 規約 + DOMAIN_CAP) | `a03f628` |
| 2026-04-12 | 1.3.1 | 文書保守性改善。ルール 8(実装完了→実コード参照に圧縮)、ルール 9(正規定義箇所の一元化)追加。改訂履歴を圧縮、冗長箇所を正規定義への参照に置換(約 30 行削減) | — |
| 2026-04-20 | 1.6.0 | ADR-023(LLM intel age-decay τ=12h 指数関数減衰)追加。confirm cliff / TTL cliff 解消。TTL 48h に延長、cap は decayed score でランク | — |
| 2026-04-21 | 1.6.1 | EVIDENCE/CHAIN UI Phase A/B/C-1。`resolveChainTargetCountry()` 経由化、`test_ui_integrity.py` 追加 | `ef77580` 他 |
| 2026-04-21 | 1.6.2 | フロント `core_theater` 直参照 全 15 箇所をヘルパー経由に統一移行。ADR-005 フロント移行完了 | — |
| 2026-04-21 | 1.6.3 | P1/P2 observability 実装(`/api/analytics/*`、session overlay、SHOW_BACKGROUND_TL、12 センサー SensorTier 宣言、HUD オーバーレイ化、rss_narrative 第一信号修正) | `018f099` 他 |
| 2026-04-21 | 1.6.4 | NARRATIVE_GEO_TERMS に 7 参加国追加(AU/GU/IQ/MY/RO/SK/VN)。クロスシアター誤帰属解消 | `efd47f2` |
| 2026-04-21 | 1.6.5 | CTLog self-healing(degraded モード自動遷移、`upstream_health()` API)+ Layer 3 session overlay UI 実装(ADR-003 完全実装) | — |
| 2026-04-21 | 1.6.6 | ADR-024 追加: CTLog 上流耐障害性。失敗モード 6 種に細分化、サイレント 5xx 修正。Tier 1 基盤(`_require_analyst()`、migration v10 shadow_eval_log) | — |
| 2026-04-23 | 1.6.7 | TL/dual-weight 評価に絶対期限と決定基準付与(10.5 節)。Calidog certstream の 60s close を確認し既定 false 化、watchdog 追加。Upstreams 管理タブ追加 | — |
| 2026-04-25 | 1.8.0 | **ツール定義のブラッシュアップに伴う設計原則の全面改訂**。CLAUDE.md の 4 文定義(NP4 結論最大化への舵切り)に整合させ、Section 1 を 1 文 → 4 文に置換、Section 3 の P1〜P5 を NP1〜NP7 に全面書換(優先度ピラミッド + 旧呼称マッピング表を併設)。**旧 P5(ツールは判断しない)を完全廃止**し、NP4(結論最大化) + NP7(組織内ノード) で責務を分担。ADR-025 の根拠を P5 → NP4/NP5+8 に再定式化(「観察可能性 > 自動化」→「自動化は許容、観察可能性は不可欠」)。ADR-026 新規追加: 設計 W = participant weight の制約付き自動 calibration(`configured_weight × adjustment_factor`、adjustment ∈ [0.7, 1.3] hard clip、5 ゲート AND 条件、shadow → opt-in → default-on 段階展開、shadow_sampler 再利用、analyst override 常時可能)。Out of Scope の根拠を P5 違反 → NP4/NP6/NP7 で再定義。OQ-6 と R15 を追加。散在する P1〜P5 参照を NP 系に置換 | TBD |
| 2026-04-25 | 1.8.1 | **ADR-009 follow-up Stage 1+2 完了**。dual-core scenario の sequence event を per-country 7 種類 + scenario-wide 2 種類で対称登録(NARRATIVE_BURST / SYNC_DDOS / FIRMS_ANOMALY / ISR_SURGE / AIS_DARK_GAP / NOTAM_SURGE / OONI CENSORSHIP / MIL_AIR_SURGE / Tor+IHR CENSORSHIP)。pure helper `resolve_seq_fire_targets()` と `select_secondary_ec_hits()` を `radar/scoring.py` に追加(各々 8 テスト)。設計判断: per-country 系はデータ存在ベース(NP6 honest provenance を NP1 sensitivity に優先)。F (weight_advisory + secondary_ecs API + confidence histogram) / E (scenario_contribution_log retention) / C (weight_advisory timeseries) / D (shadow_drift detection) も併せて完了 | `437e86c`〜`761f4e4` |

---

**END OF DOCUMENT**
