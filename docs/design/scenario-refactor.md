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
| **現バージョン** | 1.3.1 |
| **作成日** | 2026-04-11 |
| **最終更新** | 2026-04-12 |
| **現在のフェーズ** | **Phase 0 完了、Phase 1 着手準備完了** |
| **採用方針** | **C-lite** で開始、運用知見をもとに **C-medium** へ進化 |
| **責任者** | kamonegi13(@juzo1192) |
| **想定総工数** | 約 22-28 日(Phase 1〜5、v1.2 で現実化)|

### Phase 進行表

| Phase | 概要 | 状態 | 完了日 |
|-------|------|------|--------|
| **Phase 0** | 設計確定、ドキュメント整備 | **完了** | 2026-04-12 |
| **Phase 1** | シナリオデータモデルと用語整理 | **着手準備完了** | — |
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
- 寄与の重みは `scenario.participants[country].weight` で定義
- アナリストが手動で関連付けを行う必要はない

### P3: スコア合成式は完全に透明
**根拠**: 拘束③④
**意味**:
- スコアは展開可能な積和式で構成される（→ 正規定義: 7.1 節）
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
  - 計算過程: `value × llm_weight × participant_weight = contribution`
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

**Status**: Accepted (2026-04-11)
**Context**: 既存の `core_theater` は「最高スコアの国を選ぶロジック」と「アナリストが宣言した主要対象国」の2つの意味で混在使用されていた。
**Decision**: `core_theater` を廃止し、`focused_scenario` に置き換える。意味は「アナリストが現在フォーカスしているシナリオ ID」。
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
- ✅ P4(検証可能性)を保てる(履歴を不用意に失わない)
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
**Context**: 既存設計では `adversaries: list[str]` を participants と別フィールドで保持し、scoring に算入していなかった。しかし「CN の cyber 動員」は Taiwan Contingency の重要な前兆であり、scoring に算入されないのは設計原則 P2 に反する。
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
- 計算式は rationale の `formula_trace` に完全に記録される(P4)
**Consequences**:
- ✅ LLM 判断と analyst 判断の両方が scoring に反映
- ✅ P3 の透明性を保ちつつ、より精度の高いスコアリング
- ⚠️ LLM プロンプトで country_weights を返させる必要(Phase 3)
- ⚠️ 既存 test は両方の weight を考慮した期待値に更新

**リスク注記(v1.2 追記)**:
この ADR は **将来 single-weight 方式に後退する選択肢を残す** 形で Accepted している。以下の懸念を Phase 2-3 の実運用で観察する:

1. **LLM 非決定性**: 同じ記事を別時刻に再分析すると `country_weights` が変わりうる。これは signal.raw_score に直接掛かるため、scoring 安定性の外乱源になる。
2. **ハルシネーション**: LLM が「TW に関連あり」と 0.8 を返した根拠が原典に無い場合、scoring が過大化する。拘束④(検証可能)を守るには `llm_reasoning` と evidence URL を厳密に保持する必要がある。
3. **P3(透明性)との緊張**: 「なぜ TW 経由が 0.6 で US 経由が 1.0 なのか」の問いに対して「LLM がそう判定したから」という答えは、直接性を弱める。アナリストにとっての可読性を Phase 4 の HUD 設計で実証する必要がある。
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
- 既存履歴は **破棄せず保持**(P4: 過去の検証可能性)
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
1. participant weight がすでに「この国の観測はどれだけ重要か」を表現しており、domain weight との二重の重み付けは P3（透明性）を損なう
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
- **global sensor の LLM**: `countries` は **LLM が判定した関連国のみ**（全 participant を列挙しない）。LLM が特定国に帰属させた根拠が必要（P4）

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

**change_log のリテンション**: 永続保持(P4 重視、変更頻度が低いためサイズ問題は発生しない)。

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
    evidence_url: str | None               # 原典 URL(P4)
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
      "score": 6.4,
      "domains": {
        "cyber": 3.2,
        "physical": 1.2,
        "info": 1.0
      },
      "convergence_bonus": 1.0,
      "active_countries": ["TW", "US", "JP"],
      "contributions": [
        {
          "rationale": { /* RationaleEntry */ },
          "contributing_country": "US",
          "llm_country_weight": 1.0,
          "participant_weight": 0.8,
          "participant_role": "primary_ally",
          "final_contribution": 2.4,
          "formula_trace": "3.0 (raw) × 1.0 (llm:US) × 0.8 (participant:US) = 2.4"
        },
        {
          "rationale": { /* RationaleEntry — same signal, TW route */ },
          "contributing_country": "TW",
          "llm_country_weight": 0.6,
          "participant_weight": 1.0,
          "participant_role": "primary_target",
          "final_contribution": 1.8,
          "formula_trace": "3.0 (raw) × 0.6 (llm:TW) × 1.0 (participant:TW) = 1.8"
        }
      ],
      "data_freshness_sec": 287
    },
    "eastern_europe": {
      "id": "eastern_europe",
      "name": "Eastern Europe",
      "is_focused": false,
      "scoring_mode": "lite",
      "tl": null,
      "score_lite": 4.1,
      "domains_lite": {
        "cyber": 0.8,
        "physical": 0.3,
        "info": 3.0
      },
      "indicators": {
        "llm_intel_24h": 12,
        "active_countries": 4,
        "domain_signal_counts": {
          "cyber": 2,
          "physical": 1,
          "info": 9
        }
      },
      "contributions": [ /* C-lite 下でも A 群 signal 由来の寄与を返す */ ],
      "lite_bias_warning": "LITE mode: LLM intel + global signals only. Physical and per-country cyber signals are not observed.",
      "data_freshness_sec": 287
    }
  },
  "global_data_freshness_sec": 287,
  "scenario_history_starts_at": 1681000000
}
```

**重要な数値の検算**(P3):
- `sum(domains) = 3.2 + 1.2 + 1.0 = 5.4`
- `score = sum(domains) + convergence_bonus = 5.4 + 1.0 = 6.4` ✓
- contributions の `formula_trace` は `raw_score × llm_country_weight × participant_weight = final_contribution` の形式。**convergence_bonus は contribution には掛からない**（domain 合計への加算であり、個別寄与の乗数ではない）
- 上記例の 2 contributions(US 経由 2.4 + TW 経由 1.8 = 4.2)はサンプルの一部。実際の domains 合計 5.4 には他の contributions も含まれる

**同一 signal が複数 contribution を生む仕様**:

LLM signal `countries=["US","TW"], country_weights={"US":1.0,"TW":0.6}` が Taiwan Contingency に寄与する場合:
- US 経由の contribution: `raw × 1.0 × 0.8 (US participant)`
- TW 経由の contribution: `raw × 0.6 × 1.0 (TW participant)`

これは **二重計上ではなく仕様**(同じ事象が複数 country 経由で影響するモデル)。
ただし signal_source dedup(ADR-007)で `(signal_source, contributing_country)` 単位で MAX される。

---

## 7. スコアリングアルゴリズム

### 7.1 シナリオスコア計算(疑似コード)

```python
def compute_scenario_score(
    scenario: Scenario,
    all_signals: list[Signal],
    is_focused: bool,
    global_config: ScoringConfig,
) -> ScenarioState:
    """
    Compute scenario-level score from country-tagged signals.

    Formula (per contribution):
        contribution = signal.raw_score
                     × signal.country_weights.get(country, 1.0)
                     × participant.weight
    """
    contributions: list[ScenarioContribution] = []

    for signal in all_signals:
        if not signal.countries:
            # Global signal (ADR-022): flat contribution, no country attribution
            final = signal.raw_score * GLOBAL_SIGNAL_WEIGHT
            contributions.append(ScenarioContribution(
                rationale=RationaleEntry(signal=signal, suppress_reason=None),
                contributing_country="GLOBAL",
                llm_country_weight=1.0,
                participant_weight=GLOBAL_SIGNAL_WEIGHT,
                participant_role="global",
                final_contribution=final,
                formula_trace=(
                    f"{signal.raw_score:.2f} (raw) "
                    f"× {GLOBAL_SIGNAL_WEIGHT:.2f} (global) "
                    f"= {final:.2f}"
                ),
            ))
            continue

        for country in signal.countries:
            if country not in scenario.participants:
                continue

            participant = scenario.participants[country]
            llm_cw = signal.country_weights.get(country, 1.0)
            final = signal.raw_score * llm_cw * participant.weight

            contributions.append(ScenarioContribution(
                rationale=RationaleEntry(signal=signal, suppress_reason=None),
                contributing_country=country,
                llm_country_weight=llm_cw,
                participant_weight=participant.weight,
                participant_role=participant.role.value,
                final_contribution=final,
                formula_trace=(
                    f"{signal.raw_score:.2f} (raw) "
                    f"× {llm_cw:.2f} (llm:{country}) "
                    f"× {participant.weight:.2f} (participant:{country}) "
                    f"= {final:.2f}"
                ),
            ))

    # Dedup: (signal_source, contributing_country) 単位で MAX (ADR-007)
    deduped = dedup_by_source_country_max(contributions)

    # Domain aggregation with per-domain cap (ADR-022)
    domains = {"cyber": 0.0, "physical": 0.0, "info": 0.0}
    for c in deduped:
        domains[c.rationale.signal.domain] += c.final_contribution
    for d in domains:
        domains[d] = min(domains[d], DOMAIN_CAP)

    # Convergence bonus (within scenario)
    active_domains = [d for d, s in domains.items() if s > 0]
    active_countries = set(c.contributing_country for c in deduped)
    convergence_bonus = compute_convergence_bonus(active_domains)

    total_score = sum(domains.values()) + convergence_bonus

    # Scoring mode is runtime, not scenario attribute (ADR-019)
    scoring_mode = "full" if is_focused else "lite"

    # TL judgement (focused のみ、background は None、ADR-008)
    if is_focused:
        tl = derive_tl(total_score, active_domains, domains["physical"])
    else:
        tl = None

    return ScenarioState(
        scenario=scenario,
        is_focused=is_focused,
        scoring_mode=scoring_mode,
        score=total_score,
        domains=domains,
        active_countries=sorted(active_countries),
        convergence_bonus=convergence_bonus,
        tl=tl,
        contributions=deduped,
    )


def dedup_by_source_country_max(
    contributions: list[ScenarioContribution],
) -> list[ScenarioContribution]:
    """
    (signal_source, contributing_country) 単位で MAX dedup.

    既存実装は signal_source 単位だったが、ADR-007 で複合キー単位に変更。
    異なる国で観測された同一 signal_source(例: BGP)は独立した事実として採用される。
    """
    best: dict[tuple[str, str], ScenarioContribution] = {}
    for c in contributions:
        key = (c.rationale.signal.signal_source, c.contributing_country)
        if key not in best or c.final_contribution > best[key].final_contribution:
            best[key] = c
    return list(best.values())
```

### 7.2 Convergence bonus 計算

既存の WeightedConvergenceEngine の bonus 仕様を継承:

```python
def compute_convergence_bonus(active_domains: list[str]) -> float:
    """
    - FULL (3 domains active): +2.0
    - DUAL (2 domains active): +1.0
    - SINGLE or empty:         +0.0

    将来拡張: 複数 active_country による追加 boost は ADR-012 の
    meta-scenario layer で再検討(現フェーズでは非実装)。
    """
    n = len(active_domains)
    if n >= 3:
        return 2.0
    if n == 2:
        return 1.0
    return 0.0
```

### 7.3 TL 判定式

```python
def derive_tl(
    total_score: float,
    active_domains: list[str],
    physical_score: float,
) -> int:
    """
    TL 判定(scenario 単位)。既存の閾値を継承。

    - TL1: score >= 9 かつ physical degradation(physical_score >= 3.0)
    - TL2: score >= 6 かつ active domains >= 2
    - TL3: score >= 4
    - TL4: score >= 2
    - TL5: それ以外
    """
    if total_score >= 9 and physical_score >= 3.0:
        return 1
    if total_score >= 6 and len(active_domains) >= 2:
        return 2
    if total_score >= 4:
        return 3
    if total_score >= 2:
        return 4
    return 5
```

**physical degradation の定義**: 上記式では「scenario の physical ドメイン合計が 3.0 以上」で代用。将来的に「N 参加国で物理センサーが degraded 状態」等のより厳格な判定に差し替え可能(Phase 2 以降の校正対象)。

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

`contributions` は C-lite でも返す(P4 検証可能性)。ただし **per-country sensor 由来の contribution は含まれない**(該当データが fetch されていないため)。

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

各フェーズは **完了条件を満たさなければ次に進まない**。Phase 完了時にこのドキュメントの「Phase 進行表」を更新する。

### Phase 1: シナリオデータモデルと用語整理(~4-5日)

**スコープ**:
- `geo_data.json` にプリセット5シナリオを追加(ADR-013 の通り)
- SQLite migration: `scenarios`, `scenario_participants`, `scenario_change_log`, `scenario_reserved_ids` テーブル追加、`sequence_events` に `scenario_id` カラム追加
- `radar/scenarios.py` モジュール新設
  - Scenario, Participant, Role の dataclass / enum
  - loader(geo_data.json → Layer 1、SQLite → Layer 2、HTTP session → Layer 3)
  - バリデータ(role enum、scenario_id 正規表現、weight 範囲、scenario 予約語)
- `radar/scoring.py` に `Signal` データクラスを追加
- `BaseSensor` に `tier: SensorTier` 属性を追加(全センサーに `GLOBAL` または `FOCUSED_ONLY` を付与)
- `radar/config.py` に `DEFAULT_FOCUSED_SCENARIO = os.getenv("DEFAULT_FOCUSED_SCENARIO", "taiwan_contingency")` を追加
- `/api/scenarios` GET エンドポイント追加(list のみ、CRUD は Phase 4)
- `CLAUDE.md` 用語セクションの追加(v1.1 で実施済)

**完了条件**:
- ✅ プリセット5シナリオ(Tier 1: 3、Tier 2: 2、SCS は disabled)が起動時にロードされる
- ✅ `/api/scenarios` が5件を返す(disabled を含む)
- ✅ SQLite migration が既存 DB を破損させずに実行される
- ✅ sequence_events の新カラムが追加され、既存レコードは scenario_id=null で読み込める
- ✅ 既存の `/api/threat_data` は引き続き動作(後方互換維持、旧 core_theater パラメータも受け付ける)
- ✅ test_engine.py の既存テストが全てパス
- ✅ `radar/scenarios.py` の単体テスト:
  - role enum バリデーション
  - scenario_id 正規表現
  - 予約語拒否
  - Layer 1/2 merge
  - core_country null 許容
- ✅ Signal クラスの単体テスト

**依存**: なし

**リスク**:
- R4: 既存コードの `theater` 参照が膨大で、段階的置換が進まない
  - → 対策: Phase 1 では用語置換は最小限、本格的な置換は Phase 2-4 で順次

### Phase 2: シナリオスコアリングエンジン(~4日)

**スコープ**:
- `radar/scoring.py` に `compute_scenario_score()`, `dedup_by_source_country_max()`, `compute_convergence_bonus()`, `derive_tl()` を実装
- `radar/routes/core.py` に scenario 単位の scoring loop を追加
- API `/api/threat_data` に scenario 形式のレスポンスを追加(旧形式と並行、`scenarios` キー追加)
- `?focus=...` パラメータの追加(旧 `?core=...` との両対応)
- drill-down 専用エンドポイント `/api/scenario/{id}/breakdown` を追加
- 既存センサーのデータ変換層: 既存の rationale 出力を `Signal` データクラスに変換するアダプタ
- sequence_events を scenario 単位に書き込むよう `register_sequence_event` を拡張(ADR-020)

**完了条件**:
- ✅ `/api/threat_data?focus=taiwan_contingency` がシナリオ単位 TL を返す
- ✅ background scenario には TL を出さず、indicators + contributions を返す
- ✅ 既存 API レスポンスとの後方互換が維持されている(deprecated フラグ付き)
- ✅ rationale/contribution に `evidence_url` と `formula_trace` が含まれる
- ✅ dedup が `(signal_source, contributing_country)` 単位で動作することを単体テストで確認
- ✅ 単体テスト: 5シナリオ × 各種シグナルパターン(enabled=false の SCS は scoring 対象外テスト含む)で期待値検証
- ✅ edge cases(focused 不在、participant 0件、signal.countries 空など)のテスト
- ✅ **二重カウント実証テスト(v1.2 追加)**: LLM signal `countries=["US","TW"], country_weights={"US":1.0,"TW":0.6}` を Taiwan Contingency に食わせ、US 経由と TW 経由の 2 つの contribution が生成され、両方が合算されることを確認(これは「仕様」として Accepted されているが、数値として確認)
- ✅ **adversary 寄与の検証(v1.2 追加)**: CN の threatfox signal(`countries=["CN"]`)が Taiwan Contingency の cyber スコアに `adversary weight 0.7` で寄与することを確認
- ✅ **TL ベースライン計測の開始(v1.2 追加)**: 7.3.1 節の再校正計画に従い、Phase 2 稼働開始後 2 週間にわたり 5 シナリオの score / domain / TL 分布を DB に記録する scheduler を組み込む(集計テーブル `scenario_tl_observation` を追加)

**依存**: Phase 1

### Phase 3: LLM プロンプトと intel queue の country 化(~8-12日)

**スコープ**:
- 6種類の LLM intel sensor のプロンプトを multi-country 出力に変更
  - apt_intel, ground_osint, military_exercise, hacktivist_intel, hacktivist_news_sensor, diplomatic
- **1センサーずつ段階的に変更**(全部一括ではない)、各変更後 1-2日の品質観察期間(v1.2: 6センサー × 実装1日+観察1-2日 = 12-18日だが、並行作業で圧縮。実質 8-12日を見込む)
- `intel_queue.submit()` の引数を `theater: str` → `countries: list[str], country_weights: dict[str, float]` に
- `RationaleEntry` を `Signal` ベースに移行
- LLM intel の dedup ロジックを multi-country 対応に(Jaccard 類似度 + countries の集合演算)
- DB スキーマ migration: 既存 LLM intel item の `theater` カラムを `countries` (JSON) と `country_weights` (JSON) に変換、既存データは `countries=[theater], country_weights={theater:1.0}` に補完

**完了条件**:
- ✅ LLM が `["US", "TW"]` のような multi-country タグを返す
- ✅ LLM が country_weights を返した場合、scoring に反映される
- ✅ LLM が country_weights を返さない場合、全て 1.0 で動作する
- ✅ 既存 LLM intel item の migration 後も読み込み可能
- ✅ 各センサーの品質観察期間を経て劣化がないことを確認
- ✅ scenario filter が集合演算で動作
- ✅ 統合テスト: 「Iranian APT exploit US PLCs」が `countries=["US","TW"]` でタグ付けされ、Taiwan Contingency の rationale に出現

**依存**: Phase 2

**リスク**:
- R1: LLM プロンプト変更で intel 品質劣化
- → 対策: 1センサーずつ段階的変更、観察期間、ロールバック手順を準備

### Phase 4: HUD のシナリオ単位再設計(~6-8日)

**スコープ**:
- `radar.js` の HUD レンダリングを scenario カード単位に
- focused scenario のフル詳細表示
- background scenario カード(LITE バッジ + indicators + bias warning)
- scenario 切替 UI(クリックで focus 変更、切替時にデータ再 fetch)
- Scenario Manager 管理画面(admin パネル内)
  - シナリオ一覧、編集、新規作成、delete/archive/restore、reset
  - participants の追加/削除/重み/role 調整(role は dropdown)
- Layer 3 セッション override UI(analyst 向け、URL param または temporary UI control で重みを一時変更)
- `i18n.js` に scenario 関連の翻訳キー追加(EN/JA)
  - scenario 名、役割ラベル、lifecycle state、bias warning
- `index.html` Help Guide Ch.8 (Intuition UI), Ch.9 (API Reference), Ch.10 (Admin) の更新

**完了条件**:
- ✅ HUD に focused scenario の詳細とその他 scenario カードが並列表示される
- ✅ クリックで focus 切替が可能
- ✅ admin が新規シナリオを作成・編集・delete・restore できる
- ✅ admin が purge(完全削除)できる(確認ダイアログ必須)
- ✅ analyst がセッション override で重みを一時変更できる
- ✅ disabled な SCS シナリオを enable できる(動的構成のデモ)
- ✅ EN/JA すべて翻訳済み、ハードコード文字列なし
- ✅ Help Guide が新 UI と整合

**依存**: Phase 2, Phase 3

### Phase 5: 検証 UX と bias インジケータ(~3日)

**スコープ**:
- rationale/contribution のクリック展開 UX
  - sensor, raw value, llm_country_weight, participant_weight, formula_trace, evidence URL の表示
  - LLM 由来の場合は llm_reasoning も表示
- background scenario の bias 警告表示
  - `lite_bias_warning` フィールドを目立たせる
  - domain breakdown (cyber/physical/info signal 件数)
- "what-if" 機能(特定 contribution を一時的に除外したらスコアがどうなるか)
- evidence URL のクリックで原典 fetch(新タブ)
- 旧 country-level API の deprecation ヘッダ付与

**完了条件**:
- ✅ すべての contribution が原典に追跡可能
- ✅ background scenario の表示に LITE バッジと bias warning が必ずある
- ✅ what-if が動作する
- ✅ Help Guide に「rationale の検証方法」の章が追加されている
- ✅ **TL 閾値の再校正完了(v1.2 追加)**: 7.3.1 節の校正手順に基づき、Phase 2 稼働開始後の TL 分布データを検証し、必要に応じて閾値を調整。調整を行った場合は ADR として記録
- ✅ **ADR-015 dual-weight 評価(v1.2 追加)**: Phase 2-3 で収集した LLM country_weights の観察指標(ADR-015 リスク注記参照)を評価し、問題があれば single-weight 方式への後退 ADR を起案

**依存**: Phase 4

---

## 11. 将来課題(Open Questions と範囲外)

### 11.1 当面範囲外(Phase 5 完了後に再評価)

| 項目 | 理由 | 再評価トリガ |
|------|------|------------|
| **meta-scenario layer**(cross-scenario 相関)(ADR-012) | 複雑性が高い、まず単一 scenario の精度を上げる | Phase 5 安定運用後 |
| **シナリオ自動検出** | P5 違反の懸念、シナリオ定義はアナリスト責務 | 運用で必要性が確認された場合 |
| **scenario テンプレート共有機構** | スコープ過大 | コミュニティ要求があれば |
| **LLM 多言語化(非英語 feed の充実)** | LLM bias 軽減の手段だが工数大 | bias による見逃しが問題化した場合 |

### 11.2 意図的に実装しない(Out of Scope)

要望が出ても断る根拠。

| 項目 | 理由 |
|------|------|
| **scenario auto-suggestion** | P5 違反(ツールは判断しない) |
| **未来予測(forecasting)** | P5 違反、また OSINT のみでは精度確保困難 |
| **自律行動(自動ブロック等)** | P5 違反 |
| **ML ベースのスコアリング** | P3 違反(透明性欠如) |
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

---

**END OF DOCUMENT**
