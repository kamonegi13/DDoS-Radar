# v2.0 UI 設計 — Conclusion Drill-down + Sensor Watchpane

> **このドキュメントの目的**
> v2.0 conclusions API 上に乗る analyst-facing UI の設計仕様。
> Phase 1.4 P2 で「最小スコープ (NP7 disclaimer banner のみ)」に絞った際、
> 残課題として deferred されたフロントエンド作業を統合的に設計する。
> 設計の上位根拠は [v2-migration.md](v2-migration.md) を参照。本書は UI 層の
> 単一情報源であり、コード側で UI 設計判断が必要になったら本書を直す
> (radar.js / index.html / radar.css のコメントを直すのではない)。

| 項目 | 値 |
|------|-----|
| 作成日 | 2026-04-26 |
| 状態 | DRAFT — Phase 2 着手前のレビュー待ち |
| 着手予定 | v2-migration.md **Phase 3** (UI と運用、2026-09-15 deadline)。Phase 2 (結論層 deriver) の進捗で前倒し可能 |
| 新セッションでまず読むもの | CLAUDE.md → v2-migration.md §0-§5 → 本書 |

---

## 1. 背景: Phase 1.4 P2 の縮小判断と Phase 2 への deferral

Phase 1.4 P2 当初プランは「v1 → v2 envelope 完全移行 (`adaptV2ToInternal()` shim 経由)」だった。実装直前の audit で以下が判明:

| 観点 | v1 envelope | v2 envelope (現在) |
|------|-------------|-------------------|
| フィールド系統 | 30+ (per-domain raw, sensor outputs, sequence_events 等) | 5 ConclusionType (THREAT_LEVEL, TREND, PER_DOMAIN, ANOMALY, ATTACK_MODE) |
| 表示できる粒度 | 信号レベル (raw values, deltas) | 結論レベル (TL=4, trend=ESCALATING) |
| アナリスト透明性 | UI 上に直接展開 | `audit_trace` endpoint 経由でのみ取得可能 |

直接 adapt すると UI の 8 割が "unavailable" placeholder になり、**NP4 (結論最大化)** に正面から反する。一方、UI を v1 並走のままにすると **NP6 (完全な導出開示)** が UI 上に届かず、結局 v2 conclusions API は "API として正しく出力されているが UI には現れない" 状態になる。

本書はこのジレンマを「結論カード + drill-down + 常設 sensor watchpane」の 3 層モデルで解消する。

---

## 2. 設計制約

| ID | 原則 | UI 設計への制約 |
|----|------|----------------|
| **NP1** | 感度優先 | アナリストがセンサー個別出力を即座に検査できる経路を **常時** 用意 (drill-down だけでは「結論レベルで隠された signal」を見落とす) |
| **NP4** | 結論最大化 | 結論カードは "現時点で技術的に出せる最大の結論" を一目で表示 (TL + trend + per-domain + anomaly + attack_mode の 5 種が並ぶ) |
| **NP5+8** | 結論品質規律 | calibration_status をカード内に常時表記 (結論不可は明示)。データ蓄積後の恒常的結論不可は赤バッジで強調 |
| **NP6** | 完全な導出開示 | 結論カード → drill-down 1 クリックで `audit_trace` (formula_ref + threshold_ref + source_urls + LLM prompt 全文) に到達可能。ステップ数が 2 を超える経路は禁止 |
| **NP7** | 組織内ノード | 各カード上部 + ページ常設バナー (Phase 1.4 P2 で実装済) で "Tool conclusion only — final judgment by organizational process" を表示 |

---

## 3. アーキテクチャ全体像

```
┌──────────────────────────────────────────────────────────────────┐
│  画面トップ: NP7 disclaimer banner (Phase 1.4 P2 実装済)        │
├──────────────────────────────────────────────────────────────────┤
│  Layer 1: Conclusion Cards (5 種、focused scenario あたり)       │
│    ┌────────────┬────────────┬────────────┬────────────┐         │
│    │THREAT_LEVEL│   TREND    │ PER_DOMAIN │  ANOMALY   │…        │
│    │  TL = 4    │ ESCALATING │ cyber:high │  3 active  │         │
│    │  conf .82  │  conf .71  │  phys:med  │            │         │
│    │ [drill ▶ ] │ [drill ▶ ] │ [drill ▶ ] │ [drill ▶ ] │         │
│    └────────────┴────────────┴────────────┴────────────┘         │
│         │           │            │            │                   │
│         └───────────┴────┬───────┴────────────┘                   │
│                          ▼                                        │
│  Layer 2: Drill-down Modal (audit_trace 統合)                    │
│    ┌────────────────────────────────────────────────────────┐    │
│    │ Conclusion: THREAT_LEVEL=4 (id: ...)                   │    │
│    │ ──────────────────────────────────────────             │    │
│    │ formula_ref:    radar.scoring.derive_tl#L142           │    │
│    │ threshold_ref:  {tl_floor: 0.65, ...}                  │    │
│    │ calibration:    {sample_size: 240, last_eval: ...}     │    │
│    │ source_urls:    [3 URLs, click to open]                │    │
│    │ llm_prompt:     [system + user, 全文展開]              │    │
│    └────────────────────────────────────────────────────────┘    │
├──────────────────────────────────────────────────────────────────┤
│  Layer 3: Sensor Watchpane (常設、アナリスト選択型)              │
│    ┌────────────────────────────────────────────────────────┐    │
│    │ [+ Add sensor]                                         │    │
│    │ ├ ct_log [TW]: 142 surge 1h, baseline σ=2.1 [chart]    │    │
│    │ ├ bgp_anomaly [TW→US]: 3 events 1h [chart]             │    │
│    │ └ apt_intel [CN→TW]: 2 confirmed [list]                │    │
│    └────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

3 層の役割分担:
- **Layer 1 (結論カード)** — NP4 の結論最大化を 1 画面で達成
- **Layer 2 (drill-down)** — NP6 の透明性を「結論 → 派生過程」の 1 クリックで提供
- **Layer 3 (watchpane)** — NP1 の感度を「結論レベルで隠された生信号」へのアナリスト主導アクセスで担保

---

## 4. Layer 1: Conclusion Cards

### 4.1 表示

5 種の ConclusionType それぞれに対し 1 カード。`/api/v2/scenarios/<id>/conclusions` envelope の `conclusions[]` を type 別にバケット化して描画。

| Type | カード内容 | 結論不可時の表示 |
|------|-----------|-----------------|
| THREAT_LEVEL | TL 数値 (1-5) + confidence bar + 24h delta | "INSUFFICIENT_DATA" バッジ + 不足データ種別 |
| TREND | ESCALATING / DEESCALATING / FLAT + 信頼区間 | "INSUFFICIENT_HISTORY" + 必要時間窓 |
| PER_DOMAIN | cyber / phys / info の 3 行、各 high/med/low | DEGRADED ドメインを赤線 |
| ANOMALY | active anomaly 件数 + top 3 ラベル | "NO_ACTIVE" (空のカードではなくフラット表示) |
| ATTACK_MODE | 推定モード + confidence | confidence < 0.6 → `TENTATIVE` ラベル必須 (v2-migration.md §RISK) |

### 4.2 フェッチ戦略

- 既存 `/api/threat_data` のポーリング (10s) と並走
- `/api/v2/scenarios/<focused_scenario>/conclusions` を同じ周期で叩く
- focus 切替時は cache invalidate して再フェッチ
- 503 (V2_API_ENABLED=false) → カード全体を非表示 (banner だけ残す)

### 4.3 既存フィールドとの分業

| 情報 | ソース |
|------|--------|
| Layer 1 結論 | v2 conclusions envelope |
| マップピン / per-country pulses | v1 `/api/threat_data` (UI 別領域) |
| シナリオ切替 / focus | v1 (現状維持、v2 migration は Phase 3) |
| Layer 3 watchpane raw signals | v1 + 後述 Observation API (新設) |

v1 と v2 を **異なる UI 領域に並置** することで adapter を介さず両方の強みを残す。これは Phase 1.4 P2 の deferral 判断の直接的な答え。

---

## 5. Layer 2: Drill-down Modal

### 5.1 起動経路

各 Conclusion Card の `[drill ▶ ]` ボタン → `/api/v2/conclusions/<conclusion_id>/audit_trace` を叩いてモーダル表示。

### 5.2 既存 audit_trace endpoint の活用

`radar/routes/conclusions_v2.py` 既存実装 ([radar/routes/conclusions_v2.py:126](../../radar/routes/conclusions_v2.py#L126)) はすでに以下を返す:
- `formula_ref` (例: `radar.scoring.derive_tl#L142`)
- `threshold_ref` (dict)
- `source_urls` (list)
- `calibration_status` (dict)
- `metadata`
- `llm_prompt` (system + user 全文 / sha256 解決済)

**設計は既に揃っている**。UI 側の作業は描画のみ。

### 5.3 描画コンポーネント設計

| セクション | 描画 |
|-----------|------|
| Header | conclusion_type + observed_at + scenario_id |
| Disclaimer (NP7) | envelope.final_judgment_disclaimer をモーダル上部にも表示 (バナーとは独立に冗長表示) |
| Formula | `formula_ref` を monospace 表示 + (将来) GitHub リンク化 |
| Thresholds | `threshold_ref` を key-value テーブル |
| Calibration | `calibration_status` を NP5+8 sentinel として強調 (sample_size 不足時は赤) |
| Sources | `source_urls[]` を target=_blank リンク + rel=noopener |
| LLM Prompt | system / user を collapsible (デフォルト折りたたみ、長文対策) |

### 5.4 i18n キー命名

`drill_modal.section.formula` / `drill_modal.section.thresholds` / 等の `drill_modal.*` 名前空間で統一。EN/JA 両方追加 (CLAUDE.md §1)。

### 5.5 アクセシビリティ (WCAG 2.2)

- `role="dialog"` + `aria-modal="true"` + focus trap
- ESC で close、Tab で循環
- Calibration 警告色は色だけに依存しない (アイコン + テキスト併用)

---

## 6. Layer 3: Sensor Watchpane

### 6.1 動機

NP1 (感度) は「結論レベルで隠された signal を見落とすな」という原則。結論カード + drill-down だけでは、**deriver が signal を結論に反映しなかった (= 閾値以下、ノイズと判定)** ケースを覆えない。アナリストが「最近 ct_log の TW surge が増えている気がする」と感じたとき、結論待ちではなく即座に raw を見られる経路が必須。

### 6.2 仕様

| 項目 | 仕様 |
|------|------|
| 配置 | 画面右側ドック (panel-chrome.md の `createFloatingPanel({id, titleKey, ...})` に準拠) |
| 状態 | アナリストが追加した sensor list (LocalStorage 永続化) |
| 表示 | sensor あたり 1 row: `[sensor] [country/scope]: 数値 + 1h delta + sparkline` |
| 削除 | row hover で × ボタン |
| 追加 | `[+ Add sensor]` ボタン → 検索可能なドロップダウン (sensor name × country/scope) |
| 更新 | 既存ポーリング (10s) に乗せる、追加コストは差分 fetch のみ |
| データソース | **既存 `/api/sensor/<name>/snapshot` は存在しない (§7.1 棚卸し結果)。新エンドポイント新設が必要 (§7)** |

### 6.3 alarm モード (Phase 2.5 候補)

- watchpane row に「条件式 (例: ct_log_surge_1h > 200)」を設定可能にする
- 条件成立で背景色変化 + 任意 web notification
- 結論層で隠れた signal の早期発見支援
- 着手は drill-down + watchpane base が安定後 (Phase 3 もしくは Phase 2 後半)

---

## 7. Observation スキーマ

### 7.1 既存 API の再利用可否調査 (Phase 3 タスク 1 — 2026-04-26 完了)

#### 棚卸し結果

`radar/routes/` 配下で `sensor` を含む全 endpoint を列挙:

| Endpoint | 提供内容 | watchpane 要件への適合 |
|----------|---------|----------------------|
| `GET /api/sensor_config` ([radar/routes/admin.py:245](../../radar/routes/admin.py#L245)) | enabled フラグと domain weights のみ | ✗ observation データなし |
| `GET /api/sensor_reliability` ([radar/routes/analytics.py:51](../../radar/routes/analytics.py#L51)) | 成功率などのメタ統計 | ✗ observation データなし |
| `GET /api/admin/sensor_health` ([radar/routes/admin.py:652](../../radar/routes/admin.py#L652)) | health enum, CB state, cache age, fetch_log の信頼性集計 (current snapshot 1 点) | △ "現在値ステータス" は出るが時系列なし |
| `GET /api/score_breakdown` ([radar/routes/analytics.py:626](../../radar/routes/analytics.py#L626)) | 現 cycle の per-sensor `(sensor, status, score, value, fired_reason, suppressed)` (focused scenario のみ) | △ 現値は出る。1h delta / sparkline は出ない |
| `GET /api/scenario/<id>/timeseries`, `…/country/<c>/timeseries` ([radar/routes/analytics.py:1373](../../radar/routes/analytics.py#L1373)) | scoring 集約 score の時系列 (theater 単位) | ✗ sensor 単位ではなく集約後の TL/score |

**`/api/sensor/<name>/snapshot` は存在しない**。v2-ui.md §6.2 旧版の「既存 API を再利用」前提は事実誤認だった。

#### バックエンドデータの実情

sensor 単位の raw observation 時系列を持つ schema が DB に**ない**:

- `time_series_ts` / `time_series` ([radar/database.py:1587](../../radar/database.py#L1587), [radar/database.py:1626](../../radar/database.py#L1626)) は **theater (国) 単位の集約 score** を保存。`series_type` は `combined` / `l3` / `l7` 等で sensor 名は持たない
- `fetch_log` は `(sensor_name, ts, success, duration_ms)` のみで observation value を持たない
- BaseSensor の in-memory `set_cache()` は最新 1 点のみ (TTL ベース)。1h 履歴は再構成不可

#### 判断

| 項目 | 決定 |
|------|------|
| 再利用 | 不可。既存 endpoint は (a) 設定/メタ情報、(b) 集約後 TL のみ。sensor × scope の raw observation 時系列を持つ surface はゼロ |
| 新設 endpoint | `GET /api/v2/sensors/<sensor_name>/observations?scope=<country|global|src→dst>&hours=1` を新設 |
| バックエンド | **新 schema 追加** が必要。`sensor_observation_ts(sensor TEXT, scope TEXT, ts REAL, value REAL, baseline REAL)` (max_entries=720 → 12h@1min cycle、TTL 自動 prune)。scoring tick で各 sensor の signals を append |
| 暫定モード | ~~schema migration 完了前は `/api/score_breakdown` の current value を返す degraded mode~~ → **2026-04-26 解消**: v25 マイグレーション (`sensor_observation_ts`) 適用済み。scoring tick が `scope="focused"` で各 rationale 行を persist し、endpoint は実 1h 履歴を返却。観測点 < 2 (fresh DB / 初サイクル) のときのみ rationale_matrix 由来の単一点で seeding し `history_shallow: true` を返す |
| 認証 | 既存 `_require_analyst()` (v2 endpoint と同等) |
| Phase | schema 追加と endpoint 実装は Phase 3 タスク 4 (Sensor Watchpane 基本) に含める。タスク 1 (本書) は判断記録まで |

#### 残課題 (タスク 4 着手時に決める)

- ~~旧 sensor も新 ts table に書き込むか、新規 sensor のみに限定するか~~ → **決定 2026-04-26**: 全 rationale 行を一律 persist (scoring tick で `for _r in rationale: sensor_obs_record(...)`)。31 sensors × cycle で十分軽量
- scope の正規化規則 → **暫定 2026-04-26**: 全行を `scope="focused"` で記録 (focused scenario が単一であるため整合)。background/cross-country scope は C-medium 移行時に再検討
- ~~ts の retention (12h で十分か、24h まで伸ばすか)~~ → **決定 2026-04-26**: 24h TTL (`sensor_obs_record(ttl_sec=86400.0)`)。sparkline 用途で十分、INSERT 毎に opportunistic prune

#### 新設エンドポイント仕様 (実装は Phase 3 タスク 4)

| 項目 | 案 |
|------|-----|
| Endpoint | `GET /api/v2/sensors/<sensor_name>/observations?scope=<scope>&hours=1` |
| Response | `{sensor, scope, observations: [{ts, value, baseline, delta_vs_baseline}], baseline_window_hours, history_shallow: bool}` |
| 認証 | 既存 `_require_analyst()` |
| キャッシュ | sensor 自身のキャッシュ TTL に追従 (差分 fetch でコスト最小化) |
| degraded | (実装後) 観測点 < 2 のときのみ `observations: [現値1点], history_shallow: true` で graceful 返却。schema は v25 で landed (2026-04-26) |

### 7.2 watchpane state 永続化

- LocalStorage キー: `watchpane.v1.state`
- 形式: `{sensors: [{name, scope, added_at}], version: 1}`
- マイグレーション戦略: `version` キーで upgrade hook (壊さず無視)

---

## 8. Open Questions

| # | 質問 | 想定 deciding party |
|---|------|---------------------|
| OQ-UI-1 | 結論カードの並び順は固定か、アナリスト並べ替え可能か | Phase 2 着手 1 週目で UX 試作後に判断 |
| OQ-UI-2 | drill-down モーダルから Markdown export を Phase 2 で出すか Phase 3 まで延ばすか | v2-migration.md §6 (Phase 3 export) との整合 |
| OQ-UI-3 | watchpane の sensor list は user 単位 (DB 永続化) か device 単位 (LocalStorage) か | 一旦 LocalStorage、要望が出たら DB へ昇格 |
| OQ-UI-4 | confidence < 0.6 attack_mode を結論カードに出すか drill-down 内のみにするか | NP4 (出す) vs リスク (誤判断助長) のトレードオフ。出す方向で `TENTATIVE` ラベル + 薄色化を提案 |
| OQ-UI-5 | per-domain DEGRADED の DB 由来 vs リアルタイム再計算 | v2-migration.md PER_DOMAIN deriver の実装方針に追従 |

---

## 9. Phase 着手順序

| 順 | タスク | 完了条件 | 工数 |
|----|--------|---------|------|
| 1 | 既存 sensor snapshot API 棚卸し (§7.1) | 再利用可否の判断記録 | 0.5d |
| 2 | Conclusion Cards 実装 (Layer 1) | 5 type 全部、focus 切替時 invalidate、503 時 graceful hide、E2E ブラウザ確認 | 3-4d |
| 3 | Drill-down Modal 実装 (Layer 2) | audit_trace 全 6 セクション描画、a11y チェック、i18n EN/JA | 2-3d |
| 4 | Sensor Watchpane 基本 (Layer 3) | 追加/削除/永続化、既存 sensor API 統合 | 3-4d |
| 5 | Help Guide Ch.1 + Ch.8 + Ch.10 更新 | EN/JA 両方、新 UI を反映 | 1d |
| 6 | フロントエンド codemap 再生成 + コミット | `python scripts/gen_frontend_codemap.py` | 0.5d |
| **計** | | | **10-13d** |

watchpane alarm モード (§6.3) は本順序の外。Phase 2 後半か Phase 3 へ。

---

## 10. 新セッション着手手順 (handoff)

新セッションで Phase 3 (UI 着手) を開始するときの読み順:

1. `CLAUDE.md` 全文 — 用語、§5.5 (Read 予算規律)、設計原則 NP1-NP7
2. `docs/design/v2-migration.md` §0 (TL;DR) → §3 (NP6 ギャップ ~65%) → §6.5 (envelope) → §8 (UI スケッチ)
3. `docs/design/v2-ui.md` (本書) 全文
4. `docs/design/panel-chrome.md` — Layer 3 watchpane の panel 契約
5. `docs/CODEMAPS/radar.js.md` + `docs/CODEMAPS/radar.css.md` — 既存コード地形の把握 (radar.js の全文 Read は禁止)
6. `radar/routes/conclusions_v2.py` (全文、~200 行 OK) — audit_trace endpoint 仕様
7. `radar/conclusions/api.py` — `build_envelope` 構造

着手前にこのファイルを更新してよい場合 (本書を「設計の単一情報源」として運用するための rule):

- 新たな Open Question が発見されたら §8 に追記
- 既存 OQ が決着したら §8 から削除し決定内容を該当章に反映
- §9 の工数は実測で更新 (見積りと実測が乖離したら理由を追記)
- 完了タスクは §9 で `~~ 取り消し線 ~~` ではなく行ごと削除 (履歴は git log で追える)

---

## 11. 既存 Phase 1.4 成果との接続

| 成果物 | UI 設計への影響 |
|--------|---------------|
| Phase 1.4 P1 (RFC 9745/8594 sunset headers) | 影響なし (HTTP 層のみ) |
| Phase 1.4 P2 (NP7 banner) | Layer 1 上部の banner として既設置。Layer 1 カード化で **削除しない** (冗長表示は意図された設計) |
| Phase 1.4 P3 (`legacy_telemetry` 統合) | watchpane が v1 sensor API を叩き続ける場合の v1 残存ユーザカウントに影響。watchpane を v2 sensor API に切替えると `[V1Sunset]` 観察が綺麗になる → Phase 2 工数 §7 の優先度を上げる根拠 |
| Phase 1.4 C (`[V1Sunset]` 観察ログ) | T+90d (2026-07-26) までに watchpane 経由の v1 sensor 依存を解消できれば residual=0 を維持できる |

---

## 12. リスク

| ID | リスク | 影響 | 対策 |
|----|--------|------|------|
| R-UI-1 | watchpane の sensor list が肥大化し描画コスト増 | M | row 上限 20 (LocalStorage 段で enforce)、超過時はアナリストに警告 |
| R-UI-2 | drill-down LLM prompt が極端に長い (10kB+) と DOM が重い | L | collapsible デフォルト折りたたみ、開いたときに lazy render |
| R-UI-3 | 5 種の結論カードを並べると small viewport (< 1280px) で潰れる | M | レスポンシブ: 2x3 grid → 1x5 stack の breakpoint 設計 |
| R-UI-4 | アナリストが drill-down を見ずに結論カードだけで判断する | H (NP6 の実効性低下) | カードの confidence bar 横に小さな `?` icon + ホバーで「派生開示は drill-down へ」誘導文 |
| R-UI-5 | watchpane raw signal がノイズで埋まり結論層を信じなくなる (NP4 退化) | M | sensor あたり baseline + delta を必ず併記、生数値だけの表示は禁止 |
