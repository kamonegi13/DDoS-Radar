# Calibration Governor Audit — 2026-07-31

> **Schedule**: 2026-07-31 (~3 months after Phase 5 closure on 2026-04-30)
> **Owner**: kamonegi13(@juzo1192)
> **Trigger**: planned audit per v2-migration.md §0.2.1

## 1. 監査の目的

2026-04-30 PM に投入した autotune proposer ガード層 (Phase A/B) が、3 ヶ月の運用で:

1. **真の disable 候補・dormant participant を見逃していないか** (false negative リスク)
2. **fleet 健全時に提案が再開されているか** (suppression が永続化していないか)
3. **新規 sensor / scenario 追加時にガード閾値の再評価が必要か** (gate 閾値の経年劣化)

を確認する。Phase A/B ガードは NP1 (感度優先) を遵守して「健全な情報源を遮断しない」設計だが、過剰防衛で legitimate な proposal まで止めていないかを実データで検証する。

## 2. 必須チェック項目

### 2.1 Phase A guard (sensor_disable fetch-layer)

#### 観察項目
```bash
# 過去 90d で skip した sensor 数 / 採用した提案数
docker exec noroshi python -c "
from radar.database import db
import time
conn = db._get_conn()
since = time.time() - 90 * 86400
# Skipped (proxy: log lines containing 'skipping disable proposal')
# → スクリプト化したログ集約が必要、または systemd journal grep
print('=== sensor_disable proposals emitted in 90d ===')
for r in conn.execute(
    \"SELECT target_country, state, COUNT(*) FROM scenario_proposals \"
    \"WHERE proposal_type='sensor_disable' AND emitted_at > ? \"
    \"GROUP BY target_country, state ORDER BY COUNT(*) DESC\",
    (since,)
).fetchall():
    print(' ', r[0], r[1], r[2])
"
```

#### 判定基準
- **OK**: 90d で 1 件以上の proposal が emit されていれば、ガードが「ゼロ即殺」になっていない証拠
- **要調査**: 90d で 0 件しか emit されていない場合、ガード閾値 (`ok_24h >= 10 and not last_err`) が硬すぎる可能性
- **NP1 違反**: CB OPEN や success_rate < 0.5 の sensor が disable 候補に上がっていない

#### 推奨アクション (要調査時)
- `_sensor_fetch_layer_healthy()` の閾値 `ok_24h >= 10` を運用実績で再キャリブレーション
- 新規 LLM_GATED_SENSORS 追加時はガード除外チェックを通すか確認

### 2.2 Phase B guard (sensor_coverage_healthy)

#### 観察項目
```bash
docker exec noroshi python -c "
from radar.database import db
import time
# Run sensor_coverage_healthy 30 times over last 24h to see distribution
# Approximation: count signals in 30d windows ending each hour
conn = db._get_conn()
now = time.time()
window_30d = 30 * 86400
total = 0
for table in ('llm_intel', 'sequence_events', 'sensor_observation_ts'):
    r = conn.execute(f'SELECT COUNT(*) FROM {table} WHERE ts > ?', (now - window_30d,)).fetchone()
    total += r[0]
    print(f'  {table}: {r[0]}')
print(f'TOTAL global signals (30d): {total}')
print(f'  threshold (default min=50): {\"HEALTHY\" if total >= 50 else \"DEGRADED\"}')"
```

#### 判定基準
- **OK**: total ≥ 500 の場合、coverage は十分。50 という閾値は最小ガードであって運用閾値ではない
- **要調査**: 50 〜 200 の場合、Phase B ガードが頻繁にフィレード = dormant_participant / weight_too_high が emit されない期間が長い → 閾値を 100〜200 に引き上げ検討
- **設計失敗**: 50 未満が継続している場合、sensor 自体に問題あり (Phase B が正しく短絡している)

#### 推奨アクション
- `MIN_GLOBAL_SIGNALS` env var を追加して運用で調整可能に (現状 hardcode 50)
- coverage_details の `total_global_signals` を Prometheus メトリクスで継続監視

### 2.3 Phase D supersession (discovery cluster)

#### 観察項目
```bash
docker exec noroshi python -c "
from radar.database import db
import time
conn = db._get_conn()
since = time.time() - 90 * 86400
print('=== discovery proposals state distribution (90d) ===')
for r in conn.execute(
    \"SELECT state, COUNT(*) FROM scenario_proposals \"
    \"WHERE proposal_type='scenario_discovery' AND emitted_at > ? GROUP BY state\",
    (since,)
).fetchall():
    print(' ', r[0], r[1])
"
```

#### 判定基準
- **OK**: superseded > 0 件かつ pending が cluster 数程度 (5-20 件) — supersession が動いている
- **要調査**: pending が cluster 数の 5 倍以上 — supersession が機能していない疑い
- **設計失敗**: superseded = 0 件のまま — fingerprint 計算にバグ

### 2.4 Phase F drift classification

#### 観察項目
```bash
docker exec noroshi python -c "
from radar.database import db
import time
conn = db._get_conn()
since = time.time() - 90 * 86400
print('=== drift signal types (90d) ===')
for r in conn.execute(
    \"SELECT drift_signal, severity, COUNT(*) FROM scenario_drift_events \"
    \"WHERE emitted_at > ? GROUP BY drift_signal, severity ORDER BY COUNT(*) DESC\",
    (since,)
).fetchall():
    print(' ', r)
"
```

#### 判定基準
- **OK**: participant_silent (amber) と sensor_outage (red) が両方とも emit されている
- **OK / 健全**: sensor_outage がほぼ 0 件 — 90d で fleet 障害が無かったことを示す
- **要調査**: weight_stale が emit されている — Phase F の switch が古いコードに残っている
- **要調査**: sensor_outage が大量 emit されているのに analyst が誰も ack していない — operational alarm

## 3. Decision Layer Audit (副次的に確認)

### 3.1 decisions テーブル retention

```bash
docker exec noroshi python -c "
from radar.database import db
conn = db._get_conn()
r = conn.execute('SELECT COUNT(*) FROM decisions').fetchone()
print(f'Total decisions: {r[0]}')
oldest = conn.execute('SELECT MIN(decided_at) FROM decisions').fetchone()
import time
if oldest[0]:
    age_days = (time.time() - oldest[0]) / 86400
    print(f'Oldest decision: {age_days:.1f} days ago')
"
```

判定基準:
- **OK**: 総件数 < 10,000 — retention 不要
- **要対処**: 総件数 ≥ 10,000 — retention policy 検討 (例: superseded を 90 日後に hard delete、active は無期限保持)

## 4. 監査チェックリスト (印刷可能)

監査実施日に以下をチェック:

- [ ] Phase A guard: 90d で sensor_disable proposal が ≥ 1 件 emit されている
- [ ] Phase A guard: CB OPEN sensor が disable 候補に上がっている (人為的に CB トリップで確認可能)
- [ ] Phase B guard: 30d global signal total が threshold の 10 倍以上
- [ ] Phase B guard: dormant_participant が legitimate に emit されている (90d で ≥ 1 件、かつ analyst が応答している)
- [ ] Phase D supersession: superseded 状態の row が存在する
- [ ] Phase F classification: participant_silent と sensor_outage が両方 emit パスを通っている
- [ ] decisions テーブル件数が retention を必要とするレベルに達していない
- [ ] week-cron diversity avg が ≥ 2.0 に到達したか — 到達していれば Layer 1 cross-evidence + LLM 第二パス再導入条件成立
- [ ] intel_research 案件 (diplomatic 7 feed / hacktivist 7 channel) が解消されたか確認
- [ ] 新 sensor / scenario 追加時のガード除外 / 包含チェック

## 5. 監査結果テンプレート

監査実施時に以下のセクションを埋めて `docs/audits/2026-07-31-calibration-governor.md` に保存:

```markdown
# Calibration Governor Audit — 2026-07-31 結果

## サマリ
- 全体判定: [OK / 要調整 / 要再設計]
- Phase A guard 状況: ___
- Phase B guard 状況: ___
- Phase D supersession 状況: ___
- Phase F classification 状況: ___

## 数値
- 90d sensor_disable proposals: __
- 30d global signal total: __
- 90d discovery superseded: __
- 90d drift signals (sensor_outage / participant_silent): __ / __
- decisions テーブル総件数: __

## 異常事象
(あれば)

## 推奨アクション
(なければ「閾値そのまま、次回 audit 2027-01-31」)

## 次回 audit 予定
2027-01-31 (6 ヶ月後 — 半年 cadence へ移行)
```

## 6. 関連リンク

- 設計: [v2-migration.md §0.1.6 (Autotune Audit Fix)](v2-migration.md)
- 実装コミット: `11721a0`, `c84d7d8` (2026-04-30)
- ガードコード: [`radar/calibration/sensor_disable_proposer.py`](../radar/calibration/sensor_disable_proposer.py), [`radar/calibration/_proposal_guards.py`](../radar/calibration/_proposal_guards.py)
- テスト: [`test_autotune_proposer_guards.py`](../../tests/test_autotune_proposer_guards.py)
