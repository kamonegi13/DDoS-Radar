# D1 素材: ソース行数インベントリ（生データ）

取得: 2026-08-03。venv / __pycache__ / node_modules 除外。

## 規模サマリ

| 領域 | ファイル数 | 行数 |
|---|---:|---:|
| radar/（トップレベル） | 33 | 23,176 |
| radar/routes/ | 22 | 10,493 |
| radar/sensors/ | 38 | 9,718 |
| radar/conclusions/ | 21 | 5,173 |
| radar/analytics/ | 3 | 456 |
| scripts/ | 21 | 6,286 |
| tests/ | 101 | 31,304 |
| リポジトリ直下 .py | 4 | 348 |
| **Python 計** | **243** | **96,670** |
| フロントエンド（.js/.html/.css） | 16 | 29,143 |

## Python 上位（800 行超 = オーナーのファイル上限ルール違反）

```
6629  radar/database.py          ← 上限の 8.3 倍
3174  radar/routes/core.py       ← 4.0 倍
1735  radar/scoring.py           ← 2.2 倍
1612  radar/config.py            ← 2.0 倍
1560  tests/test_engine.py
1211  radar/intel_queue.py
1134  radar/routes/analytics.py
1026  radar/climate.py
1008  radar/engine.py
 937  radar/routes/conclusions_v2.py
 921  radar/llm_routing.py
 887  radar/calibration/auto_apply_tier_governor.py
 880  tests/test_proposal_lifecycle.py
 823  radar/scheduler.py
 814  tests/test_scenario_scoring.py
 813  radar/routes/calibration_v2.py
```

## フロントエンド全ファイル

```
14833  radar.js        ← 上限の 18.5 倍。最重症
 5008  radar.css
 3246  index.html
 1976  i18n.js
 1016  tradecraft.js
  645  controls_panel.js
  443  autotune_wizard.js
  338  self_explanation.js
  334  llm_features_hub.js
  281  tradecraft.css
  241  map_dim.js
  218  triage_display_mode.js
  203  wp_alarm.js
  164  triage_score.js
  102  hud_v2_overlay.js
   95  login-init.js
```

## 一次観察

- 800 行超は Python 実装 13 ファイル（テスト除く）+ フロントエンド 4 ファイル
- 一方で radar/conclusions/ は 21 ファイル 5,173 行（平均 246 行）と健全な分割粒度 —
  後期に書かれた層ほど分割規律が良い傾向。新しい設計文化は既に存在しており、
  リビルドはそれを全体に遡及適用する行為と位置付けられる
- tests/ 31k 行（101 ファイル）は Python 実装（65k 行）の約半分の規模 = 仕様資産として厚い
