# D2 素材: git 共変更分析（隠れ結合の実測）

実行: 2026-08-03、全 655 コミット。マスコミット（ソース 15 ファイル超 = rename/i18n 一括系）15 件は除外。
tests/ docs/ は除外。スクリプト: scratchpad/cochange.py（このセッション限り）。

## Top 35 共変更ペア（回数, Jaccard）

```
 82  0.28  index.html  <->  radar.js
 80  0.33  i18n.js  <->  index.html
 74  0.45  radar.css  <->  radar.js
 73  0.39  i18n.js  <->  radar.js
 55  0.42  i18n.js  <->  radar.css
 53  0.21  index.html  <->  radar.css
 37  0.14  index.html  <->  radar_api.py
 27  0.14  radar.js  <->  radar/routes/core.py
 25  0.22  radar/database.py  <->  radar/routes/core.py
 23  0.09  index.html  <->  radar/routes/core.py
 21  0.10  radar.js  <->  radar/database.py
 18  0.25  radar/routes/analytics.py  <->  radar/routes/core.py
 17  0.07  index.html  <->  radar/config.py
 16  0.11  i18n.js  <->  radar/routes/core.py
 15  0.05  index.html  <->  radar/database.py
 14  0.10  i18n.js  <->  radar/config.py
 14  0.17  radar/routes/core.py  <->  radar/scoring.py
 14  0.08  radar.js  <->  radar/routes/analytics.py
 13  0.07  radar.js  <->  radar/config.py
 13  0.08  radar.js  <->  radar/routes/admin.py
 13  0.10  radar.css  <->  radar/routes/core.py
 12  0.05  index.html  <->  radar/__init__.py
 12  0.05  index.html  <->  radar/routes/analytics.py
 12  0.12  radar/config.py  <->  radar/routes/core.py
 12  0.13  radar/database.py  <->  radar/routes/analytics.py
 12  0.07  i18n.js  <->  radar/database.py
 12  0.12  radar/database.py  <->  radar/scoring.py
 12  0.08  radar.css  <->  radar/database.py
 11  0.16  radar/config.py  <->  radar/scoring.py
 11  0.10  radar/config.py  <->  radar/database.py
 11  0.12  radar/database.py  <->  radar/intel_queue.py
 10  0.06  radar.js  <->  radar/routes/__init__.py
 10  0.77  radar/sensors/diplomatic.py  <->  radar/sensors/military_exercise.py
  9  0.05  radar.js  <->  radar/routes/conclusions_v2.py
  9  0.05  radar.js  <->  radar/scoring.py
```

## 最多変更ファイル Top 15

```
223  index.html
156  radar.js
102  i18n.js
 84  radar.css
 77  radar/database.py
 72  radar_api.py
 63  radar/routes/core.py
 48  radar/config.py
 33  radar/scoring.py
 30  radar/scheduler.py
 27  radar/routes/analytics.py
 24  radar/__init__.py
 24  radar/routes/conclusions_v2.py
 24  radar/intel_queue.py
 23  radar/routes/admin.py
```

## 一次解釈（D2 統合時に検証すること）

1. **フロントエンド 4 点クラスタが最強結合**（index.html / radar.js / i18n.js / radar.css、Jaccard 0.21〜0.45）。
   どの機能追加も 4 ファイル全部に触れる = モノリス SPA の実害の定量化。
   「有機的に連結していない」仮説の最有力な実測証拠。フロントエンド全面書き換え判定を支持
2. **radar.js ↔ routes/core.py が 27 回** — API 契約が明文化されておらず、変更が両端に波及している証拠。
   Phase S の S2（API 契約書）の必要性を裏付ける
3. **database.py ↔ routes/core.py が 25 回（Jaccard 0.22）** — god-module 同士の結合。分割候補の優先順位根拠
4. **diplomatic.py ↔ military_exercise.py が Jaccard 0.77**（共変更 10 / 合計出現 13）—
   双子センサーのコピペドリフト疑い。センサー層エージェントの所見と突合すること
5. **index.html が全体の最多変更（223 回）** — INTEL GUIDE 更新義務（CLAUDE.md ルール 2）により
   バックエンド変更が index.html に連鎖する構造。ガイドの分離（別ファイル化）はリビルド設計の論点候補
