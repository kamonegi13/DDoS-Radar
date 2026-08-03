# S1 素材: LLM 較正系の仕様抽出（生データ）

生存した子調査の出力（2026-08-03）。S1-calibration 正本へ編入する。証拠は file:line。

## A. g3b_llm_annotator（クラスタ LLM 注釈）

1. 状態は production > shadow > none の 3 値。production が shadow を上書き（:118-123、検証: TestEnvGate 2 件）
2. state="none" で run_once は DB 非接触の no-op `{"skipped":True,"reason":"both_flags_off",...}`（:292-297）。デフォルト配備は両 off（NP7 shadow-first）
3. フラグ解決は LLM Feature Hub 優先、env フォールバック（key=`g3b_cluster_annotator`）。Hub 優先順位: kill switch → DB override → env → registry default(OFF, np7_concern, requires_admin)（:94-115、llm_features.py:376-411,183-198）。**Hub の DB override/kill switch 経路からの g3b 挙動は未検証**
4. 対象は `discovery_cluster` の `annotation_state='none'` を id 昇順 LIMIT（既定 20）（:153-183,281）
5. 0 件なら `no_unannotated_clusters`（:308-313）
6. 日次コール上限 `G3B_DAILY_CALL_CAP` 既定 50。計測は `llm_call_log` の caller 一致 かつ ts > now-86400（:90-91,134-150,299-306）
7. **cap はソフトガード**: `_calls_in_last_24h` は例外を握り潰して 0 を返すため、llm_call_log が読めない環境で上限が事実上無効化（:141-150、docstring 明記、未検証）
8. **cap 消費の過大計上**: `used += 1` が `_annotate_one` の戻り値に無関係で実行され、circuit_open / empty_countries で LLM を呼ばなかった分まで消費扱い（:318-323、未検証）
9. CB は LLM 失敗 N 連続で開く。N=`G3B_CIRCUIT_BREAKER_FAILURES` 既定 5。成功でリセット（:86-87,242-256）
10. **CB スコープの doc/impl 乖離**: docstring は「プロセス再起動までリセットされない」だが実装は run_once 冒頭で毎回リセット → 実効スコープは 1 run（:81-83 宣言 vs :288-290、docstring :27-28）
11. CB 発火時は残クラスタを全て skipped 計上して break（:330-333、skipped_count 値は未検証）
12. LLM 失敗時は annotation を書かず `annotation_state='none'` のまま → 次 run で再選択（自動リトライ相当）（:242-254）
13. NP3: 例外を投げず skipped 化（circuit_open / empty_countries / import_failed / persist_failed）（:209-227,271-275,186-201、各分岐は未検証）
14. LLM パラメータ固定: temperature=0.1 / max_tokens=300 / use_case=DISCOVERY / caller=g3b_llm_annotator。期待 JSON: kind∈{scenario,random}, suggested_name, suggested_description, confidence_self_reported∈[0,1], rationale。system prompt は「迷ったら random」（:61-79,229-241、PROMPT_VERSION="g3b_llm_annotator/v1"）
15. 永続化時に切り詰め: kind 既定 random / name 120 / description 500 / rationale 300、confidence は float(x or 0.0)。prompt_version + annotated_at 付与、`sort_keys=True` で決定化（:258-269,195。切り詰め長は未検証）
16. **NP6 違反**: docstring は「prompt_sha256 + raw_response を記録」と書くが、実装は prompt_version のみ。どちらも annotation dict に存在しない（docstring :37-39 vs 実装 :258-269）
17. 永続化は `annotation_state` に run の state をそのまま書く。shadow 行は `?include_shadow=true` でない限り UI から除外（:186-201）
18. 戻り値: `{skipped,state,annotated,errors,skipped_count,calls_used,calls_cap,circuit_open}`（:334-343）
19. scheduler は 24 サイクル周期 offset 5 で起動、例外は握り潰し（scheduler.py:379-394、未検証）
20. NP1: 注釈は suggest-only。シナリオ自動生成はせず analyst の Wizard apply が必須（docstring :32-33）

## B. llm_confidence_calibrator（センサ別 LLM 信頼度下限）

21. 入力は ground truth ではなく `analyst_feedback` のラベル集計（自動ラベル込み）。ラベル値 TP/FP/FN（:98-113）
22. **構造的欠陥**: JOIN が `li.theater = c.scenario_id` でありセンサ単位でなくシナリオ単位。「その source_type の llm_intel が 1 件でも存在するシナリオの全 feedback」を llm_intel 行数分だけ重複カウント → **sample_n の意味が歪む**（:98-105、未検証）
23. 対象は 7 センサのハードコード tuple（apt_intel, diplomatic, military_exercise, rss_narrative, ground_osint, hacktivist_intel, hacktivist_news）（:49-57）
24. センサ名→source_type のマッピング例外 3 件: rss_narrative→narrative、hacktivist_news/hacktivist_intel→hacktivist（:93-97）
25. 最小サンプル `LLM_CONF_CALIB_MIN_FEEDBACK` 既定 30、母数は TP+FP+FN。未満は `insufficient_feedback`（:60-61,113-115,155-160）
26. DB エラー時も None で黙って no-op（NP3、:106-108）
27. **計算式は bin 分割でも Platt scaling でもない ±0.05 ヒューリスティック**: recall=tp/max(1,tp+fn)、precision=tp/max(1,tp+fp)。分岐 A（緩め）: recall<floor → max(floor_lo, global_min−0.05)。分岐 B（締め）: precision<0.5 かつ recall≥floor+0.10 → min(floor_hi, global_min+0.05)。A が先に評価され、recall 不足時は precision を見ない（:116-119,136-148,161-167。**両分岐とも未検証**）
28. recall floor `LLM_CONF_CALIB_RECALL_FLOOR` 既定 0.85 → 締め分岐の実効閾値は 0.95（:64-65,142）
29. floor 許容レンジ `[max(0.10,gmin−0.10), min(0.95,gmin+0.20)]`、`LLM_CONFIDENCE_MIN` 既定 0.35 → [0.25,0.55]。提案値は常に gmin±0.05 なので **clamp はデフォルトで実効しない**（:68-69,132-134）
30. **収束しない**: `_propose_floor` は global_min からの ±0.05 のみを返し、直近採択された `llm_confidence_min.<sensor>` を参照しない → 同方向の再提案は常に同値（:122-148）
31. 「変化量 0.02 未満なら提案しない」ガードは存在するが、差分が常に 0.05 なので**常に通過**（:138-139,143-145）
32. 出力先は threshold_history（governor 経由）。Proposal(key=`llm_confidence_min.<sensor>`, derived_from, applied_by="auto:llm_confidence", sample_n, formula_ref, evidence{tp,fp,fn,recall,precision,global_default})。CALIBRATOR_VERSION="llm_confidence_calibrator/v1"（:43-44,168-193、governor 結合は未検証）
33. governor 二次ガード順: sample_too_small(既定 30) → recall_red → tier_gate(評価不能時も安全側で拒否) → cooldown(既定 72h) → magnitude clamp(既定 10%)（auto_tune_governor.py:56-64,154-215）
34. Phase C v1 では提案のみ。適用は `V2_AUTO_TUNE_LLM_CONFIDENCE` opt-in（docstring :25-27）
35. `calibrate_all_sensors()` は 1 センサの例外が他を止めない（:196-213）

## C. auto_feedback_etl

36. conclusions 台帳 → analyst_feedback 自動ラベル。源は GDELT トーンスパイク（キー不要）/ ACLED 死者数相関（キー要）/ RSS kinetic 正規表現（キー不要）（:1-33、**専用テスト不在**）
37. 薄いラッパで、実処理は `scripts/run_ground_truth_etl.py` / `run_rss_etl.py` の `run_etl` を sys.path 経由で import 再利用（:45-51,73,129）
38. 両パスとも同一ゲート `V2_GROUND_TRUTH_ETL_ENABLED` 既定 false（意図的に 1 ダイヤル）（:68-70,120-126、config.py:290-292）
39. `None` は失敗でなくガード終了のシグナル（:60-66,117-119）
40. ground truth 既定: window_days=14, limit=1000, enable_gdelt/llm_intel/sequence=True（:54-58,92-104）
41. ACLED は API キーと email の**両方**が揃った時のみ有効化。片方欠落で GDELT-only に自動縮退（:88-90、config.py:293-294）
42. RSS 既定: window_days=14, **limit=4000**（ground truth の 1000 と非対称）, use_llm=False（:107-112,157-167）
43. RSS feed は env `BG_OBSERVER_FEEDS` 優先、未設定なら `background_observer._DEFAULT_FEEDS`（9 本）。空なら None（:144-155）
44. scenario_store 未ロードなら `radar.config._raw_geo` から遅延ロード、失敗で None（:78-86,134-142）
45. **dedup は下流 ETL の冪等性で担保**: ground truth は `(conclusion_id, analyst_id)` 既存検出 → `already_persisted`。analyst_id は `auto:gdelt`/`auto:acled`/`auto:both`/`auto:rss`。RSS はエピソード鍵 `(scenario,country,UTC日)` を notes に刻印し LIKE 判定（2026-07-04 導入の擬似複製対策 = 1 外部イベント 1 トライアル強制）（ground_truth_etl.py:497-511,514-522,536-545,68-72,152-154）
46. 実行は scheduler 24 サイクル周期 offset 6（GT）/ offset 7（RSS）。g3b が offset 5（scheduler.py:396-445）
47. **ログ集計キーの不一致**: scheduler は `k.startswith("labelled_")` を合計するが、ETL の実カウンタは `label_<LabelValue>`/`persisted`/`no_verdict`/`already_persisted`/`skipped_*` → **常に 0 を表示**（scheduler.py:415-416 vs run_ground_truth_etl.py:336-401）
48. NP3: 例外握り潰しは scheduler 側の責務。本モジュールは import 失敗のみ捕捉（:93-104,158-167）

## D. run_now（手動一括較正ディスパッチャ）

49. `all` の実行順は決定的 8 段: tl, llm_conf, sensor_disable, scenario, structure, discovery, g3b, drift（:44-55、検証: TestDispatchAll::test_runs_phases_in_order）
50. **docstring drift**: docstring の phase 一覧は 6 個で `structure`/`discovery`/`g3b` が欠落（:8-14 vs :44-53）
51. phase→関数は遅延 import。1 つの import 失敗が他を妨げない。未知名は ValueError（:71-98。**parametrize は 5 phase のみ、structure/discovery は callable 検証すら無い**）
52. import 失敗 → `import_failed: ...`[:200] + WARNING、実行失敗 → str(exc)[:200] + log.exception（:106-130）
53. `_dispatch_one` は決して raise しない。`dispatch("all")` は break/raise なし（:101-143、検証: 8 件返り ok=7/err=1）
54. dispatch が raise するのは未知 phase の ValueError のみ（空文字も未知扱い）（:137-140）
55. 戻り値は frozen dataclass RunResult{phase, started_at, duration_ms, summary, error} + `succeeded` プロパティ。常に list（単一 phase でも長さ 1）（:58-68,133-143）
56. phase 関数が None を返したら空 dict に正規化して成功扱い（:116,122）
57. テキスト報告形式は固定（ヘッダ + `[OK ]`/`[ERR]` 行 + 集計行）（:146-165）
58. `--json` は `{phase, results(asdict 配列), n_ok, n_err}` indent=2（:185-192）
59. 終了コード: 1 件でも失敗で 1、全成功で 0（:196）
60. **デッドコード**: `except ValueError: return 2` は argparse の `choices` が先に弾くため到達不能（:172-175,179-183）
61. NP7: ほとんどの phase は pending proposal のみで production scoring に副作用なし。例外はセンサ自動 disable（`V2_AUTO_DISABLE_ENABLED` で gate）（docstring :22-24）

## E. check_recall_post_autotune（autotune 後 recall 劣化検知）

62. 2 段構成（グローバルトレンド + autotune 行ごとの帰属分析）、`overall_ok = global_ok and autotune_ok`。長期スナップショットは `check_recall_baseline.py` の担当（:14-23,275）
63. CLI 既定: `--hours 168`(7d), `--max-drop 0.10`, `--min-samples 10`, strict 未指定, `--db` は `$RADAR_DB_PATH` or `radar/persistence/radar.db`（:224-254）
64. `_global_recall` = TP/(TP+FN)、分母 0 で None。窓は左閉右開。FP 無視。**最小サンプルガードも try/except も無く DB エラーが伝播**（`_recall_for_cell` と非対称）（:65-80）
65. `_recall_for_cell` は scenario_id 指定で conclusions と JOIN、None ならグローバル。DB 例外は None（:83-115）
66. **非対称**: 最小サンプル判定の母数は TP+FN+FP だが recall 分母は TP+FN のみ（:108-115）
67. グローバルの pre/post いずれか None なら skipped 扱いで OK（データ不足で fail させない）（:133-138）
68. `drop = pre − post` が max_drop を厳密超過で False。pre 窓 `[now−2h, now−h)`, post 窓 `[now−h, now)`（:124-146）
69. `drop <= max_drop`（recall 上昇含む）は OK。境界値 `drop == max_drop` は OK 側（**境界値は未検証**）（:141,147-151）
70. per-autotune 対象は `threshold_history` の `state='active'` かつ `effective_from ∈ [earliest, now−h)`、DESC LIMIT 100。earliest = now − max(14d, 2h)（:159-173。LIMIT 100 と state フィルタは未検証）
71. threshold_history クエリが例外なら OK + info で縮退（テーブル未作成でも落ちない）（:174-175、未検証）
72. **メッセージ不整合**: 0 件時のメッセージが `"in the last 7d"` だが実 lookback は既定 14d（:179-184 vs :164）
73. 各行の pre/post どちらか None なら continue（fail させない）。scope 空は 'global' 表示（:186-204、未検証）
74. `drop > max_drop` の行が 1 件でもあれば全体 False。NP6 のため必ず threshold_history の行 id をメッセージに含める（:205-211）
75. `0 < drop <= max_drop` は info、`drop <= 0` は**完全に無出力**（elif 連鎖に else が無い）（:212-217）
76. 既定は warn-only（exit 0）、`--strict` でのみ exit 1。CI 先行投入のための意図的設計（:276-285）
77. NP1: 判定は recall のみ。precision は per-cell の min_samples 判定以外では計算すらされない（:108-115）
78. import 時に `V2_NP7_DISCLAIMER` を setdefault し repo root を sys.path[0] に挿入。テストはこの副作用に依存（:47-59,250）
79. テストは 12 件。CLI 3 件は `check_global_trend`/`check_per_autotune` を monkeypatch した合成テストで実 DB を通していない

## テスト不在（明確なもの）

- `auto_feedback_etl.py`: 専用テストファイルが存在しない（tests/ 全体で参照ゼロ）
- `llm_confidence_calibrator`: テストは 2 件のみ。**proposal を発火させる分岐（recall 低下 / precision 低下）はどちらも未カバー**
- `run_now._phase_func`: structure / discovery は callable 検証すら無い
