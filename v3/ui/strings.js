/**
 * Noroshi v3 L7 — the dictionary. Japanese only, single table.
 *
 * CLAUDE.md §1: the UI is Japanese-only with no language switch, and every
 * user-visible string goes through this table or a `data-i18n*` attribute.
 * The table is not a convenience — it is the audit surface. Strings written
 * inline cannot be checked for terminology drift, cannot be found when a
 * panel is retired, and cannot be proven translated; DP17 is exactly the
 * handful of v1 strings that bypassed the dictionary.
 *
 * This is a separate table from `i18n.js` rather than an extension of it,
 * because P8 §8 says the 1,556 v1 keys are pruned once the v3 screen
 * inventory is fixed and only then ported. Pruning by construction is what
 * this file is: it holds the keys v3's screens actually use and nothing
 * else, and `scripts/check_i18n_keys.py` audits it in v3 scope with
 * undefined references AND unused keys both fatal — stricter than the v1
 * table, which still carries the debt the pruning will remove.
 *
 * Terms deliberately kept in English are listed in
 * docs/design/ja-localization.md §2: recall / precision / drift /
 * calibration, the TL band words, sensor ids, NP-numbers and API state
 * values. `scripts/check_i18n_keys.py` knows the same list.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiStrings = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const STRINGS = {
        // ── NP7 (S1-UI-024) ─────────────────────────────────────────────
        'ui.np7.banner': '本ツールの出力は最終判断ではありません。最終的な状況判断は、本ツールの出力を含む複数の情報源を統合した組織のプロセスによって行われます。',
        'ui.np7.breach': '警告: サーバ応答に NP7 注意文が含まれていませんでした。結論の取り扱いに注意し、この事象を記録してください。',

        // ── section headings (P9 R-D: content words, never the loop's
        //    meta-language — the question lines and the 目標 N 秒 targets
        //    were WP-4.3's D-8 and live only in P9 §6 now) ─────────────────
        'ui.stage.situation': 'シナリオ別の脅威レベル',
        'ui.stage.triage': '注目すべき事象（優先度順）',
        'ui.stage.drilldown': '結論と根拠',
        'ui.stage.feedback': 'この判断へのフィードバック',
        'ui.stage.verify': '導出と What-If',

        // ── サイドバーナビゲーション（P9 §1.5 D-20 — 問いごとに 1 画面） ──
        'ui.nav.group.overview': '概観',
        'ui.nav.group.verify': '検証',
        'ui.nav.group.ops': '運用',
        'ui.nav.situation': '状況',
        'ui.nav.verify': '導出・What-If',
        'ui.nav.reliability': '信頼性',
        'ui.nav.decisions': '判断履歴',
        'ui.nav.settings': '設定',
        'ui.nav.back_to_situation': '← 状況ビューへ戻る',
        'ui.scenario.head': 'シナリオ面: {scenario}',
        'ui.scenario.notice.not_loaded': 'このシナリオの結論（R2）をまだ取得していません。結論の取得は focus 中のシナリオに限られます。',
        'ui.scenario.notice.other_scenario': '以下の結論・地理面は focus 中の {served} のものです。{requested} の面を見るには、状況ビューのカードで focus を移してください。',

        // ── 初回オンボード（P9 §3.6、§2.2 R-D: 並列の案内であって手順では
        //    ない — 番号も目標秒数も持たない） ─────────────────────────────
        'ui.onboarding.title': 'この画面でできること',
        'ui.onboarding.expand': '案内を開く',
        'ui.onboarding.collapse': '案内を閉じる',
        'ui.onboarding.q1': '何か変わったか — 冒頭のサマリ文とシナリオカードが答えます',
        'ui.onboarding.q2': '次に何を見るべきか — 注目レーンが優先度順に並べます',
        'ui.onboarding.q3': 'なぜそう言えるのか — カード名を選ぶとそのシナリオの結論と根拠へ、各結論の「なぜ?」で導出へ',
        'ui.onboarding.q4': 'ツールの判断は正しかったか — シナリオ面の下部でラベルを投稿できます',
        'ui.onboarding.q5': 'この系は生きているか — [信頼性] に自己評価とセンサー、[判断履歴] に判断台帳があります',

        // ── TL bands (band words stay English — ja-localization §2) ──────
        'ui.tl.1': 'CRITICAL',
        'ui.tl.2': 'SEVERE',
        'ui.tl.3': 'HIGH',
        'ui.tl.4': 'ELEVATED',
        'ui.tl.5': 'NORMAL',
        'ui.tl.unknown': '不明',

        // ── trend ───────────────────────────────────────────────────────
        'ui.trend.escalating': '悪化',
        'ui.trend.deescalating': '改善',
        'ui.trend.flat': '横ばい',
        'ui.trend.unknown': '傾向不明',

        // ── duration ────────────────────────────────────────────────────
        'ui.duration.seconds': '{n} 秒',
        'ui.duration.minutes': '{n} 分',
        'ui.duration.hours': '{n} 時間',
        'ui.duration.days': '{n} 日',
        'ui.duration.unknown': '期間不明',

        // ── freshness ───────────────────────────────────────────────────
        'ui.freshness.fresh': '最新',
        'ui.freshness.aging': 'やや古い',
        'ui.freshness.stale': '古い',
        'ui.freshness.failed': '取得失敗',
        'ui.freshness.unknown': '鮮度不明',
        'ui.freshness.age': '{age}前の採点',
        'ui.freshness.held': '（直前の取得結果を表示中）',
        'ui.freshness.failed_detail': '取得に失敗（{why}）。表示中の値は {age}前のものです',
        'ui.freshness.boundaries': '「やや古い」は {aging} 秒以上、「古い」は {stale} 秒以上。いずれも表示用の帯であり、採点には使われません',

        // ── AP3 composite trust chip ────────────────────────────────────
        'ui.trust.trusted': '信頼度: 通常',
        'ui.trust.reserved': '信頼度: 留保つき',
        'ui.trust.distrust': '信頼度: 結論を信じないこと',
        'ui.trust.formula': 'trust = min(recall, null-zone, drift, 稼働監視, データ鮮度) — 最悪の要素が全体を決めます（NP1）',
        'ui.trust.tooltip_row': '{name}: {state} / 実効値 {value} / 境界 {boundary} / 出所 {source}',
        'ui.trust.component.recall': 'recall',
        'ui.trust.component.null_zone': 'null-zone',
        'ui.trust.component.drift': 'drift',
        'ui.trust.component.ops_health': '稼働監視',
        'ui.trust.component.freshness': 'データ鮮度',
        'ui.trust.reason.recall': 'recall 低下',
        'ui.trust.reason.null_zone': '結論不可の継続',
        'ui.trust.reason.drift': 'drift 検知',
        'ui.trust.reason.ops_health': '稼働監視が未供給',
        'ui.trust.reason.freshness': 'データが古い',
        'ui.trust.reason.none': '要素なし',
        'ui.trust.state.measured': '測定済',
        'ui.trust.state.unmeasurable': '測定不能',
        'ui.trust.state.unsupplied': '未供給',
        'ui.trust.state.boundary_undisclosed': '境界が未開示',

        // ── situation board ─────────────────────────────────────────────
        'ui.board.focused': 'focus 中',
        'ui.board.focus_here': 'このシナリオを focus',
        'ui.board.score': 'スコア {score}',
        'ui.board.tl_caption': '脅威レベル',
        'ui.board.open_face': 'シナリオ面を開く（scenario_id: {id}）',
        'ui.board.availability.concluded': '結論あり',
        'ui.board.availability.inconclusive': '結論不可',
        'ui.board.availability.never_observed': '観測実績なし',
        // 結論不可カードは「なぜ出せないか」と「何があれば出せるか」を文で
        // 言う（P9 §3.1 / O-7）。文はサーバが送った状態の言語化であって、
        // 判断の再構成ではない。
        'ui.board.availability.sentence.inconclusive': '結論を出せていません。採点は走りましたが、この時点の結論に足りる根拠がありません（故障ではありません）。',
        'ui.board.availability.sentence.never_observed': 'このシナリオの観測が台帳にまだ 1 件もありません。センサーが観測を書き込むと採点が始まります。',
        'ui.board.resolution.days': '解消の見込み: あと {days} 日（較正窓 {window} 日のうち {observed} 日を観測済）。',
        'ui.board.resolution.unsupplied': '解消条件はこのカードには供給されていません。シナリオ面の結論不可欄（R2）に理由と解消条件が出ます。',
        'ui.board.coverage.full': '全センサー稼働（scoring_mode: {mode}）',
        'ui.board.coverage.limited': 'background のため観測範囲が限定されています（scoring_mode: {mode}）',
        'ui.board.since.first_sighting': 'この画面でこのシナリオを表示するのは初回です。次回からは前回表示との差を文で出します。',
        'ui.board.since.worsened': '前回確認（{ago}前）から悪化しました。TL {previous} → {current}（severity {delta}）。',
        'ui.board.since.improved': '前回確認（{ago}前）から改善しました。TL {previous} → {current}（severity {delta}）。',
        'ui.board.since.unchanged': '前回確認（{ago}前）から変化はありません（TL {previous}）。',
        'ui.board.since.unknown': '前回確認（{ago}前）との比較ができません（前回 TL {previous}、現在は結論不可）。',
        'ui.board.summary.unsupplied': '状況サマリ文がサーバから供給されていません（R1 の board_summary 未供給）。下のカードと注目レーンを直接読んでください。',
        'ui.board.summary.template': '文の生成テンプレート: {ref}',
        'ui.board.participants_label': 'このシナリオの参加国（結合の強い順）',
        'ui.board.why': 'なぜ? →',
        'ui.board.mode.full': '全センサー採点',
        'ui.board.mode.lite': 'LLM 情勢+グローバル信号のみ',
        'ui.board.mode.unknown': '採点範囲は未記録',
        'ui.board.derived.mode_only': '由来: {mode}。',
        'ui.board.derived.line': '由来: {mode} — {parts}。',
        'ui.board.derived.domain': '{name} {sources} 件',
        'ui.board.derived.unavailable': '由来: {mode} — この時点ではドメイン別の像はありません（{reason}）。',
        'ui.board.derived.absent': '由来: {mode} — ドメイン別内訳の記録がまだありません。',
        'ui.board.derived.unreadable': '由来: {mode} — ドメイン別内訳の行が読めません（記録は存在します）。',

        // ── 状況ビューのシナリオ地図（P9 §2.2 R-F / §3.7、§1.4 D-15/D-18
        //    で主面化 — タイトル・説明文は密度のため撤去、意味は tooltip） ──
        'ui.board_map.membership': '{name} — TL {tl}',
        'ui.board_map.membership_null': '{name} — TL 未算出',
        'ui.board_map.adversary_suffix': '（敵対側）',
        'ui.board_map.unplaced_on_real': '地図に置けない国: {list}（座標資産の未登録 — 観測は落としていません）',
        // ── 観測レイヤ（P8 §9 / NP9） ────────────────────────────────────
        'ui.board_map.obs.counts': '観測（24 時間）: 発火 {fired} 件 / 抑制 {suppressed} 件（{band}）',
        'ui.board_map.obs.band_dense': '毎 tick の国別掃引',
        'ui.board_map.obs.band_global': '全球掃引の到達のみ',
        'ui.board_map.obs.silent': 'この 24 時間、国別掃引の対象外で、全球掃引からも観測が届いていません（静けさではなく未観測）',
        'ui.board_map.obs.unsupplied': '観測ボード（R16）が未取得のため、観測数は表示できません',
        'ui.board_map.legend': '数字 = 24 時間の発火観測数。大マーカー = シナリオ参加国（色は最深刻 TL）、小ドット = 全球掃引のみが到達した国。数字なし = 未観測（静けさとは区別されます）',
        'ui.board_map.coverage_silent': '観測範囲: センサー {total} 基中 {silent} 基が沈黙 — {names}（上の数字はこれらの寄与を含みません）',
        'ui.board_map.coverage_all': '観測範囲: 宣言センサー {total} 基すべてが観測を書き込んでいます',
        'ui.board_map.coverage_unsupplied': '観測範囲: センサー面（R8）が未取得のため確認できません',
        'empty.board_map.role': 'ここには監視中の全シナリオの参加国が、地域ブロックのタイル地図で表示されます。',
        'empty.board_map.reason_not_loaded': 'シナリオ台帳（R1）をまだ取得できていないため、いまは空です。',
        'empty.board_map.reason_no_scenarios': 'シナリオが 1 件も構成されていないため、いまは空です。',
        'empty.board_map.fills_when': 'シナリオ定義が読めた時点で、参加国タイルが自動的に並びます。',

        // ── domains ─────────────────────────────────────────────────────
        'ui.domain.cyber': 'サイバー',
        'ui.domain.physical': '物理',
        'ui.domain.info': '情報',
        'ui.domain.state.ACTIVE': '活性',
        'ui.domain.state.ELEVATED': '上昇',
        'ui.domain.state.DEGRADING': '低下中',
        'ui.domain.state.STABLE': '安定',
        'ui.domain.state.INSUFFICIENT_SIGNAL': '信号不足',
        'ui.domain.state.unknown': '状態不明',

        // ── attention lane ──────────────────────────────────────────────
        'ui.lane.open': '開く',
        'ui.lane.open_absent': 'シナリオが特定されていないため、この行からは開けません。',
        'ui.lane.ack': '確認済',
        'ui.lane.snooze': '一時保留',
        'ui.lane.dismiss': '却下',
        'ui.lane.expand': '全件表示（あと {n} 件）',
        'ui.lane.collapse': '上位のみ表示',
        'ui.lane.summary': '{shown} / {total} 件を表示。順位付け対象 {considered} 件、下限未満で除外 {filtered} 件。',
        'ui.lane.suppressed': '抑止中 {n} 件（確認済 {acked} / 一時保留 {snoozed} / 却下 {dismissed}）。抑止しても消えません。',
        'ui.lane.basis': '順位の根拠: score {score} = novelty {novelty} × 確信度変化 {confidence} × 未確認度 {blindness} / 式 {formula} / 台帳 {snapshot}',
        'ui.lane.rank_fallback': '（順位未確定）',
        'ui.lane.narrative.unsupplied': '説明文がサーバから供給されていません。',
        'ui.lane.state.active': '未対応',
        'ui.lane.state.acked': '確認済',
        'ui.lane.state.snoozed': '一時保留',
        'ui.lane.state.dismissed': '却下',

        // ── conclusion face ─────────────────────────────────────────────
        'ui.conclusion.type.threat_level': '全体脅威レベル',
        'ui.conclusion.type.trend': 'トレンド',
        'ui.conclusion.type.per_domain': 'ドメイン別兆候',
        'ui.conclusion.type.anomaly': '個別異常事象',
        'ui.conclusion.type.attack_mode': '推定攻撃シナリオ',
        'ui.conclusion.section.missing': 'この結論型はサーバから返されていません（結論不可とは異なります）。',
        'ui.conclusion.state': '判定 {state} / 確信度 {confidence}',
        'ui.conclusion.formula': '式: {ref}',
        'ui.conclusion.why': 'なぜそう言えるのか',
        'ui.conclusion.overridden': 'ガードが発火しましたが、警報側のため結論を公表しています（NP1）。',
        'ui.conclusion.unreadable': '再構成できなかった台帳行が {n} 件あります。導出の鎖に欠落があります。',
        'ui.conclusion.empty.not_loaded': '結論をまだ取得していません。',
        'ui.conclusion.unavailable.insufficient_data': '結論不可: 判断の根拠となるデータが不足しています。',
        'ui.conclusion.unavailable.calibration_pending': '結論不可: calibration に必要な観測期間が未達です。',
        'ui.conclusion.unavailable.sensor_degraded': '結論不可: センサーの被覆が劣化しています。',
        'ui.conclusion.unavailable.upstream_failure': '結論不可: 上流ソースの取得に失敗しています。',
        'ui.conclusion.guard': '発言したガード: {guard} / 条件: {condition} / 詳細: {detail}',
        'ui.conclusion.guard_row': '{guard}（{reason}）発火: {fired} — {detail}',
        'ui.conclusion.resolves': '解消の見込み: あと {days} 日（{text}）',
        'ui.conclusion.resolves_unknown': '解消条件はサーバから供給されていません。',
        'ui.conclusion.calibration.summary': 'calibration: {status} / recall {recall} / precision {precision} / 標本数 {n}',
        'ui.conclusion.calibration.degraded': 'calibration が DEGRADED です。実際のエスカレーションを見逃している可能性があります（NP1）。',
        'ui.conclusion.calibration.provisional': '標本数 {value} は開示された下限 {boundary} を下回るため、暫定値として扱ってください。',
        'ui.conclusion.calibration.floor_undisclosed': '標本数 {value} の妥当性を判断する下限がサーバから開示されていません。',

        // ── derivation ──────────────────────────────────────────────────
        'ui.derivation.title': '導出ビュー',
        'ui.derivation.lead': 'この結論は、どの式・どの実効閾値・どの観測・どの一次ソースから出たのか。',
        'ui.derivation.section.formula': '計算式',
        'ui.derivation.section.inputs': '入力値',
        'ui.derivation.section.thresholds': '実効閾値',
        'ui.derivation.section.calibration': 'calibration',
        'ui.derivation.section.input_health': '入力の健全性',
        'ui.derivation.section.guards': 'ガード評価（抑制寄与を含む）',
        'ui.derivation.section.sources': '一次ソース',
        'ui.derivation.section.llm_prompt': 'LLM プロンプト同一性',
        'ui.derivation.section.none': 'この節に該当するものはありません。',
        'ui.derivation.section.formula_unrecorded': '式の参照先が記録されていません。',
        'ui.derivation.section.llm_unused': 'LLM は使用していません。',
        'ui.derivation.empty.not_loaded': '結論を選ぶと導出根拠を表示します。',

        // ── self-evaluation and sensors ─────────────────────────────────
        'ui.selfeval.title': '自己評価の内訳',
        'ui.selfeval.lead': '今このツールの結論をどこまで信じてよいか。合成信頼度を作っている要素の全数。',
        'ui.selfeval.col.component': '要素',
        'ui.selfeval.col.state': '状態',
        'ui.selfeval.col.value': '実効値',
        'ui.selfeval.col.boundary': '境界',
        'ui.selfeval.col.source': '境界の出所',
        'ui.selfeval.col.detail': '詳細',
        'ui.sensors.title': 'センサー健全性',
        'ui.sensors.lead': 'どの観測源が生きていて、どれが沈黙しているか。',
        'ui.sensors.col.sensor': 'センサー',
        'ui.sensors.col.domain': 'ドメイン',
        'ui.sensors.col.observations': '観測数',
        'ui.sensors.col.fired': '発火',
        'ui.sensors.col.suppressed': '抑制',
        'ui.sensors.col.silent': '状態',
        'ui.sensors.state.silent': '沈黙 — この窓で観測ゼロ',
        'ui.sensors.state.last_seen': '最終観測 {ago}前',

        // ── decision ledger (AP4) ───────────────────────────────────────
        'ui.decisions.title': '判断台帳',
        'ui.decisions.lead': '自動化と人が、いつ・何を・どの理由で決めたか（追記のみ・読み取り専用）。',
        'ui.decisions.sentence': '{actor} が {target} に {action} を実行（{type}）。',
        'ui.decisions.sentence_no_target': '{actor} が {action} を実行（{type}）。',
        'ui.decisions.reason': '理由: {reason}',
        'ui.decisions.automated': '自動',

        // ── proposals ───────────────────────────────────────────────────
        'ui.proposals.title': '提案レビュー',
        'ui.proposals.lead': 'ツールが自分で出した変更提案のうち、まだ裁定されていないものは何か。',
        'ui.proposals.change': '{from} → {to}（標本数 {n}）',
        'ui.proposals.apply': '適用',
        'ui.proposals.dismiss': '却下',
        'ui.proposals.defer': '保留',

        // ── what-if (server dry-run) ────────────────────────────────────
        'ui.whatif.title': '反実仮想（サーバ dry-run）',
        'ui.whatif.lead': '入力をこう変えたら結論は動くのか。動かないなら、その結論は何に支えられているのか。',
        'ui.whatif.hint': '採点はサーバの L2 カーネルが行います。この画面は baseline と counterfactual の差分を表示するだけで、ブラウザ側では一切採点しません。',
        'ui.whatif.placeholder': '{"weights": {"scenario_id": {"TW": 0.8}}}',
        'ui.whatif.run': 'dry-run を実行',
        'ui.whatif.col.scenario': 'シナリオ',
        'ui.whatif.col.baseline': 'baseline（基準）TL',
        'ui.whatif.col.counterfactual': 'counterfactual（反実仮想）TL',
        'ui.whatif.col.severity_delta': 'severity 差分',
        'ui.whatif.col.score_delta': 'スコア差分',

        // ── replay (AP4) ────────────────────────────────────────────────
        'ui.replay.label': '過去断面 (UTC)',
        'ui.replay.slider_label': '時間をたどる（7 日）',
        'ui.replay.live': 'ライブへ',
        'ui.replay.at_live': 'ライブ',
        'ui.replay.at_instant': '{at} 時点',
        'ui.replay.active': 'Replay 表示中: {at} 時点の断面です。現在の状況ではありません。',

        // ── feedback form (S1-UI-043 is the reference form) ─────────────
        'ui.feedback.title': 'この結論の判定は正しかったか',
        'ui.feedback.analysts': '投稿したアナリスト {n} 名。単一の裁定ではなく全ラベルの件数を示します。',
        'ui.feedback.label.TRUE_POSITIVE': 'TP（正しく警報）',
        'ui.feedback.label.FALSE_POSITIVE': 'FP（誤警報）',
        'ui.feedback.label.TRUE_NEGATIVE': 'TN（正しく平常）',
        'ui.feedback.label.FALSE_NEGATIVE': 'FN（見逃し）',
        'ui.feedback.ready': '送信できます。',
        'ui.feedback.no_label': 'ラベルを選択してください。',
        'ui.feedback.reason_required': '理由の入力が必要です。',
        'ui.feedback.saving': '保存中です。',
        'ui.feedback.saved': '保存しました。集計を更新しました。',
        'ui.feedback.rejected': 'サーバに拒否されました。',
        'ui.feedback.network_error': 'ネットワーク障害で送信できませんでした。',
        'ui.feedback.unsupported': 'この結論は保存されていないため、ラベルを付けられません。',

        // ── commands, prompts, toasts ───────────────────────────────────
        'ui.action.refresh': '再取得',
        'ui.command.focus': 'focus の変更',
        'ui.command.ack': '確認済の記録',
        'ui.command.snooze': '一時保留',
        'ui.command.dismiss': '却下',
        'ui.command.proposal_apply': '提案の適用',
        'ui.command.proposal_dismiss': '提案の却下',
        'ui.command.proposal_defer': '提案の保留',
        'ui.command.whatif': '反実仮想の実行',
        'ui.command.feedback': 'ラベルの投稿',
        'ui.prompt.focus_reason': 'focus を変更する理由を入力してください（判断台帳に記録されます）',
        'ui.prompt.proposal_reason': '裁定の理由を入力してください（判断台帳に記録されます）',
        'ui.prompt.snooze_minutes': '一時保留する分数を入力してください（1〜1440）',
        'ui.prompt.feedback_reason': 'この判定を選んだ理由を入力してください（較正の教師信号として台帳に残ります）',
        'ui.prompt.feedback_url': '裏付けとなる観測の URL があれば入力してください（任意。空欄可）',
        'ui.confirm.proposal_apply': 'この提案を適用します。最終判断は組織のプロセスで行われることを確認しましたか。',
        'ui.toast.command_ok': '{what}: 完了しました。',
        'ui.toast.command_failed': '{what}: 失敗しました（{why}）。',
        'ui.toast.reason_required': '理由が空のため送信しませんでした。',
        'ui.toast.bad_minutes': '分数として解釈できない入力のため送信しませんでした。',
        'ui.toast.bad_overlay': 'overlay が JSON として解釈できません。',
        'ui.toast.render_failed': '{section} の描画に失敗しました（{why}）。この区画は更新されていません。',
        'ui.toast.refresh_failed': '再取得に失敗しました（{why}）。次の周期で再試行します。',

        // ── deferred surfaces (P7 entries L6 does not serve yet) ────────
        'ui.deferred.intel_read': 'インテルレビュー: 供給 API (R11) が未実装のため、この画面はまだありません。',
        'ui.deferred.intel_verdict': 'インテル裁定: 指令 API (C3) が未実装です。',
        'ui.deferred.suppressions': 'ノイズ除外規則: 指令 API (C8) が未実装です。',
        'ui.deferred.human_anchor': '人間アンカー: 指令 API (C10) が未実装です。',
        'ui.deferred.scenario_admin': 'シナリオ管理: 指令 API (C11) が未実装です。',
        'ui.deferred.llm_ops': 'LLM 運用: 指令 API (C12) が未実装です。',
        // 未着地面（P9 §3.3）。断片を本番ビューに散らす代わりに、検証ビュー
        // 末尾の 1 表へ集約する。「まだ無い」と「データが無い」は別の状態で
        // あり、前者は 1 か所で全数を数えられなければならない。
        'ui.deferred.title': '未着地の機能',
        'ui.deferred.lead': 'この配備にまだ無い面の全数。空の画面ではなく、未着地であることをここで一括して申告します。',
        'ui.deferred.col.id': '繰延 ID',
        'ui.deferred.col.reason': '理由',
        'ui.deferred.col.landing': '着地予定 WP',
        'ui.deferred.landing.unplanned': '未登録（P3 の作業表に着地先の記載なし）',
        'ui.deferred.onboarding_persistence': '案内カードの開閉状態を利用者ごとに保存する面がありません。R14 は配備設定の registry であって利用者設定ではなく、利用者設定を持つ API はどの面にも供給されていません。localStorage 単独での保存は S1-UI-035 が禁じるため、開閉状態は保存していません。',

        // ── login gate (S1-UI-001〜005) ─────────────────────────────────
        'ui.auth.title': 'Noroshi v3 — サインイン',
        'ui.auth.lede': 'このツールの結論は最終判断ではありません。閲覧には認証が必要です。',
        'ui.auth.user': '利用者 ID',
        'ui.auth.password': 'パスワード',
        'ui.auth.submit': 'サインイン',
        'ui.auth.submitting': '確認中…',
        'ui.auth.checking': 'セッションを確認しています…',
        'ui.auth.signout': 'サインアウト',
        'ui.auth.identity': '{user}（{role}）',
        'ui.auth.required': '入力が不足しているため送信しませんでした。',
        'ui.auth.detail': 'サーバの応答: {why}',
        'ui.auth.reason.never': 'サインインしてください。',
        'ui.auth.reason.expired': 'セッションの有効期限が切れました。再度サインインしてください。',
        'ui.auth.reason.revoked': 'セッションが失効しました（ログアウト・パスワード変更・権限変更のいずれか）。再度サインインしてください。',
        'ui.auth.reason.signed_out': 'サインアウトしました。',
        'ui.auth.reason.refused': '利用者 ID またはパスワードが正しくありません。',
        'ui.auth.reason.throttled': 'ログイン試行が多すぎます。しばらく待って再試行してください。',
        'ui.auth.reason.unavailable': 'この配備は認証機構なしで構成されています。運用者に連絡してください。',
        'ui.auth.reason.transport': 'サーバに到達できませんでした。ネットワークを確認してください。',

        // ── 表示モード（S1-UI-030〜032/034） ─────────────────────────────
        'ui.mode.dormant': '待機表示',
        'ui.mode.pin-dock': '常設表示',
        'ui.mode.critical-banner': '最重要バナー',
        'ui.mode.banner': '重大事象があります（対象 {item}）。確認済・一時保留・却下では消えません。',
        'ui.mode.reason.flagged': 'サーバが重大標識（{flag}）を付けた行があります（対象 {item}）。閾値評価は行いません（NP1）。',
        'ui.mode.reason.top_band': 'CRITICAL 帯の行があります（対象 {item}）。閾値評価は行いません（NP1）。',
        'ui.mode.reason.not_loaded': '注目レーンを未取得のため畳みません。「静か」と「未取得」は別の主張です。',
        'ui.mode.reason.ranked_rows': '順位付けされた行が {n} 件あります。',
        'ui.mode.reason.holding': 'レーンは静かですが、畳むまでの連続静穏回数に達していません（{n}/{of} 回）。',
        'ui.mode.reason.quiet': '{n} 周期連続で順位付けされた行がありません。',
        'ui.mode.reason.quiet_unexplained': '{n} 周期連続で行がなく、サーバも空の理由を返していません。',
        'ui.mode.reason.pinned': '常時表示の指定があるため、最小でも常設表示を維持します。',

        // ── focus 切替の遮蔽（S1-UI-048/049） ────────────────────────────
        'ui.dim.loading': 'focus 切替中です。結論の到着まで地理面を遮蔽しています。',
        'ui.dim.timed_out': '同期未完了 — 最後に取得した状態を表示中です。遮蔽は維持します（前のシナリオの数値を新しい名前で見せないため）。任意のキーで解除できます。',
        'ui.dim.refreshing': '更新中です（残りの取得を待っています）。',
        'ui.dim.stale': '更新が完了しませんでした。表示は最後に取得した状態です。',
        'ui.dim.suppressed': 'Replay 中のため遮蔽しません。',
        'ui.dim.retry': '再取得',

        // ── 異常の地理面（P8 §6） ───────────────────────────────────────
        'ui.geo.title': '異常の地理面',
        'ui.geo.offroster': 'シナリオ未登録の観測',
        'ui.geo.summary': 'participant {participants} 件 / 発火 {fired} 件 / 抑制 {suppressed} 件 / 観測 {observations} 件（直近 {window}）',
        'ui.geo.weight': '結合重み {weight}',
        'ui.geo.chain': '連鎖起点',
        'ui.geo.adversary': '攻撃側',
        'ui.geo.layer_off': 'このレイヤは表示していません。',
        'ui.geo.layer.participants': 'participant マーカー',
        'ui.geo.layer.anomalies': '異常事象マーカー',
        'ui.geo.layer.chain': 'シーケンス連鎖',
        'ui.geo.layer.reference': '静的参照（チョークポイント・ケーブル・ISR）',
        'ui.geo.layer.reference_unserved': 'サーバが座標を供給していないため描画できません。合成ルートは geo_data.json を読んでいますが、API 面に載せる経路がありません。ブラウザ側に座標表を持てば第 2 の配備データ読み手になるため、持ちません。',
        'ui.geo.fired_row': '{sensor}（{domain}）発火 / raw {score} / 確信度 {confidence}',
        'ui.geo.suppressed_row': '{sensor}（{domain}）抑制 — 理由: {reason}',
        'ui.geo.marker.unobserved': '観測行なし（「静か」ではなく「観測していない」）',
        'ui.geo.marker.fired': '発火 {fired} 件 / 抑制 {suppressed} 件 / 観測 {observations} 件',
        'ui.geo.marker.suppressed_only': '発火なし。抑制 {suppressed} 件（観測 {observations} 件）— 抑制は「起きていない」ではありません。',
        'ui.geo.marker.observed_quiet': '観測 {observations} 件、いずれも発火せず',
        // 国タイル地図（P9 §3.4）。座標は使わず、参加国を地域ブロックに
        // 並べた CSS グリッドで「どこで起きているか」に答える。地域名は
        // 配置表に実在する地域のみ定義する（空のブロックは「そこは静か」
        // と読めてしまうが、実際には見てすらいない）。
        'ui.geo.tilemap.title': '国タイル地図',
        'ui.geo.tilemap.lead': '参加国を地域ブロックに配置した図です。地理座標は使っていません（配置は表示上の定数）。',
        'ui.geo.tilemap.list_head': '国別の一覧（タイル地図と同じ内容）',
        'ui.geo.tilemap.unplaced_note': '配置表に登録がない国です。地域ブロックに置けないためここへまとめています（観測は落としていません）。',
        'ui.geo.tile.tip': '{country} — {role} / {state}',
        'ui.geo.region.east_asia': '東アジア',
        'ui.geo.region.southeast_asia': '東南アジア',
        'ui.geo.region.middle_east': '中東',
        'ui.geo.region.europe': '欧州',
        'ui.geo.region.north_america': '北米',
        'ui.geo.region.oceania': 'オセアニア',
        'ui.geo.region.unplaced': '配置未定義',
        'ui.geo.role.unlisted': 'シナリオ未登録',
        'ui.geo.role.unmapped': '（未知の役割 — 観測クラスとして扱っています）',
        'ui.geo.role.primary_target': '主対象',
        'ui.geo.role.principal_belligerent': '主交戦国',
        'ui.geo.role.adversary': '敵対国',
        'ui.geo.role.proxy_front': '代理勢力',
        'ui.geo.role.primary_ally': '主要同盟国',
        'ui.geo.role.secondary_ally': 'second 同盟国',
        'ui.geo.role.forward_base': '前方拠点',
        'ui.geo.role.extended_deterrence': '拡大抑止',
        'ui.geo.role.force_projection': '戦力投射',
        'ui.geo.role.spillover_risk': '波及リスク',
        'ui.geo.role.secondary_party': '副次当事国',
        'ui.geo.role.regional_power': '地域大国',
        'ui.geo.role.strategic_observer': '戦略的観測国',

        // ── SETTINGS（S1-UI-067〜070 / G-15 の恒久化） ───────────────────
        'ui.settings.title': '設定',
        'ui.settings.lead': 'この配備で運用可変なキーは何で、いまどの層の値が効いているか。',
        'ui.settings.lede': '本画面に出るのは、3 段テスト（読み手が実在する / 読み手の AST がキー名を含む / override が出力を変える）を通過したキーだけです。本番の設定面は 98 キーを並べ、うち 95 キーは DB override 層に届いていませんでした（G-15）。数が少ないことは欠落ではなく、可変であると検証できたキーがこれだけであるという事実です。',
        'ui.settings.summary': '可変キー {variable} 件（本画面で変更可）／固定定数 {pinned} 件（R10 が開示。変更はコード変更）',
        'ui.settings.col.key': 'キーと可変である理由',
        'ui.settings.col.badges': '出所・env・読み手・可変性',
        'ui.settings.col.value': '現在値',
        'ui.settings.col.default': '既定値',
        'ui.settings.col.override': 'override の記録',
        'ui.settings.col.actions': '操作',
        'ui.settings.source.override': '出所: override',
        'ui.settings.source.env': '出所: env',
        'ui.settings.source.default': '出所: default',
        'ui.settings.source.unknown': '出所: サーバ未申告',
        'ui.settings.env.present': 'env 層にあり',
        'ui.settings.env.absent': 'env 層になし',
        'ui.settings.writable': '可変',
        'ui.settings.consumer_tip': 'このキーを実際に読む関数です。R14 が申告しています。反映タイミングと影響度のバッジは、サーバがそれを申告していないため出しません（申告の無いバッジはブラウザ側の推測になります）。',
        'ui.settings.no_override': 'override なし',
        'ui.settings.override_by': '{actor} が {at} に設定 — 理由: {reason}',
        'ui.settings.save': '保存',
        'ui.settings.clear': 'override 解除',
        'ui.settings.gt_title': 'ground truth 一覧（読み取り専用）',
        'ui.settings.gt_lead': 'どの時点のどのシナリオに、人がどの正解ラベルを与えたか（較正の入力）。',
        'ui.settings.gt.scenario': 'シナリオ',
        'ui.settings.gt.observed_at': '観測時刻 (UTC)',
        'ui.settings.gt.label': 'ラベル',
        'ui.settings.gt.actor': '記録者',
        'ui.settings.gt.source': '出典 / 理由',
        'ui.settings.empty.not_loaded': '設定をまだ取得していません。',
        'ui.settings.empty.no_variable_keys': 'この配備には運用可変キーがありません（設定解決チェーンが未供給の可能性があります）。',
        'ui.settings.confirm': '{key}: {from} → {to}（単位 {unit}）。読み手は {consumer} です。この変更を判断台帳に記録して適用しますか。',
        'ui.settings.confirm_clear': '{key} の override を解除します。env 層または既定値へ戻ります。解除も追記として台帳に残ります。',
        'ui.settings.prompt.reason': '変更の理由を入力してください（必須。判断台帳に残ります）',
        'ui.settings.command.save': '設定の変更',
        'ui.settings.command.clear': 'override の解除',
        'ui.settings.error.unknown_key': 'このキーは可変キー一覧にありません。',
        'ui.settings.error.no_change': '差分がないため送信しませんでした。',
        'ui.settings.error.not_bool': 'bool のキーには true / false のみ指定できます。',
        'ui.settings.error.empty': '値が空です。',
        'ui.settings.error.not_number': '数値として解釈できません。',
        'ui.settings.error.not_integer': 'このキーの単位は count のため整数のみです。',
        'ui.settings.result.applied': '適用しました。3 層チェーンの再解決値は {value}（出所 {source}）です。',
        'ui.settings.result.recorded_no_effect': '台帳には記録されましたが、実効値は変わっていません（再解決値 {value} / 出所 {source}）。これは G-15 の兆候です。',
        'ui.settings.result.refused': 'サーバに拒否されました（{why}）。',

        // ── ライブチャネル（S1-UI-009〜011 / §7-2 #112） ─────────────────
        // 状態語 connected / degraded / disconnected は S1-UI-011 の契約語で
        // あり、ja-localization §2 の「API 状態値の生値は訳さない」に従って
        // 英語のまま残す。括弧内は読み手のための注釈であって訳語ではない。
        'ui.live.state.unmounted': 'live: unmounted（チャネル未マウント）',
        'ui.live.state.connecting': 'live: connecting（接続試行中）',
        'ui.live.state.connected': 'live: connected（接続中）',
        'ui.live.state.degraded': 'live: degraded（確立に繰り返し失敗）',
        'ui.live.state.disconnected': 'live: disconnected（切断）',
        'ui.live.polling_continues': 'ライブチャネルの状態にかかわらず、ポーリングは継続します（切断時も加速しません）。push は再取得の合図であり、表示値そのものではありません。',
        'ui.live.server_reason': 'サーバの申告: {why}',
        'ui.live.reason.unknown': '配備設定（R15c）を未取得のため、チャネルの有無が不明です。',
        'ui.live.reason.undeclared': '配備設定に websocket の申告がありません。接続は試みません。',
        'ui.live.reason.unmounted': 'この配備は socket チャネルを合成していません。「切断」ではなく「最初から無い」状態です。',
        'ui.live.reason.dialling': '接続を試みています。',
        'ui.live.reason.connected': '接続しました。以降 push は該当射影の再取得の合図として扱います。',
        'ui.live.reason.dropped': '接続が切れました。バックオフして再試行します。',
        'ui.live.reason.degraded': '接続確立に繰り返し失敗しています（degraded）。単発の切断とは区別しています。',
        'ui.live.reason.stopped': 'クライアント側で停止しました。',
        'ui.live.subscribed': 'シナリオの購読が確立しました。',
        'ui.live.accepted': 'push を受理し、該当射影を再取得します。',
        'ui.live.drop.malformed': '解釈できない push を破棄しました。',
        'ui.live.drop.retired': 'v3 で廃止済のイベント名を受信しました。サーバが古い可能性があります。',
        'ui.live.drop.server_error': 'サーバがチャネル上でエラーを返しました。',
        'ui.live.drop.unpublished': '発行されないはずのイベントを受信しました。契約違反として記録します。',
        'ui.live.drop.unknown': '未知のイベント名を破棄しました。',
        'ui.live.drop.other_scenario': '現在の focus と異なるシナリオの push を破棄しました。',

        // ── misc ────────────────────────────────────────────────────────
        'ui.yes': 'はい',
        'ui.no': 'いいえ',
        'ui.error.unknown': '原因不明',

        // ══ term.* — 内部語彙の自己定義（P9 §2 R-C / §4） ════════════════
        //
        // D-2: 画面が出す TL・severity・結論不可・scoring_mode・null-zone・
        // drift・recall・収斂 は S 仕様の内部語彙であり、これまで画面上に
        // 定義が無かった。「TL4 / ELEVATED」は答えではなく符号で、符号を
        // 読めない者は導出も検証できない（NP6）。
        //
        // 1 語 1 文。語そのもの（recall / drift / null-zone / scoring_mode）
        // は ja-localization §2 により英語のまま残し、意味だけを日本語で
        // 与える — 訳さないことと定義しないことは別、が R-C の趣旨。
        // 「詳細: INTEL GUIDE Ch.N」リンクは付けない（理由は terms.js）。
        'term.tl': '脅威レベル。1〜5 の整数で、1 が最も危険（DEFCON 型のため数値が小さいほど深刻）。',
        'term.severity': 'severity は 6 − TL で求める深刻度。TL とは向きが逆で、数値が大きいほど深刻。',
        'term.inconclusive': '結論不可。データまたは calibration の不足で結論を出せない状態であり、センサーやサーバの故障とは区別される。',
        'term.null_zone': 'null-zone は、採点は走ったが結論を出せる根拠に届かない領域。ここに長く留まり続けること自体がツールの設計失敗の兆候。',
        'term.scoring_mode': 'scoring_mode は採点時の観測範囲。full は全センサー稼働、lite は LLM とグローバル信号のみ。',
        'term.drift': 'drift は、calibration を行った時点と現在で入力の分布がずれていること。ずれたまま出した結論は過去の calibration では保証されない。',
        'term.recall': 'recall は、実際に起きたエスカレーションのうちツールが検知できた割合。NP1 により precision より優先する。',
        'term.convergence': '収斂は、複数ドメインのセンサーが同じ方向を同時に指すこと。単一ソースの信号より結論の強度が高い（NP2）。',

        // ══ empty.* — 空状態の 3 点セット（P9 §3.5 / D-4） ═══════════════
        //
        // 空可能なすべての面は 3 つを必ず言う: (a) ここは何を表示する場所か
        // (b) いま空である理由 (c) 何が起きれば埋まるか。S1-UI-008（空画面
        // 禁止）は (b) までしか要求しておらず、その結果 冷起動の画面は
        // 「空である」とだけ言って、初見者が画面の役割自体を学べなかった。
        //
        // (b) はサーバが申告した状態からのみ引く。サーバが理由を言って
        // いない面では、理由を捏造せず「申告が無い」と言う。
        'empty.reason.unstated': 'この面が空である理由をサーバは申告していません。空であるという事実だけが確かです。',
        'empty.reason.unrecognised': 'サーバは空の理由として {reason} を申告していますが、この画面はその語の説明文を持っていません。',

        'empty.board.role': 'ここは、監視中のシナリオごとの脅威レベルと、前回確認からの変化を並べる場所です。',
        'empty.board.reason_no_scenarios': 'この配備には登録されたシナリオが 1 件もありません。',
        'empty.board.reason_not_loaded': 'シナリオ台帳（R1）をまだ取得していません。',
        'empty.board.fills_when': 'シナリオが登録され、R1 が台帳を返すと、シナリオごとのカードがここに並びます。',

        'empty.lane.role': 'ここは、次に見るべき対象を順位付けの根拠つきで上から並べる場所です。',
        'empty.lane.reason_ranker_has_not_run': '順位付けがまだ実行されていません（注目対象が無いことを意味しません）。',
        'empty.lane.reason_all_rows_below_min_score': '順位付けは走りましたが、全候補が表示下限を下回りました。',
        'empty.lane.reason_no_ranked_items': '順位付けの対象となる結論がありません。',
        'empty.lane.reason_not_loaded': '注目レーン（R6）をまだ取得していません。',
        'empty.lane.fills_when': '異常兆候が検知され順位付けが実行されると、優先度順にここへ並びます。',

        'empty.geo.role': 'ここは、focus 中のシナリオの参加国ごとに、異常がどこで起きているかを示す場所です。',
        'empty.geo.reason_no_focus': 'focus 中のシナリオがありません。',
        'empty.geo.reason_scenario_not_loaded': 'シナリオ台帳にこのシナリオがありません。',
        'empty.geo.reason_not_loaded': '観測（R5）をまだ取得していません。',
        'empty.geo.reason_no_observations': '窓内に観測が 1 件もありません。平常ではなく、観測が無いという意味です。',
        'empty.geo.reason_observed_nothing_fired': '観測はありますが、発火・抑制いずれもありません。',
        'empty.geo.fills_when': 'シナリオを focus し、その参加国でセンサーが発火または抑制されると、タイルと一覧が埋まります。',

        'empty.proposals.role': 'ここは、ツールが自分で出した変更提案のうち、まだ裁定されていないものを並べる場所です。',
        'empty.proposals.reason_none': '保留中の提案がありません。',
        'empty.proposals.fills_when': '較正の結果として重み等の変更提案が生成されると、裁定待ちの行がここへ並びます。',

        'empty.decisions.role': 'ここは、自動化と人が、いつ・何を・どの理由で決めたかを時系列で並べる場所です。',
        'empty.decisions.reason_none': '記録された判断がありません。',
        'empty.decisions.fills_when': 'focus の変更・確認済の記録・提案の裁定など、台帳に追記される操作が行われると行が増えます。',

        'empty.sensors.role': 'ここは、どの観測源が生きていて、どれが沈黙しているかを並べる場所です。',
        'empty.sensors.reason_none': 'センサーの観測がありません。',
        'empty.sensors.fills_when': 'センサーが観測を書き込み、R8 がその健全性を返すと行が並びます。',

        'empty.groundtruth.role': 'ここは、どの時点のどのシナリオに人がどの正解ラベルを与えたかを並べる場所です（calibration の入力）。',
        'empty.groundtruth.reason_none': '記録された ground truth がありません。',
        'empty.groundtruth.reason_not_loaded': 'ground truth（C9g）をまだ取得していません。',
        'empty.groundtruth.fills_when': 'アナリストが正解ラベルを登録すると、calibration の入力としてここへ並びます。',

        'empty.whatif.role': 'ここは、入力をこう変えたら結論が動くかを、サーバの dry-run 結果として並べる場所です。',
        'empty.whatif.reason_not_run': 'まだ実行していません。',
        'empty.whatif.reason_no_scenarios': 'dry-run は走りましたが、対象シナリオが返っていません。',
        'empty.whatif.fills_when': 'overlay を入力して dry-run を実行すると、baseline と counterfactual の差分がここへ並びます。',
    };

    /**
     * Look up a key and fill its `{name}` slots.
     *
     * A missing key returns the key itself rather than throwing or
     * rendering empty: a visible `ui.thing.missing` on screen is a bug
     * report, whereas a blank element is a bug nobody notices. The audit
     * (`scripts/check_i18n_keys.py`) is what stops it reaching an analyst.
     */
    function t(key, vars) {
        let text = STRINGS[key];
        if (text === undefined) return key;
        if (!vars) return text;
        Object.keys(vars).forEach(function (name) {
            text = text.split('{' + name + '}').join(String(vars[name]));
        });
        return text;
    }

    /** Apply `data-i18n*` attributes. Idempotent. */
    function applyStatic(scope) {
        const root = scope || (typeof document !== 'undefined' ? document : null);
        if (!root || !root.querySelectorAll) return;
        root.querySelectorAll('[data-i18n]').forEach(function (el) {
            el.textContent = t(el.getAttribute('data-i18n'));
        });
        root.querySelectorAll('[data-i18n-html]').forEach(function (el) {
            el.innerHTML = t(el.getAttribute('data-i18n-html'));
        });
        root.querySelectorAll('[data-i18n-tip]').forEach(function (el) {
            el.setAttribute('title', t(el.getAttribute('data-i18n-tip')));
        });
        root.querySelectorAll('[data-i18n-ph]').forEach(function (el) {
            el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph')));
        });
    }

    return { STRINGS: STRINGS, t: t, applyStatic: applyStatic };
});
