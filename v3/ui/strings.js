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

        // ── loop stages ─────────────────────────────────────────────────
        'ui.stage.situation': '状況確認',
        'ui.stage.situation_q': '何か変わったか。今このツールを信じてよいか。（目標 10 秒）',
        'ui.stage.triage': 'トリアージ',
        'ui.stage.triage_q': '次に何を見るべきか。（目標 30 秒）',
        'ui.stage.drilldown': 'ドリルダウン',
        'ui.stage.drilldown_q': 'なぜそう言えるのか。何が起きたのか。',
        'ui.stage.feedback': 'フィードバック',
        'ui.stage.feedback_q': 'ツールの判断は正しかったか。',
        'ui.stage.verify': '検証',
        'ui.stage.verify_q': 'この系は生きているか。過去の判断は妥当だったか。',

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
        'ui.board.availability.concluded': '結論あり',
        'ui.board.availability.inconclusive': '結論不可（詳細はドリルダウン）',
        'ui.board.availability.never_observed': '観測実績なし',
        'ui.board.coverage.full': '全センサー稼働（scoring_mode: {mode}）',
        'ui.board.coverage.limited': 'background のため観測範囲が限定されています（scoring_mode: {mode}）',
        'ui.board.since.first_sighting': '前回確認の記録がありません（この画面での初回表示）',
        'ui.board.since.worsened': '前回確認から悪化（severity {delta}、前回 TL{previous}）',
        'ui.board.since.improved': '前回確認から改善（severity {delta}、前回 TL{previous}）',
        'ui.board.since.unchanged': '前回確認から変化なし（前回 TL{previous}）',
        'ui.board.since.unknown': '前回確認との比較ができません（前回 TL{previous}）',
        'ui.board.empty.no_scenarios': '登録されたシナリオがありません。',
        'ui.board.empty.not_loaded': 'シナリオ台帳をまだ取得していません。',

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
        'ui.lane.empty.ranker_has_not_run': '順位付けがまだ実行されていません（注目対象が無いことを意味しません）。',
        'ui.lane.empty.all_rows_below_min_score': '全候補が表示下限を下回りました。',
        'ui.lane.empty.no_ranked_items': '順位付けの対象となる結論がありません。',
        'ui.lane.empty.not_loaded': '注目レーンをまだ取得していません。',

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
        'ui.selfeval.col.component': '要素',
        'ui.selfeval.col.state': '状態',
        'ui.selfeval.col.value': '実効値',
        'ui.selfeval.col.boundary': '境界',
        'ui.selfeval.col.source': '境界の出所',
        'ui.selfeval.col.detail': '詳細',
        'ui.sensors.title': 'センサー健全性',
        'ui.sensors.col.sensor': 'センサー',
        'ui.sensors.col.domain': 'ドメイン',
        'ui.sensors.col.observations': '観測数',
        'ui.sensors.col.fired': '発火',
        'ui.sensors.col.suppressed': '抑制',
        'ui.sensors.col.silent': '無音継続',
        'ui.sensors.empty': 'センサーの観測がありません。',

        // ── decision ledger (AP4) ───────────────────────────────────────
        'ui.decisions.title': '判断台帳',
        'ui.decisions.col.at': '時刻 (UTC)',
        'ui.decisions.col.type': '種別',
        'ui.decisions.col.action': 'アクション',
        'ui.decisions.col.target': '対象',
        'ui.decisions.col.actor': '実行者',
        'ui.decisions.col.reason': '理由',
        'ui.decisions.automated': '自動',
        'ui.decisions.empty': '記録された判断がありません。',

        // ── proposals ───────────────────────────────────────────────────
        'ui.proposals.title': '提案レビュー',
        'ui.proposals.change': '{from} → {to}（標本数 {n}）',
        'ui.proposals.apply': '適用',
        'ui.proposals.dismiss': '却下',
        'ui.proposals.defer': '保留',
        'ui.proposals.empty': '保留中の提案はありません。',

        // ── what-if (server dry-run) ────────────────────────────────────
        'ui.whatif.title': '反実仮想（サーバ dry-run）',
        'ui.whatif.hint': '採点はサーバの L2 カーネルが行います。この画面は baseline と counterfactual の差分を表示するだけで、ブラウザ側では一切採点しません。',
        'ui.whatif.placeholder': '{"weights": {"scenario_id": {"TW": 0.8}}}',
        'ui.whatif.run': 'dry-run を実行',
        'ui.whatif.col.scenario': 'シナリオ',
        'ui.whatif.col.baseline': 'baseline（基準）TL',
        'ui.whatif.col.counterfactual': 'counterfactual（反実仮想）TL',
        'ui.whatif.col.severity_delta': 'severity 差分',
        'ui.whatif.col.score_delta': 'スコア差分',
        'ui.whatif.empty.not_run': 'まだ実行していません。',
        'ui.whatif.empty.no_scenarios': '対象シナリオがありません。',

        // ── replay (AP4) ────────────────────────────────────────────────
        'ui.replay.label': '過去断面 (UTC)',
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
        'ui.deferred.auth': '認証: 指令 API (C13) が未実装のため、ログインゲートは未接続です。',

        // ── misc ────────────────────────────────────────────────────────
        'ui.yes': 'はい',
        'ui.no': 'いいえ',
        'ui.error.unknown': '原因不明',
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
