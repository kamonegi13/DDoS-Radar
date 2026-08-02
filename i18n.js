/**
 * DDoS-Radar i18n — UI string dictionary (Japanese-only as of 2026-08-02)
 *
 * Policy: the UI is Japanese-only; there is no language switch. This stays
 * a keyed table rather than inline literals so the CI audit
 * (scripts/check_i18n_keys.py) can keep catching undefined references,
 * dead keys, and untranslated values.
 *
 * Terms deliberately left in English (CRITICAL/SEVERE/…, recall, drift,
 * Calibration, BGP, NP1-NP7, sensor IDs, API state codes) are enumerated
 * in docs/design/ja-localization.md §2 — over-translating them hurts a
 * CTI professional's reading speed.
 *
 * Usage:
 *   _t('key')          → return the string for `key`
 *   _t('key', {n: 3})  → with {n} placeholder substitution
 *
 * Key naming convention: namespace.sub_namespace.key
 * Placeholder format:    {name} inside string values
 */

const STRINGS = {

    // ══════════════════════════════════════════════════════════════
    // NP7 Final-Judgment Disclaimer Banner (v2 conclusions API)
    // ══════════════════════════════════════════════════════════════
    'banner.np7.fallback':            '本ツールの結論であり、最終判断は組織のプロセスによって行われます。',

    // ══════════════════════════════════════════════════════════════
    // Conclusion Cards (Layer 1 — v2 conclusions envelope renderer)
    // See docs/design/v2-ui.md §4
    // ══════════════════════════════════════════════════════════════
    'cc.title.threat_level':          '脅威レベル',
    'cc.title.trend':                 'トレンド',
    'cc.title.per_domain':            'ドメイン別',
    'cc.title.anomaly':               '異常事象',
    'cc.title.attack_mode':           '攻撃モード',
    'cc.label.confidence':            '確信度',
    'cc.label.unavailable':           '結論不可',
    'cc.label.insufficient_data':     'データ不足',
    'cc.label.insufficient_history':  '履歴不足',
    'cc.label.no_active':             '該当なし',
    'cc.label.tentative':             '暫定',
    'cc.label.degraded':              '劣化',
    'cc.label.calibration_pending':   'Calibration 待機中',
    'cc.label.sensor_degraded':       'センサー劣化',
    'cc.label.upstream_failure':      '上流障害',
    'cc.btn.drill':                   '導出 ▶',
    'cc.btn.drill_tooltip':           '導出開示を開く: 式・閾値・一次ソース・LLM プロンプト (NP6)',
    'cc.btn.export_md':               'Markdown 出力',
    'cc.btn.export_md_tooltip':       'シナリオの結論一式を 1 ファイルの .md として保存',
    'cc.horizon.short':               '24h',
    'cc.horizon.medium':              '7d',
    'cc.horizon.long':                '30d',
    'cc.domain.cyber':                'サイバー',
    'cc.domain.physical':             '物理',
    'cc.domain.info':                 '情報',
    'cc.tl.prefix':                   'TL',
    'cc.scoring_mode.full':           'full',
    'cc.scoring_mode.lite':           'C-lite',
    'cc.calib.sample_n':              'サンプル数 n={n}',
    'cc.calib.no_data':               'Calibration データ蓄積中',
    'cc.empty.waiting':               '初回スコアリングサイクル待機中…',
    'cc.error.fetch_failed':          '結論の取得に失敗しました',
    'cc.tip.np7':                     '本ツールの結論であり、最終判断は組織のプロセスが行います。',

    // Drill-down modal (Layer 2 — audit_trace)
    'drill_modal.title':              '結論導出経路 (Audit Trace)',
    'drill_modal.loading':            'audit trace を取得中…',
    'drill_modal.error.fetch_failed': 'audit trace の取得に失敗しました ({status})',
    'drill_modal.error.network':      'audit trace 取得時にネットワークエラー',
    'drill_modal.section.header':     '結論',
    'drill_modal.section.disclaimer': 'NP7 注意書き',
    'drill_modal.section.formula':    '計算式の参照先',
    'drill_modal.section.thresholds': '閾値リファレンス',
    'drill_modal.section.calibration':'Calibration ステータス',
    'drill_modal.section.sources':    '一次ソース',
    'drill_modal.section.metadata':   'メタデータ',
    'drill_modal.section.rationale_matrix': '寄与センサー一覧',
    'drill_modal.section.llm_prompt': 'LLM プロンプト',
    'drill_modal.label.scenario':     'シナリオ',
    'drill_modal.label.observed_at':  '観測時刻',
    'drill_modal.label.conclusion_id':'結論 ID',
    'drill_modal.label.confidence':   '確信度',
    'drill_modal.empty.formula':      '計算式の参照先は記録されていません',
    'drill_modal.empty.thresholds':   '閾値は記録されていません',
    'drill_modal.empty.calibration':  'Calibration ステータスは記録されていません',
    'drill_modal.empty.sources':      '一次ソースは記録されていません',
    'drill_modal.empty.metadata':     'メタデータは記録されていません',
    'drill_modal.empty.rationale_matrix': '寄与センサーは記録されていません',
    'drill_modal.rationale.col.sensor':       'センサー',
    'drill_modal.rationale.col.domain':       'ドメイン',
    'drill_modal.rationale.col.country':      '国',
    'drill_modal.rationale.col.contribution': '寄与スコア',
    'drill_modal.rationale.col.formula':      '計算式',
    'drill_modal.rationale.col.evidence':     '一次ソース',
    'drill_modal.calib.sample_size':  'サンプルサイズ',
    'drill_modal.calib.status':       'ステータス',
    'drill_modal.calib.last_updated': '最終更新',
    'drill_modal.calib.warn_low_n':   'サンプルサイズが閾値以下 — calibration は暫定値',
    'drill_modal.calib.recall':       'Recall (TP/(TP+FN))',
    'drill_modal.calib.precision':    'Precision (TP/(TP+FP))',
    'drill_modal.calib.fn':           'False negatives（見逃し）',
    'drill_modal.calib.sample_n':     'ラベル済みサンプル (n)',
    'drill_modal.calib.last_label_at': '最終ラベル時刻',
    'drill_modal.calib.warn_degraded': 'Recall が下限を下回っています — 実際のエスカレーションを見逃しています (NP1)',
    'drill_modal.llm.missing':        'プロンプト本文は保持されていません (prompt-store 導入前 / パージ済)',
    'drill_modal.llm.no_prompt':      'この結論は LLM プロンプトを使用していません',
    'drill_modal.llm.model':          'モデル',
    'drill_modal.llm.temperature':    'Temperature',
    'drill_modal.llm.use_count':      '使用回数',
    'drill_modal.llm.first_seen':     '初回使用',
    'drill_modal.llm.last_seen':      '最終使用',
    'drill_modal.llm.expand':         'プロンプト全文を表示',
    'drill_modal.llm.collapse':       'プロンプトを隠す',
    'drill_modal.llm.sha256':         'SHA-256',
    'drill_modal.section.feedback':       'アナリスト フィードバック',
    'drill_modal.feedback.legend':        'この結論をラベル付け（ground truth）:',
    'drill_modal.feedback.label.TRUE_POSITIVE':  'True Positive — 実際にエスカレート、検知正しい',
    'drill_modal.feedback.label.FALSE_POSITIVE': 'False Positive — 検知したが実態なし',
    'drill_modal.feedback.label.TRUE_NEGATIVE':  'True Negative — 検知せず、実態もなし',
    'drill_modal.feedback.label.FALSE_NEGATIVE': 'False Negative — 実態があったが見逃し',
    'drill_modal.feedback.url_placeholder':   '実観測 URL (ACLED/GDELT/報道、任意)',
    'drill_modal.feedback.notes_placeholder': '備考 (任意、最大 2000 文字)',
    'drill_modal.feedback.submit':            'フィードバック 送信',
    'drill_modal.feedback.summary_meta':      '合計: {total} • 個別 analyst 数: {distinct}',
    'drill_modal.feedback.summary_empty':     'この結論への フィードバック はまだありません。',
    'drill_modal.feedback.disabled':          '未保存の結論には フィードバック を送信できません。',
    'drill_modal.feedback.status.no_label':   'ラベルを選択してください。',

    // Human-anchor labeling queue (AP3, 2026-07-04; natural-question UX 2026-07-05)
    'human_anchor.title':              '人間アンカーキュー',
    'human_anchor.loading':            'キューを読み込み中…',
    'human_anchor.error':              'キューを取得できませんでした — API / 認証を確認してください。',
    'human_anchor.empty':              'キューは空です — 今週の候補はすべて人手でラベル付け済みです。ありがとうございます。',
    'human_anchor.progress':           '今週の人手ラベル: {done}/{target}。回答 1 件ごとに、ツールの recall が独立した判断で裏付けられます。',
    'human_anchor.tool_showed':        'この時点でのツールの判断: {stance}',
    'human_anchor.search':             '🔎 この期間のニュースを調べる ↗',
    'human_anchor.skip':               'わからない — 今はスキップ',
    'human_anchor.evidence.prompt':    '根拠リンクを追加 (任意 — 確認された脅威として記録します):',
    'human_anchor.evidence.record':    '記録',
    'human_anchor.recorded':           '✓ {label} として記録しました。ありがとうございます — この 1 件がツールの recall の裏付けになります。',
    'human_anchor.recorded_miss':      '✓ 記録しました: ツールは実際のエスカレーションを見逃していました。最も価値の高いラベルです — ありがとうございます。',

    'drill_modal.feedback.status.submitting': '保存中…',
    'drill_modal.feedback.status.saved':      'フィードバック を保存しました。',
    'drill_modal.feedback.status.bad_label':  'サーバーがラベルを拒否しました。',
    'drill_modal.feedback.status.failed':     '保存失敗 (HTTP {status})。',
    'drill_modal.feedback.status.network':    'ネットワークエラー — 再試行してください。',

    'drill_modal.section.llm_aug':            'LLM 補強',
    'drill_modal.llm_aug.empty':              'この結論には LLM 補強が記録されていません。',
    'drill_modal.llm_aug.attempted':          'LLM 呼び出し試行',
    'drill_modal.llm_aug.failed':             '失敗 ({error})',
    'drill_modal.llm_aug.agreement':          'LLM の同意度',
    'drill_modal.llm_aug.suggested_alt':      'LLM 提案の代替モード',
    'drill_modal.llm_aug.conf_adj':           'confidence 調整量',

    // Sensor Watchpane (Layer 3)
    'watchpane.title':                'センサー監視盤',
    'hud.coord.toggle.label':         'Coord 線',
    'hud.coord.toggle.tip':           '地図上の Coordination 線の表示。IDF 重み付き overlap (calculate_overlap_idf) を使用：Cloudflare/AWS など世界共通の ASN は抑制され、希少な ASN 共起のみがスコアされるため、平常時はほぼ 0、上昇時は実質的なインフラ共有を示す。\\nOFF: 全非表示（現状の既定 — 地図が最も静粛）。\\nSTRONG: coordIdx ≥ 1.5（≈P95）のみ — analyst が動くべき上位 5%。\\nALL: noise floor (≥ 0.5) 超の全ペア — 全体像。',
    'hud.coord.mode.all':             'ALL',
    'hud.coord.mode.strong':          'STRONG',
    'hud.coord.mode.off':             'OFF',
    'watchpane.btn.add':              '+ センサー追加',
    'watchpane.empty':                'センサー未選択。+ センサー追加 で開始。',
    'watchpane.tag.history_shallow':  '履歴限定',
    'watchpane.tip.history_shallow':  'pin 中のセンサーのうち少なくとも 1 件で蓄積観測点が 2 点未満のため、sparkline は現サイクルのみ表示。1h 履歴は次の数スコアリングサイクルで埋まります。',
    'watchpane.col.sensor':           'センサー',
    'watchpane.col.scope':            'スコープ',
    'watchpane.col.value':            '値',
    'watchpane.col.delta':            '1h 差分',
    'watchpane.scope.focused':        'focused',
    'watchpane.scope.global':         'global',
    'watchpane.row.remove':           '削除',
    'watchpane.row.no_data':          '今サイクルでは観測なし',
    'watchpane.row.suppressed':       'suppressed',
    'watchpane.row.fired':            'FIRED',
    'watchpane.row.normal':           'NORMAL',
    'watchpane.row.fetch_error':      '取得エラー',
    'watchpane.add.title':            'センサー追加',
    'watchpane.add.search_ph':        'センサーを絞り込み…',
    'watchpane.add.no_match':         '一致なし',
    'watchpane.add.already_added':    '追加済',
    'watchpane.alarm.title':          'アラーム条件',
    'watchpane.alarm.btn.tip_unset':       'アラーム未設定 — クリックで条件を設定',
    'watchpane.alarm.btn.tip_configured':  'アラーム設定済',
    'watchpane.alarm.label.field':    'フィールド',
    'watchpane.alarm.label.op':       '演算子',
    'watchpane.alarm.label.value':    '値',
    'watchpane.alarm.label.notify':   '遷移時に Web 通知を送信',
    'watchpane.alarm.field.score':    'スコア（最新）',
    'watchpane.alarm.field.value':    'raw 値',
    'watchpane.alarm.field.delta':    'Δ ベースライン差',
    'watchpane.alarm.field.status':   'ステータス',
    'watchpane.alarm.btn.clear':      '解除',
    'watchpane.alarm.btn.save':       '保存',
    'watchpane.alarm.error.invalid':  '不正な値 — 数値を入力（またはステータスを選択）',
    'watchpane.alarm.hint':           '最新観測値が条件に一致したら発火。通知は false→true 遷移ごとに 1 回発射（連続 active 中は抑制）。',
    'watchpane.notify.title':         'センサーアラーム',

    // ══════════════════════════════════════════════════════════════
    // HUD — top bar
    // ══════════════════════════════════════════════════════════════
    'hud.btn.sync':                   'SYNC',
    'hud.btn.chain':                  'CHAIN',
    'hud.btn.tools':                  'TOOLS ▾',
    'hud.btn.report':                 'レポート ▾',
    'hud.btn.sitrep':                 'SITREP',
    'hud.btn.evidence':               'EVIDENCE',
    'hud.btn.salute':                 'SALUTE',
    'hud.btn.export_md':              'MD 出力',
    'hud.btn.intel_guide':            'インテルガイド',
    'hud.btn.config':                 '設定',
    'hud.diag.label':                 '診断',
    'hud.tooltip.settings_menu':      '設定 — インテルガイド / Config',
    'hud.discrepancy_alert':          '! 矛盾検知: マスキロフカ (欺瞞工作) の可能性',

    // ── scenario chip (Row 1 SITUATION) ───────────────────────────
    'hud.scenario.label':             'シナリオ',
    'hud.scenario.none':              '—',
    'hud.tooltip.scenario':           'フォーカス中のシナリオ — クリックでシナリオバーへ移動して切替',

    // ── convergence label (JS-generated) ──────────────────────────
    'hud.convergence.full':           '⚡ 完全収斂',
    'hud.convergence.dual':           '⚠ 2ドメイン収斂',
    'hud.convergence.single':         '◉ 単一ドメイン',
    'hud.convergence.none':           '収斂: —',
    'hud.label.threat_24h':           '脅威 24h:',
    'hud.tooltip.threat_24h':         '脅威レベル履歴（直近24時間 / 288サイクル）',
    'hud.label.convergence_short':    '収斂:',

    // ── vector buttons ────────────────────────────────────────────
    'hud.vec.all':                    '全ベクター',
    'hud.vec.l3':                     'L3 大容量型',
    'hud.vec.l7':                     'L7 アプリ層型',

    // ── bottom row labels ─────────────────────────────────────────
    'hud.label.overlap':              '協調:',
    'hud.label.l7_shift':             'L7変移:',
    'hud.label.strikes':              '攻撃:',
    'hud.label.bgp':                  'BGP:',
    'hud.label.multi_front':          '多正面:',
    'hud.label.velocity':             '速度:',
    'hud.tooltip.velocity':           'エスカレーション速度（脅威スコアの1階微分）。変化の方向を示すことで正常性バイアスを排除。',
    'hud.ambush.text':                '⚡ 待伏警告',
    'hud.tooltip.ambush':             '待伏パターン：2階微分Zスコア急上昇 — 指数的エスカレーションを示す。',
    'hud.label.blockade':             '封鎖:',
    'hud.tooltip.blockade':           '封鎖指数 = DDoS強度 / ネットワーク疎通性。政治的ノイズと実インフラ無力化を区別。',
    'hud.label.survival':             '生存確認:',
    'hud.tooltip.survival':           '生存確認: Check-Host.net による重要インフラの疎通確認。OK=全ノード到達可 / PARTIAL=部分障害 / BLACKOUT=全ノード不達',
    'hud.label.c2sync':               'C2同期:',
    'hud.tooltip.c2sync':             'C2同期: 複数国の攻撃開始が60秒以内に収斂 → 国家レベルの指揮統制の証拠',
    'hud.label.chain':                'チェーン:',
    'hud.tooltip.chain_hud':          'エスカレーション順序チェーン: 24時間窓内の情報→ISR→DDoS→動態の証拠連鎖。',
    'hud.label.comms':                '通信:',
    'hud.label.triangulation':        '三角:',
    'hud.tooltip.triangulation':      '三角測量: 3ドメイン(サイバー/物理/情報)すべてが独立して異常を確認 — 最高確信度の収斂。',
    'hud.label.silent_div':           '沈黙:',
    'hud.tooltip.silent_div':         'サイレント乖離: サイバー+物理ドメインが活性化、情報ドメインが沈黙 — 紛争前の偵察/準備段階の可能性。',
    'hud.label.baseline':             '基準Z:',
    'hud.tooltip.baseline':           '基準値: 国別のZスコア。現在スコアがその国の30日間平均と比較してどの程度乖離しているかを表示。',
    'hud.label.sys':                  'SENSOR',
    'hud.tooltip.sys_chip':           'システム状態: WS接続 + センサー稼働状況（OK / STALE / ERROR / DISABLED）',
    'hud.label.climate':              'CLIMATE',
    // Phase 9 (2026-05-13) — calibration noise-floor remediation chips.
    'hud.label.global_threat':        '国横断',
    'hud.tooltip.global_threat':      '国横断: 国に紐づかない脅威指標（cf_botnet_overlap, threatfox, …）。独立したレーンとして切り出し、全シナリオを一律に押し上げないようにしている。値 = raw_score × global_signal_weight の総和。',
    'hud.label.skew':                 '偏り',
    'hud.tooltip.skew':               'TL 分布の偏り: 直近 7d における TL=5（平時の平穏）の比率。緑 ≥30%、橙 15-30%、赤 <15%。旧来の DRIFT chip が見逃す「TL≥2 が何日も続く」状態を捉える。',
    'hud.tooltip.tl_proximity':       'TL近接度: 現在スコアから次の脅威レベル境界までの距離',
    'tl_prox.near_esc':               '{pts}pt → TL{tl}',
    'tl_prox.near_deesc':             '{pts}pt → TL{tl}',
    'tl_prox.tooltip_up':             'エスカレーションまで{pts}ポイント (TL{tl})',
    'tl_prox.tooltip_down':           'デエスカレーションまで{pts}ポイント (TL{tl})',
    // ── HUD redesign additions ────────────────────────────────────
    'hud.tooltip.tl_duration':        '現在の脅威レベルでの滞在時間（高TLでの長期滞在は正常性バイアスを呼ぶため可視化）',
    'hud.tooltip.tl_divergence':      'v1 の derive_tl() と v2 の結論台帳が現在の TL で食い違っている。バッジは v2 の判定を表示する（オーバーレイ優先）。HUD のスパークラインと FOCUS カードも v2 に従う。通常は TL 遷移から 10–30s 以内に解消する。THREAT LV バッジをクリックすると v2 の監査経路を確認できる。',

    // ── TRIAGE Lane display modes (commit C, 2026-04-30) ─────────────
    // The TRIAGE Lane no longer always pushes the map down. It runs in
    // 3 modes: dormant (hidden), pin-dock (corner overlay on the map),
    // critical-banner (HUD-flow slim banner). Mode is auto-selected
    // from max attention_score + critical-event flags. Analyst can
    // pin the corner overlay expanded or force always-visible mode
    // via CONTROLS.
    'triage.tooltip.pin_dock':         'attention_score (novelty × Δconfidence × analyst_blindness) 上位 3 件。ホバーで展開、クリックで固定。dormant 閾値 (既定 0.40) を超える項目が無い場合は非表示。',
    'triage.tooltip.pin_dock_pin':     'クリックで展開表示を固定 (ホバー解除・リロード後も維持)。',
    'triage.tooltip.critical_banner':  'シナリオが critical 閾値 (既定 0.85) を超えたか、TL5 エスカレーションが発火した。項目をクリックして v2 監査経路を精査。閉じることはできない — NP1 (感度優先)。',
    'triage.tooltip.dormant_explain':  'トリアージは dormant — 注目シナリオに attention_score ≥ 0.40 の項目が無い。該当項目が出た時点でレーンは再表示される。',
    'triage.label.compact':            'トリアージ',
    'triage.label.critical':           '⚠ トリアージアラート',
    'triage.label.actions':            '操作',

    // ── TRIAGE actions popover (Phase 2 of Decision Layer, 2026-04-30) ─
    // Right-side ⋯ menu on the compact bar. Snooze / dismiss / visibility
    // all record into the unified decisions ledger. NP1 invariant:
    // critical events bypass snooze + dismiss in the client display
    // resolver, NOT in the server endpoint (the ledger records facts;
    // suppression is a UI decision).
    'triage.tooltip.menu':             'トリアージ操作: 精査 / 確認済みにする / スヌーズ / 表示設定。critical 事象はスヌーズを迂回する (NP1)。',
    'triage.snooze.chip':              '⏸ トリアージをミュート中 {n}m',
    'triage.snooze.chip.tooltip':      'トリアージレーンをミュート中 (NP1: critical 事象は引き続き表示)。クリックで解除。',

    // ── Decision History modal (Phase 4 of Decision Layer / AP4) ──────
    'tools.decision_history':          '判断履歴',
    'controls.tool.decision_history.desc': 'トリアージ・Calibration ガバナンス・閾値操作にまたがるアナリスト判断の時系列台帳。AP4 のフォレンジックタイムライン。',
    'decision_history.title':          '判断履歴 (AP4)',
    'decision_history.close':          '[ X ] 閉じる',
    'decision_history.loading':        '読み込み中…',
    'decision_history.disclaimer':     'AP4 判断履歴 — アナリストの全操作を実行者・理由・パラメータ付きで記録する。完全なフォレンジック時系列は LLM Features の監査ログと scenario_change_log を併せて参照。',

    // ── Pending Decisions governance_state (F3 of fix series, 2026-04-30) ─
    // Labels for the inline badge that appears next to a settled card's
    // heading. Open cards have no badge. After Re-evaluate the card
    // returns to open state and these labels disappear.

    // ── Scenario admin-override warning (Phase 3.3, problem 49, 2026-04-30 PM) ─
    // Surfaces when an admin has overridden the preset's enabled flag.
    // Tooltip carries the disabled_reason from geo_data.json so the
    // analyst sees the policy rationale without leaving the card.
    'scenario.warning.admin_override_enabled.label':   '⚠ 管理者オーバーライド',
    'scenario.warning.admin_override_enabled.tooltip': 'プリセット (geo_data.json) では無効だが、Layer-2 の管理者オーバーライドによりこのシナリオは有効化されている。理由: {reason}',
    'hud.label.eta':                  'ETA',
    'hud.tooltip.eta':                'ETA: 現在の速度から次のTL境界までの推定到達時間。速度が小さい場合は非表示。',
    'hud.eta.tooltip_up':             '{pts}pt → TL{tl}、現在の速度で推定 約{eta}',
    'hud.eta.tooltip_down':           '{pts}pt → TL{tl}（沈静化）、現在の速度で推定 約{eta}',
    'hud.label.hod_z':                'Z-HOD',
    'hud.tooltip.hod_z':              '時間帯Zスコア: 過去7日以上の同時間帯と比較した偏差（時間帯バイアスを補正する BASE-Z の補完指標）',
    'hud.hod_z.detail':               'z = {z} σ ・ 同時間帯サンプル数 n={n}',
    'hud.label.intel':                'INTEL',
    'hud.tooltip.intel_corrob':       'インテル裏付け: フォーカス中シナリオで24時間以内に確定したLLMインテル数。クリックでインテルパネルを開く。',
    'hud.intel.detail':               'アクティブ {active}件 (24h)  ・  直近1時間で +{fresh}件',
    'hud.label.bg_alert':             'BG',
    'hud.tooltip.bg_alert':           '背景シナリオが急上昇中 — クリックで詳細パネルを開く。',
    'hud.bg_alert.detail':            '{name} 直近1時間で +{delta} pt（背景）',
    'hud.tooltip.split_tag':          '攻撃側寄与 / 標的側寄与。偏りは攻勢的か防勢的かの構図を示唆する。',
    // ── Hamburger control panel ──────────────────────────────────
    'hud.tooltip.hamburger':          '操作メニューを開く（ベクトル/同期/ツール/レポート/設定/ユーザー）',
    'hud.hh.title':                   '操作',
    'hud.hh.section.vector':          '表示ベクトル',
    'hud.hh.section.data':            'データ',
    'hud.hh.section.reports':         'レポート',
    'hud.hh.section.settings':        '設定',
    'hud.hh.section.language':        '言語',
    'hud.hh.section.tools':           'ツール & パネル',
    'hud.tooltip.comms':              '通信: 緑=全センサー稼働中 / 橙=異常な沈黙を検出 — センサー妨害または作戦前通信封止の可能性',
    'hud.domain.cyber':               'サイバー',
    'hud.tooltip.domain_cyber':       'サイバードメインスコア',
    'hud.domain.physical':            '物理',
    'hud.tooltip.domain_physical':    '物理ドメインスコア',
    'hud.domain.info':                '情報',
    'hud.tooltip.domain_info':        '情報ドメインスコア',
    'hud.tooltip.domain_expand':      'クリックでセンサー別スコア内訳を展開',
    'dd.hint':                        'センサー行クリック → 地図フォーカス  ·  ⊙ = センサー位置にズーム',
    'dd.btn.focus_map':               '地図上のセンサーにズーム',

    // ── C2 sync (JS-generated) ────────────────────────────────────
    'hud.c2sync.detected':            '検知 (+{n}pt)',
    'hud.c2sync.partial':             '部分同期 ({pct}%)',
    'hud.c2sync.no_sync':             '未同期',

    // ── chain badge (JS-generated) ────────────────────────────────
    'hud.chain.full':                 '✔ 完全',
    'hud.chain.partial':              '≈ 部分',

    // ── velocity (JS-generated) ───────────────────────────────────
    'hud.velocity.stable':            '安定',
    'hud.velocity.unit':              '/サイクル',

    // ══════════════════════════════════════════════════════════════
    // TOOLS dropdown
    // ══════════════════════════════════════════════════════════════
    'tools.target_visibility':        'ターゲット可視性',
    'tools.live_threat_telemetry':    '攻撃送信元フィード',
    'tools.evidence_chain':           '証拠チェーン',
    'tools.telegram_sigint':          'Telegram SIGINT',
    'tools.weather_brief':            '気象ブリーフィング',
    'tools.salute_export':            'SALUTEエクスポート',
    'tools.greynoise':                'GreyNoise',

    // ══════════════════════════════════════════════════════════════
    // Panel — common
    // ══════════════════════════════════════════════════════════════
    'panel.common.dock':              'ドック',
    'panel.common.dock_tooltip':      'サイドバーに戻す',
    'panel.common.minimize_tooltip':  '最小化',
    'panel.common.close_tooltip':     '閉じる',

    // ══════════════════════════════════════════════════════════════
    // Panel — Target Visibility
    // ══════════════════════════════════════════════════════════════
    'panel.target.title':             'ターゲット可視性',
    'panel.target.hint':              '焦点シナリオの参加国。編集は管理画面 → Scenarios から。',

    // ══════════════════════════════════════════════════════════════
    // Panel — Attack Origin Feed
    // ══════════════════════════════════════════════════════════════
    'panel.dashboard.title':          '攻撃送信元フィード',
    'panel.dashboard.waiting':        'APIテレメトリ待機中...',

    // ══════════════════════════════════════════════════════════════
    // Footer / status bar
    // ══════════════════════════════════════════════════════════════
    'footer.system_init':             'システム初期化中...',
    'status.sync':                    '同期',
    'status.syncing':                 '同期中...',
    'status.sync_done':               '同期完了: {time}（次回15分後）',
    'status.pending':                 '変更あり。SYNCを実行してください。',
    'status.init_complete':           '> 初期化完了。ダッシュボードを描画中。',

    // ══════════════════════════════════════════════════════════════
    // Settings modal
    // ══════════════════════════════════════════════════════════════
    'modal.settings.title':           'マスター設定',
    'modal.settings.close':           '[ X ] 閉じる',
    'modal.settings.tab.sensors':     'センサー',
    'modal.settings.tab.fetchlog':    'フェッチログ',
    'modal.settings.tab.upstreams':   '上流ソース',
    'modal.settings.tab.fleet':       'フリート稼働',
    'modal.settings.tab.sysconfig':   'システム',
    'modal.settings.tab.users':       'ユーザー管理',

    // ── Fleet Health tab ───────────────────────────────────────────
    'modal.fleet.help':               'センサー単位のフリート稼働状況: サーキットブレーカー状態、キャッシュ鮮度、直近の信頼性、最終エラー。HUD のセンサードットが要約しているのと同じ /api/admin/sensor_health を、センサー毎の詳細＋クォータ／レート制限の可視化付きで表示します。',
    'modal.fleet.refresh_btn':        '\\u21bb 更新',
    'modal.fleet.loading':            '読み込み中...',
    'modal.fleet.window_label':       '集計窓:',
    'modal.fleet.filter_label':       'ドメイン:',
    'modal.fleet.filter.all':         '全て',
    'fleet.summary':                  '合計 {total} · OK {ok} · 劣化 {degraded} · 古い {stale} · エラー {err} · CB開 {cb} · 無効 {off}',
    'fleet.col.health':               '稼働',
    'fleet.col.cb':                   'CB',
    'fleet.col.cache_age':            'キャッシュ齢',
    'fleet.col.reliability':          '信頼性',
    'fleet.col.last_error':           '最終エラー',
    'fleet.col.poll':                 'ポーリング',
    'fleet.no_error':                 '—',
    'fleet.never_fetched':            '未実行',
    'fleet.cb.open':                  '開放',
    'fleet.cb.half_open':             '半開',
    'fleet.cb.closed':                '閉鎖',
    'fleet.empty_filter':             '選択ドメインに一致するセンサーがありません。',
    'fleet.load_error':               'フリート稼働の取得に失敗: {msg}',
    'fleet.last_refreshed':           '最終更新: {time}',

    // ── Upstreams tab ──────────────────────────────────────────────
    'modal.upstreams.help':           '複数のフィードを集約するセンサー(現在は CT Log: certstream push + certspotter pull + crt.sh フォールバック)について、上流ソース単位の稼働状況を表示します。センサー全体のフェッチログから推測することなく「実際のデータフィードが生きているか」を確認できます。',
    'modal.upstreams.refresh_btn':    '\\u21bb 更新',
    'modal.upstreams.loading':        '読み込み中...',
    'upstreams.empty':                '上流ソースの稼働状況を報告しているマルチソースセンサーはありません。',
    'upstreams.no_failures':          '失敗なし',
    'upstreams.last_msg':             '最終メッセージ',
    'upstreams.mode_counters':        'モード別カウンタ',
    'upstreams.never':                '未取得',
    'upstreams.last_refreshed':       '最終更新: {time}',
    'upstreams.load_error':           '上流ソース状態の取得に失敗: {msg}',
    'upstreams.poll':                 'ポーリング',
    'upstreams.buffer':               'バッファ',
    'upstreams.field.running':                '稼働中',
    'upstreams.field.messages_total':         '受信メッセージ総数',
    'upstreams.field.matches_total':          'マッチ総数',
    'upstreams.field.connect_count':          '接続回数',
    'upstreams.field.watched_domains':        '監視対象ドメイン数',
    'upstreams.field.heartbeat_budget_sec':   'ハートビート許容(秒)',
    'upstreams.field.liveness_budget_sec':    '生存確認許容(秒)',
    'upstreams.field.observation_count_24h':  '観測数(24h)',
    'upstreams.field.queries_made':           '実行クエリ数',
    'upstreams.field.rate_limit_remaining':   'レート制限残数',
    'upstreams.coverage.title':       '監視 apex カバレッジ',
    'upstreams.coverage.stalest':     '最も古い監視 apex',
    'upstreams.coverage.no_data':     'カバレッジデータなし',

    // ── System Config tab ──────────────────────────────────────────────
    'sysconfig.help':                 '<span class="code-block">config.env</span> の設定を編集します。変更は即座にディスクに書き込まれます。<span class="cfg-live-badge">ライブ</span> の設定は即時反映、<span class="cfg-restart-badge">再起動</span> の設定は <code>docker compose restart</code> が必要です。',
    'sysconfig.section.api_keys':     'API キー',
    'sysconfig.section.scope':        'デフォルトスコープ',
    'sysconfig.scope.desc':           '起動時のフォーカスシナリオのデフォルト。参加国や敵対国はシナリオタブで管理します。',
    'sysconfig.field.default_focused_scenario': 'デフォルトフォーカスシナリオ',
    'sysconfig.adv_toggle':           '\\u25b6 詳細設定',
    'sysconfig.adv_toggle_open':      '\\u25bc 詳細設定',
    'sysconfig.adv_warning':          '\\u26a0 不適切な値を設定するとシステムが正常に動作しなくなる可能性があります。影響を理解した上で変更してください。',
    'sysconfig.section.network':      'ネットワーク / SSL',
    'sysconfig.field.ssl_enabled':    '有効',
    'sysconfig.field.ssl_disabled':   '無効',
    'sysconfig.section.cache':        'キャッシュ &amp; ポーリング',
    'sysconfig.field.cache_expiry':   'キャッシュ有効期限（秒）',
    'sysconfig.field.opensky_int':    'OpenSky 最小間隔（秒）',
    'sysconfig.field.narrative_int':  'ナラティブ ポーリング間隔（秒）',
    'sysconfig.field.telegram_int':         'Telegram ポーリング間隔（秒）',
    'sysconfig.field.telegram_kw':          'Telegram 攻撃キーワード',
    'sysconfig.field.telegram_conf_thresh': 'Telegram 主張確信度しきい値',
    'sysconfig.field.checkhost_int':        'Check-Host ポーリング間隔（秒）',
    'sysconfig.field.checkhost_to':   'Check-Host タイムアウト（ms）',
    'sysconfig.field.checkhost_nodes':'Check-Host ノード',
    'sysconfig.section.threat':       '脅威スコアリング',
    'sysconfig.field.air_anomaly':    '空域異常閾値（比率）',
    'sysconfig.field.air_closure':    '空域閉鎖閾値（比率）',
    'sysconfig.field.air_window':     '空域ベースライン ウィンドウ（サイクル）',
    'sysconfig.field.gdelt_tone':     'GDELT トーン警告閾値',
    'sysconfig.field.gdelt_history':  'GDELT 履歴ウィンドウ（日）',
    'sysconfig.field.conv_dual':      '二重収斂ボーナス',
    'sysconfig.field.conv_full':      '完全収斂ボーナス',
    'sysconfig.field.hysteresis':     '脅威レベル ヒステリシスサイクル',
    'sysconfig.section.ddos':         'DDoS 加速エンジン',
    'sysconfig.field.ambush_z':       '伏撃 Z スコア閾値',
    'sysconfig.field.deriv_window':   '速度微分 ウィンドウ（サイクル）',
    'sysconfig.field.sync_delta':     'C2 同期デルタ（ms）',
    'sysconfig.field.sync_threshold': 'C2 同期スコア閾値（0〜1）',
    'sysconfig.section.narrative':    'ナラティブ バースト検出',
    'sysconfig.field.narr_alert_z':   'ナラティブ 警告 Z スコア',
    'sysconfig.field.narr_crit_z':    'ナラティブ 重大 Z スコア',
    'sysconfig.field.narr_baseline':  'ナラティブ ベースライン日数',
    'sysconfig.section.chain':        'シーケンスチェーン',
    'sysconfig.field.chain_window':   'チェーン ウィンドウ（秒）',
    'sysconfig.field.chain_full':     'フルチェーン ボーナスポイント',
    'sysconfig.field.chain_partial':  'パーシャルチェーン ボーナスポイント',
    'sysconfig.section.maritime':     '海上 / ISR センサー',
    'sysconfig.field.ais_dark_gap':   'AIS ダークギャップ閾値（秒）',
    'sysconfig.field.ais_anchor':     'AIS 投錨検出半径（km）',
    'sysconfig.field.isr_surge':      'ISR サージ閾値（機）',
    'sysconfig.field.isr_icao':       'ISR ICAO 機種コード',
    'sysconfig.field.gps_jam':        'GPS ジャミング閾値',
    'sysconfig.field.gps_jam_crit':   'GPS ジャミング クリティカル閾値',
    'sysconfig.field.ct_log_surge':   'CT ログサージ閾値',
    'sysconfig.field.usgs_mag':       'USGS 最小マグニチュード',
    'sysconfig.field.dw_cyber':       'ドメイン重み — サイバー（0–1）',
    'sysconfig.field.dw_physical':    'ドメイン重み — フィジカル（0–1）',
    'sysconfig.field.dw_info':        'ドメイン重み — 情報（0–1）',
    'sysconfig.help.domain_weights':  '3つの重みの合計は 1.0',
    'sysconfig.save_btn':             'config.env に保存',
    'sysconfig.restart_note':         '\\u26a0 一部の設定は再起動が必要です（docker compose restart）',
    'sysconfig.section.llm':          'LLMインテリジェンス',
    'sysconfig.help.llm_desc':        'Ollama のローカル起動が必要。Docker内（Mac/Windows）では hostname に host.docker.internal を使用。',
    'sysconfig.field.llm_enabled':    'LLM 有効',
    'sysconfig.field.llm_host':       'Ollama ホスト',
    'sysconfig.field.llm_model':      'モデル',
    'sysconfig.field.llm_timeout':    'リクエストタイムアウト（秒）',
    'sysconfig.section.llm_thresholds': 'インテルキュー閾値',
    'sysconfig.field.llm_auto_threshold': '自動承認閾値',
    'sysconfig.help.llm_auto_threshold':  'この確信度以上 \\u2192 AUTO-CONFIRMED（アナリスト審査不要）',
    'sysconfig.field.llm_min_confidence': '最低確信度',
    'sysconfig.help.llm_min_confidence':  'これ未満のアイテムは破棄',
    'sysconfig.field.llm_override_window': '取消可能時間（秒）',
    'sysconfig.help.llm_override_window':  'AUTO-CONFIRMEDアイテムの取消可能な時間',
    'sysconfig.field.llm_pending_auto_reject': '保留自動拒否（時間）',
    'sysconfig.help.llm_pending_auto_reject':  '未確認のPENDINGアイテムを自動拒否するまでの時間（0＝無効）',
    'sysconfig.field.intel_retention': 'インテル保持期間（日）',
    'sysconfig.field.intel_age_decay_enabled': '経時減衰 (ADR-023)',
    'sysconfig.help.intel_age_decay_enabled':  'confirm 後の寄与を経過時間で指数関数的に減衰（confirm/TTL の段差を平滑化）',
    'sysconfig.field.intel_age_decay_tau':     '減衰時定数 \\u03c4（時間）',
    'sysconfig.help.intel_age_decay_tau':      '重み=1/e @age=\\u03c4、\\u22480.14 @2\\u00b7\\u03c4、\\u22480.05 @3\\u00b7\\u03c4。既定 12h \\u2248 1勤務シフト',
    'sysconfig.llm.fetch_models':     'モデル取得 \\u21ba',
    'sysconfig.llm.fetching':         '取得中...',
    'sysconfig.llm.no_models':        'モデルが見つかりません — Ollama は起動していますか？',
    'sysconfig.llm.models_loaded':    '\\u2713 {n} 件のモデルを読み込みました',
    'sysconfig.llm.fetch_error':      '\\u2717 {msg}',
    'sysconfig.llm.model_hint':       '「モデル取得」でOllamaから読み込み、または手動入力。',




    'modal.sensors.help':             '個別センサーモジュールの有効/無効を切り替え。<b>サイバー</b>=ネットワーク脅威、<b>物理</b>=インフラ・空域、<b>情報</b>=情報・影響工作。',
    'modal.sensors.help_graceful':    '無効化されたセンサーはドメインスコアへの寄与がゼロになります（グレースフルデグラデーション）。',
    'modal.sensors.loading':          'センサー状態を読み込み中...',

    'modal.fetchlog.help':            '各センサーが外部APIから最後に取得した結果を表示。',
    'modal.fetchlog.stale_note':      'キャッシュ経過時間がポーリング間隔の3倍を超えると <b>STALE（古い）</b> とフラグされます。',
    'modal.fetchlog.refresh_btn':     '↻ 更新',
    'modal.fetchlog.loading':         '読み込み中...',

    'modal.minimap.region_preview':   '地域プレビュー',
    'modal.minimap.legend.core':      '◆ コア',
    'modal.minimap.legend.link':      '◆ 参加国',
    'modal.minimap.legend.adversary': '◆ 敵対国',

    // ══════════════════════════════════════════════════════════════
    // Country Intel modal
    // ══════════════════════════════════════════════════════════════
    'modal.country.title_prefix':     '国家インテル',

    // ══════════════════════════════════════════════════════════════
    // SITREP modal
    // ══════════════════════════════════════════════════════════════
    'modal.sitrep.title':             '状況報告（SITREP）— 脅威レベル評価',
    'modal.sitrep.timeline_label':    '脅威レベルタイムライン（直近288サイクル）',
    'modal.sitrep.report_label':      '自動生成レポート',

    // ══════════════════════════════════════════════════════════════
    // Evidence modal
    // ══════════════════════════════════════════════════════════════
    'modal.evidence.title':           '分析根拠 — 証拠パネル',
    'modal.evidence.section_convergence': '収斂スコア内訳',
    'modal.evidence.section_assessment':  'システム評価',
    'modal.evidence.section_rationale':   'センサー根拠マトリクス',
    'modal.evidence.th_sensor':       'センサー',
    'modal.evidence.th_domain':       'ドメイン',
    'modal.evidence.th_status':       '状態',
    'modal.evidence.th_observed':     '観測値',
    'modal.evidence.th_score':        'スコア',
    'modal.evidence.th_confidence':   '確信度',
    'modal.evidence.th_reason':       '発火理由 / 備考',
    'modal.evidence.noise_filters':   '適用ノイズフィルター:',
    'modal.evidence.btn_salute':      'SALUTEレポート出力',
    'modal.evidence.btn_sitrep':      'SITREPを表示',
    'modal.evidence.no_filters':      'なし',
    'modal.evidence.system_note_label': 'システムノート',
    'modal.evidence.convergence_score': '収斂スコア:',

    // ══════════════════════════════════════════════════════════════
    // Intel Guide modal
    // ══════════════════════════════════════════════════════════════
    'modal.help.title':               'インテリジェンス運用ガイド — MDO C4ISR 戦略レーダー',
    'modal.help.ch1':                 '1. 適用限界',
    'modal.help.ch2':                 '2. 結論',
    'modal.help.ch3':                 '3. マップ',
    'modal.help.ch4':                 '4. HUD とパネル',
    'modal.help.ch5':                 '5. ワークフロー',
    'modal.help.ch6':                 '6. センサー',
    'modal.help.ch7':                 '7. スコアリング',
    'modal.help.ch8':                 '8. Calibration',
    'modal.help.ch9':                 '9. トレードクラフト',
    'modal.help.ch10':                '10. recall 計測',
    'modal.help.ch11':                '11. シナリオ',
    'modal.help.ch12':                '12. API',
    'modal.help.ch13':                '13. 管理',
    'modal.help.ch14':                '14. 運用基盤',
    // Map dim overlay (focus-change loading state)
    'map.dim.switching':              '{name} に切替中…',
    'map.dim.timeout':                '同期未完了 — 最後に取得した状態を表示中。',
    'map.dim.retry':                  '再試行',
    'map.dim.aria_busy':              'マップを新しいシナリオに更新中',
    'map.refresh.label':              'テレメトリを更新中…',
    'map.refresh.label_named':        'テレメトリを更新中 — {name}',

    // ══════════════════════════════════════════════════════════════
    // Panel — Weather Brief
    // ══════════════════════════════════════════════════════════════
    'panel.weather.title':            '作戦気象ブリーフ',

    // ══════════════════════════════════════════════════════════════
    // Panel — SALUTE Report
    // ══════════════════════════════════════════════════════════════
    'panel.salute.title':             'SALUTE 報告書',
    'panel.salute.btn_copy':          'コピー',
    'panel.salute.btn_download':      'ダウンロード',
    'panel.salute.cross_ref':         '相互参照',

    // ══════════════════════════════════════════════════════════════
    // Panel — Evidence Chain
    // ══════════════════════════════════════════════════════════════
    'panel.chain.title':              '証拠チェーン',
    'panel.chain.no_events':          'イベントなし',
    'panel.chain.24h_window':         '24時間ウィンドウ — 時系列順',
    'panel.chain.narrative_z':        'ナラティブZ',
    'panel.chain.isr_aircraft':       'ISR機数',
    'panel.chain.ais_dark_gaps':      'AIS不通区間',
    'panel.chain.v9_intel':           '── v9 インテリジェンス ──',
    'panel.chain.telegram_mirror':    'テレグラムミラー',
    'panel.chain.sigint_open':        'SIGINT↗',
    'panel.chain.sigint_tooltip':     'SIGINTパネルを開く',
    'panel.chain.infra_survival':     'インフラ生存',
    'panel.chain.c2_sync':            'C2同期',
    'panel.chain.llm_intel':          'LLM インテル',
    'panel.chain.toggle_group':       'グループの折りたたみ／展開',
    'chain.llm_intel.active':         '件確認済',
    'chain.llm_intel.review':         '件要確認',
    'chain.llm_intel.none':           '—',

    // ── chain sequence badge ──────────────────────────────────────
    'chain.seq.full_chain':           '✔ チェーン完全確認',
    'chain.seq.partial':              '≈ チェーン部分確認',
    'chain.seq.none':                 '活動中のシーケンスチェーンなし',

    // ── chain event type labels ───────────────────────────────────
    'chain.event.narrative_burst':    'ナラティブバースト',
    'chain.event.isr_surge':          'ISRサージ',
    'chain.event.sync_ddos':          '同期DDoS',
    'chain.event.firms_anomaly':      '動態異常',
    'chain.event.ais_dark_gap':       'AIS消灯区間',
    'chain.event.telegram_intent':    'Telegram: 攻撃意図',
    'chain.event.maskirovka':         'マスキロフカ（欺瞞）',
    'chain.event.c2_sync':            'C2時間的同期',
    'chain.event.infra_blackout':     'インフラ停電',
    'chain.no_events_24h':            '24時間ウィンドウにイベントなし',

    // ── chain: infra / telegram detail ───────────────────────────
    'chain.maskirovka.title':         '⚠ 欺瞞工作 (MASKIROVKA) 検知',
    'chain.infra_check.label':        'インフラ確認 — ノード: {n}',
    'chain.telegram_monitor.label':   'Telegram監視 — {n}チャンネル',
    'chain.telegram_monitor.targets': '標的URL:',

    // ── chain: C2 sync detail ─────────────────────────────────────
    'chain.c2sync.detected':          '同期 +{n}pt',
    'chain.c2sync.partial':           '部分同期',
    'chain.c2sync.no_sync':           '未同期',

    // ══════════════════════════════════════════════════════════════
    // Telegram SIGINT panel
    // ══════════════════════════════════════════════════════════════
    'tg.status.intent_detected':      '██ 意図検知',
    'tg.status.targets_found':        '◆ 標的確認',
    'tg.status.all_clear':            '── 異常なし',
    'tg.poll.active':                 '{active}/{monitored} 活動中',
    'tg.grid.not_polled':             'センサー未ポーリング',
    'tg.grid.no_active':              '今サイクルは活動なし — 下のログを参照',
    'tg.grid.no_activity':            'チャンネル活動を検出せず',
    'tg.roster.no_channels':          'THREAT_ACTOR_MAPPINGにチャンネルがありません',
    'tg.log.no_intercepts':           '傍受記録なし',
    'tg.entry.intent':                '意図検知',
    'tg.entry.target':                '標的',
    'tg.confirm.clear_log':           'サーバー上の傍受ログを消去しますか？',
    'tg.monitor.label':               'Telegram監視 — {n}チャンネル',
    'tg.monitor.targets':             '標的URL:',

    // ══════════════════════════════════════════════════════════════
    // GreyNoise panel
    // ══════════════════════════════════════════════════════════════
    'gn.tier.enterprise':             'ENTERPRISE',
    'gn.tier.community':              'COMMUNITY',
    'gn.tier.no_key':                 'NO KEY',
    'gn.suppress.active':             '⚡ サイバースコア抑制中',
    'gn.querying':                    'GreyNoise に照会中...',
    'gn.remaining':                   '本日残り: {n}/50',
    'gn.result.noise':                '■ NOISE',
    'gn.result.targeted':             '■ TARGETED',
    'gn.result.riot':                 '■ RIOT (benign infra)',
    'gn.result.cached':               '[キャッシュ]',
    'gn.log.no_lookups':              'ルックアップ履歴なし。',
    'gn.log.noise':                   'ノイズ',
    'gn.log.targeted':                '標的',
    'gn.no_theater_data':             '国別データなし',

    // ══════════════════════════════════════════════════════════════
    // Sensor config / mute
    // ══════════════════════════════════════════════════════════════
    'sensor.mute.prompt':             'センサーをミュート: {name}\\n理由（任意）:',
    'sensor.toggle.enabled':          '有効',
    'sensor.toggle.disabled':         '無効',
    'sensor.no_sensors':              '登録済みセンサーなし。',
    'sensor.load_error':              'センサー設定の読み込みに失敗: {msg}',

    // ══════════════════════════════════════════════════════════════
    // Evidence panel: mute button / suppressed label
    // ══════════════════════════════════════════════════════════════
    'evidence.btn.mute':              'ミュート',
    'evidence.btn.unmute':            'ミュート解除',
    'evidence.suppressed':            '抑制中: {reason}',
    'evidence.no_data':               '根拠データなし。',
    'evidence.no_system_note':        'システムノートなし。',

    // ══════════════════════════════════════════════════════════════
    // SITREP cards (JS-generated)
    // ══════════════════════════════════════════════════════════════
    'sitrep.card.threat_now':         '現在の脅威',
    'sitrep.card.threat_1h':          '直近1時間の脅威範囲',
    'sitrep.card.convergence':        '収斂状態',
    'sitrep.card.history':            '履歴',
    'sitrep.card.trend':              '推移: {icon} {text}',
    'sitrep.card.avg':                '平均: {n}',
    'sitrep.card.domains':            'ドメイン: {list}',
    'sitrep.card.none':               'なし',
    'sitrep.card.cycles':             '{n} サイクル',
    'sitrep.card.window':             '{h}時間ウィンドウ',
    'sitrep.loading':                 '読み込み中…',
    'sitrep.no_data':                 'データなし。',
    'sitrep.error':                   'エラー: {msg}',

    // ══════════════════════════════════════════════════════════════
    // Country Intel Panel (JS-generated)
    // ══════════════════════════════════════════════════════════════
    'cip.modal_title':                '国家インテル — {name} ({code})',
    'cip.role.core':                  '★ 中核',
    'cip.role.link':                  '◎ 連携',
    'cip.global_share':               'グローバルシェア L3: {l3} / L7: {l7}',
    'cip.section.cyber':              '🔵 サイバードメイン — DDoSテレメトリ',
    'cip.label.avg_spike':            '平均スパイク',
    'cip.label.l7_shift':             'L7ベクターシフト',
    'cip.label.ioda':                 'インフラ障害 (IODA)',
    'cip.label.bgp_routing':          'BGPルーティング (RIPE)',
    'cip.label.top_sources':          '主要攻撃元（スパイク順）',
    'cip.no_sources':                 '主要攻撃元なし',
    'cip.state_asn_badge':            '国家系ASN',
    'cip.spike_label':                'スパイク {n}x',
    'cip.ioda.normal':                '🟢 正常',
    'cip.ioda.outage':                '🔴 障害',
    'cip.ioda.outage_wx':             '🟠 障害（気象ノイズ除外）',
    'cip.l7shift.active':             'L7 シフト',
    'cip.l7shift.none':               'なし',
    'cip.section.physical':           '🟠 物理ドメイン — インフラ',
    'cip.label.weather':              '気象',
    'cip.label.airspace':             '空域 ({airport})',
    'cip.label.ixp_nodes':            'IXPノード',
    'cip.weather.wind':               '風速 {n}m/s',
    'cip.airspace.drop':              '— 減少率 {pct}%',
    'cip.section.info':               '🟣 情報ドメイン — メディアトーン (GDELT)',
    'cip.label.current_tone':         '現在のトーン',
    'cip.label.alert_status':         'アラート状態',
    'cip.baseline_label':             'ベースライン (28日): {base}   Δ {delta}',
    'cip.threshold_label':            'しきい値: {n}',
    'cip.section.predictive':         '⚡ 予測インジケータ',
    'cip.theater_label':              '(国: {name})',
    'cip.label.esc_velocity':         'エスカレーション速度',
    'cip.sub.1st_deriv':              '1次微分 / サイクル',
    'cip.label.blockade_index':       '封鎖指数',
    'cip.sub.blockade':               'DDoS / ネット到達性',
    'cip.label.narrative_z':          'ナラティブ Zスコア',
    'cip.sub.30d_baseline':           '30日ベースライン',
    'cip.label.isr_aircraft':         'ISR 航空機',
    'cip.sub.high_alt_recon':         '高高度偵察',
    'cip.label.ais_dark_gaps':        'AIS 消灯区間',
    'cip.sub.transponder':            'トランスポンダ途絶',
    'cip.label.seq_chain':            'シーケンスチェーン',
    'cip.sub.24h':                    '24時間ウィンドウ',
    'cip.chain.full':                 'チェーン完全',
    'cip.chain.partial':              '部分確認',
    'cip.chain.none':                 'チェーンなし',
    'cip.ambush.active':              '⚡ 待伏パターン検知',
    'cip.vessels_unit':               '{n} 隻',

    // ── Country Intel: IHR / RIPE Atlas / Tor Metrics ───────────
    'cip.label.ihr_disco':            '切断イベント (IHR)',
    'cip.label.ihr_delay':            '遅延異常 (IHR)',
    'cip.ihr.normal':                 '🟢 正常',
    'cip.ihr.disco':                  '🔴 切断検出',
    'cip.ihr.hegemony':               '🟠 ヘゲモニー警報',
    'cip.ihr.delay':                  '🟡 遅延異常',
    'cip.ihr.events':                 '{n} イベント',
    'cip.ihr.alarms':                 '{n} アラーム',
    'cip.label.ripe_atlas':           'プローブ到達性 (RIPE Atlas)',
    'cip.label.ripe_latency':         '測定RTT',
    'cip.atlas.normal':               '🟢 正常',
    'cip.atlas.probe_drop':           '🟠 プローブ減少',
    'cip.atlas.probe_blackout':       '🔴 プローブ消失',
    'cip.atlas.probes':               'アクティブ {n} プローブ',
    'cip.atlas.drop_pct':             '減少率 {pct}%',
    'cip.atlas.rtt':                  '平均 {avg}ms / p95 {p95}ms',
    'cip.label.tor_metrics':          'Torネットワーク',
    'cip.tor.normal':                 '🟢 正常',
    'cip.tor.relay_drop':             '🟠 リレー減少',
    'cip.tor.user_surge':             '🟡 ユーザー急増',
    'cip.tor.censorship':             '🔴 検閲の兆候',
    'cip.tor.relays':                 'リレー {n} / ブリッジ {b}',
    'cip.tor.users':                  'ブリッジユーザー {n}',
    'cip.tor.surge_pct':              '急増 {pct}%',
    'cip.section.network':            '🌐 ネットワーク到達性',
    'cip.section.censorship':         '🔒 検閲 / Tor',

    // ══════════════════════════════════════════════════════════════
    // Map — target list badges
    // ══════════════════════════════════════════════════════════════
    'map.net.outage':                 '障害',
    'map.net.outage_wx':              '障害(気象)',
    'map.net.normal':                 '正常',
    'map.net.tooltip_ok':             '🟢 正常',
    'map.net.tooltip_outage':         '🔴 BGP障害',
    'map.net.tooltip_wx':             '🟠 BGP障害（気象ノイズ除外）',
    'map.net.status_prefix':          'ネット: ',
    'map.net.tooltip_prefix':         'ネット状態: ',
    'map.shift_badge':                'L7シフト{actors}',
    'map.shift_tooltip':              '発信元別 L7 シフト検知:{actors}',
    'map.state_asn_badge':            '国家系ASN',
    'map.state_asn_tooltip':          '国家帰属ASN検知:\\n{asns}',
    'map.new_actor_badge':            '新規',
    'map.new_actor_tooltip':          '7日ベースラインなし: 新規インフラ',
    'map.target_tooltip':             '{info} | グローバル: {pct}% | ネット: {net}',
    'map.no_threats_vector':          'このベクターに重大な脅威なし。',
    'map.no_threats':                 '重大な脅威を検出せず。',

    // ── map: overlay popups ────────────────────────────────────────
    'map.popup.bgp_outage':           'BGP障害検知',
    'map.popup.firms_title':          '熱異常 (FIRMS)',
    'map.popup.firms_code':           'コード: {code}',
    'map.popup.firms_sub':            '運動作戦前兆',
    'map.popup.submarine_cable':      '海底ケーブルルート',
    'map.popup.connects':             '接続先:',
    'map.popup.cable_landing':        'ケーブル陸揚局',
    'map.popup.maritime_strait':      '海上チョークポイント',
    'map.popup.nato_corridor':        'NATOケーブル回廊',
    'map.popup.dark_gap_badge':       '⚠ AIS消灯区間検知',
    'map.popup.stationary_badge':     '⚓ 停留異常',
    'map.popup.normal_badge':         '● 正常',
    'map.popup.cables_label':         'ケーブル: {names}',
    'map.popup.ais_radius':           'AIS監視半径: 55 km',
    'map.popup.airspace_aircraft':    '航空機数: {count} (ベースライン: {base})',
    'map.popup.airspace_drop':        '減少率: {pct}%',
    'map.popup.weather_title':        '気象: {code}',
    'map.popup.weather_severity':     '深刻度: {sev} | 風速: {wind} m/s',
    'map.popup.weather_noise_note':   'ノイズフィルター有効: BGP/空域アラートを抑制中',
    'map.popup.gdelt_title':          '{name} — メディアトーン',
    'map.popup.gdelt_tone':           'トーン: {val}',
    'map.popup.gdelt_tone_na':        'トーン: データなし',
    'map.popup.gdelt_baseline':       'ベースライン (28日): {base} | {delta}',
    'map.popup.gdelt_status':         '状態: {status}',
    'map.popup.gdelt_noise_note':     'ノイズフィルター: 悪天候により有効',
    'map.popup.gdelt_delta_na':       'Δ データなし',
    'map.popup.ixp_more':             '…他{n}件',
    'map.popup.airspace_drop_pct':    '— 減少率 {pct}%',

    // ── map: tooltip ──────────────────────────────────────────────
    'map.tooltip.airspace':           '{airport}: {pct}%減少 ({count}/{base}機)',
    'map.tooltip.weather':            '{desc} — 風速 {wind}m/s',

    // ══════════════════════════════════════════════════════════════
    // Data fetch log panel (JS-generated)
    // ══════════════════════════════════════════════════════════════
    'fetchlog.last_refreshed':        '最終更新: {time}',
    'fetchlog.grid.last_fetch':       '最終取得',
    'fetchlog.grid.duration':         '所要時間',
    'fetchlog.grid.http_status':      'HTTPステータス',
    'fetchlog.grid.cache_age':        'キャッシュ経過',
    'fetchlog.history_label':         '履歴（新しい順→）:',
    'fetchlog.no_data':               'データなし',
    'fetchlog.load_error':            'フェッチログの読み込みに失敗: {msg}',
    'fetchlog.tooltip.ok':            '\\nステータス: OK\\n{error}',
    'fetchlog.tooltip.error':         '\\nステータス: エラー\\n{error}',

    // ══════════════════════════════════════════════════════════════
    // Radio Silence indicator
    // ══════════════════════════════════════════════════════════════
    'rs.live_text':                   'ライブ',
    'rs.quiet_text':                  '静寂',
    'rs.tooltip.live':                '通信活発: 全センサー正常報告中。異常な静寂なし。',
    'rs.tooltip.quiet':               '無線封鎖: スコア≥3だが速度=0。\\nセンサー抑制または作戦前通信封鎖の可能性あり。\\nアナリストによる確認を推奨。',

    // ══════════════════════════════════════════════════════════════
    // Dashboard empty states
    // ══════════════════════════════════════════════════════════════
    'dash.no_active_pins':            '焦点シナリオがありません。管理画面 → Scenarios で選択してください。',

    // ══════════════════════════════════════════════════════════════
    // Survival HUD (JS-generated tooltips)
    // ══════════════════════════════════════════════════════════════
    'survival.tooltip.header':        'インフラ稼働状況  [{status}  {pct}%]',
    'survival.asphyx_note':           '⚠ アスフィキシエーション検知\\n  成功率=100%だが遅延が3×ベースライン以上\\n  CDNがパケットロスを隠蔽中 — インフラ圧迫',

    // ══════════════════════════════════════════════════════════════
    // Tools menu — additional entries
    // ══════════════════════════════════════════════════════════════
    'tools.history_analysis':         '履歴分析',
    'tools.user_management':          'ユーザー管理',
    'tools.whatif_sim':               'What-Ifシミュレーション',
    'tools.spof_analysis':            'SPOF分析',

    // ══════════════════════════════════════════════════════════════
    // What-If Simulation panel
    // ══════════════════════════════════════════════════════════════
    'panel.whatif.title':             'WHAT-IFシミュレーション',
    'panel.whatif.bonus_header':      'ボーナス＆フラグ',
    'panel.whatif.tl1_hard':          'コア劣化 (TL1ハードゲート)',
    'panel.whatif.seq_bonus':         'シーケンスボーナス',
    'panel.whatif.temporal_bonus':    '時間的整合性',
    'panel.whatif.run_btn':           'シミュレーション実行',
    'panel.whatif.no_events':         'シミュレーションするセンサーイベントを1つ以上選択してください。',
    'panel.whatif.computing':         '計算中...',
    'panel.whatif.api_error':         'API接続エラー',
    'panel.whatif.total_score':       '合計スコア',
    'panel.whatif.conv_bonus':        '収斂',
    'panel.whatif.seq_bonus_label':   'シーケンス',
    'panel.whatif.temporal_bonus_label': '時間的整合',

    // ══════════════════════════════════════════════════════════════
    // SPOF Analysis panel
    // ══════════════════════════════════════════════════════════════
    'panel.spof.title':               'SPOF分析',
    'panel.spof.loading':             'センサー依存関係を分析中...',
    'panel.spof.api_error':           '脅威データがまだありません。最初のポーリングサイクルを待ってください。',
    'panel.spof.sensors_active':      'アクティブ',
    'panel.spof.redundant':           '冗長性あり',
    'panel.spof.no_redundancy':       'センサー単一',
    'panel.spof.impact_header':       'センサー障害影響分析',
    'panel.spof.score_impact':        'スコア影響',
    'panel.spof.domain_lost':         'ドメイン無効化',
    'panel.spof.no_spof':             '全センサー正常 — 重大な依存関係なし。',

    // ══════════════════════════════════════════════════════════════
    // Phase 2 badges (HUD / Deep Analytics)
    // ══════════════════════════════════════════════════════════════
    'badge.space_weather':            '宇宙天気',
    'badge.space_weather.none':       '静穏',
    'badge.space_weather.minor':      '小規模',
    'badge.space_weather.moderate':   '中規模',
    'badge.space_weather.strong':     '強い',
    'badge.space_weather.severe':     '深刻',
    'badge.space_weather.extreme':    '極端',
    'badge.space_weather.suppressing':'物理センサーを抑制中',
    'badge.feint_detected':           '陽動攻撃検出',
    'badge.feint_primary':            '主攻: {domain}',
    'badge.feint_distractors':        '陽動: {domains}',
    'badge.adaptive_zscore':          '適応型Zスコア',
    'badge.adaptive_zscore.active':   'アクティブ ({n}センサー)',
    'badge.adaptive_zscore.learning': '学習中 ({n}/{min}サンプル)',

    // ══════════════════════════════════════════════════════════════
    // Phase 3: Correlation Heatmap panel
    // ══════════════════════════════════════════════════════════════
    'tools.corr_heatmap':             '相関ヒートマップ',
    'panel.corr.title':               'センサー × 国',
    'panel.corr.loading':             'センサーデータを読み込み中...',
    'panel.corr.no_data':             'センサーデータなし',
    'panel.heatmap.toggle.all':       '全て',
    'panel.heatmap.toggle.cyber':     'サイバー',
    'panel.heatmap.toggle.physical':  '物理',
    'panel.heatmap.toggle.info':      '情報',
    'panel.heatmap.legend.quiet':     '静穏',
    'panel.heatmap.legend.warning':   '警戒',
    'panel.heatmap.legend.alert':     '警報',

    // ══════════════════════════════════════════════════════════════
    // LLM Intelligence Panel
    // ══════════════════════════════════════════════════════════════
    'tools.llm_intelligence':               'LLMインテリジェンス',
    'panel.llm_intel.title':                'LLMインテリジェンス',
    'panel.llm_intel.status_online':        'LLM オンライン',
    'panel.llm_intel.status_offline':       'LLM オフライン',
    'panel.llm_intel.status_disabled':      'LLM 無効',
    'panel.llm_intel.filter_all':           'すべて',
    'panel.llm_intel.filter_hacktivist':    'ハクティビスト',
    'panel.llm_intel.filter_diplo':         '外交',
    'panel.llm_intel.filter_military':      '軍事',
    'panel.llm_intel.filter_ground':        'グラウンド',
    'panel.llm_intel.filter_apt':           'APT',
    'panel.llm_intel.filter_narrative':     'ナラティブ',
    'panel.llm_intel.filter_convergence':   '収斂',
    'panel.llm_intel.filter_corroborated':  '複合確認',
    'panel.llm_intel.filter_triage':        'トリアージ',
    'panel.llm_intel.triage_empty':         '審査待ちのインテルはありません。',
    'panel.llm_intel.triage_showing':       '表示中',
    'panel.llm_intel.triage_scenario':      'シナリオ',
    'panel.llm_intel.triage_no_scenario':   'シナリオ結合なし — 国タグがアクティブシナリオ参加国と一致しません。',
    'panel.llm_intel.triage_corroborated':  '裏付け',
    'panel.llm_intel.triage_coupling_tip':  '参加重み × ソース確信度。値が大きいほどこのシナリオへの作戦的影響が高い。',
    'panel.llm_intel.triage_cred_tip':      'ソース確信度（0.30〜0.95）。自動承認には ≥ 0.75 が必要。',
    'panel.llm_intel.gate.low_confidence':       '確信度不足',
    'panel.llm_intel.gate.low_confidence_tip':   'LLM確信度が自動承認閾値（0.80）未満。スコア反映には手動承認が必要。',
    'panel.llm_intel.gate.low_source_credibility':     'ソース確信度不足',
    'panel.llm_intel.gate.low_source_credibility_tip': 'ソース確信度が0.75未満。実績が積み上がるまで自動承認は保留。',
    'panel.llm_intel.gate.ecosystem_blocked':       'エコシステム拒否',
    'panel.llm_intel.gate.ecosystem_blocked_tip':   'ソースのエコシステム（国家系メディア等）が自動承認の拒否リスト。手動審査必須。',
    'panel.llm_intel.gate.ecosystem_unclassified':     'エコシステム不明',
    'panel.llm_intel.gate.ecosystem_unclassified_tip': 'ソースのエコシステム未分類。フェイル・クローズ方針により既知信頼系のみ自動承認。',
    'panel.llm_intel.gate.manual_review':       '手動審査',
    'panel.llm_intel.gate.manual_review_tip':   '全ゲートを通過していますがアナリスト確認が必要です。',
    'panel.llm_intel.pulse_tip':            '高優先度の滞留トリアージ {n} 件あり。最古経過: {h}h。',
    'panel.llm_intel.stat_auto':            '自動',
    'panel.llm_intel.stat_manual':          '手動',
    'panel.llm_intel.stat_pending':         '審査待ち',
    'panel.llm_intel.stat_rejected':        '却下',
    'panel.llm_intel.stat_review':          '要確認',
    'panel.llm_intel.stat_auto_tip':        '自動承認: 投入時の閾値 + auto-judge のバックグラウンド適用',
    'panel.llm_intel.stat_manual_tip':      'アナリストが承認（手動レビュー）',
    'panel.llm_intel.stat_pending_tip':     'アナリストのレビュー待ち、または auto-judge には根拠不足',
    'panel.llm_intel.stat_reject_tip':      '却下（auto-judge / アナリスト / 誤検知）',
    'panel.llm_intel.empty':               'インテルアイテムなし',
    'panel.llm_intel.score_applied':        'スコア反映済み',
    'panel.llm_intel.btn_raw':             '▼ 原文',
    'panel.llm_intel.btn_confirm':          '✓ 承認',
    'panel.llm_intel.btn_dismiss':          '✗ 却下',
    'panel.llm_intel.btn_false_pos':        '⚠ 誤報',
    'panel.llm_intel.btn_reject':           '✗ 拒否',
    'panel.llm_intel.btn_override':         '✗ 取消',
    'panel.llm_intel.btn_revert':           '↩ 差戻し',
    'panel.llm_intel.override_confirm':     'この自動承認アイテムを取り消しますか？スコアへの加算が取り消されます。',
    'panel.llm_intel.override_failed':      '取消に失敗しました。',
    'panel.llm_intel.confirm_failed':       '承認に失敗しました: {reason}',
    'panel.llm_intel.reject_failed':        '却下に失敗しました: {reason}',
    'panel.llm_intel.revert_failed':        '取り消しに失敗しました: {reason}',
    'panel.llm_intel.diag_title':           '診断',
    'panel.llm_intel.diag_empty':           'このウィンドウ内にLLM呼出なし',
    'panel.llm_intel.diag_col_sensor':      'センサー',
    'panel.llm_intel.diag_col_calls':       '呼出',
    'panel.llm_intel.diag_col_auto':        'auto',         /* legacy alias */
    'panel.llm_intel.diag_col_ingest':      'ingest',       /* renamed for clarity */
    'panel.llm_intel.diag_col_ingest_tip':  '投入時点で自動承認された項目（LLM 呼び出し時の判定）。バックグラウンドの auto-judge が後から承認した項目はここに含まれない — 上のライフサイクル集計を参照。',
    'panel.llm_intel.diag_col_pending':     '保留',
    'panel.llm_intel.diag_col_filtered':    'フィルタ',
    'panel.llm_intel.diag_col_dedup':       '重複',
    'panel.llm_intel.diag_col_err':         'エラー',
    'panel.llm_intel.diag_col_conf':        '信頼',
    'panel.llm_intel.diag_col_ms':          'ms',
    'panel.llm_intel.diag_breakdown_title': 'センサー層フィルタ内訳',
    'panel.llm_intel.diag_lifecycle_title': 'ライフサイクル（{h}h ウィンドウ）',
    'panel.llm_intel.diag_lifecycle_note':  '下のセンサー別テーブルは投入時点の判定のみを示す。バックグラウンドの auto-judge による承認は、テーブルではなくこのライフサイクル集計に現れる。',
    'panel.llm_intel.diag_lc_auto':         '自動',
    'panel.llm_intel.diag_lc_manual':       '手動',
    'panel.llm_intel.diag_lc_pending':      '保留',
    'panel.llm_intel.diag_lc_review':       '要レビュー',
    'panel.llm_intel.diag_lc_rejected':     '却下',

    // ══════════════════════════════════════════════════════════════
    // Alert Lane / TRIAGE bar (post-redesign 2026-04-29)
    // ══════════════════════════════════════════════════════════════
    'alert_lane.title':                     'トリアージ',
    'alert_lane.subtitle':                  '— 注目度スコア順 (新規性 × 確信度の変化 × 最終閲覧からの経過時間)',
    'alert_lane.btn_ack':                   '確認済みにする',
    'alert_lane.btn_ack_tip':               '確認済みにする — 状態が変化するまでこの項目を非表示にする',
    'alert_lane.btn_drill':                 '精査 ▶',
    'alert_lane.btn_drill_tip':             '監査経路のドリルダウンを開く (式・センサー・ソース)',
    // ══════════════════════════════════════════════════════════════
    // Strategic Climate Feed
    // ══════════════════════════════════════════════════════════════
    'tools.strategic_climate':            '戦略的環境気候',
    'panel.climate.title':                '戦略的環境気候',
    'panel.climate.gauge_label':          '環境気候',
    'panel.climate.loading':              '環境シグナルを収集中...',
    'panel.climate.no_events':            '環境シグナルなし',
    'panel.climate.filter_all':           '全て',
    'panel.climate.filter_time':          '時間',
    'panel.climate.filter_space':         '空間',
    'panel.climate.filter_target':        '対象',
    'panel.climate.filter_context':       '暦',
    'hud.tooltip.climate':                '戦略的環境気候 — 間接的環境指標',
    'panel.climate.baseline_exact':       '完全一致',
    'panel.climate.baseline_hour':        '時間帯',
    'panel.climate.baseline_all':         '全体',
    'panel.climate.baseline_tooltip':     '季節ベースライン: 完全一致=同曜日同時間帯, 時間帯=同時間帯全曜日, 全体=全履歴平均',

    // ══════════════════════════════════════════════════════════════
    // Evidence Panel: Contribution Waterfall & Counter-Signals
    'evidence.wf_bonus':                  '収斂ボーナス',
    'evidence.counter_signals':           '反証シグナル（正常な読み取り値）',
    'evidence.intel_gaps':                'インテリジェンスギャップ（オフラインセンサー）',
    'evidence.gap_never':                 'データなし',
    'evidence.gap_last_data':             '最終取得',

    // Sensor Health: Circuit Breaker
    'sensor.health.circuit_open':             'サーキットオープン（自動一時停止）',
    'sensor.health.circuit_open_persistent':  'サーキットオープン — 複数回のリカバリプローブ失敗',

    // Phase 3: TOOLS menu sections
    'tools.section.core':             'コア',
    'tools.section.analytics':        'アナリティクス',
    'tools.section.simulation':       'シミュレーション',
    'tools.section.tradecraft':       'トレードクラフト',
    'tools.section.admin':            '管理',
    'tools.tradecraft':               'アナリスト・トレードクラフト',
    'tools.sensor_watchpane':         'センサー監視盤',

    // ── Tradecraft panel (F4-F14 analyst surface) ──────────────────────
    'panel.tradecraft.title':                    'アナリスト・トレードクラフト',
    'panel.tradecraft.scenario_label':            'シナリオ',
    'panel.tradecraft.loading':                  '読み込み中…',
    'panel.tradecraft.tab.hidden':               '隠れシグナル',
    'panel.tradecraft.tab.coverage':             'カバレッジ',
    'panel.tradecraft.tab.disconf':              '反証証拠',
    'panel.tradecraft.tab.compare':              'シナリオ比較',
    'panel.tradecraft.tab.ach':                  'ACH',
    'panel.tradecraft.tab.dissent':              '少数意見',
    'panel.tradecraft.tab.assumptions':          '前提条件',
    'panel.tradecraft.tab.premortem':            'プリモーテム',
    'panel.tradecraft.tab.decisions':            '決定台帳',
    'panel.tradecraft.tab.whatif':               'What-If重み',

    'panel.tradecraft.col.time':                 '時刻',
    'panel.tradecraft.col.country':              '国',
    'panel.tradecraft.col.sensor':               'センサー',
    'panel.tradecraft.col.domain':               'ドメイン',
    'panel.tradecraft.col.reason':               '抑制理由',
    'panel.tradecraft.col.detail':               '詳細',
    'panel.tradecraft.col.state':                '状態',
    'panel.tradecraft.col.last_success':         '最終成功',
    'panel.tradecraft.col.fail_count':           '失敗数',
    'panel.tradecraft.col.summary':              '要約',
    'panel.tradecraft.col.source_kind':          '種別',
    'panel.tradecraft.col.strength':             '強度',
    'panel.tradecraft.col.author':               '作成者',
    'panel.tradecraft.col.actions':              '',
    'panel.tradecraft.col.scenario':             'シナリオ',
    'panel.tradecraft.col.score':                'スコア',
    'panel.tradecraft.col.cyber':                'サイバー',
    'panel.tradecraft.col.physical':             '物理',
    'panel.tradecraft.col.info':                 '情報',
    'panel.tradecraft.col.signals':              '信号数',
    'panel.tradecraft.col.actor':                '実行者',
    'panel.tradecraft.col.type':                 '種別',
    'panel.tradecraft.col.session':              'セッション',

    'panel.tradecraft.btn.add':                  '追加',
    'panel.tradecraft.btn.retract':              '撤回',
    'panel.tradecraft.btn.compare':              '比較実行',
    'panel.tradecraft.btn.new_matrix':           '新規マトリクス',
    'panel.tradecraft.btn.add_hyp':              '+ 仮説',
    'panel.tradecraft.btn.add_ev':               '+ 証拠',
    'panel.tradecraft.btn.resolve':              '解決',
    'panel.tradecraft.btn.log':                  '決定を記録',

    'panel.tradecraft.hidden.help':              'FIRED したが、ミュート/ノイズ分類/低確信度などで抑制されたシグナル。データは存在するがスコアに寄与していない「データの出口」を可視化する。',
    'panel.tradecraft.hidden.empty':             '直近の窓では抑制されたシグナルはありません。',
    'panel.tradecraft.coverage.help':            'このシナリオに関連するセンサーごとの回路ブレーカー状態。劣化したセンサーは盲点を生む可能性がある。',
    'panel.tradecraft.coverage.empty':           'まだカバレッジスナップショットがありません — 次のスコアリング周期を待ってください。',
    'panel.tradecraft.coverage.summary':         '{total} センサー中 {degraded} が劣化',
    'panel.tradecraft.disconf.help':             '現在のシナリオ評価に矛盾する証拠を記録します。確証バイアス対策として明示的な反証を強制する。',
    'panel.tradecraft.disconf.empty':            'まだ反証証拠は登録されていません。',
    'panel.tradecraft.disconf.summary_ph':       '現状の読みに矛盾する観測・引用・分析は何か?',
    'panel.tradecraft.disconf.sref_ph':          'ソース参照(URL / intel_id / rationale_id ― 任意)',
    'panel.tradecraft.disconf.kind_note':        '手動ノート',
    'panel.tradecraft.disconf.kind_intel':       'インテル項目',
    'panel.tradecraft.disconf.kind_rationale':   'ラショナル項目',
    'panel.tradecraft.disconf.strength_1':       '強度 1 ― 伝聞程度',
    'panel.tradecraft.disconf.strength_2':       '強度 2 ― 弱',
    'panel.tradecraft.disconf.strength_3':       '強度 3 ― 中',
    'panel.tradecraft.disconf.strength_4':       '強度 4 ― 強',
    'panel.tradecraft.disconf.strength_5':       '強度 5 ― 決定的',
    'panel.tradecraft.disconf.retracted':        '撤回済み',
    'panel.tradecraft.compare.help':             '複数シナリオの LITE+FULL スコアを横並び比較。フォーカス中シナリオが背景シナリオとどう違うかを見るのに有用。',
    'panel.tradecraft.compare.need2':            '比較には少なくとも2つのシナリオを選択してください。',
    'panel.tradecraft.compare.as_focused':       '各行はそのシナリオがフォーカス中の場合(全センサー稼働)として再採点した結果。',
    'panel.tradecraft.ach.help':                 'Heuer 競合仮説分析(ACH)。各証拠を仮説ごとに −2(強く矛盾)から +2(強く一致)まで評価。Σが最も負でない仮説=最も否定されていない。証拠の重み = 信頼性 × 関連性(各1–5)。',
    'panel.tradecraft.ach.empty':                'マトリクスがありません — 上で作成してください。',
    'panel.tradecraft.ach.title_ph':             'マトリクス・タイトル(例:「中国は2026年Q4までに敵対行動を開始するか?」)',
    'panel.tradecraft.ach.hyp_ph':               '仮説(相互排他的に)',
    'panel.tradecraft.ach.null_hyp':             '帰無仮説(現状維持/ベースライン)',
    'panel.tradecraft.ach.ev_ph':                '証拠項目',
    'panel.tradecraft.ach.sref_ph':              'ソース参照(任意)',
    'panel.tradecraft.ach.credibility':          '信頼性 1–5(ソースの確信度)',
    'panel.tradecraft.ach.relevance':            '関連性 1–5(これら仮説への診断力)',
    'panel.tradecraft.ach.cred_rel':             '信頼性 × 関連性 / 25',
    'panel.tradecraft.ach.need_both':            '採点を始めるには仮説と証拠を1つ以上追加してください。',
    'panel.tradecraft.ach.tally_help':           'Σ 行 = Σ(consistency × 信頼性 × 関連性 / 25)。Σ が最も負でない仮説が最も否定されていない。',
    'panel.tradecraft.dissent.help':             '少数意見を記録。コンセンサスに埋もれず明示的に異論を残す(デビルズ・アドボケイト)。',
    'panel.tradecraft.dissent.empty':            '少数意見は登録されていません。',
    'panel.tradecraft.dissent.title_ph':         '異論タイトル(1行要約)',
    'panel.tradecraft.dissent.body_ph':          'コンセンサスはどこを見落としているか?推論と支持シグナルを含める。',
    'panel.tradecraft.dissent.tl_none':          '(代替TLの提案なし)',
    'panel.tradecraft.dissent.resolution':       '解決',
    'panel.tradecraft.dissent.resolved':         '解決済み',
    'panel.tradecraft.dissent.resolve_prompt':   '解決ノート(この異論はどう扱われたか?):',
    'panel.tradecraft.assumptions.help':         '主要前提条件チェック(KAC)。シナリオを支える前提を列挙。ロックでドリフト防止、無効化で破綻を明示。',
    'panel.tradecraft.assumptions.empty':        '登録された前提条件はありません。',
    'panel.tradecraft.assumptions.stmt_ph':      '前提条件の文(例:「PLA冬季演習のOPLANは防御的」)',
    'panel.tradecraft.assumptions.rat_ph':       '根拠 / ソース',
    'panel.tradecraft.assumptions.conf_low':     '低確信度',
    'panel.tradecraft.assumptions.conf_med':     '中確信度',
    'panel.tradecraft.assumptions.conf_high':    '高確信度',
    'panel.tradecraft.assumptions.confidence':   '確信度',
    'panel.tradecraft.assumptions.locked':       'ロック中',
    'panel.tradecraft.assumptions.invalidated':  '無効化',
    'panel.tradecraft.assumptions.btn.invalidate': '無効化',
    'panel.tradecraft.assumptions.btn.lock':     'ロック',
    'panel.tradecraft.assumptions.btn.unlock':   'ロック解除',
    'panel.tradecraft.assumptions.btn.history':  '履歴',
    'panel.tradecraft.assumptions.invalidate_prompt': '無効化理由(何が変わったか?):',
    'panel.tradecraft.premortem.help':           'プリモーテム(Klein 2007)。シナリオ評価が外れたと仮定して、失敗モード・想定結末・根本原因・先行兆候・緩和策を列挙。',
    'panel.tradecraft.premortem.empty':          'プリモーテム項目はありません。',
    'panel.tradecraft.premortem.mode_fp':        '偽陽性(脅威を過大に読んだ)',
    'panel.tradecraft.premortem.mode_fn':        '偽陰性(脅威を過小に読んだ)',
    'panel.tradecraft.premortem.mode_bias':      '認知バイアス(フレーミング/アンカリング)',
    'panel.tradecraft.premortem.mode_unknown':   '不明な失敗モード',
    'panel.tradecraft.premortem.imagined_ph':    '想定結末(具体的に何が起きるか?)',
    'panel.tradecraft.premortem.rootcause_ph':   '根本原因(なぜ読みが外れたのか?)',
    'panel.tradecraft.premortem.warning_ph':     '先行兆候(最初に何を観測するか?)',
    'panel.tradecraft.premortem.mitigation_ph':  '緩和策(どう対応するか?)',
    'panel.tradecraft.premortem.imagined':       '想定結末',
    'panel.tradecraft.premortem.rootcause':      '根本原因',
    'panel.tradecraft.premortem.warning':        '先行兆候',
    'panel.tradecraft.premortem.mitigation':     '緩和策',
    'panel.tradecraft.premortem.resolved':       '解決済み',
    'panel.tradecraft.premortem.resolve_confirm': 'このプリモーテム項目を解決済みにしますか?',
    'panel.tradecraft.decisions.help':           '決定台帳。アナリストの判断変更を session_id(タブ単位 UUID)付きで記録、事後レビュー用。',
    'panel.tradecraft.decisions.empty':          '記録された決定はありません。',
    'panel.tradecraft.decisions.sum_ph':         '何を決定したか?(一行)',
    'panel.tradecraft.decisions.rat_ph':         '根拠 / 文脈(任意)',
    'panel.tradecraft.decisions.show_auto':      '自動記録された tradecraft アクションを表示',
    'panel.tradecraft.decisions.auto_tag':       '自動',
    'panel.tradecraft.decisions.auto_tip':       'tradecraft 書き込み (F6/F8/F10/F11/F13) により自動記録。上のチェックを外すと手動入力のみ表示。',
    'panel.tradecraft.decisions.type.threshold': '閾値変更',
    'panel.tradecraft.decisions.type.weight':    '重みオーバーライド',
    'panel.tradecraft.decisions.type.classify':  'シグナル分類',
    'panel.tradecraft.decisions.type.intel':     'インテル操作',
    'panel.tradecraft.decisions.type.report':    'レポート公開',
    'panel.tradecraft.decisions.type.other':    'その他',
    'panel.tradecraft.whatif.help':              'スライダーで参加国の結合重みをオーバーライドし、RUN で最新スナップショットに対して採点を再生。読み取り専用 — 本番スコアには影響しません。',
    'panel.tradecraft.whatif.run':               'シミュレーション実行',
    'panel.tradecraft.whatif.reset':             'リセット',
    'panel.tradecraft.whatif.base':              'ベースライン',
    'panel.tradecraft.whatif.sim':               'シミュレーション',
    'panel.tradecraft.whatif.snapshot_age':      'スナップショット年齢',

    // F1/F2/F3 inline badges
    'evidence.prov.chain_tip':                   'signal_source: {src} · 裏付けセンサー: {chain}',
    'evidence.prov.solo_tip':                    'signal_source: {src}(同じグループに他センサーなし)',
    'scenario.freshness_tip':                    'スコアは {age} 前のキャッシュを使用。90秒超で警告。',
    'panel.llm_intel.cred_tier.trusted':         '信頼済',
    'panel.llm_intel.cred_tier.standard':        '標準',
    'panel.llm_intel.cred_tier.unverified':      '未確認',
    'panel.llm_intel.cred_tier_tip':             '{tier} ソース · {src} · 確信度 {val}',

    // Phase 3: HUD UX
    'hud.tooltip.expand_secondary':   '副次メトリクスの表示/非表示',
    'hud.sync.next':                  '次の同期まで',
    'hud.tooltip.ws_status':          'WebSocket状態: 緑=接続中、橙=ポーリングフォールバック',

    // ══════════════════════════════════════════════════════════════
    // User Management panel
    // ══════════════════════════════════════════════════════════════
    'panel.usermgr.title':            'ユーザー管理',
    'panel.usermgr.authenticate':     '認証',
    'panel.usermgr.ph.username':      'ユーザー名',
    'panel.usermgr.ph.password':      'パスワード',
    'panel.usermgr.btn.login':        'ログイン',
    'panel.usermgr.btn.logout':       'ログアウト',
    'panel.usermgr.add_header':       'ユーザー追加',
    'panel.usermgr.registered':       '登録ユーザー一覧',
    'panel.usermgr.reset_header':     'パスワードリセット：',
    'panel.usermgr.ph.new_password':  '新しいパスワード（6文字以上）',
    'panel.usermgr.btn.reset':        'リセット',
    'panel.usermgr.btn.cancel':       'キャンセル',
    'panel.usermgr.btn.add':          '追加',
    'panel.usermgr.msg.enter_creds':  '認証情報を入力してください',
    'panel.usermgr.msg.login_failed': 'ログイン失敗',
    'panel.usermgr.msg.conn_error':   '接続エラー',
    'panel.usermgr.msg.logged_in':    'ログイン中: {username}（{role}）',
    'panel.usermgr.msg.admin_req':    '— 管理には admin 権限が必要です',
    'panel.usermgr.err.admin_priv':   'ユーザー一覧の表示には admin 権限が必要です。',
    'panel.usermgr.err.load_users':   'ユーザーの読み込みに失敗しました。',
    'panel.usermgr.err.load_error':   'ユーザー読み込みエラー。',
    'panel.usermgr.tbl.username':     'ユーザー名',
    'panel.usermgr.tbl.role':         'ロール',
    'panel.usermgr.tbl.created':      '作成日',
    'panel.usermgr.tbl.last_login':   '最終ログイン',
    'panel.usermgr.tbl.actions':      '操作',
    'panel.usermgr.tbl.never':        '未ログイン',
    'panel.usermgr.btn.pw':           'PW',
    'panel.usermgr.tip.reset_pw':     'パスワードリセット',
    'panel.usermgr.btn.del':          '削除',
    'panel.usermgr.tip.delete':       'ユーザーを削除',
    'panel.usermgr.val.user_pass_req':'ユーザー名とパスワードを入力してください',
    'panel.usermgr.val.pass_min6':    'パスワードは6文字以上にしてください',
    'panel.usermgr.err.add_user':     'ユーザーの追加に失敗しました',
    'panel.usermgr.err.update_role':  'ロールの変更に失敗しました',
    'panel.usermgr.err.delete_user':  'ユーザーの削除に失敗しました',
    'panel.usermgr.err.reset_pw':     'パスワードのリセットに失敗しました',
    'panel.usermgr.confirm.delete':   'ユーザー「{username}」を削除しますか？この操作は元に戻せません。',
    'panel.usermgr.confirm.pw_reset': '{username} のパスワードをリセットしました',
    'panel.usermgr.change_pw_header': 'パスワード変更',
    'panel.usermgr.ph.old_password':  '現在のパスワード',
    'panel.usermgr.ph.new_password':  '新しいパスワード（6文字以上）',
    'panel.usermgr.btn.change_pw':    '変更',
    'panel.usermgr.err.old_pw_req':   '現在のパスワードを入力してください',
    'panel.usermgr.err.change_pw':    'パスワードの変更に失敗しました',
    'panel.usermgr.msg.pw_changed':   'パスワードを変更しました',
    'panel.usermgr.ph.select_user':   '-- ユーザーを選択 --',
    'panel.usermgr.err.select_user':  'ユーザーを選択してください',
    'panel.usermgr.roles_header':     'ロール一覧',
    'panel.usermgr.role_desc.admin':  'フルアクセス。ユーザー管理、システム設定、シナリオ管理、全ての運用機能を利用可能。',
    'panel.usermgr.role_desc.analyst':'運用アクセス。シナリオフォーカス切替、センサー設定、インテルレビュー、監視機能を利用可能。',
    'panel.usermgr.role_desc.viewer': '閲覧専用。ダッシュボード閲覧、フェッチログ確認、自身のパスワード変更のみ。',

    // ══════════════════════════════════════════════════════════════
    // History Analysis panel
    // ══════════════════════════════════════════════════════════════
    'panel.history.title':            '履歴分析',
    'panel.history.theater':          '国：',
    'panel.history.range':            '範囲：',
    'panel.history.range_24h':        '24時間',
    'panel.history.range_3d':         '3日間',
    'panel.history.range_7d':         '7日間',
    'panel.history.range_14d':        '14日間',
    'panel.history.range_28d':        '28日間',
    'panel.history.btn.refresh':      '更新',
    'panel.history.btn.export':       'エクスポート',
    'panel.history.hdr.threat_trend': '脅威スコア推移',
    'panel.history.hdr.hod_baseline': '時間帯別ベースライン（CF スパイク平均）',
    'panel.history.hdr.seq_events':   'シーケンスイベント',
    'panel.history.hdr.alerts':       '最近のアラート',
    'panel.history.no_data':          'データ不足',
    'panel.history.no_hod':           'HOD データなし',
    'panel.history.no_events':        '該当期間のイベントなし',
    'panel.history.no_alerts':        'アラートなし',
    'panel.history.stat.points':      'データ数',
    'panel.history.stat.peak':        'ピーク',
    'panel.history.stat.avg':         '平均',
    'panel.history.stat.events':      'イベント',
    'panel.history.stat.alerts':      'アラート',
    'panel.history.dur.ongoing':      '継続中',
    'panel.history.label.transition': '{n} 遷移',
    'panel.history.label.transitions':'{n} 遷移',
    'panel.history.label.peak':       'ピーク',

    // ── threat level labels (HUD) ───────────────────────────────
    'threat_lv.5':                    '脅威 Lv 5: 正常',
    'threat_lv.4':                    '脅威 Lv 4: 警戒',
    'threat_lv.3':                    '脅威 Lv 3: 高',
    'threat_lv.2':                    '脅威 Lv 2: 深刻',
    'threat_lv.1':                    '脅威 Lv 1: 危機的',

    // ── telegram SIGINT status ──────────────────────────────────
    'tg.hud.intent':                  '意図検知 ({n} ch)',
    'tg.hud.targets_found':           '標的確認',
    'tg.hud.clear':                   '異常なし',

    // ── unit labels ─────────────────────────────────────────────
    'unit.aircraft':                  '{n} 機',
    'unit.vessels':                   '{n} 隻',

    // ── telemetry badges / tooltips ─────────────────────────────
    'badge.bgp_outage':               'BGP⚠',
    'badge.bgp_wx':                   'BGP(天候)',
    'badge.media_alert':              'M⚠',
    'badge.media_wx':                 'M(天候)',
    'badge.airspace_wx':              '✈(天候)',
    'badge.l7_shift':                 'L7 シフト',
    'badge.new_actor':                '新規',
    'badge.state_asn':                '国家ASN',
    'tooltip.bgp_outage':             'BGP/障害検出',
    'tooltip.bgp_wx':                 '障害（天候によるミュート）',
    'tooltip.media_alert':            'メディアトーン低下',
    'tooltip.media_wx':               'メディアトーン（天候によるミュート）',
    'tooltip.airspace_wx':            '空域異常（天候によるミュート）',
    'tooltip.l7_shift':               'オリジン別L7シフト検出元:{actors}',
    'tooltip.new_actor':              '28日間のベースラインなし: 新規インフラ',
    'tooltip.state_asn':              '国家帰属ASN検出:\\n{asns}',
    'tooltip.cdn_asphyxiation':       'CDN窒息: 成功率は正常だがレイテンシがベースラインの3倍以上',
    'tooltip.thermal_anomaly':        '熱異常 (FIRMS)',

    // ── DDoS Core Strengthening (v10) ────────────────────────────
    'evidence.blockade_index':        '封鎖指数',
    'evidence.blockade_scored':       'インフラ封鎖有効（BI≥7.0）— 脅威スコアに反映',
    'evidence.cdn_asphyxiation':      'CDN窒息',
    'evidence.cdn_asphyx_scored':     'CDNがパケットロスを隠蔽するがレイテンシ3倍化でインフラ負荷を検出 — 独立シグナル',
    'evidence.vector_shift_severe':   '重度L7シフト',
    'evidence.vector_shift_moderate': 'L7シフト',
    'evidence.adversary_multi':       '複数アクター敵対攻撃（{n}アクター）',
    'evidence.seq_decay':             'シーケンスボーナス {pct}% 減衰（イベント経過時間）',
    'evidence.ddos_bgp_causal':       'DDoS-BGP因果: CFスパイクとBGP障害が同時発生',

    // ── DDoS Intelligence Enhancement (v11) ─────────────────────
    'evidence.ioda_proper':           'IODA本格API',
    'evidence.ioda_multi_source':     'IODA: {n}個の独立データソースで確認（{sources}）',
    'evidence.ioda_fallback':         'IODA: CF Radarフォールバック使用（IODA API到達不能）',
    'evidence.bgp_hijack':            'BGPハイジャック検出',
    'evidence.bgp_hijack_detail':     'BGP操作: 進行中のハイジャック{hijacks}件、ルートリーク{leaks}件',
    'evidence.bgp_trend_withdraw':    'BGPプレフィックス傾向: 減少中（{pct}%低下）',
    'evidence.bgp_trend_stable':      'BGPプレフィックス傾向: 安定',
    'evidence.bgp_trend_growing':     'BGPプレフィックス傾向: 増加中（{pct}%上昇）',
    'evidence.entropy_concentrating': '攻撃ソース集中化（エントロピー{delta}%低下）',
    'evidence.entropy_dispersing':    '攻撃ソース分散化（エントロピー{delta}%上昇）',
    'evidence.entropy_stable':        '攻撃ソース分布安定',
    'label.ioda_source':              'IODAソース',
    'label.bgp_events':              'BGPイベント',
    'label.origin_entropy':           'オリジンエントロピー',
    'label.prefix_trend':             'プレフィックス傾向',

    // ── ISR / map popups ────────────────────────────────────────
    'map.popup.isr_track':            '▲ ISR 追跡',
    'map.popup.isr_callsign':         'コールサイン: {cs}',
    'map.popup.isr_alt_speed':        '高度: {alt} km  |  速度: {spd} kt',
    'map.popup.isr_squawk':           'スコーク: {sq}',

    // ── CIP panel extra labels ──────────────────────────────────
    'cip.label.baseline_28d':         'ベースライン(28日): {base}  Δ {delta}',

    // ── config save status ──────────────────────────────────────
    'config.status.saving':           '保存中...',
    'config.status.saved':            '✓ 保存完了（{n} 件更新）',
    'config.status.needs_restart':    '— 一部の設定は再起動が必要です',
    'config.status.error':            '✗ エラー: {msg}',
    'config.status.load_error':       '読み込み失敗: {msg}',
    'sysconfig.badge.restart':        '再起動',
    'sysconfig.badge.live':           'ライブ',

    // ══════════════════════════════════════════════════════════════
    // System Config — additional fields
    // ══════════════════════════════════════════════════════════════
    'sysconfig.section.server':       'サーバー',
    'sysconfig.help.host_external':   '外部からアクセスする場合は 0.0.0.0 に設定',
    'sysconfig.section.auth':         '認証（JWT）',
    'sysconfig.help.default_admin_pw':'初回起動時の admin パスワード（運用後はAPIで変更）',
    'sysconfig.help.jwt_secret':      '空欄の場合は起動毎にランダム生成（再起動でトークン無効化）',
    'sysconfig.section.notifications':'アラート通知',
    'sysconfig.help.notifications':   'Threat Level変化・Ambush検出時に外部通知を送信。Webhook URLを設定すると有効になります。',
    'sysconfig.section.plugins':      'プラグインセンサー',
    'sysconfig.help.server_restart':  'Server 設定はすべて再起動が必要です。',
    'sysconfig.help.auth_desc':       'ユーザー認証とセッション管理。初回起動時にデフォルト admin ユーザーが作成されます。',
    'sysconfig.help.debounce':        '同一アラートの連続通知を抑制する間隔',
    'sysconfig.help.plugins_desc':    'plugins/ ディレクトリからBaseSensorサブクラスを動的にロードします。',
    'sysconfig.help.plugin_enabled':  'カンマ区切りのファイル名（拡張子なし）、または * で全プラグイン',
    'sysconfig.help.plugin_disabled': '明示的に無効にするプラグイン名（カンマ区切り）',

    // ══════════════════════════════════════════════════════════════
    // CAC — Context-Aware Convergence
    // ══════════════════════════════════════════════════════════════
    'hud.label.context_align':        'ALIGN',
    'hud.tooltip.context_align':      '文脈整合度: 4軸（時間/空間/対象/方向）のうちいくつが高リスク状態か',
    'hud.label.direction':            'DIR:',
    'hud.tooltip.direction':          'シグナル方向性: 発火シグナルの支配的分類',
    'evidence.context_alignment':     '文脈整合度',
    'evidence.direction':             '方向性',
    'evidence.btn.classify_tip':      'このシグナルをノイズとして分類（演習/保守/既知）',
    'evidence.convergence_score':     '収斂スコア',
    'evidence.none':                  'なし',
    'evidence.dir_counter_label':     '敵対:{adv} 友軍:{frd} 対象:{tgt}',
    'evidence.wf_legend.cyber':       'サイバー',
    'evidence.wf_legend.phys':        '物理',
    'evidence.wf_legend.info':        '情報',
    'evidence.wf_legend.bonus':       'ボーナス',
    'evidence.domain.cyber':          'サイバー',
    'evidence.domain.physical':       '物理',
    'evidence.domain.info':           '情報',
    'evidence.domain.other':          'その他',
    'evidence.group.count':           '{fired}/{total} 発火',
    'evidence.group.total':           'Σ {n}pt',
    'modal.evidence.th_direction':    '方向',
    'cac.axis.temporal':              '時間',
    'cac.axis.spatial':               '空間',
    'cac.axis.target':                '対象',
    'cac.axis.direction':             '方向',
    'dir.adversary':                  '敵性攻勢',
    'dir.friendly':                   '友軍防御',
    'dir.target':                     '対象影響',
    'dir.unknown':                    '不明',
    'noise.classify_prompt':          '{sensor} のシグナルを分類:',
    'noise.classify_hint':            '番号を入力 (1-4):',
    'noise.invalid_choice':           '無効な選択です。',
    'noise.exercise':                 '演習 / 訓練',
    'noise.maintenance':              '定期保守',
    'noise.known_noise':              '既知ノイズ源',
    'noise.false_positive':           '誤検知',
    'noise.expires_prompt':           '自動失効までの時間（空欄=永続）:',
    'threat_cls.prompt':              '現在の脅威状況を分類:',
    'threat_cls.exercise':            '演習 / 訓練',
    'threat_cls.maintenance':         '定期保守',
    'threat_cls.confirmed_threat':    '確認済み脅威',
    'threat_cls.false_positive':      '誤検知',
    'threat_cls.notes_prompt':        '追加メモ（任意）:',

    // ══════════════════════════════════════════════════════════════
    // Phase C: New Sensors S1-S7
    // ══════════════════════════════════════════════════════════════
    // S1: NOTAM
    'sensor.notam':                   'NOTAM異常',
    'sensor.notam.desc':              '空域制限急増検知（TFR / 軍事NOTAM）',
    'sensor.notam.surge':             'NOTAM急増: {total}件 (軍事{mil}件)',
    'sensor.notam.normal':            'NOTAM異常なし',
    'badge.notam_surge':              'NOTAM急増',
    // S2: Travel Advisory
    'sensor.travel_advisory':         '渡航勧告',
    'sensor.travel_advisory.desc':    '米国務省渡航勧告レベル監視',
    'sensor.travel_advisory.level':   'レベル{n}: {label}',
    'sensor.travel_advisory.upgraded':'引上げ',
    'sensor.travel_advisory.l1':      '通常注意',
    'sensor.travel_advisory.l2':      '注意強化',
    'sensor.travel_advisory.l3':      '渡航再検討',
    'sensor.travel_advisory.l4':      '渡航中止勧告',
    'badge.travel_advisory':          '渡航勧告',
    // S3: OONI Censorship
    'sensor.ooni':                    'OONI検閲',
    'sensor.ooni.desc':               'インターネット検閲測定（Webブロッキング、DNS改竄）',
    'sensor.ooni.censoring':          '検閲検知: 異常率{rate}',
    'sensor.ooni.heavy':              '重度検閲: 異常率{rate}、確認{confirmed}',
    'sensor.ooni.normal':             '重大な検閲なし',
    'badge.ooni_censorship':          '検閲',
    // S4: USGS Seismic
    'sensor.usgs_seismic':            'USGS地震',
    'sensor.usgs_seismic.desc':       '海底ケーブル・チョークポイント付近の地震監視',
    'sensor.usgs_seismic.cable':      '海底ケーブル付近で地震: {cp}',
    'sensor.usgs_seismic.nuclear':    '核実験疑い（{n}候補）',
    'sensor.usgs_seismic.normal':     '重大な地震活動なし',
    'badge.seismic_cable':            '地震/ケーブル',
    'badge.nuclear_candidate':        '核実験？',
    // S5: Military Support Aircraft
    'sensor.mil_support_air':         '軍事支援航空機',
    'sensor.mil_support_air.desc':    '空中給油機・輸送機・早期警戒機の追跡',
    'sensor.mil_support_air.surge':   '軍事航空機急増: 給油={tanker} 輸送={transport} 早警={awacs}',
    'sensor.mil_support_air.normal':  '軍事支援航空機の異常なし',
    'badge.mil_air_surge':            '軍事航空急増',
    'badge.tanker':                   '給油機',
    'badge.transport':                '輸送機',
    'badge.awacs':                    'AWACS',
    // S6: GPS Jamming
    'sensor.gps_jamming':             'GPSジャミング',
    'sensor.gps_jamming.desc':        '監視対象国の周辺のGPS妨害/スプーフィング検知',
    'sensor.gps_jamming.detected':    'GPSジャミング検知: 最大={max}、平均={avg}',
    'sensor.gps_jamming.critical':    '重大GPSジャミング: 最大={max}',
    'sensor.gps_jamming.normal':      'GPS干渉なし',
    'badge.gps_jamming':              'GPS妨害',
    // S7: CT Log
    'sensor.ct_log':                  'CTログ監視',
    'sensor.ct_log.desc':             '証明書透明性ログ異常検知',
    'sensor.ct_log.surge':            '証明書急増: {total}件 (政府{gov}件)',
    'sensor.ct_log.gov_surge':        '政府証明書急増: {gov}件',
    'sensor.ct_log.normal':           'CTログ異常なし',
    'badge.ct_surge':                 '証明書急増',

    // ── Scenario (Phase 4) ──
    'scenario.badge.focused':         'フォーカス',
    'scenario.badge.lite':            'LITE',
    'scenario.state.active':          'アクティブ',
    'scenario.state.paused':          '一時停止',
    'scenario.state.archived':        'アーカイブ済',
    'scenario.role.primary_target':   '主要標的',
    'scenario.role.principal_belligerent': '主要交戦国',
    'scenario.role.adversary':        '敵対国',
    'scenario.role.primary_ally':     '主要同盟国',
    'scenario.role.forward_base':     '前方基地',
    'scenario.role.secondary_ally':   '二次同盟国',
    'scenario.role.extended_deterrence': '拡大抑止',
    'scenario.role.strategic_observer': '戦略的観察者',
    'scenario.role.proxy_front':      '代理戦線',
    'scenario.role.force_projection': '戦力投射',
    'scenario.role.secondary_party':  '二次当事国',
    'scenario.role.spillover_risk':   '波及リスク',
    'scenario.role.regional_power':   '地域大国',
    'scenario.mgr.title':            'シナリオ管理',
    'scenario.mgr.create':           'シナリオ作成',
    'scenario.mgr.edit':             'シナリオ編集',
    'scenario.mgr.delete':           '削除',
    'scenario.mgr.archive':          'アーカイブ',
    'scenario.mgr.restore':          '復元',
    'scenario.mgr.purge':            '完全削除',
    'scenario.mgr.reset':            'プリセットに戻す',
    'scenario.mgr.purge_confirm':    'このシナリオと全データを完全に削除しますか？この操作は取り消せません。',
    'scenario.mgr.name_en':          '名称 (英語)',
    'scenario.mgr.name_ja':          '名称 (日本語)',
    'scenario.mgr.desc_en':          '説明 (英語)',
    'scenario.mgr.desc_ja':          '説明 (日本語)',
    'scenario.mgr.core_country':     'コア国家',
    'scenario.mgr.participants':     '参加国',
    'scenario.mgr.add_participant':  '参加国を追加',
    'scenario.mgr.weight':           '重み',
    'scenario.mgr.role':             '役割',
    'scenario.mgr.country':          '国',
    'scenario.mgr.save':             '保存',
    'scenario.mgr.cancel':           'キャンセル',
    'scenario.mgr.enabled':          '有効',
    'scenario.mgr.disabled':         '無効',
    'scenario.mgr.enable':           '有効化',
    'scenario.mgr.disable':          '無効化',
    'scenario.mgr.bloc_all':         'すべて',
    'scenario.mgr.bloc_selected':    '選択済み',
    'scenario.mgr.ph_search':        '国名またはコードでフィルタ...',
    'scenario.mgr.err.no_participants': '少なくとも1つのparticipantが必要です',
    'scenario.mgr.source_preset':    'プリセット',
    'scenario.mgr.source_db':        'カスタム',
    'scenario.mgr.changelog':        '変更履歴',
    'scenario.mgr.no_changes':       '変更履歴なし',
    'scenario.tab.scenarios':        'シナリオ',
    // Phase 5: detail panel
    'scenario.badge.lite_warn':      '偏り注意',
    'scenario.tl.lite_insufficient': '観測不足',
    'scenario.tl.lite_insufficient_tip': '観測可能な信号が不足: 3ドメインのうち0-1ドメインしかデータがありません。脅威レベルは導出不能です。フル観測するにはこのシナリオにfocusを切り替えてください。',
    'scenario.coverage.badge':       'カバー {pct}%',
    'scenario.coverage.tip':         'ドメインカバー率: {pct}% — 観測欠落: {blind}。LITEモードではこのシナリオは {pct}% のドメインのみで採点されており、実際のリスクを過小/過大評価する可能性があります。フル観測するにはfocusを切り替えてください。',
    'scenario.detail.score':         'スコア',
    'scenario.detail.contributions': '寄与一覧',
    'scenario.detail.no_contributions': '寄与は記録されていません。',
    'scenario.detail.col_sensor':    'センサー',
    'scenario.detail.col_country':   '国',
    'scenario.detail.col_role':      '役割',
    'scenario.detail.col_raw':       '原値',
    'scenario.detail.col_llm_w':     'LLM重み',
    'scenario.detail.col_part_w':    '参加重み',
    'scenario.detail.col_contrib':   '寄与',
    'scenario.detail.col_evidence':  '原典',
    'scenario.detail.col_whatif':    '仮定',
    'scenario.detail.value':         '観測値',
    'scenario.detail.llm_reasoning': 'LLM根拠',
    'scenario.detail.observed':      '観測時刻',
    'scenario.detail.lite_bias':     'LITEモード: LLMインテルとグローバルシグナルのみ使用。物理センサーおよび国別サイバーシグナルは取得されていません。非英語・非テキスト事象はスコアに反映されません。フォーカス中シナリオのTLと直接比較しないでください。',
    'scenario.detail.whatif_result': 'What-If結果:',
    'scenario.detail.whatif_reset':  'リセット',
    'scenario.btn.switch_focus':     'フォーカス切替',
    'scenario.btn.switch_focus_tip': 'このシナリオに全センサースコアリングを切り替え',
    'scenario.detail.indicators':    'インジケータ',
    'scenario.detail.active_countries': 'アクティブ国',
    'scenario.overlay.title':        'Layer 3 重み上書き',
    'scenario.overlay.edit':         '重み調整',
    'scenario.overlay.apply':        '適用',
    'scenario.overlay.reset':        'リセット',
    'scenario.overlay.close':        '閉じる',
    'scenario.overlay.active_badge': '適用中',
    'scenario.overlay.help':         'セッション限定の重み上書きによる仮説検証。変更は本セッションのみ反映され、タブを閉じると破棄されます。[0.0–1.0]の範囲外の値は拒否されます。',
    // Phase A-D: velocity, patterns, C-lite evaluation
    'scenario.pattern.silent_div':     'サイレント乖離',
    'scenario.pattern.silent_div_tip': 'サイレント乖離: サイバーと物理信号が活発だが情報ドメインの報道がない — 典型的な開戦前兆パターン',
    'scenario.pattern.ctx_align_tip':  'コンテキスト整合: 3軸以上（時間・空間・対象・方向）が収斂 — 偶然ではなく相関した信号',
    'scenario.eta_tip':                '現在の速度での次の脅威レベルへの推定到達時間',

    // §10.5 Pending Decisions (TL recalibration + ADR-015 dual-weight)

    // ══════════════════════════════════════════════════════════════
    // Login gate
    // ══════════════════════════════════════════════════════════════
    'login.error.required':            'ユーザー名とパスワードを入力してください',
    'login.error.failed':              'ログインに失敗しました',
    'login.error.connection':          '接続エラー',

    // ══════════════════════════════════════════════════════════════
    // Common UI labels
    // ══════════════════════════════════════════════════════════════
    'ui.loading':                      '読み込み中...',
    'ui.waiting_api':                  'APIテレメトリを待機中...',
    'ui.api_unavailable':              'API利用不可',
    'ui.none':                         'なし',
    'ui.saving':                       '保存中...',
    'ui.saved':                        '保存完了!',
    'ui.error':                        'エラー',

    // ══════════════════════════════════════════════════════════════
    // Sync / Dashboard
    // ══════════════════════════════════════════════════════════════
    'dash.changes_pending':            '変更あり。SYNCを押してください。',
    'climate.badge_prefix':            'CLIMATE',

    // ══════════════════════════════════════════════════════════════
    // Scenario Manager
    // ══════════════════════════════════════════════════════════════
    'scenario.mgr.no_scenarios':       'シナリオが見つかりません。',
    'scenario.mgr.err.id_required':    'IDが必要です',

    // ══════════════════════════════════════════════════════════════
    // Auto-tuning Wizard (Tier 4 commits 13-15)
    // ══════════════════════════════════════════════════════════════
    'wizard.title':                    'オートチューン提案',
    'wizard.loading':                  '提案を読み込み中...',
    'wizard.empty':                    '保留中の提案なし。',
    'wizard.disclaimer':               '本ツールの結論のみ — 最終判断は組織のプロセスによる。適用には明示的な確認が必要。',
    'wizard.tab.scenario_improver':    'Scenario Improver',  /* legacy alias */
    'wizard.tab.recall_positive':      'Recall+',
    'wizard.tab.recall_negative':      'Recall-',
    'wizard.tab.structure':            '構造',
    'wizard.tab.diagnostic':           '診断',
    'wizard.tab.sensor_disable':       'センサー無効化',
    'wizard.tab.drift':                'drift シグナル',
    'wizard.tab.discovery':            '探索',
    'wizard.diagnostic.empty':         '診断項目なし — システムは正常。',
    'wizard.diagnostic.note':          '診断提案は情報提供のみ。適用の経路はなく、却下のみ可能。',
    'wizard.recall_negative.note':     'recall を低下させる提案には、5 ソースによる厳格な休眠根拠 + 保護対象外の role + シナリオの活性が必要。適用には NP7 確認が必要。',
    'wizard.row.target':               '対象: {target}',
    'wizard.row.scenario':             'シナリオ: {scenario}',
    'wizard.row.formula_ref':          '式: {formula}',
    'wizard.row.sample_n':             'n={n}',
    'wizard.row.emitted_at':           '発行: {ago}',
    'wizard.row.recall_warning':       '⚠ recall 低下 — 確認が必要',
    'wizard.row.btn.apply':            '適用',
    'wizard.row.btn.dismiss':          '却下',
    'wizard.row.btn.defer':            '30d 延期',
    'wizard.row.btn.ack':              '確認済みにする',
    'wizard.row.btn.preview':          'プレビュー',
    'wizard.row.evidence_label':       '根拠:',
    'wizard.row.confidence':           '確信度 {value}',
    'wizard.row.confidence_low':       '確信度 低',
    'wizard.confirm.title':            '適用の確認（recall 低下を伴う変更）',
    'wizard.confirm.warn':             'この変更は recall を低下させる可能性がある。根拠を確認したうえで、適用を確定すること。',
    'wizard.confirm.cancel':           '取消',
    'wizard.confirm.apply':            '適用を確定',
    'wizard.confirm.success':          '適用した。',
    'wizard.confirm.failed':           '適用に失敗しました: {error}',
    'wizard.action.dismissed':         '却下した。',
    'wizard.action.deferred':          '30d 延期した。',
    'wizard.action.acknowledged':      '確認済みにした。',
    'wizard.action.failed':            '操作に失敗しました: {error}',
    'wizard.discovery.cluster':        'クラスタ #{idx}',
    'wizard.discovery.countries':      '国: {countries}',
    'wizard.discovery.centroid':       '重心: {centroid}',
    'wizard.discovery.annotation_kind': 'アノテーション: {kind}',
    'wizard.discovery.suggested_name': '提案名: {name}',
    'wizard.discovery.no_annotation':  '（LLM アノテーション未生成）',
    'wizard.discovery.shadow_mode':    'shadow モード',
    'wizard.discovery.production_mode': 'production モード',

    // ══════════════════════════════════════════════════════════════
    // Discovery panel (Tier 4 commit 15)
    // ══════════════════════════════════════════════════════════════
    'discovery.panel.title':           'シナリオ探索',
    'discovery.panel.empty':           '探索クラスタはまだない。',
    'discovery.panel.refresh':         '更新',
    'discovery.panel.run_id':          'run #{id}',
    'discovery.panel.eps':             'eps={eps}',
    'discovery.panel.min_samples':     'min_samples={n}',
    'discovery.panel.n_clusters':      'クラスタ {n} 件',
    'discovery.panel.btn.review':      'ウィザードで確認',
    'discovery.panel.btn.replay':      'リプレイ',
    'discovery.panel.replay_title':    '探索実行のリプレイ',

    // ══════════════════════════════════════════════════════════════
    // AP3 self-eval HUD chip (Tier 4 commit 16)
    // ══════════════════════════════════════════════════════════════
    'autotune.chip.title':             'オートチューン健全性',
    'autotune.chip.applied':           '適用済み {n} 件（7d）',
    'autotune.chip.pending':           '保留 {n} 件',
    'autotune.chip.drift':             'drift 未確認 {n} 件',
    'autotune.chip.recall_red':        'recall RED',
    'autotune.chip.recall_ok':         'recall 正常',
    'autotune.chip.open_wizard':       'ウィザードを開く',
    'tools.autotune_wizard':           'オートチューンウィザード',
    'tools.llm_features':              'LLM 機能',
    'tools.llm_routing':               'LLM モデルルーティング',

    // ──────────────────────────────────────────────────────────────────
    // Phase 9.3+9.4 — Settings shell + LLM Console
    // ──────────────────────────────────────────────────────────────────
    'settings.v2.title':               '設定',
    'settings.v2.search_ph':           '/ 検索…',
    'settings.llm.connection':         '接続',
    'settings.llm.intel_pipeline':     'インテルパイプライン',
    'settings.llm.features':           '機能',
    'settings.llm.routing':            'ルーティング',
    'settings.llm.embedding':          'Embedding モデル',
    'settings.llm.self_eval':          '自己評価',
    'settings.system.legacy':          'レガシー CONFIG',
    'settings.system.config':          'システム設定',
    'settings.audit.changes':          '変更監査',
    'settings.audit.decisions':        '判断履歴',
    'settings.audit.feedback':         'アナリストフィードバック',
    'settings.audit.auto_judge':       '自動判定ログ',
    // R3 — verb-based group labels
    'settings.operate.scope':          'スコープ / 既定値',
    'settings.operate.intel':          'インテルキュー',
    'settings.operate.corroboration':  '裏付け',
    'settings.operate.notifications':  '通知',
    'settings.operate.calibration':    '自動 Calibration',
    'settings.operate.sensors':        'センサー',
    'settings.operate.scenarios':      'シナリオ',
    'settings.tune.scoring':           '脅威スコアリング',
    'settings.tune.zscore':            'Z-score ベースライン',
    'settings.tune.sequence':          'シーケンスチェーン',
    'settings.tune.ddos':              'DDoS エンジン',
    'settings.tune.narrative':         'ナラティブバースト',
    'settings.tune.airspace':          '空域',
    'settings.tune.maritime':          '海洋 / ISR',
    'settings.tune.gdelt':             'GDELT',
    'settings.infra.network':          'ネットワーク / SSL',
    'settings.infra.cache':            'キャッシュ',
    'settings.infra.poll':             'ポーリング間隔',
    'settings.infra.server':           'サーバー / 起動',
    'settings.infra.plugins':          'プラグイン',
    'settings.infra.fetch_log':        '取得ログ',
    'settings.access.users':           'ユーザー / ロール',
    'settings.access.api_keys':        'API キー',
    'settings.access.webhooks':        'Webhook 設定',
    'settings.access.jwt':             'JWT ポリシー',
    'settings.access.admin':           '管理者初期設定',
    'settings.legacy.go':              '開く',
    // Phase 9.5 C17 — legacy tab ingestion labels
    'settings.sensors.catalog':        'センサーカタログ',
    'settings.sensors.fetch_log':      '取得ログ',
    'settings.infra.upstreams':        'アップストリーム',
    'settings.infra.fleet':            'センサー稼働状況',
    'settings.scenarios.list':         'シナリオ',
    'settings.operators.users':        'ユーザー / ロール',
    // Phase 9.5 C19 — tool deeplinks
    'settings.tools.tradecraft':       'トレードクラフトルール',
    'settings.tools.watchpane':        'センサーウォッチペイン',
    'settings.tools.autotune':         'オートチューンウィザード',
    'settings.tools.attention':        '注目度ルール',

    // ══════════════════════════════════════════════════════════════
    // LLM Feature Hub (commit J)
    // ══════════════════════════════════════════════════════════════
    'llm_features.title':              'LLM 機能ハブ',
    'llm_features.close':              '[ X ] 閉じる',
    'llm_features.loading':            '読み込み中…',
    'llm_features.disclaimer':         '本ツールの結論のみ — 最終判断は組織のプロセスによる。状態変更は監査ログに記録される（NP6）。',
    'llm_features.chip.title':         'LLM',
    'llm_features.chip.tip':           'LLM 機能が稼働中。クリックして管理する。',
    // Phase 8 (LLM survey v10) — model routing chip.
    'llm_routing.chip.title':          'MODEL',
    'llm_routing.chip.tip':            'LLM モデルルーティング — v10 スタックにおける primary モデルの可用性。',
    'llm_routing.save':                '保存',
    'llm_routing.reset':               'リセット',

    // ══════════════════════════════════════════════════════════════
    // CONTROLS Tools Hub redesign (commits L–P, 2026-04-29)
    // ══════════════════════════════════════════════════════════════
    'hud.btn.tools_hub':               'Open Tools Hub ⇲',     /* legacy */
    'controls.title':                  'ツールハブ',
    'controls.close':                  '[ X ] 閉じる',
    'controls.loading':                'ツールを読み込み中…',
    'controls.search_placeholder':     'ツールを検索…（/ でフォーカス、Esc で閉じる）',
    'controls.search_hint':            '/ でフォーカス · Esc で閉じる',
    'controls.no_match':               '該当するツールなし。',
    'controls.btn.open':               '開く',
    'controls.btn.open_tip':           'このパネルを開く（既に開いている場合は何もしない）',
    'controls.btn.close':              '閉じる',
    'controls.btn.close_tip':          'このパネルを閉じる',
    'controls.btn.dock_left_tip':      'このパネルを左サイドバーにドックする',
    'controls.btn.dock_right_tip':     'このパネルを右サイドバーにドックする',
    'controls.btn.float_tip':          'このパネルを切り離してフローティング表示する',
    'controls.btn.snooze':             '24h スヌーズ',
    'controls.btn.dismiss':            '却下',
    'controls.btn.apply_threshold':    '{value} を適用',
    'controls.section.intelligence':       'インテリジェンス',
    'controls.section.scenario_targeting': 'シナリオ・対象選定',
    'controls.section.simulation_analysis':'シミュレーション・分析',
    'controls.section.tradecraft':         'トレードクラフト',
    'controls.section.automation':         '自動化',
    'controls.section.admin':              '管理',
    'controls.section.suggestions':        '閾値の更新提案',

    'controls.tool.llm_intel.desc':    'アナリストのレビュー待ちの LLM 抽出インテル項目。',
    'controls.tool.dashboard.desc':    '攻撃元テレメトリのライブフィード。',
    'controls.tool.tg.desc':           'Telegram SIGINT ミラー — ナラティブのバースト、チャンネル活動。',
    'controls.tool.chain.desc':        'センサーと結論をまたぐ根拠チェーン。',
    'controls.tool.gn.desc':           'GreyNoise の IP レピュテーション照会とキャッシュ。',
    'controls.tool.target.desc':       '国別の可視性、センサーカバレッジ、脅威オーバーレイ。',
    'controls.tool.climate.desc':      '戦略環境ゲージ — 長期スパンのエスカレーション兆候。',
    'controls.tool.weather.desc':      'AOR の気象ブリーフと予報の確信度。',
    'controls.tool.whatif.desc':       'What-If シミュレーター — 入力を変動させて影響を観察する。',
    'controls.tool.spof.desc':         'センサーメッシュ全体の単一障害点分析。',
    'controls.tool.corr.desc':         'センサー相関ヒートマップ。',
    'controls.tool.tradecraft.desc':   'アナリスト向けトレードクラフト一式（判断台帳、仮説、…）。',
    'controls.tool.watchpane.desc':    'センサー監視パネル — 健全性の状態、ミュート、ノイズ分類。',
    'controls.tool.history.desc':      'トレンドとリプレイのための履歴分析（28 日ウィンドウ）。',
    'controls.tool.autotune.desc':     'オートチューンウィザード — 保留中の提案、drift シグナル、ディスカバリクラスタ。',
    'controls.tool.llm_features.desc': 'LLM 機能ハブ — どの AI 機能を有効にするかを制御する。',
    'controls.tool.llm_routing.desc':  'LLM モデルルーティング (v10) — 各 use_case が呼ぶモデル、三層オーバーライド（DB/env/code）、プリフライトの go/no-go。',
    'controls.tool.usrmgr.desc':       'ユーザーとロールの管理。',

};

// ============================================================
// i18n runtime — EN-only as of 2026-04-28
// ============================================================

/**
 * Translate a key with optional placeholder substitution.
 *   _t('map.popup.firms_code', { code: 'JP' }) → 'Code: JP'
 *
 * Single-language lookup against STRINGS. Returns the key itself when
 * missing (audited by scripts/check_i18n_keys.py — undefined refs are
 * caught at CI).
 */
function _t(key, vars) {
  let str = STRINGS[key];
  if (str === undefined) return key;  // last-resort: render the key
  if (vars) {
    Object.entries(vars).forEach(([k, v]) => {
      str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), v);
    });
  }
  return str;
}

/**
 * Apply translations to all data-i18n elements in the DOM.
 * Idempotent — safe to call multiple times.
 */
function _applyStaticTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const translated = _t(key);
    // Preserve child elements (e.g. cfg-restart-badge/cfg-live-badge spans):
    // only update the first direct text node instead of wiping all children.
    const firstText = Array.from(el.childNodes).find(n => n.nodeType === Node.TEXT_NODE);
    if (firstText) {
      firstText.textContent = translated;
    } else if (!el.childElementCount) {
      el.textContent = translated;
    } else {
      el.insertBefore(document.createTextNode(translated), el.firstChild);
    }
  });
  document.querySelectorAll('[data-i18n-html]').forEach(el => {
    const key = el.getAttribute('data-i18n-html');
    el.innerHTML = _t(key);
  });
  document.querySelectorAll('[data-i18n-tip]').forEach(el => {
    const key = el.getAttribute('data-i18n-tip');
    el.setAttribute('data-tooltip', _t(key));
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    const key = el.getAttribute('data-i18n-ph');
    el.setAttribute('placeholder', _t(key));
  });
}

// The INTEL GUIDE was bilingual (EN/JA blocks toggled by setGuideLang)
// until 2026-08-02. The UI is Japanese-only now, so the toggle, the
// `.guide-lang-en` blocks, and localStorage.guide_lang are all gone.
// See docs/design/ja-localization.md.

document.addEventListener('DOMContentLoaded', () => {
  _applyStaticTranslations();
});
