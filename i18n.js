/**
 * DDoS-Radar i18n — UI string dictionary (EN-only as of 2026-04-28)
 *
 * Policy: the UI is English-only. Browser auto-translation (Chrome / Edge /
 * Safari) handles label-level localisation on demand. Long-form analyst
 * reading content (INTEL GUIDE chapters in index.html#help-modal) keeps
 * a hand-curated bilingual EN/JA pair toggled by setGuideLang().
 *
 * Usage:
 *   _t('key')              → return the EN string for `key`
 *   _t('key', {n: 3})     → with {n} placeholder substitution
 *   setGuideLang('ja')    → switch INTEL GUIDE chapter visibility (guide-only,
 *                            does NOT affect the rest of the UI)
 *
 * Key naming convention: namespace.sub_namespace.key
 * Placeholder format:    {name} inside string values
 */

const STRINGS = {

    // ══════════════════════════════════════════════════════════════
    // NP7 Final-Judgment Disclaimer Banner (v2 conclusions API)
    // ══════════════════════════════════════════════════════════════
    'banner.np7.fallback':            'Tool conclusion only — final judgment by organizational process.',

    // ══════════════════════════════════════════════════════════════
    // Conclusion Cards (Layer 1 — v2 conclusions envelope renderer)
    // See docs/design/v2-ui.md §4
    // ══════════════════════════════════════════════════════════════
    'cc.title.threat_level':          'Threat Level',
    'cc.title.trend':                 'Trend',
    'cc.title.per_domain':            'Per-Domain',
    'cc.title.anomaly':               'Top Anomaly',
    'cc.title.attack_mode':           'Attack Mode',
    'cc.label.confidence':            'conf',
    'cc.label.unavailable':           'Unavailable',
    'cc.label.insufficient_data':     'INSUFFICIENT_DATA',
    'cc.label.insufficient_history':  'INSUFFICIENT_HISTORY',
    'cc.label.no_active':             'NO ACTIVE',
    'cc.label.tentative':             'TENTATIVE',
    'cc.label.degraded':              'DEGRADED',
    'cc.label.calibration_pending':   'CALIBRATION_PENDING',
    'cc.label.sensor_degraded':       'SENSOR_DEGRADED',
    'cc.label.upstream_failure':      'UPSTREAM_FAILURE',
    'cc.btn.drill':                   'drill ▶',
    'cc.btn.drill_tooltip':           'Open derivation: formula, thresholds, sources, LLM prompt (NP6)',
    'cc.btn.export_md':               'Export Markdown',
    'cc.btn.export_md_tooltip':       'Download all conclusions for this scenario as a single .md report',
    'cc.horizon.short':               '24h',
    'cc.horizon.medium':              '7d',
    'cc.horizon.long':                '30d',
    'cc.domain.cyber':                'Cyber',
    'cc.domain.physical':             'Physical',
    'cc.domain.info':                 'Info',
    'cc.tl.prefix':                   'TL',
    'cc.scoring_mode.full':           'full',
    'cc.scoring_mode.lite':           'C-lite',
    'cc.calib.sample_n':              'sample n={n}',
    'cc.calib.no_data':               'no calibration data yet',
    'cc.empty.waiting':               'Waiting for first scoring cycle…',
    'cc.error.fetch_failed':          'Failed to fetch conclusions',
    'cc.tip.np7':                     'Tool conclusion only — organizational process holds the final call.',

    // Drill-down modal (Layer 2 — audit_trace)
    'drill_modal.title':              'Conclusion Audit Trace',
    'drill_modal.close':              '[ X ] Close',
    'drill_modal.loading':            'Loading audit trace…',
    'drill_modal.error.fetch_failed': 'Failed to fetch audit trace ({status})',
    'drill_modal.error.network':      'Network error while fetching audit trace',
    'drill_modal.section.header':     'Conclusion',
    'drill_modal.section.disclaimer': 'NP7 Disclaimer',
    'drill_modal.section.formula':    'Formula reference',
    'drill_modal.section.thresholds': 'Threshold reference',
    'drill_modal.section.calibration':'Calibration status',
    'drill_modal.section.sources':    'Primary sources',
    'drill_modal.section.metadata':   'Metadata',
    'drill_modal.section.rationale_matrix': 'Rationale matrix',
    'drill_modal.section.llm_prompt': 'LLM prompt',
    'drill_modal.label.scenario':     'Scenario',
    'drill_modal.label.observed_at':  'Observed at',
    'drill_modal.label.conclusion_id':'Conclusion ID',
    'drill_modal.label.confidence':   'Confidence',
    'drill_modal.empty.formula':      'No formula reference recorded',
    'drill_modal.empty.thresholds':   'No threshold values recorded',
    'drill_modal.empty.calibration':  'No calibration status recorded',
    'drill_modal.empty.sources':      'No primary sources recorded',
    'drill_modal.empty.metadata':     'No metadata recorded',
    'drill_modal.empty.rationale_matrix': 'No contributing signals recorded',
    'drill_modal.rationale.col.sensor':       'Sensor',
    'drill_modal.rationale.col.domain':       'Domain',
    'drill_modal.rationale.col.country':      'Country',
    'drill_modal.rationale.col.contribution': 'Contribution',
    'drill_modal.rationale.col.formula':      'Formula trace',
    'drill_modal.rationale.col.evidence':     'Evidence',
    'drill_modal.calib.sample_size':  'Sample size',
    'drill_modal.calib.status':       'Status',
    'drill_modal.calib.last_updated': 'Last updated',
    'drill_modal.calib.warn_low_n':   'Sample size below threshold — calibration is tentative',
    'drill_modal.llm.missing':        'Prompt text not retained (predates prompt-store or purged)',
    'drill_modal.llm.no_prompt':      'No LLM prompt was used for this conclusion',
    'drill_modal.llm.model':          'Model',
    'drill_modal.llm.temperature':    'Temperature',
    'drill_modal.llm.use_count':      'Use count',
    'drill_modal.llm.first_seen':     'First seen',
    'drill_modal.llm.last_seen':      'Last seen',
    'drill_modal.llm.expand':         'Show full prompt',
    'drill_modal.llm.collapse':       'Hide prompt',
    'drill_modal.llm.sha256':         'SHA-256',
    'drill_modal.section.feedback':       'Analyst feedback',
    'drill_modal.feedback.legend':        'Label this conclusion (ground truth):',
    'drill_modal.feedback.label.TRUE_POSITIVE':  'True Positive — real escalation, correctly flagged',
    'drill_modal.feedback.label.FALSE_POSITIVE': 'False Positive — flagged but no real escalation',
    'drill_modal.feedback.label.TRUE_NEGATIVE':  'True Negative — correctly not flagged',
    'drill_modal.feedback.label.FALSE_NEGATIVE': 'False Negative — missed real escalation',
    'drill_modal.feedback.url_placeholder':   'Observed outcome URL (ACLED/GDELT/news, optional)',
    'drill_modal.feedback.notes_placeholder': 'Notes (optional, max 2000 chars)',
    'drill_modal.feedback.submit':            'Submit feedback',
    'drill_modal.feedback.summary_meta':      'Total: {total} • Distinct analysts: {distinct}',
    'drill_modal.feedback.summary_empty':     'No feedback yet for this conclusion.',
    'drill_modal.feedback.disabled':          'Feedback unavailable for unsaved conclusions.',
    'drill_modal.feedback.status.no_label':   'Choose a label first.',
    'drill_modal.feedback.status.submitting': 'Saving…',
    'drill_modal.feedback.status.saved':      'Feedback saved.',
    'drill_modal.feedback.status.bad_label':  'Server rejected the label.',
    'drill_modal.feedback.status.failed':     'Save failed (HTTP {status}).',
    'drill_modal.feedback.status.network':    'Network error — try again.',

    'drill_modal.section.llm_aug':            'LLM augmentation',
    'drill_modal.llm_aug.empty':              'No LLM augmentation for this conclusion.',
    'drill_modal.llm_aug.attempted':          'LLM call attempted',
    'drill_modal.llm_aug.failed':             'failed ({error})',
    'drill_modal.llm_aug.agreement':          'Agreement',
    'drill_modal.llm_aug.suggested_alt':      'Suggested alternative',
    'drill_modal.llm_aug.conf_adj':           'Confidence nudge',

    // Sensor Watchpane (Layer 3)
    'watchpane.title':                'Sensor Watchpane',
    'hud.coord.toggle.label':         'Coord links',
    'hud.coord.toggle.tip':           'Coordination link visibility on the map. Powered by the IDF-weighted overlap (calculate_overlap_idf): ubiquitous global ASNs (Cloudflare/AWS/etc.) are suppressed and only rare ASN co-occurrence is scored, so peacetime baseline reads close to 0 and elevated values reflect genuinely shared infrastructure.\nOFF: hide all links (current default — cleanest map).\nSTRONG: pairs with coordIdx ≥ 1.5 (≈P95) — analyst-actionable, top ~5%.\nALL: every pair above the noise floor (≥ 0.5) — full picture.',
    'hud.coord.mode.all':             'ALL',
    'hud.coord.mode.strong':          'STRONG',
    'hud.coord.mode.off':             'OFF',
    'watchpane.btn.add':              '+ Add sensor',
    'watchpane.empty':                'No sensors selected. Click + Add sensor to start.',
    'watchpane.tag.history_shallow':  'history shallow',
    'watchpane.tip.history_shallow':  'At least one pinned sensor has fewer than 2 stored observations yet — its sparkline shows only the current cycle. The 1h series fills in over the next few scoring ticks.',
    'watchpane.col.sensor':           'Sensor',
    'watchpane.col.scope':            'Scope',
    'watchpane.col.value':            'Value',
    'watchpane.col.delta':            '1h Δ',
    'watchpane.scope.focused':        'focused',
    'watchpane.scope.global':         'global',
    'watchpane.row.remove':           'Remove',
    'watchpane.row.no_data':          'no data this cycle',
    'watchpane.row.suppressed':       'suppressed',
    'watchpane.row.fired':            'FIRED',
    'watchpane.row.normal':           'NORMAL',
    'watchpane.row.fetch_error':      'fetch error',
    'watchpane.add.title':            'Add sensor',
    'watchpane.add.search_ph':        'Filter sensors…',
    'watchpane.add.no_match':         'No sensors match',
    'watchpane.add.already_added':    'already added',
    'watchpane.alarm.title':          'Alarm condition',
    'watchpane.alarm.btn.tip_unset':       'No alarm — click to set a condition',
    'watchpane.alarm.btn.tip_configured':  'Alarm configured',
    'watchpane.alarm.label.field':    'Field',
    'watchpane.alarm.label.op':       'Operator',
    'watchpane.alarm.label.value':    'Value',
    'watchpane.alarm.label.notify':   'Send Web Notification on transition',
    'watchpane.alarm.field.score':    'score (latest)',
    'watchpane.alarm.field.value':    'raw value',
    'watchpane.alarm.field.delta':    'Δ vs baseline',
    'watchpane.alarm.field.status':   'status',
    'watchpane.alarm.btn.clear':      'Clear',
    'watchpane.alarm.btn.save':       'Save',
    'watchpane.alarm.error.invalid':  'Invalid value — enter a number (or pick a status)',
    'watchpane.alarm.hint':           'Fires when the latest observation matches the condition. Notification fires once per false→true edge (suppressed while continuously active).',
    'watchpane.notify.title':         'Sensor alarm',

    // ══════════════════════════════════════════════════════════════
    // HUD — top bar
    // ══════════════════════════════════════════════════════════════
    'hud.btn.sync':                   'SYNC',
    'hud.btn.chain':                  'CHAIN',
    'hud.btn.tools':                  'TOOLS ▾',
    'hud.btn.report':                 'REPORT ▾',
    'hud.btn.sitrep':                 'SITREP',
    'hud.btn.evidence':               'EVIDENCE',
    'hud.btn.salute':                 'SALUTE',
    'hud.btn.export_md':              'EXPORT MD',
    'hud.btn.intel_guide':            'Intel Guide',
    'hud.btn.config':                 'Config',
    'hud.diag.label':                 'DIAG',
    'hud.tooltip.settings_menu':      'Settings — Intel Guide / Config',
    'hud.discrepancy_alert':          '! DISCREPANCY DETECTED: POSSIBLE MASKIROVKA',

    // ── scenario chip (Row 1 SITUATION) ───────────────────────────
    'hud.scenario.label':             'SCENARIO',
    'hud.scenario.none':              '—',
    'hud.tooltip.scenario':           'Focused scenario — click to switch focus from the Scenario Bar',

    // ── convergence label (JS-generated) ──────────────────────────
    'hud.convergence.full':           '⚡ FULL CONVERGENCE',
    'hud.convergence.dual':           '⚠ DUAL DOMAIN',
    'hud.convergence.single':         '◉ SINGLE DOMAIN',
    'hud.convergence.none':           'CONVERGENCE: —',
    'hud.label.threat_24h':           'THREAT 24h:',
    'hud.tooltip.threat_24h':         'Threat Level History (last 24 hours / 288 cycles)',
    'hud.label.convergence_short':    'CVG:',

    // ── vector buttons ────────────────────────────────────────────
    'hud.vec.all':                    'ALL VECTORS',
    'hud.vec.l3':                     'L3 VOLUMETRIC',
    'hud.vec.l7':                     'L7 APPLICATION',

    // ── bottom row labels ─────────────────────────────────────────
    'hud.label.overlap':              'Coord:',
    'hud.label.l7_shift':             'L7 Shift:',
    'hud.label.strikes':              'Strikes:',
    'hud.label.bgp':                  'BGP:',
    'hud.label.multi_front':          'Multi-Front:',
    'hud.label.velocity':             'VELOCITY:',
    'hud.tooltip.velocity':           'Rate of Escalation (1st derivative of threat score). Destroys Normalcy Bias by showing DIRECTION of change.',
    'hud.ambush.text':                '⚡ AMBUSH',
    'hud.tooltip.ambush':             'Ambush Pattern: 2nd derivative Z-Score spike indicating exponential escalation.',
    'hud.label.blockade':             'BLOCKADE',
    'hud.tooltip.blockade':           'Blockade Index = DDoS Intensity / Network Reachability. Distinguishes Political Noise from Real Infrastructure Neutralization.',
    'hud.label.survival':             'SURVIVAL:',
    'hud.tooltip.survival':           'SURVIVAL: Check-Host.net real liveness check for key infrastructure. OK=all nodes reachable / PARTIAL=partial outage / BLACKOUT=all nodes unreachable',
    'hud.label.c2sync':               'C2-SYNC:',
    'hud.tooltip.c2sync':             'C2 SYNC: Multiple theater attack onsets converge within 60 s → evidence of nation-state command and control',
    'hud.label.chain':                'CHAIN:',
    'hud.tooltip.chain_hud':          'Escalation Sequence Chain: Evidence chain of Narrative→ISR→DDoS→Kinetic within 24h window.',
    'hud.label.comms':                'COMMS:',
    'hud.label.triangulation':        'TRI:',
    'hud.tooltip.triangulation':      'TRIANGULATION: All 3 domains (Cyber/Physical/Info) independently confirm anomalous activity — highest confidence convergence.',
    'hud.label.silent_div':           'SILENT:',
    'hud.tooltip.silent_div':         'SILENT DIVERGENCE: Cyber+Physical domains active but Info domain silent — possible pre-conflict reconnaissance/preparation.',
    'hud.label.baseline':             'Z-30D',
    'hud.tooltip.baseline':           'BASELINE: Theater-specific Z-score showing how current score compares to 30-day historical average for this theater.',
    'hud.label.sys':                  'SENSOR',
    'hud.tooltip.sys_chip':           'System status: WS link + sensor fleet health (OK / STALE / ERROR / DISABLED)',
    'hud.label.climate':              'CLIMATE',
    'hud.tooltip.tl_proximity':       'TL Proximity: distance from current score to next Threat Level boundary',
    'tl_prox.near_esc':               '{pts}pt → TL{tl}',
    'tl_prox.near_deesc':             '{pts}pt → TL{tl}',
    'tl_prox.tooltip_up':             '{pts} points to escalation (TL{tl})',
    'tl_prox.tooltip_down':           '{pts} points to de-escalation (TL{tl})',
    // ── HUD redesign additions ────────────────────────────────────
    'hud.tooltip.tl_duration':        'Time spent at the current Threat Level (counters normalcy bias — long stays at elevated TL deserve scrutiny)',
    'hud.label.eta':                  'ETA',
    'hud.tooltip.eta':                'ETA: projected time to next TL boundary based on current velocity. Suppressed when velocity is too small to be meaningful.',
    'hud.eta.tooltip_up':             '{pts}pt → TL{tl}, est. ~{eta} at current rate',
    'hud.eta.tooltip_down':           '{pts}pt → TL{tl} (de-esc), est. ~{eta} at current rate',
    'hud.label.hod_z':                'Z-HOD',
    'hud.tooltip.hod_z':              'Hour-of-Day Z-score: deviation vs. the same hour over the past 7+ days (corrects time-of-day bias in the BASE-Z chip)',
    'hud.hod_z.detail':               'z = {z} σ over n={n} same-hour samples',
    'hud.label.intel':                'INTEL',
    'hud.tooltip.intel_corrob':       'Intel Corroboration: active LLM-confirmed intel items in 24h for the focused scenario. Click to open the LLM Intelligence panel.',
    'hud.intel.detail':               '{active} active items (24h)  ·  +{fresh} new in last hour',
    'hud.label.bg_alert':             'BG',
    'hud.tooltip.bg_alert':           'Background scenario rising fast — click to open detail panel.',
    'hud.bg_alert.detail':            '{name} +{delta} pt in last hour (background)',
    'hud.tooltip.split_tag':          'Adversary contribution / Target contribution to this domain. Imbalance hints at offensive vs defensive posture.',
    // ── Hamburger control panel ──────────────────────────────────
    'hud.tooltip.hamburger':          'Open Controls Menu (vector / sync / tools / reports / settings / language / user)',
    'hud.hh.title':                   'CONTROLS',
    'hud.hh.section.vector':          'VIEW VECTOR',
    'hud.hh.section.data':            'DATA',
    'hud.hh.section.reports':         'REPORTS',
    'hud.hh.section.settings':        'SETTINGS',
    'hud.hh.section.language':        'LANGUAGE',
    'hud.hh.section.tools':           'TOOLS & PANELS',
    'hud.tooltip.comms':              'COMMS: GREEN=All sensors live / ORANGE=Abnormal silence detected — possible sensor suppression or pre-op comms blackout',
    'hud.domain.cyber':               'Cyber',
    'hud.tooltip.domain_cyber':       'Cyber domain score',
    'hud.domain.physical':            'Physical',
    'hud.tooltip.domain_physical':    'Physical domain score',
    'hud.domain.info':                'Info',
    'hud.tooltip.domain_info':        'Info domain score',
    'hud.tooltip.domain_expand':      'Click to expand per-sensor score breakdown',
    'dd.hint':                        'Click sensor row → focus on map  ·  ⊙ = zoom to sensor position',
    'dd.btn.focus_map':               'Zoom to sensor on map',

    // ── C2 sync (JS-generated) ────────────────────────────────────
    'hud.c2sync.detected':            'DETECTED (+{n}pt)',
    'hud.c2sync.partial':             'PARTIAL ({pct}%)',
    'hud.c2sync.no_sync':             'NO SYNC',

    // ── chain badge (JS-generated) ────────────────────────────────
    'hud.chain.full':                 '✔ FULL',
    'hud.chain.partial':              '≈ PARTIAL',

    // ── velocity (JS-generated) ───────────────────────────────────
    'hud.velocity.stable':            'STABLE',
    'hud.velocity.unit':              '/cycle',

    // ══════════════════════════════════════════════════════════════
    // TOOLS dropdown
    // ══════════════════════════════════════════════════════════════
    'tools.target_visibility':        'Target Visibility',
    'tools.live_threat_telemetry':    'Attack Origin Feed',
    'tools.evidence_chain':           'Evidence Chain',
    'tools.telegram_sigint':          'Telegram SIGINT',
    'tools.weather_brief':            'Weather Brief',
    'tools.salute_export':            'SALUTE Export',
    'tools.greynoise':                'GreyNoise',

    // ══════════════════════════════════════════════════════════════
    // Panel — common
    // ══════════════════════════════════════════════════════════════
    'panel.common.dock':              'Dock',
    'panel.common.dock_tooltip':      'Snap back to sidebar',
    'panel.common.minimize_tooltip':  'Minimize',
    'panel.common.close_tooltip':     'Close',

    // ══════════════════════════════════════════════════════════════
    // Panel — Target Visibility
    // ══════════════════════════════════════════════════════════════
    'panel.target.title':             'Target Visibility',
    'panel.target.hint':              'Participants of the focused scenario. Edit via Admin → Scenarios.',

    // ══════════════════════════════════════════════════════════════
    // Panel — Attack Origin Feed
    // ══════════════════════════════════════════════════════════════
    'panel.dashboard.title':          'Attack Origin Feed',
    'panel.dashboard.waiting':        'Waiting for API telemetry...',

    // ══════════════════════════════════════════════════════════════
    // Footer / status bar
    // ══════════════════════════════════════════════════════════════
    'footer.system_init':             'System Initializing...',
    'status.syncing':                 'SYNCING...',
    'status.sync_done':               'Data Synced: {time} (Next in 15 min)',
    'status.pending':                 'Changes pending. Press SYNC.',
    'status.init_complete':           '> Initialization Complete. Rendering Dashboard.',

    // ══════════════════════════════════════════════════════════════
    // Settings modal
    // ══════════════════════════════════════════════════════════════
    'modal.settings.title':           'Master Configuration',
    'modal.settings.close':           '[ X ] Close',
    'modal.settings.tab.sensors':     'Sensors',
    'modal.settings.tab.fetchlog':    'Fetch Log',
    'modal.settings.tab.upstreams':   'Upstreams',
    'modal.settings.tab.fleet':       'Fleet Health',
    'modal.settings.tab.sysconfig':   'System',
    'modal.settings.tab.users':       'Users',

    // ── Fleet Health tab ───────────────────────────────────────────
    'modal.fleet.help':               'Per-sensor fleet status: circuit-breaker state, cache freshness, recent reliability, last error. Surfaces the same /api/admin/sensor_health data the HUD dots summarize, with full per-sensor detail and quota/rate-limit visibility.',
    'modal.fleet.refresh_btn':        '\u21bb Refresh',
    'modal.fleet.loading':            'Loading...',
    'modal.fleet.window_label':       'Window:',
    'modal.fleet.filter_label':       'Domain:',
    'modal.fleet.filter.all':         'All',
    'fleet.summary':                  'Total {total} · OK {ok} · Degraded {degraded} · Stale {stale} · Error {err} · CB Open {cb} · Disabled {off}',
    'fleet.col.health':               'Health',
    'fleet.col.cb':                   'CB',
    'fleet.col.cache_age':            'Cache Age',
    'fleet.col.reliability':          'Reliability',
    'fleet.col.last_error':           'Last Error',
    'fleet.col.poll':                 'Poll',
    'fleet.no_error':                 '—',
    'fleet.never_fetched':            'never',
    'fleet.cb.open':                  'OPEN',
    'fleet.cb.half_open':             'HALF',
    'fleet.cb.closed':                'CLOSED',
    'fleet.empty_filter':             'No sensors match the selected domain filter.',
    'fleet.load_error':               'Failed to load fleet health: {msg}',
    'fleet.last_refreshed':           'Last refreshed: {time}',

    // ── Upstreams tab ──────────────────────────────────────────────
    'modal.upstreams.help':           'Shows the per-upstream-source health for sensors that aggregate multiple feeds (currently CT Log: certstream push + certspotter pull + crt.sh fallback). Lets you answer "is the actual data feed alive?" without inferring it from sensor-level fetch logs.',
    'modal.upstreams.refresh_btn':    '\u21bb Refresh',
    'modal.upstreams.loading':        'Loading...',
    'upstreams.empty':                'No multi-source sensors are reporting upstream health.',
    'upstreams.no_failures':          'No failures',
    'upstreams.last_msg':             'Last message',
    'upstreams.mode_counters':        'Mode counters',
    'upstreams.never':                'never',
    'upstreams.last_refreshed':       'Last refreshed: {time}',
    'upstreams.load_error':           'Failed to load upstream health: {msg}',
    'upstreams.poll':                 'Poll',
    'upstreams.buffer':               'Buffer',
    'upstreams.field.running':                'Running',
    'upstreams.field.messages_total':         'Messages total',
    'upstreams.field.matches_total':          'Matches total',
    'upstreams.field.connect_count':          'Connects',
    'upstreams.field.watched_domains':        'Watched domains',
    'upstreams.field.heartbeat_budget_sec':   'Heartbeat budget (s)',
    'upstreams.field.liveness_budget_sec':    'Liveness budget (s)',
    'upstreams.field.observation_count_24h':  'Observations (24h)',
    'upstreams.field.queries_made':           'Queries made',
    'upstreams.field.rate_limit_remaining':   'Rate limit remaining',
    'upstreams.coverage.title':       'Watched apex coverage',
    'upstreams.coverage.stalest':     'Stalest watched apexes',
    'upstreams.coverage.no_data':     'No coverage data yet',

    // ── System Config tab ──────────────────────────────────────────────
    'sysconfig.help':                 'Edit <span class="code-block">config.env</span> settings. Changes are written to disk immediately. <span class="cfg-live-badge">live</span> settings take effect instantly; <span class="cfg-restart-badge">restart</span> settings require <code>docker compose restart</code>.',
    'sysconfig.section.api_keys':     'API Keys',
    'sysconfig.section.scope':        'Default Focus',
    'sysconfig.scope.desc':           'Startup default for the focused scenario. Participants and adversaries are managed in the Scenarios tab.',
    'sysconfig.field.default_focused_scenario': 'Default Focused Scenario',
    'sysconfig.adv_toggle':           '\u25b6 Advanced Settings',
    'sysconfig.adv_toggle_open':      '\u25bc Advanced Settings',
    'sysconfig.adv_warning':          '\u26a0 Incorrect values may cause system malfunction. Change only if you understand the impact.',
    'sysconfig.section.network':      'Network / SSL',
    'sysconfig.field.ssl_enabled':    'Enabled',
    'sysconfig.field.ssl_disabled':   'Disabled',
    'sysconfig.section.cache':        'Cache &amp; Polling',
    'sysconfig.field.cache_expiry':   'Cache Expiry (seconds)',
    'sysconfig.field.opensky_int':    'OpenSky Min Interval (seconds)',
    'sysconfig.field.narrative_int':  'Narrative Poll Interval (seconds)',
    'sysconfig.field.telegram_int':         'Telegram Poll Interval (seconds)',
    'sysconfig.field.telegram_kw':          'Telegram Attack Keywords',
    'sysconfig.field.telegram_conf_thresh': 'Telegram Claim Confidence Threshold',
    'sysconfig.field.checkhost_int':        'Check-Host Poll Interval (seconds)',
    'sysconfig.field.checkhost_to':   'Check-Host Timeout (ms)',
    'sysconfig.field.checkhost_nodes':'Check-Host Nodes',
    'sysconfig.section.threat':       'Threat Scoring',
    'sysconfig.field.air_anomaly':    'Airspace Anomaly Threshold (ratio)',
    'sysconfig.field.air_closure':    'Airspace Closure Threshold (ratio)',
    'sysconfig.field.air_window':     'Airspace Baseline Window (cycles)',
    'sysconfig.field.gdelt_tone':     'GDELT Tone Alert Threshold',
    'sysconfig.field.gdelt_history':  'GDELT History Window (days)',
    'sysconfig.field.conv_dual':      'Dual Convergence Bonus',
    'sysconfig.field.conv_full':      'Full Convergence Bonus',
    'sysconfig.field.hysteresis':     'Threat Level Hysteresis Cycles',
    'sysconfig.section.ddos':         'DDoS Acceleration Engine',
    'sysconfig.field.ambush_z':       'Ambush Z-Score Threshold',
    'sysconfig.field.deriv_window':   'Velocity Derivative Window (cycles)',
    'sysconfig.field.sync_delta':     'C2 Sync Delta (ms)',
    'sysconfig.field.sync_threshold': 'C2 Sync Score Threshold (0\u20131)',
    'sysconfig.section.narrative':    'Narrative Burst Detector',
    'sysconfig.field.narr_alert_z':   'Narrative Alert Z-Score',
    'sysconfig.field.narr_crit_z':    'Narrative Critical Z-Score',
    'sysconfig.field.narr_baseline':  'Narrative Baseline Days',
    'sysconfig.section.chain':        'Sequence Chain',
    'sysconfig.field.chain_window':   'Chain Window (seconds)',
    'sysconfig.field.chain_full':     'Full Chain Bonus Points',
    'sysconfig.field.chain_partial':  'Partial Chain Bonus Points',
    'sysconfig.section.maritime':     'Maritime / ISR Sensors',
    'sysconfig.field.ais_dark_gap':   'AIS Dark Gap Threshold (seconds)',
    'sysconfig.field.ais_anchor':     'AIS Anchor Detection Radius (km)',
    'sysconfig.field.isr_surge':      'ISR Surge Threshold (aircraft)',
    'sysconfig.field.isr_icao':       'ISR ICAO Type Codes',
    'sysconfig.field.gps_jam':        'GPS Jamming Threshold',
    'sysconfig.field.gps_jam_crit':   'GPS Jamming Critical Threshold',
    'sysconfig.field.ct_log_surge':   'CT Log Surge Threshold',
    'sysconfig.field.usgs_mag':       'USGS Min Magnitude',
    'sysconfig.field.dw_cyber':       'Domain Weight — Cyber (0–1)',
    'sysconfig.field.dw_physical':    'Domain Weight — Physical (0–1)',
    'sysconfig.field.dw_info':        'Domain Weight — Info (0–1)',
    'sysconfig.help.domain_weights':  'Three weights must sum to 1.0',
    'sysconfig.save_btn':             'Save to config.env',
    'sysconfig.restart_note':         '\u26a0 Some settings require server restart (docker compose restart)',
    'sysconfig.section.llm':          'LLM Intelligence',
    'sysconfig.help.llm_desc':        'Requires Ollama running locally. Inside Docker on Mac/Windows use host.docker.internal as the hostname.',
    'sysconfig.field.llm_enabled':    'LLM Enabled',
    'sysconfig.field.llm_host':       'Ollama Host',
    'sysconfig.field.llm_model':      'Model',
    'sysconfig.field.llm_timeout':    'Request Timeout (s)',
    'sysconfig.section.llm_thresholds': 'Intel Queue Thresholds',
    'sysconfig.field.llm_auto_threshold': 'Auto-Confirm Threshold',
    'sysconfig.help.llm_auto_threshold':  'Confidence \u2265 this \u2192 AUTO-CONFIRMED (no analyst review needed)',
    'sysconfig.field.llm_min_confidence': 'Min Confidence',
    'sysconfig.help.llm_min_confidence':  'Items below this are silently discarded',
    'sysconfig.field.llm_override_window': 'Override Window (s)',
    'sysconfig.help.llm_override_window':  'Seconds within which AUTO-CONFIRMED items can be overridden',
    'sysconfig.field.llm_pending_auto_reject': 'Auto-Reject Pending After (h)',
    'sysconfig.help.llm_pending_auto_reject':  'Hours until unreviewed PENDING items are auto-rejected (0 = disabled)',
    'sysconfig.field.intel_retention': 'Intel Retention (days)',
    'sysconfig.field.intel_age_decay_enabled': 'Age-Decay Enabled (ADR-023)',
    'sysconfig.help.intel_age_decay_enabled':  'Exponentially decay confirmed intel contributions by age (smooths confirm/TTL cliffs)',
    'sysconfig.field.intel_age_decay_tau':     'Age-Decay \u03c4 (hours)',
    'sysconfig.help.intel_age_decay_tau':      'Time constant: weight=1/e at age=\u03c4, ~0.14 at 2\u00b7\u03c4, ~0.05 at 3\u00b7\u03c4. Default 12h \u2248 1 work cycle',
    'sysconfig.llm.fetch_models':     'Fetch Models \u21ba',
    'sysconfig.llm.fetching':         'Fetching...',
    'sysconfig.llm.no_models':        'No models found — is Ollama running?',
    'sysconfig.llm.models_loaded':    '\u2713 {n} model(s) loaded',
    'sysconfig.llm.fetch_error':      '\u2717 {msg}',
    'sysconfig.llm.model_hint':       'Click "Fetch Models" to load from Ollama, or type manually.',




    'modal.sensors.help':             'Enable or disable individual sensor modules. <b>Cyber</b> = network threats, <b>Physical</b> = infrastructure & airspace, <b>Info</b> = information & influence operations.',
    'modal.sensors.help_graceful':    'Disabled sensors contribute zero to their domain score (Graceful Degradation).',
    'modal.sensors.loading':          'Loading sensor status...',

    'modal.fetchlog.help':            'Shows the last fetch result for each sensor from its external API.',
    'modal.fetchlog.stale_note':      'Cache age exceeding 3× the poll interval is flagged as <b>STALE</b>.',
    'modal.fetchlog.refresh_btn':     '↻ Refresh',
    'modal.fetchlog.loading':         'Loading...',

    'modal.minimap.region_preview':   'Region Preview',
    'modal.minimap.legend.core':      '◆ Core',
    'modal.minimap.legend.link':      '◆ Participant',
    'modal.minimap.legend.adversary': '◆ Adversary',

    // ══════════════════════════════════════════════════════════════
    // Country Intel modal
    // ══════════════════════════════════════════════════════════════
    'modal.country.title_prefix':     'Country Intel',
    'modal.country.close':            '[ X ] Close',

    // ══════════════════════════════════════════════════════════════
    // SITREP modal
    // ══════════════════════════════════════════════════════════════
    'modal.sitrep.title':             'Situation Report (SITREP) — Threat Level Assessment',
    'modal.sitrep.close':             '[ X ] Close',
    'modal.sitrep.timeline_label':    'THREAT LEVEL Timeline (last 288 cycles)',
    'modal.sitrep.report_label':      'Auto-generated Report',

    // ══════════════════════════════════════════════════════════════
    // Evidence modal
    // ══════════════════════════════════════════════════════════════
    'modal.evidence.title':           'Analytic Rationale — Evidence Panel',
    'modal.evidence.close':           '[ X ] Close',
    'modal.evidence.section_convergence': 'Convergence Score Breakdown',
    'modal.evidence.section_assessment':  'System Assessment',
    'modal.evidence.section_rationale':   'Sensor Rationale Matrix',
    'modal.evidence.th_sensor':       'Sensor',
    'modal.evidence.th_domain':       'Domain',
    'modal.evidence.th_status':       'Status',
    'modal.evidence.th_observed':     'Observed Value',
    'modal.evidence.th_score':        'Score',
    'modal.evidence.th_confidence':   'Confidence',
    'modal.evidence.th_reason':       'Fired Reason / Note',
    'modal.evidence.noise_filters':   'Noise filters applied:',
    'modal.evidence.btn_salute':      'Export SALUTE Report',
    'modal.evidence.btn_sitrep':      'View SITREP',
    'modal.evidence.no_filters':      'None',
    'modal.evidence.system_note_label': 'System Note',
    'modal.evidence.convergence_score': 'Convergence Score:',

    // ══════════════════════════════════════════════════════════════
    // Intel Guide modal
    // ══════════════════════════════════════════════════════════════
    'modal.help.title':               'Intelligence Operations Guide — MDO C4ISR Strategic Radar',
    'modal.help.close':               '[ X ] Close',
    'modal.help.ch1':                 '1. Sensors',
    'modal.help.ch2':                 '2. Map',
    'modal.help.ch3':                 '3. Score',
    'modal.help.ch4':                 '4. Threat Lv.',
    'modal.help.ch5':                 '5. Calibration',
    'modal.help.ch6':                 '6. Workflow',
    'modal.help.ch7':                 '7. Config',
    'modal.help.ch8':                 '8. Intuition UI',
    'modal.help.ch9':                 '9. API Reference',
    'modal.help.ch10':                '10. Admin',
    'modal.help.ch11':                '11. Limitations',
    'modal.help.ch12':                '12. Tradecraft',
    'modal.help.ch13':                '13. Feedback & Recall',
    // Map dim overlay (focus-change loading state)
    'map.dim.switching':              'Switching to {name}…',
    'map.dim.timeout':                'Sync incomplete — showing last known state.',
    'map.dim.retry':                  'Retry',
    'map.dim.aria_busy':              'Map is updating to new scenario',
    'map.refresh.label':              'Refreshing telemetry…',
    'map.refresh.label_named':        'Refreshing telemetry — {name}',

    // ══════════════════════════════════════════════════════════════
    // Panel — Weather Brief
    // ══════════════════════════════════════════════════════════════
    'panel.weather.title':            'OPS WEATHER BRIEF',

    // ══════════════════════════════════════════════════════════════
    // Panel — SALUTE Report
    // ══════════════════════════════════════════════════════════════
    'panel.salute.title':             'SALUTE REPORT',
    'panel.salute.btn_close':         '[ X ] Close',
    'panel.salute.btn_copy':          'Copy',
    'panel.salute.btn_download':      'Download',
    'panel.salute.cross_ref':         'CROSS-REF',

    // ══════════════════════════════════════════════════════════════
    // Panel — Evidence Chain
    // ══════════════════════════════════════════════════════════════
    'panel.chain.title':              'Evidence Chain',
    'panel.chain.no_events':          'NO EVENTS',
    'panel.chain.24h_window':         '24h WINDOW — LOOSELY ORDERED',
    'panel.chain.narrative_z':        'Narrative Z',
    'panel.chain.isr_aircraft':       'ISR Aircraft',
    'panel.chain.ais_dark_gaps':      'AIS Dark Gaps',
    'panel.chain.v9_intel':           '── v9 INTELLIGENCE ──',
    'panel.chain.telegram_mirror':    'Telegram Mirror',
    'panel.chain.sigint_open':        'SIGINT↗',
    'panel.chain.sigint_tooltip':     'Open SIGINT Panel',
    'panel.chain.infra_survival':     'Infra Survival',
    'panel.chain.c2_sync':            'C2 Sync',
    'panel.chain.llm_intel':          'LLM Intel',
    'panel.chain.toggle_group':       'Collapse / expand group',
    'chain.llm_intel.active':         'active',
    'chain.llm_intel.review':         'REVIEW',
    'chain.llm_intel.none':           '—',

    // ── chain sequence badge ──────────────────────────────────────
    'chain.seq.full_chain':           '✔ FULL CHAIN CONFIRMED',
    'chain.seq.partial':              '≈ PARTIAL CHAIN',
    'chain.seq.none':                 'NO ACTIVE CHAIN',

    // ── chain event type labels ───────────────────────────────────
    'chain.event.narrative_burst':    'Narrative Burst',
    'chain.event.isr_surge':          'ISR Surge',
    'chain.event.sync_ddos':          'Sync DDoS',
    'chain.event.firms_anomaly':      'Kinetic Anomaly',
    'chain.event.ais_dark_gap':       'AIS Dark Gap',
    'chain.event.telegram_intent':    'Telegram: Attack Intent',
    'chain.event.maskirovka':         'Maskirovka (Deception)',
    'chain.event.c2_sync':            'C2 Temporal Sync',
    'chain.event.infra_blackout':     'Infra Blackout',
    'chain.no_events_24h':            'No events in 24h window',

    // ── chain: infra / telegram detail ───────────────────────────
    'chain.maskirovka.title':         '⚠ MASKIROVKA DETECTED',
    'chain.infra_check.label':        'INFRA CHECK — NODES: {n}',
    'chain.telegram_monitor.label':   'TELEGRAM MONITOR — {n} channels',
    'chain.telegram_monitor.targets': 'TARGET URLs:',

    // ── chain: C2 sync detail ─────────────────────────────────────
    'chain.c2sync.detected':          'SYNC +{n}pt',
    'chain.c2sync.partial':           'PARTIAL',
    'chain.c2sync.no_sync':           'NO SYNC',

    // ══════════════════════════════════════════════════════════════
    // Telegram SIGINT panel
    // ══════════════════════════════════════════════════════════════
    'tg.status.intent_detected':      '██ INTENT DETECTED',
    'tg.status.targets_found':        '◆ TARGETS FOUND',
    'tg.status.all_clear':            '── ALL CLEAR',
    'tg.poll.active':                 '{active}/{monitored} active',
    'tg.grid.not_polled':             'Sensor not yet polled',
    'tg.grid.no_active':              'No active channels this cycle — see log below',
    'tg.grid.no_activity':            'No channel activity detected',
    'tg.roster.no_channels':          'No channels in THREAT_ACTOR_MAPPING',
    'tg.log.no_intercepts':           'NO INTERCEPTS RECORDED',
    'tg.entry.intent':                'INTENT',
    'tg.entry.target':                'TARGET',
    'tg.confirm.clear_log':           'Clear intercept log on server?',
    'tg.monitor.label':               'Telegram Monitor — {n} channels',
    'tg.monitor.targets':             'Target URLs:',

    // ══════════════════════════════════════════════════════════════
    // GreyNoise panel
    // ══════════════════════════════════════════════════════════════
    'gn.tier.enterprise':             'ENTERPRISE',
    'gn.tier.community':              'COMMUNITY',
    'gn.tier.no_key':                 'NO KEY',
    'gn.suppress.active':             '⚡ SUPPRESSING CYBER SCORE',
    'gn.querying':                    'Querying GreyNoise...',
    'gn.remaining':                   'Remaining today: {n}/50',
    'gn.result.noise':                '■ NOISE',
    'gn.result.targeted':             '■ TARGETED',
    'gn.result.riot':                 '■ RIOT (benign infra)',
    'gn.result.cached':               '[cached]',
    'gn.log.no_lookups':              'No lookups yet.',
    'gn.log.noise':                   'NOISE',
    'gn.log.targeted':                'TARGETED',
    'gn.no_theater_data':             'No theater data',

    // ══════════════════════════════════════════════════════════════
    // Sensor config / mute
    // ══════════════════════════════════════════════════════════════
    'sensor.mute.prompt':             'Muting sensor: {name}\nReason (optional):',
    'sensor.toggle.enabled':          'Enabled',
    'sensor.toggle.disabled':         'Disabled',
    'sensor.no_sensors':              'No sensors registered.',
    'sensor.load_error':              'Failed to load sensor config: {msg}',

    // ══════════════════════════════════════════════════════════════
    // Evidence panel: mute button / suppressed label
    // ══════════════════════════════════════════════════════════════
    'evidence.btn.mute':              'MUTE',
    'evidence.btn.unmute':            'UNMUTE',
    'evidence.suppressed':            'SUPPRESSED: {reason}',
    'evidence.no_data':               'No rationale data available.',
    'evidence.no_system_note':        'No system note available.',

    // ══════════════════════════════════════════════════════════════
    // SITREP cards (JS-generated)
    // ══════════════════════════════════════════════════════════════
    'sitrep.card.threat_now':         'THREAT NOW',
    'sitrep.card.threat_1h':          'THREAT 1h RANGE',
    'sitrep.card.convergence':        'CONVERGENCE',
    'sitrep.card.history':            'HISTORY',
    'sitrep.card.trend':              'Trend: {icon} {text}',
    'sitrep.card.avg':                'Avg: {n}',
    'sitrep.card.domains':            'Domains: {list}',
    'sitrep.card.none':               'None',
    'sitrep.card.cycles':             '{n} cycles',
    'sitrep.card.window':             '{h}h window',
    'sitrep.loading':                 'Loading…',
    'sitrep.no_data':                 'No data.',
    'sitrep.error':                   'Error: {msg}',

    // ══════════════════════════════════════════════════════════════
    // Country Intel Panel (JS-generated)
    // ══════════════════════════════════════════════════════════════
    'cip.modal_title':                'Country Intel — {name} ({code})',
    'cip.role.core':                  '★ Core',
    'cip.role.link':                  '◎ Link',
    'cip.global_share':               'Global share L3: {l3} / L7: {l7}',
    'cip.section.cyber':              '🔵 Cyber Domain — DDoS Telemetry',
    'cip.label.avg_spike':            'Avg Spike',
    'cip.label.l7_shift':             'L7 Vector Shift',
    'cip.label.ioda':                 'Infra Outage (IODA)',
    'cip.label.bgp_routing':          'Prefix Routing (RIPE)',
    'cip.label.top_sources':          'Top Attack Sources (by spike)',
    'cip.no_sources':                 'No significant sources',
    'cip.state_asn_badge':            'STATE-ASN',
    'cip.spike_label':                'spike {n}x',
    'cip.ioda.normal':                '🟢 NORMAL',
    'cip.ioda.outage':                '🔴 OUTAGE',
    'cip.ioda.outage_wx':             '🟠 OUTAGE (Weather Muted)',
    'cip.l7shift.active':             'L7 SHIFT',
    'cip.l7shift.none':               'None',
    'cip.section.physical':           '🟠 Physical Domain — Infrastructure',
    'cip.label.weather':              'Weather',
    'cip.label.airspace':             'Airspace ({airport})',
    'cip.label.ixp_nodes':            'IXP Nodes',
    'cip.weather.wind':               'wind {n}m/s',
    'cip.airspace.drop':              '— drop {pct}%',
    'cip.section.info':               '🟣 Info Domain — Media Tone (GDELT)',
    'cip.label.current_tone':         'Current Tone',
    'cip.label.alert_status':         'Alert Status',
    'cip.baseline_label':             'Baseline (28d): {base}   Δ {delta}',
    'cip.threshold_label':            'Threshold: {n}',
    'cip.section.predictive':         '⚡ Predictive Indicators',
    'cip.theater_label':              '(theater: {name})',
    'cip.label.esc_velocity':         'Escalation Velocity',
    'cip.sub.1st_deriv':              '1st derivative / cycle',
    'cip.label.blockade_index':       'Blockade Index',
    'cip.sub.blockade':               'DDoS / net reachability',
    'cip.label.narrative_z':          'Narrative Z-Score',
    'cip.sub.30d_baseline':           '30d baseline',
    'cip.label.isr_aircraft':         'ISR Aircraft',
    'cip.sub.high_alt_recon':         'High-alt recon',
    'cip.label.ais_dark_gaps':        'AIS Dark Gaps',
    'cip.sub.transponder':            'Transponder blackouts',
    'cip.label.seq_chain':            'Sequence Chain',
    'cip.sub.24h':                    '24h window',
    'cip.chain.full':                 'FULL CHAIN',
    'cip.chain.partial':              'PARTIAL',
    'cip.chain.none':                 'NO CHAIN',
    'cip.ambush.active':              '⚡ AMBUSH PATTERN ACTIVE',
    'cip.vessels_unit':               '{n} vessels',

    // ── Country Intel: IHR / RIPE Atlas / Tor Metrics ───────────
    'cip.label.ihr_disco':            'Disconnection (IHR)',
    'cip.label.ihr_delay':            'Delay Anomaly (IHR)',
    'cip.ihr.normal':                 '🟢 NORMAL',
    'cip.ihr.disco':                  '🔴 DISCO EVENT',
    'cip.ihr.hegemony':               '🟠 HEGEMONY ALARM',
    'cip.ihr.delay':                  '🟡 DELAY ANOMALY',
    'cip.ihr.events':                 '{n} events',
    'cip.ihr.alarms':                 '{n} alarms',
    'cip.label.ripe_atlas':           'Probe Reach (RIPE Atlas)',
    'cip.label.ripe_latency':         'Measurement RTT',
    'cip.atlas.normal':               '🟢 NORMAL',
    'cip.atlas.probe_drop':           '🟠 PROBE DROP',
    'cip.atlas.probe_blackout':       '🔴 PROBE BLACKOUT',
    'cip.atlas.probes':               '{n} active probes',
    'cip.atlas.drop_pct':             'drop {pct}%',
    'cip.atlas.rtt':                  'avg {avg}ms / p95 {p95}ms',
    'cip.label.tor_metrics':          'Tor Network',
    'cip.tor.normal':                 '🟢 NORMAL',
    'cip.tor.relay_drop':             '🟠 RELAY DROP',
    'cip.tor.user_surge':             '🟡 USER SURGE',
    'cip.tor.censorship':             '🔴 CENSORSHIP INDICATOR',
    'cip.tor.relays':                 '{n} relays / {b} bridges',
    'cip.tor.users':                  '{n} bridge users',
    'cip.tor.surge_pct':              'surge {pct}%',
    'cip.section.network':            '🌐 Network Reachability',
    'cip.section.censorship':         '🔒 Censorship / Tor',

    // ══════════════════════════════════════════════════════════════
    // Map — target list badges
    // ══════════════════════════════════════════════════════════════
    'map.net.outage':                 'OUTAGE',
    'map.net.outage_wx':              'OUTAGE(Wx)',
    'map.net.normal':                 'NORMAL',
    'map.net.tooltip_ok':             '🟢 NORMAL',
    'map.net.tooltip_outage':         '🔴 BGP/OUTAGE',
    'map.net.tooltip_wx':             '🟠 BGP/OUTAGE (Weather Muted)',
    'map.net.status_prefix':          'Net: ',
    'map.net.tooltip_prefix':         'Network Status: ',
    'map.shift_badge':                'L7 SHIFT{actors}',
    'map.shift_tooltip':              'Per-origin L7 shift detected from:{actors}',
    'map.state_asn_badge':            'STATE-ASN',
    'map.state_asn_tooltip':          'State-attributed ASN detected:\n{asns}',
    'map.new_actor_badge':            'NEW',
    'map.new_actor_tooltip':          'No 7-day baseline: new infrastructure',
    'map.target_tooltip':             '{info} | Global: {pct}% | Net: {net}',
    'map.no_threats_vector':          'No significant threats in this vector.',
    'map.no_threats':                 'No significant threats detected.',

    // ── map: overlay popups ────────────────────────────────────────
    'map.popup.bgp_outage':           'BGP/OUTAGE DETECTED',
    'map.popup.firms_title':          'Thermal Anomaly (FIRMS)',
    'map.popup.firms_code':           'Code: {code}',
    'map.popup.firms_sub':            'Kinetic Strike Precursor',
    'map.popup.submarine_cable':      'SUBMARINE CABLE ROUTE',
    'map.popup.connects':             'CONNECTS:',
    'map.popup.cable_landing':        'Cable Landing Station',
    'map.popup.maritime_strait':      'Maritime Chokepoint',
    'map.popup.nato_corridor':        'NATO Cable Corridor',
    'map.popup.dark_gap_badge':       '⚠ AIS DARK GAP DETECTED',
    'map.popup.stationary_badge':     '⚓ STATIONARY ANOMALY',
    'map.popup.normal_badge':         '● NORMAL',
    'map.popup.cables_label':         'CABLES: {names}',
    'map.popup.ais_radius':           'AIS MONITOR RADIUS: 55 km',
    'map.popup.airspace_aircraft':    'Aircraft: {count} (baseline: {base})',
    'map.popup.airspace_drop':        'Drop: {pct}%',
    'map.popup.weather_title':        'Weather: {code}',
    'map.popup.weather_severity':     'Severity: {sev} | Wind: {wind} m/s',
    'map.popup.weather_noise_note':   'Noise filter active: suppresses BGP/Airspace alerts',
    'map.popup.gdelt_title':          '{name} — Media Tone',
    'map.popup.gdelt_tone':           'Tone: {val}',
    'map.popup.gdelt_tone_na':        'Tone: N/A',
    'map.popup.gdelt_baseline':       'Baseline (28d): {base} | {delta}',
    'map.popup.gdelt_status':         'Status: {status}',
    'map.popup.gdelt_noise_note':     'Noise filter: severe weather active',
    'map.popup.gdelt_delta_na':       'Δ N/A',
    'map.popup.ixp_more':             '…and {n} more',
    'map.popup.airspace_drop_pct':    '— drop {pct}%',

    // ── map: tooltip ──────────────────────────────────────────────
    'map.tooltip.airspace':           '{airport}: {pct}% drop ({count}/{base} ac)',
    'map.tooltip.weather':            '{desc} — wind {wind}m/s',

    // ══════════════════════════════════════════════════════════════
    // Data fetch log panel (JS-generated)
    // ══════════════════════════════════════════════════════════════
    'fetchlog.last_refreshed':        'Last refreshed: {time}',
    'fetchlog.grid.last_fetch':       'Last fetch',
    'fetchlog.grid.duration':         'Duration',
    'fetchlog.grid.http_status':      'HTTP Status',
    'fetchlog.grid.cache_age':        'Cache Age',
    'fetchlog.history_label':         'History (newest →):',
    'fetchlog.no_data':               'no data yet',
    'fetchlog.load_error':            'Failed to load fetch log: {msg}',
    'fetchlog.tooltip.ok':            '\nStatus: OK\n{error}',
    'fetchlog.tooltip.error':         '\nStatus: ERROR\n{error}',

    // ══════════════════════════════════════════════════════════════
    // Radio Silence indicator
    // ══════════════════════════════════════════════════════════════
    'rs.live_text':                   'LIVE',
    'rs.quiet_text':                  'QUIET',
    'rs.tooltip.live':                'COMMS LIVE: All sensors reporting normally. No abnormal silence detected.',
    'rs.tooltip.quiet':               'RADIO SILENCE: Score ≥3 but velocity=0.\nPossible sensor suppression or pre-op comms blackout.\nHITL verification recommended.',

    // ══════════════════════════════════════════════════════════════
    // Dashboard empty states
    // ══════════════════════════════════════════════════════════════
    'dash.no_active_pins':            'No scenario focused. Select a scenario in Admin → Scenarios.',

    // ══════════════════════════════════════════════════════════════
    // Survival HUD (JS-generated tooltips)
    // ══════════════════════════════════════════════════════════════
    'survival.tooltip.header':        'INFRA LIVENESS  [{status}  {pct}%]',
    'survival.asphyx_note':           '⚠ ASPHYXIATION DETECTED\n  Success=100% but latency ≥3× baseline\n  CDN is masking packet loss — infra under strain',

    // ══════════════════════════════════════════════════════════════
    // Tools menu — additional entries
    // ══════════════════════════════════════════════════════════════
    'tools.history_analysis':         'History Analysis',
    'tools.user_management':          'User Management',
    'tools.whatif_sim':               'What-If Sim',
    'tools.spof_analysis':            'SPOF Analysis',

    // ══════════════════════════════════════════════════════════════
    // What-If Simulation panel
    // ══════════════════════════════════════════════════════════════
    'panel.whatif.title':             'WHAT-IF SIMULATION',
    'panel.whatif.bonus_header':      'BONUSES & FLAGS',
    'panel.whatif.tl1_hard':          'Core Degraded (TL1 Hard Gate)',
    'panel.whatif.seq_bonus':         'Sequence Bonus',
    'panel.whatif.temporal_bonus':    'Temporal Coherence',
    'panel.whatif.run_btn':           'RUN SIMULATION',
    'panel.whatif.no_events':         'Select at least one sensor event to simulate.',
    'panel.whatif.computing':         'Computing...',
    'panel.whatif.api_error':         'API unavailable',
    'panel.whatif.total_score':       'Total Score',
    'panel.whatif.conv_bonus':        'Convergence',
    'panel.whatif.seq_bonus_label':   'Sequence',
    'panel.whatif.temporal_bonus_label': 'Temporal',

    // ══════════════════════════════════════════════════════════════
    // SPOF Analysis panel
    // ══════════════════════════════════════════════════════════════
    'panel.spof.title':               'SPOF ANALYSIS',
    'panel.spof.loading':             'Analyzing sensor dependencies...',
    'panel.spof.api_error':           'No threat data available yet. Wait for first polling cycle.',
    'panel.spof.sensors_active':      'Active',
    'panel.spof.redundant':           'Redundant',
    'panel.spof.no_redundancy':       'Single sensor',
    'panel.spof.impact_header':       'SENSOR FAILURE IMPACT',
    'panel.spof.score_impact':        'Score impact',
    'panel.spof.domain_lost':         'Domain deactivated',
    'panel.spof.no_spof':             'All sensors nominal — no critical dependencies.',

    // ══════════════════════════════════════════════════════════════
    // Phase 2 badges (HUD / Deep Analytics)
    // ══════════════════════════════════════════════════════════════
    'badge.space_weather':            'Space Wx',
    'badge.space_weather.none':       'Quiet',
    'badge.space_weather.minor':      'Minor',
    'badge.space_weather.moderate':   'Moderate',
    'badge.space_weather.strong':     'Strong',
    'badge.space_weather.severe':     'Severe',
    'badge.space_weather.extreme':    'Extreme',
    'badge.space_weather.suppressing':'Suppressing physical sensors',
    'badge.feint_detected':           'FEINT DETECTED',
    'badge.feint_primary':            'Primary: {domain}',
    'badge.feint_distractors':        'Distractors: {domains}',
    'badge.adaptive_zscore':          'Adaptive Z-Score',
    'badge.adaptive_zscore.active':   'Active ({n} sensors)',
    'badge.adaptive_zscore.learning': 'Learning ({n}/{min} samples)',

    // ══════════════════════════════════════════════════════════════
    // Phase 3: Correlation Heatmap panel
    // ══════════════════════════════════════════════════════════════
    'tools.corr_heatmap':             'Sensor Heatmap',
    'panel.corr.title':               'SENSOR × THEATER',
    'panel.corr.loading':             'Loading sensor data...',
    'panel.corr.no_data':             'No sensor data available',
    'panel.heatmap.toggle.all':       'ALL',
    'panel.heatmap.toggle.cyber':     'CYBER',
    'panel.heatmap.toggle.physical':  'PHYS',
    'panel.heatmap.toggle.info':      'INFO',
    'panel.heatmap.legend.quiet':     'Quiet',
    'panel.heatmap.legend.warning':   'Warning',
    'panel.heatmap.legend.alert':     'Alert',

    // ══════════════════════════════════════════════════════════════
    // LLM Intelligence Panel
    // ══════════════════════════════════════════════════════════════
    'tools.llm_intelligence':               'LLM Intelligence',
    'panel.llm_intel.title':                'LLM INTELLIGENCE',
    'panel.llm_intel.status_online':        'LLM ONLINE',
    'panel.llm_intel.status_offline':       'LLM OFFLINE',
    'panel.llm_intel.status_disabled':      'LLM DISABLED',
    'panel.llm_intel.filter_all':           'ALL',
    'panel.llm_intel.filter_hacktivist':    'HACKTIVIST',
    'panel.llm_intel.filter_diplo':         'DIPLO',
    'panel.llm_intel.filter_military':      'MILITARY',
    'panel.llm_intel.filter_ground':        'GROUND',
    'panel.llm_intel.filter_apt':           'APT',
    'panel.llm_intel.filter_narrative':     'NARRATIVE',
    'panel.llm_intel.filter_convergence':   'CONV',
    'panel.llm_intel.filter_corroborated':  'CORR',
    'panel.llm_intel.filter_triage':        'TRIAGE',
    'panel.llm_intel.triage_empty':         'No pending intel awaiting review.',
    'panel.llm_intel.triage_showing':       'Showing',
    'panel.llm_intel.triage_scenario':      'Scenario',
    'panel.llm_intel.triage_no_scenario':   'No scenario coupling — country tags do not match any active scenario participant.',
    'panel.llm_intel.triage_corroborated':  'corroborated',
    'panel.llm_intel.triage_coupling_tip':  'Participant weight × source confidence. Higher = more operationally significant for this scenario.',
    'panel.llm_intel.triage_cred_tip':      'Source credibility (0.30–0.95). Auto-confirm requires ≥ 0.75.',
    'panel.llm_intel.gate.low_confidence':       'low conf',
    'panel.llm_intel.gate.low_confidence_tip':   'LLM confidence below auto-confirm threshold (0.80). Manual analyst confirmation required to apply score.',
    'panel.llm_intel.gate.low_source_credibility':     'low cred',
    'panel.llm_intel.gate.low_source_credibility_tip': 'Source credibility below 0.75. Auto-confirm blocked until source establishes a track record.',
    'panel.llm_intel.gate.ecosystem_blocked':       'eco blocked',
    'panel.llm_intel.gate.ecosystem_blocked_tip':   'Source ecosystem (e.g., state media) is on the auto-confirm denylist. Manual review mandatory.',
    'panel.llm_intel.gate.ecosystem_unclassified':     'eco unknown',
    'panel.llm_intel.gate.ecosystem_unclassified_tip': 'Source ecosystem not classified. Fail-closed: only known-trusted ecosystems auto-confirm.',
    'panel.llm_intel.gate.manual_review':       'manual',
    'panel.llm_intel.gate.manual_review_tip':   'All gates passed but item is flagged for analyst review.',
    'panel.llm_intel.pulse_tip':            '{n} stale high-priority pending item(s) awaiting triage. Oldest age: {h}h.',
    'panel.llm_intel.stat_auto':            'AUTO',
    'panel.llm_intel.stat_manual':          'MANUAL',
    'panel.llm_intel.stat_pending':         'PENDING',
    'panel.llm_intel.stat_rejected':        'REJECTED',
    'panel.llm_intel.stat_review':          'REVIEW',
    'panel.llm_intel.stat_auto_tip':        'Auto-confirmed: ingestion-time threshold + auto-judge background apply',
    'panel.llm_intel.stat_manual_tip':      'Confirmed by an analyst (manual review)',
    'panel.llm_intel.stat_pending_tip':     'Awaiting analyst review or insufficient evidence for auto-judge',
    'panel.llm_intel.stat_reject_tip':      'Rejected (auto-judge, analyst, or false-positive)',
    'panel.llm_intel.empty':               'No intelligence items',
    'panel.llm_intel.score_applied':        'Score applied',
    'panel.llm_intel.btn_raw':             '▼ raw',
    'panel.llm_intel.btn_confirm':          '✓ CONFIRM',
    'panel.llm_intel.btn_dismiss':          '✗ DISMISS',
    'panel.llm_intel.btn_false_pos':        '⚠ FALSE',
    'panel.llm_intel.btn_reject':           '✗ REJECT',
    'panel.llm_intel.btn_override':         '✗ OVERRIDE',
    'panel.llm_intel.btn_revert':           '↩ REVERT',
    'panel.llm_intel.override_confirm':     'Override this AUTO-CONFIRMED item? Its score contribution will be reversed.',
    'panel.llm_intel.override_failed':      'Override failed.',
    'panel.llm_intel.diag_title':           'Diagnostics',
    'panel.llm_intel.diag_empty':           'No LLM calls in this window',
    'panel.llm_intel.diag_col_sensor':      'sensor',
    'panel.llm_intel.diag_col_calls':       'calls',
    'panel.llm_intel.diag_col_auto':        'auto',
    'panel.llm_intel.diag_col_pending':     'pend',
    'panel.llm_intel.diag_col_filtered':    'filt',
    'panel.llm_intel.diag_col_dedup':       'dedup',
    'panel.llm_intel.diag_col_err':         'err',
    'panel.llm_intel.diag_col_conf':        'conf',
    'panel.llm_intel.diag_col_ms':          'ms',
    'panel.llm_intel.diag_breakdown_title': 'SENSOR FILTER BREAKDOWN',
    // ══════════════════════════════════════════════════════════════
    // Strategic Climate Feed
    // ══════════════════════════════════════════════════════════════
    'tools.strategic_climate':            'Strategic Climate',
    'panel.climate.title':                'STRATEGIC CLIMATE',
    'panel.climate.gauge_label':          'CLIMATE',
    'panel.climate.loading':              'Collecting climate signals...',
    'panel.climate.no_events':            'No climate signals detected',
    'panel.climate.filter_all':           'ALL',
    'panel.climate.filter_time':          'TIME',
    'panel.climate.filter_space':         'SPACE',
    'panel.climate.filter_target':        'TARGET',
    'panel.climate.filter_context':       'CAL',
    'hud.tooltip.climate':                'Strategic Climate — Indirect environmental indicators',
    'panel.climate.baseline_exact':       'exact',
    'panel.climate.baseline_hour':        'hour',
    'panel.climate.baseline_all':         'all',
    'panel.climate.baseline_tooltip':     'Seasonal baseline level: exact=same weekday+time, hour=same time-of-day, all=flat average',

    // ══════════════════════════════════════════════════════════════
    // Evidence Panel: Contribution Waterfall & Counter-Signals
    'evidence.wf_bonus':                  'Convergence Bonus',
    'evidence.counter_signals':           'COUNTER-SIGNALS (normal readings)',
    'evidence.intel_gaps':                'INTELLIGENCE GAPS (offline sensors)',
    'evidence.gap_never':                 'never',
    'evidence.gap_last_data':             'Last data',

    // Sensor Health: Circuit Breaker
    'sensor.health.circuit_open':             'CIRCUIT OPEN (auto-paused)',
    'sensor.health.circuit_open_persistent':  'CIRCUIT OPEN — multiple recovery probes failed',

    // Phase 3: TOOLS menu sections
    'tools.section.core':             'CORE',
    'tools.section.analytics':        'ANALYTICS',
    'tools.section.simulation':       'SIMULATION',
    'tools.section.tradecraft':       'TRADECRAFT',
    'tools.section.admin':            'ADMIN',
    'tools.tradecraft':               'Analyst Tradecraft',
    'tools.sensor_watchpane':         'Sensor Watchpane',

    // ── Tradecraft panel (F4-F14 analyst surface) ──────────────────────
    'panel.tradecraft.title':                    'Analyst Tradecraft',
    'panel.tradecraft.scenario_label':            'Scenario',
    'panel.tradecraft.loading':                  'Loading…',
    'panel.tradecraft.tab.hidden':               'Hidden Signals',
    'panel.tradecraft.tab.coverage':             'Coverage',
    'panel.tradecraft.tab.disconf':              'Disconfirming',
    'panel.tradecraft.tab.compare':              'Compare',
    'panel.tradecraft.tab.ach':                  'ACH',
    'panel.tradecraft.tab.dissent':              'Dissent',
    'panel.tradecraft.tab.assumptions':          'Assumptions',
    'panel.tradecraft.tab.premortem':            'Pre-Mortem',
    'panel.tradecraft.tab.decisions':            'Decisions',
    'panel.tradecraft.tab.whatif':               'What-If Weights',

    'panel.tradecraft.col.time':                 'Time',
    'panel.tradecraft.col.country':              'Country',
    'panel.tradecraft.col.sensor':               'Sensor',
    'panel.tradecraft.col.domain':               'Domain',
    'panel.tradecraft.col.reason':               'Hide reason',
    'panel.tradecraft.col.detail':               'Detail',
    'panel.tradecraft.col.state':                'State',
    'panel.tradecraft.col.last_success':         'Last OK',
    'panel.tradecraft.col.fail_count':           'Fails',
    'panel.tradecraft.col.summary':              'Summary',
    'panel.tradecraft.col.source_kind':          'Kind',
    'panel.tradecraft.col.strength':             'Str',
    'panel.tradecraft.col.author':               'Author',
    'panel.tradecraft.col.actions':              '',
    'panel.tradecraft.col.scenario':             'Scenario',
    'panel.tradecraft.col.score':                'Score',
    'panel.tradecraft.col.cyber':                'Cyber',
    'panel.tradecraft.col.physical':             'Physical',
    'panel.tradecraft.col.info':                 'Info',
    'panel.tradecraft.col.signals':              '#Signals',
    'panel.tradecraft.col.actor':                'Actor',
    'panel.tradecraft.col.type':                 'Type',
    'panel.tradecraft.col.session':              'Sess',

    'panel.tradecraft.btn.add':                  'ADD',
    'panel.tradecraft.btn.retract':              'RETRACT',
    'panel.tradecraft.btn.compare':              'COMPARE',
    'panel.tradecraft.btn.new_matrix':           'NEW MATRIX',
    'panel.tradecraft.btn.add_hyp':              '+ HYPOTHESIS',
    'panel.tradecraft.btn.add_ev':               '+ EVIDENCE',
    'panel.tradecraft.btn.resolve':              'RESOLVE',
    'panel.tradecraft.btn.log':                  'LOG DECISION',

    'panel.tradecraft.hidden.help':              'Signals that fired but were suppressed by mute, noise classification, or low confidence. These are exits where data exists but is not influencing the score.',
    'panel.tradecraft.hidden.empty':             'No suppressed signals in the recent window.',
    'panel.tradecraft.coverage.help':            'Per-sensor circuit-breaker state for this scenario. Degraded sensors may create blind spots.',
    'panel.tradecraft.coverage.empty':           'No coverage snapshot yet — wait for the next scoring cycle.',
    'panel.tradecraft.coverage.summary':         '{degraded} of {total} sensors degraded',
    'panel.tradecraft.disconf.help':             'Record evidence that contradicts the current scenario reading. Forces explicit disconfirmation to fight confirmation bias.',
    'panel.tradecraft.disconf.empty':            'No disconfirming evidence recorded yet.',
    'panel.tradecraft.disconf.summary_ph':       'What observation, citation, or analysis contradicts the current reading?',
    'panel.tradecraft.disconf.sref_ph':          'Source reference (URL / intel_id / rationale_id — optional)',
    'panel.tradecraft.disconf.kind_note':        'Manual note',
    'panel.tradecraft.disconf.kind_intel':       'Intel item',
    'panel.tradecraft.disconf.kind_rationale':   'Rationale entry',
    'panel.tradecraft.disconf.strength_1':       'Strength 1 — anecdotal',
    'panel.tradecraft.disconf.strength_2':       'Strength 2 — weak',
    'panel.tradecraft.disconf.strength_3':       'Strength 3 — moderate',
    'panel.tradecraft.disconf.strength_4':       'Strength 4 — strong',
    'panel.tradecraft.disconf.strength_5':       'Strength 5 — decisive',
    'panel.tradecraft.disconf.retracted':        'Retracted',
    'panel.tradecraft.compare.help':             'Side-by-side comparison of LITE+FULL scoring across scenarios. Useful for spotting where the focused scenario differs from background scenarios.',
    'panel.tradecraft.compare.need2':            'Pick at least two scenarios to compare.',
    'panel.tradecraft.compare.as_focused':       'Each row re-scored as if that scenario were the focused one (full sensor suite).',
    'panel.tradecraft.ach.help':                 'Heuer Analysis of Competing Hypotheses. Score each evidence item from −2 (very inconsistent) to +2 (very consistent). Lowest negative Σ = hypothesis least disconfirmed. Evidence weight = credibility × relevance (1–5 each).',
    'panel.tradecraft.ach.empty':                'No matrices yet — create one above.',
    'panel.tradecraft.ach.title_ph':             'Matrix title (e.g. "Will PRC initiate hostilities by 2026-Q4?")',
    'panel.tradecraft.ach.hyp_ph':               'Hypothesis (mutually exclusive)',
    'panel.tradecraft.ach.null_hyp':             'Null hypothesis (baseline / status quo)',
    'panel.tradecraft.ach.ev_ph':                'Evidence item',
    'panel.tradecraft.ach.sref_ph':              'Source reference (optional)',
    'panel.tradecraft.ach.credibility':          'Credibility 1–5 (how trustworthy is the source)',
    'panel.tradecraft.ach.relevance':            'Relevance 1–5 (how diagnostic is it for these hypotheses)',
    'panel.tradecraft.ach.cred_rel':             'Credibility × Relevance / 25',
    'panel.tradecraft.ach.need_both':            'Add at least one hypothesis and one evidence item to begin scoring.',
    'panel.tradecraft.ach.tally_help':           'Σ row = Σ (consistency × credibility × relevance / 25). Hypothesis with the LEAST negative Σ is least disconfirmed.',
    'panel.tradecraft.dissent.help':             'Record a minority position. Forces the team to log dissent rather than suppress it (Devil\'s Advocate).',
    'panel.tradecraft.dissent.empty':            'No dissenting views recorded.',
    'panel.tradecraft.dissent.title_ph':         'Dissent title (one-line summary)',
    'panel.tradecraft.dissent.body_ph':          'Why does the consensus miss the mark? Include reasoning and supporting signals.',
    'panel.tradecraft.dissent.tl_none':          '(no alternate TL suggestion)',
    'panel.tradecraft.dissent.resolution':       'Resolution',
    'panel.tradecraft.dissent.resolved':         'Resolved',
    'panel.tradecraft.dissent.resolve_prompt':   'Resolution note (how was this dissent addressed?):',
    'panel.tradecraft.assumptions.help':         'Key Assumptions Check (KAC). List the load-bearing assumptions behind this scenario. Lock to prevent drift; invalidate when broken.',
    'panel.tradecraft.assumptions.empty':        'No assumptions registered.',
    'panel.tradecraft.assumptions.stmt_ph':      'Assumption statement (e.g. "PLA winter exercise OPLAN remains defensive")',
    'panel.tradecraft.assumptions.rat_ph':       'Rationale / source basis',
    'panel.tradecraft.assumptions.conf_low':     'Low confidence',
    'panel.tradecraft.assumptions.conf_med':     'Medium confidence',
    'panel.tradecraft.assumptions.conf_high':    'High confidence',
    'panel.tradecraft.assumptions.confidence':   'conf',
    'panel.tradecraft.assumptions.locked':       'Locked',
    'panel.tradecraft.assumptions.invalidated':  'Invalidated',
    'panel.tradecraft.assumptions.btn.invalidate': 'Invalidate',
    'panel.tradecraft.assumptions.btn.lock':     'Lock',
    'panel.tradecraft.assumptions.btn.unlock':   'Unlock',
    'panel.tradecraft.assumptions.btn.history':  'History',
    'panel.tradecraft.assumptions.invalidate_prompt': 'Reason for invalidating (what changed?):',
    'panel.tradecraft.premortem.help':           'Pre-Mortem (Klein 2007). Assume the scenario reading is wrong: enumerate failure modes, imagined outcomes, root causes, early warnings, and mitigations.',
    'panel.tradecraft.premortem.empty':          'No pre-mortem entries yet.',
    'panel.tradecraft.premortem.mode_fp':        'False positive (we over-read the threat)',
    'panel.tradecraft.premortem.mode_fn':        'False negative (we under-read the threat)',
    'panel.tradecraft.premortem.mode_bias':      'Cognitive bias (framing / anchoring error)',
    'panel.tradecraft.premortem.mode_unknown':   'Unknown failure mode',
    'panel.tradecraft.premortem.imagined_ph':    'Imagined outcome (concretely: what goes wrong?)',
    'panel.tradecraft.premortem.rootcause_ph':   'Root cause (why did the reading fail?)',
    'panel.tradecraft.premortem.warning_ph':     'Early warning (what would we observe first?)',
    'panel.tradecraft.premortem.mitigation_ph':  'Mitigation (what would we do?)',
    'panel.tradecraft.premortem.imagined':       'Imagined outcome',
    'panel.tradecraft.premortem.rootcause':      'Root cause',
    'panel.tradecraft.premortem.warning':        'Early warning',
    'panel.tradecraft.premortem.mitigation':     'Mitigation',
    'panel.tradecraft.premortem.resolved':       'Resolved',
    'panel.tradecraft.premortem.resolve_confirm': 'Mark this pre-mortem entry as resolved?',
    'panel.tradecraft.decisions.help':           'Decision ledger. Records analyst-driven changes with session_id (per-tab UUID) for post-hoc review.',
    'panel.tradecraft.decisions.empty':          'No decisions logged yet.',
    'panel.tradecraft.decisions.sum_ph':         'What did you decide? (one-liner)',
    'panel.tradecraft.decisions.rat_ph':         'Rationale / context (optional)',
    'panel.tradecraft.decisions.show_auto':      'Show auto-logged tradecraft actions',
    'panel.tradecraft.decisions.auto_tag':       'auto',
    'panel.tradecraft.decisions.auto_tip':       'Auto-logged by tradecraft write-through (F6/F8/F10/F11/F13). Hide with the checkbox above to see only manually-entered decisions.',
    'panel.tradecraft.decisions.type.threshold': 'Threshold change',
    'panel.tradecraft.decisions.type.weight':    'Weight override',
    'panel.tradecraft.decisions.type.classify':  'Signal classification',
    'panel.tradecraft.decisions.type.intel':     'Intel action',
    'panel.tradecraft.decisions.type.report':    'Report publish',
    'panel.tradecraft.decisions.type.other':    'Other',
    'panel.tradecraft.whatif.help':              'Move sliders to override participant coupling weights, then RUN to replay scoring against the latest snapshot. Read-only — does not affect production scoring.',
    'panel.tradecraft.whatif.run':               'RUN SIMULATION',
    'panel.tradecraft.whatif.reset':             'RESET',
    'panel.tradecraft.whatif.base':              'Baseline',
    'panel.tradecraft.whatif.sim':               'Simulated',
    'panel.tradecraft.whatif.snapshot_age':      'Snapshot age',

    // F1/F2/F3 inline badges
    'evidence.prov.chain_tip':                   'signal_source: {src} · also corroborated by: {chain}',
    'evidence.prov.solo_tip':                    'signal_source: {src} (no other sensor in this group)',
    'scenario.freshness_tip':                    'Score uses cache aged {age}. Stale > 90s.',
    'panel.llm_intel.cred_tier.trusted':         'Trusted',
    'panel.llm_intel.cred_tier.standard':        'Standard',
    'panel.llm_intel.cred_tier.unverified':      'Unverified',
    'panel.llm_intel.cred_tier_tip':             '{tier} source · {src} · credibility {val}',

    // Phase 3: HUD UX
    'hud.tooltip.expand_secondary':   'Show/hide secondary metrics',
    'hud.sync.next':                  'Next sync in',
    'hud.tooltip.ws_status':          'WebSocket status: green=connected, orange=polling fallback',

    // ══════════════════════════════════════════════════════════════
    // User Management panel
    // ══════════════════════════════════════════════════════════════
    'panel.usermgr.title':            'User Management',
    'panel.usermgr.authenticate':     'AUTHENTICATE',
    'panel.usermgr.ph.username':      'Username',
    'panel.usermgr.ph.password':      'Password',
    'panel.usermgr.btn.login':        'LOGIN',
    'panel.usermgr.btn.logout':       'LOGOUT',
    'panel.usermgr.add_header':       'ADD USER',
    'panel.usermgr.registered':       'REGISTERED USERS',
    'panel.usermgr.reset_header':     'RESET PASSWORD:',
    'panel.usermgr.ph.new_password':  'New password (6+ chars)',
    'panel.usermgr.btn.reset':        'RESET',
    'panel.usermgr.btn.cancel':       'CANCEL',
    'panel.usermgr.btn.add':          'ADD',
    'panel.usermgr.msg.enter_creds':  'Enter credentials',
    'panel.usermgr.msg.login_failed': 'Login failed',
    'panel.usermgr.msg.conn_error':   'Connection error',
    'panel.usermgr.msg.logged_in':    'Logged in as: {username} ({role})',
    'panel.usermgr.msg.admin_req':    '— admin required for management',
    'panel.usermgr.err.admin_priv':   'Admin privileges required to view users.',
    'panel.usermgr.err.load_users':   'Failed to load users.',
    'panel.usermgr.err.load_error':   'Error loading users.',
    'panel.usermgr.tbl.username':     'Username',
    'panel.usermgr.tbl.role':         'Role',
    'panel.usermgr.tbl.created':      'Created',
    'panel.usermgr.tbl.last_login':   'Last Login',
    'panel.usermgr.tbl.actions':      'Actions',
    'panel.usermgr.tbl.never':        'Never',
    'panel.usermgr.btn.pw':           'PW',
    'panel.usermgr.tip.reset_pw':     'Reset password',
    'panel.usermgr.btn.del':          'DEL',
    'panel.usermgr.tip.delete':       'Delete user',
    'panel.usermgr.val.user_pass_req':'Username and password required',
    'panel.usermgr.val.pass_min6':    'Password must be at least 6 characters',
    'panel.usermgr.err.add_user':     'Failed to add user',
    'panel.usermgr.err.update_role':  'Failed to update role',
    'panel.usermgr.err.delete_user':  'Failed to delete user',
    'panel.usermgr.err.reset_pw':     'Failed to reset password',
    'panel.usermgr.confirm.delete':   'Delete user "{username}"? This cannot be undone.',
    'panel.usermgr.confirm.pw_reset': 'Password reset for {username}',
    'panel.usermgr.change_pw_header': 'CHANGE PASSWORD',
    'panel.usermgr.ph.old_password':  'Current password',
    'panel.usermgr.ph.new_password':  'New password (6+ chars)',
    'panel.usermgr.btn.change_pw':    'CHANGE',
    'panel.usermgr.err.old_pw_req':   'Current password is required',
    'panel.usermgr.err.change_pw':    'Failed to change password',
    'panel.usermgr.msg.pw_changed':   'Password changed successfully',
    'panel.usermgr.ph.select_user':   '-- Select user --',
    'panel.usermgr.err.select_user':  'Select a user first',
    'panel.usermgr.roles_header':     'ROLES',
    'panel.usermgr.role_desc.admin':  'Full system access. User management, system configuration, scenario management, and all operational features.',
    'panel.usermgr.role_desc.analyst':'Operational access. Scenario focus switching, sensor configuration, intel review, and monitoring features.',
    'panel.usermgr.role_desc.viewer': 'Read-only access. View dashboards, fetch logs, and change own password only.',

    // ══════════════════════════════════════════════════════════════
    // History Analysis panel
    // ══════════════════════════════════════════════════════════════
    'panel.history.title':            'History Analysis',
    'panel.history.theater':          'Country:',
    'panel.history.range':            'Range:',
    'panel.history.range_24h':        '24h',
    'panel.history.range_3d':         '3 days',
    'panel.history.range_7d':         '7 days',
    'panel.history.range_14d':        '14 days',
    'panel.history.range_28d':        '28 days',
    'panel.history.btn.refresh':      'Refresh',
    'panel.history.btn.export':       'Export',
    'panel.history.hdr.threat_trend': 'Threat Score Trend',
    'panel.history.hdr.hod_baseline': 'Hour-of-Day Baseline (CF Spike Avg)',
    'panel.history.hdr.seq_events':   'Sequence Events',
    'panel.history.hdr.alerts':       'Recent Alerts',
    'panel.history.no_data':          'Insufficient data',
    'panel.history.no_hod':           'No HOD data',
    'panel.history.no_events':        'No events in range',
    'panel.history.no_alerts':        'No alerts',
    'panel.history.stat.points':      'DATA PTS',
    'panel.history.stat.peak':        'PEAK',
    'panel.history.stat.avg':         'AVG',
    'panel.history.stat.events':      'EVENTS',
    'panel.history.stat.alerts':      'ALERTS',
    'panel.history.dur.ongoing':      'ongoing',
    'panel.history.label.transition': '{n} transition',
    'panel.history.label.transitions':'{n} transitions',
    'panel.history.label.peak':       'peak',

    // ── threat level labels (HUD) ───────────────────────────────
    'threat_lv.5':                    'THREAT Lv 5: NORMAL',
    'threat_lv.4':                    'THREAT Lv 4: ELEVATED',
    'threat_lv.3':                    'THREAT Lv 3: HIGH',
    'threat_lv.2':                    'THREAT Lv 2: SEVERE',
    'threat_lv.1':                    'THREAT Lv 1: CRITICAL',

    // ── telegram SIGINT status ──────────────────────────────────
    'tg.hud.intent':                  'INTENT ({n} ch)',
    'tg.hud.targets_found':           'TARGETS FOUND',
    'tg.hud.clear':                   'CLEAR',

    // ── unit labels ─────────────────────────────────────────────
    'unit.aircraft':                  '{n} ac',
    'unit.vessels':                   '{n} vessels',

    // ── telemetry badges / tooltips ─────────────────────────────
    'badge.bgp_outage':               'BGP⚠',
    'badge.bgp_wx':                   'BGP(Wx)',
    'badge.media_alert':              'M⚠',
    'badge.media_wx':                 'M(Wx)',
    'badge.airspace_wx':              '✈(Wx)',
    'badge.l7_shift':                 'L7 SHIFT',
    'badge.new_actor':                'NEW',
    'badge.state_asn':                'STATE-ASN',
    'tooltip.bgp_outage':             'BGP/Outage Detected',
    'tooltip.bgp_wx':                 'Outage (Weather Muted)',
    'tooltip.media_alert':            'Media Tone Drop',
    'tooltip.media_wx':               'Media Tone (Weather Muted)',
    'tooltip.airspace_wx':            'Airspace Anomaly (Weather Muted)',
    'tooltip.l7_shift':               'Per-origin L7 shift detected from:{actors}',
    'tooltip.new_actor':              'No 28-day baseline: new infrastructure',
    'tooltip.state_asn':              'State-attributed ASN detected:\n{asns}',
    'tooltip.cdn_asphyxiation':       'CDN Asphyxiation: success rate appears normal but latency ≥3× baseline',
    'tooltip.thermal_anomaly':        'Thermal Anomaly (FIRMS)',

    // ── DDoS Core Strengthening (v10) ────────────────────────────
    'evidence.blockade_index':        'Blockade Index',
    'evidence.blockade_scored':       'Effective infrastructure blockade (BI≥7.0) — contributes to threat score',
    'evidence.cdn_asphyxiation':      'CDN Asphyxiation',
    'evidence.cdn_asphyx_scored':     'CDN masks packet loss but latency tripling reveals strain — independent signal',
    'evidence.vector_shift_severe':   'Severe L7 Shift',
    'evidence.vector_shift_moderate': 'L7 Shift',
    'evidence.adversary_multi':       'Multi-Actor Adversary Strike ({n} actors)',
    'evidence.seq_decay':             'Sequence bonus decayed by {pct}% (event age)',
    'evidence.ddos_bgp_causal':       'DDoS-BGP Causal Link: CF spike concurrent with BGP outage',

    // ── DDoS Intelligence Enhancement (v11) ─────────────────────
    'evidence.ioda_proper':           'IODA Proper API',
    'evidence.ioda_multi_source':     'IODA: Confirmed by {n} independent datasources ({sources})',
    'evidence.ioda_fallback':         'IODA: Using CF Radar fallback (IODA API unreachable)',
    'evidence.bgp_hijack':            'BGP Hijack Detected',
    'evidence.bgp_hijack_detail':     'BGP manipulation: {hijacks} ongoing hijack(s), {leaks} route leak(s)',
    'evidence.bgp_trend_withdraw':    'BGP Prefix Trend: Withdrawing ({pct}% decline)',
    'evidence.bgp_trend_stable':      'BGP Prefix Trend: Stable',
    'evidence.bgp_trend_growing':     'BGP Prefix Trend: Growing ({pct}% increase)',
    'evidence.entropy_concentrating': 'Attack sources concentrating ({delta}% entropy drop)',
    'evidence.entropy_dispersing':    'Attack sources dispersing ({delta}% entropy rise)',
    'evidence.entropy_stable':        'Attack source distribution stable',
    'label.ioda_source':              'IODA Source',
    'label.bgp_events':              'BGP Events',
    'label.origin_entropy':           'Origin Entropy',
    'label.prefix_trend':             'Prefix Trend',

    // ── ISR / map popups ────────────────────────────────────────
    'map.popup.isr_track':            '▲ ISR TRACK',
    'map.popup.isr_callsign':         'Callsign: {cs}',
    'map.popup.isr_alt_speed':        'Alt: {alt} km  |  Speed: {spd} kt',
    'map.popup.isr_squawk':           'Squawk: {sq}',

    // ── CIP panel extra labels ──────────────────────────────────
    'cip.label.baseline_28d':         'Baseline (28d): {base}  Δ {delta}',

    // ── config save status ──────────────────────────────────────
    'config.status.saving':           'Saving...',
    'config.status.saved':            '✓ Saved ({n} keys updated)',
    'config.status.needs_restart':    '— restart required for some settings',
    'config.status.error':            '✗ Error: {msg}',
    'config.status.load_error':       'Failed to load: {msg}',
    'sysconfig.badge.restart':        'restart',
    'sysconfig.badge.live':           'live',

    // ══════════════════════════════════════════════════════════════
    // System Config — additional fields
    // ══════════════════════════════════════════════════════════════
    'sysconfig.section.server':       'Server',
    'sysconfig.help.host_external':   'Set to 0.0.0.0 to allow external access',
    'sysconfig.section.auth':         'Authentication (JWT)',
    'sysconfig.help.default_admin_pw':'Admin password on first startup (change via API after deployment)',
    'sysconfig.help.jwt_secret':      'If blank, randomly generated on each startup (tokens invalidated on restart)',
    'sysconfig.section.notifications':'Alert Notifications',
    'sysconfig.help.notifications':   'Sends external notifications on Threat Level changes and Ambush detection. Configure a Webhook URL to enable.',
    'sysconfig.section.plugins':      'Plugin Sensors',
    'sysconfig.help.server_restart':  'All Server settings require restart.',
    'sysconfig.help.auth_desc':       'User authentication and session management. A default admin user is created on first startup.',
    'sysconfig.help.debounce':        'Interval to suppress repeated alerts of the same type',
    'sysconfig.help.plugins_desc':    'Dynamically loads BaseSensor subclasses from the plugins/ directory.',
    'sysconfig.help.plugin_enabled':  'Comma-separated filenames (without extension), or * for all plugins',
    'sysconfig.help.plugin_disabled': 'Plugin names to explicitly disable (comma-separated)',

    // ══════════════════════════════════════════════════════════════
    // CAC — Context-Aware Convergence
    // ══════════════════════════════════════════════════════════════
    'hud.label.context_align':        'ALIGN',
    'hud.tooltip.context_align':      'Context Alignment: how many axes (Temporal/Spatial/Target/Direction) are in high-risk state',
    'hud.label.direction':            'DIR:',
    'hud.tooltip.direction':          'Signal Direction: dominant classification of fired signals',
    'evidence.context_alignment':     'Context Alignment',
    'evidence.direction':             'Direction',
    'evidence.btn.classify_tip':      'Classify this signal as noise (exercise/maintenance/known)',
    'evidence.convergence_score':     'Convergence Score',
    'evidence.none':                  'None',
    'evidence.dir_counter_label':     'ADV:{adv} FRD:{frd} TGT:{tgt}',
    'evidence.wf_legend.cyber':       'CYBER',
    'evidence.wf_legend.phys':        'PHYS',
    'evidence.wf_legend.info':        'INFO',
    'evidence.wf_legend.bonus':       'BONUS',
    'evidence.domain.cyber':          'CYBER',
    'evidence.domain.physical':       'PHYSICAL',
    'evidence.domain.info':           'INFO',
    'evidence.domain.other':          'OTHER',
    'evidence.group.count':           '{fired}/{total} fired',
    'evidence.group.total':           'Σ {n}pt',
    'modal.evidence.th_direction':    'Direction',
    'cac.axis.temporal':              'Temporal',
    'cac.axis.spatial':               'Spatial',
    'cac.axis.target':                'Target',
    'cac.axis.direction':             'Direction',
    'dir.adversary':                  'ADVERSARY OFFENSIVE',
    'dir.friendly':                   'FRIENDLY DEFENSIVE',
    'dir.target':                     'TARGET IMPACT',
    'dir.unknown':                    'UNKNOWN',
    'noise.classify_prompt':          'Classify signal from {sensor} as:',
    'noise.classify_hint':            'Enter number (1-4):',
    'noise.invalid_choice':           'Invalid choice.',
    'noise.exercise':                 'Exercise / Drill',
    'noise.maintenance':              'Scheduled Maintenance',
    'noise.known_noise':              'Known Noise Source',
    'noise.false_positive':           'False Positive',
    'noise.expires_prompt':           'Auto-expire after hours (blank = permanent):',
    'threat_cls.prompt':              'Classify current threat situation:',
    'threat_cls.exercise':            'Exercise / Drill',
    'threat_cls.maintenance':         'Scheduled Maintenance',
    'threat_cls.confirmed_threat':    'Confirmed Threat',
    'threat_cls.false_positive':      'False Positive',
    'threat_cls.notes_prompt':        'Additional notes (optional):',

    // ══════════════════════════════════════════════════════════════
    // Phase C: New Sensors S1-S7
    // ══════════════════════════════════════════════════════════════
    // S1: NOTAM
    'sensor.notam':                   'NOTAM Anomaly',
    'sensor.notam.desc':              'Airspace restriction surge detection (TFR / military NOTAMs)',
    'sensor.notam.surge':             'NOTAM surge: {total} notices ({mil} military)',
    'sensor.notam.normal':            'No NOTAM anomalies',
    'badge.notam_surge':              'NOTAM SURGE',
    // S2: Travel Advisory
    'sensor.travel_advisory':         'Travel Advisory',
    'sensor.travel_advisory.desc':    'US State Dept travel advisory level monitoring',
    'sensor.travel_advisory.level':   'Level {n}: {label}',
    'sensor.travel_advisory.upgraded':'UPGRADED',
    'sensor.travel_advisory.l1':      'Normal Precautions',
    'sensor.travel_advisory.l2':      'Increased Caution',
    'sensor.travel_advisory.l3':      'Reconsider Travel',
    'sensor.travel_advisory.l4':      'Do Not Travel',
    'badge.travel_advisory':          'TRAVEL ADV',
    // S3: OONI Censorship
    'sensor.ooni':                    'OONI Censorship',
    'sensor.ooni.desc':               'Internet censorship measurement (website blocking, DNS tampering)',
    'sensor.ooni.censoring':          'Censorship detected: {rate} anomaly rate',
    'sensor.ooni.heavy':              'Heavy censorship: {rate} anomaly, {confirmed} confirmed',
    'sensor.ooni.normal':             'No significant censorship',
    'badge.ooni_censorship':          'CENSORSHIP',
    // S4: USGS Seismic
    'sensor.usgs_seismic':            'USGS Seismic',
    'sensor.usgs_seismic.desc':       'Earthquake monitoring near submarine cables and chokepoints',
    'sensor.usgs_seismic.cable':      'Seismic event near submarine cable: {cp}',
    'sensor.usgs_seismic.nuclear':    'Possible nuclear test signature ({n} candidates)',
    'sensor.usgs_seismic.normal':     'No significant seismic activity',
    'badge.seismic_cable':            'SEISMIC / CABLE',
    'badge.nuclear_candidate':        'NUCLEAR TEST?',
    // S5: Military Support Aircraft
    'sensor.mil_support_air':         'Mil Support Air',
    'sensor.mil_support_air.desc':    'Military tanker, transport, and AWACS aircraft tracking',
    'sensor.mil_support_air.surge':   'Military air surge: T={tanker} C={transport} A={awacs}',
    'sensor.mil_support_air.normal':  'No military support aircraft anomaly',
    'badge.mil_air_surge':            'MIL AIR SURGE',
    'badge.tanker':                   'TANKER',
    'badge.transport':                'TRANSPORT',
    'badge.awacs':                    'AWACS',
    // S6: GPS Jamming
    'sensor.gps_jamming':             'GPS Jamming',
    'sensor.gps_jamming.desc':        'GPS interference / spoofing detection near theaters',
    'sensor.gps_jamming.detected':    'GPS jamming detected: max={max}, avg={avg}',
    'sensor.gps_jamming.critical':    'Critical GPS jamming: max={max}',
    'sensor.gps_jamming.normal':      'No GPS interference detected',
    'badge.gps_jamming':              'GPS JAM',
    // S7: CT Log
    'sensor.ct_log':                  'CT Log Monitor',
    'sensor.ct_log.desc':             'Certificate Transparency log anomaly detection',
    'sensor.ct_log.surge':            'Certificate surge: {total} certs ({gov} gov)',
    'sensor.ct_log.gov_surge':        'Government certificate surge: {gov} gov certs',
    'sensor.ct_log.normal':           'No CT log anomalies',
    'badge.ct_surge':                 'CERT SURGE',

    // ── Scenario (Phase 4) ──
    'scenario.badge.focused':         'FOCUSED',
    'scenario.badge.lite':            'LITE',
    'scenario.state.active':          'Active',
    'scenario.state.paused':          'Paused',
    'scenario.state.archived':        'Archived',
    'scenario.role.primary_target':   'Primary Target',
    'scenario.role.principal_belligerent': 'Principal Belligerent',
    'scenario.role.adversary':        'Adversary',
    'scenario.role.primary_ally':     'Primary Ally',
    'scenario.role.forward_base':     'Forward Base',
    'scenario.role.secondary_ally':   'Secondary Ally',
    'scenario.role.extended_deterrence': 'Extended Deterrence',
    'scenario.role.strategic_observer': 'Strategic Observer',
    'scenario.role.proxy_front':      'Proxy Front',
    'scenario.role.force_projection': 'Force Projection',
    'scenario.role.secondary_party':  'Secondary Party',
    'scenario.role.spillover_risk':   'Spillover Risk',
    'scenario.role.regional_power':   'Regional Power',
    'scenario.mgr.title':            'Scenario Manager',
    'scenario.mgr.create':           'Create Scenario',
    'scenario.mgr.edit':             'Edit Scenario',
    'scenario.mgr.delete':           'Delete',
    'scenario.mgr.archive':          'Archive',
    'scenario.mgr.restore':          'Restore',
    'scenario.mgr.purge':            'Purge',
    'scenario.mgr.reset':            'Reset to Preset',
    'scenario.mgr.purge_confirm':    'Permanently delete this scenario and all its data? This cannot be undone.',
    'scenario.mgr.name_en':          'Name (EN)',
    'scenario.mgr.name_ja':          'Name (JA)',
    'scenario.mgr.desc_en':          'Description (EN)',
    'scenario.mgr.desc_ja':          'Description (JA)',
    'scenario.mgr.core_country':     'Core Country',
    'scenario.mgr.participants':     'Participants',
    'scenario.mgr.add_participant':  'Add Participant',
    'scenario.mgr.weight':           'Weight',
    'scenario.mgr.role':             'Role',
    'scenario.mgr.country':          'Country',
    'scenario.mgr.save':             'Save',
    'scenario.mgr.cancel':           'Cancel',
    'scenario.mgr.enabled':          'Enabled',
    'scenario.mgr.disabled':         'Disabled',
    'scenario.mgr.enable':           'Enable',
    'scenario.mgr.disable':          'Disable',
    'scenario.mgr.bloc_all':         'ALL',
    'scenario.mgr.bloc_selected':    'SELECTED',
    'scenario.mgr.ph_search':        'Filter by country name or code...',
    'scenario.mgr.err.no_participants': 'At least one participant is required',
    'scenario.mgr.source_preset':    'Preset',
    'scenario.mgr.source_db':        'Custom',
    'scenario.mgr.changelog':        'Change Log',
    'scenario.mgr.no_changes':       'No changes recorded.',
    'scenario.tab.scenarios':        'Scenarios',
    // Phase 5: detail panel
    'scenario.badge.lite_warn':      'BIAS',
    'scenario.tl.lite_insufficient': 'LITE-INS',
    'scenario.tl.lite_insufficient_tip': 'Insufficient observable signal: only 0-1 of 3 domains has any data. Threat level is not derivable. Switch focus to this scenario for full sensor coverage.',
    'scenario.coverage.badge':       'Coverage {pct}%',
    'scenario.coverage.tip':         'Domain coverage: {pct}% — blind: {blind}. In lite mode this scenario is scored from {pct}% of domains; the score may understate or overstate the actual risk. Switch focus for full sensor coverage.',
    'scenario.detail.score':         'Score',
    'scenario.detail.contributions': 'Contributions',
    'scenario.detail.no_contributions': 'No contributions recorded.',
    'scenario.detail.col_sensor':    'Sensor',
    'scenario.detail.col_country':   'Country',
    'scenario.detail.col_role':      'Role',
    'scenario.detail.col_raw':       'Raw',
    'scenario.detail.col_llm_w':     'LLM W',
    'scenario.detail.col_part_w':    'Part W',
    'scenario.detail.col_contrib':   'Contrib',
    'scenario.detail.col_evidence':  'Src',
    'scenario.detail.col_whatif':    'What-If',
    'scenario.detail.value':         'Value',
    'scenario.detail.llm_reasoning': 'LLM Reasoning',
    'scenario.detail.observed':      'Observed',
    'scenario.detail.lite_bias':     'LITE mode: LLM intel and global signals only. Physical and per-country cyber signals are NOT observed. This scenario\'s score under-counts non-English and non-textual events. Do not compare directly to the focused TL.',
    'scenario.detail.whatif_result': 'What-If Result:',
    'scenario.detail.whatif_reset':  'Reset What-If',
    'scenario.btn.switch_focus':     'SWITCH FOCUS',
    'scenario.btn.switch_focus_tip': 'Switch full-sensor scoring to this scenario',
    'scenario.detail.indicators':    'Indicators',
    'scenario.detail.active_countries': 'Active',
    'scenario.overlay.title':        'Layer 3 Overlay',
    'scenario.overlay.edit':         'Weights',
    'scenario.overlay.apply':        'Apply',
    'scenario.overlay.reset':        'Reset',
    'scenario.overlay.close':        'Close',
    'scenario.overlay.active_badge': 'ACTIVE',
    'scenario.overlay.help':         'Session-only weight overrides for hypothesis testing. Changes affect only your session and are discarded when you close the tab. Values outside [0.0–1.0] are rejected.',
    // Phase A-D: velocity, patterns, C-lite evaluation
    'scenario.pattern.silent_div':     'SILENT DIV',
    'scenario.pattern.silent_div_tip': 'Silent Divergence: cyber and physical signals active with no information-domain coverage — a classic pre-conflict indicator',
    'scenario.pattern.ctx_align_tip':  'Context Alignment: 3+ axes (temporal, spatial, target, direction) converging — signals are correlated, not coincidental',
    'scenario.eta_tip':                'Estimated time to next threat level at current velocity',
    'scenario.clite.title':            'C-lite Evaluation',
    'scenario.clite.load_btn':         'Load C-lite Evaluation',
    'scenario.clite.switches':         'Switches',
    'scenario.clite.misses':           'Misses',
    'scenario.clite.miss_rate':        'Miss Rate',
    'scenario.clite.avg_delta':        'Avg Delta',
    'scenario.clite.max_delta':        'Max Delta',
    'scenario.clite.by_scenario':      'By Scenario',
    'scenario.clite.scenario':         'Scenario',
    'scenario.clite.rec_lite_sufficient':    'LITE mode is sufficient — background miss rate is low',
    'scenario.clite.rec_consider_c_medium':  'Consider C-MEDIUM — background miss rate exceeds 15%',
    'scenario.clite.rec_insufficient_data':  'Insufficient data — more focus switches needed for evaluation',

    // §10.5 Pending Decisions (TL recalibration + ADR-015 dual-weight)
    'scenario.pending.title':               'Pending Decisions (§10.5)',
    'scenario.pending.load_btn':            'Load Pending Decisions',
    'scenario.pending.tl_recal_name':       'TL Recalibration (§7.3.1)',
    'scenario.pending.dual_weight_name':    'ADR-015 Dual-Weight',
    'scenario.pending.pin_label':           'Pending Decisions',
    'scenario.pending.pin_tip':             'Click to open Scenario Manager — §10.5 evaluation deadlines approaching',
    'scenario.pending.days_remaining':      '{n} d remaining',
    'scenario.pending.overdue_by':          'overdue by {n} d',
    'scenario.pending.extended_hard':       'Hard deadline (one 14d extension): {d}',
    'scenario.pending.extended_past':       'Extension window also exhausted — decision mandatory',
    'scenario.pending.samples':             'Samples',
    'scenario.pending.low_weight_pct':      'Low-Weight %',
    'scenario.pending.tl_rollup':           '{raise} scenario(s) recommend RAISE, {extend} waiting for more data, {accept} balanced',
    'scenario.pending.rec_accept_current':         'ACCEPT CURRENT — thresholds/weights are aligned',
    'scenario.pending.rec_rollback_to_single_weight': 'ROLLBACK to single-weight — LLM country_weight noise exceeds §10.5 thresholds',
    'scenario.pending.rec_raise_thresholds':       'RAISE TL thresholds — TL2/TL1 firing too frequently',
    'scenario.pending.rec_extend_or_wait':          'EXTEND OR WAIT — insufficient samples for a confident call',

    // ══════════════════════════════════════════════════════════════
    // Login gate
    // ══════════════════════════════════════════════════════════════
    'login.error.required':            'Username and password required',
    'login.error.failed':              'Login failed',
    'login.error.connection':          'Connection error',

    // ══════════════════════════════════════════════════════════════
    // Common UI labels
    // ══════════════════════════════════════════════════════════════
    'ui.loading':                      'Loading...',
    'ui.waiting_api':                  'Waiting for API telemetry...',
    'ui.api_unavailable':              'API unavailable',
    'ui.none':                         'None',
    'ui.saving':                       'Saving...',
    'ui.saved':                        'Saved!',
    'ui.error':                        'Error',

    // ══════════════════════════════════════════════════════════════
    // Sync / Dashboard
    // ══════════════════════════════════════════════════════════════
    'dash.changes_pending':            'Changes pending. Press SYNC.',
    'climate.badge_prefix':            'CLIMATE',

    // ══════════════════════════════════════════════════════════════
    // Scenario Manager
    // ══════════════════════════════════════════════════════════════
    'scenario.mgr.no_scenarios':       'No scenarios found.',
    'scenario.mgr.err.id_required':    'ID required',

    // ══════════════════════════════════════════════════════════════
    // Auto-tuning Wizard (Tier 4 commits 13-15)
    // ══════════════════════════════════════════════════════════════
    'wizard.title':                    'Auto-tune Proposals',
    'wizard.close':                    '[ X ] Close',
    'wizard.loading':                  'Loading proposals...',
    'wizard.empty':                    'No pending proposals.',
    'wizard.disclaimer':               'Tool conclusion only — final judgment by organizational process. Apply requires explicit confirmation.',
    'wizard.tab.scenario_improver':    'Scenario Improver',  /* legacy alias */
    'wizard.tab.recall_positive':      'Recall+',
    'wizard.tab.recall_negative':      'Recall-',
    'wizard.tab.structure':            'Structure',
    'wizard.tab.diagnostic':           'Diagnostic',
    'wizard.tab.sensor_disable':       'Sensor Disable',
    'wizard.tab.drift':                'Drift Signals',
    'wizard.tab.discovery':            'Discovery',
    'wizard.diagnostic.empty':         'No diagnostics — system healthy.',
    'wizard.diagnostic.note':          'Diagnostic proposals are informational only. They have no Apply path; only Dismiss is available.',
    'wizard.recall_negative.note':     'Recall-reducing proposals require strict 5-source dormancy evidence + non-protected role + active scenario vitality. Apply requires NP7 confirmation.',
    'wizard.row.target':               'Target: {target}',
    'wizard.row.scenario':             'Scenario: {scenario}',
    'wizard.row.formula_ref':          'formula: {formula}',
    'wizard.row.sample_n':             'n={n}',
    'wizard.row.emitted_at':           'emitted {ago}',
    'wizard.row.recall_warning':       '⚠ Recall-reducing — confirmation required',
    'wizard.row.btn.apply':            'Apply',
    'wizard.row.btn.dismiss':          'Dismiss',
    'wizard.row.btn.defer':            'Defer 30d',
    'wizard.row.btn.ack':              'Acknowledge',
    'wizard.row.btn.preview':          'Preview',
    'wizard.row.evidence_label':       'Evidence:',
    'wizard.row.confidence':           'conf {value}',
    'wizard.row.confidence_low':       'low confidence',
    'wizard.confirm.title':            'Confirm Apply (Recall-Reducing)',
    'wizard.confirm.warn':             'This change may reduce recall. Review the rationale and confirm before applying.',
    'wizard.confirm.cancel':           'Cancel',
    'wizard.confirm.apply':            'Confirm Apply',
    'wizard.confirm.success':          'Applied successfully.',
    'wizard.confirm.failed':           'Apply failed: {error}',
    'wizard.action.dismissed':         'Dismissed.',
    'wizard.action.deferred':          'Deferred (30d).',
    'wizard.action.acknowledged':      'Acknowledged.',
    'wizard.action.failed':            'Action failed: {error}',
    'wizard.discovery.cluster':        'Cluster #{idx}',
    'wizard.discovery.countries':      'Countries: {countries}',
    'wizard.discovery.centroid':       'Centroid: {centroid}',
    'wizard.discovery.annotation_kind': 'Annotation: {kind}',
    'wizard.discovery.suggested_name': 'Suggested: {name}',
    'wizard.discovery.no_annotation':  '(no LLM annotation yet)',
    'wizard.discovery.shadow_mode':    'shadow',
    'wizard.discovery.production_mode': 'production',

    // ══════════════════════════════════════════════════════════════
    // Discovery panel (Tier 4 commit 15)
    // ══════════════════════════════════════════════════════════════
    'discovery.panel.title':           'Scenario Discovery',
    'discovery.panel.empty':           'No discovery clusters yet.',
    'discovery.panel.refresh':         'Refresh',
    'discovery.panel.run_id':          'run #{id}',
    'discovery.panel.eps':             'eps={eps}',
    'discovery.panel.min_samples':     'min_samples={n}',
    'discovery.panel.n_clusters':      '{n} clusters',
    'discovery.panel.btn.review':      'Review in Wizard',
    'discovery.panel.btn.replay':      'Replay',
    'discovery.panel.replay_title':    'Discovery Run Replay',

    // ══════════════════════════════════════════════════════════════
    // AP3 self-eval HUD chip (Tier 4 commit 16)
    // ══════════════════════════════════════════════════════════════
    'autotune.chip.title':             'Auto-tune Health',
    'autotune.chip.applied':           '{n} applied (7d)',
    'autotune.chip.pending':           '{n} pending',
    'autotune.chip.drift':             '{n} drift unack',
    'autotune.chip.recall_red':        'recall RED',
    'autotune.chip.recall_ok':         'recall OK',
    'autotune.chip.open_wizard':       'Open Wizard',
    'tools.autotune_wizard':           'Auto-tune Wizard',

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

// ============================================================
// INTEL GUIDE local language toggle (bilingual EN/JA prose only)
// ============================================================

/**
 * Toggle visibility of `.guide-lang-en` / `.guide-lang-ja` divs inside
 * #help-modal. Persisted to localStorage.guide_lang. Default: 'en'.
 *
 * Independent of any UI language state — the rest of the app is EN-only
 * and browser auto-translation handles non-English readers for short
 * labels. The GUIDE keeps a hand-curated bilingual pair because long-form
 * analyst prose translates poorly via machine and is high-leverage
 * (NP6 disclosure of why thresholds fire).
 */
function setGuideLang(lang) {
  if (lang !== 'en' && lang !== 'ja') return;
  localStorage.setItem('guide_lang', lang);
  const guide = document.getElementById('help-modal');
  if (!guide) return;
  guide.querySelectorAll('.guide-lang-en').forEach(el => {
    el.style.display = lang === 'en' ? '' : 'none';
  });
  guide.querySelectorAll('.guide-lang-ja').forEach(el => {
    el.style.display = lang === 'ja' ? '' : 'none';
  });
  const btnEn = document.getElementById('guide-lang-btn-en');
  const btnJa = document.getElementById('guide-lang-btn-ja');
  if (btnEn) btnEn.classList.toggle('guide-lang-active', lang === 'en');
  if (btnJa) btnJa.classList.toggle('guide-lang-active', lang === 'ja');
}

// First-load init: apply static EN translations, then sync GUIDE pill to
// the persisted preference (default 'en') so a returning JA reader does
// not have to re-toggle every visit.
document.addEventListener('DOMContentLoaded', () => {
  _applyStaticTranslations();
  const guideLang = localStorage.getItem('guide_lang') || 'en';
  setGuideLang(guideLang);
});
