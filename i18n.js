/**
 * DDoS-Radar i18n — Translation Dictionary
 *
 * Usage:
 *   _t('key')              → translated string for current language
 *   _t('key', {n: 3})     → with placeholder substitution: {n} → 3
 *   setLang('ja')          → switch language (persisted to localStorage)
 *
 * Key naming convention: namespace.sub_namespace.key
 * Placeholder format:    {name} inside string values
 *
 * Supported languages: 'en' (English), 'ja' (Japanese)
 */

const LANG = {
  en: {

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
    'hud.btn.intel_guide':            'Intel Guide',
    'hud.btn.config':                 'Config',
    'hud.diag.label':                 'DIAG',
    'hud.tooltip.settings_menu':      'Settings — Intel Guide / Config',

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
    'tools.live_threat_telemetry':    'Live Threat Telemetry',
    'tools.evidence_chain':           'Evidence Chain',
    'tools.telegram_sigint':          'Telegram SIGINT',
    'tools.threat_pulse':             'Threat Pulse',
    'tools.weather_brief':            'Weather Brief',
    'tools.salute_export':            'SALUTE Export',
    'tools.historical_analog':        'Historical Analog',
    'tools.ops_clock':                'Ops Clock',
    'tools.greynoise':                'GreyNoise',
    'tools.analyst_notebook':         'Analyst Notebook',

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
    // Panel — Live Threat Telemetry
    // ══════════════════════════════════════════════════════════════
    'panel.dashboard.title':          'Live Threat Telemetry',
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
    'modal.settings.tab.sysconfig':   'System',
    'modal.settings.tab.users':       'Users',

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

    // ══════════════════════════════════════════════════════════════
    // Panel — Operational Clock
    // ══════════════════════════════════════════════════════════════
    'panel.clock.title':              'OPERATIONAL CLOCK',
    'clock.local_prefix':             'LOCAL: ',
    'clock.last_event':               'LAST EVENT: {m}m {s}s ago',

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
    'panel.salute.copied':            'SALUTE report copied to clipboard',
    'panel.salute.cross_ref':         'CROSS-REF',

    // ══════════════════════════════════════════════════════════════
    // Panel — Historical Analog
    // ══════════════════════════════════════════════════════════════
    'panel.ha.title':                 'HISTORICAL ANALOG',
    'ha.accumulating':                'Accumulating data...',
    'ha.note':                        'PEARSON R — LAST 20 CYCLES vs KNOWN EVENTS',

    // ══════════════════════════════════════════════════════════════
    // Panel — Threat Pulse
    // ══════════════════════════════════════════════════════════════
    'panel.pulse.title':              'THREAT PULSE',

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
    // Analyst Notebook
    // ══════════════════════════════════════════════════════════════
    'notebook.no_entries':            'No entries yet.\nYour assessments, IP lookups, and sensor mutes are recorded here automatically.',
    'notebook.export.header':         '=== ANALYST NOTEBOOK EXPORT ===',
    'notebook.export.generated':      'Generated: {iso}',
    'notebook.export.assessment':     'Assessment: {a} | Confidence: {c}',
    'notebook.export.watch_for':      'WATCH FOR: {text}',
    'notebook.export.shift_log':      '--- SHIFT LOG ---',
    'notebook.export.copied':         'COPIED!',
    'notebook.confirm.clear':         'Clear all notebook entries? This cannot be undone.',
    'notebook.entry.sensor_unmuted':  'Sensor unmuted: {name}',
    'notebook.entry.sensor_muted':    'Sensor muted: {name}',
    'notebook.entry.ip_noise':        'NOISE',
    'notebook.entry.ip_targeted':     'TARGETED',
    'notebook.entry.defcon':          'Threat Level {dir} {from} → {to} (score: {score})',

    // ══════════════════════════════════════════════════════════════
    // Sensor config / mute
    // ══════════════════════════════════════════════════════════════
    'sensor.mute.prompt':             'Muting sensor: {name}\nReason (optional — recorded in Analyst Notebook):',
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
    'tools.action_plan':              'Action Plan',

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
    // Action Plan panel
    // ══════════════════════════════════════════════════════════════
    'panel.ap.title':                 'ACTION PLAN',
    'panel.ap.current':               'CURRENT',
    'panel.ap.all_clear':             'All clear — review escalation procedures below for readiness.',
    'panel.ap.llm_context':           'LLM Intel Context',
    'ap.intel.theater_prefix':        '[{t}]',
    'panel.ap.tl5.monitor':           'Maintain routine OSINT monitoring cycle',
    'panel.ap.tl5.baseline':          'Verify HOD baseline data collection is active',
    'panel.ap.tl5.review':            'Review sensor health dashboard weekly',
    'panel.ap.tl4.watch':             'Increase monitoring frequency to 15-min intervals',
    'panel.ap.tl4.analytics':         'Review Deep Analytics for anomaly confirmation',
    'panel.ap.tl4.notify':            'Notify on-duty analyst of elevated status',
    'panel.ap.tl4.log':               'Begin logging observations in Analyst Notebook',
    'panel.ap.tl3.rate_limit':        'Enforce CDN rate limiting on critical endpoints',
    'panel.ap.tl3.cdn':               'Verify CDN/WAF rules are up to date',
    'panel.ap.tl3.increase_polling':  'Switch to 5-min polling (SYNC mode)',
    'panel.ap.tl3.soc_alert':         'Alert SOC team and begin active monitoring',
    'panel.ap.tl3.backup_dns':        'Activate backup DNS configuration',
    'panel.ap.tl2.failover':          'Prepare infrastructure failover (standby activation)',
    'panel.ap.tl2.escalate':          'Escalate to senior leadership / duty officer',
    'panel.ap.tl2.lockdown':          'Enable enhanced access controls on critical systems',
    'panel.ap.tl2.coordinate':        'Coordinate with ISP / upstream providers',
    'panel.ap.tl2.ir_prep':           'Stage incident response team and playbook',
    'panel.ap.tl2.geo_block':         'Consider geo-blocking adversary origin ASNs',
    'panel.ap.tl1.ir_activate':       'ACTIVATE incident response procedure',
    'panel.ap.tl1.report':            'Report to CERT / relevant authorities',
    'panel.ap.tl1.isolate':           'Isolate compromised network segments',
    'panel.ap.tl1.backup_comm':       'Switch to backup communication channels',
    'panel.ap.tl1.evidence':          'Begin forensic evidence preservation',
    'panel.ap.tl1.full_staff':        'Full SOC staffing — all hands on deck',
    'panel.ap.tl1.null_route':        'Deploy null-route / blackhole for attack traffic',

    // ══════════════════════════════════════════════════════════════
    // Escalation Tracker panel (Phase 2)
    // ══════════════════════════════════════════════════════════════
    'tools.phase_escalation':         'Phase & Escalation',
    'panel.esc.title':                'ESCALATION TRACKER',
    'panel.esc.loading':              'Loading escalation data...',
    'panel.esc.api_error':            'No threat data available yet.',
    'panel.esc.current_tl':           'Current TL',
    'panel.esc.duration':             'Duration',
    'panel.esc.velocity':             'Velocity',
    'panel.esc.trend':                'Score Trend',
    'panel.esc.pattern':              'Pattern',
    'panel.esc.pattern.STABLE':       'STABLE',
    'panel.esc.pattern.ESCALATING':   'ESCALATING',
    'panel.esc.pattern.DE_ESCALATING':'DE-ESCALATING',
    'panel.esc.pattern.OSCILLATING':  'OSCILLATING',
    'panel.esc.prediction':           'Prediction',
    'panel.esc.predicted_tl':         'Next TL → {tl}',
    'panel.esc.predicted_time':       'ETA: {time}',
    'panel.esc.no_prediction':        'Insufficient data for prediction',
    'panel.esc.transitions':          'TL Transitions',
    'panel.esc.no_transitions':       'No transitions recorded',

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
    'panel.llm_intel.stat_pending':         'PENDING',
    'panel.llm_intel.stat_rejected':        'REJ.',
    'panel.llm_intel.stat_review':          'REVIEW',
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
    // Situation Board
    // ══════════════════════════════════════════════════════════════
    'tools.situation_board':              'Situation Board',
    'panel.sitboard.title':               'SITUATION BOARD',
    'panel.sitboard.loading':             'Loading situation data...',
    'panel.sitboard.no_data':             'No situation data available yet',
    'panel.sitboard.filter_all':          'ALL THEATERS',
    'panel.sitboard.dir_escalating':      'ESCALATING',
    'panel.sitboard.dir_stable':          'STABLE',
    'panel.sitboard.dir_de_escalating':   'DE-ESCALATING',
    'panel.sitboard.metric_tone':         'Media Tone',
    'panel.sitboard.metric_media':        'State Media',
    'panel.sitboard.metric_aviation':     'Civilian Aviation',
    'panel.sitboard.metric_forex':        'Currency',
    'panel.sitboard.metric_climate_active': 'Active indirect signals',
    'panel.sitboard.dir_desc_esc':        'Multiple indicators trending toward heightened tension',
    'panel.sitboard.dir_desc_deesc':      'Indicators suggest easing tension',
    'panel.sitboard.dir_desc_stable':     'No significant directional change detected',
    'panel.sitboard.clm_t2':             'Media Tempo',
    'panel.sitboard.clm_t4':             'Search Trends',
    'panel.sitboard.clm_s1':             'Aviation Rerouting',
    'panel.sitboard.clm_s2':             'Shipping Anomaly',
    'panel.sitboard.clm_s3':             'Forex Stress',
    'panel.sitboard.clm_o1':             'Cert Surge',
    'panel.sitboard.clm_o3':             'Narrative Shift',
    'panel.sitboard.sync_tip':            'Simultaneous changes detected in',
    'panel.sitboard.density_tip':         'Wire event frequency (6h)',
    'panel.sitboard.tone_hostile':        'hostile',
    'panel.sitboard.tone_negative':       'negative',
    'panel.sitboard.tone_neutral':        'neutral',
    'panel.sitboard.tone_positive':       'positive',
    'panel.sitboard.above_normal':        'above normal',
    'panel.sitboard.below_normal':        'below normal',
    'panel.sitboard.fx_weakening':        'weakening',
    'panel.sitboard.fx_strengthening':    'strengthening',
    'panel.sitboard.tip_tone':            'GDELT global media tone index',
    'panel.sitboard.tip_media':           'State-affiliated media publication rate vs baseline',
    'panel.sitboard.tip_aviation':        'Civilian flight count change from baseline',
    'panel.sitboard.tip_forex':           'Currency deviation from baseline',
    'panel.sitboard.tip_climate':         'Active indirect indicators',

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
    'tools.section.admin':            'ADMIN',

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
    'panel.history.theater':          'Theater:',
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
    'notebook.entry.noise_excluded':  'Noise exclusion added: {sensor} → {reason}',
    'threat_cls.prompt':              'Classify current threat situation:',
    'threat_cls.exercise':            'Exercise / Drill',
    'threat_cls.maintenance':         'Scheduled Maintenance',
    'threat_cls.confirmed_threat':    'Confirmed Threat',
    'threat_cls.false_positive':      'False Positive',
    'threat_cls.notes_prompt':        'Additional notes (optional):',
    'notebook.entry.threat_classified': 'Threat classified: {cls}',
    'notebook.entry.llm_credibility_adjusted': 'LLM source credibility adjusted ({cls}) — check Intel panel for review items',

    // Attack Phase Panel
    'panel.phase.title':              'PHASE & ESCALATION',
    'panel.phase.escalation':         'Escalation Status',
    'panel.phase.loading':            'Analyzing attack phase...',
    'panel.phase.no_data':            'No threat data available.',
    'panel.phase.context_alignment':  'Context Alignment',
    'panel.phase.direction':          'Signal Direction',
    'panel.phase.trend':              'Escalation Trend',
    'panel.phase.btn_classify':       'Classify Threat',
    'panel.phase.llm_intel':          'LLM Intelligence',
    'phase.0.label':                  'PHASE 0: NORMAL',
    'phase.0.desc':                   'No significant indicators. Routine monitoring.',
    'phase.1.label':                  'PHASE 1: WATCH',
    'phase.1.desc':                   'Early indicators detected. Single-domain activity.',
    'phase.2.label':                  'PHASE 2: ELEVATED',
    'phase.2.desc':                   'Multi-domain signals converging. Possible preparation.',
    'phase.3.label':                  'PHASE 3: HEIGHTENED',
    'phase.3.desc':                   'Strong adversary offensive pattern. Dual-domain convergence.',
    'phase.4.label':                  'PHASE 4: CRITICAL',
    'phase.4.desc':                   'Full convergence with infrastructure degradation. Imminent threat.',

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

  },

  // ============================================================
  // JAPANESE
  // ============================================================
  ja: {

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
    'hud.btn.intel_guide':            'インテルガイド',
    'hud.btn.config':                 '設定',
    'hud.diag.label':                 '診断',
    'hud.tooltip.settings_menu':      '設定 — インテルガイド / Config',

    // ── scenario chip (Row 1 SITUATION) ───────────────────────────
    'hud.scenario.label':             'シナリオ',
    'hud.scenario.none':              '—',
    'hud.tooltip.scenario':           'フォーカス中のシナリオ — クリックでシナリオバーへ移動して切替',

    'hud.convergence.full':           '⚡ 完全収束',
    'hud.convergence.dual':           '⚠ 2ドメイン収束',
    'hud.convergence.single':         '◉ 単一ドメイン',
    'hud.convergence.none':           '収束: —',
    'hud.label.threat_24h':           '脅威 24h:',
    'hud.tooltip.threat_24h':         '脅威レベル履歴（直近24時間 / 288サイクル）',
    'hud.label.convergence_short':    '収束:',

    'hud.vec.all':                    '全ベクター',
    'hud.vec.l3':                     'L3 大容量型',
    'hud.vec.l7':                     'L7 アプリ層型',

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
    'hud.tooltip.c2sync':             'C2同期: 複数シアターの攻撃開始が60秒以内に収束 → 国家レベルの指揮統制の証拠',
    'hud.label.chain':                'チェーン:',
    'hud.tooltip.chain_hud':          'エスカレーション順序チェーン: 24時間窓内の情報→ISR→DDoS→動態の証拠連鎖。',
    'hud.label.comms':                '通信:',
    'hud.label.triangulation':        '三角:',
    'hud.tooltip.triangulation':      '三角測量: 3ドメイン(サイバー/物理/情報)すべてが独立して異常を確認 — 最高信頼度の収束。',
    'hud.label.silent_div':           '沈黙:',
    'hud.tooltip.silent_div':         'サイレント乖離: サイバー+物理ドメインが活性化、情報ドメインが沈黙 — 紛争前の偵察/準備段階の可能性。',
    'hud.label.baseline':             '基準Z:',
    'hud.tooltip.baseline':           '基準値: シアター固有のZスコア。現在スコアがそのシアターの30日間平均と比較してどの程度乖離しているかを表示。',
    'hud.label.sys':                  'SENSOR',
    'hud.tooltip.sys_chip':           'システム状態: WS接続 + センサー稼働状況（OK / STALE / ERROR / DISABLED）',
    'hud.label.climate':              'CLIMATE',
    'hud.tooltip.tl_proximity':       'TL近接度: 現在スコアから次の脅威レベル境界までの距離',
    'tl_prox.near_esc':               '{pts}pt → TL{tl}',
    'tl_prox.near_deesc':             '{pts}pt → TL{tl}',
    'tl_prox.tooltip_up':             'エスカレーションまで{pts}ポイント (TL{tl})',
    'tl_prox.tooltip_down':           'デエスカレーションまで{pts}ポイント (TL{tl})',
    // ── HUDリデザイン追加 ────────────────────────────────────────
    'hud.tooltip.tl_duration':        '現在の脅威レベルでの滞在時間（高TLでの長期滞在は正常性バイアスを呼ぶため可視化）',
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
    // ── ハンバーガー制御パネル ───────────────────────────────────
    'hud.tooltip.hamburger':          '操作メニューを開く（ベクトル/同期/ツール/レポート/設定/言語/ユーザー）',
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

    'hud.c2sync.detected':            '検知 (+{n}pt)',
    'hud.c2sync.partial':             '部分同期 ({pct}%)',
    'hud.c2sync.no_sync':             '未同期',

    'hud.chain.full':                 '✔ 完全',
    'hud.chain.partial':              '≈ 部分',

    'hud.velocity.stable':            '安定',
    'hud.velocity.unit':              '/サイクル',

    // ══════════════════════════════════════════════════════════════
    // TOOLS dropdown
    // ══════════════════════════════════════════════════════════════
    'tools.target_visibility':        'ターゲット可視性',
    'tools.live_threat_telemetry':    'リアルタイム脅威テレメトリ',
    'tools.evidence_chain':           '証拠チェーン',
    'tools.telegram_sigint':          'Telegram SIGINT',
    'tools.threat_pulse':             '脅威パルス',
    'tools.weather_brief':            '気象ブリーフィング',
    'tools.salute_export':            'SALUTEエクスポート',
    'tools.historical_analog':        '歴史的パターン類推',
    'tools.ops_clock':                '作戦時計',
    'tools.greynoise':                'GreyNoise',
    'tools.analyst_notebook':         'アナリストノートブック',

    // ══════════════════════════════════════════════════════════════
    // Panel — common
    // ══════════════════════════════════════════════════════════════
    'panel.common.dock':              'Dock',
    'panel.common.dock_tooltip':      'サイドバーに戻す',
    'panel.common.minimize_tooltip':  '最小化',
    'panel.common.close_tooltip':     '閉じる',

    // ══════════════════════════════════════════════════════════════
    // Panel — Target Visibility
    // ══════════════════════════════════════════════════════════════
    'panel.target.title':             'ターゲット可視性',
    'panel.target.hint':              '焦点シナリオの参加国。編集は管理画面 → Scenarios から。',

    // ══════════════════════════════════════════════════════════════
    // Panel — Live Threat Telemetry
    // ══════════════════════════════════════════════════════════════
    'panel.dashboard.title':          'リアルタイム脅威テレメトリ',
    'panel.dashboard.waiting':        'APIテレメトリ待機中...',

    // ══════════════════════════════════════════════════════════════
    // Footer / status bar
    // ══════════════════════════════════════════════════════════════
    'footer.system_init':             'システム初期化中...',
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
    'modal.settings.tab.sysconfig':   'システム',
    'modal.settings.tab.users':       'ユーザー管理',

    // ── System Config tab ──────────────────────────────────────────────
    'sysconfig.help':                 '<span class="code-block">config.env</span> の設定を編集します。変更は即座にディスクに書き込まれます。<span class="cfg-live-badge">ライブ</span> の設定は即時反映、<span class="cfg-restart-badge">再起動</span> の設定は <code>docker compose restart</code> が必要です。',
    'sysconfig.section.api_keys':     'API キー',
    'sysconfig.section.scope':        'デフォルトスコープ',
    'sysconfig.scope.desc':           '起動時のフォーカスシナリオのデフォルト。参加国や敵対国はシナリオタブで管理します。',
    'sysconfig.field.default_focused_scenario': 'デフォルトフォーカスシナリオ',
    'sysconfig.adv_toggle':           '\u25b6 詳細設定',
    'sysconfig.adv_toggle_open':      '\u25bc 詳細設定',
    'sysconfig.adv_warning':          '\u26a0 不適切な値を設定するとシステムが正常に動作しなくなる可能性があります。影響を理解した上で変更してください。',
    'sysconfig.section.network':      'ネットワーク / SSL',
    'sysconfig.field.ssl_enabled':    '有効',
    'sysconfig.field.ssl_disabled':   '無効',
    'sysconfig.section.cache':        'キャッシュ &amp; ポーリング',
    'sysconfig.field.cache_expiry':   'キャッシュ有効期限（秒）',
    'sysconfig.field.opensky_int':    'OpenSky 最小間隔（秒）',
    'sysconfig.field.narrative_int':  'ナラティブ ポーリング間隔（秒）',
    'sysconfig.field.telegram_int':         'Telegram ポーリング間隔（秒）',
    'sysconfig.field.telegram_kw':          'Telegram 攻撃キーワード',
    'sysconfig.field.telegram_conf_thresh': 'Telegram 主張信頼度しきい値',
    'sysconfig.field.checkhost_int':        'Check-Host ポーリング間隔（秒）',
    'sysconfig.field.checkhost_to':   'Check-Host タイムアウト（ms）',
    'sysconfig.field.checkhost_nodes':'Check-Host ノード',
    'sysconfig.section.threat':       '脅威スコアリング',
    'sysconfig.field.air_anomaly':    '空域異常閾値（比率）',
    'sysconfig.field.air_closure':    '空域閉鎖閾値（比率）',
    'sysconfig.field.air_window':     '空域ベースライン ウィンドウ（サイクル）',
    'sysconfig.field.gdelt_tone':     'GDELT トーン警告閾値',
    'sysconfig.field.gdelt_history':  'GDELT 履歴ウィンドウ（日）',
    'sysconfig.field.conv_dual':      '二重収束ボーナス',
    'sysconfig.field.conv_full':      '完全収束ボーナス',
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
    'sysconfig.restart_note':         '\u26a0 一部の設定は再起動が必要です（docker compose restart）',
    'sysconfig.section.llm':          'LLMインテリジェンス',
    'sysconfig.help.llm_desc':        'Ollama のローカル起動が必要。Docker内（Mac/Windows）では hostname に host.docker.internal を使用。',
    'sysconfig.field.llm_enabled':    'LLM 有効',
    'sysconfig.field.llm_host':       'Ollama ホスト',
    'sysconfig.field.llm_model':      'モデル',
    'sysconfig.field.llm_timeout':    'リクエストタイムアウト（秒）',
    'sysconfig.section.llm_thresholds': 'インテルキュー閾値',
    'sysconfig.field.llm_auto_threshold': '自動承認閾値',
    'sysconfig.help.llm_auto_threshold':  'この信頼度以上 \u2192 AUTO-CONFIRMED（アナリスト審査不要）',
    'sysconfig.field.llm_min_confidence': '最低信頼度',
    'sysconfig.help.llm_min_confidence':  'これ未満のアイテムは破棄',
    'sysconfig.field.llm_override_window': '取消可能時間（秒）',
    'sysconfig.help.llm_override_window':  'AUTO-CONFIRMEDアイテムの取消可能な時間',
    'sysconfig.field.llm_pending_auto_reject': '保留自動拒否（時間）',
    'sysconfig.help.llm_pending_auto_reject':  '未確認のPENDINGアイテムを自動拒否するまでの時間（0＝無効）',
    'sysconfig.field.intel_retention': 'インテル保持期間（日）',
    'sysconfig.field.intel_age_decay_enabled': '経時減衰 (ADR-023)',
    'sysconfig.help.intel_age_decay_enabled':  'confirm 後の寄与を経過時間で指数関数的に減衰（confirm/TTL の段差を平滑化）',
    'sysconfig.field.intel_age_decay_tau':     '減衰時定数 \u03c4（時間）',
    'sysconfig.help.intel_age_decay_tau':      '重み=1/e @age=\u03c4、\u22480.14 @2\u00b7\u03c4、\u22480.05 @3\u00b7\u03c4。既定 12h \u2248 1勤務シフト',
    'sysconfig.llm.fetch_models':     'モデル取得 \u21ba',
    'sysconfig.llm.fetching':         '取得中...',
    'sysconfig.llm.no_models':        'モデルが見つかりません — Ollama は起動していますか？',
    'sysconfig.llm.models_loaded':    '\u2713 {n} 件のモデルを読み込みました',
    'sysconfig.llm.fetch_error':      '\u2717 {msg}',
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
    'modal.country.close':            '[ X ] 閉じる',

    // ══════════════════════════════════════════════════════════════
    // SITREP modal
    // ══════════════════════════════════════════════════════════════
    'modal.sitrep.title':             '状況報告（SITREP）— 脅威レベル評価',
    'modal.sitrep.close':             '[ X ] 閉じる',
    'modal.sitrep.timeline_label':    '脅威レベルタイムライン（直近288サイクル）',
    'modal.sitrep.report_label':      '自動生成レポート',

    // ══════════════════════════════════════════════════════════════
    // Evidence modal
    // ══════════════════════════════════════════════════════════════
    'modal.evidence.title':           '分析根拠 — 証拠パネル',
    'modal.evidence.close':           '[ X ] 閉じる',
    'modal.evidence.section_convergence': '収束スコア内訳',
    'modal.evidence.section_assessment':  'システム評価',
    'modal.evidence.section_rationale':   'センサー根拠マトリクス',
    'modal.evidence.th_sensor':       'センサー',
    'modal.evidence.th_domain':       'ドメイン',
    'modal.evidence.th_status':       '状態',
    'modal.evidence.th_observed':     '観測値',
    'modal.evidence.th_score':        'スコア',
    'modal.evidence.th_confidence':   '信頼度',
    'modal.evidence.th_reason':       '発火理由 / 備考',
    'modal.evidence.noise_filters':   '適用ノイズフィルター:',
    'modal.evidence.btn_salute':      'SALUTEレポート出力',
    'modal.evidence.btn_sitrep':      'SITREPを表示',
    'modal.evidence.no_filters':      'なし',
    'modal.evidence.system_note_label': 'システムノート',
    'modal.evidence.convergence_score': '収束スコア:',

    // ══════════════════════════════════════════════════════════════
    // Intel Guide modal
    // ══════════════════════════════════════════════════════════════
    'modal.help.title':               'インテリジェンス運用ガイド — MDO C4ISR 戦略レーダー',
    'modal.help.close':               '[ X ] 閉じる',
    'modal.help.ch1':                 '1. センサー',
    'modal.help.ch2':                 '2. マップ',
    'modal.help.ch3':                 '3. スコア',
    'modal.help.ch4':                 '4. 脅威 Lv.',
    'modal.help.ch5':                 '5. 校正',
    'modal.help.ch6':                 '6. ワークフロー',
    'modal.help.ch7':                 '7. 設定',
    'modal.help.ch8':                 '8. 直感UI',
    'modal.help.ch9':                 '9. API参照',
    'modal.help.ch10':                '10. 管理',
    'modal.help.ch11':                '11. 限界と方向性',

    // ══════════════════════════════════════════════════════════════
    // Panel — Operational Clock
    // ══════════════════════════════════════════════════════════════
    'panel.clock.title':              '作戦時計',
    'clock.local_prefix':             '現地時刻: ',
    'clock.last_event':               '最終イベント: {m}分 {s}秒前',

    // ══════════════════════════════════════════════════════════════
    // Panel — Weather Brief
    // ══════════════════════════════════════════════════════════════
    'panel.weather.title':            '作戦気象ブリーフ',

    // ══════════════════════════════════════════════════════════════
    // Panel — SALUTE Report
    // ══════════════════════════════════════════════════════════════
    'panel.salute.title':             'SALUTE 報告書',
    'panel.salute.btn_close':         '[ X ] 閉じる',
    'panel.salute.btn_copy':          'コピー',
    'panel.salute.btn_download':      'ダウンロード',
    'panel.salute.copied':            'SALUTE報告書をクリップボードにコピーしました',
    'panel.salute.cross_ref':         '相互参照',

    // ══════════════════════════════════════════════════════════════
    // Panel — Historical Analog
    // ══════════════════════════════════════════════════════════════
    'panel.ha.title':                 '歴史的パターン類推',
    'ha.accumulating':                'データ蓄積中...',
    'ha.note':                        'ピアソン相関係数 — 直近20サイクル vs 既知イベント',

    // ══════════════════════════════════════════════════════════════
    // Panel — Threat Pulse
    // ══════════════════════════════════════════════════════════════
    'panel.pulse.title':              '脅威パルス',

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
    'chain.llm_intel.active':         '件確認済',
    'chain.llm_intel.review':         '件要確認',
    'chain.llm_intel.none':           '—',

    'chain.seq.full_chain':           '✔ チェーン完全確認',
    'chain.seq.partial':              '≈ チェーン部分確認',
    'chain.seq.none':                 '活動中のシーケンスチェーンなし',

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

    'chain.maskirovka.title':         '⚠ 欺瞞工作 (MASKIROVKA) 検知',
    'chain.infra_check.label':        'インフラ確認 — ノード: {n}',
    'chain.telegram_monitor.label':   'Telegram監視 — {n}チャンネル',
    'chain.telegram_monitor.targets': '標的URL:',

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
    'gn.result.cached':               '[cached]',
    'gn.log.no_lookups':              'ルックアップ履歴なし。',
    'gn.log.noise':                   'ノイズ',
    'gn.log.targeted':                '標的',
    'gn.no_theater_data':             'シアターデータなし',

    // ══════════════════════════════════════════════════════════════
    // Analyst Notebook
    // ══════════════════════════════════════════════════════════════
    'notebook.no_entries':            'エントリなし。\nアセスメント、IPルックアップ、センサーミュートは自動記録されます。',
    'notebook.export.header':         '=== アナリストノートブック エクスポート ===',
    'notebook.export.generated':      '生成日時: {iso}',
    'notebook.export.assessment':     'アセスメント: {a} | 確信度: {c}',
    'notebook.export.watch_for':      '監視対象: {text}',
    'notebook.export.shift_log':      '--- シフトログ ---',
    'notebook.export.copied':         'コピー済み',
    'notebook.confirm.clear':         'ノートブックの全エントリを消去しますか？この操作は取り消せません。',
    'notebook.entry.sensor_unmuted':  'センサーミュート解除: {name}',
    'notebook.entry.sensor_muted':    'センサーミュート: {name}',
    'notebook.entry.ip_noise':        'ノイズ',
    'notebook.entry.ip_targeted':     '標的',
    'notebook.entry.defcon':          '脅威レベル {dir} {from} → {to} (スコア: {score})',

    // ══════════════════════════════════════════════════════════════
    // Sensor config / mute
    // ══════════════════════════════════════════════════════════════
    'sensor.mute.prompt':             'センサーをミュート: {name}\n理由（任意 — アナリストノートブックに記録されます）:',
    'sensor.toggle.enabled':          '有効',
    'sensor.toggle.disabled':         '無効',
    'sensor.no_sensors':              '登録済みセンサーなし。',
    'sensor.load_error':              'センサー設定の読み込みに失敗: {msg}',

    // ══════════════════════════════════════════════════════════════
    // Evidence panel
    // ══════════════════════════════════════════════════════════════
    'evidence.btn.mute':              'ミュート',
    'evidence.btn.unmute':            'ミュート解除',
    'evidence.suppressed':            '抑制中: {reason}',
    'evidence.no_data':               '根拠データなし。',
    'evidence.no_system_note':        'システムノートなし。',

    // ══════════════════════════════════════════════════════════════
    // SITREP cards
    // ══════════════════════════════════════════════════════════════
    'sitrep.card.threat_now':         '現在の脅威',
    'sitrep.card.threat_1h':          '直近1時間の脅威範囲',
    'sitrep.card.convergence':        '収束状態',
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
    // Country Intel Panel
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
    'cip.theater_label':              '(担当正面: {name})',
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
    'map.net.status_prefix':          'Net: ',
    'map.net.tooltip_prefix':         'ネット状態: ',
    'map.shift_badge':                'L7シフト{actors}',
    'map.shift_tooltip':              '発信元別 L7 シフト検知:{actors}',
    'map.state_asn_badge':            '国家系ASN',
    'map.state_asn_tooltip':          '国家帰属ASN検知:\n{asns}',
    'map.new_actor_badge':            '新規',
    'map.new_actor_tooltip':          '7日ベースラインなし: 新規インフラ',
    'map.target_tooltip':             '{info} | グローバル: {pct}% | ネット: {net}',
    'map.no_threats_vector':          'このベクターに重大な脅威なし。',
    'map.no_threats':                 '重大な脅威を検出せず。',

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

    'map.tooltip.airspace':           '{airport}: {pct}%減少 ({count}/{base}機)',
    'map.tooltip.weather':            '{desc} — 風速 {wind}m/s',

    // ══════════════════════════════════════════════════════════════
    // Data fetch log panel
    // ══════════════════════════════════════════════════════════════
    'fetchlog.last_refreshed':        '最終更新: {time}',
    'fetchlog.grid.last_fetch':       '最終取得',
    'fetchlog.grid.duration':         '所要時間',
    'fetchlog.grid.http_status':      'HTTPステータス',
    'fetchlog.grid.cache_age':        'キャッシュ経過',
    'fetchlog.history_label':         '履歴（新しい順→）:',
    'fetchlog.no_data':               'データなし',
    'fetchlog.load_error':            'フェッチログの読み込みに失敗: {msg}',
    'fetchlog.tooltip.ok':            '\nステータス: OK\n{error}',
    'fetchlog.tooltip.error':         '\nステータス: エラー\n{error}',

    // ══════════════════════════════════════════════════════════════
    // Radio Silence indicator
    // ══════════════════════════════════════════════════════════════
    'rs.live_text':                   'ライブ',
    'rs.quiet_text':                  '静寂',
    'rs.tooltip.live':                '通信活発: 全センサー正常報告中。異常な静寂なし。',
    'rs.tooltip.quiet':               '無線封鎖: スコア≥3だが速度=0。\nセンサー抑制または作戦前通信封鎖の可能性あり。\nアナリストによる確認を推奨。',

    // ══════════════════════════════════════════════════════════════
    // Dashboard empty states
    // ══════════════════════════════════════════════════════════════
    'dash.no_active_pins':            '焦点シナリオがありません。管理画面 → Scenarios で選択してください。',

    // ══════════════════════════════════════════════════════════════
    // Survival HUD
    // ══════════════════════════════════════════════════════════════
    'survival.tooltip.header':        'INFRA LIVENESS  [{status}  {pct}%]',
    'survival.asphyx_note':           '⚠ アスフィキシエーション検知\n  成功率=100%だが遅延が3×ベースライン以上\n  CDNがパケットロスを隠蔽中 — インフラ圧迫',

    // ══════════════════════════════════════════════════════════════
    // Tools menu — additional items
    // ══════════════════════════════════════════════════════════════
    'tools.history_analysis':         '履歴分析',
    'tools.user_management':          'ユーザー管理',
    'tools.whatif_sim':               'What-Ifシミュレーション',
    'tools.spof_analysis':            'SPOF分析',
    'tools.action_plan':              'アクションプラン',

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
    // Action Plan panel
    // ══════════════════════════════════════════════════════════════
    'panel.ap.title':                 'アクションプラン',
    'panel.ap.current':               '現在',
    'panel.ap.all_clear':             '異常なし — 以下のエスカレーション手順を確認してください。',
    'panel.ap.llm_context':           'LLMインテルコンテキスト',
    'ap.intel.theater_prefix':        '[{t}]',
    'panel.ap.tl5.monitor':           '通常のOSINT監視サイクルを維持',
    'panel.ap.tl5.baseline':          'HODベースラインデータ収集が有効か確認',
    'panel.ap.tl5.review':            '週次でセンサー健全性ダッシュボードをレビュー',
    'panel.ap.tl4.watch':             '監視頻度を15分間隔に増加',
    'panel.ap.tl4.analytics':         'Deep Analyticsで異常を確認',
    'panel.ap.tl4.notify':            '当直アナリストに状態変化を通知',
    'panel.ap.tl4.log':               'アナリストノートブックに観察記録を開始',
    'panel.ap.tl3.rate_limit':        '重要エンドポイントにCDNレート制限を適用',
    'panel.ap.tl3.cdn':               'CDN/WAFルールが最新か確認',
    'panel.ap.tl3.increase_polling':  '5分間隔ポーリングに切替（SYNCモード）',
    'panel.ap.tl3.soc_alert':         'SOCチームに警戒態勢を通知',
    'panel.ap.tl3.backup_dns':        'バックアップDNS設定を有効化',
    'panel.ap.tl2.failover':          'インフラのフェイルオーバー準備（スタンバイ起動）',
    'panel.ap.tl2.escalate':          '上級幹部/当直責任者にエスカレーション',
    'panel.ap.tl2.lockdown':          '重要システムのアクセス制御を強化',
    'panel.ap.tl2.coordinate':        'ISP/上流プロバイダと連携',
    'panel.ap.tl2.ir_prep':           'インシデントレスポンスチームとプレイブックを待機',
    'panel.ap.tl2.geo_block':         '敵対国ASNのジオブロッキングを検討',
    'panel.ap.tl1.ir_activate':       'インシデントレスポンス手順を発動',
    'panel.ap.tl1.report':            'CERT/関係当局に報告',
    'panel.ap.tl1.isolate':           '侵害されたネットワークセグメントを隔離',
    'panel.ap.tl1.backup_comm':       'バックアップ通信チャネルに切替',
    'panel.ap.tl1.evidence':          'フォレンジック証拠保全を開始',
    'panel.ap.tl1.full_staff':        'SOC全員召集 — 総員配置',
    'panel.ap.tl1.null_route':        '攻撃トラフィックのnull-route/ブラックホール展開',

    // ══════════════════════════════════════════════════════════════
    // Escalation Tracker panel (Phase 2)
    // ══════════════════════════════════════════════════════════════
    'tools.phase_escalation':         'フェーズ＆エスカレーション',
    'panel.esc.title':                'エスカレーショントラッカー',
    'panel.esc.loading':              'エスカレーションデータを読み込み中...',
    'panel.esc.api_error':            '脅威データがまだありません。',
    'panel.esc.current_tl':           '現在のTL',
    'panel.esc.duration':             '持続時間',
    'panel.esc.velocity':             '速度',
    'panel.esc.trend':                'スコアトレンド',
    'panel.esc.pattern':              'パターン',
    'panel.esc.pattern.STABLE':       '安定',
    'panel.esc.pattern.ESCALATING':   'エスカレーション中',
    'panel.esc.pattern.DE_ESCALATING':'デエスカレーション中',
    'panel.esc.pattern.OSCILLATING':  '振動',
    'panel.esc.prediction':           '予測',
    'panel.esc.predicted_tl':         '次のTL → {tl}',
    'panel.esc.predicted_time':       '予想到達: {time}',
    'panel.esc.no_prediction':        '予測に必要なデータが不足',
    'panel.esc.transitions':          'TL遷移履歴',
    'panel.esc.no_transitions':       '遷移記録なし',

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
    // Phase 3: 相関ヒートマップパネル
    // ══════════════════════════════════════════════════════════════
    'tools.corr_heatmap':             '相関ヒートマップ',
    'panel.corr.title':               'センサー × シアター',
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
    // LLMインテリジェンスパネル
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
    'panel.llm_intel.filter_convergence':   '収束',
    'panel.llm_intel.filter_corroborated':  '複合確認',
    'panel.llm_intel.filter_triage':        'トリアージ',
    'panel.llm_intel.triage_empty':         '審査待ちのインテルはありません。',
    'panel.llm_intel.triage_showing':       '表示中',
    'panel.llm_intel.triage_scenario':      'シナリオ',
    'panel.llm_intel.triage_no_scenario':   'シナリオ結合なし — 国タグがアクティブシナリオ参加国と一致しません。',
    'panel.llm_intel.triage_corroborated':  '裏付け',
    'panel.llm_intel.triage_coupling_tip':  '参加重み × ソース信頼度。値が大きいほどこのシナリオへの作戦的影響が高い。',
    'panel.llm_intel.triage_cred_tip':      'ソース信頼度（0.30〜0.95）。自動承認には ≥ 0.75 が必要。',
    'panel.llm_intel.gate.low_confidence':       '信頼度不足',
    'panel.llm_intel.gate.low_confidence_tip':   'LLM信頼度が自動承認閾値（0.80）未満。スコア反映には手動承認が必要。',
    'panel.llm_intel.gate.low_source_credibility':     'ソース信頼度不足',
    'panel.llm_intel.gate.low_source_credibility_tip': 'ソース信頼度が0.75未満。実績が積み上がるまで自動承認は保留。',
    'panel.llm_intel.gate.ecosystem_blocked':       'エコシステム拒否',
    'panel.llm_intel.gate.ecosystem_blocked_tip':   'ソースのエコシステム（国家系メディア等）が自動承認の拒否リスト。手動審査必須。',
    'panel.llm_intel.gate.ecosystem_unclassified':     'エコシステム不明',
    'panel.llm_intel.gate.ecosystem_unclassified_tip': 'ソースのエコシステム未分類。フェイル・クローズ方針により既知信頼系のみ自動承認。',
    'panel.llm_intel.gate.manual_review':       '手動審査',
    'panel.llm_intel.gate.manual_review_tip':   '全ゲートを通過していますがアナリスト確認が必要です。',
    'panel.llm_intel.pulse_tip':            '高優先度の滞留トリアージ {n} 件あり。最古経過: {h}h。',
    'panel.llm_intel.stat_pending':         '審査待ち',
    'panel.llm_intel.stat_rejected':        '却下',
    'panel.llm_intel.stat_review':          '要確認',
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
    'panel.llm_intel.diag_title':           '診断',
    'panel.llm_intel.diag_empty':           'このウィンドウ内にLLM呼出なし',
    'panel.llm_intel.diag_col_sensor':      'センサー',
    'panel.llm_intel.diag_col_calls':       '呼出',
    'panel.llm_intel.diag_col_auto':        '自動',
    'panel.llm_intel.diag_col_pending':     '保留',
    'panel.llm_intel.diag_col_filtered':    'フィルタ',
    'panel.llm_intel.diag_col_dedup':       '重複',
    'panel.llm_intel.diag_col_err':         'エラー',
    'panel.llm_intel.diag_col_conf':        '信頼',
    'panel.llm_intel.diag_col_ms':          'ms',
    'panel.llm_intel.diag_breakdown_title': 'センサー層フィルタ内訳',
    // ══════════════════════════════════════════════════════════════
    // 戦略的環境気候フィード
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
    // 情勢ボード
    // ══════════════════════════════════════════════════════════════
    'tools.situation_board':              '情勢ボード',
    'panel.sitboard.title':               '情勢ボード',
    'panel.sitboard.loading':             '情勢データを読み込み中...',
    'panel.sitboard.no_data':             '情勢データはまだありません',
    'panel.sitboard.filter_all':          '全シアター',
    'panel.sitboard.dir_escalating':      'エスカレーション中',
    'panel.sitboard.dir_stable':          '安定',
    'panel.sitboard.dir_de_escalating':   'デエスカレーション中',
    'panel.sitboard.metric_tone':         'メディア論調',
    'panel.sitboard.metric_media':        '国営メディア',
    'panel.sitboard.metric_aviation':     '民間航空',
    'panel.sitboard.metric_forex':        '通貨',
    'panel.sitboard.metric_climate_active': '活性化中の間接指標',
    'panel.sitboard.dir_desc_esc':        '複数の指標が緊張の高まりを示唆',
    'panel.sitboard.dir_desc_deesc':      '指標は緊張の緩和を示唆',
    'panel.sitboard.dir_desc_stable':     '有意な方向性の変化なし',
    'panel.sitboard.clm_t2':             'メディアテンポ',
    'panel.sitboard.clm_t4':             '検索トレンド',
    'panel.sitboard.clm_s1':             '航空回避',
    'panel.sitboard.clm_s2':             '船舶異常',
    'panel.sitboard.clm_s3':             '為替ストレス',
    'panel.sitboard.clm_o1':             '証明書急増',
    'panel.sitboard.clm_o3':             'ナラティブシフト',
    'panel.sitboard.sync_tip':            '同時変化を検出：',
    'panel.sitboard.density_tip':         'ワイヤーイベント頻度（6時間）',
    'panel.sitboard.tone_hostile':        '敵対的',
    'panel.sitboard.tone_negative':       'ネガティブ',
    'panel.sitboard.tone_neutral':        '中立',
    'panel.sitboard.tone_positive':       'ポジティブ',
    'panel.sitboard.above_normal':        '通常以上',
    'panel.sitboard.below_normal':        '通常以下',
    'panel.sitboard.fx_weakening':        '下落',
    'panel.sitboard.fx_strengthening':    '上昇',
    'panel.sitboard.tip_tone':            'GDELTグローバルメディア論調指数',
    'panel.sitboard.tip_media':           '国営メディア発行レート vs 基準値',
    'panel.sitboard.tip_aviation':        '民間航空便数の基準値からの変化',
    'panel.sitboard.tip_forex':           '通貨の基準値からの偏差',
    'panel.sitboard.tip_climate':         '活性化中の間接指標',

    // エビデンスパネル：寄与率ウォーターフォール＆反証
    'evidence.wf_bonus':                  '収束ボーナス',
    'evidence.counter_signals':           '反証シグナル（正常な読み取り値）',
    'evidence.intel_gaps':                'インテリジェンスギャップ（オフラインセンサー）',
    'evidence.gap_never':                 'データなし',
    'evidence.gap_last_data':             '最終取得',

    // センサーヘルス：サーキットブレーカー
    'sensor.health.circuit_open':             'サーキットオープン（自動一時停止）',
    'sensor.health.circuit_open_persistent':  'サーキットオープン — 複数回のリカバリプローブ失敗',

    // Phase 3: TOOLSメニューセクション
    'tools.section.core':             'コア',
    'tools.section.analytics':        'アナリティクス',
    'tools.section.simulation':       'シミュレーション',
    'tools.section.admin':            '管理',

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
    'panel.history.theater':          'シアター：',
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

    // ── Threat level labels (HUD) ──────────────────────────────
    'threat_lv.5':                    '脅威 Lv 5: 正常',
    'threat_lv.4':                    '脅威 Lv 4: 警戒',
    'threat_lv.3':                    '脅威 Lv 3: 高',
    'threat_lv.2':                    '脅威 Lv 2: 深刻',
    'threat_lv.1':                    '脅威 Lv 1: 危機的',

    // ── Telegram SIGINT status ────────────────────────────────
    'tg.hud.intent':                  '意図検知 ({n} ch)',
    'tg.hud.targets_found':           '標的確認',
    'tg.hud.clear':                   '異常なし',

    // ── Unit labels ───────────────────────────────────────────
    'unit.aircraft':                  '{n} 機',
    'unit.vessels':                   '{n} 隻',

    // ── Telemetry badges / tooltips ────────────────────────────
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
    'tooltip.state_asn':              '国家帰属ASN検出:\n{asns}',
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

    // ── ISR / map popups ─────────────────────────────────────
    'map.popup.isr_track':            '▲ ISR 追跡',
    'map.popup.isr_callsign':         'コールサイン: {cs}',
    'map.popup.isr_alt_speed':        '高度: {alt} km  |  速度: {spd} kt',
    'map.popup.isr_squawk':           'スコーク: {sq}',

    // ── CIP panel extra labels ────────────────────────────────
    'cip.label.baseline_28d':         'ベースライン(28日): {base}  Δ {delta}',

    // ── Config save status ────────────────────────────────────
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
    'evidence.convergence_score':     '収束スコア',
    'evidence.none':                  'なし',
    'evidence.dir_counter_label':     '敵対:{adv} 友軍:{frd} 対象:{tgt}',
    'evidence.wf_legend.cyber':       'サイバー',
    'evidence.wf_legend.phys':        '物理',
    'evidence.wf_legend.info':        '情報',
    'evidence.wf_legend.bonus':       'ボーナス',
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
    'notebook.entry.noise_excluded':  'ノイズ除外追加: {sensor} → {reason}',
    'threat_cls.prompt':              '現在の脅威状況を分類:',
    'threat_cls.exercise':            '演習 / 訓練',
    'threat_cls.maintenance':         '定期保守',
    'threat_cls.confirmed_threat':    '確認済み脅威',
    'threat_cls.false_positive':      '誤検知',
    'threat_cls.notes_prompt':        '追加メモ（任意）:',
    'notebook.entry.threat_classified': '脅威分類: {cls}',
    'notebook.entry.llm_credibility_adjusted': 'LLMソース信頼度更新 ({cls}) — Intelパネルで要確認アイテムを確認してください',

    // Attack Phase Panel
    'panel.phase.title':              'フェーズ＆エスカレーション',
    'panel.phase.escalation':         'エスカレーション状況',
    'panel.phase.loading':            '攻撃フェーズを分析中...',
    'panel.phase.no_data':            '脅威データなし',
    'panel.phase.context_alignment':  '文脈整合度',
    'panel.phase.direction':          'シグナル方向性',
    'panel.phase.trend':              'エスカレーション傾向',
    'panel.phase.btn_classify':       '脅威を分類',
    'panel.phase.llm_intel':          'LLMインテリジェンス',
    'phase.0.label':                  'フェーズ0: 通常',
    'phase.0.desc':                   '有意な兆候なし。通常監視。',
    'phase.1.label':                  'フェーズ1: 注意',
    'phase.1.desc':                   '初期兆候を検出。単一ドメインの活動。',
    'phase.2.label':                  'フェーズ2: 警戒',
    'phase.2.desc':                   '複数ドメインのシグナルが収束。準備段階の可能性。',
    'phase.3.label':                  'フェーズ3: 高脅威',
    'phase.3.desc':                   '強い敵性攻勢パターン。二重ドメイン収束。',
    'phase.4.label':                  'フェーズ4: 危機',
    'phase.4.desc':                   '完全収束とインフラ劣化。脅威が差し迫っている。',

    // ══════════════════════════════════════════════════════════════
    // Phase C: 新規センサー S1-S7
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
    'sensor.gps_jamming.desc':        '戦域付近のGPS妨害/スプーフィング検知',
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
    // Phase A-D: velocity, patterns, C-lite evaluation
    'scenario.pattern.silent_div':     'サイレント乖離',
    'scenario.pattern.silent_div_tip': 'サイレント乖離: サイバーと物理信号が活発だが情報ドメインの報道がない — 典型的な開戦前兆パターン',
    'scenario.pattern.ctx_align_tip':  'コンテキスト整合: 3軸以上（時間・空間・対象・方向）が収斂 — 偶然ではなく相関した信号',
    'scenario.eta_tip':                '現在の速度での次の脅威レベルへの推定到達時間',
    'scenario.clite.title':            'C-lite 評価',
    'scenario.clite.load_btn':         'C-lite評価を読み込む',
    'scenario.clite.switches':         '切替回数',
    'scenario.clite.misses':           'ミス',
    'scenario.clite.miss_rate':        'ミス率',
    'scenario.clite.avg_delta':        '平均Δ',
    'scenario.clite.max_delta':        '最大Δ',
    'scenario.clite.by_scenario':      'シナリオ別',
    'scenario.clite.scenario':         'シナリオ',
    'scenario.clite.rec_lite_sufficient':    'LITEモードで十分 — バックグラウンドのミス率は低い',
    'scenario.clite.rec_consider_c_medium':  'C-MEDIUMを検討 — バックグラウンドのミス率が15%超過',
    'scenario.clite.rec_insufficient_data':  'データ不足 — 評価には更なるフォーカス切替が必要',

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

  },
};

// ============================================================
// i18n runtime
// ============================================================

let _currentLang = localStorage.getItem('ddos_radar_lang') || 'en';

/**
 * Translate a key with optional placeholder substitution.
 * _t('map.popup.firms_code', { code: 'JP' }) → 'Code: JP'
 */
function _t(key, vars) {
  const dict = LANG[_currentLang] || LANG['en'];
  let str = dict[key];
  if (str === undefined) {
    // Fallback to English
    str = LANG['en'][key];
    if (str === undefined) return key;  // return key itself as last resort
  }
  if (vars) {
    Object.entries(vars).forEach(([k, v]) => {
      str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), v);
    });
  }
  return str;
}

/**
 * Apply translations to all data-i18n elements in the DOM.
 * Elements with data-i18n-html get innerHTML updated (safe for trusted strings).
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

/**
 * Set active language, persist to localStorage, re-render static text,
 * and trigger a full data re-render so JS-generated strings update.
 */
function setLang(lang) {
  if (!LANG[lang]) return;
  _currentLang = lang;
  document.documentElement.lang = lang;
  localStorage.setItem('ddos_radar_lang', lang);

  // Update EN/JP lang selector buttons
  const btnEn = document.getElementById('lang-btn-en');
  const btnJa = document.getElementById('lang-btn-ja');
  if (btnEn) btnEn.classList.toggle('lang-active', lang === 'en');
  if (btnJa) btnJa.classList.toggle('lang-active', lang === 'ja');

  // Re-apply static translations
  _applyStaticTranslations();

  // Switch INTEL GUIDE chapter visibility
  const guide = document.getElementById('help-modal');
  if (guide) {
    guide.querySelectorAll('.guide-lang-en').forEach(el => {
      el.style.display = lang === 'en' ? '' : 'none';
    });
    guide.querySelectorAll('.guide-lang-ja').forEach(el => {
      el.style.display = lang === 'ja' ? '' : 'none';
    });
  }

  // Re-render dynamic content if data is available
  if (typeof renderTelemetry === 'function' && typeof latestData !== 'undefined' && latestData) {
    renderTelemetry(latestData);
  }
  if (typeof updateChainPanel === 'function' && typeof latestData !== 'undefined' && latestData) {
    const strat = (latestData.strategic_alert || {});
    updateChainPanel(strat);
  }
  if (typeof renderWeatherBrief === 'function') renderWeatherBrief();
  if (typeof renderSaluteBoard === 'function') renderSaluteBoard();
  if (typeof renderNbLog === 'function') renderNbLog();
  if (typeof renderGnLog === 'function') renderGnLog();
}

// Apply static translations and init lang buttons on first load
document.addEventListener('DOMContentLoaded', () => {
  _applyStaticTranslations();
  const btnEn = document.getElementById('lang-btn-en');
  const btnJa = document.getElementById('lang-btn-ja');
  if (btnEn) btnEn.classList.toggle('lang-active', _currentLang === 'en');
  if (btnJa) btnJa.classList.toggle('lang-active', _currentLang === 'ja');

  // Apply guide language visibility for persisted language (e.g. Japanese saved from last session)
  // Without this, guide-lang-ja divs remain display:none from HTML even when Japanese is selected
  const guide = document.getElementById('help-modal');
  if (guide) {
    guide.querySelectorAll('.guide-lang-en').forEach(el => {
      el.style.display = _currentLang === 'en' ? '' : 'none';
    });
    guide.querySelectorAll('.guide-lang-ja').forEach(el => {
      el.style.display = _currentLang === 'ja' ? '' : 'none';
    });
  }
});
