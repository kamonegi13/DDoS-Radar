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
    'hud.btn.sitrep':                 'SITREP',
    'hud.btn.intel_guide':            'Intel Guide',
    'hud.btn.config':                 'Config',
    'hud.btn.lang':                   'JA',

    'hud.tooltip.chain':              'Evidence Chain Timeline — Escalation Sequence Viewer',
    'hud.tooltip.tools':              'Intuition Tools — RPD Analysis Panels',
    'hud.tooltip.sync':               'Force data sync',

    // ── threat meter (static text within HUD) ─────────────────────
    'hud.threat.click_hint':          'Click to view Analytic Rationale',

    // ── convergence label (JS-generated) ──────────────────────────
    'hud.convergence.full':           '⚡ FULL CONVERGENCE',
    'hud.convergence.dual':           '⚠ DUAL DOMAIN',
    'hud.convergence.single':         '◉ SINGLE DOMAIN',
    'hud.convergence.none':           'CONVERGENCE: —',
    'hud.label.threat_24h':           'THREAT 24h:',
    'hud.tooltip.threat_24h':         'Threat Level History (last 24 hours / 288 cycles)',
    'hud.label.epicenter':            'Epicenter:',

    // ── vector buttons ────────────────────────────────────────────
    'hud.vec.all':                    'ALL VECTORS',
    'hud.vec.l3':                     'L3 VOLUMETRIC',
    'hud.vec.l7':                     'L7 APPLICATION',

    // ── bottom row labels ─────────────────────────────────────────
    'hud.label.overlap':              'Overlap:',
    'hud.label.l7_shift':             'L7 Shift:',
    'hud.label.strikes':              'Strikes:',
    'hud.label.bgp':                  'BGP:',
    'hud.label.multi_front':          'Multi-Front:',
    'hud.label.velocity':             'VELOCITY:',
    'hud.tooltip.velocity':           'Rate of Escalation (1st derivative of threat score). Destroys Normalcy Bias by showing DIRECTION of change.',
    'hud.ambush.text':                '⚡ AMBUSH',
    'hud.tooltip.ambush':             'Ambush Pattern: 2nd derivative Z-Score spike indicating exponential escalation.',
    'hud.label.blockade':             'BLOCKADE:',
    'hud.tooltip.blockade':           'Blockade Index = DDoS Intensity / Network Reachability. Distinguishes Political Noise from Real Infrastructure Neutralization.',
    'hud.label.survival':             'SURVIVAL:',
    'hud.tooltip.survival':           'SURVIVAL: Check-Host.net real liveness check for key infrastructure. OK=all nodes reachable / PARTIAL=partial outage / BLACKOUT=all nodes unreachable',
    'hud.label.c2sync':               'C2-SYNC:',
    'hud.tooltip.c2sync':             'C2 SYNC: Multiple theater attack onsets converge within 60 s → evidence of nation-state command and control',
    'hud.label.chain':                'CHAIN:',
    'hud.tooltip.chain_hud':          'Escalation Sequence Chain: Evidence chain of Narrative→ISR→DDoS→Kinetic within 24h window.',
    'hud.label.comms':                'COMMS:',
    'hud.tooltip.comms':              'COMMS: GREEN=All sensors live / ORANGE=Abnormal silence detected — possible sensor suppression or pre-op comms blackout',
    'hud.domain.cyber':               'Cyber',
    'hud.tooltip.domain_cyber':       'Cyber domain score',
    'hud.domain.physical':            'Physical',
    'hud.tooltip.domain_physical':    'Physical domain score',
    'hud.domain.info':                'Info',
    'hud.tooltip.domain_info':        'Info domain score',
    'hud.discrepancy_alert':          '! DISCREPANCY DETECTED: POSSIBLE MASKIROVKA',

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
    'tools.salute_board':             'SALUTE Board',
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
    'panel.target.hint':              'Toggle pinned targets on/off.',

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
    'modal.settings.tab.strategy':    'Strategy Scope',
    'modal.settings.tab.actors':      'Threat Actors',
    'modal.settings.tab.pins':        'Quick Pins',
    'modal.settings.tab.sensors':     'Sensors',
    'modal.settings.tab.fetchlog':    'Fetch Log',

    'modal.strategy.help_core':       '<b>Epicenter (Core):</b> The primary focal point of a contingency scenario.',
    'modal.strategy.help_link':       '<b>Correlate (Link):</b> Allied nations to monitor for coordinated attacks originating from the same botnets.',
    'modal.strategy.search':          'Filter countries...',
    'modal.strategy.th_core':         'Core',
    'modal.strategy.th_core_tooltip': 'Epicenter (Primary Focus)',
    'modal.strategy.th_link':         'Link',
    'modal.strategy.th_link_tooltip': 'Calculate Correlation',
    'modal.strategy.th_country':      'Country / Region',

    'modal.actors.help':              '<b>Adversary State:</b> Nation-states conducting systematic cyber operations. Alerts trigger when adversary domestic infrastructure is used directly for attacks.',
    'modal.actors.help_auto_src':     'Narrative sources are automatically selected to match the adversary bloc.',

    'modal.pins.help':                '<b>Quick Pin:</b> Select countries to appear in the "Target Visibility" panel on the main screen for rapid on/off switching.',
    'modal.pins.search':              'Filter countries...',

    'modal.sensors.help':             'Enable or disable individual sensor modules. <b>Cyber</b> = network threats, <b>Physical</b> = infrastructure & airspace, <b>Info</b> = information & influence operations.',
    'modal.sensors.help_graceful':    'Disabled sensors contribute zero to their domain score (Graceful Degradation).',
    'modal.sensors.loading':          'Loading sensor status...',

    'modal.fetchlog.help':            'Shows the last fetch result for each sensor from its external API.',
    'modal.fetchlog.stale_note':      'Cache age exceeding 3× the poll interval is flagged as <b>STALE</b>.',
    'modal.fetchlog.refresh_btn':     '↻ Refresh',
    'modal.fetchlog.loading':         'Loading...',

    'modal.minimap.region_preview':   'Region Preview',
    'modal.minimap.legend.core':      '◆ Core',
    'modal.minimap.legend.link':      '◆ Link',
    'modal.minimap.legend.adversary': '◆ Adversary',
    'modal.minimap.legend.pin':       '◆ Pin',

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
    'modal.evidence.th_sensor':       'Sensor',
    'modal.evidence.th_domain':       'Domain',
    'modal.evidence.th_status':       'Status',
    'modal.evidence.th_observed':     'Observed Value',
    'modal.evidence.th_score':        'Score',
    'modal.evidence.th_reason':       'Fired Reason / Note',
    'modal.evidence.noise_filters':   'Noise filters applied:',
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
    'dash.no_active_pins':            'No targets active in Scope or Pins.',

    // ══════════════════════════════════════════════════════════════
    // Survival HUD (JS-generated tooltips)
    // ══════════════════════════════════════════════════════════════
    'survival.tooltip.header':        'INFRA LIVENESS  [{status}  {pct}%]',
    'survival.asphyx_note':           '⚠ ASPHYXIATION DETECTED\n  Success=100% but latency ≥3× baseline\n  CDN is masking packet loss — infra under strain',

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
    'hud.btn.sitrep':                 'SITREP',
    'hud.btn.intel_guide':            'インテルガイド',
    'hud.btn.config':                 '設定',
    'hud.btn.lang':                   'EN',

    'hud.tooltip.chain':              '証拠チェーンタイムライン — エスカレーション順序ビューア',
    'hud.tooltip.tools':              '直感ツール — RPD分析パネル',
    'hud.tooltip.sync':               'データを強制同期',

    'hud.threat.click_hint':          'クリックして分析根拠を表示',

    'hud.convergence.full':           '⚡ 完全収束',
    'hud.convergence.dual':           '⚠ 2ドメイン収束',
    'hud.convergence.single':         '◉ 単一ドメイン',
    'hud.convergence.none':           '収束: —',
    'hud.label.threat_24h':           '脅威 24h:',
    'hud.tooltip.threat_24h':         '脅威レベル履歴（直近24時間 / 288サイクル）',
    'hud.label.epicenter':            '震源地:',

    'hud.vec.all':                    '全ベクター',
    'hud.vec.l3':                     'L3 大容量型',
    'hud.vec.l7':                     'L7 アプリ層型',

    'hud.label.overlap':              '重複:',
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
    'hud.tooltip.comms':              '通信: 緑=全センサー稼働中 / 橙=異常な沈黙を検出 — センサー妨害または作戦前通信封止の可能性',
    'hud.domain.cyber':               'サイバー',
    'hud.tooltip.domain_cyber':       'サイバードメインスコア',
    'hud.domain.physical':            '物理',
    'hud.tooltip.domain_physical':    '物理ドメインスコア',
    'hud.domain.info':                '情報',
    'hud.tooltip.domain_info':        '情報ドメインスコア',
    'hud.discrepancy_alert':          '! 乖離検出: マスキロフカの可能性',

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
    'tools.salute_board':             'SALUTE 報告板',
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
    'panel.target.hint':              '固定ターゲットのオン/オフを切り替え。',

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
    'modal.settings.tab.strategy':    '戦略スコープ',
    'modal.settings.tab.actors':      '脅威アクター',
    'modal.settings.tab.pins':        'クイックピン',
    'modal.settings.tab.sensors':     'センサー',
    'modal.settings.tab.fetchlog':    'フェッチログ',

    'modal.strategy.help_core':       '<b>震源地（コア）:</b> シナリオの主要焦点国。',
    'modal.strategy.help_link':       '<b>連携（リンク）:</b> 同一ボットネットからの協調攻撃を監視する同盟国。',
    'modal.strategy.search':          '国でフィルター...',
    'modal.strategy.th_core':         'コア',
    'modal.strategy.th_core_tooltip': '震源地（主要焦点）',
    'modal.strategy.th_link':         'リンク',
    'modal.strategy.th_link_tooltip': '相関を計算',
    'modal.strategy.th_country':      '国 / 地域',

    'modal.actors.help':              '<b>敵対国家:</b> 組織的サイバー作戦を実施する国家。敵対国の国内インフラが直接攻撃に使用されるとアラートが発生。',
    'modal.actors.help_auto_src':     'ナラティブソースは敵対ブロックに合わせて自動選択されます。',

    'modal.pins.help':                '<b>クイックピン:</b> メイン画面の「ターゲット可視性」パネルに表示し、素早くオン/オフ切り替えできる国を選択。',
    'modal.pins.search':              '国でフィルター...',

    'modal.sensors.help':             '個別センサーモジュールの有効/無効を切り替え。<b>サイバー</b>=ネットワーク脅威、<b>物理</b>=インフラ・空域、<b>情報</b>=情報・影響工作。',
    'modal.sensors.help_graceful':    '無効化されたセンサーはドメインスコアへの寄与がゼロになります（グレースフルデグラデーション）。',
    'modal.sensors.loading':          'センサー状態を読み込み中...',

    'modal.fetchlog.help':            '各センサーが外部APIから最後に取得した結果を表示。',
    'modal.fetchlog.stale_note':      'キャッシュ経過時間がポーリング間隔の3倍を超えると <b>STALE（古い）</b> とフラグされます。',
    'modal.fetchlog.refresh_btn':     '↻ 更新',
    'modal.fetchlog.loading':         '読み込み中...',

    'modal.minimap.region_preview':   '地域プレビュー',
    'modal.minimap.legend.core':      '◆ コア',
    'modal.minimap.legend.link':      '◆ リンク',
    'modal.minimap.legend.adversary': '◆ 敵対国',
    'modal.minimap.legend.pin':       '◆ ピン',

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
    'modal.evidence.th_sensor':       'センサー',
    'modal.evidence.th_domain':       'ドメイン',
    'modal.evidence.th_status':       '状態',
    'modal.evidence.th_observed':     '観測値',
    'modal.evidence.th_score':        'スコア',
    'modal.evidence.th_reason':       '発火理由 / 備考',
    'modal.evidence.noise_filters':   '適用ノイズフィルター:',
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
    'gn.remaining':                   'Remaining today: {n}/50',
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
    'dash.no_active_pins':            'スコープまたはピンにアクティブなターゲットがありません。',

    // ══════════════════════════════════════════════════════════════
    // Survival HUD
    // ══════════════════════════════════════════════════════════════
    'survival.tooltip.header':        'INFRA LIVENESS  [{status}  {pct}%]',
    'survival.asphyx_note':           '⚠ アスフィキシエーション検知\n  成功率=100%だが遅延が3×ベースライン以上\n  CDNがパケットロスを隠蔽中 — インフラ圧迫',

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
    el.textContent = _t(key);
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
  localStorage.setItem('ddos_radar_lang', lang);

  // Update lang-toggle button label
  const btn = document.getElementById('lang-toggle-btn');
  if (btn) btn.textContent = _t('hud.btn.lang');

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

// Apply static translations on first load (after DOM ready)
document.addEventListener('DOMContentLoaded', _applyStaticTranslations);
