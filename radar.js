    // HTML escape utility — prevents XSS when inserting external API strings into innerHTML
    const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

    // ── Auth: wrap fetch to include JWT and handle 401 ──
    const _origFetch = window.fetch.bind(window);
    window.fetch = function(url, opts = {}) {
        const token = localStorage.getItem('radar_access_token');
        if (token && typeof url === 'string' && url.startsWith('/api/')) {
            opts.headers = opts.headers || {};
            if (!opts.headers['Authorization']) {
                opts.headers['Authorization'] = 'Bearer ' + token;
            }
        }
        return _origFetch(url, opts).then(res => {
            if (res.status === 401 && typeof url === 'string' && url.startsWith('/api/')
                && !url.includes('/api/auth/login')) {
                // Try token refresh once
                const refreshToken = localStorage.getItem('radar_refresh_token');
                if (refreshToken) {
                    return _origFetch('/api/auth/refresh', {
                        method: 'POST',
                        headers: { 'Authorization': 'Bearer ' + refreshToken }
                    }).then(rr => {
                        if (rr.ok) {
                            return rr.json().then(d => {
                                localStorage.setItem('radar_access_token', d.access_token);
                                opts.headers = opts.headers || {};
                                opts.headers['Authorization'] = 'Bearer ' + d.access_token;
                                return _origFetch(url, opts);
                            });
                        }
                        // Refresh failed — show login gate
                        localStorage.removeItem('radar_access_token');
                        localStorage.removeItem('radar_refresh_token');
                        document.getElementById('login-gate').style.display = 'flex';
                        return res;
                    });
                }
                // No refresh token — show login gate
                localStorage.removeItem('radar_access_token');
                document.getElementById('login-gate').style.display = 'flex';
            }
            return res;
        });
    };



    let latestData = null;
    let currentVector = 'all';
    let mapCenterMode = 'atlantic';
    let _lastRenderSig = ''; // P4-Opt: diff signature cache
    let lastSyncedConfig = { core: "", correlates: [], adversaries: [], displays: [] };
    let lastSyncedTimeText = "System Initializing...";
    let isFirstLoad = true;
    let loaderLogInterval;
    let _nodeOkRetryTimer = null; // One-shot retry when CheckHost hasn't initialized yet
    const _panelCallbacks = {}; // per-panel onShow/onHide hooks keyed by panelId
    let STRATEGIC_BLOCS_DATA = {};  // { RUSSIA: {label, color, adversary, theaters[]}, ... }
    let ADVERSARY_OPTIONS    = [];  // [ {code, bloc, label, color}, ... ]
    let COUNTRY_BLOC_TAGS    = {};  // { "US": ["RUSSIA","CHINA","IRAN","DPRK"], ... }

    // HITL Analyst Mute State
    let mutedSensors;
    try { mutedSensors = new Set(JSON.parse(localStorage.getItem('mutedSensors') || '[]')); }
    catch (e) { console.warn('[MUTE] localStorage parse error — reset to empty:', e); mutedSensors = new Set(); }

    window.toggleMute = function(sensorName) {
        if (mutedSensors.has(sensorName)) {
            mutedSensors.delete(sensorName);
            addNotebookEntry('UNMUTE', _t('notebook.entry.sensor_unmuted', {name: sensorName}));
        } else {
            // Reason input dialog (optional)
            const reason = prompt(_t('sensor.mute.prompt', {name: sensorName}), '') ?? '';
            mutedSensors.add(sensorName);
            addNotebookEntry('MUTE', _t('notebook.entry.sensor_muted', {name: sensorName}) + (reason ? ' — ' + reason : ''));
        }
        localStorage.setItem('mutedSensors', JSON.stringify([...mutedSensors]));
        forceDataSync(); // Trigger immediate recalculation
    };

    // ── GreyNoise Investigator ─────────────────────────────────────────────────
    let _gnLog = JSON.parse(localStorage.getItem('gnLookupLog') || '[]');

    const toggleGnPanel = _createPanelToggle('gn-panel', { onShow: () => renderGnLog() });

    function updateGreyNoisePanel(analytics) {
        const gn = analytics.greynoise || {};
        // Tier badge
        const tierEl = document.getElementById('gn-tier-badge');
        if (tierEl) {
            const tier = gn.gnql_tier || 'none';
            tierEl.className = 'gn-tier-badge ' + (
                tier === 'enterprise'        ? 'gn-tier-enterprise' :
                tier === 'community_limited' ? 'gn-tier-community' : 'gn-tier-none'
            );
            tierEl.textContent = tier === 'enterprise' ? _t('gn.tier.enterprise') :
                                 tier === 'community_limited' ? _t('gn.tier.community') : _t('gn.tier.no_key');
        }
        const suppEl = document.getElementById('gn-suppress-badge');
        if (suppEl) {
            if (gn.suppressing) {
                suppEl.textContent = _t('gn.suppress.active');
                suppEl.style.color = '#ff6600';
            } else {
                suppEl.textContent = gn.noise_class ? gn.noise_class : '—';
                suppEl.style.color = gn.noise_class === 'TARGETED' ? '#00ff88' :
                                     gn.noise_class === 'MIXED' ? '#ffaa00' :
                                     gn.noise_class === 'NOISE_DOMINANT' ? '#ff2200' : '#555';
            }
        }
        // Per-theater list
        const listEl = document.getElementById('gn-theater-list');
        if (listEl && gn.theater_data) {
            listEl.innerHTML = Object.entries(gn.theater_data).map(([cc, d]) => {
                const nc = d.noise_class || 'UNKNOWN';
                const nr = d.noise_ratio !== null && d.noise_ratio !== undefined ? ` (${Math.round(d.noise_ratio * 100)}%)` : '';
                return `<div class="gn-theater-row">
                    <span style="color:#888;font-size:10px;">${cc}</span>
                    <span class="gn-noise-${nc}" style="font-size:10px;font-weight:bold;">${nc}${nr}</span>
                </div>`;
            }).join('') || `<div style="color:#444;font-size:9px;">${_t('gn.no_theater_data')}</div>`;
        }
    }

    function doIpCheck() {
        const input = document.getElementById('gn-ip-input');
        const ip = input ? input.value.trim() : '';
        if (!ip) return;
        const resultEl = document.getElementById('gn-result-card');
        const remEl    = document.getElementById('gn-daily-rem');
        if (resultEl) { resultEl.style.display = 'block'; resultEl.innerHTML = '<span style="color:#555;">' + _t('gn.querying') + '</span>'; }
        fetch(`/api/ip_check?ip=${encodeURIComponent(ip)}`)
            .then(r => r.json())
            .then(d => {
                if (remEl) remEl.textContent = d.daily_remaining !== undefined ? _t('gn.remaining', {n: d.daily_remaining}) : '';
                if (d.error) {
                    if (resultEl) resultEl.innerHTML = `<span style="color:#ff4444;">Error: ${esc(d.error)}</span>`;
                    return;
                }
                const noiseStr  = d.noise ? `<span class="gn-result-noise">${_t('gn.result.noise')}</span>` : `<span class="gn-result-targeted">${_t('gn.result.targeted')}</span>`;
                const riotStr   = d.riot  ? `<span class="gn-result-riot">${_t('gn.result.riot')}</span>` : '';
                const classStr  = d.classification || 'unknown';
                const nameStr   = d.name || '—';
                const lastSeen  = d.last_seen || '—';
                const cached    = d.cached ? ` <span style="color:#555;">${_t('gn.result.cached')}</span>` : '';
                if (resultEl) resultEl.innerHTML =
                    `<div>${noiseStr} ${riotStr}${cached}</div>` +
                    `<div style="color:#888;">Class: <span style="color:#ccc;">${esc(classStr)}</span></div>` +
                    `<div style="color:#888;">Name:  <span style="color:#ccc;">${esc(nameStr)}</span></div>` +
                    `<div style="color:#888;">Seen:  <span style="color:#ccc;">${esc(lastSeen)}</span></div>`;
                // Auto-log to investigation log and notebook
                const logEntry = { ts: Date.now(), ip: d.ip, noise: d.noise, riot: d.riot, classification: classStr, name: nameStr, cached: d.cached };
                _gnLog.unshift(logEntry);
                if (_gnLog.length > 20) _gnLog = _gnLog.slice(0, 20);
                localStorage.setItem('gnLookupLog', JSON.stringify(_gnLog));
                renderGnLog();
                // Notebook auto-entry
                addNotebookEntry('IP_CHECK',
                    `IP ${d.ip}: ${d.noise ? _t('notebook.entry.ip_noise') : _t('notebook.entry.ip_targeted')} | ${classStr} | ${nameStr}`);
            })
            .catch(e => {
                if (resultEl) resultEl.innerHTML = `<span style="color:#ff4444;">Network error: ${esc(e.message)}</span>`;
            });
    }

    function renderGnLog() {
        const el = document.getElementById('gn-log');
        if (!el) return;
        if (!_gnLog.length) { el.innerHTML = `<div style="color:#333;font-size:9px;">${_t('gn.log.no_lookups')}</div>`; return; }
        el.innerHTML = _gnLog.map(e => {
            const t  = new Date(e.ts).toLocaleTimeString('ja-JP', {hour:'2-digit',minute:'2-digit'});
            const cls = e.noise ? 'gn-log-noise' : e.classification === 'unknown' ? 'gn-log-unknown' : 'gn-log-targeted';
            return `<div class="gn-log-entry"><span style="color:#444;">${t}</span> <span style="color:#888;">${e.ip}</span> → <span class="${cls}">${e.noise?'NOISE':'TARGETED'}</span> <span style="color:#666;">${e.name||''}</span></div>`;
        }).join('');
    }

    // ── Telegram SIGINT Panel (v10) ──────────────────────────────────────────
    let _tgFilter   = null;
    let _tgLastData = {};

    // ── Unified Panel Toggle System ────────────────────────────────────────────

    /**
     * Factory: create a toggle function for a floating/docked panel.
     * @param {string} panelId  - DOM id of the panel element
     * @param {Object} opts
     * @param {boolean}  opts.floating     - true to auto-float when not docked (default true)
     * @param {number}   opts.defaultLeft  - initial left offset (default: innerWidth - 320)
     * @param {number}   opts.defaultTop   - initial top offset (default: 130)
     * @param {boolean}  opts.clampPos     - clamp stored position to viewport (default: true for floating)
     * @param {Function} opts.onShow       - called after panel is shown
     * @param {Function} opts.onHide       - called after panel is hidden
     */
    function _createPanelToggle(panelId, opts = {}) {
        const { floating = true, defaultLeft, defaultLeftFn, defaultTop = 130, clampPos = true, onShow, onHide } = opts;
        if (onShow || onHide) _panelCallbacks[panelId] = { onShow, onHide };
        return function() {
            const panel = document.getElementById(panelId);
            if (!panel) return;
            const show = !panel.style.display || panel.style.display === 'none';
            if (show && floating && !panel.classList.contains('docked')) {
                if (panel.parentElement !== document.body) document.body.appendChild(panel);
                panel.classList.add('floating', 'active');
                if (clampPos) {
                    const defLeft = defaultLeftFn ? defaultLeftFn() : (defaultLeft || (window.innerWidth - 320));
                    const rawLeft = parseInt(panel.style.left) || defLeft;
                    const rawTop  = parseInt(panel.style.top)  || defaultTop;
                    panel.style.left = Math.max(10, Math.min(rawLeft, window.innerWidth  - 200)) + 'px';
                    panel.style.top  = Math.max(10, Math.min(rawTop,  window.innerHeight - 100)) + 'px';
                }
            }
            panel.style.display = show ? 'flex' : 'none';
            if (show && onShow) onShow();
            if (!show && onHide) onHide();
            updateSidebarVisibility();
            syncToolsMenuState();
            saveLocalState();
        };
    }

    function _panelClose(panelId) {
        const p = document.getElementById(panelId);
        if (!p) return;
        p.style.display = 'none';
        const cb = _panelCallbacks[panelId];
        if (cb && cb.onHide) cb.onHide();
        updateSidebarVisibility();
        if (typeof syncToolsMenuState === 'function') syncToolsMenuState();
        saveLocalState();
    }

    const toggleTargetPanel    = _createPanelToggle('target-panel',    { floating: false });
    const toggleDashboardPanel = _createPanelToggle('dashboard-panel', { floating: false });
    const toggleTgSigint       = _createPanelToggle('tg-sigint-panel', { floating: true });

    function openTgSigint() {
        const p = document.getElementById('tg-sigint-panel');
        if (!p) return;
        if (!p.classList.contains('docked') && p.parentElement !== document.body)
            document.body.appendChild(p);
        p.style.display = 'flex';
        p.classList.add('floating', 'active');
        setTimeout(() => p.classList.remove('active'), 1000);
        updateSidebarVisibility();
        syncToolsMenuState();
        saveLocalState();
    }

    function tgSetFilter(type, value) {
        _tgFilter = { type, value };
        const lbl  = document.getElementById('tgsig-filter-label');
        const txt  = document.getElementById('tgsig-filter-text');
        if (lbl) lbl.style.display = '';
        if (txt) txt.textContent = value;
        _renderTgLog(_tgLastData);
    }

    function tgClearFilter() {
        _tgFilter = null;
        const lbl = document.getElementById('tgsig-filter-label');
        if (lbl) lbl.style.display = 'none';
        _renderTgLog(_tgLastData);
    }

    function tgClearLog() {
        if (!confirm(_t('tg.confirm.clear_log'))) return;
        fetch(`/api/telegram_log/clear`, { method: 'POST' })
            .then(() => {
                _tgLastData = Object.assign({}, _tgLastData, { recent_hits: [] });
                _renderTgLog(_tgLastData);
            })
            .catch(() => {});
    }

    function _tgEsc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function renderTgSigintPanel(tg) {
        _tgLastData = tg;

        // Status badge
        const badge = document.getElementById('tgsig-status-badge');
        if (badge) {
            if (tg.has_intent) {
                badge.textContent = _t('tg.status.intent_detected');
                badge.style.color = '#ff66cc';
                badge.style.background = 'rgba(255,102,204,0.1)';
            } else if (tg.status === 'TARGETS_FOUND') {
                badge.textContent = _t('tg.status.targets_found');
                badge.style.color = '#ffaa00';
                badge.style.background = 'rgba(255,170,0,0.1)';
            } else {
                badge.textContent = _t('tg.status.all_clear');
                badge.style.color = '#555';
                badge.style.background = '#0a0a0a';
            }
        }

        // Poll info
        const pollInfo = document.getElementById('tgsig-poll-info');
        if (pollInfo) {
            const active    = (tg.active_channels || []).length;
            const monitored = (tg.channels_monitored || []).length;
            const ts        = tg.last_poll_ts ? tg.last_poll_ts.substring(11,16) + ' UTC' : '—';
            const ok        = tg.last_poll_ok !== false;
            pollInfo.innerHTML =
                `${active}/${monitored} active &nbsp;<span style="color:${ok?'#00cc66':'#cc4444'};">${ok?'●':'✕'}</span>&nbsp; ${ts}`;
        }

        // Theater grid
        const grid = document.getElementById('tgsig-theater-grid');
        if (grid) {
            const breakdown = tg.theater_breakdown || {};
            const entries   = Object.entries(breakdown);
            if (entries.length === 0) {
                const hasHistory = (tg.recent_hits || []).length > 0;
                const polled     = !!tg.last_poll_ts;
                const gridMsg    = !polled          ? _t('tg.grid.not_polled')
                                 : hasHistory       ? _t('tg.grid.no_active')
                                 : _t('tg.grid.no_activity');
                grid.innerHTML = `<span style="font-size:9px;color:#333;">${gridMsg}</span>`;
            } else {
                grid.innerHTML = entries.map(([theater, data]) => {
                    const st    = data.status || 'CLEAR';
                    const color = st === 'INTENT_DETECTED' ? '#ff66cc' : st === 'TARGETS_FOUND' ? '#ffaa00' : '#3a3a3a';
                    const bg    = st === 'INTENT_DETECTED' ? 'rgba(255,102,204,0.1)' : st === 'TARGETS_FOUND' ? 'rgba(255,170,0,0.1)' : 'transparent';
                    const label = st === 'INTENT_DETECTED' ? '██' : st === 'TARGETS_FOUND' ? '◆' : '──';
                    return `<span class="tgsig-theater-btn" style="color:${color};background:${bg};border-color:${color}55;"
                        onclick="tgSetFilter('theater','${_tgEsc(theater)}')" data-tooltip="${theater}: ${st}">
                        ${_tgEsc(theater)}[${label}]</span>`;
                }).join('');
            }
        }

        _renderTgLog(tg);

        // Channel roster
        const roster    = document.getElementById('tgsig-roster');
        const monitored = tg.channels_monitored || [];
        const active    = tg.active_channels    || [];
        if (roster) {
            if (monitored.length === 0) {
                roster.innerHTML = `<span style="font-size:9px;color:#333;">${_t('tg.roster.no_channels')}</span>`;
            } else {
                roster.innerHTML = monitored.map(ch => {
                    const isActive = active.includes(ch);
                    return `<span class="tgsig-roster-badge${isActive?' active':''}"
                        onclick="tgSetFilter('channel','${_tgEsc(ch)}')">${_tgEsc(ch)}</span>`;
                }).join('');
            }
        }
    }

    function _renderTgLog(tg) {
        const logEl = document.getElementById('tgsig-intercept-log');
        if (!logEl) return;
        const hits = tg.recent_hits || [];
        const filtered = _tgFilter ? hits.filter(h =>
            (_tgFilter.type === 'theater' && h.theater === _tgFilter.value) ||
            (_tgFilter.type === 'channel' && h.channel === _tgFilter.value)
        ) : hits;

        if (filtered.length === 0) {
            logEl.innerHTML = `<div style="color:#2a2a2a;font-size:10px;text-align:center;padding:14px 0;font-family:'Courier New',monospace;">${_t('tg.log.no_intercepts')}</div>`;
            return;
        }

        logEl.innerHTML = filtered.map(h => {
            const ts       = h.ts ? h.ts.substring(11,16) + ' UTC' : '';
            const isIntent = h.status === 'INTENT_DETECTED';
            const color    = isIntent ? '#ff66cc' : '#ffaa00';
            const cls      = isIntent ? 'intent' : 'target';
            const kwStr    = (h.keywords_matched || []).join(' · ') || '—';
            const urlStr   = (h.target_urls || []).map(u => u.replace(/^https?:\/\//,'')).join(' · ');
            const snippet  = h.snippet
                ? `<div class="tgsig-snippet">${_tgEsc(h.snippet)}</div>` : '';
            const srcLink  = h.channel_url
                ? `<a href="${_tgEsc(h.channel_url)}" target="_blank" class="tgsig-src-link">↗SRC</a>` : '';
            return `<div class="tgsig-entry ${cls}">
                <div class="tgsig-entry-hdr">
                    <span><span style="color:#aaa;">${_tgEsc(h.channel||'?')}</span>&nbsp;·&nbsp;${ts}&nbsp;·&nbsp;${_tgEsc(h.theater||'')}</span>
                    ${srcLink}
                </div>
                <div class="tgsig-entry-class" style="color:${color};">
                    ${isIntent?'INTENT':'TARGET'}
                    <span class="tgsig-entry-kw">&nbsp;${_tgEsc(kwStr)}</span>
                </div>
                ${urlStr ? `<div class="tgsig-entry-urls">${_tgEsc(urlStr)}</div>` : ''}
                ${snippet}
            </div>`;
        }).join('');
    }
    // ── End Telegram SIGINT Panel ────────────────────────────────────────────

    function clearGnLog() {
        _gnLog = [];
        localStorage.setItem('gnLookupLog', '[]');
        renderGnLog();
        const rc = document.getElementById('gn-result-card');
        if (rc) { rc.style.display='none'; rc.innerHTML=''; }
    }

    // ── Analyst Notebook ───────────────────────────────────────────────────────
    let _nbLog        = JSON.parse(localStorage.getItem('nbLog')        || '[]');
    let _nbConfidence = parseInt(localStorage.getItem('nbConfidence')   || '3');
    let _nbAssessment = localStorage.getItem('nbAssessment')            || 'NOMINAL';
    let _lastDefconLevel = null;   // for DEFCON auto-log

    const toggleNotebook = _createPanelToggle('notebook-panel', {
        defaultLeftFn: () => window.innerWidth - 340, defaultTop: 150,
        onShow: () => { restoreNbState(); renderNbLog(); },
    });

    function restoreNbState() {
        const sel = document.getElementById('nb-assessment');
        if (sel) sel.value = _nbAssessment;
        const hf = document.getElementById('nb-handoff');
        if (hf) hf.value = localStorage.getItem('nbHandoff') || '';
        renderNbConfidence();
    }

    function saveNbState() {
        const sel = document.getElementById('nb-assessment');
        if (sel) { _nbAssessment = sel.value; localStorage.setItem('nbAssessment', _nbAssessment); }
        const hf = document.getElementById('nb-handoff');
        if (hf) localStorage.setItem('nbHandoff', hf.value);
    }

    function setNbConfidence(level) {
        _nbConfidence = level;
        localStorage.setItem('nbConfidence', String(level));
        renderNbConfidence();
    }

    function renderNbConfidence() {
        const row = document.getElementById('nb-confidence-row');
        if (!row) return;
        row.querySelectorAll('.nb-dot').forEach((dot, i) => {
            dot.className = 'nb-dot ' + (i < _nbConfidence ? 'nb-dot-on' : 'nb-dot-off');
        });
    }

    function addNotebookEntry(type, content) {
        const sel = document.getElementById('nb-assessment');
        const assessment = sel ? sel.value : _nbAssessment;
        const entry = {
            ts:         Date.now(),
            type:       type,
            content:    content,
            assessment: assessment,
            confidence: _nbConfidence,
        };
        _nbLog.unshift(entry);
        if (_nbLog.length > 200) _nbLog = _nbLog.slice(0, 200);
        localStorage.setItem('nbLog', JSON.stringify(_nbLog));
        renderNbLog();
    }

    function addManualNote() {
        const ta = document.getElementById('nb-text');
        const text = ta ? ta.value.trim() : '';
        if (!text) return;
        saveNbState();
        addNotebookEntry('ANALYST', text);
        if (ta) ta.value = '';
    }

    function renderNbLog() {
        const container = document.getElementById('nb-log-container');
        if (!container) return;
        if (!_nbLog.length) { container.innerHTML = `<div style="color:#333;font-size:9px;text-align:center;">${_t('notebook.no_entries').replace('\n', '<br>')}</div>`; return; }
        container.innerHTML = _nbLog.map(e => {
            const t = new Date(e.ts).toLocaleTimeString('ja-JP', { hour:'2-digit', minute:'2-digit', second:'2-digit' });
            const typeClass = `nb-type-${e.type}`;
            const assessBadge = e.assessment && e.type === 'ANALYST'
                ? `<span class="nb-assessment-badge nb-assess-${e.assessment}">${e.assessment}</span>`
                : '';
            const confStr = e.type === 'ANALYST' && e.confidence
                ? `<span style="color:#554400;font-size:9px;"> conf:${'●'.repeat(e.confidence)}${'○'.repeat(5-e.confidence)}</span>`
                : '';
            return `<div class="nb-log-entry">
                <div class="nb-ts">${t} <span class="${typeClass}">[${e.type}]</span>${assessBadge}${confStr}</div>
                <div style="color:#aaa;font-size:10px;margin-top:1px;">${e.content}</div>
            </div>`;
        }).join('');
    }

    function exportNotebook() {
        const handoff = (document.getElementById('nb-handoff') || {}).value || '';
        let text = `=== ANALYST NOTEBOOK EXPORT ===\n`;
        text += `Generated: ${new Date().toISOString()}\n`;
        text += `Assessment: ${_nbAssessment} | Confidence: ${'●'.repeat(_nbConfidence)}${'○'.repeat(5-_nbConfidence)}\n`;
        if (handoff) text += `WATCH FOR: ${handoff}\n`;
        text += `\n--- SHIFT LOG ---\n`;
        _nbLog.forEach(e => {
            const t = new Date(e.ts).toISOString().replace('T',' ').slice(0,19) + 'Z';
            text += `[${t}] [${e.type}] ${e.content}\n`;
        });
        navigator.clipboard.writeText(text).then(() => {
            const btn = document.querySelector('#notebook-panel button[onclick="exportNotebook()"]');
            if (btn) { const orig = btn.textContent; btn.textContent = _t('notebook.export.copied'); setTimeout(() => btn.textContent = orig, 1500); }
        }).catch(() => { prompt('Copy the notebook export:', text); });
    }

    function clearNotebook() {
        if (!confirm(_t('notebook.confirm.clear'))) return;
        _nbLog = [];
        localStorage.setItem('nbLog', '[]');
        renderNbLog();
    }

    // ── Custom Tooltip Logic ──
    const tooltip = document.getElementById('custom-tooltip');
    document.addEventListener('mouseover', e => {
        const target = e.target.closest('[data-tooltip]');
        if (target) {
            tooltip.textContent = target.getAttribute('data-tooltip');
            tooltip.style.display = 'block';
        }
    });
    // P6-Opt: throttle mousemove with RAF (position update at most once per frame)
    let _ttX = 0, _ttY = 0, _ttRaf = false;
    document.addEventListener('mousemove', e => {
        if (tooltip.style.display === 'block') {
            _ttX = e.pageX; _ttY = e.pageY;
            if (!_ttRaf) {
                _ttRaf = true;
                requestAnimationFrame(() => {
                    tooltip.style.left = (_ttX + 15) + 'px';
                    tooltip.style.top  = (_ttY + 15) + 'px';
                    _ttRaf = false;
                });
            }
        }
    });
    document.addEventListener('mouseout', e => {
        if (e.target.closest('[data-tooltip]')) {
            tooltip.style.display = 'none';
        }
    });

    const loaderLogs = [
        "> Polling Cloudflare L3/L7 Telemetry...",
        "> Fetching IODA BGP Outage Data...",
        "> Scanning OpenSky Network for Airspace Anomalies...",
        "> Checking NASA FIRMS Thermal Detectors...",
        "> Cross-referencing ThreatFox APT Signatures...",
        "> Retrieving GDELT Media Tone Indicators...",
        "> Compiling PeeringDB/Chokepoint Critical Nodes...",
        "> Calculating MDO Convergence Score..."
    ];
    if (isFirstLoad) {
        let logIdx = 0;
        loaderLogInterval = setInterval(() => {
            const logEl = document.getElementById('loader-log');
            if (logEl) logEl.innerText = loaderLogs[logIdx % loaderLogs.length];
            logIdx++;
        }, 350);
    }

    function switchMapCenter(mode) {
        // Map is fixed to Atlantic view — no-op
    }

    function switchVector(v) {
        currentVector = v;
        ['all', 'l3', 'l7'].forEach(key => {
            const btn = document.getElementById(`vec-btn-${key}`);
            const activeClass = key === 'l3' ? 'active-l3' : key === 'l7' ? 'active-l7' : 'active-all';
            btn.className = 'vec-btn' + (key === v ? ` ${activeClass}` : '');
        });
        saveLocalState();
        if (latestData) renderTelemetry(latestData);
    }

    function toggleContent(e, contentId, btn) {
        e.stopPropagation(); const content = document.getElementById(contentId);
        if (content.classList.contains('content-collapsed')) { content.classList.remove('content-collapsed'); btn.innerText = '−'; } 
        else { content.classList.add('content-collapsed'); btn.innerText = '＋'; }
    }
    const _ROLE_LEVEL = { viewer: 0, analyst: 1, admin: 2 };
    function _applyRoleVisibility(container) {
        const role = localStorage.getItem('radar_role') || 'viewer';
        const level = _ROLE_LEVEL[role] ?? 0;
        container.querySelectorAll('[data-role-min]').forEach(el => {
            const req = _ROLE_LEVEL[el.dataset.roleMin] ?? 0;
            el.style.display = level >= req ? '' : 'none';
        });
        // If active tab is hidden, switch to first visible tab
        const tabs = container.querySelectorAll('.tabs .tab');
        const activeTab = container.querySelector('.tabs .tab.active');
        if (activeTab && activeTab.style.display === 'none') {
            const firstVisible = Array.from(tabs).find(t => t.style.display !== 'none');
            if (firstVisible) firstVisible.click();
        }
    }
    function openModal(modalId) {
        document.querySelectorAll('.modal-window').forEach(el => el.style.display = 'none');
        document.querySelectorAll('.draggable-panel.floating').forEach(el => el.classList.remove('active'));
        const modal = document.getElementById(modalId);
        modal.style.display = 'flex';
        document.getElementById('settings-backdrop').style.display = 'block';
        if (modalId === 'settings-modal') {
            _applyRoleVisibility(modal);
            requestAnimationFrame(() => { _initMinimap(); _minimapFlyTo(_activeRegion); _updateMinimap(); });
        }
    }
    function switchGuideChapter(n) {
        document.querySelectorAll('.guide-chapter').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.guide-ch-btn').forEach(el => el.classList.remove('active'));
        const ch = document.getElementById('guide-ch-' + n);
        if (ch) ch.classList.add('active');
        document.querySelector(`.guide-ch-btn[data-ch="${n}"]`)?.classList.add('active');
    }
    function closeAllModals() {
        document.querySelectorAll('.modal-window').forEach(el => el.style.display = 'none');
        document.getElementById('settings-backdrop').style.display = 'none';
    }

    // ── Intuition UI: TOOLS Dropdown ──────────────────────────────────────────
    const TOOL_MAP = [
        { panelId: 'target-panel',         dotId: 'tm-dot-tgt',   itemId: 'tm-item-tgt'   },
        { panelId: 'dashboard-panel',      dotId: 'tm-dot-dash',  itemId: 'tm-item-dash'  },
        { panelId: 'chain-panel',          dotId: 'tm-dot-chain', itemId: 'tm-item-chain' },
        { panelId: 'tg-sigint-panel',      dotId: 'tm-dot-tg',    itemId: 'tm-item-tg'    },
        { panelId: 'pulse-panel',          dotId: 'tm-dot-pulse', itemId: 'tm-item-pulse' },
        { panelId: 'weather-brief-panel',  dotId: 'tm-dot-wx',    itemId: 'tm-item-wx'    },
        { panelId: 'salute-panel',         dotId: 'tm-dot-sal',   itemId: 'tm-item-sal'   },
        { panelId: 'hist-analog-panel',    dotId: 'tm-dot-ha',    itemId: 'tm-item-ha'    },
        { panelId: 'op-clock-panel',       dotId: 'tm-dot-clk',   itemId: 'tm-item-clk'  },
        { panelId: 'gn-panel',             dotId: 'tm-dot-gn',    itemId: 'tm-item-gn'    },
        { panelId: 'notebook-panel',       dotId: 'tm-dot-nb',    itemId: 'tm-item-nb'    },
        { panelId: 'history-panel',        dotId: 'tm-dot-hist',  itemId: 'tm-item-hist'  },
    ];

    function toggleToolsMenu() {
        const menu = document.getElementById('tools-menu');
        if (!menu) return;
        menu.classList.toggle('open');
        syncToolsMenuState();
    }

    // Close menu on outside click
    document.addEventListener('click', e => {
        if (!e.target.closest('.tools-dropdown-wrap')) {
            const m = document.getElementById('tools-menu');
            if (m) m.classList.remove('open');
        }
    });

    function handleToolToggle(panelId, toggleFn, dotId, itemId) {
        toggleFn();
        syncToolsMenuState();
    }

    // Sync dot/item/button appearance for all tools
    function syncToolsMenuState() {
        let anyOpen = false;
        TOOL_MAP.forEach(({ panelId, dotId, itemId }) => {
            const panel  = document.getElementById(panelId);
            const dot    = document.getElementById(dotId);
            const item   = document.getElementById(itemId);
            // Docked panels with no inline display (display='') are visually shown via CSS;
            // treat them as open unless explicitly set to 'none'.
            const isOpen = !!(panel && panel.style.display !== 'none' &&
                              (panel.style.display || panel.classList.contains('docked')));
            if (isOpen) anyOpen = true;
            if (dot)  dot.className  = 'tools-menu-dot'  + (isOpen ? ' on' : '');
            if (item) item.className = 'tools-menu-item' + (isOpen ? ' tm-active' : '');
        });
        const btn = document.getElementById('tools-dropdown-btn');
        if (btn) {
            if (anyOpen) btn.classList.add('tools-active');
            else         btn.classList.remove('tools-active');
        }
    }

    // ── Evidence Chain Panel ──────────────────────────────────────────────────
    const toggleChainPanel = _createPanelToggle('chain-panel', {
        defaultLeftFn: () => window.innerWidth - 700, defaultTop: 120,
    });

    const EVENT_LABELS = {
        NARRATIVE_BURST: _t('chain.event.narrative_burst'),
        ISR_SURGE:       _t('chain.event.isr_surge'),
        SYNC_DDOS:       _t('chain.event.sync_ddos'),
        FIRMS_ANOMALY:   _t('chain.event.firms_anomaly'),
        AIS_DARK_GAP:    _t('chain.event.ais_dark_gap'),
        // v9
        TELEGRAM_INTENT: _t('chain.event.telegram_intent'),
        MASKIROVKA:      _t('chain.event.maskirovka'),
        C2_SYNC:         _t('chain.event.c2_sync'),
        INFRA_BLACKOUT:  _t('chain.event.infra_blackout'),
    };
    const EVENT_COLORS = {
        NARRATIVE_BURST: '#cc66ff',
        ISR_SURGE:       '#ffaa00',
        SYNC_DDOS:       '#00ffff',
        FIRMS_ANOMALY:   '#ff4444',
        AIS_DARK_GAP:    '#44aaff',
        // v9
        TELEGRAM_INTENT: '#ff66cc',
        MASKIROVKA:      '#ff8800',
        C2_SYNC:         '#ffffff',
        INFRA_BLACKOUT:  '#ff2200',
    };

    function updateChainPanel(strat) {
        const p8 = strat.analytics || {};
        // Sequence badge
        const badge = document.getElementById('chain-seq-badge');
        if (badge) {
            const sc = p8.sequence_status || '';
            badge.textContent = sc.includes('FULL_CHAIN') ? _t('chain.seq.full_chain')
                              : sc.includes('PARTIAL')    ? _t('chain.seq.partial')
                              : _t('chain.seq.none');
            badge.className = 'chain-seq-badge ' + (
                sc.includes('FULL_CHAIN') ? 'chain-seq-FULL_CHAIN' :
                sc.includes('PARTIAL')    ? 'chain-seq-PARTIAL' : 'chain-seq-NONE'
            );
        }
        // Quick metrics (v8)
        const nEl = document.getElementById('ev-narrative-z');
        const iEl = document.getElementById('ev-isr-count');
        const aEl = document.getElementById('ev-ais-gaps');
        if (nEl) nEl.textContent = p8.narrative ? (p8.narrative.z_score || 0).toFixed(2) + ' σ' : '—';
        if (iEl) iEl.textContent = p8.isr ? (p8.isr.count || 0) + ' ac' : '—';
        if (aEl) aEl.textContent = p8.ais ? (p8.ais.dark_gaps || 0) + ' vessels' : '—';

        // ── v9: Survival HUD (Check-Host) ──────────────────────────────────────
        const survEl    = document.getElementById('hud-survival');
        const survIcon  = document.getElementById('hud-survival-icon');
        const survNodes = document.getElementById('hud-survival-nodes');
        const ch = p8.check_host || {};
        const tg = p8.telegram_mirror || {};   // defined here — before the detail code further below
        const chStatus = ch.status || 'UNKNOWN';
        const chRate   = ch.theater_success_rate;
        if (survEl) {
            const COLOR_MAP = { OK: '#00ff88', PARTIAL: '#ffaa00', BLACKOUT: '#ff2200', UNKNOWN: '#555' };
            let survLabel = chStatus + (chRate !== null && chRate !== undefined ? ` (${Math.round(chRate * 100)}%)` : '');
            if (ch.asphyxiation) survLabel += ' ⚠ASP';
            survEl.textContent  = survLabel;
            survEl.style.color  = ch.asphyxiation ? '#ff8800' : (COLOR_MAP[chStatus] || '#aaa');
            survEl.title        = ch.asphyxiation ? 'CDN Asphyxiation: success rate appears normal but latency ≥3× baseline' : '';
        }
        if (survIcon) {
            survIcon.textContent = chStatus === 'OK' ? '●' : chStatus === 'PARTIAL' ? '◐' : chStatus === 'BLACKOUT' ? '○' : '?';
            survIcon.style.color  = chStatus === 'OK' ? '#00ff88' : chStatus === 'PARTIAL' ? '#ffaa00' : '#ff2200';
        }
        // Per-node status dots (8px squares) — compact replacement for text chips
        if (survNodes) {
            const nodeOk   = ch.node_ok || {};
            const entries  = Object.entries(nodeOk);
            const wrapCls  = ch.asphyxiation ? 'node-dots-asphyx' : '';
            const dots = entries.map(([node, st]) => {
                const dotCls = st === 'OK'      ? 'node-dot-ok'
                             : st === 'TIMEOUT' ? 'node-dot-timeout'
                             : st === 'FAIL'    ? 'node-dot-fail'
                             : st === 'PENDING' ? 'node-dot-pending'
                             :                    'node-dot-unknown';
                return `<span class="node-dot ${dotCls}"></span>`;
            }).join('');
            survNodes.innerHTML = dots ? `<span class="${wrapCls}" style="display:inline-flex;align-items:center;">${dots}</span>` : '';

            // Update parent hud-item tooltip with full node breakdown (shown on hover)
            const survItem = document.getElementById('hud-survival-item');
            if (survItem) {
                if (entries.length > 0) {
                    const nodeLines = entries.map(([n, s]) => `  ${n.padEnd(5)}: ${s}`).join('\n');
                    const aspNote   = ch.asphyxiation
                        ? '\n\n' + _t('survival.asphyx_note')
                        : '';
                    survItem.dataset.tooltip =
                        _t('survival.tooltip.header', {status: chStatus, pct: chRate != null ? Math.round(chRate*100) : ''}) + '\n' +
                        `─────────────────────────\n` +
                        nodeLines + aspNote;
                } else {
                    survItem.dataset.tooltip = _t('hud.tooltip.survival');
                }
            }
        }

        // ── DISCREPANCY / Maskirovka HUD alert ─────────────────────────────────
        const mskAlert = document.getElementById('hud-discrepancy-alert');
        const hudEl    = document.getElementById('top-hud');
        const mskNow   = (p8.maskirovka || {}).detected;
        if (mskAlert) mskAlert.style.display = mskNow ? 'block' : 'none';
        if (hudEl) {
            if (mskNow) hudEl.classList.add('hud-discrepancy-border');
            else        hudEl.classList.remove('hud-discrepancy-border');
        }

        // ── v9: C2 Temporal Coherence ──────────────────────────────────────────
        const c2El = document.getElementById('hud-c2sync');
        const tc = p8.temporal_coherence || {};
        if (c2El) {
            if (tc.is_c2_sync) {
                c2El.textContent = _t('hud.c2sync.detected', {n: tc.bonus});
                c2El.style.color = '#ff2200';
            } else if (tc.coherence_score > 0) {
                c2El.textContent = _t('hud.c2sync.partial', {pct: (tc.coherence_score * 100).toFixed(0)});
                c2El.style.color = '#ffaa00';
            } else {
                c2El.textContent = _t('hud.c2sync.no_sync');
                c2El.style.color = '#555';
            }
        }

        // ── v9: CheckHost URL detail in chain panel ────────────────────────────
        const chDetailEl = document.getElementById('chain-checkhost-detail');
        if (chDetailEl) {
            const urlResults = ch.url_results || {};
            const entries = Object.entries(urlResults);
            if (entries.length > 0 && chStatus !== 'UNKNOWN') {
                chDetailEl.style.display = 'block';
                chDetailEl.innerHTML = `<div style="font-size:9px;color:#336633;letter-spacing:1px;margin-bottom:4px;">${_t('chain.infra_check.label', {n: (ch.nodes||[]).length})}</div>` +
                    entries.map(([url, r]) => {
                        const label = url.replace(/^https?:\/\//, '').split('/')[0];
                        const st    = r.status || 'UNKNOWN';
                        const lat   = r.avg_latency_ms ? `${r.avg_latency_ms}ms` : '';
                        const ok    = r.ok_nodes !== undefined ? `${r.ok_nodes}/${r.total_nodes}` : '';
                        return `<div class="ch-url-row">
                            <span class="ch-url-label" data-tooltip="${url}">${label}</span>
                            <span style="color:#555;font-size:9px;">${ok} ${lat}</span>
                            <span class="ch-status-${st}">${st}</span>
                        </div>`;
                    }).join('');
            } else {
                chDetailEl.style.display = 'none';
            }
        }

        // ── v9: Telegram channel detail in chain panel ─────────────────────────
        const tgDetailEl = document.getElementById('chain-telegram-detail');
        if (tgDetailEl) {
            const monitored    = tg.channels_monitored || [];
            const active       = tg.active_channels    || [];
            const targetUrls   = tg.target_urls        || [];
            if (monitored.length > 0) {
                tgDetailEl.style.display = 'block';
                const chBadges = monitored.map(ch => {
                    const isActive = active.includes(ch);
                    return `<span class="tg-ch-badge" style="${isActive ? 'background:rgba(255,102,204,0.2);color:#ff66cc;border-color:#ff66cc88;' : 'opacity:0.4;'}">${ch}</span>`;
                }).join('');
                const urlList = targetUrls.slice(0,3).map(u =>
                    `<div class="tg-url-item" data-tooltip="${u}">${u.replace(/^https?:\/\//,'').slice(0,40)}</div>`
                ).join('');
                tgDetailEl.innerHTML =
                    `<div style="font-size:9px;color:#663366;letter-spacing:1px;margin-bottom:4px;">${_t('chain.telegram_monitor.label', {n: monitored.length})}</div>` +
                    `<div style="margin-bottom:${targetUrls.length?'6px':'0'};">${chBadges}</div>` +
                    (targetUrls.length ? `<div style="font-size:9px;color:#663300;letter-spacing:1px;margin-bottom:3px;">${_t('chain.telegram_monitor.targets')}</div>${urlList}` : '');
            } else {
                tgDetailEl.style.display = 'none';
            }
        }

        // ── v9: Maskirovka flag in Chain panel ─────────────────────────────────
        const msk = p8.maskirovka || {};
        const mskEl = document.getElementById('chain-maskirovka');
        if (mskEl) {
            if (msk.detected) {
                mskEl.style.display = 'block';
                mskEl.innerHTML = `<span style="color:#ff8800;font-weight:700;">${_t('chain.maskirovka.title')}</span>
                    <div style="color:#aaa;font-size:10px;margin-top:2px;">${msk.reason || ''}</div>`;
            } else {
                mskEl.style.display = 'none';
            }
        }

        // ── v9: Telegram Mirror quick stat ────────────────────────────────────
        const tgEl = document.getElementById('ev-telegram-intent');
        if (tgEl) {
            if (tg.has_intent) {
                tgEl.textContent = `INTENT (${(tg.active_channels || []).length} ch)`;
                tgEl.style.color = '#ff66cc';
            } else if (tg.status === 'TARGETS_FOUND') {
                tgEl.textContent = 'TARGETS FOUND';
                tgEl.style.color = '#ffaa00';
            } else {
                tgEl.textContent = 'CLEAR';
                tgEl.style.color = '#555';
            }
        }
        // ── v10: Telegram SIGINT Panel ────────────────────────────────────────
        renderTgSigintPanel(tg);
        // ev-checkhost-status (chain panel sub-metric)
        const chsEl = document.getElementById('ev-checkhost-status');
        if (chsEl) {
            chsEl.textContent = chStatus + (chRate !== null && chRate !== undefined ? ` ${Math.round(chRate*100)}%` : '');
            chsEl.style.color = chStatus === 'OK' ? '#00ff88' : chStatus === 'PARTIAL' ? '#ffaa00' : chStatus === 'BLACKOUT' ? '#ff2200' : '#555';
        }
        // ev-c2sync-detail (chain panel sub-metric)
        const c2dEl = document.getElementById('ev-c2sync-detail');
        if (c2dEl) {
            c2dEl.textContent = tc.is_c2_sync ? _t('chain.c2sync.detected', {n: tc.bonus}) : tc.coherence_score > 0 ? _t('chain.c2sync.partial') : _t('chain.c2sync.no_sync');
            c2dEl.style.color  = tc.is_c2_sync ? '#ff2200' : tc.coherence_score > 0 ? '#ffaa00' : '#555';
        }

        // Async: fetch sequence event list and render
        const theater = strat.core_theater || '';
        if (!theater) return;
        fetch(`/api/sequence_chain?theater=${encodeURIComponent(theater)}`)
            .then(r => r.json())
            .then(data => {
                const chain = (data.chains || {})[theater] || {};
                // Deduplicate: keep only the latest occurrence of each event type
                const _seen = new Set();
                const events = (chain.events || []).slice().reverse().filter(ev => {
                    if (_seen.has(ev.type)) return false;
                    _seen.add(ev.type); return true;
                }).reverse();
                const container = document.getElementById('chain-events');
                if (!container) return;
                if (!events.length) {
                    container.innerHTML = `<div style="color:#555;font-size:10px;text-align:center;">${_t('chain.no_events_24h')}</div>`;
                    return;
                }
                let html = '';
                events.forEach((ev, idx) => {
                    const color  = EVENT_COLORS[ev.type] || '#888';
                    const label  = EVENT_LABELS[ev.type] || ev.type;
                    const dt     = new Date(ev.ts * 1000);
                    const timeStr = dt.toLocaleTimeString('ja-JP', {hour:'2-digit', minute:'2-digit'});
                    html += `<div class="chain-event">
                        <div style="display:flex;flex-direction:column;align-items:center;">
                            <div class="chain-dot chain-dot-${ev.type}" style="background:${color};"></div>
                            ${idx < events.length - 1 ? '<div class="chain-line"></div>' : ''}
                        </div>
                        <div class="chain-text">
                            <div class="chain-type" style="color:${color};">${label}</div>
                            <div class="chain-time">${timeStr}</div>
                        </div>
                    </div>`;
                });
                container.innerHTML = html;
            })
            .catch(() => {});
    }
    function switchTab(tabId) {
        document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
        const tabBtn = document.querySelector(`.tab[onclick*="'${tabId}'"]`);
        if (tabBtn) tabBtn.classList.add('active');
        document.getElementById(`tab-${tabId}`).classList.add('active');
        const mapPanel = document.getElementById('modal-map-panel');
        const showMap  = ['strategy', 'actors', 'pins'].includes(tabId) && tabId !== 'sysconfig';
        if (mapPanel) mapPanel.style.display = showMap ? 'flex' : 'none';
        if (showMap) {
            _initMinimap();
            _minimapFlyTo(_activeRegion);
            _syncPillsVisual();   // sync all tab pills to current selected region
            _reapplyFilters();    // reapply current region filter
            requestAnimationFrame(() => { _minimap?.invalidateSize(); _updateMinimap(); });
        }
    }

    // ── Panel Registry & Sidebar Order ──────────────────────────────────────────
    const ALL_DOCKABLE_PANELS = [
        { id: 'target-panel',         ph: 'target-placeholder'    },
        { id: 'dashboard-panel',      ph: 'dashboard-placeholder' },
        { id: 'chain-panel',          ph: 'chain-placeholder'     },
        { id: 'pulse-panel',          ph: 'lsb-ph-pulse'          },
        { id: 'weather-brief-panel',  ph: 'lsb-ph-wx'             },
        { id: 'salute-panel',         ph: 'lsb-ph-sal'            },
        { id: 'hist-analog-panel',    ph: 'lsb-ph-ha'             },
        { id: 'op-clock-panel',       ph: 'lsb-ph-clk'            },
        { id: 'gn-panel',            ph: 'lsb-ph-gn'             },
        { id: 'notebook-panel',       ph: 'lsb-ph-nb'             },
        { id: 'tg-sigint-panel',      ph: 'lsb-ph-tg'             },
        { id: 'history-panel',        ph: 'lsb-ph-hist'           },
    ];

    // Remembered order of panels within each sidebar (panel IDs, top→bottom)
    let _sidebarOrder = {
        'sidebar':      ['target-panel', 'dashboard-panel', 'chain-panel'],
        'left-sidebar': ['pulse-panel', 'weather-brief-panel', 'salute-panel', 'hist-analog-panel', 'op-clock-panel', 'gn-panel', 'notebook-panel', 'tg-sigint-panel', 'history-panel']
    };

    // Re-order placeholder divs within a sidebar to match _sidebarOrder
    function applyPlaceholderOrder(sidebarId) {
        const sb = document.getElementById(sidebarId);
        if (!sb) return;
        const order  = (_sidebarOrder[sidebarId] || []).slice();
        const footer = sb.querySelector('.sidebar-footer');
        // Move known ordered placeholders first
        order.forEach(panelId => {
            const entry = ALL_DOCKABLE_PANELS.find(p => p.id === panelId);
            if (!entry) return;
            const ph = document.getElementById(entry.ph);
            if (!ph || !sb.contains(ph)) return;
            if (footer) sb.insertBefore(ph, footer); else sb.appendChild(ph);
        });
        // Any placeholders not yet in order list go at end
        ALL_DOCKABLE_PANELS.forEach(({ id, ph: phId }) => {
            if (order.includes(id)) return;
            const ph = document.getElementById(phId);
            if (!ph || !sb.contains(ph)) return;
            if (footer) sb.insertBefore(ph, footer); else sb.appendChild(ph);
        });
    }

    // Update _sidebarOrder by reading current DOM order for a sidebar
    function updateSidebarOrderFromDOM(sidebarId) {
        const sb = document.getElementById(sidebarId);
        if (!sb) return;
        const order = [];
        sb.querySelectorAll('.draggable-panel').forEach(p => { if (p.id) order.push(p.id); });
        _sidebarOrder[sidebarId] = order;
    }

    // ── Sidebar Visibility ─────────────────────────────────────────────────────
    function updateSidebarVisibility() {
        // Left sidebar: show when ≥1 docked panel is visible inside it
        const lsb = document.getElementById('left-sidebar');
        if (lsb) {
            let hasVisible = false;
            lsb.querySelectorAll('.draggable-panel.docked').forEach(p => {
                if (p.style.display !== 'none') hasVisible = true;
            });
            const lsbWasVisible = lsb.style.display !== 'none';
            lsb.style.display = hasVisible ? 'flex' : 'none';
            if (lsbWasVisible !== hasVisible) {
                requestAnimationFrame(() => {
                    map.invalidateSize({ animate: false });
                    _fitMapToViewport();
                });
            }
        }
        // Right sidebar: show/hide panel area; footer is fixed so always visible independently
        const rsb = document.getElementById('sidebar');
        if (rsb) {
            const anyDocked = rsb.querySelectorAll('.draggable-panel.docked').length > 0;
            rsb.style.display = anyDocked ? 'flex' : 'none';

            // dashboard-placeholder flex-grow: 1 only when dashboard-panel is actually docked inside it.
            // Without this, an empty placeholder pushes chain-panel to the bottom of the sidebar.
            const dashPh    = document.getElementById('dashboard-placeholder');
            const dashPanel = document.getElementById('dashboard-panel');
            if (dashPh && dashPanel) {
                const isDashDocked = dashPanel.classList.contains('docked') && dashPh.contains(dashPanel);
                dashPh.style.flexGrow = isDashDocked ? '' : '0';
            }

            // Zoom control: lower when sidebar is present (don't need to clear footer), raise when absent
            const zoomCtrl = document.querySelector('.leaflet-bottom.leaflet-right');
            if (zoomCtrl) zoomCtrl.style.bottom = anyDocked ? '' : '46px';

            // Sync footer width to sidebar's actual rendered width so they align perfectly
            const footerEl = document.querySelector('.sidebar-footer');
            requestAnimationFrame(() => {
                if (footerEl) {
                    footerEl.style.width = anyDocked
                        ? rsb.getBoundingClientRect().width + 'px'
                        : '400px';
                }
                // Recalculate map size after dock visibility change
                map.invalidateSize({ animate: false });
                _fitMapToViewport();
            });
        }
    }

    function setupDockablePanel(panelId, placeholderId, defaultWidth) {
        const panel = document.getElementById(panelId);
        const placeholder = document.getElementById(placeholderId);
        const handle = panel.querySelector('.drag-handle');
        const dockBtn = panel.querySelector('.dock-btn');
        const toggleBtn = panel.querySelector('.toggle-btn');
        const content = panel.querySelector('.panel-content');

        if (toggleBtn && content) {
            toggleBtn.onmousedown = function(e) {
                e.stopPropagation();
                if (content.style.display === 'none') {
                    content.style.display = 'flex'; toggleBtn.innerText = '−'; toggleBtn.classList.remove('active-btn');
                    if(panel.classList.contains('docked') && panelId === 'dashboard-panel') { panel.style.flexGrow = '1'; placeholder.style.flexGrow = ''; }
                } else {
                    content.style.display = 'none'; toggleBtn.innerText = '＋'; toggleBtn.classList.add('active-btn');
                    if(panel.classList.contains('docked') && panelId === 'dashboard-panel') { panel.style.flexGrow = '0'; placeholder.style.flexGrow = '0'; }
                }
                saveLocalState();
            };
        }

        // Apply defaultWidth to initial floating state as well (same size as after dock→undock)
        if (panel.classList.contains('floating') && !panel.classList.contains('docked')) {
            if (!panel.style.width) panel.style.width = defaultWidth + 'px';
        }

        // Which sidebar currently contains this panel's placeholder?
        function getSidebarId() {
            const lsb = document.getElementById('left-sidebar');
            const rsb = document.getElementById('sidebar');
            if (lsb && lsb.contains(placeholder)) return 'left-sidebar';
            if (rsb && rsb.contains(placeholder)) return 'sidebar';
            return null;
        }

        // Dock button: use remembered order
        dockBtn.onmousedown = function(e) { e.stopPropagation(); dockToSidebar(null); };

        // Dock panel — mouseY=null → remembered order; mouseY=number → position by drag
        function dockToSidebar(mouseY) {
            placeholder.appendChild(panel);
            panel.classList.remove('floating', 'active');
            panel.classList.add('docked');
            panel.style.left = ''; panel.style.top = ''; panel.style.width = ''; panel.style.height = '';
            panel.style.display = 'flex';
            dockBtn.style.display = 'none';

            const sbId = getSidebarId();
            const sb   = sbId ? document.getElementById(sbId) : null;
            if (sb) {
                if (mouseY != null) {
                    // Drag-to-dock: insert near cursor Y
                    const footer = sb.querySelector('.sidebar-footer');
                    const candidates = [...sb.children].filter(ch => ch !== placeholder && (footer ? ch !== footer : true));
                    let insertBefore = footer || null;
                    for (const ch of candidates) {
                        const r = ch.getBoundingClientRect();
                        if (mouseY < r.top + r.height / 2) { insertBefore = ch; break; }
                    }
                    sb.insertBefore(placeholder, insertBefore);
                    updateSidebarOrderFromDOM(sbId);
                } else {
                    // Dock button: restore remembered position
                    applyPlaceholderOrder(sbId);
                }
            }

            updateSidebarVisibility();
            if (typeof syncToolsMenuState === 'function') syncToolsMenuState();
            saveLocalState();
        }

        // Undock from sidebar and start floating (optionally continue drag from currentE)
        function undockAndFloat(startE, currentE) {
            const rect = panel.getBoundingClientRect();
            document.body.appendChild(panel);
            panel.classList.remove('docked'); panel.classList.add('floating', 'active');
            panel.style.display = 'flex';
            panel.style.width = defaultWidth + 'px';
            if (panelId === 'dashboard-panel') panel.style.height = '400px';
            panel.style.left = rect.left + 'px'; panel.style.top = rect.top + 'px';
            dockBtn.style.display = 'inline-block';
            updateSidebarVisibility();
            if (currentE) {
                pos3 = currentE.clientX; pos4 = currentE.clientY;
                document.onmouseup = closeDragElement;
                document.onmousemove = elementDrag;
            }
        }

        // Drag-within-sidebar to reorder; drift outside sidebar boundary → undock
        function startSidebarSort(startE) {
            const sbId = getSidebarId();
            const sb   = sbId ? document.getElementById(sbId) : null;
            if (!sb) { undockAndFloat(startE, null); return; }

            const indicator = document.createElement('div');
            indicator.className = 'sb-drop-indicator';
            let currentInsertBefore = null;
            let movedOutside = false;
            let hasMoved = false; // true only after actual mouse movement

            function getInsertTarget(my) {
                const footer = sb.querySelector('.sidebar-footer');
                const others = [...sb.children].filter(ch => ch !== placeholder && ch !== indicator && (footer ? ch !== footer : true));
                let ins = footer || null;
                for (const ch of others) {
                    const r = ch.getBoundingClientRect();
                    if (my < r.top + r.height / 2) { ins = ch; break; }
                }
                return ins;
            }

            function onMove(me) {
                if (!hasMoved) {
                    // Only start visual drag after a few pixels of movement
                    const dx = me.clientX - startE.clientX;
                    const dy = me.clientY - startE.clientY;
                    if (Math.abs(dx) < 4 && Math.abs(dy) < 4) return;
                    hasMoved = true;
                    panel.classList.add('sb-dragging');
                }
                const sbRect = sb.getBoundingClientRect();
                if (!movedOutside && (me.clientX < sbRect.left - 40 || me.clientX > sbRect.right + 40)) {
                    movedOutside = true;
                    panel.classList.remove('sb-dragging');
                    if (indicator.parentElement) indicator.parentElement.removeChild(indicator);
                    document.onmousemove = null; document.onmouseup = null;
                    undockAndFloat(startE, me);
                    return;
                }
                currentInsertBefore = getInsertTarget(me.clientY);
                if (indicator.parentElement) indicator.parentElement.removeChild(indicator);
                sb.insertBefore(indicator, currentInsertBefore);
            }

            function onUp() {
                document.onmousemove = null; document.onmouseup = null;
                panel.classList.remove('sb-dragging');
                if (indicator.parentElement) indicator.parentElement.removeChild(indicator);
                if (hasMoved && !movedOutside) {
                    // Only reorder if user actually dragged within sidebar
                    sb.insertBefore(placeholder, currentInsertBefore);
                    updateSidebarOrderFromDOM(sbId);
                    saveLocalState();
                } else if (!hasMoved && content && toggleBtn) {
                    // Pure click on header → toggle minimize (same as toggle-btn)
                    if (content.style.display === 'none') {
                        content.style.display = 'flex'; toggleBtn.innerText = '−'; toggleBtn.classList.remove('active-btn');
                        if (panel.classList.contains('docked') && panelId === 'dashboard-panel') { panel.style.flexGrow = '1'; placeholder.style.flexGrow = ''; }
                    } else {
                        content.style.display = 'none'; toggleBtn.innerText = '＋'; toggleBtn.classList.add('active-btn');
                        if (panel.classList.contains('docked') && panelId === 'dashboard-panel') { panel.style.flexGrow = '0'; placeholder.style.flexGrow = '0'; }
                    }
                    saveLocalState();
                }
            }

            document.onmousemove = onMove;
            document.onmouseup = onUp;
        }

        let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

        panel.onmousedown = function() {
            if (panel.classList.contains('floating')) {
                document.querySelectorAll('.draggable-panel.floating').forEach(el => el.classList.remove('active'));
                panel.classList.add('active');
            }
        };

        handle.onmousedown = function(e) {
            if(e.target.closest('.icon-btn')) return;
            e.preventDefault();

            if (panel.classList.contains('docked')) {
                // Docked panel drag: reorder within sidebar, or drift outside to undock
                startSidebarSort(e);
                return;
            }

            // Floating panel drag
            document.querySelectorAll('.draggable-panel.floating').forEach(el => el.classList.remove('active'));
            panel.classList.add('active');
            pos3 = e.clientX; pos4 = e.clientY;
            document.onmouseup = closeDragElement; document.onmousemove = elementDrag;
        };

        function elementDrag(e) {
            e.preventDefault(); pos1 = pos3 - e.clientX; pos2 = pos4 - e.clientY; pos3 = e.clientX; pos4 = e.clientY;
            panel.style.top = (panel.offsetTop - pos2) + "px"; panel.style.left = (panel.offsetLeft - pos1) + "px";
        }

        function closeDragElement(e) {
            document.onmouseup = null; document.onmousemove = null;
            if (e && panel.classList.contains('floating')) {
                const SNAP = 80;
                const atLeft  = e.clientX < SNAP;
                const atRight = e.clientX > window.innerWidth - SNAP;

                if (atLeft || atRight) {
                    const snapSidebarId = atLeft ? 'left-sidebar' : 'sidebar';
                    const snapSb = document.getElementById(snapSidebarId);
                    if (snapSb && snapSb.contains(placeholder)) {
                        dockToSidebar(e.clientY); return;
                    }
                }

                for (const sid of ['sidebar', 'left-sidebar']) {
                    const sb = document.getElementById(sid);
                    if (!sb || sb.style.display === 'none') continue;
                    const sbRect = sb.getBoundingClientRect();
                    if (e.clientX >= sbRect.left && e.clientX <= sbRect.right &&
                        e.clientY >= sbRect.top  && e.clientY <= sbRect.bottom &&
                        sb.contains(placeholder)) {
                        dockToSidebar(e.clientY); return;
                    }
                }
            }
            updateSidebarVisibility();
            saveLocalState();
        }

        panel.addEventListener('mouseup', function(e) { saveLocalState(); });
    }

    // defaultWidth: title uses white-space:nowrap (no wrapping); width is content-first
    setupDockablePanel('target-panel',        'target-placeholder',    340);
    setupDockablePanel('dashboard-panel',     'dashboard-placeholder', 400);
    setupDockablePanel('chain-panel',         'chain-placeholder',     300);
    setupDockablePanel('pulse-panel',         'lsb-ph-pulse',          260);
    setupDockablePanel('weather-brief-panel', 'lsb-ph-wx',             420);
    setupDockablePanel('salute-panel',        'lsb-ph-sal',            380);
    setupDockablePanel('hist-analog-panel',   'lsb-ph-ha',             340);
    setupDockablePanel('op-clock-panel',      'lsb-ph-clk',            340);
    setupDockablePanel('gn-panel',            'lsb-ph-gn',             400);
    setupDockablePanel('notebook-panel',      'lsb-ph-nb',             340);
    setupDockablePanel('tg-sigint-panel',     'lsb-ph-tg',             460);
    setupDockablePanel('history-panel',        'lsb-ph-hist',           620);
    updateSidebarVisibility();

    const map = L.map('map', {
        zoomControl: false,
        zoomSnap: 0.1,
        zoomDelta: 0.5,
        maxBoundsViscosity: 1.0,
        worldCopyJump: false,
        maxBounds: [[-85.0511, -180], [85.0511, 180]],
    }).setView([20.0, 10.0], 3);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { attribution: '&copy; CARTO', maxZoom: 18 }).addTo(map);
    L.control.zoom({ position: 'bottomright' }).addTo(map);

    // Fit one world map tile to both screen width and height — hide blank tile areas completely
    function _fitMapToViewport() {
        const el = document.getElementById('map');
        const W  = el.offsetWidth  || window.innerWidth;
        const H  = el.offsetHeight || window.innerHeight;
        const zW = Math.log2(W / 256);
        const zH = Math.log2(H / 256);
        const z  = Math.max(zW, zH); // zoom that leaves no blank tiles for either width or height
        map.setMinZoom(z);
        if (map.getZoom() < z) map.setZoom(z, { animate: false });
    }
    _fitMapToViewport();
    map.on('resize', _fitMapToViewport);
    window.addEventListener('resize', _fitMapToViewport);

    const targetLayer = L.layerGroup().addTo(map);
    const sourceLayer = L.layerGroup().addTo(map);
    const lineLayer   = L.layerGroup().addTo(map);
    const iodaLayer   = L.layerGroup().addTo(map);
    const airspaceLayer = L.layerGroup().addTo(map);
    const weatherLayer  = L.layerGroup().addTo(map);
    const gdeltLayer    = L.layerGroup().addTo(map);
    const criticalNodesLayer = L.layerGroup().addTo(map);
    
    // Additional Map Layers
    const firmsLayer = L.layerGroup().addTo(map);
    const cableRoutesLayer  = L.layerGroup().addTo(map);
    const chokepointsLayer  = L.layerGroup().addTo(map);

    // [Intuition UI] Threat Terrain — threat-density heatmap-style circle overlay
    const threatTerrainLayer = L.layerGroup(); // hidden by default

    // Physical position layers (new)
    const isrZoneLayer          = L.layerGroup().addTo(map);
    const isrAircraftLayer      = L.layerGroup().addTo(map);
    const aisVesselLayer        = L.layerGroup().addTo(map);

    // Threat Situation Map layers
    const haloLayer         = L.layerGroup().addTo(map);
    const sensorMarkerLayer = L.layerGroup().addTo(map);

    const overlayLayers = {
        "Target Nodes":      targetLayer,
        "Cyber Strikes":     lineLayer,
        "Attack Origins":    sourceLayer,
        "BGP Outages":       iodaLayer,
        "Airspace Anomaly":  airspaceLayer,
        "ISR Zones":         isrZoneLayer,
        "ISR Aircraft":      isrAircraftLayer,
        "AIS Vessels":       aisVesselLayer,
        "Weather Events":    weatherLayer,
        "Media Tone Alert":  gdeltLayer,
        "FIRMS Anomalies":   firmsLayer,
        "Cable Routes":      cableRoutesLayer,
        "Cable Chokepoints": chokepointsLayer,
        "Threat Terrain":    threatTerrainLayer,
        "Threat Halos":      haloLayer,
        "Sensor Status":     sensorMarkerLayer,
    };
    L.control.layers(null, overlayLayers, { position: 'topright', collapsed: true }).addTo(map);

    const collapsedTargets = new Set();
    window.toggleTargetList = function(listId, arrowId) {
        const listEl = document.getElementById(listId); const arrowEl = document.getElementById(arrowId);
        if (listEl.style.display === 'none') { listEl.style.display = 'block'; arrowEl.innerText = '▼'; collapsedTargets.delete(listId); } 
        else { listEl.style.display = 'none'; arrowEl.innerText = '▶'; collapsedTargets.add(listId); }
    };

    function shiftLng(lng) { 
        if (mapCenterMode === 'pacific') {
            return lng < -30 ? lng + 360 : lng; 
        } else {
            return lng; 
        }
    }

    // P5-Opt: Bézier curve cache (same pair is not recalculated)
    const _curveCache = new Map();
    function getCurvePoints(startLat, startLng, endLat, endLng) {
        const key = `${startLat},${startLng},${endLat},${endLng}`;
        if (_curveCache.has(key)) return _curveCache.get(key);
        const points = []; const numPoints = 20; // 50→20: no visible difference, 60% less computation
        const midLat = (startLat + endLat) / 2; const midLng = (startLng + endLng) / 2;
        const diffLat = endLat - startLat; const diffLng = endLng - startLng;
        const ctrlLat = midLat - diffLng * 0.2; const ctrlLng = midLng + diffLat * 0.2;
        for (let i = 0; i <= numPoints; i++) {
            const t = i / numPoints;
            const lat = Math.pow(1 - t, 2) * startLat + 2 * (1 - t) * t * ctrlLat + Math.pow(t, 2) * endLat;
            const lng = Math.pow(1 - t, 2) * startLng + 2 * (1 - t) * t * ctrlLng + Math.pow(t, 2) * endLng;
            points.push([lat, lng]);
        }
        if (_curveCache.size > 300) _curveCache.delete(_curveCache.keys().next().value);
        _curveCache.set(key, points);
        return points;
    }

    // THEATERS: dynamically fetched from app_config — initially empty
    let THEATERS = [];

    // ── Region Preview Mini-map ────────────────────────────────────────────────
    let _minimap = null;
    let _minimapMarkers = null;
    let _activeRegion    = '';          // selected region shared across tabs
    let _syncPillsVisual = () => {};    // sync active state across all pill containers
    let _reapplyFilters  = () => {};

    const REGION_BOUNDS = {
        "East Asia":   [[18, 98],  [52, 150]],
        "SE Asia":     [[-10, 92], [28, 142]],
        "S. Asia":     [[4, 58],   [38, 100]],
        "C. Asia":     [[35, 42],  [62, 92]],
        "Middle East": [[10, 30],  [44, 66]],
        "N. Africa":   [[14, -20], [38, 58]],
        "Africa":      [[-36, -22], [28, 58]],
        "W. Europe":   [[34, -16], [72, 32]],
        "N. Europe":   [[54, 4],   [72, 32]],
        "E. Europe":   [[40, 12],  [62, 44]],
        "Russia":      [[48, 28],  [78, 180]],
        "N. America":  [[13, -170], [73, -52]],
        "L. America":  [[-56, -84], [14, -33]],
        "Caribbean":   [[4, -93],  [26, -57]],
        "Oceania":     [[-48, 108], [5, 180]],
    };

    function _initMinimap() {
        if (_minimap) return;
        _minimap = L.map('modal-minimap', {
            zoomControl: false, attributionControl: false,
            dragging: true, scrollWheelZoom: true, doubleClickZoom: true, boxZoom: false,
            maxBoundsViscosity: 0.6,
        }).fitWorld();
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            maxZoom: 8, subdomains: 'abcd',
        }).addTo(_minimap);
        _minimapMarkers = L.layerGroup().addTo(_minimap);
    }

    function _updateMinimap() {
        if (!_minimap || !_minimapMarkers) return;
        _minimapMarkers.clearLayers();
        const coreVal  = document.querySelector('.radio-core:checked')?.value;
        const linkVals = new Set([...document.querySelectorAll('.check-correlate:checked')].map(c => c.value));
        const advVals  = new Set([...document.querySelectorAll('.check-adversary:checked')].map(c => c.value));
        const pinVals  = new Set([...document.querySelectorAll('.check-pin:checked')].map(c => c.value));

        THEATERS.forEach(t => {
            if (t.lat == null || t.lng == null) return;
            let color, radius, fillOpacity, weight, opacity;
            if (t.code === coreVal)         { color = '#00ffff'; radius = 7; fillOpacity = 0.9; weight = 2;   opacity = 1.0; }
            else if (linkVals.has(t.code))  { color = '#ffaa00'; radius = 5; fillOpacity = 0.8; weight = 1.5; opacity = 1.0; }
            else if (advVals.has(t.code))   { color = '#ff5555'; radius = 5; fillOpacity = 0.8; weight = 1.5; opacity = 1.0; }
            else if (pinVals.has(t.code))   { color = '#55ee77'; radius = 4; fillOpacity = 0.7; weight = 1.5; opacity = 1.0; }
            else                            { color = '#334455'; radius = 2; fillOpacity = 0.5; weight = 0;   opacity = 0.5; }

            L.circleMarker([t.lat, t.lng], { radius, color, fillColor: color, fillOpacity, weight, opacity })
             .bindTooltip(`${t.name} (${t.code})`, { sticky: true, className: 'minimap-tooltip' })
             .addTo(_minimapMarkers);
        });
        setTimeout(() => _minimap.invalidateSize(), 50);
    }

    function _minimapFlyTo(region) {
        if (!_minimap) return;
        if (!region) {
            _minimap.flyToBounds([[-78, -175], [78, 175]], { padding: [4, 4], animate: true, duration: 0.4 });
        } else {
            const b = REGION_BOUNDS[region];
            if (b) _minimap.flyToBounds(b, { padding: [8, 8], maxZoom: 6, animate: true, duration: 0.4 });
        }
    }

    // Region display order
    const REGION_ORDER = [
        "East Asia","SE Asia","S. Asia","C. Asia","Middle East",
        "N. Africa","Africa","W. Europe","N. Europe","E. Europe",
        "Russia","N. America","L. America","Caribbean","Oceania","Other"
    ];

    // Bloc bounds for minimap fly-to on bloc pill click
    const BLOC_BOUNDS = {
        'RUSSIA': [[35, -15], [72,  50]],
        'CHINA':  [[-12, 90], [48, 150]],
        'IRAN':   [[ 10, 28], [42,  72]],
        'DPRK':   [[ 33,120], [45, 135]],
    };
    let _activeBloc = '';  // independent filter state for strategy tab

    function buildTheaterUI() {
        const strategyTbody = document.getElementById('strategy-tbody');
        const actorsGrid    = document.getElementById('actors-grid');
        const pinsGrid      = document.getElementById('pins-grid');
        strategyTbody.innerHTML = '';
        actorsGrid.innerHTML    = '';
        pinsGrid.innerHTML      = '';

        // ── Strategy table: multi-placement (country can appear in multiple blocs) ──

        // Theater lookup by code
        const theaterMap = {};
        THEATERS.forEach(t => { theaterMap[t.code] = t; });

        // Primary bloc per country: COUNTRY_BLOC_TAGS[0] takes precedence,
        // otherwise first bloc encountered in STRATEGIC_BLOCS order.
        const primaryBlocForCountry = {};
        Object.entries(STRATEGIC_BLOCS_DATA).forEach(([blocKey, info]) => {
            const cats = info.categories || (info.theaters ? [{theaters: info.theaters}] : []);
            cats.forEach(cat => {
                (cat.theaters || []).forEach(code => {
                    if (!primaryBlocForCountry[code]) primaryBlocForCountry[code] = blocKey;
                });
            });
        });
        Object.entries(COUNTRY_BLOC_TAGS).forEach(([code, blocs]) => {
            if (blocs && blocs.length > 0) primaryBlocForCountry[code] = blocs[0];
        });

        // Track all countries assigned to at least one bloc (for OTHER bucket)
        const countryInAnyBloc = new Set();
        Object.values(STRATEGIC_BLOCS_DATA).forEach(info => {
            const cats = info.categories || (info.theaters ? [{theaters: info.theaters}] : []);
            cats.forEach(cat => { (cat.theaters || []).forEach(code => countryInAnyBloc.add(code)); });
        });

        // Helper: bloc abbreviation
        function blocAbbr(b) {
            return b === 'RUSSIA' ? 'RU' : b === 'CHINA' ? 'CN' : b === 'IRAN' ? 'IR' : b === 'DPRK' ? 'KP' : b.slice(0, 2);
        }

        // Helper: bloc badges — primaryBloc (permanent primary threat) gets filled badge
        function makeBlocBadges(allBlocs, primaryBloc) {
            return allBlocs.map(b => {
                const c = (STRATEGIC_BLOCS_DATA[b] || {}).color || '#888';
                const abbr = blocAbbr(b);
                const isPrimary = b === primaryBloc;
                const style = isPrimary
                    ? `background:${c};color:#111;border:1px solid ${c};`
                    : `background:transparent;color:${c};border:1px solid ${c}88;`;
                return `<span title="${b}" style="display:inline-block;font-size:9px;font-weight:bold;padding:1px 4px;border-radius:2px;margin-left:3px;vertical-align:middle;line-height:14px;${style}">${abbr}</span>`;
            }).join('');
        }

        // Emit bloc header → subcat header → country rows (one row per country-bloc placement)
        const blocsWithRows = new Set();
        Object.entries(STRATEGIC_BLOCS_DATA).forEach(([blocKey, blocInfo]) => {
            const cats = blocInfo.categories || (blocInfo.theaters ? [{key:'_', label:'', theaters: blocInfo.theaters}] : []);
            const hasAny = cats.some(cat => (cat.theaters || []).some(code => theaterMap[code]));
            if (!hasAny) return;
            blocsWithRows.add(blocKey);

            const hdr = document.createElement('tr');
            hdr.className = 'bloc-header';
            hdr.dataset.bloc = blocKey;
            hdr.innerHTML = `<td colspan="3" style="padding:4px 6px;background:${blocInfo.color}18;border-top:1px solid ${blocInfo.color}44;border-bottom:1px solid ${blocInfo.color}22;">` +
                `<span style="color:${blocInfo.color};font-size:10px;font-weight:bold;letter-spacing:1px;">▲ ${blocInfo.label.toUpperCase()}</span></td>`;
            strategyTbody.appendChild(hdr);

            cats.forEach(cat => {
                const catCodes = (cat.theaters || []).filter(code => theaterMap[code]);
                if (!catCodes.length) return;

                if (cat.label) {
                    const subHdr = document.createElement('tr');
                    subHdr.className = 'subcat-header';
                    subHdr.dataset.bloc = blocKey;
                    subHdr.innerHTML = `<td colspan="3" style="padding:2px 6px 2px 14px;background:${blocInfo.color}0c;border-bottom:1px solid ${blocInfo.color}18;">` +
                        `<span style="color:${blocInfo.color}bb;font-size:9px;letter-spacing:0.5px;">◆ ${cat.label.toUpperCase()}</span></td>`;
                    strategyTbody.appendChild(subHdr);
                }

                catCodes.forEach(code => {
                    const t = theaterMap[code];
                    const primaryBloc = primaryBlocForCountry[code] || blocKey;
                    const isPrimary = primaryBloc === blocKey;
                    const allBlocs = COUNTRY_BLOC_TAGS[code] || [blocKey];
                    const tr = document.createElement('tr');
                    tr.dataset.name = t.name.toLowerCase();
                    tr.dataset.bloc = blocKey;
                    tr.dataset.blocs = allBlocs.join(' ');
                    tr.dataset.primary = isPrimary ? '1' : '0';
                    const blocBadges = makeBlocBadges(allBlocs, primaryBloc);
                    tr.innerHTML = `<td class="center"><input type="radio" name="core_theater" value="${t.code}" class="radio-core"></td>` +
                        `<td class="center"><input type="checkbox" class="check-correlate" value="${t.code}"></td>` +
                        `<td><div style="display:flex;justify-content:space-between;align-items:center;gap:6px;">` +
                        `<label style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${t.name} <span style="color:#555;font-size:10px;">${t.code}</span></label>` +
                        `<div style="display:flex;gap:2px;flex-shrink:0;">${blocBadges}</div>` +
                        `</div></td>`;
                    strategyTbody.appendChild(tr);
                });
            });
        });

        // OTHER bucket (countries not in any bloc)
        const otherTheaters = THEATERS.filter(t => !countryInAnyBloc.has(t.code));
        if (otherTheaters.length) {
            const hdr = document.createElement('tr');
            hdr.className = 'bloc-header';
            hdr.dataset.bloc = 'OTHER';
            hdr.innerHTML = `<td colspan="3" style="padding:4px 6px;background:#33333318;border-top:1px solid #44444444;border-bottom:1px solid #33333322;">` +
                `<span style="color:#888;font-size:10px;font-weight:bold;letter-spacing:1px;">▲ OTHER</span></td>`;
            strategyTbody.appendChild(hdr);
            otherTheaters.forEach(t => {
                const tr = document.createElement('tr');
                tr.dataset.name = t.name.toLowerCase();
                tr.dataset.bloc = 'OTHER';
                tr.dataset.blocs = 'OTHER';
                tr.dataset.primary = '1';
                tr.innerHTML = `<td class="center"><input type="radio" name="core_theater" value="${t.code}" class="radio-core"></td>` +
                    `<td class="center"><input type="checkbox" class="check-correlate" value="${t.code}"></td>` +
                    `<td><label>${t.name} <span style="color:#555;font-size:10px;">${t.code}</span></label></td>`;
                strategyTbody.appendChild(tr);
            });
        }

        // ── Actors grid: adversary states only ──────────────────────────────
        const advopts = ADVERSARY_OPTIONS.length ? ADVERSARY_OPTIONS
            : Object.entries(STRATEGIC_BLOCS_DATA).map(([k, v]) => ({code: v.adversary, bloc: k, label: v.label, color: v.color}));
        advopts.forEach(opt => {
            const lbl = document.createElement('label');
            lbl.style.cssText = `display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid ${opt.color}44;border-radius:3px;cursor:pointer;`;
            lbl.innerHTML = `<input type="checkbox" class="check-adversary" value="${opt.code}">` +
                `<span style="color:${opt.color};font-weight:bold;min-width:26px;">${opt.code}</span>` +
                `<span style="color:#aaa;font-size:11px;">${opt.label}</span>`;
            actorsGrid.appendChild(lbl);
        });

        // ── Pins grid: all countries (region-grouped) ───────────────────────
        THEATERS.forEach(t => {
            const pinLabel = document.createElement('label');
            pinLabel.dataset.name   = t.name.toLowerCase();
            pinLabel.dataset.region = t.region || 'Other';
            pinLabel.innerHTML = `<input type="checkbox" class="check-pin" value="${t.code}"> ${t.name}`;
            pinsGrid.appendChild(pinLabel);
        });

        // ── Strategy: bloc pills ─────────────────────────────────────────────
        function buildBlocPills(containerId) {
            const c = document.getElementById(containerId);
            if (!c) return c;
            const allBlocs = Object.entries(STRATEGIC_BLOCS_DATA).filter(([k]) => blocsWithRows.has(k));
            c.innerHTML = `<button class="region-pill${_activeBloc === '' ? ' active' : ''}" data-bloc="">ALL</button>` +
                allBlocs.map(([k, v]) =>
                    `<button class="region-pill${k === _activeBloc ? ' active' : ''}" data-bloc="${k}" style="border-color:${v.color}55;color:${_activeBloc===k?'#111':v.color}">${v.label}</button>`
                ).join('') +
                (otherTheaters.length ? `<button class="region-pill${_activeBloc==='OTHER'?' active':''}" data-bloc="OTHER" style="border-color:#44444455;color:#888">Other</button>` : '');
            return c;
        }

        // ── Pins: region pills (unchanged) ───────────────────────────────────
        const allRegions = [...new Set(THEATERS.map(t => t.region || 'Other'))];
        allRegions.sort((a, b) => {
            const ia = REGION_ORDER.indexOf(a), ib = REGION_ORDER.indexOf(b);
            if (ia < 0 && ib < 0) return a.localeCompare(b);
            if (ia < 0) return 1; if (ib < 0) return -1;
            return ia - ib;
        });
        function buildRegionPills(containerId) {
            const c = document.getElementById(containerId);
            if (!c) return c;
            c.innerHTML = `<button class="region-pill${_activeRegion === '' ? ' active' : ''}" data-region="">ALL</button>` +
                allRegions.map(r => `<button class="region-pill${r === _activeRegion ? ' active' : ''}" data-region="${r}">${r}</button>`).join('');
            return c;
        }

        // Sync visual active state independently for each tab type
        _syncPillsVisual = () => {
            const sc = document.getElementById('pills-strategy');
            if (sc) sc.querySelectorAll('.region-pill').forEach(p => {
                p.classList.toggle('active', (p.dataset.bloc || '') === _activeBloc);
                if (p.dataset.bloc && STRATEGIC_BLOCS_DATA[p.dataset.bloc]) {
                    p.style.color = p.classList.contains('active') ? '#111' : STRATEGIC_BLOCS_DATA[p.dataset.bloc].color;
                }
            });
            ['pills-pins'].forEach(id => {
                const c = document.getElementById(id);
                if (!c) return;
                c.querySelectorAll('.region-pill').forEach(p => {
                    p.classList.toggle('active', (p.dataset.region || '') === _activeRegion);
                });
            });
        };

        // Strategy bloc filter
        function makeBlocFilter(pillContainer, searchInputId, getRows) {
            if (!pillContainer) return () => {};
            let searchText = '';
            function apply() {
                getRows().forEach(r => {
                    if (r.classList.contains('bloc-header')) {
                        r.style.display = (!_activeBloc || r.dataset.bloc === _activeBloc) ? '' : 'none';
                        return;
                    }
                    if (r.classList.contains('subcat-header')) {
                        // Sub-category headers only appear when a specific bloc is filtered
                        r.style.display = (_activeBloc && r.dataset.bloc === _activeBloc) ? '' : 'none';
                        return;
                    }
                    const nm = !searchText || (r.dataset.name || '').includes(searchText);
                    let bm;
                    if (_activeBloc) {
                        // Bloc filter: show all rows in this bloc's section (includes cross-bloc countries)
                        bm = r.dataset.bloc === _activeBloc;
                    } else {
                        // ALL view: flat list — show only each country's primary occurrence
                        bm = r.dataset.primary === '1';
                    }
                    r.style.display = (bm && nm) ? '' : 'none';
                });
            }
            pillContainer.addEventListener('click', e => {
                if (!e.target.classList.contains('region-pill')) return;
                _activeBloc = e.target.dataset.bloc || '';
                _syncPillsVisual();
                _reapplyFilters();
                // Fly minimap to bloc bounds
                if (!_activeBloc) {
                    _minimapFlyTo('');
                } else {
                    const b = BLOC_BOUNDS[_activeBloc];
                    if (_minimap && b) _minimap.flyToBounds(b, {padding:[8,8], maxZoom:5, animate:true, duration:0.4});
                }
            });
            const el = document.getElementById(searchInputId);
            if (el) el.addEventListener('input', () => { searchText = el.value.toLowerCase(); apply(); });
            return apply;
        }

        // Region filter (pins)
        function makeRegionFilter(pillContainer, searchInputId, getRows) {
            if (!pillContainer) return () => {};
            let searchText = '';
            function apply() {
                getRows().forEach(r => {
                    const rm = !_activeRegion || r.dataset.region === _activeRegion;
                    const nm = !searchText || (r.dataset.name || '').includes(searchText);
                    r.style.display = (rm && nm) ? '' : 'none';
                });
            }
            pillContainer.addEventListener('click', e => {
                if (!e.target.classList.contains('region-pill')) return;
                _activeRegion = e.target.dataset.region;
                _syncPillsVisual();
                _reapplyFilters();
                _minimapFlyTo(_activeRegion);
            });
            const el = document.getElementById(searchInputId);
            if (el) el.addEventListener('input', () => { searchText = el.value.toLowerCase(); apply(); });
            return apply;
        }

        const applyS = makeBlocFilter(buildBlocPills('pills-strategy'),  'search-strategy', () => strategyTbody.querySelectorAll('tr'));
        const applyP = makeRegionFilter(buildRegionPills('pills-pins'),  'search-pins',     () => pinsGrid.querySelectorAll('label'));
        _reapplyFilters = () => { applyS(); applyP(); };

        _reapplyFilters();

        [strategyTbody, actorsGrid, pinsGrid].forEach(container => {
            container.addEventListener('change', () => _updateMinimap());
        });
    }

    function renderQuickToggles() {
        const displayGrid = document.getElementById('display-checkboxes');
        const currentChecked = Array.from(document.querySelectorAll('.check-display:checked')).map(cb => cb.value);
        
        const pinnedCodes = new Set();
        document.querySelectorAll('.check-pin:checked').forEach(cb => pinnedCodes.add(cb.value));
        const coreVal = document.querySelector('.radio-core:checked')?.value;
        if (coreVal) pinnedCodes.add(coreVal);
        document.querySelectorAll('.check-correlate:checked').forEach(cb => pinnedCodes.add(cb.value));

        displayGrid.innerHTML = ''; 
        
        Array.from(pinnedCodes).forEach(code => {
            const t = THEATERS.find(theater => theater.code === code);
            if (!t) return;
            const isChecked = currentChecked.includes(code) ? 'checked' : '';
            const lbl = document.createElement('label');
            lbl.innerHTML = `<input type="checkbox" class="check-display" value="${code}" ${isChecked}> ${t.name}`;
            displayGrid.appendChild(lbl);
        });

        if(displayGrid.innerHTML === '') displayGrid.innerHTML = `<div style="color:#888; font-size:11px;">${_t('dash.no_active_pins')}</div>`;
    }

    function updateUIConsistency() {
        document.querySelectorAll('#strategy-tbody tr').forEach(tr => {
            const coreRadio = tr.querySelector('.radio-core'); const corrCb = tr.querySelector('.check-correlate');
            if (!coreRadio || !corrCb) return;
            if (coreRadio.checked) { corrCb.disabled = true; corrCb.checked = false; } else { corrCb.disabled = false; }
        });
    }

    function getCurrentConfig() {
        return {
            core: document.querySelector('input[name="core_theater"]:checked')?.value || '',
            correlates: Array.from(document.querySelectorAll('.check-correlate:checked')).map(cb => cb.value),
            adversaries: Array.from(document.querySelectorAll('.check-adversary:checked')).map(cb => cb.value),
            displays: Array.from(document.querySelectorAll('.check-display:checked')).map(cb => cb.value)
        };
    }

    function checkPendingState() {
        const curr = getCurrentConfig();
        let needsApiSync = false;

        if (curr.core !== lastSyncedConfig.core) needsApiSync = true;
        if (curr.correlates.sort().join(',') !== lastSyncedConfig.correlates.sort().join(',')) needsApiSync = true;
        if (curr.adversaries.sort().join(',') !== lastSyncedConfig.adversaries.sort().join(',')) needsApiSync = true;

        const fetchedCountries = new Set([
            lastSyncedConfig.core, 
            ...lastSyncedConfig.correlates, 
            ...lastSyncedConfig.displays
        ].filter(Boolean));

        const hasUnfetchedDisplay = curr.displays.some(code => !fetchedCountries.has(code));
        if (hasUnfetchedDisplay) needsApiSync = true;

        const syncBtnTop = document.getElementById('btn-sync-top');
        const syncBtnSide = document.getElementById('btn-sync-side');
        const updateTimeEl = document.getElementById('update-time');

        if (needsApiSync) {
            updateTimeEl.innerHTML = `<span style="color:#ffaa00;">Changes pending. Press SYNC.</span>`;
            syncBtnTop.classList.add("pending");
            syncBtnSide.classList.add("pending");
        } else {
            updateTimeEl.innerText = lastSyncedTimeText;
            syncBtnTop.classList.remove("pending");
            syncBtnSide.classList.remove("pending");
            
            if (latestData) renderTelemetry(latestData);
        }
    }

    function forceDataSync() { fetchDDoSData(true); }
    window.forceDataSync = forceDataSync;

    async function fetchDDoSData(force = false) {
        const curr = getCurrentConfig();
        
        const fetchSet = new Set(curr.displays);
        if (curr.core) fetchSet.add(curr.core);
        curr.correlates.forEach(c => fetchSet.add(c));
        const fetchTargets = Array.from(fetchSet).join(',');

        const selectedCorrelates = curr.correlates.join(',');
        const selectedAdversaries = curr.adversaries.join(',');
        const coreTheater = curr.core;
        const mutedList = Array.from(mutedSensors).join(',');

        const syncBtnTop = document.getElementById('btn-sync-top');
        const syncBtnSide = document.getElementById('btn-sync-side');

        if (force) {
            syncBtnTop.innerText = _t('status.syncing'); syncBtnTop.classList.add("syncing");
            syncBtnSide.innerText = _t('status.syncing'); syncBtnSide.classList.add("syncing");
        }

        try {
            // Append &muted=${mutedList}
            const apiUrl = `/api/threat_data?targets=${fetchTargets}&core=${coreTheater}&correlates=${selectedCorrelates}&adversaries=${selectedAdversaries}&muted=${mutedList}&force=${force}`;
            const response = await fetch(apiUrl);
            latestData = await response.json(); 
            
            lastSyncedTimeText = `Data Synced: ${new Date().toLocaleTimeString()} (Next in 15 min)`;
            document.getElementById('update-time').innerText = lastSyncedTimeText;
            lastSyncedConfig = getCurrentConfig();

            // Re-subscribe WS room if core theater changed
            if (_wsSocket && _wsConnected && coreTheater && coreTheater !== _wsSubscribedTheater) {
                if (_wsSubscribedTheater) _wsSocket.emit('unsubscribe_theater', _wsSubscribedTheater);
                _wsSocket.emit('subscribe_theater', coreTheater);
                _wsSubscribedTheater = coreTheater;
                console.log('[WS] Re-subscribed to', coreTheater);
            }

            renderTelemetry(latestData);

            // If node_ok is empty (CheckHost sensor still initializing at startup),
            // schedule a one-shot retry after 60s instead of waiting the full 15 min poll.
            const _chNodeOk = ((latestData.strategic_alert || {}).analytics || {}).check_host;
            const _nodeOkEmpty = !_chNodeOk || Object.keys(_chNodeOk.node_ok || {}).length === 0;
            if (_nodeOkEmpty && !_nodeOkRetryTimer) {
                _nodeOkRetryTimer = setTimeout(() => {
                    _nodeOkRetryTimer = null;
                    fetchDDoSData(false);
                }, 60000);
            } else if (!_nodeOkEmpty && _nodeOkRetryTimer) {
                clearTimeout(_nodeOkRetryTimer);
                _nodeOkRetryTimer = null;
            }

        } catch (error) {
            console.error("API Error:", error); 
        } finally {
            syncBtnTop.innerText = "SYNC"; syncBtnTop.classList.remove("syncing");
            syncBtnSide.innerText = "SYNC"; syncBtnSide.classList.remove("syncing");
            checkPendingState();

            if (isFirstLoad) {
                clearInterval(loaderLogInterval);
                const logEl = document.getElementById('loader-log');
                if (logEl) {
                    logEl.style.color = "#00ffff";
                    logEl.innerText = "> Initialization Complete. Rendering Dashboard.";
                }
                const loader = document.getElementById('global-loader');
                setTimeout(() => {
                    loader.style.opacity = '0';
                    setTimeout(() => { loader.style.display = 'none'; }, 500);
                }, 400); 
                isFirstLoad = false;
            }
        }
    }

    function renderTelemetry(data) {
        const curr = getCurrentConfig();
        const displayTargets = curr.displays;

        // P4-Opt: skip if data, vector, display targets, and map center are unchanged
        const _sig = `${data.timestamp || ''}_${currentVector}_${[...displayTargets].sort().join(',')}_${mapCenterMode}`;
        if (_sig === _lastRenderSig) return;
        _lastRenderSig = _sig;

        const threatEl = document.getElementById('hud-threat');
        const epicenterEl = document.getElementById('hud-epicenter');
        const overlapEl = document.getElementById('hud-overlap');
        const shiftEl = document.getElementById('hud-vector-shift');
        const strikesEl = document.getElementById('hud-strikes');
        const outagesEl = document.getElementById('hud-outages');
        const coordinatedEl = document.getElementById('hud-coordinated');

        if (data.strategic_alert) {
            const strat = data.strategic_alert;
            const threatLabels = { 5: "THREAT Lv 5: NORMAL", 4: "THREAT Lv 4: ELEVATED", 3: "THREAT Lv 3: HIGH", 2: "THREAT Lv 2: SEVERE", 1: "THREAT Lv 1: CRITICAL" };
            threatEl.className = `threat-hud threat-${strat.threat_level}-hud`;
            if (strat.threat_breakdown) {
                const b = strat.threat_breakdown;
                const lines = [
                    `Threat Score: ${b.total_score}`,
                    `Core Spike: ${b.core_spike_val}x  (>2x:${b.core_spike_2x?'✔':'✗'} >4x:${b.core_spike_4x?'✔':'✗'} >6x:${b.core_spike_6x?'✔':'✗'})`,
                    `High Correlation(>45%): ${b.high_correlation?'✔':'✗'}`,
                    `L7 Shift: ${b.core_shifted?'✔':'✗'}`,
                    `Adversary Strike: ${b.major_adversary?'✔':'✗'}`,
                    `BGP Degraded: ${b.core_degraded?'✔':'✗'}`,
                    `Multi-Front(>3x): ${b.is_coordinated?'✔':'✗'}`,
                    `Lv1 Hard Req: ${b.tl1_hard?'✔':'✗'}`,
                    `\nClick to view full Rationale Matrix.`
                ];
                threatEl.setAttribute('data-tooltip', lines.join('\n'));
            }
            threatEl.innerText = threatLabels[strat.threat_level];
            epicenterEl.innerText = strat.core_theater || 'None';

            let overlapText = "None";
            if (strat.correlations && Object.keys(strat.correlations).length > 0) {
                let arr = [];
                for (const [pair, overlap] of Object.entries(strat.correlations)) {
                    const color = overlap > 40 ? "#ff2a2a" : (overlap > 20 ? "#ffaa00" : "#fff");
                    const l3v = strat.correlations_l3 ? (strat.correlations_l3[pair] || 0).toFixed(1) : '-';
                    const l7v = strat.correlations_l7 ? (strat.correlations_l7[pair] || 0).toFixed(1) : '-';
                    arr.push(`<span style="color:${color}" data-tooltip="L3 overlap: ${l3v}%\nL7 overlap: ${l7v}%">${pair}: ${overlap}%</span>`);
                }
                overlapText = arr.join(' | ');
            }
            overlapEl.innerHTML = overlapText;
            
            if (strat.vector_shifts && strat.vector_shifts.length > 0) {
                shiftEl.innerHTML = `<span class="alert-text">${strat.vector_shifts.join(', ')}</span>`;
            } else {
                shiftEl.innerText = "None";
            }
            
            let strikesText = "None";
            if (strat.adversary_strikes && strat.adversary_strikes.length > 0) {
                let arr = [];
                strat.adversary_strikes.forEach(strike => { arr.push(`<span class="warn-text">${strike.actor}➔${strike.target} (x${strike.spike})</span>`); });
                strikesText = arr.join(' | ');
            }
            strikesEl.innerHTML = strikesText;

            const degraded = strat.degraded_theaters && strat.degraded_theaters.length > 0 ? strat.degraded_theaters.join(', ') : "None";
            outagesEl.innerHTML = `<span class="${degraded !== 'None' ? 'warn-text' : ''}">${degraded}</span>`;

            if (coordinatedEl) {
                if (strat.coordinated_theaters && strat.coordinated_theaters.length >= 2) {
                    coordinatedEl.innerHTML = `<span class="alert-text">ACTIVE [${strat.coordinated_theaters.join(', ')}]</span>`;
                } else {
                    coordinatedEl.innerText = "None";
                }
            }

            if (strat.domains) {
                ['cyber', 'physical', 'info'].forEach(d => {
                    const info = strat.domains[d] || { score: 0, status: 'NORMAL' };
                    const barEl    = document.getElementById(`bar-${d}`);
                    const statusEl = document.getElementById(`status-${d}`);
                    if (barEl)    barEl.style.width = `${Math.min(info.score * 8, 80)}px`;
                    if (statusEl) {
                        statusEl.textContent = `${info.score}pt`;
                        statusEl.className = `domain-status ${info.status}`;
                    }
                });
            }

            const convEl = document.getElementById('hud-convergence');
            if (convEl && strat.convergence_level) {
                const lvl = strat.convergence_level;
                const labels = {
                    FULL_CONVERGENCE: _t('hud.convergence.full'),
                    DUAL_DOMAIN:      _t('hud.convergence.dual'),
                    SINGLE_DOMAIN:    _t('hud.convergence.single'),
                    NONE:             _t('hud.convergence.none'),
                };
                convEl.textContent = labels[lvl] || lvl;
                convEl.className = `conv-${lvl}`;
                const b = strat.threat_breakdown || {};
                const bonus = b.convergence_bonus || 0;
                const held  = b.threat_held ? ' [HOLD]' : '';
                convEl.setAttribute('data-tooltip', `Score: ${b.total_score} + Bonus: ${bonus} = ${b.score_with_bonus} → Threat Lv ${b.threat_raw}${held}`);
            }

            if (data.threat_history) {
                updateThreatSparkline(data.threat_history);
            }

            threatEl.onclick = () => openEvidencePanel(strat);

            // ── HUD update ────────────────────────────────────────────────
            const p8 = strat.analytics || {};

            // Velocity Meter
            const velEl    = document.getElementById('hud-velocity');
            const arrowEl  = document.getElementById('hud-velocity-arrow');
            if (velEl && p8.velocity !== undefined) {
                const v = p8.velocity;
                const absV = Math.abs(v);
                // Scale: 0.001 pt/s ≈ 0.9 pt/cycle (900 s) for typical variation
                const dispV = absV < 0.0001 ? _t('hud.velocity.stable') : (absV * 900).toFixed(2) + _t('hud.velocity.unit');
                velEl.textContent = dispV;
                if (v > 0.0001)       { velEl.style.color='#ff6644'; arrowEl.textContent='↑'; arrowEl.style.color='#ff6644'; }
                else if (v < -0.0001) { velEl.style.color='#66ffaa'; arrowEl.textContent='↓'; arrowEl.style.color='#66ffaa'; }
                else                  { velEl.style.color='#aaa';    arrowEl.textContent='→'; arrowEl.style.color='#aaa'; }
            }
            // Ambush Alert
            const ambushWrap = document.getElementById('hud-ambush-wrap');
            if (ambushWrap) ambushWrap.style.display = p8.is_ambush ? 'flex' : 'none';

            // Blockade Index
            const blockadeEl   = document.getElementById('hud-blockade');
            const blockadeFill = document.getElementById('hud-blockade-fill');
            if (blockadeEl && p8.blockade_index !== undefined) {
                const bi = p8.blockade_index;
                blockadeEl.textContent = bi.toFixed(1);
                const pct = Math.min(bi / 10 * 100, 100);
                if (blockadeFill) {
                    blockadeFill.style.width = pct + '%';
                    blockadeFill.style.background = bi >= 7 ? '#ff2200' : bi >= 4 ? '#ff6600' : bi >= 1.5 ? '#ffaa00' : '#338833';
                }
                blockadeEl.style.color = bi >= 7 ? '#ff2200' : bi >= 4 ? '#ff6600' : bi >= 1.5 ? '#ffaa00' : '#aaa';
            }
            // Sequence Chain badge
            const chainEl = document.getElementById('hud-chain');
            if (chainEl && p8.sequence_status) {
                const sc = p8.sequence_status;
                chainEl.textContent = sc.includes('FULL_CHAIN') ? _t('hud.chain.full') : sc.includes('PARTIAL') ? _t('hud.chain.partial') : '—';
                chainEl.style.color = sc.includes('FULL_CHAIN') ? '#ff4444' : sc.includes('PARTIAL') ? '#ffaa00' : '#555';
            }
            // Update Evidence Chain Panel
            updateChainPanel(strat);

            // ── v9 new sensor panel update ───────────────────────────────
            if (document.getElementById('gn-panel')?.style.display !== 'none') {
                updateGreyNoisePanel(p8);
            }
            // Auto-log DEFCON changes to Analyst Notebook
            const newLevel = strat.threat_level;
            if (_lastDefconLevel !== null && _lastDefconLevel !== newLevel) {
                addNotebookEntry('DEFCON',
                    _t('notebook.entry.defcon', {dir: _lastDefconLevel > newLevel ? '▼' : '▲', from: _lastDefconLevel, to: newLevel, score: strat.threat_score || '?'}));
            }
            _lastDefconLevel = newLevel;

            // ── Intuition UI integrated call ───────────────────────────
            applyAmbientAtmosphere(strat.threat_level);
            updateRadioSilence(p8, strat);
            recordSignificantEvent(strat.threat_level);

            // ── Threat Situation Map (TSM) ──────────────────────────────
            const coreCode  = strat.core_theater;
            const coreTgt   = (data.targets || []).find(t => t.code === coreCode);
            const coreCoord = coreTgt ? {lat: coreTgt.lat, lng: coreTgt.lng} : null;
            updateThreatHalo(strat, coreCoord);
            updateSensorMarkers(strat, coreCoord);
            updateDrilldown(strat);

            // Refresh open panels only (suppress unnecessary API calls)
            const wbPanel = document.getElementById('weather-brief-panel');
            if (wbPanel && wbPanel.style.display !== 'none') renderWeatherBrief();
            const salPanel = document.getElementById('salute-panel');
            if (salPanel && salPanel.style.display !== 'none') renderSaluteBoard();
            const haPanel = document.getElementById('hist-analog-panel');
            if (haPanel && haPanel.style.display !== 'none') renderHistoricalAnalog();
        }

        // ── Sensor Fleet Health HUD ──
        _updateSensorHealthHUD(data.sensor_health);

        const originContainer = document.getElementById('origin-list-container');
        targetLayer.clearLayers(); sourceLayer.clearLayers(); lineLayer.clearLayers(); iodaLayer.clearLayers();
        let originHtml = "";

        const drawnLabels = new Set();

        function drawCountryLabel(lat, lng, name, code) {
            if (!drawnLabels.has(code)) {
                L.circleMarker([lat, lng], { radius: 1, color: 'transparent', fillColor: 'transparent' })
                 .bindTooltip(name.toUpperCase(), { permanent: true, direction: 'right', className: 'country-label', offset: [12, 0] })
                 .addTo(sourceLayer);
                drawnLabels.add(code);
            }
        }

        const targetCodesSet = new Set(
            (data.targets || []).filter(t => displayTargets.includes(t.code)).map(t => t.code)
        );

        if (displayTargets.length === 0) {
            originHtml = "<div style='color:grey; padding: 10px;'>No targets active. Turn on toggles in Target Visibility panel.</div>";
        } else if (data.targets) {
            const vecShareKey = currentVector === 'l3' ? 'global_share_l3' : currentVector === 'l7' ? 'global_share_l7' : 'global_share';
            data.targets.sort((a, b) => (b[vecShareKey] || 0) - (a[vecShareKey] || 0)).forEach(t => {
                if (!displayTargets.includes(t.code)) return;

                const isOutage = t.is_bgp_outage;
                const isEffOutage = t.is_bgp_effective;
                
                let targetClass = "target-normal";
                if (isOutage) {
                    targetClass = isEffOutage ? "target-degraded" : "target-weather";
                }

                const intel = ((data.strategic_alert || {}).country_intel || {})[t.code] || {};
                const iodaSt = intel.ioda_status || "NORMAL";
                const ixpCnt = intel.ixp_count || 0;
                const gdeltD = intel.gdelt;
                const airspD = intel.airspace;

                let badges = '';
                if (isOutage) {
                    if (isEffOutage) {
                        badges += `<span class="tm-badge tm-badge-bgp" data-tooltip="BGP/Outage Detected">BGP⚠</span>`;
                    } else {
                        badges += `<span class="tm-badge" style="border:1px solid #ffaa00; color:#ffaa00; background:rgba(255,170,0,0.18);" data-tooltip="Outage (Weather Muted)">BGP(Wx)</span>`;
                    }
                } else if (iodaSt === "BGP_OUTAGE") {
                    badges += `<span class="tm-badge" style="border:1px solid #ffaa00; color:#ffaa00; background:rgba(255,170,0,0.18);" data-tooltip="Outage (Weather Muted)">BGP(Wx)</span>`;
                }

                if (ixpCnt > 0)
                    badges += `<span class="tm-badge tm-badge-ixp">IXP×${ixpCnt}</span>`;
                
                if (gdeltD) {
                    if (gdeltD.status === "ALERT") {
                        badges += `<span class="tm-badge tm-badge-gdelt" data-tooltip="Media Tone Drop">M⚠</span>`;
                    } else if (gdeltD.status === "WEATHER_NOISE") {
                        badges += `<span class="tm-badge" style="border:1px solid #aaa; color:#aaa; background:rgba(170,170,170,0.15);" data-tooltip="Media Tone (Weather Muted)">M(Wx)</span>`;
                    }
                }
                
                if (airspD && airspD.severity && airspD.severity !== "NORMAL") {
                    if (airspD.status === "WEATHER_NOISE") {
                        badges += `<span class="tm-badge" style="border:1px solid #aaa; color:#aaa; background:rgba(170,170,170,0.15);" data-tooltip="Airspace Anomaly (Weather Muted)">✈(Wx)</span>`;
                    } else {
                        badges += `<span class="tm-badge tm-badge-air" data-tooltip="Airspace Anomaly">✈</span>`;
                    }
                }

                const dynamicIcon = L.divIcon({
                    className: '',
                    html: `<div class="target-marker-wrapper ${targetClass}"><div class="ddos-ring"></div><div class="ddos-core"></div>${badges ? `<div class="tm-badges-wrap">${badges}</div>` : ''}</div>`,
                    iconSize: [80, 80], iconAnchor: [40, 40], popupAnchor: [0, -40]
                });

                let targetLngShifted = shiftLng(t.lng);
                
                const netStatusTextTip = isOutage ? (isEffOutage ? _t('map.net.tooltip_outage') : _t('map.net.tooltip_wx')) : _t('map.net.tooltip_ok');

                L.marker([t.lat, targetLngShifted], { icon: dynamicIcon })
                 .bindTooltip(`<b>${t.info}</b> — ${netStatusTextTip}`, { direction: 'top', sticky: false })
                 .on('click', () => openCountryDetail(t.code))
                 .addTo(targetLayer);

                drawCountryLabel(t.lat, targetLngShifted, t.info, t.code);

                // P7-Opt: replace 30 divs with a single <canvas> (DOM reduction)
                let sparklineHtml = "";
                const histL3 = t.trend_history_l3 || [];
                const histL7 = t.trend_history_l7 || [];
                if (histL3.length > 0 || histL7.length > 0) {
                    sparklineHtml = `<canvas class="sparkline-canvas" width="64" height="20" data-l3="${histL3.join(',')}" data-l7="${histL7.join(',')}" data-vec="${currentVector}" title="L3(red)/L7(green) spike trend (75 min)"></canvas>`;
                }

                const targetShare = parseFloat(t[vecShareKey] || 0).toFixed(2);
                const vecLabel = currentVector === 'l3' ? 'L3' : currentVector === 'l7' ? 'L7' : 'GL';
                
                const netStatusText = isOutage ? (isEffOutage ? _t('map.net.outage') : _t('map.net.outage_wx')) : _t('map.net.normal');
                const statusColor = isOutage ? (isEffOutage ? "#ff2a2a" : "#ffaa00") : "#66ff66";
                const statusBadge = `<span class="status-badge" style="color: ${statusColor}; border-color: ${statusColor};" data-tooltip="${_t('map.net.tooltip_prefix')}${netStatusTextTip}">${_t('map.net.status_prefix')}${netStatusText}</span>`;
                
                const shiftActorStr = (t.shift_actors && t.shift_actors.length > 0) ? ` [${t.shift_actors.join(',')}]` : '';
                const shiftBadge = t.is_vector_shift ? `<span class="shift-badge" data-tooltip="Per-origin L7 shift detected from:${shiftActorStr}">L7 SHIFT${shiftActorStr}</span>` : "";

                const safeId = t.code.toLowerCase(); const listId = `list-${safeId}`; const arrowId = `arrow-${safeId}`;
                const displayStyle = collapsedTargets.has(listId) ? 'none' : 'block';
                const arrowTxt = collapsedTargets.has(listId) ? '▶' : '▼';

                originHtml += `
                    <div class="target-group-title" onclick="toggleTargetList('${listId}', '${arrowId}')" data-tooltip="${t.info} | Global: ${targetShare}% | Net: ${netStatusTextTip}">
                        <div class="target-title-left">
                            <span id="${arrowId}" class="toggle-arrow">${arrowTxt}</span>
                            <span class="target-name">[ ${t.info} ]</span>
                            <span class="target-share">(${vecLabel}: ${targetShare}%)</span>
                        </div>
                        <div class="target-title-right">
                            ${shiftBadge}
                            ${statusBadge}
                            ${sparklineHtml}
                        </div>
                    </div>
                    <ul id="${listId}" class='origin-list-ul' style="display: ${displayStyle};">
                `;

                if (t.sources && t.sources.length > 0) {
                    const getW = s => currentVector === 'l3' ? (s.l3_weight || 0) : currentVector === 'l7' ? (s.l7_weight || 0) : (s.weight || 0);
                    const getSpike = s => currentVector === 'l3' ? (s.l3_spike || s.spike_factor || 1.0) : currentVector === 'l7' ? (s.l7_spike || s.spike_factor || 1.0) : (s.spike_factor || 1.0);

                    const sortedSources = t.sources
                        .filter(s => getW(s) > 0.001)
                        .sort((a, b) => getW(b) - getW(a));

                    if (sortedSources.length === 0) {
                        originHtml += `<li style="color:grey;">${_t('map.no_threats_vector')}</li>`;
                    } else {
                    sortedSources.forEach(s => {
                        const w = getW(s); const spike = getSpike(s);
                        let lineColor, lineOpacity, speedClass, glowClass, spikeHtml = "";
                        if (spike >= 6.0) { lineColor = '#ff2a2a'; lineOpacity = 0.9; speedClass = 'flow-fast'; glowClass = 'glow-high'; spikeHtml = `<span class="spike-alert">SEVERE (x${spike})</span>`;
                        } else if (spike >= 2.0) { lineColor = '#ffaa00'; lineOpacity = 0.75; speedClass = 'flow-medium'; glowClass = 'glow-none'; spikeHtml = `<span style="color:#ffaa00; font-size:11px; margin-left:5px;">Elevated (x${spike})</span>`;
                        } else if (w >= 1.0) { lineColor = '#ffaa00'; lineOpacity = 0.25; speedClass = 'flow-medium'; glowClass = 'glow-none';
                        } else { lineColor = '#cc88ff'; lineOpacity = 0.60; speedClass = 'flow-slow'; glowClass = 'glow-none'; }

                        const totalPct = parseFloat(w).toFixed(2);
                        const l3Pct = parseFloat(s.l3_weight).toFixed(2); const l7Pct = parseFloat(s.l7_weight).toFixed(2);
                        const vecDetail = currentVector === 'all'
                            ? `<span class="origin-stats">↳ <span style="color:#ff6666">L3: ${l3Pct}%</span> / <span style="color:#66ff66">L7: ${l7Pct}%</span></span>`
                            : currentVector === 'l3'
                                ? `<span class="origin-stats">↳ <span style="color:#ff6666">L3: ${l3Pct}%</span> <span style="color:#555">/ L7: ${l7Pct}%</span></span>`
                                : `<span class="origin-stats">↳ <span style="color:#555">L3: ${l3Pct}% /</span> <span style="color:#66ff66"> L7: ${l7Pct}%</span></span>`;

                        const originShiftBadge = s.is_l7_shift ? `<span style="color:#ffaa00; font-size:10px; font-weight:bold; margin-left:5px; border:1px solid #ffaa00; padding:1px 3px; border-radius:2px;">L7&uarr;</span>` : "";
                        const confClass = s.confidence === 'HIGH' ? 'conf-high' : s.confidence === 'MEDIUM' ? 'conf-medium' : 'conf-low';
                        const confBadge = s.confidence ? `<span class="conf-badge ${confClass}">${s.confidence}</span>` : "";
                        const newActorBadge = s.is_new_actor ? `<span class="new-actor-badge" data-tooltip="No 28-day baseline: new infrastructure">NEW</span>` : "";
                        const asnLabel = s.state_asns && s.state_asns.length > 0 ? s.state_asns.join(',') : '';
                        const stateAsnBadge = s.is_state_asn ? `<span class="state-asn-badge" data-tooltip="State-attributed ASN detected:\n${asnLabel}">STATE-ASN</span>` : "";
                        originHtml += `<li class="origin-item"><span style="color:${lineColor}; font-size:14px;">■</span> <b>${s.name}</b> <span style="color:#fff;">[${totalPct}%]</span> ${spikeHtml}${originShiftBadge}${stateAsnBadge}${newActorBadge}${confBadge} ${vecDetail}</li>`;

                        let sourceLngShifted = shiftLng(s.lng);

                        L.circleMarker([s.lat, sourceLngShifted], { radius: 4, color: lineColor, fillColor: lineColor, fillOpacity: lineOpacity + 0.2 })
                         .addTo(sourceLayer);

                        drawCountryLabel(s.lat, sourceLngShifted, s.name, s.code);

                        const curvePoints = getCurvePoints(s.lat, sourceLngShifted, t.lat, targetLngShifted);
                        // Line weight: L2 max 2.5px (SEVERE), L1 = L2+2px for rail halo
                        const baseWidth = Math.max(0.8, Math.min(2.5, w * 1.8));
                        const dynamicLineWidth = glowClass === 'glow-high' ? Math.min(3.0, baseWidth + 0.6) : baseWidth;
                        // Base opacity per severity
                        const trackOpacity = { 'flow-fast': 0.38, 'flow-medium': 0.26, 'flow-slow': 0.15 }[speedClass] || 0.20;
                        // Layer 1: base track — 2px wider than dot layer for visible rail
                        L.polyline(curvePoints, { color: lineColor, weight: dynamicLineWidth + 2, opacity: trackOpacity, interactive: false }).addTo(lineLayer);
                        // Layer 2: firefly dots — fixed 8px dot size and constant px/s speed regardless of arc length
                        const pl = L.polyline(curvePoints, { className: `attack-curve ${speedClass}`, color: lineColor, weight: dynamicLineWidth, opacity: lineOpacity, interactive: false }).addTo(lineLayer);
                        const el = pl.getElement();
                        if (el) {
                            const pxLen = el.getTotalLength();
                            el.setAttribute('pathLength', '100');
                            // Dot count scales with arc length (1–4 dots)
                            const numDots = pxLen < 150 ? 1 : pxLen < 300 ? 2 : pxLen < 500 ? 3 : 4;
                            // Fixed 8px dot in pathLength-normalised units, capped so dots always fit
                            const dotUnits = Math.min(8 * 100 / pxLen, 100 / (numDots * 2));
                            const gapUnits = (100 - numDots * dotUnits) / numDots;
                            const dash = `${dotUnits.toFixed(3)} ${gapUnits.toFixed(3)}`;
                            el.style.strokeDasharray = Array(numDots).fill(dash).join(' ');
                            const pxPerSec = { 'flow-fast': 80, 'flow-medium': 35, 'flow-slow': 12 }[speedClass] || 30;
                            el.style.animationDuration = `${Math.max(1, pxLen / pxPerSec).toFixed(2)}s`;
                        }
                    });
                    }
                } else { originHtml += `<li style="color:grey;">${_t('map.no_threats')}</li>`; }
                originHtml += `</ul>`;
            });
        }
        
        airspaceLayer.clearLayers(); weatherLayer.clearLayers();
        gdeltLayer.clearLayers(); criticalNodesLayer.clearLayers();
        
        // Clear layers
        firmsLayer.clearLayers(); cableRoutesLayer.clearLayers(); chokepointsLayer.clearLayers();
        isrZoneLayer.clearLayers(); isrAircraftLayer.clearLayers();
        aisVesselLayer.clearLayers();

        const overlays = data.strategic_alert && data.strategic_alert.map_overlays;
        if (overlays) {
            (overlays.ioda_outages || []).forEach(o => {
                if (targetCodesSet.has(o.code)) return;
                const lngS = shiftLng(o.lng);
                const icon = L.divIcon({
                    className: '',
                    html: `<div style="width:0;height:0;border-left:9px solid transparent;border-right:9px solid transparent;border-bottom:18px solid #ff2a2a;filter:drop-shadow(0 0 6px #ff2a2a);"></div>`,
                    iconSize: [18, 18], iconAnchor: [9, 18],
                });
                L.marker([o.lat, lngS], { icon })
                 .bindPopup(`<b>${o.name}</b><br><span style="color:#ff2a2a;">${_t('map.popup.bgp_outage')}</span>`)
                 .on('click', () => openCountryDetail(o.code))
                 .addTo(iodaLayer);
            });

            (overlays.airspace_anomaly || []).forEach(a => {
                const lngS = shiftLng(a.lng);
                const isClosure = a.severity === 'CLOSURE';
                const col  = isClosure ? '#ff2a2a' : '#ffaa00';
                const glow = isClosure ? 'drop-shadow(0 0 8px #ff2a2a)' : 'drop-shadow(0 0 5px #ffaa00)';
                const icon = L.divIcon({
                    className: '',
                    html: `<div style="font-size:18px;line-height:1;filter:${glow}; cursor:help;" data-tooltip="${a.airport}: ${a.drop_pct}% drop (${a.count}/${a.baseline} ac)">✈</div>`,
                    iconSize: [20, 20], iconAnchor: [10, 10],
                });
                L.marker([a.lat, lngS], { icon })
                 .bindPopup(
                    `<b>${a.airport} (${a.code})</b><br>` +
                    `<span style="color:${col};font-weight:bold;">${a.severity}</span><br>` +
                    `Aircraft: ${a.count} (baseline: ${a.baseline})<br>` +
                    `Drop: <b>${a.drop_pct}%</b>`
                 )
                 .addTo(airspaceLayer);
            });

            (overlays.weather_events || []).forEach(w => {
                const lngS = shiftLng(w.lng);
                const isSevere = w.is_severe;
                const col   = isSevere ? '#ff6600' : '#aaaaaa';
                const emoji = isSevere ? '⛈' : '🌧';
                const icon  = L.divIcon({
                    className: '',
                    html: `<div style="font-size:16px;line-height:1;filter:drop-shadow(0 0 4px ${col}); cursor:help;" data-tooltip="${w.description} — wind ${w.wind_speed}m/s">${emoji}</div>`,
                    iconSize: [18, 18], iconAnchor: [-16, 34],
                });
                L.marker([w.lat, lngS], { icon })
                 .bindPopup(
                    `<b>Weather: ${w.code}</b><br>` +
                    `<span style="color:${col};">${w.description}</span><br>` +
                    `Severity: ${w.severity} | Wind: ${w.wind_speed} m/s` +
                    (isSevere ? '<br><i style="color:#ffaa00;">Noise filter active: suppresses BGP/Airspace alerts</i>' : '')
                 )
                 .addTo(weatherLayer);
            });

            (overlays.gdelt_events || []).forEach(g => {
                const lngS   = shiftLng(g.lng);
                const isAlert = g.is_alert;
                const col    = isAlert ? '#cc44ff' : '#8855aa';
                const glow   = isAlert ? 'drop-shadow(0 0 8px #cc44ff)' : 'drop-shadow(0 0 4px #8855aa)';
                const deltaStr = g.delta != null ? `Δ${g.delta > 0 ? '+' : ''}${g.delta.toFixed(1)}` : 'Δ N/A';
                const icon = L.divIcon({
                    className: '',
                    html: `<div style="width:22px;height:22px;border-radius:50%;border:3px solid ${col};background:${col}33;filter:${glow};box-sizing:border-box;"></div>`,
                    iconSize: [22, 22], iconAnchor: [36, 36],
                });
                const baseStr = g.tone_baseline != null ? g.tone_baseline.toFixed(1) : 'N/A';
                L.marker([g.lat, lngS], { icon })
                 .bindPopup(
                    `<b>${g.name} — Media Tone</b><br>` +
                    `<span style="color:${col};">` +
                    (g.tone_current != null ? `Tone: <b>${g.tone_current.toFixed(1)}</b>` : 'Tone: N/A') +
                    `</span><br>` +
                    `Baseline (28d): ${baseStr} | ${deltaStr}<br>` +
                    `Status: <b>${g.status}</b>` +
                    (g.status === 'WEATHER_NOISE' ? '<br><i style="color:#ffaa00;">Noise filter: severe weather active</i>' : '')
                 )
                 .addTo(gdeltLayer);
            });

            const ixpByCountry = {};
            (overlays.critical_nodes || []).forEach(n => {
                if (targetCodesSet.has(n.country)) return;
                if (!ixpByCountry[n.country]) ixpByCountry[n.country] = { lat: n.lat, lng: n.lng, ixps: [] };
                ixpByCountry[n.country].ixps.push(n.name);
            });
            Object.entries(ixpByCountry).forEach(([country, info]) => {
                const lngS  = shiftLng(info.lng);
                const count = info.ixps.length;
                const col   = '#ffee44';
                const icon  = L.divIcon({
                    className: '',
                    html: `<div style="position:relative;width:10px;height:10px;transform:rotate(45deg);background:${col}33;border:2px solid ${col};filter:drop-shadow(0 0 3px ${col});box-sizing:border-box;"></div>`,
                    iconSize: [10, 10], iconAnchor: [5, 5],
                });
                const nameList = info.ixps.slice(0, 5).join('<br>') + (count > 5 ? `<br>…and ${count-5} more` : '');
                L.marker([info.lat, lngS], { icon })
                 .bindPopup(`<b style="color:${col};">IXP [${country}]</b> × ${count}<br><span style="font-size:11px;color:#aaa;">${nameList}</span>`)
                 .on('click', () => openCountryDetail(country))
                 .addTo(criticalNodesLayer);
            });

            // Render NASA FIRMS Anomalies
            (overlays.firms_anomalies || []).forEach(f => {
                const lngS = shiftLng(f.lng);
                const icon = L.divIcon({ 
                    html: `<div style="font-size:20px; filter:drop-shadow(0 0 10px #ff2a2a); cursor:help;" data-tooltip="Thermal Anomaly (FIRMS)">🔥</div>`, 
                    className: '', 
                    iconSize: [20,20] 
                });
                L.marker([f.lat, lngS], {icon})
                 .bindPopup(`<b>Thermal Anomaly (FIRMS)</b><br>Code: ${f.code}<br><span style="color:#ff2a2a; font-weight:bold;">Kinetic Strike Precursor</span>`)
                 .addTo(firmsLayer);
            });

            // ── Render Cable Routes (static polylines) ──────────────────
            // Anti-meridian segment splitting + endpoint interpolation:
            // Detect segments where |ΔLng|>180, linearly interpolate the exact latitude
            // at the map edge (±180°), and snap segment endpoints to ±180° exactly.
            // This ensures the map cut and the cable line cut coincide.
            function buildRouteSegments(waypoints) {
                const pts = waypoints.map(w => [w.lat, shiftLng(w.lng)]);
                if (mapCenterMode === 'pacific') return [pts]; // shiftLng already resolved
                const segments = [];
                let seg = [pts[0]];
                for (let i = 1; i < pts.length; i++) {
                    const prev = seg[seg.length - 1];
                    const curr = pts[i];
                    const dLng = curr[1] - prev[1];
                    if (Math.abs(dLng) > 180) {
                        // Segment crossing the anti-meridian (±180°): interpolate the crossing point
                        const fromEast  = prev[1] > 0; // crossing from the +180 side?
                        const edgeA     = fromEast ?  180 : -180; // end longitude of this segment
                        const edgeB     = fromEast ? -180 :  180; // start longitude of next segment
                        // actual angular distance crossed (always positive)
                        const totalDist = fromEast
                            ? (180 - prev[1]) + (curr[1] + 180)
                            : (prev[1] + 180) + (180 - curr[1]);
                        const frac      = fromEast
                            ? (180 - prev[1]) / totalDist
                            : (prev[1] + 180) / totalDist;
                        const crossLat  = prev[0] + frac * (curr[0] - prev[0]);
                        seg.push([crossLat, edgeA]);
                        if (seg.length >= 2) segments.push(seg);
                        seg = [[crossLat, edgeB], curr];
                    } else {
                        seg.push(curr);
                    }
                }
                if (seg.length >= 2) segments.push(seg);
                return segments;
            }

            (overlays.cable_routes || []).forEach(route => {
                const segs = buildRouteSegments(route.waypoints || []);
                if (!segs.length) return;
                const popupHtml = `
                    <div style="min-width:220px;padding:10px 12px 8px;">
                        <div style="color:#5ab8cc;font-weight:bold;font-size:12px;letter-spacing:0.5px;margin-bottom:2px;">▬ ${route.name}</div>
                        <div style="color:#335566;font-size:9px;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;border-bottom:1px solid #1a2e3a;padding-bottom:6px;">SUBMARINE CABLE ROUTE</div>
                        <div style="color:#889;font-size:10px;margin-bottom:6px;">${route.description || ''}</div>
                        ${route.connects && route.connects.length ? `<div style="color:#446677;font-size:9px;border-top:1px solid #1a2e3a;padding-top:5px;line-height:1.7;">CONNECTS:<br><span style="color:#667;">${route.connects.join(' → ')}</span></div>` : ''}
                    </div>
                `;
                segs.forEach(pts => {
                    L.polyline(pts, {
                        color: '#5ab8cc',
                        weight: 1.5,
                        opacity: 0.25,
                        lineJoin: 'round'
                    }).bindPopup(popupHtml).addTo(cableRoutesLayer);
                });
            });

            // ── Render Cable Chokepoints (enhanced) ──────────────────────
            (overlays.chokepoints || []).forEach(c => {
                const lngS  = shiftLng(c.lng);
                const status = c.status  || 'normal';
                const cpType = c.type    || 'cable_landing';

                // Color by status and type
                const BASE_COLOR = {
                    cable_landing:   '#00ffff',
                    maritime_strait: '#ffaa00',
                    nato_corridor:   '#4488ff',
                };
                const STATUS_COLOR = {
                    dark_gap:   '#ff3300',
                    stationary: '#ff9900',
                    normal:     BASE_COLOR[cpType] || '#00ffff',
                };
                const color = STATUS_COLOR[status];

                // AIS surveillance zone circle (55 km)
                const zoneAlpha = status === 'dark_gap' ? 0.18 : status === 'stationary' ? 0.10 : 0.04;
                L.circle([c.lat, lngS], {
                    radius:      55000,
                    color:       color,
                    weight:      status === 'dark_gap' ? 1.5 : 0.8,
                    opacity:     status !== 'normal'   ? 0.65 : 0.25,
                    fillColor:   color,
                    fillOpacity: zoneAlpha,
                    interactive: false,
                    dashArray:   status === 'normal' ? '4 6' : null,
                }).addTo(chokepointsLayer);

                // Type icon
                const ICON_CHAR = { cable_landing:'◆', maritime_strait:'⬡', nato_corridor:'⬟' };
                const iconChar  = ICON_CHAR[cpType] || '◆';
                const fontSize  = cpType === 'maritime_strait' ? 16 : 14;
                const pulseStyle = status === 'dark_gap' ? 'animation:cp-pulse 1s infinite;' : '';

                const icon = L.divIcon({
                    html: `<div style="color:${color};font-size:${fontSize}px;filter:drop-shadow(0 0 6px ${color});cursor:help;${pulseStyle}">${iconChar}</div>`,
                    className: '',
                    iconSize:   [16, 16],
                    iconAnchor: [8, 8],
                });

                // Rich popup
                const TYPE_LABEL = {
                    cable_landing:   'Cable Landing Station',
                    maritime_strait: 'Maritime Chokepoint',
                    nato_corridor:   'NATO Cable Corridor',
                };
                const STATUS_BADGE = {
                    dark_gap:   `<span style="color:#ff3300;font-weight:bold;">⚠ AIS DARK GAP DETECTED</span>`,
                    stationary: `<span style="color:#ff9900;font-weight:bold;">⚓ STATIONARY ANOMALY</span>`,
                    normal:     `<span style="color:#00cc66;">● NORMAL</span>`,
                };
                const cablesHtml = (c.cables && c.cables.length)
                    ? `<div style="margin-top:5px;color:#aaa;font-size:9px;">CABLES: ${c.cables.join(', ')}</div>`
                    : '';

                L.marker([c.lat, lngS], {icon})
                 .bindPopup(`
                    <div style="min-width:220px;padding:10px 12px 8px;">
                        <div style="color:${color};font-weight:bold;font-size:12px;letter-spacing:0.5px;margin-bottom:2px;">${iconChar} ${c.name}</div>
                        <div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;border-bottom:1px solid #1a2e3a;padding-bottom:6px;">${TYPE_LABEL[cpType]||cpType} &nbsp;·&nbsp; ${c.country}</div>
                        <div style="margin-bottom:6px;">${STATUS_BADGE[status]||STATUS_BADGE.normal}</div>
                        ${cablesHtml}
                        <div style="margin-top:7px;color:#334455;font-size:9px;letter-spacing:0.5px;">AIS MONITOR RADIUS: 55 km</div>
                    </div>
                 `, { maxWidth: 280 })
                 .addTo(chokepointsLayer);
            });
            // ── ISR Hotspot Zones ─────────────────────────────────────────
            (overlays.isr_hotspots || []).forEach(hs => {
                const lngS   = shiftLng(hs.lng);
                const isSurge = hs.is_surge;
                const col    = isSurge ? '#ff4400' : '#ffaa00';
                // Monitoring radius circle
                L.circle([hs.lat, lngS], {
                    radius:      (hs.radius_km || 200) * 1000,
                    color:       col,
                    weight:      isSurge ? 1.5 : 0.8,
                    opacity:     isSurge ? 0.65 : 0.25,
                    fillColor:   col,
                    fillOpacity: isSurge ? 0.10 : 0.03,
                    interactive: false,
                    dashArray:   isSurge ? null : '6 10',
                }).addTo(isrZoneLayer);
                // Center marker
                const icon = L.divIcon({
                    html: `<div style="color:${col};font-size:12px;filter:drop-shadow(0 0 5px ${col});${isSurge ? 'animation:cp-pulse 1s infinite;' : ''}">✦</div>`,
                    className: '', iconSize: [12, 12], iconAnchor: [6, 6],
                });
                L.marker([hs.lat, lngS], { icon })
                 .bindPopup(
                    `<div style="min-width:200px;padding:8px 10px 6px;">` +
                    `<div style="color:${col};font-weight:bold;font-size:12px;">✦ ${hs.name}</div>` +
                    `<div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1px;margin:4px 0;">ISR HOTSPOT ZONE · ${hs.theater}</div>` +
                    `<div>ISR Aircraft: <b style="color:${col};">${hs.isr_count}</b></div>` +
                    `<div>Status: <b style="color:${col};">${isSurge ? '⚡ SURGE' : '● NORMAL'}</b></div>` +
                    `<div style="color:#555;font-size:9px;margin-top:4px;">Radius: ${hs.radius_km || 200} km</div>` +
                    `</div>`
                 )
                 .addTo(isrZoneLayer);
            });

            // ── ISR Aircraft (individual tracks) ─────────────────────────
            (overlays.isr_hotspots || []).forEach(hs => {
                (hs.tracks || []).forEach(ac => {
                    if (ac.lat == null || ac.lon == null) return;
                    const lngS  = shiftLng(ac.lon);
                    const hdg   = ac.heading || 0;
                    const isMil = ac.squawk === '7777';
                    const col   = isMil ? '#ff2200' : '#ffaa00';
                    const altKm = (ac.alt_m / 1000).toFixed(1);
                    const velKt = Math.round((ac.vel_ms || 0) * 1.944);
                    const icon  = L.divIcon({
                        html: `<div style="color:${col};font-size:14px;line-height:1;transform:rotate(${hdg}deg);filter:drop-shadow(0 0 6px ${col});">▲</div>`,
                        className: '', iconSize: [14, 14], iconAnchor: [7, 7],
                    });
                    L.marker([ac.lat, lngS], { icon })
                     .bindPopup(
                        `<div style="min-width:180px;padding:8px 10px 6px;">` +
                        `<div style="color:${col};font-weight:bold;font-size:12px;">▲ ISR TRACK</div>` +
                        `<div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1px;margin:4px 0;">${hs.name}</div>` +
                        `<div>Callsign: <b>${ac.callsign || ac.icao24 || '—'}</b></div>` +
                        `<div>Alt: <b>${altKm} km</b> &nbsp;|&nbsp; Speed: <b>${velKt} kt</b></div>` +
                        (ac.squawk ? `<div>Squawk: <b style="color:${col};">${ac.squawk}</b></div>` : '') +
                        `</div>`
                     )
                     .addTo(isrAircraftLayer);
                });
            });

            // ── AIS Vessels (dark gaps + stationary anomalies) ────────────
            (overlays.ais_dark_gaps || []).forEach(v => {
                if (v.lat == null || v.lng == null) return;
                const lngS = shiftLng(v.lng);
                const icon = L.divIcon({
                    html: `<div style="color:#ff3300;font-size:18px;line-height:1;filter:drop-shadow(0 0 7px #ff3300);animation:cp-pulse 1s infinite;">⚓</div>`,
                    className: '', iconSize: [18, 18], iconAnchor: [9, 9],
                });
                L.marker([v.lat, lngS], { icon })
                 .bindPopup(
                    `<div style="min-width:200px;padding:8px 10px 6px;">` +
                    `<div style="color:#ff3300;font-weight:bold;font-size:12px;">⚓ AIS DARK GAP</div>` +
                    `<div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1px;margin:4px 0;">EMCON / TRANSPONDER SILENT</div>` +
                    `<div>Vessel: <b>${esc(v.name || v.mmsi)}</b></div>` +
                    `<div>Silent: <b style="color:#ff3300;">${v.gap_hours} h</b></div>` +
                    `<div>Chokepoint: ${esc(v.chokepoint)}</div>` +
                    `<div>Distance: ${v.dist_km} km</div>` +
                    `</div>`
                 )
                 .addTo(aisVesselLayer);
            });
            (overlays.ais_stationary || []).forEach(v => {
                if (v.lat == null || v.lng == null) return;
                const lngS = shiftLng(v.lng);
                const icon = L.divIcon({
                    html: `<div style="color:#ff9900;font-size:18px;line-height:1;filter:drop-shadow(0 0 5px #ff9900);">⚓</div>`,
                    className: '', iconSize: [18, 18], iconAnchor: [9, 9],
                });
                L.marker([v.lat, lngS], { icon })
                 .bindPopup(
                    `<div style="min-width:200px;padding:8px 10px 6px;">` +
                    `<div style="color:#ff9900;font-weight:bold;font-size:12px;">⚓ STATIONARY ANOMALY</div>` +
                    `<div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1px;margin:4px 0;">NON-COMMERCIAL VESSEL ANCHORED</div>` +
                    `<div>Vessel: <b>${esc(v.name || v.mmsi)}</b></div>` +
                    `<div>Chokepoint: ${esc(v.chokepoint)}</div>` +
                    `<div>Distance: ${v.dist_km} km</div>` +
                    `</div>`
                 )
                 .addTo(aisVesselLayer);
            });

        }

        originContainer.innerHTML = originHtml;

        // ── Intuition UI: Pulse Display + Threat Terrain (common to all renders) ──
        updatePulseDisplay(data.threat_history || []);
        updateThreatTerrain(data);

        // P7-Opt: batch Canvas rendering after innerHTML is finalized
        originContainer.querySelectorAll('.sparkline-canvas').forEach(cvs => {
            const l3 = cvs.dataset.l3 ? cvs.dataset.l3.split(',').map(Number) : [];
            const l7 = cvs.dataset.l7 ? cvs.dataset.l7.split(',').map(Number) : [];
            const vec = cvs.dataset.vec || 'all';
            const ctx = cvs.getContext('2d');
            const W = cvs.width, H = cvs.height, half = H / 2;
            const barW = 3, gap = 1;
            ctx.clearRect(0, 0, W, H);
            ctx.globalAlpha = vec === 'l7' ? 0.25 : 1.0;
            ctx.fillStyle = '#ff6666';
            l3.forEach((v, i) => { const bh = Math.min(half, v * 5); ctx.fillRect(i * (barW + gap), half - bh, barW, bh); });
            ctx.globalAlpha = vec === 'l3' ? 0.25 : 1.0;
            ctx.fillStyle = '#66ff66';
            l7.forEach((v, i) => { const bh = Math.min(half, v * 5); ctx.fillRect(i * (barW + gap), half, barW, bh); });
        });
    }

    function saveLocalState() {
        const stateObj = getCurrentConfig();
        stateObj.pins = {};
        document.querySelectorAll('.check-pin').forEach(cb => stateObj.pins[cb.value] = cb.checked);

        stateObj.layout = {};
        ALL_DOCKABLE_PANELS.forEach(({ id, ph }) => {
            const panel = document.getElementById(id);
            if (!panel) return;
            const content = panel.querySelector('.panel-content');
            const toggleBtn = panel.querySelector('.toggle-btn');
            stateObj.layout[id] = {
                docked:    panel.classList.contains('docked'),
                visible:   panel.style.display !== 'none',
                minimized: content && toggleBtn ? content.style.display === 'none' : false,
                top: panel.style.top, left: panel.style.left,
                width: panel.style.width, height: panel.style.height,
                ph,
            };
        });

        stateObj.ui = {
            vector: currentVector,
            mapCenter: mapCenterMode
        };
        stateObj.layoutVersion = LAYOUT_VERSION;
        stateObj.sidebarOrder  = JSON.parse(JSON.stringify(_sidebarOrder));

        localStorage.setItem('ctiIntelAlerts', JSON.stringify(stateObj));
    }

    function restoreLayoutState(layoutState) {
        ALL_DOCKABLE_PANELS.forEach(({ id, ph: defaultPh }) => {
            const state = layoutState[id];
            if (!state) return;
            const panel = document.getElementById(id);
            if (!panel) return;
            const content  = panel.querySelector('.panel-content');
            const toggleBtn = panel.querySelector('.toggle-btn');
            const dockBtn  = panel.querySelector('.dock-btn');
            const phId     = state.ph || defaultPh;
            const placeholder = document.getElementById(phId);

            // Restore minimize state
            if (content && toggleBtn) {
                if (state.minimized) {
                    content.style.display = 'none'; toggleBtn.innerText = '＋'; toggleBtn.classList.add('active-btn');
                    if (state.docked && id === 'dashboard-panel') { panel.style.flexGrow = '0'; if (placeholder) placeholder.style.flexGrow = '0'; }
                } else {
                    content.style.display = 'flex'; toggleBtn.innerText = '−'; toggleBtn.classList.remove('active-btn');
                    if (state.docked && id === 'dashboard-panel') { panel.style.flexGrow = '1'; if (placeholder) placeholder.style.flexGrow = ''; }
                }
            }

            // Docked panels are always visible; floating panels use saved visibility (default: true)
            const isVisible = state.docked ? true : (state.visible !== false);
            if (state.docked && placeholder) {
                placeholder.appendChild(panel);
                panel.classList.remove('floating', 'active'); panel.classList.add('docked');
                panel.style.left = ''; panel.style.top = ''; panel.style.width = ''; panel.style.height = '';
                panel.style.display = isVisible ? 'flex' : 'none';
                if (dockBtn) dockBtn.style.display = 'none';
            } else {
                document.body.appendChild(panel);
                panel.classList.remove('docked'); panel.classList.add('floating');
                panel.style.top   = state.top   || '';
                panel.style.left  = state.left  || '';
                panel.style.width = state.width || '';
                panel.style.height = state.height || '';
                panel.style.display = isVisible ? 'flex' : 'none';
                if (dockBtn) dockBtn.style.display = 'inline-block';
            }
        });
        updateSidebarVisibility();
        syncToolsMenuState();
    }

    const LAYOUT_VERSION = 10; // bump when layout structure changes to auto-clear stale state

    function loadTargetState(defaults) {
        // Initialize THEATERS from app_config global list before building UI
        if (defaults.available_countries && defaults.available_countries.length) {
            THEATERS = defaults.available_countries.map(c => ({ code: c.code, name: c.name, region: c.region || 'Other', lat: c.lat, lng: c.lng }));
        }
        if (defaults.strategic_blocs)   STRATEGIC_BLOCS_DATA = defaults.strategic_blocs;
        if (defaults.adversary_options) ADVERSARY_OPTIONS    = defaults.adversary_options;
        if (defaults.country_bloc_tags) COUNTRY_BLOC_TAGS    = defaults.country_bloc_tags;
        buildTheaterUI();

        const savedState = localStorage.getItem('ctiIntelAlerts');
        if (savedState) {
            const stateObj = JSON.parse(savedState);
            // If saved layout version is outdated, discard only the layout portion
            if (!stateObj.layoutVersion || stateObj.layoutVersion < LAYOUT_VERSION) {
                delete stateObj.layout;
            }
            document.querySelectorAll('#strategy-tbody tr').forEach(tr => {
                const coreRadio = tr.querySelector('.radio-core'); const corrCb = tr.querySelector('.check-correlate');
                if (coreRadio && stateObj.core === coreRadio.value) coreRadio.checked = true;
                if (corrCb && stateObj.correlates && Array.isArray(stateObj.correlates)) {
                    corrCb.checked = stateObj.correlates.includes(corrCb.value);
                }
            });
            document.querySelectorAll('.check-adversary').forEach(cb => { 
                if (stateObj.adversaries && Array.isArray(stateObj.adversaries)) {
                    cb.checked = stateObj.adversaries.includes(cb.value);
                } 
            });
            document.querySelectorAll('.check-pin').forEach(cb => { 
                if (stateObj.pins && stateObj.pins[cb.value] !== undefined) {
                    cb.checked = stateObj.pins[cb.value]; 
                }
            });
            
            renderQuickToggles();
            document.querySelectorAll('.check-display').forEach(cb => { 
                if (stateObj.displays && Array.isArray(stateObj.displays)) {
                    cb.checked = stateObj.displays.includes(cb.value); 
                }
            });
            
            if (stateObj.layout) restoreLayoutState(stateObj.layout);
            if (stateObj.sidebarOrder) {
                _sidebarOrder = stateObj.sidebarOrder;
                applyPlaceholderOrder('left-sidebar');
                applyPlaceholderOrder('sidebar');
            }

            if (stateObj.ui) {
                currentVector = stateObj.ui.vector || 'all';
                mapCenterMode = stateObj.ui.mapCenter || 'pacific';
            }
        } else {
            const defaultCore = document.querySelector(`.radio-core[value="${defaults.default_core}"]`); if(defaultCore) defaultCore.checked = true;
            defaults.default_correlates.forEach(c => { const cb = document.querySelector(`.check-correlate[value="${c}"]`); if(cb) cb.checked = true; });
            defaults.default_adversaries.forEach(c => { const cb = document.querySelector(`.check-adversary[value="${c}"]`); if(cb) cb.checked = true; });
            defaults.default_pins.forEach(c => { const cb = document.querySelector(`.check-pin[value="${c}"]`); if(cb) cb.checked = true; });
            
            renderQuickToggles();
            document.querySelectorAll('.check-display').forEach(cb => cb.checked = true);
        }
        
        mapCenterMode = 'atlantic';
        map.setView([20.0, 10.0], map.getZoom(), { animate: false });
        
        ['all', 'l3', 'l7'].forEach(key => {
            const btn = document.getElementById(`vec-btn-${key}`);
            const activeClass = key === 'l3' ? 'active-l3' : key === 'l7' ? 'active-l7' : 'active-all';
            btn.className = 'vec-btn' + (key === currentVector ? ` ${activeClass}` : '');
        });

        updateUIConsistency();
    }

    document.addEventListener('change', (e) => {
        if (e.target.matches('.check-pin, .radio-core, .check-correlate')) {
            renderQuickToggles();
        }
        if (e.target.matches('.check-pin, .radio-core, .check-correlate, .check-adversary, .check-display')) {
            updateUIConsistency();
            saveLocalState();
            checkPendingState();
        }
        if (e.target.matches('.check-display') && latestData) {
            renderTelemetry(latestData);
        }
    });

    async function initApp() {
        // Display logged-in username in HUD
        const _storedUser = localStorage.getItem('radar_username');
        const _storedRole = localStorage.getItem('radar_role');
        if (_storedUser) {
            const el = document.getElementById('hud-username');
            if (el) el.textContent = `${_storedUser} (${_storedRole || 'viewer'})`;
        }

        let defaults = {
            default_core: "TW",
            default_correlates: ["JP", "US"],
            default_adversaries: ["CN", "RU", "KP"],
            default_pins: ["TW", "JP", "US"]
        };
        try {
            const res = await fetch(`/api/app_config`);
            if (res.ok) {
                defaults = await res.json();
            }
        } catch(e) {
            console.warn("Failed to load config from backend. Using fallbacks.", e);
        }
        
        loadTargetState(defaults);
        lastSyncedConfig = getCurrentConfig();

        // Only fetch data if user is authenticated; otherwise wait for login
        if (localStorage.getItem('radar_access_token')) {
            fetchDDoSData(false);
        } else {
            // Hide loader since we're waiting for login
            const loader = document.getElementById('global-loader');
            if (loader) { loader.style.opacity = '0'; setTimeout(() => { loader.style.display = 'none'; }, 300); }
        }

        // ── WebSocket: real-time push (polling fallback at 15-min interval) ──
        let _wsConnected = false;
        let _wsSocket = null;
        let _wsSubscribedTheater = '';
        if (typeof io !== 'undefined') {
            try {
                _wsSocket = io({ transports: ['websocket', 'polling'] });
                _wsSocket.on('connect', () => {
                    _wsConnected = true;
                    const core = getCurrentConfig().core || 'TW';
                    _wsSubscribedTheater = core;
                    _wsSocket.emit('subscribe_theater', core);
                    console.log('[WS] Connected, subscribed to', core);
                });
                _wsSocket.on('disconnect', () => {
                    _wsConnected = false;
                    _wsSubscribedTheater = '';
                    console.log('[WS] Disconnected — polling fallback active');
                });
                _wsSocket.on('threat_update', (data) => {
                    latestData = data;
                    lastSyncedTimeText = `Data Synced: ${new Date().toLocaleTimeString()} (WS Live)`;
                    document.getElementById('update-time').innerText = lastSyncedTimeText;
                    renderTelemetry(latestData);
                });
                _wsSocket.on('ambush_alert', (data) => {
                    console.warn('[WS] AMBUSH ALERT:', data);
                    const wrap = document.getElementById('hud-ambush-wrap');
                    if (wrap) { wrap.style.display = 'flex'; wrap.classList.add('atm-critical'); }
                });
                _wsSocket.on('sequence_event', (data) => {
                    console.info('[WS] Sequence event:', data.status, data);
                    const badge = document.getElementById('chain-seq-badge');
                    if (badge) badge.textContent = data.status || '';
                });
                _wsSocket.on('notification_result', (data) => {
                    const ok = data.success;
                    const msg = `[${data.channel}] ${data.title}${ok ? '' : ' — FAILED: ' + data.detail}`;
                    console.info('[WS] Notification:', msg);
                    // Brief HUD flash for notification delivery
                    const el = document.getElementById('update-time');
                    if (el) {
                        const prev = el.textContent;
                        el.textContent = ok ? `✓ ${data.channel} notified` : `✗ ${data.channel} failed`;
                        el.style.color = ok ? '#00ff88' : '#ff4444';
                        setTimeout(() => { el.textContent = prev; el.style.color = ''; }, 4000);
                    }
                });
                _wsSocket.on('sensor_status', (data) => {
                    console.info('[WS] Sensor status:', data.sensor, data.status);
                    if (data.sensor && data.status) {
                        _sensorHealthCache[data.sensor] = data.status;
                        _updateSensorHealthHUD(_sensorHealthCache);
                    }
                });
            } catch (e) {
                console.warn('[WS] Socket.IO init failed, using polling fallback:', e);
            }
        }
        // Polling fallback: always active, but interval is longer when WS is connected
        setInterval(() => {
            if (!_wsConnected) fetchDDoSData(false);
        }, _wsConnected ? 1800000 : 900000);
    }
    
    // Boot sequence
    initApp();

    function openCountryDetail(code) {
        if (!latestData) return;
        const strat   = latestData.strategic_alert || {};
        const intel   = (strat.country_intel || {})[code] || {};
        const tgtData = (latestData.targets || []).find(t => t.code === code) || {};
        const coordName = (strat.core_theater === code ? _t('cip.role.core') : _t('cip.role.link'));

        document.getElementById('country-modal-title').textContent = _t('cip.modal_title', {name: tgtData.info || code, code: code});

        const spike    = tgtData.avg_spike   != null ? `${tgtData.avg_spike.toFixed(2)}x` : '—';
        const shareL3  = tgtData.global_share_l3 != null ? `${tgtData.global_share_l3.toFixed(2)}%` : '—';
        const shareL7  = tgtData.global_share_l7 != null ? `${tgtData.global_share_l7.toFixed(2)}%` : '—';
        const shift    = tgtData.is_vector_shift ? `<span class="cip-warn">${_t('cip.l7shift.active')}</span>` : `<span style="color:#555">${_t('cip.l7shift.none')}</span>`;
        
        const iodaSt   = intel.ioda_status || 'NORMAL';
        const isEffDeg = intel.is_bgp_degraded;
        let iodaCol = 'cip-ok';
        let iodaTxt = _t('cip.ioda.normal');
        if (iodaSt === "BGP_OUTAGE") {
            if (isEffDeg) {
                iodaCol = 'cip-alert';
                iodaTxt = _t('cip.ioda.outage');
            } else {
                iodaCol = 'cip-warn';
                iodaTxt = _t('cip.ioda.outage_wx');
            }
        }

        const sortedSrc = ((tgtData.sources || []).filter(s => s.weight > 0)
            .sort((a, b) => b.spike_factor - a.spike_factor)).slice(0, 5);
        const srcHtml = sortedSrc.length
            ? `<ul class="cip-sources-list">${sortedSrc.map(s =>
                `<li><span>${s.name} [${s.code}]${s.is_state_asn ? ` <b style="color:#ff4444">${_t('cip.state_asn_badge')}</b>` : ''}</span>
                <span style="color:#ffaa00">${_t('cip.spike_label', {n: s.spike_factor})}</span></li>`
              ).join('')}</ul>`
            : `<span style="color:#555;font-size:12px;">${_t('cip.no_sources')}</span>`;

        const wx     = intel.weather || {};
        const wxTxt  = wx.condition
            ? `${wx.condition} — ${wx.description || ''} (wind ${wx.wind_speed || 0}m/s)`
            : '—';
        const wxSev  = wx.severity || 'NORMAL';
        const wxCol  = wxSev === 'SEVERE' ? 'cip-alert' : wxSev === 'MODERATE' ? 'cip-warn' : 'cip-ok';

        const air    = intel.airspace || {};
        const airTxt = air.status
            ? `${air.airport || '?'}: ${air.count != null ? air.count : '?'} ac (base ${air.baseline_avg != null ? air.baseline_avg : '?'})`
            : '—';
        const airCol = (air.status === 'CLOSURE' || air.status === 'ANOMALY') ? 'cip-alert'
                     : air.status === 'WEATHER_NOISE' ? 'cip-warn' : 'cip-ok';
        const airLbl = air.status || '—';

        const bgpR   = intel.bgp_routing || {};
        const bgpTxt = bgpR.announced_prefixes != null
            ? `${bgpR.announced_prefixes} pfx / ${bgpR.seen_ases || '?'} ASes`
            : '—';
        const bgpCol = bgpR.is_anomaly ? 'cip-alert' : 'cip-ok';
        const bgpLbl = bgpR.is_anomaly ? `⚠ DROP ${bgpR.drop_pct}%` : (bgpR.status || '—');

        const gdelt  = intel.gdelt || {};
        const gdTone = gdelt.tone_current != null ? gdelt.tone_current.toFixed(1) : '—';
        const gdBase = gdelt.tone_baseline != null ? gdelt.tone_baseline.toFixed(1) : '—';
        const gdDelta= gdelt.delta != null ? `${gdelt.delta > 0 ? '+' : ''}${gdelt.delta.toFixed(1)}` : '—';
        const gdCol  = gdelt.status === 'ALERT' ? 'cip-alert' : gdelt.status === 'WEATHER_NOISE' ? 'cip-warn' : 'cip-ok';
        const gdLbl  = gdelt.status || '—';

        const ixpCnt   = intel.ixp_count || 0;
        const ixpNames = (intel.ixp_names || []).slice(0, 4).join(', ') || '—';

        document.getElementById('country-modal-body').innerHTML = `
        <div class="cip-header">
            <div class="cip-flag">🌐</div>
            <div>
                <div class="cip-title">${tgtData.info || code}</div>
                <div class="cip-code">${code} &nbsp;|&nbsp; ${coordName} &nbsp;|&nbsp; Global share L3: ${shareL3} / L7: ${shareL7}</div>
            </div>
        </div>

        <div class="cip-section">
            <div class="cip-section-title">${_t('cip.section.cyber')}</div>
            <div class="cip-grid">
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.avg_spike')}</div>
                    <div class="cip-card-value">${spike}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.l7_shift')}</div>
                    <div class="cip-card-value">${shift}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.ioda')}</div>
                    <div class="cip-card-value ${iodaCol}">${iodaTxt}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.bgp_routing')}</div>
                    <div class="cip-card-value ${bgpCol}">${bgpTxt}</div>
                    <div class="cip-card-sub">${bgpLbl}</div>
                </div>
            </div>
            <div class="cip-card" style="margin-top:6px;">
                <div class="cip-card-label">${_t('cip.label.top_sources')}</div>
                ${srcHtml}
            </div>
        </div>

        <div class="cip-section">
            <div class="cip-section-title">${_t('cip.section.physical')}</div>
            <div class="cip-grid">
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.weather')}</div>
                    <div class="cip-card-value ${wxCol}" style="font-size:12px;">${wxTxt}</div>
                    <div class="cip-card-sub">${wxSev}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.airspace', {airport: air.airport || '?'})}</div>
                    <div class="cip-card-value ${airCol}" style="font-size:12px;">${airTxt}</div>
                    <div class="cip-card-sub">${airLbl}${air.drop_pct != null ? ' — drop ' + air.drop_pct + '%' : ''}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.ixp_nodes')}</div>
                    <div class="cip-card-value">${ixpCnt}</div>
                    <div class="cip-card-sub" style="font-size:10px;">${ixpNames}</div>
                </div>
            </div>
        </div>

        <div class="cip-section">
            <div class="cip-section-title">${_t('cip.section.info')}</div>
            <div class="cip-grid">
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.current_tone')}</div>
                    <div class="cip-card-value ${gdCol}">${gdTone}</div>
                    <div class="cip-card-sub">Baseline (28d): ${gdBase} &nbsp; Δ ${gdDelta}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.alert_status')}</div>
                    <div class="cip-card-value ${gdCol}">${gdLbl}</div>
                    <div class="cip-card-sub">Threshold: ${-15.0}</div>
                </div>
            </div>
        </div>

        ${(function() {
            const p8 = strat.analytics || {};
            const p8Theater = strat.core_theater || '—';
            const velRaw = p8.velocity;
            const velColor = velRaw > 0.0005 ? '#ff4444' : velRaw > 0.0001 ? '#ffaa00' : '#00ff88';
            const velTxt  = velRaw !== undefined
                ? `<span style="color:${velColor}">${velRaw > 0 ? '+' : ''}${velRaw.toFixed(4)}</span>`
                : '—';
            const biRaw  = p8.blockade_index;
            const biTxt  = biRaw !== undefined ? biRaw.toFixed(2) : '—';
            const biCol  = biRaw >= 5 ? 'cip-alert' : biRaw >= 2 ? 'cip-warn' : 'cip-ok';
            const nzRaw  = p8.narrative ? (p8.narrative.z_score || 0) : null;
            const nzTxt  = nzRaw !== null ? nzRaw.toFixed(2) + ' σ' : '—';
            const nzCol  = nzRaw >= 3 ? 'cip-alert' : nzRaw >= 2 ? 'cip-warn' : 'cip-ok';
            const isrCnt = p8.isr ? (p8.isr.count || 0) : null;
            const isrTxt = isrCnt !== null ? isrCnt + ' ac' : '—';
            const isrCol = isrCnt >= 3 ? 'cip-warn' : 'cip-ok';
            const aisCnt = p8.ais ? (p8.ais.dark_gaps || 0) : null;
            const aisTxt = aisCnt !== null ? aisCnt + ' vessels' : '—';
            const aisCol = aisCnt >= 1 ? 'cip-warn' : 'cip-ok';
            const seqSt  = p8.sequence_status || '';
            const seqTxt = seqSt.includes('FULL_CHAIN') ? _t('cip.chain.full')
                         : seqSt.includes('PARTIAL')    ? _t('cip.chain.partial') : _t('cip.chain.none');
            const seqCol = seqSt.includes('FULL_CHAIN') ? 'cip-alert'
                         : seqSt.includes('PARTIAL')    ? 'cip-warn' : 'cip-ok';
            const ambushBadge = p8.is_ambush
                ? `<div style="margin-top:6px; padding:4px 8px; background:rgba(255,34,0,0.1); border-left:3px solid #ff2200; border-radius:0 4px 4px 0; font-size:10px; color:#ff4444; font-weight:bold;">${_t('cip.ambush.active')}</div>` : '';
            return `<div class="cip-section">
            <div class="cip-section-title">${_t('cip.section.predictive')} <span style="color:#555;font-size:9px;font-weight:normal;">${_t('cip.theater_label', {name: p8Theater})}</span></div>
            <div class="cip-grid">
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.esc_velocity')}</div>
                    <div class="cip-card-value">${velTxt}</div>
                    <div class="cip-card-sub">${_t('cip.sub.1st_deriv')}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.blockade_index')}</div>
                    <div class="cip-card-value ${biCol}">${biTxt}</div>
                    <div class="cip-card-sub">${_t('cip.sub.blockade')}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.narrative_z')}</div>
                    <div class="cip-card-value ${nzCol}">${nzTxt}</div>
                    <div class="cip-card-sub">${_t('cip.sub.30d_baseline')}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.isr_aircraft')}</div>
                    <div class="cip-card-value ${isrCol}">${isrTxt}</div>
                    <div class="cip-card-sub">${_t('cip.sub.high_alt_recon')}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.ais_dark_gaps')}</div>
                    <div class="cip-card-value ${aisCol}">${aisTxt}</div>
                    <div class="cip-card-sub">${_t('cip.sub.transponder')}</div>
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.seq_chain')}</div>
                    <div class="cip-card-value ${seqCol}">${seqTxt}</div>
                    <div class="cip-card-sub">${_t('cip.sub.24h')}</div>
                </div>
            </div>${ambushBadge}
        </div>`;
        })()}`;

        openModal('country-modal');
    }

    function openEvidencePanel(strat) {
        const convEl = document.getElementById('evidence-convergence');
        if (strat.domains) {
            convEl.innerHTML = Object.entries(strat.domains).map(([d, info]) =>
                `<div class="convergence-item"><span class="rat-domain-${d}">${d.toUpperCase()}</span>: <span class="conv-val">${info.score}pt</span> × ${info.weight} = <b style="color:#fff">${info.weighted}</b></div>`
            ).join('') +
            (strat.convergence_score !== undefined
                ? `<div class="convergence-item" style="margin-left:8px; border-left:2px solid #555; padding-left:8px;">Convergence Score: <span class="conv-val">${strat.convergence_score}</span></div>`
                : '');
        } else {
            convEl.innerHTML = '';
        }

        document.getElementById('evidence-system-note').textContent =
            strat.system_note || _t('evidence.no_system_note');

        const nf = strat.noise_filters_applied;
        document.getElementById('evidence-noise-filters').textContent =
            (nf && nf.length > 0) ? nf.join(', ') : 'None';

        const tbody = document.getElementById('evidence-tbody');
        if (strat.rationale_matrix && strat.rationale_matrix.length > 0) {
            tbody.innerHTML = strat.rationale_matrix.map(e => {
                const scoreHtml = e.score > 0
                    ? `<span class="rat-score-pos">+${e.score}</span>`
                    : `<span class="rat-score-zero">0</span>`;
                const reasonText = e.suppressed
                    ? `<span style="color:#ffaa00">${_t('evidence.suppressed', {reason: e.suppress_reason || ''})}</span>`
                    : (e.fired_reason || '<span style="color:#444">—</span>');
                
                // Inject MUTE / UNMUTE button
                const isMuted = mutedSensors.has(e.sensor);
                const muteBtnTxt = isMuted ? _t('evidence.btn.unmute') : _t('evidence.btn.mute');
                const muteBtnStyle = isMuted ? 'color:#ffaa00; border-color:#ffaa00;' : 'color:#555; border-color:#555;';
                const muteBtn = `<button onclick="toggleMute('${e.sensor}')" style="background:transparent; border:1px solid; border-radius:3px; font-size:9px; cursor:pointer; margin-left:8px; transition:0.2s; ${muteBtnStyle}">${muteBtnTxt}</button>`;

                return `<tr>
                    <td style="font-family:monospace; font-size:11px; color:#ccc;">${e.sensor} ${muteBtn}</td>
                    <td><span class="rat-domain-${e.domain}">${e.domain}</span></td>
                    <td><span class="rat-status-${e.status}">${e.status}</span></td>
                    <td style="color:#fff; font-size:11px;">${e.value}</td>
                    <td style="text-align:center;">${scoreHtml}</td>
                    <td style="font-size:11px; color:#aaa;">${reasonText}</td>
                </tr>`;
            }).join('');
        } else {
            tbody.innerHTML = `<tr><td colspan="6" style="color:#555; text-align:center;">${_t('evidence.no_data')}</td></tr>`;
        }

        openModal('evidence-modal');
    }

    async function loadSensorConfig() {
        const container = document.getElementById('sensor-list-container');
        try {
            const res  = await fetch(`/api/sensor_config`);
            const data = await res.json();
            const sensors = data.sensors || [];

            if (sensors.length === 0) {
                container.innerHTML = `<div style="color:#555;">${_t('sensor.no_sensors')}</div>`;
                return;
            }

            container.innerHTML = sensors.map(s => {
                const phaseNote = '';
                const healthCls = `sensor-health-${s.health}`;
                const toggleCls = s.enabled ? 'active' : '';
                const toggleTxt = s.enabled ? _t('sensor.toggle.enabled') : _t('sensor.toggle.disabled');
                const pollMin   = Math.round(s.poll_interval_sec / 60);
                return `<div class="sensor-row">
                    <span class="sensor-name">${s.name}</span>
                    <span class="sensor-domain-tag sensor-domain-${s.domain}">${s.domain}</span>
                    <span class="sensor-health ${healthCls}">${s.health}</span>
                    <span style="font-size:10px; color:#555;">${pollMin}min</span>
                    ${phaseNote}
                    <button class="sensor-toggle ${toggleCls}"
                        onclick="toggleSensor('${s.name}', ${!s.enabled}, this)">
                        ${toggleTxt}
                    </button>
                </div>`;
            }).join('');
        } catch (e) {
            container.innerHTML = `<div style="color:#ff2a2a;">${_t('sensor.load_error', {msg: e.message})}</div>`;
        }
    }

    async function toggleSensor(name, enable, btn) {
        try {
            const res = await fetch(`/api/sensor_config`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, enabled: enable }),
            });
            const data = await res.json();
            if (data.ok) {
                btn.textContent = data.enabled ? _t('sensor.toggle.enabled') : _t('sensor.toggle.disabled');
                btn.className = 'sensor-toggle' + (data.enabled ? ' active' : '');
            }
        } catch (e) {
            console.error('toggleSensor failed:', e);
        }
    }

    async function openSitrep() {
        openModal('sitrep-modal');
        document.getElementById('sitrep-text').textContent = _t('sitrep.loading');
        document.getElementById('sitrep-summary').innerHTML = '';
        try {
            const [sitrepRes, timelineRes] = await Promise.all([
                fetch(`/api/sitrep`),
                fetch(`/api/alert_timeline?limit=288`),
            ]);
            const sitrep   = await sitrepRes.json();
            const timeline = await timelineRes.json();

            const s = sitrep.summary || {};
            const threatColor = d => ['','#ff0000','#ff2a2a','#ffaa00','#ffff00','#66ff66'][d] || '#888';
            const trendIcon   = t => t === 'ESCALATING' ? '▲' : t === 'DE-ESCALATING' ? '▼' : '—';
            const cards = [
                { label: _t('sitrep.card.threat_now'), value: `Lv ${s.threat_current || '—'}`, sub: `Trend: ${trendIcon(s.threat_trend)} ${s.threat_trend || '—'}`, color: threatColor(s.threat_current) },
                { label: _t('sitrep.card.threat_1h'), value: `Lv ${s.threat_min_1h || '—'}–${s.threat_max_1h || '—'}`, sub: `Avg: ${s.threat_avg_1h || '—'}`, color: '#aaa' },
                { label: _t('sitrep.card.convergence'), value: (s.convergence || 'NONE').replace(/_/g,' '), sub: `Domains: ${(s.active_domains || []).join(', ') || 'None'}`, color: s.convergence === 'FULL_CONVERGENCE' ? '#ff2a2a' : s.convergence === 'DUAL_DOMAIN' ? '#ffaa00' : '#888' },
                { label: _t('sitrep.card.history'), value: `${s.cycle_count || 0} cycles`, sub: `${Math.round((s.span_minutes || 0) / 60 * 10) / 10}h window`, color: '#555' },
            ];
            document.getElementById('sitrep-summary').innerHTML = cards.map(c =>
                `<div class="sitrep-card">
                    <div class="sitrep-card-label">${c.label}</div>
                    <div class="sitrep-card-value" style="color:${c.color};">${c.value}</div>
                    <div class="sitrep-card-sub">${c.sub}</div>
                </div>`
            ).join('');

            document.getElementById('sitrep-text').textContent = sitrep.text || _t('sitrep.no_data');

            const entries = timeline.timeline || [];
            const canvas  = document.getElementById('sitrep-timeline-canvas');
            drawThreatTimeline(canvas, entries);

        } catch(e) {
            document.getElementById('sitrep-text').textContent = `Error: ${e.message}`;
        }
    }

    function drawThreatTimeline(canvas, entries) {
        if (!canvas || entries.length === 0) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.width, H = canvas.height;
        ctx.clearRect(0, 0, W, H);

        ctx.strokeStyle = '#1a1a1a';
        ctx.lineWidth   = 1;
        for (let d = 1; d <= 5; d++) {
            const y = Math.round(((d - 1) / 4) * (H - 10)) + 5;
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
        }

        ctx.font = '9px monospace';
        ctx.fillStyle = '#333';
        for (let d = 1; d <= 5; d++) {
            const y = Math.round(((d - 1) / 4) * (H - 10)) + 5;
            ctx.fillText(`L${d}`, 2, y - 1);
        }

        const threatColors = { 1: '#ff0000', 2: '#ff2a2a', 3: '#ffaa00', 4: '#ffff00', 5: '#66ff66' };
        const n = entries.length;
        const barW = Math.max(1, Math.floor(W / n));

        entries.forEach((e, i) => {
            const d   = e.threat_level || 5;
            const x   = Math.floor(i * (W / n));
            const y   = Math.round(((d - 1) / 4) * (H - 10)) + 5;
            const col = threatColors[d] || '#444';
            ctx.fillStyle = col + '99';
            ctx.fillRect(x, 5, barW - 1, H - 10);
            ctx.fillStyle = col;
            ctx.beginPath(); ctx.arc(x + barW / 2, y, 2, 0, Math.PI * 2); ctx.fill();
        });

        ctx.strokeStyle = '#00ffff88';
        ctx.lineWidth   = 1.5;
        ctx.beginPath();
        entries.forEach((e, i) => {
            const d = e.threat_level || 5;
            const x = Math.floor(i * (W / n)) + barW / 2;
            const y = Math.round(((d - 1) / 4) * (H - 10)) + 5;
            if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        });
        ctx.stroke();
    }

    function updateThreatSparkline(threatHistory) {
        const canvas = document.getElementById('hud-threat-spark');
        if (!canvas || !threatHistory || threatHistory.length === 0) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.width, H = canvas.height;
        ctx.clearRect(0, 0, W, H);
        const n    = threatHistory.length;
        const barW = Math.max(1, Math.floor(W / n));
        const threatColors = { 1: '#ff0000', 2: '#ff2a2a', 3: '#ffaa00', 4: '#ffff00', 5: '#66ff66' };

        threatHistory.forEach(([, d], i) => {
            const x   = Math.floor(i * (W / n));
            const y   = Math.round(((d - 1) / 4) * (H - 2)) + 1;
            const col = threatColors[d] || '#444';
            ctx.fillStyle = col;
            ctx.fillRect(x, y, barW - 1, H - y);
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    //  INTUITION UI — Recognition-Primed Decision (RPD) Components
    //  Eight UI elements that appeal to the analyst's heuristics and intuition
    // ══════════════════════════════════════════════════════════════════════

    let _pulseHistory   = []; // [{ts, threat_level}] — EKG pulse history
    let _lastEventTs    = Date.now(); // timestamp of the last significant event
    let _clockInterval  = null;
    let _histEvents     = []; // geo_data HISTORICAL_EVENTS cache

    // ── A. Ambient Atmosphere ──────────────────────────────────────────
    // Switch body class based on threat level → CSS keyframes subtly tint background
    function applyAmbientAtmosphere(threatLevel) {
        const body = document.body;
        body.classList.remove('atm-critical', 'atm-severe', 'atm-high');
        if      (threatLevel === 1) body.classList.add('atm-critical');
        else if (threatLevel === 2) body.classList.add('atm-severe');
        else if (threatLevel === 3) body.classList.add('atm-high');
    }

    // ── B. Pulse Display ──────────────────────────────────────────────
    // Scrolling EKG waveform — visualize threat score time series as a heartbeat graph
    function updatePulseDisplay(threatHistory) {
        if (!threatHistory || !threatHistory.length) return;
        _pulseHistory = threatHistory.slice(-60);
        drawPulseCanvas();
    }

    function drawPulseCanvas() {
        const canvas = document.getElementById('pulse-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.width, H = canvas.height;
        ctx.clearRect(0, 0, W, H);
        if (!_pulseHistory.length) return;

        // Faint grid lines
        ctx.strokeStyle = '#1c1c1c';
        ctx.lineWidth = 0.5;
        for (let i = 0; i <= 4; i++) {
            const y = (i / 4) * (H - 6) + 3;
            ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
        }

        const n   = _pulseHistory.length;
        const col = { 1:'#ff0000', 2:'#ff2a2a', 3:'#ffaa00', 4:'#ffff00', 5:'#66ff66' };
        const lastDef = _pulseHistory[_pulseHistory.length - 1][1];
        const lineCol = col[lastDef] || '#00ffff';

        // threat_level: 1(critical, top)→5(normal, bottom). y = top→bottom
        const pts = _pulseHistory.map(([, d], i) => {
            const x = (i / Math.max(n - 1, 1)) * (W - 4) + 2;
            const y = ((d - 1) / 4) * (H - 8) + 4;
            return [x, y];
        });

        // Fill area
        ctx.beginPath();
        ctx.moveTo(pts[0][0], H);
        pts.forEach(([x, y]) => ctx.lineTo(x, y));
        ctx.lineTo(pts[pts.length - 1][0], H);
        ctx.closePath();
        ctx.fillStyle = lineCol + '14';
        ctx.fill();

        // Line
        ctx.beginPath();
        pts.forEach(([x, y], i) => { if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); });
        ctx.strokeStyle = lineCol + 'cc';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Latest dot
        const [lx, ly] = pts[pts.length - 1];
        ctx.beginPath();
        ctx.arc(lx, ly, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = lineCol;
        ctx.fill();

        // Threat rate (transitions/hour) + current Threat Lv indicator
        const bpmEl = document.getElementById('pulse-bpm');
        const tlEl  = document.getElementById('pulse-threat-lv');
        if (bpmEl) {
            const changes = _pulseHistory.slice(1).filter(([,d], i) => d !== _pulseHistory[i][1]).length;
            const spanH   = (_pulseHistory.length * 15) / 3600;
            const rate    = spanH > 0 ? Math.round(changes / spanH) : 0;
            bpmEl.textContent = rate + ' /h';
        }
        if (tlEl) {
            const THREAT_COL = { 1:'#ff0000', 2:'#ff4444', 3:'#ffaa00', 4:'#ffff00', 5:'#66ff66' };
            tlEl.textContent = lastDef;
            tlEl.style.color = THREAT_COL[lastDef] || '#ccc';
        }
    }

    // ── C. Operational Clock ──────────────────────────────────────────
    // Real-time Zulu time + elapsed time since last significant event
    const togglePulseDisplay = _createPanelToggle('pulse-panel');

    const toggleOpClock = _createPanelToggle('op-clock-panel', {
        onShow: () => { tickClock(); if (!_clockInterval) _clockInterval = setInterval(tickClock, 1000); },
        onHide: () => { if (_clockInterval) { clearInterval(_clockInterval); _clockInterval = null; } },
    });

    function tickClock() {
        const zEl = document.getElementById('clock-zulu');
        const lEl = document.getElementById('clock-local');
        const dEl = document.getElementById('clock-date');
        const sEl = document.getElementById('clock-since');
        if (!zEl) return;

        const now  = new Date();
        const pad  = n => String(n).padStart(2, '0');
        const zulu = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}Z`;
        zEl.textContent = zulu;
        if (lEl) lEl.textContent = _t('clock.local_prefix') + now.toLocaleTimeString();
        if (dEl) {
            const months = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
            dEl.textContent = `${now.getUTCDate()} ${months[now.getUTCMonth()]} ${now.getUTCFullYear()} UTC`;
        }
        if (sEl) {
            const ms   = Date.now() - _lastEventTs;
            const mins = Math.floor(ms / 60000);
            const secs = Math.floor((ms % 60000) / 1000);
            sEl.textContent = _t('clock.last_event', {m: mins, s: secs});
        }
    }

    // ── D. Operational Weather Brief ──────────────────────────────────
    // Intuitive weather-metaphor representation of the threat environment — fetched from /api/weather_brief
    const toggleWeatherBrief = _createPanelToggle('weather-brief-panel', { onShow: renderWeatherBrief });

    async function renderWeatherBrief() {
        const panel = document.getElementById('weather-brief-panel');
        if (!panel || panel.style.display === 'none') return;
        const bodyEl = panel.querySelector('.wb-body');
        const sumEl  = panel.querySelector('.wb-summary');
        if (!bodyEl) return;

        const ICONS = {
            clear:'☀️', hazy:'🌤', overcast:'☁️', squall:'🌩', storm:'⛈', fog:'🌫',
            rising_pressure:'📈', falling_pressure:'📉', stable_pressure:'🟰',
            calm:'🌊', choppy:'🌊', rough:'🌊', turbulent:'⚡',
            clear_sky:'🔭', limited_vis:'👁', surge:'🛩', blackout:'🚫',
            dark:'🌑', default:'●'
        };

        try {
            const res = await fetch(`/api/weather_brief?lang=${_currentLang}`);
            const wb  = await res.json();
            const brief = wb.brief || {};
            const DOMAIN_ICON = { cyber:'⛈', maritime:'🌫', info:'📡', air:'🔭', infra:'🏗' };
            const DOMAIN_CLS  = {
                cyber: 'wb-domain-cyber', info: 'wb-domain-info',
                maritime: 'wb-domain-physical', infra: 'wb-domain-physical', air: ''
            };
            const STATE_COLOR = {
                // English states
                'CLEAR':'#00cc66','CLEAR PASSAGE':'#00cc66','CLEAR SKIES':'#00cc66',
                'STEADY STATE':'#00cc66','NOMINAL':'#00cc66',
                'ELEVATED SWELL':'#cccc00','OBSERVED — ROUTINE ISR PATTERN':'#cccc00',
                'ELEVATED — POLITICAL NOISE LEVEL':'#cccc00','RESTRICTED WATERS — OBSTACLE':'#cccc00',
                'ACTIVE STORM FRONT':'#cc8800','REDUCED VISIBILITY — PATCHY FOG':'#cc8800',
                'ELEVATED PRESSURE — BUILDING STORM':'#cc8800','SEVERE — SUSTAINED PRESSURE':'#cc8800',
                'MAJOR STORM':'#cc4400','ZERO VISIBILITY — DENSE FOG':'#cc4400',
                'ACTIVE — FULL ISR DEPLOYMENT':'#cc4400',
                'RAPID INTENSIFICATION':'#ff2200','INFORMATION STORM — HURRICANE FORCE':'#ff2200',
                'CATASTROPHIC — INFRASTRUCTURE COLLAPSE':'#ff2200',
                // Japanese states
                '平穏 — 異常なし':'#00cc66','通過良好 — 異常なし':'#00cc66','晴天 — ISR集中なし':'#00cc66',
                '定常状態 — 通常範囲内':'#00cc66','正常 — 安定':'#00cc66',
                'うねり上昇中':'#cccc00','観測 — 通常ISRパターン':'#cccc00',
                '上昇 — 政治的ノイズレベル':'#cccc00','制限水域 — 障害物検出':'#cccc00',
                '嵐の前線活発化':'#cc8800','視界低下 — 断続的霧':'#cc8800',
                '上昇気圧 — 嵐発達中':'#cc8800','深刻 — 持続的圧力':'#cc8800',
                '大規模サイバー嵐':'#cc4400','視界ゼロ — 濃霧':'#cc4400',
                '活発 — ISR全面展開':'#cc4400',
                '急速強化中 — 指数的上昇':'#ff2200','情報嵐 — ハリケーン級':'#ff2200',
                '壊滅的 — インフラ崩壊':'#ff2200',
            };
            bodyEl.innerHTML = Object.entries(brief).map(([key, v]) => {
                const icon  = DOMAIN_ICON[key] || '●';
                const cls   = DOMAIN_CLS[key] || '';
                const color = STATE_COLOR[v.state] || '#aaa';
                return `<div class="wb-row">
                    <div class="wb-icon">${icon}</div>
                    <div class="wb-info">
                        <div class="wb-domain-tag ${cls}">${key.toUpperCase()}</div>
                        <div class="wb-condition" style="color:${color};">${v.state}</div>
                        <div class="wb-desc">${v.detail}</div>
                    </div>
                </div>`;
            }).join('');
            if (sumEl) sumEl.textContent = wb.summary || '';
        } catch(e) {
            bodyEl.innerHTML = '<div style="color:#666;font-size:10px;text-align:center;">API unavailable</div>';
        }
    }

    // ── E. SALUTE Board ───────────────────────────────────────────────
    // Size/Activity/Location/Unit/Time/Equipment — military contact report format
    const toggleSaluteBoard = _createPanelToggle('salute-panel', { onShow: renderSaluteBoard });

    async function renderSaluteBoard() {
        const panel = document.getElementById('salute-panel');
        if (!panel || panel.style.display === 'none') return;
        const bodyEl = panel.querySelector('.salute-body');
        const tsEl   = document.getElementById('salute-ts');
        if (!bodyEl) return;

        if (tsEl) {
            const now = new Date();
            const pad = n => String(n).padStart(2, '0');
            tsEl.textContent = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}Z`;
        }

        try {
            const res = await fetch(`/api/salute_report?lang=${_currentLang}`);
            const sal = (await res.json()).report || {};
            const fields = [
                { k:'S', l:'SIZE',     v: sal.size      || '—' },
                { k:'A', l:'ACTIVITY', v: sal.activity  || '—' },
                { k:'L', l:'LOCATION', v: sal.location  || '—' },
                { k:'U', l:'UNIT',     v: sal.unit       || '—' },
                { k:'T', l:'TIME',     v: sal.time       || '—' },
                { k:'E', l:'EQUIP',    v: sal.equipment  || '—' },
            ];
            bodyEl.innerHTML = fields.map(f =>
                `<div class="s-row">
                    <span class="s-key">${f.k}</span>
                    <span class="s-label">${f.l}</span>
                    <span class="s-val">${f.v}</span>
                </div>`
            ).join('') + (sal.assessment
                ? `<div class="s-assess">${sal.assessment}</div>` : '');
        } catch(e) {
            bodyEl.innerHTML = '<div style="color:#666;font-size:10px;text-align:center;">API unavailable</div>';
        }
    }

    // ── F. Historical Pattern Analog ──────────────────────────────────
    // Match current pattern against past confirmed cases using Pearson correlation
    const toggleHistAnalog = _createPanelToggle('hist-analog-panel', { onShow: renderHistoricalAnalog });

    async function renderHistoricalAnalog() {
        const panel = document.getElementById('hist-analog-panel');
        if (!panel || panel.style.display === 'none') return;
        const bodyEl = panel.querySelector('.ha-body');
        if (!bodyEl) return;

        // Cache historical patterns (API fetch on first call only)
        if (!_histEvents.length) {
            try {
                const res = await fetch(`/api/historical_events`);
                const d   = await res.json();
                _histEvents = (d.events || []).filter(e => e.id !== 'normal_baseline');
            } catch(e) {}
        }

        if (!_histEvents.length || !latestData || !(latestData.threat_history || []).length) {
            bodyEl.innerHTML = `<div style="color:#666;font-size:10px;text-align:center;">${_t('ha.accumulating')}</div>`;
            return;
        }

        // Current pattern: last 20 cycles → normalized to 0(normal)–1(crisis)
        const hist = latestData.threat_history || [];
        const cur20 = hist.slice(-20).map(([, d]) => (5 - d) / 4);
        while (cur20.length < 20) cur20.unshift(0);

        // Match using Pearson correlation coefficient
        function pearson(a, b) {
            const n = a.length;
            const ma = a.reduce((s, v) => s + v, 0) / n;
            const mb = b.reduce((s, v) => s + v, 0) / n;
            let num = 0, da = 0, db = 0;
            for (let i = 0; i < n; i++) {
                const ai = a[i] - ma, bi = b[i] - mb;
                num += ai * bi; da += ai * ai; db += bi * bi;
            }
            return da * db > 0 ? num / Math.sqrt(da * db) : 0;
        }

        const matches = _histEvents.map(ev => ({
            ...ev,
            sim: Math.max(0, pearson(cur20, (ev.pattern || new Array(20).fill(0))))
        })).sort((a, b) => b.sim - a.sim).slice(0, 3);

        bodyEl.innerHTML = matches.map(ev => {
            const pct = Math.round(ev.sim * 100);
            const col = ev.color || '#666';
            const cid = `ha-cv-${ev.id}`;
            return `<div class="ha-event-card" style="border-left-color:${col}50;">
                <div class="ha-event-name" style="color:${col};">${ev.label || ev.id}</div>
                <div class="ha-event-sim">
                    <span style="color:#888; font-size:9px;">${ev.short || ''}</span>
                    <span style="color:${pct > 45 ? col : '#778'}; font-weight:${pct > 55 ? 'bold' : 'normal'};">${pct}%</span>
                </div>
                <div class="ha-bar"><div class="ha-bar-fill" style="width:${pct}%; background:${col};"></div></div>
                <canvas id="${cid}" class="ha-canvas" width="241" height="32"></canvas>
            </div>`;
        }).join('') + `<div class="ha-note">${_t('ha.note')}</div>`;

        // Draw mini-graph for each card (current=cyan, historical=dim color)
        requestAnimationFrame(() => {
            matches.forEach(ev => {
                const cvs = document.getElementById(`ha-cv-${ev.id}`);
                if (!cvs) return;
                const ctx = cvs.getContext('2d');
                const W = cvs.width, H = cvs.height;
                ctx.clearRect(0, 0, W, H);
                const col = ev.color || '#666';
                const pat = ev.pattern || new Array(20).fill(0);
                const n   = 20;

                // Historical pattern (faint)
                ctx.beginPath();
                pat.forEach((v, i) => {
                    const x = (i / (n-1)) * (W-2) + 1;
                    const y = H - v * (H-4) - 2;
                    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
                });
                ctx.strokeStyle = col + '55';
                ctx.lineWidth = 1;
                ctx.stroke();

                // Current pattern (sharp)
                ctx.beginPath();
                cur20.forEach((v, i) => {
                    const x = (i / (n-1)) * (W-2) + 1;
                    const y = H - v * (H-4) - 2;
                    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
                });
                ctx.strokeStyle = '#00ffff77';
                ctx.lineWidth = 1;
                ctx.stroke();
            });
        });
    }

    // ── G. Radio Silence Indicator ────────────────────────────────────
    // All sensors abnormally quiet: possible sensor suppression or pre-operation comms blackout
    function updateRadioSilence(p8, strat) {
        const wrap = document.getElementById('hud-radio-silence');
        const dot  = wrap ? wrap.querySelector('.rs-dot') : null;
        const txt  = document.getElementById('hud-rs-text');
        if (!wrap || !dot || !txt) return;

        const velocity = p8 ? Math.abs(p8.velocity || 0) : 0;
        const score    = strat ? ((strat.threat_breakdown || {}).total_score || 0) : 0;
        // "Quiet anomaly": score at or above significance level but velocity is zero
        const isQuiet  = velocity < 0.00005 && score >= 3;

        wrap.classList.add('active');
        if (isQuiet) {
            dot.className = 'rs-dot rs-dot-quiet';
            txt.textContent  = _t('rs.quiet_text');
            txt.style.color  = '#ff8800';
            wrap.setAttribute('data-tooltip', _t('rs.tooltip.quiet'));
        } else {
            dot.className = 'rs-dot rs-dot-live';
            txt.textContent  = _t('rs.live_text');
            txt.style.color  = '#00ff88';
            wrap.setAttribute('data-tooltip', _t('rs.tooltip.live'));
        }
    }

    // ── H. Threat Terrain Overlay ─────────────────────────────────────
    // Visualize per-country threat intensity with Leaflet Circles (choropleth-style)
    function updateThreatTerrain(data) {
        threatTerrainLayer.clearLayers();
        if (!data.targets) return;
        data.targets.forEach(t => {
            const spike = t.avg_spike || 1;
            const isOut = t.is_bgp_effective;
            if (spike < 1.5 && !isOut) return; // skip normal
            const intensity = Math.min(1, (spike - 1) / 6);
            const radius    = 120000 + intensity * 500000; // metres
            const col = isOut ? '#ff0000' : spike > 4 ? '#ff6600' : '#ffaa00';
            L.circle([t.lat, shiftLng(t.lng)], {
                radius,
                color: 'transparent',
                fillColor: col,
                fillOpacity: 0.04 + intensity * 0.10,
                interactive: false,
            }).addTo(threatTerrainLayer);
        });
    }

    // ── Significant event detected → reset operational tempo timer ────
    function recordSignificantEvent(threatLevel) {
        if (threatLevel <= 3) _lastEventTs = Date.now();
    }

    async function loadFetchLog() {
        const container = document.getElementById('fetchlog-container');
        const tsEl      = document.getElementById('fetchlog-ts');
        try {
            const res  = await fetch(`/api/data_status`);
            const data = await res.json();
            tsEl.textContent = _t('fetchlog.last_refreshed', {time: new Date(data.ts).toLocaleTimeString()});

            const domainColor = { cyber: '#00ffff', physical: '#ffaa00', info: '#cc66ff' };

            container.innerHTML = data.sensors.map(s => {
                const last = s.last_fetch;
                const healthCls = { OK:'#66ff66', ERROR:'#ff4444', STALE:'#ff8800',
                                    INITIALIZING:'#888', DISABLED:'#444' }[s.health] || '#888';
                const successIcon = last
                    ? (last.success ? '<span style="color:#66ff66;">✔</span>' : '<span style="color:#ff4444;">✗</span>')
                    : '<span style="color:#555;">—</span>';
                const lastTs = last ? new Date(last.ts).toLocaleTimeString() : '—';
                const duration = last && last.duration_ms != null ? `${last.duration_ms}ms` : '—';
                const httpSt   = last && last.http_status   ? last.http_status : '—';
                const cacheAge = s.cache_age_sec != null ? `${s.cache_age_sec}s` : '—';
                const dCol = domainColor[s.domain] || '#888';
                const errMsg   = last && last.error ? `<div style="color:#ff4444;font-size:10px;margin-bottom:4px;">${last.error}</div>` : '';

                const histBar = (s.fetch_log || []).map(e =>
                    `<span style="display:inline-block;width:8px;height:16px;margin:0 1px;vertical-align:middle;border-radius:2px;background:${e.success ? '#66ff66' : '#ff4444'}44;border:1px solid ${e.success ? '#66ff66' : '#ff4444'};" data-tooltip="${new Date(e.ts).toLocaleTimeString()}\nStatus: ${e.success ? 'OK' : 'ERROR'}\n${e.error || ''}"></span>`
                ).join('');

                return `
                <div style="margin-bottom:10px;padding:10px;background:#111;border:1px solid #222;border-left:3px solid ${healthCls};border-radius:4px;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                        <span style="font-size:13px;font-weight:bold;color:#eee;">${s.sensor}</span>
                        <span style="font-size:10px;padding:2px 6px;border-radius:10px;background:${dCol}22;color:${dCol};border:1px solid ${dCol}44; text-transform:uppercase;">${s.domain}</span>
                        <span style="font-size:11px;padding:1px 6px;border-radius:3px;color:${healthCls};border:1px solid ${healthCls}55;">${s.health}</span>
                        <span style="margin-left:auto;font-size:11px;color:#555;">poll: ${Math.round(s.poll_interval_sec/60)}min</span>
                    </div>
                    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:6px;font-size:11px;color:#888;margin-bottom:6px;">
                        <div>${_t('fetchlog.grid.last_fetch')}<br><b style="color:#ccc;">${successIcon} ${lastTs}</b></div>
                        <div>${_t('fetchlog.grid.duration')}<br><b style="color:#ccc;">${duration}</b></div>
                        <div>${_t('fetchlog.grid.http_status')}<br><b style="color:#ccc;">${httpSt}</b></div>
                        <div>${_t('fetchlog.grid.cache_age')}<br><b style="color:#ccc;">${cacheAge}</b></div>
                    </div>
                    ${errMsg}
                    <div style="font-size:10px;color:#555;margin-top:4px;">
                        ${_t('fetchlog.history_label')} ${histBar || `<span style="color:#333;">${_t('fetchlog.no_data')}</span>`}
                    </div>
                </div>`;
            }).join('');
        } catch (e) {
            container.innerHTML = `<div style="color:#ff2a2a;">${_t('fetchlog.load_error', {msg: e.message})}</div>`;
        }
    }

    // ── Admin headers helper ─────────────────────────────────────────────────────
    function _adminHeaders(extra = {}) {
        return { ...extra };
    }

    // ── System Config (env_config) ────────────────────────────────────────────
    async function loadEnvConfig() {
        try {
            const res = await fetch(`/api/env_config`, { headers: _adminHeaders() });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const cfg = await res.json();
            // Populate plain inputs (skip picker-managed hidden inputs)
            const pickerKeys = new Set(['DEFAULT_CORE','DEFAULT_ADVERSARIES','DEFAULT_CORRELATES','DEFAULT_PINS']);
            document.querySelectorAll('[id^="ec-"]').forEach(el => {
                const key = el.id.replace('ec-', '');
                if (!pickerKeys.has(key) && cfg[key] !== undefined) {
                    el.value = cfg[key];
                }
            });
            // Populate scope pickers
            await populateEnvScopePickers(cfg);
            const st = document.getElementById('env-status');
            if (st) { st.textContent = ''; }
        } catch(e) {
            const st = document.getElementById('env-status');
            if (st) { st.textContent = 'Failed to load: ' + e.message; st.className = 'env-status err'; }
        }
    }

    // Scope picker state
    const _envScope = { adversaries: new Set(), correlates: new Set(), pins: new Set() };

    async function populateEnvScopePickers(cfg) {
        // Init state from config values
        _envScope.adversaries = new Set((cfg.DEFAULT_ADVERSARIES || '').split(',').map(s => s.trim()).filter(Boolean));
        _envScope.correlates  = new Set((cfg.DEFAULT_CORRELATES  || '').split(',').map(s => s.trim()).filter(Boolean));
        _envScope.pins        = new Set((cfg.DEFAULT_PINS        || '').split(',').map(s => s.trim()).filter(Boolean));

        let appCfg;
        try {
            const r = await fetch(`/api/app_config`);
            if (!r.ok) return;
            appCfg = await r.json();
        } catch(e) { return; }

        const countries   = appCfg.available_countries || [];
        const adversaries = appCfg.adversary_options   || [];

        // Core Theater: <select>
        const coreSelect = document.getElementById('ec-DEFAULT_CORE');
        if (coreSelect) {
            coreSelect.innerHTML = '<option value="">— none —</option>';
            countries.forEach(c => {
                const opt = new Option(`${c.code}  –  ${c.name}`, c.code);
                coreSelect.appendChild(opt);
            });
            coreSelect.value = cfg.DEFAULT_CORE || '';
        }

        // Adversaries: toggle cards
        const advPicker = document.getElementById('ec-DEFAULT_ADVERSARIES-picker');
        if (advPicker) {
            advPicker.innerHTML = '';
            adversaries.forEach(a => {
                const code = typeof a === 'object' ? a.code : a;
                const name = typeof a === 'object' ? (a.name || a.code) : a;
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'adv-bloc-btn' + (_envScope.adversaries.has(code) ? ' active' : '');
                btn.innerHTML = `<span class="adv-bloc-code">${code}</span><span class="adv-bloc-name">${name}</span>`;
                btn.onclick = () => {
                    if (_envScope.adversaries.has(code)) {
                        _envScope.adversaries.delete(code);
                        btn.classList.remove('active');
                    } else {
                        _envScope.adversaries.add(code);
                        btn.classList.add('active');
                    }
                };
                advPicker.appendChild(btn);
            });
        }

        // Correlates + Pins: tag pickers
        _buildTagPicker('ec-correlates-list', 'ec-correlates-tags', 'ec-search-correlates', _envScope.correlates, countries);
        _buildTagPicker('ec-pins-list',       'ec-pins-tags',       'ec-search-pins',       _envScope.pins,       countries);
    }

    function _buildTagPicker(listId, tagsId, searchId, selectedSet, countries) {
        const listEl   = document.getElementById(listId);
        const tagsEl   = document.getElementById(tagsId);
        const searchEl = document.getElementById(searchId);
        if (!listEl || !tagsEl) return;

        function renderTags() {
            tagsEl.innerHTML = '';
            const codes = [...selectedSet].sort();
            if (codes.length === 0) {
                tagsEl.innerHTML = `<span class="scope-tags-empty">${_t('sysconfig.scope.none_selected')}</span>`;
                return;
            }
            codes.forEach(code => {
                const tag = document.createElement('span');
                tag.className = 'scope-tag';
                const rm = document.createElement('button');
                rm.type = 'button';
                rm.className = 'scope-tag-remove';
                rm.textContent = '×';
                rm.title = 'Remove';
                rm.onclick = () => {
                    selectedSet.delete(code);
                    renderTags();
                    renderList(searchEl ? searchEl.value : '');
                };
                tag.appendChild(document.createTextNode(code + ' '));
                tag.appendChild(rm);
                tagsEl.appendChild(tag);
            });
        }

        function renderList(filter) {
            listEl.innerHTML = '';
            const f = (filter || '').toLowerCase().trim();
            countries
                .filter(c => !f || c.code.toLowerCase().includes(f) || c.name.toLowerCase().includes(f))
                .forEach(c => {
                    const item = document.createElement('div');
                    const sel  = selectedSet.has(c.code);
                    item.className = 'scope-list-item' + (sel ? ' selected' : '');
                    item.innerHTML = `<span class="scope-item-code">${c.code}</span><span class="scope-item-name">${c.name}</span>${sel ? '<span class="scope-item-check">✓</span>' : ''}`;
                    item.onclick = () => {
                        if (selectedSet.has(c.code)) selectedSet.delete(c.code);
                        else selectedSet.add(c.code);
                        renderTags();
                        renderList(searchEl ? searchEl.value : '');
                    };
                    listEl.appendChild(item);
                });
        }

        renderTags();
        renderList('');
        if (searchEl) searchEl.oninput = () => renderList(searchEl.value);
    }

    function syncEnvScopePickersToInputs() {
        const a = document.getElementById('ec-DEFAULT_ADVERSARIES');
        if (a) a.value = [..._envScope.adversaries].join(',');
        const c = document.getElementById('ec-DEFAULT_CORRELATES');
        if (c) c.value = [..._envScope.correlates].join(',');
        const p = document.getElementById('ec-DEFAULT_PINS');
        if (p) p.value = [..._envScope.pins].join(',');
    }

    async function saveEnvConfig() {
        syncEnvScopePickersToInputs();
        const updates = {};
        document.querySelectorAll('[id^="ec-"]').forEach(el => {
            if (el.type === 'hidden' && el.value === '') return; // skip empty hidden
            const key = el.id.replace('ec-', '');
            if (el.value !== '') updates[key] = el.value;
        });
        const st = document.getElementById('env-status');
        if (st) { st.textContent = 'Saving...'; st.className = 'env-status'; }
        try {
            const res = await fetch(`/api/env_config`, {
                method: 'POST',
                headers: _adminHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(updates)
            });
            const data = await res.json();
            if (data.ok) {
                if (st) {
                    st.textContent = `✓ Saved (${data.updated.length} keys updated)`;
                    st.className = 'env-status ok';
                    setTimeout(() => { if (st) st.textContent = ''; }, 4000);
                }
            } else {
                throw new Error(data.error || 'Unknown error');
            }
        } catch(e) {
            if (st) { st.textContent = '✗ Error: ' + e.message; st.className = 'env-status err'; }
        }
    }

    function toggleEnvAdvanced() {
        const sec = document.getElementById('env-adv-section');
        const btn = document.getElementById('env-adv-btn');
        if (!sec || !btn) return;
        const open = sec.classList.toggle('open');
        btn.textContent = _t(open ? 'sysconfig.adv_toggle_open' : 'sysconfig.adv_toggle');
    }

    // ═══════════════════════════════════════════════════════════════════
    // Threat Situation Map (TSM) — Theater Halo + Sensor Status Icons
    // ═══════════════════════════════════════════════════════════════════

    // Per-sensor config: angle (degrees from north, CW), short label, domain
    const SENSOR_ICON_CFG = {
        'cloudflare_radar': {angle:   0, label: 'CF',   domain: 'cyber'},
        'ripe_bgp':         {angle: 330, label: 'BGP',  domain: 'cyber'},
        'check_host':       {angle:  30, label: 'CH',   domain: 'cyber'},
        'threatfox':        {angle: 305, label: 'TFX',  domain: 'cyber'},
        'greynoise':        {angle:  55, label: 'GN',   domain: 'cyber'},
        'ioda_bgp':         {angle: 280, label: 'IODA', domain: 'cyber'},
        'opensky':          {angle:  75, label: 'AIR',  domain: 'physical'},
        'peeringdb_ixp':    {angle:  95, label: 'IXP',  domain: 'physical'},
        'isr_hotspot':      {angle: 118, label: 'ISR',  domain: 'physical'},
        'nasa_firms':       {angle: 143, label: 'FIRE', domain: 'physical'},
        'ais_maritime':     {angle: 167, label: 'AIS',  domain: 'physical'},
        'openweather':      {angle: 192, label: 'WX',   domain: 'physical'},
        'telegram_mirror':  {angle: 215, label: 'TG',   domain: 'info'},
        'gdelt':            {angle: 243, label: 'GDT',  domain: 'info'},
        'rss_narrative':    {angle: 268, label: 'RSS',  domain: 'info'},
    };

    const HALO_CFG = {
        1: {color: '#cc0000', radius: 550000},
        2: {color: '#ff4400', radius: 450000},
        3: {color: '#ff8800', radius: 350000},
        4: {color: '#ffcc00', radius: 250000},
    };

    // Convert angle (deg from north, CW) + distance (km) to [lat,lng] offset from base
    function _sensorCoord(baseLat, baseLng, angleDeg, distKm) {
        const rad  = angleDeg * Math.PI / 180;
        const dLat = (distKm / 111.0) * Math.cos(rad);
        const dLng = (distKm / (111.0 * Math.cos(baseLat * Math.PI / 180))) * Math.sin(rad);
        return [baseLat + dLat, baseLng + dLng];
    }

    // Cache core theater coord for this render cycle
    let _coreCoord = null;

    function updateThreatHalo(strat, coreCoord) {
        haloLayer.clearLayers();
        _coreCoord = coreCoord;
        const tl  = strat.threat_level;
        const cfg = HALO_CFG[tl];
        if (!cfg || !coreCoord) return;

        const lat = coreCoord.lat;
        const lng = shiftLng(coreCoord.lng);

        // Solid dashed ring
        L.circle([lat, lng], {
            radius: cfg.radius,
            color: cfg.color, weight: 1.5,
            opacity: 0.6, fillOpacity: 0.03,
            className: 'theater-halo-ring',
            interactive: false,
        }).addTo(haloLayer);

        // Pulsing outer ring
        L.circle([lat, lng], {
            radius: cfg.radius * 1.18,
            color: cfg.color, weight: 1,
            opacity: 0, fillOpacity: 0,
            className: `theater-halo-pulse tl${tl}`,
            interactive: false,
        }).addTo(haloLayer);

        // TL label — positioned just above the halo top edge
        const labelOffsetKm = cfg.radius / 1000 + 60;
        const [lblLat] = _sensorCoord(lat, lng, 0, labelOffsetKm);
        L.marker([lblLat, lng], {
            icon: L.divIcon({
                className: '',
                html: `<div class="halo-tl-label tl${tl}">TL-${tl}</div>`,
                iconSize: [48, 18], iconAnchor: [24, 18],
            }),
            interactive: false,
        }).addTo(haloLayer);
    }

    function updateSensorMarkers(strat, coreCoord) {
        sensorMarkerLayer.clearLayers();
        const tl = strat.threat_level;
        if (tl > 4 || !coreCoord) return;

        const baseLat = coreCoord.lat;
        const baseLng = shiftLng(coreCoord.lng);
        // Ring distance scales with TL severity
        const distKm  = 500 + (5 - tl) * 40; // TL4=540, TL3=580, TL2=620, TL1=660

        const rationale = strat.rationale_matrix || [];
        const entryMap  = {};
        rationale.forEach(e => { entryMap[e.sensor] = e; });

        Object.entries(SENSOR_ICON_CFG).forEach(([sensor, cfg]) => {
            const entry = entryMap[sensor];
            if (!entry) return;

            const isFired     = entry.status === 'FIRED' && !entry.suppressed;
            const isSuppressed = entry.suppressed;
            if (!isFired && !isSuppressed) return; // hide inactive sensors

            const [iconLat, iconLng] = _sensorCoord(baseLat, baseLng, cfg.angle, distKm);
            const score     = entry.score || 0;
            const scoreStr  = score > 0 ? `+${score}` : '';
            const divClass  = isSuppressed ? 'suppressed' : 'fired';

            const icon = L.divIcon({
                className: '',
                html: `<div class="sensor-icon-div ${divClass}">` +
                      `<div class="sensor-icon-badge domain-${cfg.domain}">${cfg.label}</div>` +
                      (scoreStr ? `<div class="sensor-icon-score">${scoreStr}</div>` : '') +
                      `</div>`,
                iconSize: [40, 28], iconAnchor: [20, 14],
            });

            const domainColor = cfg.domain === 'cyber' ? '#00ffff' : cfg.domain === 'physical' ? '#ffaa00' : '#cc66ff';
            const popup = `<div style="font-family:'Courier New',monospace;font-size:11px;min-width:150px;">` +
                `<b style="color:${domainColor}">${sensor}</b><br>` +
                `Status: <b>${entry.status}</b>${isSuppressed ? ' <span style="color:#888">[MUTED]</span>' : ''}<br>` +
                `Score: <b>+${score}pt</b><br>` +
                (entry.value        ? `Value: ${entry.value}<br>` : '') +
                (entry.fired_reason ? `Reason: ${entry.fired_reason}` : '') +
                (isSuppressed && entry.suppress_reason ? `<br><span style="color:#666">Suppressed: ${entry.suppress_reason}</span>` : '') +
                `</div>`;

            L.marker([iconLat, iconLng], {icon})
             .bindPopup(popup)
             .addTo(sensorMarkerLayer);
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // Domain Drilldown Panel
    // ═══════════════════════════════════════════════════════════════════

    let _drilldownOpen   = false;
    let _drilldownStrat  = null;

    window.toggleDrilldown = function() {
        _drilldownOpen = !_drilldownOpen;
        const panel   = document.getElementById('domain-drilldown-panel');
        const hint    = document.getElementById('dd-toggle-hint');
        if (panel) panel.style.display = _drilldownOpen ? 'block' : 'none';
        if (hint)  hint.textContent = _drilldownOpen ? '▴' : '▾';
        if (_drilldownOpen && _drilldownStrat) _updateDrilldownContent(_drilldownStrat);
    };

    function updateDrilldown(strat) {
        _drilldownStrat = strat;
        if (_drilldownOpen) _updateDrilldownContent(strat);
    }

    function _updateDrilldownContent(strat) {
        const domainColors  = {cyber: '#00ffff', physical: '#ffaa00', info: '#cc66ff'};
        const rationale     = strat.rationale_matrix || [];
        const domainData    = strat.domains || {};

        ['cyber', 'physical', 'info'].forEach(domain => {
            const col   = document.getElementById(`dd-sensors-${domain}`);
            const scoreEl = document.getElementById(`dd-score-${domain}`);
            if (!col) return;

            const color   = domainColors[domain];
            const dScore  = (domainData[domain] || {}).score || 0;
            if (scoreEl) { scoreEl.textContent = `${dScore}pt`; scoreEl.style.color = color; }

            const entries = rationale
                .filter(e => e.domain === domain)
                .sort((a, b) => (b.score || 0) - (a.score || 0));

            col.innerHTML = entries.map(e => {
                const isFired     = e.status === 'FIRED' && !e.suppressed;
                const isSuppressed = e.suppressed;
                const rowClass    = isSuppressed ? 'suppressed' : isFired ? 'fired' : 'not-fired';
                const pct         = Math.min(((e.score || 0) / 3) * 100, 100);
                const cfg         = SENSOR_ICON_CFG[e.sensor];
                const label       = cfg ? cfg.label : (e.sensor || '').substring(0, 6).toUpperCase();
                const detail      = (e.value || e.fired_reason || '').substring(0, 28);
                const mapBtn      = cfg
                    ? `<span class="dd-map-btn" onclick="event.stopPropagation();focusSensorOnMap('${e.sensor}')" title="${_t('dd.btn.focus_map')}">⊙</span>`
                    : '';

                return `<div class="dd-sensor-row ${rowClass}" onclick="focusSensorOnMap('${e.sensor}')">` +
                    `<span class="dd-label" style="color:${isFired ? color : '#777'}">${label}</span>` +
                    `<div class="dd-bar-wrap"><div class="dd-bar-fill" style="width:${pct}%;background:${isFired ? color : '#333'};"></div></div>` +
                    `<span class="dd-score" style="color:${isFired ? color : '#666'}">${e.score > 0 ? '+'+e.score : '—'}</span>` +
                    `<span class="dd-detail">${detail}</span>` +
                    mapBtn +
                    `</div>`;
            }).join('');
        });
    }

    window.focusSensorOnMap = function(sensorName) {
        if (!_drilldownStrat || !_coreCoord) return;
        const cfg = SENSOR_ICON_CFG[sensorName];
        if (!cfg) {
            map.flyTo([_coreCoord.lat, shiftLng(_coreCoord.lng)], 5, {animate: true, duration: 0.8});
            return;
        }
        const tl     = _drilldownStrat.threat_level;
        const distKm = 500 + (5 - tl) * 40;
        const [lat, lng] = _sensorCoord(_coreCoord.lat, shiftLng(_coreCoord.lng), cfg.angle, distKm);
        map.flyTo([lat, lng], 6, {animate: true, duration: 0.8});
    };

    // ── User Management Panel ──────────────────────────────────────────────
    // Sync with global auth tokens from localStorage
    let _umgrToken = localStorage.getItem('radar_access_token');
    let _umgrUser = localStorage.getItem('radar_username');

    window.toggleUserMgr = function() {
        openModal('settings-modal');
        switchTab('users');
        umgrLoadUsers();
    };

    window.umgrLogout = function() {
        _umgrToken = null;
        _umgrUser = null;
        localStorage.removeItem('radar_access_token');
        localStorage.removeItem('radar_refresh_token');
        localStorage.removeItem('radar_username');
        localStorage.removeItem('radar_role');
        // Show login gate
        document.getElementById('login-gate').style.display = 'flex';
        closeAllModals();
    };

    function _umgrHeaders() {
        const token = localStorage.getItem('radar_access_token') || _umgrToken;
        return { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
    }

    window.umgrLoadUsers = async function() {
        const container = document.getElementById('usrmgr-list');
        if (!container || !_umgrToken) return;
        try {
            const res = await fetch('/api/auth/users', { headers: _umgrHeaders() });
            if (res.status === 403) { container.innerHTML = `<div style="color:#ff6666;font-size:10px;">${_t('panel.usermgr.err.admin_priv')}</div>`; return; }
            if (!res.ok) { container.innerHTML = `<div style="color:#ff6666;font-size:10px;">${_t('panel.usermgr.err.load_users')}</div>`; return; }
            const users = await res.json();
            container.innerHTML = '';
            const table = document.createElement('table');
            table.style.cssText = 'width:100%;border-collapse:collapse;font-size:10px;';
            // Header
            const thead = table.createTHead();
            const hr = thead.insertRow();
            [_t('panel.usermgr.tbl.username'), _t('panel.usermgr.tbl.role'), _t('panel.usermgr.tbl.created'), _t('panel.usermgr.tbl.last_login'), _t('panel.usermgr.tbl.actions')].forEach(h => {
                const th = document.createElement('th');
                th.textContent = h;
                th.style.cssText = 'text-align:left;padding:3px 6px;color:#888;border-bottom:1px solid #333;font-weight:normal;letter-spacing:1px;font-size:9px;';
                hr.appendChild(th);
            });
            // Rows
            const tbody = table.createTBody();
            users.forEach(u => {
                const tr = tbody.insertRow();
                tr.style.borderBottom = '1px solid #1a1a1a';
                // Username
                const tdName = tr.insertCell();
                tdName.textContent = u.username;
                tdName.style.cssText = 'padding:4px 6px;color:#ccc;';
                // Role (editable select)
                const tdRole = tr.insertCell();
                tdRole.style.cssText = 'padding:4px 6px;';
                if (u.username === _umgrUser) {
                    tdRole.textContent = u.role;
                    tdRole.style.color = '#66ccff';
                } else {
                    const sel = document.createElement('select');
                    sel.style.cssText = 'background:#111;border:1px solid #333;color:#ccc;padding:2px 4px;border-radius:3px;font-size:10px;cursor:pointer;';
                    ['admin', 'analyst', 'viewer'].forEach(r => {
                        const opt = document.createElement('option');
                        opt.value = r; opt.textContent = r;
                        if (r === u.role) opt.selected = true;
                        sel.appendChild(opt);
                    });
                    sel.onchange = () => umgrChangeRole(u.username, sel.value);
                    tdRole.appendChild(sel);
                }
                // Created
                const tdCreated = tr.insertCell();
                tdCreated.textContent = u.created_at ? new Date(u.created_at * 1000).toLocaleDateString() : '—';
                tdCreated.style.cssText = 'padding:4px 6px;color:#666;';
                // Last Login
                const tdLogin = tr.insertCell();
                tdLogin.textContent = u.last_login ? new Date(u.last_login * 1000).toLocaleString() : _t('panel.usermgr.tbl.never');
                tdLogin.style.cssText = 'padding:4px 6px;color:#666;';
                // Actions
                const tdAct = tr.insertCell();
                tdAct.style.cssText = 'padding:4px 6px;';
                if (u.username !== _umgrUser) {
                    const btnReset = document.createElement('button');
                    btnReset.textContent = _t('panel.usermgr.btn.pw');
                    btnReset.title = _t('panel.usermgr.tip.reset_pw');
                    btnReset.style.cssText = 'background:none;border:1px solid #444;color:#ffaa00;font-size:9px;padding:1px 6px;border-radius:2px;cursor:pointer;margin-right:4px;';
                    btnReset.onclick = () => {
                        const sel = document.getElementById('usrmgr-reset-target-select');
                        if (sel) sel.value = u.username;
                        document.getElementById('usrmgr-reset-pw').value = '';
                        document.getElementById('usrmgr-reset-section').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    };
                    tdAct.appendChild(btnReset);

                    const btnDel = document.createElement('button');
                    btnDel.textContent = _t('panel.usermgr.btn.del');
                    btnDel.title = _t('panel.usermgr.tip.delete');
                    btnDel.style.cssText = 'background:none;border:1px solid #442222;color:#ff4444;font-size:9px;padding:1px 6px;border-radius:2px;cursor:pointer;';
                    btnDel.onclick = () => umgrDeleteUser(u.username);
                    tdAct.appendChild(btnDel);
                } else {
                    tdAct.innerHTML = '<span style="color:#444;font-size:9px;">—</span>';
                }
            });
            container.appendChild(table);
            // Populate reset dropdown
            const resetSel = document.getElementById('usrmgr-reset-target-select');
            if (resetSel) {
                const prev = resetSel.value;
                resetSel.innerHTML = `<option value="">${_t('panel.usermgr.ph.select_user')}</option>`;
                users.filter(u => u.username !== _umgrUser).forEach(u => {
                    const opt = document.createElement('option');
                    opt.value = u.username; opt.textContent = u.username;
                    resetSel.appendChild(opt);
                });
                if (prev) resetSel.value = prev;
            }
        } catch (e) { container.innerHTML = `<div style="color:#ff6666;font-size:10px;">${_t('panel.usermgr.err.load_error')}</div>`; }
    };

    window.umgrAddUser = async function() {
        const user = document.getElementById('usrmgr-new-user').value.trim();
        const pass = document.getElementById('usrmgr-new-pass').value;
        const role = document.getElementById('usrmgr-new-role').value;
        if (!user || !pass) return alert(_t('panel.usermgr.val.user_pass_req'));
        if (pass.length < 6) return alert(_t('panel.usermgr.val.pass_min6'));
        try {
            const res = await fetch('/api/auth/register', {
                method: 'POST', headers: _umgrHeaders(),
                body: JSON.stringify({ username: user, password: pass, role })
            });
            const data = await res.json();
            if (!res.ok) return alert(data.error || _t('panel.usermgr.err.add_user'));
            document.getElementById('usrmgr-new-user').value = '';
            document.getElementById('usrmgr-new-pass').value = '';
            umgrLoadUsers();
        } catch (e) { alert(_t('panel.usermgr.msg.conn_error')); }
    };

    window.umgrChangeRole = async function(username, newRole) {
        try {
            const res = await fetch(`/api/auth/users/${encodeURIComponent(username)}/role`, {
                method: 'PUT', headers: _umgrHeaders(),
                body: JSON.stringify({ role: newRole })
            });
            const data = await res.json();
            if (!res.ok) { alert(data.error || _t('panel.usermgr.err.update_role')); umgrLoadUsers(); }
        } catch (e) { alert(_t('panel.usermgr.msg.conn_error')); }
    };

    window.umgrDeleteUser = async function(username) {
        if (!confirm(_t('panel.usermgr.confirm.delete', {username}))) return;
        try {
            const res = await fetch(`/api/auth/users/${encodeURIComponent(username)}`, {
                method: 'DELETE', headers: _umgrHeaders()
            });
            const data = await res.json();
            if (!res.ok) return alert(data.error || _t('panel.usermgr.err.delete_user'));
            umgrLoadUsers();
        } catch (e) { alert(_t('panel.usermgr.msg.conn_error')); }
    };

    window.umgrResetPw = async function() {
        const sel = document.getElementById('usrmgr-reset-target-select');
        const target = sel ? sel.value : '';
        const statusEl = document.getElementById('usrmgr-reset-status');
        if (!target) { if (statusEl) { statusEl.textContent = _t('panel.usermgr.err.select_user'); statusEl.style.color = '#ff6666'; } return; }
        const newPw = document.getElementById('usrmgr-reset-pw').value;
        if (!newPw || newPw.length < 6) { if (statusEl) { statusEl.textContent = _t('panel.usermgr.val.pass_min6'); statusEl.style.color = '#ff6666'; } return; }
        try {
            const res = await fetch(`/api/auth/users/${encodeURIComponent(target)}/reset-password`, {
                method: 'POST', headers: _umgrHeaders(),
                body: JSON.stringify({ new_password: newPw })
            });
            const data = await res.json();
            if (!res.ok) { if (statusEl) { statusEl.textContent = data.error || _t('panel.usermgr.err.reset_pw'); statusEl.style.color = '#ff6666'; } return; }
            document.getElementById('usrmgr-reset-pw').value = '';
            if (statusEl) { statusEl.textContent = _t('panel.usermgr.confirm.pw_reset', {username: target}); statusEl.style.color = '#66ff66'; }
        } catch (e) { if (statusEl) { statusEl.textContent = _t('panel.usermgr.msg.conn_error'); statusEl.style.color = '#ff6666'; } }
    };

    window.umgrChangePw = async function() {
        const oldPw = document.getElementById('usrmgr-old-pw').value;
        const newPw = document.getElementById('usrmgr-change-pw').value;
        const statusEl = document.getElementById('usrmgr-changepw-status');
        if (!oldPw) { statusEl.textContent = _t('panel.usermgr.err.old_pw_req'); statusEl.style.color = '#ff6666'; return; }
        if (!newPw || newPw.length < 6) { statusEl.textContent = _t('panel.usermgr.val.pass_min6'); statusEl.style.color = '#ff6666'; return; }
        try {
            const res = await fetch('/api/auth/password', {
                method: 'PUT', headers: _umgrHeaders(),
                body: JSON.stringify({ old_password: oldPw, new_password: newPw })
            });
            const data = await res.json();
            if (!res.ok) { statusEl.textContent = data.error || _t('panel.usermgr.err.change_pw'); statusEl.style.color = '#ff6666'; return; }
            statusEl.textContent = _t('panel.usermgr.msg.pw_changed'); statusEl.style.color = '#66ff66';
            document.getElementById('usrmgr-old-pw').value = '';
            document.getElementById('usrmgr-change-pw').value = '';
        } catch (e) { statusEl.textContent = _t('panel.usermgr.msg.conn_error'); statusEl.style.color = '#ff6666'; }
    };

    // ── Sensor Fleet Health HUD ─────────────────────────────────────────────
    const _SENSOR_STATUS_COLOR = { OK: '#00ff88', STALE: '#ffaa00', ERROR: '#ff2222', DISABLED: '#444', INITIALIZING: '#666' };
    let _sensorHealthCache = {};
    function _updateSensorHealthHUD(healthMap) {
        if (!healthMap) return;
        _sensorHealthCache = healthMap;
        const dotsEl = document.getElementById('hud-sensor-dots');
        const summaryEl = document.getElementById('hud-sensor-summary');
        if (!dotsEl) return;
        const entries = Object.entries(healthMap);
        let ok = 0, stale = 0, err = 0, disabled = 0;
        entries.forEach(([, st]) => {
            if (st === 'OK') ok++;
            else if (st === 'STALE') stale++;
            else if (st === 'ERROR') err++;
            else disabled++;
        });
        const total = entries.length;
        // Dots
        dotsEl.innerHTML = entries.map(([name, st]) => {
            const color = _SENSOR_STATUS_COLOR[st] || '#444';
            return `<span style="width:6px;height:6px;border-radius:50%;background:${color};display:inline-block;" title="${name}: ${st}"></span>`;
        }).join('');
        // Summary text
        if (summaryEl) {
            if (err > 0) { summaryEl.textContent = `${ok}/${total}`; summaryEl.style.color = '#ff2222'; }
            else if (stale > 0) { summaryEl.textContent = `${ok}/${total}`; summaryEl.style.color = '#ffaa00'; }
            else { summaryEl.textContent = `${ok}/${total}`; summaryEl.style.color = '#00ff88'; }
        }
    }

    // ── History Analysis Panel ─────────────────────────────────────────────
    window.toggleHistoryPanel = function() {
        const p = document.getElementById('history-panel');
        if (!p) return;
        const vis = p.style.display !== 'none';
        p.style.display = vis ? 'none' : '';
        if (!vis) {
            // Populate theater selector from config
            const sel = document.getElementById('hist-theater');
            if (sel && window._appConfig) {
                const theaters = new Set([window._appConfig.core, ...(window._appConfig.pins||[]), ...(window._appConfig.correlates||[])]);
                sel.innerHTML = '';
                theaters.forEach(t => {
                    const o = document.createElement('option');
                    o.value = t; o.textContent = t;
                    if (t === window._appConfig.core) o.selected = true;
                    sel.appendChild(o);
                });
            }
            loadHistoryData();
        }
    };

    // TL color mapping used across history panel
    const _TL_COLORS = ['#ff2222','#ff4444','#ffaa00','#ffff00','#66ff66'];
    function _tlColor(tl) { return _TL_COLORS[Math.max(0,Math.min(4,(tl||1)-1))]; }

    window.loadHistoryData = function() {
        const theater = document.getElementById('hist-theater')?.value || 'TW';
        const hours = parseInt(document.getElementById('hist-range')?.value || '168');

        fetch(`/api/history/timeseries?theater=${theater}&hours=${hours}&series=combined,l3,l7`)
            .then(r => r.json())
            .then(data => _drawScoreChart(data))
            .catch(e => console.error('[History] timeseries error:', e));

        fetch(`/api/history/hod_baseline?theater=${theater}&type=hod_baseline`)
            .then(r => r.json())
            .then(data => _drawHodChart(data))
            .catch(e => console.error('[History] hod error:', e));

        fetch(`/api/history/sequence_events?theater=${theater}&hours=${hours}`)
            .then(r => r.json())
            .then(data => _renderSeqEvents(data))
            .catch(e => console.error('[History] seq error:', e));

        const sinceTs = Math.floor(Date.now()/1000) - hours * 3600;
        fetch(`/api/history/alerts?limit=200&since=${sinceTs}`)
            .then(r => r.json())
            .then(data => _renderAlerts(data))
            .catch(e => console.error('[History] alerts error:', e));
    };

    function _drawScoreChart(data) {
        const canvas = document.getElementById('hist-score-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width, h = canvas.height;
        const pad = { top: 8, right: 8, bottom: 18, left: 36 };
        const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
        ctx.clearRect(0, 0, w, h);

        const scored = data.series?.scored || [];
        if (scored.length < 2) {
            ctx.fillStyle = '#555'; ctx.font = '10px monospace';
            ctx.fillText(_t('panel.history.no_data'), w/2 - 30, h/2);
            return;
        }

        // Update summary stats
        const vals = scored.map(p => p.value);
        const peak = Math.max(...vals);
        const avg = vals.reduce((a,b) => a+b, 0) / vals.length;
        const elPts = document.getElementById('hist-stat-points');
        const elPeak = document.getElementById('hist-stat-peak');
        const elAvg = document.getElementById('hist-stat-avg');
        if (elPts) elPts.textContent = scored.length;
        if (elPeak) { elPeak.textContent = peak.toFixed(1); elPeak.style.color = peak >= 80 ? '#ff2222' : peak >= 50 ? '#ffaa00' : '#0ff'; }
        if (elAvg) elAvg.textContent = avg.toFixed(1);

        const mn = Math.min(...vals), mx = Math.max(...vals, 1);
        const range = mx - mn || 1;

        // TL zone backgrounds (5 zones evenly divided across score range)
        const zoneColors = ['rgba(34,170,68,0.06)','rgba(102,204,0,0.06)','rgba(255,170,0,0.06)','rgba(255,102,0,0.08)','rgba(255,34,34,0.10)'];
        for (let z = 0; z < 5; z++) {
            const zTop = pad.top + ch - ((z+1)/5) * ch;
            const zH = ch / 5;
            ctx.fillStyle = zoneColors[z];
            ctx.fillRect(pad.left, zTop, cw, zH);
        }

        // Grid lines + Y labels
        ctx.strokeStyle = '#1a1a1a'; ctx.lineWidth = 0.5;
        ctx.fillStyle = '#555'; ctx.font = '8px monospace'; ctx.textAlign = 'right';
        for (let i = 0; i <= 4; i++) {
            const yVal = mn + (i/4) * range;
            const y = pad.top + ch - (i/4) * ch;
            ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
            ctx.fillText(yVal.toFixed(0), pad.left - 4, y + 3);
        }
        ctx.textAlign = 'left';

        // X helper
        const toX = i => pad.left + (i / (scored.length - 1)) * cw;
        const toY = v => pad.top + ch - ((v - mn) / range) * ch;

        // Area fill with gradient
        const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + ch);
        grad.addColorStop(0, 'rgba(0,255,255,0.25)');
        grad.addColorStop(1, 'rgba(0,255,255,0.02)');
        ctx.fillStyle = grad;
        ctx.beginPath();
        ctx.moveTo(toX(0), pad.top + ch);
        scored.forEach((p, i) => ctx.lineTo(toX(i), toY(p.value)));
        ctx.lineTo(toX(scored.length - 1), pad.top + ch);
        ctx.closePath(); ctx.fill();

        // Score line
        ctx.strokeStyle = '#0ff'; ctx.lineWidth = 1.5;
        ctx.beginPath();
        scored.forEach((p, i) => { i === 0 ? ctx.moveTo(toX(i), toY(p.value)) : ctx.lineTo(toX(i), toY(p.value)); });
        ctx.stroke();

        // Data point dots (sample to avoid clutter)
        const step = Math.max(1, Math.floor(scored.length / 40));
        ctx.fillStyle = '#0ff';
        for (let i = 0; i < scored.length; i += step) {
            ctx.beginPath(); ctx.arc(toX(i), toY(scored[i].value), 1.5, 0, Math.PI * 2); ctx.fill();
        }

        // X-axis date labels
        ctx.fillStyle = '#555'; ctx.font = '8px monospace';
        const labelCount = Math.min(5, scored.length);
        for (let i = 0; i < labelCount; i++) {
            const idx = Math.floor(i / (labelCount - 1) * (scored.length - 1));
            const dt = new Date(scored[idx].ts * 1000);
            const label = `${(dt.getMonth()+1)}/${dt.getDate()} ${String(dt.getHours()).padStart(2,'0')}:00`;
            ctx.textAlign = i === labelCount - 1 ? 'right' : i === 0 ? 'left' : 'center';
            ctx.fillText(label, toX(idx), h - 2);
        }
        ctx.textAlign = 'left';
    }

    function _drawHodChart(data) {
        const canvas = document.getElementById('hist-hod-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width, h = canvas.height;
        const pad = { top: 6, right: 8, bottom: 16, left: 30 };
        const cw = w - pad.left - pad.right, ch = h - pad.top - pad.bottom;
        ctx.clearRect(0, 0, w, h);

        const stats = data.hod_stats || [];
        if (!stats.length) return;

        const means = stats.map(s => s.mean).filter(v => v !== null);
        if (!means.length) {
            ctx.fillStyle = '#555'; ctx.font = '10px monospace';
            ctx.fillText(_t('panel.history.no_hod'), w/2 - 30, h/2);
            return;
        }
        const mx = Math.max(...means, 0.01);
        // Include std dev in max for proper scaling
        const mxWithStd = Math.max(...stats.map(s => s.mean !== null ? s.mean + (s.std || 0) : 0), 0.01);
        const barW = cw / 24;
        const now = new Date().getHours();

        // Overall average line
        const overallAvg = means.reduce((a,b) => a + b, 0) / means.length;
        const avgY = pad.top + ch - (overallAvg / mxWithStd) * ch;

        // Y-axis grid
        ctx.strokeStyle = '#1a1a1a'; ctx.lineWidth = 0.5;
        ctx.fillStyle = '#444'; ctx.font = '7px monospace'; ctx.textAlign = 'right';
        for (let i = 0; i <= 3; i++) {
            const yVal = (i/3) * mxWithStd;
            const y = pad.top + ch - (i/3) * ch;
            ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
            ctx.fillText(yVal.toFixed(1), pad.left - 3, y + 3);
        }
        ctx.textAlign = 'left';

        stats.forEach((s, i) => {
            if (s.mean === null) return;
            const x = pad.left + i * barW;
            const barH = (s.mean / mxWithStd) * ch;
            const y = pad.top + ch - barH;

            // Std dev whisker (background range)
            if (s.std) {
                const stdTop = pad.top + ch - (Math.min(s.mean + s.std, mxWithStd) / mxWithStd) * ch;
                const stdBot = pad.top + ch - (Math.max(s.mean - s.std, 0) / mxWithStd) * ch;
                ctx.fillStyle = 'rgba(255,255,255,0.04)';
                ctx.fillRect(x + 1, stdTop, barW - 2, stdBot - stdTop);
            }

            // Bar color by intensity
            const intensity = s.mean / mx;
            const r = Math.floor(intensity * 255);
            const g = Math.floor((1 - intensity) * 200);
            ctx.fillStyle = `rgb(${r},${g},50)`;

            // Current hour highlight
            if (i === now) {
                ctx.fillStyle = `rgba(${r},${g},50,0.9)`;
                ctx.shadowColor = `rgb(${r},${g},50)`;
                ctx.shadowBlur = 6;
            }
            ctx.fillRect(x + 1, y, barW - 2, barH);
            ctx.shadowBlur = 0;

            // Current hour marker
            if (i === now) {
                ctx.strokeStyle = '#0ff'; ctx.lineWidth = 1;
                ctx.strokeRect(x, y - 1, barW, barH + 2);
            }

            // Std dev whisker line
            if (s.std) {
                const wTop = pad.top + ch - (Math.min(s.mean + s.std, mxWithStd) / mxWithStd) * ch;
                const wBot = pad.top + ch - (Math.max(s.mean - s.std, 0) / mxWithStd) * ch;
                ctx.strokeStyle = 'rgba(255,255,255,0.25)'; ctx.lineWidth = 1;
                const cx = x + barW / 2;
                ctx.beginPath(); ctx.moveTo(cx, wTop); ctx.lineTo(cx, wBot); ctx.stroke();
                // Caps
                ctx.beginPath(); ctx.moveTo(cx - 2, wTop); ctx.lineTo(cx + 2, wTop); ctx.stroke();
                ctx.beginPath(); ctx.moveTo(cx - 2, wBot); ctx.lineTo(cx + 2, wBot); ctx.stroke();
            }

            // Hour label
            ctx.fillStyle = i === now ? '#0ff' : '#555';
            ctx.font = i === now ? 'bold 7px monospace' : '7px monospace';
            ctx.textAlign = 'center';
            ctx.fillText(String(i).padStart(2, '0'), x + barW/2, h - 2);
        });

        // Average reference line
        ctx.strokeStyle = '#ffaa0066'; ctx.lineWidth = 1;
        ctx.setLineDash([4, 4]);
        ctx.beginPath(); ctx.moveTo(pad.left, avgY); ctx.lineTo(w - pad.right, avgY); ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = '#ffaa00'; ctx.font = '7px monospace'; ctx.textAlign = 'left';
        ctx.fillText('avg', w - pad.right + 2, avgY + 3);
        ctx.textAlign = 'left';
    }

    function _renderSeqEvents(data) {
        const el = document.getElementById('hist-seq-events');
        if (!el) return;
        const events = data.events || [];
        // Update summary stat
        const elEv = document.getElementById('hist-stat-events');
        if (elEv) { elEv.textContent = events.length; elEv.style.color = events.length > 10 ? '#ff6600' : '#0ff'; }

        if (!events.length) {
            el.innerHTML = `<span style="color:#555">${_t('panel.history.no_events')}</span>`;
            return;
        }
        const colorMap = { BURST: '#ff8800', SURGE: '#ffee00', DDOS: '#ff2222', CHAIN: '#ff44ff', SYNC: '#ff2222' };
        const iconMap = { BURST: '◆', SURGE: '▲', DDOS: '●', CHAIN: '◈', SYNC: '●' };
        el.innerHTML = '<div class="hist-seq-line">' + events.slice(-30).map(e => {
            const dt = new Date(e.ts * 1000);
            const timeStr = `${(dt.getMonth()+1)}/${dt.getDate()} ${String(dt.getHours()).padStart(2,'0')}:${String(dt.getMinutes()).padStart(2,'0')}`;
            const key = Object.keys(colorMap).find(k => e.type.includes(k)) || '';
            const color = colorMap[key] || '#0ff';
            const icon = iconMap[key] || '◇';
            const meta = e.meta ? `<span style="color:#444;margin-left:4px;">${typeof e.meta === 'string' ? e.meta : JSON.stringify(e.meta).slice(0,60)}</span>` : '';
            return `<div class="hist-seq-item">` +
                   `<span style="color:${color};font-size:10px;">${icon}</span>` +
                   `<div><span style="color:#555;font-size:8px;">${timeStr}</span> ` +
                   `<span style="color:${color};font-weight:bold;font-size:9px;">${e.type}</span>${meta}</div>` +
                   `</div>`;
        }).join('') + '</div>';
    }

    function _renderAlerts(data) {
        const el = document.getElementById('hist-alerts');
        const stripCanvas = document.getElementById('hist-tl-strip');
        const distEl = document.getElementById('hist-tl-dist');
        const alerts = data.alerts || [];

        // Update summary stat
        const elAl = document.getElementById('hist-stat-alerts');
        if (elAl) { elAl.textContent = alerts.length; elAl.style.color = alerts.length > 20 ? '#ff2222' : '#0ff'; }

        if (!alerts.length) {
            if (el) el.innerHTML = `<span style="color:#555">${_t('panel.history.no_alerts')}</span>`;
            if (distEl) distEl.innerHTML = '';
            if (stripCanvas) { const ctx = stripCanvas.getContext('2d'); ctx.clearRect(0, 0, stripCanvas.width, stripCanvas.height); }
            return;
        }

        // ── TL Timeline Strip (colored horizontal bar) ──
        if (stripCanvas && alerts.length >= 2) {
            const ctx = stripCanvas.getContext('2d');
            const sw = stripCanvas.width, sh = stripCanvas.height;
            ctx.clearRect(0, 0, sw, sh);
            const tMin = alerts[0].ts, tMax = alerts[alerts.length-1].ts;
            const tRange = tMax - tMin || 1;
            // Draw segments between consecutive alerts
            for (let i = 0; i < alerts.length; i++) {
                const a = alerts[i];
                const next = alerts[i+1];
                const x1 = ((a.ts - tMin) / tRange) * sw;
                const x2 = next ? ((next.ts - tMin) / tRange) * sw : sw;
                const color = _tlColor(a.threat_level || 1);
                ctx.fillStyle = color;
                ctx.fillRect(x1, 4, Math.max(x2 - x1, 1), sh - 8);
            }
            // Time labels
            ctx.fillStyle = '#555'; ctx.font = '7px monospace';
            const dtMin = new Date(tMin * 1000), dtMax = new Date(tMax * 1000);
            const fmtDate = d => `${d.getMonth()+1}/${d.getDate()}`;
            ctx.textAlign = 'left'; ctx.fillText(fmtDate(dtMin), 2, sh - 1);
            ctx.textAlign = 'right'; ctx.fillText(fmtDate(dtMax), sw - 2, sh - 1);
            ctx.textAlign = 'left';
            // TL scale legend at top
            ctx.font = '7px monospace';
            for (let tl = 1; tl <= 5; tl++) {
                const lx = sw - 80 + (tl-1) * 16;
                ctx.fillStyle = _tlColor(tl);
                ctx.fillRect(lx, 0, 10, 3);
                ctx.fillText(tl, lx + 2, 10);
            }
        }

        // ── TL Distribution Bar ──
        if (distEl) {
            // Calculate time spent at each TL
            const tlTime = [0,0,0,0,0]; // TL1-5
            for (let i = 0; i < alerts.length; i++) {
                const tl = Math.max(1, Math.min(5, alerts[i].threat_level || 1));
                const duration = (i < alerts.length - 1) ? (alerts[i+1].ts - alerts[i].ts) : 0;
                tlTime[tl - 1] += duration;
            }
            const total = tlTime.reduce((a,b) => a+b, 0) || 1;
            distEl.innerHTML = tlTime.map((t, i) => {
                const pct = (t / total * 100);
                if (pct < 0.5) return '';
                const color = _TL_COLORS[i];
                return `<div style="flex:${Math.max(pct,3)};background:${color}33;border:1px solid ${color}44;border-radius:2px;padding:2px 4px;text-align:center;">` +
                       `<span style="color:${color};font-weight:bold;">TL${i+1}</span> ` +
                       `<span style="color:#888;">${pct.toFixed(0)}%</span></div>`;
            }).join('');
        }

        // ── Alert Details (grouped by day) ──
        if (el) {
            // Group by date
            const groups = {};
            alerts.forEach(a => {
                const d = new Date((a.ts||0) * 1000);
                const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
                if (!groups[key]) groups[key] = [];
                groups[key].push(a);
            });

            let html = '';
            const sortedDays = Object.keys(groups).sort().reverse(); // newest first
            sortedDays.forEach(day => {
                const dayAlerts = groups[day];
                // Day header with summary
                const tlCounts = {};
                dayAlerts.forEach(a => { const tl = a.threat_level||1; tlCounts[tl] = (tlCounts[tl]||0) + 1; });
                const maxTl = Math.max(...dayAlerts.map(a => a.threat_level||1));
                const tlBadges = Object.entries(tlCounts).sort((a,b) => b[0]-a[0]).map(([tl,cnt]) => {
                    const c = _tlColor(+tl);
                    return `<span style="color:${c};font-size:8px;">TL${tl}×${cnt}</span>`;
                }).join(' ');

                html += `<div style="margin-bottom:6px;">`;
                html += `<div style="display:flex;align-items:center;gap:6px;padding:2px 0;border-bottom:1px solid #1a1a1a;margin-bottom:2px;">`;
                html += `<span style="color:#888;font-size:9px;font-weight:bold;">${day}</span>`;
                html += `<span style="color:#555;font-size:8px;">(${dayAlerts.length})</span>`;
                html += `<span>${tlBadges}</span>`;
                html += `</div>`;

                // Individual alerts within day
                dayAlerts.forEach((a, idx) => {
                    const dt = new Date((a.ts||0) * 1000);
                    const timeStr = `${String(dt.getHours()).padStart(2,'0')}:${String(dt.getMinutes()).padStart(2,'0')}`;
                    const tl = a.threat_level || 1;
                    const color = _tlColor(tl);
                    const prevTl = idx > 0 ? (dayAlerts[idx-1].threat_level || 1) : tl;
                    const arrow = tl > prevTl ? `<span class="hist-alert-arrow" style="color:#ff2222;">▲</span>`
                                : tl < prevTl ? `<span class="hist-alert-arrow" style="color:#22aa44;">▼</span>`
                                : `<span class="hist-alert-arrow" style="color:#333;">─</span>`;
                    html += `<div class="hist-alert-row">` +
                           `<span style="color:#444;font-size:8px;min-width:36px;">${timeStr}</span>` +
                           `${arrow}` +
                           `<span class="hist-tl-badge" style="background:${color}22;color:${color};border:1px solid ${color}44;">TL${tl}</span>` +
                           `<span style="color:#888;font-size:9px;">${a.core || ''}</span>` +
                           `<span style="color:#555;font-size:9px;">score <b style="color:#aaa">${(a.score||0).toFixed(1)}</b></span>` +
                           `</div>`;
                });
                html += `</div>`;
            });
            el.innerHTML = html;
        }
    }

    window.exportHistoryData = function() {
        const theater = document.getElementById('hist-theater')?.value || 'TW';
        window.open(`/api/history/export?theater=${theater}`, '_blank');
    };
