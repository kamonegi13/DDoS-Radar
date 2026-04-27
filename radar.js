    // HTML escape utility — prevents XSS when inserting external API strings into innerHTML
    const esc = s => { s = String(s ?? ''); return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); };
    // URL scheme guard — prevents javascript: / data: URI injection in href attributes
    const safeHref = u => { try { const p = new URL(u); return (p.protocol === 'https:' || p.protocol === 'http:') ? esc(u) : '#'; } catch { return '#'; } };

    // ── Auth: wrap fetch to include JWT and handle 401 ──
    const _origFetch = window.fetch.bind(window);
    let _refreshPromise = null; // Serialize concurrent refresh attempts

    // Proactive token refresh: refresh when 80% of lifetime has elapsed
    // This prevents 401 errors from ever reaching the user
    const _TOKEN_LIFETIME_MS = (parseInt(localStorage.getItem('radar_token_lifetime') || '3600') || 3600) * 1000;
    const _REFRESH_THRESHOLD = 0.8; // refresh at 80% of lifetime
    let _tokenAcquiredAt = Date.now();

    function _scheduleProactiveRefresh() {
        const delay = _TOKEN_LIFETIME_MS * _REFRESH_THRESHOLD;
        setTimeout(() => {
            const refreshToken = localStorage.getItem('radar_refresh_token');
            if (!refreshToken) return;
            _doTokenRefresh(refreshToken).then(ok => {
                if (ok) _scheduleProactiveRefresh();
            });
        }, delay);
    }

    function _doTokenRefresh(refreshToken) {
        // Serialize: if already refreshing, reuse the same promise
        if (_refreshPromise) return _refreshPromise;
        _refreshPromise = _origFetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + refreshToken }
        }).then(rr => {
            if (rr.ok) {
                return rr.json().then(d => {
                    localStorage.setItem('radar_access_token', d.access_token);
                    _tokenAcquiredAt = Date.now();
                    return true;
                });
            }
            // Refresh failed — show login gate
            _showLoginGate();
            return false;
        }).catch(() => {
            return false;
        }).finally(() => {
            _refreshPromise = null;
        });
        return _refreshPromise;
    }

    function _showLoginGate() {
        localStorage.removeItem('radar_access_token');
        localStorage.removeItem('radar_refresh_token');
        const gate = document.getElementById('login-gate');
        if (gate) gate.style.display = 'flex';
    }

    // Layer 3 session overlay (ADR-003): weight hypothesis testing via
    // in-memory per-scenario overrides.  Stored in sessionStorage so it
    // is cleared when the tab closes — this is deliberate per the ADR
    // (stateless, non-persistent).  Backend reads `X-Scenario-Overlay`.
    function _scGetOverlay(scenarioId) {
        if (!scenarioId) return null;
        try {
            const raw = sessionStorage.getItem('sc_overlay:' + scenarioId);
            if (!raw) return null;
            const o = JSON.parse(raw);
            return (o && typeof o === 'object') ? o : null;
        } catch { return null; }
    }

    window.fetch = function(url, opts = {}) {
        const token = localStorage.getItem('radar_access_token');
        if (token && typeof url === 'string' && url.startsWith('/api/')) {
            opts.headers = opts.headers || {};
            if (!opts.headers['Authorization']) {
                opts.headers['Authorization'] = 'Bearer ' + token;
            }
        }
        // Inject Layer 3 overlay for /api/threat_data requests with ?focus=
        if (typeof url === 'string' && url.indexOf('/api/threat_data') === 0) {
            const m = url.match(/[?&]focus=([^&]+)/);
            if (m) {
                const ov = _scGetOverlay(decodeURIComponent(m[1]));
                if (ov && Object.keys(ov).length > 0) {
                    opts.headers = opts.headers || {};
                    opts.headers['X-Scenario-Overlay'] = JSON.stringify(ov);
                }
            }
        }
        return _origFetch(url, opts).then(res => {
            if (res.status === 401 && typeof url === 'string' && url.startsWith('/api/')
                && !url.includes('/api/auth/login') && !url.includes('/api/auth/refresh')) {
                const refreshToken = localStorage.getItem('radar_refresh_token');
                if (refreshToken) {
                    return _doTokenRefresh(refreshToken).then(ok => {
                        if (ok) {
                            // Retry original request with new token
                            opts.headers = opts.headers || {};
                            opts.headers['Authorization'] = 'Bearer ' + localStorage.getItem('radar_access_token');
                            return _origFetch(url, opts);
                        }
                        return res;
                    });
                }
                _showLoginGate();
            }
            return res;
        });
    };

    // Start proactive refresh cycle if we have a token
    if (localStorage.getItem('radar_access_token')) {
        _scheduleProactiveRefresh();
    }



    let latestData = null;
    let currentVector = 'all';
    let mapCenterMode = 'atlantic';
    let _lastRenderSig = ''; // P4-Opt: diff signature cache
    window._resetRenderSig = () => { _lastRenderSig = ''; };
    // Legacy config shape retained for compatibility with forceDataSync diff logic;
    // under scenario-unit mode these fields are driven by the focused scenario.
    let lastSyncedConfig = { core: "", correlates: [], adversaries: [], displays: [] };
    let lastSyncedTimeText = "System Initializing...";
    let isFirstLoad = true;
    let loaderLogInterval;
    let _nodeOkRetryTimer = null; // One-shot retry when CheckHost hasn't initialized yet
    // Per-panel onShow/onHide hooks keyed by panelId.
    // Entries persist for the app lifetime because panels are static DOM elements
    // that are shown/hidden (never destroyed). No cleanup needed on panel close.
    const _panelCallbacks = {};
    let STRATEGIC_BLOCS_DATA = {};  // { RUSSIA: {label, color, adversary, theaters[]}, ... }
    let ADVERSARY_OPTIONS    = [];  // [ {code, bloc, label, color}, ... ]
    let COUNTRY_BLOC_TAGS    = {};  // { "US": ["RUSSIA","CHINA","IRAN","DPRK"], ... }

    // HITL Analyst Mute State
    let mutedSensors;
    try { mutedSensors = new Set(JSON.parse(localStorage.getItem('mutedSensors') || '[]')); }
    catch (e) { console.warn('[MUTE] localStorage parse error — reset to empty:', e); mutedSensors = new Set(); }

    // Resolve the "target country" for CHAIN fetch / LLM intel filter.
    // Prefer scenario participants[role=primary_target], fall back to the legacy
    // strat.core_theater field while backend deprecation (sunset 2026-10-01) is in flight.
    // ADR-V2-006 A-2: prefer the new core_country key; fall back to core_theater
    // until A-5 sunset removes the legacy alias.
    function resolveChainTargetCountry(strat) {
        if (!strat) return '';
        const parts = strat.participants;
        if (parts && typeof parts === 'object') {
            let primary = '';
            let bestWeight = -1;
            for (const [code, p] of Object.entries(parts)) {
                if (!p || typeof p !== 'object') continue;
                if (p.role === 'primary_target') return String(code).toUpperCase();
                if (p.role && p.role !== 'adversary' && (p.weight || 0) > bestWeight) {
                    primary = String(code).toUpperCase();
                    bestWeight = p.weight || 0;
                }
            }
            if (primary) return primary;
        }
        return ((strat.core_country ?? strat.core_theater) || '').toUpperCase();
    }

    // Evidence Rationale Matrix: collapsed domain groups (persisted)
    let _evCollapsedDomains;
    try { _evCollapsedDomains = new Set(JSON.parse(localStorage.getItem('evCollapsedDomains') || '[]')); }
    catch (e) { _evCollapsedDomains = new Set(); }
    window.toggleEvDomain = function(domain) {
        if (_evCollapsedDomains.has(domain)) _evCollapsedDomains.delete(domain);
        else _evCollapsedDomains.add(domain);
        try { localStorage.setItem('evCollapsedDomains', JSON.stringify([..._evCollapsedDomains])); } catch (e) {}
        // Toggle row visibility in-place to avoid full re-render flash
        document.querySelectorAll(`tr[data-ev-domain="${domain}"]`).forEach(tr => {
            tr.style.display = _evCollapsedDomains.has(domain) ? 'none' : '';
        });
        const caret = document.querySelector(`[data-ev-caret="${domain}"]`);
        if (caret) caret.textContent = _evCollapsedDomains.has(domain) ? '▸' : '▾';
    };

    // Chain panel: collapsed metric groups (persisted, Phase A4)
    let _chainCollapsedGroups;
    try { _chainCollapsedGroups = new Set(JSON.parse(localStorage.getItem('chainCollapsedGroups') || '[]')); }
    catch (e) { _chainCollapsedGroups = new Set(); }
    function _applyChainCollapseState() {
        ['v8', 'v9'].forEach(g => {
            const grid = document.getElementById(`chain-metrics-${g}`);
            const toggle = document.querySelector(`.chain-group-toggle[data-chain-group="${g}"]`);
            if (!grid) return;
            const collapsed = _chainCollapsedGroups.has(g);
            grid.classList.toggle('chain-group-collapsed', collapsed);
            if (toggle) toggle.textContent = collapsed ? '▸' : '▾';
        });
    }
    window.toggleChainGroup = function(group) {
        if (_chainCollapsedGroups.has(group)) _chainCollapsedGroups.delete(group);
        else _chainCollapsedGroups.add(group);
        try { localStorage.setItem('chainCollapsedGroups', JSON.stringify([..._chainCollapsedGroups])); } catch (e) {}
        _applyChainCollapseState();
    };
    // Bind click delegation. Script loads at body end, so DOM may already be ready.
    function _bindChainGroupToggles() {
        document.querySelectorAll('.chain-group-toggle[data-chain-group]').forEach(el => {
            if (el.dataset.bound === '1') return;
            el.dataset.bound = '1';
            el.addEventListener('click', (ev) => {
                ev.stopPropagation();
                window.toggleChainGroup(el.dataset.chainGroup);
            });
        });
        _applyChainCollapseState();
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _bindChainGroupToggles);
    } else {
        _bindChainGroupToggles();
    }

    window.toggleMute = function(sensorName) {
        if (mutedSensors.has(sensorName)) {
            mutedSensors.delete(sensorName);
        } else {
            // Reason prompt kept so the analyst still records intent at the click site
            prompt(_t('sensor.mute.prompt', {name: sensorName}), '');
            mutedSensors.add(sensorName);
        }
        localStorage.setItem('mutedSensors', JSON.stringify([...mutedSensors]));
        forceDataSync(); // Trigger immediate recalculation
    };

    // ── CAC: Noise Classification Dialog ────────────────────────────────────
    window.openNoiseClassify = function(sensorName, value, domain) {
        const reasons = ['exercise', 'maintenance', 'known_noise', 'false_positive'];
        const labels = reasons.map(r => _t('noise.' + r));
        const choice = prompt(
            _t('noise.classify_prompt', {sensor: sensorName}) + '\n' +
            reasons.map((r, i) => `${i + 1}. ${labels[i]}`).join('\n') +
            '\n\n' + _t('noise.classify_hint'),
            ''
        );
        if (!choice) return;
        const idx = parseInt(choice) - 1;
        if (idx < 0 || idx >= reasons.length) {
            alert(_t('noise.invalid_choice'));
            return;
        }
        const reason = reasons[idx];
        const expiresHours = prompt(_t('noise.expires_prompt'), '24');
        const payload = {
            sensor: sensorName,
            theater: getCurrentConfig().core || '',
            pattern: value.substring(0, 100),
            reason: reason,
            expires_hours: expiresHours ? parseFloat(expiresHours) : null,
            created_by: 'analyst',
        };
        fetch('/api/noise_exclusion', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload),
        })
        .then(r => r.json())
        .then(d => {
            if (d.ok) {
                forceDataSync();
            } else {
                alert(d.error || 'Failed');
            }
        })
        .catch(e => alert('Error: ' + e.message));
    };

    // ── CAC: Confirmed Threat Classification ─────────────────────────────────
    window.openThreatClassify = function() {
        const strat = (window._lastThreatData || {}).strategic_alert;
        if (!strat) return;
        const reasons = ['exercise', 'maintenance', 'confirmed_threat', 'false_positive'];
        const labels = reasons.map(r => _t('threat_cls.' + r));
        const choice = prompt(
            _t('threat_cls.prompt') + '\n' +
            reasons.map((r, i) => `${i + 1}. ${labels[i]}`).join('\n'),
            ''
        );
        if (!choice) return;
        const idx = parseInt(choice) - 1;
        if (idx < 0 || idx >= reasons.length) return;
        const classification = reasons[idx];
        const notes = prompt(_t('threat_cls.notes_prompt'), '') || '';
        const firedSensors = (strat.rationale_matrix || [])
            .filter(e => e.status === 'FIRED' && !e.suppressed)
            .map(e => e.sensor);
        fetch('/api/confirmed_threats', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                theater: resolveChainTargetCountry(strat),
                classification: classification,
                sensors_active: firedSensors,
                threat_level: strat.threat_level,
                notes: notes,
                created_by: 'analyst',
            }),
        })
        .then(r => r.json())
        .then(d => {
            if (d.ok) {
                // Refresh LLM Intel panel so review_needed items become visible
                if (typeof _fetchLlmIntel === 'function') _fetchLlmIntel();
            }
        })
        .catch(e => console.warn('[ThreatClassify]', e));
    };

    // ── GreyNoise Investigator ─────────────────────────────────────────────────
    let _gnLog = [];
    try { _gnLog = JSON.parse(localStorage.getItem('gnLookupLog') || '[]'); } catch(e) { /* corrupted localStorage */ }

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
        // ADR-V2-006 A-2: prefer country_data; fall back to legacy theater_data.
        const listEl = document.getElementById('gn-theater-list');
        const gnCountryData = gn.country_data ?? gn.theater_data;
        if (listEl && gnCountryData) {
            listEl.innerHTML = Object.entries(gnCountryData).map(([cc, d]) => {
                const nc = d.noise_class || 'UNKNOWN';
                const nr = d.noise_ratio !== null && d.noise_ratio !== undefined ? ` (${Math.round(d.noise_ratio * 100)}%)` : '';
                return `<div class="gn-theater-row">
                    <span style="color:#888;font-size:10px;">${esc(cc)}</span>
                    <span class="gn-noise-${esc(nc)}" style="font-size:10px;font-weight:bold;">${esc(nc)}${nr}</span>
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
            return `<div class="gn-log-entry"><span style="color:#444;">${t}</span> <span style="color:#888;">${esc(e.ip)}</span> → <span class="${cls}">${e.noise?'NOISE':'TARGETED'}</span> <span style="color:#666;">${esc(e.name||'')}</span></div>`;
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
            // Re-render dirty panels that were skipped while hidden
            if (show && panel.dataset.dirty === '1') {
                panel.dataset.dirty = '';
                const _dirtyMap = {
                    'weather-brief-panel': typeof renderWeatherBrief === 'function' ? renderWeatherBrief : null,
                    'corr-heatmap-panel': typeof renderCorrHeatmap === 'function' ? renderCorrHeatmap : null,
                    'gn-panel': typeof updateGreyNoisePanel === 'function' ? () => updateGreyNoisePanel(window._lastThreatData) : null,
                };
                if (_dirtyMap[panelId]) _dirtyMap[panelId]();
            }
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

    // Expose panel factory + close helper so out-of-file panel scripts
    // (e.g. tradecraft.js) can reuse the standard floating-panel chrome.
    window._createPanelToggle = _createPanelToggle;
    window._panelClose = _panelClose;

    /**
     * Standard floating-panel builder — generates the shared chrome (drag handle,
     * title with data-i18n, minimize/close buttons), wraps existing panel body
     * content in a .panel-content container, registers the panel with
     * setupFloatingOnlyPanel, applies i18n, and returns a toggle function.
     *
     * Why this exists: panel chrome (title typography, icon buttons, drag/close
     * wiring) was authored by copy-paste in index.html across ~15 panels. This
     * factory makes the chrome a real component — every panel that uses it is
     * guaranteed to render identical typography/buttons and participate in the
     * same drag/close/clamp behavior. New panels should use this instead of
     * hand-authoring the .panel-header-unified header block.
     *
     * Usage: author the panel body in index.html as:
     *     <div id="foo-panel" style="display:none;"><!-- body content --></div>
     * then at startup call:
     *     createFloatingPanel({ id: 'foo-panel', titleKey: 'panel.foo.title', ... })
     *
     * @param {Object}  opts
     * @param {string}  opts.id              - existing panel div id (its current
     *                                         children become the body)
     * @param {string}  opts.titleKey        - data-i18n key for the title
     * @param {string}  [opts.titleFallback] - text to show until i18n applies
     * @param {number}  [opts.defaultLeft]   - initial left offset
     * @param {number}  [opts.defaultTop]    - initial top offset
     * @param {number}  [opts.width]         - fixed width in px
     * @param {boolean} [opts.minimizable]   - show − button (default true)
     * @param {boolean} [opts.closable]      - show ✕ button (default true)
     * @param {string}  [opts.bodyClass]     - extra class on .panel-content
     * @param {Function}[opts.onShow]
     * @param {Function}[opts.onHide]
     * @returns {Function} toggle function (call to show/hide)
     */
    window.createFloatingPanel = function createFloatingPanel(opts) {
        const {
            id, titleKey, titleFallback = '',
            defaultLeft, defaultTop = 130, width,
            minimizable = true, closable = true,
            bodyClass,
            onShow, onHide,
        } = opts || {};
        if (!id || !titleKey) {
            console.warn('createFloatingPanel: id and titleKey are required');
            return null;
        }
        const panel = document.getElementById(id);
        if (!panel) {
            console.warn(`createFloatingPanel: #${id} not found in DOM`);
            return null;
        }
        // Capture existing body content (authored in index.html)
        const existingChildren = Array.from(panel.childNodes);
        const content = document.createElement('div');
        content.className = 'panel-content' + (bodyClass ? ' ' + bodyClass : '');
        for (const child of existingChildren) content.appendChild(child);
        // Build standard chrome header
        const header = document.createElement('div');
        header.className = 'drag-handle panel-header-unified';
        const titleSpan = document.createElement('span');
        titleSpan.setAttribute('data-i18n', titleKey);
        titleSpan.textContent = titleFallback || titleKey;
        header.appendChild(titleSpan);
        const btnGroup = document.createElement('div');
        if (minimizable) {
            const minBtn = document.createElement('span');
            minBtn.className = 'icon-btn toggle-btn';
            minBtn.setAttribute('data-tooltip', 'Minimize');
            minBtn.setAttribute('data-i18n-tip', 'panel.common.minimize_tooltip');
            minBtn.textContent = '−';
            btnGroup.appendChild(minBtn);
        }
        if (closable) {
            const closeBtn = document.createElement('span');
            closeBtn.className = 'icon-btn';
            closeBtn.setAttribute('data-tooltip', 'Close');
            closeBtn.setAttribute('data-i18n-tip', 'panel.common.close_tooltip');
            closeBtn.style.color = '#ff444488';
            closeBtn.textContent = '✕';
            closeBtn.addEventListener('click', () => _panelClose(id));
            btnGroup.appendChild(closeBtn);
        }
        header.appendChild(btnGroup);
        // Reset panel root and assemble
        panel.className = 'draggable-panel floating';
        panel.style.display = 'none';
        if (defaultLeft != null) panel.style.left = defaultLeft + 'px';
        if (defaultTop != null)  panel.style.top  = defaultTop  + 'px';
        if (width != null)       panel.style.width = width + 'px';
        panel.innerHTML = '';
        panel.appendChild(header);
        panel.appendChild(content);
        // Register drag/minimize behavior
        setupFloatingOnlyPanel(id);
        // Apply i18n translations for the new data-i18n nodes
        if (typeof _applyStaticTranslations === 'function') _applyStaticTranslations();
        // Return toggle function (participates in _panelCallbacks / clamp / sync)
        return _createPanelToggle(id, {
            floating: true,
            defaultLeft, defaultTop,
            onShow, onHide,
        });
    };

    const toggleTargetPanel    = _createPanelToggle('target-panel',    { floating: false });
    const toggleDashboardPanel = _createPanelToggle('dashboard-panel', { floating: false });
    const toggleTgSigint       = _createPanelToggle('tg-sigint-panel', { floating: true, onShow: () => {
        if (window._lastThreatData) {
            const strat = window._lastThreatData.strategic_alert || {};
            const tg = (strat.analytics || {}).telegram_mirror || {};
            renderTgSigintPanel(tg);
        }
    }});

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
            const ts        = tg.last_poll_ts ? new Date(tg.last_poll_ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '—';
            const ok        = tg.last_poll_ok !== false;
            pollInfo.innerHTML =
                `${active}/${monitored} active &nbsp;<span style="color:${ok?'#00cc66':'#cc4444'};">${ok?'●':'✕'}</span>&nbsp; ${ts}`;
        }

        // Theater grid
        // ADR-V2-006 A-2: prefer country_breakdown; fall back to legacy theater_breakdown.
        const grid = document.getElementById('tgsig-theater-grid');
        if (grid) {
            const breakdown = tg.country_breakdown ?? tg.theater_breakdown ?? {};
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
                        onclick="tgSetFilter('theater','${esc(theater)}')" data-tooltip="${theater}: ${st}">
                        ${esc(theater)}[${label}]</span>`;
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
                        onclick="tgSetFilter('channel','${esc(ch)}')">${esc(ch)}</span>`;
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
            const ts       = h.ts ? new Date(h.ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '';
            const isIntent = h.status === 'INTENT_DETECTED';
            const color    = isIntent ? '#ff66cc' : '#ffaa00';
            const cls      = isIntent ? 'intent' : 'target';
            const kwStr    = (h.keywords_matched || []).join(' · ') || '—';
            const urlStr   = (h.target_urls || []).map(u => u.replace(/^https?:\/\//,'')).join(' · ');
            const snippet  = h.snippet
                ? `<div class="tgsig-snippet">${esc(h.snippet)}</div>` : '';
            const srcLink  = h.channel_url
                ? `<a href="${safeHref(h.channel_url)}" target="_blank" class="tgsig-src-link">↗SRC</a>` : '';
            return `<div class="tgsig-entry ${cls}">
                <div class="tgsig-entry-hdr">
                    <span><span style="color:#aaa;">${esc(h.channel||'?')}</span>&nbsp;·&nbsp;${ts}&nbsp;·&nbsp;${esc(h.theater||'')}</span>
                    ${srcLink}
                </div>
                <div class="tgsig-entry-class" style="color:${color};">
                    ${isIntent?'INTENT':'TARGET'}
                    <span class="tgsig-entry-kw">&nbsp;${esc(kwStr)}</span>
                </div>
                ${urlStr ? `<div class="tgsig-entry-urls">${esc(urlStr)}</div>` : ''}
                ${snippet}
            </div>`;
        }).join('');
    }
    // ── End Telegram SIGINT Panel ────────────────────────────────────────────

    // Auto-refresh TG SIGINT panel when visible
    window._updateTgSigintFromPoll = function(data) {
        const p = document.getElementById('tg-sigint-panel');
        if (p && p.style.display !== 'none') {
            const strat = (data && data.strategic_alert) || {};
            const tg = (strat.analytics || {}).telegram_mirror || {};
            renderTgSigintPanel(tg);
        }
    };

    function clearGnLog() {
        _gnLog = [];
        localStorage.setItem('gnLookupLog', '[]');
        renderGnLog();
        const rc = document.getElementById('gn-result-card');
        if (rc) { rc.style.display='none'; rc.innerHTML=''; }
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

    // CHAIN event ↔ bottom metric bidirectional highlight
    document.addEventListener('mouseover', e => {
        const el = e.target.closest('[data-chain-type]');
        if (!el) return;
        const t = el.getAttribute('data-chain-type');
        if (!t) return;
        document.querySelectorAll(`[data-chain-type="${t}"]`).forEach(n => n.classList.add('chain-highlighted'));
    });
    document.addEventListener('mouseout', e => {
        const el = e.target.closest('[data-chain-type]');
        if (!el) return;
        document.querySelectorAll('.chain-highlighted').forEach(n => n.classList.remove('chain-highlighted'));
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
            // Auto-load the active tab's data on first open
            const activeTab = modal.querySelector('.tab.active');
            if (activeTab) activeTab.click();
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
        { panelId: 'weather-brief-panel',  dotId: 'tm-dot-wx',    itemId: 'tm-item-wx'    },
        { panelId: 'gn-panel',             dotId: 'tm-dot-gn',    itemId: 'tm-item-gn'    },
        { panelId: 'history-panel',        dotId: 'tm-dot-hist',  itemId: 'tm-item-hist'  },
        { panelId: 'whatif-panel',         dotId: 'tm-dot-wif',   itemId: 'tm-item-wif'   },
        { panelId: 'spof-panel',           dotId: 'tm-dot-spof',  itemId: 'tm-item-spof'  },
        { panelId: 'corr-heatmap-panel', dotId: 'tm-dot-corr', itemId: 'tm-item-corr'  },
        { panelId: 'climate-panel',      dotId: 'tm-dot-climate', itemId: 'tm-item-climate' },
        { panelId: 'llm-intel-panel',    dotId: 'tm-dot-llm',     itemId: 'tm-item-llm'     },
        { panelId: 'sensor-watchpane',   dotId: 'tm-dot-wp',      itemId: 'tm-item-wp'      },
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

    // Close overlay detail panels when clicking outside (panel itself or trigger are safe)
    document.addEventListener('click', e => {
        const t = e.target;

        // Domain drilldown: trigger = #hud-domains-wrap; panel = #domain-drilldown-panel
        const ddPanel = document.getElementById('domain-drilldown-panel');
        if (ddPanel && ddPanel.style.display === 'block'
            && !t.closest('#domain-drilldown-panel')
            && !t.closest('#hud-domains-wrap')) {
            if (typeof window.toggleDrilldown === 'function') window.toggleDrilldown();
        }

        // Scenario detail: trigger = .sc-card; panel = #scenario-detail-panel
        const scPanel = document.getElementById('scenario-detail-panel');
        if (scPanel && scPanel.style.display !== 'none'
            && !t.closest('#scenario-detail-panel')
            && !t.closest('.sc-card')) {
            if (typeof window._closeScenarioDetail === 'function') window._closeScenarioDetail();
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
        if (iEl) iEl.textContent = p8.isr ? _t('unit.aircraft', {n: p8.isr.count || 0}) : '—';
        if (aEl) aEl.textContent = p8.ais ? _t('unit.vessels', {n: p8.ais.dark_gaps || 0}) : '—';

        // ── v9: Survival HUD (Check-Host) ──────────────────────────────────────
        const survEl    = document.getElementById('hud-survival');
        const survIcon  = document.getElementById('hud-survival-icon');
        const survNodes = document.getElementById('hud-survival-nodes');
        const ch = p8.check_host || {};
        const tg = p8.telegram_mirror || {};   // defined here — before the detail code further below
        const chStatus = ch.status || 'UNKNOWN';
        // ADR-V2-006 A-2: prefer country_success_rate; fall back to legacy theater_success_rate.
        const chRate   = ch.country_success_rate ?? ch.theater_success_rate;
        if (survEl) {
            const COLOR_MAP = { OK: '#00ff88', PARTIAL: '#ffaa00', BLACKOUT: '#ff2200', UNKNOWN: '#555' };
            let survLabel = chStatus + (chRate !== null && chRate !== undefined ? ` (${Math.round(chRate * 100)}%)` : '');
            if (ch.asphyxiation) survLabel += ' ⚠ASP';
            survEl.textContent  = survLabel;
            survEl.style.color  = ch.asphyxiation ? '#ff8800' : (COLOR_MAP[chStatus] || '#aaa');
            survEl.title        = ch.asphyxiation ? _t('tooltip.cdn_asphyxiation') : '';
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
        if (mskAlert) mskAlert.style.display = mskNow ? 'inline-flex' : 'none';
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
                    <div style="color:#aaa;font-size:10px;margin-top:2px;">${esc(msk.reason || '')}</div>`;
            } else {
                mskEl.style.display = 'none';
            }
        }

        // ── v9: Telegram Mirror quick stat ────────────────────────────────────
        const tgEl = document.getElementById('ev-telegram-intent');
        if (tgEl) {
            if (tg.has_intent) {
                tgEl.textContent = _t('tg.hud.intent', {n: (tg.active_channels || []).length});
                tgEl.style.color = '#ff66cc';
            } else if (tg.status === 'TARGETS_FOUND') {
                tgEl.textContent = _t('tg.hud.targets_found');
                tgEl.style.color = '#ffaa00';
            } else {
                tgEl.textContent = _t('tg.hud.clear');
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

        // ev-llm-intel (chain panel — LLM confirmed intel count for this theater)
        const llmIntelEl = document.getElementById('ev-llm-intel');
        if (llmIntelEl) {
            const curTheater = resolveChainTargetCountry(strat);
            const active = _llmItems.filter(i =>
                (i.status === 'auto_confirmed' || i.status === 'confirmed') &&
                (!curTheater || i.theater === curTheater)
            );
            const reviewNeeded = _llmItems.filter(i => i.status === 'review_needed' && (!curTheater || i.theater === curTheater));
            if (reviewNeeded.length > 0) {
                llmIntelEl.textContent = `⚠ ${reviewNeeded.length} ${_t('chain.llm_intel.review')}`;
                llmIntelEl.style.color = '#ff8800';
                llmIntelEl.dataset.tooltip = reviewNeeded.map(i => esc(i.headline)).join('\n');
            } else if (active.length > 0) {
                llmIntelEl.textContent = `● ${active.length} ${_t('chain.llm_intel.active')}`;
                llmIntelEl.style.color = '#aa88ff';
                llmIntelEl.dataset.tooltip = active.map(i => esc(i.headline)).join('\n');
            } else {
                llmIntelEl.textContent = _t('chain.llm_intel.none');
                llmIntelEl.style.color = '#555';
                llmIntelEl.dataset.tooltip = '';
            }
        }

        // Async: fetch sequence event list and render
        const theater = resolveChainTargetCountry(strat);
        if (!theater) return;
        fetch(`/api/sequence_chain?country=${encodeURIComponent(theater)}`)
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
                events.forEach((ev) => {
                    const color  = EVENT_COLORS[ev.type] || '#888';
                    const label  = EVENT_LABELS[ev.type] || ev.type;
                    const dt     = new Date(ev.ts * 1000);
                    const _lang  = (localStorage.getItem('ddos_radar_lang') || 'en') === 'ja' ? 'ja-JP' : 'en-US';
                    const timeStr = dt.toLocaleTimeString(_lang, {hour:'2-digit', minute:'2-digit'});
                    // Single-line compact row: dot + label + time inline (Phase A2)
                    html += `<div class="chain-event" data-chain-type="${ev.type}">
                        <div class="chain-dot chain-dot-${ev.type}" style="background:${color};"></div>
                        <div class="chain-text">
                            <span class="chain-type" style="color:${color};">${label}</span>
                            <span class="chain-time">${timeStr}</span>
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
        const showMap  = false;
        if (mapPanel) mapPanel.style.display = 'none';
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
        { id: 'weather-brief-panel',  ph: 'lsb-ph-wx'             },
        { id: 'gn-panel',            ph: 'lsb-ph-gn'             },
        { id: 'tg-sigint-panel',      ph: 'lsb-ph-tg'             },
        { id: 'history-panel',        ph: 'lsb-ph-hist'           },
        { id: 'corr-heatmap-panel',  ph: 'lsb-ph-corr'           },
        { id: 'climate-panel',       ph: 'lsb-ph-climate'        },
        { id: 'llm-intel-panel',     ph: 'lsb-ph-llm'            },
        // Floating-only panels (no sidebar placeholder)
        { id: 'whatif-panel',        ph: null                     },
        { id: 'spof-panel',         ph: null                     },
        { id: 'sensor-watchpane',   ph: null                     },
    ];

    // Remembered order of panels within each sidebar (panel IDs, top→bottom)
    let _sidebarOrder = {
        'sidebar':      ['target-panel', 'dashboard-panel', 'chain-panel'],
        'left-sidebar': ['climate-panel', 'llm-intel-panel', 'weather-brief-panel', 'gn-panel', 'tg-sigint-panel', 'history-panel', 'corr-heatmap-panel']
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

    // Lightweight floating-only panel: drag + minimize + close, no dock/sidebar support
    function setupFloatingOnlyPanel(panelId) {
        const panel = document.getElementById(panelId);
        if (!panel) return;
        const handle = panel.querySelector('.drag-handle');
        const toggleBtn = panel.querySelector('.toggle-btn');
        const content = panel.querySelector('.panel-content');

        if (toggleBtn && content) {
            toggleBtn.onmousedown = function(e) {
                e.stopPropagation();
                if (content.style.display === 'none') {
                    content.style.display = 'flex'; toggleBtn.innerText = '−'; toggleBtn.classList.remove('active-btn');
                } else {
                    content.style.display = 'none'; toggleBtn.innerText = '＋'; toggleBtn.classList.add('active-btn');
                }
                saveLocalState();
            };
        }

        let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

        panel.onmousedown = function() {
            if (panel.classList.contains('floating')) {
                document.querySelectorAll('.draggable-panel.floating').forEach(el => el.classList.remove('active'));
                panel.classList.add('active');
            }
        };

        if (handle) {
            handle.onmousedown = function(e) {
                if (e.target.closest('.icon-btn')) return;
                e.preventDefault();
                document.querySelectorAll('.draggable-panel.floating').forEach(el => el.classList.remove('active'));
                panel.classList.add('active');
                pos3 = e.clientX; pos4 = e.clientY;
                const onMove = function(me) {
                    me.preventDefault();
                    pos1 = pos3 - me.clientX; pos2 = pos4 - me.clientY; pos3 = me.clientX; pos4 = me.clientY;
                    panel.style.top = (panel.offsetTop - pos2) + 'px'; panel.style.left = (panel.offsetLeft - pos1) + 'px';
                };
                const onUp = function() { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); saveLocalState(); };
                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            };
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
                document.addEventListener('mousemove', elementDrag);
                document.addEventListener('mouseup', closeDragElement);
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
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                    undockAndFloat(startE, me);
                    return;
                }
                currentInsertBefore = getInsertTarget(me.clientY);
                if (indicator.parentElement) indicator.parentElement.removeChild(indicator);
                sb.insertBefore(indicator, currentInsertBefore);
            }

            function onUp() {
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
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

            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
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
            document.addEventListener('mousemove', elementDrag);
            document.addEventListener('mouseup', closeDragElement);
        };

        function elementDrag(e) {
            e.preventDefault(); pos1 = pos3 - e.clientX; pos2 = pos4 - e.clientY; pos3 = e.clientX; pos4 = e.clientY;
            panel.style.top = (panel.offsetTop - pos2) + "px"; panel.style.left = (panel.offsetLeft - pos1) + "px";
        }

        function closeDragElement(e) {
            document.removeEventListener('mousemove', elementDrag);
            document.removeEventListener('mouseup', closeDragElement);
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
    // Dockable panels (constant monitoring / always-visible)
    setupDockablePanel('target-panel',        'target-placeholder',    340);
    setupDockablePanel('dashboard-panel',     'dashboard-placeholder', 400);
    setupDockablePanel('chain-panel',         'chain-placeholder',     300);
    setupDockablePanel('weather-brief-panel', 'lsb-ph-wx',             420);
    // Floating-only panels (on-demand tools)
    setupFloatingOnlyPanel('gn-panel');
    setupFloatingOnlyPanel('tg-sigint-panel');
    setupFloatingOnlyPanel('history-panel');
    setupFloatingOnlyPanel('whatif-panel');
    setupFloatingOnlyPanel('spof-panel');
    // 'tradecraft-panel' is registered inside createFloatingPanel() in
    // tradecraft.js boot(), so it is intentionally NOT listed here.
    setupDockablePanel('corr-heatmap-panel', 'lsb-ph-corr',           340);
    setupDockablePanel('climate-panel',      'lsb-ph-climate',        380);
    setupDockablePanel('llm-intel-panel',   'lsb-ph-llm',            440);
    updateSidebarVisibility();

    const map = L.map('map', {
        zoomControl: false,
        zoomSnap: 0.1,
        zoomDelta: 0.5,
        maxBoundsViscosity: 1.0,
        worldCopyJump: false,
        maxBounds: [[-85.0511, -180], [85.0511, 180]],
    }).setView([20.0, 10.0], 3);
    window._radarMap = map;
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
    const coordLinkLayer    = L.layerGroup().addTo(map);  // Constellation links
    const participantLayer  = L.layerGroup().addTo(map);  // Scenario participant role markers

    const overlayLayers = {
        "Participants":      participantLayer,
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
        "Coordination":      coordLinkLayer,
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
        const points = []; const numPoints = 20;
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
        // Scope is now scenario-driven: participants come from the focused
        // scenario's strategic_alert payload, not from DOM toggles.
        const strat = (latestData || {}).strategic_alert || {};
        const coreVal = resolveChainTargetCountry(strat);
        const advSet  = new Set(strat.adversary_states || []);
        const partSet = new Set(strat.active_theaters || []);
        if (coreVal) partSet.add(coreVal);

        THEATERS.forEach(t => {
            if (t.lat == null || t.lng == null) return;
            let color, radius, fillOpacity, weight, opacity;
            if (t.code === coreVal)        { color = '#00ffff'; radius = 7; fillOpacity = 0.9; weight = 2;   opacity = 1.0; }
            else if (advSet.has(t.code))   { color = '#ff5555'; radius = 5; fillOpacity = 0.8; weight = 1.5; opacity = 1.0; }
            else if (partSet.has(t.code))  { color = '#ffaa00'; radius = 5; fillOpacity = 0.8; weight = 1.5; opacity = 1.0; }
            else                           { color = '#334455'; radius = 2; fillOpacity = 0.5; weight = 0;   opacity = 0.5; }

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
    let _activeBloc = '';  // retained for region pill state (Pins tab removed)

    function buildTheaterUI() {
        // Strategy / Actors / Pins tabs were removed — scope is now driven by
        // the focused scenario's participants (see Scenario Manager admin tab).
        _reapplyFilters = () => {};
        _syncPillsVisual = () => {};
    }

    function renderQuickToggles() {
        // Quick Pins grid was removed. The active country set is derived from
        // the focused scenario's participants as published in strategic_alert.
        const displayGrid = document.getElementById('display-checkboxes');
        if (!displayGrid) return;
        const strat = (latestData || {}).strategic_alert || {};
        const active = new Set(strat.active_theaters || []);
        const _coreVal = resolveChainTargetCountry(strat);
        if (_coreVal) active.add(_coreVal);
        displayGrid.innerHTML = '';
        Array.from(active).forEach(code => {
            const t = THEATERS.find(theater => theater.code === code);
            if (!t) return;
            const lbl = document.createElement('label');
            lbl.innerHTML = `<input type="checkbox" class="check-display" value="${code}" checked disabled> ${t.name}`;
            displayGrid.appendChild(lbl);
        });
        if (displayGrid.innerHTML === '') {
            displayGrid.innerHTML = `<div style="color:#888; font-size:11px;">${_t('dash.no_active_pins')}</div>`;
        }
    }

    function updateUIConsistency() {
        // No-op: Strategy table was removed.
    }

    function getCurrentConfig() {
        // Scope is now derived from the focused scenario server-side; the URL
        // only needs to carry the focus id. Preserve the shape for legacy callers.
        const strat = (latestData || {}).strategic_alert || {};
        const active = new Set(strat.active_theaters || []);
        const _coreVal = resolveChainTargetCountry(strat);
        if (_coreVal) active.add(_coreVal);
        return {
            core: _coreVal,
            correlates: [],
            adversaries: [],
            displays: Array.from(active)
        };
    }

    function checkPendingState() {
        // Pending-sync state is only driven by explicit SYNC presses now; the
        // scope picker UI was removed. Keep the function for callers but treat
        // state as always "in sync" after the most recent fetch.
        const needsApiSync = false;

        const syncBtnTop = document.getElementById('btn-sync-top');
        const syncBtnSide = document.getElementById('btn-sync-side');
        const updateTimeEl = document.getElementById('update-time');
        if (!syncBtnTop || !syncBtnSide || !updateTimeEl) return;

        if (needsApiSync) {
            updateTimeEl.innerHTML = `<span style="color:#ffaa00;">${_t('dash.changes_pending')}</span>`;
            syncBtnTop.classList.add("pending");
            syncBtnSide.classList.add("pending");
        } else {
            updateTimeEl.innerText = lastSyncedTimeText;
            syncBtnTop.classList.remove("pending");
            syncBtnSide.classList.remove("pending");
            
            if (latestData) renderTelemetry(latestData);
        }
    }

    // WS state — declared before fetchDDoSData so it can reference them
    let _wsConnected = false;
    let _wsSocket = null;
    let _wsSubscribedTheater = '';
    let _lastSyncTime = 0;
    const _POLL_INTERVAL_MS = 15 * 60 * 1000; // 15 min

    function forceDataSync() { fetchDDoSData(true); }
    window.forceDataSync = forceDataSync;

    // ── NP7 disclaimer banner (Phase 1.4 P2) ─────────────────────────────
    // Fetches the canonical final-judgment disclaimer text from the v2
    // conclusions envelope and renders it into #np7-banner-text. Falls back
    // to the i18n key (already in the DOM) if v2 is degraded so NP7 is
    // satisfied even when v2 is unavailable. One-shot per session — the
    // disclaimer is global (config.V2_NP7_DISCLAIMER), not per-scenario, so
    // no need to re-fetch on focus changes.
    let _np7BannerLoaded = false;
    async function _refreshNp7Banner(scenarioId) {
        if (_np7BannerLoaded || !scenarioId) return;
        try {
            const resp = await fetch(`/api/v2/scenarios/${encodeURIComponent(scenarioId)}/conclusions`);
            if (!resp.ok) return;  // 503 (v2 disabled) / 404 (no scenario) → keep fallback text
            const env = await resp.json();
            const text = env && env.final_judgment_disclaimer;
            if (typeof text !== 'string' || !text) return;
            const node = document.getElementById('np7-banner-text');
            if (node) {
                node.textContent = text;  // textContent — no XSS path even if server text changes
                _np7BannerLoaded = true;
            }
        } catch (e) {
            // Silent — NP7 fallback in DOM is the safety net.
        }
    }

    // ── Conclusion Cards Layer 1 (Phase 3 — v2 conclusions envelope) ─────
    // Renders the 5 ConclusionType buckets (THREAT_LEVEL, TREND, PER_DOMAIN,
    // ANOMALY, ATTACK_MODE) from the v2 envelope into #cc-grid. Hidden when
    // v2 is degraded (503/404) or when the envelope contains no conclusions.
    // See docs/design/v2-ui.md §4. Drill-down (Layer 2) is wired in a
    // follow-up task — the button currently no-ops with a placeholder.
    let _ccLastFocus = null;
    let _ccInflightFocus = null;
    let _ccAbort = null;
    // HUD↔Cards consistency: cache the latest v2 envelope per focused scenario so
    // _hudV2OverlayStrat() can override v1 strategic_alert.threat_level/domains
    // with the same values the cards display. Stale entries (>180s) fall through
    // to the v1 values per NP3 (fault tolerance: HUD must never go blank).
    const _ccEnvelopeCache = {};
    const _CC_ENVELOPE_TTL_MS = 180_000;
    let _ccExportInflight = false;
    const _CC_TYPE_ORDER = ['threat_level', 'trend', 'per_domain', 'anomaly', 'attack_mode'];

    // Phase 3 — Markdown export. Fetches the .md endpoint (JWT auto-injected
    // by the global fetch override) and triggers a browser download. Kept on
    // the toolbar rather than inside individual cards because the export is
    // per-scenario (all 5 conclusions in one file), not per-conclusion.
    async function _ccExportMarkdown(scenarioId) {
        if (!scenarioId || _ccExportInflight) return;
        _ccExportInflight = true;
        const btn = document.getElementById('cc-export-md');
        if (btn) btn.disabled = true;
        try {
            const resp = await fetch(
                `/api/v2/scenarios/${encodeURIComponent(scenarioId)}/conclusions.md`,
            );
            if (!resp.ok) {
                if (window.console) console.warn('[ConclusionCards] export failed', resp.status);
                return;
            }
            const text = await resp.text();
            const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${scenarioId}-conclusions.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            // Revoke shortly after the click so the browser has time to start the download.
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (e) {
            if (window.console) console.warn('[ConclusionCards] export error', e);
        } finally {
            _ccExportInflight = false;
            if (btn && _ccLastFocus) btn.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        const btn = document.getElementById('cc-export-md');
        if (!btn) return;
        btn.addEventListener('click', () => {
            if (_ccLastFocus) _ccExportMarkdown(_ccLastFocus);
        });
    });

    function _ccTitleKey(type) { return `cc.title.${type}`; }
    function _ccUnavailableText(reason) {
        if (!reason) return _t('cc.label.unavailable');
        const k = `cc.label.${reason}`;
        const tx = _t(k);
        return (tx && tx !== k) ? tx : reason.toUpperCase();
    }
    function _ccConfidencePct(c) {
        const v = (typeof c === 'number' && isFinite(c)) ? Math.max(0, Math.min(1, c)) : 0;
        return Math.round(v * 100);
    }
    function _ccParseKvState(state) {
        // "short_term=STABLE;medium_term=STABLE;long_term=INSUFFICIENT_DATA"
        const out = {};
        if (typeof state !== 'string') return out;
        state.split(';').forEach((pair) => {
            const [k, v] = pair.split('=');
            if (k && v) out[k.trim()] = v.trim();
        });
        return out;
    }
    function _ccTrendStateClass(label) {
        if (!label) return 'cc-trend-insufficient_data';
        return 'cc-trend-' + String(label).toLowerCase();
    }
    function _ccDomainStatusClass(label) {
        const u = String(label || '').toUpperCase();
        if (u === 'ACTIVE') return 'cc-status-active';
        if (u === 'ELEVATED') return 'cc-status-elevated';
        if (u === 'STABLE') return 'cc-status-stable';
        return 'cc-status-insufficient';
    }

    function _ccRenderCard(c) {
        const type = c.conclusion_type;
        const titleKey = _ccTitleKey(type);
        const confPct = _ccConfidencePct(c.confidence);
        const isAvail = c.conclusion_unavailable_reason == null && c.state != null;
        const card = document.createElement('div');
        card.className = 'cc-card cc-card-' + type;
        if (!isAvail) card.classList.add('cc-unavailable');

        // Header
        const titleEl = document.createElement('div');
        titleEl.className = 'cc-card-title';
        titleEl.setAttribute('data-i18n', titleKey);
        titleEl.textContent = _t(titleKey);
        card.appendChild(titleEl);

        // Body — varies by type
        const body = document.createElement('div');
        body.className = 'cc-card-body';
        if (!isAvail) {
            const stateEl = document.createElement('div');
            stateEl.className = 'cc-card-state';
            stateEl.textContent = _ccUnavailableText(c.conclusion_unavailable_reason);
            body.appendChild(stateEl);
            const meta = document.createElement('div');
            meta.className = 'cc-card-meta';
            const detail = (c.metadata && c.metadata.reason_detail) || '';
            if (detail) meta.textContent = detail;
            body.appendChild(meta);
        } else if (type === 'threat_level') {
            const tl = parseInt(c.state, 10);
            const stateEl = document.createElement('div');
            stateEl.className = 'cc-card-state cc-tl-' + (isFinite(tl) ? tl : 'unk');
            stateEl.textContent = _t('cc.tl.prefix') + ' ' + (isFinite(tl) ? tl : c.state);
            body.appendChild(stateEl);
            const md = c.metadata || {};
            const meta = document.createElement('div');
            meta.className = 'cc-card-meta';
            const score = (typeof md.score === 'number') ? md.score.toFixed(2) : '—';
            const ad = (typeof md.active_domain_count === 'number') ? md.active_domain_count : '—';
            meta.innerHTML = `<div class="cc-row"><span>score</span><span>${_escHtml(score)}</span></div>` +
                             `<div class="cc-row"><span>active domains</span><span>${_escHtml(String(ad))}</span></div>`;
            body.appendChild(meta);
        } else if (type === 'trend') {
            const horizons = _ccParseKvState(c.state);
            const labels = { short_term: 'cc.horizon.short', medium_term: 'cc.horizon.medium', long_term: 'cc.horizon.long' };
            ['short_term', 'medium_term', 'long_term'].forEach((h) => {
                const v = horizons[h] || 'INSUFFICIENT_DATA';
                const row = document.createElement('div');
                row.className = 'cc-horizon-row';
                row.innerHTML = `<span class="cc-horizon-label">${_escHtml(_t(labels[h]))}</span>` +
                                `<span class="cc-horizon-state ${_ccTrendStateClass(v)}">${_escHtml(v)}</span>`;
                body.appendChild(row);
            });
        } else if (type === 'per_domain') {
            const doms = _ccParseKvState(c.state);
            const md = (c.metadata && c.metadata.domain_scores) || {};
            ['cyber', 'physical', 'info'].forEach((d) => {
                const status = doms[d] || 'INSUFFICIENT_SIGNAL';
                const score = (typeof md[d] === 'number') ? md[d].toFixed(2) : '—';
                if (String(status).toUpperCase() === 'DEGRADED') card.classList.add('cc-degraded');
                const row = document.createElement('div');
                row.className = 'cc-domain-row';
                row.innerHTML = `<span class="cc-domain-name">${_escHtml(_t('cc.domain.' + d))}</span>` +
                                `<span class="cc-domain-status ${_ccDomainStatusClass(status)}">${_escHtml(status)}</span>` +
                                `<span class="cc-domain-name">${_escHtml(score)}</span>`;
                body.appendChild(row);
            });
        } else if (type === 'anomaly') {
            const text = String(c.state || '');
            const md = c.metadata || {};
            const ranked = Array.isArray(md.ranked_anomalies) ? md.ranked_anomalies : null;
            const stateEl = document.createElement('div');
            stateEl.className = 'cc-anomaly-text';
            stateEl.textContent = text;
            body.appendChild(stateEl);
            if (ranked && ranked.length > 1) {
                const meta = document.createElement('div');
                meta.className = 'cc-card-meta';
                const more = ranked.length - 1;
                meta.textContent = `+${more}`;
                body.appendChild(meta);
            }
        } else if (type === 'attack_mode') {
            const stateEl = document.createElement('div');
            stateEl.className = 'cc-card-state';
            stateEl.textContent = String(c.state);
            body.appendChild(stateEl);
            const md = c.metadata || {};
            const ranked = Array.isArray(md.ranked_modes) ? md.ranked_modes.slice(1, 3) : [];
            if (ranked.length) {
                const meta = document.createElement('div');
                meta.className = 'cc-card-meta';
                meta.innerHTML = ranked.map((m) => {
                    const nm = (m && m.mode) || '';
                    const cf = (m && typeof m.confidence === 'number') ? m.confidence.toFixed(2) : '—';
                    return `<div class="cc-row"><span>${_escHtml(nm)}</span><span>${_escHtml(cf)}</span></div>`;
                }).join('');
                body.appendChild(meta);
            }
            if (typeof c.confidence === 'number' && c.confidence < 0.6) {
                card.classList.add('cc-tentative');
            }
        }
        card.appendChild(body);

        // Footer — confidence bar + drill button
        const footer = document.createElement('div');
        footer.className = 'cc-card-footer';
        const conf = document.createElement('div');
        conf.className = 'cc-confidence';
        conf.innerHTML = `<span>${_escHtml(_t('cc.label.confidence'))}</span>` +
                         `<span class="cc-confidence-bar"><span class="cc-confidence-bar-fill" style="width:${confPct}%"></span></span>` +
                         `<span>${confPct}%</span>`;
        footer.appendChild(conf);

        // Tentative badge for low-confidence attack modes
        if (type === 'attack_mode' && isAvail && typeof c.confidence === 'number' && c.confidence < 0.6) {
            const badge = document.createElement('span');
            badge.className = 'cc-badge cc-badge-warn';
            badge.setAttribute('data-i18n', 'cc.label.tentative');
            badge.textContent = _t('cc.label.tentative');
            footer.appendChild(badge);
        }

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'cc-drill-btn';
        btn.setAttribute('data-i18n', 'cc.btn.drill');
        btn.setAttribute('data-i18n-tip', 'cc.btn.drill_tooltip');
        btn.title = _t('cc.btn.drill_tooltip');
        btn.textContent = _t('cc.btn.drill');
        btn.disabled = !c.id;  // Unavailable conclusions have no id → no audit trace
        btn.addEventListener('click', () => {
            if (c.id) _ccOpenDrillModal(c);
        });
        footer.appendChild(btn);
        card.appendChild(footer);
        return card;
    }

    /**
     * Return the cached v2 byType envelope for `focusedId` if it is fresh,
     * else null. Single source of truth for the cache+TTL gate so the HUD
     * overlay and the HUD click handler agree on freshness.
     *
     * @param {string|null|undefined} focusedId
     * @returns {Object<string,object>|null}
     */
    function _hudFreshEnvelopeByType(focusedId) {
        if (!focusedId) return null;
        const entry = _ccEnvelopeCache[focusedId];
        if (!entry) return null;
        if (Date.now() - entry.ts > _CC_ENVELOPE_TTL_MS) return null;
        return entry.byType || null;
    }

    /**
     * TTL/cache gate around HudV2Overlay.applyOverlay. Returns the original
     * `strat` when no fresh envelope is cached for the focused scenario —
     * preserving NP3 (HUD must keep working when v2 is down).
     *
     * Pure merge logic lives in `hud_v2_overlay.js` (window.HudV2Overlay),
     * so it can be unit-tested under Node without a browser. This wrapper
     * only owns the cache key + TTL.
     *
     * @param {object|null|undefined} strat — v1 data.strategic_alert
     * @param {string|null|undefined} focusedId — focused scenario id
     * @returns {object|null|undefined} new strat (or original on no-op)
     */
    function _hudV2OverlayStrat(strat, focusedId) {
        if (!strat) return strat;
        const byType = _hudFreshEnvelopeByType(focusedId);
        if (!byType) return strat;
        const overlay = (window.HudV2Overlay && window.HudV2Overlay.applyOverlay) || null;
        if (!overlay) return strat;  // Defensive: hud_v2_overlay.js failed to load
        return overlay(strat, byType);
    }

    function _ccRenderEmpty(grid) {
        grid.innerHTML = '';
        const empty = document.createElement('div');
        empty.className = 'cc-card cc-unavailable';
        empty.style.gridColumn = '1 / -1';
        const t = document.createElement('div');
        t.className = 'cc-card-meta';
        t.textContent = _t('cc.empty.waiting');
        empty.appendChild(t);
        grid.appendChild(empty);
    }

    async function _refreshConclusionCards(scenarioId) {
        const bar = document.getElementById('conclusion-cards-bar');
        const grid = document.getElementById('cc-grid');
        if (!bar || !grid) return;

        if (!scenarioId) {
            bar.classList.remove('cc-visible');
            const btn = document.getElementById('cc-export-md');
            if (btn) btn.disabled = true;
            return;
        }

        // Invalidate immediately on focus change so the user sees the
        // grid clear while the new fetch is in flight.
        const focusChanged = _ccLastFocus !== scenarioId;
        if (focusChanged) {
            _ccLastFocus = scenarioId;
            grid.innerHTML = '';
        }

        // Skip ONLY when a fetch for this same focus is already running.
        // On focus change we abort the stale fetch and start a fresh one
        // so the bar updates immediately without waiting for the next poll.
        if (_ccInflightFocus === scenarioId) return;
        if (_ccAbort) {
            try { _ccAbort.abort(); } catch (_) { /* AbortController unsupported → ignore */ }
        }
        const ac = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        _ccAbort = ac;
        _ccInflightFocus = scenarioId;

        try {
            const resp = await fetch(
                `/api/v2/scenarios/${encodeURIComponent(scenarioId)}/conclusions`,
                ac ? { signal: ac.signal } : undefined,
            );
            // Stale-response guard — focus may have changed again while awaiting
            if (_ccLastFocus !== scenarioId) return;
            if (resp.status === 503 || resp.status === 404) {
                bar.classList.remove('cc-visible');  // Graceful hide when v2 is degraded
                const btn = document.getElementById('cc-export-md');
                if (btn) btn.disabled = true;
                return;
            }
            if (!resp.ok) return;  // Keep previous render on transient errors
            const env = await resp.json();
            if (_ccLastFocus !== scenarioId) return;  // Re-check after JSON parse
            const list = Array.isArray(env && env.conclusions) ? env.conclusions : [];
            if (list.length === 0) {
                bar.classList.add('cc-visible');
                _ccRenderEmpty(grid);
                const btn = document.getElementById('cc-export-md');
                if (btn) btn.disabled = true;  // Nothing to export yet.
                return;
            }
            const byType = {};
            list.forEach((c) => { if (c && c.conclusion_type) byType[c.conclusion_type] = c; });
            // Stash the just-fetched envelope so the HUD can pull TL + per_domain
            // from the same source the cards render. Single point of truth.
            _ccEnvelopeCache[scenarioId] = { ts: Date.now(), byType };

            grid.innerHTML = '';
            _CC_TYPE_ORDER.forEach((type) => {
                const c = byType[type];
                if (!c) {
                    // Synthesize an unavailable placeholder so the slot doesn't collapse
                    grid.appendChild(_ccRenderCard({
                        conclusion_type: type,
                        state: null,
                        confidence: 0,
                        conclusion_unavailable_reason: 'insufficient_data',
                        metadata: { reason_detail: '' },
                        id: null,
                    }));
                    return;
                }
                grid.appendChild(_ccRenderCard(c));
            });
            bar.classList.add('cc-visible');
            // Enable export now that at least one real conclusion is rendered.
            const hasReal = list.some((c) => c && c.id);
            const btn = document.getElementById('cc-export-md');
            if (btn) btn.disabled = !hasReal;
        } catch (e) {
            if (e && e.name === 'AbortError') return;  // Superseded by a newer focus — expected
            // Network error — keep prior render. Don't surface a noisy toast;
            // the next poll will retry. Guarded console keeps test output quiet.
            if (window.console) console.debug('[ConclusionCards] fetch error', e);
        } finally {
            if (_ccInflightFocus === scenarioId) _ccInflightFocus = null;
            if (_ccAbort === ac) _ccAbort = null;
        }
    }

    // ── Conclusion Drill-down Modal (Layer 2 — audit_trace) ─────────────
    // Renders the full derivation path for a single conclusion: formula_ref,
    // threshold_ref, calibration_status (with low-N warning per NP5+8),
    // source_urls, metadata, and the resolved LLM prompt (collapsible per
    // R-UI-2, default folded for long prompts). Backed by GET
    // /api/v2/conclusions/<id>/audit_trace.
    let _ccDrillAbort = null;
    let _ccDrillReturnFocus = null;
    let _ccDrillKeyHandler = null;

    function _ccFmtTimestamp(v) {
        if (v == null || v === '') return '—';
        // audit_trace stores observed_at as a unix epoch (seconds, float).
        const n = (typeof v === 'number') ? v : parseFloat(v);
        if (isFinite(n) && n > 0) {
            try { return new Date(n * 1000).toISOString(); } catch (_) { /* fallthrough */ }
        }
        return String(v);
    }

    function _ccDrillRow(key, val) {
        const row = document.createElement('div');
        row.className = 'dm-row';
        const k = document.createElement('div');
        k.className = 'dm-key';
        k.textContent = key;
        const v = document.createElement('div');
        v.className = 'dm-val';
        v.textContent = (val == null || val === '') ? '—' : String(val);
        row.appendChild(k);
        row.appendChild(v);
        return row;
    }

    function _ccDrillSection(titleKey, bodyEl, isEmpty) {
        const sec = document.createElement('section');
        sec.className = 'dm-section';
        const title = document.createElement('div');
        title.className = 'dm-section-title';
        title.setAttribute('data-i18n', titleKey);
        title.textContent = _t(titleKey);
        sec.appendChild(title);
        const body = document.createElement('div');
        body.className = 'dm-section-body' + (isEmpty ? ' dm-empty' : '');
        body.appendChild(bodyEl);
        sec.appendChild(body);
        return sec;
    }

    function _ccDrillRenderHeader(trace) {
        const wrap = document.createElement('div');
        const typeRow = _ccDrillRow(_t(_ccTitleKey(trace.conclusion_type) || 'cc.title.threat_level'),
                                     trace.conclusion_type || '—');
        wrap.appendChild(typeRow);
        wrap.appendChild(_ccDrillRow(_t('drill_modal.label.scenario'), trace.scenario_id || '—'));
        wrap.appendChild(_ccDrillRow(_t('drill_modal.label.observed_at'), _ccFmtTimestamp(trace.observed_at)));
        wrap.appendChild(_ccDrillRow(_t('drill_modal.label.conclusion_id'), trace.conclusion_id || '—'));
        return wrap;
    }

    function _ccDrillRenderDisclaimer(trace) {
        const div = document.createElement('div');
        div.className = 'dm-disclaimer';
        div.textContent = trace.final_judgment_disclaimer || _t('cc.tip.np7');
        return div;
    }

    function _ccDrillRenderFormula(trace) {
        const div = document.createElement('div');
        div.className = 'dm-monospace';
        div.textContent = trace.formula_ref || _t('drill_modal.empty.formula');
        return div;
    }

    function _ccDrillRenderKvTable(obj, emptyKey, excludeKeys) {
        const wrap = document.createElement('div');
        const skip = new Set(Array.isArray(excludeKeys) ? excludeKeys : []);
        const keys = obj ? Object.keys(obj).filter((k) => !skip.has(k)) : [];
        if (keys.length === 0) {
            wrap.textContent = _t(emptyKey);
            return wrap;
        }
        keys.forEach((k) => {
            const v = obj[k];
            const display = (v != null && typeof v === 'object') ? JSON.stringify(v) : v;
            wrap.appendChild(_ccDrillRow(k, display));
        });
        return wrap;
    }

    /**
     * Render the rationale_matrix as a structured table (mirrors v1 evidence
     * panel's per-sensor breakdown). NP6: every contributing signal is
     * surfaced with sensor / domain / country / contribution / formula /
     * evidence link, sorted server-side by |final_contribution| descending.
     *
     * Returns an empty container with `drill_modal.empty.rationale_matrix`
     * text when no entries exist (the section is then marked empty by the
     * caller and rendered collapsed).
     */
    function _ccDrillRenderRationaleMatrix(trace) {
        const wrap = document.createElement('div');
        const rm = (trace && trace.metadata && trace.metadata.rationale_matrix) || [];
        if (!Array.isArray(rm) || rm.length === 0) {
            wrap.textContent = _t('drill_modal.empty.rationale_matrix');
            return wrap;
        }
        const table = document.createElement('table');
        table.className = 'dm-rationale-table';
        const thead = document.createElement('thead');
        const headRow = document.createElement('tr');
        ['sensor', 'domain', 'country', 'contribution', 'formula', 'evidence'].forEach((c) => {
            const th = document.createElement('th');
            th.setAttribute('data-i18n', 'drill_modal.rationale.col.' + c);
            th.textContent = _t('drill_modal.rationale.col.' + c);
            headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        const tbody = document.createElement('tbody');
        rm.forEach((row) => {
            const tr = document.createElement('tr');
            if (row && row.suppress_reason) tr.classList.add('dm-rationale-suppressed');

            const tdSensor = document.createElement('td');
            tdSensor.textContent = (row && row.sensor) || '';
            tr.appendChild(tdSensor);

            const tdDomain = document.createElement('td');
            tdDomain.className = 'dm-rationale-domain dm-rationale-domain-' + ((row && row.domain) || '');
            tdDomain.textContent = (row && row.domain) || '';
            tr.appendChild(tdDomain);

            const tdCountry = document.createElement('td');
            const cc = (row && row.contributing_country) || '';
            const role = (row && row.participant_role) || '';
            tdCountry.textContent = role ? `${cc} (${role})` : cc;
            tr.appendChild(tdCountry);

            const tdContrib = document.createElement('td');
            tdContrib.className = 'dm-rationale-num';
            const fc = (row && typeof row.final_contribution === 'number') ? row.final_contribution : null;
            tdContrib.textContent = (fc != null) ? fc.toFixed(3) : '—';
            tr.appendChild(tdContrib);

            const tdFormula = document.createElement('td');
            tdFormula.className = 'dm-rationale-formula';
            tdFormula.textContent = (row && row.formula_trace) || '';
            tr.appendChild(tdFormula);

            const tdEvidence = document.createElement('td');
            const url = row && row.evidence_url;
            if (url) {
                const a = document.createElement('a');
                a.href = url;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.textContent = '🔗';
                a.title = url;
                tdEvidence.appendChild(a);
            } else {
                tdEvidence.textContent = '—';
            }
            tr.appendChild(tdEvidence);

            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        wrap.appendChild(table);
        return wrap;
    }

    function _ccDrillRenderCalibration(trace) {
        const cs = trace.calibration_status || {};
        const wrap = document.createElement('div');
        const keys = Object.keys(cs);
        if (keys.length === 0) {
            wrap.textContent = _t('drill_modal.empty.calibration');
            return wrap;
        }
        // Surface canonical fields first when present, then fall back to raw dump
        const canonical = ['status', 'sample_size', 'last_updated'];
        const seen = new Set();
        canonical.forEach((k) => {
            if (k in cs) {
                const labelKey = k === 'status' ? 'drill_modal.calib.status'
                              : k === 'sample_size' ? 'drill_modal.calib.sample_size'
                              : 'drill_modal.calib.last_updated';
                const v = (k === 'last_updated') ? _ccFmtTimestamp(cs[k]) : cs[k];
                wrap.appendChild(_ccDrillRow(_t(labelKey), v));
                seen.add(k);
            }
        });
        keys.forEach((k) => {
            if (seen.has(k)) return;
            const v = cs[k];
            const display = (v != null && typeof v === 'object') ? JSON.stringify(v) : v;
            wrap.appendChild(_ccDrillRow(k, display));
        });
        // Low-N warning (NP5+8) — surface when sample_size present and small
        const n = parseFloat(cs.sample_size);
        if (isFinite(n) && n > 0 && n < 10) {
            const warn = document.createElement('div');
            warn.className = 'dm-warn';
            warn.setAttribute('role', 'status');
            warn.textContent = _t('drill_modal.calib.warn_low_n');
            wrap.appendChild(warn);
        }
        return wrap;
    }

    function _ccDrillRenderSources(trace) {
        const urls = Array.isArray(trace.source_urls) ? trace.source_urls : [];
        if (urls.length === 0) {
            const div = document.createElement('div');
            div.textContent = _t('drill_modal.empty.sources');
            return div;
        }
        const ul = document.createElement('ul');
        ul.className = 'dm-source-list';
        urls.forEach((u) => {
            const li = document.createElement('li');
            const a = document.createElement('a');
            // Only http(s) become clickable to avoid javascript: schemes from
            // metadata pollution. Anything else falls back to text.
            const safe = (typeof u === 'string') && /^https?:\/\//i.test(u);
            if (safe) {
                a.href = u;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                a.textContent = u;
                li.appendChild(a);
            } else {
                li.textContent = String(u);
            }
            ul.appendChild(li);
        });
        return ul;
    }

    function _ccDrillRenderLlmPrompt(trace) {
        const wrap = document.createElement('div');
        const lp = trace.llm_prompt;
        if (lp == null) {
            wrap.textContent = _t('drill_modal.llm.no_prompt');
            return wrap;
        }
        if (lp.missing) {
            wrap.appendChild(_ccDrillRow(_t('drill_modal.llm.sha256'), lp.sha256 || '—'));
            const note = document.createElement('div');
            note.className = 'dm-warn';
            note.textContent = _t('drill_modal.llm.missing');
            wrap.appendChild(note);
            return wrap;
        }
        wrap.appendChild(_ccDrillRow(_t('drill_modal.llm.model'),       lp.model));
        wrap.appendChild(_ccDrillRow(_t('drill_modal.llm.temperature'), lp.temperature));
        wrap.appendChild(_ccDrillRow(_t('drill_modal.llm.use_count'),   lp.use_count));
        wrap.appendChild(_ccDrillRow(_t('drill_modal.llm.first_seen'),  _ccFmtTimestamp(lp.first_seen_at)));
        wrap.appendChild(_ccDrillRow(_t('drill_modal.llm.last_seen'),   _ccFmtTimestamp(lp.last_seen_at)));
        wrap.appendChild(_ccDrillRow(_t('drill_modal.llm.sha256'),      lp.sha256 || '—'));
        const text = lp.prompt_text || '';
        if (text) {
            const toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'dm-collapse-toggle';
            toggle.textContent = _t('drill_modal.llm.expand');
            const content = document.createElement('div');
            content.className = 'dm-collapse-content';
            content.style.display = 'none';
            content.textContent = text;  // textContent — defeats any HTML payload
            toggle.addEventListener('click', () => {
                const open = content.style.display !== 'none';
                content.style.display = open ? 'none' : '';
                toggle.textContent = _t(open ? 'drill_modal.llm.expand' : 'drill_modal.llm.collapse');
            });
            wrap.appendChild(toggle);
            wrap.appendChild(content);
        }
        return wrap;
    }

    // Phase 3 — analyst feedback widget (ADR-V2-011). Renders the four-way
    // confusion-matrix labels, a free-text notes field, and the current
    // multi-analyst summary. Per v2-migration §11 the summary always shows
    // counts (never a single chosen verdict) so a lone analyst's label
    // cannot masquerade as consensus.
    const _CC_FEEDBACK_LABELS = [
        'TRUE_POSITIVE', 'FALSE_POSITIVE', 'TRUE_NEGATIVE', 'FALSE_NEGATIVE',
    ];

    function _ccFeedbackRenderSummary(summary) {
        const wrap = document.createElement('div');
        wrap.className = 'dm-feedback-summary';
        const counts = (summary && summary.label_counts) || {};
        if (!summary || !summary.total) {
            const empty = document.createElement('div');
            empty.className = 'dm-empty';
            empty.textContent = _t('drill_modal.feedback.summary_empty');
            wrap.appendChild(empty);
            return wrap;
        }
        const meta = document.createElement('div');
        meta.className = 'dm-feedback-meta';
        meta.textContent = _t('drill_modal.feedback.summary_meta', {
            total: summary.total,
            distinct: summary.distinct_analysts,
        });
        wrap.appendChild(meta);
        _CC_FEEDBACK_LABELS.forEach((lbl) => {
            const n = Number(counts[lbl] || 0);
            const row = document.createElement('div');
            row.className = 'dm-feedback-row';
            row.innerHTML = `<span>${_escHtml(_t('drill_modal.feedback.label.' + lbl))}</span>` +
                            `<span>${_escHtml(String(n))}</span>`;
            wrap.appendChild(row);
        });
        return wrap;
    }

    async function _ccFeedbackLoad(conclusionId, summaryHost) {
        try {
            const resp = await fetch(
                `/api/v2/conclusions/${encodeURIComponent(conclusionId)}/feedback`,
            );
            if (!resp.ok) return;  // Render-time best effort; failure leaves prior summary
            const body = await resp.json();
            summaryHost.innerHTML = '';
            summaryHost.appendChild(_ccFeedbackRenderSummary(body && body.summary));
        } catch (e) {
            if (window.console) console.debug('[FeedbackWidget] load error', e);
        }
    }

    async function _ccFeedbackSubmit(conclusionId, payload, statusEl, summaryHost, submitBtn) {
        statusEl.textContent = _t('drill_modal.feedback.status.submitting');
        submitBtn.disabled = true;
        try {
            const resp = await fetch(
                `/api/v2/conclusions/${encodeURIComponent(conclusionId)}/feedback`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                },
            );
            if (resp.status === 201) {
                const body = await resp.json();
                statusEl.textContent = _t('drill_modal.feedback.status.saved');
                summaryHost.innerHTML = '';
                summaryHost.appendChild(_ccFeedbackRenderSummary(body && body.summary));
            } else if (resp.status === 400) {
                statusEl.textContent = _t('drill_modal.feedback.status.bad_label');
            } else {
                statusEl.textContent = _t('drill_modal.feedback.status.failed', { status: resp.status });
            }
        } catch (e) {
            statusEl.textContent = _t('drill_modal.feedback.status.network');
            if (window.console) console.debug('[FeedbackWidget] submit error', e);
        } finally {
            submitBtn.disabled = false;
        }
    }

    function _ccDrillRenderLlmAugmentation(trace) {
        // ATTACK_MODE LLM augmentation surfaces narrative + agreement +
        // suggested_alternative_mode + key_evidence as a dedicated card so
        // analysts see the LLM's read at a glance instead of digging in
        // the raw metadata blob. Empty when conclusion has no augmentation
        // (i.e. flag off, LLM offline, or rule-based INSUFFICIENT_DATA).
        const wrap = document.createElement('div');
        wrap.className = 'dm-llm-aug';
        const aug = (trace && trace.metadata && trace.metadata.llm_augmentation) || null;
        if (!aug || typeof aug !== 'object') {
            wrap.textContent = _t('drill_modal.llm_aug.empty');
            return wrap;
        }
        if (aug.ok === false) {
            const row = _ccDrillRow(_t('drill_modal.llm_aug.attempted'),
                                    _t('drill_modal.llm_aug.failed', { error: String(aug.error || '—') }));
            wrap.appendChild(row);
            return wrap;
        }
        if (aug.agreement) {
            wrap.appendChild(_ccDrillRow(_t('drill_modal.llm_aug.agreement'),
                                          String(aug.agreement)));
        }
        if (aug.suggested_alternative_mode) {
            wrap.appendChild(_ccDrillRow(_t('drill_modal.llm_aug.suggested_alt'),
                                          String(aug.suggested_alternative_mode)));
        }
        if (typeof aug.confidence_adjustment_applied === 'number') {
            const sign = aug.confidence_adjustment_applied >= 0 ? '+' : '';
            wrap.appendChild(_ccDrillRow(_t('drill_modal.llm_aug.conf_adj'),
                                          `${sign}${aug.confidence_adjustment_applied}`));
        }
        if (aug.narrative) {
            const block = document.createElement('div');
            block.className = 'dm-llm-aug-narrative';
            block.textContent = String(aug.narrative);
            wrap.appendChild(block);
        }
        if (Array.isArray(aug.key_evidence) && aug.key_evidence.length) {
            const ul = document.createElement('ul');
            ul.className = 'dm-llm-aug-evidence';
            aug.key_evidence.forEach((e) => {
                const li = document.createElement('li');
                li.textContent = String(e);
                ul.appendChild(li);
            });
            wrap.appendChild(ul);
        }
        return wrap;
    }

    function _ccDrillRenderFeedback(trace) {
        const wrap = document.createElement('div');
        wrap.className = 'dm-feedback';
        if (!trace || !trace.conclusion_id) {
            wrap.textContent = _t('drill_modal.feedback.disabled');
            return wrap;
        }

        const summaryHost = document.createElement('div');
        summaryHost.className = 'dm-feedback-summary-host';
        summaryHost.appendChild(_ccFeedbackRenderSummary(null));
        wrap.appendChild(summaryHost);

        const form = document.createElement('div');
        form.className = 'dm-feedback-form';
        // Radio group — uses fieldset for a11y
        const fs = document.createElement('fieldset');
        fs.className = 'dm-feedback-fieldset';
        const legend = document.createElement('legend');
        legend.textContent = _t('drill_modal.feedback.legend');
        fs.appendChild(legend);
        const radioName = `dm-feedback-label-${trace.conclusion_id}`;
        _CC_FEEDBACK_LABELS.forEach((lbl) => {
            const id = `${radioName}-${lbl}`;
            const lab = document.createElement('label');
            lab.htmlFor = id;
            lab.className = 'dm-feedback-radio';
            const r = document.createElement('input');
            r.type = 'radio'; r.name = radioName; r.value = lbl; r.id = id;
            lab.appendChild(r);
            const span = document.createElement('span');
            span.textContent = _t('drill_modal.feedback.label.' + lbl);
            lab.appendChild(span);
            fs.appendChild(lab);
        });
        form.appendChild(fs);

        // Optional outcome URL + notes
        const urlInput = document.createElement('input');
        urlInput.type = 'url'; urlInput.className = 'dm-feedback-url';
        urlInput.placeholder = _t('drill_modal.feedback.url_placeholder');
        form.appendChild(urlInput);

        const notes = document.createElement('textarea');
        notes.className = 'dm-feedback-notes';
        notes.rows = 3;
        notes.placeholder = _t('drill_modal.feedback.notes_placeholder');
        notes.maxLength = 2000;
        form.appendChild(notes);

        const actions = document.createElement('div');
        actions.className = 'dm-feedback-actions';
        const submit = document.createElement('button');
        submit.type = 'button';
        submit.className = 'dm-feedback-submit';
        submit.textContent = _t('drill_modal.feedback.submit');
        const status = document.createElement('span');
        status.className = 'dm-feedback-status';
        actions.appendChild(submit);
        actions.appendChild(status);
        form.appendChild(actions);

        submit.addEventListener('click', () => {
            const checked = fs.querySelector('input[type="radio"]:checked');
            if (!checked) {
                status.textContent = _t('drill_modal.feedback.status.no_label');
                return;
            }
            const payload = { label: checked.value };
            const u = urlInput.value && urlInput.value.trim();
            if (u) payload.observed_outcome_url = u;
            const n = notes.value && notes.value.trim();
            if (n) payload.notes = n;
            _ccFeedbackSubmit(trace.conclusion_id, payload, status, summaryHost, submit);
        });

        wrap.appendChild(form);
        // Kick off the initial summary fetch (replaces the placeholder).
        _ccFeedbackLoad(trace.conclusion_id, summaryHost);
        return wrap;
    }

    function _ccDrillRender(trace) {
        const body = document.getElementById('cc-drill-body');
        if (!body) return;
        body.innerHTML = '';
        body.appendChild(_ccDrillSection('drill_modal.section.header',      _ccDrillRenderHeader(trace), false));
        body.appendChild(_ccDrillSection('drill_modal.section.disclaimer',  _ccDrillRenderDisclaimer(trace), false));
        body.appendChild(_ccDrillSection('drill_modal.section.formula',     _ccDrillRenderFormula(trace),
                                          !trace.formula_ref));
        const trEl = _ccDrillRenderKvTable(trace.threshold_ref, 'drill_modal.empty.thresholds');
        const trEmpty = !trace.threshold_ref || Object.keys(trace.threshold_ref || {}).length === 0;
        body.appendChild(_ccDrillSection('drill_modal.section.thresholds',  trEl, trEmpty));
        body.appendChild(_ccDrillSection('drill_modal.section.calibration', _ccDrillRenderCalibration(trace),
                                          !trace.calibration_status || Object.keys(trace.calibration_status || {}).length === 0));
        body.appendChild(_ccDrillSection('drill_modal.section.sources',     _ccDrillRenderSources(trace),
                                          !trace.source_urls || trace.source_urls.length === 0));

        // NP6: rationale_matrix lives only on threat_level conclusions today.
        // Render it as its own structured table and exclude the key from the
        // generic metadata kv dump (would dump as a JSON wall otherwise).
        const isThreat = trace && trace.conclusion_type === 'threat_level';
        const hasRm = isThreat && trace.metadata && Array.isArray(trace.metadata.rationale_matrix)
                       && trace.metadata.rationale_matrix.length > 0;
        if (isThreat) {
            body.appendChild(_ccDrillSection('drill_modal.section.rationale_matrix',
                                             _ccDrillRenderRationaleMatrix(trace), !hasRm));
        }
        const metadataExcludes = isThreat ? ['rationale_matrix'] : [];
        const mdEl = _ccDrillRenderKvTable(trace.metadata, 'drill_modal.empty.metadata', metadataExcludes);
        const mdKeyCount = trace.metadata
            ? Object.keys(trace.metadata).filter((k) => !metadataExcludes.includes(k)).length
            : 0;
        const mdEmpty = mdKeyCount === 0;
        body.appendChild(_ccDrillSection('drill_modal.section.metadata',    mdEl, mdEmpty));
        body.appendChild(_ccDrillSection('drill_modal.section.llm_prompt',  _ccDrillRenderLlmPrompt(trace), false));
        // Show LLM augmentation only for attack_mode where it is meaningful;
        // other types use the generic metadata kv table which is enough.
        if (trace && trace.conclusion_type === 'attack_mode') {
            const augEl = _ccDrillRenderLlmAugmentation(trace);
            const augHasContent = !!(trace.metadata && trace.metadata.llm_augmentation);
            body.appendChild(_ccDrillSection('drill_modal.section.llm_aug', augEl, !augHasContent));
        }
        body.appendChild(_ccDrillSection('drill_modal.section.feedback',    _ccDrillRenderFeedback(trace), false));
    }

    function _ccDrillRenderError(msg) {
        const body = document.getElementById('cc-drill-body');
        if (!body) return;
        body.innerHTML = '';
        const div = document.createElement('div');
        div.className = 'dm-error';
        div.setAttribute('role', 'alert');
        div.textContent = msg;
        body.appendChild(div);
    }

    async function _ccOpenDrillModal(c) {
        const modal = document.getElementById('cc-drill-modal');
        const body = document.getElementById('cc-drill-body');
        const backdrop = document.getElementById('settings-backdrop');
        if (!modal || !body) return;

        _ccDrillReturnFocus = document.activeElement;
        body.innerHTML = `<div class="dm-loading">${_escHtml(_t('drill_modal.loading'))}</div>`;
        // Re-use the global modal stack (settings-backdrop handles ESC by
        // closeAllModals; we register our own ESC for predictable focus return).
        if (typeof openModal === 'function') {
            openModal('cc-drill-modal');
        } else {
            modal.style.display = 'flex';
            if (backdrop) backdrop.style.display = 'block';
        }
        // Move focus to the modal body so screen readers announce the dialog.
        try { body.focus(); } catch (_) { /* ignored */ }

        // ESC key handler — register once per open
        _ccDrillKeyHandler = (e) => {
            if (e.key === 'Escape') {
                e.stopPropagation();
                _ccCloseDrillModal();
            }
        };
        document.addEventListener('keydown', _ccDrillKeyHandler, true);

        // Cancel any prior in-flight drill fetch
        if (_ccDrillAbort) {
            try { _ccDrillAbort.abort(); } catch (_) { /* unsupported → ignore */ }
        }
        const ac = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        _ccDrillAbort = ac;

        try {
            const resp = await fetch(
                `/api/v2/conclusions/${encodeURIComponent(c.id)}/audit_trace`,
                ac ? { signal: ac.signal } : undefined,
            );
            if (!resp.ok) {
                _ccDrillRenderError(_t('drill_modal.error.fetch_failed', { status: resp.status }));
                return;
            }
            const trace = await resp.json();
            _ccDrillRender(trace);
        } catch (e) {
            if (e && e.name === 'AbortError') return;
            _ccDrillRenderError(_t('drill_modal.error.network'));
            if (window.console) console.debug('[DrillModal] fetch error', e);
        } finally {
            if (_ccDrillAbort === ac) _ccDrillAbort = null;
        }
    }

    function _ccCloseDrillModal() {
        const modal = document.getElementById('cc-drill-modal');
        const backdrop = document.getElementById('settings-backdrop');
        if (modal) modal.style.display = 'none';
        // Only hide backdrop if no other modal is open
        const otherOpen = !!document.querySelector('.modal-window[style*="display: flex"]:not(#cc-drill-modal)');
        if (backdrop && !otherOpen) backdrop.style.display = 'none';
        if (_ccDrillKeyHandler) {
            document.removeEventListener('keydown', _ccDrillKeyHandler, true);
            _ccDrillKeyHandler = null;
        }
        if (_ccDrillAbort) {
            try { _ccDrillAbort.abort(); } catch (_) { /* ignored */ }
            _ccDrillAbort = null;
        }
        if (_ccDrillReturnFocus && typeof _ccDrillReturnFocus.focus === 'function') {
            try { _ccDrillReturnFocus.focus(); } catch (_) { /* ignored */ }
        }
        _ccDrillReturnFocus = null;
    }

    // Expose close for the modal header [X] button (must be window-scoped
    // because the markup lives in index.html and uses inline onclick).
    window._ccCloseDrillModal = _ccCloseDrillModal;

    // ── Sensor Watchpane (Layer 3) ─────────────────────────────────────
    // Floating panel that lets the analyst pin individual sensors and watch
    // their observations cycle-by-cycle, sourced from
    // /api/v2/sensors/<name>/observations. Backend persists per-cycle scores
    // into sensor_observation_ts (1h–6h window); the API only flags
    // history_shallow when fewer than 2 points have accumulated for a sensor
    // (fresh DB / very first cycle) — the toolbar tag mirrors that.
    const _WP_STORAGE_KEY = 'watchpane.v1.state';
    const _WP_STATE_VERSION = 2;  // v2 adds optional `alarm` per row
    let _wpState = { sensors: [], version: _WP_STATE_VERSION };
    let _wpCatalog = null;            // [{sensor, label, domain}]
    let _wpToggleFn = null;
    let _wpRefreshInflight = false;
    const _wpLastObs = new Map();     // key="sensor::scope" → last response

    // Alarm condition fields/operators. Kept tiny and explicit per NP6 — every
    // alarm is fully describable as `<field> <op> <number-or-status>` so the
    // analyst can reason about exactly when it fires. Pure logic lives in
    // wp_alarm.js so it can be unit-tested under Node.
    const _WP_ALARM_FIELDS        = window.WatchpaneAlarm.FIELDS;
    const _WP_ALARM_OPS_NUMERIC   = window.WatchpaneAlarm.OPS_NUMERIC;
    const _WP_ALARM_OPS_STATUS    = window.WatchpaneAlarm.OPS_STATUS;
    const _WP_ALARM_STATUS_VALUES = window.WatchpaneAlarm.STATUS_VALUES;
    const _wpNormalizeAlarm = window.WatchpaneAlarm.normalizeAlarm;

    function _wpLoadState() {
        try {
            const raw = localStorage.getItem(_WP_STORAGE_KEY);
            _wpState = window.WatchpaneAlarm.loadStateFromRaw(raw, _WP_STATE_VERSION);
        } catch (e) {
            if (window.console) console.debug('[Watchpane] state load failed', e);
        }
    }

    function _wpSaveState() {
        try { localStorage.setItem(_WP_STORAGE_KEY, JSON.stringify(_wpState)); }
        catch (e) { if (window.console) console.debug('[Watchpane] state save failed', e); }
    }

    // Pure evaluator + describer live in wp_alarm.js (testable under Node).
    const _wpAlarmMatches  = window.WatchpaneAlarm.alarmMatches;
    const _wpAlarmDescribe = window.WatchpaneAlarm.alarmDescribe;

    function _wpNotify(sensor, alarm) {
        if (!alarm.notify) return;
        if (typeof Notification === 'undefined') return;
        if (Notification.permission !== 'granted') return;
        try {
            const title = _t('watchpane.notify.title') || 'Sensor alarm';
            const body  = `${sensor.name} (${sensor.scope}) — ${_wpAlarmDescribe(alarm)}`;
            new Notification(title, { body, tag: `wp-alarm-${sensor.name}-${sensor.scope}` });
        } catch (e) {
            if (window.console) console.debug('[Watchpane] notify failed', e);
        }
    }

    // Walk all rows after a refresh, fire one notification per false→true edge.
    // Pure edge-trigger logic lives in wp_alarm.js — this function only
    // commits the new state and dispatches notifications for rising rows.
    function _wpEvaluateAlarms() {
        const result = window.WatchpaneAlarm.evaluateAlarmsEdge(
            _wpState, _wpLastObs, Date.now()
        );
        if (!result.changed) return;
        _wpState = result.nextState;
        for (const row of result.rising) _wpNotify(row, row.alarm);
        _wpSaveState();
    }

    async function _wpLoadCatalog() {
        if (_wpCatalog) return _wpCatalog;
        try {
            const resp = await fetch('/api/v2/sensors/catalog');
            if (!resp.ok) return null;
            const env = await resp.json();
            _wpCatalog = Array.isArray(env && env.sensors) ? env.sensors : [];
            return _wpCatalog;
        } catch (e) {
            if (window.console) console.debug('[Watchpane] catalog fetch failed', e);
            return null;
        }
    }

    function _wpRowKey(name, scope) { return `${name}::${scope}`; }

    function _wpRenderSpark(observations) {
        // 1 point → single dot (fresh sensor, history shallow).
        // N points → polyline normalised to local min/max so even subtle
        // deltas read at a glance. SVG is intentionally tiny.
        const w = 60, h = 18;
        if (!observations || observations.length === 0) {
            return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"></svg>`;
        }
        if (observations.length === 1) {
            const v = Number(observations[0].value || 0);
            const cx = w / 2;
            const cy = h - Math.max(2, Math.min(h - 2, (v / 5) * (h - 2)));
            return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`
                 + `<circle cx="${cx}" cy="${cy}" r="2.2" fill="var(--color-accent)" />`
                 + `</svg>`;
        }
        // Multi-point (future): polyline normalised to range
        const vals = observations.map(o => Number(o.value || 0));
        const max = Math.max(...vals, 1), min = Math.min(...vals, 0);
        const span = Math.max(0.001, max - min);
        const pts = vals.map((v, i) => {
            const x = (i / (vals.length - 1)) * w;
            const y = h - ((v - min) / span) * (h - 2) - 1;
            return `${x.toFixed(1)},${y.toFixed(1)}`;
        }).join(' ');
        return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`
             + `<polyline points="${pts}" fill="none" stroke="var(--color-accent)" stroke-width="1.2" />`
             + `</svg>`;
    }

    function _wpStatusClass(curr) {
        if (!curr) return 'wp-status-error';
        if (curr.suppressed) return 'wp-status-suppressed';
        const s = (curr.status || '').toUpperCase();
        if (s === 'FIRED' || s === 'CRITICAL' || s === 'ELEVATED') return 'wp-status-fired';
        if (s === 'NORMAL' || s === 'OK') return 'wp-status-normal';
        return '';
    }

    function _wpStatusText(curr) {
        if (!curr) return _t('watchpane.row.no_data');
        if (curr.suppressed) return _t('watchpane.row.suppressed');
        const s = (curr.status || '').toUpperCase();
        if (s === 'FIRED' || s === 'CRITICAL' || s === 'ELEVATED') return _t('watchpane.row.fired');
        if (s === 'NORMAL' || s === 'OK') return _t('watchpane.row.normal');
        return s || '—';
    }

    function _wpUpdateShallowTag() {
        const tag = document.getElementById('wp-shallow-tag');
        if (!tag) return;
        const anyShallow = _wpState.sensors.some(s => {
            const env = _wpLastObs.get(_wpRowKey(s.name, s.scope));
            return env && env.history_shallow === true;
        });
        tag.style.display = anyShallow ? '' : 'none';
    }

    function _wpRender() {
        const rowsEl = document.getElementById('wp-rows');
        if (!rowsEl) return;
        _wpUpdateShallowTag();
        if (_wpState.sensors.length === 0) {
            rowsEl.innerHTML = `<div class="wp-empty" data-i18n="watchpane.empty">${_escHtml(_t('watchpane.empty'))}</div>`;
            return;
        }
        const lang = (typeof _currentLang !== 'undefined') ? _currentLang : 'en';
        const labelOf = (name) => {
            if (!_wpCatalog) return name;
            const row = _wpCatalog.find(r => r.sensor === name);
            return row ? (row.label || name) : name;
        };
        const html = _wpState.sensors.map((s, idx) => {
            const safeName = _escHtml(s.name);
            const safeScope = _escHtml(s.scope);
            const obs = _wpLastObs.get(_wpRowKey(s.name, s.scope));
            const observations = obs ? (obs.observations || []) : null;
            const curr = obs ? obs.current : null;
            // Latest point (backend orders ascending by ts).
            const latest = (observations && observations.length)
                ? observations[observations.length - 1] : null;
            const valueDisp = latest ? Number(latest.value || 0).toFixed(2) : '—';
            const statusCls = _wpStatusClass(curr);
            const statusTxt = _wpStatusText(curr);
            const rawValueTip = (curr && curr.raw_value != null) ? String(curr.raw_value) : '';
            const alarmActive = !!(s.alarm && s.alarm.is_active);
            const alarmConfigured = !!s.alarm;
            const rowCls = 'wp-row' + (alarmActive ? ' wp-row-alarm' : '');
            const bellCls = 'wp-alarm-btn'
                + (alarmActive ? ' wp-alarm-active' : (alarmConfigured ? ' wp-alarm-set' : ''));
            const bellTip = alarmConfigured
                ? `${_t('watchpane.alarm.btn.tip_configured')}: ${_wpAlarmDescribe(s.alarm)}`
                : _t('watchpane.alarm.btn.tip_unset');
            const alarmBadge = alarmActive
                ? `<span class="wp-alarm-badge" title="${_escHtml(_wpAlarmDescribe(s.alarm))}">⚠</span>`
                : '';
            // Build the sub-line as plain text first so we can use it for the
            // title (full hover text) without relying on slicing. The visible
            // span keeps the full raw_value — CSS line-clamp handles overflow.
            const subPlain = `${s.scope} · ${statusTxt}` + (rawValueTip ? ` · ${rawValueTip}` : '');
            return `
                <div class="${rowCls}" data-wp-idx="${idx}">
                    <div class="wp-meta">
                        <div class="wp-name" title="${safeName}">${alarmBadge}${_escHtml(labelOf(s.name))}</div>
                        <div class="wp-sub ${statusCls}" title="${_escHtml(subPlain)}">${safeScope} · <span class="${statusCls}">${_escHtml(statusTxt)}</span>${rawValueTip ? ` · <span>${_escHtml(rawValueTip)}</span>` : ''}</div>
                    </div>
                    <span class="wp-spark">${_wpRenderSpark(observations)}</span>
                    <span class="wp-value ${statusCls}">${_escHtml(valueDisp)}</span>
                    <button type="button" class="${bellCls}" title="${_escHtml(bellTip)}"
                            onclick="window._wpOpenAlarmEditor(${idx})">🔔</button>
                    <button type="button" class="wp-remove" data-i18n-tip="watchpane.row.remove"
                            title="${_escHtml(_t('watchpane.row.remove'))}"
                            onclick="window._wpRemoveSensor(${idx})">×</button>
                </div>
            `;
        }).join('');
        rowsEl.innerHTML = html;
    }

    async function _wpRefreshOne(name, scope) {
        try {
            const resp = await fetch(
                `/api/v2/sensors/${encodeURIComponent(name)}/observations`
                + `?scope=${encodeURIComponent(scope)}&hours=1`
            );
            if (!resp.ok) {
                _wpLastObs.delete(_wpRowKey(name, scope));
                return;
            }
            const env = await resp.json();
            _wpLastObs.set(_wpRowKey(name, scope), env);
        } catch (e) {
            // Network error — drop cached value so the row shows fetch error
            _wpLastObs.delete(_wpRowKey(name, scope));
            if (window.console) console.debug('[Watchpane] obs fetch failed', name, scope, e);
        }
    }

    async function _wpRefreshAll() {
        if (_wpRefreshInflight) return;
        const panel = document.getElementById('sensor-watchpane');
        if (!panel || panel.style.display === 'none') return;  // Only poll while visible
        if (_wpState.sensors.length === 0) return;
        _wpRefreshInflight = true;
        try {
            await Promise.all(_wpState.sensors.map(s => _wpRefreshOne(s.name, s.scope)));
            // Alarm evaluation must happen AFTER the new envelopes land in
            // _wpLastObs but BEFORE rendering, so the row can paint with the
            // updated active state in the same paint cycle.
            _wpEvaluateAlarms();
            _wpRender();
        } finally {
            _wpRefreshInflight = false;
        }
    }

    function _wpOpenAdd() {
        const overlay = document.getElementById('wp-add-overlay');
        if (!overlay) return;
        overlay.style.display = 'flex';
        const search = document.getElementById('wp-add-search');
        if (search) { search.value = ''; setTimeout(() => search.focus(), 50); }
        _wpLoadCatalog().then(() => _wpRenderAddList(''));
    }

    function _wpCloseAdd() {
        const overlay = document.getElementById('wp-add-overlay');
        if (overlay) overlay.style.display = 'none';
    }
    window._wpCloseAdd = _wpCloseAdd;

    function _wpRenderAddList(filter) {
        const listEl = document.getElementById('wp-add-list');
        if (!listEl) return;
        if (!_wpCatalog) {
            listEl.innerHTML = `<div class="wp-add-empty">${_escHtml(_t('ui.loading') || 'Loading…')}</div>`;
            return;
        }
        const f = (filter || '').toLowerCase().trim();
        const taken = new Set(_wpState.sensors.map(s => `${s.name}::${s.scope}`));
        // Filter on either sensor id or label (case-insensitive substring)
        const matches = _wpCatalog.filter(row => {
            if (!f) return true;
            return (row.sensor || '').toLowerCase().includes(f)
                || (row.label || '').toLowerCase().includes(f)
                || (row.domain || '').toLowerCase().includes(f);
        });
        if (matches.length === 0) {
            listEl.innerHTML = `<div class="wp-add-empty">${_escHtml(_t('watchpane.add.no_match'))}</div>`;
            return;
        }
        // Default scope is 'focused' for now; scope picker is deferred until
        // the multi-scope schema lands (§7.1 future)
        const html = matches.map(row => {
            const dup = taken.has(`${row.sensor}::focused`);
            const safeName = _escHtml(row.sensor);
            const safeLabel = _escHtml(row.label || row.sensor);
            const safeDomain = _escHtml(row.domain || '');
            const cls = dup ? 'wp-add-item wp-disabled' : 'wp-add-item';
            const onclick = dup ? '' : `onclick="window._wpAddSensor('${safeName}', 'focused')"`;
            const trailing = dup
                ? `<span class="wp-add-domain">(${_escHtml(_t('watchpane.add.already_added'))})</span>`
                : `<span class="wp-add-domain">${safeDomain}</span>`;
            return `<div class="${cls}" ${onclick}><span>${safeLabel}</span>${trailing}</div>`;
        }).join('');
        listEl.innerHTML = html;
    }

    window._wpAddSensor = function(name, scope) {
        const sc = scope || 'focused';
        if (_wpState.sensors.find(s => s.name === name && s.scope === sc)) return;
        _wpState.sensors.push({ name, scope: sc, added_at: Date.now() });
        _wpSaveState();
        _wpCloseAdd();
        _wpRender();
        _wpRefreshOne(name, sc).then(() => _wpRender());
    };

    window._wpRemoveSensor = function(idx) {
        if (idx < 0 || idx >= _wpState.sensors.length) return;
        const removed = _wpState.sensors.splice(idx, 1)[0];
        if (removed) _wpLastObs.delete(_wpRowKey(removed.name, removed.scope));
        _wpSaveState();
        _wpRender();
    };

    let _wpAlarmEditIdx = -1;

    function _wpRequestNotificationPermission() {
        if (typeof Notification === 'undefined') return;
        if (Notification.permission === 'default') {
            try { Notification.requestPermission(); } catch (e) { /* legacy promise-less browsers */ }
        }
    }

    function _wpAlarmFieldOps(field) {
        return field === 'status' ? _WP_ALARM_OPS_STATUS : _WP_ALARM_OPS_NUMERIC;
    }

    window._wpOpenAlarmEditor = function(idx) {
        if (idx < 0 || idx >= _wpState.sensors.length) return;
        _wpAlarmEditIdx = idx;
        const overlay = document.getElementById('wp-alarm-overlay');
        if (!overlay) return;
        const s = _wpState.sensors[idx];
        const a = s.alarm;
        const fieldEl = document.getElementById('wp-alarm-field');
        const opEl    = document.getElementById('wp-alarm-op');
        const valEl   = document.getElementById('wp-alarm-value');
        const statusEl = document.getElementById('wp-alarm-status-value');
        const notifyEl = document.getElementById('wp-alarm-notify');
        const titleEl = document.getElementById('wp-alarm-title');
        if (titleEl) titleEl.textContent = `${_t('watchpane.alarm.title')} — ${s.name}`;
        // Field options
        if (fieldEl) {
            fieldEl.innerHTML = _WP_ALARM_FIELDS.map(
                f => `<option value="${f}">${_escHtml(_t('watchpane.alarm.field.' + f) || f)}</option>`
            ).join('');
            fieldEl.value = (a && a.field) || 'score';
        }
        const refreshOpAndValue = () => {
            const field = fieldEl ? fieldEl.value : 'score';
            const ops = _wpAlarmFieldOps(field);
            if (opEl) {
                opEl.innerHTML = ops.map(o => `<option value="${o}">${o}</option>`).join('');
                opEl.value = (a && ops.includes(a.op)) ? a.op : ops[0];
            }
            if (field === 'status') {
                if (valEl) valEl.style.display = 'none';
                if (statusEl) {
                    statusEl.style.display = '';
                    statusEl.innerHTML = _WP_ALARM_STATUS_VALUES.map(
                        v => `<option value="${v}">${v}</option>`
                    ).join('');
                    statusEl.value = (a && _WP_ALARM_STATUS_VALUES.includes(String(a.value).toUpperCase()))
                        ? String(a.value).toUpperCase() : 'FIRED';
                }
            } else {
                if (statusEl) statusEl.style.display = 'none';
                if (valEl) {
                    valEl.style.display = '';
                    valEl.value = (a && Number.isFinite(Number(a.value))) ? String(a.value) : '';
                }
            }
        };
        refreshOpAndValue();
        if (fieldEl) fieldEl.onchange = refreshOpAndValue;
        if (notifyEl) notifyEl.checked = !a || a.notify !== false;
        overlay.style.display = 'flex';
        _wpRequestNotificationPermission();
    };

    window._wpCloseAlarmEditor = function() {
        const overlay = document.getElementById('wp-alarm-overlay');
        if (overlay) overlay.style.display = 'none';
        _wpAlarmEditIdx = -1;
    };

    window._wpSaveAlarm = function() {
        if (_wpAlarmEditIdx < 0) return;
        const s = _wpState.sensors[_wpAlarmEditIdx];
        if (!s) return;
        const fieldEl = document.getElementById('wp-alarm-field');
        const opEl    = document.getElementById('wp-alarm-op');
        const valEl   = document.getElementById('wp-alarm-value');
        const statusEl = document.getElementById('wp-alarm-status-value');
        const notifyEl = document.getElementById('wp-alarm-notify');
        const field = fieldEl ? fieldEl.value : 'score';
        const op    = opEl ? opEl.value : '>';
        const value = field === 'status'
            ? (statusEl ? statusEl.value : 'FIRED')
            : (valEl ? Number(valEl.value) : NaN);
        const candidate = _wpNormalizeAlarm({
            field, op, value,
            notify: notifyEl ? notifyEl.checked : true,
        });
        if (!candidate) {
            const errEl = document.getElementById('wp-alarm-error');
            if (errEl) {
                errEl.textContent = _t('watchpane.alarm.error.invalid') || 'Invalid value';
                errEl.style.display = '';
            }
            return;
        }
        _wpState = window.WatchpaneAlarm.applyAlarmToState(_wpState, _wpAlarmEditIdx, candidate);
        // Re-evaluate immediately so the row reflects the new condition without
        // waiting for the next 10s poll.
        _wpEvaluateAlarms();
        _wpSaveState();
        _wpRender();
        window._wpCloseAlarmEditor();
    };

    window._wpClearAlarm = function() {
        if (_wpAlarmEditIdx < 0) return;
        _wpState = window.WatchpaneAlarm.applyAlarmToState(_wpState, _wpAlarmEditIdx, null);
        _wpSaveState();
        _wpRender();
        window._wpCloseAlarmEditor();
    };

    function _wpInit() {
        const panel = document.getElementById('sensor-watchpane');
        if (!panel) return;
        if (typeof window.createFloatingPanel !== 'function') return;
        _wpToggleFn = window.createFloatingPanel({
            id: 'sensor-watchpane',
            titleKey: 'watchpane.title',
            titleFallback: 'Sensor Watchpane',
            defaultLeft: window.innerWidth - 440,
            defaultTop: 140,
            width: 420,
            bodyClass: 'wp-body',
            onShow: () => { _wpRefreshAll(); },
        });
        // Bind add-button + search input (delegated to avoid losing handlers
        // when the body markup gets re-rendered).
        const addBtn = document.getElementById('wp-add-btn');
        if (addBtn) addBtn.addEventListener('click', _wpOpenAdd);
        const search = document.getElementById('wp-add-search');
        if (search) {
            search.addEventListener('input', (e) => _wpRenderAddList(e.target.value));
            search.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') { e.stopPropagation(); _wpCloseAdd(); }
            });
        }
        _wpLoadState();
        _wpRender();
        // Piggyback on the 10s scoring poll for refresh
    }

    window.toggleSensorWatchpane = function() {
        if (!_wpToggleFn) _wpInit();
        if (_wpToggleFn) _wpToggleFn();
    };

    // Init at boot so localStorage sensors are visible without opening first
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _wpInit);
    } else {
        // Defer so createFloatingPanel definition (above) is in scope
        setTimeout(_wpInit, 0);
    }

    async function fetchDDoSData(force = false) {
        // Under scenario-unit mode the server derives scope from the focused
        // scenario; only focus + muted + force are passed.
        const mutedList = Array.from(mutedSensors).join(',');
        const coreTheater = resolveChainTargetCountry((latestData || {}).strategic_alert || {});

        const syncBtnTop = document.getElementById('btn-sync-top');
        const syncBtnSide = document.getElementById('btn-sync-side');

        if (force) {
            syncBtnTop.innerText = _t('status.syncing'); syncBtnTop.classList.add("syncing");
            syncBtnSide.innerText = _t('status.syncing'); syncBtnSide.classList.add("syncing");
        }

        try {
            const _focusParam = _getScenarioFocus();
            const _params = new URLSearchParams({
                muted: mutedList, force: force,
                focus: _focusParam
            });
            const apiUrl = `/api/threat_data?${_params}`;
            const response = await fetch(apiUrl);
            if (!response.ok) {
                console.warn(`[API] HTTP ${response.status} — keeping previous data`);
                return;  // Preserve latestData from last successful poll
            }
            latestData = await response.json();
            
            _lastSyncTime = Date.now();
            lastSyncedTimeText = `Data Synced: ${new Date().toLocaleTimeString()}`;
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

            // Fire-and-forget: hydrate NP7 banner with v2 disclaimer. One-shot.
            _refreshNp7Banner(_focusParam);
            // Fire-and-forget: refresh Layer 1 conclusion cards (re-fetched
            // every poll so cards stay in lockstep with v1 telemetry).
            _refreshConclusionCards(_focusParam);

            // Fire-and-forget: refresh Layer 3 sensor watchpane rows when visible
            if (typeof _wpRefreshAll === 'function') _wpRefreshAll();

            // Refresh LLM Intel data on every poll so chain panel and intel panel stay current
            if (typeof _fetchLlmIntel === 'function') _fetchLlmIntel();

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

    // ── Map overlay sub-renderers (extracted from renderTelemetry) ─────
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
                const fromEast  = prev[1] > 0;
                const edgeA     = fromEast ?  180 : -180;
                const edgeB     = fromEast ? -180 :  180;
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

    function _renderSignalOverlays(overlays, targetCodesSet) {
        (overlays.ioda_outages || []).forEach(o => {
            if (targetCodesSet.has(o.code)) return;
            const lngS = shiftLng(o.lng);
            const icon = L.divIcon({
                className: '',
                html: `<div style="width:0;height:0;border-left:9px solid transparent;border-right:9px solid transparent;border-bottom:18px solid #ff2a2a;filter:drop-shadow(0 0 6px #ff2a2a);"></div>`,
                iconSize: [18, 18], iconAnchor: [9, 18],
            });
            L.marker([o.lat, lngS], { icon })
             .bindPopup(`<b>${esc(o.name)}</b><br><span style="color:#ff2a2a;">${_t('map.popup.bgp_outage')}</span>`)
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
                html: `<div style="font-size:18px;line-height:1;filter:${glow}; cursor:help;" data-tooltip="${_t('map.tooltip.airspace', {airport: esc(a.airport), pct: a.drop_pct, count: a.count, base: a.baseline})}">✈</div>`,
                iconSize: [20, 20], iconAnchor: [10, 10],
            });
            L.marker([a.lat, lngS], { icon })
             .bindPopup(
                `<b>${esc(a.airport)} (${esc(a.code)})</b><br>` +
                `<span style="color:${col};font-weight:bold;">${esc(a.severity)}</span><br>` +
                `${_t('map.popup.airspace_aircraft', {count: a.count, base: a.baseline})}<br>` +
                `${_t('map.popup.airspace_drop', {pct: a.drop_pct})}`
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
                html: `<div style="font-size:16px;line-height:1;filter:drop-shadow(0 0 4px ${col}); cursor:help;" data-tooltip="${esc(w.description)} — wind ${esc(w.wind_speed)}m/s">${emoji}</div>`,
                iconSize: [18, 18], iconAnchor: [-16, 34],
            });
            L.marker([w.lat, lngS], { icon })
             .bindPopup(
                `<b>Weather: ${esc(w.code)}</b><br>` +
                `<span style="color:${col};">${esc(w.description)}</span><br>` +
                `Severity: ${esc(w.severity)} | Wind: ${esc(w.wind_speed)} m/s` +
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
                `<b>${_t('map.popup.gdelt_title', {name: esc(g.name)})}</b><br>` +
                `<span style="color:${col};">` +
                (g.tone_current != null ? _t('map.popup.gdelt_tone', {val: g.tone_current.toFixed(1)}) : _t('map.popup.gdelt_tone_na')) +
                `</span><br>` +
                `${_t('map.popup.gdelt_baseline', {base: baseStr, delta: deltaStr})}<br>` +
                `${_t('map.popup.gdelt_status', {status: esc(g.status)})}` +
                (g.status === 'WEATHER_NOISE' ? `<br><i style="color:#ffaa00;">${_t('map.popup.gdelt_noise_note')}</i>` : '')
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
            const nameList = info.ixps.slice(0, 5).map(n => esc(n)).join('<br>') + (count > 5 ? `<br>…and ${count-5} more` : '');
            L.marker([info.lat, lngS], { icon })
             .bindPopup(`<b style="color:${col};">IXP [${esc(country)}]</b> × ${count}<br><span style="font-size:11px;color:#aaa;">${nameList}</span>`)
             .on('click', () => openCountryDetail(country))
             .addTo(criticalNodesLayer);
        });
    }

    function _renderPhysicalInfraOverlays(overlays) {
        // NASA FIRMS Anomalies
        (overlays.firms_anomalies || []).forEach(f => {
            const lngS = shiftLng(f.lng);
            const icon = L.divIcon({
                html: `<div style="font-size:20px; filter:drop-shadow(0 0 10px #ff2a2a); cursor:help;" data-tooltip="${_t('tooltip.thermal_anomaly')}">🔥</div>`,
                className: '',
                iconSize: [20,20]
            });
            L.marker([f.lat, lngS], {icon})
             .bindPopup(`<b>${_t('map.popup.firms_title')}</b><br>${_t('map.popup.firms_code', {code: esc(f.code)})}<br><span style="color:#ff2a2a; font-weight:bold;">${_t('map.popup.firms_sub')}</span>`)
             .addTo(firmsLayer);
        });

        // Cable Routes (static polylines with anti-meridian splitting)
        (overlays.cable_routes || []).forEach(route => {
            const segs = buildRouteSegments(route.waypoints || []);
            if (!segs.length) return;
            const popupHtml = `
                <div style="min-width:220px;padding:10px 12px 8px;">
                    <div style="color:#5ab8cc;font-weight:bold;font-size:12px;letter-spacing:0.5px;margin-bottom:2px;">▬ ${esc(route.name)}</div>
                    <div style="color:#335566;font-size:9px;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;border-bottom:1px solid #1a2e3a;padding-bottom:6px;">SUBMARINE CABLE ROUTE</div>
                    <div style="color:#889;font-size:10px;margin-bottom:6px;">${esc(route.description || '')}</div>
                    ${route.connects && route.connects.length ? `<div style="color:#446677;font-size:9px;border-top:1px solid #1a2e3a;padding-top:5px;line-height:1.7;">CONNECTS:<br><span style="color:#667;">${route.connects.map(c => esc(c)).join(' → ')}</span></div>` : ''}
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

        // Cable Chokepoints (enhanced)
        (overlays.chokepoints || []).forEach(c => {
            const lngS  = shiftLng(c.lng);
            const status = c.status  || 'normal';
            const cpType = c.type    || 'cable_landing';

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
                ? `<div style="margin-top:5px;color:#aaa;font-size:9px;">CABLES: ${c.cables.map(cb => esc(cb)).join(', ')}</div>`
                : '';

            L.marker([c.lat, lngS], {icon})
             .bindPopup(`
                <div style="min-width:220px;padding:10px 12px 8px;">
                    <div style="color:${color};font-weight:bold;font-size:12px;letter-spacing:0.5px;margin-bottom:2px;">${iconChar} ${esc(c.name)}</div>
                    <div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;border-bottom:1px solid #1a2e3a;padding-bottom:6px;">${TYPE_LABEL[cpType]||esc(cpType)} &nbsp;·&nbsp; ${esc(c.country)}</div>
                    <div style="margin-bottom:6px;">${STATUS_BADGE[status]||STATUS_BADGE.normal}</div>
                    ${cablesHtml}
                    <div style="margin-top:7px;color:#334455;font-size:9px;letter-spacing:0.5px;">AIS MONITOR RADIUS: 55 km</div>
                </div>
             `, { maxWidth: 280 })
             .addTo(chokepointsLayer);
        });
    }

    function _renderMilitaryTrackOverlays(overlays) {
        // ISR Hotspot Zones
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
                `<div style="color:${col};font-weight:bold;font-size:12px;">✦ ${esc(hs.name)}</div>` +
                `<div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1px;margin:4px 0;">ISR HOTSPOT ZONE · ${esc(hs.country ?? hs.theater)}</div>` +
                `<div>ISR Aircraft: <b style="color:${col};">${esc(hs.isr_count)}</b></div>` +
                `<div>Status: <b style="color:${col};">${isSurge ? '⚡ SURGE' : '● NORMAL'}</b></div>` +
                `<div style="color:#555;font-size:9px;margin-top:4px;">Radius: ${esc(hs.radius_km || 200)} km</div>` +
                `</div>`
             )
             .addTo(isrZoneLayer);
        });

        // ISR Aircraft (individual tracks)
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
                    `<div style="color:${col};font-weight:bold;font-size:12px;">${_t('map.popup.isr_track')}</div>` +
                    `<div style="color:#446677;font-size:9px;text-transform:uppercase;letter-spacing:1px;margin:4px 0;">${esc(hs.name)}</div>` +
                    `<div>${_t('map.popup.isr_callsign', {cs: esc(ac.callsign || ac.icao24 || '—')})}</div>` +
                    `<div>${_t('map.popup.isr_alt_speed', {alt: altKm, spd: velKt})}</div>` +
                    (ac.squawk ? `<div>${_t('map.popup.isr_squawk', {sq: `<b style="color:${col};">${esc(ac.squawk)}</b>`})}</div>` : '') +
                    `</div>`
                 )
                 .addTo(isrAircraftLayer);
            });
        });

        // AIS Vessels (dark gaps + stationary anomalies)
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
                `<div>Silent: <b style="color:#ff3300;">${esc(v.gap_hours)} h</b></div>` +
                `<div>Chokepoint: ${esc(v.chokepoint)}</div>` +
                `<div>Distance: ${esc(v.dist_km)} km</div>` +
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
                `<div>Distance: ${esc(v.dist_km)} km</div>` +
                `</div>`
             )
             .addTo(aisVesselLayer);
        });
    }

    function renderTelemetry(data) {
        window._lastThreatData = data; // Store for CAC threat classification

        // Always update auxiliary panels regardless of data change (they fetch independently)
        if (window._updateClimateFromPoll) window._updateClimateFromPoll(data);
        if (window._updateTgSigintFromPoll) window._updateTgSigintFromPoll(data);
        if (window._updateLlmIntelFromPoll) window._updateLlmIntelFromPoll();

        // Repopulate the Target Visibility panel from the latest focused scenario.
        // Scope is scenario-driven now, so this must re-render each poll.
        renderQuickToggles();

        const curr = getCurrentConfig();
        const displayTargets = curr.displays;

        // P4-Opt: skip if data + UI state are unchanged
        // Hash strategic_alert including convergence level and domain scores
        const _stratHash = data.strategic_alert ? (
            (data.strategic_alert.threat_level || 0) + '_' +
            (data.strategic_alert.score_with_bonus || 0) + '_' +
            (data.strategic_alert.convergence_level || '') + '_' +
            JSON.stringify(data.strategic_alert.domains || {}) + '_' +
            (data.strategic_alert.rationale_matrix || []).map(e => `${e.sensor}:${e.status}:${e.score}`).join(',')
        ) : '';
        const _tgtHash = (data.targets || []).map(t => `${t.code}:${t.avg_spike||0}:${t.l7_spike||0}`).join('|');
        // Include v2 envelope freshness in the render signature so HUD re-renders
        // when _ccEnvelopeCache refreshes (otherwise a stable v1 strategic_alert
        // would short-circuit the v2 overlay and the HUD would lag the cards).
        const _v2Hash = (() => {
            const e = _ccEnvelopeCache[data.focused_scenario];
            return e ? String(e.ts) : '';
        })();
        const _sig = `${data.timestamp || ''}_${currentVector}_${[...displayTargets].sort().join(',')}_${mapCenterMode}_${_stratHash}_${_tgtHash}_${_v2Hash}`;
        if (_sig === _lastRenderSig) return;
        _lastRenderSig = _sig;

        const threatEl = document.getElementById('hud-threat');
        const scenarioNameEl = document.getElementById('hud-scenario-name');
        const overlapEl = document.getElementById('hud-overlap');
        const shiftEl = document.getElementById('hud-vector-shift');
        const strikesEl = document.getElementById('hud-strikes');
        const outagesEl = document.getElementById('hud-outages');
        const coordinatedEl = document.getElementById('hud-coordinated');

        if (data.strategic_alert) {
            // Reconcile HUD with v2 Conclusion Cards: TL and per_domain values
            // come from the same v2 envelope when available, eliminating the
            // brief HUD/Cards mismatch that arises from independent v1/v2
            // computations during the v1→v2 sunset window.
            const strat = _hudV2OverlayStrat(data.strategic_alert, data.focused_scenario);
            const threatLabels = { 5: _t('threat_lv.5'), 4: _t('threat_lv.4'), 3: _t('threat_lv.3'), 2: _t('threat_lv.2'), 1: _t('threat_lv.1') };
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

            // TL Proximity indicator (hud-item style)
            const proxEl = document.getElementById('hud-tl-proximity');
            const proxWrap = document.getElementById('hud-tl-proximity-wrap');
            if (proxEl && proxWrap) {
                const tlp = (strat.analytics || {}).tl_proximity;
                if (tlp) {
                    const lbl = tlp.proximity_label;
                    if (lbl === 'NEAR_ESCALATION') {
                        proxEl.className = 'hud-value tl-prox-up';
                        proxEl.textContent = '▲ ' + _t('tl_prox.near_esc', {pts: tlp.distance_up, tl: tlp.next_tl_up});
                        proxEl.setAttribute('data-tooltip', _t('tl_prox.tooltip_up', {pts: tlp.distance_up, tl: tlp.next_tl_up}));
                        proxWrap.style.display = '';
                    } else if (lbl === 'NEAR_DE_ESCALATION') {
                        proxEl.className = 'hud-value tl-prox-down';
                        proxEl.textContent = '▼ ' + _t('tl_prox.near_deesc', {pts: tlp.distance_down, tl: tlp.next_tl_down});
                        proxEl.setAttribute('data-tooltip', _t('tl_prox.tooltip_down', {pts: tlp.distance_down, tl: tlp.next_tl_down}));
                        proxWrap.style.display = '';
                    } else {
                        proxWrap.style.display = 'none';
                        proxEl.textContent = '';
                    }
                } else {
                    proxWrap.style.display = 'none';
                    proxEl.textContent = '';
                }
            }

            // CAC: Context Alignment HUD indicator
            const cacWrap = document.getElementById('hud-cac-wrap');
            const cacEl = document.getElementById('hud-cac-score');
            const dirWrap = document.getElementById('hud-direction-wrap');
            const dirEl = document.getElementById('hud-direction');
            const ca = (strat.analytics || {}).context_alignment;
            if (ca && cacWrap && cacEl) {
                const caLabel = ca.label || 'LOW';
                const caScore = ca.alignment_score || 0;
                cacEl.className = `hud-value cac-${caLabel.toLowerCase()}`;
                cacEl.textContent = `${caScore}/4 ${caLabel}`;
                const axisDetail = ca.axes ? Object.entries(ca.axes).map(([k, v]) =>
                    `${k}: ${v.aligned ? '●' : '○'} ${v.detail}`).join('\n') : '';
                cacEl.setAttribute('data-tooltip', _t('hud.tooltip.context_align') + '\n' + axisDetail);
                cacWrap.style.display = caScore > 0 ? '' : 'none';
            } else if (cacWrap) {
                cacWrap.style.display = 'none';
            }
            const ds = (strat.analytics || {}).direction_summary;
            if (ds && dirWrap && dirEl) {
                const dom = ds.dominant_direction || 'UNKNOWN';
                const short = { 'ADVERSARY_OFFENSIVE': '⚔ ADV', 'FRIENDLY_DEFENSIVE': '🛡 FRD', 'TARGET_IMPACT': '⚡ TGT', 'UNKNOWN': '? UNK' };
                dirEl.textContent = short[dom] || dom;
                dirEl.setAttribute('data-tooltip', `${_t('hud.tooltip.direction')}\nADV:${ds.adversary_offensive} FRD:${ds.friendly_defensive} TGT:${ds.target_impact} UNK:${ds.unknown}\nClarity: ${((ds.direction_clarity || 0) * 100).toFixed(0)}%`);
                dirWrap.style.display = (ds.adversary_offensive > 0 || ds.target_impact > 0) ? 'inline-flex' : 'none';
            } else if (dirWrap) {
                dirWrap.style.display = 'none';
            }

            // Scenario chip — show focused scenario name (replaces Epicenter)
            if (scenarioNameEl) {
                const focusedId = data.focused_scenario || '';
                const sc = (data.scenarios || {})[focusedId];
                const lang = (typeof _currentLang !== 'undefined') ? _currentLang : 'en';
                let dispName = focusedId || _t('hud.scenario.none');
                if (sc) dispName = lang === 'ja' ? (sc.name_ja || sc.name_en || focusedId) : (sc.name_en || focusedId);
                scenarioNameEl.textContent = dispName;
            }

            // Phase 5-6: HUD max-overlap pill switched from raw % to IDF.
            // Color cutoffs mirror the Coord-link tiers (A-2): IDF >= 1.5 is
            // a real outlier, 1.0 is mid, below is noise. Raw % saturated at
            // P50≈53% in normal ops so the prior 40/20 thresholds were
            // miscalibrated against the actual distribution.
            const _idfPairs = strat.correlations_idf_l3 || strat.correlations_idf || {};
            if (Object.keys(_idfPairs).length > 0) {
                const maxEntry = Object.entries(_idfPairs).reduce((a, b) => b[1] > a[1] ? b : a, ['—', 0]);
                const maxIdf = Number(maxEntry[1]) || 0;
                const color = maxIdf >= 1.5 ? '#ff2a2a' : maxIdf >= 1.0 ? '#ffaa00' : '#888';
                overlapEl.innerHTML = `<span style="color:${color}">${esc(maxEntry[0])}: ${maxIdf.toFixed(2)} IDF</span>`;
                overlapEl.setAttribute('data-tooltip', Object.entries(_idfPairs).map(([k,v]) => `${k}: ${Number(v).toFixed(2)} IDF`).join('\n') + '\n(see map: Origin Overlap layer)');
            } else {
                overlapEl.innerHTML = _t('ui.none');
            }
            
            if (strat.vector_shifts && strat.vector_shifts.length > 0) {
                shiftEl.innerHTML = `<span class="alert-text">${esc(strat.vector_shifts.join(', '))}</span>`;
            } else {
                shiftEl.innerText = "None";
            }

            let strikesText = "None";
            if (strat.adversary_strikes && strat.adversary_strikes.length > 0) {
                let arr = [];
                strat.adversary_strikes.forEach(strike => { arr.push(`<span class="warn-text">${esc(strike.actor)}➔${esc(strike.target)} (x${esc(strike.spike)})</span>`); });
                strikesText = arr.join(' | ');
            }
            strikesEl.innerHTML = strikesText;

            // ADR-V2-006 A-2: prefer country_* lists; fall back to legacy theater_* lists.
            const _degradedList = strat.degraded_countries ?? strat.degraded_theaters;
            const degraded = _degradedList && _degradedList.length > 0 ? esc(_degradedList.join(', ')) : "None";
            outagesEl.innerHTML = `<span class="${degraded !== 'None' ? 'warn-text' : ''}">${degraded}</span>`;

            if (coordinatedEl) {
                const _coordinatedList = strat.coordinated_countries ?? strat.coordinated_theaters;
                if (_coordinatedList && _coordinatedList.length >= 2) {
                    coordinatedEl.innerHTML = `<span class="alert-text">ACTIVE [${esc(_coordinatedList.join(', '))}]</span>`;
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

            // NP6 transparency: prefer the v2 drill-down (formula / thresholds /
            // sources / llm_prompt / calibration) over the v1 evidence panel
            // when a fresh threat_level conclusion is cached. Falls back to
            // the v1 panel when v2 is degraded or the conclusion has no id —
            // keeps the surface usable during the v1 sunset window (NP3).
            threatEl.onclick = () => {
                const byType = _hudFreshEnvelopeByType(data.focused_scenario);
                const tlC = byType && byType.threat_level;
                if (tlC && tlC.id && tlC.conclusion_unavailable_reason == null) {
                    _ccOpenDrillModal(tlC);
                    return;
                }
                openEvidencePanel(strat);
            };

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
            // Ambush Alert (exception banner item)
            const ambushWrap = document.getElementById('hud-ambush-wrap');
            if (ambushWrap) ambushWrap.style.display = p8.is_ambush ? 'inline-flex' : 'none';

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

            // A3: Triangulation indicator (exception banner)
            const triEl = document.getElementById('hud-triangulation');
            if (triEl) triEl.style.display = p8.triangulation?.is_triangulated ? 'inline-flex' : 'none';

            // A1: Silent Divergence indicator (exception banner)
            const sdEl = document.getElementById('hud-silent-div');
            const sdText = document.getElementById('hud-silent-text');
            if (sdEl && p8.silent_divergence) {
                const sd = p8.silent_divergence;
                sdEl.style.display = sd.detected ? 'inline-flex' : 'none';
                if (sdText && sd.detected) {
                    sdText.textContent = sd.confidence;
                }
            } else if (sdEl) {
                sdEl.style.display = 'none';
            }

            // A2: Country Baseline Z-score (legacy key: theater_baseline)
            const baseZEl = document.getElementById('hud-baseline-z');
            const _baselineSrc = p8.country_baseline ?? p8.theater_baseline;
            if (baseZEl && _baselineSrc) {
                const tb = _baselineSrc;
                if (tb.samples >= 20) {
                    const z = tb.z_score;
                    baseZEl.textContent = (z >= 0 ? '+' : '') + z.toFixed(1) + 'σ';
                    baseZEl.style.color = z > 2.0 ? '#ff2200' : z > 1.0 ? '#ffaa00' : z < -1.0 ? '#66ffaa' : '#aaa';
                } else {
                    baseZEl.textContent = `(n=${tb.samples})`;
                    baseZEl.style.color = '#555';
                }
            }

            // ── HUD additions: TL duration / ETA / HOD-Z / INTEL / domain split ──
            _updateNewHudChips(data, strat, p8);

            // ── v9 new sensor panel update ───────────────────────────────
            const gnEl = document.getElementById('gn-panel');
            if (gnEl && gnEl.style.display !== 'none') {
                updateGreyNoisePanel(p8);
                gnEl.dataset.dirty = '';
            } else if (gnEl) {
                gnEl.dataset.dirty = '1';
            }
            // ── Intuition UI integrated call ───────────────────────────
            applyAmbientAtmosphere(strat.threat_level);
            updateRadioSilence(p8, strat);

            // ── Threat Situation Map (TSM) ──────────────────────────────
            const coreCode  = resolveChainTargetCountry(strat);
            const coreTgt   = (data.targets || []).find(t => t.code === coreCode);
            const coreCoord = coreTgt ? {lat: coreTgt.lat, lng: coreTgt.lng} : null;
            updateThreatHalo(strat, coreCoord);
            updateSensorMarkers(strat, coreCoord);
            updateDrilldown(strat);

            // Refresh open/visible panels only; mark hidden ones dirty for on-show render
            const _panelRenders = [
                ['weather-brief-panel', renderWeatherBrief],
                ['corr-heatmap-panel', renderCorrHeatmap],
            ];
            for (const [pid, fn] of _panelRenders) {
                const el = document.getElementById(pid);
                if (!el) continue;
                if (el.style.display !== 'none' || el.closest('#left-sidebar')) {
                    fn();
                    el.dataset.dirty = '';
                } else {
                    el.dataset.dirty = '1';
                }
            }
        }

        // ── Sensor Fleet Health HUD ──
        _updateSensorHealthHUD(data.sensor_health);

        // ── Scenario Bar ──
        renderScenarioBar(data);

        const originContainer = document.getElementById('origin-list-container');
        targetLayer.clearLayers(); sourceLayer.clearLayers(); lineLayer.clearLayers(); iodaLayer.clearLayers();
        participantLayer.clearLayers();
        let originHtml = "";

        // ── Role-based participant markers ──────────────────────────────
        // Role → visual class mapping (NATO convention)
        const _ROLE_CLASS = {
            'primary_target': 'target', 'principal_belligerent': 'target',
            'adversary': 'hostile',
            'primary_ally': 'friendly', 'forward_base': 'friendly',
            'secondary_ally': 'friendly', 'extended_deterrence': 'friendly',
            'force_projection': 'friendly',
            'proxy_front': 'volatile', 'spillover_risk': 'volatile',
            'secondary_party': 'volatile',
            'strategic_observer': 'observer', 'regional_power': 'observer',
        };
        const _participants = data.participants || {};
        Object.keys(_participants).forEach(cc => {
            const p = _participants[cc];
            if (p.active) return; // active countries get full target markers below
            const cls = _ROLE_CLASS[p.role] || 'observer';
            // Size: 20-32px based on weight
            const sz = Math.round(20 + (p.weight || 0.5) * 12);
            const icon = L.divIcon({
                className: '',
                html: `<div class="participant-marker pm-${cls}" style="width:${sz}px;height:${sz}px;"><div class="pm-dot"></div><div class="pm-label">${cc}</div></div>`,
                iconSize: [sz, sz], iconAnchor: [sz / 2, sz / 2],
            });
            L.marker([p.lat, shiftLng(p.lng)], { icon: icon, interactive: true })
                .bindTooltip(`<b>${p.name}</b> — ${_t('scenario.role.' + p.role)}`, { direction: 'top' })
                .on('click', () => openCountryDetail(cc))
                .addTo(participantLayer);
        });

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
            originHtml = `<div style='color:grey; padding: 10px;'>${_t('dash.no_active_pins')}</div>`;
        } else if (data.targets && data.targets.length > 0) {
            const vecShareKey = currentVector === 'l3' ? 'global_share_l3' : currentVector === 'l7' ? 'global_share_l7' : 'global_share';
            data.targets.sort((a, b) => (b[vecShareKey] || 0) - (a[vecShareKey] || 0)).forEach(t => {
                if (!displayTargets.includes(t.code)) return;

                const isOutage = t.is_bgp_outage;
                const isEffOutage = t.is_bgp_effective;
                
                let targetClass = "target-normal";
                if (isOutage) {
                    targetClass = isEffOutage ? "target-degraded" : "target-weather";
                }

                // Role-based marker class (NATO color convention)
                const roleClass = t.role ? ('role-' + (_ROLE_CLASS[t.role] || 'observer')) : '';

                const intel = ((data.strategic_alert || {}).country_intel || {})[t.code] || {};
                const iodaSt = intel.ioda_status || "NORMAL";
                const ixpCnt = intel.ixp_count || 0;
                const gdeltD = intel.gdelt;
                const airspD = intel.airspace;

                let badges = '';
                if (isOutage) {
                    if (isEffOutage) {
                        badges += `<span class="tm-badge tm-badge-bgp" data-tooltip="${_t('tooltip.bgp_outage')}">${_t('badge.bgp_outage')}</span>`;
                    } else {
                        badges += `<span class="tm-badge" style="border:1px solid #ffaa00; color:#ffaa00; background:rgba(255,170,0,0.18);" data-tooltip="${_t('tooltip.bgp_wx')}">${_t('badge.bgp_wx')}</span>`;
                    }
                } else if (iodaSt === "BGP_OUTAGE") {
                    badges += `<span class="tm-badge" style="border:1px solid #ffaa00; color:#ffaa00; background:rgba(255,170,0,0.18);" data-tooltip="${_t('tooltip.bgp_wx')}">${_t('badge.bgp_wx')}</span>`;
                }

                if (ixpCnt > 0)
                    badges += `<span class="tm-badge tm-badge-ixp">IXP×${ixpCnt}</span>`;

                if (gdeltD) {
                    if (gdeltD.status === "ALERT") {
                        badges += `<span class="tm-badge tm-badge-gdelt" data-tooltip="${_t('tooltip.media_alert')}">${_t('badge.media_alert')}</span>`;
                    } else if (gdeltD.status === "WEATHER_NOISE") {
                        badges += `<span class="tm-badge" style="border:1px solid #aaa; color:#aaa; background:rgba(170,170,170,0.15);" data-tooltip="${_t('tooltip.media_wx')}">${_t('badge.media_wx')}</span>`;
                    }
                }

                if (airspD && airspD.severity && airspD.severity !== "NORMAL") {
                    if (airspD.status === "WEATHER_NOISE") {
                        badges += `<span class="tm-badge" style="border:1px solid #aaa; color:#aaa; background:rgba(170,170,170,0.15);" data-tooltip="${_t('tooltip.airspace_wx')}">${_t('badge.airspace_wx')}</span>`;
                    } else {
                        badges += `<span class="tm-badge tm-badge-air" data-tooltip="Airspace Anomaly">✈</span>`;
                    }
                }

                // Scale marker by participant weight (0.0-1.0 → 56-80px)
                const _pw = t.participant_weight || 1.0;
                const _mSize = Math.round(56 + _pw * 24);
                const _mHalf = Math.round(_mSize / 2);
                const _ringOff = Math.round((_mSize - 80) / 2);  // offset for ring centering
                const dynamicIcon = L.divIcon({
                    className: '',
                    html: `<div class="target-marker-wrapper ${targetClass} ${roleClass}" style="width:${_mSize}px;height:${_mSize}px;"><div class="ddos-ring" style="width:${_mSize}px;height:${_mSize}px;"></div><div class="ddos-core" style="top:${_mHalf - 5}px;left:${_mHalf - 5}px;"></div>${badges ? `<div class="tm-badges-wrap">${badges}</div>` : ''}</div>`,
                    iconSize: [_mSize, _mSize], iconAnchor: [_mHalf, _mHalf], popupAnchor: [0, -_mHalf]
                });

                let targetLngShifted = shiftLng(t.lng);
                
                const netStatusTextTip = isOutage ? (isEffOutage ? _t('map.net.tooltip_outage') : _t('map.net.tooltip_wx')) : _t('map.net.tooltip_ok');

                const _roleTip = t.role ? ` [${_t('scenario.role.' + t.role)}]` : '';
                L.marker([t.lat, targetLngShifted], { icon: dynamicIcon })
                 .bindTooltip(`<b>${t.info}</b>${_roleTip} — ${netStatusTextTip}`, { direction: 'top', sticky: false })
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
                const shiftBadge = t.is_vector_shift ? `<span class="shift-badge" data-tooltip="${_t('tooltip.l7_shift', {actors: shiftActorStr})}">${_t('badge.l7_shift')}${shiftActorStr}</span>` : "";

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
                        const newActorBadge = s.is_new_actor ? `<span class="new-actor-badge" data-tooltip="${_t('tooltip.new_actor')}">${_t('badge.new_actor')}</span>` : "";
                        const asnLabel = s.state_asns && s.state_asns.length > 0 ? s.state_asns.join(',') : '';
                        const stateAsnBadge = s.is_state_asn ? `<span class="state-asn-badge" data-tooltip="${_t('tooltip.state_asn', {asns: asnLabel})}">${_t('badge.state_asn')}</span>` : "";
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
                        // noClip: prevent Leaflet from clipping the SVG path to the viewport,
                        // which would shorten getTotalLength() and distort dot size / speed.
                        L.polyline(curvePoints, { color: lineColor, weight: dynamicLineWidth + 2, opacity: trackOpacity, interactive: false, noClip: true }).addTo(lineLayer);
                        // Layer 2: firefly dots — fixed 8px dot size and constant px/s speed regardless of arc length
                        const pl = L.polyline(curvePoints, { className: `attack-curve ${speedClass}`, color: lineColor, weight: dynamicLineWidth, opacity: lineOpacity, interactive: false, noClip: true }).addTo(lineLayer);
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
            _renderSignalOverlays(overlays, targetCodesSet);
            _renderPhysicalInfraOverlays(overlays);
            _renderMilitaryTrackOverlays(overlays);
        }

        originContainer.innerHTML = originHtml;

        // ── Intuition UI: Threat Terrain + Overlap Links ──
        updateThreatTerrain(data);
        updateCoordinationIndex(data);

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

            // Respect saved visibility for both docked and floating panels
            const isVisible = state.visible !== false;
            if (state.docked && placeholder) {
                placeholder.appendChild(panel);
                panel.classList.remove('floating', 'active'); panel.classList.add('docked');
                panel.style.left = ''; panel.style.top = ''; panel.style.width = ''; panel.style.height = '';
                panel.style.display = isVisible ? 'flex' : 'none';
                if (dockBtn) dockBtn.style.display = 'none';
            } else {
                document.body.appendChild(panel);
                panel.classList.remove('docked'); panel.classList.add('floating');
                if (isVisible) panel.classList.add('active');
                panel.style.top   = state.top   || '';
                panel.style.left  = state.left  || '';
                panel.style.width = state.width || '';
                panel.style.height = state.height || '';
                panel.style.display = isVisible ? 'flex' : 'none';
                if (dockBtn) dockBtn.style.display = 'inline-block';
            }

            // Fire onShow callback so restored panels load their data
            if (isVisible) {
                const cb = _panelCallbacks[id];
                if (cb && cb.onShow) cb.onShow();
            }
        });
        updateSidebarVisibility();
        syncToolsMenuState();
    }

    const LAYOUT_VERSION = 15; // bump when layout structure changes to auto-clear stale state

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
            let stateObj;
            try { stateObj = JSON.parse(savedState); } catch(e) { stateObj = {}; }
            // If saved layout version is outdated, discard only the layout portion
            if (!stateObj.layoutVersion || stateObj.layoutVersion < LAYOUT_VERSION) {
                delete stateObj.layout;
            }

            renderQuickToggles();

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
            renderQuickToggles();
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
        // Scope pickers were removed; only display-layer toggles (if any) still fire here.
        if (e.target.matches('.check-display')) {
            saveLocalState();
            if (latestData) renderTelemetry(latestData);
        }
    });

    async function initApp() {
        // Display logged-in username + role in the hamburger user section
        const _storedUser = localStorage.getItem('radar_username');
        const _storedRole = localStorage.getItem('radar_role');
        if (_storedUser) {
            const nameEl = document.getElementById('hud-username');
            const roleEl = document.getElementById('hud-user-role');
            const avEl   = document.getElementById('hud-user-avatar');
            if (nameEl) nameEl.textContent = _storedUser;
            if (roleEl) roleEl.textContent = _storedRole || 'viewer';
            if (avEl)   avEl.textContent = (_storedUser[0] || '?').toUpperCase();
        }

        let defaults = {
            default_focused_scenario: "taiwan_contingency"
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
        if (typeof io !== 'undefined') {
            try {
                const _wsToken = localStorage.getItem('radar_access_token') || '';
                _wsSocket = io({ transports: ['websocket', 'polling'], auth: { token: _wsToken } });
                _wsSocket.on('connect', () => {
                    _wsConnected = true;
                    const core = getCurrentConfig().core || '';
                    if (!core) return;
                    _wsSubscribedTheater = core;
                    _wsSocket.emit('subscribe_theater', core);
                    console.log('[WS] Connected, subscribed to', core);
                    const dot = document.getElementById('ws-status-dot');
                    if (dot) dot.className = 'ws-dot ws-dot-connected';
                });
                _wsSocket.on('disconnect', () => {
                    _wsConnected = false;
                    _wsSubscribedTheater = '';
                    console.log('[WS] Disconnected — polling fallback active');
                    const dot = document.getElementById('ws-status-dot');
                    if (dot) dot.className = 'ws-dot ws-dot-disconnected';
                });
                _wsSocket.on('threat_update', (data) => {
                    // WS pushes only strategic_alert — merge into existing latestData
                    // instead of replacing, so that targets/sensor_health/etc. are preserved.
                    if (latestData) {
                        latestData.strategic_alert = data;
                        latestData.timestamp = new Date().toISOString();
                    } else {
                        latestData = { strategic_alert: data, targets: [], timestamp: new Date().toISOString() };
                    }
                    _lastSyncTime = Date.now();
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
                    if (!data || typeof data.sensor !== 'string' || typeof data.status !== 'string') return;
                    // Guard against prototype pollution via crafted sensor names
                    if (data.sensor === '__proto__' || data.sensor === 'constructor' || data.sensor === 'prototype') return;
                    console.info('[WS] Sensor status:', data.sensor, data.status);
                    // Preserve existing object fields (domain, last_fetch_ts, cb_state) when WS only sends status string
                    const prev = _sensorHealthCache[data.sensor];
                    if (prev && typeof prev === 'object') {
                        _sensorHealthCache[data.sensor] = { ...prev, status: data.status, cb_state: data.status === 'CIRCUIT_OPEN' ? 'OPEN' : prev.cb_state };
                    } else {
                        _sensorHealthCache[data.sensor] = data.status;
                    }
                    _updateSensorHealthHUD(_sensorHealthCache);
                });

                // LLM Intel real-time update: refresh intel panel when new item arrives
                _wsSocket.on('intel_update', (data) => {
                    console.info('[WS] Intel update:', data.source_type, data.status, data.headline);
                    if (typeof _fetchLlmIntel === 'function') _fetchLlmIntel();
                });
            } catch (e) {
                console.warn('[WS] Socket.IO init failed, using polling fallback:', e);
            }
        }
        // Periodic refresh: always poll to trigger server-side scoring + WS push
        // WS delivers real-time alerts (ambush, sensor status) between polls
        const _POLL_HIDDEN_MS = 60 * 60 * 1000; // 60 min when tab hidden
        let _pollTimer = setInterval(() => fetchDDoSData(false), _POLL_INTERVAL_MS);

        document.addEventListener('visibilitychange', () => {
            clearInterval(_pollTimer);
            if (document.hidden) {
                // Reduce polling when analyst is in another tab
                _pollTimer = setInterval(() => fetchDDoSData(false), _POLL_HIDDEN_MS);
                console.info('[Poll] Tab hidden — reduced to 60min interval');
            } else {
                // Immediate catch-up fetch, then resume normal interval
                fetchDDoSData(false);
                _pollTimer = setInterval(() => fetchDDoSData(false), _POLL_INTERVAL_MS);
                console.info('[Poll] Tab visible — resumed normal interval');
            }
        });
    }
    
    // Boot sequence
    initApp();

    function openCountryDetail(code) {
        if (!latestData) return;
        const strat   = latestData.strategic_alert || {};
        const intel   = (strat.country_intel || {})[code] || {};
        const tgtData = (latestData.targets || []).find(t => t.code === code) || {};
        const coordName = (resolveChainTargetCountry(strat) === code ? _t('cip.role.core') : _t('cip.role.link'));

        document.getElementById('country-modal-title').textContent = _t('cip.modal_title', {name: tgtData.info || code, code: code});

        const spike    = tgtData.avg_spike   != null ? `${tgtData.avg_spike.toFixed(2)}x` : '—';
        const shareL3  = tgtData.global_share_l3 != null ? `${tgtData.global_share_l3.toFixed(2)}%` : '—';
        const shareL7  = tgtData.global_share_l7 != null ? `${tgtData.global_share_l7.toFixed(2)}%` : '—';
        const shift    = tgtData.is_vector_shift ? `<span class="cip-warn">${_t('cip.l7shift.active')}</span>` : `<span style="color:#555">${_t('cip.l7shift.none')}</span>`;
        
        const iodaSt   = intel.ioda_status || 'NORMAL';
        const isEffDeg = intel.is_bgp_degraded;
        const iodaDetail = intel.ioda_detail || null;
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
        // Build IODA datasource detail sub-text
        let iodaSubHtml = '';
        if (iodaDetail && iodaDetail.sources) {
            const srcEntries = Object.entries(iodaDetail.sources);
            if (srcEntries.length) {
                iodaSubHtml = srcEntries.map(([ds, info]) => {
                    const lvl = info.level || 'normal';
                    const col = lvl === 'critical' ? '#ff4444' : lvl === 'warning' ? '#ffaa00' : '#555';
                    return `<span style="color:${col};font-size:10px;">${esc(ds)}: ${esc(lvl)}</span>`;
                }).join(' · ');
            }
        }
        if (intel.ioda_source) {
            const srcLabel = intel.ioda_source === 'ioda_proper' ? 'IODA' : intel.ioda_source === 'cf_fallback' ? 'CF Radar' : esc(intel.ioda_source);
            iodaSubHtml = (iodaSubHtml ? iodaSubHtml + '<br>' : '') + `<span style="color:#888;font-size:10px;">src: ${srcLabel}</span>`;
        }

        const sortedSrc = ((tgtData.sources || []).filter(s => s.weight > 0)
            .sort((a, b) => b.spike_factor - a.spike_factor)).slice(0, 5);
        const srcHtml = sortedSrc.length
            ? `<ul class="cip-sources-list">${sortedSrc.map(s =>
                `<li><span>${esc(s.name)} [${esc(s.code)}]${s.is_state_asn ? ` <b style="color:#ff4444">${_t('cip.state_asn_badge')}</b>` : ''}</span>
                <span style="color:#ffaa00">${_t('cip.spike_label', {n: s.spike_factor})}</span></li>`
              ).join('')}</ul>`
            : `<span style="color:#555;font-size:12px;">${_t('cip.no_sources')}</span>`;

        const wx     = intel.weather || {};
        const wxTxt  = wx.condition
            ? `${esc(wx.condition)} — ${esc(wx.description || '')} (wind ${esc(String(wx.wind_speed || 0))}m/s)`
            : '—';
        const wxSev  = wx.severity || 'NORMAL';
        const wxCol  = wxSev === 'SEVERE' ? 'cip-alert' : wxSev === 'MODERATE' ? 'cip-warn' : 'cip-ok';

        const air    = intel.airspace || {};
        const airTxt = air.status
            ? `${esc(air.airport || '?')}: ${_t('unit.aircraft', {n: air.count != null ? air.count : '?'})} (base ${air.baseline_avg != null ? air.baseline_avg : '?'})`
            : '—';
        const airCol = (air.status === 'CLOSURE' || air.status === 'ANOMALY') ? 'cip-alert'
                     : air.status === 'WEATHER_NOISE' ? 'cip-warn' : 'cip-ok';
        const airLbl = air.status || '—';

        const bgpR   = intel.bgp_routing || {};
        const bgpTxt = bgpR.announced_prefixes != null
            ? `${bgpR.announced_prefixes} pfx / ${bgpR.seen_ases || '?'} ASes`
            : '—';
        const bgpCol = bgpR.is_anomaly ? 'cip-alert' : 'cip-ok';
        let bgpLbl = bgpR.is_anomaly ? `⚠ DROP ${bgpR.drop_pct}%` : (bgpR.status || '—');
        if (bgpR.prefix_trend) {
            const trendCol = bgpR.prefix_trend === 'WITHDRAWING' ? '#ff4444' : bgpR.prefix_trend === 'GROWING' ? '#00ff88' : '#888';
            const trendPct = bgpR.prefix_trend_pct != null ? ` (${bgpR.prefix_trend_pct > 0 ? '+' : ''}${bgpR.prefix_trend_pct.toFixed(1)}%)` : '';
            bgpLbl += ` <span style="color:${trendCol};font-size:10px;">${esc(bgpR.prefix_trend)}${trendPct}</span>`;
        }

        const gdelt  = intel.gdelt || {};
        const gdTone = gdelt.tone_current != null ? gdelt.tone_current.toFixed(1) : '—';
        const gdBase = gdelt.tone_baseline != null ? gdelt.tone_baseline.toFixed(1) : '—';
        const gdDelta= gdelt.delta != null ? `${gdelt.delta > 0 ? '+' : ''}${gdelt.delta.toFixed(1)}` : '—';
        const gdCol  = gdelt.status === 'ALERT' ? 'cip-alert' : gdelt.status === 'WEATHER_NOISE' ? 'cip-warn' : 'cip-ok';
        const gdLbl  = gdelt.status || '—';

        const ixpCnt   = intel.ixp_count || 0;
        const ixpNames = (intel.ixp_names || []).slice(0, 4).join(', ') || '—';

        // IHR data
        const ihrSt    = intel.ihr_status || 'NORMAL';
        const ihrDisco = intel.ihr_disco || [];
        const ihrCol   = ihrSt === 'DISCO_EVENT' ? 'cip-alert' : ihrSt === 'HEGEMONY_ALARM' ? 'cip-warn' : ihrSt === 'DELAY_ANOMALY' ? 'cip-warn' : 'cip-ok';
        const ihrTxt   = ihrSt === 'DISCO_EVENT' ? _t('cip.ihr.disco')
                       : ihrSt === 'HEGEMONY_ALARM' ? _t('cip.ihr.hegemony')
                       : ihrSt === 'DELAY_ANOMALY' ? _t('cip.ihr.delay')
                       : _t('cip.ihr.normal');
        const ihrSub   = ihrDisco.length ? _t('cip.ihr.events', {n: ihrDisco.length}) : '';

        // RIPE Atlas data
        const atlasD   = intel.ripe_atlas || {};
        const atlasSt  = atlasD.status || 'NORMAL';
        const atlasCol = atlasSt === 'PROBE_BLACKOUT' ? 'cip-alert' : atlasSt === 'PROBE_DROP' ? 'cip-warn' : 'cip-ok';
        const atlasTxt = atlasSt === 'PROBE_BLACKOUT' ? _t('cip.atlas.probe_blackout')
                       : atlasSt === 'PROBE_DROP' ? _t('cip.atlas.probe_drop')
                       : _t('cip.atlas.normal');
        const atlasProbes = atlasD.probes || {};
        const atlasSub = atlasProbes.active != null ? _t('cip.atlas.probes', {n: atlasProbes.active}) : '';
        const atlasLat = atlasD.latency || {};
        const atlasRtt = atlasLat.avg_ms != null ? _t('cip.atlas.rtt', {avg: atlasLat.avg_ms, p95: atlasLat.p95_ms}) : '—';

        // Tor Metrics data
        const torD     = intel.tor_metrics || {};
        const torSt    = torD.status || 'NORMAL';
        const torCol   = torSt === 'CENSORSHIP_INDICATOR' ? 'cip-alert' : torSt === 'RELAY_DROP' ? 'cip-warn' : torSt === 'USER_SURGE' ? 'cip-warn' : 'cip-ok';
        const torTxt   = torSt === 'CENSORSHIP_INDICATOR' ? _t('cip.tor.censorship')
                       : torSt === 'RELAY_DROP' ? _t('cip.tor.relay_drop')
                       : torSt === 'USER_SURGE' ? _t('cip.tor.user_surge')
                       : _t('cip.tor.normal');
        const torRelays  = torD.relays || {};
        const torClients = torD.clients || {};
        const torSub   = torRelays.running != null ? _t('cip.tor.relays', {n: torRelays.running, b: torRelays.bridges || 0}) : '';
        const torUsers = torClients.bridge_users != null ? _t('cip.tor.users', {n: torClients.bridge_users}) : '';

        document.getElementById('country-modal-body').innerHTML = `
        <div class="cip-header">
            <div class="cip-flag">🌐</div>
            <div>
                <div class="cip-title">${esc(tgtData.info || code)}</div>
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
                    ${iodaSubHtml ? `<div class="cip-card-sub">${iodaSubHtml}</div>` : ''}
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
            <div class="cip-section-title">${_t('cip.section.network')}</div>
            <div class="cip-grid">
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.ihr_disco')}</div>
                    <div class="cip-card-value ${ihrCol}">${ihrTxt}</div>
                    ${ihrSub ? `<div class="cip-card-sub">${ihrSub}</div>` : ''}
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.ripe_atlas')}</div>
                    <div class="cip-card-value ${atlasCol}">${atlasTxt}</div>
                    ${atlasSub ? `<div class="cip-card-sub">${atlasSub}</div>` : ''}
                </div>
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.ripe_latency')}</div>
                    <div class="cip-card-value">${atlasRtt}</div>
                </div>
            </div>
        </div>

        <div class="cip-section">
            <div class="cip-section-title">${_t('cip.section.censorship')}</div>
            <div class="cip-grid">
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.tor_metrics')}</div>
                    <div class="cip-card-value ${torCol}">${torTxt}</div>
                    ${torSub ? `<div class="cip-card-sub">${torSub}</div>` : ''}
                </div>
                ${torUsers ? `<div class="cip-card">
                    <div class="cip-card-label">Bridge Users</div>
                    <div class="cip-card-value">${torUsers}</div>
                </div>` : ''}
            </div>
        </div>

        <div class="cip-section">
            <div class="cip-section-title">${_t('cip.section.info')}</div>
            <div class="cip-grid">
                <div class="cip-card">
                    <div class="cip-card-label">${_t('cip.label.current_tone')}</div>
                    <div class="cip-card-value ${gdCol}">${gdTone}</div>
                    <div class="cip-card-sub">${_t('cip.label.baseline_28d', {base: gdBase, delta: gdDelta})}</div>
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
            const p8Theater = resolveChainTargetCountry(strat) || '—';
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
            const isrTxt = isrCnt !== null ? _t('unit.aircraft', {n: isrCnt}) : '—';
            const isrCol = isrCnt >= 3 ? 'cip-warn' : 'cip-ok';
            const aisCnt = p8.ais ? (p8.ais.dark_gaps || 0) : null;
            const aisTxt = aisCnt !== null ? _t('unit.vessels', {n: aisCnt}) : '—';
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
            let convHtml = Object.entries(strat.domains).map(([d, info]) =>
                `<div class="convergence-item"><span class="rat-domain-${d}">${d.toUpperCase()}</span>: <span class="conv-val">${info.score}pt</span> × ${info.weight} = <b style="color:#fff">${info.weighted}</b></div>`
            ).join('');
            if (strat.convergence_score !== undefined) {
                convHtml += `<div class="convergence-item" style="margin-left:8px; border-left:2px solid #555; padding-left:8px;">${_t('evidence.convergence_score')}: <span class="conv-val">${strat.convergence_score}</span></div>`;
            }
            // CAC: Context Alignment display
            const ca = (strat.analytics || {}).context_alignment;
            if (ca) {
                const cacClass = `cac-${(ca.label || 'LOW').toLowerCase()}`;
                convHtml += `<div class="convergence-item cac-summary" style="margin-left:8px; border-left:2px solid #555; padding-left:8px;">`;
                convHtml += `<span class="${cacClass}">${_t('evidence.context_alignment')}: ${ca.alignment_score}/4 (${ca.label})</span>`;
                if (ca.axes) {
                    convHtml += `<div class="cac-axes">`;
                    for (const [axis, info] of Object.entries(ca.axes)) {
                        const dot = info.aligned ? '●' : '○';
                        const axisColor = info.aligned ? '#00ffff' : '#444';
                        convHtml += `<span style="color:${axisColor}; margin-right:8px; cursor:help;" data-tooltip="${_escAttr(info.detail || '')}">${dot} ${_t('cac.axis.' + axis)}</span>`;
                    }
                    convHtml += `</div>`;
                }
                convHtml += `</div>`;
            }
            // CAC: Direction Summary
            const ds = (strat.analytics || {}).direction_summary;
            if (ds && ds.dominant_direction !== 'UNKNOWN') {
                const dirLabels = { 'ADVERSARY_OFFENSIVE': _t('dir.adversary'), 'FRIENDLY_DEFENSIVE': _t('dir.friendly'), 'TARGET_IMPACT': _t('dir.target'), 'UNKNOWN': _t('dir.unknown') };
                const dirColors = { 'ADVERSARY_OFFENSIVE': '#ff2a2a', 'FRIENDLY_DEFENSIVE': '#00cc66', 'TARGET_IMPACT': '#ffaa00', 'UNKNOWN': '#555' };
                const adv = ds.adversary_offensive || 0;
                const frd = ds.friendly_defensive || 0;
                const tgt = ds.target_impact || 0;
                const total = adv + frd + tgt;
                convHtml += `<div class="convergence-item" style="margin-left:8px; border-left:2px solid #555; padding-left:8px;">`;
                convHtml += `<span style="color:${dirColors[ds.dominant_direction]}">${_t('evidence.direction')}: ${dirLabels[ds.dominant_direction]} (${(ds.direction_clarity * 100).toFixed(0)}%)</span>`;
                if (total > 0) {
                    const advPct = (adv / total * 100).toFixed(1);
                    const frdPct = (frd / total * 100).toFixed(1);
                    const tgtPct = (tgt / total * 100).toFixed(1);
                    convHtml += `<div class="dir-bar" style="display:flex;height:10px;margin-top:4px;border-radius:2px;overflow:hidden;background:#1a1a1a;border:1px solid #333;"
                        data-tooltip="${_t('dir.adversary')}: ${adv} (${advPct}%) / ${_t('dir.friendly')}: ${frd} (${frdPct}%) / ${_t('dir.target')}: ${tgt} (${tgtPct}%)">`;
                    if (adv > 0) convHtml += `<div style="width:${advPct}%;background:#ff2a2a;" title="${_t('dir.adversary')}: ${adv}"></div>`;
                    if (frd > 0) convHtml += `<div style="width:${frdPct}%;background:#00cc66;" title="${_t('dir.friendly')}: ${frd}"></div>`;
                    if (tgt > 0) convHtml += `<div style="width:${tgtPct}%;background:#ffaa00;" title="${_t('dir.target')}: ${tgt}"></div>`;
                    convHtml += `</div>`;
                    convHtml += `<div style="display:flex;justify-content:space-between;font-size:9px;color:#888;margin-top:2px;">
                        <span style="color:#ff2a2a;">${_t('dir.adversary')} ${adv}</span>
                        <span style="color:#00cc66;">${_t('dir.friendly')} ${frd}</span>
                        <span style="color:#ffaa00;">${_t('dir.target')} ${tgt}</span>
                    </div>`;
                }
                convHtml += `</div>`;
            }
            convEl.innerHTML = convHtml;
        } else {
            convEl.innerHTML = '';
        }

        document.getElementById('evidence-system-note').textContent =
            strat.system_note || _t('evidence.no_system_note');

        const nf = strat.noise_filters_applied;
        document.getElementById('evidence-noise-filters').textContent =
            (nf && nf.length > 0) ? nf.join(', ') : _t('evidence.none');

        const tbody = document.getElementById('evidence-tbody');
        if (strat.rationale_matrix && strat.rationale_matrix.length > 0) {
            // Group by domain: cyber → physical → info → others
            const _domainOrder = ['cyber', 'physical', 'info'];
            const _grouped = {};
            for (const e of strat.rationale_matrix) {
                const d = e.domain || 'other';
                (_grouped[d] = _grouped[d] || []).push(e);
            }
            const _orderedDomains = [
                ..._domainOrder.filter(d => _grouped[d]),
                ...Object.keys(_grouped).filter(d => !_domainOrder.includes(d)).sort(),
            ];
            const _renderRow = e => {
                const scoreHtml = e.score > 0
                    ? `<span class="rat-score-pos">+${e.score}</span>`
                    : `<span class="rat-score-zero">0</span>`;
                const reasonText = e.suppressed
                    ? `<span style="color:#ffaa00">${_t('evidence.suppressed', {reason: esc(e.suppress_reason || '')})}</span>`
                    : (esc(e.fired_reason) || '<span style="color:#444">—</span>');
                
                // Inject MUTE / UNMUTE button
                const isMuted = mutedSensors.has(e.sensor);
                const muteBtnTxt = isMuted ? _t('evidence.btn.unmute') : _t('evidence.btn.mute');
                const muteBtnStyle = isMuted ? 'color:#ffaa00; border-color:#ffaa00;' : 'color:#555; border-color:#555;';
                const muteBtn = `<button onclick="toggleMute('${esc(e.sensor)}')" style="background:transparent; border:1px solid; border-radius:3px; font-size:9px; cursor:pointer; margin-left:8px; transition:0.2s; ${muteBtnStyle}">${muteBtnTxt}</button>`;

                // Confidence badge: color-coded by level (Evidence-scoped classes to avoid cascade clash)
                const conf = e.confidence != null ? e.confidence : 1.0;
                const confClass = conf >= 0.8 ? 'ev-conf-high' : conf >= 0.5 ? 'ev-conf-mid' : 'ev-conf-low';
                const confHtml = `<span class="ev-conf-badge ${confClass}">${(conf * 100).toFixed(0)}%</span>`;

                // CAC: Direction badge
                const dirBadgeColors = { 'ADVERSARY_OFFENSIVE': '#ff2a2a', 'FRIENDLY_DEFENSIVE': '#00cc66', 'TARGET_IMPACT': '#ffaa00', 'UNKNOWN': '#333' };
                const dirBadgeShort = { 'ADVERSARY_OFFENSIVE': 'ADV', 'FRIENDLY_DEFENSIVE': 'FRD', 'TARGET_IMPACT': 'TGT', 'UNKNOWN': '—' };
                const dir = e.direction || 'UNKNOWN';
                const dirConf = e.direction_confidence != null ? e.direction_confidence : 0;
                const dirColor = dirBadgeColors[dir] || '#333';
                const dirHtml = dir !== 'UNKNOWN'
                    ? `<span class="dir-badge" style="color:${dirColor}; border-color:${dirColor};" data-tooltip="${_escAttr(dir)} (${(dirConf*100).toFixed(0)}%)">${dirBadgeShort[dir]}</span>`
                    : '<span class="dir-badge" style="color:#333;">—</span>';

                // CAC: Noise classification button (only for FIRED entries)
                const classifyBtn = (e.status === 'FIRED' && !e.suppressed)
                    ? `<button onclick="openNoiseClassify('${esc(e.sensor)}','${esc(e.value)}','${esc(e.domain)}')" class="btn-classify" data-tooltip="${_escAttr(_t('evidence.btn.classify_tip'))}">📋</button>`
                    : '';

                const _domain = e.domain || 'other';
                const _hidden = _evCollapsedDomains.has(_domain);

                // F1 provenance: sensor_chain shows other sensors that share this
                // signal_source (corroborating sources). signal_source itself is
                // the dedup key. Tooltip exposes both for analyst verification.
                let provHtml = '';
                if (e.signal_source) {
                    const chain = Array.isArray(e.sensor_chain) ? e.sensor_chain : [];
                    const chainLabel = chain.length > 0
                        ? `+${chain.length}`
                        : '·';
                    const chainTip = chain.length > 0
                        ? _t('evidence.prov.chain_tip', { src: e.signal_source, chain: chain.join(', ') })
                        : _t('evidence.prov.solo_tip', { src: e.signal_source });
                    provHtml = `<span class="rat-prov" title="${_escAttr(chainTip)}">⛓ ${esc(chainLabel)}</span>`;
                }

                return `<tr data-ev-domain="${esc(_domain)}"${_hidden ? ' style="display:none;"' : ''}>
                    <td style="font-family:monospace; font-size:11px; color:#ccc;">${esc(e.sensor)} ${provHtml}${muteBtn}${classifyBtn}</td>
                    <td><span class="rat-domain-${esc(e.domain)}">${esc(e.domain)}</span></td>
                    <td><span class="rat-status-${esc(e.status)}">${esc(e.status)}</span></td>
                    <td style="color:#fff; font-size:11px;">${esc(e.value)}</td>
                    <td style="text-align:center;">${scoreHtml}</td>
                    <td style="text-align:center;">${confHtml}</td>
                    <td style="text-align:center;">${dirHtml}</td>
                    <td style="font-size:11px; color:#aaa;">${reasonText}</td>
                </tr>`;
            };
            const _renderHeader = (domain, entries) => {
                const firedCount = entries.filter(x => x.status === 'FIRED' && !x.suppressed).length;
                const total = entries.reduce((s, x) => s + (x.score || 0), 0);
                const caret = _evCollapsedDomains.has(domain) ? '▸' : '▾';
                const domLabel = _t('evidence.domain.' + domain) || domain.toUpperCase();
                return `<tr class="ev-group-header" onclick="toggleEvDomain('${esc(domain)}')">
                    <td colspan="8" style="cursor:pointer; user-select:none; background:rgba(255,255,255,0.03); padding:4px 8px; border-top:1px solid #222;">
                        <span data-ev-caret="${esc(domain)}" style="color:#888; display:inline-block; width:14px;">${caret}</span>
                        <span class="rat-domain-${esc(domain)}" style="font-weight:bold; font-size:11px; letter-spacing:0.5px;">${esc(domLabel)}</span>
                        <span style="color:#666; font-size:10px; margin-left:8px;">${_t('evidence.group.count', {fired: firedCount, total: entries.length})} · ${_t('evidence.group.total', {n: total})}</span>
                    </td>
                </tr>`;
            };
            tbody.innerHTML = _orderedDomains.map(d =>
                _renderHeader(d, _grouped[d]) + _grouped[d].map(_renderRow).join('')
            ).join('');
        } else {
            tbody.innerHTML = `<tr><td colspan="8" style="color:#555; text-align:center;">${_t('evidence.no_data')}</td></tr>`;
        }

        // ── #5: Contribution Waterfall ───────────────────────────────────
        const wfEl = document.getElementById('evidence-waterfall');
        if (wfEl && strat.rationale_matrix) {
            const fired = strat.rationale_matrix.filter(e => e.status === 'FIRED' && !e.suppressed && e.score > 0);
            const totalRaw = fired.reduce((s, e) => s + (e.score * (e.confidence != null ? e.confidence : 1)), 0);
            const bonus = (strat.threat_breakdown || {}).convergence_bonus || 0;
            const totalWithBonus = totalRaw + bonus;
            if (totalWithBonus > 0) {
                const domainColors = { cyber: 'var(--color-accent, #00ffff)', physical: 'var(--color-warning, #ffaa00)', info: '#cc66ff' };
                let wfHtml = '<div class="wf-bar">';
                fired.sort((a, b) => (b.score * (b.confidence || 1)) - (a.score * (a.confidence || 1)));
                for (const e of fired) {
                    const eff = e.score * (e.confidence != null ? e.confidence : 1);
                    const pct = (eff / totalWithBonus) * 100;
                    if (pct < 1) continue;
                    const color = domainColors[e.domain] || '#888';
                    const label = pct >= 8 ? `<span class="wf-label">${_escHtml(e.sensor)}</span>` : '';
                    wfHtml += `<div class="wf-segment" style="width:${pct.toFixed(1)}%;background:${color}; cursor:help;" data-tooltip="${_escAttr(e.sensor)}: ${eff.toFixed(1)}pt (${pct.toFixed(0)}%) [${_escAttr(e.domain)}]">${label}</div>`;
                }
                if (bonus > 0) {
                    const bPct = (bonus / totalWithBonus) * 100;
                    const bLabel = bPct >= 8 ? `<span class="wf-label">+${bonus}</span>` : '';
                    wfHtml += `<div class="wf-segment wf-bonus" style="width:${bPct.toFixed(1)}%; cursor:help;" data-tooltip="${_escAttr(_t('evidence.wf_bonus'))}: +${bonus}pt (${bPct.toFixed(0)}%)">${bLabel}</div>`;
                }
                wfHtml += '</div>';
                wfHtml += `<div class="wf-legend"><span class="wf-leg-item" style="color:var(--color-accent,#00ffff);">● ${_t('evidence.wf_legend.cyber')}</span><span class="wf-leg-item" style="color:var(--color-warning,#ffaa00);">● ${_t('evidence.wf_legend.phys')}</span><span class="wf-leg-item" style="color:#cc66ff;">● ${_t('evidence.wf_legend.info')}</span>`;
                if (bonus > 0) wfHtml += `<span class="wf-leg-item" style="color:#44ff88;">● ${_t('evidence.wf_legend.bonus')}</span>`;
                wfHtml += `</div>`;
                wfEl.innerHTML = wfHtml;
                wfEl.style.display = 'block';
            } else {
                wfEl.innerHTML = '';
                wfEl.style.display = 'none';
            }
        } else if (wfEl) {
            wfEl.innerHTML = '';
            wfEl.style.display = 'none';
        }

        // ── #6: Counter-Signals & Intelligence Gaps ──────────────────────
        const csEl = document.getElementById('evidence-counter-signals');
        if (csEl && strat.rationale_matrix) {
            const healthMap = _sensorHealthCache || {};
            const notFired = strat.rationale_matrix.filter(e => e.status !== 'FIRED' && e.status !== 'SUPPRESSED');
            // Counter-signals: sensor is healthy but did not fire (reassuring)
            const counters = [];
            // Intelligence gaps: sensor is offline/degraded (blind spot)
            const gaps = [];
            for (const e of notFired) {
                const hInfo = healthMap[e.sensor];
                const st = hInfo ? (typeof hInfo === 'string' ? hInfo : hInfo.status) : null;
                const lastTs = hInfo && typeof hInfo === 'object' ? hInfo.last_fetch_ts : null;
                if (st === 'OK' || st === 'DEGRADED') {
                    counters.push(e);
                } else if (st === 'ERROR' || st === 'CIRCUIT_OPEN' || st === 'STALE' || st === 'DISABLED') {
                    gaps.push({ ...e, health_status: st, last_fetch_ts: lastTs });
                }
            }
            // Also find sensors in healthMap that have NO rationale entry
            const rationaleSensors = new Set(strat.rationale_matrix.map(e => e.sensor));
            for (const [name, hInfo] of Object.entries(healthMap)) {
                if (rationaleSensors.has(name)) continue;
                const st = typeof hInfo === 'string' ? hInfo : (hInfo.status || 'DISABLED');
                const lastTs = typeof hInfo === 'object' ? hInfo.last_fetch_ts : null;
                const domain = typeof hInfo === 'object' ? (hInfo.domain || '') : '';
                if (st === 'ERROR' || st === 'CIRCUIT_OPEN' || st === 'STALE') {
                    gaps.push({ sensor: name, domain, health_status: st, last_fetch_ts: lastTs });
                }
            }

            let csHtml = '';
            if (counters.length > 0) {
                csHtml += `<div class="cs-section"><div class="cs-header cs-ok">${_t('evidence.counter_signals')} (${counters.length})</div>`;
                csHtml += counters.map(e =>
                    `<span class="cs-chip cs-chip-ok" data-tooltip="${_escAttr(e.sensor)}: ${_escAttr(e.value || 'OK')}"><span class="rat-domain-${_escAttr(e.domain || '?')}">${(e.domain || '?')[0].toUpperCase()}</span> ${_escHtml(e.sensor)}</span>`
                ).join('');
                csHtml += '</div>';
            }
            if (gaps.length > 0) {
                csHtml += `<div class="cs-section"><div class="cs-header cs-gap">${_t('evidence.intel_gaps')} (${gaps.length})</div>`;
                csHtml += gaps.map(g => {
                    const age = g.last_fetch_ts ? _formatAge(g.last_fetch_ts) : _t('evidence.gap_never');
                    const icon = g.health_status === 'CIRCUIT_OPEN' ? '⏸' : g.health_status === 'DISABLED' ? '○' : '✕';
                    return `<span class="cs-chip cs-chip-gap" data-tooltip="${_escAttr(g.sensor)}: ${_escAttr(g.health_status)} — ${_escAttr(_t('evidence.gap_last_data'))}: ${_escAttr(age)}">${icon} <span class="rat-domain-${_escAttr(g.domain || '?')}">${(g.domain || '?')[0].toUpperCase()}</span> ${_escHtml(g.sensor)}</span>`;
                }).join('');
                csHtml += '</div>';
            }
            if (csHtml) {
                csEl.innerHTML = csHtml;
                csEl.style.display = 'block';
            } else {
                csEl.style.display = 'none';
            }
        } else if (csEl) {
            csEl.innerHTML = '';
            csEl.style.display = 'none';
        }

        openModal('evidence-modal');
    }

    function _formatAge(ts) {
        const sec = Math.floor(Date.now() / 1000 - ts);
        if (sec < 0) return '~0m';
        if (sec < 60) return '~1m';
        if (sec < 3600) return Math.floor(sec / 60) + 'm';
        if (sec < 86400) return Math.floor(sec / 3600) + 'h';
        return Math.floor(sec / 86400) + 'd';
    }

    // HUD button entry point — opens Evidence Modal with last known data
    window.openEvidenceFromHud = function() {
        const strat = (window._lastThreatData || {}).strategic_alert;
        if (strat) {
            openEvidencePanel(strat);
        } else {
            openModal('evidence-modal');
        }
    };

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
                    <span class="sensor-name">${esc(s.name)}</span>
                    <span class="sensor-domain-tag sensor-domain-${esc(s.domain)}">${esc(s.domain)}</span>
                    <span class="sensor-health ${healthCls}">${esc(s.health)}</span>
                    <span style="font-size:10px; color:#555;">${pollMin}min</span>
                    ${phaseNote}
                    <button class="sensor-toggle ${toggleCls}"
                        data-sensor="${esc(s.name)}" data-enable="${!s.enabled}"
                        onclick="toggleSensor(this.dataset.sensor, this.dataset.enable==='true', this)">
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

        // Cap displayed entries: each bar = 2px min + 1px gap
        const maxBars = Math.floor(W / 3);
        const visible = threatHistory.length > maxBars ? threatHistory.slice(-maxBars) : threatHistory;
        const n    = visible.length;
        const barW = Math.floor(W / n);
        const gap  = 1;
        const bw   = barW - gap;
        const offset = Math.floor((W - barW * n) / 2); // center bars
        const threatColors = { 1: '#ff0000', 2: '#ff2a2a', 3: '#ffaa00', 4: '#ffff00', 5: '#66ff66' };

        // severity = 6-d so that Lv1 CRITICAL=5 (tallest), Lv5 NORMAL=1 (shortest)
        // Minimum bar height is 3px so NORMAL state is always visible
        visible.forEach(([, d], i) => {
            const x   = offset + i * barW;
            const severity = 6 - d;  // 1→5, 2→4, 3→3, 4→2, 5→1
            const barH = Math.max(3, Math.round((severity / 5) * H));
            ctx.fillStyle = threatColors[d] || '#444';
            ctx.fillRect(x, H - barH, bw, barH);
        });
    }

    // ══════════════════════════════════════════════════════════════════════
    //  INTUITION UI — Recognition-Primed Decision (RPD) Components
    //  Eight UI elements that appeal to the analyst's heuristics and intuition
    // ══════════════════════════════════════════════════════════════════════

    // ── A. Ambient Atmosphere ──────────────────────────────────────────
    // Switch body class based on threat level → CSS keyframes subtly tint background
    function applyAmbientAtmosphere(threatLevel) {
        const body = document.body;
        body.classList.remove('atm-critical', 'atm-severe', 'atm-high');
        if      (threatLevel === 1) body.classList.add('atm-critical');
        else if (threatLevel === 2) body.classList.add('atm-severe');
        else if (threatLevel === 3) body.classList.add('atm-high');
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
                        <div class="wb-domain-tag ${cls}">${esc(key.toUpperCase())}</div>
                        <div class="wb-condition" style="color:${color};">${esc(v.state)}</div>
                        <div class="wb-desc">${esc(v.detail)}</div>
                    </div>
                </div>`;
            }).join('');
            if (sumEl) sumEl.textContent = wb.summary || '';
        } catch(e) {
            bodyEl.innerHTML = `<div style="color:#666;font-size:10px;text-align:center;">${_t('ui.api_unavailable')}</div>`;
        }
    }

    // ── E. SALUTE Report (on-demand export modal) ──────────────────────
    // Size/Activity/Location/Unit/Time/Equipment — military contact report format
    // Generates a snapshot report for copy/download instead of a live panel
    let _lastSaluteData = null;

    async function openSaluteModal() {
        const modal = document.getElementById('salute-modal');
        if (!modal) return;
        openModal('salute-modal');
        const bodyEl = modal.querySelector('.salute-body');
        const tsEl   = document.getElementById('salute-ts');

        const now = new Date();
        const pad = n => String(n).padStart(2, '0');
        if (tsEl) tsEl.textContent = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}Z`;

        try {
            const res = await fetch(`/api/salute_report?lang=${_currentLang}`);
            const sal = (await res.json()).report || {};
            _lastSaluteData = sal;
            const fields = [
                { k:'S', l:'SIZE',     v: sal.size      || '—' },
                { k:'A', l:'ACTIVITY', v: sal.activity  || '—' },
                { k:'L', l:'LOCATION', v: sal.location  || '—' },
                { k:'U', l:'UNIT',     v: sal.unit       || '—' },
                { k:'T', l:'TIME',     v: sal.time       || '—' },
                { k:'E', l:'EQUIP',    v: sal.equipment  || '—' },
            ];
            // TL badge
            const tl = sal.threat_level || 5;
            const tlColors = {1:'#ff0000',2:'#ff4444',3:'#ffaa00',4:'#ffff00',5:'#00ffff'};
            const tlBadge = `<div class="s-tl-badge" style="border-color:${tlColors[tl]}44;"><span class="s-tl-level" style="color:${tlColors[tl]};">TL${tl}</span></div>`;

            bodyEl.innerHTML = tlBadge +
                fields.map(f =>
                    `<div class="s-row">
                        <span class="s-key">${f.k}</span>
                        <span class="s-label">${f.l}</span>
                        <span class="s-val">${esc(f.v)}</span>
                    </div>`
                ).join('') +
                (sal.cross_ref ? `<div class="s-crossref"><span class="s-crossref-label">${_t('panel.salute.cross_ref')}</span> ${esc(sal.cross_ref)}</div>` : '') +
                (sal.assessment ? `<div class="s-assess">${esc(sal.assessment)}</div>` : '');
        } catch(e) {
            bodyEl.innerHTML = `<div style="color:#666;font-size:10px;text-align:center;">${_t('ui.api_unavailable')}</div>`;
        }
    }

    function closeSaluteModal() {
        closeAllModals();
    }

    function _saluteToText() {
        if (!_lastSaluteData) return '';
        const s = _lastSaluteData;
        const now = new Date();
        const dtg = now.toISOString().replace('T', ' ').slice(0, 16) + 'Z';
        return [
            `SALUTE REPORT — ${dtg}`,
            `THREAT LEVEL: ${s.threat_level || '—'}`,
            '─'.repeat(40),
            `S (SIZE):      ${s.size || '—'}`,
            `A (ACTIVITY):  ${s.activity || '—'}`,
            `L (LOCATION):  ${s.location || '—'}`,
            `U (UNIT):      ${s.unit || '—'}`,
            `T (TIME):      ${s.time || '—'}`,
            `E (EQUIPMENT): ${s.equipment || '—'}`,
            '',
            s.cross_ref ? `CROSS-REF:  ${s.cross_ref}` : '',
            '',
            s.assessment ? `ASSESSMENT:\n${s.assessment}` : '',
        ].filter(Boolean).join('\n');
    }

    function copySaluteReport() {
        const text = _saluteToText();
        if (!text) return;
        navigator.clipboard.writeText(text);
    }

    function downloadSaluteReport() {
        const text = _saluteToText();
        if (!text) return;
        const blob = new Blob([text], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        const now = new Date();
        a.download = `SALUTE_${now.toISOString().slice(0,10)}_${now.toISOString().slice(11,16).replace(':','')}.txt`;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    // ── G. Radio Silence Indicator ────────────────────────────────────
    // Sensors abnormally quiet: possible sensor suppression or pre-op comms blackout.
    // Now lives in the exception banner — only rendered when quiet anomaly fires
    // (no neutral "LIVE" badge consumes HUD real estate).
    function updateRadioSilence(p8, strat) {
        const wrap = document.getElementById('hud-radio-silence');
        const txt  = document.getElementById('hud-rs-text');
        if (!wrap || !txt) return;

        const velocity = p8 ? Math.abs(p8.velocity || 0) : 0;
        const score    = strat ? ((strat.threat_breakdown || {}).total_score || 0) : 0;
        const isQuiet  = velocity < 0.00005 && score >= 3;

        wrap.style.display = isQuiet ? 'inline-flex' : 'none';
        if (isQuiet) {
            txt.textContent = _t('rs.quiet_text');
            wrap.setAttribute('data-tooltip', _t('rs.tooltip.quiet'));
        }
    }

    // ── HUD chip updates introduced with the 3-row redesign ──────────
    // Reads fields the API now exposes (tl_duration_sec, intel_active_24h,
    // intel_new_1h, hod_z, eta_to_next_tl_sec, domain_split, scenarios[id]
    // .indicators.score_delta_1h) and renders the new chip group.
    function _formatDuration(sec) {
        if (sec == null || !isFinite(sec) || sec <= 0) return '';
        const m = Math.round(sec / 60);
        if (m < 60) return m + 'm';
        const h = Math.floor(m / 60), rm = m % 60;
        if (h < 24) return rm > 0 ? `${h}h${rm}m` : `${h}h`;
        const d = Math.floor(h / 24), rh = h % 24;
        return rh > 0 ? `${d}d${rh}h` : `${d}d`;
    }

    function _updateNewHudChips(data, strat, p8) {
        if (!strat) return;
        const ana = strat.analytics || {};
        const focusedId = data.focused_scenario || '';
        const focusedSc = (data.scenarios || {})[focusedId] || {};
        // Backend writes A1/A3/A5 fields at the scenario top level (not under .indicators)
        const ind       = focusedSc;

        // ── A1: TL duration (combats normalcy bias) ──────────────────
        const tlDurEl = document.getElementById('hud-tl-duration');
        if (tlDurEl) {
            const sec = ind.tl_duration_sec;
            if (sec != null && sec > 60) {
                tlDurEl.textContent = '· ' + _formatDuration(sec);
                tlDurEl.classList.toggle('long', sec >= 7200);
                tlDurEl.setAttribute('data-tooltip',
                    _t('hud.tooltip.tl_duration') + '\n' + _formatDuration(sec));
            } else {
                tlDurEl.textContent = '';
                tlDurEl.classList.remove('long');
            }
        }

        // ── ETA chip (proximity points + projected time) ─────────────
        const etaChip = document.getElementById('hud-eta-chip');
        const etaTime = document.getElementById('hud-eta-time');
        const tlp     = ana.tl_proximity;
        const eta     = ana.eta_to_next_tl_sec;
        if (etaChip && etaTime && tlp) {
            const lbl = tlp.proximity_label;
            etaChip.classList.remove('escalating', 'deescalating');
            if (eta && (lbl === 'NEAR_ESCALATION' || lbl === 'NEAR_DE_ESCALATION')) {
                const dir   = eta.direction || '';
                const isUp  = dir === 'escalating';
                etaChip.classList.add(isUp ? 'escalating' : 'deescalating');
                etaTime.textContent = '~' + _formatDuration(eta.eta_sec);
                etaTime.style.display = '';
                etaChip.style.display = '';
                etaChip.setAttribute('data-tooltip',
                    _t('hud.tooltip.eta') + '\n' +
                    (isUp
                        ? _t('hud.eta.tooltip_up',   {pts: tlp.distance_up,   tl: tlp.next_tl_up,   eta: _formatDuration(eta.eta_sec)})
                        : _t('hud.eta.tooltip_down', {pts: tlp.distance_down, tl: tlp.next_tl_down, eta: _formatDuration(eta.eta_sec)})));
            } else if (lbl === 'NEAR_ESCALATION' || lbl === 'NEAR_DE_ESCALATION') {
                // proximity present but velocity too small for ETA
                etaTime.textContent = '';
                etaTime.style.display = 'none';
                etaChip.style.display = '';
            } else {
                etaChip.style.display = 'none';
            }
        } else if (etaChip) {
            etaChip.style.display = 'none';
        }

        // ── HOD Z-score chip (current hour vs same-hour baseline) ────
        const hodChip = document.getElementById('hud-hod-chip');
        const hodEl   = document.getElementById('hud-hod-z');
        if (hodChip && hodEl) {
            const z = ana.hod_z;
            const n = ana.hod_n || 0;
            if (z != null && n >= 7) {
                const az = Math.abs(z);
                hodEl.textContent = (z >= 0 ? '+' : '') + z.toFixed(1) + 'σ';
                hodEl.className = 'hud-chip-value ' + (
                    az >= 2.5 ? 'hod-critical' :
                    az >= 1.5 ? 'hod-warning'  :
                    az >= 1.0 ? 'hod-elevated' : 'hod-normal');
                hodChip.classList.toggle('hod-active', az >= 1.5);
                hodChip.style.display = '';
                hodChip.setAttribute('data-tooltip',
                    _t('hud.tooltip.hod_z') + '\n' +
                    _t('hud.hod_z.detail', {z: z.toFixed(2), n: n}));
            } else {
                hodChip.style.display = 'none';
            }
        }

        // ── INTEL corroboration chip ─────────────────────────────────
        const intelEl    = document.getElementById('hud-intel-active');
        const intelNew   = document.getElementById('hud-intel-new');
        const intelChip  = document.getElementById('hud-intel-chip');
        if (intelEl && intelChip) {
            const active = ind.intel_active_24h;
            const fresh  = ind.intel_new_1h;
            if (active != null) {
                intelEl.textContent = String(active);
                intelChip.style.display = '';
                if (intelNew) {
                    if (fresh != null && fresh > 0) {
                        intelNew.textContent = '+' + fresh;
                        intelNew.classList.add('fresh');
                    } else {
                        intelNew.textContent = '';
                        intelNew.classList.remove('fresh');
                    }
                }
                intelChip.setAttribute('data-tooltip',
                    _t('hud.tooltip.intel_corrob') + '\n' +
                    _t('hud.intel.detail', {active: active, fresh: fresh || 0}));
                intelChip.onclick = () => {
                    if (typeof toggleLlmIntelPanel === 'function') toggleLlmIntelPanel();
                };
            } else {
                intelChip.style.display = 'none';
            }
        }

        // ── Per-domain ADV/TGT split tags (Row 2) ────────────────────
        const split = ind.domain_split || {};
        ['cyber', 'physical', 'info'].forEach(d => {
            const tagEl = document.getElementById('split-' + d);
            if (!tagEl) return;
            const sd = split[d] || {};
            const adv = +(sd.adversary || 0);
            const tgt = +(sd.target    || 0);
            if (adv + tgt < 0.05) {
                tagEl.style.display = 'none';
                tagEl.textContent = '';
                return;
            }
            tagEl.innerHTML =
                `<span class="split-adv">${adv.toFixed(1)}</span>` +
                `<span class="split-sep">/</span>` +
                `<span class="split-tgt">${tgt.toFixed(1)}</span>`;
            tagEl.style.display = '';
            tagEl.setAttribute('data-tooltip',
                _t('hud.tooltip.split_tag', {adv: adv.toFixed(2), tgt: tgt.toFixed(2)}));
        });

        // ── Background scenario alert (BG rising fast) ───────────────
        const bgAlert = document.getElementById('hud-bg-alert');
        const bgText  = document.getElementById('hud-bg-alert-text');
        if (bgAlert && bgText) {
            let bestId = null, bestDelta = 0, bestName = '';
            const lang = (typeof _currentLang !== 'undefined') ? _currentLang : 'en';
            const allSc = data.scenarios || {};
            Object.entries(allSc).forEach(([sid, sc]) => {
                if (sid === focusedId) return;
                const d = sc.score_delta_1h;
                if (d != null && d > bestDelta && d >= 1.0) {
                    bestDelta = d;
                    bestId = sid;
                    bestName = (lang === 'ja' ? sc.name_ja : sc.name_en) || sid;
                }
            });
            if (bestId) {
                bgText.textContent = `${bestName} +${bestDelta.toFixed(1)}`;
                bgAlert.style.display = 'inline-flex';
                bgAlert.setAttribute('data-tooltip',
                    _t('hud.tooltip.bg_alert') + '\n' +
                    _t('hud.bg_alert.detail', {name: bestName, delta: bestDelta.toFixed(2)}));
                bgAlert.onclick = () => {
                    if (typeof window.toggleScenarioDetail === 'function') window.toggleScenarioDetail(bestId);
                    else if (typeof focusScenarioBar === 'function') focusScenarioBar();
                };
            } else {
                bgAlert.style.display = 'none';
                bgAlert.onclick = null;
            }
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

    // ── Coordination Index: Constellation Pattern ──────────────────
    // Visibility toggle: 'off' | 'strong' | 'all'. Default 'off' because in
    // multi-country scenarios (Taiwan etc.) the underlying overlap saturates at
    // a structural baseline (5/21 pairs ≥70% even with no temporal coherence),
    // so the layer pulses orange across most of the map at all times and conveys
    // no actionable signal. Analysts can opt into STRONG/ALL for investigation.
    // (Backend already scopes `correlations` to the focused scenario's
    // participants — see scenarios.py derive_focus_context.)
    const _COORD_LINK_MODE_KEY = 'radar_coord_link_mode';
    const _COORD_LINK_MODES = ['off', 'strong', 'all'];
    // ─── IDF-correlation thresholds (calculate_overlap_idf, range 0-~5) ────
    // Calibrated from live shadow-surface data on 2026-04-26 (n=21 pairs,
    // single tick): IDF P50=0.0  P75=0.29  P90=1.22  P95=1.48  max=4.12
    // (raw equivalents: P50=53  P75=64  P95=87  max=91 — saturated).
    // Semantics-preserving mapping:
    //   OVERLAP_THRESHOLD 15  → 0.5  (suppress noise floor; no rare ASN sharing)
    //   _COORD_STRONG_MIN 60  → 1.5  (≈P95, top ~5% — analyst-actionable)
    //   (new) _COORD_ALARM_MIN 3.0   (P99+, rare ASN co-occurrence — alarm-grade)
    // Phase 6: raw mode removed — these are the only thresholds in use.
    const _COORD_IDF_OVERLAP_THRESHOLD = 0.5;
    const _COORD_IDF_STRONG_MIN        = 1.5;
    const _COORD_IDF_ALARM_MIN         = 3.0;
    function _getCoordLinkMode() {
        const v = localStorage.getItem(_COORD_LINK_MODE_KEY);
        // Migrate the short-lived 'focused' value (8f97a9b → next commit) to
        // 'off' silently — both map to "the quiet default" semantically.
        if (v === 'focused') { localStorage.setItem(_COORD_LINK_MODE_KEY, 'off'); return 'off'; }
        return _COORD_LINK_MODES.includes(v) ? v : 'off';
    }
    function _renderCoordToggleLabel() {
        const btn = document.getElementById('hud-coord-toggle');
        if (!btn) return;
        const mode = _getCoordLinkMode();
        btn.textContent = _t(`hud.coord.mode.${mode}`) || mode.toUpperCase();
        btn.dataset.mode = mode;
    }
    window._cycleCoordLinkMode = function () {
        const cur = _getCoordLinkMode();
        const next = _COORD_LINK_MODES[(_COORD_LINK_MODES.indexOf(cur) + 1) % _COORD_LINK_MODES.length];
        localStorage.setItem(_COORD_LINK_MODE_KEY, next);
        _renderCoordToggleLabel();
        // Re-render with cached data
        if (window._lastThreatData) updateCoordinationIndex(window._lastThreatData);
    };
    // Initial label paint (deferred until DOM + i18n are ready)
    if (document.readyState !== 'loading') setTimeout(_renderCoordToggleLabel, 0);
    else document.addEventListener('DOMContentLoaded', _renderCoordToggleLabel);

    // ─── Source-dependent parameter pack ─────────────────────────────────────
    // Phase 6: raw correlations removed. Coord links are now driven exclusively
    // by the IDF-weighted index (sparse 0–~5 scale, ubiquitous cloud/CDN ASNs
    // suppressed). 'idf_l3' is the canonical source — falls back to per-tick
    // 'idf' on a fresh DB before the L3 window has warmed up. All scale-sensitive
    // numbers (thresholds, bonuses, color tiers, display format) live here so
    // the rendering loop is source-agnostic.

    function _buildCoordParams(strat) {
        // IDF params — cutoffs come from A-1 percentile data (v2-migration §10.2).
        const base = {
            scaleMax: 8,                   // soft cap; live max ~5.4 (idf_l3)
            threshold: _COORD_IDF_OVERLAP_THRESHOLD, // 0.5
            strongMin: _COORD_IDF_STRONG_MIN,        // 1.5
            hotTier: 2.0, midTier: 1.0, c2HighTier: _COORD_IDF_STRONG_MIN,
            bonusBoth: 0.5, bonusC2Sync: 0.75, bonusC2Partial: 0.25, bonusStrike: 0.5,
            displayFormat: (v) => v.toFixed(2),
            l3Field: 'correlations_idf_l3', l7Field: 'correlations_idf_l7',
        };
        // Prefer L3 (more stable). Fall back to per-tick IDF only if L3 is empty
        // (fresh DB, no warm-up yet) AND per-tick has any non-zero value.
        const l3 = strat && strat.correlations_idf_l3;
        const l3Empty = !l3 || Object.values(l3).every(v => !v);
        const tick = strat && strat.correlations_idf;
        const useTick = l3Empty && tick && Object.values(tick).some(v => v > 0);
        return { ...base, field: useTick ? 'correlations_idf' : 'correlations_idf_l3' };
    }

    function _coordColor(coordIdx, isC2Sync, params) {
        if (isC2Sync && coordIdx > params.c2HighTier) return '#ff4444';
        if (coordIdx > params.hotTier) return '#ff8833';
        if (coordIdx > params.midTier) return '#ffcc44';
        return '#66ffee';
    }

    function updateCoordinationIndex(data) {
        coordLinkLayer.clearLayers();
        const mode = _getCoordLinkMode();
        if (mode === 'off') return;
        const strat = data && data.strategic_alert;
        if (!strat) return;
        const params = _buildCoordParams(strat);
        const correlations = strat[params.field];
        if (!correlations) return;

        const targets = data.targets || [];
        const posMap = {}, spikeMap = {};
        targets.forEach(t => {
            if (t.lat != null && t.lng != null) posMap[t.code] = {lat: t.lat, lng: shiftLng(t.lng)};
            spikeMap[t.code] = t.avg_spike || 0;
        });

        // STRONG mode: only render pairs whose final coordIdx >= threshold.
        // Under IDF this drops to top ~5% (P95) — heavy filter by design.
        const minCoordIdx = (mode === 'strong') ? params.strongMin : 0;

        const tc = (strat.analytics || {}).temporal_coherence || {};
        const isC2Sync = tc.is_c2_sync || false;
        const c2Score = tc.coherence_score || 0;
        const strikes = strat.adversary_strikes || [];
        const strikeTargets = new Set(strikes.map(s => s.target));

        const diamondPlaced = new Set();

        for (const [pair, overlap] of Object.entries(correlations)) {
            const [a, b] = pair.split('-');
            const ca = posMap[a], cb = posMap[b];
            if (!ca || !cb) continue;

            let coordIdx = overlap;
            const bothElevated = spikeMap[a] > 2 && spikeMap[b] > 2;
            if (bothElevated) coordIdx += params.bonusBoth;
            if (isC2Sync) coordIdx += params.bonusC2Sync;
            else if (c2Score > 0) coordIdx += params.bonusC2Partial;
            if (strikeTargets.has(a) && strikeTargets.has(b)) coordIdx += params.bonusStrike;
            coordIdx = Math.min(params.scaleMax, Math.max(0, coordIdx));
            if (coordIdx < params.threshold) continue;
            if (coordIdx < minCoordIdx) continue;

            const norm = Math.min(1, (coordIdx - params.threshold) / (params.scaleMax - params.threshold));
            const color = _coordColor(coordIdx, isC2Sync, params);
            const isC2High = isC2Sync && coordIdx > params.c2HighTier;

            // Tiered visual intensity: low(cyan) is subtle, high(red) is aggressive
            let coreW, glowW, glowOp, speedCls;
            if (isC2High) {
                coreW = 4; glowW = 12; glowOp = 0.35; speedCls = 'coord-core-fast';
            } else if (coordIdx > params.hotTier) {
                coreW = 3; glowW = 10; glowOp = 0.22; speedCls = 'coord-core-fast';
            } else if (coordIdx > params.midTier) {
                coreW = 2; glowW = 7; glowOp = 0.12; speedCls = 'coord-core-med';
            } else {
                coreW = 1; glowW = 4; glowOp = 0.05; speedCls = 'coord-core-slow';
            }
            const c2Cls = isC2High ? ' coord-c2sync' : '';

            // Layer 1: Glow track (opacity=1, CSS animation controls stroke-opacity)
            L.polyline([[ca.lat, ca.lng], [cb.lat, cb.lng]], {
                color, weight: glowW, opacity: 1,
                lineCap: 'round', interactive: false, className: 'coord-glow ' + speedCls
            }).addTo(coordLinkLayer);

            // Layer 2: Core line (opacity=1, CSS animation controls stroke-opacity)
            const coreLine = L.polyline([[ca.lat, ca.lng], [cb.lat, cb.lng]], {
                color, weight: coreW, opacity: 1,
                lineCap: 'round', interactive: true,
                className: 'coord-core ' + speedCls + c2Cls
            }).addTo(coordLinkLayer);


            // Rich tooltip with signal breakdown — uses the same source the
            // map is rendering from so the analyst sees consistent numbers.
            const l3v = strat[params.l3Field] ? (strat[params.l3Field][pair] || 0) : null;
            const l7v = strat[params.l7Field] ? (strat[params.l7Field][pair] || 0) : null;
            const fmt = params.displayFormat;
            const l3s = l3v == null ? '—' : fmt(l3v);
            const l7s = l7v == null ? '—' : fmt(l7v);
            let tipHtml = `<b>${a} ↔ ${b}</b> — Coord: ${fmt(coordIdx)}`;
            tipHtml += `<br><span style="color:#888">Origin:</span> ${fmt(overlap)} (<span style="color:#ff6666">L3:${l3s}</span> <span style="color:#66ff66">L7:${l7s}</span>)`;
            if (bothElevated) tipHtml += `<br><span style="color:#ffaa00">▲ Both elevated (${spikeMap[a].toFixed(1)}× / ${spikeMap[b].toFixed(1)}×)</span>`;
            if (isC2Sync) tipHtml += `<br><span style="color:#ff2200">⚡ C2-SYNC confirmed</span>`;
            else if (c2Score > 0) tipHtml += `<br><span style="color:#ffaa00">◉ Partial temporal coherence</span>`;
            if (strikeTargets.has(a) && strikeTargets.has(b)) tipHtml += `<br><span style="color:#ff4444">✦ Adversary strikes on both</span>`;
            coreLine.bindTooltip(tipHtml, {sticky: true, className: 'coord-tooltip'});

            // Midpoint percentage label
            const midLat = (ca.lat + cb.lat) / 2;
            const midLng = (ca.lng + cb.lng) / 2;
            const labelIcon = L.divIcon({
                className: '',
                html: `<div style="font-size:13px;font-weight:bold;font-family:monospace;color:${color};text-shadow:0 0 6px rgba(0,0,0,0.95),0 0 2px rgba(0,0,0,0.8);white-space:nowrap;pointer-events:none;">${params.displayFormat(coordIdx)}</div>`,
                iconSize: [40, 18], iconAnchor: [20, 9],
            });
            L.marker([midLat, midLng], {icon: labelIcon, interactive: false}).addTo(coordLinkLayer);

            // Diamond endpoint markers (one per theater)
            for (const code of [a, b]) {
                if (diamondPlaced.has(code)) continue;
                diamondPlaced.add(code);
                const pos = posMap[code];
                const pulseCls = isC2High ? ' coord-diamond-pulse' : '';
                const dIcon = L.divIcon({
                    className: '',
                    html: `<div class="coord-diamond${pulseCls}" style="width:8px;height:8px;background:${color};transform:rotate(45deg);box-shadow:0 0 6px ${color}88;"></div>`,
                    iconSize: [8, 8], iconAnchor: [4, 4],
                });
                L.marker([pos.lat, pos.lng], {icon: dIcon, interactive: false}).addTo(coordLinkLayer);
            }
        }
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
                const errMsg   = last && last.error ? `<div style="color:#ff4444;font-size:10px;margin-bottom:4px;">${esc(last.error)}</div>` : '';

                const histBar = (s.fetch_log || []).map(e =>
                    `<span style="display:inline-block;width:8px;height:16px;margin:0 1px;vertical-align:middle;border-radius:2px;background:${e.success ? '#66ff66' : '#ff4444'}44;border:1px solid ${e.success ? '#66ff66' : '#ff4444'};" data-tooltip="${new Date(e.ts).toLocaleTimeString()}\nStatus: ${e.success ? 'OK' : 'ERROR'}\n${esc(e.error || '')}"></span>`
                ).join('');

                return `
                <div style="margin-bottom:10px;padding:10px;background:#111;border:1px solid #222;border-left:3px solid ${healthCls};border-radius:4px;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                        <span style="font-size:13px;font-weight:bold;color:#eee;">${esc(s.sensor)}</span>
                        <span style="font-size:10px;padding:2px 6px;border-radius:10px;background:${dCol}22;color:${dCol};border:1px solid ${dCol}44; text-transform:uppercase;">${esc(s.domain)}</span>
                        <span style="font-size:11px;padding:1px 6px;border-radius:3px;color:${healthCls};border:1px solid ${healthCls}55;">${esc(s.health)}</span>
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

    // ── Upstream Sources panel (CT log multi-source coverage) ────────────────────
    function _fmtAge(sec) {
        if (sec == null) return '—';
        if (sec < 60) return `${Math.round(sec)}s`;
        if (sec < 3600) return `${Math.round(sec/60)}m`;
        if (sec < 86400) return `${Math.round(sec/3600)}h`;
        return `${Math.round(sec/86400)}d`;
    }

    function _statusColor(status) {
        return ({
            healthy: '#66ff66', ok: '#66ff66',
            degraded: '#ff8800',
            dead: '#ff4444', error: '#ff4444',
            unknown: '#888888',
        }[(status || '').toLowerCase()] || '#888');
    }

    function _renderUpstreamSource(srcName, h) {
        const sCol  = _statusColor(h.status);
        const spec  = h.source_specific || {};
        const modes = h.mode_counters || {};
        const lastMsgAge = spec.last_message_age_sec;
        const ageStr = (lastMsgAge != null) ? _fmtAge(lastMsgAge) : '—';
        const kindBadge = spec.kind ? `<span style="font-size:10px;padding:1px 6px;border-radius:10px;background:#222;color:#aaa;border:1px solid #333;text-transform:uppercase;">${esc(spec.kind)}</span>` : '';
        const modeRows = Object.entries(modes)
            .filter(([_, v]) => v > 0)
            .map(([k, v]) => `<span style="display:inline-block;padding:1px 5px;margin:1px 2px;background:#1a0a0a;color:#ff8800;border:1px solid #553;border-radius:3px;font-size:10px;">${esc(k)}: ${v}</span>`)
            .join('') || `<span style="color:#555;font-size:10px;">${_t('upstreams.no_failures')}</span>`;

        let kvRows = '';
        const kvSpec = [
            ['url',                  'URL'],
            ['running',              _t('upstreams.field.running')],
            ['messages_total',       _t('upstreams.field.messages_total')],
            ['matches_total',        _t('upstreams.field.matches_total')],
            ['connect_count',        _t('upstreams.field.connect_count')],
            ['watched_domains',      _t('upstreams.field.watched_domains')],
            ['heartbeat_budget_sec', _t('upstreams.field.heartbeat_budget_sec')],
            ['liveness_budget_sec',  _t('upstreams.field.liveness_budget_sec')],
            ['observation_count_24h', _t('upstreams.field.observation_count_24h')],
            ['queries_made',         _t('upstreams.field.queries_made')],
            ['rate_limit_remaining', _t('upstreams.field.rate_limit_remaining')],
        ];
        for (const [k, label] of kvSpec) {
            if (spec[k] !== undefined && spec[k] !== null && spec[k] !== '') {
                kvRows += `<div><span style="color:#666;">${esc(label)}:</span> <b style="color:#ccc;">${esc(String(spec[k]))}</b></div>`;
            }
        }

        return `
        <div style="margin:6px 0;padding:8px 10px;background:#0d0d0d;border:1px solid #222;border-left:3px solid ${sCol};border-radius:3px;">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
                <span style="font-size:12px;font-weight:bold;color:#eee;">${esc(srcName)}</span>
                ${kindBadge}
                <span style="font-size:11px;padding:1px 6px;border-radius:3px;color:${sCol};border:1px solid ${sCol}55;">${esc(h.status || 'unknown')}</span>
                <span style="margin-left:auto;font-size:11px;color:#555;">
                    ${_t('upstreams.last_msg')}: <b style="color:#ccc;">${ageStr}</b>
                </span>
            </div>
            <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:2px 12px;font-size:11px;">${kvRows}</div>
            <div style="margin-top:6px;font-size:11px;color:#666;">${_t('upstreams.mode_counters')}:</div>
            <div style="margin-top:2px;">${modeRows}</div>
        </div>`;
    }

    function _renderCoverageBar(coverage) {
        if (!coverage) return '';
        const obs24 = coverage.observed_24h || 0;
        const obs72 = coverage.observed_72h || 0;
        const total = coverage.total_watched || 0;
        const pct24 = total ? (100 * obs24 / total) : 0;
        const pct72 = total ? (100 * obs72 / total) : 0;
        const stalest = (coverage.stalest_apexes || []).slice(0, 10);
        const stalestRows = stalest.map(a => {
            const last = a.last_observed_ts ? _fmtAge((Date.now()/1000) - a.last_observed_ts) : _t('upstreams.never');
            return `<div style="display:flex;justify-content:space-between;font-size:11px;color:#999;padding:1px 0;border-bottom:1px solid #1a1a1a;"><span>${esc(a.domain || a)}</span><span style="color:#777;">${esc(last)}</span></div>`;
        }).join('') || `<div style="color:#555;font-size:11px;">${_t('upstreams.coverage.no_data')}</div>`;

        return `
        <div style="margin-top:8px;padding:8px;background:#0d0d0d;border:1px solid #222;border-radius:3px;">
            <div style="font-size:11px;color:#aaa;margin-bottom:6px;">${_t('upstreams.coverage.title')}: <b style="color:#eee;">${obs24}/${total}</b> (24h, ${pct24.toFixed(1)}%) — <b style="color:#eee;">${obs72}/${total}</b> (72h, ${pct72.toFixed(1)}%)</div>
            <div style="height:6px;background:#1a1a1a;border-radius:3px;overflow:hidden;margin-bottom:8px;">
                <div style="height:100%;width:${pct72}%;background:linear-gradient(90deg,#66ff66 0%,#66ff66 ${pct24/Math.max(pct72,0.001)*100}%,#ff8800 ${pct24/Math.max(pct72,0.001)*100}%,#ff8800 100%);"></div>
            </div>
            <div style="font-size:11px;color:#888;margin-bottom:4px;">${_t('upstreams.coverage.stalest')}:</div>
            ${stalestRows}
        </div>`;
    }

    async function loadUpstreams() {
        const container = document.getElementById('upstreams-container');
        const tsEl      = document.getElementById('upstreams-ts');
        try {
            const res = await fetch(`/api/admin/sensor_health`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            tsEl.textContent = _t('upstreams.last_refreshed', {time: new Date().toLocaleTimeString()});

            const withUpstream = (data.sensors || []).filter(s => s.upstream && !s.upstream.error);
            if (!withUpstream.length) {
                container.innerHTML = `<div style="color:#555;font-size:13px;">${_t('upstreams.empty')}</div>`;
                return;
            }

            container.innerHTML = withUpstream.map(s => {
                const u = s.upstream || {};
                const sCol = _statusColor(u.status);
                const sources = u.sources || {};
                const sourceCards = Object.entries(sources)
                    .map(([n, h]) => _renderUpstreamSource(n, h))
                    .join('');
                const coverageHtml = _renderCoverageBar(u.coverage);
                const buf = u.buffer || {};
                const bufLine = (buf.size != null) ? `<span style="color:#666;">${_t('upstreams.buffer')}:</span> <b style="color:#ccc;">${buf.size}/${buf.max_obs || '?'}</b> (${buf.window_hours || '?'}h)` : '';
                const anomalies = u.anomaly_counts || {};
                const anomalyLine = Object.entries(anomalies)
                    .map(([k, v]) => `<span style="color:#666;">${esc(k)}:</span> <b style="color:#${v>0?'ff8800':'ccc'};">${v}</b>`)
                    .join(' &nbsp; ');
                return `
                <div style="margin-bottom:14px;padding:10px;background:#111;border:1px solid #222;border-left:3px solid ${sCol};border-radius:4px;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
                        <span style="font-size:14px;font-weight:bold;color:#eee;">${esc(s.name)}</span>
                        <span style="font-size:11px;padding:2px 6px;border-radius:3px;color:${sCol};border:1px solid ${sCol}55;">${esc(u.status || 'unknown')}</span>
                        <span style="margin-left:auto;font-size:11px;color:#666;">
                            ${_t('upstreams.poll')}: <b style="color:#ccc;">${Math.round((u.current_interval_sec||0)/60)}min</b>
                        </span>
                    </div>
                    <div style="display:flex;gap:14px;font-size:11px;color:#888;margin-bottom:8px;">
                        <div>${bufLine}</div>
                        <div>${anomalyLine}</div>
                    </div>
                    ${sourceCards}
                    ${coverageHtml}
                </div>`;
            }).join('');
        } catch (e) {
            container.innerHTML = `<div style="color:#ff2a2a;">${_t('upstreams.load_error', {msg: e.message})}</div>`;
        }
    }

    // ── Fleet Health (admin tab) ─────────────────────────────────────────────
    let _fleetCache = null;
    function _fleetFmtAge(sec) {
        if (sec == null) return _t('fleet.never_fetched');
        if (sec < 60) return `${Math.round(sec)}s`;
        if (sec < 3600) return `${Math.round(sec/60)}m`;
        if (sec < 86400) return `${Math.round(sec/3600)}h`;
        return `${Math.round(sec/86400)}d`;
    }
    function _fleetHealthColor(h) {
        if (h === 'OK') return 'var(--color-ok)';
        if (h === 'DEGRADED' || h === 'STALE') return 'var(--color-warning)';
        if (h === 'ERROR' || h === 'CIRCUIT_OPEN' || h === 'CIRCUIT_OPEN_PERSISTENT') return 'var(--color-severe)';
        return 'var(--color-muted)';
    }
    function _fleetCbBadge(state) {
        if (!state || state === 'closed') return `<span style="color:var(--color-ok);">${_t('fleet.cb.closed')}</span>`;
        if (state === 'half_open' || state === 'half-open') return `<span style="color:var(--color-warning);">${_t('fleet.cb.half_open')}</span>`;
        if (state === 'open') return `<span style="color:var(--color-severe);font-weight:bold;">${_t('fleet.cb.open')}</span>`;
        return `<span style="color:var(--color-muted);">${esc(state)}</span>`;
    }
    function _renderFleetCached() {
        if (!_fleetCache) return;
        const container = document.getElementById('fleet-container');
        const summaryEl = document.getElementById('fleet-summary');
        const filter = document.getElementById('fleet-domain-filter')?.value || 'all';
        const sensors = (_fleetCache.sensors || [])
            .filter(s => filter === 'all' || s.domain === filter)
            .slice()
            .sort((a, b) => (a.domain || '').localeCompare(b.domain || '') || a.name.localeCompare(b.name));
        const sm = _fleetCache.summary || {};
        if (summaryEl) {
            summaryEl.textContent = _t('fleet.summary', {
                total: sm.total || 0, ok: sm.ok || 0, degraded: sm.degraded || 0,
                stale: sm.stale || 0, err: sm.error || 0,
                cb: sm.circuit_open || 0, off: sm.disabled || 0,
            });
        }
        if (!sensors.length) {
            container.innerHTML = `<div style="color:#555;font-size:13px;">${_t('fleet.empty_filter')}</div>`;
            return;
        }
        const rows = sensors.map(s => {
            const hCol = _fleetHealthColor(s.health);
            const rel = s.reliability || {};
            const successPct = rel.success_rate != null ? `${(rel.success_rate * 100).toFixed(1)}%` : '—';
            const totalFetches = rel.total_fetches || 0;
            const avgMs = rel.avg_duration_ms ? `${Math.round(rel.avg_duration_ms)}ms` : '—';
            const cbFails = s.cb_fail_count || 0;
            const lastErr = s.last_error || _t('fleet.no_error');
            const errCol = s.last_error ? '#ff8888' : '#666';
            const upstream = s.upstream;
            let upstreamSection = '';
            if (upstream && !upstream.error && upstream.sources) {
                const srcDots = Object.entries(upstream.sources).map(([n, h]) => {
                    const c = _statusColor ? _statusColor(h.status) : '#888';
                    return `<span title="${esc(n)}: ${esc(h.status || '?')}" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${c};margin-right:3px;"></span>`;
                }).join('');
                upstreamSection = `<div style="margin-top:6px;font-size:10px;color:#666;">↳ upstream (${esc(upstream.status || '?')}): ${srcDots}</div>`;
            }
            return `
            <div style="margin-bottom:8px;padding:8px 10px;background:#0e0e10;border:1px solid #1c1c20;border-left:3px solid ${hCol};border-radius:3px;">
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                    <span style="font-weight:bold;color:#eee;font-size:12px;min-width:160px;">${esc(s.name)}</span>
                    <span style="font-size:9px;padding:1px 5px;border-radius:2px;background:#1a1a20;color:#888;">${esc((s.domain || '?').toUpperCase())}</span>
                    <span style="font-size:9px;padding:1px 5px;border-radius:2px;background:#0a0a14;color:#88a;">${esc(s.tier || 'GLOBAL')}</span>
                    <span style="font-size:11px;color:${hCol};font-weight:bold;">${esc(s.health || '?')}</span>
                    <span style="font-size:10px;color:#666;">CB: ${_fleetCbBadge(s.cb_state)}${cbFails > 0 ? ` <span style="color:#ff8800;">(${cbFails} fails)</span>` : ''}</span>
                    <span style="margin-left:auto;font-size:10px;color:#555;">poll ${Math.round((s.poll_interval_sec||0)/60)}m</span>
                </div>
                <div style="display:flex;gap:14px;font-size:10px;color:#888;margin-top:5px;flex-wrap:wrap;">
                    <span><span style="color:#555;">${_t('fleet.col.cache_age')}:</span> <b style="color:#bbb;">${_fleetFmtAge(s.cache_age_sec)}</b></span>
                    <span><span style="color:#555;">${_t('fleet.col.reliability')} (${totalFetches}):</span> <b style="color:#bbb;">${successPct}</b> @ ${avgMs}</span>
                    ${s.enabled ? '' : '<span style="color:#666;">[disabled]</span>'}
                </div>
                <div style="font-size:10px;color:${errCol};margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(lastErr)}">
                    <span style="color:#555;">${_t('fleet.col.last_error')}:</span> ${esc(lastErr)}
                </div>
                ${upstreamSection}
            </div>`;
        }).join('');
        container.innerHTML = rows;
    }
    window._renderFleetCached = _renderFleetCached;
    async function loadFleetHealth() {
        const container = document.getElementById('fleet-container');
        const tsEl = document.getElementById('fleet-ts');
        const hours = document.getElementById('fleet-window-hours')?.value || '24';
        try {
            const res = await fetch(`/api/admin/sensor_health?hours=${encodeURIComponent(hours)}`, { headers: _adminHeaders() });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            _fleetCache = await res.json();
            if (tsEl) tsEl.textContent = _t('fleet.last_refreshed', { time: new Date().toLocaleTimeString() });
            _renderFleetCached();
        } catch (e) {
            container.innerHTML = `<div style="color:#ff2a2a;">${_t('fleet.load_error', { msg: e.message })}</div>`;
        }
    }
    window.loadFleetHealth = loadFleetHealth;

    // ── Admin headers helper ─────────────────────────────────────────────────────
    function _adminHeaders(extra = {}) {
        return { ...extra };
    }

    // ── System Config (env_config) ────────────────────────────────────────────
    async function loadEnvConfig() {
        const _rn = document.getElementById('env-restart-note');
        if (_rn) _rn.style.display = 'none';
        try {
            const res = await fetch(`/api/env_config`, { headers: _adminHeaders() });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const cfg = await res.json();
            document.querySelectorAll('[id^="ec-"]').forEach(el => {
                const key = el.id.replace('ec-', '');
                if (key === 'LLM_MODEL_manual') return; // skip manual fallback field
                if (cfg[key] !== undefined) {
                    el.value = cfg[key];
                    if (key === 'LLM_MODEL') el.dataset.current = cfg[key];
                }
            });
            const st = document.getElementById('env-status');
            if (st) { st.textContent = ''; }
            // Auto-fetch Ollama models so the Model select shows the current selection
            fetchLlmModels();
        } catch(e) {
            const st = document.getElementById('env-status');
            if (st) { st.textContent = _t('config.status.load_error', {msg: e.message}); st.className = 'env-status err'; }
        }
    }

    async function saveEnvConfig() {
        const updates = {};
        const _skipKeys = new Set(['LLM_MODEL_manual']);
        document.querySelectorAll('[id^="ec-"]').forEach(el => {
            if (el.type === 'hidden' && el.value === '') return; // skip empty hidden
            const key = el.id.replace('ec-', '');
            if (_skipKeys.has(key)) return; // UI-only field, not a real config key
            if (el.value !== '') updates[key] = el.value;
        });
        const st = document.getElementById('env-status');
        if (st) { st.textContent = _t('config.status.saving'); st.className = 'env-status'; }
        try {
            const res = await fetch(`/api/env_config`, {
                method: 'POST',
                headers: _adminHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(updates)
            });
            const data = await res.json();
            if (data.ok) {
                // Immediately reload reloadable keys (no restart needed for those)
                let needsRestart = false;
                try {
                    const rel = await fetch('/api/env_config/reload', {
                        method: 'POST',
                        headers: _adminHeaders(),
                    });
                    const relData = await rel.json();
                    needsRestart = relData.ok && relData.needs_restart && relData.needs_restart.length > 0;
                } catch(_) {}
                const restartNote = document.getElementById('env-restart-note');
                if (restartNote) restartNote.style.display = needsRestart ? 'block' : 'none';
                if (st) {
                    st.textContent = _t('config.status.saved', {n: data.updated.length});
                    st.className = 'env-status ok';
                    setTimeout(() => { if (st) st.textContent = ''; }, 6000);
                }
            } else {
                throw new Error(data.error || 'Unknown error');
            }
        } catch(e) {
            if (st) { st.textContent = _t('config.status.error', {msg: e.message}); st.className = 'env-status err'; }
        }
    }

    function toggleEnvAdvanced() {
        const sec = document.getElementById('env-adv-section');
        const btn = document.getElementById('env-adv-btn');
        if (!sec || !btn) return;
        const open = sec.classList.toggle('open');
        btn.textContent = _t(open ? 'sysconfig.adv_toggle_open' : 'sysconfig.adv_toggle');
    }

    // ── LLM Model Fetch ───────────────────────────────────────────────────────
    window.fetchLlmModels = async function() {
        const hostEl    = document.getElementById('ec-LLM_HOST');
        const selectEl  = document.getElementById('ec-LLM_MODEL');
        const manualEl  = document.getElementById('ec-LLM_MODEL_manual');
        const statusEl  = document.getElementById('llm-model-status');
        if (!hostEl || !selectEl) return;

        const host = (hostEl.value || 'http://host.docker.internal:11434').replace(/\/$/, '');
        if (statusEl) { statusEl.textContent = _t('sysconfig.llm.fetching'); statusEl.style.color = '#aa88ff'; }

        try {
            const res = await fetch(`/api/llm_models?host=${encodeURIComponent(host)}`, {
                headers: _adminHeaders(),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            const models = data.models || [];

            if (models.length === 0) {
                if (statusEl) { statusEl.textContent = _t('sysconfig.llm.no_models'); statusEl.style.color = '#ff8800'; }
                selectEl.style.display = 'none';
                if (manualEl) manualEl.style.display = '';
                return;
            }

            // Populate dropdown
            const currentVal = (manualEl && manualEl.value) || selectEl.dataset.current || '';
            selectEl.innerHTML = '';
            models.forEach(m => {
                const opt = new Option(m, m);
                if (m === currentVal) opt.selected = true;
                selectEl.appendChild(opt);
            });
            // If no match, preselect first
            if (!selectEl.value && models.length > 0) selectEl.value = models[0];

            selectEl.style.display = '';
            if (manualEl) manualEl.style.display = 'none';
            if (statusEl) { statusEl.textContent = _t('sysconfig.llm.models_loaded', {n: models.length}); statusEl.style.color = '#44aa44'; }
        } catch(e) {
            if (statusEl) { statusEl.textContent = _t('sysconfig.llm.fetch_error', {msg: e.message}); statusEl.style.color = '#ff4444'; }
            // Fall back to manual entry
            selectEl.style.display = 'none';
            if (manualEl) manualEl.style.display = '';
        }
    };

    // Sync manual model input → hidden ec-LLM_MODEL when select is hidden
    document.addEventListener('input', e => {
        if (e.target && e.target.id === 'ec-LLM_MODEL_manual') {
            const sel = document.getElementById('ec-LLM_MODEL');
            if (sel && sel.style.display === 'none') {
                // Ensure the manual value will be picked up by saveEnvConfig via the select
                // We repurpose the select by adding an option matching the typed value
                sel.innerHTML = `<option value="${esc(e.target.value)}" selected>${esc(e.target.value)}</option>`;
            }
        }
    });

    // ═══════════════════════════════════════════════════════════════════
    // Threat Situation Map (TSM) — Theater Halo + Sensor Status Icons
    // ═══════════════════════════════════════════════════════════════════

    // Per-sensor config: angle (degrees from north, CW), short label, domain
    const SENSOR_ICON_CFG = {
        'cloudflare_radar':    {angle:   0, label: 'CF',    domain: 'cyber'},
        'cf_spike_core':       {angle:   0, label: 'DDOS',  domain: 'cyber'},
        'cf_coordinated':      {angle:   0, label: 'COORD', domain: 'cyber'},
        'cf_botnet_overlap':   {angle:   0, label: 'BOTNT', domain: 'cyber'},
        'cf_adversary_strike': {angle:   0, label: 'ADVST', domain: 'cyber'},
        'cf_vector_shift':     {angle:   0, label: 'VSHFT', domain: 'cyber'},
        'cf_bgp_hijack':       {angle:   0, label: 'HIJCK', domain: 'cyber'},
        'ripe_bgp':            {angle: 330, label: 'BGP',   domain: 'cyber'},
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
        'ihr_disco':        {angle: 135, label: 'IHR',  domain: 'physical'},
        'ihr_delay':        {angle: 150, label: 'IHRd', domain: 'physical'},
        'ripe_atlas':       {angle: 108, label: 'ATL',  domain: 'physical'},
        'tor_metrics':      {angle: 230, label: 'TOR',  domain: 'info'},
        // Composite / derived sensors (no dedicated map marker — angle matches nearest domain)
        'ct_log':           {angle:  30, label: 'CT',   domain: 'cyber'},
        'ooni_censorship':  {angle:  30, label: 'OONI', domain: 'cyber'},
        'gps_jamming':      {angle: 192, label: 'GPS',  domain: 'physical'},
        'usgs_seismic':     {angle: 143, label: 'SEIS', domain: 'physical'},
        'mil_support_air':  {angle:  75, label: 'MIL',  domain: 'physical'},
        'space_weather':    {angle: 192, label: 'SPWX', domain: 'physical'},
        'notam':            {angle:  75, label: 'NTAM', domain: 'physical'},
        'travel_advisory':  {angle: 268, label: 'TRVL', domain: 'info'},
        'ddos_acceleration':{angle:   0, label: 'DACC', domain: 'cyber'},
        'blockade_index':   {angle:   0, label: 'BLKD', domain: 'cyber'},
        'cdn_asphyxiation': {angle:   0, label: 'CDN',  domain: 'cyber'},
        'silent_divergence':{angle:   0, label: 'SDIV', domain: 'cyber'},
        'maskirovka_flag':  {angle: 268, label: 'MASK', domain: 'info'},
        'feint_detector':   {angle:   0, label: 'FINT', domain: 'cyber'},
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
                `<b style="color:${domainColor}">${esc(sensor)}</b><br>` +
                `Status: <b>${esc(entry.status)}</b>${isSuppressed ? ' <span style="color:#888">[MUTED]</span>' : ''}<br>` +
                `Score: <b>+${score}pt</b><br>` +
                (entry.value        ? `Value: ${esc(entry.value)}<br>` : '') +
                (entry.fired_reason ? `Reason: ${esc(entry.fired_reason)}` : '') +
                (isSuppressed && entry.suppress_reason ? `<br><span style="color:#666">Suppressed: ${esc(entry.suppress_reason)}</span>` : '') +
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
        if (_drilldownOpen) {
            const hud = document.getElementById('top-hud');
            if (hud) {
                const bottom = hud.getBoundingClientRect().bottom;
                document.documentElement.style.setProperty('--top-hud-height', `${bottom}px`);
            }
        }
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
                    ? `<span class="dd-map-btn" onclick="event.stopPropagation();focusSensorOnMap('${esc(e.sensor)}')" title="${_t('dd.btn.focus_map')}">⊙</span>`
                    : '';

                return `<div class="dd-sensor-row ${rowClass}" onclick="focusSensorOnMap('${esc(e.sensor)}')">` +
                    `<span class="dd-label" style="color:${isFired ? color : '#777'}">${esc(label)}</span>` +
                    `<div class="dd-bar-wrap"><div class="dd-bar-fill" style="width:${pct}%;background:${isFired ? color : '#333'};"></div></div>` +
                    `<span class="dd-score" style="color:${isFired ? color : '#666'}">${e.score > 0 ? '+'+e.score : '—'}</span>` +
                    `<span class="dd-detail">${esc(detail)}</span>` +
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
    const _SENSOR_STATUS_COLOR = { OK: '#00ff88', DEGRADED: '#ffcc00', STALE: '#ffaa00', ERROR: '#ff2222', CIRCUIT_OPEN: '#ff6600', CIRCUIT_OPEN_PERSISTENT: '#cc2200', DISABLED: '#444', INITIALIZING: '#666' };
    let _sensorHealthCache = {};
    function _updateSensorHealthHUD(healthMap) {
        if (!healthMap) return;
        _sensorHealthCache = healthMap;
        const dotsEl  = document.getElementById('hud-sensor-dots');
        const sysChip = document.getElementById('hud-sys-chip');
        const entries = Object.entries(healthMap).sort((a, b) => a[0].localeCompare(b[0]));
        let ok = 0, stale = 0, err = 0, disabled = 0;
        const errNames = [], staleNames = [];
        const dots = [];
        entries.forEach(([name, v]) => {
            const st = typeof v === 'string' ? v : (v.status || 'DISABLED');
            let cls = 'hud-sdot-off';
            if (st === 'OK') { ok++; cls = 'hud-sdot-ok'; }
            else if (st === 'DEGRADED' || st === 'STALE') { stale++; staleNames.push(name); cls = 'hud-sdot-stale'; }
            else if (st === 'ERROR' || st === 'CIRCUIT_OPEN' || st === 'CIRCUIT_OPEN_PERSISTENT') { err++; errNames.push(name); cls = 'hud-sdot-err'; }
            else disabled++;
            dots.push(`<span class="hud-sensor-dot ${cls}" title="${name}: ${st}"></span>`);
        });
        if (dotsEl) dotsEl.innerHTML = dots.join('');
        if (sysChip) {
            const lines = [`OK: ${ok}  STALE: ${stale}  ERR: ${err}  OFF: ${disabled}`];
            if (errNames.length)   lines.push('ERR: ' + errNames.join(', '));
            if (staleNames.length) lines.push('STALE: ' + staleNames.join(', '));
            sysChip.setAttribute('data-tooltip', lines.join('\n'));
        }
    }

    // ── History Analysis Panel ─────────────────────────────────────────────
    function _historyPanelOnShow() {
        // Populate theater selector from DB (all theaters with recorded data)
        const sel = document.getElementById('hist-theater');
        if (sel) {
            const prev = sel.value;
            fetch('/api/history/theaters').then(r => {
                if (!r.ok) throw new Error(r.status);
                return r.json();
            }).then(data => {
                const theaters = data.theaters || [];
                if (!theaters.length) return;
                sel.innerHTML = '';
                theaters.forEach(t => {
                    const o = document.createElement('option');
                    o.value = t; o.textContent = t;
                    sel.appendChild(o);
                });
                // Keep previous selection, or default to core theater
                const core = getCurrentConfig().core;
                sel.value = prev && theaters.includes(prev) ? prev : theaters.includes(core) ? core : theaters[0];
                loadHistoryData();
            }).catch(() => loadHistoryData());
        } else {
            loadHistoryData();
        }
    }
    const toggleHistoryPanel = _createPanelToggle('history-panel', { onShow: _historyPanelOnShow });
    window.toggleHistoryPanel = toggleHistoryPanel;

    // TL color mapping used across history panel
    const _TL_COLORS = ['#ff2222','#ff4444','#ffaa00','#ffff00','#66ff66'];
    function _tlColor(tl) { return _TL_COLORS[Math.max(0,Math.min(4,(tl||1)-1))]; }

    window.loadHistoryData = function() {
        const theater = document.getElementById('hist-theater')?.value || 'TW';
        const hours = parseInt(document.getElementById('hist-range')?.value || '168');

        fetch(`/api/history/timeseries?country=${theater}&hours=${hours}&series=combined,l3,l7`)
            .then(r => r.json())
            .then(data => _drawScoreChart(data))
            .catch(e => console.error('[History] timeseries error:', e));

        fetch(`/api/history/hod_baseline?country=${theater}&type=hod_baseline`)
            .then(r => r.json())
            .then(data => _drawHodChart(data))
            .catch(e => console.error('[History] hod error:', e));

        fetch(`/api/history/sequence_events?country=${theater}&hours=${hours}`)
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
        if (elPeak) { elPeak.textContent = peak.toFixed(1); elPeak.style.color = peak >= 10 ? '#ff2222' : peak >= 5 ? '#ffaa00' : '#0ff'; }
        if (elAvg) elAvg.textContent = avg.toFixed(1);

        // Fixed Y-axis: 0–25 (spike factor cap) so severity is always visually apparent
        const mn = 0, mx = 25;
        const range = mx;

        // TL zone backgrounds — severity bands
        const zones = [
            { from: 0,  to: 2,  color: 'rgba(34,170,68,0.06)' },   // Normal
            { from: 2,  to: 5,  color: 'rgba(102,204,0,0.06)' },   // Elevated
            { from: 5,  to: 10, color: 'rgba(255,170,0,0.06)' },   // Warning
            { from: 10, to: 18, color: 'rgba(255,102,0,0.08)' },   // Severe
            { from: 18, to: 25, color: 'rgba(255,34,34,0.10)' },   // Critical
        ];
        zones.forEach(z => {
            const yBot = pad.top + ch - (z.from / mx) * ch;
            const yTop = pad.top + ch - (z.to / mx) * ch;
            ctx.fillStyle = z.color;
            ctx.fillRect(pad.left, yTop, cw, yBot - yTop);
        });

        // Grid lines + Y labels (0, 5, 10, 15, 20, 25)
        ctx.strokeStyle = '#1a1a1a'; ctx.lineWidth = 0.5;
        ctx.fillStyle = '#555'; ctx.font = '8px monospace'; ctx.textAlign = 'right';
        for (let yVal = 0; yVal <= 25; yVal += 5) {
            const y = pad.top + ch - (yVal / mx) * ch;
            ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
            ctx.fillText(yVal, pad.left - 4, y + 3);
        }
        ctx.textAlign = 'left';

        // X helper
        const toX = i => pad.left + (i / (scored.length - 1)) * cw;
        const toY = v => pad.top + ch - (Math.min(v, mx) / range) * ch;

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
        // Group events by date
        const groups = {};
        events.slice(-50).forEach(e => {
            const d = new Date(e.ts * 1000);
            const day = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
            if (!groups[day]) groups[day] = [];
            groups[day].push(e);
        });
        let html = '';
        Object.keys(groups).sort().reverse().forEach(day => {
            const dayEvents = groups[day];
            // Count types for day summary
            const typeCounts = {};
            dayEvents.forEach(e => {
                const k = Object.keys(colorMap).find(k => e.type.includes(k)) || 'OTHER';
                typeCounts[k] = (typeCounts[k]||0) + 1;
            });
            const typeBadges = Object.entries(typeCounts).map(([k,n]) => {
                const c = colorMap[k] || '#0ff';
                return `<span style="color:${c};font-size:8px;">${k}×${n}</span>`;
            }).join(' ');

            html += `<div style="margin-bottom:6px;">`;
            html += `<div style="display:flex;align-items:center;gap:6px;padding:2px 0;border-bottom:1px solid #1a1a1a;margin-bottom:2px;">`;
            html += `<span style="color:#888;font-size:9px;font-weight:bold;">${day}</span>`;
            html += `<span>${typeBadges}</span>`;
            html += `</div>`;
            dayEvents.forEach(e => {
                const dt = new Date(e.ts * 1000);
                const timeStr = `${String(dt.getHours()).padStart(2,'0')}:${String(dt.getMinutes()).padStart(2,'0')}`;
                const key = Object.keys(colorMap).find(k => e.type.includes(k)) || '';
                const color = colorMap[key] || '#0ff';
                const icon = iconMap[key] || '◇';
                const meta = e.meta ? `<span style="color:#444;margin-left:4px;">${typeof e.meta === 'string' ? esc(e.meta) : esc(JSON.stringify(e.meta).slice(0,60))}</span>` : '';
                html += `<div class="hist-seq-item">` +
                       `<span style="color:${color};font-size:10px;">${icon}</span>` +
                       `<div><span style="color:#555;font-size:8px;">${timeStr}</span> ` +
                       `<span style="color:${color};font-weight:bold;font-size:9px;">${e.type}</span>${meta}</div>` +
                       `</div>`;
            });
            html += `</div>`;
        });
        el.innerHTML = html;
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

        // ── Alert Details: show only TL transitions with duration ──
        if (el) {
            // Collapse consecutive same-TL alerts into transitions
            const transitions = [];
            for (let i = 0; i < alerts.length; i++) {
                const a = alerts[i];
                const tl = a.threat_level || 1;
                const prev = transitions[transitions.length - 1];
                if (!prev || prev.tl !== tl) {
                    // New TL level — close previous and start new
                    if (prev) prev.endTs = a.ts;
                    transitions.push({ tl, startTs: a.ts, endTs: null, core: a.core || '', score: a.score || 0, peakScore: a.score || 0 });
                } else {
                    // Same TL — update peak score
                    if ((a.score || 0) > prev.peakScore) prev.peakScore = a.score || 0;
                }
            }

            // Group transitions by date
            const groups = {};
            transitions.forEach(t => {
                const d = new Date(t.startTs * 1000);
                const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
                if (!groups[key]) groups[key] = [];
                groups[key].push(t);
            });

            const _fmtDur = sec => {
                if (!sec || sec <= 0) return _t('panel.history.dur.ongoing');
                if (sec < 60) return `${Math.round(sec)}s`;
                if (sec < 3600) return `${Math.round(sec/60)}m`;
                const h = Math.floor(sec/3600), m = Math.round((sec%3600)/60);
                return m > 0 ? `${h}h${m}m` : `${h}h`;
            };

            let html = '';
            const sortedDays = Object.keys(groups).sort().reverse();
            sortedDays.forEach(day => {
                const dayTrans = groups[day];
                const maxTl = Math.min(...dayTrans.map(t => t.tl));
                const dayColor = _tlColor(maxTl);
                const changes = dayTrans.length;

                html += `<div style="margin-bottom:8px;">`;
                html += `<div style="display:flex;align-items:center;gap:6px;padding:2px 0;border-bottom:1px solid #1a1a1a;margin-bottom:3px;">`;
                html += `<span style="color:#888;font-size:9px;font-weight:bold;">${day}</span>`;
                html += `<span style="color:#555;font-size:8px;">${changes !== 1 ? _t('panel.history.label.transitions', {n: changes}) : _t('panel.history.label.transition', {n: changes})}</span>`;
                html += `</div>`;

                dayTrans.forEach((t, idx) => {
                    const dt = new Date(t.startTs * 1000);
                    const timeStr = `${String(dt.getHours()).padStart(2,'0')}:${String(dt.getMinutes()).padStart(2,'0')}`;
                    const color = _tlColor(t.tl);
                    const dur = t.endTs ? _fmtDur(t.endTs - t.startTs) : _t('panel.history.dur.ongoing');
                    const prevTl = idx > 0 ? dayTrans[idx-1].tl : t.tl;
                    const arrow = t.tl < prevTl ? `<span style="color:#ff2222;font-size:9px;">▲</span>`
                                : t.tl > prevTl ? `<span style="color:#22aa44;font-size:9px;">▼</span>`
                                : `<span style="color:#333;font-size:9px;">→</span>`;

                    html += `<div class="hist-alert-row" style="padding:2px 0;">` +
                           `<span style="color:#555;font-size:8px;min-width:36px;">${timeStr}</span>` +
                           `${arrow}` +
                           `<span class="hist-tl-badge" style="background:${color}22;color:${color};border:1px solid ${color}44;">TL${t.tl}</span>` +
                           `<span style="color:#666;font-size:8px;min-width:40px;">${dur}</span>` +
                           `<span style="color:#555;font-size:8px;">${_t('panel.history.label.peak')} <b style="color:#aaa">${t.peakScore.toFixed(1)}</b></span>` +
                           `</div>`;
                });
                html += `</div>`;
            });
            el.innerHTML = html || `<span style="color:#555">${_t('panel.history.no_alerts')}</span>`;
        }
    }

    window.exportHistoryData = function() {
        const theater = document.getElementById('hist-theater')?.value || 'TW';
        window.open(`/api/history/export?country=${theater}`, '_blank');
    };


    // ══════════════════════════════════════════════════════════════════════════
    // ── What-If Simulation / SPOF Analysis ────────────────────────────────
    // ══════════════════════════════════════════════════════════════════════════

    // ── G. What-If Simulation Panel ──────────────────────────────────────────
    const toggleWhatIfPanel = _createPanelToggle('whatif-panel', { onShow: initWhatIfPanel });

    let _whatifCatalog = null;

    async function initWhatIfPanel() {
        const panel = document.getElementById('whatif-panel');
        if (!panel || panel.style.display === 'none') return;
        const body = panel.querySelector('.whatif-body');
        if (!body) return;

        // Load catalog once
        if (!_whatifCatalog) {
            try {
                const res = await fetch('/api/whatif/catalog');
                const data = await res.json();
                _whatifCatalog = data.sensors || [];
            } catch(e) {
                body.innerHTML = `<div style="color:#666;text-align:center;font-size:10px;">${_t('panel.whatif.api_error')}</div>`;
                return;
            }
        }

        renderWhatIfForm(body);
    }

    function renderWhatIfForm(body) {
        const domains = { cyber: [], physical: [], info: [] };
        _whatifCatalog.forEach(s => {
            if (domains[s.domain]) domains[s.domain].push(s);
        });

        const domainLabels = {
            cyber:    { label: 'CYBER',    color: '#00ccff' },
            physical: { label: 'PHYSICAL', color: '#ff8800' },
            info:     { label: 'INFO',     color: '#aa44ff' },
        };

        let html = `<div class="whatif-form">`;

        for (const [d, sensors] of Object.entries(domains)) {
            const dl = domainLabels[d];
            html += `<div class="whatif-domain-group">`;
            html += `<div class="whatif-domain-header" style="color:${dl.color}">${dl.label}</div>`;
            sensors.forEach(s => {
                const isSuppressor = s.is_suppressor;
                html += `<div class="whatif-sensor-row" data-sensor="${s.sensor}">`;
                html += `<label class="whatif-sensor-label" title="${s.sensor}">`;
                html += `<input type="checkbox" class="whatif-cb" data-sensor="${s.sensor}" ${isSuppressor ? 'data-suppressor="1"' : ''}>`;
                html += ` ${s.label}</label>`;
                if (!isSuppressor) {
                    html += `<input type="number" class="whatif-score" data-sensor="${s.sensor}" min="0" max="${s.max_score}" value="${s.max_score}" style="width:32px;">`;
                }
                html += `</div>`;
            });
            html += `</div>`;
        }

        // Bonus controls
        html += `<div class="whatif-bonus-group">`;
        html += `<div class="whatif-domain-header" style="color:#ffcc00">${_t('panel.whatif.bonus_header')}</div>`;
        html += `<div class="whatif-sensor-row">`;
        html += `<label class="whatif-sensor-label"><input type="checkbox" id="whatif-tl1hard"> ${_t('panel.whatif.tl1_hard')}</label>`;
        html += `</div>`;
        html += `<div class="whatif-sensor-row">`;
        html += `<label class="whatif-sensor-label">${_t('panel.whatif.seq_bonus')}</label>`;
        html += `<select id="whatif-seq-bonus" style="width:80px;"><option value="0">0</option><option value="1">+1 (PARTIAL)</option><option value="3">+3 (FULL)</option></select>`;
        html += `</div>`;
        html += `<div class="whatif-sensor-row">`;
        html += `<label class="whatif-sensor-label">${_t('panel.whatif.temporal_bonus')}</label>`;
        html += `<select id="whatif-temporal-bonus" style="width:80px;"><option value="0">0</option><option value="1">+1 (PARTIAL)</option><option value="2">+2 (C2 SYNC)</option></select>`;
        html += `</div>`;
        html += `</div>`;

        html += `<button class="whatif-run-btn" onclick="runWhatIfSimulation()">${_t('panel.whatif.run_btn')}</button>`;
        html += `</div>`;
        html += `<div class="whatif-result" id="whatif-result"></div>`;

        body.innerHTML = html;
    }

    window.runWhatIfSimulation = async function() {
        const events = [];
        document.querySelectorAll('.whatif-cb:checked').forEach(cb => {
            const sensor = cb.dataset.sensor;
            const isSuppressor = cb.dataset.suppressor === '1';
            const scoreEl = document.querySelector(`.whatif-score[data-sensor="${sensor}"]`);
            events.push({
                sensor,
                score: isSuppressor ? 0 : parseInt(scoreEl?.value || 0),
                suppressed: isSuppressor,
            });
        });

        const tl1Hard = document.getElementById('whatif-tl1hard')?.checked || false;
        const seqBonus = parseInt(document.getElementById('whatif-seq-bonus')?.value || 0);
        const temporalBonus = parseInt(document.getElementById('whatif-temporal-bonus')?.value || 0);

        const resultEl = document.getElementById('whatif-result');
        if (!resultEl) return;

        if (events.length === 0) {
            resultEl.innerHTML = `<div style="color:#666;text-align:center;font-size:10px;padding:8px;">${_t('panel.whatif.no_events')}</div>`;
            return;
        }

        resultEl.innerHTML = `<div style="color:#555;text-align:center;font-size:10px;padding:8px;">${_t('panel.whatif.computing')}</div>`;

        try {
            const res = await fetch('/api/whatif/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ events, tl1_hard: tl1Hard, sequence_bonus: seqBonus, temporal_bonus: temporalBonus }),
            });
            const data = await res.json();
            renderWhatIfResult(resultEl, data);
        } catch(e) {
            resultEl.innerHTML = `<div style="color:#ff4444;text-align:center;font-size:10px;padding:8px;">${_t('panel.whatif.api_error')}</div>`;
        }
    };

    function renderWhatIfResult(el, data) {
        const tlColor = _tlColor(data.threat_level);
        const convColors = { FULL_CONVERGENCE: '#ff2222', DUAL_DOMAIN: '#ff8800', SINGLE_DOMAIN: '#ffcc00', NONE: '#444' };
        const convColor = convColors[data.convergence_level] || '#444';

        let html = `<div class="whatif-result-header">`;
        html += `<div class="whatif-tl-badge" style="background:${tlColor}22;color:${tlColor};border:1px solid ${tlColor}55;">`;
        html += `TL${data.threat_level}</div>`;
        html += `<div class="whatif-score-display">`;
        html += `<span style="color:#aaa;font-size:10px;">${_t('panel.whatif.total_score')}: <b style="color:#eee">${data.score_with_bonus}</b></span>`;
        html += `<span style="color:${convColor};font-size:9px;">${data.convergence_level.replace('_', ' ')}</span>`;
        html += `</div></div>`;

        // Domain breakdown
        html += `<div class="whatif-domain-bars">`;
        const dColors = { cyber: '#00ccff', physical: '#ff8800', info: '#aa44ff' };
        for (const [d, info] of Object.entries(data.domain_scores || {})) {
            const pct = Math.min((info.score / 10) * 100, 100);
            html += `<div class="whatif-domain-bar">`;
            html += `<span style="color:${dColors[d]};font-size:9px;min-width:55px;">${d.toUpperCase()} ${info.score}pt</span>`;
            html += `<div class="whatif-bar-track"><div class="whatif-bar-fill" style="width:${pct}%;background:${dColors[d]}"></div></div>`;
            html += `<span style="color:#666;font-size:8px;">${info.status}</span>`;
            html += `</div>`;
        }
        html += `</div>`;

        // Bonus summary
        if (data.convergence_bonus || data.sequence_bonus || data.temporal_bonus) {
            html += `<div class="whatif-bonus-summary">`;
            if (data.convergence_bonus) html += `<span class="whatif-bonus-tag">${_t('panel.whatif.conv_bonus')}: +${data.convergence_bonus}</span>`;
            if (data.sequence_bonus) html += `<span class="whatif-bonus-tag">${_t('panel.whatif.seq_bonus_label')}: +${data.sequence_bonus}</span>`;
            if (data.temporal_bonus) html += `<span class="whatif-bonus-tag">${_t('panel.whatif.temporal_bonus_label')}: +${data.temporal_bonus}</span>`;
            if (data.tl1_hard) html += `<span class="whatif-bonus-tag" style="color:#ff2222;">TL1 HARD ✓</span>`;
            html += `</div>`;
        }

        // System note
        html += `<div class="whatif-note">${data.system_note || ''}</div>`;

        el.innerHTML = html;
    }


    // ── H. SPOF Analysis Panel ───────────────────────────────────────────────
    const toggleSpofPanel = _createPanelToggle('spof-panel', { onShow: renderSpofPanel });

    async function renderSpofPanel() {
        const panel = document.getElementById('spof-panel');
        if (!panel || panel.style.display === 'none') return;
        const body = panel.querySelector('.spof-body');
        if (!body) return;

        body.innerHTML = `<div style="color:#555;text-align:center;font-size:10px;padding:12px;">${_t('panel.spof.loading')}</div>`;

        try {
            const res = await fetch('/api/spof_analysis');
            if (!res.ok) throw new Error('API error');
            const data = await res.json();
            renderSpofContent(body, data);
        } catch(e) {
            body.innerHTML = `<div style="color:#666;text-align:center;font-size:10px;padding:12px;">${_t('panel.spof.api_error')}</div>`;
        }
    }

    function renderSpofContent(body, data) {
        const critColors = { CRITICAL: '#ff2222', HIGH: '#ff8800', MEDIUM: '#ffcc00', LOW: '#44aa44' };
        let html = '';

        // Domain health summary
        html += `<div class="spof-domain-summary">`;
        const dColors = { cyber: '#00ccff', physical: '#ff8800', info: '#aa44ff' };
        for (const [d, info] of Object.entries(data.domain_summary || {})) {
            const redundancy = info.has_redundancy;
            html += `<div class="spof-domain-card" style="border-color:${dColors[d]}33">`;
            html += `<div style="color:${dColors[d]};font-size:9px;font-weight:bold;">${d.toUpperCase()}</div>`;
            html += `<div style="color:#888;font-size:8px;">${_t('panel.spof.sensors_active')}: ${info.fired_count}/${info.sensor_count}</div>`;
            html += redundancy
                ? `<div style="color:#44aa44;font-size:8px;">✓ ${_t('panel.spof.redundant')}</div>`
                : `<div style="color:#ff8800;font-size:8px;">⚠ ${_t('panel.spof.no_redundancy')}</div>`;
            if (info.critical_spofs > 0) {
                html += `<div style="color:#ff2222;font-size:8px;">⛔ ${info.critical_spofs} CRITICAL SPOF</div>`;
            }
            html += `</div>`;
        }
        html += `</div>`;

        // SPOF entries
        if (data.spof_entries && data.spof_entries.length > 0) {
            html += `<div class="spof-list-header">${_t('panel.spof.impact_header')}</div>`;
            data.spof_entries.forEach(entry => {
                const color = critColors[entry.criticality] || '#666';
                html += `<div class="spof-entry" style="border-left:2px solid ${color}">`;
                html += `<div class="spof-entry-top">`;
                html += `<span class="spof-crit-badge" style="color:${color}">${entry.criticality}</span>`;
                html += `<span style="color:#ccc;font-size:9px;">${entry.sensor}</span>`;
                html += `<span style="color:${dColors[entry.domain] || '#888'};font-size:8px;">${entry.domain}</span>`;
                html += `</div>`;
                html += `<div class="spof-entry-detail">`;
                html += `<span style="color:#888;font-size:8px;">${_t('panel.spof.score_impact')}: -${entry.score_impact}pt</span>`;
                if (entry.domain_lost) html += `<span style="color:#ff4444;font-size:8px;">⚠ ${_t('panel.spof.domain_lost')}</span>`;
                if (entry.convergence_downgrade) html += `<span style="color:#ff8800;font-size:8px;">↓ ${entry.convergence_from} → ${entry.convergence_to}</span>`;
                html += `</div>`;
                // Sensor health indicator
                const healthColor = entry.health === 'ok' ? '#44aa44' : entry.health === 'stale' ? '#ffcc00' : '#ff4444';
                html += `<div class="spof-entry-health">`;
                html += `<span style="color:${healthColor};font-size:8px;">● ${entry.health}</span>`;
                if (entry.cache_age_sec != null) html += `<span style="color:#555;font-size:8px;">${Math.round(entry.cache_age_sec/60)}m ago</span>`;
                if (entry.last_error) html += `<span style="color:#ff444488;font-size:7px;" title="${entry.last_error}">err</span>`;
                html += `</div>`;
                html += `</div>`;
            });
        } else {
            html += `<div style="color:#44aa44;text-align:center;font-size:10px;padding:12px;">${_t('panel.spof.no_spof')}</div>`;
        }

        body.innerHTML = html;
    }

    // ── HUD dropdowns + scenario-chip focus ─────────────────────────
    function focusScenarioBar() {
        const bar = document.getElementById('scenario-bar');
        if (!bar) return;
        bar.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        bar.classList.add('scenario-bar-flash');
        setTimeout(() => bar.classList.remove('scenario-bar-flash'), 1200);
    }
    window.focusScenarioBar = focusScenarioBar;

    function _toggleHudMenu(menuId) {
        const menu = document.getElementById(menuId);
        if (!menu) return;
        const isOpen = menu.classList.contains('open');
        document.querySelectorAll('.hud-dropdown.open').forEach(el => el.classList.remove('open'));
        if (!isOpen) menu.classList.add('open');
    }
    function toggleReportMenu()    { _toggleHudMenu('report-menu'); }
    function closeReportMenu()     { const m = document.getElementById('report-menu'); if (m) m.classList.remove('open'); }
    function toggleSettingsMenu()  { _toggleHudMenu('settings-menu'); }
    function closeSettingsMenu()   { const m = document.getElementById('settings-menu'); if (m) m.classList.remove('open'); }
    window.toggleReportMenu   = toggleReportMenu;
    window.closeReportMenu    = closeReportMenu;
    window.toggleSettingsMenu = toggleSettingsMenu;
    window.closeSettingsMenu  = closeSettingsMenu;

    // Click outside any HUD dropdown to close
    document.addEventListener('click', (ev) => {
        if (ev.target.closest('.hud-menu-wrap')) return;
        document.querySelectorAll('.hud-dropdown.open').forEach(el => el.classList.remove('open'));
    });

    // ── Hamburger control panel (right-side slide-out) ─────────────
    // Holds every operational control. Backdrop click + ESC also close.
    function toggleHudHamburger() {
        const panel = document.getElementById('hud-hamburger-panel');
        const btn   = document.getElementById('hud-hamburger-btn');
        if (!panel) return;
        const isOpen = panel.style.display !== 'none';
        if (isOpen) {
            closeHudHamburger();
        } else {
            panel.style.display = 'flex';
            if (btn) btn.classList.add('open');
            // Insert backdrop only if missing
            if (!document.getElementById('hud-hh-backdrop')) {
                const bd = document.createElement('div');
                bd.id = 'hud-hh-backdrop';
                bd.className = 'hh-backdrop';
                bd.onclick = closeHudHamburger;
                document.body.appendChild(bd);
            }
        }
    }
    function closeHudHamburger() {
        const panel = document.getElementById('hud-hamburger-panel');
        const btn   = document.getElementById('hud-hamburger-btn');
        const bd    = document.getElementById('hud-hh-backdrop');
        if (panel) panel.style.display = 'none';
        if (btn)   btn.classList.remove('open');
        if (bd)    bd.remove();
        // Also collapse any nested tools menu
        const tm = document.getElementById('tools-menu');
        if (tm) tm.classList.remove('open');
    }
    window.toggleHudHamburger = toggleHudHamburger;
    window.closeHudHamburger  = closeHudHamburger;
    document.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape') closeHudHamburger();
    });

    // ═══════════════════════════════════════════════════════════════
    // Phase 3: Sync countdown timer
    // ═══════════════════════════════════════════════════════════════
    if (window._syncCountdownInterval) clearInterval(window._syncCountdownInterval);
    window._syncCountdownInterval = setInterval(() => {
        if (!_lastSyncTime) return;
        const elapsed = Date.now() - _lastSyncTime;
        const remaining = Math.max(0, _POLL_INTERVAL_MS - elapsed);
        const mm = String(Math.floor(remaining / 60000)).padStart(2, '0');
        const ss = String(Math.floor((remaining % 60000) / 1000)).padStart(2, '0');
        const el = document.getElementById('update-time');
        if (!el) return;
        if (_wsConnected) {
            el.innerText = `WS Live | ${_t('hud.sync.next')} ${mm}:${ss}`;
        } else {
            el.innerText = `${_t('hud.sync.next')} ${mm}:${ss}`;
        }
    }, 1000);

    // ═══════════════════════════════════════════════════════════════
    // Phase 3 → Phase 4: Sensor × Theater Heatmap
    // ═══════════════════════════════════════════════════════════════
    const toggleCorrHeatmap = _createPanelToggle('corr-heatmap-panel', { floating: false, onShow: renderCorrHeatmap });
    let _heatmapDomain = 'all'; // 'all' | 'cyber' | 'physical' | 'info'

    // Sensor definitions for the heatmap: name, short label, domain, data extractor
    // Extractor: (intel, tgtDetail, code, sa) → {level: 0|1|2, label: string, tip: string}
    //   level: 0=quiet, 1=warning, 2=alert
    const _HEATMAP_SENSORS = [
        { name: 'cloudflare_radar', lbl: 'CF',   domain: 'cyber',    extract: (_i, td) => {
            const sp = td && td.avg_spike || 0;
            return sp >= 3 ? {level:2, label:sp.toFixed(1)+'×', tip:'DDoS spike '+sp.toFixed(1)+'×'}
                 : sp >= 1.5 ? {level:1, label:sp.toFixed(1)+'×', tip:'Elevated '+sp.toFixed(1)+'×'}
                 : {level:0, label:sp > 0 ? sp.toFixed(1)+'×' : '—', tip:'Normal'};
        }},
        { name: 'ioda_bgp', lbl: 'IODA', domain: 'cyber',    extract: (i) => {
            const st = i.ioda_status || 'NORMAL';
            return st === 'BGP_OUTAGE' ? {level: i.is_bgp_degraded ? 2 : 1, label:'OUT', tip:'BGP Outage'+(i.is_bgp_degraded?'':' (Wx)')}
                 : {level:0, label:'OK', tip:'Normal'};
        }},
        { name: 'ripe_bgp', lbl: 'BGP',  domain: 'cyber',    extract: (i) => {
            const b = i.bgp_routing || {};
            return b.is_anomaly ? {level:2, label:'⚠'+((b.drop_pct||0))+'%', tip:'BGP anomaly, drop '+(b.drop_pct||0)+'%'}
                 : {level:0, label:b.announced_prefixes != null ? b.announced_prefixes+'pfx' : '—', tip:'Stable'};
        }},
        { name: 'check_host', lbl: 'CH',  domain: 'cyber',    extract: (_i, _td, code, sa) => {
            const ch = (sa.analytics || {}).check_host || {};
            if (resolveChainTargetCountry(sa) !== code) return {level:-1, label:'—', tip:'Core only'};
            const sr = ch.country_success_rate ?? ch.theater_success_rate;
            return sr != null && sr < 0.5 ? {level:2, label:Math.round(sr*100)+'%', tip:'Reachability '+Math.round(sr*100)+'%'}
                 : sr != null && sr < 0.9 ? {level:1, label:Math.round(sr*100)+'%', tip:'Partial: '+Math.round(sr*100)+'%'}
                 : {level:0, label:sr != null ? Math.round(sr*100)+'%' : '—', tip:'OK'};
        }},
        { name: 'threatfox', lbl: 'TFX', domain: 'cyber',    extract: (_i, _td, code, sa) => {
            const r = (sa.rationale_matrix||[]).find(e => e.sensor === 'threatfox');
            return r && r.status === 'FIRED' ? {level:1, label:'⚠', tip:r.fired_reason||'Active'} : {level:0, label:'—', tip:'Clear'};
        }},
        { name: 'greynoise', lbl: 'GN',  domain: 'cyber',    extract: (_i, _td, code, sa) => {
            const gn = (sa.analytics || {}).greynoise || {};
            if (gn.suppressing) return {level:1, label:'NOISE', tip:'Noise dominant — suppressing cyber'};
            return {level:0, label:gn.noise_class || '—', tip:gn.noise_class || 'Unknown'};
        }},
        { name: 'openweather', lbl: 'WX', domain: 'physical', extract: (i) => {
            const wx = i.weather || {};
            const s = wx.severity || 'NORMAL';
            return s === 'SEVERE' ? {level:2, label:'SEV', tip:wx.condition||'Severe weather'}
                 : s === 'MODERATE' ? {level:1, label:'MOD', tip:wx.condition||'Moderate'}
                 : {level:0, label:'OK', tip:wx.condition||'Normal'};
        }},
        { name: 'opensky', lbl: 'AIR',   domain: 'physical', extract: (i) => {
            const a = i.airspace || {};
            return a.status === 'CLOSURE' || a.status === 'ANOMALY' ? {level:2, label:a.status.slice(0,4), tip:a.airport+': '+a.status}
                 : a.status === 'WEATHER_NOISE' ? {level:1, label:'Wx', tip:a.airport+': weather noise'}
                 : {level:0, label:a.count != null ? a.count : '—', tip:a.airport||'—'};
        }},
        { name: 'ihr_health', lbl: 'IHR', domain: 'physical', extract: (i) => {
            const st = i.ihr_status || 'NORMAL';
            return st === 'DISCO_EVENT' ? {level:2, label:'DISCO', tip:'IHR disconnection event'}
                 : st === 'HEGEMONY_ALARM' ? {level:1, label:'HEG', tip:'Hegemony alarm'}
                 : st === 'DELAY_ANOMALY' ? {level:1, label:'DLY', tip:'Delay anomaly'}
                 : {level:0, label:'OK', tip:'Normal'};
        }},
        { name: 'ripe_atlas', lbl: 'ATL', domain: 'physical', extract: (i) => {
            const a = i.ripe_atlas || {};
            const st = a.status || 'NORMAL';
            return st === 'PROBE_BLACKOUT' ? {level:2, label:'OUT', tip:'Probe blackout'}
                 : st === 'PROBE_DROP' ? {level:1, label:'DROP', tip:'Probe drop'}
                 : {level:0, label:a.probes && a.probes.active != null ? a.probes.active : '—', tip:'Normal'};
        }},
        { name: 'isr_hotspot', lbl: 'ISR', domain: 'physical', extract: (_i, _td, code, sa) => {
            const isr = (sa.analytics || {}).isr || {};
            if (resolveChainTargetCountry(sa) !== code) return {level:-1, label:'—', tip:'Core only'};
            return isr.is_surge ? {level:2, label:isr.count, tip:'ISR surge: '+isr.count+' aircraft'}
                 : isr.count > 0 ? {level:0, label:isr.count, tip:isr.count+' aircraft'}
                 : {level:0, label:'0', tip:'No ISR activity'};
        }},
        { name: 'ais_maritime', lbl: 'AIS', domain: 'physical', extract: (_i, _td, code, sa) => {
            const ais = (sa.analytics || {}).ais || {};
            if (resolveChainTargetCountry(sa) !== code) return {level:-1, label:'—', tip:'Core only'};
            return ais.has_anomaly ? {level:2, label:ais.dark_gaps+'gap', tip:'Dark gaps: '+ais.dark_gaps}
                 : {level:0, label:'OK', tip:'Normal'};
        }},
        { name: 'space_weather', lbl: 'SpWx', domain: 'physical', extract: (_i, _td, _c, sa) => {
            const sw = (sa.analytics || {}).space_weather || {};
            if (sw.suppressing) return {level:2, label:sw.storm_level||'⚠', tip:'Suppressing physical: '+(sw.suppress_reason||'')};
            const kp = sw.kp_index;
            return kp >= 5 ? {level:1, label:'Kp'+kp, tip:'Kp index: '+kp} : {level:0, label:kp != null ? 'Kp'+kp : '—', tip:'Quiet'};
        }},
        { name: 'gdelt', lbl: 'GDT',     domain: 'info',     extract: (i) => {
            const g = i.gdelt || {};
            return g.status === 'ALERT' ? {level:2, label:g.tone_current != null ? g.tone_current.toFixed(0) : '⚠', tip:'GDELT alert, tone='+((g.tone_current||0).toFixed(1))}
                 : {level:0, label:g.tone_current != null ? g.tone_current.toFixed(0) : '—', tip:'Tone: '+(g.tone_current||'—')};
        }},
        { name: 'rss_narrative', lbl: 'RSS', domain: 'info',  extract: (_i, _td, code, sa) => {
            const r = (sa.rationale_matrix||[]).find(e => e.sensor === 'rss_narrative');
            return r && r.status === 'FIRED' ? {level:1, label:'⚠', tip:r.fired_reason||'Narrative burst'} : {level:0, label:'—', tip:'Clear'};
        }},
        { name: 'telegram_mirror', lbl: 'TG', domain: 'info', extract: (_i, _td, code, sa) => {
            const tg = (sa.analytics || {}).telegram_mirror || {};
            if (resolveChainTargetCountry(sa) !== code) return {level:-1, label:'—', tip:'Core only'};
            return tg.has_intent ? {level:2, label:'INTENT', tip:'Telegram intent detected'}
                 : tg.status === 'TARGETS_FOUND' ? {level:1, label:'TGT', tip:'Targets found'}
                 : {level:0, label:tg.status||'—', tip:tg.status||'Pending'};
        }},
        { name: 'tor_metrics', lbl: 'TOR',  domain: 'info',   extract: (i) => {
            const t = i.tor_metrics || {};
            const st = t.status || 'NORMAL';
            return st === 'CENSORSHIP_INDICATOR' ? {level:2, label:'CENS', tip:'Censorship indicator'}
                 : st === 'RELAY_DROP' ? {level:1, label:'DROP', tip:'Relay drop'}
                 : st === 'USER_SURGE' ? {level:1, label:'SURGE', tip:'User surge'}
                 : {level:0, label:'OK', tip:'Normal'};
        }},
    ];

    function renderCorrHeatmap() {
        const panel = document.getElementById('corr-heatmap-panel');
        if (!panel || (panel.style.display === 'none' && !panel.closest('#left-sidebar'))) return;
        const body = panel.querySelector('.corr-heatmap-body');
        if (!body) return;

        const sa = latestData && latestData.strategic_alert;
        if (!sa) {
            body.innerHTML = `<div style="color:#666; font-size:10px; text-align:center; padding:10px 0;">${_t('panel.corr.no_data')}</div>`;
            return;
        }

        const countryIntel = sa.country_intel || {};
        const targets = latestData.targets || [];
        const tgtMap = {};
        targets.forEach(t => { tgtMap[t.code] = t; });

        // Theaters: core + correlates (from targets list)
        const theaters = targets.map(t => t.code).filter(c => c);
        if (!theaters.length) {
            body.innerHTML = `<div style="color:#666; font-size:10px; text-align:center; padding:10px 0;">${_t('panel.corr.no_data')}</div>`;
            return;
        }

        // Filter sensors by domain
        const sensors = _heatmapDomain === 'all' ? _HEATMAP_SENSORS
            : _HEATMAP_SENSORS.filter(s => s.domain === _heatmapDomain);

        let html = '';
        // Domain toggle buttons
        html += `<div class="corr-toggle-group">`;
        ['all', 'cyber', 'physical', 'info'].forEach(m => {
            const active = m === _heatmapDomain ? ' corr-toggle-active' : '';
            const label = _t('panel.heatmap.toggle.' + m);
            html += `<button class="corr-toggle-btn${active}" onclick="_setCorrMode('${m}')">${label}</button>`;
        });
        html += `</div>`;

        const isDocked = !panel.classList.contains('floating');
        const labelCol = isDocked ? 32 : 40;
        const n = theaters.length;

        html += `<div class="corr-grid-wrap">`;
        const compactCls = isDocked ? ' corr-grid-compact' : '';
        html += `<div class="corr-grid${compactCls}" style="grid-template-columns: ${labelCol}px repeat(${n}, 1fr);">`;

        // Header row: theater codes
        html += `<div class="corr-corner"></div>`;
        const _coreCode = resolveChainTargetCountry(sa);
        theaters.forEach(t => {
            const isCore = t === _coreCode;
            html += `<div class="corr-col-label" style="${isCore ? 'color:#00ffff;font-weight:bold;' : ''}">${t}</div>`;
        });

        // Sensor rows
        const domainColors = {cyber:'#4488ff', physical:'#ff8800', info:'#aa66ff'};
        sensors.forEach(sensor => {
            const domCol = domainColors[sensor.domain] || '#888';
            html += `<div class="corr-row-label" style="color:${domCol};" data-tooltip="${sensor.name}">${sensor.lbl}</div>`;
            theaters.forEach(code => {
                const intel = countryIntel[code] || {};
                const td = tgtMap[code] || {};
                const cell = sensor.extract(intel, td, code, sa);
                if (cell.level === -1) {
                    // No data for this theater
                    html += `<div class="corr-cell" style="background:transparent; color:#333;" data-tooltip="${sensor.lbl}@${code}: ${cell.tip}">—</div>`;
                } else {
                    const bg = cell.level === 2 ? 'rgba(255,34,0,0.25)'
                             : cell.level === 1 ? 'rgba(255,170,0,0.2)'
                             : 'rgba(255,255,255,0.03)';
                    const fg = cell.level === 2 ? '#ff4444'
                             : cell.level === 1 ? '#ffaa00'
                             : '#666';
                    html += `<div class="corr-cell" style="background:${bg}; color:${fg};" data-tooltip="${sensor.lbl}@${code}: ${cell.tip}">${cell.label}</div>`;
                }
            });
        });

        html += `</div></div>`;

        // Legend
        html += `<div class="corr-legend">`;
        html += `<span style="color:#666;">● ${_t('panel.heatmap.legend.quiet')}</span>`;
        html += `<span style="color:#ffaa00;">● ${_t('panel.heatmap.legend.warning')}</span>`;
        html += `<span style="color:#ff4444;">● ${_t('panel.heatmap.legend.alert')}</span>`;
        html += `</div>`;

        body.innerHTML = html;
    }

    function _setCorrMode(mode) {
        _heatmapDomain = mode;
        renderCorrHeatmap();
    }
    window._setCorrMode = _setCorrMode;

    // ═══════════════════════════════════════════════════════════════════════════
    //  STRATEGIC CLIMATE FEED
    // ═══════════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════════
    // LLM INTELLIGENCE PANEL
    // ═══════════════════════════════════════════════════════════════════════════
    let _llmActiveFilter = 'triage';
    let _llmItems = [];

    const toggleLlmIntelPanel = _createPanelToggle('llm-intel-panel', { onShow: _fetchLlmIntel });
    window.toggleLlmIntelPanel = toggleLlmIntelPanel;

    function _fetchLlmIntel() {
        const isTriage = _llmActiveFilter === 'triage';
        const url = isTriage
            ? '/api/intel/pending/triage?limit=50'
            : '/api/intel' + (_llmActiveFilter === 'all' ? '' : '?source_type=' + _llmActiveFilter);
        fetch(url)
            .then(r => r.json())
            .then(data => {
                _llmItems = data.items || [];
                if (!isTriage) _renderLlmStats(data.stats || {});
                if (isTriage) _renderTriageItems(_llmItems, data);
                else _renderLlmItems(_llmItems);
            })
            .catch(e => console.debug('[Intel] fetch failed:', e));
        fetch('/api/intel/stats')
            .then(r => r.json())
            .then(s => { _renderLlmStatusBar(s); _renderLlmStats(s); })
            .catch(e => console.debug('[Intel] stats fetch failed:', e));
    }

    function _renderTriageItems(items, payload) {
        const list = document.getElementById('llm-intel-list');
        if (!list) return;
        if (!items || items.length === 0) {
            list.innerHTML = '<div class="llm-empty">' + _t('panel.llm_intel.triage_empty') + '</div>';
            return;
        }
        const summary = '<div class="llm-triage-summary">'
            + _t('panel.llm_intel.triage_showing') + ' '
            + (payload.shown || items.length) + ' / ' + (payload.total_pending || items.length)
            + '</div>';
        list.innerHTML = summary + items.map(_renderTriageItem).join('');
    }

    function _renderTriageItem(item) {
        const lang = (typeof _currentLang !== 'undefined') ? _currentLang : 'en';
        const conf = item.confidence || 0;
        const confPct = Math.round(conf * 100) + '%';
        const confClass = conf >= 0.80 ? 'llm-item-conf-hi' : conf >= 0.65 ? 'llm-item-conf-mid' : 'llm-item-conf-lo';
        const priority = item.priority || 0;
        const prPct = Math.min(100, Math.round(priority * 100));
        const prClass = priority >= 0.5 ? 'llm-pr-hi' : priority >= 0.25 ? 'llm-pr-mid' : 'llm-pr-lo';
        const ageStr = (item.age_hours != null) ? item.age_hours.toFixed(1) + 'h' : '—';
        const badgeClass = 'llm-badge-' + (item.source_type || 'unknown');
        const badgeLabel = _escHtml((item.source_type || '').toUpperCase());
        const scoreStr = item.score_delta > 0 ? ' +' + item.score_delta + ' ' + _escHtml((item.domain || '').toUpperCase()) : '';

        let scenarioLine = '';
        if (item.top_scenario) {
            const sc = item.top_scenario;
            const scName = lang === 'ja' ? (sc.name_ja || sc.name_en) : sc.name_en;
            scenarioLine = '<div class="llm-tri-scenario">'
                + '<span class="llm-tri-scenario-label">' + _t('panel.llm_intel.triage_scenario') + ':</span> '
                + '<span class="llm-tri-scenario-name">' + _escHtml(scName) + '</span> '
                + '<span class="llm-tri-coupling" title="' + _t('panel.llm_intel.triage_coupling_tip') + '">'
                + '⊗ ' + sc.coupling.toFixed(2) + ' (' + _escHtml(sc.country) + ')</span>'
                + '</div>';
        } else if (item.matched_scenarios && item.matched_scenarios.length === 0) {
            scenarioLine = '<div class="llm-tri-scenario llm-tri-no-scenario">'
                + '<span>⚠ ' + _t('panel.llm_intel.triage_no_scenario') + '</span>'
                + '</div>';
        }

        let corrLine = '';
        if (item.corroboration_count > 0) {
            const ecos = item.corroborating_ecosystems || [];
            corrLine = '<span class="llm-tri-corr" title="' + _escHtml((item.corroborating_sources || []).join(', ')) + '">'
                     + '✦ ' + _t('panel.llm_intel.triage_corroborated') + ' ×' + item.corroboration_count
                     + (ecos.length > 1 ? ' [' + _escHtml(ecos.join('/')) + ']' : '')
                     + '</span>';
        }

        const gateReason = item.gate_reason || 'manual_review';
        const gateLabel = _t('panel.llm_intel.gate.' + gateReason.split(':')[0]) || gateReason;
        const gateExtra = gateReason.includes(':') ? ' (' + _escHtml(gateReason.split(':')[1]) + ')' : '';
        const gateTip = _t('panel.llm_intel.gate.' + gateReason.split(':')[0] + '_tip') || gateReason;
        const gateLine = '<span class="llm-tri-gate llm-tri-gate-' + _escHtml(gateReason.split(':')[0]) + '" '
                       + 'title="' + _escHtml(gateTip) + '">'
                       + '⊘ ' + _escHtml(gateLabel) + gateExtra
                       + '</span>';

        // F3 source reliability: tier classification (trusted ≥0.75 = auto-confirm
        // floor; standard 0.50–0.75; unverified <0.50). Badge color hints at how
        // much weight the analyst should put on this single source alone.
        const credVal = item.source_credibility || 0;
        const credTier = credVal >= 0.75 ? 'trusted' : credVal >= 0.50 ? 'standard' : 'unverified';
        const credTierLabel = _t('panel.llm_intel.cred_tier.' + credTier);
        const sourceIdShort = item.source_id ? _escHtml(String(item.source_id).replace(/_/g, ' ')) : '';
        const credLine = '<span class="llm-tri-cred llm-tri-cred-' + credTier + '" title="'
                       + _escAttr(_t('panel.llm_intel.cred_tier_tip', { tier: credTierLabel, src: sourceIdShort, val: credVal.toFixed(2) }))
                       + '">'
                       + (credTier === 'trusted' ? '★ ' : credTier === 'standard' ? '◆ ' : '○ ')
                       + 'CRED ' + credVal.toFixed(2)
                       + '</span>';

        let actions = '<button class="llm-btn llm-btn-raw" onclick="_llmToggleRaw(\'' + _escHtml(item.id) + '\')">' + _t('panel.llm_intel.btn_raw') + '</button>';
        actions += '<button class="llm-btn llm-btn-confirm" onclick="_llmConfirm(\'' + _escHtml(item.id) + '\')">'
                 + _t('panel.llm_intel.btn_confirm') + (scoreStr ? ' ' + scoreStr : '') + '</button>';
        actions += '<button class="llm-btn llm-btn-reject" onclick="_llmReject(\'' + _escHtml(item.id) + '\')">' + _t('panel.llm_intel.btn_dismiss') + '</button>';
        actions += '<button class="llm-btn llm-btn-false-pos" onclick="_llmRejectFP(\'' + _escHtml(item.id) + '\')">' + _t('panel.llm_intel.btn_false_pos') + '</button>';

        return `<div class="llm-item llm-item-triage" id="llm-item-${_escHtml(item.id)}">
            <div class="llm-tri-bar">
                <div class="llm-tri-bar-fill ${prClass}" style="width:${prPct}%"></div>
                <span class="llm-tri-bar-label">PR ${priority.toFixed(2)}</span>
            </div>
            <div class="llm-item-header">
                <span class="llm-item-badge ${badgeClass}">${badgeLabel}</span>
                <span class="llm-item-time">${ageStr}</span>
                <span class="llm-item-theater">${_escHtml(item.country ?? item.theater ?? '')}</span>
                <span class="${confClass}">${confPct}</span>
                ${credLine}
                ${corrLine}
            </div>
            <div class="llm-item-headline">${_escHtml(item.headline || '')}</div>
            ${scenarioLine}
            <div class="llm-tri-meta">${gateLine}</div>
            <div class="llm-item-raw" id="llm-raw-${_escHtml(item.id)}">${_escHtml(item.raw_text || '')}</div>
            <div class="llm-item-actions">${actions}</div>
        </div>`;
    }

    function _renderLlmStatusBar(stats) {
        const dot  = document.getElementById('llm-status-dot');
        const text = document.getElementById('llm-status-text');
        const mdl  = document.getElementById('llm-status-model');
        if (dot) {
            if (!stats.llm_enabled) {
                dot.className  = 'llm-status-dot offline';
                text.textContent = _t('panel.llm_intel.status_disabled');
                mdl.textContent  = '';
            } else if (stats.llm_online) {
                dot.className  = 'llm-status-dot online';
                text.textContent = _t('panel.llm_intel.status_online');
                mdl.textContent  = '';
            } else {
                dot.className  = 'llm-status-dot offline';
                text.textContent = _t('panel.llm_intel.status_offline');
                mdl.textContent  = '';
            }
        }
        _applyTriagePulse(stats && stats.triage_pulse);
    }

    // Q3: non-disruptive pulse on LLM Intelligence menu item when stale high-priority pending exists.
    function _applyTriagePulse(pulse) {
        const item  = document.getElementById('tm-item-llm');
        const badge = document.getElementById('tm-triage-badge-llm');
        if (!item) return;
        const count = (pulse && typeof pulse.count === 'number') ? pulse.count : 0;
        if (count > 0) {
            item.classList.add('tm-pulse');
            if (badge) {
                badge.hidden = false;
                badge.textContent = count > 99 ? '99+' : String(count);
                const oldest = pulse.oldest_stale_hours != null ? pulse.oldest_stale_hours.toFixed(1) : '?';
                badge.title = _t('panel.llm_intel.pulse_tip', { n: count, h: oldest });
            }
        } else {
            item.classList.remove('tm-pulse');
            if (badge) { badge.hidden = true; badge.title = ''; }
        }
    }

    function _renderLlmStats(stats) {
        const setEl = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
        setEl('llm-stat-auto',    '● AUTO '    + (stats.auto_confirmed || 0));
        setEl('llm-stat-pending', '⚠ ' + _t('panel.llm_intel.stat_pending') + ' ' + (stats.pending || 0));
        setEl('llm-stat-reject',  '✗ ' + _t('panel.llm_intel.stat_rejected') + ' ' + ((stats.rejected || 0) + (stats.overridden || 0)));
        const reviewEl = document.getElementById('llm-stat-review');
        if (reviewEl) {
            const rv = stats.review_needed || 0;
            reviewEl.style.display = rv > 0 ? '' : 'none';
            reviewEl.textContent = '🔴 ' + _t('panel.llm_intel.stat_review') + ' ' + rv;
        }
    }

    function _renderLlmItems(items) {
        const list = document.getElementById('llm-intel-list');
        if (!list) return;
        if (!items || items.length === 0) {
            list.innerHTML = '<div class="llm-empty">' + _t('panel.llm_intel.empty') + '</div>';
            return;
        }
        list.innerHTML = items.map(item => _renderLlmItem(item)).join('');
    }

    function _renderLlmItem(item) {
        const statusClass = 'llm-item-status-' + (item.status || 'pending');
        const badgeClass  = 'llm-badge-' + (item.source_type || 'unknown');
        const badgeLabel  = _escHtml((item.source_type || '').toUpperCase());
        const timeStr     = item.ts ? new Date(item.ts * 1000).toLocaleTimeString('ja-JP', {hour:'2-digit', minute:'2-digit'}) : '—';
        const conf        = item.confidence || 0;
        const confClass   = conf >= 0.80 ? 'llm-item-conf-hi' : conf >= 0.65 ? 'llm-item-conf-mid' : 'llm-item-conf-lo';
        const confPct     = Math.round(conf * 100) + '%';
        const scoreStr    = item.score_delta > 0 ? ' +' + item.score_delta + ' ' + _escHtml((item.domain || '').toUpperCase()) : '';
        const isAuto      = item.status === 'auto_confirmed';
        const isPending   = item.status === 'pending' || item.status === 'review_needed';
        const isReview    = item.status === 'review_needed';

        // Status label
        let statusLabel = '';
        if (isAuto)    statusLabel = '<span class="llm-status-label-auto">AUTO</span>';
        else if (isReview)  statusLabel = '<span class="llm-status-label-review">REVIEW</span>';
        else if (isPending) statusLabel = '<span class="llm-status-label-pending">PENDING</span>';
        else if (item.status === 'confirmed')  statusLabel = '<span class="llm-status-label-confirmed">CONFIRMED</span>';
        else if (item.status === 'rejected' || item.status === 'overridden') statusLabel = '<span class="llm-status-label-rejected">' + _escHtml(item.status.toUpperCase()) + '</span>';

        // Score applied display
        const scoreApplied = (isAuto || item.status === 'confirmed') && scoreStr
            ? '<div style="font-size:9px;color:#44cc88;margin-top:2px;">' + _t('panel.llm_intel.score_applied') + ': ' + scoreStr + '</div>'
            : '';

        // Action buttons
        let actions = '<button class="llm-btn llm-btn-raw" onclick="_llmToggleRaw(\'' + _escHtml(item.id) + '\')" data-i18n="panel.llm_intel.btn_raw">' + _t('panel.llm_intel.btn_raw') + '</button>';
        if (isPending) {
            actions += '<button class="llm-btn llm-btn-confirm" onclick="_llmConfirm(\'' + _escHtml(item.id) + '\')" data-i18n="panel.llm_intel.btn_confirm">'
                     + _t('panel.llm_intel.btn_confirm') + (scoreStr ? ' ' + scoreStr : '') + '</button>';
            actions += '<button class="llm-btn llm-btn-reject" onclick="_llmReject(\'' + _escHtml(item.id) + '\')" data-i18n="panel.llm_intel.btn_dismiss">' + _t('panel.llm_intel.btn_dismiss') + '</button>';
            actions += '<button class="llm-btn llm-btn-false-pos" onclick="_llmRejectFP(\'' + _escHtml(item.id) + '\')" data-i18n="panel.llm_intel.btn_false_pos">' + _t('panel.llm_intel.btn_false_pos') + '</button>';
        } else if (isAuto) {
            actions += '<button class="llm-btn llm-btn-override" onclick="_llmOverride(\'' + _escHtml(item.id) + '\')" data-i18n="panel.llm_intel.btn_override">' + _t('panel.llm_intel.btn_override') + '</button>';
        } else if (item.status === 'confirmed' || item.status === 'rejected') {
            actions += '<button class="llm-btn llm-btn-revert" onclick="_llmRevert(\'' + _escHtml(item.id) + '\')" data-i18n="panel.llm_intel.btn_revert">' + _t('panel.llm_intel.btn_revert') + '</button>';
        }

        return `<div class="llm-item ${statusClass}" id="llm-item-${_escHtml(item.id)}">
            <div class="llm-item-header">
                <span class="llm-item-badge ${badgeClass}">${badgeLabel}</span>
                <span class="llm-item-time">${timeStr}</span>
                ${statusLabel}
                <span class="llm-item-theater">${_escHtml(item.country ?? item.theater ?? '')}</span>
            </div>
            <div class="llm-item-headline">${_escHtml(item.headline || '')}</div>
            <div class="llm-item-conf"><span class="${confClass}">${confPct}</span> conf${scoreApplied ? '' : (scoreStr ? '<span class="llm-item-score">' + scoreStr + '</span>' : '')}</div>
            ${scoreApplied}
            <div class="llm-item-raw" id="llm-raw-${_escHtml(item.id)}">${_escHtml(item.raw_text || '')}</div>
            <div class="llm-item-actions">${actions}</div>
        </div>`;
    }

    window._llmFilter = function(src) {
        _llmActiveFilter = src;
        document.querySelectorAll('.llm-filter-btn').forEach(b => {
            b.classList.toggle('llm-filter-active', b.dataset.src === src);
        });
        _fetchLlmIntel();
    };

    window._llmToggleRaw = function(itemId) {
        const el = document.getElementById('llm-raw-' + itemId);
        if (el) el.classList.toggle('visible');
    };

    window._llmConfirm = function(itemId) {
        fetch('/api/intel/' + encodeURIComponent(itemId) + '/confirm', { method: 'POST' })
            .then(r => r.json())
            .then(() => { _fetchLlmIntel(); fetchDDoSData(); })
            .catch(() => {});
    };

    window._llmReject = function(itemId) {
        fetch('/api/intel/' + encodeURIComponent(itemId) + '/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ classification: 'irrelevant' }),
        })
            .then(r => r.json())
            .then(() => { _fetchLlmIntel(); fetchDDoSData(); })
            .catch(() => {});
    };

    window._llmRejectFP = function(itemId) {
        fetch('/api/intel/' + encodeURIComponent(itemId) + '/reject', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ classification: 'false_positive' }),
        })
            .then(r => r.json())
            .then(() => { _fetchLlmIntel(); fetchDDoSData(); })
            .catch(() => {});
    };

    window._llmRevert = function(itemId) {
        fetch('/api/intel/' + encodeURIComponent(itemId) + '/revert', { method: 'POST' })
            .then(r => r.json())
            .then(() => { _fetchLlmIntel(); fetchDDoSData(); })
            .catch(() => {});
    };

    window._llmOverride = function(itemId) {
        if (!confirm(_t('panel.llm_intel.override_confirm'))) return;
        fetch('/api/intel/' + encodeURIComponent(itemId) + '/override', { method: 'POST' })
            .then(r => r.json().then(data => ({ ok: r.ok, data })))
            .then(({ ok, data }) => {
                if (!ok || !data.ok) {
                    const err = (data && data.error) || '';
                    alert(_t('panel.llm_intel.override_failed') + (err ? ' — ' + err : ''));
                    _fetchLlmIntel();
                    return;
                }
                // Success: refresh intel panel AND immediately re-fetch threat score
                _fetchLlmIntel();
                fetchDDoSData(true);
            })
            .catch(() => {});
    };

    // Auto-refresh when panel is visible (called from main poll loop)
    window._updateLlmIntelFromPoll = function() {
        const panel = document.getElementById('llm-intel-panel');
        if (panel && panel.style.display !== 'none') {
            _fetchLlmIntel();
            if (_llmDiagOpen) _fetchLlmDiag();
        }
    };

    // ═══════════════════════════════════════════════════════════════════════════
    // LLM Intel Diagnostics (sensor-layer observability)
    //   — surfaces /api/intel/llm_call_stats so operators can distinguish
    //     "sensor silent" from "LLM down" from "all dropped by sensor filter"
    //     without shelling into the container.
    // ═══════════════════════════════════════════════════════════════════════════
    let _llmDiagOpen = false;
    let _llmDiagWindow = 24;

    window._llmToggleDiag = function() {
        _llmDiagOpen = !_llmDiagOpen;
        const body = document.getElementById('llm-diag-body');
        const chev = document.getElementById('llm-diag-chev');
        if (body) body.style.display = _llmDiagOpen ? 'block' : 'none';
        if (chev) chev.classList.toggle('open', _llmDiagOpen);
        if (_llmDiagOpen) _fetchLlmDiag();
    };

    window._llmSetDiagWindow = function(hours) {
        _llmDiagWindow = hours;
        document.querySelectorAll('.llm-diag-win-btn').forEach(b => {
            b.classList.toggle('llm-diag-win-active', Number(b.dataset.win) === hours);
        });
        if (_llmDiagOpen) _fetchLlmDiag();
    };

    function _fetchLlmDiag() {
        fetch('/api/intel/llm_call_stats?hours=' + _llmDiagWindow)
            .then(r => r.json())
            .then(data => _renderLlmDiag(data))
            .catch(e => console.debug('[Diag] fetch failed:', e));
    }

    function _renderLlmDiag(data) {
        const body = document.getElementById('llm-diag-body');
        if (!body) return;
        const per = (data && data.per_caller) || [];
        const breakdown = (data && data.sensor_filter_breakdown) || [];

        if (!per.length) {
            body.innerHTML = '<div class="llm-diag-empty">' + _t('panel.llm_intel.diag_empty') + '</div>';
            return;
        }

        // Per-caller stats table.  Each row shows: sensor | total | auto | pend |
        // filtered | dedup | err | avg_conf | avg_ms. "err" sums parse_failed +
        // http_error + timeout + exception.
        const hdr = '<tr>'
            + '<th class="col-name">' + _t('panel.llm_intel.diag_col_sensor') + '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_calls') + '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_auto')    + '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_pending') + '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_filtered')+ '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_dedup')   + '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_err')     + '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_conf')    + '</th>'
            + '<th>' + _t('panel.llm_intel.diag_col_ms')      + '</th>'
            + '</tr>';

        const cls = (n, cssClass) => n > 0 ? '<td class="' + cssClass + '">' + n + '</td>' : '<td class="llm-diag-val-muted">0</td>';
        const rows = per.map(r => {
            const err = (r.parse_failed || 0) + (r.http_error || 0) + (r.timeout || 0) + (r.exception || 0);
            const conf = r.avg_confidence != null ? r.avg_confidence.toFixed(2) : '—';
            const ms   = r.avg_duration_ms != null ? r.avg_duration_ms : '—';
            return '<tr>'
                + '<td class="col-name">' + _escHtml(r.caller || '') + '</td>'
                + '<td>' + (r.total || 0) + '</td>'
                + cls(r.auto_confirmed,  'llm-diag-val-ok')
                + cls(r.pending,         'llm-diag-val-pending')
                + cls(r.sensor_filtered, 'llm-diag-val-filtered')
                + cls(r.discarded_dedup, 'llm-diag-val-dedup')
                + cls(err,               'llm-diag-val-err')
                + '<td>' + conf + '</td>'
                + '<td>' + ms + '</td>'
                + '</tr>';
        }).join('');

        let html = '<table class="llm-diag-table">' + hdr + rows + '</table>';

        // Sensor-layer filter breakdown list. Empty if no filters fired.
        if (breakdown.length) {
            html += '<div class="llm-diag-breakdown-title">'
                 + _t('panel.llm_intel.diag_breakdown_title') + '</div>';
            html += breakdown.map(b => '<div class="llm-diag-reason-row">'
                + '<span class="rr-sensor">' + _escHtml(b.caller || '') + '</span>'
                + '<span class="rr-reason">' + _escHtml(b.reason || '') + '</span>'
                + '<span class="rr-count">'  + (b.count || 0) + '</span>'
                + '</div>').join('');
        }

        body.innerHTML = html;
    }

    // ═══════════════════════════════════════════════════════════════════════════

    let _climateActiveFilter = 'all';

    const toggleClimatePanel = _createPanelToggle('climate-panel', { onShow: _fetchClimateData });
    window.toggleClimatePanel = toggleClimatePanel;

    function _fetchClimateData() {
        fetch('/api/climate').then(r => r.json()).then(data => {
            _renderClimateGauge(data.gauge || {});
            _renderClimateFeed(data.feed || []);
        }).catch(() => {});
    }

    // Update HUD badge from main polling loop data
    function _updateClimateHud(gaugeData) {
        const badge = document.getElementById('hud-climate-badge');
        const dot = document.getElementById('hud-climate-dot');
        const text = document.getElementById('hud-climate-text');
        if (!badge || !gaugeData || !gaugeData.level) return;

        const level = gaugeData.level;
        const colors = { FROZEN: '#4488aa', COOL: '#44aa66', WARMING: '#ffaa00', HOT: '#ff6622', FLASHPOINT: '#ff2a2a' };
        const color = colors[level] || '#666';

        dot.setAttribute('data-level', level);
        text.textContent = _t('climate.badge_prefix') + ': ' + level;
        text.style.color = color;
        badge.style.borderColor = color + '44';

        // Also update panel gauge if visible
        _renderClimateGauge(gaugeData);
    }

    function _renderClimateGauge(gauge) {
        const fill = document.getElementById('climate-gauge-fill');
        const levelEl = document.getElementById('climate-gauge-level');
        if (!fill || !levelEl) return;

        const level = gauge.level || 'COOL';
        const colors = { FROZEN: '#4488aa', COOL: '#44aa66', WARMING: '#ffaa00', HOT: '#ff6622', FLASHPOINT: '#ff2a2a' };
        fill.setAttribute('data-level', level);
        levelEl.textContent = level;
        levelEl.style.color = colors[level] || '#666';
    }

    function _renderClimateFeed(events) {
        const container = document.getElementById('climate-feed');
        if (!container) return;

        const filtered = _climateActiveFilter === 'all' ? events
            : events.filter(e => e.axis === _climateActiveFilter);

        if (!filtered.length) {
            container.innerHTML = `<div style="color:#555; font-size:10px; text-align:center; padding:20px 0;">${_t('panel.climate.no_events')}</div>`;
            return;
        }

        const axisIcons = { time: '⏱', space: '📍', target: '🎯', context: '📅' };

        container.innerHTML = filtered.map(ev => {
            const icon = axisIcons[ev.axis] || '•';
            return `<div class="climate-event" data-severity="${ev.severity}">
                <div class="climate-event-header">
                    <span class="climate-event-ts">${_fmtTs(ev.ts_iso, ev.ts)}</span>
                    <span class="climate-event-tag" data-axis="${ev.axis}">${icon} ${(ev.indicator || '').toUpperCase()}</span>
                    <span class="climate-event-headline">${_escHtml(ev.headline || '')}</span>
                </div>
                <div class="climate-event-detail">${_escHtml(ev.detail || '')}</div>
            </div>`;
        }).join('');
    }

    function _climateFilter(axis) {
        _climateActiveFilter = axis;
        document.querySelectorAll('.climate-filter-btn').forEach(btn => {
            btn.classList.toggle('climate-filter-active', btn.getAttribute('data-axis') === axis);
        });
        // Re-fetch and render
        _fetchClimateData();
    }
    window._climateFilter = _climateFilter;

    function _fmtTs(iso, epoch) {
        if (iso) {
            const d = new Date(iso);
            if (!isNaN(d)) return d.toLocaleString();
        }
        if (epoch) {
            const d = new Date(epoch * 1000);
            if (!isNaN(d)) return d.toLocaleString();
        }
        return iso || '';
    }

    // Semantic aliases for esc() — _escHtml for element text content,
    // _escAttr for attribute values. Both delegate to the same esc() sanitizer;
    // separate names exist for readability at call sites.
    function _escHtml(s) { return esc(s); }
    function _escAttr(s) { return esc(s); }

    // Expose for main render loop
    window._updateClimateFromPoll = function(data) {
        if (data && data.climate_gauge) {
            _updateClimateHud(data.climate_gauge);
        }
        // Auto-refresh climate panel if visible
        const cp = document.getElementById('climate-panel');
        if (cp && cp.style.display !== 'none') {
            _fetchClimateData();
        }
    };

    // ── Scenario Bar (Phase 4) ─────────────────────────────────────────
    let _scenarioFocusId = localStorage.getItem('radar_focused_scenario') || null;

    function _getScenarioFocus() {
        if (_scenarioFocusId) return _scenarioFocusId;
        return (window._lastThreatData || {}).focused_scenario || '';
    }

    let _scenarioDetailOpen = null;
    let _scenarioWhatIfExcluded = new Set();

    function renderScenarioBar(data) {
        const container = document.getElementById('scenario-cards');
        if (!container) return;
        const scenarios = data.scenarios || {};
        const focusedId = data.focused_scenario || '';
        const lang = (typeof _currentLang !== 'undefined') ? _currentLang : 'en';
        const ids = Object.keys(scenarios);
        if (ids.length === 0) { container.innerHTML = ''; return; }

        // Sort: focused stays anchored at the left so analyst always sees their
        // active scenario first. Background cards then sort by velocity_pts_per_hour
        // descending — most operationally urgent (fastest-rising) at the top so
        // analysts catch escalation candidates without scrolling. Missing/null
        // velocity falls below all numeric values; ties break by id for stability.
        const velOf = (sid) => {
            const v = (scenarios[sid] || {}).velocity_pts_per_hour;
            return (typeof v === 'number' && isFinite(v)) ? v : -Infinity;
        };
        const sorted = ids.slice().sort((a, b) => {
            if (a === focusedId) return -1;
            if (b === focusedId) return 1;
            const va = velOf(a), vb = velOf(b);
            if (va !== vb) return vb - va;
            return a.localeCompare(b);
        });

        let html = '';
        for (const sid of sorted) {
            const sc = scenarios[sid];
            const isFocused = (sid === focusedId);
            const name = lang === 'ja' ? (sc.name_ja || sc.name_en || sid) : (sc.name_en || sid);
            const tl = sc.tl;
            const score = (sc.score || 0).toFixed(2);
            const mode = sc.scoring_mode || 'lite';
            const domains = sc.domains || {};

            const cardClass = isFocused ? 'sc-card sc-card-focused' : 'sc-card';
            const badge = isFocused
                ? `<span class="sc-badge sc-badge-focused">${_t('scenario.badge.focused')}</span>`
                : `<span class="sc-badge sc-badge-lite">${_t('scenario.badge.lite')}</span>`;

            const liteInsufficient = _isLiteInsufficient(sc, isFocused);
            let tlHtml = '';
            if (liteInsufficient) {
                tlHtml = `<span class="sc-tl sc-tl-lite-insufficient" `
                       + `title="${_t('scenario.tl.lite_insufficient_tip')}">`
                       + `${_t('scenario.tl.lite_insufficient')}</span>`;
            } else if (tl != null) {
                tlHtml = `<span class="sc-tl sc-tl-${tl}">TL${tl}</span>`;
            }

            const cyberActive = (domains.cyber || 0) > 0 ? 'sc-domain-active' : 'sc-domain-inactive';
            const physActive  = (domains.physical || 0) > 0 ? 'sc-domain-active' : 'sc-domain-inactive';
            const infoActive  = (domains.info || 0) > 0 ? 'sc-domain-active' : 'sc-domain-inactive';

            let tooltip = '';
            if (isFocused) {
                const parts = [
                    `Score: ${score}`,
                    `Cyber: ${(domains.cyber||0).toFixed(2)}`,
                    `Physical: ${(domains.physical||0).toFixed(2)}`,
                    `Info: ${(domains.info||0).toFixed(2)}`,
                ];
                if (sc.convergence_bonus) parts.push(`Convergence: +${sc.convergence_bonus.toFixed(2)}`);
                if (sc.active_countries && sc.active_countries.length) parts.push(`Countries: ${sc.active_countries.join(', ')}`);
                tooltip = ` data-tooltip="${_escHtml(parts.join('\n'))}"`;
            }

            const safeSid = _escHtml(sid);
            const detailBtn = ` onclick="toggleScenarioDetail('${safeSid}')"`;

            // Phase A: Velocity trend arrow
            const vTrend = sc.velocity_trend || 'stable';
            const vPtsH = sc.velocity_pts_per_hour;
            const trendCls = vTrend === 'rising' ? 'sc-trend-rising'
                           : vTrend === 'falling' ? 'sc-trend-falling'
                           : 'sc-trend-stable';
            const trendIcon = vTrend === 'rising' ? '▲'
                            : vTrend === 'falling' ? '▼' : '—';
            const trendTip = vPtsH != null
                ? `${vPtsH > 0 ? '+' : ''}${vPtsH.toFixed(1)} pts/h`
                : vTrend;

            // Pattern warning badges (focused only) — row1 right
            let patternHtml = '';
            if (isFocused && sc.patterns) {
                if (sc.patterns.silent_divergence && sc.patterns.silent_divergence.detected) {
                    patternHtml += `<span class="sc-pattern-badge sc-pattern-silent-div" `
                         + `title="${_t('scenario.pattern.silent_div_tip')}">`
                         + `${_t('scenario.pattern.silent_div')}</span>`;
                }
                if (sc.patterns.context_alignment && sc.patterns.context_alignment.score >= 3) {
                    const axLabel = sc.patterns.context_alignment.label || 'HIGH';
                    patternHtml += `<span class="sc-pattern-badge sc-pattern-ctx-align" `
                         + `title="${_t('scenario.pattern.ctx_align_tip')}">`
                         + `${_escHtml(axLabel)}</span>`;
                }
            }

            // ETA display (focused only) — row2 right
            let etaHtml = '';
            if (isFocused && sc.eta_to_next_tl) {
                const eta = sc.eta_to_next_tl;
                const etaH = Math.round(eta.eta_sec / 3600);
                const etaDir = eta.direction === 'escalating' ? '↑' : '↓';
                const etaLabel = etaH >= 1
                    ? `ETA ${etaDir}TL${eta.target_tl}: ~${etaH}h`
                    : `ETA ${etaDir}TL${eta.target_tl}: <1h`;
                etaHtml = `<span class="sc-eta" title="${_t('scenario.eta_tip')}">${_escHtml(etaLabel)}</span>`;
            }

            // Lite bias warning tag (background cards only) — row2
            let liteTagHtml = '';
            if (!isFocused && sc.lite_bias_warning) {
                liteTagHtml = `<span class="sc-lite-tag">${_t('scenario.badge.lite_warn')}</span>`;
            }

            // Coverage badge (background cards only) — row2
            // Surfaces NP6 transparency: when fewer than 2/3 domains have any
            // signal, the lite-mode score is structurally biased. Tooltip
            // names the missing domains so analysts can decide if the gap is
            // expected (e.g. info-only periods) or a real blind spot.
            let coverageBadgeHtml = '';
            if (!isFocused && sc.indicators
                && sc.indicators.coverage_completeness != null
                && sc.indicators.coverage_completeness < 0.66) {
                const covPct = Math.round(sc.indicators.coverage_completeness * 100);
                const covCls = sc.indicators.coverage_completeness <= 0.33
                    ? 'sc-coverage-badge sc-coverage-critical'
                    : 'sc-coverage-badge sc-coverage-warn';
                const blind = (sc.indicators.blind_domains || []).join(', ') || '—';
                const covTip = _t('scenario.coverage.tip', { pct: covPct, blind: blind });
                const covLabel = _t('scenario.coverage.badge', { pct: covPct });
                coverageBadgeHtml = `<span class="${covCls}" title="${_escHtml(covTip)}">${_escHtml(covLabel)}</span>`;
            }

            // Focus switch button (background cards only) — row1 right
            let focusBtnHtml = '';
            if (!isFocused) {
                focusBtnHtml = `<span class="sc-focus-btn" `
                     + `onclick="event.stopPropagation();window.switchScenarioFocus('${safeSid}')" `
                     + `title="${_t('scenario.btn.switch_focus_tip')}">◎</span>`;
            }

            // ── Render: 2-row layout ─────────────────────────────────────
            // row1 (primary): TL | name (ellipsis, fills) | pattern + ◎
            // row2 (meta):    badge • score • C/P/I dots • trend • ETA [• lite-tag]
            html += `<div class="${cardClass}"${detailBtn}${tooltip}>`;
            html += `<div class="sc-row-primary">`;
            html += tlHtml;
            html += `<span class="sc-name" title="${_escHtml(name)}">${_escHtml(name)}</span>`;
            html += patternHtml;
            html += focusBtnHtml;
            html += `</div>`;
            html += `<div class="sc-row-meta">`;
            html += badge;
            html += `<span class="sc-score">${score}</span>`;
            html += `<span class="sc-domains">`;
            html += `<span class="sc-domain-dot sc-domain-cyber ${cyberActive}">C</span>`;
            html += `<span class="sc-domain-dot sc-domain-physical ${physActive}">P</span>`;
            html += `<span class="sc-domain-dot sc-domain-info ${infoActive}">I</span>`;
            html += `</span>`;
            html += `<span class="sc-trend ${trendCls}" title="${_escHtml(trendTip)}">${trendIcon}</span>`;
            html += etaHtml;
            html += liteTagHtml;
            html += coverageBadgeHtml;

            // F2 data freshness: chip turns warning when scenario score is built
            // from cache older than 60s (config-aligned with TTL).
            if (sc.data_freshness_sec != null) {
                const fs = Math.max(0, Math.floor(sc.data_freshness_sec));
                const fsLabel = fs < 60 ? `${fs}s` : `${Math.floor(fs / 60)}m`;
                const stale = fs > 90;
                const fcls = stale ? 'sc-fresh sc-fresh-stale' : 'sc-fresh';
                html += `<span class="${fcls}" title="${_t('scenario.freshness_tip', { age: fsLabel })}">⏲ ${_escHtml(fsLabel)}</span>`;
            }

            html += `</div>`;
            html += `</div>`;
        }
        container.innerHTML = html;

        if (_scenarioDetailOpen && scenarios[_scenarioDetailOpen]) {
            _renderScenarioDetail(scenarios[_scenarioDetailOpen], _scenarioDetailOpen);
        }
    }

    window._closeScenarioDetail = function() {
        const panel = document.getElementById('scenario-detail-panel');
        if (panel) panel.style.display = 'none';
        _scenarioDetailOpen = null;
    };

    window.toggleScenarioDetail = function(scenarioId) {
        const panel = document.getElementById('scenario-detail-panel');
        if (!panel) return;
        if (_scenarioDetailOpen === scenarioId) {
            panel.style.display = 'none';
            _scenarioDetailOpen = null;
            return;
        }
        _scenarioDetailOpen = scenarioId;
        _scenarioWhatIfExcluded = new Set();
        const data = window._lastThreatData;
        if (!data || !data.scenarios || !data.scenarios[scenarioId]) return;
        _renderScenarioDetail(data.scenarios[scenarioId], scenarioId);
        const scBar = document.getElementById('scenario-bar');
        if (scBar) {
            const bottom = scBar.getBoundingClientRect().bottom;
            document.documentElement.style.setProperty('--scenario-detail-top', `${bottom + 4}px`);
        }
        panel.style.display = '';
    };

    function _renderScenarioDetail(sc, scenarioId) {
        const panel = document.getElementById('scenario-detail-panel');
        if (!panel) return;
        const lang = (typeof _currentLang !== 'undefined') ? _currentLang : 'en';
        const name = lang === 'ja' ? (sc.name_ja || sc.name_en || scenarioId) : (sc.name_en || scenarioId);
        const isFocused = sc.is_focused;
        const contributions = sc.contributions || [];
        const domains = sc.domains || {};

        let html = `<div class="sc-detail-header">`;
        html += `<span class="sc-detail-title">${_escHtml(name)}</span>`;
        const safeScenarioId = _escHtml(scenarioId);
        html += `<span class="sc-detail-mode ${isFocused ? 'sc-mode-full' : 'sc-mode-lite'}">${_escHtml(sc.scoring_mode || 'lite')}</span>`;
        const detailLiteInsufficient = _isLiteInsufficient(sc, isFocused);
        if (detailLiteInsufficient) {
            html += `<span class="sc-tl sc-tl-lite-insufficient" `
                 + `title="${_t('scenario.tl.lite_insufficient_tip')}">`
                 + `${_t('scenario.tl.lite_insufficient')}</span>`;
        } else if (sc.tl != null) {
            html += `<span class="sc-tl sc-tl-${sc.tl}">TL${sc.tl}</span>`;
        }
        html += `<span class="sc-detail-score">${_t('scenario.detail.score')}: ${(sc.score||0).toFixed(2)}</span>`;
        if (!isFocused) {
            html += `<button class="sc-detail-focus-btn" `
                 + `onclick="event.stopPropagation();window.switchScenarioFocus('${safeScenarioId}')">`
                 + `${_t('scenario.btn.switch_focus')}</button>`;
        }
        html += `<span class="sc-detail-close" onclick="toggleScenarioDetail('${safeScenarioId}')">✕</span>`;
        html += `</div>`;

        if (!isFocused && sc.lite_bias_warning) {
            html += `<div class="sc-bias-warning">`;
            html += `<span class="sc-bias-icon">⚠</span> `;
            html += `<span>${_t('scenario.detail.lite_bias')}</span>`;
            html += `</div>`;
        }

        html += `<div class="sc-detail-domains">`;
        for (const d of ['cyber', 'physical', 'info']) {
            const v = (domains[d] || 0).toFixed(2);
            const cls = parseFloat(v) > 0 ? `sc-dom-bar sc-dom-${d}` : `sc-dom-bar sc-dom-${d} sc-dom-zero`;
            html += `<div class="${cls}"><span class="sc-dom-label">${d.charAt(0).toUpperCase()}</span> <span class="sc-dom-val">${v}</span></div>`;
        }
        if (sc.convergence_bonus) {
            html += `<div class="sc-dom-bar sc-dom-conv"><span class="sc-dom-label">+</span> <span class="sc-dom-val">${sc.convergence_bonus.toFixed(2)}</span></div>`;
        }
        html += `</div>`;

        // Layer 3 session overlay UI (ADR-003) — focused scenario, analyst+ only
        if (isFocused) {
            const _scRole = localStorage.getItem('radar_role') || 'viewer';
            const _scLevel = _ROLE_LEVEL[_scRole] ?? 0;
            if (_scLevel >= 1) {
                const ov = _scGetOverlay(scenarioId) || {};
                const ovActive = Object.keys(ov).length > 0;
                const parts = sc.participants || {};
                const editing = _scOverlayEditOpen.has(scenarioId);
                html += `<div class="sc-overlay-section${ovActive ? ' sc-overlay-active' : ''}">`;
                html += `<div class="sc-overlay-header">`;
                html += `<span class="sc-overlay-title">${_t('scenario.overlay.title')}</span>`;
                if (ovActive) html += ` <span class="sc-overlay-badge">${_t('scenario.overlay.active_badge')}</span>`;
                html += ` <button class="btn-tactical sc-overlay-toggle" onclick="event.stopPropagation();scToggleOverlayEdit('${safeScenarioId}')">${editing ? '▾' : '▸'} ${_t('scenario.overlay.edit')}</button>`;
                if (ovActive) {
                    html += ` <button class="btn-tactical sc-overlay-reset-btn" onclick="event.stopPropagation();scResetOverlay('${safeScenarioId}')">${_t('scenario.overlay.reset')}</button>`;
                }
                html += `</div>`;
                if (editing) {
                    html += `<div class="sc-overlay-help">${_t('scenario.overlay.help')}</div>`;
                    html += `<div class="sc-overlay-grid">`;
                    for (const cc of Object.keys(parts)) {
                        const p = parts[cc] || {};
                        const baseW = (p.base_weight != null ? p.base_weight
                                      : (p.weight != null ? p.weight : 0.5));
                        const curW = (ov[cc] != null) ? ov[cc]
                                    : (p.weight != null ? p.weight : baseW);
                        const changed = (ov[cc] != null) && Math.abs(ov[cc] - baseW) > 1e-6;
                        html += `<div class="sc-overlay-row${changed ? ' sc-overlay-row-changed' : ''}">`;
                        html += `<span class="sc-overlay-cc">${_escHtml(cc)}</span>`;
                        html += `<span class="sc-overlay-role">${_t('scenario.role.' + p.role)}</span>`;
                        html += `<input type="range" class="sc-overlay-range" min="0" max="1" step="0.05" `
                             + `value="${curW}" `
                             + `data-sc-id="${safeScenarioId}" data-sc-cc="${_escHtml(cc)}" data-sc-base="${baseW}" `
                             + `oninput="scOnOverlayInput(this)" `
                             + `onclick="event.stopPropagation();">`;
                        html += `<span class="sc-overlay-val" id="sc-ov-val-${_escHtml(cc)}">${curW.toFixed(2)}</span>`;
                        html += `<span class="sc-overlay-base">(${baseW.toFixed(2)})</span>`;
                        html += `</div>`;
                    }
                    html += `</div>`;
                    html += `<div class="sc-overlay-actions">`;
                    html += `<button class="btn-tactical sc-overlay-apply-btn" onclick="event.stopPropagation();scApplyOverlay('${safeScenarioId}')">${_t('scenario.overlay.apply')}</button>`;
                    html += `<button class="btn-tactical" onclick="event.stopPropagation();scToggleOverlayEdit('${safeScenarioId}')">${_t('scenario.overlay.close')}</button>`;
                    html += `</div>`;
                }
                html += `</div>`;
            }
        }

        if (contributions.length > 0) {
            const whatIfResult = _computeWhatIf(sc, contributions);

            if (_scenarioWhatIfExcluded.size > 0 && whatIfResult) {
                html += `<div class="sc-whatif-result">`;
                html += `<span class="sc-whatif-label">${_t('scenario.detail.whatif_result')}</span> `;
                html += `<span class="sc-whatif-score">${whatIfResult.score.toFixed(2)}</span>`;
                if (whatIfResult.tl != null) html += ` <span class="sc-tl sc-tl-${whatIfResult.tl}">TL${whatIfResult.tl}</span>`;
                html += ` <span class="sc-whatif-delta">(${whatIfResult.delta >= 0 ? '+' : ''}${whatIfResult.delta.toFixed(2)})</span>`;
                html += `</div>`;
            }

            html += `<div class="sc-contrib-header">`;
            html += `<span>${_t('scenario.detail.contributions')} (${contributions.length})</span>`;
            if (isFocused) html += ` <button class="btn-tactical sc-whatif-btn" onclick="scResetWhatIf()">${_t('scenario.detail.whatif_reset')}</button>`;
            html += `</div>`;
            html += `<table class="sc-contrib-table"><thead><tr>`;
            html += `<th>${_t('scenario.detail.col_sensor')}</th>`;
            html += `<th>${_t('scenario.detail.col_country')}</th>`;
            html += `<th>${_t('scenario.detail.col_role')}</th>`;
            html += `<th>${_t('scenario.detail.col_raw')}</th>`;
            html += `<th>${_t('scenario.detail.col_llm_w')}</th>`;
            html += `<th>${_t('scenario.detail.col_part_w')}</th>`;
            html += `<th>${_t('scenario.detail.col_contrib')}</th>`;
            html += `<th>${_t('scenario.detail.col_evidence')}</th>`;
            if (isFocused) html += `<th>${_t('scenario.detail.col_whatif')}</th>`;
            html += `</tr></thead><tbody>`;
            for (let i = 0; i < contributions.length; i++) {
                const c = contributions[i];
                const s = c.signal || {};
                const excluded = _scenarioWhatIfExcluded.has(i);
                const rowCls = excluded ? 'sc-contrib-excluded' : '';
                html += `<tr class="${rowCls}" onclick="scToggleContribDetail(${i})" style="cursor:pointer;">`;
                html += `<td class="sc-td-sensor"><span class="sc-sensor-domain sc-sensor-${s.domain || 'info'}">${(s.domain||'?')[0].toUpperCase()}</span> ${_escHtml(s.sensor || '')}</td>`;
                html += `<td class="sc-td-cc">${_escHtml(c.contributing_country)}</td>`;
                html += `<td class="sc-td-role">${_t('scenario.role.' + c.participant_role)}</td>`;
                html += `<td class="sc-td-num">${(s.raw_score || 0).toFixed(1)}</td>`;
                html += `<td class="sc-td-num">${c.llm_country_weight.toFixed(2)}</td>`;
                html += `<td class="sc-td-num">${c.participant_weight.toFixed(2)}</td>`;
                html += `<td class="sc-td-num sc-td-contrib">${c.final_contribution.toFixed(2)}</td>`;
                html += `<td class="sc-td-link">`;
                if (s.evidence_url) {
                    html += `<a href="${safeHref(s.evidence_url)}" target="_blank" rel="noopener" onclick="event.stopPropagation();" title="${esc(s.evidence_url)}">🔗</a>`;
                }
                html += `</td>`;
                if (isFocused) {
                    html += `<td class="sc-td-whatif"><button class="btn-tactical sc-whatif-toggle ${excluded ? 'sc-whatif-on' : ''}" onclick="event.stopPropagation();scToggleWhatIf(${i})">${excluded ? '✓' : '✕'}</button></td>`;
                }
                html += `</tr>`;
                html += `<tr class="sc-contrib-detail" id="sc-contrib-detail-${i}" style="display:none;"><td colspan="${isFocused ? 9 : 8}">`;
                html += `<div class="sc-detail-expand">`;
                html += `<div class="sc-formula">${_escHtml(c.formula_trace)}</div>`;
                if (s.value_display) html += `<div class="sc-val-display">${_t('scenario.detail.value')}: ${_escHtml(s.value_display)}</div>`;
                if (s.llm_reasoning) html += `<div class="sc-llm-reason">${_t('scenario.detail.llm_reasoning')}: ${_escHtml(s.llm_reasoning)}</div>`;
                if (s.observed_at) html += `<div class="sc-obs-time">${_t('scenario.detail.observed')}: ${new Date(s.observed_at * 1000).toLocaleString()}</div>`;
                if (s.evidence_url) html += `<div class="sc-evidence"><a href="${safeHref(s.evidence_url)}" target="_blank" rel="noopener">${esc(s.evidence_url)}</a></div>`;
                html += `</div></td></tr>`;
            }
            html += `</tbody></table>`;
        } else {
            html += `<div class="sc-no-contrib">${_t('scenario.detail.no_contributions')}</div>`;
        }

        if (!isFocused && sc.indicators) {
            const ind = sc.indicators;
            html += `<div class="sc-indicators">`;
            html += `<span class="sc-ind-label">${_t('scenario.detail.indicators')}:</span> `;
            html += `LLM 24h: ${ind.llm_intel_24h || 0} `;
            html += `| ${_t('scenario.detail.active_countries')}: ${ind.active_countries || 0} `;
            const dsc = ind.domain_signal_counts || {};
            html += `| C:${dsc.cyber||0} P:${dsc.physical||0} I:${dsc.info||0}`;
            html += `</div>`;
        }

        panel.innerHTML = html;
    }

    // Layer 3 overlay editor state: which scenarios have the editor open
    const _scOverlayEditOpen = new Set();
    // Pending (un-applied) edits: { [scenarioId]: { [cc]: weight } }
    const _scOverlayPending = {};

    window.scToggleOverlayEdit = function(scenarioId) {
        if (_scOverlayEditOpen.has(scenarioId)) _scOverlayEditOpen.delete(scenarioId);
        else _scOverlayEditOpen.add(scenarioId);
        if (latestData && latestData.scenarios) {
            const sc = latestData.scenarios[scenarioId];
            if (sc) _renderScenarioDetail(sc, scenarioId);
        }
    };

    window.scOnOverlayInput = function(inputEl) {
        const sid = inputEl.getAttribute('data-sc-id');
        const cc = inputEl.getAttribute('data-sc-cc');
        const v = parseFloat(inputEl.value);
        if (!sid || !cc || !isFinite(v)) return;
        _scOverlayPending[sid] = _scOverlayPending[sid] || {};
        _scOverlayPending[sid][cc] = v;
        const valEl = document.getElementById('sc-ov-val-' + cc);
        if (valEl) valEl.textContent = v.toFixed(2);
        const row = inputEl.closest('.sc-overlay-row');
        if (row) {
            const base = parseFloat(inputEl.getAttribute('data-sc-base') || '0');
            row.classList.toggle('sc-overlay-row-changed', Math.abs(v - base) > 1e-6);
        }
    };

    window.scApplyOverlay = function(scenarioId) {
        const sc = latestData && latestData.scenarios && latestData.scenarios[scenarioId];
        if (!sc) return;
        const parts = sc.participants || {};
        const pending = _scOverlayPending[scenarioId] || {};
        const existing = _scGetOverlay(scenarioId) || {};
        const merged = { ...existing, ...pending };
        const clean = {};
        for (const cc of Object.keys(merged)) {
            const p = parts[cc];
            if (!p) continue;
            const v = parseFloat(merged[cc]);
            if (!isFinite(v) || v < 0 || v > 1) continue;
            const base = (p.base_weight != null ? p.base_weight
                         : (p.weight != null ? p.weight : 0.5));
            if (Math.abs(v - base) < 1e-6) continue;
            clean[cc] = Math.round(v * 100) / 100;
        }
        if (Object.keys(clean).length === 0) {
            sessionStorage.removeItem('sc_overlay:' + scenarioId);
        } else {
            sessionStorage.setItem('sc_overlay:' + scenarioId, JSON.stringify(clean));
        }
        delete _scOverlayPending[scenarioId];
        _scOverlayEditOpen.delete(scenarioId);
        if (typeof forceDataSync === 'function') forceDataSync();
        else if (typeof window._resetRenderSig === 'function') window._resetRenderSig();
    };

    window.scResetOverlay = function(scenarioId) {
        sessionStorage.removeItem('sc_overlay:' + scenarioId);
        delete _scOverlayPending[scenarioId];
        if (typeof forceDataSync === 'function') forceDataSync();
    };

    function _isLiteInsufficient(sc, isFocused) {
        if (isFocused) return false;
        const ind = sc && sc.indicators;
        if (!ind) return false;
        const cov = ind.coverage_completeness;
        if (cov == null) return false;
        return cov < 0.34;
    }

    function _computeWhatIf(sc, contributions) {
        if (_scenarioWhatIfExcluded.size === 0) return null;
        const domains = { cyber: 0, physical: 0, info: 0 };
        for (let i = 0; i < contributions.length; i++) {
            if (_scenarioWhatIfExcluded.has(i)) continue;
            const c = contributions[i];
            const d = (c.signal || {}).domain || 'info';
            if (d in domains) domains[d] += c.final_contribution;
        }
        const DOMAIN_CAP = 6.0;
        for (const d in domains) domains[d] = Math.min(domains[d], DOMAIN_CAP);
        const activeDomains = Object.values(domains).filter(v => v > 0).length;
        let convBonus = 0;
        if (activeDomains >= 3) convBonus = 2.0;
        else if (activeDomains >= 2) convBonus = 1.0;
        const score = Object.values(domains).reduce((a, b) => a + b, 0) + convBonus;
        let tl = null;
        if (sc.is_focused) {
            if (score >= 9 && domains.physical >= 3.0) tl = 1;
            else if (score >= 6 && activeDomains >= 2) tl = 2;
            else if (score >= 4) tl = 3;
            else if (score >= 2) tl = 4;
            else tl = 5;
        }
        return { score, tl, delta: score - (sc.score || 0) };
    }

    window.scToggleWhatIf = function(idx) {
        if (_scenarioWhatIfExcluded.has(idx)) _scenarioWhatIfExcluded.delete(idx);
        else _scenarioWhatIfExcluded.add(idx);
        const data = window._lastThreatData;
        if (data && data.scenarios && _scenarioDetailOpen) {
            _renderScenarioDetail(data.scenarios[_scenarioDetailOpen], _scenarioDetailOpen);
        }
    };

    window.scResetWhatIf = function() {
        _scenarioWhatIfExcluded = new Set();
        const data = window._lastThreatData;
        if (data && data.scenarios && _scenarioDetailOpen) {
            _renderScenarioDetail(data.scenarios[_scenarioDetailOpen], _scenarioDetailOpen);
        }
    };

    window.scToggleContribDetail = function(idx) {
        const row = document.getElementById('sc-contrib-detail-' + idx);
        if (!row) return;
        row.style.display = row.style.display === 'none' ? '' : 'none';
    };

    window.switchScenarioFocus = function(scenarioId) {
        if (!scenarioId) return;
        _scenarioFocusId = scenarioId;
        localStorage.setItem('radar_focused_scenario', scenarioId);
        _scenarioDetailOpen = null;
        _scenarioWhatIfExcluded = new Set();
        const detailPanel = document.getElementById('scenario-detail-panel');
        if (detailPanel) detailPanel.style.display = 'none';

        // Optimistic UI: re-render scenario bar with the new focus marker
        // immediately from cached telemetry so the analyst sees feedback
        // before the (potentially slow) force-sync round-trip completes.
        if (latestData && latestData.scenarios) {
            latestData.focused_scenario = scenarioId;
            try { renderScenarioBar(latestData); } catch (_) { /* defensive */ }
        }

        // v2 surfaces (cards + NP7 banner) are independent of v1 force-sync
        // and respond in <100ms. Fire them now so the analyst sees the new
        // focus reflected immediately rather than after the v1 await.
        _refreshNp7Banner(scenarioId);
        _refreshConclusionCards(scenarioId);

        // v1 force-refresh (slower; updates rest of telemetry).
        fetchDDoSData(true);
    };

    // ── Scenario Manager (Phase 4 Admin) ───────────────────────────────

    window.loadScenarioManager = async function() {
        const listEl = document.getElementById('scenario-mgr-list');
        if (!listEl) return;
        listEl.innerHTML = `<div style="color:#666;font-size:10px;">${_t('ui.loading')}</div>`;
        try {
            const resp = await fetch('/api/admin/scenarios');
            if (!resp.ok) { listEl.innerHTML = `<div style="color:red;">${_t('ui.error')} ${resp.status}</div>`; return; }
            const data = await resp.json();
            _scMgrRenderList(data.scenarios || [], listEl);
        } catch (e) {
            listEl.innerHTML = `<div style="color:red;">${_escHtml(e.message)}</div>`;
        }
    };

    const _ROLE_OPTIONS = [
        'primary_target','principal_belligerent','adversary','primary_ally',
        'forward_base','secondary_ally','extended_deterrence','strategic_observer',
        'proxy_front','force_projection','secondary_party','spillover_risk','regional_power'
    ];

    function _scMgrRenderList(scenarios, container) {
        const lang = (typeof _currentLang !== 'undefined') ? _currentLang : 'en';
        if (!scenarios.length) {
            container.innerHTML = `<div style="color:#666;font-size:11px;">${_t('scenario.mgr.no_scenarios')}</div>`;
            return;
        }
        let html = '';
        for (const sc of scenarios) {
            const primaryName = lang === 'ja' ? (sc.name_ja || sc.name_en) : (sc.name_en || sc.name_ja);
            const altName     = lang === 'ja' ? (sc.name_en || '')         : (sc.name_ja || '');
            const pCount = Object.keys(sc.participants || {}).length;
            const core = sc.core_country ? sc.core_country.toUpperCase() : '—';
            const stateLabel = _t('scenario.state.' + sc.state);
            const srcLabel   = sc.source === 'preset' ? _t('scenario.mgr.source_preset') : _t('scenario.mgr.source_db');
            const cardClasses = [
                'scmgr-card',
                `state-${sc.state}`,
                sc.enabled ? '' : 'disabled',
            ].filter(Boolean).join(' ');

            html += `<div class="${cardClasses}">`;
            html += `  <div class="scmgr-state-badge scmgr-state-${sc.state}">${_escHtml(stateLabel)}</div>`;
            html += `  <div class="scmgr-head">`;
            html += `    <div class="scmgr-head-row">`;
            html += `      <span class="scmgr-id">${_escHtml(sc.id)}</span>`;
            html += `      <span class="scmgr-name">${_escHtml(primaryName)}</span>`;
            if (altName) {
                html += `      <span style="font-size:11px;color:#888;">${_escHtml(altName)}</span>`;
            }
            html += `    </div>`;
            html += `    <div class="scmgr-meta">`;
            html += `      <span><b>${_t('scenario.mgr.core_country')}:</b> ${_escHtml(core)}</span>`;
            html += `      <span><b>${_t('scenario.mgr.participants')}:</b> ${pCount}</span>`;
            html += `      <span><b>Enabled:</b> ${sc.enabled ? 'yes' : 'no'}</span>`;
            html += `    </div>`;
            html += `  </div>`;
            html += `  <span class="scmgr-src-pill scmgr-src-${sc.source}">${_escHtml(srcLabel)}</span>`;

            html += `  <div class="scmgr-actions">`;
            html += `    <button class="btn-tactical" onclick="scMgrShowEdit('${sc.id}')">${_t('scenario.mgr.edit')}</button>`;
            if (sc.state === 'active') {
                html += `    <button class="btn-tactical" style="color:#ffaa00;" onclick="scMgrArchive('${sc.id}')">${_t('scenario.mgr.archive')}</button>`;
            } else if (sc.state === 'archived') {
                html += `    <button class="btn-tactical" style="color:#00ff88;" onclick="scMgrRestore('${sc.id}')">${_t('scenario.mgr.restore')}</button>`;
            }
            if (sc.source === 'db') {
                html += `    <button class="btn-tactical" style="color:#ff2a2a;" onclick="scMgrPurge('${sc.id}')">${_t('scenario.mgr.purge')}</button>`;
            } else {
                html += `    <button class="btn-tactical" style="color:#888;" onclick="scMgrReset('${sc.id}')">${_t('scenario.mgr.reset')}</button>`;
            }
            if (sc.enabled) {
                html += `    <button class="btn-tactical" style="color:#ff6666;" onclick="scMgrToggleEnabled('${sc.id}', false)">${_t('scenario.mgr.disable')}</button>`;
            } else {
                html += `    <button class="btn-tactical" style="color:#00ff88;" onclick="scMgrToggleEnabled('${sc.id}', true)">${_t('scenario.mgr.enable')}</button>`;
            }
            html += `  </div>`;
            html += `</div>`;
        }
        container.innerHTML = html;
    }

    // Build the editor UI. Designed like the legacy Strategy Scope tab:
    // browse the full country list with bloc filter pills + text search,
    // toggle checkboxes to mark participants, set role/weight inline.
    function _scMgrEditorHtml(sc, isNew) {
        const title = isNew ? _t('scenario.mgr.create') : `${_t('scenario.mgr.edit')}: ${_escHtml(sc.id || '')}`;
        const participants = sc.participants || {};
        const coreCountry = (sc.core_country || '').toUpperCase();

        let html = '<div class="scmgr-editor">';

        // Header: title + save/cancel actions
        html += '<div class="scmgr-editor-header">';
        html += `  <div class="scmgr-editor-title">${title}</div>`;
        html += '  <div class="scmgr-editor-actions">';
        html += `    <button class="btn-tactical btn-action" onclick="scMgrSave(${isNew})">${_t('scenario.mgr.save')}</button>`;
        html += `    <button class="btn-tactical" style="color:#888;" onclick="scMgrCancelEdit()">${_t('scenario.mgr.cancel')}</button>`;
        html += '    <span id="scmgr-status"></span>';
        html += '  </div>';
        html += '</div>';

        // Form fields
        html += '<div class="scmgr-form">';
        if (isNew) {
            html += `  <label class="scmgr-form-full">ID <input id="scmgr-id" value="" placeholder="taiwan_contingency" style="font-family:'Courier New',monospace;"></label>`;
        }
        html += `  <label>${_t('scenario.mgr.name_en')} <input id="scmgr-name-en" value="${_escHtml(sc.name_en||'')}"></label>`;
        html += `  <label>${_t('scenario.mgr.name_ja')} <input id="scmgr-name-ja" value="${_escHtml(sc.name_ja||'')}"></label>`;
        html += `  <label>${_t('scenario.mgr.desc_en')} <input id="scmgr-desc-en" value="${_escHtml(sc.description_en||'')}"></label>`;
        html += `  <label>${_t('scenario.mgr.desc_ja')} <input id="scmgr-desc-ja" value="${_escHtml(sc.description_ja||'')}"></label>`;
        // Core country is a dropdown populated from currently-selected participants.
        html += `  <label>${_t('scenario.mgr.core_country')} <select id="scmgr-core-sel"><option value="">(none)</option></select></label>`;
        html += '</div>';

        // Country picker: bloc filter pills, search, full country list
        html += '<div class="scmgr-picker">';
        html += '  <div class="scmgr-picker-header">';
        html += `    <span class="scmgr-picker-title">${_t('scenario.mgr.participants')}</span>`;
        html += '    <span class="scmgr-picker-count" id="scmgr-picker-count">0 / 0</span>';
        html += '  </div>';
        html += '  <div class="scmgr-picker-filters">';
        html += `    <button type="button" class="scmgr-bloc-pill active" data-bloc="ALL" onclick="scMgrSetBloc(this)">${_t('scenario.mgr.bloc_all')}</button>`;
        html += `    <button type="button" class="scmgr-bloc-pill" data-bloc="SELECTED" onclick="scMgrSetBloc(this)">${_t('scenario.mgr.bloc_selected')}</button>`;
        for (const blocKey of ['RUSSIA','CHINA','IRAN','DPRK']) {
            const meta = (STRATEGIC_BLOCS_DATA || {})[blocKey] || {};
            const label = meta.label || blocKey;
            html += `    <button type="button" class="scmgr-bloc-pill" data-bloc="${blocKey}" onclick="scMgrSetBloc(this)">▲ ${_escHtml(label)}</button>`;
        }
        html += `    <input type="search" id="scmgr-picker-search" placeholder="${_t('scenario.mgr.ph_search')}" oninput="scMgrApplyFilter()">`;
        html += '  </div>';

        // Table of all countries
        html += '  <div class="scmgr-picker-scroll"><table class="scmgr-picker-table">';
        html += '    <thead><tr>';
        html += '      <th style="width:28px;"></th>';
        html += `      <th style="width:50px;">${_t('scenario.mgr.country')}</th>`;
        html += '      <th>Name</th>';
        html += '      <th style="width:110px;">Bloc</th>';
        html += `      <th style="width:165px;">${_t('scenario.mgr.role')}</th>`;
        html += `      <th style="width:80px;">${_t('scenario.mgr.weight')}</th>`;
        html += '    </tr></thead>';
        html += '    <tbody id="scmgr-picker-body">';
        const sortedTheaters = (THEATERS || []).slice().sort((a, b) => a.name.localeCompare(b.name));
        if (sortedTheaters.length === 0) {
            html += '<tr><td colspan="6" class="scmgr-p-empty">Country list not loaded.</td></tr>';
        } else {
            for (const t of sortedTheaters) {
                const sel = participants[t.code];
                html += _scMgrCountryRow(t, sel, coreCountry);
            }
        }
        html += '    </tbody></table></div>';
        html += '</div>';

        html += '</div>'; // /.scmgr-editor
        return html;
    }

    function _scMgrCountryRow(theater, selected, coreCountry) {
        const cc = theater.code;
        const isSel = !!selected;
        const weight = isSel ? selected.weight : 0.5;
        const role   = isSel ? selected.role   : 'secondary_party';
        const blocs  = (COUNTRY_BLOC_TAGS || {})[cc] || [];
        const isCore = (cc === coreCountry);

        const roleOpts = _ROLE_OPTIONS.map(r =>
            `<option value="${r}"${r===role?' selected':''}>${_t('scenario.role.'+r)}</option>`
        ).join('');

        const blocBadges = blocs.map(b =>
            `<span class="scmgr-bloc-badge" data-bloc="${b}">${(STRATEGIC_BLOCS_DATA[b]||{}).adversary||b}</span>`
        ).join('');

        const blocDataAttr = blocs.join(',');
        const rowClass = ['scmgr-p-row'];
        if (isSel) rowClass.push('selected');
        const disabledAttr = isSel ? '' : 'disabled';

        return `<tr class="${rowClass.join(' ')}" data-cc="${cc}" data-blocs="${blocDataAttr}" data-name="${_escHtml(theater.name.toLowerCase())}">
            <td class="scmgr-p-chk"><input type="checkbox" ${isSel?'checked':''} onchange="scMgrToggleParticipant('${cc}', this.checked)"></td>
            <td class="scmgr-p-code">${cc}</td>
            <td class="scmgr-p-name${isCore?' core-flag':''}">${_escHtml(theater.name)}</td>
            <td><div class="scmgr-p-blocs">${blocBadges}</div></td>
            <td class="scmgr-p-role"><select ${disabledAttr}>${roleOpts}</select></td>
            <td class="scmgr-p-weight"><input type="number" min="0" max="1" step="0.05" value="${weight}" ${disabledAttr}></td>
        </tr>`;
    }

    // ── Editor interaction helpers ─────────────────────────────────────
    let _scMgrEditId = null;
    let _scMgrBlocFilter = 'ALL';

    window.scMgrSetBloc = function(btn) {
        _scMgrBlocFilter = btn.getAttribute('data-bloc') || 'ALL';
        document.querySelectorAll('.scmgr-bloc-pill').forEach(el => el.classList.remove('active'));
        btn.classList.add('active');
        scMgrApplyFilter();
    };

    window.scMgrApplyFilter = function() {
        const searchEl = document.getElementById('scmgr-picker-search');
        const q = (searchEl?.value || '').trim().toLowerCase();
        const rows = document.querySelectorAll('#scmgr-picker-body .scmgr-p-row');
        rows.forEach(row => {
            const cc = (row.getAttribute('data-cc') || '').toLowerCase();
            const name = row.getAttribute('data-name') || '';
            const blocs = (row.getAttribute('data-blocs') || '').split(',').filter(Boolean);
            const selected = row.classList.contains('selected');

            let blocMatch = true;
            if (_scMgrBlocFilter === 'SELECTED') {
                blocMatch = selected;
            } else if (_scMgrBlocFilter !== 'ALL') {
                blocMatch = blocs.includes(_scMgrBlocFilter);
            }
            const textMatch = !q || name.includes(q) || cc.includes(q);
            row.classList.toggle('hidden', !(blocMatch && textMatch));
        });
    };

    // Toggle a participant row; enable/disable its inline controls, refresh
    // core country dropdown and selection counter.
    window.scMgrToggleParticipant = function(cc, checked) {
        const row = document.querySelector(`#scmgr-picker-body .scmgr-p-row[data-cc="${cc}"]`);
        if (!row) return;
        row.classList.toggle('selected', checked);
        const roleSel   = row.querySelector('.scmgr-p-role select');
        const weightInp = row.querySelector('.scmgr-p-weight input');
        if (roleSel)   roleSel.disabled   = !checked;
        if (weightInp) weightInp.disabled = !checked;
        _scMgrRefreshCoreOptions();
        _scMgrUpdatePickerCount();
        if (_scMgrBlocFilter === 'SELECTED') scMgrApplyFilter();
    };

    function _scMgrGetSelectedRows() {
        return document.querySelectorAll('#scmgr-picker-body .scmgr-p-row.selected');
    }

    function _scMgrUpdatePickerCount() {
        const countEl = document.getElementById('scmgr-picker-count');
        if (!countEl) return;
        const total = document.querySelectorAll('#scmgr-picker-body .scmgr-p-row').length;
        const selN  = _scMgrGetSelectedRows().length;
        countEl.textContent = `${selN} / ${total}`;
    }

    // Core country dropdown = currently selected participants only; this keeps
    // the scenario well-formed (core_country must be one of participants).
    function _scMgrRefreshCoreOptions() {
        const sel = document.getElementById('scmgr-core-sel');
        if (!sel) return;
        const current = sel.value;
        const opts = ['<option value="">(none)</option>'];
        _scMgrGetSelectedRows().forEach(row => {
            const cc = row.getAttribute('data-cc');
            const name = row.querySelector('.scmgr-p-name')?.textContent || cc;
            const isSelected = cc === current ? ' selected' : '';
            opts.push(`<option value="${cc}"${isSelected}>${cc} — ${name.replace(' ★ CORE','')}</option>`);
        });
        sel.innerHTML = opts.join('');
    }

    // Open the editor and run post-render initializers: populate the core
    // dropdown from the current selection set, update the counter, and scroll
    // the first selected row into view.
    function _scMgrOpenEditor(sc, isNew) {
        _scMgrBlocFilter = 'ALL';
        const editor = document.getElementById('scenario-mgr-editor');
        editor.innerHTML = _scMgrEditorHtml(sc, isNew);
        editor.style.display = '';
        // After DOM insert, wire up core dropdown + counter against the
        // initially-selected rows. Preserve the scenario's existing core
        // country selection if it matches a participant.
        const coreSel = document.getElementById('scmgr-core-sel');
        if (coreSel && sc.core_country) coreSel.dataset.initial = sc.core_country.toUpperCase();
        _scMgrRefreshCoreOptions();
        if (coreSel && coreSel.dataset.initial) {
            coreSel.value = coreSel.dataset.initial;
        }
        _scMgrUpdatePickerCount();
        // Scroll the editor into view so it's reachable inside the settings
        // modal's scrollable tab pane.
        requestAnimationFrame(() => {
            editor.scrollIntoView({ block: 'start', behavior: 'smooth' });
        });
    }

    window.scMgrShowCreate = function() {
        _scMgrEditId = null;
        _scMgrOpenEditor({}, true);
    };

    window.scMgrShowEdit = async function(sid) {
        _scMgrEditId = sid;
        try {
            const resp = await fetch('/api/admin/scenarios');
            if (!resp.ok) return;
            const data = await resp.json();
            const sc = (data.scenarios || []).find(s => s.id === sid);
            if (!sc) return;
            _scMgrOpenEditor(sc, false);
        } catch (e) { console.error(e); }
    };

    window.scMgrCancelEdit = function() {
        const editor = document.getElementById('scenario-mgr-editor');
        editor.style.display = 'none';
        editor.innerHTML = '';
        _scMgrEditId = null;
    };

    window.scMgrSave = async function(isNew) {
        const status = document.getElementById('scmgr-status');
        const sid = isNew ? (document.getElementById('scmgr-id')?.value || '').trim().toLowerCase() : _scMgrEditId;
        if (!sid) { if (status) status.textContent = _t('scenario.mgr.err.id_required'); return; }

        const payload = {
            id: sid,
            name_en: document.getElementById('scmgr-name-en')?.value || '',
            name_ja: document.getElementById('scmgr-name-ja')?.value || '',
            description_en: document.getElementById('scmgr-desc-en')?.value || '',
            description_ja: document.getElementById('scmgr-desc-ja')?.value || '',
            core_country: (document.getElementById('scmgr-core-sel')?.value || '').toUpperCase(),
            state: 'active',
            enabled: true,
            participants: {},
        };

        for (const row of _scMgrGetSelectedRows()) {
            const cc = (row.getAttribute('data-cc') || '').toUpperCase();
            if (!cc) continue;
            const wt = parseFloat(row.querySelector('.scmgr-p-weight input')?.value || '0');
            const role = row.querySelector('.scmgr-p-role select')?.value || 'secondary_party';
            payload.participants[cc] = { weight: wt, role: role };
        }

        if (Object.keys(payload.participants).length === 0) {
            if (status) status.textContent = _t('scenario.mgr.err.no_participants');
            return;
        }

        const url = isNew ? '/api/admin/scenarios' : `/api/admin/scenarios/${sid}`;
        const method = isNew ? 'POST' : 'PUT';
        try {
            if (status) status.textContent = _t('ui.saving');
            const resp = await fetch(url, {
                method, headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload)
            });
            const result = await resp.json();
            if (!resp.ok) {
                if (status) status.textContent = result.error || _t('ui.error');
                return;
            }
            if (status) status.textContent = _t('ui.saved');
            scMgrCancelEdit();
            loadScenarioManager();
        } catch (e) {
            if (status) status.textContent = e.message;
        }
    };

    window.scMgrArchive = async function(sid) {
        await fetch(`/api/admin/scenarios/${sid}/state`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ state: 'archived' })
        });
        loadScenarioManager();
    };

    window.scMgrRestore = async function(sid) {
        await fetch(`/api/admin/scenarios/${sid}/state`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ state: 'active' })
        });
        loadScenarioManager();
    };

    window.scMgrPurge = async function(sid) {
        if (!confirm(_t('scenario.mgr.purge_confirm'))) return;
        await fetch(`/api/admin/scenarios/${sid}?purge=true`, { method: 'DELETE' });
        loadScenarioManager();
    };

    window.scMgrReset = async function(sid) {
        await fetch(`/api/admin/scenarios/${sid}/reset`, { method: 'POST' });
        loadScenarioManager();
    };

    window.scMgrToggleEnabled = async function(sid, enabled) {
        await fetch(`/api/admin/scenarios/${sid}/enabled`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ enabled })
        });
        loadScenarioManager();
    };

    // Phase D: C-lite evaluation panel
    window.loadCliteEvaluation = async function() {
        const panel = document.getElementById('clite-eval-panel');
        if (!panel) return;
        panel.innerHTML = `<div style="color:#666;font-size:10px;">${_t('ui.loading')}</div>`;
        try {
            const resp = await fetch('/api/analytics/clite_evaluation?days=28');
            if (!resp.ok) { panel.innerHTML = `<div style="color:red;">${_t('ui.error')} ${resp.status}</div>`; return; }
            const d = await resp.json();
            const missRatePct = (d.miss_rate * 100).toFixed(1);
            const recCls = d.recommendation === 'CONSIDER_C_MEDIUM'
                ? 'clite-rec-warn' : 'clite-rec-ok';
            let html = '<div class="clite-eval">';
            html += `<div class="clite-eval-title">${_t('scenario.clite.title')}</div>`;
            html += '<div class="clite-eval-stats">';
            html += `<div class="clite-stat"><span class="clite-stat-value">${d.total_switches}</span>`;
            html += `<span class="clite-stat-label">${_t('scenario.clite.switches')}</span></div>`;
            html += `<div class="clite-stat"><span class="clite-stat-value">${d.misses}</span>`;
            html += `<span class="clite-stat-label">${_t('scenario.clite.misses')}</span></div>`;
            html += `<div class="clite-stat"><span class="clite-stat-value">${missRatePct}%</span>`;
            html += `<span class="clite-stat-label">${_t('scenario.clite.miss_rate')}</span></div>`;
            html += `<div class="clite-stat"><span class="clite-stat-value">${d.avg_delta.toFixed(1)}</span>`;
            html += `<span class="clite-stat-label">${_t('scenario.clite.avg_delta')}</span></div>`;
            html += `<div class="clite-stat"><span class="clite-stat-value">${d.max_delta.toFixed(1)}</span>`;
            html += `<span class="clite-stat-label">${_t('scenario.clite.max_delta')}</span></div>`;
            html += '</div>';
            html += `<div class="clite-recommendation ${recCls}">`;
            html += `${_t('scenario.clite.rec_' + d.recommendation.toLowerCase())}</div>`;
            // Per-scenario breakdown
            const byScen = d.by_scenario || {};
            const sids = Object.keys(byScen);
            if (sids.length > 0) {
                html += `<div class="clite-breakdown-title">${_t('scenario.clite.by_scenario')}</div>`;
                html += '<table class="clite-breakdown-table"><thead><tr>';
                html += `<th>${_t('scenario.clite.scenario')}</th><th>${_t('scenario.clite.switches')}</th>`;
                html += `<th>${_t('scenario.clite.misses')}</th><th>${_t('scenario.clite.avg_delta')}</th></tr></thead><tbody>`;
                for (const sid of sids) {
                    const s = byScen[sid];
                    html += `<tr><td>${_escHtml(sid)}</td><td>${s.switches}</td>`;
                    html += `<td>${s.misses}</td><td>${s.avg_delta.toFixed(1)}</td></tr>`;
                }
                html += '</tbody></table>';
            }
            html += '</div>';
            panel.innerHTML = html;
        } catch (e) {
            panel.innerHTML = `<div style="color:red;">${_escHtml(e.message)}</div>`;
        }
    };

    // ── §10.5 Pending Decisions ────────────────────────────────────────
    // Shared helpers for the admin panel (detailed) and dashboard pin (compact).
    function _pdRecClass(rec) {
        if (rec === 'ACCEPT_CURRENT')          return 'rec-accept';
        if (rec === 'ROLLBACK_TO_SINGLE_WEIGHT')return 'rec-rollback';
        if (rec === 'RAISE_THRESHOLDS')        return 'rec-raise';
        return 'rec-extend';
    }
    function _pdDeadlineSeverity(days, past) {
        if (past) return 'overdue';
        if (days <= 7) return 'soon';
        return 'ok';
    }
    function _pdRecI18n(rec) {
        const key = 'scenario.pending.rec_' + rec.toLowerCase();
        return _t(key);
    }
    window.openScenarioMgrTab = function () {
        openModal('settings-modal');
        switchTab('scenarios');
    };
    async function _fetchPendingDecisions() {
        const [tlResp, dwResp] = await Promise.all([
            fetch('/api/analytics/tl_recalibration_advisory'),
            fetch('/api/analytics/dual_weight_evaluation'),
        ]);
        if (!tlResp.ok || !dwResp.ok) {
            throw new Error(`HTTP ${tlResp.status}/${dwResp.status}`);
        }
        return {
            tl: await tlResp.json(),
            dw: await dwResp.json(),
        };
    }
    function _renderPendingDecisionCard(name, deadline, decision, bodyHtml) {
        const sev = _pdDeadlineSeverity(deadline.days_remaining, deadline.past_primary);
        const recCls = _pdRecClass(decision.recommendation);
        const daysLabel = deadline.past_primary
            ? _t('scenario.pending.overdue_by', { n: Math.abs(deadline.days_remaining).toFixed(1) })
            : _t('scenario.pending.days_remaining', { n: deadline.days_remaining.toFixed(1) });
        const extLabel = deadline.past_extended
            ? _t('scenario.pending.extended_past')
            : _t('scenario.pending.extended_hard', { d: _escHtml(deadline.extended_hard) });
        let html = `<div class="pending-decision-card pd-${sev}">`;
        html += `<div class="pending-decision-head">`;
        html += `<span class="pending-decision-name">${_escHtml(name)}</span>`;
        html += `<span class="pending-decision-deadline pd-${sev}">`;
        html += `${_escHtml(deadline.primary)} · ${_escHtml(daysLabel)}`;
        html += `</span></div>`;
        html += `<div class="pending-decision-rec ${recCls}">${_escHtml(_pdRecI18n(decision.recommendation))}</div>`;
        if (decision.reason) {
            html += `<div class="pending-decision-reason">${_escHtml(decision.reason)}</div>`;
        }
        html += bodyHtml || '';
        html += `<div class="pending-decision-meta">${_escHtml(extLabel)}</div>`;
        if (decision.manual_review_needed) {
            html += `<div class="pending-decision-manual">${_escHtml(decision.manual_review_needed)}</div>`;
        }
        html += `</div>`;
        return html;
    }
    window.loadPendingDecisions = async function () {
        const panel = document.getElementById('pending-decisions-panel');
        if (!panel) return;
        panel.innerHTML = `<div style="color:#666;font-size:10px;">${_t('ui.loading')}</div>`;
        try {
            const { tl, dw } = await _fetchPendingDecisions();
            let html = `<div class="pending-decisions">`;
            html += `<div class="pending-decisions-title">${_t('scenario.pending.title')}</div>`;

            // Dual-weight (fleet-level decision)
            {
                const m         = dw.decision.measured || {};
                const sdPct     = (m.sample_weighted_sd || 0).toFixed(3);
                const lowPct    = (m.pooled_low_weight_pct || 0).toFixed(1);
                const samples   = m.total_samples || 0;
                let body = `<div class="pending-decision-meta">`;
                body += `<b>SD:</b> ${sdPct} &nbsp; `;
                body += `<b>${_t('scenario.pending.low_weight_pct')}:</b> ${lowPct}% &nbsp; `;
                body += `<b>${_t('scenario.pending.samples')}:</b> ${samples}`;
                body += `</div>`;
                html += _renderPendingDecisionCard(
                    _t('scenario.pending.dual_weight_name'),
                    dw.deadline, dw.decision, body);
            }

            // TL recalibration (per-scenario with roll-up)
            {
                const dueCount = (tl.scenarios || []).filter(
                    s => s.decision && s.decision.recommendation === 'RAISE_THRESHOLDS').length;
                const extCount = (tl.scenarios || []).filter(
                    s => s.decision && s.decision.recommendation === 'EXTEND_OR_WAIT').length;
                const acceptCount = (tl.scenarios || []).filter(
                    s => s.decision && s.decision.recommendation === 'ACCEPT_CURRENT').length;
                const rollupDecision = {
                    recommendation: dueCount > 0 ? 'RAISE_THRESHOLDS'
                                   : extCount > 0 ? 'EXTEND_OR_WAIT'
                                   : 'ACCEPT_CURRENT',
                    reason: _t('scenario.pending.tl_rollup', {
                        raise: dueCount, extend: extCount, accept: acceptCount,
                    }),
                    manual_review_needed:
                        (tl.scenarios[0] && tl.scenarios[0].decision &&
                         tl.scenarios[0].decision.manual_review_needed) || '',
                };
                let body = '<div class="pending-decision-scenarios">';
                for (const s of (tl.scenarios || [])) {
                    const rec = (s.decision && s.decision.recommendation) || 'EXTEND_OR_WAIT';
                    const m = s.decision && s.decision.measured;
                    const label = s.label || s.scenario_id;
                    body += `<div class="pd-sc-row">`;
                    body += `<span>${_escHtml(label)}</span>`;
                    if (m) {
                        body += `<span>obs ${s.observations} · TL2 ${m.tl2_per_week}/wk · TL1 ${m.tl1_per_week}/wk · ${_escHtml(rec)}</span>`;
                    } else {
                        body += `<span>obs ${s.observations}/${s.min_required} · ${_escHtml(rec)}</span>`;
                    }
                    body += `</div>`;
                }
                body += '</div>';
                html += _renderPendingDecisionCard(
                    _t('scenario.pending.tl_recal_name'),
                    tl.deadline, rollupDecision, body);
            }

            html += `</div>`;
            panel.innerHTML = html;
        } catch (e) {
            panel.innerHTML = `<div style="color:red;">${_escHtml(e.message)}</div>`;
        }
    };

    // Dashboard pin: auto-loads once on boot and every hour; hides when no
    // deadline is soon/overdue. Click → opens Scenario Manager tab.
    async function _refreshPendingDecisionsPin() {
        const pin = document.getElementById('pending-decisions-pin');
        if (!pin) return;
        try {
            const { tl, dw } = await _fetchPendingDecisions();
            const items = [
                { name: _t('scenario.pending.tl_recal_name'),
                  deadline: tl.deadline, rec: _pickTlRollupRec(tl) },
                { name: _t('scenario.pending.dual_weight_name'),
                  deadline: dw.deadline, rec: dw.decision.recommendation },
            ];
            const visible = items.filter(it =>
                it.deadline.past_primary || it.deadline.days_remaining <= 14
                || it.rec === 'ROLLBACK_TO_SINGLE_WEIGHT'
                || it.rec === 'RAISE_THRESHOLDS');
            if (visible.length === 0) { pin.style.display = 'none'; return; }
            const overdueAny = visible.some(it => it.deadline.past_primary);
            pin.className = overdueAny ? 'pd-pin-overdue' : 'pd-pin-soon';
            let html = `<span class="pd-pin-label">${_t('scenario.pending.pin_label')}</span>`;
            for (const it of visible) {
                const daysCls = it.deadline.past_primary ? 'pd-overdue' : '';
                const daysTxt = it.deadline.past_primary
                    ? _t('scenario.pending.overdue_by', { n: Math.abs(it.deadline.days_remaining).toFixed(0) })
                    : _t('scenario.pending.days_remaining', { n: it.deadline.days_remaining.toFixed(0) });
                html += `<span class="pd-pin-item">`;
                html += `<span class="pd-pin-item-name">${_escHtml(it.name)}:</span>`;
                html += `<span class="pd-pin-item-days ${daysCls}">${_escHtml(daysTxt)}</span>`;
                html += `<span class="pd-pin-item-rec">· ${_escHtml(_pdRecI18n(it.rec))}</span>`;
                html += `</span>`;
            }
            pin.innerHTML = html;
            pin.style.display = 'flex';
        } catch (e) {
            pin.style.display = 'none';
        }
    }
    function _pickTlRollupRec(tl) {
        const scs = tl.scenarios || [];
        if (scs.some(s => s.decision && s.decision.recommendation === 'RAISE_THRESHOLDS'))
            return 'RAISE_THRESHOLDS';
        if (scs.some(s => s.decision && s.decision.recommendation === 'EXTEND_OR_WAIT'))
            return 'EXTEND_OR_WAIT';
        return 'ACCEPT_CURRENT';
    }
    // Kick off once after initial boot, then refresh hourly.
    setTimeout(_refreshPendingDecisionsPin, 12000);
    setInterval(_refreshPendingDecisionsPin, 3600 * 1000);
