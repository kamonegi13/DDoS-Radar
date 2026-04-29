/**
 * CONTROLS panel — redesigned 2026-04-29 (commits L–P).
 *
 * Replaces the hamburger → CONTROLS → TOOLS-dropdown three-step flow
 * with a single grid of cards grouped by purpose. Each card shows
 * panel state (open / closed / dock position) and a live data badge
 * (pending count, sensor health, etc.).
 *
 * Architecture:
 *   - TOOLS_REGISTRY: declarative list of every tool with section,
 *     icon, label, description, panelId, default dock, status hook.
 *   - renderControlsPanel(): builds the grid (idempotent — re-render
 *     replaces the body).
 *   - poll loop: refreshes status badges + ATTENTION section every 5s
 *     while the panel is open.
 *
 * The legacy ToolsDropdown markup remains in index.html as a fallback
 * for keyboard shortcuts and screen readers — but is hidden by CSS.
 *
 * Public window hooks (used by the legacy CONTROLS panel button):
 *   - window._controlsRender()        force a render
 *   - window._controlsRefresh()       fetch status + re-render badges
 *   - window._controlsToggleCard(id)  click handler for a card
 *   - window._controlsCycleDock(id)   dock cycle (left → right → float)
 *   - window._controlsAcknowledge(ruleId)   snooze ATTENTION rule for 24h
 *   - window._controlsApplySuggestion(rid)  apply learned threshold
 */
(function () {
    'use strict';

    // ── TOOLS_REGISTRY ─────────────────────────────────────────────

    // Sections (display order):
    //   intelligence: intel-related (LLM Intel, Telegram, Evidence, ...)
    //   scenario_targeting: target visibility, climate, weather
    //   simulation_analysis: what-if, SPOF, sensor heatmap
    //   tradecraft: analyst tradecraft, sensor watchpane, history
    //   automation: auto-tune, LLM features
    //   admin: user management
    const SECTIONS = [
        { id: 'intelligence', labelKey: 'controls.section.intelligence' },
        { id: 'scenario_targeting', labelKey: 'controls.section.scenario_targeting' },
        { id: 'simulation_analysis', labelKey: 'controls.section.simulation_analysis' },
        { id: 'tradecraft', labelKey: 'controls.section.tradecraft' },
        { id: 'automation', labelKey: 'controls.section.automation' },
        { id: 'admin', labelKey: 'controls.section.admin' },
    ];

    const TOOLS_REGISTRY = [
        // ─ Intelligence ─
        {
            id: 'llm-intel', section: 'intelligence', icon: '🤖',
            labelKey: 'tools.llm_intelligence',
            descKey: 'controls.tool.llm_intel.desc',
            panelId: 'llm-intel-panel',
            toggleFn: () => window.toggleLlmIntelPanel && window.toggleLlmIntelPanel(),
            statusHook: 'llm_intel',
        },
        {
            id: 'dashboard', section: 'intelligence', icon: '📡',
            labelKey: 'tools.live_threat_telemetry',
            descKey: 'controls.tool.dashboard.desc',
            panelId: 'dashboard-panel',
            toggleFn: () => window.toggleDashboardPanel && window.toggleDashboardPanel(),
        },
        {
            id: 'tg-sigint', section: 'intelligence', icon: '📻',
            labelKey: 'tools.telegram_sigint',
            descKey: 'controls.tool.tg.desc',
            panelId: 'tg-sigint-panel',
            toggleFn: () => window.toggleTgSigint && window.toggleTgSigint(),
        },
        {
            id: 'chain', section: 'intelligence', icon: '🔗',
            labelKey: 'tools.evidence_chain',
            descKey: 'controls.tool.chain.desc',
            panelId: 'chain-panel',
            toggleFn: () => window.toggleChainPanel && window.toggleChainPanel(),
        },
        {
            id: 'gn', section: 'intelligence', icon: '🔍',
            labelKey: 'tools.greynoise',
            descKey: 'controls.tool.gn.desc',
            panelId: 'gn-panel',
            toggleFn: () => window.toggleGnPanel && window.toggleGnPanel(),
        },

        // ─ Scenario & Targeting ─
        {
            id: 'target', section: 'scenario_targeting', icon: '🎯',
            labelKey: 'tools.target_visibility',
            descKey: 'controls.tool.target.desc',
            panelId: 'target-panel',
            toggleFn: () => window.toggleTargetPanel && window.toggleTargetPanel(),
        },
        {
            id: 'climate', section: 'scenario_targeting', icon: '🌡',
            labelKey: 'tools.strategic_climate',
            descKey: 'controls.tool.climate.desc',
            panelId: 'climate-panel',
            toggleFn: () => window.toggleClimatePanel && window.toggleClimatePanel(),
        },
        {
            id: 'weather', section: 'scenario_targeting', icon: '☂',
            labelKey: 'tools.weather_brief',
            descKey: 'controls.tool.weather.desc',
            panelId: 'weather-brief-panel',
            toggleFn: () => window.toggleWeatherBrief && window.toggleWeatherBrief(),
        },

        // ─ Simulation & Analysis ─
        {
            id: 'whatif', section: 'simulation_analysis', icon: '🧪',
            labelKey: 'tools.whatif_sim',
            descKey: 'controls.tool.whatif.desc',
            panelId: 'whatif-panel',
            toggleFn: () => window.toggleWhatIfPanel && window.toggleWhatIfPanel(),
        },
        {
            id: 'spof', section: 'simulation_analysis', icon: '🔗',
            labelKey: 'tools.spof_analysis',
            descKey: 'controls.tool.spof.desc',
            panelId: 'spof-panel',
            toggleFn: () => window.toggleSpofPanel && window.toggleSpofPanel(),
        },
        {
            id: 'corr', section: 'simulation_analysis', icon: '🔥',
            labelKey: 'tools.corr_heatmap',
            descKey: 'controls.tool.corr.desc',
            panelId: 'corr-heatmap-panel',
            toggleFn: () => window.toggleCorrHeatmap && window.toggleCorrHeatmap(),
        },

        // ─ Tradecraft ─
        {
            id: 'tradecraft', section: 'tradecraft', icon: '📖',
            labelKey: 'tools.tradecraft',
            descKey: 'controls.tool.tradecraft.desc',
            panelId: 'tradecraft-panel',
            toggleFn: () => window.toggleTradecraftPanel && window.toggleTradecraftPanel(),
        },
        {
            id: 'watchpane', section: 'tradecraft', icon: '👁',
            labelKey: 'tools.sensor_watchpane',
            descKey: 'controls.tool.watchpane.desc',
            panelId: 'sensor-watchpane',
            toggleFn: () => window.toggleSensorWatchpane && window.toggleSensorWatchpane(),
            statusHook: 'sensor_watchpane',
        },
        {
            id: 'hist', section: 'tradecraft', icon: '📊',
            labelKey: 'tools.history_analysis',
            descKey: 'controls.tool.history.desc',
            panelId: 'history-panel',
            toggleFn: () => window.toggleHistoryPanel && window.toggleHistoryPanel(),
        },

        // ─ Automation ─
        {
            id: 'autotune', section: 'automation', icon: '⚙',
            labelKey: 'tools.autotune_wizard',
            descKey: 'controls.tool.autotune.desc',
            panelId: 'autotune-wizard-modal',
            toggleFn: () => window._wizardOpen && window._wizardOpen(),
            statusHook: 'autotune',
        },
        {
            id: 'llm-features', section: 'automation', icon: '🤖',
            labelKey: 'tools.llm_features',
            descKey: 'controls.tool.llm_features.desc',
            panelId: 'llm-features-modal',
            toggleFn: () => window._llmFeaturesOpen && window._llmFeaturesOpen(),
            statusHook: 'llm_features',
        },

        // ─ Admin ─
        {
            id: 'usrmgr', section: 'admin', icon: '👤',
            labelKey: 'tools.user_management',
            descKey: 'controls.tool.usrmgr.desc',
            panelId: 'settings-modal',
            toggleFn: () => {
                if (typeof openModal === 'function') {
                    openModal('settings-modal');
                    if (typeof switchTab === 'function') switchTab('users');
                    if (typeof umgrLoadUsers === 'function') umgrLoadUsers();
                }
            },
        },
    ];

    // Lookup helpers
    const _byId = new Map(TOOLS_REGISTRY.map(t => [t.id, t]));
    function getTool(id) { return _byId.get(id); }

    // ── State ─────────────────────────────────────────────────────────

    let _pollTimer = null;
    let _searchQuery = '';
    let _statusCache = { tools: {}, attention: [], suggestions: [] };
    let _snoozedUntil = {};   // ruleId → unix seconds

    // ── Panel detection ──────────────────────────────────────────────

    function isPanelOpen(panelId) {
        const p = document.getElementById(panelId);
        if (!p) return false;
        if (p.style.display === 'none') return false;
        if (p.style.display) return true;
        if (p.classList.contains('docked')) return true;
        return false;
    }

    function getPanelDock(panelId) {
        const p = document.getElementById(panelId);
        if (!p) return 'closed';
        if (!isPanelOpen(panelId)) return 'closed';
        const left = document.getElementById('left-sidebar');
        const right = document.getElementById('sidebar');
        if (left && left.contains(p)) return 'left';
        if (right && right.contains(p)) return 'right';
        if (p.classList.contains('floating')) return 'floating';
        if (p.classList.contains('modal-window')) return 'modal';
        return 'unknown';
    }

    // ── Render ────────────────────────────────────────────────────────

    function _t(key, vars) {
        return (typeof window._t === 'function' ? window._t(key, vars) : key);
    }

    function _escHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function dockBadge(dock) {
        if (dock === 'closed') return '<span class="cp-dock cp-dock-closed">○ closed</span>';
        if (dock === 'left')   return '<span class="cp-dock cp-dock-open">●OPEN ⇄L</span>';
        if (dock === 'right')  return '<span class="cp-dock cp-dock-open">●OPEN ⇄R</span>';
        if (dock === 'floating') return '<span class="cp-dock cp-dock-open">●OPEN ⇄F</span>';
        if (dock === 'modal') return '<span class="cp-dock cp-dock-open">●OPEN</span>';
        return '<span class="cp-dock cp-dock-open">●OPEN</span>';
    }

    function statusBadge(toolId) {
        const status = _statusCache.tools[toolId];
        if (!status) return '';
        if (typeof status === 'string') {
            return '<span class="cp-status">' + _escHtml(status) + '</span>';
        }
        if (status.text) {
            const cls = 'cp-status'
                + (status.severity ? ' cp-sev-' + status.severity : '');
            return '<span class="' + cls + '">'
                + _escHtml(status.text) + '</span>';
        }
        return '';
    }

    function matchesQuery(tool) {
        if (!_searchQuery) return true;
        const q = _searchQuery.toLowerCase();
        const name = _t(tool.labelKey).toLowerCase();
        const desc = _t(tool.descKey || '').toLowerCase();
        return name.indexOf(q) >= 0 || desc.indexOf(q) >= 0;
    }

    function renderToolCard(tool) {
        const dock = getPanelDock(tool.panelId);
        const dockHtml = dockBadge(dock);
        const status = statusBadge(tool.id);
        const dimmed = !matchesQuery(tool) ? ' cp-card-dimmed' : '';
        return '<div class="cp-card' + dimmed + '" data-tool-id="' + tool.id + '"'
            + ' onclick="window._controlsToggleCard(\'' + tool.id + '\')"'
            + ' title="' + _escHtml(_t(tool.descKey || tool.labelKey)) + '">'
            + '  <div class="cp-card-head">'
            + '    <span class="cp-icon">' + _escHtml(tool.icon || '') + '</span>'
            + '    <span class="cp-name">' + _escHtml(_t(tool.labelKey)) + '</span>'
            + '  </div>'
            + '  <div class="cp-card-state">' + dockHtml + status + '</div>'
            + '</div>';
    }

    function renderAttentionCard(rule) {
        const sev = rule.severity || 'info';
        const isSnoozed = _snoozedUntil[rule.rule_id]
            && _snoozedUntil[rule.rule_id] > (Date.now() / 1000);
        if (isSnoozed) return '';
        const tool = getTool(rule.tool_id);
        const toolName = tool ? _t(tool.labelKey) : rule.tool_id;
        const sevLabel = sev === 'critical' ? '🔴 CRITICAL'
            : sev === 'warning' ? '⚠ WARNING'
            : 'ℹ INFO';
        const canSnooze = sev !== 'critical';
        return '<div class="cp-attention cp-sev-' + sev + '">'
            + '  <div class="cp-att-head">'
            + '    <span class="cp-att-sev">' + sevLabel + '</span>'
            + '    <span class="cp-att-tool">' + _escHtml(toolName) + '</span>'
            + '  </div>'
            + '  <div class="cp-att-msg">' + _escHtml(rule.message || '') + '</div>'
            + '  <div class="cp-att-actions">'
            + '    <button class="cp-btn cp-btn-open" onclick="window._controlsToggleCard(\''
            + (tool ? tool.id : '') + '\')">Open</button>'
            + (canSnooze
                ? '<button class="cp-btn cp-btn-snooze" onclick="window._controlsAcknowledge(\''
                  + rule.rule_id + '\')">Snooze 24h</button>'
                : '')
            + '  </div>'
            + '</div>';
    }

    function renderSuggestion(s) {
        return '<div class="cp-suggestion">'
            + '  <span class="cp-sug-icon">💡</span>'
            + '  <span class="cp-sug-text">'
            + _escHtml(s.message || ('Suggested threshold for ' + s.rule_id))
            + '</span>'
            + '  <button class="cp-btn cp-btn-suggest"'
            + '          onclick="window._controlsApplySuggestion(\'' + s.rule_id + '\')">'
            + '    Apply ' + _escHtml(String(s.suggested))
            + '  </button>'
            + '  <button class="cp-btn cp-btn-dismiss"'
            + '          onclick="window._controlsDismissSuggestion(\'' + s.rule_id + '\')">'
            + '    Dismiss</button>'
            + '</div>';
    }

    function render() {
        const body = document.getElementById('controls-panel-body');
        if (!body) return;

        let html = '';

        // Search
        html += '<div class="cp-search">'
            + '<input type="text" id="controls-search" placeholder="' + _escHtml(_t('controls.search_placeholder'))
            + '" oninput="window._controlsSetQuery(this.value)" value="' + _escHtml(_searchQuery) + '">'
            + '<span class="cp-search-hint">' + _escHtml(_t('controls.search_hint')) + '</span>'
            + '</div>';

        // ATTENTION section (only if rules present)
        const att = (_statusCache.attention || [])
            .filter(r => !(_snoozedUntil[r.rule_id]
                && _snoozedUntil[r.rule_id] > (Date.now() / 1000)));
        if (att.length) {
            // Order: critical → warning → info
            const sevOrder = { critical: 0, warning: 1, info: 2 };
            att.sort((a, b) =>
                (sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9));
            html += '<div class="cp-section cp-section-attention">'
                + '<div class="cp-section-title">⚠ ATTENTION</div>'
                + att.map(renderAttentionCard).join('')
                + '</div>';
        }

        // Suggestions section (adaptive learning)
        const sugs = (_statusCache.suggestions || []);
        if (sugs.length) {
            html += '<div class="cp-section cp-section-suggestions">'
                + '<div class="cp-section-title">💡 ' + _escHtml(_t('controls.section.suggestions')) + '</div>'
                + sugs.map(renderSuggestion).join('')
                + '</div>';
        }

        // Tool sections
        for (const sec of SECTIONS) {
            const tools = TOOLS_REGISTRY.filter(t => t.section === sec.id);
            if (!tools.length) continue;
            const cards = tools.map(renderToolCard).join('');
            html += '<div class="cp-section">'
                + '<div class="cp-section-title">' + _escHtml(_t(sec.labelKey)) + '</div>'
                + '<div class="cp-grid">' + cards + '</div>'
                + '</div>';
        }

        body.innerHTML = html;
    }

    // ── Status fetching ───────────────────────────────────────────────

    async function refreshStatus() {
        try {
            const resp = await fetch('/api/v2/attention');
            if (resp.ok) {
                const body = await resp.json();
                const data = (body && body.data) || {};
                _statusCache.attention = data.rules || [];
                _statusCache.tools = data.tool_status || {};
                _statusCache.suggestions = data.suggestions || [];
            }
        } catch (e) {
            // NP3 — silent fallback, keep last cache
        }
        render();
    }

    // ── Public hooks ──────────────────────────────────────────────────

    window._controlsRender = render;
    window._controlsRefresh = refreshStatus;

    window._controlsToggleCard = function (toolId) {
        const tool = getTool(toolId);
        if (!tool) return;
        try {
            tool.toggleFn();
        } catch (err) {
            console.warn('[controls] toggle', toolId, 'failed', err);
        }
        // Re-render after a short delay so DOM state settles.
        setTimeout(render, 50);
    };

    window._controlsCycleDock = function (toolId) {
        // dock cycle is handled by existing draggable-panel logic; for v1 we
        // surface only "click to toggle" + the natural drag-to-dock UX.
        // Future: programmatic dock via _moveToSidebar helper.
        return window._controlsToggleCard(toolId);
    };

    window._controlsSetQuery = function (q) {
        _searchQuery = String(q || '');
        render();
    };

    window._controlsAcknowledge = async function (ruleId) {
        _snoozedUntil[ruleId] = (Date.now() / 1000) + 24 * 3600;
        try {
            await fetch('/api/v2/attention/' + encodeURIComponent(ruleId) + '/snooze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hours: 24 }),
            });
        } catch (e) { /* server-side snooze is best-effort */ }
        render();
    };

    window._controlsApplySuggestion = async function (ruleId) {
        const sug = (_statusCache.suggestions || []).find(s => s.rule_id === ruleId);
        if (!sug) return;
        const ok = window.confirm(
            'Apply suggested threshold ' + sug.suggested + ' for ' + ruleId + '?\n\n'
            + (sug.message || ''));
        if (!ok) return;
        try {
            await fetch('/api/v2/attention/thresholds/' + encodeURIComponent(ruleId), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threshold: sug.suggested }),
            });
            await refreshStatus();
        } catch (e) {
            window.alert('Apply failed: ' + e);
        }
    };

    window._controlsDismissSuggestion = function (ruleId) {
        _statusCache.suggestions = (_statusCache.suggestions || [])
            .filter(s => s.rule_id !== ruleId);
        render();
    };

    // ── Polling lifecycle ─────────────────────────────────────────────

    function startPolling() {
        if (_pollTimer) return;
        refreshStatus();
        _pollTimer = setInterval(refreshStatus, 5000);
    }

    function stopPolling() {
        if (_pollTimer) {
            clearInterval(_pollTimer);
            _pollTimer = null;
        }
    }

    // Hook into the new Tools Hub modal show/hide.
    function _watchControlsPanel() {
        const cp = document.getElementById('controls-tools-modal');
        if (!cp) return;
        const observer = new MutationObserver(() => {
            const visible = cp.style.display === 'flex'
                || (cp.style.display !== 'none' && cp.offsetParent !== null);
            if (visible) startPolling();
            else stopPolling();
        });
        observer.observe(cp, { attributes: true, attributeFilter: ['style', 'class'] });
    }

    // Keyboard: '/' focuses search when panel is open, Esc closes panel.
    document.addEventListener('keydown', (e) => {
        const cp = document.getElementById('controls-tools-modal');
        if (!cp) return;
        const visible = cp.style.display === 'flex';
        if (!visible) return;
        if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
            e.preventDefault();
            const search = document.getElementById('controls-search');
            if (search) search.focus();
        } else if (e.key === 'Escape') {
            window._controlsCloseHub();
        }
    });

    window._controlsOpenHub = function () {
        if (typeof openModal === 'function') {
            openModal('controls-tools-modal');
        } else {
            const m = document.getElementById('controls-tools-modal');
            if (m) m.style.display = 'flex';
        }
        render();
        refreshStatus();
    };

    window._controlsCloseHub = function () {
        if (typeof closeAllModals === 'function') {
            closeAllModals();
        } else {
            const m = document.getElementById('controls-tools-modal');
            if (m) m.style.display = 'none';
        }
    };

    // Initialise once DOM is ready
    function _init() {
        _watchControlsPanel();
        render();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _init);
    } else {
        _init();
    }
})();
