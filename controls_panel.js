/**
 * CONTROLS Tools Hub — embedded design (commits Q–U, 2026-04-29).
 *
 * Replaces the modal-based hub with an in-CONTROLS-panel embedded
 * accordion. Each tool is a card with explicit [Open] [Close] +
 * dock-position buttons (left/right/float) so analysts never have to
 * guess what a single click will do.
 *
 * Design rationale (analyst workflow):
 *   - Modal hid the map; embedded keeps the map + scenario bar + alert
 *     lane visible while inspecting tool state.
 *   - Click-to-toggle led to misclicks under time pressure; explicit
 *     [Open]/[Close] surfaces intent and current state at the same
 *     position (active button is filled).
 *   - DOCK was discoverable only through drag; this version exposes
 *     left / right / float buttons inline.
 *   - Accordion folds non-active sections so the panel stays tall but
 *     not overwhelming; ATTENTION + INTELLIGENCE default-expanded.
 */
(function () {
    'use strict';

    // ── Sections ────────────────────────────────────────────────────────

    const SECTIONS = [
        { id: 'intelligence',      labelKey: 'controls.section.intelligence',      defaultOpen: true  },
        { id: 'scenario_targeting',labelKey: 'controls.section.scenario_targeting',defaultOpen: false },
        { id: 'simulation_analysis',labelKey:'controls.section.simulation_analysis',defaultOpen: false },
        { id: 'tradecraft',        labelKey: 'controls.section.tradecraft',        defaultOpen: false },
        { id: 'automation',        labelKey: 'controls.section.automation',        defaultOpen: false },
        { id: 'admin',             labelKey: 'controls.section.admin',             defaultOpen: false },
    ];

    // ── TOOLS_REGISTRY ──────────────────────────────────────────────────
    // dockable: panel can be docked into a sidebar; placeholderId is the
    //           DOM anchor inside the target sidebar
    // floating: panel can ONLY float (no sidebar dock target)
    // modal:    panel is a modal (open/close only, no dock semantics)

    const TOOLS_REGISTRY = [
        // ─ Intelligence ─
        { id: 'llm-intel', section: 'intelligence', icon: '🤖',
          labelKey: 'tools.llm_intelligence', descKey: 'controls.tool.llm_intel.desc',
          panelId: 'llm-intel-panel', placeholderId: 'lsb-ph-llm',
          kind: 'dockable', toggleFn: () => window.toggleLlmIntelPanel && window.toggleLlmIntelPanel() },
        { id: 'dashboard', section: 'intelligence', icon: '📡',
          labelKey: 'tools.live_threat_telemetry', descKey: 'controls.tool.dashboard.desc',
          panelId: 'dashboard-panel', placeholderId: 'dashboard-placeholder',
          kind: 'dockable', toggleFn: () => window.toggleDashboardPanel && window.toggleDashboardPanel() },
        { id: 'tg-sigint', section: 'intelligence', icon: '📻',
          labelKey: 'tools.telegram_sigint', descKey: 'controls.tool.tg.desc',
          panelId: 'tg-sigint-panel', placeholderId: null,
          kind: 'floating', toggleFn: () => window.toggleTgSigint && window.toggleTgSigint() },
        { id: 'chain', section: 'intelligence', icon: '🔗',
          labelKey: 'tools.evidence_chain', descKey: 'controls.tool.chain.desc',
          panelId: 'chain-panel', placeholderId: 'chain-placeholder',
          kind: 'dockable', toggleFn: () => window.toggleChainPanel && window.toggleChainPanel() },
        { id: 'gn', section: 'intelligence', icon: '🔍',
          labelKey: 'tools.greynoise', descKey: 'controls.tool.gn.desc',
          panelId: 'gn-panel', placeholderId: null,
          kind: 'floating', toggleFn: () => window.toggleGnPanel && window.toggleGnPanel() },

        // ─ Scenario & Targeting ─
        { id: 'target', section: 'scenario_targeting', icon: '🎯',
          labelKey: 'tools.target_visibility', descKey: 'controls.tool.target.desc',
          panelId: 'target-panel', placeholderId: 'target-placeholder',
          kind: 'dockable', toggleFn: () => window.toggleTargetPanel && window.toggleTargetPanel() },
        { id: 'climate', section: 'scenario_targeting', icon: '🌡',
          labelKey: 'tools.strategic_climate', descKey: 'controls.tool.climate.desc',
          panelId: 'climate-panel', placeholderId: 'lsb-ph-climate',
          kind: 'dockable', toggleFn: () => window.toggleClimatePanel && window.toggleClimatePanel() },
        { id: 'weather', section: 'scenario_targeting', icon: '☂',
          labelKey: 'tools.weather_brief', descKey: 'controls.tool.weather.desc',
          panelId: 'weather-brief-panel', placeholderId: 'lsb-ph-wx',
          kind: 'dockable', toggleFn: () => window.toggleWeatherBrief && window.toggleWeatherBrief() },

        // ─ Simulation & Analysis ─
        { id: 'whatif', section: 'simulation_analysis', icon: '🧪',
          labelKey: 'tools.whatif_sim', descKey: 'controls.tool.whatif.desc',
          panelId: 'whatif-panel', placeholderId: null,
          kind: 'floating', toggleFn: () => window.toggleWhatIfPanel && window.toggleWhatIfPanel() },
        { id: 'spof', section: 'simulation_analysis', icon: '🔗',
          labelKey: 'tools.spof_analysis', descKey: 'controls.tool.spof.desc',
          panelId: 'spof-panel', placeholderId: null,
          kind: 'floating', toggleFn: () => window.toggleSpofPanel && window.toggleSpofPanel() },
        { id: 'corr', section: 'simulation_analysis', icon: '🔥',
          labelKey: 'tools.corr_heatmap', descKey: 'controls.tool.corr.desc',
          panelId: 'corr-heatmap-panel', placeholderId: 'lsb-ph-corr',
          kind: 'dockable', toggleFn: () => window.toggleCorrHeatmap && window.toggleCorrHeatmap() },

        // ─ Tradecraft ─
        { id: 'tradecraft', section: 'tradecraft', icon: '📖',
          labelKey: 'tools.tradecraft', descKey: 'controls.tool.tradecraft.desc',
          panelId: 'tradecraft-panel', placeholderId: null,
          kind: 'floating', toggleFn: () => window.toggleTradecraftPanel && window.toggleTradecraftPanel() },
        { id: 'watchpane', section: 'tradecraft', icon: '👁',
          labelKey: 'tools.sensor_watchpane', descKey: 'controls.tool.watchpane.desc',
          panelId: 'sensor-watchpane', placeholderId: null,
          kind: 'floating', toggleFn: () => window.toggleSensorWatchpane && window.toggleSensorWatchpane() },
        { id: 'hist', section: 'tradecraft', icon: '📊',
          labelKey: 'tools.history_analysis', descKey: 'controls.tool.history.desc',
          panelId: 'history-panel', placeholderId: null,
          kind: 'floating', toggleFn: () => window.toggleHistoryPanel && window.toggleHistoryPanel() },

        // ─ Automation (modal) ─
        // For kind:'modal' we provide BOTH openFn (idempotent: opens
        // even if already open) and closeFn (idempotent: closes even
        // if already closed). _ensureOpen/_ensureClosed dispatch to
        // these instead of treating toggleFn as a real toggle —
        // avoids the bug where calling _wizardOpen on an open wizard
        // does nothing useful and the [Close] button never closes.
        { id: 'autotune', section: 'automation', icon: '⚙',
          labelKey: 'tools.autotune_wizard', descKey: 'controls.tool.autotune.desc',
          panelId: 'autotune-wizard-modal', placeholderId: null,
          kind: 'modal',
          openFn:  () => window._wizardOpen  && window._wizardOpen(),
          closeFn: () => window._wizardClose && window._wizardClose() },
        // Phase 9.4 (C16) — both LLM cards now route to the unified
        // Settings shell. The old llm-features-modal and ad-hoc routing
        // overlay remain in the DOM as fallbacks for the auto-tune
        // wizard's deeplinks but are no longer the primary entry points.
        { id: 'llm-features', section: 'automation', icon: '🤖',
          labelKey: 'tools.llm_features', descKey: 'controls.tool.llm_features.desc',
          panelId: 'settings-modal-v2', placeholderId: null,
          kind: 'modal',
          openFn:  () => (window._settingsOpen
                          || window._llmFeaturesOpen
                          || function(){})('llm.features'),
          closeFn: () => (window._settingsClose
                          || window._llmFeaturesClose
                          || function(){})() },
        { id: 'llm-routing', section: 'automation', icon: '🧩',
          labelKey: 'tools.llm_routing', descKey: 'controls.tool.llm_routing.desc',
          panelId: 'settings-modal-v2', placeholderId: null,
          kind: 'modal',
          openFn:  () => (window._settingsOpen
                          || window._llmRoutingOpen
                          || function(){})('llm.routing'),
          closeFn: () => (window._settingsClose || function(){})() },
        { id: 'decision-history', section: 'automation', icon: '📜',
          labelKey: 'tools.decision_history', descKey: 'controls.tool.decision_history.desc',
          panelId: 'decision-history-modal', placeholderId: null,
          kind: 'modal',
          openFn:  () => window._decisionHistoryOpen  && window._decisionHistoryOpen(),
          closeFn: () => window._decisionHistoryClose && window._decisionHistoryClose() },

        // ─ Admin (modal) ─
        { id: 'usrmgr', section: 'admin', icon: '👤',
          labelKey: 'tools.user_management', descKey: 'controls.tool.usrmgr.desc',
          panelId: 'settings-modal', placeholderId: null,
          kind: 'modal',
          openFn: () => {
              if (typeof openModal === 'function') {
                  openModal('settings-modal');
                  if (typeof switchTab === 'function') switchTab('users');
                  if (typeof umgrLoadUsers === 'function') umgrLoadUsers();
              }
          },
          closeFn: () => {
              if (typeof closeAllModals === 'function') closeAllModals();
          } },
    ];

    const _byId = new Map(TOOLS_REGISTRY.map(t => [t.id, t]));
    function getTool(id) { return _byId.get(id); }

    // ── State ───────────────────────────────────────────────────────────

    let _pollTimer = null;
    let _searchQuery = '';
    let _statusCache = { tools: {}, attention: [], suggestions: [] };
    let _snoozedUntil = {};
    // Persisted accordion state per section
    let _sectionOpen = _loadAccordionState();

    function _loadAccordionState() {
        try {
            const raw = localStorage.getItem('cp_section_open');
            if (raw) {
                const parsed = JSON.parse(raw);
                if (parsed && typeof parsed === 'object') return parsed;
            }
        } catch (e) { /* ignore */ }
        const init = {};
        SECTIONS.forEach(s => init[s.id] = !!s.defaultOpen);
        return init;
    }

    function _saveAccordionState() {
        try {
            localStorage.setItem('cp_section_open', JSON.stringify(_sectionOpen));
        } catch (e) { /* ignore */ }
    }

    // ── Panel state detection ──────────────────────────────────────────

    function isPanelOpen(panelId) {
        const p = document.getElementById(panelId);
        if (!p) return false;
        if (p.style.display === 'none') return false;
        if (p.style.display) return true;
        if (p.classList.contains('docked')) return true;
        if (p.classList.contains('modal-window')) {
            return p.style.display === 'flex';
        }
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

    // ── DOCK helpers ────────────────────────────────────────────────────
    // Programmatically move a panel between sidebars and floating by
    // mimicking the existing dragdrop logic in radar.js (move placeholder
    // to target sidebar, then trigger the panel's dock-btn click).

    function _moveTo(toolId, target /* 'left' | 'right' | 'float' */) {
        const tool = getTool(toolId);
        if (!tool || tool.kind !== 'dockable') return;
        const panel = document.getElementById(tool.panelId);
        const placeholder = tool.placeholderId
            ? document.getElementById(tool.placeholderId) : null;
        if (!panel || !placeholder) return;

        if (target === 'float') {
            // Undock to float: copy panel to body, restore floating styles
            const rect = panel.getBoundingClientRect();
            document.body.appendChild(panel);
            panel.classList.remove('docked');
            panel.classList.add('floating');
            panel.style.display = 'flex';
            panel.style.left = Math.max(80, rect.left) + 'px';
            panel.style.top  = Math.max(60, rect.top) + 'px';
            // Visible dock button
            const dockBtn = panel.querySelector('.dock-btn');
            if (dockBtn) dockBtn.style.display = 'inline-block';
        } else {
            // Move placeholder to the requested sidebar (if not already)
            const targetSb = document.getElementById(
                target === 'left' ? 'left-sidebar' : 'sidebar');
            if (targetSb && !targetSb.contains(placeholder)) {
                // Insert before sidebar-footer if present, else append
                const footer = targetSb.querySelector('.sidebar-footer');
                if (footer) targetSb.insertBefore(placeholder, footer);
                else targetSb.appendChild(placeholder);
            }
            // Move panel into placeholder
            placeholder.appendChild(panel);
            panel.classList.remove('floating');
            panel.classList.add('docked');
            panel.style.left = '';
            panel.style.top = '';
            panel.style.width = '';
            panel.style.height = '';
            panel.style.display = 'flex';
            const dockBtn = panel.querySelector('.dock-btn');
            if (dockBtn) dockBtn.style.display = 'none';
        }
        if (typeof updateSidebarVisibility === 'function') updateSidebarVisibility();
        if (typeof saveLocalState === 'function') saveLocalState();
        setTimeout(() => { render(); refreshStatus(); }, 50);
    }

    function _ensureOpen(toolId) {
        const tool = getTool(toolId);
        if (!tool) return;
        if (isPanelOpen(tool.panelId)) return;
        // Modal kinds use explicit openFn (toggleFn is reserved for
        // panels whose toggleFn is genuinely a toggle).
        try {
            if (tool.openFn) tool.openFn();
            else if (tool.toggleFn) tool.toggleFn();
        } catch (e) {}
    }

    function _ensureClosed(toolId) {
        const tool = getTool(toolId);
        if (!tool) return;
        if (!isPanelOpen(tool.panelId)) return;
        // Modal kinds use explicit closeFn — calling their open-only
        // toggleFn again on an already-open modal does nothing useful
        // and that was the original bug. Non-modal panels still rely
        // on toggleFn because their toggle truly toggles.
        try {
            if (tool.closeFn) tool.closeFn();
            else if (tool.toggleFn) tool.toggleFn();
        } catch (e) {}
    }

    // ── Render ──────────────────────────────────────────────────────────

    function _t(key, vars) {
        return (typeof window._t === 'function' ? window._t(key, vars) : key);
    }

    function _escHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function statusBadge(toolId) {
        const status = _statusCache.tools[toolId];
        if (!status || !status.text) return '';
        const cls = 'cp-status'
            + (status.severity ? ' cp-sev-' + status.severity : '');
        return '<span class="' + cls + '">' + _escHtml(status.text) + '</span>';
    }

    function dockLabel(dock) {
        if (dock === 'closed') return '○ closed';
        if (dock === 'left') return '●OPEN ⇄L';
        if (dock === 'right') return '●OPEN ⇄R';
        if (dock === 'floating') return '●OPEN ⤢';
        if (dock === 'modal') return '●OPEN';
        return '●OPEN';
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
        const isOpen = dock !== 'closed';
        const dockTxt = dockLabel(dock);
        const status = statusBadge(tool.id);
        const dimmed = !matchesQuery(tool) ? ' cp-card-dimmed' : '';

        // Build action buttons. Layout depends on tool kind:
        //   modal:    [Open] [Close]
        //   floating: [Open] [Close]   (no dock targets)
        //   dockable: [Open] [Close]   then     [⇄L] [⇄R] [⤢]
        let buttons = '';
        const openCls = 'cp-btn cp-btn-open' + (isOpen ? ' cp-active' : '');
        const closeCls = 'cp-btn cp-btn-close' + (!isOpen ? ' cp-active' : '');
        buttons += '<button class="' + openCls + '" title="' + _escHtml(_t('controls.btn.open_tip'))
            + '" onclick="window._controlsOpenTool(\'' + tool.id + '\')">'
            + _escHtml(_t('controls.btn.open')) + '</button>';
        buttons += '<button class="' + closeCls + '" title="' + _escHtml(_t('controls.btn.close_tip'))
            + '" onclick="window._controlsCloseTool(\'' + tool.id + '\')">'
            + _escHtml(_t('controls.btn.close')) + '</button>';
        if (tool.kind === 'dockable') {
            const lCls  = 'cp-btn cp-btn-dock' + (dock === 'left' ? ' cp-active' : '');
            const rCls  = 'cp-btn cp-btn-dock' + (dock === 'right' ? ' cp-active' : '');
            const fCls  = 'cp-btn cp-btn-dock' + (dock === 'floating' ? ' cp-active' : '');
            buttons += '<span class="cp-btn-spacer"></span>';
            buttons += '<button class="' + lCls + '" title="' + _escHtml(_t('controls.btn.dock_left_tip'))
                + '" onclick="window._controlsDock(\'' + tool.id + '\',\'left\')">⇄L</button>';
            buttons += '<button class="' + rCls + '" title="' + _escHtml(_t('controls.btn.dock_right_tip'))
                + '" onclick="window._controlsDock(\'' + tool.id + '\',\'right\')">⇄R</button>';
            buttons += '<button class="' + fCls + '" title="' + _escHtml(_t('controls.btn.float_tip'))
                + '" onclick="window._controlsDock(\'' + tool.id + '\',\'float\')">⤢</button>';
        }

        return '<div class="cp-card' + dimmed + '" data-tool-id="' + tool.id + '"'
            + ' title="' + _escHtml(_t(tool.descKey || tool.labelKey)) + '">'
            + '  <div class="cp-card-head">'
            + '    <span class="cp-icon">' + _escHtml(tool.icon || '') + '</span>'
            + '    <span class="cp-name">' + _escHtml(_t(tool.labelKey)) + '</span>'
            + '    <span class="cp-card-state">'
            +        '<span class="cp-dock cp-dock-' + (isOpen ? 'open' : 'closed') + '">' + dockTxt + '</span>'
            +        status
            + '    </span>'
            + '  </div>'
            + '  <div class="cp-card-actions">' + buttons + '</div>'
            + '</div>';
    }

    function renderAttentionCard(rule) {
        const sev = rule.severity || 'info';
        if (_snoozedUntil[rule.rule_id]
            && _snoozedUntil[rule.rule_id] > (Date.now() / 1000)) {
            return '';
        }
        const tool = getTool(rule.tool_id);
        const toolName = tool ? _t(tool.labelKey) : rule.tool_id;
        const sevLabel = sev === 'critical' ? '🔴 CRITICAL'
            : sev === 'warning' ? '⚠ WARNING' : 'ℹ INFO';
        const canSnooze = sev !== 'critical';
        return '<div class="cp-attention cp-sev-' + sev + '">'
            + '<div class="cp-att-head">'
            +   '<span class="cp-att-sev">' + sevLabel + '</span>'
            +   '<span class="cp-att-tool">' + _escHtml(toolName) + '</span>'
            + '</div>'
            + '<div class="cp-att-msg">' + _escHtml(rule.message || '') + '</div>'
            + '<div class="cp-att-actions">'
            +   '<button class="cp-btn cp-btn-attn-open" onclick="window._controlsOpenTool(\''
            +     (tool ? tool.id : '') + '\')">' + _escHtml(_t('controls.btn.open')) + '</button>'
            + (canSnooze
                ? '<button class="cp-btn cp-btn-snooze" onclick="window._controlsAcknowledge(\''
                  + rule.rule_id + '\')">' + _escHtml(_t('controls.btn.snooze')) + '</button>'
                : '')
            + '</div>'
            + '</div>';
    }

    function renderSuggestion(s) {
        return '<div class="cp-suggestion">'
            + '<span class="cp-sug-icon">💡</span>'
            + '<span class="cp-sug-text">'
            + _escHtml(s.message || (s.rule_id + ' の推奨閾値'))
            + '</span>'
            + '<button class="cp-btn cp-btn-suggest" onclick="window._controlsApplySuggestion(\'' + s.rule_id + '\')">'
            +   _escHtml(_t('controls.btn.apply_threshold', { value: s.suggested })) + '</button>'
            + '<button class="cp-btn cp-btn-dismiss" onclick="window._controlsDismissSuggestion(\'' + s.rule_id + '\')">'
            +   _escHtml(_t('controls.btn.dismiss')) + '</button>'
            + '</div>';
    }

    function renderAccordionHeader(sec, count) {
        const open = !!_sectionOpen[sec.id];
        return '<div class="cp-acc-head' + (open ? ' open' : '') + '"'
            + ' onclick="window._controlsToggleSection(\'' + sec.id + '\')">'
            + '<span class="cp-acc-chev">' + (open ? '▼' : '▶') + '</span>'
            + '<span class="cp-acc-title">' + _escHtml(_t(sec.labelKey)) + '</span>'
            + '<span class="cp-acc-count">' + count + '</span>'
            + '</div>';
    }

    function render() {
        const body = document.getElementById('controls-tools-embedded');
        if (!body) return;

        let html = '';

        // Search bar (sticky at top of embedded)
        html += '<div class="cp-search">'
            + '<input type="text" id="controls-search" placeholder="' + _escHtml(_t('controls.search_placeholder'))
            + '" oninput="window._controlsSetQuery(this.value)" value="' + _escHtml(_searchQuery) + '">'
            + '</div>';

        // ATTENTION section (always expanded; no accordion)
        const att = (_statusCache.attention || []).filter(r =>
            !(_snoozedUntil[r.rule_id]
              && _snoozedUntil[r.rule_id] > (Date.now() / 1000)));
        if (att.length) {
            const sevOrder = { critical: 0, warning: 1, info: 2 };
            att.sort((a, b) =>
                (sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9));
            html += '<div class="cp-section cp-section-attention">'
                + '<div class="cp-section-title">⚠ ATTENTION ('
                +   att.length + ')</div>'
                + att.map(renderAttentionCard).join('')
                + '</div>';
        }

        // Suggestions
        const sugs = (_statusCache.suggestions || []);
        if (sugs.length) {
            html += '<div class="cp-section cp-section-suggestions">'
                + '<div class="cp-section-title">💡 '
                + _escHtml(_t('controls.section.suggestions')) + '</div>'
                + sugs.map(renderSuggestion).join('')
                + '</div>';
        }

        // Accordion sections
        for (const sec of SECTIONS) {
            const tools = TOOLS_REGISTRY.filter(t => t.section === sec.id);
            if (!tools.length) continue;
            const visibleTools = tools.filter(matchesQuery);
            const cnt = tools.length;
            html += '<div class="cp-section">';
            html += renderAccordionHeader(sec, cnt);
            if (_sectionOpen[sec.id] || _searchQuery) {
                // Expand when accordion is open OR a query is active so search
                // results across sections are visible immediately.
                html += '<div class="cp-acc-body">'
                    + (visibleTools.length
                        ? visibleTools.map(renderToolCard).join('')
                        : '<div class="cp-empty-tip">'
                          + _escHtml(_t('controls.no_match')) + '</div>')
                    + '</div>';
            }
            html += '</div>';
        }

        body.innerHTML = html;
    }

    // ── Status fetching ─────────────────────────────────────────────────

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
        } catch (e) { /* NP3 fallback */ }
        render();
    }

    // ── Public hooks ────────────────────────────────────────────────────

    window._controlsRender = render;
    window._controlsRefresh = refreshStatus;

    window._controlsOpenTool = function (toolId) {
        _ensureOpen(toolId);
        setTimeout(() => { render(); }, 50);
    };
    window._controlsCloseTool = function (toolId) {
        _ensureClosed(toolId);
        setTimeout(() => { render(); }, 50);
    };
    window._controlsDock = function (toolId, target) {
        const tool = getTool(toolId);
        if (!tool) return;
        // Ensure panel is open before docking
        _ensureOpen(toolId);
        _moveTo(toolId, target);
    };

    window._controlsToggleSection = function (sectionId) {
        _sectionOpen[sectionId] = !_sectionOpen[sectionId];
        _saveAccordionState();
        render();
    };

    window._controlsSetQuery = function (q) {
        _searchQuery = String(q || '');
        render();
    };

    window._controlsAcknowledge = async function (ruleId) {
        _snoozedUntil[ruleId] = (Date.now() / 1000) + 24 * 3600;
        try {
            const r = await fetch('/api/v2/attention/' + encodeURIComponent(ruleId) + '/snooze', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hours: 24 }),
            });
            if (!r.ok) {
                throw new Error('HTTP ' + r.status);
            }
        } catch (e) {
            // SF9 (audit fix): a swallowed POST failure left the rule
            // appearing snoozed in local memory while the server-side
            // snooze was never recorded. After a refresh the rule
            // re-fired and the analyst could not tell the snooze had
            // not been persisted. Surface a brief warning so the
            // analyst knows to retry.
            console.warn('[Controls] snooze POST failed for', ruleId, e);
            if (typeof window.showToast === 'function') {
                window.showToast('スヌーズをサーバーに保存できませんでした — 再読み込み時に再表示されます。');
            } else {
                alert('スヌーズをサーバーに保存できませんでした — 再読み込み時に再表示されます。');
            }
            // Roll back the optimistic local snooze so render() reflects truth.
            delete _snoozedUntil[ruleId];
        }
        render();
    };

    window._controlsApplySuggestion = async function (ruleId) {
        const sug = (_statusCache.suggestions || []).find(s => s.rule_id === ruleId);
        if (!sug) return;
        const ok = window.confirm(
            ruleId + ' に推奨閾値 ' + sug.suggested + ' を適用しますか？\n\n'
            + (sug.message || ''));
        if (!ok) return;
        try {
            await fetch('/api/v2/attention/thresholds/' + encodeURIComponent(ruleId), {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threshold: sug.suggested }),
            });
            await refreshStatus();
        } catch (e) {
            window.alert('適用に失敗しました: ' + e);
        }
    };

    window._controlsDismissSuggestion = function (ruleId) {
        _statusCache.suggestions = (_statusCache.suggestions || [])
            .filter(s => s.rule_id !== ruleId);
        render();
    };

    // ── Polling lifecycle ───────────────────────────────────────────────

    function startPolling() {
        if (_pollTimer) return;
        refreshStatus();
        _pollTimer = setInterval(refreshStatus, 5000);
    }
    function stopPolling() {
        if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
    }

    // Hook into the CONTROLS panel (#hud-hamburger-panel) show/hide.
    function _watchControlsPanel() {
        const cp = document.getElementById('hud-hamburger-panel');
        if (!cp) return;
        const observer = new MutationObserver(() => {
            const visible = cp.style.display !== 'none' && cp.offsetParent !== null;
            if (visible) startPolling();
            else stopPolling();
        });
        observer.observe(cp, { attributes: true, attributeFilter: ['style', 'class'] });
    }

    // Keyboard: '/' focuses search, Esc closes panel.
    document.addEventListener('keydown', (e) => {
        const cp = document.getElementById('hud-hamburger-panel');
        if (!cp) return;
        const visible = cp.style.display !== 'none' && cp.offsetParent !== null;
        if (!visible) return;
        if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
            e.preventDefault();
            const search = document.getElementById('controls-search');
            if (search) search.focus();
        } else if (e.key === 'Escape') {
            if (typeof closeHudHamburger === 'function') closeHudHamburger();
        }
    });

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
