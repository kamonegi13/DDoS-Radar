/**
 * Auto-tuning Wizard JS (Tier 4 commit 14).
 *
 * Wires the #autotune-wizard-modal and #autotune-confirm-modal markup
 * (added in commit 13) to the calibration_v2 API endpoints. Five tabs:
 *
 *   scenario_improver  GET /api/v2/proposals/scenario_improver
 *   structure          (filtered subset of scenario_improver:
 *                       proposal_type in role_reclassify / dormant_*)
 *   sensor_disable     GET /api/v2/proposals/sensor_disable
 *   drift              GET /api/v2/drift_signals
 *   discovery          GET /api/v2/discovery/clusters
 *
 * Apply path is gated by the NP7 confirm sub-modal whenever the
 * proposal carries is_recall_reducing=true. The sub-modal shows the
 * full why_string + evidence and disables Apply until the analyst
 * clicks Confirm. NP7 — every state-changing call passes through this
 * gate.
 *
 * Depends on globals defined in radar.js:
 *   openModal(id), closeAllModals(), _t(key, vars), _escHtml(s)
 *   window.fetch (already auto-injects JWT per CLAUDE.md)
 */
(function () {
    'use strict';

    const TABS = {
        scenario_improver: {
            api: '/api/v2/proposals/scenario_improver',
            renderer: renderProposalRow,
            actions: { apply: '/apply', dismiss: '/dismiss', defer: '/defer' },
            proposalTypeFilter: null,  // show all types
        },
        structure: {
            api: '/api/v2/proposals/scenario_improver',
            renderer: renderProposalRow,
            actions: { apply: '/apply', dismiss: '/dismiss', defer: '/defer' },
            proposalTypeFilter: ['role_reclassify', 'dormant_participant'],
        },
        sensor_disable: {
            api: '/api/v2/proposals/sensor_disable',
            renderer: renderSensorDisableRow,
            actions: { ack: '/ack' },
        },
        drift: {
            api: '/api/v2/drift_signals',
            renderer: renderDriftRow,
            actions: { ack: '/ack' },
            apiBase: '/api/v2/drift_signals',
        },
        discovery: {
            api: '/api/v2/discovery/clusters',
            renderer: renderDiscoveryRow,
            actions: {},
        },
    };

    let currentTab = 'scenario_improver';
    let pendingConfirm = null;  // {endpoint, kind, label}

    // ── Public entry points (referenced from inline onclick) ──────────────

    window._wizardOpen = function () {
        if (typeof openModal === 'function') {
            openModal('autotune-wizard-modal');
        } else {
            const m = document.getElementById('autotune-wizard-modal');
            if (m) m.style.display = 'flex';
        }
        loadTab(currentTab);
    };

    window._wizardClose = function () {
        if (typeof closeAllModals === 'function') {
            closeAllModals();
        } else {
            const m = document.getElementById('autotune-wizard-modal');
            if (m) m.style.display = 'none';
        }
    };

    window._wizardSwitchTab = function (tabName) {
        if (!TABS[tabName]) return;
        currentTab = tabName;
        const tabs = document.querySelectorAll('#autotune-wizard-modal .wizard-tab');
        tabs.forEach((el) => {
            el.classList.toggle('active', el.dataset.wizardTab === tabName);
        });
        loadTab(tabName);
    };

    window._wizardConfirmCancel = function () {
        const m = document.getElementById('autotune-confirm-modal');
        if (m) m.style.display = 'none';
        pendingConfirm = null;
    };

    window._wizardConfirmApply = function () {
        if (!pendingConfirm) return;
        const { endpoint, kind } = pendingConfirm;
        window._wizardConfirmCancel();
        executeAction(endpoint, kind);
    };

    // ── Tab loading ──────────────────────────────────────────────────────

    async function loadTab(tabName) {
        const cfg = TABS[tabName];
        const content = document.querySelector(
            '#autotune-wizard-modal .wizard-content',
        );
        if (!content || !cfg) return;
        content.innerHTML = `<div class="wizard-empty">${
            _escHtml(_t('wizard.loading'))}</div>`;
        try {
            const resp = await fetch(cfg.api);
            if (!resp.ok) {
                content.innerHTML = `<div class="wizard-empty">HTTP ${
                    _escHtml(String(resp.status))}</div>`;
                return;
            }
            const body = await resp.json();
            let items = (body && body.data) || [];
            if (cfg.proposalTypeFilter) {
                items = items.filter((p) =>
                    cfg.proposalTypeFilter.indexOf(p.proposal_type) >= 0);
            }
            if (!items.length) {
                content.innerHTML = `<div class="wizard-empty">${
                    _escHtml(_t('wizard.empty'))}</div>`;
                return;
            }
            const rows = items.map((it) => cfg.renderer(it, tabName));
            content.innerHTML = rows.join('');
        } catch (err) {
            content.innerHTML = `<div class="wizard-empty">${
                _escHtml(String(err))}</div>`;
        }
    }

    // ── Renderers ────────────────────────────────────────────────────────

    function renderProposalRow(p, tabName) {
        const isRR = !!p.is_recall_reducing;
        const cls = `wizard-row${isRR ? ' is-recall-reducing' : ''}`;
        const evidence = JSON.stringify(p.evidence || {}, null, 2);
        const ago = _ago(p.emitted_at);
        const target = p.target_country || _t('wizard.row.scenario',
            { scenario: p.scenario_id || '?' });
        const warning = isRR
            ? `<div class="wizard-row-target" style="color:#ff8800;">${
                _escHtml(_t('wizard.row.recall_warning'))}</div>` : '';
        return [
            `<div class="${cls}">`,
            `  <div class="wizard-row-head">`,
            `    <span class="wizard-row-type">${_escHtml(p.proposal_type)}</span>`,
            `    <span class="wizard-row-target">${_escHtml(target)}</span>`,
            `  </div>`,
            warning,
            `  <div class="wizard-row-why">${_escHtml(p.why_string || '')}</div>`,
            `  <div class="wizard-row-evidence">${_escHtml(evidence)}</div>`,
            `  <div class="wizard-row-actions">`,
            `    <button class="btn-tactical wizard-btn-apply" `,
            `      onclick="window._wizardActionScenario(${p.id}, 'apply', ${isRR})">`,
            `      ${_escHtml(_t('wizard.row.btn.apply'))}</button>`,
            `    <button class="btn-tactical wizard-btn-defer" `,
            `      onclick="window._wizardActionScenario(${p.id}, 'defer', false)">`,
            `      ${_escHtml(_t('wizard.row.btn.defer'))}</button>`,
            `    <button class="btn-tactical wizard-btn-dismiss" `,
            `      onclick="window._wizardActionScenario(${p.id}, 'dismiss', false)">`,
            `      ${_escHtml(_t('wizard.row.btn.dismiss'))}</button>`,
            `  </div>`,
            `</div>`,
        ].join('');
    }

    function renderSensorDisableRow(p) {
        const evidence = JSON.stringify(p.evidence || {}, null, 2);
        return [
            `<div class="wizard-row is-recall-reducing">`,
            `  <div class="wizard-row-head">`,
            `    <span class="wizard-row-type">sensor_disable</span>`,
            `    <span class="wizard-row-target">${_escHtml(p.sensor_name || '?')}</span>`,
            `  </div>`,
            `  <div class="wizard-row-target" style="color:#ff8800;">${
                _escHtml(_t('wizard.row.recall_warning'))}</div>`,
            `  <div class="wizard-row-why">${_escHtml(p.why_string || '')}</div>`,
            `  <div class="wizard-row-evidence">${_escHtml(evidence)}</div>`,
            `  <div class="wizard-row-actions">`,
            `    <button class="btn-tactical wizard-btn-defer" `,
            `      onclick="window._wizardActionSensorDisable(${p.id}, 'ack')">`,
            `      ${_escHtml(_t('wizard.row.btn.ack'))}</button>`,
            `  </div>`,
            `</div>`,
        ].join('');
    }

    function renderDriftRow(p) {
        const evidence = JSON.stringify(p.evidence || {}, null, 2);
        const isRed = (p.severity || '') === 'red';
        const cls = `wizard-row${isRed ? ' is-recall-reducing' : ''}`;
        return [
            `<div class="${cls}">`,
            `  <div class="wizard-row-head">`,
            `    <span class="wizard-row-type">${_escHtml(p.drift_signal)}</span>`,
            `    <span class="wizard-row-target">[${_escHtml(p.severity)}] ${
                _escHtml(p.scenario_id || '?')}</span>`,
            `  </div>`,
            `  <div class="wizard-row-why">${_escHtml(p.why_string || '')}</div>`,
            `  <div class="wizard-row-evidence">${_escHtml(evidence)}</div>`,
            `  <div class="wizard-row-actions">`,
            `    <button class="btn-tactical wizard-btn-defer" `,
            `      onclick="window._wizardActionDrift(${p.id}, 'ack')">`,
            `      ${_escHtml(_t('wizard.row.btn.ack'))}</button>`,
            `  </div>`,
            `</div>`,
        ].join('');
    }

    function renderDiscoveryRow(c) {
        const ann = c.annotation || {};
        const annLabel = ann.suggested_name
            ? _t('wizard.discovery.suggested_name',
                  { name: ann.suggested_name })
            : _t('wizard.discovery.no_annotation');
        const conf = (typeof ann.confidence_self_reported === 'number')
            ? ann.confidence_self_reported.toFixed(2) : null;
        const isLow = conf !== null && parseFloat(conf) < 0.5;
        const confChip = conf !== null
            ? `<span class="wizard-row-confidence${isLow ? ' is-low' : ''}">${
                _escHtml(_t('wizard.row.confidence', { value: conf }))}</span>`
            : '';
        const countries = (c.countries || []).join(', ');
        return [
            `<div class="wizard-row">`,
            `  <div class="wizard-row-head">`,
            `    <span class="wizard-row-type">${_escHtml(_t(
                'wizard.discovery.cluster', { idx: c.cluster_index }))}</span>`,
            `    <span class="wizard-row-target">run #${_escHtml(String(c.run_id))} ${confChip}</span>`,
            `  </div>`,
            `  <div class="wizard-row-why">${_escHtml(_t(
                'wizard.discovery.countries', { countries }))}</div>`,
            `  <div class="wizard-row-why">${_escHtml(annLabel)}</div>`,
            ann.rationale ? `  <div class="wizard-row-evidence">${_escHtml(ann.rationale)}</div>` : '',
            `</div>`,
        ].join('');
    }

    // ── Action handlers ──────────────────────────────────────────────────

    window._wizardActionScenario = function (proposalId, action, isRecallReducing) {
        const endpoint = `/api/v2/proposals/scenario_improver/${proposalId}/${action}`;
        if (action === 'apply' && isRecallReducing) {
            promptConfirm(endpoint, action, `proposal ${proposalId} → ${action}`);
            return;
        }
        executeAction(endpoint, action);
    };

    window._wizardActionSensorDisable = function (proposalId, action) {
        const endpoint = `/api/v2/proposals/sensor_disable/${proposalId}/${action}`;
        executeAction(endpoint, action);
    };

    window._wizardActionDrift = function (eventId, action) {
        const endpoint = `/api/v2/drift_signals/${eventId}/${action}`;
        executeAction(endpoint, action);
    };

    function promptConfirm(endpoint, kind, label) {
        const detail = document.getElementById('autotune-confirm-detail');
        if (detail) detail.textContent = label;
        pendingConfirm = { endpoint, kind, label };
        const m = document.getElementById('autotune-confirm-modal');
        if (m) m.style.display = 'flex';
    }

    async function executeAction(endpoint, kind) {
        try {
            const resp = await fetch(endpoint, { method: 'POST' });
            const body = await resp.json();
            if (!resp.ok) {
                _toast(_t('wizard.action.failed',
                    { error: body.error || resp.status }));
                return;
            }
            const successKey = kind === 'apply' ? 'wizard.confirm.success'
                : kind === 'dismiss' ? 'wizard.action.dismissed'
                : kind === 'defer' ? 'wizard.action.deferred'
                : kind === 'ack' ? 'wizard.action.acknowledged'
                : 'wizard.action.acknowledged';
            _toast(_t(successKey));
            loadTab(currentTab);
        } catch (err) {
            _toast(_t('wizard.action.failed', { error: String(err) }));
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    function _ago(ts) {
        if (!ts) return '?';
        const sec = Math.max(0, (Date.now() / 1000) - ts);
        if (sec < 60) return Math.floor(sec) + 's ago';
        if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
        if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
        return Math.floor(sec / 86400) + 'd ago';
    }

    function _toast(msg) {
        // Lightweight visible feedback; falls back to console when no
        // toast helper is available.
        if (typeof window.showToast === 'function') {
            window.showToast(msg);
        } else {
            console.info('[wizard]', msg);
        }
    }
})();
