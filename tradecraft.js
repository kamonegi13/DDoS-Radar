/* tradecraft.js — Analyst Tradecraft surface (F4-F14)
 *
 * Provides the UI for the structured analytic techniques layer:
 *   F4 Hidden Signals        F5 Coverage Gap          F6 Disconfirming Evidence
 *   F7 Scenario Comparison   F8 ACH Matrix            F9 What-If Weight Slider
 *   F10 Key Assumptions      F11 Pre-Mortem           F13 Dissenting View
 *   F14 Decision Ledger
 *
 * Backend endpoints live under /api/analyst/* and /api/scenarios/*.
 * All writes carry a session_id derived from a per-tab UUID stored in
 * sessionStorage (F14 design choice: tab-unit granularity).
 */
(function () {
    'use strict';

    // ── Tab-unit session id (F14) ──────────────────────────────────────────
    const SESSION_KEY = 'tradecraft.session_id';
    function _sessionId() {
        try {
            let id = sessionStorage.getItem(SESSION_KEY);
            if (!id) {
                id = (window.crypto && window.crypto.randomUUID)
                    ? window.crypto.randomUUID()
                    : ('s_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10));
                sessionStorage.setItem(SESSION_KEY, id);
            }
            return id;
        } catch (e) {
            return 's_anon_' + Date.now().toString(36);
        }
    }

    // ── Tiny helpers ───────────────────────────────────────────────────────
    function _t(key, vars) {
        if (typeof window._t === 'function') return window._t(key, vars);
        return key;
    }
    function _esc(s) {
        if (typeof window._escHtml === 'function') return window._escHtml(s);
        if (s == null) return '';
        return String(s).replace(/[&<>"']/g, c => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }
    function _fetchJSON(url, opts) {
        opts = opts || {};
        opts.headers = Object.assign({ 'Accept': 'application/json' }, opts.headers || {});
        if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData)) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(opts.body);
        }
        return fetch(url, opts).then(r => {
            if (!r.ok) {
                return r.json().catch(() => ({})).then(j => {
                    const err = new Error(j.error || ('HTTP ' + r.status));
                    err.status = r.status;
                    throw err;
                });
            }
            return r.json();
        });
    }
    function _fmtTs(ts) {
        if (!ts) return '—';
        try {
            const d = new Date(ts * 1000);
            return d.toISOString().replace('T', ' ').slice(0, 16) + 'Z';
        } catch (e) {
            return String(ts);
        }
    }
    function _ago(ts) {
        if (!ts) return '—';
        const sec = Math.max(0, Math.floor(Date.now() / 1000 - ts));
        if (sec < 60) return sec + 's';
        if (sec < 3600) return Math.floor(sec / 60) + 'm';
        if (sec < 86400) return Math.floor(sec / 3600) + 'h';
        return Math.floor(sec / 86400) + 'd';
    }

    // ── State ──────────────────────────────────────────────────────────────
    const STATE = {
        scenarioId: null,
        scenarios: [],
        activeTab: 'hidden',
        compareIds: new Set(),
        achMatrixId: null,
        whatifWeights: {},
    };

    // ── Boot ───────────────────────────────────────────────────────────────
    function boot() {
        const panel = document.getElementById('tradecraft-panel');
        if (!panel) return;
        bindTabs();
        loadScenariosInto(document.getElementById('tradecraft-scenario'));
        const sel = document.getElementById('tradecraft-scenario');
        if (sel) {
            sel.addEventListener('change', () => {
                STATE.scenarioId = sel.value || null;
                renderActiveTab();
            });
        }
        // Re-render whenever the panel becomes visible again
        const obs = new MutationObserver(() => {
            if (panel.style.display !== 'none' && STATE.scenarioId) renderActiveTab();
        });
        obs.observe(panel, { attributes: true, attributeFilter: ['style'] });
    }

    function bindTabs() {
        document.querySelectorAll('#tradecraft-tabs .tc-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                STATE.activeTab = btn.dataset.tcTab;
                document.querySelectorAll('#tradecraft-tabs .tc-tab').forEach(b => b.classList.toggle('active', b === btn));
                document.querySelectorAll('#tradecraft-body .tc-pane').forEach(p => {
                    p.style.display = (p.id === 'tc-pane-' + STATE.activeTab) ? '' : 'none';
                });
                renderActiveTab();
            });
        });
    }

    function loadScenariosInto(sel) {
        if (!sel) return;
        _fetchJSON('/api/scenarios').then(j => {
            const list = (j && j.scenarios) || [];
            STATE.scenarios = list;
            sel.innerHTML = list.map(s =>
                `<option value="${_esc(s.id)}">${_esc(s.name || s.id)}</option>`
            ).join('');
            STATE.scenarioId = list[0] ? list[0].id : null;
            if (STATE.scenarioId) renderActiveTab();
        }).catch(() => {
            sel.innerHTML = '<option value="">—</option>';
        });
    }

    function renderActiveTab() {
        const id = STATE.scenarioId;
        if (!id) return;
        const fn = TAB_RENDERERS[STATE.activeTab];
        if (fn) fn(id);
    }

    // ── Tab renderers ──────────────────────────────────────────────────────
    const TAB_RENDERERS = {
        hidden: renderHidden,
        coverage: renderCoverage,
        disconf: renderDisconf,
        compare: renderCompare,
        ach: renderAch,
        dissent: renderDissent,
        assumptions: renderAssumptions,
        premortem: renderPremortem,
        decisions: renderDecisions,
        whatif: renderWhatIf,
    };

    // F4 Hidden Signals ----------------------------------------------------
    function renderHidden(scenarioId) {
        const pane = document.getElementById('tc-pane-hidden');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/hidden_signals?scenario_id=${encodeURIComponent(scenarioId)}&limit=100`)
            .then(j => {
                const items = j.items || [];
                if (!items.length) {
                    pane.innerHTML = '<div class="tc-empty">' + _esc(_t('panel.tradecraft.hidden.empty')) + '</div>';
                    return;
                }
                let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.hidden.help'))}</div>`;
                html += '<table class="tc-table"><thead><tr>'
                    + `<th>${_esc(_t('panel.tradecraft.col.time'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.country'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.sensor'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.domain'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.reason'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.detail'))}</th>`
                    + '</tr></thead><tbody>';
                items.forEach(it => {
                    const det = it.detail ? JSON.stringify(it.detail) : '';
                    html += '<tr>'
                        + `<td title="${_esc(_fmtTs(it.ts))}">${_esc(_ago(it.ts))}</td>`
                        + `<td>${_esc(it.country || '—')}</td>`
                        + `<td>${_esc(it.sensor)}</td>`
                        + `<td><span class="tc-dom-${_esc(it.domain)}">${_esc(it.domain)}</span></td>`
                        + `<td>${_esc(it.hide_reason)}</td>`
                        + `<td class="tc-detail">${_esc(det.slice(0, 120))}</td>`
                        + '</tr>';
                });
                html += '</tbody></table>';
                pane.innerHTML = html;
            })
            .catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F5 Coverage Gap ------------------------------------------------------
    function renderCoverage(scenarioId) {
        const pane = document.getElementById('tc-pane-coverage');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/coverage?scenario_id=${encodeURIComponent(scenarioId)}`)
            .then(j => {
                const items = j.items || [];
                if (!items.length) {
                    pane.innerHTML = '<div class="tc-empty">' + _esc(_t('panel.tradecraft.coverage.empty')) + '</div>';
                    return;
                }
                let degraded = 0;
                let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.coverage.help'))}</div>`;
                html += '<table class="tc-table"><thead><tr>'
                    + `<th>${_esc(_t('panel.tradecraft.col.sensor'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.domain'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.state'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.last_success'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.fail_count'))}</th>`
                    + '</tr></thead><tbody>';
                items.forEach(it => {
                    const ok = it.state === 'ok';
                    if (!ok) degraded++;
                    html += `<tr class="${ok ? '' : 'tc-row-warn'}">`
                        + `<td>${_esc(it.sensor)}</td>`
                        + `<td><span class="tc-dom-${_esc(it.domain)}">${_esc(it.domain || '—')}</span></td>`
                        + `<td>${_esc(it.state)}</td>`
                        + `<td title="${_esc(_fmtTs(it.last_success_ts))}">${_esc(_ago(it.last_success_ts))}</td>`
                        + `<td>${_esc(it.fail_count || 0)}</td>`
                        + '</tr>';
                });
                html += '</tbody></table>';
                html = `<div class="tc-summary">${_esc(_t('panel.tradecraft.coverage.summary', { degraded, total: items.length }))}</div>` + html;
                pane.innerHTML = html;
            })
            .catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F6 Disconfirming Evidence -------------------------------------------
    function renderDisconf(scenarioId) {
        const pane = document.getElementById('tc-pane-disconf');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/disconf?scenario_id=${encodeURIComponent(scenarioId)}`)
            .then(j => {
                const items = j.items || [];
                let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.disconf.help'))}</div>`;
                html += `<form id="tc-disconf-form" class="tc-form">
                    <textarea name="claim" rows="2" placeholder="${_esc(_t('panel.tradecraft.disconf.claim_ph'))}" required></textarea>
                    <textarea name="evidence" rows="2" placeholder="${_esc(_t('panel.tradecraft.disconf.evidence_ph'))}"></textarea>
                    <input name="source_url" placeholder="${_esc(_t('panel.tradecraft.disconf.source_ph'))}" />
                    <select name="weight">
                        <option value="0.25">${_esc(_t('panel.tradecraft.weight.weak'))} (0.25)</option>
                        <option value="0.50" selected>${_esc(_t('panel.tradecraft.weight.medium'))} (0.50)</option>
                        <option value="0.75">${_esc(_t('panel.tradecraft.weight.strong'))} (0.75)</option>
                        <option value="1.00">${_esc(_t('panel.tradecraft.weight.decisive'))} (1.00)</option>
                    </select>
                    <button type="submit">${_esc(_t('panel.tradecraft.btn.add'))}</button>
                </form>`;
                if (items.length) {
                    html += '<table class="tc-table"><thead><tr>'
                        + `<th>${_esc(_t('panel.tradecraft.col.time'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.claim'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.evidence'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.weight'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.author'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.actions'))}</th>`
                        + '</tr></thead><tbody>';
                    items.forEach(it => {
                        const retracted = it.is_retracted;
                        html += `<tr class="${retracted ? 'tc-row-retracted' : ''}">`
                            + `<td title="${_esc(_fmtTs(it.created_at))}">${_esc(_ago(it.created_at))}</td>`
                            + `<td>${_esc(it.claim)}</td>`
                            + `<td>${_esc(it.evidence || '')}${it.source_url ? ` <a href="${_esc(it.source_url)}" target="_blank" rel="noopener">↗</a>` : ''}</td>`
                            + `<td>${_esc(it.weight)}</td>`
                            + `<td>${_esc(it.author || '')}</td>`
                            + `<td>${retracted ? `<span class="tc-tag">${_esc(_t('panel.tradecraft.disconf.retracted'))}</span>` : `<button class="tc-mini" data-disconf-retract="${_esc(it.id)}">${_esc(_t('panel.tradecraft.btn.retract'))}</button>`}</td>`
                            + '</tr>';
                    });
                    html += '</tbody></table>';
                } else {
                    html += '<div class="tc-empty">' + _esc(_t('panel.tradecraft.disconf.empty')) + '</div>';
                }
                pane.innerHTML = html;
                const form = document.getElementById('tc-disconf-form');
                if (form) {
                    form.addEventListener('submit', ev => {
                        ev.preventDefault();
                        const fd = new FormData(form);
                        _fetchJSON('/api/analyst/disconf', {
                            method: 'POST',
                            body: {
                                scenario_id: scenarioId,
                                claim: fd.get('claim'),
                                evidence: fd.get('evidence'),
                                source_url: fd.get('source_url'),
                                weight: parseFloat(fd.get('weight')),
                                session_id: _sessionId(),
                            },
                        }).then(() => renderDisconf(scenarioId))
                          .catch(e => alert(e.message));
                    });
                }
                pane.querySelectorAll('[data-disconf-retract]').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-disconf-retract');
                        _fetchJSON(`/api/analyst/disconf/${encodeURIComponent(id)}/retract`, { method: 'POST', body: {} })
                            .then(() => renderDisconf(scenarioId))
                            .catch(e => alert(e.message));
                    });
                });
            })
            .catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F7 Scenario Comparison ----------------------------------------------
    function renderCompare(scenarioId) {
        const pane = document.getElementById('tc-pane-compare');
        // Default selection: focused + up to 2 others
        if (!STATE.compareIds.size) {
            STATE.compareIds.add(scenarioId);
            STATE.scenarios.slice(0, 3).forEach(s => STATE.compareIds.add(s.id));
        }
        let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.compare.help'))}</div>`;
        html += '<div class="tc-checkboxes">';
        STATE.scenarios.forEach(s => {
            const checked = STATE.compareIds.has(s.id) ? 'checked' : '';
            html += `<label class="tc-chk"><input type="checkbox" data-compare-id="${_esc(s.id)}" ${checked}/> ${_esc(s.name || s.id)}</label>`;
        });
        html += '</div>';
        html += `<button id="tc-compare-run" class="tc-btn-primary">${_esc(_t('panel.tradecraft.btn.compare'))}</button>`;
        html += '<div id="tc-compare-result" style="margin-top:10px;"></div>';
        pane.innerHTML = html;
        pane.querySelectorAll('[data-compare-id]').forEach(cb => {
            cb.addEventListener('change', () => {
                const id = cb.getAttribute('data-compare-id');
                if (cb.checked) STATE.compareIds.add(id); else STATE.compareIds.delete(id);
            });
        });
        document.getElementById('tc-compare-run').addEventListener('click', () => {
            const ids = Array.from(STATE.compareIds);
            if (ids.length < 2) { alert(_t('panel.tradecraft.compare.need2')); return; }
            const url = '/api/scenarios/compare?ids=' + encodeURIComponent(ids.join(','));
            const target = document.getElementById('tc-compare-result');
            target.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
            _fetchJSON(url).then(j => {
                const rows = j.scenarios || [];
                if (!rows.length) { target.innerHTML = '<div class="tc-empty">—</div>'; return; }
                let h = '<table class="tc-table"><thead><tr>'
                    + `<th>${_esc(_t('panel.tradecraft.col.scenario'))}</th>`
                    + '<th>TL</th>'
                    + `<th>${_esc(_t('panel.tradecraft.col.score'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.cyber'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.physical'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.info'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.signals'))}</th>`
                    + '</tr></thead><tbody>';
                rows.forEach(r => {
                    const tl = r.tl != null ? r.tl : '—';
                    h += '<tr>'
                        + `<td><b>${_esc(r.name || r.scenario_id)}</b></td>`
                        + `<td><span class="tc-tl tc-tl-${tl}">TL${tl}</span></td>`
                        + `<td>${_esc((r.score || 0).toFixed(2))}</td>`
                        + `<td>${_esc((r.domain_scores && r.domain_scores.cyber || 0).toFixed(2))}</td>`
                        + `<td>${_esc((r.domain_scores && r.domain_scores.physical || 0).toFixed(2))}</td>`
                        + `<td>${_esc((r.domain_scores && r.domain_scores.info || 0).toFixed(2))}</td>`
                        + `<td>${_esc(r.signal_count || 0)}</td>`
                        + '</tr>';
                });
                h += '</tbody></table>';
                target.innerHTML = h;
            }).catch(e => { target.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
        });
    }

    // F8 ACH Matrix -------------------------------------------------------
    function renderAch(scenarioId) {
        const pane = document.getElementById('tc-pane-ach');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/ach?scenario_id=${encodeURIComponent(scenarioId)}`)
            .then(j => {
                const matrices = j.matrices || [];
                let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.ach.help'))}</div>`;
                html += `<form id="tc-ach-create" class="tc-form">
                    <input name="title" placeholder="${_esc(_t('panel.tradecraft.ach.title_ph'))}" required />
                    <button type="submit">${_esc(_t('panel.tradecraft.btn.new_matrix'))}</button>
                </form>`;
                html += '<div class="tc-ach-list">';
                if (!matrices.length) {
                    html += '<div class="tc-empty">' + _esc(_t('panel.tradecraft.ach.empty')) + '</div>';
                } else {
                    matrices.forEach(m => {
                        html += `<button class="tc-ach-item ${STATE.achMatrixId === m.id ? 'active' : ''}" data-ach-id="${_esc(m.id)}">${_esc(m.title)} <span class="tc-mini-tag">${_esc(_ago(m.created_at))}</span></button>`;
                    });
                }
                html += '</div><div id="tc-ach-detail" style="margin-top:12px;"></div>';
                pane.innerHTML = html;

                document.getElementById('tc-ach-create').addEventListener('submit', ev => {
                    ev.preventDefault();
                    const fd = new FormData(ev.target);
                    _fetchJSON('/api/analyst/ach', {
                        method: 'POST',
                        body: { scenario_id: scenarioId, title: fd.get('title') },
                    }).then(r => { STATE.achMatrixId = r.id; renderAch(scenarioId); })
                      .catch(e => alert(e.message));
                });
                pane.querySelectorAll('[data-ach-id]').forEach(b => {
                    b.addEventListener('click', () => {
                        STATE.achMatrixId = parseInt(b.getAttribute('data-ach-id'), 10);
                        renderAchDetail();
                        pane.querySelectorAll('[data-ach-id]').forEach(x => x.classList.toggle('active', x === b));
                    });
                });
                if (STATE.achMatrixId) renderAchDetail();
            })
            .catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    function renderAchDetail() {
        const target = document.getElementById('tc-ach-detail');
        if (!target || !STATE.achMatrixId) return;
        target.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/ach/${STATE.achMatrixId}`).then(m => {
            const hyps = m.hypotheses || [];
            const evs = m.evidence || [];
            const scores = {};
            (m.scores || []).forEach(s => { scores[s.evidence_id + ':' + s.hypothesis_id] = s.score; });

            let h = `<div class="tc-ach-controls">
                <form class="tc-form-inline" id="tc-ach-add-hyp">
                    <input name="text" placeholder="${_esc(_t('panel.tradecraft.ach.hyp_ph'))}" required/>
                    <button>${_esc(_t('panel.tradecraft.btn.add_hyp'))}</button>
                </form>
                <form class="tc-form-inline" id="tc-ach-add-ev">
                    <input name="text" placeholder="${_esc(_t('panel.tradecraft.ach.ev_ph'))}" required/>
                    <select name="diagnosticity">
                        <option value="0.5">${_esc(_t('panel.tradecraft.ach.diag_low'))} 0.5</option>
                        <option value="1.0" selected>${_esc(_t('panel.tradecraft.ach.diag_med'))} 1.0</option>
                        <option value="2.0">${_esc(_t('panel.tradecraft.ach.diag_high'))} 2.0</option>
                    </select>
                    <button>${_esc(_t('panel.tradecraft.btn.add_ev'))}</button>
                </form>
            </div>`;

            if (!hyps.length || !evs.length) {
                h += `<div class="tc-empty">${_esc(_t('panel.tradecraft.ach.need_both'))}</div>`;
            } else {
                h += '<table class="tc-ach-matrix"><thead><tr><th></th>';
                hyps.forEach(hp => h += `<th>${_esc(hp.text)}</th>`);
                h += '<th class="tc-mini">D</th></tr></thead><tbody>';
                // Tally
                const tally = hyps.map(() => 0);
                evs.forEach(ev => {
                    h += `<tr><td class="tc-ach-evcell">${_esc(ev.text)}</td>`;
                    hyps.forEach((hp, hi) => {
                        const k = ev.id + ':' + hp.id;
                        const sc = scores[k];
                        const cls = sc == null ? '' : (sc < 0 ? 'tc-ach-neg' : sc > 0 ? 'tc-ach-pos' : 'tc-ach-zero');
                        if (sc != null) tally[hi] += sc * (ev.diagnosticity || 1.0);
                        h += `<td class="${cls}"><select data-ach-score data-ev="${ev.id}" data-hp="${hp.id}">
                            <option value="">·</option>
                            <option value="-2" ${sc == -2 ? 'selected' : ''}>−−</option>
                            <option value="-1" ${sc == -1 ? 'selected' : ''}>−</option>
                            <option value="0" ${sc == 0 ? 'selected' : ''}>0</option>
                            <option value="1" ${sc == 1 ? 'selected' : ''}>+</option>
                            <option value="2" ${sc == 2 ? 'selected' : ''}>++</option>
                        </select></td>`;
                    });
                    h += `<td class="tc-mini">${_esc(ev.diagnosticity)}</td></tr>`;
                });
                h += '<tr class="tc-ach-tally"><td><b>Σ</b></td>';
                tally.forEach(v => h += `<td><b>${v.toFixed(1)}</b></td>`);
                h += '<td></td></tr>';
                h += '</tbody></table>';
                h += `<div class="tc-help">${_esc(_t('panel.tradecraft.ach.tally_help'))}</div>`;
            }
            target.innerHTML = h;

            const hf = document.getElementById('tc-ach-add-hyp');
            if (hf) hf.addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(hf);
                _fetchJSON(`/api/analyst/ach/${STATE.achMatrixId}/hypothesis`, {
                    method: 'POST', body: { text: fd.get('text') },
                }).then(renderAchDetail).catch(e => alert(e.message));
            });
            const ef = document.getElementById('tc-ach-add-ev');
            if (ef) ef.addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(ef);
                _fetchJSON(`/api/analyst/ach/${STATE.achMatrixId}/evidence`, {
                    method: 'POST',
                    body: { text: fd.get('text'), diagnosticity: parseFloat(fd.get('diagnosticity')) },
                }).then(renderAchDetail).catch(e => alert(e.message));
            });
            target.querySelectorAll('[data-ach-score]').forEach(sel => {
                sel.addEventListener('change', () => {
                    const v = sel.value;
                    if (v === '') return;
                    _fetchJSON(`/api/analyst/ach/${STATE.achMatrixId}/score`, {
                        method: 'POST',
                        body: {
                            evidence_id: parseInt(sel.dataset.ev, 10),
                            hypothesis_id: parseInt(sel.dataset.hp, 10),
                            score: parseInt(v, 10),
                        },
                    }).then(renderAchDetail).catch(e => alert(e.message));
                });
            });
        }).catch(e => { target.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F13 Dissenting View -------------------------------------------------
    function renderDissent(scenarioId) {
        const pane = document.getElementById('tc-pane-dissent');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/dissent?scenario_id=${encodeURIComponent(scenarioId)}`).then(j => {
            const items = j.items || [];
            let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.dissent.help'))}</div>`;
            html += `<form id="tc-dissent-form" class="tc-form">
                <textarea name="position" rows="3" placeholder="${_esc(_t('panel.tradecraft.dissent.pos_ph'))}" required></textarea>
                <textarea name="rationale" rows="3" placeholder="${_esc(_t('panel.tradecraft.dissent.rat_ph'))}"></textarea>
                <button>${_esc(_t('panel.tradecraft.btn.add'))}</button>
            </form>`;
            if (items.length) {
                html += '<div class="tc-dissent-list">';
                items.forEach(it => {
                    html += `<div class="tc-card ${it.resolved_at ? 'tc-card-resolved' : ''}">
                        <div class="tc-card-head"><b>${_esc(it.author || '?')}</b> · ${_esc(_ago(it.created_at))}
                            ${it.resolved_at ? `<span class="tc-tag">${_esc(_t('panel.tradecraft.dissent.resolved'))}</span>` : `<button class="tc-mini" data-dissent-resolve="${it.id}">${_esc(_t('panel.tradecraft.btn.resolve'))}</button>`}
                        </div>
                        <div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.dissent.position'))}:</b> ${_esc(it.position)}</div>
                        ${it.rationale ? `<div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.dissent.rationale'))}:</b> ${_esc(it.rationale)}</div>` : ''}
                        ${it.resolution_note ? `<div class="tc-card-body tc-card-resnote"><b>${_esc(_t('panel.tradecraft.dissent.resolution'))}:</b> ${_esc(it.resolution_note)}</div>` : ''}
                    </div>`;
                });
                html += '</div>';
            } else {
                html += '<div class="tc-empty">' + _esc(_t('panel.tradecraft.dissent.empty')) + '</div>';
            }
            pane.innerHTML = html;
            document.getElementById('tc-dissent-form').addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(ev.target);
                _fetchJSON('/api/analyst/dissent', {
                    method: 'POST',
                    body: {
                        scenario_id: scenarioId,
                        position: fd.get('position'),
                        rationale: fd.get('rationale'),
                        session_id: _sessionId(),
                    },
                }).then(() => renderDissent(scenarioId)).catch(e => alert(e.message));
            });
            pane.querySelectorAll('[data-dissent-resolve]').forEach(b => {
                b.addEventListener('click', () => {
                    const note = prompt(_t('panel.tradecraft.dissent.resolve_prompt'));
                    if (note === null) return;
                    _fetchJSON(`/api/analyst/dissent/${b.getAttribute('data-dissent-resolve')}/resolve`, {
                        method: 'POST', body: { resolution_note: note },
                    }).then(() => renderDissent(scenarioId)).catch(e => alert(e.message));
                });
            });
        }).catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F10 Key Assumptions -------------------------------------------------
    function renderAssumptions(scenarioId) {
        const pane = document.getElementById('tc-pane-assumptions');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/assumptions?scenario_id=${encodeURIComponent(scenarioId)}`).then(j => {
            const items = j.items || [];
            let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.assumptions.help'))}</div>`;
            html += `<form id="tc-asm-form" class="tc-form">
                <textarea name="statement" rows="2" placeholder="${_esc(_t('panel.tradecraft.assumptions.stmt_ph'))}" required></textarea>
                <textarea name="rationale" rows="2" placeholder="${_esc(_t('panel.tradecraft.assumptions.rat_ph'))}"></textarea>
                <select name="confidence">
                    <option value="0.30">${_esc(_t('panel.tradecraft.assumptions.conf_low'))}</option>
                    <option value="0.60" selected>${_esc(_t('panel.tradecraft.assumptions.conf_med'))}</option>
                    <option value="0.85">${_esc(_t('panel.tradecraft.assumptions.conf_high'))}</option>
                </select>
                <button>${_esc(_t('panel.tradecraft.btn.add'))}</button>
            </form>`;
            if (items.length) {
                html += '<div class="tc-asm-list">';
                items.forEach(it => {
                    const cls = (it.invalidated_at ? 'tc-card-invalid' : (it.is_locked ? 'tc-card-locked' : ''));
                    html += `<div class="tc-card ${cls}">
                        <div class="tc-card-head">
                            <b>${_esc(it.statement)}</b>
                            <span class="tc-tag">${_esc(_t('panel.tradecraft.assumptions.confidence'))}: ${_esc(it.confidence)}</span>
                            ${it.is_locked ? `<span class="tc-tag tc-tag-lock">${_esc(_t('panel.tradecraft.assumptions.locked'))}</span>` : ''}
                            ${it.invalidated_at ? `<span class="tc-tag tc-tag-invalid">${_esc(_t('panel.tradecraft.assumptions.invalidated'))}</span>` : ''}
                        </div>
                        ${it.rationale ? `<div class="tc-card-body">${_esc(it.rationale)}</div>` : ''}
                        <div class="tc-card-meta">${_esc(it.author || '?')} · ${_esc(_ago(it.created_at))}</div>
                        <div class="tc-card-actions">
                            ${!it.invalidated_at ? `
                                <button class="tc-mini" data-asm-invalidate="${it.id}">${_esc(_t('panel.tradecraft.assumptions.btn.invalidate'))}</button>
                                <button class="tc-mini" data-asm-lock="${it.id}" data-current-lock="${it.is_locked ? '1' : '0'}">${it.is_locked ? _esc(_t('panel.tradecraft.assumptions.btn.unlock')) : _esc(_t('panel.tradecraft.assumptions.btn.lock'))}</button>
                                <button class="tc-mini" data-asm-log="${it.id}">${_esc(_t('panel.tradecraft.assumptions.btn.history'))}</button>
                            ` : ''}
                        </div>
                        <div class="tc-asm-log" id="tc-asm-log-${it.id}" style="display:none;"></div>
                    </div>`;
                });
                html += '</div>';
            } else {
                html += '<div class="tc-empty">' + _esc(_t('panel.tradecraft.assumptions.empty')) + '</div>';
            }
            pane.innerHTML = html;

            document.getElementById('tc-asm-form').addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(ev.target);
                _fetchJSON('/api/analyst/assumptions', {
                    method: 'POST',
                    body: {
                        scenario_id: scenarioId,
                        statement: fd.get('statement'),
                        rationale: fd.get('rationale'),
                        confidence: parseFloat(fd.get('confidence')),
                        session_id: _sessionId(),
                    },
                }).then(() => renderAssumptions(scenarioId)).catch(e => alert(e.message));
            });
            pane.querySelectorAll('[data-asm-invalidate]').forEach(b => {
                b.addEventListener('click', () => {
                    const reason = prompt(_t('panel.tradecraft.assumptions.invalidate_prompt'));
                    if (reason === null) return;
                    _fetchJSON(`/api/analyst/assumptions/${b.getAttribute('data-asm-invalidate')}/invalidate`, {
                        method: 'POST', body: { reason, session_id: _sessionId() },
                    }).then(() => renderAssumptions(scenarioId)).catch(e => alert(e.message));
                });
            });
            pane.querySelectorAll('[data-asm-lock]').forEach(b => {
                b.addEventListener('click', () => {
                    const lock = b.getAttribute('data-current-lock') !== '1';
                    _fetchJSON(`/api/analyst/assumptions/${b.getAttribute('data-asm-lock')}/lock`, {
                        method: 'POST', body: { lock },
                    }).then(() => renderAssumptions(scenarioId)).catch(e => alert(e.message));
                });
            });
            pane.querySelectorAll('[data-asm-log]').forEach(b => {
                b.addEventListener('click', () => {
                    const id = b.getAttribute('data-asm-log');
                    const box = document.getElementById('tc-asm-log-' + id);
                    if (box.style.display !== 'none') { box.style.display = 'none'; return; }
                    box.style.display = '';
                    box.innerHTML = '<div class="tc-loading">…</div>';
                    _fetchJSON(`/api/analyst/assumptions/${id}/log`).then(j => {
                        const rows = j.items || [];
                        if (!rows.length) { box.innerHTML = '<div class="tc-empty">—</div>'; return; }
                        box.innerHTML = '<table class="tc-table tc-table-mini"><thead><tr><th>t</th><th>actor</th><th>action</th><th>note</th></tr></thead><tbody>'
                            + rows.map(r => `<tr><td>${_esc(_fmtTs(r.created_at))}</td><td>${_esc(r.actor || '')}</td><td>${_esc(r.action)}</td><td>${_esc(r.note || '')}</td></tr>`).join('')
                            + '</tbody></table>';
                    }).catch(e => { box.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
                });
            });
        }).catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F11 Pre-Mortem ------------------------------------------------------
    function renderPremortem(scenarioId) {
        const pane = document.getElementById('tc-pane-premortem');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/premortem?scenario_id=${encodeURIComponent(scenarioId)}`).then(j => {
            const items = j.items || [];
            let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.premortem.help'))}</div>`;
            html += `<form id="tc-pm-form" class="tc-form">
                <textarea name="failure_mode" rows="2" placeholder="${_esc(_t('panel.tradecraft.premortem.mode_ph'))}" required></textarea>
                <textarea name="early_indicator" rows="2" placeholder="${_esc(_t('panel.tradecraft.premortem.indicator_ph'))}"></textarea>
                <textarea name="mitigation" rows="2" placeholder="${_esc(_t('panel.tradecraft.premortem.mitigation_ph'))}"></textarea>
                <select name="severity">
                    <option value="low">${_esc(_t('panel.tradecraft.premortem.sev_low'))}</option>
                    <option value="medium" selected>${_esc(_t('panel.tradecraft.premortem.sev_med'))}</option>
                    <option value="high">${_esc(_t('panel.tradecraft.premortem.sev_high'))}</option>
                </select>
                <button>${_esc(_t('panel.tradecraft.btn.add'))}</button>
            </form>`;
            if (items.length) {
                html += '<div class="tc-pm-list">';
                items.forEach(it => {
                    html += `<div class="tc-card tc-pm-card tc-sev-${_esc(it.severity)} ${it.resolved_at ? 'tc-card-resolved' : ''}">
                        <div class="tc-card-head">
                            <b>${_esc(it.failure_mode)}</b>
                            <span class="tc-tag tc-sev-tag-${_esc(it.severity)}">${_esc(it.severity)}</span>
                            ${it.resolved_at ? `<span class="tc-tag">${_esc(_t('panel.tradecraft.premortem.resolved'))}</span>` : `<button class="tc-mini" data-pm-resolve="${it.id}">${_esc(_t('panel.tradecraft.btn.resolve'))}</button>`}
                        </div>
                        ${it.early_indicator ? `<div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.premortem.indicator'))}:</b> ${_esc(it.early_indicator)}</div>` : ''}
                        ${it.mitigation ? `<div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.premortem.mitigation'))}:</b> ${_esc(it.mitigation)}</div>` : ''}
                        <div class="tc-card-meta">${_esc(it.author || '?')} · ${_esc(_ago(it.created_at))}</div>
                    </div>`;
                });
                html += '</div>';
            } else {
                html += '<div class="tc-empty">' + _esc(_t('panel.tradecraft.premortem.empty')) + '</div>';
            }
            pane.innerHTML = html;

            document.getElementById('tc-pm-form').addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(ev.target);
                _fetchJSON('/api/analyst/premortem', {
                    method: 'POST',
                    body: {
                        scenario_id: scenarioId,
                        failure_mode: fd.get('failure_mode'),
                        early_indicator: fd.get('early_indicator'),
                        mitigation: fd.get('mitigation'),
                        severity: fd.get('severity'),
                        session_id: _sessionId(),
                    },
                }).then(() => renderPremortem(scenarioId)).catch(e => alert(e.message));
            });
            pane.querySelectorAll('[data-pm-resolve]').forEach(b => {
                b.addEventListener('click', () => {
                    const note = prompt(_t('panel.tradecraft.premortem.resolve_prompt')) || '';
                    _fetchJSON(`/api/analyst/premortem/${b.getAttribute('data-pm-resolve')}/resolve`, {
                        method: 'POST', body: { resolution_note: note },
                    }).then(() => renderPremortem(scenarioId)).catch(e => alert(e.message));
                });
            });
        }).catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F14 Decision Ledger -------------------------------------------------
    function renderDecisions(scenarioId) {
        const pane = document.getElementById('tc-pane-decisions');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/decisions?scenario_id=${encodeURIComponent(scenarioId)}&limit=200`).then(j => {
            const items = j.items || [];
            let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.decisions.help'))}</div>`;
            html += `<form id="tc-dec-form" class="tc-form">
                <select name="decision_type">
                    <option value="threshold_change">${_esc(_t('panel.tradecraft.decisions.type.threshold'))}</option>
                    <option value="weight_override">${_esc(_t('panel.tradecraft.decisions.type.weight'))}</option>
                    <option value="signal_classify">${_esc(_t('panel.tradecraft.decisions.type.classify'))}</option>
                    <option value="intel_action">${_esc(_t('panel.tradecraft.decisions.type.intel'))}</option>
                    <option value="report_publish">${_esc(_t('panel.tradecraft.decisions.type.report'))}</option>
                    <option value="other" selected>${_esc(_t('panel.tradecraft.decisions.type.other'))}</option>
                </select>
                <textarea name="summary" rows="2" placeholder="${_esc(_t('panel.tradecraft.decisions.sum_ph'))}" required></textarea>
                <textarea name="rationale" rows="2" placeholder="${_esc(_t('panel.tradecraft.decisions.rat_ph'))}"></textarea>
                <button>${_esc(_t('panel.tradecraft.btn.log'))}</button>
            </form>`;
            if (items.length) {
                html += '<table class="tc-table"><thead><tr>'
                    + `<th>${_esc(_t('panel.tradecraft.col.time'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.actor'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.type'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.summary'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.session'))}</th>`
                    + '</tr></thead><tbody>';
                items.forEach(it => {
                    html += '<tr>'
                        + `<td title="${_esc(_fmtTs(it.created_at))}">${_esc(_ago(it.created_at))}</td>`
                        + `<td>${_esc(it.actor || '')}</td>`
                        + `<td>${_esc(it.decision_type)}</td>`
                        + `<td>${_esc(it.summary)}${it.rationale ? `<div class="tc-mini-meta">${_esc(it.rationale)}</div>` : ''}</td>`
                        + `<td class="tc-mini">${_esc((it.session_id || '').slice(0, 8))}</td>`
                        + '</tr>';
                });
                html += '</tbody></table>';
            } else {
                html += '<div class="tc-empty">' + _esc(_t('panel.tradecraft.decisions.empty')) + '</div>';
            }
            pane.innerHTML = html;

            document.getElementById('tc-dec-form').addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(ev.target);
                _fetchJSON('/api/analyst/decisions', {
                    method: 'POST',
                    body: {
                        scenario_id: scenarioId,
                        decision_type: fd.get('decision_type'),
                        summary: fd.get('summary'),
                        rationale: fd.get('rationale'),
                        session_id: _sessionId(),
                    },
                }).then(() => renderDecisions(scenarioId)).catch(e => alert(e.message));
            });
        }).catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F9 What-If Weight Slider --------------------------------------------
    function renderWhatIf(scenarioId) {
        const pane = document.getElementById('tc-pane-whatif');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        const sc = STATE.scenarios.find(s => s.id === scenarioId);
        if (!sc) { pane.innerHTML = '<div class="tc-empty">—</div>'; return; }

        // Fetch full scenario detail (participants + weights) via /api/scenarios?id=
        _fetchJSON('/api/scenarios').then(j => {
            const full = (j.scenarios || []).find(s => s.id === scenarioId);
            const participants = (full && full.participants) || [];
            STATE.whatifWeights[scenarioId] = STATE.whatifWeights[scenarioId] || {};
            const overrides = STATE.whatifWeights[scenarioId];

            let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.whatif.help'))}</div>`;
            html += '<div class="tc-whatif-grid">';
            participants.forEach(p => {
                const cur = overrides[p.country] != null ? overrides[p.country] : (p.weight || 1.0);
                html += `<div class="tc-wif-row">
                    <div class="tc-wif-label">${_esc(p.country)} <span class="tc-mini-meta">${_esc(p.role || '')}</span></div>
                    <input type="range" min="0" max="2" step="0.05" value="${cur}" data-wif-country="${_esc(p.country)}" />
                    <div class="tc-wif-val" id="tc-wif-val-${_esc(p.country)}">${cur.toFixed(2)}</div>
                    <div class="tc-mini-meta">base: ${(p.weight || 1.0).toFixed(2)}</div>
                </div>`;
            });
            html += '</div>';
            html += `<div class="tc-wif-actions">
                <button id="tc-wif-run" class="tc-btn-primary">${_esc(_t('panel.tradecraft.whatif.run'))}</button>
                <button id="tc-wif-reset">${_esc(_t('panel.tradecraft.whatif.reset'))}</button>
            </div>`;
            html += '<div id="tc-wif-result" style="margin-top:10px;"></div>';
            pane.innerHTML = html;

            pane.querySelectorAll('[data-wif-country]').forEach(slider => {
                slider.addEventListener('input', () => {
                    const c = slider.getAttribute('data-wif-country');
                    const v = parseFloat(slider.value);
                    overrides[c] = v;
                    const lab = document.getElementById('tc-wif-val-' + c);
                    if (lab) lab.textContent = v.toFixed(2);
                });
            });
            document.getElementById('tc-wif-reset').addEventListener('click', () => {
                STATE.whatifWeights[scenarioId] = {};
                renderWhatIf(scenarioId);
            });
            document.getElementById('tc-wif-run').addEventListener('click', () => {
                const target = document.getElementById('tc-wif-result');
                target.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
                _fetchJSON(`/api/scenarios/${encodeURIComponent(scenarioId)}/whatif_weights`, {
                    method: 'POST',
                    body: {
                        weight_overrides: overrides,
                        session_id: _sessionId(),
                    },
                }).then(r => {
                    const base = r.baseline || {};
                    const sim = r.simulated || {};
                    const dScore = (sim.score || 0) - (base.score || 0);
                    const dTL = (sim.tl != null && base.tl != null) ? (sim.tl - base.tl) : 0;
                    target.innerHTML = `
                        <table class="tc-table">
                            <thead><tr><th>—</th><th>${_esc(_t('panel.tradecraft.whatif.base'))}</th><th>${_esc(_t('panel.tradecraft.whatif.sim'))}</th><th>Δ</th></tr></thead>
                            <tbody>
                                <tr><td>TL</td><td>TL${base.tl}</td><td>TL${sim.tl}</td><td class="${dTL < 0 ? 'tc-up' : (dTL > 0 ? 'tc-down' : '')}">${dTL > 0 ? '+' : ''}${dTL}</td></tr>
                                <tr><td>${_esc(_t('panel.tradecraft.col.score'))}</td><td>${(base.score || 0).toFixed(2)}</td><td>${(sim.score || 0).toFixed(2)}</td><td class="${dScore > 0 ? 'tc-up' : (dScore < 0 ? 'tc-down' : '')}">${dScore > 0 ? '+' : ''}${dScore.toFixed(2)}</td></tr>
                            </tbody>
                        </table>
                        <div class="tc-mini-meta">${_esc(_t('panel.tradecraft.whatif.snapshot_age'))}: ${_esc(_ago(r.snapshot_ts))}</div>
                    `;
                }).catch(e => { target.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
            });
        }).catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // ── Public API ─────────────────────────────────────────────────────────
    function toggleTradecraftPanel() {
        const p = document.getElementById('tradecraft-panel');
        if (!p) return;
        if (p.style.display === 'none' || !p.style.display) {
            if (!p.classList.contains('docked') && p.parentElement !== document.body) document.body.appendChild(p);
            p.style.display = 'flex';
            p.classList.add('floating', 'active');
            setTimeout(() => p.classList.remove('active'), 1000);
            if (typeof window.updateSidebarVisibility === 'function') window.updateSidebarVisibility();
            if (typeof window.syncToolsMenuState === 'function') window.syncToolsMenuState();
            if (typeof window.saveLocalState === 'function') window.saveLocalState();
            if (STATE.scenarioId) renderActiveTab();
        } else {
            p.style.display = 'none';
            if (typeof window.updateSidebarVisibility === 'function') window.updateSidebarVisibility();
            if (typeof window.syncToolsMenuState === 'function') window.syncToolsMenuState();
            if (typeof window.saveLocalState === 'function') window.saveLocalState();
        }
    }

    window.toggleTradecraftPanel = toggleTradecraftPanel;
    window._tradecraftSessionId = _sessionId;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
