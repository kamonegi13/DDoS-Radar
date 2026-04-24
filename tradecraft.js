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
            // Backend returns scenarios as a dict keyed by id; normalize to array.
            const raw = (j && j.scenarios) || {};
            const list = Array.isArray(raw)
                ? raw
                : Object.entries(raw).map(([id, s]) => ({
                    id, name: s.name_en || s.name_ja || id, ...s,
                }));
            STATE.scenarios = list;
            sel.innerHTML = list.map(s =>
                `<option value="${_esc(s.id)}">${_esc(s.name_en || s.name || s.id)}</option>`
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
        _fetchJSON(`/api/analyst/disconf?scenario_id=${encodeURIComponent(scenarioId)}&include_retracted=1`)
            .then(j => {
                const items = j.items || [];
                let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.disconf.help'))}</div>`;
                html += `<form id="tc-disconf-form" class="tc-form">
                    <textarea name="summary" rows="2" placeholder="${_esc(_t('panel.tradecraft.disconf.summary_ph'))}" required></textarea>
                    <select name="source_kind">
                        <option value="manual_note" selected>${_esc(_t('panel.tradecraft.disconf.kind_note'))}</option>
                        <option value="intel_item">${_esc(_t('panel.tradecraft.disconf.kind_intel'))}</option>
                        <option value="rationale">${_esc(_t('panel.tradecraft.disconf.kind_rationale'))}</option>
                    </select>
                    <input name="source_ref" placeholder="${_esc(_t('panel.tradecraft.disconf.sref_ph'))}" />
                    <select name="strength">
                        <option value="1">${_esc(_t('panel.tradecraft.disconf.strength_1'))}</option>
                        <option value="2" selected>${_esc(_t('panel.tradecraft.disconf.strength_2'))}</option>
                        <option value="3">${_esc(_t('panel.tradecraft.disconf.strength_3'))}</option>
                        <option value="4">${_esc(_t('panel.tradecraft.disconf.strength_4'))}</option>
                        <option value="5">${_esc(_t('panel.tradecraft.disconf.strength_5'))}</option>
                    </select>
                    <button type="submit">${_esc(_t('panel.tradecraft.btn.add'))}</button>
                </form>`;
                if (items.length) {
                    html += '<table class="tc-table"><thead><tr>'
                        + `<th>${_esc(_t('panel.tradecraft.col.time'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.summary'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.source_kind'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.strength'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.author'))}</th>`
                        + `<th>${_esc(_t('panel.tradecraft.col.actions'))}</th>`
                        + '</tr></thead><tbody>';
                    items.forEach(it => {
                        const retracted = !!it.retracted_at;
                        const sref = it.source_ref || '';
                        const srefDisplay = /^https?:\/\//i.test(sref)
                            ? ` <a href="${_esc(sref)}" target="_blank" rel="noopener">↗</a>`
                            : (sref ? ` <span class="tc-mini-meta">${_esc(sref)}</span>` : '');
                        html += `<tr class="${retracted ? 'tc-row-retracted' : ''}">`
                            + `<td title="${_esc(_fmtTs(it.tagged_at))}">${_esc(_ago(it.tagged_at))}</td>`
                            + `<td>${_esc(it.summary || '')}</td>`
                            + `<td>${_esc(it.source_kind || '')}${srefDisplay}</td>`
                            + `<td>${_esc(it.strength)}</td>`
                            + `<td>${_esc(it.tagged_by || '')}</td>`
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
                                summary: fd.get('summary'),
                                source_kind: fd.get('source_kind'),
                                source_ref: fd.get('source_ref') || null,
                                strength: parseInt(fd.get('strength'), 10),
                                session_id: _sessionId(),
                            },
                        }).then(() => renderDisconf(scenarioId))
                          .catch(e => alert(e.message));
                    });
                }
                pane.querySelectorAll('[data-disconf-retract]').forEach(btn => {
                    btn.addEventListener('click', () => {
                        const id = btn.getAttribute('data-disconf-retract');
                        _fetchJSON(`/api/analyst/disconf/${encodeURIComponent(id)}/retract`, {
                            method: 'POST',
                            body: { session_id: _sessionId() },
                        })
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
            const label = s.name_en || s.name || s.id;
            html += `<label class="tc-chk"><input type="checkbox" data-compare-id="${_esc(s.id)}" ${checked}/> ${_esc(label)}</label>`;
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
                let h = `<div class="tc-mini-meta">${_esc(_t('panel.tradecraft.compare.as_focused'))}</div>`;
                h += '<table class="tc-table"><thead><tr>'
                    + `<th>${_esc(_t('panel.tradecraft.col.scenario'))}</th>`
                    + '<th>TL</th>'
                    + `<th>${_esc(_t('panel.tradecraft.col.score'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.cyber'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.physical'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.info'))}</th>`
                    + `<th>${_esc(_t('panel.tradecraft.col.signals'))}</th>`
                    + '</tr></thead><tbody>';
                rows.forEach(r => {
                    // Backend returns both lite and full ScenarioState; show full (as-if-focused).
                    if (r.error) {
                        h += `<tr><td><b>${_esc(r.scenario_id)}</b></td><td colspan="6" class="tc-error">${_esc(r.error)}</td></tr>`;
                        return;
                    }
                    const full = r.full || {};
                    const tl = full.tl != null ? full.tl : '—';
                    const domains = full.domains || {};
                    const contribs = full.contributions || [];
                    const name = r.name_en || r.scenario_id;
                    h += '<tr>'
                        + `<td><b>${_esc(name)}</b></td>`
                        + `<td><span class="tc-tl tc-tl-${_esc(tl)}">TL${_esc(tl)}</span></td>`
                        + `<td>${_esc((full.score || 0).toFixed(2))}</td>`
                        + `<td>${_esc((domains.cyber || 0).toFixed(2))}</td>`
                        + `<td>${_esc((domains.physical || 0).toFixed(2))}</td>`
                        + `<td>${_esc((domains.info || 0).toFixed(2))}</td>`
                        + `<td>${_esc(contribs.length)}</td>`
                        + '</tr>';
                });
                h += '</tbody></table>';
                if (j.snapshot_age_sec != null) {
                    h += `<div class="tc-mini-meta">${_esc(_t('panel.tradecraft.whatif.snapshot_age'))}: ${_esc(j.snapshot_age_sec)}s</div>`;
                }
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
            (m.scores || []).forEach(s => { scores[s.evidence_id + ':' + s.hypothesis_id] = s.consistency; });

            let h = `<div class="tc-ach-controls">
                <form class="tc-form-inline" id="tc-ach-add-hyp">
                    <input name="text" placeholder="${_esc(_t('panel.tradecraft.ach.hyp_ph'))}" required/>
                    <label class="tc-chk"><input type="checkbox" name="is_null"/> ${_esc(_t('panel.tradecraft.ach.null_hyp'))}</label>
                    <button>${_esc(_t('panel.tradecraft.btn.add_hyp'))}</button>
                </form>
                <form class="tc-form-inline" id="tc-ach-add-ev">
                    <input name="text" placeholder="${_esc(_t('panel.tradecraft.ach.ev_ph'))}" required/>
                    <input name="source_ref" placeholder="${_esc(_t('panel.tradecraft.ach.sref_ph'))}" />
                    <select name="credibility" title="${_esc(_t('panel.tradecraft.ach.credibility'))}">
                        <option value="1">Cred 1</option>
                        <option value="2">Cred 2</option>
                        <option value="3" selected>Cred 3</option>
                        <option value="4">Cred 4</option>
                        <option value="5">Cred 5</option>
                    </select>
                    <select name="relevance" title="${_esc(_t('panel.tradecraft.ach.relevance'))}">
                        <option value="1">Rel 1</option>
                        <option value="2">Rel 2</option>
                        <option value="3" selected>Rel 3</option>
                        <option value="4">Rel 4</option>
                        <option value="5">Rel 5</option>
                    </select>
                    <button>${_esc(_t('panel.tradecraft.btn.add_ev'))}</button>
                </form>
            </div>`;

            if (!hyps.length || !evs.length) {
                h += `<div class="tc-empty">${_esc(_t('panel.tradecraft.ach.need_both'))}</div>`;
            } else {
                h += '<table class="tc-ach-matrix"><thead><tr><th></th>';
                hyps.forEach(hp => {
                    const nullMark = hp.is_null_hypothesis ? ' ∅' : '';
                    h += `<th>${_esc(hp.text)}${nullMark}</th>`;
                });
                h += `<th class="tc-mini" title="${_esc(_t('panel.tradecraft.ach.cred_rel'))}">C·R</th></tr></thead><tbody>`;
                // Tally = sum(consistency) weighted by credibility*relevance/25 (max product = 25).
                const tally = hyps.map(() => 0);
                evs.forEach(ev => {
                    const diagWeight = ((ev.credibility || 3) * (ev.relevance || 3)) / 25;
                    h += `<tr><td class="tc-ach-evcell">${_esc(ev.text)}${ev.source_ref ? ` <span class="tc-mini-meta">(${_esc(ev.source_ref)})</span>` : ''}</td>`;
                    hyps.forEach((hp, hi) => {
                        const k = ev.id + ':' + hp.id;
                        const sc = scores[k];
                        const cls = sc == null ? '' : (sc < 0 ? 'tc-ach-neg' : sc > 0 ? 'tc-ach-pos' : 'tc-ach-zero');
                        if (sc != null) tally[hi] += sc * diagWeight;
                        h += `<td class="${cls}"><select data-ach-score data-ev="${ev.id}" data-hp="${hp.id}">
                            <option value="">·</option>
                            <option value="-2" ${sc === -2 ? 'selected' : ''}>−−</option>
                            <option value="-1" ${sc === -1 ? 'selected' : ''}>−</option>
                            <option value="0" ${sc === 0 ? 'selected' : ''}>0</option>
                            <option value="1" ${sc === 1 ? 'selected' : ''}>+</option>
                            <option value="2" ${sc === 2 ? 'selected' : ''}>++</option>
                        </select></td>`;
                    });
                    h += `<td class="tc-mini">${_esc(ev.credibility)}·${_esc(ev.relevance)}</td></tr>`;
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
                    method: 'POST',
                    body: {
                        text: fd.get('text'),
                        is_null_hypothesis: fd.get('is_null') === 'on',
                        session_id: _sessionId(),
                    },
                }).then(renderAchDetail).catch(e => alert(e.message));
            });
            const ef = document.getElementById('tc-ach-add-ev');
            if (ef) ef.addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(ef);
                _fetchJSON(`/api/analyst/ach/${STATE.achMatrixId}/evidence`, {
                    method: 'POST',
                    body: {
                        text: fd.get('text'),
                        source_ref: fd.get('source_ref') || null,
                        credibility: parseInt(fd.get('credibility'), 10),
                        relevance: parseInt(fd.get('relevance'), 10),
                        session_id: _sessionId(),
                    },
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
                            consistency: parseInt(v, 10),
                            session_id: _sessionId(),
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
                <input name="title" type="text" placeholder="${_esc(_t('panel.tradecraft.dissent.title_ph'))}" required />
                <textarea name="body" rows="4" placeholder="${_esc(_t('panel.tradecraft.dissent.body_ph'))}" required></textarea>
                <select name="argues_for_tl">
                    <option value="">${_esc(_t('panel.tradecraft.dissent.tl_none'))}</option>
                    <option value="1">TL1</option><option value="2">TL2</option><option value="3">TL3</option>
                    <option value="4">TL4</option><option value="5">TL5</option>
                </select>
                <button>${_esc(_t('panel.tradecraft.btn.add'))}</button>
            </form>`;
            if (items.length) {
                html += '<div class="tc-dissent-list">';
                items.forEach(it => {
                    const tlPill = (it.argues_for_tl != null) ? `<span class="tc-tl tc-tl-${_esc(it.argues_for_tl)}">TL${_esc(it.argues_for_tl)}</span>` : '';
                    html += `<div class="tc-card ${it.resolved_at ? 'tc-card-resolved' : ''}">
                        <div class="tc-card-head"><b>${_esc(it.title)}</b> ${tlPill}
                            ${it.resolved_at ? `<span class="tc-tag">${_esc(_t('panel.tradecraft.dissent.resolved'))}</span>` : `<button class="tc-mini" data-dissent-resolve="${it.id}">${_esc(_t('panel.tradecraft.btn.resolve'))}</button>`}
                        </div>
                        <div class="tc-card-body">${_esc(it.body)}</div>
                        <div class="tc-card-meta">${_esc(it.created_by || '?')} · ${_esc(_ago(it.created_at))}</div>
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
                const argues = fd.get('argues_for_tl');
                _fetchJSON('/api/analyst/dissent', {
                    method: 'POST',
                    body: {
                        scenario_id: scenarioId,
                        title: fd.get('title'),
                        body: fd.get('body'),
                        argues_for_tl: argues ? parseInt(argues, 10) : null,
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
                    <option value="low">${_esc(_t('panel.tradecraft.assumptions.conf_low'))}</option>
                    <option value="medium" selected>${_esc(_t('panel.tradecraft.assumptions.conf_med'))}</option>
                    <option value="high">${_esc(_t('panel.tradecraft.assumptions.conf_high'))}</option>
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
                        <div class="tc-card-meta">${_esc(it.created_by || '?')} · ${_esc(_ago(it.created_at))}</div>
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
                        confidence: fd.get('confidence'),
                        session_id: _sessionId(),
                    },
                }).then(() => renderAssumptions(scenarioId)).catch(e => alert(e.message));
            });
            pane.querySelectorAll('[data-asm-invalidate]').forEach(b => {
                b.addEventListener('click', () => {
                    const reason = prompt(_t('panel.tradecraft.assumptions.invalidate_prompt'));
                    if (reason === null) return;
                    _fetchJSON(`/api/analyst/assumptions/${b.getAttribute('data-asm-invalidate')}/invalidate`, {
                        method: 'POST', body: { note: reason, session_id: _sessionId() },
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
                        const rows = j.entries || [];
                        if (!rows.length) { box.innerHTML = '<div class="tc-empty">—</div>'; return; }
                        box.innerHTML = '<table class="tc-table tc-table-mini"><thead><tr><th>t</th><th>actor</th><th>action</th><th>note</th></tr></thead><tbody>'
                            + rows.map(r => `<tr><td>${_esc(_fmtTs(r.changed_at))}</td><td>${_esc(r.changed_by || '')}</td><td>${_esc(r.change_type)}</td><td>${_esc(r.note || '')}</td></tr>`).join('')
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
                <select name="failure_mode" required>
                    <option value="false_positive">${_esc(_t('panel.tradecraft.premortem.mode_fp'))}</option>
                    <option value="false_negative">${_esc(_t('panel.tradecraft.premortem.mode_fn'))}</option>
                    <option value="cognitive_bias">${_esc(_t('panel.tradecraft.premortem.mode_bias'))}</option>
                </select>
                <textarea name="imagined_outcome" rows="2" placeholder="${_esc(_t('panel.tradecraft.premortem.imagined_ph'))}" required></textarea>
                <textarea name="root_cause" rows="2" placeholder="${_esc(_t('panel.tradecraft.premortem.rootcause_ph'))}" required></textarea>
                <textarea name="early_warning" rows="2" placeholder="${_esc(_t('panel.tradecraft.premortem.warning_ph'))}"></textarea>
                <textarea name="mitigation" rows="2" placeholder="${_esc(_t('panel.tradecraft.premortem.mitigation_ph'))}"></textarea>
                <button>${_esc(_t('panel.tradecraft.btn.add'))}</button>
            </form>`;
            if (items.length) {
                html += '<div class="tc-pm-list">';
                items.forEach(it => {
                    const modeLabel = _t('panel.tradecraft.premortem.mode_' + (
                        it.failure_mode === 'false_positive' ? 'fp' :
                        it.failure_mode === 'false_negative' ? 'fn' :
                        it.failure_mode === 'cognitive_bias' ? 'bias' : 'unknown'));
                    const modeClass = it.failure_mode === 'false_positive' ? 'high'
                                    : it.failure_mode === 'false_negative' ? 'medium'
                                    : 'low';
                    html += `<div class="tc-card tc-pm-card tc-sev-${modeClass} ${it.resolved_at ? 'tc-card-resolved' : ''}">
                        <div class="tc-card-head">
                            <span class="tc-tag tc-sev-tag-${modeClass}">${_esc(modeLabel)}</span>
                            ${it.resolved_at ? `<span class="tc-tag">${_esc(_t('panel.tradecraft.premortem.resolved'))}</span>` : `<button class="tc-mini" data-pm-resolve="${it.id}">${_esc(_t('panel.tradecraft.btn.resolve'))}</button>`}
                        </div>
                        <div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.premortem.imagined'))}:</b> ${_esc(it.imagined_outcome)}</div>
                        <div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.premortem.rootcause'))}:</b> ${_esc(it.root_cause)}</div>
                        ${it.early_warning ? `<div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.premortem.warning'))}:</b> ${_esc(it.early_warning)}</div>` : ''}
                        ${it.mitigation ? `<div class="tc-card-body"><b>${_esc(_t('panel.tradecraft.premortem.mitigation'))}:</b> ${_esc(it.mitigation)}</div>` : ''}
                        <div class="tc-card-meta">${_esc(it.created_by || '?')} · ${_esc(_ago(it.created_at))}</div>
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
                        imagined_outcome: fd.get('imagined_outcome'),
                        root_cause: fd.get('root_cause'),
                        early_warning: fd.get('early_warning'),
                        mitigation: fd.get('mitigation'),
                        session_id: _sessionId(),
                    },
                }).then(() => renderPremortem(scenarioId)).catch(e => alert(e.message));
            });
            pane.querySelectorAll('[data-pm-resolve]').forEach(b => {
                b.addEventListener('click', () => {
                    if (!confirm(_t('panel.tradecraft.premortem.resolve_confirm'))) return;
                    _fetchJSON(`/api/analyst/premortem/${b.getAttribute('data-pm-resolve')}/resolve`, {
                        method: 'POST', body: { session_id: _sessionId() },
                    }).then(() => renderPremortem(scenarioId)).catch(e => alert(e.message));
                });
            });
        }).catch(e => { pane.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
    }

    // F14 Decision Ledger -------------------------------------------------
    // Auto-logged entries (from F6/F8/F10/F11/F13 write-through) carry
    // detail.auto === true. Operators can toggle them in/out of view.
    let _decShowAuto = true;

    function _isAutoEntry(it) {
        const d = it && it.detail;
        return !!(d && d.auto === true);
    }

    function renderDecisions(scenarioId) {
        const pane = document.getElementById('tc-pane-decisions');
        pane.innerHTML = '<div class="tc-loading">' + _esc(_t('panel.tradecraft.loading')) + '</div>';
        _fetchJSON(`/api/analyst/decisions?scenario_id=${encodeURIComponent(scenarioId)}&limit=200`).then(j => {
            const allItems = j.items || [];
            const autoCount = allItems.filter(_isAutoEntry).length;
            const items = _decShowAuto ? allItems : allItems.filter(it => !_isAutoEntry(it));

            let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.decisions.help'))}</div>`;
            html += `<label class="tc-filter-toggle">
                <input type="checkbox" id="tc-dec-show-auto"${_decShowAuto ? ' checked' : ''}>
                <span>${_esc(_t('panel.tradecraft.decisions.show_auto'))} <span class="tc-mini">(${autoCount})</span></span>
            </label>`;
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
                    const detail = it.detail || {};
                    const rationale = detail.rationale || '';
                    const auto = _isAutoEntry(it);
                    const rowCls = auto ? ' class="tc-row-auto"' : '';
                    const badge = auto ? ` <span class="tc-badge-auto" title="${_esc(_t('panel.tradecraft.decisions.auto_tip'))}">${_esc(_t('panel.tradecraft.decisions.auto_tag'))}</span>` : '';
                    const ts = it.logged_at != null ? it.logged_at : it.created_at;
                    html += `<tr${rowCls}>`
                        + `<td title="${_esc(_fmtTs(ts))}">${_esc(_ago(ts))}</td>`
                        + `<td>${_esc(it.username || '')}</td>`
                        + `<td>${_esc(it.decision_type)}${badge}</td>`
                        + `<td>${_esc(it.summary)}${rationale ? `<div class="tc-mini-meta">${_esc(rationale)}</div>` : ''}</td>`
                        + `<td class="tc-mini">${_esc((it.session_id || '').slice(0, 12))}</td>`
                        + '</tr>';
                });
                html += '</tbody></table>';
            } else {
                html += '<div class="tc-empty">' + _esc(_t('panel.tradecraft.decisions.empty')) + '</div>';
            }
            pane.innerHTML = html;

            const toggle = document.getElementById('tc-dec-show-auto');
            if (toggle) {
                toggle.addEventListener('change', () => {
                    _decShowAuto = toggle.checked;
                    renderDecisions(scenarioId);
                });
            }
            document.getElementById('tc-dec-form').addEventListener('submit', ev => {
                ev.preventDefault();
                const fd = new FormData(ev.target);
                const rationale = (fd.get('rationale') || '').trim();
                _fetchJSON('/api/analyst/decisions', {
                    method: 'POST',
                    body: {
                        scenario_id: scenarioId,
                        decision_type: fd.get('decision_type'),
                        summary: fd.get('summary'),
                        detail: rationale ? { rationale } : {},
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
        const sc = (STATE.scenarios || []).find(s => s.id === scenarioId);
        if (!sc) { pane.innerHTML = '<div class="tc-empty">—</div>'; return; }

        // participants is a dict keyed by country code; normalize to array.
        const participantsDict = sc.participants || {};
        const participants = Object.entries(participantsDict).map(([cc, p]) => ({
            country: cc,
            weight: (p && p.weight != null) ? p.weight : 1.0,
            role: (p && p.role) || '',
        }));
        STATE.whatifWeights[scenarioId] = STATE.whatifWeights[scenarioId] || {};
        const overrides = STATE.whatifWeights[scenarioId];

        let html = `<div class="tc-help">${_esc(_t('panel.tradecraft.whatif.help'))}</div>`;
        html += '<div class="tc-whatif-grid">';
        participants.forEach(p => {
            const cur = overrides[p.country] != null ? overrides[p.country] : p.weight;
            html += `<div class="tc-wif-row">
                <div class="tc-wif-label">${_esc(p.country)} <span class="tc-mini-meta">${_esc(p.role)}</span></div>
                <input type="range" min="0" max="1" step="0.05" value="${cur}" data-wif-country="${_esc(p.country)}" />
                <div class="tc-wif-val" id="tc-wif-val-${_esc(p.country)}">${cur.toFixed(2)}</div>
                <div class="tc-mini-meta">base: ${p.weight.toFixed(2)}</div>
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
                    weights: overrides,
                    session_id: _sessionId(),
                },
            }).then(r => {
                // Backend returns a flat ScenarioState dict with baseline_* fields.
                const baseTl = r.baseline_tl;
                const baseScore = r.baseline_score || 0;
                const simTl = r.tl;
                const simScore = r.score || 0;
                const dScore = (r.delta_score != null) ? r.delta_score : (simScore - baseScore);
                const dTL = (simTl != null && baseTl != null) ? (simTl - baseTl) : 0;
                const ageSec = (r.snapshot_age_sec != null) ? Math.round(r.snapshot_age_sec) : null;
                target.innerHTML = `
                    <table class="tc-table">
                        <thead><tr><th>—</th><th>${_esc(_t('panel.tradecraft.whatif.base'))}</th><th>${_esc(_t('panel.tradecraft.whatif.sim'))}</th><th>Δ</th></tr></thead>
                        <tbody>
                            <tr><td>TL</td><td>TL${baseTl != null ? baseTl : '—'}</td><td>TL${simTl != null ? simTl : '—'}</td><td class="${dTL < 0 ? 'tc-up' : (dTL > 0 ? 'tc-down' : '')}">${dTL > 0 ? '+' : ''}${dTL}</td></tr>
                            <tr><td>${_esc(_t('panel.tradecraft.col.score'))}</td><td>${baseScore.toFixed(2)}</td><td>${simScore.toFixed(2)}</td><td class="${dScore > 0 ? 'tc-up' : (dScore < 0 ? 'tc-down' : '')}">${dScore > 0 ? '+' : ''}${dScore.toFixed(2)}</td></tr>
                        </tbody>
                    </table>
                    ${ageSec != null ? `<div class="tc-mini-meta">${_esc(_t('panel.tradecraft.whatif.snapshot_age'))}: ${ageSec}s</div>` : ''}
                `;
            }).catch(e => { target.innerHTML = `<div class="tc-error">${_esc(e.message)}</div>`; });
        });
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
