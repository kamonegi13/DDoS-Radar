/**
 * LLM Feature Hub UI (commit J).
 *
 * Wires the #llm-features-modal markup to the /api/v2/llm_features
 * endpoints. Five exported window hooks:
 *
 *   _llmFeaturesOpen()      — load + render, then show modal
 *   _llmFeaturesClose()
 *   _llmFeaturesSet(key, state)        — POST /<key>/set
 *   _llmFeaturesClear(key)             — POST /<key>/clear
 *   _llmFeaturesKillSwitch(state)      — POST /kill_switch
 *
 * Plus an automatic HUD chip refresh that polls /api/v2/llm_features
 * every 60s and reflects how many features are active vs shadow vs
 * off (kill switch turns the chip red).
 */
(function () {
    'use strict';

    const TIER_ORDER = ['core', 'augment', 'narrative', 'discovery'];
    const TIER_LABELS = {
        core:      'Tier 0: Core（常時稼働、kill switch でのみ停止）',
        augment:   'Tier 1: 判断補助（アナリストレビュー対象）',
        narrative: 'Tier 2: 説明生成（表示のみ、低リスク）',
        discovery: 'Tier 3: Discovery（NP7 — アナリスト確認が必要）',
    };

    let _historyOpen = false;

    // ── Public entry points ─────────────────────────────────────────────

    // Phase 9.4 C16 — redirect to the unified Settings shell. The legacy
    // #llm-features-modal markup remains as a fallback (escape hatch
    // for ops scripts that pin to it) but new callers land in the shell.
    window._llmFeaturesOpen = async function () {
        if (typeof window._settingsOpen === 'function') {
            return window._settingsOpen('llm.features');
        }
        if (typeof openModal === 'function') openModal('llm-features-modal');
        await refresh();
    };
    window._llmFeaturesOpenLegacy = async function () {
        if (typeof openModal === 'function') openModal('llm-features-modal');
        await refresh();
    };

    window._llmFeaturesClose = function () {
        if (typeof closeAllModals === 'function') closeAllModals();
    };

    window._llmFeaturesSet = async function (key, state) {
        let reason = '';
        // For NP7 features (g3b_cluster_annotator etc.), require a confirmation
        // step that captures the reason.
        const meta = _featureMetaCache.get(key);
        if (meta && meta.np7_concern && state !== 'off') {
            const ok = window.confirm(
                'NP7 — この機能はシナリオ構造の提案に影響します。\n\n'
                + '状態を「' + state + '」に設定すると、LLM が discovery '
                + 'アノテーションを生成するようになります。\n\n'
                + '有効化してよろしいですか？'
            );
            if (!ok) return;
            reason = window.prompt(
                '任意: 変更理由を短く入力してください（監査経路に記録）',
                ''
            ) || '';
        }
        await postJson(
            '/api/v2/llm_features/' + encodeURIComponent(key) + '/set',
            { state: state, reason: reason || undefined }
        );
        await refresh();
    };

    window._llmFeaturesClear = async function (key) {
        await postJson(
            '/api/v2/llm_features/' + encodeURIComponent(key) + '/clear',
            {}
        );
        await refresh();
    };

    window._llmFeaturesKillSwitch = async function (state) {
        if (state === 'on') {
            const ok = window.confirm(
                '⚠ KILL SWITCH ⚠\n\n'
                + '作動させると、センサーのインテル抽出を含む LLM 駆動機能を'
                + 'すべて無効化します。kill switch を解除するまで、'
                + '新規インテルの取り込みは停止します。\n\n'
                + '作動させてよろしいですか？'
            );
            if (!ok) return;
        }
        await postJson(
            '/api/v2/llm_features/kill_switch',
            { state: state }
        );
        await refresh();
    };

    window._llmFeaturesToggleHistory = async function () {
        _historyOpen = !_historyOpen;
        const el = document.getElementById('lfh-history');
        if (el) el.style.display = _historyOpen ? 'block' : 'none';
        const chev = document.getElementById('lfh-history-chev');
        if (chev) chev.classList.toggle('open', _historyOpen);
        if (_historyOpen) await refreshHistory();
    };

    // ── Internals ───────────────────────────────────────────────────────

    const _featureMetaCache = new Map();

    async function refresh() {
        try {
            const resp = await fetch('/api/v2/llm_features');
            if (!resp.ok) return;
            const body = await resp.json();
            const features = (body && body.data) || [];
            renderFeatures(features);
            updateChip(features);
            // Cache metadata for the confirm-flow
            _featureMetaCache.clear();
            features.forEach(f => _featureMetaCache.set(f.key, f));
        } catch (err) {
            console.debug('[lfh] refresh failed:', err);
        }
    }

    function renderFeatures(features) {
        const body = document.getElementById('llm-features-body');
        if (!body) return;
        const killActive = features.length > 0 && features[0].kill_switch_active;

        const grouped = new Map(TIER_ORDER.map(t => [t, []]));
        features.forEach(f => {
            (grouped.get(f.tier) || grouped.get('augment')).push(f);
        });

        let html = '';

        // Kill switch panel
        html += '<div class="lfh-kill ' + (killActive ? 'engaged' : '') + '">'
            + '<span class="lfh-kill-icon">🔴</span>'
            + '<span class="lfh-kill-label">'
            + (killActive
                ? 'KILL SWITCH 作動中 — LLM 機能はすべて OFF'
                : 'Kill switch（LLM 機能を一括停止）')
            + '</span>'
            + '<button class="lfh-btn lfh-btn-' + (killActive ? 'release' : 'kill') + '"'
            + ' onclick="window._llmFeaturesKillSwitch(\''
            + (killActive ? 'off' : 'on') + '\')">'
            + (killActive ? '解除' : '作動') + '</button>'
            + '</div>';

        // Per-tier groups
        for (const tier of TIER_ORDER) {
            const items = grouped.get(tier) || [];
            if (!items.length) continue;
            html += '<div class="lfh-tier">';
            html += '<div class="lfh-tier-title">' + _escHtml(TIER_LABELS[tier]) + '</div>';
            html += items.map(renderFeatureRow).join('');
            html += '</div>';
        }

        // History toggle
        html += '<div class="lfh-history-toggle" onclick="window._llmFeaturesToggleHistory()">'
            + '<span class="lfh-history-chev" id="lfh-history-chev">▸</span>'
            + ' 最近の状態変更（直近 30d）'
            + '</div>';
        html += '<div class="lfh-history" id="lfh-history" style="display:none;">'
            + '<div class="lfh-history-loading">読み込み中…</div>'
            + '</div>';

        body.innerHTML = html;
    }

    function renderFeatureRow(f) {
        const state = f.current_state;
        const stateClass = 'lfh-state-' + state;
        const sourceLabel = f.source === 'ui_override' ? 'UI override'
            : f.source === 'env' ? 'env'
            : 'default';
        const np7Tag = f.np7_concern
            ? '<span class="lfh-np7-tag" title="NP7: 構造に影響する機能">NP7</span>'
            : '';
        // Build state buttons. supports_shadow controls whether SHADOW button shows.
        const stateBtns = [];
        if (f.supports_shadow) {
            stateBtns.push(stateBtn(f.key, 'shadow', state));
        }
        stateBtns.push(stateBtn(f.key, 'on', state));
        stateBtns.push(stateBtn(f.key, 'off', state));

        return '<div class="lfh-row ' + stateClass + '">'
            + '<div class="lfh-row-head">'
            +   '<span class="lfh-row-name">' + _escHtml(f.name) + '</span>'
            +   np7Tag
            +   '<span class="lfh-row-state">' + state.toUpperCase() + '</span>'
            +   '<span class="lfh-row-source">[' + sourceLabel + ']</span>'
            + '</div>'
            + '<div class="lfh-row-desc">' + _escHtml(f.description) + '</div>'
            + '<div class="lfh-row-actions">'
            +   stateBtns.join(' ')
            + (f.source === 'ui_override'
                ? ' <button class="lfh-btn lfh-btn-clear" onclick="window._llmFeaturesClear(\''
                  + _escHtml(f.key) + '\')" title="UI 上書きを破棄し env+default に戻す">'
                  + '自動（復帰）</button>'
                : '')
            + '</div>'
            + '</div>';
    }

    function stateBtn(key, target, current) {
        const active = current === target;
        const cls = 'lfh-btn lfh-btn-state' + (active ? ' active' : '');
        return '<button class="' + cls + '" '
            + 'onclick="window._llmFeaturesSet(\'' + _escHtml(key) + '\',\'' + target + '\')">'
            + target.toUpperCase()
            + '</button>';
    }

    async function refreshHistory() {
        const el = document.getElementById('lfh-history');
        if (!el) return;
        try {
            const resp = await fetch('/api/v2/llm_features/audit?hours=720&limit=200');
            const body = await resp.json();
            const rows = (body && body.data) || [];
            if (!rows.length) {
                el.innerHTML = '<div class="lfh-history-empty">最近の変更なし。</div>';
                return;
            }
            el.innerHTML = '<table class="lfh-history-table">'
                + '<tr><th>日時</th><th>機能</th><th>変更前</th><th>変更後</th><th>実行者</th><th>理由</th></tr>'
                + rows.map(r => {
                    const t = r.changed_at
                        ? new Date(r.changed_at * 1000).toLocaleString('ja-JP', {
                            month: '2-digit', day: '2-digit',
                            hour: '2-digit', minute: '2-digit',
                        })
                        : '—';
                    return '<tr>'
                        + '<td>' + _escHtml(t) + '</td>'
                        + '<td>' + _escHtml(r.feature_key || '') + '</td>'
                        + '<td>' + _escHtml(r.old_state || '—') + '</td>'
                        + '<td><b>' + _escHtml(r.new_state || '') + '</b></td>'
                        + '<td>' + _escHtml(r.changed_by || '') + '</td>'
                        + '<td>' + _escHtml(r.reason || '') + '</td>'
                        + '</tr>';
                }).join('')
                + '</table>';
        } catch (err) {
            el.innerHTML = '<div class="lfh-history-empty">読み込みに失敗しました。</div>';
        }
    }

    async function postJson(url, body) {
        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await resp.json();
            if (!resp.ok) {
                window.alert('操作に失敗しました: ' + (data.error || resp.status));
                return false;
            }
            return true;
        } catch (err) {
            window.alert('ネットワークエラー: ' + err);
            return false;
        }
    }

    // ── HUD chip ────────────────────────────────────────────────────────

    function updateChip(features) {
        const valEl = document.getElementById('hud-llm-feat-value');
        const chip = document.getElementById('hud-llm-feat-chip');
        if (!valEl || !chip) return;
        if (!features.length) {
            valEl.textContent = '—';
            chip.style.color = '';
            return;
        }
        const killActive = features[0].kill_switch_active;
        if (killActive) {
            valEl.textContent = 'KILL';
            chip.style.color = '#ff4444';
            chip.title = 'Kill switch 作動中 — LLM 機能はすべて OFF。';
            return;
        }
        let on = 0, shadow = 0, off = 0;
        features.forEach(f => {
            if (f.current_state === 'on') on++;
            else if (f.current_state === 'shadow') shadow++;
            else off++;
        });
        const total = features.length;
        valEl.textContent = on + '/' + total
            + (shadow > 0 ? ' +' + shadow + 's' : '');
        // Color: green when all on, amber when any shadow, default when some off.
        if (on === total) chip.style.color = '#44cc66';
        else if (shadow > 0) chip.style.color = '#ffaa00';
        else if (on > 0) chip.style.color = 'var(--color-accent)';
        else chip.style.color = '#888';
        chip.title = 'LLM 機能: on ' + on + '、shadow ' + shadow + '、off '
            + off + '。クリックで管理。';
    }

    function _escHtml(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Polling: every 60s, after a 6s startup delay (lets login + first
    // refresh complete first).
    function _initChip() {
        setTimeout(() => {
            refresh();
            setInterval(refresh, 60000);
        }, 6000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _initChip);
    } else {
        _initChip();
    }
})();
