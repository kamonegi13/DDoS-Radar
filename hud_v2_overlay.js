/**
 * Noroshi HUD↔v2 Conclusion overlay — pure reconciler
 *
 * Extracted from radar.js so the overlay can be unit-tested under Node
 * without a browser. Loaded as a plain script in index.html (exposes
 * `window.HudV2Overlay`) and via `require()` in test_hud_v2_overlay.js.
 *
 * Design contract (per Phase 4 prep — eliminate v1↔v2 HUD/Cards drift):
 *   - applyOverlay(strat, byType) returns a NEW strat with TL and per_domain
 *     sourced from v2 conclusions when available; v1 values pass through
 *     otherwise (NP3 fault tolerance: HUD never blanks when v2 is down).
 *   - Pure: no side effects, no Date.now, no DOM. The TTL/freshness gate
 *     and the cache lookup live in radar.js — this module only handles
 *     the field-by-field merge.
 *   - Immutable: never mutates inputs (per coding-style.md / NP6).
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.HudV2Overlay = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * Parse a v2 kv-state string ("cyber=ACTIVE;physical=STABLE;info=...")
     * into a plain object. Keys/values are trimmed; malformed pairs drop
     * silently — matches _ccParseKvState in radar.js.
     *
     * @param {string|null|undefined} state
     * @returns {Object<string,string>}
     */
    function parseKvState(state) {
        const out = {};
        if (typeof state !== 'string') return out;
        state.split(';').forEach((pair) => {
            const idx = pair.indexOf('=');
            if (idx <= 0) return;
            const k = pair.slice(0, idx).trim();
            const v = pair.slice(idx + 1).trim();
            if (k && v) out[k] = v;
        });
        return out;
    }

    /**
     * Build a HUD-shaped strat by overlaying v2 conclusions onto a v1 strat.
     *
     * Rules:
     *   - threat_level: use v2 byType.threat_level.state when available and
     *     numeric and not flagged unavailable; else keep v1.
     *   - domains: use v2 byType.per_domain (state + metadata.domain_scores)
     *     when available and not flagged unavailable; per-domain fallback
     *     to v1 values when a key is missing.
     *   - Returns the original `strat` reference unchanged when neither v2
     *     conclusion is usable (cheap no-op for the common down-state).
     *
     * @param {object|null|undefined} strat — v1 strategic_alert
     * @param {Object<string,object>|null|undefined} byType — v2 conclusions
     *        keyed by conclusion_type
     * @returns {object|null|undefined}
     */
    function applyOverlay(strat, byType) {
        if (!strat) return strat;
        if (!byType || typeof byType !== 'object') return strat;

        const tlC = byType.threat_level;
        const tlAvail = tlC && tlC.conclusion_unavailable_reason == null;
        const tlVal = tlAvail ? parseInt(tlC.state, 10) : NaN;
        const useTl = Number.isFinite(tlVal);

        const pdC = byType.per_domain;
        const pdAvail = pdC && pdC.conclusion_unavailable_reason == null;
        const usePd = !!pdAvail;

        if (!useTl && !usePd) return strat;

        const out = Object.assign({}, strat);

        if (useTl) out.threat_level = tlVal;

        if (usePd) {
            const statusByDomain = parseKvState(pdC.state);
            const scoreByDomain = (pdC.metadata && pdC.metadata.domain_scores) || {};
            const v1Domains = strat.domains || {};
            const newDomains = {};
            ['cyber', 'physical', 'info'].forEach((d) => {
                const v1 = v1Domains[d] || { score: 0, status: 'NORMAL' };
                const score = (typeof scoreByDomain[d] === 'number') ? scoreByDomain[d] : v1.score;
                const status = statusByDomain[d] || v1.status;
                newDomains[d] = Object.assign({}, v1, { score: score, status: status });
            });
            out.domains = newDomains;
        }
        return out;
    }

    return { parseKvState: parseKvState, applyOverlay: applyOverlay };
});
