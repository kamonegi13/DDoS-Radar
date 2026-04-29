/**
 * DDoS-Radar Triage Display Mode — pure state-machine
 *
 * Resolves the TRIAGE Lane display mode from the current
 * attention-score signals. Three modes:
 *
 *   - 'dormant':         no item meets the dormant threshold; lane hidden
 *   - 'pin-dock':        at least one item ≥ dormant threshold; corner
 *                        overlay on the map (no HUD-flow space taken)
 *   - 'critical-banner': max score ≥ critical threshold OR an explicit
 *                        critical event (TL5 escalation, recall-reducing
 *                        pending, etc.); HUD-flow 24px banner with pulse
 *
 * Hysteresis: each transition has separate enter/exit thresholds to
 * avoid flicker when scores oscillate around the boundary. The
 * defaults are calibrated for AP1's score band:
 *
 *   dormant_enter:    0.40   (drop into dormant when max <  0.40)
 *   dormant_exit:     0.50   (leave dormant once  max ≥ 0.50)
 *   critical_enter:   0.85   (enter critical when max ≥ 0.85)
 *   critical_exit:    0.78   (leave critical once max <  0.78)
 *
 * Honors NP1 by always elevating to critical-banner on explicit
 * `hasCritical` (e.g., kill-switch engaged, TL5 escalation), bypassing
 * the score thresholds entirely. NP6: the chosen mode and the values
 * that produced it are returned together so the UI can surface them.
 *
 * Loaded as a plain script in index.html (window.TriageDisplayMode)
 * and via require() in test_triage_display_mode.js. Mirrors the
 * triage_score.js / hud_v2_overlay.js extraction pattern.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.TriageDisplayMode = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const DEFAULT_THRESHOLDS = Object.freeze({
        dormantEnter: 0.40,
        dormantExit: 0.50,
        criticalEnter: 0.85,
        criticalExit: 0.78,
    });

    const MODE_DORMANT = 'dormant';
    const MODE_PIN_DOCK = 'pin-dock';
    const MODE_CRITICAL = 'critical-banner';

    function _isFiniteNumber(x) {
        return typeof x === 'number' && isFinite(x);
    }

    function _normalizeThresholds(thr) {
        const t = thr || {};
        const out = {
            dormantEnter:  _isFiniteNumber(t.dormantEnter)  ? t.dormantEnter  : DEFAULT_THRESHOLDS.dormantEnter,
            dormantExit:   _isFiniteNumber(t.dormantExit)   ? t.dormantExit   : DEFAULT_THRESHOLDS.dormantExit,
            criticalEnter: _isFiniteNumber(t.criticalEnter) ? t.criticalEnter : DEFAULT_THRESHOLDS.criticalEnter,
            criticalExit:  _isFiniteNumber(t.criticalExit)  ? t.criticalExit  : DEFAULT_THRESHOLDS.criticalExit,
        };
        // Sanity: enter MUST be ≥ exit for both bands. If misconfigured
        // (e.g., per-user override inverted), force enter ≥ exit so the
        // hysteresis is not pathological. Prefer the larger value as
        // enter, the smaller as exit.
        if (out.dormantEnter > out.dormantExit) {
            const a = out.dormantEnter;
            out.dormantEnter = out.dormantExit;
            out.dormantExit = a;
        }
        if (out.criticalExit > out.criticalEnter) {
            const a = out.criticalEnter;
            out.criticalEnter = out.criticalExit;
            out.criticalExit = a;
        }
        return out;
    }

    /**
     * Resolve the next display mode given the current max score, an
     * optional explicit critical flag, the previous mode (for
     * hysteresis), and threshold overrides.
     *
     * @param {object} params
     * @param {number} params.maxScore       max attention_score across items, or 0 when empty
     * @param {boolean} [params.hasCritical] true when an explicit critical event is active
     * @param {string} [params.prevMode]     previous mode ('dormant'|'pin-dock'|'critical-banner')
     * @param {object} [params.thresholds]   { dormantEnter, dormantExit, criticalEnter, criticalExit }
     * @param {boolean} [params.alwaysVisible] when true, dormant mode is suppressed
     *                                          (analyst override; minimum mode is pin-dock)
     * @returns {{mode: string, reason: string, maxScore: number, thresholds: object}}
     */
    function resolveMode(params) {
        const p = params || {};
        const maxScore = _isFiniteNumber(p.maxScore) ? p.maxScore : 0;
        const hasCritical = !!p.hasCritical;
        const prev = (p.prevMode === MODE_DORMANT
                  || p.prevMode === MODE_PIN_DOCK
                  || p.prevMode === MODE_CRITICAL)
            ? p.prevMode : null;
        const thr = _normalizeThresholds(p.thresholds);
        const alwaysVisible = !!p.alwaysVisible;

        // 1. Explicit critical event always wins (NP1).
        if (hasCritical) {
            return {
                mode: MODE_CRITICAL,
                reason: 'explicit critical event',
                maxScore: maxScore,
                thresholds: thr,
            };
        }

        // 2. Critical-band entry / hysteresis.
        if (maxScore >= thr.criticalEnter) {
            return {
                mode: MODE_CRITICAL,
                reason: 'maxScore ' + maxScore.toFixed(2)
                      + ' ≥ criticalEnter ' + thr.criticalEnter.toFixed(2),
                maxScore: maxScore,
                thresholds: thr,
            };
        }
        if (prev === MODE_CRITICAL && maxScore >= thr.criticalExit) {
            return {
                mode: MODE_CRITICAL,
                reason: 'sticky critical; ' + maxScore.toFixed(2)
                      + ' still ≥ criticalExit ' + thr.criticalExit.toFixed(2),
                maxScore: maxScore,
                thresholds: thr,
            };
        }

        // 3. Always-visible override: never enter dormant.
        if (alwaysVisible) {
            return {
                mode: MODE_PIN_DOCK,
                reason: 'analyst override: always-visible',
                maxScore: maxScore,
                thresholds: thr,
            };
        }

        // 4. Dormant-band hysteresis.
        if (prev === MODE_DORMANT && maxScore < thr.dormantExit) {
            return {
                mode: MODE_DORMANT,
                reason: 'sticky dormant; ' + maxScore.toFixed(2)
                      + ' < dormantExit ' + thr.dormantExit.toFixed(2),
                maxScore: maxScore,
                thresholds: thr,
            };
        }
        if (maxScore < thr.dormantEnter) {
            return {
                mode: MODE_DORMANT,
                reason: 'maxScore ' + maxScore.toFixed(2)
                      + ' < dormantEnter ' + thr.dormantEnter.toFixed(2),
                maxScore: maxScore,
                thresholds: thr,
            };
        }

        // 5. Default: pin-dock band (between dormantEnter and criticalEnter).
        return {
            mode: MODE_PIN_DOCK,
            reason: 'in pin-dock band ['
                  + thr.dormantEnter.toFixed(2) + ', '
                  + thr.criticalEnter.toFixed(2) + ')',
            maxScore: maxScore,
            thresholds: thr,
        };
    }

    /**
     * Convenience: extract maxScore + hasCritical from a list of triage
     * items (the ranked output of TriageScore.rankItems plus per-item
     * augmentation done by the caller — `tl`, `criticalFlag`, etc.).
     *
     * @param {Array<object>} items - each entry must expose `.score`;
     *   optional fields read: `.tl`, `.scoreDelta`, `.criticalFlag`.
     * @returns {{maxScore: number, hasCritical: boolean}}
     */
    function summarizeItems(items) {
        if (!Array.isArray(items) || items.length === 0) {
            return { maxScore: 0, hasCritical: false };
        }
        let maxScore = 0;
        let hasCritical = false;
        for (let i = 0; i < items.length; i++) {
            const it = items[i] || {};
            const s = _isFiniteNumber(it.score) ? it.score : 0;
            if (s > maxScore) maxScore = s;
            if (it.criticalFlag === true) hasCritical = true;
            // Soft critical heuristics (the caller can pre-compute and
            // set `criticalFlag` when it has more info — these are
            // fallback heuristics that work from what triage_score
            // alone exposes):
            if (it.tl === 5 && _isFiniteNumber(it.scoreDelta) && it.scoreDelta > 0) {
                hasCritical = true;
            }
        }
        return { maxScore: maxScore, hasCritical: hasCritical };
    }

    return {
        resolveMode: resolveMode,
        summarizeItems: summarizeItems,
        DEFAULT_THRESHOLDS: DEFAULT_THRESHOLDS,
        MODE_DORMANT: MODE_DORMANT,
        MODE_PIN_DOCK: MODE_PIN_DOCK,
        MODE_CRITICAL: MODE_CRITICAL,
    };
});
