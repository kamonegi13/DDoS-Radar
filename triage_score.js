/**
 * Noroshi Triage — pure attention_score / ranking
 *
 * Implements the AP1 (Active Triage) score that ranks event-shaped
 * conclusions for the Alert Lane:
 *
 *   attention_score = novelty × confidence_delta × analyst_blindness
 *
 * where each component is bounded to [0, 1] and the product is bounded
 * to [0, 1]. The components are *deterministic functions of inputs*
 * (no LLM, no random) so the ranking is fully derivable per AP2 + NP6.
 *
 * Inputs:
 *   - conclusion: v2 conclusion object (id, conclusion_type, state,
 *                 confidence, observed_at, conclusion_unavailable_reason,
 *                 metadata)
 *   - history:    optional { lastFireTs?: number, prevConfidence?: number }
 *                 — if absent, novelty defaults to 1 (new) and
 *                 confidence_delta defaults to confidence (treat as fresh).
 *   - analystState: optional { lastViewTs?: number, ackedIds?: Set<string> }
 *                 — if absent, blindness defaults to 1 (never viewed).
 *   - now: timestamp seconds (for testability)
 *
 * Components:
 *   novelty             ramp 0..1 over last 48h since last fire of this
 *                       conclusion mode for this scenario. brand-new = 1,
 *                       fired 48h ago = 0.
 *   confidence_delta    abs(current_conf - prev_conf), clamped to [0,1].
 *                       Fresh items (prev=undefined) score current_conf.
 *   analyst_blindness   ramp 0..1 over last 6h since the analyst last
 *                       opened this scenario. just-viewed = 0, ≥6h = 1.
 *
 * Acknowledged conclusions (id in ackedIds) get attention_score = 0
 * regardless of inputs — analyst has signalled they've seen it.
 *
 * Loaded as a plain script in index.html (window.TriageScore) and via
 * require() in test_triage_score.js. Mirrors the wp_alarm.js /
 * hud_v2_overlay.js extraction pattern.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.TriageScore = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const NOVELTY_HORIZON_SEC = 48 * 3600;     // 48h ramp
    const BLINDNESS_HORIZON_SEC = 6 * 3600;    // 6h ramp
    const MAX_SCORE = 1.0;
    const MIN_FIRE_THRESHOLD = 0.05;            // below this → don't surface

    function _clamp01(x) {
        if (typeof x !== 'number' || !isFinite(x)) return 0;
        return Math.max(0, Math.min(1, x));
    }

    /**
     * @param {object} conclusion
     * @param {object} [history] - {lastFireTs, prevConfidence}
     * @param {object} [analystState] - {lastViewTs, ackedIds}
     * @param {number} [now] - seconds since epoch
     * @returns {{score: number, components: {novelty: number, confDelta: number, blindness: number}, why: string[]}}
     */
    function computeAttentionScore(conclusion, history, analystState, now) {
        const ts = (typeof now === 'number' && isFinite(now))
            ? now : (Date.now() / 1000);
        const why = [];

        if (!conclusion || !conclusion.id) {
            return { score: 0, components: { novelty: 0, confDelta: 0, blindness: 0 }, why: ['conclusion id なし'] };
        }
        if (conclusion.conclusion_unavailable_reason) {
            return { score: 0, components: { novelty: 0, confDelta: 0, blindness: 0 }, why: ['結論不可'] };
        }
        if (analystState && analystState.ackedIds && analystState.ackedIds.has &&
                analystState.ackedIds.has(conclusion.id)) {
            return { score: 0, components: { novelty: 0, confDelta: 0, blindness: 0 }, why: ['確認済み'] };
        }

        // novelty: 1 for brand-new; ramps to 0 over NOVELTY_HORIZON_SEC.
        const lastFireTs = history && typeof history.lastFireTs === 'number'
            ? history.lastFireTs : null;
        let novelty;
        if (lastFireTs == null) {
            novelty = 1.0;
            why.push('novelty: 48h 以内の発火履歴なし');
        } else {
            const age = Math.max(0, ts - lastFireTs);
            novelty = _clamp01(1 - age / NOVELTY_HORIZON_SEC);
            const ageH = (age / 3600).toFixed(1);
            why.push(`novelty ${novelty.toFixed(2)}（前回発火 ${ageH}h 前）`);
        }

        // confidence_delta
        const conf = (typeof conclusion.confidence === 'number') ? conclusion.confidence : 0;
        const prevConf = history && typeof history.prevConfidence === 'number'
            ? history.prevConfidence : null;
        let confDelta;
        if (prevConf == null) {
            confDelta = _clamp01(conf);
            why.push(`確信度 ${conf.toFixed(2)}（前回値なし）`);
        } else {
            confDelta = _clamp01(Math.abs(conf - prevConf));
            const arrow = conf >= prevConf ? '↑' : '↓';
            why.push(`Δconf ${confDelta.toFixed(2)} ${arrow}（前回 ${prevConf.toFixed(2)}）`);
        }

        // analyst_blindness
        const lastViewTs = analystState && typeof analystState.lastViewTs === 'number'
            ? analystState.lastViewTs : null;
        let blindness;
        if (lastViewTs == null) {
            blindness = 1.0;
            why.push('6h 以上未確認');
        } else {
            const since = Math.max(0, ts - lastViewTs);
            blindness = _clamp01(since / BLINDNESS_HORIZON_SEC);
            const sinceH = (since / 3600).toFixed(1);
            why.push(`blindness ${blindness.toFixed(2)}（最終確認 ${sinceH}h 前）`);
        }

        const score = _clamp01(novelty * confDelta * blindness);
        return {
            score: Math.min(MAX_SCORE, score),
            components: { novelty, confDelta, blindness },
            why,
        };
    }

    /**
     * Rank a list of {conclusion, history?, analystState?} entries by
     * attention_score descending. Returns a NEW sorted array of entries
     * augmented with `score`, `components`, `why`. Items below
     * MIN_FIRE_THRESHOLD are dropped.
     *
     * @param {Array<{conclusion: object, history?: object}>} entries
     * @param {object} [analystState]
     * @param {number} [now]
     * @returns {Array<{conclusion: object, score: number, components: object, why: string[], rank: number}>}
     */
    function rankItems(entries, analystState, now) {
        if (!Array.isArray(entries)) return [];
        const scored = entries
            .map(e => {
                const r = computeAttentionScore(e.conclusion, e.history, analystState, now);
                return Object.assign({}, e, r);
            })
            .filter(e => e.score >= MIN_FIRE_THRESHOLD)
            .sort((a, b) => b.score - a.score);
        return scored.map((e, i) => Object.assign({}, e, { rank: i + 1 }));
    }

    return {
        computeAttentionScore: computeAttentionScore,
        rankItems: rankItems,
        NOVELTY_HORIZON_SEC: NOVELTY_HORIZON_SEC,
        BLINDNESS_HORIZON_SEC: BLINDNESS_HORIZON_SEC,
        MIN_FIRE_THRESHOLD: MIN_FIRE_THRESHOLD,
    };
});
