/**
 * Noroshi v3 L7 — the attention lane (pure, DOM-free).
 *
 * Step ② of the primary loop: "what should I look at next?", with a
 * thirty-second budget. P8 §2 puts the top rows on Tier 0 and the full list
 * one click away.
 *
 * The one thing this module must NOT do is rank. v1's `triage_score.js`
 * computed `novelty × confidence_delta × analyst_blindness` in the browser,
 * which meant the ordering an analyst acted on existed nowhere afterwards —
 * AP1 asks for the basis of the ranking to be permanently visible, and a
 * number recomputed per page-load leaves no trail (P5 O-8, G-03). In v3 S8
 * writes `attention_rank` rows to the ledger and R6 projects them with
 * `rank_position` already decided. This module orders BY `rank_position`
 * and never by `score` — the distinction matters, because following the
 * score would silently re-rank whenever the browser and the ledger
 * disagreed, and the ledger is the thing the decision trail replays.
 *
 * The second rule is that nothing disappears. S1-UI-032 forbids snooze and
 * dismiss from acting as silencers. v3 keeps rows in the projection with an
 * `analyst_state`, and this module folds the suppressed ones into a COUNTED
 * group rather than dropping them: an analyst always sees that three things
 * are snoozed, even when they cannot see which without expanding. A lane
 * that can hide a row can hide the one that mattered.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiLane = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * How many rows Tier 0 shows before "see all".
     *
     * A display cap, not a threshold on data: it changes how much of the
     * server's ranking is on screen, never which rows exist or in what order.
     * P8 §2 says "上位 3〜5 行"; five is the top of that range, chosen
     * because NP1 prefers showing one row too many to one too few.
     */
    var TIER0_ROWS = 5;

    //: The per-user states R6 can report. `active` means "no row written".
    var ACTIVE = 'active';
    var ACKED = 'acked';
    var SNOOZED = 'snoozed';
    var DISMISSED = 'dismissed';
    var STATES = [ACTIVE, ACKED, SNOOZED, DISMISSED];

    function _factor(row, name) {
        var value = row[name];
        return typeof value === 'number' && Number.isFinite(value) ? value : null;
    }

    /**
     * One lane row.
     *
     * `narrative` is the server's rendered sentence (R6 `narrative`, produced
     * by the backend template engine P7 §4 promoted `self_explanation.js`
     * into). The browser does not compose it, does not fall back to a locally
     * generated one, and does not let an LLM overwrite it — P8 §5 retires
     * S1-UI-036's "LLM is merely an overlay" entirely. When the server sends
     * no narrative the row says so rather than inventing prose.
     */
    function _row(raw, index) {
        var state = STATES.indexOf(raw.analyst_state) === -1
            ? ACTIVE : raw.analyst_state;
        return {
            itemId: raw.item_id,
            itemKind: raw.item_kind || null,
            scenarioId: raw.scenario_id || null,
            // The ledger's position, verbatim. Falls back to arrival order
            // only when the server omitted it, and says so.
            rankPosition: typeof raw.rank_position === 'number'
                ? raw.rank_position : null,
            rankFallback: typeof raw.rank_position !== 'number',
            arrivalIndex: index,
            score: _factor(raw, 'score'),
            factors: {
                novelty: _factor(raw, 'novelty'),
                confidence_delta: _factor(raw, 'confidence_delta'),
                analyst_blindness: _factor(raw, 'analyst_blindness'),
            },
            components: raw.components || null,
            formulaRef: raw.formula_ref || null,
            narrative: typeof raw.narrative === 'string' && raw.narrative
                ? raw.narrative : null,
            narrativeTemplateRef: raw.narrative_template_ref || null,
            narrativeMissingKey: (typeof raw.narrative === 'string' && raw.narrative)
                ? null : 'ui.lane.narrative.unsupplied',
            analystState: state,
            analystStateKey: 'ui.lane.state.' + state,
            analystStateExpiresAt: typeof raw.analyst_state_expires_at === 'number'
                ? raw.analyst_state_expires_at : null,
            suppressed: raw.suppressed === true,
        };
    }

    /**
     * Order by the ledger's `rank_position`, never by score.
     *
     * Rows the server did not rank sort after ranked ones, in arrival order,
     * and carry `rankFallback` so the row can say that its position is the
     * browser's guess rather than the ledger's decision.
     */
    function _byLedgerRank(a, b) {
        if (a.rankPosition === null && b.rankPosition === null) {
            return a.arrivalIndex - b.arrivalIndex;
        }
        if (a.rankPosition === null) return 1;
        if (b.rankPosition === null) return -1;
        if (a.rankPosition !== b.rankPosition) return a.rankPosition - b.rankPosition;
        return a.arrivalIndex - b.arrivalIndex;
    }

    /**
     * Build the lane.
     *
     * @param {object} input
     * @param {object|null} input.attention  R6 envelope
     * @param {number} [input.tier0Rows]     display cap for Tier 0
     * @returns {object}
     */
    function buildLane(input) {
        input = input || {};
        var envelope = input.attention || null;
        var raw = (envelope && Array.isArray(envelope.attention))
            ? envelope.attention : [];
        var cap = typeof input.tier0Rows === 'number' && input.tier0Rows > 0
            ? Math.floor(input.tier0Rows) : TIER0_ROWS;

        var rows = raw.map(_row).sort(_byLedgerRank);
        var visible = rows.filter(function (r) { return !r.suppressed; });
        var suppressed = rows.filter(function (r) { return r.suppressed; });

        // S1-UI-032: suppressed rows are counted in the open, always. The
        // group is collapsed, not absent — an analyst can see that three
        // things are being held back without having to remember to look.
        var suppressedByState = {};
        STATES.forEach(function (s) { suppressedByState[s] = 0; });
        suppressed.forEach(function (r) {
            suppressedByState[r.analystState] = (suppressedByState[r.analystState] || 0) + 1;
        });

        var emptyReason = envelope ? (envelope.empty_reason || null) : null;
        var isEmpty = rows.length === 0;

        return {
            tier0: visible.slice(0, cap),
            rows: visible,
            suppressed: suppressed,
            suppressedCount: suppressed.length,
            suppressedByState: suppressedByState,
            total: rows.length,
            hiddenBelowCap: Math.max(0, visible.length - cap),
            tier0Cap: cap,

            snapshotId: envelope ? (envelope.snapshot_id || null) : null,
            computedAt: envelope && typeof envelope.computed_at === 'number'
                ? envelope.computed_at : null,
            considered: envelope && typeof envelope.considered === 'number'
                ? envelope.considered : null,
            filteredBelowMinScore: envelope
                && typeof envelope.filtered_below_min_score === 'number'
                ? envelope.filtered_below_min_score : null,
            thresholds: envelope ? (envelope.thresholds || null) : null,
            thresholdDisclosure: envelope ? (envelope.threshold_disclosure || null) : null,
            narrativeTemplates: envelope ? (envelope.narrative_templates || null) : null,
            formulaRef: envelope ? (envelope.formula_ref || null) : null,

            // NP5+8 / S1-UI-008: an empty lane must say WHY it is empty. A
            // ranker that has not run and a world with nothing worth ranking
            // look identical on screen unless the projection says which.
            empty: isEmpty,
            emptyKey: !isEmpty ? null
                : (envelope
                    ? 'ui.lane.empty.' + (emptyReason || 'no_ranked_items')
                    : 'ui.lane.empty.not_loaded'),
            emptyReason: emptyReason,
        };
    }

    /**
     * The row's ranking basis, for the tooltip (AP1: the basis is always
     * visible). Values only — the sentence is the dictionary's.
     */
    function rankBasis(row, lane) {
        if (!row) return null;
        return {
            score: row.score,
            factors: row.factors,
            components: row.components,
            formulaRef: row.formulaRef || (lane ? lane.formulaRef : null),
            rankPosition: row.rankPosition,
            rankFallback: row.rankFallback,
            snapshotId: lane ? lane.snapshotId : null,
            disclosure: lane ? lane.thresholdDisclosure : null,
        };
    }

    return {
        buildLane: buildLane,
        rankBasis: rankBasis,
        TIER0_ROWS: TIER0_ROWS,
        STATES: STATES,
        ACTIVE: ACTIVE, ACKED: ACKED, SNOOZED: SNOOZED, DISMISSED: DISMISSED,
    };
});
