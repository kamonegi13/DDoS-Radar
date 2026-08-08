/**
 * Noroshi v3 L7 — the Tier 0 situation board (pure, DOM-free).
 *
 * This is step ① of the analyst's primary loop: "has anything changed, and
 * can I trust this tool right now?", with a ten-second budget. P8 §2 gives
 * the board four things — the scenario cards, the composite trust chip, the
 * top of the attention lane, and the permanent NP7 bar. This module builds
 * the cards; `trust.js` folds the chip and `lane.js` builds the lane.
 *
 * What a card may contain is bounded by what R1 actually serves. R1 carries
 * TL, the 24 h severity delta, score, scoring mode, null-zone and
 * never-observed flags, participants and roles — but NOT per-domain scores.
 * Those live on the `per_domain` conclusion, which is fetched only for the
 * focused scenario (R2). So the focused card carries the domain mini-bar and
 * background cards declare that they do not: S1-UI-053's "background
 * scenarios must self-declare their observational limits", which exists so
 * that C-lite's structural bias is disclosed on the same screen as the
 * conclusion it biases.
 *
 * Nothing here computes a threat level, a score or a rank. The card is a
 * projection of numbers the server already decided (P8 derivation rule 3).
 * The one derived quantity is "what changed since I last looked", which is
 * a comparison between two values the server sent at two different times —
 * memory of a display, not a re-derivation of a conclusion.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiBoard = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var F = (typeof require === 'function')
        ? require('./format')
        : (typeof window !== 'undefined' ? window.NoroshiFormat : null);

    //: The three domains, in the order the tool always names them.
    var DOMAINS = ['cyber', 'physical', 'info'];

    // ── conclusion availability, as the card shows it ───────────────────
    var CONCLUDED = 'concluded';
    var INCONCLUSIVE = 'inconclusive';       // in a null zone right now (O-7)
    var NEVER_OBSERVED = 'never_observed';   // no observation has ever landed

    /**
     * "What changed since I last looked at this card?"
     *
     * `lastSeen` is local UI memory of the TL this browser last displayed
     * for each scenario — deliberately NOT the same thing as R6's
     * `analyst_blindness`, which the server measures from the organisation's
     * last command (§7-2 #87). One is "what this screen showed you"; the
     * other is "what the organisation has acted on". Conflating them is how
     * v1 ended up with an ack that lived only in one browser's localStorage.
     *
     * On the first sighting the card says so. It never reports a delta of
     * zero for a scenario it has no memory of — that would claim "nothing
     * changed" on the strength of having never looked.
     */
    function _sinceLastCheck(scenario, lastSeen) {
        var seenEntry = lastSeen && lastSeen[scenario.scenario_id];
        var currentTl = typeof scenario.threat_level === 'number'
            ? scenario.threat_level : null;
        if (!seenEntry || typeof seenEntry.threat_level !== 'number') {
            return { seen: false, previousTl: null, severityDelta: null,
                     seenAt: null, labelKey: 'ui.board.since.first_sighting' };
        }
        var previousTl = seenEntry.threat_level;
        var delta = (currentTl === null)
            ? null
            : F.severityOf(currentTl) - F.severityOf(previousTl);
        var labelKey = 'ui.board.since.unchanged';
        if (delta === null) labelKey = 'ui.board.since.unknown';
        else if (delta > 0) labelKey = 'ui.board.since.worsened';
        else if (delta < 0) labelKey = 'ui.board.since.improved';
        return {
            seen: true, previousTl: previousTl, severityDelta: delta,
            seenAt: typeof seenEntry.at === 'number' ? seenEntry.at : null,
            labelKey: labelKey,
        };
    }

    /**
     * The per-domain mini-bar, built from the focused scenario's per_domain
     * conclusion.
     *
     * Colour follows the server's state word only (S1-UI-019: "フロントは数値
     * 閾値を持たない"). Bar length is `score / denominator`, where the
     * denominator is the `magnitude_denom` the conclusion itself discloses in
     * its `threshold_ref` — so the bar's full-scale point is the backend's,
     * not a saturation constant invented here. If the conclusion does not
     * disclose one, the bar reports that instead of picking a number.
     */
    function _domainBar(perDomainConclusion) {
        if (!perDomainConclusion) return null;
        var metadata = perDomainConclusion.metadata || {};
        var scores = metadata.domain_scores;
        var states = metadata.domain_states;
        if (!scores || !states) return null;
        var thresholdRef = perDomainConclusion.threshold_ref || {};
        var denom = typeof thresholdRef.magnitude_denom === 'number'
            && thresholdRef.magnitude_denom > 0
            ? thresholdRef.magnitude_denom : null;
        return {
            denominator: denom,
            denominatorSource: denom === null
                ? null : 'R2:conclusion.threshold_ref.magnitude_denom',
            domains: DOMAINS.map(function (domain) {
                var score = typeof scores[domain] === 'number' ? scores[domain] : null;
                var state = typeof states[domain] === 'string' ? states[domain] : null;
                return {
                    domain: domain,
                    score: score,
                    state: state,
                    // A state word the frontend does not recognise is drawn
                    // neutral, never as calm and never as dangerous
                    // (S1-UI-023).
                    stateKey: state ? 'ui.domain.state.' + state : 'ui.domain.state.unknown',
                    fill: (score === null || denom === null)
                        ? null : Math.max(0, Math.min(1, score / denom)),
                };
            }),
        };
    }

    /** Availability, as the card must show it (O-7). */
    function _availability(scenario) {
        if (scenario.never_observed === true) {
            return { state: NEVER_OBSERVED, labelKey: 'ui.board.availability.never_observed' };
        }
        if (scenario.in_null_zone === true) {
            return { state: INCONCLUSIVE, labelKey: 'ui.board.availability.inconclusive' };
        }
        if (typeof scenario.threat_level !== 'number') {
            return { state: INCONCLUSIVE, labelKey: 'ui.board.availability.inconclusive' };
        }
        return { state: CONCLUDED, labelKey: 'ui.board.availability.concluded' };
    }

    /**
     * Background scenarios declare what they could not see.
     *
     * R1 does not carry a coverage ratio, so the declaration is categorical
     * rather than numeric: this scenario is scored in the reduced mode the
     * server named, and the card says which mode. Inventing a coverage
     * percentage the server did not send would be worse than saying less.
     */
    function _coverage(scenario, focused) {
        if (focused) {
            return { limited: false, scoringMode: scenario.scoring_mode || null,
                     labelKey: 'ui.board.coverage.full' };
        }
        return {
            limited: true,
            scoringMode: scenario.scoring_mode || null,
            labelKey: 'ui.board.coverage.limited',
        };
    }

    function _card(scenario, options) {
        var focused = scenario.scenario_id === options.focusedScenario;
        var participants = scenario.participants || {};
        return {
            scenarioId: scenario.scenario_id,
            focused: focused,
            tl: F.tlBand(typeof scenario.threat_level === 'number'
                ? scenario.threat_level : null),
            availability: _availability(scenario),
            trend: F.trendOf(typeof scenario.severity_delta_24h === 'number'
                ? scenario.severity_delta_24h : null),
            sinceLastCheck: _sinceLastCheck(scenario, options.lastSeen),
            score: typeof scenario.score === 'number' ? scenario.score : null,
            observedAt: typeof scenario.observed_at === 'number'
                ? scenario.observed_at : null,
            scoringMode: scenario.scoring_mode || null,
            coverage: _coverage(scenario, focused),
            domains: focused ? _domainBar(options.perDomain) : null,
            participantCount: Object.keys(participants).length,
            adversaries: Array.isArray(scenario.adversaries)
                ? scenario.adversaries.slice() : [],
            roles: scenario.roles || {},
        };
    }

    /**
     * S1-UI-051: focused first unconditionally, then by how much moved.
     *
     * R1 serves a 24 h severity delta rather than v1's 1 h score delta, so
     * the ordering question the bar answers is "what moved most in a day".
     * Scenarios with no delta sort last rather than sorting as zero — a
     * scenario nobody has measured is not a scenario that did not move.
     * Ties break on scenario id so the order is reproducible (AP2).
     */
    function _sortCards(cards) {
        return cards.slice().sort(function (a, b) {
            if (a.focused !== b.focused) return a.focused ? -1 : 1;
            var da = a.trend.delta === null ? null : Math.abs(a.trend.delta);
            var db = b.trend.delta === null ? null : Math.abs(b.trend.delta);
            if (da === null && db !== null) return 1;
            if (db === null && da !== null) return -1;
            if (da !== null && db !== null && da !== db) return db - da;
            return a.scenarioId < b.scenarioId ? -1 : (a.scenarioId > b.scenarioId ? 1 : 0);
        });
    }

    /** Pull the focused scenario's `per_domain` conclusion out of R2. */
    function perDomainOf(conclusionsEnvelope) {
        if (!conclusionsEnvelope) return null;
        var list = conclusionsEnvelope.conclusions;
        if (!Array.isArray(list)) return null;
        for (var i = 0; i < list.length; i += 1) {
            if (list[i] && list[i].conclusion_type === 'per_domain'
                    && list[i].conclusion_unavailable_reason === null) {
                return list[i];
            }
        }
        return null;
    }

    /**
     * Build the Tier 0 board.
     *
     * @param {object} input
     * @param {object|null} input.scenarios     R1 envelope
     * @param {object|null} input.conclusions   R2 envelope for the focused scenario
     * @param {object} [input.lastSeen]         local memory {sid: {threat_level, at}}
     * @returns {{cards: Array, focusedScenario: string|null, focusSource: string|null,
     *            scenarioCount: number, empty: boolean, emptyKey: string|null}}
     */
    function buildBoard(input) {
        input = input || {};
        var envelope = input.scenarios || null;
        var scenarios = (envelope && Array.isArray(envelope.scenarios))
            ? envelope.scenarios : [];
        var focusedScenario = envelope ? (envelope.focused_scenario || null) : null;
        var options = {
            focusedScenario: focusedScenario,
            lastSeen: input.lastSeen || null,
            perDomain: perDomainOf(input.conclusions),
        };
        var cards = _sortCards(scenarios.map(function (s) { return _card(s, options); }));
        return {
            cards: cards,
            focusedScenario: focusedScenario,
            focusSource: envelope ? (envelope.focus_source || null) : null,
            scenarioCount: cards.length,
            // S1-UI-008 forbids a blank screen: an empty board says why it
            // is empty rather than showing nothing.
            empty: cards.length === 0,
            emptyKey: cards.length === 0
                ? (envelope ? 'ui.board.empty.no_scenarios' : 'ui.board.empty.not_loaded')
                : null,
        };
    }

    /**
     * Record what the analyst has now been shown, for the next comparison.
     * Immutable: returns a new map (CLAUDE.md's immutability rule).
     */
    function rememberSeen(lastSeen, cards, now) {
        var next = Object.assign({}, lastSeen || {});
        (cards || []).forEach(function (card) {
            if (card.tl.tl === null) return;      // never remember an absence
            next[card.scenarioId] = { threat_level: card.tl.tl, at: now };
        });
        return next;
    }

    return {
        buildBoard: buildBoard,
        rememberSeen: rememberSeen,
        perDomainOf: perDomainOf,
        DOMAINS: DOMAINS,
        CONCLUDED: CONCLUDED,
        INCONCLUSIVE: INCONCLUSIVE,
        NEVER_OBSERVED: NEVER_OBSERVED,
    };
});
