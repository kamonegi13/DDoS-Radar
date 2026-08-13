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
    //: For the participant strip's flag glyphs only — placement stays the
    //: board map's business and no cell is read here.
    var Tiles = (typeof require === 'function')
        ? require('./geo_tiles')
        : (typeof window !== 'undefined' ? window.NoroshiGeoTiles : null);

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

    /**
     * Availability, as the card must show it (O-7).
     *
     * Two keys, not one: the short word labels the state next to the TL
     * block, and `sentenceKey` is the plain-Japanese sentence P9 §3.1 asks
     * for on a card that cannot conclude. A card whose only statement is
     * the token 結論不可 tells an analyst the tool's word for the state and
     * nothing about what the state is — R-A's whole point. A concluded card
     * needs no such sentence: the TL and the change line are the sentence.
     */
    function _availability(scenario) {
        if (scenario.never_observed === true) {
            return { state: NEVER_OBSERVED,
                     labelKey: 'ui.board.availability.never_observed',
                     sentenceKey: 'ui.board.availability.sentence.never_observed' };
        }
        if (scenario.in_null_zone === true || typeof scenario.threat_level !== 'number') {
            return { state: INCONCLUSIVE,
                     labelKey: 'ui.board.availability.inconclusive',
                     sentenceKey: 'ui.board.availability.sentence.inconclusive' };
        }
        return { state: CONCLUDED, labelKey: 'ui.board.availability.concluded',
                 sentenceKey: null };
    }

    /**
     * What would clear a card's 結論不可, when the server has said.
     *
     * R1 carries no resolution hint at all; R2 carries one, as the
     * envelope-level `calibration_pending` block (days remaining against
     * the calibration window). R2 is fetched for the focused scenario
     * ONLY, so the block is attached to the card whose id matches the
     * envelope's `scenario_id` and to no other. That equality test is the
     * whole guard: attaching one scenario's calibration state to another
     * scenario's card is the shape of the 2026-08-02 calibration incident
     * (cross-scenario attribution), and it is silent when it happens.
     *
     * When no hint was served the card says THAT, rather than implying the
     * state is unexplained (O-7 / S1-UI-008).
     */
    function _calibrationPending(conclusionsEnvelope) {
        var pending = conclusionsEnvelope
            ? conclusionsEnvelope.calibration_pending : null;
        if (!pending || typeof pending.days_remaining !== 'number') return null;
        return {
            scenarioId: conclusionsEnvelope.scenario_id || null,
            daysRemaining: pending.days_remaining,
            daysObserved: typeof pending.days_observed === 'number'
                ? pending.days_observed : null,
            windowDays: typeof pending.window_days === 'number'
                ? pending.window_days : null,
        };
    }

    function _resolution(scenario, availability, pending) {
        if (availability.state === CONCLUDED) {
            return { hint: null, labelKey: null };
        }
        var applies = pending && pending.scenarioId !== null
            && pending.scenarioId === scenario.scenario_id;
        return applies
            ? { hint: pending, labelKey: 'ui.board.resolution.days' }
            : { hint: null, labelKey: 'ui.board.resolution.unsupplied' };
    }

    /**
     * The situation sentence (P9 §2 R-A, §5), rendered by the server.
     *
     * The browser NEVER composes this. Counting how many scenarios moved
     * and naming the most urgent is a derivation, and a derivation done in
     * the browser is one the ledger cannot replay and the audit cannot
     * reach (G-09 / NP6). When R1 serves no `board_summary`, the slot says
     * it was not supplied — exactly as a lane row does for a missing
     * narrative — and the analyst reads the cards instead.
     */
    function _summary(envelope) {
        var raw = envelope ? envelope.board_summary : null;
        var text = (raw && typeof raw.text === 'string' && raw.text) ? raw.text : null;
        return {
            supplied: text !== null,
            text: text,
            templateRef: (raw && typeof raw.template_ref === 'string'
                          && raw.template_ref) ? raw.template_ref : null,
            unsuppliedKey: text === null ? 'ui.board.summary.unsupplied' : null,
        };
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

    /**
     * The card's participant strip (P9 §3.7): the geographic identity the
     * second owner review found missing from Tier 0 (D-10). Weight order,
     * ties on the code, matching the server's own sweep order
     * (`v3/runtime/geo.py::participants_of`) — the country the scenario is
     * coupled to hardest comes first. This strip is also the accessible
     * twin of the board map: the map's grid is decoration over exactly
     * these facts, so it can stay `aria-hidden`.
     */
    function _participantStrip(scenario) {
        var participants = scenario.participants || {};
        var roles = scenario.roles || {};
        var adversaries = Array.isArray(scenario.adversaries)
            ? scenario.adversaries : [];
        return Object.keys(participants).sort(function (a, b) {
            var wa = typeof participants[a] === 'number' ? participants[a] : 0;
            var wb = typeof participants[b] === 'number' ? participants[b] : 0;
            if (wa !== wb) return wb - wa;
            return a < b ? -1 : (a > b ? 1 : 0);
        }).map(function (country) {
            var code = String(country).toUpperCase();
            var role = typeof roles[country] === 'string'
                ? roles[country] : null;
            return {
                country: code,
                flag: Tiles.flagOf(code),
                role: role,
                roleKey: role ? 'ui.geo.role.' + role : 'ui.geo.role.unlisted',
                isAdversary: adversaries.indexOf(country) !== -1
                    || adversaries.indexOf(code) !== -1,
            };
        });
    }

    /**
     * The card's provenance line (P9 §2.2 R-E, D-11): where the number
     * came from, as the server stored it. R1's `derived_from` is the
     * PER_DOMAIN conclusion row of the same tick, projected through R2's
     * own read path — this function only re-keys it for display and keeps
     * the three states apart: supplied with a picture, supplied but
     * unavailable (the tick could not build a domain picture), and not
     * supplied at all. Folding those together would be G-17 — "no record"
     * shown as "three quiet domains".
     */
    function _derivedFrom(scenario) {
        var derived = scenario.derived_from;
        if (!derived || derived.supplied !== true) {
            return {
                supplied: false,
                reasonKey: derived && derived.reason === 'unreadable_row'
                    ? 'ui.board.derived.unreadable'
                    : 'ui.board.derived.absent',
            };
        }
        var domains = derived.domains || {};
        var extras = Object.keys(domains).filter(function (domain) {
            return DOMAINS.indexOf(domain) === -1;
        }).sort();
        var order = DOMAINS.filter(function (domain) {
            return Object.prototype.hasOwnProperty.call(domains, domain);
        }).concat(extras);
        return {
            supplied: true,
            unavailable: typeof derived.unavailable_reason === 'string'
                ? derived.unavailable_reason : null,
            observedAt: typeof derived.observed_at === 'number'
                ? derived.observed_at : null,
            domains: order.map(function (domain) {
                var entry = domains[domain] || {};
                return {
                    domain: domain,
                    score: typeof entry.score === 'number' ? entry.score : null,
                    state: typeof entry.state === 'string' ? entry.state : null,
                    sources: typeof entry.sources === 'number'
                        ? entry.sources : null,
                };
            }),
        };
    }

    function _card(scenario, options) {
        var focused = scenario.scenario_id === options.focusedScenario;
        var participants = scenario.participants || {};
        var availability = _availability(scenario);
        return {
            scenarioId: scenario.scenario_id,
            // The analyst's vocabulary, when the server has one for this
            // scenario (P9 §5). `scenario_id` remains the identity — the
            // card keeps it in the tooltip and in `data-scenario` — but a
            // raw id is not what a person calls a theatre.
            displayName: (typeof scenario.display_name_ja === 'string'
                          && scenario.display_name_ja)
                ? scenario.display_name_ja : null,
            focused: focused,
            tl: F.tlBand(typeof scenario.threat_level === 'number'
                ? scenario.threat_level : null),
            availability: availability,
            resolution: _resolution(scenario, availability,
                                    options.calibrationPending),
            trend: F.trendOf(typeof scenario.severity_delta_24h === 'number'
                ? scenario.severity_delta_24h : null),
            sinceLastCheck: _sinceLastCheck(scenario, options.lastSeen),
            score: typeof scenario.score === 'number' ? scenario.score : null,
            observedAt: typeof scenario.observed_at === 'number'
                ? scenario.observed_at : null,
            scoringMode: scenario.scoring_mode || null,
            coverage: _coverage(scenario, focused),
            domains: focused ? _domainBar(options.perDomain) : null,
            derivedFrom: _derivedFrom(scenario),
            participantCount: Object.keys(participants).length,
            participants: _participantStrip(scenario),
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
            calibrationPending: _calibrationPending(input.conclusions),
        };
        var cards = _sortCards(scenarios.map(function (s) { return _card(s, options); }));
        return {
            cards: cards,
            summary: _summary(envelope),
            focusedScenario: focusedScenario,
            focusSource: envelope ? (envelope.focus_source || null) : null,
            scenarioCount: cards.length,
            // S1-UI-008 forbids a blank screen, and P9 §3.5 raises the bar:
            // saying WHY the board is empty is one of three things it owes a
            // reader who has never seen it full. The other two — what this
            // place shows, and what would fill it — do not depend on the
            // payload, so the triple is assembled once in `format.js`.
            empty: cards.length === 0,
            emptyState: cards.length === 0
                ? F.emptyState('board', envelope
                    ? 'empty.board.reason_no_scenarios'
                    : 'empty.board.reason_not_loaded')
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
