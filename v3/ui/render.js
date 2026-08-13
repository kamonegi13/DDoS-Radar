/**
 * Noroshi v3 L7 — HTML builders (pure, DOM-free).
 *
 * Every function here takes a view model and returns a string. None of them
 * touches the document, holds state, or fetches anything, so the markup an
 * analyst actually sees is testable under Node — which is the half of v1
 * that was never testable at all: radar.js built its HTML inline inside the
 * same functions that queried the DOM and drove the fetch layer, and so had
 * 0% coverage over fourteen thousand lines.
 *
 * Two rules hold throughout:
 *
 * **Everything external is escaped.** `esc()` wraps every interpolation of
 * a server-supplied value, in text position and attribute position alike.
 * Source URLs additionally go through `safeUrl`, which returns null for any
 * scheme other than http/https so the caller renders them as plain text
 * (S1-UI-041). Adapter output and LLM metadata are outside data.
 *
 * **No prose is written here.** Every visible word comes from the dictionary
 * via `_t(key)`; this file contains keys, never sentences (CLAUDE.md §1,
 * DP17). `tests/test_v3_ui_discipline.py` fails on Japanese text appearing
 * in any module but `strings.js`.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiRender = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var S = (typeof require === 'function')
        ? require('./strings')
        : (typeof window !== 'undefined' ? window.NoroshiStrings : null);
    var Fmt = (typeof require === 'function')
        ? require('./format')
        : (typeof window !== 'undefined' ? window.NoroshiFormat : null);
    var Fresh = (typeof require === 'function')
        ? require('./freshness')
        : (typeof window !== 'undefined' ? window.NoroshiFreshness : null);
    var Lane = (typeof require === 'function')
        ? require('./lane')
        : (typeof window !== 'undefined' ? window.NoroshiLane : null);
    var C = (typeof require === 'function')
        ? require('./conclusions')
        : (typeof window !== 'undefined' ? window.NoroshiConclusions : null);
    var Terms = (typeof require === 'function')
        ? require('./terms')
        : (typeof window !== 'undefined' ? window.NoroshiTerms : null);
    var _t = S.t;
    var esc = Fmt.escHtml;

    /**
     * An empty surface, in the three parts P9 §3.5 requires.
     *
     * Role, reason, fills-when — always all three, always in that order, and
     * never assembled here: the triple arrives from the view model, which is
     * the only layer that knows which server state produced it. The wrapper
     * varies because the same block has to sit inside an `<ol>`, a `<tbody>`
     * and a `<div>` without producing invalid markup; nothing else does.
     */
    function emptyStateHtml(state, options) {
        var opts = options || {};
        var body = '<span class="empty-role">'
            + esc(_t(state.roleKey)) + '</span>'
            + '<span class="empty-reason">'
            + esc(_t(state.reasonKey, state.reasonVars)) + '</span>'
            + '<span class="empty-fills">'
            + esc(_t(state.fillsWhenKey)) + '</span>';
        var attrs = ' class="empty empty-state" role="status"';
        if (opts.tag === 'li') return '<li' + attrs + '>' + body + '</li>';
        if (opts.tag === 'tr') {
            return '<tr class="empty"><td colspan="'
                + esc(String(opts.colspan || 1)) + '"'
                + ' class="empty-state" role="status">' + body + '</td></tr>';
        }
        return '<p' + attrs + '>' + body + '</p>';
    }

    function freshnessBadge(result) {
        var f = Fresh.freshnessOf({
            observedAt: result ? result.observedAt : null,
            now: Date.now() / 1000,
            fetchOk: result ? result.ok : false,
            errorCode: result && result.error ? result.error.code : null,
        });
        var age = Fmt.duration(f.ageSec);
        var detail = f.level === Fresh.FAILED
            ? _t('ui.freshness.failed_detail', {
                why: (result && result.error && (result.error.message || result.error.code))
                    || _t('ui.error.unknown'),
                age: _t(age.key, age.vars),
            })
            : _t('ui.freshness.age', { age: _t(age.key, age.vars) });
        return '<span class="freshness freshness-' + esc(f.level) + '" '
            + 'title="' + esc(_t('ui.freshness.boundaries', {
                aging: f.boundaries.aging_sec, stale: f.boundaries.stale_sec })) + '">'
            + esc(_t(f.labelKey)) + ' · ' + esc(detail)
            + (result && result.held
                ? ' <em>' + esc(_t('ui.freshness.held')) + '</em>' : '')
            + '</span>';
    }


    /**
     * The AP3 chip, plus a definition for whatever term is holding it down.
     *
     * The component rows live in a `title` attribute and cannot carry markup,
     * so the ⓘ goes beside the chip and defines the ONE term the fold's
     * reason names — recall, null-zone or drift. `ops_health` and
     * `freshness` are already Japanese on screen and need no gloss, so they
     * produce no marker rather than a marker with nothing to say.
     */
    function trustChipHtml(fold, terms) {
        var marks = Terms.markersOf(terms);
        var reason = fold.reason;
        var lines = fold.components.map(function (c) {
            return _t('ui.trust.tooltip_row', {
                name: _t(c.labelKey),
                state: _t(c.stateKey),
                value: c.value === null ? Fmt.ABSENT : Fmt.num(c.value, 3),
                boundary: c.boundary ? Fmt.num(c.boundary.value, 3) : Fmt.ABSENT,
                source: c.boundary ? c.boundary.source : Fmt.ABSENT,
            });
        });
        return '<button type="button" class="trust-chip trust-' + esc(fold.band) + '" '
            + 'id="trust-chip" aria-label="' + esc(_t(fold.labelKey)) + '" '
            + 'title="' + esc(_t(fold.formulaKey) + '\n' + lines.join('\n')) + '">'
            + '<span class="trust-band">' + esc(_t(fold.labelKey)) + '</span>'
            + '<span class="trust-reason">' + esc(_t(reason.labelKey)) + '</span>'
            + '</button>'
            + marks.mark(Terms.componentTerm(reason.componentId));
    }

    /**
     * The situation sentence (P9 §2 R-A), or the admission that none came.
     *
     * The template reference travels with the sentence, because a sentence
     * an analyst cannot trace is not a disclosure (NP6). Nothing is
     * composed here — see `board.js` `_summary`.
     */
    function boardSummaryHtml(summary) {
        if (!summary || !summary.supplied) {
            return '<span class="summary-unsupplied">'
                + esc(_t((summary && summary.unsuppliedKey)
                    || 'ui.board.summary.unsupplied')) + '</span>';
        }
        return '<span class="summary-text">' + esc(summary.text) + '</span>'
            + (summary.templateRef
                ? '<span class="summary-ref">' + esc(_t('ui.board.summary.template',
                    { ref: summary.templateRef })) + '</span>'
                : '');
    }

    /**
     * Which scenario the face below actually belongs to (P9 §3.2).
     *
     * Empty outside the scenario view. Inside it, the heading names the
     * scenario that was ASKED for and the notice — when there is one —
     * names the scenario that was SERVED. Never one label over the other's
     * numbers.
     */
    function faceScopeHtml(scope) {
        if (!scope || !scope.present) return '';
        return '<span class="scenario-head-name">'
            + esc(_t('ui.scenario.head', { scenario: scope.requestedLabel }))
            + '</span>'
            + (scope.noticeKey
                ? '<span class="scenario-head-notice">'
                  + esc(_t(scope.noticeKey, { requested: scope.requestedLabel,
                                              served: scope.servedLabel }))
                  + '</span>'
                : '');
    }

    /**
     * One scenario card (P9 §3.1).
     *
     * The TL block is the dominant element and the change line is a
     * sentence, in that order, because ① asks "has anything changed" and a
     * grid of equally-weighted chips answers it only after the analyst has
     * decoded twelve fields. Score, trend delta and coverage stay — they
     * are demoted, not dropped: P9 §7 is explicit that this slice adds no
     * display and removes none.
     *
     * `now` is a parameter rather than a call to the clock so the sentence
     * "last checked 2 hours ago" is reproducible under test.
     *
     * `terms` is the view's term-marker issuer (P9 §4). The FIRST card to
     * print a threat level carries the ⓘ that defines one; the first card
     * that cannot conclude carries the one for 結論不可, and so on. Passing
     * none renders no markers — which is what a builder called from a test
     * about something else should do.
     */
    function cardHtml(card, now, terms) {
        var marks = Terms.markersOf(terms);
        var tl = card.tl;
        var since = card.sinceLastCheck;
        var clock = typeof now === 'number' ? now : Date.now() / 1000;
        var domainBar = '';
        if (card.domains) {
            domainBar = '<ul class="domain-bar">' + card.domains.domains.map(function (d) {
                var width = d.fill === null ? 0 : Math.round(d.fill * 100);
                return '<li class="domain domain-' + esc(String(d.state || 'unknown')) + '">'
                    + '<span class="domain-name">' + esc(_t('ui.domain.' + d.domain)) + '</span>'
                    + '<span class="domain-track"><span class="domain-fill" '
                    + 'style="width:' + width + '%"></span></span>'
                    + '<span class="domain-value">' + esc(Fmt.num(d.score, 1)) + '</span>'
                    + '<span class="domain-state">' + esc(_t(d.stateKey)) + '</span>'
                    + '</li>';
            }).join('') + '</ul>';
        }
        var ago = Fmt.duration(since.seenAt === null || since.seenAt === undefined
            ? null : clock - since.seenAt);
        var resolution = card.resolution || null;
        var hint = resolution ? resolution.hint : null;
        var unavailableBlock = card.availability.sentenceKey
            ? '<p class="card-inconclusive">'
              + esc(_t(card.availability.sentenceKey))
              + marks.mark('inconclusive') + '</p>'
              + (resolution && resolution.labelKey
                  ? '<p class="card-resolution">' + esc(_t(resolution.labelKey, {
                      days: hint ? Fmt.num(hint.daysRemaining) : Fmt.ABSENT,
                      observed: hint ? Fmt.num(hint.daysObserved) : Fmt.ABSENT,
                      window: hint ? Fmt.num(hint.windowDays) : Fmt.ABSENT,
                  })) + '</p>'
                  : '')
            : '';
        // The participant strip (P9 §3.7, D-10): which countries this
        // scenario is about, hardest-coupled first. Also the accessible
        // twin of the board map — see `board.js::_participantStrip`.
        var strip = '';
        if (card.participants && card.participants.length) {
            strip = '<ul class="card-countries" aria-label="'
                + esc(_t('ui.board.participants_label')) + '">'
                + card.participants.map(function (p) {
                    return '<li class="cc'
                        + (p.isAdversary ? ' cc-adversary' : '')
                        + '" title="' + esc(p.country + ' — ' + _t(p.roleKey))
                        + '"><span class="cc-flag">' + esc(p.flag)
                        + '</span><span class="cc-iso">' + esc(p.country)
                        + '</span></li>';
                }).join('') + '</ul>';
        }
        var name = card.displayName || card.scenarioId;
        return '<article class="card card-' + esc(tl.band)
            + (card.focused ? ' card-focused' : '') + '" data-scenario="'
            + esc(card.scenarioId) + '">'
            + '<header class="card-head">'
            // The name is the way into the scenario face: the thing an
            // analyst points at to ask "what is going on here" is its name,
            // and a button is reachable from the keyboard where a clickable
            // <article> is not.
            + '<h3 class="card-title"><button type="button" class="card-open" '
            + 'data-open-scenario="' + esc(card.scenarioId) + '" title="'
            + esc(_t('ui.board.open_face', { id: card.scenarioId })) + '">'
            + esc(name) + '</button></h3>'
            + (card.focused
                ? '<span class="chip chip-focus">' + esc(_t('ui.board.focused')) + '</span>'
                : '<button type="button" class="focus-btn" data-focus="'
                  + esc(card.scenarioId) + '">' + esc(_t('ui.board.focus_here')) + '</button>')
            + '</header>'
            + '<div class="card-body">'
            + '<div class="card-tl" style="--tl-color: var(' + esc(tl.cssVar) + ')">'
            + '<span class="tl-value">' + esc(tl.tl === null ? Fmt.ABSENT : String(tl.tl))
            + '</span><span class="tl-label">' + esc(_t(tl.labelKey)) + '</span>'
            + '<span class="tl-caption">' + esc(_t('ui.board.tl_caption'))
            + marks.mark('tl') + '</span></div>'
            + '<div class="card-lines">'
            + '<p class="card-since">' + esc(_t(since.labelKey, {
                ago: _t(ago.key, ago.vars),
                delta: Fmt.signed(since.severityDelta),
                current: tl.tl === null ? Fmt.ABSENT : String(tl.tl),
                previous: since.previousTl === null ? Fmt.ABSENT : String(since.previousTl),
            }))
            // The change sentence is the only place on the board that prints
            // the word `severity`, and its direction is the opposite of the
            // TL beside it — which is exactly the confusion that inverted
            // calibration on 2026-08-02.
            + (since.seen ? marks.mark('severity') : '') + '</p>'
            + unavailableBlock
            + '<p class="card-meta">'
            + '<span class="card-availability">' + esc(_t(card.availability.labelKey))
            + '</span> <span class="card-trend"><span class="trend-glyph">'
            + esc(card.trend.glyph) + '</span> ' + esc(_t(card.trend.labelKey)) + ' '
            + esc(Fmt.signed(card.trend.delta)) + '</span> '
            + '<span class="card-score">'
            + esc(_t('ui.board.score', { score: Fmt.num(card.score, 2) }))
            + '</span></p>'
            + '</div></div>'
            + strip
            + domainBar
            + '<p class="card-coverage">' + esc(_t(card.coverage.labelKey, {
                mode: card.coverage.scoringMode || Fmt.ABSENT }))
            + marks.mark('scoring_mode') + '</p>'
            + '</article>';
    }


    function laneRowHtml(row, lane) {
        var basis = Lane.rankBasis(row, lane);
        var tip = _t('ui.lane.basis', {
            score: Fmt.num(basis.score, 3),
            novelty: Fmt.num(basis.factors.novelty, 3),
            confidence: Fmt.num(basis.factors.confidence_delta, 3),
            blindness: Fmt.num(basis.factors.analyst_blindness, 3),
            formula: basis.formulaRef || Fmt.ABSENT,
            snapshot: basis.snapshotId || Fmt.ABSENT,
        });
        // The sentence is the row (P9 §3.1 point 4). Rank and score are the
        // basis for the sentence being HERE rather than lower down, which
        // is a different question from what the row says — so they go to
        // the secondary line and the tooltip, where AP1's "the basis is
        // always visible" is still satisfied.
        return '<li class="lane-row" data-item="' + esc(row.itemId) + '">'
            + '<p class="lane-narrative">'
            + esc(row.narrative === null ? _t(row.narrativeMissingKey) : row.narrative)
            + '</p>'
            + '<p class="lane-meta">'
            + '<span class="lane-rank" title="' + esc(tip) + '">'
            + esc(_t('ui.lane.rank_label', {
                n: row.rankPosition === null ? Fmt.ABSENT : String(row.rankPosition) }))
            + (row.rankFallback
                ? '<em class="lane-rank-fallback">'
                  + esc(_t('ui.lane.rank_fallback')) + '</em>' : '')
            + '</span>'
            + '<span class="lane-scenario">' + esc(row.scenarioId || Fmt.ABSENT) + '</span>'
            + '</p>'
            + '<span class="lane-actions">'
            + (row.scenarioId
                ? '<button type="button" data-open-scenario="' + esc(row.scenarioId)
                  + '" data-item-open="' + esc(row.itemId) + '">'
                  + esc(_t('ui.lane.open')) + '</button>'
                : '<span class="lane-open-absent">'
                  + esc(_t('ui.lane.open_absent')) + '</span>')
            + '<button type="button" data-ack="' + esc(row.itemId) + '">'
            + esc(_t('ui.lane.ack')) + '</button>'
            + '<button type="button" data-snooze="' + esc(row.itemId) + '">'
            + esc(_t('ui.lane.snooze')) + '</button>'
            + '<button type="button" data-dismiss="' + esc(row.itemId) + '">'
            + esc(_t('ui.lane.dismiss')) + '</button>'
            + '</span></li>';
    }


    function calibrationHtml(row) {
        var notes = row.calibrationNotes.map(function (note) {
            return '<li class="calib-note calib-' + esc(note.severity) + '">'
                + esc(_t(note.labelKey, {
                    value: Fmt.num(note.value, 3),
                    boundary: note.boundary === null || note.boundary === undefined
                        ? Fmt.ABSENT : Fmt.num(note.boundary, 3),
                })) + '</li>';
        }).join('');
        var status = row.calibration || {};
        return '<div class="calibration">'
            + '<p>' + esc(_t('ui.conclusion.calibration.summary', {
                status: status.status || Fmt.ABSENT,
                recall: Fmt.num(status.recall, 3),
                precision: Fmt.num(status.precision, 3),
                n: status.sample_n === undefined ? Fmt.ABSENT : status.sample_n,
            })) + '</p>'
            + (notes ? '<ul class="calib-notes">' + notes + '</ul>' : '')
            + '</div>';
    }

    function unavailableHtml(u, terms) {
        var marks = Terms.markersOf(terms);
        var evaluated = u.evaluated.map(function (g) {
            return '<li class="guard guard-' + (g.fired ? 'fired' : 'quiet') + '">'
                + esc(_t('ui.conclusion.guard_row', {
                    guard: g.guard_id, reason: g.reason,
                    fired: _t(g.fired ? 'ui.yes' : 'ui.no'),
                    detail: g.detail || Fmt.ABSENT,
                })) + '</li>';
        }).join('');
        return '<div class="unavailable">'
            + '<p class="unavailable-reason">' + esc(_t(u.reasonKey))
            + marks.mark('inconclusive') + '</p>'
            + '<p class="unavailable-guard">' + esc(_t('ui.conclusion.guard', {
                guard: u.guardId || Fmt.ABSENT,
                condition: u.guardCondition || Fmt.ABSENT,
                detail: u.detail || Fmt.ABSENT,
            })) + '</p>'
            + (u.resolution
                ? '<p class="unavailable-resolution">'
                  + esc(_t('ui.conclusion.resolves', {
                      days: Fmt.num(u.resolution.daysRemaining, 1),
                      text: u.resolution.text || Fmt.ABSENT })) + '</p>'
                : '<p class="unavailable-resolution">'
                  + esc(_t('ui.conclusion.resolves_unknown')) + '</p>')
            + (evaluated ? '<ul class="guards">' + evaluated + '</ul>' : '')
            + '</div>';
    }

    function conclusionRowHtml(row, terms) {
        return '<div class="conclusion-row' + (row.available ? '' : ' conclusion-unavailable')
            + '" data-conclusion="' + esc(row.conclusionId || '') + '">'
            + '<p class="conclusion-state">'
            + esc(_t('ui.conclusion.state', {
                state: row.state === null ? Fmt.ABSENT : String(row.state),
                confidence: Fmt.num(row.confidence, 2),
            })) + '</p>'
            + (row.overridden
                ? '<p class="override">' + esc(_t('ui.conclusion.overridden')) + '</p>' : '')
            + (row.available ? '' : unavailableHtml(row.unavailable, terms))
            + calibrationHtml(row)
            + '<p class="conclusion-formula">' + esc(_t('ui.conclusion.formula', {
                ref: row.formulaRef || Fmt.ABSENT })) + '</p>'
            + '<ul class="sources">' + row.sourceUrls.map(function (u) {
                return '<li>' + (u.href
                    ? '<a href="' + esc(u.href) + '" rel="noopener noreferrer" '
                      + 'target="_blank">' + esc(u.raw) + '</a>'
                    : esc(u.raw)) + '</li>';
            }).join('') + '</ul>'
            + (row.conclusionId
                ? '<button type="button" class="derive-btn" data-derive="'
                  + esc(row.conclusionId) + '">' + esc(_t('ui.conclusion.why')) + '</button>'
                : '')
            + '</div>';
    }


    /**
     * The analyst-feedback form (step ④ of the loop).
     *
     * S1-UI-043 is named in D3 as the one surface in v1 where every outcome
     * of an operation was visible, and P8 keeps it as v3's reference form.
     * So: four labels and no fifth, a required reason, an optional evidence
     * URL, the tally always shown as per-label counts plus the number of
     * analysts who submitted (never a single verdict — one analyst's opinion
     * must not read as consensus), and the interaction state printed inline
     * whatever it is.
     */
    function feedbackFormHtml(conclusionId, tally, formState) {
        var counts = C.LABELS.map(function (label) {
            return '<li class="tally-row"><span class="tally-label">'
                + esc(_t('ui.feedback.label.' + label)) + '</span>'
                + '<span class="tally-count">' + esc(String(tally.counts[label]))
                + '</span></li>';
        }).join('');
        var buttons = C.LABELS.map(function (label) {
            return '<button type="button" class="label-btn" data-label-for="'
                + esc(conclusionId || '') + '" data-label="' + esc(label) + '">'
                + esc(_t('ui.feedback.label.' + label)) + '</button>';
        }).join('');
        return '<section class="feedback" data-feedback-for="'
            + esc(conclusionId || '') + '">'
            + '<h5>' + esc(_t('ui.feedback.title')) + '</h5>'
            + '<ul class="tally">' + counts + '</ul>'
            + '<p class="tally-analysts">' + esc(_t('ui.feedback.analysts',
                { n: tally.analysts })) + '</p>'
            + (conclusionId
                ? '<div class="feedback-form">' + buttons + '</div>'
                : '')
            + '<p class="feedback-state feedback-' + esc(formState.state) + '">'
            + esc(_t(formState.messageKey))
            + (formState.detail ? ' — ' + esc(String(formState.detail)) : '')
            + '</p></section>';
    }

    /** One derivation section. Empty sections still render, saying so. */
    function derivationSectionHtml(section) {
        var body = section.present
            ? '<pre class="derivation-payload">'
              + esc(JSON.stringify(section.payload, null, 2)) + '</pre>'
            : '<p class="empty">' + esc(_t(section.emptyKey)) + '</p>';
        return '<section class="derivation-section">'
            + '<h5>' + esc(_t(section.titleKey)) + '</h5>' + body + '</section>';
    }

    /**
     * One AP3 component row in the Tier 2 breakdown.
     *
     * This is where recall, null-zone and drift render as WORDS rather than
     * as a tooltip line, so this is where R-C attaches their definitions.
     */
    function trustComponentRowHtml(c, terms) {
        var marks = Terms.markersOf(terms);
        return '<tr class="trust-' + esc(c.band) + '">'
            + '<td>' + esc(_t(c.labelKey))
            + marks.mark(Terms.componentTerm(c.id)) + '</td>'
            + '<td>' + esc(_t(c.stateKey)) + '</td>'
            + '<td>' + esc(c.value === null ? Fmt.ABSENT : Fmt.num(c.value, 3)) + '</td>'
            + '<td>' + esc(c.boundary ? Fmt.num(c.boundary.value, 3) : Fmt.ABSENT) + '</td>'
            + '<td>' + esc(c.boundary ? c.boundary.source : Fmt.ABSENT) + '</td>'
            + '<td>' + esc(c.detail || Fmt.ABSENT) + '</td></tr>';
    }

    /** One sensor health row. Counts print absent, never "undefined". */
    function sensorRowHtml(s) {
        var silent = Fmt.duration(s.silent_for_sec);
        return '<tr><td>' + esc(s.sensor) + '</td>'
            + '<td>' + esc(s.domain || Fmt.ABSENT) + '</td>'
            + '<td>' + esc(Fmt.num(s.observation_count)) + '</td>'
            + '<td>' + esc(Fmt.num(s.fired_count)) + '</td>'
            + '<td>' + esc(Fmt.num(s.suppressed_count)) + '</td>'
            + '<td>' + esc(s.silent_for_sec === null || s.silent_for_sec === undefined
                ? Fmt.ABSENT : _t(silent.key, silent.vars)) + '</td></tr>';
    }

    /** One decision-ledger row (AP4). Read-only by construction. */
    function decisionRowHtml(d) {
        return '<tr><td>' + esc(Fmt.utcStamp(d.decided_at)) + '</td>'
            + '<td>' + esc(d.decision_type) + '</td>'
            + '<td>' + esc(d.action) + '</td>'
            + '<td>' + esc(d.target_id || Fmt.ABSENT) + '</td>'
            + '<td>' + esc(d.actor_id || _t('ui.decisions.automated')) + '</td>'
            + '<td>' + esc(d.reason || Fmt.ABSENT) + '</td></tr>';
    }

    /** One proposal. A terminal proposal offers no verbs. */
    function proposalRowHtml(p) {
        var terminal = p.is_terminal === true;
        return '<li class="proposal proposal-' + esc(p.state) + '">'
            + '<span class="proposal-kind">' + esc(p.proposal_type) + '</span>'
            + '<span class="proposal-target">' + esc(p.scenario_id || Fmt.ABSENT)
            + ' / ' + esc(p.target_country || Fmt.ABSENT) + '</span>'
            + '<span class="proposal-change">' + esc(_t('ui.proposals.change', {
                from: Fmt.num(p.prior_value, 3), to: Fmt.num(p.proposed_value, 3),
                n: p.sample_n === undefined ? Fmt.ABSENT : p.sample_n })) + '</span>'
            + '<span class="proposal-state">' + esc(p.state) + '</span>'
            + (terminal ? '' : '<span class="proposal-actions">'
                + '<button type="button" data-proposal-apply="' + esc(p.proposal_id)
                + '">' + esc(_t('ui.proposals.apply')) + '</button>'
                + '<button type="button" data-proposal-dismiss="' + esc(p.proposal_id)
                + '">' + esc(_t('ui.proposals.dismiss')) + '</button>'
                + '<button type="button" data-proposal-defer="' + esc(p.proposal_id)
                + '">' + esc(_t('ui.proposals.defer')) + '</button></span>')
            + '</li>';
    }

    /** One what-if diff row: two server answers, subtracted. */
    function whatIfRowHtml(s) {
        return '<tr class="' + (s.tl.changed ? 'whatif-changed' : '') + '">'
            + '<td>' + esc(s.scenarioId) + '</td>'
            + '<td>' + esc(s.tl.baseline === null ? Fmt.ABSENT : String(s.tl.baseline)) + '</td>'
            + '<td>' + esc(s.tl.counterfactual === null
                ? Fmt.ABSENT : String(s.tl.counterfactual)) + '</td>'
            + '<td>' + esc(Fmt.signed(s.tl.severityDelta)) + '</td>'
            + '<td>' + esc(Fmt.signed(s.score.delta, 2)) + '</td></tr>';
    }

    // ── the geographic face (P8 §6) ─────────────────────────────────────

    /**
     * One country marker. The role is the first visual dimension
     * (S1-UI-060) and the coupling weight is the second.
     *
     * The suppressed rows are listed with their reasons rather than folded
     * into a count: E-17's whole point is that "excluded" and "quiet" are
     * different observations, and a marker that showed only a number would
     * be back to reporting both as the same colour.
     */
    function geoMarkerHtml(marker) {
        var suppressed = marker.suppressed.map(function (s) {
            return '<li class="geo-suppressed-row">'
                + esc(_t('ui.geo.suppressed_row', {
                    sensor: s.sensor || Fmt.ABSENT,
                    domain: s.domain ? _t('ui.domain.' + s.domain) : Fmt.ABSENT,
                    reason: s.reason || Fmt.ABSENT,
                })) + '</li>';
        }).join('');
        var fired = marker.fired.map(function (f) {
            return '<li class="geo-fired-row">'
                + esc(_t('ui.geo.fired_row', {
                    sensor: f.sensor || Fmt.ABSENT,
                    domain: f.domain ? _t('ui.domain.' + f.domain) : Fmt.ABSENT,
                    score: Fmt.num(f.rawScore, 2),
                    confidence: Fmt.num(f.confidence, 2),
                })) + '</li>';
        }).join('');
        return '<li class="geo-marker geo-role-' + esc(marker.roleClass) + '" '
            + 'data-country="' + esc(marker.country) + '">'
            + '<span class="geo-country">' + esc(marker.country) + '</span>'
            + '<span class="geo-role">'
            + esc(marker.role ? _t('ui.geo.role.' + marker.role)
                : _t('ui.geo.role.unlisted'))
            + (marker.roleKnown ? ''
                : ' <em>' + esc(_t('ui.geo.role.unmapped')) + '</em>')
            + '</span>'
            + '<span class="geo-weight">' + esc(_t('ui.geo.weight', {
                weight: Fmt.num(marker.weight, 2) })) + '</span>'
            + (marker.isChainCountry
                ? '<span class="chip chip-chain">' + esc(_t('ui.geo.chain')) + '</span>' : '')
            + (marker.isAdversary
                ? '<span class="chip chip-adversary">'
                  + esc(_t('ui.geo.adversary')) + '</span>' : '')
            + '<span class="geo-state">' + esc(_t(marker.stateKey, {
                fired: marker.firedCount, suppressed: marker.suppressedCount,
                observations: marker.observations })) + '</span>'
            + (fired ? '<ul class="geo-fired">' + fired + '</ul>' : '')
            + (suppressed ? '<ul class="geo-suppressed">' + suppressed + '</ul>' : '')
            + '</li>';
    }

    // ── the country-tile map (P9 §3.4) ──────────────────────────────────

    /**
     * One country tile.
     *
     * The role is the ring, the domains that produced events are the dots,
     * and the ISO2 is printed beside the flag rather than replaced by it —
     * an emoji the platform cannot render must not be able to take the
     * country's identity with it.
     *
     * `aria-hidden` is applied to the whole grid by its container, not per
     * tile: the marker list below carries the same facts in the order
     * `geo.js` sorted them, and a screen reader should hear them once.
     */
    function geoTileHtml(tile) {
        var dots = tile.dots.map(function (dot) {
            return '<span class="tile-dot tile-dot-' + esc(dot.kind)
                + ' tile-domain-' + esc(dot.domain) + '"></span>';
        }).join('');
        var tip = _t('ui.geo.tile.tip', {
            country: tile.country,
            role: _t(tile.roleKey),
            state: _t(tile.stateKey, {
                fired: tile.firedCount,
                suppressed: tile.suppressedCount,
                observations: tile.observations,
            }),
        });
        return '<li class="geo-tile geo-role-' + esc(tile.roleClass)
            + (tile.hasEvents ? ' geo-tile-events' : '')
            + (tile.isAdversary ? ' geo-tile-adversary' : '')
            + (tile.isChainCountry ? ' geo-tile-chain' : '')
            + '" data-country="' + esc(tile.country) + '"'
            + (tile.placed
                ? ' style="grid-column:' + esc(String(tile.col))
                  + ';grid-row:' + esc(String(tile.row)) + '"'
                : '')
            + ' title="' + esc(tip) + '">'
            + '<span class="tile-flag">' + esc(tile.flag) + '</span>'
            + '<span class="tile-iso">' + esc(tile.country) + '</span>'
            + '<span class="tile-dots">' + dots + '</span>'
            + '</li>';
    }

    /**
     * The whole grid: one block per region that has a participant, then the
     * spillover row for countries the placement table does not know.
     *
     * The spillover row is not an error state — it is the map admitting that
     * a frontend asset is behind the deployment data, which G-17 says must
     * be visible rather than silently dropped.
     */
    function geoTileMapHtml(map) {
        var blocks = map.regions.map(function (region) {
            return '<section class="geo-region" data-region="' + esc(region.id) + '">'
                + '<h5 class="geo-region-name">' + esc(_t(region.labelKey)) + '</h5>'
                + '<ul class="geo-region-grid" style="grid-template-columns:repeat('
                + esc(String(region.columns)) + ',1fr);grid-template-rows:repeat('
                + esc(String(region.rows)) + ',auto)">'
                + region.tiles.map(geoTileHtml).join('')
                + '</ul></section>';
        }).join('');
        var spill = map.spillover.present
            ? '<section class="geo-region geo-region-unplaced" data-region="unplaced">'
              + '<h5 class="geo-region-name">'
              + esc(_t(map.spillover.labelKey)) + '</h5>'
              + '<p class="hint">' + esc(_t(map.spillover.noteKey)) + '</p>'
              + '<ul class="geo-region-grid geo-region-grid-flow">'
              + map.spillover.tiles.map(geoTileHtml).join('')
              + '</ul></section>'
            : '';
        return blocks + spill;
    }

    /**
     * One tile of the situation view's scenario map (P9 §2.2 R-F).
     *
     * The tile's colour is `--bm-color`, the CSS variable of the most
     * severe scenario the country participates in — supplied by
     * `board_map.js`, which did the severity comparison in the one module
     * allowed to (through `format.js`). The tooltip lists every scenario
     * the country belongs to; `data-map-scenarios` carries the same list
     * for the card-hover highlight, space-separated so
     * `[data-map-scenarios~="id"]` matches.
     */
    function bmTileHtml(tile) {
        var tip = tile.memberships.map(function (m) {
            var line = m.tl.tl === null
                ? _t('ui.board_map.membership_null', { name: m.displayName })
                : _t('ui.board_map.membership', {
                    name: m.displayName, tl: String(m.tl.tl) });
            return line
                + (m.isAdversary ? _t('ui.board_map.adversary_suffix') : '');
        }).join('\n');
        return '<li class="geo-tile bm-tile bm-band-' + esc(tile.band)
            + (tile.isAdversary ? ' geo-tile-adversary' : '')
            + (tile.hasFocused ? ' bm-tile-focused' : '')
            + '" data-country="' + esc(tile.country) + '"'
            + ' data-map-scenarios="' + esc(tile.scenarioIds.join(' ')) + '"'
            + ' style="' + (tile.placed
                ? 'grid-column:' + esc(String(tile.col))
                  + ';grid-row:' + esc(String(tile.row)) + ';'
                : '')
            + '--bm-color: var(' + esc(tile.cssVar) + ')"'
            + ' title="' + esc(tip) + '">'
            + '<span class="tile-flag">' + esc(tile.flag) + '</span>'
            + '<span class="tile-iso">' + esc(tile.country) + '</span>'
            + (tile.membershipCount > 1
                ? '<span class="bm-multi">' + esc(String(tile.membershipCount))
                  + '</span>'
                : '')
            + '</li>';
    }

    /**
     * The whole-board scenario map. Same regional skeleton as the scenario
     * face's `geoTileMapHtml` — one block per region that has a
     * participant, spillover for countries the placement table does not
     * know — but the tiles carry scenario membership and TL colour instead
     * of event dots (events are R2's, and R2 serves the focused scenario
     * only).
     */
    function boardMapHtml(map) {
        var blocks = map.regions.map(function (region) {
            return '<section class="geo-region" data-region="'
                + esc(region.id) + '">'
                + '<h5 class="geo-region-name">' + esc(_t(region.labelKey))
                + '</h5>'
                + '<ul class="geo-region-grid" style="grid-template-columns:repeat('
                + esc(String(region.columns)) + ',1fr);grid-template-rows:repeat('
                + esc(String(region.rows)) + ',auto)">'
                + region.tiles.map(bmTileHtml).join('')
                + '</ul></section>';
        }).join('');
        var spill = map.spillover.present
            ? '<section class="geo-region geo-region-unplaced" data-region="unplaced">'
              + '<h5 class="geo-region-name">'
              + esc(_t(map.spillover.labelKey)) + '</h5>'
              + '<p class="hint">' + esc(_t(map.spillover.noteKey)) + '</p>'
              + '<ul class="geo-region-grid geo-region-grid-flow">'
              + map.spillover.tiles.map(bmTileHtml).join('')
              + '</ul></section>'
            : '';
        return blocks + spill;
    }

    /** One layer toggle. An unserved layer says what it is waiting for. */
    function geoLayerHtml(layer, on) {
        if (!layer.available) {
            return '<li class="geo-layer geo-layer-unserved">'
                + '<span>' + esc(_t('ui.geo.layer.' + layer.id)) + '</span>'
                + '<em>' + esc(_t(layer.unavailableKey)) + '</em></li>';
        }
        return '<li class="geo-layer"><label>'
            + '<input type="checkbox" data-geo-layer="' + esc(layer.id) + '"'
            + (on ? ' checked' : '') + '>'
            + '<span>' + esc(_t('ui.geo.layer.' + layer.id)) + '</span>'
            + '</label></li>';
    }

    // ── SETTINGS (S1-UI-067〜070) ───────────────────────────────────────

    /**
     * One registry key.
     *
     * Four badge systems, each filled from something R14 states: which
     * layer won, whether the environment holds the key at all, who reads
     * it, and that it is variable. Nothing here is inferred — a badge the
     * server did not supply is not drawn (see `settings.js` on the retired
     * TIMING and IMPACT badges).
     */
    function settingsRowHtml(row) {
        var input = row.widget.kind === 'toggle'
            ? '<input type="checkbox" data-setting-key="' + esc(row.key) + '"'
              + (row.value === true ? ' checked' : '') + '>'
            : '<input type="number" data-setting-key="' + esc(row.key) + '" '
              + 'value="' + esc(row.valueText === null ? '' : row.valueText) + '"'
              + (row.widget.integerOnly ? ' step="1"' : '') + '>';
        return '<tr class="setting setting-' + esc(row.source || 'unknown') + '" '
            + 'data-setting-row="' + esc(row.key) + '">'
            + '<td class="setting-key"><code>' + esc(row.key) + '</code>'
            + '<p class="setting-why">' + esc(row.why || Fmt.ABSENT) + '</p></td>'
            + '<td class="setting-badges">'
            + '<span class="badge badge-source">' + esc(_t(row.sourceKey)) + '</span>'
            + '<span class="badge badge-env">' + esc(_t(row.envKey)) + '</span>'
            + '<span class="badge badge-consumer" title="'
            + esc(_t('ui.settings.consumer_tip')) + '">'
            + esc(row.consumer || Fmt.ABSENT) + '</span>'
            + '<span class="badge badge-writable">'
            + esc(_t('ui.settings.writable')) + '</span></td>'
            + '<td class="setting-value">' + input
            + '<span class="setting-unit">' + esc(row.unit || Fmt.ABSENT) + '</span></td>'
            + '<td class="setting-default">' + esc(row.defaultText === null
                ? Fmt.ABSENT : row.defaultText) + '</td>'
            + '<td class="setting-override">' + esc(row.override
                ? _t('ui.settings.override_by', {
                    actor: row.overrideActor || Fmt.ABSENT,
                    reason: row.overrideReason || Fmt.ABSENT,
                    at: Fmt.utcStamp(row.overrideAt) })
                : _t('ui.settings.no_override')) + '</td>'
            + '<td class="setting-actions">'
            + '<button type="button" data-setting-save="' + esc(row.key) + '">'
            + esc(_t('ui.settings.save')) + '</button>'
            + '<button type="button" data-setting-clear="' + esc(row.key) + '"'
            + (row.source === 'override' ? '' : ' disabled') + '>'
            + esc(_t('ui.settings.clear')) + '</button>'
            + '<span class="setting-result" data-setting-result="'
            + esc(row.key) + '"></span></td></tr>';
    }

    /** One ground-truth assertion (C9g). Read-only: C9p is not on this screen. */
    function groundTruthRowHtml(entry) {
        var row = entry.entry || {};
        return '<tr><td>' + esc(entry.scenarioId) + '</td>'
            + '<td>' + esc(Fmt.utcStamp(row.observed_at)) + '</td>'
            + '<td>' + esc(row.label || Fmt.ABSENT) + '</td>'
            + '<td>' + esc(row.actor_id || Fmt.ABSENT) + '</td>'
            + '<td>' + esc(row.source_url || row.reason || Fmt.ABSENT) + '</td></tr>';
    }

    // ── live channel and presentation state ─────────────────────────────

    /**
     * The connection chip (S1-UI-011), with one state more than the clause.
     *
     * `unmounted` is not `disconnected`. Saying "disconnected" about a
     * deployment that declares no channel is a false alarm, and a chip that
     * cries wolf is a chip an analyst stops reading — which costs the two
     * states that matter.
     */
    function liveChipHtml(live) {
        var detail = live.serverReason
            ? _t('ui.live.server_reason', { why: live.serverReason }) : '';
        return '<span class="live-chip live-' + esc(live.connection) + '" '
            + 'title="' + esc(_t(live.reasonKey) + (detail ? '\n' + detail : '')
                + '\n' + _t('ui.live.polling_continues')) + '">'
            + esc(_t('ui.live.state.' + live.connection))
            + (live.subscribed
                ? ' · ' + esc(live.subscribed) : '')
            + '</span>';
    }

    /** The display-mode chip. Its reason is always on it (NP6, S1-UI-030). */
    function modeChipHtml(decision) {
        return '<span class="mode-chip mode-' + esc(decision.mode) + '" '
            + 'title="' + esc(_t(decision.reasonKey, decision.reasonVars)) + '">'
            + esc(_t('ui.mode.' + decision.mode)) + '</span>';
    }

    return {
        freshnessBadge: freshnessBadge,
        trustChipHtml: trustChipHtml,
        boardSummaryHtml: boardSummaryHtml,
        faceScopeHtml: faceScopeHtml,
        emptyStateHtml: emptyStateHtml,
        geoMarkerHtml: geoMarkerHtml,
        geoTileHtml: geoTileHtml,
        geoTileMapHtml: geoTileMapHtml,
        bmTileHtml: bmTileHtml,
        boardMapHtml: boardMapHtml,
        geoLayerHtml: geoLayerHtml,
        settingsRowHtml: settingsRowHtml,
        groundTruthRowHtml: groundTruthRowHtml,
        liveChipHtml: liveChipHtml,
        modeChipHtml: modeChipHtml,
        cardHtml: cardHtml,
        laneRowHtml: laneRowHtml,
        calibrationHtml: calibrationHtml,
        unavailableHtml: unavailableHtml,
        conclusionRowHtml: conclusionRowHtml,
        feedbackFormHtml: feedbackFormHtml,
        derivationSectionHtml: derivationSectionHtml,
        trustComponentRowHtml: trustComponentRowHtml,
        sensorRowHtml: sensorRowHtml,
        decisionRowHtml: decisionRowHtml,
        proposalRowHtml: proposalRowHtml,
        whatIfRowHtml: whatIfRowHtml,
    };
});
