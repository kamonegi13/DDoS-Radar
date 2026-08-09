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

    var _t = S.t;
    var esc = Fmt.escHtml;

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


    function trustChipHtml(fold) {
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
            + '</button>';
    }

    function cardHtml(card) {
        var tl = card.tl;
        var since = card.sinceLastCheck;
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
        return '<article class="card card-' + esc(tl.band)
            + (card.focused ? ' card-focused' : '') + '" data-scenario="'
            + esc(card.scenarioId) + '">'
            + '<header class="card-head">'
            + '<h3 class="card-title">' + esc(card.scenarioId) + '</h3>'
            + (card.focused
                ? '<span class="chip chip-focus">' + esc(_t('ui.board.focused')) + '</span>'
                : '<button type="button" class="focus-btn" data-focus="'
                  + esc(card.scenarioId) + '">' + esc(_t('ui.board.focus_here')) + '</button>')
            + '</header>'
            + '<div class="card-tl" style="--tl-color: var(' + esc(tl.cssVar) + ')">'
            + '<span class="tl-value">' + esc(tl.tl === null ? Fmt.ABSENT : String(tl.tl))
            + '</span><span class="tl-label">' + esc(_t(tl.labelKey)) + '</span></div>'
            + '<p class="card-availability">' + esc(_t(card.availability.labelKey)) + '</p>'
            + '<p class="card-trend"><span class="trend-glyph">' + esc(card.trend.glyph)
            + '</span> ' + esc(_t(card.trend.labelKey)) + ' '
            + esc(Fmt.signed(card.trend.delta)) + '</p>'
            + '<p class="card-since">' + esc(_t(since.labelKey, {
                delta: Fmt.signed(since.severityDelta),
                previous: since.previousTl === null ? Fmt.ABSENT : String(since.previousTl),
            })) + '</p>'
            + '<p class="card-score">' + esc(_t('ui.board.score', { score: Fmt.num(card.score, 2) }))
            + '</p>'
            + domainBar
            + '<p class="card-coverage">' + esc(_t(card.coverage.labelKey, {
                mode: card.coverage.scoringMode || Fmt.ABSENT })) + '</p>'
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
        return '<li class="lane-row" data-item="' + esc(row.itemId) + '">'
            + '<span class="lane-rank" title="' + esc(tip) + '">'
            + esc(row.rankPosition === null ? Fmt.ABSENT : String(row.rankPosition))
            + (row.rankFallback
                ? '<em class="lane-rank-fallback">'
                  + esc(_t('ui.lane.rank_fallback')) + '</em>' : '')
            + '</span>'
            + '<span class="lane-scenario">' + esc(row.scenarioId || Fmt.ABSENT) + '</span>'
            + '<span class="lane-narrative">'
            + esc(row.narrative === null ? _t(row.narrativeMissingKey) : row.narrative)
            + '</span>'
            + '<span class="lane-actions">'
            + '<button type="button" data-open="' + esc(row.itemId) + '">'
            + esc(_t('ui.lane.open')) + '</button>'
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

    function unavailableHtml(u) {
        var evaluated = u.evaluated.map(function (g) {
            return '<li class="guard guard-' + (g.fired ? 'fired' : 'quiet') + '">'
                + esc(_t('ui.conclusion.guard_row', {
                    guard: g.guard_id, reason: g.reason,
                    fired: _t(g.fired ? 'ui.yes' : 'ui.no'),
                    detail: g.detail || Fmt.ABSENT,
                })) + '</li>';
        }).join('');
        return '<div class="unavailable">'
            + '<p class="unavailable-reason">' + esc(_t(u.reasonKey)) + '</p>'
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

    function conclusionRowHtml(row) {
        return '<div class="conclusion-row' + (row.available ? '' : ' conclusion-unavailable')
            + '" data-conclusion="' + esc(row.conclusionId || '') + '">'
            + '<p class="conclusion-state">'
            + esc(_t('ui.conclusion.state', {
                state: row.state === null ? Fmt.ABSENT : String(row.state),
                confidence: Fmt.num(row.confidence, 2),
            })) + '</p>'
            + (row.overridden
                ? '<p class="override">' + esc(_t('ui.conclusion.overridden')) + '</p>' : '')
            + (row.available ? '' : unavailableHtml(row.unavailable))
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

    /** One AP3 component row in the Tier 2 breakdown. */
    function trustComponentRowHtml(c) {
        return '<tr class="trust-' + esc(c.band) + '">'
            + '<td>' + esc(_t(c.labelKey)) + '</td>'
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
        geoMarkerHtml: geoMarkerHtml,
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
