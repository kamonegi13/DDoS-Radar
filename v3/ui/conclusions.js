/**
 * Noroshi v3 L7 — the conclusion face, the derivation view, and what-if
 * (pure, DOM-free).
 *
 * Step ③ of the primary loop — "why do you say that, and what happened?" —
 * and step ④, "was the tool right?". P8 §7 splits v1's eleven-section
 * drilldown modal into two homes without losing a section: the Tier 1
 * conclusion face (what the tool concluded, and how sure) and the Tier 2
 * derivation view (the full chain: formula → effective thresholds →
 * contributions → observations → primary sources → prompt identity).
 *
 * Three things this module refuses to do:
 *
 * **It does not derive.** No threat level is computed, no score summed, no
 * threshold compared against a number this file knows. What-if in particular
 * is a DIFF of two server answers (C6 returns `baseline` and
 * `counterfactual`, both scored by the same L2 kernel), never a second
 * scoring engine — that was G-09, and the browser's copy had different
 * domain caps from the backend's, so it showed analysts differences that did
 * not exist.
 *
 * **It does not hide an absent section.** S1-UI-038: a section with no data
 * says "none", because a missing section and a missing value are different
 * failures and an omitted section is invisible. Every section this module
 * emits carries a `present` flag and an empty-reason key.
 *
 * **It does not treat an inability to conclude as nothing to show.** DP10
 * recorded that v1 gave inconclusive conclusions no route to a disclosure
 * surface at all — the one case where an analyst most needs to know why. The
 * face renders the unavailable reason, the guard that emitted it, and the
 * condition that would clear it, all of which the server discloses (R2's
 * `calibration_pending` block, R10's `unavailable_reason_registry`).
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiConclusions = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var F = (typeof require === 'function')
        ? require('./format')
        : (typeof window !== 'undefined' ? window.NoroshiFormat : null);

    //: The five outputs, in the order the tool definition names them.
    var CONCLUSION_TYPES = ['threat_level', 'trend', 'per_domain',
                            'anomaly', 'attack_mode'];

    //: The four analyst labels (C2's closed vocabulary).
    var LABELS = ['TRUE_POSITIVE', 'FALSE_POSITIVE',
                  'TRUE_NEGATIVE', 'FALSE_NEGATIVE'];

    // ── feedback interaction states (S1-UI-043 is the v3 reference form) ─
    var FB_IDLE = 'idle';
    var FB_NO_LABEL = 'no_label';
    var FB_SAVING = 'saving';
    var FB_SAVED = 'saved';
    var FB_REJECTED = 'rejected';
    var FB_NETWORK_ERROR = 'network_error';
    var FB_UNSUPPORTED = 'unsupported';
    var FEEDBACK_STATES = [FB_IDLE, FB_NO_LABEL, FB_SAVING, FB_SAVED,
                           FB_REJECTED, FB_NETWORK_ERROR, FB_UNSUPPORTED];

    // ── calibration ─────────────────────────────────────────────────────

    /**
     * The calibration warnings a conclusion must carry (S1-UI-039).
     *
     * Both warnings are server-sourced. "Degraded" is the server's own status
     * word — no number is compared here. The provisional-sample warning uses
     * `MIN_RECALL_DENOM`, the count R10 discloses as the point below which
     * the confusion cell is INSUFFICIENT_DATA; without R10 the module reports
     * that it cannot judge the sample rather than picking a count.
     */
    function calibrationNotes(calibrationStatus, thresholds) {
        var notes = [];
        var status = calibrationStatus || {};
        if (status.status === 'DEGRADED') {
            // NP1: a degraded calibration means real escalations are being
            // missed, and that belongs beside the conclusion, not in a panel.
            notes.push({ kind: 'degraded', severity: 'high',
                         labelKey: 'ui.conclusion.calibration.degraded',
                         value: status.recall === undefined ? null : status.recall });
        }
        var sampleN = typeof status.sample_n === 'number' ? status.sample_n : null;
        var floor = null;
        var floorSource = null;
        if (thresholds && thresholds.calibration
                && thresholds.calibration.MIN_RECALL_DENOM
                && typeof thresholds.calibration.MIN_RECALL_DENOM.value === 'number') {
            floor = thresholds.calibration.MIN_RECALL_DENOM.value;
            floorSource = 'R10:calibration.MIN_RECALL_DENOM';
        }
        if (sampleN !== null && sampleN > 0) {
            if (floor === null) {
                notes.push({ kind: 'sample_floor_undisclosed', severity: 'medium',
                             labelKey: 'ui.conclusion.calibration.floor_undisclosed',
                             value: sampleN, boundary: null, boundarySource: null });
            } else if (sampleN < floor) {
                notes.push({ kind: 'provisional', severity: 'medium',
                             labelKey: 'ui.conclusion.calibration.provisional',
                             value: sampleN, boundary: floor, boundarySource: floorSource });
            }
        }
        return notes;
    }

    // ── unavailability ──────────────────────────────────────────────────

    /**
     * Why this conclusion could not be reached, and what would clear it.
     *
     * The guard registry (R10 `unavailable_reason_registry`) pairs each
     * reason with the guard that emits it and the condition it tests. That
     * pairing is the whole of F-12's remedy — the four reasons used to be an
     * enum with three unreachable values, so "insufficient_data" meant
     * "something" and an analyst could not tell a dead feed from a quiet
     * world. Here the face shows which guard spoke.
     */
    function unavailability(conclusion, projection, registry) {
        var reason = conclusion ? conclusion.conclusion_unavailable_reason : null;
        if (!reason) return null;
        var guard = null;
        (registry || []).forEach(function (entry) {
            if (!guard && entry && entry.reason === reason) guard = entry;
        });
        var suppression = (conclusion && conclusion.suppression) || null;
        var resolution = null;
        if (projection && projection.calibration_pending
                && Array.isArray(projection.calibration_pending.types)
                && projection.calibration_pending.types.indexOf(
                    conclusion.conclusion_type) !== -1) {
            resolution = {
                daysRemaining: projection.calibration_pending.days_remaining,
                daysObserved: projection.calibration_pending.days_observed,
                windowDays: projection.calibration_pending.window_days,
                text: projection.calibration_pending.resolves_by || null,
            };
        }
        return {
            reason: reason,
            reasonKey: 'ui.conclusion.unavailable.' + reason,
            guardId: suppression ? (suppression.guard_id || null)
                : (guard ? guard.guard_id : null),
            guardCondition: guard ? (guard.condition || null) : null,
            detail: suppression ? (suppression.detail || null) : null,
            // Every guard that was consulted, not only the one that fired —
            // "why did the others not fire" is part of the derivation.
            evaluated: (suppression && Array.isArray(suppression.evaluated))
                ? suppression.evaluated.slice() : [],
            resolution: resolution,
        };
    }

    // ── the Tier 1 conclusion face ──────────────────────────────────────

    function _faceRow(conclusion, projection, thresholds, registry) {
        var unavailable = unavailability(conclusion, projection, registry);
        return {
            conclusionId: conclusion.id || null,
            type: conclusion.conclusion_type,
            typeKey: 'ui.conclusion.type.' + conclusion.conclusion_type,
            state: conclusion.state === undefined ? null : conclusion.state,
            confidence: typeof conclusion.confidence === 'number'
                ? conclusion.confidence : null,
            observedAt: typeof conclusion.observed_at === 'number'
                ? conclusion.observed_at : null,
            available: !unavailable,
            unavailable: unavailable,
            // P7 R2 puts calibration_status on ALL five types; v1 had it on
            // two. Absence is therefore reportable rather than expected.
            calibration: conclusion.calibration_status || null,
            calibrationNotes: calibrationNotes(conclusion.calibration_status, thresholds),
            formulaRef: conclusion.formula_ref || null,
            sourceUrls: (Array.isArray(conclusion.source_urls)
                ? conclusion.source_urls : []).map(function (url) {
                    return { raw: url, href: F.safeUrl(url) };
                }),
            llmPromptSha256: conclusion.llm_prompt_sha256 || null,
            inputHealth: conclusion.input_health || null,
            suppression: conclusion.suppression || null,
            // NP1: a conclusion published even though a guard fired is a
            // deliberate override, and the face must say so out loud.
            overridden: !!(conclusion.suppression
                && conclusion.suppression.overridden === true),
            metadata: conclusion.metadata || null,
            // TL is the only type whose state is a level; it is read, never
            // computed, and non-TL states are left as the server's words.
            tl: conclusion.conclusion_type === 'threat_level'
                ? F.tlBand(_intOrNull(conclusion.state)) : null,
        };
    }

    /**
     * Parse the TL the server sent. `parseInt` on the server's own string is
     * a read, not a derivation: nothing here decides what the level should
     * be, only what integer the server said it is.
     */
    function _intOrNull(value) {
        if (typeof value === 'number' && Number.isFinite(value)) return value;
        if (typeof value !== 'string') return null;
        if (!/^-?\d+$/.test(value.trim())) return null;
        return parseInt(value, 10);
    }

    /**
     * Build the conclusion face for one scenario.
     *
     * @param {object} input
     * @param {object|null} input.conclusions  R2 envelope
     * @param {object|null} input.thresholds   R10 `thresholds` block
     * @param {Array|null} input.reasonRegistry R10 `unavailable_reason_registry`
     * @returns {object}
     */
    function buildFace(input) {
        input = input || {};
        var envelope = input.conclusions || null;
        var list = (envelope && Array.isArray(envelope.conclusions))
            ? envelope.conclusions : [];
        var projection = envelope ? (envelope.projection || null) : null;
        if (envelope && envelope.calibration_pending && projection) {
            projection = Object.assign({}, projection,
                { calibration_pending: envelope.calibration_pending });
        }

        var byType = {};
        list.forEach(function (c) {
            if (!c || !c.conclusion_type) return;
            if (!byType[c.conclusion_type]) byType[c.conclusion_type] = [];
            byType[c.conclusion_type].push(
                _faceRow(c, projection, input.thresholds, input.reasonRegistry));
        });

        // Every one of the five types has a slot, always. A type the server
        // did not send at all is `missing`, which is not the same failure as
        // a type it sent with an unavailable reason — one is a gap in the
        // projection, the other is the tool declining to conclude.
        var sections = CONCLUSION_TYPES.map(function (type) {
            var rows = byType[type] || [];
            return {
                type: type,
                titleKey: 'ui.conclusion.type.' + type,
                present: rows.length > 0,
                rows: rows,
                emptyKey: rows.length ? null : 'ui.conclusion.section.missing',
            };
        });

        var unreadable = (projection && Array.isArray(projection.unreadable_rows))
            ? projection.unreadable_rows.slice() : [];

        return {
            scenarioId: envelope ? (envelope.scenario_id || null) : null,
            at: envelope && typeof envelope.at === 'number' ? envelope.at : null,
            isReplay: !!(envelope && typeof envelope.at === 'number'),
            observedAt: envelope && typeof envelope.observed_at === 'number'
                ? envelope.observed_at : null,
            disclaimer: envelope ? (envelope.final_judgment_disclaimer || null) : null,
            sections: sections,
            typesPresent: (projection && projection.types_present) || [],
            typesMissing: (projection && projection.types_missing) || [],
            // A row the server could not rebuild is a hole in the audit
            // trail; it is surfaced, not swallowed.
            unreadableRows: unreadable,
            empty: !envelope,
            emptyKey: envelope ? null : 'ui.conclusion.empty.not_loaded',
        };
    }

    // ── the Tier 2 derivation view ──────────────────────────────────────

    function _section(id, present, payload, emptyKey) {
        return {
            id: id,
            titleKey: 'ui.derivation.section.' + id,
            present: present,
            payload: present ? payload : null,
            emptyKey: present ? null : (emptyKey || 'ui.derivation.section.none'),
        };
    }

    /**
     * The full derivation chain, as ordered sections.
     *
     * Order is fixed and every section is emitted whether or not it has
     * content (S1-UI-038). The contribution matrix keeps suppressed rows
     * visible and marked (S1-UI-040) — "why it did NOT count" is part of the
     * derivation, and dropping those rows is how a suppression becomes
     * invisible.
     */
    function buildDerivation(input) {
        input = input || {};
        var envelope = input.derivation || null;
        var d = (envelope && envelope.derivation) || null;
        if (!d) {
            return {
                present: false, sections: [],
                emptyKey: 'ui.derivation.empty.not_loaded',
            };
        }
        var provenance = d.provenance || {};
        var suppression = d.suppression || null;
        var guards = Array.isArray(d.guards_evaluated) ? d.guards_evaluated : [];
        var sources = (Array.isArray(d.source_urls) ? d.source_urls : [])
            .map(function (url) { return { raw: url, href: F.safeUrl(url) }; });
        var thresholdRef = d.threshold_ref || {};
        var thresholdRows = Object.keys(thresholdRef).sort().map(function (key) {
            return { key: key, value: thresholdRef[key] };
        });
        var inputs = provenance.inputs || {};
        var inputRows = Object.keys(inputs).sort().map(function (key) {
            return { key: key, value: inputs[key] };
        });

        var sections = [
            _section('formula', !!d.formula_ref, {
                formulaRef: d.formula_ref,
                computedAt: provenance.computed_at === undefined
                    ? null : provenance.computed_at,
            }, 'ui.derivation.section.formula_unrecorded'),
            _section('inputs', inputRows.length > 0, { rows: inputRows }),
            _section('thresholds', thresholdRows.length > 0, { rows: thresholdRows }),
            _section('calibration', !!d.calibration_status, {
                status: d.calibration_status,
                notes: calibrationNotes(d.calibration_status, input.thresholds),
            }),
            _section('input_health', !!d.input_health, { health: d.input_health }),
            _section('guards', guards.length > 0 || !!suppression, {
                // The guard that spoke, plus every guard that was asked.
                fired: suppression,
                overridden: !!(suppression && suppression.overridden === true),
                evaluated: guards.length ? guards.slice()
                    : ((suppression && Array.isArray(suppression.evaluated))
                        ? suppression.evaluated.slice() : []),
            }),
            _section('sources', sources.length > 0, {
                sources: sources,
                sourceRefs: Array.isArray(provenance.source_refs)
                    ? provenance.source_refs.slice() : [],
            }),
            _section('llm_prompt', !!d.llm_prompt_sha256, {
                sha256: d.llm_prompt_sha256,
            }, 'ui.derivation.section.llm_unused'),
        ];

        return {
            present: true,
            conclusionId: d.conclusion_id || null,
            sections: sections,
            emptyKey: null,
        };
    }

    // ── what-if: a diff of two server answers, never a second engine ────

    function _scenarioDiff(scenarioId, base, cf) {
        function pick(result, key) {
            return result && typeof result[key] === 'number' ? result[key] : null;
        }
        var baseTl = pick(base, 'tl');
        var cfTl = pick(cf, 'tl');
        var baseSeverity = F.severityOf(baseTl);
        var cfSeverity = F.severityOf(cfTl);
        var domains = {};
        var domainNames = {};
        [base, cf].forEach(function (r) {
            Object.keys((r && r.domains) || {}).forEach(function (d) {
                domainNames[d] = true;
            });
        });
        Object.keys(domainNames).sort().forEach(function (d) {
            var a = base && base.domains ? base.domains[d] : null;
            var b = cf && cf.domains ? cf.domains[d] : null;
            domains[d] = {
                baseline: typeof a === 'number' ? a : null,
                counterfactual: typeof b === 'number' ? b : null,
                delta: (typeof a === 'number' && typeof b === 'number') ? b - a : null,
            };
        });
        return {
            scenarioId: scenarioId,
            tl: {
                baseline: baseTl, counterfactual: cfTl,
                baselineBand: F.tlBand(baseTl), counterfactualBand: F.tlBand(cfTl),
                // Severity delta, so "the counterfactual is worse" reads as
                // positive. Both numbers came from the server.
                severityDelta: (baseSeverity === null || cfSeverity === null)
                    ? null : cfSeverity - baseSeverity,
                changed: baseTl !== cfTl,
            },
            score: {
                baseline: pick(base, 'score'), counterfactual: pick(cf, 'score'),
                delta: (pick(base, 'score') === null || pick(cf, 'score') === null)
                    ? null : pick(cf, 'score') - pick(base, 'score'),
            },
            domains: domains,
            convergence: {
                baseline: base ? (base.convergence || null) : null,
                counterfactual: cf ? (cf.convergence || null) : null,
            },
        };
    }

    /**
     * Compare C6's two answers.
     *
     * Both halves were scored by the SAME backend kernel in one dry-run
     * request. This function subtracts them. It does not know what a domain
     * cap is, what a convergence bonus is worth, or how a score becomes a
     * threat level — which is precisely why it cannot disagree with the
     * backend the way v1's in-browser re-implementation did (G-09 / DP4).
     */
    function diffWhatIf(envelope) {
        if (!envelope || !envelope.baseline || !envelope.counterfactual) {
            return { present: false, scenarios: [],
                     emptyKey: 'ui.whatif.empty.not_run' };
        }
        var baseScenarios = envelope.baseline.scenarios || {};
        var cfScenarios = envelope.counterfactual.scenarios || {};
        var ids = {};
        Object.keys(baseScenarios).forEach(function (k) { ids[k] = true; });
        Object.keys(cfScenarios).forEach(function (k) { ids[k] = true; });
        var scenarios = Object.keys(ids).sort().map(function (sid) {
            return _scenarioDiff(sid, baseScenarios[sid], cfScenarios[sid]);
        });
        return {
            present: true,
            scenarios: scenarios,
            changed: scenarios.filter(function (s) { return s.tl.changed; }),
            overlay: envelope.overlay || null,
            baselineSettings: envelope.baseline.settings || null,
            counterfactualSettings: envelope.counterfactual.settings || null,
            emptyKey: scenarios.length ? null : 'ui.whatif.empty.no_scenarios',
        };
    }

    // ── feedback (step ④) ───────────────────────────────────────────────

    /**
     * The feedback form's interaction state.
     *
     * S1-UI-043 is named in D3 as the ONE surface in v1 where every outcome
     * of an operation was visible, and P8 keeps it as the reference form for
     * v3: five distinct outcomes, all shown inline, none of them a silent
     * console log. C2 additionally requires a non-empty reason (§7-2 #78), so
     * "no reason" is refused before the request rather than by the server.
     */
    function feedbackState(input) {
        input = input || {};
        if (input.conclusionId === null || input.conclusionId === undefined) {
            return { state: FB_UNSUPPORTED, canSubmit: false,
                     messageKey: 'ui.feedback.unsupported' };
        }
        if (input.inFlight === true) {
            return { state: FB_SAVING, canSubmit: false,
                     messageKey: 'ui.feedback.saving' };
        }
        if (input.networkError) {
            return { state: FB_NETWORK_ERROR, canSubmit: true,
                     messageKey: 'ui.feedback.network_error',
                     detail: input.networkError };
        }
        if (input.serverError) {
            return { state: FB_REJECTED, canSubmit: true,
                     messageKey: 'ui.feedback.rejected',
                     detail: input.serverError };
        }
        if (input.savedAt) {
            return { state: FB_SAVED, canSubmit: true,
                     messageKey: 'ui.feedback.saved', detail: null };
        }
        if (LABELS.indexOf(input.label) === -1) {
            return { state: FB_NO_LABEL, canSubmit: false,
                     messageKey: 'ui.feedback.no_label' };
        }
        if (typeof input.reason !== 'string' || !input.reason.trim()) {
            return { state: FB_NO_LABEL, canSubmit: false,
                     messageKey: 'ui.feedback.reason_required' };
        }
        return { state: FB_IDLE, canSubmit: true,
                 messageKey: 'ui.feedback.ready', detail: null };
    }

    /**
     * The label tally, always as counts per label plus the number of
     * analysts (S1-UI-043: never a single verdict — one analyst's opinion
     * must not look like consensus).
     */
    function labelTally(analystLabels) {
        var counts = {};
        LABELS.forEach(function (l) { counts[l] = 0; });
        var analysts = 0;
        Object.keys(analystLabels || {}).forEach(function (actorId) {
            var entry = analystLabels[actorId];
            if (!entry || LABELS.indexOf(entry.label) === -1) return;
            counts[entry.label] += 1;
            analysts += 1;
        });
        return { counts: counts, analysts: analysts, labels: LABELS.slice() };
    }

    return {
        buildFace: buildFace,
        buildDerivation: buildDerivation,
        diffWhatIf: diffWhatIf,
        calibrationNotes: calibrationNotes,
        unavailability: unavailability,
        feedbackState: feedbackState,
        labelTally: labelTally,
        CONCLUSION_TYPES: CONCLUSION_TYPES,
        LABELS: LABELS,
        FEEDBACK_STATES: FEEDBACK_STATES,
        FB_IDLE: FB_IDLE, FB_NO_LABEL: FB_NO_LABEL, FB_SAVING: FB_SAVING,
        FB_SAVED: FB_SAVED, FB_REJECTED: FB_REJECTED,
        FB_NETWORK_ERROR: FB_NETWORK_ERROR, FB_UNSUPPORTED: FB_UNSUPPORTED,
    };
});
