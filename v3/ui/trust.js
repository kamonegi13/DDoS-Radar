/**
 * Noroshi v3 L7 — the AP3 composite confidence chip (pure, DOM-free).
 *
 * AP3 asks for one thing: the analyst can tell in seconds how far to trust
 * this tool right now. v1 answered it with twelve chips across HUD Row 3,
 * which is a reading task, not a glance — and every one of their good/warn/
 * crit boundaries was a literal in the browser (P5 O-13), so the standard by
 * which the tool judged itself lived nowhere an analyst could inspect.
 *
 * P8 §4 replaces the twelve with one chip carrying:
 *
 *     trust = min(recall, null-zone, drift, ops-health, freshness)
 *
 * where `min` is worst-wins over a three-band lattice. NP1 is the reason:
 * if one leg is doubtful, doubt the whole thing. The twelve indicators are
 * not deleted — they move to the Tier 2 self-evaluation detail. What is
 * deleted is their permanent occupation of the screen.
 *
 * Two rules make this module honest rather than merely shorter:
 *
 * **No boundary is declared here.** Every threshold is read out of a server
 * response and echoed back in the component's `boundary` block with the
 * field it came from. When the server has not disclosed a boundary, the
 * component reports `boundary_undisclosed` and sits on the middle band —
 * it does not fall back to a number this file happens to know. That is the
 * whole of P5 O-13's remedy: the frontend cannot drift from the backend
 * about what "healthy" means, because it does not have an opinion.
 *
 * **Absence is never health.** A component can be `unsupplied` (the server
 * does not serve it at all — today, L5's five liveness monitors) or
 * `unmeasurable` (served, but null, with the server's own reason). Both
 * land on the middle band and both keep their distinction, because F-12 was
 * four unavailability reasons of which three had no generation path, and an
 * analyst could not tell "the feeds are down" from "the world is quiet".
 * Neither state may ever fold to TRUSTED.
 *
 * Loaded as a plain script in the v3 shell (window.NoroshiTrust) and via
 * require() in tests.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiTrust = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ── the three bands (P8 §4) ─────────────────────────────────────────
    var TRUSTED = 'trusted';     // blue   — read the conclusions normally
    var RESERVED = 'reserved';   // amber  — read them with the stated reserve
    var DISTRUST = 'distrust';   // red    — do not act on the conclusions

    //: Severity order. Higher wins the fold.
    var _RANK = { trusted: 0, reserved: 1, distrust: 2 };

    // ── component states ────────────────────────────────────────────────
    var MEASURED = 'measured';
    var UNMEASURABLE = 'unmeasurable';           // served as null, with a reason
    var UNSUPPLIED = 'unsupplied';               // the server serves no such field
    var BOUNDARY_UNDISCLOSED = 'boundary_undisclosed';   // measured, but against what?

    /**
     * The five components of P8 §4's fold, in declaration order.
     * Declaration order is also the tie-break when two components share the
     * worst band, so the reason slot is reproducible (AP2).
     */
    var COMPONENT_IDS = ['recall', 'null_zone', 'drift', 'ops_health', 'freshness'];

    function worstBand(bands) {
        if (!bands || !bands.length) {
            // Nothing to fold is not the same as nothing wrong. An empty
            // component set means the fold has no evidence at all, which is
            // exactly the case NP1 says to treat as doubtful.
            return RESERVED;
        }
        var worst = TRUSTED;
        for (var i = 0; i < bands.length; i += 1) {
            if (_RANK[bands[i]] > _RANK[worst]) worst = bands[i];
        }
        return worst;
    }

    function _num(value) {
        return typeof value === 'number' && Number.isFinite(value) ? value : null;
    }

    function _component(id, fields) {
        var out = {
            id: id,
            band: fields.band,
            state: fields.state,
            value: fields.value === undefined ? null : fields.value,
            unit: fields.unit || null,
            detail: fields.detail === undefined ? null : fields.detail,
            boundary: fields.boundary || null,
            labelKey: 'ui.trust.component.' + id,
            stateKey: 'ui.trust.state.' + fields.state,
        };
        return out;
    }

    /** Read a `{value, unit, provenance_ref}` disclosure out of R10. */
    function _disclosed(thresholds, group, name) {
        if (!thresholds || typeof thresholds !== 'object') return null;
        var groupObj = thresholds[group];
        if (!groupObj || typeof groupObj !== 'object') return null;
        var entry = groupObj[name];
        if (!entry || typeof entry !== 'object') return null;
        var value = _num(entry.value);
        if (value === null) return null;
        return {
            value: value,
            unit: entry.unit || null,
            provenance_ref: entry.provenance_ref || null,
            source: 'R10:' + group + '.' + name,
        };
    }

    function _served(value, unit, source) {
        var n = _num(value);
        if (n === null) return null;
        return { value: n, unit: unit || null, provenance_ref: null, source: source };
    }

    // ── the five components ─────────────────────────────────────────────
    //
    // Each takes the server payloads and returns a component record. None of
    // them contains a numeric literal used as a threshold; every comparison
    // is against a `boundary` that arrived from R7 or R10.

    function _recall(selfEval, thresholds) {
        var boundary = _disclosed(thresholds, 'calibration', 'DEGRADED_RECALL_FLOOR');
        var calibration = selfEval && selfEval.calibration;
        if (!calibration || !Object.prototype.hasOwnProperty.call(calibration, 'recall')) {
            return _component('recall', {
                band: RESERVED, state: UNSUPPLIED, boundary: boundary,
                detail: null, unit: 'ratio',
            });
        }
        var value = _num(calibration.recall);
        if (value === null) {
            return _component('recall', {
                band: RESERVED, state: UNMEASURABLE, boundary: boundary,
                detail: calibration.recall_error || null, unit: 'ratio',
            });
        }
        if (!boundary) {
            return _component('recall', {
                band: RESERVED, state: BOUNDARY_UNDISCLOSED, value: value,
                boundary: null, unit: 'ratio',
            });
        }
        // The server states that `recall == floor` is OK, so the failing
        // comparison is strictly-below.
        return _component('recall', {
            band: value < boundary.value ? DISTRUST : TRUSTED,
            state: MEASURED, value: value, boundary: boundary, unit: 'ratio',
        });
    }

    function _drift(selfEval, thresholds) {
        var boundary = _disclosed(thresholds, 'calibration', 'DESIGN_W_MAX_DROP');
        var calibration = selfEval && selfEval.calibration;
        if (!calibration || !Object.prototype.hasOwnProperty.call(calibration, 'drift')) {
            return _component('drift', {
                band: RESERVED, state: UNSUPPLIED, boundary: boundary, unit: 'ratio',
            });
        }
        var value = _num(calibration.drift);
        if (value === null) {
            return _component('drift', {
                band: RESERVED, state: UNMEASURABLE, boundary: boundary,
                detail: calibration.drift_error || null, unit: 'ratio',
            });
        }
        if (!boundary) {
            return _component('drift', {
                band: RESERVED, state: BOUNDARY_UNDISCLOSED, value: value,
                boundary: null, unit: 'ratio',
            });
        }
        // S5-VERIF-038: `drop == max_drop` is on the passing side.
        return _component('drift', {
            band: value > boundary.value ? DISTRUST : TRUSTED,
            state: MEASURED, value: value, boundary: boundary, unit: 'ratio',
        });
    }

    function _nullZone(selfEval) {
        var nz = selfEval && selfEval.null_zone;
        if (!nz || typeof nz !== 'object') {
            return _component('null_zone', {
                band: RESERVED, state: UNSUPPLIED, unit: 's',
            });
        }
        var boundary = _served(nz.threshold_sec, 's',
                               'R7:self_eval.null_zone.threshold_sec');
        var scenarios = Array.isArray(nz.scenarios) ? nz.scenarios : [];
        var longest = scenarios.reduce(function (acc, s) {
            var span = _num(s && s.longest_span_sec);
            return span !== null && span > acc ? span : acc;
        }, 0);
        if (nz.any_chronic === true) {
            // NP5+8: a transient inability to conclude is allowed; a chronic
            // one is a design failure, and the chip says so in red.
            return _component('null_zone', {
                band: DISTRUST, state: MEASURED, value: longest,
                boundary: boundary, unit: 's',
                detail: scenarios.filter(function (s) { return s && s.is_chronic; })
                    .map(function (s) { return s.scenario_id; }).join(',') || null,
            });
        }
        var ongoing = scenarios.filter(function (s) { return s && s.ongoing === true; });
        if (ongoing.length) {
            return _component('null_zone', {
                band: RESERVED, state: MEASURED, value: longest,
                boundary: boundary, unit: 's',
                detail: ongoing.map(function (s) { return s.scenario_id; }).join(','),
            });
        }
        return _component('null_zone', {
            band: TRUSTED, state: MEASURED, value: longest,
            boundary: boundary, unit: 's',
        });
    }

    function _freshness(selfEval) {
        var data = selfEval && selfEval.data;
        if (!data || typeof data !== 'object'
                || !Object.prototype.hasOwnProperty.call(data, 'data_age_sec')) {
            return _component('freshness', {
                band: RESERVED, state: UNSUPPLIED, unit: 's',
            });
        }
        var boundary = _served(data.max_freshness_horizon_sec, 's',
                               'R7:self_eval.data.max_freshness_horizon_sec');
        var value = _num(data.data_age_sec);
        if (value === null) {
            return _component('freshness', {
                band: RESERVED, state: UNMEASURABLE, boundary: boundary, unit: 's',
                detail: null,
            });
        }
        if (!boundary) {
            return _component('freshness', {
                band: RESERVED, state: BOUNDARY_UNDISCLOSED, value: value,
                boundary: null, unit: 's',
            });
        }
        return _component('freshness', {
            band: value > boundary.value ? DISTRUST : TRUSTED,
            state: MEASURED, value: value, boundary: boundary, unit: 's',
        });
    }

    /**
     * L5's liveness monitors, heartbeat, backup age and LLM health.
     *
     * SERVED since WP-4.1g. R7 now carries `ops_health` on every response:
     * four named monitors (backup, capacity, l5_checks, llm_health) with a
     * verdict each, folded worst-wins on the server. Two of them v3 can
     * answer today and two it cannot, and the block says which — so the
     * chip reads MEASURED-reserved with a named cause instead of
     * UNSUPPLIED. The UNSUPPLIED branch stays because a deployment can
     * still be composed without the block, and "the field is absent" and
     * "the monitor is absent" are different facts.
     *
     * The chip still folds nothing itself: `worst_band` arrives decided.
     */
    function _opsHealth(selfEval) {
        var ops = selfEval && selfEval.ops_health;
        if (!ops || typeof ops !== 'object') {
            return _component('ops_health', {
                band: RESERVED, state: UNSUPPLIED, unit: null,
                detail: null,
            });
        }
        var boundary = _served(ops.threshold, null, 'R7:self_eval.ops_health.threshold');
        var worst = ops.worst_band;
        if (worst !== TRUSTED && worst !== RESERVED && worst !== DISTRUST) {
            return _component('ops_health', {
                band: RESERVED, state: UNMEASURABLE, boundary: boundary,
                detail: ops.error || null,
            });
        }
        return _component('ops_health', {
            band: worst, state: MEASURED, value: _num(ops.failing_count),
            boundary: boundary, detail: ops.worst_monitor || null,
        });
    }

    /**
     * Fold the reliability components into one chip.
     *
     * @param {object} input
     * @param {object|null} input.selfEval    R7's `self_eval` block
     * @param {object|null} input.thresholds  R10's `thresholds` block
     * @param {number} [input.now]
     * @returns {{band: string, labelKey: string, formulaKey: string,
     *            foldRule: string, reason: object, components: Array}}
     */
    function foldTrust(input) {
        input = input || {};
        var selfEval = input.selfEval || null;
        var thresholds = input.thresholds || null;

        var components = [
            _recall(selfEval, thresholds),
            _nullZone(selfEval),
            _drift(selfEval, thresholds),
            _opsHealth(selfEval),
            _freshness(selfEval),
        ];
        // Declaration order is the tie-break, so re-order to COMPONENT_IDS
        // rather than to the order the readers happened to be called in.
        components.sort(function (a, b) {
            return COMPONENT_IDS.indexOf(a.id) - COMPONENT_IDS.indexOf(b.id);
        });

        var band = worstBand(components.map(function (c) { return c.band; }));

        var worstComponent = null;
        for (var i = 0; i < components.length; i += 1) {
            if (components[i].band === band) { worstComponent = components[i]; break; }
        }

        return {
            band: band,
            labelKey: 'ui.trust.' + band,
            formulaKey: 'ui.trust.formula',
            foldRule: 'min',
            reason: {
                componentId: worstComponent ? worstComponent.id : null,
                state: worstComponent ? worstComponent.state : null,
                // One word, as P8 §4 asks: the worst element named, not a
                // sentence assembled in the browser.
                labelKey: worstComponent
                    ? 'ui.trust.reason.' + worstComponent.id
                    : 'ui.trust.reason.none',
                detail: worstComponent ? worstComponent.detail : null,
            },
            components: components,
        };
    }

    return {
        foldTrust: foldTrust,
        worstBand: worstBand,
        COMPONENT_IDS: COMPONENT_IDS,
        TRUSTED: TRUSTED, RESERVED: RESERVED, DISTRUST: DISTRUST,
        MEASURED: MEASURED, UNMEASURABLE: UNMEASURABLE,
        UNSUPPLIED: UNSUPPLIED, BOUNDARY_UNDISCLOSED: BOUNDARY_UNDISCLOSED,
    };
});
