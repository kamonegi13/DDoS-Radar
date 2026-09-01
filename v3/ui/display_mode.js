/**
 * Noroshi v3 L7 — the attention lane's display mode (pure, DOM-free).
 *
 * S1-UI-030 requires three modes with hysteresis — dormant / pin-dock /
 * critical-banner — and requires the chosen mode to carry its reason in
 * plain language (NP6). S1-UI-031 requires an explicit critical marker to
 * override every threshold. S1-UI-032 requires suppression to be unable to
 * silence a critical. S1-UI-034 requires a persisted "always visible" that
 * floors the mode at pin-dock.
 *
 * **What is deliberately NOT ported: the numbers.** v1's normative module
 * entered dormant below 0.40 and left above 0.50, entered critical above
 * 0.85 and left below 0.78 — four score bands living only in the browser.
 * They are not here, for two reasons that are the same reason:
 *
 *   * `score` is a quantity the server decides. A browser that compares it
 *     against a browser-held boundary is holding a threshold the backend
 *     cannot see, which is G-09's shape applied to presentation instead of
 *     to the ladder. `tests/test_v3_ui_discipline.py` refuses the
 *     comparison syntactically, and two of the four v1 bands (0.4, 0.5)
 *     collide with live backend thresholds — the gate would have caught the
 *     port even if nobody had thought about it.
 *   * the server already applies the only score threshold that exists:
 *     `min_score` is a per-user floor R6 enforces before a row is sent
 *     (`v3/attention/thresholds.py`), so "is this worth showing" has been
 *     answered once, by the side that owns the number. Asking it again with
 *     a second set of constants is how two answers to one question start
 *     disagreeing.
 *
 * So the mode is a function of facts the server states — is there a ranked
 * row, is any of them critical — and the hysteresis is expressed in
 * CONSECUTIVE QUIET EVALUATIONS rather than in a score band. That keeps the
 * asymmetry NP1 wants: a heavier mode is entered on the first evaluation
 * that warrants it and left only after the lane has been quiet for several
 * cycles in a row. Entering fast and leaving slow is what hysteresis is
 * for; the numeric width was only ever one way to spell it.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiDisplayMode = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var Fmt = (typeof require === 'function')
        ? require('./format')
        : (typeof window !== 'undefined' ? window.NoroshiFormat : null);

    var DORMANT = 'dormant';
    var PIN_DOCK = 'pin-dock';
    var CRITICAL_BANNER = 'critical-banner';
    var MODES = [DORMANT, PIN_DOCK, CRITICAL_BANNER];

    //: Ordering, so "at least pin-dock" is expressible without comparing
    //: strings. Not a threshold on anything the server decides.
    var WEIGHT = { dormant: 0, 'pin-dock': 1, 'critical-banner': 2 };

    /**
     * How many consecutive quiet evaluations it takes to step down.
     *
     * The hysteresis width, in cycles rather than in score. Three at the
     * default poll cadence is roughly three quarters of an hour of nothing —
     * long enough that a lane flickering between one row and none does not
     * flicker the banner with it, short enough that a genuinely quiet day
     * collapses the surface within one working session.
     */
    var QUIET_CYCLES_TO_STEP_DOWN = 3;

    /**
     * Markers the SERVER may set on a row to force the banner.
     *
     * S1-UI-031: an explicit critical marker outranks every other input. The
     * three names are v1's (`critical`, `recall_reducing`, `kill_switch`) and
     * they are read off the row — this module never decides that something is
     * critical, it only notices that the server said so.
     */
    var CRITICAL_FLAGS = ['critical', 'recall_reducing', 'kill_switch'];

    function _flagged(row) {
        if (!row || typeof row !== 'object') return null;
        for (var i = 0; i < CRITICAL_FLAGS.length; i += 1) {
            var name = CRITICAL_FLAGS[i];
            if (row[name] === true) return name;
            if (Array.isArray(row.flags) && row.flags.indexOf(name) !== -1) {
                return name;
            }
        }
        return null;
    }

    /**
     * Is the row's threat level the top band?
     *
     * A LOOKUP through `format.tlBand`, which is a table keyed by the integer
     * the server sent and contains no comparison at all. Writing
     * `tl <= 1` here would be a ladder with one rung.
     */
    function _topBand(tl) {
        if (!Fmt) return false;
        return Fmt.tlBand(tl).band === Fmt.TL_BANDS[1].band;
    }

    /**
     * Why the banner fired, as a server-attributable fact.
     *
     * Returns `{reasonKey, itemId, flag}` or null. Suppression is not
     * consulted: S1-UI-032 makes acknowledgement, snooze and dismissal
     * incapable of hiding a critical, so a suppressed critical row still
     * raises the banner and the row still counts.
     */
    function criticalIn(rows) {
        var list = Array.isArray(rows) ? rows : [];
        for (var i = 0; i < list.length; i += 1) {
            var row = list[i];
            var flag = _flagged(row);
            if (flag) {
                return { reasonKey: 'ui.mode.reason.flagged',
                         itemId: row.itemId || row.item_id || null, flag: flag };
            }
        }
        for (var j = 0; j < list.length; j += 1) {
            var candidate = list[j];
            if (!candidate) continue;
            var level = typeof candidate.threatLevel === 'number'
                ? candidate.threatLevel : candidate.threat_level;
            if (_topBand(level)) {
                return { reasonKey: 'ui.mode.reason.top_band',
                         itemId: candidate.itemId || candidate.item_id || null,
                         flag: null };
            }
        }
        return null;
    }

    /**
     * Decide the mode for one evaluation.
     *
     * @param {object} input
     * @param {object|null} input.lane        the `buildLane` view model
     * @param {string|null} input.previous    the previous mode
     * @param {number} [input.quietCycles]    consecutive quiet evaluations so far
     * @param {boolean} [input.alwaysVisible] the persisted "keep it up" pin
     * @param {number} [input.quietCyclesToStepDown]
     * @returns {{mode, previous, reasonKey, reasonVars, quietCycles,
     *            criticalItemId, flooredByPin, changed}}
     */
    function evaluate(input) {
        input = input || {};
        var lane = input.lane || null;
        var previous = MODES.indexOf(input.previous) === -1 ? null : input.previous;
        var priorQuiet = typeof input.quietCycles === 'number'
            && input.quietCycles >= 0 ? Math.floor(input.quietCycles) : 0;
        var stepDownAfter = typeof input.quietCyclesToStepDown === 'number'
            && input.quietCyclesToStepDown > 0
            ? Math.floor(input.quietCyclesToStepDown) : QUIET_CYCLES_TO_STEP_DOWN;
        var pinned = input.alwaysVisible === true;

        // Suppressed rows participate: S1-UI-032 records the analyst's
        // suppression in the ledger but forbids it from acting as a mute.
        var all = lane ? (lane.rows || []).concat(lane.suppressed || []) : [];
        var active = lane ? (lane.rows || []) : [];
        var critical = criticalIn(all);

        var decided, reasonKey, reasonVars = {}, quiet = priorQuiet;

        if (critical) {
            // S1-UI-031: unconditional. No cycle count, no pin, no floor.
            decided = CRITICAL_BANNER;
            reasonKey = critical.reasonKey;
            reasonVars = { item: critical.itemId || Fmt.ABSENT,
                           flag: critical.flag || Fmt.ABSENT };
            quiet = 0;
        } else if (lane === null) {
            // Nothing has been fetched. NOT dormant: an unloaded lane and an
            // empty lane are different claims, and collapsing the surface for
            // the first would tell an analyst the world is quiet when the
            // truth is that nobody has asked yet (G-17).
            decided = PIN_DOCK;
            reasonKey = 'ui.mode.reason.not_loaded';
            quiet = 0;
        } else if (active.length > 0) {
            decided = PIN_DOCK;
            reasonKey = 'ui.mode.reason.ranked_rows';
            reasonVars = { n: active.length };
            quiet = 0;
        } else {
            quiet = priorQuiet + 1;
            if (previous !== null && WEIGHT[previous] > WEIGHT[DORMANT]
                    && quiet < stepDownAfter) {
                // Hysteresis: the lane is quiet but has not been quiet for
                // long enough to fold the surface away.
                decided = previous === CRITICAL_BANNER ? PIN_DOCK : previous;
                reasonKey = 'ui.mode.reason.holding';
                reasonVars = { n: quiet, of: stepDownAfter };
            } else {
                decided = DORMANT;
                reasonKey = lane.empty && lane.emptyReason === null && !lane.total
                    ? 'ui.mode.reason.quiet_unexplained' : 'ui.mode.reason.quiet';
                reasonVars = { n: quiet };
            }
        }

        // S1-UI-034: the pin is a floor, never a ceiling — it can lift
        // dormant to pin-dock and can never hold a critical banner down.
        var flooredByPin = false;
        if (pinned && WEIGHT[decided] < WEIGHT[PIN_DOCK]) {
            decided = PIN_DOCK;
            flooredByPin = true;
            reasonKey = 'ui.mode.reason.pinned';
            reasonVars = {};
        }

        return {
            mode: decided,
            previous: previous,
            reasonKey: reasonKey,
            reasonVars: reasonVars,
            quietCycles: quiet,
            criticalItemId: critical ? critical.itemId : null,
            flooredByPin: flooredByPin,
            changed: previous !== decided,
        };
    }

    return {
        evaluate: evaluate,
        criticalIn: criticalIn,
        MODES: MODES,
        DORMANT: DORMANT,
        PIN_DOCK: PIN_DOCK,
        CRITICAL_BANNER: CRITICAL_BANNER,
        CRITICAL_FLAGS: CRITICAL_FLAGS,
        QUIET_CYCLES_TO_STEP_DOWN: QUIET_CYCLES_TO_STEP_DOWN,
    };
});
