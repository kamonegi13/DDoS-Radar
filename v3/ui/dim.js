/**
 * Noroshi v3 L7 — the focus-change dim, as a state machine (pure, DOM-free).
 *
 * S1-UI-048: focus switching is a TWO-PHASE loading state, not a spinner.
 * `DIMMED → REFRESHING → ENDED`, with `STALE` as the alternative terminal.
 * Phase 1 masks the geographic face and is released by the arrival of the
 * conclusions projection; phase 2 is a light "updating" marker released by
 * the arrival of the scenario ledger. Once phase 1 has been released the
 * timeouts are disarmed, so a slow second leg is waited for rather than
 * being declared broken.
 *
 * S1-UI-049 is the half that matters more than the animation. If phase 1
 * times out the mask is KEPT and gains a sentence — "sync incomplete; you
 * are looking at the last state that arrived" — plus a retry affordance and
 * an unconditional keyboard escape. A mask that silently lifted on timeout
 * would show the previous scenario's numbers under the new scenario's name,
 * which is the worst outcome available here: not a missing answer but a
 * confidently mislabelled one. And no dim is applied during replay: the
 * analyst moved the timeline deliberately, and flickering the surface at a
 * deliberate action trains people to ignore the flicker.
 *
 * The machine holds no timer. It is given `now` and told what arrived, and
 * it answers what the screen should be — so every transition, including the
 * two timeouts, is a table-driven assertion under Node rather than something
 * that can only be observed by waiting.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiDim = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var IDLE = 'idle';
    var DIMMED = 'dimmed';
    var REFRESHING = 'refreshing';
    var ENDED = 'ended';
    var STALE = 'stale';
    var STATES = [IDLE, DIMMED, REFRESHING, ENDED, STALE];

    /**
     * How long phase 1 masks before it stops promising and starts warning.
     *
     * Display timings, in milliseconds. They gate an overlay and nothing
     * else: no conclusion, no score and no threat level is a function of
     * either number, and neither is ever compared against a server value.
     * Both are v1's normative widths (`map_dim.js`), kept because the
     * behaviour they produce was the specified one.
     */
    var MASK_TIMEOUT_MS = 8000;
    var MARKER_TIMEOUT_MS = 30000;

    /** The legs, named. Phase 1 releases the mask; phase 2 the marker. */
    var LEG_CONCLUSIONS = 'conclusions';
    var LEG_LEDGER = 'ledger';

    function _ms(value, fallback) {
        return typeof value === 'number' && Number.isFinite(value) && value > 0
            ? value : fallback;
    }

    /**
     * Create one dim controller.
     *
     * @param {object} [options]
     * @param {number} [options.maskTimeoutMs]
     * @param {number} [options.markerTimeoutMs]
     */
    function createDim(options) {
        options = options || {};
        var maskTimeout = _ms(options.maskTimeoutMs, MASK_TIMEOUT_MS);
        var markerTimeout = _ms(options.markerTimeoutMs, MARKER_TIMEOUT_MS);

        var state = {
            phase: IDLE,
            scenarioId: null,
            startedAt: null,
            legs: {},
            timedOut: false,
            escaped: false,
            suppressedReason: null,
        };

        function _view() {
            var masked = state.phase === DIMMED && !state.escaped;
            return {
                phase: state.phase,
                scenarioId: state.scenarioId,
                masked: masked,
                marker: state.phase === REFRESHING,
                timedOut: state.timedOut,
                escaped: state.escaped,
                suppressedReason: state.suppressedReason,
                legs: { conclusions: state.legs[LEG_CONCLUSIONS] === true,
                        ledger: state.legs[LEG_LEDGER] === true },
                // S1-UI-049: the mask that outlived its budget says so and
                // offers a way out. Both facts are part of the view, not
                // something the DOM layer decides on its own.
                messageKey: state.suppressedReason
                    ? 'ui.dim.suppressed'
                    : (state.phase === DIMMED
                        ? (state.timedOut ? 'ui.dim.timed_out' : 'ui.dim.loading')
                        : (state.phase === REFRESHING ? 'ui.dim.refreshing'
                            : (state.phase === STALE ? 'ui.dim.stale' : null))),
                offersRetry: state.phase === DIMMED && state.timedOut,
                offersEscape: state.phase === DIMMED,
            };
        }

        /**
         * A focus change began.
         *
         * `replay` suppresses the whole machine (S1-UI-049): during a replay
         * the analyst is driving, and the surface must not blink at them.
         */
        function begin(scenarioId, now, options2) {
            options2 = options2 || {};
            if (options2.replay === true) {
                state = { phase: IDLE, scenarioId: scenarioId, startedAt: null,
                          legs: {}, timedOut: false, escaped: false,
                          suppressedReason: 'replay' };
                return _view();
            }
            state = { phase: DIMMED, scenarioId: scenarioId,
                      startedAt: typeof now === 'number' ? now : null,
                      legs: {}, timedOut: false, escaped: false,
                      suppressedReason: null };
            return _view();
        }

        /**
         * A leg landed. Phase 1 ends on `conclusions`, phase 2 on `ledger`.
         *
         * Arrival CLEARS the timeout flag: a leg that came back late still
         * came back, and leaving the warning up after it would be the
         * mirror of the defect above — an accurate screen wearing a stale
         * complaint.
         */
        function arrived(leg, now) {
            if (state.suppressedReason) return _view();
            if (state.phase === IDLE || state.phase === ENDED
                    || state.phase === STALE) {
                return _view();
            }
            state.legs[leg] = true;
            if (leg === LEG_CONCLUSIONS && state.phase === DIMMED) {
                // Phase 1 released. From here the timeouts are disarmed —
                // the mask is gone, so a slow second leg costs an analyst
                // nothing but the marker.
                state.phase = REFRESHING;
                state.timedOut = false;
                state.escaped = false;
            }
            if (state.legs[LEG_LEDGER] === true && state.phase === REFRESHING) {
                state.phase = ENDED;
            }
            if (typeof now === 'number' && state.startedAt === null) {
                state.startedAt = now;
            }
            return _view();
        }

        /**
         * Advance the clock. The ONLY place a timeout can happen.
         *
         * Phase 1 keeps the mask and raises the warning; phase 2 gives up
         * on the marker and terminates in STALE, which is a different
         * terminal from ENDED precisely so the caller can tell "everything
         * arrived" from "we stopped waiting".
         */
        function tick(now) {
            if (state.suppressedReason || state.startedAt === null) return _view();
            var elapsed = now - state.startedAt;
            if (state.phase === DIMMED && elapsed >= maskTimeout) {
                state.timedOut = true;
            }
            if (state.phase === REFRESHING && elapsed >= markerTimeout) {
                state.phase = STALE;
            }
            return _view();
        }

        /** S1-UI-049's keyboard escape: the mask lifts, the marker stays. */
        function escape() {
            if (state.phase === DIMMED) {
                state.escaped = true;
                state.phase = REFRESHING;
            }
            return _view();
        }

        function view() { return _view(); }

        return {
            begin: begin, arrived: arrived, tick: tick,
            escape: escape, view: view,
            maskTimeoutMs: maskTimeout, markerTimeoutMs: markerTimeout,
        };
    }

    return {
        createDim: createDim,
        STATES: STATES,
        IDLE: IDLE, DIMMED: DIMMED, REFRESHING: REFRESHING,
        ENDED: ENDED, STALE: STALE,
        LEG_CONCLUSIONS: LEG_CONCLUSIONS, LEG_LEDGER: LEG_LEDGER,
        MASK_TIMEOUT_MS: MASK_TIMEOUT_MS, MARKER_TIMEOUT_MS: MARKER_TIMEOUT_MS,
    };
});
