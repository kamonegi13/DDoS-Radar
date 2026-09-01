/**
 * Noroshi v3 L7 — the replay scrubber's arithmetic (pure, DOM-free).
 *
 * WP-4.9b (P9 §6.7, principle R-H): v1 had a slider that let an analyst
 * DRAG through time and watch the board change — the order and speed of
 * a deterioration as an experience, not a delta number. WP-4.2 flattened
 * it to a datetime-local field; this module brings the manipulation back.
 *
 * All of it is arithmetic between three quantities:
 *
 *   * a POSITION on the slider, an integer 0..STEPS (0 = the window's
 *     start, STEPS = now = live);
 *   * an INSTANT, a unix timestamp inside the window;
 *   * the WINDOW, `now - REPLAY_WINDOW_SEC .. now`.
 *
 * The window is seven days by default and never exceeds 90: R3 caps
 * history reads at 90 days, and a slider that scrubs past what the
 * server will answer promises time travel it cannot deliver (P8 §9 —
 * no representation beyond the retention it rides on).
 *
 * The right edge IS live: `instantFor(STEPS)` returns null rather than
 * `now`, because "live" and "replaying the newest instant" are
 * different states — one follows new data, the other is frozen — and
 * S1-UI-012's replay machinery keys off exactly that null.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiReplay = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    //: Seven days of scrub by default; the R3 read cap is the hard roof.
    var REPLAY_WINDOW_SEC = 7 * 86400;
    var MAX_WINDOW_SEC = 90 * 86400;
    //: 15-minute steps: finer than the scoring cadence, coarse enough
    //: that a full drag is hundreds of fetches, not tens of thousands.
    var STEP_SEC = 900;

    function _window(windowSec) {
        var wanted = typeof windowSec === 'number' && windowSec > 0
            ? windowSec : REPLAY_WINDOW_SEC;
        return Math.min(wanted, MAX_WINDOW_SEC);
    }

    /**
     * @param {number} now unix seconds — passed in, never read from a
     *                     clock here (AP2: same inputs, same scale)
     * @param {number} [windowSec]
     * @returns {{steps: number, stepSec: number, windowSec: number,
     *            start: number, end: number}}
     */
    function scaleFor(now, windowSec) {
        var span = _window(windowSec);
        var steps = Math.round(span / STEP_SEC);
        return { steps: steps, stepSec: STEP_SEC, windowSec: span,
                 start: now - span, end: now };
    }

    /** Slider position -> unix instant, or null at the live edge. */
    function instantFor(scale, position) {
        var raw = Number(position);
        if (!Number.isFinite(raw)) return null;
        var clamped = Math.max(0, Math.min(scale.steps, Math.round(raw)));
        if (clamped >= scale.steps) return null;   // the right edge IS live
        return scale.start + clamped * scale.stepSec;
    }

    /** Unix instant (or null = live) -> slider position. */
    function positionFor(scale, instant) {
        if (instant === null || instant === undefined) return scale.steps;
        var clamped = Math.max(scale.start, Math.min(scale.end, instant));
        return Math.round((clamped - scale.start) / scale.stepSec);
    }

    return {
        scaleFor: scaleFor,
        instantFor: instantFor,
        positionFor: positionFor,
        REPLAY_WINDOW_SEC: REPLAY_WINDOW_SEC,
        MAX_WINDOW_SEC: MAX_WINDOW_SEC,
        STEP_SEC: STEP_SEC,
    };
});
