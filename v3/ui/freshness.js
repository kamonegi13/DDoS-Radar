/**
 * Noroshi v3 L7 — change detection and staleness (pure, DOM-free).
 *
 * This module is the structural answer to G-10.
 *
 * v1 skipped redraws by comparing a hand-written signature built from four
 * fields (timestamp / scoring summary / target summary / v2 envelope time).
 * Map overlays, participants and the correlation map were not on that list,
 * so any change confined to them was fetched, parsed, stored — and never
 * drawn. "Data updated, display silently stale" was therefore not a bug to
 * be found but a defect class the design guaranteed.
 *
 * The remedy is not a longer list. A longer list is the same defect with a
 * later expiry date: the next field someone adds is off it again. Here the
 * signature is a fold over the WHOLE value — every leaf, every key, arrays
 * ordered, types tagged. There is nothing to remember to add, because
 * nothing is enumerated. `tests/ui_v3/test_freshness.js` mutates every leaf
 * of a deep payload one at a time and requires the signature to move for
 * each one; a field list cannot pass that test.
 *
 * The second half is DP2. S1-UI-008 requires the last good data to be kept
 * when a fetch fails — correct, an empty screen is worse. But v1 kept it
 * with no degradation marker, so held data and live data looked identical.
 * `freshnessOf` therefore always reports the age of what is on screen, and
 * a failed fetch can never resolve to FRESH regardless of how young the
 * held projection is.
 *
 * Loaded as a plain script in the v3 shell (window.NoroshiFreshness) and
 * via require() in tests. Mirrors the pure-module pattern of
 * triage_score.js / wp_alarm.js (P1 §11).
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiFreshness = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ── freshness levels ────────────────────────────────────────────────
    // Values are dictionary suffixes, not prose: every level renders
    // through `_t('ui.freshness.<level>')` (CLAUDE.md §1, DP17).
    var FRESH = 'fresh';
    var AGING = 'aging';
    var STALE = 'stale';
    var FAILED = 'failed';
    var UNKNOWN = 'unknown';

    /**
     * Display boundaries for the age band, in seconds.
     *
     * These are the ONLY numeric thresholds this module owns, and they are
     * exported so `freshnessOf` can hand them to the tooltip: NP6 forbids a
     * boundary the analyst cannot see. They are display bands, not scoring
     * thresholds — nothing downstream of a conclusion depends on them, and
     * they never enter a comparison that produces a threat level.
     *
     * Provenance: the scoring tick's cadence is 900 s (`v3/runtime/tick.py`),
     * so a projection older than one cadence is "aging" (a tick has been
     * missed or the conclusion genuinely did not change) and one older than
     * four cadences is "stale". Registered in wp25-l0-adapter-design.md
     * §7-2 #96 rather than left as an undeclared constant.
     */
    var FRESHNESS_AGING_SEC = 900;
    var FRESHNESS_STALE_SEC = 3600;

    // ── signature ───────────────────────────────────────────────────────

    /**
     * Canonical, type-tagged serialisation of an arbitrary value.
     *
     * Type tags matter: without them `{a: 1}` and `{a: '1'}` collapse, and a
     * server that started returning a stringified score would look like no
     * change at all. Absent keys and null values are also kept distinct,
     * because "the field went away" is exactly the kind of change that must
     * force a redraw.
     */
    function _canonical(value, seen) {
        if (value === undefined) return 'u';
        if (value === null) return 'z';
        var t = typeof value;
        if (t === 'boolean') return 'b:' + (value ? '1' : '0');
        if (t === 'number') return Number.isFinite(value) ? 'n:' + value : 'n:!' + String(value);
        if (t === 'string') return 's:' + value.length + ':' + value;
        if (t === 'bigint') return 'g:' + value.toString();
        if (t === 'function' || t === 'symbol') return 'x:' + String(value);

        if (seen.indexOf(value) !== -1) return 'c';   // cycle: fold to a marker
        seen.push(value);
        var out;
        if (Array.isArray(value)) {
            var parts = new Array(value.length);
            for (var i = 0; i < value.length; i += 1) {
                parts[i] = _canonical(value[i], seen);
            }
            out = 'a[' + parts.join(',') + ']';
        } else {
            var keys = Object.keys(value).sort();
            var kv = new Array(keys.length);
            for (var j = 0; j < keys.length; j += 1) {
                kv[j] = keys[j].length + ':' + keys[j] + '=' +
                    _canonical(value[keys[j]], seen);
            }
            out = 'o{' + kv.join(',') + '}';
        }
        seen.pop();
        return out;
    }

    /**
     * A stable signature over the ENTIRE value.
     *
     * FNV-1a folded over the canonical form, twice with different offsets,
     * so the 64 bits of output make an accidental collision between two
     * projections a non-event rather than a silent stale screen.
     *
     * @param {*} value
     * @returns {string} hex signature
     */
    function signatureOf(value) {
        var text = _canonical(value, []);
        var h1 = 0x811c9dc5;          // FNV-1a 32 offset basis
        var h2 = 0x01000193;          // second lane, different seed
        for (var i = 0; i < text.length; i += 1) {
            var c = text.charCodeAt(i);
            h1 = (h1 ^ c) >>> 0;
            h1 = Math.imul(h1, 0x01000193) >>> 0;
            h2 = (h2 ^ ((c << 3) | (i & 7))) >>> 0;
            h2 = Math.imul(h2, 0x85ebca6b) >>> 0;
        }
        return ('00000000' + h1.toString(16)).slice(-8) +
               ('00000000' + h2.toString(16)).slice(-8) +
               ':' + text.length;
    }

    /**
     * Clock fields that move on every fetch whether or not anything changed.
     *
     * This is the ONE concession to enumeration in this module, and its
     * direction is the opposite of G-10's. G-10 was an *inclusion* list —
     * "these fields count as a change" — so anything not on it was ignored,
     * and the list could not keep up with the payload. This is an
     * *exclusion* list of two names that are, by definition, "what time is
     * it": `served_at` and `data_freshness_sec`, both stamped by the
     * dispatcher on every response. Everything else, known or unknown,
     * still participates in the signature.
     *
     * An exclusion list fails safe: forgetting to add a new volatile field
     * causes a redundant redraw, which an analyst never notices. Forgetting
     * to add a field to an inclusion list causes a missed redraw, which is
     * the defect this whole module exists to prevent.
     */
    var VOLATILE_KEYS = ['served_at', 'data_freshness_sec', 'fetchedAt', 'servedAt'];

    /** A copy of `value` with the clock fields removed, at any depth. */
    function omitVolatile(value, seen) {
        seen = seen || [];
        if (!value || typeof value !== 'object') return value;
        if (seen.indexOf(value) !== -1) return null;
        seen.push(value);
        var out;
        if (Array.isArray(value)) {
            out = value.map(function (item) { return omitVolatile(item, seen); });
        } else {
            out = {};
            Object.keys(value).forEach(function (key) {
                if (VOLATILE_KEYS.indexOf(key) !== -1) return;
                out[key] = omitVolatile(value[key], seen);
            });
        }
        seen.pop();
        return out;
    }

    // ── change detector ─────────────────────────────────────────────────

    /**
     * Per-view redraw gate.
     *
     * `shouldRender` returns a decision object rather than a bare boolean so
     * that a skip is a recorded, inspectable event. v1's skip was invisible;
     * an analyst looking at an unchanged screen had no way to distinguish
     * "nothing changed" from "the redraw was suppressed". Here the DOM layer
     * can surface the last decision, and the tests can assert on it.
     *
     * `invalidate` / `invalidateAll` implement S1-UI-012's MUST: the
     * signature is discarded on focus change, on login completion and when a
     * replay cross-section is applied. Both demand a non-empty reason —
     * an unexplained invalidation is an unexplained redraw (NP6).
     */
    function createChangeDetector() {
        var signatures = Object.create(null);
        var invalidated = Object.create(null);
        var decisions = Object.create(null);

        function _record(viewId, decision) {
            decisions[viewId] = decision;
            return decision;
        }

        function shouldRender(viewId, payload) {
            // The clock is stripped here rather than by each caller, so a
            // caller cannot accidentally reintroduce a field list by
            // "cleaning up" its payload before handing it over.
            var signature = signatureOf(omitVolatile(payload));
            var previous = signatures[viewId];
            signatures[viewId] = signature;
            if (Object.prototype.hasOwnProperty.call(invalidated, viewId)) {
                var why = invalidated[viewId];
                delete invalidated[viewId];
                return _record(viewId, {
                    render: true, reason: 'invalidated', detail: why,
                    signature: signature, previousSignature: previous || null,
                });
            }
            if (previous === undefined) {
                return _record(viewId, {
                    render: true, reason: 'first', detail: null,
                    signature: signature, previousSignature: null,
                });
            }
            if (previous !== signature) {
                return _record(viewId, {
                    render: true, reason: 'changed', detail: null,
                    signature: signature, previousSignature: previous,
                });
            }
            return _record(viewId, {
                render: false, reason: 'unchanged', detail: null,
                signature: signature, previousSignature: previous,
            });
        }

        function invalidate(viewId, reason) {
            if (typeof reason !== 'string' || !reason) {
                throw new Error(
                    'invalidate(viewId, reason): a reason is required — an ' +
                    'unexplained cache drop is an unexplained redraw (NP6)');
            }
            invalidated[viewId] = reason;
            delete signatures[viewId];
        }

        function invalidateAll(reason) {
            if (typeof reason !== 'string' || !reason) {
                throw new Error(
                    'invalidateAll(reason): a reason is required (NP6)');
            }
            Object.keys(signatures).forEach(function (viewId) {
                invalidate(viewId, reason);
            });
            Object.keys(decisions).forEach(function (viewId) {
                if (!Object.prototype.hasOwnProperty.call(invalidated, viewId)) {
                    invalidated[viewId] = reason;
                }
            });
        }

        return {
            shouldRender: shouldRender,
            invalidate: invalidate,
            invalidateAll: invalidateAll,
            lastSignature: function (viewId) { return signatures[viewId] || null; },
            lastDecision: function (viewId) { return decisions[viewId] || null; },
        };
    }

    // ── freshness ───────────────────────────────────────────────────────

    /**
     * "How old is what I am looking at, and did the last fetch work?"
     *
     * @param {object} input
     * @param {number|null} input.observedAt  envelope `observed_at`, seconds
     * @param {number} input.now              seconds
     * @param {boolean} input.fetchOk         did the LAST fetch succeed
     * @param {string} [input.errorCode]      error code when it did not
     * @param {string} [input.forceLevel]     test hook; never used by the DOM layer
     * @returns {{level: string, ageSec: number|null, labelKey: string,
     *            errorCode: string|null, boundaries: object}}
     */
    function freshnessOf(input) {
        input = input || {};
        var observedAt = input.observedAt;
        var now = typeof input.now === 'number' ? input.now : 0;
        var ageSec = null;
        if (typeof observedAt === 'number' && Number.isFinite(observedAt)) {
            ageSec = Math.max(0, now - observedAt);
        }

        var level;
        if (input.forceLevel) {
            level = input.forceLevel;
        } else if (input.fetchOk === false) {
            // DP2 / S1-UI-008: the held data stays on screen, but it can
            // never claim to be fresh. A young projection behind a broken
            // fetch is the exact case v1 rendered as healthy.
            level = FAILED;
        } else if (ageSec === null) {
            level = UNKNOWN;
        } else if (ageSec >= FRESHNESS_STALE_SEC) {
            level = STALE;
        } else if (ageSec >= FRESHNESS_AGING_SEC) {
            level = AGING;
        } else {
            level = FRESH;
        }

        return {
            level: level,
            ageSec: ageSec,
            labelKey: 'ui.freshness.' + level,
            errorCode: input.errorCode || null,
            boundaries: {
                aging_sec: FRESHNESS_AGING_SEC,
                stale_sec: FRESHNESS_STALE_SEC,
            },
        };
    }

    return {
        signatureOf: signatureOf,
        omitVolatile: omitVolatile,
        VOLATILE_KEYS: VOLATILE_KEYS,
        createChangeDetector: createChangeDetector,
        freshnessOf: freshnessOf,
        FRESHNESS_AGING_SEC: FRESHNESS_AGING_SEC,
        FRESHNESS_STALE_SEC: FRESHNESS_STALE_SEC,
        FRESH: FRESH, AGING: AGING, STALE: STALE,
        FAILED: FAILED, UNKNOWN: UNKNOWN,
    };
});
