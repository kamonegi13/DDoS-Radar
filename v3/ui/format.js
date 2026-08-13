/**
 * Noroshi v3 L7 — shared display formatting (pure, DOM-free).
 *
 * Everything here turns a server-supplied value into something a template
 * can print. Nothing here decides anything.
 *
 * Two rules the rest of the layer depends on:
 *
 * **The threat level is looked up, never compared.** `tlBand` is a table
 * keyed by the integer the server sent. It contains no `<`, no `>`, no
 * arithmetic — so there is no ladder here that could drift from the
 * backend's, and the no-client-derivation gate
 * (`tests/test_v3_ui_discipline.py`) has nothing to find. The one piece of
 * TL arithmetic that does exist, `severityOf`, is the DEFCON conversion
 * `6 - TL` that CLAUDE.md's memory entry demands be used for every
 * comparison — it is here, once, so that no caller reinvents it and gets
 * the direction backwards, which is how the 2026-08-02 calibration
 * inversion happened.
 *
 * **A missing number renders as absent, never as zero.** S1-UI-052: "数値が
 * 欠測のときは 0 を捏造せず「—」". A fabricated zero on a threat display is
 * a claim that the world is quiet.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiFormat = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    //: What a missing value prints as. Never "0".
    var ABSENT = '—';

    /**
     * TL → display band. A lookup, not a ladder.
     *
     * TL1 is the worst (DEFCON-style) — see CLAUDE.md's TL scale note. Each
     * band names a `:root` custom property in radar.css; no colour literal
     * appears anywhere in the v3 UI.
     */
    var TL_BANDS = {
        1: { band: 'critical', cssVar: '--color-critical', labelKey: 'ui.tl.1' },
        2: { band: 'severe', cssVar: '--color-severe', labelKey: 'ui.tl.2' },
        3: { band: 'high', cssVar: '--color-warning', labelKey: 'ui.tl.3' },
        4: { band: 'elevated', cssVar: '--color-elevated', labelKey: 'ui.tl.4' },
        5: { band: 'normal', cssVar: '--color-normal', labelKey: 'ui.tl.5' },
    };

    var TL_UNKNOWN = {
        band: 'unknown', cssVar: '--color-muted', labelKey: 'ui.tl.unknown',
    };

    /**
     * @param {number|null} tl the integer the server sent, unmodified
     * @returns {{band: string, cssVar: string, labelKey: string, tl: number|null}}
     */
    function tlBand(tl) {
        var entry = Object.prototype.hasOwnProperty.call(TL_BANDS, tl)
            ? TL_BANDS[tl] : null;
        if (!entry || typeof tl !== 'number') {
            return { band: TL_UNKNOWN.band, cssVar: TL_UNKNOWN.cssVar,
                     labelKey: TL_UNKNOWN.labelKey, tl: null };
        }
        return { band: entry.band, cssVar: entry.cssVar,
                 labelKey: entry.labelKey, tl: tl };
    }

    /**
     * DEFCON conversion. The ONLY place `6 - TL` is written in the v3 UI.
     *
     * Every comparison between threat levels goes through severity, because
     * TL is inverted and comparing it directly reads backwards. Getting this
     * wrong is not hypothetical: it is what broke calibration on 2026-08-02.
     */
    var TL_SEVERITY_ORIGIN = 6;

    function severityOf(tl) {
        if (typeof tl !== 'number' || !Number.isFinite(tl)) return null;
        return TL_SEVERITY_ORIGIN - tl;
    }

    /**
     * Direction of travel from a severity delta.
     *
     * The server sends `severity_delta_24h` already in severity space (R1),
     * so positive means the situation got WORSE. Named `escalating` /
     * `deescalating` rather than up/down for exactly that reason.
     */
    function trendOf(severityDelta) {
        if (typeof severityDelta !== 'number' || !Number.isFinite(severityDelta)) {
            return { direction: 'unknown', delta: null,
                     labelKey: 'ui.trend.unknown', glyph: '·' };
        }
        if (severityDelta > 0) {
            return { direction: 'escalating', delta: severityDelta,
                     labelKey: 'ui.trend.escalating', glyph: '▲' };
        }
        if (severityDelta < 0) {
            return { direction: 'deescalating', delta: severityDelta,
                     labelKey: 'ui.trend.deescalating', glyph: '▼' };
        }
        return { direction: 'flat', delta: 0,
                 labelKey: 'ui.trend.flat', glyph: '→' };
    }

    /** A number for display, or ABSENT. Never a fabricated zero. */
    function num(value, digits) {
        if (typeof value !== 'number' || !Number.isFinite(value)) return ABSENT;
        return digits === undefined ? String(value) : value.toFixed(digits);
    }

    /** A signed number, so "+2" and "-2" are distinguishable at a glance. */
    function signed(value, digits) {
        if (typeof value !== 'number' || !Number.isFinite(value)) return ABSENT;
        var text = digits === undefined ? String(Math.abs(value))
            : Math.abs(value).toFixed(digits);
        if (value > 0) return '+' + text;
        if (value < 0) return '-' + text;
        return digits === undefined ? '0' : (0).toFixed(digits);
    }

    /**
     * Seconds → a coarse, translatable duration.
     *
     * Returns a key plus its slot value rather than a formatted string, so
     * the dictionary owns the wording (CLAUDE.md §1: no prose in JS).
     */
    var _MINUTE = 60;
    var _HOUR = 3600;
    var _DAY = 86400;

    function duration(seconds) {
        if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) {
            return { key: 'ui.duration.unknown', vars: {} };
        }
        if (seconds < _MINUTE) {
            return { key: 'ui.duration.seconds', vars: { n: Math.floor(seconds) } };
        }
        if (seconds < _HOUR) {
            return { key: 'ui.duration.minutes', vars: { n: Math.floor(seconds / _MINUTE) } };
        }
        if (seconds < _DAY) {
            return { key: 'ui.duration.hours', vars: { n: Math.floor(seconds / _HOUR) } };
        }
        return { key: 'ui.duration.days', vars: { n: Math.floor(seconds / _DAY) } };
    }

    /** Unix seconds → an ISO-8601 UTC stamp, or ABSENT. */
    function utcStamp(seconds) {
        if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return ABSENT;
        return new Date(seconds * 1000).toISOString().replace('.000', '');
    }

    /**
     * The three things an empty surface must say (P9 §3.5, diagnosis D-4).
     *
     * S1-UI-008 forbids a blank screen, and WP-4.2 satisfied it: every empty
     * surface said WHY it was empty. On a cold-start shadow that produced a
     * screen reading "結論不可 / 空 / 空 / 空" — true in every line, and
     * useless, because a first-time reader could not learn what the place is
     * FOR from a page that had never been full. So the contract is three
     * parts, not one:
     *
     *   role       — what this place shows when it has something to show
     *   reason     — why it is empty right NOW
     *   fills_when — what would have to happen for it to fill
     *
     * The reason comes from the caller, which takes it from state the server
     * supplied (the lane's `empty_reason`, the geographic face's three
     * G-17 emptinesses, R1's presence or absence). When no state was served
     * the triple falls back to `empty.reason.unstated`, which says that the
     * server did not say — inventing a plausible reason here would be a
     * derivation with no ledger behind it (G-09).
     *
     * @param {string} surface  the `empty.<surface>.*` family
     * @param {string|null} reasonKey  a full key literal, or null
     */
    var EMPTY_PREFIX = 'empty.';
    var EMPTY_REASON_UNSTATED = 'empty.reason.unstated';

    function emptyState(surface, reasonKey, reasonVars) {
        var supplied = !!(typeof reasonKey === 'string' && reasonKey);
        return {
            surface: surface,
            roleKey: EMPTY_PREFIX + surface + '.role',
            reasonKey: supplied ? reasonKey : EMPTY_REASON_UNSTATED,
            reasonVars: reasonVars || {},
            reasonSupplied: supplied,
            fillsWhenKey: EMPTY_PREFIX + surface + '.fills_when',
        };
    }

    /**
     * HTML-escape an external string.
     *
     * S1-UI-041. Defined locally rather than reaching for `window._escHtml`,
     * matching the load-order-independent pattern every satellite panel in
     * this codebase already uses — and so the pure modules stay testable
     * under Node, where no window exists.
     */
    function escHtml(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /**
     * A URL safe to render as a link, or null.
     *
     * S1-UI-041: only http/https become links; everything else — including
     * `javascript:` and `data:` — is returned as null so the caller renders
     * it as plain text. Source URLs and evidence links arrive from adapters
     * and from LLM metadata, which is to say from outside.
     */
    function safeUrl(value) {
        if (typeof value !== 'string') return null;
        var trimmed = value.trim();
        if (!/^https?:\/\//i.test(trimmed)) return null;
        // Whitespace and control characters inside a URL are how an
        // attribute gets broken out of; reject rather than repair.
        if (/[\u0000-\u0020\u007f]/.test(trimmed)) return null;
        return trimmed;
    }

    return {
        ABSENT: ABSENT,
        TL_BANDS: TL_BANDS,
        TL_SEVERITY_ORIGIN: TL_SEVERITY_ORIGIN,
        tlBand: tlBand,
        severityOf: severityOf,
        trendOf: trendOf,
        num: num,
        signed: signed,
        duration: duration,
        utcStamp: utcStamp,
        escHtml: escHtml,
        safeUrl: safeUrl,
        emptyState: emptyState,
        EMPTY_REASON_UNSTATED: EMPTY_REASON_UNSTATED,
    };
});
