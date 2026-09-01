/**
 * Noroshi v3 L7 — SETTINGS, driven by the registry (pure, DOM-free).
 *
 * This screen exists to end G-15 rather than to reproduce it. Production's
 * settings surface offered ninety-eight keys; ninety-five of them never
 * reached the DB-override layer, so the panel showed values, accepted
 * edits, and changed nothing — and nobody could see that, because the panel
 * reported what it had sent. A settings screen that writes a value no
 * reader consumes is the same defect with a new stylesheet.
 *
 * So the list here is not "the keys we have". It is **the keys that pass
 * v3's three-stage test**: a consumer exists, the consumer's AST names the
 * key, and overriding the key changes what the consumer produces
 * (`tests/test_config_registry.py`). That test is CI, not documentation —
 * an entry that stops being read fails the build rather than quietly
 * becoming decoration. There are nine such keys today. Nine is a short
 * list and the screen says so out loud, with the count of pinned constants
 * beside it, because "there are only nine dials" is the honest headline and
 * hiding it behind a fuller-looking form is how ninety-five dead ones went
 * unnoticed for months.
 *
 * Four properties, each answering a surviving clause:
 *
 * * **Registry-driven, no per-key UI code** (S1-UI-067). The widget is
 *   chosen from the declared `unit`; adding a key to `v3/config/registry.py`
 *   makes it appear here with no edit to this file.
 * * **Four badge systems** (S1-UI-068), each filled from something the
 *   server actually states — `source` (which of override / env / default
 *   won), `env_present`, `consumer` (who reads it), and variability. What
 *   is NOT filled is v1's TIMING and IMPACT badges: R14 declares neither,
 *   and a badge computed in the browser is a claim about the backend that
 *   the backend never made. IMPACT's only mechanical job was to force a
 *   reason on high-impact keys; v3 requires a reason on EVERY config
 *   change (`requires_reason=True` in `v3/commands/spec.py`), which is
 *   strictly stronger, so the badge has nothing left to gate.
 * * **A diff, confirmed before it is sent** (S1-UI-069). No diff means no
 *   request and an explicit "no change" — not a round trip that reports
 *   success for having done nothing.
 * * **Saved and in-effect are different answers** (S1-UI-070). The command
 *   response carries `effect`, which is the key re-resolved through the
 *   same chain R14 reads, plus `changed`. A row that was appended to the
 *   ledger without moving the resolved value says exactly that.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiSettings = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    //: The resolution layers, in precedence order (v3/config/resolution.py).
    var SOURCE_OVERRIDE = 'override';
    var SOURCE_ENV = 'env';
    var SOURCE_DEFAULT = 'default';
    var SOURCES = [SOURCE_OVERRIDE, SOURCE_ENV, SOURCE_DEFAULT];

    //: Widget kinds. S1-UI-067's ordering, reduced to the units the v3
    //: kernel actually declares: there is no enum, no string list and no
    //: secret among the variable keys, so the branches for them are absent
    //: rather than written and unreachable.
    var WIDGET_TOGGLE = 'toggle';
    var WIDGET_RATIO = 'ratio';
    var WIDGET_NUMBER = 'number';
    var WIDGET_INTEGER = 'integer';

    //: unit -> widget. Units come from `v3/kernel/units.py` via R14.
    var UNIT_WIDGET = {
        bool: WIDGET_TOGGLE,
        ratio: WIDGET_RATIO,
        percent: WIDGET_RATIO,
        count: WIDGET_INTEGER,
        s: WIDGET_NUMBER,
        h: WIDGET_NUMBER,
        d: WIDGET_NUMBER,
        score: WIDGET_NUMBER,
        multiplier: WIDGET_NUMBER,
        index: WIDGET_NUMBER,
    };

    //: R10's pinned halves. Named here because R10 also carries `variable`,
    //: which is this screen's own list and must not be counted twice.
    var PINNED_CATALOGUES = ['conclusions', 'calibration', 'scoring_pinned'];

    function widgetFor(unit) {
        var kind = UNIT_WIDGET[unit] || WIDGET_NUMBER;
        return {
            kind: kind,
            inputType: kind === WIDGET_TOGGLE ? 'checkbox' : 'number',
            // `count` is whole-number by construction on the server
            // (`_INTEGER_UNITS`); saying so in the widget stops a rejection
            // that could have been prevented before the request.
            integerOnly: kind === WIDGET_INTEGER,
        };
    }

    function _text(value) {
        if (value === null || value === undefined) return null;
        if (typeof value === 'boolean') return value ? 'true' : 'false';
        return String(value);
    }

    /**
     * One key, as the screen needs it.
     *
     * Everything on this object came off the wire. The only thing computed
     * here is which widget to draw, and the widget draws no value of its
     * own — `value` and `default` are the server's, printed.
     */
    function _row(entry) {
        var source = SOURCES.indexOf(entry.source) === -1 ? null : entry.source;
        var override = entry.override || null;
        return {
            key: entry.key,
            value: entry.value === undefined ? null : entry.value,
            valueText: _text(entry.value),
            unit: entry.unit || null,
            defaultValue: entry.default === undefined ? null : entry.default,
            defaultText: _text(entry.default),
            why: entry.why || null,
            consumer: entry.consumer || null,
            source: source,
            sourceKey: source ? 'ui.settings.source.' + source
                : 'ui.settings.source.unknown',
            envPresent: entry.env_present === true,
            envKey: entry.env_present === true
                ? 'ui.settings.env.present' : 'ui.settings.env.absent',
            override: override,
            overrideActor: override ? (override.actor_id || null) : null,
            overrideReason: override ? (override.reason || null) : null,
            overrideAt: override && typeof override.at === 'number'
                ? override.at : null,
            widget: widgetFor(entry.unit),
            // Every key R14 serves is operationally variable by definition —
            // the pinned constants are a different endpoint (R10). Stated as
            // a field so the badge reads off data rather than off "it is on
            // this screen, therefore it is writable".
            writable: true,
        };
    }

    /**
     * Build the screen.
     *
     * @param {object} input
     * @param {object|null} input.config      R14 body
     * @param {object|null} input.thresholds  R10 body, for the pinned count
     * @param {object|null} input.groundTruth C9g body
     */
    function buildSettings(input) {
        input = input || {};
        var body = input.config || null;
        var entries = (body && Array.isArray(body.config)) ? body.config : [];
        var rows = entries.map(_row).sort(function (a, b) {
            return a.key < b.key ? -1 : (a.key > b.key ? 1 : 0);
        });

        // The pinned half, counted from R10's own disclosure. Counted rather
        // than asserted: the sentence "nine are variable and N are not" has
        // to move when the catalogue moves, or it becomes the kind of stale
        // claim this screen exists to prevent. R10 serves three pinned
        // catalogues beside the variable declaration, and all three are
        // "changed only by a code change", so all three are counted.
        var pinned = (input.thresholds && input.thresholds.thresholds)
            ? input.thresholds.thresholds : null;
        var pinnedCount = null;
        if (pinned && typeof pinned === 'object') {
            pinnedCount = PINNED_CATALOGUES.reduce(function (sum, name) {
                var table = pinned[name];
                return sum + (table && typeof table === 'object'
                    ? Object.keys(table).length : 0);
            }, 0);
        }

        // C9g serves `{scenario_id: [rows]}`, not a flat list. Flattened
        // here with the scenario carried onto each row, because a ground
        // truth row that lost the scenario it belongs to is a label without
        // a subject — and mislabelled ground truth is how calibration broke
        // three times.
        var gt = input.groundTruth || null;
        var gtRows = [];
        if (gt && gt.ground_truth && typeof gt.ground_truth === 'object') {
            Object.keys(gt.ground_truth).sort().forEach(function (sid) {
                var rows2 = gt.ground_truth[sid];
                if (!Array.isArray(rows2)) return;
                rows2.forEach(function (entry) {
                    gtRows.push({ scenarioId: sid, entry: entry });
                });
            });
        }

        return {
            rows: rows,
            present: body !== null,
            variableCount: rows.length,
            pinnedCount: pinnedCount,
            layers: (body && Array.isArray(body.layers)) ? body.layers
                : SOURCES.slice(),
            environmentLayerKeys: (body && Array.isArray(body.environment_layer_keys))
                ? body.environment_layer_keys : [],
            pinnedNote: body ? (body.pinned_note || null) : null,
            groundTruth: gtRows,
            groundTruthLoaded: gt !== null,
            // Three distinct emptinesses again (G-17): not fetched, fetched
            // and refused for want of a resolution chain, fetched and empty.
            emptyKey: body === null ? 'ui.settings.empty.not_loaded'
                : (rows.length === 0 ? 'ui.settings.empty.no_variable_keys' : null),
        };
    }

    // ── editing ─────────────────────────────────────────────────────────

    /**
     * Parse what the analyst typed, in the unit the server declared.
     *
     * Refuses; never repairs. A silently coerced value reads back as what
     * was typed in one place and as the coercion in another, which is how a
     * dial comes to be believed — `v3/attention/thresholds.py` makes the
     * same argument for the same reason.
     */
    function parseInput(row, raw) {
        if (!row) return { ok: false, errorKey: 'ui.settings.error.unknown_key' };
        if (row.widget.kind === WIDGET_TOGGLE) {
            if (typeof raw === 'boolean') return { ok: true, value: raw };
            if (raw === 'true') return { ok: true, value: true };
            if (raw === 'false') return { ok: true, value: false };
            return { ok: false, errorKey: 'ui.settings.error.not_bool' };
        }
        var text = typeof raw === 'string' ? raw.trim() : raw;
        if (text === '' || text === null || text === undefined) {
            return { ok: false, errorKey: 'ui.settings.error.empty' };
        }
        var parsed = Number(text);
        if (!Number.isFinite(parsed)) {
            return { ok: false, errorKey: 'ui.settings.error.not_number' };
        }
        if (row.widget.integerOnly && Math.floor(parsed) !== parsed) {
            return { ok: false, errorKey: 'ui.settings.error.not_integer' };
        }
        return { ok: true, value: parsed };
    }

    /**
     * The diff S1-UI-069 requires before anything is sent.
     *
     * No diff is answered locally with "no change" — sending it would get a
     * 200 back for having done nothing, and a success message for a no-op
     * is how an analyst learns to believe the message rather than the state.
     */
    function diffOf(row, raw) {
        var parsed = parseInput(row, raw);
        if (!parsed.ok) {
            return { ok: false, changed: false, errorKey: parsed.errorKey,
                     key: row ? row.key : null };
        }
        var changed = _text(parsed.value) !== _text(row.value);
        return {
            ok: true,
            changed: changed,
            key: row.key,
            from: row.value,
            fromText: row.valueText,
            to: parsed.value,
            toText: _text(parsed.value),
            unit: row.unit,
            consumer: row.consumer,
            source: row.source,
            errorKey: changed ? null : 'ui.settings.error.no_change',
        };
    }

    /**
     * What the analyst confirms, as slots for the dictionary.
     *
     * The sentence is the dictionary's; this returns the values that go in
     * it, so the confirmation cannot drift from the request in wording or
     * in content.
     */
    function confirmVars(diff) {
        return {
            key: diff.key,
            from: diff.fromText === null ? '' : diff.fromText,
            to: diff.toText === null ? '' : diff.toText,
            unit: diff.unit || '',
            consumer: diff.consumer || '',
        };
    }

    /**
     * Read a command result the way S1-UI-070 requires.
     *
     * `effect` is the server's re-resolution after the append; `changed` is
     * the server's own verdict on whether anything moved. A ledger row that
     * did not move the resolved value gets said out loud — that combination
     * is precisely G-15's fingerprint, and it is now visible on the screen
     * where the write happened rather than months later in an audit.
     */
    function resultOf(result) {
        if (!result || !result.ok) {
            var error = (result && result.error) || {};
            return {
                saved: false, changed: false, effect: null,
                messageKey: 'ui.settings.result.refused',
                detail: error.message || error.code || null,
            };
        }
        var body = result.body || {};
        var effect = (body.effect && body.effect.config) ? body.effect.config : null;
        var changed = body.changed === true;
        return {
            saved: true,
            changed: changed,
            effect: effect,
            effectValue: effect ? effect.value : null,
            effectValueText: effect ? _text(effect.value) : null,
            effectSource: effect ? effect.source : null,
            commandId: body.command ? body.command.command_id : null,
            messageKey: changed ? 'ui.settings.result.applied'
                : 'ui.settings.result.recorded_no_effect',
            detail: null,
        };
    }

    return {
        buildSettings: buildSettings,
        widgetFor: widgetFor,
        parseInput: parseInput,
        diffOf: diffOf,
        confirmVars: confirmVars,
        resultOf: resultOf,
        SOURCES: SOURCES,
        SOURCE_OVERRIDE: SOURCE_OVERRIDE,
        SOURCE_ENV: SOURCE_ENV,
        SOURCE_DEFAULT: SOURCE_DEFAULT,
        UNIT_WIDGET: UNIT_WIDGET,
        PINNED_CATALOGUES: PINNED_CATALOGUES,
        WIDGET_TOGGLE: WIDGET_TOGGLE, WIDGET_RATIO: WIDGET_RATIO,
        WIDGET_NUMBER: WIDGET_NUMBER, WIDGET_INTEGER: WIDGET_INTEGER,
    };
});
