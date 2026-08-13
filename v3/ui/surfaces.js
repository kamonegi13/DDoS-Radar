/**
 * Noroshi v3 L7 — the DOM for the four surfaces WP-4.2 left unbuilt.
 *
 * A second DOM file for the same reason `gate.js` was the first: these are
 * features with their own elements and their own commands, and folding them
 * into `app.js` would grow one file past the point where anybody reads it —
 * which is how v1 arrived at fourteen thousand untested lines. Everything
 * with a decision in it is next door in the pure modules (`geo.js`,
 * `settings.js`, `display_mode.js`, `dim.js`, `live.js`); this file fetches
 * nothing on its own, decides nothing on its own, and writes elements.
 *
 * The four:
 *
 *   1. **the geographic face** — P8 §6's Tier 1 map, at the granularity the
 *      server serves. Layer choice persists, which is the S1-UI-057 defect
 *      being fixed rather than carried.
 *   2. **SETTINGS** — the nine keys that pass the registry's three-stage
 *      test, each written through C7 and read back through R14.
 *   3. **display mode and the focus dim** — two state machines, applied to
 *      the document as classes and one overlay.
 *   4. **the live channel** — the connection chip, and the refetch a push
 *      triggers.
 *
 * Every render here goes through the SAME change detector `app.js` uses, so
 * G-10's fold covers these surfaces too: nothing in this file enumerates
 * what counts as a change, and a freshness or connection indicator is
 * written before the redraw gate rather than behind it.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiSurfaces = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    function _mod(name, global) {
        if (typeof require === 'function') return require(name);
        return typeof window !== 'undefined' ? window[global] : null;
    }

    var S = _mod('./strings', 'NoroshiStrings');
    var Fmt = _mod('./format', 'NoroshiFormat');
    var Render = _mod('./render', 'NoroshiRender');
    var Geo = _mod('./geo', 'NoroshiGeo');
    var Tiles = _mod('./geo_tiles', 'NoroshiGeoTiles');
    var Settings = _mod('./settings', 'NoroshiSettings');
    var Mode = _mod('./display_mode', 'NoroshiDisplayMode');
    var Dim = _mod('./dim', 'NoroshiDim');
    var Live = _mod('./live', 'NoroshiLive');

    var _t = S.t;
    var esc = Fmt.escHtml;

    function _browserSocketFactory() {
        if (typeof window === 'undefined'
                || typeof window.WebSocket !== 'function') {
            return null;
        }
        return function (assetPath) {
            var scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            return new window.WebSocket(
                scheme + '//' + window.location.host + assetPath);
        };
    }

    /**
     * @param {object} options
     * @param {object} options.doc          the document
     * @param {object} options.client       `client.js` instance
     * @param {object} options.detector     the shared change detector
     * @param {function} options.toast      (kind, key, vars) -> void
     * @param {function} options.refresh    (reason) -> Promise
     * @param {function} options.results    () -> the shell's fetch results
     * @param {function} options.focus      () -> focused scenario id or null
     * @param {function} options.layers     () -> persisted geo layer state
     * @param {function} options.saveLayers (next) -> void
     * @param {function} [options.ask]      (key) -> string|null
     * @param {function} [options.confirm]  (key, vars) -> boolean
     * @param {function} [options.now]      () -> ms
     * @param {function} [options.socketFactory]
     */
    function createSurfaces(options) {
        options = options || {};
        var doc = options.doc;
        var client = options.client;
        var detector = options.detector;
        var toast = options.toast || function () {};
        var refresh = options.refresh || function () { return Promise.resolve(); };
        var results = options.results || function () { return {}; };
        var focusOf = options.focus || function () { return null; };
        var layersOf = options.layers || function () { return null; };
        var saveLayers = options.saveLayers || function () {};
        var ask = options.ask || function () { return null; };
        var confirmWith = options.confirm || function () { return true; };
        var now = options.now || function () { return Date.now(); };

        var dim = Dim.createDim({});
        var live = Live.createLiveClient({
            // The one place a real socket is constructed. Built here rather
            // than in `app.js` because this file already owns the client,
            // and guarded on `window` so the module stays requireable under
            // Node — where the absence of a factory is itself correct: a
            // client with nothing to dial reports the deployment and stops.
            socketFactory: options.socketFactory !== undefined
                ? options.socketFactory : _browserSocketFactory(),
            focus: focusOf,
            onState: function () { renderLive(); },
            onCue: function (verdict) { onCue(verdict); },
        });

        var local = {
            mode: null,
            quietCycles: 0,
            alwaysVisible: false,
            settingResults: {},
            liveView: live.view(),
        };

        // ── DOM helpers, named the way the wiring gate expects ──────────
        function $(id) { return doc ? doc.getElementById(id) : null; }
        function setHtml(id, html) { var n = $(id); if (n) n.innerHTML = html; }
        function setText(id, text) { var n = $(id); if (n) n.textContent = text; }
        function setHidden(id, hidden) { var n = $(id); if (n) n.hidden = !!hidden; }

        // ── 1. the geographic face ──────────────────────────────────────

        function renderGeo() {
            var r = results();
            var face = Geo.buildFace({
                scenarios: r.R1 ? r.R1.body : null,
                evidence: r.R5 ? r.R5.body : null,
                scenarioId: focusOf(),
                layers: layersOf(),
            });

            // Outside the gate, always: the staleness of the evidence read
            // is the one thing a skipped redraw must never be able to hide.
            setHtml('geo-freshness', Render.freshnessBadge(r.R5 || null));
            setHtml('geo-layers', face.layerCatalogue.map(function (layer) {
                return Render.geoLayerHtml(layer, face.layers[layer.id] === true);
            }).join(''));

            if (!detector.shouldRender('geo', { face: face, r1: r.R1, r5: r.R5 }).render) {
                return;
            }

            setHtml('geo-summary', esc(_t('ui.geo.summary', {
                participants: face.participantCount,
                fired: face.firedTotal,
                suppressed: face.suppressedTotal,
                observations: face.observationTotal === null
                    ? Fmt.ABSENT : face.observationTotal,
                window: face.windowSec === null ? Fmt.ABSENT
                    : _t(Fmt.duration(face.windowSec).key,
                         Fmt.duration(face.windowSec).vars),
            })));
            setHtml('geo-empty', face.emptyState
                ? Render.emptyStateHtml(face.emptyState) : '');

            // P9 §3.4: the tile map is the primary visual and the list is the
            // accessible representation of the same facts. The grid is built
            // from the markers the list renders — one fold, two presentations,
            // so they cannot disagree about what fired where.
            var tileMap = Tiles.buildTileMap({
                markers: face.layers.participants ? face.markers : [],
                offRoster: face.offRoster,
            });
            setHtml('geo-tilemap', face.layers.participants
                ? Render.geoTileMapHtml(tileMap) : '');
            setHtml('geo-markers', face.layers.participants
                ? face.markers.map(Render.geoMarkerHtml).join('')
                : '<li class="empty">' + esc(_t('ui.geo.layer_off')) + '</li>');
            setHtml('geo-offroster', face.offRoster.length === 0 ? ''
                : face.offRoster.map(Render.geoMarkerHtml).join(''));
            setHidden('geo-offroster-head', face.offRoster.length === 0);
        }

        // ── 2. SETTINGS ─────────────────────────────────────────────────

        function renderSettings() {
            var r = results();
            var view = Settings.buildSettings({
                config: r.R14 ? r.R14.body : null,
                thresholds: r.R10 ? r.R10.body : null,
                groundTruth: r.C9g ? r.C9g.body : null,
            });
            setHtml('settings-freshness', Render.freshnessBadge(r.R14 || null));
            if (!detector.shouldRender('settings', {
                    view: view, r14: r.R14, r10: r.R10, c9g: r.C9g,
                    outcomes: local.settingResults }).render) {
                return;
            }

            // The headline G-15 could not say: how many dials there are, and
            // how many constants are not dials at all.
            setHtml('settings-summary', esc(_t('ui.settings.summary', {
                variable: view.variableCount,
                pinned: view.pinnedCount === null ? Fmt.ABSENT : view.pinnedCount,
            })));
            setHtml('settings-rows', view.emptyKey
                ? '<tr><td colspan="6" class="empty">'
                  + esc(_t(view.emptyKey)) + '</td></tr>'
                : view.rows.map(Render.settingsRowHtml).join(''));
            setHtml('groundtruth-rows', view.groundTruth.length === 0
                ? Render.emptyStateHtml(
                    Fmt.emptyState('groundtruth', view.groundTruthLoaded
                        ? 'empty.groundtruth.reason_none'
                        : 'empty.groundtruth.reason_not_loaded'),
                    { tag: 'tr', colspan: 5 })
                : view.groundTruth.map(Render.groundTruthRowHtml).join(''));

            // Outcomes are written after the table so a redraw cannot drop
            // the sentence that says what the last save actually did.
            Object.keys(local.settingResults).forEach(function (key) {
                var outcome = local.settingResults[key];
                var slot = doc && doc.querySelector
                    ? doc.querySelector('[data-setting-result="' + key + '"]') : null;
                if (!slot) return;
                slot.textContent = _t(outcome.messageKey, {
                    value: outcome.effectValueText === null || outcome.effectValueText === undefined
                        ? Fmt.ABSENT : outcome.effectValueText,
                    source: outcome.effectSource || Fmt.ABSENT,
                    why: outcome.detail || '',
                });
            });
        }

        function _rowFor(key) {
            var r = results();
            var view = Settings.buildSettings({ config: r.R14 ? r.R14.body : null });
            for (var i = 0; i < view.rows.length; i += 1) {
                if (view.rows[i].key === key) return view.rows[i];
            }
            return null;
        }

        function _inputValue(key, row) {
            var node = doc && doc.querySelector
                ? doc.querySelector('[data-setting-key="' + key + '"]') : null;
            if (!node) return null;
            return row.widget.kind === Settings.WIDGET_TOGGLE
                ? node.checked === true : node.value;
        }

        /**
         * Save one key: parse, diff, confirm, send, read the effect back.
         *
         * The order matters. Parsing and diffing happen before the request
         * so a malformed entry and a no-op both cost zero round trips and
         * neither can come back as a 200 the analyst reads as success.
         */
        function saveSetting(key, button) {
            var row = _rowFor(key);
            if (!row) { toast('error', 'ui.settings.error.unknown_key'); return; }
            var diff = Settings.diffOf(row, _inputValue(key, row));
            if (!diff.ok || !diff.changed) {
                toast('error', diff.errorKey || 'ui.settings.error.no_change');
                return;
            }
            if (!confirmWith('ui.settings.confirm', Settings.confirmVars(diff))) return;
            // Every config change requires a reason server-side; refusing an
            // empty one here means the analyst is told immediately rather
            // than by a 400 after the fact (defence in depth, S1-UI-072).
            var reason = ask('ui.settings.prompt.reason');
            if (reason === null) return;
            if (button) button.disabled = true;
            client.commands.setConfig(key, diff.to, reason)
                .then(function (result) { return _settled(key, result); })
                .catch(function (err) {
                    toast('error', 'ui.toast.command_failed', {
                        what: _t('ui.settings.command.save'),
                        why: (err && err.message) || _t('ui.error.unknown'),
                    });
                })
                .then(function () { if (button) button.disabled = false; });
        }

        function clearSetting(key, button) {
            if (!confirmWith('ui.settings.confirm_clear', { key: key })) return;
            var reason = ask('ui.settings.prompt.reason');
            if (reason === null) return;
            if (button) button.disabled = true;
            client.commands.clearConfig(key, reason)
                .then(function (result) { return _settled(key, result); })
                .catch(function (err) {
                    toast('error', 'ui.toast.command_failed', {
                        what: _t('ui.settings.command.clear'),
                        why: (err && err.message) || _t('ui.error.unknown'),
                    });
                })
                .then(function () { if (button) button.disabled = false; });
        }

        function _settled(key, result) {
            var outcome = Settings.resultOf(result);
            local.settingResults[key] = outcome;
            toast(outcome.saved && outcome.changed ? 'ok' : 'error',
                  outcome.messageKey, {
                      value: outcome.effectValueText === null
                          || outcome.effectValueText === undefined
                          ? Fmt.ABSENT : outcome.effectValueText,
                      source: outcome.effectSource || Fmt.ABSENT,
                      why: outcome.detail || '',
                  });
            detector.invalidate('settings', 'config_committed');
            // S1-UI-035: re-read before re-rendering. What is shown after a
            // save is what R14 now resolves, never what was typed.
            return refresh('config_committed');
        }

        // ── 3. display mode and the focus dim ───────────────────────────

        function renderMode(lane) {
            var decision = Mode.evaluate({
                lane: lane || null,
                previous: local.mode,
                quietCycles: local.quietCycles,
                alwaysVisible: local.alwaysVisible,
            });
            local.mode = decision.mode;
            local.quietCycles = decision.quietCycles;
            setHtml('mode-slot', Render.modeChipHtml(decision));
            var stage = $('stage-2');
            if (stage && stage.setAttribute) {
                stage.setAttribute('data-mode', decision.mode);
            }
            setHidden('critical-banner', decision.mode !== Mode.CRITICAL_BANNER);
            if (decision.mode === Mode.CRITICAL_BANNER) {
                setText('critical-banner', _t('ui.mode.banner', {
                    item: decision.criticalItemId || Fmt.ABSENT }));
            }
            return decision;
        }

        function renderDim() {
            var view = dim.view();
            setHidden('dim-overlay', !view.masked && !view.marker
                && view.phase !== Dim.STALE);
            setText('dim-message', view.messageKey ? _t(view.messageKey) : '');
            setHidden('dim-retry', !view.offersRetry);
            var overlay = $('dim-overlay');
            if (overlay && overlay.setAttribute) {
                overlay.setAttribute('data-phase', view.phase);
                overlay.setAttribute('data-masked', view.masked ? 'true' : 'false');
            }
            return view;
        }

        function noteFocusChange(scenarioId, replay) {
            dim.begin(scenarioId, now(), { replay: replay === true });
            renderDim();
        }

        function noteArrival(leg) {
            dim.arrived(leg, now());
            renderDim();
        }

        function tickDim() {
            dim.tick(now());
            renderDim();
        }

        // ── 4. the live channel ─────────────────────────────────────────

        function renderLive() {
            local.liveView = live.view();
            setHtml('live-slot', Render.liveChipHtml(local.liveView));
        }

        /**
         * A push arrived. Invalidate what it touched and refetch.
         *
         * Never a merge: the socket payload is not an envelope, so putting
         * it on screen would show values with no NP7 sentence and no
         * dispatcher-stamped age. Polling is untouched — the push only means
         * the next read happens now rather than at the next cadence.
         */
        function onCue(verdict) {
            if (!verdict || !verdict.accepted) {
                renderLive();
                return;
            }
            verdict.invalidate.forEach(function (key) {
                detector.invalidate(_viewFor(key), 'live_push');
            });
            refresh('live_push');
        }

        //: read key -> the view whose signature it feeds.
        var VIEW_OF = { R2: 'face', R4: 'feedback', R4d: 'derivation',
                        R6: 'lane', R7: 'selfeval', R8: 'selfeval' };

        function _viewFor(readKey) { return VIEW_OF[readKey] || 'board'; }

        /**
         * Hand the deployment's own declaration to the live client.
         *
         * Only when it CHANGES. Reconfiguring on every render would re-dial
         * behind the client's back while a backoff retry was already
         * pending, which turns one honest reconnection into a poll — the
         * thing S1-UI-011 forbids in the other direction.
         */
        var lastDeclaration = undefined;
        function configureLive() {
            var r = results();
            var body = r.R15c ? r.R15c.body : null;
            var declaration = body ? body.app_config : null;
            var signature = JSON.stringify(
                declaration ? (declaration.websocket || null) : null);
            if (signature === lastDeclaration) return;
            lastDeclaration = signature;
            live.configure(declaration);
        }

        // ── binding ─────────────────────────────────────────────────────

        function onClick(event) {
            var target = event.target;
            if (!target || !target.getAttribute || target.disabled) return;
            var save = target.getAttribute('data-setting-save');
            if (save) { saveSetting(save, target); return; }
            var clear = target.getAttribute('data-setting-clear');
            if (clear) { clearSetting(clear, target); return; }
            var layer = target.getAttribute('data-geo-layer');
            if (layer) {
                saveLayers(Geo.toggleLayer(layersOf(), layer));
                detector.invalidate('geo', 'layer_toggled');
                renderGeo();
                return;
            }
            if (target.getAttribute('data-dim-retry') !== null) {
                refresh('dim_retry');
            }
        }

        function onKeydown() {
            // S1-UI-049: any key releases the mask. Unconditional on
            // purpose — a stuck overlay must not need a specific key
            // nobody documented.
            if (dim.view().masked) {
                dim.escape();
                renderDim();
            }
        }

        function bind() {
            if (!doc || !doc.addEventListener) return;
            doc.addEventListener('click', onClick);
            doc.addEventListener('keydown', onKeydown);
        }

        function renderAll(lane) {
            configureLive();
            renderLive();
            renderGeo();
            renderSettings();
            renderMode(lane);
            renderDim();
        }

        return {
            bind: bind,
            renderAll: renderAll,
            renderGeo: renderGeo,
            renderSettings: renderSettings,
            renderMode: renderMode,
            renderDim: renderDim,
            renderLive: renderLive,
            noteFocusChange: noteFocusChange,
            noteArrival: noteArrival,
            tickDim: tickDim,
            configureLive: configureLive,
            saveSetting: saveSetting,
            clearSetting: clearSetting,
            live: live,
            dim: dim,
            state: local,
        };
    }

    return { createSurfaces: createSurfaces };
});
