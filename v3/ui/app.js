/**
 * Noroshi v3 L7 — the thin DOM layer.
 *
 * Everything with a decision in it lives in the pure modules next to this
 * one and is tested under Node. This file does three things and no more:
 * it fetches, it hands payloads to a view model, and it writes the result
 * into the document. That division is P1 §11's, and it is the reason the
 * six v1 pure modules had 160 tests while radar.js had none.
 *
 * The page is the analyst's primary loop, in order. Section 1 is the
 * ten-second situation check, section 2 the thirty-second triage, section 3
 * the drilldown, section 4 the feedback, section 5 the weekly verification.
 * There is no floating panel and no panel manager: P8 §7 retires the panel
 * accumulation, and a surface whose structure is the loop does not need
 * one.
 *
 * Rendering goes through `NoroshiFreshness.createChangeDetector`. Nothing
 * here decides for itself whether something changed — the detector folds
 * the whole payload, so a field nobody thought about still forces a redraw
 * (G-10). Every section carries a freshness badge fed by the same fetch
 * result, so held data announces its age instead of impersonating live data.
 */
(function () {
    'use strict';

    var S = window.NoroshiStrings;
    var Fmt = window.NoroshiFormat;
    var Fresh = window.NoroshiFreshness;
    var Trust = window.NoroshiTrust;
    var Board = window.NoroshiBoard;
    var Lane = window.NoroshiLane;
    var Conc = window.NoroshiConclusions;
    var ClientLib = window.NoroshiClient;
    var Render = window.NoroshiRender;
    var Gate = window.NoroshiGate;
    var Surfaces = window.NoroshiSurfaces;
    var Dim = window.NoroshiDim;
    var Views = window.NoroshiViews;
    var Terms = window.NoroshiTerms;
    var BoardMap = window.NoroshiBoardMap;
    var BoardMapView = window.NoroshiBoardMapView;
    var MapCoords = window.NoroshiMapCoords;

    var _t = S.t;
    var esc = Fmt.escHtml;

    // The HTML builders live in render.js so they can be tested without
    // a DOM. This file keeps only the wiring.
    var freshnessBadge = Render.freshnessBadge;
    var trustChipHtml = Render.trustChipHtml;
    var cardHtml = Render.cardHtml;
    var laneRowHtml = Render.laneRowHtml;
    var conclusionRowHtml = Render.conclusionRowHtml;
    var feedbackFormHtml = Render.feedbackFormHtml;

    // ── local persistence: one key, one shape, defined once (DP9) ───────
    var STORE_KEY = 'noroshi.v3.ui.v1';
    //: `geoLayers` is here rather than in a second key because S1-UI-057's
    //: defect was that the map's layer choice did NOT persist — one shape,
    //: one key, and the choice survives a reload like every other piece of
    //: interaction state.
    var STORE_SHAPE = { focusedScenario: null, lastSeen: {}, tier: 0,
                        geoLayers: null };

    function loadStore() {
        try {
            var raw = window.localStorage.getItem(STORE_KEY);
            if (!raw) return Object.assign({}, STORE_SHAPE);
            var parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== 'object') return Object.assign({}, STORE_SHAPE);
            return Object.assign({}, STORE_SHAPE, parsed);
        } catch (err) {
            // A corrupt store degrades to defaults; it never takes the app down.
            return Object.assign({}, STORE_SHAPE);
        }
    }

    function saveStore(next) {
        try { window.localStorage.setItem(STORE_KEY, JSON.stringify(next)); }
        catch (err) { /* storage disabled: the UI works, memory does not persist */ }
    }

    // ── polling cadence (S1-UI-006) ─────────────────────────────────────
    var POLL_VISIBLE_MS = 15 * 60 * 1000;
    var POLL_HIDDEN_MS = 60 * 60 * 1000;

    //: The snooze window C4s accepts. Stated here so the prompt's
    //: promise ("1\u301c1440") and the check that enforces it cannot drift.
    var SNOOZE_MIN_MINUTES = 1;
    var SNOOZE_MAX_MINUTES = 1440;

    var state = {
        store: loadStore(),
        detector: Fresh.createChangeDetector(),
        client: null,
        results: {},            // key -> last fetch result
        timer: null,
        openConclusionId: null,
        feedback: {},           // conclusionId -> {label, reason, ...}
        replayAt: null,
        gate: null,
        session: null,
        surfaces: null,
        lane: null,             // last lane view model, for the display mode
        dimTimer: null,
        views: null,            // which view is on screen (P9 R-B)
        boardMapView: null,     // the real-map keeper (P9 §1.3, WP-4.5a)
        //: scenario_id -> the name the analyst reads, as R1 supplies it.
        //: A display lookup, never a source of truth: `scenario_id` stays
        //: the identity everywhere a value is keyed or sent.
        names: {},
    };

    // ── DOM helpers ─────────────────────────────────────────────────────

    function $(id) { return document.getElementById(id); }

    function setHtml(id, html) {
        var node = $(id);
        if (node) node.innerHTML = html;
    }

    /**
     * The operation-feedback surface DP1 recorded as missing entirely.
     *
     * v1 had no shared toast: `showToast` was referenced in two files and
     * defined in none, so snooze failures, export failures and anchor
     * submissions all failed in silence. Every non-idempotent command in
     * this file reports through here, success and failure alike.
     */
    function toast(kind, messageKey, vars) {
        var node = $('toast-rail');
        if (!node) return;
        var item = document.createElement('div');
        item.className = 'toast toast-' + kind;
        item.setAttribute('role', kind === 'error' ? 'alert' : 'status');
        item.textContent = _t(messageKey, vars);
        node.appendChild(item);
        window.setTimeout(function () {
            if (item.parentNode) item.parentNode.removeChild(item);
        }, 8000);
    }

    function commandFeedback(label, result) {
        if (result && result.ok) {
            toast('ok', 'ui.toast.command_ok', { what: _t(label) });
            return true;
        }
        var error = (result && result.error) || {};
        toast('error', 'ui.toast.command_failed', {
            what: _t(label),
            why: error.message || error.code || _t('ui.error.unknown'),
        });
        return false;
    }

    // ── freshness badge ─────────────────────────────────────────────────

    // ── section 1: the situation board ──────────────────────────────────

    function renderBoard() {
        var scenariosResult = state.results.R1;
        var conclusionsResult = state.results.R2;
        var selfEvalResult = state.results.R7;
        var thresholdsResult = state.results.R10;

        var board = Board.buildBoard({
            scenarios: scenariosResult ? scenariosResult.body : null,
            conclusions: conclusionsResult ? conclusionsResult.body : null,
            lastSeen: state.store.lastSeen,
        });
        var fold = Trust.foldTrust({
            selfEval: selfEvalResult && selfEvalResult.body
                ? selfEvalResult.body.self_eval : null,
            thresholds: thresholdsResult && thresholdsResult.body
                ? thresholdsResult.body.thresholds : null,
        });

        // Staleness is NEVER behind the redraw gate. A skipped redraw must
        // not be able to leave a badge claiming the data is current — that
        // combination is G-10 with an extra step.
        setHtml('board-freshness', freshnessBadge(scenariosResult));
        var breachNode = $('disclaimer-breach');
        if (breachNode) {
            breachNode.hidden = ![scenariosResult, conclusionsResult, selfEvalResult]
                .some(function (r) { return r && r.disclaimerMissing; });
        }

        // The signature is taken over the WHOLE fetch results, not a summary
        // of them: `shouldRender` strips the clock fields itself and folds
        // everything else. Nothing here enumerates what counts as a change.
        var decision = state.detector.shouldRender('board', {
            view: { board: board, fold: fold },
            results: [scenariosResult, conclusionsResult,
                      selfEvalResult, thresholdsResult,
                      state.results.R16],
        });
        if (!decision.render) return;

        // One issuer for the whole 状況 view, created here because the trust
        // chip and the cards are written in the same pass: P9 §4 marks a term
        // at its first occurrence IN THE VIEW, not once per builder.
        var terms = Terms.createMarkers(Views.SITUATION);
        setHtml('trust-slot', trustChipHtml(fold, terms));
        // The sentence first, then the cards it summarises (P9 R-A).
        setHtml('board-summary', Render.boardSummaryHtml(board.summary));
        var now = Date.now() / 1000;
        setHtml('board-cards', board.empty
            ? Render.emptyStateHtml(board.emptyState)
            : board.cards.map(function (card) {
                return cardHtml(card, now, terms);
            }).join(''));

        // The scenario map (P9 §2.2 R-F; real map per §1.3) — same R1 rows
        // the cards project, so it sits behind the same redraw decision: a
        // map that repaints when the cards were judged unchanged would be
        // two clocks. The view keeps the Leaflet instance across renders
        // and falls back to the tile grid when the library never loaded.
        var observationsResult = state.results.R16;
        var mapModel = BoardMap.buildBoardMap({
            scenarios: scenariosResult && scenariosResult.body
                ? scenariosResult.body.scenarios : null,
            observations: observationsResult && observationsResult.body
                ? observationsResult.body : null,
        });
        if (!state.boardMapView) {
            state.boardMapView = BoardMapView.createBoardMapView({
                doc: document,
                leaflet: typeof window.L !== 'undefined' ? window.L : null,
                containerId: 'board-map',
                coords: MapCoords,
                markerHtml: Render.bmMarkerHtml,
                obsMarkerHtml: Render.bmObsMarkerHtml,
                fallbackHtml: Render.boardMapHtml,
                emptyHtml: function (emptyState) {
                    return Render.emptyStateHtml(emptyState
                        || Fmt.emptyState('board_map',
                                          'empty.board_map.reason_not_loaded'));
                },
            });
        }
        var mapOutcome = state.boardMapView.render(mapModel);
        var noteNode = $('board-map-note');
        if (noteNode) {
            var unplacedOnMap = mapOutcome.unplaced || [];
            noteNode.hidden = unplacedOnMap.length === 0;
            noteNode.textContent = unplacedOnMap.length === 0 ? ''
                : _t('ui.board_map.unplaced_on_real',
                     { list: unplacedOnMap.join(', ') });
        }

        var names = {};
        board.cards.forEach(function (card) {
            if (card.displayName) names[card.scenarioId] = card.displayName;
        });
        state.names = names;
        renderScopeHead();

        state.store = Object.assign({}, state.store, {
            lastSeen: Board.rememberSeen(state.store.lastSeen, board.cards,
                                         Date.now() / 1000),
        });
        saveStore(state.store);
    }

    // ── section 2: the attention lane ───────────────────────────────────

    function renderLane() {
        var result = state.results.R6;
        var lane = Lane.buildLane({ attention: result ? result.body : null });
        // Kept whether or not the redraw proceeds: the display mode is a
        // function of the CURRENT lane, and feeding it a stale one because
        // the rows happened not to change is how a critical row raises no
        // banner.
        state.lane = lane;
        setHtml('lane-freshness', freshnessBadge(result));
        var showAll = state.store.tier >= 1;
        var decision = state.detector.shouldRender('lane', {
            view: lane, showAll: showAll, result: result,
        });
        if (!decision.render) return;

        var rows = showAll ? lane.rows : lane.tier0;
        setHtml('lane-rows', lane.empty
            ? Render.emptyStateHtml(lane.emptyState, { tag: 'li' })
            : rows.map(function (row) {
                return laneRowHtml(row, lane, state.names);
            }).join(''));
        setHtml('lane-summary', _t('ui.lane.summary', {
            shown: rows.length, total: lane.total,
            considered: lane.considered === null ? Fmt.ABSENT : lane.considered,
            filtered: lane.filteredBelowMinScore === null
                ? Fmt.ABSENT : lane.filteredBelowMinScore,
        }));
        // S1-UI-032: suppressed rows are counted in the open, always.
        setHtml('lane-suppressed', lane.suppressedCount === 0 ? ''
            : esc(_t('ui.lane.suppressed', {
                n: lane.suppressedCount,
                acked: lane.suppressedByState.acked,
                snoozed: lane.suppressedByState.snoozed,
                dismissed: lane.suppressedByState.dismissed,
            })));
        var more = $('lane-more');
        if (more) {
            more.hidden = lane.hiddenBelowCap === 0 && showAll;
            more.textContent = showAll
                ? _t('ui.lane.collapse')
                : _t('ui.lane.expand', { n: lane.hiddenBelowCap });
        }
    }

    // ── section 3: the conclusion face ──────────────────────────────────

    /**
     * Whose face is on screen (P9 §3.2).
     *
     * Written outside the redraw gate and re-run on every route change,
     * because the heading is a function of the ROUTE as well as of the
     * payload: a gate that folds only the payload would leave the previous
     * scenario's name above the next scenario's face, which is precisely
     * the mislabel S1-UI-048 exists to prevent.
     */
    function renderScopeHead() {
        var result = state.results.R2;
        var scope = Views.faceScope(
            state.views ? state.views.route() : null,
            (result && result.body) ? result.body.scenario_id : null,
            state.names);
        setHtml('scenario-view-head', Render.faceScopeHtml(scope));
    }

    function renderFace() {
        var result = state.results.R2;
        var thresholds = state.results.R10;
        var face = Conc.buildFace({
            conclusions: result ? result.body : null,
            thresholds: thresholds && thresholds.body ? thresholds.body.thresholds : null,
            reasonRegistry: thresholds && thresholds.body
                ? thresholds.body.unavailable_reason_registry : null,
        });
        setHtml('face-freshness', freshnessBadge(result));
        renderScopeHead();
        var decision = state.detector.shouldRender('face', {
            view: face, result: result, thresholds: thresholds,
        });
        if (!decision.render) return;

        // The scenario view's own term issuer: 結論不可 is defined at its
        // first appearance here, independently of the board's marker, because
        // the two views are separate readings (P9 §4).
        var terms = Terms.createMarkers(Views.SCENARIO);
        setHtml('face-sections', face.empty
            ? '<p class="empty">' + esc(_t(face.emptyKey)) + '</p>'
            : face.sections.map(function (section) {
                return '<section class="face-section" data-type="' + esc(section.type) + '">'
                    + '<h4>' + esc(_t(section.titleKey)) + '</h4>'
                    + (section.present
                        ? section.rows.map(function (row) {
                            return conclusionRowHtml(row, terms);
                        }).join('')
                        : '<p class="empty">' + esc(_t(section.emptyKey)) + '</p>')
                    + '</section>';
            }).join(''));

        var replay = $('replay-badge');
        if (replay) {
            replay.hidden = !face.isReplay;
            replay.textContent = face.isReplay
                ? _t('ui.replay.active', { at: Fmt.utcStamp(face.at) }) : '';
        }
        if (face.unreadableRows.length) {
            setHtml('face-unreadable', esc(_t('ui.conclusion.unreadable',
                                              { n: face.unreadableRows.length })));
        } else {
            setHtml('face-unreadable', '');
        }
    }

    // ── section 5: derivation, self-evaluation, ledger, what-if ─────────

    function renderDerivation() {
        var result = state.results.R4d;
        var thresholds = state.results.R10;
        var view = Conc.buildDerivation({
            derivation: result ? result.body : null,
            thresholds: thresholds && thresholds.body ? thresholds.body.thresholds : null,
        });
        if (!state.detector.shouldRender('derivation',
                { view: view, result: result, thresholds: thresholds }).render) return;
        setHtml('derivation-body', !view.present
            ? '<p class="empty">' + esc(_t(view.emptyKey)) + '</p>'
            : view.sections.map(Render.derivationSectionHtml).join(''));
    }

    function renderSelfEval() {
        var selfEval = state.results.R7;
        var sensors = state.results.R8;
        var thresholds = state.results.R10;
        var fold = Trust.foldTrust({
            selfEval: selfEval && selfEval.body ? selfEval.body.self_eval : null,
            thresholds: thresholds && thresholds.body ? thresholds.body.thresholds : null,
        });
        var sensorRows = (sensors && sensors.body && Array.isArray(sensors.body.sensors))
            ? sensors.body.sensors : [];
        if (!state.detector.shouldRender('selfeval', {
                fold: fold, selfEval: selfEval, sensors: sensors,
                thresholds: thresholds }).render) {
            return;
        }
        var terms = Terms.createMarkers(Views.VERIFY);
        setHtml('selfeval-components',
                fold.components.map(function (component) {
                    return Render.trustComponentRowHtml(component, terms);
                }).join(''));
        setHtml('sensor-rows', sensorRows.length === 0
            ? Render.emptyStateHtml(
                Fmt.emptyState('sensors', 'empty.sensors.reason_none'),
                { tag: 'tr', colspan: 6 })
            : sensorRows.map(Render.sensorRowHtml).join(''));
    }

    function renderDecisions() {
        var result = state.results.R9;
        var rows = (result && result.body && Array.isArray(result.body.decisions))
            ? result.body.decisions : [];
        if (!state.detector.shouldRender('decisions', result).render) return;
        setHtml('decision-rows', rows.length === 0
            ? Render.emptyStateHtml(
                Fmt.emptyState('decisions', 'empty.decisions.reason_none'),
                { tag: 'tr', colspan: 6 })
            : rows.map(Render.decisionRowHtml).join(''));
    }

    function renderProposals() {
        var result = state.results.R13;
        var rows = (result && result.body && Array.isArray(result.body.proposals))
            ? result.body.proposals : [];
        if (!state.detector.shouldRender('proposals', result).render) return;
        setHtml('proposal-rows', rows.length === 0
            ? Render.emptyStateHtml(
                Fmt.emptyState('proposals', 'empty.proposals.reason_none'),
                { tag: 'li' })
            : rows.map(Render.proposalRowHtml).join(''));
    }

    function renderWhatIf(diff) {
        setHtml('whatif-body', diff.emptyState
            ? Render.emptyStateHtml(diff.emptyState, { tag: 'tr', colspan: 5 })
            : diff.scenarios.map(Render.whatIfRowHtml).join(''));
    }


    // ── section 4: analyst feedback (C2) ────────────────────────────────

    /**
     * The label form for the currently opened conclusion.
     *
     * Rendered against R4, which carries the existing `analyst_labels`, so
     * the tally the analyst sees is the server's and not a local count.
     */
    function renderFeedback() {
        var conclusionId = state.openConclusionId;
        var result = state.results.R4;
        var labels = (result && result.ok && result.body)
            ? result.body.analyst_labels : null;
        var tally = Conc.labelTally(labels);
        var draft = state.feedback[conclusionId] || {};
        var formState = Conc.feedbackState({
            conclusionId: conclusionId,
            label: draft.label, reason: draft.reason,
            inFlight: draft.inFlight, savedAt: draft.savedAt,
            serverError: draft.serverError, networkError: draft.networkError,
        });
        if (!state.detector.shouldRender('feedback', {
                conclusionId: conclusionId, tally: tally,
                formState: formState, result: result }).render) {
            return;
        }
        setHtml('feedback-slot', feedbackFormHtml(conclusionId, tally, formState));
    }

    /**
     * Submit one label. The reason is required by C2 (§7-2 #78) and refused
     * here before the request, so an empty one costs no round trip.
     */
    function submitFeedback(conclusionId, button) {
        var label = button.getAttribute('data-label');
        var reason = askReason('ui.prompt.feedback_reason');
        if (reason === null) return;
        var url = window.prompt(_t('ui.prompt.feedback_url'));
        state.feedback[conclusionId] = { label: label, reason: reason, inFlight: true };
        state.detector.invalidate('feedback', 'feedback_submitting');
        renderFeedback();
        button.disabled = true;
        state.client.commands.feedback(conclusionId, {
            label: label, reason: reason,
            observed_outcome_url: (url && url.trim()) ? url.trim() : null,
        }).then(function (result) {
            state.feedback[conclusionId] = result.ok
                ? { label: label, reason: reason, savedAt: Date.now() / 1000 }
                : { label: label, reason: reason,
                    serverError: result.error && (result.error.message || result.error.code) };
            commandFeedback('ui.command.feedback', result);
            return result.ok ? state.client.reads.conclusion(conclusionId).then(record)
                : null;
        }).catch(function (err) {
            state.feedback[conclusionId] = {
                label: label, reason: reason,
                networkError: (err && err.message) || _t('ui.error.unknown'),
            };
        }).then(function () {
            button.disabled = false;
            state.detector.invalidate('feedback', 'feedback_settled');
            renderFeedback();
        });
    }

    // ── fetching ────────────────────────────────────────────────────────

    function record(result) {
        state.results[result.key] = result;
        return result;
    }

    function refresh(reason) {
        var focused = state.store.focusedScenario;
        var reads = [
            state.client.reads.scenarios().then(record),
            state.client.reads.observationBoard().then(record),
            state.client.reads.attention().then(record),
            state.client.reads.selfEval().then(record),
            state.client.reads.thresholds().then(record),
            state.client.reads.sensors().then(record),
            state.client.reads.decisions({ limit: 100 }).then(record),
            state.client.reads.proposals().then(record),
            // SETTINGS reads: the resolved values, the pinned catalogue it
            // is counted against, and the ground truth list P8 puts on the
            // same screen.
            state.client.reads.config().then(record),
            state.client.reads.groundTruth().then(record),
            // What the deployment says about its own socket channel. Asked
            // rather than assumed — see `live.js`.
            state.client.reads.appConfig().then(record),
        ];
        if (focused) {
            var params = state.replayAt ? { at: state.replayAt } : null;
            reads.push(state.client.reads.conclusions(focused, params).then(record));
            // R5 is the geographic face's only supply (P8 §2).
            reads.push(state.client.reads.evidence(focused, params).then(record));
        }
        // An open derivation is re-read with everything else. Leaving it on
        // the first response would make the one surface whose whole purpose
        // is "why does it say that" the one surface showing a stale answer.
        if (state.openConclusionId) {
            reads.push(state.client.reads
                .derivation(state.openConclusionId).then(record));
            reads.push(state.client.reads
                .conclusion(state.openConclusionId).then(record));
        }
        return Promise.all(reads).then(function () {
            // R1 is authoritative about focus; adopt it when the server and
            // this browser disagree, then re-read the focused projection.
            var r1 = state.results.R1;
            if (r1 && r1.ok && r1.body && r1.body.focused_scenario
                    && r1.body.focused_scenario !== state.store.focusedScenario) {
                var next = r1.body.focused_scenario;
                state.store = Object.assign({}, state.store,
                                            { focusedScenario: next });
                saveStore(state.store);
                state.detector.invalidateAll('focus_changed');
                // S1-UI-048 phase 1 opens here and is released by the
                // conclusions leg below; S1-UI-049 suppresses the whole
                // machine during a replay.
                if (state.surfaces) {
                    state.surfaces.noteFocusChange(next, state.replayAt !== null);
                }
                var at = state.replayAt ? { at: state.replayAt } : null;
                return Promise.all([
                    state.client.reads.conclusions(next, at).then(record),
                    state.client.reads.evidence(next, at).then(record),
                ]).then(function () {
                    if (state.surfaces) {
                        state.surfaces.noteArrival(Dim.LEG_CONCLUSIONS);
                        state.surfaces.noteArrival(Dim.LEG_LEDGER);
                    }
                    return null;
                });
            }
            return null;
        }).then(function () {
            renderAll(reason);
        });
    }

    /**
     * Render every section, and let one broken section fail alone.
     *
     * Each render is isolated because they are independent projections and a
     * malformed payload in one must not blank the other six. The failure is
     * announced rather than logged: a section that stopped drawing while the
     * rest of the screen kept updating is the most deceptive state this UI
     * can be in — everything looks live, and one panel is frozen at whatever
     * it last managed to draw. That is G-10 reached by a different route, so
     * it gets the same treatment: made loud.
     */
    function renderAll(reason) {
        if (reason) state.detector.invalidateAll(reason);
        var sections = [
            ['board', renderBoard], ['lane', renderLane], ['face', renderFace],
            ['selfeval', renderSelfEval], ['decisions', renderDecisions],
            ['proposals', renderProposals], ['derivation', renderDerivation],
            ['feedback', renderFeedback],
            // The four WP-4.3 surfaces render inside the same isolation, so
            // a malformed evidence payload takes the map down and nothing
            // else — and says so instead of freezing quietly.
            ['surfaces', function () {
                if (state.surfaces) state.surfaces.renderAll(state.lane);
            }],
        ];
        sections.forEach(function (entry) {
            try {
                entry[1]();
            } catch (err) {
                // The signature must not survive a failed render, or the next
                // cycle would decide "nothing changed" and never retry.
                state.detector.invalidate(entry[0], 'render_failed');
                toast('error', 'ui.toast.render_failed', {
                    section: entry[0],
                    why: (err && err.message) || _t('ui.error.unknown'),
                });
            }
        });
    }

    /**
     * The polling loop, which must survive anything.
     *
     * `schedule` is called from the `finally` of every cycle. Without that, a
     * single thrown render would drop the `.then` chain and the 15-minute
     * poll would stop forever, with no error visible anywhere — the screen
     * would simply stop updating and keep claiming to be a live display.
     */
    function schedule() {
        if (state.timer) window.clearTimeout(state.timer);
        var interval = document.hidden ? POLL_HIDDEN_MS : POLL_VISIBLE_MS;
        state.timer = window.setTimeout(function () {
            cycle(null);
        }, interval);
    }

    function cycle(reason) {
        // Nothing is fetched while the gate is closed. A locked screen that
        // kept polling would answer 401 into an overlay nobody can see
        // past, and would rearm the timer on every failure.
        if (state.session && !state.session.isOpen()) {
            return Promise.resolve();
        }
        return refresh(reason).catch(function (err) {
            toast('error', 'ui.toast.refresh_failed', {
                why: (err && err.message) || _t('ui.error.unknown'),
            });
        }).then(schedule, schedule);
    }

    // ── commands ────────────────────────────────────────────────────────

    function askReason(promptKey) {
        var reason = window.prompt(_t(promptKey));
        if (reason === null) return null;
        if (!reason.trim()) {
            toast('error', 'ui.toast.reason_required');
            return null;
        }
        return reason.trim();
    }

    /**
     * S1-UI-035: the UI moves only after the server has confirmed. No
     * optimistic update — the projection is re-read and re-rendered from
     * what the server now says, so a failure cannot leave the screen
     * claiming something the ledger does not contain.
     */
    function afterCommand(label, result) {
        if (!commandFeedback(label, result)) return Promise.resolve();
        return refresh('command_committed');
    }

    /**
     * The command surface, as data.
     *
     * Each entry names the attribute that triggers it, what it needs from
     * the analyst before it will run, and the command to send. Written as a
     * table rather than a chain of `if` blocks because seven near-identical
     * branches is where one of them quietly loses its confirmation gate —
     * which is the shape of G-01 one layer up.
     */
    var COMMANDS = [
        { attr: 'data-focus', label: 'ui.command.focus',
          reasonKey: 'ui.prompt.focus_reason',
          send: function (id, ctx) { return state.client.commands.focus(id, ctx.reason); } },
        { attr: 'data-ack', label: 'ui.command.ack',
          send: function (id) { return state.client.commands.ack(id, null); } },
        { attr: 'data-snooze', label: 'ui.command.snooze', minutes: true,
          send: function (id, ctx) {
              return state.client.commands.snooze(id, ctx.minutes, null);
          } },
        { attr: 'data-dismiss', label: 'ui.command.dismiss',
          send: function (id) { return state.client.commands.dismiss(id, null); } },
        { attr: 'data-proposal-apply', label: 'ui.command.proposal_apply',
          reasonKey: 'ui.prompt.proposal_reason',
          confirmKey: 'ui.confirm.proposal_apply',
          send: function (id, ctx) {
              return state.client.commands.applyProposal(id, ctx.reason);
          } },
        { attr: 'data-proposal-dismiss', label: 'ui.command.proposal_dismiss',
          reasonKey: 'ui.prompt.proposal_reason',
          send: function (id, ctx) {
              return state.client.commands.dismissProposal(id, ctx.reason);
          } },
        { attr: 'data-proposal-defer', label: 'ui.command.proposal_defer',
          reasonKey: 'ui.prompt.proposal_reason',
          send: function (id, ctx) {
              return state.client.commands.deferProposal(id, ctx.reason);
          } },
    ];

    /** Gather what a command needs, or null if the analyst backed out. */
    function collect(spec) {
        var ctx = {};
        if (spec.reasonKey) {
            ctx.reason = askReason(spec.reasonKey);
            if (ctx.reason === null) return null;
        }
        if (spec.minutes) {
            var raw = window.prompt(_t('ui.prompt.snooze_minutes'));
            if (raw === null) return null;
            var minutes = parseInt(raw, 10);
            // The prompt promises 1–1440; refusing here rather than letting
            // the server refuse means the analyst sees why immediately, and
            // the clamp the server applies is never a silent correction.
            if (!Number.isFinite(minutes) || minutes < SNOOZE_MIN_MINUTES
                    || minutes > SNOOZE_MAX_MINUTES) {
                toast('error', 'ui.toast.bad_minutes');
                return null;
            }
            ctx.minutes = minutes;
        }
        if (spec.confirmKey && !window.confirm(_t(spec.confirmKey))) return null;
        return ctx;
    }

    /**
     * Run one command with the button disabled until the server has answered
     * AND the projections have been re-read.
     *
     * Without the guard a second click reaches the server before the row
     * re-renders, and for a proposal that is two adjudications of the same
     * proposal in the decision ledger — an audit trail that records an
     * intent the analyst had once.
     */
    function runCommand(spec, id, button) {
        var ctx = collect(spec);
        if (ctx === null) return;
        if (button) button.disabled = true;
        spec.send(id, ctx)
            .then(function (result) { return afterCommand(spec.label, result); })
            .catch(function (err) {
                toast('error', 'ui.toast.command_failed', {
                    what: _t(spec.label),
                    why: (err && err.message) || _t('ui.error.unknown'),
                });
            })
            .then(function () { if (button) button.disabled = false; });
    }

    /**
     * The "なぜ?" trail (D-7): a conclusion leads to the derivation view.
     *
     * The route moves BEFORE the read, so the analyst is looking at the
     * surface the answer will land on rather than watching a section they
     * cannot see refresh itself.
     */
    function openDerivation(conclusionId, button) {
        state.openConclusionId = conclusionId;
        if (state.views) state.views.go(Views.hashFor(Views.VERIFY, null));
        if (button) button.disabled = true;
        Promise.all([
            state.client.reads.derivation(conclusionId).then(record),
            state.client.reads.conclusion(conclusionId).then(record),
        ]).then(function () {
            state.detector.invalidate('feedback', 'conclusion_opened');
            renderFeedback();
            state.detector.invalidate('derivation', 'conclusion_opened');
            renderDerivation();
            var section = $('stage-5');
            if (section && section.scrollIntoView) {
                section.scrollIntoView({ behavior: 'smooth' });
            }
        }).then(function () { if (button) button.disabled = false; },
                function () { if (button) button.disabled = false; });
    }

    function onClick(event) {
        var target = event.target;
        if (!(target instanceof window.HTMLElement)) return;
        if (target.disabled) return;

        // Navigation before commands: opening a scenario face changes only
        // what is on screen. It sends nothing, writes nothing to the
        // ledger, and does not move focus — moving focus is C1, and it
        // asks for a reason because it is a decision (S1-UI-035).
        var openScenario = target.getAttribute('data-open-scenario');
        if (openScenario && state.views) {
            state.views.go(Views.hashFor(Views.SCENARIO, openScenario));
            return;
        }

        for (var i = 0; i < COMMANDS.length; i += 1) {
            var id = target.getAttribute(COMMANDS[i].attr);
            if (id) { runCommand(COMMANDS[i], id, target); return; }
        }

        var deriveId = target.getAttribute('data-derive');
        if (deriveId) { openDerivation(deriveId, target); return; }

        var labelId = target.getAttribute('data-label-for');
        if (labelId) { submitFeedback(labelId, target); }
    }

    /**
     * Card ⇄ map highlight (P9 §3.7). Pointing at a card lights the tiles
     * of that scenario's participants — the map answers "where" for the
     * card under the pointer. Delegated from the card container so a
     * redraw does not shed the listeners; keyboard focus gets the same
     * treatment as hover (the strip's facts are already in the cards, so
     * this is emphasis, not information).
     */
    function _setMapHighlight(scenarioId, on) {
        var map = $('board-map');
        if (!map) return;
        var tiles = map.querySelectorAll(
            '[data-map-scenarios~="' + scenarioId + '"]');
        for (var i = 0; i < tiles.length; i += 1) {
            tiles[i].classList.toggle('map-hot', on);
        }
    }

    function _cardScenarioOf(node) {
        while (node && node !== document) {
            if (node instanceof window.HTMLElement
                    && node.hasAttribute('data-scenario')) {
                return node.getAttribute('data-scenario');
            }
            node = node.parentNode;
        }
        return null;
    }

    function bindMapHighlight() {
        var cards = $('board-cards');
        if (!cards) return;
        var hot = null;
        var move = function (event) {
            var id = _cardScenarioOf(event.target);
            if (id === hot) return;
            if (hot !== null) _setMapHighlight(hot, false);
            hot = id;
            if (hot !== null) _setMapHighlight(hot, true);
        };
        var leave = function () {
            if (hot !== null) _setMapHighlight(hot, false);
            hot = null;
        };
        cards.addEventListener('mouseover', move);
        cards.addEventListener('mouseleave', leave);
        cards.addEventListener('focusin', move);
        cards.addEventListener('focusout', leave);
    }

    function bindLaneToggle() {
        var more = $('lane-more');
        if (!more) return;
        more.addEventListener('click', function () {
            state.store = Object.assign({}, state.store,
                                        { tier: state.store.tier >= 1 ? 0 : 1 });
            saveStore(state.store);
            state.detector.invalidate('lane', 'tier_toggled');
            renderLane();
        });
    }

    function bindRefresh() {
        var refreshBtn = $('refresh-btn');
        if (!refreshBtn) return;
        refreshBtn.addEventListener('click', function () {
            refreshBtn.disabled = true;
            cycle('manual_refresh').then(function () {
                refreshBtn.disabled = false;
            }, function () { refreshBtn.disabled = false; });
        });
    }

    function bindReplay() {
        var replayInput = $('replay-at');
        if (!replayInput) return;
        replayInput.addEventListener('change', function () {
            var value = replayInput.value ? Date.parse(replayInput.value) : NaN;
            state.replayAt = Number.isFinite(value) ? Math.floor(value / 1000) : null;
            // S1-UI-012: a replay cross-section invalidates every cached
            // signature; the same components then render past data.
            cycle('replay_applied');
        });
    }

    function bindWhatIf() {
        var whatifBtn = $('whatif-run');
        if (!whatifBtn) return;
        whatifBtn.addEventListener('click', function () {
            var raw = $('whatif-overlay') ? $('whatif-overlay').value : '';
            var overlay;
            try { overlay = raw ? JSON.parse(raw) : {}; }
            catch (err) {
                toast('error', 'ui.toast.bad_overlay');
                return;
            }
            whatifBtn.disabled = true;
            state.client.commands.whatIf(overlay).then(function (result) {
                if (!result.ok) {
                    commandFeedback('ui.command.whatif', result);
                    renderWhatIf({ present: false, scenarios: [],
                                   emptyState: Fmt.emptyState(
                                       'whatif', 'empty.whatif.reason_not_run') });
                    return;
                }
                renderWhatIf(Conc.diffWhatIf(result.body));
            }).catch(function (err) {
                toast('error', 'ui.toast.command_failed', {
                    what: _t('ui.command.whatif'),
                    why: (err && err.message) || _t('ui.error.unknown'),
                });
            }).then(function () { whatifBtn.disabled = false; });
        });
    }

    function bind() {
        document.addEventListener('click', onClick);
        bindMapHighlight();
        bindLaneToggle();
        bindRefresh();
        bindReplay();
        bindWhatIf();
        // S1-UI-006: coming back into view refetches immediately, then
        // resumes the slower cadence. Without it there is a blind window.
        document.addEventListener('visibilitychange', function () {
            if (!document.hidden) cycle('became_visible');
            else schedule();
        });
    }

    function transport(url, init) {
        return window.fetch(url, init).then(function (response) {
            return response.json()
                .catch(function () { return null; })
                .then(function (json) {
                    return { status: response.status, json: json };
                });
        });
    }

    function boot() {
        S.applyStatic(document);
        // The session comes first: it decides whether anything else runs.
        // Its access token lives in memory, never in `localStorage` — what
        // survives a reload is the httpOnly refresh cookie (§7-2 #103).
        state.gate = Gate.createGateUi({
            doc: document,
            transport: transport,
            onOpen: function () { cycle('signed_in'); },
            // A locked screen stops polling: otherwise it keeps answering
            // 401 behind an overlay nobody can see past.
            onLock: function () {
                if (state.timer) {
                    window.clearTimeout(state.timer);
                    state.timer = null;
                }
            },
            onRefused: function (key) { toast('error', key); },
        });
        state.session = state.gate.session;
        state.client = ClientLib.createClient({
            transport: transport,
            tokenProvider: function () { return state.session.token(); },
            // A 401 mid-session refreshes once and then locks the gate with
            // the reason on screen. Never a panel that silently stops.
            onUnauthorized: function () {
                return state.session.onUnauthorized();
            },
        });
        // Every deferred surface says "not served yet" rather than showing
        // an empty panel that looks like "nothing to see".
        Object.keys(ClientLib.DEFERRED).forEach(function (id) {
            var node = document.querySelector('[data-deferred="' + id + '"]');
            if (node) node.textContent = _t(ClientLib.DEFERRED[id]);
        });
        state.surfaces = Surfaces.createSurfaces({
            doc: document,
            client: state.client,
            detector: state.detector,
            toast: toast,
            refresh: refresh,
            results: function () { return state.results; },
            focus: function () { return state.store.focusedScenario; },
            layers: function () { return state.store.geoLayers; },
            saveLayers: function (next) {
                state.store = Object.assign({}, state.store, { geoLayers: next });
                saveStore(state.store);
            },
            ask: askReason,
            confirm: function (key, vars) { return window.confirm(_t(key, vars)); },
        });
        // The view split (P9 R-B). Created before the first render so the
        // Tier 2 tables are already off screen when they first draw: a
        // frame of the audit view under the situation board is D-1 again,
        // however briefly.
        state.views = Views.createViews({
            doc: document,
            win: window,
            onRoute: function () { renderScopeHead(); },
        });
        state.views.bind();
        bind();
        state.surfaces.bind();
        // The dim's timeouts are the only thing in this layer that needs a
        // clock of its own: without it a stalled leg would sit under a mask
        // that never grew a sentence (S1-UI-049).
        state.dimTimer = window.setInterval(function () {
            state.surfaces.tickDim();
        }, 1000);
        state.gate.bind();
        renderWhatIf({ present: false, scenarios: [],
                       emptyState: Fmt.emptyState('whatif',
                                                  'empty.whatif.reason_not_run') });
        // `begin()` asks the server whether this browser still holds a
        // session, and `onOpen` starts the loop if it does. Nothing fetches
        // before that answer — a dashboard drawn first and gated afterwards
        // is a dashboard that leaked one frame.
        state.gate.render();
        return state.gate.begin();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
