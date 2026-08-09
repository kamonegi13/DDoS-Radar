/**
 * Noroshi v3 L7 — the geographic face of O-4 (pure, DOM-free).
 *
 * P8 §6 demoted the map. The forward derivation found exactly one question
 * it answers — *"where is the anomaly happening"* — and situation checking,
 * which used to be the reason the map sat in the middle of the screen, is
 * answered by the board. So this is Tier 1, four layers rather than twenty,
 * and it is built from R1 (who is in the scenario, and in what role) and R5
 * (what fired, where, and what was suppressed).
 *
 * **There is no cartographic projection here, and that is a server gap
 * rather than a design choice.** `v3/runtime/geo.py` holds
 * `country_coordinates`, `chokepoints` and the ISR `zones` with real
 * latitudes, and the composition root loads all of it — but nothing puts
 * any of it on the wire. `ScenarioRef` carries participants, roles,
 * adversaries and the chain country and says in its own docstring that the
 * API does not read `geo_data.json` because "a second reader of deployment
 * data is a second ledger that drifts". Shipping a coordinate table inside
 * this file would BE that second reader, and it would be one the backend
 * could not see drifting. So the face is drawn at the granularity the
 * server actually serves — the country — and the layer that needs pixels
 * declares itself unserved instead of being drawn from browser-side
 * geography. P8 §6 already defaults that layer to OFF; what changes is that
 * it now says why it is empty rather than looking switched off.
 *
 * The layers that DO survive are all here and all server-fed:
 *
 *   * **participants**, with the role as the first visual dimension —
 *     S1-UI-060's thirteen roles onto five classes, unknown roles onto the
 *     observer class, marker weight from the coupling weight the scoring
 *     kernel actually uses.
 *   * **anomaly markers**, from R5's fired rows, attached to the
 *     participant they belong to rather than drawn a second time beside it
 *     (S1-UI-058's no-double-draw rule, which is the reason the v1 map had
 *     two dots for one BGP outage).
 *   * **suppressed rows, kept visible with their reason** — E-17 and
 *     S1-UI-040. A signal that fired and was excluded is not the same fact
 *     as a signal that did not fire, and rendering both as quiet is how a
 *     map reports calm it has not observed.
 *   * **the sequence chain's country**, which R1 names (`chain_country`).
 *
 * G-17 governs the empty states: "not fetched", "fetched, no observations
 * at all" and "observed, nothing fired" are three different claims and the
 * face makes an analyst able to tell which one they are looking at.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiGeo = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * S1-UI-060: thirteen roles, five visual classes, role first.
     *
     * The mapping is a display decision — it groups labels the server sends
     * into the five things an analyst needs to tell apart at a glance — and
     * it changes no number. An unlisted role lands in `observer`, which is
     * the class that claims least.
     */
    var ROLE_CLASS = {
        primary_target: 'target',
        principal_belligerent: 'target',
        adversary: 'adversary',
        proxy_front: 'adversary',
        primary_ally: 'allied',
        secondary_ally: 'allied',
        forward_base: 'allied',
        extended_deterrence: 'allied',
        force_projection: 'allied',
        spillover_risk: 'unstable',
        secondary_party: 'unstable',
        regional_power: 'unstable',
        strategic_observer: 'observer',
    };
    var CLASSES = ['target', 'adversary', 'allied', 'unstable', 'observer'];
    var UNKNOWN_CLASS = 'observer';

    //: R5 tags countryless observations with this. It is a bucket, never a
    //: participant — folding global signals into a country would attribute
    //: them to somewhere they were not observed.
    var GLOBAL = 'GLOBAL';

    var FIRED = 'FIRED';

    /**
     * The four layers P8 §6 keeps, and whether each can be drawn.
     *
     * `reference` is present with `available: false` rather than absent:
     * P8 keeps the layer, the server does not supply it, and a toggle that
     * silently does nothing is worse than one that says what it is waiting
     * for.
     */
    var LAYERS = [
        { id: 'participants', defaultOn: true, available: true },
        { id: 'anomalies', defaultOn: true, available: true },
        { id: 'chain', defaultOn: true, available: true },
        { id: 'reference', defaultOn: false, available: false,
          unavailableKey: 'ui.geo.layer.reference_unserved' },
    ];

    function _layerState(saved) {
        var out = {};
        LAYERS.forEach(function (layer) {
            if (!layer.available) { out[layer.id] = false; return; }
            var stored = saved && Object.prototype.hasOwnProperty.call(saved, layer.id)
                ? saved[layer.id] : undefined;
            out[layer.id] = typeof stored === 'boolean' ? stored : layer.defaultOn;
        });
        return out;
    }

    function _scenarioRow(scenarios, scenarioId) {
        var rows = (scenarios && Array.isArray(scenarios.scenarios))
            ? scenarios.scenarios : [];
        for (var i = 0; i < rows.length; i += 1) {
            if (rows[i] && rows[i].scenario_id === scenarioId) return rows[i];
        }
        return null;
    }

    function _num(value) {
        return typeof value === 'number' && Number.isFinite(value) ? value : null;
    }

    /**
     * Fold R5's matrix into per-country buckets.
     *
     * Fired and suppressed are counted separately and the suppressed rows
     * keep their reason, because "nothing fired" and "it fired and we
     * excluded it" are the two facts E-17 says a surface must not merge.
     */
    function _byCountry(evidence) {
        var matrix = (evidence && Array.isArray(evidence.matrix))
            ? evidence.matrix : [];
        var buckets = Object.create(null);
        matrix.forEach(function (row) {
            if (!row) return;
            var country = typeof row.country === 'string' && row.country
                ? row.country : GLOBAL;
            var bucket = buckets[country];
            if (!bucket) {
                bucket = { country: country, observations: 0, fired: [],
                           suppressed: [], domains: {}, sensors: {} };
                buckets[country] = bucket;
            }
            bucket.observations += 1;
            if (row.domain) bucket.domains[row.domain] = true;
            if (row.sensor) bucket.sensors[row.sensor] = true;
            if (row.suppressed === true) {
                bucket.suppressed.push({
                    sensor: row.sensor || null,
                    domain: row.domain || null,
                    reason: row.suppress_reason || null,
                    observedAt: _num(row.observed_at),
                });
            } else if (row.status === FIRED) {
                bucket.fired.push({
                    sensor: row.sensor || null,
                    domain: row.domain || null,
                    rawScore: _num(row.raw_score),
                    confidence: _num(row.confidence),
                    observedAt: _num(row.observed_at),
                    evidenceUrl: typeof row.evidence_url === 'string'
                        ? row.evidence_url : null,
                });
            }
        });
        return buckets;
    }

    function _marker(country, role, weight, bucket, extras) {
        var domains = bucket ? Object.keys(bucket.domains).sort() : [];
        return {
            country: country,
            role: role || null,
            roleClass: (role && ROLE_CLASS[role]) || UNKNOWN_CLASS,
            roleKnown: !!(role && Object.prototype.hasOwnProperty.call(ROLE_CLASS, role)),
            // The coupling weight the kernel scores with, verbatim. It sizes
            // the marker; it is never recombined into anything.
            weight: _num(weight),
            isAdversary: extras.isAdversary === true,
            isChainCountry: extras.isChainCountry === true,
            observations: bucket ? bucket.observations : 0,
            firedCount: bucket ? bucket.fired.length : 0,
            suppressedCount: bucket ? bucket.suppressed.length : 0,
            fired: bucket ? bucket.fired : [],
            suppressed: bucket ? bucket.suppressed : [],
            domains: domains,
            sensors: bucket ? Object.keys(bucket.sensors).sort() : [],
            // G-17 at marker granularity: a participant with no row at all
            // is not a participant that is quiet.
            stateKey: !bucket ? 'ui.geo.marker.unobserved'
                : (bucket.fired.length ? 'ui.geo.marker.fired'
                    : (bucket.suppressed.length ? 'ui.geo.marker.suppressed_only'
                        : 'ui.geo.marker.observed_quiet')),
        };
    }

    /**
     * Order: loudest first, then role class, then country.
     *
     * Fired count before coupling weight, because the question this face
     * answers is "where is it happening" and not "who matters most" — the
     * board already answers the second one.
     */
    function _byLoudness(a, b) {
        if (a.firedCount !== b.firedCount) return b.firedCount - a.firedCount;
        if (a.suppressedCount !== b.suppressedCount) {
            return b.suppressedCount - a.suppressedCount;
        }
        var ra = CLASSES.indexOf(a.roleClass);
        var rb = CLASSES.indexOf(b.roleClass);
        if (ra !== rb) return ra - rb;
        return a.country < b.country ? -1 : (a.country > b.country ? 1 : 0);
    }

    /**
     * Build the geographic face.
     *
     * @param {object} input
     * @param {object|null} input.scenarios  R1 body
     * @param {object|null} input.evidence   R5 body
     * @param {string|null} input.scenarioId the focused scenario
     * @param {object|null} input.layers     persisted layer toggles
     * @returns {object}
     */
    function buildFace(input) {
        input = input || {};
        var scenarioId = input.scenarioId || null;
        var row = _scenarioRow(input.scenarios, scenarioId);
        var evidence = (input.evidence && input.evidence.evidence)
            ? input.evidence.evidence : null;
        var layers = _layerState(input.layers);

        var participants = (row && row.participants) ? row.participants : {};
        var roles = (row && row.roles) ? row.roles : {};
        var adversaries = (row && Array.isArray(row.adversaries))
            ? row.adversaries : [];
        var chainCountry = row ? (row.chain_country || null) : null;
        var buckets = _byCountry(evidence);

        var markers = Object.keys(participants).sort().map(function (country) {
            return _marker(country, roles[country], participants[country],
                           buckets[country] || null,
                           { isAdversary: adversaries.indexOf(country) !== -1,
                             isChainCountry: chainCountry === country });
        });
        markers.sort(_byLoudness);

        // S1-UI-058: a country already drawn as a participant is not drawn
        // again as a signal. Everything left over — GLOBAL, and any country
        // the ledger observed that the scenario does not list — becomes its
        // own row, because dropping it would hide an observation whose only
        // fault is that nobody declared it a participant.
        var declared = {};
        markers.forEach(function (m) { declared[m.country] = true; });
        var offRoster = Object.keys(buckets).sort()
            .filter(function (country) { return !declared[country]; })
            .map(function (country) {
                return _marker(country, null, null, buckets[country],
                               { isAdversary: adversaries.indexOf(country) !== -1,
                                 isChainCountry: chainCountry === country });
            });
        offRoster.sort(_byLoudness);

        var firedTotal = markers.concat(offRoster).reduce(
            function (sum, m) { return sum + m.firedCount; }, 0);
        var suppressedTotal = markers.concat(offRoster).reduce(
            function (sum, m) { return sum + m.suppressedCount; }, 0);
        var observationTotal = evidence
            && typeof evidence.observation_count === 'number'
            ? evidence.observation_count : null;

        // Three distinct emptinesses (G-17). "Nothing on the map" must never
        // be the same picture for "we have not asked", "we asked and the
        // ledger is empty" and "we asked, there are observations, none of
        // them fired".
        var emptyKey = null;
        if (!scenarioId) emptyKey = 'ui.geo.empty.no_focus';
        else if (!row) emptyKey = 'ui.geo.empty.scenario_not_loaded';
        else if (evidence === null) emptyKey = 'ui.geo.empty.not_loaded';
        else if (observationTotal === 0) emptyKey = 'ui.geo.empty.no_observations';
        else if (firedTotal === 0 && suppressedTotal === 0) {
            emptyKey = 'ui.geo.empty.observed_nothing_fired';
        }

        return {
            scenarioId: scenarioId,
            present: !!(row && evidence),
            markers: markers,
            offRoster: offRoster,
            chainCountry: chainCountry,
            layers: layers,
            layerCatalogue: LAYERS,
            windowSec: evidence ? _num(evidence.window_sec) : null,
            at: evidence ? _num(evidence.at) : null,
            countries: evidence && Array.isArray(evidence.countries)
                ? evidence.countries : [],
            firedTotal: firedTotal,
            suppressedTotal: suppressedTotal,
            observationTotal: observationTotal,
            participantCount: markers.length,
            emptyKey: emptyKey,
            // The unserved layer, named with its reason rather than hidden.
            unservedLayers: LAYERS.filter(function (l) { return !l.available; })
                .map(function (l) {
                    return { id: l.id, reasonKey: l.unavailableKey };
                }),
        };
    }

    /** Flip one layer, immutably. Refuses layers the server cannot supply. */
    function toggleLayer(layers, layerId) {
        var current = _layerState(layers);
        var entry = null;
        LAYERS.forEach(function (l) { if (l.id === layerId) entry = l; });
        if (!entry || !entry.available) return current;
        var next = {};
        Object.keys(current).forEach(function (key) { next[key] = current[key]; });
        next[layerId] = !current[layerId];
        return next;
    }

    return {
        buildFace: buildFace,
        toggleLayer: toggleLayer,
        layerState: _layerState,
        ROLE_CLASS: ROLE_CLASS,
        CLASSES: CLASSES,
        UNKNOWN_CLASS: UNKNOWN_CLASS,
        LAYERS: LAYERS,
        GLOBAL: GLOBAL,
    };
});
