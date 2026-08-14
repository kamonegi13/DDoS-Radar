/**
 * Noroshi v3 L7 — the situation view's scenario map (pure, DOM-free).
 *
 * P9 §2.2 R-F, answering diagnosis D-10: the second owner review (2026-08-13)
 * found that a scenario card is a number with no geography — "which region
 * is this even about" had no answer on the opening screen, where v1 kept a
 * map beside the numbers precisely for that question. The tile map WP-4.3d
 * built answers it, but only inside the scenario face and only for the
 * focused scenario.
 *
 * This module draws the WHOLE board: every participant of every configured
 * scenario, from R1 rows alone (participants / roles / adversaries /
 * threat_level). No event dots — events are R2's and R2 is fetched for the
 * focused scenario only, and a map that draws only the dots it happens to
 * have looks like a map of where it is quiet (S1-UI-048's shape). Where a
 * country sits comes from `geo_tiles.js`'s placement table, which stays the
 * single frontend authority on cells; this module re-derives nothing about
 * placement and adds no coordinates.
 *
 * Colour rule (P9 §3.7): a country participating in several scenarios is
 * painted with the MOST SEVERE of its scenarios' current threat levels —
 * comparison in severity space (6 − TL), never TL space, through
 * `format.js`'s `severityOf` (the 2026-08-02 inversion is why that detour
 * exists). Scenarios whose TL is null rank below every measured one, and a
 * country whose every scenario is unmeasured is painted as unknown rather
 * than as calm (G-17: absence of a measurement is not NORMAL).
 *
 * The adversary ring marks a country declared as the attacking side in ANY
 * of its scenarios: the mark means "a belligerent somewhere on this board",
 * and the tooltip carries the per-scenario detail.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiBoardMap = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var F = (typeof require === 'function')
        ? require('./format')
        : (typeof window !== 'undefined' ? window.NoroshiFormat : null);
    var Tiles = (typeof require === 'function')
        ? require('./geo_tiles')
        : (typeof window !== 'undefined' ? window.NoroshiGeoTiles : null);

    /**
     * One (country, scenario) membership. `severity` is the sort key and
     * `null` means "not measured", which sorts after every measured value
     * rather than as zero — an unmeasured scenario is not a calm one.
     */
    function _membership(scenario, country) {
        var participants = scenario.participants || {};
        var roles = scenario.roles || {};
        var adversaries = Array.isArray(scenario.adversaries)
            ? scenario.adversaries : [];
        var tl = typeof scenario.threat_level === 'number'
            ? scenario.threat_level : null;
        return {
            scenarioId: scenario.scenario_id,
            displayName: (typeof scenario.display_name_ja === 'string'
                          && scenario.display_name_ja)
                ? scenario.display_name_ja : scenario.scenario_id,
            tl: F.tlBand(tl),
            severity: F.severityOf(tl),
            weight: typeof participants[country] === 'number'
                ? participants[country] : null,
            role: typeof roles[country] === 'string' ? roles[country] : null,
            isAdversary: adversaries.indexOf(country) !== -1,
            focused: scenario.focused === true,
            //: R-I (P9 §1.9): the 24h severity movement, signed. The map
            //: reserves motion for exactly this — a scenario that moved
            //: pulses through its participants; one that did not sits
            //: quiet. null = not comparable, which is quiet too (a change
            //: nobody measured must not glow, G-17).
            severityDelta: typeof scenario.severity_delta_24h === 'number'
                ? scenario.severity_delta_24h : null,
        };
    }

    /** Severity desc, null last; scenario id breaks ties (AP2 — two renders
     *  of the same board paint the same dominant scenario). */
    function _byDominance(a, b) {
        if (a.severity === null && b.severity !== null) return 1;
        if (b.severity === null && a.severity !== null) return -1;
        if (a.severity !== null && b.severity !== null
                && a.severity !== b.severity) {
            return b.severity - a.severity;
        }
        return a.scenarioId < b.scenarioId ? -1
            : (a.scenarioId > b.scenarioId ? 1 : 0);
    }

    /**
     * R16's row for one country, re-keyed for display (P8 §9 / NP9).
     *
     * The sweep band is load-bearing: `silent` must stay distinguishable
     * from "zero fired", because a country nobody swept and a country
     * that was swept and stayed quiet are different facts (G-17). A
     * missing R16 envelope degrades to `null` — the tile then says
     * "observation supply absent", never "no observations".
     */
    function _observationOf(entry) {
        if (!entry) return null;
        return {
            band: entry.band || null,
            fired: typeof entry.fired_total === 'number'
                ? entry.fired_total : null,
            suppressed: typeof entry.suppressed_total === 'number'
                ? entry.suppressed_total : null,
            domains: entry.domains || {},
        };
    }

    function _tile(country, memberships, observation, attentionTop) {
        var sorted = memberships.slice().sort(_byDominance);
        var dominant = sorted[0] && sorted[0].severity !== null
            ? sorted[0] : null;
        var placement = Tiles.placementOf(country);
        var band = dominant ? dominant.tl : F.tlBand(null);
        // R-I: worsened wins over improved when a country sits in both —
        // NP1's direction, applied to emphasis.
        var worsened = sorted.some(function (m) {
            return m.severityDelta !== null && m.severityDelta > 0;
        });
        var improved = sorted.some(function (m) {
            return m.severityDelta !== null && m.severityDelta < 0;
        });
        return {
            //: 'worse' | 'better' | null — what the pulse animation keys on.
            change: worsened ? 'worse' : (improved ? 'better' : null),
            //: The attention lane's #1 scenario pings here (R-I ②).
            isAttentionTop: attentionTop !== null && sorted.some(function (m) {
                return m.scenarioId === attentionTop;
            }),
            observation: _observationOf(observation),
            country: country,
            flag: Tiles.flagOf(country),
            region: placement ? placement.region : null,
            col: placement ? placement.col : null,
            row: placement ? placement.row : null,
            placed: placement !== null,
            memberships: sorted,
            membershipCount: sorted.length,
            scenarioIds: sorted.map(function (m) { return m.scenarioId; }),
            dominant: dominant,
            band: band.band,
            cssVar: band.cssVar,
            //: the attacking side in ANY of its scenarios — see header.
            isAdversary: sorted.some(function (m) { return m.isAdversary; }),
            hasFocused: sorted.some(function (m) { return m.focused; }),
        };
    }

    function _extent(tiles, axis) {
        return tiles.reduce(function (most, tile) {
            return tile[axis] > most ? tile[axis] : most;
        }, 1);
    }

    /**
     * @param {object} input
     * @param {Array|null} input.scenarios  R1's `scenarios` rows, verbatim
     * @returns {object} the board map view model
     */
    function buildBoardMap(input) {
        input = input || {};
        var scenarios = Array.isArray(input.scenarios) ? input.scenarios : [];

        if (scenarios.length === 0) {
            return {
                empty: true,
                emptyState: F.emptyState('board_map',
                    input.scenarios
                        ? 'empty.board_map.reason_no_scenarios'
                        : 'empty.board_map.reason_not_loaded'),
                regions: [],
                spillover: { present: false, tiles: [] },
                countryCount: 0,
                scenarioCount: 0,
                observationOnly: [],
                observationsSupplied: false,
                observationWindowSec: null,
            };
        }

        var byCountry = {};
        scenarios.forEach(function (scenario) {
            if (!scenario || typeof scenario.scenario_id !== 'string') return;
            Object.keys(scenario.participants || {}).forEach(function (raw) {
                var country = String(raw).toUpperCase();
                if (!byCountry[country]) byCountry[country] = [];
                byCountry[country].push(_membership(scenario, country));
            });
        });

        // R16, keyed by country. `null` when the supply has not arrived —
        // a different fact from "arrived and empty" (G-17).
        var observations = input.observations || null;
        var obsByCountry = {};
        ((observations && observations.countries) || []).forEach(function (e) {
            if (e && typeof e.country === 'string') {
                obsByCountry[e.country.toUpperCase()] = e;
            }
        });

        var attentionTop = typeof input.attentionTopScenario === 'string'
            && input.attentionTopScenario
            ? input.attentionTopScenario : null;

        var placed = [];
        var spillover = [];
        Object.keys(byCountry).sort().forEach(function (country) {
            var tile = _tile(country, byCountry[country],
                             obsByCountry[country] || null, attentionTop);
            (tile.placed ? placed : spillover).push(tile);
        });

        // The observation reach beyond the rosters (NP9): countries only
        // the globally-sweeping adapters heard from. Small markers, no TL
        // — they are observation, not conclusion.
        var observationOnly = Object.keys(obsByCountry).sort()
            .filter(function (country) {
                return !Object.prototype.hasOwnProperty.call(byCountry,
                                                             country)
                    && country !== 'GLOBAL';
            })
            .map(function (country) {
                return {
                    country: country,
                    observation: _observationOf(obsByCountry[country]),
                };
            });

        var regions = Tiles.REGIONS.map(function (region) {
            var tiles = placed.filter(function (tile) {
                return tile.region === region.id;
            });
            return {
                id: region.id,
                labelKey: region.labelKey,
                tiles: tiles,
                columns: _extent(tiles, 'col'),
                rows: _extent(tiles, 'row'),
            };
            // Regions with no participant are dropped, same ruling as the
            // scenario-face map: an empty grey block reads as "quiet here"
            // and the tool has not looked there at all.
        }).filter(function (region) { return region.tiles.length > 0; });

        return {
            empty: false,
            emptyState: null,
            regions: regions,
            //: G-17 — a country the placement table does not know is a gap
            //: in a frontend asset, never a dropped country.
            spillover: {
                present: spillover.length > 0,
                labelKey: Tiles.UNPLACED_LABEL_KEY,
                noteKey: 'ui.geo.tilemap.unplaced_note',
                tiles: spillover,
            },
            countryCount: placed.length + spillover.length,
            scenarioCount: scenarios.length,
            observationOnly: observationOnly,
            //: `false` when R16 never arrived — the view says the supply
            //: is absent rather than drawing a world with no observations.
            observationsSupplied: observations !== null,
            observationWindowSec: observations
                && typeof observations.window_sec === 'number'
                ? observations.window_sec : null,
        };
    }

    /**
     * WP-4.9c (P8 §9 / NP9 (b)): the coverage line under the map — which
     * declared sensors are actually writing, and which are silent. R8
     * already refuses to omit a silent adapter (G-17); this fold carries
     * that honesty to Tier 0, where the observation numbers live. A
     * reader of the counts must be able to see, on the same surface,
     * that e.g. NOTAM contributes nothing to them right now.
     */
    function foldSensorCoverage(sensorsBody) {
        if (!sensorsBody || !Array.isArray(sensorsBody.sensors)) {
            return { supplied: false, total: 0, silentCount: 0,
                     silentNames: [] };
        }
        var silent = sensorsBody.sensors.filter(function (row) {
            return row && row.observation_count === 0;
        }).map(function (row) { return String(row.sensor); }).sort();
        return {
            supplied: true,
            total: sensorsBody.sensors.length,
            silentCount: silent.length,
            silentNames: silent,
        };
    }

    return {
        buildBoardMap: buildBoardMap,
        foldSensorCoverage: foldSensorCoverage,
    };
});
