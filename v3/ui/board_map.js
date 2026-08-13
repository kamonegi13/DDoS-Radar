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

    function _tile(country, memberships) {
        var sorted = memberships.slice().sort(_byDominance);
        var dominant = sorted[0] && sorted[0].severity !== null
            ? sorted[0] : null;
        var placement = Tiles.placementOf(country);
        var band = dominant ? dominant.tl : F.tlBand(null);
        return {
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

        var placed = [];
        var spillover = [];
        Object.keys(byCountry).sort().forEach(function (country) {
            var tile = _tile(country, byCountry[country]);
            (tile.placed ? placed : spillover).push(tile);
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
        };
    }

    return {
        buildBoardMap: buildBoardMap,
    };
});
