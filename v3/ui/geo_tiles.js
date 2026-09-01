/**
 * Noroshi v3 L7 — the country-tile map (pure, DOM-free).
 *
 * P9 §3.4, answering diagnosis D-5: P8 §6 asks the geographic face "**where**
 * is the anomaly happening", and WP-4.2 answered it with a `<ul>` of country
 * codes. That is not a wrong answer, it is an unreadable one — a reader has
 * to hold thirty ISO codes in their head to see that four of the loud ones
 * are neighbours.
 *
 * The wire still carries no coordinates and this module does not add any.
 * `geo.js` explains at length why a latitude table in the browser would be a
 * second reader of deployment data that the backend could not watch drift,
 * and that ruling is unchanged: **there is no lat/lng in this file**. What
 * is here is a placement table — region, column, row — which is a FRONTEND
 * DESIGN ASSET in the same sense as the typographic scale or the role
 * colours. P9 §3.4 says so in terms: 「タイル配置は静的定数(フロント資産)で
 * 足りる」. Nothing downstream of a conclusion reads it, no server value is
 * reconstructed from it, and if a country moves one cell the only thing that
 * changes is where a reader's eye lands.
 *
 * Three properties the tests pin, each of which is a defect if lost:
 *
 *   * **Every participant has a cell.** The placement table covers the
 *     complete participant set of every scenario in `geo_data.json`. A
 *     participant with no cell would vanish from the primary visual while
 *     still being counted in the summary line.
 *   * **A country with no cell is never dropped** (G-17). Off-roster
 *     observations, `GLOBAL`, and any country a future scenario adds before
 *     this table learns about it, all land in the 配置未定義 spillover row.
 *     The map says "I do not know where to put this" rather than saying
 *     nothing.
 *   * **The tile carries what the marker carries.** Role class, adversary
 *     and chain flags, fired and suppressed counts, and one dot per domain
 *     that produced an event — all read from the marker `geo.js` already
 *     built. This module re-derives nothing; it places.
 *
 * The tile map is a visual duplicate: the marker list stays in the document
 * as the accessible representation and the grid is `aria-hidden`, so a
 * screen reader hears the facts once, in the order `geo.js` sorted them.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiGeoTiles = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * The regions, in P9 §3.4's order.
     *
     * 南アジア and アフリカ are named in §3.4 but absent here: no scenario in
     * this deployment has a participant in either, and a block with no
     * countries is a promise the map cannot keep. They arrive with the first
     * scenario that needs them.
     */
    var REGIONS = [
        { id: 'east_asia', labelKey: 'ui.geo.region.east_asia' },
        { id: 'southeast_asia', labelKey: 'ui.geo.region.southeast_asia' },
        { id: 'middle_east', labelKey: 'ui.geo.region.middle_east' },
        { id: 'europe', labelKey: 'ui.geo.region.europe' },
        { id: 'north_america', labelKey: 'ui.geo.region.north_america' },
        { id: 'oceania', labelKey: 'ui.geo.region.oceania' },
    ];

    var UNPLACED_LABEL_KEY = 'ui.geo.region.unplaced';

    /**
     * ISO2 → where the tile sits. Columns run west→east, rows north→south,
     * within a region block only: this is a schematic, not a projection, and
     * two regions' grids have nothing to do with each other.
     *
     * The set is every participant of every scenario in `geo_data.json`
     * (29 countries across five scenarios). `tests/ui_v3/test_geo_tiles.js`
     * carries that list independently and fails if the two disagree, so a
     * scenario gaining a participant is caught here rather than discovered
     * as a country missing from the map.
     */
    var PLACEMENTS = {
        // ── 東アジア ────────────────────────────────────────────────────
        CN: { region: 'east_asia', col: 1, row: 2 },
        KP: { region: 'east_asia', col: 2, row: 1 },
        KR: { region: 'east_asia', col: 2, row: 2 },
        TW: { region: 'east_asia', col: 2, row: 3 },
        JP: { region: 'east_asia', col: 3, row: 1 },

        // ── 東南アジア ──────────────────────────────────────────────────
        VN: { region: 'southeast_asia', col: 1, row: 1 },
        PH: { region: 'southeast_asia', col: 2, row: 1 },
        MY: { region: 'southeast_asia', col: 1, row: 2 },

        // ── 中東 ────────────────────────────────────────────────────────
        LB: { region: 'middle_east', col: 1, row: 1 },
        SY: { region: 'middle_east', col: 2, row: 1 },
        IQ: { region: 'middle_east', col: 3, row: 1 },
        IR: { region: 'middle_east', col: 4, row: 1 },
        IL: { region: 'middle_east', col: 1, row: 2 },
        SA: { region: 'middle_east', col: 3, row: 2 },
        YE: { region: 'middle_east', col: 3, row: 3 },

        // ── 欧州 ────────────────────────────────────────────────────────
        FI: { region: 'europe', col: 1, row: 1 },
        EE: { region: 'europe', col: 2, row: 1 },
        RU: { region: 'europe', col: 4, row: 1 },
        LV: { region: 'europe', col: 2, row: 2 },
        LT: { region: 'europe', col: 2, row: 3 },
        BY: { region: 'europe', col: 3, row: 3 },
        PL: { region: 'europe', col: 1, row: 4 },
        UA: { region: 'europe', col: 2, row: 4 },
        SK: { region: 'europe', col: 1, row: 5 },
        RO: { region: 'europe', col: 2, row: 5 },
        MD: { region: 'europe', col: 3, row: 5 },

        // ── 北米 ────────────────────────────────────────────────────────
        US: { region: 'north_america', col: 1, row: 1 },

        // ── オセアニア ──────────────────────────────────────────────────
        GU: { region: 'oceania', col: 1, row: 1 },
        AU: { region: 'oceania', col: 1, row: 2 },
    };

    //: Regional-indicator arithmetic: 'A' → U+1F1E6. The flag is decoration
    //: on top of the ISO2 the tile already prints, so a code point pair the
    //: platform cannot render costs nothing.
    var FLAG_BASE = 0x1F1E6;
    var LETTER_A = 65;

    function flagOf(iso2) {
        if (typeof iso2 !== 'string' || !/^[A-Z]{2}$/.test(iso2)) return '';
        return String.fromCodePoint(
            FLAG_BASE + (iso2.charCodeAt(0) - LETTER_A),
            FLAG_BASE + (iso2.charCodeAt(1) - LETTER_A));
    }

    function placementOf(iso2) {
        return Object.prototype.hasOwnProperty.call(PLACEMENTS, iso2)
            ? PLACEMENTS[iso2] : null;
    }

    /**
     * One dot per domain that produced an event, fired and suppressed kept
     * apart.
     *
     * E-17 again, at tile granularity: a suppressed row is not a quiet one,
     * so it gets its own dot kind rather than being counted with the fired
     * ones or dropped for not having fired. Domains are sorted so two
     * renders of the same marker produce the same tile (AP2).
     */
    function _dots(marker) {
        var kinds = { fired: {}, suppressed: {} };
        (marker.fired || []).forEach(function (row) {
            if (row && row.domain) kinds.fired[row.domain] = true;
        });
        (marker.suppressed || []).forEach(function (row) {
            if (row && row.domain) kinds.suppressed[row.domain] = true;
        });
        var out = [];
        Object.keys(kinds.fired).sort().forEach(function (domain) {
            out.push({ domain: domain, kind: 'fired' });
        });
        Object.keys(kinds.suppressed).sort().forEach(function (domain) {
            if (kinds.fired[domain] === true) return;   // one dot per domain
            out.push({ domain: domain, kind: 'suppressed' });
        });
        return out;
    }

    function _tile(marker, placement) {
        return {
            country: marker.country,
            flag: flagOf(marker.country),
            region: placement ? placement.region : null,
            col: placement ? placement.col : null,
            row: placement ? placement.row : null,
            placed: placement !== null,
            roleClass: marker.roleClass,
            role: marker.role || null,
            roleKey: marker.role
                ? 'ui.geo.role.' + marker.role : 'ui.geo.role.unlisted',
            roleKnown: marker.roleKnown === true,
            isAdversary: marker.isAdversary === true,
            isChainCountry: marker.isChainCountry === true,
            firedCount: marker.firedCount,
            suppressedCount: marker.suppressedCount,
            observations: marker.observations,
            //: The marker's own G-17 state word, carried across unchanged —
            //: the tile must not invent a fourth state by looking at counts.
            stateKey: marker.stateKey,
            hasEvents: marker.firedCount > 0 || marker.suppressedCount > 0,
            dots: _dots(marker),
        };
    }

    function _extent(tiles, axis) {
        return tiles.reduce(function (most, tile) {
            return tile[axis] > most ? tile[axis] : most;
        }, 1);
    }

    /**
     * Build the tile map from the markers `geo.js` produced.
     *
     * @param {object} input
     * @param {Array} input.markers    participant markers, already sorted
     * @param {Array} [input.offRoster] observed countries the scenario does
     *                                  not list, `GLOBAL` among them
     * @returns {object}
     */
    function buildTileMap(input) {
        input = input || {};
        var markers = Array.isArray(input.markers) ? input.markers : [];
        var offRoster = Array.isArray(input.offRoster) ? input.offRoster : [];
        var all = markers.concat(offRoster);

        var placed = [];
        var spillover = [];
        all.forEach(function (marker) {
            if (!marker || typeof marker.country !== 'string') return;
            var placement = placementOf(marker.country);
            var tile = _tile(marker, placement);
            (placement ? placed : spillover).push(tile);
        });

        var regions = REGIONS.map(function (region) {
            var tiles = placed.filter(function (tile) {
                return tile.region === region.id;
            });
            return {
                id: region.id,
                labelKey: region.labelKey,
                tiles: tiles,
                columns: _extent(tiles, 'col'),
                rows: _extent(tiles, 'row'),
                firedTotal: tiles.reduce(function (sum, tile) {
                    return sum + tile.firedCount;
                }, 0),
            };
            // Regions with no participant are dropped below rather than
            // rendered empty: a block of grey cells reads as "quiet here",
            // and the tool has not looked there at all.
        }).filter(function (region) { return region.tiles.length > 0; });

        return {
            regions: regions,
            //: Never dropped (G-17). A country the placement table does not
            //: know is a gap in a frontend asset, not an absence of signal.
            spillover: {
                present: spillover.length > 0,
                labelKey: UNPLACED_LABEL_KEY,
                noteKey: 'ui.geo.tilemap.unplaced_note',
                tiles: spillover,
            },
            placedCount: placed.length,
            spilloverCount: spillover.length,
            countryCount: placed.length + spillover.length,
            empty: placed.length === 0 && spillover.length === 0,
        };
    }

    return {
        buildTileMap: buildTileMap,
        placementOf: placementOf,
        flagOf: flagOf,
        REGIONS: REGIONS,
        PLACEMENTS: PLACEMENTS,
        UNPLACED_LABEL_KEY: UNPLACED_LABEL_KEY,
    };
});
