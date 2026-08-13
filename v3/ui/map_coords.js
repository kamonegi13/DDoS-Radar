/**
 * Noroshi v3 L7 — country centroids for the real map (display asset).
 *
 * P9 §1.3 (D-13): the region-block tile grid carried no geographic
 * intuition — no adjacency, no distance, no shape — and the owner review
 * said so in terms: "show an actual map and colour it". v1's answer was
 * Leaflet over CARTO's dark tiles with a circle per country
 * (`radar.js:1732-1741`), and that is the look this file brings back.
 *
 * On the two coordinate rulings:
 *
 *   * "**No coordinate on the wire**" is UNCHANGED. The server still
 *     serves participants, roles and threat levels — never a lat/lng.
 *   * "**No lat/lng in the browser**" (geo.js's ruling) is AMENDED by
 *     P9 §1.3. geo.js's fear was a second reader of deployment data that
 *     nobody watches drift on. The answer is to put the watch in CI:
 *     `tests/ui_v3/test_map_coords.js` compares this table against
 *     `geo_data.json`'s COUNTRY_COORDS and fails the build on any
 *     divergence. A country's centroid is not deployment data anyway —
 *     it is a display constant of the same class as the tile placement
 *     table, and nothing downstream of a conclusion reads it.
 *
 * The set covers every participant of every scenario in this deployment
 * (the same 29 countries `geo_tiles.js` places). A country missing here
 * is not dropped from the map path — `board_map_view.js` counts it as
 * unplaceable and says so, G-17's shape.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiMapCoords = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    //: ISO2 → [lat, lng]. Values are geo_data.json's COUNTRY_COORDS,
    //: copied once and pinned by test_map_coords.js — edit THERE first.
    var COORDS = {
        AU: [-25.2744, 133.7751],
        BY: [53.7098, 27.9534],
        CN: [35.8617, 104.1954],
        EE: [58.5953, 25.0136],
        FI: [61.9241, 25.7482],
        GU: [13.4443, 144.7937],
        IL: [31.0461, 34.8516],
        IQ: [33.2232, 43.6793],
        IR: [32.4279, 53.688],
        JP: [36.2048, 138.2529],
        KP: [40.3399, 127.5101],
        KR: [35.9078, 127.7669],
        LB: [33.8547, 35.8623],
        LT: [55.1694, 23.8813],
        LV: [56.8796, 24.6032],
        MD: [47.4116, 28.3699],
        MY: [4.2105, 101.9758],
        PH: [12.8797, 121.774],
        PL: [51.9194, 19.1451],
        RO: [45.9432, 24.9668],
        RU: [61.524, 105.3188],
        SA: [23.8859, 45.0792],
        SK: [48.669, 19.699],
        SY: [34.8021, 38.9968],
        TW: [23.6978, 120.9605],
        UA: [48.3794, 31.1656],
        US: [37.0902, -95.7129],
        VN: [14.0583, 108.2772],
        YE: [15.5527, 48.5164],
    };

    function coordsOf(iso2) {
        return Object.prototype.hasOwnProperty.call(COORDS, iso2)
            ? COORDS[iso2] : null;
    }

    return {
        COORDS: COORDS,
        coordsOf: coordsOf,
    };
});
