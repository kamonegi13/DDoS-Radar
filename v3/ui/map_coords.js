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
 * The set covers every country geo_data.json knows (147 as of
 * 2026-08-14) — since R16 the map draws the OBSERVATION reach, which is
 * far wider than the scenario rosters. A country missing here
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
        AD: [42.5462, 1.6015],
        AE: [23.4241, 53.8478],
        AF: [33.9391, 67.71],
        AL: [41.1533, 20.1683],
        AM: [40.0691, 45.0382],
        AO: [-11.2027, 17.8739],
        AR: [-38.4161, -63.6167],
        AT: [47.5162, 14.5501],
        AU: [-25.2744, 133.7751],
        AZ: [40.1431, 47.5769],
        BA: [43.9159, 17.6791],
        BD: [23.685, 90.3563],
        BE: [50.5039, 4.4699],
        BG: [42.7339, 25.4858],
        BH: [25.9304, 50.6378],
        BN: [4.5353, 114.7277],
        BO: [-16.2902, -63.5887],
        BR: [-14.235, -51.9253],
        BT: [27.5142, 90.4336],
        BY: [53.7098, 27.9534],
        CA: [56.1304, -106.3468],
        CD: [-4.0383, 21.7587],
        CH: [46.8182, 8.2275],
        CI: [7.54, -5.5471],
        CL: [-35.6751, -71.543],
        CM: [3.848, 11.5021],
        CN: [35.8617, 104.1954],
        CO: [4.5709, -74.2973],
        CR: [9.7489, -83.7534],
        CU: [21.5218, -77.7812],
        CY: [35.1264, 33.4299],
        CZ: [49.8153, 15.473],
        DE: [51.1657, 10.4515],
        DK: [56.2639, 9.5018],
        DO: [18.7357, -70.1627],
        DZ: [28.0339, 1.6596],
        EC: [-1.8312, -78.1834],
        EE: [58.5953, 25.0136],
        EG: [26.8206, 30.8025],
        ES: [40.4637, -3.7492],
        ET: [9.145, 40.4897],
        FI: [61.9241, 25.7482],
        FJ: [-17.7134, 178.065],
        FR: [46.2276, 2.2137],
        GB: [55.3781, -3.436],
        GE: [42.3154, 43.3569],
        GH: [7.9465, -1.0232],
        GR: [39.0742, 21.8243],
        GT: [15.7835, -90.2308],
        GU: [13.4443, 144.7937],
        GY: [4.8604, -58.9302],
        HK: [22.3193, 114.1694],
        HN: [15.2, -86.2419],
        HR: [45.1, 15.2],
        HU: [47.1625, 19.5033],
        ID: [-0.7893, 113.9213],
        IE: [53.1424, -7.6921],
        IL: [31.0461, 34.8516],
        IN: [20.5937, 78.9629],
        IQ: [33.2232, 43.6793],
        IR: [32.4279, 53.688],
        IS: [64.9631, -19.0208],
        IT: [41.8719, 12.5674],
        JM: [18.1096, -77.2975],
        JO: [30.5852, 36.2384],
        JP: [36.2048, 138.2529],
        KE: [-0.0236, 37.9062],
        KG: [41.2044, 74.7661],
        KH: [12.5657, 104.991],
        KP: [40.3399, 127.5101],
        KR: [35.9078, 127.7669],
        KW: [29.3117, 47.4818],
        KZ: [48.0196, 66.9237],
        LA: [19.8563, 102.4955],
        LB: [33.8547, 35.8623],
        LK: [7.8731, 80.7718],
        LT: [55.1694, 23.8813],
        LU: [49.8153, 6.1296],
        LV: [56.8796, 24.6032],
        LY: [26.3351, 17.2283],
        MA: [31.7917, -7.0926],
        MD: [47.4116, 28.3699],
        ME: [42.7087, 19.3744],
        MG: [-18.7669, 46.8691],
        MK: [41.6086, 21.7453],
        ML: [17.5707, -3.9962],
        MM: [21.9162, 95.956],
        MN: [46.8625, 103.8467],
        MO: [22.1987, 113.5439],
        MT: [35.9375, 14.3754],
        MU: [-20.3484, 57.5522],
        MV: [3.2028, 73.2207],
        MX: [23.6345, -102.5528],
        MY: [4.2105, 101.9758],
        MZ: [-18.6657, 35.5296],
        NE: [17.6078, 8.0817],
        NG: [9.082, 8.6753],
        NI: [12.8654, -85.2072],
        NL: [52.1326, 5.2913],
        NO: [60.472, 8.4689],
        NP: [28.3949, 84.124],
        NZ: [-40.9006, 174.886],
        OM: [21.4735, 55.9754],
        PA: [8.538, -80.7821],
        PE: [-9.19, -75.0152],
        PG: [-6.315, 143.9555],
        PH: [12.8797, 121.774],
        PK: [30.3753, 69.3451],
        PL: [51.9194, 19.1451],
        PR: [18.2208, -66.5901],
        PT: [39.3999, -8.2245],
        PY: [-23.4425, -58.4438],
        QA: [25.3548, 51.1839],
        RO: [45.9432, 24.9668],
        RS: [44.0165, 21.0059],
        RU: [61.524, 105.3188],
        RW: [-1.9403, 29.8739],
        SA: [23.8859, 45.0792],
        SD: [12.8628, 30.2176],
        SE: [60.1282, 18.6435],
        SG: [1.3521, 103.8198],
        SI: [46.1512, 14.9955],
        SK: [48.669, 19.699],
        SN: [14.4974, -14.4524],
        SR: [3.9193, -56.0278],
        SV: [13.7942, -88.8965],
        SY: [34.8021, 38.9968],
        TH: [15.87, 100.9925],
        TJ: [38.861, 71.2761],
        TL: [-8.8742, 125.7275],
        TM: [38.9697, 59.5563],
        TN: [33.8869, 9.5375],
        TR: [38.9637, 35.2433],
        TW: [23.6978, 120.9605],
        TZ: [-6.369, 34.8888],
        UA: [48.3794, 31.1656],
        UG: [1.3733, 32.2903],
        US: [37.0902, -95.7129],
        UY: [-32.5228, -55.7658],
        UZ: [41.3775, 64.5853],
        VE: [6.4238, -66.5897],
        VN: [14.0583, 108.2772],
        XK: [42.6026, 20.903],
        YE: [15.5527, 48.5164],
        ZA: [-30.5595, 22.9375],
        ZM: [-13.1339, 27.8493],
        ZW: [-19.0154, 29.1549],
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
