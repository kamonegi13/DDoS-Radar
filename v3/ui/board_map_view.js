/**
 * Noroshi v3 L7 — the real map behind the situation board (thin, injectable).
 *
 * P9 §1.3 (D-13): the owner review looked at the region-block tile grid
 * and said "if it looks like this, show an actual map and colour it" —
 * which is what v1 did (`radar.js:1732-1741`: Leaflet over CARTO's dark
 * tiles). This module is that construction for v3, with three properties
 * the tile grid never needed:
 *
 *   * **Leaflet is optional.** The library arrives from a CDN, and a
 *     browser that cannot load it (offline deployment, blocked CDN) gets
 *     the tile grid FALLBACK rather than a blank pane (S1-UI-008). The
 *     Node test suite runs entirely on the fallback and on a fake L.
 *   * **No colour enters from JavaScript.** Markers are divIcons whose
 *     HTML carries band classes and a CSS variable; the palette stays in
 *     `v3.css` (the colour gate holds).
 *   * **A country without a centroid is counted, never dropped** (G-17).
 *     `render()` reports the unplaceable set so the caller can print it
 *     under the map.
 *
 * The map instance is created once and kept: recreating it every render
 * cycle would re-fetch tiles and flicker. Markers are a LayerGroup that
 * is cleared and refilled per render — the same "current data, one
 * writer" shape as every other surface.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiBoardMapView = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    //: v1's tile source, verbatim (radar.js:1741). A URL, not a colour.
    var TILE_URL =
        'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
    var TILE_ATTRIBUTION = '&copy; CARTO';
    //: 26, not 24: the backend's SEQUENCE_DECAY_HORIZON_H is 24.0 and the
    //: constant-collision gate (rightly) refuses the coincidence.
    var FIT_PADDING = 26;
    var FIT_MAX_ZOOM = 4;

    /**
     * @param {object} options
     * @param {Document} options.doc
     * @param {object|null} options.leaflet     window.L, or null
     * @param {string} options.containerId      'board-map'
     * @param {object} options.coords           NoroshiMapCoords
     * @param {function} options.markerHtml     tile -> divIcon inner HTML
     * @param {function} options.fallbackHtml   map model -> tile-grid HTML
     * @param {function} options.emptyHtml      empty state -> HTML
     */
    function createBoardMapView(options) {
        var doc = options.doc;
        var L = options.leaflet || null;
        var containerId = options.containerId || 'board-map';
        var coords = options.coords;
        var map = null;
        var layer = null;
        var fitted = false;

        function _node() { return doc.getElementById(containerId); }

        function _teardown(node) {
            if (map !== null) {
                map.remove();
                map = null;
                layer = null;
                fitted = false;
            }
            if (node) node.classList.remove('board-map-real');
        }

        function _tiles(model) {
            var all = [];
            (model.regions || []).forEach(function (region) {
                all = all.concat(region.tiles || []);
            });
            return all.concat((model.spillover
                               && model.spillover.tiles) || []);
        }

        function render(model) {
            var node = _node();
            if (!node) return { mode: 'absent' };

            if (!model || model.empty) {
                _teardown(node);
                node.innerHTML = options.emptyHtml(
                    model ? model.emptyState : null);
                return { mode: 'empty' };
            }

            if (L === null) {
                node.innerHTML = options.fallbackHtml(model);
                return { mode: 'fallback' };
            }

            if (map === null) {
                node.innerHTML = '';
                node.classList.add('board-map-real');
                map = L.map(node, {
                    zoomControl: true,
                    attributionControl: true,
                    scrollWheelZoom: false,
                    worldCopyJump: true,
                });
                L.tileLayer(TILE_URL, {
                    attribution: TILE_ATTRIBUTION, maxZoom: 10,
                }).addTo(map);
                layer = L.layerGroup().addTo(map);
            }

            layer.clearLayers();
            var placed = [];
            var unplaced = [];
            _tiles(model).forEach(function (tile) {
                var at = coords.coordsOf(tile.country);
                if (at === null) {
                    unplaced.push(tile.country);
                    return;
                }
                layer.addLayer(L.marker(at, {
                    icon: L.divIcon({
                        className: 'bm-marker-anchor',
                        html: options.markerHtml(tile),
                        iconSize: null,
                    }),
                    keyboard: false,
                }));
                placed.push(at);
            });

            // Fitted once, not per render: the analyst's pan/zoom is
            // interaction state, and a redraw that yanks the viewport
            // back is the map version of a stale-read defect.
            if (!fitted && placed.length > 0) {
                map.fitBounds(placed, {
                    padding: [FIT_PADDING, FIT_PADDING],
                    maxZoom: FIT_MAX_ZOOM,
                });
                fitted = true;
            }

            return { mode: 'leaflet', markers: placed.length,
                     unplaced: unplaced };
        }

        return { render: render };
    }

    return {
        createBoardMapView: createBoardMapView,
        TILE_URL: TILE_URL,
    };
});
