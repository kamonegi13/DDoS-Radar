"""The WP-2.6 roster, transcribed from the design sheet and checked.

Design sheet §3-2 lists 22 adapters: cyber 7 + physical 15. This module
holds that list twice — once as the DECLARED roster (what the design
sheet says) and once as the BUILT registry (what this package actually
exports) — and the suite compares them. A port that goes missing, an
identifier that drifts, or an adapter added without a design-sheet row
therefore fails a test rather than disappearing.

That is the shape the ETL's `S3_MIGRATE_35` registry and L2's clause
registry already use, and it exists for a measured reason: `scenarios`
went missing from the migration plan precisely because nothing compared
the plan with the spec.

One identifier differs from its design-sheet row on purpose. The row
reads `nasa_firms`; the disposition in the same row is "rename to
`nasa_eonet`" (DP6/NP6 — the sensor never fetched FIRMS). The rename is
data here, not a special case in the comparison, so the reason travels
with it.
"""
from __future__ import annotations

from v3.adapters.cyber.apt_intel import APT_INTEL_ADAPTER
from v3.adapters.cyber.cloudflare_radar import CLOUDFLARE_RADAR_ADAPTER
from v3.adapters.cyber.ct_log import CT_LOG_ADAPTER
from v3.adapters.cyber.greynoise import GREYNOISE_ADAPTER
from v3.adapters.cyber.ooni_censorship import OONI_CENSORSHIP_ADAPTER
from v3.adapters.cyber.ripe_bgp import RIPE_BGP_ADAPTER
from v3.adapters.cyber.threatfox import THREATFOX_ADAPTER
from v3.adapters.info.bg_observer_rss import BG_OBSERVER_RSS_ADAPTER
from v3.adapters.info.gdelt import GDELT_ADAPTER
from v3.adapters.info.rss_narrative import RSS_NARRATIVE_ADAPTER
from v3.adapters.info.telegram_mirror import TELEGRAM_MIRROR_ADAPTER
from v3.adapters.info.tor_metrics import TOR_METRICS_ADAPTER
from v3.adapters.info.travel_advisory import TRAVEL_ADVISORY_ADAPTER
from v3.adapters.llm.diplomatic import DIPLOMATIC_ADAPTER
from v3.adapters.llm.hacktivist_news import HACKTIVIST_NEWS_ADAPTER
from v3.adapters.llm.military_exercise import MILITARY_EXERCISE_ADAPTER
from v3.adapters.physical.ais_maritime import AIS_MARITIME_ADAPTER
from v3.adapters.physical.check_host import CHECK_HOST_ADAPTER
from v3.adapters.physical.gps_jamming import GPS_JAMMING_ADAPTER
from v3.adapters.physical.ihr_health import IHR_HEALTH_ADAPTER
from v3.adapters.physical.ioda_bgp import IODA_BGP_ADAPTER
from v3.adapters.physical.nasa_eonet import (LEGACY_ADAPTER_ID
                                             as NASA_LEGACY_ID,
                                             NASA_EONET, NASA_EONET_ADAPTER)
from v3.adapters.physical.notam import NOTAM_ADAPTER
from v3.adapters.physical.openweather import OPENWEATHER_ADAPTER
from v3.adapters.physical.opensky import (ISR_HOTSPOT_ADAPTER,
                                          MIL_SUPPORT_AIR_ADAPTER,
                                          OPENSKY_ADAPTER)
from v3.adapters.physical.peeringdb_ixp import PEERINGDB_IXP_ADAPTER
from v3.adapters.physical.ripe_atlas import RIPE_ATLAS_ADAPTER
from v3.adapters.physical.space_weather import SPACE_WEATHER_ADAPTER
from v3.adapters.physical.usgs_seismic import USGS_SEISMIC_ADAPTER
from v3.adapters.types import SourceAdapter
from v3.fetch.registry import AdapterRegistry

#: The design sheet §3-2 table, in its order. `(row, id_in_the_table)`.
WP26_DESIGN_SHEET_ROWS: tuple[tuple[int, str], ...] = (
    (1, "cloudflare_radar"), (2, "ripe_bgp"), (3, "greynoise"),
    (4, "ooni_censorship"), (5, "threatfox"), (6, "ct_log"),
    (7, "apt_intel"),
    (8, "opensky"), (9, "isr_hotspot"), (10, "mil_support_air"),
    (11, "ais_maritime"), (12, "gps_jamming"), (13, "notam"),
    (14, "nasa_firms"), (15, "openweather"), (16, "usgs_seismic"),
    (17, "space_weather"), (18, "peeringdb_ixp"), (19, "ihr_health"),
    (20, "ioda_bgp"), (21, "check_host"), (22, "ripe_atlas"),
)

#: Renames the design sheet itself mandates. `table id -> shipped id`.
#:
#: Both sides are read from the adapter that owns them rather than spelled
#: again here. §3-2 row 14 and §7-2 expected difference #5: DP6/C-07 — the
#: sensor fetched NASA EONET while calling itself FIRMS, so an analyst
#: following the identifier to its source found nothing that produced the
#: conclusion, an NP6 failure in the field NP6 exists to protect. A second
#: copy of the pair would be a second place for it to rot.
DESIGN_SHEET_RENAMES: dict = {
    NASA_LEGACY_ID: NASA_EONET.value,
}

#: The 22, in design-sheet order.
WP26_ADAPTERS: tuple[SourceAdapter, ...] = (
    CLOUDFLARE_RADAR_ADAPTER, RIPE_BGP_ADAPTER, GREYNOISE_ADAPTER,
    OONI_CENSORSHIP_ADAPTER, THREATFOX_ADAPTER, CT_LOG_ADAPTER,
    APT_INTEL_ADAPTER,
    OPENSKY_ADAPTER, ISR_HOTSPOT_ADAPTER, MIL_SUPPORT_AIR_ADAPTER,
    AIS_MARITIME_ADAPTER, GPS_JAMMING_ADAPTER, NOTAM_ADAPTER,
    NASA_EONET_ADAPTER, OPENWEATHER_ADAPTER, USGS_SEISMIC_ADAPTER,
    SPACE_WEATHER_ADAPTER, PEERINGDB_IXP_ADAPTER, IHR_HEALTH_ADAPTER,
    IODA_BGP_ADAPTER, CHECK_HOST_ADAPTER, RIPE_ATLAS_ADAPTER,
)


# ── WP-2.7: §3-3's twelve ────────────────────────────────────────────────

#: The design sheet §3-3 table, in its order. `(row, id_in_the_table)`.
WP27_DESIGN_SHEET_ROWS: tuple[tuple[int, str], ...] = (
    (23, "gdelt"), (24, "rss_narrative"), (25, "telegram_mirror"),
    (26, "tor_metrics"), (27, "travel_advisory"), (28, "bg_observer_rss"),
    (29, "diplomatic"), (30, "military_exercise"), (31, "hacktivist_intel"),
    (32, "hacktivist_news"), (33, "ground_osint"), (34, "convergence_tracker"),
)

#: §4-3 / §3-3 row 34. Not an omission — a ruling, with its reason next to
#: it. `convergence_tracker` was a second scoring pipeline: a private
#: SQLite (A-09), a cross-layer read of scoring-owned data (DP10), and
#: `domain="mixed"`, a fourth value outside the three-domain vocabulary
#: (A5). Its question — "are several sources seeing one event?" — is
#: answered by `v3.matching.corroborate` and returned as metadata that
#: carries no score, because O-17 keeps the convergence arithmetic in the
#: S5 formula alone.
NOT_PORTED: dict = {
    "convergence_tracker":
        "design sheet §4-3: not ported as an adapter. Its verdict becomes "
        "independence metadata (v3.matching.corroborate); its three defects "
        "(A-09 private store, DP10 cross-layer read, A5 domain='mixed') "
        "have no destination in v3.",
}

#: §3-5 H-3 / **裁定要求 9, ruled 2026-08-08**: two rows leave this batch.
#:
#: Both have no HTTP at all — their input is ANOTHER adapter's OUTPUT, and
#: the declaration model has no vocabulary for that. `SourceAdapter.requests`
#: holds `RequestSpec | RequestChain | RequestContinuation`, and `normalize`
#: sees exactly one already-fetched payload (§2-2 barrier 1). Building them
#: anyway costs one of the barriers: either a cache handle is passed into
#: `normalize` (barrier 1 gone) or the adapter reads for itself (barriers
#: 2/4 gone). §2-4 is the record of what happens when a model is made to
#: look as though it can express something it cannot — eight adapters that
#: could not issue their own production request, and nobody noticing because
#: nothing had called them yet.
#:
#: DEFERRED is not PENDING. Pending means this batch still owes the work;
#: deferred means this batch cannot express it and names the one that can.
DEFERRED_WP41: dict = {
    "hacktivist_intel":
        "design sheet §3-5 H-3 / 裁定要求 9 (ruled 2026-08-08): no HTTP. "
        "Its input is `telegram_mirror`'s class-variable intercept log, "
        "i.e. another adapter's output, which the declaration model cannot "
        "state. Landing WP-4.1 (composition root), by the SAME wiring as "
        "§7-2 #11 (reduction) and #35 (suppression) — all three need "
        "another adapter's output, and solving them separately would build "
        "three mechanisms for one gap (A-02 reproduced deliberately). The "
        "shared extraction machinery is already here: it needs one "
        "`IntelProfile` once the input is wired.",
    "ground_osint":
        "design sheet §3-5 H-3 / 裁定要求 9 (ruled 2026-08-08): no HTTP. "
        "Reads the telegram intercept log AND the live caches of "
        "`cloudflare_radar` and `check_host` "
        "(`radar/sensors/ground_osint_sensor.py:67-82`, ast-verified) — "
        "another adapter's output again. Landing WP-4.1, by the same "
        "wiring as §7-2 #11 (reduction) and #35 (suppression). Whoever "
        "builds that wiring MUST route the reads through "
        "`Evidence.fresh()`: production checks neither freshness nor "
        "health (a bare `try/except Exception: pass`), which is DP2/B-03 "
        "itself, and copying the wiring would copy the defect.",
}

#: Built so far in the WP-2.7 batch, in design-sheet order. The shared
#: machinery landed first (`v3/fetch/llm.py`, `v3/adapters/llm/extraction
#: .py`, `v3/matching/corroboration.py`) and these sit on it.
WP27_ADAPTERS: tuple[SourceAdapter, ...] = (
    GDELT_ADAPTER, RSS_NARRATIVE_ADAPTER, TELEGRAM_MIRROR_ADAPTER,
    TOR_METRICS_ADAPTER, TRAVEL_ADVISORY_ADAPTER,
    BG_OBSERVER_RSS_ADAPTER,
    DIPLOMATIC_ADAPTER, MILITARY_EXERCISE_ADAPTER,
    HACKTIVIST_NEWS_ADAPTER,
)

#: The rows §3-3 declares that this package does not yet export. This
#: exists so the gap is a FAILING LIST rather than an absence: the suite
#: recomputes it from the design sheet and the built roster, so adding an
#: adapter without removing its row here fails, and so does leaving a row
#: here after its adapter ships.
PENDING_WP27: tuple[str, ...] = ()


def declared_adapter_ids() -> tuple[str, ...]:
    """All 34 design-sheet identifiers, renames applied, sheet order."""
    return tuple(DESIGN_SHEET_RENAMES.get(name, name)
                 for _, name in WP26_DESIGN_SHEET_ROWS + WP27_DESIGN_SHEET_ROWS)


def buildable_adapter_ids() -> tuple[str, ...]:
    """The 34 minus the ones ruled not-ported. What may exist as code.

    A deferred adapter is still buildable — WP-4.1 will build it. What it
    is not is *expected here*, which is a different question and a
    different function.
    """
    return tuple(name for name in declared_adapter_ids()
                 if name not in NOT_PORTED)


def expected_adapter_ids() -> tuple[str, ...]:
    """What the built registry must contain, right now.

    Buildable minus still-pending minus deferred. Deriving it rather than
    listing it is what makes `PENDING_WP27` and `DEFERRED_WP41`
    load-bearing: shipping an adapter without striking its row leaves the
    roster short and the suite red, and so does striking a row without
    shipping.
    """
    return tuple(name for name in buildable_adapter_ids()
                 if name not in PENDING_WP27 and name not in DEFERRED_WP41)


ALL_ADAPTERS: tuple[SourceAdapter, ...] = WP26_ADAPTERS + WP27_ADAPTERS


def build_registry(adapters=ALL_ADAPTERS) -> AdapterRegistry:
    """The registry a composition root receives.

    Going through `AdapterRegistry` rather than exposing a list is what
    makes an identifier resolvable — `resolve()` refuses a name it does
    not know, which is the referential integrity F-02 lacked when
    `_FORCE_SYNC_SENSORS` named two sensors that did not exist.
    """
    return AdapterRegistry(adapters)


__all__ = ["WP26_ADAPTERS", "WP26_DESIGN_SHEET_ROWS",
           "WP27_ADAPTERS", "WP27_DESIGN_SHEET_ROWS",
           "ALL_ADAPTERS", "DESIGN_SHEET_RENAMES", "NOT_PORTED",
           "PENDING_WP27", "DEFERRED_WP41", "declared_adapter_ids",
           "buildable_adapter_ids", "expected_adapter_ids", "build_registry"]
