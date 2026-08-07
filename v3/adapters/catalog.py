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


def expected_adapter_ids() -> tuple[str, ...]:
    """Design-sheet identifiers with the mandated renames applied."""
    return tuple(DESIGN_SHEET_RENAMES.get(name, name)
                 for _, name in WP26_DESIGN_SHEET_ROWS)


def build_registry(adapters=WP26_ADAPTERS) -> AdapterRegistry:
    """The registry a composition root receives.

    Going through `AdapterRegistry` rather than exposing a list is what
    makes an identifier resolvable — `resolve()` refuses a name it does
    not know, which is the referential integrity F-02 lacked when
    `_FORCE_SYNC_SENSORS` named two sensors that did not exist.
    """
    return AdapterRegistry(adapters)


__all__ = ["WP26_ADAPTERS", "WP26_DESIGN_SHEET_ROWS", "DESIGN_SHEET_RENAMES",
           "expected_adapter_ids", "build_registry"]
