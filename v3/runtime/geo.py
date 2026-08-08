"""Deployment geography, loaded here so nothing under `v3/` has to read it.

`NormalizeContext` takes coordinates, chokepoints, tactical keywords and
geo terms as arguments rather than reading `geo_data.json` itself, and
`ExpansionInput` takes concrete placeholder values rather than looking
zones up. Both choices push the same job here: `geo_data.json` is
deployment data that changes without a code release, so a copy inside a
pure module would be a second ledger to keep in step (A-02's shape), and a
pure function that reads a file is not a pure function.

This module is where the file is opened, once, by an explicit call.
Loading is NOT done at import — a module-level `json.load` would make
every test process depend on a data file it never asked for, and would
put a filesystem read inside the import graph the boundary suites exist to
keep empty.

The ledger's own vocabulary is stale in one place and is READ, not
rewritten: `ISR_HOTSPOTS` tags each zone with `theater`, a term the
project retired in favour of `country`. Renaming it in the file is a
migration; renaming it here is a translation, and the translation is
`_zone_country`.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional, Sequence

from v3.kernel.errors import DomainError

#: The repository's deployment data. Passed explicitly by the composition
#: root in production; this default exists so tests and tools do not each
#: hardcode the same relative path.
DEFAULT_PATH = pathlib.Path(__file__).resolve().parents[2] / "geo_data.json"

#: `geo_data.json`'s field name for what the project calls a country.
LEGACY_COUNTRY_FIELD = "theater"


@dataclass(frozen=True, slots=True)
class Zone:
    """One named ISR hotspot. 30 of them over 21 countries.

    `name` is load-bearing, not decoration: `core.py:2929-2931` joins the
    ledger's zone list to the observation's `hotspots[]` ON THE NAME to
    populate the map overlay's tracks. A zone that reaches the wire
    without its name reaches the overlay as an empty track list.
    """

    name: str
    country: str
    lat: float
    lng: float
    radius_km: float = 200.0

    @property
    def scope_key(self) -> str:
        """`TW/Taiwan Strait Median Line` — unique, and readable in a plan."""
        return f"{self.country}/{self.name}"


@dataclass(frozen=True, slots=True)
class Geography:
    """Everything the composition root supplies downstream, as one value."""

    zones: tuple[Zone, ...] = ()
    chokepoints: tuple[tuple, ...] = ()
    country_coordinates: Mapping[str, tuple] = MappingProxyType({})
    country_names: Mapping[str, str] = MappingProxyType({})
    tactical_keywords: Mapping[str, tuple] = MappingProxyType({})
    geo_terms: Mapping[str, tuple] = MappingProxyType({})
    airport_boxes: Mapping[str, Mapping] = MappingProxyType({})
    scenarios: Mapping[str, Mapping] = MappingProxyType({})
    #: ISO2 -> the state URLs `check_host` probes for reachability.
    infrastructure_urls: Mapping[str, tuple] = MappingProxyType({})
    #: ISO2 -> the domains `ct_log` watches for anomalous CA issuance.
    watched_domains: Mapping[str, tuple] = MappingProxyType({})
    #: channel -> {bloc, lang, confidence_weight} for `telegram_mirror`.
    telegram_channels: Mapping[str, Mapping] = MappingProxyType({})

    def zones_for(self, countries: Iterable[str]) -> tuple[Zone, ...]:
        """Every zone of every named country, in ledger order.

        Order is preserved so a plan reads the same way twice and so the
        `hotspots[]` array the reduction concatenates lands in the order
        the overlay's ledger lists them.
        """
        wanted = {str(c).upper() for c in countries}
        return tuple(z for z in self.zones if z.country in wanted)

    def chokepoints_for(self, countries: Iterable[str]) -> tuple[tuple, ...]:
        wanted = {str(c).upper() for c in countries}
        return tuple(cp for cp in self.chokepoints
                     if str(cp[3]).upper() in wanted)

    def zone_census(self) -> Mapping[str, int]:
        """country -> zone count. The number H-1's first census got wrong.

        Kept as a derivation rather than a written-down table for exactly
        that reason: the design sheet's hand-written census omitted JP's
        two zones and IN's two, and JP is a forward base in the focused
        scenario.
        """
        counts: dict = {}
        for zone in self.zones:
            counts[zone.country] = counts.get(zone.country, 0) + 1
        return MappingProxyType(counts)


def _zone_country(record: Mapping) -> str:
    """`theater` in the file, `country` everywhere else."""
    value = record.get(LEGACY_COUNTRY_FIELD) or record.get("country") or ""
    return str(value).strip().upper()


def load(path=None) -> Geography:
    """Read `geo_data.json` once and hand back an immutable value.

    Raises rather than degrading. A geography that silently loaded half a
    file would expand half the zones, and a country watched over one of
    its two ISR corridors is a country whose second corridor is not
    watched — a coverage loss that presents as calm.
    """
    location = pathlib.Path(path) if path is not None else DEFAULT_PATH
    try:
        document = json.loads(location.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DomainError(
            f"could not read deployment geography from {location}: {exc}. "
            f"Running without it would silently narrow coverage — half the "
            f"ISR zones, no chokepoints, no tactical keywords — and a "
            f"narrowed sweep looks exactly like a quiet one.") from exc
    return from_document(document)


def from_document(document: Mapping) -> Geography:
    """Build the value from an already-parsed document. Pure."""
    if not isinstance(document, Mapping):
        raise DomainError(
            f"geography document must be a mapping, got "
            f"{type(document).__name__}")

    zones = []
    for record in document.get("ISR_HOTSPOTS", ()):
        country = _zone_country(record)
        name = str(record.get("name", "")).strip()
        if not country or not name:
            raise DomainError(
                f"ISR hotspot {record!r} has no usable country/name; the "
                f"overlay join is on `name` and the request scope is on "
                f"country, so neither may be blank")
        zones.append(Zone(
            name=name, country=country,
            lat=float(record["lat"]), lng=float(record["lng"]),
            radius_km=float(record.get("radius_km", 200.0))))

    chokepoints = tuple(
        (str(cp.get("name", "")), float(cp["lat"]), float(cp["lng"]),
         str(cp.get("country", "")).upper())
        for cp in document.get("CHOKEPOINTS", ()))

    coords = document.get("COUNTRY_COORDS", {}) or {}
    return Geography(
        zones=tuple(zones),
        chokepoints=chokepoints,
        country_coordinates=MappingProxyType({
            str(code).upper(): (float(row["lat"]), float(row["lng"]))
            for code, row in coords.items()}),
        country_names=MappingProxyType({
            str(code).upper(): str(row.get("name", ""))
            for code, row in coords.items() if row.get("name")}),
        tactical_keywords=MappingProxyType({
            str(code).upper(): tuple(terms)
            for code, terms in (document.get("TACTICAL_KEYWORDS", {})
                                or {}).items()}),
        geo_terms=MappingProxyType({
            str(code).upper(): tuple(terms)
            for code, terms in (document.get("NARRATIVE_GEO_TERMS", {})
                                or {}).items()}),
        airport_boxes=MappingProxyType({
            str(code).upper(): MappingProxyType(dict(row))
            for code, row in (document.get("AIRPORT_BOXES", {})
                              or {}).items()}),
        scenarios=MappingProxyType({
            str(key): MappingProxyType(dict(row))
            for key, row in (document.get("SCENARIOS", {}) or {}).items()}),
        infrastructure_urls=_by_country_lists(
            document.get("INFRASTRUCTURE_URLS", {})),
        watched_domains=_by_country_lists(
            document.get("CT_LOG_WATCHED_DOMAINS", {})),
        telegram_channels=MappingProxyType({
            str(name): MappingProxyType(dict(meta))
            for name, meta in (document.get("TELEGRAM_CHANNEL_META", {})
                               or {}).items()
            if not str(name).startswith("_")}))


def _by_country_lists(table) -> Mapping[str, tuple]:
    """ISO2 -> tuple of strings, skipping the file's `_comment` entries.

    `CT_LOG_WATCHED_DOMAINS` carries a `_comment` key explaining the
    curation policy. Treating it as a country produces a request for a
    paragraph of prose, which the upstream answers with something.
    """
    return MappingProxyType({
        str(code).upper(): tuple(str(v) for v in values)
        for code, values in (table or {}).items()
        if not str(code).startswith("_") and isinstance(values, (list, tuple))})


def participants_of(geography: Geography, scenario_id: str
                    ) -> tuple[str, ...]:
    """The countries a scenario is scored over, in weight order.

    Weight order rather than file order so the highest-coupled country is
    fetched first when a rate limit truncates a cycle: losing the tail of
    a sweep should cost the least-coupled participant, not whichever one
    the JSON happened to list last.
    """
    scenario = geography.scenarios.get(scenario_id)
    if scenario is None:
        raise DomainError(
            f"unknown scenario {scenario_id!r}; declared scenarios are "
            f"{sorted(geography.scenarios)}")
    participants = scenario.get("participants", {}) or {}
    ordered = sorted(participants.items(),
                     key=lambda item: (-float(item[1].get("weight", 0.0)),
                                       item[0]))
    return tuple(str(code).upper() for code, _ in ordered)


def adversaries_of(geography: Geography, scenario_id: str) -> tuple[str, ...]:
    """Participants whose declared role is the attacking side."""
    scenario = geography.scenarios.get(scenario_id) or {}
    participants = scenario.get("participants", {}) or {}
    return tuple(sorted(
        str(code).upper() for code, row in participants.items()
        if str(row.get("role", "")) == "adversary"))


__all__ = ["Zone", "Geography", "load", "from_document", "participants_of",
           "adversaries_of", "DEFAULT_PATH", "LEGACY_COUNTRY_FIELD"]
