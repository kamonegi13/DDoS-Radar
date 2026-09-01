"""The adapter registry — where an `AdapterId` comes from (§2-3).

F-02 is the defect this exists to make unwritable. `_FORCE_SYNC_SENSORS`
contained the strings `"cf"` and `"ioda"`; the registered sensors were
`"cloudflare_radar"` and `"ioda_bgp"`. The match was `s.name in
_FORCE_SYNC_SENSORS`, so the force-fetch path excluded the two most
important sensors for the entire life of the feature, and nothing ever
complained — two strings failing to match is not an error condition.

`resolve()` turns a name into an `AdapterId` and **raises on a name it
does not know**. A list of adapter identifiers therefore fails at the line
where it is written, not silently at the line where it is used.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Optional

from v3.adapters.types import AdapterId, SourceAdapter
from v3.kernel.errors import DomainError


class AdapterRegistry:
    """An immutable set of declared adapters, indexed by identifier."""

    def __init__(self, adapters: Iterable[SourceAdapter]):
        indexed: dict[str, SourceAdapter] = {}
        for adapter in adapters:
            if not isinstance(adapter, SourceAdapter):
                raise DomainError(
                    f"registry holds SourceAdapter values, got "
                    f"{type(adapter).__name__}")
            name = adapter.adapter_id.value
            if name in indexed:
                raise DomainError(
                    f"duplicate adapter id {name!r}: two declarations for one "
                    f"identifier means one of them silently never runs")
            indexed[name] = adapter
        self._by_name: Mapping[str, SourceAdapter] = indexed

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, item) -> bool:
        name = item.value if isinstance(item, AdapterId) else item
        return name in self._by_name

    def resolve(self, name: str) -> AdapterId:
        """Name -> AdapterId, refusing anything unregistered.

        The referential integrity F-02 lacked. Note the error names the
        near misses: a typo is usually one character from something real,
        and saying so turns a puzzle into a fix.
        """
        if not isinstance(name, str):
            raise DomainError(
                f"resolve takes an adapter name, got {type(name).__name__}")
        adapter = self._by_name.get(name)
        if adapter is None:
            close = sorted(
                candidate for candidate in self._by_name
                if name in candidate or candidate.startswith(name[:3] or "\0"))
            raise DomainError(
                f"no adapter named {name!r}"
                + (f"; did you mean {close}?" if close else "")
                + ". This is defect F-02: a string that names no adapter "
                  "used to be indistinguishable from one that named a "
                  "disabled adapter.")
        return adapter.adapter_id

    def get(self, adapter_id: AdapterId) -> SourceAdapter:
        if not isinstance(adapter_id, AdapterId):
            raise DomainError(
                f"get takes an AdapterId, got {type(adapter_id).__name__}. "
                f"Use resolve(name) to obtain one — that is the step which "
                f"refuses an unknown name.")
        adapter = self._by_name.get(adapter_id.value)
        if adapter is None:
            raise DomainError(f"adapter {adapter_id} is not in this registry")
        return adapter

    def all(self) -> tuple[SourceAdapter, ...]:
        return tuple(self._by_name[name] for name in sorted(self._by_name))

    def enabled(self) -> tuple[SourceAdapter, ...]:
        return tuple(a for a in self.all() if a.enabled)

    def disabled(self) -> tuple[SourceAdapter, ...]:
        return tuple(a for a in self.all() if not a.enabled)

    def by_category(self, category: str) -> tuple[SourceAdapter, ...]:
        return tuple(a for a in self.all() if a.category == category)

    def rate_limit_groups(self) -> Mapping[str, tuple[str, ...]]:
        """group -> adapter names. Shows the shared quotas at a glance.

        OpenSky's three adapters share one group and one upstream quota
        (D1 §4 K01); a per-adapter limiter would let them collectively
        exceed a limit each of them individually respects.
        """
        grouped: dict[str, list[str]] = {}
        for adapter in self.all():
            grouped.setdefault(adapter.rate_limit_group, []).append(
                adapter.adapter_id.value)
        return {group: tuple(sorted(names))
                for group, names in sorted(grouped.items())}

    def _key_ids(self, *, required: bool) -> tuple[str, ...]:
        found: set = set()
        for adapter in self.enabled():
            for requirement in (adapter.auth,) + tuple(
                    spec.auth for spec in adapter.declared_specs
                    if spec.auth is not None):
                if requirement.key_id and \
                        requirement.is_required is required and \
                        requirement.declares_credential:
                    found.add(requirement.key_id)
        return tuple(sorted(found))

    def required_key_ids(self) -> tuple[str, ...]:
        """Secrets the composition root MUST supply. Nothing reads env.

        Optional credentials are not here: OpenSky ships anonymous, and
        listing its key as required would make a supported production
        configuration look like a misconfiguration.
        """
        return self._key_ids(required=True)

    def optional_key_ids(self) -> tuple[str, ...]:
        """Secrets that RAISE a source's quota or coverage when supplied.

        Enumerable so that "we are running three sensors anonymously" is a
        readable fact rather than something an operator discovers from a
        rate-limit graph.
        """
        return self._key_ids(required=False)


__all__ = ["AdapterRegistry"]
