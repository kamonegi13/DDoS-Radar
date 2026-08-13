"""The one module under `v3/` allowed to read the process environment.

Adapters declare `AuthRequirement(key_id, placement, name, value_template,
optional)` — WHAT credential they need and WHERE it goes, never its value.
`HttpClient` receives a `{key_id: material}` mapping and renders it into
the declared header or query parameter. Between the two there has to be
something that reads a secret store, and this is it.

The licence is scoped to this FILE by
`scripts/check_kernel_discipline.py::_ENV_OWNER`, not to `v3/runtime/`,
and `tests/test_runtime_boundary.py` sweeps all of `v3/` by AST to prove
no second module became a reader. A package-wide exemption would have
recreated G-15 one layer up: `os.getenv` available everywhere is how 95
of 98 registered configuration keys ended up never read.

**Anonymous operation is a fact, not a silence.** Six adapters declare a
credential; two of them declare it `optional=True`, which means
production runs WITHOUT it (OpenSky ships anonymous at 400 requests/day,
CertSpotter's free tier is tokenless). Declaring those mandatory took
three physical sensors dark for anyone running the shipped
`config.env.example`, so absence must not fail — but it must not be
invisible either, because "reduced quota" and "full coverage" produce the
same-looking empty result when the quota runs out. `resolve()` therefore
returns a posture for EVERY declared credential, and the caller cannot
obtain the material without also obtaining the list of adapters that will
run anonymously.

Nothing here is read at import. A composition root that snapshots the
environment on import makes every test process a configured process, and
`tests/test_runtime_boundary.py` installs a tripwire `os.environ` to prove
this module does not.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping, Optional, Sequence

from v3.kernel.errors import DomainError

#: The credential was supplied and will be sent.
AUTHENTICATED = "authenticated"
#: The credential is `optional=True` and no material was supplied. The
#: adapter runs, at whatever the source grants an unauthenticated caller.
ANONYMOUS = "anonymous"
#: The credential is required and no material was supplied. The adapter
#: will not reach the wire: `HttpClient` returns `AUTH_MISSING` before the
#: socket opens. Enumerated here so it is known BEFORE the cycle, not
#: reconstructed from fetch_log afterwards.
UNSATISFIED = "unsatisfied"

MODES: frozenset = frozenset({AUTHENTICATED, ANONYMOUS, UNSATISFIED})


@dataclass(frozen=True, slots=True)
class CredentialPosture:
    """How ONE adapter will authenticate this run, and why."""

    adapter_id: str
    key_id: str
    mode: str
    #: The adapter's own `AuthRequirement.note`, carried through so the
    #: disclosure says what anonymous operation costs at this source
    #: rather than only that it is happening.
    note: str = ""

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise DomainError(
                f"unknown credential mode {self.mode!r}, expected one of "
                f"{sorted(MODES)}")
        for name in ("adapter_id", "key_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(
                    f"CredentialPosture {name} must be non-empty, got "
                    f"{value!r}")

    @property
    def degraded(self) -> bool:
        return self.mode != AUTHENTICATED

    def as_dict(self) -> dict:
        return {"adapter_id": self.adapter_id, "key_id": self.key_id,
                "mode": self.mode, "note": self.note}


@dataclass(frozen=True, slots=True)
class CredentialPlan:
    """The material, and the honest account of what it does not cover.

    Both halves are in one value deliberately. A caller that could take
    `material` without `postures` would be a caller that can run three
    sources anonymously and never say so — and a quota-limited anonymous
    fetch fails by returning less data, which is the failure mode NP1
    treats as the worst kind.
    """

    material: Mapping[str, str]
    postures: tuple[CredentialPosture, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "material",
                           MappingProxyType(dict(self.material)))
        object.__setattr__(self, "postures", tuple(self.postures))

    def _mode(self, mode: str) -> tuple[CredentialPosture, ...]:
        return tuple(p for p in self.postures if p.mode == mode)

    @property
    def authenticated(self) -> tuple[CredentialPosture, ...]:
        return self._mode(AUTHENTICATED)

    @property
    def anonymous(self) -> tuple[CredentialPosture, ...]:
        return self._mode(ANONYMOUS)

    @property
    def unsatisfied(self) -> tuple[CredentialPosture, ...]:
        return self._mode(UNSATISFIED)

    @property
    def is_fully_credentialled(self) -> bool:
        return not any(p.degraded for p in self.postures)

    def mode_for(self, adapter_id: str) -> str:
        """How this adapter will authenticate. AUTHENTICATED if it needs
        no credential at all — 25 of 31 adapters are in that case."""
        for posture in self.postures:
            if posture.adapter_id == adapter_id:
                return posture.mode
        return AUTHENTICATED

    def as_dict(self) -> dict:
        """The disclosure. Never contains a secret — only key IDs."""
        return {
            "postures": [p.as_dict() for p in self.postures],
            "anonymous": [p.adapter_id for p in self.anonymous],
            "unsatisfied": [p.adapter_id for p in self.unsatisfied],
            "fully_credentialled": self.is_fully_credentialled,
        }

    def announcement(self) -> tuple[str, ...]:
        """One plain sentence per degraded adapter (NP6 / AP2 shape).

        Returned rather than logged: this module knows what happened, not
        where the operator reads. The tick writes them where they land.
        """
        lines = []
        for posture in self.anonymous:
            lines.append(
                f"{posture.adapter_id}: running ANONYMOUSLY — no "
                f"{posture.key_id} supplied. "
                f"{posture.note or 'Reduced quota or feature set applies.'}")
        for posture in self.unsatisfied:
            lines.append(
                f"{posture.adapter_id}: NO FETCH — required credential "
                f"{posture.key_id} was not supplied; every request will "
                f"return auth_missing before the socket opens.")
        return tuple(lines)


def required_key_ids(adapters: Iterable) -> tuple[str, ...]:
    """Every `key_id` the ENABLED adapters declare, in sorted order.

    Derived from the adapters rather than from a second list: a hardcoded
    key inventory is a list that drifts, and drift here presents as a
    source silently running anonymous.

    Disabled adapters are excluded for the same anti-drift reason: an
    adapter `run_due` will never plan cannot use a credential, and
    inventorying one (greynoise's, once GNQL went 410) tells the operator
    a key is wanted that no request could ever spend.
    """
    keys = set()
    for adapter in adapters:
        if not getattr(adapter, "enabled", True):
            continue
        for requirement in _requirements(adapter):
            if requirement.key_id:
                keys.add(requirement.key_id)
    return tuple(sorted(keys))


def from_environment(key_ids: Sequence[str]) -> Mapping[str, str]:
    """Read exactly the named keys from the process environment.

    Narrow by construction: the caller passes the key IDs the adapters
    declare (`required_key_ids`), so this cannot pick up a variable no
    adapter asked for, and the set of things it CAN read is derivable
    from the adapter registry rather than from this file.

    Empty and whitespace-only values are treated as absent. A key set to
    the empty string in `config.env` is the shape a half-finished deploy
    leaves behind, and rendering `Authorization: Bearer ` is a request
    that fails in a way the source reports as "no data".
    """
    if isinstance(key_ids, (str, bytes)):
        raise DomainError(
            f"from_environment takes a sequence of key ids, not the string "
            f"{key_ids!r}: a bare string reads its characters as keys")
    found = {}
    for key_id in key_ids:
        value = os.environ.get(str(key_id))
        if value is not None and value.strip():
            found[str(key_id)] = value.strip()
    return MappingProxyType(found)


def optional_value(key_id: str,
                   source: Optional[Mapping[str, str]] = None
                   ) -> Optional[str]:
    """One named secret, or None. NEVER generated, never persisted.

    Used by the composition root for the session surface's signing key and
    for bootstrap material. The asymmetry with production is deliberate
    and is the whole protection for the live system: `radar/auth.py`
    generates a key when `JWT_SECRET_KEY` is unset and APPENDS it to
    `config.env`. A second process doing the same thing would race that
    file, and the loser's key change logs every analyst out — the ops
    record's standing caution. So v3 reads its OWN key id, reads nothing
    if it is absent, and the caller composes a deployment with no session
    surface rather than one with an invented secret.
    """
    if source is not None:
        value = source.get(str(key_id))
    else:
        value = from_environment([str(key_id)]).get(str(key_id))
    if value is None or not str(value).strip():
        return None
    return str(value).strip()


def _requirements(adapter) -> tuple:
    """Every `AuthRequirement` an adapter can present, deduplicated.

    An adapter's credential can live on the adapter OR on an individual
    `RequestSpec` — `ioda_bgp`'s fallback is a Cloudflare endpoint needing
    Cloudflare's token while its primary needs none — and `client.fetch`
    prefers the per-request one. A posture built only from `adapter.auth`
    would report that adapter as needing nothing.
    """
    seen = []
    candidates = [getattr(adapter, "auth", None)]
    for declared in getattr(adapter, "requests", ()):
        for spec in _specs_of(declared):
            candidates.append(getattr(spec, "auth", None))
    for requirement in candidates:
        if requirement is None or not getattr(
                requirement, "declares_credential", False):
            continue
        identity = (requirement.key_id, requirement.optional)
        if identity not in [(r.key_id, r.optional) for r in seen]:
            seen.append(requirement)
    return tuple(seen)


def _specs_of(declared) -> tuple:
    """Flatten a RequestSpec / RequestChain / RequestContinuation."""
    alternatives = getattr(declared, "alternatives", None)
    if alternatives:
        specs = list(alternatives)
    else:
        specs = [declared]
    followed = getattr(declared, "then", None) or getattr(
        declared, "continuation", None)
    if followed is not None:
        specs.append(getattr(followed, "spec", followed))
    return tuple(spec for spec in specs if hasattr(spec, "url"))


def resolve(adapters: Iterable,
            source: Optional[Mapping[str, str]] = None) -> CredentialPlan:
    """Match declared requirements against available material.

    `source` is a plain mapping so tests supply one without touching the
    environment and so a deployment can layer several stores before
    calling. `None` means "read the environment for exactly the keys these
    adapters declare" — the production path, and the only one that
    touches `os.environ`.
    """
    adapters = tuple(adapters)
    material = dict(source) if source is not None else dict(
        from_environment(required_key_ids(adapters)))
    material = {k: v for k, v in material.items()
                if isinstance(v, str) and v.strip()}

    postures = []
    for adapter in adapters:
        adapter_id = getattr(adapter, "name", None) or str(
            getattr(adapter, "adapter_id", ""))
        for requirement in _requirements(adapter):
            if requirement.key_id in material:
                mode = AUTHENTICATED
            elif requirement.optional:
                mode = ANONYMOUS
            else:
                mode = UNSATISFIED
            postures.append(CredentialPosture(
                adapter_id=adapter_id, key_id=requirement.key_id,
                mode=mode, note=getattr(requirement, "note", "")))
    return CredentialPlan(material=material, postures=tuple(postures))


__all__ = ["AUTHENTICATED", "ANONYMOUS", "UNSATISFIED", "MODES",
           "CredentialPosture", "CredentialPlan", "resolve",
           "from_environment", "optional_value", "required_key_ids"]
