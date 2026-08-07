"""What an adapter is allowed to say. Design sheet §2.

An adapter declares two things: **what to fetch** (`requests`) and **how to
normalize** (`normalize`). It cannot declare how to fetch — no timeout, no
retry policy, no parser choice, no circuit breaker, no output destination.

That restriction is the entire design, and it is a response to a measured
failure. A-10: the shared helpers `_safe_get` / `_safe_post` /
`handle_rate_limit` existed and had **zero callers**; all 28 fetch
implementations used raw `requests`; 429 was handled by 8 of 36 sensors.
S4-NF-061 concludes that "put it in the base class and ask people to use
it" has already been tried and failed, so v3 must close the path instead.

`normalize` receives bytes that have already been fetched and returns
values. There is no client in its scope, nothing to write to, and no way
to ask for another URL — the four barriers in §2-2 are what make that
true rather than customary.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from v3.kernel import Window
from v3.kernel.errors import DomainError

# ── categories (the S1 books' five) ─────────────────────────────────────
CYBER = "cyber"
PHYSICAL = "physical"
INFO = "info"
LLM = "llm"
META = "meta"
CATEGORIES: frozenset = frozenset({CYBER, PHYSICAL, INFO, LLM, META})

# ── the three scoring domains an observation may land in ────────────────
SCORING_DOMAINS: frozenset = frozenset({"cyber", "physical", "info"})

# ── auth shapes ─────────────────────────────────────────────────────────
AUTH_NONE = "none"
AUTH_API_KEY = "api_key"
AUTH_OAUTH2 = "oauth2"


@dataclass(frozen=True, slots=True)
class AdapterId:
    """A typed adapter identifier (§2-3, repairing F-02).

    F-02 measured the cost of string literals: `_FORCE_SYNC_SENSORS`
    listed `"cf"` and `"ioda"` while the real names were
    `"cloudflare_radar"` and `"ioda_bgp"`, so the force-fetch path
    silently excluded the two most important sensors — for as long as the
    feature existed. Nothing objected, because comparing two strings that
    do not match is not an error.

    Obtaining one of these goes through the registry, which refuses a name
    it does not know. A typo therefore fails where it is written.
    """

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise DomainError(
                f"adapter id must be a non-empty string, got {self.value!r}")
        if not self.value.replace("_", "").isalnum() or \
                not self.value.islower():
            raise DomainError(
                f"adapter id must be lower_snake_case, got {self.value!r}; "
                f"the identifier appears in the ledger and in fetch_log and "
                f"must round-trip unchanged")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AuthRequirement:
    """What credential a source needs — never the credential itself.

    `key_id` names a secret the composition root supplies at run time.
    Nothing under `v3/` reads the environment (the discipline gate fails
    the build on `os.getenv`), so an adapter cannot pick up a key on its
    own even if it wanted to.
    """

    kind: str = AUTH_NONE
    key_id: Optional[str] = None
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in (AUTH_NONE, AUTH_API_KEY, AUTH_OAUTH2):
            raise DomainError(f"unknown auth kind {self.kind!r}")
        if self.kind != AUTH_NONE and not self.key_id:
            raise DomainError(
                f"auth kind {self.kind!r} needs a key_id naming the secret "
                f"the composition root must supply")

    @property
    def is_required(self) -> bool:
        return self.kind != AUTH_NONE


@dataclass(frozen=True, slots=True)
class RequestSpec:
    """One upstream request, declared. Carries no callables (§2-1).

    A function here would be a place to write "how to fetch", which is the
    one thing an adapter must not be able to express.
    """

    url: str
    method: str = "GET"
    params: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    expect_content: str = "any"          # any | json | xml | csv | text
    label: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url.startswith(
                ("http://", "https://")):
            raise DomainError(
                f"RequestSpec url must be an absolute http(s) URL, got "
                f"{self.url!r}")
        if self.method not in ("GET", "POST"):
            raise DomainError(
                f"RequestSpec method must be GET or POST, got {self.method!r}")
        for name, mapping in (("params", self.params),
                              ("headers", self.headers)):
            if not isinstance(mapping, Mapping):
                raise DomainError(f"RequestSpec {name} must be a mapping")
            for key, value in mapping.items():
                if callable(value):
                    raise DomainError(
                        f"RequestSpec {name}[{key!r}] is callable. A "
                        f"RequestSpec is a declaration; a function here "
                        f"would be 'how to fetch', which adapters cannot "
                        f"declare (§2-1).")
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))
        object.__setattr__(self, "headers",
                           MappingProxyType(dict(self.headers)))

    # Hashability ruling (WP-2.5 review): value-equal, deliberately NOT
    # hashable. `frozen=True` normally advertises hashability, but this
    # type holds a mapping, so the generated __hash__ raises deep inside
    # itself. Setting it to None turns that into an immediate, legible
    # "unhashable type" at the call site. These are values to compare, not
    # dictionary keys.
    __hash__ = None



@dataclass(frozen=True, slots=True)
class FetchedPayload:
    """Bytes that have already been retrieved. All `normalize` ever sees."""

    url: str
    status: int
    body: bytes
    fetched_at: float
    content_type: str = ""
    label: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.body, (bytes, bytearray)):
            raise DomainError(
                f"FetchedPayload body must be bytes, got "
                f"{type(self.body).__name__}")
        object.__setattr__(self, "body", bytes(self.body))

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, "replace")

    def json(self) -> Any:
        import json
        return json.loads(self.body.decode("utf-8", "replace"))


@dataclass(frozen=True, slots=True)
class NormalizeContext:
    """Everything `normalize` may consult. Note what is absent.

    No HTTP client, no ledger handle, no clock — `now` is the fetch
    instant, passed in, so normalization of a recorded payload reproduces
    exactly (which is what makes the fixture tests meaningful and parity
    replay possible).
    """

    adapter_id: AdapterId
    now: float
    countries: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.now <= 0:
            raise DomainError(
                f"NormalizeContext.now must be a positive timestamp, got "
                f"{self.now}")
        object.__setattr__(self, "countries",
                           tuple(c.upper() for c in self.countries))


@dataclass(frozen=True, slots=True)
class ObservationDraft:
    """What `normalize` returns: a value, not a stored fact.

    The runner turns this into a kernel `Evidence` and a
    `SignalObservation`. Adapters do not write to L1 (§2-2) — A-03 and
    A-09 are what happens when they can: sensors calling `set_cache`,
    baselines living in process memory, and eventually a second SQLite
    file nobody governs.
    """

    signal_source: str
    domain: str
    country: str
    status: str
    raw_score: float = 0.0
    confidence: float = 1.0
    suppressed: bool = False
    suppress_reason: Optional[str] = None
    evidence_url: Optional[str] = None
    value: str = ""
    flags: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("signal_source", "domain", "status"):
            text = getattr(self, name)
            if not isinstance(text, str) or not text.strip():
                raise DomainError(
                    f"ObservationDraft {name} must be non-empty, got "
                    f"{text!r}")
            object.__setattr__(self, name, text.strip())
        if self.domain not in SCORING_DOMAINS:
            raise DomainError(
                f"ObservationDraft domain must be one of "
                f"{sorted(SCORING_DOMAINS)}, got {self.domain!r}")
        object.__setattr__(self, "country", (self.country or "").strip().upper())
        for name in ("raw_score", "confidence"):
            number = getattr(self, name)
            if isinstance(number, bool) or not isinstance(number, (int, float)):
                raise DomainError(
                    f"ObservationDraft {name} must be a number, got "
                    f"{type(number).__name__}")
            if math.isnan(number) or math.isinf(number):
                raise DomainError(
                    f"ObservationDraft {name} must be finite, got {number!r}: "
                    f"a NaN stored as a fact compares False against every "
                    f"later threshold")
            object.__setattr__(self, name, float(number))
        if not 0.0 <= self.confidence <= 1.0:
            raise DomainError(
                f"confidence must be within [0,1], got {self.confidence}")
        if not isinstance(self.suppressed, bool):
            raise DomainError(
                f"suppressed must be a real bool, got "
                f"{type(self.suppressed).__name__}; coercing would make the "
                f"string 'false' mean True")
        object.__setattr__(self, "flags", MappingProxyType(dict(self.flags)))

    # Hashability ruling (WP-2.5 review): value-equal, deliberately NOT
    # hashable. `frozen=True` normally advertises hashability, but this
    # type holds a mapping, so the generated __hash__ raises deep inside
    # itself. Setting it to None turns that into an immediate, legible
    # "unhashable type" at the call site. These are values to compare, not
    # dictionary keys.
    __hash__ = None


NormalizeFn = Callable[[FetchedPayload, NormalizeContext],
                       "tuple[ObservationDraft, ...]"]


@dataclass(frozen=True, slots=True)
class SourceAdapter:
    """One source, declared. §2-1's shape exactly."""

    adapter_id: AdapterId
    category: str
    requests: tuple[RequestSpec, ...]
    cadence: Window
    normalize: NormalizeFn
    freshness_horizon_sec: float
    auth: AuthRequirement = field(default_factory=AuthRequirement)
    rate_limit_group: str = ""
    min_interval_sec: float = 0.0
    record_body: bool = False
    knowledge_refs: tuple[str, ...] = ()
    enabled: bool = True
    disabled_reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, AdapterId):
            raise DomainError(
                f"adapter_id must be an AdapterId, got "
                f"{type(self.adapter_id).__name__}. A bare string is how "
                f"F-02 misnamed two sensors out of the force-fetch path.")
        if self.category not in CATEGORIES:
            raise DomainError(
                f"unknown category {self.category!r}; expected one of "
                f"{sorted(CATEGORIES)}")
        if not isinstance(self.cadence, Window):
            raise DomainError(
                f"cadence must be a kernel Window, got "
                f"{type(self.cadence).__name__} (F-06)")
        if not callable(self.normalize):
            raise DomainError("normalize must be callable")
        requests = tuple(self.requests)
        for spec in requests:
            if not isinstance(spec, RequestSpec):
                raise DomainError(
                    f"requests must hold RequestSpec values, got "
                    f"{type(spec).__name__}")
        if self.enabled and not requests and self.category != META:
            raise DomainError(
                f"{self.adapter_id} is enabled but declares no requests; a "
                f"source that fetches nothing should say so with "
                f"enabled=False and a reason")
        if not self.enabled and not self.disabled_reason:
            raise DomainError(
                f"{self.adapter_id} is disabled without a reason. NOTAM is "
                f"disabled because no free international API exists (K14) — "
                f"a disabled adapter with no stated cause is indistinguish"
                f"able from an oversight.")
        object.__setattr__(self, "requests", requests)
        if self.freshness_horizon_sec <= 0:
            raise DomainError(
                f"freshness_horizon_sec must be positive, got "
                f"{self.freshness_horizon_sec}: it becomes the kernel "
                f"Evidence horizon, and a non-positive one makes every "
                f"observation instantly stale")
        object.__setattr__(self, "rate_limit_group",
                           self.rate_limit_group or self.adapter_id.value)
        object.__setattr__(self, "knowledge_refs", tuple(self.knowledge_refs))

    @property
    def name(self) -> str:
        return self.adapter_id.value


__all__ = [
    "AdapterId", "AuthRequirement", "RequestSpec", "FetchedPayload",
    "NormalizeContext", "ObservationDraft", "NormalizeFn", "SourceAdapter",
    "CATEGORIES", "SCORING_DOMAINS", "CYBER", "PHYSICAL", "INFO", "LLM",
    "META", "AUTH_NONE", "AUTH_API_KEY", "AUTH_OAUTH2",
]
