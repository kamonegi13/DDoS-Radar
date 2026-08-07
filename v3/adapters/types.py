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

import json
import math
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Sequence, Union

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
AUTH_KINDS: frozenset = frozenset({AUTH_NONE, AUTH_API_KEY, AUTH_OAUTH2})

#: WHERE the credential travels. The WP-2.6 sweep found that `client.py`
#: hard-coded `{"Auth-Key": secret}` for every adapter. That header is
#: right for exactly one source (abuse.ch); Cloudflare wants
#: `Authorization: Bearer` (`radar/config.py:322`), GreyNoise's header is
#: literally `key` (`radar/sensors/greynoise.py:49`), and OpenWeather takes
#: no header at all — the key is the query parameter `appid`
#: (`radar/sensors/openweather.py:25`). Three sources were therefore
#: presenting a credential no server would read, and a 401 that leaves the
#: previous reading in place is indistinguishable from a quiet day.
AUTH_IN_HEADER = "header"
AUTH_IN_QUERY = "query"
AUTH_PLACEMENTS: frozenset = frozenset({AUTH_IN_HEADER, AUTH_IN_QUERY})

#: The one slot a credential value may occupy in a declared template.
SECRET_SLOT = "{secret}"

# ── fallback triggers (§2-1, ruling 3) ──────────────────────────────────
#: Advance to the next alternative when the fetch itself did not succeed.
#: This is what production does in both shipped chains: `ct_log`'s
#: CertSpotter source returns None on timeout / connection error / non-200
#: and the orchestrator moves to crt.sh; `ioda`'s `_fetch_ioda_proper`
#: returns None on the same conditions and `_fetch_cf_fallback` runs.
FALLBACK_ON_FAILURE = "failure"
#: Also advance when the fetch succeeded but returned no bytes. The kernel
#: can see "no bytes"; it cannot see "no useful content", because judging
#: that requires parsing, which is `normalize`'s job and happens after the
#: chain has already been resolved. No shipped adapter selects this yet —
#: choosing it where production does not would be an unregistered
#: behavioural difference (P2 §5-C) — but K02's shape (AISHub answering a
#: rejected request with HTTP 200 and an empty body) is exactly what it
#: exists for.
FALLBACK_ON_FAILURE_OR_EMPTY = "failure_or_empty"
FALLBACK_TRIGGERS: frozenset = frozenset({FALLBACK_ON_FAILURE,
                                          FALLBACK_ON_FAILURE_OR_EMPTY})

#: Content types a declared body may use. JSON only: every production POST
#: body under `radar/sensors/` is JSON, and a second serializer would be a
#: second place for the wire format to drift from the declaration.
JSON_CONTENT_TYPES: frozenset = frozenset({"application/json"})

# ── the statuses an adapter may emit ────────────────────────────────────
#: Admitted by the scoring kernel when not suppressed (v3.scoring.inputs
#: STATUS_FIRED, S1-PIPE-009). Spelling is load-bearing.
STATUS_FIRED = "FIRED"
#: Measured, nothing to report.
STATUS_OK = "OK"
#: Measured, and the reading is explained by something the analyst should
#: discount (weather, a geomagnetic storm, an earthquake by a cable).
STATUS_SUPPRESSED = "SUPPRESSED"
#: The source ran but could not measure this country.
STATUS_NO_DATA = "NO_DATA"
#: A measurement whose verdict needs a baseline this layer does not hold.
#:
#: DP4 records the hour-of-day Z-score written three times (`ripe_bgp`,
#: `check_host`, the scoring layer) and the least-squares trend written
#: three times; design sheet §3-2 collapses both into the L1 baseline
#: store plus L2's `trend.py`. Until that wiring lands, an adapter whose
#: firing rule is "compare against my history" reports what it measured
#: and says so, rather than inventing a verdict from a baseline it does
#: not have — or, worse, reporting OK, which reads as "measured, nothing
#: wrong" and is how a blind spot becomes silence (NP1).
STATUS_OBSERVED = "OBSERVED"

ADAPTER_STATUSES: frozenset = frozenset({
    STATUS_FIRED, STATUS_OK, STATUS_SUPPRESSED, STATUS_NO_DATA,
    STATUS_OBSERVED})


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
    """What credential a source needs, WHERE it goes — never the value.

    `key_id` names a secret the composition root supplies at run time.
    Nothing under `v3/` reads the environment (the discipline gate fails
    the build on `os.getenv`), so an adapter cannot pick up a key on its
    own even if it wanted to.

    **`name` and `value_template` have no defaults, deliberately.** The
    defect this type is repairing was a default — one hard-coded header
    that happened to be right for the source it was written against and
    wrong for the three that came later. A default here would relocate
    that failure rather than remove it: an adapter that forgot to declare
    its header would still send something plausible to a server that
    rejects it, and a rejection this layer reads as "no data" is silence.
    Omission must fail where it is written.

    `optional=True` means production runs WITHOUT the credential when the
    composition root has none: `opensky` ships anonymous (400 req/day,
    `radar/sensors/opensky_auth.py:17`), `ct_log`'s CertSpotter token and
    `threatfox`'s Auth-Key are `if key:` guards. Declaring those mandatory
    aborted the fetch with AUTH_MISSING before the socket opened, which
    took three physical sensors dark for anyone running the shipped
    `config.env.example`.
    """

    kind: str = AUTH_NONE
    key_id: Optional[str] = None
    placement: str = AUTH_IN_HEADER
    #: The header name, or the query parameter name, exactly as the wire
    #: wants it — `Auth-Key`, `key`, `Authorization`, `appid`.
    name: str = ""
    #: How the value is written, with `{secret}` marking the credential's
    #: place: `"{secret}"` for a raw key, `"Bearer {secret}"` for OAuth2.
    value_template: str = ""
    #: The source works without this credential (at a reduced quota or a
    #: reduced feature set). Absent material means ANONYMOUS, not failure.
    optional: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in AUTH_KINDS:
            raise DomainError(f"unknown auth kind {self.kind!r}")
        if self.kind == AUTH_NONE:
            if self.optional:
                raise DomainError(
                    "optional=True with kind=none says an absent credential "
                    "is acceptable where no credential is declared at all; "
                    "one of the two statements is wrong")
            if self.name or self.value_template:
                raise DomainError(
                    f"auth kind 'none' cannot name a header or a template, "
                    f"got name={self.name!r} template={self.value_template!r}")
            return
        if not self.key_id:
            raise DomainError(
                f"auth kind {self.kind!r} needs a key_id naming the secret "
                f"the composition root must supply")
        if self.placement not in AUTH_PLACEMENTS:
            raise DomainError(
                f"unknown auth placement {self.placement!r}; expected one of "
                f"{sorted(AUTH_PLACEMENTS)}. OpenWeather is the reason this "
                f"field exists — its key is the query parameter 'appid', not "
                f"a header, and sending it as a header is a 401 that reads "
                f"as a quiet day.")
        if not isinstance(self.name, str) or not self.name.strip():
            raise DomainError(
                f"auth kind {self.kind!r} must declare the name it travels "
                f"under ({'header' if self.placement == AUTH_IN_HEADER else 'query parameter'}). "
                f"There is no default: the hard-coded 'Auth-Key' that this "
                f"field replaces was correct for one source and silently "
                f"wrong for three.")
        object.__setattr__(self, "name", self.name.strip())
        if not isinstance(self.value_template, str) or \
                SECRET_SLOT not in self.value_template:
            raise DomainError(
                f"auth value_template must contain {SECRET_SLOT} marking "
                f"where the credential goes, got "
                f"{self.value_template!r}. Cloudflare's is "
                f"'Bearer {SECRET_SLOT}'; GreyNoise's is '{SECRET_SLOT}'.")
        if self.value_template.count(SECRET_SLOT) != 1:
            raise DomainError(
                f"auth value_template must contain {SECRET_SLOT} exactly "
                f"once, got {self.value_template!r}")

    @property
    def declares_credential(self) -> bool:
        """This source has a credential at all — required or not."""
        return self.kind != AUTH_NONE

    @property
    def is_required(self) -> bool:
        """The composition root MUST supply material for this source.

        Optional credentials are excluded: a missing one is a documented
        production mode (anonymous OpenSky), not a configuration gap.
        """
        return self.declares_credential and not self.optional

    @property
    def in_header(self) -> bool:
        return self.declares_credential and self.placement == AUTH_IN_HEADER

    @property
    def in_query(self) -> bool:
        return self.declares_credential and self.placement == AUTH_IN_QUERY

    def render(self, secret: str) -> str:
        """The wire value for a supplied secret. The ONLY place the two meet."""
        if not self.declares_credential:
            raise DomainError(
                "a no-auth requirement has no value to render")
        return self.value_template.replace(SECRET_SLOT, secret)


def _reject_callables(where: str, items) -> None:
    """A function anywhere in a declaration is 'how to fetch' (§2-1)."""
    for key, value in items:
        if callable(value):
            raise DomainError(
                f"RequestSpec {where}[{key!r}] is callable. A RequestSpec is "
                f"a declaration; a function here would be 'how to fetch', "
                f"which adapters cannot declare (§2-1).")


@dataclass(frozen=True, slots=True)
class RequestSpec:
    """One upstream request, declared. Carries no callables (§2-1).

    A function here would be a place to write "how to fetch", which is the
    one thing an adapter must not be able to express.

    **`params` is an ordered sequence of pairs, not a mapping.** A mapping
    keeps one value per name, and two production requests need more:
    `check_host` sends `node[]` five times (JP/US/DE/NL/FR,
    `radar/sensors/checkhost.py:46-47`, which itself notes "Pass list of
    tuples to requests to allow repeated same key"), and `ct_log`'s
    CertSpotter call sends `expand=dns_names` AND `expand=issuer`
    (`ct_log_sources/certspotter.py:268`). Without `issuer`, every
    certificate parses to `unknown` and is dropped, so that adapter is
    permanently silent. Order is part of fidelity too — the WP-2.6 sweep
    found a reordered table — so the declared order is the sent order.
    """

    url: str
    method: str = "GET"
    params: tuple = ()
    headers: Mapping[str, str] = field(default_factory=dict)
    #: A JSON request body. ThreatFox posts one in production
    #: (`radar/sensors/threatfox.py:42`, `json=payload`); the WP-2.6 port
    #: turned it into a query string, which abuse.ch answers with an error.
    body: Optional[Mapping[str, Any]] = None
    body_content_type: str = ""
    #: An auth override for THIS request. Almost always unset — the
    #: adapter's own `auth` applies. `ioda_bgp` is the exception: its
    #: declared fallback is a Cloudflare Radar endpoint that needs
    #: Cloudflare's bearer token while its primary needs nothing, so the
    #: credential belongs to the request rather than to the source.
    auth: Optional[AuthRequirement] = None
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
        object.__setattr__(self, "params", _as_param_pairs(self.params))
        if not isinstance(self.headers, Mapping):
            raise DomainError("RequestSpec headers must be a mapping")
        _reject_callables("headers", self.headers.items())
        object.__setattr__(self, "headers",
                           MappingProxyType(dict(self.headers)))
        if self.auth is not None and not isinstance(self.auth,
                                                    AuthRequirement):
            raise DomainError(
                f"RequestSpec auth must be an AuthRequirement, got "
                f"{type(self.auth).__name__}")
        self._validate_body()

    def _validate_body(self) -> None:
        if self.body is None:
            if self.body_content_type:
                raise DomainError(
                    f"RequestSpec declares body_content_type "
                    f"{self.body_content_type!r} with no body to send")
            return
        if self.method != "POST":
            raise DomainError(
                f"a request body needs method POST, got {self.method!r}")
        if not isinstance(self.body, Mapping):
            raise DomainError(
                f"RequestSpec body must be a mapping (it is serialized as a "
                f"JSON object), got {type(self.body).__name__}")
        if self.body_content_type not in JSON_CONTENT_TYPES:
            raise DomainError(
                f"a body must declare body_content_type as one of "
                f"{sorted(JSON_CONTENT_TYPES)}, got "
                f"{self.body_content_type!r}")
        if any(name.lower() == "content-type" for name in self.headers):
            raise DomainError(
                "a Content-Type header beside a declared body gives the wire "
                "format two declarations that can drift; body_content_type "
                "is the one that ships")
        _reject_callables("body", self.body.items())
        object.__setattr__(self, "body", MappingProxyType(dict(self.body)))

    def param_values(self, name: str) -> tuple:
        """Every value declared under `name`, in declaration order."""
        return tuple(value for key, value in self.params if key == name)

    def body_bytes(self) -> Optional[bytes]:
        """The serialized body, or None. Deterministic for a given body."""
        if self.body is None:
            return None
        return json.dumps(dict(self.body), sort_keys=False,
                          ensure_ascii=False).encode("utf-8")

    def substituted(self, *, url: str, params: tuple, headers: Mapping,
                    body: Optional[Mapping], label: str) -> "RequestSpec":
        """A copy with templates resolved. Used only by the expander."""
        return replace(self, url=url, params=params, headers=dict(headers),
                       body=None if body is None else dict(body), label=label)

    # Hashability ruling (WP-2.5 review): value-equal, deliberately NOT
    # hashable. `frozen=True` normally advertises hashability, but this
    # type holds a mapping, so the generated __hash__ raises deep inside
    # itself. Setting it to None turns that into an immediate, legible
    # "unhashable type" at the call site. These are values to compare, not
    # dictionary keys.
    __hash__ = None


def _as_param_pairs(params) -> tuple:
    """Validate and freeze the (name, value) sequence.

    A `Mapping` is refused rather than converted. Converting would accept
    the shape that cannot express `expand` twice, and the loss would
    happen at the dictionary literal — before this function ever sees it —
    so there would be nothing left to complain about.
    """
    if isinstance(params, Mapping):
        raise DomainError(
            "RequestSpec params must be an ordered sequence of "
            "(name, value) pairs, not a mapping: a mapping keeps one value "
            "per name, and production sends 'expand' twice (ct_log) and "
            "'node[]' five times (check_host). Write "
            "((\"expand\", \"dns_names\"), (\"expand\", \"issuer\")).")
    if isinstance(params, (str, bytes)) or not isinstance(params, Sequence):
        raise DomainError(
            f"RequestSpec params must be a sequence of (name, value) pairs, "
            f"got {type(params).__name__}")
    pairs: list = []
    for entry in params:
        if isinstance(entry, (str, bytes)) or not isinstance(entry, Sequence) \
                or len(entry) != 2:
            raise DomainError(
                f"RequestSpec params entry must be a (name, value) pair, got "
                f"{entry!r}")
        name, value = entry
        if callable(value):
            raise DomainError(
                f"RequestSpec params[{name!r}] is callable. A RequestSpec is "
                f"a declaration; a function here would be 'how to fetch', "
                f"which adapters cannot declare (§2-1).")
        if not isinstance(name, str):
            raise DomainError(
                f"RequestSpec parameter name must be a string, got {name!r}")
        pairs.append((name, str(value)))
    return tuple(pairs)


@dataclass(frozen=True, slots=True)
class RequestChain:
    """Try the first alternative; fall back only if it does not answer.

    K05 and K19 are both conditional in production. `ct_log` queries
    CertSpotter and reaches crt.sh only for what CertSpotter rejects
    (`radar/sensors/ct_log.py:144-152`); `ioda_bgp` calls the Georgia Tech
    IODA API and `_fetch_cf_fallback` **only when that returns None**
    (`radar/sensors/ioda.py:49-55`).

    v3's runner fetched every declared spec unconditionally, so for
    `ioda_bgp` a Cloudflare traffic anomaly could FIRED-override IODA's
    OK. That is a structural difference in the sensitive direction, and it
    existed because the model had no way to say "only if".

    The chain is DATA. `advance_on` names a condition the kernel knows how
    to evaluate; it is not a predicate the adapter supplies, because a
    predicate is "how to fetch".
    """

    alternatives: tuple = ()
    advance_on: str = FALLBACK_ON_FAILURE
    #: Why a second source exists at all. Required for the same reason
    #: `disabled_reason` is: a fallback with no stated cause cannot be
    #: told apart from a duplicate somebody forgot to delete.
    reason: str = ""
    label: str = ""

    def __post_init__(self) -> None:
        alternatives = tuple(self.alternatives)
        if len(alternatives) < 2:
            raise DomainError(
                f"a RequestChain needs at least two alternatives, got "
                f"{len(alternatives)}; a chain of one is a plain RequestSpec")
        for spec in alternatives:
            if not isinstance(spec, RequestSpec):
                raise DomainError(
                    f"a RequestChain holds RequestSpec alternatives, got "
                    f"{type(spec).__name__}")
        object.__setattr__(self, "alternatives", alternatives)
        if self.advance_on not in FALLBACK_TRIGGERS:
            raise DomainError(
                f"unknown advance_on {self.advance_on!r}; expected one of "
                f"{sorted(FALLBACK_TRIGGERS)}. It is a declared condition, "
                f"not a predicate — a function here would be 'how to fetch'.")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise DomainError(
                "a RequestChain must state the reason a fallback exists; an "
                "unexplained second source is indistinguishable from one "
                "nobody removed")
        object.__setattr__(self, "reason", self.reason.strip())

    __hash__ = None


@dataclass(frozen=True, slots=True)
class ResponseValue:
    """One value the kernel lifts out of a response into the next request.

    `path` is a declared route into the decoded JSON document — data, not
    a lookup function. A callable here would be `normalize`'s job moved
    into the declaration, and with it the ability to reach the network a
    second time on terms nobody else can see.

    Only JSON is addressable. Every production continuation in the 34
    sources is a JSON handshake (`check-host.net` answers
    `{"request_id": "..."}`), and a second addressing language would be a
    second place for the declaration to disagree with the wire.
    """

    placeholder: str
    path: tuple = ()
    #: A missing value ends the continuation with a recorded failure. It
    #: is `True` for every shipped case and exists so that an optional
    #: handshake field, if one ever appears, is stated rather than assumed.
    required: bool = True

    def __post_init__(self) -> None:
        name = self.placeholder
        if not isinstance(name, str) or not name:
            raise DomainError(
                f"ResponseValue placeholder must be a non-empty string, got "
                f"{name!r}")
        if not name.replace("_", "").isalnum() or not name.islower():
            raise DomainError(
                f"ResponseValue placeholder must be lower_snake_case, got "
                f"{name!r}: it is substituted by the same expander that "
                f"resolves {{country}}, which only recognises that spelling")
        path = tuple(self.path)
        if not path:
            raise DomainError(
                f"ResponseValue {name!r} declares no path into the response; "
                f"an extraction with no route extracts nothing")
        for key in path:
            if callable(key):
                raise DomainError(
                    f"ResponseValue {name!r} path element {key!r} is "
                    f"callable. A path is data; a function here would be "
                    f"'how to fetch' (§2-1).")
            if not isinstance(key, (str, int)) or isinstance(key, bool):
                raise DomainError(
                    f"ResponseValue {name!r} path elements must be object "
                    f"keys or array indices, got {type(key).__name__}")
        object.__setattr__(self, "path", path)
        if not isinstance(self.required, bool):
            raise DomainError(
                f"ResponseValue required must be a real bool, got "
                f"{type(self.required).__name__}")

    @property
    def slot(self) -> str:
        """The literal the second request writes where this value goes."""
        return "{" + self.placeholder + "}"

    __hash__ = None


def _spec_mentions(spec: RequestSpec, slot: str) -> bool:
    """Does any text this spec puts on the wire contain `slot`?"""
    texts = [spec.url, spec.label]
    for key, value in spec.params:
        texts.extend((key, value))
    for key, value in spec.headers.items():
        texts.extend((key, value))
    if spec.body is not None:
        for key, value in spec.body.items():
            texts.extend((key, value))
    return any(isinstance(text, str) and slot in text for text in texts)


@dataclass(frozen=True, slots=True)
class RequestContinuation:
    """A, then B(A). The second request needs the first one's answer.

    `RequestChain` says "A **or** B". This says "A **then** B(A)", and the
    difference is not academic: `check_host` posts a check, reads
    `request_id` out of the reply, waits, and fetches
    `check-result/{request_id}` (`radar/sensors/checkhost.py:60-72`).
    Declaring that as two independent requests made the second one
    unfetchable — `{request_id}` has no value at plan time, so the whole
    adapter was skipped as `unresolved_placeholder` and the most direct
    infrastructure-reachability sensor in the roster never ran.

    The invariant is unchanged: the adapter declares WHAT (which field
    carries the handle, how long the upstream needs) and the kernel
    decides HOW (when to decode, how to wait, what to record when the
    handle never arrives). `carries` is data and `delay_sec` is a number;
    neither is a callable, so there is still nowhere to write a private
    fetch.
    """

    first: RequestSpec
    then: RequestSpec
    carries: tuple = ()
    #: How long the upstream needs before the result exists. Declared, not
    #: slept — `radar/sensors/checkhost.py:66` is a bare `time.sleep(5)`
    #: inside the sensor, which is exactly the "how to fetch" an adapter
    #: must not be able to express.
    delay_sec: float = 0.0
    #: Why a second request exists at all — the same requirement
    #: `RequestChain.reason` carries, for the same reason.
    reason: str = ""
    label: str = ""

    def __post_init__(self) -> None:
        for name in ("first", "then"):
            spec = getattr(self, name)
            if not isinstance(spec, RequestSpec):
                raise DomainError(
                    f"RequestContinuation {name} must be a RequestSpec, got "
                    f"{type(spec).__name__}")
        carries = tuple(self.carries)
        if not carries:
            raise DomainError(
                "a RequestContinuation must carry at least one value from "
                "the first response; carrying none makes it two independent "
                "requests, which is what RequestSpec already expresses")
        seen: set = set()
        for value in carries:
            if not isinstance(value, ResponseValue):
                raise DomainError(
                    f"RequestContinuation carries ResponseValue entries, got "
                    f"{type(value).__name__}")
            if value.placeholder in seen:
                raise DomainError(
                    f"RequestContinuation carries {value.placeholder!r} "
                    f"twice; two extractions for one slot cannot both win")
            seen.add(value.placeholder)
            if not _spec_mentions(self.then, value.slot):
                raise DomainError(
                    f"RequestContinuation carries {value.placeholder!r} but "
                    f"the second request never writes {value.slot}. An "
                    f"extraction nothing consumes is a value read from the "
                    f"wire and dropped, which reads as a working handshake.")
        object.__setattr__(self, "carries", carries)
        delay = self.delay_sec
        if isinstance(delay, bool) or not isinstance(delay, (int, float)):
            raise DomainError(
                f"RequestContinuation delay_sec must be a number, got "
                f"{type(delay).__name__}")
        if delay < 0 or math.isnan(delay) or math.isinf(delay):
            raise DomainError(
                f"RequestContinuation delay_sec must be a finite "
                f"non-negative number of seconds, got {delay!r}")
        object.__setattr__(self, "delay_sec", float(delay))
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise DomainError(
                "a RequestContinuation must state why the second request "
                "exists; an unexplained follow-up is indistinguishable from "
                "a duplicate nobody removed")
        object.__setattr__(self, "reason", self.reason.strip())

    @property
    def alternatives(self) -> tuple:
        """The specs this declaration can put on the wire, in order.

        Named to match `RequestChain` so that auditing code which only
        wants "what might be fetched" does not have to know which of the
        two it is holding.
        """
        return (self.first, self.then)

    __hash__ = None


#: What an adapter may put in `requests`: an unconditional request, a
#: fallback chain ("A or B"), or a continuation ("A then B(A)").
DeclaredRequest = Union[RequestSpec, RequestChain, RequestContinuation]



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
    # Geography, supplied rather than read. Several sources answer
    # globally and are made per-country by arithmetic (a fire inside a
    # radius, an earthquake inside a territory, a tile near a coast), so
    # `normalize` needs coordinates — but nothing under `v3/` reads
    # configuration, so the composition root passes them in and the pure
    # function stays a pure function of its arguments.
    country_coordinates: Mapping[str, tuple] = field(default_factory=dict)
    #: ISO2 -> English name, for sources whose data is tagged with names
    #: rather than codes (ThreatFox tags read "Taiwan", not "TW").
    country_names: Mapping[str, str] = field(default_factory=dict)
    #: `(name, lat, lon, country)` per watched chokepoint.
    chokepoints: tuple = ()
    #: Scenario adversaries, for rules phrased "inside hostile territory".
    adversaries: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.now <= 0:
            raise DomainError(
                f"NormalizeContext.now must be a positive timestamp, got "
                f"{self.now}")
        object.__setattr__(self, "countries",
                           tuple(c.upper() for c in self.countries))
        object.__setattr__(self, "adversaries",
                           tuple(c.upper() for c in self.adversaries))
        object.__setattr__(self, "country_coordinates",
                           MappingProxyType({
                               str(code).upper(): tuple(point)
                               for code, point in
                               dict(self.country_coordinates).items()}))
        object.__setattr__(self, "country_names",
                           MappingProxyType({
                               str(code).upper(): str(name)
                               for code, name in
                               dict(self.country_names).items()}))
        object.__setattr__(self, "chokepoints", tuple(self.chokepoints))


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
    #: The `fired_reason` the scoring layer records — the sentence an
    #: analyst reads next to the verdict ("BGP anomaly confirmed",
    #: `radar/routes/core.py:1097`). Before this field existed the value
    #: had nowhere to go, so `check_host` improvised it into `flags` under
    #: an ad-hoc key; one adapter inventing a convention is how the next
    #: five invent five more.
    reason: str = ""
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
        if not isinstance(self.reason, str):
            raise DomainError(
                f"ObservationDraft reason must be a string, got "
                f"{type(self.reason).__name__}")
        object.__setattr__(self, "reason", self.reason.strip())
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
    # Baselines this source's verdict depends on, named. An adapter that
    # needs history to decide anything DECLARES that need rather than
    # keeping the history itself: DP3 lists nine sensors holding detection
    # state in process memory, where a restart silently costs detection
    # capability (`ais_maritime` loses dark-gap detection entirely). A
    # declared dependency is visible in the registry; a dictionary on an
    # instance is visible to nobody.
    baseline_refs: tuple[str, ...] = ()
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
            if not isinstance(spec, (RequestSpec, RequestChain,
                                     RequestContinuation)):
                raise DomainError(
                    f"requests must hold RequestSpec, RequestChain or "
                    f"RequestContinuation values, got {type(spec).__name__}")
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

    @property
    def declared_specs(self) -> tuple:
        """Every RequestSpec declared, chains flattened, in order.

        For inspection and auditing — the runner works from expanded
        steps, because only those know which alternatives are conditional.
        """
        flat: list = []
        for declared in self.requests:
            if isinstance(declared, (RequestChain, RequestContinuation)):
                flat.extend(declared.alternatives)
            else:
                flat.append(declared)
        return tuple(flat)


__all__ = [
    "AdapterId", "AuthRequirement", "RequestSpec", "RequestChain",
    "ResponseValue", "RequestContinuation",
    "DeclaredRequest", "FetchedPayload",
    "NormalizeContext", "ObservationDraft", "NormalizeFn", "SourceAdapter",
    "CATEGORIES", "SCORING_DOMAINS", "CYBER", "PHYSICAL", "INFO", "LLM",
    "META", "AUTH_NONE", "AUTH_API_KEY", "AUTH_OAUTH2", "AUTH_KINDS",
    "AUTH_IN_HEADER", "AUTH_IN_QUERY", "AUTH_PLACEMENTS", "SECRET_SLOT",
    "FALLBACK_ON_FAILURE", "FALLBACK_ON_FAILURE_OR_EMPTY",
    "FALLBACK_TRIGGERS", "JSON_CONTENT_TYPES",
    "STATUS_FIRED", "STATUS_OK", "STATUS_SUPPRESSED", "STATUS_NO_DATA",
    "STATUS_OBSERVED", "ADAPTER_STATUSES",
]
