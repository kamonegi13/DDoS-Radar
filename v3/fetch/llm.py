"""The one LLM submission path. Everything that asks a model asks here.

A-02 measured eight copies of this skeleton in production, one per sensor
that extracts intel. They had drifted: `max_tokens` runs 200 / 250 / 256 /
280 / 300 / 400 / 512 across the eight (`ast`-verified at
diplomatic.py:469, hacktivist_news_sensor.py:345, hacktivist_intel_sensor
.py:145 + ground_osint_sensor.py:221, apt_intel.py:504, military_exercise
.py:315, convergence_tracker.py:370, rss_narrative.py:409), and the
confidence floor is 0.35 in seven of them and 0.50 in the eighth
(convergence_tracker.py:382). Eight skeletons means eight parsing habits
and eight prompt shapes, and S5-VERIF-022 requires that a recorded
response can be replayed for ALL of them. P6 O-17 / design sheet §4-1
rules that the submission mouth is one. This is it.

WHAT IS SHARED HERE (S1-INGEST-010..013, 020):
    the request body, the tolerant response parse, the availability
    no-op, the failure vocabulary, and — new in v3 — the recording.

WHAT AN ADAPTER STILL CHOOSES (S1 §4 表 2's v3 norm, which limits the
per-sensor surface to exactly four slots):
    prefilter, prompt body, score_delta formula, domain.

RECORDING IS NOT OPTIONAL. `submit()` writes an `llm_call` row for every
exchange that reaches the model, because S5-VERIF-022 replays a recorded
response by `prompt_sha256` and MUST NOT call a live model during parity.
Production records only `prompt_version` on the annotation path (E-08),
so a conclusion drawn there is already unreplayable; the fix has to be at
the mouth, or every caller gets to forget separately.

NO ENVIRONMENT IS READ. The endpoint and the model id arrive as
arguments, the way credentials do — `v3/` forbids `os.getenv`, and an
endpoint resolved in here would be a second configuration surface behind
the one the composition root already owns.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional

from v3.fetch import recorder
from v3.fetch.client import OK as FETCH_OK
from v3.kernel.errors import DomainError
from v3.adapters.types import RequestSpec

#: The Ollama generate path. Pinned from radar/llm_client.py:30
#: (`_GENERATE_URL = f"{LLM_HOST}/api/generate"`).
GENERATE_PATH = "/api/generate"

#: The roster path. Pinned from radar/llm_client.py:31 (`_TAGS_URL`), read
#: by `llm_available()` at `:427`. It lives here for the same reason
#: `GENERATE_PATH` does: this file is the only one licensed to issue an
#: Ollama request (`tests/test_fetch_boundary.py`), so the probe cannot be
#: a second egress somewhere in `v3/runtime/`.
TAGS_PATH = "/api/tags"

#: radar/llm_client.py:427 — `requests.get(_TAGS_URL, timeout=5)`. v1
#: spends one scalar on connect AND read; v3's client separates them, so
#: this is carried as the CONNECT bound (what the 5 was protecting against
#: is an unreachable host) and the read bound stays the caller's
#: `LLM_TIMEOUT`.
AVAILABILITY_TIMEOUT_SEC = 5.0

#: radar/llm_client.py:532 — the shared function's own defaults, which
#: every one of the eight callers relies on for temperature (none of them
#: passes it; `ast`-verified across all eight call sites).
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MAX_TOKENS = 512

#: The body key Ollama reads. NOT `max_tokens` — radar/llm_client.py:447
#: (`opts = {"temperature": temperature, "num_predict": max_tokens}`).
#: Sending `max_tokens` would be accepted and ignored, and the model would
#: silently truncate at its own default, which is the "request the server
#: does not read" failure the WP-2.6 sweep found three times.
MAX_TOKENS_KEY = "num_predict"

# outcome vocabulary — S1-INGEST-013/014/020 want these distinguishable
DISABLED = "llm_disabled"
UNAVAILABLE = "llm_unavailable"
#: NEW, and deliberately not v1's. `llm_available()` returns a bare
#: `False` for "nothing answered on 11434" and for "Ollama answered and
#: does not hold this model" alike (radar/llm_client.py:427-441). The two
#: point at different repairs — start the daemon, or pull the model — and
#: S1-INGEST-020 asks that a cycle's silence be attributable, so they are
#: counted apart here.
MODEL_ABSENT = "llm_model_absent"
HTTP_ERROR = "http_error"
PARSE_FAILED = "json_parse_failed"
REPLAY_MISSING = "replay_response_missing"


@dataclass(frozen=True, slots=True)
class LlmRequest:
    """One exchange, fully specified. Nothing is filled in later."""

    prompt: str
    system: str = ""
    model_id: str = ""
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS
    #: `"json"` (production's value, free-form JSON) or a JSON SCHEMA as a
    #: mapping. WP-0.4 v2 needs the second: Tier 2's verdict is a closed
    #: vocabulary, and a schema makes an out-of-vocabulary answer
    #: impossible at the transport rather than a parse to validate after
    #: the fact. Ollama reads both under the same `format` key, so this is
    #: one field with two admissible shapes rather than a second request
    #: type (measured against Ollama 0.32.8 before landing).
    response_format: Any = "json"
    #: Reasoning-effort control for models that have one (`"low"` /
    #: `"medium"` / `"high"`, or a bool). Absent from the body when None,
    #: because an absent key and an explicit default are different
    #: requests to a model that has no thinking mode at all. Bench note
    #: (2026-08-15): gpt-oss:20b at thinking-high spends the token budget
    #: on reasoning and returns no JSON — the same failure mode
    #: `_CONCLUSION_GEMMA31` records for v1's routing.
    think: Optional[Any] = None

    def __post_init__(self) -> None:
        if not isinstance(self.prompt, str) or not self.prompt.strip():
            raise DomainError("llm prompt must be a non-empty string")
        if self.response_format is not None and \
                not isinstance(self.response_format, (str, Mapping)):
            raise DomainError(
                f"response_format is 'json' or a JSON schema mapping, got "
                f"{type(self.response_format).__name__}: a format the "
                f"server does not read is a constraint that silently is "
                f"not applied (the WP-2.6 sweep's recurring shape)")
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise DomainError(
                "llm model_id is required: S5-VERIF-022 replays by prompt "
                "AND model, so an exchange recorded without one cannot be "
                "shown to have come from the model it claims")
        if isinstance(self.temperature, bool) or not isinstance(
                self.temperature, (int, float)):
            raise DomainError("llm temperature must be a number")
        if isinstance(self.max_tokens, bool) or not isinstance(
                self.max_tokens, int) or self.max_tokens <= 0:
            raise DomainError("llm max_tokens must be a positive integer")

    def body(self) -> Mapping[str, Any]:
        """The request body, transcribed from radar/llm_client.py:585-601.

        `system` is present only when non-empty and `format` only when
        set, matching production's conditional assignment — an empty
        `system` key is a different request from an absent one.
        """
        payload: dict = {
            "model": self.model_id,
            "prompt": self.prompt,
            "stream": False,
            "options": {"temperature": float(self.temperature),
                        MAX_TOKENS_KEY: int(self.max_tokens)},
        }
        if self.response_format:
            payload["format"] = (dict(self.response_format)
                                 if isinstance(self.response_format, Mapping)
                                 else self.response_format)
        if self.system:
            payload["system"] = self.system
        if self.think is not None:
            payload["think"] = self.think
        return MappingProxyType(payload)

    def spec(self, *, endpoint: str) -> RequestSpec:
        """The declarative request the shared HTTP client will issue.

        Built as a `RequestSpec` rather than as a bespoke call so the LLM
        exchange goes through the SAME single HTTP exit (§1-4) as every
        fetch — timeout, breaker and `fetch_log` included. A second HTTP
        path for the model is a second path that can forget them.
        """
        base = endpoint.rstrip("/")
        if not base:
            raise DomainError(
                "llm endpoint is required; it is supplied by the "
                "composition root, never read from the environment here")
        return RequestSpec(
            url=f"{base}{GENERATE_PATH}",
            method="POST",
            body=self.body(),
            body_content_type="application/json",
            label="llm_generate")


@dataclass(frozen=True, slots=True)
class LlmResult:
    """The outcome, in production's shape plus what replay needs.

    `ok=False` carries a reason from the vocabulary above rather than an
    empty dict, because S1-INGEST-014 requires "the model saw no signal"
    and "the call failed" to be separable — they point at different
    repairs, and merging them makes both undiagnosable.
    """

    ok: bool
    data: Mapping[str, Any] = field(default_factory=dict)
    error: str = ""
    response_text: str = ""
    replayed: bool = False
    recorded_sha256: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "data",
                           MappingProxyType(dict(self.data or {})))


def parse_response(text: str) -> tuple[bool, dict]:
    """The tolerant parse, transcribed from radar/llm_client.py:649-663.

    Three steps in this order, and no more: strip fenced-code lines, try
    `json.loads`, then slice from the first `{` to the last `}` and try
    again. Production does NOT re-ask the model, and neither does this —
    a retry would make the same prompt produce two different recordings.
    """
    if not isinstance(text, str):
        return False, {}
    stripped = text.strip()
    if not stripped:
        return False, {}
    if "```" in stripped:
        stripped = "\n".join(
            line for line in stripped.splitlines()
            if not line.strip().startswith("```")).strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}") + 1
        if start < 0 or end <= start:
            return False, {}
        try:
            parsed = json.loads(stripped[start:end])
        except json.JSONDecodeError:
            return False, {}
    if not isinstance(parsed, dict):
        # A bare list or scalar parses but has no fields to validate, and
        # S1-INGEST-013 forbids continuing on a fallback value.
        return False, {}
    return True, parsed


def _response_text(payload) -> str:
    """Ollama's envelope: `response`, falling back to `thinking`.

    radar/llm_client.py:623-630 — a thinking model can answer with an
    empty `response` and its whole answer in `thinking`, and treating
    that as an empty answer loses the exchange.
    """
    if payload is None:
        return ""
    try:
        envelope = payload.json()
    except Exception:
        return ""
    if not isinstance(envelope, dict):
        return ""
    text = str(envelope.get("response") or "").strip()
    if text:
        return text
    return str(envelope.get("thinking") or "").strip()


@dataclass(frozen=True, slots=True)
class Availability:
    """Whether the model can be asked, and why not when it cannot.

    A boolean would have been enough for the CALLER — it either submits or
    it does not — and not enough for the report it has to write. G-17: a
    stage that skipped every article must be able to say which silence it
    was, and `False` cannot.
    """

    available: bool
    reason: str = ""
    models: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"available": self.available, "reason": self.reason,
                "models": list(self.models)}


def model_matches(models, model_id: str) -> bool:
    """v1's match rule, transcribed from radar/llm_client.py:430-431.

    `any(m == LLM_MODEL or m.startswith(LLM_MODEL.split(":")[0]))` — the
    prefix arm is what lets `gemma4:26b` be satisfied by a roster entry of
    `gemma4:26b-instruct`, and dropping it would report a present model as
    absent on every tagged pull.
    """
    wanted = str(model_id or "").strip()
    if not wanted:
        return False
    family = wanted.split(":")[0]
    return any(str(name) == wanted or str(name).startswith(family)
               for name in models)


def probe(*, client, endpoint: str, model_id: str, now: float,
          enabled: bool = True) -> Availability:
    """Can this deployment ask the model right now? radar/llm_client.py:427.

    One GET per tick, before any submission, because S1-INGEST-010 wants an
    unavailable model to be a no-op SUCCESS rather than N failed POSTs: a
    down Ollama would otherwise cost `cap x LLM_TIMEOUT` of the tick and
    advance nothing.

    Every non-answer is a NAMED reason, never a bare False — see
    `MODEL_ABSENT`.
    """
    if not enabled:
        return Availability(False, DISABLED)
    base = str(endpoint or "").rstrip("/")
    if not base:
        raise DomainError(
            "llm endpoint is required; it is supplied by the composition "
            "root, never read from the environment here")
    outcome = client.fetch(RequestSpec(url=f"{base}{TAGS_PATH}",
                                       label="llm_tags"), now=now)
    if outcome.outcome != FETCH_OK:
        return Availability(False, UNAVAILABLE)
    envelope = None
    try:
        envelope = outcome.payload.json() if outcome.payload else None
    except Exception:                       # noqa: BLE001 - not a document
        envelope = None
    if not isinstance(envelope, dict):
        return Availability(False, UNAVAILABLE)
    names = tuple(str((row or {}).get("name") or "")
                  for row in (envelope.get("models") or [])
                  if isinstance(row, Mapping))
    if not model_matches(names, model_id):
        return Availability(False, MODEL_ABSENT, names)
    return Availability(True, "", names)


def replay(request: LlmRequest, *, store) -> Optional[LlmResult]:
    """The recorded exchange for this prompt, or None. S5-VERIF-022.

    None is a fact to report, not a gap to fill: the clause requires the
    conclusion type to be excluded from parity and the exclusion stated,
    never a live model called to make the numbers line up.
    """
    row = recorder.recorded_response(store, request.prompt)
    if row is None:
        return None
    ok, data = parse_response(row.get("response") or "")
    return LlmResult(ok=ok, data=data,
                     error="" if ok else PARSE_FAILED,
                     response_text=row.get("response") or "",
                     replayed=True,
                     recorded_sha256=row.get("prompt_sha256") or "")


def submit(request: LlmRequest, *, client, store, adapter_id: str,
           now: float, endpoint: str, available: bool = True,
           replay_only: bool = False) -> LlmResult:
    """Ask the model once, record the exchange, return the parsed answer.

    S1-INGEST-010: an unavailable or disabled model is a no-op SUCCESS.
    The caller records no failure and the breaker does not advance,
    because a stopped LLM is not a broken sensor — opening a sensor's
    breaker because the model is down would take the sensor's own
    non-LLM output down with it.

    S5-VERIF-022: with `replay_only`, no request is issued at all. A
    missing recording returns `REPLAY_MISSING` rather than falling
    through to the network, which is the whole point — a parity run that
    can reach a live model is a parity run that is not reproducible.
    """
    if replay_only:
        return replay(request, store=store) or LlmResult(
            ok=False, error=REPLAY_MISSING)
    if not available:
        return LlmResult(ok=False, error=UNAVAILABLE)

    outcome = client.fetch(request.spec(endpoint=endpoint), now=now)
    if outcome.outcome != FETCH_OK:
        return LlmResult(ok=False,
                         error=f"{HTTP_ERROR}:{outcome.outcome}")

    text = _response_text(outcome.payload)
    # Recorded BEFORE the parse. An unparseable answer is exactly the one
    # worth keeping: it is the evidence for why the conclusion is absent,
    # and recording only the answers we liked would make the ledger agree
    # with us by construction.
    digest = ""
    if text:
        digest = recorder.record_llm_call(
            store, adapter_id, prompt=request.prompt, response=text,
            model_id=request.model_id, temperature=request.temperature,
            called_at=now)
    ok, data = parse_response(text)
    return LlmResult(ok=ok, data=data, error="" if ok else PARSE_FAILED,
                     response_text=text, recorded_sha256=digest)


__all__ = ["LlmRequest", "LlmResult", "submit", "replay", "parse_response",
           "Availability", "probe", "model_matches",
           "GENERATE_PATH", "TAGS_PATH", "AVAILABILITY_TIMEOUT_SEC",
           "MAX_TOKENS_KEY", "DEFAULT_TEMPERATURE",
           "DEFAULT_MAX_TOKENS", "DISABLED", "UNAVAILABLE", "MODEL_ABSENT",
           "HTTP_ERROR", "PARSE_FAILED", "REPLAY_MISSING"]
