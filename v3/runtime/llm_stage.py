"""The LLM extraction stage. The production caller `v3/fetch/llm.py` lacked.

C12 in `v3/api/registry.py` records the measurement this module answers,
and it is blunter than the deferral that preceded it: **no production path
in v3 called `v3/fetch/llm.py::submit`** (AST-verified; the only callers
were tests). The consequences were all silent ones —

    the `llm_call` ledger had never held a row, so S5-VERIF-022 had
    nothing to replay;
    four adapters wrote candidate articles into L1 under
    `flags["awaiting"] = "llm_extraction"` and nothing ever came for
    them;
    `v3/adapters/llm/extraction.py` — "the one extraction surface" —
    said of itself, through `v3/runtime/reduce_common.py:157-162`, that
    "nothing in v3/runtime/ calls it yet".

Every part existed. Nothing walked between them. This module is the walk:

    collect  this cycle's awaiting articles, from the drafts the fold
             hook sees
    prefilter / prompt   each adapter's own two slots (S1 §4 表 2)
    submit   ONE exchange per accepted article, through the one mouth
    build    the shared validator's thirteen-field envelope
    append   through the SAME seam the runner uses
             (`v3/fetch/runner.py::append_drafts`), never a second one

WHERE IT SITS. A stage of the tick, called after the fetch cycle and
BEFORE scoring (`v3/runtime/tick.py`), so an item extracted in a tick is
scored in that tick rather than in the next one — L2 reads L1's in-force
projection at `now`, and writing after the score would make every intel
item one tick late for no stated reason.

WHAT IT DOES NOT DO. It does not read the environment (the egress, the
endpoint and the model id arrive as arguments, from the composition root),
it does not build an HTTP client, and it does not decide whether an item
is worth anything — `score_delta` is the adapter's slot and the weighting
is L2's.

裁定 (WP-2.7 stage, 2026-08-13) are marked inline. Each states what it
chose, and what the alternative would have cost.
"""
from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Sequence

from v3.adapters.cyber import apt_intel as apt_intel_source
from v3.adapters.llm import diplomatic as diplomatic_source
from v3.adapters.llm import extraction as ex
from v3.adapters.llm import hacktivist_news as hacktivist_source
from v3.adapters.llm import military_exercise as military_source
from v3.adapters.types import AdapterId, ObservationDraft
from v3.fetch import llm as llm_module
from v3.fetch.runner import append_drafts
from v3.kernel.errors import DomainError

#: The flag the four candidate-article adapters stamp on a row that is
#: still waiting for a model. Matched by PREFIX, because `apt_intel`
#: spells it `"llm_extraction (WP-2.7)"` (`apt_intel.py:116`) and the
#: others spell it `"llm_extraction"` — and a stage that matched only the
#: exact string would silently ignore one of the four families it exists
#: to serve.
AWAITING = "llm_extraction"

#: 裁定 — the per-tick article budget.
#:
#: S1-INGEST's gating clauses fix per-SOURCE gates (rss_narrative only on
#: a Z-burst, convergence cooldowns) and no global per-tick cap, so this
#: number is chosen rather than transcribed, and it is chosen against the
#: clock: the tick's default interval is 60s
#: (`v3/runtime/loop.py::DEFAULT_INTERVAL_SEC`) and one exchange is bounded
#: by LLM_TIMEOUT, 30s (v1 parity, `radar/config.py:675`).
#:
#: WORST CASE ADDED TICK TIME: 4 x 30s = 120s of generation, plus one 30s
#: availability probe = 150s. That already exceeds the interval, which is
#: the point of stopping at four: a larger cap makes the acquisition half
#: of the tick a hostage to a serial GPU queue, and the loop's own
#: schedule is what NP3 protects. Four is also one call for each of the
#: three sources that have an `IntelProfile` plus one, so no source is
#: structurally starved in a cycle where all three produce.
LLM_ARTICLES_PER_TICK = 4

# ── the vocabulary of a skipped article (S1-INGEST-020 / G-17) ──────────
#: Nothing was wired: `run_tick` got no egress. A deployment fact, and NOT
#: the same as a disabled model — one is a composition that did not supply
#: an LLM, the other is an operator who turned it off.
NOT_WIRED = "llm_not_wired"
#: The adapter has no `IntelProfile`, so its articles reach no model.
#: `apt_intel` is the live case and says so in its own source
#: (`apt_intel.py:112-116`).
NO_PROFILE = "no_intel_profile"
#: Slot 1 said no. Cheap, and it is the reason production spends nothing
#: on an article with no text.
PREFILTERED = "prefilter_rejected"
#: The budget ran out. Counted, because "we did not ask" and "we asked and
#: the model found nothing" are the two facts this programme refuses to
#: let look alike.
OVER_BUDGET = "over_budget"
#: The same article arrived on two feeds in one cycle.
DUPLICATE = "duplicate_article"
#: Nothing was waiting. Named rather than left as an empty report,
#: because S1-INGEST-020 asks a silent cycle to say WHICH silence it was,
#: and "no feed produced a candidate" is a different fact from "the model
#: was down".
NO_CANDIDATE = "no_candidate_article"
#: The shared validator refused the model's answer on an invariant. Filed
#: with the drops rather than raised: the answer is EXTERNAL data, and a
#: tick that dies because a model returned a surprising shape is a tick
#: that stops scoring every other sensor too (NP3).
EXTRACTION_REFUSED = "extraction_refused"


# ── what a source needs beyond its four slots ───────────────────────────

@dataclass(frozen=True, slots=True)
class IntelSource:
    """One wired family: its profile, and how it names an unheadlined item.

    `headline_fallback` is NOT a fifth behavioural slot (S1 §4 表 2 pins
    four). It is the adapter's own already-written function, bound here to
    the `(article, answer, primary)` the stage happens to hold — production
    computes the same string at the same point (`diplomatic.py:539`,
    `hacktivist_news_sensor.py:441`). `military_exercise` declares none, so
    it gets none: an absent fallback means the model's own empty headline
    stands, which is what `build_item` already does.
    """

    profile: ex.IntelProfile
    headline_fallback: Optional[Callable[[Mapping, Mapping, str], str]] = None

    def fallback_for(self, article: Mapping, answer: Mapping,
                     primary: str) -> str:
        if self.headline_fallback is None:
            return ""
        return str(self.headline_fallback(article, answer, primary))


def _diplomatic_headline(article: Mapping, answer: Mapping,
                         primary: str) -> str:
    return diplomatic_source.headline_fallback(
        str(article.get("feed") or diplomatic_source.SOURCE_TYPE), primary)


def _hacktivist_headline(article: Mapping, answer: Mapping,
                         primary: str) -> str:
    return hacktivist_source.headline_fallback(
        str(answer.get("group_name") or ""), primary)


#: The families that CAN be extracted, by adapter name.
#:
#: `apt_intel` is deliberately absent and its absence is counted, never
#: quietly skipped: it declares no `IntelProfile` at all, and inventing a
#: prompt for it here would be an eighth prompt written outside the
#: adapter that owns it — precisely A-02's shape. Its articles are
#: reported under `NO_PROFILE` every tick, which is the honest reading of
#: "this family is not yet extracted".
SOURCES: Mapping[str, IntelSource] = MappingProxyType({
    "diplomatic": IntelSource(diplomatic_source.PROFILE,
                              _diplomatic_headline),
    "military_exercise": IntelSource(military_source.PROFILE),
    "hacktivist_news": IntelSource(hacktivist_source.PROFILE,
                                   _hacktivist_headline),
})

#: Named so the disclosure can say WHICH family is unserved rather than
#: leaving the reader to diff two lists.
UNPROFILED: tuple[str, ...] = (apt_intel_source.SIGNAL_SOURCE,)


# ── the composition root's bundle ───────────────────────────────────────

@dataclass(frozen=True, slots=True)
class LlmEgress:
    """The dedicated LLM exit, and what it asks. Built by the root only.

    Carries the CLIENT because the stage must not construct one: v3 has a
    single HTTP exit per purpose and the composition root decides its
    timeout and retry ladder. This one is deliberately NOT the sensor
    client — a 30s read timeout and `max_attempts=1` (v1 parity: one
    attempt, no retry, `radar/llm_client.py:289`) are wrong for a public
    API and right for a serial GPU queue, where a retry ladder multiplies
    the load that caused the timeout.
    """

    client: Any
    endpoint: str
    model_id: str
    enabled: bool = True
    articles_per_tick: int = LLM_ARTICLES_PER_TICK
    #: S5-VERIF-022: a parity run reuses stored answers and issues nothing.
    replay_only: bool = False

    def __post_init__(self) -> None:
        if self.client is None:
            raise DomainError(
                "LlmEgress needs a client; the stage does not build one "
                "(v3/runtime/ injects transports, it does not become one)")
        if not str(self.endpoint or "").strip():
            raise DomainError(
                "LlmEgress needs an endpoint; it is resolved by the "
                "composition root and nothing under v3/ reads it from the "
                "environment")
        if not str(self.model_id or "").strip():
            raise DomainError(
                "LlmEgress needs a model id: S5-VERIF-022 replays by prompt "
                "AND model, so an exchange recorded without one cannot be "
                "shown to have come from the model it claims")
        if int(self.articles_per_tick) < 0:
            raise DomainError("articles_per_tick cannot be negative")


@dataclass(frozen=True, slots=True)
class Candidate:
    """One article waiting for a model, with where it came from."""

    adapter_id: str
    article: Mapping[str, Any]
    feed: str = ""

    @property
    def dedup_key(self) -> str:
        """The adapter's own key, or the title. Never empty-and-equal:
        two untitled articles must not dedup onto each other."""
        key = str(self.article.get("dedup_key") or "").strip()
        if key:
            return f"{self.adapter_id}:{key}"
        return f"{self.adapter_id}:{self.feed}:{self.article.get('title', '')}"


# ── the report ──────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class LlmStageReport:
    """What the stage did, including every way it did nothing.

    On the `TickReport` because `ops_health`'s LLM rollup has nothing else
    to read: a stage that ran, found the model down and skipped eleven
    articles must not be indistinguishable from a stage that was never
    called (G-17). Counts, not booleans, for the same reason.
    """

    enabled: bool = True
    available: bool = False
    reason: str = ""
    model_id: str = ""
    articles_considered: int = 0
    articles_accepted: int = 0
    submitted: int = 0
    succeeded: int = 0
    failed: int = 0
    items_built: int = 0
    observations_written: int = 0
    budget: int = LLM_ARTICLES_PER_TICK
    #: reason -> count, from the vocabulary above plus `llm.DISABLED` /
    #: `llm.UNAVAILABLE` / `llm.MODEL_ABSENT`.
    skipped: Mapping[str, int] = field(default_factory=dict)
    #: `build_item`'s drop reasons — the S1-INGEST-014 separation between
    #: "the model saw no signal" and "it scored under the floor".
    drops: Mapping[str, int] = field(default_factory=dict)
    #: transport / parse failures, by `LlmResult.error`.
    errors: Mapping[str, int] = field(default_factory=dict)
    by_adapter: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("skipped", "drops", "errors", "by_adapter"):
            object.__setattr__(self, name,
                               MappingProxyType(dict(getattr(self, name))))

    def as_dict(self) -> dict:
        return {"enabled": self.enabled, "available": self.available,
                "reason": self.reason, "model_id": self.model_id,
                "articles_considered": self.articles_considered,
                "articles_accepted": self.articles_accepted,
                "submitted": self.submitted, "succeeded": self.succeeded,
                "failed": self.failed, "items_built": self.items_built,
                "observations_written": self.observations_written,
                "budget": self.budget,
                "skipped": dict(self.skipped),
                # Named on its own because the ruling asks the stage to say
                # this one out loud: an unreachable model must never read
                # as a quiet cycle.
                "skipped_unavailable": int(
                    self.skipped.get(llm_module.UNAVAILABLE, 0)),
                "drops": dict(self.drops), "errors": dict(self.errors),
                "unprofiled_families": list(UNPROFILED),
                "by_adapter": {name: dict(row)
                               for name, row in self.by_adapter.items()}}


def unwired() -> LlmStageReport:
    """The report for a tick that was given no egress at all.

    A value rather than an empty mapping, because `ops_health` reads an
    empty mapping as UNSUPPLIED and this state is not unsupplied — it is
    supplied and negative, and the difference is whether an operator goes
    looking for a broken probe or for a missing composition.
    """
    return LlmStageReport(enabled=False, available=False, reason=NOT_WIRED,
                          budget=0)


# ── collection ──────────────────────────────────────────────────────────

def collect(awaiting: Mapping[str, Sequence[ObservationDraft]]
            ) -> tuple[Candidate, ...]:
    """This cycle's candidate articles, from the drafts the fold hook saw.

    WHY HERE, and not from L1. Three collection points were available and
    two of them lie:

      * the FOLDED row that reaches L1 flattens per-article provenance —
        `reduce_common.py:180-186` keeps `feeds_with_candidates` at row
        level, so an article read back from there cannot say which feed
        carried it, and `source_id` on the intel envelope is exactly that
        (S1-INGEST-019);
      * a read-back of L1 would need a query keyed on `tick_id`, which no
        store method offers; `signals_between` is keyed on time and would
        return other ticks' rows landing in the same second.

    The fold hook sees the RAW drafts, one per selected article, and it
    runs inside the transaction that writes them (`runner.py:619-626`) —
    so what it hands over is what L1 received, with the provenance still
    attached. That is the honest point, and it costs no second read.
    """
    candidates: list[Candidate] = []
    for adapter_id, drafts in sorted(awaiting.items()):
        for draft in drafts or ():
            flags = dict(getattr(draft, "flags", {}) or {})
            if not str(flags.get("awaiting") or "").startswith(AWAITING):
                continue
            article = flags.get("article")
            if not isinstance(article, Mapping) or not article:
                continue
            candidates.append(Candidate(adapter_id=str(adapter_id),
                                        article=dict(article),
                                        feed=str(flags.get("feed") or "")))
    return tuple(candidates)


def _round_robin(candidates: Sequence[Candidate], *, budget: int
                 ) -> tuple[tuple[Candidate, ...], tuple[Candidate, ...]]:
    """Spend the budget one article per adapter per pass. NP1.

    First-come would let `diplomatic` — eleven feeds, up to eight selected
    articles — consume the whole budget every cycle and leave
    `hacktivist_news` structurally unheard. A source nobody ever asks is a
    detection that cannot happen, which is the miss NP1 ranks above a
    false positive.
    """
    if budget <= 0:
        return (), tuple(candidates)
    queues: dict[str, list[Candidate]] = {}
    for candidate in candidates:
        queues.setdefault(candidate.adapter_id, []).append(candidate)
    taken: list[Candidate] = []
    while len(taken) < budget and any(queues.values()):
        for name in sorted(queues):
            if len(taken) >= budget:
                break
            if queues[name]:
                taken.append(queues[name].pop(0))
    accepted = set(id(candidate) for candidate in taken)
    deferred = tuple(candidate for candidate in candidates
                     if id(candidate) not in accepted)
    return tuple(taken), deferred


def _context(candidate: Candidate, *, now: float,
             countries: Sequence[str]) -> dict:
    """The prompt's context. One builder, read differently by each slot.

    `today` is derived from the tick's `now` rather than from the wall
    clock, so a replayed cycle builds the same prompt and therefore the
    same `prompt_sha256` — S5-VERIF-022 replays BY that hash, and a prompt
    carrying today's date would make yesterday's recording unfindable.

    `theaters` falls back to the tick's participant union, because
    `hacktivist_news` articles carry none (its prompt calls the list
    "CONTEXT only" and tells the model not to force-assign from it).
    """
    article = candidate.article
    theaters = article.get("theaters")
    if not isinstance(theaters, (list, tuple)) or not theaters:
        theaters = tuple(countries)
    return {"today": time.strftime("%Y-%m-%d", time.gmtime(float(now))),
            "theaters": tuple(str(code) for code in theaters),
            "country": str(article.get("country") or ""),
            "org": str(article.get("org") or ""),
            "source": candidate.feed}


def _merge(drafts: Sequence[ObservationDraft]) -> ObservationDraft:
    """N items for one (sensor, country) -> the ONE row L1 can hold.

    L1 is `UNIQUE (tick_id, sensor, signal_source, country)`, so a second
    item for TW from the same source in the same tick raises rather than
    being stored — the fold has to happen HERE or the tick dies on its own
    output.

    ADDITIVE, per S1-INGEST-018 ("`base + bonus`, never multiplicative").
    Keeping only the largest would have been simpler and would discard
    evidence, which is the direction NP1 forbids; every merged envelope
    stays in `flags["merged_items"]` so the published number can be taken
    apart (NP6).

    The representative — highest score first, then highest confidence — is
    what supplies the headline and the URL, because a row has one of each.
    """
    ordered = sorted(drafts, key=lambda d: (d.raw_score, d.confidence),
                     reverse=True)
    lead = ordered[0]
    if len(ordered) == 1:
        return dataclasses.replace(
            lead, flags={**dict(lead.flags), "merged_count": 1,
                         "merged_items": [dict(lead.flags)]})
    return dataclasses.replace(
        lead,
        raw_score=float(sum(draft.raw_score for draft in ordered)),
        confidence=max(draft.confidence for draft in ordered),
        flags={**dict(lead.flags),
               "merged_count": len(ordered),
               "merged_items": [dict(draft.flags) for draft in ordered]})


def _bump(counter: dict, key: str, amount: int = 1) -> None:
    counter[key] = counter.get(key, 0) + amount


def run(*, egress: Optional[LlmEgress], store, registry,
        awaiting: Mapping[str, Sequence[ObservationDraft]], now: float,
        countries: Sequence[str] = (), tick_id: str = "") -> LlmStageReport:
    """One tick's extraction. Returns the report; raises only on a bug.

    S1-INGEST-010 governs the top of this function: a disabled or
    unreachable model returns a SUCCESSFUL no-op with a counted reason.
    Nothing here advances a circuit breaker and nothing here fails a
    sensor — a stopped Ollama is not a broken RSS feed, and opening the
    feed's breaker because the model is down would take the feed's own
    non-LLM output down with it.
    """
    candidates = collect(awaiting)
    considered = len(candidates)
    skipped: dict = {}
    by_adapter: dict = {}
    for candidate in candidates:
        row = by_adapter.setdefault(
            candidate.adapter_id,
            {"profile": candidate.adapter_id in SOURCES, "considered": 0,
             "submitted": 0, "written": 0})
        row["considered"] += 1

    if egress is None:
        report = unwired()
        return dataclasses.replace(
            report, articles_considered=considered,
            skipped={NOT_WIRED: considered} if considered else {},
            by_adapter=by_adapter)

    if not egress.enabled:
        return LlmStageReport(
            enabled=False, available=False, reason=llm_module.DISABLED,
            model_id=egress.model_id, articles_considered=considered,
            budget=int(egress.articles_per_tick),
            skipped={llm_module.DISABLED: considered} if considered else {},
            by_adapter=by_adapter)

    if not candidates:
        # No probe. Asking whether the model is up in a cycle with nothing
        # to ask it is a request that can only produce a misleading number.
        return LlmStageReport(
            enabled=True, available=False, reason=NO_CANDIDATE,
            model_id=egress.model_id, budget=int(egress.articles_per_tick),
            by_adapter=by_adapter)

    availability = llm_module.probe(
        client=egress.client, endpoint=egress.endpoint,
        model_id=egress.model_id, now=now) if not egress.replay_only \
        else llm_module.Availability(True, "")
    if not availability.available:
        return LlmStageReport(
            enabled=True, available=False, reason=availability.reason,
            model_id=egress.model_id, articles_considered=considered,
            budget=int(egress.articles_per_tick),
            skipped={availability.reason: considered},
            by_adapter=by_adapter)

    # Drop the families with no profile and the duplicates BEFORE the
    # budget is spent: a budget consumed by an article that could never
    # have reached a model is a budget that silently shrank.
    eligible: list[Candidate] = []
    seen: set = set()
    for candidate in candidates:
        source = SOURCES.get(candidate.adapter_id)
        if source is None:
            _bump(skipped, NO_PROFILE)
            continue
        if candidate.dedup_key in seen:
            _bump(skipped, DUPLICATE)
            continue
        seen.add(candidate.dedup_key)
        if not source.profile.prefilter(candidate.article):
            _bump(skipped, PREFILTERED)
            continue
        eligible.append(candidate)

    accepted, deferred = _round_robin(eligible,
                                      budget=int(egress.articles_per_tick))
    if deferred:
        _bump(skipped, OVER_BUDGET, len(deferred))

    submitted = succeeded = failed = 0
    drops: dict = {}
    errors: dict = {}
    per_country: dict = {}
    for candidate in accepted:
        source = SOURCES[candidate.adapter_id]
        system, user = source.profile.prompt(
            candidate.article,
            _context(candidate, now=now, countries=countries))
        request = llm_module.LlmRequest(
            prompt=user, system=system, model_id=egress.model_id,
            max_tokens=int(source.profile.max_tokens))
        submitted += 1
        by_adapter[candidate.adapter_id]["submitted"] += 1
        result = llm_module.submit(
            request, client=egress.client, store=store,
            adapter_id=candidate.adapter_id, now=now,
            endpoint=egress.endpoint, available=True,
            replay_only=egress.replay_only)
        if not result.ok:
            failed += 1
            _bump(errors, result.error or "unknown")
            continue
        succeeded += 1
        for answer in ex.explode(source.profile, result.data):
            primary = ex.primary_country(answer)
            try:
                item, reason = ex.build_item(
                    source.profile, answer, candidate.article, now=now,
                    # scope is EMPTY on purpose. `hacktivist_news`'s prompt
                    # tells the model to return an out-of-list country
                    # because "the system will handle filtering", and A9 is
                    # the record of the system NOT handling it — the
                    # discard was abolished. A country outside every
                    # scenario contributes nothing to any score anyway, so
                    # filtering here would buy nothing and could only lose
                    # a detection (NP1).
                    scope=(),
                    source_id=candidate.feed or source.profile.source_type,
                    headline_fallback=source.fallback_for(candidate.article,
                                                          answer, primary))
            except DomainError:
                # The DOMAIN's own refusal on external data, counted and
                # survived. Only DomainError: a TypeError here would be a
                # bug in this stage, and swallowing it would hide the bug
                # behind a drop count.
                _bump(drops, EXTRACTION_REFUSED)
                continue
            if item is None:
                _bump(drops, reason or "unknown")
                continue
            draft = item.as_draft()
            per_country.setdefault(
                (candidate.adapter_id, draft.country), []).append(
                    dataclasses.replace(draft, flags={
                        **dict(draft.flags),
                        # NP6 / S5-VERIF-022: the exchange this row came
                        # from, findable by the hash the recording is keyed
                        # on. A conclusion whose prompt cannot be located
                        # is a conclusion nobody can replay, and E-08 is
                        # the record of production storing only a version
                        # string and losing exactly this.
                        "prompt_sha256": result.recorded_sha256,
                        "llm_model": egress.model_id,
                        "llm_replayed": bool(result.replayed),
                        "source_feed": candidate.feed,
                    }))

    written = 0
    if per_country:
        with store.transaction() as conn:
            for (adapter_id, _country), drafts in sorted(
                    per_country.items()):
                adapter = registry.get(AdapterId(adapter_id))
                count = append_drafts(store, adapter, (_merge(drafts),),
                                      tick_id=tick_id, now=now,
                                      connection=conn)
                written += count
                by_adapter[adapter_id]["written"] += count

    return LlmStageReport(
        enabled=True, available=True, reason="", model_id=egress.model_id,
        articles_considered=considered, articles_accepted=len(accepted),
        submitted=submitted, succeeded=succeeded, failed=failed,
        items_built=sum(len(rows) for rows in per_country.values()),
        observations_written=written, budget=int(egress.articles_per_tick),
        skipped=skipped, drops=drops, errors=errors, by_adapter=by_adapter)


__all__ = ["run", "collect", "unwired", "LlmEgress", "LlmStageReport",
           "Candidate", "IntelSource", "SOURCES", "UNPROFILED",
           "AWAITING", "LLM_ARTICLES_PER_TICK", "NOT_WIRED", "NO_PROFILE",
           "PREFILTERED", "OVER_BUDGET", "DUPLICATE", "NO_CANDIDATE",
           "EXTRACTION_REFUSED"]
