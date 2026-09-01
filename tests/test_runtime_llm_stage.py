"""The LLM extraction stage — the production caller `v3/fetch/llm.py` lacked.

`v3/api/registry.py`'s C12 records the measurement this suite answers:
`v3/fetch/llm.py::submit` had ZERO production call sites, so the `llm_call`
ledger had never held a row and four adapters' selected articles sat
forever behind `flags["awaiting"] = "llm_extraction"`. The submission
mouth, the extraction surface and the four adapters' LLM halves all
existed; nothing walked between them.

What is pinned here:

  * a disabled or unreachable model is a NO-OP SUCCESS with a COUNTED
    reason (S1-INGEST-010 / G-17) — never a silent tick and never a
    sensor failure;
  * the per-tick article budget bites, and it is spent round-robin so one
    chatty adapter cannot starve the others (NP1);
  * exactly one `submit` per accepted article, and the recording that
    S5-VERIF-022 replays travels onto the observation (NP6);
  * the tick writes the resulting `llm_intel` rows through the SAME append
    seam the runner uses, before scoring, so an extracted item counts in
    the tick that extracted it.

No test here touches a socket or a real Ollama: the transport is a fake
that answers from a script (§6-1).
"""
import json

import pytest

from v3.adapters.types import (AdapterId, INFO, ObservationDraft,
                               RequestSpec, SourceAdapter, STATUS_OBSERVED,
                               STATUS_FIRED)
from v3.fetch import llm as llm_module
from v3.fetch.registry import AdapterRegistry
from v3.kernel.window import Window
from v3.ledger.store import LedgerStore
from v3.runtime import llm_stage

NOW = 1_800_000_000.0
ENDPOINT = "http://127.0.0.1:11434"
MODEL = "llama3.2:3b"


# ── fakes ────────────────────────────────────────────────────────────────

class _Payload:
    def __init__(self, envelope, url=""):
        self._envelope = envelope
        self.url = url
        self.body = b"{}"
        self.status = 200
        self.content_type = "application/json"

    def json(self):
        return self._envelope


class _Outcome:
    def __init__(self, outcome, payload=None):
        self.outcome = outcome
        self.payload = payload
        self.succeeded = outcome == "ok"


class _LlmClient:
    """Answers `/api/tags` from a roster and `/api/generate` from a script.

    Records every spec, so "one submit per accepted article" is a count
    this suite can read rather than a claim it has to trust.
    """

    def __init__(self, answers=None, *, models=(MODEL,), tags_outcome="ok",
                 generate_outcome="ok"):
        self._answers = list(answers or [])
        self._models = list(models)
        self._tags_outcome = tags_outcome
        self._generate_outcome = generate_outcome
        self.specs = []
        self.generate_specs = []
        self.tags_specs = []

    def fetch(self, spec, *, now, **kwargs):
        self.specs.append(spec)
        if spec.url.endswith(llm_module.TAGS_PATH):
            self.tags_specs.append(spec)
            return _Outcome(self._tags_outcome, _Payload(
                {"models": [{"name": name} for name in self._models]}))
        self.generate_specs.append(spec)
        if self._generate_outcome != "ok":
            return _Outcome(self._generate_outcome)
        answer = self._answers.pop(0) if self._answers else _answer()
        text = answer if isinstance(answer, str) else json.dumps(answer)
        return _Outcome("ok", _Payload({"response": text}))

    def pause(self, seconds):
        pass


def _answer(**over) -> dict:
    """A diplomatic-shaped answer the shared validator accepts."""
    fields = {"headline": "MOFA warns over strait transit",
              "escalation_signal": True,
              "geographic_focus": "Taiwan Strait",
              "theater": "TW",
              "countries": ["TW", "CN"],
              "country_weights": {"TW": 1.0, "CN": 0.6},
              "theater_link": "direct",
              "diplomatic_action": "warning",
              "target_country": "CN",
              "urgency": "high",
              "confidence": 0.8}
    fields.update(over)
    return fields


def _article(title="MOFA statement on strait transit", **over) -> dict:
    fields = {"title": title,
              "summary": "The ministry issued a statement.",
              "link": f"https://example.test/{abs(hash(title)) % 9973}",
              "published": "Mon, 01 Jan 2024 00:00:00 GMT",
              "country": "JP",
              "theaters": ["TW", "JP"],
              "dedup_key": f"diplomatic:{title}"}
    fields.update(over)
    return fields


def _folded(adapter_id: str, articles, *, signal_source="", awaiting=None):
    """The RAW per-article drafts the fold hook sees, one per article.

    Not the folded row: `v3/runtime/llm_stage.collect` reads the drafts
    BEFORE `fold_candidate_articles` flattens them, because the fold keeps
    the feed at row level and `source_id` needs it per article.
    """
    return tuple(
        ObservationDraft(
            signal_source=signal_source or adapter_id, domain=INFO,
            country="", status=STATUS_OBSERVED, raw_score=0.0,
            value=str(article.get("title", ""))[:200],
            flags={"feed": f"{adapter_id}_feed",
                   "article": article,
                   "awaiting": (llm_stage.AWAITING if awaiting is None
                                else awaiting)},
            evidence_url=article.get("link"))
        for article in articles)


def _adapter(name: str) -> SourceAdapter:
    return SourceAdapter(
        adapter_id=AdapterId(name), category=INFO,
        cadence=Window.from_days(1.0, cadence_sec=1.0),
        requests=(RequestSpec(url=f"https://{name}.test/x"),),
        normalize=lambda payload, context: (),
        freshness_horizon_sec=86400.0, rate_limit_group=name)


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "llm_stage.db"))
    yield instance
    instance.close()


@pytest.fixture
def registry():
    return AdapterRegistry((_adapter("diplomatic"),
                            _adapter("military_exercise"),
                            _adapter("hacktivist_news"),
                            _adapter("apt_intel")))


def _egress(client, *, enabled=True, budget=None) -> llm_stage.LlmEgress:
    return llm_stage.LlmEgress(
        client=client, endpoint=ENDPOINT, model_id=MODEL, enabled=enabled,
        articles_per_tick=(llm_stage.LLM_ARTICLES_PER_TICK if budget is None
                           else budget))


def _run(store, registry, awaiting, *, egress, countries=("TW", "CN"),
         tick_id="t1"):
    return llm_stage.run(egress=egress, store=store, registry=registry,
                         awaiting=awaiting, now=NOW, countries=countries,
                         tick_id=tick_id)


# ── the no-ops ───────────────────────────────────────────────────────────

class TestAStoppedModelIsNotABrokenSensor:
    """S1-INGEST-010: disabled or unavailable is a SUCCESS with a reason."""

    def test_a_disabled_model_asks_nothing_and_says_so(self, store, registry):
        client = _LlmClient()
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [_article()])},
                      egress=_egress(client, enabled=False))
        assert client.specs == []
        assert report.enabled is False
        assert report.reason == llm_module.DISABLED
        assert report.skipped[llm_module.DISABLED] == 1
        assert report.submitted == 0

    def test_an_unreachable_model_counts_what_it_did_not_ask(self, store,
                                                             registry):
        client = _LlmClient(tags_outcome="timeout")
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic",
                                              [_article("a"),
                                               _article("b")])},
                      egress=_egress(client))
        assert client.generate_specs == []
        assert report.available is False
        assert report.reason == llm_module.UNAVAILABLE
        assert report.as_dict()["skipped_unavailable"] == 2

    def test_a_model_the_server_does_not_hold_is_named_separately(
            self, store, registry):
        """v1 folds "host down" and "model absent" into one `False`
        (`radar/llm_client.py:427-441`). They point at different repairs —
        start Ollama, or pull the model — so they are counted apart."""
        client = _LlmClient(models=("some-other-model:7b",))
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [_article()])},
                      egress=_egress(client))
        assert client.generate_specs == []
        assert report.reason == llm_module.MODEL_ABSENT

    def test_nothing_awaiting_still_produces_a_report(self, store, registry):
        """S1-INGEST-020: a silent cycle names its silence. No probe is
        spent either — asking whether the model is up in a cycle with
        nothing to ask it can only produce a misleading number."""
        client = _LlmClient()
        report = _run(store, registry, {}, egress=_egress(client))
        assert report.articles_considered == 0
        assert report.observations_written == 0
        assert report.reason == llm_stage.NO_CANDIDATE
        assert client.specs == []

    def test_a_refused_answer_does_not_take_the_tick_down(self, store,
                                                          registry,
                                                          monkeypatch):
        """The answer is EXTERNAL data. A domain refusal on it is counted
        and survived; a tick that dies here would stop scoring every other
        sensor too (NP3)."""
        import dataclasses

        from v3.adapters.llm import diplomatic as source
        from v3.kernel.errors import DomainError

        def _refuse(data):
            raise DomainError("the answer violated an invariant")

        monkeypatch.setattr(llm_stage, "SOURCES", {
            "diplomatic": llm_stage.IntelSource(
                dataclasses.replace(source.PROFILE, score_delta=_refuse))})
        client = _LlmClient()
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [_article()])},
                      egress=_egress(client))
        assert report.observations_written == 0
        assert report.drops[llm_stage.EXTRACTION_REFUSED] == 1
        assert report.succeeded == 1        # the exchange itself was fine

    def test_an_unwired_stage_reports_rather_than_vanishes(self):
        """G-17: `llm=None` is a fact about the deployment, not a silence."""
        report = llm_stage.unwired()
        assert report.enabled is False
        assert report.reason == llm_stage.NOT_WIRED
        assert report.as_dict()["reason"] == llm_stage.NOT_WIRED


# ── the budget ───────────────────────────────────────────────────────────

class TestTheBudget:
    def test_the_cap_bounds_the_calls(self, store, registry):
        client = _LlmClient()
        articles = [_article(f"item {n}") for n in range(9)]
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", articles)},
                      egress=_egress(client, budget=3))
        assert len(client.generate_specs) == 3
        assert report.submitted == 3
        assert report.skipped[llm_stage.OVER_BUDGET] == 6

    def test_the_budget_is_spent_round_robin_across_adapters(self, store,
                                                             registry):
        """NP1: a source with eleven feeds must not consume the whole
        budget and leave a source with one feed unheard."""
        client = _LlmClient()
        report = _run(
            store, registry,
            {"diplomatic": _folded("diplomatic",
                                    [_article(f"d{n}") for n in range(5)]),
             "military_exercise": _folded("military_exercise",
                                           [_article("m0")])},
            egress=_egress(client, budget=2))
        assert report.by_adapter["diplomatic"]["submitted"] == 1
        assert report.by_adapter["military_exercise"]["submitted"] == 1

    def test_the_declared_cap_is_small_enough_to_state(self):
        """The worst case is stated in the module, so a reviewer can price
        it: cap x LLM_TIMEOUT is added to a tick whose default interval is
        60s."""
        assert 1 <= llm_stage.LLM_ARTICLES_PER_TICK <= 8


# ── one submit per accepted article ──────────────────────────────────────

class TestOneSubmitPerAcceptedArticle:
    def test_each_accepted_article_is_asked_once(self, store, registry):
        client = _LlmClient()
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic",
                                              [_article("a"),
                                               _article("b")])},
                      egress=_egress(client))
        assert len(client.generate_specs) == 2
        assert report.articles_considered == 2
        assert report.submitted == 2

    def test_the_prefilter_spends_no_call(self, store, registry):
        """Slot 1. An article with no text cannot answer anything and
        still costs a call."""
        client = _LlmClient()
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic",
                                              [_article(title="",
                                                        summary="")])},
                      egress=_egress(client))
        assert client.generate_specs == []
        assert report.skipped[llm_stage.PREFILTERED] == 1

    def test_one_article_is_asked_once_however_many_feeds_carried_it(
            self, store, registry):
        client = _LlmClient()
        same = _article("identical headline")
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [same,
                                                             dict(same)])},
                      egress=_egress(client))
        assert len(client.generate_specs) == 1
        assert report.skipped[llm_stage.DUPLICATE] == 1

    def test_an_adapter_without_a_profile_is_counted_never_dropped(
            self, store, registry):
        """`apt_intel` declares no `IntelProfile` (its own module says so).
        Its articles must not disappear into a stage that answered for
        three of the four families and looked complete."""
        client = _LlmClient()
        report = _run(store, registry,
                      {"apt_intel": _folded("apt_intel", [_article("cve")],
                                             awaiting="llm_extraction "
                                                      "(WP-2.7)")},
                      egress=_egress(client))
        assert client.generate_specs == []
        assert report.skipped[llm_stage.NO_PROFILE] == 1
        assert report.by_adapter["apt_intel"]["profile"] is False


# ── what lands in L1 ─────────────────────────────────────────────────────

class TestWhatLandsInL1:
    def test_an_accepted_answer_becomes_an_llm_intel_observation(
            self, store, registry):
        client = _LlmClient()
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [_article()])},
                      egress=_egress(client))
        assert report.observations_written == 1
        row = store.latest_signal_at(NOW, sensor="diplomatic", country="TW",
                                     signal_source="llm_intel")
        assert row is not None
        assert row["status"] == STATUS_FIRED
        assert row["raw_score"] > 0

    def test_the_recording_travels_onto_the_observation(self, store,
                                                        registry):
        """NP6 / S5-VERIF-022: a conclusion whose prompt cannot be found
        is a conclusion nobody can replay."""
        client = _LlmClient()
        _run(store, registry,
             {"diplomatic": _folded("diplomatic", [_article()])},
             egress=_egress(client))
        row = store.latest_signal_at(NOW, sensor="diplomatic", country="TW",
                                     signal_source="llm_intel")
        flags = json.loads(row["flags"])
        assert len(flags["prompt_sha256"]) == 64
        assert flags["llm_model"] == MODEL
        assert flags["origin"] == "llm_intel"

    def test_every_exchange_is_recorded_in_the_llm_call_ledger(self, store,
                                                              registry):
        client = _LlmClient()
        _run(store, registry,
             {"diplomatic": _folded("diplomatic", [_article("a"),
                                                    _article("b")])},
             egress=_egress(client))
        with store.transaction() as conn:
            rows = conn.execute("SELECT adapter_id, model_id FROM llm_call"
                                ).fetchall()
        assert len(rows) == 2
        assert {row[0] for row in rows} == {"diplomatic"}
        assert {row[1] for row in rows} == {MODEL}

    def test_two_items_for_one_country_are_added_not_dropped(self, store,
                                                             registry):
        """L1 is UNIQUE on (tick_id, sensor, signal_source, country), so a
        second item for TW would raise. S1-INGEST-018 composes additively;
        keeping only the larger would discard evidence, which is the
        direction NP1 forbids."""
        client = _LlmClient(answers=[_answer(urgency="high"),
                                     _answer(urgency="low")])
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic",
                                              [_article("a"),
                                               _article("b")])},
                      egress=_egress(client))
        assert report.items_built == 2
        assert report.observations_written == 1
        row = store.latest_signal_at(NOW, sensor="diplomatic", country="TW",
                                     signal_source="llm_intel")
        flags = json.loads(row["flags"])
        assert flags["merged_count"] == 2
        assert row["raw_score"] == pytest.approx(
            sum(item["score_delta_raw"] for item in flags["merged_items"]))

    def test_an_answer_below_the_floor_is_dropped_with_its_own_reason(
            self, store, registry):
        client = _LlmClient(answers=[_answer(confidence=0.1)])
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [_article()])},
                      egress=_egress(client))
        assert report.observations_written == 0
        assert report.drops["confidence_below_floor"] == 1

    def test_an_unparseable_answer_is_a_failure_not_an_item(self, store,
                                                            registry):
        client = _LlmClient(answers=["I am afraid I cannot do that"])
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [_article()])},
                      egress=_egress(client))
        assert report.failed == 1
        assert report.succeeded == 0
        assert report.observations_written == 0

    def test_a_transport_failure_does_not_take_the_tick_down(self, store,
                                                             registry):
        client = _LlmClient(generate_outcome="timeout")
        report = _run(store, registry,
                      {"diplomatic": _folded("diplomatic", [_article()])},
                      egress=_egress(client))
        assert report.failed == 1
        assert report.observations_written == 0
        assert report.errors["http_error:timeout"] == 1


# ── the tick ─────────────────────────────────────────────────────────────

GEO_DOC = {
    "COUNTRY_COORDS": {"TW": {"lat": 23.7, "lng": 121.0, "name": "Taiwan"}},
    "SCENARIOS": {"taiwan_contingency": {
        "participants": {"TW": {"weight": 1.0, "role": "primary_target"},
                         "CN": {"weight": 0.7, "role": "adversary"}}}},
}


class _FetchOutcome:
    def __init__(self, url):
        self.outcome, self.url, self.status = "ok", url, 200
        self.latency_ms, self.attempts, self.detail = 1.0, 1, ""
        self.body_sha256 = "0" * 64
        self.url_sha256 = "1" * 64
        self.payload = _Payload({}, url=url)
        self.succeeded = True


class _FetchClient:
    """The sensor egress. Separate from the LLM one, as in composition."""

    def fetch(self, spec, *, now, auth=None, **kwargs):
        return _FetchOutcome(spec.url)

    def pause(self, seconds):
        pass


def _diplomatic_adapter(articles):
    """The real fold, reached through the real reduce table.

    `normalize` returns the per-article rows `v3/adapters/llm/diplomatic
    .py::normalize` returns; the fold that collapses them is the one
    `v3/runtime/reduce.py` declares for the name `diplomatic`. Collecting
    from anything else would be testing a shape this suite invented.
    """
    from v3.adapters.llm import diplomatic as source

    drafts = tuple(
        ObservationDraft(
            signal_source=source.SIGNAL_SOURCE, domain=source.SENSOR_DOMAIN,
            country="", status=STATUS_OBSERVED, raw_score=0.0,
            value=article["title"][:200],
            flags={"feed": "mofa_jp", "article": article,
                   "selection_slot": "keyword_or_theater",
                   "awaiting": "llm_extraction",
                   "item_domain": source.ITEM_DOMAIN},
            evidence_url=article["link"])
        for article in articles)
    base = _adapter("diplomatic")
    import dataclasses
    return dataclasses.replace(
        base, normalize=lambda payload, context, _d=drafts: _d)


def _run_tick(store, egress):
    from v3.runtime import geo as geo_module
    from v3.runtime import tick as tick_module

    return tick_module.run_tick(
        now=NOW, registry=AdapterRegistry([_diplomatic_adapter(
            [_article("MOFA statement on strait transit")])]),
        store=store, client=_FetchClient(),
        geography=geo_module.from_document(GEO_DOC),
        scenario_ids=("taiwan_contingency",), llm=egress)


class TestTheTickWiresIt:
    def test_run_tick_produces_an_llm_call_row_and_an_observation(
            self, tmp_path):
        """The end this whole WP exists for: a tick that walks the path."""
        store = LedgerStore(str(tmp_path / "tick.db"))
        try:
            report = _run_tick(store, _egress(_LlmClient()))
            assert report.llm["submitted"] == 1
            assert report.llm["observations_written"] == 1
            with store.transaction() as conn:
                assert conn.execute(
                    "SELECT COUNT(*) FROM llm_call").fetchone()[0] == 1
                assert conn.execute(
                    "SELECT COUNT(*) FROM signal_observation "
                    "WHERE signal_source = 'llm_intel'").fetchone()[0] == 1
        finally:
            store.close()

    def test_a_tick_without_an_egress_still_discloses_the_stage(self,
                                                                tmp_path):
        store = LedgerStore(str(tmp_path / "tick2.db"))
        try:
            report = _run_tick(store, None)
            assert report.llm["reason"] == llm_stage.NOT_WIRED
            assert "llm" in report.as_dict()
        finally:
            store.close()

    def test_the_intel_row_is_counted_in_the_ticks_own_total(self, tmp_path):
        """`observations_written` is what an operator reads to decide the
        tick did something. An extracted item that landed in L1 but not in
        that number would be a row the tick wrote and did not admit to."""
        store = LedgerStore(str(tmp_path / "tick3.db"))
        try:
            with_model = _run_tick(store, _egress(_LlmClient()))
        finally:
            store.close()
        other = LedgerStore(str(tmp_path / "tick4.db"))
        try:
            without = _run_tick(other, None)
        finally:
            other.close()
        assert with_model.observations_written == \
            without.observations_written + 1


# ── the composition root ─────────────────────────────────────────────────

class TestTheRootBuildsASecondEgress:
    """Ruling 3: the model gets its own client, and the sensors' is
    untouched. One shared client would have to hold either a 30s timeout
    (wrong for a public API) or a retry ladder (wrong for a serial GPU
    queue)."""

    def _settings(self, tmp_path, **over):
        from v3.server import settings as settings_module

        fields = {"ledger_path": str(tmp_path / "v3.db")}
        fields.update(over)
        return settings_module.ServerSettings(**fields)

    def test_the_llm_client_does_not_retry(self, tmp_path):
        from v3.server import composition

        egress = composition._llm_egress(self._settings(tmp_path))
        try:
            assert egress.client._max_attempts == 1
            assert egress.client.timeout == (
                llm_module.AVAILABILITY_TIMEOUT_SEC, 30.0)
        finally:
            egress.client.close()

    def test_a_disabled_deployment_builds_no_second_egress(self, tmp_path):
        from v3.server import composition

        assert composition._llm_egress(
            self._settings(tmp_path, llm_enabled=False)) is None

    def test_the_environment_names_are_v1s_so_the_shadow_inherits_them(self):
        """`docker-compose.yml`'s `v3_shadow` already reads `config.env`
        through `env_file`. Reading the same names is what makes the shadow
        ask the SAME model as production; a `NOROSHI_V3_` alias would be a
        second value to keep in step."""
        from v3.server import settings as settings_module

        for key in ("LLM_ENABLED", "LLM_HOST", "LLM_MODEL", "LLM_TIMEOUT"):
            assert key in settings_module.KEY_IDS
            assert any(row["key"] == key
                       for row in settings_module.describe())

    def test_the_settings_resolve_from_a_snapshot(self, tmp_path):
        from v3.server import settings as settings_module

        resolved = settings_module.from_environment({
            "NOROSHI_V3_LEDGER_PATH": str(tmp_path / "v3.db"),
            "LLM_HOST": "http://host.docker.internal:11434",
            "LLM_MODEL": "gemma4:26b", "LLM_TIMEOUT": "45"})
        assert resolved.llm_enabled is True
        assert resolved.llm_model == "gemma4:26b"
        assert resolved.llm_timeout_sec == 45.0

    def test_an_enabled_stage_without_a_host_is_refused(self, tmp_path):
        from v3.kernel.errors import DomainError
        from v3.server import settings as settings_module

        with pytest.raises(DomainError):
            settings_module.ServerSettings(
                ledger_path=str(tmp_path / "v3.db"), llm_host="")
