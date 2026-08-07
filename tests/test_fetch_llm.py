"""WP-2.7 — the ONE LLM submission path (P6 O-17, design sheet §4-1).

Production has eight copies of this skeleton (A-02). These tests pin the
single replacement: the request body Ollama actually reads, the tolerant
parse, the availability no-op, and — the clause this WP exists to make
possible — that every exchange is recorded well enough to replay
(S5-VERIF-022).

Values are transcribed from `radar/llm_client.py`, verified by parsing
that file with `ast` rather than by reading it, because the WP-2.6 sweep
found 97 infidelities in values that all looked correctly transcribed.
The AST check lives in `TestTheProductionValuesAreWhatWeTranscribed` and
runs against the live source, so a production change fails this suite
instead of drifting past it.
"""
import ast
import json
import pathlib

import pytest

from v3.fetch import llm, recorder
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
LLM_CLIENT = REPO_ROOT / "radar" / "llm_client.py"
NOW = 1_700_000_000.0
ENDPOINT = "http://127.0.0.1:11434"


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "v3.db"))
    yield instance
    instance.close()


def request(**over) -> llm.LlmRequest:
    fields = {"prompt": "analyse this statement", "system": "you are an analyst",
              "model_id": "llama3.2:3b"}
    fields.update(over)
    return llm.LlmRequest(**fields)


class _Payload:
    """Just enough of `FetchedPayload` for the parse path."""

    def __init__(self, envelope):
        self._envelope = envelope

    def json(self):
        if isinstance(self._envelope, Exception):
            raise self._envelope
        return self._envelope


class _Outcome:
    def __init__(self, outcome, payload=None):
        self.outcome = outcome
        self.payload = payload


class _Client:
    """Records the spec it was handed; issues nothing."""

    def __init__(self, outcome):
        self._outcome = outcome
        self.specs = []

    def fetch(self, spec, *, now, **kwargs):
        self.specs.append(spec)
        return self._outcome


def _ok_client(answer: str):
    return _Client(_Outcome("ok", _Payload({"response": answer})))


# ── the request body ─────────────────────────────────────────────────────

class TestTheRequestBody:
    def test_the_token_budget_is_sent_as_num_predict(self):
        """`max_tokens` is accepted and IGNORED by Ollama. The body key is
        `num_predict` (radar/llm_client.py:447); sending the wrong one
        truncates at the server default and reads as a terse model."""
        body = request(max_tokens=300).body()
        assert body["options"]["num_predict"] == 300
        assert "max_tokens" not in body["options"]

    def test_the_body_is_the_production_shape(self):
        body = request().body()
        assert body["model"] == "llama3.2:3b"
        assert body["stream"] is False
        assert body["format"] == "json"
        assert body["system"] == "you are an analyst"
        assert body["options"]["temperature"] == llm.DEFAULT_TEMPERATURE

    def test_an_empty_system_prompt_is_absent_rather_than_empty(self):
        """Production assigns `payload['system']` only when truthy
        (llm_client.py:593); an empty key is a different request."""
        assert "system" not in request(system="").body()

    def test_the_url_is_the_generate_endpoint(self):
        spec = request().spec(endpoint=ENDPOINT + "/")
        assert spec.url == "http://127.0.0.1:11434/api/generate"
        assert spec.method == "POST"
        assert spec.body_content_type == "application/json"

    def test_the_endpoint_is_supplied_never_read_from_the_environment(self):
        with pytest.raises(DomainError):
            request().spec(endpoint="")

    def test_a_request_without_a_model_is_refused(self):
        """S5-VERIF-022 replays by prompt AND model."""
        with pytest.raises(DomainError):
            llm.LlmRequest(prompt="x", model_id="")

    def test_a_zero_token_budget_is_refused(self):
        with pytest.raises(DomainError):
            request(max_tokens=0)


# ── the tolerant parse ───────────────────────────────────────────────────

class TestTheTolerantParse:
    def test_plain_json_parses(self):
        assert llm.parse_response('{"a": 1}') == (True, {"a": 1})

    def test_a_fenced_block_is_unwrapped(self):
        assert llm.parse_response('```json\n{"a": 1}\n```') == (True, {"a": 1})

    def test_prose_around_the_object_is_sliced_away(self):
        ok, data = llm.parse_response('Sure!\n{"a": 1}\nHope that helps.')
        assert (ok, data) == (True, {"a": 1})

    def test_an_unparseable_answer_yields_no_fallback_value(self):
        """S1-INGEST-013 forbids continuing on a default."""
        assert llm.parse_response("no json here") == (False, {})

    def test_a_bare_list_is_not_an_object(self):
        assert llm.parse_response("[1, 2, 3]") == (False, {})

    def test_an_empty_answer_is_a_failure_not_an_empty_finding(self):
        assert llm.parse_response("   ") == (False, {})

    def test_the_parse_never_re_asks_the_model(self):
        """A retry would make one prompt produce two recordings, and
        S5-VERIF-022 keys replay on the prompt."""
        source = pathlib.Path(
            REPO_ROOT / "v3" / "fetch" / "llm.py").read_text()
        tree = ast.parse(source)
        parse = next(n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef)
                     and n.name == "parse_response")
        calls = {ast.unparse(n.func) for n in ast.walk(parse)
                 if isinstance(n, ast.Call)}
        assert not any("fetch" in name or "submit" in name for name in calls)


class TestTheOllamaEnvelope:
    def test_a_thinking_model_answering_in_thinking_is_still_heard(self):
        payload = _Payload({"response": "", "thinking": '{"a": 1}'})
        assert llm._response_text(payload) == '{"a": 1}'

    def test_a_broken_envelope_yields_no_text_rather_than_raising(self):
        assert llm._response_text(_Payload(ValueError("bad json"))) == ""


# ── availability, recording, replay ──────────────────────────────────────

class TestAvailability:
    def test_an_unavailable_model_is_a_no_op_not_a_failure(self, store):
        """S1-INGEST-010: a stopped LLM is not a broken sensor. Opening
        the sensor's breaker would take its non-LLM output down too."""
        client = _ok_client('{"a": 1}')
        result = llm.submit(request(), client=client, store=store,
                            adapter_id="diplomatic", now=NOW,
                            endpoint=ENDPOINT, available=False)
        assert result.ok is False
        assert result.error == llm.UNAVAILABLE
        assert client.specs == [], "no request may be issued"


class TestRecordingIsMandatory:
    """S5-VERIF-022's precondition, and the reason this WP exists."""

    def test_a_successful_exchange_is_recorded_in_full(self, store):
        result = llm.submit(request(), client=_ok_client('{"urgency": "high"}'),
                            store=store, adapter_id="diplomatic", now=NOW,
                            endpoint=ENDPOINT)
        assert result.ok is True
        row = recorder.recorded_response(store, "analyse this statement")
        assert row is not None
        assert row["prompt"] == "analyse this statement"
        assert row["response"] == '{"urgency": "high"}'
        assert row["model_id"] == "llama3.2:3b"
        assert row["temperature"] == pytest.approx(llm.DEFAULT_TEMPERATURE)
        assert row["adapter_id"] == "diplomatic"
        assert row["prompt_sha256"] == result.recorded_sha256

    def test_an_unparseable_answer_is_recorded_too(self, store):
        """The evidence for why a conclusion is absent. Recording only
        the answers we liked would make the ledger agree by construction."""
        result = llm.submit(request(), client=_ok_client("I cannot comply"),
                            store=store, adapter_id="diplomatic", now=NOW,
                            endpoint=ENDPOINT)
        assert result.ok is False and result.error == llm.PARSE_FAILED
        assert recorder.recorded_response(
            store, "analyse this statement")["response"] == "I cannot comply"

    def test_an_http_failure_records_no_exchange_and_says_so(self, store):
        client = _Client(_Outcome("timeout"))
        result = llm.submit(request(), client=client, store=store,
                            adapter_id="diplomatic", now=NOW,
                            endpoint=ENDPOINT)
        assert result.ok is False
        assert result.error == f"{llm.HTTP_ERROR}:timeout"
        assert recorder.recorded_response(store, "analyse this statement") is None

    def test_the_recording_happens_before_the_parse(self):
        """Parsed-first would let a parse bug delete the evidence of it."""
        source = pathlib.Path(REPO_ROOT / "v3" / "fetch" / "llm.py").read_text()
        tree = ast.parse(source)
        submit = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == "submit")
        record_line = min(n.lineno for n in ast.walk(submit)
                          if isinstance(n, ast.Call)
                          and ast.unparse(n.func).endswith("record_llm_call"))
        parse_line = min(n.lineno for n in ast.walk(submit)
                         if isinstance(n, ast.Call)
                         and ast.unparse(n.func).endswith("parse_response"))
        assert record_line < parse_line


class TestReplay:
    def test_a_recorded_exchange_replays_without_a_client(self, store):
        recorder.record_llm_call(store, "diplomatic",
                                 prompt="analyse this statement",
                                 response='{"urgency": "critical"}',
                                 model_id="llama3.2:3b", temperature=0.1,
                                 called_at=NOW)
        result = llm.submit(request(), client=None, store=store,
                            adapter_id="diplomatic", now=NOW,
                            endpoint=ENDPOINT, replay_only=True)
        assert result.replayed is True
        assert result.data["urgency"] == "critical"

    def test_a_missing_recording_is_reported_never_filled_by_a_model(self, store):
        """S5-VERIF-022: the conclusion type is then excluded from parity
        and the exclusion stated. A live call would make the numbers agree
        and the run unreproducible."""
        client = _ok_client('{"urgency": "low"}')
        result = llm.submit(request(), client=client, store=store,
                            adapter_id="diplomatic", now=NOW,
                            endpoint=ENDPOINT, replay_only=True)
        assert result.ok is False
        assert result.error == llm.REPLAY_MISSING
        assert client.specs == []


# ── the AST fidelity check, run against the live production source ───────

class TestTheProductionValuesAreWhatWeTranscribed:
    """WP-2.6's method, applied during the port rather than after it."""

    def _tree(self):
        return ast.parse(LLM_CLIENT.read_text(encoding="utf-8"))

    def _function(self, name):
        return next(n for n in ast.walk(self._tree())
                    if isinstance(n, ast.FunctionDef) and n.name == name)

    def test_the_shared_functions_defaults_are_our_defaults(self):
        node = self._function("llm_analyze_json")
        names = [a.arg for a in node.args.args]
        defaults = dict(zip(names[-len(node.args.defaults):],
                            [ast.literal_eval(d) for d in node.args.defaults]))
        assert defaults["temperature"] == llm.DEFAULT_TEMPERATURE
        assert defaults["max_tokens"] == llm.DEFAULT_MAX_TOKENS

    def test_the_options_key_is_still_num_predict(self):
        node = self._function("_build_options")
        keys = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Dict):
                keys |= {k.value for k in sub.keys
                         if isinstance(k, ast.Constant)}
            if isinstance(sub, ast.Subscript) and \
                    isinstance(sub.slice, ast.Constant):
                keys.add(sub.slice.value)
        assert llm.MAX_TOKENS_KEY in keys
        assert "max_tokens" not in keys

    def test_the_generate_path_is_still_api_generate(self):
        tree = self._tree()
        joined = [ast.unparse(n) for n in ast.walk(tree)
                  if isinstance(n, ast.JoinedStr)]
        assert any(llm.GENERATE_PATH in text for text in joined), \
            "radar/llm_client.py no longer builds a /api/generate URL"

    def test_the_body_is_still_a_non_streaming_json_request(self):
        node = self._function("llm_analyze_json")
        payload = next(n for n in ast.walk(node)
                       if isinstance(n, ast.AnnAssign)
                       and ast.unparse(n.target) == "payload")
        pairs = {k.value: ast.unparse(v)
                 for k, v in zip(payload.value.keys, payload.value.values)
                 if isinstance(k, ast.Constant)}
        assert pairs["stream"] == "False"
        assert pairs["format"] == "'json'"
        assert set(pairs) == {"model", "prompt", "stream", "format", "options"}
        ours = dict(request().body())
        ours.pop("system")
        assert set(ours) == set(pairs)
