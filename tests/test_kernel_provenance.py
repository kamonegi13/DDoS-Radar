"""WP-2.1 K kernel — Provenance (NP6, E-08).

NP6 requires that every conclusion be traceable to the formula, the
effective thresholds, the primary sources and the LLM prompt that produced
it. The diagnosis found that disclosure bolted on afterwards is disclosure
that goes missing: E-08 is prompts that were never recorded, and the
conclusion envelope had no slot that would have forced the question.

The type is built now so that L3 (WP-3.1) can make conclusions
unconstructible without one. Immutable, so a provenance record cannot be
edited after the conclusion it justifies has shipped.
"""
import pytest

from v3.kernel import Provenance
from v3.kernel.errors import DomainError


def _provenance(**overrides):
    payload = {
        "formula_ref": "S1-SCORING-007",
        "inputs": {"jam_ratio": 0.08, "threshold": 0.03},
        "source_refs": ("gpsjam.org/2026-08-05",),
        "computed_at": 1_786_000_000.0,
    }
    payload.update(overrides)
    return Provenance(**payload)


class TestConstruction:
    def test_a_complete_record_builds(self):
        record = _provenance()
        assert record.formula_ref == "S1-SCORING-007"
        assert record.computed_at == 1_786_000_000.0

    @pytest.mark.parametrize("formula_ref", ["", "   ", None])
    def test_a_missing_formula_reference_raises(self, formula_ref):
        with pytest.raises(DomainError) as exc:
            _provenance(formula_ref=formula_ref)
        assert "formula_ref" in str(exc.value)

    @pytest.mark.parametrize("computed_at", [0, -1, None, "now"])
    def test_a_missing_or_invalid_timestamp_raises(self, computed_at):
        with pytest.raises(DomainError):
            _provenance(computed_at=computed_at)

    def test_non_string_source_refs_raise(self):
        with pytest.raises(DomainError):
            _provenance(source_refs=(42,))

    def test_empty_source_ref_strings_raise(self):
        with pytest.raises(DomainError):
            _provenance(source_refs=("",))

    def test_non_string_input_keys_raise(self):
        with pytest.raises(DomainError):
            _provenance(inputs={1: "x"})

    def test_source_refs_accepts_any_sequence(self):
        record = _provenance(source_refs=["a", "b"])
        assert record.source_refs == ("a", "b")

    def test_no_sources_is_allowed_but_visible(self):
        # A derived quantity may genuinely have no primary source; the
        # emptiness must be explicit rather than absent.
        record = _provenance(source_refs=())
        assert record.source_refs == ()
        assert record.has_sources is False


class TestImmutability:
    def test_fields_cannot_be_reassigned(self):
        with pytest.raises(Exception):
            _provenance().formula_ref = "something else"

    def test_inputs_cannot_be_mutated_through_the_accessor(self):
        # A read-only view, not a copy: silently editing a throwaway copy
        # would still read like it worked at the call site.
        record = _provenance()
        with pytest.raises(TypeError):
            record.inputs["jam_ratio"] = 999
        assert record.inputs["jam_ratio"] == 0.08

    def test_mutating_the_source_dict_afterwards_does_not_leak_in(self):
        payload = {"a": 1}
        record = _provenance(inputs=payload)
        payload["a"] = 2
        assert record.inputs["a"] == 1

    def test_source_refs_are_a_tuple(self):
        assert isinstance(_provenance().source_refs, tuple)

    def test_has_no_dict(self):
        assert not hasattr(_provenance(), "__dict__")

    def test_is_hashable(self):
        assert len({_provenance(), _provenance()}) == 1


class TestDerivation:
    def test_with_input_returns_a_new_record(self):
        original = _provenance()
        extended = original.with_input("baseline", 0.01)
        assert extended is not original
        assert "baseline" not in original.inputs
        assert extended.inputs["baseline"] == 0.01

    def test_with_input_preserves_everything_else(self):
        original = _provenance()
        extended = original.with_input("baseline", 0.01)
        assert extended.formula_ref == original.formula_ref
        assert extended.source_refs == original.source_refs

    def test_with_source_returns_a_new_record(self):
        original = _provenance()
        extended = original.with_source("rss://example/feed")
        assert original.source_refs == ("gpsjam.org/2026-08-05",)
        assert "rss://example/feed" in extended.source_refs

    def test_with_source_rejects_an_empty_reference(self):
        with pytest.raises(DomainError):
            _provenance().with_source("")


class TestSerialization:
    def test_as_dict_round_trips_the_disclosure(self):
        record = _provenance()
        payload = record.as_dict()
        assert payload["formula_ref"] == "S1-SCORING-007"
        assert payload["inputs"]["threshold"] == 0.03
        assert payload["source_refs"] == ["gpsjam.org/2026-08-05"]

    def test_as_dict_is_json_serializable(self):
        import json
        json.dumps(_provenance().as_dict())

    def test_as_dict_is_a_copy(self):
        record = _provenance()
        record.as_dict()["formula_ref"] = "tampered"
        assert record.formula_ref == "S1-SCORING-007"


class TestHistoricalDefect:
    """E-08: the prompt that was never recorded."""

    def test_an_llm_prompt_reference_has_a_home(self):
        record = _provenance(
            formula_ref="S1-INTEL-021",
            inputs={"model": "qwen2.5:14b", "temperature": 0.2},
            source_refs=("prompt://intel_extract/v7",
                         "https://example.test/article"))
        assert "prompt://intel_extract/v7" in record.source_refs
        assert record.inputs["model"] == "qwen2.5:14b"

    def test_disclosure_cannot_be_added_after_the_fact(self):
        # The record is frozen: a conclusion shipped without a source
        # cannot have one quietly appended to the same object later.
        record = _provenance(source_refs=())
        with pytest.raises(Exception):
            record.source_refs = ("invented afterwards",)
        # Deriving a NEW record is allowed and leaves the original intact.
        assert record.with_source("added later").source_refs != record.source_refs


class TestRepresentation:
    def test_str_summarises_without_raising(self):
        text = str(_provenance())
        assert "S1-SCORING-007" in text
        assert "2 inputs" in text
        assert "1 sources" in text

    def test_str_works_with_no_inputs_or_sources(self):
        assert str(_provenance(inputs={}, source_refs=())) is not None


class TestInputsAreJsonPrimitives:
    """Nested mutables were a live hole: values were stored by reference,
    so `record.inputs["k"]["nested"] = ...` edited a shipped disclosure
    while equality and hash — computed once at construction — kept the old
    answer. Restricting values to JSON primitives closes it at the source
    and matches what as_dict()/json.dumps already promise."""

    @pytest.mark.parametrize("value", [1, 2.5, "text", True, False, None])
    def test_json_primitives_are_accepted(self, value):
        assert _provenance(inputs={"k": value}).inputs["k"] == value

    @pytest.mark.parametrize("value", [
        {"nested": 1}, [1, 2], (1, 2), {1, 2}, object(),
    ])
    def test_structured_values_are_refused(self, value):
        with pytest.raises(DomainError) as exc:
            _provenance(inputs={"k": value})
        assert "serialize" in str(exc.value) or "primitive" in str(exc.value)

    def test_the_tamper_path_is_now_unreachable(self):
        # The reviewer's repro, verbatim in shape.
        payload = {"thresholds": {"jam": 0.03}}
        with pytest.raises(DomainError):
            _provenance(inputs=payload)

    def test_a_caller_can_still_disclose_structure_by_serializing(self):
        import json
        record = _provenance(inputs={"thresholds": json.dumps({"jam": 0.03})})
        assert json.loads(record.inputs["thresholds"]) == {"jam": 0.03}

    def test_with_input_validates_too(self):
        with pytest.raises(DomainError):
            _provenance().with_input("nested", {"a": 1})

    def test_equality_cannot_drift_from_the_reported_inputs(self):
        first = _provenance(inputs={"a": 1})
        second = _provenance(inputs={"a": 1})
        assert first == second and hash(first) == hash(second)
        assert first.inputs == second.inputs
