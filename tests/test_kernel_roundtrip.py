"""WP-2.1 K kernel — serialization, copying, and re-validation.

Three properties that only matter once the kernel has consumers, which is
exactly why they are pinned before those consumers exist:

  * pickle / deepcopy round-trips. L1 will hand these types across process
    and cache boundaries; a type that silently fails to pickle would be
    discovered as a runtime error deep in a worker.
  * `dataclasses.replace()` re-runs validation. It bypasses the
    constructor call site but not `__post_init__`, and a type whose
    invariants held only on the first construction is not a type.
  * subclassing is refused, so no descendant can re-enable an operator
    the base deliberately removed.
"""
import copy
import dataclasses
import pickle

import pytest

from v3.kernel import (Evidence, Percentage, Provenance, Ratio, Threshold,
                       ThreatLevel, Window)
from v3.kernel.errors import DomainError

NOW = 1_786_000_000.0


def _samples():
    return [
        ThreatLevel(2),
        Ratio(0.08),
        Percentage(8.0),
        Window.from_days(30, cadence_sec=900),
        Threshold.pinned(0.03, unit="ratio", provenance_ref="S1-X"),
        Threshold.registry_backed("SOME_KEY", unit="ratio"),
        Provenance(formula_ref="S1-SCORING-007", computed_at=NOW,
                   inputs={"a": 1, "b": "two", "c": 3.5, "d": True, "e": None},
                   source_refs=("src://one",)),
        Evidence.observe({"k": 1}, observed_at=NOW,
                         freshness_horizon_sec=3600, source="probe"),
    ]


@pytest.mark.parametrize("original", _samples(),
                         ids=lambda o: type(o).__name__ + str(id(o))[-4:])
class TestRoundTrips:
    def test_pickle_round_trip(self, original):
        restored = pickle.loads(pickle.dumps(original))
        assert type(restored) is type(original)

    def test_deepcopy_round_trip(self, original):
        restored = copy.deepcopy(original)
        assert type(restored) is type(original)

    def test_shallow_copy_round_trip(self, original):
        assert type(copy.copy(original)) is type(original)


class TestRoundTripsPreserveValue:
    def test_threat_level(self):
        assert pickle.loads(pickle.dumps(ThreatLevel(2))) == ThreatLevel(2)

    def test_units(self):
        assert pickle.loads(pickle.dumps(Ratio(0.08))) == Ratio(0.08)
        assert pickle.loads(pickle.dumps(Percentage(8.0))) == Percentage(8.0)

    def test_window(self):
        window = Window.from_days(30, cadence_sec=900)
        assert pickle.loads(pickle.dumps(window)) == window

    def test_provenance(self):
        record = Provenance(formula_ref="S1-X", computed_at=NOW,
                            inputs={"a": 1}, source_refs=("s",))
        restored = pickle.loads(pickle.dumps(record))
        assert restored == record
        assert restored.inputs == {"a": 1}
        assert restored.source_refs == ("s",)

    def test_provenance_deepcopy_keeps_the_read_only_view(self):
        record = Provenance(formula_ref="S1-X", computed_at=NOW,
                            inputs={"a": 1})
        restored = copy.deepcopy(record)
        with pytest.raises(TypeError):
            restored.inputs["a"] = 2

    def test_evidence_payload_survives(self):
        evidence = Evidence.observe({"k": 1}, observed_at=NOW,
                                    freshness_horizon_sec=3600,
                                    source="probe")
        restored = pickle.loads(pickle.dumps(evidence))
        assert restored.fresh(now=NOW) == {"k": 1}

    def test_threshold_resolution_survives(self):
        threshold = Threshold.pinned(0.03, unit="ratio",
                                     provenance_ref="S1-X")
        restored = pickle.loads(pickle.dumps(threshold))
        assert restored.resolve().value == Ratio(0.03)


class TestReplaceReValidates:
    """`dataclasses.replace()` skips the factory but not __post_init__."""

    def test_threat_level(self):
        with pytest.raises(DomainError):
            dataclasses.replace(ThreatLevel(2), value=9)

    def test_ratio(self):
        with pytest.raises(DomainError):
            dataclasses.replace(Ratio(0.5), value=3.0)

    def test_percentage(self):
        with pytest.raises(DomainError):
            dataclasses.replace(Percentage(50.0), value=500.0)

    def test_window_days(self):
        with pytest.raises(DomainError):
            dataclasses.replace(Window.from_days(30, cadence_sec=900),
                                declared_days=0)

    def test_window_cadence(self):
        with pytest.raises(DomainError):
            dataclasses.replace(Window.from_days(30, cadence_sec=900),
                                cadence_sec=-1)

    def test_provenance_formula_ref(self):
        record = Provenance(formula_ref="S1-X", computed_at=NOW)
        with pytest.raises(DomainError):
            dataclasses.replace(record, formula_ref="")

    def test_provenance_inputs(self):
        record = Provenance(formula_ref="S1-X", computed_at=NOW)
        with pytest.raises(DomainError):
            dataclasses.replace(record, inputs={"nested": {"no": 1}})

    def test_evidence_horizon(self):
        evidence = Evidence.observe(1, observed_at=NOW,
                                    freshness_horizon_sec=60, source="p")
        with pytest.raises(DomainError):
            dataclasses.replace(evidence, freshness_horizon_sec=0)

    def test_threshold_unit(self):
        threshold = Threshold.pinned(0.03, unit="ratio",
                                     provenance_ref="S1-X")
        with pytest.raises(DomainError):
            dataclasses.replace(threshold, unit="furlongs")

    def test_a_valid_replace_still_works(self):
        assert dataclasses.replace(ThreatLevel(2), value=4) == ThreatLevel(4)


class TestSubclassingIsRefused:
    """A descendant must not be able to re-enable a removed operator."""

    def test_threat_level_is_final(self):
        with pytest.raises(TypeError) as exc:
            class EvilTL(ThreatLevel):
                def __lt__(self, other):
                    return self.value < other.value
        assert "final" in str(exc.value).lower()

    def test_ratio_is_final(self):
        with pytest.raises(TypeError):
            class EvilRatio(Ratio):
                def __eq__(self, other):
                    return True

    def test_percentage_is_final(self):
        with pytest.raises(TypeError):
            class EvilPct(Percentage):
                pass

    def test_window_is_final(self):
        with pytest.raises(TypeError):
            class EvilWindow(Window):
                pass

    def test_threshold_is_final(self):
        with pytest.raises(TypeError):
            class EvilThreshold(Threshold):
                pass

    def test_provenance_is_final(self):
        with pytest.raises(TypeError):
            class EvilProvenance(Provenance):
                pass

    def test_evidence_is_final(self):
        with pytest.raises(TypeError):
            class EvilEvidence(Evidence):
                pass
