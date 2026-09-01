"""The clause partition, and WP-3.2's condition 4 as a machine check.

`v3.conclusions.registry` established the discipline: a completion
condition phrased as "the clauses are implemented" is satisfiable by
implementing all of them, including other packages' clauses, so the
partition has to be code that the suite checks.

Condition 4 names twelve specific clauses. The test below asserts each is
in IMPLEMENTED, so the twelve cannot quietly move to DEFERRED.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from v3.calibration import registry as REG

SPEC = Path(__file__).resolve().parent.parent / "docs" / "design" / "v3" / \
    "S1-calibration.md"


class TestPartition:

    def test_every_clause_is_accounted_for(self):
        assert REG.unaccounted() == frozenset()

    def test_the_partitions_do_not_overlap(self):
        pairs = [(REG.IMPLEMENTED, REG.DEFERRED),
                 (REG.IMPLEMENTED, REG.EXCLUDED),
                 (REG.DEFERRED, REG.EXCLUDED)]
        for left, right in pairs:
            assert not (set(left) & set(right))

    def test_the_universe_is_the_spec_s_sixty_eight_clauses(self):
        assert len(REG.S1_CALIBRATION_CLAUSES) == 68

    def test_no_clause_is_invented(self):
        assert REG.accounted_for() <= REG.S1_CALIBRATION_CLAUSES

    def test_every_implemented_clause_names_a_test_class(self):
        for entry in REG.IMPLEMENTED.values():
            assert entry.test_class.startswith("Test"), entry.clause

    def test_every_named_test_class_exists_in_the_suite(self):
        # A registry entry pointing at a test class nobody wrote is the
        # paperwork version of E-03.
        tests_dir = Path(__file__).resolve().parent
        declared = set()
        for path in tests_dir.glob("test_v3_calibration_*.py"):
            declared |= set(re.findall(r"^class (Test\w+)",
                                       path.read_text(encoding="utf-8"),
                                       re.MULTILINE))
        for entry in REG.IMPLEMENTED.values():
            assert entry.test_class in declared, (
                f"{entry.clause} names {entry.test_class}, which no "
                f"calibration suite defines")

    def test_every_deferred_clause_names_an_owner(self):
        for entry in REG.DEFERRED.values():
            assert entry.owner and entry.note, entry.clause

    def test_deferrals_are_grouped_by_owner(self):
        grouped = REG.deferrals_by_owner()
        assert sum(len(v) for v in grouped.values()) == len(REG.DEFERRED)


class TestConditionFourTheTwelveIncidentGuards:
    """WP-3.2 completion condition 4."""

    def test_all_twelve_are_implemented(self):
        assert REG.incident_derived_not_implemented() == frozenset()

    @pytest.mark.parametrize("clause", REG.INCIDENT_DERIVED)
    def test_each_incident_clause_has_a_pinning_test(self, clause):
        assert REG.IMPLEMENTED[clause].test_class.startswith("Test")

    def test_the_twelve_match_the_spec_s_own_annotations(self):
        # Read the annotations out of the spec rather than trusting the
        # tuple: S5-VERIF-037's lesson is that a hand-maintained count
        # drifts from the thing it counts.
        text = SPEC.read_text(encoding="utf-8")
        found: list = []
        current = None
        for line in text.splitlines():
            heading = re.match(r"^#### (S1-CALIB-\d{3}):", line)
            if heading:
                current = heading.group(1)
            elif current and "由来: インシデント" in line:
                found.append(current)
                current = None
        assert sorted(found) == sorted(REG.INCIDENT_DERIVED), (
            f"spec annotates {sorted(found)}, registry lists "
            f"{sorted(REG.INCIDENT_DERIVED)}")

    def test_there_are_exactly_twelve(self):
        assert len(REG.INCIDENT_DERIVED) == 12
