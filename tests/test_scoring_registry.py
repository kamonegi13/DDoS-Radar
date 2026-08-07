"""WP-2.4 — the clause accounting, checked mechanically.

P6 O-14 permits one scoring kernel on condition that the clauses left out
are named with reasons. A prose list would rot; this one is compared
against the transcribed clause universe on every run, so a clause added to
either S1 book, or an implementation quietly dropped, fails the suite
rather than disappearing.

Same shape as tests/test_etl_migrate.py's S3_MIGRATE_35 check, and for the
same reason: `scenarios` went missing from the migration precisely because
nothing compared the plan against the spec.
"""
import inspect
import re
from pathlib import Path

import pytest

from v3.scoring import registry
from v3.scoring.registry import (EXCLUDED, IMPLEMENTED, PIPE_CLAUSES,
                                 S1_SCORING_CLAUSES, SCORE_CLAUSES, Rationale,
                                 exclusions_by_rationale, unaccounted)

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "docs" / "design" / "v3"


class TestTheClauseUniverseMatchesTheSpecs:
    """The transcription is checked against the books themselves."""

    def _clause_ids(self, filename: str, prefix: str) -> set:
        text = (SPEC_DIR / filename).read_text(encoding="utf-8")
        return set(re.findall(rf"^### ({prefix}-\d{{3}}):", text,
                              flags=re.MULTILINE))

    def test_the_scoring_core_book_has_exactly_the_transcribed_clauses(self):
        found = self._clause_ids("S1-scoring-core.md", "S1-SCORE")
        assert found == set(SCORE_CLAUSES)

    def test_the_pipeline_book_has_exactly_the_transcribed_clauses(self):
        found = self._clause_ids("S1-scoring-pipeline.md", "S1-PIPE")
        assert found == set(PIPE_CLAUSES)

    def test_the_universe_is_ninety_one_clauses(self):
        assert len(SCORE_CLAUSES) == 44
        assert len(PIPE_CLAUSES) == 47
        assert len(S1_SCORING_CLAUSES) == 91

    def test_neither_book_has_a_numbering_gap(self):
        assert SCORE_CLAUSES[0] == "S1-SCORE-001"
        assert SCORE_CLAUSES[-1] == "S1-SCORE-044"
        assert PIPE_CLAUSES[0] == "S1-PIPE-001"
        assert PIPE_CLAUSES[-1] == "S1-PIPE-047"


class TestTotality:
    """Every clause is implemented-with-a-test or excluded-with-a-reason."""

    def test_no_clause_is_unaccounted_for(self):
        assert unaccounted() == frozenset()

    def test_the_two_registries_do_not_overlap(self):
        assert set(IMPLEMENTED) & set(EXCLUDED) == set()

    def test_the_registries_cover_the_universe_exactly(self):
        covered = set(IMPLEMENTED) | set(EXCLUDED)
        assert covered - S1_SCORING_CLAUSES == set(), "clause not in any book"
        assert S1_SCORING_CLAUSES - covered == set(), "clause with no ruling"

    def test_the_split_is_the_recorded_one(self):
        assert len(IMPLEMENTED) == 34
        assert len(EXCLUDED) == 57


class TestEveryImplementedClauseHasALivingTest:
    """A claimed clause whose test class vanished is not a claim."""

    def _test_classes(self) -> set:
        import tests.test_scoring_kernel as suite
        return {name for name, obj in inspect.getmembers(suite, inspect.isclass)
                if name.startswith("Test")}

    def test_every_named_test_class_exists(self):
        present = self._test_classes()
        missing = sorted(entry.test_class for entry in IMPLEMENTED.values()
                         if entry.test_class not in present)
        assert missing == [], f"clause registry names absent classes: {missing}"

    def test_every_implemented_clause_names_a_location(self):
        for clause, entry in IMPLEMENTED.items():
            assert entry.where.strip(), f"{clause} has no implementation site"
            assert entry.test_class.strip(), f"{clause} has no test class"

    def test_the_formula_ref_lists_the_implemented_clauses(self):
        """The provenance disclosure is derived from this registry."""
        from v3.scoring.kernel import FORMULA_REF
        for clause in IMPLEMENTED:
            assert clause in FORMULA_REF


class TestEveryExclusionCarriesAReason:
    def test_each_rationale_is_from_the_closed_vocabulary(self):
        allowed = {value for name, value in vars(Rationale).items()
                   if not name.startswith("_") and isinstance(value, str)}
        for clause, entry in EXCLUDED.items():
            assert entry.rationale in allowed, \
                f"{clause} uses an unlisted rationale {entry.rationale!r}"

    def test_each_exclusion_cites_specific_evidence(self):
        for clause, entry in EXCLUDED.items():
            assert len(entry.evidence) > 40, \
                f"{clause}'s rationale is too thin to audit: {entry.evidence!r}"

    def test_the_o14_exclusions_name_the_effective_path(self):
        """A non-effective ruling has to say what IS effective instead."""
        for clause, entry in EXCLUDED.items():
            if entry.rationale != Rationale.NON_EFFECTIVE:
                continue
            assert any(marker in entry.evidence
                       for marker in ("radar/", "S1-SCORE-", "engine",
                                      "test")), \
                f"{clause} claims non-effective without evidence"

    def test_score_036_records_the_o15_consumer_survey(self):
        entry = EXCLUDED["S1-SCORE-036"]
        assert entry.rationale == Rationale.NOT_PORTED_O15
        assert "consumer survey" in entry.evidence
        assert "zero hits" in entry.evidence

    def test_the_engine_formula_family_is_excluded_as_a_family(self):
        """O-14: the losing family goes out together, not clause by clause."""
        for clause in ("S1-SCORE-002", "S1-SCORE-006", "S1-SCORE-019",
                       "S1-SCORE-020"):
            assert EXCLUDED[clause].rationale == Rationale.NON_EFFECTIVE

    def test_exclusions_group_into_reportable_categories(self):
        grouped = exclusions_by_rationale()
        assert sum(len(clauses) for clauses in grouped.values()) == len(EXCLUDED)
        assert Rationale.NON_EFFECTIVE in grouped


class TestNoFormulaIsWrittenTwice:
    """Completion condition 3: the TL ladder exists once."""

    def _scoring_sources(self):
        return sorted((REPO_ROOT / "v3" / "scoring").glob("*.py"))

    def test_only_one_module_derives_a_threat_level(self):
        definers = [path.name for path in self._scoring_sources()
                    if "def derive_tl" in path.read_text(encoding="utf-8")]
        assert definers == ["threat_level.py"]

    def test_the_tl_floors_appear_only_in_the_catalogue(self):
        """The 9 / 6 / 4 / 2 ladder must not be re-typed anywhere."""
        offenders = []
        for path in self._scoring_sources():
            if path.name in ("thresholds.py", "registry.py"):
                continue
            source = path.read_text(encoding="utf-8")
            for literal in ("9.0", "6.0", "4.0", "2.0"):
                if re.search(rf"score\s*>=\s*{re.escape(literal)}", source):
                    offenders.append((path.name, literal))
        assert offenders == []

    def test_only_one_module_computes_a_regression_slope(self):
        definers = [path.name for path in self._scoring_sources()
                    if "def linear_regression_slope" in
                    path.read_text(encoding="utf-8")]
        assert definers == ["trend.py"]

    def test_no_module_maps_a_threat_level_to_severity_itself(self):
        """P6 O-15: ThreatLevel.severity() is the only mapping.

        Parsed rather than grepped — the phrase "6 - TL" appears in prose
        all over this layer explaining the rule, and a text search cannot
        tell an explanation from a second implementation.
        """
        import ast
        offenders = []
        for path in self._scoring_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.BinOp) or \
                        not isinstance(node.op, ast.Sub):
                    continue
                left = node.left
                if isinstance(left, ast.Constant) and left.value in (5, 6):
                    offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []


class TestThresholdDuality:
    """Completion condition 4: P6 O-18's two shapes, and nothing else."""

    def test_every_variable_key_is_registry_backed(self):
        from v3.scoring.thresholds import VARIABLE
        for name, entry in VARIABLE.items():
            assert entry.threshold.is_registry_backed, name
            assert entry.key == name

    def test_every_variable_key_justifies_its_variability(self):
        from v3.scoring.thresholds import VARIABLE
        for name, entry in VARIABLE.items():
            assert len(entry.why) > 60, \
                f"{name} has no real case for being runtime-variable: " \
                f"{entry.why!r}"

    def test_the_variable_surface_stays_small(self):
        """O-18 targets 20-30 keys across the WHOLE system, not per layer."""
        from v3.scoring.thresholds import VARIABLE
        assert len(VARIABLE) <= 12, \
            "the scoring layer alone is consuming O-18's whole budget"

    def test_every_pinned_threshold_discloses_its_source(self):
        from v3.scoring.thresholds import pinned_names, pinned_threshold
        for name in pinned_names():
            threshold = pinned_threshold(name)
            assert not threshold.is_registry_backed, name
            assert threshold.provenance_ref, name
            assert len(threshold.provenance_ref) > 20, name

    def test_the_tl_floors_are_pinned_at_their_adr_values(self):
        """ADR-V3-004: unchanged from production, for the parity window."""
        from v3.scoring import thresholds
        assert thresholds.TL1_SCORE_FLOOR == 9.0
        assert thresholds.TL1_PHYSICAL_FLOOR == 3.0
        assert thresholds.TL2_SCORE_FLOOR == 6.0
        assert thresholds.TL2_MIN_DOMAINS == 2
        assert thresholds.TL3_SCORE_FLOOR == 4.0
        assert thresholds.TL4_SCORE_FLOOR == 2.0

    def test_the_tl_floors_cite_adr_v3_004(self):
        from v3.scoring.thresholds import pinned_threshold
        for name in ("TL1_SCORE_FLOOR", "TL2_SCORE_FLOOR", "TL3_SCORE_FLOOR",
                     "TL4_SCORE_FLOOR"):
            assert "ADR-V3-004" in pinned_threshold(name).provenance_ref

    def test_engine_only_keys_are_not_registered(self):
        """They would be live dials nothing reads — the G-15 shape."""
        from v3.scoring.thresholds import VARIABLE
        for key in ("CONVERGENCE_FULL_BONUS", "DOMAIN_WEIGHT_CYBER",
                    "DOMAIN_WEIGHT_PHYSICAL", "DOMAIN_WEIGHT_INFO"):
            assert key not in VARIABLE

    def test_the_settings_object_exposes_only_variable_keys(self):
        from v3.scoring.settings import ScoringSettings
        disclosed = set(ScoringSettings().disclosed())
        assert "convergence_full_bonus" not in disclosed
        assert "domain_weight_cyber" not in disclosed
        assert "domain_cap" in disclosed

    def test_resolve_settings_reads_every_variable_key_through_the_chain(self):
        """The production boundary, exercised without booting the app.

        `_default_resolver` is the kernel's lazy hook into the legacy
        3-layer registry. Substituting it here is the only way to prove
        resolve_settings() actually resolves — the alternative was
        shipping the one impure function in the layer untested.
        """
        import v3.kernel.threshold as threshold_module
        from v3.scoring.settings import resolve_settings
        from v3.scoring.thresholds import VARIABLE

        asked = []

        def fake(key):
            asked.append(key)
            return (VARIABLE[key].default, "db")

        original = threshold_module._default_resolver
        threshold_module._default_resolver = fake
        try:
            resolved = resolve_settings()
        finally:
            threshold_module._default_resolver = original

        assert sorted(asked) == sorted(VARIABLE)
        assert resolved.domain_cap == 6.0
        assert resolved.llm_primary_threshold.value == pytest.approx(0.8)
        assert resolved.global_signals_decoupled is True
        assert resolved.convergence_scenario_specific is False

    def test_resolve_settings_refuses_a_missing_key_rather_than_defaulting(self):
        """G-15: a silent fallback is how 95 dead keys stayed invisible."""
        import v3.kernel.threshold as threshold_module
        from v3.kernel.errors import ThresholdResolutionError
        from v3.scoring.settings import resolve_settings

        original = threshold_module._default_resolver
        threshold_module._default_resolver = lambda key: (None, "default")
        try:
            with pytest.raises(ThresholdResolutionError):
                resolve_settings()
        finally:
            threshold_module._default_resolver = original

    def test_resolution_is_not_reachable_from_the_kernel(self):
        """The impure step lives in settings.py and only there."""
        offenders = []
        for path in sorted((REPO_ROOT / "v3" / "scoring").glob("*.py")):
            if path.name in ("settings.py", "thresholds.py"):
                continue
            if ".resolve()" in path.read_text(encoding="utf-8"):
                offenders.append(path.name)
        assert offenders == []


class TestRegistryIsDocumentedInPlace:
    def test_the_module_explains_why_the_ledger_exists(self):
        doc = registry.__doc__ or ""
        assert "O-14" in doc
        assert len(doc) > 400

    @pytest.mark.parametrize("clause", ["S1-SCORE-004", "S1-SCORE-005",
                                        "S1-PIPE-009", "S1-PIPE-026"])
    def test_load_bearing_clauses_are_implemented(self, clause):
        assert clause in IMPLEMENTED
