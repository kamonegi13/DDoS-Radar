"""WP-3.1 — the clause partition must cover S1-conclusions exactly.

`v3.scoring.registry` exists because a completion condition phrased as
"the clauses are implemented" is satisfied by implementing all of them,
including the ones a ruling removed. The same trap applies here with an
extra twist: S1-conclusions spans four layers, so most of its clauses are
neither implemented here nor excluded — they are owed by another WP, and a
partition without that third bucket forces every one of them into the
wrong one.

These tests are what makes the partition a claim rather than a comment.
"""
from v3.conclusions import registry as R


class TestThePartitionIsComplete:
    def test_the_universe_is_the_45_clauses(self):
        assert len(R.S1_CONCLUSION_CLAUSES) == 45
        assert "S1-CONC-001" in R.S1_CONCLUSION_CLAUSES
        assert "S1-CONC-045" in R.S1_CONCLUSION_CLAUSES

    def test_no_clause_is_unaccounted_for(self):
        assert R.unaccounted() == frozenset()

    def test_the_three_partitions_do_not_overlap(self):
        assert not (set(R.IMPLEMENTED) & set(R.DEFERRED))
        assert not (set(R.IMPLEMENTED) & set(R.EXCLUDED))
        assert not (set(R.DEFERRED) & set(R.EXCLUDED))

    def test_the_partitions_exactly_cover_the_universe(self):
        assert R.accounted_for() == R.S1_CONCLUSION_CLAUSES

    def test_no_clause_outside_the_universe_is_claimed(self):
        assert R.accounted_for() <= R.S1_CONCLUSION_CLAUSES


class TestEveryClaimIsCheckable:
    def test_every_implemented_clause_names_a_module_and_a_test_class(self):
        for entry in R.IMPLEMENTED.values():
            assert entry.where.strip(), entry.clause
            assert entry.test_class.strip(), entry.clause

    def test_every_named_test_class_actually_exists(self):
        # A clause claimed as implemented whose test was renamed away
        # stops being a claim and starts being a lie.
        import tests.test_conclusions_availability as availability_suite
        import tests.test_conclusions_derive as derive_suite
        import tests.test_conclusions_invariants as invariants_suite
        import tests.test_v3_conclusions_ledger as ledger_suite

        modules = (availability_suite, derive_suite, invariants_suite,
                   ledger_suite)
        for entry in R.IMPLEMENTED.values():
            assert any(hasattr(module, entry.test_class)
                       for module in modules), \
                f"{entry.clause} names a missing test class " \
                f"{entry.test_class}"

    def test_every_deferred_clause_names_the_wp_that_owes_it(self):
        owners = {R.Owner.L4_CALIBRATION, R.Owner.L6_API,
                  R.Owner.L6_REPORTING}
        for entry in R.DEFERRED.values():
            assert entry.owner in owners, entry.clause
            assert entry.note.strip(), entry.clause

    def test_no_owner_is_declared_that_nothing_uses(self):
        # A vocabulary entry with no member is a slot waiting to be
        # filled by guesswork; the test that lists allowed owners would
        # keep passing while the clause it was meant for went nowhere.
        declared = {value for name, value in vars(R.Owner).items()
                    if not name.startswith("_") and isinstance(value, str)}
        assert declared == {entry.owner for entry in R.DEFERRED.values()}

    def test_every_exclusion_gives_a_rationale_and_evidence(self):
        for entry in R.EXCLUDED.values():
            assert entry.rationale.strip() and entry.evidence.strip()

    def test_the_o16_exclusions_are_the_compensation_chain(self):
        # 033 continuity ledger, 034 chronic two-criteria, 035 snapshot:
        # the three mechanisms P6 O-16 replaced with one derived view.
        assert set(R.EXCLUDED) == {"S1-CONC-033", "S1-CONC-034",
                                   "S1-CONC-035"}
        assert all(entry.rationale == R.Rationale.DERIVED_VIEW_O16
                   for entry in R.EXCLUDED.values())

    def test_the_calibration_clauses_all_point_at_wp_3_2(self):
        for clause in ("S1-CONC-029", "S1-CONC-030", "S1-CONC-040",
                       "S1-CONC-043"):
            assert R.DEFERRED[clause].owner == R.Owner.L4_CALIBRATION
