"""WP-2.7 — LLM intel extraction: one implementation, and where it lands.

Two things are proved here.

1. THE SHAPE (P6 O-17 / design sheet §4-1, §4-2, §4-3). One extraction
   implementation over one submission path; the per-source surface is
   exactly four slots; an extracted item is an ordinary L1 observation,
   not a row in a second scoring queue; `convergence_tracker` is not
   ported and its question is answered as metadata carrying no score.

2. THE CLAUSES (S1-INGEST-011..020), each mapped by name.

The literals are transcribed from production and `ast`-verified against
the live sources in `TestTheProductionLiteralsHoldStill`, so a production
change fails this suite rather than drifting past it.
"""
import ast
import pathlib

import pytest

from v3.adapters.llm import extraction as ex
from v3.kernel.errors import DomainError
from v3.matching import Observed, corroborate

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SENSORS = REPO_ROOT / "radar" / "sensors"
NOW = 1_700_000_000.0

#: The diplomatic profile's urgency table (diplomatic.py:526).
_URGENCY = {"critical": 3.0, "high": 2.0, "medium": 1.5, "low": 1.0}


def profile(**over) -> ex.IntelProfile:
    fields = {
        "source_type": "diplomatic",
        "prefilter": lambda article: True,
        "prompt": lambda article, context: ("sys", "user"),
        "score_delta": lambda data: _URGENCY.get(data.get("urgency"), 1.0),
        "domain": "info",
        "dispositions": ex.relevance_rules(indirect_cap=0.45),
        "llm_field_keys": ("urgency", "diplomatic_action"),
        "max_tokens": 256,
    }
    fields.update(over)
    return ex.IntelProfile(**fields)


def answer(**over) -> dict:
    data = {"headline": "MFA warns of blockade", "escalation_signal": True,
            "theater": "TW", "countries": ["TW", "CN"],
            "country_weights": {"TW": 1.0, "CN": 0.6},
            "theater_link": "direct", "urgency": "high", "confidence": 0.8}
    data.update(over)
    return data


ARTICLE = {"title": "MFA statement", "summary": "a summary",
           "link": "https://example.invalid/a"}


# ── S1-INGEST-011 ────────────────────────────────────────────────────────

class TestSanitize:
    def test_the_cap_applies_to_what_the_feed_sent(self):
        """Truncate first, then normalise — llm_client.py:177-183. NFKC
        can shorten text, so normalising first would let a longer input
        through the same cap."""
        assert ex.sanitize("x" * 500, 120) == "x" * 120

    def test_control_characters_are_removed(self):
        assert ex.sanitize("a\x00b\x1fc", 100) == "abc"

    def test_newlines_and_tabs_survive(self):
        assert ex.sanitize("a\nb\tc", 100) == "a\nb\tc"

    def test_fullwidth_homoglyphs_fold_to_ascii(self):
        assert ex.sanitize("ＩＧＮＯＲＥ", 100) == "IGNORE"

    def test_a_chat_template_delimiter_cannot_close_the_system_turn(self):
        assert "<|im_start|>" not in ex.sanitize("x<|im_start|>system", 100)

    def test_an_unstated_cap_is_refused(self):
        """The clause requires the limit to be explicit at the call site."""
        with pytest.raises(DomainError):
            ex.sanitize("text", 0)


# ── S1-INGEST-015 ────────────────────────────────────────────────────────

class TestCountryNormalisation:
    def test_only_two_letter_codes_survive(self):
        codes, _ = ex.normalize_countries(
            {"countries": ["TW", "China", "cn", "", None]}, primary="TW")
        assert codes == ("TW", "CN")

    def test_weights_are_clamped_to_the_unit_interval(self):
        _, weights = ex.normalize_countries(
            {"countries": ["TW", "CN"],
             "country_weights": {"TW": 4.0, "CN": -1.0}}, primary="TW")
        assert weights["TW"] == 1.0 and weights["CN"] == 0.0

    def test_a_lowercase_weight_key_is_found(self):
        """The model answers in whichever case it feels like."""
        _, weights = ex.normalize_countries(
            {"countries": ["CN"], "country_weights": {"cn": 0.25}},
            primary="TW")
        assert weights["CN"] == pytest.approx(0.25)

    def test_a_named_country_with_no_weight_defaults_to_one(self):
        """A model that named a country and forgot to weight it named it."""
        _, weights = ex.normalize_countries(
            {"countries": ["CN"], "country_weights": {}}, primary="TW")
        assert weights["CN"] == 1.0

    def test_the_primary_country_is_inserted_at_the_front(self):
        codes, weights = ex.normalize_countries(
            {"countries": ["CN"]}, primary="TW")
        assert codes[0] == "TW" and weights["TW"] == 1.0


# ── S1-INGEST-016 / 017 / 014 ────────────────────────────────────────────

class TestAdmission:
    def test_an_item_the_model_could_not_attribute_is_discarded(self):
        """S1-INGEST-016: never a forced assignment to the nearest
        target — that is the Phase 9-E attribution-pollution incident."""
        item, reason = ex.build_item(profile(), answer(theater=None), ARTICLE,
                                     now=NOW)
        assert item is None and reason == ex.NO_PRIMARY_COUNTRY

    def test_a_country_outside_the_scope_is_discarded(self):
        item, reason = ex.build_item(profile(), answer(), ARTICLE, now=NOW,
                                     scope=("UA", "RU"))
        assert item is None and reason == ex.NOT_IN_SCOPE

    def test_relevance_none_is_discarded(self):
        item, reason = ex.build_item(profile(), answer(theater_link="none"),
                                     ARTICLE, now=NOW)
        assert item is None and reason == ex.RELEVANCE_NONE

    def test_indirect_relevance_is_capped_at_the_source_specific_value(self):
        """0.45 for diplomatic (diplomatic.py:518), 0.50 for
        military_exercise (military_exercise.py:385) — one shared value
        would be an invention, which P2 §5-C forbids mid-port."""
        item, _ = ex.build_item(
            profile(), answer(theater_link="indirect", confidence=0.9),
            ARTICLE, now=NOW)
        assert item.confidence == 0.45
        item, _ = ex.build_item(
            profile(dispositions=ex.relevance_rules(indirect_cap=0.50)),
            answer(theater_link="indirect", confidence=0.9), ARTICLE, now=NOW)
        assert item.confidence == 0.50

    def test_a_source_with_no_cap_rule_is_left_alone(self):
        item, _ = ex.build_item(
            profile(dispositions=ex.relevance_rules(indirect_cap=None)),
            answer(theater_link="indirect", confidence=0.9), ARTICLE, now=NOW)
        assert item.confidence == 0.9

    def test_a_relevance_answer_outside_the_enum_is_dropped_not_accepted(self):
        """`safe_enum(theater_link, {direct,indirect,none}, "none")`
        (`diplomatic.py:507`, `military_exercise.py:374`) folds every
        unrecognised answer onto `none`, and `none` is a DISCARD. Reading
        an unknown value as `direct` — or defaulting an ABSENT key to
        `direct` — admits items production drops, which is a real
        difference even though it points the sensitive way."""
        for bad in ("probable", "", "DIRECTLY"):
            item, reason = ex.build_item(profile(), answer(theater_link=bad),
                                         ARTICLE, now=NOW)
            assert (item, reason) == (None, ex.RELEVANCE_NONE), bad
        item, reason = ex.build_item(profile(), {
            k: v for k, v in answer().items() if k != "theater_link"},
            ARTICLE, now=NOW)
        assert (item, reason) == (None, ex.RELEVANCE_NONE)

    def test_an_absent_escalation_flag_is_a_silence_not_a_signal(self):
        """Every production copy reads `data.get("escalation_signal",
        False)` (`diplomatic.py:479`, `military_exercise.py:354`,
        `rss_narrative.py:473`), so a model that omits the field has said
        nothing. Testing `is False` instead would admit every malformed
        answer."""
        stripped = {k: v for k, v in answer().items()
                    if k != "escalation_signal"}
        item, reason = ex.build_item(profile(), stripped, ARTICLE, now=NOW)
        assert (item, reason) == (None, ex.NO_SIGNAL)

    def test_the_floor_and_the_absent_signal_are_different_reasons(self):
        """S1-INGEST-014: one points at the threshold, the other at the
        prompt. A single `dropped` counter makes both undiagnosable."""
        low, low_reason = ex.build_item(profile(), answer(confidence=0.2),
                                        ARTICLE, now=NOW)
        quiet, quiet_reason = ex.build_item(
            profile(), answer(escalation_signal=False), ARTICLE, now=NOW)
        assert (low, quiet) == (None, None)
        assert low_reason == ex.BELOW_FLOOR
        assert quiet_reason == ex.NO_SIGNAL
        assert low_reason != quiet_reason

    def test_the_floor_is_the_value_seven_of_the_eight_copies_use(self):
        assert ex.CONFIDENCE_FLOOR == 0.35

    def test_the_boundary_confidence_is_admitted(self):
        item, _ = ex.build_item(profile(), answer(confidence=0.35), ARTICLE,
                                now=NOW)
        assert item is not None


# ── S1-INGEST-018 / 019 ──────────────────────────────────────────────────

class TestTheEnvelope:
    def test_the_thirteen_fields_are_all_present(self):
        item, _ = ex.build_item(profile(), answer(), ARTICLE, now=NOW)
        for name in ("source_type", "source_id", "country", "countries",
                     "country_weights", "ts", "confidence", "raw_text",
                     "raw_url", "headline", "llm_fields", "score_delta",
                     "domain"):
            assert hasattr(item, name), name

    def test_the_limits_are_the_production_ones(self):
        item, _ = ex.build_item(
            profile(), answer(headline="h" * 400),
            {"summary": "s" * 4000, "link": ""}, now=NOW)
        assert len(item.headline) == ex.HEADLINE_LIMIT == 100
        assert len(item.raw_text) == ex.RAW_TEXT_LIMIT == 1000

    def test_the_confidence_is_rounded_to_three_digits(self):
        item, _ = ex.build_item(profile(), answer(confidence=0.8234567),
                                ARTICLE, now=NOW)
        assert item.confidence == 0.823

    def test_the_score_is_additive_and_owned_by_the_profile(self):
        """S1-INGEST-018: this layer never multiplies the profile's
        number — multiplicative composition makes the value jump."""
        item, _ = ex.build_item(profile(), answer(urgency="critical"),
                                ARTICLE, now=NOW)
        assert item.score_delta == 3.0

    def test_the_fourth_domain_value_cannot_get_back_in(self):
        """`convergence_tracker` emitted `mixed` (A5 / S1-SENSI-053), a
        value outside the scoring layer's vocabulary. It is not ported,
        and the type refuses it."""
        with pytest.raises(DomainError):
            ex.IntelItem(source_type="x", source_id="x", country="TW",
                         countries=("TW",), country_weights={"TW": 1.0},
                         ts=NOW, confidence=0.5, raw_text="", raw_url="",
                         headline="h", llm_fields={}, score_delta=1.0,
                         domain="mixed")


# ── O-17 / §4-2: the item lands as an L1 observation ─────────────────────

class TestItemsLandAsObservations:
    def _draft(self, **over):
        item, _ = ex.build_item(profile(), answer(**over), ARTICLE, now=NOW)
        return item.as_draft()

    def test_the_signal_source_is_the_pinned_literal(self):
        """S1-INTEL-020 fixes it, S1-SCORE-008 dedups on it, and
        v3/parity/adapter.py reads it back to recover origin=llm_intel."""
        assert self._draft().signal_source == "llm_intel"
        assert ex.LLM_INTEL_SOURCE == "llm_intel"

    def test_the_raw_score_is_the_undecayed_delta(self):
        """O-17 abolished the second decay. The age term is L2's
        (WP-2.4 addendum); pre-decaying here would rebuild it."""
        draft = self._draft(urgency="critical")
        assert draft.raw_score == 3.0
        assert draft.flags["score_delta_raw"] == 3.0

    def test_the_observation_carries_its_own_timestamp(self):
        """Without it L2 cannot age the item, and production's
        `observed_at=current_time` (core.py:2074) proves the failure
        mode: an age recovered downstream there is always zero."""
        assert self._draft().flags["observed_at"] == NOW

    def test_the_country_weights_travel_for_S1_SCORE_009(self):
        draft = self._draft()
        assert draft.flags["country_weights"]["CN"] == pytest.approx(0.6)
        assert draft.country == "TW"

    def test_there_is_no_second_queue_for_intel(self):
        """§4-2: `ObservationDraft` is the only output. A separate intel
        queue type in this package would be the second pipeline O-17
        found."""
        source = (REPO_ROOT / "v3" / "adapters" / "llm").glob("*.py")
        for path in source:
            text = path.read_text(encoding="utf-8")
            assert "intel_queue" not in text, path.name


# ── §4-1: the four-slot surface ──────────────────────────────────────────

class TestTheProfileIsFourSlots:
    def test_the_behavioural_surface_is_exactly_the_four_slots(self):
        """The limit is on BEHAVIOUR, not on field count (裁定要求 10,
        ruled 2026-08-08). A fifth CALLABLE is the eight-copy shape
        growing back, because a callable is where a sensor's habits go;
        declared data has no branch to hide them in."""
        import dataclasses
        callables = {f.name for f in dataclasses.fields(ex.IntelProfile)
                     if callable(getattr(profile(), f.name))}
        assert callables == {"prefilter", "prompt", "score_delta"}
        assert set(ex.BEHAVIOURAL_SLOTS) == callables | {"domain"}

    def test_everything_else_on_the_profile_is_inert_data(self):
        """The test that would fail if a fifth slot arrived wearing a
        data-shaped name."""
        import dataclasses
        built = profile()
        for field in dataclasses.fields(ex.IntelProfile):
            if field.name in ex.BEHAVIOURAL_SLOTS:
                continue
            value = getattr(built, field.name)
            assert not callable(value), field.name
            for element in (value if isinstance(value, tuple) else ()):
                assert not callable(element), field.name

    def test_a_disposition_rule_refuses_a_callable(self):
        """Mirrors `RequestContinuation.path`: the moment a rule can hold
        a predicate, "which value" becomes "how to decide", and the one
        extraction implementation has eight behaviours inside it again."""
        with pytest.raises(DomainError):
            ex.DispositionRule(field=lambda data: "x", values=("none",),
                               outcome=ex.DROP, reason="r")
        with pytest.raises(DomainError):
            ex.DispositionRule(field="event_type", values=(lambda d: True,),
                               outcome=ex.DROP, reason="r")

    def test_a_drop_rule_must_name_its_silence(self):
        """S1-INGEST-020. An unnamed drop collapses into the shared
        `no_escalation_signal`, and "the model saw nothing" and "this was
        a weekly tracker" call for opposite responses."""
        with pytest.raises(DomainError):
            ex.DispositionRule(field="event_type", values=("none",),
                               outcome=ex.DROP)

    def test_a_cap_below_the_floor_is_refused(self):
        """What makes ONE evaluation order provably safe. Production
        applies its caps at two different points relative to the floor
        (`military_exercise.py:348` before, `:385` after); the two orders
        agree only while every cap sits at or above the floor."""
        with pytest.raises(DomainError):
            ex.DispositionRule(field="event_type", values=("status_report",),
                               outcome=ex.CAP, cap=0.20)
        ex.DispositionRule(field="event_type", values=("status_report",),
                           outcome=ex.CAP, cap=ex.CONFIDENCE_FLOOR)

    def test_two_rules_cannot_claim_the_same_value(self):
        with pytest.raises(DomainError):
            profile(dispositions=(
                ex.DispositionRule(field="event_type", values=("none",),
                                   outcome=ex.DROP, reason="a"),
                ex.DispositionRule(field="event_type", values=("none",),
                                   outcome=ex.ACCEPT)))

    def test_the_first_matching_drop_wins_so_the_specific_reason_survives(
            self):
        """Declaration order is production's order: `military_exercise
        .py:343` runs the `event_type` gate ahead of the shared
        `escalation_signal` test, so an item that is both a non-event and
        unsignalled is filed under the source's own code."""
        rules = (ex.DispositionRule(field="event_type", values=("none",),
                                    outcome=ex.DROP,
                                    reason="event_type_none",
                                    matches_unrecognised=True),
                 ex.DispositionRule(
                     field="event_type",
                     values=("new_deployment", "exercise_start"),
                     outcome=ex.ACCEPT))
        item, reason = ex.build_item(
            profile(dispositions=rules),
            answer(event_type="none", escalation_signal=False), ARTICLE,
            now=NOW)
        assert (item, reason) == (None, "event_type_none")

    def test_a_profile_cannot_declare_a_fourth_domain(self):
        with pytest.raises(DomainError):
            profile(domain="mixed")

    def test_there_is_exactly_one_submission_implementation(self):
        """A-02's eight skeletons become one. Anything in v3 that builds
        an Ollama request other than `v3/fetch/llm.py` is a second one."""
        offenders = []
        for path in (REPO_ROOT / "v3").rglob("*.py"):
            if path.name == "llm.py" and path.parent.name == "fetch":
                continue
            text = path.read_text(encoding="utf-8")
            if "/api/generate" in text or "num_predict" in text:
                offenders.append(str(path.relative_to(REPO_ROOT)))
        assert offenders == []

    def test_there_is_exactly_one_extraction_implementation(self):
        definers = [path.name for path in
                    (REPO_ROOT / "v3").rglob("*.py")
                    if "def build_item" in path.read_text(encoding="utf-8")]
        assert definers == ["extraction.py"]


# ── §4-3: convergence_tracker's disposition ──────────────────────────────

class TestCorroborationCarriesNoScore:
    def test_corroboration_is_metadata_not_points(self):
        verdict = corroborate(
            Observed("llm_intel", "PLA announces live-fire drill in strait"),
            [Observed("gdelt", "PLA announces live fire drill near strait")])
        payload = verdict.as_dict()
        assert verdict.is_corroborated
        assert "score" not in payload and "bonus" not in payload
        assert payload["independent_sources"] == 2

    def test_the_same_source_twice_is_not_corroboration(self):
        """S1-SCORE-008 already folds one source by MAX; counting it
        again here would double-count the one fact NP2 rests on."""
        verdict = corroborate(
            Observed("llm_intel", "PLA announces live-fire drill"),
            [Observed("llm_intel", "PLA announces live-fire drill")])
        assert verdict.is_corroborated is False
        assert verdict.independent_sources == 1

    def test_non_latin_sources_can_corroborate_each_other(self):
        """F-09: `[a-z]{3,}` gave both of these zero tokens, so TASS and
        Xinhua could never support one another."""
        verdict = corroborate(
            Observed("tass", "Военные учения в Тайваньском проливе"),
            [Observed("kcna", "Военные учения в Тайваньском проливе сегодня")])
        assert verdict.is_corroborated

    def test_the_group_key_does_not_depend_on_arrival_order(self):
        subject = Observed("llm_intel", "strait drill announced")
        left = corroborate(subject, [Observed("gdelt", "strait drill announced"),
                                     Observed("rss", "strait drill announced")])
        right = corroborate(subject, [Observed("rss", "strait drill announced"),
                                      Observed("gdelt", "strait drill announced")])
        assert left.group_key == right.group_key

    def test_an_unlabelled_account_is_refused(self):
        with pytest.raises(DomainError):
            Observed("", "headline")

    def test_the_tracker_is_named_as_not_ported_rather_than_left_out(self):
        """§4-3 is a ruling, so it is recorded where the roster is — an
        adapter that is simply absent is indistinguishable from one that
        was forgotten, which is the accounting failure the catalog
        registry exists to prevent."""
        from v3.adapters.catalog import (NOT_PORTED, buildable_adapter_ids,
                                         declared_adapter_ids)
        assert "convergence_tracker" in declared_adapter_ids()
        assert "convergence_tracker" in NOT_PORTED
        assert "convergence_tracker" not in buildable_adapter_ids()

    def test_no_v3_module_implements_the_tracker(self):
        for path in (REPO_ROOT / "v3").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "class ConvergenceTracker" not in text, path.name
            assert "CONVERGENCE_TRACKER_ADAPTER" not in text, path.name


# ── the AST fidelity check, against the live production sources ──────────

class TestTheProductionLiteralsHoldStill:
    def _floor_literals(self, filename: str) -> set:
        """Every literal compared against a `confidence` name."""
        tree = ast.parse((SENSORS / filename).read_text(encoding="utf-8"))
        found = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            if "confidence" not in ast.unparse(node.left):
                continue
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant) and \
                        isinstance(comparator.value, float):
                    found.add(comparator.value)
        return found

    @pytest.mark.parametrize("filename", [
        "diplomatic.py", "military_exercise.py", "hacktivist_intel_sensor.py",
        "hacktivist_news_sensor.py", "ground_osint_sensor.py"])
    def test_every_ported_source_still_floors_confidence_at_the_shared_value(
            self, filename):
        assert ex.CONFIDENCE_FLOOR in self._floor_literals(filename)

    def test_the_unported_tracker_is_the_one_that_disagrees(self):
        """0.50, not 0.35 (convergence_tracker.py:382). The divergence
        leaves with the adapter that is not ported."""
        floors = self._floor_literals("convergence_tracker.py")
        assert 0.50 in floors and ex.CONFIDENCE_FLOOR not in floors

    def test_the_envelope_limits_are_still_the_production_ones(self):
        """diplomatic.py:528-550 — the reference envelope."""
        tree = ast.parse((SENSORS / "diplomatic.py").read_text(
            encoding="utf-8"))
        slices, rounds = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Subscript) and \
                    isinstance(node.slice, ast.Slice) and \
                    isinstance(node.slice.upper, ast.Constant):
                slices.add(node.slice.upper.value)
            if isinstance(node, ast.Call) and \
                    ast.unparse(node.func) == "round" and \
                    len(node.args) == 2 and \
                    isinstance(node.args[1], ast.Constant):
                rounds.add(node.args[1].value)
        assert ex.RAW_TEXT_LIMIT in slices
        assert ex.HEADLINE_LIMIT in slices
        assert ex.CONFIDENCE_DIGITS in rounds

    def test_the_indirect_caps_still_disagree_across_the_two_sources(self):
        """Proving the per-source cap is not an invention: production
        really does use two different values."""
        def caps(filename):
            tree = ast.parse((SENSORS / filename).read_text(encoding="utf-8"))
            return {node.args[1].value
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and ast.unparse(node.func) == "min"
                    and len(node.args) == 2
                    and "confidence" in ast.unparse(node.args[0])
                    and isinstance(node.args[1], ast.Constant)}
        assert 0.45 in caps("diplomatic.py")
        assert 0.50 in caps("military_exercise.py")
