"""WP-2.6 — the roster, the knowledge ledger, and the I/O barriers.

Three accounting jobs live here, and each one fails on drift rather than
on someone noticing:

1. **Totality.** The design sheet §3-2 table is parsed from the document
   itself and compared with what this package exports. An adapter that
   goes missing, an identifier that drifts, or a row added to the sheet
   without a port all fail. Same shape as the ETL's `S3_MIGRATE_35` check
   and L2's clause registry — `scenarios` went missing from the migration
   plan precisely because nothing compared the plan with the spec.

2. **D1 §4's twenty facts.** One fact, one test, with the fact in the
   test's name (§6-2). The meta-test below checks the mapping in both
   directions: a fact claimed by an adapter with no test fails, and a
   test naming a fact no adapter claims fails.

3. **The four I/O barriers**, run against every adapter rather than
   against the exemplar alone — including the closure-smuggling shape
   that WP-2.5 proved barriers 2 and 3 cannot see.
"""
import ast
import re
import socket
import threading
from pathlib import Path

import pytest

from v3.adapters import catalog, knowledge
from v3.adapters.catalog import (DESIGN_SHEET_RENAMES, WP26_ADAPTERS,
                                 WP26_DESIGN_SHEET_ROWS, build_registry,
                                 expected_adapter_ids)
from v3.adapters.knowledge import (KNOWLEDGE, KNOWLEDGE_TESTS, WP26_KNOWLEDGE,
                                   unknown_refs)
from v3.adapters.types import (ADAPTER_STATUSES, AdapterId, FetchedPayload,
                               NormalizeContext, ObservationDraft,
                               RequestChain)

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "docs" / "design" / "v3" / "wp25-l0-adapter-design.md"
ADAPTERS_DIR = REPO_ROOT / "v3" / "adapters"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "adapters"
T0 = 1_700_000_000.0


# ── 1. totality against the design sheet ────────────────────────────────

def _design_sheet_rows() -> list[tuple[int, str]]:
    """Parse §3-2's table out of the document, not out of a copy of it."""
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("### 3-2.")[1].split("### 3-3.")[0]
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`([a-z0-9_]+)`\s*\|",
                      section, flags=re.MULTILINE)
    return [(int(number), name) for number, name in rows]


def _design_sheet_rows_27() -> list[tuple[int, str]]:
    """Parse §3-3's table out of the document, same as §3-2's."""
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("### 3-3.")[1].split("### 3-4.")[0]
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`([a-z0-9_]+)`\s*\|",
                      section, flags=re.MULTILINE)
    return [(int(number), name) for number, name in rows]


class TestTotalityAcrossBothBatches:
    """The full 34 (§3-0), parsed from the sheet rather than restated.

    WP-2.6 shipped 22. WP-2.7 ships the shared machinery first and its
    per-source declarations after, so the roster is deliberately short —
    and `PENDING_WP27` is what makes short different from missing. Both
    directions fail: an adapter built without striking its row, and a row
    left standing after its adapter ships.
    """

    def test_the_wp27_transcription_matches_the_document(self):
        from v3.adapters.catalog import WP27_DESIGN_SHEET_ROWS
        assert _design_sheet_rows_27() == list(WP27_DESIGN_SHEET_ROWS)

    def test_the_two_sheets_declare_thirty_four_adapters(self):
        from v3.adapters.catalog import declared_adapter_ids
        assert len(_design_sheet_rows()) + len(_design_sheet_rows_27()) == 34
        assert len(declared_adapter_ids()) == 34
        assert len(set(declared_adapter_ids())) == 34

    def test_the_row_numbers_run_one_to_thirty_four_without_a_gap(self):
        numbers = [n for n, _ in _design_sheet_rows() + _design_sheet_rows_27()]
        assert numbers == list(range(1, 35))

    def test_the_one_not_ported_adapter_is_the_one_the_sheet_rules_out(self):
        from v3.adapters.catalog import NOT_PORTED, buildable_adapter_ids
        assert set(NOT_PORTED) == {"convergence_tracker"}
        assert len(buildable_adapter_ids()) == 33
        assert "convergence_tracker" not in buildable_adapter_ids()

    def test_every_not_ported_entry_carries_its_reason(self):
        from v3.adapters.catalog import NOT_PORTED
        for name, reason in NOT_PORTED.items():
            assert "§4-3" in reason, name
            assert len(reason) > 80, name

    def test_pending_names_only_rows_the_sheet_declares(self):
        from v3.adapters.catalog import PENDING_WP27, buildable_adapter_ids
        assert not set(PENDING_WP27) - set(buildable_adapter_ids())

    def test_the_two_deferred_adapters_are_the_ones_ruling_nine_names(self):
        """Ruling 9 (2026-08-08): `hacktivist_intel` and `ground_osint` go
        to WP-4.1, because their input is another adapter's OUTPUT and the
        declaration model has no vocabulary for that. Forcing it breaks
        barrier 1 (a cache handle inside `normalize`) or barriers 2/4 (the
        adapter reading for itself) — the §2-4 lesson repeating.

        Deferred is its own state, distinct from pending: pending means
        "this batch still owes it", deferred means "this batch cannot
        express it and another one will".
        """
        from v3.adapters.catalog import DEFERRED_WP41, buildable_adapter_ids
        assert set(DEFERRED_WP41) == {"hacktivist_intel", "ground_osint"}
        assert not set(DEFERRED_WP41) - set(buildable_adapter_ids())

    def test_every_deferred_entry_names_its_reason_and_its_landing_wp(self):
        """A deferral with no stated cause is indistinguishable from a
        port somebody abandoned — the same argument `disabled_reason` and
        `RequestChain.reason` carry."""
        from v3.adapters.catalog import DEFERRED_WP41
        for name, reason in DEFERRED_WP41.items():
            assert "WP-4.1" in reason, name
            assert "H-3" in reason, name
            assert len(reason) > 120, name

    def test_the_deferred_share_a_mechanism_with_reduction_and_suppression(
            self):
        """§7-2 #11 (reduction) and #35 (suppression) are the same gap.

        All three need another adapter's output. Ruling 9 takes option (c)
        — one wiring in the composition root — precisely so three separate
        mechanisms are not invented, which is A-02 (the same computation
        implemented several times) reproduced on purpose.
        """
        from v3.adapters.catalog import DEFERRED_WP41
        blob = " ".join(DEFERRED_WP41.values())
        assert "#11" in blob and "#35" in blob

    def test_a_deferred_adapter_is_neither_pending_nor_built(self):
        from v3.adapters.catalog import (ALL_ADAPTERS, DEFERRED_WP41,
                                         PENDING_WP27)
        built = {adapter.adapter_id.value for adapter in ALL_ADAPTERS}
        assert built & set(DEFERRED_WP41) == set()
        assert set(PENDING_WP27) & set(DEFERRED_WP41) == set()

    def test_a_pending_adapter_is_not_also_built(self):
        from v3.adapters.catalog import ALL_ADAPTERS, PENDING_WP27
        built = {adapter.adapter_id.value for adapter in ALL_ADAPTERS}
        assert built & set(PENDING_WP27) == set(), \
            "an adapter shipped without striking its PENDING_WP27 row"

    def test_the_built_roster_is_exactly_declared_minus_ruled_out_minus_pending(
            self):
        from v3.adapters.catalog import ALL_ADAPTERS, expected_adapter_ids
        built = {adapter.adapter_id.value for adapter in ALL_ADAPTERS}
        assert built == set(expected_adapter_ids())

    def test_the_wp27_batch_still_accounts_for_all_eleven_rows(self):
        """The invariant that holds at every point of the port.

        §3-3 lists twelve rows; `convergence_tracker` is not ported, so
        eleven are buildable. Each of those eleven is in exactly one state
        at all times — shipped, still owed, or deferred to WP-4.1 — so a
        row cannot be quietly dropped by moving it out of `PENDING_WP27`
        without it turning up somewhere else.
        """
        from v3.adapters.catalog import (DEFERRED_WP41, PENDING_WP27,
                                         WP27_ADAPTERS, WP27_DESIGN_SHEET_ROWS,
                                         NOT_PORTED)
        rows = {name for _, name in WP27_DESIGN_SHEET_ROWS}
        buildable = rows - set(NOT_PORTED)
        shipped = {adapter.adapter_id.value for adapter in WP27_ADAPTERS}
        assert len(buildable) == 11
        assert shipped | set(PENDING_WP27) | set(DEFERRED_WP41) == buildable
        assert len(shipped) + len(PENDING_WP27) + len(DEFERRED_WP41) == 11

    def test_ruling_nine_leaves_nine_adapters_for_this_work_package(self):
        """Ruling 9's arithmetic, reconciled and derived rather than
        asserted.

        The ruling states the WP-2.7 population as **10, not 12**: the
        twelve §3-3 rows less the two deferred ones. Nine of those ten are
        BUILT — the tenth is `convergence_tracker`, which §4-3 rules out as
        an adapter altogether and which was already excluded from the
        sheet's own "実移植は 11" count. So the totality shape is
        34 declared / 33 buildable / 31 built / 2 deferred, and 31 is
        22 + 9 rather than 22 + 10.
        """
        from v3.adapters.catalog import (ALL_ADAPTERS, DEFERRED_WP41,
                                         PENDING_WP27, WP26_ADAPTERS,
                                         WP27_ADAPTERS, buildable_adapter_ids,
                                         declared_adapter_ids)
        assert len(declared_adapter_ids()) == 34
        assert len(buildable_adapter_ids()) == 33
        assert len(DEFERRED_WP41) == 2
        if not PENDING_WP27:                       # the finished shape
            assert len(WP26_ADAPTERS) == 22
            assert len(WP27_ADAPTERS) == 9
            assert len(ALL_ADAPTERS) == 31
            assert len(buildable_adapter_ids()) - len(DEFERRED_WP41) == 31


class TestTheRosterMatchesTheDesignSheet:
    def test_the_transcription_matches_the_document(self):
        assert _design_sheet_rows() == list(WP26_DESIGN_SHEET_ROWS)

    def test_the_sheet_lists_twenty_two_adapters(self):
        assert len(WP26_DESIGN_SHEET_ROWS) == 22

    def test_every_declared_adapter_is_built(self):
        """Sheet order, across both batches.

        Comparing `WP26_ADAPTERS` alone stopped being the whole roster the
        moment WP-2.7 shipped its first declaration; the tuple compared
        here is the one `expected_adapter_ids()` derives, so a §3-3 row
        landing out of order fails just as a §3-2 one would.
        """
        from v3.adapters.catalog import ALL_ADAPTERS
        assert tuple(adapter.name for adapter in ALL_ADAPTERS) == \
            expected_adapter_ids()

    def test_no_adapter_is_built_that_the_sheet_does_not_list(self):
        from v3.adapters.catalog import ALL_ADAPTERS
        assert set(adapter.name for adapter in ALL_ADAPTERS) == \
            set(expected_adapter_ids())

    def test_the_only_rename_is_the_one_the_sheet_mandates(self):
        """DP6/§7-2 #5: the sensor called itself FIRMS and fetched EONET."""
        assert DESIGN_SHEET_RENAMES == {"nasa_firms": "nasa_eonet"}


class TestTheExpectedDifferenceRegister:
    """§7-2 read from the document. P2 §5-C makes an unregistered
    difference a cutover abort, so the register is a contract, not a note:
    a WP-2.6 adapter that behaves differently from live v2 must appear
    here or must be changed back.
    """

    @staticmethod
    def _registered() -> list[str]:
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 7-2.")[1].split("\n## ")[0]
        return re.findall(r"^\|\s*\d+\s*\|\s*`([a-z0-9_]+)`", section,
                          flags=re.MULTILINE)

    def test_threatfox_zero_hit_observations_are_registered(self):
        """S1-SENS-014 says a country with no hits MUST NOT appear; the
        port emits an OK observation for it anyway, so that "nothing seen"
        and "not looked at" stop being the same absence (NP1). Sound, and
        still a processing difference — so it is registered rather than
        left for the parity harness to discover."""
        assert "threatfox" in self._registered()

    def test_the_ct_log_score_three_ceiling_is_registered(self):
        """RULING #4. While the untrusted-CA verdict stays OBSERVED-
        pending, a payload legacy scores 3 scores at most 2 here. That is
        the *insensitive* direction — the one class that aborts cutover
        under C-02/C-03 — so it is registered now rather than after
        someone sees whether the L1 wiring lands first. Registering
        something that later becomes moot costs nothing; the reverse
        costs the cutover."""
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 7-2.")[1].split("\n## ")[0]
        row = [line for line in section.splitlines()
               if line.startswith("| 8 ") and "`ct_log`" in line]
        assert len(row) == 1, "§7-2 #8 (ct_log score-3 ceiling) is missing"
        assert "insensitive" in row[0]

    def test_every_registered_name_is_a_real_adapter_or_a_known_rename(self):
        known = set(expected_adapter_ids()) | set(DESIGN_SHEET_RENAMES)
        wp27 = {"hacktivist_news", "travel_advisory"}   # §3-3, not this WP
        assert set(self._registered()) - known - wp27 == set()

    def test_the_open_hand_offs_are_written_down_where_the_code_points(self):
        """Two adapter docstrings cite §3-5 — the ISR multi-zone gap and
        the AISHub envelope ruling request. A citation to a section that
        does not exist is how "raised for a ruling" became a claim nobody
        could check."""
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 3-5.")[1].split("\n## ")[0]
        assert "H-1" in section and "H-2" in section
        assert "ISR_HOTSPOTS" in section and "AISHub" in section
        assert "WP-4.1" in section          # H-1 names its landing WP
        assert "裁定待ち" in section          # H-2 says the ruling is open

    def test_ruling_nine_is_recorded_where_the_code_points(self):
        """`DEFERRED_WP41` cites §3-5 H-3 and 裁定要求 9. A citation to a
        section that does not say what the code claims is how "raised for
        a ruling" became an assertion nobody could check — the same
        failure `test_the_open_hand_offs_are_written_down_where_the_code_
        points` exists to prevent for H-1 and H-2.
        """
        from v3.adapters.catalog import DEFERRED_WP41
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 3-5.")[1].split("\n## ")[0]
        assert "H-3" in section
        for name in DEFERRED_WP41:
            assert f"`{name}`" in section, name
        # The ruling itself, not merely the request.
        assert "裁定（オーナー、2026-08-08）" in section
        assert "WP-4.1" in section

    def test_the_deferral_is_no_longer_an_open_ruling_request(self):
        """§8's entry must not still read as awaiting a decision. An open
        request and a closed one call for opposite actions from whoever
        picks the work package up next."""
        text = SPEC.read_text(encoding="utf-8")
        heading = [line for line in text.splitlines()
                   if line.startswith("### 裁定要求 9")]
        assert len(heading) == 1
        assert "裁定済み" in heading[0]

    def test_the_totality_the_ruling_states_is_the_one_the_code_derives(self):
        """The sheet's arithmetic and the catalog's must agree.

        The ruling as written says "22+10"; the sheet reconciles that to
        31 built, because `convergence_tracker` is one of the ten rows and
        is not an adapter (§4-3). Numbers restated in prose drift from
        numbers that are computed, so the prose is checked against the
        computation rather than trusted alongside it.
        """
        from v3.adapters.catalog import (DEFERRED_WP41, buildable_adapter_ids,
                                         declared_adapter_ids)
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 3-5.")[1].split("\n## ")[0]
        assert f"| declared | **{len(declared_adapter_ids())}** |" in section
        assert f"| buildable | **{len(buildable_adapter_ids())}** |" in section
        assert f"| deferred | **{len(DEFERRED_WP41)}** |" in section
        built = len(buildable_adapter_ids()) - len(DEFERRED_WP41)
        assert f"| built（完了時） | **{built}** |" in section

    def test_the_retired_parity_difference_says_what_replaced_it(self):
        """§7-2 #38 was fixed rather than carried. A register entry that
        is simply deleted leaves a reader unable to tell a repaired
        difference from one nobody wrote down."""
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 7-2.")[1].split("\n## ")[0]
        row = [line for line in section.splitlines()
               if line.startswith("| 38 ")]
        assert len(row) == 1
        assert "RETIRED" in row[0]
        assert "_age_weight" in row[0]
        assert "S5-VERIF-031" in row[0]

    def test_the_split_is_seven_cyber_and_fifteen_physical(self):
        registry = build_registry()
        assert len(registry.by_category("cyber")) == 7
        assert len(registry.by_category("physical")) == 15

    def test_exactly_two_adapters_are_disabled_and_both_say_why(self):
        disabled = build_registry().disabled()
        assert [adapter.name for adapter in disabled] == \
            ["ihr_health", "notam"]
        assert all(adapter.disabled_reason for adapter in disabled)

    def test_every_identifier_resolves_through_the_registry(self):
        """F-02: a name that resolves nowhere used to be indistinguishable
        from one naming a disabled adapter."""
        registry = build_registry()
        for name in expected_adapter_ids():
            assert registry.get(registry.resolve(name)).name == name
        with pytest.raises(Exception):
            registry.resolve("cf")      # the F-02 string itself


class TestTheDeclarationsAreWellFormed:
    @pytest.mark.parametrize("adapter", WP26_ADAPTERS,
                             ids=lambda a: a.name)
    def test_each_adapter_declares_a_finite_freshness_horizon(self, adapter):
        assert adapter.freshness_horizon_sec > 0

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS,
                             ids=lambda a: a.name)
    def test_each_adapter_names_only_known_knowledge_items(self, adapter):
        assert unknown_refs(adapter.knowledge_refs) == frozenset()

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS,
                             ids=lambda a: a.name)
    def test_no_adapter_carries_a_credential_value(self, adapter):
        """Auth is a NAME for a secret; the composition root supplies the
        value. Nothing under `v3/` reads the environment."""
        if adapter.auth.is_required:
            assert adapter.auth.key_id and adapter.auth.key_id.isupper()

    def test_the_opensky_family_shares_one_rate_limit_group(self):
        groups = build_registry().rate_limit_groups()
        assert groups["opensky"] == ("isr_hotspot", "mil_support_air",
                                     "opensky")

    def test_the_required_secrets_are_the_expected_six(self):
        # THREE of the six moved to `optional_key_ids` — not because the
        # sources stopped wanting them, but because production runs without
        # them: OpenSky ships anonymous (config.env.example:90-91),
        # CertSpotter's free tier is tokenless. Declaring those mandatory
        # aborted the fetch with AUTH_MISSING before the socket opened.
        assert build_registry().required_key_ids() == (
            "CF_API_TOKEN", "GREYNOISE_API_KEY", "OWM_API_KEY",
            "THREATFOX_API_KEY")
        assert build_registry().optional_key_ids() == (
            "CERTSPOTTER_API_TOKEN", "OPENSKY_CLIENT_CREDENTIALS")

    def test_baseline_dependencies_are_declared_where_they_exist(self):
        """DP3: nine sensors kept detection state in process memory, so a
        restart cost detection capability silently. A declared dependency
        is visible in the registry; an instance dictionary is visible to
        nobody."""
        declared = {adapter.name: adapter.baseline_refs
                    for adapter in WP26_ADAPTERS if adapter.baseline_refs}
        assert set(declared) == {
            "opensky", "ais_maritime", "gps_jamming", "check_host",
            "ripe_atlas", "ripe_bgp", "ooni_censorship", "ct_log",
            "apt_intel", "cloudflare_radar"}


# ── 2. D1 §4's twenty facts, one test each ──────────────────────────────

class TestKnowledgeLedger:
    def test_the_twenty_items_are_all_transcribed(self):
        assert len(KNOWLEDGE) == 20
        assert sorted(KNOWLEDGE) == [f"K{n:02d}" for n in range(1, 21)]

    def test_the_design_sheet_declares_the_same_twenty(self):
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 3-1.")[1].split("### 3-2.")[0]
        assert set(re.findall(r"\bK(\d{2})\b", section)) == \
            {f"{n:02d}" for n in range(1, 21)}

    def test_every_fact_a_built_adapter_claims_has_a_test(self):
        """The invariant that survives a port in progress.

        Keying this to a batch label meant the check stopped moving as
        soon as WP-2.7 shipped its first adapter. Keyed to what the BUILT
        roster claims, it stays load-bearing throughout: an adapter that
        lands naming a fact with no test fails, and a test naming a fact
        no shipped adapter claims fails too.
        """
        from v3.adapters.catalog import ALL_ADAPTERS
        claimed = {ref for adapter in ALL_ADAPTERS
                   for ref in adapter.knowledge_refs}
        assert set(KNOWLEDGE_TESTS) == claimed

    def test_every_named_test_exists_somewhere_in_the_adapter_suites(self):
        """A mapping entry whose test was renamed away stops being a claim
        and starts being a lie.

        Searched across the adapter suites rather than this module alone —
        the WP-2.7 facts are pinned in `test_adapters_info.py`, and a
        check that only looked here would have reported them missing while
        they existed, or (worse) invited them to be written here away from
        the adapters they describe.
        """
        names: set = set()
        for path in sorted(REPO_ROOT.glob("tests/test_adapters_*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.FunctionDef):
                    names.add(node.name)
        for key, name in sorted(KNOWLEDGE_TESTS.items()):
            assert name in names, f"{key} names a missing test: {name}"

    def test_the_wp26_facts_are_all_claimed_by_a_wp26_adapter(self):
        claimed = {ref for adapter in WP26_ADAPTERS
                   for ref in adapter.knowledge_refs}
        assert claimed == WP26_KNOWLEDGE

    def test_the_other_five_facts_belong_to_the_next_batch(self):
        assert knowledge.WP27_KNOWLEDGE == frozenset(
            {"K07", "K08", "K13", "K18", "K20"})


class TestKnowledgeItems:
    """One item, one test, the fact written into the name (§6-2)."""

    def test_k01_opensky_three_adapters_share_one_rate_limit_group(self):
        from v3.adapters.physical import opensky
        for adapter in (opensky.OPENSKY_ADAPTER, opensky.ISR_HOTSPOT_ADAPTER,
                        opensky.MIL_SUPPORT_AIR_ADAPTER):
            assert adapter.rate_limit_group == "opensky"
            assert adapter.min_interval_sec == 10.0
        # A per-adapter limiter would let three adapters that each respect
        # the quota collectively exceed it.
        assert build_registry().rate_limit_groups()["opensky"] == (
            "isr_hotspot", "mil_support_air", "opensky")

    def test_k02_aishub_rate_limit_is_http_200_with_empty_body(self):
        """An empty body on a 200 is a throttle, not "no vessels". The
        kernel classifies it, and `normalize` returns nothing rather than
        an all-clear — because "no vessels near the chokepoint" is what a
        blockade looks like."""
        from v3.adapters.physical import ais_maritime
        empty = FetchedPayload(url="http://data.aishub.net/ws.php", status=200,
                               body=b"", fetched_at=T0, label="cp=X;lat=0;lon=0")
        drafts = ais_maritime.normalize(
            empty, NormalizeContext(adapter_id=AdapterId("ais_maritime"),
                                    now=T0, countries=("TW",)))
        assert drafts[0].flags["vessels_examined"] == 0
        assert drafts[0].status != "FIRED"

    def test_k03_checkhost_two_stage_request_id_flow_and_no_latency_penalty(
            self):
        from v3.adapters.physical import check_host
        from v3.adapters.types import RequestContinuation
        # K03's first fact is a CONTINUATION, not two independent requests:
        # the second one's address is inside the first one's answer. As two
        # requests, `{request_id}` was unresolvable at plan time and the
        # adapter was skipped every cycle (design sheet §2-4 row 8).
        declared, = check_host.CHECK_HOST_ADAPTER.requests
        assert isinstance(declared, RequestContinuation)
        labels = [spec.label for spec in declared.alternatives]
        assert labels == ["request", "result"]
        assert "{request_id}" in declared.then.url
        assert [value.placeholder for value in declared.carries] \
            == ["request_id"]
        assert declared.delay_sec == check_host.RESULT_DELAY_SEC
        assert check_host.RESULT_DELAY_SEC == 5.0
        # Latency never lowers the rate: a 9-second intercontinental check
        # that succeeded is a success.
        assert check_host.summarise_nodes(
            {"a.node": [[1, 9.0, "Found", "302", ""]],
             "b.node": [[1, 8.5, "Found", "302", ""]]})["success_rate"] == 1.0

    def test_k04_ooni_degrades_after_three_empty_cycles(self):
        from v3.adapters.cyber import ooni_censorship
        assert ooni_censorship.DEGRADED_AFTER_FAILURES == 3
        assert ooni_censorship.DEGRADED_CADENCE_SEC == 7200.0
        assert ooni_censorship.NORMAL_CADENCE_SEC == 1800.0

    def test_k05_ct_log_empty_200_is_authoritative_success(self):
        """Falling through to the next source after a 200-empty discards
        an answer and lets a slower source's staleness overwrite it."""
        from v3.adapters.cyber import ct_log
        empty = FetchedPayload(url="https://api.certspotter.com/v1/issuances",
                               status=200, body=b"[]", fetched_at=T0,
                               label="certspotter")
        drafts = ct_log.normalize(
            empty, NormalizeContext(adapter_id=AdapterId("ct_log"), now=T0,
                                    countries=("TW",)))
        assert len(drafts) == 1 and drafts[0].flags["total_recent"] == 0

    def test_k06_ihr_is_reached_at_the_www_ihr_live_mirror(self):
        """`ihr.iijlab.net` 301s here; behind a proxy that hop times out."""
        from v3.adapters.physical import ihr_health
        assert ihr_health.IHR_API_BASE == "https://www.ihr.live/ihr/api"
        assert all(spec.url.startswith("https://www.ihr.live")
                   for spec in ihr_health.IHR_HEALTH_ADAPTER.requests)

    def test_k09_cisa_advisory_feed_url_is_the_moved_one(self):
        """The URL is asserted against the LIVE sensor rather than a
        literal. This test previously held a literal the port had
        invented, so it certified the drift it existed to catch —
        `tests/test_adapters_cyber.py::TestAptIntel` parses
        `_CERT_SOURCES` and pins all five."""
        from v3.adapters.cyber import apt_intel
        assert "/cybersecurity-advisories/" in apt_intel.CISA_ADVISORIES_URL
        assert apt_intel.CISA_ADVISORIES_URL == \
            dict(apt_intel.FEEDS)["cisa_advisories"]
        # Akamai answers 403 to script user-agents.
        assert apt_intel.APT_INTEL_ADAPTER.requests[0].headers[
            "User-Agent"].startswith("Mozilla/")

    def test_k10_threatfox_sends_auth_key_on_get_iocs(self):
        """It did not always need one; today a keyless call is a 401, and
        a 401 that keeps the old cache looks like a quiet day."""
        from v3.adapters.cyber import threatfox
        auth = threatfox.THREATFOX_ADAPTER.auth
        assert auth.is_required and auth.key_id == "THREATFOX_API_KEY"
        assert auth.name == "Auth-Key" and auth.value_template == "{secret}"
        # A JSON BODY, as production sends it (`threatfox.py:20,42`) — the
        # first port made it a query string, which abuse.ch does not read.
        spec = threatfox.THREATFOX_ADAPTER.requests[0]
        assert spec.method == "POST" and spec.params == ()
        assert spec.body["query"] == "get_iocs"

    def test_k11_greynoise_gnql_failure_is_permanent_and_still_a_success(self):
        """410 (v2 retired), 401 (community key), 403/429 (tier, rate) are
        structural unavailability. Treating them as failures manufactures
        a permanently DEGRADED sensor nobody reads any more."""
        from v3.adapters.cyber import greynoise
        # A body that does not parse into the shape production reads
        # (`greynoise.py:192-197`). `b"{}"` is NOT that: production's two
        # chained `.get(..., default)` calls make an empty object a
        # MEASURED zero (TARGETED, ratio 0%), not an unobtainable one.
        empty = FetchedPayload(url="https://api.greynoise.io/x", status=200,
                               body=b"not json", fetched_at=T0,
                               label="gnql:TW")
        draft = greynoise.normalize(
            empty, NormalizeContext(adapter_id=AdapterId("greynoise"),
                                    now=T0, countries=("TW",)))[0]
        assert draft.flags["noise_class"] == "UNKNOWN"
        assert draft.flags["suppress_confidence"] is False

    def test_k12_gpsjam_discovers_the_newest_day_from_the_manifest(self):
        """Today's tiles do not exist; asking for them returns nothing,
        which reads as calm."""
        from v3.adapters.physical import gps_jamming
        manifest = (FIXTURES / "gps_jamming" / "manifest.csv").read_text()
        assert gps_jamming.latest_manifest_date(manifest) == "2026-08-06"
        assert gps_jamming.latest_manifest_date("") == ""
        assert gps_jamming.GPS_JAMMING_ADAPTER.requests[0].label == "manifest"

    def test_k14_notam_is_disabled_because_no_free_api_exists(self):
        from v3.adapters.physical import notam
        assert notam.NOTAM_ADAPTER.enabled is False
        assert "no free international NOTAM API" in \
            notam.NOTAM_ADAPTER.disabled_reason

    def test_k15_courtesy_delays_are_declared_not_slept(self):
        """RIPE 0.3s, GreyNoise 0.5s, PeeringDB 10s, OONI 0.5s — one
        mechanism, not four sleeps inside four fetch functions."""
        registry = build_registry()
        expected = {"ripe_bgp": 0.3, "greynoise": 0.5, "peeringdb_ixp": 10.0,
                    "ooni_censorship": 0.5, "ripe_atlas": 0.3}
        for name, interval in expected.items():
            adapter = registry.get(registry.resolve(name))
            assert adapter.min_interval_sec == interval, name

    def test_k16_usgs_nuclear_candidate_needs_magnitude_depth_and_territory(
            self):
        from v3.adapters.physical import usgs_seismic
        assert usgs_seismic.NUCLEAR_MIN_MAGNITUDE == 4.0
        assert usgs_seismic.NUCLEAR_MAX_DEPTH_KM == 10.0
        assert usgs_seismic.TERRITORY_HALF_DEG == 5.0

    def test_k17_space_weather_suppresses_at_kp_six_or_xray_class_m(self):
        from v3.adapters.physical import space_weather
        assert space_weather.KP_SUPPRESS_THRESHOLD == 6.0
        assert space_weather.XRAY_SUPPRESS_CLASS == "M"
        assert space_weather.XRAY_CLASS_ORDER["M"] == 3

    def test_k19_ioda_falls_back_to_cloudflare_radar(self):
        from v3.adapters.physical import ioda_bgp
        # A CHAIN, not two unconditional requests: production reaches
        # Cloudflare only when `_fetch_ioda_proper` returns None
        # (`radar/sensors/ioda.py:49-55`). Fetching both let a Cloudflare
        # anomaly FIRED-override IODA's OK.
        chain = ioda_bgp.IODA_BGP_ADAPTER.requests[0]
        assert isinstance(chain, RequestChain)
        assert [spec.label for spec in chain.alternatives] == [
            "ioda", "cf_fallback"]
        assert "ioda.inetintel" in chain.alternatives[0].url
        assert "cloudflare" in chain.alternatives[1].url
        # ...and the fallback carries Cloudflare's own credential, because
        # the primary needs none.
        assert chain.alternatives[0].auth is None
        assert chain.alternatives[1].auth.key_id == "CF_API_TOKEN"


# ── 3. the four I/O barriers, across all 22 ─────────────────────────────

class _NoNetwork:
    """RECORDS connect attempts as well as refusing them (WP-2.5).

    The first version of this guard only raised, which a smuggled
    `HttpClient` defeats: the client catches `requests.RequestException`
    by design and returns a CONNECTION_ERROR outcome, so `normalize`
    returns normally and an exception-expecting barrier sees a clean run.
    Counting attempts detects the call regardless of who swallows it.

    `connect` is patched rather than the socket class, because replacing
    the class breaks import machinery and makes the test pass for the
    wrong reason.
    """

    def __init__(self):
        self.attempts = []

    def __enter__(self):
        guard = self
        self._connect = socket.socket.connect
        self._getaddrinfo = socket.getaddrinfo

        def refuse_connect(_self, address, *args, **kwargs):
            guard.attempts.append(("connect", address))
            raise AssertionError(f"normalize reached the network ({address})")

        def refuse_lookup(host, *args, **kwargs):
            # Resolution happens FIRST and fails before connect() is
            # called, so instrumenting connect alone missed the attempt.
            guard.attempts.append(("resolve", host))
            raise AssertionError(
                f"normalize reached the network (resolving {host})")

        socket.socket.connect = refuse_connect
        socket.getaddrinfo = refuse_lookup
        return self

    def __exit__(self, *exc):
        socket.socket.connect = self._connect
        socket.getaddrinfo = self._getaddrinfo

    @property
    def reached_the_network(self) -> bool:
        return bool(self.attempts)


def _fixture_payloads(adapter_name: str):
    directory = FIXTURES / adapter_name
    if not directory.is_dir():
        return []
    return [FetchedPayload(url=f"https://recorded.test/{path.name}",
                           status=200, body=path.read_bytes(), fetched_at=T0,
                           label=path.stem)
            for path in sorted(directory.iterdir()) if path.is_file()]


class TestBarrierFourAcrossEveryAdapter:
    """Executing every `normalize` with the network instrumented.

    Barriers 1-3 read signatures, imports and import-time effects; a
    `normalize` that CAPTURED a client at declaration time imports nothing
    when called and starts nothing when imported, so only this one sees
    it. WP-2.5 proved that on the exemplar; here it runs against all 22.
    """

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS, ids=lambda a: a.name)
    def test_normalize_never_reaches_the_network(self, adapter):
        context = NormalizeContext(
            adapter_id=adapter.adapter_id, now=T0, countries=("TW", "JP"),
            country_coordinates={"TW": (25.03, 121.5), "JP": (35.68, 139.7)},
            country_names={"TW": "Taiwan", "JP": "Japan"},
            chokepoints=(("Bashi Channel", 21.9, 121.0, "TW"),),
            adversaries=("CN",))
        payloads = _fixture_payloads(adapter.name) or [
            FetchedPayload(url="https://recorded.test/empty", status=200,
                           body=b"{}", fetched_at=T0)]
        with _NoNetwork() as guard:
            for payload in payloads:
                drafts = adapter.normalize(payload, context)
                assert isinstance(drafts, tuple)
                for draft in drafts:
                    assert isinstance(draft, ObservationDraft)
        assert guard.reached_the_network is False

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS, ids=lambda a: a.name)
    def test_normalize_emits_only_known_statuses(self, adapter):
        """A status outside the vocabulary reaches the scoring kernel as a
        string nothing admits — silently scoring zero."""
        context = NormalizeContext(
            adapter_id=adapter.adapter_id, now=T0, countries=("TW",),
            country_coordinates={"TW": (25.03, 121.5)},
            country_names={"TW": "Taiwan"},
            chokepoints=(("Bashi Channel", 21.9, 121.0, "TW"),),
            adversaries=("CN",))
        for payload in _fixture_payloads(adapter.name):
            for draft in adapter.normalize(payload, context):
                assert draft.status in ADAPTER_STATUSES, draft.status

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS, ids=lambda a: a.name)
    def test_normalization_is_deterministic(self, adapter):
        """Same bytes, same instant, same values — what makes a recorded
        fixture meaningful and a parity replay possible."""
        context = NormalizeContext(
            adapter_id=adapter.adapter_id, now=T0, countries=("TW",),
            country_coordinates={"TW": (25.03, 121.5)},
            country_names={"TW": "Taiwan"},
            chokepoints=(("Bashi Channel", 21.9, 121.0, "TW"),),
            adversaries=("CN",))
        for payload in _fixture_payloads(adapter.name):
            assert adapter.normalize(payload, context) == \
                adapter.normalize(payload, context)

    def test_malformed_bytes_never_raise(self):
        """One upstream serving nonsense must not abort the cycle for the
        other 21 adapters."""
        context = NormalizeContext(adapter_id=AdapterId("probe"), now=T0,
                                   countries=("TW",),
                                   country_coordinates={"TW": (25.0, 121.5)})
        for adapter in WP26_ADAPTERS:
            for body in (b"", b"\x00\x01not json", b"<html>nope</html>",
                         b"[]", b"{}", b"null"):
                payload = FetchedPayload(url="https://recorded.test/x",
                                         status=200, body=body,
                                         fetched_at=T0, label="result")
                assert isinstance(adapter.normalize(payload, context), tuple)


class TestBarriersTwoAndThree:
    def test_no_adapter_module_imports_an_http_or_socket_library(
            self, discipline_gate):
        forbidden = discipline_gate._HTTP_MODULES
        offenders = []
        for path in sorted(ADAPTERS_DIR.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                else:
                    continue
                for module in modules:
                    if any(module == entry or module.startswith(entry + ".")
                           or entry.startswith(module + ".")
                           for entry in forbidden):
                        offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []

    def test_the_gate_passes_over_the_whole_package(self, discipline_gate):
        assert discipline_gate.main(["v3/adapters"]) == 0

    def test_importing_every_adapter_starts_no_thread(self):
        """§1-2: import is inert. ~40 threads at import is what pointed the
        legacy suite at the production database."""
        before = threading.active_count()
        import importlib
        for module in ("v3.adapters.catalog", "v3.adapters.cyber.ct_log",
                       "v3.adapters.physical.opensky"):
            importlib.import_module(module)
        assert threading.active_count() == before

    def test_no_adapter_module_imports_the_legacy_package(self):
        for path in sorted(ADAPTERS_DIR.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            assert "import radar" not in source, path.name
            assert "from radar" not in source, path.name
