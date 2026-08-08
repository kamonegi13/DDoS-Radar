"""P7 R13 / C5 — the unified proposal queue and its adjudication, served.

WP-3.3 landed the queue and the state machine; this is the L6 binding the
registry said was all that remained. What the tests pin is that the
binding did not quietly acquire semantics of its own:

* the queue R13 serves is `v3/calibration/queue.py::entries`, so the state
  of a row is the fold of its adjudication commands and not a column;
* `?at=` bounds BOTH the emission window and the fold;
* an ILLEGAL transition is a 400 the analyst can see. Production's UPDATE
  matches zero rows and reports success, so a dismissal an analyst
  believes they made is silently lost — the G-01 shape one layer over;
* the deferred-proposal defect (裁定要求 11) is PRESERVED, not fixed here.
"""
from __future__ import annotations

import pytest

from tests.conclusions_fixtures import NOW
from v3.api import (ApiRequest, Principal, ReadContext, ReadOnlyLedger,
                    ScenarioRef, handle)
from v3.api.vocabulary import ROLE_ANALYST, ROLE_VIEWER
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.calibration import lifecycle as L
from v3.conclusions import NP7_DISCLAIMER
from v3.ledger import LedgerStore
from v3.ledger.records import ProposalRecord

SCENARIO = "taiwan_contingency"
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)
VIEWER = Principal(user_id="v-1", role=ROLE_VIEWER)
PROPOSAL_ID = "p-1"


def _record(proposal_id=PROPOSAL_ID, *, emitted_at=None,
            proposal_type=L.TYPE_TL_THRESHOLD, key="tl1_total"):
    return ProposalRecord(
        proposal_id=proposal_id, proposal_type=proposal_type,
        scenario_id=SCENARIO, proposal_key=key, impact="low",
        emitted_at=NOW - 3600.0 if emitted_at is None else emitted_at,
        epoch_id="e2026_08_02", formula_ref="S1-CALIB-015",
        prior_value=9.0, proposed_value=8.55, direction="looser",
        sample_n=24, evidence={"tp": 6, "fn": 5},
        payload={"band": "tl1_total"})


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "proposals.db"))
    handle_.append_proposal(_record(), now=NOW)
    yield handle_
    handle_.close()


def _read_context(store, *, now=NOW, principal=ANALYST):
    return ReadContext(ledger=ReadOnlyLedger(store), now=now,
                       principal=principal,
                       scenarios=(ScenarioRef(scenario_id=SCENARIO),))


def _write_context(store, principal=ANALYST, *, now=NOW):
    return WriteContext(read=_read_context(store, now=now,
                                           principal=principal),
                        ledger=CommandLedger(store), principal=principal)


def _get(store, path, params=None, principal=ANALYST, *, now=NOW):
    return handle(ApiRequest(method="GET", path=path, params=params or {},
                             principal=principal),
                  _read_context(store, now=now, principal=principal))


def _post(store, path, body=None, principal=ANALYST, *, now=NOW):
    return handle(ApiRequest(method="POST", path=path, body=body or {},
                             principal=principal),
                  _write_context(store, principal, now=now))


class TestTheQueueIsOneProjection:
    def test_r13_serves_the_emitted_row_with_its_folded_state(self, store):
        body = _get(store, "/api/v3/proposals").as_dict()
        assert len(body["proposals"]) == 1
        row = body["proposals"][0]
        assert row["proposal_id"] == PROPOSAL_ID
        assert row["state"] == L.PENDING
        assert row["adjudications"] == []
        assert row["is_terminal"] is False
        assert body["pending"] == 1

    def test_the_response_discloses_the_state_machine(self, store):
        body = _get(store, "/api/v3/proposals").as_dict()
        assert body["states"] == list(L.STATES)
        assert body["kinds"] == list(L.PROPOSAL_TYPES)
        assert body["vocabulary"]["allowed_from"]
        assert body["final_judgment_disclaimer"] == NP7_DISCLAIMER

    def test_pending_is_the_absence_of_an_adjudication_not_a_column(self,
                                                                    store):
        rows = store.proposals_between(NOW - 86400, NOW)
        assert "state" not in rows[0]

    def test_an_unknown_state_filter_is_refused(self, store):
        assert _get(store, "/api/v3/proposals",
                    {"state": "accepted"}).status == 400

    def test_a_kind_filter_narrows(self, store):
        assert _get(store, "/api/v3/proposals",
                    {"kind": L.TYPE_SENSOR_DISABLE}
                    ).as_dict()["proposals"] == []

    def test_a_read_writes_nothing(self, store):
        before = store.count_commands()
        _get(store, "/api/v3/proposals")
        assert store.count_commands() == before


class TestAdjudicationIsACommand:
    def test_applying_moves_the_state_and_leaves_one_audit_row(self, store):
        before = store.count_commands()
        response = _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/apply",
                         {"reason": "recall が床を割ったため"})
        assert response.status == 200
        assert store.count_commands() == before + 1
        assert _get(store, "/api/v3/proposals").as_dict()[
            "proposals"][0]["state"] == L.APPLIED

    def test_the_reason_is_required(self, store):
        response = _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/dismiss")
        assert response.status == 400
        assert "reason" in str(response.as_dict()["error_detail"])

    def test_an_illegal_transition_is_visible_rather_than_silent(self, store):
        _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/apply",
              {"reason": "適用"})
        second = _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/dismiss",
                       {"reason": "やはり却下"})
        assert second.status == 400, (
            "production's UPDATE matches zero rows and reports success, so "
            "the analyst is not told their decision was lost")

    def test_the_history_is_the_decision_trail(self, store):
        _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/defer",
              {"reason": "様子を見る"})
        row = _get(store, "/api/v3/proposals").as_dict()["proposals"][0]
        assert row["state"] == L.SNOOZED_30D
        assert len(row["adjudications"]) == 1
        assert row["adjudications"][0]["actor_id"] == ANALYST.user_id
        # A9: production tells an analyst decision from an automatic one by
        # a marker inside a text column. Here the actor is a field, and an
        # analyst id does not carry the automation prefix.
        assert not row["adjudications"][0]["actor_id"].startswith("auto:")

    def test_an_unknown_proposal_is_404(self, store):
        assert _post(store, "/api/v3/proposals/nope/apply",
                     {"reason": "x"}).status == 404

    def test_a_viewer_may_not_adjudicate(self, store):
        assert _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/apply",
                     {"reason": "x"}, principal=VIEWER).status == 403

    def test_there_is_no_route_for_the_automatic_edges(self):
        """A9: production distinguishes an analyst decision from an
        automatic one by a marker string. Here the analyst simply has no
        verb for the transitions an automaton makes."""
        from v3.api import routes as R
        paths = [route.path for route in R.ROUTES]
        assert not [p for p in paths if p.endswith("/revive")]
        assert not [p for p in paths if p.endswith("/supersede")]


class TestReplayIsTheSameProjection:
    def test_at_shows_the_state_that_was_in_force_then(self, store):
        _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/apply",
              {"reason": "適用"}, now=NOW + 60)
        live = _get(store, "/api/v3/proposals", now=NOW + 120).as_dict()
        past = _get(store, "/api/v3/proposals", {"at": str(NOW)},
                    now=NOW + 120).as_dict()
        assert live["proposals"][0]["state"] == L.APPLIED
        assert past["proposals"][0]["state"] == L.PENDING

    def test_at_also_bounds_the_emission_window(self, store):
        store.append_proposal(_record("p-2", emitted_at=NOW + 300),
                              now=NOW + 300)
        past = _get(store, "/api/v3/proposals", {"at": str(NOW)},
                    now=NOW + 600).as_dict()
        assert [row["proposal_id"] for row in past["proposals"]] == \
            [PROPOSAL_ID]


class TestTheDeferDefectIsPreservedNotFixed:
    """裁定要求 11, ruled 2026-08-08.

    Production revives a deferred proposal into `pending` without moving
    `emitted_at`, and auto-dismiss reads `emitted_at`; with snooze and
    staleness both at 30 days a deferral is a dismissal with a delay. The
    ruling is to PRESERVE it — a calibration-lifecycle change inside the
    parity window makes a later difference un-attributable — so this test
    exists to make a silent "fix" fail rather than pass.
    """

    def test_the_two_windows_are_still_equal(self):
        assert L.SNOOZE_SEC == L.ACTIONABLE_STALE_SEC == 30 * 86400.0

    def test_revival_does_not_survive_the_staleness_check(self):
        assert L.defer_survives_revival(
            emitted_at=NOW, deferred_at=NOW + 86400.0,
            proposal_type=L.TYPE_TL_THRESHOLD) is False

    def test_deferring_through_the_api_reaches_the_preserved_edge(self,
                                                                  store):
        response = _post(store, f"/api/v3/proposals/{PROPOSAL_ID}/defer",
                         {"reason": "保留"})
        assert response.status == 200
        assert _get(store, "/api/v3/proposals").as_dict()[
            "proposals"][0]["state"] == L.SNOOZED_30D
