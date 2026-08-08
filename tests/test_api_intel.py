"""P7 R11 + C3 — the intel queue and its adjudication.

The deferral said "キューの裁定状態を持つ表がまだ無い". The table was never
the blocker: the state is a fold of `command_record`, the same mechanism
the proposal lifecycle and the user store use, so there is one place an
analyst decision is recorded and R9 already projects it.

What these tests are about:

* **`reject` means the row stops scoring.** Not "is marked rejected" —
  `observations_at` drops it, and the test breaks the edge to prove the
  assertion is load-bearing rather than incidental.
* **`revert` from `pending` raises.** Production matches zero rows and
  reports success, so an analyst's undo of a never-decided item is lost.
* **the NP7 envelope is present.** `GET /api/intel/pending/triage` was the
  one legacy endpoint that returned conclusions without the disclaimer.
"""
from __future__ import annotations

import json

import pytest

from v3.api import (ApiRequest, Principal, ReadContext, ReadOnlyLedger,
                    handle)
from v3.api import routes as R
from v3.api import registry as REG
from v3.api.vocabulary import ROLE_ANALYST, ROLE_VIEWER
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.conclusions import NP7_DISCLAIMER
from v3.intel import adjudication as A
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.kernel.evidence import Evidence
from v3.ledger.records import SignalObservation
from v3.runtime import scoring as SCORING

NOW = 1_800_000_000.0
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)
VIEWER = Principal(user_id="v-1", role=ROLE_VIEWER)


def _observation(store, *, source, at, country="TW", sensor="apt_intel"):
    store.append_signal(SignalObservation(
        tick_id=f"tick-{at:.0f}-{country}", sensor=sensor,
        signal_source=source, domain="cyber", country=country,
        evidence=Evidence.observe({}, source=sensor, observed_at=at,
                                  freshness_horizon_sec=86400.0),
        status="FIRED", raw_score=3.0, confidence=0.8,
        evidence_url="https://example.invalid/1"), at)


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "intel.db"))
    _observation(handle_, source=A.INTEL_SIGNAL_SOURCE, at=NOW - 60)
    _observation(handle_, source=A.INTEL_SIGNAL_SOURCE, at=NOW - 120,
                 country="JP")
    _observation(handle_, source="ripe_bgp", at=NOW - 30, sensor="ripe_bgp")
    yield handle_
    handle_.close()


def _read(store, *, now=NOW):
    return ReadContext(ledger=ReadOnlyLedger(store), now=now)


def _write(store, principal=ANALYST, *, now=NOW):
    return WriteContext(read=_read(store, now=now),
                        ledger=CommandLedger(store), principal=principal)


def _queue(store, *, params=None, now=NOW, principal=ANALYST):
    return handle(ApiRequest(method="GET", path="/api/v3/intel",
                             params=params or {}, principal=principal),
                  _read(store, now=now))


def _item_ids(store):
    return [str(row["id"]) for row in
            store.signals_between(NOW - 3600, NOW)
            if row["signal_source"] == A.INTEL_SIGNAL_SOURCE]


_DEFAULT_BODY = {"reason": "現地報道と一致"}


def _verb(store, item_id, verb, *, body=_DEFAULT_BODY, now=NOW,
          principal=ANALYST):
    return handle(
        ApiRequest(method="POST", path=f"/api/v3/intel/{item_id}/{verb}",
                   body=dict(body), principal=principal),
        _write(store, principal, now=now))


class TestTheQueueIsAProjectionNotATable:
    def test_only_llm_intel_rows_appear(self, store):
        body = _queue(store).as_dict()
        assert len(body["intel"]) == 2
        assert {item["signal_source"] for item in body["intel"]} == {
            A.INTEL_SIGNAL_SOURCE}

    def test_an_unjudged_item_is_pending_with_no_row_anywhere(self, store):
        body = _queue(store).as_dict()
        assert all(item["state"] == A.STATE_PENDING
                   for item in body["intel"])
        assert body["pending_count"] == 2
        assert store.count_commands() == 0

    def test_the_envelope_carries_np7(self, store):
        body = _queue(store).as_dict()
        assert body["final_judgment_disclaimer"] == NP7_DISCLAIMER

    def test_an_unknown_state_filter_is_a_400_naming_the_states(self, store):
        response = _queue(store, params={"state": "auto_confirmed"})
        assert response.status == 400
        assert A.STATE_PENDING in response.as_dict()["error_detail"][
            "detail"]["states"]

    def test_a_viewer_cannot_read_the_queue(self, store):
        assert _queue(store, principal=VIEWER).status == 403


class TestTheAdjudicationIsTheFold:
    def test_confirm_removes_the_item_from_the_pending_queue(self, store):
        item_id = _item_ids(store)[0]
        assert _verb(store, item_id, "confirm").status == 200
        body = _queue(store, params={"state": A.STATE_PENDING},
                      now=NOW + 1).as_dict()
        assert [item["item_id"] for item in body["intel"]] != [item_id]
        assert body["pending_count"] == 1

    def test_one_command_row_and_it_names_the_actor(self, store):
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "reject")
        rows = store.command_records()
        assert len(rows) == 1
        assert rows[0]["action"] == A.INTEL_REJECT
        assert rows[0]["actor_id"] == "a-1"
        assert rows[0]["target_kind"] == A.TARGET_INTEL

    def test_revert_from_pending_is_refused(self, store):
        item_id = _item_ids(store)[0]
        response = _verb(store, item_id, "revert")
        assert response.status == 400
        assert store.count_commands() == 0, (
            "a refused adjudication must leave no trace of a change that "
            "did not happen")

    def test_revert_after_a_decision_returns_it_to_the_queue(self, store):
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "reject")
        assert _verb(store, item_id, "revert", now=NOW + 1).status == 200
        state = A.intel_state(ReadOnlyLedger(store), item_id, until=NOW + 2)
        assert state["state"] == A.STATE_PENDING
        assert state["previous_state"] == A.STATE_REJECTED

    def test_the_same_decision_twice_is_refused(self, store):
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "confirm")
        assert _verb(store, item_id, "confirm", now=NOW + 1).status == 400

    def test_rejecting_demands_a_stated_basis(self, store):
        item_id = _item_ids(store)[0]
        assert _verb(store, item_id, "reject", body={}).status == 400

    def test_the_trail_shows_it(self, store):
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "reject")
        body = handle(ApiRequest(method="GET", path="/api/v3/decisions",
                                 params={"type": A.TARGET_INTEL},
                                 principal=ANALYST),
                      _read(store, now=NOW + 1)).as_dict()
        assert [row["action"] for row in body["decisions"]] == [
            A.INTEL_REJECT]


class TestRejectActuallyStopsTheScoring:
    """The reader. Without it, `reject` is a label an analyst believes."""

    def test_a_rejected_row_leaves_the_kernel_input(self, store):
        before = SCORING.observations_at(store, now=NOW)
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "reject")
        after = SCORING.observations_at(store, now=NOW + 1)
        assert len(after) == len(before) - 1

    def test_reverting_puts_it_back(self, store):
        baseline = len(SCORING.observations_at(store, now=NOW))
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "reject", now=NOW + 1)
        assert len(SCORING.observations_at(store, now=NOW + 2)) == baseline - 1
        _verb(store, item_id, "revert", now=NOW + 3)
        assert len(SCORING.observations_at(store, now=NOW + 4)) == baseline

    def test_the_edge_is_load_bearing(self, store, monkeypatch):
        """Mutation: blind the reader and the assertion above must fail.

        Otherwise "rejected intel does not score" would be a coincidence of
        the fixture rather than a property of the wiring.
        """
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "reject")
        monkeypatch.setattr(A, "rejected_ids",
                            lambda ledger, until=None: frozenset())
        # With the reader blinded the rejected row comes back, which is
        # exactly what the un-blinded case must not do.
        blinded = SCORING.observations_at(store, now=NOW + 1)
        monkeypatch.undo()
        assert len(blinded) == len(
            SCORING.observations_at(store, now=NOW + 1)) + 1

    def test_the_row_is_not_deleted(self, store):
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "reject")
        body = _queue(store, now=NOW + 1).as_dict()
        rejected = [item for item in body["intel"]
                    if item["item_id"] == item_id]
        assert rejected and rejected[0]["state"] == A.STATE_REJECTED, (
            "L1 is append-only and R11 must still show what was rejected — "
            "a row that vanishes makes 'I judged it' and 'I never saw it' "
            "look identical")


class TestTheSurfaceLedgerAgrees:
    def test_r11_and_c3_are_served(self):
        assert {"R11", "C3"} <= REG.served_ids()
        assert not ({"R11", "C3"} & REG.deferred_ids())

    def test_override_is_absent_and_the_registry_says_why(self):
        assert A.ACTIONS == (A.INTEL_CONFIRM, A.INTEL_REJECT, A.INTEL_REVERT)
        entry = [item for item in REG.SERVED if item.p7_id == "C3"][0]
        assert "override" in entry.summary

    def test_every_c3_route_is_a_declared_command(self):
        for route_id in ("C3c", "C3r", "C3v"):
            route = R.by_id(route_id)
            assert route is not None and route.side_effect is True
            assert route.access.minimum_role == ROLE_ANALYST

    def test_the_adjudication_state_survives_a_json_round_trip(self, store):
        item_id = _item_ids(store)[0]
        _verb(store, item_id, "confirm")
        state = A.intel_state(ReadOnlyLedger(store), item_id, until=NOW + 1)
        assert json.loads(json.dumps(state)) == state


class TestTheFoldRefusesNonsense:
    def test_an_unknown_action_is_not_a_command(self, store):
        with pytest.raises(DomainError):
            A.apply_revert({"state": A.STATE_PENDING}, target_id="1",
                           payload={}, actor_id="a", at=NOW)
