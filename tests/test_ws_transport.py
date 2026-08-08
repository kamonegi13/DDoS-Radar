"""P7 §1.3 — the socket layer, for the three events that have a publisher.

The transport was deferred through four work packages and the reason was
never the library: an event with no publisher is a name, and a channel
emitting half its contract is worse than none because a client cannot tell
"no change" from "not implemented". WP-4.1f closes three of the four — the
ranking gave `attention_update` its publisher — and registers the fourth
with the blocker named.

What is pinned here:

* `PUBLISHED_EVENTS` and `UNPUBLISHED_EVENTS` PARTITION `ws.EVENTS`, so a
  contract gap is arithmetic rather than prose;
* every payload is derived from a `TickReport`, so what a client receives
  is also in the tick's own record (AP4);
* the room is the scenario, and a room is told only its own rows;
* import is inert and needs no web framework.
"""
from __future__ import annotations

import pytest

from v3.api import ws
from v3.api import ws_publish as WP
from v3.api.registry import WS_TRANSPORT
from v3.kernel.errors import DomainError
from v3.runtime.tick import TickReport

SCENARIO = "taiwan_contingency"
OTHER = "korea_peninsula"
NOW = 1_786_000_000.0


def _report(**kwargs) -> TickReport:
    base = dict(
        tick_id="tick-1", now=NOW, scenario_ids=(SCENARIO, OTHER),
        planned=(), skipped=(), withheld={}, observations_written=0,
        health={SCENARIO: {"degraded": False}, OTHER: {"degraded": True}},
        conclusions={SCENARIO: {"threat_level": "TL3"}},
        credentials={}, suppressors={}, coverage={},
        attention={"snapshot_id": "attn-1", "computed_at": NOW,
                   "considered": 2, "changed": True,
                   "rows": [{"scenario_id": SCENARIO, "item_id": "c1",
                             "rank_position": 1, "score": 0.8},
                            {"scenario_id": OTHER, "item_id": "c2",
                             "rank_position": 2, "score": 0.2}]})
    base.update(kwargs)
    return TickReport(**base)


class TestTheContractIsPartitioned:
    def test_published_and_unpublished_cover_the_four_events_exactly(self):
        assert set(WP.PUBLISHED_EVENTS) | set(WP.UNPUBLISHED_EVENTS) == \
            set(ws.EVENTS)
        assert set(WP.PUBLISHED_EVENTS) & set(WP.UNPUBLISHED_EVENTS) == set()

    def test_three_of_the_four_have_publishers(self):
        assert len(WP.PUBLISHED_EVENTS) == 3
        assert list(WP.UNPUBLISHED_EVENTS) == [ws.NOTIFICATION_RESULT]

    def test_the_unpublished_event_names_its_blocker(self):
        reason = WP.UNPUBLISHED_EVENTS[ws.NOTIFICATION_RESULT]
        assert "通知系" in reason and reason.strip()

    def test_the_registry_defers_one_event_not_the_channel(self):
        assert WS_TRANSPORT.p7_id == "WS.notification_result"
        assert WS_TRANSPORT.owner.strip() and WS_TRANSPORT.reason.strip()

    def test_an_emission_of_an_unpublished_event_is_refused(self):
        with pytest.raises(DomainError) as excinfo:
            WP.Emission(room=ws.room_for(SCENARIO),
                        event=ws.NOTIFICATION_RESULT, payload={})
        assert "no publisher" in str(excinfo.value)

    def test_an_emission_outside_a_scenario_room_is_refused(self):
        with pytest.raises(DomainError):
            WP.Emission(room="theater:TW", event=ws.CONCLUSION_UPDATE,
                        payload={})


class TestThePayloadIsDerivedFromTheTick:
    def test_a_conclusion_update_is_emitted_for_the_scenario_that_changed(
            self):
        emissions = WP.emissions_for(_report())
        rooms = {(e.event, e.room) for e in emissions}
        assert (ws.CONCLUSION_UPDATE, ws.room_for(SCENARIO)) in rooms
        assert (ws.CONCLUSION_UPDATE, ws.room_for(OTHER)) not in rooms

    def test_sensor_status_follows_the_input_health(self):
        emissions = [e for e in WP.emissions_for(_report())
                     if e.event == ws.SENSOR_STATUS]
        assert {e.room for e in emissions} == {ws.room_for(SCENARIO),
                                               ws.room_for(OTHER)}

    def test_attention_update_tells_each_room_only_its_own_rows(self):
        emissions = [e for e in WP.emissions_for(_report())
                     if e.event == ws.ATTENTION_UPDATE]
        by_room = {e.room: e.payload for e in emissions}
        assert [row["item_id"]
                for row in by_room[ws.room_for(SCENARIO)]["attention"]] == \
            ["c1"]
        assert [row["item_id"]
                for row in by_room[ws.room_for(OTHER)]["attention"]] == ["c2"]

    def test_an_unchanged_ranking_publishes_nothing(self):
        """The ranker still returns its rows when it decided not to write
        them (`RankReport.rows` is populated either way), so the flag is
        the thing that must be read — publishing on rows alone would emit
        an `attention_update` on every tick for a ranking that did not
        move."""
        unchanged = _report()
        rows = list(unchanged.attention["rows"])
        assert rows, "the fixture must carry rows for this to mean anything"
        report = _report(attention={"snapshot_id": "attn-1",
                                    "computed_at": NOW, "considered": 2,
                                    "changed": False, "rows": rows})
        assert not [e for e in WP.emissions_for(report)
                    if e.event == ws.ATTENTION_UPDATE]

    def test_the_order_never_puts_a_rank_before_its_conclusion(self):
        events = [e.event for e in WP.emissions_for(_report())]
        assert events.index(ws.CONCLUSION_UPDATE) < \
            events.index(ws.ATTENTION_UPDATE)

    def test_every_payload_carries_the_tick_that_produced_it(self):
        for emission in WP.emissions_for(_report()):
            payload = emission.payload
            assert payload.get("tick_id") == "tick-1" or \
                payload.get("snapshot_id") == "attn-1"

    def test_a_tick_that_did_nothing_emits_nothing(self):
        report = _report(conclusions={}, health={}, attention={})
        assert WP.emissions_for(report) == ()

    def test_publish_hands_every_emission_to_the_emitter(self):
        seen = []
        emissions = WP.publish(
            lambda event, payload, room: seen.append((event, room)),
            _report())
        assert len(seen) == len(emissions) > 0
        assert seen == [(e.event, e.room) for e in emissions]

    def test_the_emissions_are_a_pure_function_of_the_report(self):
        report = _report()
        assert [e.as_dict() for e in WP.emissions_for(report)] == \
            [e.as_dict() for e in WP.emissions_for(report)]


class TestImportIsInert:
    def test_the_module_imports_without_a_web_framework(self):
        import subprocess
        import sys
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys, v3.api.ws_publish; "
             "print(any(m.startswith('flask') for m in sys.modules))"],
            capture_output=True, text=True, cwd=str(root), timeout=120)
        assert proc.stdout.strip() == "False", proc.stdout + proc.stderr

    def test_the_factory_exists_but_builds_nothing_at_import(self):
        assert callable(WP.create_channel)
