"""The websocket vocabulary. One channel, four events, no `theater`.

C-01's deepest layer was here: the room key was `theater:{COUNTRY}`, so a
scenario spanning several countries could never be one room, and the
`threat_update` payload had to carry a `__ws_scenario_id` tag bolted on
afterwards to say which scenario a country's update belonged to. Focus
switching raced against that tag.

P7 §1.3 and S2-PROP-020 settle it: the room is the scenario, the tag
becomes unnecessary because the room already is the answer, and two
events are absorbed rather than renamed — `ambush_alert` (DDoS-era
vocabulary) and `sequence_event` both become `conclusion_update` of the
anomaly type, so a client has one thing to subscribe to instead of three
that could disagree.

This module is vocabulary only. The socket layer lands with the command
surface (registered in `v3.api.registry` as deferred); declaring the
names now is what lets the tests refuse the retired ones today rather
than after a client has been written against them.
"""
from __future__ import annotations

from v3.api.vocabulary import FORBIDDEN_RESPONSE_KEYS
from v3.kernel.errors import DomainError

ROOM_PREFIX = "scenario:"

CONCLUSION_UPDATE = "conclusion_update"
ATTENTION_UPDATE = "attention_update"
SENSOR_STATUS = "sensor_status"
NOTIFICATION_RESULT = "notification_result"

#: P7 §1.3 — the whole channel. Four events, not ten.
EVENTS: tuple[str, ...] = (CONCLUSION_UPDATE, ATTENTION_UPDATE,
                           SENSOR_STATUS, NOTIFICATION_RESULT)

#: What each retired event became. `None` means "absorbed with no
#: replacement name of its own", which is a disposition, not a gap.
RETIRED_EVENTS: dict = {
    "threat_update": CONCLUSION_UPDATE,
    "ambush_alert": CONCLUSION_UPDATE,
    "sequence_event": CONCLUSION_UPDATE,
    "intel_update": CONCLUSION_UPDATE,
    "subscribe_theater": "subscribe_scenario",
    "unsubscribe_theater": "unsubscribe_scenario",
}

SUBSCRIBE = "subscribe_scenario"
UNSUBSCRIBE = "unsubscribe_scenario"


def room_for(scenario_id: str) -> str:
    """`scenario:{sid}`. The room IS the scenario (S2-PROP-020).

    A country-keyed room cannot be one-to-one with focus, because a
    scenario has several participants — which is why the legacy payload
    needed a `__ws_scenario_id` tag and why switching focus raced it.
    """
    if not isinstance(scenario_id, str) or not scenario_id.strip():
        raise DomainError("a room needs a non-empty scenario_id")
    cleaned = scenario_id.strip()
    for word in FORBIDDEN_RESPONSE_KEYS:
        if word in cleaned.lower():
            raise DomainError(
                f"room {cleaned!r} uses retired vocabulary: the room key "
                f"is the scenario id (C-01)")
    return f"{ROOM_PREFIX}{cleaned}"


def scenario_of(room: str) -> str:
    if not isinstance(room, str) or not room.startswith(ROOM_PREFIX):
        raise DomainError(
            f"{room!r} is not a v3 room; rooms are '{ROOM_PREFIX}<sid>'")
    return room[len(ROOM_PREFIX):]


__all__ = ["EVENTS", "RETIRED_EVENTS", "ROOM_PREFIX", "SUBSCRIBE",
           "UNSUBSCRIBE", "CONCLUSION_UPDATE", "ATTENTION_UPDATE",
           "SENSOR_STATUS", "NOTIFICATION_RESULT", "room_for",
           "scenario_of"]
