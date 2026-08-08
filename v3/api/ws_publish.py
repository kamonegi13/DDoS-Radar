"""P7 §1.3's transport — the three events that have a publisher.

`v3/api/ws.py` is the vocabulary; this is the wire. It was deferred as a
whole until now for a stated reason, and the reason was never the socket
library: **an event with no publisher is a name, and a channel that emits
half its contract is worse than none, because a client cannot tell "no
change" from "not implemented".**

Of the four events, three now have a publisher and one does not:

    conclusion_update   `TickReport.conclusions` (WP-4.1e wired the tick)
    sensor_status       `TickReport.health`
    attention_update    `TickReport.attention` (WP-4.1f, this package)
    notification_result NO PUBLISHER — v3 has no notification subsystem
                        at all. Not a binding that is missing: there is
                        nothing that sends a Telegram message, so there is
                        no result to report. Registered as deferred rather
                        than emitted empty, and `UNPUBLISHED_EVENTS` is
                        what a client reads to know that.

**The payload is derived, not invented.** `emissions_for` is a pure
function of one `TickReport`, so every byte on the socket is also in the
tick's own record — an event whose content is not in the ledger is an
event nobody can check afterwards, which is the AP4 hole this whole work
package exists to close.

**Import is inert and Flask-SocketIO is imported inside the factory**, the
same contract `v3/api/binding.py` holds: the handler layer stays importable
in an environment with no web framework at all.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from v3.api import ws
from v3.kernel.errors import DomainError

#: Events this transport can actually put on the wire, and the one it
#: cannot. Named rather than implied: `EVENTS - PUBLISHED` is the contract
#: gap, and a test asserts the two partition `ws.EVENTS` exactly.
PUBLISHED_EVENTS: tuple[str, ...] = (ws.CONCLUSION_UPDATE, ws.SENSOR_STATUS,
                                     ws.ATTENTION_UPDATE)

UNPUBLISHED_EVENTS: dict = {
    ws.NOTIFICATION_RESULT:
        "発行者が存在しない。v3 に通知系（Telegram 送出とその結果）が"
        "まだ無いため、報告すべき『結果』そのものが無い。空で流すと"
        "『通知が成功した』と読めるため出さない（WP-4.2 / 通知スライス）",
}


@dataclass(frozen=True, slots=True)
class Emission:
    """One event, its room, and its payload. A value, not a side effect.

    Separating "what would be sent" from "sending it" is what makes the
    transport testable without a socket — and it is the same separation
    that keeps the payload a pure function of the tick report.
    """

    room: str
    event: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.event not in PUBLISHED_EVENTS:
            raise DomainError(
                f"{self.event!r} has no publisher. The channel's four events "
                f"are {list(ws.EVENTS)}; this transport emits "
                f"{list(PUBLISHED_EVENTS)} and refuses the rest, because an "
                f"event emitted empty reads as 'it happened and there was "
                f"nothing to report'.")
        if not self.room.startswith(ws.ROOM_PREFIX):
            raise DomainError(
                f"{self.room!r} is not a v3 room; the room IS the scenario "
                f"(S2-PROP-020, C-01's deepest layer)")
        if not isinstance(self.payload, Mapping):
            raise DomainError("an emission's payload is a mapping")
        object.__setattr__(self, "payload", dict(self.payload))

    def as_dict(self) -> dict:
        return {"room": self.room, "event": self.event,
                "payload": dict(self.payload)}


def _report_field(report, name: str) -> Mapping:
    value = getattr(report, name, None)
    return dict(value) if isinstance(value, Mapping) else {}


def emissions_for(report) -> tuple:
    """Every event one tick produces, in a fixed order. Pure.

    Ordered conclusions -> sensors -> attention, per scenario, because a
    client applying them in receipt order must never see a ranking that
    refers to a conclusion it has not been told about yet.
    """
    scenario_ids = tuple(getattr(report, "scenario_ids", ()) or ())
    conclusions = _report_field(report, "conclusions")
    health = _report_field(report, "health")
    attention = _report_field(report, "attention")
    tick_id = getattr(report, "tick_id", None)
    observed_at = getattr(report, "now", None)
    built = []
    for scenario_id in scenario_ids:
        room = ws.room_for(scenario_id)
        if scenario_id in conclusions:
            built.append(Emission(
                room=room, event=ws.CONCLUSION_UPDATE,
                payload={"scenario_id": scenario_id, "tick_id": tick_id,
                         "observed_at": observed_at,
                         "conclusions": conclusions[scenario_id]}))
        if scenario_id in health:
            built.append(Emission(
                room=room, event=ws.SENSOR_STATUS,
                payload={"scenario_id": scenario_id, "tick_id": tick_id,
                         "observed_at": observed_at,
                         "input_health": health[scenario_id]}))
    # The ranking is cross-scenario by construction (R6 ranks every
    # scenario's findings together), so each room is told the rows that
    # concern IT — a client must not learn another scenario's rank from a
    # room it subscribed to for this one.
    if attention.get("changed"):
        rows = list(attention.get("rows") or [])
        for scenario_id in scenario_ids:
            mine = [row for row in rows
                    if str(row.get("scenario_id")) == scenario_id]
            if not mine:
                continue
            built.append(Emission(
                room=ws.room_for(scenario_id), event=ws.ATTENTION_UPDATE,
                payload={"scenario_id": scenario_id,
                         "snapshot_id": attention.get("snapshot_id"),
                         "computed_at": attention.get("computed_at"),
                         "considered": attention.get("considered"),
                         "attention": mine}))
    return tuple(built)


def publish(emitter: Callable, report) -> tuple:
    """Hand every emission to `emitter(event, payload, room)`. Returns them.

    Takes a callable rather than a socketio object so the composition root
    decides what "emit" means — and so this function can be exercised
    against a list in a test that has no server.
    """
    emissions = emissions_for(report)
    for emission in emissions:
        emitter(emission.event, dict(emission.payload), emission.room)
    return emissions


def create_channel(socketio, *, scenario_ids: Optional[Callable] = None,
                   principal_factory: Optional[Callable] = None):
    """Register the subscribe/unsubscribe verbs. Returns an emitter.

    `flask_socketio` is imported HERE, inside the factory, so importing
    this module costs nothing and `v3/api/` stays importable without a web
    framework. The returned callable is what `publish` takes, which is the
    only way anything reaches the wire.

    Subscription is authorized the same way a route is: the composition
    root supplies the principal, and an anonymous socket gets nothing. A
    socket that could subscribe without a principal would be a read path
    around `v3/api/authorization.py`, i.e. G-01 in a second doorway.
    """
    from flask_socketio import emit, join_room, leave_room

    def _principal():
        return None if principal_factory is None else principal_factory()

    def _known(scenario_id: str) -> bool:
        if scenario_ids is None:
            return True
        return scenario_id in set(scenario_ids())

    @socketio.on(ws.SUBSCRIBE)
    def _subscribe(payload):  # pragma: no cover - exercised via the harness
        principal = _principal()
        if principal is None or getattr(principal, "is_anonymous", True):
            emit("error", {"code": "api.unauthenticated",
                           "message": "認証が必要です"})
            return
        scenario_id = str((payload or {}).get("scenario_id") or "")
        if not scenario_id or not _known(scenario_id):
            emit("error", {"code": "api.not_found",
                           "message": f"シナリオ {scenario_id} は存在しません"})
            return
        join_room(ws.room_for(scenario_id))
        emit("subscribed", {"scenario_id": scenario_id,
                            "events": list(PUBLISHED_EVENTS),
                            "unpublished": dict(UNPUBLISHED_EVENTS)})

    @socketio.on(ws.UNSUBSCRIBE)
    def _unsubscribe(payload):  # pragma: no cover - harness
        scenario_id = str((payload or {}).get("scenario_id") or "")
        if scenario_id:
            leave_room(ws.room_for(scenario_id))

    def emitter(event: str, payload: Mapping, room: str) -> None:
        socketio.emit(event, dict(payload), to=room)

    return emitter


__all__ = ["PUBLISHED_EVENTS", "UNPUBLISHED_EVENTS", "Emission",
           "emissions_for", "publish", "create_channel"]
