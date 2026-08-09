/**
 * Unit tests for v3/ui/live.js — the live channel client.
 *
 * Run:  node tests/ui_v3/test_live.js
 *
 * The load-bearing ones:
 *   - a deployment that declares no channel puts the client in `unmounted`
 *     and dials NOTHING. §7-2 #112's whole point is that a reader and a
 *     writer must arrive together; a chip that said "disconnected" about a
 *     deployment which never had a channel would be the mirror defect —
 *     a live-looking surface with nothing behind it;
 *   - a push is a cue, never a payload. `applyMessage` returns read keys to
 *     invalidate and no data at all, because socket frames carry no NP7
 *     sentence and no dispatcher freshness stamp (G-13);
 *   - a push naming another scenario is discarded (S1-UI-010);
 *   - `degraded` and `disconnected` are reached by different histories
 *     (S1-UI-011), and polling is never suspended either way.
 */
'use strict';

const assert = require('assert');
const L = require('../../v3/ui/live');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

function fakeSocket() {
    const sent = [];
    const socket = {
        sent,
        closed: false,
        send(text) { sent.push(text); },
        close() { socket.closed = true; },
    };
    return socket;
}

function harness(overrides) {
    const sockets = [];
    const scheduled = [];
    const states = [];
    const cues = [];
    let focus = 'taiwan';
    const client = L.createLiveClient(Object.assign({
        socketFactory() { const s = fakeSocket(); sockets.push(s); return s; },
        focus() { return focus; },
        onState(v) { states.push(v); },
        onCue(v) { cues.push(v); },
        schedule(fn, ms) { scheduled.push({ fn, ms }); return scheduled.length; },
        cancel() {},
    }, overrides || {}));
    return {
        client, sockets, scheduled, states, cues,
        setFocus(next) { focus = next; },
    };
}

const MOUNTED = { websocket: { mounted: true, reason: null, unpublished: {} } };
const ABSENT = {
    websocket: {
        mounted: false,
        reason: 'socket チャネルは合成しない',
        unpublished: { notification_result: '発行者が存在しない' },
    },
};

// ── the deployment is asked, not assumed ─────────────────────────────────

test('an unmounted deployment is `unmounted`, not `disconnected`', () => {
    const h = harness();
    const v = h.client.configure(ABSENT);
    assert.strictEqual(v.connection, L.UNMOUNTED);
    assert.strictEqual(v.reasonKey, 'ui.live.reason.unmounted');
    assert.notStrictEqual(v.connection, L.DISCONNECTED);
});

test('an unmounted deployment causes no dial at all', () => {
    const h = harness();
    h.client.configure(ABSENT);
    assert.strictEqual(h.sockets.length, 0);
    assert.strictEqual(h.scheduled.length, 0);
});

test("the server's stated reason is carried to the chip verbatim", () => {
    const h = harness();
    const v = h.client.configure(ABSENT);
    assert.strictEqual(v.serverReason, ABSENT.websocket.reason);
    assert.deepStrictEqual(v.unpublished, ABSENT.websocket.unpublished);
});

test('an app_config not yet fetched is neither mounted nor absent', () => {
    const plan = L.planFrom(null);
    assert.strictEqual(plan.connect, false);
    assert.strictEqual(plan.state, L.CONNECTING);
    assert.strictEqual(plan.reasonKey, 'ui.live.reason.unknown');
});

test('an app_config with no websocket key declares itself undeclared', () => {
    const plan = L.planFrom({ mode: 'shadow' });
    assert.strictEqual(plan.connect, false);
    assert.strictEqual(plan.state, L.UNMOUNTED);
    assert.strictEqual(plan.reasonKey, 'ui.live.reason.undeclared');
});

test('a mounted deployment dials exactly once', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    assert.strictEqual(h.sockets.length, 1);
    h.client.configure(MOUNTED);
    assert.strictEqual(h.sockets.length, 1);
});

// ── framing ──────────────────────────────────────────────────────────────

test('the Engine.IO open packet is recognised with its handshake', () => {
    const f = L.decodeFrame('0{"sid":"abc","pingInterval":25000}');
    assert.strictEqual(f.kind, 'open');
    assert.strictEqual(f.handshake.sid, 'abc');
});

test('a ping decodes as a ping and pong is a bare 3', () => {
    assert.strictEqual(L.decodeFrame('2').kind, 'ping');
    assert.strictEqual(L.encodePong(), '3');
});

test('a Socket.IO event decodes to a name and a payload', () => {
    const f = L.decodeFrame('42["conclusion_update",{"scenario_id":"taiwan"}]');
    assert.strictEqual(f.kind, 'event');
    assert.strictEqual(f.event, 'conclusion_update');
    assert.strictEqual(f.payload.scenario_id, 'taiwan');
});

test('an emitted event is a well-formed Socket.IO frame', () => {
    assert.strictEqual(
        L.encodeEvent('subscribe_scenario', { scenario_id: 'taiwan' }),
        '42["subscribe_scenario",{"scenario_id":"taiwan"}]');
});

test('malformed frames are ignored rather than thrown', () => {
    ['', null, undefined, '4', '42', '42{', '9zzz', '42"bare"']
        .forEach((raw) => {
            const f = L.decodeFrame(raw);
            assert.ok(f && typeof f.kind === 'string');
            assert.notStrictEqual(f.kind, 'event');
        });
});

test('a connect error is distinguishable from a close', () => {
    assert.strictEqual(L.decodeFrame('44{"message":"nope"}').kind, 'connect_error');
    assert.strictEqual(L.decodeFrame('41').kind, 'close');
    assert.strictEqual(L.decodeFrame('1').kind, 'close');
});

// ── routing: a push is a cue ─────────────────────────────────────────────

test('every published event maps to the reads it invalidates', () => {
    Object.keys(L.INVALIDATES).forEach((event) => {
        const v = L.applyMessage({ event, payload: { scenario_id: 'taiwan' } },
                                 'taiwan');
        assert.strictEqual(v.accepted, true, event);
        assert.ok(v.invalidate.length > 0, event);
    });
});

test('the verdict carries no data from the push', () => {
    const v = L.applyMessage({
        event: 'conclusion_update',
        payload: { scenario_id: 'taiwan', conclusions: [{ threat_level: 1 }] },
    }, 'taiwan');
    assert.strictEqual(JSON.stringify(v).indexOf('threat_level'), -1);
    assert.strictEqual(v.accepted, true);
});

test('a push for another scenario is discarded (S1-UI-010)', () => {
    const v = L.applyMessage({
        event: 'conclusion_update', payload: { scenario_id: 'ukraine' },
    }, 'taiwan');
    assert.strictEqual(v.accepted, false);
    assert.strictEqual(v.reasonKey, 'ui.live.drop.other_scenario');
    assert.deepStrictEqual(v.invalidate, []);
});

test('a push claiming no scenario is accepted', () => {
    const v = L.applyMessage({ event: 'attention_update', payload: {} }, 'taiwan');
    assert.strictEqual(v.accepted, true);
});

test('a retired event name is reported, not silently dropped', () => {
    L.RETIRED_EVENTS.forEach((event) => {
        const v = L.applyMessage({ event, payload: {} }, 'taiwan');
        assert.strictEqual(v.accepted, false, event);
        assert.strictEqual(v.reasonKey, 'ui.live.drop.retired', event);
    });
});

test('the event the server refuses to publish is a contract breach if it arrives', () => {
    const v = L.applyMessage({ event: 'notification_result', payload: {} }, null);
    assert.strictEqual(v.accepted, false);
    assert.strictEqual(v.reasonKey, 'ui.live.drop.unpublished');
});

test('a server-side error frame is surfaced', () => {
    const v = L.applyMessage({ event: 'error',
                               payload: { code: 'api.unauthenticated' } }, null);
    assert.strictEqual(v.reasonKey, 'ui.live.drop.server_error');
    assert.strictEqual(v.detail, 'api.unauthenticated');
});

test('an unknown event is dropped with its own reason', () => {
    const v = L.applyMessage({ event: 'weather_brief', payload: {} }, null);
    assert.strictEqual(v.reasonKey, 'ui.live.drop.unknown');
});

// ── the socket lifecycle ─────────────────────────────────────────────────

test('a Socket.IO connect subscribes to the focused scenario', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    h.sockets[0].onmessage({ data: '0{"sid":"a"}' });
    h.sockets[0].onmessage({ data: '40{"sid":"b"}' });
    assert.strictEqual(h.client.view().connection, L.CONNECTED);
    assert.deepStrictEqual(h.sockets[0].sent, [
        '42["subscribe_scenario",{"scenario_id":"taiwan"}]']);
});

test('a ping is answered with a pong', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    h.sockets[0].onmessage({ data: '2' });
    assert.deepStrictEqual(h.sockets[0].sent, ['3']);
});

test('re-subscribing leaves the previous room first', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    h.sockets[0].onmessage({ data: '40{}' });
    h.setFocus('ukraine');
    h.client.subscribe('ukraine');
    assert.deepStrictEqual(h.sockets[0].sent, [
        '42["subscribe_scenario",{"scenario_id":"taiwan"}]',
        '42["unsubscribe_scenario",{"scenario_id":"taiwan"}]',
        '42["subscribe_scenario",{"scenario_id":"ukraine"}]',
    ]);
});

test('an accepted push reaches the cue callback', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    h.sockets[0].onmessage({ data: '40{}' });
    h.sockets[0].onmessage({
        data: '42["attention_update",{"scenario_id":"taiwan"}]' });
    assert.strictEqual(h.cues.length, 1);
    assert.strictEqual(h.cues[0].accepted, true);
    assert.deepStrictEqual(h.cues[0].invalidate, ['R6']);
});

test('one drop is disconnected; repeated failures are degraded', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    h.sockets[0].onclose();
    assert.strictEqual(h.client.view().connection, L.DISCONNECTED);
    h.scheduled[h.scheduled.length - 1].fn();
    h.sockets[1].onclose();
    assert.strictEqual(h.client.view().connection, L.DISCONNECTED);
    h.scheduled[h.scheduled.length - 1].fn();
    h.sockets[2].onclose();
    assert.strictEqual(h.client.view().connection, L.DEGRADED);
});

test('a protocol-level refusal goes straight to degraded', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    h.sockets[0].onmessage({ data: '44{"message":"unauthenticated"}' });
    assert.strictEqual(h.client.view().connection, L.DEGRADED);
});

test('backoff grows and then stops growing', () => {
    assert.strictEqual(L.backoffMs(1), L.RETRY_BASE_MS);
    assert.ok(L.backoffMs(2) > L.backoffMs(1));
    assert.strictEqual(L.backoffMs(99), L.RETRY_CEILING_MS);
});

test('a successful connect resets the failure count', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    h.sockets[0].onclose();
    h.scheduled[h.scheduled.length - 1].fn();
    h.sockets[1].onmessage({ data: '40{}' });
    assert.strictEqual(h.client.view().attempts, 0);
});

test('polling is never suspended, in any state', () => {
    const h = harness();
    h.client.configure(ABSENT);
    assert.strictEqual(h.client.view().pollingContinues, true);
    h.client.configure(MOUNTED);
    h.sockets[0].onclose();
    assert.strictEqual(h.client.view().pollingContinues, true);
});

test('stop closes the socket and schedules nothing further', () => {
    const h = harness();
    h.client.configure(MOUNTED);
    const before = h.scheduled.length;
    const v = h.client.stop();
    assert.strictEqual(h.sockets[0].closed, true);
    assert.strictEqual(v.connection, L.DISCONNECTED);
    assert.strictEqual(h.scheduled.length, before);
});

test('a client with no socket factory reports rather than throws', () => {
    const client = L.createLiveClient({ socketFactory: null });
    const v = client.configure(MOUNTED);
    assert.ok(L.STATES.indexOf(v.connection) !== -1);
});

console.log(`\n\n${passed} passed, ${failed} failed`);
if (failed > 0) {
    failures.forEach(({ name, error }) => {
        console.error(`\n  FAIL: ${name}`);
        console.error('  ' + (error.stack || error));
    });
    process.exit(1);
}
process.exit(0);
