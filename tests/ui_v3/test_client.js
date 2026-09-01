/**
 * Unit tests for v3/ui/client.js — the read/command client.
 *
 * Run:  node tests/ui_v3/test_client.js
 *
 * The transport is injected, so this suite exercises the real request
 * construction, the real envelope handling and the real failure paths with
 * no browser and no server.
 */
'use strict';

const assert = require('assert');
const Client = require('../../v3/ui/client');

let passed = 0, failed = 0;
const failures = [];
const pending = [];

function test(name, fn) {
    const result = (async () => {
        try { await fn(); passed += 1; process.stdout.write('.'); }
        catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
    })();
    pending.push(result);
}

const NOW = 1800000000;
const DISCLAIMER = Client.NP7_DISCLAIMER;

function envelope(extra) {
    return Object.assign({
        api_version: '3.0',
        scenario_id: '__tool__',
        observed_at: NOW - 30,
        final_judgment_disclaimer: DISCLAIMER,
        conclusions: [],
        data_freshness_sec: 30,
        served_at: NOW,
    }, extra || {});
}

/** A transport that records calls and replays a queue of responses. */
function stubTransport(responses) {
    const calls = [];
    const queue = responses.slice();
    const fn = (url, init) => {
        calls.push({ url, init });
        const next = queue.length > 1 ? queue.shift() : queue[0];
        if (next instanceof Error) return Promise.reject(next);
        return Promise.resolve(next);
    };
    fn.calls = calls;
    return fn;
}

function client(transport, options) {
    return Client.createClient(Object.assign({
        transport: transport, now: () => NOW,
    }, options || {}));
}

// ── request construction ─────────────────────────────────────────────────

test('reads go to /api/v3 with the declared path', async () => {
    const t = stubTransport([{ status: 200, json: envelope() }]);
    await client(t).reads.scenarios();
    assert.strictEqual(t.calls[0].url, '/api/v3/scenarios');
    assert.strictEqual(t.calls[0].init.method, 'GET');
});

test('path segments are URL-encoded', async () => {
    const t = stubTransport([{ status: 200, json: envelope() }]);
    await client(t).reads.conclusions('a/b c');
    assert.strictEqual(t.calls[0].url, '/api/v3/scenarios/a%2Fb%20c/conclusions');
});

test('query params are sorted and empty ones are dropped', async () => {
    const t = stubTransport([{ status: 200, json: envelope() }]);
    await client(t).reads.evidence('s', { sensor: 'x', domain: 'cyber', at: null, window: '' });
    assert.strictEqual(t.calls[0].url,
        '/api/v3/scenarios/s/evidence?domain=cyber&sensor=x');
});

test('a token becomes a bearer header; no token means no header', async () => {
    const t = stubTransport([{ status: 200, json: envelope() }]);
    await client(t, { tokenProvider: () => 'tok' }).reads.scenarios();
    assert.strictEqual(t.calls[0].init.headers.Authorization, 'Bearer tok');

    const t2 = stubTransport([{ status: 200, json: envelope() }]);
    await client(t2).reads.scenarios();
    assert.strictEqual(t2.calls[0].init.headers.Authorization, undefined);
});

test('commands send a JSON body and declare the content type', async () => {
    const t = stubTransport([{ status: 200, json: envelope({ effect: {} }) }]);
    await client(t).commands.focus('taiwan_contingency', 'なぜ');
    assert.strictEqual(t.calls[0].init.method, 'POST');
    assert.strictEqual(t.calls[0].init.headers['Content-Type'], 'application/json');
    assert.deepStrictEqual(JSON.parse(t.calls[0].init.body),
        { scenario_id: 'taiwan_contingency', reason: 'なぜ' });
});

test('the threshold command is a PUT, as the route declares', async () => {
    const t = stubTransport([{ status: 200, json: envelope({ effect: {} }) }]);
    await client(t).commands.attentionThresholds({ min_score: 0.2 }, 'r');
    assert.strictEqual(t.calls[0].init.method, 'PUT');
});

// ── NP7 discipline (G-13) ────────────────────────────────────────────────

test('an envelope carrying the exact sentence is not flagged', async () => {
    const r = await client(stubTransport([{ status: 200, json: envelope() }]))
        .reads.scenarios();
    assert.strictEqual(r.disclaimerMissing, false);
});

test('a missing NP7 sentence is recorded, not thrown and not ignored', async () => {
    const body = envelope();
    delete body.final_judgment_disclaimer;
    const r = await client(stubTransport([{ status: 200, json: body }])).reads.scenarios();
    assert.strictEqual(r.ok, true, 'the screen still renders');
    assert.strictEqual(r.disclaimerMissing, true, 'and the breach is reported');
});

test('an ALTERED NP7 sentence counts as missing', async () => {
    const r = await client(stubTransport([
        { status: 200, json: envelope({ final_judgment_disclaimer: 'Tool conclusion only.' }) },
    ])).reads.scenarios();
    assert.strictEqual(r.disclaimerMissing, true);
});

// ── failure handling (S1-UI-008 + DP2) ───────────────────────────────────

test('a failed fetch keeps the last good body and says the fetch failed', async () => {
    const t = stubTransport([
        { status: 200, json: envelope({ scenarios: [{ scenario_id: 'a' }] }) },
        { status: 503, json: { error: 'api.unavailable',
                               error_detail: { code: 'api.unavailable', message: '停止中' } } },
    ]);
    const c = client(t);
    const first = await c.reads.scenarios();
    assert.strictEqual(first.ok, true);
    const second = await c.reads.scenarios();
    assert.strictEqual(second.ok, false);
    assert.strictEqual(second.held, true);
    assert.deepStrictEqual(second.body.scenarios, [{ scenario_id: 'a' }],
        'the previous data is still renderable');
    assert.strictEqual(second.error.code, 'api.unavailable');
    assert.strictEqual(second.error.status, 503);
    assert.strictEqual(second.error.message, '停止中');
});

test('a first-ever failure holds nothing and says so', async () => {
    const r = await client(stubTransport([{ status: 404, json: { error: 'api.not_found' } }]))
        .reads.scenarios();
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.held, false);
    assert.strictEqual(r.body, null);
});

test('a thrown transport error reads differently from a 4xx', async () => {
    const r = await client(stubTransport([new Error('offline')])).reads.scenarios();
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.error.code, 'api.transport');
    assert.strictEqual(r.error.status, null);
    assert.strictEqual(r.error.known, false);
});

test('an unrecognised error code is passed through, not mapped to a familiar one', async () => {
    const r = await client(stubTransport([{ status: 418, json: { error: 'api.brand_new' } }]))
        .reads.scenarios();
    assert.strictEqual(r.error.code, 'api.brand_new');
    assert.strictEqual(r.error.known, false);
});

test('held state is per resource key, not global', async () => {
    const t = stubTransport([{ status: 200, json: envelope({ tag: 'x' }) }]);
    const c = client(t);
    await c.reads.scenarios();
    assert.deepStrictEqual(c.heldKeys(), ['R1']);
    await c.reads.selfEval();
    assert.deepStrictEqual(c.heldKeys().sort(), ['R1', 'R7']);
});

// ── freshness passthrough ────────────────────────────────────────────────

test('observed_at, freshness and served_at come through for the staleness badge', async () => {
    const r = await client(stubTransport([{ status: 200, json: envelope() }]))
        .reads.scenarios();
    assert.strictEqual(r.observedAt, NOW - 30);
    assert.strictEqual(r.freshnessSec, 30);
    assert.strictEqual(r.servedAt, NOW);
});

test('an ?at= response carries its cross-section timestamp', async () => {
    const r = await client(stubTransport([{ status: 200, json: envelope({ at: NOW - 7200 }) }]))
        .reads.conclusions('s', { at: NOW - 7200 });
    assert.strictEqual(r.at, NOW - 7200);
});

// ── commands report the read-back effect, never the request (G-15) ───────

test('effectOf returns the server read-back, not the submitted value', async () => {
    const c = client(stubTransport([{ status: 200, json: envelope({
        command: { command_id: 'k1', action: 'config.set', target_id: 'X' },
        sequence: 7, changed: true,
        effect: { config: { key: 'X', value: 42, source: 'override' } },
    }) }]));
    const result = await c.commands.setConfig('X', 99, 'r');
    const effect = c.effectOf(result);
    assert.strictEqual(effect.effect.config.value, 42,
        'the effect is what the server read back (42), not what we sent (99)');
    assert.strictEqual(effect.changed, true);
    assert.strictEqual(effect.sequence, 7);
});

test('effectOf on a failed command is null, never an assumed success', async () => {
    const c = client(stubTransport([{ status: 403, json: { error: 'api.forbidden' } }]));
    assert.strictEqual(c.effectOf(await c.commands.focus('s', 'r')), null);
});

// ── deferred surfaces are declared ───────────────────────────────────────

test('unserved P7 entries are named so the shell can say "not yet"', () => {
    ['R11', 'C3', 'C8', 'C10', 'C11', 'C12'].forEach(id => {
        assert.ok(Client.DEFERRED[id], `${id} must be declared deferred`);
        assert.ok(/^ui\.deferred\./.test(Client.DEFERRED[id]));
    });
});

test('C13 is NOT deferred any more — the gate is on the screen', () => {
    // §7-2 #99 retired. A surface that declares itself absent while it is
    // being rendered is the same defect the deferred list exists to
    // prevent, pointing the other way.
    assert.strictEqual(Client.DEFERRED.C13, undefined);
});

// ── the 401 policy (S1-UI-003, §7-2 #99) ─────────────────────────────────

test('a 401 asks the session what to do and retries once when told to',
     async () => {
    const transport = stubTransport([
        { status: 401, json: { error: 'api.unauthenticated' } },
        { status: 200, json: envelope() },
    ]);
    let asked = 0;
    const c = client(transport, {
        onUnauthorized: () => { asked += 1; return Promise.resolve(true); },
    });
    const result = await c.reads.scenarios();
    assert.strictEqual(asked, 1);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(transport.calls.length, 2);
});

test('a 401 the session cannot repair is reported, not retried', async () => {
    const transport = stubTransport([
        { status: 401, json: { error: 'api.unauthenticated' } }]);
    const c = client(transport, {
        onUnauthorized: () => Promise.resolve(false) });
    const result = await c.reads.scenarios();
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.error.code, 'api.unauthenticated');
    assert.strictEqual(transport.calls.length, 1);
});

test('the retry is ONCE: a second 401 is an answer, not another attempt',
     async () => {
    const transport = stubTransport([
        { status: 401, json: { error: 'api.unauthenticated' } }]);
    let asked = 0;
    const c = client(transport, {
        onUnauthorized: () => { asked += 1; return Promise.resolve(true); },
    });
    const result = await c.reads.scenarios();
    assert.strictEqual(asked, 1);
    assert.strictEqual(transport.calls.length, 2);
    assert.strictEqual(result.ok, false);
});

test('without a session hook a 401 is an ordinary error', async () => {
    const transport = stubTransport([
        { status: 401, json: { error: 'api.unauthenticated' } }]);
    const result = await client(transport).reads.scenarios();
    assert.strictEqual(result.ok, false);
    assert.strictEqual(transport.calls.length, 1);
});

test('every request carries same-origin credentials so the cookie rides',
     async () => {
    const transport = stubTransport([{ status: 200, json: envelope() }]);
    await client(transport).reads.scenarios();
    assert.strictEqual(transport.calls[0].init.credentials, 'same-origin');
});

test('createClient refuses to exist without a transport', () => {
    assert.throws(() => Client.createClient({}), /transport/);
});

// ── Report ───────────────────────────────────────────────────────────────

Promise.all(pending).then(() => {
    console.log(`\n\n${passed} passed, ${failed} failed`);
    if (failed > 0) {
        failures.forEach(({ name, error }) => {
            console.error(`\n  FAIL: ${name}`);
            console.error('  ' + (error.stack || error));
        });
        process.exit(1);
    }
    process.exit(0);
});
