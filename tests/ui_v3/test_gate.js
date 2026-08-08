/**
 * Unit tests for v3/ui/gate.js — what the login gate SHOWS.
 *
 * Run:  node tests/ui_v3/test_gate.js
 *
 * `auth.js` decides what the session is; this decides what the screen says
 * about it. Keeping the display decision pure is what makes "an expired
 * session says expired, not wrong password" an assertion rather than a
 * screenshot — and it is the property §7-2 #99 is really about: an analyst
 * must never have to infer their auth state from an empty panel.
 */
'use strict';

const assert = require('assert');
const Auth = require('../../v3/ui/auth');
const Gate = require('../../v3/ui/gate');

let passed = 0, failed = 0;
const failures = [];
const pending = [];

function test(name, fn) {
    pending.push({ name, fn });
}

async function run() {
    for (const { name, fn } of pending) {
        try { await fn(); passed += 1; process.stdout.write('.'); }
        catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
    }
}

const CSRF = 'a'.repeat(32);
const COOKIE_STRING = Auth.CSRF_COOKIE + '=' + CSRF;

function sessionBody() {
    return { session: { user_id: 'kamo', role: 'analyst',
                        access_token: 'tok', access_expires_sec: 3600 } };
}

function stubPost(responses) {
    const calls = [];
    const queue = responses.slice();
    const fn = (path, body, headers) => {
        calls.push({ path, body, headers });
        const next = queue.length > 1 ? queue.shift() : queue[0];
        return Promise.resolve(next);
    };
    fn.calls = calls;
    return fn;
}

// ── the pure view ────────────────────────────────────────────────────────

test('no session at all reads as closed, never as open', () => {
    const view = Gate.viewOf(null);
    assert.strictEqual(view.gateHidden, false);
    assert.strictEqual(view.mainHidden, true);
    assert.ok(view.reasonKey);
});

test('checking disables the form and says so, instead of "please sign in"',
     () => {
    const s = Auth.createSession({ post: stubPost([{ status: 200, json: {} }]),
                                   cookies: () => COOKIE_STRING });
    const view = Gate.viewOf(s);
    assert.strictEqual(view.reasonKey, 'ui.auth.checking');
    assert.strictEqual(view.submitKey, 'ui.auth.submitting');
    assert.strictEqual(view.submitDisabled, true);
});

test('an open session hides the gate and shows the loop', async () => {
    const s = Auth.createSession({ post: stubPost([{ status: 200,
                                                     json: sessionBody() }]),
                                   cookies: () => COOKIE_STRING });
    await s.begin();
    const view = Gate.viewOf(s);
    assert.strictEqual(view.gateHidden, true);
    assert.strictEqual(view.mainHidden, false);
    assert.strictEqual(view.barHidden, false);
    assert.strictEqual(view.reasonKey, null);
    assert.deepStrictEqual(view.identity, { user: 'kamo', role: 'analyst' });
});

test('a locked session always carries a reason key', async () => {
    const s = Auth.createSession({ post: stubPost([]), cookies: () => '' });
    await s.begin();
    const view = Gate.viewOf(s);
    assert.strictEqual(view.mainHidden, true);
    assert.strictEqual(view.reasonKey, 'ui.auth.reason.never');
    assert.strictEqual(view.identity, null);
});

test('a stale server message is not shown under a "checking" line', () => {
    const s = Auth.createSession({ post: stubPost([{ status: 200, json: {} }]),
                                   cookies: () => COOKIE_STRING });
    assert.strictEqual(Gate.viewOf(s).detailMessage, null);
});

// ── the DOM half ─────────────────────────────────────────────────────────

function makeElement() {
    return {
        hidden: false, disabled: false, value: '', textContent: '',
        listeners: {},
        addEventListener(name, fn) { this.listeners[name] = fn; },
    };
}

function makeDoc() {
    const nodes = {};
    ['auth-gate', 'app-main', 'auth-bar', 'auth-reason', 'auth-detail',
     'auth-submit', 'auth-identity', 'auth-user', 'auth-password',
     'auth-form', 'auth-signout'].forEach((id) => { nodes[id] = makeElement(); });
    return { nodes, getElementById: (id) => nodes[id] || null,
             cookie: COOKIE_STRING };
}

function ui(post, extra) {
    const doc = makeDoc();
    const gate = Gate.createGateUi(Object.assign({
        doc: doc,
        transport: (path, init) => post(path, JSON.parse(init.body || '{}'),
                                        init.headers),
    }, extra || {}));
    return { doc, gate };
}

test('an unauthenticated boot hides main and shows the gate', async () => {
    const { doc, gate } = ui(stubPost([]));
    doc.cookie = '';
    await gate.begin();
    assert.strictEqual(doc.nodes['auth-gate'].hidden, false);
    assert.strictEqual(doc.nodes['app-main'].hidden, true);
    assert.ok(/サインイン/.test(doc.nodes['auth-reason'].textContent),
              doc.nodes['auth-reason'].textContent);
});

test('a live refresh cookie opens straight through', async () => {
    const { doc, gate } = ui(stubPost([{ status: 200, json: sessionBody() }]));
    await gate.begin();
    assert.strictEqual(doc.nodes['auth-gate'].hidden, true);
    assert.strictEqual(doc.nodes['app-main'].hidden, false);
    assert.ok(/kamo/.test(doc.nodes['auth-identity'].textContent));
});

test("the server's prose is shown as text, never as markup", async () => {
    const { doc, gate } = ui(stubPost([{ status: 401, json: {
        error: 'api.unauthenticated',
        error_detail: { code: 'api.unauthenticated',
                        message: '<img src=x onerror=alert(1)>' } } }]));
    await gate.begin();
    const detail = doc.nodes['auth-detail'];
    assert.strictEqual(detail.hidden, false);
    assert.ok(detail.textContent.indexOf('<img') !== -1);
    // `textContent` was written, not `innerHTML` — the element has no
    // innerHTML at all in this fake, so a markup write would have thrown.
    assert.strictEqual(detail.innerHTML, undefined);
});

test('an empty credential is refused locally and sends nothing', async () => {
    const refusals = [];
    const post = stubPost([{ status: 200, json: sessionBody() }]);
    const { doc, gate } = ui(post, { onRefused: (k) => refusals.push(k) });
    doc.nodes['auth-user'].value = '   ';
    doc.nodes['auth-password'].value = '';
    await gate.submit();
    assert.deepStrictEqual(refusals, ['ui.auth.required']);
    assert.strictEqual(post.calls.length, 0);
});

test('the password field is cleared after a submit', async () => {
    const { doc, gate } = ui(stubPost([{ status: 200, json: sessionBody() }]));
    doc.nodes['auth-user'].value = 'kamo';
    doc.nodes['auth-password'].value = 'secret';
    await gate.submit();
    assert.strictEqual(doc.nodes['auth-password'].value, '');
});

test('opening and locking notify the caller so the loop can start or stop',
     async () => {
    const events = [];
    const { gate } = ui(stubPost([{ status: 200, json: sessionBody() },
                                  { status: 200, json: { ok: true } }]), {
        onOpen: () => events.push('open'),
        onLock: () => events.push('lock'),
    });
    await gate.begin();
    await gate.session.signOut();
    assert.deepStrictEqual(events, ['open', 'lock']);
});

test('the checking state does not fire onLock', async () => {
    const events = [];
    const { gate } = ui(stubPost([{ status: 200, json: sessionBody() }]), {
        onLock: () => events.push('lock'),
    });
    await gate.begin();
    assert.deepStrictEqual(events, []);
});

test('binding attaches the form and the sign-out control', () => {
    const { doc, gate } = ui(stubPost([]));
    gate.bind();
    assert.strictEqual(typeof doc.nodes['auth-form'].listeners.submit,
                       'function');
    assert.strictEqual(typeof doc.nodes['auth-signout'].listeners.click,
                       'function');
});

// ── Report ───────────────────────────────────────────────────────────────

run().then(() => {
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
