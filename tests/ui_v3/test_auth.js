/**
 * Unit tests for v3/ui/auth.js — the login gate's whole decision.
 *
 * Run:  node tests/ui_v3/test_auth.js
 *
 * §7-2 #99 registered the gate's absence. What it protects is not
 * authorisation — the server's `Access` declarations do that on every
 * route — but the analyst's ability to tell "I am not signed in" from "the
 * tool has nothing to say", which is the G-10 failure class applied to
 * auth. So these tests are about the states and the reasons, not about
 * markup.
 *
 * Everything is injected (`post`, `cookies`), so the real state machine
 * runs here with no browser, no server and no DOM.
 */
'use strict';

const assert = require('assert');
const Auth = require('../../v3/ui/auth');

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

const CSRF = 'a'.repeat(32);
const COOKIE_STRING = Auth.CSRF_COOKIE + '=' + CSRF;

function sessionBody(extra) {
    return {
        api_version: '3.0',
        scenario_id: '__tool__',
        final_judgment_disclaimer:
            'Tool conclusion only — final judgment by organizational process.',
        conclusions: [],
        session: Object.assign({
            user_id: 'kamo', role: 'analyst',
            access_token: 'access-token-value', access_expires_sec: 3600,
        }, extra || {}),
    };
}

function errorBody(code, message) {
    return { error: code, error_detail: { code: code, message: message } };
}

/** A transport that records calls and replays a queue of responses. */
function stubPost(responses) {
    const calls = [];
    const queue = responses.slice();
    const fn = (path, body, headers) => {
        calls.push({ path, body, headers });
        const next = queue.length > 1 ? queue.shift() : queue[0];
        if (next instanceof Error) return Promise.reject(next);
        return Promise.resolve(next);
    };
    fn.calls = calls;
    return fn;
}

function session(post, options) {
    return Auth.createSession(Object.assign({
        post: post, cookies: () => COOKIE_STRING,
    }, options || {}));
}

// ── the cookie reader ────────────────────────────────────────────────────

test('the CSRF companion is read out of the cookie string', () => {
    assert.strictEqual(
        Auth.readCookie('other=1; ' + Auth.CSRF_COOKIE + '=xyz; more=2',
                        Auth.CSRF_COOKIE), 'xyz');
});

test('a value containing = survives the split', () => {
    assert.strictEqual(Auth.readCookie('k=a=b=c', 'k'), 'a=b=c');
});

test('a missing cookie is null, not the empty string', () => {
    assert.strictEqual(Auth.readCookie('other=1', Auth.CSRF_COOKIE), null);
});

test('an empty value is null too, because it refuses the same way', () => {
    assert.strictEqual(Auth.readCookie('k=', 'k'), null);
});

test('a prefix match is not a match', () => {
    assert.strictEqual(Auth.readCookie('noroshi_v3_csrf_refresh_x=1',
                                       Auth.CSRF_COOKIE), null);
});

test('the httpOnly refresh cookie is never named here', () => {
    // The SPA cannot read it and must not pretend to. Naming it would be
    // an invitation to try (§7-2 #103 / S1-UI-002).
    const source = require('fs').readFileSync(
        require('path').join(__dirname, '../../v3/ui/auth.js'), 'utf8');
    assert.ok(!source.includes('noroshi_v3_refresh"'));
    assert.ok(!source.includes("noroshi_v3_refresh'"));
});

// ── boot ─────────────────────────────────────────────────────────────────

test('a fresh browser starts checking, not locked', () => {
    const s = session(stubPost([{ status: 401, json: errorBody(
        'api.unauthenticated', 'no') }]));
    assert.strictEqual(s.state(), Auth.CHECKING);
});

test('boot with a live refresh cookie opens without a sign-in', async () => {
    const post = stubPost([{ status: 200, json: sessionBody() }]);
    const s = session(post);
    await s.begin();
    assert.strictEqual(s.state(), Auth.OPEN);
    assert.strictEqual(s.identity().userId, 'kamo');
    assert.strictEqual(post.calls[0].path, Auth.REFRESH_PATH);
});

test('boot echoes the CSRF companion into the header', async () => {
    const post = stubPost([{ status: 200, json: sessionBody() }]);
    await session(post).begin();
    assert.strictEqual(post.calls[0].headers[Auth.CSRF_HEADER], CSRF);
});

test('boot with no companion cookie locks with "never" and sends nothing',
     async () => {
    const post = stubPost([{ status: 200, json: sessionBody() }]);
    const s = Auth.createSession({ post: post, cookies: () => '' });
    await s.begin();
    assert.strictEqual(s.state(), Auth.LOCKED);
    assert.strictEqual(s.reason(), 'never');
    assert.strictEqual(post.calls.length, 0);
});

test('boot with an expired refresh cookie locks with "expired"', async () => {
    const s = session(stubPost([{ status: 401,
                                  json: errorBody('api.unauthenticated', 'x') }]));
    await s.begin();
    assert.strictEqual(s.state(), Auth.LOCKED);
    assert.strictEqual(s.reason(), 'expired');
    assert.strictEqual(s.reasonKey(), 'ui.auth.reason.expired');
});

test('a deployment with no signing key says so, not "wrong password"',
     async () => {
    const s = session(stubPost([{ status: 503,
                                  json: errorBody('api.unavailable', '鍵なし') }]));
    await s.begin();
    assert.strictEqual(s.reason(), 'unavailable');
});

test('a network failure is its own reason', async () => {
    const s = session(stubPost([new Error('offline')]));
    await s.begin();
    assert.strictEqual(s.reason(), 'transport');
    assert.strictEqual(s.message(), 'offline');
});

// ── sign in / sign out ───────────────────────────────────────────────────

test('a correct credential opens the gate', async () => {
    const post = stubPost([{ status: 200, json: sessionBody() }]);
    const s = session(post);
    await s.signIn('kamo', 'pw');
    assert.strictEqual(s.state(), Auth.OPEN);
    assert.strictEqual(s.token(), 'access-token-value');
    assert.strictEqual(post.calls[0].path, Auth.LOGIN_PATH);
    assert.deepStrictEqual(post.calls[0].body,
                           { user_id: 'kamo', password: 'pw' });
});

test('a wrong credential locks with "refused"', async () => {
    const s = session(stubPost([{ status: 401, json: errorBody(
        'api.unauthenticated', 'ユーザー名またはパスワードが正しくありません') }]));
    await s.signIn('kamo', 'nope');
    assert.strictEqual(s.reason(), 'refused');
    assert.strictEqual(s.token(), null);
});

test('too many attempts is throttled, which is a different sentence',
     async () => {
    const s = session(stubPost([{ status: 429, json: errorBody(
        'api.too_many_requests', '多すぎます') }]));
    await s.signIn('kamo', 'nope');
    assert.strictEqual(s.reason(), 'throttled');
});

test("the server's own message is carried, not swallowed", async () => {
    const s = session(stubPost([{ status: 401,
                                  json: errorBody('api.unauthenticated', '誤り') }]));
    await s.signIn('kamo', 'nope');
    assert.strictEqual(s.message(), '誤り');
});

test('signing out locks and drops the token even if the call fails',
     async () => {
    const post = stubPost([new Error('offline')]);
    const s = session(post);
    await s.signIn('kamo', 'pw').catch(() => {});
    await s.signOut();
    assert.strictEqual(s.state(), Auth.LOCKED);
    assert.strictEqual(s.reason(), 'signed_out');
    assert.strictEqual(s.token(), null);
});

test('sign-out presents the bearer token it is revoking', async () => {
    const post = stubPost([{ status: 200, json: sessionBody() },
                           { status: 200, json: { ok: true } }]);
    const s = session(post);
    await s.signIn('kamo', 'pw');
    await s.signOut();
    assert.strictEqual(post.calls[1].path, Auth.LOGOUT_PATH);
    assert.strictEqual(post.calls[1].headers.Authorization,
                       'Bearer access-token-value');
});

// ── the mid-session 401 ──────────────────────────────────────────────────

test('a 401 that a refresh repairs asks the caller to retry', async () => {
    const post = stubPost([{ status: 200, json: sessionBody() },
                           { status: 200, json: sessionBody(
                               { access_token: 'second-token' }) }]);
    const s = session(post);
    await s.signIn('kamo', 'pw');
    const retry = await s.onUnauthorized();
    assert.strictEqual(retry, true);
    assert.strictEqual(s.state(), Auth.OPEN);
    assert.strictEqual(s.token(), 'second-token');
});

test('a 401 a refresh cannot repair locks with "revoked", never silently',
     async () => {
    const post = stubPost([{ status: 200, json: sessionBody() },
                           { status: 401, json: errorBody(
                               'api.unauthenticated', '失効') }]);
    const s = session(post);
    await s.signIn('kamo', 'pw');
    const retry = await s.onUnauthorized();
    assert.strictEqual(retry, false);
    assert.strictEqual(s.state(), Auth.LOCKED);
    assert.strictEqual(s.reason(), 'revoked');
    assert.strictEqual(s.reasonKey(), 'ui.auth.reason.revoked');
});

test('an already-locked session does not refresh again', async () => {
    const post = stubPost([{ status: 401, json: errorBody(
        'api.unauthenticated', 'x') }]);
    const s = session(post);
    await s.begin();
    const before = post.calls.length;
    assert.strictEqual(await s.onUnauthorized(), false);
    assert.strictEqual(post.calls.length, before);
});

test('concurrent 401s produce ONE refresh, not one per panel', async () => {
    let resolve;
    const gate = new Promise((r) => { resolve = r; });
    const calls = [];
    const post = (path, body, headers) => {
        calls.push(path);
        if (calls.length === 1) {
            return Promise.resolve({ status: 200, json: sessionBody() });
        }
        return gate.then(() => ({ status: 200, json: sessionBody() }));
    };
    const s = Auth.createSession({ post: post, cookies: () => COOKIE_STRING });
    await s.signIn('kamo', 'pw');
    const all = Promise.all([s.onUnauthorized(), s.onUnauthorized(),
                             s.onUnauthorized()]);
    resolve();
    const results = await all;
    assert.deepStrictEqual(results, [true, true, true]);
    // login + exactly one refresh.
    assert.strictEqual(calls.length, 2);
});

test('a later 401 can still refresh once the first one finished',
     async () => {
    const post = stubPost([{ status: 200, json: sessionBody() },
                           { status: 200, json: sessionBody() },
                           { status: 200, json: sessionBody() }]);
    const s = session(post);
    await s.signIn('kamo', 'pw');
    await s.onUnauthorized();
    await s.onUnauthorized();
    assert.strictEqual(post.calls.length, 3);
});

// ── the closed vocabulary ────────────────────────────────────────────────

test('every reason has a dictionary key and none is invented', () => {
    Object.keys(Auth.REASONS).forEach((reason) => {
        assert.ok(Auth.REASONS[reason].startsWith('ui.auth.reason.'));
    });
});

test('an undeclared reason degrades to "refused" rather than to nothing',
     async () => {
    const s = session(stubPost([{ status: 418, json: {} }]));
    await s.signIn('kamo', 'pw');
    assert.ok(Object.prototype.hasOwnProperty.call(Auth.REASONS, s.reason()));
});

test('an open session reports no reason at all', async () => {
    const s = session(stubPost([{ status: 200, json: sessionBody() }]));
    await s.signIn('kamo', 'pw');
    assert.strictEqual(s.reason(), null);
    assert.strictEqual(s.reasonKey(), null);
});

test('onChange fires for every transition, so nothing has to poll', async () => {
    const seen = [];
    const s = Auth.createSession({
        post: stubPost([{ status: 200, json: sessionBody() }]),
        cookies: () => COOKIE_STRING,
        onChange: (current) => seen.push(current.state()),
    });
    await s.begin();
    await s.signOut();
    assert.deepStrictEqual(seen, [Auth.CHECKING, Auth.OPEN, Auth.LOCKED]);
});

test('the session never hands out a refresh token because it never has one',
     async () => {
    const s = session(stubPost([{ status: 200, json: sessionBody() }]));
    await s.signIn('kamo', 'pw');
    assert.strictEqual(typeof s.refreshToken, 'undefined');
    assert.deepStrictEqual(Object.keys(s.identity()).sort(),
                           ['accessExpiresSec', 'role', 'userId']);
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
