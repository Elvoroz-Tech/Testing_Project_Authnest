/* global Buffer */
// npm test — pure-logic tests for sessionRenewal.js (fake cookie jar + fake fetch, no browser needed)
import test from 'node:test';
import assert from 'node:assert/strict';

function browser() {
  const jar = new Map();
  globalThis.document = {
    get cookie() { return [...jar].map(([k, v]) => `${k}=${v}`).join('; '); },
    set cookie(str) {
      const [pair, ...attrs] = str.split(';').map((x) => x.trim());
      const i = pair.indexOf('='); const name = pair.slice(0, i); const value = pair.slice(i + 1);
      const exp = attrs.find((a) => /^expires=/i.test(a));
      if (exp && new Date(exp.slice(8)).getTime() < Date.now()) jar.delete(name); else jar.set(name, value);
    },
  };
  Object.defineProperty(globalThis, 'navigator', { configurable: true, writable: true, value: {} });
  return jar;
}
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (secondsLeft) => `${b64({ alg: 'none' })}.${b64({ exp: Math.floor(Date.now() / 1000) + secondsLeft })}.sig`;
const load = () => import(`./sessionRenewal.js?${Math.random()}`); // fresh module (fresh in-flight state) per test
const reply = (status, body) => async () => new Response(JSON.stringify(body), { status });

test('decodeJwtExpiry reads exp; garbage and missing exp give null', async () => {
  browser(); const m = await load();
  assert.ok(Math.abs(m.decodeJwtExpiry(jwt(600)) - (Date.now() + 600000)) < 2000);
  assert.equal(m.decodeJwtExpiry('nope'), null);
  assert.equal(m.decodeJwtExpiry(`x.${b64({})}.y`), null);
});

test('getLocalSession reflects the cookies; needsRenewal only when a refresh token exists', async () => {
  const jar = browser(); const m = await load();
  assert.deepEqual(m.getLocalSession(), { hasAccess: false, hasRefresh: false, accessExpiresInMs: null });
  assert.equal(m.needsRenewal(m.getLocalSession()), false);                       // signed out: nothing to renew
  jar.set('userRefreshToken', 'r');
  assert.equal(m.needsRenewal(m.getLocalSession()), true);                        // "an hour later": access gone, refresh alive
  jar.set('userToken', jwt(30));
  assert.equal(m.needsRenewal(m.getLocalSession()), true);                        // inside the 2-minute window
  jar.set('userToken', jwt(3000));
  assert.equal(m.needsRenewal(m.getLocalSession()), false);
  jar.delete('userRefreshToken');
  jar.set('userToken', jwt(5));
  assert.equal(m.needsRenewal(m.getLocalSession()), false);                       // no refresh token -> can't renew anyway
});

test('nextCheckDelayMs wakes 2 minutes before expiry, clamped to 15 s … 30 min', async () => {
  browser(); const m = await load();
  const at = (ms) => ({ hasAccess: true, hasRefresh: true, accessExpiresInMs: ms });
  assert.equal(m.nextCheckDelayMs(at(10 * 60 * 1000)), 8 * 60 * 1000);
  assert.equal(m.nextCheckDelayMs(at(60 * 1000)), 15 * 1000);
  assert.equal(m.nextCheckDelayMs(at(6 * 3600 * 1000)), 30 * 60 * 1000);
  assert.equal(m.nextCheckDelayMs({ hasAccess: false, hasRefresh: false, accessExpiresInMs: null }), 60 * 1000);
});

test('renewSession: success / signed-out / outage map to distinct statuses', async () => {
  const jar = browser(); const m = await load();
  jar.set('userRefreshToken', 'r');
  assert.deepEqual(await m.renewSession({ fetchImpl: reply(200, { success: true, accessExpiresInSeconds: 3599 }) }), { status: 'renewed', accessExpiresInSeconds: 3599 });
  const out = await m.renewSession({ fetchImpl: reply(401, { code: 'TOKEN_REUSE_DETECTED', message: 'ended' }) });
  assert.deepEqual([out.status, out.code], ['signed_out', 'TOKEN_REUSE_DETECTED']);
  assert.equal((await m.renewSession({ fetchImpl: reply(503, { message: 'down' }) })).status, 'transient');
  assert.equal((await m.renewSession({ fetchImpl: async () => { throw new TypeError('offline'); } })).status, 'transient');
});

test('renewSession is single-flight: parallel callers share one request', async () => {
  const jar = browser(); const m = await load(); jar.set('userRefreshToken', 'r');
  let calls = 0;
  const slow = async () => { calls++; await new Promise((r) => setTimeout(r, 20)); return new Response(JSON.stringify({ success: true }), { status: 200 }); };
  const rs = await Promise.all([1, 2, 3, 4, 5].map(() => m.renewSession({ fetchImpl: slow })));
  assert.equal(calls, 1);
  assert.ok(rs.every((r) => r.status === 'renewed'));
});

test('a tab that waited for the lock skips the request when another tab already renewed', async () => {
  const jar = browser(); const m = await load(); jar.set('userRefreshToken', 'r');
  // simulate a lock whose holder renewed the cookie while we waited
  Object.defineProperty(globalThis, 'navigator', { configurable: true, writable: true, value: {
    locks: { request: async (_name, fn) => { jar.set('userToken', jwt(3500)); return fn(); } },
  } });
  let calls = 0;
  const r = await m.renewSession({ fetchImpl: async () => { calls++; return new Response('{}', { status: 200 }); } });
  assert.equal(r.status, 'skipped'); assert.equal(calls, 0);
});

test('force:true renews even when the token is fresh (the "Renew now" button)', async () => {
  const jar = browser(); const m = await load(); jar.set('userRefreshToken', 'r'); jar.set('userToken', jwt(3500));
  assert.equal((await m.renewSession({ force: true, fetchImpl: reply(200, { success: true }) })).status, 'renewed');
});

test('events are emitted for renewals but not for skipped checks; simulateAccessTokenExpiry removes the cookie', async () => {
  const jar = browser(); const m = await load(); jar.set('userRefreshToken', 'r'); jar.set('userToken', jwt(3500));
  const seen = []; const off = m.onSessionEvent((e) => seen.push(e.type));
  await m.renewSession({ fetchImpl: reply(200, { success: true }) });           // fresh token, not forced -> skipped
  m.simulateAccessTokenExpiry();
  assert.equal(jar.has('userToken'), false);
  await m.renewSession({ fetchImpl: reply(200, { success: true }) });
  off();
  assert.deepEqual(seen, ['simulated_expiry', 'renewed']);
});

test('fetchServerSession returns the JSON or null on failure', async () => {
  browser(); const m = await load();
  assert.deepEqual(await m.fetchServerSession(reply(200, { authenticated: true })), { authenticated: true });
  assert.equal(await m.fetchServerSession(reply(500, {})), null);
  assert.equal(await m.fetchServerSession(async () => { throw new Error('x'); }), null);
});

test('a session that exists only as httpOnly cookies (no JS-readable ones) is NOT skipped — the backend decides', async () => {
  browser(); const m = await load();
  let calls = 0;
  const r = await m.renewSession({ fetchImpl: async () => { calls++; return new Response(JSON.stringify({ success: true }), { status: 200 }); } });
  assert.equal(r.status, 'renewed'); assert.equal(calls, 1);
});
