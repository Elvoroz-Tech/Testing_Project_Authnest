// npm test — exercises authnestSession.js over real HTTP against a FAKE AuthNest that enforces the same
// rules as the real one: access tokens are JWTs with an expiry, refresh tokens rotate (each works once),
// logout-self ends a session. No AuthNest server, database or network needed.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const { createSessionRouter } = require('../authnestSession');

// ── fake AuthNest ────────────────────────────────────────────────────
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (secondsLeft, n = 0) => `${b64({ alg: 'none' })}.${b64({ exp: Math.floor(Date.now() / 1000) + secondsLeft, n })}.sig`;

function fakeSaas() {
  const s = { validRefresh: new Set(), validAccess: new Set(), calls: { refresh: 0, logoutSelf: 0 }, down: false, n: 0, revokedSessions: 0 };
  s.newSession = (ttl = 3600) => { const a = jwt(ttl, ++s.n); const r = `RT${s.n}`; s.validAccess.add(a); s.validRefresh.add(r); return { access: a, refresh: r }; };
  s.post = async (url, body, opts = {}) => {
    if (s.down) { const e = new Error('connect ECONNREFUSED'); e.code = 'ECONNREFUSED'; throw e; }
    const reply = (status, data) => ({ status, data });
    if (url.endsWith('/api/users/auth/refresh-token')) {
      s.calls.refresh++;
      await new Promise((r) => setTimeout(r, 15));
      if (s.validRefresh.delete(body.refreshToken)) { const n = s.newSession(); return reply(200, { success: true, accessToken: n.access, refreshToken: n.refresh }); }
      return reply(401, { success: false, message: 'invalid', code: 'TOKEN_REUSE_DETECTED' });
    }
    if (url.endsWith('/api/users/logout-self')) {
      s.calls.logoutSelf++;
      const t = (opts.headers.Authorization || '').replace('Bearer ', '');
      if (!s.validAccess.has(t)) return reply(401, { success: false });
      s.validAccess.clear(); s.validRefresh.clear(); s.revokedSessions++;
      return reply(200, { success: true });
    }
    if (url.endsWith('/api/users/portal/handoff')) {
      const t = (opts.headers.Authorization || '').replace('Bearer ', '');
      if (!s.validAccess.has(t)) return reply(401, { success: false });
      s.lastHandoff = body;
      return reply(200, { success: true, url: `http://saas-frontend.test/user/portal?code=C${++s.n}` });
    }
    return reply(404, {});
  };
  return s;
}

const fakeAuthnest = (saas) => ({
  getClientConfig: () => ({ authnestBaseUrl: 'http://saas.test', clientBaseUrl: 'http://localhost:5175' }),
  validateUserToken: async (token) => { if (saas.validAccess.has(token)) return { success: true, user: { name: 'Test User', email: 'u@example.com' } }; throw new Error('Invalid token'); },
  handleLogout: async () => ({ success: true }),
  getLoginLink: () => 'http://saas.test/login',
  handleLogoutAll: async (token) => { if (!saas.validAccess.has(token)) throw new Error('bad'); saas.validAccess.clear(); saas.validRefresh.clear(); return { success: true, tokensRemoved: 1 }; },
});

async function start(saas) {
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  app.use('/api/authnest', createSessionRouter(fakeAuthnest(saas)));
  const server = await new Promise((resolve) => { const sv = app.listen(0, '127.0.0.1', () => resolve(sv)); });
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

class Browser {
  constructor(url) { this.url = url; this.jar = new Map(); this.setCookies = []; }
  set(name, value, httpOnly = false) { this.jar.set(name, { value, httpOnly }); }
  get(name) { return this.jar.get(name)?.value; }
  has(name) { return this.jar.has(name); }
  async req(method, path, headers = {}) {
    const res = await fetch(this.url + path, { method, headers: { Cookie: [...this.jar].map(([k, v]) => `${k}=${v.value}`).join('; '), ...headers } });
    this.setCookies = res.headers.getSetCookie();
    for (const line of this.setCookies) {
      const [pair, ...attrs] = line.split(';').map((x) => x.trim());
      const i = pair.indexOf('='); const name = pair.slice(0, i); const value = pair.slice(i + 1);
      const expired = attrs.some((a) => /^expires=Thu, 01 Jan 1970/i.test(a)) || value === '';
      if (expired) this.jar.delete(name); else this.jar.set(name, { value, httpOnly: attrs.some((a) => a.toLowerCase() === 'httponly') });
    }
    const body = await res.json().catch(() => ({}));
    return { status: res.status, body };
  }
}
const same = { 'Sec-Fetch-Site': 'same-origin' };
const realPost = axios.post;
async function withApp(fn) {
  const saas = fakeSaas(); axios.post = saas.post;
  const app = await start(saas);
  try { await fn({ saas, ...app }); } finally { axios.post = realPost; app.server.close(); }
}
const jsSession = (b, saas, { access = true } = {}) => { const n = saas.newSession(); if (access) b.set('userToken', n.access); b.set('userRefreshToken', n.refresh); return n; };

// ── tests ────────────────────────────────────────────────────────────
test('GET /session is cheap (no upstream call) and reports renewability', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas);
  const r = await b.req('GET', '/api/authnest/session');
  assert.deepEqual([r.body.authenticated, r.body.renewable, r.body.hasAccessToken], [true, true, true]);
  assert.ok(r.body.accessExpiresInSeconds > 3000);
  assert.equal(saas.calls.refresh, 0);
  const out = await new Browser(url).req('GET', '/api/authnest/session');
  assert.equal(out.body.authenticated, false);
}));

test('getUserData: a valid session works without any refresh', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas);
  const r = await b.req('GET', '/api/authnest/getUserData');
  assert.equal(r.status, 200); assert.equal(r.body.data.email, 'u@example.com'); assert.equal(saas.calls.refresh, 0);
}));

test('"an hour later": access cookie gone -> getUserData renews silently, re-issues JS-readable cookies, rotates the refresh token', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); const first = jsSession(b, saas, { access: false });
  const r = await b.req('GET', '/api/authnest/getUserData');
  assert.equal(r.status, 200); assert.equal(saas.calls.refresh, 1);
  assert.notEqual(b.get('userRefreshToken'), first.refresh);
  assert.equal(b.jar.get('userToken').httpOnly, false);          // the browser SDK reads these from document.cookie
  assert.equal(b.jar.get('userRefreshToken').httpOnly, false);
  assert.equal(b.has('authnest_user_token'), false);             // no httpOnly cookies invented for a JS-flavour session
}));

test('httpOnly flavour stays httpOnly (and never leaks into JS-readable cookies)', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); const n = saas.newSession(); b.set('user_refresh_token', n.refresh, true);
  const r = await b.req('GET', '/api/authnest/getUserData');
  assert.equal(r.status, 200);
  assert.equal(b.jar.get('authnest_user_token').httpOnly, true); assert.equal(b.jar.get('user_refresh_token').httpOnly, true);
  assert.equal(b.has('userToken'), false);
}));

test('six simultaneous requests share ONE upstream refresh (a browser fires several at once; a 2nd use of a rotated token would look like a replay)', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas, { access: false });
  const clone = () => { const c = new Browser(url); c.jar = new Map(b.jar); return c; };   // several tabs / components, same cookies
  const rs = await Promise.all([
    clone().req('GET', '/api/authnest/getUserData'), clone().req('POST', '/api/authnest/session/refresh', same),
    clone().req('GET', '/api/authnest/getUserData'), clone().req('POST', '/api/authnest/session/refresh', same),
    clone().req('GET', '/api/authnest/getUserData'), clone().req('GET', '/api/authnest/getUserData'),
  ]);
  assert.deepEqual(rs.map((r) => r.status), [200, 200, 200, 200, 200, 200]);
  assert.equal(saas.calls.refresh, 1);
}));

test('a rejected refresh token -> 401 and every session cookie cleared', () => withApp(async ({ url }) => {
  const b = new Browser(url); b.set('userRefreshToken', 'never-issued'); b.set('userToken', 'stale');
  const r = await b.req('POST', '/api/authnest/session/refresh', same);
  assert.equal(r.status, 401); assert.equal(r.body.code, 'TOKEN_REUSE_DETECTED');
  assert.equal(b.has('userRefreshToken') || b.has('userToken'), false);
  assert.equal((await new Browser(url).req('POST', '/api/authnest/session/refresh', same)).status, 401); // nothing to renew
}));

test('an AuthNest outage is 503 (transient) and NEVER signs the user out', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas, { access: false }); saas.down = true;
  const r = await b.req('POST', '/api/authnest/session/refresh', same);
  assert.equal(r.status, 503); assert.equal(r.body.transient, true); assert.equal(b.has('userRefreshToken'), true);
  const g = await b.req('GET', '/api/authnest/getUserData');
  assert.equal(g.status, 503); assert.equal(b.has('userRefreshToken'), true);
}));

test('cross-site POSTs are refused (Sec-Fetch-Site / foreign Origin); same-origin and header-less callers are allowed', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas);
  assert.equal((await b.req('POST', '/api/authnest/session/refresh', { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  assert.equal((await b.req('POST', '/api/authnest/logout', { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  assert.equal((await b.req('POST', '/api/authnest/logout-all', { Origin: 'https://evil.example' })).status, 403);
  assert.equal(b.has('userToken'), true);                                                  // refused requests changed nothing
  assert.equal((await b.req('POST', '/api/authnest/session/refresh', { 'Sec-Fetch-Site': 'same-origin' })).status, 200);
  assert.equal((await b.req('POST', '/api/authnest/session/refresh', { Origin: 'http://localhost:5175' })).status, 200);
  assert.equal((await b.req('POST', '/api/authnest/session/refresh')).status, 200);
}));

test('logout with an EXPIRED access token: renews first, revokes the whole session on AuthNest, clears every cookie', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); const n = jsSession(b, saas, { access: false }); b.set('authnest_csrf', 'x', true);
  const r = await b.req('POST', '/api/authnest/logout', same);
  assert.equal(r.status, 200); assert.equal(r.body.revokedOnSaas, true); assert.equal(saas.calls.logoutSelf, 1);
  assert.equal(saas.validRefresh.size, 0);                                                  // the refresh token is dead server-side
  for (const name of ['userToken', 'userRefreshToken', 'authnest_user_token', 'user_refresh_token', 'user_token', 'authnest_csrf']) assert.equal(b.has(name), false, name);
  assert.ok(b.setCookies.length >= 6);
  assert.equal(saas.validRefresh.has(n.refresh), false);
}));

test('logout-all revokes every session', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas); const other = saas.newSession();
  const r = await b.req('POST', '/api/authnest/logout-all', same);
  assert.equal(r.status, 200); assert.equal(r.body.revokedOnSaas, true);
  assert.equal(saas.validAccess.has(other.access), false); assert.equal(saas.validRefresh.has(other.refresh), false);
  assert.equal(b.has('userToken'), false);
}));

test('logout while AuthNest is down still signs out locally and says so honestly', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas); saas.down = true;
  const r = await b.req('POST', '/api/authnest/logout', same);
  assert.equal(r.status, 200); assert.equal(r.body.revokedOnSaas, false); assert.equal(b.has('userToken'), false);
}));

test('getUserData: a token AuthNest no longer accepts (revoked mid-life) is renewed once, then 401 if it still fails', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); const n = jsSession(b, saas);
  saas.validAccess.delete(n.access);                    // revoked on the server although the cookie still looks fresh
  const r = await b.req('GET', '/api/authnest/getUserData');
  assert.equal(r.status, 200); assert.equal(saas.calls.refresh, 1);       // renewed and retried once
  saas.validRefresh.clear(); saas.validAccess.clear(); saas.down = false;
  const dead = await b.req('GET', '/api/authnest/getUserData');
  assert.equal(dead.status, 401);
}));

test('user-data callback pre-hook stores the refresh token (only when the callback is well-formed), then falls through', () => withApp(async ({ url }) => {
  // no SDK router is mounted in this test, so the request falls through to Express' 404 — what matters is the cookie
  const ok = new Browser(url);
  await ok.req('GET', '/api/authnest/auth/user-data-callback?token=A&refreshToken=R&data=%7B%7D&state=s');
  assert.equal(ok.jar.get('user_refresh_token')?.value, 'R'); assert.equal(ok.jar.get('user_refresh_token').httpOnly, true);
  for (const q of ['token=A&refreshToken=R&state=s', 'token=A&refreshToken=R&data=%7B%7D&error=denied', 'token=A&data=%7B%7D']) {
    const b = new Browser(url); await b.req('GET', `/api/authnest/auth/user-data-callback?${q}`);
    assert.equal(b.has('user_refresh_token'), false, q);
  }
}));

// ── account portal handoff ───────────────────────────────────────────
const portal = (url, b, qs) => fetch(`${url}/api/authnest/portal?${qs}`, { redirect: 'manual', headers: { Cookie: [...b.jar].map(([k, v]) => `${k}=${v.value}`).join('; ') } });

test('portal: signed-in visitor is redirected to the hosted page with a one-time code', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas);
  const r = await portal(url, b, 'page=security&return_to=' + encodeURIComponent('http://localhost:5175/account'));
  assert.equal(r.status, 302);
  assert.match(r.headers.get('location'), /^http:\/\/saas-frontend\.test\/user\/portal\?code=/);
  assert.deepEqual(saas.lastHandoff, { page: 'security', returnTo: 'http://localhost:5175/account', env: process.env.NODE_ENV === 'production' ? 'production' : 'development' });
}));

test('portal: expired access token is renewed first', () => withApp(async ({ saas, url }) => {
  const b = new Browser(url); jsSession(b, saas, { access: false });
  const r = await portal(url, b, 'page=profile');
  assert.equal(r.status, 302); assert.equal(saas.calls.refresh, 1);
}));

test('portal: signed-out visitor goes to the login page', () => withApp(async ({ url }) => {
  const r = await portal(url, new Browser(url), 'page=profile');
  assert.equal(r.status, 302); assert.equal(r.headers.get('location'), 'http://saas.test/login');
}));
