// sessionRenewal.js — keeps an AuthNest session alive from the browser.
//
// The newer AuthNest issues a 1-hour access token and a 30-day refresh token that rotates on every
// use. @elvoroz/authnest-react stores them in two JS-readable cookies (userToken / userRefreshToken) but does
// not renew them by itself, so without this file the visitor would be signed out every hour.
//
// The actual renewal happens on THIS app's backend (POST /api/authnest/session/refresh, see
// Testing Backend/authnestSession.js) — it holds the SaaS URL and de-duplicates concurrent refreshes.
// This module only decides WHEN to ask, and makes sure that happens once even with several tabs open.

export const SESSION_ENDPOINT = '/api/authnest/session';
export const REFRESH_ENDPOINT = '/api/authnest/session/refresh';
export const ACCESS_COOKIE = 'userToken';
export const REFRESH_COOKIE = 'userRefreshToken';
export const RENEW_AHEAD_MS = 2 * 60 * 1000; // renew when less than 2 minutes remain

export function readCookie(name) {
  try {
    for (const part of document.cookie.split(';')) {
      const i = part.indexOf('=');
      if (i !== -1 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
    }
  } catch { /* no document */ }
  return null;
}

/** Expiry (ms since epoch) from a JWT's `exp` claim, or null when it can't be read. */
export function decodeJwtExpiry(token) {
  try {
    const payload = String(token).split('.')[1];
    if (!payload) return null;
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const exp = JSON.parse(json).exp;
    return typeof exp === 'number' ? exp * 1000 : null;
  } catch {
    return null;
  }
}

/** What this browser can see locally (no network): the JS-readable session cookies. */
export function getLocalSession(now = Date.now()) {
  const access = readCookie(ACCESS_COOKIE);
  const refresh = readCookie(REFRESH_COOKIE);
  const exp = access ? decodeJwtExpiry(access) : null;
  return {
    hasAccess: !!access,
    hasRefresh: !!refresh,
    accessExpiresInMs: exp === null ? null : exp - now,
  };
}

/** true when a refresh token exists and the access token is missing or about to expire. */
export function needsRenewal(session, aheadMs = RENEW_AHEAD_MS) {
  if (!session.hasRefresh) return false;
  if (!session.hasAccess) return true;
  return session.accessExpiresInMs !== null && session.accessExpiresInMs < aheadMs;
}

/** Milliseconds until the next check should run (never faster than 15 s, never slower than 30 min). */
export function nextCheckDelayMs(session, aheadMs = RENEW_AHEAD_MS) {
  if (!session.hasRefresh && !session.hasAccess) return 60 * 1000;
  if (session.accessExpiresInMs === null) return 60 * 1000;
  return Math.min(Math.max(session.accessExpiresInMs - aheadMs, 15 * 1000), 30 * 60 * 1000);
}

// ── tiny event log so pages can show what the keeper did ──────────────
const listeners = new Set();
export function onSessionEvent(fn) { listeners.add(fn); return () => listeners.delete(fn); }
function emit(event) { listeners.forEach((fn) => { try { fn({ at: new Date(), ...event }); } catch { /* listener bug */ } }); }

let inFlight = null;

async function doRenew({ fetchImpl, force }) {
  // Re-check inside the lock: another tab may have renewed while we waited. Only meaningful when the
  // JS-readable cookies exist — a session kept purely in httpOnly cookies can't be inspected here, so
  // let the backend decide.
  const local = getLocalSession();
  if (!force && (local.hasAccess || local.hasRefresh) && !needsRenewal(local)) return { status: 'skipped' };
  let res;
  try {
    res = await fetchImpl(REFRESH_ENDPOINT, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    return { status: 'transient', message: e.message }; // offline: keep the session
  }
  const body = await res.json().catch(() => ({}));
  if (res.ok && body.success) return { status: 'renewed', accessExpiresInSeconds: body.accessExpiresInSeconds ?? null };
  if (res.status === 401) return { status: 'signed_out', code: body.code, message: body.message };
  return { status: 'transient', message: body.message || `Server answered ${res.status}` };
}

/**
 * Ask the backend to renew the session. Single-flight in this page; serialised across tabs with the
 * Web Locks API where available. Never throws.
 * @returns {Promise<{status: 'renewed'|'skipped'|'signed_out'|'transient', accessExpiresInSeconds?: number, code?: string, message?: string}>}
 */
export function renewSession({ force = false, fetchImpl = (...a) => fetch(...a) } = {}) {
  if (inFlight) return inFlight;
  const run = () => doRenew({ fetchImpl, force });
  const locked = (typeof navigator !== 'undefined' && navigator.locks && navigator.locks.request)
    ? navigator.locks.request('authnest-testing-session-renew', run)
    : run();
  inFlight = Promise.resolve(locked)
    .then((r) => { if (r.status !== 'skipped') emit({ type: r.status, ...r }); return r; })
    .finally(() => { inFlight = null; });
  return inFlight;
}

/** Server-side view (also sees httpOnly cookies). One small request, no SaaS call. */
export async function fetchServerSession(fetchImpl = (...a) => fetch(...a)) {
  try {
    const res = await fetchImpl(SESSION_ENDPOINT, { credentials: 'include' });
    return res.ok ? await res.json() : null;
  } catch {
    return null;
  }
}

/** Deletes the JS-readable access cookie — simulates "an hour has passed" for testing. */
export function simulateAccessTokenExpiry() {
  document.cookie = `${ACCESS_COOKIE}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/`;
  emit({ type: 'simulated_expiry' });
}
