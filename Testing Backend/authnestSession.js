// authnestSession.js — session handling for the AuthNest testing backend.
//
// WHY THIS FILE EXISTS
// The newer AuthNest SaaS issues SHORT-LIVED sessions: a 1-hour access token plus a 30-day refresh
// token that ROTATES (each refresh token works exactly once). The stock routes that
// `authnest.getRouter()` mounts don't renew anything, so on their own an end user would be signed
// out every hour and `/logout` would leave the session alive on the SaaS. This module replaces the
// three routes that are affected and adds two small session routes — using only the SDK's public
// surface plus documented SaaS endpoints, so `@elvoroz/authnest-server` itself needs no changes:
//
//   GET  /api/authnest/session          cheap status (no SaaS call): is the visitor signed in / renewable?
//   POST /api/authnest/session/refresh  renew the session now (used by the frontend's <SessionKeeper/>)
//   GET  /api/authnest/getUserData      like the SDK's, but renews an expired access token first
//   POST /api/authnest/logout           revokes the session on the SaaS, then clears every cookie
//   POST /api/authnest/logout-all       same, for every device
//   GET  /api/authnest/portal           opens a hosted account page (profile, security, …) already signed in
//   GET  /api/authnest/auth/user-data-callback   (pre-hook only) also keeps the refresh token — see below
//
// COOKIES
// The SDK and the browser SDK store the tokens under different names depending on the flow, so this
// module reads all of them and writes back only the flavour(s) that were present:
//   browser SDK (JS-readable):  userToken / userRefreshToken
//   server SDK  (httpOnly):     authnest_user_token / user_refresh_token   (+ legacy user_token)

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const ACCESS_NAMES = ['authnest_user_token', 'user_token', 'userToken'];
const REFRESH_NAMES = ['user_refresh_token', 'userRefreshToken'];
const OTHER_COOKIES = ['authnest_csrf', 'authnest_csrf_token'];
const ACCESS_MAX_AGE_MS = 60 * 60 * 1000;
const REFRESH_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

// A refresh token is single-use. A browser routinely fires several requests at once (page load:
// status panel + navbar + a button), and they all carry the SAME cookie. Without de-duplication the
// second one would present an already-spent token, which the SaaS treats as a possible replay
// (and, if it arrives late enough, revokes the whole session). So concurrent — and just-completed —
// refreshes with the same token share ONE upstream call.
const SHARE_RESULT_MS = 8000;

const first = (req, names) => {
  for (const n of names) if (req.cookies && req.cookies[n]) return { name: n, value: req.cookies[n] };
  return null;
};

function jwtExpiryMs(token) {
  try {
    const payload = JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8'));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
  } catch (e) {
    return null;
  }
}

/**
 * @param {import('@elvoroz/authnest-server')} authnest   an AuthNestClient instance
 * @param {object} [options]
 * @param {(req) => boolean} [options.isTrustedRequest]  override the CSRF-style origin check
 */
function createSessionRouter(authnest, options = {}) {
  const router = express.Router();
  const isProduction = process.env.NODE_ENV === 'production';
  const shared = new Map(); // sha256(refreshToken) -> { promise, expires }

  const config = () => authnest.getClientConfig();
  const baseUrl = () => config().authnestBaseUrl;

  // ── request hygiene ────────────────────────────────────────────────
  // These routes act on cookies, so a cross-site page must not be able to trigger them. Cookies are
  // SameSite=Strict already; this is a second, independent check. Browsers send Sec-Fetch-Site on
  // every request; non-browser callers (curl, tests) send neither header and are allowed.
  const trustedOrigins = () => [config().clientBaseUrl, process.env.CLIENT_BASE_URL, ...(process.env.FRONTEND_ORIGINS || '').split(',')]
    .map((s) => (s || '').trim().replace(/\/$/, '')).filter(Boolean);
  const isTrusted = options.isTrustedRequest || ((req) => {
    const site = req.get('Sec-Fetch-Site');
    if (site) return ['same-origin', 'same-site', 'none'].includes(site);
    const origin = req.get('Origin');
    if (!origin) return true;
    return trustedOrigins().includes(origin.replace(/\/$/, '')) || origin === `${req.protocol}://${req.get('host')}`;
  });
  const requireTrusted = (req, res, next) => (isTrusted(req)
    ? next()
    : res.status(403).json({ success: false, message: 'Cross-site request refused.' }));

  // ── cookies ────────────────────────────────────────────────────────
  const cookieBase = { secure: isProduction, sameSite: 'strict', path: '/' };

  function setSessionCookies(req, res, { accessToken, refreshToken }) {
    const exp = jwtExpiryMs(accessToken);
    const accessAge = exp ? Math.max(exp - Date.now(), 1000) : ACCESS_MAX_AGE_MS;
    const hadHttpOnly = !!(req.cookies && (req.cookies.user_refresh_token || req.cookies.authnest_user_token));
    const hadJs = !!(req.cookies && (req.cookies.userRefreshToken || req.cookies.userToken));
    // If neither flavour is identifiable (shouldn't happen: we only refresh when a refresh cookie exists)
    // fall back to the httpOnly flavour, the safer one.
    if (hadHttpOnly || !hadJs) {
      res.cookie('authnest_user_token', accessToken, { ...cookieBase, httpOnly: true, maxAge: accessAge });
      res.cookie('user_refresh_token', refreshToken, { ...cookieBase, httpOnly: true, maxAge: REFRESH_MAX_AGE_MS });
    }
    if (hadJs) {
      // The browser SDK reads these from document.cookie, so they must NOT be httpOnly.
      res.cookie('userToken', accessToken, { ...cookieBase, httpOnly: false, maxAge: accessAge });
      res.cookie('userRefreshToken', refreshToken, { ...cookieBase, httpOnly: false, maxAge: REFRESH_MAX_AGE_MS });
    }
    // The legacy name is only ever cleared, never re-issued.
    if (req.cookies && req.cookies.user_token) res.clearCookie('user_token', { path: '/' });
  }

  function clearSessionCookies(res) {
    [...ACCESS_NAMES, ...REFRESH_NAMES, ...OTHER_COOKIES].forEach((n) => res.clearCookie(n, { path: '/' }));
  }

  // ── talking to the SaaS ────────────────────────────────────────────
  async function callSaasRefresh(refreshToken, req) {
    let response;
    try {
      response = await axios.post(
        `${baseUrl()}/api/users/auth/refresh-token`,
        { refreshToken },
        {
          headers: { 'Content-Type': 'application/json', 'User-Agent': req.get('User-Agent') || 'AuthNest-Testing-Backend', ...(config().clientBaseUrl ? { Origin: config().clientBaseUrl } : {}) },
          timeout: 10000,
          validateStatus: () => true,
        }
      );
    } catch (e) {
      return { ok: false, transient: true, message: `Could not reach AuthNest (${e.code || e.message})` };
    }
    const { status, data } = response;
    if (status === 200 && data && data.success && data.accessToken && data.refreshToken) {
      return { ok: true, accessToken: data.accessToken, refreshToken: data.refreshToken };
    }
    if (status === 401 || status === 403) {
      return { ok: false, rejected: true, code: data && data.code, message: (data && data.message) || 'Session expired' };
    }
    return { ok: false, transient: true, message: (data && data.message) || `AuthNest answered ${status}` };
  }

  function refreshOnce(refreshToken, req) {
    const key = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const hit = shared.get(key);
    if (hit && hit.expires > Date.now()) return hit.promise;
    const entry = { promise: callSaasRefresh(refreshToken, req), expires: Date.now() + SHARE_RESULT_MS };
    shared.set(key, entry);
    entry.promise.then((r) => { if (!r.ok) shared.delete(key); }); // never share a failure
    setTimeout(() => shared.delete(key), SHARE_RESULT_MS + 500).unref();
    return entry.promise;
  }

  /**
   * Returns a usable access token for this request, renewing it if needed.
   * @returns {Promise<{ token?: string, renewed?: boolean, rejected?: boolean, transient?: boolean, message?: string }>}
   */
  async function ensureAccessToken(req, res, { forceRefresh = false } = {}) {
    const access = first(req, ACCESS_NAMES);
    const refresh = first(req, REFRESH_NAMES);
    const exp = access ? jwtExpiryMs(access.value) : null;
    const usable = access && (exp === null || exp - Date.now() > 30 * 1000);
    if (usable && !forceRefresh) return { token: access.value, renewed: false };
    if (!refresh) return access ? { token: access.value, renewed: false } : { rejected: true, message: 'Not signed in' };

    const r = await refreshOnce(refresh.value, req);
    if (r.ok) {
      setSessionCookies(req, res, r);
      return { token: r.accessToken, renewed: true };
    }
    if (r.rejected) { clearSessionCookies(res); return { rejected: true, code: r.code, message: r.message }; }
    return { transient: true, message: r.message };
  }

  // ── routes ─────────────────────────────────────────────────────────
  // The SDK's user-data callback stores the ACCESS token in an httpOnly cookie but (in @elvoroz/authnest-server
  // 1.0.9 as published) drops the refresh token that AuthNest now sends along. Without it the session
  // could never be renewed and would end after an hour. This pre-hook stores it, then lets the SDK's own
  // handler carry on (newer SDK versions set the same cookie themselves; setting it twice is harmless).
  router.get('/auth/user-data-callback', (req, res, next) => {
    const { token, refreshToken, data, error } = req.query;
    if (!error && data && token && typeof refreshToken === 'string' && refreshToken) {
      res.cookie('user_refresh_token', refreshToken, { ...cookieBase, httpOnly: true, maxAge: REFRESH_MAX_AGE_MS });
    }
    next();
  });

  router.get('/session', (req, res) => {
    const access = first(req, ACCESS_NAMES);
    const refresh = first(req, REFRESH_NAMES);
    const exp = access ? jwtExpiryMs(access.value) : null;
    const secondsLeft = exp ? Math.round((exp - Date.now()) / 1000) : null;
    res.json({
      success: true,
      authenticated: !!((access && (secondsLeft === null || secondsLeft > 0)) || refresh),
      hasAccessToken: !!access,
      accessExpiresInSeconds: secondsLeft,
      renewable: !!refresh,
    });
  });

  router.post('/session/refresh', requireTrusted, async (req, res) => {
    const r = await ensureAccessToken(req, res, { forceRefresh: true });
    if (r.token && r.renewed) {
      const exp = jwtExpiryMs(r.token);
      return res.json({ success: true, renewed: true, accessExpiresInSeconds: exp ? Math.round((exp - Date.now()) / 1000) : null });
    }
    if (r.token) return res.json({ success: true, renewed: false });
    if (r.transient) return res.status(503).json({ success: false, transient: true, message: r.message });
    return res.status(401).json({ success: false, code: r.code || 'SESSION_EXPIRED', message: r.message || 'Session expired. Please log in again.' });
  });

  router.get('/getUserData', async (req, res) => {
    try {
      let s = await ensureAccessToken(req, res);
      if (!s.token) {
        return s.transient
          ? res.status(503).json({ success: false, message: s.message })
          : res.status(401).json({ success: false, message: 'Authentication required. Please login first.' });
      }

      const validate = async (token) => {
        try { return await authnest.validateUserToken(token, req); } catch (e) { return null; }
      };
      let result = await validate(s.token);

      // The token can be revoked or expire between the check above and here; renew once and retry.
      if (!(result && result.success) && !s.renewed) {
        s = await ensureAccessToken(req, res, { forceRefresh: true });
        if (s.token) result = await validate(s.token);
      }

      if (result && result.success) {
        return res.json({ success: true, data: result.user, message: 'User data retrieved successfully' });
      }
      return res.status(401).json({ success: false, message: 'Invalid or expired authentication' });
    } catch (error) {
      console.error('getUserData error:', error.message);
      return res.status(500).json({ success: false, message: 'Failed to fetch user data' });
    }
  });

  /** Ends the session on the SaaS as far as the caller's credentials allow, then clears every cookie. */
  async function endSession(req, res, { all }) {
    const summary = { revokedOnSaas: false };
    try {
      // The access token lasts an hour, so it is often gone by the time someone clicks "log out".
      // Renew first: the refresh token alone can't authorise a revocation, but a fresh access token can.
      const s = await ensureAccessToken(req, res);
      if (s.token) {
        if (all) {
          const out = await authnest.handleLogoutAll(s.token);
          summary.revokedOnSaas = !!(out && out.success);
        } else {
          // /logout-self revokes this session's access AND refresh tokens together. (The SDK's
          // handleLogout only removes the access token.) Best effort: a Client that enabled the
          // IP-binding Zero Trust option will refuse this server-to-server call, in which case the
          // SDK call below still removes the access token.
          const r = await axios.post(`${baseUrl()}/api/users/logout-self`, {}, {
            headers: { Authorization: `Bearer ${s.token}`, 'User-Agent': req.get('User-Agent') || 'AuthNest-Testing-Backend' },
            timeout: 8000,
            validateStatus: () => true,
          }).catch(() => null);
          summary.revokedOnSaas = !!(r && r.status === 200);
          await authnest.handleLogout(s.token).catch(() => {});
        }
      }
    } catch (e) {
      console.error('logout: SaaS revocation failed (cookies are cleared anyway):', e.message);
    } finally {
      clearSessionCookies(res);
    }
    return summary;
  }

  router.post('/logout', requireTrusted, async (req, res) => {
    const summary = await endSession(req, res, { all: false });
    res.json({ success: true, message: 'Logged out', ...summary });
  });

  router.post('/logout-all', requireTrusted, async (req, res) => {
    const summary = await endSession(req, res, { all: true });
    res.json({ success: true, message: summary.revokedOnSaas ? 'Logged out from all devices' : 'Signed out here; could not confirm sign-out on other devices', ...summary });
  });

  // GET /portal?page=security&return_to=<url on this site>
  // Renews the session if needed, asks AuthNest for a one-time portal code, then redirects.
  // Same job as the SDK's route of the same name (authnest-server >= 1.2.0), but with token renewal.
  router.get('/portal', async (req, res) => {
    const page = typeof req.query.page === 'string' ? req.query.page : 'profile';
    const returnTo = (typeof req.query.return_to === 'string' && req.query.return_to) || req.get('Referer') || config().clientBaseUrl || null;
    const toLogin = () => {
      try { return res.redirect(authnest.getLoginLink(undefined, undefined, req.query.session_id, req)); } catch (e) { return res.status(401).json({ success: false, message: 'Please log in first.' }); }
    };
    try {
      const s = await ensureAccessToken(req, res);
      if (!s.token) return s.transient ? res.status(503).json({ success: false, message: s.message }) : toLogin();
      const r = await axios.post(`${baseUrl()}/api/users/portal/handoff`, { page, returnTo, env: process.env.NODE_ENV === 'production' ? 'production' : 'development' }, {
        headers: {
          Authorization: `Bearer ${s.token}`,
          'Content-Type': 'application/json',
          'User-Agent': req.get('User-Agent') || 'AuthNest-Testing-Backend',
          ...(config().clientBaseUrl ? { Origin: config().clientBaseUrl } : {}),
        },
        timeout: 10000,
        validateStatus: () => true,
      });
      if (r.status === 200 && r.data && r.data.success && r.data.url) return res.redirect(r.data.url);
      if (r.status === 401 || r.status === 403) return toLogin();
      return res.status(502).json({ success: false, message: (r.data && r.data.message) || 'Could not open the account page.' });
    } catch (e) {
      console.error('portal: handoff failed:', e.message);
      return res.status(502).json({ success: false, message: 'Could not open the account page.' });
    }
  });

  return router;
}

module.exports = { createSessionRouter, jwtExpiryMs, ACCESS_NAMES, REFRESH_NAMES };
