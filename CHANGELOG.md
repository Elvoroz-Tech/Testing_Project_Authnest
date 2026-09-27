# Changelog — AuthNest testing project

## Account portal handoff

- Navbar: when signed in, a "My account" menu (`src/components/AccountMenu.jsx`) opens AuthNest's hosted
  pages (Dashboard, Profile, Security, Devices, Activity, Notifications, Help) already signed in, with a
  "Back to" link returning to this site. Log out moved into that menu.
- Backend: `GET /api/authnest/portal?page=…&return_to=…` in `authnestSession.js` renews the session if
  needed, asks AuthNest for a one-time portal code and redirects (SDK route of the same name excluded).
- Setup: `http://localhost:5175` (your frontend) must be one of the website URLs registered for the API
  key, otherwise the "Back to" link falls back to the registered website.
- Tests: 3 new cases in `test/authnestSession.test.js` (16/16 pass).

## 2.0.0 — Updated for the newer AuthNest SaaS (short-lived sessions, hardened sign-in)

**Why this release exists.** The newer AuthNest SaaS changed how sessions work: user access tokens now last **1 hour**
(they were 7 days) and are paired with a **30-day refresh token that rotates** on every use, and logging out really
revokes the session on the server. The SDK packages (`authnest-react` 1.0.10, `authnest-server` 1.0.9) were **not**
changed, and neither renews a session by itself. Left as it was, this project would have signed every visitor out once an
hour and its Log-out button would not have ended the session on AuthNest. All changes are inside this project; **nothing
in the AuthNest SaaS or the SDKs was modified.**

### Fixed
- **Visitors were signed out every hour.** The access-token cookie now expires after 1 hour and nothing renewed it. Added
  `SessionKeeper` (frontend) + `POST /api/authnest/session/refresh` (backend). Verified against a running new SaaS: an
  expired access cookie is renewed silently and `getUserData` keeps working.
- **`getUserData` failed as soon as the access token expired.** The route is now replaced by one that renews first.
- **Logout did not end the session.** The SDK's `logout` only removes the access token on AuthNest (the refresh token
  survives for 30 days), never clears the httpOnly cookies (`authnest-react` clears only the JS-readable ones), and cannot
  revoke anything once the access token has expired — it looks for the cookie, which is gone after an hour (the usual
  case: people log out after being idle). The replacement renews first when needed, calls AuthNest's
  `/api/users/logout-self` (revokes the access **and** refresh token together), then clears every session cookie
  (`authnest_user_token`, `user_refresh_token`, `user_token`, `userToken`, `userRefreshToken`, `authnest_csrf`).
  Verified: after logout the old refresh token is rejected by AuthNest.
- **`.env.example` was wrong about which AuthNest gets called.** It said `NODE_ENV` chooses the AuthNest URL. In
  `authnest-server` the URL comes from `AUTHNEST_BASE_URL`, then `AUTHNEST_DEV_MODE=true` (localhost:5000), then production —
  so `NODE_ENV=development` alone still talked to the **production** service. `.env.example` now documents
  `AUTHNEST_BASE_URL`.
- **The SDK's user-data callback answered HTTP 500** (`crypto.randomBytes is not a function` on Node 19+, `crypto is not defined`
  on older Node — the SDK uses `crypto` without importing it, so it resolves to the Web Crypto global or nothing). Added a one-line global polyfill at the top of
  `app.js`; harmless once the SDK is fixed.
- **The SDK's user-data callback dropped the refresh token**, so that flow could never be renewed. A pre-hook on
  `/auth/user-data-callback` now stores it in an httpOnly cookie.

### Added
- `Testing Backend/authnestSession.js` — routes `GET /api/authnest/session`, `POST /api/authnest/session/refresh`,
  `GET /api/authnest/getUserData`, `POST /api/authnest/logout`, `POST /api/authnest/logout-all`, mounted before the SDK
  router (which now excludes `getUserData`, `logout`, `logoutAll`). Notable behaviour:
  - reads and writes both cookie flavours (browser-SDK `userToken`/`userRefreshToken`, server-SDK httpOnly
    `authnest_user_token`/`user_refresh_token`) and re-issues only the flavour that was present;
  - **concurrent refreshes share one upstream call** (a rotated refresh token used twice looks like a replay to AuthNest,
    which then revokes the session);
  - a rejected refresh clears the cookies (401); an AuthNest outage answers **503 and keeps the cookies** so an outage
    never logs anyone out;
  - state-changing routes refuse cross-site requests (`Sec-Fetch-Site` / foreign `Origin`);
  - uses only public SDK methods plus AuthNest's documented endpoints, so it works with `authnest-server` 1.0.9 as
    published (which has no `refreshUserToken`) and with newer versions.
- `Testing Frontend/src/utils/sessionRenewal.js` + `src/components/SessionKeeper.jsx` — renew ~2 min before expiry, on
  tab-visible and on coming back online; single-flight and Web-Locks-serialised across tabs; tell `authnest-react` to
  re-read its status after a renewal or sign-out; also handles sessions that exist only as httpOnly cookies.
- `Testing Frontend/src/pages/SessionTesting.jsx` (route `/SessionTesting`) — live token/expiry view, **Renew now**,
  **Simulate "an hour later"**, `getUserData`, backend status, and an event log. Navbar links to Home / Modals / Session.
- Tests: backend `npm test` (13 tests over real HTTP against a fake AuthNest that enforces token rotation) and frontend
  `npm test` (10 tests). Root `README.md` describing the project, pages and how sessions work.
- Backend `npm start` script; frontend `npm test` script.

### Verified against the newer SaaS (running locally, with both the published `authnest-server@1.0.9` and the SDK source in the main repo)
27 end-to-end checks passed: getUserData with the new tokens; silent renewal for both cookie flavours; rotation (spent
refresh token rejected); six simultaneous requests → exactly one refresh on AuthNest; cross-site refusal; logout with an
expired access token revokes the refresh token on AuthNest; logout-all ends other devices; a rejected token clears
cookies; a replayed old refresh cookie is refused and AuthNest ends the session; an unreachable AuthNest gives 503 and
keeps the user signed in. The frontend builds and lints clean with the published `authnest-react@1.0.10` and with the SDK
source in the main repo. The `SessionKeeper` component was also exercised in jsdom (8 scenarios: renew-at-once, renew
before expiry, 401, outage, httpOnly-only session, signed-out, wake-ups, unmount) — that harness is not shipped.

### Unchanged (checked, no action needed)
- Hosted sign-in — password, passwordless (e-mail/SMS code, magic link), social (Google, GitHub, Microsoft, Facebook,
  LinkedIn, Discord, GitLab, Apple), passkeys, MFA, step-up — all happens on AuthNest's own login page and returns the
  same `token` / `refreshToken` / `session_id` to this app, so no change was needed for any of it.
- `vite.config.js`: port 5175 is still in the SDK's default CORS allow-list; the `/api` proxy is unchanged.
- `netlify.toml` and `backup/app.js`: unchanged. The old hand-rolled app in `backup/` still targets endpoints that exist
  (`/api/registration-forms/grabApiKeys`, `/api/clients/user-data`, `/api/clients/client-data`) but is not run.
- Dependencies: no version changes were required.

### Known limitations (SaaS/SDK side — deliberately not touched here)
- `authnest-server`'s `handleLogout` removes only the access token on AuthNest and its logout routes ignore the browser
  cookies; this project works around both. The same applies to any other app using the stock router.
- The `logout-self` revocation is a server-to-server call from this backend. If a Client turns on AuthNest's
  **IP-binding Zero Trust** option, AuthNest will refuse it (the request comes from this server's IP, not the browser's);
  the access token is still removed via the SDK call and the cookies are cleared, and the response says
  `revokedOnSaas: false`.
- AuthNest applies a global per-IP request limit; every request this backend makes on behalf of all visitors comes from
  one IP, so a busy deployment may need that limit raised on the AuthNest side.
- The refresh-sharing window (8 s) is in memory, per backend instance; with several instances behind a load balancer use
  sticky sessions or a shared store.
