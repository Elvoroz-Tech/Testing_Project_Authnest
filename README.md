# AuthNest testing project

A small app for testing an integration of AuthNest end to end: a Vite/React frontend that uses
`authnest-react`, and an Express backend that uses `authnest-server`.

```
Testing Frontend/   React app (port 5175)  — login/registration buttons, profile & security modals, session testing page
Testing Backend/    Express API (port 9000) — authnest-server router + session handling for the newer AuthNest
```

## Running it

1. **Backend** — `cd "Testing Backend" && npm install`, copy `.env.example` to `.env`, fill in
   `CLIENT_AUTHNEST_API_KEY`, `CLIENT_AUTHNEST_SECRET_KEY`, `MONGODB_URI`, and set **`AUTHNEST_BASE_URL`** to the
   AuthNest backend you want to test against (see the note in `.env.example` — `NODE_ENV` does not choose it).
   `npm start`.
2. **Frontend** — `cd "Testing Frontend" && npm install && npm run dev`, open <http://localhost:5175>.
   (Port 5175 is deliberate: it is in the SDK's default CORS allow-list.) Vite proxies `/api` to the backend.

## Pages

| Route | What it tests |
|---|---|
| `/` | Log in / register / log out (navbar), user data, profile and security-settings modals |
| `/ModalsTesting` | Two-factor, password-confirm and e-mail-verification modals |
| `/SessionTesting` | **Session behaviour of the newer AuthNest** — live view of the access/refresh tokens, "Renew now", "Simulate an hour later", `getUserData`, and a log of silent renewals |

## How sessions work with the newer AuthNest

AuthNest now issues a **1-hour access token** and a **30-day refresh token that rotates** (each refresh token works
once; replaying a used one ends the whole session). Neither SDK renews by itself, so this project does it:

* `Testing Backend/authnestSession.js` replaces three of the SDK router's routes (`getUserData`, `logout`, `logout-all`)
  and adds `GET /api/authnest/session` and `POST /api/authnest/session/refresh`. It renews expired access tokens,
  shares one upstream refresh between simultaneous requests, and makes logout really end the session on AuthNest.
* `Testing Frontend/src/components/SessionKeeper.jsx` (mounted once in `App.jsx`) renews the token ~2 minutes before it
  expires, when the tab becomes visible again, and when the network returns — so visitors aren't signed out hourly.

Sign-in itself (password, passwordless codes/links, social providers, passkeys, MFA, step-up) all happens on AuthNest's
hosted login page, so it needs nothing from this app; whatever the Super Admin enables there just works.

## Tests

```
cd "Testing Backend"  && npm test     # 13 tests: session module over real HTTP against a fake AuthNest that enforces rotation
cd "Testing Frontend" && npm test     # 10 tests: renewal timing / single-flight / cross-tab logic
```

Neither needs an AuthNest server. See `CHANGELOG.md` for what changed and why.
