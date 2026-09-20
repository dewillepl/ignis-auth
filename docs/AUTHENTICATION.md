# Authentication

Upstream Ignis ships without a login gate and expects a reverse proxy to provide one.
This fork has a built-in one: a username and password, checked against a bcrypt hash, in
front of everything the server exposes.

## What is protected

Once auth is configured, an unauthenticated request reaches nothing but the login page:

| Surface                              | Unauthenticated result           |
| ------------------------------------ | -------------------------------- |
| `/` and the Obsidian assets          | redirect to `/login`             |
| `/api/*` (fs, vault, proxy, plugins) | `401` + `X-Ignis-Auth: required` |
| `/vault-files/*` (attachments)       | `401`                            |
| `/ws` WebSocket upgrade              | `401`, socket closed             |
| `/login`, `/logout`, `/favicon.png`  | reachable, by design             |

The gate is mounted before every route and every static mount in
[`server/index.js`](../apps/ignis-server/server/index.js), so a route added later is
protected by default rather than by remembering to protect it.

## Setup

Generate a hash:

```bash
npm run auth:hash
```

It prompts without echoing, and prints the line to paste into `.env`. To avoid the prompt:
`npm run auth:hash -- 'yourpassword'`. Without a local Node install, run it in the image:
`docker run --rm ignis:local node apps/ignis-server/scripts/hash-password.js 'yourpassword'`.

Put the result in `.env` next to `docker-compose.yml` (see [`.env.example`](../.env.example)):

```
AUTH_USERNAME=kuba
AUTH_PASSWORD_HASH=$$2b$$12$$....
```

The doubled `$$` is deliberate. docker-compose reads a single `$` in `.env` as variable
interpolation and mangles the hash; quoting does not help. The generator emits the doubled
form, and the server accepts either, so a hash copied straight from PHP's
`password_hash($pw, PASSWORD_BCRYPT)` also works.

Compose picks the file up through `env_file: - .env`.

## Environment variables

| Variable                 | Default        | Meaning                                                        |
| ------------------------ | -------------- | -------------------------------------------------------------- |
| `AUTH_USERNAME`          | –              | The single account's username.                                  |
| `AUTH_PASSWORD_HASH`     | –              | bcrypt hash (`$2a$`/`$2b$`/`$2y$`), plain or `$$`-doubled.      |
| `AUTH_ENABLED`           | auto           | Unset follows the credentials. `true` without them fails to start; `false` turns the gate off. |
| `AUTH_SESSION_SECRET`    | generated      | HMAC key for session cookies. Generated and stored in `/app/data/.session-secret` when unset. |
| `AUTH_SESSION_TTL_HOURS` | `168`          | Session lifetime. Refreshed once past half of it.               |
| `AUTH_MAX_ATTEMPTS`      | `5`            | Failed logins per IP before a lockout.                          |
| `AUTH_LOCKOUT_MINUTES`   | `15`           | How long that lockout lasts.                                    |
| `AUTH_COOKIE_SECURE`     | `false`        | Mark the cookie `Secure`. Turn on when served over HTTPS.       |
| `AUTH_COOKIE_NAME`       | `ignis_session`| Cookie name.                                                    |
| `AUTH_TRUST_PROXY`       | `false`        | Read the client IP from `X-Forwarded-For`. Only behind a proxy you trust. |

Missing credentials mean the gate stays off and the server says so loudly at startup, which
keeps the upstream behaviour intact for anyone running this fork without configuring auth.

## How it works

- **Password check** – bcrypt (`bcryptjs`, pure JS, so `npm ci --ignore-scripts` in the
  Dockerfile stays valid). A wrong username is compared against a dummy hash so both failure
  modes cost the same time and cannot be told apart.
- **Session** – a signed cookie, no server-side store:
  `base64url(payload).base64url(HMAC-SHA256(payload))`, `HttpOnly`, `SameSite=Lax`, `Path=/`.
  Nothing to lose on restart, and no session table to grow.
- **Credential fingerprint** – the payload carries a hash of username + password hash +
  secret, so changing either signs out every existing session.
- **Rolling refresh** – a session past half its lifetime gets a fresh cookie on the next
  request, so an open tab does not expire mid-edit.
- **Throttling** – failures are counted per IP; `AUTH_MAX_ATTEMPTS` in a 15-minute window
  triggers a lockout, and the correct password is refused while it stands.
- **Expiry in an open tab** – [`assets/auth-client.js`](../apps/ignis-server/server/assets/auth-client.js)
  watches for `401` + `X-Ignis-Auth: required` on `fetch`/`XHR` and sends the tab to the login
  page, instead of the UI quietly failing every request.
- **Sign-out button** – the same script exposes `window.__ignisAuth.signOut()`, which the
  bridge plugin's button calls; it posts to `/logout` and lands on the login page whether or
  not the request got through.

## Signing out

A sign-out button sits with Obsidian's own help and settings icons - the bottom bar of the
left drawer in the mobile/tablet layout a browser gets, the bottom of the left ribbon on
desktop. It asks for confirmation, then ends the session and returns to the login page.
`/logout` still works on its own (GET or POST) for scripts and bookmarks.

It lives in the Ignis bridge plugin
([`packages/bridge/src/logout-button.js`](../packages/bridge/src/logout-button.js)), which runs
inside Obsidian. Obsidian builds the drawer lazily and rebuilds it on layout changes, so a
debounced MutationObserver re-inserts the button rather than placing it once at startup. The
button appears only when authentication is on: `assets/auth-client.js`, which the server injects
only in that case, publishes `window.__ignisAuth` for the plugin to read.

## Limits

- One account. Multiple users would need a user store, which this does not have.
- No 2FA, and no password change from inside the app: change `.env` and restart.
- `SameSite=Lax` plus a same-origin form is what stops cross-site request forgery; there is
  no separate CSRF token.
- Serve it over HTTPS before exposing it beyond localhost, and set `AUTH_COOKIE_SECURE=true`
  when you do. The gate protects the vault; it does not encrypt the traffic.
