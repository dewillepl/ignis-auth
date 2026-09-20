// Username + password gate in front of the whole server.
//
// Everything except the login page itself requires a valid session cookie: the API, the
// WebSocket, the Obsidian assets and the vault files. Credentials come from the environment
// (see ./config.js), the password is checked against a bcrypt hash, and a signed cookie
// (see ./session.js) carries the session from there on.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const express = require("express");
const bcrypt = require("bcryptjs");

const { loadAuthConfig } = require("./config");
const { createSessions } = require("./session");
const { createRateLimiter, clientIp } = require("./rate-limit");

// Compared against when the username is wrong, so a bad username costs the same time as a bad
// password and cannot be told apart from one.
const DUMMY_HASH =
  "$2b$10$OClnM7m9/S6PO1tyPIJEcuBvDD777Rhgp3CTItI22N5SyUtCPajIO";

// bcrypt only reads the first 72 bytes; the cap just stops a huge body from being hashed at all.
const MAX_PASSWORD_BYTES = 1024;

const LOGIN_PATH = "/login";
const LOGOUT_PATH = "/logout";

// Reachable without a session. Everything else goes through the gate.
const PUBLIC_PATHS = new Set([
  LOGIN_PATH,
  LOGOUT_PATH,
  "/favicon.png",
  "/api/auth/session",
]);

const LOGIN_TEMPLATE = fs.readFileSync(
  path.join(__dirname, "login.html"),
  "utf-8",
);

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Only same-site absolute paths survive, so ?next= cannot bounce the user to another origin.
function safeNext(value) {
  if (typeof value !== "string" || !value.startsWith("/")) {
    return "/";
  }

  if (value.startsWith("//") || value.includes("\\")) {
    return "/";
  }

  return value.length > 512 ? "/" : value;
}

function renderLogin({ error = "", next = "/", username = "" } = {}) {
  const errorBlock = error
    ? `<div class="error" role="alert">${escapeHtml(error)}</div>`
    : "";

  return LOGIN_TEMPLATE.replace("__ERROR__", errorBlock)
    .replace("__NEXT__", escapeHtml(next))
    .replace("__USERNAME__", escapeHtml(username));
}

function timingSafeEquals(a, b) {
  // Hashing first keeps the comparison constant-time regardless of length.
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();

  return crypto.timingSafeEqual(ha, hb);
}

function wantsJson(req) {
  if (req.is("application/json")) {
    return true;
  }

  const accept = req.headers.accept || "";

  return accept.includes("application/json") && !accept.includes("text/html");
}

function isHtmlNavigation(req) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return false;
  }

  return (req.headers.accept || "").includes("text/html");
}

// Mounts the gate and the login routes. Call before any route that should be protected.
// Returns null when auth is disabled, so callers can skip the WebSocket wiring too.
function setupAuth(app, authConfig = loadAuthConfig()) {
  if (!authConfig.enabled) {
    console.warn(
      "[auth] Authentication is DISABLED - anyone who can reach this server can read and write the vaults.",
    );
    console.warn(
      "[auth] Set AUTH_USERNAME and AUTH_PASSWORD_HASH to turn it on (npm run auth:hash).",
    );

    return null;
  }

  const sessions = createSessions(authConfig);
  const limiter = createRateLimiter({
    maxAttempts: authConfig.maxAttempts,
    lockoutMs: authConfig.lockoutMs,
  });

  // Populate req.auth for anything downstream, and roll the cookie forward on active sessions.
  app.use((req, res, next) => {
    const token = sessions.readToken(req);
    const payload = token ? sessions.verify(token) : null;

    if (payload) {
      req.auth = { user: payload.u };

      if (sessions.needsRefresh(payload)) {
        sessions.setCookie(res, sessions.issue());
      }
    }

    next();
  });

  app.get(LOGIN_PATH, (req, res) => {
    res.set("Cache-Control", "no-store");

    if (req.auth) {
      return res.redirect(302, safeNext(req.query.next));
    }

    res
      .status(200)
      .type("html")
      .send(renderLogin({ next: safeNext(req.query.next) }));
  });

  app.post(
    LOGIN_PATH,
    express.urlencoded({ extended: false, limit: "8kb" }),
    async (req, res) => {
      res.set("Cache-Control", "no-store");

      const body = req.body || {};
      const next = safeNext(body.next);
      const username = typeof body.username === "string" ? body.username : "";
      const password = typeof body.password === "string" ? body.password : "";
      const ip = clientIp(req, authConfig.trustProxy);

      const gate = limiter.check(ip);

      if (!gate.allowed) {
        const message = `Too many failed attempts. Try again in ${Math.ceil(
          gate.retryAfterSeconds / 60,
        )} minute(s).`;

        console.warn(`[auth] Locked out login attempt from ${ip}`);
        res.set("Retry-After", String(gate.retryAfterSeconds));

        return wantsJson(req)
          ? res.status(429).json({ error: message })
          : res
              .status(429)
              .type("html")
              .send(renderLogin({ error: message, next, username }));
      }

      const userMatches = timingSafeEquals(username, authConfig.username);

      // Always run bcrypt, even for a wrong username, so both failures take the same time.
      const hashToCheck = userMatches ? authConfig.passwordHash : DUMMY_HASH;
      let passwordMatches = false;

      if (Buffer.byteLength(password, "utf-8") <= MAX_PASSWORD_BYTES) {
        try {
          passwordMatches = await bcrypt.compare(password, hashToCheck);
        } catch (e) {
          console.error("[auth] bcrypt comparison failed:", e.message);
        }
      }

      if (!userMatches || !passwordMatches) {
        const state = limiter.recordFailure(ip);

        console.warn(
          `[auth] Failed login for "${username.slice(0, 32)}" from ${ip}`,
        );

        const message = state.allowed
          ? "Incorrect username or password."
          : `Too many failed attempts. Try again in ${Math.ceil(
              state.retryAfterSeconds / 60,
            )} minute(s).`;

        const status = state.allowed ? 401 : 429;

        if (!state.allowed) {
          res.set("Retry-After", String(state.retryAfterSeconds));
        }

        return wantsJson(req)
          ? res.status(status).json({ error: message })
          : res
              .status(status)
              .type("html")
              .send(renderLogin({ error: message, next, username }));
      }

      limiter.recordSuccess(ip);
      sessions.setCookie(res, sessions.issue());
      console.log(`[auth] Signed in: ${authConfig.username} from ${ip}`);

      return wantsJson(req)
        ? res.json({ ok: true, user: authConfig.username, next })
        : res.redirect(302, next);
    },
  );

  const logout = (req, res) => {
    sessions.clearCookie(res);
    res.set("Cache-Control", "no-store");

    return wantsJson(req)
      ? res.json({ ok: true })
      : res.redirect(302, LOGIN_PATH);
  };

  app.post(LOGOUT_PATH, logout);
  app.get(LOGOUT_PATH, logout);

  app.get("/api/auth/session", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.json(
      req.auth
        ? { authenticated: true, user: req.auth.user }
        : { authenticated: false },
    );
  });

  // The gate itself. Anything past this point has a session.
  app.use((req, res, next) => {
    if (req.auth) {
      // Responses differ per session, so a shared cache must not reuse one across users.
      res.set("Vary", "Cookie");
      return next();
    }

    if (PUBLIC_PATHS.has(req.path)) {
      return next();
    }

    res.set("Cache-Control", "no-store");

    if (isHtmlNavigation(req)) {
      const target = safeNext(req.originalUrl);

      return res.redirect(
        302,
        target === "/"
          ? LOGIN_PATH
          : `${LOGIN_PATH}?next=${encodeURIComponent(target)}`,
      );
    }

    // Marks the response for the client-side helper, which turns it into a redirect.
    res.set("X-Ignis-Auth", "required");

    return res.status(401).json({ error: "Authentication required" });
  });

  console.log(
    `[auth] Authentication enabled for user "${authConfig.username}"`,
  );

  if (!authConfig.secretPersisted) {
    console.warn(
      "[auth] Session secret is in memory only; a restart signs everyone out.",
    );
  }

  return { sessions, limiter, config: authConfig };
}

// Refuses unauthenticated WebSocket upgrades. The HTTP gate never sees them, since an upgrade
// bypasses the Express middleware chain entirely.
function wireAuthWebSocket(server, auth) {
  if (!auth) {
    return;
  }

  const origEmit = server.emit.bind(server);

  server.emit = function (event, req, ...rest) {
    if (event === "upgrade") {
      const token = auth.sessions.readToken(req);

      if (!auth.sessions.verify(token)) {
        const socket = rest[0];

        console.warn("[auth] Rejected unauthenticated WebSocket upgrade");

        if (socket && socket.writable) {
          socket.write(
            "HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n",
          );
          socket.destroy();
        }

        return false;
      }
    }

    return origEmit(event, req, ...rest);
  };
}

module.exports = { setupAuth, wireAuthWebSocket, renderLogin, safeNext };
