import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { createRequire } from "module";
import fs from "fs";
import os from "os";
import path from "path";

const require = createRequire(import.meta.url);

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "auth-gate-test-"));
process.env.VAULT_ROOT = path.join(ROOT, "vaults");
process.env.DATA_ROOT = path.join(ROOT, "data");

const express = require("express");
const bcrypt = require("bcryptjs");
const { setupAuth } = require("./index.js");

const PASSWORD = "correct horse";
const AUTH_CONFIG = {
  enabled: true,
  username: "kuba",
  // Cheapest cost bcrypt allows; this suite logs in a lot.
  passwordHash: bcrypt.hashSync(PASSWORD, 4),
  secret: "test-secret-that-is-long-enough",
  secretPersisted: true,
  cookieName: "ignis_session",
  cookieSecure: false,
  ttlMs: 60_000,
  maxAttempts: 3,
  lockoutMs: 60_000,
  trustProxy: false,
};

let server;
let base;
let auth;

const HTML = { Accept: "text/html" };

function login(body, headers = {}) {
  return fetch(`${base}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(body).toString(),
    redirect: "manual",
  });
}

function sessionCookie(response) {
  const raw = response.headers.getSetCookie?.() || [];
  const cookie = raw.find((c) => c.startsWith("ignis_session="));

  return cookie ? cookie.split(";")[0] : null;
}

beforeAll(async () => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "log").mockImplementation(() => {});

  const app = express();
  app.use(express.json());
  auth = setupAuth(app, AUTH_CONFIG);

  app.get("/", (req, res) => res.type("html").send("<html>vault</html>"));
  app.get("/api/ping", (req, res) =>
    res.json({ ok: true, user: req.auth.user }),
  );

  await new Promise((resolve) => {
    server = app.listen(0, resolve);
  });

  base = `http://127.0.0.1:${server.address().port}`;
});

afterAll(() => {
  server?.close();
  auth?.limiter.stop();
  vi.restoreAllMocks();
  fs.rmSync(ROOT, { recursive: true, force: true });
});

describe("unauthenticated requests", () => {
  it("redirects a page load to the login form", async () => {
    const res = await fetch(base + "/", { headers: HTML, redirect: "manual" });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/login");
  });

  it("keeps the requested URL in ?next=", async () => {
    const res = await fetch(`${base}/?vault=Notes`, {
      headers: HTML,
      redirect: "manual",
    });

    expect(res.headers.get("location")).toBe("/login?next=%2F%3Fvault%3DNotes");
  });

  it("answers API calls with 401 instead of a redirect", async () => {
    const res = await fetch(base + "/api/ping");

    expect(res.status).toBe(401);
    expect(res.headers.get("x-ignis-auth")).toBe("required");
  });

  it("serves the login page", async () => {
    const res = await fetch(base + "/login");
    const body = await res.text();

    expect(res.status).toBe(200);
    expect(body).toContain("Sign in");
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("ignores a forged session cookie", async () => {
    const res = await fetch(base + "/api/ping", {
      headers: { Cookie: "ignis_session=made.up" },
    });

    expect(res.status).toBe(401);
  });
});

describe("signing in", () => {
  it("rejects a wrong password without issuing a cookie", async () => {
    const res = await login({ username: "kuba", password: "nope" });

    expect(res.status).toBe(401);
    expect(sessionCookie(res)).toBeNull();
    expect(await res.text()).toContain("Incorrect username or password");
  });

  it("rejects a wrong username", async () => {
    const res = await login({ username: "someone", password: PASSWORD });

    expect(res.status).toBe(401);
    expect(sessionCookie(res)).toBeNull();
  });

  it("sets a session cookie and lets the request through", async () => {
    const res = await login({ username: "kuba", password: PASSWORD });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");

    const cookie = sessionCookie(res);
    expect(cookie).toBeTruthy();

    const ping = await fetch(base + "/api/ping", {
      headers: { Cookie: cookie },
    });

    expect(ping.status).toBe(200);
    expect(await ping.json()).toEqual({ ok: true, user: "kuba" });
  });

  it("answers JSON logins with JSON", async () => {
    const res = await fetch(base + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "kuba", password: PASSWORD }),
      redirect: "manual",
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, user: "kuba" });
  });

  it("follows ?next= back to the requested page", async () => {
    const res = await login({
      username: "kuba",
      password: PASSWORD,
      next: "/?vault=Notes",
    });

    expect(res.headers.get("location")).toBe("/?vault=Notes");
  });

  // ?next= is attacker-controllable, so it must never leave this origin.
  it("refuses to bounce to another origin", async () => {
    const res = await login({
      username: "kuba",
      password: PASSWORD,
      next: "https://evil.example/",
    });

    expect(res.headers.get("location")).toBe("/");

    const protocolRelative = await login({
      username: "kuba",
      password: PASSWORD,
      next: "//evil.example/",
    });

    expect(protocolRelative.headers.get("location")).toBe("/");
  });

  it("sends an already-signed-in visitor away from the login page", async () => {
    const cookie = sessionCookie(
      await login({ username: "kuba", password: PASSWORD }),
    );

    const res = await fetch(base + "/login", {
      headers: { Cookie: cookie },
      redirect: "manual",
    });

    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/");
  });
});

describe("signing out", () => {
  it("clears the cookie and closes access again", async () => {
    const cookie = sessionCookie(
      await login({ username: "kuba", password: PASSWORD }),
    );

    const res = await fetch(base + "/logout", {
      method: "POST",
      headers: { Cookie: cookie, Accept: "application/json" },
      redirect: "manual",
    });

    expect(res.status).toBe(200);
    expect(sessionCookie(res)).toBe("ignis_session=");
  });
});

describe("session endpoint", () => {
  it("reports the signed-in user, and nothing without a session", async () => {
    const anon = await fetch(base + "/api/auth/session");

    expect(await anon.json()).toEqual({ authenticated: false });

    const cookie = sessionCookie(
      await login({ username: "kuba", password: PASSWORD }),
    );
    const signedIn = await fetch(base + "/api/auth/session", {
      headers: { Cookie: cookie },
    });

    expect(await signedIn.json()).toEqual({
      authenticated: true,
      user: "kuba",
    });
  });
});

describe("brute-force throttling", () => {
  it("locks the client out after repeated failures", async () => {
    // Runs last: the limiter keys on IP, and every test here shares 127.0.0.1.
    let res;

    for (let i = 0; i < AUTH_CONFIG.maxAttempts; i++) {
      res = await login({ username: "kuba", password: "wrong" });
    }

    expect(res.status).toBe(429);
    expect(Number(res.headers.get("retry-after"))).toBeGreaterThan(0);

    // Even the right password is refused while the lockout stands.
    const correct = await login({ username: "kuba", password: PASSWORD });

    expect(correct.status).toBe(429);
    expect(sessionCookie(correct)).toBeNull();
  });
});
