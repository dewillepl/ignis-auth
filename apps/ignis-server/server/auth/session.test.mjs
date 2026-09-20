import { describe, it, expect } from "vitest";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const { createSessions, parseCookies } = require("./session.js");

function make(overrides = {}) {
  return createSessions({
    secret: "s".repeat(32),
    ttlMs: 60_000,
    cookieName: "ignis_session",
    cookieSecure: false,
    username: "kuba",
    passwordHash: "$2b$12$abcdefghijklmnopqrstuv",
    ...overrides,
  });
}

describe("session tokens", () => {
  it("verifies a token it issued", () => {
    const s = make();
    const payload = s.verify(s.issue());

    expect(payload.u).toBe("kuba");
  });

  it("rejects a tampered payload", () => {
    const s = make();
    const sig = s.issue().split(".")[1];
    const flipped = Buffer.from(
      JSON.stringify({ u: "root", fp: s.fingerprint, exp: Date.now() + 1000 }),
    ).toString("base64url");

    expect(s.verify(`${flipped}.${sig}`)).toBeNull();
  });

  it("rejects a token signed with another secret", () => {
    const token = make({ secret: "other-secret-value-32-chars-long" }).issue();

    expect(make().verify(token)).toBeNull();
  });

  it("rejects a token past its expiry", () => {
    const s = make();
    const token = s.issue();

    expect(s.verify(token, Date.now() + 61_000)).toBeNull();
  });

  it("rejects tokens issued for other credentials", () => {
    const token = make().issue();

    expect(make({ passwordHash: "$2b$12$changed" }).verify(token)).toBeNull();
    expect(make({ username: "someone-else" }).verify(token)).toBeNull();
  });

  it("rejects junk", () => {
    const s = make();

    expect(s.verify("")).toBeNull();
    expect(s.verify("no-dot")).toBeNull();
    expect(s.verify(null)).toBeNull();
    expect(s.verify("a".repeat(5000))).toBeNull();
  });

  it("asks for a refresh only past half the lifetime", () => {
    const s = make();
    const payload = s.verify(s.issue());

    expect(s.needsRefresh(payload, Date.now() + 20_000)).toBe(false);
    expect(s.needsRefresh(payload, Date.now() + 40_000)).toBe(true);
  });

  it("writes an HttpOnly cookie and a clearing one", () => {
    const s = make();
    const headers = [];
    const res = { append: (name, value) => headers.push(value) };

    s.setCookie(res, "token-value");
    s.clearCookie(res);

    expect(headers[0]).toContain("ignis_session=token-value");
    expect(headers[0]).toContain("HttpOnly");
    expect(headers[0]).toContain("SameSite=Lax");
    expect(headers[0]).not.toContain("Secure");
    expect(headers[1]).toContain("Max-Age=0");
  });

  it("marks the cookie Secure when configured", () => {
    const headers = [];

    make({ cookieSecure: true }).setCookie(
      { append: (name, value) => headers.push(value) },
      "t",
    );

    expect(headers[0]).toContain("Secure");
  });
});

describe("parseCookies", () => {
  it("splits a cookie header", () => {
    const cookies = parseCookies({
      headers: { cookie: "a=1; ignis_session=abc%3Ddef; b=2" },
    });

    expect(cookies.a).toBe("1");
    expect(cookies.ignis_session).toBe("abc=def");
  });

  it("survives a missing or malformed header", () => {
    expect(parseCookies({ headers: {} })).toEqual({});
    expect(parseCookies({ headers: { cookie: "novalue" } })).toEqual({});
  });
});
