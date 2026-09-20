import { describe, it, expect, afterEach } from "vitest";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const { createRateLimiter, clientIp } = require("./rate-limit.js");

let limiter;

afterEach(() => limiter?.stop());

describe("login rate limiting", () => {
  it("locks out after the configured number of failures", () => {
    limiter = createRateLimiter({ maxAttempts: 3, lockoutMs: 60_000 });

    expect(limiter.recordFailure("1.2.3.4").allowed).toBe(true);
    expect(limiter.recordFailure("1.2.3.4").allowed).toBe(true);
    expect(limiter.recordFailure("1.2.3.4").allowed).toBe(false);
    expect(limiter.check("1.2.3.4").retryAfterSeconds).toBe(60);
  });

  it("keeps the lockout per IP", () => {
    limiter = createRateLimiter({ maxAttempts: 2 });

    limiter.recordFailure("1.2.3.4");
    limiter.recordFailure("1.2.3.4");

    expect(limiter.check("1.2.3.4").allowed).toBe(false);
    expect(limiter.check("5.6.7.8").allowed).toBe(true);
  });

  it("lets the client back in once the lockout passes", () => {
    limiter = createRateLimiter({ maxAttempts: 1, lockoutMs: 1000 });

    limiter.recordFailure("1.2.3.4");

    expect(limiter.check("1.2.3.4", Date.now() + 1500).allowed).toBe(true);
  });

  it("forgets failures after a success", () => {
    limiter = createRateLimiter({ maxAttempts: 2 });

    limiter.recordFailure("1.2.3.4");
    limiter.recordSuccess("1.2.3.4");
    limiter.recordFailure("1.2.3.4");

    expect(limiter.check("1.2.3.4").allowed).toBe(true);
  });

  it("starts a fresh window after a quiet period", () => {
    limiter = createRateLimiter({ maxAttempts: 2, windowMs: 1000 });
    const t0 = Date.now();

    limiter.recordFailure("1.2.3.4", t0);

    expect(limiter.recordFailure("1.2.3.4", t0 + 5000).allowed).toBe(true);
  });
});

describe("clientIp", () => {
  const req = {
    headers: { "x-forwarded-for": "9.9.9.9, 10.0.0.1" },
    socket: { remoteAddress: "127.0.0.1" },
  };

  it("ignores X-Forwarded-For unless a proxy is trusted", () => {
    expect(clientIp(req, false)).toBe("127.0.0.1");
  });

  it("takes the first forwarded hop when it is trusted", () => {
    expect(clientIp(req, true)).toBe("9.9.9.9");
  });
});
