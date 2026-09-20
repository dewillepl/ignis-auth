import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { createRequire } from "module";
import fs from "fs";
import os from "os";
import path from "path";

const require = createRequire(import.meta.url);

// config.js creates VAULT_ROOT/DATA_ROOT on require, so point them at scratch dirs first.
const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "auth-config-test-"));
process.env.VAULT_ROOT = path.join(ROOT, "vaults");
process.env.DATA_ROOT = path.join(ROOT, "data");

const {
  loadAuthConfig,
  normalizeHash,
  isBcryptHash,
  resolveEnabled,
} = require("./config.js");

const HASH = "$2y$12$LbEQghWj8ZsSO7Ig3BYm3OdI62i1QnR23XdZrat1DpcQAhvSKEXze";
const DATA_ROOT = process.env.DATA_ROOT;

beforeAll(() => {
  fs.mkdirSync(DATA_ROOT, { recursive: true });
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterAll(() => {
  vi.restoreAllMocks();
  fs.rmSync(ROOT, { recursive: true, force: true });
});

describe("normalizeHash", () => {
  it("accepts a plain bcrypt hash", () => {
    expect(normalizeHash(HASH)).toBe(HASH);
    expect(normalizeHash(HASH.replace("$2y$", "$2b$"))).toBeTruthy();
    expect(normalizeHash(`  ${HASH}  `)).toBe(HASH);
  });

  // docker-compose eats a single "$" in .env, so the documented form doubles them.
  it("undoubles a compose-escaped hash", () => {
    expect(normalizeHash(HASH.replace(/\$/g, "$$$$"))).toBe(HASH);
  });

  it("rejects anything that is not a bcrypt hash", () => {
    expect(normalizeHash("hunter2")).toBeNull();
    expect(normalizeHash("$2y$12$tooshort")).toBeNull();
    expect(normalizeHash(undefined)).toBeNull();
    expect(isBcryptHash("$1$md5$whatever")).toBe(false);
  });
});

describe("resolveEnabled", () => {
  it("follows the credentials when AUTH_ENABLED is unset", () => {
    expect(resolveEnabled({}, true)).toBe(true);
    expect(resolveEnabled({}, false)).toBe(false);
  });

  it("stays off when explicitly disabled", () => {
    expect(resolveEnabled({ AUTH_ENABLED: "false" }, true)).toBe(false);
  });

  // Failing closed beats starting an unprotected server the operator believes is protected.
  it("refuses to start when it is required but not configured", () => {
    expect(() => resolveEnabled({ AUTH_ENABLED: "true" }, false)).toThrow();
  });
});

describe("loadAuthConfig", () => {
  it("is disabled without credentials", () => {
    expect(loadAuthConfig({}, DATA_ROOT)).toEqual({ enabled: false });
  });

  it("is disabled when the hash is unusable", () => {
    const cfg = loadAuthConfig(
      { AUTH_USERNAME: "kuba", AUTH_PASSWORD_HASH: "not-a-hash" },
      DATA_ROOT,
    );

    expect(cfg.enabled).toBe(false);
  });

  it("reads credentials and applies the defaults", () => {
    const cfg = loadAuthConfig(
      { AUTH_USERNAME: " kuba ", AUTH_PASSWORD_HASH: HASH },
      DATA_ROOT,
    );

    expect(cfg.enabled).toBe(true);
    expect(cfg.username).toBe("kuba");
    expect(cfg.passwordHash).toBe(HASH);
    expect(cfg.cookieSecure).toBe(false);
    expect(cfg.ttlMs).toBe(168 * 60 * 60 * 1000);
    expect(cfg.maxAttempts).toBe(5);
    expect(cfg.trustProxy).toBe(false);
  });

  it("honours the tunables", () => {
    const cfg = loadAuthConfig(
      {
        AUTH_USERNAME: "kuba",
        AUTH_PASSWORD_HASH: HASH,
        AUTH_SESSION_TTL_HOURS: "2",
        AUTH_MAX_ATTEMPTS: "9",
        AUTH_LOCKOUT_MINUTES: "1",
        AUTH_COOKIE_SECURE: "true",
        AUTH_TRUST_PROXY: "true",
        AUTH_SESSION_SECRET: "x".repeat(32),
      },
      DATA_ROOT,
    );

    expect(cfg.ttlMs).toBe(2 * 60 * 60 * 1000);
    expect(cfg.maxAttempts).toBe(9);
    expect(cfg.lockoutMs).toBe(60_000);
    expect(cfg.cookieSecure).toBe(true);
    expect(cfg.trustProxy).toBe(true);
    expect(cfg.secret).toBe("x".repeat(32));
  });

  // Sessions must survive a restart, so the generated secret is written next to the server state.
  it("persists a generated session secret and reuses it", () => {
    const env = { AUTH_USERNAME: "kuba", AUTH_PASSWORD_HASH: HASH };
    const first = loadAuthConfig(env, DATA_ROOT);
    const second = loadAuthConfig(env, DATA_ROOT);

    expect(first.secretPersisted).toBe(true);
    expect(first.secret).toHaveLength(64);
    expect(second.secret).toBe(first.secret);
    expect(fs.existsSync(path.join(DATA_ROOT, ".session-secret"))).toBe(true);
  });
});
