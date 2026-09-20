// Auth configuration, read from the environment at startup.
//
// Credentials never touch disk: the username and a bcrypt hash of the password come from
// env vars (a .env file in the Docker setup). The hash format is the one PHP's
// password_hash($pw, PASSWORD_BCRYPT) produces, so hashes can be moved between apps.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const serverConfig = require("../config");

const COOKIE_NAME = "ignis_session";
const SECRET_FILE = ".session-secret";
const DEFAULT_TTL_HOURS = 168;
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_LOCKOUT_MINUTES = 15;

// $2a$ / $2b$ / $2y$, two-digit cost, then 22 chars of salt + 31 of digest in bcrypt's base64.
const BCRYPT_RE = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

function isBcryptHash(value) {
  return typeof value === "string" && BCRYPT_RE.test(value);
}

// docker-compose treats a single "$" in .env as variable interpolation, so the documented way
// to store a bcrypt hash there is to double every "$". Compose collapses them back on its own
// when the value is interpolated into the compose file, but `env_file:` and `docker run
// --env-file` hand the value over untouched - so accept the doubled form too.
function normalizeHash(raw) {
  if (typeof raw !== "string") {
    return null;
  }

  const trimmed = raw.trim();

  if (isBcryptHash(trimmed)) {
    return trimmed;
  }

  const undoubled = trimmed.replace(/\$\$/g, "$");

  return isBcryptHash(undoubled) ? undoubled : null;
}

function parseNumber(raw, fallback) {
  const n = Number(raw);

  return Number.isFinite(n) && n > 0 ? n : fallback;
}

// A stable secret keeps sessions valid across restarts. An operator-supplied one wins;
// otherwise we persist a random secret next to the other server state.
function resolveSecret(env, dataRoot) {
  const fromEnv = env.AUTH_SESSION_SECRET;

  if (typeof fromEnv === "string" && fromEnv.length >= 16) {
    return { secret: fromEnv, persisted: true };
  }

  if (fromEnv) {
    console.warn(
      "[auth] AUTH_SESSION_SECRET is shorter than 16 characters; ignoring it",
    );
  }

  const file = path.join(dataRoot, SECRET_FILE);

  try {
    const existing = fs.readFileSync(file, "utf-8").trim();

    if (existing.length >= 16) {
      return { secret: existing, persisted: true };
    }
  } catch {
    // No secret stored yet; fall through and write one.
  }

  const generated = crypto.randomBytes(32).toString("hex");

  try {
    fs.writeFileSync(file, generated + "\n", { mode: 0o600 });
    return { secret: generated, persisted: true };
  } catch (e) {
    console.warn(
      `[auth] Could not persist the session secret to ${file}; sessions will not survive a restart:`,
      e.message,
    );

    return { secret: generated, persisted: false };
  }
}

// Decides whether auth runs at all.
// Unset AUTH_ENABLED follows the credentials: present means on. AUTH_ENABLED=true without
// credentials is a misconfiguration we refuse to start with, rather than silently serving
// the vault to anyone.
function resolveEnabled(env, hasCredentials) {
  const explicit = env.AUTH_ENABLED;

  if (explicit === "false") {
    return false;
  }

  if (explicit === "true" && !hasCredentials) {
    throw new Error(
      "AUTH_ENABLED=true but AUTH_USERNAME / AUTH_PASSWORD_HASH are missing or invalid. " +
        "Generate a hash with `npm run auth:hash` and set both, or set AUTH_ENABLED=false.",
    );
  }

  return hasCredentials;
}

function loadAuthConfig(env = process.env, dataRoot = serverConfig.dataRoot) {
  const username =
    typeof env.AUTH_USERNAME === "string" ? env.AUTH_USERNAME.trim() : "";
  const rawHash = env.AUTH_PASSWORD_HASH;
  const passwordHash = normalizeHash(rawHash);

  if (rawHash && !passwordHash) {
    console.error(
      "[auth] AUTH_PASSWORD_HASH is not a valid bcrypt hash (expected $2a$/$2b$/$2y$ + cost + 53 chars)",
    );
  }

  const hasCredentials = Boolean(username && passwordHash);
  const enabled = resolveEnabled(env, hasCredentials);

  if (!enabled) {
    return { enabled: false };
  }

  const { secret, persisted } = resolveSecret(env, dataRoot);

  return {
    enabled: true,
    username,
    passwordHash,
    secret,
    secretPersisted: persisted,
    cookieName: env.AUTH_COOKIE_NAME || COOKIE_NAME,
    // Off by default: plain http on localhost is the common case, and a Secure cookie there
    // is never sent back, which locks the user out. Turn it on behind an HTTPS proxy.
    cookieSecure: env.AUTH_COOKIE_SECURE === "true",
    ttlMs:
      parseNumber(env.AUTH_SESSION_TTL_HOURS, DEFAULT_TTL_HOURS) *
      60 *
      60 *
      1000,
    maxAttempts: parseNumber(env.AUTH_MAX_ATTEMPTS, DEFAULT_MAX_ATTEMPTS),
    lockoutMs:
      parseNumber(env.AUTH_LOCKOUT_MINUTES, DEFAULT_LOCKOUT_MINUTES) *
      60 *
      1000,
    // Client IPs come from X-Forwarded-For only when a proxy in front is trusted to set it;
    // otherwise a client could forge it and dodge the login rate limit.
    trustProxy: env.AUTH_TRUST_PROXY === "true" || env.TRUST_PROXY === "true",
  };
}

module.exports = {
  loadAuthConfig,
  normalizeHash,
  isBcryptHash,
  resolveEnabled,
  COOKIE_NAME,
};
