// Stateless session tokens.
//
// A token is `<payload>.<hmac>`, both base64url. Nothing is stored server-side: the HMAC over
// the payload is what makes it unforgeable, so sessions survive a restart as long as the
// secret does. The payload carries a fingerprint of the credentials, which means changing the
// username or password invalidates every token that was issued for the old ones.

const crypto = require("crypto");

const REFRESH_AFTER_FRACTION = 0.5;

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function credentialFingerprint(username, passwordHash, secret) {
  return crypto
    .createHash("sha256")
    .update(`${username}\0${passwordHash}\0${secret}`)
    .digest("base64url")
    .slice(0, 16);
}

// Splits a Cookie header. Values are percent-decoded to mirror how we write them.
function parseCookies(req) {
  const header = req.headers?.cookie;
  const out = Object.create(null);

  if (!header) {
    return out;
  }

  for (const part of header.split(";")) {
    const eq = part.indexOf("=");

    if (eq === -1) {
      continue;
    }

    const name = part.slice(0, eq).trim();

    if (!name || name in out) {
      continue;
    }

    try {
      out[name] = decodeURIComponent(part.slice(eq + 1).trim());
    } catch {
      out[name] = part.slice(eq + 1).trim();
    }
  }

  return out;
}

function createSessions(options) {
  const { secret, ttlMs, cookieName, cookieSecure, username, passwordHash } =
    options;

  const fingerprint = credentialFingerprint(username, passwordHash, secret);

  function signature(payloadPart) {
    return b64url(
      crypto.createHmac("sha256", secret).update(payloadPart).digest(),
    );
  }

  function issue(now = Date.now()) {
    const payload = {
      u: username,
      fp: fingerprint,
      iat: now,
      exp: now + ttlMs,
    };

    const part = b64url(JSON.stringify(payload));

    return `${part}.${signature(part)}`;
  }

  function verify(token, now = Date.now()) {
    if (typeof token !== "string" || token.length > 4096) {
      return null;
    }

    const dot = token.indexOf(".");

    if (dot === -1) {
      return null;
    }

    const part = token.slice(0, dot);
    const provided = Buffer.from(token.slice(dot + 1));
    const expected = Buffer.from(signature(part));

    if (
      provided.length !== expected.length ||
      !crypto.timingSafeEqual(provided, expected)
    ) {
      return null;
    }

    let payload;

    try {
      payload = JSON.parse(Buffer.from(part, "base64url").toString("utf-8"));
    } catch {
      return null;
    }

    if (!payload || typeof payload !== "object") {
      return null;
    }

    // A token signed before a credential change stays cryptographically valid, so the
    // fingerprint is what actually retires it.
    if (payload.fp !== fingerprint) {
      return null;
    }

    if (typeof payload.exp !== "number" || payload.exp <= now) {
      return null;
    }

    return payload;
  }

  // True once a token is past half its lifetime, so an active session keeps rolling forward
  // instead of expiring under the user mid-edit.
  function needsRefresh(payload, now = Date.now()) {
    if (!payload || typeof payload.iat !== "number") {
      return false;
    }

    return now - payload.iat > ttlMs * REFRESH_AFTER_FRACTION;
  }

  function cookieAttributes(maxAgeSeconds) {
    const parts = [
      `Path=/`,
      `HttpOnly`,
      `SameSite=Lax`,
      `Max-Age=${maxAgeSeconds}`,
    ];

    if (cookieSecure) {
      parts.push("Secure");
    }

    return parts.join("; ");
  }

  function setCookie(res, token) {
    res.append(
      "Set-Cookie",
      `${cookieName}=${encodeURIComponent(token)}; ${cookieAttributes(
        Math.floor(ttlMs / 1000),
      )}`,
    );
  }

  function clearCookie(res) {
    res.append("Set-Cookie", `${cookieName}=; ${cookieAttributes(0)}`);
  }

  function readToken(req) {
    return parseCookies(req)[cookieName] || null;
  }

  return {
    issue,
    verify,
    needsRefresh,
    setCookie,
    clearCookie,
    readToken,
    cookieName,
    fingerprint,
  };
}

module.exports = { createSessions, parseCookies, credentialFingerprint };
