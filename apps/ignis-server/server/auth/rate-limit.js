// Failed-login throttling, per client IP.
//
// Bcrypt is slow by design, but not slow enough to make an unbounded guessing loop pointless.
// After `maxAttempts` failures inside the window, that IP is locked out for `lockoutMs`.

const MAX_TRACKED_IPS = 10000;
const SWEEP_INTERVAL_MS = 60 * 1000;

function createRateLimiter(options = {}) {
  const {
    maxAttempts = 5,
    windowMs = 15 * 60 * 1000,
    lockoutMs = 15 * 60 * 1000,
  } = options;

  // ip -> { fails, firstFailAt, lockedUntil }
  const entries = new Map();

  function expired(entry, now) {
    if (entry.lockedUntil > now) {
      return false;
    }

    return now - entry.firstFailAt > windowMs && entry.lockedUntil <= now;
  }

  function sweep(now = Date.now()) {
    for (const [ip, entry] of entries) {
      if (expired(entry, now)) {
        entries.delete(ip);
      }
    }
  }

  // Returns { allowed, retryAfterSeconds }.
  function check(ip, now = Date.now()) {
    const entry = entries.get(ip);

    if (!entry || entry.lockedUntil <= now) {
      return { allowed: true, retryAfterSeconds: 0 };
    }

    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((entry.lockedUntil - now) / 1000),
    };
  }

  function recordFailure(ip, now = Date.now()) {
    let entry = entries.get(ip);

    // The window is per burst: a first failure after a quiet window starts counting over.
    if (!entry || (now - entry.firstFailAt > windowMs && entry.fails > 0)) {
      entry = { fails: 0, firstFailAt: now, lockedUntil: 0 };

      // Bound the map so a spray of spoofed source IPs cannot grow it without limit.
      if (entries.size >= MAX_TRACKED_IPS) {
        sweep(now);

        if (entries.size >= MAX_TRACKED_IPS) {
          entries.delete(entries.keys().next().value);
        }
      }

      entries.set(ip, entry);
    }

    entry.fails += 1;

    if (entry.fails >= maxAttempts) {
      entry.lockedUntil = now + lockoutMs;
    }

    return check(ip, now);
  }

  function recordSuccess(ip) {
    entries.delete(ip);
  }

  const timer = setInterval(() => sweep(), SWEEP_INTERVAL_MS);
  timer.unref?.();

  return {
    check,
    recordFailure,
    recordSuccess,
    stop: () => clearInterval(timer),
    _entries: entries,
  };
}

// The socket address is the only value a client cannot set. X-Forwarded-For is used only when
// the operator says a proxy in front is trusted to write it.
function clientIp(req, trustProxy) {
  if (trustProxy) {
    const forwarded = req.headers["x-forwarded-for"];

    if (typeof forwarded === "string" && forwarded.length > 0) {
      const first = forwarded.split(",")[0].trim();

      if (first) {
        return first;
      }
    }
  }

  return req.socket?.remoteAddress || req.ip || "unknown";
}

module.exports = { createRateLimiter, clientIp };
