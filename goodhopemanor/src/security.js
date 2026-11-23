'use strict';
const crypto = require('node:crypto');
const {promisify} = require('node:util');
const scrypt = promisify(crypto.scrypt);
const PASSWORD_PARAMS = {N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024};
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const randomToken = (length = 32) => crypto.randomBytes(length).toString('base64url');
function strongPassword(value) {
  return (
    typeof value === 'string' &&
    value.length >= 14 &&
    value.length <= 128 &&
    !/(password|qwerty|123456|goodhope|welcome|admin01|letmein)/i.test(value)
  );
}
async function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const key = await scrypt(password, Buffer.from(salt, 'hex'), 32, PASSWORD_PARAMS);
  return {passwordSalt: salt, passwordHash: Buffer.from(key).toString('hex')};
}
async function verifyPassword(password, user) {
  if (!user || typeof password !== 'string' || password.length > 256) return false;
  const key = await scrypt(password, Buffer.from(user.password_salt, 'hex'), 32, PASSWORD_PARAMS);
  const stored = Buffer.from(user.password_hash, 'hex');
  return stored.length === key.length && crypto.timingSafeEqual(stored, key);
}
function securityHeaders(production = false) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Content-Security-Policy':
      "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'" +
      (production ? '; upgrade-insecure-requests' : ''),
    ...(production ? {'Strict-Transport-Security': 'max-age=31536000'} : {}),
  };
}
function cookie(sid, production, maxAge = 1800) {
  return `ghm_sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${production ? '; Secure' : ''}`;
}
function getCookie(req) {
  const entry = (req.headers.cookie || '').split(';').find((x) => x.trim().startsWith('ghm_sid='));
  return entry ? entry.trim().slice(8) : '';
}
// Each trusted reverse proxy appends the address it received the request from, so with N trusted
// proxies the real client is the Nth X-Forwarded-For entry from the right. Entries further left are
// supplied by the client and can be forged, so they are never used.
function clientIp(req, trustProxyHops = 0) {
  const socketIp = req.socket.remoteAddress || 'unknown';
  if (!trustProxyHops) return socketIp;
  const chain = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
  if (!chain.length) return socketIp;
  return chain[Math.max(0, chain.length - trustProxyHops)];
}
function sanitizeText(input, max = 180) {
  return typeof input === 'string' ? input.trim().slice(0, max) : '';
}
function safeFilename(input) {
  return (
    sanitizeText(input, 160)
      // Control characters are matched on purpose: they must never reach a stored filename.
      // eslint-disable-next-line no-control-regex
      .replace(/[\\/\u0000-\u001f\u007f"\r\n]/g, '_')
      .replace(/[^a-zA-Z0-9._\- ]/g, '_')
      .replace(/^\.+/, 'file')
      .slice(0, 120) || 'document'
  );
}
function sameOrigin(req, config) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return true;
  const origin = req.headers.origin;
  if (origin) {
    try {
      if (new URL(origin).origin !== new URL(config.publicBaseUrl).origin) {
        // allow loopback dev host on random test ports
        if (!(!config.production && /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(origin)))
          return false;
      }
    } catch {
      return false;
    }
  }
  return true;
}
module.exports = {
  sha256,
  randomToken,
  strongPassword,
  hashPassword,
  verifyPassword,
  securityHeaders,
  cookie,
  getCookie,
  clientIp,
  sanitizeText,
  safeFilename,
  sameOrigin,
};
