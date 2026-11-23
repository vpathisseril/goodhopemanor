'use strict';
/** Services shared by every route: database access, sessions, permissions, rate limiting, files. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {sha256, randomToken, cookie, getCookie, clientIp} = require('./security');
const {json, headers} = require('./responses');

const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const SESSION_IDLE_MS = 30 * 60 * 1000;
const RESET_TTL_MS = 30 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS_PER_IP = 30;
const MAX_ATTEMPTS_PER_USER = 6;

/** A document is public when approved, active, and today (facility time) is within its dates. */
function publicEligible(row) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(new Date());
  const get = (type) => parts.find((p) => p.type === type).value;
  const today = `${get('year')}-${get('month')}-${get('day')}`;
  return (
    !!row.approved &&
    !row.archived &&
    !row.deleted &&
    (!row.effective_date || row.effective_date <= today) &&
    (!row.expiration_date || row.expiration_date >= today)
  );
}

const fullDoc = (row) => ({
  id: row.id,
  title: row.title,
  category: row.category,
  effectiveDate: row.effective_date,
  expirationDate: row.expiration_date,
  approved: !!row.approved,
  archived: !!row.archived,
  version: row.current_version,
  createdAt: row.created_at,
  updatedAt: row.updated_at,
  approvedAt: row.approved_at,
});

const publicUser = (u) => ({
  id: u.id,
  username: u.username,
  email: u.email,
  role: u.role,
  disabled: !!u.disabled,
  mustChangePassword: !!u.must_change,
  createdAt: u.created_at,
});

function createContext(config, store) {
  const {db, audit, tx} = store;
  const statements = {
    userById: db.prepare('SELECT * FROM users WHERE id=?'),
    userByName: db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE'),
    documentById: db.prepare('SELECT * FROM documents WHERE id=? AND deleted=0'),
    publicDocuments: db.prepare(
      'SELECT * FROM documents WHERE deleted=0 AND approved=1 AND archived=0 ORDER BY updated_at DESC',
    ),
    currentVersion: db.prepare('SELECT * FROM document_versions WHERE document_id=? AND version=?'),
    sessionByHash: db.prepare('SELECT * FROM sessions WHERE sid_hash=?'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE sid_hash=?'),
    touchSession: db.prepare('UPDATE sessions SET last_seen_ms=? WHERE sid_hash=?'),
  };
  const reply = (res, status, body, extra) => json(res, config, status, body, extra);

  // Verified against when a username does not exist, so the response time does not reveal it.
  const dummyUser = {
    password_salt: crypto.randomBytes(16).toString('hex'),
    password_hash: crypto.randomBytes(32).toString('hex'),
  };

  function getAuth(req) {
    const token = getCookie(req);
    if (!token || token.length > 200) return null;
    const sidHash = sha256(token);
    const session = statements.sessionByHash.get(sidHash);
    if (!session) return null;
    const now = Date.now();
    if (now > session.expires_ms || now - session.last_seen_ms > SESSION_IDLE_MS) {
      statements.deleteSession.run(sidHash);
      return null;
    }
    const user = statements.userById.get(session.user_id);
    if (!user || user.disabled) {
      statements.deleteSession.run(sidHash);
      return null;
    }
    statements.touchSession.run(now, sidHash);
    return {user, session, sidHash};
  }

  function checkCsrf(req, res, auth) {
    if (req.headers['x-csrf-token'] === auth.session.csrf) return true;
    reply(res, 403, {error: 'Security token missing or invalid'});
    return false;
  }

  /** Any signed-in session with a valid CSRF token, including one that must change its password. */
  function requireSession(req, res) {
    const auth = getAuth(req);
    if (!auth) {
      reply(res, 401, {error: 'Login required'});
      return null;
    }
    return checkCsrf(req, res, auth) ? auth : null;
  }

  /** A fully set-up account with one of `roles`; `requireWrite` also demands the CSRF token. */
  function authorize(req, res, roles = [], requireWrite = false) {
    const auth = getAuth(req);
    if (!auth) {
      reply(res, 401, {error: 'Login required'});
      return null;
    }
    if (auth.user.must_change) {
      reply(res, 403, {error: 'Password change required'});
      return null;
    }
    if (roles.length && !roles.includes(auth.user.role)) {
      reply(res, 403, {error: 'Insufficient permissions'});
      return null;
    }
    if (requireWrite && !checkCsrf(req, res, auth)) return null;
    return auth;
  }

  function startSession(res, user) {
    const sid = randomToken(32);
    const csrf = randomToken(24);
    const ms = Date.now();
    db.prepare(
      'INSERT INTO sessions (sid_hash,user_id,csrf,created_ms,last_seen_ms,expires_ms) VALUES (?,?,?,?,?,?)',
    ).run(sha256(sid), user.id, csrf, ms, ms, ms + SESSION_ABSOLUTE_MS);
    res.setHeader('Set-Cookie', cookie(sid, config.production));
    return {csrf, forcePasswordChange: !!user.must_change};
  }

  /** Replaces any earlier link with a single-use, 30-minute password-setup link. */
  function makeInvite(userId) {
    const token = randomToken(40);
    tx(() => {
      db.prepare('DELETE FROM password_tokens WHERE user_id=?').run(userId);
      db.prepare('INSERT INTO password_tokens (token_hash,user_id,expires_ms) VALUES (?,?,?)').run(
        sha256(token),
        userId,
        Date.now() + RESET_TTL_MS,
      );
    });
    const base = config.publicBaseUrl.replace(/\/$/, '');
    return `${base}/documents.html#reset=${encodeURIComponent(token)}`;
  }

  const attempts = new Map();
  const userKey = (ip, username) => `user:${ip}:${String(username).toLowerCase().slice(0, 70)}`;

  /** Records a login attempt and returns true when the address or account is over its limit. */
  function rateLimit(req, username) {
    const ip = clientIp(req, config.trustProxyHops);
    const now = Date.now();
    const keys = [
      [`ip:${ip}`, MAX_ATTEMPTS_PER_IP],
      [userKey(ip, username), MAX_ATTEMPTS_PER_USER],
    ];
    let blocked = false;
    for (const [key, max] of keys) {
      const recent = (attempts.get(key) || []).filter((t) => now - t < RATE_WINDOW_MS);
      if (recent.length >= max) blocked = true;
      recent.push(now);
      attempts.set(key, recent);
    }
    if (attempts.size > 2000) {
      for (const [key, times] of attempts) {
        if (times.at(-1) < now - RATE_WINDOW_MS) attempts.delete(key);
      }
    }
    return blocked;
  }

  function clearRate(req, username) {
    attempts.delete(userKey(clientIp(req, config.trustProxyHops), username));
  }

  /** Streams a stored document version after checking its size and SHA-256 against the database. */
  async function sendFile(req, res, version) {
    if (!version) return reply(res, 404, {error: 'Document version not found'});
    const file = path.join(config.storageDir, version.stored_name);
    let stat;
    try {
      stat = await fs.promises.stat(file);
    } catch {
      return reply(res, 404, {error: 'Document file unavailable'});
    }
    if (!stat.isFile()) return reply(res, 404, {error: 'Document file unavailable'});
    if (stat.size !== version.file_size) {
      return reply(res, 503, {error: 'Document integrity verification required'});
    }
    // Hash in chunks so a large file never sits whole in memory or blocks other requests.
    const hash = crypto.createHash('sha256');
    for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
    if (hash.digest('hex') !== version.file_sha256) {
      return reply(res, 503, {error: 'Document integrity verification required'});
    }
    // Always an attachment, so the browser never runs active Office/PDF content in our origin.
    const safe = version.original_name.replace(/[^a-z0-9 ._-]/gi, '_').replace(/"/g, '_');
    headers(res, config, {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${safe}"`,
      'Content-Length': stat.size,
      'X-Download-Options': 'noopen',
    });
    res.writeHead(200);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file)
      .on('error', () => res.destroy())
      .pipe(res);
  }

  return {
    config,
    db,
    audit,
    tx,
    statements,
    reply,
    dummyUser,
    getAuth,
    requireSession,
    authorize,
    startSession,
    makeInvite,
    rateLimit,
    clearRate,
    sendFile,
  };
}

module.exports = {createContext, publicEligible, fullDoc, publicUser};
