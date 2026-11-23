'use strict';
/** Login, logout, session status and password management. */
const {
  strongPassword,
  hashPassword,
  verifyPassword,
  cookie,
  sanitizeText,
  sha256,
} = require('../security');
const {ApiError, nowISOString, readJson} = require('../http');

module.exports = function authRoutes(ctx) {
  const {db, tx, audit, statements, reply} = ctx;

  async function session(req, res) {
    const auth = ctx.getAuth(req);
    if (!auth) return reply(res, 200, {authenticated: false});
    return reply(res, 200, {
      authenticated: true,
      username: auth.user.username,
      role: auth.user.role,
      forcePasswordChange: !!auth.user.must_change,
      csrfToken: auth.session.csrf,
    });
  }

  async function login(req, res) {
    const body = await readJson(req);
    const username = sanitizeText(body.username, 80);
    if (ctx.rateLimit(req, username)) {
      return reply(res, 429, {error: 'Too many attempts; try again later'});
    }
    const user = statements.userByName.get(username);
    const verified = await verifyPassword(body.password, user || ctx.dummyUser);
    if (!user || user.disabled || !verified) {
      return reply(res, 401, {error: 'Invalid username or password'});
    }
    ctx.clearRate(req, username);
    db.prepare('DELETE FROM sessions WHERE expires_ms<?').run(Date.now());
    const started = ctx.startSession(res, user);
    audit(user.id, 'auth.login', user.id);
    return reply(res, 200, {ok: true, ...started, role: user.role, username: user.username});
  }

  async function logout(req, res) {
    const auth = ctx.requireSession(req, res);
    if (!auth) return;
    db.prepare('DELETE FROM sessions WHERE sid_hash=?').run(auth.sidHash);
    audit(auth.user.id, 'auth.logout', auth.user.id);
    return reply(res, 200, {ok: true}, {'Set-Cookie': cookie('', ctx.config.production, 0)});
  }

  async function changePassword(req, res) {
    const auth = ctx.requireSession(req, res);
    if (!auth) return;
    const body = await readJson(req);
    if (!strongPassword(body.newPassword)) {
      return reply(res, 400, {
        error: 'Choose a unique password with 14–128 characters; avoid common passwords',
      });
    }
    // A forced first-login change has no known current password to check.
    if (!auth.user.must_change && !(await verifyPassword(body.oldPassword, auth.user))) {
      return reply(res, 403, {error: 'Current password is incorrect'});
    }
    if (await verifyPassword(body.newPassword, auth.user)) {
      return reply(res, 400, {error: 'Choose a different password'});
    }
    const hp = await hashPassword(body.newPassword);
    tx(() => {
      db.prepare(
        'UPDATE users SET password_hash=?,password_salt=?,must_change=0,updated_at=? WHERE id=?',
      ).run(hp.passwordHash, hp.passwordSalt, nowISOString(), auth.user.id);
      // Keep this session; sign out every other one.
      db.prepare('DELETE FROM sessions WHERE user_id=? AND sid_hash<>?').run(
        auth.user.id,
        auth.sidHash,
      );
      db.prepare('DELETE FROM password_tokens WHERE user_id=?').run(auth.user.id);
      audit(auth.user.id, 'auth.password_change', auth.user.id);
    });
    return reply(res, 200, {ok: true});
  }

  async function resetPassword(req, res) {
    const body = await readJson(req);
    if (
      !strongPassword(body.newPassword) ||
      typeof body.token !== 'string' ||
      body.token.length < 35
    ) {
      return reply(res, 400, {error: 'Invalid reset request or weak password'});
    }
    const record = db
      .prepare('SELECT * FROM password_tokens WHERE token_hash=? AND consumed_ms IS NULL')
      .get(sha256(body.token));
    if (!record || record.expires_ms < Date.now()) {
      return reply(res, 400, {error: 'Reset link is invalid or expired'});
    }
    const hp = await hashPassword(body.newPassword);
    tx(() => {
      // Consume the token inside the transaction so two concurrent requests cannot both use it.
      const changed = db
        .prepare(
          'UPDATE password_tokens SET consumed_ms=? WHERE token_hash=? AND consumed_ms IS NULL AND expires_ms>=?',
        )
        .run(Date.now(), record.token_hash, Date.now());
      if (changed.changes !== 1) throw new ApiError(400, 'Reset link has already been used');
      db.prepare(
        'UPDATE users SET password_hash=?,password_salt=?,must_change=0,updated_at=? WHERE id=? AND disabled=0',
      ).run(hp.passwordHash, hp.passwordSalt, nowISOString(), record.user_id);
      db.prepare('DELETE FROM sessions WHERE user_id=?').run(record.user_id);
      audit(record.user_id, 'auth.password_reset', record.user_id);
    });
    return reply(res, 200, {ok: true});
  }

  return [
    {methods: ['GET'], path: '/api/auth/session', handler: session},
    {methods: ['POST'], path: '/api/auth/login', handler: login},
    {methods: ['POST'], path: '/api/auth/logout', handler: logout},
    {methods: ['POST'], path: '/api/auth/change-password', handler: changePassword},
    {methods: ['POST'], path: '/api/auth/reset-password', handler: resetPassword},
  ];
};
