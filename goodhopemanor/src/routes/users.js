'use strict';
/** Staff account management (administrators only). */
const crypto = require('node:crypto');
const {ROLES} = require('../database');
const {randomToken, hashPassword, sanitizeText} = require('../security');
const {sendInvitation} = require('../email');
const {nowISOString, readJson} = require('../http');
const {publicUser} = require('../context');

const ID = '([0-9a-f-]{36})';
const USERNAME = /^[a-z][a-z0-9._-]{2,39}$/i;
const EMAIL = /^\S+@\S+\.\S+$/;

module.exports = function userRoutes(ctx) {
  const {config, db, tx, audit, statements, reply} = ctx;

  /** Emails the link when a provider is configured; otherwise the admin must share it securely. */
  async function deliverInvite(actorId, user, invitationUrl) {
    try {
      return await sendInvitation(config, user.email, user.username, invitationUrl);
    } catch {
      audit(actorId, 'user.email_failed', user.id);
      return {sent: false};
    }
  }

  async function list(req, res) {
    if (!ctx.authorize(req, res, ['admin'])) return;
    const users = db.prepare('SELECT * FROM users ORDER BY created_at').all().map(publicUser);
    return reply(res, 200, {users});
  }

  async function create(req, res) {
    const auth = ctx.authorize(req, res, ['admin'], true);
    if (!auth) return;
    const body = await readJson(req);
    const username = sanitizeText(body.username, 80);
    const email = sanitizeText(body.email, 254).toLowerCase();
    const {role} = body;
    if (!USERNAME.test(username) || !EMAIL.test(email) || !ROLES.includes(role)) {
      return reply(res, 400, {error: 'Valid username, email and role are required'});
    }
    if (statements.userByName.get(username)) {
      return reply(res, 409, {error: 'Username already exists'});
    }
    if (db.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE').get(email)) {
      return reply(res, 409, {error: 'Email already exists'});
    }
    // The account gets an unknown random password; the user sets their own through the invite link.
    const hp = await hashPassword(randomToken(40));
    const id = crypto.randomUUID();
    const now = nowISOString();
    tx(() => {
      db.prepare(
        'INSERT INTO users (id,username,email,role,disabled,must_change,password_salt,password_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
      ).run(id, username, email, role, 0, 1, hp.passwordSalt, hp.passwordHash, now, now);
      audit(auth.user.id, 'user.create', id, {role});
    });
    const invitationUrl = ctx.makeInvite(id);
    const delivery = await deliverInvite(auth.user.id, {id, email, username}, invitationUrl);
    return reply(res, 201, {
      ok: true,
      user: {id, username, email, role},
      invitationUrl: delivery.sent ? null : invitationUrl,
      emailSent: delivery.sent,
      emailMessage: delivery.sent
        ? 'Invitation sent'
        : 'Email not configured or unavailable. Share the one-time invitation link securely.',
    });
  }

  async function resetInvite(req, res, [id]) {
    const auth = ctx.authorize(req, res, ['admin'], true);
    if (!auth) return;
    const user = statements.userById.get(id);
    if (!user || user.disabled) return reply(res, 404, {error: 'Active user not found'});
    const invitationUrl = ctx.makeInvite(user.id);
    audit(auth.user.id, 'user.reset_invite', user.id);
    const delivery = await deliverInvite(auth.user.id, user, invitationUrl);
    return reply(res, 200, {
      ok: true,
      invitationUrl: delivery.sent ? null : invitationUrl,
      emailSent: delivery.sent,
    });
  }

  async function update(req, res, [id]) {
    const auth = ctx.authorize(req, res, ['admin'], true);
    if (!auth) return;
    const target = statements.userById.get(id);
    if (!target) return reply(res, 404, {error: 'User not found'});
    const body = await readJson(req);
    const role = body.role === undefined ? target.role : body.role;
    const disabled = body.disabled === undefined ? target.disabled : body.disabled ? 1 : 0;
    if (!ROLES.includes(role) || typeof disabled !== 'number') {
      return reply(res, 400, {error: 'Invalid role or status'});
    }
    const losesAdmin = disabled || role !== 'admin';
    const activeAdmins = db
      .prepare("SELECT count(*) AS n FROM users WHERE role='admin' AND disabled=0")
      .get().n;
    if (target.role === 'admin' && !target.disabled && losesAdmin && activeAdmins <= 1) {
      return reply(res, 409, {error: 'Cannot remove the last active administrator'});
    }
    if (target.id === auth.user.id && losesAdmin) {
      return reply(res, 409, {error: 'You cannot remove your own administrative access'});
    }
    tx(() => {
      db.prepare('UPDATE users SET role=?,disabled=?,updated_at=? WHERE id=?').run(
        role,
        disabled,
        nowISOString(),
        target.id,
      );
      // A disabled account or changed role must not keep using permissions granted at login.
      if (disabled || role !== target.role) {
        db.prepare('DELETE FROM sessions WHERE user_id=?').run(target.id);
      }
      audit(auth.user.id, 'user.update', target.id, {role, disabled: !!disabled});
    });
    return reply(res, 200, {ok: true});
  }

  return [
    {methods: ['GET'], path: '/api/admin/users', handler: list},
    {methods: ['POST'], path: '/api/admin/users', handler: create},
    {
      methods: ['POST'],
      path: new RegExp(`^/api/admin/users/${ID}/reset$`, 'i'),
      handler: resetInvite,
    },
    {methods: ['PATCH'], path: new RegExp(`^/api/admin/users/${ID}$`, 'i'), handler: update},
  ];
};
