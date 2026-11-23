#!/usr/bin/env node
'use strict';
/** Offline owner-initiated credential recovery. Run on the server with the web process stopped. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {DatabaseSync} = require('node:sqlite');
const {hashPassword, strongPassword} = require('../src/security');
async function run() {
  const directory = process.env.GOODHOPE_DATA_DIR;
  const password = process.env.RECOVERY_PASSWORD;
  const username = process.argv[2] || 'admin';
  if (!directory || !path.isAbsolute(directory))
    throw new Error('Set GOODHOPE_DATA_DIR to the private persistent storage directory');
  if (!strongPassword(password))
    throw new Error('RECOVERY_PASSWORD must be a new unique 14+ character private password');
  if (!/^[a-z][a-z0-9._-]{2,39}$/i.test(username)) throw new Error('Invalid username');
  const database = path.join(directory, 'goodhope.sqlite');
  if (!fs.existsSync(database)) throw new Error('Database missing');
  const db = new DatabaseSync(database);
  try {
    const user = db.prepare('SELECT id FROM users WHERE username=? COLLATE NOCASE').get(username);
    if (!user) throw new Error('Account does not exist');
    const hp = await hashPassword(password);
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare(
        'UPDATE users SET password_hash=?,password_salt=?,must_change=1,disabled=0,updated_at=? WHERE id=?',
      ).run(hp.passwordHash, hp.passwordSalt, new Date().toISOString(), user.id);
      db.prepare('DELETE FROM sessions WHERE user_id=?').run(user.id);
      db.prepare('DELETE FROM password_tokens WHERE user_id=?').run(user.id);
      db.prepare(
        'INSERT INTO audit_log (id,created_at,actor_id,event,target_id,details) VALUES (?,?,?,?,?,?)',
      ).run(
        crypto.randomUUID(),
        new Date().toISOString(),
        null,
        'auth.offline_recovery',
        user.id,
        '{}',
      );
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
    console.log(
      'Recovery password updated, account enabled, existing sessions revoked; change this password immediately at first login.',
    );
  } finally {
    db.close();
  }
}
run().catch((e) => {
  console.error('Recovery aborted:', e.message);
  process.exitCode = 1;
});
