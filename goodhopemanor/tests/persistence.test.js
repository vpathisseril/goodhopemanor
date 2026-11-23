'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {spawnSync} = require('node:child_process');
const {initialize} = require('../src/app');
const SECRET = 'Private-Long-Bootstrap-Passphrase-2026';
test('user state, sessions, backups, integrity and restore survive restarts', async (t) => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'ghm-persist-'));
  const backupRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ghm-backup-'));
  const backupPath = path.join(backupRoot, 'snapshot');
  const target = path.join(backupRoot, 'restored');
  t.after(() => {
    fs.rmSync(data, {recursive: true, force: true});
    fs.rmSync(backupRoot, {recursive: true, force: true});
  });
  const cfg = {
    ...process.env,
    NODE_ENV: 'test',
    INITIAL_ADMIN_PASSWORD: SECRET,
    GOODHOPE_DATA_DIR: data,
    PORT: '3000',
  };
  let app = await initialize(cfg);
  let base;
  await new Promise((ok) => app.server.listen(0, '127.0.0.1', ok));
  base = 'http://127.0.0.1:' + app.server.address().port;
  const res = await fetch(base + '/api/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: 'admin', password: SECRET}),
  });
  assert.equal(res.status, 200);
  const cookie = res.headers.get('set-cookie').split(';')[0];
  const dataBody = await res.json();
  const change = await fetch(base + '/api/auth/change-password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', Cookie: cookie, 'x-csrf-token': dataBody.csrf},
    body: JSON.stringify({newPassword: SECRET + '-Changed'}),
  });
  assert.equal(change.status, 200);
  await new Promise((resolve) => app.server.close(resolve));
  app.db.close();
  app = await initialize({...cfg, INITIAL_ADMIN_PASSWORD: ''});
  await new Promise((ok) => app.server.listen(0, '127.0.0.1', ok));
  base = 'http://127.0.0.1:' + app.server.address().port;
  const renewed = await fetch(base + '/api/auth/session', {headers: {Cookie: cookie}});
  assert.equal((await renewed.json()).authenticated, true);
  await new Promise((resolve) => app.server.close(resolve));
  app.db.close();
  const cmd = ['scripts/backup.js', backupPath];
  const result = spawnSync(process.execPath, cmd, {
    cwd: path.resolve(__dirname, '..'),
    env: {...process.env, GOODHOPE_DATA_DIR: data},
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const manifest = JSON.parse(fs.readFileSync(path.join(backupPath, 'MANIFEST.json'), 'utf8'));
  assert.ok(manifest.files.some((x) => x.name === 'goodhope.sqlite'));
  const restore = spawnSync(process.execPath, ['scripts/restore.js', backupPath, target], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });
  assert.equal(restore.status, 0, restore.stderr);
  assert.ok(fs.existsSync(path.join(target, 'goodhope.sqlite')));
  const failed = spawnSync(process.execPath, ['scripts/restore.js', backupPath, target], {
    cwd: path.resolve(__dirname, '..'),
    encoding: 'utf8',
  });
  assert.notEqual(failed.status, 0, 'Refuse overwrite of an existing database');
  app = await initialize({...cfg, INITIAL_ADMIN_PASSWORD: '', GOODHOPE_DATA_DIR: target});
  const saved = app.db.prepare('SELECT count(*) AS n FROM users').get();
  assert.equal(saved.n, 1);
  const sessions = app.db.prepare('SELECT count(*) AS n FROM sessions').get();
  assert.equal(sessions.n, 1);
  app.db.close();
});
