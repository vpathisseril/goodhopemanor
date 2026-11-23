'use strict';
/** HTTP API tests. Each test starts its own server and builds only the state it needs. */
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {loadConfig} = require('../src/config');
const {magicType, isSafeDocx} = require('../src/uploads');
const {
  PASSWORD,
  PDF,
  startApp,
  adminSession,
  invitedSession,
  staffSessions,
  uploadFile,
  approvedDocument,
} = require('./helpers');

const publicCount = async (server) =>
  (await server.request('/api/documents/public')).data.documents.length;

test('public pages load and private files are never served statically', async (t) => {
  const server = await startApp(t);
  for (const url of [
    '/',
    '/index.html',
    '/documents.html',
    '/contact.html',
    '/assets/images/exterior-good-hope-manor.jpg',
    '/assets/images/favicon.png',
    '/api/health',
  ]) {
    assert.equal((await server.request(url)).status, 200, url);
  }
  for (const url of [
    '/server.js',
    '/.env',
    '/src/app.js',
    '/data/goodhope.sqlite',
    '/uploads/test.pdf',
    '/.git/config',
    '/../server.js',
    '/%2e%2e/server.js',
  ]) {
    assert.ok([400, 403, 404].includes((await server.request(url)).status), url);
  }
  const page = await server.request('/index.html');
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
});

test('admin first login is forced to change password', async (t) => {
  const server = await startApp(t);
  const auth = await server.login('admin', PASSWORD);
  assert.equal(auth.status, 200);
  assert.equal(auth.data.forcePasswordChange, true);
  const session = {cookie: auth.cookie, csrf: auth.data.csrf};
  const change = (newPassword, s = session) =>
    server.request('/api/auth/change-password', 'POST', {newPassword}, s);

  assert.equal((await server.request('/api/admin/documents', 'GET', null, session)).status, 403);
  assert.equal((await change('password01')).status, 400, 'weak password');
  assert.equal(
    (await change(PASSWORD + '-Changed', {cookie: session.cookie})).status,
    403,
    'missing CSRF token',
  );
  assert.equal((await change(PASSWORD + '-Changed')).status, 200);
  assert.equal((await server.request('/api/admin/documents', 'GET', null, session)).status, 200);
  assert.equal((await server.login('admin', PASSWORD)).status, 401, 'old password rejected');
  assert.equal((await server.request('/api/admin/audit', 'GET', null, session)).status, 200);
});

test('only administrators manage users; invitations create working accounts', async (t) => {
  const server = await startApp(t);
  const {admin, editor, approver} = await staffSessions(server);
  assert.equal((await server.request('/api/admin/users', 'GET', null, editor)).status, 403);
  assert.equal((await server.request('/api/admin/users', 'GET', null, approver)).status, 403);
  const escalate = await server.request(
    '/api/admin/users',
    'POST',
    {username: 'hack', email: 'hack@test.com', role: 'admin'},
    editor,
  );
  assert.equal(escalate.status, 403);
  const users = await server.request('/api/admin/users', 'GET', null, admin);
  assert.equal(users.data.users.length, 3);
  assert.ok(!JSON.stringify(users.data).includes('password_hash'));
});

test('forged extensions, active content, infected bytes and bad categories are rejected', async (t) => {
  const server = await startApp(t);
  const admin = await adminSession(server);
  const editor = await invitedSession(server, admin, 'editor1', 'editor');
  for (const [filename, bytes] of [
    ['fake.pdf', Buffer.from('ordinary text')],
    ['attack.html', Buffer.from('<h1>malware</h1>')],
    ['bad.pdf', Buffer.concat([PDF, Buffer.from('EICAR-TEST')])],
  ]) {
    const r = await uploadFile(
      server,
      editor,
      '/api/admin/documents',
      {title: 'File', category: 'Menu'},
      filename,
      bytes,
    );
    assert.ok([400, 422].includes(r.status), `${filename} ${r.status}`);
  }
  const badCategory = await uploadFile(
    server,
    editor,
    '/api/admin/documents',
    {title: 'Menu', category: 'Unknown category'},
    'menu.pdf',
    PDF,
  );
  assert.equal(badCategory.status, 400);
});

test('invalid sessions, foreign origins, oversized uploads and replayed invitations fail', async (t) => {
  const server = await startApp(t);
  const admin = await adminSession(server);
  const editor = await invitedSession(server, admin, 'editor1', 'editor');

  const forged = await server.request('/api/admin/documents', 'GET', null, {
    cookie: 'ghm_sid=invalid',
  });
  assert.equal(forged.status, 401);

  const crossSite = await server.request(
    '/api/admin/users',
    'POST',
    {username: 'fakeuser', email: 'fake@example.com', role: 'admin'},
    {...admin, headers: {Origin: 'https://malicious.invalid'}},
  );
  assert.equal(crossSite.status, 403);

  const huge = Buffer.alloc(20 * 1024 * 1024 + 300000, 0x41);
  const tooBig = await uploadFile(
    server,
    editor,
    '/api/admin/documents',
    {title: 'Huge document', category: 'Menu'},
    'large.pdf',
    huge,
  );
  assert.equal(tooBig.status, 413);

  const created = await server.request(
    '/api/admin/users',
    'POST',
    {username: 'resettest', email: 'resettest@example.com', role: 'editor'},
    admin,
  );
  assert.equal(created.status, 201);
  const token = decodeURIComponent(created.data.invitationUrl.split('#reset=')[1]);
  const use = (newPassword) =>
    server.request('/api/auth/reset-password', 'POST', {token, newPassword});
  assert.equal((await use(PASSWORD + '-ResetTest')).status, 200);
  assert.equal((await use(PASSWORD + '-Replay')).status, 400, 'invitation is single-use');
});

test('uploads are private until an approver approves them; editors cannot approve', async (t) => {
  const server = await startApp(t);
  const {editor, approver} = await staffSessions(server);
  const created = await uploadFile(
    server,
    editor,
    '/api/admin/documents',
    {title: 'Monthly Menu', category: 'Menu', effectiveDate: '2026-01-01'},
    'menu.pdf',
    PDF,
  );
  assert.equal(created.status, 201, JSON.stringify(created.data));
  assert.equal(created.data.approved, false);
  const id = created.data.documentId;
  const approve = (session) =>
    server.request(`/api/admin/documents/${id}`, 'PATCH', {action: 'approve'}, session);

  assert.equal(await publicCount(server), 0);
  assert.equal((await server.request(`/api/documents/${id}/download`)).status, 404);
  assert.equal((await approve(editor)).status, 403, 'editor cannot approve');
  assert.equal((await approve({cookie: approver.cookie})).status, 403, 'CSRF token required');
  assert.equal((await approve(approver)).status, 200);
  assert.equal(await publicCount(server), 1);
  assert.deepEqual((await server.request(`/api/documents/${id}/download`)).data, PDF);
});

test('a replacement file withdraws public access until reapproved; history is kept', async (t) => {
  const server = await startApp(t);
  const staff = await staffSessions(server);
  const id = await approvedDocument(server, staff);

  const replaced = await uploadFile(
    server,
    staff.editor,
    `/api/admin/documents/${id}/versions`,
    {},
    'newmenu.pdf',
    Buffer.from('%PDF-1.4\nrevised menu\n%%EOF\n'),
  );
  assert.equal(replaced.status, 201, JSON.stringify(replaced.data));
  assert.equal(replaced.data.version, 2);
  assert.equal(await publicCount(server), 0);
  assert.equal((await server.request(`/api/documents/${id}/download`)).status, 404);

  const history = await server.request(
    `/api/admin/documents/${id}/versions`,
    'GET',
    null,
    staff.editor,
  );
  assert.equal(history.data.versions.length, 2);

  const approved = await server.request(
    `/api/admin/documents/${id}`,
    'PATCH',
    {action: 'approve'},
    staff.approver,
  );
  assert.equal(approved.status, 200);
  assert.equal((await server.request('/api/documents/public')).data.documents[0].version, 2);
});

test('a stored file altered on disk, even at the same size, is not served', async (t) => {
  const server = await startApp(t);
  const id = await approvedDocument(server, await staffSessions(server));
  const row = server.app.db
    .prepare('SELECT stored_name FROM document_versions WHERE document_id=? AND version=1')
    .get(id);
  const file = path.join(server.tmp, 'private-files', row.stored_name);
  const original = fs.readFileSync(file);
  const tampered = Buffer.from(original);
  tampered[14] ^= 1;

  fs.writeFileSync(file, tampered);
  assert.equal((await server.request(`/api/documents/${id}/download`)).status, 503);
  fs.writeFileSync(file, original);
  assert.equal((await server.request(`/api/documents/${id}/download`)).status, 200);
});

test('expired, archived or edited documents are hidden from guests', async (t) => {
  const server = await startApp(t);
  const staff = await staffSessions(server);
  const id = await approvedDocument(server, staff);
  const update = (body, session = staff.editor) =>
    server.request(`/api/admin/documents/${id}`, 'PATCH', body, session);
  assert.equal(await publicCount(server), 1);

  // An edit withdraws approval; reapproving an already-expired document keeps it hidden.
  assert.equal((await update({action: 'metadata', expirationDate: '2026-02-01'})).status, 200);
  assert.equal(await publicCount(server), 0);
  assert.equal((await update({action: 'approve'}, staff.approver)).status, 200);
  assert.equal(await publicCount(server), 0);

  // Archiving withdraws approval too, so unarchiving alone does not republish.
  assert.equal((await update({action: 'metadata', expirationDate: ''})).status, 200);
  assert.equal((await update({action: 'approve'}, staff.approver)).status, 200);
  assert.equal(await publicCount(server), 1);
  assert.equal((await update({action: 'archive'})).status, 200);
  assert.equal((await update({action: 'unarchive'})).status, 200);
  assert.equal(await publicCount(server), 0);
});

test('the last administrator cannot be demoted; disabled users lose access at once', async (t) => {
  const server = await startApp(t);
  const admin = await adminSession(server);
  const editor = await invitedSession(server, admin, 'editor1', 'editor');
  const {users} = (await server.request('/api/admin/users', 'GET', null, admin)).data;
  const adminUser = users.find((u) => u.username === 'admin');

  const demote = await server.request(
    `/api/admin/users/${adminUser.id}`,
    'PATCH',
    {role: 'editor'},
    admin,
  );
  assert.equal(demote.status, 409);
  const disable = await server.request(
    `/api/admin/users/${editor.id}`,
    'PATCH',
    {disabled: true},
    admin,
  );
  assert.equal(disable.status, 200);
  assert.equal((await server.request('/api/admin/documents', 'GET', null, editor)).status, 401);
});

test('logout ends the session', async (t) => {
  const server = await startApp(t);
  const admin = await adminSession(server);
  assert.equal((await server.request('/api/admin/audit', 'GET', null, admin)).status, 200);
  assert.equal((await server.request('/api/auth/logout', 'POST', {}, admin)).status, 200);
  assert.equal((await server.request('/api/admin/audit', 'GET', null, admin)).status, 401);
});

test('production fails closed without persistent storage, HTTPS and antivirus scanner', () => {
  const production = {
    NODE_ENV: 'production',
    DEPLOYMENT_MODE: 'single-instance',
    PUBLIC_BASE_URL: 'https://example.com',
    AV_SCANNER: '/usr/bin/clamscan',
  };
  assert.throws(
    () => loadConfig({...production, GOODHOPE_DATA_DIR: './data'}),
    /private, mounted persistent volume/,
  );
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ghm-prod-config-'));
  try {
    const withDir = {...production, GOODHOPE_DATA_DIR: directory};
    assert.throws(() => loadConfig({...withDir, PUBLIC_BASE_URL: 'http://example.com'}), /HTTPS/);
    assert.throws(() => loadConfig({...withDir, AV_SCANNER: undefined}), /AV_SCANNER/);
    assert.throws(() => loadConfig({...withDir, DEPLOYMENT_MODE: 'autoscale'}), /single-instance/);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('uploaded content headers require genuine file types', () => {
  assert.equal(magicType(Buffer.from('not really a pdf'), '.pdf'), false);
  assert.equal(magicType(Buffer.from('hello world PDF'.repeat(20)), '.pdf'), false);
  assert.equal(magicType(PDF, '.pdf'), true);
  assert.equal(isSafeDocx(Buffer.from('PKnotreally')), false);
});
