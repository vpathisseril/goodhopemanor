'use strict';
/**
 * Fixtures for the HTTP tests. Every test starts its own server on its own temporary database,
 * so tests never depend on one another and can run alone (node --test --test-name-pattern=...).
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {initialize} = require('../src/app');

const PASSWORD = 'Correct-Horse-Battery-Maple-2026!';
const PDF = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nstartxref\n0\n%%EOF\n');

/** Starts a fresh server for test `t`; it is stopped and its data deleted when `t` ends. */
async function startApp(t) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ghm-test-'));
  const app = await initialize({
    ...process.env,
    NODE_ENV: 'test',
    PORT: '3000',
    GOODHOPE_DATA_DIR: tmp,
    INITIAL_ADMIN_PASSWORD: PASSWORD,
    AV_SCANNER: path.join(__dirname, 'fixtures', 'mock-clamscan'),
    PUBLIC_BASE_URL: 'http://127.0.0.1:3000',
  });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  t.after(async () => {
    await new Promise((resolve) => app.server.close(resolve));
    app.db.close();
    fs.rmSync(tmp, {recursive: true, force: true});
  });

  async function request(url, method = 'GET', body = null, {cookie, csrf, headers = {}} = {}) {
    const init = {method, headers: {...headers}};
    if (cookie) init.headers.Cookie = cookie;
    if (csrf) init.headers['x-csrf-token'] = csrf;
    if (body !== null) {
      if (body instanceof Buffer) init.body = body;
      else {
        init.body = JSON.stringify(body);
        init.headers['Content-Type'] = 'application/json';
      }
    }
    const response = await fetch(base + url, init);
    const type = response.headers.get('content-type') || '';
    const bytes = Buffer.from(await response.arrayBuffer());
    const data = type.includes('application/json') ? JSON.parse(bytes.toString()) : bytes;
    return {status: response.status, headers: response.headers, data};
  }

  async function login(username, password) {
    const result = await request('/api/auth/login', 'POST', {username, password});
    return {
      ...result,
      cookie: result.headers.get('set-cookie')?.split(';')[0],
      csrf: result.data.csrf,
    };
  }

  return {app, tmp, request, login};
}

/** Logs in the bootstrap admin and completes the forced first password change. */
async function adminSession(server) {
  const auth = await server.login('admin', PASSWORD);
  assert.equal(auth.status, 200);
  const session = {cookie: auth.cookie, csrf: auth.data.csrf};
  const changed = await server.request(
    '/api/auth/change-password',
    'POST',
    {newPassword: PASSWORD + '-Changed'},
    session,
  );
  assert.equal(changed.status, 200);
  return session;
}

/** Creates a user via an admin invitation, sets their password, and returns their session. */
async function invitedSession(server, admin, username, role) {
  const created = await server.request(
    '/api/admin/users',
    'POST',
    {username, email: `${username}@example.com`, role},
    admin,
  );
  assert.equal(created.status, 201);
  const token = decodeURIComponent(created.data.invitationUrl.split('#reset=')[1]);
  const password = `${PASSWORD}-${username}`;
  const reset = await server.request('/api/auth/reset-password', 'POST', {
    token,
    newPassword: password,
  });
  assert.equal(reset.status, 200);
  const auth = await server.login(username, password);
  assert.equal(auth.status, 200);
  return {cookie: auth.cookie, csrf: auth.data.csrf, id: created.data.user.id};
}

/** Admin, editor and approver sessions on a fresh server. */
async function staffSessions(server) {
  const admin = await adminSession(server);
  const editor = await invitedSession(server, admin, 'editor1', 'editor');
  const approver = await invitedSession(server, admin, 'approver1', 'approver');
  return {admin, editor, approver};
}

/** Builds a multipart/form-data body with text fields and one file. */
function multipart(fields, filename, bytes) {
  const boundary = '--------TestMultipart' + crypto.randomBytes(8).toString('hex');
  const chunks = Object.entries(fields).map(([name, value]) =>
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`,
    ),
  );
  chunks.push(
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
    ),
    bytes,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  );
  return {
    body: Buffer.concat(chunks),
    headers: {'Content-Type': 'multipart/form-data; boundary=' + boundary},
  };
}

/** Uploads a file to `url` as `session`; returns the raw response. */
function uploadFile(server, session, url, fields, filename, bytes) {
  const form = multipart(fields, filename, bytes);
  return server.request(url, 'POST', form.body, {...session, headers: form.headers});
}

/** Uploads a document as the editor and approves it; returns its id. */
async function approvedDocument(server, {editor, approver}) {
  const created = await uploadFile(
    server,
    editor,
    '/api/admin/documents',
    {title: 'Monthly Menu', category: 'Menu', effectiveDate: '2026-01-01'},
    'menu.pdf',
    PDF,
  );
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const id = created.data.documentId;
  const approved = await server.request(
    `/api/admin/documents/${id}`,
    'PATCH',
    {action: 'approve'},
    approver,
  );
  assert.equal(approved.status, 200);
  return id;
}

module.exports = {
  PASSWORD,
  PDF,
  startApp,
  adminSession,
  invitedSession,
  staffSessions,
  uploadFile,
  approvedDocument,
};
