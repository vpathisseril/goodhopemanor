'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {loadConfig} = require('../src/config');
const {openDatabase} = require('../src/database');

test('oversized audit details are stored as valid JSON, never cut mid-string', (t) => {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'ghm-audit-'));
  const config = loadConfig({NODE_ENV: 'test', GOODHOPE_DATA_DIR: data});
  const {db, audit} = openDatabase(config);
  t.after(() => {
    db.close();
    fs.rmSync(data, {recursive: true, force: true});
  });

  audit(null, 'test.small', null, {note: 'ok'});
  audit(null, 'test.large', null, {note: 'x'.repeat(5000)});

  const rows = db.prepare('SELECT event, details FROM audit_log').all();
  const byEvent = Object.fromEntries(rows.map((row) => [row.event, JSON.parse(row.details)]));
  assert.deepEqual(byEvent['test.small'], {note: 'ok'});
  assert.equal(byEvent['test.large'].truncated, true);
  assert.ok(byEvent['test.large'].originalLength > 2000);
});
