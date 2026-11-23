#!/usr/bin/env node
'use strict';
/** Offline backup of a single-instance deployment. Stop the service first. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {DatabaseSync, backup} = require('node:sqlite');
const sha = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
async function run() {
  const data = process.env.GOODHOPE_DATA_DIR;
  const root = process.argv[2];
  if (!data || !path.isAbsolute(data) || !root || !path.isAbsolute(root))
    throw new Error(
      'Usage: GOODHOPE_DATA_DIR=/mounted/private node scripts/backup.js /mounted/backups/backup-YYYY-MM-DD',
    );
  if (fs.existsSync(root))
    throw new Error('Backup destination already exists; choose a fresh path');
  const dbFile = path.join(data, 'goodhope.sqlite');
  if (!fs.existsSync(dbFile)) throw new Error('Database not found');
  fs.mkdirSync(root, {recursive: true, mode: 0o700});
  const db = new DatabaseSync(dbFile, {readOnly: true});
  try {
    await backup(db, path.join(root, 'goodhope.sqlite'));
  } finally {
    db.close();
  }
  fs.mkdirSync(path.join(root, 'private-files'), {recursive: true, mode: 0o700});
  const files = [];
  const add = (src, dest) => {
    fs.copyFileSync(src, dest);
    fs.chmodSync(dest, 0o600);
    files.push({
      name: path.relative(root, dest).replace(/\\/g, '/'),
      sha256: sha(dest),
      bytes: fs.statSync(dest).size,
    });
  };
  files.push({
    name: 'goodhope.sqlite',
    sha256: sha(path.join(root, 'goodhope.sqlite')),
    bytes: fs.statSync(path.join(root, 'goodhope.sqlite')).size,
  });
  for (const name of fs.readdirSync(path.join(data, 'private-files'))) {
    if (!/^[a-f0-9-]{36}\.(pdf|doc|docx|jpg|jpeg|png)$/i.test(name))
      throw new Error('Unexpected upload filename: ' + name);
    const source = path.join(data, 'private-files', name);
    if (fs.statSync(source).isFile()) add(source, path.join(root, 'private-files', name));
  }
  fs.writeFileSync(
    path.join(root, 'MANIFEST.json'),
    JSON.stringify({version: 1, createdAt: new Date().toISOString(), files}, null, 2),
    {mode: 0o600},
  );
  console.log(`Backup verified: ${files.length} file(s), destination ${root}`);
}
run().catch((error) => {
  console.error('Backup failed:', error.message);
  process.exitCode = 1;
});
