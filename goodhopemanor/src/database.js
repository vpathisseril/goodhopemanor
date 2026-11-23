'use strict';
const fs = require('node:fs');
const crypto=require('node:crypto');
const {DatabaseSync} = require('node:sqlite');
const {hashPassword,strongPassword}=require('./security');
const ROLES = ['admin','editor','approver'];
const CATEGORIES=['Visitation Policy','Monthly Activity Calendars','Menu','Resident Notices','Other Facility Documents'];
function openDatabase(config) {
  const db = new DatabaseSync(config.dbFile);
  fs.chmodSync(config.dbFile,0o600);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
      role TEXT NOT NULL CHECK(role IN ('admin','editor','approver')),
      disabled INTEGER NOT NULL DEFAULT 0, must_change INTEGER NOT NULL DEFAULT 1,
      password_salt TEXT NOT NULL, password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      sid_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      csrf TEXT NOT NULL, created_ms INTEGER NOT NULL, last_seen_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_tokens (
      token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_ms INTEGER NOT NULL, consumed_ms INTEGER
    );
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
      effective_date TEXT NOT NULL DEFAULT '', expiration_date TEXT NOT NULL DEFAULT '',
      approved INTEGER NOT NULL DEFAULT 0, approved_by TEXT, approved_at TEXT,
      archived INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0,
      current_version INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, created_by TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS document_versions (
      document_id TEXT NOT NULL REFERENCES documents(id), version INTEGER NOT NULL,
      stored_name TEXT NOT NULL UNIQUE, original_name TEXT NOT NULL, mime TEXT NOT NULL,
      file_sha256 TEXT NOT NULL, file_size INTEGER NOT NULL, scanned_at TEXT,
      created_at TEXT NOT NULL, uploaded_by TEXT NOT NULL,
      PRIMARY KEY(document_id,version)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY, created_at TEXT NOT NULL, actor_id TEXT, event TEXT NOT NULL,
      target_id TEXT, details TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_ms);
    CREATE INDEX IF NOT EXISTS docs_visibility_idx ON documents(approved,archived,deleted,effective_date,expiration_date);
    CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_log(created_at);
  `);
  function audit(actorId,event,targetId=null,details={}){
    db.prepare('INSERT INTO audit_log (id,created_at,actor_id,event,target_id,details) VALUES (?,?,?,?,?,?)')
      .run(crypto.randomUUID(),new Date().toISOString(),actorId||null,event,targetId,JSON.stringify(details).slice(0,2000));
  }
  function tx(work){db.exec('BEGIN IMMEDIATE');try{const result=work();db.exec('COMMIT');return result;}catch(e){db.exec('ROLLBACK');throw e;}}
  async function seedAdmin(){
    if(db.prepare('SELECT count(*) AS n FROM users').get().n) return;
    if(!strongPassword(config.bootstrapPassword)){
      throw new Error('Set INITIAL_ADMIN_PASSWORD privately: 14–128 characters, not a common password. Never use password01.');
    }
    const hp=await hashPassword(config.bootstrapPassword);
    const id=crypto.randomUUID();const now=new Date().toISOString();
    db.prepare('INSERT INTO users (id,username,email,role,disabled,must_change,password_salt,password_hash,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(id,'admin',config.bootstrapEmail,'admin',0,1,hp.passwordSalt,hp.passwordHash,now,now);
    audit(id,'system.bootstrap',id);
  }
  return {db,audit,tx,seedAdmin};
}
module.exports={openDatabase,ROLES,CATEGORIES};
