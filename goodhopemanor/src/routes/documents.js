'use strict';
/** Public document listing and downloads, and staff document management. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {ROLES, CATEGORIES} = require('../database');
const {sanitizeText} = require('../security');
const {parseMultipart, processUpload} = require('../uploads');
const {ApiError, nowISOString, validateDate, readBody, readJson} = require('../http');
const {publicEligible, fullDoc} = require('../context');

const ID = '([0-9a-f-]{36})';
const DEFAULT_CATEGORY = 'Other Facility Documents';

const datesValid = (effective, expiration) =>
  validateDate(effective) &&
  validateDate(expiration) &&
  !(effective && expiration && effective > expiration);

module.exports = function documentRoutes(ctx) {
  const {config, db, tx, audit, statements, reply} = ctx;

  async function listPublic(req, res) {
    const documents = statements.publicDocuments.all().filter(publicEligible).map(fullDoc);
    return reply(res, 200, {documents});
  }

  async function downloadPublic(req, res, [id]) {
    const doc = statements.documentById.get(id);
    if (!doc || !publicEligible(doc)) return reply(res, 404, {error: 'Document not available'});
    return ctx.sendFile(req, res, statements.currentVersion.get(doc.id, doc.current_version));
  }

  async function listAll(req, res) {
    if (!ctx.authorize(req, res, ROLES)) return;
    const rows = db
      .prepare('SELECT * FROM documents WHERE deleted=0 ORDER BY updated_at DESC')
      .all();
    return reply(res, 200, {documents: rows.map(fullDoc)});
  }

  async function listVersions(req, res, [id]) {
    if (!ctx.authorize(req, res, ROLES)) return;
    if (!statements.documentById.get(id)) return reply(res, 404, {error: 'Document not found'});
    const versions = db
      .prepare(
        'SELECT version,original_name,mime,file_sha256,file_size,scanned_at,created_at,uploaded_by FROM document_versions WHERE document_id=? ORDER BY version DESC',
      )
      .all(id);
    return reply(res, 200, {versions});
  }

  async function downloadVersion(req, res, [id, version]) {
    if (!ctx.authorize(req, res, ROLES)) return;
    const doc = statements.documentById.get(id);
    if (!doc) return reply(res, 404, {error: 'Document not found'});
    return ctx.sendFile(req, res, statements.currentVersion.get(doc.id, Number(version)));
  }

  /** New document (no id) or a replacement file for an existing one (id). Always starts unapproved. */
  async function upload(req, res, [existingId]) {
    const auth = ctx.authorize(req, res, ['admin', 'editor'], true);
    if (!auth) return;
    const raw = await readBody(req, config.maxUpload + 200000);
    const {fields, file} = parseMultipart(raw, req.headers['content-type']);
    const category = fields.category || DEFAULT_CATEGORY;
    const title = sanitizeText(fields.title, 150);
    const effective = fields.effectiveDate || '';
    const expiration = fields.expirationDate || '';
    if (
      !CATEGORIES.includes(category) ||
      (!existingId && !title) ||
      !datesValid(effective, expiration)
    ) {
      return reply(res, 400, {error: 'Invalid document metadata or dates'});
    }
    const parsed = await processUpload(file, config);
    const date = nowISOString();
    let id = crypto.randomUUID();
    let version = 1;
    try {
      tx(() => {
        if (existingId) {
          id = existingId;
          const prev = statements.documentById.get(id);
          if (!prev) throw new ApiError(404, 'Document not found');
          version = prev.current_version + 1;
          db.prepare(
            'UPDATE documents SET current_version=?,approved=0,approved_by=NULL,approved_at=NULL,updated_at=? WHERE id=?',
          ).run(version, date, id);
        } else {
          db.prepare(
            'INSERT INTO documents (id,title,category,effective_date,expiration_date,approved,archived,deleted,current_version,created_at,updated_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
          ).run(id, title, category, effective, expiration, 0, 0, 0, 1, date, date, auth.user.id);
        }
        db.prepare(
          'INSERT INTO document_versions (document_id,version,stored_name,original_name,mime,file_sha256,file_size,scanned_at,created_at,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?)',
        ).run(
          id,
          version,
          parsed.storedName,
          parsed.originalName,
          parsed.mime,
          parsed.fileHash,
          parsed.fileSize,
          parsed.scannedAt,
          date,
          auth.user.id,
        );
        audit(auth.user.id, existingId ? 'document.replace' : 'document.upload', id, {
          version,
          sha256: parsed.fileHash,
        });
      });
    } catch (e) {
      // The file was stored before the transaction; remove it so no orphan is left behind.
      fs.rmSync(path.join(config.storageDir, parsed.storedName), {force: true});
      throw e;
    }
    return reply(res, 201, {ok: true, documentId: id, version, approved: false});
  }

  async function remove(req, res, [id]) {
    const auth = ctx.authorize(req, res, ROLES, true);
    if (!auth) return;
    const doc = statements.documentById.get(id);
    if (!doc) return reply(res, 404, {error: 'Document not found'});
    if (auth.user.role !== 'admin') return reply(res, 403, {error: 'Administrator role required'});
    tx(() => {
      db.prepare('UPDATE documents SET deleted=1,approved=0,updated_at=? WHERE id=?').run(
        nowISOString(),
        doc.id,
      );
      audit(auth.user.id, 'document.delete', doc.id);
    });
    return reply(res, 200, {ok: true});
  }

  function setApproval(auth, doc, action, res) {
    if (!['admin', 'approver'].includes(auth.user.role)) {
      return reply(res, 403, {error: 'Approver role required'});
    }
    const approved = action === 'approve' ? 1 : 0;
    if (approved) {
      const current = statements.currentVersion.get(doc.id, doc.current_version);
      if (!current || !current.scanned_at) {
        return reply(res, 409, {error: 'Document must pass malware scanning before approval'});
      }
    }
    tx(() => {
      db.prepare(
        'UPDATE documents SET approved=?,approved_by=?,approved_at=?,updated_at=? WHERE id=?',
      ).run(
        approved,
        approved ? auth.user.id : null,
        approved ? nowISOString() : null,
        nowISOString(),
        doc.id,
      );
      audit(auth.user.id, 'document.' + action, doc.id, {version: doc.current_version});
    });
    return reply(res, 200, {ok: true});
  }

  function setArchived(auth, doc, action, res) {
    if (!['admin', 'editor'].includes(auth.user.role)) {
      return reply(res, 403, {error: 'Editor role required'});
    }
    tx(() => {
      db.prepare('UPDATE documents SET archived=?,approved=0,updated_at=? WHERE id=?').run(
        action === 'archive' ? 1 : 0,
        nowISOString(),
        doc.id,
      );
      audit(auth.user.id, 'document.' + action, doc.id);
    });
    return reply(res, 200, {ok: true});
  }

  function updateMetadata(auth, doc, body, res) {
    if (!['admin', 'editor'].includes(auth.user.role)) {
      return reply(res, 403, {error: 'Editor role required'});
    }
    const title = sanitizeText(body.title ?? doc.title, 150);
    const category = body.category ?? doc.category;
    const effective = body.effectiveDate ?? doc.effective_date;
    const expiration = body.expirationDate ?? doc.expiration_date;
    if (!title || !CATEGORIES.includes(category) || !datesValid(effective, expiration)) {
      return reply(res, 400, {error: 'Invalid metadata'});
    }
    // Any edit withdraws approval so an approver reviews the change.
    tx(() => {
      db.prepare(
        'UPDATE documents SET title=?,category=?,effective_date=?,expiration_date=?,approved=0,approved_by=NULL,approved_at=NULL,updated_at=? WHERE id=?',
      ).run(title, category, effective, expiration, nowISOString(), doc.id);
      audit(auth.user.id, 'document.metadata', doc.id);
    });
    return reply(res, 200, {ok: true});
  }

  async function update(req, res, [id]) {
    const auth = ctx.authorize(req, res, ROLES, true);
    if (!auth) return;
    const doc = statements.documentById.get(id);
    if (!doc) return reply(res, 404, {error: 'Document not found'});
    const body = await readJson(req);
    const {action} = body;
    if (action === 'approve' || action === 'unapprove') return setApproval(auth, doc, action, res);
    if (action === 'archive' || action === 'unarchive') return setArchived(auth, doc, action, res);
    if (action === 'metadata') return updateMetadata(auth, doc, body, res);
    return reply(res, 400, {error: 'Invalid action'});
  }

  return [
    {methods: ['GET'], path: '/api/documents/public', handler: listPublic},
    {
      methods: ['GET', 'HEAD'],
      path: new RegExp(`^/api/documents/${ID}/download$`, 'i'),
      handler: downloadPublic,
    },
    {methods: ['GET'], path: '/api/admin/documents', handler: listAll},
    {methods: ['POST'], path: '/api/admin/documents', handler: upload},
    {
      methods: ['GET'],
      path: new RegExp(`^/api/admin/documents/${ID}/versions$`, 'i'),
      handler: listVersions,
    },
    {
      methods: ['POST'],
      path: new RegExp(`^/api/admin/documents/${ID}/versions$`, 'i'),
      handler: upload,
    },
    {
      methods: ['GET', 'HEAD'],
      path: new RegExp(`^/api/admin/documents/${ID}/versions/(\\d+)/download$`, 'i'),
      handler: downloadVersion,
    },
    {methods: ['PATCH'], path: new RegExp(`^/api/admin/documents/${ID}$`, 'i'), handler: update},
    {methods: ['DELETE'], path: new RegExp(`^/api/admin/documents/${ID}$`, 'i'), handler: remove},
  ];
};
