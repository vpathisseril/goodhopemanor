'use strict';
/** Recent audit history (administrators only). */

// Rows written before the audit() truncation fix may hold cut-off JSON; never let one break the view.
function parseAuditDetails(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {unreadable: true};
  }
}

module.exports = function auditRoutes(ctx) {
  const {db, reply} = ctx;

  async function recent(req, res) {
    if (!ctx.authorize(req, res, ['admin'])) return;
    const events = db
      .prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200')
      .all()
      .map((row) => ({
        createdAt: row.created_at,
        actorId: row.actor_id,
        event: row.event,
        targetId: row.target_id,
        details: parseAuditDetails(row.details),
      }));
    return reply(res, 200, {events});
  }

  return [{methods: ['GET'], path: '/api/admin/audit', handler: recent}];
};
