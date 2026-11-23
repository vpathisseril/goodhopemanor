'use strict';
/** Request helpers shared by the route modules. */

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const nowISOString = () => new Date().toISOString();

/** True for '' (no date) or a real calendar date in YYYY-MM-DD form. */
const validateDate = (value) =>
  typeof value === 'string' &&
  (!value ||
    (/^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value + 'T00:00:00Z'))));

async function readBody(req, limit = 1024 * 1024) {
  const len = Number(req.headers['content-length'] || 0);
  if (len > limit) throw new ApiError(413, 'Request exceeds size limit');
  const parts = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > limit) throw new ApiError(413, 'Request exceeds size limit');
    parts.push(chunk);
  }
  return Buffer.concat(parts);
}

async function readJson(req) {
  const buffer = await readBody(req);
  const type = String(req.headers['content-type'] || '').toLowerCase();
  if (!type.startsWith('application/json')) throw new ApiError(415, 'Expected JSON request');
  try {
    return JSON.parse(buffer.toString('utf8') || '{}');
  } catch {
    throw new ApiError(400, 'Invalid JSON request');
  }
}

module.exports = {ApiError, nowISOString, validateDate, readBody, readJson};
