'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {securityHeaders} = require('./security');
const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.xml': 'application/xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};
function headers(res, config, extra = {}) {
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(securityHeaders(config.production))) res.setHeader(k, v);
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
}
function json(res, config, status, obj, extra = {}) {
  headers(res, config, {'Content-Type': 'application/json; charset=utf-8', ...extra});
  res.writeHead(status);
  res.end(JSON.stringify(obj));
}
function serveStatic(req, res, config, url) {
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return json(res, config, 400, {error: 'Invalid path'});
  }
  if (pathname === '/') pathname = '/index.html';
  const html = /^\/[a-z0-9-]+\.html$/i.test(pathname);
  const rootAsset = /^\/(?:styles\.css|script\.js|documents\.js|robots\.txt|sitemap\.xml)$/i.test(
    pathname,
  );
  const image = /^\/assets\/images\/[a-z0-9._-]+\.(?:png|jpg|jpeg|ico|webp)$/i.test(pathname);
  if (!html && !rootAsset && !image) return json(res, config, 404, {error: 'Not found'});
  const full = path.resolve(config.root, '.' + pathname);
  if (!full.startsWith(config.root + path.sep)) return json(res, config, 403, {error: 'Forbidden'});
  let file = full,
    status = 200;
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    file = path.join(config.root, '404.html');
    status = 404;
  }
  const stat = fs.statSync(file),
    type = CONTENT_TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream';
  headers(res, config, {'Content-Type': type, 'Content-Length': stat.size});
  res.writeHead(status);
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(file)
    .on('error', () => res.destroy())
    .pipe(res);
}
module.exports = {headers, json, serveStatic};
